/*
 * Copyright Intel Corp. 2020-2021
 *
 * ch_process.c: Process controller for Cloud-Hypervisor driver
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library.  If not, see
 * <http://www.gnu.org/licenses/>.
 */

#include <config.h>

#include <fcntl.h>
#include <unistd.h>

#include "ch_cgroup.h"
#include "ch_domain.h"
#include "ch_monitor.h"
#include "ch_process.h"
#include "viralloc.h"
#include "virerror.h"
#include "virlog.h"
#include "virnuma.h"

#define VIR_FROM_THIS VIR_FROM_CH

VIR_LOG_INIT("ch.ch_process");

#define START_SOCKET_POSTFIX ": starting up socket\n"
#define START_VM_POSTFIX ": starting up vm\n"

static virCHMonitor *
virCHProcessConnectMonitor(virCHDriver *driver,
                           virDomainObj *vm)
{
    virCHMonitor *monitor = NULL;
    virCHDriverConfig *cfg = virCHDriverGetConfig(driver);

    monitor = virCHMonitorNew(vm, cfg->stateDir);

    virObjectUnref(cfg);
    return monitor;
}

static int virCHProcessGetAllCpuAffinity(virBitmap **cpumapRet) {
  *cpumapRet = NULL;

  if (!virHostCPUHasBitmap())
    return 0;

  if (!(*cpumapRet = virHostCPUGetOnlineBitmap()))
    return -1;

  return 0;
}

#if defined(HAVE_SCHED_GETAFFINITY) || defined(HAVE_BSD_CPU_AFFINITY)
static int virCHProcessInitCpuAffinity(virDomainObj *vm) {
  g_autoptr(virBitmap) cpumapToSet = NULL;
  virDomainNumatuneMemMode mem_mode;
  virCHDomainObjPrivate *priv = vm->privateData;

  if (!vm->pid) {
    virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                   _("Cannot setup CPU affinity until process is started"));
    return -1;
  }

  if (virDomainNumaGetNodeCount(vm->def->numa) <= 1 &&
      virDomainNumatuneGetMode(vm->def->numa, -1, &mem_mode) == 0 &&
      mem_mode == VIR_DOMAIN_NUMATUNE_MEM_STRICT) {
    virBitmap *nodeset = NULL;

    if (virDomainNumatuneMaybeGetNodeset(vm->def->numa, priv->autoNodeset,
                                         &nodeset, -1) < 0)
      return -1;

    if (virNumaNodesetToCPUset(nodeset, &cpumapToSet) < 0)
      return -1;
  } else if (vm->def->cputune.emulatorpin) {
    if (!(cpumapToSet = virBitmapNewCopy(vm->def->cputune.emulatorpin)))
      return -1;
  } else {
    if (virCHProcessGetAllCpuAffinity(&cpumapToSet) < 0)
      return -1;
  }

  if (cpumapToSet && virProcessSetAffinity(vm->pid, cpumapToSet, false) < 0) {
    return -1;
  }

  return 0;
}
#else  /* !defined(HAVE_SCHED_GETAFFINITY) && !defined(HAVE_BSD_CPU_AFFINITY)  \
        */
static int virCHProcessInitCpuAffinity(virDomainObj *vm G_GNUC_UNUSED) {
  return 0;
}
#endif /* !defined(HAVE_SCHED_GETAFFINITY) && !defined(HAVE_BSD_CPU_AFFINITY)  \
        */

/**
 * virCHProcessSetupPid:
 *
 * This function sets resource properties (affinity, cgroups,
 * scheduler) for any PID associated with a domain.  It should be used
 * to set up emulator PIDs as well as vCPU and I/O thread pids to
 * ensure they are all handled the same way.
 *
 * Returns 0 on success, -1 on error.
 */
static int virCHProcessSetupPid(virDomainObj *vm, pid_t pid,
                                virCgroupThreadName nameval, int id,
                                virBitmap *cpumask, unsigned long long period,
                                long long quota,
                                virDomainThreadSchedParam *sched) {
  virCHDomainObjPrivate *priv = vm->privateData;
  virDomainNumatuneMemMode mem_mode;
  virCgroup *cgroup = NULL;
  virBitmap *use_cpumask = NULL;
  virBitmap *affinity_cpumask = NULL;
  g_autoptr(virBitmap) hostcpumap = NULL;
  g_autofree char *mem_mask = NULL;
  int ret = -1;

  if ((period || quota) &&
      !virCgroupHasController(priv->cgroup, VIR_CGROUP_CONTROLLER_CPU)) {
    virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                   _("cgroup cpu is required for scheduler tuning"));
    goto cleanup;
  }

  /* Infer which cpumask shall be used. */
  if (cpumask) {
    use_cpumask = cpumask;
  } else if (vm->def->placement_mode == VIR_DOMAIN_CPU_PLACEMENT_MODE_AUTO) {
    use_cpumask = priv->autoCpuset;
  } else if (vm->def->cpumask) {
    use_cpumask = vm->def->cpumask;
  } else {
    /* we can't assume cloud-hypervisor itself is running on all pCPUs,
     * so we need to explicitly set the spawned instance to all pCPUs. */
    if (virCHProcessGetAllCpuAffinity(&hostcpumap) < 0)
      goto cleanup;
    affinity_cpumask = hostcpumap;
  }

  /*
   * If CPU cgroup controller is not initialized here, then we need
   * neither period nor quota settings.  And if CPUSET controller is
   * not initialized either, then there's nothing to do anyway.
   */
  if (virCgroupHasController(priv->cgroup, VIR_CGROUP_CONTROLLER_CPU) ||
      virCgroupHasController(priv->cgroup, VIR_CGROUP_CONTROLLER_CPUSET)) {

    if (virDomainNumatuneGetMode(vm->def->numa, -1, &mem_mode) == 0 &&
        mem_mode == VIR_DOMAIN_NUMATUNE_MEM_STRICT &&
        virDomainNumatuneMaybeFormatNodeset(vm->def->numa, priv->autoNodeset,
                                            &mem_mask, -1) < 0)
      goto cleanup;

    if (virCgroupNewThread(priv->cgroup, nameval, id, true, &cgroup) < 0)
      goto cleanup;

    if (virCgroupHasController(priv->cgroup, VIR_CGROUP_CONTROLLER_CPUSET)) {
      if (use_cpumask && chSetupCgroupCpusetCpus(cgroup, use_cpumask) < 0)
        goto cleanup;

      if (mem_mask && virCgroupSetCpusetMems(cgroup, mem_mask) < 0)
        goto cleanup;
    }

    if ((period || quota) && chSetupCgroupVcpuBW(cgroup, period, quota) < 0)
      goto cleanup;

    /* Move the thread to the sub dir */
    VIR_INFO("Adding pid %d to cgroup", pid);
    if (virCgroupAddThread(cgroup, pid) < 0)
      goto cleanup;
  }

  if (!affinity_cpumask)
    affinity_cpumask = use_cpumask;

  /* Setup legacy affinity. */
  if (affinity_cpumask &&
      virProcessSetAffinity(pid, affinity_cpumask, false) < 0)
    goto cleanup;

  /* Set scheduler type and priority, but not for the main thread. */
  if (sched && nameval != VIR_CGROUP_THREAD_EMULATOR &&
      virProcessSetScheduler(pid, sched->policy, sched->priority) < 0)
    goto cleanup;

  ret = 0;
  cleanup:
    if (cgroup) {
      if (ret < 0)
        virCgroupRemove(cgroup);
      virCgroupFree(cgroup);
    }

    return ret;
}

int virCHProcessSetupIOThread(virDomainObj *vm,
                              virDomainIOThreadInfo *iothread) {
  virCHDomainObjPrivate *priv = vm->privateData;
  return virCHProcessSetupPid(
      vm, iothread->iothread_id, VIR_CGROUP_THREAD_IOTHREAD,
      iothread->iothread_id,
      priv->autoCpuset, // This should be updated when CLH supports accepting
                        // iothread settings from input domain definition
      vm->def->cputune.iothread_period, vm->def->cputune.iothread_quota,
      NULL); // CLH doesn't allow choosing a scheduler for iothreads.
}

static int virCHProcessSetupIOThreads(virDomainObj *vm) {
  virCHDomainObjPrivate *priv = vm->privateData;
  virDomainIOThreadInfo **iothreads = NULL;
  size_t i;
  size_t niothreads;

  niothreads = virCHMonitorGetIOThreads(priv->monitor, &iothreads);
  for (i = 0; i < niothreads; i++) {
    VIR_DEBUG("IOThread index = %ld , tid = %d", i, iothreads[i]->iothread_id);
    if (virCHProcessSetupIOThread(vm, iothreads[i]) < 0)
      return -1;
  }
  return 0;
}

int virCHProcessSetupEmulatorThread(virDomainObj *vm,
                                    virCHMonitorEmuThreadInfo emuthread) {
  return virCHProcessSetupPid(
      vm, emuthread.tid, VIR_CGROUP_THREAD_EMULATOR, 0,
      vm->def->cputune.emulatorpin, vm->def->cputune.emulator_period,
      vm->def->cputune.emulator_quota, vm->def->cputune.emulatorsched);
}

static int virCHProcessSetupEmulatorThreads(virDomainObj *vm) {
  size_t i = 0;
  virCHDomainObjPrivate *priv = vm->privateData;
  /*
  Cloud-hypervisor start 4 Emulator threads by default:
  vmm
  cloud-hypervisor
  http-server
  signal_handler
  */
  for (i = 0; i < priv->monitor->nthreads; i++) {
    if (priv->monitor->threads[i].type == virCHThreadTypeEmulator) {
      VIR_DEBUG("Setup tid = %d (%s) Emulator thread",
                priv->monitor->threads[i].emuInfo.tid,
                priv->monitor->threads[i].emuInfo.thrName);

      if (virCHProcessSetupEmulatorThread(
              vm, priv->monitor->threads[i].emuInfo) < 0)
        return -1;
    }
  }
  return 0;
}

/**
 * virCHProcessSetupVcpu:
 * @vm: domain object
 * @vcpuid: id of VCPU to set defaults
 *
 * This function sets resource properties (cgroups, affinity, scheduler) for a
 * vCPU. This function expects that the vCPU is online and the vCPU pids were
 * correctly detected at the point when it's called.
 *
 * Returns 0 on success, -1 on error.
 */
int virCHProcessSetupVcpu(virDomainObj *vm, unsigned int vcpuid) {
  pid_t vcpupid = virCHDomainGetVcpuPid(vm, vcpuid);
  virDomainVcpuDef *vcpu = virDomainDefGetVcpu(vm->def, vcpuid);

  return virCHProcessSetupPid(vm, vcpupid, VIR_CGROUP_THREAD_VCPU, vcpuid,
                              vcpu->cpumask, vm->def->cputune.period,
                              vm->def->cputune.quota, &vcpu->sched);
}

static int virCHProcessSetupVcpus(virDomainObj *vm) {
  virDomainVcpuDef *vcpu;
  unsigned int maxvcpus = virDomainDefGetVcpusMax(vm->def);
  size_t i;

  if ((vm->def->cputune.period || vm->def->cputune.quota) &&
      !virCgroupHasController(
          ((virCHDomainObjPrivate *)vm->privateData)->cgroup,
          VIR_CGROUP_CONTROLLER_CPU)) {
    virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                   _("cgroup cpu is required for scheduler tuning"));
    return -1;
  }

  if (!virCHDomainHasVcpuPids(vm)) {
    /* If any CPU has custom affinity that differs from the
     * VM default affinity, we must reject it */
    for (i = 0; i < maxvcpus; i++) {
      vcpu = virDomainDefGetVcpu(vm->def, i);

      if (!vcpu->online)
        continue;

      if (vcpu->cpumask && !virBitmapEqual(vm->def->cpumask, vcpu->cpumask)) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("cpu affinity is not supported"));
        return -1;
      }
    }

    return 0;
  }

  for (i = 0; i < maxvcpus; i++) {
    vcpu = virDomainDefGetVcpu(vm->def, i);

    if (!vcpu->online)
      continue;

    if (virCHProcessSetupVcpu(vm, i) < 0)
      return -1;
  }

  return 0;
}

/**
 * virCHProcessStart:
 * @driver: pointer to driver structure
 * @vm: pointer to virtual machine structure
 * @reason: reason for switching vm to running state
 *
 * Starts Cloud-Hypervisor listen on a local socket
 *
 * Returns 0 on success or -1 in case of error
 */
int virCHProcessStart(virCHDriver *driver, virDomainObj *vm,
                      virDomainRunningReason reason) {
  virCHDomainObjPrivate *priv = vm->privateData;
  g_autofree int *nicindexes = NULL;
  size_t nnicindexes = 0;
  int ret = -1;

  if (!priv->monitor) {
    /* And we can get the first monitor connection now too */
    if (!(priv->monitor = virCHProcessConnectMonitor(driver, vm))) {
      virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                     _("failed to create connection to CH socket"));
      goto cleanup;
    }

    if (virCHMonitorCreateVM(priv->monitor, &nnicindexes, &nicindexes) < 0) {
      virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                     _("failed to create guest VM"));
      goto cleanup;
    }
  }

  vm->pid = priv->monitor->pid;
  vm->def->id = vm->pid;
  priv->machineName = virCHDomainGetMachineName(vm);

  if (chSetupCgroup(vm, nnicindexes, nicindexes) < 0)
    goto cleanup;

  if (virCHProcessInitCpuAffinity(vm) < 0)
    goto cleanup;

  if (virCHMonitorBootVM(priv->monitor) < 0) {
    virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("failed to boot guest VM"));
    goto cleanup;
  }

  virCHDomainRefreshThreadInfo(vm);

  VIR_DEBUG("Setting emulator tuning/settings");
  if (virCHProcessSetupEmulatorThreads(vm) < 0)
    goto cleanup;

  VIR_DEBUG("Setting iothread tuning/settings");
  if (virCHProcessSetupIOThreads(vm) < 0)
    goto cleanup;

  VIR_DEBUG("Setting global CPU cgroup (if required)");
  if (chSetupGlobalCpuCgroup(vm) < 0)
    goto cleanup;

  VIR_DEBUG("Setting vCPU tuning/settings");
  if (virCHProcessSetupVcpus(vm) < 0)
    goto cleanup;

  virDomainObjSetState(vm, VIR_DOMAIN_RUNNING, reason);

  return 0;

cleanup:
  if (ret)
    virCHProcessStop(driver, vm, VIR_DOMAIN_SHUTOFF_FAILED);

  return ret;
}

int virCHProcessStop(virCHDriver *driver G_GNUC_UNUSED, virDomainObj *vm,
                     virDomainShutoffReason reason) {
  int ret;
  int retries = 0;
  virCHDomainObjPrivate *priv = vm->privateData;

  VIR_DEBUG("Stopping VM name=%s pid=%d reason=%d", vm->def->name, (int)vm->pid,
            (int)reason);

  if (priv->monitor) {
    virCHMonitorClose(priv->monitor);
    priv->monitor = NULL;
  }

  retry:
    if ((ret = chRemoveCgroup(vm)) < 0) {
      if (ret == -EBUSY && (retries++ < 5)) {
        g_usleep(200 * 1000);
        goto retry;
      }
      VIR_WARN("Failed to remove cgroup for %s", vm->def->name);
    }

    vm->pid = -1;
    vm->def->id = -1;

    virDomainObjSetState(vm, VIR_DOMAIN_SHUTOFF, reason);

    return 0;
}
