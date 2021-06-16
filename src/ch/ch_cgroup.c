/*
 * ch_cgroup.c: CH cgroup management
 *
 * Copyright (C) 2020-2021 Microsoft, Corporation.
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

#include "ch_cgroup.h"
#include "ch_domain.h"
#include "ch_process.h"
#include "domain_audit.h"
#include "domain_cgroup.h"
#include "viralloc.h"
#include "virdevmapper.h"
#include "virerror.h"
#include "virfile.h"
#include "virlog.h"
#include "virnuma.h"
#include "virscsi.h"
#include "virstring.h"
#include "virtypedparam.h"
#include "virutil.h"
//#include <config.h>

#define VIR_FROM_THIS VIR_FROM_CH

VIR_LOG_INIT("ch.ch_cgroup");

static int chSetupBlkioCgroup(virDomainObj *vm) {
  virCHDomainObjPrivate *priv = vm->privateData;

  if (!virCgroupHasController(priv->cgroup, VIR_CGROUP_CONTROLLER_BLKIO)) {
    if (vm->def->blkio.weight || vm->def->blkio.ndevices) {
      virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                     _("Block I/O tuning is not available on this host"));
      return -1;
    } else {
      return 0;
    }
  }

  return virDomainCgroupSetupBlkio(priv->cgroup, vm->def->blkio);
}

static int chSetupMemoryCgroup(virDomainObj *vm) {
  virCHDomainObjPrivate *priv = vm->privateData;

  if (!virCgroupHasController(priv->cgroup, VIR_CGROUP_CONTROLLER_MEMORY)) {
    if (virMemoryLimitIsSet(vm->def->mem.hard_limit) ||
        virMemoryLimitIsSet(vm->def->mem.soft_limit) ||
        virMemoryLimitIsSet(vm->def->mem.swap_hard_limit)) {
      virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                     _("Memory cgroup is not available on this host"));
      return -1;
    } else {
      return 0;
    }
  }

  return virDomainCgroupSetupMemtune(priv->cgroup, vm->def->mem);
}

static int chSetupCpusetCgroup(virDomainObj *vm) {
  virCHDomainObjPrivate *priv = vm->privateData;

  if (!virCgroupHasController(priv->cgroup, VIR_CGROUP_CONTROLLER_CPUSET))
    return 0;

  if (virCgroupSetCpusetMemoryMigrate(priv->cgroup, true) < 0)
    return -1;

  return 0;
}

static int chSetupCpuCgroup(virDomainObj *vm) {
  virCHDomainObjPrivate *priv = vm->privateData;

  if (!virCgroupHasController(priv->cgroup, VIR_CGROUP_CONTROLLER_CPU)) {
    if (vm->def->cputune.sharesSpecified) {
      virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                     _("CPU tuning is not available on this host"));
      return -1;
    } else {
      return 0;
    }
  }

  if (vm->def->cputune.sharesSpecified) {
    if (virCgroupSetCpuShares(priv->cgroup, vm->def->cputune.shares) < 0)
      return -1;
  }

  return 0;
}

static int chInitCgroup(virDomainObj *vm, size_t nnicindexes, int *nicindexes) {
  virCHDomainObjPrivate *priv = vm->privateData;
  g_autoptr(virCHDriverConfig) cfg = virCHDriverGetConfig(priv->driver);

  if (!priv->driver->privileged)
    return 0;

  if (!virCgroupAvailable())
    return 0;

  virCgroupFree(priv->cgroup);

  if (!vm->def->resource) {
    virDomainResourceDef *res;

    res = g_new0(virDomainResourceDef, 1);

    res->partition = g_strdup("/machine");

    vm->def->resource = res;
  }

  if (vm->def->resource->partition[0] != '/') {
    virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                   _("Resource partition '%s' must start with '/'"),
                   vm->def->resource->partition);
    return -1;
  }

  if (virCgroupNewMachine(priv->machineName, "ch", vm->def->uuid, NULL, vm->pid,
                          false, nnicindexes, nicindexes,
                          vm->def->resource->partition, cfg->cgroupControllers,
                          0, /* maxThreadsPerProc */
                          &priv->cgroup) < 0) {
    if (virCgroupNewIgnoreError())
      return 0;

    return -1;
  }

  return 0;
}

static void chRestoreCgroupState(virDomainObj *vm) {
  g_autofree char *mem_mask = NULL;
  g_autofree char *nodeset = NULL;
  int empty = -1;
  virCHDomainObjPrivate *priv = vm->privateData;
  size_t i = 0;
  g_autoptr(virBitmap) all_nodes = NULL;
  virCgroup *cgroup_temp = NULL;

  if (!virNumaIsAvailable() ||
      !virCgroupHasController(priv->cgroup, VIR_CGROUP_CONTROLLER_CPUSET))
    return;

  if (!(all_nodes = virNumaGetHostMemoryNodeset()))
    goto error;

  if (!(mem_mask = virBitmapFormat(all_nodes)))
    goto error;

  if ((empty = virCgroupHasEmptyTasks(priv->cgroup,
                                      VIR_CGROUP_CONTROLLER_CPUSET)) <= 0)
    goto error;

  if (virCgroupSetCpusetMems(priv->cgroup, mem_mask) < 0)
    goto error;

  for (i = 0; i < virDomainDefGetVcpusMax(vm->def); i++) {
    virDomainVcpuDef *vcpu = virDomainDefGetVcpu(vm->def, i);

    if (!vcpu->online)
      continue;

    if (virCgroupNewThread(priv->cgroup, VIR_CGROUP_THREAD_VCPU, i, false,
                           &cgroup_temp) < 0 ||
        virCgroupSetCpusetMemoryMigrate(cgroup_temp, true) < 0 ||
        virCgroupGetCpusetMems(cgroup_temp, &nodeset) < 0 ||
        virCgroupSetCpusetMems(cgroup_temp, nodeset) < 0)
      goto cleanup;

    VIR_FREE(nodeset);
    virCgroupFree(cgroup_temp);
  }

  for (i = 0; i < vm->def->niothreadids; i++) {
    if (virCgroupNewThread(priv->cgroup, VIR_CGROUP_THREAD_IOTHREAD,
                           vm->def->iothreadids[i]->iothread_id, false,
                           &cgroup_temp) < 0 ||
        virCgroupSetCpusetMemoryMigrate(cgroup_temp, true) < 0 ||
        virCgroupGetCpusetMems(cgroup_temp, &nodeset) < 0 ||
        virCgroupSetCpusetMems(cgroup_temp, nodeset) < 0)
      goto cleanup;

    VIR_FREE(nodeset);
    virCgroupFree(cgroup_temp);
  }

  if (virCgroupNewThread(priv->cgroup, VIR_CGROUP_THREAD_EMULATOR, 0, false,
                         &cgroup_temp) < 0 ||
      virCgroupSetCpusetMemoryMigrate(cgroup_temp, true) < 0 ||
      virCgroupGetCpusetMems(cgroup_temp, &nodeset) < 0 ||
      virCgroupSetCpusetMems(cgroup_temp, nodeset) < 0)
    goto cleanup;

  cleanup:
    virCgroupFree(cgroup_temp);
    return;

  error:
    virResetLastError();
    VIR_DEBUG("Couldn't restore cgroups to meaningful state");
    goto cleanup;
}

int chConnectCgroup(virDomainObj *vm) {
  virCHDomainObjPrivate *priv = vm->privateData;
  g_autoptr(virCHDriverConfig) cfg = virCHDriverGetConfig(priv->driver);

  if (!priv->driver->privileged)
    return 0;

  if (!virCgroupAvailable())
    return 0;

  virCgroupFree(priv->cgroup);

  if (virCgroupNewDetectMachine(vm->def->name, "ch", vm->pid,
                                cfg->cgroupControllers, priv->machineName,
                                &priv->cgroup) < 0)
    return -1;

  chRestoreCgroupState(vm);
  return 0;
}

int chSetupCgroup(virDomainObj *vm, size_t nnicindexes, int *nicindexes) {
  virCHDomainObjPrivate *priv = vm->privateData;

  if (!vm->pid) {
    virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                   _("Cannot setup cgroups until process is started"));
    return -1;
  }

  if (chInitCgroup(vm, nnicindexes, nicindexes) < 0)
    return -1;

  if (!priv->cgroup)
    return 0;

  if (chSetupBlkioCgroup(vm) < 0)
    return -1;

  if (chSetupMemoryCgroup(vm) < 0)
    return -1;

  if (chSetupCpuCgroup(vm) < 0)
    return -1;

  if (chSetupCpusetCgroup(vm) < 0)
    return -1;

  return 0;
}

int chSetupCgroupVcpuBW(virCgroup *cgroup, unsigned long long period,
                        long long quota) {
  return virCgroupSetupCpuPeriodQuota(cgroup, period, quota);
}

int chSetupCgroupCpusetCpus(virCgroup *cgroup, virBitmap *cpumask) {
  return virCgroupSetupCpusetCpus(cgroup, cpumask);
}

int chSetupGlobalCpuCgroup(virDomainObj *vm) {
  virCHDomainObjPrivate *priv = vm->privateData;
  unsigned long long period = vm->def->cputune.global_period;
  long long quota = vm->def->cputune.global_quota;
  g_autofree char *mem_mask = NULL;
  virDomainNumatuneMemMode mem_mode;

  if ((period || quota) &&
      !virCgroupHasController(priv->cgroup, VIR_CGROUP_CONTROLLER_CPU)) {
    virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                   _("cgroup cpu is required for scheduler tuning"));
    return -1;
  }

  /*
   * If CPU cgroup controller is not initialized here, then we need
   * neither period nor quota settings.  And if CPUSET controller is
   * not initialized either, then there's nothing to do anyway.
   */
  if (!virCgroupHasController(priv->cgroup, VIR_CGROUP_CONTROLLER_CPU) &&
      !virCgroupHasController(priv->cgroup, VIR_CGROUP_CONTROLLER_CPUSET))
    return 0;

  if (virDomainNumatuneGetMode(vm->def->numa, -1, &mem_mode) == 0 &&
      mem_mode == VIR_DOMAIN_NUMATUNE_MEM_STRICT &&
      virDomainNumatuneMaybeFormatNodeset(vm->def->numa, priv->autoNodeset,
                                          &mem_mask, -1) < 0)
    return -1;

  if (period || quota) {
    if (chSetupCgroupVcpuBW(priv->cgroup, period, quota) < 0)
      return -1;
  }

  return 0;
}

int chRemoveCgroup(virDomainObj *vm) {
  virCHDomainObjPrivate *priv = vm->privateData;

  if (priv->cgroup == NULL)
    return 0; /* Not supported, so claim success */

  if (virCgroupTerminateMachine(priv->machineName) < 0) {
    if (!virCgroupNewIgnoreError())
      VIR_DEBUG("Failed to terminate cgroup for %s", vm->def->name);
  }

  return virCgroupRemove(priv->cgroup);
}

static void
chCgroupEmulatorAllNodesDataFree(chCgroupEmulatorAllNodesData *data) {
  if (!data)
    return;

  virCgroupFree(data->emulatorCgroup);
  VIR_FREE(data->emulatorMemMask);
  VIR_FREE(data);
}

/**
 * chCgroupEmulatorAllNodesAllow:
 * @cgroup: domain cgroup pointer
 * @retData: filled with structure used to roll back the operation
 *
 * Allows all NUMA nodes for the cloud hypervisor thread temporarily. This is
 * necessary when hotplugging cpus since it requires memory allocated in the
 * DMA region. Afterwards the operation can be reverted by
 * chCgroupEmulatorAllNodesRestore.
 *
 * Returns 0 on success -1 on error
 */
int chCgroupEmulatorAllNodesAllow(virCgroup *cgroup,
                                  chCgroupEmulatorAllNodesData **retData) {
  chCgroupEmulatorAllNodesData *data = NULL;
  g_autofree char *all_nodes_str = NULL;
  g_autoptr(virBitmap) all_nodes = NULL;
  int ret = -1;

  if (!virNumaIsAvailable() ||
      !virCgroupHasController(cgroup, VIR_CGROUP_CONTROLLER_CPUSET))
    return 0;

  if (!(all_nodes = virNumaGetHostMemoryNodeset()))
    goto cleanup;

  if (!(all_nodes_str = virBitmapFormat(all_nodes)))
    goto cleanup;

  data = g_new0(chCgroupEmulatorAllNodesData, 1);

  if (virCgroupNewThread(cgroup, VIR_CGROUP_THREAD_EMULATOR, 0, false,
                         &data->emulatorCgroup) < 0)
    goto cleanup;

  if (virCgroupGetCpusetMems(data->emulatorCgroup, &data->emulatorMemMask) <
          0 ||
      virCgroupSetCpusetMems(data->emulatorCgroup, all_nodes_str) < 0)
    goto cleanup;

  *retData = g_steal_pointer(&data);
  ret = 0;

  cleanup:
    chCgroupEmulatorAllNodesDataFree(data);

  return ret;
}

/**
 * chCgroupEmulatorAllNodesRestore:
 * @data: data structure created by chCgroupEmulatorAllNodesAllow
 *
 * Rolls back the setting done by chCgroupEmulatorAllNodesAllow and frees the
 * associated data.
 */
void chCgroupEmulatorAllNodesRestore(chCgroupEmulatorAllNodesData *data) {
  virError *err;

  if (!data)
    return;

  virErrorPreserveLast(&err);
  virCgroupSetCpusetMems(data->emulatorCgroup, data->emulatorMemMask);
  virErrorRestore(&err);

  chCgroupEmulatorAllNodesDataFree(data);
}
