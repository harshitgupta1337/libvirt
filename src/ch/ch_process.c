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

#include <unistd.h>
#include <fcntl.h>
#include "datatypes.h"

#include "ch_domain.h"
#include "ch_interface.h"
#include "ch_monitor.h"
#include "ch_process.h"
#include "viralloc.h"
#include "virerror.h"
#include "virlog.h"

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

/**
 * chProcessNetworkPrepareDevices
 */
static int
chProcessNetworkPrepareDevices(virCHDriverPtr driver, virDomainObjPtr vm)
{
    virDomainDefPtr def = vm->def;
    size_t i;
    virCHDomainObjPrivatePtr priv = vm->privateData;
    g_autoptr(virConnect) conn = NULL;
    char **tapfdName = NULL;
    int *tapfd = NULL;
    size_t tapfdSize = 0;

    for (i = 0; i < def->nnets; i++) {
        virDomainNetDefPtr net = def->nets[i];
        virDomainNetType actualType;

        /* If appropriate, grab a physical device from the configured
         * network's pool of devices, or resolve bridge device name
         * to the one defined in the network definition.
         */
        if (net->type == VIR_DOMAIN_NET_TYPE_NETWORK) {
            if (!conn && !(conn = virGetConnectNetwork())){
                return -1;}
            if (virDomainNetAllocateActualDevice(conn, def, net) < 0){
                return -1;}
        }

        actualType = virDomainNetGetActualType(net);
        if (actualType == VIR_DOMAIN_NET_TYPE_HOSTDEV &&
            net->type == VIR_DOMAIN_NET_TYPE_NETWORK) {
            /* Each type='hostdev' network device must also have a
             * corresponding entry in the hostdevs array. For netdevs
             * that are hardcoded as type='hostdev', this is already
             * done by the parser, but for those allocated from a
             * network / determined at runtime, we need to do it
             * separately.
             */
            virDomainHostdevDefPtr hostdev = virDomainNetGetActualHostdev(net);
            virDomainHostdevSubsysPCIPtr pcisrc = &hostdev->source.subsys.u.pci;

            if (virDomainHostdevFind(def, hostdev, NULL) >= 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("PCI device %04x:%02x:%02x.%x "
                                 "allocated from network %s is already "
                                 "in use by domain %s"),
                               pcisrc->addr.domain, pcisrc->addr.bus,
                               pcisrc->addr.slot, pcisrc->addr.function,
                               net->data.network.name, def->name);
                return -1;
            }
            if (virDomainHostdevInsert(def, hostdev) < 0)
                return -1;
        } else if (actualType == VIR_DOMAIN_NET_TYPE_USER ) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
              _("VIR_DOMAIN_NET_TYPE_USER is not a supported Network type"));
         } else if (actualType == VIR_DOMAIN_NET_TYPE_NETWORK ) {
            tapfdSize = net->driver.virtio.queues;
            if (!tapfdSize)
                tapfdSize = 2; //This needs to be at least 2, based on
                // https://github.com/cloud-hypervisor/cloud-hypervisor/blob/master/docs/networking.md

            if (VIR_ALLOC_N(tapfd, tapfdSize) < 0 ||
                VIR_ALLOC_N(tapfdName, tapfdSize) < 0)
                goto cleanup;

            memset(tapfd, -1, tapfdSize * sizeof(tapfd[0]));

            if (chInterfaceBridgeConnect(def, driver,  net,
                                       tapfd, &tapfdSize) < 0)
                goto cleanup;

            // Store tap information in Private Data
            // This info will be used while generating Network Json
            priv->tapfd = g_steal_pointer(&tapfd);
            priv->tapfdSize = tapfdSize;
         }
    }

return 0;

cleanup:
    VIR_FREE(tapfd);
    VIR_FREE(tapfdName);
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
int virCHProcessStart(virCHDriver *driver,
                      virDomainObj *vm,
                      virDomainRunningReason reason)
{
    int ret = -1;
    virCHDomainObjPrivate *priv = vm->privateData;

    /* network devices must be "prepared" before hostdevs, because
     * setting up a network device might create a new hostdev that
     * will need to be setup.
     */
    VIR_DEBUG("Preparing network devices");
    if (chProcessNetworkPrepareDevices(driver, vm) < 0)
        goto cleanup;

    if (!priv->monitor) {
        /* And we can get the first monitor connection now too */
        if (!(priv->monitor = virCHProcessConnectMonitor(driver, vm))) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                        _("failed to create connection to CH socket"));
            goto cleanup;
        }

        if (virCHMonitorCreateVM(priv->monitor) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                        _("failed to create guest VM"));
            goto cleanup;
        }
    }

    if (virCHMonitorBootVM(priv->monitor) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("failed to boot guest VM"));
        goto cleanup;
    }

    vm->pid = priv->monitor->pid;
    vm->def->id = vm->pid;
    virDomainObjSetState(vm, VIR_DOMAIN_RUNNING, reason);

    return 0;

 cleanup:
    if (ret)
        virCHProcessStop(driver, vm, VIR_DOMAIN_SHUTOFF_FAILED);

    return ret;
}

int virCHProcessStop(virCHDriver *driver G_GNUC_UNUSED,
                     virDomainObj *vm,
                     virDomainShutoffReason reason)
{
    virCHDomainObjPrivate *priv = vm->privateData;

    VIR_DEBUG("Stopping VM name=%s pid=%d reason=%d",
              vm->def->name, (int)vm->pid, (int)reason);

    if (priv->monitor) {
        virCHMonitorClose(priv->monitor);
        priv->monitor = NULL;
    }

    vm->pid = -1;
    vm->def->id = -1;

    virDomainObjSetState(vm, VIR_DOMAIN_SHUTOFF, reason);

    return 0;
}
