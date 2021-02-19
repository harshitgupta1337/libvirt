/*
 * ch_hostdev.c: Cloud Hypervisor hostdev management
 *
 * Copyright (C) 2021 Wei Liu <liuwe@microsoft.com>
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
#include <sys/ioctl.h>

#include "ch_hostdev.h"
#include "ch_domain.h"
#include "virlog.h"
#include "virerror.h"
#include "viralloc.h"
#include "virpci.h"
#include "virusb.h"
#include "virscsi.h"
#include "virnetdev.h"
#include "virfile.h"
#include "virhostdev.h"
#include "virutil.h"

#define VIR_FROM_THIS VIR_FROM_CH

VIR_LOG_INIT("ch.ch_hostdev");

bool
chHostdevHostSupportsPassthroughVFIO(void)
{
    /* condition 1 - host has IOMMU */
    if (!virHostHasIOMMU())
        return false;

    /* condition 2 - /dev/vfio/vfio exists */
    if (!virFileExists(CH_DEV_VFIO))
        return false;

    return true;
}

bool
chHostdevNeedsVFIO(const virDomainHostdevDef *hostdev)
{
    return virHostdevIsVFIODevice(hostdev) ||
        virHostdevIsMdevDevice(hostdev);
}

static bool
chHostdevPreparePCIDevicesCheckSupport(virDomainHostdevDef **hostdevs,
                                       size_t nhostdevs)
{
    bool supportsPassthroughVFIO = chHostdevHostSupportsPassthroughVFIO();
    size_t i;

    /* assign defaults for hostdev passthrough */
    for (i = 0; i < nhostdevs; i++) {
        virDomainHostdevDef *hostdev = hostdevs[i];
        virDomainHostdevSubsysPCIBackendType *backend =
                    &hostdev->source.subsys.u.pci.backend;

        if (hostdev->mode != VIR_DOMAIN_HOSTDEV_MODE_SUBSYS)
            continue;
        if (hostdev->source.subsys.type != VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI)
            continue;

        switch ((virDomainHostdevSubsysPCIBackendType)*backend) {
        case VIR_DOMAIN_HOSTDEV_PCI_BACKEND_DEFAULT:
            if (supportsPassthroughVFIO) {
                *backend = VIR_DOMAIN_HOSTDEV_PCI_BACKEND_VFIO;
            } else {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("host doesn't support passthrough of "
                                 "host PCI devices"));
                return false;
            }

            break;

        case VIR_DOMAIN_HOSTDEV_PCI_BACKEND_VFIO:
            if (!supportsPassthroughVFIO) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("host doesn't support VFIO PCI passthrough"));
                return false;
            }
            break;

        case VIR_DOMAIN_HOSTDEV_PCI_BACKEND_KVM:
        case VIR_DOMAIN_HOSTDEV_PCI_BACKEND_XEN:
        case VIR_DOMAIN_HOSTDEV_PCI_BACKEND_TYPE_LAST:
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s%s",
                           _("host doesn't support passthrough: "),
                           _(virDomainHostdevSubsysPCIBackendTypeToString(*backend)));
            return false;
        }
    }

    return true;
}

int
chHostdevPrepareNVMeDisks(virCHDriver *driver,
                          const char *name,
                          virDomainDiskDef **disks,
                          size_t ndisks)
{
    return virHostdevPrepareNVMeDevices(driver->hostdevMgr,
                                        CH_DRIVER_NAME,
                                        name, disks, ndisks);
}

int
chHostdevPreparePCIDevices(virCHDriver *driver,
                           const char *name,
                           const unsigned char *uuid,
                           virDomainHostdevDef **hostdevs,
                           int nhostdevs,
                           unsigned int flags)
{
    virHostdevManager *hostdev_mgr = driver->hostdevMgr;

    if (!chHostdevPreparePCIDevicesCheckSupport(hostdevs, nhostdevs))
        return -1;

    return virHostdevPreparePCIDevices(hostdev_mgr, CH_DRIVER_NAME,
                                       name, uuid, hostdevs,
                                       nhostdevs, flags);
}

int
chHostdevPrepareUSBDevices(virCHDriver *driver,
                           const char *name,
                           virDomainHostdevDef **hostdevs,
                           int nhostdevs,
                           unsigned int flags)
{
    virHostdevManager *hostdev_mgr = driver->hostdevMgr;

    return virHostdevPrepareUSBDevices(hostdev_mgr, CH_DRIVER_NAME, name,
                                       hostdevs, nhostdevs, flags);
}

int
chHostdevPrepareSCSIDevices(virCHDriver *driver,
                            const char *name,
                            virDomainHostdevDef **hostdevs,
                            int nhostdevs)
{
    virHostdevManager *hostdev_mgr = driver->hostdevMgr;

    return virHostdevPrepareSCSIDevices(hostdev_mgr, CH_DRIVER_NAME,
                                        name, hostdevs, nhostdevs);
}

int
chHostdevPrepareSCSIVHostDevices(virCHDriver *driver,
                                 const char *name,
                                 virDomainHostdevDef **hostdevs,
                                 int nhostdevs)
{
    virHostdevManager *hostdev_mgr = driver->hostdevMgr;

    return virHostdevPrepareSCSIVHostDevices(hostdev_mgr, CH_DRIVER_NAME,
                                             name, hostdevs, nhostdevs);
}

int
chHostdevPrepareMediatedDevices(virCHDriver *driver,
                                const char *name,
                                virDomainHostdevDef **hostdevs,
                                int nhostdevs)
{
    virHostdevManager *hostdev_mgr = driver->hostdevMgr;
    bool supportsVFIO;
    size_t i;

    /* Checking for VFIO only is fine with mdev, as IOMMU isolation is achieved
     * by the physical parent device.
     */
    supportsVFIO = virFileExists(CH_DEV_VFIO);

    for (i = 0; i < nhostdevs; i++) {
        if (virHostdevIsMdevDevice(hostdevs[i])) {
            if (!supportsVFIO) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("Mediated host device assignment requires "
                                 "VFIO support"));
                return -1;
            }
            break;
        }
    }

    return virHostdevPrepareMediatedDevices(hostdev_mgr, CH_DRIVER_NAME,
                                            name, hostdevs, nhostdevs);
}

int
chHostdevPrepareDomainDevices(virCHDriver *driver,
                              virDomainDef *def,
                              unsigned int flags)

{
    if (!def->nhostdevs && !def->ndisks)
        return 0;

    if (chHostdevPrepareNVMeDisks(driver, def->name, def->disks, def->ndisks) < 0)
        return -1;

    if (chHostdevPreparePCIDevices(driver, def->name, def->uuid,
                                   def->hostdevs, def->nhostdevs,
                                   flags) < 0)
        return -1;

    if (chHostdevPrepareUSBDevices(driver, def->name,
                                   def->hostdevs, def->nhostdevs, flags) < 0)
        return -1;

    if (chHostdevPrepareSCSIDevices(driver, def->name,
                                    def->hostdevs, def->nhostdevs) < 0)
        return -1;

    if (chHostdevPrepareSCSIVHostDevices(driver, def->name,
                                         def->hostdevs, def->nhostdevs) < 0)
        return -1;

    if (chHostdevPrepareMediatedDevices(driver, def->name,
                                        def->hostdevs, def->nhostdevs) < 0)
        return -1;

    return 0;
}

void
chHostdevReAttachOneNVMeDisk(virCHDriver *driver,
                             const char *name,
                             virStorageSource *src)
{
    virHostdevReAttachOneNVMeDevice(driver->hostdevMgr,
                                    CH_DRIVER_NAME,
                                    name,
                                    src);
}

void
chHostdevReAttachNVMeDisks(virCHDriver *driver,
                           const char *name,
                           virDomainDiskDef **disks,
                           size_t ndisks)
{
    virHostdevReAttachNVMeDevices(driver->hostdevMgr,
                                  CH_DRIVER_NAME,
                                  name, disks, ndisks);
}

void
chHostdevReAttachPCIDevices(virCHDriver *driver,
                            const char *name,
                            virDomainHostdevDef **hostdevs,
                            int nhostdevs)
{
    virCHDriverConfig *cfg = virCHDriverGetConfig(driver);
    virHostdevManager *hostdev_mgr = driver->hostdevMgr;

    virHostdevReAttachPCIDevices(hostdev_mgr, CH_DRIVER_NAME, name,
                                 hostdevs, nhostdevs);

    virObjectUnref(cfg);
}

void
chHostdevReAttachUSBDevices(virCHDriver *driver,
                            const char *name,
                            virDomainHostdevDef **hostdevs,
                            int nhostdevs)
{
    virHostdevManager *hostdev_mgr = driver->hostdevMgr;

    virHostdevReAttachUSBDevices(hostdev_mgr, CH_DRIVER_NAME,
                                 name, hostdevs, nhostdevs);
}

void
chHostdevReAttachSCSIDevices(virCHDriver *driver,
                             const char *name,
                             virDomainHostdevDef **hostdevs,
                             int nhostdevs)
{
    virHostdevManager *hostdev_mgr = driver->hostdevMgr;

    virHostdevReAttachSCSIDevices(hostdev_mgr, CH_DRIVER_NAME,
                                  name, hostdevs, nhostdevs);
}

void
chHostdevReAttachSCSIVHostDevices(virCHDriver *driver,
                                    const char *name,
                                    virDomainHostdevDef **hostdevs,
                                    int nhostdevs)
{
    virHostdevManager *hostdev_mgr = driver->hostdevMgr;

    virHostdevReAttachSCSIVHostDevices(hostdev_mgr, CH_DRIVER_NAME,
                                       name, hostdevs, nhostdevs);
}

void
chHostdevReAttachMediatedDevices(virCHDriver *driver,
                                 const char *name,
                                 virDomainHostdevDef **hostdevs,
                                 int nhostdevs)
{
    virHostdevManager *hostdev_mgr = driver->hostdevMgr;

    virHostdevReAttachMediatedDevices(hostdev_mgr, CH_DRIVER_NAME,
                                      name, hostdevs, nhostdevs);
}

void
chHostdevReAttachDomainDevices(virCHDriver *driver,
                               virDomainDef *def)
{
    if (!def->nhostdevs && !def->ndisks)
        return;

    chHostdevReAttachNVMeDisks(driver, def->name, def->disks,
                               def->ndisks);

    chHostdevReAttachPCIDevices(driver, def->name, def->hostdevs,
                                def->nhostdevs);

    chHostdevReAttachUSBDevices(driver, def->name, def->hostdevs,
                                def->nhostdevs);

    chHostdevReAttachSCSIDevices(driver, def->name, def->hostdevs,
                                 def->nhostdevs);

    chHostdevReAttachSCSIVHostDevices(driver, def->name, def->hostdevs,
                                      def->nhostdevs);

    chHostdevReAttachMediatedDevices(driver, def->name, def->hostdevs,
                                     def->nhostdevs);
}
