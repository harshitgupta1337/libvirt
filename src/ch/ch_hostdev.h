/*
 * ch_hostdev.h: Cloud Hypervisor hostdev management
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

#pragma once

#include "ch_conf.h"
#include "domain_conf.h"

bool
chHostdevHostSupportsPassthroughVFIO(void);

bool
chHostdevNeedsVFIO(const virDomainHostdevDef *hostdev);

int
chHostdevPrepareNVMeDisks(virCHDriver *driver,
                          const char *name,
                          virDomainDiskDef **disks,
                          size_t ndisks);

int
chHostdevPreparePCIDevices(virCHDriver *driver,
                           const char *name,
                           const unsigned char *uuid,
                           virDomainHostdevDef **hostdevs,
                           int nhostdevs,
                           unsigned int flags);

int
chHostdevPrepareUSBDevices(virCHDriver *driver,
                           const char *name,
                           virDomainHostdevDef **hostdevs,
                           int nhostdevs,
                           unsigned int flags);


int
chHostdevPrepareUSBDevices(virCHDriver *driver,
                           const char *name,
                           virDomainHostdevDef **hostdevs,
                           int nhostdevs,
                           unsigned int flags);

int
chHostdevPrepareSCSIDevices(virCHDriver *driver,
                            const char *name,
                            virDomainHostdevDef **hostdevs,
                            int nhostdevs);

int
chHostdevPrepareSCSIVHostDevices(virCHDriver *driver,
                                 const char *name,
                                 virDomainHostdevDef **hostdevs,
                                 int nhostdevs);

int
chHostdevPrepareMediatedDevices(virCHDriver *driver,
                                const char *name,
                                virDomainHostdevDef **hostdevs,
                                int nhostdevs);
int
chHostdevPrepareDomainDevices(virCHDriver *driver,
                              virDomainDef *def,
                              unsigned int flags);

void
chHostdevReAttachOneNVMeDisk(virCHDriver *driver,
                             const char *name,
                             virStorageSource *src);

void
chHostdevReAttachNVMeDisks(virCHDriver *driver,
                           const char *name,
                           virDomainDiskDef **disks,
                           size_t ndisks);

void
chHostdevReAttachPCIDevices(virCHDriver *driver,
                            const char *name,
                            virDomainHostdevDef **hostdevs,
                            int nhostdevs);

void
chHostdevReAttachUSBDevices(virCHDriver *driver,
                            const char *name,
                            virDomainHostdevDef **hostdevs,
                            int nhostdevs);

void
chHostdevReAttachSCSIDevices(virCHDriver *driver,
                             const char *name,
                             virDomainHostdevDef **hostdevs,
                             int nhostdevs);

void
chHostdevReAttachSCSIVHostDevices(virCHDriver *driver,
                                    const char *name,
                                    virDomainHostdevDef **hostdevs,
                                    int nhostdevs);

void
chHostdevReAttachMediatedDevices(virCHDriver *driver,
                                 const char *name,
                                 virDomainHostdevDef **hostdevs,
                                 int nhostdevs);

void
chHostdevReAttachDomainDevices(virCHDriver *driver,
                               virDomainDef *def);
