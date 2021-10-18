/*
 * ch_cgroup.h: CH cgroup management
 *
 * Copyright Microsoft Corp. 2020-2021
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

#include "virusb.h"
#include "vircgroup.h"
#include "domain_conf.h"
#include "ch_conf.h"

int chConnectCgroup(virDomainObj * vm);
int chSetupCgroup(virDomainObj * vm, size_t nnicindexes, int *nicindexes);
int chSetupCgroupVcpuBW(virCgroup * cgroup,
                        unsigned long long period, long long quota);
int chSetupCgroupCpusetCpus(virCgroup * cgroup, virBitmap * cpumask);
int chSetupGlobalCpuCgroup(virDomainObj * vm);
int chRemoveCgroup(virDomainObj * vm);

typedef struct _chCgroupEmulatorAllNodesData chCgroupEmulatorAllNodesData;

struct _chCgroupEmulatorAllNodesData {
    virCgroup *emulatorCgroup;
    char *emulatorMemMask;
};

int chCgroupEmulatorAllNodesAllow(virCgroup * cgroup,
                                  chCgroupEmulatorAllNodesData ** data);
void chCgroupEmulatorAllNodesRestore(chCgroupEmulatorAllNodesData * data);
