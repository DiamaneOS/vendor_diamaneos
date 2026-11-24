/*
 * Copyright (C) 2026 DiamaneOS
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * The filesystem VM's disks. A drive's VM has one virtio disk per public partition of the drive (each a range of its
 * own on Android), given at the VM's start, and the instance disk after them. Each connection names its disk in its
 * first request (FSVM_DISK), and /init runs one server process per connection, at most one per disk: a disk's
 * filesystem, its check and its read-only state belong to that one process. Plain C with no system calls, so the same
 * code runs in the VM and in the host tests (disks_test.c).
 */
#ifndef FSVM_DISKS_H
#define FSVM_DISKS_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "proto.h"

/* Most disks a VM serves (vold serves at most 4 public partitions of a drive). */
#define FSVM_MAX_DISKS 8u

/*
 * Checks the first request of a connection: FSVM_DISK with the host's protocol version in `node` and the disk index
 * in `arg`, nothing else set. 0 and the index in `index`, -EPROTO for another protocol version, -EINVAL otherwise
 * (also for any other first request, such as HELLO from a host of an older version).
 */
int fsvm_disk_request(const struct fsvm_req *q, uint32_t *index);

/* The device node of disk `index`: /dev/vda for 0, /dev/vdb for 1. 0, or -EINVAL. */
int fsvm_disk_path(uint32_t index, char *out, size_t size);

/* The server process of each disk, or 0. */
struct fsvm_servers {
	pid_t pid[FSVM_MAX_DISKS];
};

/* Records `pid` as the server of disk `index`, which must have none. 0, or -EBUSY. */
int fsvm_servers_set(struct fsvm_servers *s, uint32_t index, pid_t pid);

/* A process ended: the disk it served has no server any more. Its index, or -1 when it served none. */
int fsvm_servers_ended(struct fsvm_servers *s, pid_t pid);

#endif
