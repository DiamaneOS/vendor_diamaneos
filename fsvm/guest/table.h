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
 * The filesystem VM reads the partition table of its disk (phase 2: Android's kernel does not). It reports the
 * partitions Android uses, with the filesystem found on each, as the LAYOUT reply (proto.h, layout.rs). Plain C
 * with no system calls, so the same code runs in the VM and in the host tests (table_test.c).
 */
#ifndef FSVM_TABLE_H
#define FSVM_TABLE_H

#include <stddef.h>
#include <stdint.h>

#include "proto.h"

/* Reads `len` bytes at byte offset `off` of the disk. Returns 0 on success. */
typedef int (*fsvm_read_fn)(void *ctx, uint64_t off, void *buf, size_t len);

struct fsvm_layout {
	struct fsvm_layout_header h;
	struct fsvm_layout_entry e[FSVM_MAX_LAYOUT_ENTRIES];
};

/*
 * Reads the layout of a disk of `disk_sectors` 512-byte sectors. Returns 0, or a negative errno when the table is
 * malformed or claims more than the protocol allows (the disk is then not served at all).
 */
int fsvm_read_layout(fsvm_read_fn rd, void *ctx, uint64_t disk_sectors, struct fsvm_layout *out);

/* Bytes of the layout reply. */
static inline uint32_t fsvm_layout_size(const struct fsvm_layout *l)
{
	return (uint32_t)(sizeof(l->h) + l->h.count * sizeof(l->e[0]));
}

/* Finds the public entry `index` at `start` and `length`, or NULL. */
const struct fsvm_layout_entry *fsvm_layout_find(const struct fsvm_layout *l, uint32_t index, uint64_t start,
						 uint64_t length);

#endif
