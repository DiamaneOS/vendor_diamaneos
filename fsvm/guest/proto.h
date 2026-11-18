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
 * The filesystem VM protocol, version 3, the guest's side. The definitions and limits mirror fsvm_proto
 * (proto/src/lib.rs), which is the reference. Little endian, one request and one reply.
 */
#ifndef FSVM_PROTO_H
#define FSVM_PROTO_H

#include <stdint.h>

#define FSVM_PORT 5690u
#define FSVM_VERSION 4u
#define FSVM_REQ_MAGIC 0x32564d46u /* "FMV2" */
#define FSVM_RSP_MAGIC 0x32524d46u /* "FMR2" */

enum {
	FSVM_HELLO = 1,
	FSVM_LOOKUP = 2,
	FSVM_GETATTR = 3,
	FSVM_READDIR = 4,
	FSVM_READ = 5,
	FSVM_WRITE = 6,
	FSVM_CREATE = 7,
	FSVM_MKDIR = 8,
	FSVM_UNLINK = 9,
	FSVM_RMDIR = 10,
	FSVM_RENAME = 11,
	FSVM_TRUNCATE = 12,
	FSVM_SETMTIME = 13,
	FSVM_STATFS = 14,
	FSVM_FSYNC = 15,
	FSVM_FORGET = 16,
	FSVM_LAYOUT = 17, /* the partitions this VM read from its disk (layout.rs) */
	FSVM_MOUNT = 18,  /* arg: partition index (0: whole disk), node: start, node2: length, flags bit 0: read-only,
			   * len: milliseconds the filesystem check may take (0: no check) */
	FSVM_UNMOUNT = 19, /* write everything back and unmount (the filesystem is marked clean), before a stop */
	FSVM_DIRTY = 20,   /* the bytes still to be written to the disk (u64): dirty plus under write back */
};
/* FSVM_FSYNC flags bit 0: data only (fdatasync). */
#define FSVM_FSYNC_DATA 1u

#define FSVM_MAX_IO (128u * 1024u)
#define FSVM_MAX_NAME 1020u
#define FSVM_MAX_DIR_PAYLOAD (64u * 1024u)
#define FSVM_MAX_DIR_PAGE_ENTRIES 512u

/* The node id of a listed name that has no slot (READDIR): Android looks it up before it uses it. */
#define FSVM_NODE_LISTED UINT64_MAX

#define FSVM_KIND_FILE 1u
#define FSVM_KIND_DIR 2u
#define FSVM_FS_VFAT 1u
#define FSVM_FS_EXFAT 2u

#define FSVM_TABLE_NONE 0u
#define FSVM_TABLE_MBR 1u
#define FSVM_TABLE_GPT 2u
#define FSVM_MAX_LAYOUT_ENTRIES 16u
#define FSVM_MAX_LABEL 47u

struct fsvm_req {
	uint32_t magic;
	uint16_t op;
	uint16_t flags;
	uint32_t id;
	uint32_t name_len;
	uint64_t node;
	uint64_t node2;
	uint64_t arg;
	uint32_t len;
	uint32_t name2_len;
} __attribute__((packed));

struct fsvm_rsp {
	uint32_t magic;
	uint32_t id;
	int32_t status;
	uint32_t len;
} __attribute__((packed));

struct fsvm_attr {
	uint64_t node;
	uint64_t size;
	int64_t mtime_s;
	uint32_t mtime_ns;
	uint8_t kind;
	uint8_t pad[3];
} __attribute__((packed));

struct fsvm_hello {
	uint32_t version;
	uint32_t fs_kind;
	uint32_t flags; /* bit 0: mounted read-only, bit 1: the filesystem was marked dirty when mounted */
	uint32_t reserved;
	uint64_t root;
} __attribute__((packed));

struct fsvm_statfs {
	uint64_t blocks;
	uint64_t bfree;
	uint64_t bavail;
	uint32_t bsize;
	uint32_t namemax;
} __attribute__((packed));

struct fsvm_dir_page {
	uint64_t next_cookie;
	uint32_t count;
	uint32_t reserved;
} __attribute__((packed));

struct fsvm_layout_header {
	uint64_t disk_sectors;
	uint32_t table;
	uint32_t count;
	uint8_t reserved[16];
} __attribute__((packed));

struct fsvm_layout_entry {
	uint32_t index;
	uint32_t flags; /* bit 0: serial is valid */
	uint64_t start;
	uint64_t length;
	uint8_t mbr_type;
	uint8_t pad[3];
	uint8_t type_guid[16];
	uint8_t part_guid[16];
	uint32_t fs_kind;
	uint32_t serial;
	uint64_t meta_bytes;
	uint8_t label_len;
	uint8_t label[FSVM_MAX_LABEL];
	uint8_t reserved[4];
} __attribute__((packed));

_Static_assert(sizeof(struct fsvm_req) == 48, "request header");
_Static_assert(sizeof(struct fsvm_layout_header) == 32, "layout header");
_Static_assert(sizeof(struct fsvm_layout_entry) == 128, "layout entry");
_Static_assert(sizeof(struct fsvm_rsp) == 16, "reply header");
_Static_assert(sizeof(struct fsvm_attr) == 32, "attr");
_Static_assert(sizeof(struct fsvm_hello) == 24, "hello");
_Static_assert(sizeof(struct fsvm_statfs) == 32, "statfs");
_Static_assert(sizeof(struct fsvm_dir_page) == 16, "dir page");

#endif
