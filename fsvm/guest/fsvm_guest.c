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
 * /init of the filesystem VM. Its first virtio disk is a whole SD card or USB disk, or an OBB image (Android's kernel
 * reads none of their partition tables or filesystems). It serves protocol version 3 (proto.h) over vsock: LAYOUT
 * reports the partitions read from the disk (table.c), MOUNT mounts one FAT or exFAT filesystem, once, and the file
 * operations then serve it. Android checks every reply, so this program's job is to be correct, not to defend
 * Android: if a crafted filesystem takes over this VM's kernel, the VM is lost but Android is not.
 *
 * Static, single threaded, PID 1. It never returns.
 */
#include "proto.h"
#include "table.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/vm_sockets.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define MNT "/mnt"
#define MAX_NODES 65536u
#define HASH_SIZE 131072u /* power of two, at least twice MAX_NODES */

#define DISK "/dev/vda"

static uint32_t fs_kind; /* 0 until MOUNT succeeded */
static int read_only;
static uint32_t mounted_index;
static uint64_t mounted_start, mounted_length;
static uint64_t disk_sectors;
static int layout_state; /* 0 not read, 1 read, negative errno */
static struct fsvm_layout layout;

static void logline(const char *what, const char *detail, int err)
{
	char line[256];
	int n = snprintf(line, sizeof(line), "fsvm: %s %s %s\n", what, detail ? detail : "", err ? strerror(err) : "");
	if (n > 0)
		(void)!write(2, line, (size_t)n < sizeof(line) ? (size_t)n : sizeof(line) - 1);
}

/* ---- Node table: node number <-> path below MNT ("" is the root, node 1). ---- */

static char *node_path[MAX_NODES + 1];
static uint32_t hash_slot[HASH_SIZE]; /* node number, 0 = empty, UINT32_MAX = deleted */
static uint32_t next_free = 2;

static uint32_t hash_str(const char *s)
{
	uint32_t h = 2166136261u;
	while (*s)
		h = (h ^ (uint8_t)*s++) * 16777619u;
	return h;
}

static uint32_t node_find(const char *path)
{
	uint32_t i = hash_str(path) & (HASH_SIZE - 1);
	for (uint32_t probe = 0; probe < HASH_SIZE; probe++, i = (i + 1) & (HASH_SIZE - 1)) {
		uint32_t n = hash_slot[i];
		if (n == 0)
			return 0;
		if (n != UINT32_MAX && node_path[n] && strcmp(node_path[n], path) == 0)
			return n;
	}
	return 0;
}

static void slot_remove(uint32_t node)
{
	uint32_t i = hash_str(node_path[node]) & (HASH_SIZE - 1);
	for (uint32_t probe = 0; probe < HASH_SIZE; probe++, i = (i + 1) & (HASH_SIZE - 1)) {
		if (hash_slot[i] == 0)
			return;
		if (hash_slot[i] == node) {
			hash_slot[i] = UINT32_MAX;
			return;
		}
	}
}

static void slot_insert(uint32_t node)
{
	uint32_t i = hash_str(node_path[node]) & (HASH_SIZE - 1);
	while (hash_slot[i] != 0 && hash_slot[i] != UINT32_MAX)
		i = (i + 1) & (HASH_SIZE - 1);
	hash_slot[i] = node;
}

static void node_drop(uint32_t node)
{
	if (node <= 1 || node > MAX_NODES || !node_path[node])
		return;
	slot_remove(node);
	free(node_path[node]);
	node_path[node] = NULL;
}

/* Returns the node for a path, adding it if new. 0 when the table is full. */
static uint32_t node_get(const char *path)
{
	uint32_t n = node_find(path);
	if (n)
		return n;
	for (uint32_t tries = 0; tries < MAX_NODES; tries++) {
		uint32_t c = next_free;
		next_free = next_free >= MAX_NODES ? 2 : next_free + 1;
		if (!node_path[c]) {
			node_path[c] = strdup(path);
			if (!node_path[c])
				return 0;
			slot_insert(c);
			return c;
		}
	}
	return 0;
}

static const char *path_of(uint64_t node)
{
	if (node == 0 || node > MAX_NODES)
		return NULL;
	return node_path[node];
}

/* Builds MNT/<path>[/<name>] into out. */
static int full_path(char *out, size_t size, const char *path, const char *name)
{
	int n;
	if (name)
		n = snprintf(out, size, "%s%s%s/%s", MNT, *path ? "/" : "", path, name);
	else
		n = snprintf(out, size, "%s%s%s", MNT, *path ? "/" : "", path);
	return n > 0 && (size_t)n < size ? 0 : -ENAMETOOLONG;
}

static int child_path(char *out, size_t size, const char *path, const char *name)
{
	int n = *path ? snprintf(out, size, "%s/%s", path, name) : snprintf(out, size, "%s", name);
	return n > 0 && (size_t)n < size ? 0 : -ENAMETOOLONG;
}

/* After a rename, moves every node at or below `from` to `to`. */
static void node_rename(const char *from, const char *to)
{
	size_t fl = strlen(from);
	uint32_t target = node_find(to);
	if (target)
		node_drop(target);
	for (uint32_t n = 2; n <= MAX_NODES; n++) {
		char *p = node_path[n];
		if (!p || strncmp(p, from, fl) != 0 || (p[fl] != 0 && p[fl] != '/'))
			continue;
		char next[PATH_MAX];
		if (snprintf(next, sizeof(next), "%s%s", to, p + fl) >= (int)sizeof(next)) {
			node_drop(n);
			continue;
		}
		slot_remove(n);
		free(p);
		node_path[n] = strdup(next);
		if (node_path[n])
			slot_insert(n);
	}
}

/* Drops every node at or below `path` (after unlink or rmdir). */
static void node_unlink(const char *path)
{
	size_t l = strlen(path);
	for (uint32_t n = 2; n <= MAX_NODES; n++) {
		char *p = node_path[n];
		if (p && strncmp(p, path, l) == 0 && (p[l] == 0 || p[l] == '/'))
			node_drop(n);
	}
}

/* ---- I/O helpers ---- */

static int read_full(int fd, void *buf, size_t n)
{
	uint8_t *p = buf;
	while (n) {
		ssize_t r = read(fd, p, n);
		if (r < 0 && errno == EINTR)
			continue;
		if (r <= 0)
			return -1;
		p += r;
		n -= (size_t)r;
	}
	return 0;
}

static int write_full(int fd, const void *buf, size_t n)
{
	const uint8_t *p = buf;
	while (n) {
		ssize_t r = write(fd, p, n);
		if (r < 0 && errno == EINTR)
			continue;
		if (r <= 0)
			return -1;
		p += r;
		n -= (size_t)r;
	}
	return 0;
}

static int reply(int s, uint32_t id, int32_t status, const void *payload, uint32_t len)
{
	struct fsvm_rsp h = { FSVM_RSP_MAGIC, id, status, status < 0 ? 0 : len };
	if (write_full(s, &h, sizeof(h)))
		return -1;
	if (status >= 0 && len)
		return write_full(s, payload, len);
	return 0;
}

static int fill_attr(const char *rel, uint32_t node, struct fsvm_attr *a)
{
	char p[PATH_MAX];
	struct stat st;
	int r = full_path(p, sizeof(p), rel, NULL);
	if (r)
		return r;
	if (lstat(p, &st))
		return -errno;
	memset(a, 0, sizeof(*a));
	if (S_ISREG(st.st_mode))
		a->kind = FSVM_KIND_FILE;
	else if (S_ISDIR(st.st_mode))
		a->kind = FSVM_KIND_DIR;
	else
		return -ENOENT; /* FAT and exFAT hold nothing else */
	a->node = node;
	a->size = a->kind == FSVM_KIND_FILE ? (uint64_t)st.st_size : 0;
	a->mtime_s = st.st_mtim.tv_sec;
	a->mtime_ns = (uint32_t)st.st_mtim.tv_nsec;
	return 0;
}

static int name_ok(const char *name, uint32_t len)
{
	if (len == 0 || len > FSVM_MAX_NAME || memchr(name, '/', len) || strlen(name) != len)
		return 0;
	return strcmp(name, ".") && strcmp(name, "..");
}

/* ---- Requests ---- */

static uint8_t inbuf[FSVM_MAX_IO + 2 * FSVM_MAX_NAME + 2];
static uint8_t outbuf[FSVM_MAX_IO > FSVM_MAX_DIR_PAYLOAD ? FSVM_MAX_IO : FSVM_MAX_DIR_PAYLOAD];

static int attr_reply(int s, uint32_t id, const char *rel)
{
	struct fsvm_attr a;
	uint32_t node = node_get(rel);
	if (!node)
		return reply(s, id, -ENOMEM, NULL, 0);
	int r = fill_attr(rel, node, &a);
	if (r) {
		if (r == -ENOENT)
			node_drop(node);
		return reply(s, id, r, NULL, 0);
	}
	return reply(s, id, 0, &a, sizeof(a));
}

static int do_readdir(int s, const struct fsvm_req *q, const char *rel)
{
	char p[PATH_MAX];
	int r = full_path(p, sizeof(p), rel, NULL);
	if (r)
		return reply(s, q->id, r, NULL, 0);
	DIR *d = opendir(p);
	if (!d)
		return reply(s, q->id, -errno, NULL, 0);
	struct fsvm_dir_page *page = (struct fsvm_dir_page *)outbuf;
	uint32_t used = sizeof(*page), count = 0;
	uint64_t index = 0, next = 0;
	struct dirent *e;
	while ((e = readdir(d))) {
		if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, ".."))
			continue;
		if (index++ < q->arg)
			continue;
		size_t nl = strlen(e->d_name);
		if (nl > FSVM_MAX_NAME)
			continue;
		if (count == FSVM_MAX_DIR_PAGE_ENTRIES || used + sizeof(struct fsvm_attr) + 2 + nl > FSVM_MAX_DIR_PAYLOAD) {
			next = index - 1;
			break;
		}
		char child[PATH_MAX];
		if (child_path(child, sizeof(child), rel, e->d_name))
			continue;
		uint32_t node = node_get(child);
		struct fsvm_attr a;
		if (!node || fill_attr(child, node, &a))
			continue;
		uint16_t l16 = (uint16_t)nl;
		memcpy(outbuf + used, &a, sizeof(a));
		memcpy(outbuf + used + sizeof(a), &l16, 2);
		memcpy(outbuf + used + sizeof(a) + 2, e->d_name, nl);
		used += sizeof(a) + 2 + (uint32_t)nl;
		count++;
	}
	closedir(d);
	/* Cookies count entries, so they always move forward. */
	page->next_cookie = next;
	page->count = count;
	page->reserved = 0;
	return reply(s, q->id, 0, outbuf, used);
}

static int do_read(int s, const struct fsvm_req *q, const char *rel)
{
	char p[PATH_MAX];
	uint32_t want = q->len > FSVM_MAX_IO ? FSVM_MAX_IO : q->len;
	int r = full_path(p, sizeof(p), rel, NULL);
	if (r)
		return reply(s, q->id, r, NULL, 0);
	int fd = open(p, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
	if (fd < 0)
		return reply(s, q->id, -errno, NULL, 0);
	uint32_t got = 0;
	while (got < want) {
		ssize_t n = pread(fd, outbuf + got, want - got, (off_t)(q->arg + got));
		if (n < 0 && errno == EINTR)
			continue;
		if (n < 0) {
			int e = errno;
			close(fd);
			return reply(s, q->id, -e, NULL, 0);
		}
		if (n == 0)
			break;
		got += (uint32_t)n;
	}
	close(fd);
	return reply(s, q->id, 0, outbuf, got);
}

static int do_write(int s, const struct fsvm_req *q, const char *rel, const uint8_t *data)
{
	char p[PATH_MAX];
	if (read_only)
		return reply(s, q->id, -EROFS, NULL, 0);
	int r = full_path(p, sizeof(p), rel, NULL);
	if (r)
		return reply(s, q->id, r, NULL, 0);
	int fd = open(p, O_WRONLY | O_NOFOLLOW | O_CLOEXEC);
	if (fd < 0)
		return reply(s, q->id, -errno, NULL, 0);
	uint32_t done = 0;
	while (done < q->len) {
		ssize_t n = pwrite(fd, data + done, q->len - done, (off_t)(q->arg + done));
		if (n < 0 && errno == EINTR)
			continue;
		if (n <= 0)
			break;
		done += (uint32_t)n;
	}
	int e = done == 0 && q->len ? errno : 0;
	close(fd);
	if (e)
		return reply(s, q->id, -e, NULL, 0);
	uint32_t out[2] = { done, 0 };
	return reply(s, q->id, 0, out, sizeof(out));
}

static int read_layout(void);
static int do_mount(uint32_t index, uint64_t start, uint64_t length, int want_ro);

static int handle(int s, struct fsvm_req *q, const char *name, const char *name2, const uint8_t *data)
{
	char p[PATH_MAX], p2[PATH_MAX], rel[PATH_MAX], rel2[PATH_MAX];
	const char *base = path_of(q->node);
	int r;

	switch (q->op) {
	case FSVM_HELLO: {
		struct fsvm_hello h = { FSVM_VERSION, fs_kind, read_only ? 1u : 0u, 0, 1 };
		return reply(s, q->id, 0, &h, sizeof(h));
	}
	case FSVM_LAYOUT:
		r = read_layout();
		if (r)
			return reply(s, q->id, r, NULL, 0);
		return reply(s, q->id, 0, &layout, fsvm_layout_size(&layout));
	case FSVM_MOUNT: {
		if (q->arg > UINT32_MAX)
			return reply(s, q->id, -EINVAL, NULL, 0);
		r = do_mount((uint32_t)q->arg, q->node, q->node2, q->flags & 1);
		if (r)
			return reply(s, q->id, r, NULL, 0);
		struct fsvm_hello h = { FSVM_VERSION, fs_kind, read_only ? 1u : 0u, 0, 1 };
		return reply(s, q->id, 0, &h, sizeof(h));
	}
	default:
		break;
	}

	/* Everything below needs the mounted volume. */
	if (!fs_kind)
		return reply(s, q->id, -EINVAL, NULL, 0);
	if (q->op != FSVM_STATFS && !base)
		return reply(s, q->id, -ENOENT, NULL, 0);

	switch (q->op) {
	case FSVM_LOOKUP:
		if (child_path(rel, sizeof(rel), base, name))
			return reply(s, q->id, -ENAMETOOLONG, NULL, 0);
		return attr_reply(s, q->id, rel);
	case FSVM_GETATTR:
		return attr_reply(s, q->id, base);
	case FSVM_READDIR:
		return do_readdir(s, q, base);
	case FSVM_READ:
		return do_read(s, q, base);
	case FSVM_WRITE:
		return do_write(s, q, base, data);
	case FSVM_STATFS: {
		struct statfs sf;
		if (statfs(MNT, &sf))
			return reply(s, q->id, -errno, NULL, 0);
		struct fsvm_statfs o = { sf.f_blocks, sf.f_bfree, sf.f_bavail, (uint32_t)sf.f_bsize, 255 };
		return reply(s, q->id, 0, &o, sizeof(o));
	}
	case FSVM_FORGET:
		if (q->node > 1)
			node_drop((uint32_t)q->node);
		return reply(s, q->id, 0, NULL, 0);
	default:
		break;
	}

	/* Everything below changes the volume. */
	if (read_only)
		return reply(s, q->id, -EROFS, NULL, 0);
	switch (q->op) {
	case FSVM_CREATE:
	case FSVM_MKDIR:
	case FSVM_UNLINK:
	case FSVM_RMDIR:
		if (child_path(rel, sizeof(rel), base, name) || full_path(p, sizeof(p), base, name))
			return reply(s, q->id, -ENAMETOOLONG, NULL, 0);
		if (q->op == FSVM_CREATE) {
			int fd = open(p, O_CREAT | O_WRONLY | O_NOFOLLOW | O_CLOEXEC | (q->flags & 1 ? O_EXCL : 0), 0660);
			if (fd < 0)
				return reply(s, q->id, -errno, NULL, 0);
			close(fd);
			return attr_reply(s, q->id, rel);
		}
		if (q->op == FSVM_MKDIR) {
			if (mkdir(p, 0770))
				return reply(s, q->id, -errno, NULL, 0);
			return attr_reply(s, q->id, rel);
		}
		r = q->op == FSVM_UNLINK ? unlink(p) : rmdir(p);
		if (r)
			return reply(s, q->id, -errno, NULL, 0);
		node_unlink(rel);
		return reply(s, q->id, 0, NULL, 0);
	case FSVM_RENAME: {
		const char *base2 = path_of(q->node2);
		if (!base2)
			return reply(s, q->id, -ENOENT, NULL, 0);
		if (child_path(rel, sizeof(rel), base, name) || child_path(rel2, sizeof(rel2), base2, name2) ||
		    full_path(p, sizeof(p), base, name) || full_path(p2, sizeof(p2), base2, name2))
			return reply(s, q->id, -ENAMETOOLONG, NULL, 0);
		if (rename(p, p2))
			return reply(s, q->id, -errno, NULL, 0);
		node_rename(rel, rel2);
		return reply(s, q->id, 0, NULL, 0);
	}
	case FSVM_TRUNCATE:
		if (full_path(p, sizeof(p), base, NULL))
			return reply(s, q->id, -ENAMETOOLONG, NULL, 0);
		if (truncate(p, (off_t)q->arg))
			return reply(s, q->id, -errno, NULL, 0);
		return attr_reply(s, q->id, base);
	case FSVM_SETMTIME: {
		if (full_path(p, sizeof(p), base, NULL))
			return reply(s, q->id, -ENAMETOOLONG, NULL, 0);
		struct timespec ts[2] = { { 0, UTIME_OMIT }, { (time_t)q->arg, (long)q->len } };
		if (utimensat(AT_FDCWD, p, ts, AT_SYMLINK_NOFOLLOW))
			return reply(s, q->id, -errno, NULL, 0);
		return attr_reply(s, q->id, base);
	}
	case FSVM_FSYNC: {
		if (full_path(p, sizeof(p), base, NULL))
			return reply(s, q->id, -ENAMETOOLONG, NULL, 0);
		int fd = open(p, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
		if (fd < 0)
			return reply(s, q->id, -errno, NULL, 0);
		r = fsync(fd) ? -errno : 0;
		close(fd);
		return reply(s, q->id, r, NULL, 0);
	}
	default:
		return reply(s, q->id, -EINVAL, NULL, 0);
	}
}

/* Serves one connection until it closes or sends something malformed. */
static void serve(int s)
{
	for (;;) {
		struct fsvm_req q;
		if (read_full(s, &q, sizeof(q)) || q.magic != FSVM_REQ_MAGIC)
			return;
		uint32_t data_len = q.op == FSVM_WRITE ? q.len : 0;
		if (q.name_len > FSVM_MAX_NAME || q.name2_len > FSVM_MAX_NAME || data_len > FSVM_MAX_IO)
			return;
		if (read_full(s, inbuf, q.name_len))
			return;
		inbuf[q.name_len] = 0;
		char *name = (char *)inbuf;
		char *name2 = name + q.name_len + 1;
		if (read_full(s, name2, q.name2_len))
			return;
		name2[q.name2_len] = 0;
		uint8_t *data = (uint8_t *)name2 + q.name2_len + 1;
		if (read_full(s, data, data_len))
			return;
		int needs_name = q.op == FSVM_LOOKUP || q.op == FSVM_CREATE || q.op == FSVM_MKDIR ||
				 q.op == FSVM_UNLINK || q.op == FSVM_RMDIR || q.op == FSVM_RENAME;
		if (needs_name && !name_ok(name, q.name_len)) {
			if (reply(s, q.id, -EINVAL, NULL, 0))
				return;
			continue;
		}
		if (q.op == FSVM_RENAME && !name_ok(name2, q.name2_len)) {
			if (reply(s, q.id, -EINVAL, NULL, 0))
				return;
			continue;
		}
		if (handle(s, &q, name, name2, data))
			return;
	}
}

/* ---- The disk and mounting ---- */

static int disk_fd = -1;

static int disk_read(void *ctx, uint64_t off, void *buf, size_t len)
{
	(void)ctx;
	uint8_t *p = buf;
	while (len) {
		ssize_t n = pread(disk_fd, p, len, (off_t)off);
		if (n < 0 && errno == EINTR)
			continue;
		if (n <= 0)
			return -1;
		p += n;
		off += (uint64_t)n;
		len -= (size_t)n;
	}
	return 0;
}

static int read_u64_file(const char *path, uint64_t *out)
{
	char buf[32];
	int fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -errno;
	ssize_t n = read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (n <= 0)
		return -EIO;
	buf[n] = 0;
	char *end;
	errno = 0;
	unsigned long long v = strtoull(buf, &end, 10);
	if (errno || end == buf)
		return -EIO;
	*out = v;
	return 0;
}

/* Reads the partition layout once. Errors stay: a disk whose table was refused is not served. */
static int read_layout(void)
{
	if (layout_state)
		return layout_state < 0 ? layout_state : 0;
	int r = fsvm_read_layout(disk_read, NULL, disk_sectors, &layout);
	layout_state = r ? r : 1;
	if (r)
		logline("partition table refused", NULL, -r);
	return r;
}

static int try_mount(const char *dev, int want_ro)
{
	static const struct {
		const char *type;
		const char *opts;
		uint32_t kind;
	} fs[] = {
		{ "vfat", "utf8,shortname=mixed,errors=remount-ro", FSVM_FS_VFAT },
		{ "exfat", "iocharset=utf8,errors=remount-ro", FSVM_FS_EXFAT },
	};
	unsigned long base = MS_NOSUID | MS_NODEV | MS_NOEXEC | MS_NOATIME | (want_ro ? MS_RDONLY : 0);
	for (unsigned i = 0; i < sizeof(fs) / sizeof(fs[0]); i++) {
		if (!mount(dev, MNT, fs[i].type, base, fs[i].opts)) {
			fs_kind = fs[i].kind;
			read_only = want_ro;
			return 0;
		}
		/* A read-only disk: Android passed the volume without write access. */
		if (!want_ro && (errno == EROFS || errno == EACCES) &&
		    !mount(dev, MNT, fs[i].type, base | MS_RDONLY, fs[i].opts)) {
			fs_kind = fs[i].kind;
			read_only = 1;
			return 0;
		}
	}
	return -EIO;
}

/*
 * Mounts partition `index` (0: the whole disk) once. It must be in the layout read from the disk at exactly `start`
 * and `length`, and this kernel's partition device must agree. Then counts the free space once: the FAT driver reads
 * its whole table for that, which belongs here, inside MOUNT's deadline, not in a later STATFS.
 */
static int do_mount(uint32_t index, uint64_t start, uint64_t length, int want_ro)
{
	if (fs_kind) {
		if (index == mounted_index && start == mounted_start && length == mounted_length)
			return 0;
		return -EBUSY;
	}
	int r = read_layout();
	if (r)
		return r;
	if (!fsvm_layout_find(&layout, index, start, length))
		return -ENOENT;
	char dev[32];
	if (index == 0) {
		snprintf(dev, sizeof(dev), "%s", DISK);
	} else {
		char path[64];
		uint64_t s = 0, n = 0;
		snprintf(dev, sizeof(dev), "%s%u", DISK, index);
		snprintf(path, sizeof(path), "/sys/class/block/vda%u/start", index);
		if (read_u64_file(path, &s))
			return -ENOENT;
		snprintf(path, sizeof(path), "/sys/class/block/vda%u/size", index);
		if (read_u64_file(path, &n))
			return -ENOENT;
		if (s != start || n != length) {
			logline("partition differs from the table read", dev, 0);
			return -EINVAL;
		}
	}
	r = try_mount(dev, want_ro);
	if (r) {
		logline("no FAT or exFAT filesystem on", dev, errno);
		return r;
	}
	mounted_index = index;
	mounted_start = start;
	mounted_length = length;
	struct statfs sf;
	(void)statfs(MNT, &sf);
	logline("mounted", dev, 0);
	return 0;
}

int main(void)
{
	mkdir("/dev", 0755);
	mkdir(MNT, 0755);
	mount("devtmpfs", "/dev", "devtmpfs", MS_NOSUID | MS_NOEXEC, "mode=0755");
	node_path[1] = strdup("");
	if (node_path[1])
		slot_insert(1);
	for (int wait = 0; wait < 50 && access(DISK, F_OK); wait++)
		usleep(100 * 1000);
	disk_fd = open(DISK, O_RDONLY | O_CLOEXEC);
	if (disk_fd < 0 || read_u64_file("/sys/class/block/vda/size", &disk_sectors)) {
		/* Nothing to serve. Android times out and does not mount the volume. */
		logline("no disk", NULL, errno);
		for (;;)
			pause();
	}

	int ls = socket(AF_VSOCK, SOCK_STREAM | SOCK_CLOEXEC, 0);
	struct sockaddr_vm a = { 0 };
	a.svm_family = AF_VSOCK;
	a.svm_port = FSVM_PORT;
	a.svm_cid = VMADDR_CID_ANY;
	if (ls < 0 || bind(ls, (struct sockaddr *)&a, sizeof(a)) || listen(ls, 1)) {
		logline("vsock", NULL, errno);
		for (;;)
			pause();
	}
	for (;;) {
		int s = accept4(ls, NULL, NULL, SOCK_CLOEXEC);
		if (s < 0)
			continue;
		serve(s);
		close(s);
		sync();
	}
}
