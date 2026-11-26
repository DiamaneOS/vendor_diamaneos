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
 * /init of the filesystem VM. Its virtio disks are a whole SD card or USB disk (a probe), the public partitions of
 * one drive (each a range of its own on Android), or an OBB image, and the instance disk last. Android's kernel reads
 * none of their partition tables or filesystems. It serves protocol version 7 (proto.h) over vsock. Each connection
 * names its disk first (FSVM_DISK, disks.c) and gets a server process of its own, at most one per disk: LAYOUT
 * reports the partitions read from that disk (table.c), MOUNT mounts one FAT or exFAT filesystem, once, in the
 * server's own mount namespace, and the file operations then serve it. A disk's filesystem, its check and its
 * read-only state are that one process's, so one partition's dirty mark, check or broken session never touches
 * another's. Android checks every reply, so this program's job is to be correct, not to defend Android: if a crafted
 * filesystem takes over this VM's kernel, the VM is lost but Android is not.
 *
 * Static. PID 1 only accepts connections, starts and ends the servers, and never returns. Each server is single
 * threaded.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE /* syncfs and accept4 with glibc, for the host compile check (bionic has them anyway) */
#endif
#include "disks.h"
#include "proto.h"
#include "table.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <sched.h>
#include <linux/blkpg.h>
#include <linux/fs.h>
#include <linux/hdreg.h>
#include <linux/vm_sockets.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/ioctl.h>
#include <sys/reboot.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/statvfs.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define MNT "/mnt"
#define MAX_NODES 65536u
#define HASH_SIZE 131072u /* power of two, at least twice MAX_NODES */

/* The device node of this server's disk (FSVM_DISK), "/dev/vda" for the first. */
static char disk_dev[16];

static uint32_t fs_kind; /* 0 until MOUNT succeeded */
static int read_only;
static int was_dirty; /* the mounted filesystem was marked dirty before this VM mounted it */
static int check_pending; /* mounted read-only until the check after the mount passes (FSVM_CHECK) */
/* Remounted writable after a check that passed: the driver keeps the dirty mark it found for this mount's life, so the
 * orderly unmount marks the volume clean by hand (do_unmount). */
static int clean_at_unmount;
static uint32_t mounted_index;
static uint64_t mounted_start, mounted_length;
static char mounted_dev[32];
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

/*
 * ---- Node table: node id <-> path below MNT ("" is the root, node 1). ----
 *
 * A node id is a slot number in its low 32 bits and the slot's generation in its high 32 bits. A slot is only taken
 * for a node Android looked up or created, never for a name it only listed. When the table or the memory for paths
 * runs out, the least recently used slot is taken back (a clock over the slots) and its generation moves on, so an
 * old id answers ESTALE and fsvmd looks the name up again. The root is never taken back.
 */

#define MAX_PATH_BYTES (16u << 20) /* all node paths together, bounded for a small VM */

static char *node_path[MAX_NODES + 1];
static uint32_t node_gen[MAX_NODES + 1];
static uint8_t node_used[MAX_NODES + 1];
static uint32_t hash_slot[HASH_SIZE]; /* slot, 0 = empty, UINT32_MAX = deleted */
static uint32_t hash_deleted;
static size_t path_bytes;
static uint32_t clock_hand = 2;

static uint32_t hash_str(const char *s)
{
	uint32_t h = 2166136261u;
	while (*s)
		h = (h ^ (uint8_t)*s++) * 16777619u;
	return h;
}

static uint64_t node_id(uint32_t slot)
{
	return (uint64_t)node_gen[slot] << 32 | slot;
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

static void slot_insert(uint32_t slot)
{
	uint32_t i = hash_str(node_path[slot]) & (HASH_SIZE - 1);
	while (hash_slot[i] != 0 && hash_slot[i] != UINT32_MAX)
		i = (i + 1) & (HASH_SIZE - 1);
	if (hash_slot[i] == UINT32_MAX)
		hash_deleted--;
	hash_slot[i] = slot;
}

/* Rebuilds the hash when deleted marks pile up, so lookups stay short. */
static void hash_rebuild(void)
{
	memset(hash_slot, 0, sizeof(hash_slot));
	hash_deleted = 0;
	for (uint32_t n = 1; n <= MAX_NODES; n++)
		if (node_path[n])
			slot_insert(n);
}

/* After a slot's path changed or went: rebuilds the hash when deleted marks piled up. */
static void hash_maybe_rebuild(void)
{
	if (hash_deleted > HASH_SIZE / 4)
		hash_rebuild();
}

static void slot_remove(uint32_t slot)
{
	uint32_t i = hash_str(node_path[slot]) & (HASH_SIZE - 1);
	for (uint32_t probe = 0; probe < HASH_SIZE; probe++, i = (i + 1) & (HASH_SIZE - 1)) {
		if (hash_slot[i] == 0)
			return;
		if (hash_slot[i] == slot) {
			hash_slot[i] = UINT32_MAX;
			hash_deleted++;
			return;
		}
	}
}

/* Frees a slot. Its old id answers ESTALE from now on. */
static void slot_free(uint32_t slot)
{
	if (slot <= 1 || slot > MAX_NODES || !node_path[slot])
		return;
	slot_remove(slot);
	path_bytes -= strlen(node_path[slot]) + 1;
	free(node_path[slot]);
	node_path[slot] = NULL;
	node_used[slot] = 0;
	node_gen[slot]++;
	hash_maybe_rebuild();
}

/* Takes back the least recently used slot (second chance). */
static void evict_one(void)
{
	for (uint32_t step = 0; step < 2 * MAX_NODES; step++) {
		uint32_t c = clock_hand;
		clock_hand = clock_hand >= MAX_NODES ? 2 : clock_hand + 1;
		if (!node_path[c])
			continue;
		if (node_used[c]) {
			node_used[c] = 0;
			continue;
		}
		slot_free(c);
		return;
	}
}

/* Returns the slot for a path, taking one if new (and taking back an old one if needed). 0 only without memory. */
static uint32_t node_get(const char *path)
{
	uint32_t n = node_find(path);
	if (n) {
		node_used[n] = 1;
		return n;
	}
	size_t len = strlen(path) + 1;
	while (path_bytes + len > MAX_PATH_BYTES)
		evict_one();
	uint32_t c = 0;
	for (uint32_t tries = 0; tries < MAX_NODES && !c; tries++) {
		uint32_t t = clock_hand;
		clock_hand = clock_hand >= MAX_NODES ? 2 : clock_hand + 1;
		if (!node_path[t])
			c = t;
	}
	if (!c) {
		evict_one();
		for (uint32_t t = 2; t <= MAX_NODES && !c; t++)
			if (!node_path[t])
				c = t;
		if (!c)
			return 0;
	}
	node_path[c] = strdup(path);
	if (!node_path[c])
		return 0;
	path_bytes += len;
	node_used[c] = 1;
	slot_insert(c);
	return c;
}

/* The path of a node id, or NULL when the id is unknown or stale. */
static const char *path_of(uint64_t id)
{
	uint32_t slot = (uint32_t)id;
	if (slot == 0 || slot > MAX_NODES || !node_path[slot] || node_gen[slot] != (uint32_t)(id >> 32))
		return NULL;
	node_used[slot] = 1;
	return node_path[slot];
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
		slot_free(target);
	for (uint32_t n = 2; n <= MAX_NODES; n++) {
		char *p = node_path[n];
		if (!p || strncmp(p, from, fl) != 0 || (p[fl] != 0 && p[fl] != '/'))
			continue;
		char next[PATH_MAX];
		if (snprintf(next, sizeof(next), "%s%s", to, p + fl) >= (int)sizeof(next)) {
			slot_free(n);
			continue;
		}
		char *moved = strdup(next);
		if (!moved) {
			slot_free(n);
			continue;
		}
		slot_remove(n);
		path_bytes += strlen(moved) - strlen(p);
		free(p);
		node_path[n] = moved;
		slot_insert(n);
		hash_maybe_rebuild();
	}
}

/* Frees every node at or below `path` (after unlink or rmdir). */
static void node_unlink(const char *path)
{
	size_t l = strlen(path);
	for (uint32_t n = 2; n <= MAX_NODES; n++) {
		char *p = node_path[n];
		if (p && strncmp(p, path, l) == 0 && (p[l] == 0 || p[l] == '/'))
			slot_free(n);
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

static int fill_attr(const char *rel, uint64_t node, struct fsvm_attr *a)
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
	uint32_t slot = node_get(rel);
	if (!slot)
		return reply(s, id, -ENOMEM, NULL, 0);
	int r = fill_attr(rel, node_id(slot), &a);
	if (r) {
		if (r == -ENOENT)
			slot_free(slot);
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
		/* A listed name takes no slot: Android looks it up before it uses it. */
		uint32_t slot = node_find(child);
		struct fsvm_attr a;
		if (fill_attr(child, slot ? node_id(slot) : FSVM_NODE_LISTED, &a))
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

/* ---- Open files (OPEN, CLOSE): a descriptor per handle, so a file stays readable and writable after its name went,
 * as with the kernel's FAT driver. Handle ids carry a generation like node ids. ---- */

#define MAX_HANDLES 1024u
static int handle_fd[MAX_HANDLES + 1]; /* 0: free, -1: closed while the volume is mounted again (FSVM_CHECK) */
static uint32_t handle_gen[MAX_HANDLES + 1];
static char *handle_path[MAX_HANDLES + 1]; /* to open the file again after the switch */

/* The descriptor of a valid handle, or -1. */
static int handle_lookup(uint64_t h)
{
	uint32_t slot = (uint32_t)h, gen = (uint32_t)(h >> 32);
	if (slot == 0 || slot > MAX_HANDLES || handle_gen[slot] != gen || handle_fd[slot] <= 0)
		return -1;
	return handle_fd[slot];
}

static int handle_open(const char *rel, int write, uint64_t *out)
{
	char p[PATH_MAX];
	if (write && read_only)
		return -EROFS;
	int r = full_path(p, sizeof(p), rel, NULL);
	if (r)
		return r;
	for (uint32_t slot = 1; slot <= MAX_HANDLES; slot++) {
		if (handle_fd[slot] > 0)
			continue;
		int fd = open(p, (write ? O_RDWR : O_RDONLY) | O_NOFOLLOW | O_CLOEXEC);
		if (fd < 0)
			return -errno;
		if (fd == 0) { /* 0 marks a free slot */
			int high = fcntl(fd, F_DUPFD_CLOEXEC, 3);
			close(fd);
			if (high < 0)
				return -EMFILE;
			fd = high;
		}
		handle_fd[slot] = fd;
		free(handle_path[slot]);
		handle_path[slot] = strdup(rel);
		*out = (uint64_t)handle_gen[slot] << 32 | slot;
		return 0;
	}
	return -EMFILE;
}

static int handle_close(uint64_t h)
{
	if (handle_lookup(h) < 0)
		return -EBADF;
	uint32_t slot = (uint32_t)h;
	close(handle_fd[slot]);
	handle_fd[slot] = 0;
	handle_gen[slot]++;
	free(handle_path[slot]);
	handle_path[slot] = NULL;
	return 0;
}

/* Before an unmount: every open file goes, so the filesystem can be unmounted. */
static void handle_close_all(void)
{
	for (uint32_t slot = 1; slot <= MAX_HANDLES; slot++) {
		if (!handle_fd[slot])
			continue;
		if (handle_fd[slot] > 0)
			close(handle_fd[slot]);
		handle_fd[slot] = 0;
		handle_gen[slot]++;
		free(handle_path[slot]);
		handle_path[slot] = NULL;
	}
}

/* The switch after the check: open files are closed for the unmount and kept by path (-1). */
static void handle_suspend_all(void)
{
	for (uint32_t slot = 1; slot <= MAX_HANDLES; slot++)
		if (handle_fd[slot] > 0) {
			close(handle_fd[slot]);
			handle_fd[slot] = -1;
		}
}

/* ...and opened again, read-only as before, once the volume is mounted again. A file the repair removed stays
 * closed: its handle answers EBADF, which fsvmd turns into EIO. */
static void handle_resume_all(void)
{
	char p[PATH_MAX];
	for (uint32_t slot = 1; slot <= MAX_HANDLES; slot++) {
		if (handle_fd[slot] != -1)
			continue;
		int fd = handle_path[slot] && !full_path(p, sizeof(p), handle_path[slot], NULL) ?
				 open(p, O_RDONLY | O_NOFOLLOW | O_CLOEXEC) :
				 -1;
		if (fd == 0) {
			int high = fcntl(fd, F_DUPFD_CLOEXEC, 3);
			close(fd);
			fd = high;
		}
		if (fd < 0) {
			handle_fd[slot] = 0;
			handle_gen[slot]++;
			free(handle_path[slot]);
			handle_path[slot] = NULL;
			continue;
		}
		handle_fd[slot] = fd;
	}
}

static int read_fd(int s, const struct fsvm_req *q, int fd)
{
	uint32_t want = q->len > FSVM_MAX_IO ? FSVM_MAX_IO : q->len;
	uint32_t got = 0;
	while (got < want) {
		ssize_t n = pread(fd, outbuf + got, want - got, (off_t)(q->arg + got));
		if (n < 0 && errno == EINTR)
			continue;
		if (n < 0)
			return reply(s, q->id, -errno, NULL, 0);
		if (n == 0)
			break;
		got += (uint32_t)n;
	}
	return reply(s, q->id, 0, outbuf, got);
}

static int write_fd(int s, const struct fsvm_req *q, int fd, const uint8_t *data)
{
	if (read_only)
		return reply(s, q->id, -EROFS, NULL, 0);
	uint32_t done = 0;
	while (done < q->len) {
		ssize_t n = pwrite(fd, data + done, q->len - done, (off_t)(q->arg + done));
		if (n < 0 && errno == EINTR)
			continue;
		if (n <= 0)
			break;
		done += (uint32_t)n;
	}
	if (done == 0 && q->len)
		return reply(s, q->id, -errno, NULL, 0);
	uint32_t out[2] = { done, 0 };
	return reply(s, q->id, 0, out, sizeof(out));
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
static int do_mount(uint32_t index, uint64_t start, uint64_t length, int want_ro, uint32_t check_ms, int later);
static int do_unmount(void);
static int check_poll(struct fsvm_check *c);
static int check_switch(uint32_t repair_ms);
static int do_format(uint32_t kind, uint32_t budget_ms);

/* Dirty plus Writeback from /proc/meminfo, in bytes: what this VM still has to write to its disk. */
static uint64_t dirty_bytes(void)
{
	char buf[4096];
	int fd = open("/proc/meminfo", O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return 0;
	ssize_t n = read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (n <= 0)
		return 0;
	buf[n] = 0;
	uint64_t total = 0;
	static const char *keys[] = { "\nDirty:", "\nWriteback:" };
	for (unsigned i = 0; i < 2; i++) {
		const char *p = strstr(buf, keys[i]);
		if (p)
			total += strtoull(p + strlen(keys[i]), NULL, 10) * 1024;
	}
	return total;
}

static uint32_t hello_flags(void)
{
	return (read_only ? 1u : 0u) | (was_dirty ? 2u : 0u) | (check_pending ? 4u : 0u);
}

static int handle(int s, struct fsvm_req *q, const char *name, const char *name2, const uint8_t *data)
{
	char p[PATH_MAX], p2[PATH_MAX], rel[PATH_MAX], rel2[PATH_MAX];
	const char *base = path_of(q->node);
	int r;

	switch (q->op) {
	case FSVM_HELLO: {
		struct fsvm_hello h = { FSVM_VERSION, fs_kind, hello_flags(), 0, 1 };
		return reply(s, q->id, 0, &h, sizeof(h));
	}
	case FSVM_DISK:
		/* Only as a connection's first request, which /init handles: a server keeps its disk. */
		return reply(s, q->id, -EINVAL, NULL, 0);
	case FSVM_UNMOUNT:
		return reply(s, q->id, do_unmount(), NULL, 0);
	case FSVM_DIRTY: {
		uint64_t b = dirty_bytes();
		uint8_t out[8];
		for (int i = 0; i < 8; i++)
			out[i] = (uint8_t)(b >> (8 * i));
		return reply(s, q->id, 0, out, sizeof(out));
	}
	case FSVM_CHECK: {
		if (q->arg == 1)
			return reply(s, q->id, check_switch(q->len), NULL, 0);
		struct fsvm_check c;
		r = check_poll(&c);
		if (r)
			return reply(s, q->id, r, NULL, 0);
		return reply(s, q->id, 0, &c, sizeof(c));
	}
	case FSVM_FORMAT:
		return reply(s, q->id, q->arg > UINT32_MAX ? -EINVAL : do_format((uint32_t)q->arg, q->len), NULL, 0);
	case FSVM_LAYOUT:
		r = read_layout();
		if (r)
			return reply(s, q->id, r, NULL, 0);
		return reply(s, q->id, 0, &layout, fsvm_layout_size(&layout));
	case FSVM_MOUNT: {
		if (q->arg > UINT32_MAX)
			return reply(s, q->id, -EINVAL, NULL, 0);
		r = do_mount((uint32_t)q->arg, q->node, q->node2, q->flags & 1, q->len, q->flags & 2);
		if (r)
			return reply(s, q->id, r, NULL, 0);
		struct fsvm_hello h = { FSVM_VERSION, fs_kind, hello_flags(), 0, 1 };
		return reply(s, q->id, 0, &h, sizeof(h));
	}
	default:
		break;
	}

	/* Everything below needs the mounted volume. */
	if (!fs_kind)
		return reply(s, q->id, -EINVAL, NULL, 0);
	/* An open file's handle: no name needed, so it serves a file whose name went. */
	if (q->node2 && (q->op == FSVM_READ || q->op == FSVM_WRITE || q->op == FSVM_FSYNC || q->op == FSVM_CLOSE ||
			 q->op == FSVM_GETATTR || q->op == FSVM_TRUNCATE || q->op == FSVM_SETMTIME)) {
		if (q->op == FSVM_CLOSE)
			return reply(s, q->id, handle_close(q->node2), NULL, 0);
		int fd = handle_lookup(q->node2);
		if (fd < 0)
			return reply(s, q->id, -EBADF, NULL, 0);
		if (read_only && fsvm_changes_volume(q))
			return reply(s, q->id, -EROFS, NULL, 0);
		if (q->op == FSVM_TRUNCATE && ftruncate(fd, (off_t)q->arg))
			return reply(s, q->id, -errno, NULL, 0);
		if (q->op == FSVM_SETMTIME) {
			struct timespec ts[2] = { { 0, UTIME_OMIT }, { (time_t)q->arg, (long)q->len } };
			if (futimens(fd, ts))
				return reply(s, q->id, -errno, NULL, 0);
		}
		if (q->op == FSVM_GETATTR || q->op == FSVM_TRUNCATE || q->op == FSVM_SETMTIME) {
			struct stat st;
			struct fsvm_attr at;
			if (fstat(fd, &st))
				return reply(s, q->id, -errno, NULL, 0);
			memset(&at, 0, sizeof(at));
			at.node = q->node ? q->node : 1;
			at.kind = FSVM_KIND_FILE;
			at.size = (uint64_t)st.st_size;
			at.mtime_s = st.st_mtim.tv_sec;
			at.mtime_ns = (uint32_t)st.st_mtim.tv_nsec;
			return reply(s, q->id, 0, &at, sizeof(at));
		}
		if (q->op == FSVM_READ)
			return read_fd(s, q, fd);
		if (q->op == FSVM_WRITE)
			return write_fd(s, q, fd, data);
		r = ((q->flags & FSVM_FSYNC_DATA) ? fdatasync(fd) : fsync(fd)) ? -errno : 0;
		return reply(s, q->id, r, NULL, 0);
	}
	/* An id the guest no longer knows: fsvmd looks the name up again. */
	if (q->op != FSVM_STATFS && !base)
		return reply(s, q->id, -ESTALE, NULL, 0);

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
		if (q->node > 1 && path_of(q->node))
			slot_free((uint32_t)q->node);
		return reply(s, q->id, 0, NULL, 0);
	default:
		break;
	}

	/* Below: calls that change the volume, an open and a write back. A read-only volume refuses only the first. */
	if (read_only && fsvm_changes_volume(q))
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
			return reply(s, q->id, -ESTALE, NULL, 0);
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
	case FSVM_OPEN: {
		uint64_t h = 0;
		r = handle_open(base, q->flags & 1, &h);
		if (r)
			return reply(s, q->id, r, NULL, 0);
		uint8_t out[8];
		for (int i = 0; i < 8; i++)
			out[i] = (uint8_t)(h >> (8 * i));
		return reply(s, q->id, 0, out, sizeof(out));
	}
	case FSVM_FSYNC: {
		if (full_path(p, sizeof(p), base, NULL))
			return reply(s, q->id, -ENAMETOOLONG, NULL, 0);
		int fd = open(p, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
		if (fd < 0)
			return reply(s, q->id, -errno, NULL, 0);
		r = ((q->flags & FSVM_FSYNC_DATA) ? fdatasync(fd) : fsync(fd)) ? -errno : 0;
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
static unsigned sector_size = 512;

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

/* Size in bytes of a block device (or of a file, for the host harness). */
static int dev_bytes(int fd, uint64_t *out)
{
	uint64_t b = 0;
	if (!ioctl(fd, BLKGETSIZE64, &b)) {
		*out = b;
		return 0;
	}
	off_t end = lseek(fd, 0, SEEK_END);
	if (end < 0)
		return -errno;
	*out = (uint64_t)end;
	return 0;
}

/* Reads the partition layout once. Errors stay: a disk whose table was refused is not served. */
static int read_layout(void)
{
	if (layout_state)
		return layout_state < 0 ? layout_state : 0;
	int r = fsvm_read_layout(disk_read, NULL, disk_sectors, sector_size, &layout);
	layout_state = r ? r : 1;
	if (r)
		logline("partition table refused", NULL, -r);
	return r;
}

#define VFAT_OPTS "utf8,shortname=mixed,errors=remount-ro"
#define EXFAT_OPTS "iocharset=utf8,errors=remount-ro"
#define MOUNT_FLAGS (MS_NOSUID | MS_NODEV | MS_NOEXEC | MS_NOATIME | MS_DIRSYNC)

static int try_mount(const char *dev, int want_ro)
{
	static const struct {
		const char *type;
		const char *opts;
		uint32_t kind;
	} fs[] = {
		{ "vfat", VFAT_OPTS, FSVM_FS_VFAT },
		{ "exfat", EXFAT_OPTS, FSVM_FS_EXFAT },
	};
	/* MS_DIRSYNC as vold mounted cards (fs/Vfat.cpp, fs/Exfat.cpp): a directory change waits until it is on the disk.
	 * Android's VM manager opens a card with O_DIRECT, so that means on the card, not in Android's page cache, and a
	 * card pulled without eject keeps its directory structure. */
	unsigned long base = MOUNT_FLAGS | (want_ro ? MS_RDONLY : 0);
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

static int64_t now_ms(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/* Runs a checker until `deadline_ms` (now_ms). Returns its exit code, -ETIMEDOUT, or -ECHILD when it did not run. */
static int run_checker(char *const argv[], int64_t deadline_ms)
{
	if (access(argv[0], X_OK))
		return -ECHILD;
	pid_t pid = fork();
	if (pid < 0)
		return -ECHILD;
	if (pid == 0) {
		execv(argv[0], argv);
		_exit(127);
	}
	for (;;) {
		int st = 0;
		pid_t r = waitpid(pid, &st, WNOHANG);
		if (r == pid) {
			if (WIFEXITED(st))
				return WEXITSTATUS(st) == 127 ? -ECHILD : WEXITSTATUS(st);
			return -ECHILD; /* killed, for example out of memory */
		}
		if (r < 0)
			return -ECHILD;
		if (now_ms() >= deadline_ms) {
			kill(pid, SIGKILL);
			waitpid(pid, NULL, 0);
			return -ETIMEDOUT;
		}
		usleep(20 * 1000);
	}
}

/* Whether an exFAT volume is marked dirty (VolumeFlags bit 1, offset 106). */
static int exfat_dirty(const char *dev)
{
	uint8_t b[512];
	int fd = open(dev, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return 0;
	int r = pread(fd, b, sizeof(b), 0) == (ssize_t)sizeof(b) && (b[106] & 2);
	close(fd);
	return r;
}

/* The state byte Linux's FAT driver sets while it has the volume mounted writable. */
static int fat_linux_dirty(const char *dev)
{
	uint8_t b[512];
	int fd = open(dev, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return 0;
	int r = pread(fd, b, sizeof(b), 0) == (ssize_t)sizeof(b) && (b[(b[22] | b[23]) ? 0x25 : 0x41] & 1);
	close(fd);
	return r;
}

/*
 * Whether a volume is marked dirty. exFAT: VolumeFlags. FAT has two marks: the state byte in the boot sector
 * (offset 0x41 on FAT32, 0x25 on FAT12 and FAT16, bit 0), which Linux's driver sets while it has the volume mounted
 * writable, and on FAT32 the clean-shutdown bit in the second FAT entry (0x08000000), which Windows and fsck_msdos
 * use. Either one counts. Runs only while the volume is not mounted.
 */
static int volume_dirty(const char *dev, uint32_t kind)
{
	if (kind == FSVM_FS_EXFAT)
		return exfat_dirty(dev);
	uint8_t b[512], f[8];
	int fd = open(dev, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return 0;
	int r = 0;
	if (pread(fd, b, sizeof(b), 0) == (ssize_t)sizeof(b)) {
		int fat32 = !(b[22] | b[23]);
		uint32_t bps = (uint32_t)(b[11] | b[12] << 8), reserved = (uint32_t)(b[14] | b[15] << 8);
		r = b[fat32 ? 0x41 : 0x25] & 1;
		/* The clean bit on FAT32 only: FAT12 has none, and telling FAT16 from FAT12 needs the cluster count. */
		if (!r && fat32 && bps >= 512 && pread(fd, f, sizeof(f), (off_t)reserved * bps) == (ssize_t)sizeof(f)) {
			uint32_t e1 = (uint32_t)f[4] | (uint32_t)f[5] << 8 | (uint32_t)f[6] << 16 | (uint32_t)f[7] << 24;
			r = !(e1 & 0x08000000u);
		}
	}
	close(fd);
	return r;
}

/*
 * The filesystem check before a writable mount, here in the VM rather than on Android, with the tools vold used
 * (fsck_msdos and fsck.exfat, built static from the pinned tree). As on most systems it runs when the volume is
 * marked dirty: fsck_msdos -p checks only then, and fsck.exfat runs only when the exFAT dirty flag is set.
 * Returns 0 to mount as asked, 1 to mount read-only (the check did not finish), or a negative errno to refuse.
 */
/*
 * After a FAT check passed: clears the state byte Linux's driver set (fsck_msdos fixes the FAT's own clean bit, not
 * this one). Linux keeps the byte set when it mounts a volume that already had it, so without this a card stopped
 * once without an orderly unmount would get a full check on every mount. dosfstools' fsck clears it the same way.
 */
static void clear_fat_state(const char *dev)
{
	uint8_t b[512];
	int fd = open(dev, O_RDWR | O_CLOEXEC);
	if (fd < 0)
		return;
	if (pread(fd, b, sizeof(b), 0) == (ssize_t)sizeof(b) && b[510] == 0x55 && b[511] == 0xAA) {
		unsigned at = (b[22] | b[23]) ? 0x25 : 0x41;
		if (b[at] & 1) {
			uint8_t v = b[at] & (uint8_t)~1u;
			if (pwrite(fd, &v, 1, at) != 1 || fsync(fd))
				logline("clearing the FAT state byte", dev, errno);
		}
	}
	close(fd);
}

static int check_volume(const char *dev, uint32_t kind, uint32_t budget_ms)
{
	if (!budget_ms)
		return 0;
	int64_t deadline = now_ms() + budget_ms;
	if (kind == FSVM_FS_VFAT) {
		/* -f: fsck_msdos -p looks only at the FAT's clean bit, Linux marks the boot sector. A volume either marks as
		 * dirty is checked fully. */
		char *argv[] = { "/bin/fsck_msdos", "-p", "-y", (char *)dev, NULL, NULL };
		if (volume_dirty(dev, kind)) {
			argv[3] = "-f";
			argv[4] = (char *)dev;
		}
		for (int pass = 1;; pass++) {
			int r = run_checker(argv, deadline);
			if (r == 0) {
				clear_fat_state(dev);
				return 0;
			}
			if (r == 4 && pass <= 3)
				continue; /* modified, check again, as vold did */
			if (r == -ETIMEDOUT || r == -ECHILD) {
				logline("FAT check did not finish, read-only", dev, -r);
				return 1;
			}
			logline("FAT check failed", dev, 0);
			return -EIO;
		}
	}
	if (!exfat_dirty(dev))
		return 0;
	char *argv[] = { "/bin/fsck.exfat", "-y", (char *)dev, NULL };
	int r = run_checker(argv, deadline);
	if (r == 0 || r == 1)
		return 0; /* clean, or errors corrected */
	if (r == -ETIMEDOUT || r == -ECHILD) {
		logline("exFAT check did not finish, read-only", dev, -r);
		return 1;
	}
	logline("exFAT check failed", dev, 0);
	return -EIO;
}

/*
 * Formats the whole disk, as vold formatted a public volume on Android before (fs/Vfat.cpp, fs/Exfat.cpp, the same
 * arguments): newfs_msdos -O android -A, or mkfs.exfat -n External. Afterwards the layout is read again from the
 * disk, so that LAYOUT reports the new filesystem.
 */
static int do_format(uint32_t kind, uint32_t budget_ms)
{
	if (fs_kind || (kind != FSVM_FS_VFAT && kind != FSVM_FS_EXFAT) || !budget_ms)
		return -EINVAL;
	char *fat[] = { "/bin/newfs_msdos", "-O", "android", "-A", disk_dev, NULL };
	char *exf[] = { "/bin/mkfs.exfat", "-n", "External", disk_dev, NULL };
	/* Android may have discarded the disk since this VM read its layout: nothing this VM cached of it stays. */
	int c = open(disk_dev, O_RDONLY | O_CLOEXEC);
	if (c < 0 || ioctl(c, BLKFLSBUF, 0))
		logline("dropping the cached blocks before the format", disk_dev, errno);
	if (c >= 0)
		close(c);
	int r = run_checker(kind == FSVM_FS_EXFAT ? exf : fat, now_ms() + budget_ms);
	int b = open(disk_dev, O_RDONLY | O_CLOEXEC);
	if (b < 0 || fsync(b))
		r = r ? r : -EIO;
	if (b >= 0)
		close(b);
	layout_state = 0;
	logline(r ? "format failed" : "formatted", kind == FSVM_FS_EXFAT ? "exfat" : "vfat", r < 0 ? -r : 0);
	return r == 0 ? 0 : (r == -ETIMEDOUT ? -ETIMEDOUT : -EIO);
}

/* ---- The check after the mount (FSVM_CHECK) ----
 *
 * A writable mount of a volume marked dirty is read-only at once. The check runs here while the volume is served
 * read-only, without writing (fsck_msdos -n -f, fsck.exfat -n), for as long as it takes: it is not bound to vold's
 * lock or anyone's watchdog. When it ended, fsvmd asks for the switch: the volume is unmounted, repaired if the check
 * found errors (within the time fsvmd gives), marked clean and mounted writable. Open files are opened again by
 * path. An unmount (eject) during the read-only check stops it: nothing was written, the volume keeps its mark.
 */

static pid_t check_pid;
static int64_t check_start_ms, check_end_ms;
static int check_state = FSVM_CHECK_NONE;

#define CHECK_OUT "/fsck.out"

/* Whether fsck_msdos -n -f found nothing but the dirty mark. It asks "MARK FILE SYSTEM CLEAN" only when the whole
 * check ended without an error (check.c: no FSERROR, no FSFATAL), and answers "no" with -n, then exits 8. Hints it
 * may not fix (the free count or next free cluster in FSInfo) are no errors and leave that question in place. */
static int fat_only_dirty(void)
{
	char buf[16384];
	int fd = open(CHECK_OUT, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return 0;
	ssize_t n = read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (n <= 0 || n == (ssize_t)sizeof(buf) - 1)
		return 0;
	buf[n] = 0;
	int mark = 0;
	for (char *line = buf; line && *line;) {
		char *end = strchr(line, '\n');
		if (end)
			*end = 0;
		if (!strcmp(line, "MARK FILE SYSTEM CLEAN? no"))
			mark = 1;
		line = end ? end + 1 : NULL;
	}
	return mark;
}

/* In the forked checker of the check without writes: its output goes to CHECK_OUT, at most 1 MiB of it (the
 * initramfs is RAM, and a damaged or crafted card can make fsck_msdos print without end). Writes past that fail, the
 * check goes on. */
static void checker_output(void)
{
	int out = open(CHECK_OUT, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	if (out >= 0) {
		dup2(out, 1);
		dup2(out, 2);
	}
	struct rlimit fsize = { 1 << 20, 1 << 20 };
	signal(SIGXFSZ, SIG_IGN);
	setrlimit(RLIMIT_FSIZE, &fsize);
}

static void check_start(void)
{
	char *fat[] = { "/bin/fsck_msdos", "-n", "-f", mounted_dev, NULL };
	char *exf[] = { "/bin/fsck.exfat", "-n", mounted_dev, NULL };
	char **argv = fs_kind == FSVM_FS_EXFAT ? exf : fat;
	check_start_ms = now_ms();
	check_state = FSVM_CHECK_RUNNING;
	if (access(argv[0], X_OK)) {
		check_state = FSVM_CHECK_FAILED;
		return;
	}
	pid_t pid = fork();
	if (pid < 0) {
		check_state = FSVM_CHECK_FAILED;
		return;
	}
	if (pid == 0) {
		checker_output();
		execv(argv[0], argv);
		_exit(127);
	}
	check_pid = pid;
	logline("checking the volume while it is served read-only", mounted_dev, 0);
}

/* Starts the check on the first call, then reports how it goes. */
static int check_poll(struct fsvm_check *c)
{
	if (!fs_kind)
		return -EINVAL;
	if (check_pending && check_state == FSVM_CHECK_NONE)
		check_start();
	if (check_pid > 0) {
		int st = 0;
		pid_t pid = check_pid;
		pid_t r = waitpid(pid, &st, WNOHANG);
		if (r == pid || r < 0) {
			check_pid = 0;
			check_end_ms = now_ms();
			int code = r == pid && WIFEXITED(st) ? WEXITSTATUS(st) : -1;
			if (code == 127 || code < 0)
				check_state = FSVM_CHECK_FAILED;
			else if (code == 0 || (fs_kind == FSVM_FS_VFAT && code == 8 && fat_only_dirty()))
				check_state = FSVM_CHECK_PASSED;
			else if (fs_kind == FSVM_FS_EXFAT && code != 4)
				check_state = FSVM_CHECK_FAILED; /* exFAT: 4 is errors left, anything else did not check */
			else
				check_state = FSVM_CHECK_ERRORS;
			logline(check_state == FSVM_CHECK_PASSED ? "check passed" :
				check_state == FSVM_CHECK_ERRORS ? "check found errors" : "check did not run",
				mounted_dev, 0);
		}
	}
	c->state = check_pending ? (uint32_t)check_state : FSVM_CHECK_NONE;
	int64_t until = check_pid > 0 || !check_end_ms ? now_ms() : check_end_ms;
	c->elapsed_ms = check_pending && check_start_ms ? (uint32_t)(until - check_start_ms) : 0;
	return 0;
}

static void check_stop(void)
{
	if (check_pid > 0) {
		kill(check_pid, SIGKILL);
		waitpid(check_pid, NULL, 0);
		check_pid = 0;
		logline("check stopped, the volume keeps its dirty mark", mounted_dev, 0);
	}
	check_pending = 0;
	check_state = FSVM_CHECK_NONE;
}

/* After a check without repairs: the marks the check would have cleared. FAT: Linux's state byte (clear_fat_state)
 * and on FAT32 the clean bit of the second entry in every FAT. exFAT: VolumeFlags bit 1, which the boot region's
 * checksum leaves out. Only while the volume is not mounted. */
static int mark_clean(const char *dev, uint32_t kind)
{
	uint8_t b[512];
	int fd = open(dev, O_RDWR | O_CLOEXEC);
	if (fd < 0)
		return -errno;
	int r = 0;
	if (pread(fd, b, sizeof(b), 0) != (ssize_t)sizeof(b) || b[510] != 0x55 || b[511] != 0xAA) {
		r = -EIO;
	} else if (kind == FSVM_FS_EXFAT) {
		uint8_t v = b[106] & (uint8_t)~2u;
		if (pwrite(fd, &v, 1, 106) != 1)
			r = -EIO;
	} else if (!(b[22] | b[23])) {
		uint32_t bps = (uint32_t)(b[11] | b[12] << 8), reserved = (uint32_t)(b[14] | b[15] << 8);
		uint32_t fats = b[16], fat_sectors = (uint32_t)b[36] | (uint32_t)b[37] << 8 | (uint32_t)b[38] << 16 |
						     (uint32_t)b[39] << 24;
		for (uint32_t i = 0; i < fats && !r; i++) {
			off_t at = ((off_t)reserved + (off_t)i * fat_sectors) * bps + 4;
			uint8_t e[4];
			if (pread(fd, e, 4, at) != 4) {
				r = -EIO;
				break;
			}
			e[3] |= 0x08; /* 0x08000000: cleanly unmounted */
			if (pwrite(fd, e, 4, at) != 4)
				r = -EIO;
		}
	}
	if (!r && fsync(fd))
		r = -EIO;
	close(fd);
	if (!r && kind != FSVM_FS_EXFAT)
		clear_fat_state(dev);
	return r;
}

/* The read-only check once more, after a repair, within `deadline_ms`: whether the volume reads as sound now.
 * fsck_msdos reports a repair it made with exit codes vold's old check took as failures (a lost chain cleared, a
 * missing LOST.DIR), so what counts is that a check without writes finds nothing afterwards. */
static int verify_after_repair(const char *dev, uint32_t kind, int64_t deadline_ms)
{
	char *fat[] = { "/bin/fsck_msdos", "-n", "-f", (char *)dev, NULL };
	char *exf[] = { "/bin/fsck.exfat", "-n", (char *)dev, NULL };
	char **argv = kind == FSVM_FS_EXFAT ? exf : fat;
	pid_t pid = fork();
	if (pid < 0)
		return 0;
	if (pid == 0) {
		checker_output();
		execv(argv[0], argv);
		_exit(127);
	}
	for (;;) {
		int st = 0;
		pid_t r = waitpid(pid, &st, WNOHANG);
		if (r == pid) {
			int code = WIFEXITED(st) ? WEXITSTATUS(st) : -1;
			return code == 0 || (kind == FSVM_FS_VFAT && code == 8 && fat_only_dirty());
		}
		if (r < 0)
			return 0;
		if (now_ms() >= deadline_ms) {
			kill(pid, SIGKILL);
			waitpid(pid, NULL, 0);
			return 0;
		}
		usleep(20 * 1000);
	}
}

static int check_switch(uint32_t repair_ms)
{
	if (!fs_kind || !check_pending || (check_state != FSVM_CHECK_PASSED && check_state != FSVM_CHECK_ERRORS))
		return -EINVAL;
	char dev[32];
	snprintf(dev, sizeof(dev), "%s", mounted_dev);
	uint32_t kind = fs_kind;
	if (check_state == FSVM_CHECK_PASSED) {
		/* Nothing to repair: writable in place. Open files stay open and nothing waits. The driver keeps the dirty
		 * mark it found at the mount while the volume is mounted (FAT's sbi->dirty, exFAT's persistent flag), which
		 * is right while it is written, and the orderly unmount marks it clean (do_unmount). */
		if (!mount(NULL, MNT, NULL, MS_REMOUNT | MOUNT_FLAGS, kind == FSVM_FS_EXFAT ? EXFAT_OPTS : VFAT_OPTS)) {
			read_only = 0;
			check_pending = 0;
			check_state = FSVM_CHECK_NONE;
			was_dirty = 0;
			clean_at_unmount = 1;
			logline("checked, writable now (remounted)", dev, 0);
			return 0;
		}
		logline("remount for the switch, unmounting instead", MNT, errno);
	}
	handle_suspend_all();
	if (umount(MNT)) {
		int e = errno;
		handle_resume_all();
		logline("unmount for the switch", MNT, e);
		return -e;
	}
	fs_kind = 0;
	int r = 0;
	if (check_state == FSVM_CHECK_ERRORS) {
		int64_t deadline = now_ms() + (repair_ms ? repair_ms : 1);
		r = check_volume(dev, kind, repair_ms ? repair_ms : 1);
		if (r < 0 && verify_after_repair(dev, kind, deadline + 5000)) {
			logline("repaired, a check without writes finds nothing now", dev, 0);
			r = mark_clean(dev, kind);
		}
	} else {
		r = mark_clean(dev, kind);
	}
	/* 0: repaired or clean, mounted writable. Otherwise read-only again, with its marks. */
	int ro = r != 0;
	if (try_mount(dev, ro) && (ro || try_mount(dev, 1))) {
		logline("no filesystem after the switch", dev, errno);
		check_pending = 0;
		return -EIO;
	}
	struct statfs sf;
	(void)statfs(MNT, &sf);
	handle_resume_all();
	check_pending = read_only;
	check_state = read_only ? FSVM_CHECK_FAILED : FSVM_CHECK_NONE;
	was_dirty = read_only;
	logline(read_only ? "check did not pass, served read-only" : "checked, now writable", dev, 0);
	return read_only ? (r == 1 ? -ETIMEDOUT : -EIO) : 0;
}

/*
 * Mounts partition `index` (0: the whole disk) once. It must be in the layout read from the disk at exactly `start`
 * and `length`, and this kernel's partition device must agree. A writable mount is checked first, within
 * `check_ms`. Then the free space is counted once: the FAT driver reads its whole table for that, which belongs
 * here, inside MOUNT's deadline, not in a later STATFS.
 */
/*
 * A GPT without the protective MBR: this VM's kernel does not read it (Linux needs the MBR or a "gpt" switch), the
 * table reader did. The partition is added to this VM's own kernel at the range read, so it can be mounted. Only
 * inside the VM: Android's kernel never gets it.
 */
static void add_own_partition(const char *dev, uint32_t index, uint64_t start, uint64_t length)
{
	struct blkpg_partition p = { 0 };
	p.pno = (int)index;
	p.start = (long long)(start * 512);
	p.length = (long long)(length * 512);
	struct blkpg_ioctl_arg a = { 0 };
	a.op = BLKPG_ADD_PARTITION;
	a.datalen = sizeof(p);
	a.data = &p;
	if (disk_fd < 0 || ioctl(disk_fd, BLKPG, &a))
		logline("adding the partition in the VM", disk_dev, errno);
	for (int wait = 0; wait < 20 && access(dev, F_OK); wait++)
		usleep(50 * 1000); /* devtmpfs makes the node */
}

static int do_mount(uint32_t index, uint64_t start, uint64_t length, int want_ro, uint32_t check_ms, int later)
{
	if (fs_kind) {
		if (index == mounted_index && start == mounted_start && length == mounted_length)
			return 0;
		return -EBUSY;
	}
	int r = read_layout();
	if (r)
		return r;
	const struct fsvm_layout_entry *e = fsvm_layout_find(&layout, index, start, length);
	if (!e)
		return -ENOENT;
	char dev[32];
	if (index == 0) {
		snprintf(dev, sizeof(dev), "%s", disk_dev);
	} else {
		/* This kernel's partition device, compared with the table read in userspace. */
		snprintf(dev, sizeof(dev), "%s%u", disk_dev, index);
		if (access(dev, F_OK) && layout.h.table == FSVM_TABLE_GPT)
			add_own_partition(dev, index, start, length);
		int fd = open(dev, O_RDONLY | O_CLOEXEC);
		struct hd_geometry geo;
		uint64_t bytes = 0;
		int ok = fd >= 0 && !ioctl(fd, HDIO_GETGEO, &geo) && !dev_bytes(fd, &bytes);
		if (fd >= 0)
			close(fd);
		if (!ok)
			return -ENOENT;
		if ((uint64_t)geo.start != start || bytes != length * 512) {
			logline("partition differs from the table read", dev, 0);
			return -EINVAL;
		}
	}
	was_dirty = volume_dirty(dev, e->fs_kind);
	if (!want_ro && was_dirty && later) {
		/* Read-only at once, checked afterwards (FSVM_CHECK), writable only once the check passed. Nothing is
		 * written to the volume before then. */
		want_ro = 1;
		check_pending = 1;
	} else if (!want_ro && !later) {
		r = check_volume(dev, e->fs_kind, check_ms);
		if (r < 0)
			return r;
		if (r == 1)
			want_ro = 1;
	}
	r = try_mount(dev, want_ro);
	if (r) {
		check_pending = 0;
		logline("no FAT or exFAT filesystem on", dev, errno);
		return r;
	}
	mounted_index = index;
	mounted_start = start;
	mounted_length = length;
	snprintf(mounted_dev, sizeof(mounted_dev), "%s", dev);
	struct statfs sf;
	(void)statfs(MNT, &sf);
	logline(was_dirty ? "mounted, it was not cleanly unmounted before" : "mounted", dev, 0);
	return 0;
}

/*
 * Before every orderly stop: writes everything back and unmounts, which marks the filesystem clean. Nothing is
 * served afterwards. 0, or a negative errno when the filesystem could not be written back or unmounted (fsvmd then
 * still stops the VM: it has nothing better).
 */
static int do_unmount(void)
{
	if (!fs_kind)
		return 0;
	int r = 0;
	/* A check still running only reads (-n): it ends, nothing was written, the volume keeps its dirty mark and is
	 * checked at its next mount. */
	check_stop();
	handle_close_all();
	int d = open(MNT, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (d < 0 || syncfs(d))
		r = -EIO;
	/* A remounted volume whose driver hit an error (errors=remount-ro) is not marked clean. */
	struct statvfs v;
	int went_ro = !read_only && (d < 0 || fstatvfs(d, &v) || (v.f_flag & ST_RDONLY));
	if (d >= 0)
		close(d);
	if (umount(MNT)) {
		r = -errno;
		logline("unmount", MNT, errno);
		return r;
	}
	uint32_t kind = fs_kind;
	fs_kind = 0;
	/* The disk's own cache: crosvm writes the card on a flush. */
	int b = open(mounted_dev, O_RDONLY | O_CLOEXEC);
	if (b < 0 || fsync(b))
		r = r ? r : -EIO;
	if (b >= 0)
		close(b);
	/* Remounted writable after its check: the driver left its dirty mark, marked clean here once all is on the disk. */
	if (clean_at_unmount) {
		clean_at_unmount = 0;
		if (!r && !went_ro)
			r = mark_clean(mounted_dev, kind);
	}
	/* Clean means the mark Linux's driver set while mounted is gone: on FAT the boot sector byte (a FAT32 card whose
	 * FAT never carried the clean bit would otherwise read as not clean), on exFAT the volume flag. */
	if (!r && !read_only && (kind == FSVM_FS_EXFAT ? exfat_dirty(mounted_dev) : fat_linux_dirty(mounted_dev)))
		r = -EIO;
	logline(r ? "unmounted, not clean" : "unmounted, clean", mounted_dev, -r);
	return r;
}

/* ---- Self test (host harness only: fsvm_guest_init_selftest, never in the VM's initramfs) ---- */

#ifdef FSVM_SELFTEST

/* The value of `fsvm.selftest=` on the kernel command line, or -1. pvmfw passes no such argument to a real VM. */
static int selftest_arg(void)
{
	char buf[1024];
	int fd = open("/proc/cmdline", O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -1;
	ssize_t n = read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (n <= 0)
		return -1;
	buf[n] = 0;
	const char *p = strstr(buf, "fsvm.selftest=");
	return p ? atoi(p + 14) : -1;
}

/* Reads the layout, mounts a partition, writes, reads back and lists, and logs one result line for the harness. */
static void selftest(int want)
{
	char line[160];
	/* fsvm.format=1 or 2: format the disk in the VM first (FAT32 or exFAT), as FSVM_FORMAT does for vold. */
	char fcmd[1024] = "";
	int ffd = open("/proc/cmdline", O_RDONLY | O_CLOEXEC);
	if (ffd >= 0) {
		ssize_t n = read(ffd, fcmd, sizeof(fcmd) - 1);
		fcmd[n > 0 ? n : 0] = 0;
		close(ffd);
	}
	const char *fmt = strstr(fcmd, "fsvm.format=");
	if (fmt) {
		snprintf(line, sizeof(line), "%d", do_format((uint32_t)atoi(fmt + 12), 60000));
		logline("selftest format", line, 0);
	}
	int r = read_layout();
	snprintf(line, sizeof(line), "%d table %u count %u", r, layout.h.table, layout.h.count);
	logline("selftest layout", line, 0);
	for (uint32_t i = 0; !r && i < layout.h.count; i++) {
		const struct fsvm_layout_entry *e = &layout.e[i];
		snprintf(line, sizeof(line), "%u start %llu length %llu fs %u label %.*s", e->index,
			 (unsigned long long)e->start, (unsigned long long)e->length, e->fs_kind, e->label_len, e->label);
		logline("selftest part", line, 0);
	}
	const struct fsvm_layout_entry *pick = NULL;
	for (uint32_t i = 0; !r && i < layout.h.count; i++)
		if (layout.e[i].fs_kind && (want == 255 || layout.e[i].index == (uint32_t)want))
			pick = pick ? pick : &layout.e[i];
	if (!pick) {
		logline("selftest result", r ? "layout refused" : "nothing to mount", 0);
		return;
	}
	/* fsvm.checklater=1: as fsvmd mounts cards now (MOUNT flags bit 1), a dirty volume read-only first, then the
	 * check, a handle open across the switch, and the switch. */
	char cmd[1024] = "";
	int cfd = open("/proc/cmdline", O_RDONLY | O_CLOEXEC);
	if (cfd >= 0) {
		ssize_t n = read(cfd, cmd, sizeof(cmd) - 1);
		cmd[n > 0 ? n : 0] = 0;
		close(cfd);
	}
	int later = strstr(cmd, "fsvm.checklater=1") != NULL;
	int64_t t0 = now_ms();
	r = do_mount(pick->index, pick->start, pick->length, 0, later ? 0 : 20000, later);
	snprintf(line, sizeof(line), "%d after %lld ms, read-only %d, was dirty %d, check pending %d", r,
		 (long long)(now_ms() - t0), read_only, was_dirty, check_pending);
	logline("selftest mount", line, 0);
	if (r) {
		logline("selftest result", "mount failed", 0);
		return;
	}
	if (check_pending) {
		/* The window: no write reaches the volume. */
		int fd = open(MNT "/fsvm-window.txt", O_CREAT | O_WRONLY | O_CLOEXEC, 0660);
		snprintf(line, sizeof(line), "%d errno %d", fd >= 0, fd >= 0 ? 0 : errno);
		logline("selftest write while checking", line, 0);
		if (fd >= 0)
			close(fd);
		/* A file open across the switch, read-only as everything in the window. */
		uint64_t h = 0;
		DIR *rd = opendir(MNT);
		struct dirent *de0;
		char first[256] = "";
		while (rd && (de0 = readdir(rd)))
			if (de0->d_type == DT_REG) {
				snprintf(first, sizeof(first), "%s", de0->d_name);
				break;
			}
		if (rd)
			closedir(rd);
		int have = first[0] && !handle_open(first, 0, &h);
		struct fsvm_check c = { 0, 0 };
		while (!check_poll(&c) && c.state == FSVM_CHECK_RUNNING)
			usleep(100 * 1000);
		snprintf(line, sizeof(line), "state %u after %u ms", c.state, c.elapsed_ms);
		logline("selftest check", line, 0);
		int sr = check_switch(20000);
		uint8_t one;
		int readable = have && handle_lookup(h) > 0 && pread(handle_lookup(h), &one, 1, 0) >= 0;
		snprintf(line, sizeof(line), "%d read-only %d, open file %s", sr, read_only,
			 !have ? "none" : readable ? "readable" : "lost");
		logline("selftest switch", line, 0);
		if (have)
			handle_close(h);
	}
	int ok = 1;
	if (!read_only) {
		static const char msg[] = "fsvm selftest\n";
		char back[sizeof(msg)];
		int fd = open(MNT "/fsvm-selftest.txt", O_CREAT | O_TRUNC | O_RDWR | O_CLOEXEC, 0660);
		ok = fd >= 0 && write(fd, msg, sizeof(msg)) == (ssize_t)sizeof(msg) && !fsync(fd) &&
		     pread(fd, back, sizeof(back), 0) == (ssize_t)sizeof(back) && !memcmp(back, msg, sizeof(msg));
		if (fd >= 0)
			close(fd);
		/* An open file stays readable and writable through its handle after its name went (OPEN, CLOSE). */
		uint64_t h = 0;
		int hfd = -1;
		ok = ok && !handle_open("fsvm-selftest.txt", 1, &h) && (hfd = handle_lookup(h)) > 0 &&
		     !unlink(MNT "/fsvm-selftest.txt") && pwrite(hfd, "x", 1, 0) == 1 && pread(hfd, back, 1, 0) == 1 &&
		     back[0] == 'x' && !handle_close(h) && handle_lookup(h) < 0;
	}
	unsigned entries = 0;
	DIR *d = opendir(MNT);
	struct dirent *de;
	while (d && (de = readdir(d)))
		entries++;
	if (d)
		closedir(d);
	struct statfs sf;
	ok = ok && d && !statfs(MNT, &sf);
	snprintf(line, sizeof(line), "%s, %u entries, %llu free blocks", ok ? "ok" : "failed", entries,
		 ok ? (unsigned long long)sf.f_bfree : 0ULL);
	logline("selftest result", line, 0);
	/* The orderly stop fsvmd asks for: written back, unmounted, clean. */
	snprintf(line, sizeof(line), "%d", do_unmount());
	logline("selftest unmount", line, 0);
}
#endif

static void write_proc(const char *path, const char *value)
{
	int fd = open(path, O_WRONLY | O_CLOEXEC);
	if (fd < 0)
		return;
	if (write(fd, value, strlen(value)) < 0)
		logline("setting", path, errno);
	close(fd);
}

/* Opens disk `index` as this process's disk: its node, sector size and size. 0, or a negative errno. */
static int select_disk(uint32_t index)
{
	if (fsvm_disk_path(index, disk_dev, sizeof(disk_dev)))
		return -EINVAL;
	for (int wait = 0; wait < 50 && access(disk_dev, F_OK); wait++)
		usleep(100 * 1000);
	disk_fd = open(disk_dev, O_RDONLY | O_CLOEXEC);
	uint64_t bytes = 0;
	int ss = 512;
	if (disk_fd >= 0 && ioctl(disk_fd, BLKSSZGET, &ss))
		ss = 512;
	sector_size = (unsigned)ss;
	if (disk_fd < 0 || dev_bytes(disk_fd, &bytes) || bytes < 512) {
		/* Nothing to serve: Android does not mount the volume. */
		logline("no disk", disk_dev, errno);
		if (disk_fd >= 0)
			close(disk_fd);
		disk_fd = -1;
		return -ENODEV;
	}
	disk_sectors = bytes / 512;
	return 0;
}

/*
 * The server of one connection, in a process of its own (forked by /init), in a process group and a mount namespace
 * of its own: its filesystem is mounted only there, and goes with the process whatever ends it. Answers the
 * connection's FSVM_DISK `q`, serves until the connection closes or sends something malformed, then writes back and
 * unmounts (marked clean), as before an orderly stop.
 */
static void run_server(int s, int listener, const struct fsvm_req *q, uint32_t index) __attribute__((noreturn));
static void run_server(int s, int listener, const struct fsvm_req *q, uint32_t index)
{
	close(listener);
	struct timeval none = { 0, 0 };
	(void)setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &none, sizeof(none));
	int r = 0;
	if (setpgid(0, 0) || unshare(CLONE_NEWNS))
		r = -errno;
	/* The initramfs root propagates nothing, so this only makes sure: a mount here never reaches /init. */
	else if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL))
		logline("making the server's mounts private", NULL, errno);
	if (!r)
		r = select_disk(index);
	struct fsvm_hello h = { FSVM_VERSION, 0, 0, 0, 1 };
	if (reply(s, q->id, r, r ? NULL : &h, sizeof(h)) || r)
		_exit(1);
	serve(s);
	close(s);
	do_unmount();
	sync();
	_exit(0);
}

static struct fsvm_servers servers;

/* Reaps every child that ended: servers, and checkers whose server ended before them. */
static void reap_children(void)
{
	for (;;) {
		pid_t p = waitpid(-1, NULL, WNOHANG);
		if (p <= 0)
			return;
		int i = fsvm_servers_ended(&servers, p);
		if (i >= 0) {
			char name[16];
			(void)fsvm_disk_path((uint32_t)i, name, sizeof(name));
			logline("server ended for", name, 0);
		}
	}
}

/*
 * Before a new server for disk `index`: the one before it saw its connection close and writes back and unmounts, or
 * is stuck. It gets 3 s to end on its own, then it and its checker are killed (its filesystem then goes with its
 * mount namespace). 0, or -EBUSY when it still runs after 5 s more (a card that does not answer).
 */
static int end_server(uint32_t index)
{
	pid_t p = servers.pid[index];
	for (int i = 0; p && i < 80; i++) {
		if (i == 30) {
			logline("ending the earlier server of a disk", NULL, 0);
			kill(-p, SIGKILL);
		}
		usleep(100 * 1000);
		reap_children();
		if (!servers.pid[index])
			return 0;
	}
	return servers.pid[index] ? -EBUSY : 0;
}

/* A byte here for each SIGCHLD, so the accept loop waits without a timeout (an idle VM keeps no timer). */
static int child_pipe[2] = { -1, -1 };

static void on_child(int sig)
{
	(void)sig;
	int saved = errno;
	(void)!write(child_pipe[1], "c", 1);
	errno = saved;
}

/* Takes connections for ever: each names its disk, and a server of its own serves it (run_server). */
static void accept_loop(int ls)
{
	struct sigaction sa;
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = on_child;
	sa.sa_flags = SA_RESTART | SA_NOCLDSTOP;
	if (pipe2(child_pipe, O_CLOEXEC | O_NONBLOCK) == 0)
		(void)sigaction(SIGCHLD, &sa, NULL);
	for (;;) {
		struct pollfd pfd[2] = { { ls, POLLIN, 0 }, { child_pipe[0], POLLIN, 0 } };
		/* Without the pipe, the old one-second look for ended servers. */
		int n = poll(pfd, 2, child_pipe[0] >= 0 ? -1 : 1000);
		if (n > 0 && (pfd[1].revents & POLLIN)) {
			char drain[64];
			while (read(child_pipe[0], drain, sizeof(drain)) > 0)
				;
		}
		reap_children();
		if (n <= 0 || !(pfd[0].revents & POLLIN))
			continue;
		int s = accept4(ls, NULL, NULL, SOCK_CLOEXEC);
		if (s < 0)
			continue;
		/* The host sends FSVM_DISK at once: a connection that does not hold /init up. */
		struct timeval tv = { 2, 0 };
		(void)setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
		struct fsvm_req q;
		uint32_t index = 0;
		if (read_full(s, &q, sizeof(q))) {
			close(s);
			continue;
		}
		int r = fsvm_disk_request(&q, &index);
		if (r == -EPROTO)
			logline("refusing a host of another protocol version", NULL, 0);
		if (!r)
			r = end_server(index);
		pid_t p = r ? -1 : fork();
		if (p == 0) {
			/* A server reaps its own children: the accept loop's handler and pipe are not its. */
			signal(SIGCHLD, SIG_DFL);
			if (child_pipe[0] >= 0) {
				close(child_pipe[0]);
				close(child_pipe[1]);
			}
			run_server(s, ls, &q, index);
		}
		if (p < 0) {
			(void)reply(s, q.id, r ? r : -ENOMEM, NULL, 0);
		} else if (fsvm_servers_set(&servers, index, p)) {
			kill(-p, SIGKILL);
			kill(p, SIGKILL);
		}
		close(s);
	}
}

int main(void)
{
	mkdir("/dev", 0755);
	mkdir("/proc", 0555);
	mkdir("/sys", 0555);
	mkdir(MNT, 0755);
	mount("devtmpfs", "/dev", "devtmpfs", MS_NOSUID | MS_NOEXEC, "mode=0755");
	mount("proc", "/proc", "proc", MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL);
	mount("sysfs", "/sys", "sysfs", MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL);
	/* The kernel had no console to give /init (the initramfs holds no /dev/console). Logs go to it from here. */
	if (fcntl(2, F_GETFD) < 0) {
		int c = open("/dev/console", O_RDWR | O_CLOEXEC);
		if (c >= 0 && c != 2) {
			dup2(c, 1);
			dup2(c, 2);
			close(c);
		}
	}
	node_path[1] = strdup("");
	if (node_path[1]) {
		path_bytes = 1;
		slot_insert(1);
	}

	/*
	 * Written data reaches the card within about two seconds (the kernel's default is 30), so a VM that is killed
	 * without an orderly stop (fsvmd or its service killed, a broken session) loses at most that much.
	 */
	write_proc("/proc/sys/vm/dirty_expire_centisecs", "100");
	write_proc("/proc/sys/vm/dirty_writeback_centisecs", "100");
	/* And at most 8 MiB waits at any time (write back starts at 2 MiB), so an eject has little left to write. */
	write_proc("/proc/sys/vm/dirty_bytes", "8388608");
	write_proc("/proc/sys/vm/dirty_background_bytes", "2097152");

#ifdef FSVM_SELFTEST
	int want = selftest_arg();
	if (want >= 0) {
		if (!select_disk(0))
			selftest(want);
		sync();
		reboot(RB_POWER_OFF);
	}
#endif

	int ls = socket(AF_VSOCK, SOCK_STREAM | SOCK_CLOEXEC, 0);
	struct sockaddr_vm a = { 0 };
	a.svm_family = AF_VSOCK;
	a.svm_port = FSVM_PORT;
	a.svm_cid = VMADDR_CID_ANY;
	if (ls < 0 || bind(ls, (struct sockaddr *)&a, sizeof(a)) || listen(ls, 8)) {
		logline("vsock", NULL, errno);
		for (;;)
			pause();
	}
	logline("serving on vsock", NULL, 0);
	accept_loop(ls);
	return 0;
}
