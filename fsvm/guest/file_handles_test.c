/* Copyright (C) 2026 DiamaneOS
 * SPDX-License-Identifier: Apache-2.0
 */

/* The older host sysroot needs socket types before linux/vm_sockets.h. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <sys/socket.h>

/* The real guest dispatcher, without starting PID 1 or mounting a filesystem. */
#define main fsvm_guest_main
#include "fsvm_guest.c"
#undef main

static int failures;
#define CHECK(c) do { if (!(c)) { fprintf(stderr, "line %d: %s\n", __LINE__, #c); failures++; } } while (0)

static int call_file(int s[2], struct fsvm_req *q, struct fsvm_attr *at)
{
	struct fsvm_rsp rsp;
	CHECK(handle(s[0], q, "", "", NULL) == 0);
	CHECK(read(s[1], &rsp, sizeof(rsp)) == sizeof(rsp));
	CHECK(rsp.id == q->id);
	if (rsp.len) {
		CHECK(rsp.len == sizeof(*at));
		CHECK(read(s[1], at, sizeof(*at)) == sizeof(*at));
	}
	return rsp.status;
}

int main(void)
{
	char path[] = "file-handle-XXXXXX";
	int fd = mkstemp(path), s[2];
	CHECK(fd > 0);
	if (fd <= 0)
		return 1;
	CHECK(write(fd, "ORIGINAL", 8) == 8);
	CHECK(unlink(path) == 0);
	CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, s) == 0);
	fs_kind = FSVM_FS_VFAT;
	handle_fd[1] = fd;
	handle_gen[1] = 7;
	struct fsvm_req q = { .op = FSVM_TRUNCATE, .id = 9, .node2 = (7ULL << 32) | 1, .arg = 3 };
	struct fsvm_attr at = {0};
	CHECK(call_file(s, &q, &at) == 0);
	CHECK(at.size == 3 && at.kind == FSVM_KIND_FILE);
	q.op = FSVM_SETMTIME;
	q.arg = 1700000100;
	q.len = 12345;
	CHECK(call_file(s, &q, &at) == 0);
	CHECK(at.mtime_s == 1700000100 && at.mtime_ns == 12345);
	read_only = 1;
	q.op = FSVM_TRUNCATE;
	q.arg = 1;
	CHECK(call_file(s, &q, &at) == -EROFS);
	q.op = FSVM_SETMTIME;
	CHECK(call_file(s, &q, &at) == -EROFS);
	q.op = FSVM_GETATTR;
	CHECK(call_file(s, &q, &at) == 0 && at.size == 3 && at.mtime_s == 1700000100);
	q.node2++;
	CHECK(call_file(s, &q, &at) == -EBADF);
	close(fd);
	close(s[0]);
	close(s[1]);
	printf("guest file handle dispatch: %d failures\n", failures);
	return failures != 0;
}
