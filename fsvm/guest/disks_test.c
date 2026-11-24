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
 * Host tests of the guest's disk selection (disks.c): the first request of a connection, the version check, the
 * disk names, and one server per disk.
 */
#include "disks.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>

static int failures;
static const char *current = "";

#define CHECK(cond)                                                                       \
	do {                                                                              \
		if (!(cond)) {                                                            \
			fprintf(stderr, "%s:%d: %s: check failed: %s\n", __FILE__, __LINE__, \
				current, #cond);                                           \
			failures++;                                                       \
		}                                                                         \
	} while (0)

static struct fsvm_req disk_req(uint64_t index)
{
	struct fsvm_req q;
	memset(&q, 0, sizeof(q));
	q.magic = FSVM_REQ_MAGIC;
	q.op = FSVM_DISK;
	q.id = 1;
	q.node = FSVM_VERSION;
	q.arg = index;
	return q;
}

static void first_request(void)
{
	current = "first request";
	uint32_t index = 99;
	struct fsvm_req q = disk_req(0);
	CHECK(fsvm_disk_request(&q, &index) == 0 && index == 0);
	q = disk_req(3);
	CHECK(fsvm_disk_request(&q, &index) == 0 && index == 3);
	q = disk_req(FSVM_MAX_DISKS - 1);
	CHECK(fsvm_disk_request(&q, &index) == 0 && index == FSVM_MAX_DISKS - 1);

	current = "first request refused";
	index = 99;
	q = disk_req(FSVM_MAX_DISKS);
	CHECK(fsvm_disk_request(&q, &index) == -EINVAL);
	q = disk_req(UINT64_MAX);
	CHECK(fsvm_disk_request(&q, &index) == -EINVAL);
	/* A host of another version: refused by name, before anything else. */
	q = disk_req(0);
	q.node = FSVM_VERSION - 1;
	CHECK(fsvm_disk_request(&q, &index) == -EPROTO);
	q.node = FSVM_VERSION + 1;
	CHECK(fsvm_disk_request(&q, &index) == -EPROTO);
	/* An older host's first request is HELLO: no disk is chosen for it. */
	q = disk_req(0);
	q.op = FSVM_HELLO;
	CHECK(fsvm_disk_request(&q, &index) == -EINVAL);
	q = disk_req(0);
	q.op = FSVM_MOUNT;
	CHECK(fsvm_disk_request(&q, &index) == -EINVAL);
	q = disk_req(0);
	q.magic = 0;
	CHECK(fsvm_disk_request(&q, &index) == -EINVAL);
	/* Nothing else may be set: a name or data would follow the header unread. */
	q = disk_req(0);
	q.name_len = 1;
	CHECK(fsvm_disk_request(&q, &index) == -EINVAL);
	q = disk_req(0);
	q.name2_len = 1;
	CHECK(fsvm_disk_request(&q, &index) == -EINVAL);
	q = disk_req(0);
	q.len = 1;
	CHECK(fsvm_disk_request(&q, &index) == -EINVAL);
	q = disk_req(0);
	q.flags = 1;
	CHECK(fsvm_disk_request(&q, &index) == -EINVAL);
	q = disk_req(0);
	q.node2 = 1;
	CHECK(fsvm_disk_request(&q, &index) == -EINVAL);
	CHECK(index == 99);
}

static void paths(void)
{
	current = "paths";
	char p[16];
	CHECK(fsvm_disk_path(0, p, sizeof(p)) == 0 && strcmp(p, "/dev/vda") == 0);
	CHECK(fsvm_disk_path(1, p, sizeof(p)) == 0 && strcmp(p, "/dev/vdb") == 0);
	CHECK(fsvm_disk_path(FSVM_MAX_DISKS - 1, p, sizeof(p)) == 0 && strcmp(p, "/dev/vdh") == 0);
	CHECK(fsvm_disk_path(FSVM_MAX_DISKS, p, sizeof(p)) == -EINVAL);
	char small[8];
	CHECK(fsvm_disk_path(0, small, sizeof(small)) == -EINVAL);
}

static void servers(void)
{
	current = "servers";
	struct fsvm_servers s;
	memset(&s, 0, sizeof(s));
	CHECK(fsvm_servers_set(&s, 0, 100) == 0);
	CHECK(fsvm_servers_set(&s, 1, 101) == 0);
	/* One server per disk: a second one for disk 0 only once the first ended. */
	CHECK(fsvm_servers_set(&s, 0, 102) == -EBUSY);
	CHECK(fsvm_servers_set(&s, FSVM_MAX_DISKS, 103) == -EBUSY);
	CHECK(fsvm_servers_set(&s, 2, 0) == -EBUSY);
	/* A process that served no disk (a checker the kernel gave back to /init). */
	CHECK(fsvm_servers_ended(&s, 555) == -1);
	CHECK(fsvm_servers_ended(&s, 0) == -1);
	CHECK(s.pid[0] == 100 && s.pid[1] == 101);
	/* Disk 1's server ends: disk 0's keeps running. */
	CHECK(fsvm_servers_ended(&s, 101) == 1);
	CHECK(s.pid[0] == 100 && s.pid[1] == 0);
	CHECK(fsvm_servers_ended(&s, 101) == -1);
	CHECK(fsvm_servers_set(&s, 1, 104) == 0);
	CHECK(fsvm_servers_ended(&s, 100) == 0);
	CHECK(fsvm_servers_set(&s, 0, 105) == 0);
	CHECK(s.pid[0] == 105 && s.pid[1] == 104);
}

int main(void)
{
	first_request();
	paths();
	servers();
	if (failures) {
		fprintf(stderr, "fsvm_guest_disks_test: %d failures\n", failures);
		return 1;
	}
	printf("fsvm_guest_disks_test: all passed\n");
	return 0;
}
