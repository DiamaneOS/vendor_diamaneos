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

#include "disks.h"

#include <errno.h>
#include <stdio.h>

int fsvm_disk_request(const struct fsvm_req *q, uint32_t *index)
{
	if (q->magic != FSVM_REQ_MAGIC || q->op != FSVM_DISK)
		return -EINVAL;
	if (q->node != FSVM_VERSION)
		return -EPROTO;
	if (q->flags || q->name_len || q->name2_len || q->node2 || q->len || q->arg >= FSVM_MAX_DISKS)
		return -EINVAL;
	*index = (uint32_t)q->arg;
	return 0;
}

int fsvm_disk_path(uint32_t index, char *out, size_t size)
{
	if (index >= FSVM_MAX_DISKS)
		return -EINVAL;
	int n = snprintf(out, size, "/dev/vd%c", (char)('a' + index));
	return n > 0 && (size_t)n < size ? 0 : -EINVAL;
}

int fsvm_servers_set(struct fsvm_servers *s, uint32_t index, pid_t pid)
{
	if (index >= FSVM_MAX_DISKS || pid <= 0 || s->pid[index])
		return -EBUSY;
	s->pid[index] = pid;
	return 0;
}

int fsvm_servers_ended(struct fsvm_servers *s, pid_t pid)
{
	if (pid <= 0)
		return -1;
	for (uint32_t i = 0; i < FSVM_MAX_DISKS; i++) {
		if (s->pid[i] == pid) {
			s->pid[i] = 0;
			return (int)i;
		}
	}
	return -1;
}

int fsvm_changes_volume(const struct fsvm_req *q)
{
	switch (q->op) {
	case FSVM_CREATE:
	case FSVM_MKDIR:
	case FSVM_UNLINK:
	case FSVM_RMDIR:
	case FSVM_RENAME:
	case FSVM_TRUNCATE:
	case FSVM_SETMTIME:
	case FSVM_WRITE:
		return 1;
	case FSVM_OPEN:
		return q->flags & 1;
	default:
		return 0;
	}
}
