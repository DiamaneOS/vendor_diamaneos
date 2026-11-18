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
 * Partition tables and filesystem signatures, read inside the filesystem VM. Android checks everything reported
 * here again (layout.rs), so this code aims to be correct and bounded, not to defend Android. What it reads:
 *
 * - A FAT or exFAT boot sector at sector 0: a filesystem on the whole disk, no table (checked first, as blkid does,
 *   because a FAT boot sector also ends in 55 AA).
 * - An MBR: the four primary entries. Types vold serves (06 07 0b 0c 0e) are reported. Extended partitions and
 *   the logical partitions in them are not.
 * - A GPT (protective MBR type ee): the primary header and entries, or the backup when the primary fails its
 *   checksums. Only the types vold uses are reported: basic data, android_meta and android_expand.
 * - For each public partition: FAT or exFAT, its serial (the volume UUID), its label, and how much metadata its
 *   filesystem driver needs (one FAT, or the exFAT allocation bitmap).
 */
#include "table.h"

#include <errno.h>
#include <string.h>

#define SECTOR 512u
#define MAX_SECTOR 4096u
#define GPT_MAX_ENTRIES 128u
#define GPT_ENTRY_SIZE 128u
#define LABEL_SCAN_MAX (64u * 1024u)

static const uint8_t gpt_basic_data[16] = { 0xA2, 0xA0, 0xD0, 0xEB, 0xE5, 0xB9, 0x33, 0x44,
					    0x87, 0xC0, 0x68, 0xB6, 0xB7, 0x26, 0x99, 0xC7 };
static const uint8_t gpt_android_meta[16] = { 0xA2, 0x10, 0xA7, 0x19, 0xCA, 0xB3, 0xE4, 0x11,
					      0xB0, 0x26, 0x10, 0x60, 0x4B, 0x88, 0x9D, 0xCF };
static const uint8_t gpt_android_expand[16] = { 0xA4, 0x1E, 0x3D, 0x19, 0xCA, 0xB3, 0xE4, 0x11,
						0xB0, 0x75, 0x10, 0x60, 0x4B, 0x88, 0x9D, 0xCF };

static uint16_t le16(const uint8_t *p)
{
	return (uint16_t)(p[0] | p[1] << 8);
}

static uint32_t le32(const uint8_t *p)
{
	return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

static uint64_t le64(const uint8_t *p)
{
	return (uint64_t)le32(p) | (uint64_t)le32(p + 4) << 32;
}

static uint32_t crc32(const uint8_t *p, size_t n)
{
	uint32_t c = 0xFFFFFFFFu;
	while (n--) {
		c ^= *p++;
		for (int k = 0; k < 8; k++)
			c = (c >> 1) ^ (0xEDB88320u & (0u - (c & 1u)));
	}
	return ~c;
}

static int is_pow2(uint32_t v)
{
	return v && !(v & (v - 1));
}

/* ---- Labels ---- */

/* Copies an 11-byte FAT label: printable ASCII only (other bytes are in an unknown code page), trailing spaces cut. */
static void fat_label(struct fsvm_layout_entry *e, const uint8_t *raw)
{
	size_t n = 11;
	while (n && raw[n - 1] == ' ')
		n--;
	for (size_t i = 0; i < n; i++)
		if (raw[i] < 0x20 || raw[i] > 0x7E)
			return;
	memcpy(e->label, raw, n);
	e->label_len = (uint8_t)n;
}

/* Converts up to 11 UTF-16LE units to UTF-8. Leaves no label on any invalid unit. */
static void utf16_label(struct fsvm_layout_entry *e, const uint8_t *raw, unsigned units)
{
	uint8_t out[FSVM_MAX_LABEL];
	size_t n = 0;
	for (unsigned i = 0; i < units; i++) {
		uint32_t c = le16(raw + 2 * i);
		if (c >= 0xD800 && c <= 0xDBFF) {
			if (i + 1 >= units)
				return;
			uint32_t lo = le16(raw + 2 * (i + 1));
			if (lo < 0xDC00 || lo > 0xDFFF)
				return;
			c = 0x10000 + ((c - 0xD800) << 10) + (lo - 0xDC00);
			i++;
		} else if (c >= 0xDC00 && c <= 0xDFFF) {
			return;
		}
		if (c < 0x20)
			return;
		if (n + 4 > sizeof(out))
			return;
		if (c < 0x80) {
			out[n++] = (uint8_t)c;
		} else if (c < 0x800) {
			out[n++] = (uint8_t)(0xC0 | c >> 6);
			out[n++] = (uint8_t)(0x80 | (c & 0x3F));
		} else if (c < 0x10000) {
			out[n++] = (uint8_t)(0xE0 | c >> 12);
			out[n++] = (uint8_t)(0x80 | (c >> 6 & 0x3F));
			out[n++] = (uint8_t)(0x80 | (c & 0x3F));
		} else {
			out[n++] = (uint8_t)(0xF0 | c >> 18);
			out[n++] = (uint8_t)(0x80 | (c >> 12 & 0x3F));
			out[n++] = (uint8_t)(0x80 | (c >> 6 & 0x3F));
			out[n++] = (uint8_t)(0x80 | (c & 0x3F));
		}
	}
	while (n && out[n - 1] == ' ')
		n--;
	memcpy(e->label, out, n);
	e->label_len = (uint8_t)n;
}

static uint8_t scan[LABEL_SCAN_MAX];

/* ---- Filesystems ---- */

static int is_exfat(const uint8_t *b)
{
	return !memcmp(b + 3, "EXFAT   ", 8) && b[510] == 0x55 && b[511] == 0xAA;
}

/* The checks the kernel's FAT driver makes before it trusts a boot sector, plus the jump instruction. */
static int is_fat(const uint8_t *b)
{
	uint32_t bps = le16(b + 11), spc = b[13], reserved = le16(b + 14), fats = b[16], media = b[21];
	if (b[0] != 0xEB && b[0] != 0xE9)
		return 0;
	if (b[510] != 0x55 || b[511] != 0xAA)
		return 0;
	if (!is_pow2(bps) || bps < 512 || bps > 4096 || !is_pow2(spc) || !reserved || !fats || fats > 2)
		return 0;
	if (media != 0xF0 && media < 0xF8)
		return 0;
	uint32_t fat16 = le16(b + 22), fat32 = le32(b + 36);
	return fat16 || fat32;
}

/*
 * Fills the filesystem fields of `e` from the partition at byte offset `off` with `bytes` bytes. Leaves fs_kind 0
 * when nothing is recognised.
 */
static void probe_fs(fsvm_read_fn rd, void *ctx, uint64_t off, uint64_t bytes, struct fsvm_layout_entry *e)
{
	uint8_t b[SECTOR];
	if (bytes < SECTOR || rd(ctx, off, b, sizeof(b)))
		return;

	if (is_exfat(b)) {
		uint32_t heap = le32(b + 88), clusters = le32(b + 92), root = le32(b + 96);
		unsigned bps_shift = b[108], spc_shift = b[109];
		if (bps_shift < 9 || bps_shift > 12 || spc_shift > 25 - bps_shift)
			return;
		e->fs_kind = FSVM_FS_EXFAT;
		e->serial = le32(b + 100);
		e->flags |= 1;
		e->meta_bytes = ((uint64_t)clusters + 7) / 8;
		/* The volume label is an entry (type 0x83) in the root directory's first cluster. */
		uint64_t cluster = (uint64_t)1 << (bps_shift + spc_shift);
		uint64_t at = off + (((uint64_t)heap + (((uint64_t)root - 2) << spc_shift)) << bps_shift);
		size_t want = cluster < LABEL_SCAN_MAX ? (size_t)cluster : LABEL_SCAN_MAX;
		if (root < 2 || at + want > off + bytes || at < off || rd(ctx, at, scan, want))
			return;
		for (size_t i = 0; i + 32 <= want; i += 32) {
			uint8_t type = scan[i];
			if (type == 0x00)
				break;
			if (type == 0x83) {
				unsigned units = scan[i + 1];
				if (units <= 11)
					utf16_label(e, scan + i + 2, units);
				break;
			}
		}
		return;
	}

	if (!is_fat(b))
		return;
	uint32_t bps = le16(b + 11), spc = b[13], reserved = le16(b + 14), fats = b[16];
	uint32_t root_entries = le16(b + 17), fat16 = le16(b + 22);
	int is32 = fat16 == 0;
	uint64_t fat_sectors = is32 ? le32(b + 36) : fat16;
	const uint8_t *ext = b + (is32 ? 66 : 38);
	e->fs_kind = FSVM_FS_VFAT;
	e->meta_bytes = fat_sectors * bps;
	if (ext[0] == 0x28 || ext[0] == 0x29) {
		e->serial = le32(ext + 1);
		e->flags |= 1;
	}
	/* The label: the root directory's volume label entry, else the boot sector's unless it is "NO NAME". */
	uint64_t root_off, root_len;
	if (is32) {
		uint32_t root = le32(b + 44);
		uint64_t data = (uint64_t)reserved + fats * fat_sectors;
		root_off = (data + ((uint64_t)root - 2) * spc) * bps;
		root_len = (uint64_t)spc * bps;
		if (root < 2)
			root_len = 0;
	} else {
		root_off = ((uint64_t)reserved + fats * fat_sectors) * bps;
		root_len = (uint64_t)root_entries * 32;
	}
	if (root_len > LABEL_SCAN_MAX)
		root_len = LABEL_SCAN_MAX;
	if (root_len && root_off + root_len <= bytes && !rd(ctx, off + root_off, scan, (size_t)root_len)) {
		for (size_t i = 0; i + 32 <= root_len; i += 32) {
			const uint8_t *d = scan + i;
			if (d[0] == 0x00)
				break;
			if (d[0] == 0xE5 || (d[11] & 0x3F) == 0x0F)
				continue;
			if ((d[11] & 0x18) == 0x08) {
				fat_label(e, d);
				return;
			}
		}
	}
	if (ext[0] == 0x29 && memcmp(ext + 5, "NO NAME    ", 11))
		fat_label(e, ext + 5);
}

/* ---- Tables ---- */

static int add_entry(struct fsvm_layout *l, uint32_t index, uint64_t start, uint64_t length,
		     struct fsvm_layout_entry **out)
{
	if (l->h.count >= FSVM_MAX_LAYOUT_ENTRIES)
		return -E2BIG;
	struct fsvm_layout_entry *e = &l->e[l->h.count++];
	memset(e, 0, sizeof(*e));
	e->index = index;
	e->start = start;
	e->length = length;
	*out = e;
	return 0;
}

/*
 * One GPT header and its entries at `lba`. LBAs count logical blocks of `ss` bytes (512, or 4096 on some USB disks).
 * The layout counts 512-byte sectors. Returns 0 and fills `l`, or a negative errno.
 */
static int read_gpt_at(fsvm_read_fn rd, void *ctx, uint64_t disk_sectors, unsigned ss, uint64_t lba, int primary,
		       struct fsvm_layout *l)
{
	static uint8_t entries[GPT_MAX_ENTRIES * GPT_ENTRY_SIZE];
	static uint8_t h[MAX_SECTOR];
	const uint64_t f = ss / SECTOR, lbas = disk_sectors / f;
	if (lba >= lbas || rd(ctx, lba * ss, h, ss))
		return -EIO;
	if (memcmp(h, "EFI PART", 8))
		return -EINVAL;
	uint32_t hsize = le32(h + 12);
	if (hsize < 92 || hsize > ss)
		return -EINVAL;
	uint32_t want = le32(h + 16);
	memset(h + 16, 0, 4);
	if (crc32(h, hsize) != want)
		return -EINVAL;
	uint64_t my = le64(h + 24), first = le64(h + 40), last = le64(h + 48), table = le64(h + 72);
	uint32_t n = le32(h + 80), esize = le32(h + 84), ecrc = le32(h + 88);
	if (my != lba || (primary ? le64(h + 32) >= lbas : 0))
		return -EINVAL;
	/* A table claiming hundreds of entries or odd entry sizes is not one vold ever wrote. */
	if (n == 0 || n > GPT_MAX_ENTRIES || esize != GPT_ENTRY_SIZE)
		return -E2BIG;
	uint64_t tlbas = ((uint64_t)n * esize + ss - 1) / ss;
	if (first > last || last >= lbas || table < 2 || table + tlbas > lbas)
		return -EINVAL;
	if (rd(ctx, table * ss, entries, (size_t)n * esize))
		return -EIO;
	if (crc32(entries, (size_t)n * esize) != ecrc)
		return -EINVAL;

	memset(l, 0, sizeof(*l));
	l->h.disk_sectors = disk_sectors;
	l->h.table = FSVM_TABLE_GPT;
	for (uint32_t i = 0; i < n; i++) {
		const uint8_t *p = entries + (size_t)i * esize;
		int known = !memcmp(p, gpt_basic_data, 16) || !memcmp(p, gpt_android_meta, 16) ||
			    !memcmp(p, gpt_android_expand, 16);
		if (!known)
			continue;
		uint64_t s = le64(p + 32), e = le64(p + 40);
		if (e < s || s < first || e > last)
			return -EINVAL;
		struct fsvm_layout_entry *x;
		int r = add_entry(l, i + 1, s * f, (e - s + 1) * f, &x);
		if (r)
			return r;
		memcpy(x->type_guid, p, 16);
		memcpy(x->part_guid, p + 16, 16);
		if (!memcmp(p, gpt_basic_data, 16))
			probe_fs(rd, ctx, s * ss, (e - s + 1) * ss, x);
	}
	return 0;
}

int fsvm_read_layout(fsvm_read_fn rd, void *ctx, uint64_t disk_sectors, unsigned sector_size,
		     struct fsvm_layout *l)
{
	uint8_t b[SECTOR];
	const unsigned ss = sector_size;
	memset(l, 0, sizeof(*l));
	l->h.disk_sectors = disk_sectors;
	if (disk_sectors < 1 || disk_sectors > (UINT64_MAX >> 10) || (ss != 512 && ss != 4096) ||
	    disk_sectors % (ss / SECTOR))
		return -EINVAL;
	const uint64_t f = ss / SECTOR, lbas = disk_sectors / f;
	if (rd(ctx, 0, b, sizeof(b)))
		return -EIO;

	/* A filesystem on the whole disk. */
	if (is_exfat(b) || is_fat(b)) {
		struct fsvm_layout_entry *e;
		add_entry(l, 0, 0, disk_sectors, &e);
		probe_fs(rd, ctx, 0, disk_sectors * SECTOR, e);
		if (!e->fs_kind)
			l->h.count = 0;
		return 0;
	}
	if (b[510] != 0x55 || b[511] != 0xAA)
		return 0; /* nothing Android can use */

	const uint8_t *p = b + 446;
	for (int i = 0; i < 4; i++)
		if (p[16 * i] != 0x00 && p[16 * i] != 0x80)
			return 0; /* not a partition table */
	for (int i = 0; i < 4; i++) {
		if (p[16 * i + 4] == 0xEE) {
			int r = read_gpt_at(rd, ctx, disk_sectors, ss, 1, 1, l);
			if (r == -E2BIG)
				return r;
			if (r)
				r = read_gpt_at(rd, ctx, disk_sectors, ss, lbas - 1, 0, l);
			return r;
		}
	}

	l->h.table = FSVM_TABLE_MBR;
	for (int i = 0; i < 4; i++) {
		const uint8_t *q = p + 16 * i;
		uint8_t type = q[4];
		uint64_t s = le32(q + 8), n = le32(q + 12);
		if (type != 0x06 && type != 0x07 && type != 0x0b && type != 0x0c && type != 0x0e)
			continue;
		if (!n || !s || s + n > lbas)
			return -EINVAL;
		struct fsvm_layout_entry *e;
		int r = add_entry(l, (uint32_t)i + 1, s * f, n * f, &e);
		if (r)
			return r;
		e->mbr_type = type;
		probe_fs(rd, ctx, s * ss, n * ss, e);
	}
	return 0;
}

const struct fsvm_layout_entry *fsvm_layout_find(const struct fsvm_layout *l, uint32_t index, uint64_t start,
						 uint64_t length)
{
	for (uint32_t i = 0; i < l->h.count; i++) {
		const struct fsvm_layout_entry *e = &l->e[i];
		if (e->index != index || e->start != start || e->length != length || !e->fs_kind)
			continue;
		return e;
	}
	return NULL;
}
