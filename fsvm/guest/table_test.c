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
 * Host tests of the guest's table reader (table.c) on disks built in memory: honest MBR and GPT layouts with
 * several partitions, and hostile ones (hundreds of entries, ranges past the disk, overlaps, broken checksums).
 *
 * With an argument DIR, each case's LAYOUT reply is also written to DIR/<case>.layout, and the protocol's Rust
 * tests decode them (proto/tests/guest_layouts.rs), so the two sides are checked against each other.
 */
#include "table.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DISK_SECTORS (16u * 2048u) /* 16 MiB */

static uint8_t disk[DISK_SECTORS * 512u];
static const char *dump_dir;
static int failures;

#define CHECK(cond)                                                                       \
	do {                                                                              \
		if (!(cond)) {                                                            \
			fprintf(stderr, "%s:%d: %s: check failed: %s\n", __FILE__, __LINE__, \
				current, #cond);                                           \
			failures++;                                                       \
		}                                                                         \
	} while (0)

static const char *current = "";
static unsigned sector_size = 512;
/* A sector whose read fails, as on a card with a bad spot or a loose contact (UINT64_MAX: none). */
static uint64_t bad_sector = UINT64_MAX;

static int rd(void *ctx, uint64_t off, void *buf, size_t len)
{
	(void)ctx;
	if (off > sizeof(disk) || len > sizeof(disk) - off)
		return -1;
	if (bad_sector != UINT64_MAX && off < (bad_sector + 1) * 512 && off + len > bad_sector * 512)
		return -1;
	memcpy(buf, disk + off, len);
	return 0;
}

static void put16(uint8_t *p, uint16_t v)
{
	p[0] = (uint8_t)v;
	p[1] = (uint8_t)(v >> 8);
}

static void put32(uint8_t *p, uint32_t v)
{
	put16(p, (uint16_t)v);
	put16(p + 2, (uint16_t)(v >> 16));
}

static void put64(uint8_t *p, uint64_t v)
{
	put32(p, (uint32_t)v);
	put32(p + 4, (uint32_t)(v >> 32));
}

static uint32_t crc(const uint8_t *p, size_t n)
{
	uint32_t c = 0xFFFFFFFFu;
	while (n--) {
		c ^= *p++;
		for (int k = 0; k < 8; k++)
			c = (c >> 1) ^ (0xEDB88320u & (0u - (c & 1u)));
	}
	return ~c;
}

/* A FAT32 boot sector at `sector` with a label entry in its root directory. */
static void make_fat32(uint64_t sector, uint32_t serial, const char *label)
{
	uint8_t *b = disk + sector * 512;
	memset(b, 0, 512);
	b[0] = 0xEB;
	b[1] = 0x58;
	b[2] = 0x90;
	memcpy(b + 3, "MSWIN4.1", 8);
	put16(b + 11, 512);
	b[13] = 1;      /* sectors per cluster */
	put16(b + 14, 32); /* reserved */
	b[16] = 2;
	b[21] = 0xF8;
	put32(b + 36, 16); /* sectors per FAT */
	put32(b + 44, 2);  /* root cluster */
	b[66] = 0x29;
	put32(b + 67, serial);
	memcpy(b + 71, "NO NAME    ", 11);
	memcpy(b + 82, "FAT32   ", 8);
	b[510] = 0x55;
	b[511] = 0xAA;
	if (label) {
		uint8_t *root = disk + (sector + 32 + 2 * 16) * 512;
		memset(root, 0, 64);
		memset(root, ' ', 11);
		memcpy(root, label, strlen(label));
		root[11] = 0x08;
	}
}

/* An exFAT boot sector at `sector`, with a label entry of `units` UTF-16 units. */
static void make_exfat(uint64_t sector, uint32_t serial, const uint16_t *label, unsigned units)
{
	uint8_t *b = disk + sector * 512;
	memset(b, 0, 512);
	b[0] = 0xEB;
	b[1] = 0x76;
	b[2] = 0x90;
	memcpy(b + 3, "EXFAT   ", 8);
	put32(b + 88, 64);   /* cluster heap offset, sectors */
	put32(b + 92, 1000); /* clusters */
	put32(b + 96, 4);    /* root directory cluster */
	put32(b + 100, serial);
	b[108] = 9; /* 512-byte sectors */
	b[109] = 3; /* 8 sectors per cluster */
	b[510] = 0x55;
	b[511] = 0xAA;
	uint8_t *root = disk + (sector + 64 + 2 * 8) * 512;
	memset(root, 0, 64);
	root[0] = 0x83;
	root[1] = (uint8_t)units;
	for (unsigned i = 0; i < units; i++)
		put16(root + 2 + 2 * i, label[i]);
}

/* An EBR at `sector`: the logical partition (relative to the EBR) and the link (relative to the extended start). */
static void ebr(uint32_t sector, uint8_t type, uint32_t start, uint32_t count, uint32_t next, uint32_t next_count)
{
	uint8_t *b = disk + (uint64_t)sector * 512;
	memset(b + 446, 0, 64);
	b[446 + 4] = type;
	put32(b + 446 + 8, start);
	put32(b + 446 + 12, count);
	if (next_count) {
		b[462 + 4] = 0x05;
		put32(b + 462 + 8, next);
		put32(b + 462 + 12, next_count);
	}
	b[510] = 0x55;
	b[511] = 0xAA;
}

static void mbr(int slot, uint8_t boot, uint8_t type, uint32_t start, uint32_t count)
{
	uint8_t *p = disk + 446 + 16 * slot;
	p[0] = boot;
	p[4] = type;
	put32(p + 8, start);
	put32(p + 12, count);
	disk[510] = 0x55;
	disk[511] = 0xAA;
}

static const uint8_t basic[16] = { 0xA2, 0xA0, 0xD0, 0xEB, 0xE5, 0xB9, 0x33, 0x44,
				   0x87, 0xC0, 0x68, 0xB6, 0xB7, 0x26, 0x99, 0xC7 };
static const uint8_t meta[16] = { 0xA2, 0x10, 0xA7, 0x19, 0xCA, 0xB3, 0xE4, 0x11,
				  0xB0, 0x26, 0x10, 0x60, 0x4B, 0x88, 0x9D, 0xCF };
static const uint8_t expand[16] = { 0xA4, 0x1E, 0x3D, 0x19, 0xCA, 0xB3, 0xE4, 0x11,
				    0xB0, 0x75, 0x10, 0x60, 0x4B, 0x88, 0x9D, 0xCF };
static const uint8_t linux_data[16] = { 0xAF, 0x3D, 0xC6, 0x0F, 0x83, 0x84, 0x72, 0x47,
					0x8E, 0x79, 0x3D, 0x69, 0xD8, 0x47, 0x7D, 0xE4 };

struct gpt_part {
	const uint8_t *type;
	uint8_t unique;
	uint64_t first, last;
};

/*
 * A protective MBR, a primary GPT at LBA 1 and a backup at the end, with `n` entries in a table of `slots`. LBAs count
 * blocks of `sector_size` bytes, as on the disk being tested.
 */
static void make_gpt(const struct gpt_part *parts, unsigned n, uint32_t slots)
{
	static uint8_t entries[1024 * 128];
	const uint64_t ss = sector_size, lbas = (uint64_t)DISK_SECTORS * 512 / ss;
	memset(entries, 0, sizeof(entries));
	for (unsigned i = 0; i < n; i++) {
		uint8_t *e = entries + i * 128;
		memcpy(e, parts[i].type, 16);
		memset(e + 16, parts[i].unique, 16);
		put64(e + 32, parts[i].first);
		put64(e + 40, parts[i].last);
	}
	uint32_t ecount = slots > 1024 ? 1024 : slots;
	uint32_t ecrc = crc(entries, (size_t)ecount * 128);
	uint64_t tlbas = ((uint64_t)ecount * 128 + ss - 1) / ss;
	mbr(0, 0, 0xEE, 1, (uint32_t)(lbas - 1));
	for (int backup = 0; backup < 2; backup++) {
		uint64_t my = backup ? lbas - 1 : 1, alt = backup ? 1 : lbas - 1;
		uint64_t table = backup ? lbas - 1 - tlbas : 2;
		memcpy(disk + table * ss, entries, (size_t)ecount * 128);
		uint8_t *h = disk + my * ss;
		memset(h, 0, ss);
		memcpy(h, "EFI PART", 8);
		put32(h + 8, 0x00010000);
		put32(h + 12, 92);
		put64(h + 24, my);
		put64(h + 32, alt);
		put64(h + 40, ss == 512 ? 34 : 6);
		put64(h + 48, lbas - (ss == 512 ? 34 : 6));
		put64(h + 72, table);
		put32(h + 80, slots);
		put32(h + 84, 128);
		put32(h + 88, ecrc);
		put32(h + 16, crc(h, 92));
	}
}

static void reset(const char *name)
{
	current = name;
	sector_size = 512;
	bad_sector = UINT64_MAX;
	memset(disk, 0, sizeof(disk));
}

static int run(struct fsvm_layout *l)
{
	int r = fsvm_read_layout(rd, NULL, DISK_SECTORS, sector_size, l);
	if (dump_dir && r == 0) {
		char path[512];
		snprintf(path, sizeof(path), "%s/%s.layout", dump_dir, current);
		FILE *f = fopen(path, "wb");
		if (f) {
			fwrite(l, 1, fsvm_layout_size(l), f);
			fclose(f);
		}
	}
	return r;
}

int main(int argc, char **argv)
{
	static struct fsvm_layout l;
	dump_dir = argc > 1 ? argv[1] : NULL;

	reset("mbr_two_fat32");
	mbr(0, 0x80, 0x0c, 2048, 4096);
	mbr(1, 0x00, 0x0b, 8192, 8192);
	mbr(2, 0x00, 0x83, 20000, 1000); /* Linux: not reported */
	make_fat32(2048, 0x6FFFFAB8, "PHOTOS");
	make_fat32(8192, 0x12345678, NULL);
	CHECK(run(&l) == 0);
	CHECK(l.h.table == FSVM_TABLE_MBR && l.h.count == 2);
	CHECK(l.e[0].index == 1 && l.e[0].start == 2048 && l.e[0].length == 4096);
	CHECK(l.e[0].fs_kind == FSVM_FS_VFAT && l.e[0].serial == 0x6FFFFAB8 && (l.e[0].flags & 1));
	CHECK(l.e[0].label_len == 6 && !memcmp(l.e[0].label, "PHOTOS", 6));
	CHECK(l.e[0].meta_bytes == 16 * 512);
	CHECK(l.e[1].index == 2 && l.e[1].label_len == 0);
	CHECK(fsvm_layout_find(&l, 2, 8192, 8192) != NULL);
	CHECK(fsvm_layout_find(&l, 2, 8192, 8191) == NULL);
	CHECK(fsvm_layout_find(&l, 3, 20000, 1000) == NULL);

	reset("gpt_public_and_adoptable");
	{
		struct gpt_part p[] = {
			{ basic, 1, 2048, 6143 },
			{ meta, 2, 6144, 8191 },
			{ expand, 3, 8192, DISK_SECTORS - 40 },
			{ linux_data, 4, 100, 200 }, /* not reported */
		};
		make_gpt(p, 4, 128);
		uint16_t name[] = { 'K', 'a', 'r', 't', 'e', 0xE4 };
		make_exfat(2048, 0xA1B2C3D4, name, 6);
	}
	CHECK(run(&l) == 0);
	CHECK(l.h.table == FSVM_TABLE_GPT && l.h.count == 3);
	CHECK(l.e[0].fs_kind == FSVM_FS_EXFAT && l.e[0].serial == 0xA1B2C3D4);
	CHECK(l.e[0].label_len == 7 && !memcmp(l.e[0].label, "Karte\xc3\xa4", 7));
	CHECK(l.e[0].meta_bytes == 125);
	CHECK(l.e[2].index == 3 && l.e[2].part_guid[0] == 3 && l.e[2].fs_kind == 0);

	reset("gpt_primary_broken_backup_used");
	{
		struct gpt_part p[] = { { basic, 1, 2048, 6143 } };
		make_gpt(p, 1, 128);
		disk[512 + 20] ^= 1; /* primary header checksum no longer matches */
	}
	CHECK(run(&l) == 0);
	CHECK(l.h.count == 1 && l.e[0].start == 2048);

	reset("gpt_hundreds_of_entries");
	{
		struct gpt_part p[] = { { basic, 1, 2048, 6143 } };
		make_gpt(p, 1, 1000);
	}
	CHECK(run(&l) == -E2BIG);

	reset("gpt_seventeen_partitions");
	{
		struct gpt_part p[17];
		for (unsigned i = 0; i < 17; i++)
			p[i] = (struct gpt_part){ basic, (uint8_t)(i + 1), 2048 + i * 100, 2048 + i * 100 + 99 };
		make_gpt(p, 17, 128);
	}
	CHECK(run(&l) == -E2BIG);

	reset("gpt_entry_past_the_disk");
	{
		struct gpt_part p[] = { { basic, 1, 2048, DISK_SECTORS + 100 } };
		make_gpt(p, 1, 128);
	}
	CHECK(run(&l) == -EINVAL);

	reset("gpt_entry_backwards");
	{
		struct gpt_part p[] = { { basic, 1, 6000, 2048 } };
		make_gpt(p, 1, 128);
	}
	CHECK(run(&l) == -EINVAL);

	/* Overlaps pass the guest and are refused by Android (layout.rs), see guest_layouts.rs. */
	reset("gpt_overlap");
	{
		struct gpt_part p[] = { { basic, 1, 2048, 6143 }, { expand, 2, 4096, 9000 } };
		make_gpt(p, 2, 128);
	}
	CHECK(run(&l) == 0 && l.h.count == 2);

	reset("mbr_overlap");
	mbr(0, 0, 0x0c, 2048, 4096);
	mbr(1, 0, 0x0c, 4096, 4096);
	CHECK(run(&l) == 0 && l.h.count == 2);

	reset("mbr_past_the_disk");
	mbr(0, 0, 0x0c, 2048, DISK_SECTORS);
	CHECK(run(&l) == -EINVAL);

	reset("mbr_bad_boot_indicator");
	mbr(0, 0x12, 0x0c, 2048, 4096);
	CHECK(run(&l) == 0 && l.h.count == 0);

	reset("whole_disk_exfat");
	{
		uint16_t name[] = { 0xD83D, 0xDE00, 'x' }; /* a surrogate pair, then x */
		make_exfat(0, 0x00000001, name, 3);
	}
	CHECK(run(&l) == 0);
	CHECK(l.h.table == FSVM_TABLE_NONE && l.h.count == 1 && l.e[0].index == 0);
	CHECK(l.e[0].length == DISK_SECTORS && l.e[0].label_len == 5);

	reset("whole_disk_fat32");
	make_fat32(0, 0xCAFEF00D, NULL);
	CHECK(run(&l) == 0 && l.h.table == FSVM_TABLE_NONE && l.h.count == 1 && l.e[0].fs_kind == FSVM_FS_VFAT);

	reset("exfat_bad_label");
	mbr(0, 0, 0x07, 2048, 4096);
	{
		uint16_t name[] = { 'a', 0xDC00, 'b' }; /* a lone low surrogate */
		make_exfat(2048, 7, name, 3);
	}
	CHECK(run(&l) == 0 && l.h.count == 1 && l.e[0].fs_kind == FSVM_FS_EXFAT && l.e[0].label_len == 0);

	reset("mbr_unknown_filesystem");
	mbr(0, 0, 0x07, 2048, 4096); /* NTFS or exFAT type, but nothing recognisable inside */
	CHECK(run(&l) == 0 && l.h.count == 1 && l.e[0].fs_kind == 0 && l.e[0].label_len == 0);
	CHECK(fsvm_layout_find(&l, 1, 2048, 4096) == NULL);

	/* A USB disk with 4096-byte logical blocks: its GPT counts 4096-byte LBAs, the layout 512-byte sectors. */
	reset("gpt_4k_blocks");
	sector_size = 4096;
	{
		struct gpt_part p[] = {
			{ basic, 1, 256, 1279 },     /* 4096-byte LBAs: sectors 2048 to 10239 */
			{ expand, 2, 1280, 3000 },
		};
		make_gpt(p, 2, 128);
		make_fat32(2048, 0x44445555, "BIG");
	}
	CHECK(run(&l) == 0);
	CHECK(l.h.table == FSVM_TABLE_GPT && l.h.count == 2);
	CHECK(l.e[0].start == 2048 && l.e[0].length == 8192 && l.e[0].fs_kind == FSVM_FS_VFAT);
	CHECK(l.e[0].label_len == 3 && !memcmp(l.e[0].label, "BIG", 3));
	CHECK(l.e[1].start == 10240 && l.e[1].length == (3000 - 1280 + 1) * 8);
	/* The same disk read as 512-byte blocks finds no GPT header at LBA 1: nothing Android can use, no guess. */
	sector_size = 512;
	CHECK(run(&l) != 0 || l.h.count == 0);

	/* Logical partitions: an extended partition at 4096 with two logical FAT32 partitions (5 and 6) and a Linux
	 * one between them that still takes a number, as Linux numbers them. */
	reset("mbr_logical");
	mbr(0, 0, 0x0c, 2048, 2048);
	mbr(1, 0, 0x0f, 4096, 12288);
	ebr(4096, 0x0b, 64, 2048, 2112, 2112);      /* p5 at 4160 */
	ebr(4096 + 2112, 0x83, 64, 1000, 4224, 3000); /* p6, Linux, not reported */
	ebr(4096 + 4224, 0x0c, 64, 2048, 0, 0);     /* p7 at 8384 */
	make_fat32(2048, 1, NULL);
	make_fat32(4160, 0x55556666, "LOGICAL");
	make_fat32(8384, 7, NULL);
	CHECK(run(&l) == 0);
	CHECK(l.h.table == FSVM_TABLE_MBR && l.h.count == 3);
	CHECK(l.e[1].index == 5 && l.e[1].start == 4160 && l.e[1].length == 2048 && l.e[1].fs_kind == FSVM_FS_VFAT);
	CHECK(l.e[1].label_len == 7 && !memcmp(l.e[1].label, "LOGICAL", 7));
	CHECK(l.e[2].index == 7 && l.e[2].start == 8384);

	reset("mbr_logical_loop");
	mbr(0, 0, 0x05, 4096, 12288);
	ebr(4096, 0x0b, 64, 512, 2048, 2048);
	ebr(4096 + 2048, 0x0b, 64, 512, 0, 2048); /* links back to the first EBR */
	make_fat32(4160, 1, NULL);
	make_fat32(6208, 2, NULL);
	CHECK(run(&l) == -EINVAL);

	reset("mbr_logical_outside");
	mbr(0, 0, 0x05, 4096, 4096);
	ebr(4096, 0x0b, 64, 8192, 0, 0); /* past the end of the extended partition */
	CHECK(run(&l) == -EINVAL);

	reset("mbr_logical_long_chain");
	mbr(0, 0, 0x05, 2048, 20000);
	for (uint32_t i = 0; i < 40; i++)
		ebr(2048 + i * 100, 0x83, 10, 50, (i + 1) * 100, 100);
	CHECK(run(&l) == -E2BIG);

	reset("mbr_two_extended");
	mbr(0, 0, 0x05, 2048, 4096);
	mbr(1, 0, 0x0f, 8192, 4096);
	CHECK(run(&l) == -EINVAL);

	reset("mbr_logical_in_slot_three");
	mbr(0, 0, 0x05, 4096, 8192);
	ebr(4096, 0x0b, 64, 512, 0, 0);
	put32(disk + 4096 * 512 + 446 + 32 + 12, 10); /* a third entry with a size */
	CHECK(run(&l) == -EINVAL);

	/* A read error on a boot sector is not "no filesystem": the whole layout fails, so no format offer. */
	reset("read_error_boot_sector");
	mbr(0, 0, 0x0c, 2048, 4096);
	make_fat32(2048, 1, NULL);
	bad_sector = 2048;
	CHECK(run(&l) == -EIO);
	reset("read_error_logical_ebr");
	mbr(0, 0, 0x05, 4096, 8192);
	ebr(4096, 0x0b, 64, 512, 0, 0);
	bad_sector = 4096;
	CHECK(run(&l) == -EIO);
	reset("read_error_gpt_partition");
	{
		struct gpt_part p[] = { { basic, 1, 2048, 6143 } };
		make_gpt(p, 1, 128);
		make_fat32(2048, 1, NULL);
	}
	bad_sector = 2048;
	CHECK(run(&l) == -EIO);
	/* A label that cannot be read is only left out. */
	reset("read_error_label");
	mbr(0, 0, 0x0c, 2048, 4096);
	make_fat32(2048, 1, "GONE");
	bad_sector = 2048 + 32 + 2 * 16;
	CHECK(run(&l) == 0 && l.h.count == 1 && l.e[0].fs_kind == FSVM_FS_VFAT && l.e[0].label_len == 0);

	/* A GPT without the protective MBR (sector 0 empty), as some tools and cameras write it: read as a GPT. */
	reset("gpt_no_protective_mbr");
	{
		struct gpt_part p[] = { { basic, 1, 2048, 6143 } };
		make_gpt(p, 1, 128);
		memset(disk, 0, 512);
		make_fat32(2048, 9, NULL);
	}
	CHECK(run(&l) == 0 && l.h.table == FSVM_TABLE_GPT && l.h.count == 1 && l.e[0].fs_kind == FSVM_FS_VFAT);
	/* The same with both headers damaged: the layout fails (unopenable), it does not look blank. */
	reset("gpt_no_protective_mbr_damaged");
	{
		struct gpt_part p[] = { { basic, 1, 2048, 6143 } };
		make_gpt(p, 1, 128);
		memset(disk, 0, 512);
		disk[512 + 20] ^= 1;
		disk[(DISK_SECTORS - 1) * 512 + 20] ^= 1;
	}
	CHECK(run(&l) == -EINVAL);

	reset("blank");
	CHECK(run(&l) == 0 && l.h.count == 0);

	if (failures) {
		fprintf(stderr, "%d checks failed\n", failures);
		return 1;
	}
	printf("table_test: all checks passed\n");
	return 0;
}
