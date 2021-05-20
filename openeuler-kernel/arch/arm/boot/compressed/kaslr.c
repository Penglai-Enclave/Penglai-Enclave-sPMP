/*
 * Copyright (C) 2017 Linaro Ltd;  <ard.biesheuvel@linaro.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 */

#include <linux/libfdt_env.h>
#include <libfdt.h>
#include <linux/types.h>
#include <generated/compile.h>
#include <generated/utsrelease.h>
#include <linux/pgtable.h>

#include CONFIG_UNCOMPRESS_INCLUDE

struct regions {
	u32 pa_start;
	u32 pa_end;
	u32 image_size;
	u32 zimage_start;
	u32 zimage_size;
	u32 dtb_start;
	u32 dtb_size;
	u32 initrd_start;
	u32 initrd_size;
	int reserved_mem;
	int reserved_mem_addr_cells;
	int reserved_mem_size_cells;
};

extern u32 __crc16(u32 crc, u32 const input[], int byte_count);

static u32 __memparse(const char *val, const char **retptr)
{
	int base = 10;
	u32 ret = 0;

	if (*val == '0') {
		val++;
		if (*val == 'x' || *val == 'X') {
			val++;
			base = 16;
		} else {
			base = 8;
		}
	}

	while (*val != ',' && *val != ' ' && *val != '\0') {
		char c = *val++;

		switch (c) {
		case '0' ... '9':
			ret = ret * base + (c - '0');
			continue;
		case 'a' ... 'f':
			ret = ret * base + (c - 'a' + 10);
			continue;
		case 'A' ... 'F':
			ret = ret * base + (c - 'A' + 10);
			continue;
		case 'g':
		case 'G':
			ret <<= 10;
			/* fall through */
		case 'm':
		case 'M':
			ret <<= 10;
			/* fall through */
		case 'k':
		case 'K':
			ret <<= 10;
			break;
		default:
			if (retptr)
				*retptr = NULL;
			return 0;
		}
	}
	if (retptr)
		*retptr = val;
	return ret;
}

static bool regions_intersect(u32 s1, u32 e1, u32 s2, u32 e2)
{
	return e1 >= s2 && e2 >= s1;
}

static bool intersects_reserved_region(const void *fdt, u32 start,
				       u32 end, struct regions *regions)
{
	int subnode, len, i;
	u64 base, size;

	/* check for overlap with /memreserve/ entries */
	for (i = 0; i < fdt_num_mem_rsv(fdt); i++) {
		if (fdt_get_mem_rsv(fdt, i, &base, &size) < 0)
			continue;
		if (regions_intersect(start, end, base, base + size))
			return true;
	}

	if (regions->reserved_mem < 0)
		return false;

	/* check for overlap with static reservations in /reserved-memory */
	for (subnode = fdt_first_subnode(fdt, regions->reserved_mem);
	     subnode >= 0;
	     subnode = fdt_next_subnode(fdt, subnode)) {
		const fdt32_t *reg;

		len = 0;
		reg = fdt_getprop(fdt, subnode, "reg", &len);
		while (len >= (regions->reserved_mem_addr_cells +
			       regions->reserved_mem_size_cells)) {

			base = fdt32_to_cpu(reg[0]);
			if (regions->reserved_mem_addr_cells == 2)
				base = (base << 32) | fdt32_to_cpu(reg[1]);

			reg += regions->reserved_mem_addr_cells;
			len -= 4 * regions->reserved_mem_addr_cells;

			size = fdt32_to_cpu(reg[0]);
			if (regions->reserved_mem_size_cells == 2)
				size = (size << 32) | fdt32_to_cpu(reg[1]);

			reg += regions->reserved_mem_size_cells;
			len -= 4 * regions->reserved_mem_size_cells;

			if (base >= regions->pa_end)
				continue;

			if (regions_intersect(start, end, base,
					      min(base + size, (u64)U32_MAX)))
				return true;
		}
	}
	return false;
}

static bool intersects_occupied_region(const void *fdt, u32 start,
				       u32 end, struct regions *regions)
{
	if (regions_intersect(start, end, regions->zimage_start,
			      regions->zimage_start + regions->zimage_size))
		return true;

	if (regions_intersect(start, end, regions->initrd_start,
			      regions->initrd_start + regions->initrd_size))
		return true;

	if (regions_intersect(start, end, regions->dtb_start,
			      regions->dtb_start + regions->dtb_size))
		return true;

	return intersects_reserved_region(fdt, start, end, regions);
}

static u32 count_suitable_regions(const void *fdt, struct regions *regions,
				  u32 *bitmap)
{
	u32 pa, i = 0, ret = 0;

	for (pa = regions->pa_start; pa < regions->pa_end; pa += SZ_2M, i++) {
		if (!intersects_occupied_region(fdt, pa,
						pa + regions->image_size,
						regions)) {
			ret++;
		} else {
			/* set 'occupied' bit */
			bitmap[i >> 5] |= BIT(i & 0x1f);
		}
	}
	return ret;
}

static u32 get_region_number(u32 num, u32 *bitmap)
{
	u32 i;

	for (i = 0; num > 0; i++)
		if (!(bitmap[i >> 5] & BIT(i & 0x1f)))
			num--;
	return i;
}

static void get_cell_sizes(const void *fdt, int node, int *addr_cells,
			   int *size_cells)
{
	const int *prop;
	int len;

	/*
	 * Retrieve the #address-cells and #size-cells properties
	 * from the 'node', or use the default if not provided.
	 */
	*addr_cells = *size_cells = 1;

	prop = fdt_getprop(fdt, node, "#address-cells", &len);
	if (len == 4)
		*addr_cells = fdt32_to_cpu(*prop);
	prop = fdt_getprop(fdt, node, "#size-cells", &len);
	if (len == 4)
		*size_cells = fdt32_to_cpu(*prop);
}

/*
 * Original method only consider the first memory node in dtb,
 * but there may be more than one memory nodes, we only consider
 * the memory node zImage exists.
 */
static u32 get_memory_end(const void *fdt, u32 zimage_start)
{
	int mem_node, address_cells, size_cells, len;
	const fdt32_t *reg;

	/* Look for a node called "memory" at the lowest level of the tree */
	mem_node = fdt_path_offset(fdt, "/memory");
	if (mem_node <= 0)
		return 0;

	get_cell_sizes(fdt, 0, &address_cells, &size_cells);

	while(mem_node >= 0) {
		/*
		 * Now find the 'reg' property of the /memory node, and iterate over
		 * the base/size pairs.
		 */
		len = 0;
		reg = fdt_getprop(fdt, mem_node, "reg", &len);
		while (len >= 4 * (address_cells + size_cells)) {
			u64 base, size;
			base = fdt32_to_cpu(reg[0]);
			if (address_cells == 2)
				base = (base << 32) | fdt32_to_cpu(reg[1]);

			reg += address_cells;
			len -= 4 * address_cells;

			size = fdt32_to_cpu(reg[0]);
			if (size_cells == 2)
				size = (size << 32) | fdt32_to_cpu(reg[1]);

			reg += size_cells;
			len -= 4 * size_cells;

			/* Get the base and size of the zimage memory node */
			if (zimage_start >= base && zimage_start < base + size)
				return base + size;
		}
		/* If current memory node is not the one zImage exists, then traverse next memory node. */
		mem_node = fdt_node_offset_by_prop_value(fdt, mem_node, "device_type", "memory", sizeof("memory"));
	}

	return 0;
}

static char *__strstr(const char *s1, const char *s2, int l2)
{
	int l1;

	l1 = strlen(s1);
	while (l1 >= l2) {
		l1--;
		if (!memcmp(s1, s2, l2))
			return (char *)s1;
		s1++;
	}
	return NULL;
}

static const char *get_cmdline_param(const char *cmdline, const char *param,
				     int param_size)
{
	static const char default_cmdline[] = CONFIG_CMDLINE;
	const char *p;

	if (!IS_ENABLED(CONFIG_CMDLINE_FORCE) && cmdline != NULL) {
		p = __strstr(cmdline, param, param_size);
		if (p == cmdline ||
		    (p > cmdline && *(p - 1) == ' '))
			return p;
	}

	if (IS_ENABLED(CONFIG_CMDLINE_FORCE)  ||
	    IS_ENABLED(CONFIG_CMDLINE_EXTEND)) {
		p = __strstr(default_cmdline, param, param_size);
		if (p == default_cmdline ||
		    (p > default_cmdline && *(p - 1) == ' '))
			return p;
	}
	return NULL;
}

static void __puthex32(const char *name, u32 val)
{
	int i;

	while (*name)
		putc(*name++);
	putc(':');
	for (i = 28; i >= 0; i -= 4) {
		char c = (val >> i) & 0xf;

		if (c < 10)
			putc(c + '0');
		else
			putc(c + 'a' - 10);
	}
	putc('\r');
	putc('\n');
}
#define puthex32(val)	__puthex32(#val, (val))

u32 kaslr_early_init(u32 *kaslr_offset, u32 image_base, u32 image_size,
		     u32 seed, u32 zimage_start, const void *fdt,
		     u32 zimage_end)
{
	static const char __aligned(4) build_id[] = UTS_VERSION UTS_RELEASE;
	u32 bitmap[(VMALLOC_END - PAGE_OFFSET) / SZ_2M / 32] = {};
	struct regions regions;
	const char *command_line;
	const char *p;
	int chosen, len;
	u32 lowmem_top, count, num, mem_fdt;

	if (IS_ENABLED(CONFIG_EFI_STUB)) {
		extern u32 __efi_kaslr_offset;

		if (__efi_kaslr_offset == U32_MAX)
			return 0;
	}

	if (fdt_check_header(fdt))
		return 0;

	chosen = fdt_path_offset(fdt, "/chosen");
	if (chosen < 0)
		return 0;

	command_line = fdt_getprop(fdt, chosen, "bootargs", &len);

	/* check the command line for the presence of 'nokaslr' */
	p = get_cmdline_param(command_line, "nokaslr", sizeof("nokaslr") - 1);
	if (p != NULL)
		return 0;

	/* check the command line for the presence of 'vmalloc=' */
	p = get_cmdline_param(command_line, "vmalloc=", sizeof("vmalloc=") - 1);
	if (p != NULL)
		lowmem_top = VMALLOC_END - __memparse(p + 8, NULL) -
			     VMALLOC_OFFSET;
	else
		lowmem_top = VMALLOC_DEFAULT_BASE;

	regions.image_size = image_base % SZ_128M + round_up(image_size, SZ_2M);
	regions.pa_start = round_down(image_base, SZ_128M);
	regions.pa_end = lowmem_top - PAGE_OFFSET + regions.pa_start;
	regions.zimage_start = zimage_start;
	regions.zimage_size = zimage_end - zimage_start;
	regions.dtb_start = (u32)fdt;
	regions.dtb_size = fdt_totalsize(fdt);

	/*
	 * Stir up the seed a bit by taking the CRC of the DTB:
	 * hopefully there's a /chosen/kaslr-seed in there.
	 */
	seed = __crc16(seed, fdt, regions.dtb_size);

	/* stir a bit more using data that changes between builds */
	seed = __crc16(seed, (u32 *)build_id, sizeof(build_id));

	/* check for initrd on the command line */
	regions.initrd_start = regions.initrd_size = 0;
	p = get_cmdline_param(command_line, "initrd=", sizeof("initrd=") - 1);
	if (p != NULL) {
		regions.initrd_start = __memparse(p + 7, &p);
		if (*p++ == ',')
			regions.initrd_size = __memparse(p, NULL);
		if (regions.initrd_size == 0)
			regions.initrd_start = 0;
	}

	/* ... or in /chosen */
	if (regions.initrd_size == 0) {
		const fdt32_t *prop;
		u64 start = 0, end = 0;

		prop = fdt_getprop(fdt, chosen, "linux,initrd-start", &len);
		if (prop) {
			start = fdt32_to_cpu(prop[0]);
			if (len == 8)
				start = (start << 32) | fdt32_to_cpu(prop[1]);
		}

		prop = fdt_getprop(fdt, chosen, "linux,initrd-end", &len);
		if (prop) {
			end = fdt32_to_cpu(prop[0]);
			if (len == 8)
				end = (end << 32) | fdt32_to_cpu(prop[1]);
		}
		if (start != 0 && end != 0 && start < U32_MAX) {
			regions.initrd_start = start;
			regions.initrd_size = max_t(u64, end, U32_MAX) - start;
		}
	}

	/*
	 * check the memory nodes for the size of the lowmem region, traverse
	 * all memory nodes to find the node in which zImage exists, we
	 * randomize kernel only in the one zImage exists.
	 */
	mem_fdt = get_memory_end(fdt, zimage_start);
	if (mem_fdt)
		regions.pa_end = min(regions.pa_end, mem_fdt) - regions.image_size;
	else
		regions.pa_end = regions.pa_end - regions.image_size;

	puthex32(regions.image_size);
	puthex32(regions.pa_start);
	puthex32(regions.pa_end);
	puthex32(regions.zimage_start);
	puthex32(regions.zimage_size);
	puthex32(regions.dtb_start);
	puthex32(regions.dtb_size);
	puthex32(regions.initrd_start);
	puthex32(regions.initrd_size);

	/* check for a reserved-memory node and record its cell sizes */
	regions.reserved_mem = fdt_path_offset(fdt, "/reserved-memory");
	if (regions.reserved_mem >= 0)
		get_cell_sizes(fdt, regions.reserved_mem,
			       &regions.reserved_mem_addr_cells,
			       &regions.reserved_mem_size_cells);

	/*
	 * Iterate over the physical memory range covered by the lowmem region
	 * in 2 MB increments, and count each offset at which we don't overlap
	 * with any of the reserved regions for the zImage itself, the DTB,
	 * the initrd and any regions described as reserved in the device tree.
	 * If the region does overlap, set the respective bit in the bitmap[].
	 * Using this random value, we go over the bitmap and count zero bits
	 * until we counted enough iterations, and return the offset we ended
	 * up at.
	 */
	count = count_suitable_regions(fdt, &regions, bitmap);
	puthex32(count);

	num = ((u16)seed * count) >> 16;
	puthex32(num);

	*kaslr_offset = get_region_number(num, bitmap) * SZ_2M;
	puthex32(*kaslr_offset);

	return *kaslr_offset;
}
