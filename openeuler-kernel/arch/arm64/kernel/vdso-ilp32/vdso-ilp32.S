/* SPDX-License-Identifier: GPL-2.0 */

/*
 * Copyright (C) 2012 ARM Limited
 * Author: Will Deacon <will.deacon@arm.com>
 */

#include <linux/init.h>
#include <linux/linkage.h>
#include <linux/const.h>
#include <asm/page.h>

	__PAGE_ALIGNED_DATA

	.globl vdso_ilp32_start, vdso_ilp32_end
	.balign PAGE_SIZE
vdso_ilp32_start:
	.incbin "arch/arm64/kernel/vdso-ilp32/vdso-ilp32.so"
	.balign PAGE_SIZE
vdso_ilp32_end:

	.previous
