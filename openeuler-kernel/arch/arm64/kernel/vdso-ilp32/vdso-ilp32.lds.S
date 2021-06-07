/* SPDX-License-Identifier: GPL-2.0 */

/*
 * GNU linker script for the VDSO library.
 *
 * Copyright (C) 2012 ARM Limited
 * Author: Will Deacon <will.deacon@arm.com>
 * Heavily based on the vDSO linker scripts for other archs.
 */

#include <linux/const.h>
#include <asm/page.h>
#include <asm/vdso.h>

SECTIONS
{
	PROVIDE(_vdso_data = . - PAGE_SIZE);
	PROVIDE(_vdso_data = . - __VVAR_PAGES * PAGE_SIZE);
#ifdef CONFIG_TIME_NS
	PROVIDE(_timens_data = _vdso_data + PAGE_SIZE);
#endif
	. = VDSO_LBASE + SIZEOF_HEADERS;

	.hash		: { *(.hash) }			:text
	.gnu.hash	: { *(.gnu.hash) }
	.dynsym		: { *(.dynsym) }
	.dynstr		: { *(.dynstr) }
	.gnu.version	: { *(.gnu.version) }
	.gnu.version_d	: { *(.gnu.version_d) }
	.gnu.version_r	: { *(.gnu.version_r) }

	.note		: { *(.note.*) }		:text	:note

	. = ALIGN(16);

	.text		: { *(.text*) }			:text	=0xd503201f
	PROVIDE (__etext = .);
	PROVIDE (_etext = .);
	PROVIDE (etext = .);

	.eh_frame_hdr	: { *(.eh_frame_hdr) }		:text	:eh_frame_hdr
	.eh_frame	: { KEEP (*(.eh_frame)) }	:text

	.dynamic	: { *(.dynamic) }		:text	:dynamic

	.rodata		: { *(.rodata*) }		:text

	_end = .;
	PROVIDE(end = .);

	/DISCARD/	: {
		*(.note.GNU-stack)
		*(.data .data.* .gnu.linkonce.d.* .sdata*)
		*(.bss .sbss .dynbss .dynsbss)
	}
}

/*
 * We must supply the ELF program headers explicitly to get just one
 * PT_LOAD segment, and set the flags explicitly to make segments read-only.
 */
PHDRS
{
	text		PT_LOAD		FLAGS(5) FILEHDR PHDRS; /* PF_R|PF_X */
	dynamic		PT_DYNAMIC	FLAGS(4);		/* PF_R */
	note		PT_NOTE		FLAGS(4);		/* PF_R */
	eh_frame_hdr	PT_GNU_EH_FRAME;
}

/*
 * This controls what symbols we export from the DSO.
 */
VERSION
{
	LINUX_4.12 {
	global:
		__kernel_rt_sigreturn;
		__kernel_gettimeofday;
		__kernel_clock_gettime;
		__kernel_clock_getres;
	local: *;
	};
}

/*
 * Make the sigreturn code visible to the kernel.
 */
VDSO_sigtramp_ilp32		= __kernel_rt_sigreturn;
