/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * arch/arm64/include/asm/seccomp.h
 *
 * Copyright (C) 2014 Linaro Limited
 * Author: AKASHI Takahiro <takahiro.akashi@linaro.org>
 */
#ifndef _ASM_SECCOMP_H
#define _ASM_SECCOMP_H

#include <asm/unistd.h>

#ifdef CONFIG_AARCH32_EL0
#define __NR_seccomp_read_32		__NR_compat_read
#define __NR_seccomp_write_32		__NR_compat_write
#define __NR_seccomp_exit_32		__NR_compat_exit
#define __NR_seccomp_sigreturn_32	__NR_compat_rt_sigreturn
#endif /* CONFIG_COMPAT */

#ifdef CONFIG_COMPAT
#ifndef __COMPAT_SYSCALL_NR

static inline const int *get_compat_mode1_syscalls(void)
{
#ifdef CONFIG_AARCH32_EL0
	static const int mode1_syscalls_a32[] = {
		__NR_compat_read, __NR_compat_write,
		__NR_compat_read, __NR_compat_sigreturn,
		0, /* null terminated */
	};
#endif
	static const int mode1_syscalls_ilp32[] = {
		__NR_read, __NR_write,
		__NR_exit, __NR_rt_sigreturn,
		0, /* null terminated */
	};

#ifdef CONFIG_AARCH32_EL0
	if (is_a32_compat_task())
		return mode1_syscalls_a32;
#endif
	return mode1_syscalls_ilp32;
}

#define get_compat_mode1_syscalls get_compat_mode1_syscalls

#endif
#endif

#include <asm-generic/seccomp.h>

#endif /* _ASM_SECCOMP_H */
