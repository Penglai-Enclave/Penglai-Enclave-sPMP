// SPDX-License-Identifier: GPL-2.0

/*
 * AArch64- ILP32 specific system calls implementation
 * Copyright (C) 2018 Marvell.
 */

#define __SYSCALL_COMPAT

#include <linux/compat.h>
#include <linux/compiler.h>
#include <linux/syscalls.h>

#include <asm/syscall.h>

/*
 * AARCH32 requires 4-page alignment for shared memory,
 * but AARCH64 - only 1 page. This is the only difference
 * between compat and native sys_shmat(). So ILP32 just pick
 * AARCH64 version.
 */
#define __arm64_compat_sys_shmat		__arm64_sys_shmat

/*
 * ILP32 needs special handling for some ptrace requests.
 */
#define __arm64_sys_ptrace			__arm64_compat_sys_ptrace

/*
 * Using AARCH32 interface for syscalls that take 64-bit
 * parameters in registers.
 */
#define __arm64_compat_sys_fadvise64_64		__arm64_compat_sys_aarch32_fadvise64_64
#define __arm64_compat_sys_fallocate		__arm64_compat_sys_aarch32_fallocate
#define __arm64_compat_sys_ftruncate64		__arm64_compat_sys_aarch32_ftruncate64
#define __arm64_compat_sys_pread64		__arm64_compat_sys_aarch32_pread64
#define __arm64_compat_sys_pwrite64		__arm64_compat_sys_aarch32_pwrite64
#define __arm64_compat_sys_readahead		__arm64_compat_sys_aarch32_readahead
#define __arm64_compat_sys_sync_file_range2	__arm64_compat_sys_aarch32_sync_file_range2
#define __arm64_compat_sys_truncate64		__arm64_compat_sys_aarch32_truncate64
#define __arm64_sys_mmap2			__arm64_compat_sys_aarch32_mmap2

/*
 * Using AARCH32 interface for syscalls that take the size of
 * struct statfs as an argument, as it's calculated differently
 * in kernel and user spaces.
 */
#define __arm64_compat_sys_fstatfs64		__arm64_compat_sys_aarch32_fstatfs64
#define __arm64_compat_sys_statfs64		__arm64_compat_sys_aarch32_statfs64

/*
 * Using old interface for IPC syscalls that should handle IPC_64 flag.
 */
#define __arm64_compat_sys_semctl		__arm64_compat_sys_old_semctl
#define __arm64_compat_sys_msgctl		__arm64_compat_sys_old_msgctl
#define __arm64_compat_sys_shmctl		__arm64_compat_sys_old_shmctl

/*
 * Using custom wrapper for rt_sigreturn() to handle custom
 * struct rt_sigframe.
 */
#define __arm64_compat_sys_rt_sigreturn		__arm64_compat_sys_ilp32_rt_sigreturn

/*
 * Wrappers to pass the pt_regs argument.
 */
#define sys_personality		sys_arm64_personality

asmlinkage long sys_ni_syscall(const struct pt_regs *);
#define __arm64_sys_ni_syscall	sys_ni_syscall

#undef __SYSCALL
#define __SYSCALL(nr, sym)	asmlinkage long __arm64_##sym(const struct pt_regs *);
#include <asm/unistd.h>

#undef __SYSCALL
#define __SYSCALL(nr, sym)	[nr] = (syscall_fn_t)__arm64_##sym,

const syscall_fn_t ilp32_sys_call_table[__NR_syscalls] = {
	[0 ... __NR_syscalls - 1] = __arm64_sys_ni_syscall,
#include <asm/unistd.h>
};
