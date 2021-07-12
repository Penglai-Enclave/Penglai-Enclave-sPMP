/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2012 ARM Ltd.
 */
#ifndef __ASM_SIGNAL32_H
#define __ASM_SIGNAL32_H

#ifdef CONFIG_AARCH32_EL0
#include <linux/compat.h>

struct a32_sigcontext {
	/* We always set these two fields to 0 */
	compat_ulong_t			trap_no;
	compat_ulong_t			error_code;

	compat_ulong_t			oldmask;
	compat_ulong_t			arm_r0;
	compat_ulong_t			arm_r1;
	compat_ulong_t			arm_r2;
	compat_ulong_t			arm_r3;
	compat_ulong_t			arm_r4;
	compat_ulong_t			arm_r5;
	compat_ulong_t			arm_r6;
	compat_ulong_t			arm_r7;
	compat_ulong_t			arm_r8;
	compat_ulong_t			arm_r9;
	compat_ulong_t			arm_r10;
	compat_ulong_t			arm_fp;
	compat_ulong_t			arm_ip;
	compat_ulong_t			arm_sp;
	compat_ulong_t			arm_lr;
	compat_ulong_t			arm_pc;
	compat_ulong_t			arm_cpsr;
	compat_ulong_t			fault_address;
};

struct a32_ucontext {
	compat_ulong_t			uc_flags;
	compat_uptr_t			uc_link;
	compat_stack_t			uc_stack;
	struct a32_sigcontext	uc_mcontext;
	compat_sigset_t			uc_sigmask;
	int 				__unused[32 - (sizeof(compat_sigset_t) / sizeof(int))];
	compat_ulong_t			uc_regspace[128] __attribute__((__aligned__(8)));
};

struct a32_sigframe {
	struct a32_ucontext	uc;
	compat_ulong_t		retcode[2];
};

struct a32_rt_sigframe {
	struct compat_siginfo info;
	struct a32_sigframe sig;
};

int a32_setup_frame(int usig, struct ksignal *ksig, sigset_t *set,
		       struct pt_regs *regs);

int a32_setup_rt_frame(int usig, struct ksignal *ksig, sigset_t *set,
			  struct pt_regs *regs);

void a32_setup_restart_syscall(struct pt_regs *regs);
#else

static inline int a32_setup_frame(int usid, struct ksignal *ksig,
				     sigset_t *set, struct pt_regs *regs)
{
	return -ENOSYS;
}

static inline int a32_setup_rt_frame(int usig, struct ksignal *ksig, sigset_t *set,
					struct pt_regs *regs)
{
	return -ENOSYS;
}

static inline void a32_setup_restart_syscall(struct pt_regs *regs)
{
}
#endif /* CONFIG_AARCH32_EL0 */
#endif /* __ASM_SIGNAL32_H */
