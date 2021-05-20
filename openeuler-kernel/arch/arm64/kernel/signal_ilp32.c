// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (C) 1995-2009 Russell King
 * Copyright (C) 2012 ARM Ltd.
 * Copyright (C) 2018 Cavium Networks.
 * Yury Norov <ynorov@caviumnetworks.com>
 */

#include <linux/compat.h>
#include <linux/signal.h>
#include <linux/syscalls.h>

#include <asm/fpsimd.h>
#include <asm/unistd.h>
#include <asm/ucontext.h>
#include <asm/vdso.h>

#include <asm/signal_ilp32.h>
#include <asm/signal32_common.h>

#define get_sigset(s, m) get_sigset_t(s, m)
#define put_sigset(s, m) put_sigset_t(m, s)

#define restore_altstack(stack) compat_restore_altstack(stack)
#define __save_altstack(stack, sp) __compat_save_altstack(stack, sp)
#define copy_siginfo_to_user(frame_info, ksig_info) \
		copy_siginfo_to_user32(frame_info, ksig_info)

#define setup_return(regs, ka, user_layout, usig)			\
{									\
	__setup_return(regs, ka, user_layout, usig);			\
	regs->regs[30] =						\
		(unsigned long)VDSO_SYMBOL(current->mm->context.vdso,	\
						    sigtramp_ilp32);	\
}

struct ilp32_ucontext {
	u32		uc_flags;
	u32		uc_link;
	compat_stack_t	uc_stack;
	compat_sigset_t	uc_sigmask;
	/* glibc uses a 1024-bit sigset_t */
	__u8		__unused[1024 / 8 - sizeof(compat_sigset_t)];
	/* last for future expansion */
	struct sigcontext uc_mcontext;
};

struct rt_sigframe {
	struct compat_siginfo info;
	struct ilp32_ucontext uc;
};

#include <asm/signal_common.h>

COMPAT_SYSCALL_DEFINE0(ilp32_rt_sigreturn)
{
	struct pt_regs *regs = current_pt_regs();

	return __sys_rt_sigreturn(regs);
}

int ilp32_setup_rt_frame(int usig, struct ksignal *ksig,
			  sigset_t *set, struct pt_regs *regs)
{
	return __setup_rt_frame(usig, ksig, set, regs);
}
