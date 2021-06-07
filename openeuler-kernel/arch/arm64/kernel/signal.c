// SPDX-License-Identifier: GPL-2.0-only
/*
 * Based on arch/arm/kernel/signal.c
 *
 * Copyright (C) 1995-2009 Russell King
 * Copyright (C) 2012 ARM Ltd.
 */

#include <linux/cache.h>
#include <linux/compat.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/signal.h>
#include <linux/personality.h>
#include <linux/freezer.h>
#include <linux/stddef.h>
#include <linux/uaccess.h>
#include <linux/sizes.h>
#include <linux/string.h>
#include <linux/tracehook.h>
#include <linux/ratelimit.h>
#include <linux/syscalls.h>

#include <asm/daifflags.h>
#include <asm/debug-monitors.h>
#include <asm/elf.h>
#include <asm/cacheflush.h>
#include <asm/ucontext.h>
#include <asm/unistd.h>
#include <asm/fpsimd.h>
#include <asm/ptrace.h>
#include <asm/signal32.h>
#include <asm/traps.h>
#include <asm/vdso.h>
#include <asm/signal_ilp32.h>

#define get_sigset(s, m) __copy_from_user(s, m, sizeof(*s))
#define put_sigset(s, m) __copy_to_user(m, s, sizeof(*s))

/*
 * Do a signal return; undo the signal stack. These are aligned to 128-bit.
 */
struct rt_sigframe {
	struct siginfo info;
	struct ucontext uc;
};
struct rt_sigframe_user_layout;

static void setup_return(struct pt_regs *regs, struct k_sigaction *ka,
			 struct rt_sigframe_user_layout *user, int usig);

#include <asm/signal_common.h>

static int __sigframe_alloc(struct rt_sigframe_user_layout *user,
			    unsigned long *offset, size_t size, bool extend)
{
	size_t padded_size = round_up(size, 16);

	if (padded_size > user->limit - user->size &&
	    !user->extra_offset &&
	    extend) {
		int ret;

		user->limit += EXTRA_CONTEXT_SIZE;
		ret = __sigframe_alloc(user, &user->extra_offset,
				       sizeof(struct extra_context), false);
		if (ret) {
			user->limit -= EXTRA_CONTEXT_SIZE;
			return ret;
		}

		/* Reserve space for the __reserved[] terminator */
		user->size += TERMINATOR_SIZE;

		/*
		 * Allow expansion up to SIGFRAME_MAXSZ, ensuring space for
		 * the terminator:
		 */
		user->limit = SIGFRAME_MAXSZ - TERMINATOR_SIZE;
	}

	/* Still not enough space?  Bad luck! */
	if (padded_size > user->limit - user->size)
		return -ENOMEM;

	*offset = user->size;
	user->size += padded_size;

	return 0;
}

/*
 * Allocate space for an optional record of <size> bytes in the user
 * signal frame.  The offset from the signal frame base address to the
 * allocated block is assigned to *offset.
 */
int sigframe_alloc(struct rt_sigframe_user_layout *user,
			  unsigned long *offset, size_t size)
{
	return __sigframe_alloc(user, offset, size, true);
}

/* Allocate the null terminator record and prevent further allocations */
int sigframe_alloc_end(struct rt_sigframe_user_layout *user)
{
	int ret;

	/* Un-reserve the space reserved for the terminator: */
	user->limit += TERMINATOR_SIZE;

	ret = sigframe_alloc(user, &user->end_offset,
			     sizeof(struct _aarch64_ctx));
	if (ret)
		return ret;

	/* Prevent further allocation: */
	user->limit = user->size;
	return 0;
}

void __user *apply_user_offset(
	struct rt_sigframe_user_layout const *user, unsigned long offset)
{
	char __user *base = (char __user *)user->sigframe;

	return base + offset;
}

int preserve_fpsimd_context(struct fpsimd_context __user *ctx)
{
	struct user_fpsimd_state const *fpsimd =
		&current->thread.uw.fpsimd_state;
	int err;

	/* copy the FP and status/control registers */
	err = __copy_to_user(ctx->vregs, fpsimd->vregs, sizeof(fpsimd->vregs));
	__put_user_error(fpsimd->fpsr, &ctx->fpsr, err);
	__put_user_error(fpsimd->fpcr, &ctx->fpcr, err);

	/* copy the magic/size information */
	__put_user_error(FPSIMD_MAGIC, &ctx->head.magic, err);
	__put_user_error(sizeof(struct fpsimd_context), &ctx->head.size, err);

	return err ? -EFAULT : 0;
}

int restore_fpsimd_context(struct fpsimd_context __user *ctx)
{
	struct user_fpsimd_state fpsimd;
	__u32 magic, size;
	int err = 0;

	/* check the magic/size information */
	__get_user_error(magic, &ctx->head.magic, err);
	__get_user_error(size, &ctx->head.size, err);
	if (err)
		return -EFAULT;
	if (magic != FPSIMD_MAGIC || size != sizeof(struct fpsimd_context))
		return -EINVAL;

	/* copy the FP and status/control registers */
	err = __copy_from_user(fpsimd.vregs, ctx->vregs,
			       sizeof(fpsimd.vregs));
	__get_user_error(fpsimd.fpsr, &ctx->fpsr, err);
	__get_user_error(fpsimd.fpcr, &ctx->fpcr, err);

	clear_thread_flag(TIF_SVE);

	/* load the hardware registers from the fpsimd_state structure */
	if (!err)
		fpsimd_update_current_state(&fpsimd);

	return err ? -EFAULT : 0;
}

#ifdef CONFIG_ARM64_SVE

int preserve_sve_context(struct sve_context __user *ctx)
{
	int err = 0;
	u16 reserved[ARRAY_SIZE(ctx->__reserved)];
	unsigned int vl = current->thread.sve_vl;
	unsigned int vq = 0;

	if (test_thread_flag(TIF_SVE))
		vq = sve_vq_from_vl(vl);

	memset(reserved, 0, sizeof(reserved));

	__put_user_error(SVE_MAGIC, &ctx->head.magic, err);
	__put_user_error(round_up(SVE_SIG_CONTEXT_SIZE(vq), 16),
			 &ctx->head.size, err);
	__put_user_error(vl, &ctx->vl, err);
	BUILD_BUG_ON(sizeof(ctx->__reserved) != sizeof(reserved));
	err |= __copy_to_user(&ctx->__reserved, reserved, sizeof(reserved));

	if (vq) {
		/*
		 * This assumes that the SVE state has already been saved to
		 * the task struct by calling the function
		 * fpsimd_signal_preserve_current_state().
		 */
		err |= __copy_to_user((char __user *)ctx + SVE_SIG_REGS_OFFSET,
				      current->thread.sve_state,
				      SVE_SIG_REGS_SIZE(vq));
	}

	return err ? -EFAULT : 0;
}

int restore_sve_fpsimd_context(struct user_ctxs *user)
{
	int err;
	unsigned int vq;
	struct user_fpsimd_state fpsimd;
	struct sve_context sve;

	if (__copy_from_user(&sve, user->sve, sizeof(sve)))
		return -EFAULT;

	if (sve.vl != current->thread.sve_vl)
		return -EINVAL;

	if (sve.head.size <= sizeof(*user->sve)) {
		clear_thread_flag(TIF_SVE);
		goto fpsimd_only;
	}

	vq = sve_vq_from_vl(sve.vl);

	if (sve.head.size < SVE_SIG_CONTEXT_SIZE(vq))
		return -EINVAL;

	/*
	 * Careful: we are about __copy_from_user() directly into
	 * thread.sve_state with preemption enabled, so protection is
	 * needed to prevent a racing context switch from writing stale
	 * registers back over the new data.
	 */

	fpsimd_flush_task_state(current);
	/* From now, fpsimd_thread_switch() won't touch thread.sve_state */

	sve_alloc(current);
	err = __copy_from_user(current->thread.sve_state,
			       (char __user const *)user->sve +
					SVE_SIG_REGS_OFFSET,
			       SVE_SIG_REGS_SIZE(vq));
	if (err)
		return -EFAULT;

	set_thread_flag(TIF_SVE);

fpsimd_only:
	/* copy the FP and status/control registers */
	/* restore_sigframe() already checked that user->fpsimd != NULL. */
	err = __copy_from_user(fpsimd.vregs, user->fpsimd->vregs,
			       sizeof(fpsimd.vregs));
	__get_user_error(fpsimd.fpsr, &user->fpsimd->fpsr, err);
	__get_user_error(fpsimd.fpcr, &user->fpsimd->fpcr, err);

	/* load the hardware registers from the fpsimd_state structure */
	if (!err)
		fpsimd_update_current_state(&fpsimd);

	return err ? -EFAULT : 0;
}

#endif /* ! CONFIG_ARM64_SVE */

int __parse_user_sigcontext(struct user_ctxs *user,
				   struct sigcontext __user const *sc,
				   void __user const *sigframe_base)
{
	struct _aarch64_ctx __user *head;
	char __user *base = (char __user *)&sc->__reserved;
	size_t offset = 0;
	size_t limit = sizeof(sc->__reserved);
	bool have_extra_context = false;
	char const __user *const sfp = (char const __user *)sigframe_base;

	user->fpsimd = NULL;
	user->sve = NULL;

	if (!IS_ALIGNED((unsigned long)base, 16))
		goto invalid;

	while (1) {
		int err = 0;
		u32 magic, size;
		char const __user *userp;
		struct extra_context const __user *extra;
		u64 extra_datap;
		u32 extra_size;
		struct _aarch64_ctx const __user *end;
		u32 end_magic, end_size;

		if (limit - offset < sizeof(*head))
			goto invalid;

		if (!IS_ALIGNED(offset, 16))
			goto invalid;

		head = (struct _aarch64_ctx __user *)(base + offset);
		__get_user_error(magic, &head->magic, err);
		__get_user_error(size, &head->size, err);
		if (err)
			return err;

		if (limit - offset < size)
			goto invalid;

		switch (magic) {
		case 0:
			if (size)
				goto invalid;

			goto done;

		case FPSIMD_MAGIC:
			if (!system_supports_fpsimd())
				goto invalid;
			if (user->fpsimd)
				goto invalid;

			if (size < sizeof(*user->fpsimd))
				goto invalid;

			user->fpsimd = (struct fpsimd_context __user *)head;
			break;

		case ESR_MAGIC:
			/* ignore */
			break;

		case SVE_MAGIC:
			if (!system_supports_sve())
				goto invalid;

			if (user->sve)
				goto invalid;

			if (size < sizeof(*user->sve))
				goto invalid;

			user->sve = (struct sve_context __user *)head;
			break;

		case EXTRA_MAGIC:
			if (have_extra_context)
				goto invalid;

			if (size < sizeof(*extra))
				goto invalid;

			userp = (char const __user *)head;

			extra = (struct extra_context const __user *)userp;
			userp += size;

			__get_user_error(extra_datap, &extra->datap, err);
			__get_user_error(extra_size, &extra->size, err);
			if (err)
				return err;

			/* Check for the dummy terminator in __reserved[]: */

			if (limit - offset - size < TERMINATOR_SIZE)
				goto invalid;

			end = (struct _aarch64_ctx const __user *)userp;
			userp += TERMINATOR_SIZE;

			__get_user_error(end_magic, &end->magic, err);
			__get_user_error(end_size, &end->size, err);
			if (err)
				return err;

			if (end_magic || end_size)
				goto invalid;

			/* Prevent looping/repeated parsing of extra_context */
			have_extra_context = true;

			base = (__force void __user *)extra_datap;
			if (!IS_ALIGNED((unsigned long)base, 16))
				goto invalid;

			if (!IS_ALIGNED(extra_size, 16))
				goto invalid;

			if (base != userp)
				goto invalid;

			/* Reject "unreasonably large" frames: */
			if (extra_size > sfp + SIGFRAME_MAXSZ - userp)
				goto invalid;

			/*
			 * Ignore trailing terminator in __reserved[]
			 * and start parsing extra data:
			 */
			offset = 0;
			limit = extra_size;

			if (!access_ok(base, limit))
				goto invalid;

			continue;

		default:
			goto invalid;
		}

		if (size < sizeof(*head))
			goto invalid;

		if (limit - offset < size)
			goto invalid;

		offset += size;
	}

done:
	return 0;

invalid:
	return -EINVAL;
}

SYSCALL_DEFINE0(rt_sigreturn)
{
	struct pt_regs *regs = current_pt_regs();

	return __sys_rt_sigreturn(regs);
}

/*
 * Determine the layout of optional records in the signal frame
 *
 * add_all: if true, lays out the biggest possible signal frame for
 *	this task; otherwise, generates a layout for the current state
 *	of the task.
 */
int setup_sigframe_layout(struct rt_sigframe_user_layout *user, bool add_all)
{
	int err;

	err = sigframe_alloc(user, &user->fpsimd_offset,
			     sizeof(struct fpsimd_context));
	if (err)
		return err;

	/* fault information, if valid */
	if (add_all || current->thread.fault_code) {
		err = sigframe_alloc(user, &user->esr_offset,
				     sizeof(struct esr_context));
		if (err)
			return err;
	}

	if (system_supports_sve()) {
		unsigned int vq = 0;

		if (add_all || test_thread_flag(TIF_SVE)) {
			int vl = sve_max_vl;

			if (!add_all)
				vl = current->thread.sve_vl;

			vq = sve_vq_from_vl(vl);
		}

		err = sigframe_alloc(user, &user->sve_offset,
				     SVE_SIG_CONTEXT_SIZE(vq));
		if (err)
			return err;
	}

	return sigframe_alloc_end(user);
}

int setup_extra_context(char __user *sfp, unsigned long sf_size,
			char __user *extrap)
{
	int err = 0;
	struct extra_context __user *extra;
	struct _aarch64_ctx __user *end;
	u64 extra_datap;
	u32 extra_size;

	extra = (struct extra_context __user *)extrap;
	extrap += EXTRA_CONTEXT_SIZE;

	end = (struct _aarch64_ctx __user *)extrap;
	extrap += TERMINATOR_SIZE;

	/*
	 * extra_datap is just written to the signal frame.
	 * The value gets cast back to a void __user *
	 * during sigreturn.
	 */
	extra_datap = (__force u64)extrap;
	extra_size = sfp + round_up(sf_size, 16) - extrap;

	__put_user_error(EXTRA_MAGIC, &extra->head.magic, err);
	__put_user_error(EXTRA_CONTEXT_SIZE, &extra->head.size, err);
	__put_user_error(extra_datap, &extra->datap, err);
	__put_user_error(extra_size, &extra->size, err);

	/* Add the terminator */
	__put_user_error(0, &end->magic, err);
	__put_user_error(0, &end->size, err);

	return err;
}

void __setup_return(struct pt_regs *regs, struct k_sigaction *ka,
		struct rt_sigframe_user_layout *user, int usig)
{
	regs->regs[0] = usig;
	regs->sp = (unsigned long)user->sigframe;
	regs->regs[29] = (unsigned long)&user->next_frame->fp;
	regs->pc = (unsigned long)ka->sa.sa_handler;

}

static void setup_return(struct pt_regs *regs, struct k_sigaction *ka,
			 struct rt_sigframe_user_layout *user, int usig)
{
	__sigrestore_t sigtramp;

	__setup_return(regs, ka, user, usig);

	/*
	 * Signal delivery is a (wacky) indirect function call in
	 * userspace, so simulate the same setting of BTYPE as a BLR
	 * <register containing the signal handler entry point>.
	 * Signal delivery to a location in a PROT_BTI guarded page
	 * that is not a function entry point will now trigger a
	 * SIGILL in userspace.
	 *
	 * If the signal handler entry point is not in a PROT_BTI
	 * guarded page, this is harmless.
	 */
	if (system_supports_bti()) {
		regs->pstate &= ~PSR_BTYPE_MASK;
		regs->pstate |= PSR_BTYPE_C;
	}

	/* TCO (Tag Check Override) always cleared for signal handlers */
	regs->pstate &= ~PSR_TCO_BIT;

	if (ka->sa.sa_flags & SA_RESTORER)
		sigtramp = ka->sa.sa_restorer;
	else
		sigtramp = VDSO_SYMBOL(current->mm->context.vdso, sigtramp);

	regs->regs[30] = (unsigned long)sigtramp;
}

static int setup_rt_frame(int usig, struct ksignal *ksig, sigset_t *set,
			  struct pt_regs *regs)
{
	return __setup_rt_frame(usig, ksig, set, regs);
}

static void setup_restart_syscall(struct pt_regs *regs)
{
	if (is_a32_compat_task())
		a32_setup_restart_syscall(regs);
	else
		regs->regs[8] = __NR_restart_syscall;
}

/*
 * OK, we're invoking a handler
 */
static void handle_signal(struct ksignal *ksig, struct pt_regs *regs)
{
	sigset_t *oldset = sigmask_to_save();
	int usig = ksig->sig;
	int ret;

	rseq_signal_deliver(ksig, regs);

	/*
	 * Set up the stack frame
	 */
	if (is_a32_compat_task()) {
		if (ksig->ka.sa.sa_flags & SA_SIGINFO)
			ret = a32_setup_rt_frame(usig, ksig, oldset, regs);
		else
			ret = a32_setup_frame(usig, ksig, oldset, regs);
	} else if (is_ilp32_compat_task()) {
		ret = ilp32_setup_rt_frame(usig, ksig, oldset, regs);
	} else {
		ret = setup_rt_frame(usig, ksig, oldset, regs);
	}

	/*
	 * Check that the resulting registers are actually sane.
	 */
	ret |= !valid_user_regs(&regs->user_regs, current);

	/* Step into the signal handler if we are stepping */
	signal_setup_done(ret, ksig, test_thread_flag(TIF_SINGLESTEP));
}

/*
 * Note that 'init' is a special process: it doesn't get signals it doesn't
 * want to handle. Thus you cannot kill init even with a SIGKILL even by
 * mistake.
 *
 * Note that we go through the signals twice: once to check the signals that
 * the kernel can handle, and then we build all the user-level signal handling
 * stack-frames in one go after that.
 */
static void do_signal(struct pt_regs *regs)
{
	unsigned long continue_addr = 0, restart_addr = 0;
	int retval = 0;
	struct ksignal ksig;
	bool syscall = in_syscall(regs);

	/*
	 * If we were from a system call, check for system call restarting...
	 */
	if (syscall) {
		continue_addr = regs->pc;
		restart_addr = continue_addr - (a32_thumb_mode(regs) ? 2 : 4);
		retval = regs->regs[0];

		/*
		 * Avoid additional syscall restarting via ret_to_user.
		 */
		forget_syscall(regs);

		/*
		 * Prepare for system call restart. We do this here so that a
		 * debugger will see the already changed PC.
		 */
		switch (retval) {
		case -ERESTARTNOHAND:
		case -ERESTARTSYS:
		case -ERESTARTNOINTR:
		case -ERESTART_RESTARTBLOCK:
			regs->regs[0] = regs->orig_x0;
			regs->pc = restart_addr;
			break;
		}
	}

	/*
	 * Get the signal to deliver. When running under ptrace, at this point
	 * the debugger may change all of our registers.
	 */
	if (get_signal(&ksig)) {
		/*
		 * Depending on the signal settings, we may need to revert the
		 * decision to restart the system call, but skip this if a
		 * debugger has chosen to restart at a different PC.
		 */
		if (regs->pc == restart_addr &&
		    (retval == -ERESTARTNOHAND ||
		     retval == -ERESTART_RESTARTBLOCK ||
		     (retval == -ERESTARTSYS &&
		      !(ksig.ka.sa.sa_flags & SA_RESTART)))) {
			regs->regs[0] = -EINTR;
			regs->pc = continue_addr;
		}

		handle_signal(&ksig, regs);
		return;
	}

	/*
	 * Handle restarting a different system call. As above, if a debugger
	 * has chosen to restart at a different PC, ignore the restart.
	 */
	if (syscall && regs->pc == restart_addr) {
		if (retval == -ERESTART_RESTARTBLOCK)
			setup_restart_syscall(regs);
		user_rewind_single_step(current);
	}

	restore_saved_sigmask();
}

asmlinkage void do_notify_resume(struct pt_regs *regs,
				 unsigned long thread_flags)
{
	do {
		/* Check valid user FS if needed */
		addr_limit_user_check();

		if (thread_flags & _TIF_NEED_RESCHED) {
			/* Unmask Debug and SError for the next task */
			local_daif_restore(DAIF_PROCCTX_NOIRQ);

			schedule();
		} else {
			local_daif_restore(DAIF_PROCCTX);

			if (thread_flags & _TIF_UPROBE)
				uprobe_notify_resume(regs);

			if (thread_flags & _TIF_MTE_ASYNC_FAULT) {
				clear_thread_flag(TIF_MTE_ASYNC_FAULT);
				send_sig_fault(SIGSEGV, SEGV_MTEAERR,
					       (void __user *)NULL, current);
			}

			if (thread_flags & _TIF_SIGPENDING)
				do_signal(regs);

			if (thread_flags & _TIF_NOTIFY_RESUME) {
				tracehook_notify_resume(regs);
				rseq_handle_notify_resume(NULL, regs);
			}

			if (thread_flags & _TIF_FOREIGN_FPSTATE)
				fpsimd_restore_current_state();
		}

		local_daif_mask();
		thread_flags = READ_ONCE(current_thread_info()->flags);
	} while (thread_flags & _TIF_WORK_MASK);
}

unsigned long __ro_after_init signal_minsigstksz;

/*
 * Determine the stack space required for guaranteed signal devliery.
 * This function is used to populate AT_MINSIGSTKSZ at process startup.
 * cpufeatures setup is assumed to be complete.
 */
void __init minsigstksz_setup(void)
{
	struct rt_sigframe_user_layout user;

	init_user_layout(&user);

	/*
	 * If this fails, SIGFRAME_MAXSZ needs to be enlarged.  It won't
	 * be big enough, but it's our best guess:
	 */
	if (WARN_ON(setup_sigframe_layout(&user, true)))
		return;

	signal_minsigstksz = sigframe_size(&user) +
		round_up(sizeof(struct frame_record), 16) +
		16; /* max alignment padding */
}
