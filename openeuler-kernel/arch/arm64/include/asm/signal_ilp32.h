/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __ASM_SIGNAL_ILP32_H
#define __ASM_SIGNAL_ILP32_H

#ifdef CONFIG_ARM64_ILP32

#include <linux/compat.h>

int ilp32_setup_rt_frame(int usig, struct ksignal *ksig, sigset_t *set,
			  struct pt_regs *regs);

#else

static inline int ilp32_setup_rt_frame(int usig, struct ksignal *ksig,
					sigset_t *set, struct pt_regs *regs)
{
	return -ENOSYS;
}

#endif /* CONFIG_ARM64_ILP32 */

#endif /* __ASM_SIGNAL_ILP32_H */
