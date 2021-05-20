/* SPDX-License-Identifier: GPL-2.0 */

/* Common low-level thread bits accessors */

#ifndef _LINUX_THREAD_BITS_H
#define _LINUX_THREAD_BITS_H

#ifndef __ASSEMBLY__

/*
 * For per-arch arch_within_stack_frames() implementations, defined in
 * asm/thread_info.h.
 */
enum {
	BAD_STACK = -1,
	NOT_STACK = 0,
	GOOD_FRAME,
	GOOD_STACK,
};

#ifdef CONFIG_THREAD_INFO_IN_TASK
/*
 * For CONFIG_THREAD_INFO_IN_TASK kernels we need <asm/current.h> for the
 * definition of current, but for !CONFIG_THREAD_INFO_IN_TASK kernels,
 * including <asm/current.h> can cause a circular dependency on some platforms.
 */
#include <asm/current.h>
#define current_thread_info() ((struct thread_info *)current)
#endif

#include <linux/bitops.h>
#include <asm/thread_info.h>

/*
 * flag set/clear/test wrappers
 * - pass TIF_xxxx constants to these functions
 */

static inline void set_ti_thread_flag(struct thread_info *ti, int flag)
{
	set_bit(flag, (unsigned long *)&ti->flags);
}

static inline void clear_ti_thread_flag(struct thread_info *ti, int flag)
{
	clear_bit(flag, (unsigned long *)&ti->flags);
}

static inline void update_ti_thread_flag(struct thread_info *ti, int flag,
					 bool value)
{
	if (value)
		set_ti_thread_flag(ti, flag);
	else
		clear_ti_thread_flag(ti, flag);
}

static inline int test_and_set_ti_thread_flag(struct thread_info *ti, int flag)
{
	return test_and_set_bit(flag, (unsigned long *)&ti->flags);
}

static inline int test_and_clear_ti_thread_flag(struct thread_info *ti, int flag)
{
	return test_and_clear_bit(flag, (unsigned long *)&ti->flags);
}

static inline int test_ti_thread_flag(struct thread_info *ti, int flag)
{
	return test_bit(flag, (unsigned long *)&ti->flags);
}

#define set_thread_flag(flag) \
	set_ti_thread_flag(current_thread_info(), flag)
#define clear_thread_flag(flag) \
	clear_ti_thread_flag(current_thread_info(), flag)
#define update_thread_flag(flag, value) \
	update_ti_thread_flag(current_thread_info(), flag, value)
#define test_and_set_thread_flag(flag) \
	test_and_set_ti_thread_flag(current_thread_info(), flag)
#define test_and_clear_thread_flag(flag) \
	test_and_clear_ti_thread_flag(current_thread_info(), flag)
#define test_thread_flag(flag) \
	test_ti_thread_flag(current_thread_info(), flag)

#endif /* !__ASSEMBLY__ */
#endif /* _LINUX_THREAD_BITS_H */
