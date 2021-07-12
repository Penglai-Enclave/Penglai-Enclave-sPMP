/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __ASM_IS_COMPAT_H
#define __ASM_IS_COMPAT_H
#ifndef __ASSEMBLY__

#include <linux/thread_bits.h>

#ifdef CONFIG_AARCH32_EL0

static inline int is_a32_compat_task(void)
{
	return test_thread_flag(TIF_32BIT);
}

static inline int is_a32_compat_thread(struct thread_info *thread)
{
	return test_ti_thread_flag(thread, TIF_32BIT);
}

#else

static inline int is_a32_compat_task(void)

{
	return 0;
}

static inline int is_a32_compat_thread(struct thread_info *thread)
{
	return 0;
}

#endif /* CONFIG_AARCH32_EL0 */

#ifdef CONFIG_ARM64_ILP32

static inline int is_ilp32_compat_task(void)
{
	return test_thread_flag(TIF_32BIT_AARCH64);
}

static inline int is_ilp32_compat_thread(struct thread_info *thread)
{
	return test_ti_thread_flag(thread, TIF_32BIT_AARCH64);
}

#else

static inline int is_ilp32_compat_task(void)
{
	return 0;
}

static inline int is_ilp32_compat_thread(struct thread_info *thread)
{
	return 0;
}

#endif /* CONFIG_ARM64_ILP32 */

#ifdef CONFIG_COMPAT

static inline int is_compat_task(void)
{
	return is_a32_compat_task() || is_ilp32_compat_task();
}

#endif /* CONFIG_COMPAT */

static inline int is_compat_thread(struct thread_info *thread)
{
	return is_a32_compat_thread(thread) || is_ilp32_compat_thread(thread);
}


#endif /* !__ASSEMBLY__ */
#endif /* __ASM_IS_COMPAT_H */
