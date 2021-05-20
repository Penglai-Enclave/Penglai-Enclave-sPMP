// SPDX-License-Identifier: GPL-2.0

/*
 * Support for AArch32 Linux ELF binaries.
 */

/* AArch32 EABI. */
#define EF_ARM_EABI_MASK		0xff000000

#define compat_start_thread		compat_start_thread
/*
 * Unlike the native SET_PERSONALITY macro, the compat version inherits
 * READ_IMPLIES_EXEC across a fork() since this is the behaviour on
 * arch/arm/.
 */
#define COMPAT_SET_PERSONALITY(ex)					\
({									\
	clear_thread_flag(TIF_32BIT_AARCH64);				\
	set_thread_flag(TIF_32BIT);					\
})

#define COMPAT_ARCH_DLINFO
#define COMPAT_ELF_HWCAP		(a32_elf_hwcap)
#define COMPAT_ELF_HWCAP2		(a32_elf_hwcap2)

#define compat_arch_setup_additional_pages \
					aarch32_setup_additional_pages

/* AArch32 EABI. */
#define compat_elf_check_arch(x)	(system_supports_32bit_el0() && \
					 ((x)->e_machine == EM_ARM) && \
					 ((x)->e_flags & EF_ARM_EABI_MASK))

#include "../../../fs/compat_binfmt_elf.c"
