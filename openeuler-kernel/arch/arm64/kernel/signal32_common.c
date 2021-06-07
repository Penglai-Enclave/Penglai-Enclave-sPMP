// SPDX-License-Identifier: GPL-2.0

/*
 * Based on arch/arm/kernel/signal.c
 *
 * Copyright (C) 1995-2009 Russell King
 * Copyright (C) 2012 ARM Ltd.
 * Modified by Will Deacon <will.deacon@arm.com>
 */

#include <linux/compat.h>
#include <linux/signal.h>
#include <linux/uaccess.h>

#include <asm/signal32_common.h>
#include <asm/unistd.h>

int put_sigset_t(compat_sigset_t __user *uset, sigset_t *set)
{
	compat_sigset_t	cset;

	cset.sig[0] = set->sig[0] & 0xffffffffull;
	cset.sig[1] = set->sig[0] >> 32;

	return copy_to_user(uset, &cset, sizeof(*uset));
}

int get_sigset_t(sigset_t *set, const compat_sigset_t __user *uset)
{
	compat_sigset_t s32;

	if (copy_from_user(&s32, uset, sizeof(*uset)))
		return -EFAULT;

	set->sig[0] = s32.sig[0] | (((long)s32.sig[1]) << 32);
	return 0;
}
