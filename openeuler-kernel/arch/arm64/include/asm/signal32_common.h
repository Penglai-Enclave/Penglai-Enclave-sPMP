/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __ASM_SIGNAL32_COMMON_H
#define __ASM_SIGNAL32_COMMON_H

#ifdef CONFIG_COMPAT

int put_sigset_t(compat_sigset_t __user *uset, sigset_t *set);
int get_sigset_t(sigset_t *set, const compat_sigset_t __user *uset);

#endif /* CONFIG_COMPAT*/

#endif /* __ASM_SIGNAL32_COMMON_H */
