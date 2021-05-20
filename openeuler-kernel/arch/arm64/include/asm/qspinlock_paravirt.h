/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright(c) 2019 Huawei Technologies Co., Ltd
 * Author: Zengruan Ye <yezengruan@huawei.com>
 */

#ifndef __ASM_QSPINLOCK_PARAVIRT_H
#define __ASM_QSPINLOCK_PARAVIRT_H

extern void __pv_queued_spin_unlock(struct qspinlock *lock);

#endif
