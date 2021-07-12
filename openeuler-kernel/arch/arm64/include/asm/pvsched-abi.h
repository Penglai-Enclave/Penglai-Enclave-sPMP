/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright(c) 2019 Huawei Technologies Co., Ltd
 * Author: Zengruan Ye <yezengruan@huawei.com>
 */

#ifndef __ASM_PVSCHED_ABI_H
#define __ASM_PVSCHED_ABI_H

struct pvsched_vcpu_state {
	__le32 preempted;
	/* Structure must be 64 byte aligned, pad to that size */
	u8 padding[60];
} __packed;

#endif
