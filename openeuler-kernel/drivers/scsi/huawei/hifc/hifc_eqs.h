/* SPDX-License-Identifier: GPL-2.0 */
/* Huawei Hifc PCI Express Linux driver
 * Copyright(c) 2017 Huawei Technologies Co., Ltd
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 *
 */

#ifndef HIFC_EQS_H
#define HIFC_EQS_H

#define HIFC_MAX_AEQS                   3
#define HIFC_MAX_CEQS                   32

#define HIFC_EQ_MAX_PAGES               8

#define HIFC_AEQE_SIZE                  64
#define HIFC_CEQE_SIZE                  4

#define HIFC_AEQE_DESC_SIZE             4
#define HIFC_AEQE_DATA_SIZE \
			(HIFC_AEQE_SIZE - HIFC_AEQE_DESC_SIZE)

#define HIFC_DEFAULT_AEQ_LEN            4096
#define HIFC_DEFAULT_CEQ_LEN            8192

#define HIFC_MIN_AEQ_LEN                64
#define HIFC_MAX_AEQ_LEN                (512 * 1024)
#define HIFC_MIN_CEQ_LEN                64
#define HIFC_MAX_CEQ_LEN                (1024 * 1024)

#define HIFC_CEQ_ID_CMDQ                0
#define EQ_IRQ_NAME_LEN                 64

/* EQ registers */
#define HIFC_AEQ_MTT_OFF_BASE_ADDR      0x200
#define HIFC_CEQ_MTT_OFF_BASE_ADDR      0x400

#define HIFC_EQ_MTT_OFF_STRIDE          0x40

#define HIFC_CSR_AEQ_MTT_OFF(id) \
	(HIFC_AEQ_MTT_OFF_BASE_ADDR + (id) * HIFC_EQ_MTT_OFF_STRIDE)

#define HIFC_CSR_CEQ_MTT_OFF(id) \
	(HIFC_CEQ_MTT_OFF_BASE_ADDR + (id) * HIFC_EQ_MTT_OFF_STRIDE)

#define HIFC_CSR_EQ_PAGE_OFF_STRIDE                    8

#define HIFC_AEQ_HI_PHYS_ADDR_REG(q_id, pg_num) \
		(HIFC_CSR_AEQ_MTT_OFF(q_id) + \
		(pg_num) * HIFC_CSR_EQ_PAGE_OFF_STRIDE)

#define HIFC_AEQ_LO_PHYS_ADDR_REG(q_id, pg_num) \
		(HIFC_CSR_AEQ_MTT_OFF(q_id) + \
		(pg_num) * HIFC_CSR_EQ_PAGE_OFF_STRIDE + 4)

#define HIFC_CEQ_HI_PHYS_ADDR_REG(q_id, pg_num) \
		(HIFC_CSR_CEQ_MTT_OFF(q_id) + \
		(pg_num) * HIFC_CSR_EQ_PAGE_OFF_STRIDE)

#define HIFC_CEQ_LO_PHYS_ADDR_REG(q_id, pg_num) \
		(HIFC_CSR_CEQ_MTT_OFF(q_id) + \
		(pg_num) * HIFC_CSR_EQ_PAGE_OFF_STRIDE + 4)

#define HIFC_EQ_HI_PHYS_ADDR_REG(type, q_id, pg_num) \
		((u32)((type == HIFC_AEQ) ? \
		HIFC_AEQ_HI_PHYS_ADDR_REG(q_id, pg_num) : \
		HIFC_CEQ_HI_PHYS_ADDR_REG(q_id, pg_num)))

#define HIFC_EQ_LO_PHYS_ADDR_REG(type, q_id, pg_num) \
		((u32)((type == HIFC_AEQ) ? \
		HIFC_AEQ_LO_PHYS_ADDR_REG(q_id, pg_num) : \
		HIFC_CEQ_LO_PHYS_ADDR_REG(q_id, pg_num)))

#define HIFC_AEQ_CTRL_0_ADDR_BASE           0xE00
#define HIFC_AEQ_CTRL_1_ADDR_BASE           0xE04
#define HIFC_AEQ_CONS_IDX_0_ADDR_BASE       0xE08
#define HIFC_AEQ_CONS_IDX_1_ADDR_BASE       0xE0C

#define HIFC_EQ_OFF_STRIDE                  0x80

#define HIFC_CSR_AEQ_CTRL_0_ADDR(idx) \
	(HIFC_AEQ_CTRL_0_ADDR_BASE + (idx) * HIFC_EQ_OFF_STRIDE)

#define HIFC_CSR_AEQ_CTRL_1_ADDR(idx) \
	(HIFC_AEQ_CTRL_1_ADDR_BASE + (idx) * HIFC_EQ_OFF_STRIDE)

#define HIFC_CSR_AEQ_CONS_IDX_ADDR(idx) \
	(HIFC_AEQ_CONS_IDX_0_ADDR_BASE + (idx) * HIFC_EQ_OFF_STRIDE)

#define HIFC_CSR_AEQ_PROD_IDX_ADDR(idx) \
	(HIFC_AEQ_CONS_IDX_1_ADDR_BASE + (idx) * HIFC_EQ_OFF_STRIDE)

#define HIFC_CEQ_CTRL_0_ADDR_BASE           0x1000
#define HIFC_CEQ_CTRL_1_ADDR_BASE           0x1004
#define HIFC_CEQ_CONS_IDX_0_ADDR_BASE       0x1008
#define HIFC_CEQ_CONS_IDX_1_ADDR_BASE       0x100C

#define HIFC_CSR_CEQ_CTRL_0_ADDR(idx) \
	(HIFC_CEQ_CTRL_0_ADDR_BASE + (idx) * HIFC_EQ_OFF_STRIDE)

#define HIFC_CSR_CEQ_CTRL_1_ADDR(idx) \
	(HIFC_CEQ_CTRL_1_ADDR_BASE + (idx) * HIFC_EQ_OFF_STRIDE)

#define HIFC_CSR_CEQ_CONS_IDX_ADDR(idx) \
	(HIFC_CEQ_CONS_IDX_0_ADDR_BASE + (idx) * HIFC_EQ_OFF_STRIDE)

#define HIFC_CSR_CEQ_PROD_IDX_ADDR(idx) \
	(HIFC_CEQ_CONS_IDX_1_ADDR_BASE + (idx) * HIFC_EQ_OFF_STRIDE)

enum hifc_eq_type {
	HIFC_AEQ,
	HIFC_CEQ
};

enum hifc_eq_intr_mode {
	HIFC_INTR_MODE_ARMED,
	HIFC_INTR_MODE_ALWAYS,
};

enum hifc_eq_ci_arm_state {
	HIFC_EQ_NOT_ARMED,
	HIFC_EQ_ARMED,
};

struct hifc_eq_work {
	struct work_struct work;
	void *data;
};

struct hifc_ceq_tasklet_data {
	void	*data;
};

struct hifc_eq {
	struct hifc_hwdev *hwdev;
	u16 q_id;
	enum hifc_eq_type type;
	u32 page_size;
	u32 orig_page_size;
	u32 eq_len;

	u32 cons_idx;
	u16 wrapped;

	u16 elem_size;
	u16 num_pages;
	u32 num_elem_in_pg;

	struct irq_info eq_irq;
	char irq_name[EQ_IRQ_NAME_LEN];

	dma_addr_t *dma_addr;
	u8 **virt_addr;
	dma_addr_t *dma_addr_for_free;
	u8 **virt_addr_for_free;

	struct hifc_eq_work aeq_work;
	struct tasklet_struct ceq_tasklet;
	struct hifc_ceq_tasklet_data ceq_tasklet_data;

	u64 hard_intr_jif;
	u64 soft_intr_jif;
};

struct hifc_aeq_elem {
	u8 aeqe_data[HIFC_AEQE_DATA_SIZE];
	u32 desc;
};

enum hifc_aeq_cb_state {
	HIFC_AEQ_HW_CB_REG = 0,
	HIFC_AEQ_HW_CB_RUNNING,
	HIFC_AEQ_SW_CB_REG,
	HIFC_AEQ_SW_CB_RUNNING,
};

struct hifc_aeqs {
	struct hifc_hwdev *hwdev;

	hifc_aeq_hwe_cb aeq_hwe_cb[HIFC_MAX_AEQ_EVENTS];
	hifc_aeq_swe_cb aeq_swe_cb[HIFC_MAX_AEQ_SW_EVENTS];
	unsigned long aeq_hw_cb_state[HIFC_MAX_AEQ_EVENTS];
	unsigned long aeq_sw_cb_state[HIFC_MAX_AEQ_SW_EVENTS];

	struct hifc_eq aeq[HIFC_MAX_AEQS];
	u16 num_aeqs;

	struct workqueue_struct *workq;
};

enum hifc_ceq_cb_state {
	HIFC_CEQ_CB_REG = 0,
	HIFC_CEQ_CB_RUNNING,
};

struct hifc_ceqs {
	struct hifc_hwdev *hwdev;

	hifc_ceq_event_cb ceq_cb[HIFC_MAX_CEQ_EVENTS];
	void *ceq_data[HIFC_MAX_CEQ_EVENTS];
	unsigned long ceq_cb_state[HIFC_MAX_CEQ_EVENTS];

	struct hifc_eq ceq[HIFC_MAX_CEQS];
	u16 num_ceqs;
};

int hifc_aeqs_init(struct hifc_hwdev *hwdev, u16 num_aeqs,
		   struct irq_info *msix_entries);

void hifc_aeqs_free(struct hifc_hwdev *hwdev);

int hifc_ceqs_init(struct hifc_hwdev *hwdev, u16 num_ceqs,
		   struct irq_info *msix_entries);

void hifc_ceqs_free(struct hifc_hwdev *hwdev);

void hifc_get_ceq_irqs(struct hifc_hwdev *hwdev, struct irq_info *irqs,
		       u16 *num_irqs);

void hifc_get_aeq_irqs(struct hifc_hwdev *hwdev, struct irq_info *irqs,
		       u16 *num_irqs);

void hifc_dump_aeq_info(struct hifc_hwdev *hwdev);

#endif
