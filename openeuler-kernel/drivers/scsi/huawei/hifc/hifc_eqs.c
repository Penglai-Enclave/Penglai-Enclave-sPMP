// SPDX-License-Identifier: GPL-2.0
/* Huawei Hifc PCI Express Linux driver
 * Copyright(c) 2017 Huawei Technologies Co., Ltd
 *
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": [COMM]" fmt

#include <linux/types.h>
#include <linux/errno.h>
#include <linux/interrupt.h>
#include <linux/workqueue.h>
#include <linux/pci.h>
#include <linux/kernel.h>
#include <linux/device.h>
#include <linux/dma-mapping.h>
#include <linux/module.h>

#include "hifc_knl_adp.h"
#include "hifc_hw.h"
#include "hifc_hwif.h"
#include "hifc_api_cmd.h"
#include "hifc_mgmt.h"
#include "hifc_hwdev.h"
#include "hifc_eqs.h"

#define HIFC_EQS_WQ_NAME                        "hifc_eqs"

#define AEQ_CTRL_0_INTR_IDX_SHIFT               0
#define AEQ_CTRL_0_FUNC_BUSY_SHIFT              10
#define AEQ_CTRL_0_DMA_ATTR_SHIFT               12
#define AEQ_CTRL_0_PCI_INTF_IDX_SHIFT           20
#define AEQ_CTRL_0_QPS_NUM_SHIFT                22
#define AEQ_CTRL_0_INTR_MODE_SHIFT              31

#define AEQ_CTRL_0_INTR_IDX_MASK                0x3FFU
#define AEQ_CTRL_0_FUNC_BUSY_MASK               0x1U
#define AEQ_CTRL_0_DMA_ATTR_MASK                0x3FU
#define AEQ_CTRL_0_PCI_INTF_IDX_MASK            0x3U
#define AEQ_CTRL_0_QPS_NUM_MASK                 0xFFU
#define AEQ_CTRL_0_INTR_MODE_MASK               0x1U

#define AEQ_CTRL_0_GET(val, member)               \
				(((val) >> AEQ_CTRL_0_##member##_SHIFT) & \
				AEQ_CTRL_0_##member##_MASK)

#define AEQ_CTRL_0_SET(val, member)               \
				(((val) & AEQ_CTRL_0_##member##_MASK) << \
				AEQ_CTRL_0_##member##_SHIFT)

#define AEQ_CTRL_0_CLEAR(val, member)             \
				((val) & (~(AEQ_CTRL_0_##member##_MASK \
					<< AEQ_CTRL_0_##member##_SHIFT)))

#define AEQ_CTRL_1_LEN_SHIFT                    0
#define AEQ_CTRL_1_FUNC_OWN_SHIFT               21
#define AEQ_CTRL_1_ELEM_SIZE_SHIFT              24
#define AEQ_CTRL_1_PAGE_SIZE_SHIFT              28

#define AEQ_CTRL_1_LEN_MASK                     0x1FFFFFU
#define AEQ_CTRL_1_FUNC_OWN_MASK                0x1U
#define AEQ_CTRL_1_ELEM_SIZE_MASK               0x3U
#define AEQ_CTRL_1_PAGE_SIZE_MASK               0xFU

#define AEQ_CTRL_1_GET(val, member)               \
				(((val) >> AEQ_CTRL_1_##member##_SHIFT) & \
				AEQ_CTRL_1_##member##_MASK)

#define AEQ_CTRL_1_SET(val, member)               \
				(((val) & AEQ_CTRL_1_##member##_MASK) << \
				AEQ_CTRL_1_##member##_SHIFT)

#define AEQ_CTRL_1_CLEAR(val, member)             \
				((val) & (~(AEQ_CTRL_1_##member##_MASK \
					<< AEQ_CTRL_1_##member##_SHIFT)))

#define HIFC_EQ_PROD_IDX_MASK               0xFFFFF
#define HIFC_TASK_PROCESS_EQE_LIMIT         1024
#define HIFC_EQ_UPDATE_CI_STEP              64

static uint g_aeq_len = HIFC_DEFAULT_AEQ_LEN;
module_param(g_aeq_len, uint, 0444);
MODULE_PARM_DESC(g_aeq_len,
		 "aeq depth, valid range is " __stringify(HIFC_MIN_AEQ_LEN)
		 " - " __stringify(HIFC_MAX_AEQ_LEN));

static uint g_ceq_len = HIFC_DEFAULT_CEQ_LEN;
module_param(g_ceq_len, uint, 0444);
MODULE_PARM_DESC(g_ceq_len,
		 "ceq depth, valid range is " __stringify(HIFC_MIN_CEQ_LEN)
		 " - " __stringify(HIFC_MAX_CEQ_LEN));

static uint g_num_ceqe_in_tasklet = HIFC_TASK_PROCESS_EQE_LIMIT;
module_param(g_num_ceqe_in_tasklet, uint, 0444);
MODULE_PARM_DESC(g_num_ceqe_in_tasklet,
		 "The max number of ceqe can be processed in tasklet, default = 1024");

#define CEQ_CTRL_0_INTR_IDX_SHIFT               0
#define CEQ_CTRL_0_DMA_ATTR_SHIFT               12
#define CEQ_CTRL_0_LIMIT_KICK_SHIFT             20
#define CEQ_CTRL_0_PCI_INTF_IDX_SHIFT           24
#define CEQ_CTRL_0_INTR_MODE_SHIFT              31

#define CEQ_CTRL_0_INTR_IDX_MASK                0x3FFU
#define CEQ_CTRL_0_DMA_ATTR_MASK                0x3FU
#define CEQ_CTRL_0_LIMIT_KICK_MASK              0xFU
#define CEQ_CTRL_0_PCI_INTF_IDX_MASK            0x3U
#define CEQ_CTRL_0_INTR_MODE_MASK               0x1U

#define CEQ_CTRL_0_SET(val, member)               \
				(((val) & CEQ_CTRL_0_##member##_MASK) << \
				CEQ_CTRL_0_##member##_SHIFT)

#define CEQ_CTRL_1_LEN_SHIFT                    0
#define CEQ_CTRL_1_PAGE_SIZE_SHIFT              28
#define CEQ_CTRL_1_LEN_MASK                     0x1FFFFFU
#define CEQ_CTRL_1_PAGE_SIZE_MASK               0xFU

#define CEQ_CTRL_1_SET(val, member)               \
				(((val) & CEQ_CTRL_1_##member##_MASK) << \
				CEQ_CTRL_1_##member##_SHIFT)

#define EQ_ELEM_DESC_TYPE_SHIFT                 0
#define EQ_ELEM_DESC_SRC_SHIFT                  7
#define EQ_ELEM_DESC_SIZE_SHIFT                 8
#define EQ_ELEM_DESC_WRAPPED_SHIFT              31
#define EQ_ELEM_DESC_TYPE_MASK                  0x7FU
#define EQ_ELEM_DESC_SRC_MASK                   0x1U
#define EQ_ELEM_DESC_SIZE_MASK                  0xFFU
#define EQ_ELEM_DESC_WRAPPED_MASK               0x1U

#define EQ_ELEM_DESC_GET(val, member)             \
				(((val) >> EQ_ELEM_DESC_##member##_SHIFT) & \
				EQ_ELEM_DESC_##member##_MASK)

#define EQ_CONS_IDX_CONS_IDX_SHIFT              0
#define EQ_CONS_IDX_XOR_CHKSUM_SHIFT            24
#define EQ_CONS_IDX_INT_ARMED_SHIFT             31
#define EQ_CONS_IDX_CONS_IDX_MASK               0x1FFFFFU
#define EQ_CONS_IDX_XOR_CHKSUM_MASK             0xFU
#define EQ_CONS_IDX_INT_ARMED_MASK              0x1U

#define EQ_CONS_IDX_SET(val, member)               \
				(((val) & EQ_CONS_IDX_##member##_MASK) << \
				EQ_CONS_IDX_##member##_SHIFT)

#define EQ_CONS_IDX_CLEAR(val, member)             \
				((val) & (~(EQ_CONS_IDX_##member##_MASK \
					<< EQ_CONS_IDX_##member##_SHIFT)))

#define EQ_WRAPPED(eq)          ((u32)(eq)->wrapped << EQ_VALID_SHIFT)

#define EQ_CONS_IDX(eq)         ((eq)->cons_idx |  \
				((u32)(eq)->wrapped << EQ_WRAPPED_SHIFT))

#define EQ_CONS_IDX_REG_ADDR(eq)        (((eq)->type == HIFC_AEQ) ? \
				HIFC_CSR_AEQ_CONS_IDX_ADDR((eq)->q_id) : \
				HIFC_CSR_CEQ_CONS_IDX_ADDR((eq)->q_id))

#define EQ_PROD_IDX_REG_ADDR(eq)        (((eq)->type == HIFC_AEQ) ? \
				HIFC_CSR_AEQ_PROD_IDX_ADDR((eq)->q_id) : \
				HIFC_CSR_CEQ_PROD_IDX_ADDR((eq)->q_id))

#define GET_EQ_NUM_PAGES(eq, size)      \
		((u16)(ALIGN((u32)((eq)->eq_len * (eq)->elem_size), \
		(size)) / (size)))

#define GET_EQ_NUM_ELEMS(eq, pg_size)   ((pg_size) / (u32)(eq)->elem_size)

#define GET_EQ_ELEMENT(eq, idx)         \
		(((u8 *)(eq)->virt_addr[(idx) / (eq)->num_elem_in_pg]) + \
		(u32)(((idx) & ((eq)->num_elem_in_pg - 1)) * (eq)->elem_size))

#define GET_AEQ_ELEM(eq, idx)           ((struct hifc_aeq_elem *)\
					GET_EQ_ELEMENT((eq), (idx)))

#define GET_CEQ_ELEM(eq, idx)           ((u32 *)GET_EQ_ELEMENT((eq), (idx)))

#define GET_CURR_AEQ_ELEM(eq)           GET_AEQ_ELEM((eq), (eq)->cons_idx)

#define GET_CURR_CEQ_ELEM(eq)           GET_CEQ_ELEM((eq), (eq)->cons_idx)

#define PAGE_IN_4K(page_size)           ((page_size) >> 12)
#define EQ_SET_HW_PAGE_SIZE_VAL(eq)     \
		((u32)ilog2(PAGE_IN_4K((eq)->page_size)))

#define ELEMENT_SIZE_IN_32B(eq)         (((eq)->elem_size) >> 5)
#define EQ_SET_HW_ELEM_SIZE_VAL(eq)     ((u32)ilog2(ELEMENT_SIZE_IN_32B(eq)))

#define AEQ_DMA_ATTR_DEFAULT            0
#define CEQ_DMA_ATTR_DEFAULT            0
#define CEQ_LMT_KICK_DEFAULT            0
#define EQ_MSIX_RESEND_TIMER_CLEAR      1
#define EQ_WRAPPED_SHIFT                20
#define	EQ_VALID_SHIFT                  31
#define CEQE_TYPE_SHIFT                 23
#define CEQE_TYPE_MASK                  0x7

#define CEQE_TYPE(type)                 (((type) >> CEQE_TYPE_SHIFT) & \
					CEQE_TYPE_MASK)
#define CEQE_DATA_MASK                  0x3FFFFFF
#define CEQE_DATA(data)                 ((data) & CEQE_DATA_MASK)
#define EQ_MIN_PAGE_SIZE                0x1000U
#define aeq_to_aeqs(eq) \
		container_of((eq) - (eq)->q_id, struct hifc_aeqs, aeq[0])

#define ceq_to_ceqs(eq) \
		container_of((eq) - (eq)->q_id, struct hifc_ceqs, ceq[0])

/**
 * aeq_interrupt - aeq interrupt handler
 * @irq: irq number
 * @data: the async event queue of the event
 **/
static irqreturn_t aeq_interrupt(int irq, void *data)
{
	struct hifc_eq *aeq = (struct hifc_eq *)data;
	struct hifc_hwdev *hwdev = aeq->hwdev;

	struct hifc_aeqs *aeqs = aeq_to_aeqs(aeq);
	struct workqueue_struct *workq = aeqs->workq;
	struct hifc_eq_work *aeq_work;

	/* clear resend timer cnt register */
	hifc_misx_intr_clear_resend_bit(hwdev, aeq->eq_irq.msix_entry_idx,
					EQ_MSIX_RESEND_TIMER_CLEAR);

	aeq_work = &aeq->aeq_work;
	aeq_work->data = aeq;

	queue_work(workq, &aeq_work->work);

	return IRQ_HANDLED;
}

/**
 * ceq_interrupt - ceq interrupt handler
 * @irq: irq number
 * @data: the completion event queue of the event
 **/
static irqreturn_t ceq_interrupt(int irq, void *data)
{
	struct hifc_eq *ceq = (struct hifc_eq *)data;
	struct hifc_ceq_tasklet_data *ceq_tasklet_data;

	ceq->hard_intr_jif = jiffies;

	/* clear resend timer counters */
	hifc_misx_intr_clear_resend_bit(ceq->hwdev, ceq->eq_irq.msix_entry_idx,
					EQ_MSIX_RESEND_TIMER_CLEAR);

	ceq_tasklet_data = &ceq->ceq_tasklet_data;
	ceq_tasklet_data->data = data;
	tasklet_schedule(&ceq->ceq_tasklet);

	return IRQ_HANDLED;
}

static u8 eq_cons_idx_checksum_set(u32 val)
{
	u8 checksum = 0;
	u8 idx;

	for (idx = 0; idx < 32; idx += 4)
		checksum ^= ((val >> idx) & 0xF);

	return checksum & 0xF;
}

/**
 * hifc_aeq_register_hw_cb - register aeq callback for specific event
 * @hwdev: pointer to hw device
 * @event: event for the handler
 * @hw_cb: callback function
 * Return: 0 - success, negative - failure
 **/
int hifc_aeq_register_hw_cb(void *hwdev, enum hifc_aeq_type event,
			    hifc_aeq_hwe_cb hwe_cb)
{
	struct hifc_aeqs *aeqs;

	if (!hwdev || !hwe_cb || event >= HIFC_MAX_AEQ_EVENTS)
		return -EINVAL;

	aeqs = ((struct hifc_hwdev *)hwdev)->aeqs;

	aeqs->aeq_hwe_cb[event] = hwe_cb;

	set_bit(HIFC_AEQ_HW_CB_REG, &aeqs->aeq_hw_cb_state[event]);

	return 0;
}

/**
 * hifc_aeq_unregister_hw_cb - unregister the aeq callback for specific event
 * @hwdev: pointer to hw device
 * @event: event for the handler
 **/
void hifc_aeq_unregister_hw_cb(void *hwdev, enum hifc_aeq_type event)
{
	struct hifc_aeqs *aeqs;

	if (!hwdev || event >= HIFC_MAX_AEQ_EVENTS)
		return;

	aeqs = ((struct hifc_hwdev *)hwdev)->aeqs;

	clear_bit(HIFC_AEQ_HW_CB_REG, &aeqs->aeq_hw_cb_state[event]);

	while (test_bit(HIFC_AEQ_HW_CB_RUNNING, &aeqs->aeq_hw_cb_state[event]))
		usleep_range(900, 1000);

	aeqs->aeq_hwe_cb[event] = NULL;
}

/**
 * hifc_aeq_register_sw_cb - register aeq callback for sw event
 * @hwdev: pointer to hw device
 * @event: soft event for the handler
 * @sw_cb: callback function
 * Return: 0 - success, negative - failure
 **/
int hifc_aeq_register_swe_cb(void *hwdev, enum hifc_aeq_sw_type event,
			     hifc_aeq_swe_cb aeq_swe_cb)
{
	struct hifc_aeqs *aeqs;

	if (!hwdev || !aeq_swe_cb || event >= HIFC_MAX_AEQ_SW_EVENTS)
		return -EINVAL;

	aeqs = ((struct hifc_hwdev *)hwdev)->aeqs;

	aeqs->aeq_swe_cb[event] = aeq_swe_cb;

	set_bit(HIFC_AEQ_SW_CB_REG, &aeqs->aeq_sw_cb_state[event]);

	return 0;
}

/**
 * hifc_aeq_unregister_sw_cb - unregister the aeq callback for sw event
 * @hwdev: pointer to hw device
 * @event: soft event for the handler
 **/
void hifc_aeq_unregister_swe_cb(void *hwdev, enum hifc_aeq_sw_type event)
{
	struct hifc_aeqs *aeqs;

	if (!hwdev || event >= HIFC_MAX_AEQ_SW_EVENTS)
		return;

	aeqs = ((struct hifc_hwdev *)hwdev)->aeqs;

	clear_bit(HIFC_AEQ_SW_CB_REG, &aeqs->aeq_sw_cb_state[event]);

	while (test_bit(HIFC_AEQ_SW_CB_RUNNING, &aeqs->aeq_sw_cb_state[event]))
		usleep_range(900, 1000);

	aeqs->aeq_swe_cb[event] = NULL;
}

/**
 * hifc_ceq_register_sw_cb - register ceq callback for specific event
 * @hwdev: pointer to hw device
 * @event: event for the handler
 * @callback: callback function
 * Return: 0 - success, negative - failure
 **/
int hifc_ceq_register_cb(void *hwdev, enum hifc_ceq_event event,
			 hifc_ceq_event_cb callback)
{
	struct hifc_ceqs *ceqs;

	if (!hwdev || event >= HIFC_MAX_CEQ_EVENTS)
		return -EINVAL;

	ceqs = ((struct hifc_hwdev *)hwdev)->ceqs;

	ceqs->ceq_cb[event] = callback;

	set_bit(HIFC_CEQ_CB_REG, &ceqs->ceq_cb_state[event]);

	return 0;
}

/**
 * hifc_ceq_unregister_cb - unregister ceq callback for specific event
 * @hwdev: pointer to hw device
 * @event: event for the handler
 **/
void hifc_ceq_unregister_cb(void *hwdev, enum hifc_ceq_event event)
{
	struct hifc_ceqs *ceqs;

	if (!hwdev || event >= HIFC_MAX_CEQ_EVENTS)
		return;

	ceqs = ((struct hifc_hwdev *)hwdev)->ceqs;

	clear_bit(HIFC_CEQ_CB_REG, &ceqs->ceq_cb_state[event]);

	while (test_bit(HIFC_CEQ_CB_RUNNING, &ceqs->ceq_cb_state[event]))
		usleep_range(900, 1000);

	ceqs->ceq_cb[event] = NULL;
}

/**
 * set_eq_cons_idx - write the cons idx to the hw
 * @eq: The event queue to update the cons idx for
 * @arm_state: arm state value
 **/
static void set_eq_cons_idx(struct hifc_eq *eq, u32 arm_state)
{
	u32 eq_wrap_ci, val;
	u32 addr = EQ_CONS_IDX_REG_ADDR(eq);

	eq_wrap_ci = EQ_CONS_IDX(eq);

	/* other filed is resverd, set to 0 */
	val = EQ_CONS_IDX_SET(eq_wrap_ci, CONS_IDX) |
		EQ_CONS_IDX_SET(arm_state, INT_ARMED);

	val |= EQ_CONS_IDX_SET(eq_cons_idx_checksum_set(val), XOR_CHKSUM);

	hifc_hwif_write_reg(eq->hwdev->hwif, addr, val);
}

/**
 * ceq_event_handler - handle for the ceq events
 * @eqs: eqs part of the chip
 * @ceqe: ceq element of the event
 **/
static void ceq_event_handler(struct hifc_ceqs *ceqs, u32 ceqe)
{
	struct hifc_hwdev *hwdev = ceqs->hwdev;
	enum hifc_ceq_event event = CEQE_TYPE(ceqe);
	u32 ceqe_data = CEQE_DATA(ceqe);

	if (event >= HIFC_MAX_CEQ_EVENTS) {
		sdk_err(hwdev->dev_hdl, "Ceq unknown event:%d, ceqe date: 0x%x\n",
			event, ceqe_data);
		return;
	}

	set_bit(HIFC_CEQ_CB_RUNNING, &ceqs->ceq_cb_state[event]);

	if (ceqs->ceq_cb[event] &&
	    test_bit(HIFC_CEQ_CB_REG, &ceqs->ceq_cb_state[event]))
		ceqs->ceq_cb[event](hwdev, ceqe_data);

	clear_bit(HIFC_CEQ_CB_RUNNING, &ceqs->ceq_cb_state[event]);
}

static void aeq_swe_handler(struct hifc_aeqs *aeqs,
			    struct hifc_aeq_elem *aeqe_pos,
			    enum hifc_aeq_type event)
{
	enum hifc_ucode_event_type ucode_event;
	enum hifc_aeq_sw_type sw_event;
	u64 aeqe_data;
	u8 lev;

	ucode_event = event;
	/* SW event uses only the first 8B */
	sw_event = ucode_event >= HIFC_NIC_FATAL_ERROR_MAX ?
		   HIFC_STATEFULL_EVENT :
		   HIFC_STATELESS_EVENT;
	aeqe_data = be64_to_cpu((*(u64 *)aeqe_pos->aeqe_data));
	set_bit(HIFC_AEQ_SW_CB_RUNNING,
		&aeqs->aeq_sw_cb_state[sw_event]);
	if (aeqs->aeq_swe_cb[sw_event] &&
	    test_bit(HIFC_AEQ_SW_CB_REG,
		     &aeqs->aeq_sw_cb_state[sw_event])) {
		lev = aeqs->aeq_swe_cb[sw_event](aeqs->hwdev,
						 ucode_event,
						 aeqe_data);
		hifc_swe_fault_handler(aeqs->hwdev, lev,
				       ucode_event, aeqe_data);
	}
	clear_bit(HIFC_AEQ_SW_CB_RUNNING,
		  &aeqs->aeq_sw_cb_state[sw_event]);
}

static void aeq_hwe_handler(struct hifc_aeqs *aeqs,
			    struct hifc_aeq_elem *aeqe_pos,
			    enum hifc_aeq_type event, u32 aeqe_desc)
{
	u8 size;

	if (event < HIFC_MAX_AEQ_EVENTS) {
		size = EQ_ELEM_DESC_GET(aeqe_desc, SIZE);
		set_bit(HIFC_AEQ_HW_CB_RUNNING,
			&aeqs->aeq_hw_cb_state[event]);
		if (aeqs->aeq_hwe_cb[event] &&
		    test_bit(HIFC_AEQ_HW_CB_REG,
			     &aeqs->aeq_hw_cb_state[event]))
			aeqs->aeq_hwe_cb[event](aeqs->hwdev,
				aeqe_pos->aeqe_data, size);
		clear_bit(HIFC_AEQ_HW_CB_RUNNING,
			  &aeqs->aeq_hw_cb_state[event]);

		return;
	}

	sdk_warn(aeqs->hwdev->dev_hdl, "Unknown aeq hw event %d\n", event);
}

/**
 * aeq_irq_handler - handler for the aeq event
 * @eq: the async event queue of the event
 * Return: true - success, false - failure
 **/
static bool aeq_irq_handler(struct hifc_eq *eq)
{
	struct hifc_aeqs *aeqs = aeq_to_aeqs(eq);
	struct hifc_aeq_elem *aeqe_pos;
	enum hifc_aeq_type event;
	u32 aeqe_desc;
	u32 i, eqe_cnt = 0;

	for (i = 0; i < HIFC_TASK_PROCESS_EQE_LIMIT; i++) {
		aeqe_pos = GET_CURR_AEQ_ELEM(eq);

		/* Data in HW is in Big endian Format */
		aeqe_desc = be32_to_cpu(aeqe_pos->desc);

		/* HW updates wrapped bit, when it adds eq element event */
		if (EQ_ELEM_DESC_GET(aeqe_desc, WRAPPED) == eq->wrapped)
			return false;

		/* This memory barrier is needed to keep us from reading
		 * any other fields out of the cmdq wqe until we have
		 * verified the command has been processed and
		 * written back.
		 */
		dma_rmb();

		event = EQ_ELEM_DESC_GET(aeqe_desc, TYPE);
		if (EQ_ELEM_DESC_GET(aeqe_desc, SRC))
			aeq_swe_handler(aeqs, aeqe_pos, event);
		else
			aeq_hwe_handler(aeqs, aeqe_pos, event, aeqe_desc);

		eq->cons_idx++;

		if (eq->cons_idx == eq->eq_len) {
			eq->cons_idx = 0;
			eq->wrapped = !eq->wrapped;
		}

		if (++eqe_cnt >= HIFC_EQ_UPDATE_CI_STEP) {
			eqe_cnt = 0;
			set_eq_cons_idx(eq, HIFC_EQ_NOT_ARMED);
		}
	}

	return true;
}

/**
 * ceq_irq_handler - handler for the ceq event
 * @eq: the completion event queue of the event
 * Return: true - success, false - failure
 **/
static bool ceq_irq_handler(struct hifc_eq *eq)
{
	struct hifc_ceqs *ceqs = ceq_to_ceqs(eq);
	u32 ceqe, eqe_cnt = 0;
	u32 i;

	for (i = 0; i < g_num_ceqe_in_tasklet; i++) {
		ceqe = *(GET_CURR_CEQ_ELEM(eq));
		ceqe = be32_to_cpu(ceqe);

		/* HW updates wrapped bit, when it adds eq element event */
		if (EQ_ELEM_DESC_GET(ceqe, WRAPPED) == eq->wrapped)
			return false;

		ceq_event_handler(ceqs, ceqe);

		eq->cons_idx++;

		if (eq->cons_idx == eq->eq_len) {
			eq->cons_idx = 0;
			eq->wrapped = !eq->wrapped;
		}

		if (++eqe_cnt >= HIFC_EQ_UPDATE_CI_STEP) {
			eqe_cnt = 0;
			set_eq_cons_idx(eq, HIFC_EQ_NOT_ARMED);
		}
	}

	return true;
}

/**
 * eq_irq_handler - handler for the eq event
 * @data: the event queue of the event
 * Return: true - success, false - failure
 **/
static bool eq_irq_handler(void *data)
{
	struct hifc_eq *eq = (struct hifc_eq *)data;
	bool uncompleted;

	if (eq->type == HIFC_AEQ)
		uncompleted = aeq_irq_handler(eq);
	else
		uncompleted = ceq_irq_handler(eq);

	set_eq_cons_idx(eq, uncompleted ? HIFC_EQ_NOT_ARMED : HIFC_EQ_ARMED);

	return uncompleted;
}

static void reschedule_eq_handler(struct hifc_eq *eq)
{
	if (eq->type == HIFC_AEQ) {
		struct hifc_aeqs *aeqs = aeq_to_aeqs(eq);
		struct workqueue_struct *workq = aeqs->workq;
		struct hifc_eq_work *aeq_work = &eq->aeq_work;

		queue_work(workq, &aeq_work->work);
	} else {
		tasklet_schedule(&eq->ceq_tasklet);
	}
}

/**
 * ceq_tasklet - ceq tasklet for the event
 * @ceq_data: data that will be used by the tasklet(ceq)
 **/

static void ceq_tasklet(ulong ceq_data)
{
	struct hifc_ceq_tasklet_data	*ceq_tasklet_data =
				(struct hifc_ceq_tasklet_data *)ceq_data;
	struct hifc_eq *eq = (struct hifc_eq *)ceq_tasklet_data->data;

	eq->soft_intr_jif = jiffies;

	if (eq_irq_handler(ceq_tasklet_data->data))
		reschedule_eq_handler(ceq_tasklet_data->data);
}

/**
 * eq_irq_work - eq work for the event
 * @work: the work that is associated with the eq
 **/
static void eq_irq_work(struct work_struct *work)
{
	struct hifc_eq_work *aeq_work =
			container_of(work, struct hifc_eq_work, work);

	if (eq_irq_handler(aeq_work->data))
		reschedule_eq_handler(aeq_work->data);
}

struct hifc_ceq_ctrl_reg {
	u8 status;
	u8 version;
	u8 rsvd0[6];

	u16 func_id;
	u16 q_id;
	u32 ctrl0;
	u32 ctrl1;
};

static int set_ceq_ctrl_reg(struct hifc_hwdev *hwdev, u16 q_id,
			    u32 ctrl0, u32 ctrl1)
{
	struct hifc_ceq_ctrl_reg ceq_ctrl = {0};
	u16 in_size = sizeof(ceq_ctrl);
	u16 out_size = sizeof(ceq_ctrl);
	int err;

	err = hifc_global_func_id_get(hwdev, &ceq_ctrl.func_id);
	if (err)
		return err;

	ceq_ctrl.q_id = q_id;
	ceq_ctrl.ctrl0 = ctrl0;
	ceq_ctrl.ctrl1 = ctrl1;

	err = hifc_msg_to_mgmt_sync(hwdev, HIFC_MOD_COMM,
				    HIFC_MGMT_CMD_CEQ_CTRL_REG_WR_BY_UP,
				    &ceq_ctrl, in_size,
				    &ceq_ctrl, &out_size, 0);
	if (err || !out_size || ceq_ctrl.status) {
		sdk_err(hwdev->dev_hdl, "Failed to set ceq %d ctrl reg, err: %d status: 0x%x, out_size: 0x%x\n",
			q_id, err, ceq_ctrl.status, out_size);
		return -EFAULT;
	}

	return 0;
}

/**
 * set_eq_ctrls - setting eq's ctrls registers
 * @eq: the event queue for setting
 * Return: 0 - success, negative - failure
 **/
static int set_eq_ctrls(struct hifc_eq *eq)
{
	enum hifc_eq_type type = eq->type;
	struct hifc_hwif *hwif = eq->hwdev->hwif;
	struct irq_info *eq_irq = &eq->eq_irq;
	u32 addr, val, ctrl0, ctrl1, page_size_val, elem_size;
	u32 pci_intf_idx = HIFC_PCI_INTF_IDX(hwif);
	int err;

	if (type == HIFC_AEQ) {
		/* set ctrl0 */
		addr = HIFC_CSR_AEQ_CTRL_0_ADDR(eq->q_id);

		val = hifc_hwif_read_reg(hwif, addr);

		val = AEQ_CTRL_0_CLEAR(val, INTR_IDX) &
			AEQ_CTRL_0_CLEAR(val, DMA_ATTR) &
			AEQ_CTRL_0_CLEAR(val, PCI_INTF_IDX) &
			AEQ_CTRL_0_CLEAR(val, INTR_MODE);

		ctrl0 = AEQ_CTRL_0_SET(eq_irq->msix_entry_idx, INTR_IDX) |
			AEQ_CTRL_0_SET(AEQ_DMA_ATTR_DEFAULT, DMA_ATTR) |
			AEQ_CTRL_0_SET(pci_intf_idx, PCI_INTF_IDX) |

			AEQ_CTRL_0_SET(HIFC_INTR_MODE_ARMED, INTR_MODE);

		val |= ctrl0;

		hifc_hwif_write_reg(hwif, addr, val);

		/* set ctrl1 */
		addr = HIFC_CSR_AEQ_CTRL_1_ADDR(eq->q_id);

		page_size_val = EQ_SET_HW_PAGE_SIZE_VAL(eq);
		elem_size = EQ_SET_HW_ELEM_SIZE_VAL(eq);

		ctrl1 = AEQ_CTRL_1_SET(eq->eq_len, LEN)	|
			AEQ_CTRL_1_SET(elem_size, ELEM_SIZE)	|
			AEQ_CTRL_1_SET(page_size_val, PAGE_SIZE);

		hifc_hwif_write_reg(hwif, addr, ctrl1);

	} else {
		ctrl0 = CEQ_CTRL_0_SET(eq_irq->msix_entry_idx, INTR_IDX) |
			CEQ_CTRL_0_SET(CEQ_DMA_ATTR_DEFAULT, DMA_ATTR)	|
			CEQ_CTRL_0_SET(CEQ_LMT_KICK_DEFAULT, LIMIT_KICK) |
			CEQ_CTRL_0_SET(pci_intf_idx, PCI_INTF_IDX)	|
			CEQ_CTRL_0_SET(HIFC_INTR_MODE_ARMED, INTR_MODE);

		page_size_val = EQ_SET_HW_PAGE_SIZE_VAL(eq);

		ctrl1 = CEQ_CTRL_1_SET(eq->eq_len, LEN) |
			CEQ_CTRL_1_SET(page_size_val, PAGE_SIZE);

		/* set ceq ctrl reg through mgmt cpu */
		err = set_ceq_ctrl_reg(eq->hwdev, eq->q_id, ctrl0, ctrl1);
		if (err)
			return err;
	}

	return 0;
}

/**
 * ceq_elements_init - Initialize all the elements in the ceq
 * @eq: the event queue
 * @init_val: value to init with it the elements
 **/
static void ceq_elements_init(struct hifc_eq *eq, u32 init_val)
{
	u32 i;
	u32 *ceqe;

	for (i = 0; i < eq->eq_len; i++) {
		ceqe = GET_CEQ_ELEM(eq, i);
		*(ceqe) = cpu_to_be32(init_val);
	}

	wmb();	/* Write the init values */
}

/**
 * aeq_elements_init - initialize all the elements in the aeq
 * @eq: the event queue
 * @init_val: value to init with it the elements
 **/
static void aeq_elements_init(struct hifc_eq *eq, u32 init_val)
{
	struct hifc_aeq_elem *aeqe;
	u32 i;

	for (i = 0; i < eq->eq_len; i++) {
		aeqe = GET_AEQ_ELEM(eq, i);
		aeqe->desc = cpu_to_be32(init_val);
	}

	wmb();	/* Write the init values */
}

static void free_eq_pages_desc(struct hifc_eq *eq)
{
	kfree(eq->virt_addr_for_free);
	kfree(eq->dma_addr_for_free);
	kfree(eq->virt_addr);
	kfree(eq->dma_addr);
}

static int alloc_eq_pages_desc(struct hifc_eq *eq)
{
	u64 dma_addr_size, virt_addr_size;
	int err;

	dma_addr_size = eq->num_pages * sizeof(*eq->dma_addr);
	virt_addr_size = eq->num_pages * sizeof(*eq->virt_addr);

	eq->dma_addr = kzalloc(dma_addr_size, GFP_KERNEL);
	if (!eq->dma_addr)
		return -ENOMEM;

	eq->virt_addr = kzalloc(virt_addr_size, GFP_KERNEL);
	if (!eq->virt_addr) {
		err = -ENOMEM;
		goto virt_addr_alloc_err;
	}

	eq->dma_addr_for_free = kzalloc(dma_addr_size, GFP_KERNEL);
	if (!eq->dma_addr_for_free) {
		err = -ENOMEM;
		goto dma_addr_free_alloc_err;
	}

	eq->virt_addr_for_free = kzalloc(virt_addr_size, GFP_KERNEL);
	if (!eq->virt_addr_for_free) {
		err = -ENOMEM;
		goto virt_addr_free_alloc_err;
	}

	return 0;

virt_addr_free_alloc_err:
	kfree(eq->dma_addr_for_free);
dma_addr_free_alloc_err:
	kfree(eq->virt_addr);
virt_addr_alloc_err:
	kfree(eq->dma_addr);
	return err;
}

#define IS_ALIGN(x, a)	(((x) & ((a) - 1)) == 0)

static int init_eq_elements(struct hifc_eq *eq)
{
	u32 init_val;

	eq->num_elem_in_pg = GET_EQ_NUM_ELEMS(eq, eq->page_size);
	if (!IS_ALIGN(eq->num_elem_in_pg, eq->num_elem_in_pg)) {
		sdk_err(eq->hwdev->dev_hdl, "Number element in eq page != power of 2\n");
		return -EINVAL;
	}

	init_val = EQ_WRAPPED(eq);

	if (eq->type == HIFC_AEQ)
		aeq_elements_init(eq, init_val);
	else
		ceq_elements_init(eq, init_val);

	return 0;
}

/**
 * alloc_eq_pages - allocate the pages for the queue
 * @eq: the event queue
 * Return: 0 - success, negative - failure
 **/
static int alloc_eq_pages(struct hifc_eq *eq)
{
	struct hifc_hwif *hwif = eq->hwdev->hwif;
	u16 pg_num, i;
	u32 reg;
	int err;
	u8 flag = 0;

	err = alloc_eq_pages_desc(eq);
	if (err) {
		sdk_err(eq->hwdev->dev_hdl, "Failed to alloc eq pages description\n");
		return err;
	}

	for (pg_num = 0; pg_num < eq->num_pages; pg_num++) {
		eq->virt_addr_for_free[pg_num] = dma_alloc_coherent
			(eq->hwdev->dev_hdl, eq->page_size,
			&eq->dma_addr_for_free[pg_num], GFP_KERNEL);
		if (!eq->virt_addr_for_free[pg_num]) {
			err = -ENOMEM;
			goto dma_alloc_err;
		}

		eq->dma_addr[pg_num] = eq->dma_addr_for_free[pg_num];
		eq->virt_addr[pg_num] = eq->virt_addr_for_free[pg_num];
		if (!IS_ALIGN(eq->dma_addr_for_free[pg_num],
			      eq->page_size)) {
			sdk_info(eq->hwdev->dev_hdl,
				 "Address is not aligned to %u-bytes as hardware required\n",
				 eq->page_size);
			sdk_info(eq->hwdev->dev_hdl, "Change eq's page size %u\n",
				 ((eq->page_size) >> 1));
			eq->dma_addr[pg_num] = ALIGN
					(eq->dma_addr_for_free[pg_num],
					(u64)((eq->page_size) >> 1));
			eq->virt_addr[pg_num] = eq->virt_addr_for_free[pg_num] +
				((u64)eq->dma_addr[pg_num]
				 - (u64)eq->dma_addr_for_free[pg_num]);
			flag = 1;
		}
		reg = HIFC_EQ_HI_PHYS_ADDR_REG(eq->type, eq->q_id, pg_num);
		hifc_hwif_write_reg(hwif, reg,
				    upper_32_bits(eq->dma_addr[pg_num]));

		reg = HIFC_EQ_LO_PHYS_ADDR_REG(eq->type, eq->q_id, pg_num);
		hifc_hwif_write_reg(hwif, reg,
				    lower_32_bits(eq->dma_addr[pg_num]));
	}

	if (flag) {
		eq->page_size = eq->page_size >> 1;
		eq->eq_len = eq->eq_len >> 1;
	}

	err = init_eq_elements(eq);
	if (err) {
		sdk_err(eq->hwdev->dev_hdl, "Failed to init eq elements\n");
		goto dma_alloc_err;
	}

	return 0;

dma_alloc_err:
	for (i = 0; i < pg_num; i++)
		dma_free_coherent(eq->hwdev->dev_hdl, eq->page_size,
				  eq->virt_addr_for_free[i],
				  eq->dma_addr_for_free[i]);
	free_eq_pages_desc(eq);
	return err;
}

/**
 * free_eq_pages - free the pages of the queue
 * @eq: the event queue
 **/
static void free_eq_pages(struct hifc_eq *eq)
{
	struct hifc_hwdev *hwdev = eq->hwdev;
	u16 pg_num;

	for (pg_num = 0; pg_num < eq->num_pages; pg_num++)
		dma_free_coherent(hwdev->dev_hdl, eq->orig_page_size,
				  eq->virt_addr_for_free[pg_num],
				  eq->dma_addr_for_free[pg_num]);

	free_eq_pages_desc(eq);
}

static inline u32 get_page_size(struct hifc_eq *eq)
{
	u32 total_size;
	u16 count, n = 0;

	total_size = ALIGN((eq->eq_len * eq->elem_size), EQ_MIN_PAGE_SIZE);

	if (total_size <= (HIFC_EQ_MAX_PAGES * EQ_MIN_PAGE_SIZE))
		return EQ_MIN_PAGE_SIZE;

	count = (u16)(ALIGN((total_size / HIFC_EQ_MAX_PAGES),
		      EQ_MIN_PAGE_SIZE) / EQ_MIN_PAGE_SIZE);

	if (!(count & (count - 1)))
		return EQ_MIN_PAGE_SIZE * count;

	while (count) {
		count >>= 1;
		n++;
	}

	return EQ_MIN_PAGE_SIZE << n;
}

static int request_eq_irq(struct hifc_eq *eq, enum hifc_eq_type type,
			  struct irq_info *entry)
{
	int err = 0;

	if (type == HIFC_AEQ) {
		struct hifc_eq_work *aeq_work = &eq->aeq_work;

		INIT_WORK(&aeq_work->work, eq_irq_work);
	} else {
		tasklet_init(&eq->ceq_tasklet, ceq_tasklet,
			     (ulong)(&eq->ceq_tasklet_data));
	}

	if (type == HIFC_AEQ) {
		snprintf(eq->irq_name, sizeof(eq->irq_name),
			 "hifc_aeq%d@pci:%s", eq->q_id,
			 pci_name(eq->hwdev->pcidev_hdl));

		err = request_irq(entry->irq_id, aeq_interrupt, 0UL,
				  eq->irq_name, eq);
	} else {
		snprintf(eq->irq_name, sizeof(eq->irq_name),
			 "hifc_ceq%d@pci:%s", eq->q_id,
			 pci_name(eq->hwdev->pcidev_hdl));

		err = request_irq(entry->irq_id, ceq_interrupt, 0UL,
				  eq->irq_name, eq);
	}

	return err;
}

/**
 * init_eq - initialize eq
 * @eq:	the event queue
 * @hwdev: the pointer to hw device
 * @q_id: Queue id number
 * @q_len: the number of EQ elements
 * @type: the type of the event queue, ceq or aeq
 * @entry: msix entry associated with the event queue
 * Return: 0 - Success, Negative - failure
 **/
static int init_eq(struct hifc_eq *eq, struct hifc_hwdev *hwdev, u16 q_id,
		   u32 q_len, enum hifc_eq_type type, struct irq_info *entry)
{
	int err = 0;

	eq->hwdev = hwdev;
	eq->q_id = q_id;
	eq->type = type;
	eq->eq_len = q_len;

	/* clear eq_len to force eqe drop in hardware */
	if (eq->type == HIFC_AEQ)
		hifc_hwif_write_reg(eq->hwdev->hwif,
				    HIFC_CSR_AEQ_CTRL_1_ADDR(eq->q_id), 0);
	else
		set_ceq_ctrl_reg(eq->hwdev, eq->q_id, 0, 0);

	eq->cons_idx = 0;
	eq->wrapped = 0;

	eq->elem_size = (type == HIFC_AEQ) ?
			HIFC_AEQE_SIZE : HIFC_CEQE_SIZE;

	eq->page_size = get_page_size(eq);
	eq->orig_page_size = eq->page_size;
	eq->num_pages = GET_EQ_NUM_PAGES(eq, eq->page_size);
	if (eq->num_pages > HIFC_EQ_MAX_PAGES) {
		sdk_err(hwdev->dev_hdl, "Number pages:%d too many pages for eq\n",
			eq->num_pages);
		return -EINVAL;
	}

	err = alloc_eq_pages(eq);
	if (err) {
		sdk_err(hwdev->dev_hdl, "Failed to allocate pages for eq\n");
		return err;
	}

	eq->eq_irq.msix_entry_idx = entry->msix_entry_idx;
	eq->eq_irq.irq_id = entry->irq_id;

	err = set_eq_ctrls(eq);
	if (err) {
		sdk_err(hwdev->dev_hdl, "Failed to allocate pages for eq\n");
		goto init_eq_ctrls_err;
	}

	hifc_hwif_write_reg(eq->hwdev->hwif, EQ_PROD_IDX_REG_ADDR(eq), 0);
	set_eq_cons_idx(eq, HIFC_EQ_ARMED);

	err = request_eq_irq(eq, type, entry);
	if (err) {
		sdk_err(hwdev->dev_hdl, "Failed to request irq for the eq, err: %d\n",
			err);
		goto req_irq_err;
	}

	hifc_set_msix_state(hwdev, entry->msix_entry_idx, HIFC_MSIX_ENABLE);

	return 0;

init_eq_ctrls_err:
req_irq_err:
	free_eq_pages(eq);
	return err;
}

/**
 * remove_eq - remove eq
 * @eq:	the event queue
 **/
static void remove_eq(struct hifc_eq *eq)
{
	struct irq_info *entry = &eq->eq_irq;

	hifc_set_msix_state(eq->hwdev, entry->msix_entry_idx,
			    HIFC_MSIX_DISABLE);
	synchronize_irq(entry->irq_id);

	free_irq(entry->irq_id, eq);

	if (eq->type == HIFC_AEQ) {
		struct hifc_eq_work *aeq_work = &eq->aeq_work;

		cancel_work_sync(&aeq_work->work);

		/* clear eq_len to avoid hw access host memory */
		hifc_hwif_write_reg(eq->hwdev->hwif,
				    HIFC_CSR_AEQ_CTRL_1_ADDR(eq->q_id), 0);
	} else {
		tasklet_kill(&eq->ceq_tasklet);

		set_ceq_ctrl_reg(eq->hwdev, eq->q_id, 0, 0);
	}

	/* update cons_idx to avoid invalid interrupt */
	eq->cons_idx = hifc_hwif_read_reg(eq->hwdev->hwif,
					   EQ_PROD_IDX_REG_ADDR(eq));
	set_eq_cons_idx(eq, HIFC_EQ_NOT_ARMED);

	free_eq_pages(eq);
}

/**
 * hifc_aeqs_init - init all the aeqs
 * @hwdev: the pointer to hw device
 * @num_ceqs: number of AEQs
 * @msix_entries: msix entries associated with the event queues
 * Return: 0 - Success, Negative - failure
 **/
int hifc_aeqs_init(struct hifc_hwdev *hwdev, u16 num_aeqs,
		   struct irq_info *msix_entries)
{
	struct hifc_aeqs *aeqs;
	int err;
	u16 i, q_id;

	aeqs = kzalloc(sizeof(*aeqs), GFP_KERNEL);
	if (!aeqs)
		return -ENOMEM;

	hwdev->aeqs = aeqs;
	aeqs->hwdev = hwdev;
	aeqs->num_aeqs = num_aeqs;

	aeqs->workq = create_singlethread_workqueue(HIFC_EQS_WQ_NAME);
	if (!aeqs->workq) {
		sdk_err(hwdev->dev_hdl, "Failed to initialize aeq workqueue\n");
		err = -ENOMEM;
		goto create_work_err;
	}

	if (g_aeq_len < HIFC_MIN_AEQ_LEN || g_aeq_len > HIFC_MAX_AEQ_LEN) {
		sdk_warn(hwdev->dev_hdl, "Module Parameter g_aeq_len value %d out of range, resetting to %d\n",
			 g_aeq_len, HIFC_DEFAULT_AEQ_LEN);
		g_aeq_len = HIFC_DEFAULT_AEQ_LEN;
	}

	for (q_id = 0; q_id < num_aeqs; q_id++) {
		err = init_eq(&aeqs->aeq[q_id], hwdev, q_id, g_aeq_len,
			      HIFC_AEQ, &msix_entries[q_id]);
		if (err) {
			sdk_err(hwdev->dev_hdl, "Failed to init aeq %d\n",
				q_id);
			goto init_aeq_err;
		}
	}

	return 0;

init_aeq_err:
	for (i = 0; i < q_id; i++)
		remove_eq(&aeqs->aeq[i]);

	destroy_workqueue(aeqs->workq);

create_work_err:
	kfree(aeqs);

	return err;
}

/**
 * hifc_aeqs_free - free all the aeqs
 * @hwdev: the pointer to hw device
 **/
void hifc_aeqs_free(struct hifc_hwdev *hwdev)
{
	struct hifc_aeqs *aeqs = hwdev->aeqs;
	enum hifc_aeq_type aeq_event = HIFC_HW_INTER_INT;
	enum hifc_aeq_sw_type sw_aeq_event = HIFC_STATELESS_EVENT;
	u16 q_id;

	for (q_id = 0; q_id < aeqs->num_aeqs; q_id++)
		remove_eq(&aeqs->aeq[q_id]);

	for (; sw_aeq_event < HIFC_MAX_AEQ_SW_EVENTS; sw_aeq_event++)
		hifc_aeq_unregister_swe_cb(hwdev, sw_aeq_event);

	for (; aeq_event < HIFC_MAX_AEQ_EVENTS; aeq_event++)
		hifc_aeq_unregister_hw_cb(hwdev, aeq_event);

	destroy_workqueue(aeqs->workq);

	kfree(aeqs);
}

/**
 * hifc_ceqs_init - init all the ceqs
 * @hwdev: the pointer to hw device
 * @num_ceqs: number of CEQs
 * @msix_entries: msix entries associated with the event queues
 * Return: 0 - Success, Negative - failure
 **/
int hifc_ceqs_init(struct hifc_hwdev *hwdev, u16 num_ceqs,
		   struct irq_info *msix_entries)
{
	struct hifc_ceqs *ceqs;
	int err;
	u16 i, q_id;

	ceqs = kzalloc(sizeof(*ceqs), GFP_KERNEL);
	if (!ceqs)
		return -ENOMEM;

	hwdev->ceqs = ceqs;

	ceqs->hwdev = hwdev;
	ceqs->num_ceqs = num_ceqs;

	if (g_ceq_len < HIFC_MIN_CEQ_LEN || g_ceq_len > HIFC_MAX_CEQ_LEN) {
		sdk_warn(hwdev->dev_hdl, "Module Parameter g_ceq_len value %d out of range, resetting to %d\n",
			 g_ceq_len, HIFC_DEFAULT_CEQ_LEN);
		g_ceq_len = HIFC_DEFAULT_CEQ_LEN;
	}

	if (!g_num_ceqe_in_tasklet) {
		sdk_warn(hwdev->dev_hdl, "Module Parameter g_num_ceqe_in_tasklet can not be zero, resetting to %d\n",
			 HIFC_TASK_PROCESS_EQE_LIMIT);
		g_num_ceqe_in_tasklet = HIFC_TASK_PROCESS_EQE_LIMIT;
	}

	for (q_id = 0; q_id < num_ceqs; q_id++) {
		err = init_eq(&ceqs->ceq[q_id], hwdev, q_id, g_ceq_len,
			      HIFC_CEQ, &msix_entries[q_id]);
		if (err) {
			sdk_err(hwdev->dev_hdl, "Failed to init ceq %d\n",
				q_id);
			goto init_ceq_err;
		}
	}

	return 0;

init_ceq_err:
	for (i = 0; i < q_id; i++)
		remove_eq(&ceqs->ceq[i]);

	kfree(ceqs);

	return err;
}

/**
 * hifc_ceqs_free - free all the ceqs
 * @hwdev: the pointer to hw device
 **/
void hifc_ceqs_free(struct hifc_hwdev *hwdev)
{
	struct hifc_ceqs *ceqs = hwdev->ceqs;
	enum hifc_ceq_event ceq_event = HIFC_CMDQ;
	u16 q_id;

	for (q_id = 0; q_id < ceqs->num_ceqs; q_id++)
		remove_eq(&ceqs->ceq[q_id]);

	for (; ceq_event < HIFC_MAX_CEQ_EVENTS; ceq_event++)
		hifc_ceq_unregister_cb(hwdev, ceq_event);

	kfree(ceqs);
}

void hifc_get_ceq_irqs(struct hifc_hwdev *hwdev, struct irq_info *irqs,
		       u16 *num_irqs)
{
	struct hifc_ceqs *ceqs = hwdev->ceqs;
	u16 q_id;

	for (q_id = 0; q_id < ceqs->num_ceqs; q_id++) {
		irqs[q_id].irq_id = ceqs->ceq[q_id].eq_irq.irq_id;
		irqs[q_id].msix_entry_idx =
			ceqs->ceq[q_id].eq_irq.msix_entry_idx;
	}

	*num_irqs = ceqs->num_ceqs;
}

void hifc_get_aeq_irqs(struct hifc_hwdev *hwdev, struct irq_info *irqs,
		       u16 *num_irqs)
{
	struct hifc_aeqs *aeqs = hwdev->aeqs;
	u16 q_id;

	for (q_id = 0; q_id < aeqs->num_aeqs; q_id++) {
		irqs[q_id].irq_id = aeqs->aeq[q_id].eq_irq.irq_id;
		irqs[q_id].msix_entry_idx =
			aeqs->aeq[q_id].eq_irq.msix_entry_idx;
	}

	*num_irqs = aeqs->num_aeqs;
}

void hifc_dump_aeq_info(struct hifc_hwdev *hwdev)
{
	struct hifc_aeq_elem *aeqe_pos;
	struct hifc_eq *eq;
	u32 addr, ci, pi;
	int q_id;

	for (q_id = 0; q_id < hwdev->aeqs->num_aeqs; q_id++) {
		eq = &hwdev->aeqs->aeq[q_id];
		addr = EQ_CONS_IDX_REG_ADDR(eq);
		ci = hifc_hwif_read_reg(hwdev->hwif, addr);
		addr = EQ_PROD_IDX_REG_ADDR(eq);
		pi = hifc_hwif_read_reg(hwdev->hwif, addr);
		aeqe_pos = GET_CURR_AEQ_ELEM(eq);
		sdk_err(hwdev->dev_hdl, "Aeq id: %d, ci: 0x%08x, pi: 0x%x, work_state: 0x%x, wrap: %d, desc: 0x%x\n",
			q_id, ci, pi, work_busy(&eq->aeq_work.work),
			eq->wrapped, be32_to_cpu(aeqe_pos->desc));
	}
}
