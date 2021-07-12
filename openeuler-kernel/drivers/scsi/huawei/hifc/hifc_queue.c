// SPDX-License-Identifier: GPL-2.0
/* Huawei Hifc PCI Express Linux driver
 * Copyright(c) 2017 Huawei Technologies Co., Ltd
 *
 */

#include "unf_log.h"
#include "unf_common.h"
#include "hifc_queue.h"
#include "hifc_module.h"
#include "hifc_wqe.h"
#include "hifc_service.h"
#include "hifc_chipitf.h"
#include "hifc_cqm_object.h"
#include "hifc_cqm_main.h"

#define HIFC_UCODE_CMD_MODIFY_QUEUE_CONTEXT 0

#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
#define HIFC_DONE_MASK (0x00000001)
#else
#define HIFC_DONE_MASK (0x01000000)
#endif
#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
#define HIFC_OWNER_MASK (0x80000000)
#else
#define HIFC_OWNER_MASK (0x00000080)
#endif
#define HIFC_SQ_LINK_PRE (1 << 2)

#define HIFC_SQ_HEADER_ADDR_ALIGN_SIZE      (64)
#define HIFC_SQ_HEADER_ADDR_ALIGN_SIZE_MASK (HIFC_SQ_HEADER_ADDR_ALIGN_SIZE - 1)

#define HIFC_ADDR_64_ALIGN(addr)\
	(((addr) + (HIFC_SQ_HEADER_ADDR_ALIGN_SIZE_MASK)) &\
	~(HIFC_SQ_HEADER_ADDR_ALIGN_SIZE_MASK))

static unsigned int hifc_get_parity_value(unsigned long long *v_src_data,
					  unsigned int v_row,
					  unsigned int v_column)
{
	unsigned int i = 0;
	unsigned int j = 0;
	unsigned int offset = 0;
	unsigned int group = 0;
	unsigned int bit_offset = 0;
	unsigned int bit_val = 0;
	unsigned int tmp_val = 0;
	unsigned int dest_data = 0;

	for (i = 0; i < v_row; i++) {
		for (j = 0; j < v_column; j++) {
			offset = (v_row * j + i);
			group = offset / (sizeof(v_src_data[0]) * 8);
			bit_offset = offset % (sizeof(v_src_data[0]) * 8);
			tmp_val = (v_src_data[group] >> bit_offset) & 0x1;

			if (j == 0) {
				bit_val = tmp_val;
				continue;
			}

			bit_val ^= tmp_val;
		}

		bit_val = (~bit_val) & 0x1;

		dest_data |= (bit_val << i);
	}

	return dest_data;
}

/**
 * hifc_update_producer_info - update producer pi and obit value
 * @q_depth: queue max depth
 * @v_pi: pi vaue after updated queue
 * @v_owner: owner vaue after updated queue
 */
static void hifc_update_producer_info(unsigned short q_depth,
				      unsigned short *v_pi,
				      unsigned short *v_owner)
{
	unsigned short cur_pi = 0;
	unsigned short next_pi = 0;
	unsigned short owner = 0;

	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE, v_pi, return);
	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE, v_owner, return);

	cur_pi = *v_pi;
	next_pi = cur_pi + 1;

	if (next_pi < q_depth) {
		*v_pi = next_pi;
	} else {
		/* PI reversal */
		*v_pi = 0;

		/* obit reversal */
		owner = *v_owner;
		*v_owner = !owner;
	}
}

/**
 * hifc_update_consumer_info - update consumer ci and obit value
 * @q_depth: queue max deppth
 * @v_ci: ci vaue after updated queue
 * @v_owner: owner vaue after updated queue
 */
static void hifc_update_consumer_info(unsigned short q_depth,
				      unsigned short *v_ci,
				      unsigned short *v_owner)
{
	unsigned short cur_ci = 0;
	unsigned short next_ci = 0;
	unsigned short owner = 0;

	cur_ci = *v_ci;
	next_ci = cur_ci + 1;

	if (next_ci < q_depth) {
		*v_ci = next_ci;
	} else {
		/* CI reversal */
		*v_ci = 0;

		/* obit reversal */
		owner = *v_owner;
		*v_owner = !owner;
	}
}

static inline void hifc_update_cq_header(struct hifc_ci_record_s *v_ci_record,
					 unsigned short ci,
					 unsigned short owner)
{
	unsigned int size = 0;
	struct hifc_ci_record_s ci_record = { 0 };

	size = sizeof(struct hifc_ci_record_s);
	memcpy(&ci_record, v_ci_record, size);
	hifc_big_to_cpu64(&ci_record, size);

	ci_record.cmsn = ci +
			(unsigned short)(owner << HIFC_CQ_HEADER_OWNER_SHIFT);
	ci_record.dump_cmsn = ci_record.cmsn;
	hifc_cpu_to_big64(&ci_record, size);

	wmb();
	memcpy(v_ci_record, &ci_record, size);
}

static void hifc_update_srq_header(struct hifc_db_record *v_pmsn_record,
				   unsigned short pmsn)
{
	unsigned int size = 0;
	struct hifc_db_record pmsn_record = { 0 };

	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE, v_pmsn_record, return);

	size = sizeof(struct hifc_db_record);
	memcpy(&pmsn_record, v_pmsn_record, size);
	hifc_big_to_cpu64(&pmsn_record, size);

	pmsn_record.pmsn = pmsn;
	pmsn_record.dump_pmsn = pmsn_record.pmsn;
	hifc_cpu_to_big64(&pmsn_record, sizeof(struct hifc_db_record));

	wmb();
	memcpy(v_pmsn_record, &pmsn_record, size);
}

static unsigned int hifc_alloc_root_sq_info(
					struct hifc_root_info_s *v_root_info)
{
	unsigned int sq_info_size = 0;
	struct hifc_root_sq_info_s *root_sq_info = NULL;

	sq_info_size = (unsigned int)
		(sizeof(struct hifc_root_sq_info_s) * v_root_info->sq_num);
	root_sq_info = (struct hifc_root_sq_info_s *)kmalloc(sq_info_size,
							     GFP_ATOMIC);
	if (!root_sq_info) {
		HIFC_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_REG_ATT, UNF_WARN,
			   "[err]Allocate Root SQ(s) failed");

		return UNF_RETURN_ERROR;
	}

	memset(root_sq_info, 0, sq_info_size);
	v_root_info->sq_info = root_sq_info;

	return RETURN_OK;
}

static void hifc_free_root_sq_info(struct hifc_root_info_s *v_root_info)
{
	unsigned int q_index;
	struct hifc_root_sq_info_s *sq_info = NULL;

	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE, NULL != v_root_info, return);

	for (q_index = 0; q_index < v_root_info->sq_num; q_index++) {
		sq_info = (struct hifc_root_sq_info_s *)(v_root_info->sq_info) +
			  q_index;
		UNF_REFERNCE_VAR(sq_info);
	}
	kfree(v_root_info->sq_info);
	v_root_info->sq_info = NULL;
}

static void hifc_init_root_sq_base_info(struct hifc_root_info_s *v_root_info)
{
	unsigned int q_index = 0;
	unsigned short global_base_qpn = 0;
	unsigned short max_sq_num = 0;
	struct hifc_root_sq_info_s *sq_info = NULL;
	struct hifc_hba_s *hba = NULL;

	hba = (struct hifc_hba_s *)v_root_info->phba;
	global_base_qpn = hifc_get_global_base_qpn(hba->hw_dev_handle);
	max_sq_num = hifc_func_max_qnum(hba->hw_dev_handle);

	for (q_index = 0; q_index < v_root_info->sq_num; q_index++) {
		sq_info = (struct hifc_root_sq_info_s *)(v_root_info->sq_info) +
			  q_index;
		sq_info->qid = (unsigned short)q_index;
		sq_info->max_qnum = max_sq_num;
		spin_lock_init(&sq_info->root_sq_spin_lock);
		sq_info->q_depth = HIFC_ROOT_SQ_DEPTH;
		sq_info->wqe_bb_size = HIFC_ROOT_SQ_WQEBB;
		sq_info->root_info = v_root_info;
		sq_info->global_qpn = global_base_qpn + q_index;
		sq_info->owner = HIFC_ROOT_SQ_LOOP_OWNER;
		sq_info->in_flush = UNF_FALSE;
	}
}

static unsigned int hifc_alloc_root_sq_ci_addr(
				struct hifc_root_info_s *v_root_info)
{
	unsigned int q_index = 0;
	unsigned int ci_addr_size = 0;
	unsigned int ci_addr_offset = 0;
	struct hifc_hba_s *hba = NULL;
	struct hifc_root_sq_info_s *sq_info = NULL;

	/* Alignment with 4 Bytes */
	ci_addr_size = HIFC_ROOT_SQ_CI_TABLE_STEP_BYTE * v_root_info->sq_num;
	hba = (struct hifc_hba_s *)v_root_info->phba;

	v_root_info->virt_sq_ci_table_buff = dma_alloc_coherent(
						&hba->pci_dev->dev,
						ci_addr_size,
						&v_root_info->sq_ci_table_dma,
						GFP_KERNEL);
	if (!v_root_info->virt_sq_ci_table_buff) {
		HIFC_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_REG_ATT, UNF_WARN,
			   "[err]Allocate Root SQ CI table failed");

		return UNF_RETURN_ERROR;
	}
	memset(v_root_info->virt_sq_ci_table_buff, 0, ci_addr_size);
	v_root_info->sq_ci_table_size = ci_addr_size;

	for (q_index = 0; q_index < v_root_info->sq_num; q_index++) {
		ci_addr_offset = q_index * HIFC_ROOT_SQ_CI_TABLE_STEP_BYTE;
		sq_info = (struct hifc_root_sq_info_s *)(v_root_info->sq_info) +
			  q_index;
		sq_info->ci_addr = (unsigned short *)
			((void *)
			(((unsigned char *)v_root_info->virt_sq_ci_table_buff) +
			ci_addr_offset));
		sq_info->ci_dma_addr = v_root_info->sq_ci_table_dma +
				       ci_addr_offset;
	}

	return RETURN_OK;
}

static void hifc_free_root_sq_ci_addr(struct hifc_root_info_s *v_root_info)
{
	unsigned int q_index = 0;
	struct hifc_root_info_s *root_info = NULL;
	struct hifc_hba_s *hba = NULL;
	struct hifc_root_sq_info_s *sq_info = NULL;

	root_info = v_root_info;
	hba = (struct hifc_hba_s *)root_info->phba;
	dma_free_coherent(&hba->pci_dev->dev, root_info->sq_ci_table_size,
			  root_info->virt_sq_ci_table_buff,
			  root_info->sq_ci_table_dma);
	root_info->virt_sq_ci_table_buff = NULL;
	root_info->sq_ci_table_dma = 0;

	for (q_index = 0; q_index < root_info->sq_num; q_index++) {
		sq_info = (struct hifc_root_sq_info_s *)(root_info->sq_info) +
			  q_index;
		sq_info->ci_addr = NULL;
		sq_info->ci_dma_addr = 0;
	}
}

static unsigned int hifc_alloc_root_sq_buff(
			struct hifc_root_info_s *v_root_info)
{
	int ret = 0;
	unsigned int q_index = 0;
	unsigned int back_q_num = 0;
	struct hifc_root_sq_info_s *sq_info = NULL;
	struct hifc_root_info_s *root_info = NULL;
	struct hifc_hba_s *hba = NULL;

	root_info = v_root_info;
	hba = (struct hifc_hba_s *)(root_info->phba);

	for (q_index = 0; q_index < root_info->sq_num; q_index++) {
		sq_info = (struct hifc_root_sq_info_s *)(root_info->sq_info) +
			  q_index;

		/* Wqe_Base_Size:64; Depth:2048; Page_Size:4096 */
		ret = hifc_slq_alloc(hba->hw_dev_handle, sq_info->wqe_bb_size,
				     sq_info->q_depth, (u16)PAGE_SIZE,
				     (u64 *)&sq_info->cla_addr,
				     &sq_info->sq_handle);
		if ((ret != 0) || (!sq_info->sq_handle) ||
		    (sq_info->cla_addr == 0)) {
			HIFC_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_REG_ATT,
				   UNF_WARN,
				   "[err]Port(0x%x) slq_allocate Root SQ WQE buffer failed, SQ index = %u, return %u",
				   hba->port_cfg.port_id, q_index, ret);

			goto free_sq_wqe_buff;
		}
	}

	return RETURN_OK;

free_sq_wqe_buff:
	back_q_num = q_index;

	for (q_index = 0; q_index < back_q_num; q_index++) {
		sq_info = (struct hifc_root_sq_info_s *)(root_info->sq_info) +
			  q_index;
		hifc_slq_free(hba->hw_dev_handle, sq_info->sq_handle);
		sq_info->sq_handle = NULL;
		sq_info->cla_addr = 0;
	}

	return UNF_RETURN_ERROR;
}

static void hifc_free_root_sq_buff(struct hifc_root_info_s *v_root_info)
{
	unsigned int q_index = 0;
	struct hifc_root_sq_info_s *sq_info = NULL;
	struct hifc_root_info_s *root_info = NULL;
	struct hifc_hba_s *hba = NULL;

	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE, NULL != v_root_info, return);

	root_info = v_root_info;
	hba = (struct hifc_hba_s *)(root_info->phba);

	for (q_index = 0; q_index < root_info->sq_num; q_index++) {
		sq_info = (struct hifc_root_sq_info_s *)(root_info->sq_info) +
			  q_index;
		hifc_slq_free(hba->hw_dev_handle, sq_info->sq_handle);
		sq_info->sq_handle = NULL;
		sq_info->cla_addr = 0;
	}
}

irqreturn_t hifc_root_sq_irq(int v_irq, void *v_sq_info)
{
	struct hifc_root_sq_info_s *sq_info = NULL;
	unsigned short cur_ci = 0;
	static unsigned int enter_num;

	enter_num++;
	sq_info = (struct hifc_root_sq_info_s *)v_sq_info;

	cur_ci = *sq_info->ci_addr;
	cur_ci = be16_to_cpu(cur_ci);

	HIFC_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_REG_ATT, UNF_INFO,
		   "[event]Root SQ Irq Enter Num is %u, Root SQ Ci is %u",
		   enter_num, cur_ci);
	HIFC_REFERNCE_VAR(enter_num, INVALID_VALUE32, IRQ_HANDLED)
	HIFC_REFERNCE_VAR(cur_ci, INVALID_VALUE16, IRQ_HANDLED)

	return IRQ_HANDLED;
}

/*
 * hifc_alloc_root_sq_int - Allocate interrupt resources in Root SQ, and
 *                          register callback function.
 * @v_root_info: root sq struct info
 * @Return: 0 - success, negative - failure
 */
static unsigned int hifc_alloc_root_sq_int(struct hifc_root_info_s *v_root_info)
{
	int ret = UNF_RETURN_ERROR_S32;
	unsigned int q_index = 0;
	unsigned int cfg_num = 0;
	unsigned short act_num = 0;
	struct irq_info irq_info;
	struct hifc_root_sq_info_s *sq_info = NULL;
	struct hifc_root_info_s *root_info = NULL;
	struct hifc_hba_s *hba = NULL;

	root_info = v_root_info;
	hba = (struct hifc_hba_s *)(root_info->phba);

	for (q_index = 0; q_index < root_info->sq_num; q_index++) {
		ret = hifc_alloc_irqs(hba->hw_dev_handle, SERVICE_T_FC,
				      HIFC_INT_NUM_PER_QUEUE, &irq_info,
				      &act_num);
		if ((ret != RETURN_OK) ||
		    (act_num != HIFC_INT_NUM_PER_QUEUE)) {
			HIFC_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_REG_ATT,
				   UNF_WARN,
				   "[err]cfg_alloc_irqs Root SQ irq failed, SQ Index = 0x%x, return 0x%x",
				   q_index, ret);

			goto free_irq;
		}

		if (irq_info.msix_entry_idx >= HIFC_ROOT_Q_INT_ID_MAX) {
			HIFC_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_REG_ATT,
				   UNF_ERR,
				   "[err]cfg_alloc_irqs Root SQ irq id exceed 1024, msix_entry_idx 0x%x",
				   irq_info.msix_entry_idx);

			hifc_free_irq(hba->hw_dev_handle, SERVICE_T_FC,
				      irq_info.irq_id);
			goto free_irq;
		}

		sq_info = (struct hifc_root_sq_info_s *)(root_info->sq_info) +
			   q_index;
		sq_info->irq_id = (unsigned int)(irq_info.irq_id);
		sq_info->msix_entry_idx = (unsigned short)
					  (irq_info.msix_entry_idx);

		ret = snprintf(sq_info->irq_name, HIFC_IRQ_NAME_MAX - 1,
			       "Root SQ 0x%x", q_index);
		UNF_FUNCTION_RETURN_CHECK(ret, HIFC_IRQ_NAME_MAX - 1);
		ret = request_irq(sq_info->irq_id, hifc_root_sq_irq, 0UL,
				  sq_info->irq_name, sq_info);
		hifc_set_msix_state(hba->hw_dev_handle, sq_info->msix_entry_idx,
				    HIFC_MSIX_ENABLE);
		if (ret != RETURN_OK) {
			HIFC_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_REG_ATT,
				   UNF_WARN,
				   "[err]UNF_OS_REQUEST_IRQ Root SQ irq failed, SQ Index = 0x%x, return 0x%x",
				   q_index, ret);

			hifc_free_irq(hba->hw_dev_handle, SERVICE_T_FC,
				      sq_info->irq_id);
			sq_info->irq_id = 0;
			sq_info->msix_entry_idx = 0;
			goto free_irq;
		}
	}

	return RETURN_OK;

free_irq:
	cfg_num = q_index;

	for (q_index = 0; q_index < cfg_num; q_index++) {
		sq_info = (struct hifc_root_sq_info_s *)(root_info->sq_info) +
			  q_index;

		free_irq(sq_info->irq_id, sq_info);
		hifc_free_irq(hba->hw_dev_handle, SERVICE_T_FC,
			      sq_info->irq_id);
		sq_info->irq_id = 0;
		sq_info->msix_entry_idx = 0;
	}

	return UNF_RETURN_ERROR;
}

static void hifc_free_root_sq_int(struct hifc_root_info_s *v_root_info)
{
	unsigned int q_index = 0;
	struct hifc_root_sq_info_s *sq_info = NULL;
	struct hifc_root_info_s *root_info = NULL;
	struct hifc_hba_s *hba = NULL;

	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE, NULL != v_root_info, return);

	root_info = v_root_info;
	hba = (struct hifc_hba_s *)(root_info->phba);

	for (q_index = 0; q_index < root_info->sq_num; q_index++) {
		sq_info = (struct hifc_root_sq_info_s *)(root_info->sq_info) +
			  q_index;
		hifc_set_msix_state(hba->hw_dev_handle, sq_info->msix_entry_idx,
				    HIFC_MSIX_DISABLE);
		free_irq(sq_info->irq_id, sq_info);
		hifc_free_irq(hba->hw_dev_handle, SERVICE_T_FC,
			      sq_info->irq_id);
		sq_info->irq_id = 0;
		sq_info->msix_entry_idx = 0;
	}
}

/*
 * hifc_cfg_root_sq_ci_tbl - Configure CI address in SQ and interrupt number.
 * @v_root_info:  root queue info
 * @Return: 0 - success, negative - failure
 */
static unsigned int hifc_cfg_root_sq_ci_tbl(
				   struct hifc_root_info_s *v_root_info)
{
	int ret = 0;
	unsigned int queue_index = 0;
	dma_addr_t ci_dma_addr = 0;
	struct hifc_sq_attr sq_ci_attr;
	struct hifc_root_sq_info_s *sq_info = NULL;
	void *handle = NULL;

	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE, v_root_info,
			return UNF_RETURN_ERROR);

	handle = ((struct hifc_hba_s *)v_root_info->phba)->hw_dev_handle;

	for (queue_index = 0; queue_index < v_root_info->sq_num;
	     queue_index++) {
		/* Sync CI addr to hw, cfg attribute table format */
		memset(&sq_ci_attr, 0, sizeof(struct hifc_sq_attr));
		sq_info = (struct hifc_root_sq_info_s *)v_root_info->sq_info +
			  queue_index;

		sq_ci_attr.dma_attr_off = 0;
		sq_ci_attr.pending_limit = 0;
		sq_ci_attr.coalescing_time = 0;
		sq_ci_attr.intr_en = HIFC_INT_ENABLE;
		sq_ci_attr.intr_idx = sq_info->msix_entry_idx;
		sq_ci_attr.l2nic_sqn = queue_index;
		ci_dma_addr = HIFC_GET_ROOT_SQ_CI_ADDR(sq_info->ci_dma_addr,
						       queue_index);
		sq_ci_attr.ci_dma_base = ci_dma_addr >>
					HIFC_ROOT_SQ_CI_ATTRIBUTE_ADDRESS_SHIFT;

		/* Little endian used in UP */
		ret = hifc_set_ci_table(handle, sq_info->qid, &sq_ci_attr);
		if (ret != 0) {
			HIFC_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_REG_ATT,
				   UNF_ERR,
				   "[err]hifc_set_ci_table failed, return %d",
				   ret);

			return UNF_RETURN_ERROR;
		}
	}

	return RETURN_OK;
}

/**
 * hifc_alloc_root_sq_db - Allocate Doorbell buffer in root SQ
 * @v_root_info: root queue struct info
 * @Return: 0 - success, negative - failure
 */
static unsigned int hifc_alloc_root_sq_db(struct hifc_root_info_s *v_root_info)
{
	int ret = UNF_RETURN_ERROR_S32;
	unsigned int q_index = 0;
	unsigned int cfg_num = 0;
	struct hifc_root_sq_info_s *sq_info = NULL;
	struct hifc_root_info_s *root_info = NULL;
	struct hifc_hba_s *hba = NULL;

	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE, v_root_info,
			return UNF_RETURN_ERROR);

	root_info = v_root_info;
	hba = (struct hifc_hba_s *)(root_info->phba);

	for (q_index = 0; q_index < root_info->sq_num; q_index++) {
		sq_info = (struct hifc_root_sq_info_s *)(root_info->sq_info) +
			  q_index;

		ret = hifc_alloc_db_addr(hba->hw_dev_handle,
					 &sq_info->normal_db.virt_map_addr,
					 NULL);
		if (ret != RETURN_OK) {
			HIFC_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_REG_ATT,
				   UNF_WARN,
				   "[err]Allocate Root SQ DB address failed, SQ Index = %u, return %d",
				   q_index, ret);

			goto free_buff;
		}

		if (!sq_info->normal_db.virt_map_addr) {
			HIFC_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_REG_ATT,
				   UNF_WARN,
				   "[err]virt_map_addr is invalid, SQ Index = %u",
				   q_index);

			goto free_buff;
		}
	}

	return RETURN_OK;

free_buff:
	cfg_num = q_index;

	for (q_index = 0; q_index < cfg_num; q_index++) {
		sq_info = (struct hifc_root_sq_info_s *)(root_info->sq_info) +
			  q_index;

		hifc_free_db_addr(hba->hw_dev_handle,
				  sq_info->normal_db.virt_map_addr, NULL);
		sq_info->normal_db.virt_map_addr = NULL;
		sq_info->normal_db.phy_addr = 0;
	}

	return UNF_RETURN_ERROR;
}

static void hifc_afree_root_sq_db(struct hifc_root_info_s *v_root_info)
{
	unsigned int q_index = 0;
	struct hifc_root_sq_info_s *sq_info = NULL;
	struct hifc_root_info_s *root_info = NULL;
	struct hifc_hba_s *hba = NULL;

	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE, NULL != v_root_info, return);

	root_info = v_root_info;
	hba = (struct hifc_hba_s *)(root_info->phba);

	for (q_index = 0; q_index < root_info->sq_num; q_index++) {
		sq_info = (struct hifc_root_sq_info_s *)(root_info->sq_info) +
			  q_index;

		hifc_free_db_addr(hba->hw_dev_handle,
				  sq_info->normal_db.virt_map_addr, NULL);
		sq_info->normal_db.virt_map_addr = NULL;

		sq_info->normal_db.phy_addr = 0;
	}
}

static void hifc_assemble_root_sq_ctx(unsigned int cmd_sq_num,
				      struct hifc_root_sq_info_s *v_sq_info,
				      void *v_buf)
{
	unsigned int q_index = 0;
	unsigned long long ci_init_addr = 0;
	struct hifc_root_sq_info_s *sq_info = NULL;

	struct hifc_qp_ctxt_header *cmdq_header = NULL;
	struct hifc_sq_ctxt *sq_ctx = NULL;
	struct hifc_sq_ctxt_block *sq_ctx_block = NULL;

	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE, v_sq_info, return);
	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE, v_buf, return);

	sq_info = v_sq_info;
	sq_ctx_block = (struct hifc_sq_ctxt_block *)v_buf;
	cmdq_header = &sq_ctx_block->cmdq_hdr;

	/* CMD header initialization */
	cmdq_header->num_queues = (unsigned short)cmd_sq_num;
	cmdq_header->queue_type = HIFC_CMDQ_QUEUE_TYPE_SQ;
	cmdq_header->addr_offset = HIFC_ROOT_SQ_CTX_OFFSET(sq_info->max_qnum,
							   sq_info->qid);

	/* CMD Header convert to big endian */
	hifc_cpu_to_big32(cmdq_header, sizeof(struct hifc_qp_ctxt_header));

	for (q_index = 0; q_index < cmd_sq_num; q_index++) {
		sq_info = v_sq_info + q_index;
		sq_ctx = &sq_ctx_block->sq_ctx[q_index];
		memset(sq_ctx, 0, sizeof(struct hifc_sq_ctxt));

		sq_ctx->sq_ctx_dw0.global_sq_id = sq_info->global_qpn;
		sq_ctx->sq_ctx_dw0.ceq_num = 0;
		sq_ctx->sq_ctx_dw1.owner = HIFC_ROOT_SQ_LOOP_OWNER;

		ci_init_addr = hifc_slq_get_first_pageaddr(sq_info->sq_handle);

		sq_ctx->sq_ctx_dw2.ci_wqe_page_addr_hi =
				   HIFC_CI_WQE_PAGE_HIGH_ADDR(ci_init_addr);
		sq_ctx->ci_wqe_page_addr_lo =
				   HIFC_CI_WQE_PAGE_LOW_ADDR(ci_init_addr);
		sq_ctx->sq_ctx_dw4.prefetch_min =
				   HIFC_ROOT_CTX_WQE_PREFETCH_MIN;
		sq_ctx->sq_ctx_dw4.prefetch_max =
				   HIFC_ROOT_CTX_WQE_PREFETCH_MAX;
		sq_ctx->sq_ctx_dw4.prefetch_cache_threshold =
				   HIFC_ROOT_CTX_WQE_PRERETCH_THRESHOLD;
		sq_ctx->sq_ctx_dw5.prefetch_owner = HIFC_ROOT_SQ_LOOP_OWNER;
		sq_ctx->sq_ctx_dw6.prefetch_ci_wqe_addr_hi =
				   HIFC_CI_WQE_PAGE_HIGH_ADDR(ci_init_addr);
		sq_ctx->prefetch_ci_wqe_addr_lo =
				   HIFC_CI_WQE_PAGE_LOW_ADDR(ci_init_addr);
		sq_ctx->sq_ctx_dw10.cla_addr_hi =
				   HIFC_CLA_HIGH_ADDR(sq_info->cla_addr);
		sq_ctx->cla_addr_lo = HIFC_CLA_LOW_ADDR(sq_info->cla_addr);

		/* big-little endian convert */
		hifc_cpu_to_big32(sq_ctx, sizeof(struct hifc_sq_ctxt));
	}
}

static unsigned int hifc_cfg_root_sq_ctx(unsigned int cmd_sq_num,
					 void *v_handle,
					 struct hifc_cmd_buf *v_chipif_cmd_buff)
{
	int ret = 0;
	unsigned short buff_used_size = 0;
	unsigned int time_out = 0xF0000000;
	unsigned long long uc_return = 0;

	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE, v_handle,
			return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE, v_chipif_cmd_buff,
			return UNF_RETURN_ERROR);

	UNF_REFERNCE_VAR(uc_return);
	UNF_REFERNCE_VAR(time_out);
	UNF_REFERNCE_VAR(ret);

	buff_used_size = (unsigned short)(sizeof(struct hifc_qp_ctxt_header) +
			 sizeof(struct hifc_sq_ctxt) * cmd_sq_num);
	v_chipif_cmd_buff->size = buff_used_size;

	ret = hifc_cmdq_direct_resp(v_handle,
				    HIFC_ACK_TYPE_CMDQ,
				    HIFC_MOD_L2NIC,
				    HIFC_UCODE_CMD_MODIFY_QUEUE_CONTEXT,
				    v_chipif_cmd_buff,
				    (u64 *)&uc_return,
				    time_out);
	if ((ret != RETURN_OK) || (uc_return != RETURN_OK)) {
		HIFC_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_REG_ATT, UNF_ERR,
			   "[err]chipif_cmd_to_ucode_imm failed, uiret %d, ullUcRet %llu",
			   ret, uc_return);

		return UNF_RETURN_ERROR;
	}

	return RETURN_OK;
}

static unsigned int hifc_calc_cmd_sq_num(unsigned int remain_sq_num)
{
	unsigned int sq_num = 0;

	if (remain_sq_num < HIFC_ROOT_CFG_SQ_NUM_MAX)
		sq_num = remain_sq_num;
	else
		sq_num = HIFC_ROOT_CFG_SQ_NUM_MAX;

	return sq_num;
}

static unsigned int hifc_init_root_sq_ctx(struct hifc_root_info_s *v_root_info)
{
	unsigned int ret = UNF_RETURN_ERROR;
	unsigned int cmd_sq_num = 0;
	unsigned int remain_sq_num = 0;
	struct hifc_hba_s *hba = NULL;
	struct hifc_root_sq_info_s *sq_info = NULL;
	struct hifc_root_info_s *root_info = NULL;
	struct hifc_cmd_buf *chipif_cmd_buf = NULL;

	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE, v_root_info,
			return UNF_RETURN_ERROR);

	root_info = v_root_info;
	hba = (struct hifc_hba_s *)root_info->phba;
	sq_info = (struct hifc_root_sq_info_s *)(root_info->sq_info);

	chipif_cmd_buf = hifc_alloc_cmd_buf(hba->hw_dev_handle);
	if (!chipif_cmd_buf) {
		HIFC_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_REG_ATT, UNF_WARN,
			   "[err]hifc_alloc_cmd_buf failed.");

		return ENOMEM;
	}

	remain_sq_num = root_info->sq_num;
	while (remain_sq_num > 0) {
		cmd_sq_num = hifc_calc_cmd_sq_num(remain_sq_num);
		remain_sq_num -= cmd_sq_num;

		/* Assemble root SQ context */
		hifc_assemble_root_sq_ctx(cmd_sq_num, sq_info,
					  chipif_cmd_buf->buf);

		/* Send via ucode */
		ret = hifc_cfg_root_sq_ctx(cmd_sq_num, hba->hw_dev_handle,
					   chipif_cmd_buf);
		if (ret != RETURN_OK) {
			HIFC_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_REG_ATT,
				   UNF_ERR,
				   "[err]hifc_cfg_root_sq_ctx failed, return %u",
				   ret);
			break;
		}

		sq_info = sq_info + cmd_sq_num;
	}

	/* Release cmd buffer */
	hifc_free_cmd_buf(hba->hw_dev_handle, chipif_cmd_buf);
	return ret;
}

static unsigned int hifc_create_root_sqs(struct hifc_root_info_s *v_root_info)
{
	unsigned int ret = UNF_RETURN_ERROR;
	/* 1. Allocate sqinfo */
	ret = hifc_alloc_root_sq_info(v_root_info);
	if (ret != RETURN_OK) {
		HIFC_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_REG_ATT, UNF_WARN,
			   "[warn]hifc_alloc_root_sq_info failed, return %u",
			   ret);

		return ret;
	}

	/* 2. Initialize sqinfo */
	hifc_init_root_sq_base_info(v_root_info);

	/* 3. Apply SQ CI address */
	ret = hifc_alloc_root_sq_ci_addr(v_root_info);
	if (ret != RETURN_OK) {
		HIFC_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_REG_ATT, UNF_WARN,
			   "[warn]hifc_alloc_root_sq_ci_addr failed, return %u",
			   ret);

		goto free_sq_info;
	}

	/* 4. Allocate SQ buffer */
	ret = hifc_alloc_root_sq_buff(v_root_info);
	if (ret != RETURN_OK) {
		HIFC_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_REG_ATT, UNF_WARN,
			   "[warn]hifc_alloc_root_sq_buff failed, return %u",
			   ret);

		goto free_sq_ci_addr;
	}

	/* 5. Register SQ(s) interrupt */
	ret = hifc_alloc_root_sq_int(v_root_info);
	if (ret != RETURN_OK) {
		HIFC_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_REG_ATT, UNF_WARN,
			   "[warn]hifc_alloc_root_sq_int failed, return %u",
			   ret);

		goto free_root_sq_buff;
	}

	/* 6. Configure CI address in SQ and interrupt number */
	ret = hifc_cfg_root_sq_ci_tbl(v_root_info);
	if (ret != RETURN_OK) {
		HIFC_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_REG_ATT, UNF_ERR,
			   "[warn]hifc_cfg_root_sq_ci_tbl failed, return %u",
			   ret);

		goto free_root_sq_int;
	}

	/* 7. Allocate Doorbell buffer */
	ret = hifc_alloc_root_sq_db(v_root_info);
	if (ret != RETURN_OK) {
		HIFC_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_REG_ATT, UNF_WARN,
			   "[warn]hifc_alloc_root_sq_db failed, return %u",
			   ret);

		goto free_root_sq_int;
	}

	/* 8. Initialize SQ context */
	ret = hifc_init_root_sq_ctx(v_root_info);
	if (ret != RETURN_OK) {
		HIFC_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_REG_ATT, UNF_ERR,
			   "[warn]hifc_init_root_sq_ctx failed, return %u",
			   ret);

		goto free_db;
	}

	return RETURN_OK;

free_db:
	hifc_afree_root_sq_db(v_root_info);

free_root_sq_int:
	hifc_free_root_sq_int(v_root_info);

free_root_sq_buff:
	hifc_free_root_sq_buff(v_root_info);

free_sq_ci_addr:
	hifc_free_root_sq_ci_addr(v_root_info);

free_sq_info:
	hifc_free_root_sq_info(v_root_info);

	return ret;
}

static void hifc_destroy_root_sqs(struct hifc_root_info_s *v_root_info)
{
	/* Free DB resources */
	hifc_afree_root_sq_db(v_root_info);

	/* Free interrupt resources */
	hifc_free_root_sq_int(v_root_info);

	/* Free WQE buffers */
	hifc_free_root_sq_buff(v_root_info);

	/* Free CI address */
	hifc_free_root_sq_ci_addr(v_root_info);

	/* Free Root SQ struct */
	hifc_free_root_sq_info(v_root_info);
}

static unsigned int hifc_alloc_root_rq_info(
			struct hifc_root_info_s *v_root_info)
{
	unsigned int rq_info_size = 0;
	struct hifc_root_rq_info_s *root_rq_info = NULL;

	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE, v_root_info,
			return UNF_RETURN_ERROR);

	rq_info_size = (unsigned int)
		       (sizeof(struct hifc_root_rq_info_s) *
		       v_root_info->rq_num);
	root_rq_info = (struct hifc_root_rq_info_s *)kmalloc(rq_info_size,
							     GFP_ATOMIC);
	if (!root_rq_info) {
		HIFC_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_REG_ATT, UNF_WARN,
			   "[warn]Allocate Root RQ(s) failed");

		return UNF_RETURN_ERROR;
	}
	memset(root_rq_info, 0, rq_info_size);

	v_root_info->rq_info = root_rq_info;

	return RETURN_OK;
}

static void hifc_free_root_rq_info(struct hifc_root_info_s *v_root_info)
{
	struct hifc_root_info_s *root_info = NULL;

	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE, NULL != v_root_info, return);

	root_info = v_root_info;
	kfree(root_info->rq_info);
	root_info->rq_info = NULL;
}

static void hifc_init_root_rq_basic_info(struct hifc_root_info_s *v_root_info)
{
	unsigned int q_index = 0;
	unsigned short global_base_qpn = 0;
	unsigned short max_q_num = 0;
	struct hifc_root_rq_info_s *rq_info = NULL;
	struct hifc_hba_s *hba = NULL;

	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE, NULL != v_root_info, return);

	hba = (struct hifc_hba_s *)v_root_info->phba;
	global_base_qpn = hifc_get_global_base_qpn(hba->hw_dev_handle);
	max_q_num = hifc_func_max_qnum(hba->hw_dev_handle);

	for (q_index = 0; q_index < v_root_info->rq_num; q_index++) {
		rq_info = (struct hifc_root_rq_info_s *)(v_root_info->rq_info) +
			  q_index;
		rq_info->max_qnum = max_q_num;
		rq_info->qid = (unsigned short)q_index;
		rq_info->q_depth = HIFC_ROOT_RQ_DEPTH;
		rq_info->wqe_bb_size = HIFC_ROOT_RQ_WQEBB;
		rq_info->root_info = v_root_info;
		rq_info->global_qpn = global_base_qpn + q_index;
		rq_info->owner = HIFC_ROOT_RQ_LOOP_OWNER;
	}
}

static unsigned int hifc_alloc_root_rq_pi_addr(
				struct hifc_root_info_s *v_root_info)
{
	unsigned int q_index = 0;
	unsigned int pi_addr_size = 0;
	unsigned int pi_addr_offset = 0;
	struct hifc_hba_s *hba = NULL;
	struct hifc_root_rq_info_s *rq_info = NULL;

	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE, v_root_info,
			return UNF_RETURN_ERROR);

	pi_addr_size = HIFC_ROOT_RQ_PI_TABLE_STEP_BYTE * v_root_info->rq_num;
	hba = (struct hifc_hba_s *)v_root_info->phba;

	v_root_info->virt_rq_pi_table_buff =
			dma_alloc_coherent(&hba->pci_dev->dev, pi_addr_size,
					   &v_root_info->rq_pi_table_dma,
					   GFP_KERNEL);
	if (!v_root_info->virt_rq_pi_table_buff) {
		HIFC_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_REG_ATT, UNF_WARN,
			   "[warn]Allocate Root RQ PI table failed");

		return UNF_RETURN_ERROR;
	}
	memset(v_root_info->virt_rq_pi_table_buff, 0, pi_addr_size);
	v_root_info->rq_pi_table_size = pi_addr_size;

	for (q_index = 0; q_index < v_root_info->rq_num; q_index++) {
		pi_addr_offset = q_index * HIFC_ROOT_RQ_PI_TABLE_STEP_BYTE;
		rq_info = (struct hifc_root_rq_info_s *)(v_root_info->rq_info) +
			  q_index;
		rq_info->pi_vir_addr =
		   (unsigned short *)
		   ((unsigned long long)v_root_info->virt_rq_pi_table_buff +
		   pi_addr_offset);
		rq_info->pi_dma_addr = v_root_info->rq_pi_table_dma +
				       pi_addr_offset;
	}

	return RETURN_OK;
}

static void hifc_free_root_rq_pi_addr(struct hifc_root_info_s *v_root_info)
{
	unsigned int q_index = 0;
	struct hifc_root_info_s *root_info = NULL;
	struct hifc_hba_s *hba = NULL;
	struct hifc_root_rq_info_s *rq_info = NULL;

	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE, v_root_info, return);

	root_info = v_root_info;
	hba = (struct hifc_hba_s *)root_info->phba;
	dma_free_coherent(&hba->pci_dev->dev, root_info->rq_pi_table_size,
			  root_info->virt_rq_pi_table_buff,
			  root_info->rq_pi_table_dma);
	root_info->virt_rq_pi_table_buff = NULL;
	root_info->rq_pi_table_dma = 0;

	for (q_index = 0; q_index < root_info->rq_num; q_index++) {
		rq_info = (struct hifc_root_rq_info_s *)(root_info->rq_info) +
			  q_index;
		rq_info->pi_vir_addr = NULL;
		rq_info->pi_dma_addr = 0;
	}
}

static unsigned int hifc_alloc_root_rq_buff(
				struct hifc_root_info_s *v_root_info)
{
	int ret = 0;
	unsigned int q_index = 0;
	unsigned int back_q_num = 0;
	struct hifc_root_rq_info_s *rq_info = NULL;
	struct hifc_hba_s *hba = NULL;

	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE, v_root_info,
			return UNF_RETURN_ERROR);

	hba = (struct hifc_hba_s *)(v_root_info->phba);

	for (q_index = 0; q_index < v_root_info->rq_num; q_index++) {
		rq_info = (struct hifc_root_rq_info_s *)(v_root_info->rq_info) +
			  q_index;

		/* Wqe_Base_Size:32; Depth:2048; Page_Size:4096 */
		ret = hifc_slq_alloc(hba->hw_dev_handle, rq_info->wqe_bb_size,
				     rq_info->q_depth, (u16)PAGE_SIZE,
				     (u64 *)&rq_info->ci_cla_tbl_addr,
				     &rq_info->rq_handle);
		if ((ret != 0) || (!rq_info->rq_handle) ||
		    (rq_info->ci_cla_tbl_addr == 0)) {
			HIFC_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_REG_ATT,
				   UNF_WARN,
				   "[warn]slq_allocate Root RQ Buffer failed, RQ Index = %u, return %u",
				   q_index, ret);

			goto free_rq_buff;
		}
	}

	return RETURN_OK;

free_rq_buff:
	back_q_num = q_index;

	for (q_index = 0; q_index < back_q_num; q_index++) {
		rq_info = (struct hifc_root_rq_info_s *)(v_root_info->rq_info) +
			  q_index;
		hifc_slq_free(hba->hw_dev_handle, rq_info->rq_handle);
		rq_info->rq_handle = NULL;
		rq_info->ci_cla_tbl_addr = 0;
	}

	return UNF_RETURN_ERROR;
}

static void hifc_free_root_rq_buff(struct hifc_root_info_s *v_root_info)
{
	unsigned int q_index = 0;
	struct hifc_root_rq_info_s *rq_info = NULL;
	struct hifc_root_info_s *root_info = NULL;
	struct hifc_hba_s *hba = NULL;

	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE, NULL != v_root_info, return);

	root_info = v_root_info;
	hba = (struct hifc_hba_s *)(root_info->phba);

	for (q_index = 0; q_index < root_info->rq_num; q_index++) {
		rq_info = (struct hifc_root_rq_info_s *)(root_info->rq_info) +
			  q_index;
		hifc_slq_free(hba->hw_dev_handle, rq_info->rq_handle);
		rq_info->rq_handle = NULL;
		rq_info->ci_cla_tbl_addr = 0;
	}
}

irqreturn_t hifc_root_rq_irq(int v_irq, void *v_rq_info)
{
	HIFC_CHECK(INVALID_VALUE32, NULL != v_rq_info, return IRQ_NONE);

	tasklet_schedule(&((struct hifc_root_rq_info_s *)v_rq_info)->tasklet);

	return IRQ_HANDLED;
}

static unsigned int hifc_alloc_root_rq_int(struct hifc_root_info_s *v_root_info)
{
	int ret = UNF_RETURN_ERROR_S32;
	unsigned int q_index = 0;
	unsigned int cfg_num = 0;
	unsigned short act_num = 0;
	struct irq_info irq_info;
	struct hifc_root_rq_info_s *rq_info = NULL;
	struct hifc_hba_s *hba = NULL;

	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE, v_root_info,
			return UNF_RETURN_ERROR);

	hba = (struct hifc_hba_s *)(v_root_info->phba);

	for (q_index = 0; q_index < v_root_info->rq_num; q_index++) {
		ret = hifc_alloc_irqs(hba->hw_dev_handle, SERVICE_T_FC,
				      HIFC_INT_NUM_PER_QUEUE, &irq_info,
				      &act_num);
		if ((ret != RETURN_OK) || (act_num != HIFC_INT_NUM_PER_QUEUE)) {
			HIFC_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_REG_ATT,
				   UNF_WARN,
				   "[warn]cfg_alloc_irqs Root RQ irq failed, RQ Index = %u, return %d",
				   q_index, ret);

			goto free_irq;
		}

		if (irq_info.msix_entry_idx >= HIFC_ROOT_Q_INT_ID_MAX) {
			HIFC_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_REG_ATT,
				   UNF_ERR,
				   "[warn]cfg_alloc_irqs Root RQ irq id exceed 1024, msix_entry_idx %u",
				   irq_info.msix_entry_idx);

			hifc_free_irq(hba->hw_dev_handle, SERVICE_T_FC,
				      irq_info.irq_id);
			goto free_irq;
		}

		rq_info = (struct hifc_root_rq_info_s *)(v_root_info->rq_info) +
			  q_index;
		rq_info->irq_id = (unsigned int)(irq_info.irq_id);
		rq_info->msix_entry_idx = (unsigned short)
					  (irq_info.msix_entry_idx);

		ret = snprintf(rq_info->irq_name, HIFC_IRQ_NAME_MAX - 1,
			       "Root RQ %u", q_index);
		UNF_FUNCTION_RETURN_CHECK(ret, HIFC_IRQ_NAME_MAX - 1);

		tasklet_init(&rq_info->tasklet, hifc_process_root_rqe,
			     (unsigned long)rq_info);

		ret = request_irq(rq_info->irq_id, hifc_root_rq_irq, 0UL,
				  rq_info->irq_name, rq_info);
		hifc_set_msix_state(hba->hw_dev_handle, rq_info->msix_entry_idx,
				    HIFC_MSIX_ENABLE);
		if (ret != RETURN_OK) {
			HIFC_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_REG_ATT,
				   UNF_WARN,
				   "[warn]UNF_OS_REQUEST_IRQ Root RQ irq failed, RQ Index = %u, return %d",
				   q_index, ret);

			hifc_free_irq(hba->hw_dev_handle, SERVICE_T_FC,
				      rq_info->irq_id);
			memset(rq_info->irq_name, 0, HIFC_IRQ_NAME_MAX);
			rq_info->irq_id = 0;
			rq_info->msix_entry_idx = 0;
			goto free_irq;
		}
	}

	return RETURN_OK;

free_irq:
	cfg_num = q_index;

	for (q_index = 0; q_index < cfg_num; q_index++) {
		rq_info = (struct hifc_root_rq_info_s *)(v_root_info->rq_info) +
			  q_index;

		free_irq(rq_info->irq_id, rq_info);
		tasklet_kill(&rq_info->tasklet);
		hifc_free_irq(hba->hw_dev_handle, SERVICE_T_FC,
			      rq_info->irq_id);
		rq_info->irq_id = 0;
		rq_info->msix_entry_idx = 0;
	}

	return UNF_RETURN_ERROR;
}

static void hifc_free_root_rq_int(struct hifc_root_info_s *v_root_info)
{
	unsigned int q_index = 0;
	struct hifc_root_rq_info_s *rq_info = NULL;
	struct hifc_root_info_s *root_info = NULL;
	struct hifc_hba_s *hba = NULL;

	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE, NULL != v_root_info, return);

	root_info = v_root_info;
	hba = (struct hifc_hba_s *)(root_info->phba);

	for (q_index = 0; q_index < root_info->rq_num; q_index++) {
		rq_info = (struct hifc_root_rq_info_s *)(root_info->rq_info) +
			  q_index;
		hifc_set_msix_state(hba->hw_dev_handle, rq_info->msix_entry_idx,
				    HIFC_MSIX_DISABLE);
		free_irq(rq_info->irq_id, rq_info);
		tasklet_kill(&rq_info->tasklet);
		hifc_free_irq(hba->hw_dev_handle, SERVICE_T_FC,
			      rq_info->irq_id);
		rq_info->irq_id = 0;
		rq_info->msix_entry_idx = 0;
	}
}

static unsigned int hifc_alloc_root_rq_completion_buff(
				struct hifc_root_info_s *v_root_info)
{
	unsigned int q_index = 0;
	unsigned int back_index = 0;
	unsigned int rqc_buff_size = 0;
	struct hifc_root_info_s *root_info = NULL;
	struct hifc_root_rq_info_s *rq_info = NULL;
	struct hifc_hba_s *hba = NULL;

	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE, v_root_info,
			return UNF_RETURN_ERROR);

	root_info = v_root_info;
	hba = (struct hifc_hba_s *)(root_info->phba);

	for (q_index = 0; q_index < root_info->rq_num; q_index++) {
		rq_info = (struct hifc_root_rq_info_s *)(root_info->rq_info) +
			  q_index;

		/* 2048 * Size */
		rqc_buff_size = rq_info->q_depth *
				sizeof(struct hifc_root_rq_complet_info_s);
		rq_info->rq_completion_buff = dma_alloc_coherent(
						&hba->pci_dev->dev,
						rqc_buff_size,
						&rq_info->rq_completion_dma,
						GFP_KERNEL);
		if (!rq_info->rq_completion_buff) {
			HIFC_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_REG_ATT,
				   UNF_WARN,
				   "[warn]Allocate Root RQ completion buffer failed, RQ Index = %u.",
				   q_index);

			goto free_buff;
		}
		memset(rq_info->rq_completion_buff, 0, rqc_buff_size);
		rq_info->rqc_buff_size = rqc_buff_size;
	}

	return RETURN_OK;

free_buff:

	back_index = q_index;

	for (q_index = 0; q_index < back_index; q_index++) {
		rq_info = (struct hifc_root_rq_info_s *)(root_info->rq_info) +
			  q_index;
		dma_free_coherent(&hba->pci_dev->dev, rq_info->rqc_buff_size,
				  rq_info->rq_completion_buff,
				  rq_info->rq_completion_dma);
		rq_info->rq_completion_buff = NULL;
		rq_info->rq_completion_dma = 0;
		rq_info->rqc_buff_size = 0;
	}

	return UNF_RETURN_ERROR;
}

static void hifc_free_root_rq_completion_buff(
			struct hifc_root_info_s *v_root_info)
{
	unsigned int q_index = 0;
	struct hifc_root_info_s *root_info = NULL;
	struct hifc_root_rq_info_s *rq_info = NULL;
	struct hifc_hba_s *hba = NULL;

	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE, v_root_info, return);

	root_info = v_root_info;
	hba = (struct hifc_hba_s *)(root_info->phba);

	for (q_index = 0; q_index < root_info->rq_num; q_index++) {
		rq_info = (struct hifc_root_rq_info_s *)(root_info->rq_info) +
			  q_index;
		dma_free_coherent(&hba->pci_dev->dev, rq_info->rqc_buff_size,
				  rq_info->rq_completion_buff,
				  rq_info->rq_completion_dma);
		rq_info->rq_completion_buff = NULL;
		rq_info->rq_completion_dma = 0;
		rq_info->rqc_buff_size = 0;
	}
}

static unsigned int hifc_alloc_root_rq_rcv_buff(
			struct hifc_root_info_s *v_root_info)
{
	unsigned int q_index = 0;
	unsigned int back_index = 0;
	unsigned int rq_rcv_buff_size = 0;
	struct hifc_root_info_s *root_info = NULL;
	struct hifc_root_rq_info_s *rq_info = NULL;
	struct hifc_hba_s *hba = NULL;

	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE, v_root_info,
			return UNF_RETURN_ERROR);

	root_info = v_root_info;
	hba = (struct hifc_hba_s *)(root_info->phba);

	for (q_index = 0; q_index < root_info->rq_num; q_index++) {
		rq_info = (struct hifc_root_rq_info_s *)(root_info->rq_info) +
			  q_index;

		/* Depth(2048) * Buff_Size(2048) */
		rq_rcv_buff_size = rq_info->q_depth *
				   HIFC_ROOT_RQ_RECV_BUFF_SIZE;
		rq_info->rq_rcv_buff = dma_alloc_coherent(&hba->pci_dev->dev,
							  rq_rcv_buff_size,
							  &rq_info->rq_rcv_dma,
							  GFP_KERNEL);
		if (!rq_info->rq_rcv_buff) {
			HIFC_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_REG_ATT,
				   UNF_WARN,
				   "[warn]Allocate Root RQ receive buffer failed, RQ index = %u",
				   q_index);

			goto free_buff;
		}
		memset(rq_info->rq_rcv_buff, 0, rq_rcv_buff_size);
		rq_info->rq_rcv_buff_size = rq_rcv_buff_size;
	}

	return RETURN_OK;

free_buff:

	back_index = q_index;

	for (q_index = 0; q_index < back_index; q_index++) {
		rq_info = (struct hifc_root_rq_info_s *)(root_info->rq_info) +
			  q_index;
		dma_free_coherent(&hba->pci_dev->dev,
				  rq_info->rq_rcv_buff_size,
				  rq_info->rq_rcv_buff, rq_info->rq_rcv_dma);
		rq_info->rq_rcv_buff = NULL;
		rq_info->rq_rcv_dma = 0;
		rq_info->rq_rcv_buff_size = 0;
	}

	return UNF_RETURN_ERROR;
}

static void hifc_free_root_rq_rcv_buff(struct hifc_root_info_s *v_root_info)
{
	unsigned int q_index = 0;
	struct hifc_root_info_s *root_info = NULL;
	struct hifc_root_rq_info_s *rq_info = NULL;
	struct hifc_hba_s *hba = NULL;

	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE, NULL != v_root_info, return);

	root_info = v_root_info;
	hba = (struct hifc_hba_s *)(root_info->phba);

	for (q_index = 0; q_index < root_info->rq_num; q_index++) {
		rq_info = (struct hifc_root_rq_info_s *)(root_info->rq_info) +
			  q_index;
		dma_free_coherent(&hba->pci_dev->dev,
				  rq_info->rq_rcv_buff_size,
				  rq_info->rq_rcv_buff, rq_info->rq_rcv_dma);
		rq_info->rq_rcv_buff = NULL;
		rq_info->rq_rcv_dma = 0;
		rq_info->rq_rcv_buff_size = 0;
	}
}

static void hifc_init_root_rq_wqe(struct hifc_root_info_s *v_root_info)
{
	unsigned int q_index = 0;
	unsigned short wqe_index = 0;
	unsigned int dma_offset = 0;
	dma_addr_t rq_completion_dma = 0;
	dma_addr_t rq_rcv_dma = 0;
	struct nic_rq_wqe *rq_wqe = NULL;
	struct nic_wqe_ctrl_sec *wqe_ctrl = NULL;
	struct nic_rq_sge_sec *buff_sge = NULL;
	struct nic_rq_bd_sec *rq_buff_bd = NULL;
	struct hifc_root_info_s *root_info = NULL;
	struct hifc_root_rq_info_s *rq_info = NULL;

	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE, v_root_info, return);

	root_info = v_root_info;

	for (q_index = 0; q_index < root_info->rq_num; q_index++) {
		rq_info = (struct hifc_root_rq_info_s *)(root_info->rq_info) +
			  q_index;

		for (wqe_index = 0; wqe_index < rq_info->q_depth; wqe_index++) {
			rq_wqe = (struct nic_rq_wqe *)
				 hifc_slq_get_addr(rq_info->rq_handle,
						   wqe_index);
			if (!rq_wqe) {
				HIFC_TRACE(UNF_EVTLOG_DRIVER_ERR,
					   UNF_LOG_REG_ATT, UNF_ERR, "[err]Get Rq Wqe failed");

				return;
			}
			memset(rq_wqe, 0, sizeof(struct nic_rq_wqe));

			/* Initialize ctrl section */
			wqe_ctrl = &rq_wqe->rq_wqe_ctrl_sec;
			wqe_ctrl->bs.owner = HIFC_ROOT_RQ_LOOP_OWNER;
			/* control section = 8 bytes */
			wqe_ctrl->bs.ctrl_sec_len = 1;
			/* complete section = 16B for SGE */
			wqe_ctrl->bs.completion_sec_len = 2;
			/* bd section = 8B */
			wqe_ctrl->bs.buf_desc_sec_len = 1;
			wqe_ctrl->bs.cf = 1;             /* use SGE */

			/* Fill wqe receive information section */
			buff_sge = &rq_wqe->rx_sge;
			dma_offset = sizeof(struct hifc_root_rq_complet_info_s)
				      * wqe_index;
			rq_completion_dma = rq_info->rq_completion_dma +
					    dma_offset;
			buff_sge->wb_addr_low =
					HIFC_LOW_32_BITS(rq_completion_dma);
			buff_sge->wb_addr_high =
					HIFC_HIGH_32_BITS(rq_completion_dma);
			buff_sge->bs0.length =
				sizeof(struct hifc_root_rq_complet_info_s);

			/* Fill db */
			rq_buff_bd = &rq_wqe->pkt_buf_addr;
			dma_offset = HIFC_ROOT_RQ_RECV_BUFF_SIZE * wqe_index;
			rq_rcv_dma = rq_info->rq_rcv_dma + dma_offset;
			rq_buff_bd->pkt_buf_addr_high =
						HIFC_HIGH_32_BITS(rq_rcv_dma);
			rq_buff_bd->pkt_buf_addr_low =
						HIFC_LOW_32_BITS(rq_rcv_dma);

			/* big-little endian convert */
			hifc_cpu_to_big32((void *)rq_wqe,
					  sizeof(struct nic_rq_wqe));
		}

		rq_info->pi = rq_info->q_depth - 1;
		rq_info->owner = HIFC_ROOT_RQ_LOOP_OWNER;
	}
}

static unsigned int hifc_calc_cmd_rq_num(unsigned int remain_rq_num)
{
	unsigned int ret = 0;

	if (remain_rq_num < HIFC_ROOT_CFG_RQ_NUM_MAX)
		ret = remain_rq_num;
	else
		ret = HIFC_ROOT_CFG_RQ_NUM_MAX;

	return ret;
}

static void hifc_assemble_root_rq_ctx(unsigned int cmd_rq_num,
				      struct hifc_root_rq_info_s *v_rq_info,
				      void *v_buf)
{
	unsigned int q_index = 0;
	unsigned long long ci_init_addr = 0;
	struct hifc_root_rq_info_s *rq_info = NULL;
	struct hifc_qp_ctxt_header *cmdq_header = NULL;
	struct hifc_rq_ctxt *rq_ctx = NULL;
	struct hifc_rq_ctxt_block *rq_ctx_block = NULL;

	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE, v_rq_info, return);
	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE, v_buf, return);

	rq_info = v_rq_info;
	rq_ctx_block = (struct hifc_rq_ctxt_block *)v_buf;
	cmdq_header = &rq_ctx_block->cmdq_hdr;

	/* cmdheader initialization */
	cmdq_header->num_queues = (unsigned short)cmd_rq_num;
	cmdq_header->queue_type = HIFC_CMDQ_QUEUE_TYPE_RQ;
	cmdq_header->addr_offset = HIFC_ROOT_RQ_CTX_OFFSET(rq_info->max_qnum,
				   rq_info->qid);

	/* big-little endian convert */
	hifc_cpu_to_big32(cmdq_header, sizeof(struct hifc_qp_ctxt_header));

	for (q_index = 0; q_index < cmd_rq_num; q_index++) {
		rq_info = v_rq_info + q_index;
		rq_ctx = &rq_ctx_block->rq_ctx[q_index];
		memset(rq_ctx, 0, sizeof(struct hifc_rq_ctxt));

		rq_ctx->pi_gpa_hi = HIFC_HIGH_32_BITS(rq_info->pi_dma_addr);
		rq_ctx->pi_gpa_lo = HIFC_LOW_32_BITS(rq_info->pi_dma_addr);
		rq_ctx->bs2.ci = 0;
		rq_ctx->bs0.pi = 0;

		rq_ctx->bs6.ci_cla_tbl_addr_hi =
				HIFC_CLA_HIGH_ADDR(rq_info->ci_cla_tbl_addr);
		rq_ctx->ci_cla_tbl_addr_lo =
				HIFC_CLA_LOW_ADDR(rq_info->ci_cla_tbl_addr);

		ci_init_addr = hifc_slq_get_first_pageaddr(rq_info->rq_handle);
		rq_ctx->bs2.ci_wqe_page_addr_hi =
				HIFC_CI_WQE_PAGE_HIGH_ADDR(ci_init_addr);
		rq_ctx->ci_wqe_page_addr_lo =
				HIFC_CI_WQE_PAGE_LOW_ADDR(ci_init_addr);

		rq_ctx->bs.ceq_en = 0;
		rq_ctx->bs.owner = HIFC_ROOT_RQ_LOOP_OWNER;
		rq_ctx->bs0.int_num = rq_info->msix_entry_idx;

		rq_ctx->bs3.prefetch_cache_threshold =
				HIFC_ROOT_CTX_WQE_PRERETCH_THRESHOLD;
		rq_ctx->bs3.prefetch_max = HIFC_ROOT_CTX_WQE_PREFETCH_MAX;
		rq_ctx->bs3.prefetch_min = HIFC_ROOT_CTX_WQE_PREFETCH_MIN;
		rq_ctx->bs5.prefetch_ci_wqe_page_addr_hi =
					rq_ctx->bs2.ci_wqe_page_addr_hi;
		rq_ctx->prefetch_ci_wqe_page_addr_lo =
					rq_ctx->ci_wqe_page_addr_lo;

		/* big-little endian convert */
		hifc_cpu_to_big32(rq_ctx, sizeof(struct hifc_rq_ctxt));
	}
}

static unsigned int hifc_cfg_root_rq_ctx(unsigned int cmd_rq_num,
					 void *v_handle,
					 struct hifc_cmd_buf *v_chipif_cmd_buff)
{
	int ret = 0;
	unsigned short buff_used_size = 0;
	unsigned int time_out = 0xF0000000;
	unsigned long long uc_return = 0;

	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE, v_handle,
			return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE, v_chipif_cmd_buff,
			return UNF_RETURN_ERROR);

	UNF_REFERNCE_VAR(uc_return);
	UNF_REFERNCE_VAR(time_out);
	UNF_REFERNCE_VAR(ret);

	buff_used_size = (unsigned short)(sizeof(struct hifc_qp_ctxt_header) +
			 sizeof(struct hifc_rq_ctxt) * cmd_rq_num);
	v_chipif_cmd_buff->size = buff_used_size;

	ret = hifc_cmdq_direct_resp(v_handle,
				    HIFC_ACK_TYPE_CMDQ,
				    HIFC_MOD_L2NIC,
				    HIFC_UCODE_CMD_MODIFY_QUEUE_CONTEXT,
				    v_chipif_cmd_buff,
				    (u64 *)&uc_return,
				    time_out);
	if ((ret != RETURN_OK) || (uc_return != RETURN_OK)) {
		HIFC_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_REG_ATT, UNF_ERR,
			   "[err]hifc_cmdq_direct_resp failed, uiret %d, ullUcRet %llu",
			   ret, uc_return);

		return UNF_RETURN_ERROR;
	}

	return RETURN_OK;
}

static unsigned int hifc_init_root_rq_ctx(
				void *v_handle,
				struct hifc_root_info_s *v_root_info)
{
	unsigned int ret = UNF_RETURN_ERROR;
	unsigned int cmd_rq_num = 0;
	unsigned int remain_rq_num = 0;
	struct hifc_root_rq_info_s *rq_info = NULL;
	struct hifc_root_info_s *root_info = NULL;
	struct hifc_cmd_buf *chipif_cmd_buf = NULL;

	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE, v_handle,
			return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE, v_root_info,
			return UNF_RETURN_ERROR);

	root_info = v_root_info;
	rq_info = (struct hifc_root_rq_info_s *)(root_info->rq_info);

	chipif_cmd_buf = hifc_alloc_cmd_buf(v_handle);
	if (!chipif_cmd_buf) {
		HIFC_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_REG_ATT, UNF_WARN,
			   "[err]hifc_alloc_cmd_buf failed");

		return ENOMEM;
	}

	remain_rq_num = root_info->rq_num;
	while (remain_rq_num > 0) {
		cmd_rq_num = hifc_calc_cmd_rq_num(remain_rq_num);
		remain_rq_num -= cmd_rq_num;

		/* Assemble cmd buffer context */
		hifc_assemble_root_rq_ctx(cmd_rq_num, rq_info,
					  chipif_cmd_buf->buf);

		/* Send via ucode */
		ret = hifc_cfg_root_rq_ctx(cmd_rq_num, v_handle,
					   chipif_cmd_buf);
		if (ret != RETURN_OK) {
			HIFC_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_REG_ATT,
				   UNF_ERR,
				   "[err]hifc_cfg_root_rq_ctx failed, return %u",
				   ret);
			break;
		}

		rq_info = rq_info + cmd_rq_num;
	}

	/* Free cmd buffer */
	hifc_free_cmd_buf(v_handle, chipif_cmd_buf);

	return ret;
}

static void hifc_update_root_rq_pi(struct hifc_root_info_s *v_root_info)
{
	unsigned int q_index = 0;
	struct hifc_root_rq_info_s *rq_info = NULL;

	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE, NULL != v_root_info, return);

	for (q_index = 0; q_index < v_root_info->rq_num; q_index++) {
		rq_info = (struct hifc_root_rq_info_s *)(v_root_info->rq_info) +
			  q_index;

		wmb();
		*rq_info->pi_vir_addr = cpu_to_be16(rq_info->pi);
	}
}

static unsigned int hifc_create_root_rqs(struct hifc_root_info_s *v_root_info)
{
	unsigned int ret = UNF_RETURN_ERROR;
	struct hifc_hba_s *hba = NULL;

	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE, v_root_info,
			return UNF_RETURN_ERROR);

	hba = (struct hifc_hba_s *)v_root_info->phba;

	/* Allocate RQ struct */
	ret = hifc_alloc_root_rq_info(v_root_info);
	if (ret != RETURN_OK) {
		HIFC_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_REG_ATT, UNF_WARN,
			   "[warn]hifc_alloc_root_rq_info failed");

		return ret;
	}

	/* Initialize RQ basic information */
	hifc_init_root_rq_basic_info(v_root_info);

	/* Apply RQ(s) PI GPA */
	ret = hifc_alloc_root_rq_pi_addr(v_root_info);
	if (ret != RETURN_OK) {
		HIFC_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_REG_ATT, UNF_WARN,
			   "[warn]hifc_alloc_root_rq_pi_addr failed, return %u",
			   ret);

		goto free_root_rq_info;
	}

	/* Apply RQ's buffer */
	ret = hifc_alloc_root_rq_buff(v_root_info);
	if (ret != RETURN_OK) {
		HIFC_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_REG_ATT, UNF_WARN,
			   "[warn]hifc_alloc_root_rq_buff failed, return %u",
			   ret);

		goto free_rq_pi_addr;
	}

	/* Apply completion buffer */
	ret = hifc_alloc_root_rq_completion_buff(v_root_info);
	if (ret != RETURN_OK) {
		HIFC_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_REG_ATT, UNF_WARN,
			   "[warn]hifc_alloc_root_rq_completion_buff failed, return %u",
			   ret);

		goto free_root_rq_buff;
	}

	/* Allocate root RQ receiving buffer */
	ret = hifc_alloc_root_rq_rcv_buff(v_root_info);
	if (ret != RETURN_OK) {
		HIFC_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_REG_ATT, UNF_WARN,
			   "[warn]hifc_alloc_root_rq_rcv_buff failed, return %u",
			   ret);

		goto free_root_rq_completion_buff;
	}

	/* Initialize RQ WQE struct */
	hifc_init_root_rq_wqe(v_root_info);

	/* Apply RQ's interrupt resources */
	ret = hifc_alloc_root_rq_int(v_root_info);
	if (ret != RETURN_OK) {
		HIFC_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_REG_ATT, UNF_WARN,
			   "[warn]hifc_alloc_root_rq_int failed, return %u",
			   ret);

		goto free_root_rq_receive_buff;
	}

	/* Initialize RQ context */
	ret = hifc_init_root_rq_ctx(hba->hw_dev_handle, v_root_info);
	if (ret != RETURN_OK) {
		HIFC_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_REG_ATT, UNF_ERR,
			   "[err]hifc_init_root_rq_ctx Failed, return %u", ret);

		goto free_root_rq_int;
	}

	/* Update SQ PI */
	hifc_update_root_rq_pi(v_root_info);
	return RETURN_OK;

free_root_rq_int:
	hifc_free_root_rq_int(v_root_info);

free_root_rq_receive_buff:
	hifc_free_root_rq_rcv_buff(v_root_info);

free_root_rq_completion_buff:
	hifc_free_root_rq_completion_buff(v_root_info);

free_root_rq_buff:
	hifc_free_root_rq_buff(v_root_info);

free_rq_pi_addr:
	hifc_free_root_rq_pi_addr(v_root_info);

free_root_rq_info:
	hifc_free_root_rq_info(v_root_info);

	return ret;
}

static void hifc_destroy_root_rqs(struct hifc_root_info_s *v_root_info)
{
	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE, v_root_info, return);

	hifc_free_root_rq_rcv_buff(v_root_info);

	hifc_free_root_rq_completion_buff(v_root_info);

	hifc_free_root_rq_int(v_root_info);

	hifc_free_root_rq_buff(v_root_info);

	hifc_free_root_rq_pi_addr(v_root_info);

	hifc_free_root_rq_info(v_root_info);
}

static unsigned int hifc_cfg_root_ctx(struct hifc_root_info_s *v_root_info)
{
	int ret;
	struct hifc_hba_s *hba = NULL;
	struct hifc_root_info_s *root_info = NULL;

	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE, v_root_info,
			return UNF_RETURN_ERROR);

	root_info = v_root_info;
	hba = (struct hifc_hba_s *)root_info->phba;

	ret = hifc_set_root_ctxt(hba->hw_dev_handle, HIFC_ROOT_RQ_DEPTH,
				 HIFC_ROOT_SQ_DEPTH,
				 HIFC_ROOT_RQ_RECV_BUFF_SIZE);
	if (ret != RETURN_OK) {
		HIFC_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_REG_ATT, UNF_ERR,
			   "[err]chipif_func_vat_info_set failed, return [%d]",
			   ret);

		return UNF_RETURN_ERROR;
	}

	return RETURN_OK;
}

static void hifc_init_root_basic_info(struct hifc_hba_s *v_hba)
{
	struct hifc_root_info_s *root_info = NULL;

	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE, NULL != v_hba, return);

	root_info = &v_hba->root_info;
	memset(root_info, 0, sizeof(struct hifc_root_info_s));

	root_info->phba = (void *)v_hba;

	root_info->rq_num = HIFC_ROOT_RQ_NUM;
	root_info->sq_num = HIFC_ROOT_SQ_NUM;
}

unsigned int hifc_create_root_queues(void *v_hba)
{
	unsigned int ret = UNF_RETURN_ERROR;
	int slq_ret = 0;
	struct hifc_root_info_s *root_info = NULL;
	struct hifc_hba_s *hba = NULL;

	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE, v_hba,
			return UNF_RETURN_ERROR);

	/* Initialize basic root information */
	hba = (struct hifc_hba_s *)v_hba;
	hifc_init_root_basic_info(hba);

	root_info = &hba->root_info;

	/* slq Init */
	slq_ret = hifc_slq_init(hba->hw_dev_handle,
				(int)(root_info->sq_num + root_info->rq_num));
	if (slq_ret) {
		HIFC_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_REG_ATT, UNF_WARN,
			   "[err]hifc_slq_init init failed, ret:0x%x", slq_ret);

		return UNF_RETURN_ERROR;
	}

	/* Create SQ, and send cmdq to ucode for initialization of SQ context */
	ret = hifc_create_root_sqs(root_info);
	if (ret != RETURN_OK) {
		HIFC_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_REG_ATT, UNF_WARN,
			   "[err]hifc_create_root_sqs failed, return [%u]",
			   ret);

		hifc_slq_uninit(hba->hw_dev_handle);
		return ret;
	}

	/* Create RQ */
	ret = hifc_create_root_rqs(root_info);
	if (ret != RETURN_OK) {
		HIFC_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_REG_ATT, UNF_WARN,
			   "[err]hifc_create_root_rqs failed, return [%u]",
			   ret);

		hifc_destroy_root_sqs(root_info);
		hifc_slq_uninit(hba->hw_dev_handle);
		return ret;
	}

	/* Configure root context */
	ret = hifc_cfg_root_ctx(root_info);
	if (ret != RETURN_OK) {
		HIFC_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_REG_ATT, UNF_ERR,
			   "[err]hifc_cfg_root_ctx failed, return [%u]", ret);

		hifc_destroy_root_rqs(root_info);
		hifc_destroy_root_sqs(root_info);
		hifc_slq_uninit(hba->hw_dev_handle);
		return ret;
	}

	return RETURN_OK;
}

void hifc_destroy_root_queues(void *v_hba)
{
	struct hifc_hba_s *hba = NULL;
	struct hifc_root_info_s *root_info = NULL;

	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE, v_hba, return);

	hba = (struct hifc_hba_s *)v_hba;
	root_info = &hba->root_info;

	hifc_destroy_root_rqs(root_info);
	hifc_destroy_root_sqs(root_info);

	hifc_slq_uninit(hba->hw_dev_handle);
}

static void hifc_ring_root_sq_db(struct hifc_hba_s *v_hba,
				 struct hifc_root_sq_info_s *v_sq_info)
{
	struct nic_tx_doorbell db;

	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE, NULL != v_sq_info, return);

	memset(&db, 0, sizeof(struct nic_tx_doorbell));

	db.bs0.srv_type = HIFC_DOORBELL_SQ_TYPE;
	db.bs0.queue_id = v_sq_info->qid;
	db.bs0.pi_high = v_sq_info->pi >> HIFC_DOORBELL_SQ_PI_HIGH_BITS_SHIFT;
	db.bs0.cos = 0;

	db.dw0 = cpu_to_be32(db.dw0);
	wmb();

	*((unsigned long long *)(v_sq_info->normal_db.virt_map_addr)
	  + (v_sq_info->pi & HIFC_DOORBELL_SQ_PI_LOW_BITS_MASK)) =
						*(unsigned long long *)&db;
}

static int hifc_root_sq_is_empty(struct hifc_root_sq_info_s *v_sq_info)
{
	unsigned short cur_pi = 0;
	unsigned short cur_ci = 0;

	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE, v_sq_info, return UNF_TRUE);

	/* pi == ci empty, pi-ci = 1 full */
	cur_pi = v_sq_info->pi;
	cur_ci = *v_sq_info->ci_addr;
	cur_ci = be16_to_cpu(cur_ci);

	if (cur_pi == cur_ci)
		return UNF_TRUE;

	return UNF_FALSE;
}

static int hifc_root_sq_is_full(struct hifc_root_sq_info_s *v_sq_info)
{
	unsigned short cur_pi = 0;
	unsigned short cur_ci = 0;
	unsigned short valid_wqe_num = 0;

	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE, v_sq_info, return UNF_TRUE);

	/* pi == ci empty, pi-ci = 1 full */
	cur_pi = v_sq_info->pi;
	cur_ci = *v_sq_info->ci_addr;
	cur_ci = be16_to_cpu(cur_ci);
	valid_wqe_num = v_sq_info->q_depth - 1;

	if ((valid_wqe_num == cur_pi - cur_ci) ||
	    (valid_wqe_num == v_sq_info->q_depth + cur_pi - cur_ci)) {
		HIFC_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_REG_ATT, UNF_WARN,
			   "[warn]Root SQ[%u] is full, PI %u, CI %u",
			   v_sq_info->global_qpn, cur_pi, cur_ci);
		return UNF_TRUE;
	}

	return UNF_FALSE;
}

static void hifc_build_root_wqe_qsf(void *v_qsf)
{
	struct hifc_root_qsf_s *root_qsf = NULL;

	root_qsf = (struct hifc_root_qsf_s *)v_qsf;

	/* route to ucode */
	/* MSS range 0x50~0x3E00 */
	root_qsf->route_to_ucode = 1;
	root_qsf->mss = 0x3E00;
}

unsigned int hifc_root_sq_enqueue(void *v_hba, struct hifc_root_sqe_s *v_sqe)
{
	unsigned char task_type = 0;
	struct hifc_root_info_s *root_info = NULL;
	struct hifc_root_sq_info_s *sq_info = NULL;
	struct hifc_hba_s *hba = NULL;
	struct hifc_root_sqe_s *sqe = NULL;
	unsigned long flag = 0;

	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE, v_hba,
			return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE, v_sqe,
			return UNF_RETURN_ERROR);

	/* Root use one sq by default */
	hba = (struct hifc_hba_s *)v_hba;
	root_info = &hba->root_info;
	sq_info = (struct hifc_root_sq_info_s *)(root_info->sq_info);
	task_type = (unsigned char)v_sqe->task_section.fc_dw0.task_type;

	spin_lock_irqsave(&sq_info->root_sq_spin_lock, flag);

	/* Check flush state */
	if (sq_info->in_flush == UNF_TRUE) {
		HIFC_ERR_IO_STAT(hba, task_type);
		HIFC_HBA_STAT(hba, HIFC_STAT_ROOT_IO_FLUSHED);
		spin_unlock_irqrestore(&sq_info->root_sq_spin_lock, flag);
		HIFC_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_REG_ATT, UNF_WARN, "[err]Root SQ is flushing");
		return UNF_RETURN_ERROR;
	}

	/* Check root SQ whether is full */
	if (hifc_root_sq_is_full(sq_info) == UNF_TRUE) {
		HIFC_ERR_IO_STAT(hba, task_type);
		HIFC_HBA_STAT(hba, HIFC_STAT_ROOT_SQ_FULL);
		spin_unlock_irqrestore(&sq_info->root_sq_spin_lock, flag);
		HIFC_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_REG_ATT, UNF_WARN, "[err]Root SQ is full");
		return UNF_RETURN_ERROR;
	}

	if (unlikely(!hba->heart_status)) {
		spin_unlock_irqrestore(&sq_info->root_sq_spin_lock, flag);
		HIFC_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_NORMAL, UNF_ERR,
			   "[err]Heart status is false");
		return UNF_RETURN_ERROR;
	}
	/* Get available wqe */
	sqe = (struct hifc_root_sqe_s *)hifc_slq_get_addr(sq_info->sq_handle,
							  sq_info->pi);
	if (!sqe) {
		HIFC_ERR_IO_STAT(hba, task_type);
		spin_unlock_irqrestore(&sq_info->root_sq_spin_lock, flag);

		HIFC_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_REG_ATT, UNF_WARN,
			   "[err]Get root SQ Sqe failed, PI %u", sq_info->pi);

		return UNF_RETURN_ERROR;
	}

	hifc_build_root_wqe_qsf((void *)(&v_sqe->ctrl_section.qsf));
	HIFC_IO_STAT(hba, task_type);
	hifc_convert_root_wqe_to_big_endian(v_sqe);
	memcpy(sqe, v_sqe, sizeof(struct hifc_root_sqe_s));

	/* Update PI and Obit */
	hifc_update_producer_info(sq_info->q_depth, &sq_info->pi,
				  &sq_info->owner);

	/* doorbell */
	hifc_ring_root_sq_db(hba, sq_info);

	spin_unlock_irqrestore(&sq_info->root_sq_spin_lock, flag);
	UNF_REFERNCE_VAR(task_type);

	return RETURN_OK;
}

static int hifc_root_rqe_done(
		struct hifc_root_rq_complet_info_s *v_completion_info)
{
	if (v_completion_info->done != 0)
		return UNF_TRUE;

	return UNF_FALSE;
}

static void hifc_clear_root_rqe_done(
		struct hifc_root_rq_complet_info_s *v_completion_info)
{
	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE, v_completion_info, return);

	v_completion_info->done = 0;
}

static int hifc_check_root_rqe_type(
		struct hifc_root_rq_complet_info_s *v_completion_info)
{
	if (v_completion_info->fc_pkt != 0)
		return UNF_TRUE;

	return UNF_FALSE;
}

void hifc_update_root_rq_info(struct hifc_root_rq_info_s *v_rq_info,
			      unsigned short v_rcv_buf_num)
{
	unsigned short loop = 0;
	struct hifc_root_rq_complet_info_s completion_info = { 0 };
	struct hifc_root_rq_complet_info_s *complet_info = NULL;

	for (loop = 0; loop < v_rcv_buf_num; loop++) {
		/* Obtain CompletionInfo */
		complet_info = (struct hifc_root_rq_complet_info_s *)
			(v_rq_info->rq_completion_buff) + v_rq_info->ci;

		/* big-little endian convert */
		memcpy(&completion_info, complet_info, sizeof(completion_info));
		hifc_big_to_cpu32(&completion_info, sizeof(completion_info));

		/* Clear done bit */
		hifc_clear_root_rqe_done(&completion_info);

		/* Write back done bit */
		hifc_cpu_to_big32(&completion_info, sizeof(completion_info));
		memcpy(complet_info, &completion_info, sizeof(completion_info));

		/* Update Obit and PI in RQE */
		hifc_update_producer_info(v_rq_info->q_depth, &v_rq_info->pi,
					  &v_rq_info->owner);

		v_rq_info->ci = ((v_rq_info->ci + 1) < v_rq_info->q_depth) ?
				(v_rq_info->ci + 1) : 0;

		wmb();
		*v_rq_info->pi_vir_addr = cpu_to_be16(v_rq_info->pi);
	}
}

void hifc_root_rqe_analysis(
		struct hifc_hba_s *v_hba,
		struct hifc_root_rq_info_s *v_rq_info,
		struct hifc_root_rq_complet_info_s *v_completion_info,
		unsigned short v_rcv_buf_num)
{
	unsigned int ret = UNF_RETURN_ERROR;

	if (v_completion_info->sts_only) {
		/* case1: receive ElsRsp Status */
		if (v_completion_info->status == RETURN_OK)
			ret = hifc_rq_rcv_els_rsp_sts(v_hba, v_completion_info);
		else
			ret = hifc_rq_rcv_srv_err(v_hba, v_completion_info);
	} else {
		ret = hifc_rcv_service_frame_from_rq(v_hba, v_rq_info,
						     v_completion_info,
						     v_rcv_buf_num);
	}

	if (ret != RETURN_OK) {
		HIFC_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_REG_ATT, UNF_INFO,
			   "[warn]Up Layer Process RQE Frame or Status abnormal(0x%x)",
			   ret);
	}
}

void hifc_process_root_rqe(unsigned long v_rq_info)
{
	int rqe_done = UNF_FALSE;
	int rqe_valid = UNF_FALSE;
	unsigned short rcv_buf_num = 0;
	unsigned int index = 0;
	struct nic_rq_wqe *rq_wqe = NULL;
	struct hifc_hba_s *hba = NULL;
	struct hifc_root_info_s *root_info = NULL;
	struct hifc_root_rq_complet_info_s *complet_info = NULL;
	struct hifc_root_rq_complet_info_s completion_info = { 0 };

	struct hifc_root_rq_info_s *rq_info =
			(struct hifc_root_rq_info_s *)v_rq_info;
	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE, rq_info, return);

	root_info = (struct hifc_root_info_s *)(rq_info->root_info);
	hba = (struct hifc_hba_s *)(root_info->phba);

	for (index = 0; index < HIFC_RQE_MAX_PROCESS_NUM_PER_INTR; index++) {
		/* Obtain RQE */
		rq_wqe = (struct nic_rq_wqe *)
			 hifc_slq_get_addr(rq_info->rq_handle, rq_info->ci);
		if (!rq_wqe) {
			HIFC_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_REG_ATT,
				   UNF_ERR, "[err]Get Rqe failed");
			break;
		}

		/* Check whether to process RQE */
		complet_info = (struct hifc_root_rq_complet_info_s *)
			       (rq_info->rq_completion_buff) + rq_info->ci;

		memcpy(&completion_info, complet_info, sizeof(completion_info));
		hifc_big_to_cpu32(&completion_info, sizeof(completion_info));

		rqe_done = hifc_root_rqe_done(&completion_info);
		if (rqe_done != UNF_TRUE) {
			atomic_set(&rq_info->flush_state,
				   HIFC_QUEUE_FLUSH_DONE);
			break;
		}

		rmb();

		rcv_buf_num = (completion_info.buf_length +
			      HIFC_ROOT_RQ_RECV_BUFF_SIZE - 1) /
			      HIFC_ROOT_RQ_RECV_BUFF_SIZE;
		if (rcv_buf_num == 0)
			rcv_buf_num = 1;

		rqe_valid = hifc_check_root_rqe_type(&completion_info);
		if (rqe_valid == UNF_TRUE) {
			hifc_root_rqe_analysis(hba, rq_info, &completion_info,
					       rcv_buf_num);
		} else {
			/* Receive illegal frames and record */
			HIFC_IO_STAT(hba, HIFCOE_TASK_T_BUTT);

			HIFC_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_IO_ATT,
				   UNF_WARN,
				   "[warn]Port(0x%x) Receive an unsupported frame, drop it",
				   hba->port_cfg.port_id);
		}

		hifc_update_root_rq_info(rq_info, rcv_buf_num);
	}

	if (index == HIFC_RQE_MAX_PROCESS_NUM_PER_INTR)
		tasklet_schedule(&rq_info->tasklet);
}

static inline int hifc_is_scq_link_wqe(struct hifc_scq_info_s *v_scq_info)
{
	unsigned short custom_scqe_num = 0;

	custom_scqe_num = v_scq_info->ci + 1;

	if ((custom_scqe_num % v_scq_info->wqe_num_per_buf == 0) ||
	    (v_scq_info->valid_wqe_num == custom_scqe_num))
		return UNF_TRUE;
	else
		return UNF_FALSE;
}

static inline struct hifcoe_scqe_type_s *hifc_get_scq_entry(
				struct hifc_scq_info_s *v_scq_info)
{
	unsigned int buf_id = 0;
	unsigned short buf_offset = 0;
	unsigned short ci = 0;
	struct cqm_buf_list_s *buf = NULL;

	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE, v_scq_info, return NULL);

	ci = v_scq_info->ci;
	buf_id = ci / v_scq_info->wqe_num_per_buf;
	buf = &v_scq_info->cqm_scq_info->q_room_buf_1.buf_list[buf_id];
	buf_offset = (unsigned short)(ci % v_scq_info->wqe_num_per_buf);

	return (struct hifcoe_scqe_type_s *)(buf->va) + buf_offset;
}

static inline int hifc_is_cqe_done(unsigned int *v_done, unsigned int *v_owner,
				   unsigned short v_driver_owner)
{
	return ((((unsigned short)(!!(*v_done & HIFC_DONE_MASK)) ==
		v_driver_owner) && ((unsigned short)
		(!!(*v_owner & HIFC_OWNER_MASK)) == v_driver_owner)) ?
		UNF_TRUE : UNF_FALSE);
}

unsigned int hifc_process_scq_cqe_entity(unsigned long v_scq_info,
					 unsigned int proc_cnt)
{
	unsigned int ret = UNF_RETURN_ERROR;
	unsigned int index = 0;
	struct hifc_wq_header_s *queue_header = NULL;
	struct hifcoe_scqe_type_s *scqe = NULL;
	struct hifcoe_scqe_type_s tmp_scqe;

	struct hifc_scq_info_s *scq_info = (struct hifc_scq_info_s *)v_scq_info;

	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE, scq_info, return ret);

	queue_header = (struct hifc_wq_header_s *)
		       (void *)(scq_info->cqm_scq_info->q_header_vaddr);

	for (index = 0; index < proc_cnt;) {
		/* If linked wqe, then update CI */
		if (hifc_is_scq_link_wqe(scq_info) == UNF_TRUE) {
			hifc_update_consumer_info(scq_info->valid_wqe_num,
						  &scq_info->ci,
						  &scq_info->ci_owner);
			hifc_update_cq_header(&queue_header->ci_record,
					      scq_info->ci,
					      scq_info->ci_owner);

			HIFC_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_REG_ATT,
				   UNF_INFO,
				   "[info]Current wqe is a linked wqe");
			continue;
		}

		/* Get SCQE and then check obit & donebit whether been set */
		scqe = hifc_get_scq_entry(scq_info);
		if (unlikely(!scqe)) {
			HIFC_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_REG_ATT,
				   UNF_WARN, "[warn]Scqe is NULL");
			break;
		}

		if (hifc_is_cqe_done((unsigned int *)(void *)(&scqe->wd0),
				     (unsigned int *)(void *)(&scqe->ch.wd0),
				     scq_info->ci_owner) != UNF_TRUE) {
			atomic_set(&scq_info->flush_state,
				   HIFC_QUEUE_FLUSH_DONE);

			HIFC_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_REG_ATT,
				   UNF_INFO,
				   "[info]Now has no valid scqe");
			break;
		}

		/* rmb & do memory copy */
		rmb();
		memcpy(&tmp_scqe, scqe, sizeof(struct hifcoe_scqe_type_s));

		hifc_big_to_cpu32(&tmp_scqe, sizeof(struct hifcoe_scqe_type_s));

		/* process SCQ entry */
		ret = hifc_rcv_scqe_entry_from_scq(scq_info->phba,
						   (void *)&tmp_scqe,
						   scq_info->queue_id);
		if (unlikely(ret != RETURN_OK)) {
			HIFC_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_IO_ATT,
				   UNF_WARN,
				   "[warn]QueueId(0x%x) scqn(0x%x) scqe process error at CI(0x%x)",
				   scq_info->queue_id, scq_info->scqn,
				   scq_info->ci);
		}

		/* Update Driver's CI & Obit */
		hifc_update_consumer_info(scq_info->valid_wqe_num,
					  &scq_info->ci, &scq_info->ci_owner);
		hifc_update_cq_header(&queue_header->ci_record, scq_info->ci,
				      scq_info->ci_owner);
		index++;
	}
	/* Re-schedule again if necessary */
	if (proc_cnt == index)
		tasklet_schedule(&scq_info->tasklet);

	return index;
}

void hifc_set_scq_irq_cfg(struct hifc_hba_s *hba, unsigned int mode,
			  unsigned short msix_index)
{
	unsigned char pending_limt = 0;
	unsigned char coalesc_timer_cfg = 0;

	struct nic_interrupt_info info = { 0 };

	if (mode != HIFC_SCQ_INTR_LOW_LATENCY_MODE) {
		pending_limt = 5;
		coalesc_timer_cfg = 10;
	}

	memset(&info, 0, sizeof(info));
	info.interrupt_coalesc_set = 1;
	info.lli_set = 0;
	info.pending_limt = pending_limt;
	info.coalesc_timer_cfg = coalesc_timer_cfg;
	info.resend_timer_cfg = 0;
	info.msix_index = msix_index;
	hifc_set_interrupt_cfg(hba->hw_dev_handle, info);
}

void hifc_process_scq_cqe(unsigned long v_scq_info)
{
	struct hifc_scq_info_s *scq_info = (struct hifc_scq_info_s *)v_scq_info;

	HIFC_CHECK(INVALID_VALUE32, scq_info, return);

	hifc_process_scq_cqe_entity(v_scq_info,
				    HIFC_CQE_MAX_PROCESS_NUM_PER_INTR);
}

irqreturn_t hifc_scq_irq(int v_irq, void *v_scq_info)
{
	HIFC_CHECK(INVALID_VALUE32, NULL != v_scq_info, return IRQ_NONE);

	tasklet_schedule(&((struct hifc_scq_info_s *)v_scq_info)->tasklet);

	return IRQ_HANDLED;
}

static unsigned int hifc_alloc_scq_int(struct hifc_scq_info_s *v_scq_info)
{
	int ret = UNF_RETURN_ERROR_S32;
	unsigned short act_num = 0;
	struct irq_info irq_info;
	struct hifc_hba_s *hba = NULL;

	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE, v_scq_info,
			return UNF_RETURN_ERROR);

	/* 1. Alloc & check SCQ IRQ */
	hba = (struct hifc_hba_s *)(v_scq_info->phba);
	ret = hifc_alloc_irqs(hba->hw_dev_handle, SERVICE_T_FC,
			      HIFC_INT_NUM_PER_QUEUE, &irq_info, &act_num);
	if ((ret != RETURN_OK) || (act_num != HIFC_INT_NUM_PER_QUEUE)) {
		HIFC_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_REG_ATT, UNF_WARN,
			   "[err]Allocate scq irq failed, return %d", ret);

		return UNF_RETURN_ERROR;
	}

	if (irq_info.msix_entry_idx >= HIFC_SCQ_INT_ID_MAX) {
		HIFC_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_REG_ATT, UNF_ERR,
			   "[err]SCQ irq id exceed %d, msix_entry_idx %d",
			   HIFC_SCQ_INT_ID_MAX, irq_info.msix_entry_idx);

		hifc_free_irq(hba->hw_dev_handle, SERVICE_T_FC,
			      irq_info.irq_id);

		return UNF_RETURN_ERROR;
	}

	v_scq_info->irq_id = (unsigned int)(irq_info.irq_id);
	v_scq_info->msix_entry_idx = (unsigned short)(irq_info.msix_entry_idx);

	ret = snprintf(v_scq_info->irq_name, HIFC_IRQ_NAME_MAX - 1,
		       "fc_scq%u_%x_msix%u", v_scq_info->queue_id,
		       hba->port_cfg.port_id, v_scq_info->msix_entry_idx);
	UNF_FUNCTION_RETURN_CHECK(ret, HIFC_IRQ_NAME_MAX - 1);
	/* 2. SCQ IRQ tasklet init */
	tasklet_init(&v_scq_info->tasklet, hifc_process_scq_cqe,
		     (unsigned long)v_scq_info);

	/* 3. Request IRQ for SCQ */
	ret = request_irq(v_scq_info->irq_id, hifc_scq_irq, 0UL,
			  v_scq_info->irq_name, v_scq_info);
	hifc_set_msix_state(hba->hw_dev_handle, v_scq_info->msix_entry_idx,
			    HIFC_MSIX_ENABLE);
	if (ret != RETURN_OK) {
		HIFC_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_REG_ATT, UNF_WARN,
			   "[err]Request SCQ irq failed, SCQ Index = %u, return %d",
			   v_scq_info->queue_id, ret);

		hifc_free_irq(hba->hw_dev_handle, SERVICE_T_FC,
			      v_scq_info->irq_id);
		memset(v_scq_info->irq_name, 0, HIFC_IRQ_NAME_MAX);
		v_scq_info->irq_id = 0;
		v_scq_info->msix_entry_idx = 0;
		return UNF_RETURN_ERROR;
	}
	return RETURN_OK;
}

static void hifc_free_scq_int(struct hifc_scq_info_s *v_scq_info)
{
	struct hifc_hba_s *hba = NULL;

	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE, v_scq_info, return);

	hba = (struct hifc_hba_s *)(v_scq_info->phba);
	hifc_set_msix_state(hba->hw_dev_handle, v_scq_info->msix_entry_idx,
			    HIFC_MSIX_DISABLE);
	free_irq(v_scq_info->irq_id, v_scq_info);
	tasklet_kill(&v_scq_info->tasklet);
	hifc_free_irq(hba->hw_dev_handle, SERVICE_T_FC, v_scq_info->irq_id);
	memset(v_scq_info->irq_name, 0, HIFC_IRQ_NAME_MAX);
	v_scq_info->irq_id = 0;
	v_scq_info->msix_entry_idx = 0;
}

static void hifc_init_scq_info(struct hifc_hba_s *v_hba,
			       struct cqm_queue_s *v_cqm_scq,
			       unsigned int queue_id,
			       struct hifc_scq_info_s **v_ppscq_info)
{
	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE, v_hba, return);
	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE, v_cqm_scq, return);
	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE, v_ppscq_info, return);

	*v_ppscq_info = &v_hba->scq_info[queue_id];
	(*v_ppscq_info)->queue_id = queue_id;
	(*v_ppscq_info)->scqn = v_cqm_scq->index;
	(*v_ppscq_info)->phba = (void *)v_hba;

	(*v_ppscq_info)->cqm_scq_info = v_cqm_scq;
	(*v_ppscq_info)->wqe_num_per_buf = v_cqm_scq->q_room_buf_1.buf_size /
					   HIFC_SCQE_SIZE;
	(*v_ppscq_info)->wqe_size = HIFC_SCQE_SIZE;

	(*v_ppscq_info)->valid_wqe_num = (HIFC_SCQ_IS_STS(queue_id) ?
				HIFC_STS_SCQ_DEPTH : HIFC_CMD_SCQ_DEPTH);
	(*v_ppscq_info)->scqc_cq_depth = (HIFC_SCQ_IS_STS(queue_id) ?
			HIFC_STS_SCQC_CQ_DEPTH : HIFC_CMD_SCQC_CQ_DEPTH);
	(*v_ppscq_info)->scqc_ci_type = (HIFC_SCQ_IS_STS(queue_id) ?
				HIFC_STS_SCQ_CI_TYPE : HIFC_CMD_SCQ_CI_TYPE);

	(*v_ppscq_info)->ci = 0;
	(*v_ppscq_info)->ci_owner = 1;
}

static void hifc_init_scq_header(struct hifc_wq_header_s *v_queue_header)
{
	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE, v_queue_header, return);

	memset(v_queue_header, 0, sizeof(struct hifc_wq_header_s));

	/* Obit default is 1 */
	v_queue_header->db_record.pmsn = 1 << 15;
	v_queue_header->db_record.dump_pmsn =
				v_queue_header->db_record.pmsn;
	v_queue_header->ci_record.cmsn = 1 << 15;
	v_queue_header->ci_record.dump_cmsn =
				v_queue_header->ci_record.cmsn;

	/* Big endian convert */
	hifc_cpu_to_big64((void *)v_queue_header,
			  sizeof(struct hifc_wq_header_s));
}

static void hifc_cfg_scq_ctx(struct hifc_scq_info_s *v_scq_info,
			     struct hifcoe_cq_qinfo_s *v_scq_ctx)
{
	struct cqm_queue_s *cqm_scq_info = NULL;
	struct hifc_queue_info_bus_s queue_bus;
	unsigned long long parity = 0;

	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE, v_scq_info, return);

	cqm_scq_info = v_scq_info->cqm_scq_info;

	v_scq_ctx->pcie_template_hi = 0;
	v_scq_ctx->cur_cqe_gpa =
		cqm_scq_info->q_room_buf_1.buf_list->pa >> HIFC_CQE_GPA_SHIFT;
	v_scq_ctx->pi = 0;
	v_scq_ctx->pi_o = 1;
	v_scq_ctx->ci = v_scq_info->ci;
	v_scq_ctx->ci_o = v_scq_info->ci_owner;
	v_scq_ctx->c_eqn_msi_x = v_scq_info->msix_entry_idx;
	v_scq_ctx->ci_type = v_scq_info->scqc_ci_type;
	v_scq_ctx->cq_depth = v_scq_info->scqc_cq_depth;
	v_scq_ctx->armq = HIFC_ARMQ_IDLE;
	v_scq_ctx->cur_cqe_cnt = 0;
	v_scq_ctx->cqe_max_cnt = 0;
	v_scq_ctx->cqe_dmaattr_idx = 0;
	v_scq_ctx->cq_so_ro = 0;
	v_scq_ctx->init_mode = HIFC_CQ_INT_MODE;
	v_scq_ctx->next_o = 1;
	v_scq_ctx->loop_o = 1;
	v_scq_ctx->next_cq_wqe_page_gpa =
		cqm_scq_info->q_room_buf_1.buf_list[1].pa >>
		HIFC_NEXT_CQE_GPA_SHIFT;
	v_scq_ctx->pcie_template_lo = 0;

	v_scq_ctx->ci_gpa = (cqm_scq_info->q_header_paddr +
		offsetof(struct hifc_wq_header_s, ci_record)) >>
		HIFC_CQE_GPA_SHIFT;

	memset(&queue_bus, 0, sizeof(struct hifc_queue_info_bus_s));
	/* bits 20 */
	queue_bus.bus[0] |=
		((unsigned long long)(v_scq_info->scqn & 0xfffff));
	/* bits 3 */
	queue_bus.bus[0] |=
		(((unsigned long long)(v_scq_ctx->pcie_template_lo)) << 20);
	/* bits 28 */
	queue_bus.bus[0] |=
		(((unsigned long long)(v_scq_ctx->ci_gpa & 0xfffffff)) << 23);
	/* bits 6 */
	queue_bus.bus[0] |=
		(((unsigned long long)(v_scq_ctx->cqe_dmaattr_idx)) << 51);
	/* bits 2 */
	queue_bus.bus[0] |=
		(((unsigned long long)(v_scq_ctx->cq_so_ro)) << 57);
	/* bits 2 */
	queue_bus.bus[0] |=
		(((unsigned long long)(v_scq_ctx->init_mode)) << 59);
	/* bits 3 */
	queue_bus.bus[0] |=
		(((unsigned long long)(v_scq_ctx->c_eqn_msi_x & 0x7)) << 61);
	/* bits 7 */
	queue_bus.bus[1] |=
	((unsigned long long)(v_scq_ctx->c_eqn_msi_x >> 3));
	/* bits 1 */
	queue_bus.bus[1] |=
		(((unsigned long long)(v_scq_ctx->ci_type)) << 7);
	/* bits 3 */
	queue_bus.bus[1] |=
		(((unsigned long long)(v_scq_ctx->cq_depth)) << 8);
	/* bits 8 */
	queue_bus.bus[1] |=
		(((unsigned long long)(v_scq_ctx->cqe_max_cnt)) << 11);
	/* bits 3 */
	queue_bus.bus[1] |=
		(((unsigned long long)(v_scq_ctx->pcie_template_hi)) << 19);

	parity = hifc_get_parity_value(queue_bus.bus, HIFC_SCQC_BUS_ROW,
				       HIFC_SCQC_BUS_COL);
	v_scq_ctx->parity_0 = parity & 0x1;
	v_scq_ctx->parity_1 = (parity >> 0x1) & 0x1;
	v_scq_ctx->parity_2 = (parity >> 0x2) & 0x1;

	hifc_cpu_to_big64((void *)v_scq_ctx, sizeof(struct hifcoe_cq_qinfo_s));
}

static unsigned int hifc_create_scqc_via_cmdq_sync(
					struct hifc_hba_s *v_hba,
					struct hifcoe_cq_qinfo_s *v_scqc,
					unsigned int scqn)
{
#define HIFC_INIT_SCQC_TIMEOUT 3000

	int ret;
	unsigned int cvt_size;
	struct hifcoe_cmdqe_creat_scqc_s init_scqc_cmd;
	struct hifc_cmd_buf *cmdq_in_buf;

	cmdq_in_buf = hifc_alloc_cmd_buf(v_hba->hw_dev_handle);
	if (!cmdq_in_buf) {
		HIFC_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_IO_ATT, UNF_ERR,
			   "[err]cmdq in_cmd_buf alloc failed");

		HIFC_ERR_IO_STAT(v_hba, HIFCOE_TASK_T_INIT_SCQC);
		return UNF_RETURN_ERROR;
	}

	memset(&init_scqc_cmd, 0, sizeof(init_scqc_cmd));
	init_scqc_cmd.wd0.task_type = HIFCOE_TASK_T_INIT_SCQC;
	init_scqc_cmd.wd1.scqn = HIFC_LSW(scqn);
	cvt_size = sizeof(init_scqc_cmd) - sizeof(init_scqc_cmd.scqc);
	hifc_cpu_to_big32(&init_scqc_cmd, cvt_size);

	/* v_scqc is already big endian */
	memcpy(init_scqc_cmd.scqc, v_scqc, sizeof(*v_scqc));
	memcpy(cmdq_in_buf->buf, &init_scqc_cmd, sizeof(init_scqc_cmd));
	cmdq_in_buf->size = sizeof(init_scqc_cmd);

	ret = hifc_cmdq_detail_resp(v_hba->hw_dev_handle, HIFC_ACK_TYPE_CMDQ,
				    HIFC_MOD_FCOE, 0,
				    cmdq_in_buf, NULL, HIFC_INIT_SCQC_TIMEOUT);
	hifc_free_cmd_buf(v_hba->hw_dev_handle, cmdq_in_buf);
	if (ret) {
		HIFC_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_IO_ATT, UNF_ERR,
			   "[err]Send creat scqc via cmdq failed, ret=%d", ret);

		HIFC_ERR_IO_STAT(v_hba, HIFCOE_TASK_T_INIT_SCQC);
		return UNF_RETURN_ERROR;
	}

	HIFC_IO_STAT(v_hba, HIFCOE_TASK_T_INIT_SCQC);

	return RETURN_OK;
}

static unsigned int hifc_create_scq(struct hifc_hba_s *v_hba)
{
	unsigned int ret = UNF_RETURN_ERROR;
	unsigned int scq_index = 0;
	unsigned int scq_cfg_num = 0;
	struct cqm_queue_s *cqm_scq = NULL;
	void *handle = NULL;
	struct hifc_scq_info_s *scq_info = NULL;
	struct hifcoe_cq_qinfo_s scq_ctx_info;

	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE, v_hba,
			return UNF_RETURN_ERROR);

	handle = v_hba->hw_dev_handle;

	/* Create SCQ by CQM interface */
	for (scq_index = 0; scq_index < HIFC_TOTAL_SCQ_NUM; scq_index++) {
		/*
		 * 1. Create/Allocate SCQ
		 *
		 * Notice: SCQ[0, 2, 4 ...]--->CMD SCQ,
		 * SCQ[1, 3, 5 ...]--->STS SCQ, SCQ[HIFC_TOTAL_SCQ_NUM-1]
		 * --->Defaul SCQ
		 */
		cqm_scq = cqm_object_nonrdma_queue_create(
						handle,
						CQM_OBJECT_NONRDMA_SCQ,
						HIFC_SCQ_IS_STS(scq_index) ?
						HIFC_STS_SCQ_DEPTH :
						HIFC_CMD_SCQ_DEPTH,
						HIFC_SCQE_SIZE,
						v_hba);
		if (!cqm_scq) {
			HIFC_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_REG_ATT,
				   UNF_WARN, "[err]Create scq failed");

			goto free_scq;
		}

		/* 2. Initialize SCQ (info) */
		hifc_init_scq_info(v_hba, cqm_scq, scq_index, &scq_info);

		/* 3. Allocate & Initialize SCQ interrupt */
		ret = hifc_alloc_scq_int(scq_info);
		if (ret != RETURN_OK) {
			HIFC_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_REG_ATT,
				   UNF_WARN, "[err]Allocate scq interrupt failed");

			cqm_object_delete(&cqm_scq->object);
			memset(scq_info, 0, sizeof(struct hifc_scq_info_s));
			goto free_scq;
		}

		/* 4. Initialize SCQ queue header */
		hifc_init_scq_header(
			(struct hifc_wq_header_s *)
			(void *)cqm_scq->q_header_vaddr);

		/* 5. Initialize & Create SCQ CTX */
		memset(&scq_ctx_info, 0, sizeof(scq_ctx_info));
		hifc_cfg_scq_ctx(scq_info, &scq_ctx_info);
		ret = hifc_create_scqc_via_cmdq_sync(v_hba,
						     &scq_ctx_info,
						     scq_info->scqn);
		if (ret != RETURN_OK) {
			HIFC_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_REG_ATT,
				   UNF_WARN, "[err]Create scq context failed");

			cqm_object_delete(&cqm_scq->object);
			memset(scq_info, 0, sizeof(struct hifc_scq_info_s));
			goto free_scq;
		}

		HIFC_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_REG_ATT, UNF_INFO,
			   "[info]Create SCQ[%u] Scqn=%u WqeNum=%u WqeSize=%u WqePerBuf=%u CqDepth=%u CiType=%u irq=%u msix=%u",
			   scq_info->queue_id, scq_info->scqn,
			   scq_info->valid_wqe_num, scq_info->wqe_size,
			   scq_info->wqe_num_per_buf, scq_info->scqc_cq_depth,
			   scq_info->scqc_ci_type, scq_info->irq_id,
			   scq_info->msix_entry_idx);
	}

	/*
	 * Last SCQ is used to handle SCQE delivery access when clearing buffer
	 */
	v_hba->default_scqn = scq_info->scqn;

	HIFC_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_REG_ATT, UNF_MAJOR,
		   "[info]Default Scqn=%d CqmScqIndex=%u",
		   v_hba->default_scqn, cqm_scq->index);

	return RETURN_OK;

free_scq:
	hifc_flush_scq_ctx(v_hba);

	scq_cfg_num = scq_index;
	for (scq_index = 0; scq_index < scq_cfg_num; scq_index++) {
		scq_info = &v_hba->scq_info[scq_index];
		hifc_free_scq_int(scq_info);
		cqm_scq = scq_info->cqm_scq_info;
		cqm_object_delete(&cqm_scq->object);
		memset(scq_info, 0, sizeof(struct hifc_scq_info_s));
	}

	return UNF_RETURN_ERROR;
}

static void hifc_destroy_scq(struct hifc_hba_s *v_hba)
{
	unsigned int scq_index = 0;
	struct cqm_queue_s *cqm_scq = NULL;
	struct hifc_scq_info_s *scq_info = NULL;

	HIFC_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_REG_ATT, UNF_MAJOR,
		   "[info]Start destroy total %d SCQ", HIFC_TOTAL_SCQ_NUM);

	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE, v_hba, return);

	/* Use CQM to delete SCQ */
	for (scq_index = 0; scq_index < HIFC_TOTAL_SCQ_NUM; scq_index++) {
		scq_info = &v_hba->scq_info[scq_index];

		HIFC_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_REG_ATT, UNF_ALL,
			   "[info]Destroy SCQ%u, Scqn=%u, Irq=%u, msix=%u, name=%s",
			   scq_index, scq_info->scqn, scq_info->irq_id,
			   scq_info->msix_entry_idx, scq_info->irq_name);

		hifc_free_scq_int(scq_info);
		cqm_scq = scq_info->cqm_scq_info;
		cqm_object_delete(&cqm_scq->object);
		memset(scq_info, 0, sizeof(struct hifc_scq_info_s));
	}
}

static void hifc_init_srq_info(struct hifc_hba_s *v_hba,
			       struct cqm_queue_s *v_cqm_srq,
			       struct hifc_srq_info_s *v_srq_info)
{
	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE, v_hba, return);
	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE, v_cqm_srq, return);
	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE, v_srq_info, return);

	v_srq_info->phba = (void *)v_hba;

	v_srq_info->cqm_srq_info = v_cqm_srq;
	v_srq_info->wqe_num_per_buf = v_cqm_srq->q_room_buf_1.buf_size /
				      HIFC_SRQE_SIZE - 1;
	v_srq_info->wqe_size = HIFC_SRQE_SIZE;
	v_srq_info->valid_wqe_num = v_cqm_srq->valid_wqe_num;
	v_srq_info->pi = 0;
	v_srq_info->pi_owner = HIFC_SRQ_INIT_LOOP_O;
	v_srq_info->pmsn = 0;
	v_srq_info->srqn = v_cqm_srq->index;
	v_srq_info->first_rqe_rcv_dma = 0;

	HIFC_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_REG_ATT, UNF_MAJOR,
		   "[info]Init srq info(srq index 0x%x) valid wqe num 0x%x, buffer size 0x%x, wqe num per buf 0x%x",
		   v_cqm_srq->index, v_srq_info->valid_wqe_num,
		   v_cqm_srq->q_room_buf_1.buf_size,
		   v_srq_info->wqe_num_per_buf);
}

static void hifc_init_srq_header(struct hifc_wq_header_s *v_queue_header)
{
	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE, v_queue_header, return);

	memset(v_queue_header, 0, sizeof(struct hifc_wq_header_s));
}

static struct hifcoe_rqe_s *hifc_get_srq_entry(
				struct hifc_srq_info_s *v_srq_info,
				struct hifcoe_rqe_s **v_linked_rqe,
				unsigned short position)
{
	unsigned int buf_id = 0;
	unsigned int wqe_num_per_buf = 0;
	unsigned short buf_offset = 0;
	struct cqm_buf_list_s *buf = NULL;

	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE, v_srq_info, return NULL);

	wqe_num_per_buf = v_srq_info->wqe_num_per_buf;

	buf_id = position / wqe_num_per_buf;
	buf = &v_srq_info->cqm_srq_info->q_room_buf_1.buf_list[buf_id];
	buf_offset = position % ((unsigned short)wqe_num_per_buf);

	if (buf_offset + 1 == wqe_num_per_buf)
		*v_linked_rqe = (struct hifcoe_rqe_s *)(buf->va) +
				wqe_num_per_buf;
	else
		*v_linked_rqe = NULL;

	return (struct hifcoe_rqe_s *)(buf->va) + buf_offset;
}

/**
 * hifc_set_srq_wqe_owner_be - Assign a value to Owner Bit of WQE in the
 *                       big-endian format of Wqe Page.
 * @v_sqe_ctrl_in_wp: sqe ctrl wqe struct info for communicate with uncode
 * @owner: owner value which need to set
 */
static void hifc_set_srq_wqe_owner_be(
			struct hifcoe_wqe_ctrl_s *v_sqe_ctrl_in_wp,
			unsigned int owner)
{
	struct hifcoe_wqe_ctrl_ch_s wqe_ctrl_ch;

	mb();

	wqe_ctrl_ch.ctrl_ch_val = be32_to_cpu(v_sqe_ctrl_in_wp->ch.ctrl_ch_val);
	wqe_ctrl_ch.wd0.owner = owner;
	v_sqe_ctrl_in_wp->ch.ctrl_ch_val = cpu_to_be32(wqe_ctrl_ch.ctrl_ch_val);

	mb();
}

static void hifc_set_srq_link_wqe_owner_be(struct hifc_link_wqe_s *v_link_wqe,
					   unsigned int owner,
					   unsigned short pmsn)
{
	struct hifc_link_wqe_s local_lw;

	mb();
	local_lw.val_wd1 = be32_to_cpu(v_link_wqe->val_wd1);
	local_lw.wd1.msn = pmsn;
	local_lw.wd1.dump_msn = (local_lw.wd1.msn & 0x7fff);
	v_link_wqe->val_wd1 = cpu_to_be32(local_lw.val_wd1);

	local_lw.val_wd0 = be32_to_cpu(v_link_wqe->val_wd0);
	local_lw.wd0.o = owner;
	v_link_wqe->val_wd0 = cpu_to_be32(local_lw.val_wd0);
	mb();
}

void hifc_post_els_srq_wqe(struct hifc_srq_info_s *v_srq_info,
			   unsigned short buff_id)
{
	struct hifcoe_rqe_s *rqe = NULL;
	struct hifcoe_rqe_s tmp_rqe;
	struct hifcoe_rqe_s *linked_rqe = NULL;
	struct hifc_wq_header_s *wq_header = NULL;
	struct hifc_srq_buff_entry_s *buff_entry = NULL;

	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE, v_srq_info, return);
	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE,
			buff_id < v_srq_info->valid_wqe_num, return);

	buff_entry = v_srq_info->els_buff_entry_head + buff_id;

	spin_lock(&v_srq_info->srq_spin_lock);

	/* Obtain RQE, not include link wqe */
	rqe = hifc_get_srq_entry(v_srq_info, &linked_rqe, v_srq_info->pi);
	if (!rqe) {
		HIFC_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_REG_ATT, UNF_ERR,
			   "[err]post els srq,get srqe failed, valid wqe num 0x%x, pi 0x%x, pmsn 0x%x",
			   v_srq_info->valid_wqe_num, v_srq_info->pi,
			   v_srq_info->pmsn);

		spin_unlock(&v_srq_info->srq_spin_lock);

		return;
	}

	/* Initialize RQE */
	/* cs section is not used */
	memset(&tmp_rqe, 0, sizeof(struct hifcoe_rqe_s));

	/* default Obit is invalid, and set valid finally */
	hifc_build_srq_wqe_ctrls(&tmp_rqe, !v_srq_info->pi_owner,
				 v_srq_info->pmsn + 1);

	tmp_rqe.bds_sl.buf_addr_hi = HIFC_HIGH_32_BITS(buff_entry->buff_dma);
	tmp_rqe.bds_sl.buf_addr_lo = HIFC_LOW_32_BITS(buff_entry->buff_dma);
	tmp_rqe.drv_sl.wd0.user_id = buff_id;

	/* convert to big endian */
	hifc_cpu_to_big32(&tmp_rqe, sizeof(struct hifcoe_rqe_s));

	memcpy(rqe, &tmp_rqe, sizeof(struct hifcoe_rqe_s));

	/* reset Obit */
	hifc_set_srq_wqe_owner_be(
			(struct hifcoe_wqe_ctrl_s *)(void *)&rqe->ctrl_sl,
			v_srq_info->pi_owner);

	if (linked_rqe) {
		/* Update Obit in linked WQE */
		hifc_set_srq_link_wqe_owner_be(
			(struct hifc_link_wqe_s *)(void *)linked_rqe,
			v_srq_info->pi_owner,
			v_srq_info->pmsn + 1);
	}

	/* Update PI and PMSN */
	hifc_update_producer_info((unsigned short)(v_srq_info->valid_wqe_num),
				  &v_srq_info->pi,
				  &v_srq_info->pi_owner);

	/*
	 * pmsn is 16bit. The value is added to the maximum value and is
	 * automatically reversed
	 */
	v_srq_info->pmsn++;

	/* Update pmsn in queue header */
	wq_header = (struct hifc_wq_header_s *)
		    (void *)v_srq_info->cqm_srq_info->q_header_vaddr;
	hifc_update_srq_header(&wq_header->db_record, v_srq_info->pmsn);

	spin_unlock(&v_srq_info->srq_spin_lock);
}

static void hifc_cfg_srq_ctx(struct hifc_srq_info_s *v_srq_info,
			     struct hifc_srq_ctx_s *v_srq_ctx,
			     unsigned int v_sge_size,
			     unsigned long long v_rqe_gpa)
{
	struct hifc_srq_ctx_s *srq_ctx = NULL;
	struct cqm_queue_s *cqm_srq_info = NULL;
	struct hifc_queue_info_bus_s queue_bus;

	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE, v_srq_info, return);
	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE, v_srq_ctx, return);

	cqm_srq_info = v_srq_info->cqm_srq_info;
	srq_ctx = v_srq_ctx;

	srq_ctx->last_rq_pmsn = 0;
	srq_ctx->cur_rqe_msn = 0;
	srq_ctx->pcie_template = 0;
	/* The value of CTX needs to be updated when RQE is configured */
	srq_ctx->cur_rqe_gpa = v_rqe_gpa;
	srq_ctx->cur_sge_v = 0;
	srq_ctx->cur_sge_l = 0;
	/* The information received by the SRQ is reported through the SCQ.
	 * The interrupt and ArmCQ are disabled.
	 */
	srq_ctx->ceqn_msix = 0;
	srq_ctx->int_mode = 0;
	srq_ctx->cur_sge_remain_len = 0;
	srq_ctx->cur_sge_id = 0;
	srq_ctx->consant_sge_len = v_sge_size;
	srq_ctx->cur_wqe = 0;
	srq_ctx->pmsn_type = HIFC_PMSN_CI_TYPE_FROM_HOST;
	srq_ctx->bdsl = 0;
	srq_ctx->cr = 0;
	srq_ctx->csl = 0;
	srq_ctx->cf = 0;
	srq_ctx->ctrl_sl = 0;
	srq_ctx->cur_sge_gpa = 0;
	srq_ctx->cur_pmsn_gpa = cqm_srq_info->q_header_paddr;
	srq_ctx->pre_fetch_max_msn = 0;
	srq_ctx->cqe_max_cnt = 0;
	srq_ctx->cur_cqe_cnt = 0;
	srq_ctx->arm_q = 0;
	srq_ctx->cq_so_ro = 0;
	srq_ctx->cqe_dma_attr_idx = 0;
	srq_ctx->rq_so_ro = 0;
	srq_ctx->rqe_dma_attr_idx = 0;
	srq_ctx->loop_o = HIFC_SRQ_INIT_LOOP_O;
	srq_ctx->ring = HIFC_QUEUE_RING;

	memset(&queue_bus, 0, sizeof(struct hifc_queue_info_bus_s));
	/* bits 60 */
	queue_bus.bus[0] |=
		((unsigned long long)(cqm_srq_info->q_ctx_paddr >> 4));
	/* bits 4 */
	queue_bus.bus[0] |=
		(((unsigned long long)(srq_ctx->rqe_dma_attr_idx & 0xf)) << 60);
	/* bits 2 */
	queue_bus.bus[1] |=
		((unsigned long long)(srq_ctx->rqe_dma_attr_idx >> 4));
	/* bits 2 */
	queue_bus.bus[1] |= (((unsigned long long)(srq_ctx->rq_so_ro)) << 2);
	/* bits 60 */
	queue_bus.bus[1] |=
		(((unsigned long long)(srq_ctx->cur_pmsn_gpa >> 4)) << 4);
	/* bits 17 */
	queue_bus.bus[2] |= ((unsigned long long)(srq_ctx->consant_sge_len));
	/* bits 6 */
	queue_bus.bus[2] |=
		(((unsigned long long)(srq_ctx->pcie_template)) << 17);

	srq_ctx->parity = hifc_get_parity_value((void *)queue_bus.bus,
						HIFC_SRQC_BUS_ROW,
						HIFC_SRQC_BUS_COL);

	hifc_cpu_to_big64((void *)srq_ctx, sizeof(struct hifc_srq_ctx_s));
}

static unsigned int hifc_create_srqc_via_cmdq_sync(
				struct hifc_hba_s *v_hba,
				struct hifc_srq_ctx_s *v_srqc,
				unsigned long long v_ctx_gpa)
{
#define HIFC_INIT_SRQC_TIMEOUT 3000

	int ret;
	unsigned int cvt_size;
	struct hifcoe_cmdqe_creat_srqc_s init_srqc_cmd;
	struct hifc_cmd_buf *cmdq_in_buf;

	cmdq_in_buf = hifc_alloc_cmd_buf(v_hba->hw_dev_handle);
	if (!cmdq_in_buf) {
		HIFC_TRACE(UNF_EVTLOG_IO_ERR, UNF_LOG_IO_ATT, UNF_ERR,
			   "[err]cmdq in_cmd_buf alloc failed");

		HIFC_ERR_IO_STAT(v_hba, HIFCOE_TASK_T_INIT_SRQC);
		return UNF_RETURN_ERROR;
	}

	memset(&init_srqc_cmd, 0, sizeof(init_srqc_cmd));
	init_srqc_cmd.wd0.task_type = HIFCOE_TASK_T_INIT_SRQC;
	init_srqc_cmd.srqc_gpa_h = HIFC_HIGH_32_BITS(v_ctx_gpa);
	init_srqc_cmd.srqc_gpa_l = HIFC_LOW_32_BITS(v_ctx_gpa);
	cvt_size = sizeof(init_srqc_cmd) - sizeof(init_srqc_cmd.srqc);
	hifc_cpu_to_big32(&init_srqc_cmd, cvt_size);

	/* v_srqc is already big-endian */
	memcpy(init_srqc_cmd.srqc, v_srqc, sizeof(*v_srqc));
	memcpy(cmdq_in_buf->buf, &init_srqc_cmd, sizeof(init_srqc_cmd));
	cmdq_in_buf->size = sizeof(init_srqc_cmd);

	ret = hifc_cmdq_detail_resp(v_hba->hw_dev_handle, HIFC_ACK_TYPE_CMDQ,
				    HIFC_MOD_FCOE, 0, cmdq_in_buf,
				    NULL, HIFC_INIT_SRQC_TIMEOUT);

	hifc_free_cmd_buf(v_hba->hw_dev_handle, cmdq_in_buf);

	if (ret) {
		HIFC_TRACE(UNF_EVTLOG_IO_ERR, UNF_LOG_IO_ATT, UNF_ERR,
			   "[err]Send creat srqc via cmdq failed, ret=%d", ret);

		HIFC_ERR_IO_STAT(v_hba, HIFCOE_TASK_T_INIT_SRQC);
		return UNF_RETURN_ERROR;
	}

	HIFC_IO_STAT(v_hba, HIFCOE_TASK_T_INIT_SRQC);

	return RETURN_OK;
}

static void hifc_init_els_srq_wqe(struct hifc_srq_info_s *v_srq_info)
{
	unsigned int rqe_index = 0;
	struct hifc_srq_buff_entry_s *buff_entry = NULL;

	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE, v_srq_info, return);

	for (rqe_index = 0; rqe_index < v_srq_info->valid_wqe_num - 1;
	     rqe_index++) {
		buff_entry = v_srq_info->els_buff_entry_head + rqe_index;

		hifc_post_els_srq_wqe(v_srq_info, buff_entry->buff_id);
	}
}

static void hifc_free_els_srq_buff(struct hifc_hba_s *v_hba,
				   unsigned int srq_valid_wqe)
{
	unsigned int buff_index = 0;
	struct hifc_srq_info_s *srq_info = NULL;
	struct hifc_srq_buff_entry_s *buff_entry = NULL;

	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE, v_hba, return);

	srq_info = &v_hba->els_srq_info;

	if (!srq_info->els_buff_entry_head)
		return;

	for (buff_index = 0; buff_index < srq_valid_wqe; buff_index++) {
		buff_entry = &srq_info->els_buff_entry_head[buff_index];
		buff_entry->buff_addr = NULL;
	}

	if (srq_info->buff_list.buflist) {
		for (buff_index = 0; buff_index < srq_info->buff_list.buf_num;
		     buff_index++) {
			if (srq_info->buff_list.buflist[buff_index].paddr) {
				pci_unmap_single(
					v_hba->pci_dev,
					srq_info->buff_list.buflist[buff_index].paddr,
					srq_info->buff_list.buf_size,
					DMA_FROM_DEVICE);
				srq_info->buff_list.buflist[buff_index].paddr = 0;
			}
			if (srq_info->buff_list.buflist[buff_index].vaddr) {
				kfree(srq_info->buff_list.buflist[buff_index].vaddr);
				srq_info->buff_list.buflist[buff_index].vaddr = NULL;
			}
		}

		kfree(srq_info->buff_list.buflist);
		srq_info->buff_list.buflist = NULL;
	}

	if (srq_info->els_buff_entry_head) {
		kfree(srq_info->els_buff_entry_head);
		srq_info->els_buff_entry_head = NULL;
	}
}

static unsigned int hifc_alloc_els_srq_buff(struct hifc_hba_s *v_hba,
					    unsigned int srq_valid_wqe)
{
	unsigned int req_buff_size = 0;
	unsigned int buff_index = 0;
	struct hifc_srq_info_s *srq_info = NULL;
	struct hifc_srq_buff_entry_s *buff_entry = NULL;
	unsigned int buf_total_size;
	unsigned int buf_num;
	unsigned int alloc_idx;
	unsigned int cur_buf_idx = 0;
	unsigned int cur_buf_offset = 0;
	unsigned int buf_cnt_perhugebuf;

	srq_info = &v_hba->els_srq_info;

	/* Apply for entry buffer */
	req_buff_size = (unsigned int)(srq_valid_wqe *
			sizeof(struct hifc_srq_buff_entry_s));
	srq_info->els_buff_entry_head =
		(struct hifc_srq_buff_entry_s *)kmalloc(req_buff_size,
							GFP_KERNEL);
	if (!srq_info->els_buff_entry_head) {
		HIFC_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_REG_ATT, UNF_WARN,
			   "[err]Allocate ELS Srq receive buffer entrys failed");

		return UNF_RETURN_ERROR;
	}
	memset(srq_info->els_buff_entry_head, 0, req_buff_size);

	buf_total_size = HIFC_SRQ_ELS_SGE_LEN * srq_valid_wqe;

	srq_info->buff_list.buf_size =
		buf_total_size > BUF_LIST_PAGE_SIZE ?
		BUF_LIST_PAGE_SIZE : buf_total_size;
	buf_cnt_perhugebuf =
		srq_info->buff_list.buf_size / HIFC_SRQ_ELS_SGE_LEN;
	buf_num = srq_valid_wqe % buf_cnt_perhugebuf ? srq_valid_wqe /
		  buf_cnt_perhugebuf + 1 : srq_valid_wqe /
			  buf_cnt_perhugebuf;
	srq_info->buff_list.buflist = (struct buff_list_s *)
			kmalloc(buf_num * sizeof(struct buff_list_s),
				GFP_KERNEL);
	srq_info->buff_list.buf_num = buf_num;

	if (!srq_info->buff_list.buflist) {
		HIFC_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_REG_ATT, UNF_WARN,
			   "[err]Allocate ELS buf list failed out of memory");
		goto free_buff;
	}
	memset(srq_info->buff_list.buflist, 0,
	       buf_num * sizeof(struct buff_list_s));

	for (alloc_idx = 0; alloc_idx < buf_num; alloc_idx++) {
		srq_info->buff_list.buflist[alloc_idx].vaddr =
			kmalloc(srq_info->buff_list.buf_size, GFP_KERNEL);
		if (!srq_info->buff_list.buflist[alloc_idx].vaddr)
			goto free_buff;
		memset(srq_info->buff_list.buflist[alloc_idx].vaddr, 0,
		       srq_info->buff_list.buf_size);

		srq_info->buff_list.buflist[alloc_idx].paddr =
			pci_map_single(
				v_hba->pci_dev,
				srq_info->buff_list.buflist[alloc_idx].vaddr,
				srq_info->buff_list.buf_size, DMA_FROM_DEVICE);
		if (pci_dma_mapping_error(
				v_hba->pci_dev,
				srq_info->buff_list.buflist[alloc_idx].paddr)) {
			srq_info->buff_list.buflist[alloc_idx].paddr = 0;
			HIFC_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_REG_ATT,
				   UNF_WARN, "[err]Map els srq buffer failed");

			goto free_buff;
		}
	}

	/* Apply for receiving buffer and attach it to the free linked list */
	for (buff_index = 0; buff_index < srq_valid_wqe; buff_index++) {
		buff_entry = &srq_info->els_buff_entry_head[buff_index];

		cur_buf_idx = buff_index / buf_cnt_perhugebuf;

		cur_buf_offset = HIFC_SRQ_ELS_SGE_LEN *
				(buff_index % buf_cnt_perhugebuf);
		buff_entry->buff_addr =
			srq_info->buff_list.buflist[cur_buf_idx].vaddr +
			cur_buf_offset;

		buff_entry->buff_dma =
			srq_info->buff_list.buflist[cur_buf_idx].paddr +
			cur_buf_offset;

		buff_entry->buff_id = (unsigned short)buff_index;
	}

	UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_REG_ATT, UNF_INFO,
		  "[EVENT]Allocate bufnum:%u,buf_total_size:%u",
		  buf_num, buf_total_size);

	return RETURN_OK;

free_buff:
	hifc_free_els_srq_buff(v_hba, srq_valid_wqe);
	return UNF_RETURN_ERROR;
}

/**
 * hifc_root_cmdq_enqueue - Send commands to the chip via ROOT CMDQ.
 * @v_hba: hba handler to send cmd
 * @v_cmdqe: cmdqe buff
 * @cmd_len: cmdqe buff len
 * @Return: 0 - success, negative - failure
 */
unsigned int hifc_root_cmdq_enqueue(void *v_hba, union hifc_cmdqe_u *v_cmdqe,
				    unsigned short cmd_len)
{
	unsigned char wqe_type = 0;
	int cmdq_ret = 0;
	struct hifc_cmd_buf *cmdq_buf = NULL;
	struct hifc_hba_s *hba = NULL;

	hba = (struct hifc_hba_s *)v_hba;
	wqe_type = (unsigned char)v_cmdqe->common.wd0.task_type;
	HIFC_IO_STAT(hba, wqe_type);

	cmdq_buf = hifc_alloc_cmd_buf(hba->hw_dev_handle);
	if (!cmdq_buf) {
		HIFC_ERR_IO_STAT(hba, wqe_type);
		UNF_TRACE(UNF_EVTLOG_IO_WARN, UNF_LOG_IO_ATT, UNF_WARN,
			  "[warn]Port(0x%x) CqmHandle(0x%p) allocate cmdq buffer failed",
			  hba->port_cfg.port_id, hba->hw_dev_handle);

		return UNF_RETURN_ERROR;
	}

	memcpy(cmdq_buf->buf, v_cmdqe, cmd_len);
	hifc_cpu_to_big32(cmdq_buf->buf, cmd_len);
	cmdq_buf->size = cmd_len;

	cmdq_ret = hifc_cmdq_async(hba->hw_dev_handle, HIFC_ACK_TYPE_CMDQ,
				   HIFC_MOD_FCOE, 0, cmdq_buf);

	if (cmdq_ret != RETURN_OK) {
		hifc_free_cmd_buf(hba->hw_dev_handle, cmdq_buf);
		HIFC_ERR_IO_STAT(hba, wqe_type);

		UNF_TRACE(UNF_EVTLOG_IO_WARN, UNF_LOG_IO_ATT, UNF_WARN,
			  "[warn]Port(0x%x) CqmHandle(0x%p) send buff clear cmnd failed(0x%x)",
			  hba->port_cfg.port_id, hba->hw_dev_handle, cmdq_ret);

		return UNF_RETURN_ERROR;
	}
	UNF_REFERNCE_VAR(wqe_type);
	return RETURN_OK;
}

static void hifc_send_clear_srq_cmd(struct hifc_hba_s *v_hba,
				    struct hifc_srq_info_s *v_srq_info)
{
	union hifc_cmdqe_u cmdqe;
	struct cqm_queue_s *cqm_fcp_srq = NULL;
	unsigned long flag = 0;

	memset(&cmdqe, 0, sizeof(union hifc_cmdqe_u));

	spin_lock_irqsave(&v_srq_info->srq_spin_lock, flag);

	cqm_fcp_srq = v_srq_info->cqm_srq_info;
	if (!cqm_fcp_srq) {
		v_srq_info->state = HIFC_CLEAN_DONE;
		spin_unlock_irqrestore(&v_srq_info->srq_spin_lock, flag);
		return;
	}

	cmdqe.clear_srq.wd0.task_type = HIFCOE_TASK_T_CLEAR_SRQ;
	cmdqe.clear_srq.wd1.scqn = HIFC_LSW(v_hba->default_scqn);
	cmdqe.clear_srq.wd1.srq_type = v_srq_info->srq_type;
	cmdqe.clear_srq.srqc_gpa_h = HIFC_HIGH_32_BITS(
					cqm_fcp_srq->q_ctx_paddr);
	cmdqe.clear_srq.srqc_gpa_l = HIFC_LOW_32_BITS(cqm_fcp_srq->q_ctx_paddr);

	(void)queue_delayed_work(v_hba->work_queue,
				 &v_srq_info->del_work,
				 (unsigned long)msecs_to_jiffies((
				 unsigned int)HIFC_SRQ_DEL_STAGE_TIMEOUT_MS));

	spin_unlock_irqrestore(&v_srq_info->srq_spin_lock, flag);

	HIFC_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_REG_ATT, UNF_MAJOR,
		   "[info]Port 0x%x begin to clear srq 0x%x(0x%x,0x%llx)",
		   v_hba->port_cfg.port_id, v_srq_info->srq_type,
		   HIFC_LSW(v_hba->default_scqn),
		   (unsigned long long)cqm_fcp_srq->q_ctx_paddr);

	/* Run the ROOT CMDQ command to issue the clear srq command.
	 *  If the command fails to be delivered, retry upon timeout.
	 */
	(void)hifc_root_cmdq_enqueue(v_hba, &cmdqe, sizeof(cmdqe.clear_srq));
}

static void hifc_srq_clr_time_out(struct work_struct *work)
{
	struct hifc_srq_info_s *srq = NULL;
	struct hifc_hba_s *hba = NULL;
	struct cqm_queue_s *cqm_fcp_imm_srq = NULL;
	unsigned long flag = 0;

	srq = container_of(work, struct hifc_srq_info_s, del_work.work);

	spin_lock_irqsave(&srq->srq_spin_lock, flag);
	hba = srq->phba;
	cqm_fcp_imm_srq = srq->cqm_srq_info;
	spin_unlock_irqrestore(&srq->srq_spin_lock, flag);

	if (hba && cqm_fcp_imm_srq) {
		HIFC_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_REG_ATT, UNF_WARN,
			   "[warn]Port 0x%x clear srq 0x%x stat 0x%x timeout",
			   hba->port_cfg.port_id, srq->srq_type, srq->state);

		/*
		 * If the delivery fails or the execution times out after the
		 * delivery, try again once
		 */
		srq->del_retry_time++;

		if (srq->del_retry_time < 2)
			hifc_send_clear_srq_cmd(hba, srq);
		else
			srq->del_retry_time = 0;
	}
}

static unsigned int hifc_create_els_srq(struct hifc_hba_s *v_hba)
{
	unsigned int ret = UNF_RETURN_ERROR;
	struct cqm_queue_s *cqm_srq = NULL;
	struct hifc_wq_header_s *wq_header = NULL;
	struct hifc_srq_info_s *srq_info = NULL;
	struct hifc_srq_ctx_s srq_ctx = { 0 };

	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE, v_hba,
			return UNF_RETURN_ERROR);

	cqm_srq = cqm_object_fc_srq_create(v_hba->hw_dev_handle,
					   CQM_OBJECT_NONRDMA_SRQ,
					   HIFC_SRQ_ELS_DATA_DEPTH,
					   HIFC_SRQE_SIZE,
					   v_hba);
	if (!cqm_srq) {
		HIFC_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_REG_ATT, UNF_WARN,
			   "[err]Create Els Srq failed");

		return UNF_RETURN_ERROR;
	}

	/* Initialize SRQ */
	srq_info = &v_hba->els_srq_info;
	hifc_init_srq_info(v_hba, cqm_srq, srq_info);
	srq_info->srq_type = HIFC_SRQ_ELS;
	srq_info->enable = UNF_TRUE;
	srq_info->state = HIFC_CLEAN_DONE;
	srq_info->del_retry_time = 0;

	/* The srq lock is initialized and can be created repeatedly */
	spin_lock_init(&srq_info->srq_spin_lock);
	srq_info->spin_lock_init = UNF_TRUE;

	/* Initialize queue header */
	wq_header = (struct hifc_wq_header_s *)(void *)cqm_srq->q_header_vaddr;
	hifc_init_srq_header(wq_header);

	INIT_DELAYED_WORK(&srq_info->del_work, hifc_srq_clr_time_out);

	/* Apply for RQ buffer */
	ret = hifc_alloc_els_srq_buff(v_hba, srq_info->valid_wqe_num);
	if (ret != RETURN_OK) {
		HIFC_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_REG_ATT, UNF_WARN,
			   "[err]Allocate Els Srq buffer failed");

		cqm_object_delete(&cqm_srq->object);
		memset(srq_info, 0, sizeof(struct hifc_srq_info_s));
		return UNF_RETURN_ERROR;
	}

	/* Fill RQE, update queue header */
	hifc_init_els_srq_wqe(srq_info);

	/* Fill SRQ CTX */
	memset(&srq_ctx, 0, sizeof(srq_ctx));
	hifc_cfg_srq_ctx(srq_info, &srq_ctx, HIFC_SRQ_ELS_SGE_LEN,
			 srq_info->cqm_srq_info->q_room_buf_1.buf_list->pa);

	ret = hifc_create_srqc_via_cmdq_sync(
				v_hba, &srq_ctx,
				srq_info->cqm_srq_info->q_ctx_paddr);
	if (ret != RETURN_OK) {
		HIFC_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_REG_ATT, UNF_ERR,
			   "[err]Creat Els Srqc failed");

		hifc_free_els_srq_buff(v_hba, srq_info->valid_wqe_num);
		cqm_object_delete(&cqm_srq->object);
		memset(srq_info, 0, sizeof(struct hifc_srq_info_s));

		return UNF_RETURN_ERROR;
	}

	return RETURN_OK;
}

void hifc_destroy_srq(void *v_hba)
{
	/*
	 * Receive clear els srq sts
	 * ---then--->>> destroy els srq
	 */
	struct hifc_hba_s *hba = NULL;
	struct hifc_srq_info_s *srq_info = NULL;

	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE, NULL != v_hba, return);

	hba = (struct hifc_hba_s *)v_hba;
	srq_info = &hba->els_srq_info;

	/* release receive buffer */
	hifc_free_els_srq_buff(hba, srq_info->valid_wqe_num);

	/* release srq info */
	if (srq_info->cqm_srq_info) {
		cqm_object_delete(&srq_info->cqm_srq_info->object);
		srq_info->cqm_srq_info = NULL;
	}
	if (srq_info->spin_lock_init)
		srq_info->spin_lock_init = UNF_FALSE;
	srq_info->phba = NULL;
	srq_info->enable = UNF_FALSE;
	srq_info->state = HIFC_CLEAN_DONE;
}

/**
 * hifc_create_srq - Create SRQ, which contains four SRQ for receiving
 *                       instant data and a SRQ for receiving ELS data.
 * @v_hba: hba handler
 * @Return: 0 - success, negative - failure
 */
static unsigned int hifc_create_srq(struct hifc_hba_s *v_hba)
{
	unsigned int ret = UNF_RETURN_ERROR;

	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE, v_hba,
			return UNF_RETURN_ERROR);

	/* Create ELS SRQ */
	ret = hifc_create_els_srq(v_hba);
	if (ret != RETURN_OK) {
		HIFC_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_REG_ATT, UNF_WARN,
			   "[err]Create Els Srq failed");
		return UNF_RETURN_ERROR;
	}

	return RETURN_OK;
}

unsigned int hifc_create_common_share_queues(void *v_hba)
{
	unsigned int ret = UNF_RETURN_ERROR;
	struct hifc_hba_s *hba = NULL;

	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE, v_hba,
			return UNF_RETURN_ERROR);

	hba = (struct hifc_hba_s *)v_hba;

	/* Create & Init 8 pairs SCQ */
	ret = hifc_create_scq(hba);
	if (ret != RETURN_OK) {
		HIFC_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_REG_ATT, UNF_WARN, "[err]Create scq failed");

		return UNF_RETURN_ERROR;
	}

	/* Alloc SRQ resource for SIRT & ELS */
	ret = hifc_create_srq(hba);
	if (ret != RETURN_OK) {
		HIFC_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_REG_ATT, UNF_WARN, "[err]Create srq failed");

		hifc_flush_scq_ctx(hba);
		hifc_destroy_scq(hba);

		return UNF_RETURN_ERROR;
	}

	return RETURN_OK;
}

void hifc_destroy_common_share_queues(void *v_hba)
{
	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE, NULL != v_hba, return);

	hifc_destroy_scq((struct hifc_hba_s *)v_hba);
	hifc_destroy_srq((struct hifc_hba_s *)v_hba);
}

static unsigned char hifc_map_fcp_data_cos(struct hifc_hba_s *v_hba)
{
	unsigned char i = 0;
	unsigned char min_cnt_index = HIFC_PACKET_COS_FC_DATA;
	int get_init_index = UNF_FALSE;

	for (i = 0; i < HIFC_MAX_COS_NUM; i++) {
		/*
		 * Check whether the CoS is valid for the FC and cannot be
		 * occupied by the CMD
		 */
		if ((!(v_hba->cos_bit_map & (1 << i))) ||
		    (i == HIFC_PACKET_COS_FC_CMD)) {
			continue;
		}

		if (get_init_index == UNF_FALSE) {
			min_cnt_index = i;
			get_init_index = UNF_TRUE;
			continue;
		}

		if (atomic_read(&v_hba->cos_rport_cnt[i]) <
		    atomic_read(&v_hba->cos_rport_cnt[min_cnt_index])) {
			min_cnt_index = i;
		}
	}

	atomic_inc(&v_hba->cos_rport_cnt[min_cnt_index]);

	return min_cnt_index;
}

static void hifc_update_cos_rport_cnt(struct hifc_hba_s *v_hba,
				      unsigned char v_cos_index)
{
	if ((v_cos_index >= HIFC_MAX_COS_NUM) ||
	    (v_cos_index == HIFC_PACKET_COS_FC_CMD) ||
	    (!(v_hba->cos_bit_map & (1 << v_cos_index))) ||
	    (atomic_read(&v_hba->cos_rport_cnt[v_cos_index]) == 0)) {
		return;
	}

	atomic_dec(&v_hba->cos_rport_cnt[v_cos_index]);
}

void hifc_invalid_parent_sq(struct hifc_parent_sq_info_s *sq_info)
{
	sq_info->rport_index = INVALID_VALUE32;
	sq_info->context_id = INVALID_VALUE32;
	sq_info->sq_queue_id = INVALID_VALUE32;
	sq_info->cache_id = INVALID_VALUE32;
	sq_info->max_sqe_num = INVALID_VALUE32;
	sq_info->wqe_num_per_buf = INVALID_VALUE32;
	sq_info->wqe_size = HIFC_SCQE_SIZE;
	sq_info->wqe_offset = INVALID_VALUE32;
	sq_info->head_start_cmsn = HIFC_MAX_MSN;
	sq_info->head_end_cmsn = HIFC_MAX_MSN;
	sq_info->last_pmsn = INVALID_VALUE16;
	sq_info->last_pi_owner = INVALID_VALUE16;
	sq_info->local_port_id = INVALID_VALUE32;
	sq_info->remote_port_id = INVALID_VALUE32;
	sq_info->phba = NULL;
	sq_info->del_start_jiff = INVALID_VALUE64;
	sq_info->port_in_flush = UNF_FALSE;
	sq_info->sq_in_sess_rst = UNF_FALSE;
	sq_info->oqid_rd = INVALID_VALUE16;
	sq_info->oqid_wr = INVALID_VALUE16;
	sq_info->srq_ctx_addr = 0;
	atomic_set(&sq_info->sq_cashed, UNF_FALSE);
	sq_info->vport_id = 0;
	sq_info->sirt_dif_control.protect_opcode = UNF_DIF_ACTION_NONE;
	atomic_set(&sq_info->sq_valid, UNF_FALSE);
	atomic_set(&sq_info->fush_done_wait_cnt, 0);

	memset(&sq_info->delay_sqe, 0,
	       sizeof(struct hifc_delay_sqe_ctrl_info_s));
	memset(sq_info->io_stat, 0, sizeof(sq_info->io_stat));
}

static void hifc_free_link_list_wpg(struct hifc_parent_sq_info_s *v_sq)
{
	unsigned long flag = 0;
	struct hifc_hba_s *hba = NULL;
	struct list_head *node = NULL;
	struct list_head *next_node = NULL;
	struct list_head *entry_head_wqe_page = NULL;
	struct hifc_sq_wqe_page_s *sq_wpg = NULL;

	hba = (struct hifc_hba_s *)v_sq->phba;

	list_for_each_safe(node, next_node, &v_sq->list_linked_list_sq) {
		sq_wpg = list_entry(node, struct hifc_sq_wqe_page_s, entry_wpg);
		memset((void *)sq_wpg->wpg_addr, WQE_MARKER_0,
		       hba->sq_wpg_pool.wpg_size);

		spin_lock_irqsave(&hba->sq_wpg_pool.wpg_pool_lock, flag);

		entry_head_wqe_page = &sq_wpg->entry_wpg;
		list_del(entry_head_wqe_page);
		list_add_tail(entry_head_wqe_page,
			      &hba->sq_wpg_pool.list_free_wpg_pool);

		/* WqePage Pool counter */
		atomic_dec(&v_sq->wqe_page_cnt);
		atomic_dec(&hba->sq_wpg_pool.wpg_in_use);

		spin_unlock_irqrestore(&hba->sq_wpg_pool.wpg_pool_lock, flag);
	}

	HIFC_TRACE(UNF_EVTLOG_IO_INFO, UNF_LOG_IO_ATT, UNF_INFO,
		   "[info]Port(0x%x) RPort(0x%x) Sq(0x%x) link list destroyed, Sq.WqePageCnt=0x%x, SqWpgPool.wpg_in_use=0x%x",
		   hba->port_cfg.port_id, v_sq->rport_index, v_sq->context_id,
		   atomic_read(&v_sq->wqe_page_cnt),
		   atomic_read(&hba->sq_wpg_pool.wpg_in_use));
}

static void hifc_free_parent_sq(struct hifc_hba_s *v_hba,
				struct hifc_parent_queue_info_s *v_parentq_info)
{
	unsigned int ctx_flush_done = 0;
	unsigned int *ctx_dw = NULL;
	struct hifc_parent_sq_info_s *sq_info = NULL;
	unsigned int delay_cnt = 0;

	sq_info = &v_parentq_info->parent_sq_info;

	/* Free data cos */
	hifc_update_cos_rport_cnt(v_hba, v_parentq_info->queue_data_cos);

	hifc_free_link_list_wpg(sq_info);

	if (sq_info->queue_header_original) {
		pci_unmap_single(v_hba->pci_dev,
				 sq_info->queue_hdr_phy_addr_original,
				 sizeof(struct hifc_queue_header_s) +
				 HIFC_SQ_HEADER_ADDR_ALIGN_SIZE,
				 DMA_BIDIRECTIONAL);
		kfree(sq_info->queue_header_original);
		sq_info->queue_header_original = NULL;
	}

	if (v_parentq_info->parent_ctx.cqm_parent_ctx_obj) {
		ctx_dw = (unsigned int *)((void *)(
			 v_parentq_info->parent_ctx.cqm_parent_ctx_obj->vaddr));
		ctx_flush_done = ctx_dw[HIFC_CTXT_FLUSH_DONE_DW_POS] &
			 HIFC_CTXT_FLUSH_DONE_MASK_BE;
		mb();
		if ((v_parentq_info->offload_state ==
		    HIFC_QUEUE_STATE_DESTROYING) && (ctx_flush_done == 0)) {
			do {
				ctx_flush_done =
					ctx_dw[HIFC_CTXT_FLUSH_DONE_DW_POS] &
					HIFC_CTXT_FLUSH_DONE_MASK_BE;
				mb();
				if (ctx_flush_done != 0)
					break;
				delay_cnt++;
			} while (delay_cnt < 100);

			if (ctx_flush_done == 0) {
				HIFC_TRACE(UNF_EVTLOG_DRIVER_WARN,
					   UNF_LOG_REG_ATT, UNF_WARN,
					   "[warn]Port(0x%x) Rport(0x%x) flush done is not set",
					   v_hba->port_cfg.port_id,
					   sq_info->rport_index);
			}
		}

		cqm_object_delete(
			&v_parentq_info->parent_ctx.cqm_parent_ctx_obj->object);
		v_parentq_info->parent_ctx.cqm_parent_ctx_obj = NULL;
	}

	hifc_invalid_parent_sq(sq_info);
}

static inline struct hifcoe_sqe_s *hifc_get_wqe_page_entry(
					struct hifc_sq_wqe_page_s *v_wpg,
					unsigned int wqe_offset)
{
	struct hifcoe_sqe_s *wpg = NULL;

	wpg = (struct hifcoe_sqe_s *)(v_wpg->wpg_addr);
	wpg += wqe_offset;

	return wpg;
}

static struct hifc_sq_wqe_page_s *hifc_add_tail_wqe_page(
					struct hifc_parent_sq_info_s *v_sq)
{
	struct hifc_hba_s *hba = NULL;
	struct hifc_sq_wqe_page_s *esgl = NULL;
	struct list_head *free_list_head = NULL;
	unsigned long flag = 0;

	hba = (struct hifc_hba_s *)v_sq->phba;

	spin_lock_irqsave(&hba->sq_wpg_pool.wpg_pool_lock, flag);

	/* Get a WqePage from hba->sq_wpg_pool.list_free_wpg_pool, and add
	 * to v_sq.list_SqTailWqePage
	 */
	if (!list_empty(&hba->sq_wpg_pool.list_free_wpg_pool)) {
		free_list_head = (&hba->sq_wpg_pool.list_free_wpg_pool)->next;
		list_del(free_list_head);
		list_add_tail(free_list_head, &v_sq->list_linked_list_sq);
		esgl = list_entry(free_list_head, struct hifc_sq_wqe_page_s,
				  entry_wpg);

		/* WqePage Pool counter */
		atomic_inc(&hba->sq_wpg_pool.wpg_in_use);
	} else {
		esgl = NULL;
		HIFC_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_IO_ATT, UNF_WARN,
			   "[warn]SQ pool is empty when SQ(0x%x) try to get wqe page",
			   v_sq->rport_index);
		HIFC_HBA_STAT(hba, HIFC_STAT_SQ_POOL_EMPTY);
	}

	spin_unlock_irqrestore(&hba->sq_wpg_pool.wpg_pool_lock, flag);

	return esgl;
}

static struct hifc_sq_wqe_page_s *hifc_add_one_wqe_page(
					struct hifc_parent_sq_info_s *v_sq)
{
	unsigned int wqe_idx = 0;
	struct hifc_sq_wqe_page_s *wqe_page = NULL;
	struct hifcoe_sqe_s *sqe_in_wp = NULL;
	struct hifc_link_wqe_s *link_wqe_in_wpg = NULL;
	struct hifc_link_wqe_s link_wqe;

	/* Add a new Wqe Page */
	wqe_page = hifc_add_tail_wqe_page(v_sq);

	if (!wqe_page)
		return NULL;

	for (wqe_idx = 0; wqe_idx <= v_sq->wqe_num_per_buf; wqe_idx++) {
		sqe_in_wp = hifc_get_wqe_page_entry(wqe_page, wqe_idx);
		sqe_in_wp->ctrl_sl.ch.ctrl_ch_val = 0;
	}

	/* Set last WqePage as linkwqe */
	link_wqe_in_wpg = (struct hifc_link_wqe_s *)
		hifc_get_wqe_page_entry(wqe_page, v_sq->wqe_num_per_buf);
	link_wqe.val_wd0 = 0;
	link_wqe.val_wd1 = 0;
	link_wqe.next_page_addr_hi = 0;
	link_wqe.next_page_addr_lo = 0;
	link_wqe.wd0.wf = CQM_WQE_WF_LINK;
	link_wqe.wd0.ctrlsl = CQM_LINK_WQE_CTRLSL_VALUE;
	link_wqe.wd0.o = !(v_sq->last_pi_owner);
	link_wqe.wd1.lp = CQM_LINK_WQE_LP_INVALID;
	hifc_cpu_to_big32(&link_wqe, sizeof(struct hifc_link_wqe_s));
	memcpy(link_wqe_in_wpg, &link_wqe, sizeof(struct hifc_link_wqe_s));

	return wqe_page;
}

static void hifc_alloc_sq_oqid(struct hifc_hba_s *v_hba,
			       struct hifc_parent_sq_info_s *v_sq)
{
	unsigned short read_oqid = INVALID_VALUE16;
	unsigned short write_oqid = INVALID_VALUE16;
	unsigned short vf_id = INVALID_VALUE16;
	unsigned short mask_value = hifc_host_oq_id_mask(v_hba->hw_dev_handle);
	unsigned int cqm_xid = v_sq->context_id;

	vf_id = hifc_global_func_id(v_hba->hw_dev_handle);

	HIFC_OQID_RD((unsigned short)cqm_xid, vf_id, mask_value, read_oqid);
	HIFC_OQID_WR((unsigned short)cqm_xid, vf_id, mask_value, write_oqid);

	v_sq->oqid_rd = read_oqid;
	v_sq->oqid_wr = write_oqid;
}

static void hifc_parent_sq_operate_time_out(struct work_struct *work)
{
	int free_sq = UNF_FALSE;
	unsigned long flag = 0;
	struct hifc_parent_sq_info_s *parent_sq = NULL;
	struct hifc_parent_queue_info_s *parent_queue = NULL;
	struct hifc_hba_s *hba = NULL;

	HIFC_CHECK(INVALID_VALUE32, work, return);

	parent_sq = container_of(work, struct hifc_parent_sq_info_s,
				 del_work.work);
	parent_queue = container_of(parent_sq, struct hifc_parent_queue_info_s,
				    parent_sq_info);
	hba = (struct hifc_hba_s *)parent_sq->phba;
	HIFC_CHECK(INVALID_VALUE32, hba, return);

	spin_lock_irqsave(&parent_queue->parent_queue_state_lock, flag);
	if (parent_queue->offload_state == HIFC_QUEUE_STATE_DESTROYING) {
		free_sq = UNF_TRUE;
		HIFC_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_LOGIN_ATT, UNF_ERR,
			   "Port(0x%x) sq rport index(0x%x) local nportid(0x%x),remote nportid(0x%x) reset timeout.",
			   hba->port_cfg.port_id,
			   parent_sq->rport_index,
			   parent_sq->local_port_id,
			   parent_sq->remote_port_id);
	}
	spin_unlock_irqrestore(&parent_queue->parent_queue_state_lock, flag);

	/* In the server scenario, if the connection deletion times out, you
	 * can only wait or perform the FLR operation on the port. If the FLR
	 * command is run, the fault diffusion mode will be used.
	 */
	if ((parent_queue->parent_sq_info.del_start_jiff > hba->reset_time) &&
	    (parent_queue->parent_sq_info.del_start_jiff != INVALID_VALUE64) &&
	    (hba->removing == UNF_FALSE)) {
		/* There is nothing to do if session reset timeout */
		;
	}

	if (free_sq == UNF_TRUE) {
		/* There is nothing to do if session reset timeout */
		;
	}
}

static void hifc_parent_sq_wait_flush_done_time_out(struct work_struct *work)
{
	unsigned long flag = 0;
	struct hifc_parent_sq_info_s *parent_sq = NULL;
	struct hifc_parent_queue_info_s *parent_queue = NULL;
	struct hifc_hba_s *hba = NULL;
	unsigned int ctx_flush_done;
	unsigned int *ctx_dw = NULL;
	int ret;

	HIFC_CHECK(INVALID_VALUE32, work, return);

	parent_sq = container_of(work, struct hifc_parent_sq_info_s,
				 flush_done_tmo_work.work);

	HIFC_CHECK(INVALID_VALUE32, parent_sq, return);

	parent_queue = container_of(parent_sq, struct hifc_parent_queue_info_s,
				    parent_sq_info);
	hba = (struct hifc_hba_s *)parent_sq->phba;
	HIFC_CHECK(INVALID_VALUE32, hba, return);
	HIFC_CHECK(INVALID_VALUE32, parent_queue, return);

	spin_lock_irqsave(&parent_queue->parent_queue_state_lock, flag);

	if (parent_queue->offload_state != HIFC_QUEUE_STATE_DESTROYING) {
		HIFC_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT, UNF_WARN,
			   "[warn]Port(0x%x) sq rport index(0x%x) is not destroying status,offloadsts is %d",
			   hba->port_cfg.port_id,
			   parent_sq->rport_index,
			   parent_queue->offload_state);
		spin_unlock_irqrestore(&parent_queue->parent_queue_state_lock,
				       flag);
		return;
	}

	if (parent_queue->parent_ctx.cqm_parent_ctx_obj) {
		ctx_dw = (unsigned int *)((void *)
			 (parent_queue->parent_ctx.cqm_parent_ctx_obj->vaddr));
		ctx_flush_done =
				ctx_dw[HIFC_CTXT_FLUSH_DONE_DW_POS] &
				HIFC_CTXT_FLUSH_DONE_MASK_BE;
		if (ctx_flush_done == 0) {
			spin_unlock_irqrestore(
				&parent_queue->parent_queue_state_lock, flag);

			if (atomic_read(&parent_queue->parent_sq_info.fush_done_wait_cnt) < HIFC_SQ_WAIT_FLUSH_DONE_TIMEOUT_CNT) {
				HIFC_TRACE(UNF_EVTLOG_DRIVER_WARN,
					   UNF_LOG_LOGIN_ATT, UNF_WARN,
					   "[info]Port(0x%x) sq rport index(0x%x) wait flush done timeout %d times",
					   hba->port_cfg.port_id,
					   parent_sq->rport_index,
					   atomic_read(&parent_queue->parent_sq_info.fush_done_wait_cnt));

				atomic_inc(&parent_queue->parent_sq_info.fush_done_wait_cnt);

				/* Delay Free Sq info */
				ret = queue_delayed_work(hba->work_queue,
							 &parent_queue->parent_sq_info.flush_done_tmo_work,
							 (unsigned long)msecs_to_jiffies((unsigned int)HIFC_SQ_WAIT_FLUSH_DONE_TIMEOUT_MS));
				if (ret == (int)false) {
					HIFC_TRACE(UNF_EVTLOG_DRIVER_ERR,
						   UNF_LOG_LOGIN_ATT, UNF_ERR,
						   "[err]Port(0x%x) rport(0x%x) queue delayed work failed iret:%d",
						   hba->port_cfg.port_id,
						   parent_sq->rport_index,
						   ret);
					HIFC_HBA_STAT(hba, HIFC_STAT_PARENT_SQ_QUEUE_DELAYED_WORK);
				}

				return;
			} else {
				HIFC_TRACE(UNF_EVTLOG_DRIVER_ERR,
					   UNF_LOG_LOGIN_ATT, UNF_ERR,
					   "[err]Port(0x%x) sq rport index(0x%x) has wait flush done %d times,do not free sq",
					   hba->port_cfg.port_id,
					   parent_sq->rport_index,
					   atomic_read(&parent_queue->parent_sq_info.fush_done_wait_cnt));

				HIFC_HBA_STAT(hba, HIFC_STAT_CTXT_FLUSH_DONE);

				return;
			}
		}
	}

	spin_unlock_irqrestore(&parent_queue->parent_queue_state_lock, flag);

	HIFC_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT, UNF_MAJOR,
		   "[info]Port(0x%x) sq rport index(0x%x) flush done bit is ok,free sq now",
		   hba->port_cfg.port_id,
		   parent_sq->rport_index);

	hifc_free_parent_queue_info(hba, parent_queue);
}

unsigned int hifc_alloc_parent_sq(
			struct hifc_hba_s *v_hba,
			struct hifc_parent_queue_info_s *v_parentq_info,
			struct unf_rport_info_s *v_rport_info)
{
	struct hifc_parent_sq_info_s *sq_ctrl = NULL;
	struct hifc_sq_wqe_page_s *head_wpg = NULL;
	struct cqm_qpc_mpt_s *prnt_ctx = NULL;
	unsigned int queue_header_alloc_size = 0;
	unsigned long flag = 0;

	/* Craete parent context via CQM */
	prnt_ctx = cqm_object_qpc_mpt_create(v_hba->hw_dev_handle,
					     CQM_OBJECT_SERVICE_CTX,
					     HIFC_CNTX_SIZE_256B,
					     v_parentq_info,
					     CQM_INDEX_INVALID);
	if (!prnt_ctx) {
		HIFC_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_REG_ATT, UNF_ERR,
			   "[err]Create parent context failed, CQM_INDEX is 0x%x",
			   CQM_INDEX_INVALID);
		goto parent_create_fail;
	}
	v_parentq_info->parent_ctx.cqm_parent_ctx_obj = prnt_ctx;

	/* Initialize struct hifc_parent_sq_info_s */
	sq_ctrl = &v_parentq_info->parent_sq_info;
	sq_ctrl->phba = (void *)v_hba;
	sq_ctrl->rport_index = v_rport_info->rport_index;
	sq_ctrl->context_id = prnt_ctx->xid;
	sq_ctrl->sq_queue_id = HIFC_QID_SQ;
	sq_ctrl->cache_id = INVALID_VALUE32;
	sq_ctrl->max_sqe_num = v_hba->exit_count;
	/* Reduce one Link Wqe */
	sq_ctrl->wqe_num_per_buf = v_hba->sq_wpg_pool.wqe_per_wpg - 1;
	sq_ctrl->wqe_size = HIFC_SQE_SIZE;
	sq_ctrl->wqe_offset = 0;
	sq_ctrl->head_start_cmsn = 0;
	sq_ctrl->head_end_cmsn = HIFC_GET_WP_END_CMSN(0,
						      sq_ctrl->wqe_num_per_buf);
	sq_ctrl->last_pmsn = 0;
	/* Linked List SQ Owner Bit 1 valid, 0 invalid */
	sq_ctrl->last_pi_owner = 1;
	sq_ctrl->local_port_id = INVALID_VALUE32;
	sq_ctrl->remote_port_id = INVALID_VALUE32;
	sq_ctrl->sq_in_sess_rst = UNF_FALSE;
	atomic_set(&sq_ctrl->sq_valid, UNF_TRUE);
	sq_ctrl->del_start_jiff = INVALID_VALUE64;
	sq_ctrl->service_type = HIFC_GET_SERVICE_TYPE(v_hba);
	sq_ctrl->vport_id = 0;
	sq_ctrl->sirt_dif_control.protect_opcode = UNF_DIF_ACTION_NONE;
	hifc_alloc_sq_oqid(v_hba, sq_ctrl);
	atomic_set(&sq_ctrl->fush_done_wait_cnt, 0);

	/* Check whether the HBA is in the Linkdown state. Note that
	 * offload_state must be in the non-FREE state.
	 */
	spin_lock_irqsave(&v_hba->flush_state_lock, flag);
	sq_ctrl->port_in_flush = v_hba->in_flushing;
	spin_unlock_irqrestore(&v_hba->flush_state_lock, flag);

	INIT_LIST_HEAD(&sq_ctrl->list_linked_list_sq);
	atomic_set(&sq_ctrl->wqe_page_cnt, 0);
	atomic_set(&sq_ctrl->sq_dbl_cnt, 0);
	atomic_set(&sq_ctrl->sqe_minus_cqe_cnt, 1);
	atomic_set(&sq_ctrl->sq_wqe_cnt, 0);
	atomic_set(&sq_ctrl->sq_cqe_cnt, 0);
	memset(sq_ctrl->io_stat, 0, sizeof(sq_ctrl->io_stat));

	INIT_DELAYED_WORK(&sq_ctrl->del_work, hifc_parent_sq_operate_time_out);
	INIT_DELAYED_WORK(&sq_ctrl->flush_done_tmo_work,
			  hifc_parent_sq_wait_flush_done_time_out);

	memset(&sq_ctrl->delay_sqe, 0,
	       sizeof(struct hifc_delay_sqe_ctrl_info_s));

	/* Allocate and initialize the Queue Header space. 64B alignment is
	 * required. Additional 64B is applied for alignment
	 */
	queue_header_alloc_size = sizeof(struct hifc_queue_header_s) +
				  HIFC_SQ_HEADER_ADDR_ALIGN_SIZE;
	sq_ctrl->queue_header_original = kmalloc(queue_header_alloc_size,
						 GFP_ATOMIC);
	if (!sq_ctrl->queue_header_original) {
		HIFC_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_REG_ATT, UNF_ERR,
			   "[err]RPort(0x%x) create SQ queue header failed",
			   v_rport_info->rport_index);
		goto qheader_create_fail;
	}

	memset((unsigned char *)sq_ctrl->queue_header_original, 0,
	       queue_header_alloc_size);

	sq_ctrl->queue_hdr_phy_addr_original = pci_map_single(
						v_hba->pci_dev,
						sq_ctrl->queue_header_original,
						queue_header_alloc_size,
						DMA_BIDIRECTIONAL);

	if (pci_dma_mapping_error(v_hba->pci_dev,
				  sq_ctrl->queue_hdr_phy_addr_original)) {
		HIFC_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_REG_ATT, UNF_ERR,
			   "[err]RPort(0x%x) SQ queue header DMA mapping failed",
			   v_rport_info->rport_index);
		goto qheader_dma_map_fail;
	}

	/* Obtains the 64B alignment address */
	sq_ctrl->queue_header = (struct hifc_queue_header_s *)
				HIFC_ADDR_64_ALIGN(
				(unsigned long long)
				(sq_ctrl->queue_header_original));
	sq_ctrl->queue_hdr_phy_addr =
		HIFC_ADDR_64_ALIGN(sq_ctrl->queue_hdr_phy_addr_original);

	/* Each SQ is allocated with a Wqe Page by default. The WqePageCnt is
	 * incremented by one
	 */
	head_wpg = hifc_add_one_wqe_page(sq_ctrl);
	if (!head_wpg) {
		HIFC_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_REG_ATT, UNF_WARN,
			   "[err]RPort(0x%x) create SQ first wqe page failed",
			   v_rport_info->rport_index);
		goto headwpg_create_fail;
	}

	atomic_inc(&sq_ctrl->wqe_page_cnt);

	return RETURN_OK;

headwpg_create_fail:
	pci_unmap_single(v_hba->pci_dev, sq_ctrl->queue_hdr_phy_addr_original,
			 queue_header_alloc_size, DMA_BIDIRECTIONAL);

qheader_dma_map_fail:
	kfree(sq_ctrl->queue_header_original);
	sq_ctrl->queue_header_original = NULL;

qheader_create_fail:
	cqm_object_delete(&prnt_ctx->object);

parent_create_fail:
	v_parentq_info->parent_ctx.cqm_parent_ctx_obj = NULL;

	return UNF_RETURN_ERROR;
}

static void hifc_init_prnt_ctx_sq_qinfo(
				struct hifc_parent_queue_info_s *v_parent_qinfo)
{
	struct hifc_parent_sq_info_s *sq = NULL;
	struct hifc_sq_wqe_page_s *head_wqe_page = NULL;
	struct hifcoe_parent_context_s *ctx = NULL;
	struct hifcoe_sq_qinfo_s *parent_sq_ctx = NULL;
	struct hifc_queue_info_bus_s queue_bus;

	/* Obtains the Parent Context address */
	sq = &v_parent_qinfo->parent_sq_info;
	ctx = (struct hifcoe_parent_context_s *)(void *)
	      (v_parent_qinfo->parent_ctx.virt_parent_ctx);
	head_wqe_page = HIFC_GET_SQ_HEAD(sq);

	parent_sq_ctx = &ctx->sq_qinfo;

	/* The PMSN is updated by the host driver */
	parent_sq_ctx->pmsn_type = HIFC_PMSN_CI_TYPE_FROM_HOST;

	/* Indicates the value of O of the valid SQE in the current round of SQ.
	 * The value of Linked List SQ is always one, and the value of 0 is
	 * invalid.
	 */
	 /* current valid o-bit */
	parent_sq_ctx->loop_o = HIFC_OWNER_DRIVER_PRODUCT;

	/* should be opposite from loop_o */
	parent_sq_ctx->cur_wqe_o = ~(parent_sq_ctx->loop_o);

	/* the first sqe's gpa */
	parent_sq_ctx->cur_sqe_gpa = head_wqe_page->wpg_phy_addr;

	/* Indicates the GPA of the Queue header that is initialized to the SQ
	 * in the Host memory. The value must be 16-byte aligned.
	 */
	parent_sq_ctx->pmsn_gpa = sq->queue_hdr_phy_addr;
	if (wqe_pre_load != 0)
		parent_sq_ctx->pmsn_gpa |= HIFC_SQ_LINK_PRE;

	/*
	 * This field is used to fill in the dmaattr_idx field of the ComboDMA.
	 * The default value is 0
	 */
	parent_sq_ctx->sqe_dmaattr_idx = HIFC_DMA_ATTR_OFST;

	/*
	 * This field is filled using the value of RO_SO in the SGL0 of
	 * the ComboDMA
	 */
	parent_sq_ctx->sq_so_ro = HIFC_PCIE_RELAXED_ORDERING;

	parent_sq_ctx->ring = HIFC_QUEUE_LINK_STYLE;

	/* This field is used to set the SGL0 field of the Child solicDMA */
	parent_sq_ctx->zerocopy_dmaattr_idx = HIFC_DMA_ATTR_OFST;

	parent_sq_ctx->zerocopy_so_ro = HIFC_PCIE_RELAXED_ORDERING;

	/* PCIe attribute information */
	parent_sq_ctx->pcie_template = HIFC_PCIE_TEMPLATE;

	memset(&queue_bus, 0, sizeof(struct hifc_queue_info_bus_s));
	/* bits 20 */
	queue_bus.bus[0] |= ((unsigned long long)(sq->context_id & 0xfffff));
	/* bits 6 */
	queue_bus.bus[0] |=
		(((unsigned long long)(parent_sq_ctx->sqe_dmaattr_idx)) << 20);
	/* bits 2 */
	queue_bus.bus[0] |=
		(((unsigned long long)(parent_sq_ctx->sq_so_ro)) << 26);
	/* bits 1 */
	queue_bus.bus[0] |= (((unsigned long long)(parent_sq_ctx->ring)) << 28);
	/* bits 6 */
	queue_bus.bus[0] |=
		(((unsigned long long)(parent_sq_ctx->zerocopy_dmaattr_idx))
		<< 29);
	/* bits 2 */
	queue_bus.bus[0] |=
		(((unsigned long long)(parent_sq_ctx->zerocopy_so_ro)) << 35);
	/* bits 6 */
	queue_bus.bus[0] |=
		(((unsigned long long)(parent_sq_ctx->pcie_template)) << 37);
	/* bits 21 */
	queue_bus.bus[0] |=
		(((unsigned long long)(parent_sq_ctx->pmsn_gpa >> 4)) << 43);
	/* bits 39 */
	queue_bus.bus[1] |=
		((unsigned long long)(parent_sq_ctx->pmsn_gpa >> 25));
	/* bits 1 */
	queue_bus.bus[1] |=
		(((unsigned long long)(parent_sq_ctx->pmsn_type)) << 39);

	parent_sq_ctx->parity =
		hifc_get_parity_value(queue_bus.bus, HIFC_SQC_BUS_ROW,
				      HIFC_SQC_BUS_COL);

	hifc_cpu_to_big64(parent_sq_ctx, sizeof(struct hifcoe_sq_qinfo_s));
}

static void hifc_init_parent_ctx_sqc_qinfo(
				void *v_hba,
				struct hifc_parent_queue_info_s *v_parent_qinfo)
{
	unsigned int resp_scqn = 0;
	struct hifcoe_parent_context_s *ctx = NULL;
	struct hifcoe_scq_qinfo_s *resp_parent_scq_ctx = NULL;
	struct hifc_queue_info_bus_s queue_bus;

	/*
	 * Obtains the queue id of the scq returned by the CQM when the SCQ
	 * is created
	 */
	resp_scqn = v_parent_qinfo->parent_sts_scq_info.cqm_queue_id;

	/* Obtains the Parent Context address */
	ctx = (struct hifcoe_parent_context_s *)
	      (v_parent_qinfo->parent_ctx.virt_parent_ctx);

	resp_parent_scq_ctx = &ctx->resp_scq_qinfo;
	resp_parent_scq_ctx->hw_scqc_config.info.rq_th2_preld_cache_num =
								wqe_pre_load;
	resp_parent_scq_ctx->hw_scqc_config.info.rq_th1_preld_cache_num =
								wqe_pre_load;
	resp_parent_scq_ctx->hw_scqc_config.info.rq_th0_preld_cache_num =
								wqe_pre_load;
	resp_parent_scq_ctx->hw_scqc_config.info.rq_min_preld_cache_num =
								wqe_pre_load;
	resp_parent_scq_ctx->hw_scqc_config.info.sq_th2_preld_cache_num =
								wqe_pre_load;
	resp_parent_scq_ctx->hw_scqc_config.info.sq_th1_preld_cache_num =
								wqe_pre_load;
	resp_parent_scq_ctx->hw_scqc_config.info.sq_th0_preld_cache_num =
								wqe_pre_load;
	resp_parent_scq_ctx->hw_scqc_config.info.sq_min_preld_cache_num =
								wqe_pre_load;
	resp_parent_scq_ctx->hw_scqc_config.info.scq_n =
						(unsigned long long)resp_scqn;
	resp_parent_scq_ctx->hw_scqc_config.info.parity = 0;

	memset(&queue_bus, 0, sizeof(struct hifc_queue_info_bus_s));
	queue_bus.bus[0] = resp_parent_scq_ctx->hw_scqc_config.pctxt_val1;
	resp_parent_scq_ctx->hw_scqc_config.info.parity =
				hifc_get_parity_value(
					queue_bus.bus,
					HIFC_HW_SCQC_BUS_ROW,
					HIFC_HW_SCQC_BUS_COL);

	hifc_cpu_to_big64(resp_parent_scq_ctx,
			  sizeof(struct hifcoe_scq_qinfo_s));
}

static void hifc_init_parent_ctx_srq_qinfo(
				void *v_hba,
				struct hifc_parent_queue_info_s *v_parent_qinfo)
{
	struct hifc_hba_s *hba = NULL;
	struct hifcoe_parent_context_s *ctx = NULL;
	struct cqm_queue_s *cqm_els_srq = NULL;
	struct hifc_parent_sq_info_s *sq = NULL;
	struct hifc_queue_info_bus_s queue_bus;

	/* Obtains the SQ address */
	sq = &v_parent_qinfo->parent_sq_info;

	/* Obtains the Parent Context address */
	ctx = (struct hifcoe_parent_context_s *)
	      (v_parent_qinfo->parent_ctx.virt_parent_ctx);

	hba = (struct hifc_hba_s *)v_hba;
	cqm_els_srq = hba->els_srq_info.cqm_srq_info;

	/* Initialize the Parent SRQ INFO used when the ELS is received */
	ctx->els_srq_info.srqc_gpa = cqm_els_srq->q_ctx_paddr >> 4;

	memset(&queue_bus, 0, sizeof(struct hifc_queue_info_bus_s));
	queue_bus.bus[0] = ctx->els_srq_info.srqc_gpa;
	ctx->els_srq_info.parity = hifc_get_parity_value(
						queue_bus.bus,
						HIFC_HW_SRQC_BUS_ROW,
						HIFC_HW_SRQC_BUS_COL);

	hifc_cpu_to_big64(&ctx->els_srq_info,
			  sizeof(struct hifcoe_srq_qinfo_s));

	ctx->imm_srq_info.srqc_gpa = 0;
	sq->srq_ctx_addr = 0;
}

static void hifc_init_parent_rsvd_qinfo(
			struct hifc_parent_queue_info_s *v_parent_qinfo)
{
	struct hifcoe_parent_context_s *ctx = NULL;
	struct hifcoe_hw_rsvd_queue_s *hw_rsvd_qinfo = NULL;
	unsigned short max_seq = 0;
	unsigned int each = 0, seq_index = 0;

	/* Obtains the Parent Context address */
	ctx = (struct hifcoe_parent_context_s *)
	      (v_parent_qinfo->parent_ctx.virt_parent_ctx);
	hw_rsvd_qinfo = (struct hifcoe_hw_rsvd_queue_s *)&ctx->hw_rsvdq;
	memset(hw_rsvd_qinfo->seq_id_bitmap, 0,
	       sizeof(hw_rsvd_qinfo->seq_id_bitmap));

	max_seq = HIFC_HRQI_SEQ_ID_MAX;

	/* special set for sequence id 0, which is always kept by ucode for
	 * sending fcp-cmd
	 */
	hw_rsvd_qinfo->seq_id_bitmap[HIFC_HRQI_SEQ_SEPCIAL_ID] = 1;
	seq_index = HIFC_HRQI_SEQ_SEPCIAL_ID -
		    (max_seq >> HIFC_HRQI_SEQ_INDEX_SHIFT);

	/* Set the unavailable mask to start from max + 1 */
	for (each = (max_seq % HIFC_HRQI_SEQ_INDEX_MAX) + 1;
	     each < HIFC_HRQI_SEQ_INDEX_MAX; each++) {
		hw_rsvd_qinfo->seq_id_bitmap[seq_index] |= 0x1 << each;
	}

	hw_rsvd_qinfo->seq_id_bitmap[seq_index] =
			cpu_to_be64(hw_rsvd_qinfo->seq_id_bitmap[seq_index]);

	/* sepcial set for sequence id 0 */
	if (seq_index != HIFC_HRQI_SEQ_SEPCIAL_ID) {
		hw_rsvd_qinfo->seq_id_bitmap[HIFC_HRQI_SEQ_SEPCIAL_ID] =
			cpu_to_be64(
			hw_rsvd_qinfo->seq_id_bitmap[HIFC_HRQI_SEQ_SEPCIAL_ID]);
	}

	for (each = 0; each < seq_index; each++)
		hw_rsvd_qinfo->seq_id_bitmap[each] = HIFC_HRQI_SEQ_INVALID_ID;

	/* no matter what the range of seq id, last_req_seq_id is fixed
	 * value 0xff
	 */
	hw_rsvd_qinfo->wd0.last_req_seq_id = HIFC_HRQI_SEQ_ID_MAX;
	hw_rsvd_qinfo->wd0.xid = v_parent_qinfo->parent_sq_info.context_id;

	*(unsigned long long *)&hw_rsvd_qinfo->wd0 =
		cpu_to_be64(*(unsigned long long *)&hw_rsvd_qinfo->wd0);
}

static void hifc_init_oqid_in_ctx(
			struct hifcoe_parent_context_s *v_parent_ctx,
			struct hifc_parent_queue_info_s *v_parent_qinfo)
{
	v_parent_ctx->sw_section.oqid_rd =
		cpu_to_be16(v_parent_qinfo->parent_sq_info.oqid_rd);
	v_parent_ctx->sw_section.oqid_wr =
		cpu_to_be16(v_parent_qinfo->parent_sq_info.oqid_wr);
}

static void hifc_init_parent_sw_section_info(
			void *v_hba,
			struct hifc_parent_queue_info_s *v_parent_qinfo)
{
#define HIFC_VLAN_ENABLE (1)

	unsigned short rport_index;
	struct hifc_hba_s *hba = NULL;
	struct hifcoe_parent_context_s *ctx = NULL;
	struct hifcoe_sw_section_s  *sw_section = NULL;

	/* Obtains the Parent Context address */
	hba = (struct hifc_hba_s *)v_hba;
	ctx = (struct hifcoe_parent_context_s *)
	      (v_parent_qinfo->parent_ctx.virt_parent_ctx);
	sw_section = &ctx->sw_section;

	/* xid+vPortId */
	sw_section->sw_ctxt_vport_xid.xid =
		v_parent_qinfo->parent_sq_info.context_id;
	sw_section->sw_ctxt_vport_xid.vport =
		v_parent_qinfo->parent_sq_info.vport_id;
	sw_section->sw_ctxt_vport_xid.csctrl = 0;
	hifc_cpu_to_big32(&sw_section->sw_ctxt_vport_xid,
			  sizeof(sw_section->sw_ctxt_vport_xid));

	/* conn_id */
	rport_index = HIFC_LSW(v_parent_qinfo->parent_sq_info.rport_index);
	sw_section->conn_id = cpu_to_be16(rport_index);

	/* Immediate parameters */
	sw_section->immi_rq_page_size = 0;

	/* Parent SCQ INFO used for sending packets to the Cmnd */
	sw_section->scq_num_rcv_cmd =
		cpu_to_be32(v_parent_qinfo->parent_cmd_scq_info.cqm_queue_id);

	/* sw_ctxt_misc */
	sw_section->sw_ctxt_misc.dw.srv_type =
		v_parent_qinfo->parent_sq_info.service_type;
	sw_section->sw_ctxt_misc.dw.port_id = hba->port_index;

	/* only the VN2VF mode is supported */
	sw_section->sw_ctxt_misc.dw.vlan_id = 0;
	hifc_cpu_to_big32(&sw_section->sw_ctxt_misc.pctxt_val0,
			  sizeof(sw_section->sw_ctxt_misc.pctxt_val0));

	/* oqid_rd, oqid_wr */
	hifc_init_oqid_in_ctx(ctx, v_parent_qinfo);

	/* Configuring the combo length */
	sw_section->per_xmit_data_size = cpu_to_be32(combo_length_kb * 1024);

	/* sw_ctxt_config */
	sw_section->sw_ctxt_config.dw.work_mode = HIFC_PORT_MODE_INI;

	sw_section->sw_ctxt_config.dw.status = FCOE_PARENT_STATUS_INVALID;
	sw_section->sw_ctxt_config.dw.cos = hba->port_index;
	sw_section->sw_ctxt_config.dw.oq_cos_cmd = HIFC_PACKET_COS_FC_CMD;
	sw_section->sw_ctxt_config.dw.oq_cos_data =
					v_parent_qinfo->queue_data_cos;
	sw_section->sw_ctxt_config.dw.priority = 0;
	sw_section->sw_ctxt_config.dw.vlan_enable = HIFC_VLAN_ENABLE;
	sw_section->sw_ctxt_config.dw.sgl_num = dif_sgl_mode;
	hifc_cpu_to_big32(&sw_section->sw_ctxt_config.pctxt_val1,
			  sizeof(sw_section->sw_ctxt_config.pctxt_val1));

	hifc_cpu_to_big32(&sw_section->immi_dif_info,
			  sizeof(sw_section->immi_dif_info));

	sw_section->cmd_scq_gpa_h =
		HIFC_HIGH_32_BITS(hba->scq_info[v_parent_qinfo->parent_cmd_scq_info.local_queue_id].cqm_scq_info->q_header_paddr);
	sw_section->cmd_scq_gpa_l =
		HIFC_LOW_32_BITS(hba->scq_info[v_parent_qinfo->parent_cmd_scq_info.local_queue_id].cqm_scq_info->q_header_paddr);

	HIFC_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_REG_ATT, UNF_INFO,
		   "[info]Port(0x%x) RPort(0x%x) CmdLocalScqn(0x%x) QheaderGpaH(0x%x) QheaderGpaL(0x%x)",
		   hba->port_cfg.port_id,
		   v_parent_qinfo->parent_sq_info.rport_index,
		   v_parent_qinfo->parent_cmd_scq_info.local_queue_id,
		   sw_section->cmd_scq_gpa_h,
		   sw_section->cmd_scq_gpa_l);

	hifc_cpu_to_big32(&sw_section->cmd_scq_gpa_h,
			  sizeof(sw_section->cmd_scq_gpa_h));
	hifc_cpu_to_big32(&sw_section->cmd_scq_gpa_l,
			  sizeof(sw_section->cmd_scq_gpa_l));
}

void hifc_init_parent_ctx(void *v_hba,
			  struct hifc_parent_queue_info_s *v_parent_qinfo)
{
	struct hifcoe_parent_context_s *ctx = NULL;

	ctx = (struct hifcoe_parent_context_s *)
	      (v_parent_qinfo->parent_ctx.virt_parent_ctx);

	/* Initialize Parent Context */
	memset(ctx, 0, HIFC_CNTX_SIZE_256B);

	/* Initialize the Queue Info hardware area */
	hifc_init_prnt_ctx_sq_qinfo(v_parent_qinfo);
	hifc_init_parent_ctx_sqc_qinfo(v_hba, v_parent_qinfo);
	hifc_init_parent_ctx_srq_qinfo(v_hba, v_parent_qinfo);
	hifc_init_parent_rsvd_qinfo(v_parent_qinfo);

	/* Initialize Software Section */
	hifc_init_parent_sw_section_info(v_hba, v_parent_qinfo);
}

unsigned int hifc_get_rport_maped_cmd_scqn(void *phba, unsigned int rport_index)
{
	unsigned int cmd_scqn_local = 0;
	struct hifc_hba_s *hba = (struct hifc_hba_s *)phba;

	cmd_scqn_local = HIFC_RPORTID_TO_CMD_SCQN(rport_index);

	return hba->scq_info[cmd_scqn_local].scqn;
}

/**
 * hifc_get_rport_maped_sts_scqn - Obtains the SCQ channel of RPort that is used
 *                       to send STS.
 * @v_hba: hba handle
 * @rport_index: rport index
 * @Return: related scqn value with rport index
 */
unsigned int hifc_get_rport_maped_sts_scqn(void *phba, unsigned int rport_index)
{
	unsigned int sts_scqn_local = 0;
	struct hifc_hba_s *hba = (struct hifc_hba_s *)phba;

	sts_scqn_local = HIFC_RPORTID_TO_STS_SCQN(rport_index);

	return hba->scq_info[sts_scqn_local].scqn;
}

void hifc_map_shared_queue_qid(
			struct hifc_hba_s *v_hba,
			struct hifc_parent_queue_info_s *v_parent_queue_info,
			unsigned int rport_index)
{
	unsigned int cmd_scqn_local = 0;
	unsigned int sts_scqn_local = 0;

	/* The SCQ is used for each connection based on the balanced
	 * distribution of commands and responses
	 */
	cmd_scqn_local = HIFC_RPORTID_TO_CMD_SCQN(rport_index);
	sts_scqn_local = HIFC_RPORTID_TO_STS_SCQN(rport_index);
	v_parent_queue_info->parent_cmd_scq_info.local_queue_id =
							cmd_scqn_local;
	v_parent_queue_info->parent_sts_scq_info.local_queue_id =
								sts_scqn_local;
	v_parent_queue_info->parent_cmd_scq_info.cqm_queue_id =
					v_hba->scq_info[cmd_scqn_local].scqn;
	v_parent_queue_info->parent_sts_scq_info.cqm_queue_id =
					v_hba->scq_info[sts_scqn_local].scqn;

	/* Each session share with immediate SRQ and ElsSRQ */
	v_parent_queue_info->parent_els_srq_info.local_queue_id = 0;
	v_parent_queue_info->parent_els_srq_info.cqm_queue_id =
						v_hba->els_srq_info.srqn;

	/* Allocate fcp data cos value */
	v_parent_queue_info->queue_data_cos = hifc_map_fcp_data_cos(v_hba);

	/* Allocate Parent SQ vPort */
	v_parent_queue_info->parent_sq_info.vport_id +=
					v_parent_queue_info->queue_vport_id;
}

unsigned int hifc_alloc_parent_resource(void *v_hba,
					struct unf_rport_info_s *v_rport_info)
{
	unsigned int ret = UNF_RETURN_ERROR;
	struct hifc_hba_s *hba = NULL;
	struct hifc_parent_queue_info_s *v_parent_queue_info = NULL;
	unsigned long flag = 0;

	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE,  v_hba,
			return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE, v_rport_info,
			return UNF_RETURN_ERROR);

	hba = (struct hifc_hba_s *)v_hba;

	if (!hba->parent_queue_mgr) {
		HIFC_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_LOGIN_ATT, UNF_ERR,
			   "[err]Port(0x%x) cannot find parent queue pool",
			   hba->port_cfg.port_id);

		return UNF_RETURN_ERROR;
	}

	if (v_rport_info->rport_index >= UNF_HIFC_MAXRPORT_NUM) {
		HIFC_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_LOGIN_ATT, UNF_ERR,
			   "[err]Port(0x%x) allocate parent resource failed, invlaid rport index(0x%x),rport nportid(0x%x)",
			   hba->port_cfg.port_id,
			   v_rport_info->rport_index,
			   v_rport_info->nport_id);

		return UNF_RETURN_ERROR;
	}

	v_parent_queue_info =
	&hba->parent_queue_mgr->parent_queues[v_rport_info->rport_index];

	spin_lock_irqsave(&v_parent_queue_info->parent_queue_state_lock, flag);

	if (v_parent_queue_info->offload_state != HIFC_QUEUE_STATE_FREE) {
		HIFC_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_LOGIN_ATT, UNF_ERR,
			   "[err]Port(0x%x) allocate parent resource failed, invlaid rport index(0x%x),rport nportid(0x%x), offload state(0x%x)",
			   hba->port_cfg.port_id,
			   v_rport_info->rport_index,
			   v_rport_info->nport_id,
			   v_parent_queue_info->offload_state);

		spin_unlock_irqrestore(
			&v_parent_queue_info->parent_queue_state_lock,
			flag);
		return UNF_RETURN_ERROR;
	}

	v_parent_queue_info->offload_state = HIFC_QUEUE_STATE_INITIALIZED;

	/* Create Parent Context and Link List SQ */
	ret = hifc_alloc_parent_sq(hba, v_parent_queue_info, v_rport_info);
	if (ret != RETURN_OK) {
		HIFC_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_LOGIN_ATT, UNF_ERR,
			   "Port(0x%x) alloc sq resoure failed.rport index(0x%x),rport nportid(0x%x).",
			   hba->port_cfg.port_id, v_rport_info->rport_index,
			   v_rport_info->nport_id);

		v_parent_queue_info->offload_state = HIFC_QUEUE_STATE_FREE;
		hifc_invalid_parent_sq(&v_parent_queue_info->parent_sq_info);
		spin_unlock_irqrestore(
			&v_parent_queue_info->parent_queue_state_lock,
			flag);

		return UNF_RETURN_ERROR;
	}

	/* Allocate the corresponding queue xid to each parent */
	hifc_map_shared_queue_qid(hba, v_parent_queue_info,
				  v_rport_info->rport_index);

	/* Initialize Parent Context, including hardware area and ucode area */
	hifc_init_parent_ctx(v_hba, v_parent_queue_info);

	spin_unlock_irqrestore(&v_parent_queue_info->parent_queue_state_lock,
			       flag);

	HIFC_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT, UNF_MAJOR,
		   "[info]Port(0x%x) allocate parent sq success,rport index(0x%x),rport nportid(0x%x),context id(0x%x)",
		   hba->port_cfg.port_id,
		   v_rport_info->rport_index,
		   v_rport_info->nport_id,
		   v_parent_queue_info->parent_sq_info.context_id);

	return ret;
}

unsigned int hifc_free_parent_resource(void *v_hba,
				       struct unf_rport_info_s *v_rport_info)
{
	struct hifc_hba_s *hba = NULL;
	struct hifc_parent_queue_info_s *v_parent_queue_info = NULL;
	unsigned long flag = 0;
	unsigned long rst_flag = 0;
	unsigned int ret = UNF_RETURN_ERROR;
	enum hifc_session_reset_mode_e mode =
				HIFC_SESS_RST_DELETE_IO_CONN_BOTH;

	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE, v_hba,
			return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE, v_rport_info,
			return UNF_RETURN_ERROR);

	hba = (struct hifc_hba_s *)v_hba;
	if (!hba->parent_queue_mgr) {
		HIFC_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_LOGIN_ATT, UNF_ERR,
			   "[warn]Port(0x%x) cannot find parent queue pool",
			   hba->port_cfg.port_id);

		return UNF_RETURN_ERROR;
	}

	/* get parent queue info (by rport index) */
	if (v_rport_info->rport_index >= UNF_HIFC_MAXRPORT_NUM) {
		HIFC_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_LOGIN_ATT, UNF_ERR,
			   "[warn]Port(0x%x) free parent resource failed, invlaid rport_index(%u) rport_nport_id(0x%x)",
			   hba->port_cfg.port_id,
			   v_rport_info->rport_index,
			   v_rport_info->nport_id);

		return UNF_RETURN_ERROR;
	}
	v_parent_queue_info = &hba->parent_queue_mgr->parent_queues[v_rport_info->rport_index];

	spin_lock_irqsave(&v_parent_queue_info->parent_queue_state_lock, flag);

	/* 1. for has been offload */
	if (v_parent_queue_info->offload_state == HIFC_QUEUE_STATE_OFFLOADED) {
		v_parent_queue_info->offload_state =
					HIFC_QUEUE_STATE_DESTROYING;
		spin_unlock_irqrestore(
			&v_parent_queue_info->parent_queue_state_lock,
			flag);

		/* set reset state, in order to prevent I/O in_SQ */
		spin_lock_irqsave(
		&v_parent_queue_info->parent_sq_info.parent_sq_enqueue_lock,
		rst_flag);
		v_parent_queue_info->parent_sq_info.sq_in_sess_rst = UNF_TRUE;
		spin_unlock_irqrestore(
		&v_parent_queue_info->parent_sq_info.parent_sq_enqueue_lock,
		rst_flag);

		/* check pcie device state */
		if (HIFC_HBA_NOT_PRESENT(hba)) {
			HIFC_TRACE(
				UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT,
				UNF_MAJOR,
				"[info]Port(0x%x) hba is not present, free directly. rport_index(0x%x:0x%x) local_nportid(0x%x) remote_nportid(0x%x:0x%x)",
				hba->port_cfg.port_id,
				v_rport_info->rport_index,
				v_parent_queue_info->parent_sq_info.rport_index,
				v_parent_queue_info->parent_sq_info.local_port_id,
				v_rport_info->nport_id,
				v_parent_queue_info->parent_sq_info.remote_port_id);

			hifc_free_parent_queue_info(hba, v_parent_queue_info);
			return RETURN_OK;
		}

		v_parent_queue_info->parent_sq_info.del_start_jiff = jiffies;
		(void)queue_delayed_work(
				hba->work_queue,
				&v_parent_queue_info->parent_sq_info.del_work,
				(unsigned long)
				msecs_to_jiffies((unsigned int)
				HIFC_SQ_DEL_STAGE_TIMEOUT_MS));

		HIFC_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT, UNF_MAJOR,
			   "[info]Port(0x%x) begin to reset parent session, rport_index(0x%x:0x%x) local_nportid(0x%x) remote_nportid(0x%x:0x%x)",
			   hba->port_cfg.port_id,
			   v_rport_info->rport_index,
			   v_parent_queue_info->parent_sq_info.rport_index,
			   v_parent_queue_info->parent_sq_info.local_port_id,
			   v_rport_info->nport_id,
			   v_parent_queue_info->parent_sq_info.remote_port_id);

		/* Forcibly set both mode */
		mode = HIFC_SESS_RST_DELETE_IO_CONN_BOTH;
		ret = hifc_send_session_rst_cmd(v_hba, v_parent_queue_info,
						mode);

		return ret;
	} else if (v_parent_queue_info->offload_state ==
		   HIFC_QUEUE_STATE_INITIALIZED) {
		/* 2. for resource has been alloc, but not offload */
		HIFC_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT, UNF_MAJOR,
			   "[info]Port(0x%x) parent sq is not offloaded, free directly. rport_index(0x%x:0x%x) local_nportid(0x%x) remote_nportid(0x%x:0x%x)",
			   hba->port_cfg.port_id,
			   v_rport_info->rport_index,
			   v_parent_queue_info->parent_sq_info.rport_index,
			   v_parent_queue_info->parent_sq_info.local_port_id,
			   v_rport_info->nport_id,
			   v_parent_queue_info->parent_sq_info.remote_port_id);

		spin_unlock_irqrestore(
			&v_parent_queue_info->parent_queue_state_lock,
			flag);
		hifc_free_parent_queue_info(hba, v_parent_queue_info);

		return RETURN_OK;
	} else if (v_parent_queue_info->offload_state ==
		   HIFC_QUEUE_STATE_OFFLOADING) {
		/* 3. for driver has offloading CMND to uCode */
		hifc_push_destroy_parent_queue_sqe(v_hba,
						   v_parent_queue_info,
						   v_rport_info);
		spin_unlock_irqrestore(
			&v_parent_queue_info->parent_queue_state_lock,
			flag);

		HIFC_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT, UNF_MAJOR,
			   "[info]Port(0x%x) parent sq is offloading, push to delay free. rport_index(0x%x:0x%x) local_nportid(0x%x) remote_nportid(0x%x:0x%x)",
			   hba->port_cfg.port_id,
			   v_rport_info->rport_index,
			   v_parent_queue_info->parent_sq_info.rport_index,
			   v_parent_queue_info->parent_sq_info.local_port_id,
			   v_rport_info->nport_id,
			   v_parent_queue_info->parent_sq_info.remote_port_id);

		return RETURN_OK;
	} else {
		/* other state */
		HIFC_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT, UNF_WARN,
			   "[warn]Port(0x%x) parent sq is not created, do not need free state(0x%x) rport_index(0x%x:0x%x) local_nportid(0x%x) remote_nportid(0x%x:0x%x)",
			   hba->port_cfg.port_id,
			   v_parent_queue_info->offload_state,
			   v_rport_info->rport_index,
			   v_parent_queue_info->parent_sq_info.rport_index,
			   v_parent_queue_info->parent_sq_info.local_port_id,
			   v_rport_info->nport_id,
			   v_parent_queue_info->parent_sq_info.remote_port_id);

		spin_unlock_irqrestore(
			&v_parent_queue_info->parent_queue_state_lock,
			flag);

		return RETURN_OK;
	}
}

void hifc_free_parent_queue_mgr(void *v_hba)
{
	struct hifc_hba_s *hba = NULL;
	unsigned int index = 0;
	struct hifc_parent_queue_mgr_s *parent_queue_mgr;

	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE, v_hba, return);
	hba = (struct hifc_hba_s *)v_hba;

	if (!hba->parent_queue_mgr)
		return;
	parent_queue_mgr = hba->parent_queue_mgr;

	for (index = 0; index < UNF_HIFC_MAXRPORT_NUM; index++) {
		if (parent_queue_mgr->parent_queues[index].parent_ctx.virt_parent_ctx)
			parent_queue_mgr->parent_queues[index].parent_ctx.virt_parent_ctx = NULL;
	}

	if (parent_queue_mgr->parent_sq_buf_list.buflist) {
		for (index = 0;
		     index < parent_queue_mgr->parent_sq_buf_list.buf_num;
		     index++) {
			if (parent_queue_mgr->parent_sq_buf_list.buflist[index].paddr != 0) {
				pci_unmap_single(
					hba->pci_dev,
					parent_queue_mgr->parent_sq_buf_list.buflist[index].paddr,
					parent_queue_mgr->parent_sq_buf_list.buf_size,
					DMA_BIDIRECTIONAL);
				parent_queue_mgr->parent_sq_buf_list.buflist[index].paddr = 0;
			}
			if (parent_queue_mgr->parent_sq_buf_list.buflist[index].vaddr) {
				kfree(parent_queue_mgr->parent_sq_buf_list.buflist[index].vaddr);
				parent_queue_mgr->parent_sq_buf_list.buflist[index].vaddr = NULL;
			}
		}

		kfree(parent_queue_mgr->parent_sq_buf_list.buflist);
		parent_queue_mgr->parent_sq_buf_list.buflist = NULL;
	}

	vfree(parent_queue_mgr);
	hba->parent_queue_mgr = NULL;
}

void hifc_free_parent_queues(void *v_hba)
{
	unsigned int index = 0;
	unsigned long flag = 0;
	struct hifc_parent_queue_mgr_s *parent_queue_mgr = NULL;
	struct hifc_hba_s *hba = NULL;

	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE, v_hba, return);
	hba = (struct hifc_hba_s *)v_hba;
	parent_queue_mgr = hba->parent_queue_mgr;

	for (index = 0; index < UNF_HIFC_MAXRPORT_NUM; index++) {
		spin_lock_irqsave(&parent_queue_mgr->parent_queues[index].parent_queue_state_lock, flag);

		if (parent_queue_mgr->parent_queues[index].offload_state ==
		    HIFC_QUEUE_STATE_DESTROYING) {
			spin_unlock_irqrestore(
				&parent_queue_mgr->parent_queues[index].parent_queue_state_lock,
				flag);

			(void)cancel_delayed_work_sync(&parent_queue_mgr->parent_queues[index].parent_sq_info.del_work);
			(void)cancel_delayed_work_sync(&parent_queue_mgr->parent_queues[index].parent_sq_info.flush_done_tmo_work);

			/* free parent queue */
			hifc_free_parent_queue_info(
				hba,
				&parent_queue_mgr->parent_queues[index]);
			continue;
		}

		spin_unlock_irqrestore(&parent_queue_mgr->parent_queues[index].parent_queue_state_lock, flag);
	}
}

unsigned int hifc_alloc_parent_queue_mgr(void *v_hba)
{
	unsigned int index = 0;
	struct hifc_parent_queue_mgr_s *parent_queue_mgr = NULL;
	struct hifc_hba_s *hba = NULL;
	unsigned int buf_total_size;
	unsigned int buf_num;
	unsigned int alloc_idx;
	unsigned int cur_buf_idx = 0;
	unsigned int cur_buf_offset = 0;
	unsigned int uiprtctxsize = sizeof(struct hifcoe_parent_context_s);
	unsigned int buf_cnt_perhugebuf;

	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE, v_hba,
			return UNF_RETURN_ERROR);

	hba = (struct hifc_hba_s *)v_hba;

	parent_queue_mgr = (struct hifc_parent_queue_mgr_s *)vmalloc(
					sizeof(struct hifc_parent_queue_mgr_s));
	if (!parent_queue_mgr) {
		HIFC_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_REG_ATT, UNF_ERR,
			   "[err]Port(0x%x) cannot allocate queue manager",
			   hba->port_cfg.port_id);

		return UNF_RETURN_ERROR;
	}

	hba->parent_queue_mgr = parent_queue_mgr;
	memset(parent_queue_mgr, 0, sizeof(struct hifc_parent_queue_mgr_s));

	for (index = 0; index < UNF_HIFC_MAXRPORT_NUM; index++) {
		spin_lock_init(&parent_queue_mgr->parent_queues[index].parent_queue_state_lock);
		parent_queue_mgr->parent_queues[index].offload_state =
							HIFC_QUEUE_STATE_FREE;
		parent_queue_mgr->parent_queues[index].parent_sq_info.queue_header_original = NULL;
		spin_lock_init(&parent_queue_mgr->parent_queues[index].parent_sq_info.parent_sq_enqueue_lock);
		parent_queue_mgr->parent_queues[index].parent_cmd_scq_info.cqm_queue_id = INVALID_VALUE32;
		parent_queue_mgr->parent_queues[index].parent_sts_scq_info.cqm_queue_id = INVALID_VALUE32;
		parent_queue_mgr->parent_queues[index].parent_els_srq_info.cqm_queue_id = INVALID_VALUE32;
		parent_queue_mgr->parent_queues[index].parent_sq_info.del_start_jiff = INVALID_VALUE64;
		parent_queue_mgr->parent_queues[index].queue_vport_id =
								hba->vpid_start;
	}

	buf_total_size = uiprtctxsize * UNF_HIFC_MAXRPORT_NUM;
	parent_queue_mgr->parent_sq_buf_list.buf_size =
		buf_total_size > BUF_LIST_PAGE_SIZE ? BUF_LIST_PAGE_SIZE :
		buf_total_size;
	buf_cnt_perhugebuf =
		parent_queue_mgr->parent_sq_buf_list.buf_size / uiprtctxsize;
	buf_num =
		UNF_HIFC_MAXRPORT_NUM % buf_cnt_perhugebuf ?
		UNF_HIFC_MAXRPORT_NUM / buf_cnt_perhugebuf + 1 :
		UNF_HIFC_MAXRPORT_NUM / buf_cnt_perhugebuf;
	parent_queue_mgr->parent_sq_buf_list.buflist = (struct buff_list_s *)
				kmalloc(buf_num * sizeof(struct buff_list_s),
					GFP_KERNEL);
	parent_queue_mgr->parent_sq_buf_list.buf_num = buf_num;

	if (!parent_queue_mgr->parent_sq_buf_list.buflist) {
		HIFC_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_REG_ATT, UNF_WARN,
			   "[err]Allocate QueuMgr buf list failed out of memory");
		goto free_parent_queue;
	}
	memset(parent_queue_mgr->parent_sq_buf_list.buflist, 0,
	       buf_num * sizeof(struct buff_list_s));

	for (alloc_idx = 0; alloc_idx < buf_num; alloc_idx++) {
		parent_queue_mgr->parent_sq_buf_list.buflist[alloc_idx].vaddr =
			kmalloc(parent_queue_mgr->parent_sq_buf_list.buf_size,
				GFP_KERNEL);
		if (!parent_queue_mgr->parent_sq_buf_list.buflist[alloc_idx].vaddr)
			goto free_parent_queue;
		memset(
		parent_queue_mgr->parent_sq_buf_list.buflist[alloc_idx].vaddr,
		0, parent_queue_mgr->parent_sq_buf_list.buf_size);

		parent_queue_mgr->parent_sq_buf_list.buflist[alloc_idx].paddr =
			pci_map_single(
				hba->pci_dev,
				parent_queue_mgr->parent_sq_buf_list.buflist[alloc_idx].vaddr,
				parent_queue_mgr->parent_sq_buf_list.buf_size,
				DMA_BIDIRECTIONAL);
		if (pci_dma_mapping_error(
			hba->pci_dev,
			parent_queue_mgr->parent_sq_buf_list.buflist[alloc_idx].paddr)) {
			parent_queue_mgr->parent_sq_buf_list.buflist[alloc_idx].paddr = 0;
			HIFC_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_REG_ATT,
				   UNF_WARN, "[err]Map QueuMgr address failed");

			goto free_parent_queue;
		}
	}

	for (index = 0; index < UNF_HIFC_MAXRPORT_NUM; index++) {
		cur_buf_idx = index / buf_cnt_perhugebuf;
		cur_buf_offset = uiprtctxsize * (index % buf_cnt_perhugebuf);

		parent_queue_mgr->parent_queues[index].parent_ctx.virt_parent_ctx = parent_queue_mgr->parent_sq_buf_list.buflist[cur_buf_idx].vaddr + cur_buf_offset;
		parent_queue_mgr->parent_queues[index].parent_ctx.parent_ctx = parent_queue_mgr->parent_sq_buf_list.buflist[cur_buf_idx].paddr + cur_buf_offset;
	}
	UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_REG_ATT, UNF_INFO,
		  "[EVENT]Allocate bufnum:%u,buf_total_size:%u", buf_num,
		  buf_total_size);

	return RETURN_OK;

free_parent_queue:
	hifc_free_parent_queue_mgr(hba);
	return UNF_RETURN_ERROR;
}

static void hifc_release_all_wqe_pages(struct hifc_hba_s *v_hba)
{
	unsigned int index;
	struct hifc_sq_wqe_page_s *wpg = NULL;

	UNF_CHECK_VALID(0x2218, UNF_TRUE, v_hba, return);

	wpg = v_hba->sq_wpg_pool.wpg_pool_addr;

	for (index = 0; index < v_hba->sq_wpg_pool.wpg_cnt; index++) {
		if (wpg->wpg_addr) {
			dma_pool_free(v_hba->sq_wpg_pool.wpg_dma_pool,
				      wpg->wpg_addr, wpg->wpg_phy_addr);
			wpg->wpg_addr = NULL;
			wpg->wpg_phy_addr = 0;
		}

		wpg++;
	}

	HIFC_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_REG_ATT, UNF_MAJOR,
		   "[info]Port[%u] free total %u wqepages", v_hba->port_index,
		   index);
}

unsigned int hifc_alloc_parent_sq_wqe_page_pool(void *v_hba)
{
	unsigned int index = 0;
	struct hifc_sq_wqe_page_pool_s *wpg_pool = NULL;
	struct hifc_sq_wqe_page_s *wpg = NULL;
	struct hifc_hba_s *hba = NULL;

	hba = (struct hifc_hba_s *)v_hba;
	wpg_pool = &hba->sq_wpg_pool;

	INIT_LIST_HEAD(&wpg_pool->list_free_wpg_pool);
	spin_lock_init(&wpg_pool->wpg_pool_lock);
	atomic_set(&wpg_pool->wpg_in_use, 0);

	/* Calculate the number of Wqe Page required in the pool */
	wpg_pool->wpg_size = wqe_page_size;
	wpg_pool->wpg_cnt = (HIFC_MIN_WP_NUM * hba->image_count +
			    ((hba->exit_count * HIFC_SQE_SIZE) /
			    wpg_pool->wpg_size));

	wpg_pool->wqe_per_wpg = wpg_pool->wpg_size / HIFC_SQE_SIZE;

	/* Craete DMA POOL */
	wpg_pool->wpg_dma_pool = dma_pool_create("hifc_wpg_pool",
						 &hba->pci_dev->dev,
						 wpg_pool->wpg_size,
						 HIFC_SQE_SIZE, 0);
	if (!wpg_pool->wpg_dma_pool) {
		HIFC_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_REG_ATT, UNF_ERR,
			   "[err]Cannot allocate SQ WqePage DMA pool");

		goto out_create_dma_pool_err;
	}

	/* Allocate arrays to record all WqePage addresses */
	wpg_pool->wpg_pool_addr =
		(struct hifc_sq_wqe_page_s *)
		vmalloc(wpg_pool->wpg_cnt * sizeof(struct hifc_sq_wqe_page_s));
	if (!wpg_pool->wpg_pool_addr) {
		HIFC_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_REG_ATT, UNF_ERR,
			   "[err]Allocate SQ WqePageAddr array failed");

		goto out_alloc_wpg_array_err;
	}
	wpg = wpg_pool->wpg_pool_addr;
	memset(wpg, 0, wpg_pool->wpg_cnt * sizeof(struct hifc_sq_wqe_page_s));

	for (index = 0; index < wpg_pool->wpg_cnt; index++) {
		/* Apply for WqePage from DMA POOL */
		wpg->wpg_addr = dma_pool_alloc(wpg_pool->wpg_dma_pool,
					       GFP_KERNEL,
					       (u64 *)&wpg->wpg_phy_addr);
		if (!wpg->wpg_addr) {
			HIFC_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_REG_ATT,
				   UNF_ERR, "[err]Dma pool allocated failed");

			break;
		}

		/* To ensure security, clear the memory */
		memset(wpg->wpg_addr, 0, wpg_pool->wpg_size);

		/* Add to the idle linked list */
		INIT_LIST_HEAD(&wpg->entry_wpg);
		list_add_tail(&wpg->entry_wpg,
			      &wpg_pool->list_free_wpg_pool);

		wpg++;
	}
	/* ALL allocated successfully */
	if (index == wpg_pool->wpg_cnt)
		return RETURN_OK;

	hifc_release_all_wqe_pages(hba);
	vfree(wpg_pool->wpg_pool_addr);
	wpg_pool->wpg_pool_addr = NULL;

out_alloc_wpg_array_err:
	dma_pool_destroy(wpg_pool->wpg_dma_pool);
	wpg_pool->wpg_dma_pool = NULL;

out_create_dma_pool_err:
	return UNF_RETURN_ERROR;
}

void hifc_free_parent_sq_wqe_page_pool(void *v_hba)
{
	struct hifc_hba_s *hba = NULL;

	UNF_CHECK_VALID(0x2220, UNF_TRUE, v_hba, return);
	hba = (struct hifc_hba_s *)v_hba;

	hifc_release_all_wqe_pages(hba);
	hba->sq_wpg_pool.wpg_cnt = 0;

	if (hba->sq_wpg_pool.wpg_pool_addr) {
		vfree(hba->sq_wpg_pool.wpg_pool_addr);
		hba->sq_wpg_pool.wpg_pool_addr = NULL;
	}

	if (hba->sq_wpg_pool.wpg_dma_pool) {
		dma_pool_destroy(hba->sq_wpg_pool.wpg_dma_pool);
		hba->sq_wpg_pool.wpg_dma_pool = NULL;
	}
}

static inline void hifc_set_sq_wqe_owner_be(void *v_sqe)
{
	unsigned int *sqe_dw = (unsigned int *)v_sqe;

	/* Ensure that the write of WQE is complete */
	mb();
	sqe_dw[HIFC_SQE_SECOND_OBIT_DW_POS] |= HIFC_SQE_OBIT_SET_MASK_BE;

	/* Ensure that the write of Second Obit is complete */
	mb();
	sqe_dw[HIFC_SQE_FIRST_OBIT_DW_POS] |= HIFC_SQE_OBIT_SET_MASK_BE;
}

static void hifc_free_head_wqe_page(struct hifc_parent_sq_info_s *v_sq)
{
	struct hifc_hba_s *hba = NULL;
	struct hifc_sq_wqe_page_s *sq_wpg = NULL;
	struct list_head *entry_head_wqe_page = NULL;
	unsigned long flag = 0;

	atomic_dec(&v_sq->wqe_page_cnt);

	hba = (struct hifc_hba_s *)v_sq->phba;
	sq_wpg = HIFC_GET_SQ_HEAD(v_sq);
	memset((void *)sq_wpg->wpg_addr, WQE_MARKER_0,
	       hba->sq_wpg_pool.wpg_size);

	spin_lock_irqsave(&hba->sq_wpg_pool.wpg_pool_lock, flag);
	entry_head_wqe_page = &sq_wpg->entry_wpg;
	list_del(entry_head_wqe_page);
	list_add_tail(entry_head_wqe_page,
		      &hba->sq_wpg_pool.list_free_wpg_pool);

	/* WqePage Pool counter */
	atomic_dec(&hba->sq_wpg_pool.wpg_in_use);

	spin_unlock_irqrestore(&hba->sq_wpg_pool.wpg_pool_lock, flag);
}

static unsigned int hifc_parent_sq_ring_door_bell(
				struct hifc_parent_sq_info_s *v_sq)
{
	unsigned int ret = RETURN_OK;
	int ravl;
	unsigned short pmsn;
	unsigned char pmsn_lo;
	unsigned char pmsn_hi;
	unsigned long long db_val_qw;
	struct hifc_hba_s *hba;
	struct hifc_parent_sq_db_s door_bell;

	hba = (struct hifc_hba_s *)v_sq->phba;
	pmsn = v_sq->last_pmsn;
	/* Obtain the low 8 Bit of PMSN */
	pmsn_lo = (unsigned char)(pmsn & 0xFF);
	/* Obtain the high 8 Bit of PMSN */
	pmsn_hi = (unsigned char)((pmsn >> 8) & 0xFF);
	door_bell.wd0.service_type = HIFC_LSW(v_sq->service_type);
	door_bell.wd0.cos = hba->port_index;
	door_bell.wd0.c = 0;
	door_bell.wd0.arm = HIFC_DB_ARM_DISABLE;
	door_bell.wd0.cntx_size = HIFC_CNTX_SIZE_T_256B;
	door_bell.wd0.vport = v_sq->vport_id;
	door_bell.wd0.xid = v_sq->context_id;
	door_bell.wd1.sm_data = v_sq->cache_id;
	door_bell.wd1.qid = v_sq->sq_queue_id;
	door_bell.wd1.pi_hi = (unsigned int)pmsn_hi;

	if (unlikely(v_sq->cache_id == INVALID_VALUE32)) {
		HIFC_TRACE(UNF_EVTLOG_IO_ERR, UNF_LOG_IO_ATT, UNF_ERR,
			   "[err]Port(0x%x) SQ(0x%x) send DB error invalid cachedid",
			   hba->port_cfg.port_id, v_sq->context_id);
		HIFC_HBA_STAT(hba, HIFC_STAT_PARENT_SQ_INVALID_CACHED_ID);
		return UNF_RETURN_ERROR;
	}

	/* Fill Doorbell Record */
	db_val_qw = v_sq->queue_header->doorbell_record;
	db_val_qw &= (unsigned long long)(~(0xFFFFFFFF));
	db_val_qw |= (unsigned long long)((unsigned long long)pmsn << 16 |
					   pmsn);
	v_sq->queue_header->doorbell_record = cpu_to_be64(db_val_qw);

	/* ring doorbell */
	db_val_qw = *(unsigned long long *)&door_bell;
	hifc_cpu_to_big32(&db_val_qw, sizeof(db_val_qw));

	ravl = cqm_ring_hardware_db(hba->hw_dev_handle, SERVICE_T_FC, pmsn_lo,
				    db_val_qw);
	if (unlikely(ravl != CQM_SUCCESS)) {
		HIFC_TRACE(UNF_EVTLOG_IO_ERR, UNF_LOG_IO_ATT, UNF_ERR,
			   "[err]SQ(0x%x) send DB(0x%llx) failed",
			   v_sq->context_id, db_val_qw);

		ret = UNF_RETURN_ERROR;
	}

	/* Doorbell success counter */
	atomic_inc(&v_sq->sq_dbl_cnt);

	return ret;
}

unsigned int hifc_parent_sq_enqueue(struct hifc_parent_sq_info_s *v_sq,
				    struct hifcoe_sqe_s *v_io_sqe)
{
	unsigned char wqe_type = 0;
	unsigned int ret = RETURN_OK;
	unsigned int addr_wd = INVALID_VALUE32;
	unsigned int msn_wd = INVALID_VALUE32;
	unsigned short link_wqe_msn = 0;
	unsigned long flag = 0;
	struct hifc_sq_wqe_page_s *new_wqe_page = NULL;
	struct hifc_sq_wqe_page_s *tail_wpg = NULL;
	struct hifcoe_sqe_s *sqe_in_wp = NULL;
	struct hifc_link_wqe_s *link_wqe = NULL;
	struct hifc_hba_s *hba = (struct hifc_hba_s *)v_sq->phba;

	wqe_type = (unsigned char)HIFC_GET_WQE_TYPE(v_io_sqe);

	/* Serial enqueue */
	spin_lock_irqsave(&v_sq->parent_sq_enqueue_lock, flag);

	/* If the SQ is invalid, the wqe is discarded */
	if (unlikely(!atomic_read(&v_sq->sq_valid))) {
		HIFC_TRACE(UNF_EVTLOG_IO_ERR, UNF_LOG_IO_ATT, UNF_ERR,
			   "[err]SQ is invalid, reject wqe(0x%x)", wqe_type);

		spin_unlock_irqrestore(&v_sq->parent_sq_enqueue_lock, flag);

		return UNF_RETURN_ERROR;
	}

	/*
	 * The heartbeat detection status is 0, which allows control sessions
	 * enqueuing
	 */
	if (unlikely((!hba->heart_status) && HIFC_WQE_IS_IO(v_io_sqe))) {
		spin_unlock_irqrestore(&v_sq->parent_sq_enqueue_lock, flag);

		HIFC_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_NORMAL, UNF_ERR,
			   "[err]Heart status is false");

		return UNF_RETURN_ERROR;
	}

	/* Ensure to be offloaded */
	if (unlikely(atomic_read(&v_sq->sq_cashed) != UNF_TRUE)) {
		HIFC_ERR_IO_STAT((struct hifc_hba_s *)v_sq->phba, wqe_type);
		HIFC_HBA_STAT((struct hifc_hba_s *)v_sq->phba,
			      HIFC_STAT_PARENT_SQ_NOT_OFFLOADED);

		HIFC_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_NORMAL, UNF_ERR,
			   "[err]RPort(0x%x) Sq(0x%x) is not offloaded, reject wqe(0x%x)",
			   v_sq->rport_index, v_sq->context_id, wqe_type);

		spin_unlock_irqrestore(&v_sq->parent_sq_enqueue_lock, flag);

		return UNF_RETURN_ERROR;
	}

	/*
	 * Whether the SQ is in the flush state. Temporarily allow the control
	 * sessions to enqueue.
	 */
	if (unlikely(v_sq->port_in_flush && HIFC_WQE_IS_IO(v_io_sqe))) {
		HIFC_ERR_IO_STAT((struct hifc_hba_s *)v_sq->phba, wqe_type);
		HIFC_HBA_STAT((struct hifc_hba_s *)v_sq->phba,
			      HIFC_STAT_PARENT_IO_FLUSHED);

		HIFC_TRACE(UNF_EVTLOG_IO_WARN, UNF_LOG_IO_ATT, UNF_WARN,
			   "[warn]SQ(0x%x) in flush, cmsn(0x%x)-pmsn(0x%x), reject wqe(0x%x)",
			   v_sq->context_id,
			   HIFC_GET_QUEUE_CMSN(v_sq),
			   v_sq->last_pmsn, wqe_type);

		spin_unlock_irqrestore(&v_sq->parent_sq_enqueue_lock, flag);

		return UNF_RETURN_ERROR;
	}

	/*
	 * If the SQ is in the Seesion deletion state and is the WQE of the
	 * I/O path, the I/O failure is directly returned
	 */
	if (unlikely(v_sq->sq_in_sess_rst && HIFC_WQE_IS_IO(v_io_sqe))) {
		HIFC_ERR_IO_STAT((struct hifc_hba_s *)v_sq->phba, wqe_type);
		HIFC_HBA_STAT((struct hifc_hba_s *)v_sq->phba,
			      HIFC_STAT_PARENT_IO_FLUSHED);

		HIFC_TRACE(UNF_EVTLOG_IO_ERR, UNF_LOG_IO_ATT, UNF_ERR,
			   "[err]SQ(0x%x) in session reset, reject wqe(0x%x)",
			   v_sq->context_id, wqe_type);

		spin_unlock_irqrestore(&v_sq->parent_sq_enqueue_lock, flag);

		return UNF_RETURN_ERROR;
	}

	/*
	 * The PMSN position of the SQE that can be put into the SQE is LinkWqe.
	 * Apply to the CQM for a new page
	 */
	tail_wpg = HIFC_GET_SQ_TAIL(v_sq);

	if (v_sq->wqe_offset == v_sq->wqe_num_per_buf) {
		HIFC_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_NORMAL, UNF_INFO,
			   "[info]RPort(0x%x) Sq(0x%x) add wqepage at pmsn(0x%x), WpgCnt(0x%x)",
			   v_sq->rport_index, v_sq->context_id, v_sq->last_pmsn,
			   atomic_read(&v_sq->wqe_page_cnt));

		/* Add a new Wqe Page */
		new_wqe_page = hifc_add_one_wqe_page(v_sq);
		if (unlikely(!new_wqe_page)) {
			HIFC_ERR_IO_STAT((struct hifc_hba_s *)v_sq->phba,
					 wqe_type);
			spin_unlock_irqrestore(&v_sq->parent_sq_enqueue_lock,
					       flag);

			return UNF_RETURN_ERROR;
		}

		/*
		 * Set the next address of LinkWqe to the newly applied WqePage
		 */
		link_wqe = (struct hifc_link_wqe_s *)
			hifc_get_wqe_page_entry(tail_wpg, v_sq->wqe_offset);
		addr_wd = HIFC_MSD(new_wqe_page->wpg_phy_addr);
		link_wqe->next_page_addr_hi = cpu_to_be32(addr_wd);
		addr_wd = HIFC_LSD(new_wqe_page->wpg_phy_addr);
		link_wqe->next_page_addr_lo = cpu_to_be32(addr_wd);

		/* Fill LinkWqe msn */
		link_wqe_msn = HIFC_MSN_DEC(v_sq->last_pmsn);
		msn_wd = be32_to_cpu(link_wqe->val_wd1);
		msn_wd |= ((unsigned int)(link_wqe_msn & 0xffff));
		msn_wd |= (((unsigned int)(link_wqe_msn & 0x7fff)) << 16);
		link_wqe->val_wd1 = cpu_to_be32(msn_wd);

		/* Set LinkWqe's Owner Bit valid */
		hifc_set_sq_wqe_owner_be(link_wqe);

		/* The newly added WqePage starts from 0 */
		v_sq->wqe_offset = 0;

		/* Point to the tail, Link Wqe */
		tail_wpg = HIFC_GET_SQ_TAIL(v_sq);

		/* Update counter */
		atomic_inc(&v_sq->wqe_page_cnt);
	}

	/* Set pmsn of WQE Control Section, and set Owner-Bit invalid */
	hifc_build_wqe_owner_pmsn(&v_io_sqe->ctrl_sl, !v_sq->last_pi_owner,
				  v_sq->last_pmsn);

	/* Port WQE send counter */
	HIFC_IO_STAT((struct hifc_hba_s *)v_sq->phba, wqe_type);

	/*
	 * Set Done Bit of WQE, convert Control and Task Section to big endian
	 */
	hifc_convert_parent_wqe_to_big_endian(v_io_sqe);

	/*
	 * Find the position of the pointer that the SQE is placed in the
	 * WQEPAGE
	 */
	sqe_in_wp = (struct hifcoe_sqe_s *)
		    hifc_get_wqe_page_entry(tail_wpg, v_sq->wqe_offset);

	/* Copy sqe from the local memory to WqePage */
	memcpy(sqe_in_wp, v_io_sqe, sizeof(struct hifcoe_sqe_s));

	hifc_set_sq_wqe_owner_be(sqe_in_wp);

	/* ring DoorBell */
	ret = hifc_parent_sq_ring_door_bell(v_sq);
	if (unlikely(ret != RETURN_OK))
		HIFC_ERR_IO_STAT((struct hifc_hba_s *)v_sq->phba, wqe_type);

	/* Update the count of the next SQE enqueuing */
	v_sq->wqe_offset += 1;
	v_sq->last_pmsn = HIFC_MSN_INC(v_sq->last_pmsn);

	/* sq_wqe_cnt is updated for SQ statistics */
	atomic_inc(&v_sq->sq_wqe_cnt);
	atomic_inc(&v_sq->sqe_minus_cqe_cnt);
	HIFC_SQ_IO_STAT(v_sq, wqe_type);
	spin_unlock_irqrestore(&v_sq->parent_sq_enqueue_lock, flag);

	return ret;
}

static int hifc_msn_in_wqe_page(unsigned int start_msn, unsigned int end_msn,
				unsigned int cur_msn)
{
	int ret = UNF_TRUE;

	if (end_msn >= start_msn) {
		if ((cur_msn < start_msn) || (cur_msn > end_msn))
			ret = UNF_FALSE;
		else
			ret = UNF_TRUE;

	} else {
		if ((cur_msn > end_msn) && (cur_msn < start_msn))
			ret = UNF_FALSE;
		else
			ret = UNF_TRUE;
	}

	return ret;
}

void hifc_free_sq_wqe_page(struct hifc_parent_sq_info_s *v_sq,
			   unsigned int cur_msn)
{
	unsigned short wpg_start_cmsn = 0;
	unsigned short wpg_end_cmsn = 0;
	int wqe_page_in_use;

	/* If there is only zero or one Wqe Page, no release is required */
	if (atomic_read(&v_sq->wqe_page_cnt) <= HIFC_MIN_WP_NUM)
		return;

	/*
	 * Check whether the current MSN is within the MSN range covered
	 * by the WqePage
	 */
	wpg_start_cmsn = v_sq->head_start_cmsn;
	wpg_end_cmsn = v_sq->head_end_cmsn;
	wqe_page_in_use = hifc_msn_in_wqe_page(wpg_start_cmsn,
					       wpg_end_cmsn, cur_msn);

	/*
	 * If the value of CMSN is within the current Wqe Page, no release is
	 * required
	 */
	if (wqe_page_in_use == UNF_TRUE)
		return;
	/* Free WqePage */
	hifc_free_head_wqe_page(v_sq);

	/* Obtain the start MSN of the next WqePage */
	wpg_start_cmsn = HIFC_MSN_INC(wpg_end_cmsn);

	/* obtain the end MSN of the next WqePage */
	wpg_end_cmsn = HIFC_GET_WP_END_CMSN(wpg_start_cmsn,
					    v_sq->wqe_num_per_buf);

	/* Set new MSN range */
	v_sq->head_start_cmsn = wpg_start_cmsn;
	v_sq->head_end_cmsn = wpg_end_cmsn;
}

static void hifc_update_sq_wqe_completion_stat(
			struct hifc_parent_sq_info_s *v_sq,
			union hifcoe_scqe_u *v_scqe)
{
	struct hifcoe_scqe_rcv_els_gs_rsp_s *els_gs_rsp = NULL;

	els_gs_rsp = (struct hifcoe_scqe_rcv_els_gs_rsp_s *)v_scqe;

	/*
	 * For the ELS/GS RSP intermediate frame and the CQE that is more
	 * than the ELS_GS_RSP_EXCH_CHECK_FAIL, no statistics are required
	 */
	if (unlikely(HIFC_GET_SCQE_TYPE(v_scqe) == HIFC_SCQE_ELS_RSP) ||
	    (HIFC_GET_SCQE_TYPE(v_scqe) == HIFC_SCQE_GS_RSP)) {
		if (!els_gs_rsp->wd3.end_rsp || !HIFC_SCQE_ERR_TO_CM(v_scqe))
			return;
	}

	/*
	 * When the SQ statistics are updated, the PlogiAcc or PlogiAccSts
	 * that is implicitly unloaded will enter here, and one more CQE count
	 * is added
	 */
	atomic_inc(&v_sq->sq_cqe_cnt);
	atomic_dec(&v_sq->sqe_minus_cqe_cnt);
	HIFC_SQ_IO_STAT(v_sq, HIFC_GET_SCQE_TYPE(v_scqe));
}

unsigned int hifc_reclaim_sq_wqe_page(void *v_hba, union hifcoe_scqe_u *v_scqe)
{
	unsigned int cur_msn = 0;
	unsigned int rport_index = INVALID_VALUE32;
	struct hifc_hba_s *hba = NULL;
	struct hifc_parent_sq_info_s *sq = NULL;
	struct hifc_parent_queue_info_s *v_parent_queue_info = NULL;
	unsigned long state_lock_flag = 0;

	hba = (struct hifc_hba_s *)v_hba;
	rport_index = HIFC_GET_SCQE_CONN_ID(v_scqe);
	if (rport_index >= UNF_HIFC_MAXRPORT_NUM) {
		HIFC_TRACE(UNF_EVTLOG_IO_ERR, UNF_LOG_IO_ATT, UNF_ERR,
			   "[err]Port(0x%x) do not have rport index: 0x%x",
			   hba->port_cfg.port_id, rport_index);

		return UNF_RETURN_ERROR;
	}

	v_parent_queue_info =
		&hba->parent_queue_mgr->parent_queues[rport_index];
	sq = &v_parent_queue_info->parent_sq_info;
	/* If there is only zero or one Wqe Page, no release is required */
	if (atomic_read(&sq->wqe_page_cnt) <= HIFC_MIN_WP_NUM) {
		hifc_update_sq_wqe_completion_stat(sq, v_scqe);
		return RETURN_OK;
	} else {
		spin_lock_irqsave(
			&v_parent_queue_info->parent_queue_state_lock,
			state_lock_flag);

		if (v_parent_queue_info->offload_state ==
		    HIFC_QUEUE_STATE_FREE) {
			HIFC_TRACE(UNF_EVTLOG_IO_WARN, UNF_LOG_IO_ATT, UNF_WARN,
				   "[warn]Port(0x%x) RPort(0x%x) already released, no need to reclaim sq wqepage",
				   hba->port_cfg.port_id, rport_index);
			spin_unlock_irqrestore(
				&v_parent_queue_info->parent_queue_state_lock,
				state_lock_flag);

			return RETURN_OK;
		}

		cur_msn = HIFC_GET_QUEUE_CMSN(sq);
		hifc_free_sq_wqe_page(sq, cur_msn);
		hifc_update_sq_wqe_completion_stat(sq, v_scqe);

		spin_unlock_irqrestore(
			&v_parent_queue_info->parent_queue_state_lock,
			state_lock_flag);

		return RETURN_OK;
	}
}

struct hifc_parent_queue_info_s *hifc_find_parent_queue_info_by_pkg(
						void *v_hba,
						struct unf_frame_pkg_s *v_pkg)
{
	unsigned int rport_index = 0;
	struct hifc_parent_queue_info_s *v_parent_queue_info = NULL;
	struct hifc_hba_s *hba = NULL;

	hba = (struct hifc_hba_s *)v_hba;
	rport_index = v_pkg->private[PKG_PRIVATE_XCHG_RPORT_INDEX];

	if (unlikely(rport_index >= UNF_HIFC_MAXRPORT_NUM)) {
		HIFC_TRACE(UNF_EVTLOG_IO_WARN, UNF_LOG_IO_ATT, UNF_MAJOR,
			   "[warn]Port(0x%x) send pkg sid_did(0x%x_0x%x), but uplevel allocate invalid rport index: 0x%x",
			   hba->port_cfg.port_id, v_pkg->frame_head.csctl_sid,
			   v_pkg->frame_head.rctl_did, rport_index);

		return NULL;
	}

	/* parent -->> session */
	v_parent_queue_info =
			&hba->parent_queue_mgr->parent_queues[rport_index];

	return v_parent_queue_info;
}

struct hifc_parent_queue_info_s *hifc_find_parent_queue_info_by_id(
						struct hifc_hba_s *v_hba,
						unsigned int v_local_id,
						unsigned int v_remote_id)
{
	unsigned int index = 0;
	unsigned long flag = 0;
	struct hifc_parent_queue_mgr_s *parent_queue_mgr = NULL;
	struct hifc_parent_queue_info_s *v_parent_queue_info = NULL;

	parent_queue_mgr = v_hba->parent_queue_mgr;
	if (!parent_queue_mgr)
		return NULL;

	/* rport_number -->> parent_number -->> session_number */
	for (index = 0; index < UNF_HIFC_MAXRPORT_NUM; index++) {
		spin_lock_irqsave(&parent_queue_mgr->parent_queues[index].parent_queue_state_lock, flag);

		/* local_id & remote_id & offload */
		if ((v_local_id == parent_queue_mgr->parent_queues[index].parent_sq_info.local_port_id) &&
		    (v_remote_id == parent_queue_mgr->parent_queues[index].parent_sq_info.remote_port_id) &&
		    (parent_queue_mgr->parent_queues[index].offload_state ==
		    HIFC_QUEUE_STATE_OFFLOADED)) {
			v_parent_queue_info =
				&parent_queue_mgr->parent_queues[index];
			spin_unlock_irqrestore(&parent_queue_mgr->parent_queues[index].parent_queue_state_lock, flag);

			return v_parent_queue_info;
		}

		spin_unlock_irqrestore(&parent_queue_mgr->parent_queues[index].parent_queue_state_lock, flag);
	}

	return NULL;
}

struct hifc_parent_queue_info_s *hifc_find_offload_parent_queue(
						void *v_hba,
						unsigned int v_local_id,
						unsigned int v_remote_id,
						unsigned int v_rport_index)
{
	unsigned int index = 0;
	unsigned long flag = 0;
	struct hifc_hba_s *hba = v_hba;
	struct hifc_parent_queue_mgr_s *parent_queue_mgr = NULL;
	struct hifc_parent_queue_info_s *v_parent_queue_info = NULL;

	parent_queue_mgr = hba->parent_queue_mgr;
	if (!parent_queue_mgr)
		return NULL;

	for (index = 0; index < UNF_HIFC_MAXRPORT_NUM; index++) {
		if (index == v_rport_index)
			continue;

		spin_lock_irqsave(&parent_queue_mgr->parent_queues[index].parent_queue_state_lock, flag);

		if ((v_local_id == parent_queue_mgr->parent_queues[index].parent_sq_info.local_port_id) &&
		    (v_remote_id == parent_queue_mgr->parent_queues[index].parent_sq_info.remote_port_id) &&
		    (parent_queue_mgr->parent_queues[index].offload_state !=
		    HIFC_QUEUE_STATE_FREE) &&
		    (parent_queue_mgr->parent_queues[index].offload_state !=
				HIFC_QUEUE_STATE_INITIALIZED)) {
			v_parent_queue_info =
				&parent_queue_mgr->parent_queues[index];
			spin_unlock_irqrestore(
				&parent_queue_mgr->parent_queues[index].parent_queue_state_lock, flag);

			return v_parent_queue_info;
		}

		spin_unlock_irqrestore(&parent_queue_mgr->parent_queues[index].parent_queue_state_lock, flag);
	}

	return NULL;
}

struct hifc_parent_sq_info_s *hifc_find_parent_sq_by_pkg(
						void *v_hba,
						struct unf_frame_pkg_s *v_pkg)
{
	struct hifc_parent_queue_info_s *v_parent_queue_info = NULL;
	struct cqm_qpc_mpt_s *cqm_parent_ctx_obj = NULL;
	struct hifc_hba_s *hba = NULL;

	hba = (struct hifc_hba_s *)v_hba;

	v_parent_queue_info = hifc_find_parent_queue_info_by_pkg(hba, v_pkg);
	if (unlikely(!v_parent_queue_info)) {
		v_parent_queue_info = hifc_find_parent_queue_info_by_id(
						hba,
						v_pkg->frame_head.csctl_sid &
						UNF_NPORTID_MASK,
						v_pkg->frame_head.rctl_did &
						UNF_NPORTID_MASK);
		if (!v_parent_queue_info) {
			HIFC_TRACE(UNF_EVTLOG_IO_WARN, UNF_LOG_IO_ATT, UNF_WARN,
				   "[err]Port(0x%x) send pkg sid_did(0x%x_0x%x), get a null parent queue information",
				   hba->port_cfg.port_id,
				   v_pkg->frame_head.csctl_sid,
				   v_pkg->frame_head.rctl_did);

			return NULL;
		}
	}

	cqm_parent_ctx_obj = v_parent_queue_info->parent_ctx.cqm_parent_ctx_obj;
	if (unlikely(!cqm_parent_ctx_obj)) {
		HIFC_TRACE(UNF_EVTLOG_IO_WARN, UNF_LOG_IO_ATT, UNF_WARN,
			   "[err]Port(0x%x) send pkg sid_did(0x%x_0x%x) with this rport has not alloc parent sq information",
			   hba->port_cfg.port_id, v_pkg->frame_head.csctl_sid,
			   v_pkg->frame_head.rctl_did);

		return NULL;
	}

	return &v_parent_queue_info->parent_sq_info;
}

struct hifc_parent_ctx_s *hifc_get_parnt_ctx_virt_addr_by_pkg(
						void *v_hba,
						struct unf_frame_pkg_s *v_pkg)
{
	struct hifc_parent_queue_info_s *v_parent_queue_info = NULL;
	struct hifc_hba_s *hba = NULL;

	hba = (struct hifc_hba_s *)v_hba;
	v_parent_queue_info = hifc_find_parent_queue_info_by_pkg(hba, v_pkg);
	if (!v_parent_queue_info) {
		HIFC_TRACE(UNF_EVTLOG_IO_WARN, UNF_LOG_IO_ATT, UNF_WARN,
			   "[err]Port(0x%x) send pkg sid_did(0x%x_0x%x), get a null parent queue information",
			   hba->port_cfg.port_id, v_pkg->frame_head.csctl_sid,
			   v_pkg->frame_head.rctl_did);

		return NULL;
	}

	if ((!v_parent_queue_info->parent_ctx.cqm_parent_ctx_obj) ||
	    (!v_parent_queue_info->parent_ctx.virt_parent_ctx)) {
		HIFC_TRACE(UNF_EVTLOG_IO_WARN, UNF_LOG_IO_ATT, UNF_WARN,
			   "[err]Port(0x%x) send pkg sid_did(0x%x_0x%x), but this rport have not allocate a parent context yet",
			   hba->port_cfg.port_id, v_pkg->frame_head.csctl_sid,
			   v_pkg->frame_head.rctl_did);

		return NULL;
	}

	if (!v_parent_queue_info->parent_ctx.cqm_parent_ctx_obj->vaddr) {
		HIFC_TRACE(UNF_EVTLOG_IO_WARN, UNF_LOG_IO_ATT, UNF_WARN,
			   "[err]Port(0x%x) send pkg sid_did(0x%x_0x%x), but cqm have not allocate a parent context yet",
			   hba->port_cfg.port_id, v_pkg->frame_head.csctl_sid,
			   v_pkg->frame_head.rctl_did);

		return NULL;
	}

	return &v_parent_queue_info->parent_ctx;
}

unsigned int hifc_check_all_parent_queue_free(struct hifc_hba_s *v_hba)
{
	unsigned int index = 0;
	unsigned long flag = 0;
	struct hifc_parent_queue_mgr_s *parent_queue_mgr = NULL;

	parent_queue_mgr = v_hba->parent_queue_mgr;
	if (!parent_queue_mgr) {
		HIFC_TRACE(UNF_EVTLOG_IO_WARN, UNF_LOG_IO_ATT, UNF_WARN,
			   "[err]Port(0x%x) get a null parent queue mgr",
			   v_hba->port_cfg.port_id);

		return UNF_RETURN_ERROR;
	}

	for (index = 0; index < UNF_HIFC_MAXRPORT_NUM; index++) {
		spin_lock_irqsave(
		&parent_queue_mgr->parent_queues[index].parent_queue_state_lock,
		flag);

		if (parent_queue_mgr->parent_queues[index].offload_state !=
		    HIFC_QUEUE_STATE_FREE) {
			spin_unlock_irqrestore(&parent_queue_mgr->parent_queues[index].parent_queue_state_lock, flag);
			return UNF_RETURN_ERROR;
		}

		spin_unlock_irqrestore(&parent_queue_mgr->parent_queues[index].parent_queue_state_lock, flag);
	}

	return RETURN_OK;
}

unsigned int hifc_get_parent_ctx_xid_by_pkg(void *v_hba,
					    struct unf_frame_pkg_s *v_pkg)
{
	struct hifc_parent_queue_info_s *v_parent_queue_info = NULL;
	struct hifc_hba_s *hba = NULL;

	hba = (struct hifc_hba_s *)v_hba;

	v_parent_queue_info = hifc_find_parent_queue_info_by_pkg(hba, v_pkg);
	if (!v_parent_queue_info) {
		HIFC_TRACE(UNF_EVTLOG_IO_WARN, UNF_LOG_IO_ATT, UNF_WARN,
			   "[err]Port(0x%x) send pkg sid_did(0x%x_0x%x), get a null parent queue information",
			   hba->port_cfg.port_id, v_pkg->frame_head.csctl_sid,
			   v_pkg->frame_head.rctl_did);

		return INVALID_VALUE32;
	}

	if ((!v_parent_queue_info->parent_ctx.cqm_parent_ctx_obj) ||
	    (!v_parent_queue_info->parent_ctx.cqm_parent_ctx_obj->vaddr)) {
		HIFC_TRACE(UNF_EVTLOG_IO_WARN, UNF_LOG_IO_ATT, UNF_WARN,
			   "[err]Port(0x%x) send pkg sid_did(0x%x_0x%x),but this rport have not allocate a parent context yet",
			   hba->port_cfg.port_id, v_pkg->frame_head.csctl_sid,
			   v_pkg->frame_head.rctl_did);

		return INVALID_VALUE32;
	}

	return v_parent_queue_info->parent_ctx.cqm_parent_ctx_obj->xid;
}

static void hifc_flush_specific_scq(struct hifc_hba_s *v_hba,
				    unsigned int index)
{
	/*
	 * The software interrupt is scheduled and processed during the second
	 * timeout period
	 */
	struct hifc_scq_info_s *scq_info = NULL;
	unsigned int flush_done_time = 0;

	scq_info = &v_hba->scq_info[index];
	atomic_set(&scq_info->flush_state, HIFC_QUEUE_FLUSH_DOING);
	tasklet_schedule(&scq_info->tasklet);

	/*
	 * Wait for a maximum of 2 seconds. If the SCQ soft interrupt is not
	 * scheduled within 2 seconds, only timeout is returned
	 */
	while ((atomic_read(&scq_info->flush_state) != HIFC_QUEUE_FLUSH_DONE) &&
	       (flush_done_time < HIFC_QUEUE_FLUSH_WAIT_TIMEOUT_MS)) {
		msleep(HIFC_QUEUE_FLUSH_WAIT_MS);
		flush_done_time += HIFC_QUEUE_FLUSH_WAIT_MS;
		tasklet_schedule(&scq_info->tasklet);
	}

	if (atomic_read(&scq_info->flush_state) != HIFC_QUEUE_FLUSH_DONE) {
		HIFC_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_NORMAL, UNF_WARN,
			   "[warn]Port(0x%x) special scq(0x%x) flush timeout",
			   v_hba->port_cfg.port_id, index);
	}
}

static void hifc_flush_cmd_scq(struct hifc_hba_s *v_hba)
{
	unsigned int index = 0;

	for (index = HIFC_CMD_SCQN_START; index < HIFC_SESSION_SCQ_NUM;
	     index += HIFC_SCQS_PER_SESSION)
		hifc_flush_specific_scq(v_hba, index);
}

static void hifc_flush_sts_scq(struct hifc_hba_s *v_hba)
{
	unsigned int index = 0;

	/* for each STS SCQ */
	for (index = HIFC_STS_SCQN_START; index < HIFC_SESSION_SCQ_NUM;
	     index += HIFC_SCQS_PER_SESSION)
		hifc_flush_specific_scq(v_hba, index);
}

static void hifc_flush_all_scq(struct hifc_hba_s *v_hba)
{
	hifc_flush_cmd_scq(v_hba);
	hifc_flush_sts_scq(v_hba);
	/* Flush Default SCQ */
	hifc_flush_specific_scq(v_hba, HIFC_SESSION_SCQ_NUM);
}

static void hifc_wait_root_rq_empty(struct hifc_hba_s *v_hba)
{
	unsigned int q_index;
	struct hifc_root_info_s *root_info;
	struct hifc_root_rq_info_s *rq_info;
	unsigned int flush_done_time = 0;

	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE, v_hba, return);

	root_info = &v_hba->root_info;

	for (q_index = 0; q_index < root_info->rq_num; q_index++) {
		rq_info = (struct hifc_root_rq_info_s *)(root_info->rq_info) +
			  q_index;
		atomic_set(&rq_info->flush_state, HIFC_QUEUE_FLUSH_DOING);
		flush_done_time = 0;

		while ((atomic_read(&rq_info->flush_state) !=
		       HIFC_QUEUE_FLUSH_DONE) &&
		       (flush_done_time < HIFC_QUEUE_FLUSH_WAIT_TIMEOUT_MS)) {
			msleep(HIFC_QUEUE_FLUSH_WAIT_MS);
			flush_done_time += HIFC_QUEUE_FLUSH_WAIT_MS;
			tasklet_schedule(&rq_info->tasklet);
		}

		if (atomic_read(&rq_info->flush_state) !=
		    HIFC_QUEUE_FLUSH_DONE) {
			HIFC_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_NORMAL,
				   UNF_WARN,
				   "[warn]Port(0x%x) RootRq(0x%x) flush timeout",
				   v_hba->port_cfg.port_id, q_index);
		}
	}
}

void hifc_wait_root_sq_empty(void *v_hba)
{
#define HIFC_WAIT_ROOT_SQ_EMPTY_TIMEOUT_MS (50)

	unsigned int q_index = 0;
	struct hifc_root_info_s *root_info = NULL;
	struct hifc_root_sq_info_s *sq_info = NULL;
	struct hifc_hba_s *hba = NULL;
	unsigned int start_wait_time = 0;
	int time_out = UNF_FALSE;

	hba = (struct hifc_hba_s *)v_hba;
	root_info = &hba->root_info;

	/*
	 * Traverse all root sq (just one) in the HBA and change the status to
	 * in_flush
	 */
	for (q_index = 0; q_index < root_info->sq_num; q_index++) {
		sq_info = (struct hifc_root_sq_info_s *)(root_info->sq_info) +
			  q_index;
		if (!sq_info) {
			HIFC_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_REG_ATT,
				   UNF_ERR,
				   "[err]Port(0x%x) root sq(0x%x) info is NULL",
				   hba->port_cfg.port_id, q_index);
			continue;
		}

		start_wait_time = 0;
		time_out = UNF_TRUE;

		/* Wait 1 second to check whether the Root Sq is empty */
		do {
			if (hifc_root_sq_is_empty(sq_info)) {
				time_out = UNF_FALSE;
				break;
			}
			msleep(20);
			start_wait_time++;
		} while (start_wait_time < HIFC_WAIT_ROOT_SQ_EMPTY_TIMEOUT_MS);

		if (time_out) {
			HIFC_HBA_STAT(hba, HIFC_STAT_SQ_WAIT_EMPTY);

			HIFC_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_REG_ATT,
				   UNF_ERR,
				   "[err]Port(0x%x) waiting for root sq(0x%x) empty timeout",
				   hba->port_cfg.port_id, q_index);
		}
	}
}

void hifc_wait_all_queues_empty(struct hifc_hba_s *v_hba)
{
	hifc_wait_root_rq_empty(v_hba);
	hifc_flush_all_scq(v_hba);
}

void hifc_set_root_sq_flush_state(void *v_hba, int in_flush)
{
	unsigned int q_index = 0;
	unsigned long flags = 0;
	struct hifc_root_info_s *root_info = NULL;
	struct hifc_root_sq_info_s *sq_info = NULL;
	struct hifc_hba_s *hba = NULL;

	hba = (struct hifc_hba_s *)v_hba;
	root_info = &hba->root_info;

	/*
	 * for each root sq (so far, just one),
	 * set root sq state with been flushing or flush done
	 */
	for (q_index = 0; q_index < root_info->sq_num; q_index++) {
		sq_info = (struct hifc_root_sq_info_s *)(root_info->sq_info) +
			  q_index;
		if (!sq_info) {
			HIFC_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_REG_ATT,
				   UNF_ERR,
				   "[err]Port(0x%x) root sq(0x%x) info is NULL",
				   hba->port_cfg.port_id, q_index);
			continue;
		}

		spin_lock_irqsave(&sq_info->root_sq_spin_lock, flags);
		sq_info->in_flush = in_flush;
		spin_unlock_irqrestore(&sq_info->root_sq_spin_lock, flags);
	}
}

void hifc_set_rport_flush_state(void *v_hba, int in_flush)
{
	unsigned int index = 0;
	unsigned long flag = 0;
	struct hifc_parent_queue_mgr_s *parent_queue_mgr = NULL;
	struct hifc_hba_s *hba = NULL;

	hba = (struct hifc_hba_s *)v_hba;
	parent_queue_mgr = hba->parent_queue_mgr;
	if (!parent_queue_mgr) {
		HIFC_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_REG_ATT, UNF_ERR,
			   "[err]Port(0x%x) parent queue manager is empty",
			   hba->port_cfg.port_id);
		return;
	}

	/*
	 * for each HBA's R_Port(SQ),
	 * set state with been flushing or flush done
	 */
	for (index = 0; index < UNF_HIFC_MAXRPORT_NUM; index++) {
		spin_lock_irqsave(&parent_queue_mgr->parent_queues[index].parent_sq_info.parent_sq_enqueue_lock, flag);
		if (parent_queue_mgr->parent_queues[index].offload_state !=
		    HIFC_QUEUE_STATE_FREE) {
			parent_queue_mgr->parent_queues[index].parent_sq_info.port_in_flush = in_flush;
		}
		spin_unlock_irqrestore(&parent_queue_mgr->parent_queues[index].parent_sq_info.parent_sq_enqueue_lock, flag);
	}
}

/**
 * hifc_clear_fetched_sq_wqe - Inform the chip to clear the WQE that is being
 *                       processed by the chip.
 * @v_hba : hba handle
 * @Return: 0 - success, negative - failure
 */
unsigned int hifc_clear_fetched_sq_wqe(void *v_hba)
{
	unsigned int ret = UNF_RETURN_ERROR;
	union hifc_cmdqe_u cmdqe;
	struct hifc_hba_s *hba = NULL;

	UNF_CHECK_VALID(0x4909, UNF_TRUE, v_hba, return UNF_RETURN_ERROR);
	hba = (struct hifc_hba_s *)v_hba;

	/*
	 * The ROOT SQ cannot control the WQE in the empty queue of the ROOT SQ.
	 * Therefore, the ROOT SQ does not enqueue the WQE after the hardware
	 * obtains the. Link down after the wait mode is used. Therefore,
	 * the WQE of the hardware driver needs to enter the WQE of the queue
	 * after the Link down of the Link down is reported.
	 */
	hifc_wait_root_sq_empty(v_hba);

	memset(&cmdqe, 0, sizeof(union hifc_cmdqe_u));
	hifc_build_cmdqe_common(&cmdqe, HIFCOE_TASK_T_BUFFER_CLEAR, 0);
	cmdqe.buffer_clear.wd1.rx_id_start = hba->exit_base;
	cmdqe.buffer_clear.wd1.rx_id_end =
				hba->exit_base + hba->exit_count - 1;
	cmdqe.buffer_clear.scqn = hba->default_scqn;

	HIFC_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_EVENT, UNF_MAJOR,
		   "[info]Port(0x%x) start clear all fetched wqe in start(0x%x) - end(0x%x) scqn(0x%x) stage(0x%x)",
		   hba->port_cfg.port_id,
		   cmdqe.buffer_clear.wd1.rx_id_start,
		   cmdqe.buffer_clear.wd1.rx_id_end,
		   cmdqe.buffer_clear.scqn,
		   hba->q_set_stage);

	/* Send BUFFER_CLEAR command via ROOT CMDQ */
	ret = hifc_root_cmdq_enqueue(hba, &cmdqe,
				     sizeof(cmdqe.buffer_clear));

	return ret;
}

/**
 * hifc_clear_pending_sq_wqe -Inform the chip to clear the Pending Sq WQE that
 *                       is being processed by the chip.
 * @v_hba: hba handle
 * @Return: 0 - success, negative - failure
 */
unsigned int hifc_clear_pending_sq_wqe(void *v_hba)
{
	unsigned int ret = UNF_RETURN_ERROR;
	unsigned int rport_index = 0;
	unsigned int entry_cnt = 0;
	unsigned int entry_cnt_max = 0;
	unsigned int next_clr_sq = 0;
	unsigned int cmdqe_len = 0;
	unsigned long flag = 0;
	struct hifc_parent_queue_info_s *parent_qinfo;
	struct hifcoe_cmdqe_flush_sq_info_s *entry = NULL;
	union hifc_cmdqe_u *cmdqe = NULL;
	struct hifc_hba_s *hba = NULL;

	hba = (struct hifc_hba_s *)v_hba;
	cmdqe = (union hifc_cmdqe_u *)kmalloc(HIFC_CMDQE_BUFF_LEN_MAX,
					      GFP_ATOMIC);
	if (!cmdqe) {
		HIFC_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_EVENT, UNF_CRITICAL,
			   "[err]Port(0x%x) malloc flush sq information buffer cmnd failed, stage(0x%x)",
			   hba->port_cfg.port_id, hba->q_set_stage);

		return UNF_RETURN_ERROR;
	}

	memset(cmdqe, 0, HIFC_CMDQE_BUFF_LEN_MAX);
	hifc_build_cmdqe_common(cmdqe, HIFCOE_TASK_T_FLUSH_SQ, 0);
	cmdqe->flush_sq.wd0.wqe_type = HIFCOE_TASK_T_FLUSH_SQ;
	cmdqe->flush_sq.wd0.sq_qid = HIFC_LSW(hba->default_sq_id);
	cmdqe->flush_sq.wd1.scqn = HIFC_LSW(hba->default_scqn);
	cmdqe->flush_sq.wd1.port_id = hba->port_index;

	/*
	 * The CMDQE can contain a maximum of Clear 253 SQ information at a time
	 */
	entry_cnt = 0;
	entry_cnt_max = (HIFC_CMDQE_BUFF_LEN_MAX - sizeof(cmdqe->flush_sq)) /
			sizeof(*entry);
	entry = cmdqe->flush_sq.sq_info_entry;
	next_clr_sq = hba->next_clearing_sq;

	for (rport_index = next_clr_sq; rport_index < UNF_HIFC_MAXRPORT_NUM;
	     rport_index++) {
		parent_qinfo =
			&hba->parent_queue_mgr->parent_queues[rport_index];

		spin_lock_irqsave(&parent_qinfo->parent_queue_state_lock, flag);
		if (HIFC_RPORT_FLUSH_NOT_NEEDED(parent_qinfo)) {
			spin_unlock_irqrestore(
				&parent_qinfo->parent_queue_state_lock, flag);
			next_clr_sq++;
			continue;
		}
		entry->xid = parent_qinfo->parent_sq_info.context_id;
		entry->cid = parent_qinfo->parent_sq_info.cache_id;
		spin_unlock_irqrestore(&parent_qinfo->parent_queue_state_lock,
				       flag);

		HIFC_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_EVENT, UNF_MAJOR,
			   "[info]Port(0x%x) RPort[0x%x] flush pending SQ Entry: xid=0x%x, cid=0x%x",
			   hba->port_cfg.port_id, rport_index,
			   entry->xid, entry->cid);

		entry_cnt++;
		entry++;
		next_clr_sq++;

		if (entry_cnt >= entry_cnt_max)
			break;
	}

	if (entry_cnt == 0) {
		/* If no SQ needs to be flushed, the Clear Done command is
		 * directly sent to the uP
		 */
		HIFC_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_EVENT, UNF_INFO,
			   "[info]Port(0x%x) non SQ need flush wqe, clear done directly, stage (0x%x)",
			   hba->port_cfg.port_id, hba->q_set_stage);

		/* Sends the Clear Done command to the chip */
		ret = hifc_clear_sq_wqe_done(hba);
		goto free_flush_sq_cmdqe;
	}

	hba->next_clearing_sq = next_clr_sq;
	cmdqe->flush_sq.wd0.entry_count = entry_cnt;

	if (rport_index == UNF_HIFC_MAXRPORT_NUM)
		cmdqe->flush_sq.wd1.last_wqe = 1;
	else
		cmdqe->flush_sq.wd1.last_wqe = 0;

	/* Clear pending Queue */
	cmdqe_len = (unsigned int)(sizeof(cmdqe->flush_sq) +
		    entry_cnt * sizeof(*entry));
	ret = hifc_root_cmdq_enqueue(hba, cmdqe, (unsigned short)cmdqe_len);

	HIFC_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_EVENT, UNF_MAJOR,
		   "[info]Port(0x%x) clear total 0x%x SQ in this CMDQE(last=%u), stage (0x%x)",
		   hba->port_cfg.port_id, entry_cnt,
		   cmdqe->flush_sq.wd1.last_wqe, hba->q_set_stage);

free_flush_sq_cmdqe:
	kfree(cmdqe);

	return ret;
}

unsigned int hifc_wait_queue_set_flush_done(struct hifc_hba_s *v_hba)
{
	unsigned int flush_done_time = 0;
	unsigned int ret = RETURN_OK;

	while ((v_hba->q_set_stage != HIFC_QUEUE_SET_STAGE_FLUSHDONE) &&
	       (flush_done_time < HIFC_QUEUE_FLUSH_WAIT_TIMEOUT_MS)) {
		msleep(HIFC_QUEUE_FLUSH_WAIT_MS);
		flush_done_time += HIFC_QUEUE_FLUSH_WAIT_MS;
	}

	if (v_hba->q_set_stage != HIFC_QUEUE_SET_STAGE_FLUSHDONE) {
		HIFC_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_NORMAL, UNF_WARN,
			   "[warn]Port(0x%x) queue sets flush timeout with stage(0x%x)",
			   v_hba->port_cfg.port_id, v_hba->q_set_stage);

		ret = UNF_RETURN_ERROR;
	}

	return ret;
}

static void hifc_disable_all_scq_schedule(struct hifc_hba_s *v_hba)
{
	struct hifc_scq_info_s *scq_info = NULL;
	unsigned int index = 0;

	for (index = 0; index < HIFC_TOTAL_SCQ_NUM; index++) {
		scq_info = &v_hba->scq_info[index];
		tasklet_disable(&scq_info->tasklet);
	}
}

static void hifc_disable_root_rq_schedule(struct hifc_hba_s *v_hba)
{
	unsigned int index = 0;
	struct hifc_root_info_s *root_info = NULL;
	struct hifc_root_rq_info_s *rq_info = NULL;

	root_info = &v_hba->root_info;

	for (index = 0; index < root_info->rq_num; index++) {
		rq_info = (struct hifc_root_rq_info_s *)(root_info->rq_info) +
			  index;
		tasklet_disable(&rq_info->tasklet);
	}
}

void hifc_disable_queues_dispatch(struct hifc_hba_s *v_hba)
{
	hifc_disable_root_rq_schedule(v_hba);
	hifc_disable_all_scq_schedule(v_hba);
}

static void hifc_enable_root_rq_schedule(struct hifc_hba_s *v_hba)
{
	unsigned int index = 0;
	struct hifc_root_info_s *root_info = NULL;
	struct hifc_root_rq_info_s *rq_info = NULL;

	root_info = &v_hba->root_info;

	for (index = 0; index < root_info->rq_num; index++) {
		rq_info = (struct hifc_root_rq_info_s *)(root_info->rq_info) +
			  index;
		tasklet_enable(&rq_info->tasklet);
	}
}

static void hifc_enable_all_scq_schedule(struct hifc_hba_s *v_hba)
{
	struct hifc_scq_info_s *scq_info = NULL;
	unsigned int index = 0;

	for (index = 0; index < HIFC_TOTAL_SCQ_NUM; index++) {
		scq_info = &v_hba->scq_info[index];
		tasklet_enable(&scq_info->tasklet);
	}
}

void hifc_enable_queues_dispatch(void *v_hba)
{
	hifc_enable_root_rq_schedule((struct hifc_hba_s *)v_hba);
	hifc_enable_all_scq_schedule((struct hifc_hba_s *)v_hba);
}

void hifc_clear_els_srq(struct hifc_hba_s *v_hba)
{
	unsigned int index = 0;
	unsigned long flag = 0;
	struct hifc_srq_info_s *srq_info = NULL;

	srq_info = &v_hba->els_srq_info;

	spin_lock_irqsave(&srq_info->srq_spin_lock, flag);
	if ((srq_info->enable == UNF_FALSE) ||
	    (srq_info->state == HIFC_CLEAN_DOING)) {
		spin_unlock_irqrestore(&srq_info->srq_spin_lock, flag);

		return;
	}
	srq_info->enable = UNF_FALSE;
	srq_info->state = HIFC_CLEAN_DOING;
	spin_unlock_irqrestore(&srq_info->srq_spin_lock, flag);

	hifc_send_clear_srq_cmd(v_hba, &v_hba->els_srq_info);

	/* wait for uCode to clear SRQ context, the timer is 30S */
	while ((srq_info->state != HIFC_CLEAN_DONE) && (index < 60)) {
		msleep(500);
		index++;
	}

	if (srq_info->state != HIFC_CLEAN_DONE) {
		HIFC_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_NORMAL, UNF_WARN,
			   "[warn]HIFC Port(0x%x) clear els srq timeout",
			   v_hba->port_cfg.port_id);
	}
}

unsigned int hifc_wait_all_parent_queue_free(struct hifc_hba_s *v_hba)
{
	unsigned int index = 0;
	unsigned int ret = UNF_RETURN_ERROR;

	do {
		ret = hifc_check_all_parent_queue_free(v_hba);
		if (ret == RETURN_OK)
			break;

		index++;
		msleep(20);
	} while (index < 1500);

	if (ret != RETURN_OK) {
		HIFC_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_NORMAL, UNF_ERR,
			   "[warn]Port(0x%x) wait all parent queue state free timeout",
			   v_hba->port_cfg.port_id);
	}

	return ret;
}

void hifc_queue_pre_process(void *v_hba, int v_clean)
{
#define HIFC_WAIT_LINKDOWN_EVENT_MS 500

	/* From port reset & port remove */
	struct hifc_hba_s *hba = (struct hifc_hba_s *)v_hba;

	/* 1. Wait for 2s and wait for QUEUE to be FLUSH Done. */
	if (hifc_wait_queue_set_flush_done(hba) != RETURN_OK) {
		/*
		 * During the process of removing the card, if the port is
		 * disabled and the flush done is not available, the chip is
		 *  powered off or the pcie link is disconnected. In this case,
		 *  you can proceed with the next step.
		 */
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_REG_ATT, UNF_WARN,
			  "[warn]HIFC Port(0x%x) clean queue sets timeout",
			  hba->port_cfg.port_id);
	}

	/*
	 * 2. Port remove:
	 * 2.1 free parent queue
	 * 2.2 clear & destroy ELS/SIRT SRQ
	 */
	if (v_clean == UNF_TRUE) {
		if (hifc_wait_all_parent_queue_free(hba) != RETURN_OK) {
			UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_REG_ATT,
				  UNF_WARN,
				  "[warn]HIFC Port(0x%x) free all parent queue timeout",
				  hba->port_cfg.port_id);
		}

		/* clear & than destroy ELS SRQ */
		hifc_clear_els_srq(hba);
	}

	msleep(HIFC_WAIT_LINKDOWN_EVENT_MS);

	/*
	 * 3. The internal resources of the port chip are flush done. However,
	 *  there may be residual scqe or rq in the queue. The scheduling is
	 * forcibly refreshed once.
	 */
	hifc_wait_all_queues_empty(hba);

	/*
	 * 4. Disable tasklet scheduling for upstream queues on the software
	 * layer
	 */
	hifc_disable_queues_dispatch(hba);
}

unsigned int hifc_push_delay_sqe(
			void *v_hba,
			struct hifc_parent_queue_info_s *v_offload_parent_queue,
			struct hifc_root_sqe_s *v_sqe,
			struct unf_frame_pkg_s *v_pkg)
{
	unsigned long flag = 0;

	spin_lock_irqsave(&v_offload_parent_queue->parent_queue_state_lock,
			  flag);

	if ((v_offload_parent_queue->offload_state !=
	    HIFC_QUEUE_STATE_INITIALIZED) &&
	    (v_offload_parent_queue->offload_state != HIFC_QUEUE_STATE_FREE)) {
		memcpy(&v_offload_parent_queue->parent_sq_info.delay_sqe.sqe,
		       v_sqe, sizeof(struct hifc_root_sqe_s));
		v_offload_parent_queue->parent_sq_info.delay_sqe.start_jiff =
				jiffies;
		v_offload_parent_queue->parent_sq_info.delay_sqe.time_out =
				v_pkg->private[PKG_PRIVATE_XCHG_TIMEER];
		v_offload_parent_queue->parent_sq_info.delay_sqe.valid =
				UNF_TRUE;
		v_offload_parent_queue->parent_sq_info.delay_sqe.rport_index =
				v_pkg->private[PKG_PRIVATE_XCHG_RPORT_INDEX];
		v_offload_parent_queue->parent_sq_info.delay_sqe.sid =
				v_pkg->frame_head.csctl_sid & UNF_NPORTID_MASK;
		v_offload_parent_queue->parent_sq_info.delay_sqe.did =
				v_pkg->frame_head.rctl_did & UNF_NPORTID_MASK;

		spin_unlock_irqrestore(
			&v_offload_parent_queue->parent_queue_state_lock, flag);

		HIFC_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_REG_ATT, UNF_MAJOR,
			   "[info]Port(0x%x) RPort(0x%x) delay send ELS, OXID(0x%x), RXID(0x%x)",
			   ((struct hifc_hba_s *)v_hba)->port_cfg.port_id,
			   v_pkg->private[PKG_PRIVATE_XCHG_RPORT_INDEX],
			   UNF_GET_OXID(v_pkg), UNF_GET_RXID(v_pkg));

		return RETURN_OK;
	}

	spin_unlock_irqrestore(&v_offload_parent_queue->parent_queue_state_lock,
			       flag);

	return UNF_RETURN_ERROR;
}

void hifc_pop_delay_sqe(struct hifc_hba_s *v_hba,
			struct hifc_delay_sqe_ctrl_info_s *v_sqe_info)
{
	unsigned int ret = UNF_RETURN_ERROR;
	unsigned long flag = 0;
	unsigned int delay_rport_index = INVALID_VALUE32;
	struct hifc_parent_queue_info_s *parent_queue = NULL;
	enum hifc_parent_queue_state_e offload_state =
						HIFC_QUEUE_STATE_DESTROYING;
	struct hifc_destroy_ctrl_info_s destroy_sqe_info = { 0 };

	/*
	 * According to the sequence, the rport index id is reported and then
	 * the sqe of the new link setup request is delivered.
	 */
	if (v_sqe_info->valid != UNF_TRUE)
		return;
	if (jiffies_to_msecs(jiffies - v_sqe_info->start_jiff) >=
	    v_sqe_info->time_out) {
		HIFC_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_LOGIN_ATT, UNF_ERR,
			   "[err]Port(0x%x) pop delay root sqe failed, sqe start time 0x%llx, timeout value 0x%x",
			   v_hba->port_cfg.port_id,
			   v_sqe_info->start_jiff,
			   v_sqe_info->time_out);
	}

	delay_rport_index = v_sqe_info->rport_index;
	if (delay_rport_index >= UNF_HIFC_MAXRPORT_NUM) {
		HIFC_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_LOGIN_ATT, UNF_ERR,
			   "[err]Port(0x%x) pop delay root sqe failed, rport index(0x%x) is invalid",
			   v_hba->port_cfg.port_id,
			   delay_rport_index);

		return;
	}

	parent_queue =
		&v_hba->parent_queue_mgr->parent_queues[delay_rport_index];

	/* Before the root sq is delivered, check the status again to
	 * ensure that the initialization status is not uninstalled. Other
	 * states are not processed and are discarded directly.
	 */
	spin_lock_irqsave(&parent_queue->parent_queue_state_lock, flag);
	offload_state = parent_queue->offload_state;

	/* Before re-enqueuing the rootsq, check whether the offload status and
	 * connection information is consistent to prevent the old request from
	 * being sent after the connection status is changed.
	 */
	if ((offload_state == HIFC_QUEUE_STATE_INITIALIZED) &&
	    (parent_queue->parent_sq_info.local_port_id == v_sqe_info->sid) &&
	    (parent_queue->parent_sq_info.remote_port_id == v_sqe_info->did) &&
	    HIFC_CHECK_XID_MATCHED(
		parent_queue->parent_sq_info.context_id,
		v_sqe_info->sqe.task_section.fc_dw4.parent_xid)) {
		parent_queue->offload_state = HIFC_QUEUE_STATE_OFFLOADING;
		spin_unlock_irqrestore(&parent_queue->parent_queue_state_lock,
				       flag);

		HIFC_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT, UNF_MAJOR,
			   "[info]Port(0x%x) pop up delay sqe to root sq, sqe start time 0x%llx, timeout value 0x%x, rport index 0x%x, offload state 0x%x",
			   v_hba->port_cfg.port_id,
			   v_sqe_info->start_jiff,
			   v_sqe_info->time_out,
			   delay_rport_index,
			   offload_state);

		ret = hifc_root_sq_enqueue(v_hba, &v_sqe_info->sqe);
		if (ret != RETURN_OK) {
			spin_lock_irqsave(
				&parent_queue->parent_queue_state_lock, flag);

			if (parent_queue->offload_state ==
			    HIFC_QUEUE_STATE_OFFLOADING)
				parent_queue->offload_state = offload_state;

			if (parent_queue->parent_sq_info.destroy_sqe.valid ==
			    UNF_TRUE) {
				memcpy(
				&destroy_sqe_info,
				&parent_queue->parent_sq_info.destroy_sqe,
				sizeof(struct hifc_destroy_ctrl_info_s));

				parent_queue->parent_sq_info.destroy_sqe.valid =
								UNF_FALSE;
			}

			spin_unlock_irqrestore(
				&parent_queue->parent_queue_state_lock, flag);

			hifc_pop_destroy_parent_queue_sqe((void *)v_hba,
							  &destroy_sqe_info);

			HIFC_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_LOGIN_ATT,
				   UNF_ERR,
				   "[err]Port(0x%x) pop up delay sqe to root sq fail, recover offload state 0x%x",
				   v_hba->port_cfg.port_id,
				   parent_queue->offload_state);
		}
	} else {
		ret = UNF_RETURN_ERROR;
		spin_unlock_irqrestore(&parent_queue->parent_queue_state_lock,
				       flag);
	}

	if (ret != RETURN_OK) {
		HIFC_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_LOGIN_ATT, UNF_ERR,
			   "[err]Port 0x%x pop delay root sqe failed, sqe start time 0x%llx, timeout value 0x%x, rport index 0x%x, offload state 0x%x",
			   v_hba->port_cfg.port_id,
			   v_sqe_info->start_jiff,
			   v_sqe_info->time_out,
			   delay_rport_index,
			   offload_state);
	}
}

void hifc_push_destroy_parent_queue_sqe(
				void *v_hba,
				struct hifc_parent_queue_info_s *v_parent_qinfo,
				struct unf_rport_info_s *v_rport_info)
{
	v_parent_qinfo->parent_sq_info.destroy_sqe.valid = UNF_TRUE;
	v_parent_qinfo->parent_sq_info.destroy_sqe.rport_index =
						v_rport_info->rport_index;
	v_parent_qinfo->parent_sq_info.destroy_sqe.time_out =
						HIFC_SQ_DEL_STAGE_TIMEOUT_MS;
	v_parent_qinfo->parent_sq_info.destroy_sqe.start_jiff = jiffies;

	v_parent_qinfo->parent_sq_info.destroy_sqe.rport_info.nport_id =
						v_rport_info->nport_id;
	v_parent_qinfo->parent_sq_info.destroy_sqe.rport_info.rport_index =
						v_rport_info->rport_index;
	v_parent_qinfo->parent_sq_info.destroy_sqe.rport_info.port_name =
						v_rport_info->port_name;
}

void hifc_pop_destroy_parent_queue_sqe(
			void *v_hba,
			struct hifc_destroy_ctrl_info_s *v_destroy_sqe_info)
{
	struct hifc_hba_s *hba = NULL;
	unsigned int ret = UNF_RETURN_ERROR;
	unsigned long flag = 0;
	unsigned int delay_rport_index = INVALID_VALUE32;
	struct hifc_parent_queue_info_s *parent_queue = NULL;
	enum hifc_parent_queue_state_e offload_state =
						HIFC_QUEUE_STATE_DESTROYING;

	hba = (struct hifc_hba_s *)v_hba;

	if (v_destroy_sqe_info->valid != UNF_TRUE)
		return;

	if (jiffies_to_msecs(jiffies - v_destroy_sqe_info->start_jiff) <
	    v_destroy_sqe_info->time_out) {
		delay_rport_index = v_destroy_sqe_info->rport_index;
		parent_queue =
		&hba->parent_queue_mgr->parent_queues[delay_rport_index];

		/* Before delivery, check the status again to ensure that the
		 * initialization status is not uninstalled. Other states are
		 * not processed and are discarded directly.
		 */
		spin_lock_irqsave(&parent_queue->parent_queue_state_lock, flag);

		offload_state = parent_queue->offload_state;
		if ((offload_state == HIFC_QUEUE_STATE_OFFLOADED) ||
		    (offload_state == HIFC_QUEUE_STATE_INITIALIZED)) {
			spin_unlock_irqrestore(
				&parent_queue->parent_queue_state_lock, flag);

			HIFC_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT,
				   UNF_MAJOR,
				   "[info]Port 0x%x pop up delay destroy parent sq, sqe start time 0x%llx, timeout value 0x%x, rport index 0x%x, offload state 0x%x",
				   hba->port_cfg.port_id,
				   v_destroy_sqe_info->start_jiff,
				   v_destroy_sqe_info->time_out,
				   delay_rport_index,
				   offload_state);
			ret = hifc_free_parent_resource(
				hba,
				&v_destroy_sqe_info->rport_info);
		} else {
			ret = UNF_RETURN_ERROR;
			spin_unlock_irqrestore(
				&parent_queue->parent_queue_state_lock, flag);
		}
	}

	if (ret != RETURN_OK) {
		HIFC_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_LOGIN_ATT, UNF_ERR,
			   "[err]Port 0x%x pop delay destroy parent sq failed, sqe start time 0x%llx, timeout value 0x%x, rport index 0x%x, rport nport id 0x%x,offload state 0x%x",
			   hba->port_cfg.port_id,
			   v_destroy_sqe_info->start_jiff,
			   v_destroy_sqe_info->time_out,
			   delay_rport_index,
			   v_destroy_sqe_info->rport_info.nport_id,
			   offload_state);
	}
}

void hifc_free_parent_queue_info(
			void *v_hba,
			struct hifc_parent_queue_info_s *v_parent_queue_info)
{
	unsigned long flag = 0;
	unsigned int ret = UNF_RETURN_ERROR;
	unsigned int rport_index = INVALID_VALUE32;
	struct hifc_hba_s *hba = NULL;
	struct hifc_delay_sqe_ctrl_info_s sqe_info;

	memset(&sqe_info, 0, sizeof(struct hifc_delay_sqe_ctrl_info_s));
	hba = (struct hifc_hba_s *)v_hba;

	spin_lock_irqsave(&v_parent_queue_info->parent_queue_state_lock, flag);

	HIFC_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT, UNF_INFO,
		   "[info]Port(0x%x) begin to free parent sq, rport_index(0x%x)",
		   hba->port_cfg.port_id,
		   v_parent_queue_info->parent_sq_info.rport_index);

	if (v_parent_queue_info->offload_state == HIFC_QUEUE_STATE_FREE) {
		HIFC_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_LOGIN_ATT, UNF_ERR,
			   "[info]Port(0x%x) duplicate free parent sq, rport_index(0x%x)",
			   hba->port_cfg.port_id,
			   v_parent_queue_info->parent_sq_info.rport_index);

		spin_unlock_irqrestore(
				&v_parent_queue_info->parent_queue_state_lock,
				flag);
		return;
	}

	if (v_parent_queue_info->parent_sq_info.delay_sqe.valid == UNF_TRUE) {
		memcpy(&sqe_info,
		       &v_parent_queue_info->parent_sq_info.delay_sqe,
		       sizeof(struct hifc_delay_sqe_ctrl_info_s));
	}

	rport_index = v_parent_queue_info->parent_sq_info.rport_index;

	/* The Parent Contexe and SQ information is released. After
	 * initialization, the Parent Contexe and SQ information is associated
	 * with the sq in the queue of the parent
	 */
	hifc_free_parent_sq(hba, v_parent_queue_info);

	/* The initialization of all queue id is invalid */
	v_parent_queue_info->parent_cmd_scq_info.cqm_queue_id = INVALID_VALUE32;
	v_parent_queue_info->parent_sts_scq_info.cqm_queue_id = INVALID_VALUE32;
	v_parent_queue_info->parent_els_srq_info.cqm_queue_id = INVALID_VALUE32;
	v_parent_queue_info->offload_state = HIFC_QUEUE_STATE_FREE;

	spin_unlock_irqrestore(&v_parent_queue_info->parent_queue_state_lock,
			       flag);

	UNF_LOWLEVEL_PORT_EVENT(ret, hba->lport, UNF_PORT_RELEASE_RPORT_INDEX,
				(void *)&rport_index);
	hifc_pop_delay_sqe(hba, &sqe_info);

	if (ret != RETURN_OK) {
		HIFC_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_LOGIN_ATT, UNF_ERR,
			   "[warn]Port(0x%x) free parent sq with rport_index(0x%x) failed",
			   hba->port_cfg.port_id, rport_index);
	}
}

void hifc_build_session_rst_wqe(void *v_hba,
				struct hifc_parent_sq_info_s *v_sq,
				struct hifcoe_sqe_s *v_sqe,
				enum hifc_session_reset_mode_e v_mode,
				unsigned int scqn)
{
	struct hifc_hba_s *hba = NULL;

	hba = (struct hifc_hba_s *)v_hba;

	/*
	 * The reset session command does not occupy xid. Therefore,
	 * 0xffff can be used to align with the microcode.
	 */
	v_sqe->ts_sl.task_type = HIFC_SQE_SESS_RST;
	v_sqe->ts_sl.local_xid = 0xffff;
	v_sqe->ts_sl.wd0.conn_id = (unsigned short)(v_sq->rport_index);
	v_sqe->ts_sl.wd0.remote_xid = 0xffff;

	v_sqe->ts_sl.cont.reset_session.wd0.reset_exch_start = hba->exit_base;
	v_sqe->ts_sl.cont.reset_session.wd0.reset_exch_end = hba->exit_base +
						(hba->exit_count - 1);
	v_sqe->ts_sl.cont.reset_session.wd1.reset_did = v_sq->remote_port_id;
	v_sqe->ts_sl.cont.reset_session.wd1.mode = v_mode;
	v_sqe->ts_sl.cont.reset_session.wd2.reset_sid = v_sq->local_port_id;
	v_sqe->ts_sl.cont.reset_session.wd3.scqn = scqn;

	hifc_build_common_wqe_ctrls(&v_sqe->ctrl_sl,
				    sizeof(struct hifcoe_sqe_ts_s) /
				    HIFC_WQE_SECTION_CHUNK_SIZE);
}

unsigned int hifc_send_session_rst_cmd(
			void *v_hba,
			struct hifc_parent_queue_info_s *v_parent_queue_info,
			enum hifc_session_reset_mode_e v_mode)
{
	struct hifc_parent_sq_info_s *sq = NULL;
	struct hifcoe_sqe_s rst_sess_sqe;
	unsigned int ret = UNF_RETURN_ERROR;
	unsigned int sts_scqn = 0;

	memset(&rst_sess_sqe, 0, sizeof(struct hifcoe_sqe_s));
	sq = &v_parent_queue_info->parent_sq_info;
	sts_scqn = ((struct hifc_hba_s *)v_hba)->default_scqn;
	hifc_build_session_rst_wqe(v_hba, sq, &rst_sess_sqe, v_mode, sts_scqn);

	/* Run the sq command to issue the reset session command to the
	 * microcode, that is, the last command.
	 */
	ret = hifc_parent_sq_enqueue(sq, &rst_sess_sqe);

	return ret;
}

void hifc_rcvd_els_from_srq_time_out(struct work_struct *work)
{
	struct hifc_hba_s *hba = NULL;

	hba = container_of(work, struct hifc_hba_s, delay_info.del_work.work);

	/*
	 * If the frame is not processed, the frame is pushed to the CM layer:
	 * The frame may have been processed when the root rq receives data.
	 */
	if (hba->delay_info.srq_delay_flag) {
		hifc_rcv_els_cmnd(
			hba, &hba->delay_info.pkg,
			hba->delay_info.pkg.unf_cmnd_pload_bl.buffer_ptr,
			0, UNF_FALSE);
		hba->delay_info.srq_delay_flag = 0;

		HIFC_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_REG_ATT, UNF_MAJOR,
			   "[info]Port(0x%x) srq delay work timeout, send saved plgoi to CM",
			   hba->port_cfg.port_id);
	}
}

unsigned int hifc_rport_session_rst(void *v_hba,
				    struct unf_rport_info_s *v_rport_info)
{
	/* NOT USE NOW */
	struct hifc_hba_s *hba = NULL;
	struct hifc_parent_queue_info_s *v_parent_queue_info = NULL;
	unsigned long flag = 0;
	unsigned int ret = UNF_RETURN_ERROR;

	HIFC_CHECK(INVALID_VALUE32, v_hba, return UNF_RETURN_ERROR);
	HIFC_CHECK(INVALID_VALUE32, v_rport_info, return UNF_RETURN_ERROR);

	hba = (struct hifc_hba_s *)v_hba;
	if (!hba->parent_queue_mgr) {
		HIFC_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_LOGIN_ATT, UNF_ERR,
			   "[err]Port 0x%x cannot find parent queue pool",
			   hba->port_cfg.port_id);

		return UNF_RETURN_ERROR;
	}

	if (v_rport_info->rport_index >= UNF_HIFC_MAXRPORT_NUM) {
		HIFC_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_LOGIN_ATT, UNF_ERR,
			   "[err]Port 0x%x free parent resource failed, invlaid rport index %u,Rport NPortId 0x%x",
			   hba->port_cfg.port_id,
			   v_rport_info->rport_index,
			   v_rport_info->nport_id);

		return UNF_RETURN_ERROR;
	}

	v_parent_queue_info =
	&hba->parent_queue_mgr->parent_queues[v_rport_info->rport_index];

	spin_lock_irqsave(&v_parent_queue_info->parent_queue_state_lock, flag);

	if (v_parent_queue_info->offload_state == HIFC_QUEUE_STATE_OFFLOADED) {
		HIFC_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT, UNF_MAJOR,
			   "[info]Port 0x%x parent sq reset session, rport index 0x%x:0x%x,local nportid 0x%x,remote nportid 0x%x:0x%x,ctx id 0x%x, cid 0x%x",
			   hba->port_cfg.port_id,
			   v_rport_info->rport_index,
			   v_parent_queue_info->parent_sq_info.rport_index,
			   v_parent_queue_info->parent_sq_info.local_port_id,
			   v_rport_info->nport_id,
			   v_parent_queue_info->parent_sq_info.remote_port_id,
			   v_parent_queue_info->parent_sq_info.context_id,
			   v_parent_queue_info->parent_sq_info.cache_id);

		/* this scenario does not exist */
		(void)queue_delayed_work(
				hba->work_queue,
				&v_parent_queue_info->parent_sq_info.del_work,
				(unsigned long)
				msecs_to_jiffies((unsigned int)
				HIFC_SQ_DEL_STAGE_TIMEOUT_MS));

		spin_unlock_irqrestore(
			&v_parent_queue_info->parent_queue_state_lock, flag);

		/*
		 * The current session reset is in clear I/O mode, and the
		 * connection resources are not deleted
		 */
		ret = hifc_send_session_rst_cmd(hba,
						v_parent_queue_info,
						HIFC_SESS_RST_DELETE_IO_ONLY);
	} else {
		HIFC_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT, UNF_MAJOR,
			   "[info]Port 0x%x parent sq is not offloaded, no need reset session , rport index 0x%x:0x%x,local nportid 0x%x,remote nportid 0x%x:0x%x",
			   hba->port_cfg.port_id,
			   v_rport_info->rport_index,
			   v_parent_queue_info->parent_sq_info.rport_index,
			   v_parent_queue_info->parent_sq_info.local_port_id,
			   v_rport_info->nport_id,
			   v_parent_queue_info->parent_sq_info.remote_port_id);

		spin_unlock_irqrestore(
			&v_parent_queue_info->parent_queue_state_lock, flag);

		ret = RETURN_OK;
	}

	return ret;
}

/**
 * hifc_flush_ini_resp_queue - Pay attention to the processing that is being
 *                       processed, but do not pay attention to the subsequent
 *                       processing. This is the main difference between the
 *                        HIFC_FlushScq and the HIFC_FlushScq.
 * @v_hba: hba handle
 * @Return: 0 - success, negative - failure
 */
unsigned int hifc_flush_ini_resp_queue(void *v_hba)
{
	struct hifc_hba_s *hba = NULL;

	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE, v_hba,
			return UNF_RETURN_ERROR);
	hba = (struct hifc_hba_s *)v_hba;

	/*
	 * Although this function is called, the original HIFC_FlushScq is based
	 * on the scenario where the port is disabled. That is, the function is
	 * executed and the SCQ is empty. However, because the port is not
	 * disabled in the current scenario, it can only indicate that a batch
	 * of processing is completed.
	 */
	hifc_flush_sts_scq(hba);

	return RETURN_OK;
}

/*
 * Function Name       : hifc_handle_aeq_queue_error
 * Function Description: Process the queue error event sent by the chip
 *                       through AEQ.
 * Input Parameters    : *v_hba,
 *                     : *v_aeq_msg
 * Output Parameters   : N/A
 * Return Type         : void
 */
static void hifc_handle_aeq_queue_error(struct hifc_hba_s *v_hba,
					struct hifcoe_aqe_data_s *v_aeq_msg)
{
	unsigned int sts_scqn_local = 0;
	unsigned int full_ci = INVALID_VALUE32;
	unsigned int full_ci_owner = INVALID_VALUE32;
	struct hifc_scq_info_s *scq_info = NULL;
	struct hifcoe_aqe_data_s *aeq_msg = NULL;

	aeq_msg = v_aeq_msg;

	sts_scqn_local = HIFC_RPORTID_TO_STS_SCQN(aeq_msg->wd0.conn_id);
	scq_info = &v_hba->scq_info[sts_scqn_local];
	full_ci = scq_info->ci;
	full_ci_owner = scq_info->ci_owner;

	/*
	 * Currently, Flush is forcibly set to StsScq. No matter whether scq is
	 * processed, AEQE is returned
	 */
	tasklet_schedule(&scq_info->tasklet);

	HIFC_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_REG_ATT, UNF_MAJOR,
		   "[info]Port(0x%x) RPort(0x%x) LocalScqn(0x%x) CqmScqn(0x%x) is full, force flush CI from (%d|0x%x) to (%d|0x%x)",
		   v_hba->port_cfg.port_id, aeq_msg->wd0.conn_id,
		   sts_scqn_local, scq_info->scqn,
		   full_ci_owner, full_ci, scq_info->ci_owner, scq_info->ci);
}

void hifc_process_aeqe(void *v_srv_handle,
		       unsigned char event_type,
		       u64 event_val)
{
	unsigned int ret = RETURN_OK;
	struct hifc_hba_s *hba = (struct hifc_hba_s *)v_srv_handle;
	struct hifcoe_aqe_data_s aeq_msg;
	unsigned long long aeq_info = 0;
	unsigned char event_code = INVALID_VALUE8;

	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE, hba, return);

	aeq_info = cpu_to_be64(event_val);
	memcpy(&aeq_msg, (struct hifcoe_aqe_data_s *)&aeq_info,
	       sizeof(struct hifcoe_aqe_data_s));
	hifc_big_to_cpu32(&aeq_msg, sizeof(struct hifcoe_aqe_data_s));
	event_code = (unsigned char)aeq_msg.wd0.evt_code;

	switch (event_type) {
	case FC_AEQ_EVENT_QUEUE_ERROR:
		hifc_handle_aeq_queue_error(hba, &aeq_msg);
		break;

	case FC_AEQ_EVENT_WQE_FATAL_ERROR:
		UNF_LOWLEVEL_PORT_EVENT(ret,
					hba->lport,
					UNF_PORT_ABNORMAL_RESET,
					NULL);
		break;

	case FC_AEQ_EVENT_CTX_FATAL_ERROR:
		break;

	case FC_AEQ_EVENT_OFFLOAD_ERROR:
		ret = hifc_handle_aeq_offload_err(hba, &aeq_msg);
		break;

	default:
		HIFC_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_REG_ATT, UNF_ERR,
			   "[warn]Port(0x%x) receive a unsupported AEQ EventType(0x%x) EventVal(0x%llx).",
			   hba->port_cfg.port_id, event_type,
			   (unsigned long long)event_val);
		return;
	}

	if (event_code < FC_AEQ_EVT_ERR_CODE_BUTT)
		HIFC_AEQ_ERR_TYPE_STAT(hba, aeq_msg.wd0.evt_code);

	HIFC_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_REG_ATT, UNF_KEVENT,
		   "[info]Port(0x%x) receive AEQ EventType(0x%x) EventVal(0x%llx) EvtCode(0x%x) Conn_id(0x%x) Xid(0x%x) %s",
		   hba->port_cfg.port_id, event_type,
		   (unsigned long long)event_val, event_code,
		   aeq_msg.wd0.conn_id, aeq_msg.wd1.xid,
		   (ret == UNF_RETURN_ERROR) ? "ERROR" : "OK");
}
