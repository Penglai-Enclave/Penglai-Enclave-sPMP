// SPDX-License-Identifier: GPL-2.0
/* Huawei Hifc PCI Express Linux driver
 * Copyright(c) 2017 Huawei Technologies Co., Ltd
 *
 */

#include "hifc_module.h"

struct unf_cm_handle_op_s hifc_cm_handle;
unsigned int dif_sgl_mode;
unsigned int max_speed = HIFC_SPEED_32G;
unsigned int accum_db_num = 1;
unsigned int dif_type = 0x1;
unsigned int wqe_page_size = 4096;
unsigned int wqe_pre_load = 6;
unsigned int combo_length_kb = 8;
unsigned int cos_bit_map = 0x1f;
unsigned int hifc_dif_type;
unsigned int hifc_dif_enable;
unsigned char hifc_guard;

/* dfx counter */
atomic64_t rx_tx_stat[HIFC_MAX_PORT_NUM][HIFC_TASK_TYPE_STAT_NUM];
atomic64_t rx_tx_err[HIFC_MAX_PORT_NUM][HIFC_TASK_TYPE_STAT_NUM];
atomic64_t scq_err_stat[HIFC_MAX_PORT_NUM][HIFC_TASK_TYPE_STAT_NUM];
atomic64_t aeq_err_stat[HIFC_MAX_PORT_NUM][HIFC_TASK_TYPE_STAT_NUM];
atomic64_t dif_err_stat[HIFC_MAX_PORT_NUM][HIFC_TASK_TYPE_STAT_NUM];
atomic64_t mail_box_stat[HIFC_MAX_PORT_NUM][HIFC_TASK_TYPE_STAT_NUM];
atomic64_t up_err_event_stat[HIFC_MAX_PORT_NUM][HIFC_TASK_TYPE_STAT_NUM];
unsigned long long link_event_stat[HIFC_MAX_PORT_NUM][HIFC_MAX_LINK_EVENT_CNT];
unsigned long long link_reason_stat[HIFC_MAX_PORT_NUM][HIFC_MAX_LINK_REASON_CNT];
unsigned long long hba_stat[HIFC_MAX_PORT_NUM][HIFC_HBA_STAT_BUTT];
atomic64_t com_up_event_err_stat[HIFC_MAX_PORT_NUM][HIFC_TASK_TYPE_STAT_NUM];

static void hifc_realease_cmo_op_handle(void)
{
	memset(&hifc_cm_handle, 0, sizeof(struct unf_cm_handle_op_s));
}

static void hifc_check_module_para(void)
{
	if (dif_sgl_mode != 0)
		dif_sgl_mode = 1;
}

int hifc_init_module(void)
{
	int ret = RETURN_OK;

	ret = unf_common_init();
	if (ret != RETURN_OK) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_REG_ATT, UNF_ERR,
			  "[err]unf_common_init failed");

		return RETURN_ERROR_S32;
	}

	memset(rx_tx_stat, 0, sizeof(rx_tx_stat));
	memset(rx_tx_err, 0, sizeof(rx_tx_err));
	memset(scq_err_stat, 0, sizeof(scq_err_stat));
	memset(aeq_err_stat, 0, sizeof(aeq_err_stat));
	memset(dif_err_stat, 0, sizeof(dif_err_stat));
	memset(link_event_stat, 0, sizeof(link_event_stat));
	memset(link_reason_stat, 0, sizeof(link_reason_stat));
	memset(hba_stat, 0, sizeof(hba_stat));
	memset(&hifc_cm_handle, 0, sizeof(struct unf_cm_handle_op_s));
	memset(up_err_event_stat, 0, sizeof(up_err_event_stat));
	memset(mail_box_stat, 0, sizeof(mail_box_stat));
	memset(hifc_hba, 0, sizeof(hifc_hba));

	spin_lock_init(&probe_spin_lock);

	/* 2. Module parameters check */
	hifc_check_module_para();

	/* 4. Get COM Handlers used for low_level */
	if (unf_get_cm_handle_op(&hifc_cm_handle) != RETURN_OK) {
		hifc_realease_cmo_op_handle();
		return RETURN_ERROR_S32;
	}

	HIFC_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_REG_ATT, UNF_KEVENT,
		   "[event]Init HIFC module succeed");

	return ret;
}

void hifc_exit_module(void)
{
	HIFC_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_REG_ATT, UNF_MAJOR,
		   "[event]HIFC module removing...");

	hifc_realease_cmo_op_handle();

	/* 2. Unregister FC COM module(level) */
	unf_common_exit();
}

module_param(dif_sgl_mode, uint, 0444);
module_param(max_speed, uint, 0444);
module_param(wqe_page_size, uint, 0444);
module_param(combo_length_kb, uint, 0444);
module_param(cos_bit_map, uint, 0444);
