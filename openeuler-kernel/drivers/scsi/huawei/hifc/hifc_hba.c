// SPDX-License-Identifier: GPL-2.0
/* Huawei Hifc PCI Express Linux driver
 * Copyright(c) 2017 Huawei Technologies Co., Ltd
 *
 */
#include "hifc_module.h"
#include "hifc_chipitf.h"
#include "hifc_io.h"
#include "hifc_portmng.h"
#include "hifc_lld.h"
#include "hifc_cqm_object.h"
#include "hifc_cqm_main.h"
#include "hifc_mgmt.h"
#include "hifc_hba.h"

struct hifc_hba_s *hifc_hba[HIFC_HBA_PORT_MAX_NUM];
unsigned long probe_bit_map[HIFC_MAX_PROBE_PORT_NUM / HIFC_PORT_NUM_PER_TABLE];
static unsigned long card_num_bit_map[HIFC_MAX_PROBE_PORT_NUM /
						HIFC_PORT_NUM_PER_TABLE];
static struct hifc_card_num_manage_s card_num_manage[HIFC_MAX_CARD_NUM];
/* probe global lock */
spinlock_t probe_spin_lock;
unsigned int max_parent_qpc_num;

static unsigned int hifc_port_config_set(void *v_hba,
					 enum unf_port_config_set_op_e op_code,
					 void *v_var_in);
static unsigned int hifc_port_config_get(void *v_hba,
					 enum unf_port_config_get_op_e op_code,
					 void *param_out);
static unsigned int hifc_sfp_switch(void *v_hba, void *v_para_in);
static unsigned int hifc_get_hba_pcie_link_state(void *v_hba,
						 void *v_link_state);

struct service_register_template_s service_cqm_temp = {
	.scq_ctx_size = HIFC_SCQ_CNTX_SIZE,
	/* srq, scq context_size configuration */
	.srq_ctx_size = HIFC_SRQ_CNTX_SIZE,
	/* the API of asynchronous event from TILE to driver */
	.aeq_callback = hifc_process_aeqe,
};

/* default configuration: auto speed, auto topology, INI+TGT */
static struct unf_cfg_item_s hifc_port_cfg_parm[] = {
	{ "port_id",         0, 0x110000,   0xffffff},
	/* port mode:INI(0x20), TGT(0x10), BOTH(0x30) */
	{ "port_mode",       0, 0x20,       0xff},
	/* port topology, 0x3: loop, 0xc:p2p, 0xf:auto ,0x10:vn2vn */
	{ "port_topology",   0, 0xf,        0x20},
	/* alpa address of port */
	{ "port_alpa",       0, 0xdead,     0xffff},
	/* queue depth of originator registered to SCSI midlayer */
	{ "max_queue_depth", 0, 512,        512},
	{ "sest_num",        0, 4096,       4096},
	{ "max_login",       0, 2048,       2048},
	/* nodename from 32 bit to 64 bit */
	{ "node_name_high",  0, 0x1000286e, 0xffffffff},
	/* nodename from 0 bit to 31 bit */
	{ "node_name_low",   0, 0xd4bbf12f, 0xffffffff},
	/* portname from 32 bit to 64 bit */
	{ "port_name_high",  0, 0x2000286e, 0xffffffff},
	/* portname from 0 bit to 31 bit */
	{ "port_name_low",   0, 0xd4bbf12f, 0xffffffff},
	/* port speed 0:auto 1:1Gbps 2:2Gbps 3:4Gbps 4:8Gbps 5:16Gbps */
	{ "port_speed",      0, 0,          32},
	/* unit: us */
	{ "interrupt_delay", 0, 0,          100},
	{ "tape_support",    0, 0,          1},  /* tape support */
	{ "End",             0, 0,          0}
};

struct unf_low_level_function_op_s hifc_fun_op = {
	.low_level_type = UNF_HIFC_FC,
	.name = "HIFC",
	/* XID allocated from CM level */
	.xchg_mgr_type = UNF_LOW_LEVEL_MGR_TYPE_PASSTIVE,
	.abts_xchg = UNF_NO_EXTRA_ABTS_XCHG,
	.pass_through_flag = UNF_LOW_LEVEL_PASS_THROUGH_PORT_LOGIN,
	.support_max_npiv_num = UNF_HIFC_MAXNPIV_NUM,
	.chip_id = 0,
	.support_max_speed = UNF_PORT_SPEED_32_G,
	.support_max_rport = UNF_HIFC_MAXRPORT_NUM,
	.sfp_type = UNF_PORT_TYPE_FC_SFP,
	.rport_release_type = UNF_LOW_LEVEL_RELEASE_RPORT_ASYNC,
	.sirt_page_mode = UNF_LOW_LEVEL_SIRT_PAGE_MODE_XCHG,

	/* Link service */
	.service_op = {
		.pfn_unf_els_send = hifc_send_els_cmnd,
		.pfn_unf_bls_send = hifc_send_bls_cmnd,
		.pfn_unf_gs_send = hifc_send_gs_cmnd,
		.pfn_unf_cmnd_send = hifc_send_scsi_cmnd,
		.pfn_unf_release_rport_res = hifc_free_parent_resource,
		.pfn_unf_flush_ini_resp_que = hifc_flush_ini_resp_queue,
		.pfn_unf_alloc_rport_res = hifc_alloc_parent_resource,
		.pfn_unf_rport_session_rst = hifc_rport_session_rst,
	},

	/* Port Mgr */
	.port_mgr_op = {
		.pfn_ll_port_config_set = hifc_port_config_set,
		.pfn_ll_port_config_get = hifc_port_config_get,
		.pfn_ll_port_diagnose = hifc_port_diagnose,
	}
};

struct hifc_port_config_op_s {
	enum unf_port_config_set_op_e op_code;
	unsigned int (*pfn_hifc_operation)(void *v_hba, void *v_para_in);
};

struct hifc_port_config_op_s hifc_config_set_op[] = {
	{ UNF_PORT_CFG_SET_SPEED,               hifc_set_port_speed },
	{ UNF_PORT_CFG_SET_TOPO,                hifc_set_port_topo },
	{ UNF_PORT_CFG_SET_BBSCN,               hifc_set_port_bbscn },
	{ UNF_PORT_CFG_SET_SFP_SWITCH,          hifc_sfp_switch },
	{ UNF_PORT_CFG_SET_PORT_SWITCH,         hifc_sfp_switch },
	{ UNF_PORT_CFG_SET_PORT_STATE,          hifc_set_port_state },
	{ UNF_PORT_CFG_UPDATE_WWN,              NULL },
	{ UNF_PORT_CFG_SET_FCP_CONF,            hifc_set_port_fcp_conf },
	{ UNF_PORT_CFG_SET_LOOP_ROLE,           hifc_set_loop_role },
	{ UNF_PORT_CFG_SET_MAX_SUPPORT_SPEED,   hifc_set_max_support_speed },
	{ UNF_PORT_CFG_UPDATE_FABRIC_PARAM,     hifc_update_fabric_param },
	{ UNF_PORT_CFG_UPDATE_PLOGI_PARAM,      hifc_update_port_param },
	{ UNF_PORT_CFG_UPDATE_FDISC_PARAM,      NULL },
	{ UNF_PORT_CFG_SAVE_HBA_INFO,           hifc_save_hba_info },
	{ UNF_PORT_CFG_SET_HBA_BASE_INFO,       hifc_set_hba_base_info },
	{ UNF_PORT_CFG_SET_FLASH_DATA_INFO,     hifc_set_flash_data },
	{ UNF_PORT_CFG_SET_BUTT,                NULL }
};

struct hifc_port_cfg_get_op_s {
	enum unf_port_config_get_op_e op_code;
	unsigned int (*pfn_hifc_operation)(void *v_hba, void *param_out);
};

struct hifc_port_cfg_get_op_s hifc_config_get_op[] = {
	{ UNF_PORT_CFG_GET_SPEED_CFG,       hifc_get_speed_cfg },
	{ UNF_PORT_CFG_GET_SPEED_ACT,       hifc_get_speed_act },
	{ UNF_PORT_CFG_GET_TOPO_CFG,        hifc_get_topo_cfg },
	{ UNF_PORT_CFG_GET_TOPO_ACT,        hifc_get_topo_act },
	{ UNF_PORT_CFG_GET_LOOP_MAP,        hifc_get_loop_map },
	{ UNF_PORT_CFG_GET_SFP_PRESENT,     NULL },
	{ UNF_PORT_CFG_GET_SFP_INFO,        hifc_get_sfp_info },
	{ UNF_PORT_CFG_GET_FW_VER,          hifc_get_firmware_version },
	{ UNF_PORT_CFG_GET_HW_VER,          hifc_get_hardware_version },
	{ UNF_PORT_CFG_GET_WORKBALE_BBCREDIT, hifc_get_work_bale_bbcredit },
	{ UNF_PORT_CFG_GET_WORKBALE_BBSCN,  hifc_get_work_bale_bbscn },
	{ UNF_PORT_CFG_GET_LOOP_ALPA,       hifc_get_loop_alpa },
	{ UNF_PORT_CFG_GET_MAC_ADDR,        hifc_get_chip_msg },
	{ UNF_PORT_CFG_CLR_LESB,            hifc_clear_port_error_code },
	{ UNF_PORT_CFG_GET_LESB_THEN_CLR,   hifc_get_and_clear_port_error_code},
	{ UNF_PORT_CFG_GET_PORT_INFO,       hifc_get_port_current_info },
	{ UNF_PORT_CFG_GET_LED_STATE,       hifc_get_lport_led },
	{ UNF_PORT_CFG_GET_FEC,             hifc_get_port_fec },
	{ UNF_PORT_CFG_GET_PCIE_LINK_STATE, hifc_get_hba_pcie_link_state },
	{ UNF_PORT_CFG_GET_FLASH_DATA_INFO, hifc_get_flash_data },
	{ UNF_PORT_CFG_GET_BUTT,            NULL }
};

static unsigned int hifc_port_config_set(void *v_phba,
					 enum unf_port_config_set_op_e op_code,
					 void *v_var_in)
{
	unsigned int op_idx = 0;

	HIFC_CHECK(INVALID_VALUE32, v_phba, return UNF_RETURN_ERROR);

	for (op_idx = 0;
	op_idx < sizeof(hifc_config_set_op) /
	sizeof(struct hifc_port_config_op_s);
	op_idx++) {
		if (op_code == hifc_config_set_op[op_idx].op_code) {
			if (!hifc_config_set_op[op_idx].pfn_hifc_operation) {
				HIFC_TRACE(UNF_EVTLOG_DRIVER_WARN,
					   UNF_LOG_REG_ATT, UNF_WARN,
					   "[warn]Null operation for configuration, opcode(0x%x), operation ID(0x%x)",
					   op_code, op_idx);
				return UNF_RETURN_ERROR;
			} else {
				return hifc_config_set_op[op_idx].pfn_hifc_operation(v_phba, v_var_in);
			}
		}
	}

	HIFC_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_REG_ATT, UNF_WARN,
		   "[warn]No operation code for configuration, opcode(0x%x)",
		   op_code);

	return UNF_RETURN_ERROR;
}

static unsigned int hifc_port_config_get(void *v_phba,
					 enum unf_port_config_get_op_e op_code,
					 void *v_para_out)
{
	unsigned int op_idx = 0;

	HIFC_CHECK(INVALID_VALUE32, v_phba, return UNF_RETURN_ERROR);

	for (op_idx = 0;
	     op_idx < sizeof(hifc_config_get_op) /
	     sizeof(struct hifc_port_cfg_get_op_s);
	     op_idx++) {
		if (op_code == hifc_config_get_op[op_idx].op_code) {
			if (!hifc_config_get_op[op_idx].pfn_hifc_operation) {
				HIFC_TRACE(UNF_EVTLOG_DRIVER_WARN,
					   UNF_LOG_REG_ATT, UNF_WARN,
					   "[warn]Null operation to get configuration, opcode(0x%x), operation ID(0x%x)",
					   op_code, op_idx);
				return UNF_RETURN_ERROR;
			} else {
				return hifc_config_get_op[op_idx].pfn_hifc_operation(v_phba, v_para_out);
			}
		}
	}

	HIFC_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_REG_ATT, UNF_WARN,
		   "[warn]No operation to get configuration, opcode(0x%x)",
		   op_code);

	return UNF_RETURN_ERROR;
}

static unsigned int hifc_check_port_cfg(
				const struct hifc_port_cfg_s *v_port_cfg)
{
	int topo_condition, speed_condition;
	/* About Work Topology */
	topo_condition = ((v_port_cfg->port_topology != UNF_TOP_LOOP_MASK) &&
			  (v_port_cfg->port_topology != UNF_TOP_P2P_MASK) &&
			  (v_port_cfg->port_topology != UNF_TOP_AUTO_MASK));
	if (topo_condition) {
		HIFC_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_REG_ATT, UNF_ERR,
			   "[err]Configured port topology(0x%x) is incorrect",
			   v_port_cfg->port_topology);
		return UNF_RETURN_ERROR;
	}

	/* About Work Mode */
	if (v_port_cfg->port_mode != UNF_PORT_MODE_INI) {
		HIFC_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_REG_ATT, UNF_ERR,
			   "[err]Configured port mode(0x%x) is incorrect",
			   v_port_cfg->port_mode);

		return UNF_RETURN_ERROR;
	}

	/* About Work Speed */
	speed_condition = ((v_port_cfg->port_speed != UNF_PORT_SPEED_AUTO) &&
			   (v_port_cfg->port_speed != UNF_PORT_SPEED_2_G) &&
			   (v_port_cfg->port_speed != UNF_PORT_SPEED_4_G) &&
			   (v_port_cfg->port_speed != UNF_PORT_SPEED_8_G) &&
			   (v_port_cfg->port_speed != UNF_PORT_SPEED_16_G) &&
			   (v_port_cfg->port_speed != UNF_PORT_SPEED_32_G));
	if (speed_condition) {
		HIFC_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_REG_ATT, UNF_ERR,
			   "[err]Configured port speed(0x%x) is incorrect",
			   v_port_cfg->port_speed);
		return UNF_RETURN_ERROR;
	}

	HIFC_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_REG_ATT, UNF_INFO,
		   "[info]Check port configuration OK");

	return RETURN_OK;
}

static unsigned int hifc_get_port_cfg(struct hifc_hba_s *v_hba,
				      struct hifc_chip_info_s *v_chip_info,
				      unsigned char v_card_num)
{
#define UNF_CONFIG_ITEM_LEN 15

	/*
	 * Maximum length of a configuration item name, including the end
	 * character
	 */
#define UNF_MAX_ITEM_NAME_LEN (32 + 1)

	/* Get and check parameters */
	char cfg_item[UNF_MAX_ITEM_NAME_LEN];
	unsigned int ret = UNF_RETURN_ERROR;
	struct hifc_hba_s *hba = v_hba;
	int iret = RETURN_ERROR_S32;

	HIFC_CHECK(INVALID_VALUE32, hba, return UNF_RETURN_ERROR);
	memset((void *)cfg_item, 0, sizeof(cfg_item));

	hba->card_info.func_num =
		(hifc_global_func_id(v_hba->hw_dev_handle)) & UNF_FUN_ID_MASK;
	hba->card_info.card_num = v_card_num;

	/* The range of PF of FC server is from PF1 to PF2 */
	iret = snprintf(cfg_item, UNF_CONFIG_ITEM_LEN, "hifc_cfg_%1u",
			(hba->card_info.func_num));
	UNF_FUNCTION_RETURN_CHECK(iret, UNF_CONFIG_ITEM_LEN);
	cfg_item[UNF_MAX_ITEM_NAME_LEN - 1] = 0;

	HIFC_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_REG_ATT, UNF_INFO,
		   "[info]Get port configuration: %s", cfg_item);

	/* Get configuration parameters from file */
	UNF_LOWLEVEL_GET_CFG_PARMS(ret, cfg_item, &hifc_port_cfg_parm[0],
				   (unsigned int *)(void *)&hba->port_cfg,
				   sizeof(hifc_port_cfg_parm) /
				   sizeof(struct unf_cfg_item_s));
	if (ret != RETURN_OK) {
		HIFC_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_REG_ATT, UNF_ERR,
			   "[err]Port(0x%x) can't get configuration",
			   hba->port_cfg.port_id);

		return ret;
	}

	if (max_parent_qpc_num <= 2048) {
		hba->port_cfg.sest_num = 2048;
		hba->port_cfg.max_login = 2048;
	}

	hba->port_cfg.port_id &= 0xff0000;
	hba->port_cfg.port_id |= hba->card_info.card_num << 8;
	hba->port_cfg.port_id |= hba->card_info.func_num;
	hba->port_cfg.tape_support = (unsigned int)v_chip_info->tape_support;

	/* Parameters check */
	ret = hifc_check_port_cfg(&hba->port_cfg);
	if (ret != RETURN_OK) {
		HIFC_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_REG_ATT, UNF_ERR,
			   "[err]Port(0x%x) check configuration incorrect",
			   hba->port_cfg.port_id);

		return ret;
	}

	/* Set configuration which is got from file */
	hba->port_speed_cfg = hba->port_cfg.port_speed;
	hba->port_topo_cfg = hba->port_cfg.port_topology;

	return ret;
}

void hifc_flush_root_ctx(struct hifc_hba_s *v_hba)
{
	int ret = 0;

	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE, v_hba, return);

	ret = hifc_func_rx_tx_flush(v_hba->hw_dev_handle);
	if (ret) {
		HIFC_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_REG_ATT, UNF_ERR,
			   "[err]chipif_func_rx_tx_flush failed with return value(0x%x)",
			   ret);
	}
}

static unsigned int hifc_delete_srqc_via_cmdq_sync(struct hifc_hba_s *v_hba,
						   unsigned long long sqrc_gpa)
{
	/* Via CMND Queue */
#define HIFC_DEL_SRQC_TIMEOUT 3000

	int ret;
	struct hifcoe_cmdqe_delete_srqc_s del_srqc_cmd;
	struct hifc_cmd_buf *cmdq_in_buf;

	/* Alloc Cmnd buffer */
	cmdq_in_buf = hifc_alloc_cmd_buf(v_hba->hw_dev_handle);
	if (!cmdq_in_buf) {
		HIFC_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_IO_ATT, UNF_ERR,
			   "[err]cmdq in_cmd_buf allocate failed");

		HIFC_ERR_IO_STAT(v_hba, HIFCOE_TASK_T_DEL_SRQC);
		return UNF_RETURN_ERROR;
	}

	/* Build & Send Cmnd */
	memset(&del_srqc_cmd, 0, sizeof(del_srqc_cmd));
	del_srqc_cmd.wd0.task_type = HIFCOE_TASK_T_DEL_SRQC;
	del_srqc_cmd.srqc_gpa_h = HIFC_HIGH_32_BITS(sqrc_gpa);
	del_srqc_cmd.srqc_gpa_l = HIFC_LOW_32_BITS(sqrc_gpa);
	hifc_cpu_to_big32(&del_srqc_cmd, sizeof(del_srqc_cmd));
	memcpy(cmdq_in_buf->buf, &del_srqc_cmd, sizeof(del_srqc_cmd));
	cmdq_in_buf->size = sizeof(del_srqc_cmd);

	ret = hifc_cmdq_detail_resp(v_hba->hw_dev_handle, HIFC_ACK_TYPE_CMDQ,
				    HIFC_MOD_FCOE, 0,
				    cmdq_in_buf, NULL, HIFC_DEL_SRQC_TIMEOUT);

	/* Free Cmnd Buffer */
	hifc_free_cmd_buf(v_hba->hw_dev_handle, cmdq_in_buf);

	if (ret) {
		HIFC_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_IO_ATT, UNF_ERR,
			   "[err]Send del srqc via cmdq failed, ret=0x%x", ret);

		HIFC_ERR_IO_STAT(v_hba, HIFCOE_TASK_T_DEL_SRQC);
		return UNF_RETURN_ERROR;
	}

	HIFC_IO_STAT(v_hba, HIFCOE_TASK_T_DEL_SRQC);

	return RETURN_OK;
}

void hifc_flush_srq_ctx(struct hifc_hba_s *v_hba)
{
	struct hifc_srq_info_s *srq_info = NULL;

	HIFC_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_REG_ATT, UNF_MAJOR,
		   "[info]Start destroy ELS SRQC");

	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE, v_hba, return);

	/* Check state to avoid to flush SRQC again */
	srq_info = &v_hba->els_srq_info;
	if (srq_info->srq_type == HIFC_SRQ_ELS &&
	    srq_info->enable == UNF_TRUE) {
		HIFC_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_IO_ATT, UNF_MAJOR,
			   "[event]HBA(0x%x) flush ELS SRQC",
			   v_hba->port_index);

		(void)hifc_delete_srqc_via_cmdq_sync(
					v_hba,
					srq_info->cqm_srq_info->q_ctx_paddr);
	}
}

static unsigned int hifc_create_queues(struct hifc_hba_s *v_hba)
{
	unsigned int ret = UNF_RETURN_ERROR;

	ret = hifc_create_root_queues(v_hba);
	if (ret != RETURN_OK)
		goto out_creat_root_queue_fail;

	/* Initialize shared resources of SCQ and SRQ in parent queue */
	ret = hifc_create_common_share_queues(v_hba);
	if (ret != RETURN_OK)
		goto out_create_common_queue_fail;

	/* Initialize parent queue manager resources */
	ret = hifc_alloc_parent_queue_mgr(v_hba);
	if (ret != RETURN_OK)
		goto out_free_share_queue_resource;

	/* Initialize shared WQE page pool in parent SQ */
	ret = hifc_alloc_parent_sq_wqe_page_pool(v_hba);
	if (ret != RETURN_OK)
		goto out_free_parent_queue_resource;

	/*
	 * Notice: the configuration of SQ and QID(default_sq_id)
	 * must be the same in FC
	 */
	v_hba->next_clearing_sq = 0;
	v_hba->default_sq_id = HIFC_QID_SQ;

	return RETURN_OK;

out_free_parent_queue_resource:
	hifc_free_parent_queue_mgr(v_hba);

out_free_share_queue_resource:
	hifc_flush_scq_ctx(v_hba);
	hifc_flush_srq_ctx(v_hba);
	hifc_destroy_common_share_queues(v_hba);

out_create_common_queue_fail:
	hifc_destroy_root_queues(v_hba);

out_creat_root_queue_fail:
	hifc_flush_root_ctx(v_hba);

	return ret;
}

static void hifc_destroy_queues(struct hifc_hba_s *v_hba)
{
	/* Free parent queue resource */
	hifc_free_parent_queues(v_hba);

	/* Free queue manager resource */
	hifc_free_parent_queue_mgr(v_hba);

	/* Free linked List SQ and WQE page pool resource */
	hifc_free_parent_sq_wqe_page_pool(v_hba);

	/* Free shared SRQ and SCQ queue resource */
	hifc_destroy_common_share_queues(v_hba);

	/* Free root queue resource */
	hifc_destroy_root_queues(v_hba);
}

static unsigned int hifc_notify_up_open_timer(struct hifc_hba_s *v_hba)
{
	int op_code = UNF_TRUE;
	unsigned int cmd_scq_bit_map = 0;
	unsigned int scq_index = 0;
	unsigned int ret;

	for (scq_index = 0; scq_index < HIFC_TOTAL_SCQ_NUM; scq_index++)
		cmd_scq_bit_map |= HIFC_SCQ_IS_CMD(scq_index) ?
					(1 << scq_index) : (0 << scq_index);

	HIFC_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_REG_ATT, UNF_MAJOR,
		   "[info]Port(0x%x) open timer, cmdscq bitmap:0x%x",
		   v_hba->port_cfg.port_id, cmd_scq_bit_map);

	ret = hifc_notify_up_config_timer(v_hba, op_code, cmd_scq_bit_map);

	return ret;
}

static unsigned int hifc_notify_up_close_timer(struct hifc_hba_s *v_hba)
{
	int op_code = UNF_FALSE;
	unsigned int cmd_scq_bit_map = 0;
	unsigned int scq_index = 0;
	unsigned int ret;

	for (scq_index = 0; scq_index < HIFC_TOTAL_SCQ_NUM; scq_index++)
		cmd_scq_bit_map |= HIFC_SCQ_IS_CMD(scq_index) ?
				   (1 << scq_index) : (0 << scq_index);

	HIFC_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_REG_ATT, UNF_MAJOR,
		   "[info]Port(0x%x) close timer with cmd_scq bitmap(0x%x)",
		   v_hba->port_cfg.port_id, cmd_scq_bit_map);

	ret = hifc_notify_up_config_timer(v_hba, op_code, cmd_scq_bit_map);

	return ret;
}

static unsigned int hifc_initial_chip_access(struct hifc_hba_s *v_hba)
{
	int ret = RETURN_OK;

	/* 1.
	 * Initialize cqm access related with scq, emb cq, aeq(ucode-->driver)
	 */
	service_cqm_temp.service_handle = v_hba;
	ret = cqm_service_register(v_hba->hw_dev_handle, &service_cqm_temp);
	if (ret != CQM_SUCCESS)
		return UNF_RETURN_ERROR;

	/* 2. Initialize mailbox(driver-->up), aeq(up--->driver) access */
	ret = hifc_register_mgmt_msg_cb(v_hba->hw_dev_handle,
					HIFC_MOD_FC, v_hba,
					hifc_up_msg_2_driver_proc);
	if (ret != CQM_SUCCESS)
		goto out_unreg_cqm;

	return RETURN_OK;

out_unreg_cqm:
	cqm_service_unregister(v_hba->hw_dev_handle);

	return UNF_RETURN_ERROR;
}

static void hifc_release_chip_access(struct hifc_hba_s *v_hba)
{
	HIFC_CHECK(INVALID_VALUE32, v_hba->hw_dev_handle, return);

	hifc_unregister_mgmt_msg_cb(v_hba->hw_dev_handle, HIFC_MOD_FC);

	cqm_service_unregister(v_hba->hw_dev_handle);
}

static void hifc_get_chip_info(struct hifc_hba_s *v_hba)
{
	unsigned int exi_base = 0;
	unsigned int fun_index = 0;

	v_hba->vpid_start = v_hba->fc_service_cap.dev_fc_cap.vp_id_start;
	v_hba->vpid_end = v_hba->fc_service_cap.dev_fc_cap.vp_id_end;
	fun_index = hifc_global_func_id(v_hba->hw_dev_handle);
	exi_base = 0;

	exi_base += (fun_index * HIFC_EXIT_STRIDE);
	v_hba->exit_base = HIFC_LSW(exi_base);
	v_hba->exit_count = HIFC_EXIT_STRIDE;
	v_hba->image_count = UNF_HIFC_MAXRPORT_NUM;
	v_hba->max_support_speed = max_speed;
	v_hba->port_index = HIFC_LSB(fun_index);

	HIFC_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_REG_ATT, UNF_MAJOR,
		   "[info]Port(0x%x) base information: PortIndex=0x%x, ImgCount=0x%x, ExiBase=0x%x, ExiCount=0x%x, VpIdStart=0x%x, VpIdEnd=0x%x, MaxSpeed=0x%x, Speed=0x%x, Topo=0x%x",
		   v_hba->port_cfg.port_id, v_hba->port_index,
		   v_hba->image_count, v_hba->exit_base,
		   v_hba->exit_count, v_hba->vpid_start,
		   v_hba->vpid_end, v_hba->max_support_speed,
		   v_hba->port_speed_cfg, v_hba->port_topo_cfg);
}

static unsigned int hifc_init_host_res(struct hifc_hba_s *v_hba)
{
	unsigned int ret = RETURN_OK;
	struct hifc_hba_s *hba = v_hba;

	HIFC_CHECK(INVALID_VALUE32, hba, return UNF_RETURN_ERROR);

	/* Initialize spin lock */
	spin_lock_init(&hba->hba_lock);
	spin_lock_init(&hba->flush_state_lock);
	spin_lock_init(&hba->delay_info.srq_lock);
	/* Initialize init_completion */
	init_completion(&hba->hba_init_complete);
	init_completion(&hba->mbox_complete);

	/* Step-1: initialize the communication channel between driver and uP */
	ret = hifc_initial_chip_access(hba);
	if (ret != RETURN_OK) {
		HIFC_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_REG_ATT, UNF_ERR,
			   "[err]HIFC port(0x%x) can't initialize chip access",
			   hba->port_cfg.port_id);

		goto out_unmap_memory;
	}
	/* Step-2: get chip configuration information before creating
	 * queue resources
	 */
	hifc_get_chip_info(hba);

	/* Step-3: create queue resources */
	ret = hifc_create_queues(hba);
	if (ret != RETURN_OK) {
		HIFC_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_REG_ATT, UNF_ERR,
			   "[err]HIFC port(0x%x) can't create queues",
			   hba->port_cfg.port_id);

		goto out_release_chip_access;
	}

	/* Initialize status parameters */
	hba->active_port_speed = UNF_PORT_SPEED_UNKNOWN;
	hba->active_topo = UNF_ACT_TOP_UNKNOWN;
	hba->sfp_on = UNF_FALSE;
	hba->port_loop_role = UNF_LOOP_ROLE_MASTER_OR_SLAVE;
	hba->phy_link = UNF_PORT_LINK_DOWN;
	hba->q_set_stage = HIFC_QUEUE_SET_STAGE_INIT;

	/* Initialize parameters referring to the lowlevel */
	hba->remote_rttov_tag = 0;
	hba->port_bbscn_cfg = HIFC_LOWLEVEL_DEFAULT_BB_SCN;

	/* Initialize timer, and the unit of E_D_TOV is ms */
	hba->remote_edtov_tag = 0;
	hba->remote_bbcredit = 0;
	hba->compared_bbscn = 0;
	hba->compared_edtov_val = UNF_DEFAULT_EDTOV;
	hba->compared_ratov_val = UNF_DEFAULT_RATOV;
	hba->removing = UNF_FALSE;
	hba->dev_present = UNF_TRUE;

	/* Initialize parameters about cos */
	hba->cos_bit_map = cos_bit_map;
	memset(hba->cos_rport_cnt, 0, HIFC_MAX_COS_NUM * sizeof(atomic_t));

	/* Mailbox access completion */
	complete(&hba->mbox_complete);

	/* Notify uP to open timer after creating scq */
	ret = hifc_notify_up_open_timer(hba);
	if (ret != RETURN_OK) {
		HIFC_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_REG_ATT, UNF_ERR,
			   "[err]HIFC port(0x%x) can't open timer",
			   hba->port_cfg.port_id);

		goto out_destroy_queues;
	}

	HIFC_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_REG_ATT, UNF_MAJOR,
		   "[info]HIFC port(0x%x) initialize host resources succeeded",
		   hba->port_cfg.port_id);

	return ret;

out_destroy_queues:
	hifc_flush_scq_ctx(hba);
	hifc_flush_srq_ctx(hba);
	hifc_flush_root_ctx(hba);
	hifc_destroy_queues(hba);

out_release_chip_access:
	hifc_release_chip_access(hba);

out_unmap_memory:
	return ret;
}

static void hifc_update_lport_config(
			struct hifc_hba_s *v_hba,
			struct unf_low_level_function_op_s *v_low_level_fun)
{
#define HIFC_MULTI_CONF_NONSUPPORT 0

	struct unf_lport_cfg_item_s *lport_cfg_items = NULL;

	lport_cfg_items = &v_low_level_fun->lport_cfg_items;

	if (v_hba->port_cfg.max_login < v_low_level_fun->support_max_rport)
		lport_cfg_items->max_login = v_hba->port_cfg.max_login;
	else
		lport_cfg_items->max_login = v_low_level_fun->support_max_rport;

	if ((v_hba->port_cfg.sest_num / 2) < UNF_RESERVE_SFS_XCHG)
		lport_cfg_items->max_io = v_hba->port_cfg.sest_num;
	else
		lport_cfg_items->max_io = v_hba->port_cfg.sest_num -
					   UNF_RESERVE_SFS_XCHG;

	lport_cfg_items->max_sfs_xchg = UNF_MAX_SFS_XCHG;
	lport_cfg_items->port_id = v_hba->port_cfg.port_id;
	lport_cfg_items->port_mode = v_hba->port_cfg.port_mode;
	lport_cfg_items->port_topology = v_hba->port_cfg.port_topology;
	lport_cfg_items->max_queue_depth = v_hba->port_cfg.max_queue_depth;

	lport_cfg_items->port_speed = v_hba->port_cfg.port_speed;
	lport_cfg_items->tape_support = v_hba->port_cfg.tape_support;
	lport_cfg_items->res_mgmt_enabled = UNF_FALSE;

	v_low_level_fun->sys_port_name =
				*(unsigned long long *)v_hba->sys_port_name;
	v_low_level_fun->sys_node_name =
				*(unsigned long long *)v_hba->sys_node_name;

	/* Update chip information */
	v_low_level_fun->dev = v_hba->pci_dev;
	v_low_level_fun->chip_info.chip_work_mode = v_hba->work_mode;
	v_low_level_fun->chip_info.chip_type = v_hba->chip_type;
	v_low_level_fun->chip_info.disable_err_flag = 0;
	v_low_level_fun->support_max_speed = v_hba->max_support_speed;

	v_low_level_fun->chip_id = 0;

	v_low_level_fun->sfp_type = UNF_PORT_TYPE_FC_SFP;

	v_low_level_fun->multi_conf_support = HIFC_MULTI_CONF_NONSUPPORT;
	v_low_level_fun->support_max_xid_range = v_hba->port_cfg.sest_num;
	v_low_level_fun->update_fw_reset_active =
					UNF_PORT_UNGRADE_FW_RESET_INACTIVE;
	v_low_level_fun->port_type = DRV_PORT_ENTITY_TYPE_PHYSICAL;

	if ((lport_cfg_items->port_id & UNF_FIRST_LPORT_ID_MASK) ==
	    lport_cfg_items->port_id) {
		v_low_level_fun->support_upgrade_report =
						UNF_PORT_SUPPORT_UPGRADE_REPORT;
	} else {
		v_low_level_fun->support_upgrade_report =
					UNF_PORT_UNSUPPORT_UPGRADE_REPORT;
	}

	v_low_level_fun->low_level_type |= UNF_FC_PROTOCOL_TYPE;
}

static unsigned int hifc_create_lport(struct hifc_hba_s *v_hba)
{
	void *lport = NULL;
	struct unf_low_level_function_op_s low_level_fun;

	HIFC_CHECK(INVALID_VALUE32, v_hba, return UNF_RETURN_ERROR);
	hifc_fun_op.dev = v_hba->pci_dev;
	memcpy(&low_level_fun, &hifc_fun_op,
	       sizeof(struct unf_low_level_function_op_s));

	/* Update port configuration table */
	hifc_update_lport_config(v_hba, &low_level_fun);

	/* Apply for lport resources */
	UNF_LOWLEVEL_ALLOC_LPORT(lport, v_hba, &low_level_fun);
	if (!lport) {
		HIFC_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_REG_ATT, UNF_ERR,
			   "[err]Port(0x%x) can't allocate Lport",
			   v_hba->port_cfg.port_id);

		return UNF_RETURN_ERROR;
	}
	v_hba->lport = lport;

	return RETURN_OK;
}

void hifc_release_probe_index(unsigned int probe_index)
{
	if (probe_index >= HIFC_MAX_PROBE_PORT_NUM) {
		HIFC_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_REG_ATT, UNF_WARN,
			   "[warn]Probe index(0x%x) is invalid", probe_index);

		return;
	}

	spin_lock(&probe_spin_lock);
	if (!test_bit((int)probe_index, (const unsigned long *)probe_bit_map)) {
		HIFC_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_REG_ATT, UNF_WARN,
			   "[warn]Probe index(0x%x) is not probed",
			   probe_index);

		spin_unlock(&probe_spin_lock);

		return;
	}

	clear_bit((int)probe_index, probe_bit_map);
	spin_unlock(&probe_spin_lock);
}

static void hifc_release_host_res(struct hifc_hba_s *v_hba)
{
	hifc_destroy_queues(v_hba);
	hifc_release_chip_access(v_hba);

	UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT, UNF_MAJOR,
		  "[info]Port(0x%x) release low level resource done",
		  v_hba->port_cfg.port_id);
}

static struct hifc_hba_s *hifc_init_hba(struct pci_dev *v_dev,
					void *v_hwdev_handle,
					struct hifc_chip_info_s *v_chip_info,
					unsigned char v_card_num)
{
	unsigned int ret = RETURN_OK;
	struct hifc_hba_s *hba = NULL;

	/* Allocate HBA */
	hba = kmalloc(sizeof(*hba), GFP_ATOMIC);
	HIFC_CHECK(INVALID_VALUE32, hba, return NULL);
	memset(hba, 0, sizeof(struct hifc_hba_s));

	/* Heartbeat default */
	hba->heart_status = 1;

	/* Private data in pciDev */
	hba->pci_dev = v_dev;  /* PCI device */
	hba->hw_dev_handle = v_hwdev_handle;

	/* Work mode */
	hba->work_mode = v_chip_info->work_mode;
	/* Create work queue */
	hba->work_queue = create_singlethread_workqueue("hifc");
	if (!hba->work_queue) {
		HIFC_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_REG_ATT, UNF_WARN,
			   "[err]Hifc creat workqueue failed");

		goto out_free_hba;
	}
	/* Init delay work */
	INIT_DELAYED_WORK(&hba->delay_info.del_work,
			  hifc_rcvd_els_from_srq_time_out);

	/* Notice: Only use FC features */
	(void)hifc_support_fc(v_hwdev_handle, &hba->fc_service_cap);
	/* Check parent context available */
	if (hba->fc_service_cap.dev_fc_cap.max_parent_qpc_num == 0) {
		HIFC_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_REG_ATT, UNF_ERR,
			   "[err]FC parent context is not allocated in this function");

		goto out_destroy_workqueue;
	}
	max_parent_qpc_num = hba->fc_service_cap.dev_fc_cap.max_parent_qpc_num;

	/* Get port configuration */
	ret = hifc_get_port_cfg(hba, v_chip_info, v_card_num);
	if (ret != RETURN_OK) {
		HIFC_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_REG_ATT, UNF_WARN,
			   "[err]Can't get port configuration");

		goto out_destroy_workqueue;
	}
	/* Get WWN */
	*(unsigned long long *)hba->sys_node_name = v_chip_info->wwnn;
	*(unsigned long long *)hba->sys_port_name = v_chip_info->wwpn;

	/* Initialize host resources */
	ret = hifc_init_host_res(hba);
	if (ret != RETURN_OK) {
		HIFC_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_REG_ATT, UNF_ERR,
			   "[err]HIFC port(0x%x) can't initialize host resource",
			   hba->port_cfg.port_id);

		goto out_destroy_workqueue;
	}

	/* Local Port create */
	ret = hifc_create_lport(hba);
	if (ret != RETURN_OK) {
		HIFC_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_REG_ATT, UNF_ERR,
			   "[err]HIFC port(0x%x) can't create lport",
			   hba->port_cfg.port_id);
		goto out_release_host_res;
	}
	complete(&hba->hba_init_complete);

	/* Print reference count */
	HIFC_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_REG_ATT, UNF_KEVENT,
		   "[info]Port(0x%x) probe succeeded.",
		   hba->port_cfg.port_id);

	return hba;

out_release_host_res:
	hifc_flush_scq_ctx(hba);
	hifc_flush_srq_ctx(hba);
	hifc_flush_root_ctx(hba);
	hifc_release_host_res(hba);

out_destroy_workqueue:
	flush_workqueue(hba->work_queue);
	destroy_workqueue(hba->work_queue);
	hba->work_queue = NULL;

out_free_hba:
	kfree(hba);

	return NULL;
}

void hifc_get_total_probed_num(unsigned int *v_probe_cnt)
{
	unsigned int i = 0;
	unsigned int count = 0;

	spin_lock(&probe_spin_lock);
	for (i = 0; i < HIFC_MAX_PROBE_PORT_NUM; i++) {
		if (test_bit((int)i, (const unsigned long *)probe_bit_map))
			count++;
	}

	*v_probe_cnt = count;
	spin_unlock(&probe_spin_lock);

	HIFC_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_REG_ATT, UNF_INFO,
		   "[info]Probed port total number is 0x%x", count);
}

static unsigned int hifc_assign_card_num(struct hifc_lld_dev *lld_dev,
					 struct hifc_chip_info_s *v_chip_info,
					 unsigned char *v_card_num)
{
	unsigned char i = 0;
	unsigned long long card_index = 0;

	card_index = (!pci_is_root_bus(lld_dev->pdev->bus)) ?
		     lld_dev->pdev->bus->parent->number :
		      lld_dev->pdev->bus->number;

	spin_lock(&probe_spin_lock);

	for (i = 0; i < HIFC_MAX_CARD_NUM; i++) {
		if (test_bit((int)i, (const unsigned long *)card_num_bit_map)) {
			if ((card_num_manage[i].card_number == card_index) &&
			    (card_num_manage[i].is_removing == UNF_FALSE)) {
				card_num_manage[i].port_count++;
				*v_card_num = i;
				spin_unlock(&probe_spin_lock);
				return RETURN_OK;
			}
		}
	}

	for (i = 0; i < HIFC_MAX_CARD_NUM; i++) {
		if (!test_bit((int)i,
			      (const unsigned long *)card_num_bit_map)) {
			card_num_manage[i].card_number = card_index;
			card_num_manage[i].port_count = 1;
			card_num_manage[i].is_removing = UNF_FALSE;
			*v_card_num = i;
			set_bit(i, card_num_bit_map);
			spin_unlock(&probe_spin_lock);

			return RETURN_OK;
		}
	}

	spin_unlock(&probe_spin_lock);

	HIFC_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_REG_ATT, UNF_ERR,
		   "[err]Have probe more than 0x%x port, probe failed", i);

	return UNF_RETURN_ERROR;
}

static void hifc_dec_and_free_card_num(unsigned char v_card_num)
{
	/* 2 ports per card */
	if (v_card_num >= HIFC_MAX_CARD_NUM) {
		HIFC_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_REG_ATT, UNF_ERR,
			   "[err]Card number(0x%x) is invalid", v_card_num);

		return;
	}

	spin_lock(&probe_spin_lock);

	if (test_bit((int)v_card_num,
		     (const unsigned long *)card_num_bit_map)) {
		card_num_manage[v_card_num].port_count--;
		card_num_manage[v_card_num].is_removing = UNF_TRUE;

		if (card_num_manage[v_card_num].port_count == 0) {
			card_num_manage[v_card_num].card_number = 0;
			card_num_manage[v_card_num].is_removing = UNF_FALSE;
			clear_bit((int)v_card_num, card_num_bit_map);
		}
	} else {
		HIFC_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_REG_ATT, UNF_ERR,
			   "[err]Can not find card number(0x%x)", v_card_num);
	}

	spin_unlock(&probe_spin_lock);
}

unsigned int hifc_assign_probe_index(unsigned int *v_probe_index)
{
	unsigned int i = 0;

	spin_lock(&probe_spin_lock);
	for (i = 0; i < HIFC_MAX_PROBE_PORT_NUM; i++) {
		if (!test_bit((int)i, (const unsigned long *)probe_bit_map)) {
			*v_probe_index = i;
			set_bit(i, probe_bit_map);
			 spin_unlock(&probe_spin_lock);

			return RETURN_OK;
		}
	}
	spin_unlock(&probe_spin_lock);

	HIFC_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_REG_ATT, UNF_ERR,
		   "[err]Have probe more than 0x%x port, probe failed", i);

	return UNF_RETURN_ERROR;
}

int hifc_probe(struct hifc_lld_dev *lld_dev, void **uld_dev, char *uld_dev_name)
{
	struct pci_dev *dev = NULL;
	struct hifc_hba_s *hba = NULL;
	unsigned int ret = UNF_RETURN_ERROR;
	unsigned int probe_index = 0;
	unsigned int probe_total_num = 0;
	unsigned char card_num = INVALID_VALUE8;
	struct hifc_chip_info_s chip_info;

	HIFC_CHECK(INVALID_VALUE32, lld_dev, return UNF_RETURN_ERROR_S32);
	HIFC_CHECK(INVALID_VALUE32, lld_dev->hwdev,
		return UNF_RETURN_ERROR_S32);
	HIFC_CHECK(INVALID_VALUE32, lld_dev->pdev, return UNF_RETURN_ERROR_S32);
	HIFC_CHECK(INVALID_VALUE32, uld_dev, return UNF_RETURN_ERROR_S32);
	HIFC_CHECK(INVALID_VALUE32, uld_dev_name, return UNF_RETURN_ERROR_S32);

	dev = lld_dev->pdev;  /* pcie device */

	memset(&chip_info, 0, sizeof(struct hifc_chip_info_s));
	/* 1. Get & check Total_Probed_number */
	hifc_get_total_probed_num(&probe_total_num);
	if (probe_total_num >= HIFC_MAX_PORT_NUM) {
		HIFC_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_REG_ATT, UNF_ERR,
			   "[err]Total probe num (0x%x) is larger than allowed number(64)",
			   probe_total_num);

		return UNF_RETURN_ERROR_S32;
	}
	/* 2. Check device work mode */
	if (hifc_support_fc(lld_dev->hwdev, NULL)) {
		chip_info.work_mode = HIFC_SMARTIO_WORK_MODE_FC;
	} else {
		HIFC_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_REG_ATT, UNF_ERR,
			   "[err]Port work mode is not FC");
		return UNF_RETURN_ERROR_S32;
	}

	/* 4. Assign & Get new Probe index */
	ret = hifc_assign_probe_index(&probe_index);
	if (ret != RETURN_OK) {
		HIFC_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_REG_ATT, UNF_ERR,
			   "[err]AssignProbeIndex fail");

		return UNF_RETURN_ERROR_S32;
	}

	ret = hifc_get_chip_capability((void *)lld_dev->hwdev, &chip_info);
	if (ret != RETURN_OK) {
		HIFC_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_REG_ATT, UNF_ERR,
			   "[err]GetChipCapability fail");
		return UNF_RETURN_ERROR_S32;
	}

	/* Assign & Get new Card number */
	ret = hifc_assign_card_num(lld_dev, &chip_info, &card_num);
	if (ret != RETURN_OK) {
		HIFC_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_REG_ATT, UNF_ERR,
			   "[err]hifc_assign_card_num fail");
		hifc_release_probe_index(probe_index);

		return UNF_RETURN_ERROR_S32;
	}

	/* Init HBA resource */
	hba = hifc_init_hba(dev, lld_dev->hwdev, &chip_info, card_num);
	if (!hba) {
		HIFC_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_REG_ATT, UNF_ERR,
			   "[err]Probe HBA(0x%x) failed.", probe_index);

		hifc_release_probe_index(probe_index);
		hifc_dec_and_free_card_num(card_num);

		return UNF_RETURN_ERROR_S32;
	}

	/* Name by the order of probe */
	*uld_dev = hba;

	snprintf(uld_dev_name, HIFC_PORT_NAME_STR_LEN, "%s%02x%02x",
		 HIFC_PORT_NAME_LABEL,
		 hba->card_info.card_num, hba->card_info.func_num);
	memcpy(hba->port_name, uld_dev_name, HIFC_PORT_NAME_STR_LEN);

	hba->probe_index = probe_index;
	hifc_hba[probe_index] = hba;

	return RETURN_OK;
}

static unsigned int hifc_port_check_fw_ready(struct hifc_hba_s *v_hba)
{
#define HIFC_PORT_CLEAR_DONE  0
#define HIFC_PORT_CLEAR_DOING 1
	unsigned int clear_state = HIFC_PORT_CLEAR_DOING;
	unsigned int ret = RETURN_OK;
	unsigned int wait_time_out = 0;

	do {
		msleep(1000);
		wait_time_out += 1000;
		ret = hifc_mbx_get_fw_clear_stat(v_hba, &clear_state);
		if (ret != RETURN_OK)
			return UNF_RETURN_ERROR;

		/* Total time more than 30s, retry more than 3 times, failed */
		if ((wait_time_out > 30000) &&
		    (clear_state != HIFC_PORT_CLEAR_DONE))
			return UNF_RETURN_ERROR;

	} while (clear_state != HIFC_PORT_CLEAR_DONE);

	return RETURN_OK;
}

static unsigned int hifc_sfp_switch(void *v_hba, void *v_para_in)
{
	struct hifc_hba_s *hba = (struct hifc_hba_s *)v_hba;
	int turn_on = UNF_FALSE;
	unsigned int ret = RETURN_OK;

	HIFC_CHECK(INVALID_VALUE32, hba, return UNF_RETURN_ERROR);
	HIFC_CHECK(INVALID_VALUE32, v_para_in, return UNF_RETURN_ERROR);

	/* Redundancy check */
	turn_on = *((int *)v_para_in);
	if (turn_on == hba->sfp_on) {
		HIFC_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_REG_ATT, UNF_INFO,
			   "[info]Port(0x%x) FC physical port is already %s",
			   hba->port_cfg.port_id, (turn_on) ? "on" : "off");

		return ret;
	}
	if (turn_on == UNF_TRUE) {
		ret = hifc_port_check_fw_ready(hba);
		if (ret != RETURN_OK) {
			UNF_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_REG_ATT,
				  UNF_WARN,
				  "[warn]Get port(0x%x) clear state failed, turn on fail",
				  hba->port_cfg.port_id);
			return ret;
		}
		/* At first, configure port table info if necessary */
		ret = hifc_config_port_table(hba);
		if (ret != RETURN_OK) {
			UNF_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_REG_ATT,
				  UNF_ERR,
				  "[err]Port(0x%x) can't configurate port table",
				  hba->port_cfg.port_id);

			return ret;
		}
	}

	/* Switch physical port */
	ret = hifc_port_switch(hba, turn_on);
	if (ret != RETURN_OK) {
		HIFC_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_REG_ATT, UNF_WARN,
			   "[err]Port(0x%x) switch failed",
			   hba->port_cfg.port_id);
		return ret;
	}

	/* Update HBA's sfp state */
	hba->sfp_on = turn_on;

	return ret;
}

static unsigned int hifc_destroy_lport(struct hifc_hba_s *v_hba)
{
	unsigned int ret = UNF_RETURN_ERROR;

	UNF_LOWLEVEL_RELEASE_LOCAL_PORT(ret, v_hba->lport);
	v_hba->lport = NULL;

	UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT, UNF_MAJOR,
		  "[info]Port(0x%x) destroy L_Port done",
		  v_hba->port_cfg.port_id);

	return ret;
}

unsigned int hifc_port_reset(struct hifc_hba_s *v_hba)
{
	unsigned int ret = RETURN_OK;
	unsigned long time_out = 0;
	int sfp_before_reset = UNF_FALSE;
	int off_para_in = UNF_FALSE;
	struct pci_dev *dev = NULL;
	struct hifc_hba_s *hba = v_hba;

	HIFC_CHECK(INVALID_VALUE32, hba, return UNF_RETURN_ERROR);
	dev = hba->pci_dev;
	HIFC_CHECK(INVALID_VALUE32, dev, return UNF_RETURN_ERROR);

	UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_REG_ATT, UNF_KEVENT,
		  "[event]Port(0x%x) reset HBA begin",
		  hba->port_cfg.port_id);

	/* Wait for last init/reset completion */
	time_out = wait_for_completion_timeout(
			&hba->hba_init_complete,
			(unsigned long)HIFC_PORT_INIT_TIME_SEC_MAX * HZ);

	if (time_out == UNF_ZERO) {
		UNF_TRACE(INVALID_VALUE32, UNF_LOG_REG_ATT, UNF_ERR,
			  "[err]Last HBA initialize/reset timeout: %d second",
			  HIFC_PORT_INIT_TIME_SEC_MAX);

		return UNF_RETURN_ERROR;
	}

	/* Save current port state */
	sfp_before_reset = hba->sfp_on;

	/* Inform the reset event to CM level before beginning */
	UNF_LOWLEVEL_PORT_EVENT(ret, hba->lport, UNF_PORT_RESET_START, NULL);
	hba->reset_time = jiffies;

	/* Close SFP */
	ret = hifc_sfp_switch(hba, &off_para_in);
	if (ret != RETURN_OK) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_REG_ATT, UNF_ERR,
			  "[err]Port(0x%x) can't close SFP",
			  hba->port_cfg.port_id);
		hba->sfp_on = sfp_before_reset;

		complete(&hba->hba_init_complete);

		return ret;
	}

	ret = hifc_port_check_fw_ready(hba);
	if (ret != RETURN_OK) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_REG_ATT, UNF_ERR,
			  "[err]Get port(0x%x) clear state failed, hang port and report chip error",
			  hba->port_cfg.port_id);

		complete(&hba->hba_init_complete);
		return ret;
	}

	hifc_queue_pre_process(hba, UNF_FALSE);

	ret = hifc_mbox_reset_chip(hba, HIFC_MBOX_SUBTYPE_LIGHT_RESET);
	if (ret != RETURN_OK) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_REG_ATT, UNF_ERR,
			  "[err]HIFC port(0x%x) can't reset chip mailbox",
			  hba->port_cfg.port_id);

		UNF_LOWLEVEL_PORT_EVENT(ret, hba->lport,
					UNF_PORT_GET_FWLOG, NULL);
		UNF_LOWLEVEL_PORT_EVENT(ret, hba->lport,
					UNF_PORT_DEBUG_DUMP, NULL);
	}

	/* Inform the success to CM level */
	UNF_LOWLEVEL_PORT_EVENT(ret, hba->lport, UNF_PORT_RESET_END, NULL);

	/* Queue open */
	hifc_enable_queues_dispatch(hba);

	/* Open SFP */
	(void)hifc_sfp_switch(hba, &sfp_before_reset);

	complete(&hba->hba_init_complete);

	UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_REG_ATT, UNF_MAJOR,
		  "[event]Port(0x%x) reset HBA done",
		  hba->port_cfg.port_id);

	return ret;
#undef HIFC_WAIT_LINKDOWN_EVENT_MS
}

static unsigned int hifc_delete_scqc_via_cmdq_sync(struct hifc_hba_s *v_hba,
						   unsigned int scqn)
{
	/* Via CMND Queue */
#define HIFC_DEL_SCQC_TIMEOUT 3000

	int ret;
	struct hifcoe_cmdqe_delete_scqc_s del_scqc_cmd;
	struct hifc_cmd_buf *cmdq_in_buf;

	/* Alloc cmd buffer */
	cmdq_in_buf = hifc_alloc_cmd_buf(v_hba->hw_dev_handle);
	if (!cmdq_in_buf) {
		HIFC_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_IO_ATT, UNF_ERR,
			   "[err]cmdq in_cmd_buf alloc failed");
		HIFC_ERR_IO_STAT(v_hba, HIFCOE_TASK_T_DEL_SCQC);
		return UNF_RETURN_ERROR;
	}

	/* Build & Send Cmnd */
	memset(&del_scqc_cmd, 0, sizeof(del_scqc_cmd));
	del_scqc_cmd.wd0.task_type = HIFCOE_TASK_T_DEL_SCQC;
	del_scqc_cmd.wd1.scqn = HIFC_LSW(scqn);
	hifc_cpu_to_big32(&del_scqc_cmd, sizeof(del_scqc_cmd));
	memcpy(cmdq_in_buf->buf, &del_scqc_cmd, sizeof(del_scqc_cmd));
	cmdq_in_buf->size = sizeof(del_scqc_cmd);

	ret = hifc_cmdq_detail_resp(v_hba->hw_dev_handle, HIFC_ACK_TYPE_CMDQ,
				    HIFC_MOD_FCOE, 0,
				    cmdq_in_buf, NULL, HIFC_DEL_SCQC_TIMEOUT);

	/* Free cmnd buffer */
	hifc_free_cmd_buf(v_hba->hw_dev_handle, cmdq_in_buf);

	if (ret) {
		HIFC_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_IO_ATT, UNF_ERR,
			   "[err]Send del scqc via cmdq failed, ret=0x%x", ret);

		HIFC_ERR_IO_STAT(v_hba, HIFCOE_TASK_T_DEL_SCQC);
		return UNF_RETURN_ERROR;
	}

	HIFC_IO_STAT(v_hba, HIFCOE_TASK_T_DEL_SCQC);

	return RETURN_OK;
}

void hifc_flush_scq_ctx(struct hifc_hba_s *v_hba)
{
	HIFC_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_REG_ATT, UNF_MAJOR,
		   "[info]Start destroy total 0x%x SCQC", HIFC_TOTAL_SCQ_NUM);

	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE, v_hba, return);

	(void)hifc_delete_scqc_via_cmdq_sync(v_hba, 0);
}

void hifc_set_hba_flush_state(struct hifc_hba_s *v_hba, int in_flush)
{
	unsigned long flag = 0;

	spin_lock_irqsave(&v_hba->flush_state_lock, flag);
	v_hba->in_flushing = in_flush;
	spin_unlock_irqrestore(&v_hba->flush_state_lock, flag);
}

static int hifc_hba_is_present(struct hifc_hba_s *v_hba)
{
	int ret = RETURN_OK;
	int present = UNF_FALSE;
	unsigned int vendor_id = 0;

	ret = pci_read_config_dword(v_hba->pci_dev, 0, &vendor_id);
	vendor_id &= HIFC_PCI_VENDOR_ID_MASK;
	if ((ret == RETURN_OK) && (vendor_id == HIFC_PCI_VENDOR_ID)) {
		present = UNF_TRUE;
	} else {
		present = UNF_FALSE;
		v_hba->dev_present = UNF_FALSE;
	}

	UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_REG_ATT, UNF_KEVENT,
		  "[info]Port %s remove: vender_id=0x%x, ret=0x%x",
		  present ? "normal" : "surprise", vendor_id, ret);

	return present;
}

static void hifc_exit(struct pci_dev *v_dev, struct hifc_hba_s *v_hba)
{
	unsigned int ret = UNF_RETURN_ERROR;
	int sfp_switch = UNF_FALSE;
	int present = UNF_TRUE;

	v_hba->removing = UNF_TRUE;

	/* 1. Check HBA present or not */
	present = hifc_hba_is_present(v_hba);
	if (present == UNF_TRUE) {
		if (v_hba->phy_link == UNF_PORT_LINK_DOWN)
			v_hba->q_set_stage = HIFC_QUEUE_SET_STAGE_FLUSHDONE;

		/* At first, close sfp */
		sfp_switch = UNF_FALSE;
		(void)hifc_sfp_switch((void *)v_hba, (void *)&sfp_switch);
	}

	/* 2. Report COM with HBA removing: delete route timer delay work */
	UNF_LOWLEVEL_PORT_EVENT(ret, v_hba->lport, UNF_PORT_BEGIN_REMOVE, NULL);

	/* 3. Report COM with HBA Nop, COM release I/O(s) & R_Port(s) forcely */
	UNF_LOWLEVEL_PORT_EVENT(ret, v_hba->lport, UNF_PORT_NOP, NULL);
	if (ret != RETURN_OK) {
		HIFC_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_REG_ATT, UNF_ERR,
			   "[err]PCI device(%p) remove port(0x%x) failed",
			   v_dev, v_hba->port_index);
	}

	if (present == UNF_TRUE) {
		/* 4.1 Wait for all SQ empty, free SRQ buffer & SRQC */
		hifc_queue_pre_process(v_hba, UNF_TRUE);
	}

	/* 5. Destroy L_Port */
	(void)hifc_destroy_lport(v_hba);

	/* 6. With HBA is present */
	if (present == UNF_TRUE) {
		/* Enable Queues dispatch */
		hifc_enable_queues_dispatch(v_hba);
		/* Need reset port if necessary */
		(void)hifc_mbox_reset_chip(v_hba,
					   HIFC_MBOX_SUBTYPE_HEAVY_RESET);

		/* Flush SCQ context */
		hifc_flush_scq_ctx(v_hba);

		/* Flush SRQ context */
		hifc_flush_srq_ctx(v_hba);

		/* Flush Root context in order to prevent DMA */
		hifc_flush_root_ctx(v_hba);

		/*
		 * NOTE: while flushing txrx, hash bucket will be cached out in
		 *  UP. Wait to clear resources completely
		 */
		msleep(1000);

		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT, UNF_MAJOR,
			  "[info]Port(0x%x) flush scq & srq & root context done",
			  v_hba->port_cfg.port_id);
	}

	/* 7. Notify uP to close timer before delete SCQ */
	ret = hifc_notify_up_close_timer(v_hba);
	if (ret != RETURN_OK) {
		HIFC_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_REG_ATT, UNF_WARN,
			   "[err]HIFC port(0x%x) can't close timer",
			   v_hba->port_cfg.port_id);
	}

	/* 8. Release host resources */
	hifc_release_host_res(v_hba);

	/* 9. Destroy FC work queue */
	if (v_hba->work_queue) {
		flush_workqueue(v_hba->work_queue);
		destroy_workqueue(v_hba->work_queue);
		v_hba->work_queue = NULL;
	}

	/* 10. Release Probe index & Decrease card number */
	hifc_release_probe_index(v_hba->probe_index);
	hifc_dec_and_free_card_num((unsigned char)v_hba->card_info.card_num);

	/* 11. Free HBA memory */
	kfree(v_hba);

	HIFC_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_REG_ATT, UNF_MAJOR,
		   "[event]PCI device(%p) remove succeed", v_dev);
}

void hifc_remove(struct hifc_lld_dev *lld_dev, void *uld_dev)
{
	struct pci_dev *dev = NULL;
	struct hifc_hba_s *hba = (struct hifc_hba_s *)uld_dev;
	unsigned int probe_total_num = 0;
	unsigned int probe_index = 0;

	HIFC_CHECK(INVALID_VALUE32, NULL != lld_dev, return);
	HIFC_CHECK(INVALID_VALUE32, NULL != uld_dev, return);
	HIFC_CHECK(INVALID_VALUE32, NULL != lld_dev->hwdev, return);
	HIFC_CHECK(INVALID_VALUE32, NULL != lld_dev->pdev, return);

	dev = hba->pci_dev;

	/* Get total probed port number */
	hifc_get_total_probed_num(&probe_total_num);
	if (probe_total_num < 1) {
		HIFC_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_REG_ATT, UNF_WARN,
			   "[warn]Port manager is empty and no need to remove");
		return;
	}

	/* check pci vendor id */
	if (dev->vendor != HIFC_PCI_VENDOR_ID_HUAWEI) {
		HIFC_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_REG_ATT, UNF_WARN,
			   "[warn]Wrong vendor id(0x%x) and exit", dev->vendor);
		return;
	}

	/* Check function ability */

	if (!(hifc_support_fc(lld_dev->hwdev, NULL))) {
		HIFC_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_REG_ATT, UNF_ERR,
			   "[err]FC is not enable in this function");
		return;
	}

	/* Get probe index */
	probe_index = hba->probe_index;

	/* Parent context allocation check */
	if (hba->fc_service_cap.dev_fc_cap.max_parent_qpc_num == 0) {
		HIFC_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_REG_ATT, UNF_ERR,
			   "[err]FC parent context not allocate in this function");
		return;
	}

	HIFC_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_REG_ATT, UNF_MAJOR,
		   "[info]HBA(0x%x) start removing...", hba->port_index);

	/* HBA removinig... */
	hifc_exit(dev, hba);

	HIFC_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_REG_ATT, UNF_KEVENT,
		   "[event]Port(0x%x) pci device removed, vendorid(0x%04x) devid(0x%04x)",
		   probe_index, dev->vendor, dev->device);

	/* Probe index check */
	if (probe_index < HIFC_HBA_PORT_MAX_NUM) {
		hifc_hba[probe_index] = NULL;
	} else {
		HIFC_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_REG_ATT, UNF_ERR,
			   "[err]Probe index(0x%x) is invalid and remove failed",
			   probe_index);
	}

	hifc_get_total_probed_num(&probe_total_num);

	HIFC_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_REG_ATT, UNF_MAJOR,
		   "[event]Removed index=%u, RemainNum=%u",
		   probe_index, probe_total_num);
}

void hifc_event(struct hifc_lld_dev *lld_dev, void *uld_dev,
		struct hifc_event_info *event)
{
	struct hifc_hba_s *hba = uld_dev;

	HIFC_CHECK(INVALID_VALUE32, NULL != lld_dev, return);
	HIFC_CHECK(INVALID_VALUE32, NULL != lld_dev->hwdev, return);
	HIFC_CHECK(INVALID_VALUE32, NULL != lld_dev->pdev, return);
	HIFC_CHECK(INVALID_VALUE32, NULL != hba, return);
	HIFC_CHECK(INVALID_VALUE32, NULL != event, return);

	switch (event->type) {
	case HIFC_EVENT_HEART_LOST:
		hba->heart_status = 0;
		HIFC_COM_UP_ERR_EVENT_STAT(hba, HIFC_EVENT_HEART_LOST);
		break;
	default:
		break;
	}
}

static unsigned int hifc_get_hba_pcie_link_state(void *v_hba,
						 void *v_link_state)
{
	int *link_state = v_link_state;
	int present = UNF_TRUE;
	struct hifc_hba_s *hba = v_hba;
	int ret;
	int last_dev_state = UNF_TRUE;
	int cur_dev_state = UNF_TRUE;

	HIFC_CHECK(INVALID_VALUE32, v_hba, return UNF_RETURN_ERROR);
	HIFC_CHECK(INVALID_VALUE32, v_link_state, return UNF_RETURN_ERROR);
	last_dev_state = hba->dev_present;
	ret = hifc_get_card_present_state(hba->hw_dev_handle, (bool *)&present);
	if (ret || present != UNF_TRUE) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_REG_ATT, UNF_KEVENT,
			  "[event]port(0x%x) is not present,ret:%d, present:%d",
			  hba->port_cfg.port_id, ret, present);
		cur_dev_state = UNF_FALSE;
	} else {
		cur_dev_state = UNF_TRUE;
	}

	hba->dev_present = cur_dev_state;

	/* the heartbeat is considered lost only when the PCIE link is down for
	 * two times.
	 */
	if ((last_dev_state == UNF_FALSE) && (cur_dev_state == UNF_FALSE))
		hba->heart_status = UNF_FALSE;
	*link_state = hba->dev_present;

	UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_ABNORMAL, UNF_INFO,
		  "Port:0x%x,get dev present:%d", hba->port_cfg.port_id,
		  *link_state);
	return RETURN_OK;
}
