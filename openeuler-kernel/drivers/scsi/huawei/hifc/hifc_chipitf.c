// SPDX-License-Identifier: GPL-2.0
/* Huawei Fabric Channel Linux driver
 * Copyright(c) 2018 Huawei Technologies Co., Ltd
 *
 */

#include "unf_common.h"
#include "hifc_chipitf.h"

#define HIFC_MBOX_TIME_SEC_MAX    60

#define HIFC_LINK_UP_COUNT        1
#define HIFC_LINK_DOWN_COUNT      2
#define HIFC_FC_DELETE_CMND_COUNT 3

#define HIFC_MBX_MAX_TIMEOUT 10000

static unsigned int hifc_recv_fc_link_up(struct hifc_hba_s *v_hba,
					 void *v_buf_in);
static unsigned int hifc_recv_fc_link_down(struct hifc_hba_s *v_hba,
					   void *v_buf_in);
static unsigned int hifc_recv_fc_del_cmd(struct hifc_hba_s *v_hba,
					 void *v_buf_in);
static unsigned int hifc_recv_fc_error(struct hifc_hba_s *v_hba,
				       void *v_buf_in);

static struct hifc_up_2_drv_msg_handle_s up_msg_handle[] = {
	{ HIFC_MBOX_RECV_FC_LINKUP,   hifc_recv_fc_link_up },
	{ HIFC_MBOX_RECV_FC_LINKDOWN, hifc_recv_fc_link_down },
	{ HIFC_MBOX_RECV_FC_DELCMD,   hifc_recv_fc_del_cmd },
	{ HIFC_MBOX_RECV_FC_ERROR,    hifc_recv_fc_error }
};

void hifc_up_msg_2_driver_proc(void *v_hwdev_handle, void *v_pri_handle,
			       unsigned char v_cmd, void *v_buf_in,
			       unsigned short v_in_size,  void *v_buf_out,
			       unsigned short *v_out_size)
{
	unsigned int ret = UNF_RETURN_ERROR;
	unsigned int index = 0;
	struct hifc_hba_s *hba = NULL;
	struct hifc_mbox_header_s *mbx_header = NULL;

	HIFC_CHECK(INVALID_VALUE32, v_hwdev_handle, return);
	HIFC_CHECK(INVALID_VALUE32, v_pri_handle, return);
	HIFC_CHECK(INVALID_VALUE32, v_buf_in, return);
	HIFC_CHECK(INVALID_VALUE32, v_buf_out, return);
	HIFC_CHECK(INVALID_VALUE32, v_out_size, return);

	hba = (struct hifc_hba_s *)v_pri_handle;
	if (!hba) {
		HIFC_TRACE(UNF_EVTLOG_LINK_ERR, UNF_LOG_EVENT, UNF_ERR,
			   "[err]Hba is null");

		return;
	}

	mbx_header = (struct hifc_mbox_header_s *)v_buf_in;
	if (mbx_header->cmnd_type != v_cmd) {
		HIFC_TRACE(UNF_EVTLOG_LINK_ERR, UNF_LOG_EVENT, UNF_ERR,
			   "[err]Port(0x%x) cmd(0x%x) is not matched with header cmd type(0x%x)",
			   hba->port_cfg.port_id, v_cmd,
			   mbx_header->cmnd_type);
		return;
	}

	while (index < (sizeof(up_msg_handle) /
		sizeof(struct hifc_up_2_drv_msg_handle_s))) {
		if ((v_cmd == up_msg_handle[index].cmd) &&
		    (up_msg_handle[index].pfn_hifc_msg_up2drv_handler)) {
			ret =
			up_msg_handle[index].pfn_hifc_msg_up2drv_handler(
								hba,
								v_buf_in);
			if (ret != RETURN_OK) {
				HIFC_TRACE(UNF_EVTLOG_LINK_ERR, UNF_LOG_EVENT,
					   UNF_ERR,
					   "[warn]Port(0x%x) process up cmd(0x%x) failed",
					   hba->port_cfg.port_id, v_cmd);
			}

			/* Process Done & return */
			return;
		}
		index++;
	}

	HIFC_TRACE(UNF_EVTLOG_LINK_ERR, UNF_LOG_EVENT, UNF_ERR,
		   "[err]Port(0x%x) process up cmd(0x%x) failed",
		   hba->port_cfg.port_id, v_cmd);

	PRINT_OUTBOUND_IOB(UNF_MAJOR, v_buf_in, ((unsigned int)v_in_size));
}

unsigned int hifc_get_chip_msg(void *v_hba, void *v_mac)
{
	struct hifc_hba_s *hba = NULL;
	struct unf_get_chip_info_argout *wwn = NULL;
	struct hifc_inbox_get_chip_info_s get_chip_info;
	union hifc_outmbox_generic_u *chip_info_sts = NULL;
	unsigned int ret = UNF_RETURN_ERROR;

	HIFC_CHECK(INVALID_VALUE32, v_hba, return UNF_RETURN_ERROR);
	HIFC_CHECK(INVALID_VALUE32, v_mac, return UNF_RETURN_ERROR);

	hba = (struct hifc_hba_s *)v_hba;
	wwn = (struct unf_get_chip_info_argout *)v_mac;

	memset(&get_chip_info, 0, sizeof(struct hifc_inbox_get_chip_info_s));

	chip_info_sts = kmalloc(sizeof(union hifc_outmbox_generic_u),
				GFP_ATOMIC);
	if (!chip_info_sts) {
		HIFC_TRACE(UNF_EVTLOG_LINK_ERR, UNF_LOG_REG_ATT, UNF_ERR,
			   "malloc outmbox memory failed");
		return UNF_RETURN_ERROR;
	}
	memset(chip_info_sts, 0, sizeof(union hifc_outmbox_generic_u));

	get_chip_info.header.cmnd_type = HIFC_MBOX_GET_CHIP_INFO;
	get_chip_info.header.length =
	HIFC_BYTES_TO_DW_NUM(sizeof(struct hifc_inbox_get_chip_info_s));

	if (hifc_mb_send_and_wait_mbox(hba, &get_chip_info,
				       sizeof(get_chip_info), chip_info_sts) !=
				       RETURN_OK) {
		HIFC_TRACE(UNF_EVTLOG_LINK_ERR, UNF_LOG_REG_ATT, UNF_ERR,
			   "hifc can't send and wait mailbox, command type: 0x%x.",
			   get_chip_info.header.cmnd_type);

		goto exit;
	}

	if (chip_info_sts->get_chip_info_sts.status != RETURN_OK) {
		HIFC_TRACE(UNF_EVTLOG_LINK_ERR, UNF_LOG_REG_ATT, UNF_ERR,
			   "Port(0x%x) mailbox status incorrect status(0x%x) .",
			   hba->port_cfg.port_id,
			   chip_info_sts->get_chip_info_sts.status);

		goto exit;
	}

	if (chip_info_sts->get_chip_info_sts.header.cmnd_type !=
	    HIFC_MBOX_GET_CHIP_INFO_STS) {
		HIFC_TRACE(UNF_EVTLOG_LINK_ERR, UNF_LOG_REG_ATT, UNF_ERR,
			   "Port(0x%x) receive mailbox type incorrect type: 0x%x.",
			   hba->port_cfg.port_id,
			   chip_info_sts->get_chip_info_sts.header.cmnd_type);

		goto exit;
	}

	wwn->board_type = chip_info_sts->get_chip_info_sts.board_type;
	hba->card_info.card_type = chip_info_sts->get_chip_info_sts.board_type;
	wwn->wwpn = chip_info_sts->get_chip_info_sts.wwpn;
	wwn->wwnn = chip_info_sts->get_chip_info_sts.wwnn;
	wwn->sys_mac = chip_info_sts->get_chip_info_sts.sys_mac;

	ret = RETURN_OK;
exit:
	kfree(chip_info_sts);
	return ret;
}

unsigned int hifc_get_chip_capability(void *hw_dev_handle,
				      struct hifc_chip_info_s *v_chip_info)
{
	struct hifc_inbox_get_chip_info_s get_chip_info;
	union hifc_outmbox_generic_u *chip_info_sts = NULL;
	unsigned short out_size = 0;
	unsigned int ret = UNF_RETURN_ERROR;

	HIFC_CHECK(INVALID_VALUE32, hw_dev_handle, return UNF_RETURN_ERROR);

	memset(&get_chip_info, 0, sizeof(struct hifc_inbox_get_chip_info_s));

	chip_info_sts = kmalloc(sizeof(union hifc_outmbox_generic_u),
				GFP_ATOMIC);
	if (!chip_info_sts) {
		HIFC_TRACE(UNF_EVTLOG_LINK_ERR, UNF_LOG_REG_ATT, UNF_ERR,
			   "malloc outmbox memory failed");
		return UNF_RETURN_ERROR;
	}
	memset(chip_info_sts, 0, sizeof(union hifc_outmbox_generic_u));

	get_chip_info.header.cmnd_type = HIFC_MBOX_GET_CHIP_INFO;
	get_chip_info.header.length =
	HIFC_BYTES_TO_DW_NUM(sizeof(struct hifc_inbox_get_chip_info_s));
	out_size = sizeof(union hifc_outmbox_generic_u);

	if (hifc_msg_to_mgmt_sync(hw_dev_handle, HIFC_MOD_FC,
				  HIFC_MBOX_GET_CHIP_INFO,
				  (void *)&get_chip_info.header,
				  sizeof(struct hifc_inbox_get_chip_info_s),
				  (union hifc_outmbox_generic_u *)chip_info_sts,
				  &out_size,
				  (HIFC_MBX_MAX_TIMEOUT)) != RETURN_OK) {
		HIFC_TRACE(UNF_EVTLOG_LINK_ERR, UNF_LOG_REG_ATT, UNF_ERR,
			   "hifc can't send and wait mailbox, command type: 0x%x.",
			   HIFC_MBOX_GET_CHIP_INFO);

		goto exit;
	}

	if (chip_info_sts->get_chip_info_sts.status != RETURN_OK) {
		HIFC_TRACE(UNF_EVTLOG_LINK_ERR, UNF_LOG_REG_ATT, UNF_ERR,
			   "Port mailbox status incorrect status(0x%x) .",
			   chip_info_sts->get_chip_info_sts.status);

		goto exit;
	}

	if (chip_info_sts->get_chip_info_sts.header.cmnd_type !=
	    HIFC_MBOX_GET_CHIP_INFO_STS) {
		HIFC_TRACE(UNF_EVTLOG_LINK_ERR, UNF_LOG_REG_ATT, UNF_ERR,
			   "Port receive mailbox type incorrect type: 0x%x.",
			   chip_info_sts->get_chip_info_sts.header.cmnd_type);

		goto exit;
	}

	v_chip_info->wwnn = chip_info_sts->get_chip_info_sts.wwnn;
	v_chip_info->wwpn = chip_info_sts->get_chip_info_sts.wwpn;
	v_chip_info->tape_support = (unsigned char)
				chip_info_sts->get_chip_info_sts.tape_support;
	ret = RETURN_OK;
exit:
	kfree(chip_info_sts);
	return ret;
}

void hifc_get_red_info_by_rw_type(struct unf_rw_reg_param_s *param,
				  struct hifc_inmbox_get_reg_info_s *v_reg_info)
{
	if ((param->rw_type == UNF_READ) ||
	    (param->rw_type == UNF_READ_64)) {
		v_reg_info->op_code = 0;
	} else if ((param->rw_type == UNF_WRITE) ||
		   (param->rw_type == UNF_WRITE_64)) {
		v_reg_info->op_code = 1;
	}

	if ((param->rw_type == UNF_READ) ||
	    (param->rw_type == UNF_WRITE)) {
		v_reg_info->reg_len = 32;
	} else if ((param->rw_type == UNF_READ_64) ||
		   (param->rw_type == UNF_WRITE_64)) {
		v_reg_info->reg_len = 64;
	}
}

unsigned int hifc_rw_reg(void *v_hba, void *v_params)
{
	struct hifc_hba_s *hba = NULL;
	struct unf_rw_reg_param_s *param = NULL;
	struct hifc_inmbox_get_reg_info_s reg_info;
	union hifc_outmbox_generic_u *reg_info_sts = NULL;
	unsigned int para_value_out_l = 0;
	unsigned int para_value_out_h = 0;
	unsigned int ret = UNF_RETURN_ERROR;

	HIFC_CHECK(INVALID_VALUE32, v_hba, return UNF_RETURN_ERROR);
	HIFC_CHECK(INVALID_VALUE32, v_params, return UNF_RETURN_ERROR);

	hba = (struct hifc_hba_s *)v_hba;
	param = (struct unf_rw_reg_param_s *)v_params;

	memset(&reg_info, 0, sizeof(struct hifc_inmbox_get_reg_info_s));
	reg_info_sts = kmalloc(sizeof(union hifc_outmbox_generic_u),
			       GFP_ATOMIC);
	if (!reg_info_sts) {
		HIFC_TRACE(UNF_EVTLOG_LINK_ERR, UNF_LOG_REG_ATT, UNF_ERR, "malloc outmbox memory failed");
		return UNF_RETURN_ERROR;
	}
	memset(reg_info_sts, 0, sizeof(union hifc_outmbox_generic_u));

	hifc_get_red_info_by_rw_type(param, &reg_info);

	reg_info.reg_addr = param->offset;
	reg_info.reg_value_l32 = (param->value) & VALUEMASK_L;
	reg_info.reg_value_h32 = ((param->value) & VALUEMASK_H) >> 32;

	reg_info.header.cmnd_type = HIFC_MBOX_REG_RW_MODE;
	reg_info.header.length =
	HIFC_BYTES_TO_DW_NUM(sizeof(struct hifc_inmbox_get_reg_info_s));

	if (hifc_mb_send_and_wait_mbox(hba, &reg_info,
				       sizeof(reg_info),
				       reg_info_sts) != RETURN_OK) {
		HIFC_TRACE(UNF_EVTLOG_LINK_ERR, UNF_LOG_REG_ATT, UNF_ERR,
			   "hifc can't send and wait mailbox, command type: 0x%x.",
			   reg_info.header.cmnd_type);

		goto exit;
	}

	if (reg_info_sts->get_reg_info_sts.status != RETURN_OK) {
		HIFC_TRACE(UNF_EVTLOG_LINK_ERR, UNF_LOG_REG_ATT, UNF_ERR,
			   "Port(0x%x) mailbox status incorrect status(0x%x) .",
			   hba->port_cfg.port_id,
			   reg_info_sts->get_reg_info_sts.status);

		goto exit;
	}

	if (reg_info_sts->get_reg_info_sts.header.cmnd_type !=
	    HIFC_MBOX_REG_RW_MODE_STS) {
		HIFC_TRACE(UNF_EVTLOG_LINK_ERR, UNF_LOG_REG_ATT, UNF_ERR,
			   "Port(0x%x) receive mailbox type incorrect type: 0x%x.",
			   hba->port_cfg.port_id,
			   reg_info_sts->get_reg_info_sts.header.cmnd_type);

		goto exit;
	}

	para_value_out_l = reg_info_sts->get_reg_info_sts.reg_value_l32;
	para_value_out_h = reg_info_sts->get_reg_info_sts.reg_value_h32;
	param->value = (unsigned long long)para_value_out_l |
			 ((unsigned long long)para_value_out_h << 32);

	ret = RETURN_OK;
exit:
	kfree(reg_info_sts);
	return ret;
}

unsigned int hifc_config_port_table(struct hifc_hba_s *v_hba)
{
	struct hifc_inbox_config_api_s config_api;
	union hifc_outmbox_generic_u *out_mbox = NULL;
	unsigned int ret = UNF_RETURN_ERROR;

	HIFC_CHECK(INVALID_VALUE32, NULL != v_hba, return UNF_RETURN_ERROR);

	memset(&config_api, 0, sizeof(config_api));
	out_mbox = kmalloc(sizeof(union hifc_outmbox_generic_u), GFP_ATOMIC);
	if (!out_mbox) {
		HIFC_TRACE(UNF_EVTLOG_LINK_ERR, UNF_LOG_REG_ATT, UNF_ERR, "malloc outmbox memory failed");
		return UNF_RETURN_ERROR;
	}
	memset(out_mbox, 0, sizeof(union hifc_outmbox_generic_u));

	config_api.header.cmnd_type = HIFC_MBOX_CONFIG_API;
	config_api.header.length =
	HIFC_BYTES_TO_DW_NUM(sizeof(struct hifc_inbox_config_api_s));

	config_api.op_code = UNDEFINEOPCODE;

	/* change switching top cmd of CM to the cmd that up recognize */
	/* if the cmd equals UNF_TOP_P2P_MASK sending in CM  means that it
	 * should be changed into P2P top, LL using  HIFC_TOP_NON_LOOP_MASK
	 */
	if ((unsigned char)v_hba->port_topo_cfg == UNF_TOP_P2P_MASK) {
		config_api.topy_mode = 0x2;
	/* if the cmd equals UNF_TOP_LOOP_MASK sending in CM  means that it
	 * should be changed into loop top, LL using  HIFC_TOP_LOOP_MASK
	 */
	} else if ((unsigned char)v_hba->port_topo_cfg == UNF_TOP_LOOP_MASK) {
		config_api.topy_mode = 0x1;

	/* if the cmd equals UNF_TOP_AUTO_MASK sending in CM  means that it
	 * should be changed into loop top, LL using  HIFC_TOP_AUTO_MASK
	 */
	} else if ((unsigned char)v_hba->port_topo_cfg == UNF_TOP_AUTO_MASK) {
		config_api.topy_mode = 0x0;
	} else {
		HIFC_TRACE(UNF_EVTLOG_LINK_ERR, UNF_LOG_REG_ATT, UNF_ERR,
			   "[err]Port(0x%x) topo cmd is error, command type: 0x%x",
			   v_hba->port_cfg.port_id,
			   (unsigned char)v_hba->port_topo_cfg);

		return UNF_RETURN_ERROR;
	}

	/* About speed */
	config_api.sfp_speed = (unsigned char)(v_hba->port_speed_cfg);
	config_api.max_speed = (unsigned char)(v_hba->max_support_speed);

	config_api.rx_bbcredit_32g = HIFC_LOWLEVEL_DEFAULT_32G_BB_CREDIT;
	config_api.rx_bbcredit_16g = HIFC_LOWLEVEL_DEFAULT_16G_BB_CREDIT;
	config_api.rx_bbcredit_842g = HIFC_LOWLEVEL_DEFAULT_842G_BB_CREDIT;
	config_api.rdy_cnt_bf_fst_frm = HIFC_LOWLEVEL_DEFAULT_LOOP_BB_CREDIT;
	config_api.esch_value_32g = HIFC_LOWLEVEL_DEFAULT_32G_ESCH_VALUE;
	config_api.esch_value_16g = HIFC_LOWLEVEL_DEFAULT_16G_ESCH_VALUE;
	config_api.esch_value_8g = HIFC_LOWLEVEL_DEFAULT_842G_ESCH_VALUE;
	config_api.esch_value_4g = HIFC_LOWLEVEL_DEFAULT_842G_ESCH_VALUE;
	config_api.esch_value_2g = HIFC_LOWLEVEL_DEFAULT_842G_ESCH_VALUE;
	config_api.esch_bust_size = HIFC_LOWLEVEL_DEFAULT_ESCH_BUS_SIZE;

	/* default value:0xFF */
	config_api.hard_alpa = 0xFF;
	memcpy(config_api.port_name, v_hba->sys_port_name, UNF_WWN_LEN);

	/* if only for slave, the value is 1; if participate master choosing,
	 * the value is 0
	 */
	config_api.slave = v_hba->port_loop_role;

	/* 1:auto negotiate, 0:fixed mode negotiate */
	if (config_api.sfp_speed == 0)
		config_api.auto_sneg = 0x1;
	else
		config_api.auto_sneg = 0x0;

	/* send & wait */
	if (hifc_mb_send_and_wait_mbox(v_hba, &config_api,
				       sizeof(config_api),
				       out_mbox) != RETURN_OK) {
		HIFC_TRACE(UNF_EVTLOG_LINK_ERR, UNF_LOG_REG_ATT, UNF_ERR,
			   "[warn]Port(0x%x) HIFC can't send and wait mailbox, command type: 0x%x",
			   v_hba->port_cfg.port_id,
			   config_api.header.cmnd_type);

		goto exit;
	}

	/* mailbox status check */
	if (out_mbox->config_api_sts.status != RETURN_OK) {
		HIFC_TRACE(UNF_EVTLOG_LINK_ERR, UNF_LOG_EQUIP_ATT, UNF_ERR,
			   "[err]Port(0x%x) receive mailbox type(0x%x) with status(0x%x) error",
			   v_hba->port_cfg.port_id,
			   out_mbox->config_api_sts.header.cmnd_type,
			   out_mbox->config_api_sts.status);

		goto exit;
	}

	/* RSP type check */
	if (out_mbox->config_api_sts.header.cmnd_type !=
	    HIFC_MBOX_CONFIG_API_STS) {
		HIFC_TRACE(UNF_EVTLOG_LINK_ERR, UNF_LOG_EQUIP_ATT, UNF_ERR,
			   "[err]Port(0x%x) receive mailbox type(0x%x) error",
			   v_hba->port_cfg.port_id,
			   out_mbox->config_api_sts.header.cmnd_type);

		goto exit;
	}

	ret = RETURN_OK;
exit:
	kfree(out_mbox);
	return ret;
}

unsigned int hifc_port_switch(struct hifc_hba_s *v_hba, int turn_on)
{
	struct hifc_inbox_port_switch_s port_switch;
	union hifc_outmbox_generic_u *port_switch_sts = NULL;
	unsigned int ret = UNF_RETURN_ERROR;

	HIFC_CHECK(INVALID_VALUE32, NULL != v_hba, return UNF_RETURN_ERROR);

	memset(&port_switch, 0, sizeof(port_switch));

	port_switch_sts = kmalloc(sizeof(union hifc_outmbox_generic_u),
				  GFP_ATOMIC);
	if (!port_switch_sts) {
		HIFC_TRACE(UNF_EVTLOG_LINK_ERR, UNF_LOG_REG_ATT, UNF_ERR, "malloc outmbox memory failed");
		return UNF_RETURN_ERROR;
	}
	memset(port_switch_sts, 0, sizeof(union hifc_outmbox_generic_u));

	port_switch.header.cmnd_type = HIFC_MBOX_PORT_SWITCH;
	port_switch.header.length =
	HIFC_BYTES_TO_DW_NUM(sizeof(struct hifc_inbox_port_switch_s));
	port_switch.op_code = (unsigned char)turn_on;
	port_switch.port_type = (unsigned char)v_hba->port_type;

	/* set the value is 0 first, vn2vf mode, vlan discovery automatically */
	port_switch.host_id = 0;
	port_switch.pf_id =
	(unsigned char)(hifc_global_func_id(v_hba->hw_dev_handle));
	port_switch.fcoe_mode = HIFC_FIP_MODE_VN2VF;
	port_switch.conf_vlan = 0xffff;
	port_switch.sys_node_name = *(unsigned long long *)v_hba->sys_node_name;
	port_switch.sys_port_wwn = *(unsigned long long *)v_hba->sys_port_name;

	/* send & wait mailbox */
	if (hifc_mb_send_and_wait_mbox(v_hba, &port_switch, sizeof(port_switch),
				       port_switch_sts) != RETURN_OK) {
		HIFC_TRACE(UNF_EVTLOG_LINK_ERR, UNF_LOG_REG_ATT, UNF_ERR,
			   "[warn]Port(0x%x) HIFC can't send and wait mailbox, command type(0x%x) opcode(0x%x)",
			   v_hba->port_cfg.port_id,
			   port_switch.header.cmnd_type, port_switch.op_code);

		goto exit;
	}

	/* check mailbox rsp status */
	if (port_switch_sts->port_switch_sts.status != RETURN_OK) {
		HIFC_TRACE(UNF_EVTLOG_LINK_ERR, UNF_LOG_EQUIP_ATT, UNF_ERR,
			   "[err]Port(0x%x) receive mailbox type(0x%x) status(0x%x) error",
			   v_hba->port_cfg.port_id,
			   port_switch_sts->port_switch_sts.header.cmnd_type,
			   port_switch_sts->port_switch_sts.status);

		goto exit;
	}

	/* check mailbox rsp type */
	if (port_switch_sts->port_switch_sts.header.cmnd_type !=
	    HIFC_MBOX_PORT_SWITCH_STS) {
		HIFC_TRACE(UNF_EVTLOG_LINK_ERR, UNF_LOG_EQUIP_ATT, UNF_ERR,
			   "[err]Port(0x%x) receive mailbox type(0x%x) error",
			   v_hba->port_cfg.port_id,
			   port_switch_sts->port_switch_sts.header.cmnd_type);

		goto exit;
	}

	HIFC_TRACE(UNF_EVTLOG_LINK_SUC, UNF_LOG_EQUIP_ATT, UNF_MAJOR,
		   "[event]Port(0x%x) switch succeed, turns to %s",
		   v_hba->port_cfg.port_id,
		   (turn_on) ? "on" : "off");

	ret = RETURN_OK;
exit:
	kfree(port_switch_sts);
	return ret;
}

unsigned int hifc_config_login_api(struct hifc_hba_s *v_hba,
				   struct unf_port_login_parms_s *v_login_para)
{
#define HIFC_LOOP_RDYNUM 8
	int async_ret = RETURN_OK;
	unsigned int ret = UNF_RETURN_ERROR;
	struct hifc_inmbox_config_login_s cfg_login;
	union hifc_outmbox_generic_u *cfg_login_sts = NULL;

	HIFC_CHECK(INVALID_VALUE32, NULL != v_hba, return UNF_RETURN_ERROR);

	memset(&cfg_login, 0, sizeof(cfg_login));
	cfg_login_sts = kmalloc(sizeof(union hifc_outmbox_generic_u),
				GFP_ATOMIC);
	if (!cfg_login_sts) {
		HIFC_TRACE(UNF_EVTLOG_LINK_ERR, UNF_LOG_REG_ATT, UNF_ERR, "malloc outmbox memory failed");
		return UNF_RETURN_ERROR;
	}
	memset(cfg_login_sts, 0, sizeof(union hifc_outmbox_generic_u));

	cfg_login.header.cmnd_type = HIFC_MBOX_CONFIG_LOGIN_API;
	cfg_login.header.length =
	HIFC_BYTES_TO_DW_NUM(sizeof(struct hifc_inmbox_config_login_s));
	cfg_login.header.port_id = v_hba->port_index;

	cfg_login.op_code = UNDEFINEOPCODE;

	cfg_login.tx_bb_credit = v_hba->remote_bbcredit;

	cfg_login.etov = v_hba->compared_edtov_val;
	cfg_login.rtov = v_hba->compared_ratov_val;

	cfg_login.rt_tov_tag = v_hba->remote_rttov_tag;
	cfg_login.ed_tov_tag = v_hba->remote_edtov_tag;
	cfg_login.bb_credit = v_hba->remote_bbcredit;
	cfg_login.bbscn = HIFC_LSB(v_hba->compared_bbscn);

	if (cfg_login.bbscn) {
		cfg_login.lr_flag =
		(v_login_para->els_cmnd_code == ELS_PLOGI) ? 0 : 1;
		ret = hifc_mb_send_and_wait_mbox(v_hba, &cfg_login,
						 sizeof(cfg_login),
						 cfg_login_sts);
		if (ret != RETURN_OK) {
			HIFC_TRACE(UNF_EVTLOG_LINK_WARN, UNF_LOG_REG_ATT,
				   UNF_WARN,
				   "Port(0x%x) HIFC can't send and wait mailbox, command type: 0x%x.",
				   v_hba->port_cfg.port_id,
				   cfg_login.header.cmnd_type);

			goto exit;
		}

		if (cfg_login_sts->config_login_sts.header.cmnd_type !=
		    HIFC_MBOX_CONFIG_LOGIN_API_STS) {
			HIFC_TRACE(UNF_EVTLOG_LINK_INFO, UNF_LOG_REG_ATT,
				   UNF_INFO, "Port(0x%x) Receive mailbox type incorrect. Type: 0x%x.",
				   v_hba->port_cfg.port_id,
				   cfg_login_sts->config_login_sts.header.cmnd_type);

			goto exit;
		}

		if (cfg_login_sts->config_login_sts.status != STATUS_OK) {
			HIFC_TRACE(UNF_EVTLOG_LINK_WARN, UNF_LOG_LOGIN_ATT,
				   UNF_WARN, "Port(0x%x) Receive mailbox type(0x%x) status incorrect. Status: 0x%x.",
				   v_hba->port_cfg.port_id,
				   cfg_login_sts->config_login_sts.header.cmnd_type,
				   cfg_login_sts->config_login_sts.status);

			goto exit;
		}
	} else {
		async_ret = hifc_msg_to_mgmt_async(v_hba->hw_dev_handle,
						   HIFC_MOD_FC,
						   HIFC_MBOX_CONFIG_LOGIN_API,
						   &cfg_login,
						   sizeof(cfg_login));

		if (async_ret != 0) {
			HIFC_MAILBOX_STAT(v_hba,
					  HIFC_SEND_CONFIG_LOGINAPI_FAIL);
			HIFC_TRACE(UNF_EVTLOG_LINK_ERR, UNF_LOG_REG_ATT,
				   UNF_ERR,
				   "Port(0x%x) hifc can't send config login cmd to up,ret:%d.",
				   v_hba->port_cfg.port_id, async_ret);

			goto exit;
		}

		HIFC_MAILBOX_STAT(v_hba, HIFC_SEND_CONFIG_LOGINAPI);
	}

	HIFC_TRACE(UNF_EVTLOG_LINK_SUC, UNF_LOG_LOGIN_ATT, UNF_MAJOR,
		   "Port(0x%x) Topo(0x%x) Config login param to up: txbbcredit(0x%x), BB_SC_N(0x%x).",
		   v_hba->port_cfg.port_id, v_hba->active_topo,
		   cfg_login.tx_bb_credit, cfg_login.bbscn);

	ret = RETURN_OK;
exit:
	kfree(cfg_login_sts);
	return ret;
}

unsigned int hifc_mb_send_and_wait_mbox(struct hifc_hba_s *v_hba,
					const void *v_in_mbox,
					unsigned short in_size,
					union hifc_outmbox_generic_u *out_mbox)
{
	void *handle = NULL;
	unsigned short out_size = 0;
	unsigned long time_out = 0;
	int ret = 0;
	struct hifc_mbox_header_s *header;

	HIFC_CHECK(INVALID_VALUE32, v_hba, return UNF_RETURN_ERROR);
	HIFC_CHECK(INVALID_VALUE32, v_in_mbox, return UNF_RETURN_ERROR);
	HIFC_CHECK(INVALID_VALUE32, out_mbox, return UNF_RETURN_ERROR);
	HIFC_CHECK(INVALID_VALUE32, v_hba->hw_dev_handle,
		return UNF_RETURN_ERROR);

	header = (struct hifc_mbox_header_s *)v_in_mbox;
	out_size = sizeof(union hifc_outmbox_generic_u);
	handle = v_hba->hw_dev_handle;

	/* Wait for las mailbox completion: */
	time_out = wait_for_completion_timeout(
		&v_hba->mbox_complete,
		(unsigned long)msecs_to_jiffies(HIFC_MBOX_TIME_SEC_MAX * 1000));
	if (time_out == UNF_ZERO) {
		HIFC_TRACE(UNF_EVTLOG_LINK_ERR, UNF_LOG_EQUIP_ATT, UNF_ERR,
			   "[err]Port(0x%x) wait mailbox(0x%x) completion timeout: %d sec",
			   v_hba->port_cfg.port_id, header->cmnd_type,
			   HIFC_MBOX_TIME_SEC_MAX);

		return UNF_RETURN_ERROR;
	}

	/* Send Msg to uP Sync: timer 10s */
	ret = hifc_msg_to_mgmt_sync(handle, HIFC_MOD_FC, header->cmnd_type,
				    (void *)v_in_mbox, in_size,
				    (union hifc_outmbox_generic_u *)out_mbox,
				    &out_size,
				    HIFC_MBX_MAX_TIMEOUT);
	if (ret != RETURN_OK) {
		HIFC_TRACE(UNF_EVTLOG_LINK_ERR, UNF_LOG_REG_ATT, UNF_ERR,
			   "[warn]Port(0x%x) can not send mailbox(0x%x) with ret:%d",
			   v_hba->port_cfg.port_id, header->cmnd_type, ret);

		complete(&v_hba->mbox_complete);
		return UNF_RETURN_ERROR;
	}

	complete(&v_hba->mbox_complete);
	return RETURN_OK;
}

unsigned short hifc_get_global_base_qpn(void *v_handle)
{
#define NIC_UP_CMD_GET_GLOBAL_QPN 102

	int ret = 0;
	unsigned short out_size = 0;
	struct hifc_get_global_base_qpn_s qpn_base = { 0 };

	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE, v_handle,
			return INVALID_VALUE16);
	qpn_base.func_id = hifc_global_func_id(v_handle);
	out_size = (u16)sizeof(struct hifc_get_global_base_qpn_s);

	/* Send Msg to uP Sync: timer 10s */
	ret = hifc_msg_to_mgmt_sync(v_handle,
				    HIFC_MOD_L2NIC,
				    NIC_UP_CMD_GET_GLOBAL_QPN,
				    &qpn_base,
				    (u16)sizeof(qpn_base),
				    &qpn_base,
				    &out_size,
				    HIFC_MBX_MAX_TIMEOUT);

	if (ret || (!out_size) || qpn_base.status) {
		HIFC_TRACE(UNF_EVTLOG_LINK_ERR, UNF_LOG_REG_ATT, UNF_ERR,
			   "[warn]hifc_get_global_base_qpn failed, ret %d, out_size %u, qpn_info.ret%u",
			   ret, out_size, qpn_base.status);

		return 0xFFFF;
	}

	return (u16)(qpn_base.base_qpn);
}

void hifc_initial_dynamic_info(struct hifc_hba_s *v_fc_port)
{
	struct hifc_hba_s *hba = v_fc_port;
	unsigned long flag = 0;

	HIFC_CHECK(INVALID_VALUE32, NULL != hba, return);

	spin_lock_irqsave(&hba->hba_lock, flag);
	hba->active_port_speed = UNF_PORT_SPEED_UNKNOWN;
	hba->active_topo = UNF_ACT_TOP_UNKNOWN;
	hba->phy_link = UNF_PORT_LINK_DOWN;
	hba->q_set_stage = HIFC_QUEUE_SET_STAGE_INIT;
	hba->loop_map_valid = LOOP_MAP_INVALID;
	hba->delay_info.srq_delay_flag = 0;
	hba->delay_info.root_rq_rcvd_flag = 0;
	spin_unlock_irqrestore(&hba->hba_lock, flag);
}

unsigned int hifc_recv_fc_link_up(struct hifc_hba_s *v_hba, void *v_buf_in)
{
#define HIFC_LOOP_MASK     0x1
#define HIFC_LOOPMAP_COUNT 128

	unsigned int ret = UNF_RETURN_ERROR;
	struct hifc_link_event_s *buf_in = NULL;

	buf_in = (struct hifc_link_event_s *)v_buf_in;
	v_hba->phy_link = UNF_PORT_LINK_UP;
	v_hba->active_port_speed = buf_in->speed;
	v_hba->led_states.green_speed_led =
	(unsigned char)(buf_in->green_speed_led);
	v_hba->led_states.yellow_speed_led =
	(unsigned char)(buf_in->yellow_speed_led);
	v_hba->led_states.ac_led = (unsigned char)(buf_in->acled);

	if ((buf_in->top_type == HIFC_LOOP_MASK) &&
	    ((buf_in->loop_map_info[1] == UNF_FL_PORT_LOOP_ADDR) ||
	    (buf_in->loop_map_info[2] == UNF_FL_PORT_LOOP_ADDR))) {
		v_hba->active_topo = UNF_ACT_TOP_PUBLIC_LOOP; /* Public Loop */
		v_hba->active_al_pa = buf_in->alpa_value;   /* AL_PA */
		memcpy(v_hba->loop_map, buf_in->loop_map_info,
		       HIFC_LOOPMAP_COUNT);
		v_hba->loop_map_valid = LOOP_MAP_VALID;
	} else if (buf_in->top_type == HIFC_LOOP_MASK) {
		v_hba->active_topo = UNF_ACT_TOP_PRIVATE_LOOP;/* Private Loop */
		v_hba->active_al_pa = buf_in->alpa_value; /* AL_PA */
		memcpy(v_hba->loop_map, buf_in->loop_map_info,
		       HIFC_LOOPMAP_COUNT);
		v_hba->loop_map_valid = LOOP_MAP_VALID;
	} else {
		v_hba->active_topo = UNF_TOP_P2P_MASK;  /* P2P_D or P2P_F */
	}

	HIFC_TRACE(UNF_EVTLOG_LINK_INFO, UNF_LOG_EVENT, UNF_KEVENT,
		   "[event]Port(0x%x) receive link up event(0x%x) with speed(0x%x) uP_topo(0x%x) driver_topo(0x%x)",
		   v_hba->port_cfg.port_id, buf_in->link_event,
		   buf_in->speed, buf_in->top_type, v_hba->active_topo);

	/* Set clear & flush state */
	hifc_set_hba_flush_state(v_hba, UNF_FALSE);
	hifc_set_root_sq_flush_state(v_hba, UNF_FALSE);
	hifc_set_rport_flush_state(v_hba, UNF_FALSE);

	/* Report link up event to COM */
	UNF_LOWLEVEL_PORT_EVENT(ret, v_hba->lport,
				UNF_PORT_LINK_UP, &v_hba->active_port_speed);

	HIFC_LINK_EVENT_STAT(v_hba, HIFC_LINK_UP_COUNT);

	return ret;
}

unsigned int hifc_recv_fc_link_down(struct hifc_hba_s *v_hba, void *v_buf_in)
{
	unsigned int ret = UNF_RETURN_ERROR;
	struct hifc_link_event_s *buf_in = NULL;

	buf_in = (struct hifc_link_event_s *)v_buf_in;

	/* 1. Led state setting */
	v_hba->led_states.green_speed_led =
	(unsigned char)(buf_in->green_speed_led);
	v_hba->led_states.yellow_speed_led =
	(unsigned char)(buf_in->yellow_speed_led);
	v_hba->led_states.ac_led = (unsigned char)(buf_in->acled);

	HIFC_TRACE(UNF_EVTLOG_LINK_INFO, UNF_LOG_EVENT, UNF_KEVENT,
		   "[event]Port(0x%x) receive link down event(0x%x) reason(0x%x)",
		   v_hba->port_cfg.port_id, buf_in->link_event, buf_in->reason);

	hifc_initial_dynamic_info(v_hba);

	/* 2. set HBA flush state */
	hifc_set_hba_flush_state(v_hba, UNF_TRUE);

	/* 3. set Root SQ flush state */
	hifc_set_root_sq_flush_state(v_hba, UNF_TRUE);

	/* 4. set R_Port (parent SQ) flush state */
	hifc_set_rport_flush_state(v_hba, UNF_TRUE);

	/* 5. Report link down event to COM */
	UNF_LOWLEVEL_PORT_EVENT(ret, v_hba->lport, UNF_PORT_LINK_DOWN, 0);

	/* DFX setting */
	HIFC_LINK_REASON_STAT(v_hba, buf_in->reason);
	HIFC_LINK_EVENT_STAT(v_hba, HIFC_LINK_DOWN_COUNT);

	return ret;
}

unsigned int hifc_recv_fc_del_cmd(struct hifc_hba_s *v_hba, void *v_buf_in)
{
	unsigned int ret = UNF_RETURN_ERROR;
	struct hifc_link_event_s *buf_in = NULL;

	buf_in = (struct hifc_link_event_s *)v_buf_in;

	HIFC_TRACE(UNF_EVTLOG_LINK_INFO, UNF_LOG_LOGIN_ATT, UNF_KEVENT,
		   "[event]Port(0x%x) receive delete cmd event(0x%x)",
		   v_hba->port_cfg.port_id, buf_in->link_event);

	/* Send buffer clear cmnd */
	ret = hifc_clear_fetched_sq_wqe(v_hba);

	v_hba->q_set_stage = HIFC_QUEUE_SET_STAGE_SCANNING;
	HIFC_LINK_EVENT_STAT(v_hba, HIFC_FC_DELETE_CMND_COUNT);

	HIFC_REFERNCE_VAR(buf_in, buf_in, ret);
	return ret;
}

unsigned int hifc_recv_fc_error(struct hifc_hba_s *v_hba, void *v_buf_in)
{
#define FC_ERR_LEVEL_DEAD 0
#define FC_ERR_LEVEL_HIGH 1
#define FC_ERR_LEVEL_LOW  2

	unsigned int ret = UNF_RETURN_ERROR;
	struct hifc_up_error_event_s *buf_in = NULL;

	buf_in = (struct hifc_up_error_event_s *)v_buf_in;
	if (buf_in->error_type >= HIFC_UP_ERR_BUTT ||
	    buf_in->error_value >= HIFC_ERR_VALUE_BUTT) {
		HIFC_TRACE(UNF_EVTLOG_LINK_ERR, UNF_LOG_REG_ATT, UNF_ERR,
			   "Port(0x%x) receive a unsupported UP Error Event Type(0x%x) Value(0x%x).",
			   v_hba->port_cfg.port_id,
			   buf_in->error_type,
			   buf_in->error_value);
		return ret;
	}

	switch (buf_in->error_level) {
	case FC_ERR_LEVEL_DEAD:
		/* todo: chip reset */
		ret = RETURN_OK;
		break;

	case FC_ERR_LEVEL_HIGH:
		/* port reset */
		UNF_LOWLEVEL_PORT_EVENT(ret, v_hba->lport,
					UNF_PORT_ABNORMAL_RESET, NULL);
		break;

	case FC_ERR_LEVEL_LOW:
		ret = RETURN_OK;
		break;

	default:
		HIFC_TRACE(UNF_EVTLOG_LINK_ERR, UNF_LOG_REG_ATT, UNF_ERR,
			   "Port(0x%x) receive a unsupported UP Error Event Level(0x%x), Can not Process.",
			   v_hba->port_cfg.port_id, buf_in->error_level);
		return ret;
	}
	if (buf_in->error_value < HIFC_ERR_VALUE_BUTT)
		HIFC_UP_ERR_EVENT_STAT(v_hba, buf_in->error_value);

	HIFC_TRACE(UNF_EVTLOG_LINK_ERR, UNF_LOG_REG_ATT, UNF_KEVENT,
		   "[event]Port(0x%x) process UP Error Event Level(0x%x) Type(0x%x) Value(0x%x) %s.",
		   v_hba->port_cfg.port_id, buf_in->error_level,
		   buf_in->error_type, buf_in->error_value,
		   (ret == UNF_RETURN_ERROR) ? "ERROR" : "OK");

	HIFC_REFERNCE_VAR(buf_in, buf_in, ret);

	return ret;
}

unsigned int hifc_get_topo_cfg(void *v_hba, void *v_topo_cfg)
{
	struct hifc_hba_s *hba = v_hba;
	unsigned int *topo_cfg = v_topo_cfg;

	HIFC_CHECK(INVALID_VALUE32, v_hba, return UNF_RETURN_ERROR);
	HIFC_CHECK(INVALID_VALUE32, v_topo_cfg, return UNF_RETURN_ERROR);

	*topo_cfg = hba->port_topo_cfg;

	HIFC_TRACE(UNF_EVTLOG_LINK_INFO, UNF_LOG_REG_ATT, UNF_MAJOR,
		   "Get topology config: 0x%x.",
		   *topo_cfg);

	return RETURN_OK;
}

unsigned int hifc_get_topo_act(void *v_hba, void *topo_act)
{
	struct hifc_hba_s *hba = v_hba;
	enum unf_act_topo_e *ret_topo_act = topo_act;

	HIFC_CHECK(INVALID_VALUE32, hba, return UNF_RETURN_ERROR);
	HIFC_CHECK(INVALID_VALUE32, topo_act, return UNF_RETURN_ERROR);

	/* Get topo from low_level */
	*ret_topo_act = hba->active_topo;

	HIFC_TRACE(UNF_EVTLOG_LINK_INFO, UNF_LOG_REG_ATT, UNF_MAJOR,
		   "[info]Get active topology: 0x%x",
		   *ret_topo_act);

	return RETURN_OK;
}

unsigned int hifc_get_loop_alpa(void *v_hba, void *v_alpa)
{
	unsigned long flags = 0;
	struct hifc_hba_s *hba = v_hba;
	unsigned char *alpa = v_alpa;

	HIFC_CHECK(INVALID_VALUE32, hba, return UNF_RETURN_ERROR);
	HIFC_CHECK(INVALID_VALUE32, v_alpa, return UNF_RETURN_ERROR);

	spin_lock_irqsave(&hba->hba_lock, flags);
	*alpa = hba->active_al_pa;
	spin_unlock_irqrestore(&hba->hba_lock, flags);

	HIFC_TRACE(UNF_EVTLOG_LINK_INFO, UNF_LOG_REG_ATT, UNF_INFO,
		   "[info]Get active AL_PA(0x%x)", *alpa);

	return RETURN_OK;
}

unsigned int hifc_get_lport_led(void *v_hba, void *v_led_state)
{
	unsigned int ret = RETURN_OK;
	struct hifc_hba_s *hba = v_hba;
	struct hifc_led_state_s *led_state = v_led_state;

	HIFC_CHECK(INVALID_VALUE32, v_hba, return UNF_RETURN_ERROR);
	HIFC_CHECK(INVALID_VALUE32, v_led_state, return UNF_RETURN_ERROR);

	led_state->green_speed_led = hba->led_states.green_speed_led;
	led_state->yellow_speed_led = hba->led_states.yellow_speed_led;
	led_state->ac_led = hba->led_states.ac_led;

	return ret;
}

unsigned int hifc_get_hardware_version(void *v_fc_port, void *v_version)
{
	struct hifc_hba_s *fc_port = (struct hifc_hba_s *)v_fc_port;
	struct unf_version_str_s *version =
					(struct unf_version_str_s *)v_version;
	char *hard_ware_ver = NULL;

	HIFC_CHECK(INVALID_VALUE32, version, return UNF_RETURN_ERROR);
	hard_ware_ver = version->buf;
	HIFC_CHECK(INVALID_VALUE32, hard_ware_ver, return UNF_RETURN_ERROR);
	HIFC_CHECK(INVALID_VALUE32, fc_port, return UNF_RETURN_ERROR);

	hard_ware_ver[UNF_HW_VERSION_LEN - 1] = 0;

	return RETURN_OK;
}

unsigned int hifc_get_sfp_info(void *v_fc_port, void *v_sfp_info)
{
	struct unf_lport_sfp_info *sfp_info =
				(struct unf_lport_sfp_info *)v_sfp_info;
	struct hifc_hba_s *hba = (struct hifc_hba_s *)v_fc_port;
	struct hifc_inmbox_get_sfp_info_s get_sfp_info;
	union hifc_outmbox_generic_u *get_sfp_info_sts = NULL;
	unsigned int ret = UNF_RETURN_ERROR;

	HIFC_CHECK(INVALID_VALUE32, hba, return UNF_RETURN_ERROR);
	HIFC_CHECK(INVALID_VALUE32, sfp_info, return UNF_RETURN_ERROR);

	memset(&get_sfp_info, 0, sizeof(get_sfp_info));

	get_sfp_info_sts = kmalloc(sizeof(union hifc_outmbox_generic_u),
				   GFP_ATOMIC);
	if (!get_sfp_info_sts) {
		HIFC_TRACE(UNF_EVTLOG_LINK_ERR, UNF_LOG_REG_ATT, UNF_ERR, "malloc outmbox memory failed");
		return UNF_RETURN_ERROR;
	}
	memset(get_sfp_info_sts, 0, sizeof(union hifc_outmbox_generic_u));

	get_sfp_info.header.cmnd_type = HIFC_MBOX_GET_SFP_INFO;
	get_sfp_info.header.length =
	HIFC_BYTES_TO_DW_NUM(sizeof(struct hifc_inmbox_get_sfp_info_s));
	get_sfp_info.header.port_id = (hba->port_index);

	/* send mailbox and handle the return sts */
	if (hifc_mb_send_and_wait_mbox(hba, &get_sfp_info, sizeof(get_sfp_info),
				       get_sfp_info_sts) != RETURN_OK) {
		HIFC_TRACE(UNF_EVTLOG_LINK_WARN, UNF_LOG_REG_ATT, UNF_WARN,
			   "Port(0x%x) HIFC can't send and wait mailbox, command type: 0x%x.",
			   hba->port_cfg.port_id,
			   get_sfp_info.header.cmnd_type);

		goto exit;
	}

	sfp_info->status = get_sfp_info_sts->get_sfp_info_sts.status;
	if (get_sfp_info_sts->get_sfp_info_sts.status != STATUS_OK) {
		HIFC_TRACE(UNF_EVTLOG_LINK_WARN, UNF_LOG_LOGIN_ATT, UNF_WARN,
			   "Port(0x%x) Receive mailbox type(0x%x) status incorrect. Status: 0x%x.",
			   hba->port_cfg.port_id,
			   get_sfp_info_sts->get_sfp_info_sts.header.cmnd_type,
			   get_sfp_info_sts->get_sfp_info_sts.status);

		goto exit;
	}

	if (get_sfp_info_sts->get_sfp_info_sts.header.cmnd_type !=
	HIFC_MBOX_GET_SFP_INFO_STS) {
		HIFC_TRACE(UNF_EVTLOG_LINK_INFO, UNF_LOG_REG_ATT, UNF_INFO,
			   "Port(0x%x) Receive mailbox type incorrect. Type: 0x%x.",
			   hba->port_cfg.port_id,
			   get_sfp_info_sts->get_sfp_info_sts.header.cmnd_type);

		goto exit;
	}

	/* the real sfpinfo is beyond the header of sts */
	memcpy(&sfp_info->sfp_eeprom_info,
	       ((unsigned char *)get_sfp_info_sts +
	       sizeof(get_sfp_info_sts->get_sfp_info_sts)),
	       sizeof(union unf_sfp_eeprome_info));

	ret = RETURN_OK;
exit:
	kfree(get_sfp_info_sts);
	return ret;
}

unsigned int hifc_get_port_info(void *v_hba)
{
	unsigned long flags = 0;
	struct hifc_inmbox_get_port_info_s get_port_info;
	union hifc_outmbox_generic_u *port_info_sts = NULL;
	struct hifc_hba_s *hba = (struct hifc_hba_s *)v_hba;
	unsigned int ret = UNF_RETURN_ERROR;

	memset(&get_port_info, 0, sizeof(get_port_info));
	port_info_sts = kmalloc(sizeof(union hifc_outmbox_generic_u),
				GFP_ATOMIC);
	if (!port_info_sts) {
		HIFC_TRACE(UNF_EVTLOG_LINK_ERR, UNF_LOG_REG_ATT, UNF_ERR, "malloc outmbox memory failed");
		return UNF_RETURN_ERROR;
	}
	memset(port_info_sts, 0, sizeof(union hifc_outmbox_generic_u));

	get_port_info.header.cmnd_type = HIFC_MBOX_GET_PORT_INFO;
	get_port_info.header.length =
	HIFC_BYTES_TO_DW_NUM(sizeof(struct hifc_inmbox_get_port_info_s));
	get_port_info.header.port_id = hba->port_index;

	if (hifc_mb_send_and_wait_mbox(hba, &get_port_info,
				       sizeof(get_port_info), port_info_sts) !=
				       RETURN_OK) {
		HIFC_TRACE(UNF_EVTLOG_LINK_WARN, UNF_LOG_REG_ATT, UNF_WARN,
			   "Port(0x%x) send and wait mailbox type(0x%x) failed.",
			   hba->port_cfg.port_id,
			   get_port_info.header.cmnd_type);

		goto exit;
	}

	if ((port_info_sts->get_port_info_sts.status != STATUS_OK) ||
	    (port_info_sts->get_port_info_sts.header.cmnd_type !=
	    HIFC_MBOX_GET_PORT_INFO_STS)) {
		HIFC_TRACE(UNF_EVTLOG_LINK_WARN, UNF_LOG_REG_ATT, UNF_WARN,
			   "Port(0x%x) receive mailbox type(0x%x) status(0x%x) error.",
			   hba->port_cfg.port_id,
			   port_info_sts->get_port_info_sts.header.cmnd_type,
			   port_info_sts->get_port_info_sts.status);

		goto exit;
	}

	spin_lock_irqsave(&hba->hba_lock, flags);
	hba->active_bb_scn = port_info_sts->get_port_info_sts.bbscn;
	hba->active_rx_bb_credit =
	port_info_sts->get_port_info_sts.non_loop_rx_credit;
	spin_unlock_irqrestore(&hba->hba_lock, flags);

	ret = RETURN_OK;
exit:
	kfree(port_info_sts);
	return ret;
}

unsigned int hifc_get_port_current_info(void *v_hba, void *port_info)
{
	struct hifc_hba_s *hba = NULL;
	struct hifc_inmbox_get_port_info_s get_port_info;
	union hifc_outmbox_generic_u *port_info_sts = NULL;
	struct unf_get_port_info_argout *current_port_info = NULL;
	unsigned int ret = UNF_RETURN_ERROR;

	HIFC_CHECK(INVALID_VALUE32, port_info, return UNF_RETURN_ERROR);
	HIFC_CHECK(INVALID_VALUE32, v_hba, return UNF_RETURN_ERROR);

	hba = (struct hifc_hba_s *)v_hba;
	current_port_info = (struct unf_get_port_info_argout *)port_info;

	memset(&get_port_info, 0, sizeof(get_port_info));
	port_info_sts = kmalloc(sizeof(union hifc_outmbox_generic_u),
				GFP_ATOMIC);
	if (!port_info_sts) {
		HIFC_TRACE(UNF_EVTLOG_LINK_ERR, UNF_LOG_REG_ATT, UNF_ERR, "malloc outmbox memory failed");
		return UNF_RETURN_ERROR;
	}
	memset(port_info_sts, 0, sizeof(union hifc_outmbox_generic_u));

	get_port_info.header.cmnd_type = HIFC_MBOX_GET_PORT_INFO;
	get_port_info.header.length =
	HIFC_BYTES_TO_DW_NUM(sizeof(struct hifc_inmbox_get_port_info_s));
	get_port_info.header.port_id = hba->port_index;

	if (hifc_mb_send_and_wait_mbox(hba, &get_port_info,
				       sizeof(get_port_info),
				       port_info_sts) != RETURN_OK) {
		HIFC_TRACE(UNF_EVTLOG_LINK_WARN, UNF_LOG_REG_ATT, UNF_WARN,
			   "[warn]Port(0x%x) send and wait mailbox type(0x%x) failed",
			   hba->port_cfg.port_id,
			   get_port_info.header.cmnd_type);

		goto exit;
	}

	if ((port_info_sts->get_port_info_sts.status != STATUS_OK) ||
	    (port_info_sts->get_port_info_sts.header.cmnd_type !=
	    HIFC_MBOX_GET_PORT_INFO_STS)) {
		HIFC_TRACE(UNF_EVTLOG_LINK_WARN, UNF_LOG_REG_ATT, UNF_WARN,
			   "Port(0x%x) receive mailbox type(0x%x) status(0x%x) error.",
			   hba->port_cfg.port_id,
			   port_info_sts->get_port_info_sts.header.cmnd_type,
			   port_info_sts->get_port_info_sts.status);

		goto exit;
	}

	current_port_info->sfp_speed =
	(unsigned char)port_info_sts->get_port_info_sts.sfp_speed;
	current_port_info->present =
	(unsigned char)port_info_sts->get_port_info_sts.present;

	ret = RETURN_OK;
exit:
	kfree(port_info_sts);
	return ret;
}

static void hifc_get_fabric_login_params(
				struct hifc_hba_s *hba,
				struct unf_port_login_parms_s *v_param_addr)
{
	unsigned long flag = 0;

	spin_lock_irqsave(&hba->hba_lock, flag);
	hba->active_topo = v_param_addr->en_act_topo;
	hba->compared_ratov_val = v_param_addr->compared_ratov_val;
	hba->compared_edtov_val = v_param_addr->compared_edtov_val;
	hba->compared_bbscn = v_param_addr->compared_bbscn;
	hba->remote_edtov_tag = v_param_addr->remote_edtov_tag;
	hba->remote_rttov_tag = v_param_addr->remote_rttov_tag;
	hba->remote_bbcredit = v_param_addr->remote_bbcredit;
	spin_unlock_irqrestore(&hba->hba_lock, flag);

	HIFC_TRACE(UNF_EVTLOG_LINK_INFO, UNF_LOG_LOGIN_ATT, UNF_INFO,
		   "[info]Port(0x%x) topo(0x%x) get fabric params: R_A_TOV(0x%x) E_D_TOV(%u) BB_CREDIT(0x%x) BB_SC_N(0x%x)",
		   hba->port_cfg.port_id, hba->active_topo,
		   hba->compared_ratov_val, hba->compared_edtov_val,
		   hba->remote_bbcredit, hba->compared_bbscn);
}

static void hifc_get_port_login_params(
				struct hifc_hba_s *hba,
				struct unf_port_login_parms_s *v_param_addr)
{
	unsigned long flag = 0;

	spin_lock_irqsave(&hba->hba_lock, flag);
	hba->compared_ratov_val = v_param_addr->compared_ratov_val;
	hba->compared_edtov_val = v_param_addr->compared_edtov_val;
	hba->compared_bbscn = v_param_addr->compared_bbscn;
	hba->remote_edtov_tag = v_param_addr->remote_edtov_tag;
	hba->remote_rttov_tag = v_param_addr->remote_rttov_tag;
	hba->remote_bbcredit = v_param_addr->remote_bbcredit;
	spin_unlock_irqrestore(&hba->hba_lock, flag);

	HIFC_TRACE(UNF_EVTLOG_LINK_INFO, UNF_LOG_LOGIN_ATT, UNF_MAJOR,
		   "Port(0x%x) Topo(0x%x) Get Port Params: R_A_TOV(0x%x), E_D_TOV(0x%x), BB_CREDIT(0x%x), BB_SC_N(0x%x).",
		   hba->port_cfg.port_id, hba->active_topo,
		   hba->compared_ratov_val, hba->compared_edtov_val,
		   hba->remote_bbcredit, hba->compared_bbscn);
}

unsigned int hifc_update_fabric_param(void *v_hba, void *v_para_in)
{
	unsigned int ret = RETURN_OK;
	struct hifc_hba_s *hba = v_hba;
	struct unf_port_login_parms_s *login_coparms = v_para_in;

	UNF_CHECK_VALID(0x4923, UNF_B_TRUE, hba, return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(0x4924, UNF_B_TRUE, v_para_in, return UNF_RETURN_ERROR);

	hifc_get_fabric_login_params(hba, login_coparms);

	if ((hba->active_topo == UNF_ACT_TOP_P2P_FABRIC) ||
	    (hba->active_topo == UNF_ACT_TOP_PUBLIC_LOOP)) {
		if (hba->work_mode == HIFC_SMARTIO_WORK_MODE_FC)
			ret = hifc_config_login_api(hba, login_coparms);
	}

	return ret;
}

unsigned int hifc_update_port_param(void *v_hba, void *v_para_in)
{
	unsigned int ret = RETURN_OK;
	struct hifc_hba_s *hba = v_hba;
	struct unf_port_login_parms_s *login_coparms =
	(struct unf_port_login_parms_s *)v_para_in;

	UNF_CHECK_VALID(0x4923, UNF_B_TRUE, hba, return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(0x4924, UNF_B_TRUE, v_para_in, return UNF_RETURN_ERROR);

	if ((hba->active_topo == UNF_ACT_TOP_PRIVATE_LOOP) ||
	    (hba->active_topo == UNF_ACT_TOP_P2P_DIRECT)) {
		hifc_get_port_login_params(hba, login_coparms);
		ret = hifc_config_login_api(hba, login_coparms);
	}

	hifc_save_login_para_in_sq_info(hba, login_coparms);

	return ret;
}

unsigned int hifc_clear_port_error_code(void *v_hba, void *v_err_code)
{
	return RETURN_OK;
}

unsigned int hifc_get_and_clear_port_error_code(void *v_hba, void *v_err_code)
{
	struct hifc_hba_s *hba = (struct hifc_hba_s *)v_hba;
	struct hifc_inmbox_get_err_code_s get_err_code;
	union hifc_outmbox_generic_u *err_code_sts = NULL;
	struct unf_err_code_s *unf_err_code =
					(struct unf_err_code_s *)v_err_code;
	unsigned int ret = UNF_RETURN_ERROR;

	HIFC_CHECK(INVALID_VALUE32, hba, return UNF_RETURN_ERROR);
	HIFC_CHECK(INVALID_VALUE32, unf_err_code, return UNF_RETURN_ERROR);

	memset(&get_err_code, 0, sizeof(get_err_code));

	err_code_sts = kmalloc(sizeof(union hifc_outmbox_generic_u),
			       GFP_ATOMIC);
	if (!err_code_sts) {
		HIFC_TRACE(UNF_EVTLOG_LINK_ERR, UNF_LOG_REG_ATT, UNF_ERR, "malloc outmbox memory failed");
		return UNF_RETURN_ERROR;
	}
	memset(err_code_sts, 0, sizeof(union hifc_outmbox_generic_u));

	get_err_code.header.cmnd_type = HIFC_MBOX_GET_ERR_CODE;
	get_err_code.header.length =
	HIFC_BYTES_TO_DW_NUM(sizeof(struct hifc_inmbox_get_err_code_s));

	if (hifc_mb_send_and_wait_mbox(hba, &get_err_code, sizeof(get_err_code),
				       err_code_sts) != RETURN_OK) {
		HIFC_TRACE(UNF_EVTLOG_LINK_INFO, UNF_LOG_REG_ATT, UNF_INFO,
			   "Port(0x%x) HIFC can't send and wait mailbox, command type: 0x%x.",
			   hba->port_cfg.port_id,
			   get_err_code.header.cmnd_type);

		goto exit;
	}

	if (err_code_sts->get_err_code_sts.status != STATUS_OK) {
		HIFC_TRACE(UNF_EVTLOG_LINK_INFO, UNF_LOG_REG_ATT, UNF_INFO,
			   "Port(0x%x) Receive mailbox type(0x%x) status incorrect, status: 0x%x.",
			   hba->port_cfg.port_id,
			   err_code_sts->get_err_code_sts.header.cmnd_type,
			   err_code_sts->get_err_code_sts.status);

		goto exit;
	}

	unf_err_code->link_fail_count =
		err_code_sts->get_err_code_sts.err_code[0];
	unf_err_code->loss_of_sync_count =
		err_code_sts->get_err_code_sts.err_code[1];
	unf_err_code->loss_of_signal_count =
		err_code_sts->get_err_code_sts.err_code[2];
	unf_err_code->proto_error_count =
		err_code_sts->get_err_code_sts.err_code[3];
	unf_err_code->bad_rx_char_count =
		err_code_sts->get_err_code_sts.err_code[4];
	unf_err_code->bad_crc_count =
		err_code_sts->get_err_code_sts.err_code[5];
	unf_err_code->rx_eo_fa_count =
		err_code_sts->get_err_code_sts.err_code[6];
	unf_err_code->dis_frame_count =
		err_code_sts->get_err_code_sts.err_code[7];

	ret = RETURN_OK;
exit:
	kfree(err_code_sts);
	return ret;
}

unsigned int hifc_get_work_bale_bbcredit(void *v_hba, void *v_bbcredit)
{
	unsigned int *bb_credit = (unsigned int *)v_bbcredit;
	struct hifc_hba_s *hba = v_hba;

	HIFC_CHECK(INVALID_VALUE32, hba, return UNF_RETURN_ERROR);
	HIFC_CHECK(INVALID_VALUE32, v_bbcredit, return UNF_RETURN_ERROR);

	if (hba->active_port_speed == UNF_PORT_SPEED_32_G)
		*bb_credit = HIFC_LOWLEVEL_DEFAULT_32G_BB_CREDIT;
	else if (hba->active_port_speed == UNF_PORT_SPEED_16_G)
		*bb_credit = HIFC_LOWLEVEL_DEFAULT_16G_BB_CREDIT;
	else
		*bb_credit = HIFC_LOWLEVEL_DEFAULT_842G_BB_CREDIT;

	return RETURN_OK;
}

unsigned int hifc_get_work_bale_bbscn(void *v_hba, void *v_bbscn)
{
	unsigned int *bbscn = (unsigned int *)v_bbscn;
	struct hifc_hba_s *hba = (struct hifc_hba_s *)v_hba;

	HIFC_CHECK(INVALID_VALUE32, v_hba, return UNF_RETURN_ERROR);
	HIFC_CHECK(INVALID_VALUE32, v_bbscn, return UNF_RETURN_ERROR);

	*bbscn = hba->port_bbscn_cfg;

	HIFC_TRACE(UNF_EVTLOG_LINK_INFO, UNF_LOG_REG_ATT, UNF_INFO, "Return BBSCN(0x%x) to CM",
		   *bbscn);

	return RETURN_OK;
}

unsigned int hifc_get_software_version(void *v_hba, void *v_version)
{
	struct hifc_hba_s *hba = (struct hifc_hba_s *)v_hba;
	struct hifc_inmbox_get_fw_version_s fw_ver;
	union hifc_outmbox_generic_u *fw_ver_sts = NULL;
	unsigned char *ver = NULL;
	unsigned int ret = UNF_RETURN_ERROR;

	HIFC_CHECK(INVALID_VALUE32, v_version, return UNF_RETURN_ERROR);
	HIFC_CHECK(INVALID_VALUE32, hba, return UNF_RETURN_ERROR);

	memset(&fw_ver, 0, sizeof(fw_ver));
	fw_ver_sts = kmalloc(sizeof(union hifc_outmbox_generic_u), GFP_ATOMIC);
	if (!fw_ver_sts) {
		HIFC_TRACE(UNF_EVTLOG_LINK_ERR, UNF_LOG_REG_ATT, UNF_ERR, "malloc outmbox memory failed");
		return UNF_RETURN_ERROR;
	}
	memset(fw_ver_sts, 0, sizeof(union hifc_outmbox_generic_u));
	ver = (unsigned char *)&fw_ver_sts->get_fw_ver_sts;

	fw_ver.header.cmnd_type = HIFC_MBOX_GET_FW_VERSION;
	fw_ver.header.length =
	HIFC_BYTES_TO_DW_NUM(sizeof(struct hifc_inmbox_get_fw_version_s));

	if (hifc_mb_send_and_wait_mbox(hba, &fw_ver, sizeof(fw_ver),
				       fw_ver_sts) != RETURN_OK) {
		HIFC_TRACE(UNF_EVTLOG_LINK_ERR, UNF_LOG_REG_ATT, UNF_ERR,
			   "Port(0x%x) can't send and wait mailbox, command type: 0x%x.",
			   hba->port_cfg.port_id,
			   fw_ver.header.cmnd_type);

		goto exit;
	}

	if (fw_ver_sts->get_fw_ver_sts.header.cmnd_type !=
	    HIFC_MBOX_GET_FW_VERSION_STS) {
		HIFC_TRACE(UNF_EVTLOG_LINK_ERR, UNF_LOG_EQUIP_ATT, UNF_ERR,
			   "Port(0x%x) recv mailbox type(0x%x) incorrect.",
			   hba->port_cfg.port_id,
			   fw_ver_sts->get_fw_ver_sts.header.cmnd_type);

		goto exit;
	}

	if (fw_ver_sts->get_fw_ver_sts.status != RETURN_OK) {
		HIFC_TRACE(UNF_EVTLOG_LINK_ERR, UNF_LOG_EQUIP_ATT, UNF_ERR,
			   "Port(0x%x) Receive mailbox type(0x%x) status(0x%x) incorrect.",
			   hba->port_cfg.port_id,
			   fw_ver_sts->get_fw_ver_sts.header.cmnd_type,
			   fw_ver_sts->get_fw_ver_sts.status);

		goto exit;
	}

	memcpy(v_version, ver + HIFC_VER_ADDR_OFFSET,
	       sizeof(struct hifc_outmbox_get_fw_version_sts_s) -
	       HIFC_VER_ADDR_OFFSET);

	ret = RETURN_OK;
exit:
	kfree(fw_ver_sts);
	return ret;
}

unsigned int hifc_get_firmware_version(void *v_fc_port, void *v_version)
{
	struct hifc_hba_s *fc_port = (struct hifc_hba_s *)v_fc_port;
	struct unf_version_str_s *version =
				(struct unf_version_str_s *)v_version;
	char *fw_ver = NULL;

	HIFC_CHECK(INVALID_VALUE32, version, return UNF_RETURN_ERROR);
	fw_ver = version->buf;
	HIFC_CHECK(INVALID_VALUE32, fw_ver, return UNF_RETURN_ERROR);
	HIFC_CHECK(INVALID_VALUE32, fc_port, return UNF_RETURN_ERROR);

	fw_ver[UNF_FW_VERSION_LEN - 1] = 0;

	return RETURN_OK;
}

unsigned int hifc_get_loop_map(void *v_hba, void *v_buf)
{
	unsigned long flags = 0;
	struct unf_buf_s *buf = (struct unf_buf_s *)v_buf;
	struct hifc_hba_s *hba = v_hba;

	HIFC_CHECK(INVALID_VALUE32, hba, return UNF_RETURN_ERROR);
	HIFC_CHECK(INVALID_VALUE32, buf, return UNF_RETURN_ERROR);
	HIFC_CHECK(INVALID_VALUE32, buf->cbuf, return UNF_RETURN_ERROR);
	HIFC_CHECK(INVALID_VALUE32, buf->buf_len, return UNF_RETURN_ERROR);

	if (buf->buf_len > UNF_LOOPMAP_COUNT)
		return UNF_RETURN_ERROR;

	spin_lock_irqsave(&hba->hba_lock, flags);
	if (hba->loop_map_valid != LOOP_MAP_VALID) {
		spin_unlock_irqrestore(&hba->hba_lock, flags);
		return UNF_RETURN_ERROR;
	}
	memcpy(buf->cbuf, hba->loop_map, buf->buf_len);  /* do memcpy */
	spin_unlock_irqrestore(&hba->hba_lock, flags);

	return RETURN_OK;
}

unsigned int hifc_get_speed_cfg(void *v_hba, void *v_speed_cfg)
{
	struct hifc_hba_s *hba = v_hba;
	unsigned int *speed_cfg = v_speed_cfg;

	HIFC_CHECK(INVALID_VALUE32, hba, return UNF_RETURN_ERROR);
	HIFC_CHECK(INVALID_VALUE32, v_speed_cfg, return UNF_RETURN_ERROR);

	*speed_cfg = hba->port_speed_cfg;

	HIFC_TRACE(UNF_EVTLOG_LINK_INFO, UNF_LOG_REG_ATT, UNF_INFO,
		   "Get config link rate: 0x%x.",
		   *speed_cfg);

	return RETURN_OK;
}

unsigned int hifc_get_speed_act(void *v_hba, void *v_speed_act)
{
	struct hifc_hba_s *hba = v_hba;
	unsigned int *speed_act = v_speed_act;

	HIFC_CHECK(INVALID_VALUE32, hba, return UNF_RETURN_ERROR);
	HIFC_CHECK(INVALID_VALUE32, v_speed_act, return UNF_RETURN_ERROR);

	*speed_act = hba->active_port_speed;

	HIFC_TRACE(UNF_EVTLOG_LINK_INFO, UNF_LOG_REG_ATT, UNF_MAJOR,
		   "Get config link rate: 0x%x.",
		   *speed_act);
	return RETURN_OK;
}

unsigned int hifc_get_port_fec(void *v_hba, void *v_para_out)
{
	struct hifc_hba_s *hba = v_hba;
	int *fec = v_para_out;

	HIFC_CHECK(INVALID_VALUE32, hba, return UNF_RETURN_ERROR);
	HIFC_CHECK(INVALID_VALUE32, fec, return UNF_RETURN_ERROR);

	*fec = (hba->fec_status) ? UNF_TRUE : UNF_FALSE;

	HIFC_TRACE(UNF_EVTLOG_LINK_INFO, UNF_LOG_REG_ATT, UNF_MAJOR,
		   "Get Port fec: 0x%x.",
		   (hba->fec_status));
	return RETURN_OK;
}

unsigned int hifc_save_hba_info(void *v_hba, void *v_para_in)
{
	struct hifc_inmbox_save_hba_info_s *hba_info = NULL;
	struct hifc_outmbox_save_hba_info_sts_s *hba_info_sts = NULL;
	void *hba_info_addr = v_para_in;
	struct hifc_hba_s *hba = v_hba;

	HIFC_CHECK(INVALID_VALUE32, v_hba, return UNF_RETURN_ERROR);
	HIFC_CHECK(INVALID_VALUE32, v_para_in, return UNF_RETURN_ERROR);

	hba_info = vmalloc(sizeof(struct hifc_inmbox_save_hba_info_s));

	if (!hba_info)
		return UNF_RETURN_ERROR;

	hba_info_sts = vmalloc(sizeof(struct hifc_outmbox_save_hba_info_sts_s));

	if (!hba_info_sts) {
		vfree(hba_info);
		return UNF_RETURN_ERROR;
	}

	memset(hba_info, 0, sizeof(struct hifc_inmbox_save_hba_info_s));
	memset(hba_info_sts, 0,
	       sizeof(struct hifc_outmbox_save_hba_info_sts_s));

	hba_info->header.cmnd_type = HIFC_MBOX_SAVE_HBA_INFO;
	hba_info->header.length =
	HIFC_BYTES_TO_DW_NUM(sizeof(struct hifc_inmbox_save_hba_info_s));

	/* fill mailbox payload */
	memcpy(&hba_info->hba_save_info[0], hba_info_addr, SAVE_PORT_INFO_LEN);

	/* send & wait mailbox */
	if (hifc_mb_send_and_wait_mbox(
				hba, hba_info,
				sizeof(*hba_info),
				(union hifc_outmbox_generic_u *)hba_info_sts)
				!= RETURN_OK) {
		HIFC_TRACE(UNF_EVTLOG_LINK_ERR, UNF_LOG_REG_ATT, UNF_ERR,
			   "[warn]Port(0x%x) HIFC can't send and wait mailbox, command type(0x%x)",
			   hba->port_cfg.port_id,
			   hba_info->header.cmnd_type);

		vfree(hba_info);
		vfree(hba_info_sts);

		return UNF_RETURN_ERROR;
	}

	/* check mailbox rsp status */
	if (hba_info_sts->status != RETURN_OK) {
		HIFC_TRACE(UNF_EVTLOG_LINK_ERR, UNF_LOG_EQUIP_ATT, UNF_ERR,
			   "[err]Port(0x%x) receive mailbox type(0x%x) status(0x%x) error",
			   hba->port_cfg.port_id,
			   hba_info_sts->header.cmnd_type,
			   hba_info_sts->status);

		vfree(hba_info);
		vfree(hba_info_sts);

		return UNF_RETURN_ERROR;
	}

	/* check mailbox rsp type */
	if (hba_info_sts->header.cmnd_type != HIFC_MBOX_SAVE_HBA_INFO_STS) {
		HIFC_TRACE(UNF_EVTLOG_LINK_ERR, UNF_LOG_EQUIP_ATT, UNF_ERR,
			   "[err]Port(0x%x) receive mailbox type(0x%x) error",
			   hba->port_cfg.port_id,
			   hba_info_sts->header.cmnd_type);

		vfree(hba_info);
		vfree(hba_info_sts);

		return UNF_RETURN_ERROR;
	}

	memcpy(hba_info_addr, &hba_info_sts->save_hba_info[0],
	       SAVE_PORT_INFO_LEN - 8);

	HIFC_TRACE(UNF_EVTLOG_LINK_INFO, UNF_LOG_EQUIP_ATT, UNF_MAJOR,
		   "[event]Port(0x%x) save hba info succeed",
		   hba->port_cfg.port_id);

	vfree(hba_info);
	vfree(hba_info_sts);

	return RETURN_OK;
}

unsigned int hifc_mbox_reset_chip(struct hifc_hba_s *v_hba,
				  unsigned char v_sub_type)
{
	struct hifc_inmbox_port_reset_s port_reset;
	union hifc_outmbox_generic_u *port_reset_sts = NULL;
	unsigned int ret = UNF_RETURN_ERROR;

	HIFC_CHECK(INVALID_VALUE32, v_hba, return UNF_RETURN_ERROR);

	memset(&port_reset, 0, sizeof(port_reset));

	port_reset_sts = kmalloc(sizeof(union hifc_outmbox_generic_u),
				 GFP_ATOMIC);
	if (!port_reset_sts) {
		HIFC_TRACE(UNF_EVTLOG_LINK_ERR, UNF_LOG_REG_ATT, UNF_ERR, "malloc outmbox memory failed");
		return UNF_RETURN_ERROR;
	}
	memset(port_reset_sts, 0, sizeof(union hifc_outmbox_generic_u));
	port_reset.header.cmnd_type = HIFC_MBOX_PORT_RESET;
	port_reset.header.length =
	HIFC_BYTES_TO_DW_NUM(sizeof(struct hifc_inmbox_port_reset_s));
	port_reset.op_code = v_sub_type;

	if (hifc_mb_send_and_wait_mbox(v_hba, &port_reset, sizeof(port_reset),
				       port_reset_sts) != RETURN_OK) {
		HIFC_TRACE(UNF_EVTLOG_LINK_ERR, UNF_LOG_REG_ATT, UNF_ERR,
			   "[warn]Port(0x%x) can't send and wait mailbox with command type(0x%x)",
			   v_hba->port_cfg.port_id,
			   port_reset.header.cmnd_type);

		goto exit;
	}

	if (port_reset_sts->port_reset_sts.status != RETURN_OK) {
		HIFC_TRACE(UNF_EVTLOG_LINK_ERR, UNF_LOG_EQUIP_ATT, UNF_ERR,
			   "[warn]Port(0x%x) receive mailbox type(0x%x) status(0x%x) incorrect",
			   v_hba->port_cfg.port_id,
			   port_reset_sts->port_reset_sts.header.cmnd_type,
			   port_reset_sts->port_reset_sts.status);

		goto exit;
	}

	if (port_reset_sts->port_reset_sts.header.cmnd_type !=
	    HIFC_MBOX_PORT_RESET_STS) {
		HIFC_TRACE(UNF_EVTLOG_LINK_ERR, UNF_LOG_EQUIP_ATT, UNF_ERR,
			   "[warn]Port(0x%x) recv mailbox type(0x%x) incorrect",
			   v_hba->port_cfg.port_id,
			   port_reset_sts->port_reset_sts.header.cmnd_type);

		goto exit;
	}

	HIFC_TRACE(UNF_EVTLOG_LINK_INFO, UNF_LOG_EQUIP_ATT, UNF_MAJOR,
		   "[info]Port(0x%x) reset chip mailbox success",
		   v_hba->port_cfg.port_id);

	ret = RETURN_OK;
exit:
	kfree(port_reset_sts);
	return ret;
}

unsigned int hifc_clear_sq_wqe_done(struct hifc_hba_s *v_hba)
{
	int async_ret = RETURN_OK;
	struct hifc_inmbx_clear_node_s clear_done;

	clear_done.header.cmnd_type = HIFC_MBOX_BUFFER_CLEAR_DONE;
	clear_done.header.length =
	HIFC_BYTES_TO_DW_NUM(sizeof(struct hifc_inmbx_clear_node_s));
	clear_done.header.port_id = v_hba->port_index;

	async_ret = hifc_msg_to_mgmt_async(v_hba->hw_dev_handle,
					   HIFC_MOD_FC,
					   HIFC_MBOX_BUFFER_CLEAR_DONE,
					   &clear_done, sizeof(clear_done));

	if (async_ret != 0) {
		HIFC_MAILBOX_STAT(v_hba, HIFC_SEND_CLEAR_DONE_FAIL);
		HIFC_TRACE(UNF_EVTLOG_LINK_ERR, UNF_LOG_REG_ATT, UNF_ERR,
			   "[err]HIFC Port(0x%x) can't send clear done cmd to up, ret:%d",
			   v_hba->port_cfg.port_id, async_ret);

		return UNF_RETURN_ERROR;
	}

	HIFC_MAILBOX_STAT(v_hba, HIFC_SEND_CLEAR_DONE);
	v_hba->q_set_stage = HIFC_QUEUE_SET_STAGE_FLUSHDONE;
	v_hba->next_clearing_sq = 0;

	HIFC_TRACE(UNF_EVTLOG_LINK_INFO, UNF_LOG_EVENT, UNF_KEVENT,
		   "[info]Port(0x%x) clear done msg(0x%x) sent to up succeed with stage(0x%x)",
		   v_hba->port_cfg.port_id,
		   clear_done.header.cmnd_type, v_hba->q_set_stage);

	return RETURN_OK;
}

unsigned int hifc_mbx_get_fw_clear_stat(struct hifc_hba_s *v_hba,
					unsigned int *v_clear_state)
{
	struct hifc_inmbox_get_clear_state_s clr_state;
	union hifc_outmbox_generic_u *port_clr_state_sts = NULL;
	unsigned int ret = UNF_RETURN_ERROR;

	HIFC_CHECK(INVALID_VALUE32, v_hba, return UNF_RETURN_ERROR);
	HIFC_CHECK(INVALID_VALUE32, v_clear_state, return UNF_RETURN_ERROR);

	memset(&clr_state, 0, sizeof(clr_state));

	port_clr_state_sts = kmalloc(sizeof(union hifc_outmbox_generic_u),
				     GFP_ATOMIC);
	if (!port_clr_state_sts) {
		HIFC_TRACE(UNF_EVTLOG_LINK_ERR, UNF_LOG_REG_ATT, UNF_ERR, "malloc outmbox memory failed");
		return UNF_RETURN_ERROR;
	}
	memset(port_clr_state_sts, 0, sizeof(union hifc_outmbox_generic_u));

	clr_state.header.cmnd_type = HIFC_MBOX_GET_CLEAR_STATE;
	clr_state.header.length =
	HIFC_BYTES_TO_DW_NUM(sizeof(struct hifc_inmbox_get_clear_state_s));

	if (hifc_mb_send_and_wait_mbox(v_hba, &clr_state, sizeof(clr_state),
				       port_clr_state_sts) != RETURN_OK) {
		HIFC_TRACE(UNF_EVTLOG_LINK_ERR, UNF_LOG_REG_ATT, UNF_ERR,
			   "hifc can't send and wait mailbox, command type: 0x%x",
			   clr_state.header.cmnd_type);

		goto exit;
	}

	if (port_clr_state_sts->get_clr_state_sts.status != RETURN_OK) {
		HIFC_TRACE(
			UNF_EVTLOG_LINK_ERR, UNF_LOG_EQUIP_ATT, UNF_ERR,
			"Port(0x%x) Receive mailbox type(0x%x) status incorrect. Status: 0x%x, state 0x%x.",
			v_hba->port_cfg.port_id,
			port_clr_state_sts->get_clr_state_sts.header.cmnd_type,
			port_clr_state_sts->get_clr_state_sts.status,
			port_clr_state_sts->get_clr_state_sts.state);

		goto exit;
	}

	if (port_clr_state_sts->get_clr_state_sts.header.cmnd_type !=
	    HIFC_MBOX_GET_CLEAR_STATE_STS) {
		HIFC_TRACE(
			UNF_EVTLOG_LINK_ERR, UNF_LOG_EQUIP_ATT, UNF_ERR,
			"Port(0x%x) recv mailbox type(0x%x) incorrect.",
			v_hba->port_cfg.port_id,
			port_clr_state_sts->get_clr_state_sts.header.cmnd_type);

		goto exit;
	}

	HIFC_TRACE(UNF_EVTLOG_LINK_INFO, UNF_LOG_EVENT, UNF_MAJOR,
		   "Port(0x%x) get port clear state 0x%x.",
		   v_hba->port_cfg.port_id,
		   port_clr_state_sts->get_clr_state_sts.state);

	*v_clear_state = port_clr_state_sts->get_clr_state_sts.state;

	ret = RETURN_OK;
exit:
	kfree(port_clr_state_sts);
	return ret;
}

unsigned int hifc_mbx_set_fec(struct hifc_hba_s *v_hba,
			      unsigned int v_fec_opcode)
{
	struct hifc_inmbox_config_fec_s cfg_fec;
	union hifc_outmbox_generic_u *port_fec_state_sts = NULL;
	unsigned char op_code = 0;
	unsigned int ret = UNF_RETURN_ERROR;

	HIFC_CHECK(INVALID_VALUE32, v_hba, return UNF_RETURN_ERROR);

	memset(&cfg_fec, 0, sizeof(cfg_fec));

	port_fec_state_sts = kmalloc(sizeof(union hifc_outmbox_generic_u),
				     GFP_ATOMIC);
	if (!port_fec_state_sts) {
		HIFC_TRACE(UNF_EVTLOG_LINK_ERR, UNF_LOG_REG_ATT, UNF_ERR, "malloc outmbox memory failed");
		return UNF_RETURN_ERROR;
	}
	memset(port_fec_state_sts, 0, sizeof(union hifc_outmbox_generic_u));

	op_code = (unsigned char)v_fec_opcode;

	cfg_fec.header.cmnd_type = HIFC_MBOX_CONFIG_FEC;
	cfg_fec.header.length =
	HIFC_BYTES_TO_DW_NUM(sizeof(HIFC_MBOX_CONFIG_FEC));
	cfg_fec.fec_op_code = op_code;

	if (hifc_mb_send_and_wait_mbox(v_hba, &cfg_fec, sizeof(cfg_fec),
				       port_fec_state_sts) != RETURN_OK) {
		HIFC_TRACE(UNF_EVTLOG_LINK_ERR, UNF_LOG_REG_ATT, UNF_ERR,
			   "Port(0x%x) hifc can't send and wait mailbox, command type: 0x%x",
			   v_hba->port_cfg.port_id, cfg_fec.header.cmnd_type);

		goto exit;
	}

	if (port_fec_state_sts->config_fec_sts.status != RETURN_OK) {
		HIFC_TRACE(UNF_EVTLOG_LINK_ERR, UNF_LOG_EQUIP_ATT, UNF_ERR,
			   "Port(0x%x) Receive mailbox type(0x%x) status incorrect. Status: 0x%x.",
			   v_hba->port_cfg.port_id,
			   port_fec_state_sts->config_fec_sts.header.cmnd_type,
			   port_fec_state_sts->config_fec_sts.status);

		goto exit;
	}

	if (port_fec_state_sts->config_fec_sts.header.cmnd_type !=
	    HIFC_MBOX_CONFIG_FEC_STS) {
		HIFC_TRACE(UNF_EVTLOG_LINK_ERR, UNF_LOG_EQUIP_ATT, UNF_ERR,
			   "Port(0x%x) recv mailbox type(0x%x) incorrect.",
			   v_hba->port_cfg.port_id,
			   port_fec_state_sts->config_fec_sts.header.cmnd_type);

		goto exit;
	}

	v_hba->fec_status = v_fec_opcode;

	HIFC_TRACE(UNF_EVTLOG_LINK_ERR, UNF_LOG_EVENT, UNF_MAJOR,
		   "Port(0x%x) set FEC Status is %u.",
		   v_hba->port_cfg.port_id, op_code);

	ret = RETURN_OK;
exit:
	kfree(port_fec_state_sts);
	return ret;
}

unsigned int hifc_notify_up_config_timer(struct hifc_hba_s *v_hba, int op_code,
					 unsigned int user_data)
{
	struct hifc_inmbox_config_timer_s time_cfg;
	union hifc_outmbox_generic_u *time_cfg_sts = NULL;
	unsigned int ret = UNF_RETURN_ERROR;

	HIFC_CHECK(INVALID_VALUE32, v_hba, return UNF_RETURN_ERROR);

	memset(&time_cfg, 0, sizeof(time_cfg));

	time_cfg_sts = kmalloc(sizeof(union hifc_outmbox_generic_u),
			       GFP_ATOMIC);
	if (!time_cfg_sts) {
		HIFC_TRACE(UNF_EVTLOG_LINK_ERR, UNF_LOG_REG_ATT, UNF_ERR, "malloc outmbox memory failed");
		return UNF_RETURN_ERROR;
	}
	memset(time_cfg_sts, 0, sizeof(union hifc_outmbox_generic_u));
	time_cfg.header.cmnd_type = HIFC_MBOX_CONFIG_TIMER;
	time_cfg.header.length =
	HIFC_BYTES_TO_DW_NUM(sizeof(struct hifc_inmbox_config_timer_s));
	time_cfg.op_code = (unsigned short)op_code;
	time_cfg.fun_id = hifc_global_func_id(v_hba->hw_dev_handle);
	time_cfg.user_data = user_data;

	if (hifc_mb_send_and_wait_mbox(v_hba, &time_cfg, sizeof(time_cfg),
				       time_cfg_sts) != RETURN_OK) {
		HIFC_TRACE(UNF_EVTLOG_LINK_ERR, UNF_LOG_REG_ATT, UNF_ERR,
			   "[warn]Port(0x%x) hifc can't send and wait mailbox with command type(0x%x)",
			   v_hba->port_cfg.port_id, time_cfg.header.cmnd_type);

		goto exit;
	}

	if (time_cfg_sts->timer_config_sts.header.cmnd_type !=
	    HIFC_MBOX_CONFIG_TIMER_STS) {
		HIFC_TRACE(UNF_EVTLOG_LINK_ERR, UNF_LOG_EQUIP_ATT, UNF_ERR,
			   "[warn]Port(0x%x) recv mailbox type(0x%x) incorrect",
			   v_hba->port_cfg.port_id,
			   time_cfg_sts->timer_config_sts.header.cmnd_type);

		goto exit;
	}

	if (time_cfg_sts->timer_config_sts.status != RETURN_OK) {
		HIFC_TRACE(UNF_EVTLOG_LINK_ERR, UNF_LOG_EQUIP_ATT, UNF_ERR,
			   "[warn]Port(0x%x) Receive mailbox type(0x%x) status(0x%x) incorrect",
			   v_hba->port_cfg.port_id,
			   time_cfg_sts->timer_config_sts.header.cmnd_type,
			   time_cfg_sts->timer_config_sts.status);

		goto exit;
	}

	HIFC_TRACE(UNF_EVTLOG_LINK_INFO, UNF_LOG_EVENT, UNF_MAJOR,
		   "[info]Port(0x%x) notify uP to %s timer success",
		   v_hba->port_cfg.port_id, op_code ? "open" : "close");

	ret = RETURN_OK;
exit:
	kfree(time_cfg_sts);
	return ret;
}

unsigned int hifc_get_flash_data(void *v_hba, void *v_flash_data)
{
	struct hifc_hba_s *hba = NULL;
	struct unf_mbox_flash_data_mgmt_s *flash_data_mgmt = NULL;
	union hifc_outmbox_generic_u *flash_data_sts = NULL;
	unsigned int ret = UNF_RETURN_ERROR;

	HIFC_CHECK(INVALID_VALUE32, v_hba, return UNF_RETURN_ERROR);
	HIFC_CHECK(INVALID_VALUE32, v_flash_data, return UNF_RETURN_ERROR);

	hba = (struct hifc_hba_s *)v_hba;

	flash_data_mgmt = kmalloc(sizeof(struct unf_mbox_flash_data_mgmt_s),
				  GFP_ATOMIC);

	if (!flash_data_mgmt) {
		HIFC_TRACE(UNF_EVTLOG_LINK_WARN, UNF_LOG_REG_ATT, UNF_KEVENT,
			   "can't malloc buff for set flashData.");
		return ret;
	}
	flash_data_sts = kmalloc(sizeof(struct unf_flash_data_mgmt_sts_s),
				 GFP_ATOMIC);

	if (!flash_data_sts) {
		HIFC_TRACE(UNF_EVTLOG_LINK_WARN, UNF_LOG_REG_ATT, UNF_KEVENT,
			   "can't malloc buff for set flashData sts.");
		kfree(flash_data_mgmt);
		return ret;
	}
	memset(flash_data_mgmt, 0, sizeof(struct unf_mbox_flash_data_mgmt_s));
	memset(flash_data_sts, 0, sizeof(struct unf_flash_data_mgmt_sts_s));
	flash_data_mgmt->mbox_head.cmnd_type = HIFC_MBOX_FLASH_DATA_MGMT;
	flash_data_mgmt->mbox_head.length = 1; /* not used */
	flash_data_mgmt->mbox_head.op_code = 0; /* read config */

	if (hifc_mb_send_and_wait_mbox(
				hba, flash_data_mgmt,
				sizeof(struct unf_mbox_flash_data_mgmt_s),
				flash_data_sts) != RETURN_OK) {
		HIFC_TRACE(UNF_EVTLOG_LINK_ERR, UNF_LOG_REG_ATT, UNF_ERR,
			   "hifc can't send and wait mailbox, command type: 0x%x.",
			   flash_data_mgmt->mbox_head.cmnd_type);

		goto exit;
	}

	if (flash_data_sts->flash_data_sts.mbox_head.status != RETURN_OK) {
		HIFC_TRACE(UNF_EVTLOG_LINK_ERR, UNF_LOG_REG_ATT, UNF_ERR,
			   "Port(0x%x) mailbox status incorrect status(0x%x) .",
			   hba->port_cfg.port_id,
			   flash_data_sts->flash_data_sts.mbox_head.status);

		goto exit;
	}

	if (flash_data_sts->flash_data_sts.mbox_head.cmnd_type !=
	    HIFC_MBOX_FLASH_DATA_MGMT_STS) {
		HIFC_TRACE(UNF_EVTLOG_LINK_ERR, UNF_LOG_REG_ATT, UNF_ERR,
			   "Port(0x%x) receive mailbox type incorrect type: 0x%x.",
			   hba->port_cfg.port_id,
			   flash_data_sts->flash_data_sts.mbox_head.cmnd_type);

		goto exit;
	}

	memcpy((unsigned char *)v_flash_data,
	       (unsigned char *)&flash_data_sts->flash_data_sts.flash_data,
	       sizeof(struct unf_flash_data_s));
	ret = RETURN_OK;
exit:
	kfree(flash_data_mgmt);
	kfree(flash_data_sts);
	return ret;
}

unsigned int hifc_set_flash_data(void *v_hba, void *v_flash_data)
{
	struct hifc_hba_s *hba = NULL;
	struct unf_mbox_flash_data_mgmt_s *flash_data_mgmt = NULL;
	union hifc_outmbox_generic_u *flash_data_sts = NULL;
	unsigned int ret = UNF_RETURN_ERROR;

	HIFC_CHECK(INVALID_VALUE32, v_hba, return UNF_RETURN_ERROR);
	HIFC_CHECK(INVALID_VALUE32, v_flash_data, return UNF_RETURN_ERROR);

	hba = (struct hifc_hba_s *)v_hba;
	flash_data_mgmt = kmalloc(sizeof(struct unf_mbox_flash_data_mgmt_s),
				  GFP_ATOMIC);

	if (!flash_data_mgmt) {
		HIFC_TRACE(UNF_EVTLOG_LINK_ERR, UNF_LOG_REG_ATT, UNF_KEVENT,
			   "can't malloc buff for set flashData.");
		return ret;
	}
	flash_data_sts = kmalloc(sizeof(union hifc_outmbox_generic_u),
				 GFP_ATOMIC);

	if (!flash_data_sts) {
		HIFC_TRACE(UNF_EVTLOG_LINK_ERR, UNF_LOG_REG_ATT, UNF_KEVENT,
			   "can't malloc buff for set flashData sts.");
		kfree(flash_data_mgmt);
		return ret;
	}
	memset(flash_data_sts, 0, sizeof(union hifc_outmbox_generic_u));
	memset(flash_data_mgmt, 0, sizeof(struct unf_mbox_flash_data_mgmt_s));
	flash_data_mgmt->mbox_head.cmnd_type = HIFC_MBOX_FLASH_DATA_MGMT;
	flash_data_mgmt->mbox_head.length = 1; /* not used */
	flash_data_mgmt->mbox_head.op_code = 2; /* flash config */

	if (hifc_mb_send_and_wait_mbox(
				hba, flash_data_mgmt,
				sizeof(struct unf_mbox_flash_data_mgmt_s),
				flash_data_sts) != RETURN_OK) {
		HIFC_TRACE(UNF_EVTLOG_LINK_ERR, UNF_LOG_REG_ATT, UNF_KEVENT,
			   "hifc can't send and wait mailbox, command type: 0x%x.",
			   flash_data_sts->flash_data_sts.mbox_head.cmnd_type);

		goto END;
	}

	if (flash_data_sts->flash_data_sts.mbox_head.status != RETURN_OK) {
		HIFC_TRACE(UNF_EVTLOG_LINK_ERR, UNF_LOG_REG_ATT, UNF_KEVENT,
			   "Port(0x%x) mailbox status incorrect status(0x%x) .",
			   hba->port_cfg.port_id,
			   flash_data_sts->flash_data_sts.mbox_head.status);

		goto END;
	}

	if (flash_data_sts->flash_data_sts.mbox_head.cmnd_type !=
	    HIFC_MBOX_FLASH_DATA_MGMT_STS) {
		HIFC_TRACE(UNF_EVTLOG_LINK_ERR, UNF_LOG_REG_ATT, UNF_KEVENT,
			   "Port(0x%x) receive mailbox type incorrect type: 0x%x.",
			   hba->port_cfg.port_id,
			   flash_data_sts->flash_data_sts.mbox_head.cmnd_type);

		goto END;
	}
	flash_data_mgmt->mbox_head.cmnd_type = HIFC_MBOX_FLASH_DATA_MGMT;
	flash_data_mgmt->mbox_head.length = 1; /* not used */
	flash_data_mgmt->mbox_head.op_code = 1; /* write config */
	memcpy(&flash_data_mgmt->flash_data,
	       (unsigned char *)v_flash_data, sizeof(struct unf_flash_data_s));

	if (hifc_mb_send_and_wait_mbox(
				hba, flash_data_mgmt,
				sizeof(struct unf_mbox_flash_data_mgmt_s),
				flash_data_sts) != RETURN_OK) {
		HIFC_TRACE(UNF_EVTLOG_LINK_ERR, UNF_LOG_REG_ATT, UNF_ERR,
			   "hifc can't send and wait mailbox, command type: 0x%x.",
			   flash_data_sts->flash_data_sts.mbox_head.cmnd_type);

		goto END;
	}

	if (flash_data_sts->flash_data_sts.mbox_head.status != RETURN_OK) {
		HIFC_TRACE(UNF_EVTLOG_LINK_ERR, UNF_LOG_REG_ATT, UNF_KEVENT,
			   "Port(0x%x) mailbox status incorrect status(0x%x) .",
			   hba->port_cfg.port_id,
			   flash_data_sts->flash_data_sts.mbox_head.status);

		goto END;
	}

	if (flash_data_sts->flash_data_sts.mbox_head.cmnd_type !=
	    HIFC_MBOX_FLASH_DATA_MGMT_STS) {
		HIFC_TRACE(UNF_EVTLOG_LINK_ERR, UNF_LOG_REG_ATT, UNF_KEVENT,
			   "Port(0x%x) receive mailbox type incorrect type: 0x%x.",
			   hba->port_cfg.port_id,
			   flash_data_sts->flash_data_sts.mbox_head.cmnd_type);

		goto END;
	}
	ret = RETURN_OK;
END:
	kfree(flash_data_mgmt);
	kfree(flash_data_sts);
	return ret;
}
