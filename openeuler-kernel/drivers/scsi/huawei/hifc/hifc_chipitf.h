/* SPDX-License-Identifier: GPL-2.0 */
/* Huawei Hifc PCI Express Linux driver
 * Copyright(c) 2017 Huawei Technologies Co., Ltd
 *
 */

#ifndef __HIFC_CHIPITF_H__
#define __HIFC_CHIPITF_H__

#include "unf_log.h"
#include "hifc_utils.h"
#include "hifc_module.h"
#include "hifc_service.h"

/* CONF_API_CMND */
#define HIFC_MBOX_CONFIG_API        0x00
#define HIFC_MBOX_CONFIG_API_STS    0xA0

/* GET_CHIP_INFO_API_CMD */
#define HIFC_MBOX_GET_CHIP_INFO     0x01
#define HIFC_MBOX_GET_CHIP_INFO_STS 0xA1

/* PORT_RESET */
#define HIFC_MBOX_PORT_RESET        0x02
#define HIFC_MBOX_PORT_RESET_STS    0xA2

/* SFP_SWITCH_API_CMND */
#define HIFC_MBOX_PORT_SWITCH       0x03
#define HIFC_MBOX_PORT_SWITCH_STS   0xA3

/* GET_SFP_INFO */
#define HIFC_MBOX_GET_SFP_INFO      0x04
#define HIFC_MBOX_GET_SFP_INFO_STS  0xA4

/* CONF_AF_LOGIN_API_CMND */
#define HIFC_MBOX_CONFIG_LOGIN_API     0x06
#define HIFC_MBOX_CONFIG_LOGIN_API_STS 0xA6

/* BUFFER_CLEAR_DONE_CMND */
#define HIFC_MBOX_BUFFER_CLEAR_DONE     0x07
#define HIFC_MBOX_BUFFER_CLEAR_DONE_STS 0xA7

#define HIFC_MBOX_GET_ERR_CODE      0x08
#define HIFC_MBOX_GET_ERR_CODE_STS  0xA8

#define HIFC_MBOX_GET_UP_STATE      0x09
#define HIFC_MBOX_GET_UP_STATE_STS  0xA9

/* LOOPBACK MODE */
#define HIFC_MBOX_LOOPBACK_MODE     0x0A
#define HIFC_MBOX_LOOPBACK_MODE_STS 0xAA

/* REG RW MODE */
#define HIFC_MBOX_REG_RW_MODE       0x0B
#define HIFC_MBOX_REG_RW_MODE_STS   0xAB

/* GET CLEAR DONE STATE */
#define HIFC_MBOX_GET_CLEAR_STATE     0x0E
#define HIFC_MBOX_GET_CLEAR_STATE_STS 0xAE

/* GET UP & UCODE VER */
#define HIFC_MBOX_GET_FW_VERSION      0x0F
#define HIFC_MBOX_GET_FW_VERSION_STS  0xAF

/* CONFIG TIMER */
#define HIFC_MBOX_CONFIG_TIMER      0x10
#define HIFC_MBOX_CONFIG_TIMER_STS  0xB0

/* CONFIG SRQC */
#define HIFC_MBOX_CONFIG_SRQC      0x11
#define HIFC_MBOX_CONFIG_SRQC_STS  0xB1

/* Led Test */
#define HIFC_MBOX_LED_TEST      0x12
#define HIFC_MBOX_LED_TEST_STS  0xB2

/* set esch */
#define HIFC_MBOX_SET_ESCH      0x13
#define HIFC_MBOX_SET_ESCH_STS  0xB3

/* set get tx serdes */
#define HIFC_MBOX_SET_GET_SERDES_TX     0x14
#define HIFC_MBOX_SET_GET_SERDES_TX_STS 0xB4

/* get rx serdes */
#define HIFC_MBOX_GET_SERDES_RX     0x15
#define HIFC_MBOX_GET_SERDES_RX_STS 0xB5

/* i2c read write */
#define HIFC_MBOX_I2C_WR_RD      0x16
#define HIFC_MBOX_I2C_WR_RD_STS  0xB6

/* Set FEC Enable */
#define HIFC_MBOX_CONFIG_FEC      0x17
#define HIFC_MBOX_CONFIG_FEC_STS  0xB7

/* GET UCODE STATS CMD */
#define HIFC_MBOX_GET_UCODE_STAT      0x18
#define HIFC_MBOX_GET_UCODE_STAT_STS  0xB8

/* gpio read write */
#define HIFC_MBOX_GPIO_WR_RD      0x19
#define HIFC_MBOX_GPIO_WR_RD_STS  0xB9

/* GET PORT INFO CMD */
#define HIFC_MBOX_GET_PORT_INFO     0x20
#define HIFC_MBOX_GET_PORT_INFO_STS 0xC0

/* save hba info CMD */
#define HIFC_MBOX_SAVE_HBA_INFO     0x24
#define HIFC_MBOX_SAVE_HBA_INFO_STS 0xc4

#define HIFC_MBOX_FLASH_DATA_MGMT     0x25
#define HIFC_MBOX_FLASH_DATA_MGMT_STS 0xc5

/* FCOE: DRV->UP */
#define HIFC_MBOX_SEND_ELS_CMD    0x2A
#define HIFC_MBOX_SEND_VPORT_INFO 0x2B

/* FC: UP->DRV */
#define HIFC_MBOX_RECV_FC_LINKUP   0x40
#define HIFC_MBOX_RECV_FC_LINKDOWN 0x41
#define HIFC_MBOX_RECV_FC_DELCMD   0x42
#define HIFC_MBOX_RECV_FC_ERROR    0x43

#define LOOP_MAP_VALID             1
#define LOOP_MAP_INVALID           0

#define HIFC_MBOX_SIZE             1024
#define HIFC_MBOX_HEADER_SIZE      4

#define ATUOSPEED                  1
#define FIXEDSPEED                 0
#define UNDEFINEOPCODE             0

#define VALUEMASK_L                0x00000000FFFFFFFF
#define VALUEMASK_H                0xFFFFFFFF00000000

#define STATUS_OK                  0
#define STATUS_FAIL                1

enum hifc_drv_2_up_unblock_msg_cmd_code_e {
	HIFC_SEND_ELS_CMD,
	HIFC_SEND_ELS_CMD_FAIL,
	HIFC_RCV_ELS_CMD_RSP,
	HIFC_SEND_CONFIG_LOGINAPI,
	HIFC_SEND_CONFIG_LOGINAPI_FAIL,
	HIFC_RCV_CONFIG_LOGIN_API_RSP,
	HIFC_SEND_CLEAR_DONE,
	HIFC_SEND_CLEAR_DONE_FAIL,
	HIFC_RCV_CLEAR_DONE_RSP,
	HIFC_SEND_VPORT_INFO_DONE,
	HIFC_SEND_VPORT_INFO_FAIL,
	HIFC_SEND_VPORT_INFO_RSP,
	HIFC_MBOX_CMD_BUTT

};

/* up to driver handle templete */
struct hifc_up_2_drv_msg_handle_s {
	unsigned char cmd;
	unsigned int (*pfn_hifc_msg_up2drv_handler)(struct hifc_hba_s *v_hba,
						    void *v_buf_in);
};

/* Mbox Common Header */
struct hifc_mbox_header_s {
	unsigned char cmnd_type;
	unsigned char length;
	unsigned char port_id;
	unsigned char reserved;

};

/* open or close the sfp */
struct hifc_inbox_port_switch_s {
	struct hifc_mbox_header_s header;

	unsigned char op_code;
	unsigned char port_type;
	unsigned short reserved;

	unsigned char host_id;
	unsigned char pf_id;
	unsigned char fcoe_mode;
	unsigned char reserved2;

	unsigned short conf_vlan;
	unsigned short reserved3;

	unsigned long long sys_port_wwn;
	unsigned long long sys_node_name;
};

struct hifc_outbox_port_switch_sts_s {
	struct hifc_mbox_header_s header;

	unsigned short reserved;
	unsigned char reserved2;
	unsigned char status;
};

/* config API */
struct hifc_inbox_config_api_s {
	struct hifc_mbox_header_s header;

	unsigned int op_code : 8;
	unsigned int reserved1 : 24;

	unsigned char topy_mode;
	unsigned char sfp_speed;
	unsigned char max_speed;
	unsigned char hard_alpa;

	unsigned char port_name[UNF_WWN_LEN];

	unsigned int slave : 1;
	unsigned int auto_sneg : 1;
	unsigned int reserved2 : 30;

	unsigned int rx_bbcredit_32g : 16;  /* 160 */
	unsigned int rx_bbcredit_16g : 16;  /* 80 */
	unsigned int rx_bbcredit_842g : 16; /* 50 */
	unsigned int rdy_cnt_bf_fst_frm : 16; /* 8 */

	unsigned int esch_value_32g;
	unsigned int esch_value_16g;
	unsigned int esch_value_8g;
	unsigned int esch_value_4g;
	unsigned int esch_value_2g;
	unsigned int esch_bust_size;
};

struct hifc_outbox_config_api_sts_s {
	struct hifc_mbox_header_s header;

	unsigned short reserved;
	unsigned char reserved2;
	unsigned char status;
};

/* Get chip info */
struct hifc_inbox_get_chip_info_s {
	struct hifc_mbox_header_s header;

};

struct hifc_outbox_get_chip_info_sts_s {
	struct hifc_mbox_header_s header;

	unsigned char status;
	unsigned char board_type;
	unsigned char rvsd;
	unsigned char tape_support : 1;
	unsigned char reserved : 7;

	unsigned long long wwpn;
	unsigned long long wwnn;
	unsigned long long sys_mac;

};

/* Get reg info */
struct hifc_inmbox_get_reg_info_s {
	struct hifc_mbox_header_s header;
	unsigned int op_code : 1;
	unsigned int reg_len : 8;
	unsigned int rsvd : 23;
	unsigned int reg_addr;
	unsigned int reg_value_l32;
	unsigned int reg_value_h32;
	unsigned int rvsd[27];
};

/* Get reg info sts */
struct hifc_outmbox_get_reg_info_sts_s {
	struct hifc_mbox_header_s header;

	unsigned short rvsd0;
	unsigned char rvsd1;
	unsigned char status;
	unsigned int reg_value_l32;
	unsigned int reg_value_h32;
	unsigned int rvsd[28];
};

/* Config login API */
struct hifc_inmbox_config_login_s {
	struct hifc_mbox_header_s header;

	unsigned int op_code : 8;
	unsigned int reserved1 : 24;

	unsigned short tx_bb_credit;
	unsigned short reserved2;

	unsigned int rtov;
	unsigned int etov;

	unsigned int rt_tov_tag : 1;
	unsigned int ed_tov_tag : 1;
	unsigned int bb_credit : 6;
	unsigned int bbscn : 8;
	unsigned int lr_flag : 16;
};

struct hifc_outmbox_config_login_sts_s {
	struct hifc_mbox_header_s header;

	unsigned short reserved;
	unsigned char reserved2;
	unsigned char status;
};

/* port reset */
#define HIFC_MBOX_SUBTYPE_LIGHT_RESET  0x0
#define HIFC_MBOX_SUBTYPE_HEAVY_RESET  0x1

struct hifc_inmbox_port_reset_s {
	struct hifc_mbox_header_s header;

	unsigned int op_code : 8;
	unsigned int reserved1 : 24;
};

struct hifc_outmbox_port_reset_sts_s {
	struct hifc_mbox_header_s header;

	unsigned short reserved;
	unsigned char reserved2;
	unsigned char status;
};

struct hifc_inmbox_get_sfp_info_s {
	struct hifc_mbox_header_s header;
};

struct hifc_outmbox_get_sfp_info_sts_s {
	struct hifc_mbox_header_s header;

	unsigned int rcvd : 8;
	unsigned int length : 16;
	unsigned int status : 8;
};

/* get and clear error code */
struct hifc_inmbox_get_err_code_s {
	struct hifc_mbox_header_s header;
};

struct hifc_outmbox_get_err_code_sts_s {
	struct hifc_mbox_header_s header;

	unsigned short rsvd;
	unsigned char rsvd2;
	unsigned char status;

	unsigned int err_code[8];
};

/* uP-->Driver asyn event API */
struct hifc_link_event_s {
	struct hifc_mbox_header_s header;

	unsigned char link_event;
	unsigned char reason;
	unsigned char speed;
	unsigned char top_type;

	unsigned char alpa_value;
	unsigned char reserved1;
	unsigned short paticpate : 1;
	unsigned short acled : 1;
	unsigned short yellow_speed_led : 1;
	unsigned short green_speed_led : 1;
	unsigned short reserved : 12;

	unsigned char loop_map_info[128];
};

enum hifc_up_err_type_e {
	HIFC_UP_ERR_DRV_PARA = 0,
	HIFC_UP_ERR_SFP = 1,
	HIFC_UP_ERR_32G_PUB = 2,
	HIFC_UP_ERR_32G_UA = 3,
	HIFC_UP_ERR_32G_MAC = 4,
	HIFC_UP_ERR_NON32G_DFX = 5,
	HIFC_UP_ERR_NON32G_MAC = 6,
	HIFC_UP_ERR_BUTT
};

enum hifc_up_err_value_e {
	/* ERR type 0 */
	HIFC_DRV_2_UP_PARA_ERR = 0,

	/* ERR type 1 */
	HIFC_SFP_SPEED_ERR,

	/* ERR type 2 */
	HIFC_32GPUB_UA_RXESCH_FIFO_OF,
	HIFC_32GPUB_UA_RXESCH_FIFO_UCERR,

	/* ERR type 3 */
	HIFC_32G_UA_UATX_LEN_ABN,
	HIFC_32G_UA_RXAFIFO_OF,
	HIFC_32G_UA_TXAFIFO_OF,
	HIFC_32G_UA_RXAFIFO_UCERR,
	HIFC_32G_UA_TXAFIFO_UCERR,

	/* ERR type 4 */
	HIFC_32G_MAC_RX_BBC_FATAL,
	HIFC_32G_MAC_TX_BBC_FATAL,
	HIFC_32G_MAC_TXFIFO_UF,
	HIFC_32G_MAC_PCS_TXFIFO_UF,
	HIFC_32G_MAC_RXBBC_CRDT_TO,
	HIFC_32G_MAC_PCS_RXAFIFO_OF,
	HIFC_32G_MAC_PCS_TXFIFO_OF,
	HIFC_32G_MAC_FC2P_RXFIFO_OF,
	HIFC_32G_MAC_FC2P_TXFIFO_OF,
	HIFC_32G_MAC_FC2P_CAFIFO_OF,
	HIFC_32G_MAC_PCS_RXRSFECM_UCEER,
	HIFC_32G_MAC_PCS_RXAFIFO_UCEER,
	HIFC_32G_MAC_PCS_TXFIFO_UCEER,
	HIFC_32G_MAC_FC2P_RXFIFO_UCEER,
	HIFC_32G_MAC_FC2P_TXFIFO_UCEER,

	/* ERR type 5 */
	HIFC_NON32G_DFX_FC1_DFX_BF_FIFO,
	HIFC_NON32G_DFX_FC1_DFX_BP_FIFO,
	HIFC_NON32G_DFX_FC1_DFX_RX_AFIFO_ERR,
	HIFC_NON32G_DFX_FC1_DFX_TX_AFIFO_ERR,
	HIFC_NON32G_DFX_FC1_DFX_DIRQ_RXBUF_FIFO1,
	HIFC_NON32G_DFX_FC1_DFX_DIRQ_RXBBC_TO,
	HIFC_NON32G_DFX_FC1_DFX_DIRQ_TXDAT_FIFO,
	HIFC_NON32G_DFX_FC1_DFX_DIRQ_TXCMD_FIFO,
	HIFC_NON32G_DFX_FC1_ERR_R_RDY,

	/* ERR type 6 */
	HIFC_NON32G_MAC_FC1_FAIRNESS_ERROR,

	HIFC_ERR_VALUE_BUTT
};

struct hifc_up_error_event_s {
	struct hifc_mbox_header_s header;

	unsigned char link_event;
	unsigned char error_level;
	unsigned char error_type;
	unsigned char error_value;
};

struct hifc_inmbx_clear_node_s {
	struct hifc_mbox_header_s header;
};

struct hifc_inmbox_get_clear_state_s {
	struct hifc_mbox_header_s header;
	unsigned int resvd[31];
};

struct hifc_outmbox_get_clear_state_sts_s {
	struct hifc_mbox_header_s header;
	unsigned short rsvd;
	unsigned char state;  /* 1--clear doing. 0---clear done. */
	unsigned char status; /* 0--ok,!0---fail */
	unsigned int resvd[30];
};

#define HIFC_FIP_MODE_VN2VF 0
#define HIFC_FIP_MODE_VN2VN 1

/* get port state */
struct hifc_inmbox_get_port_info_s {
	struct hifc_mbox_header_s header;
};

/* save hba info */
struct hifc_inmbox_save_hba_info_s {
	struct hifc_mbox_header_s header;

	unsigned int hba_save_info[254];

};

struct hifc_outmbox_get_port_info_sts_s {
	struct hifc_mbox_header_s header;

	unsigned int status : 8;
	unsigned int fec_vis_tts_16g : 8;
	unsigned int bbscn : 8;
	unsigned int loop_credit : 8;

	unsigned int non_loop_rx_credit : 8;
	unsigned int non_loop_tx_credit : 8;
	unsigned int sfp_speed : 8;
	unsigned int present : 8;

};

struct hifc_outmbox_save_hba_info_sts_s {
	struct hifc_mbox_header_s header;
	unsigned short rsvd1;
	unsigned char rsvd2;
	unsigned char status;
	unsigned int rsvd3;
	unsigned int save_hba_info[252];
};

#define HIFC_VER_ADDR_OFFSET (8)
struct hifc_inmbox_get_fw_version_s {
	struct hifc_mbox_header_s header;
};

struct hifc_outmbox_get_fw_version_sts_s {
	struct hifc_mbox_header_s header;

	unsigned char status;
	unsigned char rsv[3];

	unsigned char ucode_ver[HIFC_VER_LEN];
	unsigned char ucode_compile_time[HIFC_COMPILE_TIME_LEN];

	unsigned char up_ver[HIFC_VER_LEN];
	unsigned char up_compile_time[HIFC_COMPILE_TIME_LEN];

	unsigned char boot_ver[HIFC_VER_LEN];
	unsigned char boot_compile_time[HIFC_COMPILE_TIME_LEN];
};

/* Set Fec Enable */
struct hifc_inmbox_config_fec_s {
	struct hifc_mbox_header_s header;

	unsigned char fec_op_code;
	unsigned char rsv0;
	unsigned short rsv1;
};

struct hifc_outmbox_config_fec_sts_s {
	struct hifc_mbox_header_s header;

	unsigned short usrsv0;
	unsigned char ucrsv1;
	unsigned char status;
};

struct hifc_inmbox_config_timer_s {
	struct hifc_mbox_header_s header;

	unsigned short op_code;
	unsigned short fun_id;
	unsigned int user_data;
};

struct hifc_outmbox_config_timer_sts_s {
	struct hifc_mbox_header_s header;

	unsigned char status;
	unsigned char rsv[3];
};

union hifc_outmbox_generic_u {
	struct {
		struct hifc_mbox_header_s header;
		unsigned int rsvd[(HIFC_MBOX_SIZE - HIFC_MBOX_HEADER_SIZE) /
				sizeof(unsigned int)];
	} generic;

	struct hifc_outbox_port_switch_sts_s port_switch_sts;
	struct hifc_outbox_config_api_sts_s config_api_sts;
	struct hifc_outbox_get_chip_info_sts_s get_chip_info_sts;
	struct hifc_outmbox_get_reg_info_sts_s get_reg_info_sts;
	struct hifc_outmbox_config_login_sts_s config_login_sts;
	struct hifc_outmbox_port_reset_sts_s port_reset_sts;
	struct hifc_outmbox_get_sfp_info_sts_s get_sfp_info_sts;
	struct hifc_outmbox_get_err_code_sts_s get_err_code_sts;
	struct hifc_outmbox_get_clear_state_sts_s get_clr_state_sts;
	struct hifc_outmbox_get_fw_version_sts_s get_fw_ver_sts;
	struct hifc_outmbox_config_fec_sts_s config_fec_sts;
	struct hifc_outmbox_config_timer_sts_s timer_config_sts;
	struct hifc_outmbox_get_port_info_sts_s get_port_info_sts;
	struct unf_flash_data_mgmt_sts_s flash_data_sts;
};

unsigned int hifc_get_chip_msg(void *v_hba, void *v_mac);
unsigned int hifc_config_port_table(struct hifc_hba_s *v_hba);
unsigned int hifc_port_switch(struct hifc_hba_s *v_hba, int turn_on);
unsigned int hifc_get_speed_act(void *v_hba, void *v_speed_act);
unsigned int hifc_get_speed_cfg(void *v_hba, void *v_speed_cfg);
unsigned int hifc_get_loop_map(void *v_hba, void *v_buf);
unsigned int hifc_get_firmware_version(void *v_fc_port, void *v_ver);
unsigned int hifc_get_work_bale_bbcredit(void *v_hba, void *v_bb_credit);
unsigned int hifc_get_work_bale_bbscn(void *v_hba, void *v_bbscn);
unsigned int hifc_get_and_clear_port_error_code(void *v_hba, void *v_err_code);
unsigned int hifc_get_port_current_info(void *v_hba, void *v_port_info);
unsigned int hifc_get_port_fec(void *v_hba, void *v_para_out);
unsigned int hifc_get_software_version(void *v_fc_port, void *v_ver);
unsigned int hifc_get_port_info(void *v_hba);
unsigned int hifc_rw_reg(void *v_hba, void *v_params);
unsigned int hifc_clear_port_error_code(void *v_hba, void *v_err_code);
unsigned int hifc_get_sfp_info(void *v_fc_port, void *v_sfp_info);
unsigned int hifc_get_hardware_version(void *v_fc_port, void *v_ver);
unsigned int hifc_get_lport_led(void *v_hba, void *v_led_state);
unsigned int hifc_get_loop_alpa(void *v_hba, void *v_alpa);
unsigned int hifc_get_topo_act(void *v_hba, void *v_topo_act);
unsigned int hifc_get_topo_cfg(void *v_hba, void *v_topo_cfg);
unsigned int hifc_config_login_api(
				struct hifc_hba_s *v_hba,
				struct unf_port_login_parms_s *v_login_parms);
unsigned int hifc_mb_send_and_wait_mbox(struct hifc_hba_s *v_hba,
					const void *v_in_mbox,
					unsigned short in_size,
					union hifc_outmbox_generic_u
					*v_out_mbox);
void hifc_up_msg_2_driver_proc(void *v_hwdev_handle,
			       void *v_pri_handle,
			       unsigned char v_cmd,
			       void *v_buf_in,
			       unsigned short v_in_size,
			       void *v_buf_out,
			       unsigned short *v_out_size);

unsigned int hifc_mbox_reset_chip(struct hifc_hba_s *v_hba,
				  unsigned char v_sub_type);
unsigned int hifc_clear_sq_wqe_done(struct hifc_hba_s *v_hba);
unsigned int hifc_update_fabric_param(void *v_hba, void *v_para_in);
unsigned int hifc_update_port_param(void *v_hba, void *v_para_in);
unsigned int hifc_mbx_get_fw_clear_stat(struct hifc_hba_s *v_hba,
					unsigned int *v_clear_state);
unsigned short hifc_get_global_base_qpn(void *v_handle);
unsigned int hifc_mbx_set_fec(struct hifc_hba_s *v_hba,
			      unsigned int v_fec_opcode);
unsigned int hifc_notify_up_config_timer(struct hifc_hba_s *v_hba,
					 int v_opcode,
					 unsigned int v_user_data);
unsigned int hifc_save_hba_info(void *v_hba, void *v_para_in);
unsigned int hifc_get_chip_capability(void *hw_dev_handle,
				      struct hifc_chip_info_s *v_chip_info);
unsigned int hifc_get_flash_data(void *v_hba, void *v_flash_data);
unsigned int hifc_set_flash_data(void *v_hba, void *v_flash_data);

#endif
