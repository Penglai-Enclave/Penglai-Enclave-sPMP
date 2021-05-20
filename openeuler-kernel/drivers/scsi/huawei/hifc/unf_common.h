/* SPDX-License-Identifier: GPL-2.0 */
/* Huawei Hifc PCI Express Linux driver
 * Copyright(c) 2017 Huawei Technologies Co., Ltd
 *
 */
#ifndef __UNF_COMMON_H
#define __UNF_COMMON_H

#include "unf_scsi_common.h"

/* V/C version number */
#define UNF_MAJOR_VERSION "3"
/* B version, B0XX Corresponding x.x */
#define UNF_B_VERSION "5.0"
/* Indicates the minor version number of the driver */
#define UNF_DRIVER_VERSION "11"
/* version num */
#define UNF_FC_VERSION UNF_MAJOR_VERSION "." UNF_B_VERSION "." UNF_DRIVER_VERSION
extern unsigned int unf_dbg_level;
extern unsigned int hifc_dif_type;
extern unsigned int hifc_dif_enable;
extern unsigned char hifc_guard;

#define RETURN_ERROR_S32     (-1)
#define UNF_RETURN_ERROR_S32 (-1)

#define UNF_IO_SUCCESS                    0x00000000
/* the host system aborted the command */
#define UNF_IO_ABORTED                    0x00000001
#define UNF_IO_FAILED                     0x00000002
#define UNF_IO_ABORT_ABTS                 0x00000003
#define UNF_IO_ABORT_LOGIN                0x00000004 /* abort login */
/* reset event aborted the transport */
#define UNF_IO_ABORT_REET                 0x00000005
#define UNF_IO_ABORT_FAILED               0x00000006 /* abort failed */
/* data out of order ,data reassembly error */
#define UNF_IO_OUTOF_ORDER                0x00000007
#define UNF_IO_FTO                        0x00000008 /* frame time out */
#define UNF_IO_LINK_FAILURE               0x00000009
#define UNF_IO_OVER_FLOW                  0x0000000a /* data over run */
#define UNF_IO_RSP_OVER                   0x0000000b
#define UNF_IO_LOST_FRAME                 0x0000000c
#define UNF_IO_UNDER_FLOW                 0x0000000d /* data under run */
#define UNF_IO_HOST_PROG_ERROR            0x0000000e
#define UNF_IO_SEST_PROG_ERROR            0x0000000f
#define UNF_IO_INVALID_ENTRY              0x00000010
#define UNF_IO_ABORT_SEQ_NOT              0x00000011
#define UNF_IO_REJECT                     0x00000012
#define UNF_IO_RS_INFO                    0x00000013
#define UNF_IO_EDC_IN_ERROR               0x00000014
#define UNF_IO_EDC_OUT_ERROR              0x00000015
#define UNF_IO_UNINIT_KEK_ERR             0x00000016
#define UNF_IO_DEK_OUTOF_RANGE            0x00000017
#define UNF_IO_KEY_UNWRAP_ERR             0x00000018
#define UNF_IO_KEY_TAG_ERR                0x00000019
#define UNF_IO_KEY_ECC_ERR                0x0000001a
#define UNF_IO_BLOCK_SIZE_ERROR           0x0000001b
#define UNF_IO_ILLEGAL_CIPHER_MODE        0x0000001c
#define UNF_IO_CLEAN_UP                   0x0000001d
#define UNF_SRR_RECEIVE                   0x0000001e /* receive srr */
/* The target device sent an ABTS to abort the I/O. */
#define UNF_IO_ABORTED_BY_TARGET          0x0000001f
#define UNF_IO_TRANSPORT_ERROR            0x00000020
#define UNF_IO_LINK_FLASH                 0x00000021
#define UNF_IO_TIMEOUT                    0x00000022
#define UNF_IO_PORT_UNAVAILABLE           0x00000023
#define UNF_IO_PORT_LOGOUT                0x00000024
#define UNF_IO_PORT_CFG_CHG               0x00000025
#define UNF_IO_FIRMWARE_RES_UNAVAILABLE   0x00000026
#define UNF_IO_TASK_MGT_OVERRUN           0x00000027
#define UNF_IO_DMA_ERROR                  0x00000028
#define UNF_IO_DIF_ERROR                  0x00000029
#define UNF_IO_NO_LPORT                   0x0000002a
#define UNF_IO_NO_XCHG                    0x0000002b
#define UNF_IO_SOFT_ERR                   0x0000002c
#define UNF_IO_XCHG_ADD_ERROR             0x0000002d
#define UNF_IO_NO_LOGIN                   0x0000002e
#define UNF_IO_NO_BUFFER                  0x0000002f
#define UNF_IO_DID_ERROR                  0x00000030
#define UNF_IO_UNSUPPORT                  0x00000031
#define UNF_IO_NOREADY                    0x00000032
#define UNF_IO_NPORTID_REUSED             0x00000033
#define UNF_IO_NPORT_HANDLE_REUSED        0x00000034
#define UNF_IO_NO_NPORT_HANDLE            0x00000035
#define UNF_IO_ABORT_BY_FW                0x00000036
#define UNF_IO_ABORT_PORT_REMOVING        0x00000037
#define UNF_IO_INCOMPLETE                 0x00000038
#define UNF_IO_DIF_REF_ERROR              0x00000039
#define UNF_IO_DIF_GEN_ERROR              0x0000003a

#define UNF_IO_ERREND 0xFFFFFFFF

/* define bits */
#define UNF_BIT(n) (0x1UL << (n))
#define UNF_BIT_0  UNF_BIT(0)
#define UNF_BIT_1  UNF_BIT(1)
#define UNF_BIT_2  UNF_BIT(2)
#define UNF_BIT_3  UNF_BIT(3)
#define UNF_BIT_4  UNF_BIT(4)
#define UNF_BIT_5  UNF_BIT(5)

struct buff_list_s {
	u8 *vaddr;
	dma_addr_t paddr;
};

struct buf_describe_s {
	struct buff_list_s *buflist;
	u32 buf_size;
	u32 buf_num;
};

#define BUF_LIST_PAGE_SIZE (PAGE_SIZE << 8)

/* Echo macro define */
#define ECHO_MG_VERSION_LOCAL  1
#define ECHO_MG_VERSION_REMOTE 2

/* save hba info macro define */
#define SAVE_PORT_INFO_LEN 1016

#define UNF_GET_NAME_HIGH_WORD(v_name) \
	(((v_name) >> 32) & 0xffffffff)
#define UNF_GET_NAME_LOW_WORD(v_name) \
	((v_name) & 0xffffffff)

#define UNF_FIRST_LPORT_ID_MASK 0xffffff00
#define HIFC_MAX_COUNTER_TYPE   128

#define UNF_EVENT_ASYN		0
#define UNF_EVENT_SYN		 1
#define UNF_GLOBAL_EVENT_ASYN 2
#define UNF_GLOBAL_EVENT_SYN  3

/* define sfp err */
#define UNF_SFP_PRESENT_FAIL 0x1
#define UNF_SFP_POWER_FAIL   0x2
#define UNF_9545_FAIL        0x3

/* obtain the values of board type and ID */
#define UNF_GET_BOARD_TYPE_AND_SLOT_ID_BY_PORTID(port_id) \
	(((port_id) & 0x00FF00) >> 8)

#define UNF_FC_SERVER_BOARD_8_G  13 /* 8G mode */
#define UNF_FC_SERVER_BOARD_16_G 7  /* 16G mode */
#define UNF_FC_SERVER_BOARD_32_G 6  /* 32G mode */

#define UNF_PORT_TYPE_FC_QSFP               1
#define UNF_PORT_TYPE_FC_SFP                0
#define UNF_PORT_UNGRADE_FW_RESET_ACTIVE    0
#define UNF_PORT_UNGRADE_FW_RESET_INACTIVE  1

#ifndef __BIG_ENDIAN__
#define __BIG_ENDIAN__ 0x4321
#endif

#ifndef __LITTLE_ENDIAN__
#define __LITTLE_ENDIAN__ 0x1234
#endif

#ifdef __BYTE_ORDER__
#undef __BYTE_ORDER__
#endif
#define __BYTE_ORDER__ __LITTLE_ENDIAN__

#ifndef INVALID_VALUE64
#define INVALID_VALUE64 0xFFFFFFFFFFFFFFFFULL
#endif /* INVALID_VALUE64 */

#ifndef INVALID_VALUE32
#define INVALID_VALUE32 0xFFFFFFFF
#endif /* INVALID_VALUE32 */

#ifndef INVALID_VALUE16
#define INVALID_VALUE16 0xFFFF
#endif /* INVALID_VALUE16 */

#ifndef INVALID_VALUE8
#define INVALID_VALUE8 0xFF
#endif /* INVALID_VALUE8 */

#ifndef RETURN_OK
#define RETURN_OK 0
#endif

#ifndef RETURN_ERROR
#define RETURN_ERROR (~0)
#endif
#define UNF_RETURN_ERROR (~0)

#ifndef UNF_RETURN_NOT_SUPPORT
#define UNF_RETURN_NOT_SUPPORT (2)
#endif

enum int_e {
	UNF_FALSE = 0,
	UNF_TRUE = 1
};

#define DRV_DIF_CRC_ERR 0x1001
#define DRV_DIF_LBA_ERR 0x1002
#define DRV_DIF_APP_ERR 0x1003

#define UNF_SCSI_SENSE_DATA_LEN SCSI_SENSE_DATA_LEN

/* RPort Management information related to Rport,
 * only used at the boundary between common and lowlevel
 */
struct unf_rport_info_s {
	unsigned int local_nport_id;
	unsigned int nport_id;
	unsigned int rport_index;
	unsigned long long port_name;
	unsigned char rsvd0[3];
};

struct unf_cfg_item_s {
	char *name;
	unsigned int min_value;
	unsigned int default_value;
	unsigned int max_value;
};

struct unf_port_params_s {
	unsigned int ra_tov;
	unsigned int ed_tov;
};

/* get wwpn adn wwnn */
struct unf_get_chip_info_argout {
	unsigned char board_type;
	unsigned long long wwpn;
	unsigned long long wwnn;
	unsigned long long sys_mac;
};

/* get sfp info: present and speed */
struct unf_get_port_info_argout {
	unsigned char sfp_speed;
	unsigned char present;
	unsigned char rsvd[2];
};

/* SFF-8436(QSFP+) Rev 4.7 */
struct sfp_plus_field_a0_s {
	unsigned char identifier;
	/* offset 1~2 */
	struct {
		unsigned char reserved;
		unsigned char status;
	} status_indicator;
	/* offset 3~21 */
	struct {
		unsigned char rx_tx_los;
		unsigned char tx_fault;
		unsigned char all_resv;

		unsigned char ini_complete : 1;
		unsigned char bit_resv : 3;
		unsigned char temp_low_warn : 1;
		unsigned char temp_high_warn : 1;
		unsigned char temp_low_alarm : 1;
		unsigned char temp_high_alarm : 1;

		unsigned char resv : 4;
		unsigned char vcc_low_warn : 1;
		unsigned char vcc_high_warn : 1;
		unsigned char vcc_low_alarm : 1;
		unsigned char vcc_high_alarm : 1;

		unsigned char resv8;
		unsigned char rx_pow[2];
		unsigned char tx_bias[2];
		unsigned char reserved[6];
		unsigned char vendor_specifics[3];
	} interrupt_flag;
	/* offset 22~33 */
	struct {
		unsigned char temp[2];
		unsigned char reserved[2];
		unsigned char supply_vol[2];
		unsigned char reserveds[2];
		unsigned char vendor_specific[4];
	} module_monitors;
	/* offset 34~81 */
	struct {
		unsigned char rx_pow[8];
		unsigned char tx_bias[8];
		unsigned char reserved[16];
		unsigned char vendor_specific[16];
	} channel_monitor_val;

	/* offset 82~85 */
	unsigned char reserved[4];

	/* offset 86~97 */
	struct {
		/* 86~88 */
		unsigned char tx_disable;
		unsigned char rx_rate_select;
		unsigned char tx_rate_select;

		/* 89~92 */
		unsigned char rx_4_app_select;
		unsigned char rx_3_app_select;
		unsigned char rx_2_app_select;
		unsigned char rx_1_app_select;
		/* 93 */
		unsigned char power_override : 1;
		unsigned char power_set : 1;
		unsigned char reserved : 6;

		/* 94~97 */
		unsigned char tx_4_app_select;
		unsigned char tx_3_app_select;
		unsigned char tx_2_app_select;
		unsigned char tx_1_app_select;
		/* 98~99 */
		unsigned char auc_reserved[2];
	} control;
	/* 100~106 */
	struct {
		/* 100 */
		unsigned char mrx_1_os : 1;
		unsigned char mrx_2_los : 1;
		unsigned char mrx_3_los : 1;
		unsigned char mrx_4_los : 1;
		unsigned char mtx_1_los : 1;
		unsigned char mtx_2_los : 1;
		unsigned char mtx_3_los : 1;
		unsigned char mtx_4_los : 1;
		/* 101 */
		unsigned char mtx_1_fault : 1;
		unsigned char mtx_2_fault : 1;
		unsigned char mtx_3_fault : 1;
		unsigned char mtx_4_fault : 1;
		unsigned char reserved : 4;
		/* 102 */
		unsigned char uc_reserved;
		/* 103 */
		unsigned char mini_cmp_flag : 1;
		unsigned char rsv : 3;
		unsigned char mtemp_low_warn : 1;
		unsigned char mtemp_high_warn : 1;
		unsigned char mtemp_low_alarm : 1;
		unsigned char mtemp_high_alarm : 1;
		/* 104 */
		unsigned char rsv1 : 4;
		unsigned char mvcc_low_warn : 1;
		unsigned char mvcc_high_warn : 1;
		unsigned char mvcc_low_alarm : 1;
		unsigned char mvcc_high_alarm : 1;
		/* 105~106 */
		unsigned char vendor_specific[2];
	} module_channel_mask_bit;
	/* 107~118 */
	unsigned char auc_resv[12];
	/* 119~126 */
	unsigned char auc_reserved[8];
	/* 127 */
	unsigned char page_select;
};

/* page 00 */
struct sfp_plus_field_00_s {
	/* 128~191 */
	struct {
		unsigned char id;
		unsigned char id_ext;
		unsigned char connector;
		unsigned char speci_com[6];
		unsigned char mode;
		unsigned char speed;
		unsigned char encoding;
		unsigned char br_nominal;
		unsigned char ext_rate_select_com;
		unsigned char length_smf;
		unsigned char length_om3;
		unsigned char length_om2;
		unsigned char length_om1;
		unsigned char length_copper;
		unsigned char device_tech;
		unsigned char vendor_name[16];
		unsigned char ex_module;
		unsigned char vendor_oui[3];
		unsigned char vendor_pn[16];
		unsigned char vendor_rev[2];
		/* Wave length or Copper cable Attenuation */
		unsigned char wave_or_copper_attenuation[2];
		unsigned char wave_length_toler[2]; /* Wavelength tolerance */
		unsigned char max_temp;
		unsigned char cc_base;
	} base_id_fields;
	/* 192~223 */
	struct {
		unsigned char options[4];
		unsigned char vendor_sn[16];
		unsigned char date_code[8];
		unsigned char diagn_monit_type;
		unsigned char enhance_opt;
		unsigned char uc_reserved;
		unsigned char ccext;
	} ext_id_fields;
	/* 224~255 */
	unsigned char vendor_spec_eeprom[32];
};

/* page 01 */
struct sfp_field_01_s {
	unsigned char optiona_l01[128];
};

/* page 02 */
struct sfp_field_02_s {
	unsigned char optiona_l02[128];
};

/* page 03 */
struct sfp_field_03_s {
	unsigned char temp_high_alarm[2];
	unsigned char temp_low_alarm[2];
	unsigned char temp_high_warn[2];
	unsigned char temp_low_warn[2];

	unsigned char reserved1[8];

	unsigned char vcc_high_alarm[2];
	unsigned char vcc_low_alarm[2];
	unsigned char vcc_high_warn[2];
	unsigned char vcc_low_warn[2];

	unsigned char reserved2[8];
	unsigned char vendor_specific1[16];

	unsigned char pow_high_alarm[2];
	unsigned char pow_low_alarm[2];
	unsigned char pow_high_warn[2];
	unsigned char pow_low_warn[2];

	unsigned char bias_high_alarm[2];
	unsigned char bias_low_alarm[2];
	unsigned char bias_high_warn[2];
	unsigned char bias_low_warn[2];

	unsigned char tx_power_high_alarm[2];
	unsigned char tx_power_low_alarm[2];
	unsigned char reserved3[4];

	unsigned char reserved4[8];

	unsigned char vendor_specific2[16];
	unsigned char reserved5[2];
	unsigned char vendor_specific3[12];
	unsigned char rx_ampl[2];
	unsigned char rx_tx_sq_disable;
	unsigned char rx_output_disable;
	unsigned char chan_monit_mask[12];
	unsigned char reserved6[2];

};

struct sfp_plus_info_s {
	struct sfp_plus_field_a0_s sfp_plus_info_a0;
	struct sfp_plus_field_00_s sfp_plus_info_00;
	struct sfp_field_01_s sfp_plus_info_01;
	struct sfp_field_02_s sfp_plus_info_02;
	struct sfp_field_03_s sfp_plus_info_03;
};

/* SFF-8472 Rev 10.4 */
struct unf_sfp_data_field_a0_s {
	/* Offset 0~63 */
	struct {
		unsigned char id;
		unsigned char id_ext;
		unsigned char connector;
		unsigned char atransceiver[8];
		unsigned char encoding;
		/* Nominal signalling rate, units of 100MBd. */
		unsigned char br_nominal;
		/* Type of rate select functionality */
		unsigned char rate_identifier;
		/* Link length supported for single mode fiber, units of km */
		unsigned char length_smf_km;
		/* Link length supported for single mode fiber,
		 * units of 100 m
		 */
		unsigned char length_smf;
		/* Link length supported for 50 um OM2 fiber, units of 10 m */
		unsigned char length_smf_om2;
		/* Link length supported for 62.5 um OM1 fiber, units of 10 m */
		unsigned char length_smf_om1;
		/* Link length supported for copper or direct attach cable,
		 * units of m
		 */
		unsigned char length_cable;
		/* Link length supported for 50 um OM3 fiber, units of 10 m */
		unsigned char length_om3;
		unsigned char vendor_name[16]; /* ASCII */
		/* Code for electronic or optical compatibility */
		unsigned char transceiver;
		unsigned char vendor_oui[3]; /* SFP vendor IEEE company ID */
		/* Part number provided by SFP vendor (ASCII) */
		unsigned char vendor_pn[16];
		/* Revision level for part number provided by vendor (ASCII) */
		unsigned char vendor_rev[4];
		/* Laser wavelength (Passive/Active Cable
		 * Specification Compliance)
		 */
		unsigned char wave_length[2];
		unsigned char unallocated;
		/* Check code for Base ID Fields (addresses 0 to 62) */
		unsigned char cc_base;
	} base_id_fields;

	/* Offset 64~95 */
	struct {
		unsigned char options[2];
		unsigned char br_max;
		unsigned char br_min;
		unsigned char vendor_sn[16];
		unsigned char date_code[8];
		unsigned char diag_monitoring_type;
		unsigned char enhanced_options;
		unsigned char sff8472_compliance;
		unsigned char cc_ext;
	} ext_id_fields;

	/* Offset 96~255 */
	struct {
		unsigned char vendor_spec_eeprom[32];
		unsigned char rsvd[128];
	} vendor_spec_id_fields;
};

struct unf_sfp_data_field_a2_s {
	/* Offset 0~119 */
	struct {
		/* 0~39 */
		struct {
			unsigned char temp_alarm_high[2];
			unsigned char temp_alarm_low[2];
			unsigned char temp_warning_high[2];
			unsigned char temp_warning_low[2];

			unsigned char vcc_alarm_high[2];
			unsigned char vcc_alarm_low[2];
			unsigned char vcc_warning_high[2];
			unsigned char vcc_warning_low[2];

			unsigned char bias_alarm_high[2];
			unsigned char bias_alarm_low[2];
			unsigned char bias_warning_high[2];
			unsigned char bias_warning_low[2];

			unsigned char tx_alarm_high[2];
			unsigned char tx_alarm_low[2];
			unsigned char tx_warning_high[2];
			unsigned char tx_warning_low[2];

			unsigned char rx_alarm_high[2];
			unsigned char rx_alarm_low[2];
			unsigned char rx_warning_high[2];
			unsigned char rx_warning_low[2];
		} alarm_warn_th;

		unsigned char unallocated0[16];
		unsigned char ext_cal_constants[36];
		unsigned char unallocated1[3];
		unsigned char cc_dmi;

		/* 96~105 */
		struct {
			unsigned char temp[2];
			unsigned char vcc[2];
			unsigned char tx_bias[2];
			unsigned char tx_power[2];
			unsigned char rx_power[2];
		} diag;

		unsigned char unallocated2[4];

		struct {
			unsigned char data_rdy_bar_state : 1;
			unsigned char rx_los : 1;
			unsigned char tx_fault_state : 1;
			unsigned char soft_rate_select_state : 1;
			unsigned char rate_select_state : 1;
			unsigned char rs_state : 1;
			unsigned char soft_tx_disable_select : 1;
			unsigned char tx_disable_state : 1;
		} status_ctrl;
		unsigned char rsvd;

		/* 112~113 */
		struct {
			/* 112 */
			unsigned char tx_alarm_low : 1;
			unsigned char tx_alarm_high : 1;
			unsigned char tx_bias_alarm_low : 1;
			unsigned char tx_bias_alarm_high : 1;
			unsigned char vcc_alarm_low : 1;
			unsigned char vcc_alarm_high : 1;
			unsigned char temp_alarm_low : 1;
			unsigned char temp_alarm_high : 1;

			/* 113 */
			unsigned char rsvd : 6;
			unsigned char rx_alarm_low : 1;
			unsigned char rx_alarm_high : 1;
		} alarm;

		unsigned char unallocated3[2];

		/* 116~117 */
		struct {
			/* 116 */
			unsigned char tx_warn_lo : 1;
			unsigned char tx_warn_hi : 1;
			unsigned char bias_warn_lo : 1;
			unsigned char bias_warn_hi : 1;
			unsigned char vcc_warn_lo : 1;
			unsigned char vcc_warn_hi : 1;
			unsigned char temp_warn_lo : 1;
			unsigned char temp_warn_hi : 1;

			/* 117 */
			unsigned char rsvd : 6;
			unsigned char rx_warn_lo : 1;
			unsigned char rx_warn_hi : 1;
		} warning;

		unsigned char ext_status_and_ctrl[2];
	} diag;

	/* Offset 120~255 */
	struct {
		unsigned char vendor_spec[8];
		unsigned char user_eeprom[120];
		unsigned char vendor_ctrl[8];
	} general_use_fields;
};

struct unf_sfp_info_s {
	struct unf_sfp_data_field_a0_s sfp_info_a0;
	struct unf_sfp_data_field_a2_s sfp_info_a2;
};

union unf_sfp_eeprome_info {
	struct unf_sfp_info_s sfp_info;
	struct sfp_plus_info_s sfp_plus_info;
};

/* sfp info end */
struct unf_lport_sfp_info {
	unsigned int status;
	union unf_sfp_eeprome_info sfp_eeprom_info;
};

struct unf_err_code_s {
	unsigned int loss_of_signal_count;
	unsigned int bad_rx_char_count;
	unsigned int loss_of_sync_count;
	unsigned int link_fail_count;
	unsigned int rx_eo_fa_count;
	unsigned int dis_frame_count;
	unsigned int bad_crc_count;
	unsigned int proto_error_count;
};

/* config file */
enum unf_scsi_mode_e {
	UNF_PORT_MODE_UNKNOWN = 0x00,
	UNF_PORT_MODE_TGT = 0x10,
	UNF_PORT_MODE_INI = 0x20,
	UNF_PORT_MODE_BOTH = 0x30
};

enum unf_port_upgrade_e {
	UNF_PORT_UNSUPPORT_UPGRADE_REPORT = 0x00,
	UNF_PORT_SUPPORT_UPGRADE_REPORT = 0x01,
	UNF_PORT_UPGRADE_BUTT
};

#define UNF_BYTES_OF_DWORD 0x4
static inline void __attribute__((unused)) unf_big_end_to_cpu(
				unsigned char *v_buffer, unsigned int v_size)
{
	unsigned int *buffer = NULL;
	unsigned int word_sum = 0;
	unsigned int i = 0;

	if (!v_buffer)
		return;

	buffer = (unsigned int *)v_buffer;

	/* byte to word */
	if (v_size % UNF_BYTES_OF_DWORD == 0)
		word_sum = v_size / UNF_BYTES_OF_DWORD;
	else
		return;

	/* word to byte */
	while (i < word_sum) {
		*buffer = be32_to_cpu(*buffer);
		buffer++;
		i++;
	}
}

static inline void __attribute__((unused)) unf_cpu_to_big_end(
					void *v_buffer, unsigned int v_size)
{
#define DWORD_BIT 32
#define BYTE_BIT  8
	unsigned int *buffer = NULL;
	unsigned int word_sum = 0;
	unsigned int i = 0;
	unsigned int tmp = 0;

	if (!v_buffer)
		return;

	buffer = (unsigned int *)v_buffer;

	/* byte to dword */
	word_sum = v_size / 4;

	/* dword to byte */
	while (i < word_sum) {
		*buffer = cpu_to_be32(*buffer);
		buffer++;
		i++;
	}

	if (v_size % 4) {
		tmp = cpu_to_be32(*buffer);
		tmp = tmp >> (DWORD_BIT - (v_size % 4) * BYTE_BIT);
		memcpy(buffer, &tmp, (v_size % 4));
	}
}

#define UNF_FUNCTION_RETURN_CHECK(ret, dstlen) \
	do { \
		if (((ret) <= 0) || ((ret) >= (dstlen))) { \
			UNF_TRACE(UNF_EVTLOG_DRIVER_ERR, \
				  UNF_LOG_REG_ATT, UNF_ERR, \
				  "function return (%d) check invalid, dst len(%d).", \
				  (ret), (dstlen)); \
		} \
	} while (0)

#define UNF_TOP_AUTO_MASK 0x0f

#define UNF_NORMAL_MODE		  0
#define UNF_SET_NOMAL_MODE(mode) (mode = UNF_NORMAL_MODE)

/*
 * SCSI status
 */
#define SCSI_CHECK_CONDITION	   0x02

enum unf_act_topo_e {
	UNF_ACT_TOP_PUBLIC_LOOP = 0x1,
	UNF_ACT_TOP_PRIVATE_LOOP = 0x2,
	UNF_ACT_TOP_P2P_DIRECT = 0x4,
	UNF_ACT_TOP_P2P_FABRIC = 0x8,
	UNF_TOP_LOOP_MASK = 0x03,
	UNF_TOP_P2P_MASK = 0x0c,
	UNF_TOP_FCOE_MASK = 0x30,
	UNF_ACT_TOP_UNKNOWN
};

#define UNF_FL_PORT_LOOP_ADDR 0x00

#define UNF_FC_PROTOCOL_TYPE   0x100

#define UNF_LOOP_ROLE_MASTER_OR_SLAVE 0x0

#define UNF_TOU16_CHECK(dest, src, over_action) \
	do { \
		if (unlikely((src) > 0xFFFF)) { \
			UNF_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_REG_ATT, \
				  UNF_ERR, "ToU16 error, src 0x%x ", (src)); \
			over_action; \
		} \
	   ((dest) = (unsigned short)(src)); \
	} while (0)

#define UNF_PORT_SPEED_AUTO 0
#define UNF_PORT_SPEED_2_G  2
#define UNF_PORT_SPEED_4_G  4
#define UNF_PORT_SPEED_8_G  8
#define UNF_PORT_SPEED_10_G 10
#define UNF_PORT_SPEED_16_G 16
#define UNF_PORT_SPEED_32_G 32

#define UNF_PORT_SPEED_UNKNOWN (~0)
#define UNF_PORT_SFP_SPEED_ERR 0xFF

#define UNF_FW_VERSION_LEN    32
#define UNF_HW_VERSION_LEN    32

/* max frame size */
#define UNF_MAX_FRAME_SIZE 2112

/* default */
#define UNF_DEFAULT_FRAME_SIZE          2048
#define UNF_DEFAULT_EDTOV               2000
#define UNF_DEFAULT_RATOV               10000
#define UNF_DEFAULT_FABRIC_RATOV        10000
#define UNF_MAX_RETRY_COUNT             3
#define UNF_DEFAULT_RRTOV               (10000 + 500) /* FCP-4 10.4.10 */
#define UNF_RRQ_MIN_TIMEOUT_INTERVAL    30000
#define UNF_LOGO_TIMEOUT_INTERVAL       3000
#define UNF_WRITE_RRQ_SENDERR_INTERVAL  3000
#define UNF_REC_TOV                     3000

#define UNF_WAIT_SEM_TIMEOUT      (5000UL)
#define UNF_WAIT_ABTS_RSP_TIMEOUT (20000UL)

#define UNF_INI_RRQ_REDUNDANT_TIME 500
#define UNF_INI_ELS_REDUNDANT_TIME 2000

/* ELS command values */
#define UNF_ELS_CMND_HIGH_MASK 0xff000000
#define UNF_ELS_CMND_RJT       0x01000000
#define UNF_ELS_CMND_ACC       0x02000000
#define UNF_ELS_CMND_PLOGI     0x03000000
#define UNF_ELS_CMND_FLOGI     0x04000000
#define UNF_ELS_CMND_LOGO      0x05000000
#define UNF_ELS_CMND_RLS       0x0F000000
#define UNF_ELS_CMND_ECHO      0x10000000
#define UNF_ELS_CMND_REC       0x13000000
#define UNF_ELS_CMND_RRQ       0x12000000
#define UNF_ELS_CMND_PRLI      0x20000000
#define UNF_ELS_CMND_PRLO      0x21000000
#define UNF_ELS_CMND_PDISC     0x50000000
#define UNF_ELS_CMND_FDISC     0x51000000
#define UNF_ELS_CMND_ADISC     0x52000000
#define UNF_ELS_CMND_FAN       0x60000000
#define UNF_ELS_CMND_RSCN      0x61000000
#define UNF_FCP_CMND_SRR       0x14000000
#define UNF_GS_CMND_SCR        0x62000000

#define UNF_PLOGI_VERSION_UPPER  0x20
#define UNF_PLOGI_VERSION_LOWER  0x20
#define UNF_PLOGI_CONCURRENT_SEQ 0x00FF
#define UNF_PLOGI_RO_CATEGORY    0x00FE
#define UNF_PLOGI_SEQ_PER_XCHG   0x0001

/* CT_IU pream defines */
#define UNF_REV_NPORTID_INIT 0x01000000
#define UNF_FSTYPE_OPT_INIT  0xfc020000
#define UNF_FSTYPE_RFT_ID    0x02170000
#define UNF_FSTYPE_GID_PT    0x01A10000
#define UNF_FSTYPE_GID_FT    0x01710000
#define UNF_FSTYPE_RFF_ID    0x021F0000
#define UNF_FSTYPE_GFF_ID    0x011F0000
#define UNF_FSTYPE_GNN_ID    0x01130000
#define UNF_FSTYPE_GPN_ID    0x01120000

#define UNF_CT_IU_RSP_MASK    0xffff0000
#define UNF_CT_IU_REASON_MASK 0x00ff0000
#define UNF_CT_IU_EXPLAN_MASK 0x0000ff00
#define UNF_CT_IU_REJECT      0x80010000
#define UNF_CT_IU_ACCEPT      0x80020000

#define UNF_FABRIC_FULL_REG    0x00000003

#define UNF_FC4_SCSI_BIT8      0x00000100
#define UNF_FC4_FCP_TYPE       0x00000008
#define UNF_FRAG_REASON_VENDOR 0

/* GID_PT, GID_FT */
#define UNF_GID_PT_TYPE 0x7F000000
#define UNF_GID_FT_TYPE 0x00000008

/*
 * FC4 defines
 */
#define UNF_FC4_FRAME_PAGE_SIZE       0x10
#define UNF_FC4_FRAME_PAGE_SIZE_SHIFT 16

#define UNF_FC4_FRAME_PARM_0_FCP           0x08000000
#define UNF_FC4_FRAME_PARM_0_I_PAIR        0x00002000
#define UNF_FC4_FRAME_PARM_0_GOOD_RSP_CODE 0x00000100

#define UNF_FC4_FRAME_PARM_3_INI                   0x00000020
#define UNF_FC4_FRAME_PARM_3_TGT                   0x00000010
#define UNF_FC4_FRAME_PARM_3_R_XFER_DIS            0x00000002
#define UNF_FC4_FRAME_PARM_3_CONF_ALLOW            0x00000080 /* bit 7 */
#define UNF_FC4_FRAME_PARM_3_REC_SUPPORT           0x00000400 /* bit 10 */
#define UNF_FC4_FRAME_PARM_3_TASK_RETRY_ID_SUPPORT 0x00000200 /* bit 9 */
#define UNF_FC4_FRAME_PARM_3_RETRY_SUPPORT         0x00000100 /* bit 8 */
#define UNF_FC4_FRAME_PARM_3_CONF_ALLOW            0x00000080 /* bit 7 */


#define UNF_GFF_ACC_MASK                   0xFF000000

/* Reject CT_IU Reason Codes */
#define UNF_CTIU_RJT_MASK            0xffff0000
#define UNF_CTIU_RJT_INVALID_COMMAND 0x00010000
#define UNF_CTIU_RJT_INVALID_VERSION 0x00020000
#define UNF_CTIU_RJT_LOGIC_ERR       0x00030000
#define UNF_CTIU_RJT_INVALID_SIZE    0x00040000
#define UNF_CTIU_RJT_LOGIC_BUSY      0x00050000
#define UNF_CTIU_RJT_PROTOCOL_ERR    0x00070000
#define UNF_CTIU_RJT_UNABLE_PERFORM  0x00090000
#define UNF_CTIU_RJT_NOT_SUPPORTED   0x000B0000

/* FS_RJT Reason code explanations, FC-GS-2 6.5 */
#define UNF_CTIU_RJT_EXP_MASK            0x0000FF00
#define UNF_CTIU_RJT_EXP_NO_ADDTION      0x00000000
#define UNF_CTIU_RJT_EXP_PORTID_NO_REG   0x00000100
#define UNF_CTIU_RJT_EXP_PORTNAME_NO_REG 0x00000200
#define UNF_CTIU_RJT_EXP_NODENAME_NO_REG 0x00000300
#define UNF_CTIU_RJT_EXP_FC4TYPE_NO_REG  0x00000700
#define UNF_CTIU_RJT_EXP_PORTTYPE_NO_REG 0x00000A00

/*
 * LS_RJT defines
 */
#define UNF_FC_LS_RJT_REASON_MASK 0x00ff0000

/*
 * LS_RJT reason code defines
 */
#define UNF_LS_OK                  0x00000000
#define UNF_LS_RJT_INVALID_COMMAND 0x00010000
#define UNF_LS_RJT_LOGICAL_ERROR   0x00030000
#define UNF_LS_RJT_BUSY            0x00050000
#define UNF_LS_RJT_PROTOCOL_ERROR  0x00070000
#define UNF_LS_RJT_REQUEST_DENIED  0x00090000
#define UNF_LS_RJT_NOT_SUPPORTED   0x000b0000
#define UNF_LS_RJT_CLASS_ERROR     0x000c0000

/*
 * LS_RJT code explanation
 */
#define UNF_LS_RJT_NO_ADDITIONAL_INFO       0x00000000
#define UNF_LS_RJT_INV_DATA_FIELD_SIZE      0x00000700
#define UNF_LS_RJT_INV_COMMON_SERV_PARAM    0x00000F00
#define UNF_LS_RJT_INVALID_OXID_RXID        0x00001700
#define UNF_LS_RJT_COMMAND_IN_PROGRESS      0x00001900
#define UNF_LS_RJT_INSUFFICIENT_RESOURCES   0x00002900
#define UNF_LS_RJT_COMMAND_NOT_SUPPORTED    0x00002C00
#define UNF_LS_RJT_UNABLE_TO_SUPLY_REQ_DATA 0x00002A00
#define UNF_LS_RJT_INVALID_PAYLOAD_LENGTH   0x00002D00

#define UNF_P2P_LOCAL_NPORT_ID  0x000000EF
#define UNF_P2P_REMOTE_NPORT_ID 0x000000D6

#define UNF_BBCREDIT_MANAGE_NFPORT  0
#define UNF_BBCREDIT_MANAGE_LPORT   1
#define UNF_BBCREDIT_LPORT          0
#define UNF_CONTIN_INCREASE_SUPPORT 1
#define UNF_CLASS_VALID             1
#define UNF_CLASS_INVALID           0
#define UNF_NOT_MEANINGFUL          0
#define UNF_NO_SERVICE_PARAMS       0
#define UNF_CLEAN_ADDRESS_DEFAULT   0
#define UNF_PRIORITY_ENABLE         1
#define UNF_PRIORITY_DISABLE        0
#define UNF_SEQUEN_DELIVERY_REQ     1 /* Sequential delivery requested */

/* RSCN */
#define UNF_RSCN_PORT_ADDR         0x0
#define UNF_RSCN_AREA_ADDR_GROUP   0x1
#define UNF_RSCN_DOMAIN_ADDR_GROUP 0x2
#define UNF_RSCN_FABRIC_ADDR_GROUP 0x3

#define UNF_GET_RSCN_PLD_LEN(v_cmnd) ((v_cmnd)&0x0000ffff)
#define UNF_RSCN_PAGE_LEN                  0x4

#define UNF_PORT_LINK_UP                   0x0000
#define UNF_PORT_LINK_DOWN                 0x0001
#define UNF_PORT_RESET_START               0x0002
#define UNF_PORT_RESET_END                 0x0003
#define UNF_PORT_LINK_UNKNOWN              0x0004
#define UNF_PORT_NOP                       0x0005
#define UNF_PORT_CORE_FATAL_ERROR          0x0006
#define UNF_PORT_CORE_UNRECOVERABLE_ERROR  0x0007
#define UNF_PORT_CORE_RECOVERABLE_ERROR    0x0008
#define UNF_PORT_UPDATE_PROCESS            0x000b
#define UNF_PORT_DEBUG_DUMP                0x000c
#define UNF_PORT_GET_FWLOG                 0x000d
#define UNF_PORT_CLEAN_DONE                0x000e
#define UNF_PORT_BEGIN_REMOVE              0x000f
#define UNF_PORT_RELEASE_RPORT_INDEX       0x0010
#define UNF_PORT_ABNORMAL_RESET            0x0012

#define UNF_READ     0
#define UNF_WRITE    1
#define UNF_READ_64  2
#define UNF_WRITE_64 3
/*
 *SCSI begin
 */
#define SCSIOPC_TEST_UNIT_READY  0x00
#define SCSIOPC_INQUIRY          0x12
#define SCSIOPC_MODE_SENSE_6     0x1A
#define SCSIOPC_MODE_SENSE_10    0x5A
#define SCSIOPC_MODE_SELECT_6    0x15
#define SCSIOPC_RESERVE          0x16
#define SCSIOPC_RELEASE          0x17
#define SCSIOPC_START_STOP_UNIT  0x1B
#define SCSIOPC_READ_CAPACITY_10 0x25
#define SCSIOPC_READ_CAPACITY_16 0x9E
#define SCSIOPC_READ_6           0x08
#define SCSIOPC_READ_10          0x28
#define SCSIOPC_READ_12          0xA8
#define SCSIOPC_READ_16          0x88
#define SCSIOPC_WRITE_6          0x0A
#define SCSIOPC_WRITE_10         0x2A
#define SCSIOPC_WRITE_12         0xAA
#define SCSIOPC_WRITE_16         0x8A
#define SCSIOPC_WRITE_VERIFY     0x2E
#define SCSIOPC_VERIFY_10        0x2F
#define SCSIOPC_VERIFY_12        0xAF
#define SCSIOPC_VERIFY_16        0x8F
#define SCSIOPC_REQUEST_SENSE    0x03
#define SCSIOPC_REPORT_LUN       0xA0
#define SCSIOPC_FORMAT_UNIT      0x04
#define SCSIOPC_SEND_DIAGNOSTIC  0x1D
#define SCSIOPC_WRITE_SAME_10    0x41
#define SCSIOPC_WRITE_SAME_16    0x93
#define SCSIOPC_READ_BUFFER      0x3C
#define SCSIOPC_WRITE_BUFFER     0x3B

#define SCSIOPC_LOG_SENSE                0x4D
#define SCSIOPC_MODE_SELECT_10           0x55
#define SCSIOPC_SYNCHRONIZE_CACHE_10     0x35
#define SCSIOPC_SYNCHRONIZE_CACHE_16     0x91
#define SCSIOPC_WRITE_AND_VERIFY_10      0x2E
#define SCSIOPC_WRITE_AND_VERIFY_12      0xAE
#define SCSIOPC_WRITE_AND_VERIFY_16      0x8E
#define SCSIOPC_READ_MEDIA_SERIAL_NUMBER 0xAB
#define SCSIOPC_REASSIGN_BLOCKS          0x07
#define SCSIOPC_ATA_PASSTHROUGH_16       0x85
#define SCSIOPC_ATA_PASSTHROUGH_12       0xa1

/*
 * SCSI end
 */
#define IS_READ_COMMAND(opcode) ((opcode) == SCSIOPC_READ_6 || \
				 (opcode) == SCSIOPC_READ_10 || \
				 (opcode) == SCSIOPC_READ_12 || \
				 (opcode) == SCSIOPC_READ_16)
#define IS_WRITE_COMMAND(opcode) ((opcode) == SCSIOPC_WRITE_6 || \
				  (opcode) == SCSIOPC_WRITE_10 || \
				  (opcode) == SCSIOPC_WRITE_12 || \
				  (opcode) == SCSIOPC_WRITE_16)

#define FCP_RSP_LEN_VALID_MASK 0x1
#define FCP_SNS_LEN_VALID_MASK 0x2
#define FCP_RESID_OVER_MASK    0x4
#define FCP_RESID_UNDER_MASK   0x8
#define FCP_CONF_REQ_MASK      0x10
#define FCP_SCSI_STATUS_GOOD   0x0

#define UNF_DELAYED_WORK_SYNC(v_ret, v_pord_id, v_work, v_work_symb) \
	do { \
		if (!cancel_delayed_work_sync(v_work)) { \
			UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_REG_ATT, \
				  UNF_INFO, \
				  "[info]LPort or RPort(0x%x) %s worker can't destroy, or no worker", \
				  v_pord_id, v_work_symb); \
			v_ret = UNF_RETURN_ERROR; \
		} else { \
			v_ret = RETURN_OK; \
		} \
	} while (0)

#define UNF_DELAYED_WORK(v_ret, v_pord_id, v_work, v_work_symb) \
	do { \
		if (!cancel_delayed_work(v_work)) { \
			UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_REG_ATT, \
				  UNF_MAJOR, \
				  "LPort or RPort(0x%x) %s worker can't destroy, or no worker.", \
				  v_pord_id, v_work_symb); \
			v_ret = UNF_RETURN_ERROR; \
		} else { \
			v_ret = RETURN_OK; \
		} \
	} while (0)

#define UNF_DELAYED_WORK_CONFUSED(v_ret, v_pord_id, v_work, v_work_symb) \
	do { \
		if (in_interrupt()) { \
			UNF_DELAYED_WORK(v_ret, v_pord_id, v_work, \
					 v_work_symb) \
		} else { \
			UNF_DELAYED_WORK_SYNC(v_ret, v_pord_id, v_work, \
					      v_work_symb) \
		} \
	} while (0)

#define UNF_GET_IO_XCHG_TAG(v_pkg) \
	((unsigned short)((v_pkg)->private[PKG_PRIVATE_XCHG_HOT_POOL_INDEX]))

#define UNF_GET_SFS_ENTRY(v_pkg) ((union unf_sfs_u *)(void *) \
	(((struct unf_frame_pkg_s *)v_pkg)->unf_cmnd_pload_bl.buffer_ptr))

/* FLOGI */
#define UNF_GET_FLOGI_PAYLOAD(v_pkg) (&(((union unf_sfs_u *) \
			(UNF_GET_SFS_ENTRY(v_pkg)))->flogi.flogi_payload))
#define UNF_FLOGI_PAYLOAD_LEN sizeof(struct unf_flogi_payload_s)

/* FLOGI  ACC */
#define UNF_GET_FLOGI_ACC_PAYLOAD(v_pkg) (&(((union unf_sfs_u *) \
			(UNF_GET_SFS_ENTRY(v_pkg)))->flogi_acc.flogi_payload))
#define UNF_FLOGI_ACC_PAYLOAD_LEN sizeof(struct unf_flogi_payload_s)

/* FDISC */
#define UNF_FDISC_PAYLOAD_LEN     UNF_FLOGI_PAYLOAD_LEN
#define UNF_FDISC_ACC_PAYLOAD_LEN UNF_FLOGI_ACC_PAYLOAD_LEN

/* PLOGI */
#define UNF_GET_PLOGI_PAYLOAD(v_pkg) \
	(&(((union unf_sfs_u *)(UNF_GET_SFS_ENTRY(v_pkg)))->plogi.payload))
#define UNF_PLOGI_PAYLOAD_LEN sizeof(struct unf_plogi_payload_s)

/* PLOGI  ACC */
#define UNF_GET_PLOGI_ACC_PAYLOAD(v_pkg) \
	(&(((union unf_sfs_u *)(UNF_GET_SFS_ENTRY(v_pkg)))->plogi_acc.payload))
#define UNF_PLOGI_ACC_PAYLOAD_LEN sizeof(struct unf_plogi_payload_s)

/* LOGO */
#define UNF_LOGO_PAYLOAD_LEN sizeof(struct unf_logo_payload_s)

/* ECHO */
#define UNF_GET_ECHO_PAYLOAD(v_pkg) \
	(((union unf_sfs_u *)(UNF_GET_SFS_ENTRY(v_pkg)))->echo.echo_pld)

/* ECHO PHYADDR */
#define UNF_GET_ECHO_PAYLOAD_PHYADDR(v_pkg) \
	(((union unf_sfs_u *)(UNF_GET_SFS_ENTRY(v_pkg)))->echo.phy_echo_addr)

#define UNF_ECHO_PAYLOAD_LEN sizeof(struct unf_echo_payload_s)

/* RLS */
#define UNF_RLS_PAYLOAD_LEN sizeof(struct unf_rls_payload_s)

/* ECHO ACC */
#define UNF_ECHO_ACC_PAYLOAD_LEN sizeof(struct unf_echo_payload_s)
/* REC */
#define UNF_REC_PAYLOAD_LEN sizeof(struct unf_rec_pld_s)

/* REC ACC */
#define UNF_GET_REC_ACC_PAYLOAD(v_pkg) \
	(&(((union unf_sfs_u *)(UNF_GET_SFS_ENTRY(v_pkg)))->els_acc.cmnd))

#define UNF_REC_ACC_PAYLOAD_LEN (sizeof(struct unf_els_acc_s) - \
				sizeof(struct unf_fchead_s))

/* RRQ */
#define UNF_RRQ_PAYLOAD_LEN (sizeof(struct unf_rrq_s) - \
			     sizeof(struct unf_fchead_s))

/* PRLI */
#define UNF_PRLI_PAYLOAD_LEN sizeof(struct unf_pril_payload_s)

/* PRLI ACC */
#define UNF_PRLI_ACC_PAYLOAD_LEN sizeof(struct unf_pril_payload_s)

/* PRLO */
#define UNF_PRLO_PAYLOAD_LEN sizeof(struct unf_pril_payload_s)

#define UNF_PRLO_ACC_PAYLOAD_LEN sizeof(struct unf_pril_payload_s)

/* PDISC */
#define UNF_PDISC_PAYLOAD_LEN sizeof(struct unf_plogi_payload_s)

/* PDISC  ACC */
#define UNF_PDISC_ACC_PAYLOAD_LEN sizeof(struct unf_plogi_payload_s)

/* ADISC */
#define UNF_ADISC_PAYLOAD_LEN sizeof(struct unf_adisc_payload_s)

/* ADISC  ACC */
#define UNF_ADISC_ACC_PAYLOAD_LEN sizeof(struct unf_adisc_payload_s)

/* RSCN ACC */
#define UNF_GET_RSCN_ACC_PAYLOAD(v_pkg) \
	(&(((union unf_sfs_u *)(UNF_GET_SFS_ENTRY(v_pkg)))->els_acc.cmnd))
#define UNF_RSCN_ACC_PAYLOAD_LEN (sizeof(struct unf_els_acc_s) - \
				  sizeof(struct unf_fchead_s))

/* LOGO ACC */
#define UNF_LOGO_ACC_PAYLOAD_LEN (sizeof(struct unf_els_acc_s) - \
				  sizeof(struct unf_fchead_s))

/* RRQ ACC */
#define UNF_RRQ_ACC_PAYLOAD_LEN (sizeof(struct unf_els_acc_s) - \
				 sizeof(struct unf_fchead_s))

/* RLS ACC */
#define UNF_RLS_ACC_PAYLOAD_LEN (sizeof(struct unf_rls_acc_s) - \
				 sizeof(struct unf_fchead_s))

/* GPN_ID */
#define UNF_GPNID_PAYLOAD_LEN (sizeof(struct unf_gpnid_s) - \
			       sizeof(struct unf_fchead_s))

#define UNF_GPNID_RSP_PAYLOAD_LEN (sizeof(struct unf_gpnid_rsp_s) - \
				   sizeof(struct unf_fchead_s))

/* GNN_ID */
#define UNF_GNNID_PAYLOAD_LEN (sizeof(struct unf_gnnid_s) - \
			       sizeof(struct unf_fchead_s))

#define UNF_GNNID_RSP_PAYLOAD_LEN (sizeof(struct unf_gnnid_rsp_s) - \
				   sizeof(struct unf_fchead_s))

/* GFF_ID */
#define UNF_GFFID_PAYLOAD_LEN (sizeof(struct unf_gffid_s) - \
			       sizeof(struct unf_fchead_s))

#define UNF_GFFID_RSP_PAYLOAD_LEN (sizeof(struct unf_gffid_rsp_s) - \
				   sizeof(struct unf_fchead_s))

/* GID_FT/GID_PT */
#define UNF_GET_GID_PAYLOAD(v_pkg) (&(((union unf_sfs_u *) \
		UNF_GET_SFS_ENTRY(v_pkg))->get_id.gid_req.ctiu_pream))

#define UNF_GID_PAYLOAD_LEN (sizeof(struct unf_ctiu_prem_s) + \
			     sizeof(unsigned int))

#define UNF_GID_ACC_PAYLOAD_LEN sizeof(struct unf_gif_acc_pld_s)

/* RFT_ID */
#define UNF_RFTID_PAYLOAD_LEN (sizeof(struct unf_rftid_s) - \
			       sizeof(struct unf_fchead_s))

#define UNF_RFTID_RSP_PAYLOAD_LEN sizeof(struct unf_ctiu_prem_s)

/* RFF_ID */
#define UNF_RFFID_PAYLOAD_LEN (sizeof(struct unf_rffid_s) - \
			       sizeof(struct unf_fchead_s))

#define UNF_RFFID_RSP_PAYLOAD_LEN sizeof(struct unf_ctiu_prem_s)

/* SRR */
#define UNF_SRR_PAYLOAD_LEN \
	sizeof(struct unf_srr_payload_s)

/* ACC&RJT */
#define UNF_ELS_ACC_RJT_LEN (sizeof(struct unf_els_rjt_s) - \
			     sizeof(struct unf_fchead_s))

/* SCR */
#define UNF_SCR_PAYLOAD_LEN (sizeof(struct unf_scr_s) - \
			     sizeof(struct unf_fchead_s))

#define UNF_SCR_RSP_PAYLOAD_LEN (sizeof(struct unf_els_acc_s) - \
				 sizeof(struct unf_fchead_s))

/**********************************************************/
#define UNF_GET_XCHG_TAG(v_pkg) (((struct unf_frame_pkg_s *) \
			v_pkg)->private[PKG_PRIVATE_XCHG_HOT_POOL_INDEX])

#define UNF_GET_SID(v_pkg) (((struct unf_frame_pkg_s *) \
			v_pkg)->frame_head.csctl_sid & UNF_NPORTID_MASK)
#define UNF_GET_DID(v_pkg) (((struct unf_frame_pkg_s *) \
			v_pkg)->frame_head.rctl_did & UNF_NPORTID_MASK)
#define UNF_GET_OXID(v_pkg) (((struct unf_frame_pkg_s *) \
			v_pkg)->frame_head.oxid_rxid >> 16)
#define UNF_GET_RXID(v_pkg) ((unsigned short)((struct unf_frame_pkg_s *) \
			v_pkg)->frame_head.oxid_rxid)
#define UNF_GET_XFER_LEN(v_pkg) (((struct unf_frame_pkg_s *)v_pkg)->transfer_len)

/* ioc abort */
#define UNF_GETXCHGALLOCTIME(v_pkg) \
	(((struct unf_frame_pkg_s *)v_pkg)->private[PKG_PRIVATE_XCHG_ALLOC_TIME])
#define UNF_SET_XCHG_ALLOC_TIME(pkg, xchg) \
	(((struct unf_frame_pkg_s *)(pkg))->private[PKG_PRIVATE_XCHG_ALLOC_TIME] = \
	(((struct unf_xchg_s *)(xchg))->private[PKG_PRIVATE_XCHG_ALLOC_TIME]))
#define UNF_SET_ABORT_INFO_IOTYPE(pkg, xchg) \
	(((struct unf_frame_pkg_s *)(pkg))->private[PKG_PRIVATE_XCHG_ABORT_INFO] |= \
	(((unsigned char)(((struct unf_xchg_s *)(xchg))->data_direction & 0x7))\
	<< 2))

#define UNF_CHECK_NPORT_FPORT_BIT(els_payload) \
	(((struct unf_flogi_payload_s *)els_payload)->fabric_parms.co_parms.n_port)

#define UNF_N_PORT 0
#define UNF_F_PORT 1

#define UNF_GET_RA_TOV_FROM_PARAMS(params) \
	(((struct unf_fabric_parms_s *)params)->co_parms.r_a_tov)
#define UNF_GET_RT_TOV_FROM_PARAMS(params) \
	(((struct unf_fabric_parms_s *)params)->co_parms.r_t_tov)
#define UNF_GET_E_D_TOV_FROM_PARAMS(params) \
	(((struct unf_fabric_parms_s *)params)->co_parms.e_d_tov)
#define UNF_GET_E_D_TOV_RESOLUTION_FROM_PARAMS(params) \
	(((struct unf_fabric_parms_s *)params)->co_parms.e_d_tov_resolution)
#define UNF_GET_BB_SC_N_FROM_PARAMS(params) \
	(((struct unf_fabric_parms_s *)params)->co_parms.bb_scn)
#define UNF_GET_BB_CREDIT_FROM_PARAMS(params) \
	(((struct unf_fabric_parms_s *)params)->co_parms.bb_credit)
enum unf_pcie_error_code_e {
	UNF_PCIE_ERROR_NONE = 0,
	UNF_PCIE_DATAPARITYDETECTED = 1,
	UNF_PCIE_SIGNALTARGETABORT,
	UNF_PCIE_RECEIVEDTARGETABORT,
	UNF_PCIE_RECEIVEDMASTERABORT,
	UNF_PCIE_SIGNALEDSYSTEMERROR,
	UNF_PCIE_DETECTEDPARITYERROR,
	UNF_PCIE_CORRECTABLEERRORDETECTED,
	UNF_PCIE_NONFATALERRORDETECTED,
	UNF_PCIE_FATALERRORDETECTED,
	UNF_PCIE_UNSUPPORTEDREQUESTDETECTED,
	UNF_PCIE_AUXILIARYPOWERDETECTED,
	UNF_PCIE_TRANSACTIONSPENDING,

	UNF_PCIE_UNCORRECTINTERERRSTATUS,
	UNF_PCIE_UNSUPPORTREQERRSTATUS,
	UNF_PCIE_ECRCERRORSTATUS,
	UNF_PCIE_MALFORMEDTLPSTATUS,
	UNF_PCIE_RECEIVEROVERFLOWSTATUS,
	UNF_PCIE_UNEXPECTCOMPLETESTATUS,
	UNF_PCIE_COMPLETERABORTSTATUS,
	UNF_PCIE_COMPLETIONTIMEOUTSTATUS,
	UNF_PCIE_FLOWCTRLPROTOCOLERRSTATUS,
	UNF_PCIE_POISONEDTLPSTATUS,
	UNF_PCIE_SURPRISEDOWNERRORSTATUS,
	UNF_PCIE_DATALINKPROTOCOLERRSTATUS,
	UNF_PCIE_ADVISORYNONFATALERRSTATUS,
	UNF_PCIE_REPLAYTIMERTIMEOUTSTATUS,
	UNF_PCIE_REPLAYNUMROLLOVERSTATUS,
	UNF_PCIE_BADDLLPSTATUS,
	UNF_PCIE_BADTLPSTATUS,
	UNF_PCIE_RECEIVERERRORSTATUS,

	UNF_PCIE_BUTT
};

#define UNF_DMA_HI32(a) (((a) >> 32) & 0xffffffff)
#define UNF_DMA_LO32(a) ((a) & 0xffffffff)

#define UNF_WWN_LEN 8
#define UNF_MAC_LEN 6

/* send BLS/ELS/BLS REPLY/ELS REPLY/GS/ */
/* rcvd BLS/ELS/REQ DONE/REPLY DONE */
#define UNF_PKG_BLS_REQ         0x0100
#define UNF_PKG_BLS_REQ_DONE    0x0101

#define UNF_PKG_ELS_REQ         0x0200

#define UNF_PKG_ELS_REQ_DONE    0x0201

#define UNF_PKG_ELS_REPLY       0x0202

#define UNF_PKG_ELS_REPLY_DONE  0x0203

#define UNF_PKG_GS_REQ          0x0300

#define UNF_PKG_GS_REQ_DONE     0x0301

#define UNF_PKG_INI_IO          0x0500
#define UNF_PKG_INI_RCV_TGT_RSP 0x0507

/* external sgl struct start */
struct unf_esgl_page_s {
	unsigned long long page_address;
	dma_addr_t esgl_phyaddr;
	unsigned int page_size;
};

struct unf_esgl_s {
	struct list_head entry_esgl;
	struct unf_esgl_page_s page;
};

/* external sgl struct end */
struct unf_frame_payld_s {
	unsigned char *buffer_ptr;
	dma_addr_t buf_dma_addr;
	unsigned int length;
};

enum pkg_private_index_e {
	PKG_PRIVATE_LOWLEVEL_XCHG_ADD = 0,
	PKG_PRIVATE_XCHG_HOT_POOL_INDEX = 1, /* Hot Pool Index */
	PKG_PRIVATE_XCHG_RPORT_INDEX = 2,    /* RPort index */
	PKG_PRIVATE_XCHG_VP_INDEX = 3,       /* VPort index */
	PKG_PRIVATE_RPORT_RX_SIZE,
	PKG_PRIVATE_XCHG_TIMEER,
	PKG_PRIVATE_XCHG_ALLOC_TIME,
	PKG_PRIVATE_XCHG_ABORT_INFO,
	PKG_PRIVATE_ECHO_CMD_SND_TIME, /* local send echo cmd time stamp */
	PKG_PRIVATE_ECHO_ACC_RCV_TIME, /* local receive echo acc time stamp */
	PKG_PRIVATE_ECHO_CMD_RCV_TIME, /* remote receive echo cmd time stamp */
	PKG_PRIVATE_ECHO_RSP_SND_TIME, /* remote send echo rsp time stamp */
	PKG_MAX_PRIVATE_DATA_SIZE
};

extern unsigned int dix_flag;
extern unsigned int dif_sgl_mode;
extern unsigned int dif_app_esc_check;
extern unsigned int dif_ref_esc_check;

#define UNF_DIF_ACTION_NONE 0

enum unf_adm_dif_mode_e {
	UNF_SWITCH_DIF_DIX = 0,
	UNF_APP_REF_ESCAPE,
	ALL_DIF_MODE = 20,
};

#define UNF_VERIFY_CRC_MASK (1 << 1)
#define UNF_VERIFY_APP_MASK (1 << 2)
#define UNF_VERIFY_LBA_MASK (1 << 3)

#define UNF_REPLACE_CRC_MASK (1 << 8)
#define UNF_REPLACE_APP_MASK (1 << 9)
#define UNF_REPLACE_LBA_MASK (1 << 10)

#define UNF_DIF_ACTION_MASK   (0xff << 16)
#define UNF_DIF_ACTION_INSERT (0x1 << 16)
#define UNF_DIF_ACTION_VERIFY_AND_DELETE  (0x2 << 16)
#define UNF_DIF_ACTION_VERIFY_AND_FORWARD (0x3 << 16)
#define UNF_DIF_ACTION_VERIFY_AND_REPLACE (0x4 << 16)

#define UNF_DIF_ACTION_NO_INCREASE_REFTAG (0x1 << 24)

#define UNF_DEFAULT_CRC_GUARD_SEED               (0)
#define UNF_CAL_BLOCK_CNT(data_len, sector_size)   ((data_len) / (sector_size))

#define UNF_DIF_DOUBLE_SGL        (1 << 1)
#define UNF_DIF_SECTSIZE_4KB      (1 << 2)
#define UNF_DIF_LBA_NONE_INCREASE (1 << 3)
#define UNF_DIF_TYPE3             (1 << 4)

#define HIFC_DIF_APP_REF_ESC_NOT_CHECK 1
#define HIFC_DIF_APP_REF_ESC_CHECK     0

enum unf_io_state_e {
	UNF_INI_IO = 0,
	UNF_TGT_XFER = 1,
	UNF_TGT_RSP = 2
};

#define UNF_PKG_LAST_RESPONSE     0
#define UNF_PKG_NOT_LAST_RESPONSE 1

#define UNF_PKG_LAST_REQUEST     1
#define UNF_PKG_NOT_LAST_REQUEST 0

struct unf_frame_pkg_s {
	/* pkt type:BLS/ELS/FC4LS/CMND/XFER/RSP */
	unsigned int type;
	unsigned int last_pkg_flag;

#define UNF_FCP_RESPONSE_VALID 0x01
#define UNF_FCP_SENSE_VALID    0x02
	/* resp and sense vailed flag */
	unsigned int response_and_sense_valid_flag;
	unsigned int cmnd;
	struct unf_fchead_s frame_head;
	unsigned int entry_count;
	void *xchg_contex;
	unsigned int transfer_len;
	unsigned int residus_len;
	unsigned int status;
	unsigned int status_sub_code;
	enum unf_io_state_e io_state;
	unsigned int qos_level;

	unsigned int private[PKG_MAX_PRIVATE_DATA_SIZE];

	unsigned char byte_orders;

	struct unf_fcp_cmnd_s *fcp_cmnd;
	struct unf_dif_control_info_s dif_control;
	struct unf_frame_payld_s unf_cmnd_pload_bl;
	struct unf_frame_payld_s unf_rsp_pload_bl;
	struct unf_frame_payld_s unf_sense_pload_bl;
	void *upper_cmd;
	unsigned int abts_maker_status;

};

#define UNF_MAX_SFS_XCHG     2048
#define UNF_RESERVE_SFS_XCHG 128 /* times on exchange mgr num */

struct unf_lport_cfg_item_s {
	unsigned int port_id;
	unsigned int port_mode; /* INI(0x20) TGT(0x10) BOTH(0x30) */
	unsigned int port_topology; /* 0x3:loop , 0xc:p2p  ,0xf:auto */
	unsigned int max_queue_depth;
	unsigned int max_io; /* Recommended Value 512-4096 */
	unsigned int max_login;
	unsigned int max_sfs_xchg;
	/* 0:auto 1:1Gbps 2:2Gbps 4:4Gbps 8:8Gbps 16:16Gbps */
	unsigned int port_speed;
	unsigned int tape_support; /* tape support */
	unsigned int fcp_conf; /* fcp confirm support */
	unsigned int bb_scn;
	unsigned int sum_resource;
	enum int_e res_mgmt_enabled;
};

struct unf_port_dynamic_info_s {
	unsigned int sfp_posion;
	unsigned int sfp_valid;
	unsigned int phy_link;
	unsigned int firmware_state;
	unsigned int cur_speed;
	unsigned int mailbox_timeout_cnt;
};

struct unf_hinicam_pkg {
	unsigned int msg_format;
	void *buff_in;
	void *buff_out;
	unsigned int in_size;
	unsigned int *out_size;
};

struct unf_version_str_s {
	char *buf;
	unsigned int buf_len;
};

struct unf_buf_s {
	unsigned char *cbuf;
	unsigned int buf_len;
};

struct unf_rw_reg_param_s {
	unsigned int rw_type;
	unsigned int offset;
	unsigned long long value;
};

/* get ucode & up ver */
#define HIFC_VER_LEN          (16)
#define HIFC_COMPILE_TIME_LEN (20)
struct unf_fw_version_s {
	unsigned int message_type;
	unsigned char fw_version[HIFC_VER_LEN];
};

enum unf_port_config_set_op_e {
	UNF_PORT_CFG_SET_SPEED,
	UNF_PORT_CFG_SET_TOPO,
	UNF_PORT_CFG_SET_BBSCN,
	UNF_PORT_CFG_SET_MODE,
	UNF_PORT_CFG_SET_SFP_SWITCH,
	UNF_PORT_CFG_SET_PORT_SWITCH,
	UNF_PORT_CFG_SET_POWER_STATE,
	UNF_PORT_CFG_SET_PORT_STATE,
	UNF_PORT_CFG_SET_INTR_COALSEC,
	UNF_PORT_CFG_UPDATE_PORT,
	UNF_PORT_CFG_UPDATE_WWN,
	UNF_PORT_CFG_TEST_FLASH,
	UNF_PORT_CFG_SET_FCP_CONF,
	UNF_PORT_CFG_SET_LOOP_ROLE,
	UNF_PORT_CFG_SET_INIT_REQ,
	UNF_PORT_CFG_SET_MAX_SUPPORT_SPEED,
	UNF_PORT_CFG_SET_MAC_ADDR,
	UNF_PORT_CFG_SET_SFP_USEDTIME,
	UNF_PORT_CFG_SET_PORT_TRANSFER_PARAMETER,
	UNF_PORT_CFG_SET_SFP_REG_WRITE,
	UNF_PORT_CFG_UPDATE_SFP,
	UNF_PORT_CFG_UPDATE_FABRIC_PARAM,
	UNF_PORT_CFG_UPDATE_PLOGI_PARAM,
	UNF_PORT_CFG_UPDATE_FDISC_PARAM,
	UNF_PORT_CFG_SAVE_HBA_INFO,
	UNF_PORT_CFG_SET_HBA_BASE_INFO,
	UNF_PORT_CFG_SET_FLASH_DATA_INFO,
	UNF_PORT_CFG_SET_BUTT
};

enum unf_port_config_get_op_e {
	UNF_PORT_CFG_GET_SPEED_CFG,
	UNF_PORT_CFG_GET_SPEED_ACT,
	UNF_PORT_CFG_GET_TOPO_CFG,
	UNF_PORT_CFG_GET_TOPO_ACT,
	UNF_PORT_CFG_GET_MODE,
	UNF_PORT_CFG_GET_LOOP_MAP,
	UNF_PORT_CFG_GET_TOV,
	UNF_PORT_CFG_GET_SFP_PRESENT,
	UNF_PORT_CFG_GET_SFP_INFO,
	UNF_PORT_CFG_GET_FW_VER,
	UNF_PORT_CFG_GET_HW_VER,
	UNF_PORT_CFG_GET_LESB_THEN_CLR, /* Link Error Status Block, LESB */
	UNF_PORT_CFG_GET_DYNAMIC_INFO,
	UNF_PORT_CFG_GET_VITAL_REGS,
	UNF_PORT_CFG_CLR_LESB,
	UNF_PORT_CFG_GET_WORKBALE_BBCREDIT,
	UNF_PORT_CFG_GET_WORKBALE_BBSCN,
	UNF_PORT_CFG_GET_FC_SERDES,
	UNF_PORT_CFG_GET_LOOP_ALPA,
	UNF_PORT_CFG_GET_SFP_DYNAMIC_INFO,
	UNF_PORT_CFG_GET_MAC_ADDR,
	UNF_PORT_CFG_GET_SFP_USEDTIME,
	UNF_PORT_CFG_GET_PORT_INFO,
	UNF_PORT_CFG_DDT_TEST,
	UNF_PORT_CFG_GET_LED_STATE,
	UNF_PORT_CFG_GET_VLAN,
	UNF_PORT_CFG_GET_SFP_REG_READ,
	UNF_PORT_CFG_GET_SFP_VER,
	UNF_PORT_CFG_GET_SFP_SUPPORT_UPDATE,
	UNF_PORT_CFG_GET_SFP_LOG,
	UNF_PORT_CFG_GET_FEC,
	UNF_PORT_CFG_GET_PCIE_LINK_STATE,
	UNF_PORT_CFG_GET_FLASH_DATA_INFO,
	UNF_PORT_CFG_GET_BUTT
};

enum unf_port_diag_op_e {
	UNF_PORT_DIAG_PORT_DETAIL,
	UNF_PORT_DIAG_RD_WR_REG,
	UNF_PORT_DIAG_BUTT
};

enum unf_port_config_state_e {
	UNF_PORT_CONFIG_STATE_START,
	UNF_PORT_CONFIG_STATE_STOP,
	UNF_PORT_CONFIG_STATE_RESET,
	UNF_PORT_CONFIG_STATE_STOP_INTR,
	UNF_PORT_CONFIG_STATE_BUTT
};

struct unf_port_login_parms_s {
	enum unf_act_topo_e en_act_topo;

	unsigned int rport_index;
	unsigned int seq_cnt : 1;
	unsigned int ed_tov : 1;
	unsigned int reserved : 14;
	unsigned int tx_mfs : 16;
	unsigned int ed_tov_timer_val;

	unsigned char remote_rttov_tag;
	unsigned char remote_edtov_tag;
	unsigned short remote_bbcredit;
	unsigned short compared_bbscn;
	unsigned int compared_edtov_val;
	unsigned int compared_ratov_val;
	unsigned int els_cmnd_code;
};

#define HIFC_FLASH_MAX_LEN 1024  // bytes

struct unf_mbox_head_info_s {
	/* mbox header */
	unsigned char cmnd_type;
	unsigned char length;
	unsigned char port_id;
	unsigned char pad0;

	/* operation */
	unsigned int op_code : 4;
	unsigned int pad1 : 28;
};

#define HIFC_FLASH_MBOX_HEAD_MAX_LEN 8  // bytes
struct unf_mbox_head_sts_s {
	/* mbox header */
	unsigned char cmnd_type;
	unsigned char length;
	unsigned char port_id;
	unsigned char pad0;

	/* operation */
	unsigned short pad1;
	unsigned char pad2;
	unsigned char status;
};

#define HIFC_FLASH_UEFI_MAX_LEN 16  // bytes
struct unf_flash_uefi_switch_s {
	unsigned char writeflag;
	unsigned char sanbooten;
	unsigned char reserved[14];
};

#define HIFC_MGMT_UEFI_MAGIC_NUM 0xAF
#define HIFC_MGMT_TMO_MAGIC_NUM  0xAE

#define HIFC_FLASH_LINK_TMO_MAX_LEN 16  // bytes
struct unf_flash_link_tmo_s {
	unsigned char writeflag;
	unsigned char link_tmo0;
	unsigned char link_tmo1;
	unsigned char link_tmo2;
	unsigned char link_tmo3;
	unsigned char reserved[11];
};

#define HIFC_FLASH_DATA_MAX_LEN (HIFC_FLASH_MAX_LEN - \
				 HIFC_FLASH_MBOX_HEAD_MAX_LEN)  // bytes
struct unf_flash_data_s {
	struct unf_flash_uefi_switch_s uefi_switch; // 16 bytes
	struct unf_flash_link_tmo_s link_tmo;       // 16 bytes
	/* once the related struct change, the reserved size needs modify */
	unsigned char reserved[HIFC_FLASH_DATA_MAX_LEN - 32];
};

/* size of hifc_flash_data_mgmt not more than 1024 bytes */
struct unf_mbox_flash_data_mgmt_s {
	struct unf_mbox_head_info_s mbox_head;  // 8 bytes
	struct unf_flash_data_s flash_data;
};

struct unf_flash_data_mgmt_sts_s {
	struct unf_mbox_head_sts_s mbox_head;  // 8 bytes
	struct unf_flash_data_s flash_data;
};

struct unf_low_level_service_op_s {
	unsigned int (*pfn_unf_els_send)(void *, struct unf_frame_pkg_s *);
	unsigned int (*pfn_unf_bls_send)(void *, struct unf_frame_pkg_s *);
	unsigned int (*pfn_unf_gs_send)(void *, struct unf_frame_pkg_s *);
	unsigned int (*pfn_unf_fc_4_ls_send)(void *, struct unf_frame_pkg_s *);
	unsigned int (*pfn_unf_cmnd_send)(void *, struct unf_frame_pkg_s *);
	unsigned int (*pfn_ll_relese_xchg_res)(void *,
					       struct unf_frame_pkg_s *);
	unsigned int (*pfn_unf_release_rport_res)(void *, struct
						  unf_rport_info_s *);
	unsigned int (*pfn_unf_get_consumed_res)(void *,
						 struct unf_frame_pkg_s *);
	unsigned int (*pfn_unf_flush_ini_resp_que)(void *);
	unsigned int (*pfn_unf_alloc_rport_res)(void *,
						struct unf_rport_info_s *);
	unsigned int (*pfn_unf_rport_session_rst)(void *,
						  struct unf_rport_info_s *);
};

struct unf_low_level_port_mgr_op_s {
	/* fcport/opcode/input parameter */
	unsigned int (*pfn_ll_port_config_set)
	(void *v_fc_port,
	 enum unf_port_config_set_op_e v_op_code,
	 void *v_para_in);
	/* fcport/opcode/output parameter */
	unsigned int (*pfn_ll_port_config_get)
	(void *v_fc_port,
	 enum unf_port_config_get_op_e v_op_code,
	 void *v_para_out);
	/* fcport/opcode/input parameter/output parameter */
	unsigned int (*pfn_ll_port_diagnose)
	(void *v_fc_port,
	 enum unf_port_diag_op_e v_op_code,
	 void *v_para);

};

struct unf_chip_info_s {
	unsigned char chip_type;
	unsigned char chip_work_mode;
	unsigned char disable_err_flag;
};

struct unf_low_level_function_op_s {
	struct unf_chip_info_s chip_info;
	/* low level type */
	unsigned int low_level_type;
	/* low level name, fc etc. */
	const char *name;
	struct pci_dev *dev;
	unsigned long long sys_node_name;
	unsigned long long sys_port_name;

	struct unf_lport_cfg_item_s lport_cfg_items;

	/* low level Xchg mgr type,
	 * active --alloc oxid and rxid
	 * passtive -- not alloc oxid and rxid
	 */
#define UNF_LOW_LEVEL_MGR_TYPE_ACTIVE   0
#define UNF_LOW_LEVEL_MGR_TYPE_PASSTIVE 1
	const unsigned int xchg_mgr_type;

#define UNF_NO_EXTRA_ABTS_XCHG 0x0
#define UNF_LL_IOC_ABTS_XCHG   0x1
	const unsigned int abts_xchg;
#define UNF_CM_RPORT_SET_QUALIFIER       0x0
#define UNF_CM_RPORT_SET_QUALIFIER_REUSE 0x1
#define UNF_CM_RPORT_SET_QUALIFIER_HIFC  0x2
	/* low level pass-through flag. */
#define UNF_LOW_LEVEL_PASS_THROUGH_FIP          0x0
#define UNF_LOW_LEVEL_PASS_THROUGH_FABRIC_LOGIN 0x1
#define UNF_LOW_LEVEL_PASS_THROUGH_PORT_LOGIN   0x2
	unsigned int pass_through_flag;
	/* low level parameter */
	unsigned int support_max_npiv_num;
	unsigned int support_max_speed;
	unsigned int fc_ser_max_speed;
	unsigned int support_max_rport;
	unsigned int support_max_xid_range;
	unsigned int sfp_type;
	unsigned int update_fw_reset_active;
	unsigned int support_upgrade_report;
	unsigned int multi_conf_support;
	unsigned int port_type;
#define UNF_LOW_LEVEL_RELEASE_RPORT_SYNC  0x0
#define UNF_LOW_LEVEL_RELEASE_RPORT_ASYNC 0x1
	unsigned char rport_release_type;
#define UNF_LOW_LEVEL_SIRT_PAGE_MODE_FIXED 0x0
#define UNF_LOW_LEVEL_SIRT_PAGE_MODE_XCHG  0x1
	unsigned char sirt_page_mode;
	unsigned char sfp_speed;
	/* IO reference */
	struct unf_low_level_service_op_s service_op;
	/* Port Mgr reference */
	struct unf_low_level_port_mgr_op_s port_mgr_op;
	unsigned char chip_id;
};

struct unf_cm_handle_op_s {
	/* return:L_Port */
	void *(*pfn_unf_alloc_local_port)(void *,
					  struct unf_low_level_function_op_s *);
	/* input para:L_Port */
	unsigned int (*pfn_unf_release_local_port)(void *);
	/* input para:lport vn2vnid,output para:ok/err */
	unsigned int (*pfn_unf_set_vn2vn_id)(void *, unsigned int);
	unsigned char (*pfn_unf_get_loop_id)(unsigned int v_port_id);
	/* input para:L_Port, FRAME_PKG_S */
	unsigned int (*pfn_unf_receive_els_pkg)(void *v_lport,
						struct unf_frame_pkg_s *v_pkg);
	/* input para:L_Port, FRAME_PKG_S */
	unsigned int (*pfn_unf_receive_gs_pkg)(void *v_lport,
					       struct unf_frame_pkg_s *v_pkg);
	/* input para:L_Port, FRAME_PKG_S */
	unsigned int (*pfn_unf_receive_bls_pkg)(void *v_lport,
						struct unf_frame_pkg_s *v_pkg);
	/* input para:L_Port, FRAME_PKG_S */
	unsigned int (*pfn_unf_receive_fc4_ls_pkg)(
					void *v_lport,
					struct unf_frame_pkg_s *v_pkg);
	/* input para:L_Port, FRAME_PKG_S */
	unsigned int (*pfn_unf_send_els_done)(void *v_lport,
					      struct unf_frame_pkg_s *v_pkg);
	unsigned int (*pfn_unf_send_fc4_ls_done)(void *v_lport,
						 struct unf_frame_pkg_s *v_pkg);
	/* input para:L_Port, FRAME_PKG_S */
	unsigned int (*pfn_unf_receive_marker_status)(
				void *v_lport, struct unf_frame_pkg_s *v_pkg);
	unsigned int (*pfn_unf_receive_abts_marker_status)(
				void *v_lport, struct unf_frame_pkg_s *v_pkg);
	/* input para:L_Port, FRAME_PKG_S */
	unsigned int (*pfn_unf_receive_ini_rsponse)(
				void *v_lport, struct unf_frame_pkg_s *v_pkg);
	int (*pfn_unf_get_cfg_parms)(char *v_section_name,
				     struct unf_cfg_item_s *v_cfg_parm,
				     unsigned int *v_cfg_value,
				     unsigned int v_item_num);
	unsigned int (*pfn_unf_cm_get_sgl_entry)(void *v_pkg,
						 char   **v_buf,
						 unsigned int *v_buf_len);
	unsigned int (*pfn_unf_cm_get_dif_sgl_entry)(void *v_pkg,
						     char **v_buf,
						     unsigned int *v_buf_len);
	struct unf_esgl_page_s *(*pfn_unf_get_one_free_esgl_page)(
				void *v_lport, struct unf_frame_pkg_s *v_pkg);
	/* input para:L_Port, EVENT */
	unsigned int (*pfn_unf_fc_port_link_event)(void *v_lport,
						   unsigned int v_events,
						   void *v_input);
	unsigned int (*pfn_unf_fcoe_update_fcf_name)(void *v_lport,
						     void *v_input);
	int (*pfn_unf_ioctl_to_com_handler)(void *v_lport,
					    struct unf_hinicam_pkg *v_pkg);
};

unsigned int unf_get_cm_handle_op(struct unf_cm_handle_op_s *v_cm_handle);
int unf_common_init(void);
void unf_common_exit(void);

struct unf_port_info_entry_s {
	unsigned int bb_scn;
	unsigned int speed;
	unsigned int topo;
	unsigned int fec;
};

enum drv_cable_connector_type_e {
	DRV_CABLE_CONNECTOR_NONE,
	DRV_CABLE_CONNECTOR_OPTICAL,
	DRV_CABLE_CONNECTOR_COPPER,
	DRV_CABLE_CONNECTOR_INVALID,
	DRV_CABLE_CONNECTOR_BUTT
};

#endif
