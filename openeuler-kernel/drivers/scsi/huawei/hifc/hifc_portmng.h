/* SPDX-License-Identifier: GPL-2.0 */
/* Huawei Hifc PCI Express Linux driver
 * Copyright(c) 2017 Huawei Technologies Co., Ltd
 *
 */

#ifndef __HIFC_PORTMNG_H__
#define __HIFC_PORTMNG_H__

#include "unf_common.h"
#include "hifc_module.h"
#include "hifc_hba.h"

#define HIFC_PORT_INFO_SIZE       10
#define HIFC_DFX_BACK_INFO_SIZE   406
#define HIFC_DFX_BACK_INFO_SIZE64 203
#define HIFC_GET_DRIVER_VERSION   16
#define HIFC_SET_BBSCN_VALUE      0
#define HIFC_QUERY_BBSCN_VALUE    1
#define HIFC_QUERY_FEC_MODE       2

#define FC_DFX_SEND_INFO_SIZE      5
#define FC_DFX_BACK_INFO_64        203
#define FC_DFX_BACK_INFO_32        406
#define FC_DFX_MAX_IO_RETURN_VALUE 0x12
#define FC_DFX_MAX_SCSI_CMD        0xFF
#define FC_DFX_SCSI_CMD_FIRST_GET  100

struct unf_adm_dfx_session_state {
	unsigned char session1 : 4;
	unsigned char session2 : 4;
};

struct session_counter_s {
	u64 target_busy;
	u64 host_busy;
	u64 remote_port_wwpn;
	u64 local_port_wwpn;
	u32 device_alloc;
	u32 device_destroy;
	u32 scsi_state;
	u32 remote_port_nportid;
	u32 remote_port_state;
	u32 remote_port_scsiid;
	u32 remote_port_index;
	u32 local_port_nportid;
	u32 local_port_ini_state;
	u32 local_port_state;
	u32 port_id;
	u32 host_id;
	u32 target_id;
	u32 abort_io;
	u32 device_reset;
	u32 target_reset;
	u32 bus_reset;
	u32 virtual_reset;
	u32 abort_io_result;
	u32 device_reset_result;
	u32 target_reset_result;
	u32 bus_reset_result;
	u32 virtual_reset_result;
};

enum hifc_adm_msg_status_e {
	HIFC_ADM_MSG_DONE = 0,
	HIFC_ADM_MSG_INCOMPLETE,
	HIFC_ADM_MSG_FAILED,
	HIFC_ADM_MSG_BUTT
};

struct hifc_port_diag_op_s {
	enum unf_port_diag_op_e op_code;
	unsigned int (*pfn_hifc_operation)(void *v_hba, void *v_para);
};

enum hifc_adm_dfx_mod_e {
	/* HBA WQE and SCQE statistic */
	HIFC_TX_RX_STATE_COUNTER = 0,
	/* TX and RX error counter, HBA counter */
	HIFC_TX_RX_ERROR_STATE_COUNTER,
	/* SCQ, AEQ, uP, common uP error counter */
	HIFC_ERROR_STATE_COUNTER,
	/* Link state counter */
	HIFC_LINK_STATE_COUNTER,
	/* Host counter */
	HIFC_HOST_COUNTER,
	/* session counter */
	HIFC_SESSION_COUNTER,
	/* DIF error counter */
	HIFC_DIF_ERROR_COUNTER,
	HIFC_ALL_DFX_TYPE = 50,
};

enum hifc_msg_format_e {
	HIFC_DFX = 7,
	HIFC_FEC_SET,
	HIFC_BBSCN,
	HIFC_PORTSTAT = 24,
	HIFC_ALL_INFO_OP = 25,
	HIFC_COMPAT_TEST = 0xFF
};

struct hifc_adm_msg_head_s {
	unsigned int size;
	unsigned short status;
	unsigned short rsvd;
};

/* port state for fc_portstat */
struct hifc_adm_port_state {
	unsigned int port_id;
	unsigned int rport_num;
	unsigned int init;
	unsigned int offloading;
	unsigned int offloaded;
	unsigned int destroying;
};

/* SQ & IoStat for fc_portstat */
struct hifc_adm_sq {
	unsigned int sq_id;
	unsigned int rport_index;
	unsigned int xid;
	unsigned int cid;
	unsigned int sid;
	unsigned int did;
	unsigned int vpid;
	unsigned int cmd_local_queue_id;
	unsigned int cmd_cqm_queue_id;
	unsigned int sts_local_queue_id;
	unsigned int sts_cqm_queue_id;
	unsigned int cos;
	unsigned int off_load;
	unsigned int cmsn;
	unsigned int pmsn;
	unsigned int db_cnt;
	unsigned int sqe_cnt;
	unsigned int cqe_cnt;
	unsigned int in_sq_cnt;
	unsigned int in_chip_cnt;
};

/* hifcadm fc_portstat struct,that is used to show ListSqinfo from mml */
struct hifc_adm_lsq_info_s {
	struct hifc_adm_msg_head_s msg_head;
	unsigned int cmd[HIFC_PORT_INFO_SIZE];
	struct hifc_adm_port_state port_state;
	struct hifc_adm_sq sq;
	unsigned int mark;
};

struct unf_adm_dfx_host_counter_s {
	unsigned int host_num;
	unsigned int port_id;
	unsigned int scsi_session_add_success;
	unsigned int scsi_session_add_failed;
	unsigned int scsi_session_del_success;
	unsigned int scsi_session_del_failed;
	unsigned int device_alloc;
	unsigned int device_destroy;
	unsigned int session_loss_tmo;
	unsigned int alloc_scsi_id;
	unsigned int reuse_scsi_id;
	unsigned int resume_scsi_id;
	unsigned int add_start_work_failed;
	unsigned int add_closing_work_failed;
	unsigned int abort_io;
	unsigned int device_reset;
	unsigned int target_reset;
	unsigned int bus_reset;
	unsigned int virtual_reset;
	unsigned int abort_io_result;
	unsigned int device_reset_result;
	unsigned int target_reset_result;
	unsigned int bus_reset_result;
	unsigned int virtual_reset_result;
	struct unf_adm_dfx_session_state session_state[1024];
};

/* hifcadm fc_port struct */
struct hifc_adm_cmd_s {
	struct hifc_adm_msg_head_s msg_head;
	unsigned int cmd[HIFC_PORT_INFO_SIZE];
};

/* hifcadm fc_dfx struct */
struct hifc_adm_dfx_cmd_s {
	struct hifc_adm_msg_head_s msg_head;
	unsigned int cmd[HIFC_PORT_INFO_SIZE];
	union {
		unsigned long long result[HIFC_DFX_BACK_INFO_SIZE64];
		struct unf_adm_dfx_host_counter_s host_cnt;
		struct session_counter_s session_cnt;
		unsigned long long scsi_cmd_in;
		unsigned long long scsi_cmd_done;
		unsigned long long target_busy;
		unsigned long long host_busy;
	} unresult;
};

unsigned int hifc_port_diagnose(void *v_hba, enum unf_port_diag_op_e op_code,
				void *v_para);
unsigned int hifc_set_port_speed(void *v_hba, void *v_para_in);
unsigned int hifc_set_port_bbscn(void *v_hba, void *v_para_in);
unsigned int hifc_set_port_state(void *v_hba, void *v_para_in);
unsigned int hifc_set_port_topo(void *v_hba, void *v_para_in);
unsigned int hifc_set_port_fcp_conf(void *v_hba, void *v_para_in);
unsigned int hifc_set_loop_role(void *v_hba, void *v_para_in);
unsigned int hifc_set_max_support_speed(void *v_hba, void *v_para_in);
unsigned int hifc_show_fc_port_detail(void *v_hba, void *v_para);
int hifc_adm(void *uld_dev, unsigned int msg_formate, void *buffin,
	     unsigned int in_size, void *buff_out, unsigned int *out_size);
unsigned int hifc_fec_mode(void *v_hba, struct unf_hinicam_pkg *v_input);
int hifc_set_dfx_mode(void *v_hba, struct unf_hinicam_pkg *v_input);
int hifc_dfx_get_link_state(void *v_hba, void *v_buff_out);
int hifc_dfx_get_error_state(void *v_hba, void *v_buff_out);
int hifc_dfx_get_rxtx_state(void *v_hba, void *v_buff_out);
unsigned int hifc_bbscn_mode(void *v_hba, struct unf_hinicam_pkg *v_input);
unsigned int hifc_port_stat(void *v_hba, struct unf_hinicam_pkg *v_input);
int hifc_dfx_dif_error(void *v_hba, void *v_buff_out, unsigned int v_clear);
unsigned int hifc_set_hba_base_info(void *v_hba, void *v_para_in);

#endif /* __HIFC_PORTMNG_H__ */
