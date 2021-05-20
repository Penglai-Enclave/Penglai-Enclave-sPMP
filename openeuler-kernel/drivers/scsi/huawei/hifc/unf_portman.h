/* SPDX-License-Identifier: GPL-2.0 */
/* Huawei Hifc PCI Express Linux driver
 * Copyright(c) 2017 Huawei Technologies Co., Ltd
 *
 */
#ifndef __UNF_PORT_MAN_H__
#define __UNF_PORT_MAN_H__

#define UNF_LPORT_POLL_TIMER ((unsigned int)(1 * 1000))

#define UNF_MAX_BBSCN_VALUE     14
#define UNF_SAVA_INFO_MODE      0
#define UNF_CLEAN_INFO_MODE     1

#define FC_DRIVE_ACTION_CHECK(condition, fail_do0, fail_do1, return) \
	do {                                                         \
		if (condition) {                                     \
			fail_do0;                                    \
			fail_do1;                                    \
			return;                                      \
		}                                                    \
	} while (0)

/* Used in hifcadm tool */
#define UNF_ENABLE_DIF_DIX_PROT 1
#define UNF_ENABLE_DIF_PROT     2
#define UNF_ENABLE_DIX_PROT     3

#define UNF_DISABLE_IP_CHECKSUM 0
#define UNF_ENABLE_IP_CHECKSUM  1

#define UNF_APP_REF_ESC_BOTH_NOT_CHECK 0
#define UNF_APP_ESC_CHECK              1
#define UNF_REF_ESC_CHECK              2
#define UNF_APP_REF_ESC_BOTH_CHECK     3

struct unf_global_card_thread_s {
	struct list_head list_card_list_head;
	spinlock_t global_card_list_lock;
	unsigned int card_sum;
};

/* Global L_Port MG,manage all L_Port */
struct unf_global_lport_s {
	struct list_head list_lport_list_head;

	/* Temporary list,used in hold list traverse */
	struct list_head list_intergrad_head;

	/* destroy list,used in card remove */
	struct list_head list_destroy_head;

	/* Dirty list,abnormal port */
	struct list_head list_dirty_head;
	spinlock_t global_lport_list_lock;
	unsigned int lport_sum;
	unsigned char dft_mode;
	int b_start_work;
};

struct unf_reset_port_argin {
	unsigned int port_id;
};

struct unf_get_topo_argout {
	unsigned int *topo_cfg;
	enum unf_act_topo_e *en_act_topo;
};

struct unf_set_topo_argin {
	unsigned int port_id;
	unsigned int topo;
};

struct unf_set_bbscn_argin {
	unsigned int port_id;
	unsigned int bb_scn;
};

struct unf_set_sfp_argin {
	unsigned int port_id;
	int turn_on;
};

struct unf_set_speed_argin {
	unsigned int port_id;
	unsigned int *speed;
};

struct unf_get_sfp_argout {
	unsigned int *status;
	union unf_sfp_eeprome_info *sfp_info;
};

struct unf_get_allinfo_argout {
	unsigned int *out_size;
	unsigned int in_size;
	void *out_buf;
	void *in_buf;
	void *lport;
};

struct unf_port_action_s {
	unsigned int action;
	unsigned int (*fn_unf_action)(struct unf_lport_s *v_lport,
				      void *v_input);
};

struct unf_hifcadm_action_s {
	unsigned int hifc_action;
	int (*fn_unf_hifc_action)(struct unf_lport_s *v_lport,
				  struct unf_hinicam_pkg *v_input);
};

struct unf_lport_info {
#define NPIVMAX 255
	unsigned int port_id;
	unsigned int options;
	int b_start_work;
	unsigned int phy_link;
	unsigned int link_up;
	unsigned int act_speed;
	unsigned int cfg_speed;
	unsigned int tape_support;
	unsigned long long port_name;
	unsigned int msi;
	unsigned int ini_io_retry_timeout;
	unsigned int support_max_npiv_num;
	unsigned int act_topo;
	unsigned int port_topology;
	unsigned int fc_ser_max_speed;
	unsigned int loss_of_signal_count;
	unsigned int bad_rx_char_count;
	unsigned int loss_of_sync_count;
	unsigned int link_fail_count;
	unsigned int rx_eo_fa_count;
	unsigned int dis_frame_count;
	unsigned int bad_crc_count;
	unsigned int proto_error_count;
	unsigned int cfg_led_mode;
	unsigned char chip_type;
	unsigned char vport_num;
	unsigned short rsvd1;
	unsigned int vport_id[NPIVMAX];
	unsigned int nport_id;
};

struct unf_admin_msg_head {
	unsigned int size;
	unsigned short status;
	unsigned char success_num;
	unsigned char rsvd;
};

#define UNF_PORT_INFO_SIZE 10

struct unf_adm_cmd {
	struct unf_admin_msg_head msg_head;
	unsigned int arg[UNF_PORT_INFO_SIZE];
};

struct unf_adm_xchg {
	unsigned int aborted;
	unsigned int ini_busy;
	unsigned int tgt_busy;
	unsigned int delay;
	unsigned int free;
	unsigned int wait;
	unsigned int sfs_free;
	unsigned int sfs_busy;
};

enum unf_admin_msg_status_e {
	UNF_ADMIN_MSG_DONE = 0,
	UNF_ADMIN_MSG_INCOMPLETE,
	UNF_ADMIN_MSG_FAILED,
	UNF_ADMIN_MSG_BUTT
};

/* the structure define with fc unf driver */
enum fc_dfx_io_count_type_e {
	FC_HOST_COUNTER = 0,
	FC_HOST_SCSI_CMD_IN_TOTAL,
	FC_HOST_SCSI_CMD_DONE_TOTAL,
	FC_SESSION_COUNTER,
	FC_SESSION_SCSI_CMD_IN,
	FC_SESSION_SCSI_CMD_DONE,
	FC_SRB_COUNT,
};

enum unf_msg_format_e {
	UNF_PORT_SET_OP = 1,
	UNF_TOPO_SET_OP,
	UNF_SPEED_SET_OP,
	UNF_INFO_GET_OP,
	UNF_INFO_CLEAR_OP,
	UNF_SFP_INFO_OP,
	UNF_DFX,
	UNF_FEC_SET = 8,
	UNF_BBSCN,
	UNF_VPORT,
	UNF_LINK_DELAY = 11,
	UNF_DIF,
	UNF_DIF_CONFIG = 14,
	UNF_SAVA_DATA,
	UNF_SHOW_XCHG = 23,
	UNF_PORTSTAT = 24,
	UNF_ALL_INFO_OP = 25,
	FC_LINK_TMO_OPT = 26,
	FC_DRV_LOG_OPT = 27,
	UNF_COMPAT_TEST = 0xFF
};

struct unf_save_info_head_s {
	unsigned int opcode : 4;
	unsigned int type : 4;
	unsigned int entry_num : 8;
	unsigned int next : 16;
};

enum unf_save_info_type_e {
	UNF_SESSION_QOS = 0,
	UNF_PORT_BASE_INFO = 2,
	UNF_SAVE_TYPE_BUTT,
};

struct unf_link_tmo_opt_s {
	struct unf_admin_msg_head head;
	unsigned int link_opt;
	int tmo_value;
	unsigned int sync_all_port;
};

struct unf_log_level_opt_s {
	struct unf_admin_msg_head head;
	unsigned int log_opt;
	unsigned int log_level;
	unsigned int log_fre_qunce;
};

extern struct unf_global_lport_s global_lport_mgr;
extern struct unf_global_card_thread_s card_thread_mgr;
extern struct workqueue_struct *unf_work_queue;

struct unf_lport_s *unf_find_lport_by_port_id(unsigned int v_port_id);
struct unf_lport_s *unf_find_lport_by_scsi_host_id(unsigned int scsi_host_id);
void *unf_lport_create_and_init(
			void *private_data,
			struct unf_low_level_function_op_s *low_level_op);
int unf_cm_reset_port(unsigned int v_port_id);
int unf_cm_sfp_switch(unsigned int v_port_id, int v_bturn_on);
int unf_cm_get_sfp_info(unsigned int v_port_id, unsigned int *v_status,
			union unf_sfp_eeprome_info *v_sfp_info,
			unsigned int *sfp_type);
int unf_cm_set_port_bbscn(unsigned int v_port_id, unsigned int v_bbscn);
int unf_cm_set_port_topo(unsigned int v_port_id, unsigned int v_topo);
int unf_cm_get_port_topo(unsigned int v_port_id,
			 unsigned int *v_topo_cfg,
			 enum unf_act_topo_e *v_en_act_topo);
int unf_cm_clear_port_error_code_sum(unsigned int v_port_id);
unsigned int unf_fc_port_link_event(void *v_lport, unsigned int v_events,
				    void *v_input);
unsigned int unf_release_local_port(void *v_lport);
void unf_lport_route_work(struct work_struct *v_work);
void unf_lport_update_topo(struct unf_lport_s *v_lport,
			   enum unf_act_topo_e v_enactive_topo);
void unf_lport_ref_dec(struct unf_lport_s *v_lport);
unsigned int unf_lport_refinc(struct unf_lport_s *v_lport);
void unf_lport_ref_dec_to_destroy(struct unf_lport_s *v_lport);
int unf_send_event(unsigned int port_id, unsigned int syn_flag,
		   void *argc_in, void *argc_out,
		   int (*p_func)(void *argc_in, void *argc_out));
void unf_port_mgmt_deinit(void);
void unf_port_mgmt_init(void);
int unf_cm_echo_test(unsigned int v_port_id, unsigned int v_nport_id,
		     unsigned int *v_link_delay);
void unf_show_dirty_port(int v_show_only, unsigned int *v_ditry_port_num);
unsigned int unf_get_error_code_sum(struct unf_lport_s *v_lport,
				    struct unf_err_code_s *v_fc_err_code);
int unf_cm_set_port_speed(unsigned int v_port_id, unsigned int *v_speed);
void *unf_lookup_lport_by_nport_id(void *v_lport, unsigned int v_nport_id);
int unf_cmd_adm_handler(void *v_lport, struct unf_hinicam_pkg *v_input);
unsigned int unf_is_lport_valid(struct unf_lport_s *v_lport);
unsigned int unf_cm_save_port_info(unsigned int v_port_id);
unsigned int unf_cm_get_save_info(struct unf_lport_s *v_lport);
unsigned int unf_cm_clear_flush(unsigned int v_port_id);
int unf_lport_reset_port(struct unf_lport_s *v_lport, unsigned int v_flag);
unsigned int unf_register_scsi_host(struct unf_lport_s *v_lport);
void unf_unregister_scsi_host(struct unf_lport_s *v_lport);
int unf_get_link_lose_tmo(struct unf_lport_s *v_lport);
int unf_set_link_lose_tmo(struct unf_lport_s *v_lport, int time_out);
void unf_init_link_lose_tmo(struct unf_lport_s *v_lport);
int unf_set_link_lose_tmo_to_all(int time_out);
void unf_destroy_scsi_id_table(struct unf_lport_s *v_lport);
unsigned int unf_lport_login(struct unf_lport_s *v_lport,
			     enum unf_act_topo_e v_en_act_topo);
unsigned int unf_init_scsi_id_table(struct unf_lport_s *v_lport);
void unf_set_lport_removing(struct unf_lport_s *v_lport);
void unf_lport_release_lw_fun_op(struct unf_lport_s *v_lport);
void unf_disc_state_ma(struct unf_lport_s *v_lport,
		       enum unf_disc_event_e v_event);
unsigned int unf_init_lport_mgr_temp(struct unf_lport_s *v_lport);
void unf_release_lport_mgr_temp(struct unf_lport_s *v_lport);

#endif
