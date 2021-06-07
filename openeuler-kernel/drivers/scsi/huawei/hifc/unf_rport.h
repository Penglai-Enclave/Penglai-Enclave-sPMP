/* SPDX-License-Identifier: GPL-2.0 */
/* Huawei Hifc PCI Express Linux driver
 * Copyright(c) 2017 Huawei Technologies Co., Ltd
 *
 */
#ifndef __UNF_RPORT_H
#define __UNF_RPORT_H

#define UNF_MAX_SCSI_ID         2048
#define UNF_LOSE_TMO            30
#define UNF_RPORT_INVALID_INDEX 0xffff

/* RSCN compare DISC list with local RPort macro */
#define UNF_RPORT_NEED_PROCESS              0x1
#define UNF_RPORT_ONLY_IN_DISC_PROCESS      0x2
#define UNF_RPORT_ONLY_IN_LOCAL_PROCESS     0x3
#define UNF_RPORT_IN_DISC_AND_LOCAL_PROCESS 0x4
#define UNF_RPORT_NOT_NEED_PROCESS          0x5

#define UNF_ECHO_SEND_MAX_TIMES 1

extern struct unf_rport_feature_pool_s *port_fea_pool;

enum unf_rport_login_state_e {
	UNF_RPORT_ST_INIT = 0x1000, /* initialized */
	UNF_RPORT_ST_PLOGI_WAIT,    /* waiting for PLOGI completion */
	UNF_RPORT_ST_PRLI_WAIT,     /* waiting for PRLI completion */
	UNF_RPORT_ST_READY,         /* ready for use */
	UNF_RPORT_ST_LOGO,          /* port logout sent */
	UNF_RPORT_ST_CLOSING,       /* being closed */
	UNF_RPORT_ST_DELETE,        /* port being deleted */
	UNF_RPORT_ST_BUTT
};

enum unf_rport_event_e {
	UNF_EVENT_RPORT_NORMAL_ENTER = 0x9000,
	UNF_EVENT_RPORT_ENTER_PLOGI = 0x9001,
	UNF_EVENT_RPORT_ENTER_PRLI = 0x9002,
	UNF_EVENT_RPORT_READY = 0x9003,
	UNF_EVENT_RPORT_LOGO = 0x9004,
	UNF_EVENT_RPORT_CLS_TIMEOUT = 0x9005,
	UNF_EVENT_RPORT_RECOVERY = 0x9006,
	UNF_EVENT_RPORT_RELOGIN = 0x9007,
	UNF_EVENT_RPORT_LINK_DOWN = 0x9008,
	UNF_EVENT_RPORT_BUTT
};

/* RPort local link state */
enum unf_port_state_e {
	UNF_PORT_STATE_LINKUP = 0x1001,
	UNF_PORT_STATE_LINKDOWN = 0x1002
};

enum unf_rport_reuse_flag_e {
	UNF_RPORT_REUSE_ONLY = 0x1001,
	UNF_RPORT_REUSE_INIT = 0x1002,
	UNF_RPORT_REUSE_RECOVER = 0x1003
};

struct unf_disc_rport_s {
	/* RPort entry */
	struct list_head entry_rport;

	unsigned int nport_id;  /* Remote port NPortID */
	unsigned int disc_done; /* 1:Disc done */
};

struct unf_rport_feature_pool_s {
	struct list_head list_busy_head;
	struct list_head list_free_head;
	void *p_port_feature_pool_addr;
	spinlock_t port_fea_pool_lock;
};

struct unf_rport_feature_recard_s {
	struct list_head entry_feature;
	unsigned long long wwpn;
	unsigned int port_feature;
	unsigned int reserved;
};

struct unf_os_thread_private_data_s {
	struct list_head list;
	spinlock_t spin_lock;
	struct task_struct *thread;
	unsigned int in_process;
	unsigned int cpu_id;
	atomic_t user_count;
};

/* Remote Port struct */
struct unf_rport_s {
	unsigned int max_frame_size;
	unsigned int supported_classes;

	/* Dynamic Attributes */
	/* Remote Port loss timeout in seconds. */
	unsigned int dev_loss_tmo;

	unsigned long long node_name;
	unsigned long long port_name;
	unsigned int nport_id; /* Remote port NPortID */
	unsigned int local_nport_id;

	unsigned int roles;

	/* Remote port local INI state */
	enum unf_port_state_e lport_ini_state;
	enum unf_port_state_e last_lport_ini_state;

	/* Remote port local TGT state */
	enum unf_port_state_e lport_tgt_state;
	enum unf_port_state_e last_lport_tgt_state;

	/* Port Type:fc */
	unsigned int port_type;

	/* RPort reference counter */
	atomic_t rport_ref_cnt;

	/* Pending IO count */
	atomic_t pending_io_cnt;

	/* RPort entry */
	struct list_head entry_rport;

	/* Port State,delay reclaim  when uiRpState == complete. */
	enum unf_rport_login_state_e rp_state;
	unsigned int disc_done; /* 1:Disc done */

	struct unf_lport_s *lport;
	void *rport;
	spinlock_t rport_state_lock;

	/* Port attribution */
	unsigned int ed_tov;
	unsigned int ra_tov;
	unsigned int options;           /* ini or tgt */
	unsigned int last_report_linkup_options;
	unsigned int fcp_conf_needed;   /* INI Rport send FCP CONF flag */
	unsigned int tape_support_needed; /* INI tape support flag */
	unsigned int retries;           /* special req retry times */
	unsigned int logo_retries;      /* logo error recovery retry times */
	unsigned int mas_retries;       /* special req retry times */
	/* Rport alloc jiffies */
	unsigned long long rport_alloc_jifs;

	void *session;

	/* binding with SCSI */
	unsigned int scsi_id;

	/* disc list compare flag */
	unsigned int rscn_position;

	unsigned int rport_index;

	/* RPort timer,closing status */
	struct work_struct closing_work;

	/* RPort timer,rport linkup */
	struct work_struct start_work;

	/* RPort timer,recovery */
	struct delayed_work recovery_work;

	/* RPort timer,TGT mode,PRLI waiting */
	struct delayed_work open_work;

	struct semaphore task_sema;
	/* Callback after rport Ready/delete.[with state:ok/fail].
	 * Creat/free TGT session here
	 * input : L_Port,R_Port,state:ready
	 * --creat session/delete--free session
	 */
	void (*pfn_unf_rport_call_back)(void *, void *, unsigned int);

	struct unf_os_thread_private_data_s *data_thread;
};

#define UNF_IO_RESULT_CNT(v_scsi_table, v_scsi_id, v_io_result)               \
	do {                                                                  \
		if (likely(((v_io_result) < UNF_MAX_IO_RETURN_VALUE) &&       \
		    ((v_scsi_id) < UNF_MAX_SCSI_ID) &&                        \
		    ((v_scsi_table)->wwn_rport_info_table) &&           \
		    (v_scsi_table->wwn_rport_info_table[v_scsi_id].dfx_counter))) {      \
			atomic64_inc(&v_scsi_table->wwn_rport_info_table[v_scsi_id].dfx_counter->io_done_cnt[v_io_result]);       \
		} else {                                                      \
			UNF_TRACE(UNF_EVTLOG_DRIVER_ERR,                      \
				  UNF_LOG_EQUIP_ATT, UNF_ERR,                 \
				  "[err] io return value(0x%x) or scsi_id(0x%x) is invalid", \
				  v_io_result, v_scsi_id);                    \
		}                                                             \
	} while (0)

#define UNF_SCSI_CMD_CNT(v_scsi_table, v_scsi_id, v_io_type)                  \
	do {                                                                  \
		if (likely(((v_io_type) < UNF_MAX_SCSI_CMD) &&                \
		    ((v_scsi_id) < UNF_MAX_SCSI_ID) &&                        \
		    ((v_scsi_table)->wwn_rport_info_table) &&                 \
		    (v_scsi_table->wwn_rport_info_table[v_scsi_id].dfx_counter))) {     \
			atomic64_inc(&((v_scsi_table->wwn_rport_info_table[v_scsi_id]).dfx_counter->scsi_cmd_cnt[v_io_type]));     \
		} else {                                                      \
			UNF_TRACE(UNF_EVTLOG_DRIVER_ERR,                      \
			UNF_LOG_EQUIP_ATT, UNF_ERR,                           \
			"[err] scsi_cmd(0x%x) or scsi_id(0x%x) is invalid",   \
			v_io_type, v_scsi_id);                                \
		}                                                             \
	} while (0)

#define UNF_SCSI_ERROR_HANDLE_CNT(v_scsi_table, v_scsi_id, v_io_type)         \
	do {                                                                  \
		if (likely(((v_io_type) < UNF_SCSI_ERROR_HANDLE_BUTT) &&      \
		    ((v_scsi_id) < UNF_MAX_SCSI_ID) &&                        \
		    ((v_scsi_table)->wwn_rport_info_table) &&                 \
		    (v_scsi_table->wwn_rport_info_table[v_scsi_id].dfx_counter))) {      \
			atomic_inc(&v_scsi_table->wwn_rport_info_table[v_scsi_id].dfx_counter->error_handle[v_io_type]);        \
		} else {                                                      \
			UNF_TRACE(UNF_EVTLOG_DRIVER_ERR,                      \
			UNF_LOG_EQUIP_ATT, UNF_ERR,                           \
			"[err] scsi_cmd(0x%x) or scsi_id(0x%x) is invalid",   \
			v_io_type, v_scsi_id);                                \
		}                                                             \
	} while (0)

#define UNF_SCSI_ERROR_HANDLE_RESULT_CNT(v_scsi_table, v_scsi_id, v_io_type)  \
	do {                                                                  \
		if (likely(((v_io_type) < UNF_SCSI_ERROR_HANDLE_BUTT) &&      \
		    ((v_scsi_id) < UNF_MAX_SCSI_ID) &&                        \
		    ((v_scsi_table)->wwn_rport_info_table) &&                 \
		    (v_scsi_table->wwn_rport_info_table[v_scsi_id].dfx_counter))) { \
			atomic_inc(&v_scsi_table->wwn_rport_info_table[v_scsi_id].dfx_counter->error_handle_result[v_io_type]);  \
		} else {                                                      \
			UNF_TRACE(UNF_EVTLOG_DRIVER_ERR,                      \
			UNF_LOG_EQUIP_ATT, UNF_ERR,                           \
			"[err] scsi_cmd(0x%x) or scsi_id(0x%x) is invalid",   \
			v_io_type, v_scsi_id);                                \
		}                                                             \
	} while (0)

void unf_rport_state_ma(struct unf_rport_s *v_rport,
			enum unf_rport_event_e v_event);
void unf_update_lport_state_by_linkup_event(struct unf_lport_s *v_lport,
					    struct unf_rport_s *v_rport,
					    unsigned int rport_att);
void unf_rport_enter_closing(struct unf_rport_s *v_rport);
void unf_clean_linkdown_rport(struct unf_lport_s *v_lport);
void unf_rport_error_recovery(struct unf_rport_s *v_rport);
struct unf_rport_s *unf_get_rport_by_nport_id(struct unf_lport_s *v_lport,
					      unsigned int nport_id);
void unf_rport_enter_logo(struct unf_lport_s *v_lport,
			  struct unf_rport_s *v_rport);
unsigned int unf_rport_ref_inc(struct unf_rport_s *v_rport);
void unf_rport_ref_dec(struct unf_rport_s *v_rport);

struct unf_rport_s *unf_rport_set_qualifier_key_reuse(
				struct unf_lport_s *v_lport,
				struct unf_rport_s *v_rport_by_nport_id,
				struct unf_rport_s *v_rport_by_wwpn,
				unsigned long long v_wwpn,
				unsigned int v_sid);
void unf_rport_delay_login(struct unf_rport_s *v_rport);
struct unf_rport_s *unf_find_valid_rport(struct unf_lport_s *v_lport,
					 unsigned long long v_wwpn,
					 unsigned int v_sid);
void unf_rport_linkdown(struct unf_lport_s *v_lport,
			struct unf_rport_s *v_rport);
struct unf_rport_s *unf_get_safe_rport(struct unf_lport_s *v_lport,
				       struct unf_rport_s *v_rport,
				       enum unf_rport_reuse_flag_e v_reuse_flag,
				       unsigned int v_nport_id);
void *unf_rport_get_free_and_init(void *v_lport,
				  unsigned int v_port_type,
				  unsigned int v_nport_id);
unsigned int unf_free_scsi_id(struct unf_lport_s *v_lport,
			      unsigned int v_scsi_id);
void unf_schedule_closing_work(struct unf_lport_s *v_lport,
			       struct unf_rport_s *v_rport);
void unf_sesion_loss_timeout(struct work_struct *v_work);
unsigned int unf_get_port_feature(unsigned long long v_wwpn);
void unf_update_port_feature(unsigned long long v_wwpn,
			     unsigned int v_port_feature);

#endif
