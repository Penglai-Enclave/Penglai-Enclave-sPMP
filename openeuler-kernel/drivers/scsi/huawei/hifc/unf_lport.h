/* SPDX-License-Identifier: GPL-2.0 */
/* Huawei Hifc PCI Express Linux driver
 * Copyright(c) 2017 Huawei Technologies Co., Ltd
 *
 */

#ifndef __UNF_LPORT_H
#define __UNF_LPORT_H
#include "unf_disc.h"
#include "unf_event.h"
#include "unf_common.h"

#define UNF_PORT_TYPE_FC           0
#define UNF_PORT_TYPE_DISC         1
#define UNF_FW_UPDATE_PATH_LEN_MAX 255
#define UNF_EXCHG_MGR_NUM (4)

#define UNF_MAX_IO_RETURN_VALUE  0x12
#define UNF_MAX_SCSI_CMD         0xFF

enum unf_scsi_error_handle_type {
	UNF_SCSI_ABORT_IO_TYPE = 0,
	UNF_SCSI_DEVICE_RESET_TYPE,
	UNF_SCSI_TARGET_RESET_TYPE,
	UNF_SCSI_BUS_RESET_TYPE,
	UNF_SCSI_HOST_RESET_TYPE,
	UNF_SCSI_VIRTUAL_RESET_TYPE,
	UNF_SCSI_ERROR_HANDLE_BUTT
};

enum unf_lport_destroy_step_e {
	UNF_LPORT_DESTROY_STEP_0_SET_REMOVING = 0,
	UNF_LPORT_DESTROY_STEP_1_REPORT_PORT_OUT,
	UNF_LPORT_DESTROY_STEP_2_CLOSE_ROUTE,
	UNF_LPORT_DESTROY_STEP_3_DESTROY_EVENT_CENTER,
	UNF_LPORT_DESTROY_STEP_4_DESTROY_EXCH_MGR,
	UNF_LPORT_DESTROY_STEP_5_DESTROY_ESGL_POOL,
	UNF_LPORT_DESTROY_STEP_6_DESTROY_DISC_MGR,
	UNF_LPORT_DESTROY_STEP_7_DESTROY_XCHG_MGR_TMP,
	UNF_LPORT_DESTROY_STEP_8_DESTROY_RPORT_MG_TMP,
	UNF_LPORT_DESTROY_STEP_9_DESTROY_LPORT_MG_TMP,
	UNF_LPORT_DESTROY_STEP_10_DESTROY_SCSI_TABLE,
	UNF_LPORT_DESTROY_STEP_11_UNREG_TGT_HOST,
	UNF_LPORT_DESTROY_STEP_12_UNREG_SCSI_HOST,
	UNF_LPORT_DESTROY_STEP_13_DESTROY_LW_INTERFACE,
	UNF_LPORT_DESTROY_STEP_BUTT
};

enum unf_lport_enhanced_feature_e {
	/* Enhance GFF feature connect even if fail to get GFF feature */
	UNF_LPORT_ENHANCED_FEATURE_ENHANCED_GFF = 0x0001,
	/* Enhance IO balance */
	UNF_LPORT_ENHANCED_FEATURE_IO_TRANSFERLIST = 0x0002,
	/* Enhance IO check */
	UNF_LPORT_ENHANCED_FEATURE_IO_CHECKPOINT = 0x0004,
	/* Close FW ROUTE */
	UNF_LPORT_ENHANCED_FEATURE_CLOSE_FW_ROUTE = 0x0008,
	/* lowest frequency read SFP information */
	UNF_LPORT_ENHANCED_FEATURE_READ_SFP_ONCE = 0x0010,
	UNF_LPORT_ENHANCED_FEATURE_BUTT
};

enum unf_lport_login_state_e {
	UNF_LPORT_ST_ONLINE = 0x2000, /* uninitialized */
	UNF_LPORT_ST_INITIAL,         /* initialized and LinkDown */
	UNF_LPORT_ST_LINK_UP,         /* initialized and Link UP */
	UNF_LPORT_ST_FLOGI_WAIT,      /* waiting for FLOGI completion */
	UNF_LPORT_ST_PLOGI_WAIT,      /* waiting for PLOGI completion */
	UNF_LPORT_ST_RNN_ID_WAIT,     /* waiting for RNN_ID completion */
	UNF_LPORT_ST_RSNN_NN_WAIT,    /* waiting for RSNN_NN completion */
	UNF_LPORT_ST_RSPN_ID_WAIT,    /* waiting for RSPN_ID completion */
	UNF_LPORT_ST_RPN_ID_WAIT,     /* waiting for RPN_ID completion */
	UNF_LPORT_ST_RFT_ID_WAIT,     /* waiting for RFT_ID completion */
	UNF_LPORT_ST_RFF_ID_WAIT,     /* waiting for RFF_ID completion */
	UNF_LPORT_ST_SCR_WAIT,        /* waiting for SCR completion */
	UNF_LPORT_ST_READY,           /* ready for use */
	UNF_LPORT_ST_LOGO,            /* waiting for LOGO completion */
	UNF_LPORT_ST_RESET,           /* being reset and will restart */
	UNF_LPORT_ST_OFFLINE,         /* offline */
	UNF_LPORT_ST_BUTT
};

enum unf_lport_event_e {
	UNF_EVENT_LPORT_NORMAL_ENTER = 0x8000, /* next state enter */
	UNF_EVENT_LPORT_ONLINE = 0x8001,       /* LPort link up */
	UNF_EVENT_LPORT_LINK_UP = 0x8002,      /* LPort link up */
	UNF_EVENT_LPORT_LINK_DOWN = 0x8003,    /* LPort link down */
	UNF_EVENT_LPORT_OFFLINE = 0x8004,      /* lPort bing stopped */
	UNF_EVENT_LPORT_RESET = 0x8005,
	UNF_EVENT_LPORT_REMOTE_ACC = 0x8006,     /* next state enter */
	UNF_EVENT_LPORT_REMOTE_RJT = 0x8007,     /* rport reject */
	UNF_EVENT_LPORT_REMOTE_TIMEOUT = 0x8008, /* rport time out */
	UNF_EVENT_LPORT_READY = 0x8009,
	UNF_EVENT_LPORT_REMOTE_BUTT
};

struct unf_cm_disc_mg_template_s {
	/* start input:L_Port,return:ok/fail */
	unsigned int (*pfn_unf_disc_start)(void *v_lport);

	/* stop input: L_Port,return:ok/fail */
	unsigned int (*pfn_unf_disc_stop)(void *v_lport);

	/* Callback after disc complete[with event:ok/fail]. */
	void (*pfn_unf_disc_callback)(void *v_lport, unsigned int v_result);
};

struct unf_chip_manage_info_s {
	struct list_head list_chip_thread_entry;
	struct list_head list_head;
	spinlock_t chip_event_list_lock;
	struct task_struct *data_thread;
	unsigned int list_num;
	unsigned int slot_id;
	unsigned char chip_id;
	unsigned char rsv;
	unsigned char sfp_9545_fault;  /* 9545 fault */
	unsigned char sfp_power_fault; /* SFP power fault */
	atomic_t ref_cnt;
	unsigned int b_thread_exit;
	struct unf_chip_info_s chip_info;
	atomic_t card_loop_test_flag;
	spinlock_t card_loop_back_state_lock;
	char update_path[UNF_FW_UPDATE_PATH_LEN_MAX];
};

enum unf_timer_type_e {
	UNF_TIMER_TYPE_INI_IO,
	UNF_TIMER_TYPE_REQ_IO,
	UNF_TIMER_TYPE_INI_RRQ,
	UNF_TIMER_TYPE_SFS,
	UNF_TIMER_TYPE_INI_ABTS
};

struct unf_cm_xchg_mgr_template_s {
	/* Get new Xchg */
	/* input:L_Port,ini/tgt type,return:initialized Xchg */
	void *(*pfn_unf_xchg_get_free_and_init)(void *, unsigned int,
						unsigned short);

	/* OXID,SID lookup Xchg */
	/* input: L_Port,OXID,SID,return:Xchg */
	void *(*pfn_unf_look_up_xchg_by_id)(void *, unsigned short,
					    unsigned int);

	/* input:L_Port,tag,return:Xchg */
	void *(*pfn_unf_look_up_xchg_by_tag)(void *, unsigned short);

	/* free Xchg */
	/* input:L_Port,Xchg,return:void */
	void (*pfn_unf_xchg_release)(void *, void *);

	/* Abort IO Xchg by SID/DID */
	/* input:L_Port,SID,DID,return:void */
	void (*pfn_unf_xchg_mgr_io_xchg_abort)(void *, void *, unsigned int,
					       unsigned int, unsigned int);

	/* Abort SFS Xchg by SID/DID */
	/* input:L_Port,SID,DID,return:void */
	void (*pfn_unf_xchg_mgr_sfs_xchg_abort)(void *, void *,
						unsigned int, unsigned int);

	/* Clean Xchg by SID/DID */
	/* input:L_Port,SID,DID,return:void */
	void (*pfn_unf_xchg_mgr_xchg_clean)(void *, unsigned int,
					    unsigned int);

	/* Add Xchg timer */
	void (*pfn_unf_xchg_add_timer)(void *, unsigned long,
				       enum unf_timer_type_e);

	/* Cancel Xchg timer */
	void (*pfn_unf_xchg_cancel_timer)(void *);

	/* L_Port, Abort flag */
	void (*pfn_unf_xchg_abort_all_io)(void *, unsigned int, int);

	/* find Xchg by scsi Cmnd sn */
	void *(*pfn_unf_look_up_xchg_by_cmnd_sn)(void *, unsigned long long,
						 unsigned int);
	/* input:L_Port,unsigned long long */
	void (*pfn_unf_xchg_abort_by_lun)(void *, void *, unsigned long long,
					  void *, int);

	void (*pfn_unf_xchg_abort_by_session)(void *, void *);

};

struct unf_rport_pool_s {
	unsigned int rport_pool_count;
	void *rport_pool_add;
	struct list_head list_rports_pool;
	spinlock_t rport_free_pool_lock;
	/* for synchronous reuse RPort POOL completion */
	struct completion *rport_pool_completion;
	unsigned long *pul_rpi_bitmap;
};

struct unf_cm_lport_template_s {
	/* Get VPort struct and init */
	/* input:pstLport,ini/tgt type,return:pstVport */
	void *(*pfn_unf_vport_get_free_and_init)(void *, unsigned int);

	/* For fast IO path */
	/* input: pstLport, VpIndex, return:pstVport */
	void *(*pfn_unf_lookup_vport_by_vp_index)(void *, unsigned short);

	/* input: pstLport, PortId,return:pstVport */
	void *(*pfn_unf_lookup_vport_by_port_id)(void *, unsigned int);

	/* input:pstLport, wwpn, return:pstVport */
	void *(*pfn_unf_lookup_vport_by_wwpn)(void *, unsigned long long);

	/* input:L_Port, DID, return:pstVport */
	void *(*pfn_unf_lookup_vport_by_did)(void *, unsigned int);

	/* input:L_Port,return:void */
	void (*pfn_unf_vport_remove)(void *);

};

struct unf_vport_pool_s {
	unsigned short vport_pool_count;
	void *vport_pool_addr;
	struct list_head list_vport_pool;
	spinlock_t vport_pool_lock;
	struct completion *vport_pool_completion;
	unsigned short slab_next_index; /* Next free vport */
	unsigned short slab_total_sum;  /* Total Vport num */
	struct unf_lport_s *vport_slab[0];
};

struct unf_esgl_pool_s {
	unsigned int esgl_pool_count;
	void *esgl_pool_addr;
	struct list_head list_esgl_pool;
	spinlock_t esgl_pool_lock;
	struct buf_describe_s esgl_buf_list;
};

/* little endium */
struct unf_port_id_page_s {
	struct list_head list_node_rscn;
	unsigned char port_id_port;
	unsigned char port_id_area;
	unsigned char port_id_domain;

	unsigned char uc_addr_format : 2;
	unsigned char uc_event_qualifier : 4;
	unsigned char uc_reserved : 2;
};

struct unf_rscn_mg_s {
	spinlock_t rscn_id_list_lock;
	unsigned int free_rscn_count;

	/* free RSCN page list */
	struct list_head list_free_rscn_page;

	/* using RSCN page list */
	struct list_head list_using_rscn_page;

	/* All RSCN PAGE Address */
	void *rscn_pool_add;
	struct unf_port_id_page_s *(*pfn_unf_get_free_rscn_node)(
							void *v_rscn_mg);
	void (*pfn_unf_release_rscn_node)(void *v_rscn_mg, void *v_rscn_node);
};

struct unf_disc_rport_mg_s {
	void *disc_pool_add;
	struct list_head list_disc_rports_pool; /* discovery DISC Rport pool */
	struct list_head list_disc_rport_busy; /* Busy discovery DiscRport */
};

struct unf_disc_manage_info_s {
	struct list_head list_head;
	spinlock_t disc_event_list_lock;
	atomic_t disc_contrl_size;

	unsigned int b_thread_exit;
	struct task_struct *data_thread;

};

struct unf_disc_s {
	unsigned int retry_count;    /* current retry counter */
	unsigned int max_retry_count; /* retry counter */
	unsigned int disc_flag;      /* Disc flag :Loop Disc,Fabric Disc */

	struct completion *disc_completion;
	atomic_t disc_ref_cnt;

	struct list_head list_busy_rports;   /* Busy RPort list */
	struct list_head list_delete_rports; /* Delete RPort list */
	struct list_head list_destroy_rports;

	spinlock_t rport_busy_pool_lock;

	struct unf_lport_s *lport;
	enum unf_disc_state_e en_states;
	struct delayed_work disc_work;

	/* Disc operation template */
	struct unf_cm_disc_mg_template_s unf_disc_temp;

	/* UNF_INIT_DISC/UNF_RSCN_DISC */
	unsigned int disc_option;

	/* RSCN list */
	struct unf_rscn_mg_s rscn_mgr;
	struct unf_disc_rport_mg_s disc_rport_mgr;
	struct unf_disc_manage_info_s disc_thread_info;

	unsigned long long last_disc_jiff;
};

enum unf_service_item_e {
	UNF_SERVICE_ITEM_FLOGI = 0,
	UNF_SERVICE_ITEM_PLOGI,
	UNF_SERVICE_ITEM_PRLI,
	UNF_SERVICE_ITEM_RSCN,
	UNF_SERVICE_ITEM_ABTS,
	UNF_SERVICE_ITEM_PDISC,
	UNF_SERVICE_ITEM_ADISC,
	UNF_SERVICE_ITEM_LOGO,
	UNF_SERVICE_ITEM_SRR,
	UNF_SERVICE_ITEM_RRQ,
	UNF_SERVICE_ITEM_ECHO,
	UNF_SERVICE_ITEM_RLS,
	UNF_SERVICE_BUTT
};

/* Link service counter */
struct unf_link_service_collect_s {
	unsigned long long service_cnt[UNF_SERVICE_BUTT];
};

struct unf_pcie_error_count_s {
	unsigned int pcie_error_count[UNF_PCIE_BUTT];
};

#define INVALID_WWPN 0

enum unf_device_scsi_state_e {
	UNF_SCSI_ST_INIT = 0,
	UNF_SCSI_ST_OFFLINE,
	UNF_SCSI_ST_ONLINE,
	UNF_SCSI_ST_DEAD,
	UNF_SCSI_ST_BUTT
};

struct unf_wwpn_dfx_counter_info_s {
	atomic64_t io_done_cnt[UNF_MAX_IO_RETURN_VALUE];
	atomic64_t scsi_cmd_cnt[UNF_MAX_SCSI_CMD];
	atomic64_t target_busy;
	atomic64_t host_busy;
	atomic_t error_handle[UNF_SCSI_ERROR_HANDLE_BUTT];
	atomic_t error_handle_result[UNF_SCSI_ERROR_HANDLE_BUTT];
	atomic_t device_alloc;
	atomic_t device_destroy;
};

#define UNF_MAX_LUN_PER_TARGET 256
struct unf_wwpn_rport_info_s {
	unsigned long long wwpn;
	struct unf_rport_s *rport;    /* Rport which linkup */
	void *lport;                  /* Lport */
	unsigned int target_id;       /* target_id distribute by scsi */
	unsigned int last_en_scis_state;
	atomic_t en_scsi_state;
	struct unf_wwpn_dfx_counter_info_s *dfx_counter;
	struct delayed_work loss_tmo_work;
	int b_need_scan;
	struct list_head fc_lun_list;
};

struct unf_rport_scsi_id_image_s {
	spinlock_t scsi_image_table_lock;
	/* ScsiId Wwpn table */
	struct unf_wwpn_rport_info_s *wwn_rport_info_table;
	unsigned int max_scsi_id;
};

enum unf_lport_dirty_flag_e {
	UNF_LPORT_DIRTY_FLAG_NONE = 0,
	UNF_LPORT_DIRTY_FLAG_XCHGMGR_DIRTY = 0x100,
	UNF_LPORT_DIRTY_FLAG_RPORT_POOL_DIRTY = 0x200,
	UNF_LPORT_DIRTY_FLAG_DISC_DIRTY = 0x400,
	UNF_LPORT_DIRTY_FLAG_BUTT
};

typedef struct unf_rport_s *(*pfn_unf_rport_set_qualifier)(
				struct unf_lport_s *v_lport,
				struct unf_rport_s *v_rport_by_nport_id,
				struct unf_rport_s *v_rport_by_wwpn,
				unsigned long long v_wwpn,
				unsigned int v_sid);
typedef unsigned int (*pfn_unf_tmf_status_recovery)(void *v_rport,
						    void *v_xchg);

enum unf_start_work_state_e {
	UNF_START_WORK_STOP,
	UNF_START_WORK_BEGIN,
	UNF_START_WORK_COMPLETE
};

struct unf_ini_private_info_s {
	unsigned int driver_type; /* Driver Type */
	void *lower; /* driver private pointer */
};

struct unf_product_hosts_info_s {
	void *p_tgt_host;
	unf_scsi_host_s *p_scsi_host;
	struct unf_ini_private_info_s drv_private_info;
	unf_scsi_host_s scsi_host;

};

struct unf_lport_s {
	unsigned int port_type;          /* Port Type: fc */
	atomic_t lport_ref_cnt; /* LPort reference counter */
	void *fc_port;         /* hard adapter hba pointer */
	void *rport;    /* Used for SCSI interface */
	void *vport;

	struct unf_product_hosts_info_s host_info; /* scsi host mg */
	struct unf_rport_scsi_id_image_s rport_scsi_table;
	int b_port_removing;

	int b_port_dir_exchange;

	spinlock_t xchg_mgr_lock;
	struct list_head list_xchg_mgr_head;
	struct list_head list_dirty_xchg_mgr_head;
	void *p_xchg_mgr[UNF_EXCHG_MGR_NUM];
	enum int_e b_priority;
	struct list_head list_vports_head;      /* Vport Mg */
	struct list_head list_intergrad_vports; /* Vport intergrad list */
	struct list_head list_destroy_vports;   /* Vport destroy list */
	/* VPort entry, hook in list_vports_head */
	struct list_head entry_vport;
	struct list_head entry_lport;     /* LPort entry */
	spinlock_t lport_state_lock;      /* UL Port Lock */
	struct unf_disc_s disc;           /* Disc and rport Mg */
	/* rport pool,Vport share Lport pool */
	struct unf_rport_pool_s rport_pool;
	struct unf_esgl_pool_s esgl_pool; /* external sgl pool */
	unsigned int port_id;             /* Port Management ,0x11000 etc. */
	enum unf_lport_login_state_e en_states;
	unsigned int link_up;
	unsigned int speed;

	unsigned long long node_name;
	unsigned long long port_name;
	unsigned long long fabric_node_name;
	unsigned int nport_id;
	unsigned int max_frame_size;
	unsigned int ed_tov;
	unsigned int ra_tov;
	unsigned int rr_tov;

	unsigned int options; /* ini or tgt */
	unsigned int retries;
	unsigned int max_retry_count;

	enum unf_act_topo_e en_act_topo;
	enum int_e b_switch_state;     /* 1---->ON,FALSE---->OFF */
	enum int_e b_bbscn_support;    /* 1---->ON,FALSE---->OFF */

	enum unf_start_work_state_e en_start_work_state;

	/* Xchg Mg operation template */
	struct unf_cm_xchg_mgr_template_s xchg_mgr_temp;
	struct unf_cm_lport_template_s lport_mgr_temp;
	struct unf_low_level_function_op_s low_level_func;
	struct unf_event_mgr event_mgr;     /* Disc and rport Mg */
	struct delayed_work retry_work; /* poll work or delay work */

	struct workqueue_struct *link_event_wq;
	struct workqueue_struct *xchg_wq;

	struct unf_err_code_s err_code_sum; /* Error code counter */
	struct unf_link_service_collect_s link_service_info;
	struct unf_pcie_error_count_s pcie_error_cnt;
	pfn_unf_rport_set_qualifier pfn_unf_qualify_rport; /* Qualify Rport */
	/* tmf marker recovery */
	pfn_unf_tmf_status_recovery pfn_unf_tmf_abnormal_recovery;
	struct delayed_work route_timer_work;         /* L_Port timer route */

	unsigned short vp_index; /* Vport Index, Lport:0 */
	struct unf_vport_pool_s *vport_pool; /* Only for Lport */

	void *root_lport;                        /* Point to physic Lport */
	struct completion *lport_free_completion; /* Free LPort Completion */

#define UNF_LPORT_NOP    1
#define UNF_LPORT_NORMAL 0

	atomic_t port_no_operater_flag;

	unsigned int enhanced_features;           /* Enhanced Features */

	unsigned int destroy_step;
	unsigned int dirty_flag;

	struct unf_lport_sfp_info sfp_info;
	struct unf_chip_manage_info_s *chip_info;

#define UNF_LOOP_BACK_TESTING  1
#define UNF_LOOP_BACK_TEST_END 0

	unsigned char sfp_power_fault_count;
	unsigned char sfp_9545_fault_count;
	unsigned long long last_tx_fault_jif; /* SFP last tx fault jiffies */

	/* Server card: UNF_FC_SERVER_BOARD_32_G(6)for 32G mode,
	 * UNF_FC_SERVER_BOARD_16_G(7)for 16G mode
	 */
	unsigned int card_type;
	atomic_t scsi_session_add_success;
	atomic_t scsi_session_add_failed;
	atomic_t scsi_session_del_success;
	atomic_t scsi_session_del_failed;
	atomic_t add_start_work_failed;
	atomic_t add_closing_work_failed;
	atomic_t device_alloc;
	atomic_t device_destroy;
	atomic_t session_loss_tmo;
	atomic_t alloc_scsi_id;
	atomic_t resume_scsi_id;
	atomic_t reuse_scsi_id;
	atomic64_t last_exchg_mgr_idx;
	atomic64_t exchg_index;

	unsigned int pcie_link_down_cnt;
	int b_pcie_linkdown;
	unsigned char fw_version[HIFC_VER_LEN];

	atomic_t link_lose_tmo;
	atomic_t err_code_obtain_freq;
};

void unf_lport_stat_ma(struct unf_lport_s *v_lport,
		       enum unf_lport_event_e v_event);
void unf_lport_error_recovery(struct unf_lport_s *v_lport);
void unf_set_lport_state(struct unf_lport_s *v_lport,
			 enum unf_lport_login_state_e v_states);
void unf_init_portparms(struct unf_lport_s *v_lport);
unsigned int unf_lport_enter_flogi(struct unf_lport_s *v_lport);
void unf_lport_enter_sns_plogi(struct unf_lport_s *v_lport);
unsigned int unf_init_disc_mgr(struct unf_lport_s *v_pst_lport);
unsigned int unf_init_lport_route(struct unf_lport_s *v_lport);
void unf_destroy_lport_route(struct unf_lport_s *v_lport);
void unf_reset_lport_params(struct unf_lport_s *v_lport);
void unf_cmmark_dirty_mem(struct unf_lport_s *v_lport,
			  enum unf_lport_dirty_flag_e v_etype);

struct unf_lport_s *unf_cm_lookup_vport_by_vp_index(struct unf_lport_s *v_lport,
						    unsigned short v_vp_index);
struct unf_lport_s *unf_cm_lookup_vport_by_did(struct unf_lport_s *v_lport,
					       unsigned int v_did);
struct unf_lport_s *unf_cm_lookup_vport_by_wwpn(struct unf_lport_s *v_lport,
						unsigned long long v_wwpn);
void unf_cm_vport_remove(struct unf_lport_s *v_vport);

#endif
