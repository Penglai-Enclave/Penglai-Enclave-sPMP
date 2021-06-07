/* SPDX-License-Identifier: GPL-2.0 */
/* Huawei Hifc PCI Express Linux driver
 * Copyright(c) 2017 Huawei Technologies Co., Ltd
 *
 */
#ifndef __UNF_FCEXCH_H__
#define __UNF_FCEXCH_H__

#include "unf_scsi_common.h"
#include "unf_lport.h"

#define DRV_VERIFY_CRC_MASK (1 << 1)
#define DRV_VERIFY_APP_MASK (1 << 2)
#define DRV_VERIFY_LBA_MASK (1 << 3)

#define DRV_DIF_CRC_POS 0
#define DRV_DIF_CRC_LEN 2
#define DRV_DIF_APP_POS 2
#define DRV_DIF_APP_LEN 2
#define DRV_DIF_LBA_POS 4
#define DRV_DIF_LBA_LEN 4

enum unf_ioflow_id_e {
	XCHG_ALLOC = 0,
	TGT_RECEIVE_ABTS,
	TGT_ABTS_DONE,
	TGT_IO_SRR,
	SFS_RESPONSE,
	SFS_TIMEOUT,
	INI_SEND_CMND,
	INI_RESPONSE_DONE,
	INI_EH_ABORT,
	INI_EH_DEVICE_RESET,
	INI_EH_BLS_DONE,
	INI_IO_TIMEOUT,
	INI_REQ_TIMEOUT,
	XCHG_CANCEL_TIMER,
	XCHG_FREE_XCHG,
	SEND_ELS,
	IO_XCHG_WAIT,
	XCHG_BUTT
};

enum unf_xchg_type_e {
	UNF_XCHG_TYPE_INI = 0, /* INI IO */
	UNF_XCHG_TYPE_SFS = 1, /* SFS IO */
	UNF_XCHG_TYPE_INVALID
};

enum unf_xchg_mgr_type_e {
	UNF_XCHG_MGR_TYPE_RANDOM = 0,
	UNF_XCHG_MGR_TYPE_FIXED = 1,
	UNF_XCHG_MGR_TYPE_INVALID
};

enum tgt_io_xchg_send_stage_e {
	TGT_IO_SEND_STAGE_NONE = 0,
	TGT_IO_SEND_STAGE_DOING = 1, /* xfer/rsp into queue */
	TGT_IO_SEND_STAGE_DONE = 2,  /* xfer/rsp into queue complete */
	TGT_IO_SEND_STAGE_ECHO = 3,  /* driver handled TSTS */
	TGT_IO_SEND_STAGE_INVALID
};

enum tgt_io_send_result_e {
	TGT_IO_SEND_RESULT_OK = 0,   /* xfer/rsp enqueue succeed */
	TGT_IO_SEND_RESULT_FAIL = 1, /* xfer/rsp enqueue fail */
	TGT_IO_SEND_RESULT_INVALID
};

struct unf_ioflow_id_s {
	char *stage;
};

#define UNF_CHECK_OXID_MATCHED(v_oxid, v_oid, xchg) \
	((v_oxid == xchg->ox_id) && (v_oid == xchg->oid) && \
	(atomic_read(&xchg->ref_cnt) > 0))

#define UNF_CHECK_ALLOCTIME_VALID(lport, xchg_tag, exchg, pkg_alloc_time, \
				  xchg_alloc_time) \
	do {  \
		if (unlikely((pkg_alloc_time != 0) && \
		    (pkg_alloc_time != xchg_alloc_time))) { \
			UNF_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_NORMAL, \
				  UNF_ERR, \
				  "Lport(0x%x_0x%x_0x%x_0x%p) AllocTime is not equal,PKG AllocTime:0x%x,Exhg AllocTime:0x%x", \
				  lport->port_id, lport->nport_id, \
				  xchg_tag, exchg, \
				  pkg_alloc_time, xchg_alloc_time); \
			return UNF_RETURN_ERROR; \
		}; \
		if (unlikely(pkg_alloc_time == 0)) { \
			UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_NORMAL, \
				  UNF_MAJOR, \
				  "Lport(0x%x_0x%x_0x%x_0x%p) pkgtime err,PKG AllocTime:0x%x,Exhg AllocTime:0x%x", \
				  lport->port_id, lport->nport_id, \
				  xchg_tag, exchg, \
				  pkg_alloc_time, xchg_alloc_time); \
		}; \
	} while (0)

#define UNF_GET_DIF_ERROR_LEVEL1(v_xchg, dif_control, check_err_code, \
				 tgt_err_code, default_err_code) \
	do { \
		if (DRV_VERIFY_CRC_MASK & \
		    v_xchg->dif_control.protect_opcode) { \
			if (memcmp(&dif_control->actual_dif[DRV_DIF_CRC_POS], \
				   &dif_control->expected_dif[DRV_DIF_CRC_POS], \
				   DRV_DIF_CRC_LEN) != 0) { \
				tgt_err_code = default_err_code; \
			} \
		} \
	} while (0)

#define UNF_GET_DIF_ERROR_LEVEL2(v_xchg, dif_control, check_err_code, \
				 tgt_err_code, default_err_code) \
	do { \
		if ((check_err_code == tgt_err_code) && \
		    (DRV_VERIFY_LBA_MASK & v_xchg->dif_control.protect_opcode)) { \
			if (memcmp(&dif_control->actual_dif[DRV_DIF_LBA_POS], \
				   &dif_control->expected_dif[DRV_DIF_LBA_POS], \
				   DRV_DIF_LBA_LEN) != 0) { \
				tgt_err_code = default_err_code; \
			} \
		} \
	} while (0)

#define UNF_GET_DIF_ERROR_LEVEL3(v_xchg, dif_control, check_err_code, \
				 tgt_err_code, default_err_code) \
	UNF_GET_DIF_ERROR_LEVEL2(v_xchg, dif_control, check_err_code, \
				 tgt_err_code, default_err_code)

#define UNF_SET_SCSI_CMND_RESULT(v_xchg, v_result) \
	((v_xchg)->scsi_cmnd_info.result = (v_result))

#define UNF_GET_GS_SFS_XCHG_TIMER(v_lport) (3 * \
					    (unsigned long)(v_lport)->ra_tov)

#define UNF_GET_BLS_SFS_XCHG_TIMER(v_lport) (2 * \
					     (unsigned long)(v_lport)->ra_tov)

#define UNF_GET_ELS_SFS_XCHG_TIMER(v_lport) (2 * \
					     (unsigned long)(v_lport)->ra_tov)

#define UNF_XCHG_MGR_FC          0
#define UNF_XCHG_MIN_XID         0x0000
#define UNF_XCHG_MAX_XID         0xffff
#define UNF_ELS_ECHO_RESULT_OK   0
#define UNF_ELS_ECHO_RESULT_FAIL 1

struct unf_xchg_s;
/* Xchg hot pool, busy IO lookup Xchg */
struct unf_xchg_hot_pool_s {
	/* Xchg sum, in hot pool */
	unsigned short total_xchges;
	/* Total number of resources consumedcorresponding to buffer */
	unsigned int total_res_cnt;
	enum int_e wait_state;

	/* pool lock */
	spinlock_t xchg_hot_pool_lock;

	/* Xchg posiontion list */
	struct list_head sfs_busylist;
	struct list_head ini_busylist;
	struct list_head list_destroy_xchg;

	/* Next free hot point */
	unsigned short slab_next_index;
	unsigned short slab_total_sum;
	unsigned short base;

	struct unf_lport_s *lport;

	struct unf_xchg_s *xchg_slab[0];

};

/* FREE POOL of Xchg*/
struct unf_xchg_free_pool_s {
	spinlock_t xchg_free_pool_lock;

	unsigned int fcp_xchg_sum;

	/* IO used Xchg */
	struct list_head list_free_xchg_list;
	unsigned int total_fcp_xchg;

	/* SFS used Xchg */
	struct list_head list_sfs_xchg_list;
	unsigned int total_sfs_xchg;
	unsigned int sfs_xchg_sum;

	struct completion *xchg_mgr_completion;
};

struct unf_big_sfs_s {
	struct list_head entry_big_sfs;
	void *vaddr;
	unsigned int size;
};

struct unf_big_sfs_pool_s {
	void *big_sfs_pool;
	unsigned int free_count;
	struct list_head list_free_pool;
	struct list_head list_busy_pool;
	spinlock_t big_sfs_pool_lock;
};

/* Xchg Manager for vport Xchg */
struct unf_xchg_mgr_s {
	/* MG  type */
	unsigned int mgr_type;

	/* MG entry */
	struct list_head xchg_mgr_entry;

	/* MG attribution */
	unsigned short min_xid;
	unsigned short max_xid;
	unsigned int mem_size;

	/* MG alloced resource */
	void *fcp_mm_start;

	unsigned int sfs_mem_size;
	void *sfs_mm_start;
	dma_addr_t sfs_phy_addr;

	struct unf_xchg_free_pool_s free_pool;
	struct unf_xchg_hot_pool_s *hot_pool;

	struct unf_big_sfs_pool_s st_big_sfs_pool;

	struct buf_describe_s big_sfs_buf_list;
	struct buf_describe_s rsp_buf_list;

};

struct unf_seq_s {
	/* Seq ID */
	unsigned char seq_id;

	/* Seq Cnt */
	unsigned short seq_cnt;

	/* Seq state and len,maybe used for fcoe */
	unsigned short seq_stat;
	unsigned int rec_data_len;
};

union unf_xchg_fcp_sfs_u {
	struct unf_sfs_entry_s sfs_entry;
	struct unf_fcp_rsp_iu_entry_s fcp_rsp_entry;
};

#define UNF_IO_STATE_NEW          0
#define TGT_IO_STATE_SEND_XFERRDY (1 << 2) /* succeed to send XFer rdy */
#define TGT_IO_STATE_RSP          (1 << 5) /* chip send rsp */
#define TGT_IO_STATE_ABORT        (1 << 7)

/* INI Upper-layer Task Management Commands */
#define INI_IO_STATE_UPTASK           (1 << 15)
/* INI Upper-layer timeout Abort flag */
#define INI_IO_STATE_UPABORT          (1 << 16)
#define INI_IO_STATE_DRABORT          (1 << 17) /* INI driver Abort flag */
#define INI_IO_STATE_DONE             (1 << 18) /* INI complete flag */
#define INI_IO_STATE_WAIT_RRQ         (1 << 19) /* INI wait send rrq */
#define INI_IO_STATE_UPSEND_ERR	      (1 << 20) /* INI send fail flag */
/* INI only clear firmware resource flag */
#define INI_IO_STATE_ABORT_RESOURCE   (1 << 21)
/* ioc abort:INI send ABTS ,5S timeout Semaphore,than set 1 */
#define INI_IO_STATE_ABORT_TIMEOUT    (1 << 22)
#define INI_IO_STATE_RRQSEND_ERR      (1 << 23) /* INI send RRQ fail flag */
/* INI busy IO session logo status */
#define INI_IO_STATE_LOGO             (1 << 24)
#define INI_IO_STATE_TMF_ABORT        (1 << 25) /* INI TMF ABORT IO flag */
#define INI_IO_STATE_REC_TIMEOUT_WAIT (1 << 26) /* INI REC TIMEOUT WAIT */
#define INI_IO_STATE_REC_TIMEOUT      (1 << 27) /* INI REC TIMEOUT */

#define TMF_RESPONSE_RECEIVED   (1 << 0)
#define MARKER_STS_RECEIVED     (1 << 1)
#define ABTS_RESPONSE_RECEIVED  (1 << 2)

struct unf_scsi_cmd_info_s {
	unsigned long time_out;
	unsigned long abort_timeout;
	void *scsi_cmnd;
	void (*pfn_done)(struct unf_scsi_cmd_s *);
	ini_get_sgl_entry_buf pfn_unf_get_sgl_entry_buf;
	struct unf_ini_error_code_s *err_code_table; /* error code table */
	char *sense_buf;
	unsigned int err_code_table_cout; /* Size of the error code table */
	unsigned int buf_len;
	unsigned int entry_cnt;
	unsigned int result; /* Stores command execution results */
	unsigned int port_id;
	/* Re-search for rport based on scsiid during retry. Otherwise,
	 * data inconsistency will occur
	 */
	unsigned int scsi_id;
	void *sgl;
};

struct unf_req_sgl_info_s {
	void *sgl;
	void *sgl_start;
	unsigned int req_index;
	unsigned int entry_index;
};

struct unf_els_echo_info_s {
	unsigned long long response_time;
	struct semaphore echo_sync_sema;
	unsigned int echo_result;
};

struct unf_xchg_s {
	/* Mg resouce relative */
	/* list delete from HotPool */
	struct unf_xchg_hot_pool_s *hot_pool;

	/* attach to FreePool */
	struct unf_xchg_free_pool_s *free_pool;
	struct unf_xchg_mgr_s *xchg_mgr;
	struct unf_lport_s *lport;       /* Local LPort/VLPort */
	struct unf_rport_s *rport;       /* Rmote Port */
	struct unf_rport_s *disc_rport;  /* Discover Rmote Port */
	struct list_head list_xchg_entry;
	struct list_head list_abort_xchg_entry;
	spinlock_t xchg_state_lock;

	/* Xchg reference */
	atomic_t ref_cnt;
	atomic_t esgl_cnt;
	int debug_hook;
	/* Xchg attribution */
	unsigned short hot_pool_tag; /* Hot pool tag */
	/* Only used for abort,ox_id
	 * lunrset/logo/plogi/linkdown set to 0xffff
	 */
	unsigned short abort_oxid;
	unsigned int xchg_type;   /* LS,TGT CMND ,REQ,or SCSI Cmnd */
	unsigned short ox_id;
	unsigned short rx_id;
	unsigned int sid;
	unsigned int did;
	unsigned int oid;          /* ID of the exchange initiator */
	unsigned int disc_port_id; /* Send GNN_ID/GFF_ID NPortId */
	unsigned char seq_id;
	unsigned char byte_orders; /* Byte order */
	struct unf_seq_s seq;

	unsigned int cmnd_code;
	unsigned int world_id;
	/* Dif control */
	struct unf_dif_control_info_s dif_control;
	struct dif_info_s dif_info;

	/* IO status Abort,timer out */
	unsigned int io_state;  /* TGT_IO_STATE_E */
	unsigned int tmf_state; /* TMF STATE */
	unsigned int ucode_abts_state;
	unsigned int abts_state;

	/* IO Enqueuing */
	enum tgt_io_xchg_send_stage_e io_send_stage; /* TGT_IO_SEND_STAGE_E */

	/* IO Enqueuing result, success or failure */
	enum tgt_io_send_result_e io_send_result; /* TGT_IO_SEND_RESULT_E */

	/* Whether ABORT is delivered to the chip for IO */
	unsigned char io_send_abort;
	/* Result of delivering ABORT to the chip
	 * (success: UNF_TRUE; failure: UNF_FALSE)
	 */
	unsigned char io_abort_result;

	/* for INI,Indicates the length of the data
	 * transmitted over the PCI link
	 */
	unsigned int data_len;

	/* ResidLen,greater than 0 UnderFlow or Less than Overflow */
	int resid_len;

	/* +++++++++++++++++IO  Special++++++++++++++++++++ */
	/* point to tgt cmnd/req/scsi cmnd */
	/* Fcp cmnd */
	struct unf_fcp_cmnd_s fcp_cmnd;

	struct unf_scsi_cmd_info_s scsi_cmnd_info;

	struct unf_req_sgl_info_s req_sgl_info;

	struct unf_req_sgl_info_s dif_sgl_info;

	unsigned long long cmnd_sn;

	/* timestamp */
	unsigned long long start_jif;
	unsigned long long alloc_jif;

	unsigned long long io_front_jif;

	/* I/O resources to be consumed,Corresponding to buffer */
	unsigned int may_consume_res_cnt;
	/* Number of resources consumed by I/Os. The value is not zero
	 * only when it is sent to the chip
	 */
	unsigned int fact_consume_res_cnt;

	/* scsi req info */
	unsigned int data_direction;

	struct unf_big_sfs_s *big_sfs_buf;

	/* scsi cmnd sense_buffer pointer */
	union unf_xchg_fcp_sfs_u fcp_sfs_union;

	/* One exchange may use several External Sgls */
	struct list_head list_esgls;

	struct unf_els_echo_info_s echo_info;

	/* +++++++++++++++++Task  Special++++++++++++++++++++ */
	struct semaphore task_sema;

	/* for RRQ ,IO Xchg add to SFS Xchg */
	void *io_xchg;

	/* Xchg delay work */
	struct delayed_work timeout_work;

	/* send result callback */
	void (*pfn_ob_callback)(struct unf_xchg_s *);

	/*Response IO callback */
	void (*pfn_callback)(void *v_lport,
			     void *v_rport,
			     void *v_xchg);

	/* Xchg release function */
	void (*pfn_free_xchg)(struct unf_xchg_s *);

	/* +++++++++++++++++low level  Special++++++++++++++++++++ */
	unsigned int private[PKG_MAX_PRIVATE_DATA_SIZE];

	/* ABTS_RSP info */
	struct unf_abts_rsps_s abts_rsps;

	unsigned long long rport_bind_jifs;

	/* sfs exchg ob callback status */
	unsigned int ob_callback_sts;
	unsigned int scsi_id;
	atomic_t delay_flag;
	void *upper_ct;
};

struct unf_esgl_page_s *unf_get_one_free_esgl_page(struct unf_lport_s *v_lport,
						   struct unf_xchg_s *v_xchg);
void unf_release_xchg_mgr_temp(struct unf_lport_s *v_lport);
unsigned int unf_init_xchg_mgr_temp(struct unf_lport_s *v_lport);
unsigned int unf_alloc_xchg_resource(struct unf_lport_s *v_lport);
void unf_free_all_xchg_mgr(struct unf_lport_s *v_lport);
void unf_xchg_mgr_destroy(struct unf_lport_s *v_lport);
unsigned int unf_xchg_ref_inc(struct unf_xchg_s *v_xchg,
			      enum unf_ioflow_id_e v_io_stage);
void unf_xchg_ref_dec(struct unf_xchg_s *v_xchg,
		      enum unf_ioflow_id_e v_io_stage);
struct unf_xchg_mgr_s *unf_get_xchg_mgr_by_lport(struct unf_lport_s *v_lport,
						 unsigned int);
struct unf_xchg_hot_pool_s *unf_get_hot_pool_by_lport(
				struct unf_lport_s *v_lport, unsigned int);
void unf_free_lport_ini_xchg(struct unf_xchg_mgr_s *v_xchg_mgr,
			     int v_done_ini_flag);
struct unf_xchg_s *unf_cm_lookup_xchg_by_cmnd_sn(
					void *v_lport,
					unsigned long long v_command_sn,
					unsigned int v_world_id);
void *unf_cm_lookup_xchg_by_id(void *v_lport, unsigned short v_oxid,
			       unsigned int v_oid);
void unf_cm_xchg_abort_by_lun(struct unf_lport_s *v_lport,
			      struct unf_rport_s *v_rport,
			      unsigned long long v_lun_id,
			      void *v_tm_xchg, int v_abort_all_lun_flag);
void unf_cm_xchg_abort_by_session(struct unf_lport_s *v_lport,
				  struct unf_rport_s *v_rport);

void unf_cm_xchg_mgr_abort_io_by_id(struct unf_lport_s *v_lport,
				    struct unf_rport_s *v_rport,
				    unsigned int v_sid,
				    unsigned int v_did,
				    unsigned int extra_io_stat);
void unf_cm_xchg_mgr_abort_sfs_by_id(struct unf_lport_s *v_lport,
				     struct unf_rport_s *v_rport,
				     unsigned int v_sid,
				     unsigned int v_did);
void unf_cm_free_xchg(void *v_lport, void *v_xchg);
void *unf_cm_get_free_xchg(void *v_lport, unsigned int v_xchg_type);
void *unf_cm_lookup_xchg_by_tag(void *v_lport, unsigned short v_hot_pool_tag);
void unf_release_esgls(struct unf_xchg_s *v_xchg);
void unf_show_all_xchg(struct unf_lport_s *v_lport,
		       struct unf_xchg_mgr_s *v_xchg_mgr);
void unf_destroy_dirty_xchg(struct unf_lport_s *v_lport, int v_show_only);
void unf_wakeup_scsi_task_cmnd(struct unf_lport_s *v_lport);
void unf_set_hot_pool_wait_state(struct unf_lport_s *v_lport,
				 enum int_e v_wait_state);
void unf_free_lport_all_xchg(struct unf_lport_s *v_lport);
bool unf_busy_io_completed(struct unf_lport_s *v_lport);
#endif
