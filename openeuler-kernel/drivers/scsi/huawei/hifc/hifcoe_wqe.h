/* SPDX-License-Identifier: GPL-2.0 */
/* Huawei Hifc PCI Express Linux driver
 * Copyright(c) 2017 Huawei Technologies Co., Ltd
 *
 */
#ifndef __HIFCOE_WQE_H__
#define __HIFCOE_WQE_H__

/*
 * TASK TYPE: in order to compatible wiht EDA, please add new type before BUTT.
 */
enum hifcoe_task_type_e {
	HIFCOE_TASK_T_EMPTY = 0,/* SCQE TYPE: means task type not initialize */

	HIFCOE_TASK_T_IWRITE = 1, /* SQE  TYPE: ini send FCP Write Command */
	HIFCOE_TASK_T_IREAD = 2,/* SQE  TYPE: ini send FCP Read Command */
	/* SCQE TYPE: ini recv fcp rsp for IREAD/IWRITE/ITMF*/
	HIFCOE_TASK_T_IRESP = 3,
	HIFCOE_TASK_T_TCMND = 4,/* NA */
	HIFCOE_TASK_T_TREAD = 5,/* SQE  TYPE: tgt send FCP Read Command */
	/* SQE  TYPE: tgt send FCP Write Command (XFER_RDY) */
	HIFCOE_TASK_T_TWRITE = 6,
	HIFCOE_TASK_T_TRESP = 7,/* SQE  TYPE: tgt send fcp rsp of Read/Write*/
	HIFCOE_TASK_T_TSTS = 8, /* SCQE TYPE: tgt sts for TREAD/TWRITE/TRESP*/
	HIFCOE_TASK_T_ABTS = 9, /* SQE  TYPE: ini send abts request Command */
	HIFCOE_TASK_T_IELS = 10,/* NA */
	HIFCOE_TASK_T_ITMF = 11,/* SQE  TYPE: ini send tmf request Command */
	HIFCOE_TASK_T_CLEAN_UP = 12,/* NA */
	HIFCOE_TASK_T_CLEAN_UP_ALL = 13,/* NA */
	HIFCOE_TASK_T_UNSOLICITED = 14, /* NA */
	HIFCOE_TASK_T_ERR_WARN = 15,/* NA */
	HIFCOE_TASK_T_SESS_EN = 16, /* CMDQ TYPE: enable session */
	HIFCOE_TASK_T_SESS_DIS = 17,/* NA */
	HIFCOE_TASK_T_SESS_DEL = 18,/* NA */
	HIFCOE_TASK_T_RQE_REPLENISH = 19,  /* NA */

	HIFCOE_TASK_T_RCV_TCMND = 20,  /* SCQE TYPE: tgt recv fcp cmd */
	HIFCOE_TASK_T_RCV_ELS_CMD = 21, /* SCQE TYPE: tgt recv els cmd */
	HIFCOE_TASK_T_RCV_ABTS_CMD = 22,/* SCQE TYPE: tgt recv abts cmd */
	/* SCQE TYPE: tgt recv immidiate data */
	HIFCOE_TASK_T_RCV_IMMIDIATE = 23,
	/*
	 * SQE  TYPE: send ESL rsp. PLOGI_ACC, PRLI_ACC will carry the parent
	 * context parameter indication.
	 */

	HIFCOE_TASK_T_ELS_RSP = 24,
	HIFCOE_TASK_T_ELS_RSP_STS = 25, /* SCQE TYPE: ELS rsp sts */

	HIFCOE_TASK_T_ABTS_RSP = 26,/* CMDQ TYPE: tgt send abts rsp */
	HIFCOE_TASK_T_ABTS_RSP_STS = 27,/* SCQE TYPE: tgt abts rsp sts*/

	HIFCOE_TASK_T_ABORT = 28,  /* CMDQ TYPE: tgt send Abort Command */
	HIFCOE_TASK_T_ABORT_STS = 29,   /* SCQE TYPE: Abort sts */

	HIFCOE_TASK_T_ELS = 30, /* SQE  TYPE: send ELS request Command */
	HIFCOE_TASK_T_RCV_ELS_RSP = 31, /* SCQE TYPE: recv ELS response */

	HIFCOE_TASK_T_GS = 32,  /* SQE  TYPE: send GS request Command */
	HIFCOE_TASK_T_RCV_GS_RSP = 33,  /* SCQE TYPE: recv GS response */

	HIFCOE_TASK_T_SESS_EN_STS = 34, /* SCQE TYPE: enable session sts */
	HIFCOE_TASK_T_SESS_DIS_STS = 35,/* NA */
	HIFCOE_TASK_T_SESS_DEL_STS = 36,/* NA */

	HIFCOE_TASK_T_RCV_ABTS_RSP = 37,/* SCQE TYPE: ini recv abts rsp */

	HIFCOE_TASK_T_BUFFER_CLEAR = 38,/* CMDQ TYPE: Buffer Clear */
	HIFCOE_TASK_T_BUFFER_CLEAR_STS = 39,/* SCQE TYPE: Buffer Clear sts */
	HIFCOE_TASK_T_FLUSH_SQ = 40,/* CMDQ TYPE: flush sq */
	HIFCOE_TASK_T_FLUSH_SQ_STS = 41,/* SCQE TYPE: flush sq sts */

	HIFCOE_TASK_T_SESS_RESET = 42,  /* SQE  TYPE: Reset session */
	HIFCOE_TASK_T_SESS_RESET_STS = 43,  /* SCQE TYPE: Reset session sts */
	HIFCOE_TASK_T_RQE_REPLENISH_STS = 44,   /* NA */
	HIFCOE_TASK_T_DUMP_EXCH = 45,   /* CMDQ TYPE: dump exch */
	HIFCOE_TASK_T_INIT_SRQC = 46,   /* CMDQ TYPE: init SRQC */
	HIFCOE_TASK_T_CLEAR_SRQ = 47,   /* CMDQ TYPE: clear SRQ */
	HIFCOE_TASK_T_CLEAR_SRQ_STS = 48,  /* SCQE TYPE: clear SRQ sts */
	HIFCOE_TASK_T_INIT_SCQC = 49,   /* CMDQ TYPE: init SCQC */
	HIFCOE_TASK_T_DEL_SCQC = 50,/* CMDQ TYPE: delete SCQC */
	HIFCOE_TASK_T_TMF_RESP = 51,/* SQE  TYPE: tgt send tmf rsp */
	HIFCOE_TASK_T_DEL_SRQC = 52,/* CMDQ TYPE: delete SRQC */
	/* SCQE TYPE: tgt recv continue immidiate data */
	HIFCOE_TASK_T_RCV_IMMI_CONTINUE = 53,
	HIFCOE_TASK_T_ITMF_RESP = 54,  /* SCQE TYPE: ini recv tmf rsp */
	HIFCOE_TASK_T_ITMF_MARKER_STS = 55,/* SCQE TYPE: tmf marker sts */
	HIFCOE_TASK_T_TACK = 56,
	HIFCOE_TASK_T_SEND_AEQERR = 57,
	HIFCOE_TASK_T_ABTS_MARKER_STS = 58,/* SCQE TYPE: abts marker sts */
	HIFCOE_TASK_T_FLR_CLEAR_IO = 59,/* FLR clear io type*/
	HIFCOE_TASK_T_BUTT
};

/*
 * error code for error report
 */
enum hifcoe_err_code_e {
	FCOE_CQE_COMPLETED = 0,  /* Successful */
	FCOE_SESS_HT_INSERT_FAIL = 1,/* Offload fail: hash insert fail */
	FCOE_SESS_HT_INSERT_DUPLICATE = 2, /* Offload fail: duplicate offload */
	FCOE_SESS_HT_BIT_SET_FAIL = 3, /* Offload fail: bloom filter set fail */
	/* Offload fail: hash delete fail(duplicate delete) */
	FCOE_SESS_HT_DELETE_FAIL = 4,
	FCOE_CQE_BUFFER_CLEAR_IO_COMPLETED = 5, /* IO done in buffer clear */
	/* IO done in session rst mode=1 */
	FCOE_CQE_SESSION_ONLY_CLEAR_IO_COMPLETED = 6,
	/* IO done in session rst mode=3 */
	FCOE_CQE_SESSION_RST_CLEAR_IO_COMPLETED = 7,
	FCOE_CQE_TMF_RSP_IO_COMPLETED = 8, /* IO done in tgt tmf rsp */
	FCOE_CQE_TMF_IO_COMPLETED = 9, /* IO done in ini tmf */
	FCOE_CQE_DRV_ABORT_IO_COMPLETED = 10,/* IO done in tgt abort */
	/* IO done in fcp rsp process. Used for the sceanrio:
	 * 1.abort before cmd
	 * 2.send fcp rsp directly after recv cmd
	 */
	FCOE_CQE_DRV_ABORT_IO_IN_RSP_COMPLETED = 11,
	/* IO done in fcp cmd process. Used for the sceanrio:
	 * 1.abort before cmd
	 * 2.child setup fail
	 */
	FCOE_CQE_DRV_ABORT_IO_IN_CMD_COMPLETED = 12,
	FCOE_CQE_WQE_FLUSH_IO_COMPLETED = 13,/* IO done in FLUSH SQ */
	/* fcp data format check: DIFX check error */
	FCOE_ERROR_CODE_DATA_DIFX_FAILED = 14,
	/* fcp data format check: task_type is not read */
	FCOE_ERROR_CODE_DATA_TASK_TYPE_INCORRECT = 15,
	/* fcp data format check: data offset is not continuous */
	FCOE_ERROR_CODE_DATA_OOO_RO = 16,
	/* fcp data format check: data is over run */
	FCOE_ERROR_CODE_DATA_EXCEEDS_DATA2TRNS = 17,
	/* fcp rsp format check: payload is too short  */
	FCOE_ERROR_CODE_FCP_RSP_INVALID_LENGTH_FIELD = 18,
	/* fcp rsp format check: fcp_conf need, but exch don't hold seq
	 * initiative
	 */
	FCOE_ERROR_CODE_FCP_RSP_CONF_REQ_NOT_SUPPORTED_YET = 19,
	/* fcp rsp format check: fcp_conf is required, but it's the last seq */
	FCOE_ERROR_CODE_FCP_RSP_OPENED_SEQ = 20,
	/* xfer rdy format check: payload is too short */
	FCOE_ERROR_CODE_XFER_INVALID_PAYLOAD_SIZE = 21,
	/* xfer rdy format check: last data out havn't finished */
	FCOE_ERROR_CODE_XFER_PEND_XFER_SET = 22,
	/* xfer rdy format check: data offset is not continuous */
	FCOE_ERROR_CODE_XFER_OOO_RO = 23,
	/* xfer rdy format check: burst len is 0 */
	FCOE_ERROR_CODE_XFER_NULL_BURST_LEN = 24,
	FCOE_ERROR_CODE_REC_TIMER_EXPIRE = 25, /* Timer expire: REC_TIMER */
	FCOE_ERROR_CODE_E_D_TIMER_EXPIRE = 26, /* Timer expire: E_D_TIMER */
	FCOE_ERROR_CODE_ABORT_TIMER_EXPIRE = 27,/* Timer expire: Abort timer */
	/* Abort IO magic number mismatch */
	FCOE_ERROR_CODE_ABORT_MAGIC_NUM_NOT_MATCH = 28,
	/* RX immidiate data cmd pkt child setup fail */
	FCOE_IMMI_CMDPKT_SETUP_FAIL = 29,
	/* RX fcp data sequence id not equal */
	FCOE_ERROR_CODE_DATA_SEQ_ID_NOT_EQUAL = 30,
	FCOE_ELS_GS_RSP_EXCH_CHECK_FAIL = 31,/* ELS/GS exch info check fail */
	FCOE_CQE_ELS_GS_SRQE_GET_FAIL = 32,  /* ELS/GS process get SRQE fail */
	FCOE_CQE_DATA_DMA_REQ_FAIL = 33, /* SMF soli-childdma rsp error */
	FCOE_CQE_SESSION_CLOSED = 34,/* Session is closed */
	FCOE_SCQ_IS_FULL = 35,  /* SCQ is full */
	FCOE_SRQ_IS_FULL = 36,   /* SRQ is full */
	FCOE_ERROR_DUCHILDCTX_SETUP_FAIL = 37, /* dpchild ctx setup fail */
	FCOE_ERROR_INVALID_TXMFS = 38,  /* invalid txmfs */
	/* offload fail,lack of SCQE,through AEQ */
	FCOE_ERROR_OFFLOAD_LACKOF_SCQE_FAIL = 39,
	FCOE_ERROR_INVALID_TASK_ID = 40, /* tx invlaid task id */
	FCOE_ERROR_INVALID_PKT_LEN = 41, /* tx els gs pakcet len check */
	FCOE_CQE_ELS_GS_REQ_CLR_IO_COMPLETED = 42,  /* IO done in els gs tx */
	FCOE_CQE_ELS_RSP_CLR_IO_COMPLETED = 43,  /* IO done in els rsp tx */
	FCOE_ERROR_CODE_RESID_UNDER_ERR = 44 /* FCP RSP RESID ERROR */
};

/* AEQ EVENT TYPE */
enum hifcoe_aeq_evt_type_e {
	/*
	 * SCQ and SRQ not enough, HOST will initiate a operation to associated
	 * SCQ/SRQ
	 */
	FC_AEQ_EVENT_QUEUE_ERROR = 48,
	/* WQE MSN check error,HOST will reset port */
	FC_AEQ_EVENT_WQE_FATAL_ERROR = 49,
	/* serious chip error, HOST will reset chip */
	FC_AEQ_EVENT_CTX_FATAL_ERROR = 50,
	FC_AEQ_EVENT_OFFLOAD_ERROR = 51,

	FC_FC_AEQ_EVENT_TYPE_LAST
};

enum hifcoe_aeq_evt_err_code_e {
	/* detail type of resource lack  */
	FC_SCQ_IS_FULL_ERR = 0,
	FC_SRQ_IS_FULL_ERR,

	/* detail type of FC_AEQ_EVENT_WQE_FATAL_ERROR  */
	FC_SQE_CHILD_SETUP_WQE_MSN_ERR = 2,
	FC_SQE_CHILD_SETUP_WQE_GPA_ERR,
	FC_CMDPKT_CHILD_SETUP_INVALID_WQE_ERR_1,
	FC_CMDPKT_CHILD_SETUP_INVALID_WQE_ERR_2,
	FC_CLEAEQ_WQE_ERR,
	FC_WQEFETCH_WQE_MSN_ERR,
	FC_WQEFETCH_QUINFO_ERR,

	/* detail type of FC_AEQ_EVENT_CTX_FATAL_ERROR  */
	FC_SCQE_ERR_BIT_ERR = 9,
	FC_UPDMA_ADDR_REQ_SRQ_ERR,
	FC_SOLICHILDDMA_ADDR_REQ_ERR,
	FC_UNSOLICHILDDMA_ADDR_REQ_ERR,
	FC_SQE_CHILD_SETUP_QINFO_ERR_1,
	FC_SQE_CHILD_SETUP_QINFO_ERR_2,
	FC_CMDPKT_CHILD_SETUP_QINFO_ERR_1,
	FC_CMDPKT_CHILD_SETUP_QINFO_ERR_2,
	FC_CMDPKT_CHILD_SETUP_PMSN_ERR,
	FC_CLEAEQ_CTX_ERR,
	FC_WQEFETCH_CTX_ERR,
	FC_FLUSH_QPC_ERR_LQP,
	FC_FLUSH_QPC_ERR_SMF,
	FC_PREFETCH_QPC_ERR_1,
	FC_PREFETCH_QPC_ERR_2,
	FC_PREFETCH_QPC_ERR_3,
	FC_PREFETCH_QPC_ERR_4,
	FC_PREFETCH_QPC_ERR_5,
	FC_PREFETCH_QPC_ERR_6,
	FC_PREFETCH_QPC_ERR_7,
	FC_PREFETCH_QPC_ERR_8,
	FC_PREFETCH_QPC_ERR_9,
	FC_PREFETCH_QPC_ERR_10,
	FC_PREFETCH_QPC_ERR_11,
	FC_PREFETCH_QPC_ERR_DEFAULT,
	FC_CHILDHASH_INSERT_SW_ERR,
	FC_CHILDHASH_LOOKUP_SW_ERR,
	FC_CHILDHASH_DEL_SW_ERR,
	FC_FLOWHASH_INSERT_SW_ERR,
	FC_FLOWHASH_LOOKUP_SW_ERR,
	FC_FLOWHASH_DEL_SW_ERR,
	FC_FLUSH_QPC_ERR_USED,
	FC_FLUSH_QPC_ERR_OUTER_LOCK,

	FC_AEQ_EVT_ERR_CODE_BUTT

};

/* AEQ data structure */
struct hifcoe_aqe_data_s {
	union {
		struct {
		#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
			u32 evt_code: 8;
			u32 rsvd: 8;
			u32 conn_id : 16; /* conn_id */
		#else
			u32 conn_id : 16;
			u32 rsvd: 8;
			u32 evt_code: 8;
		#endif
		} wd0;

		u32 data0;
	};

	union {
		struct {
		#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
			u32 rsvd: 12;
			u32 xid : 20; /* xid */
		#else
			u32 xid : 20; /* xid */
			u32 rsvd: 12;
		#endif
		} wd1;

		u32 data1;
	};
};

/* Control Section: Common Header */
struct hifcoe_wqe_ctrl_ch_s {
	union {
		struct {
		#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
			u32 owner : 1;
			u32 ctrl_sl   : 2;
			u32 csl   : 2;
			u32 dif_sl: 3;
			u32 cr: 1;
			u32 df: 1;
			u32 va: 1;
			u32 tsl   : 5;
			u32 cf: 1;
			u32 wf: 1;
			u32 rsvd0 : 4;
			u32 drv_sl: 2;
			u32 bdsl  : 8;
		#else
			u32 bdsl  : 8;
			u32 drv_sl: 2;
			u32 rsvd0 : 4;
			u32 wf: 1;
			u32 cf: 1;
			u32 tsl   : 5;
			u32 va: 1;
			u32 df: 1;
			u32 cr: 1;
			u32 dif_sl: 3;
			u32 csl   : 2;
			u32 ctrl_sl: 2;
			u32 owner : 1;
		#endif
		} wd0;

		u32 ctrl_ch_val;
	};

};

/* Control Section: Queue Specific Field */
struct hifcoe_wqe_ctrl_qsf_s {
	#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
	u32 dump_wqe_sn : 16;
	u32 wqe_sn:16;
	#else
	u32 wqe_sn:16;
	u32 dump_wqe_sn : 16;
	#endif
};

/* DIF info definition in WQE */
struct hifcoe_fc_dif_info_s {
	struct {
	#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
		/* difx enable flag:1'b0: disable;1'b1: enable */
		u32 difx_en  : 1;
		/*
		 * sector size:1'b0: sector size is 512B.1'b1: sector size is
		 * 4KB.
		 */
		u32 sct_size : 1;
		u32 difx_len : 11;
		/*
		 * The DIFX verify type: 2'b00: Type0, 2'b01: Type 1, 2'b10:
		 * Type 2, 2'b11: Type 3
		 */
		u32 dif_verify_type  : 2;
		/*
		 * The DIFX insert and replace type: 2'b00: Type0, 2'b01: Type 1
		 * , 2'b10: Type 2, 2'b11: Type 3
		 */
		u32 dif_ins_rep_type : 2;
		u32 difx_app_esc : 1;
		u32 difx_ref_esc : 1;
		u32 grd_ctrl : 3;
		u32 grd_agm_ctrl : 2;
		u32 grd_agm_ini_ctrl : 3;
		u32 ref_tag_ctrl : 3;
		u32 ref_tag_mode : 2;
	#else
		u32 ref_tag_mode : 2;
		u32 ref_tag_ctrl : 3;
		u32 grd_agm_ini_ctrl : 3;
		u32 grd_agm_ctrl : 2;
		u32 grd_ctrl : 3;
		u32 difx_ref_esc : 1;
		u32 difx_app_esc : 1;
		u32 dif_ins_rep_type : 2;
		u32 dif_verify_type  : 2;
		u32 difx_len : 11;
		u32 sct_size : 1;
		u32 difx_en  : 1;
	#endif
	} wd0;

	struct {
	#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
		u32 app_tag_ctrl : 3;
		u32 vpid : 7;
		u32 lun_qos_en   : 2;
		u32 rsvd : 4;
		u32 cmp_app_tag_msk  : 16;
	#else
		u32 cmp_app_tag_msk  : 16;
		u32 rsvd : 4;
		u32 lun_qos_en   : 2;
		u32 vpid : 7;
		u32 app_tag_ctrl	 : 3;
	#endif
	} wd1;

	#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
	u16 rep_app_tag;
	u16 cmp_app_tag;
	#else
	u16 cmp_app_tag;
	u16 rep_app_tag;
	#endif

	u32 cmp_ref_tag;
	u32 rep_ref_tag;

};

/* Task Section: TMF SQE for INI */
struct hifcoe_tmf_info_s {
	union {
		struct {
		#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
			u32 reset_exch_start  :16;
			u32 reset_exch_end	:16;
		#else
			u32 reset_exch_end	:16;
			u32 reset_exch_start  :16;
		#endif
		} bs;
		u32 value;
	} w0;

	union {
		struct {
	#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
			u32 rsvd0	   :5;
			u32 marker_sts  :1;
			u32 reset_type  :2;
			u32 reset_did  :24;
	#else
			u32 reset_did  :24;
			u32 reset_type  :2;
			u32 marker_sts  :1;
			u32 rsvd0   :5;
	#endif
		} bs;
		u32 value;
	} w1;

	union {
		struct {
#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
			u32 rsvd0   :8;
			u32 reset_sid   :24;
#else
			u32 reset_sid   :24;
			u32 rsvd0   :8;
#endif
		} bs;
		u32 value;
	} w2;

	u8 reset_lun[8];
};

/* Task Section: CMND SQE for INI */
struct hifcoe_sqe_icmnd_s {
	u8  fcp_cmnd_iu[48];
	union {
		struct hifcoe_fc_dif_info_s dif_info;
		struct hifcoe_tmf_info_s tmf;
	} info;

	u32 magic_num;
	u32 rsp_gpa_hi;
	u32 rsp_gpa_lo;
};

/* Task Section: ABTS SQE */
struct hifcoe_sqe_abts_s {
	u32 fh_parm_abts;
	u32 magic_num;
};

struct hifcoe_keys_s {
	struct {
#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
		u32 rsv		  : 16;
		u32 smac0		 : 8;
		u32 smac1		 : 8;
#else
		u32 smac1		 : 8;
		u32 smac0		 : 8;
		u32 rsv		  : 16;
#endif
	} wd0;

	u8 smac[4];

	u8 dmac[6];
	u8 sid[3];
	u8 did[3];

	u32 svlan;
	u32 cvlan;
};

/* BDSL: Session Enable WQE */
/* keys field only use 26 bytes room */
struct hifcoe_cmdqe_sess_en_s {
	struct {
	#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
		u32  task_type	   : 8;
		u32  rsvd0		   : 8;
		u32  rx_id		   : 16;
	#else
		u32  rx_id		   : 16;
		u32  rsvd0		   : 8;
		u32  task_type	   : 8;
	#endif
	} wd0;

	struct {
	#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
		u32 rsvd1		   : 12;
		u32 cid		   : 20;
	#else
		u32 cid		   : 20;
		u32 rsvd1		   : 12;
	#endif
	} wd1;

	struct {
	#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
		u32 scqn		:16;
		u32 conn_id	 :16;
	#else
		u32 conn_id	 :16;
		u32 scqn		:16;
	#endif
	} wd2;

	struct {
#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
		u32 rsvd3	   :12;
		u32 xid_p	   :20;
#else
		u32 xid_p	   :20;
		u32 rsvd3	   :12;
#endif
	} wd3;

	u32 context_gpa_hi;
	u32 context_gpa_lo;
	struct hifcoe_keys_s keys;
};

/* Control Section */
struct hifcoe_wqe_ctrl_s {
	struct hifcoe_wqe_ctrl_ch_s  ch;
	struct hifcoe_wqe_ctrl_qsf_s qsf;
};

struct hifcoe_sqe_els_rsp_s {
	struct {
	#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
	/*
	 * ELS RSP packet payload. ELS RSP payload GPA is store in BDSL, ucode
	 * use child setup to send data(do not include fc_hdr/eth_hdr)
	 */
		u32 data_len:16;
		u32 echo_flag   :16;
	#else
		u32 echo_flag   :16;
		u32 data_len:16;
	#endif
	} wd0;

	struct {
	#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
		/* Para Update:drv indicate Parent Context para need to be
		 * update or not.
		 * 00---no update
		 * 01---send PLOGI_ACC, need to updata Port para
		 * 10---send PRLI_ACC, need to updata process para
		 * 11---Reserved
		 */
		u32 para_update :2;
		u32 clr_io  :1;
		u32 lp_bflag:1;  /* use for loopback */
		u32 rsvd1   :28;
	#else
		u32 rsvd1   :28;
		u32 lp_bflag:1;
		u32 clr_io  :1;
		u32 para_update :2;
	#endif
	} wd1;

	struct {
	#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
		u32 tx_mfs  :16;
		u32 rsvd2   :14;
		u32 e_d_tov :1;
		u32 seq_cnt :1;
	#else
		u32 seq_cnt :1;
		u32 e_d_tov :1;
		u32 rsvd2   :14;
		u32 tx_mfs  :16;
	#endif
	} wd2;

	u32 e_d_tov_timer_val;

	struct {
	#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
		u32 immi_taskid_start:16;
		u32 immi_taskid_cnt :13;
		u32 xfer_dis:1;
		u32 rec :1;
		u32 conf:1;
	#else
		u32 conf:1;
		u32 rec :1;
		u32 xfer_dis:1;
		u32 immi_taskid_cnt :13;
		u32 immi_taskid_start:16;
	#endif
	} wd4;

	u32 first_burst_len;

	struct {
	#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
		u32 reset_exch_start  :16;
		u32 reset_exch_end:16;
	#else
		u32 reset_exch_end:16;
		u32 reset_exch_start  :16;
	#endif
	} wd6;

	struct {
	#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
		u32 rsvd:16;
		u32 scqn:16;
	#else
		u32 scqn:16;
		u32 rsvd:16;
	#endif
	} wd7;

	u32 magic_num;
	u32 magic_local;
	u32 magic_remote;
	u32 ts_rcv_echo_req;
};

struct hifcoe_sqe_reset_session_s {
	struct {
	#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
		u32 reset_exch_start  :16;
		u32 reset_exch_end:16;
	#else
		u32 reset_exch_end:16;
		u32 reset_exch_start  :16;
	#endif
	} wd0;

	struct {
	#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
		u32 rsvd:6;
		/*
		 * 1: clean io;
		 * 2: delete session;
		 * 3: clean io&delete session
		 */
		u32 mode:2;
		u32 reset_did   :24;
	#else
		u32 reset_did   :24;
		u32 mode:2;
		u32 rsvd:6;
	#endif
	} wd1;

	struct {
	#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
		u32 rsvd:8;
		u32 reset_sid   :24;
	#else
		u32 reset_sid   :24;
		u32 rsvd:8;
	#endif
	} wd2;

	struct {
	#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
		u32 rsvd:16;
		u32 scqn:16;
	#else
		u32 scqn:16;
		u32 rsvd:16;
	#endif
	} wd3;
};

struct hifcoe_sqe_t_els_gs_s {
	#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
	/*
	 * ELS/GS req packet payload. ELS/GS payload GPA is store in BDSL,
	 * ucode use child setup to send data(do not include fc_hdr/eth_hdr)
	 */
	u16 data_len;
	u16 echo_flag;  /* echo flag */
	#else
	u16 echo_flag;
	u16 data_len;
	#endif

	struct {
	#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
		/* Para Update: drv indicate Parent Context para need to be
		 * update or not.
		 * 00---no update
		 * 01---send PRLI Req, need to updata Port para
		 * 10---Reserved
		 * 11---Reserved
		 */
		u32 para_update	 :2;
		u32 clr_io  :1;
		u32 lp_bflag:1;   /* use for loopback */
		u32 rec_support :1;
		u32 rec_flag:1;
		u32 orign_oxid  :16;
		u32 rsvd1   :10;
	#else
		u32 rsvd1   :10;
		u32 orign_oxid  :16;
		u32 rec_flag:1;
		u32 rec_support :1;
		u32 lp_bflag:1;
		u32 clr_io  :1;
		u32 para_update :2;
	#endif
	} wd4;

	struct {
	#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
		u32 tx_mfs  :16;
		u32 rsvd2   :14;
		u32 e_d_tov :1;
		u32 seq_cnt :1;
	#else
		u32 seq_cnt :1;
		u32 e_d_tov :1;
		u32 rsvd2   :14;
		u32 tx_mfs  :16;
	#endif
	} wd5;

	u32 e_d_tov_timer_val;

	struct {
	#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
		u32 reset_exch_start  :16;
		u32 reset_exch_end:16;
	#else
		u32 reset_exch_end:16;
		u32 reset_exch_start  :16;
	#endif
	} wd6;

	struct {
	#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
		u32 rsvd:16;
		u32 scqn:16;
	#else
		u32 scqn:16;
		u32 rsvd:16;
	#endif
	} wd7;

	u32 magic_num;
};

struct hifcoe_sqe_els_gs_elsrsp_comm_s {
	#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
	u16 data_len;
	u16 rsvd;
	#else
	u16 rsvd;
	u16 data_len;
	#endif
};

/* SQE Task Section's Contents except Common Header */
union hifcoe_sqe_ts_cont_u {
	struct hifcoe_sqe_icmnd_s icmnd;
	struct hifcoe_sqe_abts_s abts;
	struct hifcoe_sqe_els_rsp_s els_rsp;
	struct hifcoe_sqe_t_els_gs_s t_els_gs;
	struct hifcoe_sqe_els_gs_elsrsp_comm_s els_gs_elsrsp_comm;
	struct hifcoe_sqe_reset_session_s reset_session;
	u32 value[16];
};

struct hifcoe_sqe_ts_s {
	/* SQE Task Section's Common Header */
	#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
	u32 task_type   :8;
	u32 rsvd:5; /* used for loopback saving bdsl's num */
	/* cdb_type = 0:CDB_LEN = 16B, cdb_type = 1:CDB_LEN = 32B */
	u32 cdb_type:1;
	/* standard immidiate data flag, use with local-xid for initiator */
	u32 immi_std:1;
	/*
	 * CRC err inject flag: drv set, and ucode use for send first packet of
	 * WQE
	 */
	u32 crc_inj :1;
	u32 local_xid   :16; /* local exch_id */
	#else
	u32 local_xid   :16;
	u32 crc_inj :1;
	u32 immi_std:1;
	/* cdb_type = 0:CDB_LEN = 16B, cdb_type = 1:CDB_LEN = 32B */
	u32 cdb_type:1;
	u32 rsvd:5;  /* used for loopback saving bdsl's num */
	u32 task_type   :8;
	#endif

	struct {
	#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
		u16 remote_xid; /* remote exch_id */
		u16 conn_id;
	#else
		u16 conn_id;
		u16 remote_xid;
	#endif
	} wd0;

	union hifcoe_sqe_ts_cont_u cont;
};

struct hifcoe_constant_sge_s {
	u32 buf_addr_hi;
	u32 buf_addr_lo;
};

struct hifcoe_variable_sge_s {
	u32 buf_addr_hi;
	u32 buf_addr_lo;

	struct {
	#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
		u32 r_flag  :1;
		u32 buf_len :31;
	#else
		u32 buf_len :31;
		u32 r_flag  :1;
	#endif
	} wd0;

	struct {
	#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
		u32 last_flag   :1;
		u32 extension_flag  :1;
		u32 xid : 14;
		u32 buf_addr_gpa: 16;
	#else
		u32 buf_addr_gpa: 16;
		u32 xid : 14;
		u32 extension_flag  :1;
		u32 last_flag   :1;
	#endif
	} wd1;
};

/* SQE, should not be over 128B */
struct hifcoe_sqe_s {
	struct hifcoe_wqe_ctrl_s ctrl_sl;
	struct hifcoe_sqe_ts_s ts_sl;
	struct hifcoe_variable_sge_s sge[2];
};

struct hifcoe_rqe_ctrl_s {
	struct hifcoe_wqe_ctrl_ch_s  ch;

	struct {
	#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
		u16 dump_wqe_msn;
		u16 wqe_msn;
	#else
		u16 wqe_msn;
		u16 dump_wqe_msn;
	#endif
	} wd0;
};

struct hifcoe_rqe_drv_s {
	struct {
	#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
	/*
	 * User ID[15:0], 15 bits valid and User ID[15] is fix to 0
	 */
		u32 user_id :16;
		u32 rsvd0   :16;
	#else
		u32 rsvd0   :16;
		u32 user_id :16;
	#endif
	} wd0;

	u32 rsvd1;
};

/* RQE,should not be over 32B */
struct hifcoe_rqe_s {
	struct hifcoe_rqe_ctrl_s ctrl_sl;
	u32 cqe_gpa_h;
	u32 cqe_gpa_l;
	struct hifcoe_constant_sge_s bds_sl;
	struct hifcoe_rqe_drv_s drv_sl;
};

struct hifcoe_cmdqe_abts_rsp_s {
	struct {
	#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
		u32  task_type	   : 8;
		u32  rsvd0   : 8;
		u32  rx_id   : 16;
	#else
		u32  rx_id   : 16;
		u32  rsvd0   : 8;
		u32  task_type  : 8;
	#endif
	} wd0;

	struct {
	#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
		u32 rsp_type:1; /* 0:BA_ACC, 1:BA_RJT */
		u32 payload_len :7;
		u32 port_id :4;
		u32 rsvd1   :4;
		u32 ox_id   :16;
	#else
		u32 ox_id   :16;
		u32 rsvd1   :4;
		u32 port_id :4;
		u32 payload_len :7;
		u32 rsp_type:1;
	#endif
	} wd1;

	struct {
	#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
		u32  scqn: 16;
		u32  conn_id : 16;
	#else
		u32  conn_id : 16;
		u32  scqn: 16;
	#endif
	} wd2;

	struct {
	#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
		u32  rsvd: 12;
		u32  xid : 20;
	#else
		u32  xid : 20;
		u32  rsvd: 12;
	#endif
	} wd3;

	struct {
	#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
		u32  rsvd: 12;
		u32  cid : 20;
	#else
		u32  cid : 20;
		u32  rsvd: 12;
	#endif
	} wd4;

	struct {
	#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
		u32  rsvd: 16;
		u32  req_rx_id   : 16;
	#else
		u32  req_rx_id   : 16;
		u32  rsvd: 16;
	#endif
	} wd5;

	/* payload length is according to rsp_type:1DWORD or 3DWORD */
	u32 payload[3];
};

struct hifcoe_cmdqe_buffer_clear_s {
	struct {
	#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
		u32 wqe_type:8;
		u32 rsvd0   :8;
		u32 rsvd1   :16;
	#else
		u32 rsvd1   :16;
		u32 rsvd0   :8;
		u32 wqe_type:8;
	#endif
	} wd0;

	struct {
	#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
		u32 rx_id_start :16;
		u32 rx_id_end   :16;
	#else
		u32 rx_id_end   :16;
		u32 rx_id_start :16;
	#endif
	} wd1;

	u32 scqn;
	u32 wd3;
};

struct hifcoe_cmdqe_flush_sq_info_s {
	u32 cid;
	u32 xid;
};

struct hifcoe_cmdqe_flush_sq_s {
	struct {
	#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
		u32 wqe_type :8;
		u32 sq_qid   :8;
		u32 entry_count  :16;
	#else
		u32 entry_count  :16;
		u32 sq_qid   :8;
		u32 wqe_type :8;
	#endif
	} wd0;

	struct {
	#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
		u32 last_wqe:1;
		u32 pos :11;
		u32 port_id:4;
		u32 scqn:16;
	#else
		u32 scqn:16;
		u32 port_id :4;
		u32 pos :11;
		u32 last_wqe:1;
	#endif
	} wd1;

	struct {
	#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
		u32 pkt_ptr :16;
		u32 rsvd:16;
	#else
		u32 rsvd:16;
		u32 pkt_ptr :16;
	#endif
	} wd2;

	struct hifcoe_cmdqe_flush_sq_info_s sq_info_entry[0];
};

struct hifcoe_cmdqe_creat_srqc_s {
	struct {
#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
		u32  task_type   : 8;
		u32  rsvd0   : 8;
		u32  rsvd1   : 16;
#else
		u32  rsvd1   : 16;
		u32  rsvd0   : 8;
		u32  task_type  : 8;
#endif
	} wd0;

	u32 srqc_gpa_h;
	u32 srqc_gpa_l;

	u32 srqc[16];/* srqc_size=64B */

};

struct hifcoe_cmdqe_delete_srqc_s {
	struct {
#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
		u32  task_type   : 8;
		u32  rsvd0   : 8;
		u32  rsvd1   : 16;
#else
		u32  rsvd1   : 16;
		u32  rsvd0   : 8;
		u32  task_type : 8;
#endif
	} wd0;

	u32 srqc_gpa_h;
	u32 srqc_gpa_l;
};

struct hifcoe_cmdqe_clr_srq_s {
	struct {
#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
		u32  task_type   : 8;
		u32  rsvd0   : 8;
		u32  rsvd1   : 16;
#else
		u32  rsvd1   : 16;
		u32  rsvd0   : 8;
		u32  task_type  : 8;
#endif
	} wd0;

	struct {
#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
		/*
		 * 0: SRQ for recv ELS;
		 * 1: SRQ for recv immidiate data
		 */
		u32  srq_type: 16;
		u32  scqn: 16;
#else
		u32  scqn: 16;
		u32  srq_type: 16;
#endif
	} wd1;

	u32 srqc_gpa_h;
	u32 srqc_gpa_l;
};

struct hifcoe_cmdqe_creat_scqc_s {
	struct {
#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
		u32  task_type  : 8;
		u32  rsvd0   : 8;
		u32  rsvd1   : 16;
#else
		u32  rsvd1   : 16;
		u32  rsvd0   : 8;
		u32  task_type  : 8;
#endif
	} wd0;

	struct {
#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
		u32  rsvd2   : 16;
		u32  scqn: 16;
#else
		u32  scqn: 16;
		u32  rsvd2   : 16;
#endif
	} wd1;

	u32 scqc[16];/* scqc_size=64B */

};

struct hifcoe_cmdqe_delete_scqc_s {
	struct {
#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
		u32  task_type   : 8;
		u32  rsvd0   : 8;
		u32  rsvd1   : 16;
#else
		u32  rsvd1   : 16;
		u32  rsvd0   : 8;
		u32  task_type  : 8;
#endif
	} wd0;

	struct {
#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
		u32  rsvd2   : 16;
		u32  scqn: 16;
#else
		u32  scqn: 16;
		u32  rsvd2  : 16;
#endif
	} wd1;
};

struct hifcoe_sqe_t_rsp_s {
	struct {
	#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
		u32 fill:2; /* 2bit of F_CTL[1:0] */
		u32 conf:1; /* Wait INI confirm, 0: disable, 1:enable */
		/*
		 * 0: payload area store payload,
		 * 1: payload area store payload GPA
		 */
		u32 mode:1;
		u32 immi:1;
		u32 rsvd0   :3;
		u32 fcp_rsp_len :8; /* FCP_RESP payload(24~96B)*/
		u32 rsvd1   :16;
	#else
		u32 rsvd1   :16;
		u32 fcp_rsp_len :8;
		u32 rsvd0   :3;
		u32 immi:1;
		u32 mode:1;
		u32 conf:1;
		u32 fill:2;
	#endif
	} wd0;

	u32 magic_num;
	u32 hotpooltag;

	union {
		struct {
			u32 addr_h;
			u32 addr_l;
		} gpa;

		struct {
			u32 data[25]; /* FCP_RESP payload buf, 100B rsvd */
		} buf;

	} payload;

};

struct hifcoe_sqe_tresp_ts_s {
	/* SQE Task Section's Common Header */
	#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
	u8  task_type;
	u8  rsvd0;
	u16 local_xid;
	#else
	u16 local_xid;
	u8  rsvd0;
	u8  task_type;
	#endif

	struct {
	#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
		u16 remote_xid;
		u16 conn_id;
	#else
		u16 conn_id;
		u16 remote_xid;
	#endif
	} wd0;

	struct hifcoe_sqe_t_rsp_s t_rsp;
};

/* SQE for fcp response, max TSL is 120B*/
struct hifcoe_sqe_tresp_s {
	struct hifcoe_wqe_ctrl_s ctrl_sl;
	struct hifcoe_sqe_tresp_ts_s ts_sl;
};

/* SCQE Common Header */
struct hifcoe_scqe_ch_s {
	struct {
	#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
		u32 owner   : 1;
		u32 err_code: 7;
		u32 cqe_remain_cnt  : 3;
		u32 rsvd0   : 13;
		u32 task_type   : 8;
	#else
		u32 task_type   : 8;
		u32 rsvd0   : 13;
		u32 cqe_remain_cnt  : 3;
		u32 err_code: 7;
		u32 owner   : 1;
	#endif
	} wd0;
};

struct hifcoe_scqe_type_s {
	struct hifcoe_scqe_ch_s ch;

	u32 rsvd0;

#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
	u16 rsvd4;
	u16 conn_id;
#else
	u16 conn_id;
	u16 rsvd4;
#endif

	u32 rsvd1[12];

	struct {
	#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
		u32 rsvd2   :31;
		u32 done:1;
	#else
		u32 done:1;
		u32 rsvd3  :31;
	#endif
	} wd0;
};

struct hifcoe_scqe_sess_sts_s {
	struct hifcoe_scqe_ch_s ch;

	struct {
	#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
		u32 rsvd1   :12;
		u32 xid_qpn :20;
	#else
		u32 xid_qpn :20;
		u32 rsvd1   :12;
	#endif
	} wd0;

	struct {
	#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
		u32 rsvd3   :16;
		u32 conn_id :16;
	#else
		u32 conn_id :16;
		u32 rsvd3   :16;
	#endif
	} wd1;

	struct {
#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
		u32 rsvd2   :12;
		u32 cid :20;
#else
		u32 cid :20;
		u32 rsvd2  :12;
#endif
	} wd2;

	u64 bloomfilter_id; /* valid only in session offload */

};

struct hifcoe_scqe_comm_rsp_sts_s {
	struct hifcoe_scqe_ch_s ch;

	struct {
	#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
		u32 ox_id   :16;
		u32 rx_id   :16;
	#else
		u32 rx_id   :16;
		u32 ox_id   :16;
	#endif
	} wd0;

	struct {
	#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
		u32 rsvd0   :16;
		u32 conn_id :16;
	#else
		u32 conn_id :16;
		u32 rsvd0   :16;
	#endif
	} wd1;

	u32 magic_num;
};

struct hifcoe_scqe_iresp_s {
	struct hifcoe_scqe_ch_s ch;

	struct {
	#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
		u32 ox_id   :16;
		u32 rx_id   :16;
	#else
		u32 rx_id   :16;
		u32 ox_id   :16;
	#endif
	} wd0;

	struct {
	#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
		u32 dif_info:5;
		u32 rsvd0   :11;
		u32 conn_id :16;
	#else
		u32 conn_id :16;
		u32 rsvd0   :11;
		u32 dif_info:5;
	#endif
	} wd1;

	struct {
	#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
		u32 rsvd0   :16;
		u32 fcp_flag:8;
		u32 scsi_status :8;
	#else
		u32 scsi_status :8;
		u32 fcp_flag:8;
		u32 rsvd0   :16;
	#endif
	} wd2;

	u32 fcp_resid;
	u32 fcp_sns_len;
	u32 fcp_rsp_len;
	u32 magic_num;
};

struct hifcoe_scqe_rcv_abts_rsp_s {
	struct hifcoe_scqe_ch_s ch;

	struct {
	#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
		u32 ox_id	   :16;
		u32 rx_id	   :16;
	#else
		u32 rx_id	   :16;
		u32 ox_id	   :16;
	#endif
	} wd0;

	struct {
	#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
		u32 rsvd0   :16;
		u32 conn_id :16;
	#else
		u32 conn_id :16;
		u32 rsvd0   :16;
	#endif
	} wd1;

	struct {
	#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
		u32 rsvd0:24;
		u32 fh_rctrl :8;
	#else
		u32 fh_rctrl :8;
		u32 rsvd0:24;
	#endif
	} wd2;

	struct {
	#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
		u32 rsvd1   :8;
		u32 did :24;
	#else
		u32 did :24;
		u32 rsvd1   :8;
	#endif
	} wd3;

	struct {
	#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
		u32 rsvd2   :8;
		u32 sid :24;
	#else
		u32 sid :24;
		u32 rsvd2   :8;
	#endif
	} wd4;

	/* payload length is according to fh_rctrl:1DWORD or 3DWORD */
	u32 payload[3];
	u32 magic_num;

};

struct hifcoe_scqe_rcv_els_cmd_s {
	struct hifcoe_scqe_ch_s ch;

	struct {
	#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
		u32 rsvd0   :8;
		u32 did :24;
	#else
		u32 did :24;
		u32 rsvd0   :8;
	#endif
	} wd0;

	struct {
	#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
		u32 rsvd1   :8;
		u32 sid :24;
	#else
		u32 sid :24;
		u32 rsvd1  :8;
	#endif
	} wd1;

	struct {
	#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
		u32 ox_id   :16;
		u32 rx_id   :16;
	#else
		u32 rx_id   :16;
		u32 ox_id   :16;
	#endif
	} wd2;

	struct{
	#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
		u32 data_len  :16;/* ELS cmd Payload length */
		u32 user_id_num   :16;/* current used user_id num */
	#else
		u32 user_id_num   :16;
		u32 data_len  :16;
	#endif
	} wd3;

	u32 user_id[9]; /* User ID of SRQ SGE, used for drvier buffer release */
	u32 ts;
};

struct hifcoe_scqe_rcv_els_gs_rsp_s {
	struct hifcoe_scqe_ch_s ch;

	struct {
	#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
		u32 ox_id	   :16;
		u32 rx_id	   :16;
	#else
		u32 rx_id	   :16;
		u32 ox_id	   :16;
	#endif
	} wd1;

	struct {
	#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
		u32 data_len:16;
		u32 conn_id :16;
	#else
		u32 conn_id :16;
		u32 data_len:16; /* ELS/GS RSP Payload length */
	#endif
	} wd2;

	struct {
	#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
		u32 end_rsp :1;
		u32 echo_rsp:1;
		u32 rsvd:6;
		u32 did :24;
	#else
		u32 did :24;
		u32 rsvd:6;
		u32 echo_rsp:1;
		u32 end_rsp :1;
	#endif
	} wd3;

	struct {
	#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
		u32 user_id_num :8;
		u32 sid :24;
	#else
		u32 sid :24;
		u32 user_id_num :8;
	#endif
	} wd4;

	u32 magic_num;
	u32 user_id[9];
};

struct hifcoe_scqe_rcv_flush_sts_s {
	struct hifcoe_scqe_ch_s ch;

	struct {
#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
		u32 last_flush : 8;
		u32 port_id: 8;
		u32 rsvd0  : 16;
#else
		u32 rsvd0  : 16;
		u32 port_id: 8;
		u32 last_flush : 8;
#endif
	} wd0;
};

struct hifcoe_scqe_rcv_clear_buf_sts_s {
	struct hifcoe_scqe_ch_s ch;
	struct {
#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
		u32 port_id: 8;
		u32 rsvd0  : 24;
#else
		u32 rsvd0  : 24;
		u32 port_id: 8;
#endif
	} wd0;
};

struct hifcoe_scqe_itmf_marker_sts_s {
	struct hifcoe_scqe_ch_s ch;

	struct {
	#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
		u32 ox_id   :16;
		u32 rx_id   :16;
	#else
		u32 rx_id   :16;
		u32 ox_id   :16;
	#endif
	} wd1;

	struct {
	#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
		u32 end_rsp  :8;
		u32 did  :24;
	#else
		u32 did  :24;
		u32 end_rsp :8;
	#endif
	} wd2;

	struct {
	#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
		u32 rsvd1:8;
		u32 sid  :24;
	#else
		u32 sid  :24;
		u32 rsvd1:8;
	#endif
	} wd3;
};

struct hifcoe_scqe_abts_marker_sts_s {
	struct hifcoe_scqe_ch_s ch;

	struct {
	#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
		u32 ox_id   :16;
		u32 rx_id   :16;
	#else
		u32 rx_id   :16;
		u32 ox_id   :16;
	#endif
	} wd1;

	struct {
	#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
		u32 end_rsp  :8;
		u32 did  :24;
	#else
		u32 did  :24;
		u32 end_rsp :8;
	#endif
	} wd2;

	struct {
	#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
		u32 io_state :8;
		u32 sid  :24;
	#else
		u32 sid  :24;
		u32 io_state :8;
	#endif
	} wd3;
};

/* SCQE, should not be over 64B */
union hifcoe_scqe_u {
	struct hifcoe_scqe_type_s  common;
	/* session enable/disable/delete sts */
	struct hifcoe_scqe_sess_sts_s  sess_sts;
	/* aborts/abts_rsp/els rsp sts */
	struct hifcoe_scqe_comm_rsp_sts_s  comm_sts;
	struct hifcoe_scqe_rcv_clear_buf_sts_s clear_sts;/* clear buffer sts */
	struct hifcoe_scqe_rcv_flush_sts_s flush_sts;  /* flush sq sts */
	struct hifcoe_scqe_iresp_s iresp;
	struct hifcoe_scqe_rcv_abts_rsp_s  rcv_abts_rsp;   /* recv abts rsp*/
	struct hifcoe_scqe_rcv_els_cmd_s   rcv_els_cmd;/* recv els cmd */
	struct hifcoe_scqe_rcv_els_gs_rsp_s rcv_els_gs_rsp;/* recv els/gs rsp */
	struct hifcoe_scqe_itmf_marker_sts_s   itmf_marker_sts;/* tmf marker */
	struct hifcoe_scqe_abts_marker_sts_s   abts_marker_sts;/* abts marker */
};

struct hifcoe_cmdqe_type_s {
	struct {
	#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
		u32  task_type   : 8;
		u32  rsvd0       : 8;
		u32  rx_id       : 16;
	#else
		u32  rx_id       : 16;
		u32  rsvd0       : 8;
		u32  task_type   : 8;
	#endif
	} wd0;
};

/* CMDQE, variable length */
union hifc_cmdqe_u {
	struct hifcoe_cmdqe_type_s common;
	struct hifcoe_cmdqe_sess_en_s  session_enable;
	struct hifcoe_cmdqe_abts_rsp_s snd_abts_rsp;
	struct hifcoe_cmdqe_buffer_clear_s buffer_clear;
	struct hifcoe_cmdqe_flush_sq_s flush_sq;
	struct hifcoe_cmdqe_creat_srqc_s  create_srqc;
	struct hifcoe_cmdqe_delete_srqc_s delete_srqc;
	struct hifcoe_cmdqe_clr_srq_s  clear_srq;
	struct hifcoe_cmdqe_creat_scqc_s  create_scqc;
	struct hifcoe_cmdqe_delete_scqc_s delete_scqc;
};

#endif
