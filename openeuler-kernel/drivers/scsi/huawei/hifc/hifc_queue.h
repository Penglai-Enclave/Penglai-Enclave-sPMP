/* SPDX-License-Identifier: GPL-2.0 */
/* Huawei Hifc PCI Express Linux driver
 * Copyright(c) 2017 Huawei Technologies Co., Ltd
 *
 */

#ifndef __HIFC_QUEUE_H__
#define __HIFC_QUEUE_H__

#include "hifc_wqe.h"
#include "hifc_hw.h"
#include "hifc_hwif.h"
#include "hifc_cqm_main.h"

#define WQE_MARKER_0     0x0
#define WQE_MARKER_6B    0x6b

#define HIFC_SQE_SIZE    128
#define HIFC_MIN_WP_NUM  2

/* Counter */
#define HIFC_STAT_SESSION_IO

/*************** PARENT SQ&Context defines *******************************/
#define HIFC_MAX_MSN                (65535)
#define HIFC_MSN_MASK               (0xffff000000000000LL)
#define HIFC_SQE_TS_SIZE            (72)
#define HIFC_SQE_FIRST_OBIT_DW_POS  (0)
#define HIFC_SQE_SECOND_OBIT_DW_POS (30)
#define HIFC_SQE_OBIT_SET_MASK_BE   (0x80)
#define HIFC_SQE_OBIT_CLEAR_MASK_BE (0xffffff7f)
#define HIFC_MAX_SQ_TASK_TYPE_CNT   (128)

/*
 * Note: if the location of flush done bit changes, the definition must be
 * modifyed again
 */
#define HIFC_CTXT_FLUSH_DONE_DW_POS  (58)
#define HIFC_CTXT_FLUSH_DONE_MASK_BE (0x4000)

#define HIFC_GET_SQ_HEAD(v_sq) \
	list_entry((&(v_sq)->list_linked_list_sq)->next,\
		   struct hifc_sq_wqe_page_s, entry_wpg)
#define HIFC_GET_SQ_TAIL(v_sq) \
	list_entry((&(v_sq)->list_linked_list_sq)->prev, \
		   struct hifc_sq_wqe_page_s, entry_wpg)
#ifdef HIFC_STAT_SESSION_IO
#define HIFC_SQ_IO_STAT(v_sq, io_type) \
	(atomic_inc(&(v_sq)->io_stat[io_type]))
#define HIFC_SQ_IO_STAT_READ(v_sq, io_type) \
	(atomic_read(&(v_sq)->io_stat[io_type]))
#endif
#define HIFC_GET_QUEUE_CMSN(v_sq)\
	((unsigned int)(be64_to_cpu(((((v_sq)->queue_header)->ci_record) \
	& HIFC_MSN_MASK))))
#define HIFC_GET_WP_END_CMSN(head_start_cmsn, wqe_num_per_buf) \
	(unsigned short)(((unsigned int)(head_start_cmsn) +\
	(unsigned int)(wqe_num_per_buf) - 1) % (HIFC_MAX_MSN + 1))
#define HIFC_MSN_INC(msn) (((HIFC_MAX_MSN) == (msn)) ? 0 : ((msn) + 1))
#define HIFC_MSN_DEC(msn) ((0 == (msn)) ? (HIFC_MAX_MSN) : ((msn) - 1))
#define HIFC_QUEUE_MSN_OFFSET(start_cmsn, end_cmsn) \
	(unsigned int)((((unsigned int)(end_cmsn) + (HIFC_MAX_MSN)) - \
	(unsigned int)(start_cmsn)) % (HIFC_MAX_MSN + 1))

/******************* ROOT SQ&RQ defines ***********************************/
#define HIFC_ROOT_Q_CTX_SIZE                 (48)
#define HIFC_ROOT_Q_CTX_CI_WQE_HI_SHIFT      (44)
#define HIFC_ROOT_Q_CTX_CI_WQE_LOW_SHIFT     (12)
#define HIFC_ROOT_Q_CTX_CLA_HI_SHIFT         (41)
#define HIFC_ROOT_Q_CTX_CLA_LOW_SHIFT        (9)
#define HIFC_ROOT_TSO_LRO_SPACE              (0)
#define HIFC_ROOT_CTX_WQE_PREFETCH_MAX       (3)
#define HIFC_ROOT_CTX_WQE_PREFETCH_MIN       (1)
#define HIFC_ROOT_CTX_WQE_PRERETCH_THRESHOLD (2)
#define HIFC_CI_WQE_PAGE_HIGH_ADDR(x) \
	(unsigned int)(((x) >> HIFC_ROOT_Q_CTX_CI_WQE_HI_SHIFT) & 0xffffffff)
#define HIFC_CI_WQE_PAGE_LOW_ADDR(x) \
	(unsigned int)(((x) >> HIFC_ROOT_Q_CTX_CI_WQE_LOW_SHIFT) & 0xffffffff)
#define HIFC_CLA_HIGH_ADDR(x)\
	(unsigned int)(((x) >> HIFC_ROOT_Q_CTX_CLA_HI_SHIFT) & 0xffffffff)
#define HIFC_CLA_LOW_ADDR(x) \
	(unsigned int)(((x) >> HIFC_ROOT_Q_CTX_CLA_LOW_SHIFT) & 0xffffffff)

/*********************** ROOT SQ defines ***********************************/
#define HIFC_ROOT_SQ_NUM                        (1)
#define HIFC_ROOT_SQ_DEPTH                      (2048)
#define HIFC_ROOT_SQ_WQEBB                      (64)
#define HIFC_ROOT_SQ_CI_TABLE_STEP_BYTE         (4)
#define HIFC_ROOT_SQ_LOOP_OWNER                 (1)
#define HIFC_ROOT_SQ_CI_ATTRIBUTE_ADDRESS_SHIFT (2)
#define HIFC_DOORBELL_SQ_TYPE                   (1)
#define HIFC_DOORBELL_SQ_PI_HIGH_BITS_SHIFT     (8)
#define HIFC_DOORBELL_SQ_PI_LOW_BITS_MASK       (0xFF)
#define HIFC_INT_NUM_PER_QUEUE                  (1)
#define HIFC_INT_ENABLE                         (1)
#define HIFC_ROOT_CFG_SQ_NUM_MAX                (42)
#define HIFC_CMDQ_QUEUE_TYPE_SQ                 (0)
#define HIFC_GET_ROOT_SQ_CI_ADDR(addr, index)  \
	((addr) + (unsigned int)((index) * HIFC_ROOT_SQ_CI_TABLE_STEP_BYTE))
#define HIFC_ROOT_SQ_CTX_OFFSET(q_num, q_id) \
	((HIFC_ROOT_TSO_LRO_SPACE * 2 * (q_num) +\
	HIFC_ROOT_Q_CTX_SIZE * (q_id)) / 16)

/********************** ROOT RQ defines ***********************************/
#define HIFC_ROOT_RQ_NUM                     (1)
#define HIFC_ROOT_RQ_DEPTH                   (1024)
#define HIFC_ROOT_RQ_WQEBB                   (32)
#define HIFC_ROOT_RQ_PI_TABLE_STEP_BYTE      (4)
#define HIFC_ROOT_RQ_LOOP_OWNER              (1)
#define HIFC_ROOT_RQ_RECV_BUFF_SIZE          (1024)
#define HIFC_ROOT_Q_INT_ID_MAX               (1024) /* 10bit */
#define HIFC_ROOT_CFG_RQ_NUM_MAX             (42)
#define HIFC_CMDQ_QUEUE_TYPE_RQ              (1)
#define HIFC_RQE_MAX_PROCESS_NUM_PER_INTR    (128)
#define HIFC_ROOT_RQ_CTX_OFFSET(q_num, q_id)\
	(((HIFC_ROOT_TSO_LRO_SPACE * 2 + HIFC_ROOT_Q_CTX_SIZE) * (q_num) +\
	HIFC_ROOT_Q_CTX_SIZE * (q_id)) / 16)

/************************** SCQ defines ***********************************/
#define HIFC_SCQ_INT_ID_MAX          (2048) /* 11BIT */
#define HIFC_SCQE_SIZE               (64)
#define HIFC_CQE_GPA_SHIFT           (4)
#define HIFC_NEXT_CQE_GPA_SHIFT      (12)
/* 1-Update Ci by Tile, 0-Update Ci by Hardware */
#define HIFC_PMSN_CI_TYPE_FROM_HOST  (0)
#define HIFC_PMSN_CI_TYPE_FROM_UCODE (1)
#define HIFC_ARMQ_IDLE               (0)
#define HIFC_CQ_INT_MODE             (2)
#define HIFC_CQ_HEADER_OWNER_SHIFT   (15)

/*
 * SCQC_CQ_DEPTH: 0-256, 1-512, 2-1k, 3-2k, 4-4k, 5-8k, 6-16k, 7-32k.
 * include LinkWqe
 */
#define HIFC_CMD_SCQ_DEPTH (4096)
#define HIFC_STS_SCQ_DEPTH (8192)

#define HIFC_CMD_SCQC_CQ_DEPTH (hifc_log2n(HIFC_CMD_SCQ_DEPTH >> 8))
#define HIFC_STS_SCQC_CQ_DEPTH (hifc_log2n(HIFC_STS_SCQ_DEPTH >> 8))
#define HIFC_STS_SCQ_CI_TYPE   HIFC_PMSN_CI_TYPE_FROM_HOST

#define HIFC_CMD_SCQ_CI_TYPE HIFC_PMSN_CI_TYPE_FROM_UCODE
#define HIFC_SCQ_INTR_LOW_LATENCY_MODE         0
#define HIFC_SCQ_INTR_POLLING_MODE             1

#define HIFC_CQE_MAX_PROCESS_NUM_PER_INTR (128)
#define HIFC_SESSION_SCQ_NUM              (16)

/*
 * SCQ[0, 2, 4 ...]CMD SCQ,SCQ[1, 3, 5 ...]STS SCQ,SCQ[HIFC_TOTAL_SCQ_NUM-1]
 * Defaul SCQ
 */
#define HIFC_CMD_SCQN_START   (0)
#define HIFC_STS_SCQN_START   (1)
#define HIFC_SCQS_PER_SESSION (2)

#define HIFC_TOTAL_SCQ_NUM (HIFC_SESSION_SCQ_NUM + 1)

#define HIFC_SCQ_IS_STS(scq_index) \
	(((scq_index) % HIFC_SCQS_PER_SESSION) || \
	((scq_index) == HIFC_SESSION_SCQ_NUM))
#define HIFC_SCQ_IS_CMD(scq_index)\
	(!HIFC_SCQ_IS_STS(scq_index))
#define HIFC_RPORTID_TO_CMD_SCQN(rport_index) \
	(((rport_index) * HIFC_SCQS_PER_SESSION) % HIFC_SESSION_SCQ_NUM)
#define HIFC_RPORTID_TO_STS_SCQN(rport_index) \
	((((rport_index) * HIFC_SCQS_PER_SESSION) + 1) % HIFC_SESSION_SCQ_NUM)

/************************** SRQ defines ***********************************/
#define HIFC_SRQE_SIZE          (32)
#define HIFC_SRQ_INIT_LOOP_O    (1)
#define HIFC_QUEUE_RING         (1)
#define HIFC_SRQ_ELS_DATA_NUM   (1)
#define HIFC_SRQ_ELS_SGE_LEN    (256)
#define HIFC_SRQ_ELS_DATA_DEPTH (4096)

#define HIFC_IRQ_NAME_MAX (30)

/* Support 2048 sessions(xid) */
#define HIFC_CQM_XID_MASK (0x7ff)

#define HIFC_QUEUE_FLUSH_DOING           (0)
#define HIFC_QUEUE_FLUSH_DONE            (1)
#define HIFC_QUEUE_FLUSH_WAIT_TIMEOUT_MS (2000)
#define HIFC_QUEUE_FLUSH_WAIT_MS         (2)

/************************* RPort defines ***********************************/
#define HIFC_EXIT_STRIDE                          (4096)
#define UNF_HIFC_MAXRPORT_NUM                     (2048)
#define HIFC_RPORT_OFFLOADED(prnt_qinfo)   \
	((prnt_qinfo)->offload_state == HIFC_QUEUE_STATE_OFFLOADED)
#define HIFC_RPORT_NOT_OFFLOADED(prnt_qinfo)  \
	((prnt_qinfo)->offload_state != HIFC_QUEUE_STATE_OFFLOADED)
#define HIFC_RPORT_FLUSH_NOT_NEEDED(prnt_qinfo)\
	(((prnt_qinfo)->offload_state == HIFC_QUEUE_STATE_INITIALIZED) ||  \
	((prnt_qinfo)->offload_state == HIFC_QUEUE_STATE_OFFLOADING) || \
	((prnt_qinfo)->offload_state == HIFC_QUEUE_STATE_FREE))
#define HIFC_CHECK_XID_MATCHED(sq_xid, sqe_xid) \
	(((sq_xid) & HIFC_CQM_XID_MASK) == ((sqe_xid) & HIFC_CQM_XID_MASK))
#define HIFC_PORT_MODE_TGT                        (0) /* Port mode */
#define HIFC_PORT_MODE_INI                        (1)
#define HIFC_PORT_MODE_BOTH                       (2)

/********** Hardware Reserved Queue Info defines ***************************/
#define HIFC_HRQI_SEQ_ID_MAX      (255)
#define HIFC_HRQI_SEQ_INDEX_MAX   (64)
#define HIFC_HRQI_SEQ_INDEX_SHIFT (6)
#define HIFC_HRQI_SEQ_SEPCIAL_ID  (3)
#define HIFC_HRQI_SEQ_INVALID_ID  (~0LL)

/************************* OQID defines ***********************************/

#define HIFC_OQID_HOST_XID_OFFSET     (5)
#define HIFC_OQID_HOST_RW_OFFSET      (4)
#define HIFC_OQID_HOST_ST_OFFSET      (2)
#define HIFC_OQID_HOST_OQID_LEN       (11)
#define HIFC_OQID_HOST_READ_FROM_HOST (0UL)
#define HIFC_OQID_HOST_WRITE_TO_HOST  (1)
#define HIFC_CPI_CHNL_ID_XOE_READ     (1UL)
#define HIFC_CPI_CHNL_ID_XOE_WRITE    (3UL)
#define HIFC_SERVICE_TYPE_FC_FCOE     (2)
/********************* sdk config defines ***********************************/
#define HIFC_CNTX_SIZE_256B      256
#define HIFC_QUEUE_LINK_STYLE    0
#define HIFC_PACKET_COS_FC_CMD   0
#define HIFC_PACKET_COS_FC_DATA  1
#define HIFC_DB_ARM_DISABLE      0
#define HIFC_DMA_ATTR_OFST       0
#define HIFC_PCIE_TEMPLATE       0
#define HIFC_PCIE_RELAXED_ORDERING 1
#define HIFC_OWNER_DRIVER_PRODUCT  1
#define HIFC_CMDQE_BUFF_LEN_MAX    2040
#define HIFC_CNTX_SIZE_T_256B      0

#define HIFC_OQID_IO_HOST_SET(xid, rw, cidx, vf_id, m, oqid)          \
	{                                                                 \
		oqid = (unsigned short)(((unsigned short)\
			((xid) << HIFC_OQID_HOST_XID_OFFSET))  \
			| ((unsigned short)((rw) << HIFC_OQID_HOST_RW_OFFSET)) \
			| ((unsigned short)(HIFC_SERVICE_TYPE_FC_FCOE << \
			HIFC_OQID_HOST_ST_OFFSET)) | (cidx));              \
		oqid = (unsigned short)\
			(((unsigned short)(oqid & (0x7ff >> (m))))\
			| ((unsigned short)((vf_id) << \
			(HIFC_OQID_HOST_OQID_LEN - (m))))); \
	}

#define HIFC_OQID_RD(xid, vf_id, m, oq_id) \
	HIFC_OQID_IO_HOST_SET(xid, HIFC_OQID_HOST_READ_FROM_HOST,\
			      HIFC_CPI_CHNL_ID_XOE_READ, vf_id, m, oq_id)

#define HIFC_OQID_WR(xid, vf_id, m, oq_id) \
	HIFC_OQID_IO_HOST_SET(xid, HIFC_OQID_HOST_WRITE_TO_HOST,\
			      HIFC_CPI_CHNL_ID_XOE_WRITE, vf_id, m, oq_id)

enum hifc_session_reset_mode_e {
	HIFC_SESS_RST_DELETE_IO_ONLY = 1,
	HIFC_SESS_RST_DELETE_CONN_ONLY = 2,
	HIFC_SESS_RST_DELETE_IO_CONN_BOTH = 3,
	HIFC_SESS_RST_MODE_BUTT
};

/* linkwqe */
#define CQM_LINK_WQE_CTRLSL_VALUE 2
#define CQM_LINK_WQE_LP_VALID     1
#define CQM_LINK_WQE_LP_INVALID   0

/****************** ROOT SQ&RQ&CTX defines ****************************/
struct nic_tx_doorbell {
	union {
		struct {
#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
			u32 srv_type : 5;
			u32 cos : 3;
			u32 c_flag : 1;
			u32 rsvd0 : 5;
			u32 queue_id : 10;
			u32 pi_high : 8;
#else
			u32 pi_high : 8;
			u32 queue_id : 10;
			u32 rsvd0 : 5;
			u32 c_flag : 1;
			u32 cos : 3;
			u32 srv_type : 5;
#endif
		} bs0;
		u32 dw0;
	};

	u32 rsvd1;
};

struct hifc_qp_ctxt_header {
	u16 num_queues;
	u16 queue_type;
	u32 addr_offset;
};

/*
 * nic_sq_ctx_1822 table define
 */
struct hifc_sq_ctxt {
	union {
		struct sq_ctx_dw0 {
#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
			/* whether generate CEQ */
			u32 ceq_arm : 1;
			u32 rsvd1 : 7;
			/* whether enable CEQ */
			u32 ceq_en : 1;
			u32 global_sq_id : 10;
			u32 ceq_num : 5;
			u32 pkt_template : 6;
			u32 rsvd2 : 2;
#else
			u32 rsvd2 : 2;
			u32 pkt_template : 6;
			u32 ceq_num : 5;
			u32 global_sq_id : 10;
			/* whether enable CEQ */
			u32 ceq_en : 1;
			u32 rsvd1 : 7;
			/* whether generate CEQ */
			u32 ceq_arm : 1;
#endif
		} sq_ctx_dw0;
		u32 dw0;
	};

	union {
		struct sq_ctx_dw1 {
#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
			u32 wqe_template : 6;
			u32 rsvd3 : 2;
			u32 owner : 1;
			/* customer index */
			u32 ci : 12;
			u32 tso_doing : 1;
			/* indicate how many sge left in current tso wqe */
			u32 sge_num_left : 6;
			/* number of sge processing */
			u32 processing_sge : 3;
			u32 rsvd4 : 1;
#else
			u32 rsvd4 : 1;
			/* number of sge processing */
			u32 processing_sge : 3;
			/* indicate how many sge left in current tso wqe */
			u32 sge_num_left : 6;
			u32 tso_doing : 1;
			/* customer index */
			u32 ci : 12;
			u32 owner : 1;
			u32 rsvd3 : 2;
			u32 wqe_template : 6;
#endif
		} sq_ctx_dw1;
		u32 dw1;
	};

	union {
		struct sq_ctx_dw2 {
#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
			u32 rsvd5 : 12;
			/* the wqe page address that current ci point to */
			u32 ci_wqe_page_addr_hi : 20;
#else
			/* the wqe page address that current ci point to */
			u32 ci_wqe_page_addr_hi : 20;
			u32 rsvd5 : 12;
#endif
		} sq_ctx_dw2;
		u32 dw2;
	};

	u32 ci_wqe_page_addr_lo;

	union {
		struct sq_ctx_dw4 {
#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
			/*
			 * The minimum prefetch WQE cacheline number of this SQ
			 */
			u32 prefetch_min : 7;
			/*
			 * The maximum prefetch WQE cacheline number of this SQ
			 */
			u32 prefetch_max : 11;
			u32 prefetch_cache_threshold : 14;
#else
			u32 prefetch_cache_threshold : 14;
			/*
			 * The maximum prefetch WQE cacheline number of this SQ
			 */
			u32 prefetch_max : 11;
			/*
			 * The minimum prefetch WQE cacheline number of this SQ
			 */
			u32 prefetch_min : 7;
#endif
		} sq_ctx_dw4;
		u32 dw4;
	};

	union {
		struct sq_ctx_dw5 {
#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
			u32 rsvd6 : 31;
			u32 prefetch_owner : 1;
#else
			u32 prefetch_owner : 1;
			u32 rsvd6 : 31;
#endif
		} sq_ctx_dw5;
		u32 dw5;
	};

	union {
		struct sq_ctx_dw6 {
#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
			u32 prefetch_ci : 12;
			u32 prefetch_ci_wqe_addr_hi : 20;
#else
			u32 prefetch_ci_wqe_addr_hi : 20;
			u32 prefetch_ci : 12;
#endif
		} sq_ctx_dw6;
		u32 dw6;
	};

	u32 prefetch_ci_wqe_addr_lo;

	union {
		struct sq_ctx_dw8 {
#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
			/* processed length of current seg */
			u32 processed_seg_len : 16;
			u32 rsvd7 : 16;
#else
			u32 rsvd7 : 16;
			/* processed length of current seg */
			u32 processed_seg_len : 16;
#endif
		} sq_ctx_dw8;
		u32 dw8;
	};

	u32 qsf;

	union {
		struct sq_ctx_dw10 {
#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
			u32 rsvd8 : 9;
			/* CI CLA table address */
			u32 cla_addr_hi : 23;
#else
			/* CI CLA table address */
			u32 cla_addr_hi : 23;
			u32 rsvd8 : 9;
#endif
		} sq_ctx_dw10;
		u32 dw10;
	};

	u32 cla_addr_lo;
};

struct hifc_sq_ctxt_block {
	struct hifc_qp_ctxt_header cmdq_hdr;
	struct hifc_sq_ctxt sq_ctx[HIFC_ROOT_CFG_SQ_NUM_MAX];
};

/*
 * nic_rq_ctx_1822 table define
 */
struct hifc_rq_ctxt {
	union {
		struct {
#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
			u32 max_count : 10;
			u32 cqe_tmpl : 6;
			u32 pkt_tmpl : 6;
			u32 wqe_tmpl : 6;
			u32 psge_valid : 1;
			u32 rsvd1 : 1;
			u32 owner : 1;
			u32 ceq_en : 1;
#else
			u32 ceq_en : 1;
			u32 owner : 1;
			u32 rsvd1 : 1;
			u32 psge_valid : 1;
			u32 wqe_tmpl : 6;
			u32 pkt_tmpl : 6;
			u32 cqe_tmpl : 6;
			u32 max_count : 10;
#endif
		} bs;
		u32 dw0;
	};

	union {
		struct {
#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
			/*
			 * Interrupt number that L2NIC engine tell SW if
			 * generate int instead of CEQ
			 */
			u32 int_num : 10;
			u32 ceq_count : 10;
			/* product index */
			u32 pi : 12;
#else
			/* product index */
			u32 pi : 12;
			u32 ceq_count : 10;
			/*
			 * Interrupt number that L2NIC engine tell SW if
			 * generate int instead of CEQ
			 */
			u32 int_num : 10;
#endif
		} bs0;
		struct {
#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
			/*
			 * CEQ arm, L2NIC engine will clear it after send ceq,
			 * driver should set it by CMD Q after receive all pkt.
			 */
			u32 ceq_arm : 1;
			u32 eq_id : 5;
			u32 rsvd2 : 4;
			u32 ceq_count : 10;
			/* product index */
			u32 pi : 12;
#else
			/* product index */
			u32 pi : 12;
			u32 ceq_count : 10;
			u32 rsvd2 : 4;
			u32 eq_id : 5;
			/* CEQ arm, L2NIC engine will clear it after send ceq,
			 * driver should set it by CMD Q after receive all pkt.
			 */
			u32 ceq_arm : 1;
#endif
		} bs1;
		u32 dw1;
	};

	union {
		struct {
#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
			/* consumer index */
			u32 ci : 12;
			/* WQE page address of current CI point to, high part */
			u32 ci_wqe_page_addr_hi : 20;
#else
			/* WQE page address of current CI point to, high part */
			u32 ci_wqe_page_addr_hi : 20;
			/* consumer index */
			u32 ci : 12;
#endif
		} bs2;
		u32 dw2;
	};

	/* WQE page address of current CI point to, low part */
	u32 ci_wqe_page_addr_lo;

	union {
		struct {
#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
			u32 prefetch_min : 7;
			u32 prefetch_max : 11;
			u32 prefetch_cache_threshold : 14;
#else
			u32 prefetch_cache_threshold : 14;
			u32 prefetch_max : 11;
			u32 prefetch_min : 7;
#endif
		} bs3;
		u32 dw3;
	};

	union {
		struct {
#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
			u32 rsvd3 : 31;
			/* ownership of WQE */
			u32 prefetch_owner : 1;
#else
			/* ownership of WQE */
			u32 prefetch_owner : 1;
			u32 rsvd3 : 31;
#endif
		} bs4;
		u32 dw4;
	};

	union {
		struct {
#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
			u32 prefetch_ci : 12;
			/* high part */
			u32 prefetch_ci_wqe_page_addr_hi : 20;
#else
			/* high part */
			u32 prefetch_ci_wqe_page_addr_hi : 20;
			u32 prefetch_ci : 12;
#endif
		} bs5;
		u32 dw5;
	};

	/* low part */
	u32 prefetch_ci_wqe_page_addr_lo;
	/* host mem GPA, high part */
	u32 pi_gpa_hi;
	/* host mem GPA, low part */
	u32 pi_gpa_lo;

	union {
		struct {
#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
			u32 rsvd4 : 9;
			u32 ci_cla_tbl_addr_hi : 23;
#else
			u32 ci_cla_tbl_addr_hi : 23;
			u32 rsvd4 : 9;
#endif
		} bs6;
		u32 dw6;
	};

	u32 ci_cla_tbl_addr_lo;
};

struct hifc_rq_ctxt_block {
	struct hifc_qp_ctxt_header cmdq_hdr;
	struct hifc_rq_ctxt rq_ctx[HIFC_ROOT_CFG_RQ_NUM_MAX];
};

struct hifc_root_qsf_s {
#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
	/* packet priority, engine pass pri to ucode */
	u32 pri : 3;
	/* unicast flag, engine pass uc to ucode */
	u32 uc : 1;
	/* sctp packet, engine pass sctp to ucode */
	u32 sctp : 1;
	/* mss */
	u32 mss : 14;
	/* when set, hi1822 calculates the tcp/udp check sum of the packet */
	u32 tcp_udp_cs : 1;
	/*
	 * transmit segmentation offload is activated when the tso flag is set
	 */
	u32 tso : 1;
	/* for udp packet, engine read the whole udp packet from host by 1 dma
	 * read, and ipsu calculate udp checksum, ucode do ip segment
	 */
	u32 ufo : 1;
	/* payload offset. it is the start position to calculate tcp/udp
	 * checksum or sctp crc
	 */
	u32 payload_offset : 8;
	/* reserved */
	u32 route_to_ucode : 2;
#else
	/* reserved */
	u32 route_to_ucode : 2;
	/*
	 * payload offset. it is the start position to calculate tcp/udp
	 * checksum or sctp crc
	 */
	u32 payload_offset : 8;
	/*
	 * for udp packet, engine read the whole udp packet from host by 1 dma
	 * read, and ipsu calculate udp checksum, ucode do ip segment
	 */
	u32 ufo : 1;
	/*
	 * transmit segmentation offload is activated when the tso flag is set
	 */
	u32 tso : 1;
	/* when set, hi1822 calculates the tcp/udp check sum of the packet */
	u32 tcp_udp_cs : 1;
	/* mss */
	u32 mss : 14;
	/* sctp packet, engine pass sctp to ucode */
	u32 sctp : 1;
	/* unicast flag, engine pass uc to ucode */
	u32 uc : 1;
	/* packet priority, engine pass pri to ucode */
	u32 pri : 3;
#endif
};

struct hifc_root_db_addr_s {
	unsigned long long phy_addr;
	void __iomem *virt_map_addr;
};

/* send queue management structure */
struct hifc_root_sq_info_s {
	spinlock_t root_sq_spin_lock;

	unsigned short qid;
	unsigned short max_qnum;
	unsigned short pi; /* ring buffer Pi */
	unsigned short ci; /* ring buffer Ci */
	unsigned short owner;
	unsigned short hardware_write_back_value;
	unsigned short q_depth;
	unsigned short wqe_bb_size; /* WQE Basic size */

	char irq_name[HIFC_IRQ_NAME_MAX];
	unsigned int irq_id;
	unsigned short msix_entry_idx;

	unsigned short *ci_addr;
	dma_addr_t ci_dma_addr;

	unsigned long long cla_addr;
	void *sq_handle;
	struct hifc_root_db_addr_s direct_db;
	struct hifc_root_db_addr_s normal_db;
	unsigned int db_idx;
	unsigned int global_qpn;
	int in_flush;
	void *root_info;
};

struct hifc_root_rq_info_s {
	unsigned short qid;
	unsigned short max_qnum;
	unsigned short pi;
	unsigned short ci;
	unsigned short owner;

	unsigned short q_depth;
	unsigned short q_mask;
	unsigned short wqe_bb_size;

	char irq_name[HIFC_IRQ_NAME_MAX];
	unsigned int irq_id;
	unsigned short msix_entry_idx;

	unsigned short *pi_vir_addr;
	dma_addr_t pi_dma_addr;

	/* Root RQ Receive Buffer size and completion buff */
	unsigned int rqc_buff_size;
	void *rq_completion_buff;
	dma_addr_t rq_completion_dma;
	unsigned int rq_rcv_buff_size;
	void *rq_rcv_buff;
	dma_addr_t rq_rcv_dma;
	void *rq_handle;

	/* for queue context init */
	unsigned long long ci_cla_tbl_addr;

	unsigned int global_qpn;
	struct tasklet_struct tasklet;
	atomic_t flush_state;

	void *root_info;
};

struct hifc_root_info_s {
	void *phba;
	unsigned int sq_num;
	unsigned int sq_ci_table_size;
	void *virt_sq_ci_table_buff;
	dma_addr_t sq_ci_table_dma;
	void *sq_info;

	unsigned int rq_num;
	unsigned int rq_pi_table_size;
	void *virt_rq_pi_table_buff;
	dma_addr_t rq_pi_table_dma;
	void *rq_info;
};

/**************************** SCQ defines ********************************/
struct hifc_scq_info_s {
	struct cqm_queue_s *cqm_scq_info;
	unsigned int wqe_num_per_buf;
	unsigned int wqe_size;
	/* 0-256, 1-512, 2-1k, 3-2k, 4-4k, 5-8k, 6-16k, 7-32k */
	unsigned int scqc_cq_depth;
	unsigned short scqc_ci_type;
	unsigned short valid_wqe_num; /* ScQ depth include link wqe */
	unsigned short ci;
	unsigned short ci_owner;

	unsigned int queue_id;
	unsigned int scqn;
	char irq_name[HIFC_IRQ_NAME_MAX];
	unsigned short msix_entry_idx;
	unsigned int irq_id;
	struct tasklet_struct tasklet;
	atomic_t flush_state;

	void *phba;
	unsigned int reserved;
	struct task_struct *delay_task;
	int task_exit;
	unsigned int intrmode;
};

/************************* SRQ depth ***********************************/
struct hifc_srq_ctx_s {
#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
	/* DW0 */
	unsigned long long last_rq_pmsn : 16;
	unsigned long long cur_rqe_msn : 16;
	unsigned long long cur_rqe_user_id : 16;
	unsigned long long parity : 8;
	unsigned long long rsvd0 : 2;
	unsigned long long pcie_template : 6;

	/* DW1 */
	unsigned long long cur_rqe_gpa;

	/* DW2 */
	unsigned long long cur_sge_v : 1;
	unsigned long long cur_sge_l : 1;
	unsigned long long int_mode : 2;
	unsigned long long ceqn_msix : 11;
	unsigned long long cur_sge_remain_len : 17;
	unsigned long long cur_sge_id : 4;
	unsigned long long consant_sge_len : 17;
	unsigned long long cur_wqe : 1;
	unsigned long long pmsn_type : 1;
	unsigned long long bdsl : 4;
	unsigned long long cr : 1;
	unsigned long long csl : 2;
	unsigned long long cf : 1;
	unsigned long long ctrl_sl : 1;

	/* DW3 */
	unsigned long long cur_sge_gpa;

	/* DW4 */
	unsigned long long cur_pmsn_gpa;

	/* DW5 */
	unsigned long long pre_fetch_max_msn : 16;
	unsigned long long cqe_max_cnt : 8;
	unsigned long long cur_cqe_cnt : 8;
	unsigned long long arm_q : 1;
	unsigned long long rsvd1 : 7;
	unsigned long long cq_so_ro : 2;
	unsigned long long cqe_dma_attr_idx : 6;
	unsigned long long rq_so_ro : 2;
	unsigned long long rqe_dma_attr_idx : 6;
	unsigned long long rsvd2 : 1;
	unsigned long long loop_o : 1;
	unsigned long long ring : 1;
	unsigned long long rsvd3 : 5;

#else
	/* DW0 */
	unsigned long long pcie_template : 6;
	unsigned long long rsvd0 : 2;
	unsigned long long parity : 8;
	unsigned long long cur_rqe_user_id : 16;
	unsigned long long cur_rqe_msn : 16;
	unsigned long long last_rq_pmsn : 16;

	/* DW1 */
	unsigned long long cur_rqe_gpa;

	/* DW2 */
	unsigned long long ctrl_sl : 1;
	unsigned long long cf : 1;
	unsigned long long csl : 2;
	unsigned long long cr : 1;
	unsigned long long bdsl : 4;
	unsigned long long pmsn_type : 1;
	unsigned long long cur_wqe : 1;
	unsigned long long consant_sge_len : 17;
	unsigned long long cur_sge_id : 4;
	unsigned long long cur_sge_remain_len : 17;
	unsigned long long ceqn_msix : 11;
	unsigned long long int_mode : 2;
	unsigned long long cur_sge_l : 1;
	unsigned long long cur_sge_v : 1;

	/* DW3 */
	unsigned long long cur_sge_gpa;

	/* DW4 */
	unsigned long long cur_pmsn_gpa;

	/* DW5 */
	unsigned long long rsvd3 : 5;
	unsigned long long ring : 1;
	unsigned long long loop_o : 1;
	unsigned long long rsvd2 : 1;
	unsigned long long rqe_dma_attr_idx : 6;
	unsigned long long rq_so_ro : 2;
	unsigned long long cqe_dma_attr_idx : 6;
	unsigned long long cq_so_ro : 2;
	unsigned long long rsvd1 : 7;
	unsigned long long arm_q : 1;
	unsigned long long cur_cqe_cnt : 8;
	unsigned long long cqe_max_cnt : 8;
	unsigned long long pre_fetch_max_msn : 16;

#endif

	/* DW6~DW7 */
	unsigned long long rsvd4;
	unsigned long long rsvd5;

};

struct hifc_srq_buff_entry_s {
	unsigned short buff_id;
	void *buff_addr;
	dma_addr_t buff_dma;
};

enum hifc_clean_state_e {
	HIFC_CLEAN_DONE,
	HIFC_CLEAN_DOING,
	HIFC_CLEAN_BUTT
};

enum hifc_srq_type_e {
	HIFC_SRQ_ELS = 1,
	HIFC_SRQ_BUTT
};

struct hifc_srq_info_s {
	enum hifc_srq_type_e srq_type;

	struct cqm_queue_s *cqm_srq_info;
	/* Wqe number per buf, dont't inlcude link wqe */
	unsigned int wqe_num_per_buf;
	unsigned int wqe_size;
	/* valid wqe number, dont't include link wqe */
	unsigned int valid_wqe_num;
	unsigned short pi;
	unsigned short pi_owner;
	unsigned short pmsn;
	unsigned short ci;
	unsigned short cmsn;
	unsigned int srqn;

	dma_addr_t first_rqe_rcv_dma;

	struct hifc_srq_buff_entry_s *els_buff_entry_head;
	struct buf_describe_s buff_list;
	spinlock_t srq_spin_lock;
	int spin_lock_init;
	int enable;
	enum hifc_clean_state_e state;
	struct delayed_work del_work;
	unsigned int del_retry_time;
	void *phba;
};

/*
 * The doorbell record keeps PI of WQE, which will be produced next time.
 * The PI is 15 bits width o-bit
 */
struct hifc_db_record {
#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
	u64 rsvd0 : 32;
	unsigned long long dump_pmsn : 16;
	unsigned long long pmsn : 16;
#else
	unsigned long long pmsn : 16;
	unsigned long long dump_pmsn : 16;
	u64 rsvd0 : 32;
#endif
};

/*
 * The ci record keeps CI of WQE, which will be consumed next time.
 * The ci is 15 bits width with 1 o-bit
 */
struct hifc_ci_record_s {
#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
	u64 rsvd0 : 32;
	unsigned long long dump_cmsn : 16;
	unsigned long long cmsn : 16;
#else
	unsigned long long cmsn : 16;
	unsigned long long dump_cmsn : 16;
	u64 rsvd0 : 32;
#endif
};

/* The accumulate data in WQ header */
struct hifc_accumulate {
	u64 data_2_uc;
	u64 data_2_drv;
};

/* The WQ header structure */
struct hifc_wq_header_s {
	struct hifc_db_record db_record;
	struct hifc_ci_record_s ci_record;
	struct hifc_accumulate soft_data;

};

/* Link list Sq WqePage Pool */
/* queue header struct */
struct hifc_queue_header_s {
	unsigned long long doorbell_record;
	unsigned long long ci_record;
	unsigned long long ulrsv1;
	unsigned long long ulrsv2;
};

/* WPG-WQEPAGE, LLSQ-LINKED LIST SQ */
struct hifc_sq_wqe_page_s {
	struct list_head entry_wpg;
	/* Wqe Page virtual addr */
	void *wpg_addr;
	/* Wqe Page physical addr */
	unsigned long long wpg_phy_addr;
};

struct hifc_sq_wqe_page_pool_s {
	unsigned int wpg_cnt;
	unsigned int wpg_size;
	unsigned int wqe_per_wpg;

	/* PCI DMA Pool */
	struct dma_pool *wpg_dma_pool;
	struct hifc_sq_wqe_page_s *wpg_pool_addr;
	struct list_head list_free_wpg_pool;
	spinlock_t wpg_pool_lock;
	atomic_t wpg_in_use;
};

#define HIFC_SQ_DEL_STAGE_TIMEOUT_MS        (3 * 1000)
#define HIFC_SRQ_DEL_STAGE_TIMEOUT_MS       (10 * 1000)
#define HIFC_SQ_WAIT_FLUSH_DONE_TIMEOUT_MS  (10)
#define HIFC_SQ_WAIT_FLUSH_DONE_TIMEOUT_CNT (3)

#define HIFC_SRQ_PROCESS_DELAY_MS (20)

/* PLOGI parameters */
struct hifc_plogi_coparams_s {
	unsigned int seq_cnt : 1;
	unsigned int ed_tov : 1;
	unsigned int reserved : 14;
	unsigned int tx_mfs : 16;
	unsigned int ed_tov_timer_val;
};

struct hifc_delay_sqe_ctrl_info_s {
	int valid;
	unsigned int rport_index;
	unsigned int time_out;
	unsigned long long start_jiff;
	unsigned int sid;
	unsigned int did;
	struct hifc_root_sqe_s sqe;
};

struct hifc_destroy_ctrl_info_s {
	int valid;
	unsigned int rport_index;
	unsigned int time_out;
	unsigned long long start_jiff;
	struct unf_rport_info_s rport_info;
};

/* PARENT SQ Info */
struct hifc_parent_sq_info_s {
	void *phba;

	spinlock_t parent_sq_enqueue_lock;
	atomic_t wqe_page_cnt;
	unsigned int rport_index;

	unsigned int context_id;

	/* Fixed value,used for Doorbell */
	unsigned int sq_queue_id;

	/* When a session is offloaded, tile will return the CacheId to the
	 * driver,which is used for Doorbell
	 */
	unsigned int cache_id;

	/* service type, fc */
	unsigned int service_type;

	/* OQID */
	unsigned short oqid_rd;
	unsigned short oqid_wr;

	unsigned int max_sqe_num; /* SQ depth */
	unsigned int wqe_num_per_buf;
	unsigned int wqe_size;

	unsigned int wqe_offset;
	unsigned short head_start_cmsn;
	unsigned short head_end_cmsn;
	unsigned short last_pmsn;
	unsigned short last_pi_owner;

	unsigned int local_port_id;
	unsigned int remote_port_id;
	int port_in_flush;
	int sq_in_sess_rst;
	atomic_t sq_valid;

	void *queue_header_original;
	struct hifc_queue_header_s *queue_header;
	dma_addr_t queue_hdr_phy_addr_original;
	dma_addr_t queue_hdr_phy_addr;

	/* Linked List SQ */
	struct list_head list_linked_list_sq;

	unsigned char vport_id;
	struct delayed_work del_work;
	struct delayed_work flush_done_tmo_work;
	unsigned long long del_start_jiff;
	dma_addr_t srq_ctx_addr;
	atomic_t sq_cashed;
	atomic_t fush_done_wait_cnt;

	struct hifc_plogi_coparams_s plogi_coparams;

	/* dif control info for immi */
	struct unf_dif_control_info_s sirt_dif_control;

	atomic_t sq_dbl_cnt;
	atomic_t sq_wqe_cnt;
	atomic_t sq_cqe_cnt;
	atomic_t sqe_minus_cqe_cnt;

	struct hifc_delay_sqe_ctrl_info_s delay_sqe;
	struct hifc_destroy_ctrl_info_s destroy_sqe;
	atomic_t io_stat[HIFC_MAX_SQ_TASK_TYPE_CNT];

};

/* parent context doorbell */
struct hifc_parent_sq_db_s {
	struct {
#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
		u32 service_type : 5;
		u32 cos : 3;
		u32 c : 1;
		u32 arm : 1;
		u32 cntx_size : 2;
		u32 vport : 7;
		u32 xid : 13;
#else
		u32 xid : 13;
		u32 vport : 7;
		u32 cntx_size : 2;
		u32 arm : 1;
		u32 c : 1;
		u32 cos : 3;
		u32 service_type : 5;
#endif
	} wd0;

	struct {
#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
		u32 qid : 4;
		u32 sm_data : 20;
		u32 pi_hi : 8;
#else
		u32 pi_hi : 8;
		u32 sm_data : 20;
		u32 qid : 4;
#endif
	} wd1;

};

struct hifc_parent_cmd_scq_info_s {
	unsigned int cqm_queue_id;
	unsigned int local_queue_id;
};

struct hifc_parent_st_scq_info_s {
	unsigned int cqm_queue_id;
	unsigned int local_queue_id;
};

struct hifc_parent_els_srq_info_s {
	unsigned int cqm_queue_id;
	unsigned int local_queue_id;
};

enum hifc_parent_queue_state_e {
	HIFC_QUEUE_STATE_INITIALIZED = 0,
	HIFC_QUEUE_STATE_OFFLOADING = 1,
	HIFC_QUEUE_STATE_OFFLOADED = 2,
	HIFC_QUEUE_STATE_DESTROYING = 3,
	HIFC_QUEUE_STATE_FREE = 4,
	HIFC_QUEUE_STATE_BUTT
};

struct hifc_parent_ctx_s {
	dma_addr_t parent_ctx;
	/* Allocated by driver, Driver filled it when a session offload */
	void *virt_parent_ctx;
	/* Allocated by CQM,used by Hardware */
	struct cqm_qpc_mpt_s *cqm_parent_ctx_obj;
};

struct hifc_parent_queue_info_s {
	spinlock_t parent_queue_state_lock;
	struct hifc_parent_ctx_s parent_ctx;
	enum hifc_parent_queue_state_e offload_state;
	struct hifc_parent_sq_info_s parent_sq_info;
	/* Cmd Scq info which is assocaiated with parent queue */
	struct hifc_parent_cmd_scq_info_s parent_cmd_scq_info;
	/* Sts Scq info which is assocaiated with parent queue */
	struct hifc_parent_st_scq_info_s parent_sts_scq_info;
	/* ELS Srq info which is assocaiated with parent queue */
	unsigned char queue_vport_id;
	struct hifc_parent_els_srq_info_s parent_els_srq_info;
	unsigned char queue_data_cos;
};

struct hifc_parent_queue_mgr_s {
	struct hifc_parent_queue_info_s parent_queues[UNF_HIFC_MAXRPORT_NUM];
	struct buf_describe_s parent_sq_buf_list;
};

struct hifc_get_global_base_qpn_s {
	/* for new version interface */
	unsigned char status;
	unsigned char version;
	unsigned char rsvd0[6];

	unsigned short func_id;
	unsigned short base_qpn;
};

#define HIFC_SRQC_BUS_ROW    8
#define HIFC_SRQC_BUS_COL    19
#define HIFC_SQC_BUS_ROW     8
#define HIFC_SQC_BUS_COL     13
#define HIFC_HW_SCQC_BUS_ROW 6
#define HIFC_HW_SCQC_BUS_COL 10
#define HIFC_HW_SRQC_BUS_ROW 4
#define HIFC_HW_SRQC_BUS_COL 15
#define HIFC_SCQC_BUS_ROW    3
#define HIFC_SCQC_BUS_COL    29

#define HIFC_QUEUE_INFO_BUS_NUM 4
struct hifc_queue_info_bus_s {
	unsigned long long bus[HIFC_QUEUE_INFO_BUS_NUM];
};

unsigned int hifc_free_parent_resource(void *v_hba,
				       struct unf_rport_info_s *v_rport_info);
unsigned int hifc_alloc_parent_resource(void *v_hba,
					struct unf_rport_info_s *v_rport_info);
unsigned int hifc_create_root_queues(void *v_hba);
void hifc_destroy_root_queues(void *v_hba);
unsigned int hifc_alloc_parent_queue_mgr(void *v_hba);
void hifc_free_parent_queue_mgr(void *v_hba);
unsigned int hifc_create_common_share_queues(void *v_hba);
void hifc_destroy_common_share_queues(void *v_hba);
unsigned int hifc_alloc_parent_sq_wqe_page_pool(void *v_hba);
void hifc_free_parent_sq_wqe_page_pool(void *v_hba);

struct hifc_parent_queue_info_s *hifc_find_parent_queue_info_by_pkg(
					void *v_hba,
					struct unf_frame_pkg_s *v_pkg);
struct hifc_parent_sq_info_s *hifc_find_parent_sq_by_pkg(
				void *v_hba, struct unf_frame_pkg_s *v_pkg);
struct hifc_parent_ctx_s *hifc_get_parnt_ctx_virt_addr_by_pkg(
				void *v_hba,
				struct unf_frame_pkg_s *v_pkg);
unsigned int hifc_get_parent_ctx_xid_by_pkg(void *v_hba,
					    struct unf_frame_pkg_s *v_pkg);

unsigned int hifc_root_sq_enqueue(void *v_hba,
				  struct hifc_root_sqe_s *v_sqe);
void hifc_process_root_rqe(unsigned long v_rq_info);

unsigned int hifc_root_cmdq_enqueue(void *v_hba,
				    union hifc_cmdqe_u *v_cmd_qe,
				    unsigned short v_cmd_len);

void hifc_process_scq_cqe(unsigned long scq_info);
unsigned int hifc_process_scq_cqe_entity(unsigned long v_scq_info,
					 unsigned int proc_cnt);

void hifc_post_els_srq_wqe(struct hifc_srq_info_s *v_srq_info,
			   unsigned short buf_id);
void hifc_process_aeqe(void *v_srv_handle, unsigned char evt_type, u64 evt_val);

unsigned int hifc_parent_sq_enqueue(struct hifc_parent_sq_info_s *v_sq,
				    struct hifcoe_sqe_s *v_sqe);
void hifc_free_sq_wqe_page(struct hifc_parent_sq_info_s *v_sq,
			   unsigned int cur_cmsn);
unsigned int hifc_reclaim_sq_wqe_page(void *v_hba, union hifcoe_scqe_u *v_scqe);

void hifc_set_root_sq_flush_state(void *v_hba, int in_flush);
void hifc_set_rport_flush_state(void *v_hba, int in_flush);
unsigned int hifc_clear_fetched_sq_wqe(void *v_hba);
unsigned int hifc_clear_pending_sq_wqe(void *v_hba);

void hifc_free_parent_queues(void *v_hba);
void hifc_enable_queues_dispatch(void *v_hba);
void hifc_queue_pre_process(void *v_hba, int v_clean);
void hifc_free_parent_queue_info(
		void *v_hba,
		struct hifc_parent_queue_info_s *v_parent_queue_info);
unsigned int hifc_send_session_rst_cmd(
		void *v_hba,
		struct hifc_parent_queue_info_s *v_parent_queue_info,
		unsigned int v_mode);
void hifc_build_session_rst_wqe(void *v_hba,
				struct hifc_parent_sq_info_s *v_sq,
				struct hifcoe_sqe_s *v_sqe,
				enum hifc_session_reset_mode_e v_mode,
				unsigned int scqn);

unsigned int hifc_rport_session_rst(void *v_hba,
				    struct unf_rport_info_s *v_rport_info);
unsigned int hifc_get_rport_maped_cmd_scqn(void *v_hba,
					   unsigned int rport_index);
unsigned int hifc_get_rport_maped_sts_scqn(void *v_hba,
					   unsigned int rport_index);

void hifc_destroy_srq(void *v_hba);
unsigned int hifc_push_delay_sqe(
		void *v_hba,
		struct hifc_parent_queue_info_s *v_offload_parent_queue,
		struct hifc_root_sqe_s *v_sqe,
		struct unf_frame_pkg_s *v_pkg);

void hifc_push_destroy_parent_queue_sqe(
		void *v_hba,
		struct hifc_parent_queue_info_s *v_offload_parent_queue,
		struct unf_rport_info_s *v_rport_info);
void hifc_pop_destroy_parent_queue_sqe(
		void *v_hba,
		struct hifc_destroy_ctrl_info_s *v_destroy_sqe_info);
struct hifc_parent_queue_info_s *hifc_find_offload_parent_queue(
		void *v_hba,
		unsigned int v_local_id,
		unsigned int v_remote_id,
		unsigned int v_rport_index);

unsigned int hifc_flush_ini_resp_queue(void *v_hba);
void hifc_rcvd_els_from_srq_time_out(struct work_struct *work);
#endif
