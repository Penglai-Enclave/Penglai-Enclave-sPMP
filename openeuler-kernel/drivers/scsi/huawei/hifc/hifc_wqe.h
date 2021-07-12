/* SPDX-License-Identifier: GPL-2.0 */
/* Huawei Hifc PCI Express Linux driver
 * Copyright(c) 2017 Huawei Technologies Co., Ltd
 *
 */

#ifndef __HIFC_WQE_H__
#define __HIFC_WQE_H__

#include "hifcoe_wqe.h"
#include "hifcoe_parent_context.h"

/* TGT WQE type */
/* DRV->uCode via Root or Parent SQ */
#define HIFC_SQE_FCP_TRD      HIFCOE_TASK_T_TREAD
#define HIFC_SQE_FCP_TWR      HIFCOE_TASK_T_TWRITE
#define HIFC_SQE_FCP_TRSP     HIFCOE_TASK_T_TRESP
#define HIFC_SQE_FCP_TACK     HIFCOE_TASK_T_TACK
#define HIFC_SQE_ELS_CMND     HIFCOE_TASK_T_ELS
#define HIFC_SQE_ELS_RSP      HIFCOE_TASK_T_ELS_RSP
#define HIFC_SQE_GS_CMND      HIFCOE_TASK_T_GS
#define HIFC_SQE_BLS_CMND     HIFCOE_TASK_T_ABTS
#define HIFC_SQE_FCP_IREAD    HIFCOE_TASK_T_IREAD
#define HIFC_SQE_FCP_IWRITE   HIFCOE_TASK_T_IWRITE
#define HIFC_SQE_FCP_ITMF     HIFCOE_TASK_T_ITMF
#define HIFC_SQE_SESS_RST     HIFCOE_TASK_T_SESS_RESET
#define HIFC_SQE_FCP_TMF_TRSP HIFCOE_TASK_T_TMF_RESP

/* DRV->uCode Via CMDQ */
#define HIFC_CMDQE_ABTS_RSP HIFCOE_TASK_T_ABTS_RSP
#define HIFC_CMDQE_ABORT    HIFCOE_TASK_T_ABORT
#define HIFC_CMDQE_SESS_DIS HIFCOE_TASK_T_SESS_DIS
#define HIFC_CMDQE_SESS_DEL HIFCOE_TASK_T_SESS_DEL

/* uCode->Drv Via CMD SCQ */
#define HIFC_SCQE_FCP_TCMND    HIFCOE_TASK_T_RCV_TCMND
#define HIFC_SCQE_ELS_CMND     HIFCOE_TASK_T_RCV_ELS_CMD
#define HIFC_SCQE_ABTS_CMD     HIFCOE_TASK_T_RCV_ABTS_CMD
#define HIFC_SCQE_FCP_IRSP     HIFCOE_TASK_T_IRESP
#define HIFC_SCQE_FCP_ITMF_RSP HIFCOE_TASK_T_ITMF_RESP

/* uCode->Drv Via STS SCQ */
#define HIFC_SCQE_FCP_TSTS        HIFCOE_TASK_T_TSTS
#define HIFC_SCQE_GS_RSP          HIFCOE_TASK_T_RCV_GS_RSP
#define HIFC_SCQE_ELS_RSP         HIFCOE_TASK_T_RCV_ELS_RSP
#define HIFC_SCQE_ABTS_RSP        HIFCOE_TASK_T_RCV_ABTS_RSP
#define HIFC_SCQE_ELS_RSP_STS     HIFCOE_TASK_T_ELS_RSP_STS
#define HIFC_SCQE_ABTS_RSP_STS    HIFCOE_TASK_T_ABTS_RSP_STS
#define HIFC_SCQE_ABORT_STS       HIFCOE_TASK_T_ABORT_STS
#define HIFC_SCQE_SESS_EN_STS     HIFCOE_TASK_T_SESS_EN_STS
#define HIFC_SCQE_SESS_DIS_STS    HIFCOE_TASK_T_SESS_DIS_STS
#define HIFC_SCQE_SESS_DEL_STS    HIFCOE_TASK_T_SESS_DEL_STS
#define HIFC_SCQE_SESS_RST_STS    HIFCOE_TASK_T_SESS_RESET_STS
#define HIFC_SCQE_ITMF_MARKER_STS HIFCOE_TASK_T_ITMF_MARKER_STS
#define HIFC_SCQE_ABTS_MARKER_STS HIFCOE_TASK_T_ABTS_MARKER_STS
#define HIFC_SCQE_FLUSH_SQ_STS    HIFCOE_TASK_T_FLUSH_SQ_STS
#define HIFC_SCQE_BUF_CLEAR_STS   HIFCOE_TASK_T_BUFFER_CLEAR_STS
#define HIFC_SCQE_CLEAR_SRQ_STS   HIFCOE_TASK_T_CLEAR_SRQ_STS

#define HIFC_LOW_32_BITS(__addr) \
	((unsigned int)((unsigned long long)(__addr) & 0xffffffff))
#define HIFC_HIGH_32_BITS(__addr)\
	((unsigned int)(((unsigned long long)(__addr) >> 32) & 0xffffffff))

/* Error Code from SCQ */
#define HIFC_COMPLETION_STATUS_SUCCESS            FCOE_CQE_COMPLETED
#define HIFC_COMPLETION_STATUS_ABORTED_SETUP_FAIL FCOE_IMMI_CMDPKT_SETUP_FAIL

#define HIFC_COMPLETION_STATUS_TIMEOUT       FCOE_ERROR_CODE_E_D_TIMER_EXPIRE
#define HIFC_COMPLETION_STATUS_DIF_ERROR     FCOE_ERROR_CODE_DATA_DIFX_FAILED
#define HIFC_COMPLETION_STATUS_DATA_OOO      FCOE_ERROR_CODE_DATA_OOO_RO
#define HIFC_COMPLETION_STATUS_DATA_OVERFLOW  \
	FCOE_ERROR_CODE_DATA_EXCEEDS_DATA2TRNS

#define HIFC_SCQE_INVALID_CONN_ID      0xffff
#define HIFC_GET_SCQE_TYPE(scqe)       ((scqe)->common.ch.wd0.task_type)
#define HIFC_GET_SCQE_STATUS(scqe)     ((scqe)->common.ch.wd0.err_code)
#define HIFC_GET_SCQE_REMAIN_CNT(scqe) ((scqe)->common.ch.wd0.cqe_remain_cnt)
#define HIFC_GET_SCQE_CONN_ID(scqe)    ((scqe)->common.conn_id)
#define HIFC_GET_WQE_TYPE(wqe)         ((wqe)->ts_sl.task_type)

#define HIFC_WQE_IS_IO(wqe)         \
	(HIFC_GET_WQE_TYPE(wqe) != HIFC_SQE_SESS_RST)

#define HIFC_SCQE_HAS_ERRCODE(scqe)   \
	(HIFC_GET_SCQE_STATUS(scqe) != HIFC_COMPLETION_STATUS_SUCCESS)

#define HIFC_SCQE_ERR_TO_CM(scqe)\
	(HIFC_GET_SCQE_STATUS(scqe) != FCOE_ELS_GS_RSP_EXCH_CHECK_FAIL)
#define HIFC_SCQE_CONN_ID_VALID(scqe) \
	(HIFC_GET_SCQE_CONN_ID(scqe) != HIFC_SCQE_INVALID_CONN_ID)

#define HIFC_WQE_SECTION_CHUNK_SIZE      8  /* 8 bytes' chunk */
#define HIFC_T_RESP_WQE_CTR_TSL_SIZE     15 /* 8 bytes' chunk */
#define HIFC_T_RD_WR_WQE_CTR_TSL_SIZE    9  /* 8 bytes' chunk */
#define HIFC_T_RD_WR_WQE_CTR_BDSL_SIZE   4  /* 8 bytes' chunk */
#define HIFC_T_RD_WR_WQE_CTR_CTRLSL_SIZE 1  /* 8 bytes' chunk */

#define HIFC_WQE_SGE_ENTRY_NUM       2 /* BD SGE and DIF SGE count */
#define HIFC_WQE_SGE_DIF_ENTRY_NUM   1 /* DIF SGE count */
#define HIFC_WQE_SGE_LAST_FLAG       1
#define HIFC_WQE_SGE_NOT_LAST_FLAG   0
#define HIFC_WQE_SGE_EXTEND_FLAG     1
#define HIFC_WQE_SGE_NOT_EXTEND_FLAG 0

#define HIFC_FCP_TMF_PORT_RESET  0
#define HIFC_FCP_TMF_LUN_RESET   1
#define HIFC_FCP_TMF_TGT_RESET   2
#define HIFC_FCP_TMF_RSVD        3
#define HIFC_NO_OFFLOAD          0
#define HIFC_HAVE_OFFLOAD        1
#define HIFC_QID_SQ              0

#define HIFC_ADJUST_DATA(old_val, new_val) ((old_val) = (new_val))

#define HIFC_GET_RESET_TYPE(tmf_flag, reset_flag)		\
	do {							\
		switch (tmf_flag) {				\
		case UNF_FCP_TM_ABORT_TASK_SET:			\
		case UNF_FCP_TM_LOGICAL_UNIT_RESET:		\
			reset_flag = HIFC_FCP_TMF_LUN_RESET;	\
			break;					\
		case UNF_FCP_TM_TARGET_RESET:			\
			reset_flag = HIFC_FCP_TMF_TGT_RESET;	\
			break;					\
		case UNF_FCP_TM_CLEAR_TASK_SET:			\
			reset_flag = HIFC_FCP_TMF_PORT_RESET;	\
			break;					\
		default:					\
			reset_flag = HIFC_FCP_TMF_RSVD;		\
		}						\
	} while (0)

/*
 * nic_wqe_ctrl_sec table define
 */
struct nic_wqe_ctrl_sec {
	union {
		struct {
#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
			/* marks ownership of WQE */
			u32 owner : 1;
			/* Control Section Length */
			u32 ctrl_sec_len : 2;
			/* Completion Section Length */
			u32 completion_sec_len : 2;
			/* DIF Section Length */
			u32 dif_sec_len : 3;
			/*
			 * Completion is Required - marks CQE generation request
			 * per WQE
			 */
			u32 cr : 1;
			/* Data Format - format of BDS */
			u32 df : 1;
			/* Virtual Address */
			u32 va : 1;
			/* Task Section Length */
			u32 task_sec_len : 5;
			/* Completion Format */
			u32 cf : 1;
			u32 wf : 1;
			/* reserved */
			u32 rsvd : 4;
			/* Driver Section Length */
			u32 drv_sec_len : 2;
			/* Buffer Descriptors Section Length */
			u32 buf_desc_sec_len : 8;
#else
			/* Buffer Descriptors Section Length */
			u32 buf_desc_sec_len : 8;
			/* Driver Section Length */
			u32 drv_sec_len : 2;
			/* reserved */
			u32 rsvd : 4;
			u32 wf : 1;
			/* Completion Format */
			u32 cf : 1;
			/* Task Section Length */
			u32 task_sec_len : 5;
			/* Virtual Address */
			u32 va : 1;
			/* Data Format - format of BDS */
			u32 df : 1;
			/*
			 * Completion is Required - marks CQE generation request
			 * per WQE
			 */
			u32 cr : 1;
			/* DIF Section Length */
			u32 dif_sec_len : 3;
			/* Completion Section Length */
			u32 completion_sec_len : 2;
			/* Control Section Length */
			u32 ctrl_sec_len : 2;
			/* marks ownership of WQE */
			u32 owner : 1;
#endif
		} bs;

		u32 dw;
	};
};

/*
 * nic_rq_sge_sec table define
 */
struct nic_rq_sge_sec {
	/* packet buffer address high */
	u32 wb_addr_high;
	/* packet buffer address low */
	u32 wb_addr_low;

	union {
		struct {
#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
			u32 rsvd : 1;
			/* SGE length */
			u32 length : 31;
#else
			/* SGE length */
			u32 length : 31;
			u32 rsvd : 1;
#endif
		} bs0;
		u32 dw0;
	};

	union {
		struct {
#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
			/* 0:list,1:last */
			u32 list : 1;
			/* 0:normal,1:pointer to next SGE */
			u32 extension : 1;
			/* key or unsed */
			u32 key : 30;
#else
			/* key or unsed */
			u32 key : 30;
			/* 0:normal,1:pointer to next SGE */
			u32 extension : 1;
			/* 0:list,1:last */
			u32 list : 1;
#endif
		} bs1;
		u32 dw1;
	};
};

/*
 * nic_rq_bd_sec table define
 */
struct nic_rq_bd_sec {
	/* packet buffer address high */
	u32 pkt_buf_addr_high;
	/* packet buffer address low */
	u32 pkt_buf_addr_low;
};

/*
 * nic_rq_wqe table define
 */
struct nic_rq_wqe {
	struct nic_wqe_ctrl_sec rq_wqe_ctrl_sec;
	u32 rsvd;
	struct nic_rq_sge_sec rx_sge;
	struct nic_rq_bd_sec pkt_buf_addr;
};

/* Link WQE structure */
struct hifc_link_wqe_s {
	union {
		struct {
			unsigned int rsv1 : 14;
			unsigned int wf : 1;
			unsigned int rsv2 : 14;
			unsigned int ctrlsl : 2;
			unsigned int o : 1;
		} wd0;
		u32 val_wd0;
	};

	union {
		struct {
			unsigned int msn : 16;
			unsigned int dump_msn : 15;
			/* lp means whether O bit is overturn */
			unsigned int lp : 1;
		} wd1;
		unsigned int val_wd1;
	};

	unsigned int next_page_addr_hi;
	unsigned int next_page_addr_lo;
};

struct hifc_root_rq_complet_info_s {
#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
	unsigned int done : 1; /* done bit,ucode will set to 1 */
	unsigned int rsvd1 : 6;
	unsigned int fc_pkt : 1; /* Marks whether the packet is fc type */
	unsigned int rsvd2 : 24;
#else
	unsigned int rsvd2 : 24;
	unsigned int fc_pkt : 1; /* Marks whether the packet is fc type */
	unsigned int rsvd1 : 6;
	unsigned int done : 1; /* done bit,ucode will set to 1 */
#endif

#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
	unsigned short buf_length;
	unsigned short exch_id;
#else
	unsigned short exch_id;
	unsigned short buf_length;
#endif

#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
	unsigned short sts_only; /* If only CMPL SECTION */
	unsigned short status;  /* 0:no err;!0:others */
#else
	unsigned short status;  /* 0:no err;!0:others */
	unsigned short sts_only; /* If only CMPL SECTION */
#endif
	unsigned int magic_num;
	unsigned int rsvd[4];
};

/* Parent SQ WQE */
struct hifc_root_sge_s {
	unsigned int buf_addr_hi;
	unsigned int buf_addr_lo;
	struct {
#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
		unsigned int ext_flag : 1;
		unsigned int buf_len : 31;
#else
		unsigned int buf_len : 31;
		unsigned int ext_flag : 1;
#endif
	} wd0;
	struct {
		unsigned int rsvd;
	} wd1;
};

/* Root SQ WQE Task Section structure for FC */
struct hifc_root_sqe_task_section_s {
	struct {
#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
		unsigned int task_type : 8;
		/* 1:offload enable,0:offload disable. */
		unsigned int off_load : 1;
		unsigned int port_id : 4;
		unsigned int host_id : 2;
		unsigned int rsvd1 : 1;
		unsigned int exch_id : 16;
#else
		unsigned int exch_id : 16;
		unsigned int rsvd1 : 1;
		unsigned int host_id : 2;
		unsigned int port_id : 4;
		unsigned int off_load : 1;
		unsigned int task_type : 8;
#endif
	} fc_dw0;

	union {
		unsigned int context_gpa_hi;
		unsigned int magic_num;
	} fc_dw1;

	struct {
		unsigned int context_gpa_lo;
	} fc_dw2;

	struct {
#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
		unsigned short scq_num;	 /* SCQ num */
		unsigned short rport_index; /* RPort */
#else
		unsigned short rport_index; /* RPort */
		unsigned short scq_num;	 /* SCQ num */
#endif
	} fc_dw3;

	struct {
#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
		unsigned int pkt_type : 1; /* pkt type 0:ETH, 1:FC */
		unsigned int pkt_cos : 3;
		unsigned int rsvd2 : 1;
		unsigned int csize : 2;
		unsigned int service_type : 5;
		unsigned int parent_xid : 20;
#else
		unsigned int parent_xid : 20;
		unsigned int service_type : 5;
		unsigned int csize : 2;
		unsigned int rsvd2 : 1;
		unsigned int pkt_cos : 3;  /* pkt cos,4:ETH, 0:FC */
		unsigned int pkt_type : 1; /* pkt type 0:ETH, 1:FC */
#endif
	} fc_dw4;

	struct {
		unsigned int rsvd;
	} fc_dw5;

};

/* Root SQ WQE */
struct hifc_root_sqe_s {
	/* Control Section */
	struct hifcoe_wqe_ctrl_s ctrl_section;
	struct hifc_root_sqe_task_section_s task_section;
	struct hifc_root_sge_s sge;
	struct hifc_root_sge_s ctx_sge;
};

/* Parent SQ WQE and Root SQ WQE Related function */
void hifc_build_service_wqe_ctrl_section(struct hifcoe_wqe_ctrl_s *v_wqe_cs,
					 unsigned int ts_size,
					 unsigned int bdsl);
void hifc_build_service_wqe_ts_common(struct hifcoe_sqe_ts_s *v_sqe_ts,
				      unsigned int rport_index,
				      unsigned short local_xid,
				      unsigned short remote_xid,
				      unsigned short data_len);
void hifc_build_els_gs_wqe_sge(struct hifcoe_sqe_s *v_sqe, void *v_buf_addr,
			       unsigned long long v_phyaddr,
			       unsigned int buf_len,
			       unsigned int xid, void *v_hba);
void hifc_build_els_wqe_ts_req(struct hifcoe_sqe_s *v_sqe,
			       void *v_sq_info, unsigned short cmnd,
			       unsigned int v_scqn, void *v_frame_pld);

void hifc_build_els_wqe_ts_rsp(struct hifcoe_sqe_s *v_sqe, void *v_sq_info,
			       void *v_frame_pld, unsigned short type,
			       unsigned short cmnd, unsigned int v_scqn);
void hifc_build_els_wqe_ts_magic_num(struct hifcoe_sqe_s *v_sqe,
				     unsigned short els_cmnd_type,
				     unsigned int v_magic_num);
void hifc_build_gs_wqe_ts_req(struct hifcoe_sqe_s *v_sqe,
			      unsigned int magic_num);
void hifc_build_bls_wqe_ts_req(struct hifcoe_sqe_s *v_sqe,
			       unsigned int abts_param,
			       unsigned int magic_num);
void hifc_build_service_wqe_root_ts(void *v_hba,
				    struct hifc_root_sqe_s *v_rt_sqe,
				    unsigned int rx_id, unsigned int rport_id,
				    unsigned int scq_num);
void hifc_build_service_wqe_root_sge(struct hifc_root_sqe_s *v_rt_sqe,
				     void *v_buf_addr,
				     unsigned long long v_phyaddr,
				     unsigned int buf_len,
				     void *v_hba);
void hifc_build_els_wqe_root_offload(struct hifc_root_sqe_s *v_rt_sqe,
				     dma_addr_t ctx_addr,
				     unsigned int xid);
void hifc_build_wqe_owner_pmsn(struct hifcoe_wqe_ctrl_s *v_wqe_cs,
			       unsigned short owner,
			       unsigned short pmsn);
void hifc_convert_parent_wqe_to_big_endian(struct hifcoe_sqe_s *v_sqe);
void hifc_convert_root_wqe_to_big_endian(struct hifc_root_sqe_s *v_sqe);
void hifc_build_icmnd_wqe_ts(void *v_hba, struct unf_frame_pkg_s *v_pkg,
			     struct hifcoe_sqe_ts_s *v_sqe_ts);
void hifc_build_icmnd_wqe_ts_header(struct unf_frame_pkg_s *v_pkg,
				    struct hifcoe_sqe_s *v_sqe,
				    unsigned char v_task_type,
				    unsigned short v_exi_base,
				    unsigned char v_port_idx);
void hifc_build_cmdqe_common(union hifc_cmdqe_u *cmdqe,
			     enum hifcoe_task_type_e task_type,
			     unsigned short rx_id);
void hifc_build_srq_wqe_ctrls(struct hifcoe_rqe_s *v_rqe, unsigned short owner,
			      unsigned short pmsn);
void hifc_build_common_wqe_ctrls(struct hifcoe_wqe_ctrl_s *v_ctrl_sl,
				 unsigned char v_task_len);
void hifc_build_service_wqe_ctx_sge(struct hifc_root_sqe_s *v_rt_sqe,
				    unsigned long long v_ctx_addr,
				    unsigned int buf_len);
void hifc_build_trd_twr_wqe_ctrls(struct unf_frame_pkg_s *v_pkg,
				  struct hifcoe_sqe_s *v_sqe);

#endif
