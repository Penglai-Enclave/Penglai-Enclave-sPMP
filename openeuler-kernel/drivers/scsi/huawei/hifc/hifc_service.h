/* SPDX-License-Identifier: GPL-2.0 */
/* Huawei Hifc PCI Express Linux driver
 * Copyright(c) 2017 Huawei Technologies Co., Ltd
 *
 */

#ifndef __HIFC_SERVICE_H__
#define __HIFC_SERVICE_H__

/* Send ElsCmnd or ElsRsp */
unsigned int hifc_send_els_cmnd(void *phba, struct unf_frame_pkg_s *v_pkg);

/* Send GsCmnd */
unsigned int hifc_send_gs_cmnd(void *v_hba, struct unf_frame_pkg_s *v_pkg);

/* Send BlsCmnd */
unsigned int hifc_send_bls_cmnd(void *v_hba, struct unf_frame_pkg_s *v_pkg);

/* Receive Frame from Root RQ */
unsigned int hifc_rcv_service_frame_from_rq(
			struct hifc_hba_s *v_hba,
			struct hifc_root_rq_info_s *rq_info,
			struct hifc_root_rq_complet_info_s *v_complet_info,
			unsigned short v_rcv_buf_num);

unsigned int hifc_rq_rcv_srv_err(struct hifc_hba_s *v_hba,
				 struct hifc_root_rq_complet_info_s *v_info);

unsigned int hifc_rq_rcv_els_rsp_sts(
				struct hifc_hba_s *v_hba,
				struct hifc_root_rq_complet_info_s *v_info);

/* Receive Frame from SCQ */
unsigned int hifc_rcv_scqe_entry_from_scq(void *v_hba, void *v_scqe,
					  unsigned int scq_idx);

/* FC txmfs */
#define HIFC_DEFAULT_TX_MAX_FREAM_SIZE 256

#define HIFC_FIRST_PKG_FLAG (1 << 0)
#define HIFC_LAST_PKG_FLAG  (1 << 1)

#define HIFC_CHECK_IF_FIRST_PKG(pkg_flag) ((pkg_flag) & HIFC_FIRST_PKG_FLAG)
#define HIFC_CHECK_IF_LAST_PKG(pkg_flag)  ((pkg_flag) & HIFC_LAST_PKG_FLAG)

#define HIFC_GET_SERVICE_TYPE(v_hba)        12
#define HIFC_GET_PACKET_TYPE(v_service_type) 1
#define HIFC_GET_PACKET_COS(v_service_type)  1
#define HIFC_GET_PRLI_PAYLOAD_LEN \
	(UNF_PRLI_PAYLOAD_LEN - UNF_PRLI_SIRT_EXTRA_SIZE)
/* Start addr of the header/payloed of the cmnd buffer in the pkg */
#define HIFC_FC_HEAD_LEN                          (sizeof(struct unf_fchead_s))
#define HIFC_PAYLOAD_OFFSET                       (sizeof(struct unf_fchead_s))
#define HIFC_GET_CMND_PAYLOAD_ADDR(v_pkg) \
	UNF_GET_FLOGI_PAYLOAD(v_pkg)
#define HIFC_GET_CMND_HEADER_ADDR(v_pkg)  \
	((v_pkg)->unf_cmnd_pload_bl.buffer_ptr)
#define HIFC_GET_RSP_HEADER_ADDR(v_pkg)   \
	((v_pkg)->unf_rsp_pload_bl.buffer_ptr)
#define HIFC_GET_RSP_PAYLOAD_ADDR(v_pkg)  \
	((v_pkg)->unf_rsp_pload_bl.buffer_ptr + HIFC_PAYLOAD_OFFSET)
#define HIFC_GET_CMND_FC_HEADER(v_pkg) \
	(&(UNF_GET_SFS_ENTRY(v_pkg)->sfs_common.frame_head))
#define HIFC_PKG_IS_ELS_RSP(els_cmnd_type)  \
	(((els_cmnd_type) == ELS_ACC) || ((els_cmnd_type) == ELS_RJT))
#define HIFC_XID_IS_VALID(xid, exi_base, exi_count) \
	(((xid) >= (exi_base)) && ((xid) < ((exi_base) + (exi_count))))

#define UNF_FC_PAYLOAD_ELS_MASK   0xFF000000
#define UNF_FC_PAYLOAD_ELS_SHIFT  24
#define UNF_FC_PAYLOAD_ELS_DWORD  0

/* Note: this pfcpayload is little endian */
#define UNF_GET_FC_PAYLOAD_ELS_CMND(pfcpayload) \
	UNF_GET_SHIFTMASK(((unsigned int *)(void *)pfcpayload)\
	[UNF_FC_PAYLOAD_ELS_DWORD], \
	UNF_FC_PAYLOAD_ELS_SHIFT, UNF_FC_PAYLOAD_ELS_MASK)

#define HIFC_ELS_CMND_MASK                0xffff
#define HIFC_ELS_CMND__RELEVANT_SHIFT     16UL
#define HIFC_GET_ELS_CMND_CODE(__cmnd) \
	((unsigned short)((__cmnd) & HIFC_ELS_CMND_MASK))
#define HIFC_GET_ELS_RSP_TYPE(__cmnd)  \
	((unsigned short)((__cmnd) & HIFC_ELS_CMND_MASK))
#define HIFC_GET_ELS_RSP_CODE(__cmnd)  \
	((unsigned short)((__cmnd) >> HIFC_ELS_CMND__RELEVANT_SHIFT & \
	HIFC_ELS_CMND_MASK))
#define HIFC_GET_GS_CMND_CODE(__cmnd)  \
	((unsigned short)((__cmnd) & HIFC_ELS_CMND_MASK))

/* ELS CMND Request */
#define ELS_CMND            0

/* fh_f_ctl - Frame control flags. */
#define HIFC_FC_EX_CTX      (1 << 23) /* sent by responder to exchange */
#define HIFC_FC_SEQ_CTX     (1 << 22) /* sent by responder to sequence */
#define HIFC_FC_FIRST_SEQ   (1 << 21) /* first sequence of this exchange */
#define HIFC_FC_LAST_SEQ    (1 << 20) /* last sequence of this exchange */
#define HIFC_FC_END_SEQ     (1 << 19) /* last frame of sequence */
#define HIFC_FC_END_CONN    (1 << 18) /* end of class 1 connection pending */
#define HIFC_FC_RES_B17     (1 << 17) /* reserved */
#define HIFC_FC_SEQ_INIT    (1 << 16) /* transfer of sequence initiative */
#define HIFC_FC_X_ID_REASS  (1 << 15) /* exchange ID has been changed */
#define HIFC_FC_X_ID_INVAL  (1 << 14) /* exchange ID invalidated */
#define HIFC_FC_ACK_1       (1 << 12) /* 13:12 = 1: ACK_1 expected */
#define HIFC_FC_ACK_N       (2 << 12) /* 13:12 = 2: ACK_N expected */
#define HIFC_FC_ACK_0       (3 << 12) /* 13:12 = 3: ACK_0 expected */
#define HIFC_FC_RES_B11     (1 << 11) /* reserved */
#define HIFC_FC_RES_B10     (1 << 10) /* reserved */
#define HIFC_FC_RETX_SEQ    (1 << 9)  /* retransmitted sequence */
#define HIFC_FC_UNI_TX      (1 << 8)  /* unidirectional transmit (class 1) */
#define HIFC_FC_CONT_SEQ(i) ((i) << 6)
#define HIFC_FC_ABT_SEQ(i)  ((i) << 4)
#define HIFC_FC_REL_OFF     (1 << 3) /* parameter is relative offset */
#define HIFC_FC_RES2        (1 << 2) /* reserved */
#define HIFC_FC_FILL(i)     ((i) & 3)  /* 1:0: bytes of trailing fill */

#define HIFC_FCTL_REQ     (HIFC_FC_FIRST_SEQ | HIFC_FC_END_SEQ |\
	HIFC_FC_SEQ_INIT)
#define HIFC_FCTL_RESP    (HIFC_FC_EX_CTX | HIFC_FC_LAST_SEQ | \
	HIFC_FC_END_SEQ | HIFC_FC_SEQ_INIT)
#define HIFC_RCTL_BLS_REQ   0x81
#define HIFC_RCTL_BLS_ACC   0x84
#define HIFC_RCTL_BLS_RJT   0x85

#define UNF_IO_STATE_NEW          0
#define TGT_IO_STATE_SEND_XFERRDY (1 << 2)
#define TGT_IO_STATE_RSP          (1 << 5)
#define TGT_IO_STATE_ABORT        (1 << 7)

enum HIFC_FC_FH_TYPE_E {
	HIFC_FC_TYPE_BLS = 0x00, /* basic link service */
	HIFC_FC_TYPE_ELS = 0x01, /* extended link service */
	HIFC_FC_TYPE_IP = 0x05,  /* IP over FC, RFC 4338 */
	HIFC_FC_TYPE_FCP = 0x08, /* SCSI FCP */
	HIFC_FC_TYPE_CT = 0x20,  /* Fibre Channel Services (FC-CT) */
	HIFC_FC_TYPE_ILS = 0x22  /* internal link service */
};

enum HIFC_FC_FH_RCTL_E {
	HIFC_FC_RCTL_DD_UNCAT = 0x00,	  /* uncategorized information */
	HIFC_FC_RCTL_DD_SOL_DATA = 0x01,   /* solicited data */
	HIFC_FC_RCTL_DD_UNSOL_CTL = 0x02,  /* unsolicited control */
	HIFC_FC_RCTL_DD_SOL_CTL = 0x03,	/* solicited control or reply */
	HIFC_FC_RCTL_DD_UNSOL_DATA = 0x04, /* unsolicited data */
	HIFC_FC_RCTL_DD_DATA_DESC = 0x05,  /* data descriptor */
	HIFC_FC_RCTL_DD_UNSOL_CMD = 0x06,  /* unsolicited command */
	HIFC_FC_RCTL_DD_CMD_STATUS = 0x07, /* command status */

#define HIFC_FC_RCTL_ILS_REQ HIFC_FC_RCTL_DD_UNSOL_CTL /* ILS request */
#define HIFC_FC_RCTL_ILS_REP HIFC_FC_RCTL_DD_SOL_CTL   /* ILS reply */

	/*
	 * Extended Link_Data
	 */
	HIFC_FC_RCTL_ELS_REQ = 0x22,  /* extended link services request */
	HIFC_FC_RCTL_ELS_RSP = 0x23,  /* extended link services reply */
	HIFC_FC_RCTL_ELS4_REQ = 0x32, /* FC-4 ELS request */
	HIFC_FC_RCTL_ELS4_RSP = 0x33, /* FC-4 ELS reply */
	/*
	 * Optional Extended Headers
	 */
	HIFC_FC_RCTL_VFTH = 0x50, /* virtual fabric tagging header */
	HIFC_FC_RCTL_IFRH = 0x51, /* inter-fabric routing header */
	HIFC_FC_RCTL_ENCH = 0x52, /* encapsulation header */
	/*
	 * Basic Link Services fh_r_ctl values.
	 */
	HIFC_FC_RCTL_BA_NOP = 0x80,  /* basic link service NOP */
	HIFC_FC_RCTL_BA_ABTS = 0x81, /* basic link service abort */
	HIFC_FC_RCTL_BA_RMC = 0x82,  /* remove connection */
	HIFC_FC_RCTL_BA_ACC = 0x84,  /* basic accept */
	HIFC_FC_RCTL_BA_RJT = 0x85,  /* basic reject */
	HIFC_FC_RCTL_BA_PRMT = 0x86, /* dedicated connection preempted */
	/*
	 * Link Control Information.
	 */
	HIFC_FC_RCTL_ACK_1 = 0xc0,  /* acknowledge_1 */
	HIFC_FC_RCTL_ACK_0 = 0xc1,  /* acknowledge_0 */
	HIFC_FC_RCTL_P_RJT = 0xc2,  /* port reject */
	HIFC_FC_RCTL_F_RJT = 0xc3,  /* fabric reject */
	HIFC_FC_RCTL_P_BSY = 0xc4,  /* port busy */
	HIFC_FC_RCTL_F_BSY = 0xc5,  /* fabric busy to data frame */
	HIFC_FC_RCTL_F_BSYL = 0xc6, /* fabric busy to link control frame */
	HIFC_FC_RCTL_LCR = 0xc7,	/* link credit reset */
	HIFC_FC_RCTL_END = 0xc9	 /* end */
};

struct hifc_fc_frame_header {
	unsigned char rctl;    /* routing control */
	unsigned char did[3]; /* Destination ID */

	unsigned char cs_ctl;   /* class of service control / pri */
	unsigned char sid[3]; /* Source ID */

	unsigned char type;     /* see enum fc_fh_type below */
	unsigned char frame_ctl[3]; /* frame control */

	unsigned char seq_id;   /* sequence ID */
	unsigned char df_ctl;   /* data field control */
	unsigned short seq_cnt; /* sequence count */

	unsigned short ox_id;   /* originator exchange ID */
	unsigned short rx_id;       /* responder exchange ID */
	unsigned int parm_offset; /* parameter or relative offset */
};

unsigned int hifc_rcv_els_cmnd(const struct hifc_hba_s *v_hba,
			       struct unf_frame_pkg_s *v_pkg,
			       unsigned char *v_pld,
			       unsigned int pld_len,
			       int first_frame);
unsigned int hifc_rcv_els_rsp(const struct hifc_hba_s *v_hba,
			      struct unf_frame_pkg_s *v_pkg,
			      unsigned int ox_id);
unsigned int hifc_rcv_els_rsp_sts(const struct hifc_hba_s *v_hba,
				  struct unf_frame_pkg_s *v_pkg,
				  unsigned int rx_id);
unsigned int hifc_rcv_gs_rsp(const struct hifc_hba_s *v_hba,
			     struct unf_frame_pkg_s *v_pkg,
			     unsigned int ox_id);
unsigned int hifc_rcv_bls_rsp(const struct hifc_hba_s *v_hba,
			      struct unf_frame_pkg_s *v_pkg,
			      unsigned int ox_id);

void hifc_save_login_para_in_sq_info(
				struct hifc_hba_s *v_hba,
				struct unf_port_login_parms_s *v_login_coparms);
unsigned int hifc_handle_aeq_offload_err(struct hifc_hba_s *v_hba,
					 struct hifcoe_aqe_data_s *v_aeg_msg);

#define HIFC_CHECK_PKG_ALLOCTIME(v_pkg)  \
	do {                                                               \
		if (unlikely(UNF_GETXCHGALLOCTIME(v_pkg) == 0)) {          \
			HIFC_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_NORMAL, \
				   UNF_WARN,                               \
				   "[warn]Invalid MagicNum,S_ID(0x%x) D_ID(0x%x) OXID(0x%x) RX_ID(0x%x) pkg type(0x%x) hot pooltag(0x%x)", \
				   UNF_GET_SID(v_pkg),   \
				   UNF_GET_DID(v_pkg),   \
				   UNF_GET_OXID(v_pkg),  \
				   UNF_GET_RXID(v_pkg),  \
				   ((struct unf_frame_pkg_s *)v_pkg)->type, \
				   UNF_GET_XCHG_TAG(v_pkg));         \
				   }                                 \
	} while (0)

#endif
