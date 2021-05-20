// SPDX-License-Identifier: GPL-2.0
/* Huawei Hifc PCI Express Linux driver
 * Copyright(c) 2017 Huawei Technologies Co., Ltd
 *
 */

#include "unf_log.h"
#include "unf_common.h"
#include "hifc_module.h"
#include "hifc_service.h"
#include "hifc_io.h"
#include "hifc_chipitf.h"

#define HIFC_RQ_ERROR_FRAME  0x100
#define HIFC_ELS_SRQ_BUF_NUM 0x9

/* Parent SCQ Receive the ELS processing function */
static unsigned int hifc_scq_rcv_els_cmd(struct hifc_hba_s *v_hba,
					 union hifcoe_scqe_u *v_scqe);
static unsigned int hifc_scq_rcv_els_rsp(struct hifc_hba_s *v_hba,
					 union hifcoe_scqe_u *v_scqe);
static unsigned int hifc_scq_rcv_els_rsp_sts(struct hifc_hba_s *v_hba,
					     union hifcoe_scqe_u *v_scqe);

/* Parent SCQ Receive the GS RSP processing function */
static unsigned int hifc_scq_rcv_gs_rsp(struct hifc_hba_s *v_hba,
					union hifcoe_scqe_u *v_scqe);

/* Parent SCQ Receive the BLS RSP processing function */
static unsigned int hifc_scq_rcv_abts_rsp(struct hifc_hba_s *v_hba,
					  union hifcoe_scqe_u *v_scqe);

/* Parent SCQ Receive the offload completion processing function */
static unsigned int hifc_scq_rcv_offload_sts(struct hifc_hba_s *v_hba,
					     union hifcoe_scqe_u *v_scqe);

/* Parent SCQ Receive the flush sq completion processing function */
static unsigned int hifc_scq_rcv_flush_sq_sts(struct hifc_hba_s *v_hba,
					      union hifcoe_scqe_u *v_scqe);

/* Parent SCQ Receive the bufferclear completion processing function */
static unsigned int hifc_scq_rcv_buf_clear_sts(struct hifc_hba_s *v_hba,
					       union hifcoe_scqe_u *v_scqe);
static unsigned int hifc_scq_rcv_sess_rst_sts(struct hifc_hba_s *v_hba,
					      union hifcoe_scqe_u *v_scqe);
static unsigned int hifc_scq_rcv_clear_srq_sts(struct hifc_hba_s *v_hba,
					       union hifcoe_scqe_u *v_scqe);
static unsigned int hifc_scq_rcv_marker_sts(struct hifc_hba_s *v_hba,
					    union hifcoe_scqe_u *v_scqe);
static unsigned int hifc_scq_rcv_abts_marker_sts(struct hifc_hba_s *v_hba,
						 union hifcoe_scqe_u *v_scqe);

typedef unsigned int (*pfn_scqe_handler)(struct hifc_hba_s *,
					 union hifcoe_scqe_u *);

struct unf_scqe_handler_table_s {
	unsigned int scqe_type; /* ELS type */
	int reclaim_sq_wpg;
	pfn_scqe_handler pfn_scqe_handle_fun;
};

struct unf_scqe_handler_table_s scqe_handler_table[] = {
	{   /* INI rcvd ELS_CMND */
		HIFC_SCQE_ELS_CMND,
		UNF_FALSE,
		hifc_scq_rcv_els_cmd
	},
	{   /* INI rcvd ELS_RSP */
		HIFC_SCQE_ELS_RSP,
		UNF_TRUE,
		hifc_scq_rcv_els_rsp
	},
	{   /* INI rcvd GS_RSP */
		HIFC_SCQE_GS_RSP,
		UNF_TRUE,
		hifc_scq_rcv_gs_rsp
	},
	{   /* INI rcvd BLS_RSP */
		HIFC_SCQE_ABTS_RSP,
		UNF_TRUE,
		hifc_scq_rcv_abts_rsp
	},
	{   /* INI rcvd FCP RSP */
		HIFC_SCQE_FCP_IRSP,
		UNF_TRUE,
		hifc_scq_recv_iresp
	},
	{   /* INI rcvd ELS_RSP STS(Done) */
		HIFC_SCQE_ELS_RSP_STS,
		UNF_TRUE,
		hifc_scq_rcv_els_rsp_sts
	},
	{   /* INI rcvd Session enable STS */
		HIFC_SCQE_SESS_EN_STS,
		UNF_FALSE,
		hifc_scq_rcv_offload_sts
	},
	{   /* INI rcvd flush (pending) SQ STS */
		HIFC_SCQE_FLUSH_SQ_STS,
		UNF_FALSE,
		hifc_scq_rcv_flush_sq_sts
	},
	{   /* INI rcvd Buffer clear STS */
		HIFC_SCQE_BUF_CLEAR_STS,
		UNF_FALSE,
		hifc_scq_rcv_buf_clear_sts
	},
	{   /* INI rcvd session reset STS */
		HIFC_SCQE_SESS_RST_STS,
		UNF_FALSE,
		hifc_scq_rcv_sess_rst_sts
	},
	{   /* ELS SRQ */
		HIFC_SCQE_CLEAR_SRQ_STS,
		UNF_FALSE,
		hifc_scq_rcv_clear_srq_sts
	},
	{   /* INI rcvd TMF RSP */
		HIFC_SCQE_FCP_ITMF_RSP,
		UNF_TRUE,
		hifc_scq_recv_iresp
	},
	{   /* INI rcvd TMF Marker STS */
		HIFC_SCQE_ITMF_MARKER_STS,
		UNF_FALSE,
		hifc_scq_rcv_marker_sts
	},
	{   /* INI rcvd ABTS Marker STS */
		HIFC_SCQE_ABTS_MARKER_STS,
		UNF_FALSE,
		hifc_scq_rcv_abts_marker_sts
	}
};

static unsigned int hifc_get_els_rps_pld_len(unsigned short type,
					     unsigned short cmnd,
					     unsigned int *v_els_acc_pld_len)
{
	unsigned int ret = RETURN_OK;

	UNF_CHECK_VALID(0x4917, UNF_TRUE, v_els_acc_pld_len,
			return UNF_RETURN_ERROR);

	/* RJT */
	if (type == ELS_RJT) {
		*v_els_acc_pld_len = UNF_ELS_ACC_RJT_LEN;
		return RETURN_OK;
	}

	/* ACC */
	switch (cmnd) {
	/* uses the same PAYLOAD length as PLOGI. */
	case ELS_FLOGI:
	case ELS_PDISC:
	case ELS_PLOGI:
		*v_els_acc_pld_len = UNF_PLOGI_ACC_PAYLOAD_LEN;
		break;

	case ELS_PRLI:
		/* The PRLI ACC payload extends 12 bytes */
		*v_els_acc_pld_len = UNF_PRLI_ACC_PAYLOAD_LEN -
				     UNF_PRLI_SIRT_EXTRA_SIZE;
		break;

	case ELS_LOGO:
		*v_els_acc_pld_len = UNF_LOGO_ACC_PAYLOAD_LEN;
		break;

	case ELS_PRLO:
		*v_els_acc_pld_len = UNF_PRLO_ACC_PAYLOAD_LEN;
		break;

	case ELS_RSCN:
		*v_els_acc_pld_len = UNF_RSCN_ACC_PAYLOAD_LEN;
		break;

	case ELS_ADISC:
		*v_els_acc_pld_len = UNF_ADISC_ACC_PAYLOAD_LEN;
		break;

	case ELS_RRQ:
		*v_els_acc_pld_len = UNF_RRQ_ACC_PAYLOAD_LEN;
		break;

	case ELS_SCR:
		*v_els_acc_pld_len = UNF_SCR_RSP_PAYLOAD_LEN;
		break;

	case ELS_ECHO:
		*v_els_acc_pld_len = UNF_ECHO_ACC_PAYLOAD_LEN;
		break;
	case ELS_RLS:
		*v_els_acc_pld_len = UNF_RLS_ACC_PAYLOAD_LEN;
		break;
	case ELS_REC:
		*v_els_acc_pld_len = UNF_REC_ACC_PAYLOAD_LEN;
		break;
	default:
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT, UNF_WARN,
			  "[warn]Unknown ELS command(0x%x)", cmnd);
		ret = UNF_RETURN_ERROR;
		break;
	}

	return ret;
}

struct hifc_els_cmd_payload_table_s {
	unsigned short cmnd; /* ELS type */
	unsigned int req_pld_len;
	unsigned int rsp_pld_len;
};

struct hifc_els_cmd_payload_table_s els_pld_table_map[] = {
	{	ELS_FDISC,
		UNF_FDISC_PAYLOAD_LEN,
		UNF_FDISC_ACC_PAYLOAD_LEN
	},
	{	ELS_FLOGI,
		UNF_FLOGI_PAYLOAD_LEN,
		UNF_FLOGI_ACC_PAYLOAD_LEN
	},
	{	ELS_PLOGI,
		UNF_PLOGI_PAYLOAD_LEN,
		UNF_PLOGI_ACC_PAYLOAD_LEN
	},
	{	ELS_SCR,
		UNF_SCR_PAYLOAD_LEN,
		UNF_SCR_RSP_PAYLOAD_LEN
	},
	{	ELS_PDISC,
		UNF_PDISC_PAYLOAD_LEN,
		UNF_PDISC_ACC_PAYLOAD_LEN
	},
	{	ELS_LOGO,
		UNF_LOGO_PAYLOAD_LEN,
		UNF_LOGO_ACC_PAYLOAD_LEN
	},
	{	ELS_PRLO,
		UNF_PRLO_PAYLOAD_LEN,
		UNF_PRLO_ACC_PAYLOAD_LEN
	},
	{	ELS_ADISC,
		UNF_ADISC_PAYLOAD_LEN,
		UNF_ADISC_ACC_PAYLOAD_LEN
	},
	{	ELS_RRQ,
		UNF_RRQ_PAYLOAD_LEN,
		UNF_RRQ_ACC_PAYLOAD_LEN
	},
	{	ELS_RSCN,
		0,
		UNF_RSCN_ACC_PAYLOAD_LEN
	},
	{	ELS_ECHO,
		UNF_ECHO_PAYLOAD_LEN,
		UNF_ECHO_ACC_PAYLOAD_LEN
	},
	{	ELS_RLS,
		UNF_RLS_PAYLOAD_LEN,
		UNF_RLS_ACC_PAYLOAD_LEN
	},
	{	ELS_REC,
		UNF_REC_PAYLOAD_LEN,
		UNF_REC_ACC_PAYLOAD_LEN
	}
};

static unsigned int hifc_get_els_req_and_acc_pld_len(unsigned short cmnd,
						     unsigned int *req_pld_len,
						     unsigned int *rsp_pld_len)
{
	unsigned int ret = RETURN_OK;
	unsigned int i;

	UNF_CHECK_VALID(0x4917, UNF_TRUE, req_pld_len, return UNF_RETURN_ERROR);

	for (i = 0; i < (sizeof(els_pld_table_map) /
	     sizeof(struct hifc_els_cmd_payload_table_s)); i++) {
		if (els_pld_table_map[i].cmnd == cmnd) {
			*req_pld_len = els_pld_table_map[i].req_pld_len;
			*rsp_pld_len = els_pld_table_map[i].rsp_pld_len;
			return ret;
		}
	}

	switch (cmnd) {
	case ELS_PRLI:
		/* If sirt is enabled, The PRLI ACC payload extends
		 * 12 bytes
		 */
		*req_pld_len = HIFC_GET_PRLI_PAYLOAD_LEN;
		*rsp_pld_len = HIFC_GET_PRLI_PAYLOAD_LEN;
		break;

	default:
		HIFC_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_LOGIN_ATT,
			   UNF_ERR, "[err]Unknown ELS_CMD(0x%x)", cmnd);
		ret = UNF_RETURN_ERROR;
		break;
	}

	return ret;
}

/*
 * Function Name       : hifc_get_els_frame_len
 * Function Description: Get ELS Frame length
 * Input Parameters    : type,
 *                     : cmnd
 * Output Parameters   : v_frame_len
 * Return Type         : unsigned int
 */
static unsigned int hifc_get_els_frame_len(unsigned short type,
					   unsigned short cmnd,
					   unsigned int *v_frame_len)
{
	unsigned int ret = RETURN_OK;
	unsigned int hdr_len = sizeof(struct unf_fchead_s);
	unsigned int req_len = 0;
	unsigned int rsp_len = 0;

	UNF_CHECK_VALID(0x4917, UNF_TRUE, v_frame_len, return UNF_RETURN_ERROR);

	if (type == ELS_RJT)
		rsp_len = UNF_ELS_ACC_RJT_LEN;
	else
		ret = hifc_get_els_req_and_acc_pld_len(cmnd, &req_len,
						       &rsp_len);

	if (ret == RETURN_OK)
		*v_frame_len = hdr_len + ((type == ELS_ACC || type == ELS_RJT) ?
			       rsp_len : req_len);

	return ret;
}

static void hifc_build_els_frame_header(unsigned short v_xid_base,
					unsigned short v_cmnd_type,
					unsigned short els_code,
					struct unf_frame_pkg_s *v_pkg)
{
	unsigned int fctl = 0;
	unsigned int rctl = 0;
	unsigned int type = 0;
	struct unf_fchead_s *cm_fc_hdr_buf = NULL;
	struct unf_fchead_s *pkg_fc_hdr_info = NULL;

	pkg_fc_hdr_info = &v_pkg->frame_head;
	cm_fc_hdr_buf = HIFC_GET_CMND_FC_HEADER(v_pkg);

	if (v_cmnd_type == ELS_CMND) {
		rctl = HIFC_FC_RCTL_ELS_REQ;
		fctl = HIFC_FCTL_REQ;

		/* If the ELS_CMD frame is sent, Adjusting the oxid */
		cm_fc_hdr_buf->oxid_rxid = pkg_fc_hdr_info->oxid_rxid +
					   ((unsigned int)v_xid_base << 16);
	} else {
		rctl = HIFC_FC_RCTL_ELS_RSP;
		fctl = HIFC_FCTL_RESP;

		/* If the ELS_RSP frame is sent, Adjusting the rxid */
		cm_fc_hdr_buf->oxid_rxid = pkg_fc_hdr_info->oxid_rxid +
					   v_xid_base;
	}

	type = HIFC_FC_TYPE_ELS;

	/* Get SID, DID, OXID, RXID from CM layer */
	cm_fc_hdr_buf->rctl_did = pkg_fc_hdr_info->rctl_did;
	cm_fc_hdr_buf->csctl_sid = pkg_fc_hdr_info->csctl_sid;
	cm_fc_hdr_buf->parameter = 0;

	/* R_CTL, CS_CTL, TYPE, F_CTL, SEQ_ID, DF_CTL, SEQ_CNT, LL filled */
	UNF_SET_FC_HEADER_RCTL(cm_fc_hdr_buf, rctl);
	UNF_SET_FC_HEADER_CS_CTL(cm_fc_hdr_buf, 0);
	UNF_SET_FC_HEADER_TYPE(cm_fc_hdr_buf, type);
	UNF_SET_FC_HEADER_FCTL(cm_fc_hdr_buf, fctl);
	UNF_SET_FC_HEADER_SEQ_CNT(cm_fc_hdr_buf, 0);
	UNF_SET_FC_HEADER_DF_CTL(cm_fc_hdr_buf, 0);
	UNF_SET_FC_HEADER_SEQ_ID(cm_fc_hdr_buf, 0);

	UNF_PRINT_SFS(UNF_INFO, 0, cm_fc_hdr_buf, sizeof(struct unf_fchead_s));
}

void hifc_save_login_para_in_sq_info(
				struct hifc_hba_s *v_hba,
				struct unf_port_login_parms_s *v_login_co_parms)
{
	struct hifc_hba_s *hba = NULL;
	unsigned int rport_index = v_login_co_parms->rport_index;
	struct hifc_parent_sq_info_s *sq_info = NULL;

	hba = (struct hifc_hba_s *)v_hba;

	if (rport_index >= UNF_HIFC_MAXRPORT_NUM) {
		HIFC_TRACE(UNF_EVTLOG_IO_ERR, UNF_LOG_IO_ATT, UNF_ERR,
			   "[err]Port(0x%x) save login parms,but uplevel alloc invalid rport index: 0x%x",
			   hba->port_cfg.port_id, rport_index);

		return;
	}

	sq_info =
	&hba->parent_queue_mgr->parent_queues[rport_index].parent_sq_info;

	sq_info->plogi_coparams.seq_cnt = v_login_co_parms->seq_cnt;
	sq_info->plogi_coparams.ed_tov = v_login_co_parms->ed_tov;
	sq_info->plogi_coparams.tx_mfs = (v_login_co_parms->tx_mfs <
	HIFC_DEFAULT_TX_MAX_FREAM_SIZE) ? HIFC_DEFAULT_TX_MAX_FREAM_SIZE :
	v_login_co_parms->tx_mfs;

	sq_info->plogi_coparams.ed_tov_timer_val =
	v_login_co_parms->ed_tov_timer_val;
}

static void hifc_save_default_plogi_param_in_ctx(
					struct hifc_hba_s *v_hba,
					struct hifcoe_parent_context_s *v_ctx,
					struct unf_frame_pkg_s *v_pkg)
{
	unsigned int tx_mfs = HIFC_DEFAULT_TX_MAX_FREAM_SIZE;
	unsigned int did = 0;

	did = UNF_GET_DID(v_pkg);

	if (did == UNF_FC_FID_DIR_SERV)
		tx_mfs = 2048;

	v_ctx->sw_section.tx_mfs = cpu_to_be16((unsigned short)(tx_mfs));
}

static void hifc_save_plogi_acc_param_in_ctx(
				struct hifc_hba_s *v_hba,
				struct hifcoe_parent_context_s *v_ctx,
				struct unf_frame_pkg_s *v_pkg)
{
#define HIFC_UCODE_MAX_PKT_SIZE_PER_DISPATCH ((8 * 1024))

	struct unf_lgn_port_coparms_s *port_co_param = NULL;
	struct unf_plogi_payload_s *plogi_acc_pld = NULL;

	plogi_acc_pld = UNF_GET_PLOGI_ACC_PAYLOAD(v_pkg);
	port_co_param = &plogi_acc_pld->parms.co_parms;

	/* e_d_tov and seq_cnt */
	hifc_big_to_cpu32(&v_ctx->sw_section.sw_ctxt_config.pctxt_val1,
			  sizeof(unsigned int));

	v_ctx->sw_section.sw_ctxt_config.dw.e_d_tov =
	port_co_param->e_d_tov_resolution;

	v_ctx->sw_section.sw_ctxt_config.dw.seq_cnt =
	port_co_param->seq_cnt;

	hifc_cpu_to_big32(&v_ctx->sw_section.sw_ctxt_config.pctxt_val1,
			  sizeof(unsigned int));

	v_ctx->sw_section.tx_mfs =
	(unsigned short)(v_pkg->private[PKG_PRIVATE_RPORT_RX_SIZE]) <
		HIFC_DEFAULT_TX_MAX_FREAM_SIZE ?
		cpu_to_be16((unsigned short)HIFC_DEFAULT_TX_MAX_FREAM_SIZE) :
		cpu_to_be16 ((unsigned short)
		(v_pkg->private[PKG_PRIVATE_RPORT_RX_SIZE]));

	v_ctx->sw_section.e_d_tov_timer_val =
		cpu_to_be32(port_co_param->e_d_tov);

	v_ctx->sw_section.mfs_unaligned_bytes =
		cpu_to_be16(HIFC_UCODE_MAX_PKT_SIZE_PER_DISPATCH %
		port_co_param->bb_receive_data_field_size);
}

static void hifc_recover_offloading_state(
				struct hifc_parent_queue_info_s *v_prntq_info,
				enum hifc_parent_queue_state_e offload_state)
{
	unsigned long flag = 0;

	spin_lock_irqsave(&v_prntq_info->parent_queue_state_lock, flag);

	if (v_prntq_info->offload_state == HIFC_QUEUE_STATE_OFFLOADING)
		v_prntq_info->offload_state = offload_state;

	spin_unlock_irqrestore(&v_prntq_info->parent_queue_state_lock, flag);
}

static void hifc_save_magic_num_in_ctx(struct hifcoe_parent_context_s *v_ctx,
				       struct unf_frame_pkg_s *v_pkg)
{
	/* The CID itself is initialized by the microcode.
	 * The driver multiplexes the CID as magicnum and then updates
	 * the CID by the microcode.
	 */
	v_ctx->sw_section.cid = cpu_to_be32(UNF_GETXCHGALLOCTIME(v_pkg));
}

static void hifc_save_magic_num_in_nurmal_root_ts(
				struct hifc_root_sqe_s *v_rt_sqe,
				struct unf_frame_pkg_s *v_pkg)
{
	v_rt_sqe->task_section.fc_dw1.magic_num = UNF_GETXCHGALLOCTIME(v_pkg);
}

static int hifc_check_need_delay_offload(
			void *v_hba,
			struct unf_frame_pkg_s *v_pkg,
			unsigned int rport_idx,
			struct hifc_parent_queue_info_s *v_cur_parent_queue,
			struct hifc_parent_queue_info_s **v_offload_parnt_queue)
{
	unsigned long flag = 0;
	struct hifc_parent_queue_info_s *offload_parnt_queue = NULL;

	spin_lock_irqsave(&v_cur_parent_queue->parent_queue_state_lock, flag);

	if (v_cur_parent_queue->offload_state == HIFC_QUEUE_STATE_OFFLOADING) {
		spin_unlock_irqrestore(
			&v_cur_parent_queue->parent_queue_state_lock, flag);

		offload_parnt_queue = hifc_find_offload_parent_queue(
			v_hba,
			v_pkg->frame_head.csctl_sid & UNF_NPORTID_MASK,
			v_pkg->frame_head.rctl_did & UNF_NPORTID_MASK,
			rport_idx);
		if (offload_parnt_queue) {
			*v_offload_parnt_queue = offload_parnt_queue;

			return UNF_TRUE;
		}
	} else {
		spin_unlock_irqrestore(
			&v_cur_parent_queue->parent_queue_state_lock, flag);
	}

	return UNF_FALSE;
}

static unsigned int hifc_build_service_wqe_root_offload(
				void *v_hba,
				struct unf_frame_pkg_s *v_pkg,
				struct hifc_parent_queue_info_s *v_parnt_qinfo,
				struct hifc_root_sqe_s *v_sqe)
{
	unsigned int cqm_xid = 0;
	unsigned short els_cmnd_type = UNF_ZERO;
	struct hifc_parent_ctx_s *parnt_ctx = NULL;
	struct hifc_parent_sq_info_s *sq_info = NULL;
	struct hifcoe_parent_context_s *v_ctx = NULL;

	els_cmnd_type = HIFC_GET_ELS_RSP_TYPE(v_pkg->cmnd);
	cqm_xid = hifc_get_parent_ctx_xid_by_pkg(v_hba, v_pkg);

	/* An offload request is initiated only when the parent queue is in the
	 * initialized state
	 */
	if (v_parnt_qinfo->offload_state == HIFC_QUEUE_STATE_INITIALIZED) {
		/* Obtain Parent Context and set WQE to off_load, GPA_Addr */
		parnt_ctx = hifc_get_parnt_ctx_virt_addr_by_pkg(v_hba, v_pkg);

		sq_info = hifc_find_parent_sq_by_pkg(v_hba, v_pkg);
		if (unlikely((!parnt_ctx) || (!sq_info) ||
			     (cqm_xid == INVALID_VALUE32))) {
			return UNF_RETURN_ERROR;
		}

		/* Fill in ROOT SQE with offload request */
		hifc_build_els_wqe_root_offload(
			v_sqe,
			parnt_ctx->cqm_parent_ctx_obj->paddr,
			cqm_xid);

		/* If the value is PlogiAcc, parse the FlogiAcc negotiation
		 * parameter and fill in Context
		 */
		v_ctx = (struct hifcoe_parent_context_s *)
					parnt_ctx->virt_parent_ctx;

		if (els_cmnd_type == ELS_ACC)
			hifc_save_plogi_acc_param_in_ctx(
			(struct hifc_hba_s *)v_hba, v_ctx, v_pkg);
		else
			hifc_save_default_plogi_param_in_ctx(
			(struct hifc_hba_s *)v_hba, v_ctx, v_pkg);

		/* The SID DID parameter is updated to Parent SQ Qinfo */
		sq_info->local_port_id = UNF_GET_SID(v_pkg);
		sq_info->remote_port_id = UNF_GET_DID(v_pkg);

		/* Transfers the key value to the ucode for offload */
		hifc_big_to_cpu32(v_ctx->key, sizeof(v_ctx->key));
		memcpy(v_ctx->key, &sq_info->local_port_id,
		       sizeof(sq_info->local_port_id));
		memcpy((unsigned char *)v_ctx->key +
		       sizeof(sq_info->local_port_id),
		       &sq_info->remote_port_id,
		       sizeof(sq_info->remote_port_id));

		hifc_cpu_to_big32(v_ctx->key, sizeof(v_ctx->key));

		/* Update magic num to parent_ctx */
		hifc_save_magic_num_in_ctx(v_ctx, v_pkg);

		hifc_build_service_wqe_ctx_sge(
					v_sqe, parnt_ctx->parent_ctx,
					sizeof(struct hifcoe_parent_context_s));

		v_parnt_qinfo->offload_state = HIFC_QUEUE_STATE_OFFLOADING;
	} else {
		/* If the connection is being uninstalled and the plogi is
		 * delivered through the root channel, the plogi must be carried
		 * to the ucode.
		 */
		v_sqe->task_section.fc_dw4.parent_xid = cqm_xid;

		HIFC_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_IO_ATT, UNF_WARN,
			   "[warn]Port(0x%x) send PLOGI with no offload while parent queue is not initialized status",
			   ((struct hifc_hba_s *)v_hba)->port_cfg.port_id);
	}

	return RETURN_OK;
}

static unsigned int hifc_send_els_via_root(void *v_hba,
					   struct unf_frame_pkg_s *v_pkg)
{
	unsigned int ret = UNF_RETURN_ERROR;
	unsigned short els_cmd_code = UNF_ZERO;
	unsigned short els_cmnd_type = UNF_ZERO;
	unsigned int frame_len = 0;
	unsigned int exch_id = 0;
	unsigned int scq_num = 0;
	unsigned int rport_idx = 0;
	int sqe_delay = UNF_FALSE;
	void *frame_addr = NULL;
	struct hifc_hba_s *hba = NULL;
	struct hifc_parent_queue_info_s *prnt_qinfo = NULL;
	struct hifc_parent_queue_info_s *offload_parnt_queue = NULL;
	struct hifc_root_sqe_s *sqe = NULL;
	struct hifc_root_sqe_s local_rt_sqe;
	unsigned long flag = 0;
	enum hifc_parent_queue_state_e last_offload_state =
					HIFC_QUEUE_STATE_INITIALIZED;
	struct hifc_destroy_ctrl_info_s destroy_sqe_info = { 0 };
	unsigned long long frame_phy_addr;

	/* The ROOT SQE is assembled in local variables and then copied to the
	 * queue memory
	 */
	sqe = &local_rt_sqe;
	hba = (struct hifc_hba_s *)v_hba;

	memset(sqe, 0, sizeof(local_rt_sqe));

	/* Determine the ELS type in the pstPkg */
	els_cmnd_type = HIFC_GET_ELS_RSP_TYPE(v_pkg->cmnd);
	if (HIFC_PKG_IS_ELS_RSP(els_cmnd_type)) {
		els_cmd_code = HIFC_GET_ELS_RSP_CODE(v_pkg->cmnd);
		exch_id = UNF_GET_RXID(v_pkg);
		sqe->task_section.fc_dw0.task_type = HIFC_SQE_ELS_RSP;
	} else {
		els_cmd_code = els_cmnd_type;
		els_cmnd_type = ELS_CMND;
		exch_id = UNF_GET_OXID(v_pkg);
		sqe->task_section.fc_dw0.task_type = HIFC_SQE_ELS_CMND;
	}
	if ((els_cmd_code == ELS_ECHO) && (els_cmnd_type != ELS_RJT)) {
		HIFC_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_REG_ATT, UNF_WARN,
			   "[info]Port(0x%x) RPort(0x%x) send ELS ECHO can't send via root Type(0x%x)",
			   hba->port_cfg.port_id, rport_idx, els_cmnd_type);

		return UNF_RETURN_NOT_SUPPORT;
	}
	exch_id += hba->exit_base;

	ret = hifc_get_els_frame_len(els_cmnd_type, els_cmd_code, &frame_len);
	if (ret != RETURN_OK) {
		dump_stack();
		return ret;
	}

	/* Obtains the frame start address */
	frame_addr = HIFC_GET_CMND_HEADER_ADDR(v_pkg);
	frame_phy_addr = v_pkg->unf_cmnd_pload_bl.buf_dma_addr;

	/* Assemble the frame header and adjust the Paylaod based on the ELS */
	hifc_build_els_frame_header(hba->exit_base, els_cmnd_type,
				    els_cmd_code, v_pkg);

	/* Assembling the Control Section */
	hifc_build_service_wqe_ctrl_section(
	&sqe->ctrl_section,
	HIFC_BYTES_TO_QW_NUM(
		sizeof(struct hifc_root_sqe_task_section_s)),
		HIFC_BYTES_TO_QW_NUM(sizeof(struct hifc_root_sge_s)));

	/* Fill in Normal Root SQE TS */
	rport_idx = v_pkg->private[PKG_PRIVATE_XCHG_RPORT_INDEX];
	scq_num = hifc_get_rport_maped_cmd_scqn(v_hba, rport_idx);
	hifc_build_service_wqe_root_ts(v_hba, sqe, exch_id, rport_idx, scq_num);

	/* Upsate magic number into sqe */
	hifc_save_magic_num_in_nurmal_root_ts(sqe, v_pkg);

	/* Fill in the special part of Normal Root SQE TS and initiate implicit
	 * uninstallation
	 */
	if ((els_cmd_code == ELS_PLOGI) && (els_cmnd_type != ELS_RJT)) {
		prnt_qinfo = hifc_find_parent_queue_info_by_pkg(hba, v_pkg);
		if (!prnt_qinfo) {
			HIFC_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_REG_ATT,
				   UNF_ERR,
				   "[warn]Port(0x%x) RPort(0x%x) send ELS Type(0x%x) find parent queue fail",
				   hba->port_cfg.port_id, rport_idx,
				   els_cmnd_type);
			return UNF_RETURN_ERROR;
		}

		spin_lock_irqsave(&prnt_qinfo->parent_queue_state_lock, flag);

		last_offload_state = prnt_qinfo->offload_state;

		/* Fill in the special part of Normal Root SQE TS */
		ret = hifc_build_service_wqe_root_offload((void *)hba,
							  v_pkg, prnt_qinfo,
							  sqe);
		if (ret != RETURN_OK) {
			spin_unlock_irqrestore(
				&prnt_qinfo->parent_queue_state_lock, flag);

			return ret;
		}

		spin_unlock_irqrestore(&prnt_qinfo->parent_queue_state_lock,
				       flag);

		/* Before the offload, check whether there is a risk of
		 * repeated offload
		 */
		sqe_delay = hifc_check_need_delay_offload((void *)hba,
							  v_pkg, rport_idx,
							  prnt_qinfo,
							  &offload_parnt_queue);
	}

	/* Fill in Normal Root SQE SGE */
	hifc_build_service_wqe_root_sge(sqe, frame_addr, frame_phy_addr,
					frame_len, v_hba);

	if (sqe_delay == UNF_TRUE) {
		ret = hifc_push_delay_sqe((void *)hba, offload_parnt_queue,
					  sqe, v_pkg);
		if (ret == RETURN_OK) {
			hifc_recover_offloading_state(prnt_qinfo,
						      last_offload_state);

			return ret;
		}
	}

	HIFC_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_REG_ATT, UNF_INFO,
		   "[info]Port(0x%x) RPort(0x%x) send ELS Type(0x%x) Code(0x%x) ExchId(0x%x)",
		   hba->port_cfg.port_id, rport_idx, els_cmnd_type,
		   els_cmd_code, exch_id);

	ret = hifc_root_sq_enqueue(hba, sqe);
	if ((ret != RETURN_OK) && (prnt_qinfo)) {
		hifc_recover_offloading_state(prnt_qinfo, last_offload_state);

		spin_lock_irqsave(&prnt_qinfo->parent_queue_state_lock, flag);

		if (prnt_qinfo->parent_sq_info.destroy_sqe.valid ==
		    UNF_TRUE) {
			memcpy(&destroy_sqe_info,
			       &prnt_qinfo->parent_sq_info.destroy_sqe,
			       sizeof(struct hifc_destroy_ctrl_info_s));

			prnt_qinfo->parent_sq_info.destroy_sqe.valid =
								UNF_FALSE;
		}

		spin_unlock_irqrestore(&prnt_qinfo->parent_queue_state_lock,
				       flag);

		hifc_pop_destroy_parent_queue_sqe((void *)v_hba,
						  &destroy_sqe_info);

		HIFC_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_REG_ATT, UNF_ERR,
			   "[warn]Port(0x%x) RPort(0x%x) send ELS Type(0x%x) Code(0x%x) ExchId(0x%x) fail, recover offloadstatus(%u)",
			   hba->port_cfg.port_id,
			   rport_idx,
			   els_cmnd_type,
			   els_cmd_code,
			   exch_id,
			   prnt_qinfo->offload_state);
	}

	return ret;
}

static void *hifc_get_els_frame_addr(struct hifc_hba_s *v_hba,
				     struct unf_frame_pkg_s *v_pkg,
				     unsigned short els_cmd_code,
				     unsigned short els_cmnd_type,
				     unsigned long long *v_phyaddr)
{
	void *frame_pld_addr;
	dma_addr_t els_frame_addr = 0;

	if (els_cmd_code == ELS_ECHO) {
		frame_pld_addr = (void *)UNF_GET_ECHO_PAYLOAD(v_pkg);
		els_frame_addr = UNF_GET_ECHO_PAYLOAD_PHYADDR(v_pkg);
	} else if (els_cmd_code == ELS_RSCN) {
		if (els_cmnd_type == ELS_CMND) {
			/* Not Support */
			frame_pld_addr = NULL;
			els_frame_addr = 0;
		} else {
			frame_pld_addr =
					(void *)UNF_GET_RSCN_ACC_PAYLOAD(v_pkg);
			els_frame_addr = v_pkg->unf_cmnd_pload_bl.buf_dma_addr +
					 sizeof(struct unf_fchead_s);
		}
	} else {
		frame_pld_addr = (void *)HIFC_GET_CMND_PAYLOAD_ADDR(v_pkg);
		els_frame_addr = v_pkg->unf_cmnd_pload_bl.buf_dma_addr +
				 sizeof(struct unf_fchead_s);
	}
	*v_phyaddr = els_frame_addr;
	return frame_pld_addr;
}

static unsigned int hifc_send_els_via_parent(
			void *v_hba,
			struct unf_frame_pkg_s *v_pkg,
			struct hifc_parent_queue_info_s *v_prntq_info)
{
	unsigned int ret = UNF_RETURN_ERROR;
	unsigned short els_cmd_code = UNF_ZERO;
	unsigned short els_cmnd_type = UNF_ZERO;
	unsigned short remote_xid = 0;
	unsigned short local_xid = 0;
	struct hifc_hba_s *hba;
	struct hifc_parent_sq_info_s *sq_info = NULL;
	struct hifcoe_sqe_s sqe;
	void *frame_pld_addr;
	unsigned int frame_pld_len = 0;
	unsigned int acc_pld_len = 0;
	unsigned long long fram_phy_addr = 0;

	hba = (struct hifc_hba_s *)v_hba;

	memset(&sqe, 0, sizeof(struct hifcoe_sqe_s));

	sq_info = &v_prntq_info->parent_sq_info;

	/* Determine the ELS type in pstPkg */
	els_cmnd_type = HIFC_GET_ELS_CMND_CODE(v_pkg->cmnd);
	if (HIFC_PKG_IS_ELS_RSP(els_cmnd_type)) {
		els_cmd_code = HIFC_GET_ELS_RSP_CODE(v_pkg->cmnd);
		remote_xid = UNF_GET_OXID(v_pkg);
		local_xid = UNF_GET_RXID(v_pkg) + hba->exit_base;
	} else {
		els_cmd_code = els_cmnd_type;
		els_cmnd_type = ELS_CMND;
		local_xid = UNF_GET_OXID(v_pkg) + hba->exit_base;
		remote_xid = UNF_GET_RXID(v_pkg);
	}

	frame_pld_addr = hifc_get_els_frame_addr(v_hba, v_pkg, els_cmd_code,
						 els_cmnd_type, &fram_phy_addr);

	if (HIFC_PKG_IS_ELS_RSP(els_cmnd_type)) {
		ret = hifc_get_els_rps_pld_len(els_cmnd_type, els_cmd_code,
					       &frame_pld_len);
		if (ret != RETURN_OK)
			return ret;

		hifc_build_els_wqe_ts_rsp(
			&sqe, sq_info, frame_pld_addr,
			els_cmnd_type, els_cmd_code,
			v_prntq_info->parent_sts_scq_info.cqm_queue_id);
	} else {
		/* Fill in HIFCOE_TASK_T_ELS */
		ret = hifc_get_els_req_and_acc_pld_len(els_cmd_code,
						       &frame_pld_len,
						       &acc_pld_len);
		if (ret != RETURN_OK)
			return ret;

		hifc_build_els_wqe_ts_req(
			&sqe, sq_info, els_cmd_code,
			v_prntq_info->parent_sts_scq_info.cqm_queue_id,
			frame_pld_addr);
	}

	/* Assemble the magicnum field of the els */
	hifc_build_els_wqe_ts_magic_num(&sqe, els_cmnd_type,
					UNF_GETXCHGALLOCTIME(v_pkg));

	/* Assemble the SQE Control Section part */
	hifc_build_service_wqe_ctrl_section(
		&sqe.ctrl_sl,
		HIFC_BYTES_TO_QW_NUM(HIFC_SQE_TS_SIZE),
		HIFC_BYTES_TO_QW_NUM(sizeof(struct hifcoe_variable_sge_s)));

	/* Assemble the SQE Task Section Els Common part */
	hifc_build_service_wqe_ts_common(&sqe.ts_sl, sq_info->rport_index,
					 local_xid, remote_xid,
					 HIFC_LSW(frame_pld_len));

	/* Build SGE */
	hifc_build_els_gs_wqe_sge(&sqe, frame_pld_addr, fram_phy_addr,
				  frame_pld_len, sq_info->context_id, v_hba);

	HIFC_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_REG_ATT, UNF_MAJOR,
		   "[info]Port(0x%x) RPort(0x%x) send ELS Type(0x%x) Code(0x%x) ExchId(0x%x)",
		   hba->port_cfg.port_id, sq_info->rport_index, els_cmnd_type,
		   els_cmd_code, local_xid);

	ret = hifc_parent_sq_enqueue(sq_info, &sqe);

	return ret;
}

unsigned int hifc_send_els_cmnd(void *v_hba, struct unf_frame_pkg_s *v_pkg)
{
	unsigned int ret = UNF_RETURN_ERROR;
	unsigned long flag = 0;
	struct hifc_hba_s *hba = NULL;
	struct hifc_parent_queue_info_s *prnt_qinfo = NULL;
	unsigned short els_cmd_code = UNF_ZERO;
	unsigned short els_rsp_code = UNF_ZERO;
	union unf_sfs_u *fc_entry = NULL;
	struct unf_rrq_s *rrq_pld = NULL;
	unsigned short ox_id = 0;
	unsigned short rx_id = 0;

	/* Check Parameters */
	UNF_CHECK_VALID(0x5014, UNF_TRUE, v_hba, return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(0x5015, UNF_TRUE, v_pkg, return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(0x5016, UNF_TRUE, UNF_GET_SFS_ENTRY(v_pkg),
			return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(0x5017, UNF_TRUE, HIFC_GET_CMND_PAYLOAD_ADDR(v_pkg),
			return UNF_RETURN_ERROR);

	HIFC_CHECK_PKG_ALLOCTIME(v_pkg);

	hba = (struct hifc_hba_s *)v_hba;
	els_cmd_code = HIFC_GET_ELS_CMND_CODE(v_pkg->cmnd);
	els_rsp_code = HIFC_GET_ELS_RSP_CODE(v_pkg->cmnd);

	/* If RRQ Req, Special processing */
	if (els_cmd_code == ELS_RRQ) {
		fc_entry = UNF_GET_SFS_ENTRY(v_pkg);
		rrq_pld = &fc_entry->rrq;
		ox_id = (unsigned short)(rrq_pld->oxid_rxid >> 16);
		rx_id = (unsigned short)(rrq_pld->oxid_rxid & 0xFFFF);
		ox_id += hba->exit_base;
		rrq_pld->oxid_rxid = ox_id << 16 | rx_id;
	}

	prnt_qinfo = hifc_find_parent_queue_info_by_pkg(hba, v_pkg);
	if (!prnt_qinfo) {
		HIFC_TRACE(UNF_EVTLOG_IO_INFO, UNF_LOG_IO_ATT, UNF_MAJOR,
			   "Port(0x%x) send ELS SID(0x%x) DID(0x%x) get a null parent queue info, send via root",
			   hba->port_cfg.port_id, v_pkg->frame_head.csctl_sid,
			   v_pkg->frame_head.rctl_did);

		/* If the Rport cannot be found, Send Pkg by Root SQ */
		ret = hifc_send_els_via_root(v_hba, v_pkg);
		return ret;
	}

	spin_lock_irqsave(&prnt_qinfo->parent_queue_state_lock, flag);

	/* After offload, Send Pkg by Parent SQ */
	if (HIFC_RPORT_OFFLOADED(prnt_qinfo)) {
		spin_unlock_irqrestore(&prnt_qinfo->parent_queue_state_lock,
				       flag);

		ret = hifc_send_els_via_parent(v_hba, v_pkg, prnt_qinfo);
	} else {
		/* Before offload, Send Pkg by Root SQ */
		spin_unlock_irqrestore(&prnt_qinfo->parent_queue_state_lock,
				       flag);

		ret = hifc_send_els_via_root(v_hba, v_pkg);
	}

	return ret;
}

unsigned int hifc_rq_rcv_els_rsp_sts(
		struct hifc_hba_s *v_hba,
		struct hifc_root_rq_complet_info_s *v_cs_info)
{
	unsigned int ret = UNF_RETURN_ERROR;
	unsigned int rx_id = (~0);
	struct unf_frame_pkg_s pkg = { 0 };

	rx_id = (unsigned int)v_cs_info->exch_id - v_hba->exit_base;
	pkg.private[PKG_PRIVATE_XCHG_ALLOC_TIME] = v_cs_info->magic_num;

	ret = hifc_rcv_els_rsp_sts(v_hba, &pkg, rx_id);
	HIFC_IO_STAT(v_hba, HIFCOE_TASK_T_ELS_RSP_STS);

	return ret;
}

static unsigned int hifc_recv_els_rsp_payload(struct hifc_hba_s *v_hba,
					      struct unf_frame_pkg_s *v_pkg,
					      unsigned int ox_id,
					      unsigned char *v_els_pld_buf,
					      unsigned int pld_len)
{
	unsigned int ret = UNF_RETURN_ERROR;

	v_pkg->type = UNF_PKG_ELS_REQ_DONE;
	v_pkg->private[PKG_PRIVATE_XCHG_HOT_POOL_INDEX] = ox_id;

	/* Payload Buffer in ROOT SQ Buffer */
	v_pkg->unf_cmnd_pload_bl.buffer_ptr = v_els_pld_buf;
	v_pkg->unf_cmnd_pload_bl.length = pld_len;
	v_pkg->byte_orders |= HIFC_BIT_2;

	/* Mark as a non-last block */
	v_pkg->last_pkg_flag = UNF_PKG_NOT_LAST_RESPONSE;

	UNF_LOWLEVEL_RECEIVE_ELS_PKG(ret, v_hba->lport, v_pkg);

	return ret;
}

static unsigned int hifc_rq_rcv_els_frame(struct hifc_hba_s *v_hba,
					  unsigned char *v_frame,
					  unsigned int frame_len,
					  unsigned short pkg_flag,
					  struct unf_frame_pkg_s *v_pkg)
{
	unsigned int ret = UNF_RETURN_ERROR;
	unsigned int ox_id = INVALID_VALUE32;
	unsigned int pld_len = 0;
	unsigned char *plg_buf = NULL;
	unsigned long flags = 0;

	plg_buf = v_frame;
	pld_len = frame_len;

	v_pkg->status = UNF_IO_SUCCESS;

	if (UNF_GET_FC_HEADER_RCTL(&v_pkg->frame_head) ==
				   HIFC_FC_RCTL_ELS_RSP) {
		ox_id = v_pkg->frame_head.oxid_rxid >> 16;

		if (!(HIFC_XID_IS_VALID(ox_id, (unsigned int)v_hba->exit_base,
					(unsigned int)v_hba->exit_count))) {
			HIFC_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_REG_ATT,
				   UNF_WARN, "[err]Port(0x%x) ExchId(0x%x) isn't in 0x%x~0x%x",
				   v_hba->port_cfg.port_id, ox_id,
				   v_hba->exit_base,
				   v_hba->exit_base + v_hba->exit_count - 1);

			goto rq_recv_error_els_frame;
		}

		ox_id -= v_hba->exit_base;

		ret = hifc_recv_els_rsp_payload(v_hba, v_pkg, ox_id, plg_buf,
						pld_len);
		if (ret != RETURN_OK) {
			HIFC_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_REG_ATT,
				   UNF_ERR,
				   "[err]Port(0x%x) receive ESL RSP payload error, OXID(0x%x) RXID(0x%x) PldLen(0x%x)",
				   v_hba->port_cfg.port_id, UNF_GET_OXID(v_pkg),
				   UNF_GET_RXID(v_pkg), pld_len);

			HIFC_ERR_IO_STAT(v_hba, HIFCOE_TASK_T_RCV_ELS_RSP);
		}

		if (HIFC_CHECK_IF_LAST_PKG(pkg_flag)) {
			ret = hifc_rcv_els_rsp(v_hba, v_pkg, ox_id);

			HIFC_IO_STAT(v_hba, HIFCOE_TASK_T_RCV_ELS_RSP);
		}
	} else if (UNF_GET_FC_HEADER_RCTL(&v_pkg->frame_head) ==
		   HIFC_FC_RCTL_ELS_REQ) {
		HIFC_IO_STAT(v_hba, HIFCOE_TASK_T_RCV_ELS_CMD);

		if (HIFC_CHECK_IF_FIRST_PKG(pkg_flag))
			v_pkg->xchg_contex = NULL;

		v_pkg->last_pkg_flag = (HIFC_CHECK_IF_LAST_PKG(pkg_flag)) ?
			UNF_PKG_LAST_REQUEST : UNF_PKG_NOT_LAST_REQUEST;

		ret = hifc_rcv_els_cmnd(v_hba, v_pkg, plg_buf, pld_len,
					HIFC_CHECK_IF_FIRST_PKG(pkg_flag));

		spin_lock_irqsave(&v_hba->delay_info.srq_lock, flags);
		if (v_hba->delay_info.srq_delay_flag) {
			v_hba->delay_info.srq_delay_flag = 0;

			if (!cancel_delayed_work(&v_hba->delay_info.del_work)) {
				HIFC_TRACE(UNF_EVTLOG_DRIVER_WARN,
					   UNF_LOG_LOGIN_ATT, UNF_WARN,
					   "[warn]Port(0x%x) rcvd plogi from srq process delay timer maybe timeout",
					   v_hba->port_cfg.port_id);
			}
			spin_unlock_irqrestore(&v_hba->delay_info.srq_lock,
					       flags);

			HIFC_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_LOGIN_ATT,
				   UNF_ERR,
				   "[info]Port(0x%x) received els from root rq and send delay plogi to CM",
				   v_hba->port_cfg.port_id);

			hifc_rcv_els_cmnd(
				v_hba, &v_hba->delay_info.pkg,
				v_hba->delay_info.pkg.unf_cmnd_pload_bl.buffer_ptr,
				0, UNF_FALSE);
		} else {
			spin_unlock_irqrestore(&v_hba->delay_info.srq_lock,
					       flags);
		}

	} else {
		goto rq_recv_error_els_frame;
	}

	return ret;

rq_recv_error_els_frame:
	return HIFC_RQ_ERROR_FRAME;
}

static unsigned int hifc_rq_rcv_bls_frame(struct hifc_hba_s *v_hba,
					  struct unf_frame_pkg_s *v_pkg)
{
	unsigned int ret = RETURN_OK;
	unsigned int ox_id = INVALID_VALUE32;

	v_pkg->status = UNF_IO_SUCCESS;

	if ((UNF_GET_FC_HEADER_RCTL(&v_pkg->frame_head) == HIFC_RCTL_BLS_ACC) ||
	    (UNF_GET_FC_HEADER_RCTL(&v_pkg->frame_head) == HIFC_RCTL_BLS_RJT)) {
		/* INI Mode */
		ox_id = UNF_GET_FC_HEADER_OXID(&v_pkg->frame_head);
		if ((ox_id < (unsigned int)v_hba->exit_base) ||
		    (ox_id >= (unsigned int)(v_hba->exit_base +
		    v_hba->exit_count))) {
			goto rq_recv_error_bls_frame;
		}
		ox_id -= v_hba->exit_base;

		ret = hifc_rcv_bls_rsp(v_hba, v_pkg, ox_id);
		HIFC_IO_STAT(v_hba, HIFCOE_TASK_T_RCV_ABTS_RSP);
	} else {
		goto rq_recv_error_bls_frame;
	}

	return ret;

rq_recv_error_bls_frame:
	return HIFC_RQ_ERROR_FRAME;
}

static unsigned int hifc_rq_rcv_service_frame(struct hifc_hba_s *v_hba,
					      unsigned char *v_frame,
					      unsigned int frame_len,
					      unsigned short pkg_flag,
					      struct unf_frame_pkg_s *v_pkg)
{
	unsigned int ret = UNF_RETURN_ERROR;
	unsigned char fc_frame_type = 0;

	fc_frame_type = UNF_GET_FC_HEADER_TYPE(&v_pkg->frame_head);

	if (fc_frame_type == HIFC_FC_TYPE_ELS) {
		v_hba->delay_info.root_rq_rcvd_flag = 1;
		ret = hifc_rq_rcv_els_frame(v_hba, v_frame, frame_len,
					    pkg_flag, v_pkg);
	} else if (fc_frame_type == HIFC_FC_TYPE_BLS) {
		ret = hifc_rq_rcv_bls_frame(v_hba, v_pkg);
	} else {
		ret = HIFC_RQ_ERROR_FRAME;
	}

	if (ret == HIFC_RQ_ERROR_FRAME) {
		/* Error statistics are collected when an invalid frame
		 * is received
		 */
		HIFC_IO_STAT(v_hba, HIFCOE_TASK_T_BUTT);

		HIFC_TRACE(UNF_EVTLOG_IO_ERR, UNF_LOG_IO_ATT, UNF_ERR,
			   "[info]Port(0x%x) Receive an unsupported  frame, Rctl(0x%x), Type(0x%x), Fctl(0x%x), Sid_Did(0x%x_0x%x),OxId_RxId(0x%x_0x%x), FrameLen(0x%x), drop it",
			   v_hba->port_cfg.port_id,
			   UNF_GET_FC_HEADER_RCTL(&v_pkg->frame_head),
			   UNF_GET_FC_HEADER_TYPE(&v_pkg->frame_head),
			   UNF_GET_FC_HEADER_FCTL(&v_pkg->frame_head),
			   UNF_GET_FC_HEADER_SID(&v_pkg->frame_head),
			   UNF_GET_FC_HEADER_DID(&v_pkg->frame_head),
			   UNF_GET_FC_HEADER_OXID(&v_pkg->frame_head),
			   UNF_GET_FC_HEADER_RXID(&v_pkg->frame_head),
			   frame_len);
	}

	return ret;
}

unsigned int hifc_rcv_service_frame_from_rq(struct hifc_hba_s *v_hba,
					    struct hifc_root_rq_info_s
					    *v_rq_info,
					    struct hifc_root_rq_complet_info_s
					    *v_complet_info,
					    unsigned short v_rcv_buf_num)
{
	unsigned short remain_len = 0;
	unsigned short rcv_len = 0;
	unsigned short pkg_flag = 0;
	unsigned int ret = UNF_RETURN_ERROR;
	unsigned short pkt_len = 0;
	void *root_rq_rcv_buf = NULL;
	unsigned short ci = 0;
	unsigned int loop = 0;
	struct unf_frame_pkg_s pkg = { 0 };
	struct unf_fchead_s *els_frame = NULL;
	unsigned char *pld_buf = NULL;
	unsigned int pld_len = 0;

	ci = v_rq_info->ci;
	pkt_len = v_complet_info->buf_length;
	memset(&pkg, 0, sizeof(pkg));

	for (loop = 0; loop < v_rcv_buf_num; loop++) {
		/* Obtain rcv buffer */
		root_rq_rcv_buf =
		(void *)((unsigned long long)v_rq_info->rq_rcv_buff +
		HIFC_ROOT_RQ_RECV_BUFF_SIZE * ci);

		/* Calculate the frame data address and length */
		els_frame = (struct unf_fchead_s *)root_rq_rcv_buf;
		rcv_len = HIFC_ROOT_RQ_RECV_BUFF_SIZE;
		pkg_flag = 0;

		if (loop == (v_rcv_buf_num - 1)) {
			pkg_flag |= HIFC_LAST_PKG_FLAG;
			remain_len = pkt_len % HIFC_ROOT_RQ_RECV_BUFF_SIZE;
			rcv_len = (remain_len > 0) ? (remain_len) :
				  HIFC_ROOT_RQ_RECV_BUFF_SIZE;
		}

		/* Calculate the frame data address and length */
		if (loop == 0) {
			pkg_flag |= HIFC_FIRST_PKG_FLAG;

			memcpy(&pkg.frame_head, els_frame,
			       sizeof(pkg.frame_head));
			hifc_big_to_cpu32(&pkg.frame_head,
					  sizeof(pkg.frame_head));
			pkg.private[PKG_PRIVATE_XCHG_ALLOC_TIME] =
				v_complet_info->magic_num;

			pld_buf = (unsigned char *)(els_frame + 1);
			pld_len = rcv_len - sizeof(pkg.frame_head);
		} else {
			pld_buf = (unsigned char *)els_frame;
			pld_len = rcv_len;
		}

		/* Processing the rqe sent by the FC ucode */
		ret = hifc_rq_rcv_service_frame(v_hba, pld_buf, pld_len,
						pkg_flag, &pkg);
		if (ret != RETURN_OK) {
			HIFC_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_REG_ATT,
				   UNF_INFO,
				   "[err]Up layer Process RQE frame or status abnormal(0x%x)",
				   ret);

			return UNF_RETURN_ERROR;
		}

		ci = ((ci + 1) < v_rq_info->q_depth) ? (ci + 1) : 0;
	}

	return RETURN_OK;
}

static unsigned int hifc_rcv_gs_rsp_payload(const struct hifc_hba_s *v_hba,
					    struct unf_frame_pkg_s *v_pkg,
					    unsigned int ox_id,
					    unsigned char *v_els_pld_buf,
					    unsigned int pld_len)
{
	unsigned int ret = UNF_RETURN_ERROR;

	v_pkg->type = UNF_PKG_GS_REQ_DONE;
	v_pkg->private[PKG_PRIVATE_XCHG_HOT_POOL_INDEX] = ox_id;

	/* Convert to small endian */
	hifc_big_to_cpu32(v_els_pld_buf, pld_len);

	/* Payload Buffer in ROOT SQ Buffer */
	v_pkg->unf_cmnd_pload_bl.buffer_ptr = v_els_pld_buf;
	v_pkg->unf_cmnd_pload_bl.length = pld_len;

	/* Mark as a non-last block */
	v_pkg->last_pkg_flag = UNF_PKG_NOT_LAST_RESPONSE;

	UNF_LOWLEVEL_RECEIVE_GS_PKG(ret, v_hba->lport, v_pkg);

	return ret;
}

static unsigned int hifc_scq_rcv_abts_rsp(struct hifc_hba_s *v_hba,
					  union hifcoe_scqe_u *v_scqe)
{
	/* Default path, which is sent from SCQ to the driver */
	unsigned char status = 0;
	unsigned int ret = UNF_RETURN_ERROR;
	unsigned int ox_id = INVALID_VALUE32;
	struct unf_frame_pkg_s pkg = { 0 };
	struct hifcoe_scqe_rcv_abts_rsp_s *abts_rsp = NULL;

	abts_rsp = &v_scqe->rcv_abts_rsp;
	pkg.private[PKG_PRIVATE_XCHG_ALLOC_TIME] = abts_rsp->magic_num;

	ox_id = (unsigned int)(abts_rsp->wd0.ox_id);

	if (unlikely((ox_id < (unsigned int)v_hba->exit_base) ||
		     (ox_id >=
		     (unsigned int)(v_hba->exit_base + v_hba->exit_count)))) {
		HIFC_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_LOGIN_ATT, UNF_ERR,
			   "[err]Port(0x%x) has bad OX_ID(0x%x) for bls_rsp",
			   v_hba->port_cfg.port_id, ox_id);

		return UNF_RETURN_ERROR;
	}

	ox_id -= v_hba->exit_base;

	if (unlikely(HIFC_SCQE_HAS_ERRCODE(v_scqe))) {
		HIFC_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT, UNF_WARN,
			   "[warn]Port(0x%x) BLS response has error code(0x%x) tag(0x%x)",
			   v_hba->port_cfg.port_id,
			   HIFC_GET_SCQE_STATUS(v_scqe),
			   (unsigned int)(abts_rsp->wd0.ox_id));

		status = UNF_IO_FAILED;
	} else {
		pkg.frame_head.rctl_did = abts_rsp->wd3.did;
		pkg.frame_head.csctl_sid = abts_rsp->wd4.sid;
		pkg.frame_head.oxid_rxid = (unsigned int)(abts_rsp->wd0.rx_id)
					     | ox_id << 16;

		/* BLS_ACC/BLS_RJT: IO_succeed */
		if (abts_rsp->wd2.fh_rctrl == HIFC_RCTL_BLS_ACC) {
			status = UNF_IO_SUCCESS;
		} else if (abts_rsp->wd2.fh_rctrl == HIFC_RCTL_BLS_RJT) {
			HIFC_TRACE(UNF_EVTLOG_DRIVER_INFO,
				   UNF_LOG_LOGIN_ATT, UNF_MAJOR,
				   "[info]Port(0x%x) ABTS RJT: %08x-%08x-%08x",
				   v_hba->port_cfg.port_id,
				   abts_rsp->payload[0],
				   abts_rsp->payload[1], abts_rsp->payload[2]);

			status = UNF_IO_SUCCESS;
		} else {
			/* 3. BA_RSP type is err: IO_failed */
			HIFC_TRACE(UNF_EVTLOG_DRIVER_ERR,
				   UNF_LOG_LOGIN_ATT, UNF_ERR,
				   "[err]Port(0x%x) BLS response RCTL is error",
				   v_hba->port_cfg.port_id);

			HIFC_ERR_IO_STAT(v_hba, HIFC_SCQE_ABTS_RSP);

			status = UNF_IO_FAILED;
		}
	}

	/* Set PKG/exchange status & Process BLS_RSP */
	pkg.status = status;
	ret = hifc_rcv_bls_rsp(v_hba, &pkg, ox_id);

	HIFC_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_REG_ATT, UNF_MAJOR,
		   "[info]Port(0x%x) recv ABTS rsp OX_ID(0x%x) RX_ID(0x%x) SID(0x%x) DID(0x%x) %s",
		   v_hba->port_cfg.port_id,
		   ox_id,
		   abts_rsp->wd0.rx_id,
		   abts_rsp->wd4.sid,
		   abts_rsp->wd3.did,
		   (ret == RETURN_OK) ? "OK" : "ERROR");

	return ret;
}

unsigned int hifc_rq_rcv_srv_err(struct hifc_hba_s *v_hba,
				 struct hifc_root_rq_complet_info_s *v_cs_info)
{
	UNF_REFERNCE_VAR(v_hba);
	UNF_REFERNCE_VAR(v_cs_info);

	HIFC_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT, UNF_WARN,
		   "[warn]hifc_rq_rcv_srv_err not implemented yet");

	if (!v_hba)
		return UNF_RETURN_ERROR;

	if (!v_cs_info)
		return UNF_RETURN_ERROR;

	return UNF_RETURN_ERROR;
}

unsigned int hifc_rcv_els_cmnd(const struct hifc_hba_s *v_hba,
			       struct unf_frame_pkg_s *v_pkg,
			       unsigned char *v_pld,
			       unsigned int pld_len,
			       int first_frame)
{
	unsigned int ret = UNF_RETURN_ERROR;

	/* Convert Payload to small endian */
	hifc_big_to_cpu32(v_pld, pld_len);

	v_pkg->type = UNF_PKG_ELS_REQ;

	v_pkg->unf_cmnd_pload_bl.buffer_ptr = v_pld;

	/* Payload length */
	v_pkg->unf_cmnd_pload_bl.length = pld_len;

	/* Obtain the Cmnd type from the Paylaod. The Cmnd is in small endian */
	if (first_frame == UNF_TRUE) {
		v_pkg->cmnd = UNF_GET_FC_PAYLOAD_ELS_CMND(
				v_pkg->unf_cmnd_pload_bl.buffer_ptr);
	}

	/* Errors have been processed in HIFC_RecvElsError */
	v_pkg->status = UNF_IO_SUCCESS;

	/* Send PKG to the CM layer */
	UNF_LOWLEVEL_RECEIVE_ELS_PKG(ret, v_hba->lport, v_pkg);

	return ret;
}

unsigned int hifc_rcv_els_rsp(const struct hifc_hba_s *v_hba,
			      struct unf_frame_pkg_s *v_pkg,
			      unsigned int ox_id)
{
	unsigned int ret = UNF_RETURN_ERROR;

	/* Receive CmndReqSts */
	v_pkg->type = UNF_PKG_ELS_REQ_DONE;
	v_pkg->private[PKG_PRIVATE_XCHG_HOT_POOL_INDEX] = ox_id;
	v_pkg->byte_orders |= HIFC_BIT_2;

	/* Mark the last block */
	v_pkg->last_pkg_flag = UNF_PKG_LAST_RESPONSE;

	/* Send PKG to the CM layer */
	UNF_LOWLEVEL_RECEIVE_ELS_PKG(ret, v_hba->lport, v_pkg);

	return ret;
}

unsigned int hifc_rcv_els_rsp_sts(const struct hifc_hba_s *v_hba,
				  struct unf_frame_pkg_s *v_pkg,
				  unsigned int rx_id)
{
	unsigned int ret = UNF_RETURN_ERROR;

	v_pkg->type = UNF_PKG_ELS_REPLY_DONE;
	v_pkg->private[PKG_PRIVATE_XCHG_HOT_POOL_INDEX] = rx_id;

	UNF_LOWLEVEL_SEND_ELS_DONE(ret, v_hba->lport, v_pkg);

	return ret;
}

unsigned int hifc_rcv_gs_rsp(const struct hifc_hba_s *v_hba,
			     struct unf_frame_pkg_s *v_pkg,
			     unsigned int ox_id)
{
	unsigned int ret = UNF_RETURN_ERROR;

	/* Receive CmndReqSts */
	v_pkg->type = UNF_PKG_GS_REQ_DONE;
	v_pkg->private[PKG_PRIVATE_XCHG_HOT_POOL_INDEX] = ox_id;

	/* Mark the last block */
	v_pkg->last_pkg_flag = UNF_PKG_LAST_RESPONSE;

	/* Send PKG to the CM layer */
	UNF_LOWLEVEL_RECEIVE_GS_PKG(ret, v_hba->lport, v_pkg);

	return ret;
}

unsigned int hifc_rcv_bls_rsp(const struct hifc_hba_s *v_hba,
			      struct unf_frame_pkg_s *v_pkg,
			      unsigned int ox_id)
{
	/*
	 * 1. SCQ (normal)
	 * 2. from Root RQ (parent no existence)
	 **
	 * single frame, single sequence
	 */
	unsigned int ret = UNF_RETURN_ERROR;

	v_pkg->type = UNF_PKG_BLS_REQ_DONE;
	v_pkg->private[PKG_PRIVATE_XCHG_HOT_POOL_INDEX] = ox_id;
	v_pkg->last_pkg_flag = UNF_PKG_LAST_RESPONSE;

	UNF_LOWLEVEL_RECEIVE_BLS_PKG(ret, v_hba->lport, v_pkg);

	return ret;
}

unsigned int hifc_rcv_tmf_marker_sts(const struct hifc_hba_s *v_hba,
				     struct unf_frame_pkg_s *v_pkg,
				     unsigned int ox_id)
{
	unsigned int ret = UNF_RETURN_ERROR;

	v_pkg->private[PKG_PRIVATE_XCHG_HOT_POOL_INDEX] = ox_id;

	/* Send PKG info to COM */
	UNF_LOWLEVEL_RECEIVE_MARKER_STS(ret, v_hba->lport, v_pkg);

	return ret;
}

unsigned int hifc_rcv_abts_marker_sts(const struct hifc_hba_s *v_hba,
				      struct unf_frame_pkg_s *v_pkg,
				      unsigned int ox_id)
{
	unsigned int ret = UNF_RETURN_ERROR;

	v_pkg->private[PKG_PRIVATE_XCHG_HOT_POOL_INDEX] = ox_id;

	UNF_LOWLEVEL_RECEIVE_ABTS_MARKER_STS(ret, v_hba->lport, v_pkg);

	return ret;
}

void hifc_scqe_error_pre_process(struct hifc_hba_s *v_hba,
				 union hifcoe_scqe_u *v_scqe)
{
	/* Currently, only printing and statistics collection are performed */
	HIFC_ERR_IO_STAT(v_hba, HIFC_GET_SCQE_TYPE(v_scqe));
	HIFC_SCQ_ERR_TYPE_STAT(v_hba, HIFC_GET_SCQE_STATUS(v_scqe));

	HIFC_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_ABNORMAL, UNF_WARN,
		   "[warn]Port(0x%x)-Task_type(%u) SCQE contain error code(%u), additional info(0x%x)",
		   v_hba->port_cfg.port_id,
		   v_scqe->common.ch.wd0.task_type,
		   v_scqe->common.ch.wd0.err_code,
		   v_scqe->common.conn_id);
}

unsigned int hifc_rcv_scqe_entry_from_scq(void *v_hba, void *v_scqe,
					  unsigned int scq_idx)
{
	unsigned int ret = UNF_RETURN_ERROR;
	int do_reclaim = UNF_FALSE;
	unsigned int index = 0;
	unsigned int total_index = 0;
	struct hifc_hba_s *hba = NULL;
	union hifcoe_scqe_u *scqe = NULL;

	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE, v_hba,
			return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE, v_scqe,
			return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE, HIFC_TOTAL_SCQ_NUM > scq_idx,
			return UNF_RETURN_ERROR);

	scqe = (union hifcoe_scqe_u *)v_scqe;
	hba = (struct hifc_hba_s *)v_hba;

	HIFC_IO_STAT(hba, HIFC_GET_SCQE_TYPE(scqe));

	/* 1. error code cheking */
	if (unlikely(HIFC_SCQE_HAS_ERRCODE(scqe))) {
		/* So far, just print & counter */
		hifc_scqe_error_pre_process(hba, scqe);
	}

	/* 2. Process SCQE by corresponding  processer */
	total_index = sizeof(scqe_handler_table) /
		       sizeof(struct unf_scqe_handler_table_s);
	while (index < total_index) {
		if (HIFC_GET_SCQE_TYPE(scqe) ==
		    scqe_handler_table[index].scqe_type) {
			ret = scqe_handler_table[index].pfn_scqe_handle_fun(
				hba, scqe);
			do_reclaim = scqe_handler_table[index].reclaim_sq_wpg;

			break;
		}

		index++;
	}

	/* 3. SCQE type check */
	if (unlikely(index == total_index)) {
		HIFC_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_LOGIN_ATT, UNF_ERR,
			   "[warn]Unknown SCQE type %d",
			   HIFC_GET_SCQE_TYPE(scqe));

		UNF_PRINT_SFS_LIMIT(UNF_ERR, hba->port_cfg.port_id, scqe,
				    sizeof(union hifcoe_scqe_u));
	}

	/* 4. If SCQE is for SQ-WQE then recovery Link List SQ free page */
	if (do_reclaim == UNF_TRUE) {
		if (HIFC_SCQE_CONN_ID_VALID(scqe)) {
			ret = hifc_reclaim_sq_wqe_page(v_hba, scqe);
		} else {
			/* NOTE: for buffer clear, the SCQE conn_id is 0xFFFF,
			 * count with HBA
			 */
			HIFC_HBA_STAT(
				(struct hifc_hba_s *)v_hba,
				HIFC_STAT_SQ_IO_BUFFER_CLEARED);
		}
	}

	return ret;
}

static void *hifc_get_els_buf_by_userid(struct hifc_hba_s *v_hba,
					unsigned short user_id)
{
	struct hifc_srq_buff_entry_s *buf_entry = NULL;
	struct hifc_srq_info_s *srq_info = NULL;

	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE, v_hba, return NULL);

	srq_info = &v_hba->els_srq_info;
	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE,
			user_id < srq_info->valid_wqe_num, return NULL);

	buf_entry = &srq_info->els_buff_entry_head[user_id];

	return buf_entry->buff_addr;
}

static unsigned int hifc_check_srq_buf_valid(struct hifc_hba_s *v_hba,
					     unsigned int *v_buf_id,
					     unsigned int v_buf_num)
{
	unsigned int index = 0;
	unsigned int buf_id = 0;
	void *srq_buf = NULL;

	for (index = 0; index < v_buf_num; index++) {
		buf_id = v_buf_id[index];

		if (buf_id < v_hba->els_srq_info.valid_wqe_num) {
			srq_buf = hifc_get_els_buf_by_userid(
					v_hba,
					(unsigned short)buf_id);
		} else {
			srq_buf = NULL;
		}

		if (!srq_buf) {
			HIFC_TRACE(UNF_EVTLOG_DRIVER_ERR,
				   UNF_LOG_LOGIN_ATT, UNF_ERR,
				   "[err]Port(0x%x) get srq buffer user id(0x%x) is null",
				   v_hba->port_cfg.port_id, buf_id);

			return UNF_RETURN_ERROR;
		}
	}

	return RETURN_OK;
}

static void hifc_reclaim_srq_buff(struct hifc_hba_s *v_hba,
				  unsigned int *v_buf_id,
				  unsigned int v_buf_num)
{
	unsigned int index = 0;
	unsigned int buf_id = 0;
	void *srq_buf = NULL;

	for (index = 0; index < v_buf_num; index++) {
		buf_id = v_buf_id[index];
		if (buf_id < v_hba->els_srq_info.valid_wqe_num) {
			srq_buf = hifc_get_els_buf_by_userid(
					v_hba,
					(unsigned short)buf_id);
		} else {
			srq_buf = NULL;
		}

		/* If the value of buffer is NULL, it indicates that the value
		 * of buffer is invalid. In this case, exit directly.
		 */
		if (!srq_buf)
			break;

		hifc_post_els_srq_wqe(&v_hba->els_srq_info,
				      (unsigned short)buf_id);
	}
}

static unsigned int hifc_check_els_gs_valid(struct hifc_hba_s *v_hba,
					    union hifcoe_scqe_u *v_scqe,
					    struct unf_frame_pkg_s *v_pkg,
					    unsigned int *v_buf_id,
					    unsigned int buf_num,
					    unsigned int frame_len)
{
	unsigned int ox_id = INVALID_VALUE32;

	ox_id = v_pkg->frame_head.oxid_rxid >> 16;

	/* The ELS CMD returns an error code and discards it directly */
	if ((sizeof(struct hifc_fc_frame_header) > frame_len) ||
	    (HIFC_SCQE_HAS_ERRCODE(v_scqe)) ||
	    (buf_num > HIFC_ELS_SRQ_BUF_NUM)) {
		HIFC_TRACE(UNF_EVTLOG_DRIVER_INFO,
			   UNF_LOG_LOGIN_ATT, UNF_KEVENT,
			   "[event]Port(0x%x) get scqe type(0x%x) payload len(0x%x),scq status(0x%x),user id num(0x%x) abnormal",
			   v_hba->port_cfg.port_id,
			   HIFC_GET_SCQE_TYPE(v_scqe),
			   frame_len,
			   HIFC_GET_SCQE_STATUS(v_scqe),
			   buf_num);

		/* ELS RSP Special Processing */
		if (HIFC_GET_SCQE_TYPE(v_scqe) == HIFC_SCQE_ELS_RSP) {
			if (HIFC_SCQE_ERR_TO_CM(v_scqe)) {
				v_pkg->status = UNF_IO_FAILED;
				(void)hifc_rcv_els_rsp(v_hba, v_pkg, ox_id);
			} else {
				HIFC_HBA_STAT(v_hba,
					      HIFC_STAT_ELS_RSP_EXCH_REUSE);
			}
		}

		/* GS RSP Special Processing */
		if (HIFC_GET_SCQE_TYPE(v_scqe) == HIFC_SCQE_GS_RSP) {
			if (HIFC_SCQE_ERR_TO_CM(v_scqe)) {
				v_pkg->status = UNF_IO_FAILED;
				(void)hifc_rcv_gs_rsp(v_hba, v_pkg, ox_id);
			} else {
				HIFC_HBA_STAT(v_hba,
					      HIFC_STAT_GS_RSP_EXCH_REUSE);
			}
		}

		/* Reclaim srq */
		if (buf_num <= HIFC_ELS_SRQ_BUF_NUM)
			hifc_reclaim_srq_buff(v_hba, v_buf_id, buf_num);

		return UNF_RETURN_ERROR;
	}

	/* ELS CMD Check the validity of the buffer sent by the ucode */
	if (HIFC_GET_SCQE_TYPE(v_scqe) == HIFC_SCQE_ELS_CMND) {
		if (hifc_check_srq_buf_valid(v_hba, v_buf_id, buf_num) !=
		    RETURN_OK) {
			HIFC_TRACE(UNF_EVTLOG_DRIVER_ERR,
				   UNF_LOG_LOGIN_ATT, UNF_ERR,
				   "[err]Port(0x%x) get els cmnd scqe user id num(0x%x) abnormal, as some srq buff is null",
				   v_hba->port_cfg.port_id, buf_num);

			hifc_reclaim_srq_buff(v_hba, v_buf_id, buf_num);

			return UNF_RETURN_ERROR;
		}
	}

	return RETURN_OK;
}

static unsigned int hifc_scq_rcv_els_cmd(struct hifc_hba_s *v_hba,
					 union hifcoe_scqe_u *v_scqe)
{
	unsigned int ret = RETURN_OK;
	unsigned int pld_len = 0;
	unsigned int hdr_len = 0;
	unsigned int frame_len = 0;
	unsigned int rcv_data_len = 0;
	unsigned int max_buf_num = 0;
	unsigned short buf_id = 0;
	unsigned int index = 0;
	unsigned char *pld = NULL;
	struct unf_frame_pkg_s pkg = { 0 };
	struct hifcoe_scqe_rcv_els_cmd_s *els_cmd = NULL;
	struct hifc_fc_frame_header  *els_frame = NULL;
	struct hifc_fc_frame_header  local_fc_frame = { 0 };
	void *els_buf = NULL;
	int first_frame = UNF_FALSE;
	unsigned long flags = 0;
	unsigned char srq_delay_flag = 0;

	els_cmd = &v_scqe->rcv_els_cmd;
	frame_len = els_cmd->wd3.data_len;
	max_buf_num = els_cmd->wd3.user_id_num;

	pkg.xchg_contex = NULL;
	pkg.status = UNF_IO_SUCCESS;

	/* Check the validity of error codes and buff. If an exception occurs,
	 * discard the error code
	 */
	ret = hifc_check_els_gs_valid(v_hba, v_scqe, &pkg, els_cmd->user_id,
				      max_buf_num, frame_len);
	if (ret != RETURN_OK)
		return RETURN_OK;

	/* Send data to COM cyclically */
	for (index = 0; index < max_buf_num; index++) {
		/* Exception record, which is not processed currently */
		if (rcv_data_len >= frame_len) {
			HIFC_TRACE(UNF_EVTLOG_DRIVER_ERR,
				   UNF_LOG_LOGIN_ATT, UNF_ERR,
				   "[err]Port(0x%x) get els cmd date len(0x%x) is bigger than fream len(0x%x)",
				   v_hba->port_cfg.port_id,
				   rcv_data_len, frame_len);
		}

		buf_id = (unsigned short)els_cmd->user_id[index];
		els_buf = hifc_get_els_buf_by_userid(v_hba, buf_id);

		/* Obtain playload address */
		pld = (unsigned char *)(els_buf);
		hdr_len = 0;
		first_frame = UNF_FALSE;
		if (index == 0) {
			els_frame = (struct hifc_fc_frame_header *)els_buf;
			pld = (unsigned char *)(els_frame + 1);

			hdr_len = sizeof(struct hifc_fc_frame_header);
			first_frame = UNF_TRUE;

			memcpy(&local_fc_frame, els_frame,
			       sizeof(struct hifc_fc_frame_header));
			hifc_big_to_cpu32(&local_fc_frame,
					  sizeof(struct hifc_fc_frame_header));
			memcpy(&pkg.frame_head, &local_fc_frame,
			       sizeof(pkg.frame_head));
		}

		/* Calculate the playload length */
		pkg.last_pkg_flag = 0;
		pld_len = HIFC_SRQ_ELS_SGE_LEN;

		if ((rcv_data_len + HIFC_SRQ_ELS_SGE_LEN) >= frame_len) {
			pkg.last_pkg_flag = 1;
			pld_len = frame_len - rcv_data_len;

			if (unlikely(
				(v_hba->active_topo == UNF_TOP_P2P_MASK) &&
				(v_hba->delay_info.root_rq_rcvd_flag == 0))) {
				/* Only data is pushed for the first time, but
				 * the last packet flag is not set
				 */
				pkg.last_pkg_flag = 0;
				srq_delay_flag = 1;

				HIFC_TRACE(UNF_EVTLOG_DRIVER_ERR,
					   UNF_LOG_LOGIN_ATT, UNF_WARN,
					   "[warn]Port(0x%x) revd els from srq, and need delay processed, topo(0x%x)",
					   v_hba->port_cfg.port_id,
					   v_hba->active_topo);
			}
		}

		/* Push data to COM */
		if (ret == RETURN_OK) {
			ret = hifc_rcv_els_cmnd(v_hba, &pkg, pld,
						(pld_len - hdr_len),
						first_frame);

			/* If the plogi arrives before the flogi, the pkg is
			 * saved, and the last packet is pushed
			 * when the root rq contains content.
			 */
			if (unlikely(srq_delay_flag == 1)) {
				spin_lock_irqsave(&v_hba->delay_info.srq_lock,
						  flags);
				memcpy(&v_hba->delay_info.pkg, &pkg,
				       sizeof(pkg));
				v_hba->delay_info.srq_delay_flag = 1;
				v_hba->delay_info.pkg.last_pkg_flag = 1;

				/* Add a 20-ms timer to prevent the root rq
				 * from processing data
				 */
				(void)queue_delayed_work(
					v_hba->work_queue,
					&v_hba->delay_info.del_work,
					(unsigned long)
					msecs_to_jiffies((unsigned int)
						HIFC_SRQ_PROCESS_DELAY_MS));

				spin_unlock_irqrestore(
					&v_hba->delay_info.srq_lock, flags);
			}
		}

		/* Reclaim srq buffer */
		hifc_post_els_srq_wqe(&v_hba->els_srq_info, buf_id);

		rcv_data_len += pld_len;
	}

	HIFC_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_REG_ATT, UNF_MAJOR,
		   "[info]Port(0x%x) recv ELS Type(0x%x) Cmnd(0x%x) OXID(0x%x) RXID(0x%x) SID(0x%x) DID(0x%x) %u",
		   v_hba->port_cfg.port_id,
		   pkg.type,
		   pkg.cmnd,
		   els_cmd->wd2.ox_id,
		   els_cmd->wd2.rx_id,
		   els_cmd->wd1.sid,
		   els_cmd->wd0.did,
		   ret);

	return ret;
}

static unsigned int hifc_get_els_gs_pld_len(struct hifc_hba_s *v_hba,
					    unsigned int v_rcv_data_len,
					    unsigned int v_frame_len)
{
	unsigned int pld_len;

	/* Exception record, which is not processed currently */
	if (v_rcv_data_len >= v_frame_len) {
		HIFC_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_LOGIN_ATT, UNF_ERR,
			   "[err]Port(0x%x) get els rsp date len(0x%x) is bigger than fream len(0x%x)",
			   v_hba->port_cfg.port_id,
			   v_rcv_data_len, v_frame_len);
	}

	pld_len = HIFC_SRQ_ELS_SGE_LEN;
	if ((v_rcv_data_len + HIFC_SRQ_ELS_SGE_LEN) >= v_frame_len)
		pld_len = v_frame_len - v_rcv_data_len;

	return pld_len;
}

static unsigned int hifc_scq_rcv_els_rsp(struct hifc_hba_s *v_hba,
					 union hifcoe_scqe_u *v_scqe)
{
	unsigned int ret = RETURN_OK;
	unsigned int pld_len = 0;
	unsigned int hdr_len = 0;
	unsigned int frame_len = 0;
	unsigned int rcv_data_len = 0;
	unsigned int max_buf_num = 0;
	unsigned short buf_id = 0;
	unsigned int index = 0;
	unsigned int ox_id = (~0);
	struct unf_frame_pkg_s pkg = { 0 };
	struct hifcoe_scqe_rcv_els_gs_rsp_s *els_rsp;
	struct hifc_fc_frame_header  *els_frame = NULL;
	void *els_buf = NULL;
	unsigned char *pld = NULL;

	els_rsp = &v_scqe->rcv_els_gs_rsp;
	frame_len = els_rsp->wd2.data_len;
	max_buf_num = els_rsp->wd4.user_id_num;

	ox_id = (unsigned int)(els_rsp->wd1.ox_id) - v_hba->exit_base;
	pkg.frame_head.oxid_rxid = (unsigned int)(els_rsp->wd1.rx_id) |
				     ox_id << 16;
	pkg.private[PKG_PRIVATE_XCHG_ALLOC_TIME] = els_rsp->magic_num;
	pkg.frame_head.csctl_sid = els_rsp->wd4.sid;
	pkg.frame_head.rctl_did = els_rsp->wd3.did;
	pkg.status = UNF_IO_SUCCESS;

	/* Handle the exception first. The ELS RSP returns the error code.
	 *  Only the OXID can submit the error code to the CM layer.
	 */
	ret = hifc_check_els_gs_valid(v_hba, v_scqe, &pkg,
				      els_rsp->user_id, max_buf_num, frame_len);
	if (ret != RETURN_OK)
		return RETURN_OK;

	/* if this is echo rsp */
	if (els_rsp->wd3.echo_rsp == UNF_TRUE) {
		/* echo time stamp fill in the Els rsp user_id last 4dword */
		pkg.private[PKG_PRIVATE_ECHO_CMD_RCV_TIME] =
							els_rsp->user_id[5];
		pkg.private[PKG_PRIVATE_ECHO_RSP_SND_TIME] =
							els_rsp->user_id[6];
		pkg.private[PKG_PRIVATE_ECHO_CMD_SND_TIME] =
							els_rsp->user_id[7];
		pkg.private[PKG_PRIVATE_ECHO_ACC_RCV_TIME] =
							els_rsp->user_id[8];
	}

	/* Send data to COM cyclically */
	for (index = 0; index < max_buf_num; index++) {
		/* Obtain buffer address */
		els_buf = NULL;
		buf_id = (unsigned short)els_rsp->user_id[index];

		els_buf = hifc_get_els_buf_by_userid(v_hba, buf_id);

		/* If the value of buffer is NULL, the buff id is abnormal and
		 * exits directly
		 */
		if (unlikely(!els_buf)) {
			HIFC_TRACE(UNF_EVTLOG_DRIVER_ERR,
				   UNF_LOG_LOGIN_ATT, UNF_ERR,
				   "[err]Port(0x%x) OXID(0x%x) RXID(0x%x) SID(0x%x) DID(0x%x) Index(0x%x) get els rsp buff user id(0x%x) abnormal",
				   v_hba->port_cfg.port_id, ox_id,
				   els_rsp->wd1.rx_id, els_rsp->wd4.sid,
				   els_rsp->wd3.did, index, buf_id);

			if (index == 0) {
				pkg.status = UNF_IO_FAILED;
				ret = hifc_rcv_els_rsp(v_hba, &pkg, ox_id);
			}

			return ret;
		}

		hdr_len = 0;
		pld = (unsigned char *)(els_buf);
		if (index == 0) {
			hdr_len = sizeof(struct hifc_fc_frame_header);

			els_frame = (struct hifc_fc_frame_header *)els_buf;
			pld = (unsigned char *)(els_frame + 1);
		}

		/* Calculate the playload length */
		pld_len = hifc_get_els_gs_pld_len(v_hba, rcv_data_len,
						  frame_len);

		/* Push data to COM */
		if (ret == RETURN_OK) {
			ret = hifc_recv_els_rsp_payload(v_hba, &pkg, ox_id, pld,
							(pld_len - hdr_len));
		}

		/* Reclaim srq buffer */
		hifc_post_els_srq_wqe(&v_hba->els_srq_info, buf_id);

		rcv_data_len += pld_len;
	}

	if ((els_rsp->wd3.end_rsp) && (ret == RETURN_OK))
		ret = hifc_rcv_els_rsp(v_hba, &pkg, ox_id);

	HIFC_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_REG_ATT, UNF_MAJOR,
		   "[info]Port(0x%x) receive ELS RSP OXID(0x%x) RXID(0x%x) SID(0x%x) DID(0x%x) end_rsp(0x%x) user_num(0x%x)",
		   v_hba->port_cfg.port_id,
		   ox_id,
		   els_rsp->wd1.rx_id,
		   els_rsp->wd4.sid,
		   els_rsp->wd3.did,
		   els_rsp->wd3.end_rsp,
		   els_rsp->wd4.user_id_num);

	return ret;
}

static unsigned int hifc_scq_rcv_gs_rsp(struct hifc_hba_s *v_hba,
					union hifcoe_scqe_u *v_scqe)
{
	unsigned int ret = RETURN_OK;
	unsigned int pld_len = 0;
	unsigned int hdr_len = 0;
	unsigned int frame_len = 0;
	unsigned int rcv_data_len = 0;
	unsigned int max_buf_num = 0;
	unsigned short buf_id = 0;
	unsigned int index = 0;
	unsigned int ox_id = (~0);
	struct unf_frame_pkg_s pkg = { 0 };
	struct hifcoe_scqe_rcv_els_gs_rsp_s *gs_rsp = NULL;
	struct hifc_fc_frame_header  *gs_frame = NULL;
	void *gs_buf = NULL;
	unsigned char *pld = NULL;

	gs_rsp = &v_scqe->rcv_els_gs_rsp;
	frame_len = gs_rsp->wd2.data_len;
	max_buf_num = gs_rsp->wd4.user_id_num;

	ox_id = (unsigned int)(gs_rsp->wd1.ox_id) - v_hba->exit_base;
	pkg.frame_head.oxid_rxid = (unsigned int)(gs_rsp->wd1.rx_id) |
				     ox_id << 16;
	pkg.private[PKG_PRIVATE_XCHG_ALLOC_TIME] = gs_rsp->magic_num;
	pkg.frame_head.csctl_sid = gs_rsp->wd4.sid;
	pkg.frame_head.rctl_did = gs_rsp->wd3.did;
	pkg.status = UNF_IO_SUCCESS;

	if (gs_rsp->wd3.end_rsp)
		HIFC_HBA_STAT(v_hba, HIFC_STAT_LAST_GS_SCQE);

	/* Exception handling: The GS RSP returns an error code. Only the OXID
	 * can submit the error code to the CM layer
	 */
	ret = hifc_check_els_gs_valid(v_hba, v_scqe, &pkg, gs_rsp->user_id,
				      max_buf_num, frame_len);
	if (ret != RETURN_OK)
		return RETURN_OK;

	/* Send data to COM cyclically */
	for (index = 0; index < max_buf_num; index++) {
		/* Obtain buffer address */
		gs_buf = NULL;
		buf_id = (unsigned short)gs_rsp->user_id[index];

		gs_buf = hifc_get_els_buf_by_userid(v_hba, buf_id);

		if (unlikely(!gs_buf)) {
			HIFC_TRACE(UNF_EVTLOG_DRIVER_ERR,
				   UNF_LOG_LOGIN_ATT, UNF_ERR,
				   "[err]Port(0x%x) OXID(0x%x) RXID(0x%x) SID(0x%x) DID(0x%x) Index(0x%x) get gs rsp scqe user id(0x%x) abnormal",
				   v_hba->port_cfg.port_id, ox_id,
				   gs_rsp->wd1.rx_id, gs_rsp->wd4.sid,
				   gs_rsp->wd3.did, index, buf_id);

			if (index == 0) {
				pkg.status = UNF_IO_FAILED;
				ret = hifc_rcv_gs_rsp(v_hba, &pkg, ox_id);
			}

			return ret;
		}

		/* Obtain playload address */
		hdr_len = 0;
		pld = (unsigned char *)(gs_buf);
		if (index == 0) {
			hdr_len = sizeof(struct hifc_fc_frame_header);

			gs_frame = (struct hifc_fc_frame_header  *)gs_buf;
			pld = (unsigned char *)(gs_frame + 1);
		}

		/* Calculate the playload length */
		pld_len = hifc_get_els_gs_pld_len(v_hba, rcv_data_len,
						  frame_len);

		/* Push data to COM */
		if (ret == RETURN_OK)
			ret = hifc_rcv_gs_rsp_payload(v_hba, &pkg, ox_id, pld,
						      (pld_len - hdr_len));

		/* Reclaim srq buffer */
		hifc_post_els_srq_wqe(&v_hba->els_srq_info, buf_id);

		rcv_data_len += pld_len;
	}

	if ((gs_rsp->wd3.end_rsp) && (ret == RETURN_OK))
		ret = hifc_rcv_gs_rsp(v_hba, &pkg, ox_id);

	HIFC_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_REG_ATT, UNF_MAJOR,
		   "[info]Port(0x%x) recv GS RSP OXID(0x%x) RXID(0x%x) SID(0x%x) DID(0x%x) end_rsp(0x%x) user_num(0x%x)",
		   v_hba->port_cfg.port_id,
		   ox_id,
		   gs_rsp->wd1.rx_id,
		   gs_rsp->wd4.sid,
		   gs_rsp->wd3.did,
		   gs_rsp->wd3.end_rsp,
		   gs_rsp->wd4.user_id_num);

	return ret;
}

static unsigned int hifc_scq_rcv_els_rsp_sts(struct hifc_hba_s *v_hba,
					     union hifcoe_scqe_u *v_scqe)
{
	unsigned int ret = UNF_RETURN_ERROR;
	unsigned int rx_id = INVALID_VALUE32;
	struct unf_frame_pkg_s pkg = { 0 };
	struct hifcoe_scqe_comm_rsp_sts_s *els_rsp_sts = NULL;

	els_rsp_sts = &v_scqe->comm_sts;
	rx_id = (unsigned int)els_rsp_sts->wd0.rx_id;
	rx_id = rx_id - v_hba->exit_base;

	pkg.private[PKG_PRIVATE_XCHG_ALLOC_TIME] = els_rsp_sts->magic_num;
	pkg.frame_head.oxid_rxid = rx_id |
				   (unsigned int)(els_rsp_sts->wd0.ox_id) << 16;

	if (unlikely(HIFC_SCQE_HAS_ERRCODE(v_scqe)))
		pkg.status = UNF_IO_FAILED;
	else
		pkg.status = UNF_IO_SUCCESS;

	ret = hifc_rcv_els_rsp_sts(v_hba, &pkg, rx_id);

	return ret;
}

static unsigned int hifc_check_rport_is_valid(
	const struct hifc_parent_queue_info_s *v_prntq_info,
	unsigned int scqe_xid)
{
	if (v_prntq_info->parent_ctx.cqm_parent_ctx_obj) {
		if ((v_prntq_info->parent_sq_info.context_id &
		    HIFC_CQM_XID_MASK) == (scqe_xid & HIFC_CQM_XID_MASK))
			return RETURN_OK;
	}

	return UNF_RETURN_ERROR;
}

static unsigned int hifc_scq_rcv_offload_sts(struct hifc_hba_s *v_hba,
					     union hifcoe_scqe_u *v_scqe)
{
	unsigned int rport_valid = UNF_RETURN_ERROR;
	unsigned int rport_index = 0;
	unsigned int cache_id = 0;
	unsigned int local_ctx_id = 0;
	unsigned long flag = 0;
	struct hifc_parent_queue_info_s *prnt_qinfo = NULL;
	struct hifcoe_scqe_sess_sts_s *offload_sts = NULL;
	struct hifc_destroy_ctrl_info_s destroy_sqe_info = { 0 };

	offload_sts = &v_scqe->sess_sts;
	rport_index = offload_sts->wd1.conn_id;
	cache_id = offload_sts->wd2.cid;
	local_ctx_id = offload_sts->wd0.xid_qpn;

	if (rport_index >= UNF_HIFC_MAXRPORT_NUM) {
		HIFC_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_LOGIN_ATT, UNF_ERR,
			   "[err]Port(0x%x) receive an error offload status: rport index(0x%x) is invalid, cache id(0x%x)",
			   v_hba->port_cfg.port_id, rport_index, cache_id);

		return UNF_RETURN_ERROR;
	}

	prnt_qinfo = &v_hba->parent_queue_mgr->parent_queues[rport_index];

	rport_valid = hifc_check_rport_is_valid(prnt_qinfo, local_ctx_id);
	if (rport_valid != RETURN_OK) {
		HIFC_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_LOGIN_ATT, UNF_ERR,
			   "[err]Port(0x%x) receive an error offload status: rport index(0x%x), context id(0x%x) is invalid",
			   v_hba->port_cfg.port_id, rport_index, local_ctx_id);

		return UNF_RETURN_ERROR;
	}

	/* off_load failed */
	if (HIFC_GET_SCQE_STATUS(v_scqe) != HIFC_COMPLETION_STATUS_SUCCESS) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_LOGIN_ATT, UNF_ERR,
			  "[err]Port(0x%x), rport(0x%x), context id(0x%x), cache id(0x%x), offload failed",
			  v_hba->port_cfg.port_id, rport_index,
			  local_ctx_id, cache_id);

		return UNF_RETURN_ERROR;
	}

	spin_lock_irqsave(&prnt_qinfo->parent_queue_state_lock, flag);
	prnt_qinfo->parent_sq_info.cache_id = cache_id;
	prnt_qinfo->offload_state = HIFC_QUEUE_STATE_OFFLOADED;
	atomic_set(&prnt_qinfo->parent_sq_info.sq_cashed, UNF_TRUE);

	if (prnt_qinfo->parent_sq_info.destroy_sqe.valid == UNF_TRUE) {
		destroy_sqe_info.valid =
			prnt_qinfo->parent_sq_info.destroy_sqe.valid;

		destroy_sqe_info.rport_index =
			prnt_qinfo->parent_sq_info.destroy_sqe.rport_index;

		destroy_sqe_info.time_out =
			prnt_qinfo->parent_sq_info.destroy_sqe.time_out;

		destroy_sqe_info.start_jiff =
			prnt_qinfo->parent_sq_info.destroy_sqe.start_jiff;

		destroy_sqe_info.rport_info.nport_id =
		prnt_qinfo->parent_sq_info.destroy_sqe.rport_info.nport_id;
		destroy_sqe_info.rport_info.rport_index =
		prnt_qinfo->parent_sq_info.destroy_sqe.rport_info.rport_index;
		destroy_sqe_info.rport_info.port_name =
		prnt_qinfo->parent_sq_info.destroy_sqe.rport_info.port_name;

		prnt_qinfo->parent_sq_info.destroy_sqe.valid = UNF_FALSE;
	}

	spin_unlock_irqrestore(&prnt_qinfo->parent_queue_state_lock, flag);

	hifc_pop_destroy_parent_queue_sqe((void *)v_hba, &destroy_sqe_info);

	return RETURN_OK;
}

unsigned int hifc_get_gs_req_and_rsp_pld_len(unsigned short cmd_code,
					     unsigned int *v_gs_pld_len,
					     unsigned int *v_gs_rsp_pld_len)
{
	UNF_CHECK_VALID(0x4917, UNF_TRUE, v_gs_pld_len,
			return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(0x4917, UNF_TRUE, v_gs_rsp_pld_len,
			return UNF_RETURN_ERROR);

	switch (cmd_code) {
	case NS_GPN_ID:
		*v_gs_pld_len = UNF_GPNID_PAYLOAD_LEN;
		*v_gs_rsp_pld_len = UNF_GPNID_RSP_PAYLOAD_LEN;
		break;

	case NS_GNN_ID:
		*v_gs_pld_len = UNF_GNNID_PAYLOAD_LEN;
		*v_gs_rsp_pld_len = UNF_GNNID_RSP_PAYLOAD_LEN;
		break;

	case NS_GFF_ID:
		*v_gs_pld_len = UNF_GFFID_PAYLOAD_LEN;
		*v_gs_rsp_pld_len = UNF_GFFID_RSP_PAYLOAD_LEN;
		break;

	case NS_GID_FT:
	case NS_GID_PT:
		*v_gs_pld_len = UNF_GID_PAYLOAD_LEN;
		*v_gs_rsp_pld_len = UNF_GID_ACC_PAYLOAD_LEN;
		break;

	case NS_RFT_ID:
		*v_gs_pld_len = UNF_RFTID_PAYLOAD_LEN;
		*v_gs_rsp_pld_len = UNF_RFTID_RSP_PAYLOAD_LEN;
		break;

	case NS_RFF_ID:
		*v_gs_pld_len = UNF_RFFID_PAYLOAD_LEN;
		*v_gs_rsp_pld_len = UNF_RFFID_RSP_PAYLOAD_LEN;
		break;
	case NS_GA_NXT:
		*v_gs_pld_len = UNF_GID_PAYLOAD_LEN;
		*v_gs_rsp_pld_len = UNF_GID_ACC_PAYLOAD_LEN;
		break;

	case NS_GIEL:
		*v_gs_pld_len = UNF_RFTID_RSP_PAYLOAD_LEN;
		*v_gs_rsp_pld_len = UNF_GID_ACC_PAYLOAD_LEN;
		break;

	default:
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_REG_ATT, UNF_WARN,
			  "[warn]Unknown GS commond type(0x%x)", cmd_code);
		return UNF_RETURN_ERROR;
	}

	return RETURN_OK;
}

static unsigned int hifc_send_gs_via_parent(void *v_hba,
					    struct unf_frame_pkg_s *v_pkg)
{
	unsigned short ox_id, rx_id;
	unsigned short cmd_code = UNF_ZERO;
	unsigned int ret = UNF_RETURN_ERROR;
	unsigned int gs_pld_len = UNF_ZERO;
	unsigned int gs_rsp_pld_len = UNF_ZERO;
	void *gs_pld_addr = NULL;
	struct hifc_hba_s *hba = NULL;
	struct hifc_parent_sq_info_s *sq_info;
	struct hifcoe_sqe_s sqe;
	unsigned long long fram_phy_addr;

	hba = (struct hifc_hba_s *)v_hba;

	memset(&sqe, 0, sizeof(struct hifcoe_sqe_s));

	sq_info = hifc_find_parent_sq_by_pkg(hba, v_pkg);
	if (!sq_info) {
		UNF_TRACE(UNF_EVTLOG_IO_ERR, UNF_LOG_IO_ATT, UNF_ERR,
			  "[err]Get NULL parent SQ information");

		return ret;
	}

	cmd_code = HIFC_GET_GS_CMND_CODE(v_pkg->cmnd);

	ret = hifc_get_gs_req_and_rsp_pld_len(cmd_code, &gs_pld_len,
					      &gs_rsp_pld_len);
	if (ret != RETURN_OK) {
		UNF_TRACE(UNF_EVTLOG_IO_ERR, UNF_LOG_IO_ATT, UNF_ERR,
			  "[err]Port(0x%x) send GS SID(0x%x) DID(0x%x), get error GS request and response payload length",
			  hba->port_cfg.port_id, v_pkg->frame_head.csctl_sid,
			  v_pkg->frame_head.rctl_did);

		return ret;
	}

	gs_pld_addr = (void *)(HIFC_GET_CMND_PAYLOAD_ADDR(v_pkg));
	fram_phy_addr = v_pkg->unf_cmnd_pload_bl.buf_dma_addr +
			sizeof(struct unf_fchead_s);

	if (cmd_code == NS_GID_FT || cmd_code == NS_GID_PT)
		gs_pld_addr = (void *)(UNF_GET_GID_PAYLOAD(v_pkg));

	/* Assemble the SQE Control Section part */
	hifc_build_service_wqe_ctrl_section(
		&sqe.ctrl_sl,
		HIFC_BYTES_TO_QW_NUM(HIFC_SQE_TS_SIZE),
		HIFC_BYTES_TO_QW_NUM(sizeof(struct hifcoe_variable_sge_s)));
	/* Assemble the SQE Task Section part */
	ox_id = UNF_GET_OXID(v_pkg) + hba->exit_base;
	rx_id = UNF_GET_RXID(v_pkg);
	hifc_build_service_wqe_ts_common(&sqe.ts_sl,
					 sq_info->rport_index, ox_id,
					 rx_id, HIFC_LSW(gs_pld_len));
	hifc_build_gs_wqe_ts_req(&sqe, UNF_GETXCHGALLOCTIME(v_pkg));

	hifc_build_els_gs_wqe_sge(&sqe, gs_pld_addr, fram_phy_addr, gs_pld_len,
				  sq_info->context_id, v_hba);

	ret = hifc_parent_sq_enqueue(sq_info, &sqe);

	return ret;
}

unsigned int hifc_send_gs_cmnd(void *v_hba, struct unf_frame_pkg_s *v_pkg)
{
	unsigned int ret = UNF_RETURN_ERROR;
	struct hifc_hba_s *hba = NULL;
	struct hifc_parent_queue_info_s *prnt_qinfo = NULL;

	UNF_CHECK_VALID(0x4913, UNF_TRUE, v_hba, return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(0x4914, UNF_TRUE, v_pkg, return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(0x4915, UNF_TRUE, UNF_GET_SFS_ENTRY(v_pkg),
			return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(0x4916, UNF_TRUE, HIFC_GET_CMND_PAYLOAD_ADDR(v_pkg),
			return UNF_RETURN_ERROR);

	HIFC_CHECK_PKG_ALLOCTIME(v_pkg);

	hba = (struct hifc_hba_s *)v_hba;
	prnt_qinfo = hifc_find_parent_queue_info_by_pkg(hba, v_pkg);

	if (!prnt_qinfo) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_IO_ATT, UNF_ERR,
			  "[err]Port(0x%x) send GS SID(0x%x) DID(0x%x), get a null parent queue information",
			  hba->port_cfg.port_id, v_pkg->frame_head.csctl_sid,
			  v_pkg->frame_head.rctl_did);

		return ret;
	}

	if (HIFC_RPORT_NOT_OFFLOADED(prnt_qinfo)) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_IO_ATT, UNF_MAJOR,
			  "[info]Port(0x%x) send GS SID(0x%x) DID(0x%x), send GS Request before PLOGI",
			  hba->port_cfg.port_id, v_pkg->frame_head.csctl_sid,
			  v_pkg->frame_head.rctl_did);

		return ret;
	}

	ret = hifc_send_gs_via_parent(v_hba, v_pkg);

	return ret;
}

static unsigned int hifc_get_bls_pld_len(struct unf_frame_pkg_s *v_pkg,
					 unsigned int *v_frame_len)
{
	unsigned int ret = RETURN_OK;
	unsigned int rctl = 0;

	UNF_CHECK_VALID(0x4917, UNF_TRUE, v_frame_len, return UNF_RETURN_ERROR);

	rctl = UNF_GET_FC_HEADER_RCTL(&v_pkg->frame_head);
	if (rctl == HIFC_RCTL_BLS_ACC) {
		/* BA_ACC */
		*v_frame_len = sizeof(struct unf_ba_acc_s);
	} else if (rctl == HIFC_RCTL_BLS_RJT) {
		/* BA_RJT */
		*v_frame_len = sizeof(struct unf_ba_rjt_s);
	} else {
		UNF_TRACE(UNF_EVTLOG_IO_ERR, UNF_LOG_IO_ATT, UNF_ERR,
			  "[warn]PKG Rclt(0x%x) not BLS ACC or RJT", rctl);

		*v_frame_len = 0;
		ret = UNF_RETURN_ERROR;
	}

	return ret;
}

static unsigned int hifc_send_bls_via_cmdq(struct hifc_hba_s *v_hba,
					   struct unf_frame_pkg_s *v_pkg)
{
	unsigned int ret = UNF_RETURN_ERROR;
	unsigned int rctl = 0;
	unsigned int bls_pld_len = 0;
	unsigned short rx_id = INVALID_VALUE16;
	unsigned short ox_id = INVALID_VALUE16;
	unsigned short exch_id = INVALID_VALUE16;
	unsigned char *bls_pld_addr = NULL;
	union hifc_cmdqe_u cmdqe;
	struct hifc_parent_sq_info_s *sq_info = NULL;

	sq_info = hifc_find_parent_sq_by_pkg(v_hba, v_pkg);
	if (!sq_info) {
		HIFC_TRACE(UNF_EVTLOG_IO_ERR, UNF_LOG_IO_ATT, UNF_ERR,
			   "[warn]Port(0x%x) send BLS SID_DID(0x%x_0x%x) with null parent queue information",
			   v_hba->port_cfg.port_id, v_pkg->frame_head.csctl_sid,
			   v_pkg->frame_head.rctl_did);

		return UNF_RETURN_ERROR;
	}

	/* Determine whether the value is ACC or RTJ and obtain the payload
	 * length of the ABTS_RSP
	 */
	ret = hifc_get_bls_pld_len(v_pkg, &bls_pld_len);
	if (ret != RETURN_OK) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_REG_ATT, UNF_ERR,
			  "[err]Port(0x%x) cmdq send BLS PKG DID(0x%x) failed",
			  v_hba->port_index, v_pkg->frame_head.rctl_did);

		return UNF_RETURN_ERROR;
	}

	rctl = UNF_GET_FC_HEADER_RCTL(&v_pkg->frame_head);
	exch_id = (v_pkg->private[PKG_PRIVATE_XCHG_HOT_POOL_INDEX]) & 0xffff;
	if ((exch_id == INVALID_VALUE16) && (rctl == HIFC_RCTL_BLS_ACC)) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_REG_ATT, UNF_ERR,
			  "[err]Port(0x%x) cmdq send BA_ACC with error RXID(0xffff)",
			  v_hba->port_index);

		return UNF_RETURN_ERROR;
	}

	/*
	 * FC-FS-3 15.3.3.1 Description:
	 * The OX_ID and RX_ID shall be set to match the Exchange in which
	 * the ABTS frame was transmitted.
	 */
	rx_id = UNF_GET_FC_HEADER_RXID(&v_pkg->frame_head);
	ox_id = UNF_GET_FC_HEADER_OXID(&v_pkg->frame_head);

	if (exch_id != INVALID_VALUE16) {
		exch_id = exch_id + v_hba->exit_base;
	} else {
		/* If the number is not an immediate number and the rxid is not
		 *  allocated to the CM, the CM may correspond to the rjt.
		 */
	}

	memset(&cmdqe, 0, sizeof(cmdqe));
	hifc_build_cmdqe_common(&cmdqe, HIFC_CMDQE_ABTS_RSP, exch_id);
	cmdqe.snd_abts_rsp.wd1.ox_id = ox_id;
	cmdqe.snd_abts_rsp.wd1.port_id = v_hba->port_index;
	cmdqe.snd_abts_rsp.wd1.payload_len = bls_pld_len;
	cmdqe.snd_abts_rsp.wd1.rsp_type = ((rctl == HIFC_RCTL_BLS_ACC) ? 0 : 1);
	cmdqe.snd_abts_rsp.wd2.conn_id = sq_info->rport_index;
	cmdqe.snd_abts_rsp.wd2.scqn = hifc_get_rport_maped_sts_scqn(v_hba,
							sq_info->rport_index);
	cmdqe.snd_abts_rsp.wd3.xid = sq_info->context_id;
	cmdqe.snd_abts_rsp.wd4.cid = sq_info->cache_id;
	cmdqe.snd_abts_rsp.wd5.req_rx_id = rx_id;
	bls_pld_addr = HIFC_GET_RSP_PAYLOAD_ADDR(v_pkg);
	memcpy(cmdqe.snd_abts_rsp.payload, bls_pld_addr, bls_pld_len);

	/* Send the ABTS_RSP command via ROOT CMDQ. */
	ret = hifc_root_cmdq_enqueue(v_hba, &cmdqe, sizeof(cmdqe.snd_abts_rsp));

	HIFC_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_REG_ATT, UNF_MAJOR,
		   "[info]Port(0x%x) RPort(0x%x) send ABTS_RSP OXID(0x%x) RXID(0x%x) EXCHID(0x%x)",
		   v_hba->port_cfg.port_id, sq_info->rport_index, ox_id,
		   rx_id, exch_id);

	return ret;
}

static unsigned int hifc_send_bls_via_parent(struct hifc_hba_s *v_hba,
					     struct unf_frame_pkg_s *v_pkg)
{
	unsigned int ret = UNF_RETURN_ERROR;
	unsigned short ox_id = INVALID_VALUE16;
	unsigned short rx_id = INVALID_VALUE16;
	struct hifcoe_sqe_s sqe;
	struct hifc_parent_sq_info_s *sq_info = NULL;
	struct hifc_parent_queue_info_s *prnt_qinfo = NULL;

	UNF_CHECK_VALID(0x5015, UNF_TRUE, (v_pkg->type == UNF_PKG_BLS_REQ),
			return UNF_RETURN_ERROR);

	memset(&sqe, 0, sizeof(struct hifcoe_sqe_s));

	prnt_qinfo = hifc_find_parent_queue_info_by_pkg(v_hba, v_pkg);
	if (!prnt_qinfo) {
		UNF_TRACE(UNF_EVTLOG_IO_WARN, UNF_LOG_IO_ATT, UNF_WARN,
			  "[warn]Port(0x%x) send BLS SID_DID(0x%x_0x%x) with null parent queue information",
			  v_hba->port_cfg.port_id, v_pkg->frame_head.csctl_sid,
			  v_pkg->frame_head.rctl_did);

		return ret;
	}

	sq_info = hifc_find_parent_sq_by_pkg(v_hba, v_pkg);
	if (!sq_info) {
		UNF_TRACE(UNF_EVTLOG_IO_WARN, UNF_LOG_IO_ATT, UNF_WARN,
			  "[warn]Port(0x%x) send ABTS SID_DID(0x%x_0x%x) with null parent queue information",
			  v_hba->port_cfg.port_id, v_pkg->frame_head.csctl_sid,
			  v_pkg->frame_head.rctl_did);

		return ret;
	}

	rx_id = UNF_GET_RXID(v_pkg);
	ox_id = UNF_GET_OXID(v_pkg) + v_hba->exit_base;

	/* Assemble the SQE Control Section part.
	 * The ABTS does not have Payload. bdsl=0
	 */
	hifc_build_service_wqe_ctrl_section(
		&sqe.ctrl_sl,
		HIFC_BYTES_TO_QW_NUM(HIFC_SQE_TS_SIZE), 0);

	/* Assemble the SQE Task Section BLS Common part. The value of DW2
	 * of BLS WQE is Rsvd, and the value of DW2 is 0
	 */
	hifc_build_service_wqe_ts_common(&sqe.ts_sl, sq_info->rport_index,
					 ox_id, rx_id, 0);

	/* Assemble the special part of the ABTS */
	hifc_build_bls_wqe_ts_req(&sqe, v_pkg->frame_head.parameter,
				  UNF_GETXCHGALLOCTIME(v_pkg));

	ret = hifc_parent_sq_enqueue(sq_info, &sqe);

	return ret;
}

unsigned int hifc_send_bls_cmnd(void *v_hba, struct unf_frame_pkg_s *v_pkg)
{
	unsigned int ret = UNF_RETURN_ERROR;
	struct hifc_hba_s *hba = NULL;
	unsigned long flag = 0;
	struct hifc_parent_queue_info_s *prnt_qinfo = NULL;

	UNF_CHECK_VALID(0x4913, UNF_TRUE, v_hba, return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(0x4914, UNF_TRUE, v_pkg, return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(0x4913, UNF_TRUE, UNF_PKG_BLS_REQ == v_pkg->type,
			return UNF_RETURN_ERROR);

	HIFC_CHECK_PKG_ALLOCTIME(v_pkg);
	hba = (struct hifc_hba_s *)v_hba;

	prnt_qinfo = hifc_find_parent_queue_info_by_pkg(hba, v_pkg);
	if (!prnt_qinfo) {
		HIFC_TRACE(UNF_EVTLOG_IO_WARN, UNF_LOG_IO_ATT, UNF_WARN,
			   "[warn]Port(0x%x) send BLS SID_DID(0x%x_0x%x) with null parent queue information",
			   hba->port_cfg.port_id, v_pkg->frame_head.csctl_sid,
			   v_pkg->frame_head.rctl_did);

		return ret;
	}

	spin_lock_irqsave(&prnt_qinfo->parent_queue_state_lock, flag);

	if (HIFC_RPORT_OFFLOADED(prnt_qinfo)) {
		spin_unlock_irqrestore(&prnt_qinfo->parent_queue_state_lock,
				       flag);

		/* INI: send ABTS_REQ via parent SQ */
		ret = hifc_send_bls_via_parent(hba, v_pkg);

	} else {
		spin_unlock_irqrestore(&prnt_qinfo->parent_queue_state_lock,
				       flag);

		ret = hifc_send_bls_via_cmdq(hba, v_pkg);
	}

	return ret;
}

static unsigned int hifc_scq_rcv_flush_sq_sts(struct hifc_hba_s *v_hba,
					      union hifcoe_scqe_u *v_scqe)
{
	/*
	 * RCVD sq flush sts
	 * --->>> continue flush or clear done
	 */
	unsigned int ret = UNF_RETURN_ERROR;

	if (v_scqe->flush_sts.wd0.port_id != v_hba->port_index) {
		HIFC_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_EVENT, UNF_CRITICAL,
			   "[err]Port(0x%x) clear_sts_port_idx(0x%x) not match hba_port_idx(0x%x), stage(0x%x)",
			   v_hba->port_cfg.port_id,
			   v_scqe->clear_sts.wd0.port_id,
			   v_hba->port_index,
			   v_hba->q_set_stage);

		return UNF_RETURN_ERROR;
	}

	if (v_scqe->flush_sts.wd0.last_flush) {
		HIFC_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_EVENT, UNF_INFO,
			   "[info]Port(0x%x) flush sq(0x%x) done, stage(0x%x)",
			   v_hba->port_cfg.port_id, v_hba->next_clearing_sq,
			   v_hba->q_set_stage);

		/* If the Flush STS is last one, send cmd done */
		ret = hifc_clear_sq_wqe_done(v_hba);
	} else {
		HIFC_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_EVENT, UNF_MAJOR,
			   "[info]Port(0x%x) continue flush sq(0x%x), stage(0x%x)",
			   v_hba->port_cfg.port_id, v_hba->next_clearing_sq,
			   v_hba->q_set_stage);

		ret = hifc_clear_pending_sq_wqe(v_hba);
	}

	return ret;
}

static unsigned int hifc_scq_rcv_buf_clear_sts(struct hifc_hba_s *v_hba,
					       union hifcoe_scqe_u *v_scqe)
{
	/*
	 * clear: fetched sq wqe
	 * ---to--->>> pending sq wqe
	 */
	unsigned int ret = UNF_RETURN_ERROR;

	if (v_scqe->clear_sts.wd0.port_id != v_hba->port_index) {
		HIFC_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_EVENT, UNF_CRITICAL,
			   "[err]Port(0x%x) clear_sts_port_idx(0x%x) not match hba_port_idx(0x%x), stage(0x%x)",
			   v_hba->port_cfg.port_id,
			   v_scqe->clear_sts.wd0.port_id,
			   v_hba->port_index,
			   v_hba->q_set_stage);

		return UNF_RETURN_ERROR;
	}

	HIFC_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_EVENT, UNF_KEVENT,
		   "[info]Port(0x%x) cleared all fetched wqe, start clear sq pending wqe, stage (0x%x)",
		   v_hba->port_cfg.port_id, v_hba->q_set_stage);

	v_hba->q_set_stage = HIFC_QUEUE_SET_STAGE_FLUSHING;
	ret = hifc_clear_pending_sq_wqe(v_hba);

	return ret;
}

static unsigned int hifc_scq_rcv_sess_rst_sts(struct hifc_hba_s *v_hba,
					      union hifcoe_scqe_u *v_scqe)
{
	unsigned int rport_index = INVALID_VALUE32;
	unsigned long flag = 0;
	struct hifc_parent_queue_info_s *parent_queue_info = NULL;
	struct hifcoe_scqe_sess_sts_s *sess_sts =
		(struct hifcoe_scqe_sess_sts_s *)(void *)v_scqe;
	unsigned int ctx_flush_done;
	unsigned int *ctx_dw = NULL;
	int ret;

	rport_index = sess_sts->wd1.conn_id;
	if (rport_index >= UNF_HIFC_MAXRPORT_NUM) {
		HIFC_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_LOGIN_ATT, UNF_ERR,
			   "[err]Port(0x%x) receive reset session cmd sts failed, invlaid rport_index(0x%x) status_code(0x%x) remain_cnt(0x%x)",
			   v_hba->port_cfg.port_id,
			   rport_index,
			   sess_sts->ch.wd0.err_code,
			   sess_sts->ch.wd0.cqe_remain_cnt);

		return UNF_RETURN_ERROR;
	}

	parent_queue_info =
		&v_hba->parent_queue_mgr->parent_queues[rport_index];

	/*
	 * If only session reset is used, the offload status of sq remains
	 * unchanged. If a link is deleted, the offload status is set to
	 * destroying and is irreversible.
	 */
	spin_lock_irqsave(&parent_queue_info->parent_queue_state_lock, flag);

	/*
	 * According to the fault tolerance principle, even if the connection
	 * deletion times out and the sts returns to delete the connection, one
	 * indicates thatthe cancel timer is successful, and 0 indicates that
	 * the timer is being processed.
	 */
	if (!cancel_delayed_work(
		&parent_queue_info->parent_sq_info.del_work)) {
		HIFC_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT, UNF_MAJOR,
			   "[info]Port(0x%x) rport_index(0x%x) delete rport timer maybe timeout",
			   v_hba->port_cfg.port_id,
			   rport_index);
	}

	/*
	 * If the SessRstSts is returned too late and the Parent Queue Info
	 * resource is released, OK is returned.
	 */
	if (parent_queue_info->offload_state != HIFC_QUEUE_STATE_DESTROYING) {
		spin_unlock_irqrestore(
			&parent_queue_info->parent_queue_state_lock, flag);

		HIFC_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT, UNF_WARN,
			   "[info]Port(0x%x) reset session cmd complete, no need to free parent qinfo, rport_index(0x%x) status_code(0x%x) remain_cnt(0x%x)",
			   v_hba->port_cfg.port_id,
			   rport_index,
			   sess_sts->ch.wd0.err_code,
			   sess_sts->ch.wd0.cqe_remain_cnt);

		return RETURN_OK;
	}

	if (parent_queue_info->parent_ctx.cqm_parent_ctx_obj) {
		ctx_dw = (unsigned int *)((void *)(parent_queue_info->parent_ctx.cqm_parent_ctx_obj->vaddr));
		ctx_flush_done = ctx_dw[HIFC_CTXT_FLUSH_DONE_DW_POS] &
			HIFC_CTXT_FLUSH_DONE_MASK_BE;
		/* memory barr */
		mb();
		if (ctx_flush_done == 0) {
			spin_unlock_irqrestore(
				&parent_queue_info->parent_queue_state_lock,
				flag);

			HIFC_TRACE(UNF_EVTLOG_DRIVER_WARN,
				   UNF_LOG_LOGIN_ATT, UNF_WARN,
				   "[warn]Port(0x%x) rport(0x%x) flushdone is not set, delay to free parent session",
				   v_hba->port_cfg.port_id, rport_index);

			/* If flushdone bit is not set,delay free Sq info */
			ret = queue_delayed_work(
				v_hba->work_queue,
				&parent_queue_info->parent_sq_info.flush_done_tmo_work,
				(unsigned long)
				msecs_to_jiffies((unsigned int)
				HIFC_SQ_WAIT_FLUSH_DONE_TIMEOUT_MS));
			if (ret == (int)false) {
				HIFC_HBA_STAT(
					v_hba,
					HIFC_STAT_PARENT_SQ_QUEUE_DELAYED_WORK);
				HIFC_TRACE(UNF_EVTLOG_DRIVER_ERR,
					   UNF_LOG_LOGIN_ATT, UNF_ERR,
					   "[err]Port(0x%x) rport(0x%x) queue delayed work failed iret:%d",
					   v_hba->port_cfg.port_id,
					   rport_index, ret);
			}

			return RETURN_OK;
		}
	}

	spin_unlock_irqrestore(&parent_queue_info->parent_queue_state_lock,
			       flag);

	HIFC_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT, UNF_MAJOR,
		   "[info]Port(0x%x) begin to free parent session with rport_index(0x%x)",
		   v_hba->port_cfg.port_id,
		   rport_index);

	hifc_free_parent_queue_info(v_hba, parent_queue_info);

	return RETURN_OK;
}

static unsigned int hifc_scq_rcv_clear_srq_sts(struct hifc_hba_s *v_hba,
					       union hifcoe_scqe_u *v_scqe)
{
	/*
	 * clear ELS/Immi SRQ
	 * ---then--->>> Destroy SRQ
	 */

	struct hifc_hba_s *hba = v_hba;
	struct hifc_srq_info_s *srq_info = NULL;

	if (HIFC_GET_SCQE_STATUS(v_scqe) != 0) {
		HIFC_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT, UNF_WARN,
			   "[warn]Port(0x%x) clear srq failed, status(0x%x)",
			   v_hba->port_cfg.port_id,
			   HIFC_GET_SCQE_STATUS(v_scqe));

		return RETURN_OK;
	}

	srq_info = &hba->els_srq_info;

	/*
	 * 1: cancel timer succeed
	 * 0: the timer is being processed, the SQ is released when the timer
	 * times out
	 */
	if (cancel_delayed_work(&srq_info->del_work)) {
		/*
		 * not free srq resource, it will be freed on hba remove
		 */
		srq_info->state = HIFC_CLEAN_DONE;
	}

	return RETURN_OK;
}

static unsigned int hifc_scq_rcv_marker_sts(struct hifc_hba_s *v_hba,
					    union hifcoe_scqe_u *v_scqe)
{
	unsigned int ret = UNF_RETURN_ERROR;
	unsigned int ox_id = INVALID_VALUE32;
	unsigned int rx_id = INVALID_VALUE32;
	struct unf_frame_pkg_s pkg = { 0 };
	struct hifcoe_scqe_itmf_marker_sts_s *marker_sts = NULL;

	marker_sts = &v_scqe->itmf_marker_sts;
	ox_id = (unsigned int)marker_sts->wd1.ox_id;
	ox_id = ox_id - v_hba->exit_base;
	rx_id = (unsigned int)marker_sts->wd1.rx_id;
	pkg.frame_head.oxid_rxid = rx_id | (unsigned int)(ox_id) << 16;

	pkg.frame_head.csctl_sid = marker_sts->wd3.sid;
	pkg.frame_head.rctl_did = marker_sts->wd2.did;

	/* 1. set pkg status */
	if (unlikely(HIFC_SCQE_HAS_ERRCODE(v_scqe)))
		pkg.status = UNF_IO_FAILED;
	else
		pkg.status = UNF_IO_SUCCESS;

	/* 2 .process rcvd marker STS: set exchange state */
	ret = hifc_rcv_tmf_marker_sts(v_hba, &pkg, ox_id);

	return ret;
}

static unsigned int hifc_scq_rcv_abts_marker_sts(struct hifc_hba_s *v_hba,
						 union hifcoe_scqe_u *v_scqe)
{
	unsigned int ret = UNF_RETURN_ERROR;
	unsigned int ox_id = INVALID_VALUE32;
	unsigned int rx_id = INVALID_VALUE32;
	struct unf_frame_pkg_s pkg = { 0 };

	struct hifcoe_scqe_abts_marker_sts_s *abts_sts = NULL;

	abts_sts = &v_scqe->abts_marker_sts;
	if (!abts_sts) {
		HIFC_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_REG_ATT, UNF_ERR,
			   "[err]ABTS marker STS is NULL");
		return ret;
	}

	ox_id = (unsigned int)abts_sts->wd1.ox_id;
	ox_id = ox_id - v_hba->exit_base;
	rx_id = (unsigned int)abts_sts->wd1.rx_id;
	pkg.frame_head.oxid_rxid = rx_id | (unsigned int)(ox_id) << 16;
	pkg.frame_head.csctl_sid = abts_sts->wd3.sid;
	pkg.frame_head.rctl_did = abts_sts->wd2.did;
	/* abts marker abts_maker_status as ucode stat */
	pkg.abts_maker_status = (unsigned int)abts_sts->wd3.io_state;

	if (unlikely(HIFC_SCQE_HAS_ERRCODE(v_scqe)))
		pkg.status = UNF_IO_FAILED;
	else
		pkg.status = UNF_IO_SUCCESS;

	ret = hifc_rcv_abts_marker_sts(v_hba, &pkg, ox_id);

	return ret;
}

unsigned int hifc_handle_aeq_offload_err(struct hifc_hba_s *v_hba,
					 struct hifcoe_aqe_data_s *v_aeq_msg)
{
	unsigned int ret = RETURN_OK;
	struct hifcoe_aqe_data_s *aeq_msg;
	unsigned int rport_index = 0;
	unsigned int local_ctx_id = 0;
	struct hifc_parent_queue_info_s *prnt_qinfo = NULL;
	struct hifc_destroy_ctrl_info_s destroy_sqe_info = { 0 };
	unsigned long flag = 0;

	aeq_msg = v_aeq_msg;

	HIFC_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_REG_ATT, UNF_ERR,
		   "[err]Port(0x%x) receive off_load Err Event, EvtCode(0x%x) Conn_id(0x%x) Xid(0x%x)",
		   v_hba->port_cfg.port_id, aeq_msg->wd0.evt_code,
		   aeq_msg->wd0.conn_id, aeq_msg->wd1.xid);

	/* Currently, only the offload failure caused by insufficient scqe is
	 * processed. Other errors are not processed temporarily.
	 */
	if (unlikely(aeq_msg->wd0.evt_code !=
		FCOE_ERROR_OFFLOAD_LACKOF_SCQE_FAIL)) {
		HIFC_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_REG_ATT, UNF_ERR,
			   "[err]Port(0x%x) receive an unsupported error code of AEQ Event, EvtCode(0x%x) Conn_id(0x%x)",
			   v_hba->port_cfg.port_id, aeq_msg->wd0.evt_code,
			   aeq_msg->wd0.conn_id);

		return UNF_RETURN_ERROR;
	}
	HIFC_SCQ_ERR_TYPE_STAT(v_hba, FCOE_ERROR_OFFLOAD_LACKOF_SCQE_FAIL);

	rport_index = aeq_msg->wd0.conn_id;
	local_ctx_id = aeq_msg->wd1.xid;

	if (rport_index >= UNF_HIFC_MAXRPORT_NUM) {
		HIFC_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_LOGIN_ATT, UNF_ERR,
			   "[err]Port(0x%x) receive an error offload status: rport index(0x%x) is invalid, Xid(0x%x)",
			   v_hba->port_cfg.port_id, rport_index,
			   aeq_msg->wd1.xid);

		return UNF_RETURN_ERROR;
	}

	prnt_qinfo = &v_hba->parent_queue_mgr->parent_queues[rport_index];
	if (hifc_check_rport_is_valid(prnt_qinfo, local_ctx_id) != RETURN_OK) {
		HIFC_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_LOGIN_ATT, UNF_ERR,
			   "[err]Port(0x%x) receive an error offload status: rport index(0x%x), context id(0x%x) is invalid",
			   v_hba->port_cfg.port_id, rport_index, local_ctx_id);

		return UNF_RETURN_ERROR;
	}

	spin_lock_irqsave(&prnt_qinfo->parent_queue_state_lock, flag);

	/* The offload status is restored only
	 * when the offload status is offloading
	 */
	if (prnt_qinfo->offload_state == HIFC_QUEUE_STATE_OFFLOADING)
		prnt_qinfo->offload_state = HIFC_QUEUE_STATE_INITIALIZED;

	spin_unlock_irqrestore(&prnt_qinfo->parent_queue_state_lock, flag);

	if (prnt_qinfo->parent_sq_info.destroy_sqe.valid == UNF_TRUE) {
		destroy_sqe_info.valid =
		prnt_qinfo->parent_sq_info.destroy_sqe.valid;
		destroy_sqe_info.rport_index =
		prnt_qinfo->parent_sq_info.destroy_sqe.rport_index;
		destroy_sqe_info.time_out =
		prnt_qinfo->parent_sq_info.destroy_sqe.time_out;
		destroy_sqe_info.start_jiff =
		prnt_qinfo->parent_sq_info.destroy_sqe.start_jiff;

		destroy_sqe_info.rport_info.nport_id =
		prnt_qinfo->parent_sq_info.destroy_sqe.rport_info.nport_id;

		destroy_sqe_info.rport_info.rport_index =
		prnt_qinfo->parent_sq_info.destroy_sqe.rport_info.rport_index;

		destroy_sqe_info.rport_info.port_name =
		prnt_qinfo->parent_sq_info.destroy_sqe.rport_info.port_name;

		prnt_qinfo->parent_sq_info.destroy_sqe.valid = UNF_FALSE;

		HIFC_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT, UNF_MAJOR,
			   "[info]Port(0x%x) pop up delay destroy parent sq, sqe start time 0x%llx, timeout value 0x%x, rport index 0x%x, offload state 0x%x",
			   v_hba->port_cfg.port_id,
			   destroy_sqe_info.start_jiff,
			   destroy_sqe_info.time_out,
			   prnt_qinfo->parent_sq_info.destroy_sqe.rport_info.rport_index,
			   HIFC_QUEUE_STATE_INITIALIZED);

		ret = hifc_free_parent_resource(v_hba,
						&destroy_sqe_info.rport_info);
		if (ret != RETURN_OK) {
			HIFC_TRACE(UNF_EVTLOG_DRIVER_ERR,
				   UNF_LOG_LOGIN_ATT, UNF_ERR,
				   "[err]Port(0x%x) pop delay destroy parent sq failed, rport index 0x%x, rport nport id 0x%x",
				   v_hba->port_cfg.port_id,
				   destroy_sqe_info.rport_info.rport_index,
				   destroy_sqe_info.rport_info.nport_id);
		}
	}

	return ret;
}
