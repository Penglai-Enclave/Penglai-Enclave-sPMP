// SPDX-License-Identifier: GPL-2.0
/* Huawei Fabric Channel Linux driver
 * Copyright(c) 2018 Huawei Technologies Co., Ltd
 *
 */

#include "hifc_module.h"
#include "hifc_service.h"

void hifc_build_common_wqe_ctrls(struct hifcoe_wqe_ctrl_s *v_ctrl_sl,
				 unsigned char v_task_len)
{
	/* "BDSL" field of CtrlS - defines the size of BDS,
	 *  which varies from 0 to 2040 bytes (8 bits of 8 bytes' chunk)
	 */
	v_ctrl_sl->ch.wd0.bdsl = 0;

	/*
	 * "DrvSL" field of CtrlS - defines the size of DrvS, which varies from
	 * 0 to 24 bytes
	 */
	v_ctrl_sl->ch.wd0.drv_sl = 0;

	/* a.
	 * b1 - linking WQE, which will be only used in linked page architecture
	 * instead of ring, it's a special control WQE which does not contain
	 * any buffer or inline data information, and will only be consumed by
	 *  hardware. The size is aligned to WQEBB/WQE b0 - normal WQE, either
	 * normal SEG WQE or inline data WQE
	 */
	v_ctrl_sl->ch.wd0.wf = 0;

	/*
	 * "CF" field of CtrlS - Completion Format - defines the format of CS.
	 * a.b0 - Status information is embedded inside of Completion Section
	 * b.b1 - Completion Section keeps SGL, where Status information
	 * should be written. (For the definition of SGLs see ?4.1* .)
	 */
	v_ctrl_sl->ch.wd0.cf = 0;

	/*
	 * "TSL" field of CtrlS - defines the size of TS, which varies from 0
	 * to 248 bytes
	 */
	v_ctrl_sl->ch.wd0.tsl = v_task_len;

	/*
	 * Variable length SGE (vSGE). The size of SGE is 16 bytes. The vSGE
	 * format is of two types, which are defined by "VA " field of CtrlS.
	 * "VA" stands for Virtual Address: o b0. SGE comprises 64-bits buffer's
	 *  pointer and 31-bits Length, each SGE can only support up to 2G-1B,
	 * it can guarantee each single SGE length can not exceed 2GB by nature,
	 *  A byte count value of zero means a 0byte data transfer.o b1.
	 * SGE comprises 64-bits buffer's pointer, 31-bits Length and 30-bits
	 * Key of the Translation table ,each SGE can only support up to 2G-1B,
	 * it can guarantee each single SGE length can notexceed 2GB by nature,
	 * A byte count value of zero means a 0byte data transfer
	 */
	v_ctrl_sl->ch.wd0.va = 0;

	/*
	 * "DF" field of CtrlS - Data Format - defines the format of BDS
	 * a.  b0 - BDS carries the list of SGEs (SGL)
	 * b.  b1 - BDS carries the inline data
	 */
	v_ctrl_sl->ch.wd0.df = 0;

	/*
	 * "CR" - Completion is Required - marks CQE generation request per WQE
	 */
	v_ctrl_sl->ch.wd0.cr = 1;

	/*
	 * "DIFSL" field of CtrlS - defines the size of DIFS, which varies from
	 * 0 to 56 bytes
	 */
	v_ctrl_sl->ch.wd0.dif_sl = 0;

	/*
	 * "CSL" field of CtrlS - defines the size of CS, which varies from 0 to
	 * 24 bytes
	 */
	v_ctrl_sl->ch.wd0.csl = 0;

	/* "CtrlSL" - C describes the size of CtrlS in 8 bytes chunks.
	 *The value Zero is not valid
	 */
	v_ctrl_sl->ch.wd0.ctrl_sl = 1;

	/* "O" - Owner - marks ownership of WQE */
	v_ctrl_sl->ch.wd0.owner = 0;
}

void hifc_build_trd_twr_wqe_ctrls(struct unf_frame_pkg_s *v_pkg,
				  struct hifcoe_sqe_s *v_sqe)
{
	/* "BDSL" field of CtrlS - defines the size of BDS, which varies from
	 * 0 to 2040 bytes (8 bits of 8 bytes' chunk)
	 */
	/* TrdWqe carry 2 SGE defaultly, 4DW per SGE, the value is 4 because
	 * unit is 2DW, in double SGL mode, bdsl is 2
	 */
	v_sqe->ctrl_sl.ch.wd0.bdsl = HIFC_T_RD_WR_WQE_CTR_BDSL_SIZE;

	/*
	 * "DrvSL" field of CtrlS - defines the size of DrvS, which varies from
	 * 0 to 24 bytes  DrvSL config for 0
	 */
	v_sqe->ctrl_sl.ch.wd0.drv_sl = 0;

	/* a. b1 - linking WQE, which will be only used in linked page
	 * architecture instead of ring, it's a special control WQE which does
	 *  not contain any buffer or inline data information, and will only be
	 * consumed by hardware. The size is aligned to WQEBB/WQE b0 - normal
	 * WQE, either normal SEG WQE or inline data WQE
	 */
	/* normal wqe */
	v_sqe->ctrl_sl.ch.wd0.wf = 0;

	/*
	 * "CF" field of CtrlS - Completion Format - defines the format of CS.
	 * a.b0 - Status information is embedded inside of Completion Section
	 * b.b1 - Completion Section keeps SGL, where Status information
	 * should be written. (For the definition of SGLs see ?4.1.)
	 */
	/* by SCQE mode, the value is ignored */
	v_sqe->ctrl_sl.ch.wd0.cf = 0;

	/* "TSL" field of CtrlS - defines the size of TS, which varies from 0 to
	 * 248 bytes
	 */
	/* TSL is configured by 56 bytes */
	v_sqe->ctrl_sl.ch.wd0.tsl = sizeof(struct hifcoe_sqe_ts_s) /
					HIFC_WQE_SECTION_CHUNK_SIZE;

	/*
	 * Variable length SGE (vSGE). The size of SGE is 16 bytes. The vSGE
	 * format is of two types, which are defined by "VA" field of CtrlS.
	 * "VA" stands for Virtual Address: o b0. SGE comprises 64-bits buffer's
	 * pointer and 31-bits Length, each SGE can only support up to 2G-1B, it
	 * can guarantee each single SGE length can not exceed 2GB by nature, A
	 * byte count value of zero means a 0byte data transfer. o b1. SGE
	 * comprises 64-bits buffer's pointer, 31-bits Length and 30-bits Key of
	 * the Translation table , each SGE can only support up to 2G-1B, it can
	 * guarantee each single SGE length can not exceed 2GB by nature, A byte
	 * count value of zero means a 0byte data transfer
	 */
	v_sqe->ctrl_sl.ch.wd0.va = 0;

	/*
	 * "DF" field of CtrlS - Data Format - defines the format of BDS
	 * a. b0 - BDS carries the list of SGEs (SGL)
	 * b.  b1 - BDS carries the inline data
	 */
	v_sqe->ctrl_sl.ch.wd0.df = 0;

	/* "CR" - Completion is Required marks CQE generation request per WQE */
	/* by SCQE mode, this value is ignored */
	v_sqe->ctrl_sl.ch.wd0.cr = 1;

	/*
	 * "DIFSL" field of CtrlS - defines the size of DIFS, which varies from
	 * 0 to 56 bytes.
	 */
	v_sqe->ctrl_sl.ch.wd0.dif_sl = 0;

	/*
	 * "CSL" field of CtrlS - defines the size of CS, which varies from 0 to
	 * 24 bytes
	 */
	v_sqe->ctrl_sl.ch.wd0.csl = 0;

	/* "CtrlSL" - C describes the size of CtrlS in 8 bytes chunks.
	 * The value Zero is not valid.
	 */
	v_sqe->ctrl_sl.ch.wd0.ctrl_sl = HIFC_T_RD_WR_WQE_CTR_CTRLSL_SIZE;

	/* "O" - Owner - marks ownership of WQE */
	v_sqe->ctrl_sl.ch.wd0.owner = 0;
}

void hifc_build_service_wqe_ts_common(struct hifcoe_sqe_ts_s *v_sqe_ts,
				      unsigned int rport_index,
				      unsigned short local_xid,
				      unsigned short remote_xid,
				      unsigned short data_len)
{
	v_sqe_ts->local_xid = local_xid;

	v_sqe_ts->wd0.conn_id = (unsigned short)rport_index;
	v_sqe_ts->wd0.remote_xid = remote_xid;

	v_sqe_ts->cont.els_gs_elsrsp_comm.data_len = data_len;
}

void hifc_build_els_gs_wqe_sge(struct hifcoe_sqe_s *v_sqe, void *v_buf_addr,
			       unsigned long long v_phy_addr,
			       unsigned int buf_len,
			       unsigned int xid, void *v_hba)
{
	unsigned long long els_rsp_phy_addr;
	struct hifcoe_variable_sge_s *psge = NULL;

	/* Fill in SGE and convert it to big-endian. */
	psge = &v_sqe->sge[0];
	els_rsp_phy_addr = v_phy_addr;
	psge->buf_addr_hi = HIFC_HIGH_32_BITS(els_rsp_phy_addr);
	psge->buf_addr_lo = HIFC_LOW_32_BITS(els_rsp_phy_addr);
	psge->wd0.buf_len = buf_len;
	psge->wd0.r_flag = 0;
	psge->wd1.extension_flag = HIFC_WQE_SGE_NOT_EXTEND_FLAG;
	psge->wd1.buf_addr_gpa = (psge->buf_addr_lo >> 16);
	psge->wd1.xid = (xid & 0x3fff);
	psge->wd1.last_flag = HIFC_WQE_SGE_LAST_FLAG;
	hifc_cpu_to_big32(psge, sizeof(*psge));

	/* Converts the payload of an FC frame into a big end. */
	hifc_cpu_to_big32(v_buf_addr, buf_len);
}

void hifc_build_els_wqe_ts_rsp(struct hifcoe_sqe_s *v_sqe, void *v_sq_info,
			       void *v_frame_pld, unsigned short type,
			       unsigned short cmnd, unsigned int v_scqn)
{
	struct unf_pril_payload_s *pri_acc_pld = NULL;
	struct hifcoe_sqe_els_rsp_s *els_rsp = NULL;
	struct hifcoe_sqe_ts_s *sqe_ts = NULL;
	struct hifc_parent_sq_info_s *sq_info = NULL;
	struct hifc_hba_s *hba = NULL;

	UNF_CHECK_VALID(0x5015, UNF_TRUE, v_sqe, return);
	UNF_CHECK_VALID(0x5015, UNF_TRUE, v_frame_pld, return);
	UNF_CHECK_VALID(0x5015, UNF_TRUE, v_sq_info, return);

	sqe_ts = &v_sqe->ts_sl;
	els_rsp = &sqe_ts->cont.els_rsp;
	sqe_ts->task_type = HIFC_SQE_ELS_RSP;

	/* The default chip does not need to update parameters. */
	els_rsp->wd1.para_update = 0x0;

	sq_info = (struct hifc_parent_sq_info_s *)v_sq_info;
	hba = (struct hifc_hba_s *)sq_info->phba;
	/* When the PLOGI request is sent, the microcode needs to be instructed
	 * to clear the I/O related to the link to avoid data inconsistency
	 * caused by the disorder of the IO.
	 */
	if (((cmnd == ELS_LOGO) || (cmnd == ELS_PLOGI)) && hba) {
		els_rsp->wd1.clr_io = 1;
		els_rsp->wd6.reset_exch_start = hba->exit_base;
		els_rsp->wd6.reset_exch_end = hba->exit_base +
						(hba->exit_count - 1);
		els_rsp->wd7.scqn = v_scqn;

		HIFC_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT, UNF_MAJOR,
			   "Port(0x%x) send cmd(0x%x) to RPort(0x%x),rport index(0x%x), notify clean io start 0x%x, end 0x%x, scqn 0x%x.",
			   sq_info->local_port_id,
			   cmnd,
			   sq_info->remote_port_id,
			   sq_info->rport_index,
			   els_rsp->wd6.reset_exch_start,
			   els_rsp->wd6.reset_exch_end,
			   v_scqn);

		return;
	}

	if (type == ELS_RJT)
		return;

	/*
	 * Enter WQE in the PrliAcc negotiation parameter, and fill in the
	 * Update flag in WQE.
	 */
	if (cmnd == ELS_PRLI) {
		/* The chip updates the PLOGI ACC negotiation parameters. */
		els_rsp->wd2.seq_cnt = sq_info->plogi_coparams.seq_cnt;
		els_rsp->wd2.e_d_tov = sq_info->plogi_coparams.ed_tov;
		els_rsp->wd2.tx_mfs = sq_info->plogi_coparams.tx_mfs;
		els_rsp->e_d_tov_timer_val =
				sq_info->plogi_coparams.ed_tov_timer_val;

		/* The chip updates the PRLI ACC parameter. */
		pri_acc_pld = (struct unf_pril_payload_s *)v_frame_pld;
		els_rsp->wd4.xfer_dis = HIFC_GET_PRLI_PARAM_WXFER(
							pri_acc_pld->parms);
		els_rsp->wd4.conf = HIFC_GET_PRLI_PARAM_CONF(
							pri_acc_pld->parms);
		els_rsp->wd4.rec = HIFC_GET_PRLI_PARAM_REC(pri_acc_pld->parms);

		els_rsp->wd1.para_update = 0x03;

		HIFC_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT, UNF_MAJOR,
			   "Port(0x%x) save rport index(0x%x) login parms,seqcnt:0x%x,e_d_tov:0x%x,txmfs:0x%x,e_d_tovtimerval:0x%x,xfer_dis:0x%x, conf:0x%x,rec:0x%x.",
			   sq_info->local_port_id,
			   sq_info->rport_index, els_rsp->wd2.seq_cnt,
			   els_rsp->wd2.e_d_tov, els_rsp->wd2.tx_mfs,
			   els_rsp->e_d_tov_timer_val, els_rsp->wd4.xfer_dis,
			   els_rsp->wd4.conf, els_rsp->wd4.rec);
	}
}

void hifc_build_els_wqe_ts_req(struct hifcoe_sqe_s *v_sqe, void *v_sq_info,
			       unsigned short cmnd, unsigned int v_scqn,
			       void *v_frame_pld)
{
	struct hifcoe_sqe_ts_s *v_sqe_ts = NULL;
	struct hifcoe_sqe_t_els_gs_s *els_req = NULL;
	struct hifc_parent_sq_info_s *sq_info = NULL;
	struct hifc_hba_s *hba = NULL;
	struct unf_rec_pld_s *rec_pld = NULL;

	v_sqe_ts = &v_sqe->ts_sl;
	v_sqe_ts->task_type = HIFC_SQE_ELS_CMND;
	els_req = &v_sqe_ts->cont.t_els_gs;

	sq_info = (struct hifc_parent_sq_info_s *)v_sq_info;
	hba = (struct hifc_hba_s *)sq_info->phba;

	/*
	 * When the PLOGI request is sent, the microcode needs to be instructed
	 * to clear the I/O related to the link to avoid data inconsistency
	 * caused by the disorder of the IO.
	 */
	if (((cmnd == ELS_LOGO) || (cmnd == ELS_PLOGI)) && hba) {
		els_req->wd4.clr_io = 1;
		els_req->wd6.reset_exch_start = hba->exit_base;
		els_req->wd6.reset_exch_end = hba->exit_base +
						(hba->exit_count - 1);
		els_req->wd7.scqn = v_scqn;
		HIFC_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT, UNF_MAJOR,
			   "Port(0x%x) Rport(0x%x) SID(0x%x) send %s to DID(0x%x), notify clean io start 0x%x, end 0x%x, scqn 0x%x.",
			   hba->port_cfg.port_id, sq_info->rport_index,
			   sq_info->local_port_id,
			   (cmnd == ELS_PLOGI) ? "PLOGI" : "LOGO",
			   sq_info->remote_port_id,
			   els_req->wd6.reset_exch_start,
			   els_req->wd6.reset_exch_end,
			   v_scqn);

		return;
	}

	/* The chip updates the PLOGI ACC negotiation parameters. */
	if (cmnd == ELS_PRLI) {
		els_req->wd5.seq_cnt = sq_info->plogi_coparams.seq_cnt;
		els_req->wd5.e_d_tov = sq_info->plogi_coparams.ed_tov;
		els_req->wd5.tx_mfs = sq_info->plogi_coparams.tx_mfs;
		els_req->e_d_tov_timer_val =
				sq_info->plogi_coparams.ed_tov_timer_val;

		els_req->wd4.rec_support = hba->port_cfg.tape_support ? 1 : 0;
		els_req->wd4.para_update = 0x01;

		HIFC_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT, UNF_INFO,
			   "Port(0x%x) save rport index(0x%x) login parms,seqcnt:0x%x, e_d_tov:0x%x,txmfs:0x%x,e_d_tovtimerval:0x%x.",
			   sq_info->local_port_id, sq_info->rport_index,
			   els_req->wd5.seq_cnt, els_req->wd5.e_d_tov,
			   els_req->wd5.tx_mfs,
			   els_req->e_d_tov_timer_val);
	}

	if (cmnd == ELS_ECHO)
		els_req->echo_flag = UNF_TRUE;
	if (cmnd == ELS_REC) {
		rec_pld = (struct unf_rec_pld_s *)v_frame_pld;
		els_req->wd4.rec_flag = 1;
		rec_pld->ox_id += hba->exit_base;
		els_req->wd4.orign_oxid = rec_pld->ox_id;

		HIFC_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT, UNF_MAJOR,
			   "Port(0x%x) Rport(0x%x) SID(0x%x) send Rec to DID(0x%x), origin_oxid 0x%x",
			   hba->port_cfg.port_id, sq_info->rport_index,
			   sq_info->local_port_id,
			   sq_info->remote_port_id,
			   els_req->wd4.orign_oxid);
	}
}

void hifc_build_els_wqe_ts_magic_num(struct hifcoe_sqe_s *v_sqe,
				     unsigned short els_cmnd_type,
				     unsigned int v_magic_num)
{
	struct hifcoe_sqe_t_els_gs_s *els_req;
	struct hifcoe_sqe_els_rsp_s *els_rsp;

	if (els_cmnd_type == ELS_ACC || els_cmnd_type == ELS_RJT) {
		els_rsp = &v_sqe->ts_sl.cont.els_rsp;
		els_rsp->magic_num = v_magic_num;
	} else {
		els_req = &v_sqe->ts_sl.cont.t_els_gs;
		els_req->magic_num = v_magic_num;
	}
}

void hifc_build_gs_wqe_ts_req(struct hifcoe_sqe_s *v_sqe,
			      unsigned int magic_num)
{
	struct hifcoe_sqe_ts_s *v_sqe_ts = NULL;
	struct hifcoe_sqe_t_els_gs_s *gs_req = NULL;

	v_sqe_ts = &v_sqe->ts_sl;
	v_sqe_ts->task_type = HIFC_SQE_GS_CMND;

	gs_req = &v_sqe_ts->cont.t_els_gs;
	gs_req->magic_num = magic_num;
}

void hifc_build_bls_wqe_ts_req(struct hifcoe_sqe_s *v_sqe,
			       unsigned int abts_param,
			       unsigned int magic_num)
{
	struct hifcoe_sqe_abts_s *abts_ts;

	v_sqe->ts_sl.task_type = HIFC_SQE_BLS_CMND;
	abts_ts = &v_sqe->ts_sl.cont.abts;
	abts_ts->fh_parm_abts = abts_param;
	abts_ts->magic_num = magic_num;
}

void hifc_build_service_wqe_root_ts(void *v_hba,
				    struct hifc_root_sqe_s *v_rt_sqe,
				    unsigned int rx_id, unsigned int rport_id,
				    unsigned int scq_num)
{
	unsigned char data_cos = 0;
	unsigned int port_id = 0;
	unsigned int service_type = 0;
	struct hifc_hba_s *hba = NULL;
	struct hifc_parent_queue_info_s *parent_queue_info = NULL;

	hba = (struct hifc_hba_s *)v_hba;

	port_id = HIFC_GET_HBA_PORT_ID(hba);
	service_type = HIFC_GET_SERVICE_TYPE(hba);

	if (rport_id >= UNF_HIFC_MAXRPORT_NUM) {
		data_cos = HIFC_GET_PACKET_COS(service_type);
	} else {
		parent_queue_info =
			&hba->parent_queue_mgr->parent_queues[rport_id];
		data_cos = parent_queue_info->queue_data_cos;
	}

	v_rt_sqe->task_section.fc_dw0.exch_id = rx_id;
	v_rt_sqe->task_section.fc_dw0.host_id = 0;
	v_rt_sqe->task_section.fc_dw0.port_id = port_id;
	v_rt_sqe->task_section.fc_dw0.off_load = HIFC_NO_OFFLOAD;
	v_rt_sqe->task_section.fc_dw3.rport_index = HIFC_LSW(rport_id);
	v_rt_sqe->task_section.fc_dw3.scq_num = HIFC_LSW(scq_num);
	v_rt_sqe->task_section.fc_dw4.service_type = UNF_GET_SHIFTMASK(
							service_type, 0, 0x1f);
	v_rt_sqe->task_section.fc_dw4.pkt_type = HIFC_GET_PACKET_TYPE(
								service_type);
	v_rt_sqe->task_section.fc_dw4.pkt_cos = data_cos;
}

void hifc_build_service_wqe_root_sge(struct hifc_root_sqe_s *v_rt_sqe,
				     void *v_buf_addr,
				     unsigned long long v_phy_addr,
				     unsigned int buf_len,
				     void *v_hba)
{
	unsigned long long frame_phy_addr;

	/* Enter the SGE and convert it to the big-endian mode. */
	frame_phy_addr = v_phy_addr;
	v_rt_sqe->sge.buf_addr_hi = HIFC_HIGH_32_BITS(frame_phy_addr);
	v_rt_sqe->sge.buf_addr_lo = HIFC_LOW_32_BITS(frame_phy_addr);
	v_rt_sqe->sge.wd0.buf_len = buf_len;
	v_rt_sqe->sge.wd0.ext_flag = 0;
	v_rt_sqe->sge.wd1.rsvd = 0;
	hifc_cpu_to_big32(&v_rt_sqe->sge, sizeof(v_rt_sqe->sge));

	/* Converting FC Frames into big Ends */
	hifc_cpu_to_big32(v_buf_addr, buf_len);
}

void hifc_build_service_wqe_ctx_sge(struct hifc_root_sqe_s *v_rt_sqe,
				    unsigned long long v_ctxt_addr,
				    unsigned int buf_len)
{
	/* The SGE is filled in and converted to the big-endian mode. */
	v_rt_sqe->ctx_sge.buf_addr_hi = HIFC_HIGH_32_BITS(v_ctxt_addr);
	v_rt_sqe->ctx_sge.buf_addr_lo = HIFC_LOW_32_BITS(v_ctxt_addr);
	v_rt_sqe->ctx_sge.wd0.buf_len = buf_len;
	v_rt_sqe->ctx_sge.wd0.ext_flag = 0;
	v_rt_sqe->ctx_sge.wd1.rsvd = 0;

	hifc_cpu_to_big32(&v_rt_sqe->ctx_sge, sizeof(v_rt_sqe->ctx_sge));
}

void hifc_build_els_wqe_root_offload(struct hifc_root_sqe_s *v_rt_sqe,
				     dma_addr_t ctxt_addr,
				     unsigned int xid)
{
	/* update Task Section DW0.OFFLOAD */
	v_rt_sqe->task_section.fc_dw0.off_load = HIFC_HAVE_OFFLOAD;

	/* update Context GPA DW1~2 */
	v_rt_sqe->task_section.fc_dw1.context_gpa_hi =
						HIFC_HIGH_32_BITS(ctxt_addr);
	v_rt_sqe->task_section.fc_dw2.context_gpa_lo =
						HIFC_LOW_32_BITS(ctxt_addr);

	/* fill Context DW4 */
	v_rt_sqe->task_section.fc_dw4.parent_xid = xid;
	v_rt_sqe->task_section.fc_dw4.csize = HIFC_CNTX_SIZE_T_256B;

	/* The sqe of the offload request has two sge. The first is the packet,
	 * and the second is the ctx.
	 */
	v_rt_sqe->ctrl_section.ch.wd0.bdsl =
		2 * HIFC_BYTES_TO_QW_NUM(sizeof(struct hifc_root_sge_s));
}

void hifc_build_service_wqe_ctrl_section(struct hifcoe_wqe_ctrl_s *v_wqe_cs,
					 unsigned int ts_size,
					 unsigned int bdsi)
{
	v_wqe_cs->ch.wd0.bdsl = bdsi;
	v_wqe_cs->ch.wd0.drv_sl = 0;
	v_wqe_cs->ch.wd0.rsvd0 = 0;
	v_wqe_cs->ch.wd0.wf = 0;
	v_wqe_cs->ch.wd0.cf = 0;
	v_wqe_cs->ch.wd0.tsl = ts_size;
	v_wqe_cs->ch.wd0.va = 0;
	v_wqe_cs->ch.wd0.df = 0;
	v_wqe_cs->ch.wd0.cr = 1;
	v_wqe_cs->ch.wd0.dif_sl = 0;
	v_wqe_cs->ch.wd0.csl = 0;
	/* divided by 8 */
	v_wqe_cs->ch.wd0.ctrl_sl = HIFC_BYTES_TO_QW_NUM(sizeof(*v_wqe_cs));
	v_wqe_cs->ch.wd0.owner = 0;
}

void hifc_build_wqe_owner_pmsn(struct hifcoe_wqe_ctrl_s *v_wqe_cs,
			       unsigned short owner,
			       unsigned short pmsn)
{
	v_wqe_cs->qsf.wqe_sn = pmsn;
	v_wqe_cs->qsf.dump_wqe_sn = v_wqe_cs->qsf.wqe_sn;
	v_wqe_cs->ch.wd0.owner = (unsigned int)owner;
}

void hifc_convert_parent_wqe_to_big_endian(struct hifcoe_sqe_s *v_sqe)
{
	if (likely((v_sqe->ts_sl.task_type != HIFCOE_TASK_T_TRESP) &&
		   (v_sqe->ts_sl.task_type != HIFCOE_TASK_T_TMF_RESP))) {
		/*
		 * Convert Control Secton and Task Section to big-endian. Before
		 * the SGE enters the queue, the upper-layer driver converts the
		 * SGE and Task Section to the big-endian mode.
		 */
		hifc_cpu_to_big32(&v_sqe->ctrl_sl, sizeof(v_sqe->ctrl_sl));
		hifc_cpu_to_big32(&v_sqe->ts_sl, sizeof(v_sqe->ts_sl));
	} else {
		/*
		 * The HIFCOE_TASK_T_TRESP may use the SGE as the Task Section
		 * to convert the entire SQE into a large end.
		 */
		hifc_cpu_to_big32(v_sqe, sizeof(struct hifcoe_sqe_tresp_s));
	}
}

void hifc_convert_root_wqe_to_big_endian(struct hifc_root_sqe_s *v_sqe)
{
	hifc_cpu_to_big32(&v_sqe->ctrl_section, sizeof(v_sqe->ctrl_section));
	hifc_cpu_to_big32(&v_sqe->task_section, sizeof(v_sqe->task_section));
}

void hifc_build_cmdqe_common(union hifc_cmdqe_u *cmdqe,
			     enum hifcoe_task_type_e task_type,
			     unsigned short rx_id)
{
	cmdqe->common.wd0.task_type = task_type;
	cmdqe->common.wd0.rx_id = rx_id;
	cmdqe->common.wd0.rsvd0 = 0;
}

#define HIFC_STANDARD_SIRT_ENABLE  1
#define HIFC_STANDARD_SIRT_DISABLE 0
#define HIFC_UNKNOWN_ID            0xFFFF

void hifc_build_icmnd_wqe_ts_header(struct unf_frame_pkg_s *v_pkg,
				    struct hifcoe_sqe_s *v_sqe,
				    unsigned char task_type,
				    unsigned short exit_base,
				    unsigned char v_port_idx)
{
	v_sqe->ts_sl.local_xid = UNF_GET_OXID(v_pkg) + exit_base;
	v_sqe->ts_sl.task_type = task_type;
	v_sqe->ts_sl.wd0.conn_id =
		(unsigned short)(v_pkg->private[PKG_PRIVATE_XCHG_RPORT_INDEX]);

	v_sqe->ts_sl.wd0.remote_xid = HIFC_UNKNOWN_ID;
}

void hifc_build_icmnd_wqe_ts(void *v_hba, struct unf_frame_pkg_s *v_pkg,
			     struct hifcoe_sqe_ts_s *v_sqe_ts)
{
	struct hifcoe_sqe_icmnd_s *icmd = &v_sqe_ts->cont.icmnd;
	void *phy_add = NULL;
	struct hifc_hba_s *hba = NULL;

	hba = (struct hifc_hba_s *)v_hba;
	v_sqe_ts->cdb_type = 0;
	memcpy(icmd->fcp_cmnd_iu, v_pkg->fcp_cmnd,
	       sizeof(struct unf_fcp_cmnd_s));

	icmd->magic_num = UNF_GETXCHGALLOCTIME(v_pkg);

	if (v_pkg->unf_rsp_pload_bl.buffer_ptr) {
		phy_add = (void *)v_pkg->unf_rsp_pload_bl.buf_dma_addr;
		icmd->rsp_gpa_hi = HIFC_HIGH_32_BITS(phy_add);
		icmd->rsp_gpa_lo = HIFC_LOW_32_BITS(phy_add);
	} else {
		HIFC_TRACE(UNF_EVTLOG_IO_ERR, UNF_LOG_IO_ATT, UNF_ERR,
			   "[err]INI Build WQE sense buffer should not be null,sid_did (0x%x_0x%x) oxid(0x%x) pkg type(0x%x) hot pool tag(0x%x).",
			   v_pkg->frame_head.csctl_sid,
			   v_pkg->frame_head.rctl_did,
			   UNF_GET_OXID(v_pkg),
			   v_pkg->type, UNF_GET_XCHG_TAG(v_pkg));
	}

	if (v_sqe_ts->task_type != HIFC_SQE_FCP_ITMF) {
		icmd->info.tmf.w0.bs.reset_exch_start = hba->exit_base;
		icmd->info.tmf.w0.bs.reset_exch_end = hba->exit_base +
						      hba->exit_count - 1;

		icmd->info.tmf.w1.bs.reset_did = UNF_GET_DID(v_pkg);
		/* delivers the marker status flag to the microcode. */
		icmd->info.tmf.w1.bs.marker_sts = 1;
		HIFC_GET_RESET_TYPE(UNF_GET_TASK_MGMT_FLAGS(
				    v_pkg->fcp_cmnd->control),
				    icmd->info.tmf.w1.bs.reset_type);

		icmd->info.tmf.w2.bs.reset_sid = UNF_GET_SID(v_pkg);

		memcpy(icmd->info.tmf.reset_lun, v_pkg->fcp_cmnd->lun,
		       sizeof(icmd->info.tmf.reset_lun));
	}
}

void hifc_build_srq_wqe_ctrls(struct hifcoe_rqe_s *v_rqe,
			      unsigned short owner,
			      unsigned short pmsn)
{
	struct hifcoe_wqe_ctrl_ch_s *wqe_ctrls = NULL;

	wqe_ctrls = &v_rqe->ctrl_sl.ch;
	wqe_ctrls->wd0.owner = owner;
	wqe_ctrls->wd0.ctrl_sl = sizeof(struct hifcoe_wqe_ctrl_s) >> 3;
	wqe_ctrls->wd0.csl = 1;
	wqe_ctrls->wd0.dif_sl = 0;
	wqe_ctrls->wd0.cr = 1;
	wqe_ctrls->wd0.df = 0;
	wqe_ctrls->wd0.va = 0;
	wqe_ctrls->wd0.tsl = 0;
	wqe_ctrls->wd0.cf = 0;
	wqe_ctrls->wd0.wf = 0;
	wqe_ctrls->wd0.drv_sl = sizeof(struct hifcoe_rqe_drv_s) >> 3;
	wqe_ctrls->wd0.bdsl = sizeof(struct hifcoe_constant_sge_s) >> 3;

	v_rqe->ctrl_sl.wd0.wqe_msn = pmsn;
	v_rqe->ctrl_sl.wd0.dump_wqe_msn = v_rqe->ctrl_sl.wd0.wqe_msn;
}
