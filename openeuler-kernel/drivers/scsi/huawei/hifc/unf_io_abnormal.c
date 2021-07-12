// SPDX-License-Identifier: GPL-2.0
/* Huawei Hifc PCI Express Linux driver
 * Copyright(c) 2017 Huawei Technologies Co., Ltd
 *
 */

#include "unf_log.h"
#include "unf_exchg.h"
#include "unf_rport.h"
#include "unf_io.h"
#include "unf_portman.h"
#include "unf_service.h"
#include "unf_io_abnormal.h"

static int unf_send_abts_success(struct unf_lport_s *v_lport,
				 struct unf_xchg_s *v_xchg,
				 struct unf_scsi_cmd_s *v_scsi_cmnd,
				 unsigned int time_out_value)
{
	int wait_marker = UNF_TRUE;
	struct unf_rport_scsi_id_image_s *scsi_image_table = NULL;
	unsigned int scsi_id;
	unsigned int ret;
	unsigned long flag = 0;

	spin_lock_irqsave(&v_xchg->xchg_state_lock, flag);
	wait_marker = (v_xchg->abts_state & MARKER_STS_RECEIVED) ?
		      UNF_FALSE : UNF_TRUE;
	spin_unlock_irqrestore(&v_xchg->xchg_state_lock, flag);

	if (wait_marker) {
		if (down_timeout(
			&v_xchg->task_sema,
			(long long)msecs_to_jiffies(time_out_value))) {
			UNF_TRACE(UNF_EVTLOG_IO_WARN, UNF_LOG_IO_ATT,
				  UNF_WARN,
				  "[warn]Port(0x%x) recv abts marker timeout,Exch(0x%p) OX_ID(0x%x 0x%x) RX_ID(0x%x)",
				  v_lport->port_id, v_xchg,
				  v_xchg->ox_id, v_xchg->hot_pool_tag,
				  v_xchg->rx_id);

			/* Cancel abts rsp timer when sema timeout */
			v_lport->xchg_mgr_temp.pfn_unf_xchg_cancel_timer(
					(void *)v_xchg);

			/* Cnacel the flag of INI_IO_STATE_UPABORT and
			 * process the io in TMF
			 */
			spin_lock_irqsave(&v_xchg->xchg_state_lock, flag);
			v_xchg->io_state &= ~INI_IO_STATE_UPABORT;
			v_xchg->io_state |= INI_IO_STATE_TMF_ABORT;
			spin_unlock_irqrestore(&v_xchg->xchg_state_lock, flag);

			return UNF_SCSI_ABORT_FAIL;
		}
	} else {
		v_xchg->ucode_abts_state = UNF_IO_SUCCESS;
	}

	scsi_image_table = &v_lport->rport_scsi_table;
	scsi_id = v_scsi_cmnd->scsi_id;

	spin_lock_irqsave(&v_xchg->xchg_state_lock, flag);
	if ((v_xchg->ucode_abts_state == UNF_IO_SUCCESS) ||
	    (v_xchg->scsi_cmnd_info.result == UNF_IO_ABORT_PORT_REMOVING)) {
		spin_unlock_irqrestore(&v_xchg->xchg_state_lock, flag);

		UNF_TRACE(UNF_EVTLOG_IO_INFO, UNF_LOG_IO_ATT, UNF_MAJOR,
			  "[info]Port(0x%x) Send ABTS succeed and recv marker Exch(0x%p) OX_ID(0x%x) RX_ID(0x%x) marker status(0x%x)",
			  v_lport->port_id, v_xchg,
			  v_xchg->ox_id, v_xchg->rx_id,
			  v_xchg->ucode_abts_state);
		ret = DID_RESET;
		UNF_IO_RESULT_CNT(scsi_image_table, scsi_id, ret);
		unf_complete_cmnd(v_scsi_cmnd, DID_RESET << 16);
		return UNF_SCSI_ABORT_SUCCESS;
	}

	v_xchg->io_state &= ~INI_IO_STATE_UPABORT;
	v_xchg->io_state |= INI_IO_STATE_TMF_ABORT;
	spin_unlock_irqrestore(&v_xchg->xchg_state_lock, flag);

	/* Cancel abts rsp timer when sema timeout */
	v_lport->xchg_mgr_temp.pfn_unf_xchg_cancel_timer((void *)v_xchg);

	UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_REG_ATT, UNF_WARN,
		  "[warn]Port(0x%x) send ABTS failed. Exch(0x%p) oxid(0x%x) hot_tag(0x%x) ret(0x%x) v_xchg->io_state (0x%x)",
		  v_lport->port_id, v_xchg, v_xchg->ox_id,
		  v_xchg->hot_pool_tag,
		  v_xchg->scsi_cmnd_info.result, v_xchg->io_state);

	/* return fail and then enter TMF */
	return UNF_SCSI_ABORT_FAIL;
}

static int unf_ini_abort_cmnd(struct unf_lport_s *v_lport,
			      struct unf_xchg_s *v_xchg,
			      struct unf_scsi_cmd_s *v_scsi_cmnd)
{
	/*
	 * About INI_IO_STATE_UPABORT:
	 *
	 * 1. Check: AC power down
	 * 2. Check: L_Port destroy
	 * 3. Check: I/O XCHG timeout
	 * 4. Set ABORT: send ABTS
	 * 5. Set ABORT: LUN reset
	 * 6. Set ABORT: Target reset
	 * 7. Check: Prevent to send I/O to target (UNF_PreferToSendScsiCmnd)
	 * 8. Check: Done INI XCHG --->>> do not call scsi_done, return directly
	 * 9. Check: INI SCSI Complete --->>>
	 *    do not call scsi_done, return directly
	 */
#define UNF_RPORT_NOTREADY_WAIT_SEM_TIMEOUT (2000) /* 2s */

	struct unf_lport_s *lport = NULL;
	struct unf_rport_s *rport = NULL;
	unsigned long flag = 0;
	struct unf_rport_scsi_id_image_s *scsi_image_table = NULL;
	unsigned int scsi_id;
	unsigned int ret;

	unsigned int time_out_value = (unsigned int)UNF_WAIT_SEM_TIMEOUT;

	UNF_CHECK_VALID(0x1335, TRUE, v_lport, return UNF_SCSI_ABORT_FAIL);
	lport = v_lport;

	/* 1. Xchg State Set: INI_IO_STATE_UPABORT */
	spin_lock_irqsave(&v_xchg->xchg_state_lock, flag);
	v_xchg->io_state |= INI_IO_STATE_UPABORT;
	rport = v_xchg->rport;
	spin_unlock_irqrestore(&v_xchg->xchg_state_lock, flag);

	/* 2. R_Port check */
	if (unlikely(!rport)) {
		UNF_TRACE(UNF_EVTLOG_IO_WARN, UNF_LOG_IO_ATT, UNF_WARN,
			  "[warn]Port(0x%x) send ABTS but no RPort, OX_ID(0x%x) RX_ID(0x%x)",
			  lport->port_id, v_xchg->ox_id, v_xchg->rx_id);

		return UNF_SCSI_ABORT_SUCCESS;
	}

	spin_lock_irqsave(&rport->rport_state_lock, flag);
	if (unlikely(rport->rp_state != UNF_RPORT_ST_READY)) {
		UNF_TRACE(UNF_EVTLOG_IO_WARN, UNF_LOG_IO_ATT,
			  UNF_WARN,
			  "[warn]Port(0x%x) find RPort's state(0x%x) is not ready but send ABTS also, exchange(0x%p) tag(0x%x)",
			  lport->port_id, rport->rp_state,
			  v_xchg, v_xchg->hot_pool_tag);

		/*
		 * Important: Send ABTS also & update timer
		 * Purpose: only used for release chip (uCode) resource,
		 * continue
		 */
		time_out_value = UNF_RPORT_NOTREADY_WAIT_SEM_TIMEOUT;
	}
	spin_unlock_irqrestore(&rport->rport_state_lock, flag);

	/* 3. L_Port State check */
	if (unlikely(lport->b_port_removing == UNF_TRUE)) {
		UNF_TRACE(UNF_EVTLOG_IO_WARN, UNF_LOG_IO_ATT, UNF_WARN,
			  "[warn]Port(0x%x) is removing", lport->port_id);

		v_xchg->io_state &= ~INI_IO_STATE_UPABORT;

		return UNF_SCSI_ABORT_FAIL;
	}

	scsi_image_table = &lport->rport_scsi_table;
	scsi_id = v_scsi_cmnd->scsi_id;

	/* If pcie linkdown, complete this io and flush all io */
	if (unlikely(lport->b_pcie_linkdown == UNF_TRUE)) {
		ret = DID_RESET;
		UNF_IO_RESULT_CNT(scsi_image_table, scsi_id, ret);
		unf_complete_cmnd(v_scsi_cmnd, DID_RESET << 16);
		unf_free_lport_all_xchg(v_lport);
		return UNF_SCSI_ABORT_SUCCESS;
	}

	UNF_TRACE(UNF_EVTLOG_IO_INFO, UNF_LOG_IO_ATT, UNF_KEVENT,
		  "[abort]Port(0x%x) Exchg(0x%p) delay(%llu) SID(0x%x) DID(0x%x) wwpn(0x%llx) OxID(0x%x 0x%x) scsi_id(0x%x) lun_id(0x%x) cmdsn(0x%llx)",
		  lport->port_id, v_xchg,
		  (unsigned long long)jiffies_to_msecs(jiffies) -
		  (unsigned long long)jiffies_to_msecs(v_xchg->alloc_jif),
		  v_xchg->sid, v_xchg->did, rport->port_name,
		  v_xchg->ox_id, v_xchg->hot_pool_tag, v_scsi_cmnd->scsi_id,
		  (unsigned int)v_scsi_cmnd->lun_id, v_scsi_cmnd->cmnd_sn);

	/* Init abts marker semaphore */
	sema_init(&v_xchg->task_sema, 0);

	if (v_xchg->scsi_cmnd_info.time_out != 0)
		lport->xchg_mgr_temp.pfn_unf_xchg_cancel_timer(v_xchg);

	/* Add timer for sending ABTS */
	v_lport->xchg_mgr_temp.pfn_unf_xchg_add_timer(
			(void *)v_xchg,
			(unsigned long)UNF_WAIT_ABTS_RSP_TIMEOUT,
			UNF_TIMER_TYPE_INI_ABTS);

	/* 4. Send INI ABTS CMND */
	if (unf_send_abts(lport, v_xchg) != RETURN_OK) {
		UNF_TRACE(UNF_EVTLOG_IO_WARN, UNF_LOG_IO_ATT, UNF_WARN,
			  "[warn]Port(0x%x) Send ABTS failed. Exch(0x%p) OX_ID(0x%x 0x%x) RX_ID(0x%x)",
			  lport->port_id, v_xchg,
			  v_xchg->ox_id, v_xchg->hot_pool_tag,
			  v_xchg->rx_id);

		/* Cancel timer when sending ABTS failed */
		v_lport->xchg_mgr_temp.pfn_unf_xchg_cancel_timer(
							(void *)v_xchg);

		/* Cnacel the flag of INI_IO_STATE_UPABORT
		 * and process the io in TMF
		 */
		spin_lock_irqsave(&v_xchg->xchg_state_lock, flag);
		v_xchg->io_state &= ~INI_IO_STATE_UPABORT;
		v_xchg->io_state |= INI_IO_STATE_TMF_ABORT;
		spin_unlock_irqrestore(&v_xchg->xchg_state_lock, flag);

		return UNF_SCSI_ABORT_FAIL;
	}

	return unf_send_abts_success(lport, v_xchg, v_scsi_cmnd,
				     time_out_value);
}

static void unf_flush_ini_resp_que(struct unf_lport_s *v_lport)
{
	UNF_CHECK_VALID(0x1335, TRUE, v_lport, return);

	if (v_lport->low_level_func.service_op.pfn_unf_flush_ini_resp_que)
		(void)v_lport->low_level_func.service_op.pfn_unf_flush_ini_resp_que(v_lport->fc_port);
}

int unf_cm_eh_abort_handler(struct unf_scsi_cmd_s *v_scsi_cmnd)
{
	/*
	 * SCSI ABORT Command --->>> FC ABTS Command
	 * If return ABORT_FAIL then enter TMF process
	 */
	struct unf_lport_s *lport = NULL;
	struct unf_xchg_s *xchg = NULL;
	struct unf_rport_s *rport = NULL;
	struct unf_lport_s *xchg_lport = NULL;
	int ret;
	unsigned long flag = 0;

	/* 1. Get L_Port: Point to Scsi_host */
	lport = unf_find_lport_by_scsi_cmd(v_scsi_cmnd);
	if (!lport) {
		UNF_TRACE(UNF_EVTLOG_IO_WARN, UNF_LOG_IO_ATT, UNF_WARN,
			  "[warn]Can't find port by scsi host id(0x%x)",
			  UNF_GET_SCSI_HOST_ID_BY_CMND(v_scsi_cmnd));
		return UNF_SCSI_ABORT_FAIL;
	}

	/* 2. find target Xchg for INI Abort CMND */
	xchg = unf_cm_lookup_xchg_by_cmnd_sn(lport, v_scsi_cmnd->cmnd_sn,
					     v_scsi_cmnd->world_id);
	if (unlikely(!xchg)) {
		UNF_TRACE(UNF_EVTLOG_IO_WARN, UNF_LOG_ABNORMAL,
			  UNF_WARN,
			  "[warn]Port(0x%x) can't find exchange by Cmdsn(0x%lx)",
			  lport->port_id,
			  (unsigned long)v_scsi_cmnd->cmnd_sn);

		unf_flush_ini_resp_que(lport);

		return UNF_SCSI_ABORT_SUCCESS;
	}

	/* 3. increase ref_cnt to protect exchange */
	ret = (int)unf_xchg_ref_inc(xchg, INI_EH_ABORT);
	if (unlikely(ret != RETURN_OK)) {
		unf_flush_ini_resp_que(lport);
		return UNF_SCSI_ABORT_SUCCESS;
	}

	v_scsi_cmnd->upper_cmnd = xchg->scsi_cmnd_info.scsi_cmnd;

	xchg->debug_hook = UNF_TRUE;

	/* 4. Exchang L_Port/R_Port Get & check */
	spin_lock_irqsave(&xchg->xchg_state_lock, flag);
	xchg_lport = xchg->lport;
	rport = xchg->rport;
	spin_unlock_irqrestore(&xchg->xchg_state_lock, flag);

	if (unlikely(!xchg_lport || !rport)) {
		UNF_TRACE(UNF_EVTLOG_IO_WARN, UNF_LOG_IO_ATT, UNF_WARN,
			  "[warn]Exchange(0x%p)'s L_Port or R_Port is NULL, state(0x%x)",
			  xchg, xchg->io_state);

		unf_xchg_ref_dec(xchg, INI_EH_ABORT);

		if (!xchg_lport)
			return UNF_SCSI_ABORT_FAIL; /* for L_Port */
		return UNF_SCSI_ABORT_SUCCESS; /* for R_Port */
	}

	/* 5. Send INI Abort Cmnd */
	ret = unf_ini_abort_cmnd(xchg_lport, xchg, v_scsi_cmnd);

	/* 6. decrease exchange ref_cnt */
	unf_xchg_ref_dec(xchg, INI_EH_ABORT);

	return ret;
}

static unsigned int unf_tmf_timeout_recovery_default(void *v_rport,
						     void *v_xchg)
{
	struct unf_lport_s *lport = NULL;
	unsigned long flag = 0;
	struct unf_xchg_s *xchg = (struct unf_xchg_s *)v_xchg;
	struct unf_rport_s *rport = (struct unf_rport_s *)v_rport;

	lport = xchg->lport;
	UNF_CHECK_VALID(0x4614, UNF_TRUE, lport, return UNF_RETURN_ERROR);

	spin_lock_irqsave(&rport->rport_state_lock, flag);
	unf_rport_state_ma(rport, UNF_EVENT_RPORT_LOGO);
	spin_unlock_irqrestore(&rport->rport_state_lock, flag);

	unf_rport_enter_logo(lport, rport);
	return RETURN_OK;
}

void unf_abts_timeout_recovery_default(void *v_rport, void *v_xchg)
{
	struct unf_lport_s *lport = NULL;
	unsigned long flag = 0;
	struct unf_xchg_s *xchg = (struct unf_xchg_s *)v_xchg;
	struct unf_rport_s *rport = (struct unf_rport_s *)v_rport;

	lport = xchg->lport;
	UNF_CHECK_VALID(0x4614, UNF_TRUE, lport, return);

	spin_lock_irqsave(&xchg->xchg_state_lock, flag);
	if (INI_IO_STATE_DONE & xchg->io_state) {
		spin_unlock_irqrestore(&xchg->xchg_state_lock, flag);

		return;
	}
	spin_unlock_irqrestore(&xchg->xchg_state_lock, flag);
	if (xchg->rport_bind_jifs != rport->rport_alloc_jifs)
		return;

	spin_lock_irqsave(&rport->rport_state_lock, flag);
	unf_rport_state_ma(rport, UNF_EVENT_RPORT_LOGO);
	spin_unlock_irqrestore(&rport->rport_state_lock, flag);

	unf_rport_enter_logo(lport, rport);
}

unsigned int unf_tmf_timeout_recovery_special(void *v_rport, void *v_xchg)
{
	/* Do port reset or R_Port LOGO */
	int ret = UNF_RETURN_ERROR;
	struct unf_lport_s *lport = NULL;
	struct unf_xchg_s *xchg = (struct unf_xchg_s *)v_xchg;
	struct unf_rport_s *rport = (struct unf_rport_s *)v_rport;

	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE, v_rport,
			return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE, v_xchg,
			return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE, xchg->lport,
			return UNF_RETURN_ERROR);

	lport = xchg->lport->root_lport;
	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE, lport,
			return UNF_RETURN_ERROR);

	/* 1. TMF response timeout & Marker STS timeout */
	if (!(xchg->tmf_state &
	     (MARKER_STS_RECEIVED | TMF_RESPONSE_RECEIVED))) {
		/* TMF timeout & marker timeout */
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT, UNF_WARN,
			  "[warn]Port(0x%x) receive marker status timeout and do recovery",
			  lport->port_id);

		/* Do port reset */
		ret = unf_cm_reset_port(lport->port_id);
		if (ret != RETURN_OK) {
			UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT,
				  UNF_WARN,
				  "[warn]Port(0x%x) do reset failed",
				  lport->port_id);

			return UNF_RETURN_ERROR;
		}

		return RETURN_OK;
	}

	/* 2. default case: Do LOGO process */
	unf_tmf_timeout_recovery_default(rport, xchg);

	return RETURN_OK;
}

void unf_tmf_abnormal_recovery(struct unf_lport_s *v_lport,
			       struct unf_rport_s *v_rport,
			       struct unf_xchg_s *v_xchg)
{
	/*
	 * for device(lun)/target(session) reset:
	 * Do port reset or R_Port LOGO
	 */
	if (v_lport->pfn_unf_tmf_abnormal_recovery)
		v_lport->pfn_unf_tmf_abnormal_recovery((void *)v_rport,
						    (void *)v_xchg);
}

static void unf_build_task_mgmt_fcp_cmnd(struct unf_fcp_cmnd_s *v_fcp_cmnd,
					 struct unf_scsi_cmd_s *v_scsi_cmnd,
					 enum unf_task_mgmt_cmnd_e v_task_mgmt)
{
	UNF_CHECK_VALID(0x1339, UNF_TRUE, v_fcp_cmnd, return);
	UNF_CHECK_VALID(0x1340, UNF_TRUE, v_scsi_cmnd, return);

	unf_big_end_to_cpu((void *)v_scsi_cmnd->pc_lun_id, UNF_FCP_LUNID_LEN_8);
	(*(unsigned long long *)(v_scsi_cmnd->pc_lun_id)) >>= 8;
	memcpy(v_fcp_cmnd->lun, v_scsi_cmnd->pc_lun_id,
	       sizeof(v_fcp_cmnd->lun));

	/*
	 * If the TASK MANAGEMENT FLAGS field is set to a nonzero value,
	 * the FCP_CDB field, the FCP_DL field, the TASK ATTRIBUTE field,
	 * the RDDATA bit, and the WRDATA bit shall be ignored and the
	 * FCP_BIDIRECTIONAL_READ_DL field shall not be
	 * included in the FCP_CMND IU payload
	 */
	v_fcp_cmnd->control = UNF_SET_TASK_MGMT_FLAGS(v_task_mgmt);

	UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_REG_ATT, UNF_MAJOR,
		  "SCSI cmnd(0x%x) is task mgmt cmnd. ntrl Flag(LITTLE END) is 0x%x.",
		  v_task_mgmt, v_fcp_cmnd->control);
}

int unf_send_scsi_mgmt_cmnd(struct unf_xchg_s *v_xchg,
			    struct unf_lport_s *v_lport,
			    struct unf_rport_s *v_rport,
			    struct unf_scsi_cmd_s *v_scsi_cmnd,
			    enum unf_task_mgmt_cmnd_e v_task_mgnt_cmd_type)
{
	/*
	 * 1. Device/LUN reset
	 * 2. Target/Session reset
	 */
	struct unf_xchg_s *xchg = NULL;
	int ret = SUCCESS;
	struct unf_frame_pkg_s pkg = { 0 };
	unsigned long flag = 0;

	UNF_CHECK_VALID(0x1341, UNF_TRUE, v_xchg, return FAILED);
	UNF_CHECK_VALID(0x1342, UNF_TRUE, v_lport, return FAILED);
	UNF_CHECK_VALID(0x1343, UNF_TRUE, v_rport, return FAILED);
	UNF_CHECK_VALID(0x1344, UNF_TRUE, v_scsi_cmnd, return FAILED);
	UNF_CHECK_VALID(0x1345, UNF_TRUE,
			((v_task_mgnt_cmd_type <= UNF_FCP_TM_TERMINATE_TASK) &&
			(v_task_mgnt_cmd_type >= UNF_FCP_TM_QUERY_TASK_SET)),
			return FAILED);

	xchg = v_xchg;
	xchg->lport = v_lport;
	xchg->rport = v_rport;

	/* 1. State: Up_Task */
	spin_lock_irqsave(&xchg->xchg_state_lock, flag);
	xchg->io_state |= INI_IO_STATE_UPTASK;
	spin_unlock_irqrestore(&xchg->xchg_state_lock, flag);

	if (v_lport->low_level_func.xchg_mgr_type ==
	    UNF_LOW_LEVEL_MGR_TYPE_PASSTIVE) {
		xchg->ox_id = xchg->hot_pool_tag;
		pkg.frame_head.oxid_rxid =
			((unsigned int)xchg->ox_id << 16) | xchg->rx_id;
	}

	/* 2. Set TASK MANAGEMENT FLAGS of FCP_CMND to
	 * the corresponding task management command
	 */
	unf_build_task_mgmt_fcp_cmnd(&xchg->fcp_cmnd, v_scsi_cmnd,
				     v_task_mgnt_cmd_type);

	pkg.xchg_contex = xchg;
	pkg.private[PKG_PRIVATE_XCHG_RPORT_INDEX] = v_rport->rport_index;
	pkg.fcp_cmnd = &xchg->fcp_cmnd;
	pkg.private[PKG_PRIVATE_XCHG_HOT_POOL_INDEX] = xchg->hot_pool_tag;
	pkg.frame_head.csctl_sid = v_lport->nport_id;
	pkg.frame_head.rctl_did = v_rport->nport_id;
	pkg.unf_rsp_pload_bl.buffer_ptr =
		(unsigned char *)xchg->fcp_sfs_union.fcp_rsp_entry.fcp_rsp_iu;
	pkg.unf_rsp_pload_bl.buf_dma_addr =
		v_xchg->fcp_sfs_union.fcp_rsp_entry.fcp_rsp_iu_phy_addr;
	pkg.unf_rsp_pload_bl.length = PAGE_SIZE;
	pkg.private[PKG_PRIVATE_XCHG_ALLOC_TIME] =
		v_xchg->private[PKG_PRIVATE_XCHG_ALLOC_TIME];

	if (unlikely(v_lport->b_pcie_linkdown == UNF_TRUE)) {
		unf_free_lport_all_xchg(v_lport);
		return SUCCESS;
	}

	UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_REG_ATT, UNF_KEVENT,
		  "[event]Port(0x%x) send task_cmnd(0x%x) to RPort(0x%x) Hottag(0x%x) lunid(0x%llx)",
		  v_lport->port_id, v_task_mgnt_cmd_type,
		  v_rport->nport_id, xchg->hot_pool_tag,
		  *((unsigned long long *)v_scsi_cmnd->pc_lun_id));

	/* 3. Init exchange task semaphore */
	sema_init(&xchg->task_sema, 0);

	/* 4. Send Mgmt Task to low-level */
	if (unf_hardware_start_io(v_lport, &pkg) != RETURN_OK) {
		UNF_TRACE(UNF_EVTLOG_IO_WARN, UNF_LOG_IO_ATT, UNF_WARN,
			  "[warn]Port(0x%x) send task_cmnd(0x%x) to RPort(0x%x) failed",
			  v_lport->port_id, v_task_mgnt_cmd_type,
			  v_rport->nport_id);

		return FAILED;
	}

	/*
	 * semaphore timeout
	 *
	 * Code review: The second input parameter needs to
	 * be converted to jiffies.
	 * set semaphore after the message is sent successfully.
	 * The semaphore is returned when the semaphore times out
	 * or is woken up.
	 *
	 * 5. The semaphore is cleared and counted when the Mgmt
	 *    Task message is sent,
	 *    and is Wake Up when the RSP message is received.
	 *    If the semaphore is not Wake Up, the semaphore is
	 *    triggered after timeout.
	 *    That is, no RSP message is received within the timeout period.
	 */
	if (down_timeout(&xchg->task_sema,
			 (long long)msecs_to_jiffies((unsigned int)UNF_WAIT_SEM_TIMEOUT))) {
		UNF_TRACE(UNF_EVTLOG_IO_WARN, UNF_LOG_IO_ATT, UNF_WARN,
			  "[warn]Port(0x%x) send task_cmnd(0x%x) to RPort(0x%x) timeout scsi id(0x%x) lun id(0x%x)",
			  v_lport->nport_id, v_task_mgnt_cmd_type,
			  v_rport->nport_id,
			  v_scsi_cmnd->scsi_id,
			  (unsigned int)v_scsi_cmnd->lun_id);

		/* semaphore timeout */
		ret = FAILED;
		spin_lock_irqsave(&v_lport->lport_state_lock, flag);
		if (v_lport->en_states == UNF_LPORT_ST_RESET)
			ret = SUCCESS;

		spin_unlock_irqrestore(&v_lport->lport_state_lock, flag);
		return ret;
	}

	/*
	 * 6. NOTE: no timeout (has been waken up)
	 * Do Scsi_Cmnd(Mgmt Task) result checking
	 *
	 * FAILED: with error code or RSP is error
	 * SUCCESS: others
	 */
	if (xchg->scsi_cmnd_info.result == UNF_IO_SUCCESS) {
		UNF_TRACE(UNF_EVTLOG_IO_INFO, UNF_LOG_IO_ATT, UNF_MAJOR,
			  "[info]Port(0x%x) send task_cmnd(0x%x) to RPort(0x%x) and receive rsp succeed",
			  v_lport->nport_id, v_task_mgnt_cmd_type,
			  v_rport->nport_id);

		ret = SUCCESS;
	} else {
		UNF_TRACE(UNF_EVTLOG_IO_WARN, UNF_LOG_IO_ATT, UNF_WARN,
			  "[warn]Port(0x%x) send task_cmnd(0x%x) to RPort(0x%x) and receive rsp failed scsi id(0x%x) lun id(0x%x)",
			  v_lport->nport_id, v_task_mgnt_cmd_type,
			  v_rport->nport_id,
			  v_scsi_cmnd->scsi_id,
			  (unsigned int)v_scsi_cmnd->lun_id);

		ret = FAILED;
	}

	return ret;
}

int unf_cm_eh_device_reset_handler(struct unf_scsi_cmd_s *v_scsi_cmnd)
{
	/* SCSI Device/LUN Reset Command --->>> FC LUN/Device Reset Command */
	struct unf_lport_s *lport = NULL;
	struct unf_rport_s *rport = NULL;
	struct unf_xchg_s *xchg = NULL;
	unsigned int cmnd_result = 0;
	int ret = SUCCESS;

	UNF_CHECK_VALID(0x1349, UNF_TRUE, v_scsi_cmnd, return FAILED);
	UNF_CHECK_VALID(0x1350, UNF_TRUE, v_scsi_cmnd->pc_lun_id,
			return FAILED);

	UNF_TRACE(UNF_EVTLOG_IO_INFO, UNF_LOG_IO_ATT, UNF_MAJOR,
		  "[event]Enter device/LUN reset handler");

	/* 1. Get L_Port */
	lport = unf_find_lport_by_scsi_cmd(v_scsi_cmnd);
	if (!lport) {
		UNF_TRACE(UNF_EVTLOG_IO_WARN, UNF_LOG_IO_ATT, UNF_WARN,
			  "[warn]Can't find port by scsi_host_id(0x%x)",
			  UNF_GET_SCSI_HOST_ID_BY_CMND(v_scsi_cmnd));

		return FAILED;
	}

	/* 2. L_Port State checking */
	if (unlikely(lport->b_port_removing == UNF_TRUE)) {
		UNF_TRACE(UNF_EVTLOG_IO_WARN, UNF_LOG_IO_ATT, UNF_WARN,
			  "[warn]Port(0x%p) is removing", lport);

		return FAILED;
	}

	/*
	 * 3. Get R_Port: no rport is found or rport is not ready,return ok
	 * from: L_Port -->> rport_scsi_table (image table)
	 * -->> rport_info_table
	 */
	rport = unf_find_rport_by_scsi_id(lport,
					  v_scsi_cmnd->err_code_table,
					  v_scsi_cmnd->err_code_table_cout,
					  UNF_GET_SCSI_ID_BY_CMND(v_scsi_cmnd),
					  &cmnd_result);
	if (unlikely(!rport)) {
		UNF_TRACE(UNF_EVTLOG_IO_WARN, UNF_LOG_IO_ATT, UNF_WARN,
			  "[warn]Port(0x%x) Can't find rport by scsi_id(0x%x)",
			  lport->port_id,
			  UNF_GET_SCSI_ID_BY_CMND(v_scsi_cmnd));

		return SUCCESS;
	}

	/*
	 * 4. Set the I/O of the corresponding LUN to abort.
	 *
	 * LUN Reset: set UP_ABORT tag, with:
	 * INI_Busy_list, IO_Wait_list,
	 * IO_Delay_list, IO_Delay_transfer_list
	 */
	unf_cm_xchg_abort_by_lun(
			lport, rport,
			*((unsigned long long *)v_scsi_cmnd->pc_lun_id),
			NULL, UNF_FALSE);

	/* 5. R_Port state check */
	if (unlikely(rport->rp_state != UNF_RPORT_ST_READY)) {
		UNF_TRACE(UNF_EVTLOG_IO_WARN, UNF_LOG_IO_ATT, UNF_WARN,
			  "[warn]Port(0x%x) RPort(0x%x) state(0x%x) SCSI Command(0x%p), rport is not ready",
			  lport->port_id, rport->nport_id,
			  rport->rp_state, v_scsi_cmnd);

		return SUCCESS;
	}

	/* 6. Get & inc ref_cnt free Xchg for Device reset */
	xchg = (struct unf_xchg_s *)unf_cm_get_free_xchg(lport,
							 UNF_XCHG_TYPE_INI);
	if (unlikely(!xchg)) {
		UNF_TRACE(UNF_EVTLOG_IO_WARN, UNF_LOG_IO_ATT, UNF_WARN,
			  "[warn]Port(0x%p) can't get free exchange", lport);

		return FAILED;
	}

	/* increase ref_cnt for protecting exchange */
	ret = (int)unf_xchg_ref_inc(xchg, INI_EH_DEVICE_RESET);
	UNF_CHECK_VALID(0x1351, UNF_TRUE, (ret == RETURN_OK), return FAILED);

	/* 7. Send Device/LUN Reset to Low level */
	ret = unf_send_scsi_mgmt_cmnd(xchg, lport, rport,
				      v_scsi_cmnd,
				      UNF_FCP_TM_LOGICAL_UNIT_RESET);
	if (unlikely(ret == FAILED)) {
		/*
		 * Do port reset or R_Port LOGO:
		 * 1. FAILED: send failed
		 * 2. FAILED: semaphore timeout
		 * 3. SUCCESS: rcvd rsp & semaphore has been waken up
		 */
		unf_tmf_abnormal_recovery(lport, rport, xchg);
	}

	/*
	 * 8. Release resource immediately if necessary
	 * NOTE: here, semaphore timeout or rcvd rsp
	 * (semaphore has been waken up)
	 */
	if (likely((lport->b_port_removing != UNF_TRUE) ||
		   (lport->root_lport != lport)))
		unf_cm_free_xchg(xchg->lport, xchg);

	/* decrease ref_cnt */
	unf_xchg_ref_dec(xchg, INI_EH_DEVICE_RESET);

	return SUCCESS;
}

int unf_cm_target_reset_handler(struct unf_scsi_cmd_s *v_scsi_cmnd)
{
	/* SCSI Target Reset Command --->>> FC Session Reset/Delete Command */
	struct unf_lport_s *lport = NULL;
	struct unf_rport_s *rport = NULL;
	struct unf_xchg_s *xchg = NULL;
	unsigned int cmnd_result = 0;
	int ret;

	UNF_CHECK_VALID(0x1355, UNF_TRUE, v_scsi_cmnd, return FAILED);
	UNF_CHECK_VALID(0x1356, UNF_TRUE, v_scsi_cmnd->pc_lun_id,
			return FAILED);

	/* 1. Get L_Port */
	lport = unf_find_lport_by_scsi_cmd(v_scsi_cmnd);
	if (!lport) {
		UNF_TRACE(UNF_EVTLOG_IO_WARN, UNF_LOG_IO_ATT, UNF_WARN,
			  "[warn]Can't find port by scsi_host_id(0x%x)",
			  UNF_GET_SCSI_HOST_ID_BY_CMND(v_scsi_cmnd));

		return FAILED;
	}

	/* 2. L_Port State check */
	if (unlikely(lport->b_port_removing == UNF_TRUE)) {
		UNF_TRACE(UNF_EVTLOG_IO_WARN, UNF_LOG_IO_ATT, UNF_WARN,
			  "[warn]Port(0x%p) is removing", lport);

		return FAILED;
	}

	/*
	 * 3. Get R_Port: no rport is found or rport is not ready,return ok
	 * from: L_Port -->> rport_scsi_table (image table) -->>
	 * rport_info_table
	 */
	rport = unf_find_rport_by_scsi_id(lport,
					  v_scsi_cmnd->err_code_table,
					  v_scsi_cmnd->err_code_table_cout,
					  UNF_GET_SCSI_ID_BY_CMND(v_scsi_cmnd),
					  &cmnd_result);
	if (unlikely(!rport)) {
		UNF_TRACE(UNF_EVTLOG_IO_WARN, UNF_LOG_IO_ATT, UNF_WARN,
			  "[warn]Can't find rport by scsi_id(0x%x)",
			  UNF_GET_SCSI_ID_BY_CMND(v_scsi_cmnd));

		return SUCCESS;
	}

	/*
	 * 4. set UP_ABORT on Target IO and Session IO
	 *
	 * LUN Reset: set UP_ABORT tag, with:
	 * INI_Busy_list, IO_Wait_list,
	 * IO_Delay_list, IO_Delay_transfer_list
	 */
	unf_cm_xchg_abort_by_session(lport, rport);

	/* 5. R_Port state check */
	if (unlikely(rport->rp_state != UNF_RPORT_ST_READY)) {
		UNF_TRACE(UNF_EVTLOG_IO_WARN, UNF_LOG_IO_ATT, UNF_WARN,
			  "[warn]Port(0x%x) RPort(0x%x) state(0x%x) is not ready, SCSI Command(0x%p)",
			  lport->port_id, rport->nport_id,
			  rport->rp_state, v_scsi_cmnd);

		return SUCCESS;
	}

	/* 6. Get free Xchg for Target Reset CMND */
	xchg = (struct unf_xchg_s *)unf_cm_get_free_xchg(lport,
							 UNF_XCHG_TYPE_INI);
	if (unlikely(!xchg)) {
		UNF_TRACE(UNF_EVTLOG_IO_WARN, UNF_LOG_IO_ATT, UNF_WARN,
			  "[warn]Port(0x%p) can't get free exchange", lport);

		return FAILED;
	}

	/* increase ref_cnt to protect exchange */
	ret = (int)unf_xchg_ref_inc(xchg, INI_EH_DEVICE_RESET);
	UNF_CHECK_VALID(0x1357, UNF_TRUE, (ret == RETURN_OK), return FAILED);

	/* 7. Send Target Reset Cmnd to low-level */
	ret = unf_send_scsi_mgmt_cmnd(xchg, lport, rport, v_scsi_cmnd,
				      UNF_FCP_TM_TARGET_RESET);
	if (unlikely(ret == FAILED)) {
		/*
		 * Do port reset or R_Port LOGO:
		 * 1. FAILED: send failed
		 * 2. FAILED: semaphore timeout
		 * 3. SUCCESS: rcvd rsp & semaphore has been waken up
		 */
		unf_tmf_abnormal_recovery(lport, rport, xchg);
	}

	/*
	 * 8. Release resource immediately if necessary
	 * NOTE: here, semaphore timeout or rcvd rsp
	 * (semaphore has been waken up)
	 */
	if (likely((lport->b_port_removing != UNF_TRUE) ||
		   (lport->root_lport != lport)))
		unf_cm_free_xchg(xchg->lport, xchg);

	/* decrease exchange ref_cnt */
	unf_xchg_ref_dec(xchg, INI_EH_DEVICE_RESET);

	return SUCCESS;
}

int unf_cm_bus_reset_handler(struct unf_scsi_cmd_s *v_scsi_cmnd)
{
	/* SCSI BUS Reset Command --->>> FC Port Reset Command */
	struct unf_lport_s *lport = NULL;
	int cmnd_result = 0;

	/* 1. Get L_Port */
	lport = unf_find_lport_by_scsi_cmd(v_scsi_cmnd);
	if (!lport) {
		UNF_TRACE(UNF_EVTLOG_IO_WARN, UNF_LOG_IO_ATT, UNF_WARN,
			  "[warn]Can't find port by scsi_host_id(0x%x)",
			  UNF_GET_SCSI_HOST_ID_BY_CMND(v_scsi_cmnd));

		return FAILED;
	}

	UNF_TRACE(UNF_EVTLOG_IO_INFO, UNF_LOG_IO_ATT, UNF_KEVENT,
		  "[event]Do port reset with scsi_bus_reset");

	cmnd_result = unf_cm_reset_port(lport->port_id);
	if (unlikely(cmnd_result == UNF_RETURN_ERROR))
		return FAILED;
	else
		return SUCCESS;
}

void unf_process_scsi_mgmt_result(struct unf_frame_pkg_s *v_pkg,
				  struct unf_xchg_s *v_xchg)
{
	unsigned char *rsp_info = NULL;
	unsigned char rsp_code = 0;
	unsigned int code_index = 0;

	/*
	 * LLT found that:RSP_CODE is the third byte of FCP_RSP_INFO,
	 * on Little endian should be byte 0, For detail FCP_4 Table 26
	 * FCP_RSP_INFO field format
	 *
	 * 1. state setting
	 * 2. wake up semaphore
	 */
	UNF_CHECK_VALID(0x1321, TRUE, v_pkg, return);
	UNF_CHECK_VALID(0x1322, TRUE, v_xchg, return);

	v_xchg->tmf_state |= TMF_RESPONSE_RECEIVED;

	if (UNF_GET_LL_ERR(v_pkg) != UNF_IO_SUCCESS) {
		UNF_TRACE(UNF_EVTLOG_IO_WARN, UNF_LOG_IO_ATT, UNF_WARN,
			  "[warn]Send scsi manage command failed with error code(0x%x)",
			  UNF_GET_LL_ERR(v_pkg));

		v_xchg->scsi_cmnd_info.result = UNF_IO_FAILED;

		/* wakeup semaphore & return */
		up(&v_xchg->task_sema);

		return;
	}

	rsp_info = v_pkg->unf_rsp_pload_bl.buffer_ptr;
	if (!rsp_info && (v_pkg->unf_rsp_pload_bl.length != 0)) {
		rsp_info =
			(unsigned char *)
			v_xchg->fcp_sfs_union.fcp_rsp_entry.fcp_rsp_iu;

		/* change to little end if necessary */
		if (rsp_info && (v_pkg->byte_orders & UNF_BIT_3))
			unf_big_end_to_cpu(
				rsp_info,
				v_pkg->unf_rsp_pload_bl.length);
	}

	if (!rsp_info) {
		UNF_TRACE(UNF_EVTLOG_IO_INFO, UNF_LOG_IO_ATT, UNF_MAJOR,
			  "[info]FCP response data pointer is NULL with Xchg TAG(0x%x)",
			  v_xchg->hot_pool_tag);

		v_xchg->scsi_cmnd_info.result = UNF_IO_SUCCESS;

		/* wakeup semaphore & return */
		up(&v_xchg->task_sema);

		return;
	}

	UNF_TRACE(UNF_EVTLOG_IO_INFO, UNF_LOG_IO_ATT, UNF_MAJOR,
		  "[info]FCP response data length(0x%x), RSP_CODE(0x%x:%x:%x:%x:%x:%x:%x:%x)",
		  v_pkg->unf_rsp_pload_bl.length,
		  rsp_info[0],
		  rsp_info[1],
		  rsp_info[2],
		  rsp_info[3],
		  rsp_info[4],
		  rsp_info[5],
		  rsp_info[6],
		  rsp_info[7]);

	rsp_code = rsp_info[code_index];
	if ((rsp_code == UNF_FCP_TM_RSP_COMPLETE) ||
	    (rsp_code == UNF_FCP_TM_RSP_SUCCEED))
		v_xchg->scsi_cmnd_info.result = UNF_IO_SUCCESS;
	else
		v_xchg->scsi_cmnd_info.result = UNF_IO_FAILED;

	/* wakeup semaphore & return */
	up(&v_xchg->task_sema);
}
