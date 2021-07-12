// SPDX-License-Identifier: GPL-2.0
/* Huawei Hifc PCI Express Linux driver
 * Copyright(c) 2017 Huawei Technologies Co., Ltd
 *
 */

#include "hifc_knl_adp.h"
#include "unf_log.h"
#include "unf_exchg.h"
#include "unf_rport.h"
#include "unf_io.h"
#include "unf_portman.h"
#include "unf_io_abnormal.h"

#define UNF_GET_FCP_CTL(pkg)     ((((pkg)->status) >> 8) & 0xFF)
#define UNF_GET_SCSI_STATUS(pkg) (((pkg)->status) & 0xFF)

static unsigned int unf_io_success_handler(struct unf_xchg_s *v_xchg,
					   struct unf_frame_pkg_s *v_pkg,
					   unsigned int v_status);
static unsigned int unf_ini_error_default_handler(struct unf_xchg_s *v_xchg,
						  struct unf_frame_pkg_s *v_pkg,
						  unsigned int v_status);
static unsigned int unf_io_under_flow_handler(struct unf_xchg_s *v_xchg,
					      struct unf_frame_pkg_s *v_pkg,
					      unsigned int v_status);
static unsigned int unf_ini_dif_error_handler(struct unf_xchg_s *v_xchg,
					      struct unf_frame_pkg_s *v_pkg,
					      unsigned int v_status);

struct unf_ini_error_handler {
	unsigned int error_code;
	unsigned int (*pfn_unf_ini_error_handler)(struct unf_xchg_s *v_xchg,
						  struct unf_frame_pkg_s *v_pkg,
						  unsigned int v_status);
};

struct unf_ini_error_handler ini_error_handler_table[] = {
	{ UNF_IO_SUCCESS,              unf_io_success_handler },
	{ UNF_IO_ABORTED,              unf_ini_error_default_handler },
	{ UNF_IO_FAILED,               unf_ini_error_default_handler },
	{ UNF_IO_ABORT_ABTS,           unf_ini_error_default_handler },
	{ UNF_IO_ABORT_LOGIN,          unf_ini_error_default_handler },
	{ UNF_IO_ABORT_REET,           unf_ini_error_default_handler },
	{ UNF_IO_ABORT_FAILED,         unf_ini_error_default_handler },
	{ UNF_IO_OUTOF_ORDER,          unf_ini_error_default_handler },
	{ UNF_IO_FTO,                  unf_ini_error_default_handler },
	{ UNF_IO_LINK_FAILURE,         unf_ini_error_default_handler },
	{ UNF_IO_OVER_FLOW,            unf_ini_error_default_handler },
	{ UNF_IO_RSP_OVER,             unf_ini_error_default_handler },
	{ UNF_IO_LOST_FRAME,           unf_ini_error_default_handler },
	{ UNF_IO_UNDER_FLOW,           unf_io_under_flow_handler },
	{ UNF_IO_HOST_PROG_ERROR,      unf_ini_error_default_handler },
	{ UNF_IO_SEST_PROG_ERROR,      unf_ini_error_default_handler },
	{ UNF_IO_INVALID_ENTRY,        unf_ini_error_default_handler },
	{ UNF_IO_ABORT_SEQ_NOT,        unf_ini_error_default_handler },
	{ UNF_IO_REJECT,               unf_ini_error_default_handler },
	{ UNF_IO_EDC_IN_ERROR,         unf_ini_error_default_handler },
	{ UNF_IO_EDC_OUT_ERROR,        unf_ini_error_default_handler },
	{ UNF_IO_UNINIT_KEK_ERR,       unf_ini_error_default_handler },
	{ UNF_IO_DEK_OUTOF_RANGE,      unf_ini_error_default_handler },
	{ UNF_IO_KEY_UNWRAP_ERR,       unf_ini_error_default_handler },
	{ UNF_IO_KEY_TAG_ERR,          unf_ini_error_default_handler },
	{ UNF_IO_KEY_ECC_ERR,          unf_ini_error_default_handler },
	{ UNF_IO_BLOCK_SIZE_ERROR,     unf_ini_error_default_handler },
	{ UNF_IO_ILLEGAL_CIPHER_MODE,  unf_ini_error_default_handler },
	{ UNF_IO_CLEAN_UP,             unf_ini_error_default_handler },
	{ UNF_IO_ABORTED_BY_TARGET,    unf_ini_error_default_handler },
	{ UNF_IO_TRANSPORT_ERROR,      unf_ini_error_default_handler },
	{ UNF_IO_LINK_FLASH,           unf_ini_error_default_handler },
	{ UNF_IO_TIMEOUT,              unf_ini_error_default_handler },
	{ UNF_IO_DMA_ERROR,            unf_ini_error_default_handler },
	{ UNF_IO_DIF_ERROR,            unf_ini_dif_error_handler },
	{ UNF_IO_INCOMPLETE,           unf_ini_error_default_handler },
	{ UNF_IO_DIF_REF_ERROR,        unf_ini_dif_error_handler },
	{ UNF_IO_DIF_GEN_ERROR,        unf_ini_dif_error_handler }
};

void unf_done_ini_xchg(struct unf_xchg_s *v_xchg)
{
	/*
	 * About I/O Done
	 * 1. normal case
	 * 2. Send ABTS & RCVD RSP
	 * 3. Send ABTS & timer timeout
	 */
	struct unf_scsi_cmd_s scsi_cmd = { 0 };
	unsigned long flags = 0;
	struct unf_scsi_cmd_info_s *scsi_cmnd_info = NULL;
	struct unf_rport_scsi_id_image_s *scsi_image_table = NULL;
	unsigned int scsi_id = 0;

	UNF_CHECK_VALID(0x1301, TRUE, v_xchg, return);

	/* scsi_cmnd validity check */
	if (unlikely(!v_xchg->scsi_cmnd_info.scsi_cmnd))
		return;

	/* 1. Free RX_ID for INI SIRT: Do not care
	 * 2. set & check exchange state
	 *
	 * for Set UP_ABORT Tag:
	 * 1) L_Port destroy
	 * 2) AC power down
	 * 3) LUN reset
	 * 4) Target/Session reset
	 * 5) SCSI send Abort(ABTS)
	 */
	spin_lock_irqsave(&v_xchg->xchg_state_lock, flags);
	v_xchg->io_state |= INI_IO_STATE_DONE;
	if (unlikely(v_xchg->io_state & (INI_IO_STATE_UPABORT |
					  INI_IO_STATE_UPSEND_ERR |
					  INI_IO_STATE_TMF_ABORT))) {
		/*
		 * a. UPABORT: scsi have send ABTS
		 *  --->>> do not call SCSI_Done, return directly
		 * b. UPSEND_ERR: error happened duiring LLDD send SCSI_CMD
		 *  --->>> do not call SCSI_Done, scsi need retry
		 */
		UNF_TRACE(UNF_EVTLOG_IO_WARN, UNF_LOG_IO_ATT, UNF_KEVENT,
			  "[event]Exchange(0x%p) Cmdsn:0x%lx upCmd:%p oxid(0x%x) with state(0x%x) has been aborted or send error",
			  v_xchg, (unsigned long)v_xchg->cmnd_sn,
			  v_xchg->scsi_cmnd_info.scsi_cmnd, v_xchg->ox_id,
			  v_xchg->io_state);

		spin_unlock_irqrestore(&v_xchg->xchg_state_lock, flags);
		/* here, return directly */
		return;
	}
	spin_unlock_irqrestore(&v_xchg->xchg_state_lock, flags);

	/* 3. Get scsi_cmnd info */
	scsi_cmnd_info = &v_xchg->scsi_cmnd_info;

	/*
	 * 4. Set:
	 * scsi_cmnd;
	 * cmnd_done_func;
	 * cmnd up_level_done;
	 * sense_buff_addr;
	 * resid_length;
	 * cmnd_result;
	 * dif_info
	 *
	 * UNF_SCSI_CMND <<-- UNF_SCSI_CMND_INFO
	 */
	UNF_SET_HOST_CMND((&scsi_cmd), scsi_cmnd_info->scsi_cmnd);
	UNF_SET_CMND_DONE_FUNC((&scsi_cmd), scsi_cmnd_info->pfn_done);
	scsi_cmd.drv_private = v_xchg->lport;
	if (unlikely((UNF_SCSI_STATUS(v_xchg->scsi_cmnd_info.result)) &
			 FCP_SNS_LEN_VALID_MASK)) {
		unf_save_sense_data(
			scsi_cmd.upper_cmnd,
			(char *)v_xchg->fcp_sfs_union.fcp_rsp_entry.fcp_rsp_iu,
			SCSI_SENSE_DATA_LEN);
	}
	UNF_SET_RESID((&scsi_cmd), (unsigned int)v_xchg->resid_len);
	UNF_SET_CMND_RESULT((&scsi_cmd), scsi_cmnd_info->result);
	memcpy(&scsi_cmd.dif_info, &v_xchg->dif_info,
	       sizeof(struct dif_info_s));

	scsi_id = scsi_cmnd_info->scsi_id;

	/* 5. call scsi_cmnd_done func: unf_scsi_done */
	UNF_DONE_SCSI_CMND(&scsi_cmd);

	/* 6. Update IO result CNT */
	if (likely(v_xchg->lport)) {
		scsi_image_table = &v_xchg->lport->rport_scsi_table;
		UNF_IO_RESULT_CNT(scsi_image_table, scsi_id,
				  (scsi_cmnd_info->result >> 16));
	}
}

static inline unsigned int unf_ini_get_sgl_entry_buf(
				ini_get_sgl_entry_buf pfn_unf_ini_get_sgl,
				void *v_cmnd,
				void *v_driver_sgl,
				void **v_upper_sgl,
				unsigned int *v_req_index,
				unsigned int *v_index,
				char **v_buf,
				unsigned int *v_buf_len)
{
	if (unlikely(!pfn_unf_ini_get_sgl)) {
		UNF_TRACE(UNF_EVTLOG_IO_INFO, UNF_LOG_IO_ATT, UNF_MAJOR,
			  "Command(0x%p) Get sgl Entry func Null.", v_cmnd);

		return UNF_RETURN_ERROR;
	}

	return pfn_unf_ini_get_sgl(v_cmnd, v_driver_sgl, v_upper_sgl,
				   v_req_index, v_index, v_buf, v_buf_len);
}

unsigned int unf_ini_get_sgl_entry(void *v_pkg, char **v_buf,
				   unsigned int *v_buf_len)
{
	struct unf_frame_pkg_s *pkg = (struct unf_frame_pkg_s *)v_pkg;
	struct unf_xchg_s *xchg = NULL;
	unsigned int ret = RETURN_OK;

	UNF_CHECK_VALID(0x1305, UNF_TRUE, v_pkg, return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(0x1306, UNF_TRUE, v_buf, return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(0x1307, UNF_TRUE, v_buf_len, return UNF_RETURN_ERROR);

	xchg = (struct unf_xchg_s *)pkg->xchg_contex;
	UNF_CHECK_VALID(0x1308, UNF_TRUE, xchg, return UNF_RETURN_ERROR);

	/* Get SGL Entry buffer for INI Mode */
	ret = unf_ini_get_sgl_entry_buf(
				xchg->scsi_cmnd_info.pfn_unf_get_sgl_entry_buf,
				xchg->scsi_cmnd_info.scsi_cmnd,
				NULL,
				&xchg->req_sgl_info.sgl,
				&xchg->scsi_cmnd_info.port_id,
				&((xchg->req_sgl_info).entry_index),
				v_buf, v_buf_len);

	return ret;
}

unsigned int unf_ini_get_dif_sgl_entry(void *v_pkg, char **v_buf,
				       unsigned int *v_buf_len)
{
	struct unf_frame_pkg_s *pkg = (struct unf_frame_pkg_s *)v_pkg;
	struct unf_xchg_s *xchg = NULL;
	unsigned int ret = RETURN_OK;

	UNF_CHECK_VALID(0x1305, UNF_TRUE, v_pkg, return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(0x1306, UNF_TRUE, v_buf, return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(0x1307, UNF_TRUE, v_buf_len, return UNF_RETURN_ERROR);

	xchg = (struct unf_xchg_s *)pkg->xchg_contex;
	UNF_CHECK_VALID(0x1308, UNF_TRUE, xchg, return UNF_RETURN_ERROR);

	/* Get SGL Entry buffer for INI Mode */
	ret = unf_ini_get_sgl_entry_buf(
				xchg->scsi_cmnd_info.pfn_unf_get_sgl_entry_buf,
				xchg->scsi_cmnd_info.scsi_cmnd,
				NULL,
				&xchg->dif_sgl_info.sgl,
				&xchg->scsi_cmnd_info.port_id,
				&xchg->dif_sgl_info.entry_index,
				v_buf, v_buf_len);
	return ret;
}

unsigned int unf_get_uplevel_cmnd_errcode(
				struct unf_ini_error_code_s *v_err_table,
				unsigned int v_err_table_count,
				unsigned int v_drv_err_code)
{
	unsigned int i;

	/* fail return UNF_RETURN_ERROR,adjust by up level */
	if (unlikely(!v_err_table)) {
		UNF_TRACE(UNF_EVTLOG_IO_INFO, UNF_LOG_IO_ATT, UNF_MAJOR,
			  "Error Code Table is Null, Error Code(0x%x).",
			  v_drv_err_code);

		return (unsigned int)UNF_SCSI_HOST(DID_ERROR);
	}

	for (i = 0; i < v_err_table_count; i++) {
		if (v_drv_err_code == v_err_table[i].drv_err_code)
			return v_err_table[i].ap_err_code;
	}

	UNF_TRACE(UNF_EVTLOG_IO_WARN, UNF_LOG_IO_ATT, UNF_WARN,
		  "[warn]Unsupported Ap Error code by Error Code(0x%x).",
		  v_drv_err_code);

	return (unsigned int)UNF_SCSI_HOST(DID_ERROR);
}

static unsigned int unf_ini_status_handle(struct unf_xchg_s *v_xchg,
					  struct unf_frame_pkg_s *v_pkg)
{
	unsigned int i;
	unsigned int ret;
	unsigned int status;

	for (i = 0;
	     i < sizeof(ini_error_handler_table) /
	     sizeof(struct unf_ini_error_handler);
	     i++) {
		if (UNF_GET_LL_ERR(v_pkg) ==
		    ini_error_handler_table[i].error_code) {
			status = unf_get_uplevel_cmnd_errcode(
				v_xchg->scsi_cmnd_info.err_code_table,
				v_xchg->scsi_cmnd_info.err_code_table_cout,
				UNF_GET_LL_ERR(v_pkg));

			if (ini_error_handler_table[i].pfn_unf_ini_error_handler) {
				ret = ini_error_handler_table[i].pfn_unf_ini_error_handler(
									v_xchg,
									v_pkg,
									status);
			} else {
				/* set exchange->result
				 * ---to--->>>scsi_result
				 */
				ret = unf_ini_error_default_handler(v_xchg,
								    v_pkg,
								    status);
			}

			return ret;
		}
	}

	status = unf_get_uplevel_cmnd_errcode(
				v_xchg->scsi_cmnd_info.err_code_table,
				v_xchg->scsi_cmnd_info.err_code_table_cout,
				UNF_IO_SOFT_ERR);

	ret = unf_ini_error_default_handler(v_xchg, v_pkg, status);

	UNF_TRACE(UNF_EVTLOG_IO_ERR, UNF_LOG_IO_ATT, UNF_ERR,
		  "[err]Can not find com status, SID(0x%x) exchange(0x%p) com_status(0x%x) DID(0x%x) hot_pool_tag(0x%x)",
		  v_xchg->sid, v_xchg, v_pkg->status,
		  v_xchg->did, v_xchg->hot_pool_tag);

	return ret;
}

static void unf_analysis_response_info(struct unf_xchg_s *v_xchg,
				       struct unf_frame_pkg_s *v_pkg,
				       unsigned int *v_status)
{
	unsigned char *resp_buf = NULL;

	/* LL_Driver use Little End, and copy RSP_INFO to COM_Driver */
	if (v_pkg->unf_rsp_pload_bl.buffer_ptr) {
		if (v_pkg->unf_rsp_pload_bl.buffer_ptr[0] !=
		    UNF_FCP_TM_RSP_COMPLETE) {
			*v_status = UNF_SCSI_HOST(DID_BUS_BUSY);

			UNF_TRACE(UNF_EVTLOG_IO_WARN, UNF_LOG_IO_ATT, UNF_WARN,
				  "[warn]Port(0x%p) DID bus busy, scsi_status(0x%x)",
				  v_xchg->lport, UNF_GET_SCSI_STATUS(v_pkg));
		}
	} else {
		resp_buf =
		(unsigned char *)v_xchg->fcp_sfs_union.fcp_rsp_entry.fcp_rsp_iu;
		if ((resp_buf)) {
			/* If chip use Little End, then change it to Big End */
			if ((v_pkg->byte_orders & UNF_BIT_3) == 0)
				unf_cpu_to_big_end(
					resp_buf,
					v_pkg->unf_rsp_pload_bl.length);

			/* Chip DAM data with Big End */
			if (resp_buf[3] != UNF_FCP_TM_RSP_COMPLETE) {
				*v_status = UNF_SCSI_HOST(DID_BUS_BUSY);

				UNF_TRACE(UNF_EVTLOG_IO_WARN, UNF_LOG_IO_ATT,
					  UNF_WARN,
					  "[warn]Port(0x%p) DID bus busy, scsi_status(0x%x)",
					  v_xchg->lport,
					  UNF_GET_SCSI_STATUS(v_pkg));
			}
		}
	}
}

static void unf_analysis_sense_info(struct unf_xchg_s *v_xchg,
				    struct unf_frame_pkg_s *v_pkg)
{
#define MIN(x, y) ((x) < (y) ? (x) : (y))

	unsigned int length = 0;

	/* 4 bytes Align */
	length = v_pkg->unf_sense_pload_bl.length;
	if (length % 4 != 0)
		length = 4 * ((length / 4) + 1);

	/*
	 * If have sense info then copy directly
	 * else, the chip has been dma the data to sense buffer
	 */
	if (v_pkg->unf_sense_pload_bl.buffer_ptr) {
		/* carry from wqe by ll_driver & ucode: do not used */
		unf_cpu_to_big_end(v_pkg->unf_sense_pload_bl.buffer_ptr,
				   length);

		memcpy(v_xchg->fcp_sfs_union.fcp_rsp_entry.fcp_rsp_iu,
		       v_pkg->unf_sense_pload_bl.buffer_ptr,
		       (unsigned int)MIN(UNF_SCSI_SENSE_DATA_LEN,
		       v_pkg->unf_sense_pload_bl.length));

		UNF_TRACE(UNF_EVTLOG_IO_INFO, UNF_LOG_IO_ATT, UNF_MAJOR,
			  "[info]LPort(0x%p), Sense Length(%u), Scsi Status(0x%x).",
			  v_xchg->lport,
			  v_pkg->unf_sense_pload_bl.length,
			  UNF_GET_SCSI_STATUS(v_pkg));
	} else if ((length != 0) &&
		   (v_xchg->fcp_sfs_union.fcp_rsp_entry.fcp_rsp_iu)) {
		/* has been dma to exchange buffer */
		if ((v_pkg->byte_orders & UNF_BIT_4) == 0) {
			unf_cpu_to_big_end(((unsigned char *)
					   (v_xchg->fcp_sfs_union.fcp_rsp_entry.fcp_rsp_iu)) +
					   v_pkg->unf_rsp_pload_bl.length,
					   v_pkg->unf_sense_pload_bl.length);
		}

		memcpy(v_xchg->fcp_sfs_union.fcp_rsp_entry.fcp_rsp_iu,
		       ((unsigned char *)
		       (v_xchg->fcp_sfs_union.fcp_rsp_entry.fcp_rsp_iu)) +
		       v_pkg->unf_rsp_pload_bl.length,
		       (unsigned int)MIN(UNF_SCSI_SENSE_DATA_LEN,
					 v_pkg->unf_sense_pload_bl.length));
	}
}

static unsigned int unf_io_success_handler(struct unf_xchg_s *v_xchg,
					   struct unf_frame_pkg_s *v_pkg,
					   unsigned int v_status)
{
	unsigned char scsi_status;
	unsigned char control;
	unsigned int status = v_status;

	UNF_CHECK_VALID(0x1311, TRUE, v_xchg, return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(0x1312, TRUE, v_pkg, return UNF_RETURN_ERROR);

	control = UNF_GET_FCP_CTL(v_pkg);
	scsi_status = UNF_GET_SCSI_STATUS(v_pkg);

	UNF_TRACE(UNF_EVTLOG_IO_INFO, UNF_LOG_IO_ATT, UNF_INFO,
		  "[info]Port(0x%p), Exchange(0x%p) Completed, Control(0x%x), Scsi Status(0x%x)",
		  v_xchg->lport, v_xchg, control, scsi_status);

	if (control & FCP_SNS_LEN_VALID_MASK) {
		/* has sense info */
		if (scsi_status == FCP_SCSI_STATUS_GOOD)
			scsi_status = SCSI_CHECK_CONDITION;

		unf_analysis_sense_info(v_xchg, v_pkg);
	} else {
		/*
		 * When the FCP_RSP_LEN_VALID bit is set to one,
		 * the content of the SCSI STATUS CODE field is not reliable
		 * and shall be ignored by the application client.
		 */
		if (control & FCP_RSP_LEN_VALID_MASK)
			unf_analysis_response_info(v_xchg, v_pkg, &status);
	}

	v_xchg->scsi_cmnd_info.result = status |
					  UNF_SCSI_STATUS(scsi_status);

	return RETURN_OK;
}

static unsigned int unf_ini_error_default_handler(struct unf_xchg_s *v_xchg,
						  struct unf_frame_pkg_s *v_pkg,
						  unsigned int v_status)
{
	/* set exchange->result  ---to--->>> scsi_cmnd->result */
	UNF_CHECK_VALID(0x1313, TRUE, v_xchg, return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(0x1314, TRUE, v_pkg, return UNF_RETURN_ERROR);

	UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_ABNORMAL, UNF_WARN,
		  "[warn]SID(0x%x) exchange(0x%p) com_status(0x%x) up_status(0x%x) DID(0x%x) hot_pool_tag(0x%x) response_len(0x%x)",
		  v_xchg->sid, v_xchg, v_pkg->status, v_status,
		  v_xchg->did, v_xchg->hot_pool_tag, v_pkg->residus_len);

	v_xchg->scsi_cmnd_info.result =
		v_status | UNF_SCSI_STATUS(UNF_GET_SCSI_STATUS(v_pkg));

	return RETURN_OK;
}

static unsigned int unf_ini_dif_error_handler(struct unf_xchg_s *v_xchg,
					      struct unf_frame_pkg_s *v_pkg,
					      unsigned int v_status)
{
	struct unf_dif_control_info_s *dif_control = NULL;
	unsigned char *sense_data = NULL;
	unsigned short sense_code = 0;

	UNF_CHECK_VALID(0x1315, TRUE, v_xchg, return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(0x1316, TRUE, v_pkg, return UNF_RETURN_ERROR);
	UNF_REFERNCE_VAR(v_status);

	/*
	 * According to DIF scheme
	 * drive set check condition(0x2) when dif error occurs,
	 * and returns the values base on the upper-layer verification resule
	 * Check sequence: crc,Lba,App,
	 * if CRC error is found, the subsequent check is not performed
	 */
	v_xchg->scsi_cmnd_info.result =
		UNF_SCSI_STATUS(SCSI_CHECK_CONDITION);
	dif_control = &v_pkg->dif_control;

	if (v_pkg->status_sub_code == 0) {
		UNF_GET_DIF_ERROR_LEVEL1(v_xchg, dif_control, 0,
					 sense_code, DRV_DIF_CRC_ERR);

		UNF_GET_DIF_ERROR_LEVEL2(v_xchg, dif_control, 0,
					 sense_code, DRV_DIF_LBA_ERR);

		UNF_GET_DIF_ERROR_LEVEL3(v_xchg, dif_control, 0,
					 sense_code, DRV_DIF_APP_ERR);

		if (sense_code == 0) {
			UNF_TRACE(UNF_EVTLOG_IO_WARN, UNF_LOG_IO_ATT, UNF_WARN,
				  "[warn]Unexpected DIF unwonted, operation_code(0x%x) actual DIF(0x%llx) expected DIF(0x%llx)",
				  v_xchg->dif_control.protect_opcode,
				  *(unsigned long long *)
				  &dif_control->actual_dif[0],
				  *(unsigned long long *)
				  &dif_control->expected_dif[0]);
		}
	} else {
		sense_code = (unsigned short)v_pkg->status_sub_code;
	}

	sense_data = (unsigned char *)
		     v_xchg->fcp_sfs_union.fcp_rsp_entry.fcp_rsp_iu;
	memset(sense_data, 0, SCSI_SENSE_DATA_LEN);
	sense_data[0] = 0x70; /* response code */
	sense_data[2] = ILLEGAL_REQUEST; /* sense key:0x05; */
	sense_data[7] = 0x7; /* additional sense length */
	sense_data[12] = (unsigned char)(sense_code >> 8);
	sense_data[13] = (unsigned char)sense_code;

	/* valid sense data length snscode[13] */
	return RETURN_OK;
}

static unsigned int unf_io_under_flow_handler(struct unf_xchg_s *v_xchg,
					      struct unf_frame_pkg_s *v_pkg,
					      unsigned int v_status)
{
	/* under flow: residlen > 0 */
	UNF_CHECK_VALID(0x1317, TRUE, v_xchg, return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(0x1318, TRUE, v_pkg, return UNF_RETURN_ERROR);

	if ((v_xchg->fcp_cmnd.cdb[0] != SCSIOPC_REPORT_LUN) &&
	    (v_xchg->fcp_cmnd.cdb[0] != SCSIOPC_INQUIRY)) {
		UNF_TRACE(UNF_EVTLOG_IO_INFO, UNF_LOG_IO_ATT, UNF_INFO,
			  "[info]IO under flow: SID(0x%x) exchange(0x%p) com status(0x%x) up_status(0x%x) DID(0x%x) hot_pool_tag(0x%x) response SID(0x%x)",
			  v_xchg->sid, v_xchg, v_pkg->status, v_status,
			  v_xchg->did, v_xchg->hot_pool_tag,
			  v_pkg->residus_len);
	}

	v_xchg->resid_len = (int)v_pkg->residus_len;
	(void)unf_io_success_handler(v_xchg, v_pkg, v_status);

	return RETURN_OK;
}

void unf_complete_cmnd(struct unf_scsi_cmd_s *v_scsi_cmnd, unsigned int result)
{
	/*
	 * Exception during process Que_CMND
	 * 1. L_Port == NULL;
	 * 2. L_Port == removing;
	 * 3. R_Port == NULL;
	 * 4. Xchg == NULL.
	 */
	UNF_CHECK_VALID(0x1319, TRUE, UNF_GET_CMND_DONE_FUNC(v_scsi_cmnd),
			return);

	UNF_TRACE(UNF_EVTLOG_IO_INFO, UNF_LOG_IO_ATT, UNF_INFO,
		  "[info]Command(0x%p), Result(0x%x).", v_scsi_cmnd, result);

	UNF_SET_CMND_RESULT(v_scsi_cmnd, result);

	/* struct unf_scsi_cmd_s->pfn_done -->> unf_scsi_done */
	UNF_DONE_SCSI_CMND(v_scsi_cmnd);
}

static inline void unf_bind_xchg_scsi_cmd(struct unf_xchg_s *v_xchg,
					  struct unf_scsi_cmd_s *v_scsi_cmnd)
{
	struct unf_scsi_cmd_info_s *scsi_cmnd_info = NULL;

	scsi_cmnd_info = &v_xchg->scsi_cmnd_info;

	/* UNF_SCSI_CMND_INFO <<-- UNF_SCSI_CMND */
	scsi_cmnd_info->err_code_table =
		UNF_GET_ERR_CODE_TABLE(v_scsi_cmnd);
	scsi_cmnd_info->err_code_table_cout =
		UNF_GET_ERR_CODE_TABLE_COUNT(v_scsi_cmnd);
	scsi_cmnd_info->pfn_done = UNF_GET_CMND_DONE_FUNC(v_scsi_cmnd);
	scsi_cmnd_info->scsi_cmnd = UNF_GET_HOST_CMND(v_scsi_cmnd);
	scsi_cmnd_info->sense_buf =
		(char *)UNF_GET_SENSE_BUF_ADDR(v_scsi_cmnd);
	/* unf_get_frame_entry_buf */
	scsi_cmnd_info->pfn_unf_get_sgl_entry_buf =
		UNF_GET_SGL_ENTRY_BUF_FUNC(v_scsi_cmnd);
	scsi_cmnd_info->sgl = UNF_GET_CMND_SGL(v_scsi_cmnd);
	scsi_cmnd_info->time_out = v_scsi_cmnd->time_out;
	scsi_cmnd_info->entry_cnt = v_scsi_cmnd->entry_count;
	scsi_cmnd_info->port_id = (unsigned int)v_scsi_cmnd->port_id;
	scsi_cmnd_info->scsi_id = UNF_GET_SCSI_ID_BY_CMND(v_scsi_cmnd);
}

unsigned int unf_ini_scsi_completed(void *v_lport,
				    struct unf_frame_pkg_s *v_pkg)
{
	struct unf_lport_s *lport = NULL;
	struct unf_xchg_s *xchg = NULL;
	struct unf_fcp_cmnd_s *fcp_cmnd = NULL;
	unsigned int control;
	unsigned short xchg_tag;
	unsigned int ret;
	unsigned long flag = 0;

	UNF_CHECK_VALID(0x1323, TRUE, v_lport, return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(0x1324, TRUE, v_pkg, return UNF_RETURN_ERROR);

	lport = (struct unf_lport_s *)v_lport;
	xchg_tag =
		(unsigned short)v_pkg->private[PKG_PRIVATE_XCHG_HOT_POOL_INDEX];

	/* 1. Find Exchange Context */
	xchg = unf_cm_lookup_xchg_by_tag(v_lport, (unsigned short)xchg_tag);
	if (unlikely(!xchg)) {
		UNF_TRACE(UNF_EVTLOG_IO_WARN, UNF_LOG_IO_ATT, UNF_WARN,
			  "[warn]Port(0x%x_0x%x) can not find exchange by tag(0x%x)",
			  lport->port_id, lport->nport_id, xchg_tag);

		/* NOTE: return directly */
		return UNF_RETURN_ERROR;
	}

	/* 2. Consistency check */
	UNF_CHECK_ALLOCTIME_VALID(lport, xchg_tag, xchg,
				  v_pkg->private[PKG_PRIVATE_XCHG_ALLOC_TIME],
				  xchg->private[PKG_PRIVATE_XCHG_ALLOC_TIME]);

	/* 3. Increase ref_cnt for exchange protecting */
	ret = unf_xchg_ref_inc(xchg, INI_RESPONSE_DONE); /* hold */
	UNF_CHECK_VALID(0x1325, TRUE, (ret == RETURN_OK),
			return UNF_RETURN_ERROR);

	fcp_cmnd = &xchg->fcp_cmnd;
	control = fcp_cmnd->control;
	control = UNF_GET_TASK_MGMT_FLAGS(control);

	/* 4. Cancel timer if necessary */
	if (xchg->scsi_cmnd_info.time_out != 0)
		lport->xchg_mgr_temp.pfn_unf_xchg_cancel_timer(xchg);

	/* 5. process scsi TMF if necessary */
	if (control != 0) {
		unf_process_scsi_mgmt_result(v_pkg, xchg);
		unf_xchg_ref_dec(xchg, INI_RESPONSE_DONE); /* cancel hold */

		/* NOTE: return directly */
		return RETURN_OK;
	}

	/* 6. Xchg Abort state check */
	spin_lock_irqsave(&xchg->xchg_state_lock, flag);
	if (INI_IO_STATE_UPABORT & xchg->io_state) {
		spin_unlock_irqrestore(&xchg->xchg_state_lock, flag);

		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_NORMAL, UNF_WARN,
			  "[warn]Port(0x%x) find exchange(%p) state(0x%x) has been aborted",
			  lport->port_id, xchg, xchg->io_state);

		/* NOTE: release exchange during SCSI ABORT(ABTS) */
		unf_xchg_ref_dec(xchg, INI_RESPONSE_DONE); /* cancel hold */

		return ret;
	}
	spin_unlock_irqrestore(&xchg->xchg_state_lock, flag);

	/*
	 * 7. INI SCSI CMND Status process
	 * set exchange->result ---to--->>> scsi_result
	 */
	ret = unf_ini_status_handle(xchg, v_pkg);

	/* 8. NOTE: release exchange if necessary */
	unf_cm_free_xchg(lport, xchg);

	/* 9. dec exch ref_cnt */
	/* cancel hold: release resource now */
	unf_xchg_ref_dec(xchg, INI_RESPONSE_DONE);

	return ret;
}

unsigned int unf_hardware_start_io(struct unf_lport_s *v_lport,
				   struct unf_frame_pkg_s *v_pkg)
{
	if (unlikely(!v_lport->low_level_func.service_op.pfn_unf_cmnd_send)) {
		UNF_TRACE(UNF_EVTLOG_IO_ERR, UNF_LOG_IO_ATT, UNF_ERR,
			  "[err]Port(0x%x) low level send scsi function is NULL",
			  v_lport->port_id);

		return UNF_RETURN_ERROR;
	}

	return v_lport->low_level_func.service_op.pfn_unf_cmnd_send(
			v_lport->fc_port,
			v_pkg);
}

struct unf_rport_s *unf_find_rport_by_scsi_id(
				struct unf_lport_s *v_lport,
				struct unf_ini_error_code_s *v_err_code_table,
				unsigned int v_err_code_table_cout,
				unsigned int v_scsi_id,
				unsigned int *v_scsi_result)
{
	struct unf_rport_scsi_id_image_s *scsi_image_table = NULL;
	struct unf_wwpn_rport_info_s *wwpn_rport_info = NULL;
	struct unf_rport_s *rport = NULL;
	unsigned long flags = 0;

	/* scsi_table -> session_table -> image_table */
	scsi_image_table = &v_lport->rport_scsi_table;

	/* 1. Scsi_Id validity check */
	if (unlikely(v_scsi_id >= scsi_image_table->max_scsi_id)) {
		UNF_TRACE(UNF_EVTLOG_IO_ERR, UNF_LOG_IO_ATT, UNF_ERR,
			  "[err]Input scsi_id(0x%x) bigger than max_scsi_id(0x%x).",
			  v_scsi_id, scsi_image_table->max_scsi_id);

		*v_scsi_result = unf_get_uplevel_cmnd_errcode(
					v_err_code_table,
					v_err_code_table_cout,
					UNF_IO_SOFT_ERR);  /* did_soft_error */

		return NULL;
	}

	/* 2. GetR_Port_Info/R_Port: use Scsi_Id find from L_Port's
	 * Rport_Scsi_Table (image table)
	 */
	spin_lock_irqsave(&scsi_image_table->scsi_image_table_lock, flags);
	wwpn_rport_info = &scsi_image_table->wwn_rport_info_table[v_scsi_id];
	rport = wwpn_rport_info->rport;
	spin_unlock_irqrestore(&scsi_image_table->scsi_image_table_lock, flags);

	if (unlikely(!rport)) {
		*v_scsi_result = unf_get_uplevel_cmnd_errcode(
					v_err_code_table,
					v_err_code_table_cout,
					/* did_not_connect */
					UNF_IO_PORT_LOGOUT);

		return NULL;
	}

	return rport;
}

static unsigned int unf_build_xchg_fcp_cmnd(struct unf_fcp_cmnd_s *v_fcp_cmnd,
					    struct unf_scsi_cmd_s *v_scsi_cmnd)
{
	/* SCSI_CMND -->> FCP_CMND */
	if (UNF_GET_DATA_DIRECTION(v_scsi_cmnd) == DMA_TO_DEVICE) {
		v_fcp_cmnd->control = UNF_FCP_WR_DATA;
	} else if (UNF_GET_DATA_DIRECTION(v_scsi_cmnd) == DMA_FROM_DEVICE) {
		v_fcp_cmnd->control = UNF_FCP_RD_DATA;
	} else {
		/* DMA Direction None */
		v_fcp_cmnd->control = 0;
	}

	memcpy(v_fcp_cmnd->cdb, &UNF_GET_FCP_CMND(v_scsi_cmnd),
	       v_scsi_cmnd->cmnd_len);

	if (((v_fcp_cmnd->control == UNF_FCP_WR_DATA) &&
	     (IS_READ_COMMAND(v_fcp_cmnd->cdb[0]))) ||
	    ((v_fcp_cmnd->control == UNF_FCP_RD_DATA) &&
	     (IS_WRITE_COMMAND(v_fcp_cmnd->cdb[0])))) {
		UNF_TRACE(UNF_EVTLOG_IO_INFO, UNF_LOG_IO_ATT, UNF_MINOR,
			  "Scsi command direction inconsistent, CDB[0](0x%x), direction(0x%x).",
			  v_fcp_cmnd->cdb[0], v_fcp_cmnd->control);

		return UNF_RETURN_ERROR;
	}

	memcpy(v_fcp_cmnd->lun, v_scsi_cmnd->pc_lun_id,
	       sizeof(v_fcp_cmnd->lun));

	unf_big_end_to_cpu((void *)v_fcp_cmnd->cdb,
			   sizeof(v_fcp_cmnd->cdb));
	v_fcp_cmnd->data_length = UNF_GET_DATA_LEN(v_scsi_cmnd);

	return RETURN_OK;
}

static void unf_adjust_xchg_len(struct unf_xchg_s *v_xchg,
				unsigned int v_scsi_cmnd)
{
	switch (v_scsi_cmnd) {
	case SCSIOPC_REQUEST_SENSE: /* requires different buffer */
		v_xchg->data_len = SCSI_SENSE_DATA_LEN;
		UNF_TRACE(UNF_EVTLOG_IO_INFO, UNF_LOG_IO_ATT, UNF_MINOR,
			  "Request Sense new.");
		break;
	case SCSIOPC_TEST_UNIT_READY:
	case SCSIOPC_RESERVE:
	case SCSIOPC_RELEASE:
	case SCSIOPC_START_STOP_UNIT:
		v_xchg->data_len = 0;
		break;
	default:
		break;
	}
}

static void unf_copy_dif_control(struct unf_dif_control_info_s *v_dif_control,
				 struct unf_scsi_cmd_s *v_scsi_cmnd)
{
	v_dif_control->fcp_dl = v_scsi_cmnd->dif_control.fcp_dl;
	v_dif_control->protect_opcode =
		v_scsi_cmnd->dif_control.protect_opcode;
	v_dif_control->start_lba = v_scsi_cmnd->dif_control.start_lba;
	v_dif_control->app_tag = v_scsi_cmnd->dif_control.app_tag;

	v_dif_control->flags = v_scsi_cmnd->dif_control.flags;
	v_dif_control->dif_sge_count =
		v_scsi_cmnd->dif_control.dif_sge_count;
	v_dif_control->dif_sgl = v_scsi_cmnd->dif_control.dif_sgl;
}

static void unf_adjsut_dif_pci_transfer_len(struct unf_xchg_s *v_xchg,
					    unsigned int direction)
{
	struct unf_dif_control_info_s *dif_control = NULL;
	unsigned int sector_size = 512;

	dif_control = &v_xchg->dif_control;

	if (dif_control->protect_opcode == UNF_DIF_ACTION_NONE)
		return;

	switch (dif_control->protect_opcode & UNF_DIF_ACTION_MASK) {
	case UNF_DIF_ACTION_INSERT:
		if (direction == DMA_TO_DEVICE) {
			/* write IO,insert,Indicates that data with DIF is
			 * transmitted over the link.
			 */
			dif_control->fcp_dl =
				v_xchg->data_len +
				UNF_CAL_BLOCK_CNT(v_xchg->data_len,
						  sector_size) *
				UNF_DIF_AREA_SIZE;
		} else {
			/* read IO,insert,Indicates that the internal DIf is
			 * carried, and the link does not carry the DIf.
			 */
			dif_control->fcp_dl = v_xchg->data_len;
		}
		break;
	case UNF_DIF_ACTION_VERIFY_AND_DELETE:
		if (direction == DMA_TO_DEVICE) {
			/* write IO,Delete,Indicates that the internal DIf is
			 * carried, and the link does not carry the DIf.
			 */
			dif_control->fcp_dl = v_xchg->data_len;
		} else {
			/* read IO,Delete,Indicates that data with DIF is
			 * carried on the link and does not contain DIF
			 * on internal.
			 */
			dif_control->fcp_dl =
				v_xchg->data_len +
				UNF_CAL_BLOCK_CNT(v_xchg->data_len,
						  sector_size) *
				UNF_DIF_AREA_SIZE;
		}
		break;
	case UNF_DIF_ACTION_VERIFY_AND_FORWARD:
		dif_control->fcp_dl =
			v_xchg->data_len +
			UNF_CAL_BLOCK_CNT(v_xchg->data_len, sector_size) *
			UNF_DIF_AREA_SIZE;
		break;
	default:
		dif_control->fcp_dl = v_xchg->data_len;
		break;
	}

	v_xchg->fcp_cmnd.data_length = dif_control->fcp_dl;
}

static int unf_save_scsi_cmnd_to_xchg(struct unf_lport_s *v_lport,
				      struct unf_rport_s *v_rport,
				      struct unf_xchg_s *v_xchg,
				      struct unf_scsi_cmd_s *v_scsi_cmnd)
{
	struct unf_lport_s *lport = v_lport;
	struct unf_rport_s *rport = v_rport;
	struct unf_xchg_s *xchg = v_xchg;
	unsigned int result;

	v_scsi_cmnd->driver_scribble = (void *)xchg->start_jif;
	xchg->rport = rport;
	xchg->rport_bind_jifs = rport->rport_alloc_jifs;

	if (lport->low_level_func.xchg_mgr_type ==
	    UNF_LOW_LEVEL_MGR_TYPE_PASSTIVE)
		xchg->ox_id = xchg->hot_pool_tag;

	/* Build Xchg SCSI_CMND info */
	unf_bind_xchg_scsi_cmd(xchg, v_scsi_cmnd);

	xchg->data_len = UNF_GET_DATA_LEN(v_scsi_cmnd);
	xchg->data_direction = UNF_GET_DATA_DIRECTION(v_scsi_cmnd);
	xchg->sid = lport->nport_id;
	xchg->did = rport->nport_id;
	xchg->private[PKG_PRIVATE_XCHG_RPORT_INDEX] = rport->rport_index;
	xchg->world_id = v_scsi_cmnd->world_id;
	xchg->cmnd_sn = v_scsi_cmnd->cmnd_sn;
	xchg->scsi_id = v_scsi_cmnd->scsi_id;

	/* Build Xchg fcp_cmnd */
	result = unf_build_xchg_fcp_cmnd(&xchg->fcp_cmnd, v_scsi_cmnd);
	if (unlikely(result != RETURN_OK))
		return UNF_RETURN_ERROR;

	unf_adjust_xchg_len(xchg, UNF_GET_FCP_CMND(v_scsi_cmnd));

	/* Dif (control) info */
	unf_copy_dif_control(&xchg->dif_control, v_scsi_cmnd);
	memcpy(&xchg->dif_info, &v_scsi_cmnd->dif_info,
	       sizeof(struct dif_info_s));
	unf_adjsut_dif_pci_transfer_len(xchg,
					UNF_GET_DATA_DIRECTION(v_scsi_cmnd));

	/* single sgl info */
	if ((xchg->data_direction != DMA_NONE) &&
	    (UNF_GET_CMND_SGL(v_scsi_cmnd))) {
		xchg->req_sgl_info.sgl = UNF_GET_CMND_SGL(v_scsi_cmnd);
		/* Save the sgl header for easy location and printing. */
		xchg->req_sgl_info.sgl_start = xchg->req_sgl_info.sgl;
		xchg->req_sgl_info.req_index = 0;
		xchg->req_sgl_info.entry_index = 0;
	}

	if (v_scsi_cmnd->dif_control.dif_sgl) {
		xchg->dif_sgl_info.sgl = UNF_INI_GET_DIF_SGL(v_scsi_cmnd);
		xchg->dif_sgl_info.entry_index = 0;
		xchg->dif_sgl_info.req_index = 0;
		xchg->dif_sgl_info.sgl_start = xchg->dif_sgl_info.sgl;
	}

	return RETURN_OK;
}

static int unf_send_fcp_cmnd(struct unf_lport_s *v_lport,
			     struct unf_rport_s *v_rport,
			     struct unf_xchg_s *v_xchg)
{
	struct unf_scsi_cmd_info_s *scsi_cmnd_info = NULL;
	struct unf_lport_s *lport = v_lport;
	struct unf_rport_s *rport = v_rport;
	struct unf_xchg_s *xchg = v_xchg;
	struct unf_frame_pkg_s pkg = { 0 };
	unsigned int result;
	unsigned long flags = 0;

	memcpy(&pkg.dif_control, &xchg->dif_control,
	       sizeof(struct unf_dif_control_info_s));
	pkg.dif_control.fcp_dl = xchg->dif_control.fcp_dl;
	pkg.transfer_len = xchg->data_len; /* Pcie data transfer length */
	pkg.xchg_contex = xchg;
	pkg.qos_level = 0;
	pkg.entry_count = xchg->scsi_cmnd_info.entry_cnt;
	scsi_cmnd_info = &v_xchg->scsi_cmnd_info;
	if ((xchg->data_direction == DMA_NONE) || (!scsi_cmnd_info->sgl))
		pkg.entry_count = 0;

	pkg.private[PKG_PRIVATE_XCHG_ALLOC_TIME] =
		xchg->private[PKG_PRIVATE_XCHG_ALLOC_TIME];
	pkg.private[PKG_PRIVATE_XCHG_VP_INDEX] = lport->vp_index;
	pkg.private[PKG_PRIVATE_XCHG_RPORT_INDEX] = rport->rport_index;
	pkg.private[PKG_PRIVATE_XCHG_HOT_POOL_INDEX] = xchg->hot_pool_tag;

	pkg.fcp_cmnd = &xchg->fcp_cmnd;
	pkg.frame_head.csctl_sid = lport->nport_id;
	pkg.frame_head.rctl_did = rport->nport_id;
	pkg.upper_cmd = xchg->scsi_cmnd_info.scsi_cmnd;

	/* exch->fcp_rsp_id --->>> pkg->buffer_ptr */
	pkg.unf_rsp_pload_bl.buffer_ptr =
		(unsigned char *)
		v_xchg->fcp_sfs_union.fcp_rsp_entry.fcp_rsp_iu;
	pkg.unf_rsp_pload_bl.buf_dma_addr =
		 v_xchg->fcp_sfs_union.fcp_rsp_entry.fcp_rsp_iu_phy_addr;
	pkg.unf_rsp_pload_bl.length = PAGE_SIZE;

	pkg.frame_head.oxid_rxid =
		((unsigned int)xchg->ox_id << 16 | xchg->rx_id);

	UNF_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_EQUIP_ATT, UNF_INFO,
		  "[info]LPort (0x%p), Nport ID(0x%x) RPort ID(0x%x) direction(0x%x) magic number(0x%x) send IO to OX_ID(0x%x) entry count(0x%x) tag(0x%x)",
		  lport, lport->nport_id, rport->nport_id,
		  v_xchg->data_direction,
		  pkg.private[PKG_PRIVATE_XCHG_ALLOC_TIME],
		  v_xchg->ox_id, pkg.entry_count, xchg->hot_pool_tag);

	atomic_inc(&rport->pending_io_cnt);
	if ((rport->tape_support_needed == UNF_TRUE) &&
	    (atomic_read(&rport->pending_io_cnt) <= 3)) {
		spin_lock_irqsave(&xchg->xchg_state_lock, flags);
		v_xchg->io_state |= INI_IO_STATE_REC_TIMEOUT_WAIT;
		spin_unlock_irqrestore(&xchg->xchg_state_lock, flags);
		scsi_cmnd_info->abort_timeout = scsi_cmnd_info->time_out;
		scsi_cmnd_info->time_out = UNF_REC_TOV;
	}

	/* 3. add INI I/O timer if necessary */
	if (scsi_cmnd_info->time_out != 0) {
		/* I/O inner timer, do not used at this time */
		lport->xchg_mgr_temp.pfn_unf_xchg_add_timer(
			xchg,
			scsi_cmnd_info->time_out,
			UNF_TIMER_TYPE_REQ_IO);
	}

	/* 4. R_Port state check */
	if (unlikely((rport->lport_ini_state != UNF_PORT_STATE_LINKUP) ||
		     (rport->rp_state > UNF_RPORT_ST_READY))) {
		UNF_TRACE(UNF_EVTLOG_IO_WARN, UNF_LOG_IO_ATT, UNF_WARN,
			  "[info]Port(0x%x) RPort(0x%p) NPortId(0x%x) inistate(0x%x): RPort state(0x%x) upper_cmd(0x%p) is not ready",
			  lport->port_id, rport, rport->nport_id,
			  rport->lport_ini_state, rport->rp_state,
			  pkg.upper_cmd);

		result = unf_get_uplevel_cmnd_errcode(
				scsi_cmnd_info->err_code_table,
				scsi_cmnd_info->err_code_table_cout,
				UNF_IO_INCOMPLETE);
		scsi_cmnd_info->result = result;
		if (scsi_cmnd_info->time_out != 0)
			lport->xchg_mgr_temp.pfn_unf_xchg_cancel_timer(xchg);

		unf_cm_free_xchg(lport, xchg);
		/* DID_IMM_RETRY */
		return RETURN_OK;
	} else if (rport->rp_state < UNF_RPORT_ST_READY) {
		UNF_TRACE(UNF_EVTLOG_IO_WARN, UNF_LOG_IO_ATT, UNF_WARN,
			  "[info]Port(0x%x) RPort(0x%p) NPortId(0x%x) inistate(0x%x): RPort state(0x%x) upper_cmd(0x%p) is not ready",
			  lport->port_id, rport, rport->nport_id,
			  rport->lport_ini_state, rport->rp_state,
			  pkg.upper_cmd);

		spin_lock_irqsave(&v_xchg->xchg_state_lock, flags);
		xchg->io_state |= INI_IO_STATE_UPSEND_ERR;  /* need retry */
		spin_unlock_irqrestore(&v_xchg->xchg_state_lock, flags);

		if (unlikely(scsi_cmnd_info->time_out != 0))
			lport->xchg_mgr_temp.pfn_unf_xchg_cancel_timer(
				(void *)xchg);

		/* Host busy & need scsi retry */
		return UNF_RETURN_ERROR;
	}

	/* 5. send scsi_cmnd to FC_LL Driver */
	if (unf_hardware_start_io(lport, &pkg) != RETURN_OK) {
		UNF_TRACE(UNF_EVTLOG_IO_WARN, UNF_LOG_IO_ATT, UNF_WARN,
			  "[warn]Port (0x%x) upper_cmd(0x%p) Hardware Send IO failed.",
			  lport->port_id, pkg.upper_cmd);

		unf_release_esgls(xchg);
		result = unf_get_uplevel_cmnd_errcode(
				scsi_cmnd_info->err_code_table,
				scsi_cmnd_info->err_code_table_cout,
				UNF_IO_INCOMPLETE);
		scsi_cmnd_info->result = result;
		if (scsi_cmnd_info->time_out != 0)
			lport->xchg_mgr_temp.pfn_unf_xchg_cancel_timer(xchg);

		unf_cm_free_xchg(lport, xchg);
		/* SCSI_DONE */
		return RETURN_OK;
	}

	return RETURN_OK;
}

int unf_prefer_to_send_scsi_cmnd(struct unf_xchg_s *v_xchg)
{
	/*
	 * About INI_IO_STATE_DRABORT:
	 * 1. Set ABORT tag: Clean L_Port/V_Port Link Down I/O
	 * with: INI_busy_list, delay_list, delay_transfer_list, wait_list
	 *
	 * 2. Set ABORT tag: for target session:
	 * with: INI_busy_list, delay_list, delay_transfer_list, wait_list
	 * a. R_Port remove
	 * b. Send PLOGI_ACC callback
	 * c. RCVD PLOGI
	 * d. RCVD LOGO
	 *
	 * 3. if set ABORT: prevent send scsi_cmnd to target
	 */
	struct unf_lport_s *lport = NULL;
	struct unf_rport_s *rport = NULL;
	int ret;
	unsigned long flags = 0;

	lport = v_xchg->lport;
	rport = v_xchg->rport;
	if (unlikely(!lport || !rport)) {
		UNF_TRACE(UNF_EVTLOG_IO_ERR, UNF_LOG_IO_ATT, UNF_ERR,
			  "[err]Port(0x%p) or RPort(0x%p) is NULL", lport,
			  rport);

		/* if happened (never happen): need retry */
		return UNF_RETURN_ERROR;
	}

	/* 1. inc ref_cnt to protect exchange */
	ret = (int)unf_xchg_ref_inc(v_xchg, INI_SEND_CMND);
	if (unlikely(ret != RETURN_OK)) {
		UNF_TRACE(UNF_EVTLOG_IO_WARN, UNF_LOG_IO_ATT, UNF_WARN,
			  "[warn]Port(0x%x) exhg(%p) exception ref(%d) ",
			  lport->port_id, v_xchg,
			  atomic_read(&v_xchg->ref_cnt));
		/* exchange exception, need retry */
		spin_lock_irqsave(&v_xchg->xchg_state_lock, flags);
		v_xchg->io_state |= INI_IO_STATE_UPSEND_ERR;
		spin_unlock_irqrestore(&v_xchg->xchg_state_lock, flags);

		/* INI_IO_STATE_UPSEND_ERR: Host busy --->>> need retry */
		return UNF_RETURN_ERROR;
	}

	/* 2. Xchg Abort state check: Free EXCH if necessary */
	spin_lock_irqsave(&v_xchg->xchg_state_lock, flags);
	if (unlikely((v_xchg->io_state & INI_IO_STATE_UPABORT) ||
		     (v_xchg->io_state & INI_IO_STATE_DRABORT))) {
		/* Prevent to send: UP_ABORT/DRV_ABORT */
		spin_unlock_irqrestore(&v_xchg->xchg_state_lock, flags);
		v_xchg->scsi_cmnd_info.result = UNF_SCSI_HOST(DID_IMM_RETRY);

		unf_xchg_ref_dec(v_xchg, INI_SEND_CMND);
		unf_cm_free_xchg(lport, v_xchg);

		/*
		 * Release exchange & return directly:
		 * 1. FC LLDD rcvd ABTS before scsi_cmnd: do nothing
		 * 2. INI_IO_STATE_UPABORT/INI_IO_STATE_DRABORT:
		 *    discard this cmnd directly
		 */
		return RETURN_OK;
	}
	spin_unlock_irqrestore(&v_xchg->xchg_state_lock, flags);

	/* 3. Send FCP_CMND to FC_LL Driver */
	ret = unf_send_fcp_cmnd(lport, rport, v_xchg);
	if (unlikely(ret != RETURN_OK)) {
		/* exchange exception, need retry */
		UNF_TRACE(UNF_EVTLOG_IO_WARN, UNF_LOG_IO_ATT, UNF_WARN,
			  "[warn]Port(0x%x) send exhg(%p) OX_ID(0x%x) RX_ID(0x%x) to Rport(%p) NPortID(0x%x) state(0x%x) scsi_id(0x%x) failed",
			  lport->port_id, v_xchg, v_xchg->ox_id,
			  v_xchg->rx_id,
			  rport, rport->nport_id, rport->rp_state,
			  rport->scsi_id);

		spin_lock_irqsave(&v_xchg->xchg_state_lock, flags);
		v_xchg->io_state |= INI_IO_STATE_UPSEND_ERR;  /* need retry */
		spin_unlock_irqrestore(&v_xchg->xchg_state_lock, flags);

		/* INI_IO_STATE_UPSEND_ERR: Host busy --->>> need retry */
		unf_cm_free_xchg(lport, v_xchg);
	}

	/* 4. dec ref_cnt */
	unf_xchg_ref_dec(v_xchg, INI_SEND_CMND);

	return ret;
}

struct unf_lport_s *unf_find_lport_by_scsi_cmd(
					struct unf_scsi_cmd_s *v_scsi_cmnd)
{
	struct unf_lport_s *lport = NULL;

	/* cmd -->> L_Port */
	lport = (struct unf_lport_s *)UNF_GET_HOST_PORT_BY_CMND(v_scsi_cmnd);
	if (unlikely(!lport)) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT, UNF_WARN,
			  "[warn]Find Port by scsi_cmnd(0x%p) failed",
			  v_scsi_cmnd);

		/* cmnd -->> scsi_host_id -->> L_Port */
		lport = unf_find_lport_by_scsi_host_id(
				UNF_GET_SCSI_ID_BY_CMND(v_scsi_cmnd));
	}
	return lport;
}

int unf_cm_queue_command(struct unf_scsi_cmd_s *v_scsi_cmnd)
{
	/* SCSI Command --->>> FC FCP Command */
	struct unf_lport_s *lport = NULL;
	struct unf_xchg_s *xchg = NULL;
	struct unf_rport_s *rport = NULL;
	struct unf_rport_scsi_id_image_s *scsi_image_table = NULL;
	unsigned int result = 0;
	int ret;
	unsigned long flags = 0;
	unsigned int scsi_id;
	unsigned int exhg_mgr_type = UNF_XCHG_MGR_TYPE_RANDOM;

	/* 1. Get L_Port */
	lport = unf_find_lport_by_scsi_cmd(v_scsi_cmnd);

	/*
	 * corresponds to the insertion or removal scenario or
	 * the remove card scenario.
	 * This method is used to search for LPort information
	 * based on SCSI_HOST_ID.
	 * The Slave alloc is not invoked when LUNs are not scanned.
	 * Therefore, the Lport cannot be obtained.
	 * You need to obtain the Lport from the Lport linked list.
	 *
	 *  FC After Link Up, the first SCSI command is inquiry.
	 *  Before inquiry, SCSI delivers slave_alloc.
	 */
	if (!lport) {
		UNF_TRACE(UNF_EVTLOG_IO_ERR, UNF_LOG_IO_ATT, UNF_ERR,
			  "[err]Find Port by scsi cmd(0x%p) failed",
			  v_scsi_cmnd);

		/* find from ini_error_code_table1 */
		result = unf_get_uplevel_cmnd_errcode(
				v_scsi_cmnd->err_code_table,
				v_scsi_cmnd->err_code_table_cout,
				UNF_IO_NO_LPORT);  /* did_not_connect */

		/* DID_NOT_CONNECT & SCSI_DONE & RETURN_OK(0) & I/O error */
		unf_complete_cmnd(v_scsi_cmnd, result);
		return RETURN_OK;
	}

	/* Get Local SCSI_Image_table & SCSI_ID */
	scsi_image_table = &lport->rport_scsi_table;
	scsi_id = v_scsi_cmnd->scsi_id;

	/* 2. L_Port State check */
	if (unlikely((lport->b_port_removing == UNF_TRUE) ||
		     (lport->b_pcie_linkdown == UNF_TRUE))) {
		UNF_TRACE(UNF_EVTLOG_IO_WARN, UNF_LOG_IO_ATT, UNF_WARN,
			  "[warn]Port(0x%x) is removing(%d) or pcielinkdown(%d) and return with scsi_id(0x%x)",
			  lport->port_id, lport->b_port_removing,
			  lport->b_pcie_linkdown,
			  UNF_GET_SCSI_ID_BY_CMND(v_scsi_cmnd));

		result = unf_get_uplevel_cmnd_errcode(
				v_scsi_cmnd->err_code_table,
				v_scsi_cmnd->err_code_table_cout,
				UNF_IO_NO_LPORT);  /* did_not_connect */

		UNF_IO_RESULT_CNT(scsi_image_table, scsi_id, (result >> 16));

		/* DID_NOT_CONNECT & SCSI_DONE & RETURN_OK(0) & I/O error */
		unf_complete_cmnd(v_scsi_cmnd, result);
		return RETURN_OK;
	}

	/* 3. Get R_Port */
	rport = unf_find_rport_by_scsi_id(lport,
					  v_scsi_cmnd->err_code_table,
					  v_scsi_cmnd->err_code_table_cout,
					  UNF_GET_SCSI_ID_BY_CMND(v_scsi_cmnd),
					  &result);
	if (unlikely(!rport)) {
		/* never happen: do not care */
		UNF_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_LOGIN_ATT, UNF_ERR,
			  "[err]Port(0x%x) find RPort by scsi_id(0x%x) failed",
			  lport->port_id,
			  UNF_GET_SCSI_ID_BY_CMND(v_scsi_cmnd));

		UNF_IO_RESULT_CNT(scsi_image_table, scsi_id, (result >> 16));

		/* DID_NOT_CONNECT/DID_SOFT_ERROR & SCSI_DONE &
		 * RETURN_OK(0) & I/O error
		 */
		unf_complete_cmnd(v_scsi_cmnd, result);
		return RETURN_OK;
	}

	/* 4. Can't get exchange & retrun host busy, retry by uplevel */
	xchg = (struct unf_xchg_s *)unf_cm_get_free_xchg(
				lport,
				exhg_mgr_type << 16 | UNF_XCHG_TYPE_INI);
	if (unlikely(!xchg)) {
		UNF_TRACE(UNF_EVTLOG_IO_WARN, UNF_LOG_IO_ATT, UNF_WARN,
			  "[err]Port(0x%x) get free exchange for INI IO(0x%x) failed",
			  lport->port_id,
			  UNF_GET_SCSI_ID_BY_CMND(v_scsi_cmnd));

		/* NOTE: need scsi retry */
		return UNF_RETURN_ERROR;
	}

	xchg->scsi_cmnd_info.result = UNF_SCSI_HOST(DID_ERROR);
	/* 5. Save the SCSI CMND information in advance. */
	ret = unf_save_scsi_cmnd_to_xchg(lport, rport, xchg, v_scsi_cmnd);
	if (unlikely(ret != RETURN_OK)) {
		UNF_TRACE(UNF_EVTLOG_IO_WARN, UNF_LOG_IO_ATT, UNF_WARN,
			  "[err]Port(0x%x) save scsi_cmnd info(0x%x) to exchange failed",
			  lport->port_id,
			  UNF_GET_SCSI_ID_BY_CMND(v_scsi_cmnd));

		spin_lock_irqsave(&xchg->xchg_state_lock, flags);
		xchg->io_state |= INI_IO_STATE_UPSEND_ERR;
		spin_unlock_irqrestore(&xchg->xchg_state_lock, flags);

		/* INI_IO_STATE_UPSEND_ERR: Don't Do SCSI_DONE,
		 * need retry I/O
		 */
		unf_cm_free_xchg(lport, xchg);
		/* NOTE: need scsi retry */
		return UNF_RETURN_ERROR;
	}

	UNF_TRACE(UNF_EVTLOG_IO_INFO, UNF_LOG_IO_ATT, UNF_INFO,
		  "[info]Get exchange(0x%p) OX_ID(0x%x) RX_ID(0x%x) hot_pool_tag(0x%x) for Pcmd:%p,Cmdsn:0x%lx,WorldId:%u",
		  xchg, xchg->ox_id, xchg->rx_id,
		  xchg->hot_pool_tag, v_scsi_cmnd->upper_cmnd,
		  (unsigned long)v_scsi_cmnd->cmnd_sn,
		  v_scsi_cmnd->world_id);
	/* 6. Send SCSI CMND */
	ret = unf_prefer_to_send_scsi_cmnd(xchg);
	return ret;
}
