// SPDX-License-Identifier: GPL-2.0
/* Huawei Hifc PCI Express Linux driver
 * Copyright(c) 2017 Huawei Technologies Co., Ltd
 *
 */
#include "hifc_module.h"
#include "hifc_utils.h"
#include "hifc_hba.h"
#include "hifc_chipitf.h"
#include "hifc_portmng.h"

struct hifc_port_diag_op_s hifc_diag_op[] = {
	{ UNF_PORT_DIAG_PORT_DETAIL, hifc_show_fc_port_detail },
	{ UNF_PORT_DIAG_RD_WR_REG, hifc_rw_reg },
	{ UNF_PORT_DIAG_BUTT, NULL }
};

char *wqe_type[HIFC_MAX_COUNTER_TYPE] = {
	"TASK_TYPE_EMPTY",
	"HIFC_SEND_IWRITE",
	"HIFC_SEND_IREAD",
	"HIFC_RECV_IRESP",
	/* obsoleted */
	"HIFC_RECV_TCMND",
	/* FCP Read IO Control Command. */
	"HIFC_SEND_TREAD",
	/* FCP Write IO Control Command (XFER_RDY). */
	"HIFC_SEND_TWRITE",
	/* Target Mode send FCP_RESP of Read/Write */
	"HIFC_SEND_TRESP",
	/* Status for FCP_TREAD/FCP_TWRITE/FCP_TRESP */
	"HIFC_RECV_TSTS",
	"HIFC_SEND_ABTS",
	"HIFC_SEND_IELS",
	"HIFC_SEND_ITMF",
	"HIFC_SEND_CLEAN_UP",
	"HIFC_SEND_CLEAN_UP_ALL",
	/* Receive unsolicited data */
	"HIFC_RECV_UNSOLICITED",
	"HIFC_RECV_ERR_WARN",
	"HIFC_RECV_SESS_EN",
	"HIFC_SEND_SESS_DIS",
	"HIFC_SEND_SESS_DEL",
	"HIFC_SEND_CQE_AVAILABLE",
	/* Receive FCP_CMND From Remote Port and Transfer to driver. 20 */
	"HIFC_RECV_TCMND",
	/* Receive ELS From Remote Port and Transfer to driver. */
	"HIFC_RECV_ELS_CMD",
	/* Receive ELS From Remote Port and Transfer to driver. */
	"HIFC_RECV_ABTS_CMD",
	/* Receive immidiate data. */
	"HIFC_RECV_IMMIDIATE",
	/*
	 * ESL response. PLOGI_ACC, PRLI_ACC will carry the parent context
	 * parameter indication.
	 */
	"HIFC_SEND_ELS_RSP",
	/* Status for ELS. */
	"HIFC_RECV_ELS_RSP_STS",
	/* ABTS response with abort flag. */
	"HIFC_SEND_ABTS_RSP",
	/* Status for ABTS. */
	"HIFC_RECV_ABTS_RSP_STS",
	/* Abort Command */
	"HIFC_SEND_ABORT",
	/* Status for ABORT. */
	"HIFC_RECV_ABORT_STS",

	"HIFC_SEND_ELS",
	"HIFC_RECV_ELS_RSP",
	/* GS request Command */
	"HIFC_SEND_GS",
	/* GS response. */
	"HIFC_RECV_GS_RSP",
	/* Status for offload req. */
	"HIFC_RECV_SESS_EN_STS",
	/* Status for session disable. */
	"HIFC_RECV_SESS_DIS_STS",
	/* Status for session delete. */
	"HIFC_RECV_SESS_DEL_STS",
	/* Status for ABORT. */
	"HIFC_RECV_ABTS_RSP",
	/* Buffer Clear */
	"HIFC_SEND_BUFFER_CLEAR",
	/* Status for Buffer Clear */
	"HIFC_RECV_BUFFER_CLEAR_STS",
	/* Flush Sq 40 */
	"HIFC_SEND_FLUSH_SQ",
	/* Status for FLUSH_SQ */
	"HIFC_RECV_FLUSH_SQ_STS",
	/* Reset session SQE type */
	"HIFC_SEND_SESS_RESET",
	/* Reset session SCQE type */
	"HIFC_RECV_SESS_RESET_STS",
	"HIFC_RECV_CQE_AVAILABLE_STS",
	"HIFC_SEND_DUMP_EXCH",
	"HIFC_SEND_INIT_SRQC",
	"HIFC_SEND_CLEAR_SRQ",
	"HIFC_RECV_CLEAR_SRQ_STS",
	"HIFC_SEND_INIT_SCQC",
	"HIFC_SEND_DEL_SCQC",
	"HIFC_SEND_TMF_RESP",
	"HIFC_SEND_DEL_SRQC",
	"HIFC_RECV_IMMI_CONTINUE",
	"HIFC_RECV_ITMF_RESP",
	"HIFC_RECV_MARKER_STS",
	"HIFC_SEND_TACK",
	"HIFC_SEND_AEQERR",
	"HIFC_RECV_ABTS_MARKER_STS"
};

char *scq_err_type[HIFC_MAX_COUNTER_TYPE] = {
	"HIFC_CQE_COMPLETED",
	"HIFC_SESS_HT_INSERT_FAIL",
	"HIFC_SESS_HT_INSERT_DUPLICATE",
	"HIFC_SESS_HT_BIT_SET_FAIL",
	"HIFC_SESS_HT_DELETE_FAIL",

	"HIFC_CQE_BUFFER_CLEAR_IO_COMPLETED",
	"HIFC_CQE_SESSION_ONLY_CLEAR_IO_COMPLETED",
	"HIFC_CQE_SESSION_RST_CLEAR_IO_COMPLETED",
	"HIFC_CQE_TMF_RSP_IO_COMPLETED",
	"HIFC_CQE_TMF_IO_COMPLETED",
	"HIFC_CQE_DRV_ABORT_IO_COMPLETED",
	"HIFC_CQE_DRV_ABORT_IO_IN_RSP_COMPLETED",
	"HIFC_CQE_DRV_ABORT_IO_IN_CMD_COMPLETED",
	"HIFC_CQE_WQE_FLUSH_IO_COMPLETED",

	"HIFC_ERROR_CODE_DATA_DIFX_FAILED",
	"HIFC_ERROR_CODE_DATA_TASK_TYPE_INCORRECT",
	"HIFC_ERROR_CODE_DATA_OOO_RO",
	"HIFC_ERROR_CODE_DATA_EXCEEDS_DATA2TRNS",

	"HIFC_ERROR_CODE_FCP_RSP_INVALID_LENGTH_FIELD",
	"HIFC_ERROR_CODE_FCP_CONF_NOT_SUPPORTED",
	"HIFC_ERROR_CODE_FCP_RSP_OPENED_SEQ",

	"HIFC_ERROR_CODE_XFER_INVALID_PAYLOAD_SIZE",
	"HIFC_ERROR_CODE_XFER_PEND_XFER_SET",
	"HIFC_ERROR_CODE_XFER_OOO_RO",
	"HIFC_ERROR_CODE_XFER_NULL_BURST_LEN",

	"HIFC_ERROR_CODE_REC_TIMER_EXPIRE",
	"HIFC_ERROR_CODE_E_D_TIMER_EXPIRE",
	"HIFC_ERROR_CODE_ABORT_TIMER_EXPIRE",
	"HIFC_ERROR_CODE_ABORT_MAGIC_NUM_NOT_MATCH",
	"HIFC_IMMI_CMDPKT_SETUP_FAIL",
	"HIFC_ERROR_CODE_DATA_SEQ_ID_NOT_EQUAL",

	"HIFC_ELS_GS_RSP_EXCH_CHECK_FAIL",
	"HIFC_CQE_ELS_GS_SRQE_GET_FAIL",
	"HIFC_CQE_DATA_DMA_REQ_FAIL",
	"HIFC_CQE_SESSION_CLOSED",
	"HIFC_SCQ_IS_FULL",
	"HIFC_SRQ_IS_FULL",
	"HIFC_DUCHILDCTX_SETUP_FAIL",
	"HIFC_ERROR_INVALID_TXMFS",
	"HIFC_OFFLOAD_LACKOF_SCQE_FAIL",
	"HIFC_INVALID_TASK_ID",
	"HIFC_INVALID_PKT_LEN",
	"HIFC_CQE_ELS_GS_REQ_CLR_IO_COMPLETED",
	"HIFC_CQE_ELS_RSP_CLR_IO_COMPLETED",
	"HIFC_CODE_RESID_UNDER_ERR"
};

char *com_up_err_event_type[HIFC_MAX_COUNTER_TYPE] = {
	"HIFC_EVENT_HEART_LOST",
};

char *aeq_err_type[HIFC_MAX_COUNTER_TYPE] = {
	/* que_err_code */
	"HIFC_SCQ_IS_FULL_ERR",
	"HIFC_SRQ_IS_FULL_ERR",
	/* wqe_fatal_err */
	"HIFC_SQE_CHILD_SETUP_WQE_MSN_ERR",
	"HIFC_SQE_CHILD_SETUP_WQE_GPA_ERR",
	"HIFC_CMDPKT_CHILD_SETUP_INVALID_WQE_ERR_1",
	"HIFC_CMDPKT_CHILD_SETUP_INVALID_WQE_ERR_2",
	"HIFC_CLEAEQ_WQE_ERR",
	"HIFC_WQEFETCH_WQE_MSN_ERR",
	"HIFC_WQEFETCH_QUINFO_ERR",

	/* ctx_fatal_err */
	"HIFC_SCQE_ERR_BIT_ERR",
	"HIFC_UPDMA_ADDR_REQ_SRQ_ERR",
	"HIFC_SOLICHILDDMA_ADDR_REQ_ERR",
	"HIFC_UNSOLICHILDDMA_ADDR_REQ_ERR",
	"HIFC_SQE_CHILD_SETUP_QINFO_ERR_1",
	"HIFC_SQE_CHILD_SETUP_QINFO_ERR_2",
	"HIFC_CMDPKT_CHILD_SETUP_QINFO_ERR_1",
	"HIFC_CMDPKT_CHILD_SETUP_QINFO_ERR_2",
	"HIFC_CMDPKT_CHILD_SETUP_PMSN_ERR",
	"HIFC_CLEAEQ_CTX_ERR",
	"HIFC_WQEFETCH_CTX_ERR",
	"HIFC_FLUSH_QPC_ERR_LQP",
	"HIFC_FLUSH_QPC_ERR_SMF",
	"HIFC_PREFETCH_QPC_ERR_1",
	"HIFC_PREFETCH_QPC_ERR_2",
	"HIFC_PREFETCH_QPC_ERR_3",
	"HIFC_PREFETCH_QPC_ERR_4",
	"HIFC_PREFETCH_QPC_ERR_5",
	"HIFC_PREFETCH_QPC_ERR_6",
	"HIFC_PREFETCH_QPC_ERR_7",
	"HIFC_PREFETCH_QPC_ERR_8",
	"HIFC_PREFETCH_QPC_ERR_9",
	"HIFC_PREFETCH_QPC_ERR_10",
	"HIFC_PREFETCH_QPC_ERR_11",
	"HIFC_PREFETCH_QPC_ERR_DEFAULT",
	"HIFC_CHILDHASH_INSERT_SW_ERR",
	"HIFC_CHILDHASH_LOOKUP_SW_ERR",
	"HIFC_CHILDHASH_DEL_SW_ERR",
	"HIFC_FLOWHASH_INSERT_SW_ERR",
	"HIFC_FLOWHASH_LOOKUP_SW_ERR",
	"HIFC_FLOWHASH_DEL_SW_ERR",
};

char *err_event_type[HIFC_MAX_COUNTER_TYPE] = {
	/* ERR type 0 Err value */
	"HIFC_DRV_2_UP_PARA_ERR",
	/* ERR type 1 Err value */
	"HIFC_SFP_SPEED_ERR",
	/* ERR type 2 Err value */
	"HIFC_32GPUB_UA_RXESCH_FIFO_OF",
	"HIFC_32GPUB_UA_RXESCH_FIFO_UCERR",

	/* ERR type 3 Err value */
	"HIFC_32G_UA_UATX_LEN_ABN",
	"HIFC_32G_UA_RXAFIFO_OF",
	"HIFC_32G_UA_TXAFIFO_OF",
	"HIFC_32G_UA_RXAFIFO_UCERR",
	"HIFC_32G_UA_TXAFIFO_UCERR",

	/* ERR type 4 Err value */
	"HIFC_32G_MAC_RX_BBC_FATAL",
	"HIFC_32G_MAC_TX_BBC_FATAL",
	"HIFC_32G_MAC_TXFIFO_UF",
	"HIFC_32G_MAC_PCS_TXFIFO_UF",
	"HIFC_32G_MAC_RXBBC_CRDT_TO",
	"HIFC_32G_MAC_PCS_RXAFIFO_OF",
	"HIFC_32G_MAC_PCS_TXFIFO_OF",
	"HIFC_32G_MAC_FC2P_RXFIFO_OF",
	"HIFC_32G_MAC_FC2P_TXFIFO_OF",
	"HIFC_32G_MAC_FC2P_CAFIFO_OF",
	"HIFC_32G_MAC_PCS_RXRSFECM_UCEER",
	"HIFC_32G_MAC_PCS_RXAFIFO_UCEER",
	"HIFC_32G_MAC_PCS_TXFIFO_UCEER",
	"HIFC_32G_MAC_FC2P_RXFIFO_UCEER",
	"HIFC_32G_MAC_FC2P_TXFIFO_UCEER",

	/* ERR type 5 Err value */
	"HIFC_NON32G_DFX_FC1_DFX_BF_FIFO",
	"HIFC_NON32G_DFX_FC1_DFX_BP_FIFO",
	"HIFC_NON32G_DFX_FC1_DFX_RX_AFIFO_ERR",
	"HIFC_NON32G_DFX_FC1_DFX_TX_AFIFO_ERR",
	"HIFC_NON32G_DFX_FC1_DFX_DIRQ_RXBUF_FIFO1",
	"HIFC_NON32G_DFX_FC1_DFX_DIRQ_RXBBC_TO",
	"HIFC_NON32G_DFX_FC1_DFX_DIRQ_TXDAT_FIFO",
	"HIFC_NON32G_DFX_FC1_DFX_DIRQ_TXCMD_FIFO",
	"HIFC_NON32G_DFX_FC1_ERR_R_RDY",

	/* ERR type 6 Err value */
	"HIFC_NON32G_MAC_FC1_FAIRNESS_ERROR",
};

unsigned int hifc_set_port_state(void *v_hba, void *v_para_in)
{
	unsigned int ret = UNF_RETURN_ERROR;
	enum unf_port_config_state_e port_state = UNF_PORT_CONFIG_STATE_START;

	HIFC_CHECK(INVALID_VALUE32, NULL != v_hba, return UNF_RETURN_ERROR);
	HIFC_CHECK(INVALID_VALUE32, NULL != v_para_in, return UNF_RETURN_ERROR);

	port_state = *((enum unf_port_config_state_e *)v_para_in);
	switch (port_state) {
	case UNF_PORT_CONFIG_STATE_RESET:
		ret = (unsigned int)hifc_port_reset(v_hba);
		break;
	default:
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_REG_ATT, UNF_WARN,
			  "[warn]Cannot set port_state(0x%x)", port_state);
		break;
	}

	return ret;
}

unsigned int hifc_set_port_speed(void *v_hba, void *v_para_in)
{
	unsigned long flags = 0;
	unsigned int port_speed = 0;
	struct hifc_hba_s *hba = v_hba;

	HIFC_CHECK(INVALID_VALUE32, NULL != hba, return UNF_RETURN_ERROR);
	HIFC_CHECK(INVALID_VALUE32, NULL != v_para_in, return UNF_RETURN_ERROR);
	port_speed = *((unsigned int *)v_para_in);

	if (port_speed > hba->max_support_speed) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_REG_ATT, UNF_WARN,
			  "[warn]Speed set(0x%x) exceed max speed(0x%x)",
			  port_speed,
			  hba->max_support_speed);
		return UNF_RETURN_ERROR;
	}

	if ((port_speed >= HIFC_SPEED_16G) &&
	    (hba->port_topo_cfg == UNF_TOP_LOOP_MASK)) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_REG_ATT, UNF_WARN,
			  "[warn]Cannot set speed(0x%x) in LOOP mode, check it",
			  port_speed);

		return UNF_RETURN_ERROR;
	}

	spin_lock_irqsave(&hba->hba_lock, flags);
	hba->port_speed_cfg = port_speed;
	spin_unlock_irqrestore(&hba->hba_lock, flags);

	if (hifc_port_reset(hba) != RETURN_OK) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_REG_ATT, UNF_ERR,
			  "[err]HIFC port(0x%x) can't reset HBA",
			  hba->port_cfg.port_id);

		return UNF_RETURN_ERROR;
	}

	UNF_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_REG_ATT, UNF_INFO,
		  "[info]HIFC port(0x%x) set port speed finished, configured speed: 0x%x",
		  hba->port_cfg.port_id, port_speed);

	return RETURN_OK;
}

unsigned int hifc_set_max_support_speed(void *v_hba, void *para_in)
{
	unsigned long flags = 0;
	unsigned char max_support_speed = 0;
	struct hifc_hba_s *hba = v_hba;

	HIFC_CHECK(INVALID_VALUE32, NULL != hba, return UNF_RETURN_ERROR);
	HIFC_CHECK(INVALID_VALUE32, NULL != para_in, return UNF_RETURN_ERROR);
	max_support_speed = *((unsigned char *)para_in);

	spin_lock_irqsave(&hba->hba_lock, flags);
	hba->max_support_speed = max_support_speed;
	spin_unlock_irqrestore(&hba->hba_lock, flags);

	if (hifc_port_reset(hba) != RETURN_OK) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_REG_ATT, UNF_ERR,
			  "[err]HIFC port(0x%x) can't reset HBA",
			  hba->port_cfg.port_id);
		return UNF_RETURN_ERROR;
	}

	UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_REG_ATT, UNF_INFO,
		  "[info]HIFC set port(0x%x) speed finished, configured max support speed: 0x%x",
		  hba->port_cfg.port_id, max_support_speed);

	return RETURN_OK;
}

unsigned int hifc_set_loop_role(void *v_hba, void *para_in)
{
	unsigned long flags = 0;
	unsigned int loop_role = 0;
	struct hifc_hba_s *hba = v_hba;

	HIFC_CHECK(INVALID_VALUE32, NULL != hba, return UNF_RETURN_ERROR);
	HIFC_CHECK(INVALID_VALUE32, NULL != para_in, return UNF_RETURN_ERROR);

	loop_role = *((unsigned int *)para_in);

	spin_lock_irqsave(&hba->hba_lock, flags);
	hba->port_loop_role = loop_role;
	spin_unlock_irqrestore(&hba->hba_lock, flags);

	if (hifc_port_reset(hba) != RETURN_OK) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_REG_ATT, UNF_ERR,
			  "[err]HIFC port(0x%x) can't reset HBA",
			  hba->port_cfg.port_id);

		return UNF_RETURN_ERROR;
	}

	UNF_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_REG_ATT, UNF_INFO,
		  "[info]HIFC port(0x%x) set loop role finished, configured loop role: 0x%x",
		  hba->port_cfg.port_id, loop_role);

	return RETURN_OK;
}

unsigned int hifc_set_port_topo(void *v_hba, void *v_para_in)
{
	unsigned long flags = 0;
	unsigned int top = 0;
	struct hifc_hba_s *hba = v_hba;

	HIFC_CHECK(INVALID_VALUE32, NULL != hba, return UNF_RETURN_ERROR);
	HIFC_CHECK(INVALID_VALUE32, NULL != v_para_in, return UNF_RETURN_ERROR);

	top = *((unsigned int *)v_para_in);
	if ((top == UNF_TOP_LOOP_MASK) &&
	    (hba->port_speed_cfg >= HIFC_SPEED_16G)) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_REG_ATT, UNF_ERR,
			  "[err]Cannot set to loop mode at speed(0x%x), check it",
			  hba->port_speed_cfg);

		return UNF_RETURN_ERROR;
	}

	spin_lock_irqsave(&hba->hba_lock, flags);
	hba->port_topo_cfg = top;
	spin_unlock_irqrestore(&hba->hba_lock, flags);

	if (hifc_port_reset(hba) != RETURN_OK) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_REG_ATT, UNF_ERR,
			  "[err]HIFC port(0x%x) can't reset HBA",
			  hba->port_cfg.port_id);

		return UNF_RETURN_ERROR;
	}

	UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_REG_ATT, UNF_INFO,
		  "[info]HIFC port(0x%x) set port topology finished, configured topology: 0x%x",
		  hba->port_cfg.port_id, top);

	return RETURN_OK;
}

unsigned int hifc_set_port_fcp_conf(void *v_hba, void *para_in)
{
	unsigned long flags = 0;
	unsigned int fcp_conf = 0;
	struct hifc_hba_s *hba = v_hba;

	HIFC_CHECK(INVALID_VALUE32, hba, return UNF_RETURN_ERROR);
	 HIFC_CHECK(INVALID_VALUE32, para_in, return UNF_RETURN_ERROR);

	fcp_conf = *((unsigned int *)para_in);

	spin_lock_irqsave(&hba->hba_lock, flags);
	hba->fcp_conf_cfg = fcp_conf;
	spin_unlock_irqrestore(&hba->hba_lock, flags);

	UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_REG_ATT, UNF_INFO,
		  "[info]HIFC set port(0x%x) FCP confirm finished, configured value: 0x%x",
		  hba->port_cfg.port_id, fcp_conf);

	return RETURN_OK;
}

unsigned int hifc_set_port_bbscn(void *v_hba, void *para_in)
{
	unsigned long flags = 0;
	unsigned int bbscn = 0;
	struct hifc_hba_s *hba = v_hba;

	HIFC_CHECK(INVALID_VALUE32, NULL != hba, return UNF_RETURN_ERROR);
	HIFC_CHECK(INVALID_VALUE32, NULL != para_in, return UNF_RETURN_ERROR);

	bbscn = *((unsigned int *)para_in);

	spin_lock_irqsave(&hba->hba_lock, flags);
	hba->port_bbscn_cfg = bbscn;
	spin_unlock_irqrestore(&hba->hba_lock, flags);

	if (hifc_port_reset(hba) != RETURN_OK) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_REG_ATT, UNF_ERR,
			  "[err]HIFC port(0x%x) can't reset HBA",
			  hba->port_cfg.port_id);

		return UNF_RETURN_ERROR;
	}

	UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_REG_ATT, UNF_INFO,
		  "[info]HIFC set port(0x%x) BBSCN finished, configured value: 0x%x",
		  hba->port_cfg.port_id, bbscn);

	return RETURN_OK;
}

unsigned int hifc_show_fc_port_detail(void *v_hba, void *v_para)
{
	struct hifc_fw_ver_detail_s version;
	void *ver_buf = NULL;
	struct unf_fw_version_s *fw_version = (struct unf_fw_version_s *)v_para;

	memset(&version, 0, sizeof(struct hifc_fw_ver_detail_s));
	ver_buf = (void *)(&version);

	/* Obtain UP, ucode and boot version */
	if (hifc_get_software_version(v_hba, ver_buf) != RETURN_OK)
		return UNF_RETURN_ERROR;

	if (fw_version->message_type == UNF_DEBUG_TYPE_MESSAGE)
		memcpy(fw_version->fw_version, version.up_ver, HIFC_VER_LEN);

	return RETURN_OK;
}

unsigned int hifc_port_diagnose(void *v_hba,
				enum unf_port_diag_op_e op_code,
				void *v_para)
{
	unsigned int op_idx = 0;

	HIFC_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_REG_ATT, UNF_MAJOR,
		   "[info]port diagnose succeed, opcode(0x%x), operation ID(0x%x)",
		   op_code, op_idx);
	HIFC_CHECK(INVALID_VALUE32, v_hba, return UNF_RETURN_ERROR);
	HIFC_CHECK(INVALID_VALUE32, v_para, return UNF_RETURN_ERROR);

	for (op_idx = 0; op_idx < sizeof(hifc_diag_op) /
	     sizeof(struct hifc_port_diag_op_s);
		op_idx++) {
		if (op_code == hifc_diag_op[op_idx].op_code) {
			if (!hifc_diag_op[op_idx].pfn_hifc_operation) {
				HIFC_TRACE(UNF_EVTLOG_DRIVER_ERR,
					   UNF_LOG_REG_ATT, UNF_ERR,
					   "[err]Null operation for diagnose, opcode(0x%x), operation ID(0x%x)",
					   op_code, op_idx);

				return UNF_RETURN_ERROR;
			} else {
				return hifc_diag_op[op_idx].pfn_hifc_operation(v_hba, v_para);
			}
		}
	}

	return RETURN_OK;
}

int hifc_dfx_get_rxtx_state(void *v_hba, void *v_buff_out)
{
	int ret = RETURN_OK;
	unsigned long long *counter_info = NULL;
	unsigned int probe_index = 0;
	unsigned int index = 0;
	unsigned int total = 0;
	struct hifc_adm_dfx_cmd_s *buff_out = NULL;
	struct hifc_hba_s *hba = (struct hifc_hba_s *)v_hba;

	buff_out = (struct hifc_adm_dfx_cmd_s *)v_buff_out;

	counter_info =
		vmalloc(sizeof(unsigned long long) * HIFC_DFX_BACK_INFO_SIZE64);
	if (!counter_info) {
		HIFC_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_REG_ATT, UNF_ERR,
			   "[err]malloc memory failed");

		return UNF_RETURN_ERROR;
	}

	memset(counter_info, 0,
	       sizeof(unsigned long long) * HIFC_DFX_BACK_INFO_SIZE64);
	probe_index = hba->probe_index;
	total = sizeof(wqe_type) / sizeof(char *);

	for (index = 0; index < total; index++) {
		if (wqe_type[index])
			counter_info[index] = HIFC_IO_STAT_READ(probe_index,
								index);
	}

	memcpy(buff_out->unresult.result, counter_info,
	       sizeof(unsigned long long) * HIFC_DFX_BACK_INFO_SIZE64);
	vfree(counter_info);
	return ret;
}

int hifc_dfx_get_rxtx_error_state(void *v_hba, void *v_buff_out)
{
	char *hba_err_type[HIFC_HBA_STAT_BUTT];
	int ret = RETURN_OK;
	unsigned long long *counter_info = NULL;
	unsigned int probe_index = 0;
	unsigned int index = 0;
	unsigned int counter = 0;
	unsigned int total = 0;
	struct hifc_adm_dfx_cmd_s *buff_out = NULL;
	struct hifc_hba_s *hba = (struct hifc_hba_s *)v_hba;

	buff_out = (struct hifc_adm_dfx_cmd_s *)v_buff_out;
	counter_info =
		vmalloc(sizeof(unsigned long long) * HIFC_DFX_BACK_INFO_SIZE64);
	if (!counter_info) {
		HIFC_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_REG_ATT, UNF_ERR,
			   "[err]malloc memory failed");
		return UNF_RETURN_ERROR;
	}

	memset(counter_info, 0,
	       sizeof(unsigned long long) * HIFC_DFX_BACK_INFO_SIZE64);
	probe_index = hba->probe_index;
	total = sizeof(wqe_type) / sizeof(char *);

	for (index = 0; index < total; index++) {
		if (wqe_type[index]) {
			counter_info[counter] =
				HIFC_ERR_IO_STAT_READ(probe_index, index);
			counter++;
		}
	}

	total = sizeof(hba_err_type) / sizeof(char *);
	for (index = 0; index < total; index++) {
		counter_info[counter] = hba_stat[probe_index][index];
		counter++;
	}

	memcpy(buff_out->unresult.result, counter_info,
	       sizeof(unsigned long long) * HIFC_DFX_BACK_INFO_SIZE64);
	vfree(counter_info);
	return ret;
}

int hifc_dfx_get_error_state(void *v_hba, void *v_buff_out)
{
	int ret = RETURN_OK;
	unsigned long long *counter_info = NULL;
	unsigned int probe_index = 0;
	unsigned int index = 0;
	unsigned int counter = 0;
	unsigned int total = 0;
	struct hifc_adm_dfx_cmd_s *buff_out = NULL;
	struct hifc_hba_s *hba = (struct hifc_hba_s *)v_hba;

	buff_out = (struct hifc_adm_dfx_cmd_s *)v_buff_out;

	counter_info =
		vmalloc(sizeof(unsigned long long) * HIFC_DFX_BACK_INFO_SIZE64);
	if (!counter_info) {
		HIFC_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_REG_ATT, UNF_ERR,
			   "[err]malloc memory failed");
		return UNF_RETURN_ERROR;
	}
	memset(counter_info, 0,
	       sizeof(unsigned long long) * HIFC_DFX_BACK_INFO_SIZE64);
	probe_index = hba->probe_index;

	total = sizeof(scq_err_type) / sizeof(char *);
	for (index = 1; index < total; index++) {
		if (scq_err_type[index]) {
			counter_info[counter] =
				HIFC_SCQ_ERR_TYPE_STAT_READ(probe_index, index);
			counter++;
		}
	}

	total = sizeof(aeq_err_type) / sizeof(char *);
	for (index = 0; index < total; index++) {
		if (aeq_err_type[index]) {
			counter_info[counter] =
				HIFC_AEQ_ERR_TYPE_STAT_READ(probe_index, index);
			counter++;
		}
	}

	total = sizeof(err_event_type) / sizeof(char *);
	for (index = 0; index < total; index++) {
		if (err_event_type[index]) {
			counter_info[counter] =
				HIFC_UP_ERR_EVENT_STAT_READ(probe_index, index);
			counter++;
		}
	}

	total = sizeof(com_up_err_event_type) / sizeof(char *);
	for (index = 0; index < total; index++) {
		if (com_up_err_event_type[index]) {
			counter_info[counter] =
				HIFC_COM_UP_ERR_EVENT_STAT_READ(probe_index,
								index);
			counter++;
		}
	}

	memcpy(buff_out->unresult.result, counter_info,
	       sizeof(unsigned long long) * HIFC_DFX_BACK_INFO_SIZE64);
	vfree(counter_info);
	return ret;
}

int hifc_dfx_get_link_state(void *v_hba, void *v_buff_out)
{
#define HIFC_LINK_UNKNOW      0
#define HIFC_LINK_UP          1
#define HIFC_LINK_DOWN        2
#define HIFC_FC_DELETE_CMND   3
#define HIFC_LINK_DOWN_REASON 4

	int ret = RETURN_OK;
	unsigned int index;
	unsigned int counter_index;
	unsigned int *counter_info = NULL;
	unsigned int probe_index = 0;
	struct hifc_adm_dfx_cmd_s *buff_out = NULL;
	struct hifc_hba_s *hba = (struct hifc_hba_s *)v_hba;

	buff_out = (struct hifc_adm_dfx_cmd_s *)v_buff_out;
	counter_info = vmalloc(sizeof(unsigned int) * HIFC_DFX_BACK_INFO_SIZE);
	if (!counter_info) {
		HIFC_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_REG_ATT, UNF_ERR,
			   "[err]malloc memory failed");
		return UNF_RETURN_ERROR;
	}

	memset(counter_info, 0, sizeof(unsigned int) * HIFC_DFX_BACK_INFO_SIZE);
	probe_index = hba->probe_index;

	counter_info[HIFC_LINK_UP] =
		(unsigned int)link_event_stat[probe_index][HIFC_LINK_UP];
	counter_info[HIFC_LINK_DOWN] =
		(unsigned int)link_event_stat[probe_index][HIFC_LINK_DOWN];
	counter_info[HIFC_FC_DELETE_CMND] =
		(unsigned int)link_event_stat[probe_index][HIFC_FC_DELETE_CMND];
	counter_info[HIFC_LINK_UNKNOW] =
		(unsigned int)link_event_stat[probe_index][HIFC_LINK_UNKNOW];

	for (index = 0; index < HIFC_MAX_LINK_REASON_CNT; index++) {
		if (link_reason_stat[probe_index][index]) {
			counter_index = HIFC_LINK_DOWN_REASON + index;
			counter_info[counter_index] =
				(unsigned int)
				link_reason_stat[probe_index][index];
		}
	}

	memcpy(buff_out->unresult.result, counter_info,
	       sizeof(unsigned int) * HIFC_DFX_BACK_INFO_SIZE);
	vfree(counter_info);
	return ret;
}

int hifc_dfx_dif_error(void *v_hba, void *v_buff_out, unsigned int v_clear)
{
#define HIFC_MAX_DIF_ERROR_COUNTER 8

	int ret = RETURN_OK;
	unsigned int index = 0;
	unsigned int total = 0;
	unsigned long long *counter_info = NULL;
	unsigned int probe_index = 0;
	struct hifc_adm_dfx_cmd_s *buff_out = NULL;
	struct hifc_hba_s *hba = (struct hifc_hba_s *)v_hba;

	buff_out = (struct hifc_adm_dfx_cmd_s *)v_buff_out;

	counter_info =
		vmalloc(sizeof(unsigned long long) * HIFC_DFX_BACK_INFO_SIZE64);
	if (!counter_info) {
		HIFC_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_REG_ATT, UNF_ERR,
			   "[err]malloc memory failed");
		return UNF_RETURN_ERROR;
	}
	memset(counter_info, 0,
	       sizeof(unsigned long long) * HIFC_DFX_BACK_INFO_SIZE64);

	probe_index = hba->probe_index;

	UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_NORMAL, UNF_MAJOR,
		  "[info]The clear flag of DIF error counter is %u", v_clear);

	if (!v_clear) {
		total = HIFC_MAX_DIF_ERROR_COUNTER;

		for (index = 1; index < total; index++)
			counter_info[index - 1] =
				HIFC_DIF_ERR_STAT_READ(probe_index, index);

		memcpy(buff_out->unresult.result, counter_info,
		       sizeof(unsigned long long) * HIFC_DFX_BACK_INFO_SIZE64);
	} else {
		memset(dif_err_stat[probe_index], 0, sizeof(dif_err_stat[0]));
	}
	vfree(counter_info);
	return ret;
}

int hifc_set_dfx_mode(void *v_hba, struct unf_hinicam_pkg *v_input)
{
	int ret = UNF_RETURN_ERROR;
	unsigned int mode;
	struct hifc_adm_dfx_cmd_s *buff_in = NULL;
	struct hifc_adm_dfx_cmd_s *buff_out = NULL;

	HIFC_CHECK(INVALID_VALUE32, v_input, return UNF_RETURN_ERROR);

	buff_in = v_input->buff_in;
	buff_out = (struct hifc_adm_dfx_cmd_s *)v_input->buff_out;

	HIFC_CHECK(INVALID_VALUE32, buff_in, return UNF_RETURN_ERROR);
	HIFC_CHECK(INVALID_VALUE32, buff_out, return UNF_RETURN_ERROR);
	HIFC_CHECK(INVALID_VALUE32,
		v_input->in_size >= sizeof(struct hifc_adm_dfx_cmd_s),
		return UNF_RETURN_ERROR);
	HIFC_CHECK(INVALID_VALUE32,
		*v_input->out_size >= sizeof(struct hifc_adm_dfx_cmd_s),
		return UNF_RETURN_ERROR);

	buff_out->msg_head.status = HIFC_ADM_MSG_DONE;
	mode = buff_in->cmd[0];
	UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_REG_ATT, UNF_INFO,
		  "[info]Enter DFX mode(%u)", mode);

	switch (mode) {
	/* HBA WQE and SCQE statistic */
	case HIFC_TX_RX_STATE_COUNTER:
		ret = hifc_dfx_get_rxtx_state(v_hba, (void *)buff_out);
		break;

	/* TX and RX error counter, HBA counter */
	case HIFC_TX_RX_ERROR_STATE_COUNTER:
		ret = hifc_dfx_get_rxtx_error_state(v_hba, (void *)buff_out);
		break;

	/* SCQ, AEQ, uP, common uP error counter */
	case HIFC_ERROR_STATE_COUNTER:
		ret = hifc_dfx_get_error_state(v_hba, (void *)buff_out);
		break;

	case HIFC_LINK_STATE_COUNTER:
		ret = hifc_dfx_get_link_state(v_hba, (void *)buff_out);
		break;

	case HIFC_HOST_COUNTER:
	case HIFC_SESSION_COUNTER:
		UNF_LOWLEVEL_TO_CM_HINICADM(ret,
					    ((struct hifc_hba_s *)v_hba)->lport,
					    v_input);
		break;

	case HIFC_DIF_ERROR_COUNTER:
		ret = hifc_dfx_dif_error(v_hba, (void *)buff_out,
					 buff_in->cmd[1]);
		break;

	default:
		break;
	}

	if (ret != RETURN_OK) {
		buff_out->msg_head.status = HIFC_ADM_MSG_FAILED;
		UNF_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_REG_ATT, UNF_ERR,
			  "[warn]Get DFX information failed, mode:0x%0x", mode);
	}

	buff_out->msg_head.size = sizeof(struct hifc_adm_dfx_cmd_s);
	*v_input->out_size = sizeof(struct hifc_adm_dfx_cmd_s);

	return ret;
}

unsigned int hifc_fec_mode(void *v_hba, struct unf_hinicam_pkg *v_input)
{
	unsigned int ret = UNF_RETURN_ERROR;
	unsigned int fec_mode = 0;
	struct hifc_adm_cmd_s *buff_in = NULL;
	struct hifc_adm_cmd_s *buff_out = NULL;
	struct hifc_hba_s *hba = (struct hifc_hba_s *)v_hba;

	HIFC_CHECK(INVALID_VALUE32, NULL != v_input, return UNF_RETURN_ERROR);

	buff_in = v_input->buff_in;
	buff_out = (struct hifc_adm_cmd_s *)v_input->buff_out;

	HIFC_CHECK(INVALID_VALUE32, NULL != buff_in, return UNF_RETURN_ERROR);
	HIFC_CHECK(INVALID_VALUE32, NULL != buff_out, return UNF_RETURN_ERROR);
	HIFC_CHECK(INVALID_VALUE32,
		v_input->in_size >= sizeof(struct hifc_adm_cmd_s),
		return UNF_RETURN_ERROR);
	HIFC_CHECK(INVALID_VALUE32,
		*v_input->out_size >= sizeof(struct hifc_adm_cmd_s),
		return UNF_RETURN_ERROR);

	buff_out->msg_head.status = HIFC_ADM_MSG_DONE;
	fec_mode = buff_in->cmd[0];

	if (fec_mode < HIFC_QUERY_FEC_MODE) {
		ret = hifc_mbx_set_fec((struct hifc_hba_s *)v_hba, fec_mode);
		hba->fec_status = fec_mode;
		if (ret != RETURN_OK) {
			buff_out->msg_head.status = HIFC_ADM_MSG_FAILED;
			UNF_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_REG_ATT,
				  UNF_ERR,
				  "[err]Set fec mode(0x%x) failed", fec_mode);

			return ret;
		}
	} else if (fec_mode == HIFC_QUERY_FEC_MODE) {
		buff_out->cmd[0] = hba->fec_status;
		ret = RETURN_OK;
	}

	buff_out->msg_head.size = sizeof(struct hifc_adm_msg_head_s);
	*v_input->out_size = sizeof(struct hifc_adm_cmd_s);

	return ret;
}

unsigned int hifc_set_hba_base_info(void *v_hba, void *v_para_in)
{
#define HIFC_MML_CLOSE_FEC        0
#define HIFC_MML_OPEN_FEC_VIA_TTS 1
#define HIFC_MML_OPEN_FEC_ONLY    2

	struct unf_port_info_entry_s *port_info = 0;
	struct hifc_hba_s *hba = v_hba;
	unsigned long flags = 0;

	HIFC_CHECK(INVALID_VALUE32, NULL != hba, return UNF_RETURN_ERROR);
	HIFC_CHECK(INVALID_VALUE32, NULL != v_para_in, return UNF_RETURN_ERROR);
	port_info = (struct unf_port_info_entry_s *)v_para_in;

	if (port_info->speed > hba->max_support_speed) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_REG_ATT, UNF_WARN,
			  "[warn]Port(0x%x) Speed set(0x%x) exceed max speed(0x%x)",
			  hba->port_cfg.port_id, port_info->speed,
			  hba->max_support_speed);

		return UNF_RETURN_ERROR;
	}

	if ((port_info->speed >= HIFC_SPEED_16G) &&
	    (port_info->topo == UNF_TOP_LOOP_MASK)) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_REG_ATT, UNF_WARN,
			  "[warn]Port(0x%x) Cannot set speed(0x%x) in LOOP mode, check it",
			  hba->port_cfg.port_id, port_info->speed);

		return UNF_RETURN_ERROR;
	}

	if ((port_info->fec != HIFC_MML_CLOSE_FEC) &&
	    (port_info->fec != HIFC_MML_OPEN_FEC_VIA_TTS) &&
	    (port_info->fec != HIFC_MML_OPEN_FEC_ONLY)) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_REG_ATT, UNF_WARN,
			  "[err]Port(0x%x) parameter error! please input 0,1 or 2!",
			  hba->port_cfg.port_id);

		return UNF_RETURN_ERROR;
	}

	if (hifc_mbx_set_fec(hba, port_info->fec) != RETURN_OK) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_REG_ATT, UNF_WARN,
			  "[err]Port(0x%x) set FEC %u failed.\n",
			  hba->port_cfg.port_id,
			  port_info->fec);

		return UNF_RETURN_ERROR;
	}

	spin_lock_irqsave(&hba->hba_lock, flags);
	hba->port_speed_cfg = port_info->speed;
	hba->port_topo_cfg = port_info->topo;
	hba->port_bbscn_cfg = port_info->bb_scn;
	spin_unlock_irqrestore(&hba->hba_lock, flags);

	return RETURN_OK;
}

unsigned int hifc_bbscn_mode(void *v_hba, struct unf_hinicam_pkg *v_input)
{
	unsigned int ret = UNF_RETURN_ERROR;
	unsigned int bbscn_mode;
	struct hifc_adm_cmd_s *buff_in = NULL;
	struct hifc_adm_cmd_s *buff_out = NULL;
	struct hifc_hba_s *hba = (struct hifc_hba_s *)v_hba;

	HIFC_CHECK(INVALID_VALUE32, NULL != v_input, return UNF_RETURN_ERROR);

	buff_in = v_input->buff_in;
	buff_out = (struct hifc_adm_cmd_s *)v_input->buff_out;

	HIFC_CHECK(INVALID_VALUE32, buff_in, return UNF_RETURN_ERROR);
	HIFC_CHECK(INVALID_VALUE32, buff_out, return UNF_RETURN_ERROR);
	HIFC_CHECK(INVALID_VALUE32,
		v_input->in_size >= sizeof(struct hifc_adm_cmd_s),
		return UNF_RETURN_ERROR);

	HIFC_CHECK(INVALID_VALUE32,
		*v_input->out_size >= sizeof(struct hifc_adm_cmd_s),
		return UNF_RETURN_ERROR);

	buff_out->msg_head.status = HIFC_ADM_MSG_DONE;
	bbscn_mode = buff_in->cmd[0];

	if (bbscn_mode == HIFC_SET_BBSCN_VALUE) {
		UNF_LOWLEVEL_TO_CM_HINICADM(ret, hba->lport, v_input);
	} else if (bbscn_mode == HIFC_QUERY_BBSCN_VALUE) {
		ret = hifc_get_port_info((void *)hba);
		if (hba->phy_link == UNF_PORT_LINK_UP) {
			buff_out->cmd[0] = hba->active_bb_scn;
			buff_out->cmd[1] = hba->port_bbscn_cfg;
		} else {
			buff_out->cmd[0] = UNF_FALSE;
			buff_out->cmd[1] = hba->port_bbscn_cfg;
		}

		buff_out->msg_head.size = sizeof(struct hifc_adm_msg_head_s) +
					  sizeof(unsigned int);
	}

	if (ret != RETURN_OK) {
		buff_out->msg_head.status = HIFC_ADM_MSG_FAILED;
		UNF_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_REG_ATT, UNF_ERR,
			  "[err]Execute BBSCN mode(0x%x) failed", bbscn_mode);

		return ret;
	}

	*v_input->out_size = sizeof(struct hifc_adm_cmd_s);

	return ret;
}

unsigned int hifc_port_stat(void *v_hba, struct unf_hinicam_pkg *v_input)
{
	struct hifc_adm_lsq_info_s *buff_in = NULL;
	struct hifc_adm_lsq_info_s *buff_out = NULL;
	struct hifc_hba_s *hba = (struct hifc_hba_s *)v_hba;
	unsigned int rport_start = 0;
	struct hifc_parent_queue_mgr_s *parent_queue_mgr = NULL;
	unsigned int index = 0;
	unsigned int queue_state[HIFC_QUEUE_STATE_BUTT] = { 0 };
	struct hifc_parent_sq_info_s *sq = NULL;
	int out_standing_cnt = 0;
	unsigned int in_sq_cnt = 0;

	HIFC_CHECK(INVALID_VALUE32, NULL != v_input, return UNF_RETURN_ERROR);
	HIFC_CHECK(INVALID_VALUE32, NULL != v_hba, return UNF_RETURN_ERROR);

	buff_in = v_input->buff_in;
	buff_out = (struct hifc_adm_lsq_info_s *)v_input->buff_out;

	HIFC_CHECK(INVALID_VALUE32, buff_in, return UNF_RETURN_ERROR);
	HIFC_CHECK(INVALID_VALUE32, buff_out, return UNF_RETURN_ERROR);
	HIFC_CHECK(INVALID_VALUE32,
		v_input->in_size >= sizeof(struct hifc_adm_lsq_info_s),
		return UNF_RETURN_ERROR);
	HIFC_CHECK(INVALID_VALUE32,
		*v_input->out_size >= sizeof(struct hifc_adm_lsq_info_s),
		return UNF_RETURN_ERROR);

	rport_start = buff_in->cmd[0];

	parent_queue_mgr = hba->parent_queue_mgr;
	if (!parent_queue_mgr) {
		HIFC_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_REG_ATT, UNF_ERR,
			   "Port 0x%x Parent Queue Manager is Empty",
			   hba->port_cfg.port_id);
		return UNF_RETURN_ERROR;
	}

	for (index = 0; index < UNF_HIFC_MAXRPORT_NUM; index++) {
		if (parent_queue_mgr->parent_queues[index].offload_state <
		    HIFC_QUEUE_STATE_BUTT)
			queue_state[parent_queue_mgr->parent_queues[index].offload_state]++;
	}

	buff_out->port_state.port_id = hba->port_cfg.port_id;
	buff_out->port_state.rport_num =
		(UNF_HIFC_MAXRPORT_NUM - queue_state[HIFC_QUEUE_STATE_FREE]);
	buff_out->port_state.init = queue_state[HIFC_QUEUE_STATE_INITIALIZED];
	buff_out->port_state.offloading =
				queue_state[HIFC_QUEUE_STATE_OFFLOADING];
	buff_out->port_state.offloaded =
				queue_state[HIFC_QUEUE_STATE_OFFLOADED];
	buff_out->port_state.destroying =
				queue_state[HIFC_QUEUE_STATE_DESTROYING];

	index = rport_start;

	if ((index < UNF_HIFC_MAXRPORT_NUM) &&
	    (parent_queue_mgr->parent_queues[index].offload_state !=
	    HIFC_QUEUE_STATE_FREE)) {
		sq = &parent_queue_mgr->parent_queues[index].parent_sq_info;

		buff_out->sq.sq_id = index;
		buff_out->sq.rport_index = sq->rport_index;
		buff_out->sq.xid = sq->context_id;
		buff_out->sq.cid = sq->cache_id;
		buff_out->sq.sid = sq->local_port_id;
		buff_out->sq.did = sq->remote_port_id;
		buff_out->sq.vpid = parent_queue_mgr->parent_queues[index].parent_sq_info.vport_id;
		buff_out->sq.cmd_local_queue_id = parent_queue_mgr->parent_queues[index].parent_cmd_scq_info.local_queue_id;
		buff_out->sq.cmd_cqm_queue_id = parent_queue_mgr->parent_queues[index].parent_cmd_scq_info.cqm_queue_id;
		buff_out->sq.sts_local_queue_id = parent_queue_mgr->parent_queues[index].parent_sts_scq_info.local_queue_id;
		buff_out->sq.sts_cqm_queue_id = parent_queue_mgr->parent_queues[index].parent_sts_scq_info.cqm_queue_id;
		buff_out->sq.cos =
			parent_queue_mgr->parent_queues[index].queue_data_cos;
		buff_out->sq.off_load =
			parent_queue_mgr->parent_queues[index].offload_state;

		out_standing_cnt = atomic_read(&sq->sqe_minus_cqe_cnt);
		/* read memory barrier */
		rmb();
		in_sq_cnt = HIFC_QUEUE_MSN_OFFSET(HIFC_GET_QUEUE_CMSN(sq),
						  sq->last_pmsn);
		/* read memory barrier */
		rmb();

		buff_out->sq.cmsn = HIFC_GET_QUEUE_CMSN(sq);
		buff_out->sq.pmsn = sq->last_pmsn;
		buff_out->sq.db_cnt = atomic_read(&sq->sq_dbl_cnt);
		buff_out->sq.sqe_cnt = atomic_read(&sq->sq_wqe_cnt);
		buff_out->sq.cqe_cnt = atomic_read(&sq->sq_cqe_cnt);
		buff_out->sq.in_sq_cnt = in_sq_cnt;
		buff_out->sq.in_chip_cnt = out_standing_cnt - (int)in_sq_cnt;

		buff_out->mark = UNF_TRUE;

	} else {
		buff_out->mark = UNF_FALSE;
	}

	return RETURN_OK;
}

unsigned int hifc_port_info(struct unf_hinicam_pkg *v_input)
{
#define HIFC_INQUIRE_PORT_NUM_MODE 1

	unsigned int ret = UNF_RETURN_ERROR;
	unsigned int inquire_type;
	unsigned int probe_total_num = 0;
	unsigned int probe_index = 0;
	unsigned int count = 0;
	struct hifc_adm_cmd_s *buff_in = NULL;
	struct hifc_adm_cmd_s *buff_out = NULL;
	struct hifc_hba_s *hba = NULL;

	HIFC_CHECK(INVALID_VALUE32, v_input, return UNF_RETURN_ERROR);

	buff_in = v_input->buff_in;
	buff_out = (struct hifc_adm_cmd_s *)v_input->buff_out;

	HIFC_CHECK(INVALID_VALUE32, buff_in, return UNF_RETURN_ERROR);
	HIFC_CHECK(INVALID_VALUE32, buff_out, return UNF_RETURN_ERROR);
	HIFC_CHECK(INVALID_VALUE32,
		v_input->in_size >= sizeof(struct hifc_adm_cmd_s),
		return UNF_RETURN_ERROR);
	HIFC_CHECK(INVALID_VALUE32,
		*v_input->out_size >= sizeof(struct hifc_adm_cmd_s),
		return UNF_RETURN_ERROR);

	hifc_get_total_probed_num(&probe_total_num);

	/* First bit is used to obtain total probe number */
	inquire_type = buff_in->cmd[0];
	if (inquire_type == HIFC_INQUIRE_PORT_NUM_MODE) {
		buff_out->cmd[0] = probe_total_num;
		buff_out->msg_head.status = HIFC_ADM_MSG_DONE;
		*v_input->out_size = sizeof(struct hifc_adm_cmd_s);

		return RETURN_OK;
	}

	spin_lock(&probe_spin_lock);
	for (probe_index = 0; probe_index < HIFC_MAX_PROBE_PORT_NUM;
	     probe_index++) {
		/* Second bit is used to determine to obtain which port */
		if (buff_in->cmd[1] == count)
			break;

		if (test_bit((int)probe_index,
			     (const unsigned long *)probe_bit_map))
			count++;
	}
	spin_unlock(&probe_spin_lock);

	if (probe_index == HIFC_MAX_PROBE_PORT_NUM) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_REG_ATT, UNF_ERR,
			  "[err]Can't find port(0x%x) total port(0x%x)",
			  buff_in->cmd[1], probe_total_num);

		buff_out->msg_head.status = HIFC_ADM_MSG_FAILED;

		return ret;
	}

	hba = hifc_hba[probe_index];
	/* Obtain buffer length applied from user */
	v_input->in_size = buff_in->cmd[2];
	if (!hba)
		return UNF_RETURN_ERROR;

	UNF_LOWLEVEL_TO_CM_HINICADM(ret, hba->lport, v_input);

	return ret;
}

int hifc_adm(void *uld_dev, unsigned int msg_formate, void *buffin,
	     unsigned int in_size, void *buff_out, unsigned int *out_size)
{
	int ret = UNF_RETURN_ERROR;
	struct hifc_hba_s *hba = NULL;
	struct unf_hinicam_pkg adm_pkg = { 0 };
	struct hifc_drv_version_s *ver_info;
	char ver_str[HIFC_VER_INFO_SIZE] = { 0 };

	HIFC_CHECK(INVALID_VALUE32, NULL != buff_out, return UNF_RETURN_ERROR);
	HIFC_CHECK(INVALID_VALUE32, NULL != buffin, return UNF_RETURN_ERROR);
	HIFC_CHECK(INVALID_VALUE32, NULL != out_size, return UNF_RETURN_ERROR);

	adm_pkg.msg_format = msg_formate;
	adm_pkg.buff_in = buffin;
	adm_pkg.buff_out = buff_out;
	adm_pkg.in_size = in_size;
	adm_pkg.out_size = out_size;

	if (msg_formate == HIFC_GET_DRIVER_VERSION) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_REG_ATT, UNF_MAJOR,
			  "[info]Enter HIFC_GET_DRIVER_VERSION");

		snprintf(ver_str, sizeof(ver_str), "%s  %s", UNF_FC_VERSION,
			 __TIME_STR__);

		ver_info = (struct hifc_drv_version_s *)buff_out;
		HIFC_CHECK(INVALID_VALUE32,
			*out_size >= sizeof(struct hifc_drv_version_s),
			return UNF_RETURN_ERROR);
		memcpy(ver_info->ver, ver_str, sizeof(ver_str));

		*(unsigned int *)out_size = sizeof(struct hifc_drv_version_s);

		return RETURN_OK;
	}

	if (msg_formate == HIFC_COMPAT_TEST) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_REG_ATT, UNF_MAJOR,
			  "[info]Enter driver compatibility test");
		/* UNF_TRUE: driver is compatible with hifcadm */
		*(unsigned char *)buff_out = UNF_TRUE;
		*(unsigned int *)out_size = sizeof(unsigned char);

		return RETURN_OK;
	}

	HIFC_CHECK(INVALID_VALUE32, NULL != uld_dev, return UNF_RETURN_ERROR);
	hba = (struct hifc_hba_s *)uld_dev;

	UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_REG_ATT, UNF_INFO,
		  "[info]Enter hifc_adm, msg_formate(0x%x)", msg_formate);

	switch (msg_formate) {
	case HIFC_DFX:
		ret = hifc_set_dfx_mode((void *)hba, &adm_pkg);
		break;
	case HIFC_FEC_SET:
		ret = (int)hifc_fec_mode((void *)hba, &adm_pkg);
		break;
	case HIFC_BBSCN:
		ret = (int)hifc_bbscn_mode((void *)hba, &adm_pkg);
		break;

	case HIFC_PORTSTAT:
		ret = (int)hifc_port_stat((void *)hba, &adm_pkg);
		break;

	case HIFC_ALL_INFO_OP:
		ret = (int)hifc_port_info(&adm_pkg);
		break;

	default:
		UNF_LOWLEVEL_TO_CM_HINICADM(ret, hba->lport, &adm_pkg);
		break;
	}

	UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_REG_ATT, UNF_INFO,
		  "[info]Enter hifc_adm 0x%x", *adm_pkg.out_size);

	return ret;
}
