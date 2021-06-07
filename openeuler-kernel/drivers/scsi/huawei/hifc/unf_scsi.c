// SPDX-License-Identifier: GPL-2.0
/* Huawei Hifc PCI Express Linux driver
 * Copyright(c) 2017 Huawei Technologies Co., Ltd
 *
 */
#include "unf_log.h"
#include "unf_scsi_common.h"
#include "unf_lport.h"
#include "unf_rport.h"
#include "unf_portman.h"
#include "unf_npiv.h"
#include "unf_exchg.h"
#include "unf_io.h"

static int unf_scsi_queue_cmd(struct Scsi_Host *shost,
			      struct scsi_cmnd *v_cmnd);
static int unf_scsi_abort_scsi_cmnd(struct scsi_cmnd *v_cmnd);
static int unf_scsi_device_reset_handler(struct scsi_cmnd *v_cmnd);
static int unf_scsi_bus_reset_handler(struct scsi_cmnd *v_cmnd);
static int unf_scsi_target_reset_handler(struct scsi_cmnd *v_cmnd);
static int unf_scsi_slave_alloc(struct scsi_device *sdev);
static void unf_scsi_destroy_slave(struct scsi_device *sdev);
static int unf_scsi_slave_configure(struct scsi_device *sdev);
static int unf_scsi_scan_finished(struct Scsi_Host *shost, unsigned long time);
static void unf_scsi_scan_start(struct Scsi_Host *shost);

static struct scsi_transport_template *scsi_transport_template;
static struct scsi_transport_template *scsi_transport_template_v;

struct unf_ini_error_code_s ini_error_code_table1[] = {
	{ UNF_IO_SUCCESS,             UNF_SCSI_HOST(DID_OK) },
	{ UNF_IO_ABORTED,             UNF_SCSI_HOST(DID_ABORT) },
	{ UNF_IO_FAILED,              UNF_SCSI_HOST(DID_ERROR) },
	{ UNF_IO_ABORT_ABTS,          UNF_SCSI_HOST(DID_ERROR) },
	{ UNF_IO_ABORT_LOGIN,         UNF_SCSI_HOST(DID_NO_CONNECT) },
	{ UNF_IO_ABORT_REET,          UNF_SCSI_HOST(DID_RESET) },
	{ UNF_IO_ABORT_FAILED,        UNF_SCSI_HOST(DID_ERROR) },
	{ UNF_IO_OUTOF_ORDER,         UNF_SCSI_HOST(DID_ERROR) },
	{ UNF_IO_FTO,                 UNF_SCSI_HOST(DID_TIME_OUT) },
	{ UNF_IO_LINK_FAILURE,        UNF_SCSI_HOST(DID_ERROR) },
	{ UNF_IO_OVER_FLOW,           UNF_SCSI_HOST(DID_ERROR) },
	{ UNF_IO_RSP_OVER,            UNF_SCSI_HOST(DID_ERROR) },
	{ UNF_IO_LOST_FRAME,          UNF_SCSI_HOST(DID_ERROR) },
	{ UNF_IO_UNDER_FLOW,          UNF_SCSI_HOST(DID_OK) },
	{ UNF_IO_HOST_PROG_ERROR,     UNF_SCSI_HOST(DID_ERROR) },
	{ UNF_IO_SEST_PROG_ERROR,     UNF_SCSI_HOST(DID_ERROR) },
	{ UNF_IO_INVALID_ENTRY,       UNF_SCSI_HOST(DID_ERROR) },
	{ UNF_IO_ABORT_SEQ_NOT,       UNF_SCSI_HOST(DID_ERROR) },
	{ UNF_IO_REJECT,              UNF_SCSI_HOST(DID_ERROR) },
	{ UNF_IO_EDC_IN_ERROR,        UNF_SCSI_HOST(DID_ERROR) },
	{ UNF_IO_EDC_OUT_ERROR,       UNF_SCSI_HOST(DID_ERROR) },
	{ UNF_IO_UNINIT_KEK_ERR,      UNF_SCSI_HOST(DID_ERROR) },
	{ UNF_IO_DEK_OUTOF_RANGE,     UNF_SCSI_HOST(DID_ERROR) },
	{ UNF_IO_KEY_UNWRAP_ERR,      UNF_SCSI_HOST(DID_ERROR) },
	{ UNF_IO_KEY_TAG_ERR,         UNF_SCSI_HOST(DID_ERROR) },
	{ UNF_IO_KEY_ECC_ERR,         UNF_SCSI_HOST(DID_ERROR) },
	{ UNF_IO_BLOCK_SIZE_ERROR,    UNF_SCSI_HOST(DID_ERROR) },
	{ UNF_IO_ILLEGAL_CIPHER_MODE, UNF_SCSI_HOST(DID_ERROR) },
	{ UNF_IO_CLEAN_UP,            UNF_SCSI_HOST(DID_ERROR) },
	{ UNF_IO_ABORTED_BY_TARGET,   UNF_SCSI_HOST(DID_ERROR) },
	{ UNF_IO_TRANSPORT_ERROR,     UNF_SCSI_HOST(DID_ERROR) },
	{ UNF_IO_LINK_FLASH,          UNF_SCSI_HOST(DID_NO_CONNECT) },
	{ UNF_IO_TIMEOUT,             UNF_SCSI_HOST(DID_TIME_OUT) },
	{ UNF_IO_DMA_ERROR,           UNF_SCSI_HOST(DID_ERROR) },
	{ UNF_IO_NO_LPORT,            UNF_SCSI_HOST(DID_NO_CONNECT) },
	{ UNF_IO_NO_XCHG,             UNF_SCSI_HOST(DID_SOFT_ERROR) },
	{ UNF_IO_SOFT_ERR,            UNF_SCSI_HOST(DID_SOFT_ERROR) },
	{ UNF_IO_PORT_LOGOUT,         UNF_SCSI_HOST(DID_NO_CONNECT) },
	{ UNF_IO_ERREND,              UNF_SCSI_HOST(DID_ERROR) },
	{ UNF_IO_DIF_ERROR,           (UNF_SCSI_HOST(DID_OK) | UNF_SCSI_STATUS(SCSI_CHECK_CONDITION)) },
	{ UNF_IO_INCOMPLETE,          UNF_SCSI_HOST(DID_IMM_RETRY) },
	{ UNF_IO_DIF_REF_ERROR,       (UNF_SCSI_HOST(DID_OK) | UNF_SCSI_STATUS(SCSI_CHECK_CONDITION)) },
	{ UNF_IO_DIF_GEN_ERROR,       (UNF_SCSI_HOST(DID_OK) | UNF_SCSI_STATUS(SCSI_CHECK_CONDITION)) }
};

unsigned int ini_err_code_table_cnt1 =
	sizeof(ini_error_code_table1) / sizeof(struct unf_ini_error_code_s);

static void unf_set_rport_loss_tmo(struct fc_rport *rport,
				   unsigned int timeout)
{
	if (timeout)
		rport->dev_loss_tmo = timeout;
	else
		rport->dev_loss_tmo = 1;
}

static void unf_get_host_port_id(struct Scsi_Host *shost)
{
	struct unf_lport_s *lport = NULL;

	lport = (struct unf_lport_s *)shost->hostdata[0];
	if (unlikely(!lport)) {
		UNF_TRACE(0x3808, UNF_LOG_LOGIN_ATT, UNF_ERR,
			  "[err]Port is null");

		return;
	}

	fc_host_port_id(shost) = lport->port_id;
}

static void unf_get_host_speed(struct Scsi_Host *shost)
{
	struct unf_lport_s *lport = NULL;
	unsigned int speed = FC_PORTSPEED_UNKNOWN;

	lport = (struct unf_lport_s *)shost->hostdata[0];
	if (unlikely(!lport)) {
		UNF_TRACE(0x3808, UNF_LOG_LOGIN_ATT, UNF_ERR,
			  "[err]Port is null");

		return;
	}

	switch (lport->speed) {
	case UNF_PORT_SPEED_2_G:
		speed = FC_PORTSPEED_2GBIT;
		break;

	case UNF_PORT_SPEED_4_G:
		speed = FC_PORTSPEED_4GBIT;
		break;

	case UNF_PORT_SPEED_8_G:
		speed = FC_PORTSPEED_8GBIT;
		break;

	case UNF_PORT_SPEED_16_G:
		speed = FC_PORTSPEED_16GBIT;
		break;

	case UNF_PORT_SPEED_32_G:
		speed = FC_PORTSPEED_32GBIT;
		break;

	default:
		UNF_TRACE(0x3808, UNF_LOG_LOGIN_ATT, UNF_MAJOR,
			  "[info]Port(0x%x) with unknown speed(0x%x) for FC mode",
			  lport->port_id, lport->speed);
		break;
	}

	fc_host_speed(shost) = speed;
}

static void unf_get_host_port_type(struct Scsi_Host *shost)
{
	struct unf_lport_s *lport = NULL;
	unsigned int port_type = FC_PORTTYPE_UNKNOWN;

	lport = (struct unf_lport_s *)shost->hostdata[0];
	if (unlikely(!lport)) {
		UNF_TRACE(0x3808, UNF_LOG_LOGIN_ATT, UNF_ERR,
			  "[err]Port is null");

		return;
	}

	switch (lport->en_act_topo) {
	case UNF_ACT_TOP_PRIVATE_LOOP:
		port_type = FC_PORTTYPE_LPORT;
		break;

	case UNF_ACT_TOP_PUBLIC_LOOP:
		port_type = FC_PORTTYPE_NLPORT;
		break;

	case UNF_ACT_TOP_P2P_DIRECT:
		port_type = FC_PORTTYPE_PTP;
		break;

	case UNF_ACT_TOP_P2P_FABRIC:
		port_type = FC_PORTTYPE_NPORT;
		break;

	default:
		UNF_TRACE(0x3808, UNF_LOG_LOGIN_ATT, UNF_MAJOR,
			  "[info]Port(0x%x) with unknown topo type(0x%x) for FC mode",
			  lport->port_id, lport->en_act_topo);
		break;
	}

	fc_host_port_type(shost) = port_type;
}

static void unf_get_symbolic_name(struct Scsi_Host *shost)
{
	unsigned char *name = NULL;
	struct unf_lport_s *lport = NULL;

	lport = (struct unf_lport_s *)shost->hostdata[0];
	if (unlikely(!lport)) {
		UNF_TRACE(0x3808, UNF_LOG_LOGIN_ATT, UNF_ERR,
			  "[err]Check l_port failed");

		return;
	}

	name = fc_host_symbolic_name(shost);
	if (name) {
		snprintf(name, FC_SYMBOLIC_NAME_SIZE,
			 "HIFC_FW_RELEASE:%s HIFC_DRV_RELEASE:%s",
			 lport->fw_version, UNF_FC_VERSION);
	}
}

static void unf_get_host_fabric_name(struct Scsi_Host *shost)
{
	struct unf_lport_s *lport = NULL;

	lport = (struct unf_lport_s *)shost->hostdata[0];
	if (unlikely(!lport)) {
		UNF_TRACE(0x3808, UNF_LOG_LOGIN_ATT, UNF_ERR,
			  "[err]Port is null");

		return;
	}

	fc_host_fabric_name(shost) = lport->fabric_node_name;
}

static void unf_get_host_port_state(struct Scsi_Host *shost)
{
	struct unf_lport_s *lport = NULL;
	enum fc_port_state port_state;

	lport = (struct unf_lport_s *)shost->hostdata[0];
	if (unlikely(!lport)) {
		UNF_TRACE(0x3808, UNF_LOG_LOGIN_ATT, UNF_ERR,
			  "[err]Port is null");

		return;
	}

	switch (lport->link_up) {
	case UNF_PORT_LINK_DOWN:
		port_state = FC_PORTSTATE_OFFLINE;
		break;

	case UNF_PORT_LINK_UP:
		port_state = FC_PORTSTATE_ONLINE;
		break;

	default:
		port_state = FC_PORTSTATE_UNKNOWN;
		break;
	}

	fc_host_port_state(shost) = port_state;
}

static void unf_dev_loss_timeout_callbk(struct fc_rport *rport)
{
	/*
	 * NOTE: about rport->dd_data
	 * --->>> local SCSI_ID
	 * 1. Assignment during scsi rport link up
	 * 2. Released when scsi rport link down & timeout(30s)
	 * 3. Used during scsi do callback with slave_alloc function
	 */
	struct Scsi_Host *host = NULL;
	struct unf_lport_s *lport = NULL;
	unsigned int scsi_id = 0;

	if (unlikely(!rport)) {
		UNF_TRACE(0x3808, UNF_LOG_LOGIN_ATT, UNF_ERR,
			  "[err]SCSI rport is null");

		return;
	}

	host = rport_to_shost(rport);
	if (unlikely(!host)) {
		UNF_TRACE(0x3808, UNF_LOG_LOGIN_ATT, UNF_ERR,
			  "[err]Host is null");

		return;
	}

	/* according to Local SCSI_ID */
	scsi_id = *(unsigned int *)(rport->dd_data);
	if (unlikely(scsi_id >= UNF_MAX_SCSI_ID)) {
		UNF_TRACE(0x3808, UNF_LOG_LOGIN_ATT, UNF_ERR,
			  "[err]scsi_id(0x%x) is max than(0x%x)",
			  scsi_id, UNF_MAX_SCSI_ID);

		return;
	}

	lport = (struct unf_lport_s *)host->hostdata[0];
	if (unf_is_lport_valid(lport) == RETURN_OK) {
		UNF_TRACE(0x3097, UNF_LOG_LOGIN_ATT, UNF_INFO,
			  "[event]Port(0x%x_0x%x) RPort scsi_id(0x%x) target_id(0x%x) loss timeout",
			  lport->port_id, lport->nport_id,
			  scsi_id, rport->scsi_target_id);

		atomic_inc(&lport->session_loss_tmo);

		/* Free SCSI ID & set table state with DEAD */
		(void)unf_free_scsi_id(lport, scsi_id);
	} else {
		UNF_TRACE(0x3097, UNF_LOG_LOGIN_ATT, UNF_ERR,
			  "[err]Port(%p) is invalid", lport);
	}

	/* reset scsi rport dd_data(local SCSI_ID) */
	*((unsigned int *)rport->dd_data) = INVALID_VALUE32;
}

int unf_scsi_create_vport(struct fc_vport *fc_port, bool disabled)
{
	struct unf_lport_s *vport = NULL;
	struct unf_lport_s *lport = NULL;
	struct Scsi_Host *shost = NULL;
	struct vport_config_s vport_config = { 0 };

	shost = vport_to_shost(fc_port);

	lport = (struct unf_lport_s *)shost->hostdata[0];
	if (unf_is_lport_valid(lport) != RETURN_OK) {
		UNF_TRACE(0x3097, UNF_LOG_LOGIN_ATT, UNF_ERR,
			  "[err]Port(%p) is invalid", lport);

		return RETURN_ERROR;
	}

	vport_config.port_name = fc_port->port_name;

	vport_config.port_mode = fc_port->roles;

	vport = unf_create_vport(lport, &vport_config);
	if (!vport) {
		UNF_TRACE(0x3097, UNF_LOG_LOGIN_ATT, UNF_ERR,
			  "[err]Port(0x%x) Create Vport failed on lldrive",
			  lport->port_id);

		return RETURN_ERROR;
	}

	fc_port->dd_data = vport;

	vport->vport = fc_port;

	return RETURN_OK;
}

int unf_scsi_delete_vport(struct fc_vport *fc_port)
{
	int ret = RETURN_ERROR;
	struct unf_lport_s *vport = NULL;

	vport = (struct unf_lport_s *)fc_port->dd_data;

	if (unf_is_lport_valid(vport) != RETURN_OK) {
		UNF_TRACE(0x3097, UNF_LOG_LOGIN_ATT, UNF_WARN,
			  "[warn]VPort(%p) is invalid or is removing",
			  vport);

		fc_port->dd_data = NULL;

		return ret;
	}

	ret = (int)unf_destroy_one_vport(vport);
	if (ret != RETURN_OK) {
		UNF_TRACE(0x3097, UNF_LOG_LOGIN_ATT, UNF_ERR,
			  "[err]VPort(0x%x) destroy failed on drive",
			  vport->port_id);

		return ret;
	}

	fc_port->dd_data = NULL;

	return ret;
}

struct fc_function_template function_template = {
	.show_host_node_name = 1,
	.show_host_port_name = 1,
	.show_host_supported_classes = 1,
	.show_host_supported_speeds = 1,

	.get_host_port_id = unf_get_host_port_id,
	.show_host_port_id = 1,
	.get_host_speed = unf_get_host_speed,
	.show_host_speed = 1,
	.get_host_port_type = unf_get_host_port_type,
	.show_host_port_type = 1,
	.get_host_symbolic_name = unf_get_symbolic_name,
	.show_host_symbolic_name = 1,
	.set_host_system_hostname = NULL,
	.show_host_system_hostname = 1,
	.get_host_fabric_name = unf_get_host_fabric_name,
	.show_host_fabric_name = 1,
	.get_host_port_state = unf_get_host_port_state,
	.show_host_port_state = 1,

	.dd_fcrport_size = sizeof(void *),
	.show_rport_supported_classes = 1,

	.get_starget_node_name = NULL,
	.show_starget_node_name = 1,
	.get_starget_port_name = NULL,
	.show_starget_port_name = 1,
	.get_starget_port_id = NULL,
	.show_starget_port_id = 1,

	.set_rport_dev_loss_tmo = unf_set_rport_loss_tmo,
	.show_rport_dev_loss_tmo = 0,

	.issue_fc_host_lip = NULL,
	.dev_loss_tmo_callbk = unf_dev_loss_timeout_callbk,
	.terminate_rport_io = NULL,
	.get_fc_host_stats = NULL,

	.vport_create = unf_scsi_create_vport,
	.vport_disable = NULL,
	.vport_delete = unf_scsi_delete_vport,
	.bsg_request = NULL,
	.bsg_timeout = NULL,
};

struct fc_function_template function_template_v = {
	.show_host_node_name = 1,
	.show_host_port_name = 1,
	.show_host_supported_classes = 1,
	.show_host_supported_speeds = 1,

	.get_host_port_id = unf_get_host_port_id,
	.show_host_port_id = 1,
	.get_host_speed = unf_get_host_speed,
	.show_host_speed = 1,
	.get_host_port_type = unf_get_host_port_type,
	.show_host_port_type = 1,
	.get_host_symbolic_name = unf_get_symbolic_name,
	.show_host_symbolic_name = 1,
	.set_host_system_hostname = NULL,
	.show_host_system_hostname = 1,
	.get_host_fabric_name = unf_get_host_fabric_name,
	.show_host_fabric_name = 1,
	.get_host_port_state = unf_get_host_port_state,
	.show_host_port_state = 1,

	.dd_fcrport_size = sizeof(void *),
	.show_rport_supported_classes = 1,

	.get_starget_node_name = NULL,
	.show_starget_node_name = 1,
	.get_starget_port_name = NULL,
	.show_starget_port_name = 1,
	.get_starget_port_id = NULL,
	.show_starget_port_id = 1,

	.set_rport_dev_loss_tmo = unf_set_rport_loss_tmo,
	.show_rport_dev_loss_tmo = 1,

	.issue_fc_host_lip = NULL,
	.dev_loss_tmo_callbk = unf_dev_loss_timeout_callbk,
	.terminate_rport_io = NULL,
	.get_fc_host_stats = NULL,

	.vport_create = NULL,
	.vport_disable = NULL,
	.vport_delete = NULL,
	.bsg_request = NULL,
	.bsg_timeout = NULL,
};

struct scsi_host_template scsi_host_template = {
	.module = THIS_MODULE,
	.name = "HIFC",

	.queuecommand = unf_scsi_queue_cmd,
	.eh_abort_handler = unf_scsi_abort_scsi_cmnd,
	.eh_device_reset_handler = unf_scsi_device_reset_handler,

	.eh_target_reset_handler = unf_scsi_target_reset_handler,
	.eh_bus_reset_handler = unf_scsi_bus_reset_handler,
	.eh_host_reset_handler = NULL,

	.slave_configure = unf_scsi_slave_configure,
	.slave_alloc = unf_scsi_slave_alloc,
	.slave_destroy = unf_scsi_destroy_slave,

	.scan_finished = unf_scsi_scan_finished,
	.scan_start = unf_scsi_scan_start,

	.this_id = -1,
	.cmd_per_lun = 3,
	.shost_attrs = NULL,
	.sg_tablesize = SG_ALL,
	.max_sectors = 0xFFFF,
	.supported_mode = MODE_INITIATOR,
};

static void unf_unmap_prot_sgl(struct scsi_cmnd *v_cmnd)
{
	struct device *dev;

	if ((scsi_get_prot_op(v_cmnd) != SCSI_PROT_NORMAL) &&
	    hifc_dif_enable && (scsi_prot_sg_count(v_cmnd))) {
		dev = v_cmnd->device->host->dma_dev;
		dma_unmap_sg(dev, scsi_prot_sglist(v_cmnd),
			     (int)scsi_prot_sg_count(v_cmnd),
			     v_cmnd->sc_data_direction);

		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_REG_ATT, UNF_INFO,
			  "scsi done cmd:%p op:%d,difsglcount:%d",
			   v_cmnd, scsi_get_prot_op(v_cmnd),
			   scsi_prot_sg_count(v_cmnd));
	}
}

void unf_scsi_done(struct unf_scsi_cmd_s *v_scsi_cmnd)
{
	struct scsi_cmnd *cmnd = NULL;

	UNF_CHECK_VALID(0x509, UNF_TRUE, v_scsi_cmnd, return);
	cmnd = (struct scsi_cmnd *)v_scsi_cmnd->upper_cmnd;
	UNF_CHECK_VALID(0x510, UNF_TRUE, cmnd, return);
	UNF_CHECK_VALID(0x511, UNF_TRUE, cmnd->scsi_done, return);

	scsi_set_resid(cmnd, (int)v_scsi_cmnd->resid);

	cmnd->result = v_scsi_cmnd->result;
	scsi_dma_unmap(cmnd);
	unf_unmap_prot_sgl(cmnd);
	return cmnd->scsi_done(cmnd);
}

void unf_host_init_attr_setting(unf_scsi_host_s *scsi_host)
{
	struct unf_lport_s *lport = NULL;
	unsigned int speed = FC_PORTSPEED_UNKNOWN;

	lport = (struct unf_lport_s *)scsi_host->hostdata[0];
	fc_host_supported_classes(scsi_host) = FC_COS_CLASS3; /* class_3 */
	fc_host_dev_loss_tmo(scsi_host) =
		(unsigned int)unf_get_link_lose_tmo(lport);  /* 30s */
	fc_host_node_name(scsi_host) = lport->node_name;
	fc_host_port_name(scsi_host) = lport->port_name;

	fc_host_max_npiv_vports(scsi_host) =
		(unsigned short)((lport == lport->root_lport) ?
		lport->low_level_func.support_max_npiv_num : 0);
	fc_host_npiv_vports_inuse(scsi_host) = 0;
	fc_host_next_vport_number(scsi_host) = 0;

	/* About speed mode */
	if ((lport->low_level_func.fc_ser_max_speed == UNF_PORT_SPEED_32_G) &&
	    (lport->card_type == UNF_FC_SERVER_BOARD_32_G)) {
		speed = FC_PORTSPEED_32GBIT | FC_PORTSPEED_16GBIT |
			FC_PORTSPEED_8GBIT;
	} else if ((lport->low_level_func.fc_ser_max_speed ==
		    UNF_PORT_SPEED_16_G) &&
		   (lport->card_type == UNF_FC_SERVER_BOARD_16_G)) {
		speed = FC_PORTSPEED_16GBIT | FC_PORTSPEED_8GBIT |
			FC_PORTSPEED_4GBIT;
	} else if ((lport->low_level_func.fc_ser_max_speed ==
		    UNF_PORT_SPEED_8_G) &&
		   (lport->card_type == UNF_FC_SERVER_BOARD_8_G)) {
		speed = FC_PORTSPEED_8GBIT | FC_PORTSPEED_4GBIT |
			FC_PORTSPEED_2GBIT;
	}

	fc_host_supported_speeds(scsi_host) = speed;
}

int unf_alloc_scsi_host(unf_scsi_host_s **v_scsi_host,
			struct unf_host_param_s *v_host_param)
{
	int ret = RETURN_ERROR;
	struct Scsi_Host *scsi_host = NULL;
	struct unf_lport_s *lport = NULL;

	UNF_CHECK_VALID(0x512, UNF_TRUE, v_scsi_host, return RETURN_ERROR);
	UNF_CHECK_VALID(0x513, UNF_TRUE, v_host_param, return RETURN_ERROR);

	UNF_TRACE(0x3808, UNF_LOG_LOGIN_ATT, UNF_MAJOR,
		  "[event]Alloc scsi host...");

	/* Check L_Port validity */
	lport = (struct unf_lport_s *)(v_host_param->lport);
	if (unlikely(!lport)) {
		UNF_TRACE(0x3808, UNF_LOG_LOGIN_ATT, UNF_ERR,
			  "[err]Port is NULL and return directly");

		return RETURN_ERROR;
	}

	scsi_host_template.can_queue = v_host_param->can_queue;
	scsi_host_template.cmd_per_lun = v_host_param->cmnd_per_lun;
	scsi_host_template.sg_tablesize = v_host_param->sg_table_size;
	scsi_host_template.max_sectors = v_host_param->max_sectors;

	/* Alloc scsi host */
	scsi_host = scsi_host_alloc(&scsi_host_template,
				    sizeof(unsigned long long));
	if (unlikely(!scsi_host)) {
		UNF_TRACE(0x3808, UNF_LOG_LOGIN_ATT, UNF_ERR,
			  "[err]Register scsi host failed");

		return RETURN_ERROR;
	}

	scsi_host->max_channel = v_host_param->max_channel;
	scsi_host->max_lun = v_host_param->max_lun;
	scsi_host->max_cmd_len = v_host_param->max_cmnd_len;
	scsi_host->unchecked_isa_dma = 0;
	scsi_host->hostdata[0] = (unsigned long)lport; /* save L_Port to scsi */
	scsi_host->unique_id = scsi_host->host_no;
	scsi_host->max_id = v_host_param->max_id;
	scsi_host->transportt = (lport == lport->root_lport) ?
			scsi_transport_template : scsi_transport_template_v;

	/* register DIF/DIX protection */
	if (hifc_dif_enable) {
		/* Enable DIF and DIX function */
		scsi_host_set_prot(scsi_host, hifc_dif_type);

		hifc_guard = SHOST_DIX_GUARD_CRC;
		/* Enable IP checksum algorithm in DIX */
		if (dix_flag)
			hifc_guard |= SHOST_DIX_GUARD_IP;
		scsi_host_set_guard(scsi_host, hifc_guard);
	}

	/* Add scsi host */
	ret = scsi_add_host(scsi_host, v_host_param->pdev);
	if (unlikely(ret)) {
		UNF_TRACE(0x3808, UNF_LOG_LOGIN_ATT, UNF_ERR,
			  "[err]Add scsi host failed with return value %d",
			  ret);

		scsi_host_put(scsi_host);
		return RETURN_ERROR;
	}

	/* Set scsi host attribute */
	unf_host_init_attr_setting(scsi_host);
	*v_scsi_host = scsi_host;

	UNF_TRACE(0x3808, UNF_LOG_LOGIN_ATT, UNF_MAJOR,
		  "[event]Alloc and add scsi host(0x%llx) succeed",
		  (unsigned long long)scsi_host);

	return RETURN_OK;
}

void unf_free_scsi_host(unf_scsi_host_s *v_scsi_host)
{
	struct Scsi_Host *scsi_host = NULL;

	scsi_host = v_scsi_host;
	fc_remove_host(scsi_host);
	scsi_remove_host(scsi_host);

	UNF_TRACE(0x3808, UNF_LOG_LOGIN_ATT, UNF_MAJOR,
		  "[event]Remove scsi host(%d) succeed", scsi_host->host_no);

	scsi_host_put(scsi_host);
}

static int unf_get_protect_mode(struct unf_lport_s *lport,
				struct scsi_cmnd *v_cmnd,
				struct unf_scsi_cmd_s *v_scsi_cmnd)
{
	struct scsi_cmnd *cmd = NULL;
	int difsegcnt = 0;
	struct unf_dif_control_info_s *dif_control_info = NULL;

	cmd = v_cmnd;
	dif_control_info = &v_scsi_cmnd->dif_control;

	switch (scsi_get_prot_op(cmd)) {
	/* OS-HBA: Unprotected, HBA-Target: Protected */
	case SCSI_PROT_READ_STRIP:
		dif_control_info->protect_opcode |=
			UNF_DIF_ACTION_VERIFY_AND_DELETE;
		break;
	case SCSI_PROT_WRITE_INSERT:
		dif_control_info->protect_opcode |=
			UNF_DIF_ACTION_INSERT;
		break;

	/* OS-HBA: Protected, HBA-Target: Unprotected */
	case SCSI_PROT_READ_INSERT:
		dif_control_info->protect_opcode |=
			UNF_DIF_ACTION_INSERT;
		break;
	case SCSI_PROT_WRITE_STRIP:
		dif_control_info->protect_opcode |=
			UNF_DIF_ACTION_VERIFY_AND_DELETE;
		break;

	/* OS-HBA: Protected, HBA-Target: Protected */
	case SCSI_PROT_READ_PASS:
	case SCSI_PROT_WRITE_PASS:
		dif_control_info->protect_opcode |=
			UNF_DIF_ACTION_VERIFY_AND_FORWARD;
		break;

	default:
		dif_control_info->protect_opcode |=
			UNF_DIF_ACTION_VERIFY_AND_FORWARD;
		break;
	}

	if (dif_sgl_mode)
		dif_control_info->flags |= UNF_DIF_DOUBLE_SGL;

	dif_control_info->protect_opcode |=
		 UNF_VERIFY_CRC_MASK | UNF_VERIFY_LBA_MASK;
	dif_control_info->dif_sge_count = scsi_prot_sg_count(cmd);
	dif_control_info->dif_sgl = scsi_prot_sglist(cmd);
	dif_control_info->start_lba =
		cpu_to_le32(((uint32_t)(0xffffffff & scsi_get_lba(cmd))));

	if (scsi_prot_sg_count(cmd)) {
		difsegcnt = dma_map_sg(&lport->low_level_func.dev->dev,
				       scsi_prot_sglist(cmd),
				       (int)scsi_prot_sg_count(cmd),
				       cmd->sc_data_direction);
		if (unlikely(!difsegcnt)) {
			UNF_TRACE(0x3808, UNF_LOG_LOGIN_ATT, UNF_WARN,
				  "[warn]Port(0x%x) cmd:%p map dif sgl err",
				  lport->port_id, cmd);
			return UNF_RETURN_ERROR;
		}
	}

	UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_REG_ATT, UNF_INFO,
		  "build scsi cmd:%p op:%d,difsglcount:%d,difsegcnt:%d",
		  cmd, scsi_get_prot_op(cmd), scsi_prot_sg_count(cmd),
		  difsegcnt);
	return RETURN_OK;
}

unsigned int unf_get_frame_entry_buf(void *v_up_cmnd,
				     void *v_driver_sgl,
				     void **v_upper_sgl,
				     unsigned int *v_port_id,
				     unsigned int *v_index,
				     char **v_buf,
				     unsigned int *v_buf_len)
{
#define HIFC_1822_MAX_DMA_LENGTH (0x20000 - 1)
	struct scatterlist *scsi_sgl = *v_upper_sgl;

	UNF_REFERNCE_VAR(v_up_cmnd);
	UNF_REFERNCE_VAR(v_driver_sgl);
	UNF_REFERNCE_VAR(v_port_id);

	if (unlikely(!scsi_sgl)) {
		UNF_TRACE(UNF_EVTLOG_IO_ERR, UNF_LOG_IO_ATT, UNF_ERR,
			  "[err]Command(0x%p) can not get SGL.", v_up_cmnd);
		return RETURN_ERROR;
	}
	*v_buf = (char *)sg_dma_address(scsi_sgl);
	*v_buf_len = sg_dma_len(scsi_sgl);
	*v_upper_sgl = (void *)sg_next(scsi_sgl);
	if (unlikely((*v_buf_len > HIFC_1822_MAX_DMA_LENGTH) ||
		     (*v_buf_len == 0))) {
		UNF_TRACE(UNF_EVTLOG_IO_ERR, UNF_LOG_IO_ATT, UNF_ERR,
			  "[err]Command(0x%p) dmalen:0x%x is not support.",
			  v_up_cmnd, *v_buf_len);
		return RETURN_ERROR;
	}

	return RETURN_OK;
}

static int unf_scsi_queue_cmd(struct Scsi_Host *shost,
			      struct scsi_cmnd *v_cmnd)
{
	struct Scsi_Host *host = NULL;
	struct scsi_cmnd *cmd = NULL;
	struct unf_scsi_cmd_s scsi_cmnd = { 0 };
	unsigned int scsi_id = 0;
	unsigned int en_scsi_state = 0;
	int ret = SCSI_MLQUEUE_HOST_BUSY;
	// unsigned int uiError = 0;
	struct unf_lport_s *lport = NULL;
	struct fc_rport *p_rport = NULL;
	struct unf_rport_scsi_id_image_s *scsi_image_table = NULL;
	unsigned int ret_value = 0;
	struct unf_rport_s *rport = NULL;
	unsigned int cmnd_result = 0;
	unsigned int rport_state_err = 0;
	unsigned int scan_device_cmd = 0;
	unsigned long long raw_lun_id = 0;
	int data_seg_cnt = 0;

	static atomic64_t ull_count;
	host = shost;
	cmd = v_cmnd;
	UNF_CHECK_VALID(0x515, UNF_TRUE, host, return RETURN_ERROR);
	UNF_CHECK_VALID(0x514, UNF_TRUE, cmd, return RETURN_ERROR);

	/* Get L_Port from scsi_cmnd */
	lport = (struct unf_lport_s *)host->hostdata[0];
	if (unlikely(!lport)) {
		UNF_TRACE(0x3808, UNF_LOG_LOGIN_ATT, UNF_ERR,
			  "[err]Check l_port failed, cmd(%p)", cmd);

		/* scsi_done & return 0 & I/O error */
		cmd->result = DID_NO_CONNECT << 16;
		cmd->scsi_done(cmd);
		return 0;
	}

	/* Check device/session local state by device_id */
	/* local SCSI_ID from device */
	scsi_id = (unsigned int)((unsigned long long)cmd->device->hostdata);
	if (unlikely(scsi_id >= UNF_MAX_SCSI_ID)) {
		UNF_TRACE(0x3808, UNF_LOG_LOGIN_ATT, UNF_ERR,
			  "[err]Port(0x%x) scsi_id(0x%x) is max than %d",
			  lport->port_id, scsi_id, UNF_MAX_SCSI_ID);

		/* scsi_done & return 0 & I/O error */
		cmd->result = DID_NO_CONNECT << 16;
		cmd->scsi_done(cmd);
		return 0;
	}

	scsi_image_table = &lport->rport_scsi_table;
	UNF_SCSI_CMD_CNT(scsi_image_table, scsi_id, cmd->cmnd[0]);

	/* Get scsi r_port */
	/*lint -e666 -esym(666,*)*/
	p_rport = starget_to_rport(scsi_target(cmd->device));
	if (unlikely(!p_rport)) {
		UNF_TRACE(0x3808, UNF_LOG_LOGIN_ATT, UNF_ERR,
			  "[err]Port(0x%x) cmd(%p) to get scsi rport failed",
			  lport->port_id, cmd);

		/* scsi_done & return 0 & I/O error */
		cmd->result = DID_NO_CONNECT << 16;
		cmd->scsi_done(cmd);
		ret_value = DID_NO_CONNECT;
		UNF_IO_RESULT_CNT(scsi_image_table, scsi_id, ret_value);
		return 0;
	}

	if (unlikely(!scsi_image_table->wwn_rport_info_table)) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_ABNORMAL, UNF_WARN,
			  "[warn]Port(0x%x) WwnRportInfoTable NULL", lport->port_id);

		cmd->result = DID_NO_CONNECT << 16;
		cmd->scsi_done(cmd);
		ret_value = DID_NO_CONNECT;
		UNF_IO_RESULT_CNT(scsi_image_table, scsi_id, ret_value);
		return 0;
	}

	if (unlikely(lport->b_port_removing == UNF_TRUE)) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_ABNORMAL, UNF_WARN,
			  "[warn]Port(0x%x) scsi_id(0x%x) rport(0x%p) target_id(0x%x) cmd(0x%p) is removing",
			  lport->port_id, scsi_id, p_rport, p_rport->scsi_target_id, cmd);

		cmd->result = DID_NO_CONNECT << 16;
		cmd->scsi_done(cmd);
		ret_value = DID_NO_CONNECT;
		UNF_IO_RESULT_CNT(scsi_image_table, scsi_id, ret_value);
		return 0;
	}

	en_scsi_state = atomic_read(&scsi_image_table->wwn_rport_info_table[scsi_id].en_scsi_state);
	if (unlikely(en_scsi_state != UNF_SCSI_ST_ONLINE)) {
		if (en_scsi_state == UNF_SCSI_ST_OFFLINE) {
			UNF_TRACE(0x3808, UNF_LOG_LOGIN_ATT, UNF_WARN,
				  "[warn]Port(0x%x) scsi_state(0x%x) scsi_id(0x%x) rport(0x%p) target_id(0x%x) cmd(0x%p), target is busy",
				  lport->port_id, en_scsi_state, scsi_id,
				  p_rport, p_rport->scsi_target_id, cmd);

			scan_device_cmd = (cmd->cmnd[0] == INQUIRY) ||
					  (cmd->cmnd[0] == REPORT_LUNS);

			/* report lun or inquiry cmd, if send failed,
			 * do not retry, prevent the scan_mutex in
			 * scsi host locked up by eachother
			 */
			if (scan_device_cmd) {
				UNF_TRACE(0x3808, UNF_LOG_LOGIN_ATT, UNF_WARN,
					  "[warn]Port(0x%x) host(0x%x) scsi_id(0x%x) lun(0x%llx) cmd(0x%x) DID_NO_CONNECT",
					  lport->port_id, host->host_no,
					  scsi_id,
					  (unsigned long long)cmd->device->lun,
					  cmd->cmnd[0]);

				cmd->result = DID_NO_CONNECT << 16;
				cmd->scsi_done(cmd);
				ret_value = DID_NO_CONNECT;
				UNF_IO_RESULT_CNT(scsi_image_table, scsi_id,
						  ret_value);

				return 0;
			}

			if (likely(scsi_image_table->wwn_rport_info_table)) {
				if (likely(scsi_image_table->wwn_rport_info_table[scsi_id].dfx_counter))
					atomic64_inc(&scsi_image_table->wwn_rport_info_table[scsi_id].dfx_counter->target_busy);
			}

			/* Target busy: need scsi retry */
			return SCSI_MLQUEUE_TARGET_BUSY;
		}
		/* timeout(DEAD): scsi_done & return 0 & I/O error */
		UNF_TRACE(0x3808, UNF_LOG_LOGIN_ATT, UNF_WARN,
			  "[warn]Port(0x%x) scsi_id(0x%x) rport(0x%p) target_id(0x%x) cmd(0x%p), target is loss timeout",
			  lport->port_id, scsi_id, p_rport,
			  p_rport->scsi_target_id, cmd);
		cmd->result = DID_NO_CONNECT << 16;
		cmd->scsi_done(cmd);
		ret_value = DID_NO_CONNECT;
		UNF_IO_RESULT_CNT(scsi_image_table, scsi_id, ret_value);

		return 0;
	}

	raw_lun_id = ((unsigned long long)cmd->device->lun << 16) &
			0x00000000ffff0000;
	if (scsi_sg_count(cmd)) {
		data_seg_cnt = dma_map_sg(&lport->low_level_func.dev->dev,
					  scsi_sglist(cmd),
					  (int)scsi_sg_count(cmd),
					  cmd->sc_data_direction);
		if (unlikely(!data_seg_cnt)) {
			UNF_TRACE(0x3808, UNF_LOG_LOGIN_ATT, UNF_WARN,
				  "[warn]Port(0x%x) scsi_id(0x%x) rport(0x%p) target_id(0x%x) cmd(0x%p), dma map sg err",
				  lport->port_id, scsi_id,
				  p_rport, p_rport->scsi_target_id, cmd);
			cmd->result = DID_BUS_BUSY << 16;
			cmd->scsi_done(cmd);
			ret_value = DID_BUS_BUSY;
			UNF_IO_RESULT_CNT(scsi_image_table, scsi_id, ret_value);
			return SCSI_MLQUEUE_HOST_BUSY;
		}
	}

	/* Construct local SCSI CMND info */
	/* save host_no to scsi_cmnd->scsi_host_id */
	scsi_cmnd.scsi_host_id = host->host_no;
	scsi_cmnd.scsi_id = scsi_id;
	scsi_cmnd.lun_id = raw_lun_id;
	scsi_cmnd.data_direction = cmd->sc_data_direction;
	scsi_cmnd.underflow = cmd->underflow;
	scsi_cmnd.cmnd_len = cmd->cmd_len;
	scsi_cmnd.pcmnd = cmd->cmnd;
	scsi_cmnd.transfer_len = cpu_to_le32((uint32_t)scsi_bufflen(cmd));
	scsi_cmnd.sense_buf_len = SCSI_SENSE_DATA_LEN;
	scsi_cmnd.sense_buf = cmd->sense_buffer;
	scsi_cmnd.time_out = 0;
	scsi_cmnd.upper_cmnd = cmd;
	scsi_cmnd.drv_private =
		(void *)(*(unsigned long long *)shost_priv(host));
	scsi_cmnd.entry_count = data_seg_cnt;
	scsi_cmnd.sgl = scsi_sglist(cmd);
	scsi_cmnd.pfn_unf_ini_get_sgl_entry = unf_get_frame_entry_buf;
	scsi_cmnd.pfn_done = unf_scsi_done;
	scsi_cmnd.pc_lun_id = (unsigned char *)&scsi_cmnd.lun_id;
	scsi_cmnd.err_code_table_cout = ini_err_code_table_cnt1;
	scsi_cmnd.err_code_table = ini_error_code_table1;
	scsi_cmnd.world_id = 0xfffffffc;
	scsi_cmnd.cmnd_sn = atomic64_inc_return(&ull_count);
	if (unlikely(scsi_cmnd.cmnd_sn == 0))
		scsi_cmnd.cmnd_sn = atomic64_inc_return(&ull_count);

	if ((scsi_get_prot_op(cmd) != SCSI_PROT_NORMAL) &&
	    hifc_dif_enable) {
		ret = unf_get_protect_mode(lport, cmd, &scsi_cmnd);
		if (ret != RETURN_OK) {
			cmd->result = DID_BUS_BUSY << 16;
			cmd->scsi_done(cmd);
			ret_value = DID_BUS_BUSY;
			UNF_IO_RESULT_CNT(scsi_image_table, scsi_id,
					  ret_value);
			scsi_dma_unmap(cmd);
			return SCSI_MLQUEUE_HOST_BUSY;
		}
	}

	UNF_TRACE(0x3808, UNF_LOG_LOGIN_ATT, UNF_INFO,
		  "[info]Port(0x%x) host(0x%x) scsi_id(0x%x) lun(0x%llx) transfer length(0x%x) cmd_len(0x%x) direction(0x%x) cmd(0x%x) under_flow(0x%x)",
		  lport->port_id, host->host_no, scsi_id,
		  (unsigned long long)cmd->device->lun,
		  scsi_cmnd.transfer_len,
		  scsi_cmnd.cmnd_len, cmd->sc_data_direction,
		  scsi_cmnd.pcmnd[0], scsi_cmnd.underflow);
	/* Bind the Exchange address corresponding to scsi_cmnd to
	 * scsi_cmnd->host_scribble
	 */
	cmd->host_scribble = (unsigned char *)scsi_cmnd.cmnd_sn;
	ret = unf_cm_queue_command(&scsi_cmnd);
	if (ret != RETURN_OK) {
		rport = unf_find_rport_by_scsi_id(lport,
						  ini_error_code_table1,
						  ini_err_code_table_cnt1,
						  scsi_id,
						  &cmnd_result);
		rport_state_err = (!rport) ||
				  (rport->lport_ini_state !=
				   UNF_PORT_STATE_LINKUP) ||
				  (rport->rp_state == UNF_RPORT_ST_CLOSING);
		scan_device_cmd = (cmd->cmnd[0] == INQUIRY) ||
					(cmd->cmnd[0] == REPORT_LUNS);

		/* report lun or inquiry cmd if send failed, do not retry,
		 * prevent the scan_mutex in scsi host locked up by eachother
		 */
		if (rport_state_err && scan_device_cmd) {
			UNF_TRACE(0x3808, UNF_LOG_LOGIN_ATT, UNF_WARN,
				  "[warn]Port(0x%x) host(0x%x) scsi_id(0x%x) lun(0x%llx) cmd(0x%x) cmResult(0x%x) DID_NO_CONNECT",
				  lport->port_id, host->host_no, scsi_id,
				  (unsigned long long)cmd->device->lun,
				  cmd->cmnd[0], cmnd_result);

			cmd->result = DID_NO_CONNECT << 16;
			cmd->scsi_done(cmd);
			ret_value = DID_NO_CONNECT;
			UNF_IO_RESULT_CNT(scsi_image_table, scsi_id, ret_value);
			scsi_dma_unmap(cmd);
			unf_unmap_prot_sgl(cmd);
			return 0;
		}

		/* Host busy: scsi need to retry */
		ret = SCSI_MLQUEUE_HOST_BUSY;
		if (likely(scsi_image_table->wwn_rport_info_table)) {
			if (likely(scsi_image_table->wwn_rport_info_table[scsi_id].dfx_counter))
				atomic64_inc(&scsi_image_table->wwn_rport_info_table[scsi_id].dfx_counter->host_busy);
		}
		scsi_dma_unmap(cmd);
		unf_unmap_prot_sgl(cmd);
		UNF_TRACE(0x3808, UNF_LOG_LOGIN_ATT, UNF_WARN,
			  "[warn]Port(0x%x) return(0x%x) to process INI IO falid",
			  lport->port_id, ret);
	}
	return ret;
}

static int unf_scsi_abort_scsi_cmnd(struct scsi_cmnd *v_cmnd)
{
	/* SCSI ABORT Command --->>> FC ABTS */
	struct unf_scsi_cmd_s scsi_cmnd = { 0 };
	struct Scsi_Host *scsi_host = NULL;
	int ret = FAILED;
	struct unf_rport_scsi_id_image_s *scsi_image_table = NULL;
	struct unf_lport_s *lport = NULL;
	unsigned int scsi_id = 0;
	unsigned int err_handle = 0;

	UNF_CHECK_VALID(0x516, UNF_TRUE, v_cmnd, return FAILED);

	lport = (struct unf_lport_s *)v_cmnd->device->host->hostdata[0];
	scsi_id = (unsigned int)((unsigned long long)v_cmnd->device->hostdata);

	if (unf_is_lport_valid(lport) == RETURN_OK) {
		scsi_image_table = &lport->rport_scsi_table;
		err_handle = UNF_SCSI_ABORT_IO_TYPE;
		UNF_SCSI_ERROR_HANDLE_CNT(scsi_image_table,
					  scsi_id, err_handle);

		UNF_TRACE(0x3808, UNF_LOG_LOGIN_ATT, UNF_MAJOR,
			  "[abort]Port(0x%x) scsi_id(0x%x) lun_id(0x%x) cmnd_type(0x%x)",
			  lport->port_id, scsi_id,
			  (unsigned int)v_cmnd->device->lun,
			  v_cmnd->cmnd[0]);
	} else {
		UNF_TRACE(0x3808, UNF_LOG_LOGIN_ATT, UNF_ERR,
			  "[err]Lport(%p) is moving or null", lport);

		return UNF_SCSI_ABORT_FAIL;
	}

	/* Check local SCSI_ID validity */
	if (unlikely(scsi_id >= UNF_MAX_SCSI_ID)) {
		UNF_TRACE(0x3808, UNF_LOG_LOGIN_ATT, UNF_ERR,
			  "[err]scsi_id(0x%x) is max than(0x%x)",
			  scsi_id, UNF_MAX_SCSI_ID);

		return UNF_SCSI_ABORT_FAIL;
	}

	/* Block scsi (check rport state -> whether offline or not) */
	ret = fc_block_scsi_eh(v_cmnd);
	if (unlikely(ret != 0)) {
		UNF_TRACE(0x3808, UNF_LOG_LOGIN_ATT, UNF_WARN,
			  "[warn]Block scsi eh failed(0x%x)", ret);

		return ret;
	}

	scsi_host = v_cmnd->device->host;
	scsi_cmnd.scsi_host_id = scsi_host->host_no;  // L_Port ID
	scsi_cmnd.scsi_id = scsi_id;  // R_Port ID (Target ID)
	scsi_cmnd.lun_id = (unsigned long long)v_cmnd->device->lun;  // LUN ID
	scsi_cmnd.upper_cmnd = v_cmnd;  // scsi_cmnd
	// L_Port
	scsi_cmnd.drv_private =
		(void *)(*(unsigned long long *)shost_priv(scsi_host));
	scsi_cmnd.cmnd_sn = (unsigned long long)(v_cmnd->host_scribble);
	scsi_cmnd.pc_lun_id = (unsigned char *)&scsi_cmnd.lun_id;
	scsi_cmnd.pfn_done = unf_scsi_done;
	scsi_cmnd.world_id = 0xfffffffc;
	/* Process scsi Abort cmnd */
	ret = unf_cm_eh_abort_handler(&scsi_cmnd);
	if (ret == UNF_SCSI_ABORT_SUCCESS) {
		if (unf_is_lport_valid(lport) == RETURN_OK) {
			scsi_image_table = &lport->rport_scsi_table;
			err_handle = UNF_SCSI_ABORT_IO_TYPE;
			UNF_SCSI_ERROR_HANDLE_RESULT_CNT(scsi_image_table,
							 scsi_id, err_handle);
		}
	}

	return ret;
}

static int unf_scsi_device_reset_handler(struct scsi_cmnd *v_cmnd)
{
	/* LUN reset */
	struct unf_scsi_cmd_s scsi_cmnd = { 0 };
	struct Scsi_Host *scsi_host = NULL;
	struct unf_rport_scsi_id_image_s *scsi_image_table = NULL;
	int ret = FAILED;
	struct unf_lport_s *lport = NULL;
	unsigned int scsi_id = 0;
	unsigned int err_handle = 0;

	UNF_CHECK_VALID(0x517, UNF_TRUE, v_cmnd, return FAILED);

	lport = (struct unf_lport_s *)v_cmnd->device->host->hostdata[0];
	if (unf_is_lport_valid(lport) == RETURN_OK) {
		scsi_image_table = &lport->rport_scsi_table;
		err_handle = UNF_SCSI_DEVICE_RESET_TYPE;
		UNF_SCSI_ERROR_HANDLE_CNT(scsi_image_table,
					  scsi_id, err_handle);

		UNF_TRACE(0x3808, UNF_LOG_LOGIN_ATT, UNF_KEVENT,
			  "[device_reset]Port(0x%x) scsi_id(0x%x) lun_id(0x%x) cmnd_type(0x%x)",
			  lport->port_id, scsi_id,
			  (unsigned int)v_cmnd->device->lun,
			  v_cmnd->cmnd[0]);
	} else {
		UNF_TRACE(0x3808, UNF_LOG_LOGIN_ATT, UNF_ERR,
			  "[err]Port is invalid");

		return FAILED;
	}

	/* Check local SCSI_ID validity */
	scsi_id = (unsigned int)((unsigned long long)v_cmnd->device->hostdata);
	if (unlikely(scsi_id >= UNF_MAX_SCSI_ID)) {
		UNF_TRACE(0x3808, UNF_LOG_LOGIN_ATT, UNF_ERR,
			  "[err]scsi_id(0x%x) is max than(0x%x)",
			  scsi_id, UNF_MAX_SCSI_ID);

		return FAILED;
	}

	/* Block scsi (check rport state -> whether offline or not) */
	ret = fc_block_scsi_eh(v_cmnd);
	if (unlikely(ret != 0)) {
		UNF_TRACE(0x3808, UNF_LOG_LOGIN_ATT, UNF_WARN,
			  "[warn]Block scsi eh failed(0x%x)", ret);

		return ret;
	}

	scsi_host = v_cmnd->device->host;
	scsi_cmnd.scsi_host_id = scsi_host->host_no;  /* l_port id */
	scsi_cmnd.scsi_id = scsi_id;  /* r_port id */
	scsi_cmnd.lun_id = (unsigned long long)v_cmnd->device->lun; /* lun id */
	scsi_cmnd.upper_cmnd = v_cmnd;  /* scsi_cmnd */
	/* l_port */
	scsi_cmnd.drv_private =
		(void *)(*(unsigned long long *)shost_priv(scsi_host));
	scsi_cmnd.pc_lun_id = (unsigned char *)&scsi_cmnd.lun_id;  /* lun id */

	/* Process scsi device/LUN reset cmnd */
	ret = unf_cm_eh_device_reset_handler(&scsi_cmnd);
	if (ret == UNF_SCSI_ABORT_SUCCESS) {
		if (unf_is_lport_valid(lport) == RETURN_OK) {
			scsi_image_table = &lport->rport_scsi_table;
			err_handle = UNF_SCSI_DEVICE_RESET_TYPE;
			UNF_SCSI_ERROR_HANDLE_RESULT_CNT(scsi_image_table,
							 scsi_id,
							 err_handle);
		}
	}

	return ret;
}

static int unf_scsi_bus_reset_handler(struct scsi_cmnd *v_cmnd)
{
	/* BUS Reset */
	struct unf_scsi_cmd_s scsi_cmnd = { 0 };
	struct unf_lport_s *lport = NULL;
	struct Scsi_Host *scsi_host = NULL;
	struct unf_rport_scsi_id_image_s *scsi_image_table = NULL;
	int ret = FAILED;
	unsigned int scsi_id = 0;
	unsigned int err_handle = 0;

	UNF_CHECK_VALID(0x517, UNF_TRUE, v_cmnd, return FAILED);

	lport = (struct unf_lport_s *)v_cmnd->device->host->hostdata[0];
	if (unlikely(!lport)) {
		UNF_TRACE(0x3808, UNF_LOG_LOGIN_ATT, UNF_ERR,
			  "[err]Port is null");

		return FAILED;
	}

	/* Check local SCSI_ID validity */
	scsi_id = (unsigned int)((unsigned long long)v_cmnd->device->hostdata);
	if (unlikely(scsi_id >= UNF_MAX_SCSI_ID)) {
		UNF_TRACE(0x3808, UNF_LOG_LOGIN_ATT, UNF_ERR,
			  "[err]scsi_id(0x%x) is max than(0x%x)",
			  scsi_id, UNF_MAX_SCSI_ID);

		return FAILED;
	}

	if (unf_is_lport_valid(lport) == RETURN_OK) {
		scsi_image_table = &lport->rport_scsi_table;
		err_handle = UNF_SCSI_BUS_RESET_TYPE;
		UNF_SCSI_ERROR_HANDLE_CNT(scsi_image_table,
					  scsi_id, err_handle);

		UNF_TRACE(0x3808, UNF_LOG_LOGIN_ATT, UNF_MAJOR,
			  "[info][bus_reset]Port(0x%x) scsi_id(0x%x) lun_id(0x%x) cmnd_type(0x%x)",
			  lport->port_id, scsi_id,
			  (unsigned int)v_cmnd->device->lun,
			  v_cmnd->cmnd[0]);
	}

	/* Block scsi (check rport state -> whether offline or not) */
	ret = fc_block_scsi_eh(v_cmnd);
	if (unlikely(ret != 0)) {
		UNF_TRACE(0x3808, UNF_LOG_LOGIN_ATT, UNF_WARN,
			  "[warn]Block scsi eh failed(0x%x)", ret);

		return ret;
	}

	scsi_host = v_cmnd->device->host;
	scsi_cmnd.scsi_host_id = scsi_host->host_no;  /* l_port id */
	scsi_cmnd.scsi_id = scsi_id;  /* r_port id */
	scsi_cmnd.lun_id = (unsigned long long)v_cmnd->device->lun; /* lun id */
	scsi_cmnd.upper_cmnd = v_cmnd;  /* scsi_cmnd */
	/* l_port */
	scsi_cmnd.drv_private =
		(void *)(*(unsigned long long *)shost_priv(scsi_host));
	scsi_cmnd.pc_lun_id = (unsigned char *)&scsi_cmnd.lun_id; /* lun id */

	/* Process scsi BUS Reset cmnd */
	ret = unf_cm_bus_reset_handler(&scsi_cmnd);
	if (ret == UNF_SCSI_ABORT_SUCCESS) {
		if (unf_is_lport_valid(lport) == RETURN_OK) {
			scsi_image_table = &lport->rport_scsi_table;
			err_handle = UNF_SCSI_BUS_RESET_TYPE;
			UNF_SCSI_ERROR_HANDLE_RESULT_CNT(scsi_image_table,
							 scsi_id,
							 err_handle);
		}
	}

	return ret;
}

static int unf_scsi_target_reset_handler(struct scsi_cmnd *v_cmnd)
{
	/* Session reset/delete */
	struct unf_scsi_cmd_s scsi_cmnd = { 0 };
	struct Scsi_Host *scsi_host = NULL;
	struct unf_rport_scsi_id_image_s *scsi_image_table = NULL;
	int ret = FAILED;
	struct unf_lport_s *lport = NULL;
	unsigned int scsi_id = 0;
	unsigned int err_handle = 0;

	UNF_CHECK_VALID(0x517, UNF_TRUE, v_cmnd, return RETURN_ERROR);

	lport = (struct unf_lport_s *)v_cmnd->device->host->hostdata[0];
	if (unlikely(!lport)) {
		UNF_TRACE(0x3808, UNF_LOG_LOGIN_ATT, UNF_ERR,
			  "[err]Port is null");

		return FAILED;
	}

	/* Check local SCSI_ID validity */
	scsi_id = (unsigned int)((unsigned long long)v_cmnd->device->hostdata);
	if (unlikely(scsi_id >= UNF_MAX_SCSI_ID)) {
		UNF_TRACE(0x3808, UNF_LOG_LOGIN_ATT, UNF_ERR,
			  "[err]scsi_id(0x%x) is max than(0x%x)",
			  scsi_id, UNF_MAX_SCSI_ID);

		return FAILED;
	}

	if (unf_is_lport_valid(lport) == RETURN_OK) {
		scsi_image_table = &lport->rport_scsi_table;
		err_handle = UNF_SCSI_TARGET_RESET_TYPE;
		UNF_SCSI_ERROR_HANDLE_CNT(scsi_image_table, scsi_id,
					  err_handle);

		UNF_TRACE(0x3808, UNF_LOG_LOGIN_ATT, UNF_KEVENT,
			  "[target_reset]Port(0x%x) scsi_id(0x%x) lun_id(0x%x) cmnd_type(0x%x)",
			  lport->port_id, scsi_id,
			  (unsigned int)v_cmnd->device->lun,
			  v_cmnd->cmnd[0]);
	}

	/* Block scsi (check rport state -> whether offline or not) */
	ret = fc_block_scsi_eh(v_cmnd);
	if (unlikely(ret != 0)) {
		UNF_TRACE(0x3808, UNF_LOG_LOGIN_ATT, UNF_WARN,
			  "[warn]Block scsi eh failed(0x%x)", ret);

		return ret;
	}

	scsi_host = v_cmnd->device->host;
	scsi_cmnd.scsi_host_id = scsi_host->host_no;  /* l_port id */
	scsi_cmnd.scsi_id = scsi_id;  /* r_port id */
	scsi_cmnd.lun_id = (unsigned long long)v_cmnd->device->lun; /* lun id */
	scsi_cmnd.upper_cmnd = v_cmnd;  /* scsi_cmnd */
	/* l_port */
	scsi_cmnd.drv_private =
		(void *)(*(unsigned long long *)shost_priv(scsi_host));
	scsi_cmnd.pc_lun_id = (unsigned char *)&scsi_cmnd.lun_id;  /* lun id */

	/* Process scsi Target/Session reset/delete cmnd */
	ret = unf_cm_target_reset_handler(&scsi_cmnd);
	if (ret == UNF_SCSI_ABORT_SUCCESS) {
		if (unf_is_lport_valid(lport) == RETURN_OK) {
			scsi_image_table = &lport->rport_scsi_table;
			err_handle = UNF_SCSI_TARGET_RESET_TYPE;
			UNF_SCSI_ERROR_HANDLE_RESULT_CNT(scsi_image_table,
							 scsi_id, err_handle);
		}
	}

	return ret;
}

static int unf_scsi_slave_alloc(struct scsi_device *sdev)
{
	/*lint -e666 -esym(666,*)*/
	struct fc_rport *rport = NULL;
	unsigned int scsi_id = 0;
	struct unf_lport_s *lport = NULL;
	struct Scsi_Host *host = NULL;
	struct unf_rport_scsi_id_image_s *scsi_image_table = NULL;

	/* About device */
	if (unlikely(!sdev)) {
		UNF_TRACE(0x4101, UNF_LOG_LOGIN_ATT, UNF_ERR,
			  "[err]SDev is null");

		return -ENXIO;
	}

	/* About scsi rport */
	rport = starget_to_rport(scsi_target(sdev));
	if (unlikely(!rport || fc_remote_port_chkready(rport))) {
		UNF_TRACE(0x4101, UNF_LOG_LOGIN_ATT, UNF_ERR,
			  "[err]SCSI rport is null");

		if (rport) {
			UNF_TRACE(0x4101, UNF_LOG_LOGIN_ATT, UNF_ERR,
				  "[err]SCSI rport is not ready(0x%x)",
				  fc_remote_port_chkready(rport));
		}

		return -ENXIO;
	}

	/* About host */
	host = rport_to_shost(rport);
	if (unlikely(!host)) {
		UNF_TRACE(0x3808, UNF_LOG_LOGIN_ATT, UNF_ERR,
			  "[err]Host is null");

		return -ENXIO;
	}

	/* About Local Port */
	lport = (struct unf_lport_s *)host->hostdata[0];
	if (unf_is_lport_valid(lport) != RETURN_OK) {
		UNF_TRACE(0x3808, UNF_LOG_LOGIN_ATT, UNF_ERR,
			  "[err]Port is invalid");

		return -ENXIO;
	}

	/* About Local SCSI_ID */
	/* use local SCSI_ID to alloc slave device */
	scsi_id = *(unsigned int *)rport->dd_data;
	if (unlikely(scsi_id >= UNF_MAX_SCSI_ID)) {
		UNF_TRACE(0x3808, UNF_LOG_LOGIN_ATT, UNF_ERR,
			  "[err]scsi_id(0x%x) is max than(0x%x)",
			  scsi_id, UNF_MAX_SCSI_ID);

		return -ENXIO;
	}

	scsi_image_table = &lport->rport_scsi_table;
	if (scsi_image_table->wwn_rport_info_table[scsi_id].dfx_counter)
		atomic_inc(&scsi_image_table->wwn_rport_info_table[scsi_id].dfx_counter->device_alloc);

	atomic_inc(&lport->device_alloc);
	/* save local SCSI_ID */
	sdev->hostdata = (void *)(unsigned long long)scsi_id;

	UNF_TRACE(0x4101, UNF_LOG_LOGIN_ATT, UNF_KEVENT,
		  "[event]Port(0x%x) use scsi_id(%d) to alloc device[%u:%u:%u:%u]",
		  lport->port_id, scsi_id, host->host_no,
		  sdev->channel, sdev->id, (unsigned int)sdev->lun);

	return 0;
}

static void unf_scsi_destroy_slave(struct scsi_device *sdev)
{
	/*
	 * NOTE: about sdev->hostdata
	 * --->>> pointing to local SCSI_ID
	 * 1. Assignment during slave allocation
	 * 2. Released when callback for slave destroy
	 * 3. Used during: Queue_CMND, Abort CMND, Device Reset,
	 *    Target Reset & Bus Reset
	 */
	/*lint -e666 -esym(666,*)*/
	struct fc_rport *rport = NULL;
	unsigned int scsi_id = 0;
	struct unf_lport_s *lport = NULL;
	struct Scsi_Host *host = NULL;
	struct unf_rport_scsi_id_image_s *scsi_image_table = NULL;

	/* About scsi device */
	if (unlikely(!sdev)) {
		UNF_TRACE(0x4101, UNF_LOG_LOGIN_ATT, UNF_ERR,
			  "[err]SDev is null");
		return;
	}

	/* About scsi rport */
	rport = starget_to_rport(scsi_target(sdev));
	if (unlikely(!rport)) {
		UNF_TRACE(0x4101, UNF_LOG_LOGIN_ATT, UNF_ERR,
			  "[err]SCSI rport is null or remote port is not ready");
		return;
	}

	/* About host */
	host = rport_to_shost(rport);
	if (unlikely(!host)) {
		UNF_TRACE(0x3808, UNF_LOG_LOGIN_ATT, UNF_ERR,
			  "[err]Host is null");
		return;
	}

	/* About L_Port */
	lport = (struct unf_lport_s *)host->hostdata[0];
	if (unf_is_lport_valid(lport) == RETURN_OK) {
		scsi_image_table = &lport->rport_scsi_table;
		atomic_inc(&lport->device_destroy);

		scsi_id = (unsigned int)((unsigned long long)sdev->hostdata);
		if ((scsi_id < UNF_MAX_SCSI_ID) &&
		    (scsi_image_table->wwn_rport_info_table)) {
			if (scsi_image_table->wwn_rport_info_table[scsi_id].dfx_counter)
				atomic_inc(&scsi_image_table->wwn_rport_info_table[scsi_id].dfx_counter->device_destroy);

			UNF_TRACE(0x4101, UNF_LOG_LOGIN_ATT, UNF_KEVENT,
				  "[event]Port(0x%x) with scsi_id(%d) to destroy slave device[%u:%u:%u:%u]",
				  lport->port_id, scsi_id, host->host_no,
				  sdev->channel, sdev->id,
				  (unsigned int)sdev->lun);
		} else {
			UNF_TRACE(0x4101, UNF_LOG_LOGIN_ATT, UNF_WARN,
				  "[err]Port(0x%x) scsi_id(%d) is invalid and destroy device[%u:%u:%u:%u]",
				  lport->port_id, scsi_id, host->host_no,
				  sdev->channel, sdev->id,
				  (unsigned int)sdev->lun);
		}
	} else {
		UNF_TRACE(0x3097, UNF_LOG_LOGIN_ATT, UNF_ERR,
			  "[err]Port(%p) is invalid", lport);
	}

	sdev->hostdata = NULL;  /* reset local SCSI_ID */
}

static int unf_scsi_slave_configure(struct scsi_device *sdev)
{
#define UNF_SCSI_DEV_DEPTH 32
	blk_queue_update_dma_alignment(sdev->request_queue, 0x7);
	scsi_change_queue_depth(sdev, UNF_SCSI_DEV_DEPTH);
	UNF_TRACE(0x4101, UNF_LOG_LOGIN_ATT, UNF_INFO,
		  "[event]Enter slave configure, set depth is %d, sdev->tagged_supported is (%d)",
		  UNF_SCSI_DEV_DEPTH, sdev->tagged_supported);

	return 0;
}

static int unf_scsi_scan_finished(struct Scsi_Host *shost, unsigned long time)
{
	UNF_TRACE(0x4101, UNF_LOG_LOGIN_ATT, UNF_MAJOR,
		  "[event]Scan finished");

	return 1;
}

static void unf_scsi_scan_start(struct Scsi_Host *shost)
{
	UNF_TRACE(0x4101, UNF_LOG_LOGIN_ATT, UNF_MAJOR,
		  "[event]Start scsi scan...");
}

unsigned int unf_register_ini_transport(void)
{
	/* Register INI Transport */
	scsi_transport_template = fc_attach_transport(&function_template);

	if (!scsi_transport_template) {
		UNF_TRACE(0x4101, UNF_LOG_LOGIN_ATT, UNF_ERR,
			  "[err]Register FC transport to scsi failed");

		return RETURN_ERROR;
	}

	scsi_transport_template_v = fc_attach_transport(&function_template_v);
	if (!scsi_transport_template_v) {
		UNF_TRACE(0x4101, UNF_LOG_LOGIN_ATT, UNF_ERR,
			  "[err]Register FC vport transport to scsi failed");

		fc_release_transport(scsi_transport_template);

		return RETURN_ERROR;
	}

	UNF_TRACE(0x4101, UNF_LOG_LOGIN_ATT, UNF_MAJOR,
		  "[event]Register FC transport to scsi succeed");

	return RETURN_OK;
}

void unf_unregister_ini_transport(void)
{
	fc_release_transport(scsi_transport_template);
	fc_release_transport(scsi_transport_template_v);
	UNF_TRACE(0x4101, UNF_LOG_LOGIN_ATT, UNF_MAJOR,
		  "[event]Unregister FC transport succeed");
}

void unf_report_io_dm_event(void *v_lport, unsigned int type,
			    unsigned int value)
{
}

void unf_save_sense_data(void *scsicmd, const char *sense, int senslen)
{
	struct scsi_cmnd *cmd;

	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE, scsicmd, return);
	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE, sense, return);

	cmd = (struct scsi_cmnd *)scsicmd;
	memcpy(cmd->sense_buffer, sense, senslen);
}
