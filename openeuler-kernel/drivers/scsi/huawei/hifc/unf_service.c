// SPDX-License-Identifier: GPL-2.0
/* Huawei Hifc PCI Express Linux driver
 * Copyright(c) 2017 Huawei Technologies Co., Ltd
 *
 */
#include "unf_exchg.h"
#include "unf_log.h"
#include "unf_rport.h"
#include "unf_exchg.h"
#include "unf_service.h"
#include "unf_portman.h"
#include "unf_npiv.h"

static void unf_flogi_callback(void *v_lport,
			       void *v_rport,
			       void *v_xchg);
static void unf_fdisc_callback(void *v_lport,
			       void *v_rport,
			       void *v_xchg);
static void unf_plogi_callback(void *v_lport,
			       void *v_rport,
			       void *v_xchg);
static unsigned int unf_rec_handler(struct unf_lport_s *v_lport,
				    unsigned int v_sid,
				    struct unf_xchg_s *v_xchg);
static void unf_gid_ft_callback(void *v_lport,
				void *v_rport,
				void *v_xchg);
static void unf_gid_pt_callback(void *v_lport,
				void *v_rport,
				void *v_xchg);
static void unf_process_rport_after_logo(struct unf_lport_s *v_lport,
					 struct unf_rport_s *v_rport);
static unsigned int unf_flogi_handler(struct unf_lport_s *v_lport,
				      unsigned int v_sid,
				      struct unf_xchg_s *v_xchg);
static unsigned int unf_plogi_handler(struct unf_lport_s *v_lport,
				      unsigned int v_sid,
				      struct unf_xchg_s *v_xchg);
static unsigned int unf_prli_handler(struct unf_lport_s *v_lport,
				     unsigned int v_sid,
				     struct unf_xchg_s *v_xchg);
static unsigned int unf_prlo_handler(struct unf_lport_s *v_lport,
				     unsigned int v_sid,
				     struct unf_xchg_s *v_xchg);
static unsigned int unf_rscn_handler(struct unf_lport_s *v_lport,
				     unsigned int v_sid,
				     struct unf_xchg_s *v_xchg);
static unsigned int unf_logo_handler(struct unf_lport_s *v_lport,
				     unsigned int v_sid,
				     struct unf_xchg_s *v_xchg);
static unsigned int unf_echo_handler(struct unf_lport_s *v_lport,
				     unsigned int v_sid,
				     struct unf_xchg_s *v_xchg);
static unsigned int unf_pdisc_handler(struct unf_lport_s *v_lport,
				      unsigned int v_sid,
				      struct unf_xchg_s *v_xchg);
static unsigned int unf_adisc_handler(struct unf_lport_s *v_lport,
				      unsigned int v_sid,
				      struct unf_xchg_s *v_xchg);
static unsigned int unf_rrq_handler(struct unf_lport_s *v_lport,
				    unsigned int v_sid,
				    struct unf_xchg_s *v_xchg);
static unsigned int unf_rls_handler(struct unf_lport_s *v_lport,
				    unsigned int v_sid,
				    struct unf_xchg_s *v_xchg);
static unsigned int unf_send_els_rjt_by_rport(
					struct unf_lport_s *v_lport,
					struct unf_xchg_s *v_xchg,
					struct unf_rport_s *v_rport,
					struct unf_rjt_info_s *v_rjt_info);

unsigned int max_frame_size = UNF_DEFAULT_FRAME_SIZE;

#define FCP_XFER_RDY_IU   0x05
#define FCP_RSP_IU        0x07
#define FCP_DATA_IU       0x01

#define UNF_GID_LAST_PORT_ID  0x80
#define UNF_LOWLEVEL_BBCREDIT 0x6
#define UNF_DEFAULT_BB_SC_N   0
#define UNF_INIT_DISC         0x1 /* first time DISC */
#define UNF_RSCN_DISC         0x2 /* RSCN Port Addr DISC */
/* Reference from FCP-4 Table33 RR_TOV:  REC_TOV + 2*R_A_TOV + 1S,
 * REC_TOV = E_D_TOV + 1s
 */
#define UNF_CALC_LPORT_RRTOV(v_lport) \
	(((v_lport)->ed_tov + 1000) + (2 * (v_lport)->ra_tov + 1000))

#define UNF_GID_CONTROL(v_nport_id) ((v_nport_id) >> 24)

#define UNF_ECHO_PLD_DATA 0x1234567890ABCDEF
#define UNF_ECHO_REQ_SIZE 0

#define UNF_GET_PORT_OPTIONS(v_fc4feature) ((v_fc4feature) >> 20)

#define UNF_GET_DOMAIN_ID(x) (((x) & 0xFF0000) >> 16) /* domain id */
#define UNF_GET_AREA_ID(x)   (((x) & 0x00FF00) >> 8)  /* area id */

#define UNF_SERVICE_GET_NPORTID_FORM_GID_PAGE(v_port_id_page) \
	(((unsigned int)(v_port_id_page)->port_id_domain << 16) | \
	 ((unsigned int)(v_port_id_page)->port_id_area << 8) | \
	 ((unsigned int)(v_port_id_page)->port_id_port))

#define UNF_GNN_GFF_ID_RJT_REASON(rjt_reason) \
	((((rjt_reason) & UNF_CTIU_RJT_MASK) == \
	 UNF_CTIU_RJT_UNABLE_PERFORM) && \
	 ((((rjt_reason) & UNF_CTIU_RJT_EXP_MASK) == \
	  UNF_CTIU_RJT_EXP_PORTID_NO_REG) || \
	 (((rjt_reason) & UNF_CTIU_RJT_EXP_MASK) == \
	  UNF_CTIU_RJT_EXP_PORTNAME_NO_REG) || \
	 (((rjt_reason) & UNF_CTIU_RJT_EXP_MASK) == \
	  UNF_CTIU_RJT_EXP_NODENAME_NO_REG)))

#define UNF_NEED_BIG_RESPONSE_BUFF(cmnd_code) \
	(((cmnd_code) == ELS_ECHO) || ((cmnd_code) == NS_GID_PT) || \
	 ((cmnd_code) == NS_GID_FT))

#define NEED_REFRESH_NPORTID(pkg) ((((pkg)->cmnd == ELS_PLOGI) || \
				   ((pkg)->cmnd == ELS_PDISC) || \
				   ((pkg)->cmnd == ELS_ADISC)))

struct unf_els_handler_table {
	unsigned int cmnd;
	unsigned int (*pfn_els_cmnd_handler)(struct unf_lport_s *,
					     unsigned int, struct unf_xchg_s *);
};

#define UNF_SERVICE_COLLECT(service_collect, item) \
	do { \
		if ((item) < UNF_SERVICE_BUTT) { \
			service_collect.service_cnt[(item)]++;  \
		} \
	} while (0)

struct unf_els_handler_table els_handle[] = {
	{ ELS_PLOGI, unf_plogi_handler },
	{ ELS_FLOGI, unf_flogi_handler },
	{ ELS_LOGO,  unf_logo_handler },
	{ ELS_ECHO,  unf_echo_handler },
	{ ELS_RRQ,   unf_rrq_handler },
	{ ELS_REC,   unf_rec_handler },
	{ ELS_PRLI,  unf_prli_handler },
	{ ELS_PRLO,  unf_prlo_handler },
	{ ELS_PDISC, unf_pdisc_handler },
	{ ELS_ADISC, unf_adisc_handler },
	{ ELS_RSCN,  unf_rscn_handler },
	{ ELS_RLS,   unf_rls_handler }
};

static void unf_check_rport_need_delay_prli(struct unf_lport_s *v_lport,
					    struct unf_rport_s *v_rport,
					    unsigned int v_port_feature)
{
	unsigned int ret = UNF_RETURN_ERROR;

	UNF_CHECK_VALID(0x3300, UNF_TRUE, v_lport, return);
	UNF_CHECK_VALID(0x3301, UNF_TRUE, v_rport, return);

	v_port_feature &= UNF_PORT_MODE_BOTH;

	/* Used for: L_Port has INI mode & R_Port is not SW */
	if (v_rport->nport_id < UNF_FC_FID_DOM_MGR) {
		/*
		 * 1. immediately: R_Port only with TGT, or
		 * L_Port only with INI & R_Port has TGT mode,
		 * send PRLI immediately
		 */
		if (((v_port_feature == UNF_PORT_MODE_TGT) ||
		     (v_lport->en_act_topo == UNF_ACT_TOP_P2P_DIRECT)) ||
		    ((v_port_feature & UNF_PORT_MODE_TGT) ==
		      UNF_PORT_MODE_TGT)) {
			UNF_TRACE(UNF_EVTLOG_DRIVER_INFO,
				  UNF_LOG_LOGIN_ATT, UNF_MAJOR,
				  "[info]LOGIN: Port(0x%x_0x%x) Rport(0x%x) with feature(0x%x) send PRLI",
				  v_lport->port_id, v_lport->nport_id,
				  v_rport->nport_id, v_port_feature);

			/* Send PRLI to remote port */
			ret = unf_send_prli(v_lport, v_rport);
			if (ret != RETURN_OK) {
				UNF_TRACE(UNF_EVTLOG_DRIVER_WARN,
					  UNF_LOG_LOGIN_ATT,
					  UNF_WARN,
					  "[warn]LOGIN: Port(0x%x_0x%x) Rport(0x%x) with feature(0x%x) send PRLI failed",
					  v_lport->port_id,
					  v_lport->nport_id,
					  v_rport->nport_id,
					  v_port_feature);

				/* Do R_Port recovery */
				unf_rport_error_recovery(v_rport);
			}
		} else if (v_port_feature != UNF_PORT_MODE_INI) {
			/* 2. R_Port has BOTH mode or unknown,
			 * Delay to send PRLI
			 */
			/* Prevent: PRLI done before PLOGI */
			UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT,
				  UNF_MAJOR,
				  "[info]LOGIN: Port(0x%x_0x%x) Rport(0x%x) with feature(0x%x) delay to send PRLI",
				  v_lport->port_id, v_lport->nport_id,
				  v_rport->nport_id, v_port_feature);

			/* Delay to send PRLI to R_Port */
			unf_rport_delay_login(v_rport);
		} else {
			/* 3. R_Port only with INI mode: wait for R_Port's
			 * PRLI: Do not care
			 */
			/* Cancel recovery(timer) work */
			if (delayed_work_pending(&v_rport->recovery_work)) {
				if (cancel_delayed_work(
					&v_rport->recovery_work)) {
					UNF_TRACE(UNF_EVTLOG_DRIVER_INFO,
						  UNF_LOG_LOGIN_ATT, UNF_INFO,
						  "[info]LOGIN: Port(0x%x_0x%x) Rport(0x%x) with feature(0x%x) is pure INI",
						  v_lport->port_id,
						  v_lport->nport_id,
						  v_rport->nport_id,
						  v_port_feature);

					unf_rport_ref_dec(v_rport);
				}
			}

			/* Server: R_Port only support INI,
			 * do not care this case
			 */
			UNF_TRACE(UNF_EVTLOG_DRIVER_INFO,
				  UNF_LOG_LOGIN_ATT, UNF_MAJOR,
				  "[info]LOGIN: Port(0x%x_0x%x) Rport(0x%x) with feature(0x%x) wait for PRLI",
				  v_lport->port_id, v_lport->nport_id,
				  v_rport->nport_id, v_port_feature);
		}
	}
}

static unsigned int unf_low_level_bb_credit(struct unf_lport_s *v_lport)
{
	struct unf_lport_s *lport = NULL;
	unsigned int ret = UNF_RETURN_ERROR;
	unsigned int bb_credit = UNF_LOWLEVEL_BBCREDIT;

	if (unlikely(!v_lport))
		return bb_credit;

	lport = v_lport;
	if (unlikely(!lport->low_level_func.port_mgr_op.pfn_ll_port_config_get))
		return bb_credit;

	ret = lport->low_level_func.port_mgr_op.pfn_ll_port_config_get(
			(void *)lport->fc_port,
			UNF_PORT_CFG_GET_WORKBALE_BBCREDIT,
			(void *)&bb_credit);
	if (unlikely(ret != RETURN_OK)) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT, UNF_INFO,
			  "[warn]Port(0x%x) get BB_Credit failed, use default value(%d)",
			  lport->port_id, UNF_LOWLEVEL_BBCREDIT);

		bb_credit = UNF_LOWLEVEL_BBCREDIT;
	}

	UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT, UNF_INFO,
		  "[info]Port(0x%x) with BB_Credit(%u)",
		  lport->port_id, bb_credit);

	return bb_credit;
}

unsigned int unf_low_level_bbscn(struct unf_lport_s *v_lport)
{
	struct unf_lport_s *lport = v_lport;
	struct unf_low_level_port_mgr_op_s *port_mgr = NULL;
	unsigned int ret = UNF_RETURN_ERROR;
	unsigned int bb_scn = UNF_DEFAULT_BB_SC_N;

	if (unlikely(!v_lport))
		return bb_scn;

	port_mgr = &lport->low_level_func.port_mgr_op;

	if (unlikely(!port_mgr->pfn_ll_port_config_get))
		return bb_scn;

	ret = port_mgr->pfn_ll_port_config_get((void *)lport->fc_port,
					    UNF_PORT_CFG_GET_WORKBALE_BBSCN,
					    (void *)&bb_scn);
	if (unlikely(ret != RETURN_OK)) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT, UNF_INFO,
			  "[warn]Port(0x%x) get bbscn failed, use default value(%d)",
			  lport->port_id, UNF_DEFAULT_BB_SC_N);

		bb_scn = UNF_DEFAULT_BB_SC_N;
	}

	UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT, UNF_INFO,
		  "[info]Port(0x%x)'s bbscn(%d)",
		  lport->port_id, bb_scn);

	return bb_scn;
}

static unsigned int unf_els_cmnd_send(struct unf_lport_s *v_lport,
				      struct unf_frame_pkg_s *v_pkg,
				      struct unf_xchg_s *v_xchg)
{
	unsigned int ret = UNF_RETURN_ERROR;
	unsigned long time_out = 0;

	UNF_CHECK_VALID(0x3302, UNF_TRUE, v_lport, return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(0x3303, UNF_TRUE, v_pkg, return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(0x3304, UNF_TRUE, v_xchg, return UNF_RETURN_ERROR);

	if (unlikely(!v_lport->low_level_func.service_op.pfn_unf_els_send)) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_LOGIN_ATT, UNF_ERR,
			  "[err]Port(0x%x) ELS send function is NULL",
			  v_lport->port_id);

		return ret;
	}

	/* Add ELS command/response (Exchange) timeout timer */
	time_out = UNF_GET_ELS_SFS_XCHG_TIMER(v_lport);
	if (v_xchg->cmnd_code == ELS_RRQ) {
		time_out = ((unsigned long)
			    UNF_GET_ELS_SFS_XCHG_TIMER(v_lport) >
			    UNF_RRQ_MIN_TIMEOUT_INTERVAL) ?
			    (unsigned long)
			    UNF_GET_ELS_SFS_XCHG_TIMER(v_lport) :
			    UNF_RRQ_MIN_TIMEOUT_INTERVAL;
	} else if (v_xchg->cmnd_code == ELS_LOGO) {
		time_out = UNF_LOGO_TIMEOUT_INTERVAL;
	}
	v_lport->xchg_mgr_temp.pfn_unf_xchg_add_timer((void *)v_xchg,
						   time_out,
						   UNF_TIMER_TYPE_SFS);

	v_pkg->private[PKG_PRIVATE_XCHG_TIMEER] =
		(unsigned int)UNF_GET_ELS_SFS_XCHG_TIMER(v_lport);
	v_pkg->private[PKG_PRIVATE_XCHG_ALLOC_TIME] =
		v_xchg->private[PKG_PRIVATE_XCHG_ALLOC_TIME];

	/* Send ELS command/response */
	ret = v_lport->low_level_func.service_op.pfn_unf_els_send(
		v_lport->fc_port, v_pkg);
	if (unlikely(ret != RETURN_OK)) {
		/* Cancel timer if send failed */
		v_lport->xchg_mgr_temp.pfn_unf_xchg_cancel_timer(
							(void *)v_xchg);
	}

	return ret;
}

static unsigned int unf_gs_cmnd_send(struct unf_lport_s *v_lport,
				     struct unf_frame_pkg_s *v_pkg,
				     struct unf_xchg_s *v_xchg)
{
	unsigned int ret = UNF_RETURN_ERROR;

	UNF_CHECK_VALID(0x3305, UNF_TRUE, v_lport, return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(0x3306, UNF_TRUE, v_pkg, return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(0x3307, UNF_TRUE, v_xchg, return UNF_RETURN_ERROR);

	if (unlikely(!v_lport->low_level_func.service_op.pfn_unf_gs_send)) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_LOGIN_ATT, UNF_ERR,
			  "[err]Port(0x%x) GS send function is NULL",
			  v_lport->port_id);

		return ret;
	}

	/* Add GS command timeout timer */
	v_lport->xchg_mgr_temp.pfn_unf_xchg_add_timer(
			(void *)v_xchg,
			(unsigned long)UNF_GET_GS_SFS_XCHG_TIMER(v_lport),
			UNF_TIMER_TYPE_SFS);
	v_pkg->private[PKG_PRIVATE_XCHG_TIMEER] = (unsigned int)
			UNF_GET_GS_SFS_XCHG_TIMER(v_lport);
	v_pkg->private[PKG_PRIVATE_XCHG_ALLOC_TIME] =
			v_xchg->private[PKG_PRIVATE_XCHG_ALLOC_TIME];

	/* Send GS command */
	ret = v_lport->low_level_func.service_op.pfn_unf_gs_send(
			v_lport->fc_port, v_pkg);
	if (unlikely(ret != RETURN_OK))
		/* Cancel timer if send failed */
		v_lport->xchg_mgr_temp.pfn_unf_xchg_cancel_timer(
							(void *)v_xchg);

	return ret;
}

static unsigned int unf_bls_cmnd_send(struct unf_lport_s *v_lport,
				      struct unf_frame_pkg_s *v_pkg,
				      struct unf_xchg_s *v_xchg)
{
	UNF_CHECK_VALID(0x3308, UNF_TRUE, v_lport, return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(0x3309, UNF_TRUE, v_pkg, return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(0x3310, UNF_TRUE, v_xchg, return UNF_RETURN_ERROR);

	v_pkg->private[PKG_PRIVATE_XCHG_TIMEER] =
		(unsigned int)UNF_GET_BLS_SFS_XCHG_TIMER(v_lport);
	v_pkg->private[PKG_PRIVATE_XCHG_ALLOC_TIME] =
		v_xchg->private[PKG_PRIVATE_XCHG_ALLOC_TIME];

	return v_lport->low_level_func.service_op.pfn_unf_bls_send(
						v_lport->fc_port, v_pkg);
}

static void unf_fill_package(struct unf_frame_pkg_s *v_pkg,
			     struct unf_xchg_s *v_xchg,
			     struct unf_rport_s *v_rport)
{
	/* v_rport maybe NULL */
	UNF_CHECK_VALID(0x3311, UNF_TRUE, v_pkg, return);
	UNF_CHECK_VALID(0x3312, UNF_TRUE, v_xchg, return);

	v_pkg->cmnd = v_xchg->cmnd_code;
	v_pkg->fcp_cmnd = &v_xchg->fcp_cmnd;
	v_pkg->frame_head.csctl_sid = v_xchg->sid;
	v_pkg->frame_head.rctl_did = v_xchg->did;
	v_pkg->frame_head.oxid_rxid = ((unsigned int)v_xchg->ox_id << 16 |
					 v_xchg->rx_id);
	v_pkg->xchg_contex = v_xchg;

	UNF_CHECK_VALID(0x3313, UNF_TRUE, v_xchg->lport, return);
	v_pkg->private[PKG_PRIVATE_XCHG_VP_INDEX] =
		v_xchg->lport->vp_index;

	if (!v_rport) {
		v_pkg->private[PKG_PRIVATE_XCHG_RPORT_INDEX] =
		UNF_RPORT_INVALID_INDEX;
		v_pkg->private[PKG_PRIVATE_RPORT_RX_SIZE] = INVALID_VALUE32;
	} else {
		v_pkg->private[PKG_PRIVATE_XCHG_RPORT_INDEX] =
			v_rport->rport_index;
		v_pkg->private[PKG_PRIVATE_RPORT_RX_SIZE] =
			v_rport->max_frame_size;
	}

	v_pkg->private[PKG_PRIVATE_XCHG_HOT_POOL_INDEX] = v_xchg->hot_pool_tag;
	v_pkg->private[PKG_PRIVATE_LOWLEVEL_XCHG_ADD] =
		v_xchg->private[PKG_PRIVATE_LOWLEVEL_XCHG_ADD];
	v_pkg->unf_cmnd_pload_bl.buffer_ptr =
		(unsigned char *)
		v_xchg->fcp_sfs_union.sfs_entry.fc_sfs_entry_ptr;
	v_pkg->unf_cmnd_pload_bl.buf_dma_addr =
		v_xchg->fcp_sfs_union.sfs_entry.sfs_buff_phy_addr;

	/* Low level need to know payload length if send ECHO response */
	v_pkg->unf_cmnd_pload_bl.length =
		v_xchg->fcp_sfs_union.sfs_entry.cur_offset;
}

static struct unf_xchg_s *unf_get_sfs_free_xchg_and_init(
					struct unf_lport_s *v_lport,
					unsigned int v_did,
					struct unf_rport_s *v_rport,
					union unf_sfs_u **v_fc_entry)
{
	struct unf_xchg_s *xchg = NULL;
	union unf_sfs_u *fc_entry = NULL;

	xchg = unf_cm_get_free_xchg(v_lport, UNF_XCHG_TYPE_SFS);
	if (!xchg)
		return NULL;

	xchg->did = v_did;
	xchg->sid = v_lport->nport_id;
	xchg->oid = xchg->sid;
	xchg->lport = v_lport;
	xchg->rport = v_rport;
	xchg->disc_rport = NULL;

	if (v_lport->low_level_func.xchg_mgr_type ==
	    UNF_LOW_LEVEL_MGR_TYPE_PASSTIVE)
		xchg->ox_id = xchg->hot_pool_tag;

	xchg->pfn_callback = NULL;
	xchg->pfn_ob_callback = NULL;

	fc_entry = xchg->fcp_sfs_union.sfs_entry.fc_sfs_entry_ptr;
	if (!fc_entry) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT, UNF_WARN,
			  "[warn]Port(0x%x) entry can't be NULL with tag(0x%x)",
			  v_lport->port_id, xchg->hot_pool_tag);

		unf_cm_free_xchg(v_lport, xchg);
		return NULL;
	}

	*v_fc_entry = fc_entry;

	return xchg;
}

static void unf_scr_callback(void *v_lport,
			     void *v_rport,
			     void *v_xchg)
{
	/* Callback function for SCR response: Send GID_PT with INI mode */
	struct unf_lport_s *lport = (struct unf_lport_s *)v_lport;
	struct unf_disc_s *disc = &lport->disc;
	struct unf_xchg_s *xchg = (struct unf_xchg_s *)v_xchg;
	struct unf_els_acc_s *els_acc = NULL;
	unsigned int ret = UNF_RETURN_ERROR;
	unsigned long lport_flag = 0;
	unsigned long disc_flag = 0;
	unsigned int cmnd = 0;

	UNF_CHECK_VALID(0x3694, UNF_TRUE, v_lport, return);
	UNF_CHECK_VALID(0x3695, UNF_TRUE, v_xchg, return);
	UNF_REFERNCE_VAR(v_rport);
	UNF_REFERNCE_VAR(ret);

	if (!xchg->fcp_sfs_union.sfs_entry.fc_sfs_entry_ptr)
		return;

	els_acc = &xchg->fcp_sfs_union.sfs_entry.fc_sfs_entry_ptr->els_acc;
	if (xchg->byte_orders & UNF_BIT_2)
		cmnd = be32_to_cpu(els_acc->cmnd);
	else
		cmnd = (els_acc->cmnd);

	if ((cmnd & UNF_ELS_CMND_HIGH_MASK) == UNF_ELS_CMND_ACC) {
		/* About ELS_CMND ACC */
		spin_lock_irqsave(&lport->lport_state_lock, lport_flag);

		/* Check L_Port state: SCR_WAIT */
		if (lport->en_states != UNF_LPORT_ST_SCR_WAIT) {
			spin_unlock_irqrestore(&lport->lport_state_lock,
					       lport_flag);

			UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT,
				  UNF_WARN,
				  "[warn]Port(0x%x_0x%x) receive SCR ACC with error state(0x%x)",
				  lport->port_id, lport->nport_id,
				  lport->en_states);
			return;
		}

		/* Update L_Port state machine: Ready */
		/* LPort: SCR_WAIT --> READY */
		unf_lport_stat_ma(lport, UNF_EVENT_LPORT_REMOTE_ACC);
		if (lport->en_states == UNF_LPORT_ST_READY) {
			UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT,
				  UNF_MAJOR,
				  "[info]LOGIN: Port(0x%x_0x%x) enter READY state when received SCR response",
				  lport->port_id, lport->nport_id);
		}

		/* Start to Discovery with INI mode: GID_PT */
		if ((lport->options & UNF_PORT_MODE_INI) ==
		    UNF_PORT_MODE_INI) {
			spin_unlock_irqrestore(&lport->lport_state_lock,
					       lport_flag);

			if (lport->disc.unf_disc_temp.pfn_unf_disc_start) {
				spin_lock_irqsave(&disc->rport_busy_pool_lock,
						  disc_flag);
				lport->disc.disc_option = UNF_INIT_DISC;
				disc->last_disc_jiff = jiffies;
				spin_unlock_irqrestore(
					&disc->rport_busy_pool_lock, disc_flag);

				ret = lport->disc.unf_disc_temp.pfn_unf_disc_start(lport);

				UNF_TRACE(UNF_EVTLOG_DRIVER_INFO,
					  UNF_LOG_LOGIN_ATT, UNF_INFO,
					  "[info]LOGIN: Port(0x%x) DISC %s with INI mode",
					  lport->port_id,
					  (ret != RETURN_OK) ? "failed" :
					  "succeed");
			}

			UNF_REFERNCE_VAR(ret);
			return;
		}
		/* TGT mode: Do not care */
		spin_unlock_irqrestore(&lport->lport_state_lock, lport_flag);

		/* NOTE: set state with UNF_DISC_ST_END used for RSCN process */
		spin_lock_irqsave(&disc->rport_busy_pool_lock, disc_flag);
		lport->disc.en_states = UNF_DISC_ST_END;
		spin_unlock_irqrestore(&disc->rport_busy_pool_lock, disc_flag);

		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT, UNF_INFO,
			  "[info]Port(0x%x) is TGT mode, no need to discovery",
			  lport->port_id);
		return;
	}
	/* About ELS_CMND response: RJT */
	unf_lport_error_recovery(lport);

	UNF_REFERNCE_VAR(ret);
}

static void unf_scr_ob_callback(struct unf_xchg_s *v_xchg)
{
	/* Callback fucnion for exception: Do L_Port error recovery */
	struct unf_lport_s *lport = NULL;
	unsigned long flag = 0;

	UNF_CHECK_VALID(0x3692, UNF_TRUE, v_xchg, return);

	spin_lock_irqsave(&v_xchg->xchg_state_lock, flag);
	lport = v_xchg->lport;
	spin_unlock_irqrestore(&v_xchg->xchg_state_lock, flag);

	UNF_CHECK_VALID(0x3693, UNF_TRUE, lport, return);

	UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT, UNF_WARN,
		  "[warn]Port(0x%x) send SCR failed and do port recovery",
		  lport->port_id);

	unf_lport_error_recovery(lport);
}

unsigned int unf_send_scr(struct unf_lport_s *v_lport,
			  struct unf_rport_s *v_rport)
{
	/* after RCVD RFF_ID ACC */
	struct unf_scr_s *scr = NULL;
	union unf_sfs_u *fc_entry = NULL;
	struct unf_xchg_s *xchg = NULL;
	unsigned int ret = UNF_RETURN_ERROR;
	struct unf_frame_pkg_s pkg = { 0 };
	unsigned short ox_id = 0;

	UNF_REFERNCE_VAR(ox_id);
	UNF_CHECK_VALID(0x3314, UNF_TRUE, v_lport, return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(0x3315, UNF_TRUE, v_rport, return UNF_RETURN_ERROR);

	/* Get free exchange for SCR */
	xchg = unf_get_sfs_free_xchg_and_init(v_lport, v_rport->nport_id,
					      NULL, &fc_entry);
	if (!xchg) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_LOGIN_ATT, UNF_ERR,
			  "[err]Port(0x%x) exchange can't be NULL for SCR",
			  v_lport->port_id);

		return ret;
	}

	xchg->cmnd_code = ELS_SCR;  /* SCR */
	ox_id = xchg->ox_id;
	/* Set callback function */
	xchg->pfn_callback = unf_scr_callback;
	xchg->pfn_ob_callback = unf_scr_ob_callback;

	/* Fill command/response package */
	unf_fill_package(&pkg, xchg, v_rport);

	scr = &fc_entry->scr;
	memset(scr, 0, sizeof(struct unf_scr_s));
	scr->payload[0] = (UNF_GS_CMND_SCR);	 /* SCR is 0x62 */
	scr->payload[1] = (UNF_FABRIC_FULL_REG); /* Full registration */

	/* Send SCR command */
	ret = unf_els_cmnd_send(v_lport, &pkg, xchg);
	if (ret != RETURN_OK)
		unf_cm_free_xchg((void *)v_lport, (void *)xchg);

	UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT, UNF_MAJOR,
		  "[info]LOGIN: SCR send %s. Port(0x%x_0x%x)--->rport(0x%x) with OX_ID(0x%x)",
		  (ret != RETURN_OK) ? "failed" : "succeed",
		  v_lport->port_id, v_lport->nport_id,
		  v_rport->nport_id, ox_id);

	UNF_REFERNCE_VAR(ox_id);
	return ret;
}

static void unf_fill_rec_pld(struct unf_rec_pld_s *v_rec_pld,
			     unsigned int v_sid,
			     unsigned short v_oxid)
{
	UNF_CHECK_VALID(0x3339, UNF_TRUE, v_rec_pld, return);

	v_rec_pld->rec_cmnd = UNF_ELS_CMND_REC;
	v_rec_pld->xchg_org_sid = v_sid;
	v_rec_pld->ox_id = v_oxid;
	v_rec_pld->rx_id = INVALID_VALUE16;
}

unsigned int unf_send_rec(struct unf_lport_s *v_lport,
			  struct unf_rport_s *v_rport,
			  struct unf_xchg_s *v_io_xchg)
{
	struct unf_rec_pld_s *rec_pld = NULL;
	union unf_sfs_u *fc_entry = NULL;
	struct unf_xchg_s *xchg = NULL;
	unsigned int ret = UNF_RETURN_ERROR;
	unsigned short ox_id = 0;
	struct unf_frame_pkg_s pkg;

	UNF_REFERNCE_VAR(ox_id);
	UNF_CHECK_VALID(0x3324, UNF_TRUE, v_lport, return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(0x3325, UNF_TRUE, v_rport, return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(0x3325, UNF_TRUE, v_io_xchg, return UNF_RETURN_ERROR);

	memset(&pkg, 0, sizeof(struct unf_frame_pkg_s));

	/* Get & Set new free exchange */
	xchg = unf_get_sfs_free_xchg_and_init(v_lport, v_rport->nport_id,
					      v_rport, &fc_entry);
	if (!xchg) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_LOGIN_ATT, UNF_ERR,
			  "[err]Port(0x%x) exchange can't be NULL for PLOGI",
			  v_lport->port_id);
		return ret;
	}

	xchg->cmnd_code = ELS_REC;
	ox_id = xchg->ox_id;
	unf_fill_package(&pkg, xchg, v_rport);

	rec_pld = &fc_entry->rec.rec_pld;
	memset(rec_pld, 0, sizeof(struct unf_rec_pld_s));

	unf_fill_rec_pld(rec_pld, v_lport->nport_id, v_io_xchg->ox_id);

	/* Start to Send REC command */
	ret = unf_els_cmnd_send(v_lport, &pkg, xchg);
	if (ret != RETURN_OK)
		unf_cm_free_xchg((void *)v_lport, (void *)xchg);

	UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT, UNF_KEVENT,
		  "[info]LOGIN: Send REC %s. Port(0x%x_0x%x_0x%llx)--->RPort(0x%x_0x%llx) with OX_ID(0x%x)",
		  (ret != RETURN_OK) ? "failed" : "succeed",
		  v_lport->port_id, v_lport->nport_id, v_lport->port_name,
		  v_rport->nport_id, v_rport->port_name, ox_id);

	UNF_REFERNCE_VAR(ox_id);
	return ret;
}

static void unf_fill_flogi_pld(struct unf_flogi_payload_s *v_flogi_pld,
			       struct unf_lport_s *v_lport)
{
	struct unf_fabric_parms_s *fabric_parms = NULL;

	UNF_CHECK_VALID(0x3316, UNF_TRUE, v_flogi_pld, return);
	UNF_CHECK_VALID(0x3317, UNF_TRUE, v_lport, return);

	fabric_parms = &v_flogi_pld->fabric_parms;
	if ((v_lport->en_act_topo == UNF_ACT_TOP_P2P_FABRIC) ||
	    (v_lport->en_act_topo == UNF_ACT_TOP_P2P_DIRECT) ||
	    (v_lport->en_act_topo == UNF_TOP_P2P_MASK)) {
		/* Fabric or P2P  topology */
		fabric_parms->co_parms.bb_credit =
			unf_low_level_bb_credit(v_lport);
		fabric_parms->co_parms.lowest_version =
			UNF_PLOGI_VERSION_LOWER;
		fabric_parms->co_parms.highest_version =
			UNF_PLOGI_VERSION_UPPER;
		fabric_parms->co_parms.bb_receive_data_field_size =
			(v_lport->max_frame_size);
		fabric_parms->co_parms.bb_scn = unf_low_level_bbscn(v_lport);
	} else {
		/* Loop topology here */
		fabric_parms->co_parms.clean_address =
			UNF_CLEAN_ADDRESS_DEFAULT;
		fabric_parms->co_parms.bb_credit = UNF_BBCREDIT_LPORT;
		fabric_parms->co_parms.lowest_version =
			UNF_PLOGI_VERSION_LOWER;
		fabric_parms->co_parms.highest_version =
			UNF_PLOGI_VERSION_UPPER;
		fabric_parms->co_parms.alternate_bb_credit_mgmt =
			UNF_BBCREDIT_MANAGE_LPORT;  /* :1 */
		fabric_parms->co_parms.bb_receive_data_field_size =
			(v_lport->max_frame_size);
	}

	if (v_lport->low_level_func.support_max_npiv_num != 0)
		fabric_parms->co_parms.clean_address = 1; /* support NPIV */

	fabric_parms->cl_parms[2].valid = UNF_CLASS_VALID;
	fabric_parms->cl_parms[2].priority = UNF_PRIORITY_DISABLE;

	fabric_parms->cl_parms[2].sequential_delivery =
		UNF_SEQUEN_DELIVERY_REQ;
	fabric_parms->cl_parms[2].received_data_field_size =
		(v_lport->max_frame_size);

	fabric_parms->high_node_name =
		UNF_GET_NAME_HIGH_WORD(v_lport->node_name);
	fabric_parms->low_node_name =
		UNF_GET_NAME_LOW_WORD(v_lport->node_name);
	fabric_parms->high_port_name =
		UNF_GET_NAME_HIGH_WORD(v_lport->port_name);
	fabric_parms->low_port_name =
		UNF_GET_NAME_LOW_WORD(v_lport->port_name);
}

static void unf_flogi_ob_callback(struct unf_xchg_s *v_xchg)
{
	/* Send FLOGI failed & Do L_Port recovery */
	struct unf_lport_s *lport = NULL;
	unsigned long flag = 0;

	UNF_CHECK_VALID(0x3644, UNF_TRUE, v_xchg, return);

	/* Get L_port from exchange context */
	spin_lock_irqsave(&v_xchg->xchg_state_lock, flag);
	lport = v_xchg->lport;
	spin_unlock_irqrestore(&v_xchg->xchg_state_lock, flag);
	UNF_CHECK_VALID(0x3645, UNF_TRUE, lport, return);

	UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT, UNF_WARN,
		  "[warn]LOGIN: Port(0x%x) send FLOGI failed",
		  lport->port_id);

	/* Check L_Port state */
	spin_lock_irqsave(&lport->lport_state_lock, flag);
	if (lport->en_states != UNF_LPORT_ST_FLOGI_WAIT) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT, UNF_WARN,
			  "[warn]LOGIN: Port(0x%x_0x%x) send FLOGI failed with state(0x%x)",
			  lport->port_id, lport->nport_id, lport->en_states);

		spin_unlock_irqrestore(&lport->lport_state_lock, flag);
		return;
	}
	spin_unlock_irqrestore(&lport->lport_state_lock, flag);

	/* Do L_Port error recovery */
	unf_lport_error_recovery(lport);
}

unsigned int unf_send_flogi(struct unf_lport_s *v_lport,
			    struct unf_rport_s *v_rport)
{
	struct unf_xchg_s *xchg = NULL;
	struct unf_flogi_payload_s *flogi_pld = NULL;
	union unf_sfs_u *fc_entry = NULL;
	unsigned int ret = UNF_RETURN_ERROR;
	struct unf_frame_pkg_s pkg = { 0 };
	unsigned short ox_id = 0;

	UNF_REFERNCE_VAR(ox_id);
	UNF_CHECK_VALID(0x3318, UNF_TRUE, v_lport, return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(0x3319, UNF_TRUE, v_rport, return UNF_RETURN_ERROR);

	/* Get & Set New free Exchange Context */
	xchg = unf_get_sfs_free_xchg_and_init(v_lport, v_rport->nport_id,
					      v_rport, &fc_entry);
	if (!xchg) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_LOGIN_ATT, UNF_ERR,
			  "[err]Port(0x%x) exchange can't be NULL for FLOGI",
			  v_lport->port_id);

		return ret;
	}

	xchg->cmnd_code = ELS_FLOGI;  /* FLOGI */

	ox_id = xchg->ox_id;

	/* Set callback function */
	/* for rcvd flogi acc/rjt processer */
	xchg->pfn_callback = unf_flogi_callback;
	/* for send flogi failed processer */
	xchg->pfn_ob_callback = unf_flogi_ob_callback;

	/* Fill package: Exchange --to-->> Package */
	unf_fill_package(&pkg, xchg, v_rport);

	/* Fill Flogi Payload */
	flogi_pld = &fc_entry->flogi.flogi_payload;
	memset(flogi_pld, 0, sizeof(struct unf_flogi_payload_s));
	unf_fill_flogi_pld(flogi_pld, v_lport);
	flogi_pld->cmnd = (UNF_ELS_CMND_FLOGI);

	UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT, UNF_MAJOR,
		  "[info]LOGIN: Begin to send FLOGI. Port(0x%x)--->rport(0x%x) with OX_ID(0x%x)",
		  v_lport->port_id, v_rport->nport_id, ox_id);

	UNF_PRINT_SFS_LIMIT(UNF_INFO, v_lport->port_id, flogi_pld,
			    sizeof(struct unf_flogi_payload_s));

	/* Start to send FLOGI command */
	ret = unf_els_cmnd_send(v_lport, &pkg, xchg);
	if (ret != RETURN_OK) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT, UNF_ERR,
			  "[warn]LOGIN: Send FLOGI failed. Port(0x%x)--->rport(0x%x)",
			  v_lport->port_id, v_rport->nport_id);

		unf_cm_free_xchg((void *)v_lport, (void *)xchg);
	}

	UNF_REFERNCE_VAR(ox_id);
	return ret;
}

static void unf_fdisc_ob_callback(struct unf_xchg_s *v_xchg)
{
	/* Do recovery */
	struct unf_lport_s *lport = NULL;
	unsigned long flag = 0;

	UNF_CHECK_VALID(0x3638, UNF_TRUE, v_xchg, return);

	spin_lock_irqsave(&v_xchg->xchg_state_lock, flag);
	lport = v_xchg->lport;
	spin_unlock_irqrestore(&v_xchg->xchg_state_lock, flag);

	UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT, UNF_WARN,
		  "[warn]LOGIN: FDISC send failed");

	UNF_CHECK_VALID(0x3639, UNF_TRUE, NULL != lport, return);

	/* Do L_Port error recovery */
	unf_lport_error_recovery(lport);
}

unsigned int unf_send_fdisc(struct unf_lport_s *v_lport,
			    struct unf_rport_s *v_rport)
{
	struct unf_xchg_s *exch = NULL;
	struct unf_flogi_payload_s *fdisc_pld = NULL;
	union unf_sfs_u *fc_entry = NULL;
	unsigned int ret = UNF_RETURN_ERROR;
	struct unf_frame_pkg_s pkg = { 0 };
	unsigned short ox_id = 0;

	UNF_REFERNCE_VAR(ox_id);
	UNF_CHECK_VALID(0x3320, UNF_TRUE, v_lport, return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(0x3321, UNF_TRUE, v_rport, return UNF_RETURN_ERROR);

	exch = unf_get_sfs_free_xchg_and_init(v_lport, v_rport->nport_id,
					      v_rport, &fc_entry);
	if (!exch) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_LOGIN_ATT, UNF_ERR,
			  "[err]Port(0x%x) exchange can't be NULL for FDISC",
			  v_lport->port_id);

		return ret;
	}

	exch->cmnd_code = ELS_FDISC;  /* FDISC */

	ox_id = exch->ox_id;

	/* Set callback function */
	exch->pfn_callback = unf_fdisc_callback;
	exch->pfn_ob_callback = unf_fdisc_ob_callback;

	unf_fill_package(&pkg, exch, v_rport);

	/* Fill FDISC entry(payload) */
	fdisc_pld = &fc_entry->fdisc.fdisc_payload;
	memset(fdisc_pld, 0, sizeof(struct unf_flogi_payload_s));
	unf_fill_flogi_pld(fdisc_pld, v_lport);
	fdisc_pld->cmnd = UNF_ELS_CMND_FDISC;  /* update cmnd type */

	/* Start to send FDISC */
	ret = unf_els_cmnd_send(v_lport, &pkg, exch);
	if (ret != RETURN_OK)
		unf_cm_free_xchg((void *)v_lport, (void *)exch);

	UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT, UNF_MAJOR,
		  "[info]LOGIN: FDISC send %s. Port(0x%x)--->rport(0x%x) with OX_ID(0x%x)",
		  (ret != RETURN_OK) ? "failed" : "succeed",
		  v_lport->port_id, v_rport->nport_id, ox_id);

	UNF_REFERNCE_VAR(ox_id);
	return ret;
}

static void unf_fill_plogi_pld(struct unf_plogi_payload_s *v_plogi_pld,
			       struct unf_lport_s *v_lport)
{
	struct unf_lgn_parms_s *login_parms = NULL;
	struct unf_lport_s *lport = NULL;

	UNF_CHECK_VALID(0x3322, UNF_TRUE, v_plogi_pld, return);
	UNF_CHECK_VALID(0x3323, UNF_TRUE, v_lport, return);

	lport = v_lport->root_lport;
	v_plogi_pld->cmnd = (UNF_ELS_CMND_PLOGI);
	login_parms = &v_plogi_pld->parms;

	if ((v_lport->en_act_topo == UNF_ACT_TOP_P2P_FABRIC) ||
	    (v_lport->en_act_topo == UNF_ACT_TOP_P2P_DIRECT)) {
		/* P2P or Fabric mode */
		login_parms->co_parms.bb_credit =
			(unf_low_level_bb_credit(v_lport));
		login_parms->co_parms.alternate_bb_credit_mgmt =
			UNF_BBCREDIT_MANAGE_NFPORT;  /* 0 */
		login_parms->co_parms.bb_scn =
			(v_lport->en_act_topo == UNF_ACT_TOP_P2P_FABRIC) ?
			0 : unf_low_level_bbscn(v_lport);
	} else {
		/* Public loop & Private loop mode */
		login_parms->co_parms.bb_credit = UNF_BBCREDIT_LPORT; /* 0 */
		login_parms->co_parms.alternate_bb_credit_mgmt =
			 UNF_BBCREDIT_MANAGE_LPORT;  /* 1 */
	}

	login_parms->co_parms.lowest_version = UNF_PLOGI_VERSION_LOWER;
	login_parms->co_parms.highest_version = UNF_PLOGI_VERSION_UPPER;
	login_parms->co_parms.continuously_increasing =
		UNF_CONTIN_INCREASE_SUPPORT;
	login_parms->co_parms.bb_receive_data_field_size =
		(v_lport->max_frame_size);
	login_parms->co_parms.nport_total_concurrent_sequences =
		(UNF_PLOGI_CONCURRENT_SEQ);
	login_parms->co_parms.relative_offset = (UNF_PLOGI_RO_CATEGORY);
	login_parms->co_parms.e_d_tov = UNF_DEFAULT_EDTOV;
	if (lport->b_priority == UNF_PRIORITY_ENABLE)
		login_parms->cl_parms[2].priority = UNF_PRIORITY_ENABLE;
	else
		login_parms->cl_parms[2].priority = UNF_PRIORITY_DISABLE;

	login_parms->cl_parms[2].valid = UNF_CLASS_VALID;  /* for class_3 */
	login_parms->cl_parms[2].received_data_field_size =
		(v_lport->max_frame_size);
	login_parms->cl_parms[2].concurrent_sequences =
		(UNF_PLOGI_CONCURRENT_SEQ);
	login_parms->cl_parms[2].open_sequences_per_exchange =
		(UNF_PLOGI_SEQ_PER_XCHG);

	login_parms->high_node_name =
		UNF_GET_NAME_HIGH_WORD(v_lport->node_name);
	login_parms->low_node_name =
		UNF_GET_NAME_LOW_WORD(v_lport->node_name);
	login_parms->high_port_name =
		UNF_GET_NAME_HIGH_WORD(v_lport->port_name);
	login_parms->low_port_name =
		UNF_GET_NAME_LOW_WORD(v_lport->port_name);

	UNF_PRINT_SFS_LIMIT(UNF_INFO, v_lport->port_id, v_plogi_pld,
			    sizeof(struct unf_plogi_payload_s));
}

static void unf_plogi_ob_callback(struct unf_xchg_s *v_xchg)
{
	/* Do L_Port or R_Port recovery */
	struct unf_lport_s *lport = NULL;
	struct unf_rport_s *rport = NULL;
	unsigned long flag = 0;

	UNF_CHECK_VALID(0x3656, UNF_TRUE, v_xchg, return);

	spin_lock_irqsave(&v_xchg->xchg_state_lock, flag);
	lport = v_xchg->lport;
	rport = v_xchg->rport;
	spin_unlock_irqrestore(&v_xchg->xchg_state_lock, flag);

	UNF_CHECK_VALID(0x3657, UNF_TRUE, lport, return);
	UNF_CHECK_VALID(0x3734, UNF_TRUE, rport, return);

	UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT, UNF_WARN,
		  "[warn]LOGIN: Port(0x%x_0x%x) send PLOGI(0x%x_0x%x) to RPort(%p:0x%x_0x%x) failed",
		  lport->port_id, lport->nport_id, v_xchg->ox_id,
		  v_xchg->rx_id, rport, rport->rport_index, rport->nport_id);

	/* Start to recovery */
	if (rport->nport_id > UNF_FC_FID_DOM_MGR) {
		/* with Name server: R_Port is fabric --->>>
		 * L_Port error recovery
		 */
		unf_lport_error_recovery(lport);
	} else {
		/* R_Port is not fabric --->>> R_Port error recovery */
		unf_rport_error_recovery(rport);
	}
}

unsigned int unf_send_plogi(struct unf_lport_s *v_lport,
			    struct unf_rport_s *v_rport)
{
	struct unf_plogi_payload_s *plogi_pld = NULL;
	union unf_sfs_u *fc_entry = NULL;
	struct unf_xchg_s *xchg = NULL;
	unsigned int ret = UNF_RETURN_ERROR;
	unsigned short ox_id = 0;
	struct unf_frame_pkg_s pkg;

	UNF_REFERNCE_VAR(ox_id);
	UNF_CHECK_VALID(0x3324, UNF_TRUE, v_lport, return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(0x3325, UNF_TRUE, v_rport, return UNF_RETURN_ERROR);

	memset(&pkg, 0, sizeof(struct unf_frame_pkg_s));

	/* Get & Set new free exchange */
	xchg = unf_get_sfs_free_xchg_and_init(v_lport, v_rport->nport_id,
					      v_rport, &fc_entry);
	if (!xchg) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_LOGIN_ATT, UNF_ERR,
			  "[err]Port(0x%x) exchange can't be NULL for PLOGI",
			  v_lport->port_id);

		return ret;
	}

	xchg->cmnd_code = ELS_PLOGI;  /* PLOGI */

	ox_id = xchg->ox_id;

	/* Set callback function */
	/* for rcvd plogi acc/rjt processer */
	xchg->pfn_callback = unf_plogi_callback;
	/* for send plogi failed processer */
	xchg->pfn_ob_callback = unf_plogi_ob_callback;

	unf_fill_package(&pkg, xchg, v_rport);

	/* Fill PLOGI payload */
	plogi_pld = &fc_entry->plogi.payload;
	memset(plogi_pld, 0, sizeof(struct unf_plogi_payload_s));
	unf_fill_plogi_pld(plogi_pld, v_lport);

	/* Start to Send PLOGI command */
	ret = unf_els_cmnd_send(v_lport, &pkg, xchg);
	if (ret != RETURN_OK)
		unf_cm_free_xchg((void *)v_lport, (void *)xchg);

	UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT, UNF_MAJOR,
		  "[info]LOGIN: Send PLOGI %s. Port(0x%x_0x%x_0x%llx)--->rport(0x%x_0x%llx) with OX_ID(0x%x)",
		  (ret != RETURN_OK) ? "failed" : "succeed",
		  v_lport->port_id, v_lport->nport_id, v_lport->port_name,
		  v_rport->nport_id, v_rport->port_name, ox_id);

	UNF_REFERNCE_VAR(ox_id);
	return ret;
}

static void unf_fill_logo_pld(struct unf_logo_payload_s *v_logo_pld,
			      struct unf_lport_s *v_lport)
{
	UNF_CHECK_VALID(0x3326, UNF_TRUE, v_logo_pld, return);
	UNF_CHECK_VALID(0x3327, UNF_TRUE, v_lport, return);

	v_logo_pld->cmnd = UNF_ELS_CMND_LOGO;
	v_logo_pld->nport_id = (v_lport->nport_id);
	v_logo_pld->high_port_name =
		UNF_GET_NAME_HIGH_WORD(v_lport->port_name);
	v_logo_pld->low_port_name =
		UNF_GET_NAME_LOW_WORD(v_lport->port_name);

	UNF_PRINT_SFS_LIMIT(UNF_INFO, v_lport->port_id,
			    v_logo_pld,
			    sizeof(struct unf_logo_payload_s));
}

static void unf_logo_ob_callback(struct unf_xchg_s *v_xchg)
{
	struct unf_lport_s *lport;
	struct unf_rport_s *rport;
	struct unf_rport_s *old_rport;
	struct unf_xchg_s *xchg;
	unsigned int nport_id = 0;
	unsigned int logo_retry = 0;

	UNF_CHECK_VALID(0x3675, UNF_TRUE, NULL, return);
	xchg = v_xchg;
	old_rport = xchg->rport;
	logo_retry = old_rport->logo_retries;

	if (old_rport->nport_id != INVALID_VALUE32)
		unf_rport_enter_closing(old_rport);

	lport = xchg->lport;
	if (unf_is_lport_valid(lport) != RETURN_OK)
		return;

	/* Get R_Port by exchange info: Init state */
	nport_id = xchg->did;
	rport = unf_get_rport_by_nport_id(lport, nport_id);
	rport = unf_get_safe_rport(lport, rport, UNF_RPORT_REUSE_INIT,
				   nport_id);
	if (!rport) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT,
			  UNF_WARN,
			  "[warn]Port(0x%x) cannot allocate RPort",
			  lport->port_id);
		return;
	}

	rport->logo_retries = logo_retry;

	UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT, UNF_WARN,
		  "[info]LOGIN: Port(0x%x) received LOGO RSP timeout topo(0x%x) retries(%u)",
		  lport->port_id,  lport->en_act_topo, rport->logo_retries);

	/* RCVD LOGO/PRLO & SEND LOGO: the same process */
	if (rport->logo_retries < UNF_MAX_RETRY_COUNT) {
		/* <: retry (LOGIN or LOGO) if necessary */
		unf_process_rport_after_logo(lport, rport);
	} else {
		/* >=: Link down */
		unf_rport_immediate_linkdown(lport, rport);
	}
}

static void unf_logo_callback(void *v_lport, void *v_rport, void *v_xchg)
{
	/* RCVD LOGO ACC/RJT: retry(LOGIN/LOGO) or link down immediately */
	struct unf_lport_s *lport = (struct unf_lport_s *)v_lport;
	struct unf_rport_s *rport = NULL;
	struct unf_rport_s *old_rport = NULL;
	struct unf_xchg_s *xchg = NULL;
	struct unf_els_rjt_s *els_acc_rjt = NULL;
	unsigned int cmnd = 0;
	unsigned int nport_id = 0;
	unsigned int logo_retry = 0;

	UNF_CHECK_VALID(0x3675, UNF_TRUE, v_xchg, return);
	UNF_REFERNCE_VAR(v_rport);

	xchg = (struct unf_xchg_s *)v_xchg;
	old_rport = xchg->rport;

	logo_retry = old_rport->logo_retries;
	if (old_rport->nport_id != INVALID_VALUE32)
		unf_rport_enter_closing(old_rport);

	if (unf_is_lport_valid(v_lport) != RETURN_OK)
		return;

	if (!xchg->fcp_sfs_union.sfs_entry.fc_sfs_entry_ptr)
		return;

	/* Get R_Port by exchange info: Init state */
	els_acc_rjt =
		&xchg->fcp_sfs_union.sfs_entry.fc_sfs_entry_ptr->els_rjt;
	nport_id = xchg->did;
	rport = unf_get_rport_by_nport_id(lport, nport_id);
	rport = unf_get_safe_rport(lport, rport,
				   UNF_RPORT_REUSE_INIT, nport_id);
	if (!rport) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT, UNF_WARN,
			  "[warn]Port(0x%x) cannot allocate RPort",
			  lport->port_id);
		return;
	}

	rport->logo_retries = logo_retry;
	cmnd = be32_to_cpu(els_acc_rjt->cmnd);
	UNF_REFERNCE_VAR(cmnd);

	UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT, UNF_MAJOR,
		  "[info]LOGIN: Port(0x%x) received LOGO RSP(0x%x), topo(0x%x) Port options(0x%x) RPort options(0x%x) retries(%d)",
		  lport->port_id, (cmnd & UNF_ELS_CMND_HIGH_MASK),
		  lport->en_act_topo,
		  lport->options, rport->options, rport->logo_retries);

	/* RCVD LOGO/PRLO & SEND LOGO: the same process */
	if (rport->logo_retries < UNF_MAX_RETRY_COUNT)
		/* <: retry (LOGIN or LOGO) if necessary */
		unf_process_rport_after_logo(lport, rport);
	else
		/* >=: Link down */
		unf_rport_immediate_linkdown(lport, rport);
}

unsigned int unf_send_logo(struct unf_lport_s *v_lport,
			   struct unf_rport_s *v_rport)
{
	struct unf_logo_payload_s *logo_pld = NULL;
	union unf_sfs_u *fc_entry = NULL;
	struct unf_xchg_s *xchg = NULL;
	struct unf_frame_pkg_s pkg = { 0 };
	unsigned int ret = UNF_RETURN_ERROR;
	unsigned short ox_id = 0;

	UNF_REFERNCE_VAR(ox_id);
	UNF_CHECK_VALID(0x3328, UNF_TRUE, v_lport, return UNF_RETURN_ERROR);

	xchg = unf_get_sfs_free_xchg_and_init(v_lport, v_rport->nport_id,
					      v_rport, &fc_entry);
	if (!xchg) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_LOGIN_ATT, UNF_ERR,
			  "[err]Port(0x%x) exchange can't be NULL for LOGO",
			  v_lport->port_id);

		return ret;
	}

	xchg->cmnd_code = ELS_LOGO;  /* LOGO */

	ox_id = xchg->ox_id;

	/* Set callback function */
	/* retry or link down immediately */
	xchg->pfn_callback = unf_logo_callback;
	xchg->pfn_ob_callback = unf_logo_ob_callback;  /* do nothing */

	unf_fill_package(&pkg, xchg, v_rport);

	/* Fill LOGO entry(payload) */
	logo_pld = &fc_entry->logo.payload;
	memset(logo_pld, 0, sizeof(struct unf_logo_payload_s));
	unf_fill_logo_pld(logo_pld, v_lport);

	/* Start to send LOGO command */
	ret = unf_els_cmnd_send(v_lport, &pkg, xchg);
	if (ret != RETURN_OK)
		unf_cm_free_xchg((void *)v_lport, (void *)xchg);

	v_rport->logo_retries++;

	UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT, UNF_KEVENT,
		  "[info]LOGIN: LOGO send %s. Port(0x%x)--->rport(0x%x) OXID(0x%x) Retries(%d)",
		  (ret != RETURN_OK) ? "failed" : "succeed",
		  v_lport->port_id, v_rport->nport_id,
		  ox_id, v_rport->logo_retries);

	UNF_REFERNCE_VAR(ox_id);
	return ret;
}

unsigned int unf_send_logo_by_did(struct unf_lport_s *v_lport,
				  unsigned int v_did)
{
	/* Has non R_Port */
	struct unf_logo_payload_s *logo_pld = NULL;
	union unf_sfs_u *fc_entry = NULL;
	struct unf_xchg_s *xchg = NULL;
	struct unf_frame_pkg_s pkg = { 0 };
	unsigned int ret = UNF_RETURN_ERROR;
	unsigned short ox_id = 0;

	UNF_REFERNCE_VAR(ox_id);
	UNF_CHECK_VALID(0x3329, UNF_TRUE, v_lport, return UNF_RETURN_ERROR);

	xchg = unf_get_sfs_free_xchg_and_init(v_lport, v_did, NULL, &fc_entry);
	if (!xchg) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_LOGIN_ATT, UNF_ERR,
			  "[err]Port(0x%x) exchange can't be NULL for LOGO",
			  v_lport->port_id);

		return ret;
	}

	xchg->cmnd_code = ELS_LOGO;  /* LOGO */

	ox_id = xchg->ox_id;

	unf_fill_package(&pkg, xchg, NULL);

	/* Fill LOGO entry(payload) */
	logo_pld = &fc_entry->logo.payload;
	memset(logo_pld, 0, sizeof(struct unf_logo_payload_s));
	unf_fill_logo_pld(logo_pld, v_lport);

	/* Start to send LOGO now */
	ret = unf_els_cmnd_send(v_lport, &pkg, xchg);
	if (ret != RETURN_OK)
		unf_cm_free_xchg((void *)v_lport, (void *)xchg);

	UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT, UNF_MAJOR,
		  "[info]LOGIN: LOGO send %s. Port(0x%x)--->rport(0x%x) with OX_ID(0x%x)",
		  (ret != RETURN_OK) ? "failed" : "succeed",
		  v_lport->port_id, v_did, ox_id);

	UNF_REFERNCE_VAR(ox_id);
	return ret;
}

static void *unf_get_one_big_sfs_buf(struct unf_xchg_s *v_xchg)
{
	struct unf_big_sfs_s *big_sfs = NULL;
	struct list_head *list_head = NULL;
	struct unf_xchg_mgr_s *xchg_mgr = NULL;
	unsigned long flag = 0;

	UNF_CHECK_VALID(0x3330, UNF_TRUE, v_xchg, return NULL);
	xchg_mgr = v_xchg->xchg_mgr;
	UNF_CHECK_VALID(0x3331, UNF_TRUE, xchg_mgr, return NULL);

	spin_lock_irqsave(&xchg_mgr->st_big_sfs_pool.big_sfs_pool_lock, flag);
	if (!list_empty(&xchg_mgr->st_big_sfs_pool.list_free_pool)) {
		/* from free to busy */
		list_head = (&xchg_mgr->st_big_sfs_pool.list_free_pool)->next;
		list_del(list_head);
		xchg_mgr->st_big_sfs_pool.free_count--;
		list_add_tail(list_head,
			      &xchg_mgr->st_big_sfs_pool.list_busy_pool);
		big_sfs = list_entry(list_head, struct unf_big_sfs_s,
				     entry_big_sfs);
	} else {
		spin_unlock_irqrestore(
				&xchg_mgr->st_big_sfs_pool.big_sfs_pool_lock,
				flag);

		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT, UNF_WARN,
			  "[warn]Allocate big sfs buf failed, count(0x%x) exchange(0x%p) command(0x%x)",
			  xchg_mgr->st_big_sfs_pool.free_count,
			  v_xchg, v_xchg->cmnd_code);

		return NULL;
	}
	spin_unlock_irqrestore(&xchg_mgr->st_big_sfs_pool.big_sfs_pool_lock,
			       flag);

	v_xchg->big_sfs_buf = big_sfs;

	UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT, UNF_INFO,
		  "[info]Allocate one address(0x%p) of big sfs buffer, remaining count(0x%x) exchange(0x%p) command(0x%x)",
		  big_sfs->vaddr,
		  xchg_mgr->st_big_sfs_pool.free_count,
		  v_xchg,
		  v_xchg->cmnd_code);

	return big_sfs->vaddr;
}

static void unf_echo_callback(void *v_lport, void *v_rport, void *v_xchg)
{
	struct unf_lport_s *lport = (struct unf_lport_s *)v_lport;
	struct unf_rport_s *rport = (struct unf_rport_s *)v_rport;
	struct unf_xchg_s *xchg = NULL;
	struct unf_echo_payload_s *echo_rsp_pld = NULL;
	unsigned int cmnd = 0;
	unsigned int mag_ver_local = 0;
	unsigned int mag_ver_remote = 0;

	UNF_CHECK_VALID(0x3332, UNF_TRUE, v_lport, return);
	UNF_CHECK_VALID(0x3333, UNF_TRUE, v_rport, return);
	UNF_CHECK_VALID(0x3334, UNF_TRUE, v_xchg, return);
	UNF_REFERNCE_VAR(lport);
	UNF_REFERNCE_VAR(rport);

	xchg = (struct unf_xchg_s *)v_xchg;
	if (!xchg->fcp_sfs_union.sfs_entry.fc_sfs_entry_ptr)
		return;

	echo_rsp_pld = xchg->fcp_sfs_union.sfs_entry.fc_sfs_entry_ptr->echo_acc.echo_pld;
	UNF_CHECK_VALID(0x3335, UNF_TRUE, NULL != echo_rsp_pld, return);

	if (xchg->byte_orders & UNF_BIT_2) {
		unf_big_end_to_cpu((unsigned char *)echo_rsp_pld,
				   sizeof(struct unf_echo_payload_s));
		cmnd = echo_rsp_pld->cmnd;
	} else {
		cmnd = echo_rsp_pld->cmnd;
	}

	mag_ver_local = echo_rsp_pld->data[0];
	mag_ver_remote = echo_rsp_pld->data[1];

	/* Print info */
	if ((cmnd & UNF_ELS_CMND_HIGH_MASK) == UNF_ELS_CMND_ACC) {
		if ((mag_ver_local == ECHO_MG_VERSION_LOCAL) &&
		    (mag_ver_remote == ECHO_MG_VERSION_REMOTE)) {
			/* both side are 1822 */
			UNF_TRACE(UNF_EVTLOG_DRIVER_INFO,
				  UNF_LOG_LOGIN_ATT, UNF_MAJOR,
				  "LPort(0x%x) send ECHO to RPort(0x%x), received ACC. local snd echo:(0x%x), remote rcv echo:(0x%x), remote snd echo acc:(0x%x), local rcv echo acc:(0x%x)",
				  lport->port_id, rport->nport_id,
				  xchg->private[PKG_PRIVATE_ECHO_CMD_SND_TIME],
				  xchg->private[PKG_PRIVATE_ECHO_CMD_RCV_TIME],
				  xchg->private[PKG_PRIVATE_ECHO_RSP_SND_TIME],
				  xchg->private[PKG_PRIVATE_ECHO_ACC_RCV_TIME]);
		} else if ((mag_ver_local == ECHO_MG_VERSION_LOCAL) &&
			   (mag_ver_remote != ECHO_MG_VERSION_REMOTE)) {
			/* the peer don't supprt smartping, only local snd
			 * and rcv rsp time stamp
			 */
			UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT,
				  UNF_MAJOR,
				  "LPort(0x%x) send ECHO to RPort(0x%x), received ACC. local snd echo:(0x%x), local rcv echo acc:(0x%x)",
				  lport->port_id, rport->nport_id,
				  xchg->private[PKG_PRIVATE_ECHO_CMD_SND_TIME],
				  xchg->private[PKG_PRIVATE_ECHO_ACC_RCV_TIME]);
		} else if ((mag_ver_local != ECHO_MG_VERSION_LOCAL) &&
			   (mag_ver_remote != ECHO_MG_VERSION_REMOTE)) {
			UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT,
				  UNF_MAJOR,
				  "LPort(0x%x) send ECHO to RPort(0x%x), received ACC. local and remote is not IN300",
				  lport->port_id, rport->nport_id);
		}
	} else {
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT, UNF_WARN,
			  "[warn]Port(0x%x) send ECHO to RPort(0x%x) and received RJT",
			  lport->port_id, rport->nport_id);
	}

	xchg->echo_info.echo_result = UNF_ELS_ECHO_RESULT_OK;
	xchg->echo_info.response_time = jiffies -
					 xchg->echo_info.response_time;

	/* wake up semaphore */
	up(&xchg->echo_info.echo_sync_sema);
}

static void unf_echo_ob_callback(struct unf_xchg_s *v_xchg)
{
	struct unf_lport_s *lport = NULL;
	struct unf_rport_s *rport = NULL;

	UNF_CHECK_VALID(0x3336, UNF_TRUE, v_xchg, return);
	lport = v_xchg->lport;
	UNF_CHECK_VALID(0x3337, UNF_TRUE, lport, return);
	rport = v_xchg->rport;
	UNF_CHECK_VALID(0x3338, UNF_TRUE, rport, return);

	UNF_REFERNCE_VAR(lport);
	UNF_REFERNCE_VAR(rport);

	UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT, UNF_WARN,
		  "[warn]Port(0x%x) send ECHO to RPort(0x%x) but timeout",
		  lport->port_id, rport->nport_id);

	v_xchg->echo_info.echo_result = UNF_ELS_ECHO_RESULT_FAIL;

	/* wake up semaphore */
	up(&v_xchg->echo_info.echo_sync_sema);
}

unsigned int unf_send_echo(struct unf_lport_s *v_lport,
			   struct unf_rport_s *v_rport,
			   unsigned int *v_time)
{
	struct unf_echo_payload_s *echo_pld = NULL;
	union unf_sfs_u *fc_entry = NULL;
	struct unf_xchg_s *xchg = NULL;
	struct unf_frame_pkg_s pkg = { 0 };
	unsigned int ret = UNF_RETURN_ERROR;
	unsigned long delay = 0;
	unsigned short ox_id = 0;
	dma_addr_t phy_echo_addr;

	UNF_CHECK_VALID(0x3340, UNF_TRUE, v_lport, return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(0x3341, UNF_TRUE, v_rport, return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(0x3342, UNF_TRUE, v_time, return UNF_RETURN_ERROR);

	delay = 2 * (unsigned long)(v_lport->ra_tov);

	xchg = unf_get_sfs_free_xchg_and_init(v_lport, v_rport->nport_id,
					      v_rport, &fc_entry);
	if (!xchg) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_LOGIN_ATT, UNF_ERR,
			  "[err]Port(0x%x) exchange can't be NULL for ECHO",
			  v_lport->port_id);

		return ret;
	}

	xchg->cmnd_code = ELS_ECHO;  /* ECHO */

	xchg->fcp_sfs_union.sfs_entry.cur_offset = UNF_ECHO_REQ_SIZE;

	ox_id = xchg->ox_id;

	/* Set callback function */
	xchg->pfn_callback = unf_echo_callback;  /* wake up semaphore */
	xchg->pfn_ob_callback = unf_echo_ob_callback;  /* wake up semaphore */

	unf_fill_package(&pkg, xchg, v_rport);

	/* Fill ECHO entry(payload) */
	echo_pld = (struct unf_echo_payload_s *)unf_get_one_big_sfs_buf(xchg);
	if (!echo_pld) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT, UNF_WARN,
			  "[warn]Port(0x%x) can't allocate buffer for ECHO",
			  v_lport->port_id);

		unf_cm_free_xchg(v_lport, xchg);
		return UNF_RETURN_ERROR;
	}

	fc_entry->echo.echo_pld = echo_pld;
	phy_echo_addr = pci_map_single(v_lport->low_level_func.dev, echo_pld,
				       UNF_ECHO_PAYLOAD_LEN, DMA_BIDIRECTIONAL);
	if (pci_dma_mapping_error(
		v_lport->low_level_func.dev, phy_echo_addr)) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT, UNF_WARN,
			  "[warn]Port(0x%x) pci map err",
			  v_lport->port_id);
		unf_cm_free_xchg(v_lport, xchg);
		return UNF_RETURN_ERROR;
	}
	fc_entry->echo.phy_echo_addr = phy_echo_addr;
	memset(echo_pld, 0, sizeof(struct unf_echo_payload_s));
	echo_pld->cmnd = (UNF_ELS_CMND_ECHO);
	echo_pld->data[0] = ECHO_MG_VERSION_LOCAL;

	ret = unf_xchg_ref_inc(xchg, SEND_ELS);
	UNF_CHECK_VALID(0x3343, UNF_TRUE, (ret == RETURN_OK),
			return UNF_RETURN_ERROR);

	/* Start to send ECHO command */
	xchg->echo_info.response_time = jiffies;
	ret = unf_els_cmnd_send(v_lport, &pkg, xchg);
	if (ret != RETURN_OK) {
		unf_cm_free_xchg((void *)v_lport, (void *)xchg);
	} else {
		if (down_timeout(&xchg->echo_info.echo_sync_sema,
				 (long)
				 msecs_to_jiffies((unsigned int)delay))) {
			UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT,
				  UNF_WARN,
				  "[warn]ECHO send %s. Port(0x%x)--->rport(0x%x) but response timeout with OX_ID(0x%x)",
				  (ret != RETURN_OK) ? "failed" : "succeed",
				  v_lport->port_id, v_rport->nport_id, ox_id);

			xchg->echo_info.echo_result =
				UNF_ELS_ECHO_RESULT_FAIL;
		}

		if (xchg->echo_info.echo_result ==
		    UNF_ELS_ECHO_RESULT_FAIL) {
			UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT,
				  UNF_MAJOR,
				  "Echo send fail or timeout");

			ret = UNF_RETURN_ERROR;
		} else {
			UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT,
				  UNF_MAJOR,
				  "echo acc rsp,echo_cmd_snd(0x%xus)-->echo_cmd_rcv(0x%xus)-->echo_acc_snd(0x%xus)-->echo_acc_rcv(0x%xus).",
				  xchg->private[PKG_PRIVATE_ECHO_CMD_SND_TIME],
				  xchg->private[PKG_PRIVATE_ECHO_CMD_RCV_TIME],
				  xchg->private[PKG_PRIVATE_ECHO_RSP_SND_TIME],
				  xchg->private[PKG_PRIVATE_ECHO_ACC_RCV_TIME]);

			*v_time = (
				xchg->private[PKG_PRIVATE_ECHO_ACC_RCV_TIME] -
				xchg->private[PKG_PRIVATE_ECHO_CMD_SND_TIME]) -
				(xchg->private[PKG_PRIVATE_ECHO_RSP_SND_TIME] -
				xchg->private[PKG_PRIVATE_ECHO_CMD_RCV_TIME]);
		}
	}

	pci_unmap_single(v_lport->low_level_func.dev, phy_echo_addr,
			 UNF_ECHO_PAYLOAD_LEN, DMA_BIDIRECTIONAL);
	fc_entry->echo.phy_echo_addr = 0;
	unf_xchg_ref_dec(xchg, SEND_ELS);
	UNF_REFERNCE_VAR(ox_id);
	return ret;
}

static void unf_fill_prli_pld(struct unf_pril_payload_s *v_prli_pld,
			      struct unf_lport_s *v_lport)
{
	unsigned int pld_len = 0;

	UNF_CHECK_VALID(0x3344, UNF_TRUE, v_prli_pld, return);
	UNF_CHECK_VALID(0x3345, UNF_TRUE, v_lport, return);

	pld_len = sizeof(struct unf_pril_payload_s) - UNF_PRLI_SIRT_EXTRA_SIZE;
	v_prli_pld->cmnd = (UNF_ELS_CMND_PRLI |
			      ((unsigned int)UNF_FC4_FRAME_PAGE_SIZE <<
			      UNF_FC4_FRAME_PAGE_SIZE_SHIFT) |
			      ((unsigned int)pld_len));

	v_prli_pld->parms[0] = (UNF_FC4_FRAME_PARM_0_FCP |
				UNF_FC4_FRAME_PARM_0_I_PAIR);
	v_prli_pld->parms[1] = UNF_NOT_MEANINGFUL;
	v_prli_pld->parms[2] = UNF_NOT_MEANINGFUL;

	/* About Read Xfer_rdy disable */
	v_prli_pld->parms[3] = (UNF_FC4_FRAME_PARM_3_R_XFER_DIS |
				v_lport->options);

	/* About FCP confirm */
	if (v_lport->low_level_func.lport_cfg_items.fcp_conf == UNF_TRUE)
		v_prli_pld->parms[3] |= UNF_FC4_FRAME_PARM_3_CONF_ALLOW;

	/* About Tape support */
	if (v_lport->low_level_func.lport_cfg_items.tape_support) {
		v_prli_pld->parms[3] |=
				(UNF_FC4_FRAME_PARM_3_REC_SUPPORT |
				UNF_FC4_FRAME_PARM_3_RETRY_SUPPORT |
				UNF_FC4_FRAME_PARM_3_TASK_RETRY_ID_SUPPORT |
				UNF_FC4_FRAME_PARM_3_CONF_ALLOW);
	}

	UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT, UNF_MAJOR,
		  "[info]Port(0x%x)'s PRLI payload: options(0x%x) parameter-3(0x%x)",
		  v_lport->port_id, v_lport->options, v_prli_pld->parms[3]);

	UNF_PRINT_SFS_LIMIT(UNF_INFO, v_lport->port_id, v_prli_pld,
			    sizeof(struct unf_pril_payload_s));
}

static void unf_prli_callback(void *v_lport, void *v_rport, void *v_xchg)
{
	/* RCVD PRLI RSP: ACC or RJT --->>> SCSI Link Up */
	struct unf_lport_s *lport = NULL;
	struct unf_rport_s *rport = NULL;
	struct unf_xchg_s *xchg = NULL;
	struct unf_pril_payload_s *prli_acc_pld = NULL;
	unsigned long flag = 0;
	unsigned int cmnd = 0;
	unsigned int options = 0;
	unsigned int fcp_conf = 0;
	unsigned int rec_support = 0;
	unsigned int task_retry_support = 0;
	unsigned int retry_support = 0;
	unsigned int tape_support = 0;
	enum unf_rport_login_state_e rport_state = UNF_RPORT_ST_INIT;

	UNF_CHECK_VALID(0x3679, UNF_TRUE, v_lport, return);
	UNF_CHECK_VALID(0x3680, UNF_TRUE, v_rport, return);
	UNF_CHECK_VALID(0x3681, UNF_TRUE, v_xchg, return);
	lport = (struct unf_lport_s *)v_lport;
	rport = (struct unf_rport_s *)v_rport;
	xchg = (struct unf_xchg_s *)v_xchg;

	if (!xchg->fcp_sfs_union.sfs_entry.fc_sfs_entry_ptr) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_LOGIN_ATT, UNF_ERR,
			  "[err]Port(0x%x) exchange(%p) entry is NULL",
			  lport->port_id, xchg);
		return;
	}

	/* Get PRLI ACC payload */
	prli_acc_pld =
		&xchg->fcp_sfs_union.sfs_entry.fc_sfs_entry_ptr->prli_acc.payload;
	if (xchg->byte_orders & UNF_BIT_2) {
		/* Change to little End, About INI/TGT mode & confirm info */
		options = be32_to_cpu(prli_acc_pld->parms[3]) &
			  (UNF_FC4_FRAME_PARM_3_TGT |
			  UNF_FC4_FRAME_PARM_3_INI);

		cmnd = be32_to_cpu(prli_acc_pld->cmnd);
		fcp_conf = be32_to_cpu(prli_acc_pld->parms[3]) &
			UNF_FC4_FRAME_PARM_3_CONF_ALLOW;
		rec_support = be32_to_cpu(prli_acc_pld->parms[3]) &
			UNF_FC4_FRAME_PARM_3_REC_SUPPORT;
		task_retry_support = be32_to_cpu(prli_acc_pld->parms[3]) &
			UNF_FC4_FRAME_PARM_3_TASK_RETRY_ID_SUPPORT;
		retry_support = be32_to_cpu(prli_acc_pld->parms[3]) &
			UNF_FC4_FRAME_PARM_3_RETRY_SUPPORT;

	} else {
		options = (prli_acc_pld->parms[3]) &
			  (UNF_FC4_FRAME_PARM_3_TGT |
			  UNF_FC4_FRAME_PARM_3_INI);

		cmnd = (prli_acc_pld->cmnd);
		fcp_conf = prli_acc_pld->parms[3] &
			UNF_FC4_FRAME_PARM_3_CONF_ALLOW;
		rec_support = prli_acc_pld->parms[3] &
			UNF_FC4_FRAME_PARM_3_REC_SUPPORT;
		task_retry_support = prli_acc_pld->parms[3] &
			UNF_FC4_FRAME_PARM_3_TASK_RETRY_ID_SUPPORT;
		retry_support = prli_acc_pld->parms[3] &
			UNF_FC4_FRAME_PARM_3_RETRY_SUPPORT;
	}

	UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT, UNF_MAJOR,
		  "[info]LOGIN: PRLI RSP: RPort(0x%x) parameter-3(0x%x) option(0x%x) cmd(0x%x) rec support:%u",
		  rport->nport_id, prli_acc_pld->parms[3], options,
		  cmnd, rec_support);

	/* PRLI ACC: R_Port READY & Report R_Port Link Up */
	if ((cmnd & UNF_ELS_CMND_HIGH_MASK) == UNF_ELS_CMND_ACC) {
		/* Update R_Port options(INI/TGT/BOTH) */
		rport->options = options;

		unf_update_port_feature(rport->port_name, rport->options);

		/* NOTE: R_Port only with INI mode, send LOGO */
		if (rport->options == UNF_PORT_MODE_INI) {
			/* Update R_Port state: LOGO */
			spin_lock_irqsave(&rport->rport_state_lock, flag);
			unf_rport_state_ma(rport, UNF_EVENT_RPORT_LOGO);
			spin_unlock_irqrestore(&rport->rport_state_lock, flag);

			/* NOTE: Start to Send LOGO */
			unf_rport_enter_logo(lport, rport);
			return;
		}

		/* About confirm */
		if (fcp_conf &&
		    (lport->low_level_func.lport_cfg_items.fcp_conf !=
		     UNF_FALSE)) {
			rport->fcp_conf_needed = UNF_TRUE;

			UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT,
				  UNF_MAJOR,
				  "[info]Port(0x%x_0x%x) FCP config is need for RPort(0x%x)",
				  lport->port_id, lport->nport_id,
				  rport->nport_id);
		}
	tape_support = (rec_support && task_retry_support && retry_support);
	if (tape_support &&
	    (lport->low_level_func.lport_cfg_items.tape_support != UNF_FALSE)) {
		rport->tape_support_needed = UNF_TRUE;

		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT, UNF_KEVENT,
			  "[info]Port(0x%x_0x%x) Rec is enabled for RPort(0x%x)",
			  lport->port_id, lport->nport_id, rport->nport_id);
	}
		/* Update R_Port state: READY */
		spin_lock_irqsave(&rport->rport_state_lock, flag);
		unf_rport_state_ma(rport, UNF_EVENT_RPORT_READY);
		rport_state = rport->rp_state;
		spin_unlock_irqrestore(&rport->rport_state_lock, flag);

		/* Report R_Port online (Link Up) event to SCSI */
		if (rport_state == UNF_RPORT_ST_READY) {
			rport->logo_retries = 0;
			unf_update_lport_state_by_linkup_event(
				lport, rport, rport->options);
		}
	} else {
		/* PRLI RJT: Do R_Port error recovery */
		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT,
			  UNF_MAJOR,
			  "[info]LOGIN: Port(0x%x)<---LS_RJT(DID:0x%x SID:0x%x) for PRLI. RPort(0x%p) OX_ID(0x%x)",
			  lport->port_id, lport->nport_id,
			  rport->nport_id, rport, xchg->ox_id);

		unf_rport_error_recovery(rport);
	}
}

static void unf_prli_ob_callback(struct unf_xchg_s *v_xchg)
{
	/* Do R_Port recovery */
	struct unf_lport_s *lport = NULL;
	struct unf_rport_s *rport = NULL;
	unsigned long flag = 0;

	UNF_CHECK_VALID(0x3676, UNF_TRUE, v_xchg, return);

	UNF_REFERNCE_VAR(lport);
	spin_lock_irqsave(&v_xchg->xchg_state_lock, flag);
	lport = v_xchg->lport;
	rport = v_xchg->rport;
	spin_unlock_irqrestore(&v_xchg->xchg_state_lock, flag);

	UNF_CHECK_VALID(0x3677, UNF_TRUE, lport, return);
	UNF_CHECK_VALID(0x3678, UNF_TRUE, rport, return);

	UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT, UNF_WARN,
		  "[warn]LOGIN: Port(0x%x_0x%x) RPort(0x%x) send PRLI failed and do recovery",
		  lport->port_id, lport->nport_id, rport->nport_id);

	/* Start to do R_Port error recovery */
	unf_rport_error_recovery(rport);

	UNF_REFERNCE_VAR(lport);
}

unsigned int unf_send_prli(struct unf_lport_s *v_lport,
			   struct unf_rport_s *v_rport)
{
	struct unf_pril_payload_s *prli_pal = NULL;
	union unf_sfs_u *fc_entry = NULL;
	struct unf_xchg_s *xchg = NULL;
	unsigned int ret = UNF_RETURN_ERROR;
	struct unf_frame_pkg_s pkg = { 0 };
	unsigned short ox_id = 0;

	UNF_REFERNCE_VAR(ox_id);
	UNF_CHECK_VALID(0x3346, UNF_TRUE, v_lport, return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(0x3347, UNF_TRUE, v_rport, return UNF_RETURN_ERROR);

	/* Get & Set new free exchange */
	xchg = unf_get_sfs_free_xchg_and_init(v_lport, v_rport->nport_id,
					      v_rport, &fc_entry);
	if (!xchg) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_LOGIN_ATT, UNF_ERR,
			  "[err]Port(0x%x) exchange can't be NULL for PRLI",
			  v_lport->port_id);

		return ret;
	}

	xchg->cmnd_code = ELS_PRLI;  // PRLI

	ox_id = xchg->ox_id;

	/* Set callback function */
	/* for rcvd prli acc/rjt processer */
	xchg->pfn_callback = unf_prli_callback;
	/* for send prli failed processer */
	xchg->pfn_ob_callback = unf_prli_ob_callback;

	unf_fill_package(&pkg, xchg, v_rport);

	/* Fill PRLI payload */
	prli_pal = &fc_entry->prli.payload;
	memset(prli_pal, 0, sizeof(struct unf_pril_payload_s));
	unf_fill_prli_pld(prli_pal, v_lport);

	/* Start to Send RPLI ELS CMND */
	ret = unf_els_cmnd_send(v_lport, &pkg, xchg);
	if (ret != RETURN_OK)
		unf_cm_free_xchg((void *)v_lport, (void *)xchg);

	UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT, UNF_MAJOR,
		  "[info]LOGIN: PRLI send %s. Port(0x%x)--->rport(0x%x) with OX_ID(0x%x)",
		  (ret != RETURN_OK) ? "failed" : "succeed",
		  v_lport->port_id, v_rport->nport_id, ox_id);

	UNF_REFERNCE_VAR(ox_id);
	return ret;
}

static void unf_fill_prlo_pld(struct unf_pril_payload_s *v_prlo_pld,
			      struct unf_lport_s *v_lport)
{
	UNF_CHECK_VALID(0x3348, UNF_TRUE, v_prlo_pld, return);
	UNF_CHECK_VALID(0x3349, UNF_TRUE, v_lport, return);

	v_prlo_pld->cmnd = (UNF_ELS_CMND_PRLO);
	v_prlo_pld->parms[0] = (UNF_FC4_FRAME_PARM_0_FCP);
	v_prlo_pld->parms[1] = UNF_NOT_MEANINGFUL;
	v_prlo_pld->parms[2] = UNF_NOT_MEANINGFUL;
	v_prlo_pld->parms[3] = UNF_NO_SERVICE_PARAMS;

	UNF_PRINT_SFS_LIMIT(UNF_INFO, v_lport->port_id, v_prlo_pld,
			    sizeof(struct unf_pril_payload_s));
}

unsigned int unf_send_prlo(struct unf_lport_s *v_lport,
			   struct unf_rport_s *v_rport)
{
	struct unf_pril_payload_s *prlo_pld = NULL;
	union unf_sfs_u *fc_entry = NULL;
	struct unf_xchg_s *xchg = NULL;
	unsigned int ret = UNF_RETURN_ERROR;
	unsigned short ox_id = 0;
	struct unf_frame_pkg_s pkg;

	UNF_REFERNCE_VAR(ox_id);
	UNF_CHECK_VALID(0x3350, UNF_TRUE, v_lport, return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(0x3351, UNF_TRUE, v_rport, return UNF_RETURN_ERROR);

	memset(&pkg, 0, sizeof(struct unf_frame_pkg_s));

	/* Get free exchange for PRLO */
	xchg = unf_get_sfs_free_xchg_and_init(v_lport, v_rport->nport_id,
					      v_rport, &fc_entry);
	if (!xchg) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_LOGIN_ATT, UNF_ERR,
			  "[err]Port(0x%x) exchange can't be NULL for PRLO",
			  v_lport->port_id);

		return ret;
	}

	xchg->cmnd_code = ELS_PRLO;  /* PRLO */

	ox_id = xchg->ox_id;

	unf_fill_package(&pkg, xchg, v_rport);

	/* Fill PRLO entry(payload) */
	prlo_pld = &fc_entry->prlo.payload;
	memset(prlo_pld, 0, sizeof(struct unf_pril_payload_s));
	unf_fill_prlo_pld(prlo_pld, v_lport);

	/* Start to send PRLO command */
	ret = unf_els_cmnd_send(v_lport, &pkg, xchg);
	if (ret != RETURN_OK)
		unf_cm_free_xchg((void *)v_lport, (void *)xchg);

	UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT, UNF_MAJOR,
		  "[info]LOGIN: PRLO send %s. Port(0x%x)--->rport(0x%x) with OX_ID(0x%x)",
		  (ret != RETURN_OK) ? "failed" : "succeed",
		  v_lport->port_id, v_rport->nport_id, ox_id);

	UNF_REFERNCE_VAR(ox_id);
	return ret;
}

static void unf_fill_rrq_pld(struct unf_rrq_s *v_rrq_pld,
			     struct unf_xchg_s *v_xchg)
{
	UNF_CHECK_VALID(0x3360, UNF_TRUE, v_rrq_pld, return);
	UNF_CHECK_VALID(0x3361, UNF_TRUE, v_xchg, return);

	v_rrq_pld->cmnd = UNF_ELS_CMND_RRQ;
	v_rrq_pld->sid = v_xchg->sid;
	v_rrq_pld->oxid_rxid = ((unsigned int)v_xchg->ox_id << 16 |
				  v_xchg->rx_id);
}

static void unf_rrq_callback(void *v_lport, void *v_rport, void *v_xchg)
{
	/* Release I/O */
	struct unf_lport_s *lport = NULL;
	struct unf_xchg_s *xchg = NULL;
	struct unf_els_acc_s *els_acc = NULL;
	unsigned int cmnd = 0;
	struct unf_xchg_s *io_xchg = NULL;

	UNF_CHECK_VALID(0x3696, UNF_TRUE, v_lport, return);
	UNF_CHECK_VALID(0x3697, UNF_TRUE, v_rport, return);
	UNF_CHECK_VALID(0x3698, UNF_TRUE, v_xchg, return);
	UNF_REFERNCE_VAR(v_rport);

	lport = (struct unf_lport_s *)v_lport;
	UNF_REFERNCE_VAR(lport);
	xchg = (struct unf_xchg_s *)v_xchg;

	if (!xchg->fcp_sfs_union.sfs_entry.fc_sfs_entry_ptr) {
		UNF_TRACE(UNF_EVTLOG_IO_WARN, UNF_LOG_IO_ATT, UNF_WARN,
			  "[warn]Port(0x%x) exchange(0x%p) SfsEntryPtr is NULL",
			  lport->port_id, xchg);
		return;
	}

	io_xchg = (struct unf_xchg_s *)xchg->io_xchg;
	if (!io_xchg) {
		UNF_TRACE(UNF_EVTLOG_IO_WARN, UNF_LOG_IO_ATT, UNF_WARN,
			  "[warn]Port(0x%x) IO exchange is NULL. RRQ cb sfs xchg(0x%p) tag(0x%x)",
			  lport->port_id, xchg, xchg->hot_pool_tag);
		return;
	}

	UNF_TRACE(UNF_EVTLOG_IO_INFO, UNF_LOG_IO_ATT, UNF_MAJOR,
		  "[info]Port(0x%x) release IO exch(0x%p) tag(0x%x). RRQ cb sfs xchg(0x%p) tag(0x%x)",
		  lport->port_id, xchg->io_xchg, io_xchg->hot_pool_tag,
		  xchg, xchg->hot_pool_tag);

	/* NOTE: release I/O exchange resource */
	unf_xchg_ref_dec(io_xchg, XCHG_ALLOC);

	els_acc = &xchg->fcp_sfs_union.sfs_entry.fc_sfs_entry_ptr->els_acc;
	if (xchg->byte_orders & UNF_BIT_2)
		cmnd = be32_to_cpu(els_acc->cmnd);
	else
		cmnd = (els_acc->cmnd);
}

static void unf_rrq_ob_callback(struct unf_xchg_s *v_xchg)
{
	/* Release I/O */
	struct unf_xchg_s *xchg = NULL;
	struct unf_xchg_s *io_xchg = NULL;

	xchg = (struct unf_xchg_s *)v_xchg;
	if (!xchg) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT, UNF_WARN,
			  "[warn]Exchange can't be NULL");
		return;
	}

	io_xchg = (struct unf_xchg_s *)xchg->io_xchg;
	if (!io_xchg) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT, UNF_WARN,
			  "[warn]IO exchange can't be NULL with Sfs exch(0x%p) tag(0x%x)",
			  xchg, xchg->hot_pool_tag);
		return;
	}

	UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT, UNF_KEVENT,
		  "[info]send RRQ failed: SFS exch(0x%p) tag(0x%x) exch(0x%p) tag(0x%x) OXID_RXID(0x%x_0x%x) SID_DID(0x%x_0x%x)",
		  xchg, xchg->hot_pool_tag, io_xchg, io_xchg->hot_pool_tag,
		  io_xchg->ox_id, io_xchg->rx_id, io_xchg->sid,
		  io_xchg->did);

	/* NOTE: Free I/O exchange resource */
	unf_xchg_ref_dec(io_xchg, XCHG_ALLOC);
}

unsigned int unf_send_rrq(struct unf_lport_s *v_lport,
			  struct unf_rport_s *v_rport,
			  struct unf_xchg_s *v_xchg)
{
	/* after ABTS Done */
	struct unf_rrq_s *rrq_pld = NULL;
	union unf_sfs_u *fc_entry = NULL;
	struct unf_xchg_s *xchg = NULL;
	struct unf_frame_pkg_s pkg = { 0 };
	unsigned int ret = UNF_RETURN_ERROR;
	unsigned short ox_id = 0;

	UNF_REFERNCE_VAR(ox_id);
	UNF_CHECK_VALID(0x3362, UNF_TRUE, v_lport, return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(0x3363, UNF_TRUE, v_rport, return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(0x3364, UNF_TRUE, v_xchg, return UNF_RETURN_ERROR);

	if (v_xchg->rport_bind_jifs != v_rport->rport_alloc_jifs ||
	    (v_rport->nport_id == INVALID_VALUE32))
		return ret;
	/* Get & Set New free Exchange for RRQ */
	xchg = unf_get_sfs_free_xchg_and_init(v_lport, v_rport->nport_id,
					      v_rport, &fc_entry);
	if (!xchg) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_LOGIN_ATT, UNF_ERR,
			  "[err]Port(0x%x) exchange can't be NULL for RRQ",
			  v_lport->port_id);

		return ret;
	}

	xchg->cmnd_code = ELS_RRQ;  // RRQ

	/* Set callback function */
	xchg->pfn_callback = unf_rrq_callback; // release I/O exchange context
	/* release I/O exchange context */
	xchg->pfn_ob_callback = unf_rrq_ob_callback;
	xchg->io_xchg = v_xchg;  // pointer to IO XCHG

	ox_id = xchg->ox_id;

	unf_fill_package(&pkg, xchg, v_rport);

	/* Fill RRQ entry(payload) */
	rrq_pld = &fc_entry->rrq;
	memset(rrq_pld, 0, sizeof(struct unf_rrq_s));
	unf_fill_rrq_pld(rrq_pld, v_xchg);

	/* Start to send RRQ command to remote port */
	ret = unf_els_cmnd_send(v_lport, &pkg, xchg);
	if (ret != RETURN_OK)
		unf_cm_free_xchg((void *)v_lport, (void *)xchg);

	UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT, UNF_MAJOR,
		  "[info]RRQ send %s. Port(0x%x)--->rport(0x%x) free old exchange(0x%x) with OX_ID(0x%x)",
		  (ret != RETURN_OK) ? "failed" : "succeed",
		  v_lport->port_id, v_rport->nport_id,
		  v_xchg->hot_pool_tag, ox_id);

	UNF_REFERNCE_VAR(ox_id);
	return ret;
}

static void unf_fill_gff_id_pld(struct unf_gffid_s *v_gff_id,
				unsigned int v_nport_id)
{
	UNF_CHECK_VALID(0x3365, UNF_TRUE, v_gff_id, return);

	v_gff_id->ctiu_pream.rev_inid = (UNF_REV_NPORTID_INIT);
	v_gff_id->ctiu_pream.gstype_gssub_options = (UNF_FSTYPE_OPT_INIT);
	v_gff_id->ctiu_pream.cmnd_rsp_size = (UNF_FSTYPE_GFF_ID);
	v_gff_id->ctiu_pream.frag_reason_exp_vend = UNF_FRAG_REASON_VENDOR;
	v_gff_id->nport_id = v_nport_id;
}

static void unf_gff_id_ob_callback(struct unf_xchg_s *v_xchg)
{
	/* Send PLOGI */
	struct unf_lport_s *lport = NULL;
	struct unf_lport_s *root_lport = NULL;
	struct unf_rport_s *rport = NULL;
	unsigned long flag = 0;
	unsigned int ret = UNF_RETURN_ERROR;
	unsigned int nport_id = 0;

	UNF_CHECK_VALID(0x3611, UNF_TRUE, v_xchg, return);

	spin_lock_irqsave(&v_xchg->xchg_state_lock, flag);
	lport = v_xchg->lport;
	nport_id = v_xchg->disc_port_id;
	spin_unlock_irqrestore(&v_xchg->xchg_state_lock, flag);

	UNF_CHECK_VALID(0x3612, UNF_TRUE, NULL != lport, return);

	root_lport = (struct unf_lport_s *)lport->root_lport;
	atomic_inc(&root_lport->disc.disc_thread_info.disc_contrl_size);
	wake_up_process(root_lport->disc.disc_thread_info.data_thread);

	/* Get (safe) R_Port */
	rport = unf_get_rport_by_nport_id(lport, nport_id);
	rport = unf_get_safe_rport(lport, rport, UNF_RPORT_REUSE_ONLY,
				   nport_id);
	if (!rport) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT, UNF_WARN,
			  "[warn]Port(0x%x) can't allocate new RPort(0x%x)",
			  lport->port_id, nport_id);
		return;
	}

	UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT, UNF_WARN,
		  "[warn]Port(0x%x_0x%x) send GFF_ID(0x%x_0x%x) to RPort(0x%x_0x%x) abnormal",
		  lport->port_id, lport->nport_id, v_xchg->ox_id,
		  v_xchg->rx_id, rport->rport_index, rport->nport_id);

	/* Update R_Port state: PLOGI_WAIT */
	spin_lock_irqsave(&rport->rport_state_lock, flag);
	rport->nport_id = nport_id;
	unf_rport_state_ma(rport, UNF_EVENT_RPORT_ENTER_PLOGI);
	spin_unlock_irqrestore(&rport->rport_state_lock, flag);

	/* NOTE: Start to send PLOGI */
	ret = unf_send_plogi(lport, rport);
	if (ret != RETURN_OK) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT, UNF_WARN,
			  "[warn]Port(0x%x) send PLOGI failed, enter recovry",
			  lport->port_id);

		/* Do R_Port recovery */
		unf_rport_error_recovery(rport);
	}
}

static void unf_check_rport_need_delay_plogi(struct unf_lport_s *v_lport,
					     struct unf_rport_s *v_rport,
					     unsigned int v_port_feature)
{
	/*
	 * Called by:
	 * 1. Private loop
	 * 2. RCVD GFF_ID ACC
	 */
	struct unf_lport_s *lport = v_lport;
	struct unf_rport_s *rport = v_rport;
	unsigned long flag = 0;
	unsigned int nport_id = 0;
	unsigned int ret = UNF_RETURN_ERROR;

	UNF_CHECK_VALID(0x3613, UNF_TRUE, v_lport, return);
	UNF_CHECK_VALID(0x3614, UNF_TRUE, v_rport, return);
	nport_id = rport->nport_id;

	/*
	 * Send GFF_ID means L_Port has INI attribute
	 **
	 * When to send PLOGI:
	 * 1. R_Port has TGT mode (COM or TGT), send PLOGI immediately
	 * 2. R_Port only with INI, send LOGO immediately
	 * 3. R_Port with unknown attribute, delay to send PLOGI
	 */
	if ((v_port_feature & UNF_PORT_MODE_TGT) ||
	    (lport->enhanced_features &
	    UNF_LPORT_ENHANCED_FEATURE_ENHANCED_GFF)) {
		/* R_Port has TGT mode: send PLOGI immediately */
		rport = unf_get_safe_rport(v_lport, rport,
					   UNF_RPORT_REUSE_ONLY, nport_id);
		UNF_CHECK_VALID(0x3615, UNF_TRUE, rport, return);

		/* Update R_Port state: PLOGI_WAIT */
		spin_lock_irqsave(&rport->rport_state_lock, flag);
		rport->nport_id = nport_id;
		unf_rport_state_ma(rport, UNF_EVENT_RPORT_ENTER_PLOGI);
		spin_unlock_irqrestore(&rport->rport_state_lock, flag);

		/* Start to send PLOGI */
		ret = unf_send_plogi(lport, rport);
		if (ret != RETURN_OK) {
			UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT,
				  UNF_WARN,
				  "[warn]LOGIN: Port(0x%x_0x%x) send PLOGI to RPort(0x%x) failed",
				  lport->port_id, lport->nport_id, nport_id);

			unf_rport_error_recovery(rport);
		}
	} else if (v_port_feature == UNF_PORT_MODE_INI) {
		/* R_Port only with INI mode: can't send PLOGI --->>>
		 * LOGO/nothing
		 */
		spin_lock_irqsave(&rport->rport_state_lock, flag);
		if (rport->rp_state == UNF_RPORT_ST_INIT) {
			spin_unlock_irqrestore(&rport->rport_state_lock, flag);

			UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT,
				  UNF_WARN,
				  "[warn]LOGIN: Port(0x%x_0x%x) send LOGO to RPort(0x%x) which only with INI mode",
				  lport->port_id, lport->nport_id, nport_id);

			/* Enter Closing state */
			unf_rport_enter_logo(lport, rport);
		} else {
			spin_unlock_irqrestore(&rport->rport_state_lock, flag);
		}
	} else {
		/* Unknown R_Port attribute: Delay to send PLOGI */
		rport = unf_get_safe_rport(v_lport, rport,
					   UNF_RPORT_REUSE_ONLY,
					   nport_id);
		UNF_CHECK_VALID(0x3616, UNF_TRUE, rport, return);

		/* Update R_Port state: PLOGI_WAIT */
		spin_lock_irqsave(&rport->rport_state_lock, flag);
		rport->nport_id = nport_id;
		unf_rport_state_ma(rport, UNF_EVENT_RPORT_ENTER_PLOGI);
		spin_unlock_irqrestore(&rport->rport_state_lock, flag);

		unf_rport_delay_login(rport);
	}
}

static void unf_rcv_gff_id_acc(struct unf_lport_s *v_lport,
			       struct unf_gffid_rsp_s *v_gff_id_rsp_pld,
			       unsigned int v_nport_id)
{
	/* Delay to LOGIN */
	struct unf_lport_s *lport = v_lport;
	struct unf_rport_s *rport = NULL;
	struct unf_gffid_rsp_s *gff_id_rsp_pld = v_gff_id_rsp_pld;
	unsigned int fc4feature = 0;
	unsigned long flag = 0;

	UNF_CHECK_VALID(0x3617, UNF_TRUE, v_lport, return);
	UNF_CHECK_VALID(0x3618, UNF_TRUE, v_gff_id_rsp_pld, return);

	fc4feature = gff_id_rsp_pld->fc_4_feature[1];
	if ((UNF_GFF_ACC_MASK & fc4feature) == 0)
		fc4feature = be32_to_cpu(gff_id_rsp_pld->fc_4_feature[1]);

	UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT, UNF_MAJOR,
		  "[info]LOGIN: Port(0x%x_0x%x) RPort(0x%x) received GFF_ID ACC. FC4 feature is 0x%x(1:TGT,2:INI,3:COM)",
		  lport->port_id, lport->nport_id, v_nport_id, fc4feature);

	/* Check (& Get new) R_Port */
	rport = unf_get_rport_by_nport_id(lport, v_nport_id);
	if (rport)
		rport = unf_find_rport(lport, v_nport_id, rport->port_name);

	if ((rport) ||
	    (UNF_GET_PORT_OPTIONS(fc4feature) != UNF_PORT_MODE_INI)) {
		rport = unf_get_safe_rport(lport, rport,
					   UNF_RPORT_REUSE_ONLY,
					   v_nport_id);
		UNF_CHECK_VALID(0x3619, UNF_TRUE, NULL != rport, return);
	} else {
		return;
	}

	if ((fc4feature & UNF_GFF_ACC_MASK) != 0) {
		spin_lock_irqsave(&rport->rport_state_lock, flag);
		rport->options = UNF_GET_PORT_OPTIONS(fc4feature);
		spin_unlock_irqrestore(&rport->rport_state_lock, flag);
	} else if (rport->port_name != INVALID_WWPN) {
		spin_lock_irqsave(&rport->rport_state_lock, flag);
		rport->options = unf_get_port_feature(rport->port_name);
		spin_unlock_irqrestore(&rport->rport_state_lock, flag);
	}

	/* NOTE: Send PLOGI if necessary */
	unf_check_rport_need_delay_plogi(lport, rport, rport->options);
}

static void unf_rcv_gff_id_rjt(struct unf_lport_s *v_lport,
			       struct unf_gffid_rsp_s *v_gff_id_rsp_pld,
			       unsigned int v_nport_id)
{
	/* Delay LOGIN or LOGO */
	struct unf_lport_s *lport = v_lport;
	struct unf_rport_s *rport = NULL;
	struct unf_gffid_rsp_s *gff_id_rsp_pld = v_gff_id_rsp_pld;
	unsigned int rjt_reason = 0;
	unsigned long flag = 0;

	UNF_CHECK_VALID(0x3620, UNF_TRUE, v_lport, return);
	UNF_CHECK_VALID(0x3621, UNF_TRUE, v_gff_id_rsp_pld, return);

	/* Check (& Get new) R_Port */
	rport = unf_get_rport_by_nport_id(lport, v_nport_id);
	if (rport)
		rport = unf_find_rport(lport, v_nport_id, rport->port_name);

	if (!rport) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT, UNF_MAJOR,
			  "[info]Port(0x%x) get RPort by N_Port_ID(0x%x) failed and alloc new",
			  lport->port_id, v_nport_id);

		rport = unf_rport_get_free_and_init(lport, UNF_PORT_TYPE_FC,
						    v_nport_id);
		UNF_CHECK_VALID(0x3622, UNF_TRUE, NULL != rport, return);

		spin_lock_irqsave(&rport->rport_state_lock, flag);
		rport->nport_id = v_nport_id;
		spin_unlock_irqrestore(&rport->rport_state_lock, flag);
	}

	rjt_reason = gff_id_rsp_pld->ctiu_pream.frag_reason_exp_vend;

	UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT, UNF_WARN,
		  "[warn]LOGIN: Port(0x%x) send GFF_ID for RPort(0x%x) but was rejected. Reason code(0x%x)",
		  lport->port_id, v_nport_id, rjt_reason);

	if (!UNF_GNN_GFF_ID_RJT_REASON(rjt_reason)) {
		rport = unf_get_safe_rport(v_lport, rport,
					   UNF_RPORT_REUSE_ONLY,
					   v_nport_id);
		UNF_CHECK_VALID(0x3623, UNF_TRUE, NULL != rport, return);

		/* Update R_Port state: PLOGI_WAIT */
		spin_lock_irqsave(&rport->rport_state_lock, flag);
		rport->nport_id = v_nport_id;
		unf_rport_state_ma(rport, UNF_EVENT_RPORT_ENTER_PLOGI);
		spin_unlock_irqrestore(&rport->rport_state_lock, flag);

		/* Delay to send PLOGI */
		unf_rport_delay_login(rport);
	} else {
		spin_lock_irqsave(&rport->rport_state_lock, flag);
		if (rport->rp_state == UNF_RPORT_ST_INIT) {
			spin_unlock_irqrestore(&rport->rport_state_lock, flag);

			/* Enter closing state */
			unf_rport_enter_logo(lport, rport);
		} else {
			spin_unlock_irqrestore(&rport->rport_state_lock, flag);
		}
	}
}

static void unf_gff_id_callback(void *v_lport, void *v_sns_port, void *v_xchg)
{
	struct unf_lport_s *lport = (struct unf_lport_s *)v_lport;
	struct unf_lport_s *root_lport = NULL;
	struct unf_xchg_s *xchg = (struct unf_xchg_s *)v_xchg;
	struct unf_gffid_rsp_s *gff_id_rsp_pld = NULL;
	unsigned int cmnd_rsp_size = 0;
	unsigned int nport_id = 0;

	UNF_CHECK_VALID(0x3626, UNF_TRUE, v_lport, return);
	UNF_CHECK_VALID(0x3627, UNF_TRUE, v_sns_port, return);
	UNF_CHECK_VALID(0x3628, UNF_TRUE, v_xchg, return);

	UNF_REFERNCE_VAR(v_sns_port);
	nport_id = xchg->disc_port_id;

	gff_id_rsp_pld =
		&xchg->fcp_sfs_union.sfs_entry.fc_sfs_entry_ptr->gff_id_rsp;
	cmnd_rsp_size = (gff_id_rsp_pld->ctiu_pream.cmnd_rsp_size);

	root_lport = (struct unf_lport_s *)lport->root_lport;
	atomic_inc(&root_lport->disc.disc_thread_info.disc_contrl_size);
	wake_up_process(root_lport->disc.disc_thread_info.data_thread);

	if ((cmnd_rsp_size & UNF_CT_IU_RSP_MASK) == UNF_CT_IU_ACCEPT) {
		/* Case for GFF_ID ACC: (Delay)PLOGI */
		unf_rcv_gff_id_acc(lport, gff_id_rsp_pld, nport_id);
	} else if ((cmnd_rsp_size & UNF_CT_IU_RSP_MASK) == UNF_CT_IU_REJECT) {
		/* Case for GFF_ID RJT: Delay PLOGI or LOGO directly */
		unf_rcv_gff_id_rjt(lport, gff_id_rsp_pld, nport_id);
	} else {
		/* Send PLOGI */
		unf_rcv_gff_id_rsp_unknown(lport, nport_id);
	}
}

unsigned int unf_send_gff_id(struct unf_lport_s *v_lport,
			     struct unf_rport_s *v_sns_port,
			     unsigned int v_nport_id)
{
	struct unf_gffid_s *gff_id = NULL;
	union unf_sfs_u *fc_entry = NULL;
	struct unf_xchg_s *xchg = NULL;
	unsigned int ret = UNF_RETURN_ERROR;
	unsigned short ox_id = 0;
	struct unf_frame_pkg_s pkg;
	struct unf_lport_s *root_lport = NULL;

	UNF_CHECK_VALID(0x3367, UNF_TRUE, v_sns_port, return UNF_RETURN_ERROR);

	if (unf_is_lport_valid(v_lport) != RETURN_OK)
		/* Lport is invalid, no retry or handle required, return ok */
		return RETURN_OK;

	root_lport = (struct unf_lport_s *)v_lport->root_lport;
	memset(&pkg, 0, sizeof(struct unf_frame_pkg_s));
	xchg = unf_get_sfs_free_xchg_and_init(v_lport, v_sns_port->nport_id,
					      v_sns_port, &fc_entry);
	if (!xchg) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_LOGIN_ATT, UNF_ERR,
			  "[err]Port(0x%x) exchange can't be NULL for GFF_ID",
			  v_lport->port_id);

		return unf_get_and_post_disc_event(v_lport, v_sns_port,
						   v_nport_id,
						   UNF_DISC_GET_FEATURE);
	}

	xchg->cmnd_code = NS_GFF_ID;  /* GFF_ID */

	xchg->disc_port_id = v_nport_id;

	/* Set callback function */
	xchg->pfn_ob_callback = unf_gff_id_ob_callback;  /* send PLOGI */
	xchg->pfn_callback = unf_gff_id_callback; /* send PLOGI or LOGO */

	ox_id = xchg->ox_id;

	unf_fill_package(&pkg, xchg, v_sns_port);

	/* Fill GFF_ID payload(entry) */
	gff_id = &fc_entry->gff_id; /* GFF_ID */
	memset(gff_id, 0, sizeof(struct unf_gffid_s));
	unf_fill_gff_id_pld(gff_id, v_nport_id);

	/* Send GFF_ID GS command now */
	ret = unf_gs_cmnd_send(v_lport, &pkg, xchg);
	if (ret != RETURN_OK)
		unf_cm_free_xchg((void *)v_lport, (void *)xchg);
	else
		atomic_dec(
			&root_lport->disc.disc_thread_info.disc_contrl_size);

	UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT, UNF_MAJOR,
		  "[info]LOGIN: GFF_ID send %s. Port(0x%x)--->rport(0x%x). Inquire RPort(0x%x) OX_ID(0x%x)",
		  (ret != RETURN_OK) ? "failed" : "succeed",
		  v_lport->port_id, v_sns_port->nport_id,
		  v_nport_id, ox_id);

	UNF_REFERNCE_VAR(ox_id);
	return ret;
}

static void unf_fill_gnn_id_pld(struct unf_gnnid_s *v_gnn_id_pld,
				unsigned int v_nport_id)
{
	/* Inquiry R_Port node name from SW */
	UNF_CHECK_VALID(0x3368, UNF_TRUE, v_gnn_id_pld, return);

	v_gnn_id_pld->ctiu_pream.rev_inid = UNF_REV_NPORTID_INIT;
	v_gnn_id_pld->ctiu_pream.gstype_gssub_options = UNF_FSTYPE_OPT_INIT;
	v_gnn_id_pld->ctiu_pream.cmnd_rsp_size = UNF_FSTYPE_GNN_ID;
	v_gnn_id_pld->ctiu_pream.frag_reason_exp_vend = UNF_FRAG_REASON_VENDOR;

	v_gnn_id_pld->nport_id = v_nport_id;
}

/*
 * Function Name       : unf_gnn_id_ob_callback
 * Function Description: Callback for sending GNN_ID abnormal
 * Input Parameters    : struct unf_xchg_s *v_xchg
 * Output Parameters   : N/A
 * Return Type         : void
 */
static void unf_gnn_id_ob_callback(struct unf_xchg_s *v_xchg)
{
	/* Send GFF_ID */
	struct unf_lport_s *lport = NULL;
	struct unf_rport_s *sns_port = NULL;
	unsigned int ret = UNF_RETURN_ERROR;
	unsigned int nport_id = 0;
	struct unf_lport_s *root_lport = NULL;

	UNF_CHECK_VALID(0x3597, UNF_TRUE, v_xchg, return);
	lport = v_xchg->lport;
	UNF_CHECK_VALID(0x3598, UNF_TRUE, lport, return);
	sns_port = v_xchg->rport;
	UNF_CHECK_VALID(0x3599, UNF_TRUE, sns_port, return);
	nport_id = v_xchg->disc_port_id;

	UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT, UNF_WARN,
		  "[warn]LOGIN: Port(0x%x) send GNN_ID failed to inquire RPort(0x%x)",
		  lport->port_id, nport_id);

	root_lport = (struct unf_lport_s *)lport->root_lport;
	atomic_inc(&root_lport->disc.disc_thread_info.disc_contrl_size);
	wake_up_process(root_lport->disc.disc_thread_info.data_thread);

	/* NOTE: continue next stage */
	ret = unf_get_and_post_disc_event(lport, sns_port, nport_id,
					  UNF_DISC_GET_FEATURE);
	if (ret != RETURN_OK) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_LOGIN_ATT, UNF_ERR,
			  "[err]Port(0x%x) add discovery event(0x%x) failed Rport(0x%x)",
			  lport->port_id, UNF_DISC_GET_FEATURE, nport_id);

		unf_rcv_gff_id_rsp_unknown(lport, nport_id);  // send PLOGI
	}
}

static void unf_rcv_gnn_id_acc(struct unf_lport_s *v_lport,
			       struct unf_rport_s *v_sns_port,
			       struct unf_gnnid_rsp_s *v_gnn_id_rsp_pld,
			       unsigned int v_nport_id)
{
	/* Send GFF_ID or Link down immediately */
	struct unf_lport_s *lport = v_lport;
	struct unf_rport_s *sns_port = v_sns_port;
	struct unf_gnnid_rsp_s *gnn_id_rsp_pld = v_gnn_id_rsp_pld;
	struct unf_rport_s *rport = NULL;
	unsigned long long node_name = 0;
	unsigned int ret = UNF_RETURN_ERROR;

	UNF_CHECK_VALID(0x3600, UNF_TRUE, v_lport, return);
	UNF_CHECK_VALID(0x3601, UNF_TRUE, v_sns_port, return);
	UNF_CHECK_VALID(0x3602, UNF_TRUE, v_gnn_id_rsp_pld, return);

	node_name = ((unsigned long long)(gnn_id_rsp_pld->node_name[0]) <<
		     32) |
		     ((unsigned long long)(gnn_id_rsp_pld->node_name[1]));

	if (node_name == lport->node_name) {
		/* R_Port & L_Port with same Node Name */
		rport = unf_get_rport_by_nport_id(lport, v_nport_id);
		if (rport) {
			UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT,
				  UNF_KEVENT,
				  "[info]Port(0x%x) has the same node name(0x%llx) with RPort(0x%x), linkdown it",
				  lport->port_id, node_name, v_nport_id);

			/* Destroy immediately */
			unf_rport_immediate_linkdown(lport, rport);
		}
	} else {
		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT, UNF_MAJOR,
			  "[info]LOGIN: Port(0x%x) got RPort(0x%x) with node name(0x%llx) by GNN_ID",
			  lport->port_id, v_nport_id, node_name);

		/* Start to Send GFF_ID */
		ret = unf_get_and_post_disc_event(lport, sns_port, v_nport_id,
						  UNF_DISC_GET_FEATURE);
		if (ret != RETURN_OK) {
			UNF_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_LOGIN_ATT,
				  UNF_ERR,
				  "[err]Port(0x%x) add discovery event(0x%x) failed Rport(0x%x)",
				  lport->port_id, UNF_DISC_GET_FEATURE,
				  v_nport_id);

			unf_rcv_gff_id_rsp_unknown(lport, v_nport_id);
		}
	}
}

static void unf_rcv_gnn_id_rjt(struct unf_lport_s *v_lport,
			       struct unf_rport_s *v_sns_port,
			       struct unf_gnnid_rsp_s *v_gnn_id_rsp_pld,
			       unsigned int v_nport_id)
{
	/* Send GFF_ID */
	struct unf_lport_s *lport = v_lport;
	struct unf_rport_s *sns_port = v_sns_port;
	struct unf_gnnid_rsp_s *gnn_id_rsp_pld = v_gnn_id_rsp_pld;
	unsigned int rjt_reason = 0;
	unsigned int ret = UNF_RETURN_ERROR;

	UNF_CHECK_VALID(0x3603, UNF_TRUE, v_lport, return);
	UNF_CHECK_VALID(0x3604, UNF_TRUE, v_sns_port, return);
	UNF_CHECK_VALID(0x3605, UNF_TRUE, v_gnn_id_rsp_pld, return);

	rjt_reason = (gnn_id_rsp_pld->ctiu_pream.frag_reason_exp_vend);

	UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT, UNF_WARN,
		  "[warn]LOGIN: Port(0x%x_0x%x) GNN_ID was rejected with reason code(0x%x)",
		  lport->port_id, lport->nport_id, rjt_reason);

	if (!UNF_GNN_GFF_ID_RJT_REASON(rjt_reason)) {
		/* Node existence: Continue next stage */
		ret = unf_get_and_post_disc_event(lport, sns_port, v_nport_id,
						  UNF_DISC_GET_FEATURE);
		if (ret != RETURN_OK) {
			UNF_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_LOGIN_ATT,
				  UNF_ERR,
				  "[err]Port(0x%x) add discovery event(0x%x) failed Rport(0x%x)",
				  lport->port_id, UNF_DISC_GET_FEATURE,
				  v_nport_id);

			unf_rcv_gff_id_rsp_unknown(lport, v_nport_id);
		}
	}
}

static void unf_gnn_id_callback(void *v_lport, void *v_sns_port, void *v_xchg)
{
	struct unf_lport_s *lport = (struct unf_lport_s *)v_lport;
	struct unf_rport_s *sns_port = (struct unf_rport_s *)v_sns_port;
	struct unf_xchg_s *xchg = (struct unf_xchg_s *)v_xchg;
	struct unf_gnnid_rsp_s *gnn_id_rsp_pld = NULL;
	unsigned int cmnd_rsp_size = 0;
	unsigned int nport_id = 0;
	struct unf_lport_s *root_lport = NULL;

	UNF_CHECK_VALID(0x3608, UNF_TRUE, v_lport, return);
	UNF_CHECK_VALID(0x3609, UNF_TRUE, v_sns_port, return);
	UNF_CHECK_VALID(0x3610, UNF_TRUE, v_xchg, return);

	nport_id = xchg->disc_port_id;
	gnn_id_rsp_pld =
		&xchg->fcp_sfs_union.sfs_entry.fc_sfs_entry_ptr->gnn_id_rsp;
	cmnd_rsp_size = (gnn_id_rsp_pld->ctiu_pream.cmnd_rsp_size);

	root_lport = (struct unf_lport_s *)lport->root_lport;
	atomic_inc(&root_lport->disc.disc_thread_info.disc_contrl_size);
	wake_up_process(root_lport->disc.disc_thread_info.data_thread);

	if ((cmnd_rsp_size & UNF_CT_IU_RSP_MASK) == UNF_CT_IU_ACCEPT) {
		/* Case ACC: send GFF_ID or Link down immediately */
		unf_rcv_gnn_id_acc(lport, sns_port, gnn_id_rsp_pld, nport_id);
	} else if ((cmnd_rsp_size & UNF_CT_IU_RSP_MASK) == UNF_CT_IU_REJECT) {
		/* Case RJT: send GFF_ID */
		unf_rcv_gnn_id_rjt(lport, sns_port, gnn_id_rsp_pld, nport_id);
	} else { /* NOTE: continue next stage */
		/* Case unknown: send GFF_ID */
		unf_rcv_gnn_id_rsp_unknown(lport, sns_port, nport_id);
	}
}

unsigned int unf_send_gnn_id(struct unf_lport_s *v_lport,
			     struct unf_rport_s *v_sns_port,
			     unsigned int v_nport_id)
{
	/* from DISC stop/re-login */
	struct unf_gnnid_s *gnn_id_pld = NULL;
	union unf_sfs_u *fc_entry = NULL;
	struct unf_xchg_s *xchg = NULL;
	unsigned int ret = UNF_RETURN_ERROR;
	unsigned short ox_id = 0;
	struct unf_frame_pkg_s pkg;
	struct unf_lport_s *root_lport = NULL;

	UNF_CHECK_VALID(0x3370, UNF_TRUE, v_sns_port, return UNF_RETURN_ERROR);

	if (unf_is_lport_valid(v_lport) != RETURN_OK)
		/* Lport is invalid, no retry or handle required, return ok */
		return RETURN_OK;

	root_lport = (struct unf_lport_s *)v_lport->root_lport;

	memset(&pkg, 0, sizeof(struct unf_frame_pkg_s));
	xchg = unf_get_sfs_free_xchg_and_init(v_lport, v_sns_port->nport_id,
					      v_sns_port, &fc_entry);
	if (!xchg) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT, UNF_WARN,
			  "[warn]Port(0x%x) exchange can't be NULL for GNN_ID",
			  v_lport->port_id);

		return unf_get_and_post_disc_event(v_lport, v_sns_port,
						   v_nport_id,
						   UNF_DISC_GET_NODE_NAME);
	}

	xchg->cmnd_code = NS_GNN_ID;  /* GNN_ID */
	xchg->disc_port_id = v_nport_id;

	ox_id = xchg->ox_id;

	/* Set callback function */
	xchg->pfn_ob_callback = unf_gnn_id_ob_callback;  /* send GFF_ID */
	xchg->pfn_callback = unf_gnn_id_callback; /* send GFF_ID */

	unf_fill_package(&pkg, xchg, v_sns_port);

	/* Fill GNN_ID entry(payload) */
	gnn_id_pld = &fc_entry->gnn_id; /* GNNID payload */
	memset(gnn_id_pld, 0, sizeof(struct unf_gnnid_s));
	unf_fill_gnn_id_pld(gnn_id_pld, v_nport_id);

	/* Start to send GNN_ID GS command */
	ret = unf_gs_cmnd_send(v_lport, &pkg, xchg);
	if (ret != RETURN_OK)
		unf_cm_free_xchg((void *)v_lport, (void *)xchg);
	else
		atomic_dec(
			&root_lport->disc.disc_thread_info.disc_contrl_size);

	UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT, UNF_MAJOR,
		  "[info]LOGIN: GNN_ID send %s. Port(0x%x_0x%x)--->rport(0x%x) inquire Nportid(0x%x) OX_ID(0x%x)",
		  (ret != RETURN_OK) ? "failed" : "succeed", v_lport->port_id,
		  v_lport->nport_id, v_sns_port->nport_id,
		  v_nport_id, ox_id);

	UNF_REFERNCE_VAR(ox_id);
	return ret;
}

static void unf_fill_gpn_id_pld(struct unf_gpnid_s *v_gpn_id_pld,
				unsigned int v_nport_id)
{
	UNF_CHECK_VALID(0x3371, UNF_TRUE, v_gpn_id_pld, return);

	v_gpn_id_pld->ctiu_pream.rev_inid = UNF_REV_NPORTID_INIT;
	v_gpn_id_pld->ctiu_pream.gstype_gssub_options = UNF_FSTYPE_OPT_INIT;
	v_gpn_id_pld->ctiu_pream.cmnd_rsp_size = UNF_FSTYPE_GPN_ID;
	v_gpn_id_pld->ctiu_pream.frag_reason_exp_vend = UNF_FRAG_REASON_VENDOR;

	/* Inquiry WWN from SW */
	v_gpn_id_pld->nport_id = v_nport_id;
}

unsigned int unf_rport_relogin(struct unf_lport_s *v_lport,
			       unsigned int v_nport_id)
{
	/* Send GNN_ID */
	struct unf_rport_s *sns_port = NULL;
	unsigned int ret = RETURN_OK;

	UNF_CHECK_VALID(0x3563, UNF_TRUE, v_lport, return UNF_RETURN_ERROR);

	/* Get SNS R_Port */
	sns_port = unf_get_rport_by_nport_id(v_lport, UNF_FC_FID_DIR_SERV);
	if (!sns_port) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT, UNF_WARN,
			  "[warn]Port(0x%x) can't find fabric Port",
			  v_lport->nport_id);

		return UNF_RETURN_ERROR;
	}

	/* Send GNN_ID now to SW */
	ret = unf_get_and_post_disc_event(v_lport, sns_port, v_nport_id,
					  UNF_DISC_GET_NODE_NAME);
	if (ret != RETURN_OK) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_LOGIN_ATT, UNF_ERR,
			  "[err]Port(0x%x) add discovery event(0x%x) failed Rport(0x%x)",
			  v_lport->nport_id, UNF_DISC_GET_NODE_NAME,
			  v_nport_id);

		/* NOTE: Continue to next stage */
		unf_rcv_gnn_id_rsp_unknown(v_lport, sns_port, v_nport_id);
	}

	return ret;
}

static void unf_rcv_gpn_id_acc(struct unf_lport_s *v_lport,
			       unsigned int v_nport_id,
			       unsigned long long v_port_name)
{
	/* then PLOGI or re-login */
	struct unf_lport_s *lport = v_lport;
	struct unf_rport_s *rport = NULL;
	unsigned long flag = 0;
	unsigned int ret = UNF_RETURN_ERROR;

	rport = unf_find_valid_rport(lport, v_port_name, v_nport_id);
	if (rport) {
		/* R_Port with TGT mode & L_Port with INI mode:
		 * send PLOGI with INIT state
		 */
		if ((rport->options & UNF_PORT_MODE_TGT) ==
		    UNF_PORT_MODE_TGT) {
			rport = unf_get_safe_rport(v_lport, rport,
						   UNF_RPORT_REUSE_INIT,
						   v_nport_id);
			UNF_CHECK_VALID(0x3630, UNF_TRUE, rport, return);

			/* Update R_Port state: PLOGI_WAIT */
			spin_lock_irqsave(&rport->rport_state_lock, flag);
			rport->nport_id = v_nport_id;
			unf_rport_state_ma(rport, UNF_EVENT_RPORT_ENTER_PLOGI);
			spin_unlock_irqrestore(&rport->rport_state_lock, flag);

			/* Start to send PLOGI */
			ret = unf_send_plogi(lport, rport);
			if (ret != RETURN_OK) {
				UNF_TRACE(UNF_EVTLOG_DRIVER_WARN,
					  UNF_LOG_LOGIN_ATT, UNF_WARN,
					  "[warn]LOGIN: Port(0x%x_0x%x) send PLOGI failed for 0x%x, enter recovry",
					  lport->port_id, lport->nport_id,
					  v_nport_id);

				unf_rport_error_recovery(rport);
			}
		} else {
			spin_lock_irqsave(&rport->rport_state_lock, flag);
			if ((rport->rp_state != UNF_RPORT_ST_PLOGI_WAIT) &&
			    (rport->rp_state != UNF_RPORT_ST_PRLI_WAIT) &&
			    (rport->rp_state != UNF_RPORT_ST_READY)) {
				unf_rport_state_ma(rport,
						   UNF_EVENT_RPORT_LOGO);
				spin_unlock_irqrestore(
					&rport->rport_state_lock, flag);

				/* Do LOGO operation */
				unf_rport_enter_logo(lport, rport);
			} else {
				spin_unlock_irqrestore(
					&rport->rport_state_lock, flag);
			}
		}
	} else {
		/* Send GNN_ID */
		(void)unf_rport_relogin(lport, v_nport_id);
	}
}

static void unf_rcv_gpn_id_rjt(struct unf_lport_s *v_lport,
			       unsigned int v_nport_id)
{
	struct unf_lport_s *lport = v_lport;
	struct unf_rport_s *rport = NULL;

	UNF_CHECK_VALID(0x3631, UNF_TRUE, v_lport, return);

	rport = unf_get_rport_by_nport_id(lport, v_nport_id);
	if (rport)
		unf_rport_linkdown(lport, rport); /* Do R_Port Link down */
}

/*
 * Function Name       : unf_rcv_gpn_id_rsp_unknown
 * Function Description: Process unknown type of GPN_ID response
 * Input Parameters    : struct unf_lport_s *v_lport
 *                     : unsigned int v_nport_id
 * Output Parameters   : N/A
 * Return Type         : void
 */
void unf_rcv_gpn_id_rsp_unknown(struct unf_lport_s *v_lport,
				unsigned int v_nport_id)
{
	struct unf_lport_s *lport = v_lport;

	UNF_CHECK_VALID(0x3632, UNF_TRUE, v_lport, return);

	UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT, UNF_WARN,
		  "[warn]LOGIN: Port(0x%x) wrong response of GPN_ID with RPort(0x%x)",
		  lport->port_id, v_nport_id);

	/* NOTE: go to next stage */
	(void)unf_rport_relogin(lport, v_nport_id);
}

static void unf_gpn_id_callback(void *v_lport, void *v_sns_port, void *v_xchg)
{
	struct unf_lport_s *lport = NULL;
	struct unf_xchg_s *xchg = NULL;
	struct unf_gpnid_rsp_s *gpn_id_rsp_pld = NULL;
	unsigned long long port_name = 0;
	unsigned int cmnd_rsp_size = 0;
	unsigned int nport_id = 0;
	struct unf_lport_s *root_lport = NULL;

	UNF_CHECK_VALID(0x3635, UNF_TRUE, v_lport, return);
	UNF_CHECK_VALID(0x3636, UNF_TRUE, v_sns_port, return);
	UNF_CHECK_VALID(0x3637, UNF_TRUE, v_xchg, return);

	UNF_REFERNCE_VAR(v_sns_port);

	lport = (struct unf_lport_s *)v_lport;
	xchg = (struct unf_xchg_s *)v_xchg;
	nport_id = xchg->disc_port_id;

	root_lport = (struct unf_lport_s *)lport->root_lport;
	atomic_inc(&root_lport->disc.disc_thread_info.disc_contrl_size);
	wake_up_process(root_lport->disc.disc_thread_info.data_thread);

	gpn_id_rsp_pld =
		&xchg->fcp_sfs_union.sfs_entry.fc_sfs_entry_ptr->gpn_id_rsp;
	cmnd_rsp_size = gpn_id_rsp_pld->ctiu_pream.cmnd_rsp_size;
	if ((cmnd_rsp_size & UNF_CT_IU_RSP_MASK) == UNF_CT_IU_ACCEPT) {
		/* GPN_ID ACC */
		port_name = ((unsigned long long)
				(gpn_id_rsp_pld->port_name[0]) << 32) |
			    ((unsigned long long)
				(gpn_id_rsp_pld->port_name[1]));

		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT,
			  UNF_MAJOR,
			  "[info]LOGIN: Port(0x%x) GPN_ID ACC with WWN(0x%llx) RPort NPort ID(0x%x)",
			  lport->port_id, port_name, nport_id);

		/* Send PLOGI or LOGO or GNN_ID */
		unf_rcv_gpn_id_acc(lport, nport_id, port_name);
	} else if ((cmnd_rsp_size & UNF_CT_IU_RSP_MASK) ==
		   UNF_CT_IU_REJECT) {
		/* GPN_ID RJT: Link Down */
		unf_rcv_gpn_id_rjt(lport, nport_id);
	} else {
		/* GPN_ID response type unknown: Send GNN_ID */
		unf_rcv_gpn_id_rsp_unknown(lport, nport_id);
	}
}

static void unf_gpn_id_ob_callback(struct unf_xchg_s *v_xchg)
{
	struct unf_lport_s *lport = NULL;
	unsigned int nport_id = 0;
	struct unf_lport_s *root_lport = NULL;

	UNF_CHECK_VALID(0x3633, UNF_TRUE, v_xchg, return);

	lport = v_xchg->lport;
	nport_id = v_xchg->disc_port_id;
	UNF_CHECK_VALID(0x3634, UNF_TRUE, lport, return);

	root_lport = (struct unf_lport_s *)lport->root_lport;
	atomic_inc(&root_lport->disc.disc_thread_info.disc_contrl_size);
	wake_up_process(root_lport->disc.disc_thread_info.data_thread);

	UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT, UNF_WARN,
		  "[warn]LOGIN: Port(0x%x) send GPN_ID failed to inquire RPort(0x%x)",
		  lport->port_id, nport_id);

	/* NOTE: go to next stage */
	(void)unf_rport_relogin(lport, nport_id);
}

unsigned int unf_send_gpn_id(struct unf_lport_s *v_lport,
			     struct unf_rport_s *v_sns_port,
			     unsigned int v_nport_id)
{
	struct unf_gpnid_s *gpn_id_pld = NULL;
	union unf_sfs_u *fc_entry = NULL;
	struct unf_xchg_s *xchg = NULL;
	unsigned int ret = UNF_RETURN_ERROR;
	unsigned short ox_id = 0;
	struct unf_frame_pkg_s pkg;
	struct unf_lport_s *root_lport = NULL;

	UNF_CHECK_VALID(0x3374, UNF_TRUE, v_sns_port, return UNF_RETURN_ERROR);

	if (unf_is_lport_valid(v_lport) != RETURN_OK) {
		/* Lport is invalid, no retry or handle required, return ok */
		return RETURN_OK;
	}
	root_lport = (struct unf_lport_s *)v_lport->root_lport;

	memset(&pkg, 0, sizeof(struct unf_frame_pkg_s));

	xchg = unf_get_sfs_free_xchg_and_init(v_lport, v_sns_port->nport_id,
					      v_sns_port, &fc_entry);
	if (!xchg) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_LOGIN_ATT, UNF_ERR,
			  "[err]Port(0x%x) exchange can't be NULL for GPN_ID",
			  v_lport->port_id);

		return unf_get_and_post_disc_event(v_lport, v_sns_port,
						   v_nport_id,
						   UNF_DISC_GET_PORT_NAME);
	}

	xchg->cmnd_code = NS_GPN_ID;  // GPN_ID
	xchg->disc_port_id = v_nport_id;

	ox_id = xchg->ox_id;

	/* Set callback function */
	xchg->pfn_callback = unf_gpn_id_callback;
	/* re-login --->>> GNN_ID */
	xchg->pfn_ob_callback = unf_gpn_id_ob_callback;

	unf_fill_package(&pkg, xchg, v_sns_port);

	/* Fill GPN_ID entry(payload) */
	gpn_id_pld = &fc_entry->gpn_id; /* GPN_ID payload */
	memset(gpn_id_pld, 0, sizeof(struct unf_gpnid_s));
	unf_fill_gpn_id_pld(gpn_id_pld, v_nport_id);

	/* Send GPN_ID GS command */
	ret = unf_gs_cmnd_send(v_lport, &pkg, xchg);
	if (ret != RETURN_OK)
		unf_cm_free_xchg((void *)v_lport, (void *)xchg);
	else
		atomic_dec(
			&root_lport->disc.disc_thread_info.disc_contrl_size);

	UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT, UNF_MAJOR,
		  "[info]LOGIN: GPN_ID send %s. Port(0x%x)--->rport(0x%x). Inquire RPort(0x%x) with OX_ID(0x%x)",
		  (ret != RETURN_OK) ? "failed" : "succeed", v_lport->port_id,
		  v_sns_port->nport_id, v_nport_id, ox_id);

	UNF_REFERNCE_VAR(ox_id);
	return ret;
}

static void unf_fill_gid_ft_pld(struct unf_gid_s *v_gid_pld)
{
	UNF_CHECK_VALID(0x3376, UNF_TRUE, v_gid_pld, return);

	v_gid_pld->ctiu_pream.rev_inid = UNF_REV_NPORTID_INIT;
	v_gid_pld->ctiu_pream.gstype_gssub_options = UNF_FSTYPE_OPT_INIT;
	v_gid_pld->ctiu_pream.cmnd_rsp_size = UNF_FSTYPE_GID_FT;
	v_gid_pld->ctiu_pream.frag_reason_exp_vend = UNF_FRAG_REASON_VENDOR;

	v_gid_pld->scope_type = UNF_GID_FT_TYPE;
}

static void unf_gid_ft_ob_callback(struct unf_xchg_s *v_xchg)
{
	/* Do recovery */
	struct unf_lport_s *lport = NULL;
	union unf_sfs_u *sfs_ptr = NULL;
	struct unf_disc_s *disc = NULL;
	unsigned long flag = 0;

	UNF_CHECK_VALID(0x3589, UNF_TRUE, v_xchg, return);

	sfs_ptr = v_xchg->fcp_sfs_union.sfs_entry.fc_sfs_entry_ptr;
	if (!sfs_ptr)
		return;

	spin_lock_irqsave(&v_xchg->xchg_state_lock, flag);
	lport = v_xchg->lport;
	spin_unlock_irqrestore(&v_xchg->xchg_state_lock, flag);
	if (!lport)
		return;

	disc = &lport->disc;
	spin_lock_irqsave(&disc->rport_busy_pool_lock, flag);
	unf_disc_state_ma(lport, UNF_EVENT_DISC_FAILED);
	spin_unlock_irqrestore(&disc->rport_busy_pool_lock, flag);

	/* Do DISC recovery operation */
	unf_disc_error_recovery(lport);
}

unsigned int unf_send_gid_ft(struct unf_lport_s *v_lport,
			     struct unf_rport_s *v_rport)
{
	struct unf_gid_s *gid_pld = NULL;
	struct unf_gid_rsp_s *gid_rsp = NULL;
	struct unf_gif_acc_pld_s *gid_acc_pld = NULL;
	union unf_sfs_u *fc_entry = NULL;
	struct unf_xchg_s *xchg = NULL;
	unsigned int ret = UNF_RETURN_ERROR;
	struct unf_frame_pkg_s pkg = { 0 };
	unsigned short ox_id = 0;

	UNF_REFERNCE_VAR(ox_id);
	UNF_CHECK_VALID(0x3377, UNF_TRUE, v_lport, return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(0x3378, UNF_TRUE, v_rport, return UNF_RETURN_ERROR);

	xchg = unf_get_sfs_free_xchg_and_init(v_lport, v_rport->nport_id,
					      v_rport, &fc_entry);
	if (!xchg) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_LOGIN_ATT, UNF_ERR,
			  "[err]Port(0x%x) exchange can't be NULL for GID_FT",
			  v_lport->port_id);

		return ret;
	}

	xchg->cmnd_code = NS_GID_FT;  // GID_FT

	ox_id = xchg->ox_id;

	/* Set callback function */
	xchg->pfn_ob_callback = unf_gid_ft_ob_callback;  // do DISC recovery
	xchg->pfn_callback = unf_gid_ft_callback;

	unf_fill_package(&pkg, xchg, v_rport);

	/* Fill GID_FT entry(payload) */
	gid_pld = &fc_entry->get_id.gid_req; /* GID req payload */
	unf_fill_gid_ft_pld(gid_pld);
	gid_rsp = &fc_entry->get_id.gid_rsp; /* GID rsp payload */

	/* Get GID_FT Response payload */
	gid_acc_pld = (struct unf_gif_acc_pld_s *)unf_get_one_big_sfs_buf(xchg);
	if (!gid_acc_pld) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT, UNF_WARN,
			  "[warn]Port(0x%x) allocate GID_FT response buffer failed",
			  v_lport->port_id);

		unf_cm_free_xchg(v_lport, xchg);
		return UNF_RETURN_ERROR;
	}
	memset(gid_acc_pld, 0, sizeof(struct unf_gif_acc_pld_s));
	gid_rsp->gid_acc_pld = gid_acc_pld;

	/* Send GID_FT GS commmand now */
	ret = unf_gs_cmnd_send(v_lport, &pkg, xchg);
	if (ret != RETURN_OK)
		unf_cm_free_xchg((void *)v_lport, (void *)xchg);

	UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT, UNF_MAJOR,
		  "[info]LOGIN: GID_FT send %s. Port(0x%x)--->rport(0x%x) with OX_ID(0x%x)",
		  (ret != RETURN_OK) ? "failed" : "succeed",
		  v_lport->port_id, v_rport->nport_id, ox_id);

	UNF_REFERNCE_VAR(ox_id);
	return ret;
}

static void unf_fill_gid_pt_pld(struct unf_gid_s *v_gid_pld,
				struct unf_lport_s *v_lport)
{
	UNF_CHECK_VALID(0x3379, UNF_TRUE, v_gid_pld, return);
	UNF_CHECK_VALID(0x3380, UNF_TRUE, v_lport, return);

	v_gid_pld->ctiu_pream.rev_inid = (UNF_REV_NPORTID_INIT);
	v_gid_pld->ctiu_pream.gstype_gssub_options = (UNF_FSTYPE_OPT_INIT);
	v_gid_pld->ctiu_pream.cmnd_rsp_size = (UNF_FSTYPE_GID_PT);
	v_gid_pld->ctiu_pream.frag_reason_exp_vend = UNF_FRAG_REASON_VENDOR;

	/* 0x7F000000 means NX_Port */
	v_gid_pld->scope_type = UNF_GID_PT_TYPE;
	UNF_PRINT_SFS_LIMIT(UNF_INFO, v_lport->port_id, v_gid_pld,
			    sizeof(struct unf_gid_s));
}

static void unf_gid_pt_ob_callback(struct unf_xchg_s *v_xchg)
{
	/* Do recovery */
	struct unf_lport_s *lport = NULL;
	union unf_sfs_u *sfs_ptr = NULL;
	struct unf_disc_s *disc = NULL;
	unsigned long flag = 0;

	UNF_CHECK_VALID(0x3593, UNF_TRUE, v_xchg, return);

	sfs_ptr = v_xchg->fcp_sfs_union.sfs_entry.fc_sfs_entry_ptr;
	if (!sfs_ptr)
		return;

	spin_lock_irqsave(&v_xchg->xchg_state_lock, flag);
	lport = v_xchg->lport;
	spin_unlock_irqrestore(&v_xchg->xchg_state_lock, flag);
	if (!lport)
		return;

	disc = &lport->disc;
	spin_lock_irqsave(&disc->rport_busy_pool_lock, flag);
	unf_disc_state_ma(lport, UNF_EVENT_DISC_FAILED);
	spin_unlock_irqrestore(&disc->rport_busy_pool_lock, flag);

	/* Do DISC recovery operation */
	unf_disc_error_recovery(lport);
}

unsigned int unf_send_gid_pt(struct unf_lport_s *v_lport,
			     struct unf_rport_s *v_rport)
{
	/* from DISC start */
	struct unf_gid_s *gid_pld = NULL;
	struct unf_gid_rsp_s *gid_rsp = NULL;
	struct unf_gif_acc_pld_s *gid_acc_pld = NULL;
	union unf_sfs_u *fc_entry = NULL;
	struct unf_xchg_s *xchg = NULL;
	unsigned int ret = UNF_RETURN_ERROR;
	struct unf_frame_pkg_s pkg = { 0 };
	unsigned short ox_id = 0;

	UNF_REFERNCE_VAR(ox_id);
	UNF_CHECK_VALID(0x3381, UNF_TRUE, v_lport, return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(0x3382, UNF_TRUE, v_rport, return UNF_RETURN_ERROR);

	xchg = unf_get_sfs_free_xchg_and_init(v_lport, v_rport->nport_id,
					      v_rport, &fc_entry);
	if (!xchg) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_LOGIN_ATT, UNF_ERR,
			  "[err]Port(0x%x) exchange can't be NULL for GID_PT",
			  v_lport->port_id);

		return ret;
	}

	xchg->cmnd_code = NS_GID_PT;  /* GID_PT */
	ox_id = xchg->ox_id;

	/* Set callback function */
	xchg->pfn_ob_callback = unf_gid_pt_ob_callback; /* do DISC recovery */
	xchg->pfn_callback = unf_gid_pt_callback;

	unf_fill_package(&pkg, xchg, v_rport);

	/* Fill GID_PT entry(payload) */
	gid_pld = &fc_entry->get_id.gid_req; /* GID req payload */
	unf_fill_gid_pt_pld(gid_pld, v_lport);
	gid_rsp = &fc_entry->get_id.gid_rsp; /* GID rsp payload */

	/* Get GID_PT response payload */
	gid_acc_pld = (struct unf_gif_acc_pld_s *)unf_get_one_big_sfs_buf(xchg);
	if (!gid_acc_pld) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT, UNF_WARN,
			  "[warn]Port(0x%0x) Allocate GID_PT response buffer failed",
			  v_lport->port_id);

		unf_cm_free_xchg(v_lport, xchg);
		return UNF_RETURN_ERROR;
	}
	memset(gid_acc_pld, 0, sizeof(struct unf_gif_acc_pld_s));
	gid_rsp->gid_acc_pld = gid_acc_pld;

	/* Send GID_PT GS command to SW */
	ret = unf_gs_cmnd_send(v_lport, &pkg, xchg);
	if (ret != RETURN_OK)
		unf_cm_free_xchg((void *)v_lport, (void *)xchg);

	UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT, UNF_MAJOR,
		  "[info]LOGIN: GID_PT send %s. Port(0x%x_0x%x)--->rport(0x%x) with OXID(0x%x)",
		  (ret != RETURN_OK) ? "failed" : "succeed",
		  v_lport->port_id, v_lport->nport_id,
		  v_rport->nport_id, ox_id);

	UNF_REFERNCE_VAR(ox_id);
	return ret;
}

static void unf_fill_rft_id_pld(struct unf_rftid_s *v_rft_id_pld,
				struct unf_lport_s *v_lport)
{
	unsigned int i = 1;

	UNF_CHECK_VALID(0x3383, UNF_TRUE, v_rft_id_pld, return);
	UNF_CHECK_VALID(0x3384, UNF_TRUE, v_lport, return);

	v_rft_id_pld->ctiu_pream.rev_inid = UNF_REV_NPORTID_INIT;
	v_rft_id_pld->ctiu_pream.gstype_gssub_options = UNF_FSTYPE_OPT_INIT;
	v_rft_id_pld->ctiu_pream.cmnd_rsp_size = UNF_FSTYPE_RFT_ID;
	v_rft_id_pld->ctiu_pream.frag_reason_exp_vend = UNF_FRAG_REASON_VENDOR;
	v_rft_id_pld->nport_id = (v_lport->nport_id);
	v_rft_id_pld->fc_4_types[0] = (UNF_FC4_SCSI_BIT8);

	for (i = 1; i < 8; i++)
		v_rft_id_pld->fc_4_types[i] = 0;
}

static void unf_rft_id_ob_callback(struct unf_xchg_s *v_xchg)
{
	/* Do recovery */
	struct unf_lport_s *lport = NULL;
	unsigned long flag = 0;

	UNF_CHECK_VALID(0x3687, UNF_TRUE, v_xchg, return);

	spin_lock_irqsave(&v_xchg->xchg_state_lock, flag);
	lport = v_xchg->lport;
	spin_unlock_irqrestore(&v_xchg->xchg_state_lock, flag);

	UNF_CHECK_VALID(0x3688, UNF_TRUE, lport, return);

	UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT, UNF_WARN,
		  "[warn]LOGIN: Port(0x%x_0x%x) send RFT_ID failed",
		  lport->port_id, lport->nport_id);

	/* Do L_Port recovery operation */
	unf_lport_error_recovery(lport);
}

static void unf_rft_id_callback(void *v_lport, void *v_rport, void *v_xchg)
{
	/* RFT_ID --->>> RFF_ID */
	struct unf_lport_s *lport = NULL;
	struct unf_rport_s *rport = NULL;
	struct unf_xchg_s *xchg = NULL;
	struct unf_ctiu_prem_s *ctiu_prem = NULL;
	unsigned int ret = UNF_RETURN_ERROR;
	unsigned int cmnd_rsp_size = 0;
	unsigned long flag = 0;

	UNF_CHECK_VALID(0x3689, UNF_TRUE, v_lport, return);
	UNF_CHECK_VALID(0x3690, UNF_TRUE, v_rport, return);
	UNF_CHECK_VALID(0x3691, UNF_TRUE, v_xchg, return);

	lport = (struct unf_lport_s *)v_lport;
	rport = (struct unf_rport_s *)v_rport;
	xchg = (struct unf_xchg_s *)v_xchg;

	if (!xchg->fcp_sfs_union.sfs_entry.fc_sfs_entry_ptr) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_LOGIN_ATT, UNF_ERR,
			  "[err]Port(0x%x) SFS entry is NULL with state(0x%x)",
			  lport->port_id, lport->en_states);
		return;
	}

	ctiu_prem = &xchg->fcp_sfs_union.sfs_entry.fc_sfs_entry_ptr->rft_id_rsp.ctiu_pream;
	cmnd_rsp_size = ctiu_prem->cmnd_rsp_size;

	UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT, UNF_MAJOR,
		  "[info]LOGIN: Port(0x%x_0x%x) RFT_ID response is (0x%x)",
		  (cmnd_rsp_size & UNF_CT_IU_RSP_MASK),
		  lport->port_id, lport->nport_id);

	if ((cmnd_rsp_size & UNF_CT_IU_RSP_MASK) == UNF_CT_IU_ACCEPT) {
		/* Case for RFT_ID ACC: send RFF_ID */
		spin_lock_irqsave(&lport->lport_state_lock, flag);
		if (lport->en_states != UNF_LPORT_ST_RFT_ID_WAIT) {
			spin_unlock_irqrestore(&lport->lport_state_lock, flag);

			UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT,
				  UNF_MAJOR,
				  "[info]Port(0x%x_0x%x) receive RFT_ID ACC in state(0x%x)",
				  lport->port_id, lport->nport_id,
				  lport->en_states);

			return;
		}

		/* LPort: RFT_ID_WAIT --> RFF_ID_WAIT */
		unf_lport_stat_ma(lport, UNF_EVENT_LPORT_REMOTE_ACC);
		spin_unlock_irqrestore(&lport->lport_state_lock, flag);

		/* Start to send RFF_ID GS command */
		ret = unf_send_rff_id(lport, rport);
		if (ret != RETURN_OK) {
			UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT,
				  UNF_WARN,
				  "[warn]LOGIN: Port(0x%x_0x%x) send RFF_ID failed",
				  lport->port_id, lport->nport_id);

			/* Do L_Port recovery */
			unf_lport_error_recovery(lport);
		}
	} else {
		/* Case for RFT_ID RJT: do recovery */
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT, UNF_WARN,
			  "[warn]LOGIN: Port(0x%x_0x%x) receive RFT_ID RJT with reason_code(0x%x) explanation(0x%x)",
			  lport->port_id, lport->nport_id,
			  (ctiu_prem->frag_reason_exp_vend) &
			  UNF_CT_IU_REASON_MASK,
			  (ctiu_prem->frag_reason_exp_vend) &
			  UNF_CT_IU_EXPLAN_MASK);

		/* Do L_Port recovery */
		unf_lport_error_recovery(lport);
	}
}

unsigned int unf_send_rft_id(struct unf_lport_s *v_lport,
			     struct unf_rport_s *v_rport)
{
	/* After PLOGI process */
	struct unf_rftid_s *rft_id = NULL;
	union unf_sfs_u *fc_entry = NULL;
	struct unf_xchg_s *xchg = NULL;
	unsigned int ret = UNF_RETURN_ERROR;
	unsigned short ox_id = 0;
	struct unf_frame_pkg_s pkg;

	UNF_REFERNCE_VAR(ox_id);
	UNF_CHECK_VALID(0x3385, UNF_TRUE, v_lport, return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(0x3386, UNF_TRUE, v_rport, return UNF_RETURN_ERROR);

	memset(&pkg, 0, sizeof(struct unf_frame_pkg_s));

	xchg = unf_get_sfs_free_xchg_and_init(v_lport, v_rport->nport_id,
					      v_rport, &fc_entry);
	if (!xchg) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_LOGIN_ATT, UNF_ERR,
			  "[err]Port(0x%x) exchange can't be NULL for RFT_ID",
			  v_lport->port_id);

		return ret;
	}

	xchg->cmnd_code = NS_RFT_ID;  /* RFT_ID */

	ox_id = xchg->ox_id;

	/* Set callback function */
	xchg->pfn_callback = unf_rft_id_callback;
	xchg->pfn_ob_callback = unf_rft_id_ob_callback; /* Do L_Port recovery */

	unf_fill_package(&pkg, xchg, v_rport);

	/* Fill RFT_ID entry(payload) */
	rft_id = &fc_entry->rft_id;
	memset(rft_id, 0, sizeof(struct unf_rftid_s));
	unf_fill_rft_id_pld(rft_id, v_lport);

	/* Send RFT_ID GS command */
	ret = unf_gs_cmnd_send(v_lport, &pkg, xchg);
	if (ret != RETURN_OK)
		unf_cm_free_xchg((void *)v_lport, (void *)xchg);

	UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT, UNF_MAJOR,
		  "[info]LOGIN: RFT_ID send %s. Port(0x%x_0x%x)--->rport(0x%x). rport(0x%p) wwpn(0x%llx) OX_ID(0x%x)",
		  (ret != RETURN_OK) ? "failed" : "succeed",
		  v_lport->port_id, v_lport->nport_id, v_rport->nport_id,
		  v_rport, v_rport->port_name, ox_id);

	UNF_REFERNCE_VAR(ox_id);
	return ret;
}

static void unf_fill_rff_id_pld(struct unf_rffid_s *v_rff_id_pld,
				struct unf_lport_s *v_lport)
{
	UNF_CHECK_VALID(0x3387, UNF_TRUE, v_rff_id_pld, return);
	UNF_CHECK_VALID(0x3388, UNF_TRUE, v_lport, return);

	v_rff_id_pld->ctiu_pream.rev_inid = UNF_REV_NPORTID_INIT;
	v_rff_id_pld->ctiu_pream.gstype_gssub_options = UNF_FSTYPE_OPT_INIT;
	v_rff_id_pld->ctiu_pream.cmnd_rsp_size = UNF_FSTYPE_RFF_ID;
	v_rff_id_pld->ctiu_pream.frag_reason_exp_vend = UNF_FRAG_REASON_VENDOR;
	v_rff_id_pld->nport_id = v_lport->nport_id;
	v_rff_id_pld->fc_4_feature = UNF_FC4_FCP_TYPE |
				     (v_lport->options << 4);
}

static void unf_rff_id_callback(void *v_lport, void *v_rport, void *v_xchg)
{
	/* RFF_ID --->>> SCR(for INI mode) */
	struct unf_lport_s *lport = NULL;
	struct unf_rport_s *rport = NULL;
	struct unf_xchg_s *xchg = NULL;
	struct unf_ctiu_prem_s *ctiu_prem = NULL;
	unsigned int ret = UNF_RETURN_ERROR;
	unsigned int cmnd_rsp_size = 0;
	unsigned long flag = 0;

	UNF_CHECK_VALID(0x3684, UNF_TRUE, v_lport, return);
	UNF_CHECK_VALID(0x3685, UNF_TRUE, v_rport, return);
	UNF_CHECK_VALID(0x3686, UNF_TRUE, v_xchg, return);

	lport = (struct unf_lport_s *)v_lport;
	xchg = (struct unf_xchg_s *)v_xchg;
	if (unlikely(!xchg->fcp_sfs_union.sfs_entry.fc_sfs_entry_ptr))
		return;

	/* SCR send to 0xfffffd(not 0xfffffc), need to get new R_Port */
	UNF_REFERNCE_VAR(v_rport);
	rport = unf_get_rport_by_nport_id(lport, UNF_FC_FID_FCTRL); // 0xfffffd
	rport = unf_get_safe_rport(lport, rport, UNF_RPORT_REUSE_ONLY,
				   UNF_FC_FID_FCTRL);
	if (unlikely(!rport)) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT,
			  UNF_WARN,
			  "[warn]Port(0x%x) can't allocate RPort(0x%x)",
			  lport->port_id, UNF_FC_FID_FCTRL);
		return;
	}

	rport->nport_id = UNF_FC_FID_FCTRL;
	ctiu_prem =
		&xchg->fcp_sfs_union.sfs_entry.fc_sfs_entry_ptr->rff_id_rsp.ctiu_pream;
	cmnd_rsp_size = ctiu_prem->cmnd_rsp_size;

	UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT, UNF_INFO,
		  "[info]LOGIN: Port(0x%x_0x%x) RFF_ID rsp is (0x%x)",
		  lport->port_id, lport->nport_id,
		  (cmnd_rsp_size & UNF_CT_IU_RSP_MASK));

	/* RSP Type check: some SW not support RFF_ID, go to next stage also */
	if ((cmnd_rsp_size & UNF_CT_IU_RSP_MASK) == UNF_CT_IU_ACCEPT) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT,
			  UNF_MAJOR,
			  "[info]LOGIN: Port(0x%x_0x%x) receive RFF ACC(0x%x) in state(0x%x)",
			  lport->port_id, lport->nport_id,
			  (cmnd_rsp_size & UNF_CT_IU_RSP_MASK),
			  lport->en_states);
	} else {
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT, UNF_WARN,
			  "[warn]LOGIN: Port(0x%x_0x%x) receive RFF RJT(0x%x) in state(0x%x) with RJT reason code(0x%x) explanation(0x%x)",
			  lport->port_id, lport->nport_id,
			  (cmnd_rsp_size & UNF_CT_IU_RSP_MASK),
			  lport->en_states,
			  (ctiu_prem->frag_reason_exp_vend) &
			  UNF_CT_IU_REASON_MASK,
			  (ctiu_prem->frag_reason_exp_vend) &
			  UNF_CT_IU_EXPLAN_MASK);
	}

	/* L_Port state check */
	spin_lock_irqsave(&lport->lport_state_lock, flag);
	if (lport->en_states != UNF_LPORT_ST_RFF_ID_WAIT) {
		spin_unlock_irqrestore(&lport->lport_state_lock, flag);
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT, UNF_WARN,
			  "[warn]LOGIN: Port(0x%x_0x%x) receive RFF reply in state(0x%x)",
			  lport->port_id, lport->nport_id, lport->en_states);

		return;
	}

	/* Update L_Port state & Send SCR to remote port */
	/* LPort: RFF_ID_WAIT --> SCR_WAIT */
	unf_lport_stat_ma(lport, UNF_EVENT_LPORT_REMOTE_ACC);
	spin_unlock_irqrestore(&lport->lport_state_lock, flag);

	/* Start to send SCR command */
	ret = unf_send_scr(lport, rport);
	if (ret != RETURN_OK) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT, UNF_WARN,
			  "[warn]LOGIN: Port(0x%x_0x%x) send SCR failed",
			  lport->port_id, lport->nport_id);

		/* Do L_Port recovery */
		unf_lport_error_recovery(lport);
	}
}

static void unf_rff_id_ob_callback(struct unf_xchg_s *v_xchg)
{
	/* Do recovery */
	struct unf_lport_s *lport = NULL;
	unsigned long flag = 0;

	UNF_CHECK_VALID(0x3682, UNF_TRUE, v_xchg, return);

	spin_lock_irqsave(&v_xchg->xchg_state_lock, flag);
	lport = v_xchg->lport;
	spin_unlock_irqrestore(&v_xchg->xchg_state_lock, flag);

	UNF_CHECK_VALID(0x3683, UNF_TRUE, NULL != lport, return);

	UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT, UNF_WARN,
		  "[warn]LOGIN: Port(0x%x_0x%x) send RFF_ID failed",
		  lport->port_id, lport->nport_id);

	/* Do L_Port recovery */
	unf_lport_error_recovery(lport);
}

unsigned int unf_send_rff_id(struct unf_lport_s *v_lport,
			     struct unf_rport_s *v_rport)
{
	/* from RFT_ID, then Send SCR */
	struct unf_rffid_s *rff_id = NULL;
	union unf_sfs_u *fc_entry = NULL;
	struct unf_xchg_s *xchg = NULL;
	unsigned int ret = UNF_RETURN_ERROR;
	struct unf_frame_pkg_s pkg = { 0 };
	unsigned short ox_id = 0;

	UNF_REFERNCE_VAR(ox_id);
	UNF_CHECK_VALID(0x3389, UNF_TRUE, v_lport, return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(0x3390, UNF_TRUE, v_rport, return UNF_RETURN_ERROR);

	UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT, UNF_INFO,
		  "%s Enter", __func__);

	xchg = unf_get_sfs_free_xchg_and_init(v_lport, v_rport->nport_id,
					      v_rport, &fc_entry);
	if (!xchg) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_LOGIN_ATT, UNF_ERR,
			  "[err]Port(0x%x) exchange can't be NULL for RFF_ID",
			  v_lport->port_id);

		return ret;
	}

	xchg->cmnd_code = NS_RFF_ID;  // RFF_ID

	ox_id = xchg->ox_id;

	/* Set callback function */
	xchg->pfn_callback = unf_rff_id_callback;
	xchg->pfn_ob_callback = unf_rff_id_ob_callback; /* Do L_Port recovery */

	unf_fill_package(&pkg, xchg, v_rport);

	/* Fill RFF_ID entry(payload) */
	rff_id = &fc_entry->rff_id;
	memset(rff_id, 0, sizeof(struct unf_rffid_s));
	unf_fill_rff_id_pld(rff_id, v_lport);

	/* Send RFF_ID GS command */
	ret = unf_gs_cmnd_send(v_lport, &pkg, xchg);
	if (ret != RETURN_OK)
		unf_cm_free_xchg((void *)v_lport, (void *)xchg);

	UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT, UNF_MAJOR,
		  "[info]LOGIN: RFF_ID feature 0x%x(10:TGT,20:INI,30:COM) send %s. Port(0x%x_0x%x)--->pstRPortid(0x%x) rport(0x%p) OX_ID(0x%x)",
		  v_lport->options, (ret != RETURN_OK) ? "failed" : "succeed",
		  v_lport->port_id, v_lport->nport_id,
		  v_rport->nport_id, v_rport, ox_id);

	UNF_REFERNCE_VAR(ox_id);
	return ret;
}

static void unf_login_with_rport_in_n2n(struct unf_lport_s *v_lport,
					unsigned long long v_remote_port_name,
					unsigned long long v_remote_nort_name)
{
	/*
	 * Call by (P2P):
	 * 1. RCVD FLOGI ACC
	 * 2. Send FLOGI ACC succeed
	 **
	 * Compare WWN, larger is master, then send PLOGI
	 */
	struct unf_lport_s *lport = v_lport;
	struct unf_rport_s *rport = NULL;
	unsigned long lport_flag = 0;
	unsigned long rport_flag = 0;
	unsigned long long port_name = 0;
	unsigned long long node_name = 0;
	unsigned int ret = RETURN_OK;

	UNF_CHECK_VALID(0x3539, UNF_TRUE, v_lport, return);

	spin_lock_irqsave(&lport->lport_state_lock, lport_flag);
	/* LPort: FLOGI_WAIT --> READY */
	unf_lport_stat_ma(lport, UNF_EVENT_LPORT_READY);
	spin_unlock_irqrestore(&lport->lport_state_lock, lport_flag);

	port_name = v_remote_port_name;
	node_name = v_remote_nort_name;

	if (lport->port_name > port_name) {
		/* Master case: send PLOGI */
		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT, UNF_MAJOR,
			  "[info]Port(0x%x)'s WWN(0x%llx) is larger than rport(0x%llx), should be master",
			  lport->port_id, lport->port_name, port_name);

		/* Update N_Port_ID now: 0xEF */
		lport->nport_id = UNF_P2P_LOCAL_NPORT_ID;

		rport = unf_find_valid_rport(v_lport, port_name,
					     UNF_P2P_REMOTE_NPORT_ID);  // 0xD6
		rport = unf_get_safe_rport(v_lport, rport,
					   UNF_RPORT_REUSE_ONLY,
					   UNF_P2P_REMOTE_NPORT_ID);
		if (rport) {
			rport->node_name = node_name;
			rport->port_name = port_name;
			rport->nport_id = UNF_P2P_REMOTE_NPORT_ID; // 0xD6
			rport->local_nport_id = UNF_P2P_LOCAL_NPORT_ID;  // 0xEF

			spin_lock_irqsave(&rport->rport_state_lock,
					  rport_flag);
			if ((rport->rp_state == UNF_RPORT_ST_PLOGI_WAIT) ||
			    (rport->rp_state == UNF_RPORT_ST_PRLI_WAIT) ||
			    (rport->rp_state == UNF_RPORT_ST_READY)) {
				UNF_TRACE(UNF_EVTLOG_DRIVER_INFO,
					  UNF_LOG_LOGIN_ATT,
					  UNF_MAJOR,
					  "[info]LOGIN: Port(0x%x) Rport(0x%x) have sent PLOGI or PRLI with state(0x%x)",
					  lport->port_id, rport->nport_id,
					  rport->rp_state);

				spin_unlock_irqrestore(&rport->rport_state_lock,
						       rport_flag);
				return;
			}
			/* Update L_Port State: PLOGI_WAIT */
			unf_rport_state_ma(rport, UNF_EVENT_RPORT_ENTER_PLOGI);
			spin_unlock_irqrestore(&rport->rport_state_lock,
					       rport_flag);

			/* P2P with master: Start to Send PLOGI */
			ret = unf_send_plogi(lport, rport);
			if (ret != RETURN_OK) {
				UNF_TRACE(UNF_EVTLOG_DRIVER_WARN,
					  UNF_LOG_LOGIN_ATT,
					  UNF_WARN,
					  "[warn]LOGIN: Port(0x%x) with WWN(0x%llx) send PLOGI to(0x%llx) failed",
					  lport->port_id, lport->port_name,
					  port_name);

				unf_rport_error_recovery(rport);
			}
		} else {
			/* Get/Alloc R_Port failed */
			UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT,
				  UNF_WARN,
				  "[warn]Port(0x%x) with WWN(0x%llx) allocate RPort(ID:0x%x,WWPN:0x%llx) failed",
				  lport->port_id, lport->port_name,
				  UNF_P2P_REMOTE_NPORT_ID, port_name);
		}
	} else {
		/* Slave case: L_Port's Port Name is smaller than R_Port */
		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT,
			  UNF_MAJOR,
			  "[info]Port(0x%x) with WWN(0x%llx) is smaller than rport(0x%llx), do nothing",
			  lport->port_id, lport->port_name, port_name);
	}
}

static void unf_flogi_acc_ob_callback(struct unf_xchg_s *v_xchg)
{
	/* Callback for Sending FLOGI ACC succeed */
	struct unf_lport_s *lport = NULL;
	struct unf_rport_s *rport = NULL;
	unsigned long flags = 0;
	unsigned long long port_name = 0;
	unsigned long long node_name = 0;

	UNF_CHECK_VALID(0x3457, UNF_TRUE, v_xchg, return);
	UNF_CHECK_VALID(0x3458, UNF_TRUE, v_xchg->lport, return);
	UNF_CHECK_VALID(0x3459, UNF_TRUE, v_xchg->rport, return);

	spin_lock_irqsave(&v_xchg->xchg_state_lock, flags);
	lport = v_xchg->lport;
	rport = v_xchg->rport;
	spin_unlock_irqrestore(&v_xchg->xchg_state_lock, flags);

	spin_lock_irqsave(&rport->rport_state_lock, flags);
	port_name = rport->port_name;
	node_name = rport->node_name;

	/* Swap case: Set WWPN & WWNN with zero */
	rport->port_name = 0;
	rport->node_name = 0;
	spin_unlock_irqrestore(&rport->rport_state_lock, flags);

	/* Enter PLOGI stage: after send FLOGI ACC succeed */
	unf_login_with_rport_in_n2n(lport, port_name, node_name);
}

unsigned int unf_send_flogi_acc(struct unf_lport_s *v_lport,
				struct unf_rport_s *v_rport,
				struct unf_xchg_s *v_xchg)
{
	struct unf_flogi_payload_s *flogi_acc_pld = NULL;
	union unf_sfs_u *fc_entry = NULL;
	unsigned int ret = UNF_RETURN_ERROR;
	struct unf_frame_pkg_s pkg = { 0 };
	unsigned short ox_id = 0;
	unsigned short rx_id = 0;

	UNF_REFERNCE_VAR(ox_id);
	UNF_REFERNCE_VAR(rx_id);
	UNF_CHECK_VALID(0x3393, UNF_TRUE, v_lport, return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(0x3394, UNF_TRUE, v_rport, return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(0x3395, UNF_TRUE, v_xchg, return UNF_RETURN_ERROR);

	v_xchg->cmnd_code = UNF_SET_ELS_ACC_TYPE(ELS_FLOGI);

	v_xchg->did = 0; /* D_ID must be 0 */
	v_xchg->sid = UNF_FC_FID_FLOGI; /* S_ID must be 0xfffffe */
	v_xchg->oid = v_xchg->sid;
	v_xchg->pfn_callback = NULL;
	v_xchg->lport = v_lport;
	v_xchg->rport = v_rport;
	/* call back for sending FLOGI response */
	v_xchg->pfn_ob_callback = unf_flogi_acc_ob_callback;
	fc_entry = v_xchg->fcp_sfs_union.sfs_entry.fc_sfs_entry_ptr;
	if (!fc_entry) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_REG_ATT, UNF_WARN,
			  "[warn]Port(0x%x) entry can't be NULL with tag(0x%x)",
			  v_lport->port_id, v_xchg->hot_pool_tag);

		unf_cm_free_xchg(v_lport, v_xchg);
		return UNF_RETURN_ERROR;
	}

	unf_fill_package(&pkg, v_xchg, v_rport);

	/* Fill FLOGI ACC payload */
	memset(fc_entry, 0, sizeof(union unf_sfs_u));
	flogi_acc_pld = &fc_entry->flogi_acc.flogi_payload;
	flogi_acc_pld->cmnd = (UNF_ELS_CMND_ACC);
	unf_fill_flogi_pld(flogi_acc_pld, v_lport);
	ox_id = v_xchg->ox_id;
	rx_id = v_xchg->rx_id;

	/* Send FLOGI ACC to remote port */
	ret = unf_els_cmnd_send(v_lport, &pkg, v_xchg);
	if (ret != RETURN_OK)
		unf_cm_free_xchg((void *)v_lport, (void *)v_xchg);

	UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_REG_ATT, UNF_MAJOR,
		  "[info]LOGIN: FLOGI ACC send %s. Port(0x%x)--->rport(0x%x) with OX_ID(0x%x) RX_ID(0x%x)",
		  (ret != RETURN_OK) ? "failed" : "succeed",
		  v_lport->port_id, v_rport->nport_id, ox_id, rx_id);

	UNF_REFERNCE_VAR(ox_id);
	UNF_REFERNCE_VAR(rx_id);
	return ret;
}

static void unf_fill_plogi_acc_pld(struct unf_plogi_payload_s *v_plogi_acc_pld,
				   struct unf_lport_s *v_lport)
{
	struct unf_lgn_parms_s *login_parms = NULL;

	UNF_CHECK_VALID(0x3396, UNF_TRUE, v_plogi_acc_pld, return);
	UNF_CHECK_VALID(0x3397, UNF_TRUE, v_lport, return);

	v_plogi_acc_pld->cmnd = (UNF_ELS_CMND_ACC);
	login_parms = &v_plogi_acc_pld->parms;

	if ((v_lport->en_act_topo == UNF_ACT_TOP_P2P_FABRIC) ||
	    (v_lport->en_act_topo == UNF_ACT_TOP_P2P_DIRECT)) {
		login_parms->co_parms.bb_credit =
			unf_low_level_bb_credit(v_lport);
		login_parms->co_parms.alternate_bb_credit_mgmt =
			UNF_BBCREDIT_MANAGE_NFPORT;  /* 0 */
		login_parms->co_parms.bb_scn =
			(v_lport->en_act_topo == UNF_ACT_TOP_P2P_FABRIC) ?
				0 : unf_low_level_bbscn(v_lport);
	} else {
		login_parms->co_parms.bb_credit = UNF_BBCREDIT_LPORT;
		login_parms->co_parms.alternate_bb_credit_mgmt =
			UNF_BBCREDIT_MANAGE_LPORT;  /* 1 */
	}

	login_parms->co_parms.lowest_version = UNF_PLOGI_VERSION_LOWER;
	login_parms->co_parms.highest_version = UNF_PLOGI_VERSION_UPPER;
	login_parms->co_parms.continuously_increasing =
		UNF_CONTIN_INCREASE_SUPPORT;
	login_parms->co_parms.bb_receive_data_field_size =
		v_lport->max_frame_size;
	login_parms->co_parms.nport_total_concurrent_sequences =
		UNF_PLOGI_CONCURRENT_SEQ;
	login_parms->co_parms.relative_offset = (UNF_PLOGI_RO_CATEGORY);
	login_parms->co_parms.e_d_tov = (v_lport->ed_tov);
	login_parms->cl_parms[2].valid = UNF_CLASS_VALID;  /* class-3 */
	login_parms->cl_parms[2].received_data_field_size =
		v_lport->max_frame_size;
	login_parms->cl_parms[2].concurrent_sequences =
		UNF_PLOGI_CONCURRENT_SEQ;
	login_parms->cl_parms[2].open_sequences_per_exchange =
		UNF_PLOGI_SEQ_PER_XCHG;
	login_parms->high_node_name =
		UNF_GET_NAME_HIGH_WORD(v_lport->node_name);
	login_parms->low_node_name =
		UNF_GET_NAME_LOW_WORD(v_lport->node_name);
	login_parms->high_port_name =
		UNF_GET_NAME_HIGH_WORD(v_lport->port_name);
	login_parms->low_port_name =
		UNF_GET_NAME_LOW_WORD(v_lport->port_name);

	UNF_PRINT_SFS_LIMIT(UNF_INFO, v_lport->port_id,
			    v_plogi_acc_pld,
			    sizeof(struct unf_plogi_payload_s));
}

static void unf_schedule_open_work(struct unf_lport_s *v_lport,
				   struct unf_rport_s *v_rport)
{
	/* Used for L_Port port only with TGT, or R_Port only with INI */
	struct unf_lport_s *lport = v_lport;
	struct unf_rport_s *rport = v_rport;
	unsigned long delay = 0;
	unsigned long flag = 0;
	unsigned int ret = 0;
	unsigned int port_feature = INVALID_VALUE32;

	UNF_CHECK_VALID(0x3452, UNF_TRUE, v_lport, return);
	UNF_CHECK_VALID(0x3453, UNF_TRUE, v_rport, return);

	delay = (unsigned long)lport->ed_tov;
	port_feature = rport->options & UNF_PORT_MODE_BOTH;

	if ((lport->options == UNF_PORT_MODE_TGT) ||
	    (port_feature == UNF_PORT_MODE_INI)) {
		spin_lock_irqsave(&rport->rport_state_lock, flag);

		ret = unf_rport_ref_inc(rport);
		if (ret != RETURN_OK) {
			UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT,
				  UNF_WARN,
				  "[warn]Port(0x%x_0x%x) RPort(0x%x) abnormal, no need open",
				  lport->port_id, lport->nport_id,
				  rport->nport_id);

			spin_unlock_irqrestore(&rport->rport_state_lock, flag);
			return;
		}

		/* Delay work pending check */
		if (delayed_work_pending(&rport->open_work)) {
			UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT,
				  UNF_WARN,
				  "[warn]Port(0x%x_0x%x) RPort(0x%x) open work is running, no need re-open",
				  lport->port_id, lport->nport_id,
				  rport->nport_id);

			spin_unlock_irqrestore(&rport->rport_state_lock, flag);
			unf_rport_ref_dec(rport);
			return;
		}

		/* start open work */
		if (queue_delayed_work(
			unf_work_queue,
			&rport->open_work,
			(unsigned long)
			msecs_to_jiffies((unsigned int)delay))) {
			UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT,
				  UNF_MAJOR,
				  "[info]Port(0x%x_0x%x) RPort(0x%x) start open work",
				  lport->port_id, lport->nport_id,
				  rport->nport_id);

			(void)unf_rport_ref_inc(rport);
		}
		spin_unlock_irqrestore(&rport->rport_state_lock, flag);

		unf_rport_ref_dec(rport);
	}
}

static void unf_plogi_acc_ob_callback(struct unf_xchg_s *v_xchg)
{
	struct unf_lport_s *lport = NULL;
	struct unf_rport_s *rport = NULL;
	unsigned long flags = 0;

	UNF_CHECK_VALID(0x3454, UNF_TRUE, v_xchg, return);

	spin_lock_irqsave(&v_xchg->xchg_state_lock, flags);
	lport = v_xchg->lport;
	rport = v_xchg->rport;
	spin_unlock_irqrestore(&v_xchg->xchg_state_lock, flags);

	UNF_CHECK_VALID(0x3455, UNF_TRUE, lport, return);
	UNF_CHECK_VALID(0x3456, UNF_TRUE, rport, return);

	/*
	 * 1. According to FC-LS 4.2.7.1:
	 * after RCVD PLOGI or sending PLOGI ACC, need to termitate open EXCH
	 */
	unf_cm_xchg_mgr_abort_io_by_id(lport, rport, rport->nport_id,
				       lport->nport_id, 0);

	/* 2. Send PLOGI ACC fail */
	if (v_xchg->ob_callback_sts != UNF_IO_SUCCESS) {
		/* Do R_Port recovery */
		unf_rport_error_recovery(rport);

		/* Do not care: Just used for L_Port only is
		 * TGT mode or R_Port only is INI mode
		 */
		unf_schedule_open_work(lport, rport);

		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN,
			  UNF_LOG_LOGIN_ATT, UNF_WARN,
			  "[warn]LOGIN: Port(0x%x_0x%x_0x%x) send PLOGI ACC failed(0x%x) with RPort(0x%x) feature(0x%x)",
			  lport->port_id, lport->nport_id,
			  lport->options, v_xchg->ob_callback_sts,
			  rport->nport_id, rport->options);

		/* NOTE: return */
		return;
	}

	/* 3. Private Loop: check whether or not need to send PRLI */
	spin_lock_irqsave(&rport->rport_state_lock, flags);
	if ((lport->en_act_topo == UNF_ACT_TOP_PRIVATE_LOOP) &&
	    ((rport->rp_state == UNF_RPORT_ST_PRLI_WAIT) ||
	    (rport->rp_state == UNF_RPORT_ST_READY))) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT,
			  UNF_MAJOR,
			  "[info]Port(0x%x_0x%x) RPort(0x%x) with State(0x%x) return directly",
			  lport->port_id, lport->nport_id,
			  rport->nport_id, rport->rp_state);

		/* Do nothing */
		spin_unlock_irqrestore(&rport->rport_state_lock, flags);
		return;
	}
	unf_rport_state_ma(rport, UNF_EVENT_RPORT_ENTER_PRLI);  // PRLI_WAIT
	spin_unlock_irqrestore(&rport->rport_state_lock, flags);

	/* 4. Set Port Feature with BOTH: cancel */
	if ((rport->options == UNF_PORT_MODE_UNKNOWN) &&
	    (rport->port_name != INVALID_WWPN))
		rport->options = unf_get_port_feature(rport->port_name);

	/*
	 * 5. Check whether need to send PRLI delay
	 * Call by: RCVD PLOGI ACC or callback for sending PLOGI ACC succeed
	 */
	unf_check_rport_need_delay_prli(lport, rport, rport->options);

	/* 6. Do not care: Just used for L_Port only is
	 * TGT mode or R_Port only is INI mode
	 */
	unf_schedule_open_work(lport, rport);

	UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT, UNF_MAJOR,
		  "[info]LOGIN: Port(0x%x_0x%x_0x%x) send PLOGI ACC succeed with RPort(0x%x) feature(0x%x)",
		  lport->port_id, lport->nport_id, lport->options,
		  rport->nport_id, rport->options);
}

unsigned int unf_send_plogi_acc(struct unf_lport_s *v_lport,
				struct unf_rport_s *v_rport,
				struct unf_xchg_s *v_xchg)
{
	struct unf_plogi_payload_s *plogi_acc_pld = NULL;
	union unf_sfs_u *fc_entry = NULL;
	unsigned int ret = UNF_RETURN_ERROR;
	struct unf_frame_pkg_s pkg = { 0 };
	unsigned short ox_id = 0;
	unsigned short rx_id = 0;

	UNF_REFERNCE_VAR(ox_id);
	UNF_REFERNCE_VAR(rx_id);
	UNF_CHECK_VALID(0x3398, UNF_TRUE, v_lport, return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(0x3399, UNF_TRUE, v_rport, return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(0x3400, UNF_TRUE, v_xchg, return UNF_RETURN_ERROR);

	v_xchg->cmnd_code = UNF_SET_ELS_ACC_TYPE(ELS_PLOGI);

	v_xchg->did = v_rport->nport_id;
	v_xchg->sid = v_lport->nport_id;
	v_xchg->oid = v_xchg->sid;
	v_xchg->pfn_callback = NULL;
	v_xchg->lport = v_lport;
	v_xchg->rport = v_rport;
	/* call back for sending PLOGI ACC */
	v_xchg->pfn_ob_callback = unf_plogi_acc_ob_callback;

	unf_fill_package(&pkg, v_xchg, v_rport);

	fc_entry = v_xchg->fcp_sfs_union.sfs_entry.fc_sfs_entry_ptr;
	if (!fc_entry) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT, UNF_WARN,
			  "[warn]Port(0x%x) entry can't be NULL with tag(0x%x)",
			  v_lport->port_id, v_xchg->hot_pool_tag);

		unf_cm_free_xchg(v_lport, v_xchg);
		return UNF_RETURN_ERROR;
	}

	/* Fill PLOGI ACC payload */
	memset(fc_entry, 0, sizeof(union unf_sfs_u));
	plogi_acc_pld = &fc_entry->plogi_acc.payload;
	unf_fill_plogi_acc_pld(plogi_acc_pld, v_lport);
	ox_id = v_xchg->ox_id;
	rx_id = v_xchg->rx_id;

	/* Start to Send PLOGI ACC now */
	ret = unf_els_cmnd_send(v_lport, &pkg, v_xchg);
	if (ret != RETURN_OK)
		/* NOTE: free exchange */
		unf_cm_free_xchg((void *)v_lport, (void *)v_xchg);

	if ((v_rport->nport_id < UNF_FC_FID_DOM_MGR) ||
	    (v_lport->en_act_topo == UNF_ACT_TOP_P2P_DIRECT)) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT, UNF_MAJOR,
			  "[info]LOGIN: PLOGI ACC send %s. Port(0x%x_0x%x_0x%llx)--->rport(0x%x_0x%llx) with OX_ID(0x%x) RX_ID(0x%x)",
			  (ret != RETURN_OK) ? "failed" : "succeed",
			  v_lport->port_id, v_lport->nport_id,
			  v_lport->port_name,
			  v_rport->nport_id, v_rport->port_name,
			  ox_id, rx_id);
	}

	UNF_REFERNCE_VAR(ox_id);
	UNF_REFERNCE_VAR(rx_id);
	return ret;
}

static void unf_fill_rjt_pld(struct unf_els_rjt_s *v_els_rjt,
			     unsigned int v_reason_code,
			     unsigned int v_reason_explanation)
{
	UNF_CHECK_VALID(0x3401, UNF_TRUE, v_els_rjt, return);

	v_els_rjt->cmnd = UNF_ELS_CMND_RJT;
	v_els_rjt->reason_code = (v_reason_code | v_reason_explanation);
}

static void unf_fill_prli_acc_pld(struct unf_pril_payload_s *v_prli_acc_pld,
				  struct unf_lport_s *v_lport,
				  struct unf_rport_s *v_rport)
{
	unsigned int port_mode = UNF_FC4_FRAME_PARM_3_TGT;

	UNF_CHECK_VALID(0x3402, UNF_TRUE, v_prli_acc_pld, return);
	UNF_CHECK_VALID(0x3403, UNF_TRUE, v_lport, return);
	UNF_CHECK_VALID(0x3404, UNF_TRUE, v_rport, return);

	v_prli_acc_pld->cmnd = (
		UNF_ELS_CMND_ACC |
		((unsigned int)UNF_FC4_FRAME_PAGE_SIZE <<
		UNF_FC4_FRAME_PAGE_SIZE_SHIFT) |
		((unsigned int)(sizeof(struct unf_pril_payload_s) -
		UNF_PRLI_SIRT_EXTRA_SIZE)));

	v_prli_acc_pld->parms[0] = (UNF_FC4_FRAME_PARM_0_FCP |
				    UNF_FC4_FRAME_PARM_0_I_PAIR |
				    UNF_FC4_FRAME_PARM_0_GOOD_RSP_CODE);
	v_prli_acc_pld->parms[1] = UNF_NOT_MEANINGFUL;
	v_prli_acc_pld->parms[2] = UNF_NOT_MEANINGFUL;

	/* About INI/TGT mode */
	if (v_rport->nport_id < UNF_FC_FID_DOM_MGR)
		/* return INI (0x20): R_Port has TGT mode,
		 * L_Port has INI mode
		 */
		port_mode = UNF_FC4_FRAME_PARM_3_INI;
	else
		port_mode = v_lport->options;

	/* About Read xfer_rdy disable */
	v_prli_acc_pld->parms[3] = (UNF_FC4_FRAME_PARM_3_R_XFER_DIS |
				    port_mode);  /* 0x2 */

	/* About Tape support */
	if (v_rport->tape_support_needed) {
		v_prli_acc_pld->parms[3] |=
				(UNF_FC4_FRAME_PARM_3_REC_SUPPORT |
				UNF_FC4_FRAME_PARM_3_RETRY_SUPPORT |
				UNF_FC4_FRAME_PARM_3_TASK_RETRY_ID_SUPPORT |
				UNF_FC4_FRAME_PARM_3_CONF_ALLOW);

		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT, UNF_MAJOR,
			  "PRLI ACC tape support");
	}

	/* About confirm */
	if (v_lport->low_level_func.lport_cfg_items.fcp_conf == UNF_TRUE)
		/* 0x80 */
		v_prli_acc_pld->parms[3] |= UNF_FC4_FRAME_PARM_3_CONF_ALLOW;

	UNF_PRINT_SFS_LIMIT(UNF_INFO, v_lport->port_id,
			    v_prli_acc_pld, sizeof(struct unf_pril_payload_s));
}

static void unf_prli_acc_ob_callback(struct unf_xchg_s *v_xchg)
{
	/* Report R_Port scsi Link Up */
	struct unf_lport_s *lport = NULL;
	struct unf_rport_s *rport = NULL;
	unsigned long flags = 0;
	enum unf_rport_login_state_e rport_state = UNF_RPORT_ST_INIT;

	UNF_CHECK_VALID(0x3449, UNF_TRUE, v_xchg, return);
	lport = v_xchg->lport;
	rport = v_xchg->rport;
	UNF_CHECK_VALID(0x3450, UNF_TRUE, lport, return);
	UNF_CHECK_VALID(0x3451, UNF_TRUE, rport, return);

	/* Update & Report Link Up */
	spin_lock_irqsave(&rport->rport_state_lock, flags);
	unf_rport_state_ma(rport, UNF_EVENT_RPORT_READY);  // READY
	rport_state = rport->rp_state;
	if (rport->nport_id < UNF_FC_FID_DOM_MGR) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT,
			  UNF_KEVENT,
			  "[event]LOGIN: Port(0x%x) RPort(0x%x) state(0x%x) WWN(0x%llx) prliacc",
			  lport->port_id, rport->nport_id,
			  rport->rp_state, rport->port_name);
	}
	spin_unlock_irqrestore(&rport->rport_state_lock, flags);

	if (rport_state == UNF_RPORT_ST_READY) {
		rport->logo_retries = 0;
		unf_update_lport_state_by_linkup_event(lport, rport,
						       rport->options);
	}
}

unsigned int unf_send_prli_acc(struct unf_lport_s *v_lport,
			       struct unf_rport_s *v_rport,
			       struct unf_xchg_s *v_xchg)
{
	struct unf_pril_payload_s *prli_acc_pld = NULL;
	union unf_sfs_u *fc_entry = NULL;
	unsigned int ret = UNF_RETURN_ERROR;
	struct unf_frame_pkg_s pkg = { 0 };
	unsigned short ox_id = 0;
	unsigned short rx_id = 0;

	UNF_REFERNCE_VAR(ox_id);
	UNF_REFERNCE_VAR(rx_id);
	UNF_CHECK_VALID(0x3405, UNF_TRUE, v_lport, return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(0x3406, UNF_TRUE, v_rport, return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(0x3407, UNF_TRUE, v_xchg, return UNF_RETURN_ERROR);

	v_xchg->cmnd_code = UNF_SET_ELS_ACC_TYPE(ELS_PRLI);
	v_xchg->did = v_rport->nport_id;
	v_xchg->sid = v_lport->nport_id;
	v_xchg->oid = v_xchg->sid;
	v_xchg->lport = v_lport;
	v_xchg->rport = v_rport;

	v_xchg->pfn_callback = NULL;
	/* callback when send succeed */
	v_xchg->pfn_ob_callback = unf_prli_acc_ob_callback;

	/* Fill common package */
	unf_fill_package(&pkg, v_xchg, v_rport);

	/* Get FC entry (alloc when create exchange) */
	fc_entry = v_xchg->fcp_sfs_union.sfs_entry.fc_sfs_entry_ptr;
	if (!fc_entry) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_LOGIN_ATT, UNF_ERR,
			  "[err]Port(0x%x) entry can't be NULL with tag(0x%x)",
			  v_lport->port_id, v_xchg->hot_pool_tag);

		unf_cm_free_xchg(v_lport, v_xchg);
		return UNF_RETURN_ERROR;
	}

	/* Fill FRLI Payload */
	memset(fc_entry, 0, sizeof(union unf_sfs_u));
	prli_acc_pld = &fc_entry->prli_acc.payload;
	unf_fill_prli_acc_pld(prli_acc_pld, v_lport, v_rport);
	ox_id = v_xchg->ox_id;
	rx_id = v_xchg->rx_id;

	/* Send ELS (RPLI) RSP */
	ret = unf_els_cmnd_send(v_lport, &pkg, v_xchg);
	if (ret != RETURN_OK)
		unf_cm_free_xchg((void *)v_lport, (void *)v_xchg);

	if ((v_rport->nport_id < UNF_FC_FID_DOM_MGR) ||
	    (v_lport->en_act_topo == UNF_ACT_TOP_P2P_DIRECT)) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT, UNF_MAJOR,
			  "[info]LOGIN: PRLI ACC send %s. Port(0x%x)--->rport(0x%x) with OX_ID(0x%x) RX_ID(0x%x)",
			  (ret != RETURN_OK) ? "failed" : "succeed",
			  v_lport->port_id, v_rport->nport_id, ox_id, rx_id);
	}

	UNF_REFERNCE_VAR(ox_id);
	UNF_REFERNCE_VAR(rx_id);
	return ret;
}

static unsigned int unf_send_rec_acc(struct unf_lport_s *v_lport,
				     struct unf_rport_s *v_rport,
				     struct unf_xchg_s *v_xchg)
{
	/* Reserved */
	UNF_REFERNCE_VAR(v_lport);
	UNF_REFERNCE_VAR(v_rport);
	UNF_REFERNCE_VAR(v_xchg);

	unf_cm_free_xchg((void *)v_lport, (void *)v_xchg);

	return RETURN_OK;
}

static void unf_rrq_acc_ob_callback(struct unf_xchg_s *v_xchg)
{
	UNF_CHECK_VALID(0x3408, UNF_TRUE, v_xchg, return);

	UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_IO_ATT, UNF_MAJOR,
		  "[info]RRQ ACC Xchg(0x%p) tag(0x%x)",
		  v_xchg, v_xchg->hot_pool_tag);

	UNF_REFERNCE_VAR(v_xchg);
}

static void unf_fill_els_acc_pld(struct unf_els_acc_s *v_els_acc_pld)
{
	UNF_CHECK_VALID(0x3420, UNF_TRUE, v_els_acc_pld, return);

	v_els_acc_pld->cmnd = UNF_ELS_CMND_ACC;
}

static void unf_rscn_acc_ob_callback(struct unf_xchg_s *v_xchg)
{
	UNF_REFERNCE_VAR(v_xchg);
}

static unsigned int unf_send_rscn_acc(struct unf_lport_s *v_lport,
				      struct unf_rport_s *v_rport,
				      struct unf_xchg_s *v_xchg)
{
	struct unf_els_acc_s *rscn_acc = NULL;
	union unf_sfs_u *fc_entry = NULL;
	unsigned int ret = UNF_RETURN_ERROR;
	unsigned short ox_id = 0;
	unsigned short rx_id = 0;
	struct unf_frame_pkg_s pkg;

	UNF_REFERNCE_VAR(ox_id);
	UNF_REFERNCE_VAR(rx_id);
	UNF_CHECK_VALID(0x3421, UNF_TRUE, v_lport, return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(0x3422, UNF_TRUE, v_rport, return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(0x3423, UNF_TRUE, v_xchg, return UNF_RETURN_ERROR);

	memset(&pkg, 0, sizeof(struct unf_frame_pkg_s));
	v_xchg->cmnd_code = UNF_SET_ELS_ACC_TYPE(ELS_RSCN);
	v_xchg->did = v_rport->nport_id;
	v_xchg->sid = v_lport->nport_id;
	v_xchg->oid = v_xchg->sid;
	v_xchg->lport = v_lport;
	v_xchg->rport = v_rport;

	/* Set call back function */
	v_xchg->pfn_callback = NULL;
	v_xchg->pfn_ob_callback = unf_rscn_acc_ob_callback;  // do nothing

	unf_fill_package(&pkg, v_xchg, v_rport);

	fc_entry = v_xchg->fcp_sfs_union.sfs_entry.fc_sfs_entry_ptr;
	if (!fc_entry) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT, UNF_WARN,
			  "[warn]Port(0x%x) entry can't be NULL with tag(0x%x)",
			  v_lport->port_id, v_xchg->hot_pool_tag);

		unf_cm_free_xchg(v_lport, v_xchg);
		return UNF_RETURN_ERROR;
	}

	memset(fc_entry, 0, sizeof(union unf_sfs_u));
	rscn_acc = &fc_entry->els_acc;
	unf_fill_els_acc_pld(rscn_acc);
	ox_id = v_xchg->ox_id;
	rx_id = v_xchg->rx_id;

	ret = unf_els_cmnd_send(v_lport, &pkg, v_xchg);
	if (ret != RETURN_OK)
		unf_cm_free_xchg((void *)v_lport, (void *)v_xchg);

	UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT, UNF_MAJOR,
		  "[info]LOGIN: RSCN ACC send %s. Port(0x%x)--->rport(0x%x) with OXID(0x%x) RXID(0x%x)",
		  (ret != RETURN_OK) ? "failed" : "succeed",
		  v_lport->port_id, v_rport->nport_id, ox_id, rx_id);

	UNF_REFERNCE_VAR(ox_id);
	UNF_REFERNCE_VAR(rx_id);
	return ret;
}

static void unf_logo_acc_ob_callback(struct unf_xchg_s *v_xchg)
{
	UNF_REFERNCE_VAR(v_xchg);
}

unsigned int unf_send_logo_acc(struct unf_lport_s *v_lport,
			       struct unf_rport_s *v_rport,
			       struct unf_xchg_s *v_xchg)
{
	struct unf_els_acc_s *logo_acc = NULL;
	union unf_sfs_u *fc_entry = NULL;
	unsigned int ret = UNF_RETURN_ERROR;
	unsigned short ox_id = 0;
	unsigned short rx_id = 0;
	struct unf_frame_pkg_s pkg;

	UNF_REFERNCE_VAR(ox_id);
	UNF_REFERNCE_VAR(rx_id);
	UNF_CHECK_VALID(0x3424, UNF_TRUE, v_lport, return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(0x3425, UNF_TRUE, v_rport, return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(0x3426, UNF_TRUE, v_xchg, return UNF_RETURN_ERROR);

	memset(&pkg, 0, sizeof(struct unf_frame_pkg_s));

	v_xchg->cmnd_code = UNF_SET_ELS_ACC_TYPE(ELS_LOGO);
	v_xchg->did = v_rport->nport_id;
	v_xchg->sid = v_lport->nport_id;
	v_xchg->oid = v_xchg->sid;
	v_xchg->lport = v_lport;
	v_xchg->rport = v_rport;
	v_xchg->pfn_callback = NULL;
	v_xchg->pfn_ob_callback = unf_logo_acc_ob_callback;  // do nothing

	unf_fill_package(&pkg, v_xchg, v_rport);

	fc_entry = v_xchg->fcp_sfs_union.sfs_entry.fc_sfs_entry_ptr;
	if (!fc_entry) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT, UNF_WARN,
			  "[warn]Port(0x%x) entry can't be NULL with tag(0x%x)",
			  v_lport->port_id, v_xchg->hot_pool_tag);

		unf_cm_free_xchg(v_lport, v_xchg);
		return UNF_RETURN_ERROR;
	}

	memset(fc_entry, 0, sizeof(union unf_sfs_u));
	logo_acc = &fc_entry->els_acc;
	unf_fill_els_acc_pld(logo_acc);
	ox_id = v_xchg->ox_id;
	rx_id = v_xchg->rx_id;

	ret = unf_els_cmnd_send(v_lport, &pkg, v_xchg);
	if (ret != RETURN_OK)
		unf_cm_free_xchg((void *)v_lport, (void *)v_xchg);

	if (v_rport->nport_id < UNF_FC_FID_DOM_MGR) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT, UNF_MAJOR,
			  "[info]LOGIN: LOGO ACC send %s. Port(0x%x)--->rport(0x%x) with OX_ID(0x%x) RX_ID(0x%x)",
			  (ret != RETURN_OK) ? "failed" : "succeed",
			  v_lport->port_id, v_rport->nport_id, ox_id, rx_id);
	}

	UNF_REFERNCE_VAR(ox_id);
	UNF_REFERNCE_VAR(rx_id);
	return ret;
}

static unsigned int unf_send_rrq_acc(struct unf_lport_s *v_lport,
				     struct unf_rport_s *v_rport,
				     struct unf_xchg_s *v_xchg)
{
	struct unf_els_acc_s *rrq_acc = NULL;
	union unf_sfs_u *fc_entry = NULL;
	unsigned int ret = UNF_RETURN_ERROR;
	unsigned short ox_id = 0;
	unsigned short rx_id = 0;
	struct unf_frame_pkg_s pkg = { 0 };

	UNF_REFERNCE_VAR(ox_id);
	UNF_REFERNCE_VAR(rx_id);
	UNF_CHECK_VALID(0x3427, UNF_TRUE, v_lport, return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(0x3428, UNF_TRUE, v_rport, return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(0x3429, UNF_TRUE, v_xchg, return UNF_RETURN_ERROR);

	v_xchg->did = v_rport->nport_id;
	v_xchg->sid = v_lport->nport_id;
	v_xchg->oid = v_xchg->sid;
	v_xchg->lport = v_lport;
	v_xchg->rport = v_rport;
	v_xchg->pfn_callback = NULL;  // do noting

	fc_entry = v_xchg->fcp_sfs_union.sfs_entry.fc_sfs_entry_ptr;
	if (!fc_entry) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT, UNF_WARN,
			  "[warn]Port(0x%x) entry can't be NULL with tag(0x%x)",
			  v_lport->port_id, v_xchg->hot_pool_tag);

		return UNF_RETURN_ERROR;
	}

	memset(fc_entry, 0, sizeof(union unf_sfs_u));
	rrq_acc = &fc_entry->els_acc;
	v_xchg->cmnd_code = UNF_SET_ELS_ACC_TYPE(ELS_RRQ);
	v_xchg->pfn_ob_callback = unf_rrq_acc_ob_callback;  // do noting
	unf_fill_els_acc_pld(rrq_acc);
	ox_id = v_xchg->ox_id;
	rx_id = v_xchg->rx_id;

	unf_fill_package(&pkg, v_xchg, v_rport);

	ret = unf_els_cmnd_send(v_lport, &pkg, v_xchg);
	UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT, UNF_MAJOR,
		  "[info]RRQ ACC send %s. Port(0x%x)--->rport(0x%x) with Xchg(0x%p) OX_ID(0x%x) RX_ID(0x%x)",
		  (ret != RETURN_OK) ? "failed" : "succeed",
		  v_lport->port_id, v_rport->nport_id, v_xchg, ox_id, rx_id);

	UNF_REFERNCE_VAR(ox_id);
	UNF_REFERNCE_VAR(rx_id);
	return ret;
}

static void unf_fill_pdisc_acc_pld(struct unf_plogi_payload_s *v_pdisc_acc_pld,
				   struct unf_lport_s *v_lport)
{
	struct unf_lgn_parms_s *login_parms = NULL;

	UNF_CHECK_VALID(0x3430, UNF_TRUE, v_pdisc_acc_pld, return);
	UNF_CHECK_VALID(0x3431, UNF_TRUE, v_lport, return);

	v_pdisc_acc_pld->cmnd = UNF_ELS_CMND_ACC;
	login_parms = &v_pdisc_acc_pld->parms;

	if ((v_lport->en_act_topo == UNF_ACT_TOP_P2P_FABRIC) ||
	    (v_lport->en_act_topo == UNF_ACT_TOP_P2P_DIRECT)) {
		login_parms->co_parms.bb_credit =
			unf_low_level_bb_credit(v_lport);
		login_parms->co_parms.alternate_bb_credit_mgmt =
			UNF_BBCREDIT_MANAGE_NFPORT;
		login_parms->co_parms.bb_scn =
			(v_lport->en_act_topo == UNF_ACT_TOP_P2P_FABRIC) ?
			0 : unf_low_level_bbscn(v_lport);
	} else {
		login_parms->co_parms.bb_credit = UNF_BBCREDIT_LPORT;
		login_parms->co_parms.alternate_bb_credit_mgmt =
			UNF_BBCREDIT_MANAGE_LPORT;
	}

	login_parms->co_parms.lowest_version = UNF_PLOGI_VERSION_LOWER;
	login_parms->co_parms.highest_version = UNF_PLOGI_VERSION_UPPER;
	login_parms->co_parms.continuously_increasing =
		UNF_CONTIN_INCREASE_SUPPORT;
	login_parms->co_parms.bb_receive_data_field_size =
		v_lport->max_frame_size;
	login_parms->co_parms.nport_total_concurrent_sequences =
		UNF_PLOGI_CONCURRENT_SEQ;
	login_parms->co_parms.relative_offset = UNF_PLOGI_RO_CATEGORY;
	login_parms->co_parms.e_d_tov = v_lport->ed_tov;

	login_parms->cl_parms[2].valid = UNF_CLASS_VALID;  // class-3
	login_parms->cl_parms[2].received_data_field_size =
		v_lport->max_frame_size;
	login_parms->cl_parms[2].concurrent_sequences =
		UNF_PLOGI_CONCURRENT_SEQ;
	login_parms->cl_parms[2].open_sequences_per_exchange =
		UNF_PLOGI_SEQ_PER_XCHG;

	login_parms->high_node_name =
		UNF_GET_NAME_HIGH_WORD(v_lport->node_name);
	login_parms->low_node_name =
		UNF_GET_NAME_LOW_WORD(v_lport->node_name);
	login_parms->high_port_name =
		UNF_GET_NAME_HIGH_WORD(v_lport->port_name);
	login_parms->low_port_name =
		UNF_GET_NAME_LOW_WORD(v_lport->port_name);

	UNF_PRINT_SFS_LIMIT(UNF_INFO, v_lport->port_id,
			    v_pdisc_acc_pld,
			    sizeof(struct unf_plogi_payload_s));
}

static void unf_pdisc_acc_ob_callback(struct unf_xchg_s *v_xchg)
{
	UNF_REFERNCE_VAR(v_xchg);
}

unsigned int unf_send_pdisc_acc(struct unf_lport_s *v_lport,
				struct unf_rport_s *v_rport,
				struct unf_xchg_s *v_xchg)
{
	struct unf_plogi_payload_s *pdisc_acc_pld = NULL;
	union unf_sfs_u *fc_entry = NULL;
	unsigned int ret = UNF_RETURN_ERROR;
	unsigned short ox_id = 0;
	unsigned short rx_id = 0;
	struct unf_frame_pkg_s pkg;

	UNF_REFERNCE_VAR(ox_id);
	UNF_REFERNCE_VAR(rx_id);
	UNF_CHECK_VALID(0x3432, UNF_TRUE, v_lport, return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(0x3433, UNF_TRUE, v_rport, return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(0x3434, UNF_TRUE, v_xchg, return UNF_RETURN_ERROR);

	memset(&pkg, 0, sizeof(struct unf_frame_pkg_s));

	v_xchg->cmnd_code = UNF_SET_ELS_ACC_TYPE(ELS_PDISC);
	v_xchg->did = v_rport->nport_id;
	v_xchg->sid = v_lport->nport_id;
	v_xchg->oid = v_xchg->sid;
	v_xchg->lport = v_lport;
	v_xchg->rport = v_rport;

	/* Set call back function */
	v_xchg->pfn_callback = NULL;
	v_xchg->pfn_ob_callback = unf_pdisc_acc_ob_callback;  // do nothing

	unf_fill_package(&pkg, v_xchg, v_rport);

	fc_entry = v_xchg->fcp_sfs_union.sfs_entry.fc_sfs_entry_ptr;
	if (!fc_entry) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT, UNF_WARN,
			  "[warn]Port(0x%x) entry can't be NULL with tag(0x%x)",
			  v_lport->port_id, v_xchg->hot_pool_tag);

		unf_cm_free_xchg(v_lport, v_xchg);
		return UNF_RETURN_ERROR;
	}

	memset(fc_entry, 0, sizeof(union unf_sfs_u));
	pdisc_acc_pld = &fc_entry->pdisc_acc.payload;
	unf_fill_pdisc_acc_pld(pdisc_acc_pld, v_lport);
	ox_id = v_xchg->ox_id;
	rx_id = v_xchg->rx_id;

	ret = unf_els_cmnd_send(v_lport, &pkg, v_xchg);
	if (ret != RETURN_OK)
		unf_cm_free_xchg((void *)v_lport, (void *)v_xchg);

	UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT, UNF_MAJOR,
		  "[info]LOGIN: Send PDISC ACC %s. Port(0x%x)--->rport(0x%x) with OX_ID(0x%x) RX_ID(0x%x)",
		  (ret != RETURN_OK) ? "failed" : "succeed",
		  v_lport->port_id, v_rport->nport_id, ox_id, rx_id);

	UNF_REFERNCE_VAR(ox_id);
	UNF_REFERNCE_VAR(rx_id);
	return ret;
}

static void unf_fill_adisc_acc_pld(struct unf_adisc_payload_s *v_adisc_acc_pld,
				   struct unf_lport_s *v_lport)
{
	UNF_CHECK_VALID(0x3435, UNF_TRUE, v_adisc_acc_pld, return);
	UNF_CHECK_VALID(0x3436, UNF_TRUE, v_lport, return);

	v_adisc_acc_pld->cmnd = (UNF_ELS_CMND_ACC);

	v_adisc_acc_pld->hard_address = (v_lport->nport_id & UNF_ALPA_MASK);
	v_adisc_acc_pld->high_node_name =
		UNF_GET_NAME_HIGH_WORD(v_lport->node_name);
	v_adisc_acc_pld->low_node_name =
		UNF_GET_NAME_LOW_WORD(v_lport->node_name);
	v_adisc_acc_pld->high_port_name =
		UNF_GET_NAME_HIGH_WORD(v_lport->port_name);
	v_adisc_acc_pld->low_port_name =
		UNF_GET_NAME_LOW_WORD(v_lport->port_name);
	v_adisc_acc_pld->nport_id = v_lport->nport_id;

	UNF_PRINT_SFS_LIMIT(UNF_INFO, v_lport->port_id,
			    v_adisc_acc_pld,
			    sizeof(struct unf_adisc_payload_s));
}

static void unf_adisc_acc_ob_callback(struct unf_xchg_s *v_xchg)
{
	UNF_REFERNCE_VAR(v_xchg);
}

static unsigned int unf_send_adisc_acc(struct unf_lport_s *v_lport,
				       struct unf_rport_s *v_rport,
				       struct unf_xchg_s *v_xchg)
{
	struct unf_adisc_payload_s *adisc_acc_pld = NULL;
	union unf_sfs_u *fc_entry = NULL;
	unsigned int ret = UNF_RETURN_ERROR;
	struct unf_frame_pkg_s pkg = { 0 };
	unsigned short ox_id = 0;
	unsigned short rx_id = 0;

	UNF_REFERNCE_VAR(ox_id);
	UNF_REFERNCE_VAR(rx_id);
	UNF_CHECK_VALID(0x3437, UNF_TRUE, v_lport, return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(0x3438, UNF_TRUE, v_rport, return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(0x3439, UNF_TRUE, v_xchg, return UNF_RETURN_ERROR);

	v_xchg->cmnd_code = UNF_SET_ELS_ACC_TYPE(ELS_ADISC);
	v_xchg->did = v_rport->nport_id;
	v_xchg->sid = v_lport->nport_id;
	v_xchg->oid = v_xchg->sid;
	v_xchg->lport = v_lport;
	v_xchg->rport = v_rport;

	v_xchg->pfn_callback = NULL;
	v_xchg->pfn_ob_callback = unf_adisc_acc_ob_callback;  // do nothing

	unf_fill_package(&pkg, v_xchg, v_rport);
	fc_entry = v_xchg->fcp_sfs_union.sfs_entry.fc_sfs_entry_ptr;
	if (!fc_entry) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT, UNF_WARN,
			  "[warn]Port(0x%x) entry can't be NULL with tag(0x%x)",
			  v_lport->port_id, v_xchg->hot_pool_tag);

		unf_cm_free_xchg(v_lport, v_xchg);
		return UNF_RETURN_ERROR;
	}

	memset(fc_entry, 0, sizeof(union unf_sfs_u));
	adisc_acc_pld = &fc_entry->adisc_acc.adisc_payl;
	unf_fill_adisc_acc_pld(adisc_acc_pld, v_lport);
	ox_id = v_xchg->ox_id;
	rx_id = v_xchg->rx_id;

	ret = unf_els_cmnd_send(v_lport, &pkg, v_xchg);
	if (ret != RETURN_OK)
		unf_cm_free_xchg((void *)v_lport, (void *)v_xchg);

	UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT, UNF_MAJOR,
		  "[info]LOGIN: Send ADISC ACC %s. Port(0x%x)--->rport(0x%x) with OX_ID(0x%x) RX_ID(0x%x)",
		  (ret != RETURN_OK) ? "failed" : "succeed",
		  v_lport->port_id, v_rport->nport_id, ox_id, rx_id);

	UNF_REFERNCE_VAR(ox_id);
	UNF_REFERNCE_VAR(rx_id);
	return ret;
}

static void unf_fill_prlo_acc_pld(struct unf_prli_prlo_s *v_prlo_acc,
				  struct unf_lport_s *v_lport)
{
	struct unf_pril_payload_s *prlo_acc_pld = NULL;

	UNF_CHECK_VALID(0x3440, UNF_TRUE, v_prlo_acc, return);

	prlo_acc_pld = &v_prlo_acc->payload;
	prlo_acc_pld->cmnd = (UNF_ELS_CMND_ACC |
				((unsigned int)UNF_FC4_FRAME_PAGE_SIZE <<
				 UNF_FC4_FRAME_PAGE_SIZE_SHIFT) |
				((unsigned int)
				sizeof(struct unf_pril_payload_s)));
	prlo_acc_pld->parms[0] = UNF_FC4_FRAME_PARM_0_FCP |
				 UNF_FC4_FRAME_PARM_0_GOOD_RSP_CODE;
	prlo_acc_pld->parms[1] = 0;
	prlo_acc_pld->parms[2] = 0;
	prlo_acc_pld->parms[3] = 0;

	UNF_PRINT_SFS_LIMIT(UNF_INFO, v_lport->port_id, prlo_acc_pld,
			    sizeof(struct unf_pril_payload_s));
}

static unsigned int unf_send_prlo_acc(struct unf_lport_s *v_lport,
				      struct unf_rport_s *v_rport,
				      struct unf_xchg_s *v_xchg)
{
	struct unf_prli_prlo_s *prlo_acc = NULL;
	union unf_sfs_u *fc_entry = NULL;
	unsigned int ret = UNF_RETURN_ERROR;
	unsigned short ox_id = 0;
	unsigned short rx_id = 0;
	struct unf_frame_pkg_s pkg;

	UNF_REFERNCE_VAR(ox_id);
	UNF_REFERNCE_VAR(rx_id);
	UNF_CHECK_VALID(0x3441, UNF_TRUE, v_lport, return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(0x3442, UNF_TRUE, v_rport, return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(0x3443, UNF_TRUE, v_xchg, return UNF_RETURN_ERROR);

	memset(&pkg, 0, sizeof(struct unf_frame_pkg_s));

	v_xchg->cmnd_code = UNF_SET_ELS_ACC_TYPE(ELS_PRLO);
	v_xchg->did = v_rport->nport_id;
	v_xchg->sid = v_lport->nport_id;
	v_xchg->oid = v_xchg->sid;
	v_xchg->lport = v_lport;
	v_xchg->rport = v_rport;

	v_xchg->pfn_callback = NULL;	// do nothing
	v_xchg->pfn_ob_callback = NULL;  // do nothing

	unf_fill_package(&pkg, v_xchg, v_rport);

	fc_entry = v_xchg->fcp_sfs_union.sfs_entry.fc_sfs_entry_ptr;
	if (!fc_entry) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT, UNF_WARN,
			  "[warn]Port(0x%x) entry can't be NULL with tag(0x%x)",
			  v_lport->port_id, v_xchg->hot_pool_tag);

		unf_cm_free_xchg(v_lport, v_xchg);
		return UNF_RETURN_ERROR;
	}

	memset(fc_entry, 0, sizeof(union unf_sfs_u));
	prlo_acc = &fc_entry->prlo_acc;
	unf_fill_prlo_acc_pld(prlo_acc, v_lport);
	ox_id = v_xchg->ox_id;
	rx_id = v_xchg->rx_id;

	ret = unf_els_cmnd_send(v_lport, &pkg, v_xchg);
	if (ret != RETURN_OK)
		unf_cm_free_xchg((void *)v_lport, (void *)v_xchg);

	UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT, UNF_MAJOR,
		  "[info]LOGIN: Send PRLO ACC %s. Port(0x%x)--->rport(0x%x) with OX_ID(0x%x) RX_ID(0x%x)",
		  (ret != RETURN_OK) ? "failed" : "succeed",
		  v_lport->port_id, v_rport->nport_id, ox_id, rx_id);

	UNF_REFERNCE_VAR(ox_id);
	UNF_REFERNCE_VAR(rx_id);
	return ret;
}

unsigned int unf_send_abts(struct unf_lport_s *v_lport,
			   struct unf_xchg_s *v_xchg)
{
	struct unf_rport_s *rport = NULL;
	unsigned int ret = UNF_RETURN_ERROR;
	struct unf_frame_pkg_s pkg;

	UNF_CHECK_VALID(0x3444, UNF_TRUE, v_lport, return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(0x3445, UNF_TRUE, v_xchg, return UNF_RETURN_ERROR);
	rport = v_xchg->rport;
	UNF_CHECK_VALID(0x3446, UNF_TRUE, rport, return UNF_RETURN_ERROR);

	/* set pkg info */
	memset(&pkg, 0, sizeof(struct unf_frame_pkg_s));
	pkg.type = UNF_PKG_BLS_REQ;
	pkg.frame_head.csctl_sid = v_xchg->sid;
	pkg.frame_head.rctl_did = v_xchg->did;
	pkg.frame_head.oxid_rxid =
		(unsigned int)v_xchg->ox_id << 16 | v_xchg->rx_id;
	pkg.xchg_contex = v_xchg;
	pkg.unf_cmnd_pload_bl.buffer_ptr =
		(unsigned char *)
		v_xchg->fcp_sfs_union.sfs_entry.fc_sfs_entry_ptr;

	pkg.unf_cmnd_pload_bl.buf_dma_addr =
		v_xchg->fcp_sfs_union.sfs_entry.sfs_buff_phy_addr;
	pkg.private[PKG_PRIVATE_XCHG_HOT_POOL_INDEX] = v_xchg->hot_pool_tag;

	UNF_SET_XCHG_ALLOC_TIME(&pkg, v_xchg);
	UNF_SET_ABORT_INFO_IOTYPE(&pkg, v_xchg);

	pkg.private[PKG_PRIVATE_XCHG_RPORT_INDEX] =
		v_xchg->private[PKG_PRIVATE_XCHG_RPORT_INDEX];

	/* Send ABTS frame to target */
	ret = unf_bls_cmnd_send(v_lport, &pkg, v_xchg);

	UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_IO_ATT, UNF_MAJOR,
		  "[info]Port(0x%x_0x%x) send ABTS %s. Abort exch(0x%p) Cmdsn:0x%lx, tag(0x%x) iotype(0x%x)",
		  v_lport->port_id, v_lport->nport_id,
		  (ret == UNF_RETURN_ERROR) ? "failed" : "succeed",
		  v_xchg, (unsigned long)v_xchg->cmnd_sn,
		  v_xchg->hot_pool_tag, v_xchg->data_direction);

	UNF_REFERNCE_VAR(rport);
	return ret;
}

unsigned int unf_release_rport_res(struct unf_lport_s *v_lport,
				   struct unf_rport_s *v_rport)
{
	unsigned int ret = UNF_RETURN_ERROR;
	struct unf_rport_info_s rport_info;

	UNF_CHECK_VALID(0x3447, UNF_TRUE, v_lport, return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(0x3448, UNF_TRUE, v_rport, return UNF_RETURN_ERROR);

	memset(&rport_info, 0, sizeof(struct unf_rport_info_s));

	rport_info.rport_index = v_rport->rport_index;
	rport_info.nport_id = v_rport->nport_id;
	rport_info.port_name = v_rport->port_name;

	/* 2. release R_Port(parent context/Session) resource */
	if (!v_lport->low_level_func.service_op.pfn_unf_release_rport_res) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT,
			  UNF_WARN,
			  "[warn]Port(0x%x) release rport resource function can't be NULL",
			  v_lport->port_id);

		return ret;
	}

	ret = v_lport->low_level_func.service_op.pfn_unf_release_rport_res(
			v_lport->fc_port,
			&rport_info);
	if (ret != RETURN_OK)
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT, UNF_WARN,
			  "[warn]Port(0x%x) rport_index(0x%x, %p) send release session CMND failed",
			  v_lport->port_id, rport_info.rport_index, v_rport);

	return ret;
}

static inline unsigned char unf_determin_bbscn(unsigned char local_bbscn,
					       unsigned char remote_bbscn)
{
	if ((remote_bbscn == 0) || (local_bbscn == 0))
		local_bbscn = 0;
	else
		local_bbscn = local_bbscn > remote_bbscn ?
			local_bbscn : remote_bbscn;

	return local_bbscn;
}

static void unf_cfg_lowlevel_fabric_params(
				struct unf_lport_s *v_lport,
				struct unf_rport_s *v_rport,
				struct unf_fabric_parms_s *v_login_parms)
{
	struct unf_port_login_parms_s login_co_parms = { 0 };
	unsigned int remote_edtov = 0;
	unsigned int ret = 0;
	unsigned char remote_edtov_resolution = 0; /* 0:ms; 1:ns */

	if (!v_lport->low_level_func.port_mgr_op.pfn_ll_port_config_set)
		return;

	login_co_parms.remote_rttov_tag =
		(unsigned char)UNF_GET_RT_TOV_FROM_PARAMS(v_login_parms);
	login_co_parms.remote_edtov_tag = 0;
	login_co_parms.remote_bbcredit =
		(unsigned short)
		UNF_GET_BB_CREDIT_FROM_PARAMS(v_login_parms);
	login_co_parms.compared_bbscn =
		(unsigned int)unf_determin_bbscn(
			(unsigned char)
			v_lport->low_level_func.lport_cfg_items.bb_scn,
			(unsigned char)
			UNF_GET_BB_SC_N_FROM_PARAMS(v_login_parms));

	remote_edtov_resolution =
		(unsigned char)
		UNF_GET_E_D_TOV_RESOLUTION_FROM_PARAMS(v_login_parms);
	remote_edtov = UNF_GET_E_D_TOV_FROM_PARAMS(v_login_parms);
	login_co_parms.compared_edtov_val =
		remote_edtov_resolution ?
		(remote_edtov / 1000000) : remote_edtov;

	login_co_parms.compared_ratov_val =
		UNF_GET_RA_TOV_FROM_PARAMS(v_login_parms);
	login_co_parms.els_cmnd_code = ELS_FLOGI;

	if (v_lport->en_act_topo & UNF_TOP_P2P_MASK) {
		login_co_parms.en_act_topo =
			(v_login_parms->co_parms.n_port == UNF_F_PORT) ?
			 UNF_ACT_TOP_P2P_FABRIC : UNF_ACT_TOP_P2P_DIRECT;
	} else {
		login_co_parms.en_act_topo = v_lport->en_act_topo;
	}

	ret = v_lport->low_level_func.port_mgr_op.pfn_ll_port_config_set(
			(void *)v_lport->fc_port,
			UNF_PORT_CFG_UPDATE_FABRIC_PARAM,
			(void *)&login_co_parms);
	if (ret != RETURN_OK)
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT, UNF_WARN,
			  "[warn]Lowlevel unsupport fabric config");
}

static unsigned int unf_check_flogi_params(
				struct unf_lport_s *v_lport,
				struct unf_rport_s *v_rport,
				struct unf_fabric_parms_s *v_fabric_parms)
{
	unsigned int ret = RETURN_OK;

	UNF_CHECK_VALID(0x3460, UNF_TRUE, v_lport, return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(0x3461, UNF_TRUE, v_rport, return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(0x3462, UNF_TRUE, v_fabric_parms,
			return UNF_RETURN_ERROR);
	UNF_REFERNCE_VAR(v_lport);
	UNF_REFERNCE_VAR(v_rport);

	if (v_fabric_parms->cl_parms[2].valid == UNF_CLASS_INVALID) {
		/* Discard directly */
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT,
			  UNF_WARN,
			  "[warn]Port(0x%x) NPort_ID(0x%x) FLOGI not support class3",
			  v_lport->port_id, v_rport->nport_id);

		return UNF_RETURN_ERROR;
	}

	return ret;
}

static void unf_save_fabric_params(struct unf_lport_s *v_lport,
				   struct unf_rport_s *v_rport,
				   struct unf_fabric_parms_s *v_fabric_parms)
{
	unsigned long long fabric_node_name = 0;

	UNF_CHECK_VALID(0x3463, UNF_TRUE, v_lport, return);
	UNF_CHECK_VALID(0x3464, UNF_TRUE, v_rport, return);
	UNF_CHECK_VALID(0x3465, UNF_TRUE, v_fabric_parms, return);

	UNF_REFERNCE_VAR(v_lport);
	fabric_node_name = (unsigned long long)
			   (((unsigned long long)
			   (v_fabric_parms->high_node_name) << 32) |
			    ((unsigned long long)
			    (v_fabric_parms->low_node_name)));

	/* R_Port for 0xfffffe is used for FLOGI, not need to save WWN */
	if (v_fabric_parms->co_parms.bb_receive_data_field_size >
	    UNF_MAX_FRAME_SIZE)
		v_rport->max_frame_size = UNF_MAX_FRAME_SIZE;  // 2112
	else
		v_rport->max_frame_size =
			v_fabric_parms->co_parms.bb_receive_data_field_size;

	/* with Fabric attribute */
	if (v_fabric_parms->co_parms.n_port == UNF_F_PORT) {
		v_rport->ed_tov = v_fabric_parms->co_parms.e_d_tov;
		v_rport->ra_tov = v_fabric_parms->co_parms.r_a_tov;
		v_lport->ed_tov = v_fabric_parms->co_parms.e_d_tov;
		v_lport->ra_tov = v_fabric_parms->co_parms.r_a_tov;
		v_lport->rr_tov = UNF_CALC_LPORT_RRTOV(v_lport);
		v_lport->fabric_node_name = fabric_node_name;
	}

	/* Configure info from FLOGI to chip */
	unf_cfg_lowlevel_fabric_params(v_lport, v_rport, v_fabric_parms);

	UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT, UNF_INFO,
		  "[info]Port(0x%x) Rport(0x%x) login parameter: E_D_TOV = %u. LPort E_D_TOV = %u. fabric nodename: 0x%x%x",
		  v_lport->port_id,
		  v_rport->nport_id,
		  (v_fabric_parms->co_parms.e_d_tov),
		  v_lport->ed_tov,
		  v_fabric_parms->high_node_name,
		  v_fabric_parms->low_node_name);
}

static unsigned int unf_flogi_handler(struct unf_lport_s *v_lport,
				      unsigned int v_sid,
				      struct unf_xchg_s *v_xchg)
{
	struct unf_rport_s *rport = NULL;
	struct unf_flogi_fdisc_acc_s *flogi_frame = NULL;
	struct unf_fabric_parms_s *fabric_login_parms = NULL;
	unsigned int ret = UNF_RETURN_ERROR;
	unsigned long flag = 0;
	unsigned long long wwpn = 0;
	unsigned long long wwnn = 0;

	UNF_CHECK_VALID(0x3466, UNF_TRUE, v_lport, return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(0x3467, UNF_TRUE, v_xchg, return UNF_RETURN_ERROR);
	UNF_REFERNCE_VAR(v_sid);

	UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_REG_ATT, UNF_MAJOR,
		  "[info]LOGIN: Port(0x%x)<---RPort(0x%x) Receive FLOGI with OX_ID(0x%x)",
		  v_lport->port_id, v_sid, v_xchg->ox_id);

	UNF_SERVICE_COLLECT(v_lport->link_service_info,
			    UNF_SERVICE_ITEM_FLOGI);

	/* Check L_Port state: Offline */
	if (v_lport->en_states >= UNF_LPORT_ST_OFFLINE) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT, UNF_WARN,
			  "[warn]Port(0x%x) with state(0x%x) not need to handle FLOGI",
			  v_lport->port_id, v_lport->en_states);

		unf_cm_free_xchg(v_lport, v_xchg);
		return ret;
	}

	flogi_frame =
		&v_xchg->fcp_sfs_union.sfs_entry.fc_sfs_entry_ptr->flogi;
	fabric_login_parms = &flogi_frame->flogi_payload.fabric_parms;
	UNF_PRINT_SFS_LIMIT(UNF_INFO, v_lport->port_id,
			    &flogi_frame->flogi_payload,
			    sizeof(struct unf_flogi_payload_s));
	wwpn = (unsigned long long)
		(((unsigned long long)
		(fabric_login_parms->high_port_name) << 32) |
		((unsigned long long)fabric_login_parms->low_port_name));
	wwnn = (unsigned long long)
		(((unsigned long long)
		(fabric_login_parms->high_node_name) << 32) |
		((unsigned long long)fabric_login_parms->low_node_name));

	/* Get (new) R_Port: reuse only */
	rport = unf_get_rport_by_nport_id(v_lport, UNF_FC_FID_FLOGI);
	rport = unf_get_safe_rport(v_lport, rport,
				   UNF_RPORT_REUSE_ONLY, UNF_FC_FID_FLOGI);
	if (unlikely(!rport)) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT, UNF_WARN,
			  "[warn]Port(0x%x) has no RPort. do nothing",
			  v_lport->port_id);

		unf_cm_free_xchg(v_lport, v_xchg);
		return UNF_RETURN_ERROR;
	}

	/* Update R_Port info */
	spin_lock_irqsave(&rport->rport_state_lock, flag);
	rport->port_name = wwpn;
	rport->node_name = wwnn;
	spin_unlock_irqrestore(&rport->rport_state_lock, flag);

	/* Check RCVD FLOGI parameters: only for class-3 */
	ret = unf_check_flogi_params(v_lport, rport, fabric_login_parms);
	if (ret != RETURN_OK) {
		/* Discard directly */
		unf_cm_free_xchg(v_lport, v_xchg);
		return UNF_RETURN_ERROR;
	}

	/* P2P fabric */
	unf_lport_update_topo(v_lport, UNF_ACT_TOP_P2P_DIRECT);

	/* Save fabric parameters */
	unf_save_fabric_params(v_lport, rport, fabric_login_parms);

	/* Send ACC for FLOGI */
	ret = unf_send_flogi_acc(v_lport, rport, v_xchg);
	if (ret != RETURN_OK) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT, UNF_WARN,
			  "[warn]LOGIN: Port(0x%x) send FLOGI ACC failed and do recover",
			  v_lport->port_id);

		/* Do L_Port recovery */
		unf_lport_error_recovery(v_lport);
	}

	return ret;
}

static void unf_cfg_lowlevel_port_params(struct unf_lport_s *v_lport,
					 struct unf_rport_s *v_rport,
					 struct unf_lgn_parms_s *v_login_parms,
					 unsigned int v_cmd_type)
{
	struct unf_port_login_parms_s login_co_parms = { 0 };
	unsigned int ret = 0;

	if (!v_lport->low_level_func.port_mgr_op.pfn_ll_port_config_set)
		return;

	login_co_parms.rport_index = v_rport->rport_index;
	login_co_parms.seq_cnt = 0;
	login_co_parms.ed_tov = 0;
	login_co_parms.ed_tov_timer_val = v_lport->ed_tov;
	login_co_parms.tx_mfs = v_rport->max_frame_size;

	login_co_parms.remote_rttov_tag =
		(unsigned char)UNF_GET_RT_TOV_FROM_PARAMS(v_login_parms);
	login_co_parms.remote_edtov_tag = 0;
	login_co_parms.remote_bbcredit =
		(unsigned short)UNF_GET_BB_CREDIT_FROM_PARAMS(v_login_parms);
	login_co_parms.els_cmnd_code = v_cmd_type;

	if (v_lport->en_act_topo == UNF_ACT_TOP_PRIVATE_LOOP) {
		login_co_parms.compared_bbscn = 0;
	} else {
		login_co_parms.compared_bbscn =
			(unsigned int)unf_determin_bbscn(
				(unsigned char)
				v_lport->low_level_func.lport_cfg_items.bb_scn,
				(unsigned char)
				UNF_GET_BB_SC_N_FROM_PARAMS(v_login_parms));
	}

	login_co_parms.compared_edtov_val = v_lport->ed_tov;
	login_co_parms.compared_ratov_val = v_lport->ra_tov;

	ret = v_lport->low_level_func.port_mgr_op.pfn_ll_port_config_set(
			(void *)v_lport->fc_port,
			UNF_PORT_CFG_UPDATE_PLOGI_PARAM,
			(void *)&login_co_parms);
	if (ret != RETURN_OK)
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT, UNF_WARN,
			  "[warn]Port(0x%x) Lowlevel unsupport port config",
			  v_lport->port_id);
}

unsigned int unf_check_plogi_params(struct unf_lport_s *v_lport,
				    struct unf_rport_s *v_rport,
				    struct unf_lgn_parms_s *v_login_parms)
{
	unsigned int ret = RETURN_OK;
	unsigned long flag = 0;

	UNF_CHECK_VALID(0x3468, UNF_TRUE, v_lport, return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(0x3469, UNF_TRUE, v_rport, return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(0x3470, UNF_TRUE, v_login_parms,
			return UNF_RETURN_ERROR);

	/* Parameters check: Class-type */
	if ((v_login_parms->cl_parms[2].valid == UNF_CLASS_INVALID) ||
	    (v_login_parms->co_parms.bb_receive_data_field_size == 0)) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT, UNF_WARN,
			  "[warn]Port(0x%x) RPort N_Port_ID(0x%x) with PLOGI parameters invalid: class3(%u), BBReceiveDataFieldSize(0x%x), send LOGO",
			  v_lport->port_id, v_rport->nport_id,
			  v_login_parms->cl_parms[2].valid,
			  v_login_parms->co_parms.bb_receive_data_field_size);

		spin_lock_irqsave(&v_rport->rport_state_lock, flag);
		/* --->>> LOGO */
		unf_rport_state_ma(v_rport, UNF_EVENT_RPORT_LOGO);
		spin_unlock_irqrestore(&v_rport->rport_state_lock, flag);

		/* Enter LOGO stage */
		unf_rport_enter_logo(v_lport, v_rport);
		return UNF_RETURN_ERROR;
	}

	/* 16G FC Brocade SW, Domain Controller's
	 * PLOGI both support CLASS-1 & CLASS-2
	 */
	if ((v_login_parms->cl_parms[0].valid == UNF_CLASS_VALID) ||
	    (v_login_parms->cl_parms[1].valid == UNF_CLASS_VALID)) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT, UNF_INFO,
			  "[info]Port(0x%x) get PLOGI class1(%u) class2(%u) from N_Port_ID(0x%x)",
			  v_lport->port_id,
			  v_login_parms->cl_parms[0].valid,
			  v_login_parms->cl_parms[1].valid,
			  v_rport->nport_id);
	}

	return ret;
}

static void unf_save_plogi_params(struct unf_lport_s *v_lport,
				  struct unf_rport_s *v_rport,
				  struct unf_lgn_parms_s *v_login_parms,
				  unsigned int v_cmd_code)
{
#define UNF_DELAY_TIME 100 /* WWPN smaller delay to send PRLI with COM mode */

	unsigned long long wwpn = INVALID_VALUE64;
	unsigned long long wwnn = INVALID_VALUE64;
	unsigned int ed_tov = 0;
	unsigned int remote_edtov = 0;

	if (v_login_parms->co_parms.bb_receive_data_field_size >
	    UNF_MAX_FRAME_SIZE)
		v_rport->max_frame_size = UNF_MAX_FRAME_SIZE;  // 2112
	else
		v_rport->max_frame_size =
			v_login_parms->co_parms.bb_receive_data_field_size;

	wwnn = (unsigned long long)
		(((unsigned long long)
		(v_login_parms->high_node_name) << 32) |
		((unsigned long long)v_login_parms->low_node_name));
	wwpn = (unsigned long long)
		(((unsigned long long)
		(v_login_parms->high_port_name) << 32) |
		((unsigned long long)v_login_parms->low_port_name));

	remote_edtov = v_login_parms->co_parms.e_d_tov;
	ed_tov = v_login_parms->co_parms.e_d_tov_resolution ?
			(remote_edtov / 1000000) : remote_edtov;

	v_rport->port_name = wwpn;
	v_rport->node_name = wwnn;
	v_rport->local_nport_id = v_lport->nport_id;

	if ((v_lport->en_act_topo == UNF_ACT_TOP_P2P_DIRECT) ||
	    (v_lport->en_act_topo == UNF_ACT_TOP_PRIVATE_LOOP)) {
		/* P2P or Private Loop */
		v_lport->ed_tov = (v_lport->ed_tov > ed_tov) ?
			v_lport->ed_tov : ed_tov;
		v_lport->ra_tov = 2 * v_lport->ed_tov;  // 2 * E_D_TOV
		v_lport->rr_tov = UNF_CALC_LPORT_RRTOV(v_lport);

		if (ed_tov != 0)
			v_rport->ed_tov = ed_tov;
		else
			v_rport->ed_tov = UNF_DEFAULT_EDTOV;
	} else {
		/* SAN: E_D_TOV updated by FLOGI */
		v_rport->ed_tov = v_lport->ed_tov;
	}

	/* WWPN smaller: delay to send PRLI */
	if (v_rport->port_name > v_lport->port_name)
		v_rport->ed_tov += UNF_DELAY_TIME;  // 100ms

	/* Configure port parameters to low level (chip) */
	unf_cfg_lowlevel_port_params(v_lport, v_rport, v_login_parms,
				     v_cmd_code);

	UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT, UNF_INFO,
		  "[info]Port(0x%x) RPort(0x%x) with WWPN(0x%llx) WWNN(0x%llx) login: ED_TOV(%u) Port: ED_TOV(%u)",
		  v_lport->port_id,
		  v_rport->nport_id,
		  v_rport->port_name, v_rport->node_name,
		  ed_tov,
		  v_lport->ed_tov);
}

static int unf_check_bbscn_is_enabled(unsigned char local_bbscn,
				      unsigned char remote_bbscn)
{
	return unf_determin_bbscn(local_bbscn, remote_bbscn) ?
				  UNF_TRUE : UNF_FALSE;
}

static unsigned int unf_irq_process_switch_2_thread(void *v_lport,
						    struct unf_xchg_s *v_xchg,
						    unf_evt_task v_evt_task)
{
	struct unf_cm_event_report *event = NULL;
	struct unf_xchg_s *xchg = NULL;
	unsigned int ret = 0;
	struct unf_lport_s *lport = NULL;

	UNF_CHECK_VALID(0x1996, UNF_TRUE, v_lport, return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(0x1996, UNF_TRUE, v_xchg, return UNF_RETURN_ERROR);
	lport = v_lport;
	xchg = v_xchg;

	if (unlikely((!lport->event_mgr.pfn_unf_get_free_event) ||
		     (!lport->event_mgr.pfn_unf_post_event) ||
		     (!lport->event_mgr.pfn_unf_release_event))) {
		UNF_TRACE(0x2065, UNF_LOG_LOGIN_ATT, UNF_WARN,
			  "[warn]Port(0x%x) event function is NULL",
			  lport->port_id);

		return UNF_RETURN_ERROR;
	}

	ret = unf_xchg_ref_inc(xchg, SFS_RESPONSE);
	UNF_CHECK_VALID(0x3343, UNF_TRUE, (ret == RETURN_OK),
			return UNF_RETURN_ERROR);

	event = lport->event_mgr.pfn_unf_get_free_event((void *)v_lport);
	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE, event,
			return UNF_RETURN_ERROR);

	event->lport = lport;
	event->event_asy_flag = UNF_EVENT_ASYN;
	event->pfn_unf_event_task = v_evt_task;
	event->para_in = v_xchg;
	lport->event_mgr.pfn_unf_post_event(lport, event);

	UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT, UNF_MAJOR,
		  "[info]Port(0x%x) start to switch thread process now",
		  lport->port_id);

	return ret;
}

static unsigned int unf_plogi_handler_com_process(struct unf_xchg_s *v_xchg)
{
	struct unf_xchg_s *xchg = v_xchg;
	struct unf_lport_s *lport = NULL;
	struct unf_rport_s *rport = NULL;
	struct unf_plogi_pdisc_s *plogi_frame = NULL;
	struct unf_lgn_parms_s *login_parms = NULL;
	unsigned int ret = UNF_RETURN_ERROR;
	unsigned long flag = 0;

	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE, xchg,
			return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE, xchg->lport,
			return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE, xchg->rport,
			return UNF_RETURN_ERROR);

	lport = xchg->lport;
	rport = xchg->rport;
	plogi_frame =
		&xchg->fcp_sfs_union.sfs_entry.fc_sfs_entry_ptr->plogi;
	login_parms = &plogi_frame->payload.parms;

	unf_save_plogi_params(lport, rport, login_parms,
			      ELS_PLOGI);

	/* Update state: PLOGI_WAIT */
	spin_lock_irqsave(&rport->rport_state_lock, flag);
	rport->nport_id = xchg->sid;
	unf_rport_state_ma(rport, UNF_EVENT_RPORT_ENTER_PLOGI);
	spin_unlock_irqrestore(&rport->rport_state_lock, flag);

	/* Send PLOGI ACC to remote port */
	ret = unf_send_plogi_acc(lport, rport, xchg);
	if (ret != RETURN_OK) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT, UNF_WARN,
			  "[warn]LOGIN: Port(0x%x) send PLOGI ACC failed",
			  lport->port_id);

		/* NOTE: exchange has been freed inner(before) */
		unf_rport_error_recovery(rport);
		return ret;
	}

	UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT, UNF_INFO,
		  "[info]LOGIN: Port(0x%x) send PLOGI ACC to Port(0x%x) succeed",
		  lport->port_id, rport->nport_id);

	return ret;
}

static int unf_plogi_async_handle(void *v_argc_in, void *v_argc_out)
{
	struct unf_xchg_s *xchg = (struct unf_xchg_s *)v_argc_in;
	unsigned int ret = RETURN_OK;

	UNF_CHECK_VALID(0x2267, UNF_TRUE, xchg, return UNF_RETURN_ERROR);

	ret = unf_plogi_handler_com_process(xchg);
	unf_xchg_ref_dec(xchg, SFS_RESPONSE);

	return (int)ret;
}

static unsigned int unf_send_els_rjt_by_did(struct unf_lport_s *v_lport,
					    struct unf_xchg_s *v_xchg,
					    unsigned int v_did,
					    struct unf_rjt_info_s *v_rjt_info)
{
	struct unf_els_rjt_s *els_rjt = NULL;
	union unf_sfs_u *fc_entry = NULL;
	struct unf_xchg_s *xchg = v_xchg;
	struct unf_frame_pkg_s pkg = { 0 };
	unsigned int ret = UNF_RETURN_ERROR;
	unsigned short ox_id = 0;
	unsigned short rx_id = 0;

	UNF_REFERNCE_VAR(ox_id);
	UNF_REFERNCE_VAR(rx_id);

	UNF_CHECK_VALID(0x3503, UNF_TRUE, v_lport, return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(0x3504, UNF_TRUE, v_xchg, return UNF_RETURN_ERROR);

	xchg->cmnd_code = UNF_SET_ELS_RJT_TYPE(v_rjt_info->els_cmnd_code);
	xchg->did = v_did;
	xchg->sid = v_lport->nport_id;
	xchg->oid = xchg->sid;
	xchg->lport = v_lport;
	xchg->rport = NULL;
	xchg->disc_rport = NULL;

	xchg->pfn_callback = NULL;
	xchg->pfn_ob_callback = NULL;

	unf_fill_package(&pkg, xchg, NULL);

	fc_entry = xchg->fcp_sfs_union.sfs_entry.fc_sfs_entry_ptr;
	if (!fc_entry) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT, UNF_WARN,
			  "[warn]Port(0x%x) entry can't be NULL with tag(0x%x)",
			  v_lport->port_id, xchg->hot_pool_tag);

		unf_cm_free_xchg(v_lport, xchg);
		return UNF_RETURN_ERROR;
	}

	els_rjt = &fc_entry->els_rjt;
	memset(els_rjt, 0, sizeof(struct unf_els_rjt_s));
	unf_fill_rjt_pld(els_rjt, v_rjt_info->reason_code,
			 v_rjt_info->reason_explanation);
	ox_id = v_xchg->ox_id;
	rx_id = v_xchg->rx_id;

	ret = unf_els_cmnd_send(v_lport, &pkg, xchg);
	if (ret != RETURN_OK)
		unf_cm_free_xchg((void *)v_lport, (void *)xchg);

	UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT, UNF_MAJOR,
		  "[info]LOGIN: Send LS_RJT %s. Port(0x%x)--->rport(0x%x) with OX_ID(0x%x) RX_ID(0x%x)",
		  (ret != RETURN_OK) ? "failed" : "succeed",
		  v_lport->port_id, v_did, ox_id, rx_id);

	UNF_REFERNCE_VAR(ox_id);
	UNF_REFERNCE_VAR(rx_id);
	return ret;
}

static unsigned int unf_plogi_handler(struct unf_lport_s *v_lport,
				      unsigned int v_sid,
				      struct unf_xchg_s *v_xchg)
{
	struct unf_xchg_s *xchg = v_xchg;
	struct unf_lport_s *lport = v_lport;
	struct unf_rport_s *rport = NULL;
	struct unf_plogi_pdisc_s *plogi_frame = NULL;
	struct unf_lgn_parms_s *login_parms = NULL;
	struct unf_rjt_info_s rjt_info = { 0 };
	unsigned long long wwpn = INVALID_VALUE64;
	unsigned int ret = UNF_RETURN_ERROR;
	int bbscn_enabled = UNF_FALSE;
	int switch_2_thread = UNF_FALSE;

	UNF_CHECK_VALID(0x3474, UNF_TRUE, v_lport, return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(0x3475, UNF_TRUE, v_xchg, return UNF_RETURN_ERROR);

	/* 1. Maybe: PLOGI is sent by Name server */
	if ((v_sid < UNF_FC_FID_DOM_MGR) ||
	    (v_lport->en_act_topo == UNF_ACT_TOP_P2P_DIRECT))
		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT, UNF_MAJOR,
			  "[info]LOGIN: Receive PLOGI. Port(0x%x_0x%x)<---RPort(0x%x) with OX_ID(0x%x)",
			  v_lport->port_id, v_lport->nport_id, v_sid,
			  v_xchg->ox_id);

	UNF_SERVICE_COLLECT(v_lport->link_service_info,
			    UNF_SERVICE_ITEM_PLOGI);

	/* 2. State check: Offline */
	if (lport->en_states >= UNF_LPORT_ST_OFFLINE) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT, UNF_WARN,
			  "[warn]Port(0x%x_0x%x) received PLOGI with state(0x%x)",
			  lport->port_id, lport->nport_id, lport->en_states);

		unf_cm_free_xchg(lport, xchg);
		return UNF_RETURN_ERROR;
	}

	/*
	 * 3. According to FC-LS 4.2.7.1:
	 * After RCVD PLogi or send Plogi ACC, need to termitate open EXCH
	 */
	unf_cm_xchg_mgr_abort_io_by_id(lport, rport, v_sid, lport->nport_id, 0);

	/* Get R_Port by WWpn */
	plogi_frame =
		&xchg->fcp_sfs_union.sfs_entry.fc_sfs_entry_ptr->plogi;
	login_parms = &plogi_frame->payload.parms;

	UNF_PRINT_SFS_LIMIT(UNF_INFO, lport->port_id,
			    &plogi_frame->payload,
			    sizeof(struct unf_plogi_payload_s));

	wwpn = (unsigned long long)
		(((unsigned long long)
		(login_parms->high_port_name) << 32) |
		((unsigned long long)login_parms->low_port_name));

	/* 4. Get (new) R_Port (by wwpn) */
	rport = unf_find_rport(lport, v_sid, wwpn);
	rport = unf_get_safe_rport(lport, rport, UNF_RPORT_REUSE_ONLY, v_sid);
	if (!rport) {
		memset(&rjt_info, 0, sizeof(struct unf_rjt_info_s));
		rjt_info.els_cmnd_code = ELS_PLOGI;
		rjt_info.reason_code = UNF_LS_RJT_BUSY;
		rjt_info.reason_explanation =
			UNF_LS_RJT_INSUFFICIENT_RESOURCES;

		/* R_Port is NULL: Send ELS RJT for PLOGI */
		(void)unf_send_els_rjt_by_did(lport, xchg, v_sid, &rjt_info);

		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT, UNF_WARN,
			  "[warn]Port(0x%x) has no RPort and send PLOGI reject",
			  lport->port_id);

		/* NOTE: exchange has been freed inner(before) */
		return UNF_RETURN_ERROR;
	}

	/* 5. Cancel recovery timer work after RCVD PLOGI */
	if (cancel_delayed_work(&rport->recovery_work))
		atomic_dec(&rport->rport_ref_cnt);

	/*
	 * 6. Plogi parameters check
	 * Call by: (RCVD) PLOGI handler & callback function for RCVD PLOGI_ACC
	 */
	ret = unf_check_plogi_params(lport, rport, login_parms);
	if (ret != RETURN_OK) {
		unf_cm_free_xchg(lport, xchg);
		return UNF_RETURN_ERROR;
	}

	xchg->lport = v_lport;
	xchg->rport = rport;
	xchg->sid = v_sid;

	/* 7. About bbscn for context change */
	bbscn_enabled = unf_check_bbscn_is_enabled(
		(unsigned char)lport->low_level_func.lport_cfg_items.bb_scn,
		(unsigned char)UNF_GET_BB_SC_N_FROM_PARAMS(login_parms));
	if ((lport->en_act_topo == UNF_ACT_TOP_P2P_DIRECT) &&
	    (bbscn_enabled == UNF_TRUE)) {
		switch_2_thread = UNF_TRUE;
		lport->b_bbscn_support = UNF_TRUE;
	}

	/* 8. Process PLOGI Frame: switch to thread if necessary */
	if ((switch_2_thread == UNF_TRUE) && (lport->root_lport == lport))
		/* Wait for LR complete sync */
		ret = unf_irq_process_switch_2_thread(lport, xchg,
						      unf_plogi_async_handle);
	else
		ret = unf_plogi_handler_com_process(xchg);

	return ret;
}

static void unf_obtain_tape_capacity(struct unf_lport_s *v_lport,
				     struct unf_rport_s *v_rport,
				     unsigned int tape_parm)
{
	unsigned int rec_support = 0;
	unsigned int task_retry_support = 0;
	unsigned int retry_support = 0;

	rec_support = tape_parm & UNF_FC4_FRAME_PARM_3_REC_SUPPORT;
	task_retry_support = tape_parm &
				UNF_FC4_FRAME_PARM_3_TASK_RETRY_ID_SUPPORT;
	retry_support = tape_parm & UNF_FC4_FRAME_PARM_3_RETRY_SUPPORT;

	if ((v_lport->low_level_func.lport_cfg_items.tape_support) &&
	    rec_support && task_retry_support && retry_support) {
		v_rport->tape_support_needed = UNF_TRUE;

		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT, UNF_MAJOR,
			  "[info]Port(0x%x_0x%x) FC_tape is needed for RPort(0x%x)",
			  v_lport->port_id, v_lport->nport_id,
			  v_rport->nport_id);
	}

	if ((tape_parm & UNF_FC4_FRAME_PARM_3_CONF_ALLOW) &&
	    (v_lport->low_level_func.lport_cfg_items.fcp_conf != UNF_FALSE)) {
		v_rport->fcp_conf_needed = UNF_TRUE;

		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT, UNF_MAJOR,
			  "[info]Port(0x%x_0x%x) FCP confirm is needed for RPort(0x%x)",
			  v_lport->port_id, v_lport->nport_id,
			  v_rport->nport_id);
	}
}

unsigned int unf_prli_handler_com_process(struct unf_xchg_s *v_xchg)
{
	struct unf_prli_prlo_s *prli = NULL;
	unsigned int ret = UNF_RETURN_ERROR;
	unsigned long flags = 0;
	unsigned int uisid = 0;
	struct unf_lport_s *lport = NULL;
	struct unf_rport_s *rport = NULL;
	struct unf_xchg_s *xchg = NULL;

	xchg = v_xchg;
	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE, xchg,
			return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE, xchg->lport,
			return UNF_RETURN_ERROR);
	lport = xchg->lport;
	uisid = v_xchg->sid;

	UNF_SERVICE_COLLECT(lport->link_service_info, UNF_SERVICE_ITEM_PRLI);

	/* 1. Get R_Port: for each R_Port from rport_busy_list */
	rport = unf_get_rport_by_nport_id(lport, uisid);
	if (!rport) {
		/* non session (R_Port) existence */
		(void)unf_send_logo_by_did(lport, uisid);

		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT, UNF_WARN,
			  "[warn]Port(0x%x_0x%x) received PRLI but no RPort SID(0x%x) OX_ID(0x%x)",
			  lport->port_id, lport->nport_id, uisid,
			  v_xchg->ox_id);

		unf_cm_free_xchg(lport, v_xchg);
		return ret;
	}

	UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT, UNF_INFO,
		  "[info]LOGIN: Receive PRLI. Port(0x%x)<---RPort(0x%x) with S_ID(0x%x)",
		  lport->port_id, rport->nport_id, uisid);

	/* 2. Get PRLI info */
	prli = &v_xchg->fcp_sfs_union.sfs_entry.fc_sfs_entry_ptr->prli;
	if ((uisid < UNF_FC_FID_DOM_MGR) ||
	    (lport->en_act_topo == UNF_ACT_TOP_P2P_DIRECT)) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT,
			  UNF_MAJOR,
			  "[info]LOGIN: Receive PRLI. Port(0x%x_0x%x)<---RPort(0x%x) parameter-3(0x%x) OX_ID(0x%x)",
			  lport->port_id, lport->nport_id, uisid,
			  prli->payload.parms[3], v_xchg->ox_id);
	}

	UNF_PRINT_SFS_LIMIT(UNF_INFO, lport->port_id,
			    &prli->payload, sizeof(struct unf_pril_payload_s));

	spin_lock_irqsave(&rport->rport_state_lock, flags);

	/* 3. Increase R_Port ref_cnt */
	ret = unf_rport_ref_inc(rport);
	if (ret != RETURN_OK) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT, UNF_WARN,
			  "[warn]Port(0x%x) RPort(0x%x_0x%p) is removing and do nothing",
			  lport->port_id, rport->nport_id, rport);

		spin_unlock_irqrestore(&rport->rport_state_lock, flags);

		unf_cm_free_xchg(lport, v_xchg);
		return RETURN_OK;
	}

	/* 4. Cancel R_Port Open work */
	if (cancel_delayed_work(&rport->open_work)) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT, UNF_MAJOR,
			  "[info]Port(0x%x_0x%x) RPort(0x%x) cancel open work succeed",
			  lport->port_id, lport->nport_id, rport->nport_id);

		/* This is not the last counter */
		atomic_dec(&rport->rport_ref_cnt);
	}

	/* 5. Check R_Port state */
	if ((rport->rp_state != UNF_RPORT_ST_PRLI_WAIT) &&
	    (rport->rp_state != UNF_RPORT_ST_READY)) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT, UNF_WARN,
			  "[warn]Port(0x%x_0x%x) RPort(0x%x) with state(0x%x) when received PRLI, send LOGO",
			  lport->port_id, lport->nport_id,
			  rport->nport_id, rport->rp_state);

		unf_rport_state_ma(rport, UNF_EVENT_RPORT_LOGO);  // LOGO
		spin_unlock_irqrestore(&rport->rport_state_lock, flags);

		/* NOTE: Start to send LOGO */
		unf_rport_enter_logo(lport, rport);

		unf_cm_free_xchg(lport, v_xchg);
		unf_rport_ref_dec(rport);

		return ret;
	}

	spin_unlock_irqrestore(&rport->rport_state_lock, flags);

	/* 6. Update R_Port options(INI/TGT/BOTH) */
	rport->options = prli->payload.parms[3] &
				(UNF_FC4_FRAME_PARM_3_TGT |
				UNF_FC4_FRAME_PARM_3_INI);

	unf_update_port_feature(rport->port_name, rport->options);

	/* for Confirm */
	rport->fcp_conf_needed = UNF_FALSE;

	unf_obtain_tape_capacity(lport, rport, prli->payload.parms[3]);

	if ((prli->payload.parms[3] & UNF_FC4_FRAME_PARM_3_CONF_ALLOW) &&
	    (lport->low_level_func.lport_cfg_items.fcp_conf != UNF_FALSE)) {
		rport->fcp_conf_needed = UNF_TRUE;

		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT, UNF_MAJOR,
			  "[info]Port(0x%x_0x%x) FCP confirm is needed for RPort(0x%x)",
			  lport->port_id, lport->nport_id, rport->nport_id);
	}
	UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT, UNF_INFO,
		  "[info]Port(0x%x_0x%x) RPort(0x%x) parameter-3(0x%x) options(0x%x)",
		  lport->port_id, lport->nport_id, rport->nport_id,
		  prli->payload.parms[3], rport->options);

	/* 7. Send PRLI ACC */
	ret = unf_send_prli_acc(lport, rport, v_xchg);
	if (ret != RETURN_OK) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT, UNF_WARN,
			  "[warn]LOGIN: Port(0x%x_0x%x) RPort(0x%x) send PRLI ACC failed",
			  lport->port_id, lport->nport_id, rport->nport_id);

		/* NOTE: exchange has been freed inner(before) */
		unf_rport_error_recovery(rport);
	}

	/* 8. Decrease R_Port ref_cnt */
	unf_rport_ref_dec(rport);

	return ret;
}

static int unf_prli_async_handle(void *v_argc_in, void *v_argc_out)
{
	struct unf_xchg_s *xchg = (struct unf_xchg_s *)v_argc_in;
	unsigned int ret = RETURN_OK;

	UNF_CHECK_VALID(0x2267, UNF_TRUE, xchg, return UNF_RETURN_ERROR);

	ret = unf_prli_handler_com_process(xchg);

	unf_xchg_ref_dec(xchg, SFS_RESPONSE);

	return (int)ret;
}

static unsigned int unf_prli_handler(struct unf_lport_s *v_lport,
				     unsigned int v_sid,
				     struct unf_xchg_s *v_xchg)
{
	unsigned int ret = UNF_RETURN_ERROR;
	int switch_2_thread = UNF_FALSE;
	struct unf_lport_s *lport = NULL;

	UNF_CHECK_VALID(0x3476, UNF_TRUE, v_lport, return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(0x3477, UNF_TRUE, v_xchg, return UNF_RETURN_ERROR);

	v_xchg->sid = v_sid;
	v_xchg->lport = v_lport;
	lport = v_lport;

	if ((v_lport->b_bbscn_support) &&
	    (v_lport->en_act_topo == UNF_ACT_TOP_P2P_DIRECT))
		switch_2_thread = UNF_TRUE;

	if ((switch_2_thread == UNF_TRUE) && (lport->root_lport == lport))
		/* Wait for LR done sync */
		ret = unf_irq_process_switch_2_thread(v_lport, v_xchg,
						      unf_prli_async_handle);
	else
		ret = unf_prli_handler_com_process(v_xchg);

	return ret;
}

static void unf_save_rscn_port_id(
			struct unf_rscn_mg_s *v_rscn_mg,
			struct unf_rscn_port_id_page_s *v_rscn_port_id)
{
	struct unf_port_id_page_s *exit_port_id_page = NULL;
	struct unf_port_id_page_s *new_port_id_page = NULL;
	struct list_head *node = NULL;
	struct list_head *next_node = NULL;
	unsigned long flag = 0;
	enum int_e repeat = UNF_FALSE;

	UNF_CHECK_VALID(0x3478, UNF_TRUE, v_rscn_mg, return);
	UNF_CHECK_VALID(0x3479, UNF_TRUE, v_rscn_port_id, return);

	/* 1. check new RSCN Port_ID (RSNC_Page)
	 * whether within RSCN_Mgr or not
	 */
	spin_lock_irqsave(&v_rscn_mg->rscn_id_list_lock, flag);
	if (list_empty(&v_rscn_mg->list_using_rscn_page)) {
		repeat = UNF_FALSE;
	} else {
		/* Check repeat: for each exist RSCN page
		 * form RSCN_Mgr Page list
		 */
		list_for_each_safe(node, next_node,
				   &v_rscn_mg->list_using_rscn_page) {
			exit_port_id_page =
				list_entry(node, struct unf_port_id_page_s,
					   list_node_rscn);
			if ((exit_port_id_page->port_id_port ==
			     v_rscn_port_id->port_id_port) &&
			    (exit_port_id_page->port_id_area ==
			     v_rscn_port_id->port_id_area) &&
			    (exit_port_id_page->port_id_domain ==
			     v_rscn_port_id->port_id_domain)) {
				repeat = UNF_TRUE;
				break;
			}
		}
	}
	spin_unlock_irqrestore(&v_rscn_mg->rscn_id_list_lock, flag);

	UNF_CHECK_VALID(0x3480, UNF_TRUE, v_rscn_mg->pfn_unf_get_free_rscn_node,
			return);

	/* 2. Get & add free RSNC Node --->>> RSCN_Mgr */
	if (repeat == UNF_FALSE) {
		new_port_id_page =
			v_rscn_mg->pfn_unf_get_free_rscn_node(v_rscn_mg);
		if (!new_port_id_page) {
			UNF_TRACE(UNF_EVTLOG_DRIVER_ERR,
				  UNF_LOG_LOGIN_ATT, UNF_ERR,
				  "[err]Get free RSCN node failed");

			return;
		}

		new_port_id_page->uc_addr_format = v_rscn_port_id->addr_format;
		new_port_id_page->uc_event_qualifier =
			v_rscn_port_id->event_qualifier;
		new_port_id_page->uc_reserved = v_rscn_port_id->reserved;
		new_port_id_page->port_id_domain =
			v_rscn_port_id->port_id_domain;
		new_port_id_page->port_id_area = v_rscn_port_id->port_id_area;
		new_port_id_page->port_id_port = v_rscn_port_id->port_id_port;

		/* Add entry to list: using_rscn_page */
		spin_lock_irqsave(&v_rscn_mg->rscn_id_list_lock, flag);
		list_add_tail(&new_port_id_page->list_node_rscn,
			      &v_rscn_mg->list_using_rscn_page);
		spin_unlock_irqrestore(&v_rscn_mg->rscn_id_list_lock, flag);
	} else {
		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT, UNF_MAJOR,
			  "[info]Port(0x%x) has repeat RSCN node with domain(0x%x) area(0x%x)",
			  v_rscn_port_id->port_id_domain,
			  v_rscn_port_id->port_id_area,
			  v_rscn_port_id->port_id_port);
	}
}

static unsigned int unf_analysis_rscn_payload(struct unf_lport_s *v_lport,
					      struct unf_rscn_pld_s *v_rscn_pld)
{
#define UNF_OS_DISC_REDISC_TIME 10000

	struct unf_rscn_port_id_page_s *rscn_port_id = NULL;
	struct unf_disc_s *disc = NULL;
	struct unf_rscn_mg_s *rscn_mgr = NULL;
	unsigned int i = 0;
	unsigned int pld_len = 0;
	unsigned int port_id_page_cnt = 0;
	unsigned int ret = RETURN_OK;
	unsigned long flag = 0;
	enum int_e need_disc_flag = UNF_FALSE;

	UNF_CHECK_VALID(0x3481, UNF_TRUE, v_lport, return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(0x3482, UNF_TRUE, v_rscn_pld, return UNF_RETURN_ERROR);

	/* This field is the length in bytes of the entire Payload,
	 * inclusive of the word 0
	 */
	pld_len = UNF_GET_RSCN_PLD_LEN(v_rscn_pld->cmnd);
	pld_len -= sizeof(v_rscn_pld->cmnd);
	port_id_page_cnt = pld_len / UNF_RSCN_PAGE_LEN;

	/* Pages within payload is nor more than 255 */
	if (port_id_page_cnt > UNF_RSCN_PAGE_SUM) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_LOGIN_ATT, UNF_ERR,
			  "[err]Port(0x%x_0x%x) page num(0x%x) exceed 255 in RSCN",
			  v_lport->port_id, v_lport->nport_id,
			  port_id_page_cnt);

		return UNF_RETURN_ERROR;
	}

	/* L_Port-->Disc-->Rscn_Mgr */
	disc = &v_lport->disc;
	rscn_mgr = &disc->rscn_mgr;

	/* for each ID from RSCN_Page: check whether need to Disc or not */
	while (i < port_id_page_cnt) {
		rscn_port_id = &v_rscn_pld->port_id_page[i];
		if (unf_lookup_lport_by_nport_id(v_lport, *(unsigned int *)rscn_port_id)) {
		/* Prevent to create session with L_Port which have the same N_Port_ID */
			UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT,
				  UNF_INFO,
				  "[info]Port(0x%x) find local N_Port_ID(0x%x) within RSCN payload",
				  ((struct unf_lport_s *)
				  (v_lport->root_lport))->nport_id,
				  *(unsigned int *)rscn_port_id);
		} else {
			/* New RSCN_Page ID find, save it to RSCN_Mgr */
			UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT,
				  UNF_INFO,
				  "[info]Port(0x%x_0x%x) save RSCN N_Port_ID(0x%x)",
				  v_lport->port_id, v_lport->nport_id,
				  *(unsigned int *)rscn_port_id);

			/* 1. new RSCN_Page ID find, save it to RSCN_Mgr */
			unf_save_rscn_port_id(rscn_mgr, rscn_port_id);
			need_disc_flag = UNF_TRUE;
			unf_report_io_dm_event(v_lport, ELS_RSCN,
					       *(unsigned int *)rscn_port_id);
		}
		i++;
	}

	if (need_disc_flag != UNF_TRUE) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_NORMAL, UNF_MAJOR,
			  "[info]Port(0x%x) find all N_Port_ID and do not need to disc",
			 ((struct unf_lport_s *)(v_lport->root_lport))->nport_id);

		return RETURN_OK;
	}

	/* 2. Do/Start Disc: Check & do Disc (GID_PT) process */
	if (!disc->unf_disc_temp.pfn_unf_disc_start) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT, UNF_WARN,
			  "[warn]Port(0x%x_0x%x) DISC start function is NULL",
			  v_lport->nport_id, v_lport->nport_id);

		return UNF_RETURN_ERROR;
	}

	spin_lock_irqsave(&disc->rport_busy_pool_lock, flag);
	if ((disc->en_states == UNF_DISC_ST_END) ||
	    ((jiffies - disc->last_disc_jiff) >
	    msecs_to_jiffies(UNF_OS_DISC_REDISC_TIME))) {
		disc->disc_option = UNF_RSCN_DISC;
		disc->last_disc_jiff = jiffies;
		spin_unlock_irqrestore(&disc->rport_busy_pool_lock, flag);

		ret = disc->unf_disc_temp.pfn_unf_disc_start(v_lport);
	} else {
		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_ABNORMAL, UNF_INFO,
			  "[info]Port(0x%x_0x%x) DISC state(0x%x) with last time(%llu) and don't do DISC",
			  v_lport->port_id, v_lport->nport_id,
			  disc->en_states, disc->last_disc_jiff);

		spin_unlock_irqrestore(&disc->rport_busy_pool_lock, flag);
	}

	return ret;
}

static unsigned int unf_rscn_handler(struct unf_lport_s *v_lport,
				     unsigned int v_sid,
				     struct unf_xchg_s *v_xchg)
{
	/*
	 * A RSCN ELS shall be sent to registered Nx_Ports
	 * when an event occurs that may have affected the state of
	 * one or more Nx_Ports, or the ULP state within the Nx_Port.
	 *
	 * The Payload of a RSCN Request includes a list
	 * containing the addresses of the affected Nx_Ports.
	 *
	 * Each affected Port_ID page contains the ID of the Nx_Port,
	 * Fabric Controller, E_Port, domain, or area for
	 * which the event was detected.
	 */
	struct unf_rscn_pld_s *rscn_pld = NULL;
	struct unf_rport_s *rport = NULL;
	unsigned int ret = UNF_RETURN_ERROR;
	unsigned int pld_len = 0;

	UNF_REFERNCE_VAR(pld_len);
	UNF_CHECK_VALID(0x3483, UNF_TRUE, v_lport, return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(0x3484, UNF_TRUE, v_xchg, return UNF_RETURN_ERROR);

	UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT, UNF_MAJOR,
		  "[info]Receive RSCN Port(0x%x_0x%x)<---RPort(0x%x) OX_ID(0x%x)",
		  v_lport->port_id, v_lport->nport_id, v_sid,
		  v_xchg->ox_id);

	UNF_SERVICE_COLLECT(v_lport->link_service_info,
			    UNF_SERVICE_ITEM_RSCN);

	/* 1. Get R_Port by S_ID */
	rport = unf_get_rport_by_nport_id(v_lport, v_sid);  // rport busy_list
	if (!rport) {
		rport = unf_rport_get_free_and_init(v_lport,
						    UNF_PORT_TYPE_FC, v_sid);
		if (!rport) {
			UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT,
				  UNF_WARN,
				  "[warn]Port(0x%x_0x%x) received RSCN but has no RPort(0x%x) with OX_ID(0x%x)",
				  v_lport->port_id, v_lport->nport_id,
				  v_sid, v_xchg->ox_id);

			unf_cm_free_xchg(v_lport, v_xchg);
			return UNF_RETURN_ERROR;
		}

		rport->nport_id = v_sid;
	}

	rscn_pld =
		v_xchg->fcp_sfs_union.sfs_entry.fc_sfs_entry_ptr->rscn.rscn_pld;
	UNF_CHECK_VALID(0x3485, UNF_TRUE, NULL != rscn_pld,
			return UNF_RETURN_ERROR);
	pld_len = UNF_GET_RSCN_PLD_LEN(rscn_pld->cmnd);
	UNF_PRINT_SFS_LIMIT(UNF_INFO, v_lport->port_id, rscn_pld, pld_len);

	/* 2. NOTE: Analysis RSCN payload(save & disc if necessary) */
	ret = unf_analysis_rscn_payload(v_lport, rscn_pld);
	if (ret != RETURN_OK)
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT, UNF_WARN,
			  "[warn]Port(0x%x_0x%x) analysis RSCN failed",
			  v_lport->port_id, v_lport->nport_id);

	/* 3. send rscn_acc after analysis payload */
	ret = unf_send_rscn_acc(v_lport, rport, v_xchg);
	if (ret != RETURN_OK) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT, UNF_WARN,
			  "[warn]Port(0x%x_0x%x) send RSCN response failed",
			  v_lport->port_id, v_lport->nport_id);

		return UNF_RETURN_ERROR;
	}

	UNF_REFERNCE_VAR(pld_len);
	return ret;
}

static void unf_analysis_pdisc_pld(struct unf_lport_s *v_lport,
				   struct unf_rport_s *v_rport,
				   struct unf_plogi_pdisc_s *v_pdisc)
{
	struct unf_lgn_parms_s *pdisc_params = NULL;
	unsigned long long wwpn = INVALID_VALUE64;
	unsigned long long wwnn = INVALID_VALUE64;

	UNF_CHECK_VALID(0x3486, UNF_TRUE, v_lport, return);
	UNF_CHECK_VALID(0x3487, UNF_TRUE, v_rport, return);
	UNF_CHECK_VALID(0x3488, UNF_TRUE, v_pdisc, return);
	UNF_REFERNCE_VAR(v_lport);

	pdisc_params = &v_pdisc->payload.parms;
	if (pdisc_params->co_parms.bb_receive_data_field_size >
	    UNF_MAX_FRAME_SIZE)
		v_rport->max_frame_size = UNF_MAX_FRAME_SIZE;  // 2112
	else
		v_rport->max_frame_size =
			pdisc_params->co_parms.bb_receive_data_field_size;

	wwnn = (unsigned long long)
		(((unsigned long long)
		(pdisc_params->high_node_name) << 32) |
		((unsigned long long)pdisc_params->low_node_name));
	wwpn = (unsigned long long)
		(((unsigned long long)(pdisc_params->high_port_name) << 32) |
		((unsigned long long)pdisc_params->low_port_name));

	v_rport->port_name = wwpn;
	v_rport->node_name = wwnn;

	UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT, UNF_MAJOR,
		  "[info]Port(0x%x) save PDISC parameters to Rport(0x%x) WWPN(0x%llx) WWNN(0x%llx)",
		  v_lport->port_id, v_rport->nport_id,
		  v_rport->port_name, v_rport->node_name);
}

static unsigned int unf_send_pdisc_rjt(struct unf_lport_s *v_lport,
				       struct unf_rport_s *v_rport,
				       struct unf_xchg_s *v_xchg)
{
	unsigned int ret = UNF_RETURN_ERROR;
	struct unf_rjt_info_s rjt_info;

	UNF_CHECK_VALID(0x3432, UNF_TRUE, v_lport, return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(0x3433, UNF_TRUE, v_rport, return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(0x3434, UNF_TRUE, v_xchg, return UNF_RETURN_ERROR);

	memset(&rjt_info, 0, sizeof(struct unf_rjt_info_s));
	rjt_info.els_cmnd_code = ELS_PDISC;
	rjt_info.reason_code = UNF_LS_RJT_LOGICAL_ERROR;
	rjt_info.reason_explanation = UNF_LS_RJT_NO_ADDITIONAL_INFO;

	ret = unf_send_els_rjt_by_rport(v_lport, v_xchg, v_rport, &rjt_info);

	return ret;
}

static unsigned int unf_pdisc_handler(struct unf_lport_s *v_lport,
				      unsigned int v_sid,
				      struct unf_xchg_s *v_xchg)
{
	struct unf_plogi_pdisc_s *pdisc = NULL;
	struct unf_rport_s *rport = NULL;
	unsigned long flags = 0;
	unsigned int ret = RETURN_OK;
	unsigned long long wwpn = 0;

	UNF_CHECK_VALID(0x3489, UNF_TRUE, v_lport, return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(0x3490, UNF_TRUE, v_xchg, return UNF_RETURN_ERROR);

	UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT, UNF_MAJOR,
		  "[info]LOGIN: Receive PDISC. Port(0x%x)<---RPort(0x%x) with OX_ID(0x%x)",
		  v_lport->port_id, v_sid, v_xchg->ox_id);

	UNF_SERVICE_COLLECT(v_lport->link_service_info, UNF_SERVICE_ITEM_PDISC);
	pdisc = &v_xchg->fcp_sfs_union.sfs_entry.fc_sfs_entry_ptr->pdisc;
	UNF_PRINT_SFS_LIMIT(UNF_INFO, v_lport->port_id,
			    &pdisc->payload,
			    sizeof(struct unf_plogi_payload_s));
	wwpn = (unsigned long long)
		(((unsigned long long)
		(pdisc->payload.parms.high_port_name) << 32) |
		((unsigned long long)pdisc->payload.parms.low_port_name));

	rport = unf_find_rport(v_lport, v_sid, wwpn);
	if (!rport) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT, UNF_WARN,
			  "[warn]Port(0x%x) can't find RPort by NPort ID(0x%x). Free exchange and send LOGO",
			  v_lport->port_id, v_sid);

		unf_cm_free_xchg(v_lport, v_xchg);
		(void)unf_send_logo_by_did(v_lport, v_sid);
	} else {
		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT, UNF_MINOR,
			  "[info]Port(0x%x) get exist RPort(0x%x) when receive PDISC with S_Id(0x%x)",
			  v_lport->port_id, rport->nport_id, v_sid);

		if (v_sid >= UNF_FC_FID_DOM_MGR)
			return unf_send_pdisc_rjt(v_lport, rport, v_xchg);

		unf_analysis_pdisc_pld(v_lport, rport, pdisc);

		/* State: READY */
		spin_lock_irqsave(&rport->rport_state_lock, flags);
		if (rport->rp_state == UNF_RPORT_ST_READY) {
			UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT,
				  UNF_MAJOR,
				  "[info]Port(0x%x) find RPort(0x%x) state is READY when receiving PDISC",
				  v_lport->port_id, v_sid);

			spin_unlock_irqrestore(&rport->rport_state_lock,
					       flags);

			ret = unf_send_pdisc_acc(v_lport, rport, v_xchg);
			if (ret != RETURN_OK) {
				UNF_TRACE(UNF_EVTLOG_DRIVER_WARN,
					  UNF_LOG_LOGIN_ATT, UNF_WARN,
					  "[warn]Port(0x%x) handle PDISC failed",
					 v_lport->port_id);

				return ret;
			}

			/* Report Down/Up event to scsi */
			unf_update_lport_state_by_linkup_event(v_lport, rport,
							       rport->options);
		}
		/* State: Closing */
		else if ((rport->rp_state == UNF_RPORT_ST_CLOSING) &&
			 (rport->session)) {
			UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT,
				  UNF_WARN,
				  "[warn]Port(0x%x) find RPort(0x%x) state is 0x%x when receiving PDISC",
				  v_lport->port_id, v_sid, rport->rp_state);

			spin_unlock_irqrestore(&rport->rport_state_lock,
					       flags);

			unf_cm_free_xchg(v_lport, v_xchg);
			(void)unf_send_logo_by_did(v_lport, v_sid);
		}
		/* State: PRLI_WAIT */
		else if (rport->rp_state == UNF_RPORT_ST_PRLI_WAIT) {
			UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT,
				  UNF_MAJOR,
				  "[info]Port(0x%x) find RPort(0x%x) state is 0x%x when receiving PDISC",
				  v_lport->port_id, v_sid, rport->rp_state);

			spin_unlock_irqrestore(&rport->rport_state_lock, flags);

			ret = unf_send_pdisc_acc(v_lport, rport, v_xchg);
			if (ret != RETURN_OK) {
				UNF_TRACE(UNF_EVTLOG_DRIVER_WARN,
					  UNF_LOG_LOGIN_ATT,
					  UNF_WARN,
					  "[warn]Port(0x%x) handle PDISC failed",
					 v_lport->port_id);

				return ret;
			}
		} else {
			UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT,
				  UNF_WARN,
				  "[warn]Port(0x%x) find RPort(0x%x) state is 0x%x when receiving PDISC, send LOGO",
				  v_lport->port_id, v_sid, rport->rp_state);

			unf_rport_state_ma(rport, UNF_EVENT_RPORT_LOGO);
			spin_unlock_irqrestore(&rport->rport_state_lock, flags);

			unf_rport_enter_logo(v_lport, rport);
			unf_cm_free_xchg(v_lport, v_xchg);
		}
	}

	return ret;
}

static void unf_analysis_adisc_pld(struct unf_lport_s *v_lport,
				   struct unf_rport_s *v_rport,
				   struct unf_adisc_payload_s *v_adisc_pld)
{
	unsigned long long wwpn = INVALID_VALUE64;
	unsigned long long wwnn = INVALID_VALUE64;

	UNF_CHECK_VALID(0x3491, UNF_TRUE, v_lport, return);
	UNF_CHECK_VALID(0x3492, UNF_TRUE, v_rport, return);
	UNF_CHECK_VALID(0x3493, UNF_TRUE, v_adisc_pld, return);
	UNF_REFERNCE_VAR(v_lport);

	wwnn = (unsigned long long)
		(((unsigned long long)(v_adisc_pld->high_node_name) << 32) |
			((unsigned long long)v_adisc_pld->low_node_name));
	wwpn = (unsigned long long)
		(((unsigned long long)(v_adisc_pld->high_port_name) << 32) |
			((unsigned long long)v_adisc_pld->low_port_name));

	v_rport->port_name = wwpn;
	v_rport->node_name = wwnn;

	UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT, UNF_MAJOR,
		  "[info]Port(0x%x) save ADISC parameters to RPort(0x%x), WWPN(0x%llx) WWNN(0x%llx) NPort ID(0x%x)",
		  v_lport->port_id, v_rport->nport_id,
		  v_rport->port_name, v_rport->node_name,
		  v_adisc_pld->nport_id);
}

static unsigned int unf_adisc_handler(struct unf_lport_s *v_lport,
				      unsigned int v_sid,
				      struct unf_xchg_s *v_xchg)
{
	struct unf_rport_s *rport = NULL;
	struct unf_adisc_payload_s *adisc_pld = NULL;
	unsigned long flags = 0;
	unsigned long long wwpn = 0;
	unsigned int ret = RETURN_OK;

	UNF_CHECK_VALID(0x3494, UNF_TRUE, v_lport, return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(0x3495, UNF_TRUE, v_xchg, return UNF_RETURN_ERROR);

	UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT, UNF_MAJOR,
		  "[info]LOGIN: Receive ADISC. Port(0x%x)<---RPort(0x%x) with OX_ID(0x%x)",
		  v_lport->port_id, v_sid, v_xchg->ox_id);

	UNF_SERVICE_COLLECT(v_lport->link_service_info,
			    UNF_SERVICE_ITEM_ADISC);
	adisc_pld = &v_xchg->fcp_sfs_union.sfs_entry.fc_sfs_entry_ptr->adisc.adisc_payl;
	UNF_PRINT_SFS_LIMIT(UNF_INFO, v_lport->port_id, adisc_pld,
			    sizeof(struct unf_adisc_payload_s));
	wwpn = (unsigned long long)
		(((unsigned long long)(adisc_pld->high_port_name) << 32) |
			((unsigned long long)adisc_pld->low_port_name));

	rport = unf_find_rport(v_lport, v_sid, wwpn);
	if (!rport) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT,
			  UNF_WARN,
			  "[warn]Port(0x%x) can't find RPort by NPort ID(0x%x). Free exchange and send LOGO",
			  v_lport->port_id, v_sid);

		unf_cm_free_xchg(v_lport, v_xchg);
		(void)unf_send_logo_by_did(v_lport, v_sid);

		return ret;
	}

	UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT, UNF_MINOR,
		  "[info]Port(0x%x) get exist RPort(0x%x) when receive ADISC with S_ID(0x%x)",
		  v_lport->port_id, rport->nport_id, v_sid);

	unf_analysis_adisc_pld(v_lport, rport, adisc_pld);

	/* State: READY */
	spin_lock_irqsave(&rport->rport_state_lock, flags);
	if (rport->rp_state == UNF_RPORT_ST_READY) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT,
			  UNF_MAJOR,
			  "[info]Port(0x%x) find RPort(0x%x) state is READY when receiving ADISC",
			  v_lport->port_id, v_sid);

		spin_unlock_irqrestore(&rport->rport_state_lock, flags);

		/* Return ACC directly */
		ret = unf_send_adisc_acc(v_lport, rport, v_xchg);
		if (ret != RETURN_OK) {
			UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT,
				  UNF_WARN,
				  "[warn]Port(0x%x) send ADISC ACC failed",
				  v_lport->port_id);

			return ret;
		}

		/* Report Down/Up event to SCSI */
		unf_update_lport_state_by_linkup_event(v_lport, rport,
						       rport->options);
	}
	/* State: Closing */
	else if ((rport->rp_state == UNF_RPORT_ST_CLOSING) &&
		 (rport->session)) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT, UNF_WARN,
			  "[warn]Port(0x%x) find RPort(0x%x) state is 0x%x when receiving ADISC",
			  v_lport->port_id, v_sid, rport->rp_state);

		spin_unlock_irqrestore(&rport->rport_state_lock, flags);

		rport = unf_get_safe_rport(v_lport, rport,
					   UNF_RPORT_REUSE_RECOVER,
					   rport->nport_id);
		if (rport) {
			spin_lock_irqsave(&rport->rport_state_lock, flags);
			rport->nport_id = v_sid;
			spin_unlock_irqrestore(&rport->rport_state_lock,
					       flags);

			ret = unf_send_adisc_acc(v_lport, rport, v_xchg);
			if (ret != RETURN_OK) {
				UNF_TRACE(UNF_EVTLOG_DRIVER_WARN,
					  UNF_LOG_LOGIN_ATT, UNF_WARN,
					  "[warn]Port(0x%x) send ADISC ACC failed",
					 v_lport->port_id);

				return ret;
			}

			unf_update_lport_state_by_linkup_event(v_lport, rport,
							       rport->options);
		} else {
			UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT,
				  UNF_WARN,
				  "[warn]Port(0x%x) can't find RPort by NPort_ID(0x%x). Free exchange and send LOGO",
				  v_lport->port_id, v_sid);

			unf_cm_free_xchg(v_lport, v_xchg);
			(void)unf_send_logo_by_did(v_lport, v_sid);
		}
	}
	/* State: PRLI_WAIT */
	else if (rport->rp_state == UNF_RPORT_ST_PRLI_WAIT) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT, UNF_MAJOR,
			  "[info]Port(0x%x) find RPort(0x%x) state is 0x%x when receiving ADISC",
			  v_lport->port_id, v_sid, rport->rp_state);

		spin_unlock_irqrestore(&rport->rport_state_lock, flags);

		ret = unf_send_adisc_acc(v_lport, rport, v_xchg);
		if (ret != RETURN_OK) {
			UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT,
				  UNF_WARN,
				  "[warn]Port(0x%x) send ADISC ACC failed",
				  v_lport->port_id);

			return ret;
		}
	} else {
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT, UNF_WARN,
			  "[warn]Port(0x%x) find RPort(0x%x) state is 0x%x when receiving ADISC, send LOGO",
			  v_lport->port_id, v_sid, rport->rp_state);

		unf_rport_state_ma(rport, UNF_EVENT_RPORT_LOGO);
		spin_unlock_irqrestore(&rport->rport_state_lock, flags);

		unf_rport_enter_logo(v_lport, rport);
		unf_cm_free_xchg(v_lport, v_xchg);
	}

	return ret;
}

static unsigned int unf_rec_handler(struct unf_lport_s *v_lport,
				    unsigned int v_sid,
				    struct unf_xchg_s *v_xchg)
{
	struct unf_rport_s *rport = NULL;
	unsigned int ret = UNF_RETURN_ERROR;

	UNF_CHECK_VALID(0x3496, UNF_TRUE, v_lport, return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(0x3497, UNF_TRUE, v_xchg, return UNF_RETURN_ERROR);
	UNF_REFERNCE_VAR(v_sid);

	UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT, UNF_MAJOR,
		  "[info]LOGIN: Port(0x%x) receive REC", v_lport->port_id);

	/* Send rec acc */
	ret = unf_send_rec_acc(v_lport, rport, v_xchg);  // discard directly

	return ret;
}

static unsigned int unf_rrq_handler(struct unf_lport_s *v_lport,
				    unsigned int v_sid,
				    struct unf_xchg_s *v_xchg)
{
	struct unf_rport_s *rport = NULL;
	struct unf_rrq_s *rrq = NULL;
	struct unf_xchg_s *xchg_reused = NULL;
	unsigned int ret = UNF_RETURN_ERROR;
	unsigned short ox_id = 0;
	unsigned short rx_id = 0;
	unsigned int sid = 0;
	unsigned long flags = 0;
	struct unf_rjt_info_s rjt_info = { 0 };
	struct unf_xchg_hot_pool_s *hot_pool = NULL;

	UNF_CHECK_VALID(0x3498, UNF_TRUE, v_lport, return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(0x3499, UNF_TRUE, v_xchg, return UNF_RETURN_ERROR);
	UNF_REFERNCE_VAR(rx_id);

	UNF_SERVICE_COLLECT(v_lport->link_service_info, UNF_SERVICE_ITEM_RRQ);
	rrq = &v_xchg->fcp_sfs_union.sfs_entry.fc_sfs_entry_ptr->rrq;
	ox_id = (unsigned short)(rrq->oxid_rxid >> 16);
	rx_id = (unsigned short)(rrq->oxid_rxid);
	sid = rrq->sid & UNF_NPORTID_MASK;

	UNF_TRACE(UNF_EVTLOG_IO_INFO, UNF_LOG_IO_ATT, UNF_KEVENT,
		  "[warn]Receive RRQ. Port(0x%x)<---RPort(0x%x) sfsXchg(0x%p) OX_ID(0x%x,0x%x) RX_ID(0x%x)",
		  v_lport->port_id, v_sid, v_xchg,
		  ox_id, v_xchg->ox_id, rx_id);

	/* Get R_Port */
	rport = unf_get_rport_by_nport_id(v_lport, v_sid);
	if (!rport) {
		UNF_TRACE(UNF_EVTLOG_IO_WARN, UNF_LOG_IO_ATT, UNF_WARN,
			  "[warn]Port(0x%x) receive RRQ but has no RPort(0x%x)",
			  v_lport->port_id, v_sid);

		/* NOTE: send LOGO */
		ret = unf_send_logo_by_did(v_lport, sid);

		unf_cm_free_xchg(v_lport, v_xchg);
		return ret;
	}

	/* Get Target (Abort I/O) exchange context */
	/* UNF_FindXchgByOxId */
	xchg_reused = unf_cm_lookup_xchg_by_id(v_lport, ox_id, sid);
	if (!xchg_reused) {
		UNF_TRACE(UNF_EVTLOG_IO_WARN, UNF_LOG_IO_ATT, UNF_WARN,
			  "[warn]Port(0x%x) cannot find exchange with OX_ID(0x%x) RX_ID(0x%x) S_ID(0x%x)",
			  v_lport->port_id, ox_id, rx_id, sid);

		rjt_info.els_cmnd_code = ELS_RRQ;
		rjt_info.reason_code = FCXLS_BA_RJT_LOGICAL_ERROR |
			FCXLS_LS_RJT_INVALID_OXID_RXID;

		/* NOTE: send ELS RJT */
		if (unf_send_els_rjt_by_rport(v_lport, v_xchg,
					      rport, &rjt_info) !=
		    RETURN_OK) {
			unf_cm_free_xchg(v_lport, v_xchg);
			return UNF_RETURN_ERROR;
		}

		return RETURN_OK;
	}

	hot_pool = xchg_reused->hot_pool;
	if (unlikely(!hot_pool)) {
		UNF_TRACE(UNF_EVTLOG_IO_INFO, UNF_LOG_IO_ATT, UNF_MAJOR,
			  "Port(0x%x) OxId(0x%x) Rxid(0x%x) Sid(0x%x) Hot Pool is NULL.",
			  v_lport->port_id, ox_id, rx_id, sid);

		return ret;
	}

	spin_lock_irqsave(&hot_pool->xchg_hot_pool_lock, flags);
	xchg_reused->ox_id = INVALID_VALUE16;
	xchg_reused->rx_id = INVALID_VALUE16;
	spin_unlock_irqrestore(&hot_pool->xchg_hot_pool_lock, flags);

	/* NOTE: release I/O exchange context */
	unf_xchg_ref_dec(xchg_reused, SFS_RESPONSE);

	/* Send RRQ ACC */
	ret = unf_send_rrq_acc(v_lport, rport, v_xchg);
	if (ret != RETURN_OK) {
		UNF_TRACE(UNF_EVTLOG_IO_WARN, UNF_LOG_IO_ATT, UNF_WARN,
			  "[warn]Port(0x%x) can not send RRQ rsp. Xchg(0x%p) Ioxchg(0x%p) OX_RX_ID(0x%x 0x%x) S_ID(0x%x)",
			  v_lport->port_id, v_xchg,
			  xchg_reused, ox_id, rx_id, sid);

		unf_cm_free_xchg(v_lport, v_xchg);
		return ret;
	}

	UNF_REFERNCE_VAR(rx_id);
	return ret;
}

static unsigned int unf_send_els_rjt_by_rport(struct unf_lport_s *v_lport,
					      struct unf_xchg_s *v_xchg,
					      struct unf_rport_s *v_rport,
					      struct unf_rjt_info_s *v_rjt_info)
{
	struct unf_els_rjt_s *els_rjt = NULL;
	union unf_sfs_u *fc_entry = NULL;
	struct unf_xchg_s *xchg = v_xchg;
	struct unf_frame_pkg_s pkg = { 0 };
	unsigned int ret = UNF_RETURN_ERROR;
	unsigned short ox_id = 0;
	unsigned short rx_id = 0;

	UNF_REFERNCE_VAR(ox_id);
	UNF_REFERNCE_VAR(rx_id);

	UNF_CHECK_VALID(0x3500, UNF_TRUE, v_lport, return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(0x3501, UNF_TRUE, v_xchg, return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(0x3502, UNF_TRUE, v_rport, return UNF_RETURN_ERROR);

	xchg->cmnd_code = UNF_SET_ELS_RJT_TYPE(v_rjt_info->els_cmnd_code);
	xchg->did = v_rport->nport_id;
	xchg->sid = v_lport->nport_id;
	xchg->oid = xchg->sid;
	xchg->lport = v_lport;
	xchg->rport = v_rport;
	xchg->disc_rport = NULL;

	xchg->pfn_callback = NULL;
	xchg->pfn_ob_callback = NULL;

	unf_fill_package(&pkg, xchg, v_rport);

	fc_entry = xchg->fcp_sfs_union.sfs_entry.fc_sfs_entry_ptr;
	if (!fc_entry) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT, UNF_WARN,
			  "[warn]Port(0x%x) entry can't be NULL with tag(0x%x)",
			  v_lport->port_id, xchg->hot_pool_tag);

		unf_cm_free_xchg(v_lport, xchg);
		return UNF_RETURN_ERROR;
	}

	els_rjt = &fc_entry->els_rjt;
	memset(els_rjt, 0, sizeof(struct unf_els_rjt_s));
	unf_fill_rjt_pld(els_rjt, v_rjt_info->reason_code,
			 v_rjt_info->reason_explanation);
	ox_id = v_xchg->ox_id;
	rx_id = v_xchg->rx_id;

	ret = unf_els_cmnd_send(v_lport, &pkg, xchg);
	if (ret != RETURN_OK)
		unf_cm_free_xchg((void *)v_lport, (void *)xchg);

	UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT, UNF_MAJOR,
		  "[info]LOGIN: Send LS_RJT for 0x%x %s. Port(0x%x)--->rport(0x%x) with OX_ID(0x%x) RX_ID(0x%x)",
		  v_rjt_info->els_cmnd_code,
		  (ret != RETURN_OK) ? "failed" : "succeed",
		  v_lport->port_id, v_rport->nport_id, ox_id, rx_id);

	UNF_REFERNCE_VAR(ox_id);
	UNF_REFERNCE_VAR(rx_id);

	return ret;
}

static unsigned int unf_els_cmnd_default_handler(struct unf_lport_s *v_lport,
						 struct unf_xchg_s *v_xchg,
						 unsigned int v_sid,
						 unsigned int v_els_cmnd_code)
{
#define ELS_LCB 0X81
#define ELS_RDP 0X18

	struct unf_rport_s *rport = NULL;
	struct unf_rjt_info_s rjt_info = { 0 };
	unsigned int ret = UNF_RETURN_ERROR;

	UNF_CHECK_VALID(0x3505, UNF_TRUE, v_lport, return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(0x3506, UNF_TRUE, v_xchg, return UNF_RETURN_ERROR);

	if ((v_els_cmnd_code != ELS_LCB) && (v_els_cmnd_code != ELS_RDP)) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_ABNORMAL, UNF_KEVENT,
			  "[info]Receive Unknown ELS command(0x%x). Port(0x%x)<---RPort(0x%x) with OX_ID(0x%x)",
			  v_els_cmnd_code, v_lport->port_id, v_sid,
			  v_xchg->ox_id);
	}

	memset(&rjt_info, 0, sizeof(struct unf_rjt_info_s));
	rjt_info.els_cmnd_code = v_els_cmnd_code;
	rjt_info.reason_code = UNF_LS_RJT_NOT_SUPPORTED;

	rport = unf_get_rport_by_nport_id(v_lport, v_sid);
	if (rport)
		ret = unf_send_els_rjt_by_rport(v_lport, v_xchg, rport,
						&rjt_info);
	else
		ret = unf_send_els_rjt_by_did(v_lport, v_xchg, v_sid,
					      &rjt_info);

	return ret;
}

static struct unf_xchg_s *unf_alloc_xchg_for_rcv_cmnd(
					struct unf_lport_s *v_lport,
					struct unf_frame_pkg_s *v_pkg)
{
	struct unf_xchg_s *xchg = NULL;
	unsigned long flags = 0;
	unsigned int i = 0;
	unsigned int offset = 0;
	unsigned char *cmnd_pld = NULL;
	unsigned int first_dword = 0;
	unsigned int alloc_time = 0;

	UNF_CHECK_VALID(0x3508, UNF_TRUE, v_lport, return NULL);
	UNF_CHECK_VALID(0x3509, UNF_TRUE, v_pkg, return NULL);

	if (!v_pkg->xchg_contex) {
		xchg = unf_cm_get_free_xchg(v_lport, UNF_XCHG_TYPE_SFS);
		if (!xchg) {
			UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT,
				  UNF_MAJOR,
				  "[warn]Port(0x%x) get new exchange failed",
				  v_lport->port_id);

			return NULL;
		}

		offset = (xchg->fcp_sfs_union.sfs_entry.cur_offset);
		cmnd_pld = (unsigned char *)xchg->fcp_sfs_union.sfs_entry.fc_sfs_entry_ptr->rscn.rscn_pld;
		first_dword = xchg->fcp_sfs_union.sfs_entry.fc_sfs_entry_ptr->sfs_common.frame_head.rctl_did;

		if ((cmnd_pld) || (first_dword != 0) || (offset != 0)) {
			UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT,
				  UNF_WARN,
				  "[warn]Port(0x%x) exchange(0x%p) abnormal, maybe data overrun, start(%llu) command(0x%x)",
				  v_lport->port_id, xchg,
				  xchg->alloc_jif, v_pkg->cmnd);

			UNF_PRINT_SFS(UNF_INFO, v_lport->port_id,
				      xchg->fcp_sfs_union.sfs_entry.fc_sfs_entry_ptr,
				      sizeof(union unf_sfs_u));
		}

		memset(xchg->fcp_sfs_union.sfs_entry.fc_sfs_entry_ptr, 0,
		       sizeof(union unf_sfs_u));

		v_pkg->xchg_contex = (void *)xchg;

		spin_lock_irqsave(&xchg->xchg_state_lock, flags);
		xchg->fcp_sfs_union.sfs_entry.cur_offset = 0;
		alloc_time = xchg->private[PKG_PRIVATE_XCHG_ALLOC_TIME];
		for (i = 0; i < PKG_MAX_PRIVATE_DATA_SIZE; i++)
			xchg->private[i] = v_pkg->private[i];

		xchg->private[PKG_PRIVATE_XCHG_ALLOC_TIME] = alloc_time;
		spin_unlock_irqrestore(&xchg->xchg_state_lock, flags);
	} else {
		xchg = (struct unf_xchg_s *)v_pkg->xchg_contex;
	}

	if (!xchg->fcp_sfs_union.sfs_entry.fc_sfs_entry_ptr) {
		unf_cm_free_xchg((void *)v_lport, (void *)xchg);

		return NULL;
	}

	return xchg;
}

static unsigned char *unf_calc_big_cmnd_pld_buffer(struct unf_xchg_s *v_xchg,
						   unsigned int v_cmnd_code)
{
	unsigned char *cmnd_pld = NULL;
	void *buf = NULL;
	unsigned char *dest = NULL;

	UNF_CHECK_VALID(0x3510, UNF_TRUE, v_xchg, return NULL);

	if (v_cmnd_code == ELS_RSCN)
		cmnd_pld = (unsigned char *)v_xchg->fcp_sfs_union.sfs_entry.fc_sfs_entry_ptr->rscn.rscn_pld;
	else
		cmnd_pld = (unsigned char *)v_xchg->fcp_sfs_union.sfs_entry.fc_sfs_entry_ptr->echo.echo_pld;

	if (!cmnd_pld) {
		buf = unf_get_one_big_sfs_buf(v_xchg);
		if (!buf)
			return NULL;

		if (v_cmnd_code == ELS_RSCN) {
			memset(buf, 0, sizeof(struct unf_rscn_pld_s));
			v_xchg->fcp_sfs_union.sfs_entry.fc_sfs_entry_ptr->rscn.rscn_pld = buf;
		} else {
			memset(buf, 0, sizeof(struct unf_echo_payload_s));
			v_xchg->fcp_sfs_union.sfs_entry.fc_sfs_entry_ptr->echo.echo_pld = buf;
		}

		dest = (unsigned char *)buf;
	} else {
		dest = (unsigned char *)
		       (cmnd_pld + v_xchg->fcp_sfs_union.sfs_entry.cur_offset);
	}

	return dest;
}

static unsigned char *unf_calc_other_pld_buffer(struct unf_xchg_s *v_xchg)
{
	unsigned char *dest = NULL;
	unsigned int offset = 0;

	UNF_CHECK_VALID(0x3511, UNF_TRUE, v_xchg, return NULL);

	offset = (sizeof(struct unf_fchead_s)) +
		(v_xchg->fcp_sfs_union.sfs_entry.cur_offset);
	dest = (unsigned char *)
		((unsigned char *)
			(v_xchg->fcp_sfs_union.sfs_entry.fc_sfs_entry_ptr) +
				 offset);

	return dest;
}

static struct unf_xchg_s *unf_mv_data_2_xchg(struct unf_lport_s *v_lport,
					     struct unf_frame_pkg_s *v_pkg)
{
	struct unf_xchg_s *xchg = NULL;
	unsigned char *dest = NULL;
	unsigned int length = 0;
	unsigned long flags = 0;

	UNF_CHECK_VALID(0x3512, UNF_TRUE, v_lport, return NULL);
	UNF_CHECK_VALID(0x3513, UNF_TRUE, v_pkg, return NULL);

	xchg = unf_alloc_xchg_for_rcv_cmnd(v_lport, v_pkg);
	if (!xchg)
		return NULL;

	spin_lock_irqsave(&xchg->xchg_state_lock, flags);

	memcpy(&xchg->fcp_sfs_union.sfs_entry.fc_sfs_entry_ptr->sfs_common.frame_head,
	       &v_pkg->frame_head,
	       sizeof(v_pkg->frame_head));

	if ((v_pkg->cmnd == ELS_RSCN) || (v_pkg->cmnd == ELS_ECHO))
		dest = unf_calc_big_cmnd_pld_buffer(xchg, v_pkg->cmnd);
	else
		dest = unf_calc_other_pld_buffer(xchg);

	if (!dest) {
		spin_unlock_irqrestore(&xchg->xchg_state_lock, flags);
		unf_cm_free_xchg((void *)v_lport, (void *)xchg);

		return NULL;
	}

	if (((xchg->fcp_sfs_union.sfs_entry.cur_offset +
	      v_pkg->unf_cmnd_pload_bl.length) >
	     (unsigned int)sizeof(union unf_sfs_u)) &&
	    (v_pkg->cmnd != ELS_RSCN) &&
	    (v_pkg->cmnd != ELS_ECHO)) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT, UNF_WARN,
			  "[warn]Port(0x%x) excange(0x%p) command(0x%x,0x%x) copy payload overrun(0x%x:0x%x:0x%x)",
			  v_lport->port_id, xchg, v_pkg->cmnd,
			  xchg->hot_pool_tag,
			  xchg->fcp_sfs_union.sfs_entry.cur_offset,
			  v_pkg->unf_cmnd_pload_bl.length,
			  (unsigned int)sizeof(union unf_sfs_u));

		spin_unlock_irqrestore(&xchg->xchg_state_lock, flags);
		unf_cm_free_xchg((void *)v_lport, (void *)xchg);

		return NULL;
	}

	length = v_pkg->unf_cmnd_pload_bl.length;
	if (length > 0)
		memcpy(dest, v_pkg->unf_cmnd_pload_bl.buffer_ptr, length);

	xchg->fcp_sfs_union.sfs_entry.cur_offset += length;
	spin_unlock_irqrestore(&xchg->xchg_state_lock, flags);

	return xchg;
}

static unsigned int unf_logo_handler(struct unf_lport_s *v_lport,
				     unsigned int v_sid,
				     struct unf_xchg_s *v_xchg)
{
	struct unf_rport_s *rport = NULL;
	struct unf_rport_s *logo_rport = NULL;
	struct unf_logo_s *logo = NULL;
	unsigned int ret = UNF_RETURN_ERROR;
	unsigned int nport_id = 0;
	struct unf_rjt_info_s rjt_info = { 0 };

	UNF_REFERNCE_VAR(logo);
	UNF_CHECK_VALID(0x3514, UNF_TRUE, v_lport, return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(0x3515, UNF_TRUE, v_xchg, return UNF_RETURN_ERROR);

	UNF_SERVICE_COLLECT(v_lport->link_service_info, UNF_SERVICE_ITEM_LOGO);
	logo = &v_xchg->fcp_sfs_union.sfs_entry.fc_sfs_entry_ptr->logo;
	nport_id = logo->payload.nport_id & UNF_NPORTID_MASK;

	if (v_sid < UNF_FC_FID_DOM_MGR) {
		/* R_Port is not fabric port */
		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT,
			  UNF_KEVENT,
			  "[info]LOGIN: Receive LOGO. Port(0x%x)<---RPort(0x%x) NPort_ID(0x%x) OXID(0x%x)",
			  v_lport->port_id, v_sid, nport_id, v_xchg->ox_id);
	}

	UNF_PRINT_SFS_LIMIT(UNF_INFO, v_lport->port_id, &logo->payload,
			    sizeof(struct unf_logo_payload_s));

	/*
	 * 1. S_ID unequal to NPort_ID:
	 * link down Rport find by NPort_ID immediately
	 */
	if (nport_id != v_sid) {
		logo_rport = unf_get_rport_by_nport_id(v_lport, nport_id);
		if (logo_rport)
			unf_rport_immediate_linkdown(v_lport, logo_rport);
	}

	/* 2. Get R_Port by S_ID (frame header) */
	rport = unf_get_rport_by_nport_id(v_lport, v_sid);
	rport = unf_get_safe_rport(v_lport, rport, UNF_RPORT_REUSE_INIT,
				   v_sid);  // INIT
	if (!rport) {
		memset(&rjt_info, 0, sizeof(struct unf_rjt_info_s));
		rjt_info.els_cmnd_code = ELS_LOGO;
		rjt_info.reason_code = UNF_LS_RJT_LOGICAL_ERROR;
		rjt_info.reason_explanation = UNF_LS_RJT_NO_ADDITIONAL_INFO;
		ret = unf_send_els_rjt_by_did(v_lport, v_xchg, v_sid,
					      &rjt_info);

		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT,
			  UNF_WARN,
			  "[warn]Port(0x%x) receive LOGO but has no RPort(0x%x)",
			  v_lport->port_id, v_sid);

		return ret;
	}

	/*
	 * 3. I/O resource release: set ABORT tag
	 *
	 * Call by: R_Port remove; RCVD LOGO; RCVD PLOGI; send PLOGI ACC
	 */
	unf_cm_xchg_mgr_abort_io_by_id(v_lport, rport, v_sid, v_lport->nport_id,
				       INI_IO_STATE_LOGO);

	/* 4. Send LOGO ACC */
	ret = unf_send_logo_acc(v_lport, rport, v_xchg);
	if (ret != RETURN_OK)
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT,
			  UNF_WARN,
			  "[warn]Port(0x%x) send LOGO failed",
			  v_lport->port_id);

	/*
	 * 5. Do same operations with RCVD LOGO/PRLO & Send LOGO:
	 * retry (LOGIN or LOGO) or link down immediately
	 */
	unf_process_rport_after_logo(v_lport, rport);

	return ret;
}

static unsigned int unf_prlo_handler(struct unf_lport_s *v_lport,
				     unsigned int v_sid,
				     struct unf_xchg_s *v_xchg)
{
	struct unf_rport_s *rport = NULL;
	struct unf_prli_prlo_s *prlo = NULL;
	unsigned int ret = UNF_RETURN_ERROR;

	UNF_REFERNCE_VAR(prlo);
	UNF_CHECK_VALID(0x3516, UNF_TRUE, v_lport, return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(0x3517, UNF_TRUE, v_xchg, return UNF_RETURN_ERROR);

	UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT, UNF_MAJOR,
		  "[info]LOGIN: Receive PRLO. Port(0x%x)<---RPort(0x%x) with OX_ID(0x%x)",
		  v_lport->port_id, v_sid, v_xchg->ox_id);

	UNF_SERVICE_COLLECT(v_lport->link_service_info, UNF_SERVICE_ITEM_LOGO);

	/* Get (new) R_Port */
	rport = unf_get_rport_by_nport_id(v_lport, v_sid);
	rport = unf_get_safe_rport(v_lport, rport,
				   UNF_RPORT_REUSE_INIT, v_sid);  /* INIT */
	if (!rport) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT, UNF_WARN,
			  "[warn]Port(0x%x) receive PRLO but has no RPort",
			  v_lport->port_id);

		/* Discard directly */
		unf_cm_free_xchg(v_lport, v_xchg);
		return ret;
	}

	prlo = &v_xchg->fcp_sfs_union.sfs_entry.fc_sfs_entry_ptr->prlo;
	UNF_PRINT_SFS_LIMIT(UNF_INFO, v_lport->port_id, &prlo->payload,
			    sizeof(struct unf_pril_payload_s));

	/* Send PRLO ACC to remote */
	ret = unf_send_prlo_acc(v_lport, rport, v_xchg);
	if (ret != RETURN_OK)
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT,
			  UNF_WARN,
			  "[warn]Port(0x%x) send PRLO ACC failed",
			  v_lport->port_id);

	/* Enter Enhanced action after LOGO (retry LOGIN or LOGO) */
	unf_process_rport_after_logo(v_lport, rport);

	UNF_REFERNCE_VAR(prlo);
	return ret;
}

static void unf_fill_echo_acc_pld(struct unf_echo_s *v_echo_acc)
{
	struct unf_echo_payload_s *echo_acc_pld = NULL;

	UNF_CHECK_VALID(0x3518, UNF_TRUE, v_echo_acc, return);

	echo_acc_pld = v_echo_acc->echo_pld;
	UNF_CHECK_VALID(0x3519, UNF_TRUE, echo_acc_pld, return);

	echo_acc_pld->cmnd = UNF_ELS_CMND_ACC;
}

static void unf_echo_acc_callback(struct unf_xchg_s *v_xchg)
{
	struct unf_lport_s *lport;

	UNF_CHECK_VALID(0x3517, UNF_TRUE, v_xchg, return);

	lport = v_xchg->lport;

	UNF_CHECK_VALID(0x3517, UNF_TRUE, lport, return);
	if (v_xchg->fcp_sfs_union.sfs_entry.fc_sfs_entry_ptr->echo_acc.phy_echo_addr) {
		pci_unmap_single(
			lport->low_level_func.dev,
			v_xchg->fcp_sfs_union.sfs_entry.fc_sfs_entry_ptr->echo_acc.phy_echo_addr,
			UNF_ECHO_PAYLOAD_LEN,
			DMA_BIDIRECTIONAL);
		v_xchg->fcp_sfs_union.sfs_entry.fc_sfs_entry_ptr->echo_acc.phy_echo_addr = 0;
	}
}

static unsigned int unf_send_echo_acc(struct unf_lport_s *v_lport,
				      unsigned int v_did,
				      struct unf_xchg_s *v_xchg)
{
	struct unf_echo_s *echo_acc = NULL;
	union unf_sfs_u *fc_entry = NULL;
	unsigned int ret = UNF_RETURN_ERROR;
	unsigned short ox_id = 0;
	unsigned short rx_id = 0;
	struct unf_frame_pkg_s pkg;
	dma_addr_t phy_echo_acc_addr;
	struct unf_rjt_info_s rjt_info = { 0 };

	UNF_REFERNCE_VAR(ox_id);
	UNF_REFERNCE_VAR(rx_id);

	UNF_CHECK_VALID(0x3520, UNF_TRUE, v_lport, return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(0x3521, UNF_TRUE, v_xchg, return UNF_RETURN_ERROR);

	memset(&pkg, 0, sizeof(struct unf_frame_pkg_s));
	v_xchg->cmnd_code = UNF_SET_ELS_ACC_TYPE(ELS_ECHO);
	v_xchg->did = v_did;
	v_xchg->sid = v_lport->nport_id;
	v_xchg->oid = v_xchg->sid;
	v_xchg->lport = v_lport;

	v_xchg->pfn_callback = NULL;
	v_xchg->pfn_ob_callback = unf_echo_acc_callback;

	unf_fill_package(&pkg, v_xchg, v_xchg->rport);

	fc_entry = v_xchg->fcp_sfs_union.sfs_entry.fc_sfs_entry_ptr;
	if (!fc_entry) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT, UNF_WARN,
			  "[warn]Port(0x%x) entry can't be NULL with tag(0x%x)",
			  v_lport->port_id, v_xchg->hot_pool_tag);

		unf_cm_free_xchg(v_lport, v_xchg);
		return UNF_RETURN_ERROR;
	}

	echo_acc = &fc_entry->echo_acc;
	unf_fill_echo_acc_pld(echo_acc);
	ox_id = v_xchg->ox_id;
	rx_id = v_xchg->rx_id;
	phy_echo_acc_addr = pci_map_single(v_lport->low_level_func.dev,
					   echo_acc->echo_pld,
					   UNF_ECHO_PAYLOAD_LEN,
					   DMA_BIDIRECTIONAL);
	if (pci_dma_mapping_error(v_lport->low_level_func.dev,
				  phy_echo_acc_addr)) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT,
			  UNF_WARN,
			  "[warn]Port(0x%x) pci map err",
			  v_lport->port_id);
		unf_cm_free_xchg(v_lport, v_xchg);
		return UNF_RETURN_ERROR;
	}
	echo_acc->phy_echo_addr = phy_echo_acc_addr;

	ret = unf_els_cmnd_send(v_lport, &pkg, v_xchg);
	if (ret != RETURN_OK) {
		pci_unmap_single(v_lport->low_level_func.dev,
				 phy_echo_acc_addr,
				 UNF_ECHO_PAYLOAD_LEN,
				 DMA_BIDIRECTIONAL);
		echo_acc->phy_echo_addr = 0;
		if (ret == UNF_RETURN_NOT_SUPPORT) {
			UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT,
				  UNF_KEVENT,
				  "[info]Port(0x%x) send ECHO reject to RPort(0x%x) with OX_ID(0x%x) RX_ID(0x%x)",
				  v_lport->port_id, v_did, ox_id, rx_id);

			rjt_info.els_cmnd_code = ELS_ECHO;
			rjt_info.reason_code = UNF_LS_RJT_NOT_SUPPORTED;
			unf_send_els_rjt_by_rport(v_lport, v_xchg,
						  v_xchg->rport,
						  &rjt_info);
		} else {
			UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT,
				  UNF_WARN,
				  "[warn]Port(0x%x) send ECHO ACC to RPort(0x%x) with OX_ID(0x%x) RX_ID(0x%x) failed",
				  v_lport->port_id, v_did, ox_id, rx_id);

			unf_cm_free_xchg((void *)v_lport, (void *)v_xchg);
		}
	}

	UNF_REFERNCE_VAR(ox_id);
	UNF_REFERNCE_VAR(rx_id);
	return ret;
}

static unsigned int unf_echo_handler(struct unf_lport_s *v_lport,
				     unsigned int v_sid,
				     struct unf_xchg_s *v_xchg)
{
	struct unf_echo_payload_s *echo_pld = NULL;
	struct unf_rport_s *rport = NULL;
	unsigned int ret = UNF_RETURN_ERROR;
	unsigned int data_len = 0;

	UNF_CHECK_VALID(0x3522, UNF_TRUE, v_lport, return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(0x3523, UNF_TRUE, v_xchg, return UNF_RETURN_ERROR);

	data_len = v_xchg->fcp_sfs_union.sfs_entry.cur_offset;

	UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT, UNF_MAJOR,
		  "[info]Receive ECHO. Port(0x%x)<---RPort(0x%x) with OX_ID(0x%x))",
		  v_lport->port_id, v_sid, v_xchg->ox_id);

	UNF_SERVICE_COLLECT(v_lport->link_service_info, UNF_SERVICE_ITEM_ECHO);
	echo_pld = v_xchg->fcp_sfs_union.sfs_entry.fc_sfs_entry_ptr->echo.echo_pld;
	UNF_PRINT_SFS_LIMIT(UNF_INFO, v_lport->port_id, echo_pld, data_len);
	rport = unf_get_rport_by_nport_id(v_lport, v_sid);
	v_xchg->rport = rport;

	ret = unf_send_echo_acc(v_lport, v_sid, v_xchg);
	if (ret != RETURN_OK)
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT, UNF_WARN,
			  "[warn]Port(0x%x) send ECHO ACC failed",
			  v_lport->port_id);

	UNF_REFERNCE_VAR(echo_pld);
	UNF_REFERNCE_VAR(data_len);
	return ret;
}

static unsigned int unf_check_els_cmnd_valid(struct unf_lport_s *v_lport,
					     struct unf_frame_pkg_s *v_fra_pkg,
					     struct unf_xchg_s *v_xchg)
{
	struct unf_lport_s *lport = v_lport;
	struct unf_frame_pkg_s *ppkg = v_fra_pkg;
	struct unf_xchg_s *xchg = v_xchg;
	struct unf_rjt_info_s rjt_info = { 0 };
	struct unf_lport_s *vport = NULL;
	unsigned int sid = 0;
	unsigned int did = 0;

	sid = (ppkg->frame_head.csctl_sid) & UNF_NPORTID_MASK;
	did = (ppkg->frame_head.rctl_did) & UNF_NPORTID_MASK;

	memset(&rjt_info, 0, sizeof(struct unf_rjt_info_s));
	rjt_info.reason_code = UNF_LS_RJT_NOT_SUPPORTED;

	if ((ppkg->cmnd == ELS_FLOGI) &&
	    (lport->en_act_topo == UNF_ACT_TOP_PRIVATE_LOOP)) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT, UNF_WARN,
			  "[warn]LOGIN: Port(0x%x) receive FLOGI in top (0x%x) and send LS_RJT",
			  lport->port_id, lport->en_act_topo);

		rjt_info.els_cmnd_code = ELS_FLOGI;
		(void)unf_send_els_rjt_by_did(lport, xchg, sid, &rjt_info);

		return UNF_RETURN_ERROR;
	}

	if ((ppkg->cmnd == ELS_PLOGI) && (did >= UNF_FC_FID_DOM_MGR)) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT, UNF_WARN,
			  "[warn]Port(0x%x)receive PLOGI with wellknown address(0x%x) and Send LS_RJT",
			  lport->port_id, did);

		rjt_info.els_cmnd_code = ELS_PLOGI;
		(void)unf_send_els_rjt_by_did(lport, xchg, sid, &rjt_info);

		return UNF_RETURN_ERROR;
	}

	if (((lport->nport_id == 0) ||
	     (lport->nport_id == INVALID_VALUE32)) &&
	    (NEED_REFRESH_NPORTID(ppkg))) {
		lport->nport_id = did;
	} else if ((did != lport->nport_id) && (ppkg->cmnd != ELS_FLOGI)) {
		vport = unf_cm_lookup_vport_by_did(lport, did);
		if (!vport) {
			UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT,
				  UNF_WARN,
				  "[warn]Port(0x%x) receive ELS cmd(0x%x) with abnormal D_ID(0x%x)",
				  lport->nport_id, ppkg->cmnd, did);

			unf_cm_free_xchg(lport, xchg);
			return UNF_RETURN_ERROR;
		}
	}

	return RETURN_OK;
}

static unsigned int unf_rcv_els_cmnd_req(struct unf_lport_s *v_lport,
					 struct unf_frame_pkg_s *v_fra_pkg)
{
	struct unf_xchg_s *xchg = NULL;
	unsigned int ret = UNF_RETURN_ERROR;
	unsigned int i = 0;
	unsigned int sid = 0;
	unsigned int did = 0;
	struct unf_lport_s *vport = NULL;
	unsigned int (*pfn_els_cmnd_handler)(struct unf_lport_s *, unsigned int,
					     struct unf_xchg_s *) = NULL;

	sid = (v_fra_pkg->frame_head.csctl_sid) & UNF_NPORTID_MASK;
	did = (v_fra_pkg->frame_head.rctl_did) & UNF_NPORTID_MASK;

	xchg = unf_mv_data_2_xchg(v_lport, v_fra_pkg);
	if (!xchg) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT, UNF_WARN,
			  "[warn]Port(0x%x) receive ElsCmnd(0x%x), exchange is NULL",
			  v_lport->port_id, v_fra_pkg->cmnd);

		return UNF_RETURN_ERROR;
	}

	if (v_fra_pkg->last_pkg_flag != UNF_TRUE) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT, UNF_INFO,
			  "[info]Exchange(%u) waiting for last WQE",
			  xchg->hot_pool_tag);

		return RETURN_OK;
	}

	UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT, UNF_INFO,
		  "[info]Exchange(%u) get last WQE", xchg->hot_pool_tag);

	if (v_lport->low_level_func.xchg_mgr_type ==
	    UNF_LOW_LEVEL_MGR_TYPE_PASSTIVE) {
		xchg->ox_id = UNF_GET_OXID(v_fra_pkg);
		xchg->abort_oxid = xchg->ox_id;
		xchg->rx_id = xchg->hot_pool_tag;
	}
	xchg->cmnd_code = v_fra_pkg->cmnd;

	ret = unf_check_els_cmnd_valid(v_lport, v_fra_pkg, xchg);
	if (ret != RETURN_OK) {
		/* NOTE: exchange has been released */
		return UNF_RETURN_ERROR;
	}

	if ((did != v_lport->nport_id)	&& (v_fra_pkg->cmnd != ELS_FLOGI)) {
		vport = unf_cm_lookup_vport_by_did(v_lport, did);
		if (!vport) {
			UNF_TRACE(UNF_EVTLOG_IO_WARN, UNF_LOG_IO_ATT, UNF_WARN,
				  "[warn]Port(0x%x) received unknown ELS command with S_ID(0x%x) D_ID(0x%x))",
				  v_lport->port_id, sid, did);

			return UNF_RETURN_ERROR;
		}
		v_lport = vport;
		UNF_TRACE(UNF_EVTLOG_IO_INFO, UNF_LOG_IO_ATT, UNF_INFO,
			  "[info]VPort(0x%x) received ELS command with S_ID(0x%x) D_ID(0x%x)",
			  v_lport->port_id, sid, did);
	}

	do {
		if ((v_fra_pkg->cmnd) == els_handle[i].cmnd) {
			pfn_els_cmnd_handler =
				els_handle[i].pfn_els_cmnd_handler;
			break;
		}

		i++;
	} while (i < (sizeof(els_handle) /
		      sizeof(struct unf_els_handler_table)));

	if (pfn_els_cmnd_handler) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT,
			  UNF_INFO,
			  "[info]Port(0x%x) receive ELS(0x%x) from RPort(0x%x) and process it",
			  v_lport->port_id, v_fra_pkg->cmnd, sid);

		ret = pfn_els_cmnd_handler(v_lport, sid, xchg);
	} else {
		ret = unf_els_cmnd_default_handler(v_lport, xchg, sid,
						   v_fra_pkg->cmnd);
	}

	return ret;
}

static unsigned int unf_send_els_rsp_succ(struct unf_lport_s *v_lport,
					  struct unf_frame_pkg_s *v_fra_pkg)
{
	struct unf_xchg_s *xchg = NULL;
	unsigned int ret = RETURN_OK;
	unsigned short hot_pool_tag = 0;
	unsigned long flags = 0;
	void (*pfn_ob_callback)(struct unf_xchg_s *) = NULL;

	UNF_CHECK_VALID(0x3529, UNF_TRUE, v_lport, return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(0x3530, UNF_TRUE, v_fra_pkg, return UNF_RETURN_ERROR);

	if (!v_lport->xchg_mgr_temp.pfn_unf_look_up_xchg_by_tag) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_LOGIN_ATT, UNF_ERR,
			  "[err]Port(0x%x) lookup exchange by tag function is NULL",
			  v_lport->port_id);

		return UNF_RETURN_ERROR;
	}

	hot_pool_tag = (unsigned short)
		(v_fra_pkg->private[PKG_PRIVATE_XCHG_HOT_POOL_INDEX]);
	xchg = (struct unf_xchg_s *)
		(v_lport->xchg_mgr_temp.pfn_unf_look_up_xchg_by_tag(
							(void *)v_lport,
							hot_pool_tag));
	if (!xchg) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_LOGIN_ATT, UNF_ERR,
			  "[err]Port(0x%x) find exhange by tag(0x%x) failed",
			  v_lport->port_id, hot_pool_tag);

		return UNF_RETURN_ERROR;
	}

	v_lport->xchg_mgr_temp.pfn_unf_xchg_cancel_timer((void *)xchg);

	spin_lock_irqsave(&xchg->xchg_state_lock, flags);
	if ((xchg->pfn_ob_callback) &&
	    (!(xchg->io_state & TGT_IO_STATE_ABORT))) {
		pfn_ob_callback = xchg->pfn_ob_callback;
		spin_unlock_irqrestore(&xchg->xchg_state_lock, flags);

		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT, UNF_INFO,
			  "[info]Port(0x%x) with exchange(0x%p) tag(%u) do callback",
			  v_lport->port_id, xchg, hot_pool_tag);

		pfn_ob_callback(xchg);
	} else {
		spin_unlock_irqrestore(&xchg->xchg_state_lock, flags);
	}

	unf_cm_free_xchg((void *)v_lport, (void *)xchg);
	return ret;
}

static unsigned char *unf_calc_big_resp_pld_buffer(struct unf_xchg_s *v_xchg,
						   unsigned int v_cmnd_code)
{
	unsigned char *resp_pld = NULL;
	unsigned char *dest = NULL;

	UNF_CHECK_VALID(0x3510, UNF_TRUE, v_xchg, return NULL);

	if (v_cmnd_code == ELS_ECHO)
		resp_pld = (unsigned char *)
			v_xchg->fcp_sfs_union.sfs_entry.fc_sfs_entry_ptr->echo.echo_pld;
	else
		resp_pld = (unsigned char *)
			v_xchg->fcp_sfs_union.sfs_entry.fc_sfs_entry_ptr->get_id.gid_rsp.gid_acc_pld;

	if (resp_pld)
		dest = (unsigned char *)
			(resp_pld + v_xchg->fcp_sfs_union.sfs_entry.cur_offset);

	return dest;
}

static unsigned char *unf_calc_other_resp_pld_buffer(struct unf_xchg_s *v_xchg)
{
	unsigned char *dest = NULL;
	unsigned int offset = 0;

	UNF_CHECK_VALID(0x3511, UNF_TRUE, v_xchg, return NULL);

	offset = v_xchg->fcp_sfs_union.sfs_entry.cur_offset;
	dest = (unsigned char *)((unsigned char *)
		(v_xchg->fcp_sfs_union.sfs_entry.fc_sfs_entry_ptr) + offset);

	return dest;
}

static unsigned int unf_mv_resp_2_xchg(struct unf_xchg_s *v_xchg,
				       struct unf_frame_pkg_s *v_pkg)
{
	unsigned char *dest = NULL;
	unsigned int length = 0;
	unsigned int offset = 0;
	unsigned int max_frame_len = 0;
	unsigned long flags = 0;

	spin_lock_irqsave(&v_xchg->xchg_state_lock, flags);

	if (UNF_NEED_BIG_RESPONSE_BUFF(v_xchg->cmnd_code)) {
		dest = unf_calc_big_resp_pld_buffer(v_xchg,
						    v_xchg->cmnd_code);
		offset = 0;
		max_frame_len = sizeof(struct unf_gif_acc_pld_s);
	} else if (v_xchg->cmnd_code == NS_GA_NXT ||
		   v_xchg->cmnd_code == NS_GIEL) {
		dest = unf_calc_big_resp_pld_buffer(v_xchg,
						    v_xchg->cmnd_code);
		offset = 0;
		max_frame_len =
			v_xchg->fcp_sfs_union.sfs_entry.sfs_buff_len;
	} else {
		dest = unf_calc_other_resp_pld_buffer(v_xchg);
		offset = sizeof(struct unf_fchead_s);
		max_frame_len = sizeof(union unf_sfs_u);
	}

	if (!dest) {
		spin_unlock_irqrestore(&v_xchg->xchg_state_lock, flags);

		return UNF_RETURN_ERROR;
	}

	if (v_xchg->fcp_sfs_union.sfs_entry.cur_offset == 0) {
		v_xchg->fcp_sfs_union.sfs_entry.cur_offset += offset;
		dest = dest + offset;
	}

	length = v_pkg->unf_cmnd_pload_bl.length;

	if ((v_xchg->fcp_sfs_union.sfs_entry.cur_offset + length) >
	    max_frame_len) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT,
			  UNF_WARN,
			  "[warn]Exchange(0x%p) command(0x%x) hotpooltag(0x%x) OX_RX_ID(0x%x) S_ID(0x%x) D_ID(0x%x) copy payload overrun(0x%x:0x%x:0x%x)",
			  v_xchg, v_xchg->cmnd_code, v_xchg->hot_pool_tag,
			  v_pkg->frame_head.oxid_rxid,
			  v_pkg->frame_head.csctl_sid & UNF_NPORTID_MASK,
			  v_pkg->frame_head.rctl_did & UNF_NPORTID_MASK,
			  v_xchg->fcp_sfs_union.sfs_entry.cur_offset,
			  v_pkg->unf_cmnd_pload_bl.length,
			  max_frame_len);

		length = max_frame_len - v_xchg->fcp_sfs_union.sfs_entry.cur_offset;
	}

	if (length > 0)
		memcpy(dest, v_pkg->unf_cmnd_pload_bl.buffer_ptr, length);

	v_xchg->fcp_sfs_union.sfs_entry.cur_offset += length;
	spin_unlock_irqrestore(&v_xchg->xchg_state_lock, flags);

	return RETURN_OK;
}

static unsigned int unf_send_els_cmnd_succ(struct unf_lport_s *v_lport,
					   struct unf_frame_pkg_s *v_fra_pkg)
{
	struct unf_xchg_s *xchg = NULL;
	unsigned int ret = RETURN_OK;
	unsigned short hot_pool_tag = 0;
	unsigned long flags = 0;
	void (*pfn_callback)(void *, void *, void *) = NULL;
	struct unf_lport_s *lport = NULL;

	UNF_CHECK_VALID(0x3531, UNF_TRUE, v_lport, return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(0x3532, UNF_TRUE, v_fra_pkg, return UNF_RETURN_ERROR);
	lport = v_lport;

	if (!lport->xchg_mgr_temp.pfn_unf_look_up_xchg_by_tag) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_LOGIN_ATT, UNF_ERR,
			  "[err]Port(0x%x) lookup exchange by tag function can't be NULL",
			  lport->port_id);

		return UNF_RETURN_ERROR;
	}

	hot_pool_tag = (unsigned short)
		(v_fra_pkg->private[PKG_PRIVATE_XCHG_HOT_POOL_INDEX]);
	xchg = (struct unf_xchg_s *)
		(lport->xchg_mgr_temp.pfn_unf_look_up_xchg_by_tag((void *)lport,
							     hot_pool_tag));
	if (!xchg) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT, UNF_WARN,
			  "[warn]Port(0x%x_0x%x) find exchange by tag(0x%x) failed",
			  lport->port_id, lport->nport_id, hot_pool_tag);

		return UNF_RETURN_ERROR;
	}

	UNF_CHECK_ALLOCTIME_VALID(
			lport, hot_pool_tag, xchg,
			v_fra_pkg->private[PKG_PRIVATE_XCHG_ALLOC_TIME],
			xchg->private[PKG_PRIVATE_XCHG_ALLOC_TIME]);

	if (((v_fra_pkg->frame_head.csctl_sid) & UNF_NPORTID_MASK) !=
	    xchg->did) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT, UNF_WARN,
			  "[warn]Port(0x%x) find exhange invalid, package S_ID(0x%x) exchange S_ID(0x%x) D_ID(0x%x)",
			  lport->port_id, v_fra_pkg->frame_head.csctl_sid,
			  xchg->sid, xchg->did);

		return UNF_RETURN_ERROR;
	}

	if (v_fra_pkg->last_pkg_flag == UNF_PKG_NOT_LAST_RESPONSE) {
		ret = unf_mv_resp_2_xchg(xchg, v_fra_pkg);

		return ret;
	}

	xchg->byte_orders = v_fra_pkg->byte_orders;
	lport->xchg_mgr_temp.pfn_unf_xchg_cancel_timer((void *)xchg);

	spin_lock_irqsave(&xchg->xchg_state_lock, flags);
	if ((xchg->pfn_callback) &&
	    ((xchg->cmnd_code == ELS_RRQ) ||
	     (xchg->cmnd_code == ELS_LOGO) ||
	     (!(xchg->io_state & TGT_IO_STATE_ABORT)))) {
		pfn_callback = xchg->pfn_callback;

		if ((xchg->cmnd_code == ELS_FLOGI) ||
		    (xchg->cmnd_code == ELS_FDISC))
			xchg->sid = v_fra_pkg->frame_head.rctl_did &
					UNF_NPORTID_MASK;

		if (xchg->cmnd_code == ELS_ECHO) {
			xchg->private[PKG_PRIVATE_ECHO_CMD_RCV_TIME] =
				v_fra_pkg->private[PKG_PRIVATE_ECHO_CMD_RCV_TIME];
			xchg->private[PKG_PRIVATE_ECHO_RSP_SND_TIME] =
				v_fra_pkg->private[PKG_PRIVATE_ECHO_RSP_SND_TIME];
			xchg->private[PKG_PRIVATE_ECHO_CMD_SND_TIME] =
				v_fra_pkg->private[PKG_PRIVATE_ECHO_CMD_SND_TIME];
			xchg->private[PKG_PRIVATE_ECHO_ACC_RCV_TIME] =
				v_fra_pkg->private[PKG_PRIVATE_ECHO_ACC_RCV_TIME];
		}
		spin_unlock_irqrestore(&xchg->xchg_state_lock, flags);

		/* Do callback */
		pfn_callback(xchg->lport, xchg->rport, xchg);
	} else {
		spin_unlock_irqrestore(&xchg->xchg_state_lock, flags);
	}

	unf_cm_free_xchg((void *)lport, (void *)xchg);
	return ret;
}

static unsigned int unf_send_els_cmnd_failed(struct unf_lport_s *v_lport,
					     struct unf_frame_pkg_s *v_fra_pkg)
{
	struct unf_xchg_s *xchg = NULL;
	unsigned int ret = RETURN_OK;
	unsigned short hot_pool_tag = 0;
	unsigned long flags = 0;
	void (*pfn_ob_callback)(struct unf_xchg_s *) = NULL;

	UNF_CHECK_VALID(0x3533, UNF_TRUE, v_lport, return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(0x3534, UNF_TRUE, v_fra_pkg, return UNF_RETURN_ERROR);

	if (!v_lport->xchg_mgr_temp.pfn_unf_look_up_xchg_by_tag) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_LOGIN_ATT, UNF_ERR,
			  "[err]Port(0x%x) lookup exchange by tag function can't be NULL",
			  v_lport->port_id);

		return UNF_RETURN_ERROR;
	}

	hot_pool_tag = (unsigned short)
		(v_fra_pkg->private[PKG_PRIVATE_XCHG_HOT_POOL_INDEX]);
	xchg = (struct unf_xchg_s *)
		(v_lport->xchg_mgr_temp.pfn_unf_look_up_xchg_by_tag(
								(void *)v_lport,
								hot_pool_tag));
	if (!xchg) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT, UNF_WARN,
			  "[warn]Port(0x%x_0x%x) find exhange by tag(0x%x) failed",
			  v_lport->port_id, v_lport->nport_id, hot_pool_tag);

		return UNF_RETURN_ERROR;
	}

	UNF_CHECK_ALLOCTIME_VALID(
			v_lport, hot_pool_tag, xchg,
			v_fra_pkg->private[PKG_PRIVATE_XCHG_ALLOC_TIME],
			xchg->private[PKG_PRIVATE_XCHG_ALLOC_TIME]);

	v_lport->xchg_mgr_temp.pfn_unf_xchg_cancel_timer((void *)xchg);

	spin_lock_irqsave(&xchg->xchg_state_lock, flags);
	if ((xchg->pfn_ob_callback) &&
	    ((xchg->cmnd_code == ELS_RRQ) ||
	     (xchg->cmnd_code == ELS_LOGO) ||
	     (!(xchg->io_state & TGT_IO_STATE_ABORT)))) {
		pfn_ob_callback = xchg->pfn_ob_callback;
		xchg->ob_callback_sts = v_fra_pkg->status;
		spin_unlock_irqrestore(&xchg->xchg_state_lock, flags);

		pfn_ob_callback(xchg);

		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT, UNF_INFO,
			  "[info]Port(0x%x) exchange(0x%p) tag(0x%x) do callback",
			  v_lport->port_id, xchg, hot_pool_tag);
	} else {
		spin_unlock_irqrestore(&xchg->xchg_state_lock, flags);
	}

	unf_cm_free_xchg((void *)v_lport, (void *)xchg);
	return ret;
}

static unsigned int unf_rcv_els_cmnd_reply(struct unf_lport_s *v_lport,
					   struct unf_frame_pkg_s *v_fra_pkg)
{
	unsigned int ret = RETURN_OK;

	UNF_CHECK_VALID(0x3535, UNF_TRUE, v_lport, return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(0x3536, UNF_TRUE, v_fra_pkg, return UNF_RETURN_ERROR);

	if ((v_fra_pkg->status == UNF_IO_SUCCESS) ||
	    (v_fra_pkg->status == UNF_IO_UNDER_FLOW))
		ret = unf_send_els_cmnd_succ(v_lport, v_fra_pkg);
	else
		ret = unf_send_els_cmnd_failed(v_lport, v_fra_pkg);

	return ret;
}

void unf_lport_enter_msn_plogi(struct unf_lport_s *v_lport)
{
	/* Fabric or Public Loop Mode: Login with Name server */
	struct unf_lport_s *lport = v_lport;
	struct unf_rport_s *rport = NULL;
	unsigned long flag = 0;
	unsigned int ret = UNF_RETURN_ERROR;
	struct unf_plogi_payload_s *plogi_pld = NULL;
	union unf_sfs_u *fc_entry = NULL;
	struct unf_xchg_s *xchg = NULL;
	struct unf_frame_pkg_s pkg;

	UNF_CHECK_VALID(0x1811, UNF_TRUE, v_lport, return);

	/* Get (safe) R_Port */
	rport = unf_rport_get_free_and_init(v_lport, UNF_PORT_TYPE_FC,
					    UNF_FC_FID_MGMT_SERV);
	if (!rport) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT,
			  UNF_WARN,
			  "[warn]Port(0x%x) allocate RPort failed",
			  v_lport->port_id);
		return;
	}

	spin_lock_irqsave(&rport->rport_state_lock, flag);
	rport->nport_id = UNF_FC_FID_MGMT_SERV;  // 0xfffffa
	spin_unlock_irqrestore(&rport->rport_state_lock, flag);

	memset(&pkg, 0, sizeof(struct unf_frame_pkg_s));

	/* Get & Set new free exchange */
	xchg = unf_cm_get_free_xchg(v_lport, UNF_XCHG_TYPE_SFS);
	if (!xchg) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_LOGIN_ATT, UNF_ERR,
			  "[err]Port(0x%x) exchange can't be NULL for PLOGI",
			  v_lport->port_id);

		return;
	}

	xchg->cmnd_code = ELS_PLOGI;  // PLOGI
	xchg->did = rport->nport_id;
	xchg->sid = v_lport->nport_id;
	xchg->oid = xchg->sid;
	xchg->lport = lport;
	xchg->rport = rport;

	if (v_lport->low_level_func.xchg_mgr_type ==
	    UNF_LOW_LEVEL_MGR_TYPE_PASSTIVE)
		xchg->ox_id = xchg->hot_pool_tag;

	/* Set callback function */
	xchg->pfn_callback = NULL;  // for rcvd plogi acc/rjt processer
	xchg->pfn_ob_callback = NULL;  // for send plogi failed processer

	unf_fill_package(&pkg, xchg, rport);

	/* Fill PLOGI payload */
	fc_entry = xchg->fcp_sfs_union.sfs_entry.fc_sfs_entry_ptr;
	if (!fc_entry) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT, UNF_WARN,
			  "[warn]Port(0x%x) entry can't be NULL with tag(0x%x)",
			  v_lport->port_id, xchg->hot_pool_tag);

		unf_cm_free_xchg(v_lport, xchg);
		return;
	}

	plogi_pld = &fc_entry->plogi.payload;
	memset(plogi_pld, 0, sizeof(struct unf_plogi_payload_s));
	unf_fill_plogi_pld(plogi_pld, v_lport);

	/* Start to Send PLOGI command */
	ret = unf_els_cmnd_send(v_lport, &pkg, xchg);
	if (ret != RETURN_OK)
		unf_cm_free_xchg((void *)v_lport, (void *)xchg);
}

static void unf_register_to_switch(struct unf_lport_s *v_lport)
{
	/* Register to Fabric, used for: FABRIC & PUBLI LOOP */
	unsigned long flag = 0;

	UNF_CHECK_VALID(0x3542, UNF_TRUE, v_lport, return);

	spin_lock_irqsave(&v_lport->lport_state_lock, flag);
	/* LPort: FLOGI_WAIT --> PLOGI_WAIT */
	unf_lport_stat_ma(v_lport, UNF_EVENT_LPORT_REMOTE_ACC);
	spin_unlock_irqrestore(&v_lport->lport_state_lock, flag);

	/* Login with Name server: PLOGI */
	unf_lport_enter_sns_plogi(v_lport);

	unf_lport_enter_msn_plogi(v_lport);

	if ((v_lport->root_lport == v_lport) &&/* Physical Port */
	    (v_lport->en_act_topo == UNF_ACT_TOP_P2P_FABRIC)) {
		unf_linkup_all_vports(v_lport);
	}
}

void unf_login_with_loop_node(struct unf_lport_s *v_lport, unsigned int v_alpa)
{
	/* Only used for Private Loop LOGIN */
	struct unf_rport_s *rport = NULL;
	unsigned long rport_flag = 0;
	unsigned int port_feature = 0;
	unsigned int ret;

	/* Check AL_PA validity */
	if (v_lport->nport_id == v_alpa) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT, UNF_INFO,
			  "[info]Port(0x%x) is the same as RPort with AL_PA(0x%x), do nothing",
			  v_lport->port_id, v_alpa);
		return;
	}

	if (v_alpa == 0) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT, UNF_WARN,
			  "[warn]Port(0x%x) RPort(0x%x) is fabric, do nothing",
			  v_lport->port_id, v_alpa);
		return;
	}

	/* Get & set R_Port: reuse only */
	rport = unf_get_rport_by_nport_id(v_lport, v_alpa);

	UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT, UNF_MAJOR,
		  "[info]LOGIN: Port(0x%x_0x%x) RPort(0x%x_0x%p) login with private loop",
		  v_lport->port_id, v_lport->nport_id, v_alpa, rport);

	rport = unf_get_safe_rport(v_lport, rport, UNF_RPORT_REUSE_ONLY,
				   v_alpa);
	if (!rport) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT, UNF_WARN,
			  "[warn]Port(0x%x_0x%x) allocate new RPort(0x%x) failed",
			  v_lport->port_id, v_lport->nport_id, v_alpa);
		return;
	}

	/* Update R_Port state & N_Port_ID */
	spin_lock_irqsave(&rport->rport_state_lock, rport_flag);
	rport->nport_id = v_alpa;
	unf_rport_state_ma(rport, UNF_EVENT_RPORT_ENTER_PLOGI);  // PLOGI_WAIT
	spin_unlock_irqrestore(&rport->rport_state_lock, rport_flag);

	/* Private Loop: check whether need delay to send PLOGI or not */
	port_feature = rport->options;

	/* check Rport and Lport feature */
	if ((port_feature == UNF_PORT_MODE_UNKNOWN) &&
	    (v_lport->options == UNF_PORT_MODE_INI)) {
		/* Start to send PLOGI */
		ret = unf_send_plogi(v_lport, rport);
		if (ret != RETURN_OK) {
			UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT,
				  UNF_WARN,
				  "[warn]LOGIN: Port(0x%x_0x%x) send PLOGI to RPort(0x%x) failed",
				  v_lport->port_id, v_lport->nport_id,
				  rport->nport_id);

			unf_rport_error_recovery(rport);
		}
	} else {
		unf_check_rport_need_delay_plogi(v_lport, rport, port_feature);
	}
}

unsigned int unf_receive_els_pkg(void *v_lport,
				 struct unf_frame_pkg_s *v_fra_pkg)
{
	struct unf_lport_s *lport = NULL;
	unsigned int ret = UNF_RETURN_ERROR;

	UNF_CHECK_VALID(0x3543, UNF_TRUE, v_lport, return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(0x3544, UNF_TRUE, v_fra_pkg, return UNF_RETURN_ERROR);
	lport = (struct unf_lport_s *)v_lport;

	switch (v_fra_pkg->type) {
	case UNF_PKG_ELS_REQ_DONE:
		ret = unf_rcv_els_cmnd_reply(lport, v_fra_pkg);
		break;

	case UNF_PKG_ELS_REQ:
		ret = unf_rcv_els_cmnd_req(lport, v_fra_pkg);
		break;

	default:
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT, UNF_WARN,
			  "[warn]Port(0x%x_0x%x) with exchange type(0x%x) abnormal",
			  lport->port_id, lport->nport_id, v_fra_pkg->type);
		break;
	}

	return ret;
}

unsigned int unf_send_els_done(void *v_lport, struct unf_frame_pkg_s *v_pkg)
{
	unsigned int ret = UNF_RETURN_ERROR;

	UNF_CHECK_VALID(0x3545, UNF_TRUE, v_lport, return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(0x3546, UNF_TRUE, v_pkg, return UNF_RETURN_ERROR);

	if (v_pkg->type == UNF_PKG_ELS_REPLY_DONE) {
		if ((v_pkg->status == UNF_IO_SUCCESS) ||
		    (v_pkg->status == UNF_IO_UNDER_FLOW))
			ret = unf_send_els_rsp_succ(v_lport, v_pkg);
		else
			ret = unf_send_els_cmnd_failed(v_lport, v_pkg);
	}

	return ret;
}

static unsigned int unf_rcv_gs_cmnd_reply(struct unf_lport_s *v_lport,
					  struct unf_frame_pkg_s *v_fra_pkg)
{
	struct unf_xchg_s *xchg = NULL;
	unsigned long flags = 0;
	unsigned short hot_pool_tag = 0;
	unsigned int ret = RETURN_OK;
	struct unf_lport_s *lport = NULL;
	void (*pfn_callback)(void *, void *, void *) = NULL;

	UNF_CHECK_VALID(0x3553, UNF_TRUE, v_lport, return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(0x3554, UNF_TRUE, v_fra_pkg, return UNF_RETURN_ERROR);
	lport = v_lport;
	hot_pool_tag = (unsigned short)
		(v_fra_pkg->private[PKG_PRIVATE_XCHG_HOT_POOL_INDEX]);

	xchg = (struct unf_xchg_s *)unf_cm_lookup_xchg_by_tag(
						(void *)lport, hot_pool_tag);
	if (!xchg) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT, UNF_WARN,
			  "[warn]Port(0x%x) find exhange by tag(0x%x) failed",
			  lport->port_id, hot_pool_tag);

		return UNF_RETURN_ERROR;
	}

	UNF_CHECK_ALLOCTIME_VALID(
			lport, hot_pool_tag, xchg,
			v_fra_pkg->private[PKG_PRIVATE_XCHG_ALLOC_TIME],
			xchg->private[PKG_PRIVATE_XCHG_ALLOC_TIME]);

	if (v_fra_pkg->last_pkg_flag == UNF_PKG_NOT_LAST_RESPONSE) {
		ret = unf_mv_resp_2_xchg(xchg, v_fra_pkg);
		return ret;
	}

	lport->xchg_mgr_temp.pfn_unf_xchg_cancel_timer((void *)xchg);

	spin_lock_irqsave(&xchg->xchg_state_lock, flags);
	if ((xchg->pfn_callback) && (!(xchg->io_state & TGT_IO_STATE_ABORT))) {
		pfn_callback = xchg->pfn_callback;
		spin_unlock_irqrestore(&xchg->xchg_state_lock, flags);

		pfn_callback(xchg->lport, xchg->rport, xchg);
	} else {
		spin_unlock_irqrestore(&xchg->xchg_state_lock, flags);
	}

	unf_cm_free_xchg((void *)lport, (void *)xchg);
	return ret;
}

static unsigned int unf_send_gs_cmnd_failed(struct unf_lport_s *v_lport,
					    struct unf_frame_pkg_s *v_fra_pkg)
{
	struct unf_xchg_s *xchg = NULL;
	unsigned int ret = RETURN_OK;
	unsigned short hot_pool_tag = 0;
	unsigned long flags = 0;

	void (*pfn_ob_callback)(struct unf_xchg_s *) = NULL;

	UNF_CHECK_VALID(0x3555, UNF_TRUE, v_lport, return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(0x3556, UNF_TRUE, v_fra_pkg, return UNF_RETURN_ERROR);

	if (!v_lport->xchg_mgr_temp.pfn_unf_look_up_xchg_by_tag) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_LOGIN_ATT, UNF_ERR,
			  "[err]Port(0x%x) loopup exchange by tag function can't be NULL",
			  v_lport->port_id);

		return UNF_RETURN_ERROR;
	}

	hot_pool_tag = (unsigned short)
		(v_fra_pkg->private[PKG_PRIVATE_XCHG_HOT_POOL_INDEX]);
	xchg = (struct unf_xchg_s *)
		(v_lport->xchg_mgr_temp.pfn_unf_look_up_xchg_by_tag(
							(void *)v_lport,
							hot_pool_tag));

	if (!xchg) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT, UNF_WARN,
			  "[warn]Port(0x%x) can't find exhange by tag(0x%x)",
			  v_lport->port_id, hot_pool_tag);

		return UNF_RETURN_ERROR;
	}

	UNF_CHECK_ALLOCTIME_VALID(
			v_lport, hot_pool_tag, xchg,
			v_fra_pkg->private[PKG_PRIVATE_XCHG_ALLOC_TIME],
			xchg->private[PKG_PRIVATE_XCHG_ALLOC_TIME]);

	v_lport->xchg_mgr_temp.pfn_unf_xchg_cancel_timer((void *)xchg);

	spin_lock_irqsave(&xchg->xchg_state_lock, flags);
	if ((xchg->pfn_ob_callback) &&
	    (!(xchg->io_state & TGT_IO_STATE_ABORT))) {
		pfn_ob_callback = xchg->pfn_ob_callback;
		spin_unlock_irqrestore(&xchg->xchg_state_lock, flags);

		pfn_ob_callback(xchg);
	} else {
		spin_unlock_irqrestore(&xchg->xchg_state_lock, flags);
	}

	unf_cm_free_xchg((void *)v_lport, (void *)xchg);
	return ret;
}

unsigned int unf_receive_gs_pkg(void *v_lport,
				struct unf_frame_pkg_s *v_fra_pkg)
{
	struct unf_lport_s *lport = NULL;
	unsigned int ret = UNF_RETURN_ERROR;

	UNF_CHECK_VALID(0x3557, UNF_TRUE, v_lport, return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(0x3558, UNF_TRUE, v_fra_pkg, return UNF_RETURN_ERROR);

	lport = (struct unf_lport_s *)v_lport;

	if ((v_fra_pkg->type) == UNF_PKG_GS_REQ_DONE) {
		if ((v_fra_pkg->status == UNF_IO_SUCCESS) ||
		    (v_fra_pkg->status == UNF_IO_UNDER_FLOW) ||
		    (v_fra_pkg->status == UNF_IO_OVER_FLOW))
			ret = unf_rcv_gs_cmnd_reply(lport, v_fra_pkg);
		else
			ret = unf_send_gs_cmnd_failed(lport, v_fra_pkg);
	} else {
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT, UNF_WARN,
			  "[warn]Port(0x%x) exchange type(0x%x) mismatch",
			  lport->port_id, v_fra_pkg->type);

		return UNF_RETURN_ERROR;
	}

	return ret;
}

static void unf_handle_init_gid_acc(struct unf_gif_acc_pld_s *v_gid_acc_pld,
				    struct unf_lport_s *v_lport)
{
	/*
	 * from SCR ACC callback
	 * NOTE: inquiry disc R_Port used for NPIV
	 */
	struct unf_disc_rport_s *disc_rport = NULL;
	struct unf_disc_s *disc = NULL;
	unsigned int ret = UNF_RETURN_ERROR;
	unsigned int gid_port_id = 0;
	unsigned int nport_id = 0;
	unsigned int i = 0;
	unsigned char control = 0;

	UNF_CHECK_VALID(0x3559, UNF_TRUE, v_gid_acc_pld, return);
	UNF_CHECK_VALID(0x3560, UNF_TRUE, v_lport, return);

	/*
	 * 1. Find & Check & Get (new) R_Port from list_disc_rports_pool
	 * then, Add to R_Port Disc_busy_list
	 */
	while (i < UNF_GID_PORT_CNT) {
		gid_port_id = (v_gid_acc_pld->gid_port_id[i]);
		nport_id = UNF_NPORTID_MASK & gid_port_id;
		control = UNF_GID_CONTROL(gid_port_id);

		/* for each N_Port_ID from GID_ACC payload */
		if ((nport_id != v_lport->nport_id) && (nport_id != 0) &&
		    (!unf_lookup_lport_by_nport_id(v_lport, nport_id))) {
			/* for New Port, not L_Port */
			UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT,
				  UNF_MAJOR,
				  "[info]Port(0x%x_0x%x) get nportid(0x%x) from GID_ACC",
				  v_lport->port_id, v_lport->nport_id,
				  nport_id);

			/* Get R_Port from list of RPort Disc Pool */
			disc_rport =
				unf_rport_get_free_and_init(v_lport,
							    UNF_PORT_TYPE_DISC,
							    nport_id);
			if (!disc_rport) {
				UNF_TRACE(UNF_EVTLOG_DRIVER_WARN,
					  UNF_LOG_LOGIN_ATT, UNF_WARN,
					  "[warn]Port(0x%x_0x%x) can't allocate new rport(0x%x) from disc pool",
					  v_lport->port_id,
					  v_lport->nport_id,
					  nport_id);

				i++;
				continue;
			}
		}

		if ((control & UNF_GID_LAST_PORT_ID) == UNF_GID_LAST_PORT_ID)
			break;

		i++;
	}

	/*
	 * 2. Do port disc stop operation:
	 * NOTE: Do DISC & release R_Port from
	 * busy_list back to list_disc_rports_pool
	 */
	disc = &v_lport->disc;
	if (!disc->unf_disc_temp.pfn_unf_disc_stop) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT, UNF_WARN,
			  "[warn]Port(0x%x_0x%x) disc stop function is NULL",
			  v_lport->port_id, v_lport->nport_id);

		return;
	}

	ret = disc->unf_disc_temp.pfn_unf_disc_stop(v_lport);
	if (ret != RETURN_OK)
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT, UNF_WARN,
			  "[warn]Port(0x%x_0x%x) do disc stop failed",
			  v_lport->port_id, v_lport->nport_id);
}

void unf_rport_immediate_linkdown(struct unf_lport_s *v_lport,
				  struct unf_rport_s *v_rport)
{
	/* Swap case: Report Link Down immediately & release R_Port */
	unsigned long flags = 0;
	struct unf_disc_s *disc = NULL;

	UNF_CHECK_VALID(0x3561, UNF_TRUE, v_lport, return);
	UNF_CHECK_VALID(0x3562, UNF_TRUE, v_rport, return);

	spin_lock_irqsave(&v_rport->rport_state_lock, flags);
	/* 1. Inc R_Port ref_cnt */
	if (unf_rport_ref_inc(v_rport) != RETURN_OK) {
		spin_unlock_irqrestore(&v_rport->rport_state_lock, flags);

		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT, UNF_WARN,
			  "[warn]Port(0x%x) Rport(0x%p,0x%x) is removing and no need process",
			  v_lport->port_id, v_rport, v_rport->nport_id);

		return;
	}

	/* 2. R_PORT state update: Link Down Event --->>> closing state */
	unf_rport_state_ma(v_rport, UNF_EVENT_RPORT_LINK_DOWN);
	spin_unlock_irqrestore(&v_rport->rport_state_lock, flags);

	/* 3. Put R_Port from busy to destroy list */
	disc = &v_lport->disc;
	spin_lock_irqsave(&disc->rport_busy_pool_lock, flags);
	list_del_init(&v_rport->entry_rport);
	list_add_tail(&v_rport->entry_rport, &disc->list_destroy_rports);
	spin_unlock_irqrestore(&disc->rport_busy_pool_lock, flags);

	/* 4. Schedule Closing work (Enqueuing workqueue) */
	unf_schedule_closing_work(v_lport, v_rport);

	unf_rport_ref_dec(v_rport);
}

static unsigned int unf_rport_check_wwn(struct unf_lport_s *v_lport,
					struct unf_rport_s *v_rport)
{
	/* Send GPN_ID */
	struct unf_rport_s *sns_port = NULL;
	unsigned int ret = RETURN_OK;

	UNF_CHECK_VALID(0x3564, UNF_TRUE, v_lport,
			return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(0x3565, UNF_TRUE, v_rport,
			return UNF_RETURN_ERROR);

	/* Get SNS R_Port */
	sns_port = unf_get_rport_by_nport_id(v_lport,
					     UNF_FC_FID_DIR_SERV);
	if (!sns_port) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT,
			  UNF_WARN,
			  "[warn]Port(0x%x) can't find fabric Port",
			  v_lport->nport_id);

		return UNF_RETURN_ERROR;
	}

	/* Send GPN_ID to SW */
	ret = unf_get_and_post_disc_event(v_lport, sns_port, v_rport->nport_id,
					  UNF_DISC_GET_PORT_NAME);
	if (ret != RETURN_OK) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_LOGIN_ATT, UNF_ERR,
			  "[err]Port(0x%x) add discovery event(0x%x) failed Rport(0x%x)",
			  v_lport->nport_id, UNF_DISC_GET_PORT_NAME,
			  v_rport->nport_id);

		unf_rcv_gpn_id_rsp_unknown(v_lport, v_rport->nport_id);
	}

	return ret;
}

static unsigned int unf_handle_rscn_port_not_in_disc(
						struct unf_lport_s *v_lport,
						unsigned int v_rscn_nport_id)
{
	/* RSCN Port_ID not in GID_ACC payload table: Link Down */
	struct unf_rport_s *rport = NULL;
	unsigned int ret = RETURN_OK;

	UNF_CHECK_VALID(0x3566, UNF_TRUE, v_lport, return UNF_RETURN_ERROR);

	/* from R_Port busy list by N_Port_ID */
	rport = unf_get_rport_by_nport_id(v_lport, v_rscn_nport_id);
	if (rport) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT,
			  UNF_KEVENT,
			  "[info]Port(0x%x) RPort(0x%x) wwpn(0x%llx) has been removed and link down it",
			  v_lport->port_id, v_rscn_nport_id,
			  rport->port_name);

		unf_rport_linkdown(v_lport, rport);
	} else {
		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT, UNF_INFO,
			  "[info]Port(0x%x) has no RPort(0x%x) and do nothing",
			  v_lport->nport_id, v_rscn_nport_id);
	}

	return ret;
}

static unsigned int unf_handle_rscn_port_in_disc(struct unf_lport_s *v_lport,
						 unsigned int v_rscn_nport_id)
{
	/* Send GPN_ID or re-login(GNN_ID) */
	struct unf_rport_s *rport = NULL;
	unsigned int ret = RETURN_OK;

	UNF_CHECK_VALID(0x3567, UNF_TRUE, v_lport, return UNF_RETURN_ERROR);

	/* from R_Port busy list by N_Port_ID */
	rport = unf_get_rport_by_nport_id(v_lport, v_rscn_nport_id);
	if (rport) {
		/* R_Port exist: send GPN_ID */
		ret = unf_rport_check_wwn(v_lport, rport);
	} else {
		if ((v_lport->options & UNF_PORT_MODE_INI) ==
		    UNF_PORT_MODE_INI) {
			/* Re-LOGIN with INI mode: Send GNN_ID */
			ret = unf_rport_relogin(v_lport, v_rscn_nport_id);
		} else {
			UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT,
				  UNF_MAJOR,
				  "[info]Port(0x%x) with no INI feature. Do nothing",
				  v_lport->nport_id);
		}
	}

	return ret;
}

static unsigned int unf_handle_rscn_port_addr(
				struct unf_port_id_page_s *v_port_id_page,
				struct unf_gif_acc_pld_s *v_gid_acc_pld,
				struct unf_lport_s *v_lport)
{
	/*
	 * Input parameters:
	 * 1. Port_ID_page: saved from RSCN payload
	 * 2. GID_ACC_payload: back from GID_ACC (GID_PT or GID_FT)
	 **
	 * Do work: check whether RSCN Port_ID within GID_ACC payload or not
	 * then, re-login or link down rport
	 */
	unsigned int rscn_nport_id = 0;
	unsigned int gid_port_id = 0;
	unsigned int nport_id = 0;
	unsigned int i = 0;
	unsigned char control = 0;
	unsigned int ret = RETURN_OK;
	enum int_e have_same_id = UNF_FALSE;

	UNF_CHECK_VALID(0x3568, UNF_TRUE, v_port_id_page,
			return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(0x3569, UNF_TRUE, v_gid_acc_pld,
			return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(0x3570, UNF_TRUE, v_lport, return UNF_RETURN_ERROR);

	/* 1. get RSCN_NPort_ID from (L_Port->Disc->RSCN_Mgr)->RSCN_Port_ID_Page */
	rscn_nport_id = UNF_SERVICE_GET_NPORTID_FORM_GID_PAGE(v_port_id_page);

	/*
	 * 2. for RSCN_NPort_ID
	 * check whether RSCN_NPort_ID within GID_ACC_Payload or not
	 */
	while (i < UNF_GID_PORT_CNT) { /* 4k */
		gid_port_id = (v_gid_acc_pld->gid_port_id[i]);
		nport_id = UNF_NPORTID_MASK & gid_port_id;
		control = UNF_GID_CONTROL(gid_port_id);

		if ((v_lport->nport_id != nport_id) && (nport_id != 0)) {
			/* is not L_Port */
			if (rscn_nport_id == nport_id) {
				/* RSCN Port_ID within GID_ACC payload */
				have_same_id = UNF_TRUE;
				break;
			}
		}

		if ((control & UNF_GID_LAST_PORT_ID) == UNF_GID_LAST_PORT_ID)
			break;

		i++;
	}

	/* 3. RSCN_Port_ID not within GID_ACC payload table */
	if (have_same_id == UNF_FALSE) {
		/* rport has been removed */
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT, UNF_INFO,
			  "[warn]Port(0x%x_0x%x) find RSCN N_Port_ID(0x%x) in GID_ACC table failed",
			  v_lport->port_id, v_lport->nport_id,
			  rscn_nport_id);

		/* Link down rport */
		ret = unf_handle_rscn_port_not_in_disc(v_lport,
						       rscn_nport_id);
	} else { /* 4. RSCN_Port_ID within GID_ACC payload table */
		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT, UNF_INFO,
			  "[info]Port(0x%x_0x%x) find RSCN N_Port_ID(0x%x) in GID_ACC table succeed",
			  v_lport->port_id, v_lport->nport_id,
			  rscn_nport_id);

		/* Re-login with INI mode */
		ret = unf_handle_rscn_port_in_disc(v_lport, rscn_nport_id);
	}

	return ret;
}

static void unf_check_rport_rscn_process(
				struct unf_rport_s *v_rport,
				struct unf_port_id_page_s *v_port_id_page)
{
	struct unf_rport_s *rport = v_rport;
	struct unf_port_id_page_s *port_id_page = v_port_id_page;
	unsigned char format = port_id_page->uc_addr_format;

	switch (format) {
	/* domain+area */
	case UNF_RSCN_AREA_ADDR_GROUP:
		if (UNF_GET_DOMAIN_ID(rport->nport_id) ==
		    port_id_page->port_id_domain &&
		    UNF_GET_AREA_ID(rport->nport_id) ==
		    port_id_page->port_id_area) {
			rport->rscn_position = UNF_RPORT_NEED_PROCESS;
		}
		break;
	/* domain */
	case UNF_RSCN_DOMAIN_ADDR_GROUP:
		if (UNF_GET_DOMAIN_ID(rport->nport_id) ==
		    port_id_page->port_id_domain)
			rport->rscn_position = UNF_RPORT_NEED_PROCESS;
		break;
	/* all */
	case UNF_RSCN_FABRIC_ADDR_GROUP:
		rport->rscn_position = UNF_RPORT_NEED_PROCESS;
		break;
	default:
		break;
	}
}

static void unf_set_rport_rscn_position(
				struct unf_lport_s *v_lport,
				struct unf_port_id_page_s *v_port_id_page)
{
	struct unf_rport_s *rport = NULL;
	struct list_head *node = NULL;
	struct list_head *next_node = NULL;
	struct unf_disc_s *disc = NULL;
	unsigned long disc_flag = 0;
	unsigned long rport_flag = 0;

	UNF_CHECK_VALID(0x3571, UNF_TRUE, v_lport, return);
	disc = &v_lport->disc;

	spin_lock_irqsave(&disc->rport_busy_pool_lock, disc_flag);
	list_for_each_safe(node, next_node, &disc->list_busy_rports) {
		rport = list_entry(node, struct unf_rport_s, entry_rport);
		spin_lock_irqsave(&rport->rport_state_lock, rport_flag);

		if (rport->nport_id < UNF_FC_FID_DOM_MGR) {
			if (rport->rscn_position == UNF_RPORT_NOT_NEED_PROCESS)
				unf_check_rport_rscn_process(rport,
							     v_port_id_page);
		} else {
			rport->rscn_position = UNF_RPORT_NOT_NEED_PROCESS;
		}

		spin_unlock_irqrestore(&rport->rport_state_lock, rport_flag);
	}
	spin_unlock_irqrestore(&disc->rport_busy_pool_lock, disc_flag);
}

static void unf_set_rport_rscn_position_local(struct unf_lport_s *v_lport)
{
	struct unf_rport_s *rport = NULL;
	struct list_head *node = NULL;
	struct list_head *next_node = NULL;
	struct unf_disc_s *disc = NULL;
	unsigned long disc_flag = 0;
	unsigned long rport_flag = 0;

	UNF_CHECK_VALID(0x3572, UNF_TRUE, v_lport, return);
	disc = &v_lport->disc;

	spin_lock_irqsave(&disc->rport_busy_pool_lock, disc_flag);
	list_for_each_safe(node, next_node, &disc->list_busy_rports) {
		rport = list_entry(node, struct unf_rport_s, entry_rport);
		spin_lock_irqsave(&rport->rport_state_lock, rport_flag);

		if (rport->nport_id < UNF_FC_FID_DOM_MGR) {
			if (rport->rscn_position == UNF_RPORT_NEED_PROCESS)
				rport->rscn_position =
					UNF_RPORT_ONLY_IN_LOCAL_PROCESS;
		} else {
			rport->rscn_position = UNF_RPORT_NOT_NEED_PROCESS;
		}

		spin_unlock_irqrestore(&rport->rport_state_lock, rport_flag);
	}
	spin_unlock_irqrestore(&disc->rport_busy_pool_lock, disc_flag);
}

static void unf_reset_rport_rscn_setting(struct unf_lport_s *v_lport)
{
	struct unf_rport_s *rport = NULL;
	struct list_head *node = NULL;
	struct list_head *next_node = NULL;
	struct unf_disc_s *disc = NULL;
	unsigned long rport_flag = 0;

	UNF_CHECK_VALID(0x3573, UNF_TRUE, v_lport, return);
	disc = &v_lport->disc;

	list_for_each_safe(node, next_node, &disc->list_busy_rports) {
		rport = list_entry(node, struct unf_rport_s, entry_rport);
		spin_lock_irqsave(&rport->rport_state_lock, rport_flag);
		rport->rscn_position = UNF_RPORT_NOT_NEED_PROCESS;
		spin_unlock_irqrestore(&rport->rport_state_lock, rport_flag);
	}
}

static void unf_compare_nport_id_with_rport_list(
				struct unf_lport_s *v_lport,
				unsigned int v_nport_id,
				struct unf_port_id_page_s *v_port_id_page)
{
	struct unf_rport_s *rport = NULL;
	unsigned long rport_flag = 0;
	unsigned char format = v_port_id_page->uc_addr_format;

	UNF_CHECK_VALID(0x3574, UNF_TRUE, v_lport, return);

	switch (format) {
	/* domain+area */
	case UNF_RSCN_AREA_ADDR_GROUP:
		if ((UNF_GET_DOMAIN_ID(v_nport_id) !=
		    v_port_id_page->port_id_domain) ||
		    (UNF_GET_AREA_ID(v_nport_id) !=
		    v_port_id_page->port_id_area))
			return;
		break;
	/* domain */
	case UNF_RSCN_DOMAIN_ADDR_GROUP:
		if (UNF_GET_DOMAIN_ID(v_nport_id) !=
		   v_port_id_page->port_id_domain)
			return;
		break;
	/* all */
	case UNF_RSCN_FABRIC_ADDR_GROUP:
		break;
	/* can't enter this branch guarantee by outer */
	default:
		break;
	}

	rport = unf_get_rport_by_nport_id(v_lport, v_nport_id);

	if (!rport) {
		if ((v_lport->options & UNF_PORT_MODE_INI) ==
		    UNF_PORT_MODE_INI) {
			UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT,
				  UNF_KEVENT,
				  "[event]Port(0x%x) Find Rport(0x%x) by RSCN",
				  v_lport->nport_id, v_nport_id);
			unf_rport_relogin(v_lport, v_nport_id);
		}
	} else {
		spin_lock_irqsave(&rport->rport_state_lock, rport_flag);
		if (rport->rscn_position == UNF_RPORT_NEED_PROCESS)
			rport->rscn_position =
				UNF_RPORT_IN_DISC_AND_LOCAL_PROCESS;

		spin_unlock_irqrestore(&rport->rport_state_lock, rport_flag);
	}
}

static void unf_compare_disc_with_local_rport(
				struct unf_lport_s *v_lport,
				struct unf_gif_acc_pld_s *v_gid_acc_pld,
				struct unf_port_id_page_s *v_port_id_page)
{
	unsigned int gid_port_id = 0;
	unsigned int nport_id = 0;
	unsigned int i = 0;
	unsigned char control = 0;

	UNF_CHECK_VALID(0x3575, UNF_TRUE, v_gid_acc_pld, return);
	UNF_CHECK_VALID(0x3576, UNF_TRUE, v_lport, return);

	while (i < UNF_GID_PORT_CNT) {
		gid_port_id = (v_gid_acc_pld->gid_port_id[i]);
		nport_id = UNF_NPORTID_MASK & gid_port_id;
		control = UNF_GID_CONTROL(gid_port_id);

		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT, UNF_INFO,
			  "[info]Port(0x%x) DISC N_Port_ID(0x%x)",
			  v_lport->nport_id, nport_id);

		if ((nport_id != 0) &&
		    (!unf_lookup_lport_by_nport_id(v_lport, nport_id)))
			unf_compare_nport_id_with_rport_list(v_lport, nport_id,
							     v_port_id_page);

		if ((UNF_GID_LAST_PORT_ID & control) == UNF_GID_LAST_PORT_ID)
			break;

		i++;
	}

	unf_set_rport_rscn_position_local(v_lport);
}

static unsigned int unf_process_each_rport_after_rscn(
						struct unf_lport_s *v_lport,
						struct unf_rport_s *v_sns_port,
						struct unf_rport_s *v_rport)
{
	unsigned long rport_flag = 0;
	unsigned int ret = RETURN_OK;

	UNF_CHECK_VALID(0x3577, UNF_TRUE, v_lport, return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(0x3578, UNF_TRUE, v_sns_port, return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(0x3579, UNF_TRUE, v_sns_port, return UNF_RETURN_ERROR);

	UNF_REFERNCE_VAR(v_sns_port);

	spin_lock_irqsave(&v_rport->rport_state_lock, rport_flag);

	if (v_rport->rscn_position == UNF_RPORT_IN_DISC_AND_LOCAL_PROCESS) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT,
			  UNF_KEVENT,
			  "[info]Port(0x%x_0x%x) RPort(0x%x) rescan position(0x%x), check wwpn",
			  v_lport->port_id, v_lport->nport_id,
			  v_rport->nport_id, v_rport->rscn_position);
		v_rport->rscn_position = UNF_RPORT_NOT_NEED_PROCESS;
		spin_unlock_irqrestore(&v_rport->rport_state_lock, rport_flag);
		ret = unf_rport_check_wwn(v_lport, v_rport);
	} else if (v_rport->rscn_position ==
		   UNF_RPORT_ONLY_IN_LOCAL_PROCESS) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT,
			  UNF_KEVENT,
			  "[event]Port(0x%x_0x%x) RPort(0x%x) rescan position(0x%x), linkdown it",
			  v_lport->port_id, v_lport->nport_id,
			  v_rport->nport_id, v_rport->rscn_position);
		v_rport->rscn_position = UNF_RPORT_NOT_NEED_PROCESS;
		spin_unlock_irqrestore(&v_rport->rport_state_lock, rport_flag);
		unf_rport_linkdown(v_lport, v_rport);
	} else {
		spin_unlock_irqrestore(&v_rport->rport_state_lock, rport_flag);
	}

	return ret;
}

static unsigned int unf_process_local_rport_after_rscn(
					struct unf_lport_s *v_lport,
					struct unf_rport_s *v_sns_port)
{
	struct unf_rport_s *rport = NULL;
	struct list_head *node = NULL;
	struct unf_disc_s *disc = NULL;
	unsigned long disc_flag = 0;
	unsigned int ret = RETURN_OK;

	UNF_CHECK_VALID(0x3580, UNF_TRUE, v_lport, return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(0x3581, UNF_TRUE, v_sns_port, return UNF_RETURN_ERROR);
	disc = &v_lport->disc;

	spin_lock_irqsave(&disc->rport_busy_pool_lock, disc_flag);
	if (list_empty(&disc->list_busy_rports)) {
		spin_unlock_irqrestore(&disc->rport_busy_pool_lock, disc_flag);

		return UNF_RETURN_ERROR;
	}

	node = (&disc->list_busy_rports)->next;

	do {
		rport = list_entry(node, struct unf_rport_s, entry_rport);

		if (rport->rscn_position == UNF_RPORT_NOT_NEED_PROCESS) {
			node = node->next;
			continue;
		} else {
			spin_unlock_irqrestore(&disc->rport_busy_pool_lock,
					       disc_flag);
			ret = unf_process_each_rport_after_rscn(v_lport,
								v_sns_port,
								rport);
			spin_lock_irqsave(&disc->rport_busy_pool_lock,
					  disc_flag);
			node = (&disc->list_busy_rports)->next;
		}
	} while (node != &disc->list_busy_rports);

	unf_reset_rport_rscn_setting(v_lport);
	spin_unlock_irqrestore(&disc->rport_busy_pool_lock, disc_flag);

	return ret;
}

static unsigned int unf_handle_rscn_group_addr(
				struct unf_port_id_page_s *v_port_id_page,
				struct unf_gif_acc_pld_s *v_gid_acc_pld,
				struct unf_lport_s *v_lport)
{
	struct unf_rport_s *sns_port = NULL;
	unsigned int ret = RETURN_OK;

	UNF_CHECK_VALID(0x3582, UNF_TRUE, v_port_id_page,
			return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(0x3583, UNF_TRUE, v_gid_acc_pld,
			return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(0x3584, UNF_TRUE, v_lport, return UNF_RETURN_ERROR);

	UNF_REFERNCE_VAR(v_port_id_page);

	sns_port = unf_get_rport_by_nport_id(v_lport, UNF_FC_FID_DIR_SERV);
	if (!sns_port) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT, UNF_WARN,
			  "[warn]Port(0x%x) find fabric port failed",
			  v_lport->port_id);

		return UNF_RETURN_ERROR;
	}

	unf_set_rport_rscn_position(v_lport, v_port_id_page);
	unf_compare_disc_with_local_rport(v_lport, v_gid_acc_pld,
					  v_port_id_page);

	ret = unf_process_local_rport_after_rscn(v_lport, sns_port);
	return ret;
}

static void unf_handle_rscn_gid_acc(struct unf_gif_acc_pld_s *v_gid_acc_pld,
				    struct unf_lport_s *v_lport)
{
	/* for N_Port_ID table return from RSCN */
	struct unf_port_id_page_s *port_id_page = NULL;
	struct unf_rscn_mg_s *rscn_mgr = NULL;
	struct list_head *list_node = NULL;
	unsigned long flag = 0;

	UNF_CHECK_VALID(0x3585, UNF_TRUE, v_gid_acc_pld, return);
	UNF_CHECK_VALID(0x3586, UNF_TRUE, v_lport, return);
	rscn_mgr = &v_lport->disc.rscn_mgr;

	spin_lock_irqsave(&rscn_mgr->rscn_id_list_lock, flag);
	while (!list_empty(&rscn_mgr->list_using_rscn_page)) {
		/*
		 * for each RSCN_Using_Page(NPortID)
		 * for each L_Port->Disc->RSCN_Mgr->
		 * RSCN_Using_Page(Port_ID_Page)
		 * NOTE:
		 * check using_page_port_id whether within
		 * GID_ACC payload or not
		 */
		list_node = (&rscn_mgr->list_using_rscn_page)->next;
		port_id_page = list_entry(list_node, struct unf_port_id_page_s,
					  list_node_rscn);
		/* NOTE: here delete node (from RSCN using Page) */
		list_del(list_node);
		spin_unlock_irqrestore(&rscn_mgr->rscn_id_list_lock, flag);

		switch (port_id_page->uc_addr_format) {
		/* each page of RSNC corresponding one of N_Port_ID */
		case UNF_RSCN_PORT_ADDR:
			(void)unf_handle_rscn_port_addr(port_id_page,
							v_gid_acc_pld,
							v_lport);
			break;

		/* each page of RSNC corresponding address group */
		case UNF_RSCN_AREA_ADDR_GROUP:
		case UNF_RSCN_DOMAIN_ADDR_GROUP:
		case UNF_RSCN_FABRIC_ADDR_GROUP:
			(void)unf_handle_rscn_group_addr(port_id_page,
							 v_gid_acc_pld,
							 v_lport);
			break;

		default:
			break;
		}

		/* NOTE: release this RSCN_Node */
		rscn_mgr->pfn_unf_release_rscn_node(rscn_mgr, port_id_page);

		/* go to next */
		spin_lock_irqsave(&rscn_mgr->rscn_id_list_lock, flag);
	}
	spin_unlock_irqrestore(&rscn_mgr->rscn_id_list_lock, flag);
}

static void unf_gid_acc_handle(struct unf_gif_acc_pld_s *v_gid_acc_pld,
			       struct unf_lport_s *v_lport)
{
#define UNF_NONE_DISC 0X0 /* before enter DISC */

	struct unf_disc_s *disc = NULL;
	unsigned long flag = 0;

	UNF_CHECK_VALID(0x3587, UNF_TRUE, v_gid_acc_pld, return);
	UNF_CHECK_VALID(0x3588, UNF_TRUE, v_lport, return);
	disc = &v_lport->disc;

	spin_lock_irqsave(&disc->rport_busy_pool_lock, flag);
	switch (disc->disc_option) {
	case UNF_INIT_DISC:  // from SCR callback with INI mode
		disc->disc_option = UNF_NONE_DISC;
		spin_unlock_irqrestore(&disc->rport_busy_pool_lock, flag);
		/* R_Port from Disc_list */
		unf_handle_init_gid_acc(v_gid_acc_pld, v_lport);
		break;

	case UNF_RSCN_DISC:  /* from RSCN payload parse(analysis) */
		disc->disc_option = UNF_NONE_DISC;
		spin_unlock_irqrestore(&disc->rport_busy_pool_lock, flag);

		/* R_Port from busy_list */
		unf_handle_rscn_gid_acc(v_gid_acc_pld, v_lport);
		break;

	default:
		spin_unlock_irqrestore(&disc->rport_busy_pool_lock, flag);

		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT, UNF_WARN,
			  "[warn]Port(0x%x_0x%x)'s disc option(0x%x) is abnormal",
			  v_lport->port_id,
			  v_lport->nport_id,
			  disc->disc_option);
		break;
	}
}

static void unf_gid_ft_callback(void *v_lport, void *v_rport, void *v_xchg)
{
	struct unf_lport_s *lport = NULL;
	struct unf_disc_s *disc = NULL;
	struct unf_gif_acc_pld_s *gid_acc_pld = NULL;
	struct unf_xchg_s *xchg = NULL;
	union unf_sfs_u *sfs_ptr = NULL;
	unsigned int cmnd_rsp_size = 0;
	unsigned int rjt_reason = 0;
	unsigned long flag = 0;

	UNF_CHECK_VALID(0x3590, UNF_TRUE, v_lport, return);
	UNF_CHECK_VALID(0x3591, UNF_TRUE, v_rport, return);
	UNF_CHECK_VALID(0x3592, UNF_TRUE, v_xchg, return);
	UNF_REFERNCE_VAR(v_rport);

	lport = (struct unf_lport_s *)v_lport;
	xchg = (struct unf_xchg_s *)v_xchg;
	disc = &lport->disc;

	sfs_ptr = xchg->fcp_sfs_union.sfs_entry.fc_sfs_entry_ptr;
	gid_acc_pld = sfs_ptr->get_id.gid_rsp.gid_acc_pld;
	if (!gid_acc_pld) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT, UNF_WARN,
			  "[warn]LOGIN: Port(0x%x) GID_FT response payload is NULL",
			  lport->port_id);

		return;
	}

	cmnd_rsp_size = (gid_acc_pld->ctiu_pream.cmnd_rsp_size);
	if ((cmnd_rsp_size & UNF_CT_IU_RSP_MASK) == UNF_CT_IU_ACCEPT) {
		spin_lock_irqsave(&disc->rport_busy_pool_lock, flag);
		unf_disc_state_ma(lport, UNF_EVENT_DISC_SUCCESS);
		spin_unlock_irqrestore(&disc->rport_busy_pool_lock, flag);

		/* Process GID_FT ACC */
		unf_gid_acc_handle(gid_acc_pld, lport);
	} else if ((cmnd_rsp_size & UNF_CT_IU_RSP_MASK) == UNF_CT_IU_REJECT) {
		rjt_reason = (gid_acc_pld->ctiu_pream.frag_reason_exp_vend);

		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT, UNF_WARN,
			  "[warn]LOGIN: Port(0x%x) GID_FT was rejected with reason code(0x%x)",
			  lport->port_id, rjt_reason);

		if ((rjt_reason & UNF_CTIU_RJT_EXP_MASK) ==
		    UNF_CTIU_RJT_EXP_FC4TYPE_NO_REG) {
			spin_lock_irqsave(&disc->rport_busy_pool_lock, flag);
			unf_disc_state_ma(lport, UNF_EVENT_DISC_SUCCESS);
			spin_unlock_irqrestore(&disc->rport_busy_pool_lock,
					       flag);

			unf_gid_acc_handle(gid_acc_pld, lport);
		} else {
			spin_lock_irqsave(&disc->rport_busy_pool_lock, flag);
			unf_disc_state_ma(lport, UNF_EVENT_DISC_SUCCESS);
			spin_unlock_irqrestore(&disc->rport_busy_pool_lock,
					       flag);
		}
	} else {
		spin_lock_irqsave(&disc->rport_busy_pool_lock, flag);
		unf_disc_state_ma(lport, UNF_EVENT_DISC_FAILED);
		spin_unlock_irqrestore(&disc->rport_busy_pool_lock, flag);

		/* Do DISC recovery operation */
		unf_disc_error_recovery(lport);
	}
}

static void unf_gid_pt_callback(void *v_lport, void *v_rport, void *v_xchg)
{
	struct unf_lport_s *lport = NULL;
	struct unf_rport_s *rport = NULL;
	struct unf_disc_s *disc = NULL;
	struct unf_gif_acc_pld_s *gid_acc_pld = NULL;
	struct unf_xchg_s *xchg = NULL;
	union unf_sfs_u *sfs_ptr = NULL;
	unsigned int cmnd_rsp_size = 0;
	unsigned int rjt_reason = 0;
	unsigned long flag = 0;
	unsigned int ret = UNF_RETURN_ERROR;

	UNF_CHECK_VALID(0x3594, UNF_TRUE, v_lport, return);
	UNF_CHECK_VALID(0x3595, UNF_TRUE, v_rport, return);
	UNF_CHECK_VALID(0x3596, UNF_TRUE, v_xchg, return);

	lport = (struct unf_lport_s *)v_lport;
	rport = (struct unf_rport_s *)v_rport;
	disc = &lport->disc;
	xchg = (struct unf_xchg_s *)v_xchg;
	sfs_ptr = xchg->fcp_sfs_union.sfs_entry.fc_sfs_entry_ptr;

	gid_acc_pld = sfs_ptr->get_id.gid_rsp.gid_acc_pld;
	if (!gid_acc_pld) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT, UNF_WARN,
			  "[warn]LOGIN: Port(0x%x) GID_PT response payload is NULL",
			  lport->port_id);

		return;
	}

	cmnd_rsp_size = (gid_acc_pld->ctiu_pream.cmnd_rsp_size);
	if ((cmnd_rsp_size & UNF_CT_IU_RSP_MASK) == UNF_CT_IU_ACCEPT) {
		spin_lock_irqsave(&disc->rport_busy_pool_lock, flag);
		unf_disc_state_ma(lport, UNF_EVENT_DISC_SUCCESS);
		spin_unlock_irqrestore(&disc->rport_busy_pool_lock, flag);

		unf_gid_acc_handle(gid_acc_pld, lport);
	} else if ((cmnd_rsp_size & UNF_CT_IU_RSP_MASK) == UNF_CT_IU_REJECT) {
		rjt_reason = (gid_acc_pld->ctiu_pream.frag_reason_exp_vend);

		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT, UNF_WARN,
			  "[warn]LOGIN: Port(0x%x_0x%x) GID_PT was rejected with reason code(0x%x)",
			  lport->port_id, lport->nport_id, rjt_reason);

		if (UNF_CTIU_RJT_EXP_PORTTYPE_NO_REG ==
		    (rjt_reason & UNF_CTIU_RJT_EXP_MASK)) {
			spin_lock_irqsave(&disc->rport_busy_pool_lock, flag);
			unf_disc_state_ma(lport, UNF_EVENT_DISC_SUCCESS);
			spin_unlock_irqrestore(&disc->rport_busy_pool_lock,
					       flag);

			unf_gid_acc_handle(gid_acc_pld, lport);
		} else {
			ret = unf_send_gid_ft(lport, rport);
			if (ret != RETURN_OK) {
				spin_lock_irqsave(&disc->rport_busy_pool_lock,
						  flag);
				unf_disc_state_ma(lport, UNF_EVENT_DISC_FAILED);
				spin_unlock_irqrestore(
					&disc->rport_busy_pool_lock, flag);

				/* Do DISC recovery */
				unf_disc_error_recovery(lport);
			}
		}
	} else {
		spin_lock_irqsave(&disc->rport_busy_pool_lock, flag);
		unf_disc_state_ma(lport, UNF_EVENT_DISC_FAILED);
		spin_unlock_irqrestore(&disc->rport_busy_pool_lock, flag);

		/* Do DISC recovery */
		unf_disc_error_recovery(lport);
	}
}

void unf_rcv_gnn_id_rsp_unknown(struct unf_lport_s *v_lport,
				struct unf_rport_s *v_sns_port,
				unsigned int v_nport_id)
{
	/* Send GFF_ID */
	struct unf_lport_s *lport = v_lport;
	struct unf_rport_s *sns_port = v_sns_port;
	unsigned int ret = UNF_RETURN_ERROR;

	UNF_CHECK_VALID(0x3606, UNF_TRUE, v_lport, return);
	UNF_CHECK_VALID(0x3607, UNF_TRUE, v_sns_port, return);

	UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT,
		  UNF_WARN,
		  "[warn]LOGIN: Port(0x%x_0x%x) Rportid(0x%x) GNN_ID response is unknown. Sending GFF_ID",
		  lport->port_id, lport->nport_id, v_nport_id);

	ret = unf_get_and_post_disc_event(lport, sns_port, v_nport_id,
					  UNF_DISC_GET_FEATURE);
	if (ret != RETURN_OK) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_LOGIN_ATT, UNF_ERR,
			  "[err]Port(0x%x) add discovery event(0x%x) failed Rport(0x%x)",
			  lport->port_id, UNF_DISC_GET_FEATURE, v_nport_id);

		/* NOTE: go to next stage */
		unf_rcv_gff_id_rsp_unknown(lport, v_nport_id);  // send PLOGI
	}
}

void unf_rcv_gff_id_rsp_unknown(struct unf_lport_s *v_lport,
				unsigned int v_nport_id)
{
	/* Send PLOGI */
	struct unf_lport_s *lport = v_lport;
	struct unf_rport_s *rport = NULL;
	unsigned long flag = 0;
	unsigned int ret = RETURN_OK;

	UNF_CHECK_VALID(0x3624, UNF_TRUE, v_lport, return);

	UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT, UNF_WARN,
		  "[warn]LOGIN: Port(0x%x) send GFF_ID for RPort(0x%x) but response is unknown",
		  lport->port_id, v_nport_id);

	/* Get (Safe) R_Port & Set State */
	rport = unf_get_rport_by_nport_id(lport, v_nport_id);
	if (rport)
		rport = unf_find_rport(lport, v_nport_id, rport->port_name);

	if (!rport) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT, UNF_WARN,
			  "[warn]Port(0x%x_0x%x) can't get RPort by NPort ID(0x%x), allocate new RPort",
			  lport->port_id, lport->nport_id, v_nport_id);

		rport = unf_rport_get_free_and_init(lport, UNF_PORT_TYPE_FC,
						    v_nport_id);
		UNF_CHECK_VALID(0x3619, UNF_TRUE, NULL != rport, return);

		spin_lock_irqsave(&rport->rport_state_lock, flag);
		rport->nport_id = v_nport_id;
		spin_unlock_irqrestore(&rport->rport_state_lock, flag);
	}

	rport = unf_get_safe_rport(lport, rport, UNF_RPORT_REUSE_ONLY,
				   v_nport_id);
	UNF_CHECK_VALID(0x3625, UNF_TRUE, rport, return);

	/* Update R_Port state: PLOGI_WAIT */
	spin_lock_irqsave(&rport->rport_state_lock, flag);
	rport->nport_id = v_nport_id;
	unf_rport_state_ma(rport, UNF_EVENT_RPORT_ENTER_PLOGI);
	spin_unlock_irqrestore(&rport->rport_state_lock, flag);

	/* Start to send PLOGI */
	ret = unf_send_plogi(lport, rport);
	if (ret != RETURN_OK) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT, UNF_WARN,
			  "[warn]LOGIN: Port(0x%x) can not send PLOGI for RPort(0x%x), enter recovery",
			  lport->port_id, v_nport_id);

		unf_rport_error_recovery(rport);
	}
}

static void unf_lport_update_nport_id(struct unf_lport_s *v_lport,
				      unsigned int v_nport_id)
{
	unsigned long flag = 0;

	UNF_CHECK_VALID(0x3646, UNF_TRUE, v_lport, return);

	spin_lock_irqsave(&v_lport->lport_state_lock, flag);
	v_lport->nport_id = v_nport_id;
	spin_unlock_irqrestore(&v_lport->lport_state_lock, flag);
}

static void unf_lport_update_time_params(
				struct unf_lport_s *v_lport,
				struct unf_flogi_payload_s *v_flogi_payload)
{
	unsigned long flag = 0;
	unsigned int ed_tov = 0;
	unsigned int ra_tov = 0;

	UNF_CHECK_VALID(0x3647, UNF_TRUE, v_lport, return);
	UNF_CHECK_VALID(0x3648, UNF_TRUE, v_flogi_payload, return);

	ed_tov = v_flogi_payload->fabric_parms.co_parms.e_d_tov;
	ra_tov = v_flogi_payload->fabric_parms.co_parms.r_a_tov;

	spin_lock_irqsave(&v_lport->lport_state_lock, flag);

	/* FC-FS-3: 21.3.4, 21.3.5 */
	if ((v_lport->en_act_topo == UNF_ACT_TOP_P2P_FABRIC) ||
	    (v_lport->en_act_topo == UNF_ACT_TOP_PUBLIC_LOOP)) {
		v_lport->ed_tov = ed_tov;
		v_lport->ra_tov = ra_tov;
	} else {
		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_EQUIP_ATT,
			  UNF_MAJOR,
			  "[info]Port(0x%x_0x%x) with topo(0x%x) no need to save time parameters",
			  v_lport->port_id, v_lport->nport_id,
			  v_lport->en_act_topo);
	}

	spin_unlock_irqrestore(&v_lport->lport_state_lock, flag);
}

static void unf_fdisc_callback(void *v_lport, void *v_rport, void *v_xchg)
{
	/* Register to Name Server or Do recovery */
	struct unf_lport_s *lport = NULL;
	struct unf_rport_s *rport = NULL;
	struct unf_xchg_s *xchg = NULL;
	struct unf_flogi_payload_s *fdisc_pld = NULL;
	unsigned long flag = 0;
	unsigned int cmd = 0;

	lport = (struct unf_lport_s *)v_lport;
	rport = (struct unf_rport_s *)v_rport;
	xchg = (struct unf_xchg_s *)v_xchg;
	UNF_CHECK_VALID(0x3640, UNF_TRUE, v_lport, return);
	UNF_CHECK_VALID(0x3641, UNF_TRUE, v_rport, return);
	UNF_CHECK_VALID(0x3642, UNF_TRUE, v_xchg, return);
	UNF_CHECK_VALID(0x3643, UNF_TRUE,
			xchg->fcp_sfs_union.sfs_entry.fc_sfs_entry_ptr,
			return);
	fdisc_pld = &xchg->fcp_sfs_union.sfs_entry.fc_sfs_entry_ptr->fdisc_acc.fdisc_payload;
	if (xchg->byte_orders & UNF_BIT_2)
		unf_big_end_to_cpu((unsigned char *)fdisc_pld,
				   sizeof(struct unf_flogi_payload_s));

	cmd = fdisc_pld->cmnd;
	UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT, UNF_MAJOR,
		  "[info]LOGIN: FDISC response is (0x%x). Port(0x%x)<---RPort(0x%x) with OX_ID(0x%x)",
		  cmd, lport->port_id, rport->nport_id, xchg->ox_id);
	rport = unf_get_rport_by_nport_id(lport, UNF_FC_FID_FLOGI);
	rport = unf_get_safe_rport(lport, rport, UNF_RPORT_REUSE_ONLY,
				   UNF_FC_FID_FLOGI);
	if (!rport) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT, UNF_WARN,
			  "[warn]Port(0x%x) has no Rport", lport->port_id);
		return;
	}

	spin_lock_irqsave(&rport->rport_state_lock, flag);
	rport->nport_id = UNF_FC_FID_FLOGI;
	spin_unlock_irqrestore(&rport->rport_state_lock, flag);

	if ((cmd & UNF_ELS_CMND_HIGH_MASK) == UNF_ELS_CMND_ACC) {
		/* Case for ACC */
		spin_lock_irqsave(&lport->lport_state_lock, flag);
		if (lport->en_states != UNF_LPORT_ST_FLOGI_WAIT) {
			UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT,
				  UNF_WARN,
				  "[warn]Port(0x%x_0x%x) receive Flogi/Fdisc ACC in state(0x%x)",
				  lport->port_id, lport->nport_id,
				  lport->en_states);

			spin_unlock_irqrestore(&lport->lport_state_lock, flag);
			return;
		}
		spin_unlock_irqrestore(&lport->lport_state_lock, flag);

		unf_lport_update_nport_id(lport, xchg->sid);
		unf_lport_update_time_params(lport, fdisc_pld);

		unf_register_to_switch(lport);
	} else {
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT, UNF_WARN,
			  "[warn]LOGIN: FDISC response is (0x%x). Port(0x%x)<---RPort(0x%x) with OX_ID(0x%x)",
			  cmd, lport->port_id, rport->nport_id,
			  xchg->ox_id);

		/* Case for RJT: Do L_Port recovery */
		unf_lport_error_recovery(lport);
	}
}

static void unf_rcv_flogi_acc(struct unf_lport_s *v_lport,
			      struct unf_rport_s *v_rport,
			      struct unf_flogi_payload_s *v_flogi_pld,
			      unsigned int v_nport_id,
			      struct unf_xchg_s *v_xchg)
{
	/* PLOGI to Name server or remote port */
	struct unf_lport_s *lport = v_lport;
	struct unf_rport_s *rport = v_rport;
	struct unf_flogi_payload_s *flogi_pld = v_flogi_pld;
	struct unf_fabric_parms_s *fabric_params = NULL;
	unsigned long long port_name = 0;
	unsigned long long node_name = 0;
	unsigned long flag = 0;

	UNF_CHECK_VALID(0x3649, UNF_TRUE, v_lport, return);
	UNF_CHECK_VALID(0x3650, UNF_TRUE, v_rport, return);
	UNF_CHECK_VALID(0x3651, UNF_TRUE, v_flogi_pld, return);

	/* Check L_Port state: FLOGI_WAIT */
	spin_lock_irqsave(&lport->lport_state_lock, flag);
	if (lport->en_states != UNF_LPORT_ST_FLOGI_WAIT) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT, UNF_WARN,
			  "[info]Port(0x%x_0x%x) receive FLOGI ACC with state(0x%x)",
			  lport->port_id, lport->nport_id, lport->en_states);

		spin_unlock_irqrestore(&lport->lport_state_lock, flag);
		return;
	}
	spin_unlock_irqrestore(&lport->lport_state_lock, flag);

	fabric_params = &flogi_pld->fabric_parms;
	node_name = (unsigned long long)
		(((unsigned long long)(fabric_params->high_node_name) << 32) |
		 ((unsigned long long)(fabric_params->low_node_name)));
	port_name = (unsigned long long)
		(((unsigned long long)(fabric_params->high_port_name) << 32) |
		 ((unsigned long long)(fabric_params->low_port_name)));

	/* flogi acc pyload class 3 service priority value */
	lport->b_priority = UNF_PRIORITY_DISABLE;

	/* Save Flogi parameters */
	unf_save_fabric_params(lport, rport, fabric_params);

	if (UNF_CHECK_NPORT_FPORT_BIT(flogi_pld) == UNF_N_PORT) {
		/* P2P Mode */
		unf_lport_update_topo(lport, UNF_ACT_TOP_P2P_DIRECT);
		unf_login_with_rport_in_n2n(lport, port_name, node_name);
	} else {
		/* for: UNF_ACT_TOP_PUBLIC_LOOP
		 * /UNF_ACT_TOP_P2P_FABRIC/UNF_TOP_P2P_MASK
		 */
		if (lport->en_act_topo != UNF_ACT_TOP_PUBLIC_LOOP)
			unf_lport_update_topo(lport, UNF_ACT_TOP_P2P_FABRIC);

		unf_lport_update_nport_id(lport, v_nport_id);
		unf_lport_update_time_params(lport, flogi_pld);

		/* Save process both for Public loop & Fabric */
		unf_register_to_switch(lport);
	}
}

static void unf_flogi_acc_com_process(struct unf_xchg_s *v_xchg)
{
	/* Maybe within interrupt or thread context */
	struct unf_lport_s *lport = NULL;
	struct unf_rport_s *rport = NULL;
	struct unf_flogi_payload_s *flogi_pld = NULL;
	unsigned int nport_id = 0;
	unsigned int cmnd = 0;
	unsigned long flags = 0;
	struct unf_xchg_s *xchg = v_xchg;

	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE, xchg, return);
	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE, xchg->lport, return);

	lport = xchg->lport;
	rport = xchg->rport;
	flogi_pld = &xchg->fcp_sfs_union.sfs_entry.fc_sfs_entry_ptr->flogi_acc.flogi_payload;
	cmnd = flogi_pld->cmnd;

	/* Get N_Port_ID & R_Port */
	/* Others: 0xFFFFFE */
	rport = unf_get_rport_by_nport_id(lport, UNF_FC_FID_FLOGI);
	nport_id = UNF_FC_FID_FLOGI;

	/* Get Safe R_Port: reuse only */
	rport = unf_get_safe_rport(lport, rport, UNF_RPORT_REUSE_ONLY,
				   nport_id);
	if (!rport) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT, UNF_WARN,
			  "[warn]Port(0x%x) can not allocate new Rport",
			  lport->port_id);

		return;
	}

	/* Update R_Port N_Port_ID */
	spin_lock_irqsave(&rport->rport_state_lock, flags);
	/* Others: 0xFFFFFE */
	rport->nport_id = UNF_FC_FID_FLOGI;
	spin_unlock_irqrestore(&rport->rport_state_lock, flags);

	/* Process FLOGI ACC or RJT */
	if ((cmnd & UNF_ELS_CMND_HIGH_MASK) == UNF_ELS_CMND_ACC) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT, UNF_MAJOR,
			  "[info]LOGIN: FLOGI response is(0x%x). Port(0x%x)<---RPort(0x%x) with OX_ID(0x%x)",
			  cmnd, lport->port_id, rport->nport_id,
			  xchg->ox_id);

		/* Case for ACC */
		unf_rcv_flogi_acc(lport, rport, flogi_pld, xchg->sid, xchg);
	} else {
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT, UNF_WARN,
			  "[warn]LOGIN: FLOGI response is(0x%x). Port(0x%x)<---RPort(0x%x) with OX_ID(0x%x)",
			  cmnd, lport->port_id, rport->nport_id,
			  xchg->ox_id);

		/* Case for RJT: do L_Port error recovery */
		unf_lport_error_recovery(lport);
	}
}

static int unf_rcv_flogi_acc_async_callback(void *v_arg_in,
					    void *v_arg_out)
{
	struct unf_xchg_s *xchg = (struct unf_xchg_s *)v_arg_in;

	UNF_CHECK_VALID(0x2267, UNF_TRUE, xchg, return UNF_RETURN_ERROR);

	unf_flogi_acc_com_process(xchg);

	unf_xchg_ref_dec(xchg, SFS_RESPONSE);
	return RETURN_OK;
}

static void unf_flogi_callback(void *v_lport, void *v_rport, void *v_xchg)
{
	/* Callback function for FLOGI ACC or RJT */
	struct unf_lport_s *lport = (struct unf_lport_s *)v_lport;
	struct unf_xchg_s *xchg = (struct unf_xchg_s *)v_xchg;
	struct unf_flogi_payload_s *flogi_pld = NULL;
	int bbscn_enabled = UNF_FALSE;
	enum unf_act_topo_e act_topo = UNF_ACT_TOP_UNKNOWN;
	int switch_2_thread = UNF_FALSE;

	UNF_CHECK_VALID(0x3652, UNF_TRUE, v_lport, return);
	UNF_CHECK_VALID(0x3653, UNF_TRUE, v_rport, return);
	UNF_CHECK_VALID(0x3654, UNF_TRUE, v_xchg, return);
	UNF_CHECK_VALID(0x3655, UNF_TRUE,
			xchg->fcp_sfs_union.sfs_entry.fc_sfs_entry_ptr,
			return);

	xchg->lport = v_lport;
	flogi_pld = &xchg->fcp_sfs_union.sfs_entry.fc_sfs_entry_ptr->flogi_acc.flogi_payload;

	if (xchg->byte_orders & UNF_BIT_2)
		unf_big_end_to_cpu((unsigned char *)flogi_pld,
				   sizeof(struct unf_flogi_payload_s));

	if ((lport->en_act_topo != UNF_ACT_TOP_PUBLIC_LOOP) &&
	    (UNF_CHECK_NPORT_FPORT_BIT(flogi_pld) == UNF_F_PORT))
		/* Get Top Mode (P2P_F) --->>> used for BBSCN */
		act_topo = UNF_ACT_TOP_P2P_FABRIC;

	bbscn_enabled = unf_check_bbscn_is_enabled(
			(unsigned char)
			lport->low_level_func.lport_cfg_items.bb_scn,
			(unsigned char)
			UNF_GET_BB_SC_N_FROM_PARAMS(&flogi_pld->fabric_parms));
	if ((act_topo == UNF_ACT_TOP_P2P_FABRIC) &&
	    (bbscn_enabled == UNF_TRUE)) {
		/* BBSCN Enable or not --->>> used for Context change */
		lport->b_bbscn_support = UNF_TRUE;
		switch_2_thread = UNF_TRUE;
	}

	if ((switch_2_thread == UNF_TRUE) && (lport->root_lport == lport)) {
		/* Wait for LR done sync: for Root Port */
		(void)unf_irq_process_switch_2_thread(
					lport, xchg,
					unf_rcv_flogi_acc_async_callback);
	} else {
		/* Process FLOGI response directly */
		unf_flogi_acc_com_process(xchg);
	}

	UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT, UNF_ALL,
		  "[info]Port(0x%x) process FLOGI response: switch(%d) to thread done",
		  lport->port_id, switch_2_thread);
}

struct unf_rport_s *unf_find_rport(struct unf_lport_s *v_lport,
				   unsigned int v_rport_nport_id,
				   unsigned long long v_port_name)
{
	struct unf_lport_s *lport = v_lport;
	struct unf_rport_s *rport = NULL;

	UNF_CHECK_VALID(0x3658, UNF_TRUE, v_lport, return NULL);

	if (v_rport_nport_id >= UNF_FC_FID_DOM_MGR) // N_Port_ID <---> SID
		/* R_Port is Fabric: by N_Port_ID */
		rport = unf_get_rport_by_nport_id(lport, v_rport_nport_id);
	else
		/* Others: by WWPN & N_Port_ID */
		rport = unf_find_valid_rport(lport, v_port_name,
					     v_rport_nport_id);

	return rport;
}

static void unf_rcv_plogi_acc(struct unf_lport_s *v_lport,
			      struct unf_rport_s *v_rport,
			      struct unf_lgn_parms_s *v_login_parms)
{
	/* PLOGI ACC: PRLI(non fabric) or RFT_ID(fabric) */
	struct unf_lport_s *lport = v_lport;
	struct unf_rport_s *rport = v_rport;
	struct unf_lgn_parms_s *login_parms = v_login_parms;
	unsigned long long node_name = 0;
	unsigned long long port_name = 0;
	unsigned long flag = 0;
	unsigned int ret = RETURN_OK;

	UNF_CHECK_VALID(0x3659, UNF_TRUE, v_lport, return);
	UNF_CHECK_VALID(0x3660, UNF_TRUE, v_rport, return);
	UNF_CHECK_VALID(0x3661, UNF_TRUE, v_login_parms, return);

	node_name = (unsigned long long)
		(((unsigned long long)(login_parms->high_node_name) << 32) |
		 ((unsigned long long)(login_parms->low_node_name)));
	port_name = (unsigned long long)
		(((unsigned long long)(login_parms->high_port_name) << 32) |
		 ((unsigned long long)(login_parms->low_port_name)));

	/* ACC & Case for: R_Port is fabric (RFT_ID) */
	if (rport->nport_id >= UNF_FC_FID_DOM_MGR) {
		/* Check L_Port state */
		spin_lock_irqsave(&lport->lport_state_lock, flag);
		if (lport->en_states != UNF_LPORT_ST_PLOGI_WAIT) {
			spin_unlock_irqrestore(&lport->lport_state_lock, flag);

			UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT,
				  UNF_WARN,
				  "[warn]Port(0x%x) receive PLOGI ACC with error state(0x%x)",
				  v_lport->port_id, lport->en_states);

			return;
		}
		/* PLOGI_WAIT --> RFT_ID_WAIT */
		unf_lport_stat_ma(lport, UNF_EVENT_LPORT_REMOTE_ACC);
		spin_unlock_irqrestore(&lport->lport_state_lock, flag);

		/* PLOGI parameters save */
		unf_save_plogi_params(lport, rport, login_parms, ELS_ACC);

		/* Update R_Port WWPN & WWNN */
		spin_lock_irqsave(&rport->rport_state_lock, flag);
		rport->node_name = node_name;
		rport->port_name = port_name;
		spin_unlock_irqrestore(&rport->rport_state_lock, flag);

		/* Start to Send RFT_ID */
		ret = unf_send_rft_id(lport, rport);
		if (ret != RETURN_OK) {
			UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT,
				  UNF_WARN,
				  "[warn]LOGIN: Port(0x%x) send RFT_ID failed",
				  v_lport->port_id);

			unf_lport_error_recovery(lport);
		}
	} else {
		/* ACC & Case for: R_Port is not fabric */
		if ((rport->options == UNF_PORT_MODE_UNKNOWN) &&
		    (rport->port_name != INVALID_WWPN))
			rport->options = unf_get_port_feature(port_name);
		/* Set Port Feature with BOTH: cancel */

		spin_lock_irqsave(&rport->rport_state_lock, flag);
		rport->node_name = node_name;
		rport->port_name = port_name;

		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT, UNF_INFO,
			  "[info]LOGIN: Port(0x%x)<---LS_ACC(DID:0x%x SID:0x%x) for PLOGI ACC with RPort state(0x%x) NodeName(0x%llx) E_D_TOV(%d)",
			  lport->port_id, lport->nport_id,
			  rport->nport_id, rport->rp_state,
			  rport->node_name, rport->ed_tov);

		if ((lport->en_act_topo == UNF_ACT_TOP_PRIVATE_LOOP) &&
		    ((rport->rp_state == UNF_RPORT_ST_PRLI_WAIT) ||
		    (rport->rp_state == UNF_RPORT_ST_READY))) {
			/* Do nothing, return directly */
			spin_unlock_irqrestore(&rport->rport_state_lock, flag);
			return;
		}

		/* PRLI_WAIT */
		unf_rport_state_ma(rport, UNF_EVENT_RPORT_ENTER_PRLI);
		spin_unlock_irqrestore(&rport->rport_state_lock, flag);

		/* PLOGI parameters save */
		unf_save_plogi_params(lport, rport, login_parms, ELS_ACC);

		/*
		 * Need Delay to Send PRLI or not
		 * Used for: L_Port with INI mode & R_Port is not Fabric
		 */
		unf_check_rport_need_delay_prli(lport, rport,
						rport->options);

		/* Do not care: Just used for L_Port only is
		 * TGT mode or R_Port only is INI mode
		 */
		unf_schedule_open_work(lport, rport);
	}
}

static void unf_plogi_acc_com_process(struct unf_xchg_s *v_xchg)
{
	struct unf_lport_s *lport = NULL;
	struct unf_rport_s *rport = NULL;
	struct unf_xchg_s *xchg = (struct unf_xchg_s *)v_xchg;
	struct unf_plogi_payload_s *plogi_pld = NULL;
	struct unf_lgn_parms_s *login_parms = NULL;
	unsigned long flag = 0;
	unsigned long long port_name = 0;
	unsigned int rport_nport_id = 0;
	unsigned int cmnd = 0;
	unsigned int ret = UNF_RETURN_ERROR;

	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE, xchg, return);
	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE, xchg->lport, return);
	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE, xchg->rport, return);

	lport = xchg->lport;
	rport = xchg->rport;
	rport_nport_id = rport->nport_id;
	plogi_pld = &xchg->fcp_sfs_union.sfs_entry.fc_sfs_entry_ptr->plogi_acc.payload;
	login_parms = &plogi_pld->parms;
	cmnd = (plogi_pld->cmnd);

	if ((cmnd & UNF_ELS_CMND_HIGH_MASK) == UNF_ELS_CMND_ACC) {
		/* Case for PLOGI ACC: Go to next stage */
		port_name = (unsigned long long)
			(((unsigned long long)(login_parms->high_port_name) << 32) |
			 ((unsigned long long)(login_parms->low_port_name)));

		/* Get (new) R_Port: 0xfffffc has same WWN with 0xfffcxx */
		rport = unf_find_rport(lport, rport_nport_id, port_name);
		rport = unf_get_safe_rport(lport, rport, UNF_RPORT_REUSE_ONLY,
					   rport_nport_id);
		if (unlikely(!rport)) {
			UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT,
				  UNF_WARN,
				  "[warn]Port(0x%x_0x%x) alloc new RPort with wwpn(0x%llx) failed",
				  lport->port_id, lport->nport_id,
				  port_name);
			return;
		}

		/* PLOGI parameters check */
		ret = unf_check_plogi_params(lport, rport, login_parms);
		if (ret != RETURN_OK)
			return;

		/* Update R_Port state */
		spin_lock_irqsave(&rport->rport_state_lock, flag);
		rport->nport_id = rport_nport_id;
		/* --->>> PLOGI_WAIT */
		unf_rport_state_ma(rport, UNF_EVENT_RPORT_ENTER_PLOGI);
		spin_unlock_irqrestore(&rport->rport_state_lock, flag);

		/* Start to process PLOGI ACC */
		unf_rcv_plogi_acc(lport, rport, login_parms);
	} else {
		/* Case for PLOGI RJT: L_Port or R_Port recovery */
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT, UNF_WARN,
			  "[warn]LOGIN: Port(0x%x)<---RPort(0x%p) with LS_RJT(DID:0x%x SID:0x%x) for PLOGI",
			  lport->port_id, rport, lport->nport_id,
			  rport->nport_id);

		if (rport->nport_id >= UNF_FC_FID_DOM_MGR)
			/* for Name server */
			unf_lport_error_recovery(lport);
		else
			unf_rport_error_recovery(rport);
	}

	UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT, UNF_MAJOR,
		  "[info]LOGIN: PLOGI response(0x%x). Port(0x%x_0x%x)<---RPort(0x%x_0x%p) wwpn(0x%llx) OX_ID(0x%x)",
		  cmnd, lport->port_id, lport->nport_id, rport->nport_id,
		  rport, port_name, xchg->ox_id);
}

static int unf_rcv_plogi_acc_async_callback(void *v_argc_in, void *v_argc_out)
{
	struct unf_xchg_s *xchg = (struct unf_xchg_s *)v_argc_in;

	UNF_CHECK_VALID(0x2267, UNF_TRUE, xchg, return UNF_RETURN_ERROR);

	unf_plogi_acc_com_process(xchg);

	unf_xchg_ref_dec(xchg, SFS_RESPONSE);

	return RETURN_OK;
}

static void unf_plogi_callback(void *v_lport, void *v_rport, void *v_xchg)
{
	struct unf_lport_s *lport = (struct unf_lport_s *)v_lport;
	struct unf_xchg_s *xchg = (struct unf_xchg_s *)v_xchg;
	struct unf_plogi_payload_s *plogi_pld = NULL;
	struct unf_lgn_parms_s *login_parms = NULL;
	int bbscn_enabled = UNF_FALSE;
	int switch_2_thread = UNF_FALSE;

	UNF_CHECK_VALID(0x3662, UNF_TRUE, v_lport, return);
	UNF_CHECK_VALID(0x3663, UNF_TRUE, v_rport, return);
	UNF_CHECK_VALID(0x3664, UNF_TRUE, v_xchg, return);
	UNF_CHECK_VALID(0x3665, UNF_TRUE,
			xchg->fcp_sfs_union.sfs_entry.fc_sfs_entry_ptr,
			return);

	plogi_pld = &xchg->fcp_sfs_union.sfs_entry.fc_sfs_entry_ptr->plogi_acc.payload;
	login_parms = &plogi_pld->parms;
	xchg->lport = v_lport;

	if (xchg->byte_orders & UNF_BIT_2)
		unf_big_end_to_cpu((unsigned char *)plogi_pld,
				   sizeof(struct unf_plogi_payload_s));

	bbscn_enabled = unf_check_bbscn_is_enabled(
		(unsigned char)lport->low_level_func.lport_cfg_items.bb_scn,
		(unsigned char)UNF_GET_BB_SC_N_FROM_PARAMS(login_parms));
	if ((bbscn_enabled == UNF_TRUE) &&
	    (lport->en_act_topo == UNF_ACT_TOP_P2P_DIRECT)) {
		switch_2_thread = UNF_TRUE;
		lport->b_bbscn_support = UNF_TRUE;
	}

	if ((switch_2_thread == UNF_TRUE) && (lport->root_lport == lport)) {
		/* Wait for LR done sync: just for ROOT Port */
		(void)unf_irq_process_switch_2_thread(
					lport, xchg,
					unf_rcv_plogi_acc_async_callback);
	} else {
		unf_plogi_acc_com_process(xchg);
	}
}

static void unf_process_logo_in_pri_loop(struct unf_lport_s *v_lport,
					 struct unf_rport_s *v_rport)
{
	/* Send PLOGI or LOGO */
	struct unf_rport_s *rport = v_rport;
	unsigned long flag = 0;

	UNF_CHECK_VALID(0x3666, UNF_TRUE, v_lport, return);
	UNF_CHECK_VALID(0x3667, UNF_TRUE, v_rport, return);

	spin_lock_irqsave(&rport->rport_state_lock, flag);
	unf_rport_state_ma(rport, UNF_EVENT_RPORT_ENTER_PLOGI); /* PLOGI WAIT */
	spin_unlock_irqrestore(&rport->rport_state_lock, flag);

	/* Private Loop with INI mode, Avoid COM Mode problem */
	unf_rport_delay_login(rport);
}

static void unf_process_logo_in_n2n(struct unf_lport_s *v_lport,
				    struct unf_rport_s *v_rport)
{
	/* Send PLOGI or LOGO */
	struct unf_lport_s *lport = v_lport;
	struct unf_rport_s *rport = v_rport;
	unsigned long flag = 0;
	unsigned int ret = UNF_RETURN_ERROR;

	UNF_CHECK_VALID(0x3668, UNF_TRUE, v_lport, return);
	UNF_CHECK_VALID(0x3669, UNF_TRUE, v_rport, return);

	spin_lock_irqsave(&rport->rport_state_lock, flag);

	unf_rport_state_ma(rport, UNF_EVENT_RPORT_ENTER_PLOGI);  // PLOGI WAIT
	spin_unlock_irqrestore(&rport->rport_state_lock, flag);

	if (lport->port_name > rport->port_name) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT,
			  UNF_MAJOR,
			  "[info]Port(0x%x)'s WWN(0x%llx) is larger than(0x%llx), should be master",
			  lport->port_id, lport->port_name,
			  rport->port_name);

		ret = unf_send_plogi(lport, rport);
		if (ret != RETURN_OK) {
			UNF_TRACE(UNF_EVTLOG_DRIVER_WARN,
				  UNF_LOG_LOGIN_ATT,
				  UNF_WARN,
				  "[warn]LOGIN: Port(0x%x) send PLOGI failed, enter recovery",
				  v_lport->port_id);

			unf_rport_error_recovery(rport);
		}
	} else {
		unf_rport_enter_logo(lport, rport);
	}
}

void unf_process_logo_in_fabric(struct unf_lport_s *v_lport,
				struct unf_rport_s *v_rport)
{
	/* Send GFF_ID or LOGO */
	struct unf_lport_s *lport = v_lport;
	struct unf_rport_s *rport = v_rport;
	struct unf_rport_s *sns_port = NULL;
	unsigned int ret = UNF_RETURN_ERROR;

	UNF_CHECK_VALID(0x3670, UNF_TRUE, v_lport, return);
	UNF_CHECK_VALID(0x3671, UNF_TRUE, v_rport, return);

	/* L_Port with INI Mode: Send GFF_ID */
	sns_port = unf_get_rport_by_nport_id(lport, UNF_FC_FID_DIR_SERV);
	if (!sns_port) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT,
			  UNF_WARN,
			  "[warn]Port(0x%x) can't find fabric port",
			  lport->port_id);
		return;
	}

	ret = unf_get_and_post_disc_event(v_lport, sns_port, rport->nport_id,
					  UNF_DISC_GET_FEATURE);
	if (ret != RETURN_OK) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_LOGIN_ATT, UNF_ERR,
			  "[err]Port(0x%x) add discovery event(0x%x) failed Rport(0x%x)",
			  lport->port_id, UNF_DISC_GET_FEATURE,
			  rport->nport_id);

		unf_rcv_gff_id_rsp_unknown(lport, rport->nport_id);
	}
}

static void unf_process_rport_after_logo(struct unf_lport_s *v_lport,
					 struct unf_rport_s *v_rport)
{
	/*
	 * 1. LOGO handler
	 * 2. RPLO handler
	 * 3. LOGO_CALL_BACK (send LOGO ACC) handler
	 */
	struct unf_lport_s *lport = v_lport;
	struct unf_rport_s *rport = v_rport;

	UNF_CHECK_VALID(0x3672, UNF_TRUE, v_lport, return);
	UNF_CHECK_VALID(0x3673, UNF_TRUE, v_rport, return);

	if (rport->nport_id < UNF_FC_FID_DOM_MGR) {
		/* R_Port is not fabric port (retry LOGIN or LOGO) */
		if (lport->en_act_topo == UNF_ACT_TOP_PRIVATE_LOOP) {
			/* Private Loop: PLOGI or LOGO */
			unf_process_logo_in_pri_loop(lport, rport);
		} else if (lport->en_act_topo == UNF_ACT_TOP_P2P_DIRECT) {
			/* Point to Point: LOGIN or LOGO */
			unf_process_logo_in_n2n(lport, rport);
		} else {
			/* Fabric or Public Loop: GFF_ID or LOGO */
			unf_process_logo_in_fabric(lport, rport);
		}
	} else {
		/* Rport is fabric port: link down now */
		unf_rport_linkdown(lport, rport);
	}
}

static unsigned int unf_rcv_bls_req_done(struct unf_lport_s *v_lport,
					 struct unf_frame_pkg_s *v_pkg)
{
	/*
	 * About I/O resource:
	 * 1. normal: Release I/O resource during RRQ processer
	 * 2. exception: Release I/O resource immediately
	 */
	struct unf_xchg_s *xchg = NULL;
	unsigned short hot_pool_tag = 0;
	unsigned long flags = 0;
	unsigned long time_ms = 0;
	unsigned int ret = RETURN_OK;
	struct unf_lport_s *lport = NULL;

	UNF_CHECK_VALID(0x3723, UNF_TRUE, v_lport, return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(0x3724, UNF_TRUE, v_pkg, return UNF_RETURN_ERROR);
	lport = v_lport;

	/* 1. BLS Request Response: Hot Pool Tag --->>> OX_ID */
	hot_pool_tag =
		(unsigned short)v_pkg->private[PKG_PRIVATE_XCHG_HOT_POOL_INDEX];
	xchg = (struct unf_xchg_s *)unf_cm_lookup_xchg_by_tag(
						(void *)lport, hot_pool_tag);
	if (!xchg) {
		UNF_TRACE(UNF_EVTLOG_IO_WARN, UNF_LOG_IO_ATT, UNF_WARN,
			  "[warn]Port(0x%x) can't find exchange by tag(0x%x) when receiving ABTS response",
			  lport->port_id, hot_pool_tag);

		/* return directly */
		return UNF_RETURN_ERROR;
	}

	/* Consistency check */
	UNF_CHECK_ALLOCTIME_VALID(v_lport, hot_pool_tag, xchg,
				  v_pkg->private[PKG_PRIVATE_XCHG_ALLOC_TIME],
				  xchg->private[PKG_PRIVATE_XCHG_ALLOC_TIME]);

	/* 2. Increase ref_cnt for exchange protecting */

	ret = unf_xchg_ref_inc(xchg, TGT_ABTS_DONE);  /* hold */
	UNF_CHECK_VALID(0x3725, UNF_TRUE, (ret == RETURN_OK),
			return UNF_RETURN_ERROR);

	/* 3. Exchag I/O State Set & Check: reused */
	spin_lock_irqsave(&xchg->xchg_state_lock, flags);
	xchg->io_state |= INI_IO_STATE_DONE;  /* I/O Done */
	xchg->abts_state |= ABTS_RESPONSE_RECEIVED;
	if (!(xchg->io_state & INI_IO_STATE_UPABORT)) {
		/* NOTE: I/O exchange has been released and used again */
		spin_unlock_irqrestore(&xchg->xchg_state_lock, flags);

		UNF_TRACE(UNF_EVTLOG_IO_WARN, UNF_LOG_IO_ATT, UNF_WARN,
			  "[warn]Port(0x%x_0x%x) SID(0x%x) exch(0x%p) (0x%x:0x%x:0x%x:0x%x) state(0x%x) is abnormal with cnt(0x%x)",
			  lport->port_id, lport->nport_id,
			  xchg->sid, xchg, xchg->hot_pool_tag,
			  xchg->ox_id, xchg->rx_id, xchg->oid,
			  xchg->io_state,
			  atomic_read(&xchg->ref_cnt));

		/* return directly */
		/* cancel ref & do nothing */
		unf_xchg_ref_dec(xchg, TGT_ABTS_DONE);
		return UNF_RETURN_ERROR;
	}
	spin_unlock_irqrestore(&xchg->xchg_state_lock, flags);

	/* 4. Exchange Timer check, cancel if necessary */
	lport->xchg_mgr_temp.pfn_unf_xchg_cancel_timer((void *)xchg);

	/*
	 * 5. Exchage I/O Status check: Succ-> Add RRQ Timer
	 * ***** pkg->status --- to --->>> scsi_cmnd->result *****
	 *
	 * FAILED: ERR_Code or X_ID is err, or BA_RSP type is err
	 */
	spin_lock_irqsave(&xchg->xchg_state_lock, flags);
	if (v_pkg->status == UNF_IO_SUCCESS) {
		/* Succeed: PKG status -->> EXCH status -->> scsi status */
		UNF_SET_SCSI_CMND_RESULT(xchg, UNF_IO_SUCCESS);
		xchg->io_state |= INI_IO_STATE_WAIT_RRQ;
		xchg->rx_id = UNF_GET_RXID(v_pkg);
		spin_unlock_irqrestore(&xchg->xchg_state_lock, flags);

		/* Add RRQ timer */
		time_ms = (unsigned long)(lport->ra_tov);
		lport->xchg_mgr_temp.pfn_unf_xchg_add_timer(
							(void *)xchg,
							time_ms,
							UNF_TIMER_TYPE_INI_RRQ);
	} else {
		/* Failed: PKG status -->> EXCH status -->> scsi status */
		UNF_SET_SCSI_CMND_RESULT(xchg, UNF_IO_FAILED);
		if (MARKER_STS_RECEIVED & xchg->abts_state) {
			spin_unlock_irqrestore(&xchg->xchg_state_lock, flags);

			/* NOTE: release I/O resource immediately */
			unf_cm_free_xchg(lport, xchg);
		} else {
			UNF_TRACE(UNF_EVTLOG_IO_WARN, UNF_LOG_IO_ATT, UNF_WARN,
				  "[warn]Port(0x%x) exch(0x%p) OX_RX(0x%x:0x%x) IOstate(0x%x) ABTSstate(0x%x) receive response abnormal ref(0x%x)",
				  lport->port_id, xchg, xchg->ox_id,
				  xchg->rx_id,
				  xchg->io_state, xchg->abts_state,
				  atomic_read(&xchg->ref_cnt));
			spin_unlock_irqrestore(&xchg->xchg_state_lock, flags);
		}
	}

	/*
	 * 6. If abts response arrived before
	 * marker sts received just wake up abts marker sema
	 */
	spin_lock_irqsave(&xchg->xchg_state_lock, flags);
	if (!(xchg->abts_state & MARKER_STS_RECEIVED)) {
		xchg->ucode_abts_state = v_pkg->status;
		spin_unlock_irqrestore(&xchg->xchg_state_lock, flags);

		/* NOTE: wake up semaphore */
		up(&xchg->task_sema);
	} else {
		spin_unlock_irqrestore(&xchg->xchg_state_lock, flags);
	}

	/* 7. dec exch ref_cnt */
	unf_xchg_ref_dec(xchg, TGT_ABTS_DONE);
	return ret;
}

static unsigned int unf_rcv_abort_ini_io_done(struct unf_lport_s *v_lport,
					      struct unf_frame_pkg_s *v_pkg)
{
	/* INI mode: do not care */
	struct unf_xchg_s *io_xchg = NULL;
	unsigned short io_pool_tag = 0;
	unsigned int ret = RETURN_OK;

	UNF_CHECK_VALID(0x3735, UNF_TRUE, v_lport, return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(0x3736, UNF_TRUE, v_pkg, return UNF_RETURN_ERROR);

	io_pool_tag = UNF_GET_IO_XCHG_TAG(v_pkg);
	io_xchg = (struct unf_xchg_s *)unf_cm_lookup_xchg_by_tag(
							(void *)v_lport,
							io_pool_tag);
	if (io_xchg) {
		UNF_CHECK_ALLOCTIME_VALID(
			v_lport, io_pool_tag, io_xchg,
			v_pkg->private[PKG_PRIVATE_XCHG_ALLOC_TIME],
			io_xchg->private[PKG_PRIVATE_XCHG_ALLOC_TIME]);

		/* 1. Timer release */
		v_lport->xchg_mgr_temp.pfn_unf_xchg_cancel_timer(
							(void *)io_xchg);

		UNF_TRACE(UNF_EVTLOG_IO_INFO, UNF_LOG_IO_ATT, UNF_MAJOR,
			  "[info]Port(0x%x) abort INI IO with status(0x%x) exchange(0x%p) tag(0x%x)",
			  v_lport->port_id, v_pkg->status,
			  io_xchg, io_pool_tag);

		/* 2. Free I/O Exchange context */
		unf_cm_free_xchg((void *)v_lport, (void *)io_xchg);
	}

	return ret;
}

unsigned int unf_receive_bls_pkg(void *v_lport, struct unf_frame_pkg_s *v_pkg)
{
	struct unf_lport_s *lport = NULL;
	unsigned int ret = UNF_RETURN_ERROR;

	lport = (struct unf_lport_s *)v_lport;
	UNF_CHECK_VALID(0x3730, UNF_TRUE, lport, return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(0x3731, UNF_TRUE, v_pkg, return UNF_RETURN_ERROR);

	if (v_pkg->type == UNF_PKG_BLS_REQ_DONE) {
		/* INI: RCVD BLS Req Done */
		ret = unf_rcv_bls_req_done(v_lport, v_pkg);
	} else if (v_pkg->type == UNF_PKG_INI_IO) {
		/* INI: Abort Done (do not care) */
		ret = unf_rcv_abort_ini_io_done(v_lport, v_pkg);
	} else {
		UNF_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_LOGIN_ATT, UNF_ERR,
			  "[err]Port(0x%x) received BLS packet type(%xh) is error",
			  lport->port_id, v_pkg->type);

		return UNF_RETURN_ERROR;
	}

	UNF_REFERNCE_VAR(lport);

	return ret;
}

static void unf_fill_rls_acc_pld(struct unf_rls_acc_s *v_rls_acc,
				 struct unf_lport_s *v_lport)
{
	struct unf_rls_acc_payload_s *rls_acc_pld = NULL;

	rls_acc_pld = &v_rls_acc->rls;
	rls_acc_pld->cmnd = UNF_ELS_CMND_ACC;

	rls_acc_pld->link_failure_count =
		v_lport->err_code_sum.link_fail_count;
	rls_acc_pld->loss_of_sync_count =
		v_lport->err_code_sum.loss_of_sync_count;
	rls_acc_pld->loss_of_signal_count =
		v_lport->err_code_sum.loss_of_signal_count;
	rls_acc_pld->primitive_seq_count = 0;
	rls_acc_pld->invalid_trans_word_count = 0;
	rls_acc_pld->invalid_crc_count =
		v_lport->err_code_sum.bad_crc_count;
}

static unsigned int unf_send_rls_acc(struct unf_lport_s *v_lport,
				     unsigned int v_did,
				     struct unf_xchg_s *v_xchg)
{
	struct unf_rls_acc_s *rls_acc = NULL;
	union unf_sfs_u *fc_entry = NULL;
	unsigned int ret = UNF_RETURN_ERROR;
	unsigned short ox_id = 0;
	unsigned short rx_id = 0;
	struct unf_frame_pkg_s pkg;

	memset(&pkg, 0, sizeof(struct unf_frame_pkg_s));
	v_xchg->cmnd_code = UNF_SET_ELS_ACC_TYPE(ELS_RLS);
	v_xchg->did = v_did;
	v_xchg->sid = v_lport->nport_id;
	v_xchg->oid = v_xchg->sid;
	v_xchg->lport = v_lport;

	v_xchg->pfn_callback = NULL;
	v_xchg->pfn_ob_callback = NULL;

	unf_fill_package(&pkg, v_xchg, v_xchg->rport);

	fc_entry = v_xchg->fcp_sfs_union.sfs_entry.fc_sfs_entry_ptr;
	if (!fc_entry) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT, UNF_WARN,
			  "[warn]Port(0x%x) entry can't be NULL with tag(0x%x)",
			  v_lport->port_id, v_xchg->hot_pool_tag);
		return UNF_RETURN_ERROR;
	}

	rls_acc = &fc_entry->rls_acc;
	unf_fill_rls_acc_pld(rls_acc, v_lport);
	ox_id = v_xchg->ox_id;
	rx_id = v_xchg->rx_id;

	ret = unf_els_cmnd_send(v_lport, &pkg, v_xchg);

	UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT, UNF_MAJOR,
		  "[info]Port(0x%x) send Rls acc  %s to RPort(0x%x) with OX_ID(0x%x) RX_ID(0x%x).",
		  v_lport->port_id, (ret != RETURN_OK) ? "failed" : "succeed",
		  v_did, ox_id, rx_id);

	UNF_REFERNCE_VAR(ox_id);
	UNF_REFERNCE_VAR(rx_id);
	return ret;
}

static unsigned int unf_rls_handler(struct unf_lport_s *v_lport,
				    unsigned int v_sid,
				    struct unf_xchg_s *v_xchg)
{
	struct unf_rport_s *rport = NULL;
	unsigned int ret = UNF_RETURN_ERROR;

	UNF_CHECK_VALID(0x3483, UNF_TRUE, v_lport, return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(0x3484, UNF_TRUE, v_xchg, return UNF_RETURN_ERROR);

	UNF_SERVICE_COLLECT(v_lport->link_service_info, UNF_SERVICE_ITEM_RLS);

	rport = unf_get_rport_by_nport_id(v_lport, v_sid);
	if (!rport) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT, UNF_WARN,
			  "[warn] Port(0x%x_0x%x) can`t find RPort by sid(0x%x) OX_ID(0x%x)",
			  v_lport->port_id, v_lport->nport_id, v_sid,
			  v_xchg->ox_id);
		unf_cm_free_xchg(v_lport, v_xchg);
		return ret;
	}
	v_xchg->rport = rport;

	ret = unf_send_rls_acc(v_lport, v_sid, v_xchg);
	if (ret != RETURN_OK) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT, UNF_WARN,
			  "[warn]Port(0x%x) send RLS ACC failed",
			  v_lport->port_id);
		unf_cm_free_xchg(v_lport, v_xchg);
	}

	return ret;
}
