// SPDX-License-Identifier: GPL-2.0
/* Huawei Hifc PCI Express Linux driver
 * Copyright(c) 2017 Huawei Technologies Co., Ltd
 *
 */
#include "unf_log.h"
#include "unf_common.h"
#include "unf_event.h"
#include "unf_lport.h"
#include "unf_rport.h"
#include "unf_exchg.h"
#include "unf_service.h"
#include "unf_portman.h"
#include "unf_npiv.h"

static void unf_lport_timeout(struct work_struct *work);

void unf_cmmark_dirty_mem(struct unf_lport_s *v_lport,
			  enum unf_lport_dirty_flag_e v_etype)
{
	UNF_CHECK_VALID(0x1801, UNF_TRUE, v_lport, return);

	v_lport->dirty_flag |= v_etype;
}

unsigned int unf_init_lport_route(struct unf_lport_s *v_lport)
{
	int ret = 0;

	UNF_CHECK_VALID(0x1802, UNF_TRUE,
			v_lport, return UNF_RETURN_ERROR);

	/* Init L_Port route work */
	INIT_DELAYED_WORK(&v_lport->route_timer_work, unf_lport_route_work);

	/* Delay route work */
	ret = queue_delayed_work(
			unf_work_queue,
			&v_lport->route_timer_work,
			(unsigned long)msecs_to_jiffies(UNF_LPORT_POLL_TIMER));
	if (unlikely(ret == UNF_FALSE)) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_EQUIP_ATT, UNF_WARN,
			  "[warn]Port(0x%x) schedule route work failed",
			  v_lport->port_id);

		return UNF_RETURN_ERROR;
	}

	return unf_lport_refinc(v_lport);
}

void unf_destroy_lport_route(struct unf_lport_s *v_lport)
{
	unsigned int ret = UNF_RETURN_ERROR;

	UNF_CHECK_VALID(0x1803, UNF_TRUE, v_lport, return);

	/* Cancel (route timer) delay work */
	UNF_DELAYED_WORK_SYNC(ret, v_lport->port_id,
			      &v_lport->route_timer_work,
			      "Route Timer work");
	if (ret == RETURN_OK) {
		/* Corresponding to ADD operation */
		unf_lport_ref_dec(v_lport);
	}

	v_lport->destroy_step = UNF_LPORT_DESTROY_STEP_2_CLOSE_ROUTE;
}

static void unf_lport_config(struct unf_lport_s *v_lport)
{
	UNF_CHECK_VALID(0x1816, UNF_TRUE, v_lport, return);

	INIT_DELAYED_WORK(&v_lport->retry_work, unf_lport_timeout);

	v_lport->max_retry_count = UNF_MAX_RETRY_COUNT;  /* 3 */
	v_lport->retries = 0;
}

void unf_init_portparms(struct unf_lport_s *v_lport)
{
	INIT_LIST_HEAD(&v_lport->list_vports_head);
	INIT_LIST_HEAD(&v_lport->list_intergrad_vports);
	INIT_LIST_HEAD(&v_lport->list_destroy_vports);
	INIT_LIST_HEAD(&v_lport->entry_lport);
	spin_lock_init(&v_lport->lport_state_lock);

	v_lport->max_frame_size = max_frame_size;
	v_lport->ed_tov = UNF_DEFAULT_EDTOV;
	v_lport->ra_tov = UNF_DEFAULT_RATOV;
	v_lport->rr_tov = UNF_DEFAULT_RRTOV;
	v_lport->fabric_node_name = 0;
	v_lport->b_priority = UNF_PRIORITY_DISABLE;
	v_lport->b_port_dir_exchange = UNF_FALSE;
	/* Delay (retry) work init */
	unf_lport_config(v_lport);

	unf_set_lport_state(v_lport, UNF_LPORT_ST_ONLINE);  /* online */

	v_lport->link_up = UNF_PORT_LINK_DOWN;
	v_lport->b_port_removing = UNF_FALSE;
	v_lport->lport_free_completion = NULL;
	v_lport->last_tx_fault_jif = 0;
	v_lport->enhanced_features = 0;
	v_lport->destroy_step = INVALID_VALUE32;
	v_lport->dirty_flag = 0;
	v_lport->b_switch_state = UNF_FALSE;
	v_lport->b_bbscn_support = UNF_FALSE;

	v_lport->en_start_work_state = UNF_START_WORK_STOP;
	v_lport->sfp_power_fault_count = 0;
	v_lport->sfp_9545_fault_count = 0;

	atomic_set(&v_lport->port_no_operater_flag, UNF_LPORT_NORMAL);
	atomic_set(&v_lport->lport_ref_cnt, 0);
	atomic_set(&v_lport->scsi_session_add_success, 0);
	atomic_set(&v_lport->scsi_session_add_failed, 0);
	atomic_set(&v_lport->scsi_session_del_success, 0);
	atomic_set(&v_lport->scsi_session_del_failed, 0);
	atomic_set(&v_lport->add_start_work_failed, 0);
	atomic_set(&v_lport->add_closing_work_failed, 0);
	atomic_set(&v_lport->alloc_scsi_id, 0);
	atomic_set(&v_lport->resume_scsi_id, 0);
	atomic_set(&v_lport->reuse_scsi_id, 0);
	atomic_set(&v_lport->device_alloc, 0);
	atomic_set(&v_lport->device_destroy, 0);
	atomic_set(&v_lport->session_loss_tmo, 0);

	atomic64_set(&v_lport->exchg_index, 1);
	atomic_inc(&v_lport->lport_ref_cnt);
	atomic_set(&v_lport->err_code_obtain_freq, 0);

	memset(&v_lport->link_service_info, 0,
	       sizeof(struct unf_link_service_collect_s));
	memset(&v_lport->err_code_sum, 0, sizeof(struct unf_err_code_s));
}

void unf_reset_lport_params(struct unf_lport_s *v_lport)
{
	struct unf_lport_s *lport = v_lport;

	UNF_CHECK_VALID(0x1804, UNF_TRUE, v_lport, return);

	lport->link_up = UNF_PORT_LINK_DOWN;
	lport->nport_id = 0;  /* Need do FLOGI again to clear N_Port_ID */
	lport->max_frame_size = max_frame_size;
	lport->ed_tov = UNF_DEFAULT_EDTOV;
	lport->ra_tov = UNF_DEFAULT_RATOV;
	lport->rr_tov = UNF_DEFAULT_RRTOV;
	lport->fabric_node_name = 0;
}

static enum unf_lport_login_state_e unf_lport_stat_online(
					enum unf_lport_login_state_e old_state,
					enum unf_lport_event_e event)
{
	enum unf_lport_login_state_e next_state = UNF_LPORT_ST_ONLINE;

	switch (event) {
	case UNF_EVENT_LPORT_LINK_UP:
		/* EVENT_LINK_UP --->>> ST_LINK_UP */
		next_state = UNF_LPORT_ST_LINK_UP;
		break;

	case UNF_EVENT_LPORT_NORMAL_ENTER:
		/* EVENT_NORMAL_ENTER --->>> ST_INITIAL */
		next_state = UNF_LPORT_ST_INITIAL;
		break;

	default:
		next_state = old_state;
		break;
	}

	return next_state;
}

static enum unf_lport_login_state_e unf_lport_stat_initial(
					enum unf_lport_login_state_e old_state,
					enum unf_lport_event_e event)
{
	enum unf_lport_login_state_e next_state = UNF_LPORT_ST_ONLINE;

	switch (event) {
	case UNF_EVENT_LPORT_LINK_UP:
		/* EVENT_LINK_UP --->>> ST_LINK_UP */
		next_state = UNF_LPORT_ST_LINK_UP;
		break;

	default:
		next_state = old_state;
		break;
	}

	return next_state;
}

static enum unf_lport_login_state_e unf_lport_stat_linkup(
					enum unf_lport_login_state_e old_state,
					enum unf_lport_event_e event)
{
	enum unf_lport_login_state_e next_state = UNF_LPORT_ST_ONLINE;

	switch (event) {
	case UNF_EVENT_LPORT_NORMAL_ENTER:
		/* EVENT_NORMAL_ENTER --->>> FLOGI_WAIT */
		next_state = UNF_LPORT_ST_FLOGI_WAIT;
		break;

	case UNF_EVENT_LPORT_READY:
		/* EVENT_READY --->>> ST_READY */
		next_state = UNF_LPORT_ST_READY;
		break;

	case UNF_EVENT_LPORT_LINK_DOWN:
		/* EVENT_LINK_DOWN --->>> ST_INITIAL */
		next_state = UNF_LPORT_ST_INITIAL;
		break;

	default:
		next_state = old_state;
		break;
	}

	return next_state;
}

static enum unf_lport_login_state_e unf_lport_stat_flogi_wait(
					enum unf_lport_login_state_e old_state,
					enum unf_lport_event_e event)
{
	enum unf_lport_login_state_e next_state = UNF_LPORT_ST_ONLINE;

	switch (event) {
	case UNF_EVENT_LPORT_REMOTE_ACC:
		/* EVENT_REMOTE_ACC --->>> ST_PLOGI_WAIT */
		next_state = UNF_LPORT_ST_PLOGI_WAIT;
		break;

	case UNF_EVENT_LPORT_READY:
		/* EVENT_READY --->>> ST_READY */
		next_state = UNF_LPORT_ST_READY;
		break;

	case UNF_EVENT_LPORT_REMOTE_TIMEOUT:
		/* EVENT_REMOTE_TIMEOUT --->>> ST_LOGO */
		next_state = UNF_LPORT_ST_LOGO;
		break;

	case UNF_EVENT_LPORT_LINK_DOWN:
		/* EVENT_LINK_DOWN --->>> ST_INITIAL */
		next_state = UNF_LPORT_ST_INITIAL;
		break;

	default:
		next_state = old_state;
		break;
	}

	return next_state;
}

static enum unf_lport_login_state_e unf_lport_stat_plogi_wait(
					enum unf_lport_login_state_e old_state,
					enum unf_lport_event_e event)
{
	enum unf_lport_login_state_e next_state = UNF_LPORT_ST_ONLINE;

	switch (event) {
	case UNF_EVENT_LPORT_REMOTE_ACC:
		/* EVENT_REMOTE_ACC --->>> ST_RFT_ID_WAIT */
		next_state = UNF_LPORT_ST_RFT_ID_WAIT;
		break;

	case UNF_EVENT_LPORT_REMOTE_TIMEOUT:
		/* EVENT_TIMEOUT --->>> ST_LOGO */
		next_state = UNF_LPORT_ST_LOGO;
		break;

	case UNF_EVENT_LPORT_LINK_DOWN:
		/* EVENT_LINK_DOWN --->>> ST_INITIAL */
		next_state = UNF_LPORT_ST_INITIAL;
		break;

	default:
		next_state = old_state;
		break;
	}

	return next_state;
}

static enum unf_lport_login_state_e unf_lport_stat_rftid_wait(
					enum unf_lport_login_state_e old_state,
					enum unf_lport_event_e event)
{
	enum unf_lport_login_state_e next_state = UNF_LPORT_ST_ONLINE;

	switch (event) {
	case UNF_EVENT_LPORT_REMOTE_ACC:
		/* EVENT_REMOTE_ACC --->>> ST_RFF_ID_WAIT */
		next_state = UNF_LPORT_ST_RFF_ID_WAIT;
		break;

	case UNF_EVENT_LPORT_REMOTE_TIMEOUT:
		/* EVENT_TIMEOUT --->>> ST_LOGO */
		next_state = UNF_LPORT_ST_LOGO;
		break;

	case UNF_EVENT_LPORT_LINK_DOWN:
		/* EVENT_LINK_DOWN --->>> ST_INITIAL */
		next_state = UNF_LPORT_ST_INITIAL;
		break;

	default:
		next_state = old_state;
		break;
	}

	return next_state;
}

static enum unf_lport_login_state_e unf_lport_stat_rffid_wait(
					enum unf_lport_login_state_e old_state,
					enum unf_lport_event_e event)
{
	enum unf_lport_login_state_e next_state = UNF_LPORT_ST_ONLINE;

	switch (event) {
	case UNF_EVENT_LPORT_REMOTE_ACC:
		/* EVENT_REMOTE_ACC --->>> ST_SCR_WAIT */
		next_state = UNF_LPORT_ST_SCR_WAIT;
		break;

	case UNF_EVENT_LPORT_REMOTE_TIMEOUT:
		/* EVENT_TIMEOUT  --->>> ST_LOGO */
		next_state = UNF_LPORT_ST_LOGO;
		break;

	case UNF_EVENT_LPORT_LINK_DOWN:
		/* EVENT_LINK_DOWN --->>> ST_INITIAL */
		next_state = UNF_LPORT_ST_INITIAL;
		break;

	default:
		next_state = old_state;
		break;
	}

	return next_state;
}

static enum unf_lport_login_state_e unf_lport_state_scr_wait(
					enum unf_lport_login_state_e old_state,
					enum unf_lport_event_e event)
{
	enum unf_lport_login_state_e next_state = UNF_LPORT_ST_ONLINE;

	switch (event) {
	case UNF_EVENT_LPORT_REMOTE_ACC:
		/* EVENT_REMOTE_ACC --->>> ST_READY */
		next_state = UNF_LPORT_ST_READY;
		break;

	case UNF_EVENT_LPORT_REMOTE_TIMEOUT:
		/* EVENT_TIMEOUT --->>> ST_LOGO */
		next_state = UNF_LPORT_ST_LOGO;
		break;

	case UNF_EVENT_LPORT_LINK_DOWN:
		/* EVENT_LINK_DOWN --->>> ST_INITIAL */
		next_state = UNF_LPORT_ST_INITIAL;
		break;

	default:
		next_state = old_state;
		break;
	}

	return next_state;
}

static enum unf_lport_login_state_e unf_lport_state_logo(
					enum unf_lport_login_state_e old_state,
					enum unf_lport_event_e event)
{
	enum unf_lport_login_state_e next_state = UNF_LPORT_ST_ONLINE;

	switch (event) {
	case UNF_EVENT_LPORT_NORMAL_ENTER:
		/* EVENT_NORMAL_ENTER --->>> ST_OFFLINE */
		next_state = UNF_LPORT_ST_OFFLINE;
		break;

	case UNF_EVENT_LPORT_LINK_DOWN:
		/* EVENT_LINK_DOWN --->>> ST_INITIAL */
		next_state = UNF_LPORT_ST_INITIAL;
		break;

	default:
		next_state = old_state;
		break;
	}

	return next_state;
}

static enum unf_lport_login_state_e unf_lport_state_offline(
					enum unf_lport_login_state_e old_state,
					enum unf_lport_event_e event)
{
	enum unf_lport_login_state_e next_state = UNF_LPORT_ST_ONLINE;

	switch (event) {
	case UNF_EVENT_LPORT_ONLINE:
		/* EVENT_ONLINE --->>> ST_ONLINE */
		next_state = UNF_LPORT_ST_ONLINE;
		break;

	case UNF_EVENT_LPORT_RESET:
		/* EVENT_RESET --->>> ST_RESET */
		next_state = UNF_LPORT_ST_RESET;
		break;

	case UNF_EVENT_LPORT_LINK_DOWN:
		/* EVENT_LINK_DOWN --->>> ST_INITIAL */
		next_state = UNF_LPORT_ST_INITIAL;
		break;

	default:
		next_state = old_state;
		break;
	}

	return next_state;
}

static enum unf_lport_login_state_e unf_lport_state_reset(
					enum unf_lport_login_state_e old_state,
					enum unf_lport_event_e event)
{
	enum unf_lport_login_state_e next_state = UNF_LPORT_ST_ONLINE;

	switch (event) {
	case UNF_EVENT_LPORT_NORMAL_ENTER:
		/* EVENT_NORMAL_ENTER --->>> ST_INITIAL */
		next_state = UNF_LPORT_ST_INITIAL;
		break;

	default:
		next_state = old_state;
		break;
	}

	return next_state;
}

static enum unf_lport_login_state_e unf_lport_state_ready(
					enum unf_lport_login_state_e old_state,
					enum unf_lport_event_e event)
{
	enum unf_lport_login_state_e next_state = UNF_LPORT_ST_ONLINE;

	switch (event) {
	case UNF_EVENT_LPORT_LINK_DOWN:
		/* EVENT_LINK_DOWN --->>> ST_INITIAL */
		next_state = UNF_LPORT_ST_INITIAL;
		break;

	case UNF_EVENT_LPORT_RESET:
		/* EVENT_RESET --->>> ST_RESET */
		next_state = UNF_LPORT_ST_RESET;
		break;

	case UNF_EVENT_LPORT_OFFLINE:
		/* EVENT_OFFLINE --->>> ST_LOGO */
		next_state = UNF_LPORT_ST_LOGO;
		break;

	default:
		next_state = old_state;
		break;
	}

	return next_state;
}

void unf_lport_stat_ma(struct unf_lport_s *v_lport,
		       enum unf_lport_event_e event)
{
	enum unf_lport_login_state_e old_state = UNF_LPORT_ST_ONLINE;
	enum unf_lport_login_state_e next_state = UNF_LPORT_ST_ONLINE;

	UNF_CHECK_VALID(0x1805, UNF_TRUE, v_lport, return);

	old_state = v_lport->en_states;
	switch (v_lport->en_states) {
	case UNF_LPORT_ST_ONLINE:
		next_state = unf_lport_stat_online(old_state, event);
		break;

	case UNF_LPORT_ST_INITIAL:
		next_state = unf_lport_stat_initial(old_state, event);
		break;

	case UNF_LPORT_ST_LINK_UP:
		next_state = unf_lport_stat_linkup(old_state, event);
		break;

	case UNF_LPORT_ST_FLOGI_WAIT:
		next_state = unf_lport_stat_flogi_wait(old_state, event);
		break;

	case UNF_LPORT_ST_PLOGI_WAIT:
		next_state = unf_lport_stat_plogi_wait(old_state, event);
		break;

	case UNF_LPORT_ST_RFT_ID_WAIT:
		next_state = unf_lport_stat_rftid_wait(old_state, event);
		break;

	case UNF_LPORT_ST_RFF_ID_WAIT:
		next_state = unf_lport_stat_rffid_wait(old_state, event);
		break;

	case UNF_LPORT_ST_SCR_WAIT:
		next_state = unf_lport_state_scr_wait(old_state, event);
		break;

	case UNF_LPORT_ST_LOGO:
		next_state = unf_lport_state_logo(old_state, event);
		break;

	case UNF_LPORT_ST_OFFLINE:
		next_state = unf_lport_state_offline(old_state, event);
		break;

	case UNF_LPORT_ST_RESET:
		next_state = unf_lport_state_reset(old_state, event);
		break;

	case UNF_LPORT_ST_READY:
		next_state = unf_lport_state_ready(old_state, event);
		break;

	default:
		next_state = old_state;
		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT, UNF_MAJOR,
			  "[info]Port(0x%x) hold state(0x%x)",
			  v_lport->port_id, v_lport->en_states);
		break;
	}

	UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT, UNF_INFO,
		  "[info]Port(0x%x) with old state(0x%x) event(0x%x) next state(0x%x)",
		  v_lport->port_id, old_state, event, next_state);

	unf_set_lport_state(v_lport, next_state);
}

unsigned int unf_init_lport_mgr_temp(struct unf_lport_s *v_lport)
{
	UNF_CHECK_VALID(0x1806, UNF_TRUE, v_lport, return UNF_RETURN_ERROR);
	v_lport->lport_mgr_temp.pfn_unf_vport_get_free_and_init = NULL;
	v_lport->lport_mgr_temp.pfn_unf_lookup_vport_by_vp_index =
						unf_lookup_vport_by_vp_index;
	v_lport->lport_mgr_temp.pfn_unf_lookup_vport_by_port_id =
						unf_lookup_vport_by_port_id;
	v_lport->lport_mgr_temp.pfn_unf_lookup_vport_by_did =
						unf_lookup_vport_by_did;
	v_lport->lport_mgr_temp.pfn_unf_lookup_vport_by_wwpn =
						unf_lookup_vport_by_wwpn;
	v_lport->lport_mgr_temp.pfn_unf_vport_remove = unf_vport_remove;
	return RETURN_OK;
}

void unf_release_lport_mgr_temp(struct unf_lport_s *v_lport)
{
	UNF_CHECK_VALID(0x1807, UNF_TRUE, v_lport, return);

	memset(&v_lport->lport_mgr_temp, 0,
	       sizeof(struct unf_cm_lport_template_s));
	v_lport->destroy_step = UNF_LPORT_DESTROY_STEP_9_DESTROY_LPORT_MG_TMP;
}

unsigned int unf_lport_retry_flogi(struct unf_lport_s *v_lport)
{
	struct unf_rport_s *rport = NULL;
	unsigned int ret = UNF_RETURN_ERROR;
	unsigned long flag = 0;

	UNF_CHECK_VALID(0x1808, UNF_TRUE,
			v_lport, return UNF_RETURN_ERROR);

	/* Get (new) R_Port */
	rport = unf_get_rport_by_nport_id(v_lport, UNF_FC_FID_FLOGI);
	rport = unf_get_safe_rport(v_lport, rport,
				   UNF_RPORT_REUSE_ONLY, UNF_FC_FID_FLOGI);
	if (unlikely(!rport)) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT, UNF_WARN,
			  "[warn]Port(0x%x) allocate RPort failed",
			  v_lport->port_id);

		return UNF_RETURN_ERROR;
	}

	/* Check L_Port state */
	spin_lock_irqsave(&v_lport->lport_state_lock, flag);
	if (v_lport->en_states != UNF_LPORT_ST_FLOGI_WAIT) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT, UNF_WARN,
			  "[warn]Port(0x%x) no need to retry FLOGI with state(0x%x)",
			  v_lport->port_id, v_lport->en_states);

		spin_unlock_irqrestore(&v_lport->lport_state_lock, flag);
		return RETURN_OK;
	}
	spin_unlock_irqrestore(&v_lport->lport_state_lock, flag);

	spin_lock_irqsave(&rport->rport_state_lock, flag);
	rport->nport_id = UNF_FC_FID_FLOGI;
	spin_unlock_irqrestore(&rport->rport_state_lock, flag);

	/* Send FLOGI or FDISC */
	if (v_lport != v_lport->root_lport) {
		ret = unf_send_fdisc(v_lport, rport);
		if (ret != RETURN_OK) {
			UNF_TRACE(UNF_EVTLOG_DRIVER_WARN,
				  UNF_LOG_LOGIN_ATT, UNF_WARN,
				  "[warn]LOGIN: Port(0x%x) send FDISC failed",
				  v_lport->port_id);

			/* Do L_Port recovery */
			unf_lport_error_recovery(v_lport);
		}
	} else {
		ret = unf_send_flogi(v_lport, rport);
		if (ret != RETURN_OK) {
			UNF_TRACE(
				UNF_EVTLOG_DRIVER_WARN,
				UNF_LOG_LOGIN_ATT, UNF_WARN,
				"[warn]LOGIN: Port(0x%x) send FLOGI failed\n",
				v_lport->port_id);

			/* Do L_Port recovery */
			unf_lport_error_recovery(v_lport);
		}
	}

	return ret;
}

unsigned int unf_lport_name_server_register(
					struct unf_lport_s *v_lport,
					enum unf_lport_login_state_e states)
{
	struct unf_rport_s *rport = NULL;
	unsigned long flag = 0;
	unsigned int ret = UNF_RETURN_ERROR;

	UNF_CHECK_VALID(0x1809, UNF_TRUE,
			v_lport, return UNF_RETURN_ERROR);

	/* Get (safe) R_Port 0xfffffc */
	rport = unf_get_rport_by_nport_id(v_lport, UNF_FC_FID_DIR_SERV);
	rport = unf_get_safe_rport(v_lport, rport, UNF_RPORT_REUSE_ONLY,
				   UNF_FC_FID_DIR_SERV);
	if (!rport) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT, UNF_WARN,
			  "[warn]Port(0x%x) allocate RPort failed",
			  v_lport->port_id);

		return UNF_RETURN_ERROR;
	}

	/* Update R_Port & L_Port state */
	spin_lock_irqsave(&rport->rport_state_lock, flag);
	rport->nport_id = UNF_FC_FID_DIR_SERV;  /* 0xfffffc */
	spin_unlock_irqrestore(&rport->rport_state_lock, flag);

	spin_lock_irqsave(&v_lport->lport_state_lock, flag);
	unf_lport_stat_ma(v_lport, UNF_EVENT_LPORT_NORMAL_ENTER);
	spin_unlock_irqrestore(&v_lport->lport_state_lock, flag);

	switch (states) {
	/* RFT_ID */
	case UNF_LPORT_ST_RFT_ID_WAIT:
		ret = unf_send_rft_id(v_lport, rport);
		break;

	/* RFF_ID */
	case UNF_LPORT_ST_RFF_ID_WAIT:
		ret = unf_send_rff_id(v_lport, rport);
		break;

	/* SCR */
	case UNF_LPORT_ST_SCR_WAIT:
		ret = unf_send_scr(v_lport, NULL);
		break;

	/* PLOGI */
	case UNF_LPORT_ST_PLOGI_WAIT:
	default:
		spin_lock_irqsave(&rport->rport_state_lock, flag);
		unf_rport_state_ma(rport, UNF_EVENT_RPORT_ENTER_PLOGI);
		spin_unlock_irqrestore(&rport->rport_state_lock, flag);

		ret = unf_send_plogi(v_lport, rport);
		break;
	}

	if (ret != RETURN_OK) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT, UNF_WARN,
			  "[warn]LOGIN: Port(0x%x) register fabric(0xfffffc) failed",
			  v_lport->nport_id);

		/* Do L_Port recovery */
		unf_lport_error_recovery(v_lport);
	}

	return ret;
}

unsigned int unf_lport_enter_sns_logo(struct unf_lport_s *v_lport,
				      struct unf_rport_s *v_rport)
{
	struct unf_rport_s *rport = NULL;
	unsigned long flag = 0;
	unsigned int ret = UNF_RETURN_ERROR;

	UNF_CHECK_VALID(0x1810, UNF_TRUE,
			v_lport, return UNF_RETURN_ERROR);

	if (!v_rport) {
		rport = unf_get_rport_by_nport_id(v_lport,
						  UNF_FC_FID_DIR_SERV);
	} else {
		rport = v_rport;
	}

	if (!rport) {
		spin_lock_irqsave(&v_lport->lport_state_lock, flag);
		unf_lport_stat_ma(v_lport, UNF_EVENT_LPORT_NORMAL_ENTER);
		spin_unlock_irqrestore(&v_lport->lport_state_lock, flag);

		return RETURN_OK;
	}

	/* Update L_Port & R_Port state */
	spin_lock_irqsave(&v_lport->lport_state_lock, flag);
	unf_lport_stat_ma(v_lport, UNF_EVENT_LPORT_NORMAL_ENTER);
	spin_unlock_irqrestore(&v_lport->lport_state_lock, flag);

	spin_lock_irqsave(&rport->rport_state_lock, flag);
	unf_rport_state_ma(rport, UNF_EVENT_RPORT_LOGO);
	spin_unlock_irqrestore(&rport->rport_state_lock, flag);

	/* Do R_Port LOGO state */
	unf_rport_enter_logo(v_lport, rport);

	return ret;
}

void unf_lport_enter_sns_plogi(struct unf_lport_s *v_lport)
{
	/* Fabric or Public Loop Mode: Login with Name server */
	struct unf_lport_s *lport = v_lport;
	struct unf_rport_s *rport = NULL;
	unsigned long flag = 0;
	unsigned int ret = UNF_RETURN_ERROR;

	UNF_CHECK_VALID(0x1811, UNF_TRUE, v_lport, return);

	/* Get (safe) R_Port 0xfffffc */
	rport = unf_get_rport_by_nport_id(lport, UNF_FC_FID_DIR_SERV);
	if (rport) {
		/* for port swap: Delete old R_Port if necessary */
		if (rport->local_nport_id != v_lport->nport_id) {
			unf_rport_immediate_linkdown(v_lport, rport);
			rport = NULL;
		}
	}

	rport = unf_get_safe_rport(v_lport, rport,
				   UNF_RPORT_REUSE_ONLY, UNF_FC_FID_DIR_SERV);
	if (!rport) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT, UNF_WARN,
			  "[warn]Port(0x%x) allocate RPort failed",
			  v_lport->port_id);

		unf_lport_error_recovery(lport);
		return;
	}

	spin_lock_irqsave(&rport->rport_state_lock, flag);
	rport->nport_id = UNF_FC_FID_DIR_SERV;  /* 0xfffffc */
	spin_unlock_irqrestore(&rport->rport_state_lock, flag);

	/* Send PLOGI to Fabric(0xfffffc) */
	ret = unf_send_plogi(lport, rport);
	if (ret != RETURN_OK) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT, UNF_WARN,
			  "[warn]LOGIN: Port(0x%x) send PLOGI to name server failed",
			  v_lport->port_id);

		unf_lport_error_recovery(lport);
	}
}

int unf_get_port_params(void *v_argin, void *v_argout)
{
	struct unf_lport_s *lport = (struct unf_lport_s *)v_argin;
	struct unf_low_level_port_mgr_op_s *port_mg = NULL;
	struct unf_port_params_s port_params = { 0 };
	int ret = RETURN_OK;

	UNF_REFERNCE_VAR(v_argout);
	UNF_CHECK_VALID(0x1812, UNF_TRUE,
			v_argin, return UNF_RETURN_ERROR);

	port_mg = &lport->low_level_func.port_mgr_op;
	if (!port_mg->pfn_ll_port_config_get) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_EQUIP_ATT, UNF_WARN,
			  "[warn]Port(0x%x) low level port_config_get function is NULL",
			  lport->port_id);

		return UNF_RETURN_ERROR;
	}

	UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_EQUIP_ATT, UNF_INFO,
		  "[warn]Port(0x%x) get parameters with default:R_A_TOV(%d) E_D_TOV(%d)",
		  lport->port_id, UNF_DEFAULT_FABRIC_RATOV, UNF_DEFAULT_EDTOV);

	port_params.ra_tov = UNF_DEFAULT_FABRIC_RATOV;
	port_params.ed_tov = UNF_DEFAULT_EDTOV;

	/* Update parameters with Fabric mode */
	if ((lport->en_act_topo == UNF_ACT_TOP_PUBLIC_LOOP) ||
	    (lport->en_act_topo == UNF_ACT_TOP_P2P_FABRIC)) {
		lport->ra_tov = port_params.ra_tov;
		lport->ed_tov = port_params.ed_tov;
	}

	return ret;
}

unsigned int unf_lport_enter_flogi(struct unf_lport_s *v_lport)
{
	struct unf_rport_s *rport = NULL;
	struct unf_cm_event_report *event = NULL;
	unsigned long flag = 0;
	unsigned int ret = UNF_RETURN_ERROR;
	unsigned int nport_id = 0;

	UNF_CHECK_VALID(0x1813, UNF_TRUE,
			v_lport, return UNF_RETURN_ERROR);

	/* Get (safe) R_Port */
	nport_id = UNF_FC_FID_FLOGI;  /* 0xfffffe */
	rport = unf_get_rport_by_nport_id(v_lport, UNF_FC_FID_FLOGI);

	rport = unf_get_safe_rport(v_lport, rport,
				   UNF_RPORT_REUSE_ONLY, nport_id);
	if (!rport) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT, UNF_WARN,
			  "[warn]Port(0x%x) allocate RPort failed",
			  v_lport->port_id);

		return UNF_RETURN_ERROR;
	}

	/* Updtae L_Port state */
	spin_lock_irqsave(&v_lport->lport_state_lock, flag);
	/* LPort: LINK UP --> FLOGI WAIT */
	unf_lport_stat_ma(v_lport, UNF_EVENT_LPORT_NORMAL_ENTER);
	spin_unlock_irqrestore(&v_lport->lport_state_lock, flag);

	/* Update R_Port N_Port_ID */
	spin_lock_irqsave(&rport->rport_state_lock, flag);
	rport->nport_id = UNF_FC_FID_FLOGI;  /* 0xfffffe */
	spin_unlock_irqrestore(&rport->rport_state_lock, flag);

	event = unf_get_one_event_node(v_lport);
	if (event) {
		event->lport = v_lport;
		event->event_asy_flag = UNF_EVENT_ASYN;
		/* NULL for timer */
		event->pfn_unf_event_task = unf_get_port_params;
		event->para_in = (void *)v_lport;
		unf_post_one_event_node(v_lport, event);
	}

	if (v_lport != v_lport->root_lport) {
		/* for NPIV */
		ret = unf_send_fdisc(v_lport, rport);
		if (ret != RETURN_OK)
			/* Do L_Port recovery */
			unf_lport_error_recovery(v_lport);
	} else {
		/* for Physical Port */
		ret = unf_send_flogi(v_lport, rport);
		if (ret != RETURN_OK)
			/* Do L_Port recovery */
			unf_lport_error_recovery(v_lport);
	}

	return ret;
}

void unf_set_lport_state(struct unf_lport_s *v_lport,
			 enum unf_lport_login_state_e states)
{
	UNF_CHECK_VALID(0x1814, UNF_TRUE, v_lport, return);
	if (states != v_lport->en_states) {
		/* Reset L_Port retry count */
		v_lport->retries = 0;
	}

	v_lport->en_states = states;
}

static void unf_lport_timeout(struct work_struct *work)
{
	struct unf_lport_s *lport = NULL;
	enum unf_lport_login_state_e state = UNF_LPORT_ST_READY;
	unsigned long flag = 0;

	UNF_CHECK_VALID(0x1815, UNF_TRUE, work, return);
	lport = container_of(work, struct unf_lport_s, retry_work.work);

	spin_lock_irqsave(&lport->lport_state_lock, flag);
	state = lport->en_states;
	UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT, UNF_WARN,
		  "[warn]Port(0x%x) is timeout with state(0x%x)",
		  lport->port_id, state);
	spin_unlock_irqrestore(&lport->lport_state_lock, flag);

	switch (state) {
	/* FLOGI retry */
	case UNF_LPORT_ST_FLOGI_WAIT:
		(void)unf_lport_retry_flogi(lport);
		break;

	case UNF_LPORT_ST_PLOGI_WAIT:
	case UNF_LPORT_ST_RFT_ID_WAIT:
	case UNF_LPORT_ST_RFF_ID_WAIT:
	case UNF_LPORT_ST_SCR_WAIT:
		(void)unf_lport_name_server_register(lport, state);
		break;

	/* Send LOGO External */
	case UNF_LPORT_ST_LOGO:
			break;

	/* Do nothing */
	case UNF_LPORT_ST_OFFLINE:
	case UNF_LPORT_ST_READY:
	case UNF_LPORT_ST_RESET:
	case UNF_LPORT_ST_ONLINE:
	case UNF_LPORT_ST_INITIAL:
	case UNF_LPORT_ST_LINK_UP:

		lport->retries = 0;
		break;
	default:
		break;
	}

	unf_lport_ref_dec_to_destroy(lport);
}

void unf_lport_error_recovery(struct unf_lport_s *v_lport)
{
	unsigned long delay = 0;
	unsigned long flag = 0;
	int ret = 0;

	UNF_CHECK_VALID(0x1817, UNF_TRUE, v_lport, return);

	if (unlikely(unf_lport_refinc(v_lport) != RETURN_OK)) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT, UNF_WARN,
			  "[warn]Port(0x%x) is removing and no need process",
			  v_lport->port_id);
		return;
	}

	spin_lock_irqsave(&v_lport->lport_state_lock, flag);

	/* Port State: removing */
	if (v_lport->b_port_removing == UNF_TRUE) {
		spin_unlock_irqrestore(&v_lport->lport_state_lock, flag);

		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT, UNF_WARN,
			  "[warn]Port(0x%x) is removing and no need process",
			  v_lport->port_id);

		unf_lport_ref_dec_to_destroy(v_lport);
		return;
	}

	/* Port State: offline */
	if (v_lport->en_states == UNF_LPORT_ST_OFFLINE) {
		spin_unlock_irqrestore(&v_lport->lport_state_lock, flag);

		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT, UNF_WARN,
			  "[warn]Port(0x%x) is offline and no need process",
			  v_lport->port_id);

		unf_lport_ref_dec_to_destroy(v_lport);
		return;
	}

	/* Queue work state check */
	if (delayed_work_pending(&v_lport->retry_work)) {
		spin_unlock_irqrestore(&v_lport->lport_state_lock, flag);

		unf_lport_ref_dec_to_destroy(v_lport);
		return;
	}

	/* Do retry operation */
	if (v_lport->retries < v_lport->max_retry_count) {
		v_lport->retries++;

		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT, UNF_MAJOR,
			  "[info]Port(0x%x_0x%x) enter recovery and retry %u times",
			  v_lport->port_id, v_lport->nport_id,
			  v_lport->retries);

		delay = (unsigned long)v_lport->ed_tov;
		ret = queue_delayed_work(unf_work_queue,
					 &v_lport->retry_work,
					 (unsigned long)msecs_to_jiffies(
							(unsigned int)delay));
		if (ret) {
			atomic_inc(&v_lport->lport_ref_cnt);

			UNF_TRACE(UNF_EVTLOG_DRIVER_INFO,
				  UNF_LOG_LOGIN_ATT, UNF_MAJOR,
				  "[info]Port(0x%x) queue work success and reference count is %d",
				  v_lport->port_id,
				  atomic_read(&v_lport->lport_ref_cnt));
		}
		spin_unlock_irqrestore(&v_lport->lport_state_lock, flag);
	} else {
		unf_lport_stat_ma(v_lport, UNF_EVENT_LPORT_REMOTE_TIMEOUT);
		spin_unlock_irqrestore(&v_lport->lport_state_lock, flag);

		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT, UNF_WARN,
			  "[warn]Port(0x%x) register operation timeout and do LOGO",
			  v_lport->port_id);

		/* Do L_Port LOGO */
		(void)unf_lport_enter_sns_logo(v_lport, NULL);
	}

	unf_lport_ref_dec_to_destroy(v_lport);
}

struct unf_lport_s *unf_cm_lookup_vport_by_vp_index(struct unf_lport_s *v_lport,
						    unsigned short v_vp_index)
{
	UNF_CHECK_VALID(0x1819, UNF_TRUE, v_lport, return NULL);

	if (v_vp_index == 0)
		return v_lport;

	if (!v_lport->lport_mgr_temp.pfn_unf_lookup_vport_by_vp_index) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_REG_ATT, UNF_ERR,
			  "[err]Port(0x%x) function do look up vport by index is NULL",
			  v_lport->port_id);

		return NULL;
	}

	return v_lport->lport_mgr_temp.pfn_unf_lookup_vport_by_vp_index(
							v_lport, v_vp_index);
}

struct unf_lport_s *unf_cm_lookup_vport_by_did(struct unf_lport_s *v_lport,
					       unsigned int v_did)
{
	UNF_CHECK_VALID(0x1821, UNF_TRUE, v_lport, return NULL);

	if (!v_lport->lport_mgr_temp.pfn_unf_lookup_vport_by_did) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_REG_ATT, UNF_ERR,
			  "[err]Port(0x%x) function do look up vport by D_ID is NULL",
			  v_lport->port_id);

		return NULL;
	}

	return v_lport->lport_mgr_temp.pfn_unf_lookup_vport_by_did(v_lport,
								   v_did);
}

struct unf_lport_s *unf_cm_lookup_vport_by_wwpn(struct unf_lport_s *v_lport,
						unsigned long long v_wwpn)
{
	UNF_CHECK_VALID(0x1822, UNF_TRUE, v_lport, return NULL);

	if (!v_lport->lport_mgr_temp.pfn_unf_lookup_vport_by_wwpn) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_REG_ATT, UNF_ERR,
			  "[err]Port(0x%x) function do look up vport by WWPN is NULL",
			  v_lport->port_id);

		return NULL;
	}

	return v_lport->lport_mgr_temp.pfn_unf_lookup_vport_by_wwpn(v_lport,
								    v_wwpn);
}

void unf_cm_vport_remove(struct unf_lport_s *v_vport)
{
	struct unf_lport_s *lport = NULL;

	UNF_CHECK_VALID(0x1823, UNF_TRUE, v_vport, return);
	lport = v_vport->root_lport;
	UNF_CHECK_VALID(0x1824, UNF_TRUE, lport, return);

	if (!lport->lport_mgr_temp.pfn_unf_vport_remove) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_REG_ATT, UNF_ERR,
			  "[err]Port(0x%x) function do vport remove is NULL",
			  lport->port_id);
		return;
	}

	lport->lport_mgr_temp.pfn_unf_vport_remove(v_vport);
}
