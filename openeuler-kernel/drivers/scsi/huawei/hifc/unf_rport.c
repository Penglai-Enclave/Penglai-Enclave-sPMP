// SPDX-License-Identifier: GPL-2.0
/* Huawei Hifc PCI Express Linux driver
 * Copyright(c) 2017 Huawei Technologies Co., Ltd
 *
 */
#include "unf_log.h"
#include "unf_common.h"
#include "unf_lport.h"
#include "unf_rport.h"
#include "unf_exchg.h"
#include "unf_service.h"
#include <scsi/scsi_transport_fc.h>
#include "unf_portman.h"

/* rport state: */
/* ready --->>> link_down --->>> cloing --->>> timeout --->>> delete */

struct unf_rport_feature_pool_s *port_fea_pool;

/*
 * Function Name       : unf_sesion_loss_timeout
 * Function Description: session loss timeout
 * Input Parameters    : struct work_struct *v_work
 * Output Parameters   : N/A
 * Return Type         : unsigned int
 */
void unf_sesion_loss_timeout(struct work_struct *v_work)
{
	struct unf_wwpn_rport_info_s *wwpn_rport_info = NULL;

	UNF_CHECK_VALID(0x3040, UNF_TRUE, v_work, return);

	wwpn_rport_info = container_of(v_work, struct unf_wwpn_rport_info_s,
				       loss_tmo_work.work);
	if (unlikely(!wwpn_rport_info)) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_LOGIN_ATT, UNF_ERR,
			  "[err]wwpn_rport_info is NULL");
		return;
	}

	atomic_set(&wwpn_rport_info->en_scsi_state, UNF_SCSI_ST_DEAD);

	UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT, UNF_KEVENT,
		  "[info]Port(0x%x) wwpn(0x%llx) set target(0x%x) scsi state to dead",
		  ((struct unf_lport_s *)(wwpn_rport_info->lport))->port_id,
		  wwpn_rport_info->wwpn,
		  wwpn_rport_info->target_id);
}

/*
 * Function Name       : unf_alloc_scsi_id
 * Function Description: alloc r_port scsi id
 * Input Parameters    : struct unf_lport_s *v_lport
 *                     : struct unf_rport_s *v_rport
 * Output Parameters   : N/A
 * Return Type         : unsigned int
 */
static unsigned int unf_alloc_scsi_id(struct unf_lport_s *v_lport,
				      struct unf_rport_s *v_rport)
{
	struct unf_rport_scsi_id_image_s *rport_scsi_table = NULL;
	struct unf_wwpn_rport_info_s *wwn_rport_info = NULL;
	unsigned long flags = 0;
	unsigned int index = 0;
	unsigned int ret = UNF_RETURN_ERROR;

	rport_scsi_table = &v_lport->rport_scsi_table;
	UNF_REFERNCE_VAR(ret);

	spin_lock_irqsave(&rport_scsi_table->scsi_image_table_lock, flags);

	/* 1. At first, existence check */
	for (index = 0; index < rport_scsi_table->max_scsi_id; index++) {
		wwn_rport_info =
			&rport_scsi_table->wwn_rport_info_table[index];
		if (v_rport->port_name == wwn_rport_info->wwpn) {
			spin_unlock_irqrestore(
				&rport_scsi_table->scsi_image_table_lock,
				flags);
			UNF_DELAYED_WORK_SYNC(ret, (v_lport->port_id),
					      (&wwn_rport_info->loss_tmo_work),
					      "loss tmo Timer work");

			/* Plug case: reuse again */
			spin_lock_irqsave(
				&rport_scsi_table->scsi_image_table_lock,
				flags);
			wwn_rport_info->rport = v_rport;
			wwn_rport_info->last_en_scis_state =
				atomic_read(&wwn_rport_info->en_scsi_state);
			atomic_set(&wwn_rport_info->en_scsi_state,
				   UNF_SCSI_ST_ONLINE);
			spin_unlock_irqrestore(
				&rport_scsi_table->scsi_image_table_lock,
				flags);

			UNF_TRACE(UNF_EVTLOG_DRIVER_INFO,
				  UNF_LOG_LOGIN_ATT, UNF_MAJOR,
				  "[info]port(0x%x) find the same scsi_id(0x%x) by wwpn(0x%llx) rport(%p) n_port_id(0x%x)",
				  v_lport->port_id, index,
				  wwn_rport_info->wwpn,
				  v_rport, v_rport->nport_id);

			atomic_inc(&v_lport->resume_scsi_id);
			goto find;
		}
	}

	/* 2. Alloc new SCSI ID */
	for (index = 0; index < rport_scsi_table->max_scsi_id; index++) {
		wwn_rport_info =
			&rport_scsi_table->wwn_rport_info_table[index];
		if (wwn_rport_info->wwpn == INVALID_WWPN) {
			spin_unlock_irqrestore(
				&rport_scsi_table->scsi_image_table_lock,
				flags);
			UNF_DELAYED_WORK_SYNC(ret, (v_lport->port_id),
					      (&wwn_rport_info->loss_tmo_work),
					      "loss tmo Timer work");

			/* Use the free space */
			spin_lock_irqsave(
				&rport_scsi_table->scsi_image_table_lock,
				flags);
			wwn_rport_info->rport = v_rport;
			wwn_rport_info->wwpn = v_rport->port_name;
			wwn_rport_info->last_en_scis_state =
				atomic_read(&wwn_rport_info->en_scsi_state);
			atomic_set(&wwn_rport_info->en_scsi_state,
				   UNF_SCSI_ST_ONLINE);
			spin_unlock_irqrestore(
				&rport_scsi_table->scsi_image_table_lock,
				flags);

			UNF_TRACE(UNF_EVTLOG_DRIVER_INFO,
				  UNF_LOG_LOGIN_ATT, UNF_MAJOR,
				  "[info]port(0x%x) allco new scsi_id(0x%x) by wwpn(0x%llx) rport(%p) n_port_id(0x%x)",
				  v_lport->port_id, index,
				  wwn_rport_info->wwpn,
				  v_rport, v_rport->nport_id);

			atomic_inc(&v_lport->alloc_scsi_id);
			goto find;
		}
	}

	/* 3. Reuse space has been used */
	for (index = 0; index < rport_scsi_table->max_scsi_id; index++) {
		wwn_rport_info =
			&rport_scsi_table->wwn_rport_info_table[index];
		if (atomic_read(&wwn_rport_info->en_scsi_state) ==
		    UNF_SCSI_ST_DEAD) {
			spin_unlock_irqrestore(
				&rport_scsi_table->scsi_image_table_lock,
				flags);
			UNF_DELAYED_WORK_SYNC(ret, (v_lport->port_id),
					      (&wwn_rport_info->loss_tmo_work),
					      "loss tmo Timer work");

			spin_lock_irqsave(
				&rport_scsi_table->scsi_image_table_lock,
				flags);
			if (wwn_rport_info->dfx_counter) {
				memset(wwn_rport_info->dfx_counter, 0,
				       sizeof(struct unf_wwpn_dfx_counter_info_s));
			}
			wwn_rport_info->rport = v_rport;
			wwn_rport_info->wwpn = v_rport->port_name;
			wwn_rport_info->last_en_scis_state =
				atomic_read(&wwn_rport_info->en_scsi_state);
			atomic_set(&wwn_rport_info->en_scsi_state,
				   UNF_SCSI_ST_ONLINE);
			spin_unlock_irqrestore(
				&rport_scsi_table->scsi_image_table_lock,
				flags);

			UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT,
				  UNF_WARN,
				  "[info]port(0x%x) reuse a dead scsi_id(0x%x) by wwpn(0x%llx) rport(%p) n_port_id(0x%x)",
				  v_lport->port_id, index,
				  wwn_rport_info->wwpn,
				  v_rport, v_rport->nport_id);

			atomic_inc(&v_lport->reuse_scsi_id);
			goto find;
		}
	}

	spin_unlock_irqrestore(&rport_scsi_table->scsi_image_table_lock,
			       flags);

	UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT, UNF_WARN,
		  "[warn]port(0x%x) there is not enough scsi_id with max_value(0x%x)",
		  v_lport->port_id, index);

	return INVALID_VALUE32;

find:
	if (!wwn_rport_info->dfx_counter) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_REG_ATT, UNF_INFO,
			  "[info]Port(0x%x) allocate Rport(0x%x) DFX buffer",
			  v_lport->port_id, wwn_rport_info->rport->nport_id);
		wwn_rport_info->dfx_counter =
			vmalloc(sizeof(struct unf_wwpn_dfx_counter_info_s));
		if (!wwn_rport_info->dfx_counter) {
			UNF_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_REG_ATT,
				  UNF_ERR,
				  "[err]Port(0x%x) allocate DFX buffer fail",
				  v_lport->port_id);

			return INVALID_VALUE32;
		}

		memset(wwn_rport_info->dfx_counter, 0,
		       sizeof(struct unf_wwpn_dfx_counter_info_s));
	}

	UNF_REFERNCE_VAR(ret);
	return index;
}

static unsigned int unf_get_scsi_id_by_wwpn(struct unf_lport_s *v_lport,
					    unsigned long long v_wwpn)
{
	struct unf_rport_scsi_id_image_s *rport_scsi_table = NULL;
	struct unf_wwpn_rport_info_s *wwn_rport_info = NULL;
	unsigned long flags = 0;
	unsigned int index = 0;

	UNF_CHECK_VALID(0x3015, UNF_TRUE,
			v_lport, return INVALID_VALUE32);
	rport_scsi_table = &v_lport->rport_scsi_table;

	if (!v_wwpn)
		return INVALID_VALUE32;

	spin_lock_irqsave(&rport_scsi_table->scsi_image_table_lock, flags);

	for (index = 0; index < rport_scsi_table->max_scsi_id; index++) {
		wwn_rport_info =
			&rport_scsi_table->wwn_rport_info_table[index];
		if (v_wwpn == wwn_rport_info->wwpn) {
			spin_unlock_irqrestore(
				&rport_scsi_table->scsi_image_table_lock,
				flags);
			return index;
		}
	}

	spin_unlock_irqrestore(&rport_scsi_table->scsi_image_table_lock,
			       flags);

	return INVALID_VALUE32;
}

static void unf_set_device_state(struct unf_lport_s *v_lport,
				 unsigned int v_scsi_id,
				 int en_scsi_state)
{
	struct unf_rport_scsi_id_image_s *scsi_image_table = NULL;
	struct unf_wwpn_rport_info_s *wwpn_rport_info = NULL;

	if (unlikely(v_scsi_id >= UNF_MAX_SCSI_ID)) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_LOGIN_ATT, UNF_ERR,
			  "[err]Port(0x%x) RPort scsi_id(0x%x) is max than 0x%x",
			  v_lport->port_id, v_scsi_id, UNF_MAX_SCSI_ID);
		return;
	}

	scsi_image_table = &v_lport->rport_scsi_table;
	wwpn_rport_info = &scsi_image_table->wwn_rport_info_table[v_scsi_id];
	atomic_set(&wwpn_rport_info->en_scsi_state, en_scsi_state);
}

static void unf_set_rport_state(struct unf_rport_s *v_rport,
				enum unf_rport_login_state_e v_states)
{
	UNF_CHECK_VALID(0x3055, UNF_TRUE, v_rport, return);

	if (v_states != v_rport->rp_state) {
		/* Reset R_Port retry count */
		v_rport->retries = 0;
	}

	v_rport->rp_state = v_states;
}

void unf_rport_linkdown(struct unf_lport_s *v_lport,
			struct unf_rport_s *v_rport)
{
	/*
	 * 1. port_logout
	 * 2. rcvd_rscn_port_not_in_disc
	 * 3. each_rport_after_rscn
	 * 4. rcvd_gpnid_rjt
	 * 5. rport_after_logout(rport is fabric port)
	 */
	unsigned long flag = 0;

	UNF_CHECK_VALID(0x3000, UNF_TRUE, v_lport, return);
	UNF_CHECK_VALID(0x3001, UNF_TRUE, v_rport, return);
	UNF_REFERNCE_VAR(v_lport);

	/* 1. Update R_Port state: Link Down Event --->>> closing state */
	spin_lock_irqsave(&v_rport->rport_state_lock, flag);
	unf_rport_state_ma(v_rport, UNF_EVENT_RPORT_LINK_DOWN);
	spin_unlock_irqrestore(&v_rport->rport_state_lock, flag);

	/* 3. Port enter closing (then enter to Delete) process */
	unf_rport_enter_closing(v_rport);
}

static struct unf_rport_s *unf_rport_is_changed(struct unf_lport_s *v_lport,
						struct unf_rport_s *v_rport,
						unsigned int v_sid)
{
	if (v_rport) {
		/* S_ID or D_ID has been changed */
		if ((v_rport->nport_id != v_sid) ||
		    (v_rport->local_nport_id != v_lport->nport_id)) {
			/*
			 * 1. Swap case: (SID or DID changed):
			 * Report link down & delete immediately
			 */
			unf_rport_immediate_linkdown(v_lport, v_rport);
			return NULL;
		}
	}

	return v_rport;
}

struct unf_rport_s *unf_rport_set_qualifier_key_reuse(
				struct unf_lport_s *v_lport,
				struct unf_rport_s *v_rport_by_nport_id,
				struct unf_rport_s *v_rport_by_wwpn,
				unsigned long long v_wwpn,
				unsigned int v_sid)
{
	/* Used for HIFC Chip */
	struct unf_rport_s *rport = NULL;
	struct unf_rport_s *rporta = NULL;
	struct unf_rport_s *rportb = NULL;
	int bwwpn_flag = 0;

	UNF_CHECK_VALID(0x3002, UNF_TRUE, v_lport, return NULL);

	/* About R_Port by N_Port_ID */
	rporta = unf_rport_is_changed(v_lport, v_rport_by_nport_id, v_sid);
	/* About R_Port by WWpn */
	rportb = unf_rport_is_changed(v_lport, v_rport_by_wwpn, v_sid);

	if (!rporta && !rportb) {
		return NULL;
	} else if (!rporta && rportb) {
		/* 3. Plug case: reuse again */
		rport = rportb;

		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT, UNF_MAJOR,
			  "[info]Port(0x%x) RPort(0x%p) WWPN(0x%llx) S_ID(0x%x) D_ID(0x%x) reused by wwpn",
			  v_lport->port_id, rport, rport->port_name,
			  rport->nport_id, rport->local_nport_id);

		return rport; /* Get by WWPN */
	} else if (rporta && !rportb) {
		bwwpn_flag = ((rporta->port_name != v_wwpn) &&
			      (rporta->port_name != 0) &&
			      (rporta->port_name != INVALID_VALUE64));
		if (bwwpn_flag) {
			/* 4. WWPN changed: Report link down
			 * & delete immediately
			 */
			unf_rport_immediate_linkdown(v_lport, rporta);
			return NULL;
		}

		/* Updtae WWPN */
		rporta->port_name = v_wwpn;
		rport = rporta;

		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT, UNF_MAJOR,
			  "[info]Port(0x%x) RPort(0x%p) WWPN(0x%llx) S_ID(0x%x) D_ID(0x%x) reused by N_Port_ID",
			  v_lport->port_id,
			  rport, rport->port_name,
			  rport->nport_id, rport->local_nport_id);

		return rport;  /* Get by N_Port_ID */
	}

	/* 5. Case for A == B && A && B */
	if (rporta == rportb) {
		rport = rporta;

		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT, UNF_MAJOR,
			  "[info]Port(0x%x) find the same RPort(0x%p) WWPN(0x%llx) S_ID(0x%x) D_ID(0x%x)",
			  v_lport->port_id,
			  rport, rport->port_name,
			  rport->nport_id, rport->local_nport_id);

		return rport;
	}

	UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT, UNF_WARN,
		  "[warn]port(0x%x) find two duplicate login. rport(A:0x%p, WWPN:0x%llx, S_ID:0x%x, D_ID:0x%x) rport(B:0x%p, WWPN:0x%llx, S_ID:0x%x, D_ID:0x%x)",
		  v_lport->port_id,
		  rporta, rporta->port_name,
		  rporta->nport_id, rporta->local_nport_id,
		  rportb, rportb->port_name,
		  rportb->nport_id, rportb->local_nport_id);

	/* 6. Case for A != B && A && B */
	unf_rport_immediate_linkdown(v_lport, rporta);
	unf_rport_immediate_linkdown(v_lport, rportb);

	return NULL;
}

struct unf_rport_s *unf_get_rport_by_wwn(struct unf_lport_s *v_lport,
					 unsigned long long v_wwpn)
{
	struct unf_lport_s *lport = NULL;
	struct unf_disc_s *disc = NULL;
	struct unf_rport_s *rport = NULL;
	struct list_head *node = NULL;
	struct list_head *next_node = NULL;
	unsigned long flag = 0;
	struct unf_rport_s *find_rport = NULL;

	UNF_CHECK_VALID(0x3049, UNF_TRUE, v_lport, return NULL);
	lport = (struct unf_lport_s *)v_lport;
	disc = &lport->disc;

	/* for each r_port from busy_list: compare wwpn(port name) */
	spin_lock_irqsave(&disc->rport_busy_pool_lock, flag);
	list_for_each_safe(node, next_node, &disc->list_busy_rports) {
		rport = list_entry(node, struct unf_rport_s, entry_rport);
		if (rport && rport->port_name == v_wwpn) {
			find_rport = rport;

			break;
		}
	}
	spin_unlock_irqrestore(&disc->rport_busy_pool_lock, flag);

	return find_rport;
}

struct unf_rport_s *unf_find_valid_rport(struct unf_lport_s *v_lport,
					 unsigned long long v_wwpn,
					 unsigned int v_sid)
{
	struct unf_rport_s *rport = NULL;
	struct unf_rport_s *rport_by_nport_id = NULL;
	struct unf_rport_s *rport_by_wwpn = NULL;
	unsigned long flags = 0;

	UNF_CHECK_VALID(0x3005, UNF_TRUE, v_lport, return NULL);
	UNF_CHECK_VALID(0x3006, UNF_TRUE,
			v_lport->pfn_unf_qualify_rport, return NULL);

	/* Get R_Port by WWN & N_Port_ID */
	rport_by_nport_id = unf_get_rport_by_nport_id(v_lport, v_sid);
	rport_by_wwpn = unf_get_rport_by_wwn(v_lport, v_wwpn);

	/* R_Port check: by WWPN */
	if (rport_by_wwpn) {
		spin_lock_irqsave(&rport_by_wwpn->rport_state_lock, flags);
		if (rport_by_wwpn->nport_id == UNF_FC_FID_FLOGI) {
			spin_unlock_irqrestore(
					&rport_by_wwpn->rport_state_lock,
					flags);

			UNF_TRACE(UNF_EVTLOG_DRIVER_ERR,
				  UNF_LOG_LOGIN_ATT, UNF_INFO,
				  "[err]Port(0x%x) RPort(0x%p) find by WWPN(0x%llx) is invalid",
				  v_lport->port_id, rport_by_wwpn, v_wwpn);

			rport_by_wwpn = NULL;
		} else {
			spin_unlock_irqrestore(
					&rport_by_wwpn->rport_state_lock,
					flags);
		}
	}

	UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT, UNF_MAJOR,
		  "[info]Port(0x%x_0x%x) RPort(0x%p) find by N_Port_ID(0x%x) and RPort(0x%p) by WWPN(0x%llx)",
		  v_lport->port_id, v_lport->nport_id,
		  rport_by_nport_id, v_sid, rport_by_wwpn, v_wwpn);

	/* R_Port validity check: get by WWPN & N_Port_ID */
	rport = v_lport->pfn_unf_qualify_rport(v_lport, rport_by_nport_id,
					       rport_by_wwpn,
					       v_wwpn, v_sid);
	return rport;
}

void unf_rport_delay_login(struct unf_rport_s *v_rport)
{
	UNF_CHECK_VALID(0x3009, UNF_TRUE, v_rport, return);

	/* Do R_Port recovery: PLOGI or PRLI or LOGO */
	unf_rport_error_recovery(v_rport);
}

unsigned int unf_rport_ref_inc(struct unf_rport_s *v_rport)
{
	UNF_CHECK_VALID(0x3010, UNF_TRUE,
			v_rport, return UNF_RETURN_ERROR);

	if (atomic_read(&v_rport->rport_ref_cnt) <= 0) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_LOGIN_ATT, UNF_ERR,
			  "[err]Rport(0x%x) reference count is wrong %d",
			  v_rport->nport_id,
			  atomic_read(&v_rport->rport_ref_cnt));
		return UNF_RETURN_ERROR;
	}

	atomic_inc(&v_rport->rport_ref_cnt);

	UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT, UNF_INFO,
		  "[info]Rport(0x%x) reference count is %d",
		  v_rport->nport_id, atomic_read(&v_rport->rport_ref_cnt));

	return RETURN_OK;
}

void unf_rport_enter_logo(struct unf_lport_s *v_lport,
			  struct unf_rport_s *v_rport)
{
	/*
	 * 1. TMF/ABTS timeout recovery                                      :Y
	 * 2. L_Port error recovery --->>> larger than retry_count           :Y
	 * 3. R_Port error recovery --->>> larger than retry_count           :Y
	 * 4. Check PLOGI parameters --->>> parameter is error               :Y
	 * 5. PRLI handler  --->>> R_Port state is error                     :Y
	 * 6. PDISC handler  --->>> R_Port state is not PRLI_WAIT            :Y
	 * 7. ADISC handler  --->>> R_Port state is not PRLI_WAIT            :Y
	 * 8. PLOGI wait timeout with R_PORT is INI mode                     :Y
	 * 9. RCVD GFFID_RJT  --->>> R_Port state is INIT                    :Y
	 * 10. RCVD GPNID_ACC  --->>> R_Port state is error                  :Y
	 * 11. Private Loop mode with LOGO case                              :Y
	 * 12. P2P mode with LOGO case                                       :Y
	 * 13. Fabric  mode with LOGO case                                   :Y
	 * 14. RCVD PRLI_ACC with R_Port is INI                              :Y
	 * 15. TGT RCVD BLS_REQ with session is error                        :Y
	 */
	unsigned long flags = 0;

	UNF_CHECK_VALID(0x3013, UNF_TRUE, v_lport, return);
	UNF_CHECK_VALID(0x3014, UNF_TRUE, v_rport, return);

	spin_lock_irqsave(&v_rport->rport_state_lock, flags);

	if ((v_rport->rp_state == UNF_RPORT_ST_CLOSING) ||
	    (v_rport->rp_state == UNF_RPORT_ST_DELETE)) {
		/* 1. Already within Closing or Delete: Do nothing */
		spin_unlock_irqrestore(&v_rport->rport_state_lock, flags);

		return;
	} else if (v_rport->rp_state == UNF_RPORT_ST_LOGO) {
		/* 2. Update R_Port state:
		 * Normal Enter Event --->>> closing state
		 */
		unf_rport_state_ma(v_rport, UNF_EVENT_RPORT_NORMAL_ENTER);
		spin_unlock_irqrestore(&v_rport->rport_state_lock, flags);

		/* Send Logo if necessary */
		if (unf_send_logo(v_lport, v_rport) != RETURN_OK)
			unf_rport_enter_closing(v_rport);
	} else {
		/*
		 * 3. Update R_Port state: Link Down Event --->>> closing state
		 * enter closing state
		 */
		unf_rport_state_ma(v_rport, UNF_EVENT_RPORT_LINK_DOWN);
		spin_unlock_irqrestore(&v_rport->rport_state_lock, flags);

		unf_rport_enter_closing(v_rport);
	}
}

unsigned int unf_free_scsi_id(struct unf_lport_s *v_lport,
			      unsigned int v_scsi_id)
{
	unsigned long flags = 0;
	struct unf_rport_scsi_id_image_s *rport_scsi_table = NULL;
	struct unf_wwpn_rport_info_s *wwn_rport_info = NULL;

	UNF_CHECK_VALID(0x3016, UNF_TRUE,
			v_lport, return UNF_RETURN_ERROR);

	if (unlikely(v_lport->b_port_removing == UNF_TRUE)) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT, UNF_WARN,
			  "[warn]Port(0x%x_0x%x) is removing and do nothing",
			  v_lport->port_id, v_lport->nport_id);

		return UNF_RETURN_ERROR;
	}

	if (unlikely(v_scsi_id >= UNF_MAX_SCSI_ID)) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_LOGIN_ATT, UNF_ERR,
			  "[err]Port(0x%x_0x%x) scsi_id(0x%x) is bigger than %d",
			  v_lport->port_id, v_lport->nport_id,
			  v_scsi_id, UNF_MAX_SCSI_ID);

		return UNF_RETURN_ERROR;
	}

	rport_scsi_table = &v_lport->rport_scsi_table;
	if (rport_scsi_table->wwn_rport_info_table) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT, UNF_INFO,
			  "[warn]Port(0x%x_0x%x) RPort(0x%p) free scsi_id(0x%x) wwpn(0x%llx) target_id(0x%x) succeed",
			  v_lport->port_id, v_lport->nport_id,
			  rport_scsi_table->wwn_rport_info_table[v_scsi_id].rport,
			  v_scsi_id,
			  rport_scsi_table->wwn_rport_info_table[v_scsi_id].wwpn,
			  rport_scsi_table->wwn_rport_info_table[v_scsi_id].target_id);

		spin_lock_irqsave(&rport_scsi_table->scsi_image_table_lock,
				  flags);
		wwn_rport_info =
			&rport_scsi_table->wwn_rport_info_table[v_scsi_id];
		if (wwn_rport_info->rport) {
			wwn_rport_info->rport->rport = NULL;
			wwn_rport_info->rport = NULL;
		}

		wwn_rport_info->target_id = INVALID_VALUE32;
		atomic_set(&wwn_rport_info->en_scsi_state, UNF_SCSI_ST_DEAD);

		/* NOTE: remain WWPN/Port_Name unchanged(un-cleared) */
		spin_unlock_irqrestore(
			&rport_scsi_table->scsi_image_table_lock,
			flags);

		return RETURN_OK;
	}

	return UNF_RETURN_ERROR;
}

static void unf_report_ini_linkup_event(struct unf_lport_s *v_lport,
					struct unf_rport_s *v_rport)
{
	UNF_CHECK_VALID(0x3031, UNF_TRUE, v_lport, return);
	UNF_CHECK_VALID(0x3032, UNF_TRUE, v_rport, return);

	UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_NORMAL, UNF_MAJOR,
		  "[event]Port(0x%x) RPort(0x%x_0x%p) put INI link up work(%p) to work_queue",
		  v_lport->port_id, v_rport->nport_id, v_rport,
		  &v_rport->start_work);

	if (unlikely(!queue_work(v_lport->link_event_wq,
				 &v_rport->start_work))) {
		atomic_inc(&v_lport->add_start_work_failed);

		UNF_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_NORMAL, UNF_ERR,
			  "[err]Port(0x%x) RPort(0x%x_0x%p) put INI link up to work_queue failed",
			  v_lport->port_id, v_rport->nport_id, v_rport);
	}
}

static void unf_report_ini_linkdown_event(struct unf_lport_s *v_lport,
					  struct unf_rport_s *v_rport)
{
	unsigned int scsi_id = 0;
	struct fc_rport *rport = NULL;
	unsigned long flag = 0;

	UNF_CHECK_VALID(0x3033, UNF_TRUE, v_lport, return);
	UNF_CHECK_VALID(0x3034, UNF_TRUE, v_rport, return);

	/*
	 * 1. set local device(rport/rport_info_table) state
	 *  -------------------------------------------------OFF_LINE
	 **
	 * about rport->scsi_id
	 * valid during rport link up to link down
	 */
	spin_lock_irqsave(&v_rport->rport_state_lock, flag);
	scsi_id = v_rport->scsi_id;
	unf_set_device_state(v_lport, scsi_id, UNF_SCSI_ST_OFFLINE);

	/* 2. delete scsi's rport */
	rport = (struct fc_rport *)v_rport->rport;
	spin_unlock_irqrestore(&v_rport->rport_state_lock, flag);
	if (rport) {
		fc_remote_port_delete(rport);

		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO,
			  UNF_LOG_LOGIN_ATT, UNF_KEVENT,
			  "[event]port(0x%x_0x%x) delete rport(0x%x) wwpn(0x%llx) scsi_id(0x%x) succeed",
			  v_lport->port_id, v_lport->nport_id,
			  v_rport->nport_id,
			  v_rport->port_name, scsi_id);

		atomic_inc(&v_lport->scsi_session_del_success);
	} else {
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT, UNF_KEVENT,
			  "[info]Port(0x%x_0x%x) delete RPort(0x%x_0x%p) failed",
			  v_lport->port_id, v_lport->nport_id,
			  v_rport->nport_id, v_rport);

		atomic_inc(&v_lport->scsi_session_del_failed);
	}
}

void unf_update_lport_state_by_linkup_event(struct unf_lport_s *v_lport,
					    struct unf_rport_s *v_rport,
					    unsigned int rport_att)
{
	/* Report R_Port Link Up/Down Event */
	unsigned long flag = 0;
	enum unf_port_state_e en_lport_state = 0;

	UNF_CHECK_VALID(0x3019, UNF_TRUE, v_lport, return);
	UNF_CHECK_VALID(0x3020, UNF_TRUE, v_rport, return);

	spin_lock_irqsave(&v_rport->rport_state_lock, flag);

	/* 1. R_Port does not has TGT mode any more */
	if (!(rport_att & UNF_FC4_FRAME_PARM_3_TGT) &&
	    (v_rport->lport_ini_state == UNF_PORT_STATE_LINKUP)) {
		v_rport->last_lport_ini_state = v_rport->lport_ini_state;
		// L_Port INI mode: Down
		v_rport->lport_ini_state = UNF_PORT_STATE_LINKDOWN;

		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT, UNF_WARN,
			  "[warn]Port(0x%x) RPort(0x%x) does not have TGT attribute(0x%x) any more",
			  v_lport->port_id, v_rport->nport_id, rport_att);
	}

	/* 2. R_Port with TGT mode, L_Port with INI mode */
	if ((rport_att & UNF_FC4_FRAME_PARM_3_TGT) &&
	    (v_lport->options & UNF_FC4_FRAME_PARM_3_INI)) {
		v_rport->last_lport_ini_state = v_rport->lport_ini_state;
		// L_Port INI mode: Up
		v_rport->lport_ini_state = UNF_PORT_STATE_LINKUP;

		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT, UNF_INFO,
			  "[warn]Port(0x%x) update INI state with last(0x%x) and now(0x%x)",
			  v_lport->port_id, v_rport->last_lport_ini_state,
			  v_rport->lport_ini_state);
	}

	/* 3. Report L_Port INI/TGT Down/Up event to SCSI */
	if (v_rport->last_lport_ini_state == v_rport->lport_ini_state) {
		if (v_rport->nport_id < UNF_FC_FID_DOM_MGR) {
			UNF_TRACE(UNF_EVTLOG_DRIVER_WARN,
				  UNF_LOG_LOGIN_ATT, UNF_WARN,
				  "[warn]Port(0x%x) RPort(0x%x %p) INI state(0x%x) has not been changed",
				  v_lport->port_id, v_rport->nport_id, v_rport,
				  v_rport->lport_ini_state);
		}

		spin_unlock_irqrestore(&v_rport->rport_state_lock, flag);

		return;
	}

	en_lport_state = v_rport->lport_ini_state;

	spin_unlock_irqrestore(&v_rport->rport_state_lock, flag);

	switch (en_lport_state) {
	/* Link Down */
	case UNF_PORT_STATE_LINKDOWN:
		unf_report_ini_linkdown_event(v_lport, v_rport);
		break;

	/* Link Up */
	case UNF_PORT_STATE_LINKUP:
		unf_report_ini_linkup_event(v_lport, v_rport);
		break;

	default:
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT, UNF_WARN,
			  "[warn]Port(0x%x) with unknown link status(0x%x)",
			  v_lport->port_id, v_rport->lport_ini_state);
		break;
	}
}

static void unf_rport_call_back(void *v_rport,
				void *v_lport,
				unsigned int v_result)
{
	/* Report R_Port link down event */
	struct unf_rport_s *rport = NULL;
	struct unf_lport_s *lport = NULL;
	unsigned long flag = 0;

	UNF_REFERNCE_VAR(lport);
	UNF_REFERNCE_VAR(v_result);

	UNF_CHECK_VALID(0x3037, UNF_TRUE, v_rport, return);
	UNF_CHECK_VALID(0x3038, UNF_TRUE, v_lport, return);
	rport = (struct unf_rport_s *)v_rport;
	lport = (struct unf_lport_s *)v_lport;

	spin_lock_irqsave(&rport->rport_state_lock, flag);
	rport->last_lport_ini_state = rport->lport_ini_state;
	rport->lport_ini_state = UNF_PORT_STATE_LINKDOWN;
	rport->last_lport_tgt_state = rport->lport_tgt_state;
	rport->lport_tgt_state = UNF_PORT_STATE_LINKDOWN;

	/* Report R_Port Link Down Event to scsi */
	if (rport->last_lport_ini_state == rport->lport_ini_state) {
		if (rport->nport_id < UNF_FC_FID_DOM_MGR) {
			UNF_TRACE(UNF_EVTLOG_DRIVER_WARN,
				  UNF_LOG_LOGIN_ATT, UNF_WARN,
				  "[warn]Port(0x%x) RPort(0x%x %p) INI state(0x%x) has not been changed",
				  lport->port_id, rport->nport_id, rport,
				  rport->lport_ini_state);
		}
		spin_unlock_irqrestore(&rport->rport_state_lock, flag);

		return;
	}

	spin_unlock_irqrestore(&rport->rport_state_lock, flag);

	unf_report_ini_linkdown_event(lport, rport);
}

static void unf_rport_recovery_timeout(struct work_struct *v_work)
{
	struct unf_lport_s *lport = NULL;
	struct unf_rport_s *rport = NULL;
	unsigned int ret = RETURN_OK;
	unsigned long flag = 0;
	enum unf_rport_login_state_e en_rp_state = UNF_RPORT_ST_INIT;

	UNF_CHECK_VALID(0x3039, UNF_TRUE, v_work, return);

	rport = container_of(v_work, struct unf_rport_s, recovery_work.work);
	if (unlikely(!rport)) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_LOGIN_ATT,
			  UNF_ERR, "[err]RPort is NULL");

		return;
	}

	lport = rport->lport;
	if (unlikely(!lport)) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_LOGIN_ATT, UNF_ERR,
			  "[err]RPort(0x%x) Port is NULL",
			  rport->nport_id);

		/* for timer */
		unf_rport_ref_dec(rport);
		return;
	}

	spin_lock_irqsave(&rport->rport_state_lock, flag);
	en_rp_state = rport->rp_state;

	UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT, UNF_MAJOR,
		  "[info]Port(0x%x_0x%x) RPort(0x%x) state(0x%x) recovery timer timeout",
		  lport->port_id, lport->nport_id,
		  rport->nport_id, en_rp_state);
	spin_unlock_irqrestore(&rport->rport_state_lock, flag);

	switch (en_rp_state) {
	case UNF_RPORT_ST_PLOGI_WAIT:
		if (((lport->en_act_topo == UNF_ACT_TOP_P2P_DIRECT) &&
		     (lport->port_name > rport->port_name)) ||
		    lport->en_act_topo != UNF_ACT_TOP_P2P_DIRECT) {
			/* P2P: Name is master with P2P_D or has INI Mode */
			ret = unf_send_plogi(rport->lport, rport);
		}
		break;

	case UNF_RPORT_ST_PRLI_WAIT:
		ret = unf_send_prli(rport->lport, rport);
		break;

	default:
		break;
	}

	if (ret != RETURN_OK)
		unf_rport_error_recovery(rport);

	/* company with timer */
	unf_rport_ref_dec(rport);
}

static unsigned int unf_get_dev_loss_tmo_by_rport(struct unf_lport_s *v_lport,
						  struct unf_rport_s *v_rport)
{
	struct fc_rport *rport = (struct fc_rport *)v_rport->rport;

	if (rport)
		return rport->dev_loss_tmo;
	else
		return (unsigned int)unf_get_link_lose_tmo(v_lport);
}

void unf_schedule_closing_work(struct unf_lport_s *v_lport,
			       struct unf_rport_s *v_rport)
{
	unsigned long flags = 0;
	struct unf_rport_scsi_id_image_s *rport_scsi_table = NULL;
	struct unf_wwpn_rport_info_s *wwn_rport_info = NULL;
	unsigned int scsi_id = 0;
	unsigned int ret = 0;
	unsigned int delay = 0;

	UNF_CHECK_VALID(0x3561, UNF_TRUE, v_lport, return);
	UNF_CHECK_VALID(0x3562, UNF_TRUE, v_rport, return);

	delay = unf_get_dev_loss_tmo_by_rport(v_lport, v_rport);
	rport_scsi_table = &v_lport->rport_scsi_table;
	scsi_id = v_rport->scsi_id;
	spin_lock_irqsave(&v_rport->rport_state_lock, flags);

	/* 1. Cancel recovery_work */
	if (cancel_delayed_work(&v_rport->recovery_work)) {
		atomic_dec(&v_rport->rport_ref_cnt);

		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT, UNF_MAJOR,
			  "[info]Port(0x%x_0x%x) RPort(0x%x_0x%p) cancel recovery work succeed",
			  v_lport->port_id, v_lport->nport_id,
			  v_rport->nport_id, v_rport);
	}

	/* 2. Cancel Open_work */
	if (cancel_delayed_work(&v_rport->open_work)) {
		atomic_dec(&v_rport->rport_ref_cnt);

		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT, UNF_MAJOR,
			  "[info]Port(0x%x_0x%x) RPort(0x%x_0x%p) cancel open work succeed",
			  v_lport->port_id, v_lport->nport_id,
			  v_rport->nport_id, v_rport);
	}

	spin_unlock_irqrestore(&v_rport->rport_state_lock, flags);

	/* 3. Work in-queue (switch to thread context) */
	if (!queue_work(v_lport->link_event_wq, &v_rport->closing_work)) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_NORMAL, UNF_ERR,
			  "[warn]Port(0x%x) RPort(0x%x_0x%p) add link down to work queue failed",
			  v_lport->port_id, v_rport->nport_id, v_rport);

		atomic_inc(&v_lport->add_closing_work_failed);

	} else {
		spin_lock_irqsave(&v_rport->rport_state_lock, flags);
		(void)unf_rport_ref_inc(v_rport);
		spin_unlock_irqrestore(&v_rport->rport_state_lock, flags);

		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_NORMAL, UNF_MAJOR,
			  "[info]Port(0x%x) RPort(0x%x_0x%p) add link down to work(%p) queue succeed",
			  v_lport->port_id, v_rport->nport_id, v_rport,
			  &v_rport->closing_work);
	}

	if (v_rport->nport_id > UNF_FC_FID_DOM_MGR)
		return;

	if (scsi_id >= UNF_MAX_SCSI_ID) {
		scsi_id = unf_get_scsi_id_by_wwpn(v_lport, v_rport->port_name);
		if (scsi_id >= UNF_MAX_SCSI_ID) {
			UNF_TRACE(UNF_EVTLOG_DRIVER_WARN,
				  UNF_LOG_NORMAL, UNF_WARN,
				  "[warn]Port(0x%x) RPort(0x%p) NPortId(0x%x) wwpn(0x%llx) option(0x%x) scsi_id(0x%x) is max than(0x%x)",
				  v_lport->port_id, v_rport, v_rport->nport_id,
				  v_rport->port_name,
				  v_rport->options, scsi_id,
				  UNF_MAX_SCSI_ID);

			return;
		}
	}

	wwn_rport_info = &rport_scsi_table->wwn_rport_info_table[scsi_id];
	ret = queue_delayed_work(
			unf_work_queue,
			&wwn_rport_info->loss_tmo_work,
			(unsigned long)delay * msecs_to_jiffies(1000));
	if (!ret) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_NORMAL, UNF_MAJOR,
			  "[info] Port(0x%x) add RPort(0x%p) NPortId(0x%x) scsi_id(0x%x) wwpn(0x%llx) loss timeout work failed",
			  v_lport->port_id, v_rport,
			  v_rport->nport_id, scsi_id,
			  v_rport->port_name);
	}
}

static void unf_rport_closing_timeout(struct work_struct *v_work)
{
	/* closing --->>>(timeout)--->>> delete */
	struct unf_rport_s *rport = NULL;
	struct unf_lport_s *lport = NULL;
	struct unf_disc_s *disc = NULL;
	unsigned long rport_flag = 0;
	unsigned long disc_flag = 0;
	void (*pfn_unf_rport_call_back)(void *, void *, unsigned int) = NULL;

	UNF_CHECK_VALID(0x3040, UNF_TRUE, v_work, return);

	/* Get R_Port & L_Port & Disc */
	rport = container_of(v_work, struct unf_rport_s, closing_work);
	if (unlikely(!rport)) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_LOGIN_ATT,
			  UNF_ERR, "[err]RPort is NULL");
		return;
	}

	lport = rport->lport;
	if (unlikely(!lport)) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_LOGIN_ATT, UNF_ERR,
			  "[err]RPort(0x%x_0x%p) Port is NULL",
			  rport->nport_id, rport);

		/* Release directly (for timer) */
		unf_rport_ref_dec(rport);
		return;
	}
	disc = &lport->disc;

	spin_lock_irqsave(&rport->rport_state_lock, rport_flag);

	/* 1. Update R_Port state: event_timeout --->>> state_delete */
	unf_rport_state_ma(rport, UNF_EVENT_RPORT_CLS_TIMEOUT);

	/* Check R_Port state */
	if (rport->rp_state != UNF_RPORT_ST_DELETE) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_LOGIN_ATT, UNF_ERR,
			  "[err]Port(0x%x_0x%x) RPort(0x%x) closing timeout with error state(0x%x)",
			  lport->port_id, lport->nport_id,
			  rport->nport_id, rport->rp_state);

		spin_unlock_irqrestore(&rport->rport_state_lock, rport_flag);

		/* Dec ref_cnt for timer */
		unf_rport_ref_dec(rport);
		return;
	}

	pfn_unf_rport_call_back = rport->pfn_unf_rport_call_back;
	spin_unlock_irqrestore(&rport->rport_state_lock, rport_flag);

	/* 2. Put R_Port to delete list */
	spin_lock_irqsave(&disc->rport_busy_pool_lock, disc_flag);
	list_del_init(&rport->entry_rport);
	list_add_tail(&rport->entry_rport, &disc->list_delete_rports);
	spin_unlock_irqrestore(&disc->rport_busy_pool_lock, disc_flag);

	/* 3. Report rport link down event to scsi */
	if (pfn_unf_rport_call_back) { /* unf_rport_call_back */
		pfn_unf_rport_call_back((void *)rport, (void *)rport->lport,
					RETURN_OK);
	} else {
		UNF_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_LOGIN_ATT, UNF_ERR,
			  "[err]RPort(0x%x) callback is NULL",
			  rport->nport_id);
	}

	/* 4. Remove/delete R_Port */
	unf_rport_ref_dec(rport);
	unf_rport_ref_dec(rport);
}

static void unf_rport_linkup_to_scsi(struct work_struct *v_work)
{
	struct fc_rport_identifiers rport_ids;
	struct fc_rport *rport = NULL;
	unsigned long flags = RETURN_OK;
	struct unf_wwpn_rport_info_s *wwn_rport_info = NULL;
	struct unf_rport_scsi_id_image_s *rport_scsi_table = NULL;
	unsigned int scsi_id = 0;

	struct unf_lport_s *lport = NULL;
	struct unf_rport_s *unf_rport = NULL;

	UNF_CHECK_VALID(0x3040, UNF_TRUE, v_work, return);

	unf_rport = container_of(v_work, struct unf_rport_s, start_work);
	if (unlikely(!unf_rport)) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_LOGIN_ATT, UNF_ERR,
			  "[err]RPort is NULL for work(%p)", v_work);
		return;
	}

	lport = unf_rport->lport;
	if (unlikely(!lport)) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_LOGIN_ATT, UNF_ERR,
			  "[err]RPort(0x%x_0x%p) Port is NULL",
			  unf_rport->nport_id, unf_rport);
		return;
	}

	/* 1. Alloc R_Port SCSI_ID (image table) */
	unf_rport->scsi_id = unf_alloc_scsi_id(lport, unf_rport);
	if (unlikely(unf_rport->scsi_id == INVALID_VALUE32)) {
		atomic_inc(&lport->scsi_session_add_failed);

		UNF_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_LOGIN_ATT, UNF_WARN,
			  "[err]Port(0x%x_0x%x) RPort(0x%x_0x%p) wwpn(0x%llx) scsi_id(0x%x) is invalid",
			  lport->port_id, lport->nport_id,
			  unf_rport->nport_id, unf_rport,
			  unf_rport->port_name, unf_rport->scsi_id);

		/* NOTE: return */
		return;
	}

	/* 2. Add rport to scsi */
	scsi_id = unf_rport->scsi_id;
	rport_ids.node_name = unf_rport->node_name;
	rport_ids.port_name = unf_rport->port_name;
	rport_ids.port_id = unf_rport->nport_id;
	rport_ids.roles = FC_RPORT_ROLE_UNKNOWN;
	rport = fc_remote_port_add(lport->host_info.p_scsi_host,
				   0, &rport_ids);
	if (unlikely(!rport)) {
		atomic_inc(&lport->scsi_session_add_failed);

		UNF_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_LOGIN_ATT, UNF_ERR,
			  "[err]Port(0x%x_0x%x) RPort(0x%x_0x%p) wwpn(0x%llx) report link up to scsi failed",
			  lport->port_id, lport->nport_id,
			  unf_rport->nport_id, unf_rport,
			  unf_rport->port_name);

		unf_free_scsi_id(lport, scsi_id);
		return;
	}

	/* 3. Change rport role save local SCSI_ID to scsi rport */
	*((unsigned int *)rport->dd_data) = scsi_id;
	rport->supported_classes = FC_COS_CLASS3;
	rport_ids.roles |= FC_PORT_ROLE_FCP_TARGET;
	fc_remote_port_rolechg(rport, rport_ids.roles);

	/* 4. Save scsi rport info to local R_Port */
	spin_lock_irqsave(&unf_rport->rport_state_lock, flags);
	unf_rport->rport = rport;
	spin_unlock_irqrestore(&unf_rport->rport_state_lock, flags);

	rport_scsi_table = &lport->rport_scsi_table;
	spin_lock_irqsave(&rport_scsi_table->scsi_image_table_lock, flags);
	wwn_rport_info = &rport_scsi_table->wwn_rport_info_table[scsi_id];
	wwn_rport_info->target_id = rport->scsi_target_id;
	wwn_rport_info->rport = unf_rport;
	atomic_set(&wwn_rport_info->en_scsi_state, UNF_SCSI_ST_ONLINE);
	spin_unlock_irqrestore(&rport_scsi_table->scsi_image_table_lock,
			       flags);

	UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT, UNF_KEVENT,
		  "[event]port(0x%x_0x%x) rport(0x%x) wwpn(0x%llx) scsi_id(0x%x) link up to scsi succeed",
		  lport->port_id, lport->nport_id,
		  unf_rport->nport_id, unf_rport->port_name,
		  scsi_id);

	atomic_inc(&lport->scsi_session_add_success);
}

static void unf_rport_open_timeout(struct work_struct *v_work)
{
	struct unf_rport_s *rport = NULL;
	struct unf_lport_s *lport = NULL;
	unsigned long flags = 0;

	UNF_CHECK_VALID(0x3041, UNF_TRUE, v_work, return);

	rport = container_of(v_work, struct unf_rport_s, open_work.work);
	if (!rport) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT, UNF_WARN,
			  "[warn]RPort is NULL");

		return;
	}

	spin_lock_irqsave(&rport->rport_state_lock, flags);
	lport = rport->lport;

	UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT, UNF_WARN,
		  "[warn]Port(0x%x_0x%x) RPort(0x%x) open work timeout with state(0x%x)",
		  lport->port_id, lport->nport_id,
		  rport->nport_id, rport->rp_state);

	/* NOTE: R_Port state check */
	if (rport->rp_state != UNF_RPORT_ST_PRLI_WAIT) {
		spin_unlock_irqrestore(&rport->rport_state_lock, flags);

		/* Dec ref_cnt for timer case */
		unf_rport_ref_dec(rport);
		return;
	}

	/* Report R_Port Link Down event */
	unf_rport_state_ma(rport, UNF_EVENT_RPORT_LINK_DOWN);

	spin_unlock_irqrestore(&rport->rport_state_lock, flags);

	unf_rport_enter_closing(rport);

	/* Dec ref_cnt for timer case */
	unf_rport_ref_dec(rport);

	UNF_REFERNCE_VAR(lport);
}

static unsigned int unf_alloc_index_for_rport(struct unf_lport_s *v_lport,
					      struct unf_rport_s *v_rport)
{
	unsigned long rport_flag = 0;
	unsigned long pool_flag = 0;
	unsigned int alloc_indx = 0;
	unsigned int max_rport = 0;
	struct unf_rport_pool_s *rport_pool = NULL;

	rport_pool = &v_lport->rport_pool;
	max_rport = v_lport->low_level_func.lport_cfg_items.max_login;

	spin_lock_irqsave(&rport_pool->rport_free_pool_lock, pool_flag);
	while (alloc_indx < max_rport) {
		if (!test_bit((int)alloc_indx, rport_pool->pul_rpi_bitmap)) {
			/* Case for HIFC */
			if (unlikely(atomic_read(
					&v_lport->port_no_operater_flag) ==
					UNF_LPORT_NOP)) {
				UNF_TRACE(UNF_EVTLOG_DRIVER_WARN,
					  UNF_LOG_LOGIN_ATT, UNF_WARN,
					  "[warn]Port(0x%x) is within NOP",
					  v_lport->port_id);

				spin_unlock_irqrestore(
					&rport_pool->rport_free_pool_lock,
					pool_flag);
				return UNF_RETURN_ERROR;
			}

			spin_lock_irqsave(&v_rport->rport_state_lock,
					  rport_flag);
			/* set R_Port index */
			v_rport->rport_index = alloc_indx;
			UNF_TRACE(UNF_EVTLOG_DRIVER_INFO,
				  UNF_LOG_LOGIN_ATT, UNF_INFO,
				  "[info]Port(0x%x) RPort(0x%x) alloc index(0x%x) succeed",
				  v_lport->port_id, alloc_indx,
				  v_rport->nport_id);

			spin_unlock_irqrestore(&v_rport->rport_state_lock,
					       rport_flag);

			/* Set (index) bit */
			set_bit((int)alloc_indx, rport_pool->pul_rpi_bitmap);

			/* Break here */
			break;
		}
		alloc_indx++;
	}
	spin_unlock_irqrestore(&rport_pool->rport_free_pool_lock, pool_flag);

	if (alloc_indx == max_rport)
		return UNF_RETURN_ERROR;
	else
		return RETURN_OK;
}

static void unf_check_rport_pool_status(struct unf_lport_s *v_lport)
{
	struct unf_lport_s *lport = v_lport;
	struct unf_rport_pool_s *rport_pool = NULL;
	unsigned long flags = 0;
	unsigned int max_rport = 0;

	UNF_CHECK_VALID(0x3045, UNF_TRUE, v_lport, return);
	rport_pool = &lport->rport_pool;

	spin_lock_irqsave(&rport_pool->rport_free_pool_lock, flags);
	max_rport = lport->low_level_func.lport_cfg_items.max_login;
	if ((rport_pool->rport_pool_completion) &&
	    (max_rport == rport_pool->rport_pool_count)) {
		complete(rport_pool->rport_pool_completion);
	}
	spin_unlock_irqrestore(&rport_pool->rport_free_pool_lock, flags);
}

void unf_init_rport_params(struct unf_rport_s *v_rport,
			   struct unf_lport_s *v_lport)
{
	struct unf_rport_s *rport = v_rport;
	unsigned long flag = 0;

	UNF_CHECK_VALID(0x3046, UNF_TRUE, rport, return);
	UNF_CHECK_VALID(0x3046, UNF_TRUE, v_lport, return);

	spin_lock_irqsave(&rport->rport_state_lock, flag);
	unf_set_rport_state(rport, UNF_RPORT_ST_INIT);
	/* set callback function */
	rport->pfn_unf_rport_call_back = unf_rport_call_back;
	rport->lport = v_lport;
	rport->fcp_conf_needed = UNF_FALSE;
	rport->tape_support_needed = UNF_FALSE;
	rport->mas_retries = UNF_MAX_RETRY_COUNT;
	rport->logo_retries = 0;
	rport->retries = 0;
	rport->rscn_position = UNF_RPORT_NOT_NEED_PROCESS;
	rport->last_lport_ini_state = UNF_PORT_STATE_LINKDOWN;
	rport->lport_ini_state = UNF_PORT_STATE_LINKDOWN;
	rport->last_lport_tgt_state = UNF_PORT_STATE_LINKDOWN;
	rport->lport_tgt_state = UNF_PORT_STATE_LINKDOWN;
	rport->node_name = 0;
	rport->port_name = INVALID_WWPN;
	rport->disc_done = 0;
	rport->scsi_id = INVALID_VALUE32;
	rport->data_thread = NULL;
	sema_init(&rport->task_sema, 0);
	atomic_set(&rport->rport_ref_cnt, 0);
	atomic_set(&rport->pending_io_cnt, 0);
	rport->rport_alloc_jifs = jiffies;

	rport->ed_tov = UNF_DEFAULT_EDTOV + 500;
	rport->ra_tov = UNF_DEFAULT_RATOV;

	INIT_WORK(&rport->closing_work, unf_rport_closing_timeout);
	INIT_WORK(&rport->start_work, unf_rport_linkup_to_scsi);
	INIT_DELAYED_WORK(&rport->recovery_work, unf_rport_recovery_timeout);
	INIT_DELAYED_WORK(&rport->open_work, unf_rport_open_timeout);

	atomic_inc(&rport->rport_ref_cnt);
	spin_unlock_irqrestore(&rport->rport_state_lock, flag);
}

static unsigned int unf_alloc_llrport_resource(struct unf_lport_s *v_lport,
					       struct unf_rport_s *v_rport,
					       unsigned int v_nport_id)
{
	unsigned int ret = RETURN_OK;
	struct unf_rport_info_s rport_info = { 0 };

	struct unf_lport_s *lport = NULL;

	lport = v_lport->root_lport;

	if (lport->low_level_func.service_op.pfn_unf_alloc_rport_res) {
		rport_info.nport_id = v_nport_id;
		rport_info.rport_index = v_rport->rport_index;
		rport_info.local_nport_id = v_lport->nport_id;  /* sid */
		rport_info.port_name = 0;

		ret = lport->low_level_func.service_op.pfn_unf_alloc_rport_res(
								lport->fc_port,
								&rport_info);
	} else {
		ret = RETURN_OK;
	}

	return ret;
}

static void *unf_add_rport_to_busy_list(struct unf_lport_s *v_lport,
					struct unf_rport_s *v_new_rport,
					unsigned int v_nport_id)
{
	struct unf_rport_pool_s *rport_pool = NULL;
	struct unf_lport_s *lport = NULL;
	struct unf_disc_s *disc = NULL;
	struct unf_rport_s *new_rport = v_new_rport;
	struct unf_rport_s *old_rport = NULL;
	struct list_head *node = NULL;
	struct list_head *next_node = NULL;
	unsigned long flag = 0;

	UNF_CHECK_VALID(0x3046, UNF_TRUE, v_lport, return NULL);
	UNF_CHECK_VALID(0x3046, UNF_TRUE, v_new_rport, return NULL);

	lport = v_lport->root_lport;
	disc = &v_lport->disc;
	UNF_CHECK_VALID(0x3046, UNF_TRUE, lport, return NULL);
	rport_pool = &lport->rport_pool;

	spin_lock_irqsave(&disc->rport_busy_pool_lock, flag);
	list_for_each_safe(node, next_node, &disc->list_busy_rports) {
		/* According to N_Port_ID */
		old_rport = list_entry(node, struct unf_rport_s, entry_rport);
		if (old_rport->nport_id == v_nport_id)
			break; /* find by N_Port_ID */
		old_rport = NULL;
	}

	if (old_rport) {
		spin_unlock_irqrestore(&disc->rport_busy_pool_lock, flag);

		/* Use old R_Port & Add new R_Port back to R_Port Pool */
		spin_lock_irqsave(&rport_pool->rport_free_pool_lock, flag);
		clear_bit((int)new_rport->rport_index,
			  rport_pool->pul_rpi_bitmap);
		list_add_tail(&new_rport->entry_rport,
			      &rport_pool->list_rports_pool);
		rport_pool->rport_pool_count++;
		spin_unlock_irqrestore(&rport_pool->rport_free_pool_lock,
				       flag);

		unf_check_rport_pool_status(lport);
		return (void *)old_rport;
	}

	if (unf_alloc_llrport_resource(v_lport, new_rport,
				       v_nport_id != RETURN_OK)) {
		spin_unlock_irqrestore(&disc->rport_busy_pool_lock, flag);

		/* Add new R_Port back to R_Port Pool */
		spin_lock_irqsave(&rport_pool->rport_free_pool_lock, flag);
		clear_bit((int)new_rport->rport_index,
			  rport_pool->pul_rpi_bitmap);
		list_add_tail(&new_rport->entry_rport,
			      &rport_pool->list_rports_pool);
		rport_pool->rport_pool_count++;
		spin_unlock_irqrestore(
			&rport_pool->rport_free_pool_lock, flag);

		unf_check_rport_pool_status(lport);

		return NULL;
	}

	/* Add new R_Port to busy list */
	list_add_tail(&new_rport->entry_rport,
		      &disc->list_busy_rports);
	new_rport->nport_id = v_nport_id; /* set R_Port N_Port_ID */
	/* set L_Port N_Port_ID */
	new_rport->local_nport_id = v_lport->nport_id;
	spin_unlock_irqrestore(&disc->rport_busy_pool_lock, flag);

	unf_init_rport_params(new_rport, v_lport);

	return (void *)new_rport;
}

void *unf_rport_get_free_and_init(void *v_lport,
				  unsigned int v_rport_type,
				  unsigned int v_nport_id)
{
	struct unf_lport_s *lport = NULL;
	struct unf_rport_pool_s *rport_pool = NULL;
	struct unf_disc_s *disc = NULL;
	struct unf_disc_s *v_port_disc = NULL;
	struct unf_rport_s *rport = NULL;
	struct list_head *list_head = NULL;
	unsigned long flag = 0;
	struct unf_disc_rport_s *disc_rport = NULL;

	UNF_REFERNCE_VAR(v_rport_type);
	UNF_REFERNCE_VAR(rport);

	UNF_CHECK_VALID(0x3046, UNF_TRUE, v_lport, return NULL);
	lport = ((struct unf_lport_s *)v_lport)->root_lport; /* ROOT L_Port */
	UNF_CHECK_VALID(0x3047, UNF_TRUE, lport, return NULL);

	/* Check L_Port state: NOP */
	if (unlikely(atomic_read(&lport->port_no_operater_flag) ==
		     UNF_LPORT_NOP)) {
		return NULL;
	}

	rport_pool = &lport->rport_pool;
	disc = &lport->disc;

	/* 1. UNF_PORT_TYPE_DISC: Get from disc_rport_pool */
	if (v_rport_type == UNF_PORT_TYPE_DISC) {
		v_port_disc = &(((struct unf_lport_s *)v_lport)->disc);

		/* NOTE: list_disc_rports_pool used
		 * with list_disc_rport_busy
		 */
		spin_lock_irqsave(&disc->rport_busy_pool_lock, flag);
		if (!list_empty(&disc->disc_rport_mgr.list_disc_rports_pool)) {
			/* Get & delete from Disc R_Port Pool &
			 * Add it to Busy list
			 */
			list_head =
			(&disc->disc_rport_mgr.list_disc_rports_pool)->next;
			list_del_init(list_head);
			disc_rport = list_entry(list_head,
						struct unf_disc_rport_s,
						entry_rport);
			/* Set R_Port N_Port_ID */
			disc_rport->nport_id = v_nport_id;
			spin_unlock_irqrestore(&disc->rport_busy_pool_lock,
					       flag);

			/* Add to list_disc_rport_busy */
			spin_lock_irqsave(&v_port_disc->rport_busy_pool_lock,
					  flag);
			list_add_tail(
			list_head,
			&v_port_disc->disc_rport_mgr.list_disc_rport_busy);
			spin_unlock_irqrestore(
				&v_port_disc->rport_busy_pool_lock, flag);
		} else {
			disc_rport = NULL;
			spin_unlock_irqrestore(&disc->rport_busy_pool_lock,
					       flag);
		}

		/* NOTE: return */
		return disc_rport;
	}

	/* 2. UNF_PORT_TYPE_FC (rport_pool): Get from list_rports_pool */
	spin_lock_irqsave(&rport_pool->rport_free_pool_lock, flag);
	if (!list_empty(&rport_pool->list_rports_pool)) {
		/* Get & delete from R_Port free Pool */
		list_head = (&rport_pool->list_rports_pool)->next;
		list_del_init(list_head);
		rport_pool->rport_pool_count--;
		rport = list_entry(list_head, struct unf_rport_s, entry_rport);
	} else {
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT, UNF_WARN,
			  "[warn]Port(0x%x_0x%x) RPort pool is empty",
			  lport->port_id, lport->nport_id);

		spin_unlock_irqrestore(&rport_pool->rport_free_pool_lock,
				       flag);

		/* NOTE: return */
		return NULL;
	}
	spin_unlock_irqrestore(&rport_pool->rport_free_pool_lock, flag);

	/* 3. Alloc (& set bit) R_Port index */
	if (unf_alloc_index_for_rport(lport, rport) != RETURN_OK) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT, UNF_WARN,
			  "[warn]Port(0x%x) allocate index for new RPort failed",
			  lport->nport_id);

		/* Alloc failed: Add R_Port back to R_Port Pool */
		spin_lock_irqsave(&rport_pool->rport_free_pool_lock, flag);
		list_add_tail(&rport->entry_rport,
			      &rport_pool->list_rports_pool);
		rport_pool->rport_pool_count++;
		spin_unlock_irqrestore(&rport_pool->rport_free_pool_lock,
				       flag);

		unf_check_rport_pool_status(lport);
		return NULL;
	}

	/* 4. Add R_Port to busy list */
	rport = unf_add_rport_to_busy_list(v_lport, rport, v_nport_id);
	UNF_REFERNCE_VAR(rport);

	return (void *)rport;
}

static void unf_reset_rport_attribute(struct unf_rport_s *v_rport)
{
	unsigned long flag = 0;

	UNF_CHECK_VALID(0x3070, 1, v_rport, return);

	spin_lock_irqsave(&v_rport->rport_state_lock, flag);
	v_rport->pfn_unf_rport_call_back = NULL;
	v_rport->lport = NULL;
	v_rport->node_name = INVALID_VALUE64;
	v_rport->port_name = INVALID_WWPN;
	v_rport->nport_id = INVALID_VALUE32;
	v_rport->local_nport_id = INVALID_VALUE32;
	v_rport->max_frame_size = UNF_MAX_FRAME_SIZE;
	v_rport->ed_tov = UNF_DEFAULT_EDTOV;
	v_rport->ra_tov = UNF_DEFAULT_RATOV;
	v_rport->rport_index = INVALID_VALUE32;
	v_rport->scsi_id = INVALID_VALUE32;
	v_rport->rport_alloc_jifs = INVALID_VALUE64;

	/* ini or tgt */
	v_rport->options = 0;

	/* fcp conf */
	v_rport->fcp_conf_needed = UNF_FALSE;

	/* special req retry times */
	v_rport->retries = 0;
	v_rport->logo_retries = 0;

	/* special req retry times */
	v_rport->mas_retries = UNF_MAX_RETRY_COUNT;

	/* for target mode */
	v_rport->session = NULL;
	v_rport->last_lport_ini_state = UNF_PORT_STATE_LINKDOWN;
	v_rport->lport_ini_state = UNF_PORT_STATE_LINKDOWN;
	v_rport->rp_state = UNF_RPORT_ST_INIT;
	v_rport->last_lport_tgt_state = UNF_PORT_STATE_LINKDOWN;
	v_rport->lport_tgt_state = UNF_PORT_STATE_LINKDOWN;
	v_rport->rscn_position = UNF_RPORT_NOT_NEED_PROCESS;
	v_rport->disc_done = 0;

	/* for scsi */
	v_rport->data_thread = NULL;
	spin_unlock_irqrestore(&v_rport->rport_state_lock, flag);
}

static unsigned int unf_rport_remove(void *v_rport)
{
	/* remove_old_rport/... --->>> rport_ref_dec --->>> rport_remove */
	struct unf_lport_s *lport = NULL;
	struct unf_rport_s *rport = NULL;
	struct unf_rport_pool_s *rport_pool = NULL;
	unsigned long flag = 0;
	unsigned int rport_index = 0;

	UNF_CHECK_VALID(0x3050, UNF_TRUE,
			v_rport, return UNF_RETURN_ERROR);

	rport = (struct unf_rport_s *)v_rport;
	lport = rport->lport;
	UNF_CHECK_VALID(0x3051, UNF_TRUE,
			lport, return UNF_RETURN_ERROR);
	rport_pool = &((struct unf_lport_s *)lport->root_lport)->rport_pool;

	UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT, UNF_INFO,
		  "[info]Remove RPort(0x%p) with remote_nport_id(0x%x) local_nport_id(0x%x)",
		  rport, rport->nport_id, rport->local_nport_id);

	/* 1. Terminate open exchange before rport remove: set ABORT tag */
	unf_cm_xchg_mgr_abort_io_by_id(lport, rport,
				       rport->nport_id, lport->nport_id, 0);

	/* 2. Abort sfp exchange before rport remove */
	unf_cm_xchg_mgr_abort_sfs_by_id(lport, rport,
					rport->nport_id, lport->nport_id);

	/* 3. Release R_Port resource: session reset/delete */
	(void)unf_release_rport_res(lport, rport);

	/* 4.1 Delete R_Port from disc destroy/delete list */
	spin_lock_irqsave(&lport->disc.rport_busy_pool_lock, flag);
	list_del_init(&rport->entry_rport);
	spin_unlock_irqrestore(&lport->disc.rport_busy_pool_lock, flag);

	rport_index = rport->rport_index;  /* according to bitmap */

	UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT, UNF_KEVENT,
		  "[event]Port(0x%x) release RPort(0x%x_%p) with index(0x%x)",
		  lport->port_id, rport->nport_id, rport, rport->rport_index);

	unf_reset_rport_attribute(rport);

	/* 4.2 Add rport to --->>> rport_pool (free pool) & clear bitmap */
	spin_lock_irqsave(&rport_pool->rport_free_pool_lock, flag);
	if (lport->low_level_func.rport_release_type ==
	    UNF_LOW_LEVEL_RELEASE_RPORT_SYNC) {
		clear_bit((int)rport_index, rport_pool->pul_rpi_bitmap);
	}
	list_add_tail(&rport->entry_rport, &rport_pool->list_rports_pool);
	rport_pool->rport_pool_count++;
	spin_unlock_irqrestore(&rport_pool->rport_free_pool_lock, flag);

	unf_check_rport_pool_status((struct unf_lport_s *)lport->root_lport);
	up(&rport->task_sema);

	return RETURN_OK;
}

void unf_rport_ref_dec(struct unf_rport_s *v_rport)
{
	unsigned long flag = 0;

	UNF_CHECK_VALID(0x3011, UNF_TRUE, v_rport, return);

	UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT, UNF_INFO,
		  "[info]Rport(0x%x) reference count is %d",
		  v_rport->nport_id, atomic_read(&v_rport->rport_ref_cnt));

	spin_lock_irqsave(&v_rport->rport_state_lock, flag);
	if (atomic_dec_and_test(&v_rport->rport_ref_cnt)) {
		spin_unlock_irqrestore(&v_rport->rport_state_lock, flag);
		(void)unf_rport_remove(v_rport);
	} else {
		spin_unlock_irqrestore(&v_rport->rport_state_lock, flag);
	}
}

static enum unf_rport_login_state_e unf_rport_stat_init(
				enum unf_rport_login_state_e v_old_state,
				enum unf_rport_event_e v_event)
{
	enum unf_rport_login_state_e en_next_state = UNF_RPORT_ST_INIT;

	switch (v_event) {
	case UNF_EVENT_RPORT_LOGO:  /* LOGO --->>> LOGO */
		en_next_state = UNF_RPORT_ST_LOGO;
		break;

	case UNF_EVENT_RPORT_ENTER_PLOGI:  /* PLOGI --->>> PLOGI_WAIT */
		en_next_state = UNF_RPORT_ST_PLOGI_WAIT;
		break;

	case UNF_EVENT_RPORT_LINK_DOWN:  /* Link Down --->>> Closing */
		en_next_state = UNF_RPORT_ST_CLOSING;
		break;

	default:
		en_next_state = v_old_state;
		break;
	}

	return en_next_state;
}

static enum unf_rport_login_state_e unf_rport_stat_plogi_wait(
				enum unf_rport_login_state_e v_old_state,
				enum unf_rport_event_e v_event)
{
	enum unf_rport_login_state_e en_next_state = UNF_RPORT_ST_INIT;

	switch (v_event) {
	case UNF_EVENT_RPORT_ENTER_PRLI:  /* PRLI --->>> PRLI_WAIT */
		en_next_state = UNF_RPORT_ST_PRLI_WAIT;
		break;

	case UNF_EVENT_RPORT_LINK_DOWN:  /* Link Down --->>> closing */
		en_next_state = UNF_RPORT_ST_CLOSING;
		break;

	case UNF_EVENT_RPORT_LOGO:  /* LOGO --->>> LOGO */
		en_next_state = UNF_RPORT_ST_LOGO;
		break;

	case UNF_EVENT_RPORT_RECOVERY:  /* Recovery --->>> Ready */
		en_next_state = UNF_RPORT_ST_READY;
		break;

	default:
		en_next_state = v_old_state;
		break;
	}

	return en_next_state;
}

static enum unf_rport_login_state_e unf_rport_stat_prli_wait(
				enum unf_rport_login_state_e v_old_state,
				enum unf_rport_event_e v_event)
{
	enum unf_rport_login_state_e en_next_state = UNF_RPORT_ST_INIT;

	switch (v_event) {
	case UNF_EVENT_RPORT_READY:  /* Ready --->>> Ready */
		en_next_state = UNF_RPORT_ST_READY;
		break;

	case UNF_EVENT_RPORT_LOGO:  /* LOGO --->>> LOGO */
		en_next_state = UNF_RPORT_ST_LOGO;
		break;

	case UNF_EVENT_RPORT_LINK_DOWN:  /* Link Down --->>> Closing */
		en_next_state = UNF_RPORT_ST_CLOSING;
		break;

	case UNF_EVENT_RPORT_RECOVERY:  /* Recovery --->>> Ready */
		en_next_state = UNF_RPORT_ST_READY;
		break;

	default:
		en_next_state = v_old_state;
		break;
	}

	return en_next_state;
}

static enum unf_rport_login_state_e unf_rport_stat_ready(
				enum unf_rport_login_state_e v_old_state,
				enum unf_rport_event_e v_event)
{
	enum unf_rport_login_state_e en_next_state = UNF_RPORT_ST_INIT;

	switch (v_event) {
	case UNF_EVENT_RPORT_LOGO:  /* LOGO --->>> LOGO */
		en_next_state = UNF_RPORT_ST_LOGO;
		break;

	case UNF_EVENT_RPORT_LINK_DOWN:  /* Link Down --->>> closing */
		en_next_state = UNF_RPORT_ST_CLOSING;
		break;

	case UNF_EVENT_RPORT_ENTER_PLOGI:  /* ready --->>> plogi_wait */
		en_next_state = UNF_RPORT_ST_PLOGI_WAIT;
		break;

	default:
		en_next_state = v_old_state;
		break;
	}

	return en_next_state;
}

static enum unf_rport_login_state_e unf_rport_stat_closing(
				enum unf_rport_login_state_e v_old_state,
				enum unf_rport_event_e v_event)
{
	enum unf_rport_login_state_e en_next_state = UNF_RPORT_ST_INIT;

	switch (v_event) {
	case UNF_EVENT_RPORT_CLS_TIMEOUT:  /* timeout --->>> delete */
		en_next_state = UNF_RPORT_ST_DELETE;
		break;

	case UNF_EVENT_RPORT_RELOGIN:  /* relogin --->>> INIT */
		en_next_state = UNF_RPORT_ST_INIT;
		break;

	case UNF_EVENT_RPORT_RECOVERY:  /* recovery --->>> ready */
		en_next_state = UNF_RPORT_ST_READY;
		break;

	default:
		en_next_state = v_old_state;
		break;
	}

	return en_next_state;
}

static enum unf_rport_login_state_e unf_rport_stat_logo(
				enum unf_rport_login_state_e v_old_state,
				enum unf_rport_event_e v_event)
{
	enum unf_rport_login_state_e en_next_state = UNF_RPORT_ST_INIT;

	switch (v_event) {
	case UNF_EVENT_RPORT_NORMAL_ENTER:  /* normal enter --->>> closing */
		en_next_state = UNF_RPORT_ST_CLOSING;
		break;

	case UNF_EVENT_RPORT_RECOVERY:  /* recovery --->>> ready */
		en_next_state = UNF_RPORT_ST_READY;
		break;

	default:
		en_next_state = v_old_state;
		break;
	}

	return en_next_state;
}

void unf_rport_state_ma(struct unf_rport_s *v_rport,
			enum unf_rport_event_e v_event)
{
	enum unf_rport_login_state_e en_old_state = UNF_RPORT_ST_INIT;
	enum unf_rport_login_state_e en_next_state = UNF_RPORT_ST_INIT;

	UNF_CHECK_VALID(0x3056, UNF_TRUE, v_rport, return);

	en_old_state = v_rport->rp_state;

	switch (v_rport->rp_state) {
	/* State INIT */
	case UNF_RPORT_ST_INIT:
		en_next_state = unf_rport_stat_init(en_old_state, v_event);
		break;

	/* State PLOGI Wait */
	case UNF_RPORT_ST_PLOGI_WAIT:
		en_next_state = unf_rport_stat_plogi_wait(en_old_state,
							  v_event);
		break;

	/* State PRLI Wait */
	case UNF_RPORT_ST_PRLI_WAIT:
		en_next_state = unf_rport_stat_prli_wait(en_old_state,
							 v_event);
		break;

	/* State LOGO */
	case UNF_RPORT_ST_LOGO:
		en_next_state = unf_rport_stat_logo(en_old_state, v_event);
		break;

	/* State CLOSING */
	case UNF_RPORT_ST_CLOSING:
		en_next_state = unf_rport_stat_closing(en_old_state, v_event);
		break;

	/* State READY */
	case UNF_RPORT_ST_READY:
		en_next_state = unf_rport_stat_ready(en_old_state, v_event);
		break;

	/* State DELETE */
	case UNF_RPORT_ST_DELETE:
	default:
		en_next_state = UNF_RPORT_ST_INIT;
		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT, UNF_MAJOR,
			  "[info]RPort(0x%x) hold state(0x%x)",
			  v_rport->nport_id, v_rport->rp_state);
		break;
	}

	UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT, UNF_MINOR,
		  "[info]RPort(0x%x) with oldstate(0x%x) event(0x%x) nextstate(0x%x)",
		  v_rport->nport_id, en_old_state, v_event, en_next_state);

	unf_set_rport_state(v_rport, en_next_state);
}

void unf_clean_linkdown_rport(struct unf_lport_s *v_lport)
{
	/* for L_Port's R_Port(s) */
	struct unf_disc_s *disc = NULL;
	struct list_head *node = NULL;
	struct list_head *next_node = NULL;
	struct unf_rport_s *rport = NULL;
	struct unf_lport_s *lport = NULL;
	unsigned long disc_lock_flag = 0;
	unsigned long rport_lock_flag = 0;

	UNF_CHECK_VALID(0x3058, UNF_TRUE, v_lport, return);
	disc = &v_lport->disc;

	/* for each busy R_Port */
	spin_lock_irqsave(&disc->rport_busy_pool_lock, disc_lock_flag);
	/* --->>> busy_rports */
	list_for_each_safe(node, next_node, &disc->list_busy_rports) {
		rport = list_entry(node, struct unf_rport_s, entry_rport);

		/* 1. Prevent process Repeatly: Closing */
		spin_lock_irqsave(&rport->rport_state_lock, rport_lock_flag);
		if (rport->rp_state == UNF_RPORT_ST_CLOSING) {
			spin_unlock_irqrestore(&rport->rport_state_lock,
					       rport_lock_flag);
			continue;
		}

		/* 2. Increase ref_cnt to protect R_Port */
		if (unf_rport_ref_inc(rport) != RETURN_OK) {
			spin_unlock_irqrestore(&rport->rport_state_lock,
					       rport_lock_flag);
			continue;
		}

		/* 3. Update R_Port state:
		 * Link Down Event --->>> closing state
		 */
		unf_rport_state_ma(rport, UNF_EVENT_RPORT_LINK_DOWN);

		/* 4. Put R_Port from busy to destroy list */
		list_del_init(&rport->entry_rport);
		list_add_tail(&rport->entry_rport, &disc->list_destroy_rports);

		lport = rport->lport;
		spin_unlock_irqrestore(&rport->rport_state_lock,
				       rport_lock_flag);

		/* 5. Schedule Closing work (Enqueuing workqueue) */
		unf_schedule_closing_work(lport, rport);

		/* 6. decrease R_Port ref_cnt (company with 2) */
		unf_rport_ref_dec(rport);
	}
	spin_unlock_irqrestore(&disc->rport_busy_pool_lock, disc_lock_flag);
}

void unf_rport_enter_closing(struct unf_rport_s *v_rport)
{
	/*
	 * call by
	 * 1. with RSCN processer
	 * 2. with LOGOUT processer
	 **
	 * from
	 * 1. R_Port Link Down
	 * 2. R_Port enter LOGO
	 */
	unsigned long rport_lock_flag = 0;
	unsigned int ret = UNF_RETURN_ERROR;
	struct unf_lport_s *lport = NULL;
	struct unf_disc_s *disc = NULL;

	UNF_CHECK_VALID(0x3059, UNF_TRUE, v_rport, return);

	/* 1. Increase ref_cnt to protect R_Port */
	spin_lock_irqsave(&v_rport->rport_state_lock, rport_lock_flag);
	ret = unf_rport_ref_inc(v_rport);
	if (ret != RETURN_OK) {
		spin_unlock_irqrestore(&v_rport->rport_state_lock,
				       rport_lock_flag);

		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT, UNF_WARN,
			  "[warn]RPort(0x%x_0x%p) is removing and no need process",
			  v_rport->nport_id, v_rport);

		return;
	}

	/* NOTE: R_Port state has been set(with closing) */

	lport = v_rport->lport;
	spin_unlock_irqrestore(&v_rport->rport_state_lock, rport_lock_flag);

	/* 2. Put R_Port from busy to destroy list */
	disc = &lport->disc;
	spin_lock_irqsave(&disc->rport_busy_pool_lock, rport_lock_flag);
	list_del_init(&v_rport->entry_rport);
	list_add_tail(&v_rport->entry_rport, &disc->list_destroy_rports);
	spin_unlock_irqrestore(&disc->rport_busy_pool_lock, rport_lock_flag);

	/* 3. Schedule Closing work (Enqueuing workqueue) */
	unf_schedule_closing_work(lport, v_rport);

	/* 4. dec R_Port ref_cnt */
	unf_rport_ref_dec(v_rport);
}

void unf_rport_error_recovery(struct unf_rport_s *v_rport)
{
	unsigned long delay = 0;
	unsigned long flag = 0;
	unsigned int ret = UNF_RETURN_ERROR;

	UNF_CHECK_VALID(0x3060, UNF_TRUE, v_rport, return);

	spin_lock_irqsave(&v_rport->rport_state_lock, flag);

	ret = unf_rport_ref_inc(v_rport);
	if (ret != RETURN_OK) {
		spin_unlock_irqrestore(&v_rport->rport_state_lock, flag);

		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT, UNF_WARN,
			  "[warn]RPort(0x%x_0x%p) is removing and no need process",
			  v_rport->nport_id, v_rport);
		return;
	}

	/* Check R_Port state */
	if ((v_rport->rp_state == UNF_RPORT_ST_CLOSING) ||
	    (v_rport->rp_state == UNF_RPORT_ST_DELETE)) {
		spin_unlock_irqrestore(&v_rport->rport_state_lock, flag);

		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT, UNF_MAJOR,
			  "[info]RPort(0x%x_0x%p) offline and no need process",
			  v_rport->nport_id, v_rport);

		unf_rport_ref_dec(v_rport);
		return;
	}

	/* Check repeatability with recovery work */
	if (delayed_work_pending(&v_rport->recovery_work)) {
		spin_unlock_irqrestore(&v_rport->rport_state_lock, flag);

		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT, UNF_MAJOR,
			  "[info]RPort(0x%x_0x%p) recovery work is running and no need process",
			  v_rport->nport_id, v_rport);

		unf_rport_ref_dec(v_rport);
		return;
	}

	/* NOTE: Re-login or Logout directly (recovery work) */
	if (v_rport->retries < v_rport->mas_retries) {
		v_rport->retries++;
		delay = (unsigned long)v_rport->ed_tov;

		if (queue_delayed_work(unf_work_queue,
				       &v_rport->recovery_work,
				       (unsigned long)msecs_to_jiffies(
						(unsigned int)delay))) {
			/* Inc ref_cnt: corresponding to this work timer */
			(void)unf_rport_ref_inc(v_rport);
		}
		spin_unlock_irqrestore(&v_rport->rport_state_lock, flag);
	} else {
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT, UNF_WARN,
			  "[warn]RPort(0x%x_0x%p) state(0x%x) retry login failed",
			  v_rport->nport_id, v_rport, v_rport->rp_state);

		/* Update R_Port state: LOGO event --->>> ST_LOGO */
		unf_rport_state_ma(v_rport, UNF_EVENT_RPORT_LOGO);
		spin_unlock_irqrestore(&v_rport->rport_state_lock, flag);

		/* Enter LOGO processer */
		unf_rport_enter_logo(v_rport->lport, v_rport);
	}

	unf_rport_ref_dec(v_rport);
}

static unsigned int unf_rport_reuse_only(struct unf_rport_s *v_rport)
{
	unsigned long flag = 0;
	unsigned int ret = UNF_RETURN_ERROR;

	UNF_CHECK_VALID(0x3061, UNF_TRUE,
			v_rport, return UNF_RETURN_ERROR);

	spin_lock_irqsave(&v_rport->rport_state_lock, flag);
	ret = unf_rport_ref_inc(v_rport);
	if (ret != RETURN_OK) {
		spin_unlock_irqrestore(&v_rport->rport_state_lock, flag);

		/* R_Port with delete state */
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT, UNF_WARN,
			  "[warn]RPort(0x%x_0x%p) is removing and no need process",
			  v_rport->nport_id, v_rport);

		return UNF_RETURN_ERROR;
	}

	/* R_Port State check: delete */
	if ((v_rport->rp_state == UNF_RPORT_ST_DELETE) ||
	    (v_rport->rp_state == UNF_RPORT_ST_CLOSING)) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT, UNF_WARN,
			  "[warn]RPort(0x%x_0x%p) state(0x%x) is delete or closing no need process",
			  v_rport->nport_id, v_rport, v_rport->rp_state);

		ret = UNF_RETURN_ERROR;
	}
	spin_unlock_irqrestore(&v_rport->rport_state_lock, flag);

	unf_rport_ref_dec(v_rport);

	return ret;
}

static unsigned int unf_rport_reuse_recover(struct unf_rport_s *v_rport)
{
	unsigned long flags = 0;
	unsigned int ret = UNF_RETURN_ERROR;

	UNF_CHECK_VALID(0x3062, UNF_TRUE,
			v_rport, return UNF_RETURN_ERROR);

	spin_lock_irqsave(&v_rport->rport_state_lock, flags);
	ret = unf_rport_ref_inc(v_rport);
	if (ret != RETURN_OK) {
		spin_unlock_irqrestore(&v_rport->rport_state_lock, flags);

		/* R_Port with delete state */
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT, UNF_WARN,
			  "[warn]RPort(0x%x_0x%p) is removing and no need process",
			  v_rport->nport_id, v_rport);

		return UNF_RETURN_ERROR;
	}

	/* R_Port state check: delete */
	if ((v_rport->rp_state == UNF_RPORT_ST_DELETE) ||
	    (v_rport->rp_state == UNF_RPORT_ST_CLOSING)) {
		ret = UNF_RETURN_ERROR;
	}

	/* Update R_Port state: recovery --->>> ready */
	unf_rport_state_ma(v_rport, UNF_EVENT_RPORT_RECOVERY);
	spin_unlock_irqrestore(&v_rport->rport_state_lock, flags);

	unf_rport_ref_dec(v_rport);

	return ret;
}

static unsigned int unf_rport_reuse_init(struct unf_rport_s *v_rport)
{
	unsigned long flage = 0;
	unsigned int ret = UNF_RETURN_ERROR;

	UNF_CHECK_VALID(0x3063, UNF_TRUE,
			v_rport, return UNF_RETURN_ERROR);

	spin_lock_irqsave(&v_rport->rport_state_lock, flage);
	ret = unf_rport_ref_inc(v_rport);
	if (ret != RETURN_OK) {
		spin_unlock_irqrestore(&v_rport->rport_state_lock, flage);

		/* R_Port with delete state */
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT, UNF_WARN,
			  "[warn]RPort(0x%x_0x%p) is removing and no need process",
			  v_rport->nport_id, v_rport);

		return UNF_RETURN_ERROR;
	}

	UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT, UNF_INFO,
		  "[info]RPort(0x%x)'s state is 0x%x with use_init flag",
		  v_rport->nport_id, v_rport->rp_state);

	/* R_Port State check: delete */
	if ((v_rport->rp_state == UNF_RPORT_ST_DELETE) ||
	    (v_rport->rp_state == UNF_RPORT_ST_CLOSING)) {
		ret = UNF_RETURN_ERROR;
	} else {
		/* Update R_Port state: re-enter Init state */
		unf_set_rport_state(v_rport, UNF_RPORT_ST_INIT);
	}
	spin_unlock_irqrestore(&v_rport->rport_state_lock, flage);

	unf_rport_ref_dec(v_rport);

	return ret;
}

struct unf_rport_s *unf_get_rport_by_nport_id(struct unf_lport_s *v_lport,
					      unsigned int nport_id)
{
	struct unf_lport_s *lport = NULL;
	struct unf_disc_s *disc = NULL;
	struct unf_rport_s *rport = NULL;
	struct list_head *node = NULL;
	struct list_head *next_node = NULL;
	unsigned long flag = 0;
	struct unf_rport_s *find_rport = NULL;

	UNF_CHECK_VALID(0x3048, UNF_TRUE, v_lport, return NULL);
	lport = (struct unf_lport_s *)v_lport;
	disc = &lport->disc;

	/* for each r_port from rport_busy_list: compare N_Port_ID */
	spin_lock_irqsave(&disc->rport_busy_pool_lock, flag);
	list_for_each_safe(node, next_node, &disc->list_busy_rports) {
		rport = list_entry(node, struct unf_rport_s, entry_rport);
		if (rport && rport->nport_id == nport_id) {
			find_rport = rport;
			break;
		}
	}
	spin_unlock_irqrestore(&disc->rport_busy_pool_lock, flag);

	return find_rport;
}

struct unf_rport_s *unf_get_safe_rport(struct unf_lport_s *v_lport,
				       struct unf_rport_s *v_rport,
				       enum unf_rport_reuse_flag_e v_reuse_flag,
				       unsigned int v_nport_id)
{
	/*
	 * New add or plug
	 *
	 *  retry_flogi          --->>> reuse_only
	 *  name_server_register --->>> reuse_only
	 *  SNS_plogi            --->>> reuse_only
	 *  enter_flogi          --->>> reuse_only
	 *  logout               --->>> reuse_only
	 *  flogi_handler        --->>> reuse_only
	 *  plogi_handler        --->>> reuse_only
	 *  adisc_handler        --->>> reuse_recovery
	 *  logout_handler       --->>> reuse_init
	 *  prlo_handler         --->>> reuse_init
	 *  login_with_loop      --->>> reuse_only
	 *  gffid_callback       --->>> reuse_only
	 *  delay_plogi          --->>> reuse_only
	 *  gffid_rjt            --->>> reuse_only
	 *  gffid_rsp_unknown    --->>> reuse_only
	 *  gpnid_acc            --->>> reuse_init
	 *  fdisc_callback       --->>> reuse_only
	 *  flogi_acc            --->>> reuse_only
	 *  plogi_acc            --->>> reuse_only
	 *  logo_callback        --->>> reuse_init
	 *  rffid_callback       --->>> reuse_only
	 */
#define UNF_AVOID_LINK_FLASH_TIME 3000

	struct unf_rport_s *rport = v_rport;
	unsigned int ret = UNF_RETURN_ERROR;

	UNF_CHECK_VALID(0x3075, UNF_TRUE, v_lport, return NULL);

	/* 1. Alloc New R_Port or Update R_Port Property */
	if (!rport) {
		/* If NULL, get/Alloc new node
		 * (R_Port from R_Port pool) directly
		 */
		rport = unf_rport_get_free_and_init(v_lport, UNF_PORT_TYPE_FC,
						    v_nport_id);
	} else {
		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT, UNF_INFO,
			  "[info]Port(0x%x) get exist RPort(0x%x) with state(0x%x) and reuse_flag(0x%x)",
			  v_lport->port_id, rport->nport_id,
			  rport->rp_state, v_reuse_flag);

		switch (v_reuse_flag) {
		case UNF_RPORT_REUSE_ONLY:
			ret = unf_rport_reuse_only(rport);
			if (ret != RETURN_OK) {
				/* R_Port within delete list: need get new */
				rport = unf_rport_get_free_and_init(
							v_lport,
							UNF_PORT_TYPE_FC,
							v_nport_id);
			}
			break;

		case UNF_RPORT_REUSE_INIT:
			ret = unf_rport_reuse_init(rport);
			if (ret != RETURN_OK) {
				/* R_Port within delete list: need get new */
				rport = unf_rport_get_free_and_init(
							v_lport,
							UNF_PORT_TYPE_FC,
							v_nport_id);
			}
			break;

		case UNF_RPORT_REUSE_RECOVER:
			ret = unf_rport_reuse_recover(rport);
			if (ret != RETURN_OK) {
				/* R_Port within delete list,
				 * NOTE: do nothing
				 */
				rport = NULL;
			}
			break;

		default:
			break;
		}
	}

	return rport;
}

unsigned int unf_get_port_feature(unsigned long long v_wwpn)
{
	struct unf_rport_feature_recard_s *port_fea = NULL;
	struct list_head *node = NULL;
	struct list_head *next_node = NULL;
	unsigned long flags = 0;
	struct list_head list_temp_node;

	spin_lock_irqsave(&port_fea_pool->port_fea_pool_lock, flags);
	list_for_each_safe(node, next_node, &port_fea_pool->list_busy_head) {
		port_fea = list_entry(node, struct unf_rport_feature_recard_s,
				      entry_feature);

		if (v_wwpn == port_fea->wwpn) {
			list_del(&port_fea->entry_feature);
			list_add(&port_fea->entry_feature,
				 &port_fea_pool->list_busy_head);

			spin_unlock_irqrestore(
				&port_fea_pool->port_fea_pool_lock, flags);

			return port_fea->port_feature;
		}
	}

	list_for_each_safe(node, next_node, &port_fea_pool->list_free_head) {
		port_fea = list_entry(node, struct unf_rport_feature_recard_s,
				      entry_feature);

		if (v_wwpn == port_fea->wwpn) {
			list_del(&port_fea->entry_feature);
			list_add(&port_fea->entry_feature,
				 &port_fea_pool->list_busy_head);

			spin_unlock_irqrestore(
				&port_fea_pool->port_fea_pool_lock, flags);

			return port_fea->port_feature;
		}
	}

	/* can't find wwpn */
	if (list_empty(&port_fea_pool->list_free_head)) {
		/* free is empty, transport busy to free */
		list_temp_node = port_fea_pool->list_free_head;
		port_fea_pool->list_free_head = port_fea_pool->list_busy_head;
		port_fea_pool->list_busy_head = list_temp_node;
	}

	port_fea = list_entry((&port_fea_pool->list_free_head)->prev,
			      struct unf_rport_feature_recard_s,
			      entry_feature);
	list_del(&port_fea->entry_feature);
	list_add(&port_fea->entry_feature, &port_fea_pool->list_busy_head);

	port_fea->wwpn = v_wwpn;
	port_fea->port_feature = UNF_PORT_MODE_UNKNOWN;

	spin_unlock_irqrestore(&port_fea_pool->port_fea_pool_lock, flags);
	return UNF_PORT_MODE_UNKNOWN;
}

void unf_update_port_feature(unsigned long long v_wwpn,
			     unsigned int v_port_feature)
{
	struct unf_rport_feature_recard_s *port_fea = NULL;
	struct list_head *node = NULL;
	struct list_head *next_node = NULL;
	unsigned long flags = 0;

	spin_lock_irqsave(&port_fea_pool->port_fea_pool_lock, flags);
	list_for_each_safe(node, next_node, &port_fea_pool->list_busy_head) {
		port_fea = list_entry(node,
				      struct unf_rport_feature_recard_s,
				      entry_feature);

		if (v_wwpn == port_fea->wwpn) {
			port_fea->port_feature = v_port_feature;
			list_del(&port_fea->entry_feature);
			list_add(&port_fea->entry_feature,
				 &port_fea_pool->list_busy_head);

			spin_unlock_irqrestore(
				&port_fea_pool->port_fea_pool_lock, flags);

			return;
		}
	}

	list_for_each_safe(node, next_node, &port_fea_pool->list_free_head) {
		port_fea = list_entry(node, struct unf_rport_feature_recard_s,
				      entry_feature);

		if (v_wwpn == port_fea->wwpn) {
			port_fea->port_feature = v_port_feature;
			list_del(&port_fea->entry_feature);
			list_add(&port_fea->entry_feature,
				 &port_fea_pool->list_busy_head);

			spin_unlock_irqrestore(
				&port_fea_pool->port_fea_pool_lock, flags);

			return;
		}
	}

	spin_unlock_irqrestore(&port_fea_pool->port_fea_pool_lock, flags);
}
