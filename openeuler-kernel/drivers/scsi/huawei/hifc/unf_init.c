// SPDX-License-Identifier: GPL-2.0
/* Huawei Fabric Channel Linux driver
 * Copyright(c) 2018 Huawei Technologies Co., Ltd
 *
 */

#include "unf_log.h"
#include "unf_event.h"
#include "unf_exchg.h"
#include "unf_portman.h"
#include "unf_rport.h"
#include "unf_service.h"
#include "unf_io.h"

#define RPORT_FEATURE_POOL_SIZE 4096

static struct unf_esgl_page_s *unf_cm_get_one_free_esgl_page(
					void *v_lport,
					struct unf_frame_pkg_s *v_fra_pkg);
static unsigned int unf_recv_tmf_marker_status(
					void *v_lport,
					struct unf_frame_pkg_s *v_fra_pkg);
static unsigned int unf_recv_abts_mrker_status(
					void *v_lport,
					struct unf_frame_pkg_s *v_fra_pkg);
static int unf_get_cfg_parms(char *v_section_name,
			     struct unf_cfg_item_s *v_cfg_parm,
			     unsigned int *v_cfg_value,
			     unsigned int v_item_num);


/* global variables */
unsigned int event_thread_exit;
struct task_struct *event_thread;

struct completion *fc_event_handle_thd_comp;
struct workqueue_struct *unf_work_queue;

struct unf_global_card_thread_s card_thread_mgr;
unsigned int unf_dbg_level = UNF_MAJOR;
unsigned int log_print_level = UNF_INFO;
unsigned int log_limted_times = UNF_LOGIN_ATT_PRINT_TIMES;

struct unf_cm_handle_op_s cm_low_levle_handle = {
	.pfn_unf_alloc_local_port = unf_lport_create_and_init,
	.pfn_unf_release_local_port = unf_release_local_port,
	.pfn_unf_receive_els_pkg = unf_receive_els_pkg,
	.pfn_unf_receive_gs_pkg = unf_receive_gs_pkg,
	.pfn_unf_receive_bls_pkg = unf_receive_bls_pkg,
	.pfn_unf_send_els_done = unf_send_els_done,
	.pfn_unf_receive_ini_rsponse = unf_ini_scsi_completed,
	.pfn_unf_get_cfg_parms = unf_get_cfg_parms,
	.pfn_unf_receive_marker_status = unf_recv_tmf_marker_status,
	.pfn_unf_receive_abts_marker_status = unf_recv_abts_mrker_status,

	.pfn_unf_cm_get_sgl_entry = unf_ini_get_sgl_entry,
	.pfn_unf_cm_get_dif_sgl_entry = unf_ini_get_dif_sgl_entry,
	.pfn_unf_get_one_free_esgl_page = unf_cm_get_one_free_esgl_page,
	.pfn_unf_fc_port_link_event = unf_fc_port_link_event,
	.pfn_unf_ioctl_to_com_handler = unf_cmd_adm_handler,
};

static struct unf_esgl_page_s *unf_cm_get_one_free_esgl_page(
					void *v_lport,
					struct unf_frame_pkg_s *v_fra_pkg)
{
	struct unf_lport_s *lport = NULL;
	struct unf_xchg_s *xchg = NULL;

	UNF_CHECK_VALID(0x1700, 1, v_lport, return NULL);
	UNF_CHECK_VALID(0x1701, 1, v_fra_pkg, return NULL);

	lport = (struct unf_lport_s *)v_lport;
	xchg = (struct unf_xchg_s *)v_fra_pkg->xchg_contex;

	return unf_get_one_free_esgl_page(lport, xchg);  /* from esgl pool */
}

static int unf_get_cfg_parms(char *v_section_name,
			     struct unf_cfg_item_s *v_cfg_parm,
			     unsigned int *v_cfg_value,
			     unsigned int v_item_num)
{
	/* Maximum length of a configuration item value,
	 * including the end character
	 */
#define UNF_MAX_ITEM_VALUE_LEN (256)

	unsigned int *value = NULL;
	struct unf_cfg_item_s *cfg_parm = NULL;
	unsigned int i = 0;

	cfg_parm = v_cfg_parm;
	value = v_cfg_value;

	for (i = 0; i < v_item_num; i++) {
		if (!cfg_parm || !value) {
			UNF_TRACE(UNF_EVTLOG_DRIVER_ERR,
				  UNF_LOG_REG_ATT, UNF_ERR,
				  "[err]Config name or value is NULL");

			return UNF_RETURN_ERROR;
		}

		if (strcmp("End", cfg_parm->name) == 0)
			break;

		if (strcmp("fw_path", cfg_parm->name) == 0) {
			cfg_parm++;
			value += UNF_MAX_ITEM_VALUE_LEN / sizeof(unsigned int);

			continue;
		}

		*value = cfg_parm->default_value;
		cfg_parm++;
		value++;
	}

	return RETURN_OK;
}

static unsigned int unf_recv_tmf_marker_status(
					void *v_lport,
					struct unf_frame_pkg_s *v_fra_pkg)
{
	struct unf_lport_s *lport = NULL;
	struct unf_xchg_s *xchg = NULL;
	unsigned short hot_pool_tag = 0;

	UNF_CHECK_VALID(0x3543, UNF_TRUE, v_lport, return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(0x3544, UNF_TRUE, v_fra_pkg, return UNF_RETURN_ERROR);
	lport = (struct unf_lport_s *)v_lport;

	/* Find exchange which point to marker sts */
	if (!lport->xchg_mgr_temp.pfn_unf_look_up_xchg_by_tag) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_LOGIN_ATT, UNF_ERR,
			  "[err]Port(0x%x) tag function is NULL",
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

	/*
	 * NOTE: set exchange TMF state with MARKER_STS_RECEIVED
	 *
	 * About TMF state
	 * 1. STS received
	 * 2. Response received
	 * 3. Do check if necessary
	 */
	xchg->tmf_state |= MARKER_STS_RECEIVED;

	UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_IO_ATT, UNF_MAJOR,
		  "[info]Marker STS: D_ID(0x%x) S_ID(0x%x) OX_ID(0x%x) RX_ID(0x%x), EXCH: D_ID(0x%x) S_ID(0x%x) OX_ID(0x%x) RX_ID(0x%x)",
		  v_fra_pkg->frame_head.rctl_did & UNF_NPORTID_MASK,
		  v_fra_pkg->frame_head.csctl_sid & UNF_NPORTID_MASK,
		  (unsigned short)(v_fra_pkg->frame_head.oxid_rxid >> 16),
		  (unsigned short)(v_fra_pkg->frame_head.oxid_rxid),
		  xchg->did,
		  xchg->sid,
		  xchg->ox_id,
		  xchg->rx_id);

	return RETURN_OK;
}

static unsigned int unf_recv_abts_mrker_status(
					void *v_lport,
					struct unf_frame_pkg_s *v_fra_pkg)
{
	struct unf_lport_s *lport = NULL;
	struct unf_xchg_s *xchg = NULL;
	unsigned short hot_pool_tag = 0;
	unsigned long flags = 0;

	UNF_CHECK_VALID(0x3543, UNF_TRUE, v_lport, return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(0x3544, UNF_TRUE, v_fra_pkg, return UNF_RETURN_ERROR);
	lport = (struct unf_lport_s *)v_lport;

	/* Find exchange by tag */
	if (!lport->xchg_mgr_temp.pfn_unf_look_up_xchg_by_tag) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_LOGIN_ATT, UNF_ERR,
			  "[err]Port(0x%x) tag function is NULL",
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

	/*
	 * NOTE: set exchange ABTS state with MARKER_STS_RECEIVED
	 *
	 * About exchange ABTS state
	 * 1. STS received
	 * 2. Response received
	 * 3. Do check if necessary
	 *
	 * About Exchange status get from low level
	 * 1. Set: when RCVD ABTS Marker
	 * 2. Set: when RCVD ABTS Req Done
	 * 3. value: set value with pkg->status
	 */
	spin_lock_irqsave(&xchg->xchg_state_lock, flags);
	xchg->ucode_abts_state = v_fra_pkg->status;
	xchg->abts_state |= MARKER_STS_RECEIVED;

	UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT, UNF_KEVENT,
		  "[info]Port(0x%x) wake up SEMA for Abts marker exchange(0x%p) oxid(0x%x 0x%x) status(0x%x)",
		  lport->port_id, xchg, xchg->ox_id, xchg->hot_pool_tag,
		  v_fra_pkg->abts_maker_status);

	/*
	 * NOTE: Second time for ABTS marker received, or
	 * ABTS response have been received, no need to wake up sema
	 */
	if ((xchg->io_state & INI_IO_STATE_ABORT_TIMEOUT) ||
	    (xchg->abts_state & ABTS_RESPONSE_RECEIVED)) {
		spin_unlock_irqrestore(&xchg->xchg_state_lock, flags);

		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT,
			  UNF_KEVENT,
			  "[info]Port(0x%x) no need to wake up SEMA for Abts marker ABTS_STATE(0x%x) IO_STATE(0x%x)",
			  lport->port_id, xchg->abts_state,
			  xchg->io_state);

		return RETURN_OK;
	}
	if (xchg->io_state & INI_IO_STATE_TMF_ABORT) {
		spin_unlock_irqrestore(&xchg->xchg_state_lock, flags);
		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT,
			  UNF_KEVENT,
			  "[info]Port(0x%x) receive Abts marker, exchange(%p) state(0x%x) free it",
			  lport->port_id, xchg, xchg->io_state);

		unf_cm_free_xchg(lport, xchg);
	} else {
		spin_unlock_irqrestore(&xchg->xchg_state_lock, flags);
		up(&xchg->task_sema);
	}

	return RETURN_OK;
}

unsigned int unf_get_cm_handle_op(struct unf_cm_handle_op_s *v_cm_handle)
{
	UNF_CHECK_VALID(0x1708, UNF_TRUE, v_cm_handle,
			return UNF_RETURN_ERROR);

	memcpy(v_cm_handle, &cm_low_levle_handle,
	       sizeof(struct unf_cm_handle_op_s));

	return RETURN_OK;
}

static void unf_uninit_cm_low_level_handle(void)
{
	memset(&cm_low_levle_handle, 0, sizeof(struct unf_cm_handle_op_s));
}

int unf_event_process(void *v_arg)
{
	struct list_head *node = NULL;
	struct unf_cm_event_report *event_node = NULL;
	unsigned long flags = 0;

	UNF_REFERNCE_VAR(v_arg);

	set_user_nice(current, 4);
	recalc_sigpending();

	UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_REG_ATT, UNF_INFO,
		  "[event]Enter event thread");

	complete(fc_event_handle_thd_comp);

	do {
		spin_lock_irqsave(&fc_event_list.fc_eventlist_lock, flags);
		if (list_empty(&fc_event_list.list_head) == UNF_TRUE) {
			spin_unlock_irqrestore(&fc_event_list.fc_eventlist_lock,
					       flags);
			set_current_state(TASK_INTERRUPTIBLE);
			schedule_timeout((long)msecs_to_jiffies(1000));
		} else {
			node = (&fc_event_list.list_head)->next;
			list_del_init(node);
			fc_event_list.list_num--;
			event_node = list_entry(node,
						struct unf_cm_event_report,
						list_entry);
			spin_unlock_irqrestore(&fc_event_list.fc_eventlist_lock,
					       flags);

			/* Process event node */
			unf_handle_event(event_node);
		}
	} while (!event_thread_exit);

	complete_and_exit(fc_event_handle_thd_comp, 0);

	UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_EVENT, UNF_MAJOR,
		  "[event]Event thread exit");

	return RETURN_OK;
}

static unsigned int unf_creat_event_center(void)
{
	struct completion fc_event_completion =
		COMPLETION_INITIALIZER(fc_event_completion);

	struct completion *p_fc_event_completion = &fc_event_completion;

	INIT_LIST_HEAD(&fc_event_list.list_head);
	fc_event_list.list_num = 0;
	spin_lock_init(&fc_event_list.fc_eventlist_lock);
	fc_event_handle_thd_comp = p_fc_event_completion;

	event_thread = kthread_run(unf_event_process, NULL, "hifc_event");
	if (IS_ERR(event_thread)) {
		complete_and_exit(fc_event_handle_thd_comp, 0);
		fc_event_handle_thd_comp = NULL;

		UNF_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_REG_ATT, UNF_ERR,
			  "[err]Create event thread failed(0x%p)",
			  event_thread);

		return UNF_RETURN_ERROR;
	}
	wait_for_completion(fc_event_handle_thd_comp);
	return RETURN_OK;
}

static void unf_cm_event_thread_exit(void)
{
	struct completion fc_event_completion =
		COMPLETION_INITIALIZER(fc_event_completion);

	struct completion *p_fc_event_completion = &fc_event_completion;

	fc_event_handle_thd_comp = p_fc_event_completion;
	event_thread_exit = 1;
	wake_up_process(event_thread);
	wait_for_completion(fc_event_handle_thd_comp);

	fc_event_handle_thd_comp = NULL;
}

static void unf_cm_cread_card_mgr_list(void)
{
	/* So far, do not care */
	INIT_LIST_HEAD(&card_thread_mgr.list_card_list_head);

	spin_lock_init(&card_thread_mgr.global_card_list_lock);

	card_thread_mgr.card_sum = 0;
}

static int unf_port_feature_pool_init(void)
{
	unsigned int i = 0;
	unsigned int rport_fea_pool_size = 0;
	struct unf_rport_feature_recard_s *rport_fea_recard = NULL;
	unsigned long flags = 0;

	rport_fea_pool_size = sizeof(struct unf_rport_feature_pool_s);
	port_fea_pool = vmalloc(rport_fea_pool_size);
	if (!port_fea_pool) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_REG_ATT, UNF_ERR,
			  "[err]cannot allocate rport feature pool");

		return UNF_RETURN_ERROR;
	}
	memset(port_fea_pool, 0, rport_fea_pool_size);
	spin_lock_init(&port_fea_pool->port_fea_pool_lock);
	INIT_LIST_HEAD(&port_fea_pool->list_busy_head);
	INIT_LIST_HEAD(&port_fea_pool->list_free_head);

	port_fea_pool->p_port_feature_pool_addr =
		vmalloc((size_t)(RPORT_FEATURE_POOL_SIZE *
			sizeof(struct unf_rport_feature_recard_s)));
	if (!port_fea_pool->p_port_feature_pool_addr) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_REG_ATT, UNF_ERR,
			  "[err]cannot allocate rport feature pool address");

		vfree(port_fea_pool);
		port_fea_pool = NULL;

		return UNF_RETURN_ERROR;
	}

	memset(port_fea_pool->p_port_feature_pool_addr, 0,
	       sizeof(struct unf_rport_feature_recard_s) *
	       RPORT_FEATURE_POOL_SIZE);
	rport_fea_recard =
		(struct unf_rport_feature_recard_s *)
		port_fea_pool->p_port_feature_pool_addr;

	spin_lock_irqsave(&port_fea_pool->port_fea_pool_lock, flags);
	for (i = 0; i < RPORT_FEATURE_POOL_SIZE; i++) {
		list_add_tail(&rport_fea_recard->entry_feature,
			      &port_fea_pool->list_free_head);
		rport_fea_recard++;
	}
	spin_unlock_irqrestore(&port_fea_pool->port_fea_pool_lock, flags);

	return RETURN_OK;
}

void unf_free_port_feature_pool(void)
{
	if (port_fea_pool->p_port_feature_pool_addr) {
		vfree(port_fea_pool->p_port_feature_pool_addr);
		port_fea_pool->p_port_feature_pool_addr = NULL;
	}
	vfree(port_fea_pool);
	port_fea_pool = NULL;
}

int unf_common_init(void)
{
	int ret = RETURN_OK;

	unf_dbg_level = UNF_MAJOR;
	log_print_level = UNF_KEVENT;

	UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_REG_ATT, UNF_KEVENT,
		  "UNF Driver Version:%s.", UNF_FC_VERSION);
	UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_REG_ATT, UNF_KEVENT,
		  "UNF Compile Time: %s", __TIME_STR__);

	ret = unf_port_feature_pool_init();
	if (ret != RETURN_OK) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_REG_ATT, UNF_ERR,
			  "[err]Port Feature Pool init failed");

		return ret;
	}

	/* 1. Init Transport */
	ret = (int)unf_register_ini_transport();
	if (ret != RETURN_OK) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_REG_ATT, UNF_ERR,
			  "[err]INI interface init failed");
		unf_free_port_feature_pool();

		return ret;
	}

	/* 2. Init L_Port MG: Y */
	unf_port_mgmt_init();

	/* 3. Init card MG list: N */
	unf_cm_cread_card_mgr_list();

	/* 4. Init global event resource: N */
	ret = (int)unf_init_global_event_msg();
	if (ret != RETURN_OK) {
		unf_unregister_ini_transport();
		unf_free_port_feature_pool();

		UNF_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_REG_ATT, UNF_ERR,
			  "[err]Create global event center failed");

		return ret;
	}

	/* 5. Create event center(one thread per pf): Y */
	ret = (int)unf_creat_event_center();
	if (ret != RETURN_OK) {
		unf_destroy_global_event_msg();
		unf_unregister_ini_transport();
		unf_free_port_feature_pool();

		fc_event_handle_thd_comp = NULL;
		UNF_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_REG_ATT, UNF_ERR,
			  "[err]Create event center (thread) failed");

		return ret;
	}

	/* 6. Create work queue: Y */
	unf_work_queue = create_workqueue("unf_wq");
	if (!unf_work_queue) {
		/* event thread exist */
		unf_cm_event_thread_exit();
		unf_destroy_global_event_msg();

		fc_event_handle_thd_comp = NULL;
		unf_unregister_ini_transport();
		unf_free_port_feature_pool();

		UNF_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_REG_ATT, UNF_ERR,
			  "[err]Create work queue failed");

		return UNF_RETURN_ERROR;
	}

	UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_REG_ATT, UNF_MAJOR,
		  "[info]Init common layer succeed");

	return ret;
}

static void unf_destroy_dirty_port(void)
{
	unsigned int v_ditry_port_num = 0;

	unf_show_dirty_port(UNF_FALSE, &v_ditry_port_num);

	UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_REG_ATT, UNF_MAJOR,
		  "[info]Sys has %d dirty L_Port(s)", v_ditry_port_num);
}

void unf_common_exit(void)
{
	unf_free_port_feature_pool();

	unf_destroy_dirty_port();

	flush_workqueue(unf_work_queue);
	destroy_workqueue(unf_work_queue);
	unf_work_queue = NULL;

	unf_cm_event_thread_exit();

	unf_destroy_global_event_msg();

	unf_uninit_cm_low_level_handle();

	unf_port_mgmt_deinit();

	unf_unregister_ini_transport();

	UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_REG_ATT, UNF_KEVENT,
		  "[info]HIFC module remove succeed");
}
