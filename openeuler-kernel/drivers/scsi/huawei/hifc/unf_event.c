// SPDX-License-Identifier: GPL-2.0
/* Huawei Hifc PCI Express Linux driver
 * Copyright(c) 2017 Huawei Technologies Co., Ltd
 *
 */

#include "unf_log.h"
#include "unf_common.h"
#include "unf_event.h"
#include "unf_lport.h"

struct unf_event_list fc_event_list;
struct unf_global_event_queue global_event_queue;

/* Max global event node */
#define UNF_MAX_GLOBAL_ENENT_NODE 24

unsigned int unf_init_event_msg(struct unf_lport_s *v_lport)
{
	struct unf_event_mgr *event_mgr = NULL;
	struct unf_cm_event_report *event_node = NULL;
	unsigned int i;
	unsigned long flags = 0;

	UNF_CHECK_VALID(0x770, UNF_TRUE, v_lport, return UNF_RETURN_ERROR);
	event_mgr = &v_lport->event_mgr;

	/* Get and Initial Event Node resource */
	event_mgr->pmem_add =
	vmalloc((size_t)event_mgr->free_event_count *
		sizeof(struct unf_cm_event_report));
	if (!event_mgr->pmem_add) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_REG_ATT, UNF_WARN,
			  "[warn]Port(0x%x) allocate event manager failed",
			  v_lport->port_id);

		return UNF_RETURN_ERROR;
	}
	memset(event_mgr->pmem_add, 0,
	       ((size_t)event_mgr->free_event_count *
	       sizeof(struct unf_cm_event_report)));

	event_node = (struct unf_cm_event_report *)(event_mgr->pmem_add);

	spin_lock_irqsave(&event_mgr->port_event_lock, flags);
	for (i = 0; i < event_mgr->free_event_count; i++) {
		INIT_LIST_HEAD(&event_node->list_entry);
		list_add_tail(&event_node->list_entry,
			      &event_mgr->list_free_event);
		event_node++;
	}
	spin_unlock_irqrestore(&event_mgr->port_event_lock, flags);

	return RETURN_OK;
}

static void unf_del_eventcenter(struct unf_lport_s *v_lport)
{
	struct unf_event_mgr *event_mgr = NULL;

	UNF_CHECK_VALID(0x771, UNF_TRUE, v_lport, return);

	event_mgr = &v_lport->event_mgr;
	event_mgr->pfn_unf_get_free_event = NULL;
	event_mgr->pfn_unf_release_event = NULL;
	event_mgr->pfn_unf_post_event = NULL;
}

void unf_init_event_node(struct unf_cm_event_report *v_event_node)
{
	UNF_CHECK_VALID(0x776, UNF_TRUE, v_event_node, return);

	v_event_node->event = UNF_EVENT_TYPE_REQUIRE;
	v_event_node->event_asy_flag = UNF_EVENT_ASYN;
	v_event_node->delay_times = 0;
	v_event_node->para_in = NULL;
	v_event_node->para_out = NULL;
	v_event_node->result = 0;
	v_event_node->lport = NULL;
	v_event_node->pfn_unf_event_task = NULL;
	v_event_node->pfn_unf_event_recovery_strategy = NULL;
	v_event_node->pfn_unf_event_alarm_strategy = NULL;
}

struct unf_cm_event_report *unf_get_free_event_node(void *v_lport)
{
	struct unf_event_mgr *event_mgr = NULL;
	struct unf_cm_event_report *event_node = NULL;
	struct list_head *list_node = NULL;
	struct unf_lport_s *root_lport = NULL;
	unsigned long flags = 0;

	UNF_CHECK_VALID(0x777, UNF_TRUE, v_lport, return NULL);
	root_lport = (struct unf_lport_s *)v_lport;
	root_lport = root_lport->root_lport;

	if (unlikely(atomic_read(&root_lport->port_no_operater_flag) ==
				 UNF_LPORT_NOP))
		return NULL;

	/* Get EventMgr from Lport */
	event_mgr = &root_lport->event_mgr;

	/* Get free node free pool */
	spin_lock_irqsave(&event_mgr->port_event_lock, flags);
	if (list_empty(&event_mgr->list_free_event)) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_REG_ATT, UNF_WARN,
			  "[warn]Port(0x%x) have no event node anymore",
			  root_lport->port_id);

		spin_unlock_irqrestore(&event_mgr->port_event_lock, flags);
		return NULL;
	}

	list_node = (&event_mgr->list_free_event)->next;
	list_del(list_node);
	event_mgr->free_event_count--;
	event_node = list_entry(list_node, struct unf_cm_event_report,
				list_entry);

	/* Initial event node */
	unf_init_event_node(event_node);
	spin_unlock_irqrestore(&event_mgr->port_event_lock, flags);

	return event_node;
}

void unf_check_event_mgr_status(struct unf_event_mgr *v_event_mgr)
{
	unsigned long flag = 0;

	UNF_CHECK_VALID(0x773, UNF_TRUE, v_event_mgr, return);

	spin_lock_irqsave(&v_event_mgr->port_event_lock, flag);
	if ((v_event_mgr->emg_completion) &&
	    (v_event_mgr->free_event_count == UNF_MAX_EVENT_NODE)) {
		complete(v_event_mgr->emg_completion);
	}
	spin_unlock_irqrestore(&v_event_mgr->port_event_lock, flag);
}

void unf_release_event(void *v_lport, void *v_event_node)
{
	struct unf_event_mgr *event_mgr = NULL;
	struct unf_lport_s *root_lport = NULL;
	struct unf_cm_event_report *event_node = NULL;
	unsigned long flags = 0;

	UNF_CHECK_VALID(0x778, UNF_TRUE, v_lport, return);
	UNF_CHECK_VALID(0x779, UNF_TRUE, v_event_node, return);

	event_node = (struct unf_cm_event_report *)v_event_node;
	root_lport = (struct unf_lport_s *)v_lport;
	root_lport = root_lport->root_lport;
	event_mgr = &root_lport->event_mgr;

	spin_lock_irqsave(&event_mgr->port_event_lock, flags);
	event_mgr->free_event_count++;
	unf_init_event_node(event_node);
	list_add_tail(&event_node->list_entry, &event_mgr->list_free_event);
	spin_unlock_irqrestore(&event_mgr->port_event_lock, flags);

	unf_check_event_mgr_status(event_mgr);
}

void unf_post_event(void *v_lport, void *v_event_node)
{
	struct unf_cm_event_report *event_node = NULL;
	struct unf_chip_manage_info_s *card_thread_info = NULL;
	struct unf_lport_s *root_lport = NULL;
	unsigned long flags = 0;

	UNF_CHECK_VALID(0x780, UNF_TRUE, v_event_node, return);
	event_node = (struct unf_cm_event_report *)v_event_node;
	UNF_REFERNCE_VAR(v_lport);

	/* If null, post to global event center */
	if (!v_lport) {
		spin_lock_irqsave(&fc_event_list.fc_eventlist_lock, flags);
		fc_event_list.list_num++;
		list_add_tail(&event_node->list_entry,
			      &fc_event_list.list_head);
		spin_unlock_irqrestore(&fc_event_list.fc_eventlist_lock,
				       flags);

		wake_up_process(event_thread);
	} else {
		root_lport = (struct unf_lport_s *)v_lport;
		root_lport = root_lport->root_lport;
		card_thread_info = root_lport->chip_info;

		/* Post to global event center */
		if (!card_thread_info) {
			UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_EVENT,
				  UNF_WARN,
				  "[warn]Port(0x%x) has strange event with type(0x%x)",
				  root_lport->nport_id, event_node->event);

			spin_lock_irqsave(&fc_event_list.fc_eventlist_lock,
					  flags);
			fc_event_list.list_num++;
			list_add_tail(&event_node->list_entry,
				      &fc_event_list.list_head);
			spin_unlock_irqrestore(
				&fc_event_list.fc_eventlist_lock,
				flags);

			wake_up_process(event_thread);
		} else {
			spin_lock_irqsave(
				&card_thread_info->chip_event_list_lock,
				flags);
			card_thread_info->list_num++;
			list_add_tail(&event_node->list_entry,
				      &card_thread_info->list_head);
			spin_unlock_irqrestore(
				&card_thread_info->chip_event_list_lock,
				flags);

			wake_up_process(card_thread_info->data_thread);
		}
	}
}

unsigned int unf_init_event_center(void *v_lport)
{
	struct unf_event_mgr *event_mgr = NULL;
	unsigned int ret = RETURN_OK;
	struct unf_lport_s *lport = NULL;

	UNF_CHECK_VALID(0x772, UNF_TRUE, v_lport, return UNF_RETURN_ERROR);
	lport = (struct unf_lport_s *)v_lport;

	/* Initial Disc manager */
	event_mgr = &lport->event_mgr;
	event_mgr->free_event_count = UNF_MAX_EVENT_NODE;
	event_mgr->pfn_unf_get_free_event = unf_get_free_event_node;
	event_mgr->pfn_unf_release_event = unf_release_event;
	event_mgr->pfn_unf_post_event = unf_post_event;

	INIT_LIST_HEAD(&event_mgr->list_free_event);
	spin_lock_init(&event_mgr->port_event_lock);
	event_mgr->emg_completion = NULL;

	ret = unf_init_event_msg(lport);
	return ret;
}

void unf_wait_event_mgr_complete(struct unf_event_mgr *v_event_mgr)
{
	struct unf_event_mgr *event_mgr = NULL;
	int wait = UNF_FALSE;
	unsigned long mg_flag = 0;

	struct completion fc_event_completion =
		COMPLETION_INITIALIZER(fc_event_completion);

	UNF_CHECK_VALID(0x774, UNF_TRUE, v_event_mgr, return);
	event_mgr = v_event_mgr;

	spin_lock_irqsave(&event_mgr->port_event_lock, mg_flag);
	if (event_mgr->free_event_count != UNF_MAX_EVENT_NODE) {
		event_mgr->emg_completion = &fc_event_completion;
		wait = UNF_TRUE;
	}
	spin_unlock_irqrestore(&event_mgr->port_event_lock, mg_flag);

	if (wait == UNF_TRUE)
		wait_for_completion(event_mgr->emg_completion);

	spin_lock_irqsave(&event_mgr->port_event_lock, mg_flag);
	event_mgr->emg_completion = NULL;
	spin_unlock_irqrestore(&event_mgr->port_event_lock, mg_flag);
}

unsigned int unf_event_center_destroy(void *v_lport)
{
	struct unf_event_mgr *event_mgr = NULL;
	struct list_head *list = NULL;
	struct list_head *list_tmp = NULL;
	struct unf_cm_event_report *event_node = NULL;
	unsigned int ret = RETURN_OK;
	unsigned long flag = 0;
	unsigned long list_lock_flag = 0;
	struct unf_lport_s *lport = NULL;

	UNF_CHECK_VALID(0x775, UNF_TRUE, v_lport, return UNF_RETURN_ERROR);
	lport = (struct unf_lport_s *)v_lport;
	event_mgr = &lport->event_mgr;

	spin_lock_irqsave(&fc_event_list.fc_eventlist_lock, list_lock_flag);
	if (!list_empty(&fc_event_list.list_head)) {
		list_for_each_safe(list, list_tmp, &fc_event_list.list_head) {
			event_node = list_entry(list,
						struct unf_cm_event_report,
						list_entry);
			if (lport == event_node->lport) {
				list_del_init(&event_node->list_entry);
				if (event_node->event_asy_flag ==
				    UNF_EVENT_SYN) {
					event_node->result = UNF_RETURN_ERROR;
					complete(&event_node->event_comp);
				}

				spin_lock_irqsave(&event_mgr->port_event_lock,
						  flag);
				event_mgr->free_event_count++;
				list_add_tail(&event_node->list_entry,
					      &event_mgr->list_free_event);
				spin_unlock_irqrestore(
					&event_mgr->port_event_lock, flag);
			}
		}
	}
	spin_unlock_irqrestore(&fc_event_list.fc_eventlist_lock,
			       list_lock_flag);

	UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_REG_ATT, UNF_MAJOR,
		  "[info]Port(0x%x) begin to wait event", lport->port_id);
	unf_wait_event_mgr_complete(event_mgr);
	UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_REG_ATT, UNF_MAJOR,
		  "[info]Port(0x%x) wait event process end", lport->port_id);

	unf_del_eventcenter(lport);
	vfree(event_mgr->pmem_add);
	event_mgr->pmem_add = NULL;
	lport->destroy_step = UNF_LPORT_DESTROY_STEP_3_DESTROY_EVENT_CENTER;

	return ret;
}

static void unf_procee_asyn_event(struct unf_cm_event_report *v_event_node)
{
	unsigned int ret = UNF_RETURN_ERROR;
	struct unf_lport_s *lport = (struct unf_lport_s *)v_event_node->lport;

	UNF_CHECK_VALID(0x782, UNF_TRUE, lport, return);
	if (v_event_node->pfn_unf_event_task)
		ret = (unsigned int)
		      v_event_node->pfn_unf_event_task(v_event_node->para_in,
						       v_event_node->para_out);

	if (lport->event_mgr.pfn_unf_release_event)
		lport->event_mgr.pfn_unf_release_event(lport, v_event_node);

	if (ret != RETURN_OK) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_EVENT, UNF_WARN,
			  "[warn]Port(0x%x) handle event(0x%x) failed",
			  lport->port_id, v_event_node->event);
	}

	UNF_REFERNCE_VAR(ret);
}

void unf_release_global_event(void *v_event_node)
{
	unsigned long flag = 0;
	struct unf_cm_event_report *event_node = NULL;

	UNF_CHECK_VALID(0x784, UNF_TRUE, v_event_node, return);
	event_node = (struct unf_cm_event_report *)v_event_node;
	unf_init_event_node(event_node);

	spin_lock_irqsave(&global_event_queue.global_eventlist_lock, flag);
	global_event_queue.list_number++;
	list_add_tail(&event_node->list_entry,
		      &global_event_queue.global_eventlist);
	spin_unlock_irqrestore(&global_event_queue.global_eventlist_lock,
			       flag);
}

void unf_handle_event(struct unf_cm_event_report *v_event_node)
{
	unsigned int ret = UNF_RETURN_ERROR;
	unsigned int event = 0;
	unsigned int event_asy_flag = UNF_EVENT_ASYN;

	UNF_CHECK_VALID(0x781, UNF_TRUE, v_event_node, return);
	UNF_REFERNCE_VAR(ret);
	UNF_REFERNCE_VAR(event);

	event = v_event_node->event;
	event_asy_flag = v_event_node->event_asy_flag;

	switch (event_asy_flag) {
	case UNF_EVENT_SYN: /* synchronous event node */
	case UNF_GLOBAL_EVENT_SYN:
		if (v_event_node->pfn_unf_event_task) {
			ret = (unsigned int)v_event_node->pfn_unf_event_task(
				v_event_node->para_in,
				v_event_node->para_out);
		}
		v_event_node->result = ret;
		complete(&v_event_node->event_comp);
		break;
	case UNF_EVENT_ASYN: /* asynchronous event node */
		unf_procee_asyn_event(v_event_node);
		break;
	case UNF_GLOBAL_EVENT_ASYN:
		if (v_event_node->pfn_unf_event_task) {
			ret = (unsigned int)v_event_node->pfn_unf_event_task(
				v_event_node->para_in,
				v_event_node->para_out);
		}
		unf_release_global_event(v_event_node);
		if (ret != RETURN_OK) {
			UNF_TRACE(UNF_EVTLOG_DRIVER_WARN,
				  UNF_LOG_EVENT, UNF_WARN,
				  "[warn]handle global event(0x%x) failed",
				  event);
		}
		break;
	default:
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_EVENT, UNF_WARN,
			  "[warn]Unknown event(0x%x)", event);
		break;
	}
}

unsigned int unf_init_global_event_msg(void)
{
	struct unf_cm_event_report *event_node = NULL;
	unsigned int ret = RETURN_OK;
	unsigned int i = 0;
	unsigned long flag = 0;

	INIT_LIST_HEAD(&global_event_queue.global_eventlist);
	spin_lock_init(&global_event_queue.global_eventlist_lock);
	global_event_queue.list_number = 0;

	global_event_queue.global_event_add =
		vmalloc(UNF_MAX_GLOBAL_ENENT_NODE *
			sizeof(struct unf_cm_event_report));
	if (!global_event_queue.global_event_add) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_REG_ATT, UNF_ERR,
			  "[err]Can't allocate global event queue");

		return UNF_RETURN_ERROR;
	}
	memset(global_event_queue.global_event_add, 0,
	       (sizeof(struct unf_cm_event_report) *
	       UNF_MAX_GLOBAL_ENENT_NODE));
	event_node = (struct unf_cm_event_report *)
		     (global_event_queue.global_event_add);

	spin_lock_irqsave(&global_event_queue.global_eventlist_lock, flag);
	for (i = 0; i < UNF_MAX_GLOBAL_ENENT_NODE; i++) {
		INIT_LIST_HEAD(&event_node->list_entry);
		list_add_tail(&event_node->list_entry,
			      &global_event_queue.global_eventlist);
		global_event_queue.list_number++;
		event_node++;
	}
	spin_unlock_irqrestore(&global_event_queue.global_eventlist_lock,
			       flag);

	return ret;
}

void unf_destroy_global_event_msg(void)
{
	if (global_event_queue.list_number != UNF_MAX_GLOBAL_ENENT_NODE) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_EVENT, UNF_CRITICAL,
			  "[warn]Global event release not complete with remain nodes(0x%x)",
			  global_event_queue.list_number);
	}

	vfree(global_event_queue.global_event_add);
}

unsigned int unf_schedule_global_event(
		void *v_para,
		unsigned int v_event_asy_flag,
		int (*pfn_unf_event_task)(void *v_argin, void *v_argout))
{
	struct list_head *list_node = NULL;
	struct unf_cm_event_report *event_node = NULL;
	unsigned long flag = 0;
	unsigned int ret = UNF_RETURN_ERROR;

	UNF_CHECK_VALID(0x783, UNF_TRUE, pfn_unf_event_task,
			return UNF_RETURN_ERROR);

	if ((v_event_asy_flag != UNF_GLOBAL_EVENT_ASYN)	&&
	    (v_event_asy_flag != UNF_GLOBAL_EVENT_SYN)) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_REG_ATT, UNF_WARN,
			  "[warn]Event async flag(0x%x) abnormity",
			  v_event_asy_flag);

		return UNF_RETURN_ERROR;
	}

	spin_lock_irqsave(&global_event_queue.global_eventlist_lock, flag);
	if (list_empty(&global_event_queue.global_eventlist)) {
		spin_unlock_irqrestore(
			&global_event_queue.global_eventlist_lock, flag);

		return UNF_RETURN_ERROR;
	}

	list_node = (&global_event_queue.global_eventlist)->next;
	list_del_init(list_node);
	global_event_queue.list_number--;
	event_node = list_entry(list_node, struct unf_cm_event_report,
				list_entry);
	spin_unlock_irqrestore(&global_event_queue.global_eventlist_lock,
			       flag);

	/* Initial global event */
	unf_init_event_node(event_node);
	init_completion(&event_node->event_comp);
	event_node->event_asy_flag = v_event_asy_flag;
	event_node->pfn_unf_event_task = pfn_unf_event_task;
	event_node->para_in = (void *)v_para;
	event_node->para_out = NULL;

	unf_post_event(NULL, event_node);

	if (v_event_asy_flag == UNF_GLOBAL_EVENT_SYN) {
		/* must wait for complete */
		wait_for_completion(&event_node->event_comp);
		ret = event_node->result;
		unf_release_global_event(event_node);
	} else {
		ret = RETURN_OK;
	}

	return ret;
}

struct unf_cm_event_report *unf_get_one_event_node(void *v_lport)
{
	struct unf_lport_s *lport = (struct unf_lport_s *)v_lport;

	UNF_CHECK_VALID(0x785, UNF_TRUE, v_lport, return NULL);
	UNF_CHECK_VALID(0x786, UNF_TRUE,
			lport->event_mgr.pfn_unf_get_free_event,
			return NULL);

	return lport->event_mgr.pfn_unf_get_free_event((void *)lport);
}

void unf_post_one_event_node(void *v_lport,
			     struct unf_cm_event_report *v_event)
{
	struct unf_lport_s *lport = (struct unf_lport_s *)v_lport;

	UNF_CHECK_VALID(0x787, UNF_TRUE, v_lport, return);
	UNF_CHECK_VALID(0x788, UNF_TRUE, v_event, return);

	UNF_CHECK_VALID(0x789, UNF_TRUE, lport->event_mgr.pfn_unf_post_event,
			return);
	UNF_CHECK_VALID(0x790, UNF_TRUE, v_event, return);

	lport->event_mgr.pfn_unf_post_event((void *)lport, v_event);
}
