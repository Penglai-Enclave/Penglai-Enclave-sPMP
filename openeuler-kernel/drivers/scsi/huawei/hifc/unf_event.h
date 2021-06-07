/* SPDX-License-Identifier: GPL-2.0 */
/* Huawei Hifc PCI Express Linux driver
 * Copyright(c) 2017 Huawei Technologies Co., Ltd
 *
 */
#ifndef __UNF_EVENT_H__
#define __UNF_EVENT_H__
#include "hifc_knl_adp.h"

enum unf_poll_flag {
	UNF_POLL_CHIPERROR_FLAG = 0, /* CHIP ERROR POLL */
	UNF_POLL_ERROR_CODE,         /* CODE ERROR POLL */
	UNF_POLL_SFP_FLAG,           /* SFP POLL */
	UNF_POLL_BUTT
};

#define UNF_MAX_EVENT_NODE 256

enum unf_event_type {
	UNF_EVENT_TYPE_ALARM = 0, /* Alarm */
	UNF_EVENT_TYPE_REQUIRE,   /* Require */
	UNF_EVENT_TYPE_RECOVERY,  /* Recovery */
	UNF_EVENT_TYPE_BUTT
};

struct unf_cm_event_report {
	/* event type */
	unsigned int event;

	/* ASY flag */
	unsigned int event_asy_flag;

	/* Delay times,must be async event */
	unsigned int delay_times;

	struct list_head list_entry;

	void *lport;

	/* parameter */
	void *para_in;
	void *para_out;
	unsigned int result;

	/* recovery strategy */
	int (*pfn_unf_event_task)(void *v_argin, void *v_argout);

	/* recovery strategy */
	int (*pfn_unf_event_recovery_strategy)(void *);

	/* alarm  strategy */
	int (*pfn_unf_event_alarm_strategy)(void *);

	struct completion event_comp;
};

struct unf_event_mgr {
	spinlock_t port_event_lock;
	unsigned int free_event_count;

	struct list_head list_free_event;

	struct completion *emg_completion;

	void *pmem_add;
	struct unf_cm_event_report *(*pfn_unf_get_free_event)(void *v_lport);
	void (*pfn_unf_release_event)(void *v_lport, void *v_event_node);
	void (*pfn_unf_post_event)(void *v_lport, void *v_event_node);
};

struct unf_global_event_queue {
	void *global_event_add;
	unsigned int list_number;
	struct list_head global_eventlist;
	spinlock_t global_eventlist_lock;
};

struct unf_event_list {
	struct list_head list_head;
	spinlock_t fc_eventlist_lock;
	unsigned int list_num; /* list node number */
};

void unf_handle_event(struct unf_cm_event_report *v_event_node);
unsigned int unf_init_global_event_msg(void);
void unf_destroy_global_event_msg(void);
unsigned int unf_schedule_global_event(
		void *v_para,
		unsigned int v_event_asy_flag,
		int (*pfn_unf_event_task)(void *v_argin, void *v_argout));

struct unf_cm_event_report *unf_get_one_event_node(void *v_lport);
void unf_post_one_event_node(void *v_lport,
			     struct unf_cm_event_report *v_event);
unsigned int unf_event_center_destroy(void *v_lport);
unsigned int unf_init_event_center(void *v_lport);

extern struct task_struct *event_thread;
extern struct unf_global_event_queue global_event_queue;
extern struct unf_event_list fc_event_list;
#endif
