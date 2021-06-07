// SPDX-License-Identifier: GPL-2.0
/* Huawei Hifc PCI Express Linux driver
 * Copyright(c) 2017 Huawei Technologies Co., Ltd
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 1, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 *
 */

#include "unf_log.h"
#include "unf_common.h"
#include "unf_lport.h"
#include "unf_rport.h"
#include "unf_exchg.h"
#include "unf_service.h"
#include "unf_portman.h"
#include "unf_rport.h"
#include "unf_io.h"
#include "unf_npiv.h"

/* Note:
 * The function related with resources allocation in Vport is shared with Lport,
 * and rootLport is acted as parameters in this function including :
 *    stEsglPool;
 *    event_mgr;
 *    stRportPool
 *    ExchMgr
 */

#define UNF_DELETE_VPORT_MAX_WAIT_TIME_MS 60000

unsigned int unf_init_vport_pool(struct unf_lport_s *v_lport)
{
	unsigned int ret = RETURN_OK;
	unsigned int i = 0;
	unsigned short vport_cnt = 0;
	struct unf_lport_s *vport = NULL;
	struct unf_vport_pool_s *vport_pool;
	unsigned int vport_pool_size = 0;
	unsigned long flags = 0;

	UNF_CHECK_VALID(0x1950, UNF_TRUE, v_lport, return RETURN_ERROR);

	UNF_TOU16_CHECK(vport_cnt, v_lport->low_level_func.support_max_npiv_num,
			return RETURN_ERROR);
	if (vport_cnt == 0) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_REG_ATT, UNF_WARN,
			  "[warn]Port(0x%x) do not support NPIV",
			  v_lport->port_id);

		return RETURN_OK;
	}

	vport_pool_size = sizeof(struct unf_vport_pool_s) +
			  sizeof(struct unf_lport_s *) * vport_cnt;
	v_lport->vport_pool = vmalloc(vport_pool_size);
	if (!v_lport->vport_pool) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_REG_ATT, UNF_ERR,
			  "[err]Port(0x%x) cannot allocate vport pool",
			  v_lport->port_id);

		return RETURN_ERROR;
	}
	memset(v_lport->vport_pool, 0, vport_pool_size);
	vport_pool = v_lport->vport_pool;
	vport_pool->vport_pool_count = vport_cnt;
	vport_pool->vport_pool_completion = NULL;
	spin_lock_init(&vport_pool->vport_pool_lock);
	INIT_LIST_HEAD(&vport_pool->list_vport_pool);

	vport_pool->vport_pool_addr = vmalloc(
			(size_t)(vport_cnt * sizeof(struct unf_lport_s)));
	if (!vport_pool->vport_pool_addr) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_REG_ATT, UNF_ERR,
			  "[err]Port(0x%x) cannot allocate vport pool address",
			  v_lport->port_id);
		vfree(v_lport->vport_pool);
		v_lport->vport_pool = NULL;

		return RETURN_ERROR;
	}

	memset(vport_pool->vport_pool_addr, 0, vport_cnt *
	       sizeof(struct unf_lport_s));
	vport = (struct unf_lport_s *)vport_pool->vport_pool_addr;

	spin_lock_irqsave(&vport_pool->vport_pool_lock, flags);
	for (i = 0; i < vport_cnt; i++) {
		list_add_tail(&vport->entry_vport,
			      &vport_pool->list_vport_pool);
		vport++;
	}

	vport_pool->slab_next_index = 0;
	vport_pool->slab_total_sum = vport_cnt;
	spin_unlock_irqrestore(&vport_pool->vport_pool_lock, flags);

	return ret;
}

void unf_free_vport_pool(struct unf_lport_s *v_lport)
{
	struct unf_vport_pool_s *vport_pool = NULL;
	int wait = UNF_FALSE;
	unsigned long flag = 0;
	unsigned int remain = 0;
	struct completion vport_pool_completion =
			COMPLETION_INITIALIZER(vport_pool_completion);

	UNF_CHECK_VALID(0x1951, UNF_TRUE, v_lport, return);
	UNF_CHECK_VALID(0x1952, UNF_TRUE, v_lport->vport_pool, return);
	vport_pool = v_lport->vport_pool;

	spin_lock_irqsave(&vport_pool->vport_pool_lock, flag);

	if (vport_pool->slab_total_sum != vport_pool->vport_pool_count) {
		vport_pool->vport_pool_completion = &vport_pool_completion;
		remain = vport_pool->slab_total_sum -
			 vport_pool->vport_pool_count;
		wait = UNF_TRUE;
	}
	spin_unlock_irqrestore(&vport_pool->vport_pool_lock, flag);

	if (wait == UNF_TRUE) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_REG_ATT, UNF_MAJOR,
			  "[info]Port(0x%x) begin to wait for vport pool completion(%ld) remain(%d)",
			  v_lport->port_id, jiffies, remain);

		wait_for_completion(vport_pool->vport_pool_completion);
		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_REG_ATT, UNF_MAJOR,
			  "[info]Port(0x%x) wait for vport pool completion end(%ld)",
			  v_lport->port_id, jiffies);
		spin_lock_irqsave(&vport_pool->vport_pool_lock, flag);
		vport_pool->vport_pool_completion = NULL;
		spin_unlock_irqrestore(&vport_pool->vport_pool_lock, flag);
	}

	if (v_lport->vport_pool->vport_pool_addr) {
		vfree(v_lport->vport_pool->vport_pool_addr);
		v_lport->vport_pool->vport_pool_addr = NULL;
	}
	vfree(v_lport->vport_pool);
	v_lport->vport_pool = NULL;

	UNF_REFERNCE_VAR(remain);
}

static inline struct unf_lport_s *unf_get_vport_by_slab_index(
					struct unf_vport_pool_s *v_vport_pool,
					unsigned short v_slab_index)
{
	UNF_CHECK_VALID(0x1953, UNF_TRUE, v_vport_pool, return NULL);

	return v_vport_pool->vport_slab[v_slab_index];
}

static inline void unf_vport_pool_slab_set(
				struct unf_vport_pool_s *v_vport_pool,
				unsigned short v_slab_index,
				struct unf_lport_s *v_vport)
{
	UNF_CHECK_VALID(0x1954, UNF_TRUE, v_vport_pool, return);

	v_vport_pool->vport_slab[v_slab_index] = v_vport;
}

unsigned int unf_alloc_vp_index(struct unf_vport_pool_s *v_vport_pool,
				struct unf_lport_s *v_vport,
				unsigned short v_vpid)
{
	unsigned short slab_index = 0;
	unsigned long flags = 0;

	UNF_CHECK_VALID(0x1955, UNF_TRUE, v_vport_pool, return RETURN_ERROR);
	UNF_CHECK_VALID(0x1956, UNF_TRUE, v_vport, return RETURN_ERROR);

	spin_lock_irqsave(&v_vport_pool->vport_pool_lock, flags);
	if (v_vpid == 0) {
		slab_index = v_vport_pool->slab_next_index;
		while (unf_get_vport_by_slab_index(v_vport_pool, slab_index)) {
			slab_index = (slab_index + 1) %
				     v_vport_pool->slab_total_sum;

			if (slab_index == v_vport_pool->slab_next_index) {
				spin_unlock_irqrestore(
					&v_vport_pool->vport_pool_lock, flags);

				UNF_TRACE(UNF_EVTLOG_DRIVER_WARN,
					  UNF_LOG_REG_ATT, UNF_WARN,
					  "[warn]VPort pool has no slab ");

				return RETURN_ERROR;
			}
		}
	} else {
		slab_index = v_vpid - 1;
		if (unf_get_vport_by_slab_index(v_vport_pool, slab_index)) {
			spin_unlock_irqrestore(&v_vport_pool->vport_pool_lock,
					       flags);

			UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_REG_ATT,
				  UNF_WARN,
				  "[warn]VPort Index(0x%x) is occupy", v_vpid);

			return RETURN_ERROR;
		}
	}

	unf_vport_pool_slab_set(v_vport_pool, slab_index, v_vport);

	v_vport_pool->slab_next_index = (slab_index + 1) %
					v_vport_pool->slab_total_sum;

	spin_unlock_irqrestore(&v_vport_pool->vport_pool_lock, flags);

	spin_lock_irqsave(&v_vport->lport_state_lock, flags);
	v_vport->vp_index = slab_index + 1; /* VpIndex=SlabIndex+1 */
	spin_unlock_irqrestore(&v_vport->lport_state_lock, flags);

	return RETURN_OK;
}

void unf_free_vp_index(struct unf_vport_pool_s *v_vport_pool,
		       struct unf_lport_s *v_vport)
{
	unsigned long flags = 0;

	UNF_CHECK_VALID(0x1957, UNF_TRUE, v_vport_pool, return);
	UNF_CHECK_VALID(0x1958, UNF_TRUE, v_vport, return);

	if ((v_vport->vp_index == 0) ||
	    (v_vport->vp_index > v_vport_pool->slab_total_sum)) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_IO_ATT, UNF_MAJOR,
			  "Input vpoot index(0x%x) is beyond the normal range, min(0x1), max(0x%x).",
			  v_vport->vp_index, v_vport_pool->slab_total_sum);
		return;
	}

	spin_lock_irqsave(&v_vport_pool->vport_pool_lock, flags);
	/* SlabIndex=VpIndex-1 */
	unf_vport_pool_slab_set(v_vport_pool, v_vport->vp_index - 1, NULL);
	spin_unlock_irqrestore(&v_vport_pool->vport_pool_lock, flags);

	spin_lock_irqsave(&v_vport->lport_state_lock, flags);
	v_vport->vp_index = INVALID_VALUE16;
	spin_unlock_irqrestore(&v_vport->lport_state_lock, flags);
}

struct unf_lport_s *unf_get_free_vport(struct unf_lport_s *v_lport)
{
	struct unf_lport_s *vport = NULL;
	struct list_head *list_head = NULL;
	struct unf_vport_pool_s *vport_pool;
	unsigned long flag = 0;

	UNF_CHECK_VALID(0x1959, 1, v_lport, return NULL);
	UNF_CHECK_VALID(0x1960, UNF_TRUE, v_lport->vport_pool, return NULL);

	vport_pool = v_lport->vport_pool;

	spin_lock_irqsave(&vport_pool->vport_pool_lock, flag);
	if (!list_empty(&vport_pool->list_vport_pool)) {
		list_head = (&vport_pool->list_vport_pool)->next;
		list_del(list_head);
		vport_pool->vport_pool_count--;
		list_add_tail(list_head, &v_lport->list_vports_head);
		vport = list_entry(list_head, struct unf_lport_s, entry_vport);
	} else {
		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_IO_ATT, UNF_WARN,
			  "[warn]LPort(0x%x)'s vport pool is empty",
			  v_lport->port_id);
		spin_unlock_irqrestore(&vport_pool->vport_pool_lock, flag);

		return NULL;
	}
	spin_unlock_irqrestore(&vport_pool->vport_pool_lock, flag);

	return vport;
}

void unf_vport_back_to_pool(void *v_vport)
{
	struct unf_lport_s *lport = NULL;
	struct unf_lport_s *vport = NULL;
	struct list_head *list = NULL;
	unsigned long flag = 0;

	UNF_CHECK_VALID(0x1961, UNF_TRUE, v_vport, return);
	vport = v_vport;
	lport = (struct unf_lport_s *)(vport->root_lport);
	UNF_CHECK_VALID(0x1962, UNF_TRUE, lport, return);
	UNF_CHECK_VALID(0x1963, UNF_TRUE, lport->vport_pool, return);

	unf_free_vp_index(lport->vport_pool, vport);

	spin_lock_irqsave(&lport->vport_pool->vport_pool_lock, flag);

	list = &vport->entry_vport;
	list_del(list);
	list_add_tail(list, &lport->vport_pool->list_vport_pool);
	lport->vport_pool->vport_pool_count++;

	spin_unlock_irqrestore(&lport->vport_pool->vport_pool_lock, flag);
}

void unf_init_vport_from_lport(struct unf_lport_s *v_vport,
			       struct unf_lport_s *v_lport)
{
	UNF_CHECK_VALID(0x1964, UNF_TRUE, v_vport, return);
	UNF_CHECK_VALID(0x1965, UNF_TRUE, v_lport, return);

	v_vport->port_type = v_lport->port_type;
	v_vport->fc_port = v_lport->fc_port;
	v_vport->en_act_topo = v_lport->en_act_topo;
	v_vport->root_lport = v_lport;
	v_vport->pfn_unf_qualify_rport = v_lport->pfn_unf_qualify_rport;
	v_vport->link_event_wq = v_lport->link_event_wq;
	v_vport->xchg_wq = v_lport->xchg_wq;

	memcpy(&v_vport->xchg_mgr_temp, &v_lport->xchg_mgr_temp,
	       sizeof(struct unf_cm_xchg_mgr_template_s));

	memcpy(&v_vport->event_mgr, &v_lport->event_mgr,
	       sizeof(struct unf_event_mgr));

	memset(&v_vport->lport_mgr_temp, 0,
	       sizeof(struct unf_cm_lport_template_s));

	memcpy(&v_vport->low_level_func, &v_lport->low_level_func,
	       sizeof(struct unf_low_level_function_op_s));
}

void unf_check_vport_pool_status(struct unf_lport_s *v_lport)
{
	struct unf_vport_pool_s *vport_pool = NULL;
	unsigned long flags = 0;

	UNF_CHECK_VALID(0x1968, UNF_TRUE, v_lport, return);
	vport_pool = v_lport->vport_pool;
	UNF_CHECK_VALID(0x1969, UNF_TRUE, vport_pool, return);

	spin_lock_irqsave(&vport_pool->vport_pool_lock, flags);

	if ((vport_pool->vport_pool_completion) &&
	    (vport_pool->slab_total_sum == vport_pool->vport_pool_count))
		complete(vport_pool->vport_pool_completion);

	spin_unlock_irqrestore(&vport_pool->vport_pool_lock, flags);
}

void unf_vport_fabric_logo(struct unf_lport_s *v_vport)
{
	struct unf_rport_s *rport = NULL;
	unsigned long flag = 0;

	rport = unf_get_rport_by_nport_id(v_vport, UNF_FC_FID_FLOGI);

	UNF_CHECK_VALID(0x1970, UNF_TRUE, rport, return);
	spin_lock_irqsave(&rport->rport_state_lock, flag);
	unf_rport_state_ma(rport, UNF_EVENT_RPORT_LOGO);
	spin_unlock_irqrestore(&rport->rport_state_lock, flag);

	unf_rport_enter_logo(v_vport, rport);
}

void unf_vport_deinit(void *v_vport)
{
	struct unf_lport_s *vport = NULL;

	UNF_CHECK_VALID(0x1971, UNF_TRUE, v_vport, return);
	vport = (struct unf_lport_s *)v_vport;

	unf_unregister_scsi_host(vport);

	unf_disc_mgr_destroy(vport);

	unf_release_xchg_mgr_temp(vport);

	unf_release_lport_mgr_temp(vport);

	unf_destroy_scsi_id_table(vport);

	unf_lport_release_lw_fun_op(vport);
	vport->fc_port = NULL;
	vport->vport = NULL;

	if (vport->lport_free_completion) {
		complete(vport->lport_free_completion);
	} else {
		UNF_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_REG_ATT, UNF_ERR,
			  "[err]VPort(0x%x) point(0x%p) completion free function is NULL",
			  vport->port_id, vport);
		dump_stack();
	}
}

void unf_vport_ref_dec(struct unf_lport_s *v_vport)
{
	UNF_CHECK_VALID(0x1972, UNF_TRUE, v_vport, return);

	if (atomic_dec_and_test(&v_vport->lport_ref_cnt)) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT, UNF_MAJOR,
			  "[info]VPort(0x%x) point(0x%p) reference count is 0 and freevport",
			  v_vport->port_id, v_vport);

		unf_vport_deinit(v_vport);
	}
}

unsigned int unf_vport_init(void *v_vport)
{
	struct unf_lport_s *vport = NULL;

	UNF_CHECK_VALID(0x1974, UNF_TRUE, v_vport, return RETURN_ERROR);
	vport = (struct unf_lport_s *)v_vport;

	vport->options = UNF_PORT_MODE_INI;
	vport->nport_id = 0;

	if (unf_init_scsi_id_table(vport) != RETURN_OK) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_REG_ATT, UNF_ERR,
			  "[err]Vport(0x%x) can not initialize SCSI ID table",
			  vport->port_id);

		return RETURN_ERROR;
	}

	if (unf_init_disc_mgr(vport) != RETURN_OK) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_REG_ATT, UNF_ERR,
			  "[err]Vport(0x%x) can not initialize discover manager",
			  vport->port_id);
		unf_destroy_scsi_id_table(vport);

		return RETURN_ERROR;
	}

	if (unf_register_scsi_host(vport) != RETURN_OK) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_REG_ATT, UNF_ERR,
			  "[err]Vport(0x%x) vport can not register SCSI host",
			  vport->port_id);
		unf_disc_mgr_destroy(vport);
		unf_destroy_scsi_id_table(vport);

		return RETURN_ERROR;
	}

	UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_REG_ATT, UNF_KEVENT,
		  "[event]Vport(0x%x) Create succeed with wwpn(0x%llx)",
		  vport->port_id, vport->port_name);

	return RETURN_OK;
}

void unf_vport_remove(void *v_vport)
{
	struct unf_lport_s *vport = NULL;
	struct unf_lport_s *lport = NULL;
	struct completion vport_free_completion =
			COMPLETION_INITIALIZER(vport_free_completion);

	UNF_CHECK_VALID(0x1975, UNF_TRUE, v_vport, return);
	vport = (struct unf_lport_s *)v_vport;
	lport = (struct unf_lport_s *)(vport->root_lport);
	vport->lport_free_completion = &vport_free_completion;

	unf_set_lport_removing(vport);

	unf_vport_ref_dec(vport);

	wait_for_completion(vport->lport_free_completion);
	unf_vport_back_to_pool(vport);

	unf_check_vport_pool_status(lport);
}

void *unf_lookup_vport_by_vp_index(void *v_lport, unsigned short v_vp_index)
{
	struct unf_lport_s *lport = NULL;
	struct unf_vport_pool_s *vport_pool = NULL;
	struct unf_lport_s *vport = NULL;
	unsigned long flags = 0;

	UNF_CHECK_VALID(0x1976, UNF_TRUE, v_lport, return NULL);

	lport = (struct unf_lport_s *)v_lport;

	vport_pool = lport->vport_pool;
	if (unlikely(!vport_pool)) {
		UNF_TRACE(UNF_EVTLOG_IO_WARN, UNF_LOG_IO_ATT, UNF_WARN,
			  "[warn]Port(0x%x) vport pool is NULL",
			  lport->port_id);

		return NULL;
	}

	if ((v_vp_index == 0) || (v_vp_index > vport_pool->slab_total_sum)) {
		UNF_TRACE(UNF_EVTLOG_IO_ERR, UNF_LOG_IO_ATT, UNF_ERR,
			  "[err]Port(0x%x) input vport index(0x%x) is beyond the normal range(0x1~0x%x)",
			  lport->port_id, v_vp_index,
			  vport_pool->slab_total_sum);

		return NULL;
	}

	spin_lock_irqsave(&vport_pool->vport_pool_lock, flags);
	/* SlabIndex=VpIndex-1 */
	vport = unf_get_vport_by_slab_index(vport_pool, v_vp_index - 1);
	spin_unlock_irqrestore(&vport_pool->vport_pool_lock, flags);

	return (void *)vport;
}

void *unf_lookup_vport_by_port_id(void *v_lport, unsigned int v_port_id)
{
	struct unf_lport_s *lport = NULL;
	struct unf_vport_pool_s *vport_pool = NULL;
	struct unf_lport_s *vport = NULL;
	struct list_head *node = NULL;
	struct list_head *next_node = NULL;
	unsigned long flag = 0;

	UNF_CHECK_VALID(0x1977, UNF_TRUE, v_lport, return NULL);

	lport = (struct unf_lport_s *)v_lport;
	vport_pool = lport->vport_pool;
	if (unlikely(!vport_pool)) {
		UNF_TRACE(UNF_EVTLOG_IO_WARN, UNF_LOG_IO_ATT, UNF_WARN,
			  "[warn]Port(0x%x) vport pool is NULL",
			  lport->port_id);

		return NULL;
	}

	spin_lock_irqsave(&vport_pool->vport_pool_lock, flag);
	list_for_each_safe(node, next_node, &lport->list_vports_head) {
		vport = list_entry(node, struct unf_lport_s, entry_vport);
		if (vport->port_id == v_port_id) {
			spin_unlock_irqrestore(&vport_pool->vport_pool_lock,
					       flag);
			return vport;
		}
	}

	list_for_each_safe(node, next_node, &lport->list_intergrad_vports) {
		vport = list_entry(node, struct unf_lport_s, entry_vport);
		if (vport->port_id == v_port_id) {
			spin_unlock_irqrestore(&vport_pool->vport_pool_lock,
					       flag);
			return vport;
		}
	}
	spin_unlock_irqrestore(&vport_pool->vport_pool_lock, flag);

	UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT, UNF_WARN,
		  "[warn]Port(0x%x) has no vport ID(0x%x).",
		  lport->port_id, v_port_id);
	return NULL;
}

void *unf_lookup_vport_by_did(void *v_lport, unsigned int v_did)
{
	struct unf_lport_s *lport = NULL;
	struct unf_vport_pool_s *vport_pool = NULL;
	struct unf_lport_s *vport = NULL;
	struct list_head *node = NULL;
	struct list_head *next_node = NULL;
	unsigned long flag = 0;

	UNF_CHECK_VALID(0x1978, UNF_TRUE, v_lport, return NULL);

	lport = (struct unf_lport_s *)v_lport;
	vport_pool = lport->vport_pool;
	if (unlikely(!vport_pool)) {
		UNF_TRACE(UNF_EVTLOG_IO_WARN, UNF_LOG_IO_ATT, UNF_WARN,
			  "[warn]Port(0x%x) vport pool is NULL",
			  lport->port_id);

		return NULL;
	}

	spin_lock_irqsave(&vport_pool->vport_pool_lock, flag);
	list_for_each_safe(node, next_node, &lport->list_vports_head) {
		vport = list_entry(node, struct unf_lport_s, entry_vport);
		if (vport->nport_id == v_did) {
			spin_unlock_irqrestore(&vport_pool->vport_pool_lock,
					       flag);

			return vport;
		}
	}

	list_for_each_safe(node, next_node, &lport->list_intergrad_vports) {
		vport = list_entry(node, struct unf_lport_s, entry_vport);
		if (vport->nport_id == v_did) {
			spin_unlock_irqrestore(&vport_pool->vport_pool_lock,
					       flag);

			return vport;
		}
	}
	spin_unlock_irqrestore(&vport_pool->vport_pool_lock, flag);

	UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT, UNF_WARN,
		  "[warn]Port(0x%x) has no vport Nport ID(0x%x)",
		  lport->port_id, v_did);
	return NULL;
}

void *unf_lookup_vport_by_wwpn(void *v_lport, unsigned long long v_wwpn)
{
	struct unf_lport_s *lport = NULL;
	struct unf_vport_pool_s *vport_pool = NULL;
	struct unf_lport_s *vport = NULL;
	struct list_head *node = NULL;
	struct list_head *next_node = NULL;
	unsigned long flag = 0;

	UNF_CHECK_VALID(0x1979, UNF_TRUE, v_lport, return NULL);

	lport = (struct unf_lport_s *)v_lport;
	vport_pool = lport->vport_pool;
	if (unlikely(!vport_pool)) {
		UNF_TRACE(UNF_EVTLOG_IO_WARN, UNF_LOG_IO_ATT, UNF_WARN,
			  "[warn]Port(0x%x) vport pool is NULL",
			  lport->port_id);

		return NULL;
	}

	spin_lock_irqsave(&vport_pool->vport_pool_lock, flag);
	list_for_each_safe(node, next_node, &lport->list_vports_head) {
		vport = list_entry(node, struct unf_lport_s, entry_vport);
		if (vport->port_name == v_wwpn) {
			spin_unlock_irqrestore(&vport_pool->vport_pool_lock,
					       flag);

			return vport;
		}
	}

	list_for_each_safe(node, next_node, &lport->list_intergrad_vports) {
		vport = list_entry(node, struct unf_lport_s, entry_vport);
		if (vport->port_name == v_wwpn) {
			spin_unlock_irqrestore(&vport_pool->vport_pool_lock,
					       flag);

			return vport;
		}
	}
	spin_unlock_irqrestore(&vport_pool->vport_pool_lock, flag);

	UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT, UNF_MAJOR,
		  "[info]Port(0x%x) has no vport WWPN(0x%llx)",
		  lport->port_id, v_wwpn);

	return NULL;
}

struct unf_lport_s *unf_alloc_vport(struct unf_lport_s *lport,
				    unsigned long long v_wwpn)
{
	struct unf_lport_s *vport = NULL;

	vport = unf_cm_lookup_vport_by_wwpn(lport, v_wwpn);
	if (vport) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_REG_ATT, UNF_WARN,
			  "[err]Port(0x%x) has find vport with wwpn(0x%llx), can't create again",
			  lport->port_id, v_wwpn);

		return NULL;
	}

	vport = unf_get_free_vport(lport);
	if (!vport) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_REG_ATT, UNF_WARN,
			  "[warn]Can not get free vport from pool");

		return NULL;
	}
	vport->root_lport = lport;
	vport->port_name = v_wwpn;

	unf_init_portparms(vport);
	unf_init_vport_from_lport(vport, lport);

	if (unf_alloc_vp_index(lport->vport_pool, vport, 0) != RETURN_OK) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_REG_ATT, UNF_WARN,
			  "[warn]Vport can not allocate vport index");
		unf_vport_back_to_pool(vport);

		return NULL;
	}
	vport->port_id = (((unsigned int)vport->vp_index) <<
			 PORTID_VPINDEX_SHIT) | lport->port_id;

	return vport;
}

unsigned int unf_npiv_conf(unsigned int v_port_id, unsigned long long v_wwpn)
{
#define VPORT_WWN_MASK  0xff00ffffffffffff
#define VPORT_WWN_SHIFT 48

	struct fc_vport_identifiers vid = { 0 };
	struct fc_vport *fc_port = NULL;
	struct Scsi_Host *shost = NULL;
	struct unf_lport_s *lport = NULL;
	struct unf_lport_s *vport = NULL;
	unsigned short vport_id = 0;

	lport = unf_find_lport_by_port_id(v_port_id);
	if (!lport) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_REG_ATT, UNF_ERR,
			  "[err]Cannot find LPort by (0x%x).", v_port_id);

		return RETURN_ERROR;
	}

	vport = unf_cm_lookup_vport_by_wwpn(lport, v_wwpn);
	if (vport) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_REG_ATT, UNF_WARN,
			  "[err]Port(0x%x) has find vport with wwpn(0x%llx), can't create again",
			  lport->port_id, v_wwpn);

		return RETURN_ERROR;
	}

	vport = unf_get_free_vport(lport);
	if (!vport) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_REG_ATT, UNF_WARN,
			  "[warn]Can not get free vport from pool");

		return RETURN_ERROR;
	}

	unf_init_portparms(vport);
	unf_init_vport_from_lport(vport, lport);

	if ((lport->port_name & VPORT_WWN_MASK) == (v_wwpn & VPORT_WWN_MASK)) {
		vport_id = (v_wwpn & ~VPORT_WWN_MASK) >> VPORT_WWN_SHIFT;
		if (vport_id == 0) {
			vport_id = (lport->port_name & ~VPORT_WWN_MASK) >>
				   VPORT_WWN_SHIFT;
		}
	}

	if (unf_alloc_vp_index(lport->vport_pool, vport, vport_id) !=
	    RETURN_OK) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_REG_ATT, UNF_WARN,
			  "[warn]Vport can not allocate vport index");
		unf_vport_back_to_pool(vport);

		return RETURN_ERROR;
	}

	vport->port_id = (((unsigned int)vport->vp_index) <<
			 PORTID_VPINDEX_SHIT) | lport->port_id;

	vid.roles = FC_PORT_ROLE_FCP_INITIATOR;
	vid.vport_type = FC_PORTTYPE_NPIV;
	vid.disable = false;
	vid.node_name = lport->node_name;

	if (v_wwpn != 0) {
		vid.port_name = v_wwpn;
	} else {
		if ((lport->port_name & ~VPORT_WWN_MASK) >> VPORT_WWN_SHIFT !=
		    vport->vp_index)
			vid.port_name =
				(lport->port_name & VPORT_WWN_MASK) |
				(((unsigned long long)vport->vp_index) <<
				VPORT_WWN_SHIFT);
		else
			vid.port_name = (lport->port_name & VPORT_WWN_MASK);
	}

	vport->port_name = vid.port_name;

	shost = lport->host_info.p_scsi_host;

	fc_port = fc_vport_create(shost, 0, &vid);
	if (!fc_port) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_REG_ATT, UNF_ERR,
			  "[err]Port(0x%x) Cannot Failed to create vport wwpn=%llx",
			  lport->port_id, vid.port_name);

		unf_vport_back_to_pool(vport);

		return RETURN_ERROR;
	}

	return RETURN_OK;
}

struct unf_lport_s *unf_create_vport(struct unf_lport_s *v_lport,
				     struct vport_config_s *v_vport_config)
{
	unsigned int ret = RETURN_OK;
	struct unf_lport_s *lport = NULL;
	struct unf_lport_s *vport = NULL;
	enum unf_act_topo_e lport_topo = UNF_ACT_TOP_UNKNOWN;
	enum unf_lport_login_state_e lport_state = UNF_LPORT_ST_ONLINE;
	unsigned long flag = 0;

	UNF_CHECK_VALID(0x1983, UNF_TRUE, v_lport, return NULL);
	UNF_CHECK_VALID(0x1983, UNF_TRUE, v_vport_config, return NULL);

	if (v_vport_config->port_mode != FC_PORT_ROLE_FCP_INITIATOR) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_REG_ATT, UNF_ERR,
			  "[err]Only support INITIATOR port mode(0x%x)",
			  v_vport_config->port_mode);

		return NULL;
	}
	lport = v_lport;

	if (lport != lport->root_lport) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_REG_ATT, UNF_ERR,
			  "[err]Port(0x%x) not root port return",
			  lport->port_id);

		return NULL;
	}

	vport = unf_cm_lookup_vport_by_wwpn(lport, v_vport_config->port_name);
	if (!vport) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_REG_ATT, UNF_WARN,
			  "[err]Port(0x%x) can not find vport with wwpn(0x%llx)",
			  lport->port_id, v_vport_config->port_name);

		return NULL;
	}

	ret = unf_vport_init(vport);
	if (ret != RETURN_OK) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_REG_ATT, UNF_WARN,
			  "[warn]VPort(0x%x) can not initialze vport",
			  vport->port_id);

		return NULL;
	}

	spin_lock_irqsave(&lport->lport_state_lock, flag);
	lport_topo = lport->en_act_topo;
	lport_state = lport->en_states;
	v_vport_config->node_name = lport->node_name;
	spin_unlock_irqrestore(&lport->lport_state_lock, flag);

	vport->port_name = v_vport_config->port_name;
	vport->node_name = v_vport_config->node_name;
	vport->nport_id = 0;

	/* only fabric topo support NPIV */
	if ((lport_topo == UNF_ACT_TOP_P2P_FABRIC) &&
	    /* after receive flogi acc */
	    (lport_state >= UNF_LPORT_ST_PLOGI_WAIT) &&
	    (lport_state <= UNF_LPORT_ST_READY)) {
		vport->link_up = lport->link_up;
		(void)unf_lport_login(vport, lport_topo);
	}

	return vport;
}

unsigned int unf_drop_vport(struct unf_lport_s *v_vport)
{
	unsigned int ret = RETURN_ERROR;
	struct fc_vport *vport = NULL;

	UNF_CHECK_VALID(0x1985, UNF_TRUE, v_vport, return RETURN_ERROR);

	vport = v_vport->vport;
	if (!vport) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_REG_ATT, UNF_ERR,
			  "[err]VPort(0x%x) find vport in scsi is NULL",
			  v_vport->port_id);

		return ret;
	}

	ret = fc_vport_terminate(vport);
	if (ret != RETURN_OK) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_REG_ATT, UNF_ERR,
			  "[err]VPort(0x%x) terminate vport(%p) in scsi failed",
			  v_vport->port_id, vport);

		return ret;
	}
	return ret;
}

unsigned int unf_delete_vport(unsigned int v_port_id, unsigned int v_vp_index)
{
	struct unf_lport_s *lport = NULL;
	unsigned short vp_index = 0;
	struct unf_lport_s *vport = NULL;

	lport = unf_find_lport_by_port_id(v_port_id);
	if (!lport) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_REG_ATT, UNF_ERR,
			  "[err]Port(0x%x) can not be found by portid",
			  v_port_id);

		return RETURN_ERROR;
	}

	if (atomic_read(&lport->port_no_operater_flag) == UNF_LPORT_NOP) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_REG_ATT, UNF_MAJOR,
			  "[info]Port(0x%x) is in NOP, destroy all vports function will be called",
			  lport->port_id);

		return RETURN_OK;
	}

	UNF_TOU16_CHECK(vp_index, v_vp_index, return RETURN_ERROR);
	vport = unf_cm_lookup_vport_by_vp_index(lport, vp_index);
	if (!vport) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_REG_ATT, UNF_WARN,
			  "[warn]Can not lookup VPort by VPort index(0x%x)",
			  vp_index);

		return RETURN_ERROR;
	}

	return unf_drop_vport(vport);
}

void unf_vport_abort_all_sfs_exch(struct unf_lport_s *vport)
{
	struct unf_xchg_hot_pool_s *hot_pool = NULL;
	struct list_head *xchg_node = NULL;
	struct list_head *next_xchg_node = NULL;
	struct unf_xchg_s *exch = NULL;
	unsigned long pool_lock_flags = 0;
	unsigned long exch_lock_flags = 0;
	unsigned int i;

	UNF_CHECK_VALID(0x1985, UNF_TRUE, vport, return);
	for (i = 0; i < UNF_EXCHG_MGR_NUM; i++) {
		hot_pool = unf_get_hot_pool_by_lport(
				(struct unf_lport_s *)(vport->root_lport), i);
		if (unlikely(!hot_pool)) {
			UNF_TRACE(UNF_EVTLOG_IO_WARN, UNF_LOG_IO_ATT, UNF_WARN,
				  "[warn]Port(0x%x) hot pool is NULL",
				  ((struct unf_lport_s *)
				  (vport->root_lport))->port_id);
			continue;
		}

		spin_lock_irqsave(&hot_pool->xchg_hot_pool_lock,
				  pool_lock_flags);
		list_for_each_safe(xchg_node, next_xchg_node,
				   &hot_pool->sfs_busylist) {
			exch = list_entry(xchg_node, struct unf_xchg_s,
					  list_xchg_entry);
			spin_lock_irqsave(&exch->xchg_state_lock,
					  exch_lock_flags);
			if (vport == exch->lport &&
			    (atomic_read(&exch->ref_cnt) > 0)) {
				exch->io_state |= TGT_IO_STATE_ABORT;
				spin_unlock_irqrestore(&exch->xchg_state_lock,
						       exch_lock_flags);
				unf_disc_ctrl_size_inc(vport, exch->cmnd_code);
				/* Transfer exch to destroy chain */
				list_del(xchg_node);
				list_add_tail(xchg_node,
					      &hot_pool->list_destroy_xchg);

			} else {
				spin_unlock_irqrestore(&exch->xchg_state_lock,
						       exch_lock_flags);
			}
		}
		spin_unlock_irqrestore(&hot_pool->xchg_hot_pool_lock,
				       pool_lock_flags);
	}
}

void unf_vport_abort_ini_io_exch(struct unf_lport_s *vport)
{
	struct unf_xchg_hot_pool_s *hot_pool = NULL;
	struct list_head *xchg_node = NULL;
	struct list_head *next_xchg_node = NULL;
	struct unf_xchg_s *exch = NULL;
	unsigned long pool_lock_flags = 0;
	unsigned long exch_lock_flags = 0;
	unsigned int i;

	UNF_CHECK_VALID(0x1986, UNF_TRUE, vport, return);
	for (i = 0; i < UNF_EXCHG_MGR_NUM; i++) {
		hot_pool = unf_get_hot_pool_by_lport(
				(struct unf_lport_s *)(vport->root_lport), i);
		if (unlikely(!hot_pool)) {
			UNF_TRACE(UNF_EVTLOG_IO_WARN, UNF_LOG_IO_ATT, UNF_WARN,
				  "[warn]Port(0x%x) MgrIdex %d hot pool is NULL",
				  ((struct unf_lport_s *)
				  (vport->root_lport))->port_id, i);
			continue;
		}

		spin_lock_irqsave(&hot_pool->xchg_hot_pool_lock,
				  pool_lock_flags);
		list_for_each_safe(xchg_node, next_xchg_node,
				   &hot_pool->ini_busylist) {
			exch = list_entry(xchg_node, struct unf_xchg_s,
					  list_xchg_entry);

			if (vport == exch->lport &&
			    atomic_read(&exch->ref_cnt) > 0) {
				/* Transfer exch to destroy chain */
				list_del(xchg_node);
				list_add_tail(xchg_node,
					      &hot_pool->list_destroy_xchg);

				spin_lock_irqsave(&exch->xchg_state_lock,
						  exch_lock_flags);
				exch->io_state |= INI_IO_STATE_DRABORT;
				spin_unlock_irqrestore(&exch->xchg_state_lock,
						       exch_lock_flags);
			}
		}

		spin_unlock_irqrestore(&hot_pool->xchg_hot_pool_lock,
				       pool_lock_flags);
	}
}

void unf_vport_abort_all_exch(struct unf_lport_s *vport)
{
	UNF_CHECK_VALID(0x1988, UNF_TRUE, vport, return);

	unf_vport_abort_all_sfs_exch(vport);

	unf_vport_abort_ini_io_exch(vport);
}

unsigned int unf_vport_wait_all_exch_removed(struct unf_lport_s *vport)
{
	struct unf_xchg_hot_pool_s *hot_pool = NULL;
	struct list_head *xchg_node = NULL;
	struct list_head *next_xchg_node = NULL;
	struct unf_xchg_s *exch = NULL;
	unsigned int vport_uses = 0;
	unsigned long flags = 0;
	unsigned long long cur_jif = jiffies;
	unsigned int i = 0;

	UNF_CHECK_VALID(0x1989, UNF_TRUE, vport, return RETURN_ERROR);

	while (1) {
		vport_uses = 0;

		for (i = 0; i < UNF_EXCHG_MGR_NUM; i++) {
			hot_pool = unf_get_hot_pool_by_lport(
					(struct unf_lport_s *)
					(vport->root_lport), i);
			if (unlikely(!hot_pool)) {
				UNF_TRACE(UNF_EVTLOG_IO_WARN,
					  UNF_LOG_IO_ATT, UNF_WARN,
					  "[warn]Port(0x%x) hot Pool is NULL",
					  ((struct unf_lport_s *)
					  (vport->root_lport))->port_id);

				continue;
			}

			spin_lock_irqsave(&hot_pool->xchg_hot_pool_lock, flags);
			list_for_each_safe(xchg_node, next_xchg_node,
					   &hot_pool->list_destroy_xchg) {
				exch = list_entry(xchg_node, struct unf_xchg_s,
						  list_xchg_entry);

				if (vport != exch->lport)
					continue;

				vport_uses++;

				if (jiffies - cur_jif >=
				    msecs_to_jiffies(UNF_DELETE_VPORT_MAX_WAIT_TIME_MS)) {
					UNF_TRACE(UNF_EVTLOG_DRIVER_ERR,
						  UNF_LOG_NORMAL, UNF_ERR,
						  "[error]VPort(0x%x) Abort Exch(0x%p) Type(0x%x) OxRxid(0x%x 0x%x), sid did(0x%x 0x%x) SeqId(0x%x) IOState(0x%x) Ref(0x%x)",
						  vport->port_id, exch,
						  (unsigned int)exch->xchg_type,
						  (unsigned int)exch->ox_id,
						  (unsigned int)exch->rx_id,
						  (unsigned int)exch->sid,
						  (unsigned int)exch->did,
						  (unsigned int)exch->seq_id,
						  (unsigned int)exch->io_state,
						  atomic_read(&exch->ref_cnt));
				}
			}
			spin_unlock_irqrestore(&hot_pool->xchg_hot_pool_lock,
					       flags);
		}

		if (vport_uses == 0) {
			UNF_TRACE(UNF_EVTLOG_IO_INFO, UNF_LOG_IO_ATT, UNF_MAJOR,
				  "[info]VPort(0x%x) has removed all exchanges it used",
				  vport->port_id);
			break;
		}

		if (jiffies - cur_jif >= msecs_to_jiffies(UNF_DELETE_VPORT_MAX_WAIT_TIME_MS))
			return RETURN_ERROR;

		msleep(1000);
	}

	return RETURN_OK;
}

unsigned int unf_vport_wait_rports_removed(struct unf_lport_s *vport)
{
	struct unf_disc_s *disc = NULL;
	struct list_head *node = NULL;
	struct list_head *next_node = NULL;
	unsigned int vport_uses = 0;
	unsigned long flags = 0;
	unsigned long long cur_jif = jiffies;
	struct unf_rport_s *rport = NULL;

	UNF_CHECK_VALID(0x1990, UNF_TRUE, vport, return RETURN_ERROR);
	disc = &vport->disc;

	while (1) {
		vport_uses = 0;
		spin_lock_irqsave(&disc->rport_busy_pool_lock, flags);
		list_for_each_safe(node, next_node, &disc->list_delete_rports) {
			rport = list_entry(node, struct unf_rport_s,
					   entry_rport);
			UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_NORMAL,
				  UNF_MAJOR,
				  "[info]Vport(0x%x) Rport(0x%x) point(%p) is in Delete",
				  vport->port_id, rport->nport_id, rport);
			vport_uses++;
		}
		list_for_each_safe(node, next_node,
				   &disc->list_destroy_rports) {
			rport = list_entry(node, struct unf_rport_s,
					   entry_rport);
			UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_NORMAL,
				  UNF_MAJOR,
				  "[info]Vport(0x%x) Rport(0x%x) point(%p) is in Destroy",
				  vport->port_id, rport->nport_id, rport);
			vport_uses++;
		}
		spin_unlock_irqrestore(&disc->rport_busy_pool_lock, flags);

		if (vport_uses == 0) {
			UNF_TRACE(UNF_EVTLOG_IO_INFO, UNF_LOG_IO_ATT, UNF_MAJOR,
				  "[info]VPort(0x%x) has removed all RPorts it used",
				  vport->port_id);
			break;
		}
		UNF_TRACE(UNF_EVTLOG_IO_WARN, UNF_LOG_IO_ATT, UNF_WARN,
			  "[warn]Vport(0x%x) has %d RPorts not removed wait timeout(30s)",
			  vport->port_id, vport_uses);

		if (jiffies - cur_jif >=
			msecs_to_jiffies(UNF_DELETE_VPORT_MAX_WAIT_TIME_MS))
			return RETURN_ERROR;

		msleep(5000);
	}

	UNF_REFERNCE_VAR(rport);

	return RETURN_OK;
}

unsigned int unf_destroy_one_vport(struct unf_lport_s *vport)
{
	unsigned int ret = RETURN_ERROR;
	struct unf_lport_s *root_port = NULL;

	UNF_CHECK_VALID(0x1992, UNF_TRUE, vport, return RETURN_ERROR);

	root_port = (struct unf_lport_s *)vport->root_lport;

	unf_vport_fabric_logo(vport);

	/* 1 set NOP */
	atomic_set(&vport->port_no_operater_flag, UNF_LPORT_NOP);
	vport->b_port_removing = UNF_TRUE;

	/* 2 report linkdown to scsi and delele rpot */
	unf_link_down_one_vport(vport);

	/* 3 set abort for exchange */
	unf_vport_abort_all_exch(vport);

	/* 4 wait exch return freepool */
	if (!root_port->b_port_dir_exchange) {
		ret = unf_vport_wait_all_exch_removed(vport);
		if (ret != RETURN_OK) {
			if ((root_port->b_port_removing) != UNF_TRUE) {
				vport->b_port_removing = UNF_FALSE;
				UNF_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_NORMAL,
					  UNF_ERR,
					  "[err]VPort(0x%x) can not wait Exchange return freepool",
					  vport->port_id);

				return RETURN_ERROR;
			}
			UNF_TRACE(UNF_EVTLOG_DRIVER_WARN,
				  UNF_LOG_NORMAL, UNF_WARN,
				  "[warn]Port(0x%x) is removing, there is dirty exchange, continue",
				  root_port->port_id);

			root_port->b_port_dir_exchange = UNF_TRUE;
		}
	}

	/* wait rport return rportpool */
	ret = unf_vport_wait_rports_removed(vport);
	if (ret != RETURN_OK) {
		vport->b_port_removing = UNF_FALSE;
		UNF_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_NORMAL, UNF_ERR,
			  "[err]VPort(0x%x) can not wait Rport return freepool",
			  vport->port_id);

		return RETURN_ERROR;
	}

	unf_cm_vport_remove(vport);

	return RETURN_OK;
}

void unf_link_down_one_vport(struct unf_lport_s *v_vport)
{
	unsigned long flag = 0;
	struct unf_lport_s *root_lport = NULL;

	UNF_TRACE(UNF_EVTLOG_IO_INFO, UNF_LOG_IO_ATT, UNF_KEVENT,
		  "[info]VPort(0x%x) linkdown", v_vport->port_id);

	spin_lock_irqsave(&v_vport->lport_state_lock, flag);
	v_vport->link_up = UNF_PORT_LINK_DOWN;
	v_vport->nport_id = 0; /* set nportid 0 before send fdisc again */
	unf_lport_stat_ma(v_vport, UNF_EVENT_LPORT_LINK_DOWN);
	spin_unlock_irqrestore(&v_vport->lport_state_lock, flag);

	root_lport = (struct unf_lport_s *)v_vport->root_lport;

	unf_flush_disc_event(&root_lport->disc, v_vport);

	unf_clean_linkdown_rport(v_vport);
}

void unf_linkdown_all_vports(void *v_lport)
{
	struct unf_lport_s *lport = NULL;
	struct unf_vport_pool_s *vport_pool = NULL;
	struct unf_lport_s *vport = NULL;
	struct list_head *node = NULL;
	struct list_head *next_node = NULL;
	unsigned long flags = 0;

	UNF_CHECK_VALID(0x1993, UNF_TRUE, v_lport, return);

	lport = (struct unf_lport_s *)v_lport;
	vport_pool = lport->vport_pool;
	if (unlikely(!vport_pool)) {
		UNF_TRACE(UNF_EVTLOG_IO_ERR, UNF_LOG_IO_ATT, UNF_ERR,
			  "[err]Port(0x%x) VPort pool is NULL",
			  lport->port_id);

		return;
	}

	/* Transfer to the transition chain */
	spin_lock_irqsave(&vport_pool->vport_pool_lock, flags);
	list_for_each_safe(node, next_node, &lport->list_vports_head) {
		vport = list_entry(node, struct unf_lport_s, entry_vport);
		list_del_init(&vport->entry_vport);
		list_add_tail(&vport->entry_vport,
			      &lport->list_intergrad_vports);
		(void)unf_lport_refinc(vport);
	}
	spin_unlock_irqrestore(&vport_pool->vport_pool_lock, flags);

	spin_lock_irqsave(&vport_pool->vport_pool_lock, flags);
	while (!list_empty(&lport->list_intergrad_vports)) {
		node = (&lport->list_intergrad_vports)->next;
		vport = list_entry(node, struct unf_lport_s, entry_vport);

		list_del_init(&vport->entry_vport);
		list_add_tail(&vport->entry_vport, &lport->list_vports_head);
		spin_unlock_irqrestore(&vport_pool->vport_pool_lock, flags);

		unf_link_down_one_vport(vport);

		unf_vport_ref_dec(vport);

		spin_lock_irqsave(&vport_pool->vport_pool_lock, flags);
	}
	spin_unlock_irqrestore(&vport_pool->vport_pool_lock, flags);
}

int unf_process_vports_linkup(void *v_arg_in, void *v_arg_out)
{
	struct unf_vport_pool_s *vport_pool = NULL;
	struct unf_lport_s *lport = NULL;
	struct unf_lport_s *vport = NULL;
	struct list_head *node = NULL;
	struct list_head *next_node = NULL;
	unsigned long flags = 0;
	int ret = RETURN_OK;

	UNF_REFERNCE_VAR(v_arg_out);
	UNF_CHECK_VALID(0x1994, UNF_TRUE, v_arg_in, return RETURN_ERROR);

	lport = (struct unf_lport_s *)v_arg_in;

	if (atomic_read(&lport->port_no_operater_flag) == UNF_LPORT_NOP) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT, UNF_WARN,
			  "[warn]Port(0x%x) is NOP don't continue",
			  lport->port_id);

		return RETURN_OK;
	}

	if (lport->link_up != UNF_PORT_LINK_UP) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT, UNF_WARN,
			  "[warn]Port(0x%x) is not linkup don't continue.",
			  lport->port_id);

		return RETURN_OK;
	}

	vport_pool = lport->vport_pool;
	if (unlikely(!vport_pool)) {
		UNF_TRACE(UNF_EVTLOG_IO_ERR, UNF_LOG_IO_ATT, UNF_ERR,
			  "[err]Port(0x%x) VPort pool is NULL.",
			  lport->port_id);

		return RETURN_OK;
	}

	/* Transfer to the transition chain */
	spin_lock_irqsave(&vport_pool->vport_pool_lock, flags);
	list_for_each_safe(node, next_node, &lport->list_vports_head) {
		vport = list_entry(node, struct unf_lport_s, entry_vport);
		list_del_init(&vport->entry_vport);
		list_add_tail(&vport->entry_vport,
			      &lport->list_intergrad_vports);
		(void)unf_lport_refinc(vport);
	}
	spin_unlock_irqrestore(&vport_pool->vport_pool_lock, flags);

	spin_lock_irqsave(&vport_pool->vport_pool_lock, flags);
	while (!list_empty(&lport->list_intergrad_vports)) {
		node = (&lport->list_intergrad_vports)->next;
		vport = list_entry(node, struct unf_lport_s, entry_vport);

		list_del_init(&vport->entry_vport);
		list_add_tail(&vport->entry_vport, &lport->list_vports_head);
		spin_unlock_irqrestore(&vport_pool->vport_pool_lock, flags);

		if (atomic_read(&vport->port_no_operater_flag) ==
		    UNF_LPORT_NOP) {
			unf_vport_ref_dec(vport);
			spin_lock_irqsave(&vport_pool->vport_pool_lock, flags);
			continue;
		}

		if ((lport->link_up == UNF_PORT_LINK_UP) &&
		    (lport->en_act_topo == UNF_ACT_TOP_P2P_FABRIC)) {
			UNF_TRACE(UNF_EVTLOG_IO_INFO, UNF_LOG_IO_ATT, UNF_MAJOR,
				  "[info]Vport(0x%x) begin login",
				  vport->port_id);

			vport->link_up = UNF_PORT_LINK_UP;
			(void)unf_lport_login(vport, lport->en_act_topo);

			msleep(100);
		} else {
			unf_link_down_one_vport(vport);

			UNF_TRACE(UNF_EVTLOG_IO_WARN, UNF_LOG_IO_ATT, UNF_WARN,
				  "[warn]Vport(0x%x) login failed because root port linkdown",
				  vport->port_id);
		}

		unf_vport_ref_dec(vport);
		spin_lock_irqsave(&vport_pool->vport_pool_lock, flags);
	}
	spin_unlock_irqrestore(&vport_pool->vport_pool_lock, flags);

	return ret;
}

void unf_linkup_all_vports(struct unf_lport_s *v_lport)
{
	struct unf_cm_event_report *event = NULL;

	UNF_CHECK_VALID(0x1996, UNF_TRUE, v_lport, return);

	if (unlikely((!v_lport->event_mgr.pfn_unf_get_free_event) ||
		     (!v_lport->event_mgr.pfn_unf_post_event) ||
		     (!v_lport->event_mgr.pfn_unf_release_event))) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_LOGIN_ATT, UNF_ERR,
			  "[err]Port(0x%x) Event fun is NULL",
			  v_lport->port_id);
		return;
	}

	event = v_lport->event_mgr.pfn_unf_get_free_event((void *)v_lport);
	UNF_CHECK_VALID(0x1997, UNF_TRUE, event, return);

	event->lport = v_lport;
	event->event_asy_flag = UNF_EVENT_ASYN;
	event->pfn_unf_event_task = unf_process_vports_linkup;
	event->para_in = (void *)v_lport;

	v_lport->event_mgr.pfn_unf_post_event(v_lport, event);
}

void unf_destroy_all_vports(struct unf_lport_s *v_lport)
{
	struct unf_vport_pool_s *vport_pool = NULL;
	struct unf_lport_s *lport = NULL;
	struct unf_lport_s *vport = NULL;
	struct list_head *node = NULL;
	struct list_head *next_node = NULL;
	unsigned long flags = 0;

	lport = v_lport;
	UNF_CHECK_VALID(0x1998, UNF_TRUE, lport, return);

	vport_pool = lport->vport_pool;
	if (unlikely(!vport_pool)) {
		UNF_TRACE(UNF_EVTLOG_IO_ERR, UNF_LOG_IO_ATT, UNF_ERR,
			  "[err]Lport(0x%x) VPort pool is NULL",
			  lport->port_id);

		return;
	}

	/* Transfer to the transition chain */
	spin_lock_irqsave(&vport_pool->vport_pool_lock, flags);
	list_for_each_safe(node, next_node, &lport->list_vports_head) {
		vport = list_entry(node, struct unf_lport_s, entry_vport);
		list_del_init(&vport->entry_vport);
		list_add_tail(&vport->entry_vport, &lport->list_destroy_vports);
	}

	list_for_each_safe(node, next_node, &lport->list_intergrad_vports) {
		vport = list_entry(node, struct unf_lport_s, entry_vport);
		list_del_init(&vport->entry_vport);
		list_add_tail(&vport->entry_vport,
			      &lport->list_destroy_vports);
		atomic_dec(&vport->lport_ref_cnt);
	}
	spin_unlock_irqrestore(&vport_pool->vport_pool_lock, flags);

	spin_lock_irqsave(&vport_pool->vport_pool_lock, flags);
	while (!list_empty(&lport->list_destroy_vports)) {
		node = (&lport->list_destroy_vports)->next;
		vport = list_entry(node, struct unf_lport_s, entry_vport);

		list_del_init(&vport->entry_vport);
		list_add_tail(&vport->entry_vport, &lport->list_vports_head);
		spin_unlock_irqrestore(&vport_pool->vport_pool_lock, flags);

		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_REG_ATT, UNF_MAJOR,
			  "[info]VPort(0x%x) Destroy begin",
			  vport->port_id);
		unf_drop_vport(vport);
		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_REG_ATT, UNF_KEVENT,
			  "[info]VPort(0x%x) Destroy end",
			  vport->port_id);

		spin_lock_irqsave(&vport_pool->vport_pool_lock, flags);
	}
	spin_unlock_irqrestore(&vport_pool->vport_pool_lock, flags);
}
