// SPDX-License-Identifier: GPL-2.0
/* Huawei Hifc PCI Express Linux driver
 * Copyright(c) 2017 Huawei Technologies Co., Ltd
 *
 */

#include "unf_log.h"
#include "unf_common.h"
#include "unf_event.h"
#include "unf_lport.h"
#include "unf_exchg.h"
#include "unf_portman.h"
#include "unf_rport.h"
#include "unf_io.h"
#include "unf_service.h"
#include "unf_rport.h"
#include "unf_npiv.h"
#include "hifc_portmng.h"

#define UNF_LOOP_STOP_NEED_WAIT    0
#define UNF_LOOP_STOP_NO_NEED_WAIT 1

#define UNF_MAX_SAVE_ENTRY_NUM                                 60
#define UNF_CHECK_CONFIG_SPEED_BY_SFSSPEED(sfs_speed, cfg_speed) \
	((sfs_speed) < (cfg_speed) || (sfs_speed) == UNF_PORT_SFP_SPEED_ERR)
#define UNF_LPORT_CHIP_ERROR(lport)                         \
	((lport)->pcie_error_cnt.pcie_error_count[UNF_PCIE_FATALERRORDETECTED])

struct unf_global_lport_s global_lport_mgr;

static unsigned int unf_port_link_up(struct unf_lport_s *v_lport,
				     void *v_in_put);
static unsigned int unf_port_link_down(struct unf_lport_s *v_lport,
				       void *v_in_put);
static unsigned int unf_port_abnormal_reset(struct unf_lport_s *v_lport,
					    void *v_in_put);
static unsigned int unf_port_reset_start(struct unf_lport_s *v_lport,
					 void *v_in_put);
static unsigned int unf_port_reset_end(struct unf_lport_s *v_lport,
				       void *v_in_put);
static unsigned int unf_port_nop(struct unf_lport_s *v_lport, void *v_in_put);
static unsigned int unf_port_clean_done(struct unf_lport_s *v_lport,
					void *v_in_put);
static unsigned int unf_port_begin_remove(struct unf_lport_s *v_lport,
					  void *v_in_put);
static unsigned int unf_port_release_rport_index(struct unf_lport_s *v_lport,
						 void *v_in_put);
static int unf_cm_port_info_get(struct unf_lport_s *v_lport,
				struct unf_hinicam_pkg *v_in_put);
static int unf_cm_port_speed_set(struct unf_lport_s *v_lport,
				 struct unf_hinicam_pkg *v_in_put);
static int unf_cm_topo_set(struct unf_lport_s *v_lport,
			   struct unf_hinicam_pkg *v_in_put);
static int unf_cm_port_set(struct unf_lport_s *v_lport,
			   struct unf_hinicam_pkg *v_in_put);
static int unf_get_port_sfp_info(struct unf_lport_s *v_lport,
				 struct unf_hinicam_pkg *v_in_put);
static int unf_cm_get_all_port_info(struct unf_lport_s *v_lport,
				    struct unf_hinicam_pkg *v_in_put);
static int unf_cm_clear_error_code_sum(struct unf_lport_s *v_lport,
				       struct unf_hinicam_pkg *v_in_put);
static int unf_cm_bbscn_set(struct unf_lport_s *v_lport,
			    struct unf_hinicam_pkg *v_in_put);
static int unf_get_io_dfx_statistics(struct unf_lport_s *v_pstLPort,
				     struct unf_hinicam_pkg *v_input);
static int unf_cm_set_vport(struct unf_lport_s *v_lport,
			    struct unf_hinicam_pkg *v_input);
static int unf_cm_link_delay_get(struct unf_lport_s *v_lport,
				 struct unf_hinicam_pkg *v_in_put);
static int unf_cm_save_data_mode(struct unf_lport_s *v_lport,
				 struct unf_hinicam_pkg *v_in_put);
static int unf_cm_set_dif(struct unf_lport_s *v_lport,
			  struct unf_hinicam_pkg *v_in_put);
static int unf_cm_select_dif_mode(struct unf_lport_s *v_lport,
				  struct unf_hinicam_pkg *v_in_put);
static int unf_cm_adm_show_xchg(struct unf_lport_s *v_lport,
				struct unf_hinicam_pkg *v_in_put);
static int unf_cm_adm_link_time_out_opt(struct unf_lport_s *v_lport,
					struct unf_hinicam_pkg *v_in_put);
static int unf_cm_adm_log_level_opt(struct unf_lport_s *v_lport,
				    struct unf_hinicam_pkg *v_in_put);

static struct unf_port_action_s lport_action[] = {
	{ UNF_PORT_LINK_UP,             unf_port_link_up },
	{ UNF_PORT_LINK_DOWN,           unf_port_link_down },
	{ UNF_PORT_RESET_START,         unf_port_reset_start },
	{ UNF_PORT_RESET_END,           unf_port_reset_end },
	{ UNF_PORT_NOP,                 unf_port_nop },
	{ UNF_PORT_CLEAN_DONE,          unf_port_clean_done },
	{ UNF_PORT_BEGIN_REMOVE,        unf_port_begin_remove },
	{ UNF_PORT_RELEASE_RPORT_INDEX, unf_port_release_rport_index },
	{ UNF_PORT_ABNORMAL_RESET,      unf_port_abnormal_reset },
};

static struct unf_hifcadm_action_s unf_hifcadm_action[] = {
	{ UNF_PORT_SET_OP,   unf_cm_port_set },
	{ UNF_TOPO_SET_OP,   unf_cm_topo_set },
	{ UNF_SPEED_SET_OP,  unf_cm_port_speed_set },
	{ UNF_INFO_GET_OP,   unf_cm_port_info_get },
	{ UNF_INFO_CLEAR_OP, unf_cm_clear_error_code_sum },
	{ UNF_SFP_INFO_OP,   unf_get_port_sfp_info },
	{ UNF_ALL_INFO_OP,   unf_cm_get_all_port_info },
	{ UNF_BBSCN,         unf_cm_bbscn_set },
	{ UNF_DFX,           unf_get_io_dfx_statistics },
	{ UNF_VPORT,         unf_cm_set_vport },
	{ UNF_LINK_DELAY,    unf_cm_link_delay_get },
	{ UNF_SAVA_DATA,     unf_cm_save_data_mode },
	{ UNF_DIF,           unf_cm_set_dif },
	{ UNF_DIF_CONFIG,    unf_cm_select_dif_mode },
	{ UNF_SHOW_XCHG,     unf_cm_adm_show_xchg },
	{ FC_LINK_TMO_OPT,   unf_cm_adm_link_time_out_opt },
	{ FC_DRV_LOG_OPT,    unf_cm_adm_log_level_opt },
};

static void unf_destroy_dirty_rport(struct unf_lport_s *v_lport,
				    int v_show_only)
{
	unsigned int dirty_rport = 0;

	UNF_REFERNCE_VAR(dirty_rport);

	/* for whole L_Port */
	if (v_lport->dirty_flag & UNF_LPORT_DIRTY_FLAG_RPORT_POOL_DIRTY) {
		dirty_rport = v_lport->rport_pool.rport_pool_count;

		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_REG_ATT, UNF_MAJOR,
			  "[info]Port(0x%x) has %u dirty RPort(s)",
			  v_lport->port_id, dirty_rport);

		/* free R_Port pool memory & bitmap */
		if (v_show_only == UNF_FALSE) {
			vfree(v_lport->rport_pool.rport_pool_add);
			v_lport->rport_pool.rport_pool_add = NULL;
			vfree(v_lport->rport_pool.pul_rpi_bitmap);
			v_lport->rport_pool.pul_rpi_bitmap = NULL;
		}
	}

	UNF_REFERNCE_VAR(dirty_rport);
}

void unf_show_dirty_port(int v_show_only, unsigned int *v_ditry_port_num)
{
	struct list_head *node = NULL;
	struct list_head *node_next = NULL;
	struct unf_lport_s *lport = NULL;
	unsigned long flags = 0;
	unsigned int port_num = 0;

	UNF_CHECK_VALID(0x2200, UNF_TRUE, NULL != v_ditry_port_num, return);

	/* for each dirty L_Port from global L_Port list */
	spin_lock_irqsave(&global_lport_mgr.global_lport_list_lock, flags);
	list_for_each_safe(node, node_next, &global_lport_mgr.list_dirty_head) {
		lport = list_entry(node, struct unf_lport_s, entry_lport);

		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_REG_ATT, UNF_MAJOR,
			  "[info]Port(0x%x) has dirty data(0x%x)",
			  lport->port_id, lport->dirty_flag);

		/* Destroy dirty L_Port's exchange(s) & R_Port(s) */
		unf_destroy_dirty_xchg(lport, v_show_only);
		unf_destroy_dirty_rport(lport, v_show_only);

		/* Delete (dirty L_Port) list entry if necessary */
		if (v_show_only == UNF_FALSE) {
			list_del_init(node);
			vfree(lport);
		}

		port_num++;
	}
	spin_unlock_irqrestore(&global_lport_mgr.global_lport_list_lock,
			       flags);

	*v_ditry_port_num = port_num;
}

int unf_send_event(unsigned int port_id,
		   unsigned int syn_flag,
		   void *argc_in,
		   void *argc_out,
		   int (*p_func)(void *argc_in, void *argc_out))
{
	struct unf_lport_s *lport = NULL;
	struct unf_cm_event_report *event = NULL;
	int ret = 0;

	lport = unf_find_lport_by_port_id(port_id);
	if (!lport) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_EQUIP_ATT, UNF_INFO,
			  "Cannot find LPort(0x%x).", port_id);

		return UNF_RETURN_ERROR;
	}

	if (unf_lport_refinc(lport) != RETURN_OK) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT, UNF_MAJOR,
			  "LPort(0x%x) is removing, no need process.",
			  lport->port_id);

		return UNF_RETURN_ERROR;
	}
	if (unlikely((!lport->event_mgr.pfn_unf_get_free_event) ||
		     (!lport->event_mgr.pfn_unf_post_event) ||
		     (!lport->event_mgr.pfn_unf_release_event))) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_EQUIP_ATT, UNF_MAJOR,
			  "Event function is NULL.");

		unf_lport_ref_dec_to_destroy(lport);

		return UNF_RETURN_ERROR;
	}

	if (lport->b_port_removing == UNF_TRUE) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT, UNF_MAJOR,
			  "LPort(0x%x) is removing, no need process.",
			  lport->port_id);

		unf_lport_ref_dec_to_destroy(lport);

		return UNF_RETURN_ERROR;
	}

	event = lport->event_mgr.pfn_unf_get_free_event((void *)lport);
	if (!event) {
		unf_lport_ref_dec_to_destroy(lport);

		return UNF_RETURN_ERROR;
	}

	init_completion(&event->event_comp);
	event->lport = lport;
	event->event_asy_flag = syn_flag;
	event->pfn_unf_event_task = p_func;
	event->para_in = argc_in;
	event->para_out = argc_out;
	lport->event_mgr.pfn_unf_post_event(lport, event);

	if (event->event_asy_flag) {
		/* You must wait for the other party to return. Otherwise,
		 *the linked list may be in disorder.
		 */
		wait_for_completion(&event->event_comp);
		ret = (int)event->result;
		lport->event_mgr.pfn_unf_release_event(lport, event);
	} else {
		ret = RETURN_OK;
	}

	unf_lport_ref_dec_to_destroy(lport);
	return ret;
}

void unf_lport_update_topo(struct unf_lport_s *v_lport,
			   enum unf_act_topo_e v_enactive_topo)
{
	unsigned long flag = 0;

	UNF_CHECK_VALID(0x2210, UNF_TRUE, NULL != v_lport, return);

	if ((v_enactive_topo > UNF_ACT_TOP_UNKNOWN) ||
	    (v_enactive_topo < UNF_ACT_TOP_PUBLIC_LOOP)) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_LOGIN_ATT, UNF_ERR,
			  "[err]Port(0x%x) set invalid topology(0x%x) with current value(0x%x)",
			  v_lport->nport_id, v_enactive_topo,
			  v_lport->en_act_topo);

		return;
	}

	spin_lock_irqsave(&v_lport->lport_state_lock, flag);
	v_lport->en_act_topo = v_enactive_topo;
	spin_unlock_irqrestore(&v_lport->lport_state_lock, flag);
}

void unf_set_lport_removing(struct unf_lport_s *v_lport)
{
	UNF_CHECK_VALID(0x2216, UNF_TRUE, (v_lport), return);

	v_lport->fc_port = NULL;
	v_lport->b_port_removing = UNF_TRUE;
	v_lport->destroy_step = UNF_LPORT_DESTROY_STEP_0_SET_REMOVING;
}

unsigned int unf_release_local_port(void *v_lport)
{
	struct unf_lport_s *lport = v_lport;
	struct completion local_port_free_completion =
		COMPLETION_INITIALIZER(local_port_free_completion);

	UNF_CHECK_VALID(0x2217, UNF_TRUE, (lport),
			return UNF_RETURN_ERROR);

	lport->lport_free_completion = &local_port_free_completion;
	unf_set_lport_removing(lport);
	unf_lport_ref_dec(lport);
	wait_for_completion(lport->lport_free_completion);
	/* for dirty case */
	if (lport->dirty_flag == 0)
		vfree(lport);

	return RETURN_OK;
}

static void unf_free_all_esgl_pages(struct unf_lport_s *v_lport)
{
	struct list_head *node = NULL;
	struct list_head *next_node = NULL;
	unsigned long flag = 0;
	unsigned int alloc_idx;

	UNF_CHECK_VALID(0x2218, UNF_TRUE, (v_lport), return);
	spin_lock_irqsave(&v_lport->esgl_pool.esgl_pool_lock, flag);
	list_for_each_safe(node, next_node,
			   &v_lport->esgl_pool.list_esgl_pool) {
		list_del(node);
	}

	spin_unlock_irqrestore(&v_lport->esgl_pool.esgl_pool_lock, flag);

	if (v_lport->esgl_pool.esgl_buf_list.buflist) {
		for (alloc_idx = 0;
		     alloc_idx < v_lport->esgl_pool.esgl_buf_list.buf_num;
		     alloc_idx++) {
			if (v_lport->esgl_pool.esgl_buf_list.buflist[alloc_idx].vaddr) {
				dma_free_coherent(&v_lport->low_level_func.dev->dev,
						  v_lport->esgl_pool.esgl_buf_list.buf_size,
						  v_lport->esgl_pool.esgl_buf_list.buflist[alloc_idx].vaddr,
						  v_lport->esgl_pool.esgl_buf_list.buflist[alloc_idx].paddr);
				v_lport->esgl_pool.esgl_buf_list.buflist[alloc_idx].vaddr = NULL;
			}
		}
		kfree(v_lport->esgl_pool.esgl_buf_list.buflist);
		v_lport->esgl_pool.esgl_buf_list.buflist = NULL;
	}
}

static unsigned int unf_init_esgl_pool(struct unf_lport_s *v_lport)
{
	struct unf_esgl_s *esgl = NULL;
	unsigned int ret = RETURN_OK;
	unsigned int index = 0;
	unsigned int buf_total_size;
	unsigned int buf_num;
	unsigned int alloc_idx;
	unsigned int cur_buf_idx = 0;
	unsigned int cur_buf_offset = 0;
	unsigned int buf_cnt_perhugebuf;

	UNF_CHECK_VALID(0x2219, UNF_TRUE, NULL != v_lport,
			return UNF_RETURN_ERROR);

	v_lport->esgl_pool.esgl_pool_count =
		v_lport->low_level_func.lport_cfg_items.max_io;
	spin_lock_init(&v_lport->esgl_pool.esgl_pool_lock);
	INIT_LIST_HEAD(&v_lport->esgl_pool.list_esgl_pool);

	v_lport->esgl_pool.esgl_pool_addr =
		vmalloc((size_t)((v_lport->esgl_pool.esgl_pool_count) *
				  sizeof(struct unf_esgl_s)));
	if (!v_lport->esgl_pool.esgl_pool_addr) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_REG_ATT, UNF_ERR,
			  "LPort(0x%x) cannot allocate ESGL Pool.",
		v_lport->port_id);

		return UNF_RETURN_ERROR;
	}
	esgl = (struct unf_esgl_s *)v_lport->esgl_pool.esgl_pool_addr;
	memset(esgl, 0, ((v_lport->esgl_pool.esgl_pool_count) *
			 sizeof(struct unf_esgl_s)));

	buf_total_size =
		(unsigned int)(PAGE_SIZE * v_lport->esgl_pool.esgl_pool_count);

	v_lport->esgl_pool.esgl_buf_list.buf_size =
		buf_total_size > BUF_LIST_PAGE_SIZE ? BUF_LIST_PAGE_SIZE :
						buf_total_size;
	buf_cnt_perhugebuf =
		v_lport->esgl_pool.esgl_buf_list.buf_size / PAGE_SIZE;
	buf_num = v_lport->esgl_pool.esgl_pool_count %
		buf_cnt_perhugebuf ? v_lport->esgl_pool.esgl_pool_count /
		buf_cnt_perhugebuf + 1 : v_lport->esgl_pool.esgl_pool_count /
		buf_cnt_perhugebuf;
	v_lport->esgl_pool.esgl_buf_list.buflist =
		(struct buff_list_s *)
		kmalloc(buf_num * sizeof(struct buff_list_s), GFP_KERNEL);
	v_lport->esgl_pool.esgl_buf_list.buf_num = buf_num;

	if (!v_lport->esgl_pool.esgl_buf_list.buflist) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_REG_ATT, UNF_WARN,
			  "[err]Allocate Esgl pool buf list failed out of memory");
		goto free_buff;
	}
	memset(v_lport->esgl_pool.esgl_buf_list.buflist, 0,
	       buf_num * sizeof(struct buff_list_s));

	for (alloc_idx = 0; alloc_idx < buf_num; alloc_idx++) {
		v_lport->esgl_pool.esgl_buf_list.buflist[alloc_idx].vaddr =
			dma_alloc_coherent(
				&v_lport->low_level_func.dev->dev,
				v_lport->esgl_pool.esgl_buf_list.buf_size,
				&v_lport->esgl_pool.esgl_buf_list.buflist[alloc_idx].paddr,
				GFP_KERNEL);
		if (!v_lport->esgl_pool.esgl_buf_list.buflist[alloc_idx].vaddr)
			goto free_buff;

		memset(v_lport->esgl_pool.esgl_buf_list.buflist[alloc_idx].vaddr,
		       0, v_lport->esgl_pool.esgl_buf_list.buf_size);
	}

	/* allocates the Esgl page, and the DMA uses the */
	for (index = 0; index < v_lport->esgl_pool.esgl_pool_count; index++) {
		if ((index != 0) && !(index % buf_cnt_perhugebuf))
			cur_buf_idx++;

		cur_buf_offset =
			(unsigned int)
			(PAGE_SIZE * (index % buf_cnt_perhugebuf));
		esgl->page.page_address =
			(unsigned long long)v_lport->esgl_pool.esgl_buf_list.buflist[cur_buf_idx].vaddr +
			cur_buf_offset;
		esgl->page.page_size = PAGE_SIZE;
		esgl->page.esgl_phyaddr =
			v_lport->esgl_pool.esgl_buf_list.buflist[cur_buf_idx].paddr +
			cur_buf_offset;
		list_add_tail(&esgl->entry_esgl,
			      &v_lport->esgl_pool.list_esgl_pool);
		esgl++;
	}

	UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_REG_ATT, UNF_INFO,
		  "[EVENT]Allocate bufnum:%u, buf_total_size:%u", buf_num,
		  buf_total_size);
	return ret;
free_buff:
	unf_free_all_esgl_pages(v_lport);
	vfree(v_lport->esgl_pool.esgl_pool_addr);

	return UNF_RETURN_ERROR;
}

static void unf_free_esgl_pool(struct unf_lport_s *v_lport)
{
	UNF_CHECK_VALID(0x2220, UNF_TRUE, (v_lport), return);

	unf_free_all_esgl_pages(v_lport);
	v_lport->esgl_pool.esgl_pool_count = 0;

	if (v_lport->esgl_pool.esgl_pool_addr) {
		vfree(v_lport->esgl_pool.esgl_pool_addr);
		v_lport->esgl_pool.esgl_pool_addr = NULL;
	}

	v_lport->destroy_step = UNF_LPORT_DESTROY_STEP_5_DESTROY_ESGL_POOL;
}

struct unf_lport_s *unf_find_lport_by_port_id(unsigned int v_port_id)
{
	struct unf_lport_s *lport = NULL;
	struct list_head *node = NULL;
	struct list_head *next_node = NULL;
	unsigned long flags = 0;
	unsigned int port_id = v_port_id & (~PORTID_VPINDEX_MASK);
	unsigned short vport_index = (v_port_id & PORTID_VPINDEX_MASK) >>
				     PORTID_VPINDEX_SHIT;

	spin_lock_irqsave(&global_lport_mgr.global_lport_list_lock, flags);

	list_for_each_safe(node, next_node,
			   &global_lport_mgr.list_lport_list_head) {
		lport = list_entry(node, struct unf_lport_s, entry_lport);
		if ((port_id == lport->port_id) &&
		    (lport->b_port_removing != UNF_TRUE)) {
			spin_unlock_irqrestore(
				&global_lport_mgr.global_lport_list_lock,
				flags);
			return unf_cm_lookup_vport_by_vp_index(lport,
							       vport_index);
		}
	}

	list_for_each_safe(node, next_node,
			   &global_lport_mgr.list_intergrad_head) {
		lport = list_entry(node, struct unf_lport_s, entry_lport);
		if ((port_id == lport->port_id) &&
		    (lport->b_port_removing != UNF_TRUE)) {
			spin_unlock_irqrestore(
				&global_lport_mgr.global_lport_list_lock,
				flags);
			return unf_cm_lookup_vport_by_vp_index(lport,
							       vport_index);
		}
	}

	spin_unlock_irqrestore(&global_lport_mgr.global_lport_list_lock, flags);

	return NULL;
}

unsigned int unf_is_vport_valid(struct unf_lport_s *v_lport,
				struct unf_lport_s *v_vport)
{
	struct unf_lport_s *lport = NULL;
	struct unf_vport_pool_s *vport_pool = NULL;
	struct unf_lport_s *vport = NULL;
	struct list_head *node = NULL;
	struct list_head *next_node = NULL;
	unsigned long flag = 0;

	UNF_CHECK_VALID(0x1977, UNF_TRUE, v_lport, return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(0x1977, UNF_TRUE, v_vport, return UNF_RETURN_ERROR);

	lport = v_lport;
	vport_pool = lport->vport_pool;
	if (unlikely(!vport_pool)) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_IO_ATT, UNF_ERR,
			  "[err]Port(0x%x) vport pool is NULL",
			  lport->port_id);

		return UNF_RETURN_ERROR;
	}

	spin_lock_irqsave(&vport_pool->vport_pool_lock, flag);
	list_for_each_safe(node, next_node, &lport->list_vports_head) {
		vport = list_entry(node, struct unf_lport_s, entry_vport);

		if (vport == v_vport && vport->b_port_removing != UNF_TRUE) {
			spin_unlock_irqrestore(&vport_pool->vport_pool_lock,
					       flag);

			return RETURN_OK;
		}
	}

	list_for_each_safe(node, next_node, &lport->list_intergrad_vports) {
		vport = list_entry(node, struct unf_lport_s, entry_vport);

		if (vport == v_vport && vport->b_port_removing != UNF_TRUE) {
			spin_unlock_irqrestore(&vport_pool->vport_pool_lock,
					       flag);

			return RETURN_OK;
		}
	}
	spin_unlock_irqrestore(&vport_pool->vport_pool_lock, flag);

	return UNF_RETURN_ERROR;
}

unsigned int unf_is_lport_valid(struct unf_lport_s *v_lport)
{
	struct unf_lport_s *lport = NULL;
	struct list_head *node = NULL;
	struct list_head *next_node = NULL;
	unsigned long flags = 0;

	spin_lock_irqsave(&global_lport_mgr.global_lport_list_lock, flags);

	list_for_each_safe(node, next_node,
			   &global_lport_mgr.list_lport_list_head) {
		lport = list_entry(node, struct unf_lport_s, entry_lport);

		if ((v_lport == lport) &&
		    (lport->b_port_removing != UNF_TRUE)) {
			spin_unlock_irqrestore(
				&global_lport_mgr.global_lport_list_lock,
				flags);
			return RETURN_OK;
		}

		if (unf_is_vport_valid(lport, v_lport) == RETURN_OK) {
			spin_unlock_irqrestore(
				&global_lport_mgr.global_lport_list_lock,
				flags);

			return RETURN_OK;
		}
	}

	list_for_each_safe(node, next_node,
			   &global_lport_mgr.list_intergrad_head) {
		lport = list_entry(node, struct unf_lport_s, entry_lport);

		if ((v_lport == lport) &&
		    (lport->b_port_removing != UNF_TRUE)) {
			spin_unlock_irqrestore(
				&global_lport_mgr.global_lport_list_lock,
				flags);
			return RETURN_OK;
		}

		if (unf_is_vport_valid(lport, v_lport) == RETURN_OK) {
			spin_unlock_irqrestore(
				&global_lport_mgr.global_lport_list_lock,
				flags);

			return RETURN_OK;
		}
	}

	list_for_each_safe(node, next_node,
			   &global_lport_mgr.list_destroy_head) {
		lport = list_entry(node, struct unf_lport_s, entry_lport);

		if ((v_lport == lport) &&
		    (lport->b_port_removing != UNF_TRUE)) {
			spin_unlock_irqrestore(
				&global_lport_mgr.global_lport_list_lock,
				flags);
			return RETURN_OK;
		}

		if (unf_is_vport_valid(lport, v_lport) == RETURN_OK) {
			spin_unlock_irqrestore(
				&global_lport_mgr.global_lport_list_lock,
				flags);

			return RETURN_OK;
		}
	}

	spin_unlock_irqrestore(&global_lport_mgr.global_lport_list_lock,
			       flags);
	return UNF_RETURN_ERROR;
}

static void unf_clean_link_down_io(struct unf_lport_s *v_lport,
				   int v_clean_flag)
{
	/* Clean L_Port/V_Port Link Down I/O: Set Abort Tag */
	UNF_CHECK_VALID(0x2225, UNF_TRUE, v_lport, return);
	UNF_CHECK_VALID(0x2685, UNF_TRUE,
			v_lport->xchg_mgr_temp.pfn_unf_xchg_abort_all_io,
			return);

	v_lport->xchg_mgr_temp.pfn_unf_xchg_abort_all_io(v_lport,
		UNF_XCHG_TYPE_INI, v_clean_flag);
	v_lport->xchg_mgr_temp.pfn_unf_xchg_abort_all_io(v_lport,
		UNF_XCHG_TYPE_SFS, v_clean_flag);
}

unsigned int unf_fc_port_link_event(void *v_lport, unsigned int v_events,
				    void *v_input)
{
	struct unf_lport_s *lport = NULL;
	unsigned int ret = UNF_RETURN_ERROR;
	unsigned int index = 0;

	if (unlikely(!v_lport))
		return UNF_RETURN_ERROR;

	lport = (struct unf_lport_s *)v_lport;

	ret = unf_lport_refinc(lport);
	if (ret != RETURN_OK) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT, UNF_MAJOR,
			  "[info]Port(0x%x) is removing and do nothing",
			  lport->port_id);
		return RETURN_OK;
	}

	/* process port event */
	while (index < (sizeof(lport_action) /
			  sizeof(struct unf_port_action_s))) {
		if (v_events == lport_action[index].action) {
			ret = lport_action[index].fn_unf_action(lport, v_input);

			unf_lport_ref_dec_to_destroy(lport);

			return ret;
		}
		index++;
	}

	UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT, UNF_WARN,
		  "[warn]Port(0x%x) receive unknown event(0x%x)",
		  lport->port_id, v_events);

	unf_lport_ref_dec_to_destroy(lport);

	return ret;
}

void unf_port_mgmt_init(void)
{
	memset(&global_lport_mgr, 0, sizeof(struct unf_global_lport_s));

	INIT_LIST_HEAD(&global_lport_mgr.list_lport_list_head);

	INIT_LIST_HEAD(&global_lport_mgr.list_intergrad_head);

	INIT_LIST_HEAD(&global_lport_mgr.list_destroy_head);

	INIT_LIST_HEAD(&global_lport_mgr.list_dirty_head);

	spin_lock_init(&global_lport_mgr.global_lport_list_lock);

	UNF_SET_NOMAL_MODE(global_lport_mgr.dft_mode);

	global_lport_mgr.b_start_work = UNF_TRUE;
}

void unf_port_mgmt_deinit(void)
{
	if (global_lport_mgr.lport_sum != 0)
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_REG_ATT, UNF_WARN,
			  "[warn]There are %u port pool memory giveaway",
			  global_lport_mgr.lport_sum);

	memset(&global_lport_mgr, 0, sizeof(struct unf_global_lport_s));

	UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_REG_ATT, UNF_MAJOR,
		  "[info]Common port manager exit succeed");
}

static void unf_port_register(struct unf_lport_s *v_lport)
{
	unsigned long flags = 0;

	UNF_CHECK_VALID(0x2230, UNF_TRUE, (v_lport), return);

	UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_REG_ATT, UNF_INFO,
		  "Register LPort(0x%p), port ID(0x%x).",
		  v_lport, v_lport->port_id);

	/* Add to the global management linked list header */
	spin_lock_irqsave(&global_lport_mgr.global_lport_list_lock, flags);
	list_add_tail(&v_lport->entry_lport,
		      &global_lport_mgr.list_lport_list_head);
	global_lport_mgr.lport_sum++;
	spin_unlock_irqrestore(&global_lport_mgr.global_lport_list_lock, flags);
}

static void unf_port_unregister(struct unf_lport_s *v_lport)
{
	unsigned long flags = 0;

	UNF_CHECK_VALID(0x2703, UNF_TRUE, (v_lport), return);

	UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_REG_ATT, UNF_INFO,
		  "Unregister LPort(0x%p), port ID(0x%x).",
		  v_lport, v_lport->port_id);

	/* Remove from the global management linked list header */
	spin_lock_irqsave(&global_lport_mgr.global_lport_list_lock, flags);
	list_del(&v_lport->entry_lport);
	global_lport_mgr.lport_sum--;
	spin_unlock_irqrestore(&global_lport_mgr.global_lport_list_lock, flags);
}

static int unf_port_switch(struct unf_lport_s *v_lport,
			   unsigned int v_switch_flag)
{
	struct unf_lport_s *lport = v_lport;
	int ret = UNF_RETURN_ERROR;
	int switch_flag = UNF_FALSE;

	UNF_CHECK_VALID(0x2261, UNF_TRUE, lport, return UNF_RETURN_ERROR);

	if (!lport->low_level_func.port_mgr_op.pfn_ll_port_config_set) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_EQUIP_ATT, UNF_WARN,
			  "[warn]Port(0x%x)'s config(switch) function is NULL",
			  lport->port_id);

		return UNF_RETURN_ERROR;
	}

	switch_flag = v_switch_flag ? UNF_TRUE : UNF_FALSE;
	ret = (int)lport->low_level_func.port_mgr_op.pfn_ll_port_config_set(
		lport->fc_port,
		UNF_PORT_CFG_SET_PORT_SWITCH, (void *)&switch_flag);
	if (ret != RETURN_OK) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_EQUIP_ATT, UNF_WARN,
			  "[warn]Port(0x%x) switch %s failed",
			  lport->port_id,
			  v_switch_flag ? "On" : "Off");

		return UNF_RETURN_ERROR;
	}

	lport->b_switch_state = (enum int_e)switch_flag;

	return RETURN_OK;
}

int unf_port_start_work(struct unf_lport_s *v_lport)
{
	unsigned long flag = 0;
	struct unf_fw_version_s fw_version = { 0 };
	unsigned int ret = UNF_RETURN_ERROR;

	UNF_CHECK_VALID(0x2231, UNF_TRUE, v_lport, return UNF_RETURN_ERROR);

	spin_lock_irqsave(&v_lport->lport_state_lock, flag);
	if (v_lport->en_start_work_state != UNF_START_WORK_STOP) {
		spin_unlock_irqrestore(&v_lport->lport_state_lock, flag);

		return RETURN_OK;
	}
	v_lport->en_start_work_state = UNF_START_WORK_COMPLETE;
	spin_unlock_irqrestore(&v_lport->lport_state_lock, flag);

	if (!v_lport->low_level_func.port_mgr_op.pfn_ll_port_diagnose) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_EQUIP_ATT, UNF_MAJOR,
			  "Port(0x%x)'s corresponding function is NULL.",
			  v_lport->port_id);

		return UNF_RETURN_ERROR;
	}

	fw_version.message_type = UNF_DEBUG_TYPE_MESSAGE;

	ret = v_lport->low_level_func.port_mgr_op.pfn_ll_port_diagnose(
		(void *)v_lport->fc_port,
		UNF_PORT_DIAG_PORT_DETAIL, &fw_version);
	if (ret != RETURN_OK)
		v_lport->fw_version[0] = '\0';
	else
		memcpy(v_lport->fw_version, fw_version.fw_version,
		       HIFC_VER_LEN);

	unf_cm_get_save_info(v_lport);
	/* switch sfp to start work */
	(void)unf_port_switch(v_lport, UNF_TRUE);

	return RETURN_OK;
}

static unsigned int unf_lport_init_lw_fun_op(
			struct unf_lport_s *v_lport,
			struct unf_low_level_function_op_s *low_level_op)
{
	UNF_CHECK_VALID(0x2235, UNF_TRUE, (v_lport), return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(0x2236, UNF_TRUE, (low_level_op),
			return UNF_RETURN_ERROR);

	v_lport->port_id = low_level_op->lport_cfg_items.port_id;
	v_lport->port_name = low_level_op->sys_port_name;
	v_lport->node_name = low_level_op->sys_node_name;
	v_lport->options = low_level_op->lport_cfg_items.port_mode;
	v_lport->en_act_topo = UNF_ACT_TOP_UNKNOWN;

	memcpy(&v_lport->low_level_func, low_level_op,
	       sizeof(struct unf_low_level_function_op_s));

	return RETURN_OK;
}

void unf_lport_release_lw_fun_op(struct unf_lport_s *v_lport)
{
	UNF_CHECK_VALID(0x2237, UNF_TRUE, v_lport, return);

	memset(&v_lport->low_level_func, 0,
	       sizeof(struct unf_low_level_function_op_s));

	v_lport->destroy_step = UNF_LPORT_DESTROY_STEP_13_DESTROY_LW_INTERFACE;
}

struct unf_lport_s *unf_find_lport_by_scsi_host_id(unsigned int scsi_host_id)
{
	struct list_head *node = NULL, *next_node = NULL;
	struct list_head *vp_node = NULL, *next_vp_node = NULL;
	struct unf_lport_s *lport = NULL;
	struct unf_lport_s *vport = NULL;
	unsigned long flags = 0;
	unsigned long vpool_flags = 0;

	spin_lock_irqsave(&global_lport_mgr.global_lport_list_lock, flags);
	list_for_each_safe(node, next_node,
			   &global_lport_mgr.list_lport_list_head) {
		lport = list_entry(node, struct unf_lport_s, entry_lport);

		if (scsi_host_id ==
		    UNF_GET_SCSI_HOST_ID((lport->host_info.p_scsi_host))) {
			spin_unlock_irqrestore(
				&global_lport_mgr.global_lport_list_lock,
				flags);

			return lport;
		}

		/* support NPIV */
		if (lport->vport_pool) {
			spin_lock_irqsave(&lport->vport_pool->vport_pool_lock,
					  vpool_flags);
			list_for_each_safe(vp_node, next_vp_node,
					   &lport->list_vports_head) {
				vport = list_entry(vp_node, struct unf_lport_s,
						   entry_vport);

				if (scsi_host_id ==
				    UNF_GET_SCSI_HOST_ID(vport->host_info.p_scsi_host)) {
					spin_unlock_irqrestore(
						&lport->vport_pool->vport_pool_lock,
						vpool_flags);
					spin_unlock_irqrestore(
						&global_lport_mgr.global_lport_list_lock,
						flags);

					return vport;
				}
			}
			spin_unlock_irqrestore(
				&lport->vport_pool->vport_pool_lock, vpool_flags);
		}
	}

	list_for_each_safe(node, next_node,
			   &global_lport_mgr.list_intergrad_head) {
		lport = list_entry(node, struct unf_lport_s, entry_lport);

		if (scsi_host_id ==
		    UNF_GET_SCSI_HOST_ID(lport->host_info.p_scsi_host)) {
			spin_unlock_irqrestore(
				&global_lport_mgr.global_lport_list_lock,
				flags);

			return lport;
		}

		/* support NPIV */
		if (lport->vport_pool) {
			spin_lock_irqsave(&lport->vport_pool->vport_pool_lock,
					  vpool_flags);
			list_for_each_safe(vp_node, next_vp_node,
					   &lport->list_vports_head) {
				vport = list_entry(vp_node, struct unf_lport_s,
						   entry_vport);

				if (scsi_host_id ==
				    UNF_GET_SCSI_HOST_ID(vport->host_info.p_scsi_host)) {
					spin_unlock_irqrestore(
						&lport->vport_pool->vport_pool_lock,
						vpool_flags);
					spin_unlock_irqrestore(
						&global_lport_mgr.global_lport_list_lock,
						flags);

					return vport;
				}
			}
			spin_unlock_irqrestore(
				&lport->vport_pool->vport_pool_lock, vpool_flags);
		}
	}
	spin_unlock_irqrestore(&global_lport_mgr.global_lport_list_lock, flags);

	UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_IO_ATT, UNF_WARN,
		  "[warn]Can not find port by scsi_host_id(0x%x), may be removing",
		  scsi_host_id);

	return NULL;
}

unsigned int unf_init_scsi_id_table(struct unf_lport_s *v_lport)
{
	struct unf_rport_scsi_id_image_s *rport_scsi_id_image = NULL;
	struct unf_wwpn_rport_info_s *wwpn_port_info = NULL;
	unsigned int idx;

	UNF_CHECK_VALID(0x2238, UNF_TRUE, (v_lport),
			return UNF_RETURN_ERROR);

	rport_scsi_id_image = &v_lport->rport_scsi_table;
	rport_scsi_id_image->max_scsi_id = UNF_MAX_SCSI_ID;

	/* If the number of remote connections supported by the L_Port is 0,
	 * an exception occurs
	 */
	if (rport_scsi_id_image->max_scsi_id == 0) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_REG_ATT, UNF_ERR,
			  "[err]Port(0x%x), supported maximum login is zero.",
			  v_lport->port_id);

		return UNF_RETURN_ERROR;
	}

	rport_scsi_id_image->wwn_rport_info_table =
		vmalloc(rport_scsi_id_image->max_scsi_id *
			sizeof(struct unf_wwpn_rport_info_s));
	if (!rport_scsi_id_image->wwn_rport_info_table) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_REG_ATT, UNF_ERR,
			  "[err]Port(0x%x) can't allocate SCSI ID Table(0x%x).",
			  v_lport->port_id, rport_scsi_id_image->max_scsi_id);

		return UNF_RETURN_ERROR;
	}
	memset(rport_scsi_id_image->wwn_rport_info_table, 0,
	       rport_scsi_id_image->max_scsi_id *
	       sizeof(struct unf_wwpn_rport_info_s));

	wwpn_port_info = rport_scsi_id_image->wwn_rport_info_table;

	for (idx = 0; idx < rport_scsi_id_image->max_scsi_id; idx++) {
		INIT_DELAYED_WORK(&wwpn_port_info->loss_tmo_work,
				  unf_sesion_loss_timeout);
		INIT_LIST_HEAD(&wwpn_port_info->fc_lun_list);
		wwpn_port_info->lport = v_lport;
		wwpn_port_info->target_id = INVALID_VALUE32;
		wwpn_port_info++;
	}

	spin_lock_init(&rport_scsi_id_image->scsi_image_table_lock);
	UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_REG_ATT, UNF_INFO,
		  "[info]Port(0x%x) supported maximum login is %d.",
		  v_lport->port_id, rport_scsi_id_image->max_scsi_id);

	return RETURN_OK;
}

void unf_destroy_scsi_id_table(struct unf_lport_s *v_lport)
{
	struct unf_rport_scsi_id_image_s *rport_scsi_id_image = NULL;
	struct unf_wwpn_rport_info_s *wwpn_rport_info = NULL;
	unsigned int i = 0;
	unsigned int ret = UNF_RETURN_ERROR;

	UNF_CHECK_VALID(0x2239, UNF_TRUE, (v_lport), return);

	rport_scsi_id_image = &v_lport->rport_scsi_table;
	if (rport_scsi_id_image->wwn_rport_info_table) {
		for (i = 0; i < UNF_MAX_SCSI_ID; i++) {
			wwpn_rport_info =
				&rport_scsi_id_image->wwn_rport_info_table[i];
			UNF_DELAYED_WORK_SYNC(ret, v_lport->port_id,
					      &wwpn_rport_info->loss_tmo_work,
					      "loss tmo Timer work");
			if (wwpn_rport_info->dfx_counter)
				vfree(wwpn_rport_info->dfx_counter);
		}

		/* just for pc_lint */
		if (ret)
			UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT,
				  UNF_INFO,
				  "Port(0x%x) cancel loss tmo work success",
				  v_lport->port_id);

		vfree(rport_scsi_id_image->wwn_rport_info_table);
		rport_scsi_id_image->wwn_rport_info_table = NULL;
	}

	rport_scsi_id_image->max_scsi_id = 0;
	v_lport->destroy_step = UNF_LPORT_DESTROY_STEP_10_DESTROY_SCSI_TABLE;
}

static unsigned int unf_lport_init(
			struct unf_lport_s *v_lport,
			void *private_data,
			struct unf_low_level_function_op_s *low_level_op)
{
	unsigned int ret = RETURN_OK;
	int ret_value = RETURN_ERROR_S32;
	char work_queue_name[16];

	unf_init_portparms(v_lport);

	/* Associating  LPort with FCPort */
	v_lport->fc_port = private_data;

	/* VpIndx=0 is reserved for Lport, and rootLport points to its own */
	v_lport->vp_index = 0;
	v_lport->root_lport = v_lport;
	v_lport->chip_info = NULL;

	/* Initialize the units related to L_Port and lw func */
	ret = unf_lport_init_lw_fun_op(v_lport, low_level_op);
	if (ret != RETURN_OK) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_REG_ATT, UNF_MAJOR,
			  "LPort(0x%x) initialize lowlevel function unsuccessful.",
			  v_lport->port_id);

		return ret;
	}

	/* Init Linkevent workqueue */
	ret_value = snprintf(work_queue_name, sizeof(work_queue_name),
			     "%x_lkq", (unsigned int)v_lport->port_id);
	UNF_FUNCTION_RETURN_CHECK(ret_value, (int)sizeof(work_queue_name));

	v_lport->link_event_wq = create_singlethread_workqueue(work_queue_name);
	if (!v_lport->link_event_wq) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_NORMAL, UNF_ERR,
			  "[err]Port(0x%x) creat link event work queue failed",
			  v_lport->port_id);

		return UNF_RETURN_ERROR;
	}
	ret_value = snprintf(work_queue_name, sizeof(work_queue_name),
			     "%x_xchgwq", (unsigned int)v_lport->port_id);
	UNF_FUNCTION_RETURN_CHECK(ret_value, (int)sizeof(work_queue_name));

	v_lport->xchg_wq = create_workqueue(work_queue_name);
	if (!v_lport->xchg_wq) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_NORMAL, UNF_ERR,
			  "[err]Port(0x%x) creat Exchg work queue failed",
			  v_lport->port_id);
		flush_workqueue(v_lport->link_event_wq);
		destroy_workqueue(v_lport->link_event_wq);
		v_lport->link_event_wq = NULL;
		return UNF_RETURN_ERROR;
	}
	/* scsi table (R_Port) required for initializing INI
	 * Initialize the scsi id Table table to manage the
	 * mapping between SCSI ID, WWN, and Rport.
	 */
	ret = unf_init_scsi_id_table(v_lport);
	if (ret != RETURN_OK) {
		flush_workqueue(v_lport->link_event_wq);
		destroy_workqueue(v_lport->link_event_wq);
		v_lport->link_event_wq = NULL;

		flush_workqueue(v_lport->xchg_wq);
		destroy_workqueue(v_lport->xchg_wq);
		v_lport->xchg_wq = NULL;
		return ret;
	}

	/* Initialize the EXCH resource */
	ret = unf_alloc_xchg_resource(v_lport);
	if (ret != RETURN_OK) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_REG_ATT, UNF_MAJOR,
			  "LPort(0x%x) can't allocate exchange resource.",
			  v_lport->port_id);

		flush_workqueue(v_lport->link_event_wq);
		destroy_workqueue(v_lport->link_event_wq);
		v_lport->link_event_wq = NULL;

		flush_workqueue(v_lport->xchg_wq);
		destroy_workqueue(v_lport->xchg_wq);
		v_lport->xchg_wq = NULL;
		unf_destroy_scsi_id_table(v_lport);

		return ret;
	}

	/* Initialize the ESGL resource pool used by Lport */
	ret = unf_init_esgl_pool(v_lport);
	if (ret != RETURN_OK) {
		flush_workqueue(v_lport->link_event_wq);
		destroy_workqueue(v_lport->link_event_wq);
		v_lport->link_event_wq = NULL;

		flush_workqueue(v_lport->xchg_wq);
		destroy_workqueue(v_lport->xchg_wq);
		v_lport->xchg_wq = NULL;
		unf_free_all_xchg_mgr(v_lport);
		unf_destroy_scsi_id_table(v_lport);

		return ret;
	}
	/* Initialize the disc manager under Lport */
	ret = unf_init_disc_mgr(v_lport);
	if (ret != RETURN_OK) {
		flush_workqueue(v_lport->link_event_wq);
		destroy_workqueue(v_lport->link_event_wq);
		v_lport->link_event_wq = NULL;

		flush_workqueue(v_lport->xchg_wq);
		destroy_workqueue(v_lport->xchg_wq);
		v_lport->xchg_wq = NULL;
		unf_free_esgl_pool(v_lport);
		unf_free_all_xchg_mgr(v_lport);
		unf_destroy_scsi_id_table(v_lport);

		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_REG_ATT, UNF_MAJOR,
			  "LPort(0x%x) initialize discover manager unsuccessful.",
			  v_lport->port_id);

		return ret;
	}

	/* Initialize the LPort manager */
	ret = unf_init_lport_mgr_temp(v_lport);
	if (ret != RETURN_OK) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_REG_ATT, UNF_MAJOR,
			  "LPort(0x%x) initialize RPort manager unsuccessful.",
			  v_lport->port_id);

		goto RELEASE_LPORT;
	}

	/* Initialize the EXCH manager */
	ret = unf_init_xchg_mgr_temp(v_lport);
	if (ret != RETURN_OK) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_REG_ATT, UNF_MAJOR,
			  "LPort(0x%x) initialize exchange manager unsuccessful.",
			  v_lport->port_id);

		goto RELEASE_LPORT;
	}
	/* Initialize the resources required by the event processing center */
	ret = unf_init_event_center(v_lport);
	if (ret != RETURN_OK) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_REG_ATT, UNF_MAJOR,
			  "LPort(0x%x) initialize event center unsuccessful.",
			  v_lport->port_id);

		goto RELEASE_LPORT;
	}
	/* Initialize the initialization status of Lport */
	unf_set_lport_state(v_lport, UNF_LPORT_ST_INITIAL);

	/* Initialize the Lport route test case */
	ret = unf_init_lport_route(v_lport);
	if (ret != RETURN_OK) {
		flush_workqueue(v_lport->link_event_wq);
		destroy_workqueue(v_lport->link_event_wq);
		v_lport->link_event_wq = NULL;

		flush_workqueue(v_lport->xchg_wq);
		destroy_workqueue(v_lport->xchg_wq);
		v_lport->xchg_wq = NULL;
		(void)unf_event_center_destroy(v_lport);
		unf_disc_mgr_destroy(v_lport);
		unf_free_esgl_pool(v_lport);
		unf_free_all_xchg_mgr(v_lport);
		unf_destroy_scsi_id_table(v_lport);

		return ret;
	}

	/* Thesupports the initialization stepof the NPIV */
	ret = unf_init_vport_pool(v_lport);
	if (ret != RETURN_OK) {
		flush_workqueue(v_lport->link_event_wq);
		destroy_workqueue(v_lport->link_event_wq);
		v_lport->link_event_wq = NULL;

		flush_workqueue(v_lport->xchg_wq);
		destroy_workqueue(v_lport->xchg_wq);
		v_lport->xchg_wq = NULL;

		unf_destroy_lport_route(v_lport);
		(void)unf_event_center_destroy(v_lport);
		unf_disc_mgr_destroy(v_lport);
		unf_free_esgl_pool(v_lport);
		unf_free_all_xchg_mgr(v_lport);
		unf_destroy_scsi_id_table(v_lport);

		return ret;
	}

	/* qualifier rport callback */
	v_lport->pfn_unf_qualify_rport = unf_rport_set_qualifier_key_reuse;
	v_lport->pfn_unf_tmf_abnormal_recovery =
		unf_tmf_timeout_recovery_special;
	return RETURN_OK;
RELEASE_LPORT:
	flush_workqueue(v_lport->link_event_wq);
	destroy_workqueue(v_lport->link_event_wq);
	v_lport->link_event_wq = NULL;

	flush_workqueue(v_lport->xchg_wq);
	destroy_workqueue(v_lport->xchg_wq);
	v_lport->xchg_wq = NULL;

	unf_disc_mgr_destroy(v_lport);
	unf_free_esgl_pool(v_lport);
	unf_free_all_xchg_mgr(v_lport);
	unf_destroy_scsi_id_table(v_lport);
	return ret;
}

static void unf_destroy_card_thread(struct unf_lport_s *v_lport)
{
	struct unf_event_mgr *event_mgr = NULL;
	struct unf_chip_manage_info_s *chip_info = NULL;
	struct list_head *list = NULL;
	struct list_head *list_tmp = NULL;
	struct unf_cm_event_report *event_node = NULL;
	unsigned long event_lock_flag = 0;
	unsigned long flag = 0;

	UNF_CHECK_VALID(0x2249, UNF_TRUE, (v_lport), return);

	/* If the thread cannot be found, apply for a new thread. */
	chip_info = v_lport->chip_info;
	if (!chip_info) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_REG_ATT, UNF_MAJOR,
			  "Port(0x%x) has no event thread.", v_lport->port_id);
		return;
	}
	event_mgr = &v_lport->event_mgr;

	spin_lock_irqsave(&chip_info->chip_event_list_lock, flag);
	if (!list_empty(&chip_info->list_head)) {
		list_for_each_safe(list, list_tmp, &chip_info->list_head) {
			event_node = list_entry(list,
						struct unf_cm_event_report,
						list_entry);

			/* The LPort under the global event node is null. */
			if (v_lport == event_node->lport) {
				list_del_init(&event_node->list_entry);
				if (event_node->event_asy_flag ==
				    UNF_EVENT_SYN) {
					event_node->result = UNF_RETURN_ERROR;
					complete(&event_node->event_comp);
				}

				spin_lock_irqsave(&event_mgr->port_event_lock,
						  event_lock_flag);
				event_mgr->free_event_count++;
				list_add_tail(&event_node->list_entry,
					      &event_mgr->list_free_event);
				spin_unlock_irqrestore(
					&event_mgr->port_event_lock,
					event_lock_flag);
			}
		}
	}
	spin_unlock_irqrestore(&chip_info->chip_event_list_lock, flag);

	/* If the number of events introduced by the event thread is 0,
	 * it indicates that no interface is used. In this case, thread
	 * resources need to be consumed
	 */
	if (atomic_dec_and_test(&chip_info->ref_cnt)) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_REG_ATT, UNF_MAJOR,
			  "Port(0x%x) destroy slot(%u) chip(0x%x) event thread succeed.",
			  v_lport->port_id, chip_info->slot_id,
			  chip_info->chip_id);
		chip_info->b_thread_exit = UNF_TRUE;
		wake_up_process(chip_info->data_thread);
		kthread_stop(chip_info->data_thread);
		chip_info->data_thread = NULL;

		spin_lock_irqsave(&card_thread_mgr.global_card_list_lock, flag);
		list_del_init(&chip_info->list_chip_thread_entry);
		card_thread_mgr.card_sum--;
		spin_unlock_irqrestore(&card_thread_mgr.global_card_list_lock,
				       flag);

		vfree(chip_info);
	}

	v_lport->chip_info = NULL;
}

unsigned int unf_lport_deinit(struct unf_lport_s *v_lport)
{
	UNF_CHECK_VALID(0x2246, UNF_TRUE, (v_lport), return UNF_RETURN_ERROR);

	/* If the card is unloaded normally, the thread is stopped once.
	 * The problem does not occur if you stop the thread again.
	 */
	unf_destroy_lport_route(v_lport);

	/* minus the reference count of the card event;
	 * the last port deletes the card thread
	 */
	unf_destroy_card_thread(v_lport);
	flush_workqueue(v_lport->link_event_wq);
	destroy_workqueue(v_lport->link_event_wq);
	v_lport->link_event_wq = NULL;

	/* Release Event Processing Center */
	(void)unf_event_center_destroy(v_lport);

	/* Release the Vport resource pool */
	unf_free_vport_pool(v_lport);

	/* Destroying the Xchg Manager */
	unf_xchg_mgr_destroy(v_lport);

	/* Release Esgl pool */
	unf_free_esgl_pool(v_lport);

	/* reliability review :Disc should release after Xchg.
	 * Destroy the disc manager
	 */
	unf_disc_mgr_destroy(v_lport);

	/* Release Xchg Mg template */
	unf_release_xchg_mgr_temp(v_lport);

	/* Release the Lport Mg template */
	unf_release_lport_mgr_temp(v_lport);

	/* Destroy the ScsiId Table */
	unf_destroy_scsi_id_table(v_lport);

	flush_workqueue(v_lport->xchg_wq);
	destroy_workqueue(v_lport->xchg_wq);
	v_lport->xchg_wq = NULL;

	/* Deregister SCSI Host */
	unf_unregister_scsi_host(v_lport);

	/* Releasing the lw Interface Template */
	unf_lport_release_lw_fun_op(v_lport);
	v_lport->fc_port = NULL;
	return RETURN_OK;
}

static int unf_card_event_process(void *v_arg)
{
	struct list_head *node = NULL;
	struct unf_cm_event_report *event_node = NULL;
	unsigned long flags = 0;
	struct unf_chip_manage_info_s *chip_info =
		(struct unf_chip_manage_info_s *)v_arg;

	UNF_REFERNCE_VAR(v_arg);

	set_user_nice(current, 4);

	UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_REG_ATT, UNF_INFO,
		  "Slot(%u) chip(0x%x) enter event thread.",
		  chip_info->slot_id, chip_info->chip_id);

	while (!kthread_should_stop()) {
		if (chip_info->b_thread_exit == UNF_TRUE)
			break;

		spin_lock_irqsave(&chip_info->chip_event_list_lock, flags);
		if (list_empty(&chip_info->list_head) == UNF_TRUE) {
			spin_unlock_irqrestore(&chip_info->chip_event_list_lock,
					       flags);

			set_current_state(TASK_INTERRUPTIBLE);
			schedule_timeout((long)msecs_to_jiffies(1000));
		} else {
			node = (&chip_info->list_head)->next;
			list_del_init(node);
			chip_info->list_num--;
			event_node = list_entry(node,
						struct unf_cm_event_report,
						list_entry);
			spin_unlock_irqrestore(&chip_info->chip_event_list_lock,
					       flags);
			unf_handle_event(event_node);
		}
	}
	UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_EVENT, UNF_MAJOR,
		  "Slot(%u) chip(0x%x) exit event thread.",
		  chip_info->slot_id, chip_info->chip_id);

	return RETURN_OK;
}

static unsigned int unf_creat_chip_thread(struct unf_lport_s *v_lport)
{
	unsigned long flag = 0;
	struct unf_chip_manage_info_s *chip_info = NULL;

	UNF_CHECK_VALID(0x2250, UNF_TRUE, (v_lport), return UNF_RETURN_ERROR);

	/* If the thread cannot be found, apply for a new thread. */
	chip_info = (struct unf_chip_manage_info_s *)vmalloc(
				sizeof(struct unf_chip_manage_info_s));
	if (!chip_info) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_REG_ATT, UNF_ERR,
			  "Port(0x%x) cannot allocate thread memory.",
			  v_lport->port_id);

		return UNF_RETURN_ERROR;
	}
	memset(chip_info, 0, sizeof(struct unf_chip_manage_info_s));

	memcpy(&chip_info->chip_info, &v_lport->low_level_func.chip_info,
	       sizeof(struct unf_chip_info_s));
	chip_info->slot_id =
		UNF_GET_BOARD_TYPE_AND_SLOT_ID_BY_PORTID(v_lport->port_id);
	chip_info->chip_id = v_lport->low_level_func.chip_id;
	chip_info->list_num = 0;
	chip_info->sfp_9545_fault = UNF_FALSE;
	chip_info->sfp_power_fault = UNF_FALSE;
	atomic_set(&chip_info->ref_cnt, 1);
	atomic_set(&chip_info->card_loop_test_flag, UNF_FALSE);
	spin_lock_init(&chip_info->card_loop_back_state_lock);
	INIT_LIST_HEAD(&chip_info->list_head);
	spin_lock_init(&chip_info->chip_event_list_lock);

	chip_info->b_thread_exit = UNF_FALSE;
	chip_info->data_thread =
		kthread_create(unf_card_event_process, chip_info,
			       "%x_et", v_lport->port_id);

	if (IS_ERR(chip_info->data_thread) ||
	    (!chip_info->data_thread)) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_REG_ATT, UNF_MAJOR,
			  "Port(0x%x) creat event thread(0x%p) unsuccessful.",
			  v_lport->port_id, chip_info->data_thread);

		vfree(chip_info);

		return UNF_RETURN_ERROR;
	}

	v_lport->chip_info = chip_info;
	wake_up_process(chip_info->data_thread);

	UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_REG_ATT, UNF_INFO,
		  "Port(0x%x) creat slot(%u) chip(0x%x) event thread succeed.",
		  v_lport->port_id, chip_info->slot_id, chip_info->chip_id);

	spin_lock_irqsave(&card_thread_mgr.global_card_list_lock, flag);
	list_add_tail(&chip_info->list_chip_thread_entry,
		      &card_thread_mgr.list_card_list_head);
	card_thread_mgr.card_sum++;
	spin_unlock_irqrestore(&card_thread_mgr.global_card_list_lock, flag);

	return RETURN_OK;
}

static unsigned int unf_find_chip_thread(struct unf_lport_s *v_lport)
{
	unsigned long flag = 0;
	struct list_head *node = NULL;
	struct list_head *next_node = NULL;
	struct unf_chip_manage_info_s *chip_info = NULL;
	unsigned int ret = UNF_RETURN_ERROR;

	spin_lock_irqsave(&card_thread_mgr.global_card_list_lock, flag);
	list_for_each_safe(node, next_node,
			   &card_thread_mgr.list_card_list_head) {
		chip_info = list_entry(node, struct unf_chip_manage_info_s,
				       list_chip_thread_entry);

		if ((chip_info->chip_id == v_lport->low_level_func.chip_id) &&
		    (chip_info->slot_id == UNF_GET_BOARD_TYPE_AND_SLOT_ID_BY_PORTID(v_lport->port_id))) {
			atomic_inc(&chip_info->ref_cnt);
			v_lport->chip_info = chip_info;

			UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_REG_ATT,
				  UNF_MAJOR,
				  "Port(0x%x) find card(%u) chip(0x%x) event thread succeed.",
				  v_lport->port_id, chip_info->slot_id,
				  chip_info->chip_id);

			spin_unlock_irqrestore(
				&card_thread_mgr.global_card_list_lock, flag);

			return RETURN_OK;
		}
	}
	spin_unlock_irqrestore(&card_thread_mgr.global_card_list_lock, flag);

	ret = unf_creat_chip_thread(v_lport);
	if (ret != RETURN_OK) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_REG_ATT, UNF_MAJOR,
			  "LPort(0x%x) creat event thread unsuccessful. Destroy LPort.",
			  v_lport->port_id);
		return UNF_RETURN_ERROR;
	} else {
		return RETURN_OK;
	}
}

static int unf_cm_get_mac_adr(void *argc_in, void *argc_out)
{
	struct unf_lport_s *lport = NULL;
	struct unf_get_chip_info_argout *chp_info = NULL;

	UNF_CHECK_VALID(0x2398, UNF_TRUE, argc_in, return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(0x2398, UNF_TRUE, argc_out, return UNF_RETURN_ERROR);

	lport = (struct unf_lport_s *)argc_in;
	chp_info = (struct unf_get_chip_info_argout *)argc_out;

	if (!lport) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_EQUIP_ATT, UNF_MAJOR,
			  " LPort is null.");

		return UNF_RETURN_ERROR;
	}

	if (!lport->low_level_func.port_mgr_op.pfn_ll_port_config_get) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_REG_ATT, UNF_MAJOR,
			  "Port(0x%x)'s corresponding function is NULL.",
			  lport->port_id);

		return UNF_RETURN_ERROR;
	}

	if (lport->low_level_func.port_mgr_op.pfn_ll_port_config_get(
		lport->fc_port,
		UNF_PORT_CFG_GET_MAC_ADDR, chp_info) != RETURN_OK) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_REG_ATT, UNF_MAJOR,
			  "Port(0x%x) get .", lport->port_id);

		return UNF_RETURN_ERROR;
	}
	return RETURN_OK;
}

static unsigned int unf_build_lport_wwn(struct unf_lport_s *v_lport)
{
	struct unf_get_chip_info_argout v_wwn = { 0 };
	unsigned int ret = UNF_RETURN_ERROR;

	UNF_CHECK_VALID(0x2403, UNF_TRUE, (v_lport), return UNF_RETURN_ERROR);

	ret = (unsigned int)unf_send_event(v_lport->port_id,
					   UNF_EVENT_SYN,
					   (void *)v_lport,
					   (void *)&v_wwn,
					   unf_cm_get_mac_adr);
	if (ret != RETURN_OK) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_REG_ATT, UNF_MAJOR,
			  "UNF_BuildSysWwn SendEvent(UNF_PortGetMacAdr) fail.");

		return UNF_RETURN_ERROR;
	}

	/* save card mode: UNF_FC_SERVER_BOARD_32_G(6):32G;
	 * UNF_FC_SERVER_BOARD_16_G(7):16G MODE
	 */
	v_lport->card_type = v_wwn.board_type;

	/* update port max speed */
	if (v_wwn.board_type == UNF_FC_SERVER_BOARD_32_G)
		v_lport->low_level_func.fc_ser_max_speed = UNF_PORT_SPEED_32_G;
	else if (v_wwn.board_type == UNF_FC_SERVER_BOARD_16_G)
		v_lport->low_level_func.fc_ser_max_speed = UNF_PORT_SPEED_16_G;
	else if (v_wwn.board_type == UNF_FC_SERVER_BOARD_8_G)
		v_lport->low_level_func.fc_ser_max_speed = UNF_PORT_SPEED_8_G;
	else
		v_lport->low_level_func.fc_ser_max_speed = UNF_PORT_SPEED_32_G;

	return RETURN_OK;
}

void *unf_lport_create_and_init(
			void *private_data,
			struct unf_low_level_function_op_s *low_level_op)
{
	struct unf_lport_s *lport = NULL;
	unsigned int ret = UNF_RETURN_ERROR;

	if (!private_data) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_REG_ATT, UNF_MAJOR,
			  "Private Data is NULL");

		return NULL;
	}
	if (!low_level_op) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_REG_ATT, UNF_MAJOR,
			  "LowLevel port(0x%p) function is NULL", private_data);

		return NULL;
	}

	/* 1. vmalloc & Memset L_Port */
	lport = vmalloc(sizeof(struct unf_lport_s));
	if (!lport) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_REG_ATT, UNF_ERR,
			  "Alloc LPort memory failed.");

		return NULL;
	}
	memset(lport, 0, sizeof(struct unf_lport_s));

	/* 2. L_Port Init */
	if (unf_lport_init(lport, private_data, low_level_op) != RETURN_OK) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_REG_ATT, UNF_MAJOR,
			  "LPort initialize unsuccessful.");

		vfree(lport);

		return NULL;
	}

	/* 4. Get or Create Chip Thread Chip_ID & Slot_ID */
	ret = unf_find_chip_thread(lport);
	if (ret != RETURN_OK) {
		(void)unf_lport_deinit(lport);

		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_REG_ATT, UNF_MAJOR,
			  "LPort(0x%x) Find Chip thread unsuccessful. Destroy LPort.",
			  lport->port_id);

		vfree(lport);
		return NULL;
	}

	/* 5. Registers with in the port management global linked list */
	unf_port_register(lport);
	/* update WWN */
	if (unf_build_lport_wwn(lport) != RETURN_OK) {
		unf_port_unregister(lport);
		(void)unf_lport_deinit(lport);
		vfree(lport);
		return NULL;
	}

	unf_init_link_lose_tmo(lport);

	/* initialize Scsi Host */
	if (unf_register_scsi_host(lport) != RETURN_OK) {
		unf_port_unregister(lport);
		(void)unf_lport_deinit(lport);
		vfree(lport);
		return NULL;
	}

	/* 7. Here, start work now */
	if (global_lport_mgr.b_start_work == UNF_TRUE) {
		if (unf_port_start_work(lport) != RETURN_OK) {
			unf_port_unregister(lport);

			(void)unf_lport_deinit(lport);

			UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_REG_ATT,
				  UNF_WARN,
				  "[warn]Port(0x%x) start work failed",
				  lport->port_id);
			vfree(lport);
			return NULL;
		}
	}

	UNF_REFERNCE_VAR(lport);
	return lport;
}

static int unf_lport_destroy(void *v_lport, void *v_arg_out)
{
	struct unf_lport_s *lport = NULL;
	unsigned long flags = 0;

	if (!v_lport) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_REG_ATT, UNF_MAJOR,
			  "LPort is NULL.");

		return UNF_RETURN_ERROR;
	}

	UNF_REFERNCE_VAR(v_arg_out);

	lport = (struct unf_lport_s *)v_lport;

	UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_NORMAL, UNF_MAJOR,
		  "Destroy LPort(0x%p), ID(0x%x).",
		  lport, lport->port_id);

	/* NPIV Ensure that all Vport are deleted */
	unf_destroy_all_vports(lport);

	lport->destroy_step = UNF_LPORT_DESTROY_STEP_1_REPORT_PORT_OUT;

	(void)unf_lport_deinit(v_lport);

	/* The port is removed from the destroy linked list.
	 * The next step is to release the memory
	 */
	spin_lock_irqsave(&global_lport_mgr.global_lport_list_lock, flags);
	list_del(&lport->entry_lport);

	/* If the port has dirty memory, the port is mounted to the
	 * linked list of dirty ports
	 */
	if (lport->dirty_flag)
		list_add_tail(&lport->entry_lport,
			      &global_lport_mgr.list_dirty_head);
	spin_unlock_irqrestore(&global_lport_mgr.global_lport_list_lock,
			       flags);

	if (lport->lport_free_completion) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_REG_ATT, UNF_MAJOR,
			  "Complete LPort(0x%p), port ID(0x%x)'s Free Completion.",
			  lport, lport->port_id);
		complete(lport->lport_free_completion);
	} else {
		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_REG_ATT, UNF_MAJOR,
			  "LPort(0x%p), port ID(0x%x)'s Free Completion is NULL.",
			  lport, lport->port_id);
		dump_stack();
	}

	return RETURN_OK;
}

unsigned int unf_lport_refinc(struct unf_lport_s *v_lport)
{
	unsigned long lport_flags = 0;

	UNF_CHECK_VALID(0x2208, UNF_TRUE, v_lport, return UNF_RETURN_ERROR);

	spin_lock_irqsave(&v_lport->lport_state_lock, lport_flags);
	if (atomic_read(&v_lport->lport_ref_cnt) <= 0) {
		spin_unlock_irqrestore(&v_lport->lport_state_lock,
				       lport_flags);

		return UNF_RETURN_ERROR;
	}

	atomic_inc(&v_lport->lport_ref_cnt);

	UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT, UNF_INFO,
		  "[info]Port(0x%p) port_id(0x%x) reference count is %d",
		  v_lport, v_lport->port_id,
		  atomic_read(&v_lport->lport_ref_cnt));

	spin_unlock_irqrestore(&v_lport->lport_state_lock, lport_flags);

	return RETURN_OK;
}

void unf_lport_ref_dec(struct unf_lport_s *v_lport)
{
	unsigned long flags = 0;
	unsigned long lport_flags = 0;

	UNF_CHECK_VALID(0x2209, UNF_TRUE, v_lport, return);

	UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT, UNF_INFO,
		  "LPort(0x%p), port ID(0x%x), reference count is %d.",
		  v_lport, v_lport->port_id,
		  atomic_read(&v_lport->lport_ref_cnt));

	spin_lock_irqsave(&global_lport_mgr.global_lport_list_lock, flags);
	spin_lock_irqsave(&v_lport->lport_state_lock, lport_flags);
	if (atomic_dec_and_test(&v_lport->lport_ref_cnt)) {
		spin_unlock_irqrestore(&v_lport->lport_state_lock, lport_flags);
		list_del(&v_lport->entry_lport);
		global_lport_mgr.lport_sum--;

		/* attaches the lport to the destroy linked list for dfx */
		list_add_tail(&v_lport->entry_lport,
			      &global_lport_mgr.list_destroy_head);
		spin_unlock_irqrestore(&global_lport_mgr.global_lport_list_lock,
				       flags);

		(void)unf_lport_destroy(v_lport, NULL);
	} else {
		spin_unlock_irqrestore(&v_lport->lport_state_lock, lport_flags);
		spin_unlock_irqrestore(&global_lport_mgr.global_lport_list_lock,
				       flags);
	}
}

static int unf_reset_port(void *v_arg_in, void *v_arg_out)
{
	struct unf_reset_port_argin *arg_in =
		(struct unf_reset_port_argin *)v_arg_in;
	struct unf_lport_s *lport = NULL;
	unsigned int ret = UNF_RETURN_ERROR;
	enum unf_port_config_state_e port_state = UNF_PORT_CONFIG_STATE_RESET;

	UNF_REFERNCE_VAR(v_arg_out);
	UNF_CHECK_VALID(0x2262, UNF_TRUE, arg_in, return UNF_RETURN_ERROR);

	lport = unf_find_lport_by_port_id(arg_in->port_id);
	if (!lport) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_EQUIP_ATT, UNF_MAJOR,
			  "Not find LPort(0x%x).", arg_in->port_id);

		return UNF_RETURN_ERROR;
	}

	/* reset port */
	if (!lport->low_level_func.port_mgr_op.pfn_ll_port_config_set) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_EQUIP_ATT, UNF_MAJOR,
			  "Port(0x%x)'s corresponding function is NULL.",
			  lport->port_id);

		return UNF_RETURN_ERROR;
	}

	lport->en_act_topo = UNF_ACT_TOP_UNKNOWN;
	lport->speed = UNF_PORT_SPEED_UNKNOWN;
	lport->fabric_node_name = 0;

	ret = lport->low_level_func.port_mgr_op.pfn_ll_port_config_set(
		lport->fc_port,
		UNF_PORT_CFG_SET_PORT_STATE, (void *)&port_state);

	if (ret != RETURN_OK) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_EQUIP_ATT, UNF_MAJOR,
			  "Reset port(0x%x) unsuccessful.", lport->port_id);

		return UNF_RETURN_ERROR;
	}

	return RETURN_OK;
}

static int unf_sfp_switch(unsigned int v_port_id, int v_turn_on)
{
	struct unf_lport_s *lport = NULL;
	int turn_on = v_turn_on;
	int ret = UNF_RETURN_ERROR;
	unsigned long flag = 0;

	if (global_lport_mgr.b_start_work == UNF_FALSE) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_EQUIP_ATT, UNF_WARN,
			  "[warn]Port(0x%x) not start work, ignored command:turn %s.",
			  v_port_id, (v_turn_on == UNF_TRUE) ? "ON" : "OFF");

		return RETURN_OK;
	}

	lport = unf_find_lport_by_port_id(v_port_id);
	if (!lport) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_EQUIP_ATT, UNF_WARN,
			  "[warn]Not find LPort(0x%x).", v_port_id);

		return UNF_RETURN_ERROR;
	}

	spin_lock_irqsave(&lport->lport_state_lock, flag);
	if (lport->en_start_work_state != UNF_START_WORK_COMPLETE) {
		spin_unlock_irqrestore(&lport->lport_state_lock, flag);
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_EQUIP_ATT, UNF_WARN,
			  "[warn]LPort(0x%x) not start work, ignored command:turn %s.",
			  v_port_id, (v_turn_on == UNF_TRUE) ? "ON" : "OFF");

		return RETURN_OK;
	}
	spin_unlock_irqrestore(&lport->lport_state_lock, flag);

	if (!lport->low_level_func.port_mgr_op.pfn_ll_port_config_set) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_EQUIP_ATT, UNF_WARN,
			  "[warn]Port(0x%x)'s corresponding function is NULL.",
			  v_port_id);

		return UNF_RETURN_ERROR;
	}

	ret = (int)lport->low_level_func.port_mgr_op.pfn_ll_port_config_set(
			lport->fc_port,
			UNF_PORT_CFG_SET_SFP_SWITCH,
			(void *)&turn_on);
	if (ret != RETURN_OK) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_EQUIP_ATT, UNF_WARN,
			  "[warn]Port(0x%x) switch SFP+ %s unsuccessful.",
			  v_port_id, v_turn_on ? "On" : "Off");

		return UNF_RETURN_ERROR;
	}

	lport->b_switch_state = (enum int_e)turn_on;

	return RETURN_OK;
}

static int unf_sfp_switch_event(void *v_argc_in, void *v_argc_out)
{
	struct unf_set_sfp_argin *in = (struct unf_set_sfp_argin *)v_argc_in;

	UNF_REFERNCE_VAR(v_argc_out);
	UNF_CHECK_VALID(0x2267, UNF_TRUE, v_argc_in, return UNF_RETURN_ERROR);

	return unf_sfp_switch(in->port_id, in->turn_on);
}

int unf_cm_sfp_switch(unsigned int v_port_id, int v_bturn_on)
{
	struct unf_set_sfp_argin in = { 0 };

	in.port_id = v_port_id;
	in.turn_on = v_bturn_on;
	return unf_send_event(v_port_id, UNF_EVENT_SYN, (void *)&in,
			      (void *)NULL, unf_sfp_switch_event);
}

static int unf_get_port_speed(void *v_argc_in, void *v_argc_out)
{
	unsigned int *speed = (unsigned int *)v_argc_out;
	struct unf_low_level_port_mgr_op_s *port_mgr = NULL;
	struct unf_lport_s *lport = NULL;
	int ret = 0;
	unsigned int port_id = *(unsigned int *)v_argc_in;

	UNF_CHECK_VALID(0x2268, UNF_TRUE, v_argc_in, return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(0x2269, UNF_TRUE, v_argc_out, return UNF_RETURN_ERROR);
	lport = unf_find_lport_by_port_id(port_id);
	if (!lport) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_EQUIP_ATT, UNF_MAJOR,
			  "Cannot Find LPort by (0x%x).", port_id);

		return UNF_RETURN_ERROR;
	}

	port_mgr = &lport->low_level_func.port_mgr_op;

	if (!port_mgr->pfn_ll_port_config_get) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_EQUIP_ATT, UNF_MAJOR,
			  "Port(0x%x)'s corresponding function is NULL.",
			  port_id);

		return UNF_RETURN_ERROR;
	}

	if (lport->link_up == UNF_PORT_LINK_UP)
		ret = (int)port_mgr->pfn_ll_port_config_get(lport->fc_port,
			UNF_PORT_CFG_GET_SPEED_ACT, (void *)speed);
	else
		*speed = UNF_PORT_SPEED_UNKNOWN;

	return ret;
}

static int unf_cm_get_port_speed(unsigned int v_port_id, unsigned int *v_speed)
{
	UNF_CHECK_VALID(0x2270, UNF_TRUE, v_speed, return UNF_RETURN_ERROR);

	return unf_send_event(v_port_id, UNF_EVENT_SYN, (void *)&v_port_id,
			      (void *)v_speed, unf_get_port_speed);
}

static int unf_set_port_speed(void *v_argc_in, void *v_argc_out)
{
	unsigned int ret = RETURN_OK;
	struct unf_set_speed_argin *in =
		(struct unf_set_speed_argin *)v_argc_in;
	struct unf_lport_s *lport = NULL;

	UNF_REFERNCE_VAR(v_argc_out);
	UNF_CHECK_VALID(0x2271, UNF_TRUE, v_argc_in, return UNF_RETURN_ERROR);
	lport = unf_find_lport_by_port_id(in->port_id);
	if (!lport) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_EQUIP_ATT, UNF_MAJOR,
			  "Cannot Find LPort by (0x%x).", in->port_id);

		return UNF_RETURN_ERROR;
	}

	if (!lport->low_level_func.port_mgr_op.pfn_ll_port_config_set) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_EQUIP_ATT, UNF_MAJOR,
			  "Port(0x%x)'s corresponding function is NULL.",
			  in->port_id);

		return UNF_RETURN_ERROR;
	}

	ret = lport->low_level_func.port_mgr_op.pfn_ll_port_config_set(
		lport->fc_port,
		UNF_PORT_CFG_SET_SPEED, (void *)in->speed);

	return (int)ret;
}

int unf_cm_set_port_speed(unsigned int v_port_id, unsigned int *v_speed)
{
	struct unf_set_speed_argin in = { 0 };

	in.port_id = v_port_id;
	in.speed = v_speed;
	return unf_send_event(v_port_id, UNF_EVENT_SYN, (void *)&in,
			      (void *)NULL, unf_set_port_speed);
}

static int unf_get_port_topo(void *argc_in, void *argc_out)
{
	struct unf_lport_s *lport = NULL;
	struct unf_get_topo_argout *out = NULL;
	struct unf_low_level_port_mgr_op_s *port_mgr = NULL;
	int ret = UNF_TRUE;
	unsigned int port_id = 0;

	UNF_CHECK_VALID(0x2283, UNF_TRUE, argc_in, return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(0x2284, UNF_TRUE, argc_out, return UNF_RETURN_ERROR);
	port_id = *(unsigned int *)argc_in;
	out = (struct unf_get_topo_argout *)argc_out;

	lport = unf_find_lport_by_port_id(port_id);
	if (!lport) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_EQUIP_ATT, UNF_MAJOR,
			  "Not find LPort(0x%x).", port_id);

		return UNF_RETURN_ERROR;
	}

	port_mgr = &lport->low_level_func.port_mgr_op;

	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE,
			port_mgr->pfn_ll_port_config_get,
			return UNF_RETURN_ERROR);

	if (lport->link_up == UNF_PORT_LINK_UP) {
		ret = (int)port_mgr->pfn_ll_port_config_get(lport->fc_port,
			UNF_PORT_CFG_GET_TOPO_ACT, (void *)out->en_act_topo);
		if (ret != RETURN_OK)
			return ret;

	} else {
		*out->en_act_topo = UNF_ACT_TOP_UNKNOWN;
	}

	ret = (int)port_mgr->pfn_ll_port_config_get(lport->fc_port,
		UNF_PORT_CFG_GET_TOPO_CFG, (void *)out->topo_cfg);

	return ret;
}

int unf_cm_get_port_topo(unsigned int v_port_id, unsigned int *v_topo_cfg,
			 enum unf_act_topo_e *v_en_act_topo)
{
	struct unf_get_topo_argout out = { 0 };

	UNF_CHECK_VALID(0x2286, UNF_TRUE, v_topo_cfg, return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(0x2287, UNF_TRUE, v_en_act_topo,
			return UNF_RETURN_ERROR);

	out.en_act_topo = v_en_act_topo;
	out.topo_cfg = v_topo_cfg;

	return unf_send_event(v_port_id, UNF_EVENT_SYN, (void *)&v_port_id,
			      (void *)&out, unf_get_port_topo);
}

static int unf_set_port_topo(void *argc_in, void *argc_out)
{
	struct unf_lport_s *lport = NULL;
	struct unf_set_topo_argin *in = NULL;
	enum int_e *b_arg_out = (enum int_e *)argc_out;
	unsigned int ret = UNF_RETURN_ERROR;

	UNF_CHECK_VALID(0x2257, UNF_TRUE, argc_out, return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(0x2288, UNF_TRUE, argc_in, return UNF_RETURN_ERROR);
	in = (struct unf_set_topo_argin *)argc_in;

	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE,
			(in->topo == UNF_TOP_LOOP_MASK) ||
			(in->topo == UNF_TOP_P2P_MASK) ||
			(in->topo == UNF_TOP_AUTO_MASK),
			return UNF_RETURN_ERROR);

	lport = unf_find_lport_by_port_id(in->port_id);
	if (!lport) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_EQUIP_ATT, UNF_MAJOR,
			  "Not find LPort(0x%x).", in->port_id);

		return UNF_RETURN_ERROR;
	}

	UNF_CHECK_VALID(
		INVALID_VALUE32, UNF_TRUE,
		lport->low_level_func.port_mgr_op.pfn_ll_port_config_set,
		return UNF_RETURN_ERROR);

	ret = lport->low_level_func.port_mgr_op.pfn_ll_port_config_set(
		lport->fc_port,
		UNF_PORT_CFG_SET_TOPO, (void *)&in->topo);
	if (ret != RETURN_OK) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_EQUIP_ATT, UNF_MAJOR,
			  "Can't set port topology.");

		return UNF_RETURN_ERROR;
	}

	lport->low_level_func.lport_cfg_items.port_topology = in->topo;
	*b_arg_out = lport->b_switch_state;

	return RETURN_OK;
}

int unf_cm_set_port_topo(unsigned int v_port_id, unsigned int v_topo)
{
	struct unf_set_topo_argin in = { 0 };
	int ret = UNF_RETURN_ERROR;
	enum int_e b_switch_state = UNF_FALSE;

	in.port_id = v_port_id;
	in.topo = v_topo;

	ret = unf_send_event(v_port_id, UNF_EVENT_SYN, (void *)&in,
			     (void *)&b_switch_state, unf_set_port_topo);

	return ret;
}

int unf_set_port_bbscn(void *argc_in, void *argc_out)
{
	struct unf_lport_s *lport = NULL;
	struct unf_set_bbscn_argin *in = NULL;
	unsigned int ret = UNF_RETURN_ERROR;

	UNF_REFERNCE_VAR(argc_out);
	UNF_CHECK_VALID(0x2300, UNF_TRUE, argc_in, return UNF_RETURN_ERROR);
	in = (struct unf_set_bbscn_argin *)argc_in;

	lport = unf_find_lport_by_port_id(in->port_id);
	if (!lport) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_EQUIP_ATT, UNF_MAJOR,
			  "Not find LPort(0x%x).", in->port_id);

		return UNF_RETURN_ERROR;
	}

	UNF_CHECK_VALID(
		INVALID_VALUE32, UNF_TRUE,
		lport->low_level_func.port_mgr_op.pfn_ll_port_config_set,
		return UNF_RETURN_ERROR);

	ret = lport->low_level_func.port_mgr_op.pfn_ll_port_config_set(
		lport->fc_port,
		UNF_PORT_CFG_SET_BBSCN, (void *)&in->bb_scn);
	if (ret != RETURN_OK) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_EQUIP_ATT, UNF_MAJOR,
			  "Cannot set port BB_SC_N.");

		return UNF_RETURN_ERROR;
	}

	/* update bbsn cfg to Lport */
	lport->low_level_func.lport_cfg_items.bb_scn = in->bb_scn;

	return RETURN_OK;
}

int unf_cm_set_port_bbscn(unsigned int v_port_id, unsigned int v_bbscn)
{
	struct unf_set_bbscn_argin in = { 0 };

	in.port_id = v_port_id;
	in.bb_scn = v_bbscn;

	return unf_send_event(v_port_id, UNF_EVENT_SYN, (void *)&in,
			      (void *)NULL, unf_set_port_bbscn);
}

unsigned int unf_get_error_code_sum(struct unf_lport_s *v_lport,
				    struct unf_err_code_s *v_fc_err_code)
{
	struct unf_low_level_port_mgr_op_s *port_mgr = NULL;
	struct unf_lport_s *lport = v_lport;
	unsigned int ret = UNF_RETURN_ERROR;
	struct unf_err_code_s fc_err_code;

	UNF_CHECK_VALID(0x2328, UNF_TRUE, v_lport, return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(0x2329, UNF_TRUE, v_fc_err_code,
			return UNF_RETURN_ERROR);

	memset(&fc_err_code, 0, sizeof(struct unf_err_code_s));

	port_mgr = &lport->low_level_func.port_mgr_op;
	if (!port_mgr->pfn_ll_port_config_get) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_EQUIP_ATT, UNF_MAJOR,
			  "Port(0x%x)'s corresponding function is NULL.",
			  lport->port_id);

		return UNF_RETURN_ERROR;
	}

	ret = port_mgr->pfn_ll_port_config_get((void *)lport->fc_port,
		UNF_PORT_CFG_GET_LESB_THEN_CLR, (void *)&fc_err_code);
	if (ret != RETURN_OK)
		return UNF_RETURN_ERROR;

	if (lport->link_up != UNF_PORT_LINK_UP) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_EQUIP_ATT, UNF_INFO,
			  "LPort(0x%x) is not link up.", lport->port_id);
		memcpy(v_fc_err_code, &lport->err_code_sum,
		       sizeof(struct unf_err_code_s));

		return RETURN_OK;
	}

	lport->err_code_sum.bad_rx_char_count += fc_err_code.bad_rx_char_count;
	lport->err_code_sum.link_fail_count += fc_err_code.link_fail_count;
	lport->err_code_sum.loss_of_signal_count +=
		fc_err_code.loss_of_signal_count;
	lport->err_code_sum.loss_of_sync_count +=
		fc_err_code.loss_of_sync_count;
	lport->err_code_sum.proto_error_count += fc_err_code.proto_error_count;

	lport->err_code_sum.rx_eo_fa_count = fc_err_code.rx_eo_fa_count;
	lport->err_code_sum.dis_frame_count = fc_err_code.dis_frame_count;
	lport->err_code_sum.bad_crc_count = fc_err_code.bad_crc_count;

	memcpy(v_fc_err_code, &lport->err_code_sum,
	       sizeof(struct unf_err_code_s));

	return RETURN_OK;
}

static int unf_clear_port_error_code_sum(void *argc_in, void *argc_out)
{
	struct unf_lport_s *lport = NULL;
	unsigned int port_id = 0;
	unsigned int ret = UNF_RETURN_ERROR;

	UNF_CHECK_VALID(0x2331, UNF_TRUE, argc_in, return UNF_RETURN_ERROR);
	UNF_REFERNCE_VAR(argc_out);

	port_id = *(unsigned int *)argc_in;
	lport = unf_find_lport_by_port_id(port_id);
	if (!lport) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_EQUIP_ATT, UNF_MAJOR,
			  "Cannot find LPort(0x%x).", port_id);

		return UNF_RETURN_ERROR;
	}

	if (!lport->low_level_func.port_mgr_op.pfn_ll_port_config_get) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_EQUIP_ATT, UNF_MAJOR,
			  "Port(0x%x)'s corresponding function is NULL.",
			  port_id);

		return UNF_RETURN_ERROR;
	}

	ret = lport->low_level_func.port_mgr_op.pfn_ll_port_config_get(
		(void *)lport->fc_port,
		UNF_PORT_CFG_CLR_LESB, NULL);
	if (ret != RETURN_OK)
		return UNF_RETURN_ERROR;

	memset(&lport->err_code_sum, 0, sizeof(struct unf_err_code_s));

	return RETURN_OK;
}

int unf_cm_clear_port_error_code_sum(unsigned int v_port_id)
{
	return unf_send_event(v_port_id, UNF_EVENT_SYN, (void *)&v_port_id,
			      (void *)NULL, unf_clear_port_error_code_sum);
}

static int unf_update_lport_sfp_info(struct unf_lport_s *v_lport,
				     enum unf_port_config_get_op_e v_type)
{
	struct unf_lport_s *lport = NULL;
	int ret = UNF_RETURN_ERROR;

	UNF_CHECK_VALID(0x2332, UNF_TRUE, v_lport, return UNF_RETURN_ERROR);
	lport = v_lport;

	if (!lport->low_level_func.port_mgr_op.pfn_ll_port_config_get) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_EQUIP_ATT, UNF_MAJOR,
			  "Port(0x%x)'s corresponding function is NULL.",
			  lport->port_id);

		return UNF_RETURN_ERROR;
	}

	ret = (int)(lport->low_level_func.port_mgr_op.pfn_ll_port_config_get(
		(void *)lport->fc_port,
		v_type, (void *)&lport->sfp_info));

	return ret;
}

static int unf_translate_sfp_status(struct unf_lport_s *v_lport,
				    struct unf_get_sfp_argout *v_out)
{
	struct unf_lport_s *lport = v_lport;
	int ret = UNF_RETURN_ERROR;

	switch (lport->sfp_info.status) {
	case UNF_SFP_PRESENT_FAIL:
		*v_out->status = DRV_CABLE_CONNECTOR_NONE;
		ret = RETURN_OK;
		break;
	case UNF_SFP_POWER_FAIL:
		*v_out->status = DRV_CABLE_CONNECTOR_INVALID;
		ret = RETURN_OK;
		break;
	case UNF_9545_FAIL:
		*v_out->status = DRV_CABLE_CONNECTOR_INVALID;
		ret = RETURN_OK;
		break;
	default:
		*v_out->status = DRV_CABLE_CONNECTOR_BUTT;
		ret = UNF_RETURN_ERROR;
		break;
	}

	return ret;
}

static void unf_record_chip_fault(struct unf_lport_s *v_lport)
{
#define UNF_CHIP_FAULT_MAX_CHECK_TIME 3

	if (v_lport->sfp_info.status == UNF_9545_FAIL) {
		/* If there are 9545 fault,explain that the sfp is power on,
		 * and reset sfp_power_fault_count
		 */
		v_lport->sfp_power_fault_count = 0;

		if (v_lport->sfp_9545_fault_count <
		    UNF_CHIP_FAULT_MAX_CHECK_TIME) {
			v_lport->sfp_9545_fault_count++;
		} else {
			v_lport->chip_info->sfp_9545_fault = UNF_TRUE;
			v_lport->sfp_9545_fault_count = 0;
		}
	} else if (v_lport->sfp_info.status == UNF_SFP_POWER_FAIL) {
		if (v_lport->sfp_power_fault_count <
		    UNF_CHIP_FAULT_MAX_CHECK_TIME) {
			v_lport->sfp_power_fault_count++;
		} else {
			v_lport->chip_info->sfp_power_fault = UNF_TRUE;
			v_lport->sfp_power_fault_count = 0;
		}
	}
}

int unf_check_sfp_tx_fault(struct unf_lport_s *v_lport,
			   struct unf_sfp_info_s *v_sfp_info)
{
	/* 24 hours ms(24*60*60*1000) */
#define UNF_SFP_TXFALT_RECOVER_INTERVEL 86400000

	struct unf_sfp_info_s *sfp_info = NULL;
	struct unf_lport_s *lport = NULL;

	sfp_info = v_sfp_info;
	lport = v_lport;

	if (sfp_info->sfp_info_a2.diag.status_ctrl.tx_fault_state == 0)
		return RETURN_OK;

	/* Repair conditions:
	 * 1 port linkdown;
	 * 2 from the last repair more than 24 hours;
	 * 3 sfp is on
	 */
	if ((lport->link_up == UNF_PORT_LINK_DOWN) &&
	    (lport->b_switch_state) &&
	    ((lport->last_tx_fault_jif == 0) ||
	     (jiffies_to_msecs(jiffies - lport->last_tx_fault_jif) >
	      UNF_SFP_TXFALT_RECOVER_INTERVEL))) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_EQUIP_ATT, UNF_MAJOR,
			  "LPort(0x%x) stat(0x%x) jiff(%ld) lastjiff(%llu) Ctrl(0x%x) TxFault set 1.",
			  lport->port_id, lport->link_up, jiffies,
			  lport->last_tx_fault_jif,
			  *((unsigned char *)
			  &sfp_info->sfp_info_a2.diag.status_ctrl));

		lport->last_tx_fault_jif = jiffies;
		(void)unf_sfp_switch(lport->port_id, UNF_FALSE);
		msleep(100);

		/* Around quickly switch port FW state error problem */
		(void)unf_sfp_switch(lport->port_id, UNF_TRUE);

		return UNF_RETURN_ERROR;
	}

	return RETURN_OK;
}

static int unf_get_sfp_info(void *argc_in, void *argc_out)
{
	struct unf_lport_s *lport = NULL;
	struct unf_get_sfp_argout *out = NULL;
	unsigned int port_id = 0;
	int ret = RETURN_OK;

	UNF_CHECK_VALID(0x2333, UNF_TRUE, argc_in, return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(0x2334, UNF_TRUE, argc_out, return UNF_RETURN_ERROR);

	port_id = *(unsigned int *)argc_in;
	out = (struct unf_get_sfp_argout *)argc_out;
	lport = unf_find_lport_by_port_id(port_id);
	if (!lport) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_EQUIP_ATT, UNF_MAJOR,
			  "Cannot find LPort(0x%x).", port_id);

		return UNF_RETURN_ERROR;
	}

	lport->sfp_info.status = 0;

	ret = unf_update_lport_sfp_info(lport, UNF_PORT_CFG_GET_SFP_INFO);

	if (ret == RETURN_OK) {
		lport->sfp_power_fault_count = 0;
		lport->sfp_9545_fault_count = 0;
		*out->status = DRV_CABLE_CONNECTOR_OPTICAL;
		if (unf_check_sfp_tx_fault(
			lport,
			&lport->sfp_info.sfp_eeprom_info.sfp_info) ==
		    UNF_RETURN_ERROR) {
			return UNF_RETURN_ERROR;
		}

		memcpy(out->sfp_info, &lport->sfp_info.sfp_eeprom_info,
		       sizeof(union unf_sfp_eeprome_info));
		ret = RETURN_OK;
	} else {
		ret = unf_translate_sfp_status(lport, out);

		unf_record_chip_fault(lport);

		UNF_TRACE(UNF_EVTLOG_IO_INFO, UNF_LOG_IO_ATT, UNF_MAJOR,
			  "Port(0x%x)'s getsfpinfo fail, sfp status(0x%x).",
			  lport->port_id, lport->sfp_info.status);
	}

	return ret;
}

int unf_cm_get_sfp_info(unsigned int v_port_id, unsigned int *v_status,
			union unf_sfp_eeprome_info *v_sfp_info,
			unsigned int *sfp_type)
{
	struct unf_lport_s *lport = NULL;
	struct unf_get_sfp_argout out = { 0 };

	lport = unf_find_lport_by_port_id(v_port_id);
	if (!lport)
		return UNF_RETURN_ERROR;

	UNF_CHECK_VALID(0x2335, UNF_TRUE, v_status, return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(0x2336, UNF_TRUE, v_sfp_info, return UNF_RETURN_ERROR);

	out.status = v_status;
	out.sfp_info = v_sfp_info;

	if (global_lport_mgr.b_start_work == UNF_FALSE) {
		UNF_TRACE(UNF_EVTLOG_IO_INFO, UNF_LOG_IO_ATT, UNF_MAJOR,
			  "Port(0x%x) have not start work, return.", v_port_id);
		return UNF_RETURN_ERROR;
	}

	*sfp_type = lport->low_level_func.sfp_type;
	return unf_send_event(v_port_id, UNF_EVENT_SYN, (void *)&v_port_id,
			      (void *)&out, unf_get_sfp_info);
}

int unf_cm_reset_port(unsigned int v_port_id)
{
	int ret = UNF_RETURN_ERROR;

	ret = unf_send_event(v_port_id, UNF_EVENT_SYN, (void *)&v_port_id,
			     (void *)NULL, unf_reset_port);
	return ret;
}

int unf_lport_reset_port(struct unf_lport_s *v_lport, unsigned int v_flag)
{
	UNF_CHECK_VALID(0x2352, UNF_TRUE, v_lport, return UNF_RETURN_ERROR);

	return unf_send_event(v_lport->port_id, v_flag,
			      (void *)&v_lport->port_id,
			      (void *)NULL,
			      unf_reset_port);
}

static inline unsigned int unf_get_loop_alpa(struct unf_lport_s *v_lport,
					     void *v_loop_alpa)
{
	unsigned int ret = UNF_RETURN_ERROR;

	UNF_CHECK_VALID(0x2357, UNF_TRUE,
			v_lport->low_level_func.port_mgr_op.pfn_ll_port_config_get,
			return UNF_RETURN_ERROR);

	ret = v_lport->low_level_func.port_mgr_op.pfn_ll_port_config_get(
		v_lport->fc_port,
		UNF_PORT_CFG_GET_LOOP_ALPA, v_loop_alpa);
	return ret;
}

static unsigned int unf_lport_enter_private_loop_login(
					struct unf_lport_s *v_lport)
{
	struct unf_lport_s *lport = v_lport;
	unsigned long flag = 0;
	unsigned int ret = UNF_RETURN_ERROR;

	UNF_CHECK_VALID(0x2358, UNF_TRUE, v_lport, return UNF_RETURN_ERROR);

	spin_lock_irqsave(&lport->lport_state_lock, flag);
	unf_lport_stat_ma(lport, UNF_EVENT_LPORT_READY);
	/* LPort: LINK_UP --> READY */
	spin_unlock_irqrestore(&lport->lport_state_lock, flag);

	unf_lport_update_topo(lport, UNF_ACT_TOP_PRIVATE_LOOP);

	/* NOP: check L_Port state */
	if (atomic_read(&lport->port_no_operater_flag) == UNF_LPORT_NOP) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT, UNF_MAJOR,
			  "[info]Port(0x%x) is NOP, do nothing",
			  lport->port_id);

		return RETURN_OK;
	}

	/* INI: check L_Port mode */
	if ((lport->options & UNF_PORT_MODE_INI) != UNF_PORT_MODE_INI) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT, UNF_MAJOR,
			  "[info]Port(0x%x) has no INI feature(0x%x), do nothing",
			  lport->port_id, lport->options);

		return RETURN_OK;
	}

	if (lport->disc.unf_disc_temp.pfn_unf_disc_start) {
		ret = lport->disc.unf_disc_temp.pfn_unf_disc_start(lport);
		if (ret != RETURN_OK) {
			UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT,
				  UNF_WARN,
				  "[warn]Port(0x%x) with nportid(0x%x) start discovery failed",
				  lport->port_id, lport->nport_id);
		}
	}

	return ret;
}

unsigned int unf_lport_login(struct unf_lport_s *v_lport,
			     enum unf_act_topo_e v_en_act_topo)
{
	unsigned int loop_alpa = 0;
	unsigned int ret = RETURN_OK;
	unsigned long flag = 0;

	UNF_CHECK_VALID(0x2359, UNF_TRUE, v_lport, return UNF_RETURN_ERROR);

	/* 1. Update (set) L_Port topo which get from low level */
	unf_lport_update_topo(v_lport, v_en_act_topo);

	spin_lock_irqsave(&v_lport->lport_state_lock, flag);

	/* 2. Link state check */
	if (v_lport->link_up != UNF_PORT_LINK_UP) {
		spin_unlock_irqrestore(&v_lport->lport_state_lock, flag);

		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT, UNF_WARN,
			  "[warn]Port(0x%x) with link_state(0x%x) port_state(0x%x) when login",
			  v_lport->port_id, v_lport->link_up,
			  v_lport->en_states);

		return UNF_RETURN_ERROR;
	}

	/* 3. Update L_Port state */
	unf_lport_stat_ma(v_lport, UNF_EVENT_LPORT_LINK_UP);
	/* LPort: INITIAL --> LINK UP */
	spin_unlock_irqrestore(&v_lport->lport_state_lock, flag);

	UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT, UNF_INFO,
		  "[info]LOGIN: Port(0x%x) start to login with topology(0x%x)",
		  v_lport->port_id, v_lport->en_act_topo);

	/* 4. Start logoin */
	if ((v_en_act_topo == UNF_TOP_P2P_MASK) ||
	    (v_en_act_topo == UNF_ACT_TOP_P2P_FABRIC) ||
	    (v_en_act_topo == UNF_ACT_TOP_P2P_DIRECT)) {
		/* P2P or Fabric mode */
		ret = unf_lport_enter_flogi(v_lport);
	} else if (v_en_act_topo == UNF_ACT_TOP_PUBLIC_LOOP) {
		/* Public loop */
		(void)unf_get_loop_alpa(v_lport, &loop_alpa);

		/* Before FLOGI ALPA just low 8 bit after FLOGI ACC switch
		 * will assign complete addresses
		 */
		spin_lock_irqsave(&v_lport->lport_state_lock, flag);
		v_lport->nport_id = loop_alpa;
		spin_unlock_irqrestore(&v_lport->lport_state_lock, flag);

		ret = unf_lport_enter_flogi(v_lport);
	} else if (v_en_act_topo == UNF_ACT_TOP_PRIVATE_LOOP) {
		/* Private loop */
		(void)unf_get_loop_alpa(v_lport, &loop_alpa);

		spin_lock_irqsave(&v_lport->lport_state_lock, flag);
		v_lport->nport_id = loop_alpa;
		spin_unlock_irqrestore(&v_lport->lport_state_lock, flag);

		ret = unf_lport_enter_private_loop_login(v_lport);
	} else {
		UNF_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_LOGIN_ATT, UNF_ERR,
			  "[err]LOGIN: Port(0x%x) login with unknown topology(0x%x)",
			  v_lport->port_id, v_lport->en_act_topo);
	}

	return ret;
}

static unsigned int unf_port_link_up(struct unf_lport_s *v_lport,
				     void *v_in_put)
{
	struct unf_lport_s *lport = v_lport;
	unsigned int ret = RETURN_OK;
	enum unf_act_topo_e en_act_topo = UNF_ACT_TOP_UNKNOWN;
	unsigned long flag = 0;

	UNF_CHECK_VALID(0x2361, UNF_TRUE, v_lport, return UNF_RETURN_ERROR);
	UNF_REFERNCE_VAR(v_in_put);

	/* If NOP state, stop */
	if (atomic_read(&lport->port_no_operater_flag) == UNF_LPORT_NOP) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_LOGIN_ATT, UNF_ERR,
			  "[warn]Port(0x%x) is NOP and do nothing",
			  lport->port_id);

		return RETURN_OK;
	}

	/* Update port state */
	spin_lock_irqsave(&lport->lport_state_lock, flag);
	lport->link_up = UNF_PORT_LINK_UP;
	lport->speed = *((unsigned int *)v_in_put);
	unf_set_lport_state(v_lport, UNF_LPORT_ST_INITIAL);
	/* INITIAL state */
	spin_unlock_irqrestore(&lport->lport_state_lock, flag);

	/* set hot pool wait state: so far, do not care */
	unf_set_hot_pool_wait_state(lport, UNF_TRUE);

	lport->enhanced_features |= UNF_LPORT_ENHANCED_FEATURE_READ_SFP_ONCE;

	/* Get port active topopolgy (from low level) */
	if (!lport->low_level_func.port_mgr_op.pfn_ll_port_config_get) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_LOGIN_ATT, UNF_ERR,
			  "[warn]Port(0x%x) get topo function is NULL",
			  lport->port_id);

		return UNF_RETURN_ERROR;
	}
	ret = lport->low_level_func.port_mgr_op.pfn_ll_port_config_get(
		lport->fc_port,
		UNF_PORT_CFG_GET_TOPO_ACT, (void *)&en_act_topo);

	if (ret != RETURN_OK) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT, UNF_ERR,
			  "[warn]Port(0x%x) get topo from low level failed",
			  lport->port_id);

		return UNF_RETURN_ERROR;
	}

	/* Start Login process */
	ret = unf_lport_login(lport, en_act_topo);

	unf_report_io_dm_event(lport, UNF_PORT_LINK_UP, 0);
	return ret;
}

static unsigned int unf_port_link_down(struct unf_lport_s *v_lport,
				       void *v_in_put)
{
	unsigned long flag = 0;
	struct unf_lport_s *lport = NULL;

	UNF_CHECK_VALID(0x2363, UNF_FALSE, v_lport, return UNF_RETURN_ERROR);
	UNF_REFERNCE_VAR(v_in_put);
	lport = v_lport;
	unf_report_io_dm_event(lport, UNF_PORT_LINK_DOWN, 0);

	/* To prevent repeated reporting linkdown */
	spin_lock_irqsave(&lport->lport_state_lock, flag);
	lport->speed = UNF_PORT_SPEED_UNKNOWN;
	lport->en_act_topo = UNF_ACT_TOP_UNKNOWN;
	if (lport->link_up == UNF_PORT_LINK_DOWN) {
		spin_unlock_irqrestore(&lport->lport_state_lock, flag);

		return RETURN_OK;
	}
	unf_lport_stat_ma(lport, UNF_EVENT_LPORT_LINK_DOWN);
	unf_reset_lport_params(lport);
	spin_unlock_irqrestore(&lport->lport_state_lock, flag);

	unf_set_hot_pool_wait_state(lport, UNF_FALSE);

	/*
	 * clear I/O:
	 * 1. INI do ABORT only,
	 * for INI: busy/delay/delay_transfer/wait
	 * Clean L_Port/V_Port Link Down I/O: only set ABORT tag
	 */
	unf_flush_disc_event(&lport->disc, NULL);

	unf_clean_link_down_io(lport, UNF_FALSE);

	/* for L_Port's R_Ports */
	unf_clean_linkdown_rport(lport);
	/* for L_Port's all Vports */
	unf_linkdown_all_vports(v_lport);
	return RETURN_OK;
}

static unsigned int unf_port_abnormal_reset(struct unf_lport_s *v_lport,
					    void *v_in_put)
{
	unsigned int ret = UNF_RETURN_ERROR;
	struct unf_lport_s *lport = NULL;

	UNF_CHECK_VALID(0x2363, UNF_FALSE, v_lport, return UNF_RETURN_ERROR);

	UNF_REFERNCE_VAR(v_in_put);

	lport = v_lport;

	ret = (unsigned int)unf_lport_reset_port(lport, UNF_EVENT_ASYN);

	return ret;
}

static unsigned int unf_port_reset_start(struct unf_lport_s *v_lport,
					 void *v_in_put)
{
	unsigned int ret = RETURN_OK;
	unsigned long flag = 0;

	UNF_CHECK_VALID(0x2364, UNF_FALSE, v_lport, return UNF_RETURN_ERROR);
	UNF_REFERNCE_VAR(v_in_put);

	spin_lock_irqsave(&v_lport->lport_state_lock, flag);
	unf_set_lport_state(v_lport, UNF_LPORT_ST_RESET);
	spin_unlock_irqrestore(&v_lport->lport_state_lock, flag);

	UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT, UNF_INFO,
		  "Port(0x%x) begin to reset.", v_lport->port_id);

	return ret;
}

static unsigned int unf_port_reset_end(struct unf_lport_s *v_lport,
				       void *v_in_put)
{
	unsigned long flag = 0;

	UNF_CHECK_VALID(0x2365, UNF_FALSE, v_lport, return UNF_RETURN_ERROR);

	UNF_REFERNCE_VAR(v_in_put);

	UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT, UNF_INFO,
		  "Port(0x%x) reset end.", v_lport->port_id);

	/* Task management command returns success and avoid
	 * repair measures case offline device
	 */
	unf_wakeup_scsi_task_cmnd(v_lport);

	spin_lock_irqsave(&v_lport->lport_state_lock, flag);
	unf_set_lport_state(v_lport, UNF_LPORT_ST_INITIAL);
	spin_unlock_irqrestore(&v_lport->lport_state_lock, flag);

	return RETURN_OK;
}

static unsigned int unf_port_nop(struct unf_lport_s *v_lport, void *v_in_put)
{
	struct unf_lport_s *lport = NULL;
	unsigned long flag = 0;

	UNF_CHECK_VALID(0x2366, UNF_FALSE, v_lport, return UNF_RETURN_ERROR);
	UNF_REFERNCE_VAR(v_in_put);
	lport = v_lport;

	atomic_set(&lport->port_no_operater_flag, UNF_LPORT_NOP);

	spin_lock_irqsave(&lport->lport_state_lock, flag);
	unf_lport_stat_ma(lport, UNF_EVENT_LPORT_LINK_DOWN);
	unf_reset_lport_params(lport);
	spin_unlock_irqrestore(&lport->lport_state_lock, flag);

	/* Set Tag prevent pending I/O to wait_list when close sfp failed */
	unf_set_hot_pool_wait_state(lport, UNF_FALSE);

	unf_flush_disc_event(&lport->disc, NULL);

	/* L_Port/V_Port's I/O(s): Clean Link Down I/O: Set Abort Tag */
	unf_clean_link_down_io(lport, UNF_FALSE);

	/* L_Port/V_Port's R_Port(s): report link down event to
	 * scsi & clear resource
	 */
	unf_clean_linkdown_rport(lport);
	unf_linkdown_all_vports(lport);
	UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT, UNF_MAJOR,
		  "[info]Port(0x%x) report NOP event done",
		  lport->nport_id);

	return RETURN_OK;
}

static unsigned int unf_port_clean_done(struct unf_lport_s *v_lport,
					void *v_in_put)
{
	UNF_CHECK_VALID(0x2691, UNF_FALSE, v_lport, return UNF_RETURN_ERROR);

	UNF_REFERNCE_VAR(v_in_put);

	/* when port reset,delte delete all Rport immediately,
	 * in order to remove immediately for resources
	 */
	unf_clean_linkdown_rport(v_lport);

	return RETURN_OK;
}

static unsigned int unf_port_begin_remove(struct unf_lport_s *v_lport,
					  void *v_in_put)
{
	UNF_CHECK_VALID(0x2691, UNF_FALSE, v_lport, return UNF_RETURN_ERROR);

	UNF_REFERNCE_VAR(v_in_put);

	/* Cancel route timer delay work */
	unf_destroy_lport_route(v_lport);

	return RETURN_OK;
}

static unsigned int unf_get_pcie_link_state(struct unf_lport_s *v_lport)
{
	struct unf_lport_s *lport = v_lport;
	int link_state = UNF_TRUE;
	unsigned int ret = UNF_RETURN_ERROR;

	UNF_CHECK_VALID(0x2257, UNF_TRUE, v_lport, return UNF_RETURN_ERROR);

	UNF_CHECK_VALID(
		INVALID_VALUE32, UNF_TRUE,
		lport->low_level_func.port_mgr_op.pfn_ll_port_config_get,
		return UNF_RETURN_ERROR);

	ret = lport->low_level_func.port_mgr_op.pfn_ll_port_config_get(
		lport->fc_port,
		UNF_PORT_CFG_GET_PCIE_LINK_STATE, (void *)&link_state);
	if (ret != RETURN_OK || link_state != UNF_TRUE) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_EQUIP_ATT, UNF_KEVENT,
			  "[err]Can't Get Pcie Link State");

		return UNF_RETURN_ERROR;
	}

	return RETURN_OK;
}

void unf_root_lport_ref_dec(struct unf_lport_s *v_lport)
{
	unsigned long flags = 0;
	unsigned long lport_flags = 0;
	unsigned int ret = UNF_RETURN_ERROR;

	UNF_CHECK_VALID(0x2385, UNF_TRUE, v_lport, return);

	UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT, UNF_INFO,
		  "[info]Port(0x%p) port_id(0x%x) reference count is %d",
		  v_lport, v_lport->port_id,
		  atomic_read(&v_lport->lport_ref_cnt));

	spin_lock_irqsave(&global_lport_mgr.global_lport_list_lock, flags);
	spin_lock_irqsave(&v_lport->lport_state_lock, lport_flags);
	if (atomic_dec_and_test(&v_lport->lport_ref_cnt)) {
		spin_unlock_irqrestore(&v_lport->lport_state_lock, lport_flags);

		list_del(&v_lport->entry_lport);
		global_lport_mgr.lport_sum--;

		/* Put L_Port to destroy list for debuging */
		list_add_tail(&v_lport->entry_lport,
			      &global_lport_mgr.list_destroy_head);
		spin_unlock_irqrestore(&global_lport_mgr.global_lport_list_lock,
				       flags);

		ret = unf_schedule_global_event((void *)v_lport,
						UNF_GLOBAL_EVENT_ASYN,
						unf_lport_destroy);
		if (ret != RETURN_OK)
			UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_EVENT,
				  UNF_CRITICAL,
				  "[warn]Schedule global event faile. remain nodes(0x%x)",
				  global_event_queue.list_number);
	} else {
		spin_unlock_irqrestore(&v_lport->lport_state_lock, lport_flags);
		spin_unlock_irqrestore(&global_lport_mgr.global_lport_list_lock,
				       flags);
	}
}

void unf_lport_ref_dec_to_destroy(struct unf_lport_s *v_lport)
{
	if (v_lport->root_lport != v_lport)
		unf_vport_ref_dec(v_lport);
	else
		unf_root_lport_ref_dec(v_lport);
}

void unf_lport_route_work(struct work_struct *v_work)
{
#define MAX_INTERVAL_TIMES 60

	struct unf_lport_s *lport = NULL;
	int ret = 0;
	struct unf_err_code_s fc_err_code;

	UNF_CHECK_VALID(0x2388, UNF_TRUE, v_work, return);

	lport = container_of(v_work, struct unf_lport_s, route_timer_work.work);
	if (unlikely(!lport)) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_EQUIP_ATT,
			  UNF_KEVENT, "[err]LPort is NULL");

		return;
	}

	if (unlikely(lport->b_port_removing == UNF_TRUE)) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_EQUIP_ATT, UNF_KEVENT,
			  "[warn]LPort(0x%x) route work is closing.",
			  lport->port_id);

		unf_lport_ref_dec_to_destroy(lport);

		return;
	}

	if (unlikely(unf_get_pcie_link_state(lport)))
		lport->pcie_link_down_cnt++;
	else
		lport->pcie_link_down_cnt = 0;

	if (lport->pcie_link_down_cnt >= 3) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_EQUIP_ATT, UNF_KEVENT,
			  "[warn]LPort(0x%x) detected pcie linkdown, closing route work",
			  lport->port_id);
		lport->b_pcie_linkdown = UNF_TRUE;
		unf_free_lport_all_xchg(lport);
		unf_lport_ref_dec_to_destroy(lport);
		return;
	}

	if (unlikely(UNF_LPORT_CHIP_ERROR(lport))) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_EQUIP_ATT, UNF_KEVENT,
			  "[warn]LPort(0x%x) reported chip error, closing route work. ",
			  lport->port_id);

		unf_lport_ref_dec_to_destroy(lport);

		return;
	}

	if (lport->enhanced_features &
	    UNF_LPORT_ENHANCED_FEATURE_CLOSE_FW_ROUTE) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_EQUIP_ATT, UNF_KEVENT,
			  "[warn]User close LPort(0x%x) route work. ",
			  lport->port_id);

		unf_lport_ref_dec_to_destroy(lport);

		return;
	}
	if (atomic_read(&lport->err_code_obtain_freq) ==  0) {
		memset(&fc_err_code, 0, sizeof(struct unf_err_code_s));
		unf_get_error_code_sum(lport, &fc_err_code);
		atomic_inc(&lport->err_code_obtain_freq);
	} else if (atomic_read(&lport->err_code_obtain_freq) ==
		   MAX_INTERVAL_TIMES) {
		atomic_set(&lport->err_code_obtain_freq, 0);
	} else {
		atomic_inc(&lport->err_code_obtain_freq);
	}
	/* Scheduling 1 second */
	ret = queue_delayed_work(
		unf_work_queue, &lport->route_timer_work,
		(unsigned long)msecs_to_jiffies(UNF_LPORT_POLL_TIMER));
	if (ret == 0) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_EQUIP_ATT, UNF_KEVENT,
			  "[warn]LPort(0x%x) schedule work unsuccessful.",
			  lport->port_id);

		unf_lport_ref_dec_to_destroy(lport);
	}
}

int unf_cm_get_port_info(void *argc_in, void *argc_out)
{
	struct unf_lport_s *lport = NULL;
	struct unf_get_port_info_argout *port_info = NULL;

	UNF_CHECK_VALID(0x2398, UNF_TRUE, argc_in, return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(0x2398, UNF_TRUE, argc_out, return UNF_RETURN_ERROR);

	lport = (struct unf_lport_s *)argc_in;
	port_info = (struct unf_get_port_info_argout *)argc_out;

	if (!lport->low_level_func.port_mgr_op.pfn_ll_port_config_get) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_REG_ATT, UNF_MAJOR,
			  "Port(0x%x)'s corresponding function is NULL.",
			  lport->port_id);

		return UNF_RETURN_ERROR;
	}

	if (lport->low_level_func.port_mgr_op.pfn_ll_port_config_get(
		lport->fc_port,
		UNF_PORT_CFG_GET_PORT_INFO, port_info) !=
	    RETURN_OK) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_REG_ATT, UNF_MAJOR,
			  "Port(0x%x) get current info failed.",
			  lport->port_id);

		return UNF_RETURN_ERROR;
	}

	return RETURN_OK;
}

static unsigned int unf_get_lport_current_info(struct unf_lport_s *v_lport)
{
	struct unf_get_port_info_argout port_info = { 0 };
	unsigned int ret = UNF_RETURN_ERROR;
	struct unf_lport_s *lport = NULL;

	UNF_CHECK_VALID(0x2403, UNF_TRUE, v_lport, return UNF_RETURN_ERROR);

	lport = unf_find_lport_by_port_id(v_lport->port_id);

	if (!lport)
		return UNF_RETURN_ERROR;

	ret = (unsigned int)unf_send_event(lport->port_id, UNF_EVENT_SYN,
					   (void *)lport,
					   (void *)&port_info,
					   unf_cm_get_port_info);
	if (ret != RETURN_OK) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_REG_ATT, UNF_MAJOR,
			  "UNF_GetPortCurrentInfo SendEvent(unf_cm_get_port_info) fail.");

		return UNF_RETURN_ERROR;
	}

	lport->low_level_func.sfp_speed = port_info.sfp_speed;

	return RETURN_OK;
}

int unf_set_link_lose_tmo_to_up(struct unf_lport_s *v_lport,
				struct unf_flash_link_tmo_s *v_link_tmo)
{
	int ret = UNF_RETURN_ERROR;
	struct unf_flash_data_s flash_data;

	if ((!v_lport) || (!v_link_tmo) ||
	    (sizeof(struct unf_flash_data_s) > HIFC_FLASH_DATA_MAX_LEN)) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_NORMAL, UNF_KEVENT,
			  "[warn]set link tmo param check fail");
		return ret;
	}
	memset(&flash_data, 0, sizeof(struct unf_flash_data_s));

	if (!v_lport->low_level_func.port_mgr_op.pfn_ll_port_config_get) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_NORMAL, UNF_KEVENT,
			  "[warn]link tmo fun null");
		return ret;
	}
	if (v_lport->low_level_func.port_mgr_op.pfn_ll_port_config_get(
		v_lport->fc_port,
		UNF_PORT_CFG_GET_FLASH_DATA_INFO, &flash_data) !=
	    RETURN_OK) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_NORMAL, UNF_KEVENT,
			  "[warn]get link tmo to up fail");
		return ret;
	}

	memcpy(&flash_data.link_tmo, v_link_tmo, HIFC_FLASH_LINK_TMO_MAX_LEN);

	if (!v_lport->low_level_func.port_mgr_op.pfn_ll_port_config_set) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_NORMAL, UNF_KEVENT,
			  "[warn]set link tmo fun null");
		return ret;
	}

	if (v_lport->low_level_func.port_mgr_op.pfn_ll_port_config_set(
		v_lport->fc_port, UNF_PORT_CFG_SET_FLASH_DATA_INFO,
		&flash_data) !=
	    RETURN_OK) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_NORMAL, UNF_KEVENT,
			  "[warn]set link tmo to up fail");
		return ret;
	}
	ret = RETURN_OK;

	return ret;
}

int unf_set_link_lose_tmo(struct unf_lport_s *v_lport, int time_out)
{
	struct unf_flash_link_tmo_s flash_link_tmo;
	int ret = UNF_RETURN_ERROR;
	unsigned int link_tmo = (unsigned int)time_out;

	memset(&flash_link_tmo, 0, sizeof(struct unf_flash_link_tmo_s));

	if (!v_lport) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_NORMAL,
			  UNF_KEVENT, "[warn]set link tmo lport  null");
		return ret;
	}

	/* 1. update gloabl var */
	if ((int)atomic_read(&v_lport->link_lose_tmo) == time_out)
		return RETURN_OK;

	atomic_set(&v_lport->link_lose_tmo, time_out);

	flash_link_tmo.writeflag = HIFC_MGMT_TMO_MAGIC_NUM;
	flash_link_tmo.link_tmo0 = (unsigned char)link_tmo;
	flash_link_tmo.link_tmo1 = (unsigned char)(link_tmo >> 8);
	flash_link_tmo.link_tmo2 = (unsigned char)(link_tmo >> 16);
	flash_link_tmo.link_tmo3 = (unsigned char)(link_tmo >> 24);

	/* 2. write to up */
	ret = unf_set_link_lose_tmo_to_up(v_lport, &flash_link_tmo);

	return ret;
}

int unf_set_link_lose_tmo_to_all(int time_out)
{
	int ret = RETURN_OK;
	struct list_head list_lport_tmp_head;
	struct list_head *node = NULL;
	struct list_head *next_node = NULL;
	struct unf_lport_s *lport = NULL;
	unsigned long flags = 0;

	INIT_LIST_HEAD(&list_lport_tmp_head);
	spin_lock_irqsave(&global_lport_mgr.global_lport_list_lock, flags);
	list_for_each_safe(node, next_node,
			   &global_lport_mgr.list_lport_list_head) {
		lport = list_entry(node, struct unf_lport_s, entry_lport);
		list_del_init(&lport->entry_lport);
		list_add_tail(&lport->entry_lport, &list_lport_tmp_head);
		(void)unf_lport_refinc(lport);
	}
	spin_unlock_irqrestore(&global_lport_mgr.global_lport_list_lock, flags);

	while (!list_empty(&list_lport_tmp_head)) {
		node = (&list_lport_tmp_head)->next;
		lport = list_entry(node, struct unf_lport_s, entry_lport);
		if (lport)
			unf_set_link_lose_tmo(lport, time_out);

		spin_lock_irqsave(&global_lport_mgr.global_lport_list_lock,
				  flags);
		list_del_init(&lport->entry_lport);
		list_add_tail(&lport->entry_lport,
			      &global_lport_mgr.list_lport_list_head);
		spin_unlock_irqrestore(&global_lport_mgr.global_lport_list_lock,
				       flags);

		unf_lport_ref_dec_to_destroy(lport);
	}

	return ret;
}

static int unf_cm_adm_show_xchg(struct unf_lport_s *v_lport,
				struct unf_hinicam_pkg *v_input)
{
	int ret = UNF_RETURN_ERROR;
	struct unf_xchg_mgr_s *xchg_mgr = NULL;
	struct unf_xchg_s *xchg = NULL;
	struct list_head *xchg_node = NULL;
	struct list_head *next_xchg_node = NULL;
	unsigned long flags = 0;
	unsigned int aborted = 0;
	unsigned int ini_busy = 0;
	unsigned int tgt_busy = 0;
	unsigned int delay = 0;
	unsigned int free = 0;
	unsigned int wait = 0;
	unsigned int sfs_free = 0;
	unsigned int sfs_busy = 0;
	unsigned int i;
	struct unf_adm_xchg *buff_out = NULL;

	buff_out = (struct unf_adm_xchg *)v_input->buff_out;
	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE, *v_input->out_size >=
		sizeof(struct unf_adm_xchg), return UNF_RETURN_ERROR);

	for (i = 0; i < UNF_EXCHG_MGR_NUM; i++) {
		xchg_mgr = unf_get_xchg_mgr_by_lport(v_lport, i);
		if (!xchg_mgr)
			continue;

		if (!xchg_mgr->hot_pool)
			continue;

		/* hot Xchg */
		spin_lock_irqsave(&xchg_mgr->hot_pool->xchg_hot_pool_lock,
				  flags);

		UNF_TRACE(0x2659, UNF_LOG_NORMAL, UNF_INFO, "ini busy :");
		list_for_each_safe(xchg_node, next_xchg_node,
				   &xchg_mgr->hot_pool->ini_busylist) {
			ini_busy++;

			xchg = list_entry(xchg_node, struct unf_xchg_s,
					  list_xchg_entry);
			UNF_TRACE(0x2660, UNF_LOG_NORMAL, UNF_INFO,
				  "0x%p--0x%x--0x%x--0x%x--0x%x--0x%x--0x%x--0x%x--0x%x--0x%x--(%llu)",
				  xchg,
				  (unsigned int)xchg->hot_pool_tag,
				  (unsigned int)xchg->xchg_type,
				  (unsigned int)xchg->ox_id,
				  (unsigned int)xchg->rx_id,
				  (unsigned int)xchg->sid,
				  (unsigned int)xchg->did,
				  (unsigned int)xchg->seq_id,
				  (unsigned int)xchg->io_state,
				  atomic_read(&xchg->ref_cnt),
				  xchg->alloc_jif);
		}

		UNF_TRACE(0x2665, UNF_LOG_NORMAL, UNF_INFO, "SFS Busy:");
		list_for_each_safe(xchg_node, next_xchg_node,
				   &xchg_mgr->hot_pool->sfs_busylist) {
			sfs_busy++;

			xchg = list_entry(xchg_node, struct unf_xchg_s,
					  list_xchg_entry);
			UNF_TRACE(0x2666, UNF_LOG_NORMAL, UNF_INFO,
				  "0x%p--0x%x--0x%x--0x%x--0x%x--0x%x--0x%x--0x%x--0x%x--0x%x--(%llu)",
				  xchg,
				  (unsigned int)xchg->hot_pool_tag,
				  (unsigned int)xchg->xchg_type,
				  (unsigned int)xchg->ox_id,
				  (unsigned int)xchg->rx_id,
				  (unsigned int)xchg->sid,
				  (unsigned int)xchg->did,
				  (unsigned int)xchg->seq_id,
				  (unsigned int)xchg->io_state,
				  atomic_read(&xchg->ref_cnt),
				  xchg->alloc_jif);
		}

		spin_unlock_irqrestore(&xchg_mgr->hot_pool->xchg_hot_pool_lock,
				       flags);

		/* free Xchg */
		spin_lock_irqsave(&xchg_mgr->free_pool.xchg_free_pool_lock,
				  flags);

		list_for_each_safe(xchg_node, next_xchg_node,
				   &xchg_mgr->free_pool.list_free_xchg_list) {
			free++;
		}

		list_for_each_safe(xchg_node, next_xchg_node,
				   &xchg_mgr->free_pool.list_sfs_xchg_list) {
			sfs_free++;
		}
		spin_unlock_irqrestore(&xchg_mgr->free_pool.xchg_free_pool_lock,
				       flags);

		ret = RETURN_OK;
	}

	buff_out->aborted = aborted;
	buff_out->ini_busy = ini_busy;
	buff_out->tgt_busy = tgt_busy;
	buff_out->delay = delay;
	buff_out->free = free;
	buff_out->wait = wait;
	buff_out->sfs_free = sfs_free;
	buff_out->sfs_busy = sfs_busy;
	UNF_REFERNCE_VAR(xchg);
	return ret;
}

static int unf_cm_adm_link_time_out_opt(struct unf_lport_s *v_lport,
					struct unf_hinicam_pkg *v_input)
{
	int ret = RETURN_OK;
	int time_out = 0;
	struct unf_link_tmo_opt_s *buff_in = NULL;
	struct unf_link_tmo_opt_s *buff_out = NULL;
	struct unf_admin_msg_head msg_head = { 0 };

	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE, v_input,
			return RETURN_ERROR);
	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE, v_lport,
			return RETURN_ERROR);

	buff_in = (struct unf_link_tmo_opt_s *)(v_input->buff_in);
	buff_out = (struct unf_link_tmo_opt_s *)(v_input->buff_out);

	msg_head.status = UNF_ADMIN_MSG_DONE;
	msg_head.size = sizeof(struct unf_admin_msg_head);
	if (buff_in->link_opt) {
		/* set link tmo value */
		time_out = unf_get_link_lose_tmo(v_lport);
		/* compatible for PI2 branch tool (not release)not
		 * include  syncAllPort section
		 */
		if (v_input->in_size > 16) {
			if (buff_in->sync_all_port)
				/* sync to all other lport */
				unf_set_link_lose_tmo_to_all(buff_in->tmo_value);
			else
				unf_set_link_lose_tmo(v_lport,
						      buff_in->tmo_value);

			buff_out->sync_all_port = 1;
		} else {
			unf_set_link_lose_tmo_to_all(buff_in->tmo_value);
		}

		buff_out->link_opt = 1;

		/* return orige value */
		buff_out->tmo_value = time_out;
		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_NORMAL, UNF_KEVENT,
			  "[info]set fc port(0x%0x)link tmo value(%d -> %d) success .",
			  v_lport->nport_id, time_out, buff_out->tmo_value);
	} else {
		/* get link tmo value */
		buff_out->tmo_value = unf_get_link_lose_tmo(v_lport);
		buff_out->link_opt = 0;
		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_NORMAL, UNF_MAJOR,
			  "get fc port(0x%0x) link tmo value(%d) success .",
			  v_lport->nport_id, buff_out->tmo_value);
	}
	*v_input->out_size = v_input->in_size;
	memcpy((void *)buff_out, &msg_head, sizeof(struct unf_admin_msg_head));
	return ret;
}

static int unf_cm_adm_log_level_opt(struct unf_lport_s *v_lport,
				    struct unf_hinicam_pkg *v_input)
{
	int ret = RETURN_OK;
	unsigned int log_level = 0;
	unsigned int log_count = 0;
	struct unf_log_level_opt_s *buff_in = NULL;
	struct unf_log_level_opt_s *buff_out = NULL;
	struct unf_admin_msg_head msg_head = { 0 };

	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE, v_input,
			return RETURN_ERROR);
	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE,
			v_input->in_size >= sizeof(struct unf_log_level_opt_s),
			return RETURN_ERROR);
	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE,
			*v_input->out_size >=
			sizeof(struct unf_log_level_opt_s),
			return RETURN_ERROR);

	buff_in = (struct unf_log_level_opt_s *)(v_input->buff_in);
	buff_out = (struct unf_log_level_opt_s *)(v_input->buff_out);

	msg_head.status = UNF_ADMIN_MSG_DONE;
	msg_head.size = sizeof(struct unf_admin_msg_head);
	if (buff_in->log_opt) {
		/* set log level value */
		log_level = log_print_level;
		log_count = log_limted_times;
		log_print_level = buff_in->log_level;
		log_limted_times = buff_in->log_fre_qunce;
		buff_out->log_opt = 1;
		/* return orige value */

		buff_out->log_level = log_level;
		buff_out->log_fre_qunce = log_count;

		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_NORMAL, UNF_MAJOR,
			  "set fc log level(%u -> %u), frenqunce(%u -> %u)in 2s success .",
			  log_level, log_print_level, log_count,
				  log_limted_times);
	} else {
		/* get link tmo value */
		buff_out->log_level = log_print_level;
		buff_out->log_fre_qunce = log_limted_times;
		buff_out->log_opt = 0;
		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_NORMAL, UNF_MAJOR,
			  "get fc log level(%u),frenqunce(%u) in 2s success .",
			  buff_out->log_level, buff_out->log_fre_qunce);
	}
	*v_input->out_size = sizeof(struct unf_log_level_opt_s);
	memcpy((void *)buff_out, &msg_head, sizeof(struct unf_admin_msg_head));
	return ret;
}

int unf_cm_echo_test(unsigned int v_port_id, unsigned int v_nport_id,
		     unsigned int *v_link_delay)
{
	struct unf_lport_s *lport = NULL;
	struct unf_rport_s *rport = NULL;
	int ret = RETURN_OK;
	unsigned int index = 0;

	lport = unf_find_lport_by_port_id(v_port_id);
	if (!lport) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_NORMAL, UNF_MAJOR,
			  "fcping request failed [invalid source lport (0x%x)].\n",
			  v_port_id);

		return UNF_RETURN_ERROR;
	}

	rport = unf_get_rport_by_nport_id(lport, v_nport_id);
	if ((!rport) || (v_nport_id == UNF_FC_FID_FLOGI)) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_NORMAL, UNF_MAJOR,
			  "fcping request failed [invalid destination rport(0x%x)].\n",
			  v_nport_id);

		return UNF_RETURN_ERROR;
	}

	for (index = 0; index < UNF_ECHO_SEND_MAX_TIMES; index++) {
		ret = (int)unf_send_echo(lport, rport, v_link_delay);
		if (ret != RETURN_OK) {
			*v_link_delay = 0xffffffff;

			UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_NORMAL,
				  UNF_MAJOR,
				  "fcping request failed [lport(0x%x)-> rport(0x%x)].\n",
				  v_port_id, v_nport_id);

		} else {
			UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_NORMAL,
				  UNF_MAJOR,
				  "fcping request succeed within %u us [lport(0x%x)->rport(0x%x)].\n",
				  *(unsigned int *)v_link_delay, v_port_id,
				  v_nport_id);
		}

		msleep(1000);
	}

	return ret;
}

static int unf_cm_link_delay_get(struct unf_lport_s *v_lport,
				 struct unf_hinicam_pkg *v_input)
{
	int ret = UNF_RETURN_ERROR;
	unsigned int link_delay = 0xffffffff;
	unsigned int nport_id = 0xffffff;
	unsigned int port_id = 0;
	struct unf_adm_cmd *buff_in = NULL;
	struct unf_adm_cmd *buff_out = NULL;
	struct unf_admin_msg_head msg_head = { 0 };

	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE, v_input,
			return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE, *v_input->out_size >=
			sizeof(struct unf_adm_cmd), return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE, v_input->in_size >=
			sizeof(struct unf_adm_cmd), return UNF_RETURN_ERROR);

	buff_in = (struct unf_adm_cmd *)(v_input->buff_in);
	buff_out = (struct unf_adm_cmd *)(v_input->buff_out);
	port_id = v_lport->port_id;
	nport_id = buff_in->arg[0];

	msg_head.status = UNF_ADMIN_MSG_DONE;

	ret = unf_cm_echo_test(port_id, nport_id, &link_delay);
	if ((ret == RETURN_OK) && (link_delay != 0xffffffff)) {
		buff_out->arg[0] = link_delay;
		msg_head.size = sizeof(struct unf_admin_msg_head) +
			sizeof(unsigned int) * 1;
	} else {
		msg_head.status = UNF_ADMIN_MSG_FAILED;
		msg_head.size = sizeof(struct unf_admin_msg_head);
	}

	*v_input->out_size = sizeof(struct unf_adm_cmd);
	memcpy((void *)buff_out, &msg_head, sizeof(struct unf_admin_msg_head));

	return ret;
}

static unsigned int unf_port_release_rport_index(struct unf_lport_s *v_lport,
						 void *v_input)
{
	unsigned int index = INVALID_VALUE32;
	unsigned int *rport_index = NULL;
	unsigned long flag = 0;
	struct unf_rport_pool_s *rport_pool = NULL;

	UNF_CHECK_VALID(0x2370, UNF_FALSE, v_lport, return UNF_RETURN_ERROR);

	if (v_input) {
		rport_index = (unsigned int *)v_input;
		index = *rport_index;
		if (index < v_lport->low_level_func.support_max_rport) {
			rport_pool = &((struct unf_lport_s *)v_lport->root_lport)->rport_pool;
			spin_lock_irqsave(&rport_pool->rport_free_pool_lock,
					  flag);
			if (test_bit((int)index, rport_pool->pul_rpi_bitmap))
				clear_bit((int)index,
					  rport_pool->pul_rpi_bitmap);
			else
				UNF_TRACE(UNF_EVTLOG_DRIVER_WARN,
					  UNF_LOG_LOGIN_ATT, UNF_ERR,
					  "[warn]Port(0x%x) try to release a free rport index(0x%x)",
					  v_lport->port_id, index);

			spin_unlock_irqrestore(
				&rport_pool->rport_free_pool_lock,
				flag);
		} else {
			UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT,
				  UNF_ERR,
				  "[warn]Port(0x%x) try to release a not exist rport index(0x%x)",
				  v_lport->port_id, index);
		}
	}

	return RETURN_OK;
}

void *unf_lookup_lport_by_nport_id(void *v_lport, unsigned int v_nport_id)
{
	struct unf_lport_s *lport = NULL;
	struct unf_vport_pool_s *vport_pool = NULL;
	struct unf_lport_s *vport = NULL;
	struct list_head *node = NULL;
	struct list_head *next_node = NULL;
	unsigned long flag = 0;

	UNF_CHECK_VALID(0x1978, UNF_TRUE, v_lport, return NULL);

	lport = (struct unf_lport_s *)v_lport;
	lport = lport->root_lport;
	vport_pool = lport->vport_pool;

	if (v_nport_id == lport->nport_id)
		return lport;

	if (unlikely(!vport_pool)) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_IO_ATT, UNF_WARN,
			  "[warn]Port(0x%x) vport pool is NULL",
			  lport->port_id);

		return NULL;
	}

	spin_lock_irqsave(&vport_pool->vport_pool_lock, flag);
	list_for_each_safe(node, next_node, &lport->list_vports_head) {
		vport = list_entry(node, struct unf_lport_s, entry_vport);
		if (vport->nport_id == v_nport_id) {
			spin_unlock_irqrestore(&vport_pool->vport_pool_lock,
					       flag);
			return vport;
		}
	}

	list_for_each_safe(node, next_node, &lport->list_intergrad_vports) {
		vport = list_entry(node, struct unf_lport_s, entry_vport);
		if (vport->nport_id == v_nport_id) {
			spin_unlock_irqrestore(&vport_pool->vport_pool_lock,
					       flag);
			return vport;
		}
	}
	spin_unlock_irqrestore(&vport_pool->vport_pool_lock, flag);

	UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT, UNF_INFO,
		  "Port(0x%x) has no vport Nport ID(0x%x)",
		  lport->port_id, v_nport_id);
	return NULL;
}

static int unf_get_port_info(struct unf_lport_s *v_lport,
			     struct unf_lport_info *v_port_info)
{
	unsigned int act_speed = INVALID_VALUE32;
	unsigned int cfg_speed = INVALID_VALUE32;
	unsigned int cfg_topo = INVALID_VALUE32;
	enum unf_act_topo_e act_topo = UNF_ACT_TOP_UNKNOWN;
	struct unf_err_code_s fc_err_code;
	unsigned int cfg_led_mode = INVALID_VALUE32;
	struct unf_vport_pool_s *vport_pool = NULL;
	struct unf_lport_s *vport = NULL;
	struct list_head *node = NULL;
	struct list_head *next_node = NULL;
	unsigned long flag = 0;

	UNF_CHECK_VALID(0x2205, UNF_TRUE, v_lport, return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(0x2206, UNF_TRUE, v_port_info, return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(0x2207, UNF_TRUE, v_lport->fc_port,
			return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(
		0x2208, UNF_TRUE,
		v_lport->low_level_func.port_mgr_op.pfn_ll_port_config_get,
		return UNF_RETURN_ERROR);
	UNF_REFERNCE_VAR(cfg_speed);
	UNF_REFERNCE_VAR(act_topo);

	memset(&fc_err_code, 0, sizeof(fc_err_code));

	/* get port speed */
	cfg_speed = v_lport->low_level_func.lport_cfg_items.port_speed;

	if (v_lport->link_up == UNF_PORT_LINK_UP)
		(void)v_lport->low_level_func.port_mgr_op.pfn_ll_port_config_get(
			v_lport->fc_port,
			UNF_PORT_CFG_GET_SPEED_ACT, (void *)&act_speed);
	else
		act_speed = UNF_PORT_SPEED_UNKNOWN;

	(void)v_lport->low_level_func.port_mgr_op.pfn_ll_port_config_get(
		v_lport->fc_port,
		UNF_PORT_CFG_GET_SPEED_CFG, (void *)&cfg_speed);

	if (v_lport->link_up == UNF_PORT_LINK_UP)
		(void)v_lport->low_level_func.port_mgr_op.pfn_ll_port_config_get(
			v_lport->fc_port,
			UNF_PORT_CFG_GET_TOPO_ACT, (void *)&act_topo);
	else
		act_topo = UNF_ACT_TOP_UNKNOWN;

	(void)v_lport->low_level_func.port_mgr_op.pfn_ll_port_config_get(
		v_lport->fc_port,
		UNF_PORT_CFG_GET_TOPO_CFG, (void *)&cfg_topo);

	(void)v_lport->low_level_func.port_mgr_op.pfn_ll_port_config_get(
		v_lport->fc_port,
		UNF_PORT_CFG_GET_LED_STATE, (void *)&cfg_led_mode);

	v_port_info->port_id = v_lport->port_id;
	v_port_info->options = v_lport->options;
	v_port_info->b_start_work = global_lport_mgr.b_start_work;
	v_port_info->phy_link = UNF_PORT_LINK_UP;
	v_port_info->link_up = v_lport->link_up;
	v_port_info->act_speed = act_speed;
	v_port_info->cfg_speed = cfg_speed;
	v_port_info->port_name = v_lport->port_name;
	v_port_info->tape_support =
		v_lport->low_level_func.lport_cfg_items.tape_support;
	v_port_info->msi = 0;
	v_port_info->ini_io_retry_timeout = 0;
	v_port_info->support_max_npiv_num =
		v_lport->low_level_func.support_max_npiv_num;
	v_port_info->act_topo = act_topo;
	v_port_info->port_topology =
		v_lport->low_level_func.lport_cfg_items.port_topology;
	v_port_info->fc_ser_max_speed =
		v_lport->low_level_func.fc_ser_max_speed;

	if (unf_get_error_code_sum(v_lport, &fc_err_code) != RETURN_OK) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_LOGIN_ATT, UNF_ERR,
			  "[err]Port(0x%x) get error code failed",
			  v_lport->port_id);

		return UNF_RETURN_ERROR;
	}

	v_port_info->loss_of_signal_count = fc_err_code.loss_of_signal_count;
	v_port_info->bad_rx_char_count = fc_err_code.bad_rx_char_count;
	v_port_info->loss_of_sync_count = fc_err_code.loss_of_sync_count;
	v_port_info->link_fail_count = fc_err_code.link_fail_count;
	v_port_info->rx_eo_fa_count = fc_err_code.rx_eo_fa_count;
	v_port_info->dis_frame_count = fc_err_code.dis_frame_count;
	v_port_info->bad_crc_count = fc_err_code.bad_crc_count;
	v_port_info->proto_error_count = fc_err_code.proto_error_count;
	v_port_info->chip_type = v_lport->low_level_func.chip_info.chip_type;
	v_port_info->cfg_led_mode = cfg_led_mode;

	v_port_info->vport_num = 0;

	vport_pool = v_lport->vport_pool;
	if (unlikely(!vport_pool))
		return RETURN_OK;

	spin_lock_irqsave(&vport_pool->vport_pool_lock, flag);
	list_for_each_safe(node, next_node, &v_lport->list_vports_head) {
		vport = list_entry(node, struct unf_lport_s, entry_vport);

		v_port_info->vport_id[v_port_info->vport_num] = vport->port_id;

		v_port_info->vport_num = v_port_info->vport_num + 1;
	}
	spin_unlock_irqrestore(&vport_pool->vport_pool_lock, flag);
	return RETURN_OK;
}

static int unf_get_vport_info(struct unf_lport_s *v_lport,
			      unsigned int v_vport_id,
			      struct unf_lport_info *v_port_info)
{
	unsigned char vport_index = INVALID_VALUE8;
	struct unf_lport_s *vport = NULL;

	UNF_CHECK_VALID(0x2203, UNF_TRUE, v_lport, return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(0x2203, UNF_TRUE, v_port_info, return UNF_RETURN_ERROR);

	vport_index = (v_vport_id & PORTID_VPINDEX_MASK) >> PORTID_VPINDEX_SHIT;
	if (unlikely(vport_index == 0)) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_NORMAL, UNF_ERR,
			  "[err]VPortId(0x%x) is not vport", v_vport_id);

		return UNF_RETURN_ERROR;
	}

	vport = unf_cm_lookup_vport_by_vp_index(v_lport, vport_index);
	if (unlikely(!vport)) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_NORMAL, UNF_ERR,
			  "[err]VPortId(0x%x) can not be found",
			  v_vport_id);

		return UNF_RETURN_ERROR;
	}

	v_port_info->port_id = vport->port_id;
	v_port_info->port_name = vport->port_name;
	v_port_info->nport_id = vport->nport_id;
	v_port_info->options = 0;

	return RETURN_OK;
}

static int unf_get_all_port_info(void *v_arg_in, void *v_arg_out)
{
	struct unf_lport_s *lport = NULL;
	struct unf_get_allinfo_argout *arg_in = NULL;
	unsigned int current_len = 0;
	struct unf_lport_info *cur_lport_info = NULL;
	struct unf_admin_msg_head msg_head = { 0 };
	int ret = UNF_RETURN_ERROR;
	unsigned int out_buf_len = 0;
	char *out_buf = NULL;
	struct hifc_adm_cmd_s *buff_in = NULL;

	UNF_CHECK_VALID(0x2203, UNF_TRUE, v_arg_in, return UNF_RETURN_ERROR);
	UNF_REFERNCE_VAR(v_arg_out);

	arg_in = (struct unf_get_allinfo_argout *)v_arg_in;
	out_buf = (char *)arg_in->out_buf;
	buff_in = (struct hifc_adm_cmd_s *)arg_in->in_buf;
	lport = (struct unf_lport_s *)arg_in->lport;

	UNF_CHECK_VALID(0x2203, UNF_TRUE, out_buf, return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(0x2203, UNF_TRUE, buff_in, return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(0x2203, UNF_TRUE, lport, return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE, arg_in->in_size >=
			sizeof(struct hifc_adm_cmd_s), return UNF_RETURN_ERROR);

	cur_lport_info = vmalloc(sizeof(struct unf_lport_info));
	if (!cur_lport_info) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_LOGIN_ATT, UNF_ERR,
			  "[err]Port(0x%x) malloc memory fail", lport->port_id);
		((struct unf_admin_msg_head *)out_buf)->status =
			UNF_ADMIN_MSG_FAILED;
		return ret;
	}

	memset(cur_lport_info, 0, sizeof(struct unf_lport_info));
	out_buf_len = arg_in->in_size;
	msg_head.status = UNF_ADMIN_MSG_DONE;
	*arg_in->out_size = out_buf_len;

	/* Storage info */
	current_len += sizeof(struct unf_admin_msg_head);

	if (lport->b_port_removing != UNF_TRUE) {
		/* Cmd[3] is Vportid */
		if (buff_in->cmd[3] != 0) {
			ret = unf_get_vport_info(lport, buff_in->cmd[3],
						 cur_lport_info);
		} else {
			ret = unf_get_port_info(lport, cur_lport_info);
		}
		if (ret != RETURN_OK) {
			UNF_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_LOGIN_ATT,
				  UNF_INFO,
				  "[err]Port(0x%x) get port information error",
				  lport->port_id);

			msg_head.status = UNF_ADMIN_MSG_FAILED;
			msg_head.size = current_len;
			memcpy(out_buf, &msg_head,
			       sizeof(struct unf_admin_msg_head));
			vfree(cur_lport_info);
			return ret;
		}

		if (out_buf_len < current_len + sizeof(struct unf_lport_info)) {
			UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_NORMAL,
				  UNF_ERR,
				  "[warn]Allocated buff size (%u < %lu) is not enough",
				  out_buf_len,
				  current_len + sizeof(struct unf_lport_info));

			/* Compatible for vport: return Lport info
			 * if tools version is not support npiv
			 */
			memcpy(out_buf + current_len, cur_lport_info,
			       out_buf_len - current_len);

			current_len = out_buf_len;

		} else {
			memcpy(out_buf + current_len, cur_lport_info,
			       sizeof(struct unf_lport_info));
			current_len += sizeof(struct unf_lport_info);
		}
	} else {
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT, UNF_INFO,
			  "[warn]Port(0x%x) is removing. Ref count 0x%x",
			  lport->port_id, atomic_read(&lport->lport_ref_cnt));

		msg_head.status = UNF_ADMIN_MSG_FAILED;
	}

	msg_head.size = current_len;
	memcpy(out_buf, &msg_head, sizeof(struct unf_admin_msg_head));
	vfree(cur_lport_info);
	return ret;
}

static int unf_cm_get_all_port_info(struct unf_lport_s *v_lport,
				    struct unf_hinicam_pkg *v_input)
{
	struct unf_get_allinfo_argout out = { 0 };
	int ret = UNF_RETURN_ERROR;

	out.out_buf = v_input->buff_out;
	out.in_buf = v_input->buff_in;
	out.out_size = v_input->out_size;
	out.in_size = v_input->in_size;
	out.lport = v_lport;

	ret = (int)unf_schedule_global_event((void *)&out,
					     UNF_GLOBAL_EVENT_SYN,
					     unf_get_all_port_info);

	return ret;
}

static int unf_cm_port_set(struct unf_lport_s *v_lport,
			   struct unf_hinicam_pkg *v_input)
{
	int ret = UNF_RETURN_ERROR;
	unsigned int mode = 0;   /* 1:portreset 2:sfp on/off */
	int turn_on = 0; /* 0:sfp off 1:sfp on */
	unsigned int port_id = 0;
	void *out_buf = NULL;
	struct unf_adm_cmd *buff_in = NULL;
	struct unf_admin_msg_head msg_head = { 0 };

	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE, v_input,
			return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE, v_input->in_size >=
			sizeof(struct unf_adm_cmd), return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE, *v_input->out_size >=
			sizeof(struct unf_adm_cmd), return UNF_RETURN_ERROR);
	out_buf = v_input->buff_out;
	buff_in = v_input->buff_in;
	mode = buff_in->arg[0];
	port_id = v_lport->port_id;

	msg_head.status = UNF_ADMIN_MSG_DONE;

	if (mode == 1) {
		ret = unf_cm_reset_port(port_id);

		if (ret != RETURN_OK)
			msg_head.status = UNF_ADMIN_MSG_FAILED;

	} else if (mode == 2) {
		turn_on = (int)buff_in->arg[1];

		if ((turn_on == 0) || (turn_on == 1)) {
			ret = unf_cm_sfp_switch(port_id, turn_on);
			if (ret != RETURN_OK)
				msg_head.status = UNF_ADMIN_MSG_FAILED;
		} else {
			UNF_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_REG_ATT,
				  UNF_ERR,
				  "[err]Switch sfp failed. Parameter(0x%x) error",
				  turn_on);
			msg_head.status = UNF_ADMIN_MSG_FAILED;
		}
	}

	msg_head.size = sizeof(struct unf_admin_msg_head);
	*v_input->out_size = sizeof(struct unf_adm_cmd);
	memcpy(out_buf, &msg_head, sizeof(struct unf_admin_msg_head));

	return ret;
}

static int unf_cm_topo_set(struct unf_lport_s *v_lport,
			   struct unf_hinicam_pkg *v_input)
{
	int ret = UNF_RETURN_ERROR;
	unsigned int topo = 0; /* topology set */
	unsigned int port_id = 0;
	void *out_buf = NULL;
	struct unf_adm_cmd *buff_in = NULL;
	struct unf_admin_msg_head msg_head = { 0 };

	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE, v_input,
			return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE, v_input->in_size >=
			sizeof(struct unf_adm_cmd), return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE, *v_input->out_size >=
			sizeof(struct unf_adm_cmd), return UNF_RETURN_ERROR);
	out_buf = v_input->buff_out;
	buff_in = v_input->buff_in;
	topo = buff_in->arg[0];
	port_id = v_lport->port_id;

	msg_head.status = UNF_ADMIN_MSG_DONE;

	if ((topo == UNF_TOP_AUTO_MASK) || (topo == UNF_TOP_LOOP_MASK) ||
	    (topo == UNF_TOP_P2P_MASK)) {
		ret = unf_cm_set_port_topo(port_id, topo);
		if (ret != RETURN_OK)
			msg_head.status = UNF_ADMIN_MSG_FAILED;
	} else {
		UNF_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_REG_ATT, UNF_ERR,
			  "[err]Set topo failed. Parameter(0x%x) error", topo);
		msg_head.status = UNF_ADMIN_MSG_FAILED;
	}

	msg_head.size = sizeof(struct unf_admin_msg_head);
	*v_input->out_size = sizeof(struct unf_adm_cmd);
	memcpy(out_buf, &msg_head, sizeof(struct unf_admin_msg_head));

	return ret;
}

static int unf_cm_port_speed_set(struct unf_lport_s *v_lport,
				 struct unf_hinicam_pkg *v_input)
{
	int ret = UNF_RETURN_ERROR;
	unsigned int port_speed = 0;
	unsigned int port_id = 0;
	void *out_buf = NULL;
	struct unf_adm_cmd *buff_in = NULL;
	struct unf_admin_msg_head msg_head = { 0 };
	struct unf_lport_s *lport = NULL;
	int check_speed_flag = UNF_TRUE;

	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE, v_input,
			return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE, v_lport,
			return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE,
			v_input->in_size >= sizeof(struct unf_adm_cmd),
			return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE,
			*v_input->out_size >= sizeof(struct unf_adm_cmd),
			return UNF_RETURN_ERROR);
	lport = v_lport;
	out_buf = v_input->buff_out;
	buff_in = v_input->buff_in;
	port_speed = buff_in->arg[0];
	port_id = v_lport->port_id;

	msg_head.status = UNF_ADMIN_MSG_DONE;

	/* get and check sfp speed */
	if (unf_get_lport_current_info(lport) != RETURN_OK) {
		msg_head.status = UNF_ADMIN_MSG_FAILED;
		lport->low_level_func.sfp_speed = UNF_PORT_SFP_SPEED_ERR;
	}
	if (UNF_CHECK_CONFIG_SPEED_BY_SFSSPEED(lport->low_level_func.sfp_speed,
					       port_speed)) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_REG_ATT, UNF_ERR,
			  "[err]Set port speed failed. Speed (0x%x) is greater than SfpSpeed (0x%x)",
			  port_speed, lport->low_level_func.sfp_speed);
		msg_head.status = UNF_ADMIN_MSG_FAILED;
		check_speed_flag = UNF_FALSE;
	} else {
		if (lport->low_level_func.fc_ser_max_speed ==
		    UNF_PORT_SPEED_32_G) {
			check_speed_flag =
				(port_speed == UNF_PORT_SPEED_AUTO) ||
				(port_speed == UNF_PORT_SPEED_8_G) ||
				(port_speed == UNF_PORT_SPEED_16_G) ||
				(port_speed == UNF_PORT_SPEED_32_G);
		} else if (lport->low_level_func.fc_ser_max_speed ==
			   UNF_PORT_SPEED_16_G) {
			check_speed_flag =
				(port_speed == UNF_PORT_SPEED_AUTO) ||
				(port_speed == UNF_PORT_SPEED_4_G) ||
				(port_speed == UNF_PORT_SPEED_8_G) ||
				(port_speed == UNF_PORT_SPEED_16_G);
		} else if (lport->low_level_func.fc_ser_max_speed ==
			   UNF_PORT_SPEED_8_G) {
			check_speed_flag =
				(port_speed == UNF_PORT_SPEED_AUTO) ||
				(port_speed == UNF_PORT_SPEED_2_G) ||
				(port_speed == UNF_PORT_SPEED_4_G) ||
				(port_speed == UNF_PORT_SPEED_8_G);
		} else {
			UNF_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_REG_ATT,
				  UNF_ERR,
				  "[err]Board maxspeed is unknown");
			msg_head.status = UNF_ADMIN_MSG_FAILED;
			check_speed_flag = UNF_FALSE;
		}
	}

	if (check_speed_flag) {
		ret = unf_cm_set_port_speed(port_id, &port_speed);
		if (ret != RETURN_OK)
			msg_head.status = UNF_ADMIN_MSG_FAILED;
	}

	msg_head.size = sizeof(struct unf_admin_msg_head);
	*v_input->out_size = sizeof(struct unf_adm_cmd);
	memcpy(out_buf, &msg_head, sizeof(struct unf_admin_msg_head));

	return ret;
}

static int unf_cm_set_vport(struct unf_lport_s *v_lport,
			    struct unf_hinicam_pkg *v_input)
{
	unsigned int ret = UNF_RETURN_ERROR;
	struct unf_lport_s *lport = NULL;
	unsigned int mode = 0;
	unsigned int index = 0;
	unsigned int high32 = 0x2000286e;
	unsigned int low32 = 0;
	unsigned long long port_name = 0;
	unsigned int port_id = 0;

	void *out_buf = NULL;
	struct unf_adm_cmd *buff_in = NULL;
	struct unf_admin_msg_head msg_head = { 0 };

	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE, v_input,
			return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE,
			v_input->in_size >= sizeof(struct unf_adm_cmd),
			return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE,
			*v_input->out_size >= sizeof(struct unf_adm_cmd),
			return UNF_RETURN_ERROR);
	out_buf = v_input->buff_out;
	buff_in = v_input->buff_in;
	port_id = v_lport->port_id;

	msg_head.status = UNF_ADMIN_MSG_DONE;

	mode = buff_in->arg[0];

	switch (mode) {
	case 1:
		/* create vport with wwpn */
		low32 = buff_in->arg[1];
		port_name = ((unsigned long)high32 << 32) | low32;

	//lint -fallthrough
	case 3:
		/* create vport and autogeneration wwpn */
		ret = unf_npiv_conf(port_id, port_name);
		if (ret != RETURN_OK)
			msg_head.status = UNF_ADMIN_MSG_FAILED;
		msleep(2000);
		break;

	case 2:
		/* delete vport by vport index */
		index = buff_in->arg[2];
		ret = unf_delete_vport(port_id, index);
		if (ret != RETURN_OK)
			msg_head.status = UNF_ADMIN_MSG_FAILED;
		break;

	case 4:
		/* delete all vport on Lport */
		lport = unf_find_lport_by_port_id(port_id);
		if (!lport) {
			UNF_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_NORMAL,
				  UNF_ERR,
				  "[err]Port(0x%x) can't find", port_id);
			msg_head.status = UNF_ADMIN_MSG_FAILED;
		} else {
			unf_destroy_all_vports(lport);
			ret = RETURN_OK;
		}
		break;

	default:
		UNF_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_NORMAL, UNF_ERR,
			  "[err]Mode is unknown");
		msg_head.status = UNF_ADMIN_MSG_FAILED;
		break;
	}

	msg_head.size = sizeof(struct unf_admin_msg_head);
	*v_input->out_size = sizeof(struct unf_adm_cmd);
	memcpy(out_buf, &msg_head, sizeof(struct unf_admin_msg_head));

	return (int)ret;
}

static int unf_cm_port_info_get(struct unf_lport_s *v_lport,
				struct unf_hinicam_pkg *v_input)
{
	int ret = UNF_RETURN_ERROR;
	unsigned int topo_cfg = 0;
	enum unf_act_topo_e topo = UNF_ACT_TOP_UNKNOWN;
	unsigned int port_speed = 0;
	unsigned int port_id = 0;
	struct unf_adm_cmd *buff_out = NULL;
	struct unf_admin_msg_head msg_head = { 0 };
	struct unf_lport_s *lport = NULL;

	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE, v_input,
			return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE,
			*v_input->out_size >= sizeof(struct unf_adm_cmd),
			return UNF_RETURN_ERROR);
	lport = v_lport;
	port_id = v_lport->port_id;
	buff_out = (struct unf_adm_cmd *)v_input->buff_out;
	msg_head.status = UNF_ADMIN_MSG_DONE;

	ret = unf_cm_get_port_topo(port_id, &topo_cfg, &topo);
	if (ret == RETURN_OK) {
		ret = unf_cm_get_port_speed(port_id, &port_speed);
		if (ret == RETURN_OK) {
			buff_out->arg[0] = lport->port_id;
			buff_out->arg[1] = topo_cfg;
			buff_out->arg[2] = topo;
			buff_out->arg[3] = port_speed;
			buff_out->arg[4] = lport->link_up;

			msg_head.size = sizeof(struct unf_admin_msg_head) +
				sizeof(unsigned int) * 5;
		} else {
			msg_head.status = UNF_ADMIN_MSG_FAILED;
			msg_head.size = sizeof(struct unf_admin_msg_head);
		}
	} else {
		msg_head.status = UNF_ADMIN_MSG_FAILED;
		msg_head.size = sizeof(struct unf_admin_msg_head);
	}

	*v_input->out_size = sizeof(struct unf_adm_cmd);
	memcpy(buff_out, &msg_head, sizeof(struct unf_admin_msg_head));

	return ret;
}

static int unf_get_port_sfp_info(struct unf_lport_s *v_lport,
				 struct unf_hinicam_pkg *v_input)
{
#define MIN_SFPINFO_LEN 512
	union unf_sfp_eeprome_info *sfp_info = NULL;
	int ret = UNF_RETURN_ERROR;
	unsigned int status = 0;
	unsigned int sfp_type = 0;
	unsigned int port_id = 0;
	char *buff_out = NULL;
	struct unf_admin_msg_head msg_head = { 0 };

	UNF_CHECK_VALID(0x2203, UNF_TRUE, v_input, return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE,
			*v_input->out_size >= MIN_SFPINFO_LEN,
			return UNF_RETURN_ERROR);
	buff_out = v_input->buff_out;
	port_id = v_lport->port_id;

	*v_input->out_size = MIN_SFPINFO_LEN;
	msg_head.status = UNF_ADMIN_MSG_DONE;

	sfp_info = vmalloc(sizeof(union unf_sfp_eeprome_info));
	if (!sfp_info)
		return UNF_RETURN_ERROR;

	memset(sfp_info, 0, sizeof(union unf_sfp_eeprome_info));

	ret = unf_cm_get_sfp_info(port_id, &status, sfp_info, &sfp_type);
	if (ret == UNF_RETURN_ERROR || (status != DRV_CABLE_CONNECTOR_OPTICAL))
		msg_head.status = UNF_ADMIN_MSG_FAILED;

	msg_head.size = sizeof(struct unf_admin_msg_head);
	memcpy(buff_out, &msg_head, sizeof(struct unf_admin_msg_head));
	memcpy((buff_out + msg_head.size),
	       &sfp_info->sfp_info, sizeof(struct unf_sfp_info_s));

	vfree(sfp_info);

	return ret;
}

static int unf_cm_clear_error_code_sum(struct unf_lport_s *v_lport,
				       struct unf_hinicam_pkg *v_input)
{
	int ret = RETURN_OK;
	void *out_buf = NULL;
	unsigned int port_id = 0;
	struct unf_admin_msg_head msg_head = { 0 };

	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE, v_input,
			return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE,
			*v_input->out_size >= sizeof(struct unf_adm_cmd),
			return UNF_RETURN_ERROR);
	out_buf = v_input->buff_out;
	port_id = v_lport->port_id;
	msg_head.status = UNF_ADMIN_MSG_DONE;

	ret = unf_cm_clear_port_error_code_sum(port_id);
	if (ret != RETURN_OK)
		msg_head.status = UNF_ADMIN_MSG_FAILED;

	msg_head.size = sizeof(struct unf_admin_msg_head);
	*v_input->out_size = sizeof(struct unf_adm_cmd);
	memcpy(out_buf, &msg_head, sizeof(struct unf_admin_msg_head));
	return ret;
}

static int unf_cm_bbscn_set(struct unf_lport_s *v_lport,
			    struct unf_hinicam_pkg *v_input)
{
	int ret = UNF_RETURN_ERROR;
	unsigned int bbscn_val = 0;
	unsigned int port_id = 0;
	void *out_buf = NULL;
	struct unf_adm_cmd *buff_in = NULL;
	struct unf_admin_msg_head msg_head = { 0 };

	UNF_CHECK_VALID(INVALID_VALUE32,
			UNF_TRUE, v_input, return UNF_RETURN_ERROR);
	out_buf = v_input->buff_out;
	buff_in = v_input->buff_in;
	port_id = v_lport->port_id;

	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE,
			out_buf, return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE,
			buff_in, return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE,
			v_input->in_size >= sizeof(struct unf_adm_cmd),
			return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE,
			*v_input->out_size >= sizeof(struct unf_adm_cmd),
			return UNF_RETURN_ERROR);
	bbscn_val = buff_in->arg[1];
	UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_REG_ATT, UNF_MAJOR,
		  "[info]BBSCN value (0x%x)", bbscn_val);
	msg_head.status = UNF_ADMIN_MSG_DONE;
	if (bbscn_val <= UNF_MAX_BBSCN_VALUE) {
		ret = unf_cm_set_port_bbscn(port_id, bbscn_val);
		if (ret != RETURN_OK)
			msg_head.status = UNF_ADMIN_MSG_FAILED;
	} else {
		UNF_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_REG_ATT, UNF_ERR,
			  "[err]BBSCN value is invalid(0x%x)", bbscn_val);
		msg_head.status = UNF_ADMIN_MSG_FAILED;
	}

	msg_head.size = sizeof(struct unf_admin_msg_head);
	*v_input->out_size = sizeof(struct unf_adm_cmd);
	memcpy(out_buf, &msg_head, sizeof(struct unf_admin_msg_head));

	return ret;
}

static void unf_fc_host_counter(struct unf_lport_s *v_lport,
				struct hifc_adm_dfx_cmd_s *v_buff_out)
{
	unsigned int scsi_id = 0;
	unsigned int index = 0;
	struct unf_rport_scsi_id_image_s *scsi_image_table = NULL;

	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE, v_lport, return);
	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE, v_buff_out, return);

	scsi_image_table = &v_lport->rport_scsi_table;
	v_buff_out->unresult.host_cnt.host_num =
			v_lport->host_info.p_scsi_host->host_no;
	v_buff_out->unresult.host_cnt.port_id = v_lport->port_id;
	v_buff_out->unresult.host_cnt.scsi_session_add_success =
				atomic_read(&v_lport->scsi_session_add_success);
	v_buff_out->unresult.host_cnt.scsi_session_add_failed =
				atomic_read(&v_lport->scsi_session_add_failed);
	v_buff_out->unresult.host_cnt.scsi_session_del_success =
				atomic_read(&v_lport->scsi_session_del_success);
	v_buff_out->unresult.host_cnt.scsi_session_del_failed =
				atomic_read(&v_lport->scsi_session_del_failed);
	v_buff_out->unresult.host_cnt.device_alloc =
				atomic_read(&v_lport->device_alloc);
	v_buff_out->unresult.host_cnt.device_destroy =
				atomic_read(&v_lport->device_destroy);
	v_buff_out->unresult.host_cnt.session_loss_tmo =
				atomic_read(&v_lport->session_loss_tmo);
	v_buff_out->unresult.host_cnt.alloc_scsi_id =
				atomic_read(&v_lport->alloc_scsi_id);
	v_buff_out->unresult.host_cnt.reuse_scsi_id =
				atomic_read(&v_lport->reuse_scsi_id);
	v_buff_out->unresult.host_cnt.resume_scsi_id =
				atomic_read(&v_lport->resume_scsi_id);
	v_buff_out->unresult.host_cnt.add_start_work_failed =
				atomic_read(&v_lport->add_start_work_failed);
	v_buff_out->unresult.host_cnt.add_closing_work_failed =
				atomic_read(&v_lport->add_closing_work_failed);

	for (scsi_id = 0; scsi_id < UNF_MAX_SCSI_ID / 2; scsi_id++) {
		index = scsi_id * 2;
		v_buff_out->unresult.host_cnt.session_state[scsi_id].session1 =
			(unsigned char)atomic_read(&scsi_image_table->wwn_rport_info_table[index].en_scsi_state);

		index = scsi_id * 2 + 1;
		v_buff_out->unresult.host_cnt.session_state[scsi_id].session2 =
			(unsigned char)atomic_read(&scsi_image_table->wwn_rport_info_table[index].en_scsi_state);
	}

	for (scsi_id = 0; scsi_id < UNF_MAX_SCSI_ID; scsi_id++) {
		if (!scsi_image_table->wwn_rport_info_table[scsi_id].dfx_counter)
			continue;
		v_buff_out->unresult.host_cnt.abort_io +=
			atomic_read(&scsi_image_table->wwn_rport_info_table[scsi_id].dfx_counter->error_handle[UNF_SCSI_ABORT_IO_TYPE]);
		v_buff_out->unresult.host_cnt.device_reset +=
			atomic_read(&scsi_image_table->wwn_rport_info_table[scsi_id].dfx_counter->error_handle[UNF_SCSI_DEVICE_RESET_TYPE]);
		v_buff_out->unresult.host_cnt.target_reset +=
			atomic_read(&scsi_image_table->wwn_rport_info_table[scsi_id].dfx_counter->error_handle[UNF_SCSI_TARGET_RESET_TYPE]);
		v_buff_out->unresult.host_cnt.bus_reset +=
			atomic_read(&scsi_image_table->wwn_rport_info_table[scsi_id].dfx_counter->error_handle[UNF_SCSI_BUS_RESET_TYPE]);
		v_buff_out->unresult.host_cnt.virtual_reset +=
			atomic_read(&scsi_image_table->wwn_rport_info_table[scsi_id].dfx_counter->error_handle[UNF_SCSI_VIRTUAL_RESET_TYPE]);
		v_buff_out->unresult.host_cnt.abort_io_result +=
			atomic_read(&scsi_image_table->wwn_rport_info_table[scsi_id].dfx_counter->error_handle_result[UNF_SCSI_ABORT_IO_TYPE]);
		v_buff_out->unresult.host_cnt.device_reset_result +=
			atomic_read(&scsi_image_table->wwn_rport_info_table[scsi_id].dfx_counter->error_handle_result[UNF_SCSI_DEVICE_RESET_TYPE]);
		v_buff_out->unresult.host_cnt.target_reset_result +=
			atomic_read(&scsi_image_table->wwn_rport_info_table[scsi_id].dfx_counter->error_handle_result[UNF_SCSI_TARGET_RESET_TYPE]);
		v_buff_out->unresult.host_cnt.bus_reset_result +=
			atomic_read(&scsi_image_table->wwn_rport_info_table[scsi_id].dfx_counter->error_handle_result[UNF_SCSI_BUS_RESET_TYPE]);
		v_buff_out->unresult.host_cnt.virtual_reset_result +=
			atomic_read(&scsi_image_table->wwn_rport_info_table[scsi_id].dfx_counter->error_handle_result[UNF_SCSI_VIRTUAL_RESET_TYPE]);
	}
}

static void unf_fc_session_counter(struct unf_lport_s *v_lport,
				   unsigned int scsi_id,
				   struct hifc_adm_dfx_cmd_s *v_buff_out)
{
	struct unf_wwpn_rport_info_s *rport_info = NULL;

	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE, v_lport, return);
	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE, v_buff_out, return);

	rport_info = &v_lport->rport_scsi_table.wwn_rport_info_table[scsi_id];
	v_buff_out->unresult.session_cnt.port_id = v_lport->port_id;
	v_buff_out->unresult.session_cnt.host_id =
				v_lport->host_info.p_scsi_host->host_no;

	if (rport_info->dfx_counter) {
		v_buff_out->unresult.session_cnt.target_busy =
			atomic64_read(&rport_info->dfx_counter->target_busy);
		v_buff_out->unresult.session_cnt.host_busy =
			atomic64_read(&rport_info->dfx_counter->host_busy);
		v_buff_out->unresult.session_cnt.abort_io =
			atomic_read(&rport_info->dfx_counter->error_handle[UNF_SCSI_ABORT_IO_TYPE]);
		v_buff_out->unresult.session_cnt.device_reset =
			atomic_read(&rport_info->dfx_counter->error_handle[UNF_SCSI_DEVICE_RESET_TYPE]);
		v_buff_out->unresult.session_cnt.target_reset =
			atomic_read(&rport_info->dfx_counter->error_handle[UNF_SCSI_TARGET_RESET_TYPE]);
		v_buff_out->unresult.session_cnt.bus_reset =
			atomic_read(&rport_info->dfx_counter->error_handle[UNF_SCSI_BUS_RESET_TYPE]);
		v_buff_out->unresult.session_cnt.virtual_reset =
			atomic_read(&rport_info->dfx_counter->error_handle[UNF_SCSI_VIRTUAL_RESET_TYPE]);

		v_buff_out->unresult.session_cnt.abort_io_result =
			atomic_read(&rport_info->dfx_counter->error_handle_result[UNF_SCSI_ABORT_IO_TYPE]);
		v_buff_out->unresult.session_cnt.device_reset_result =
			atomic_read(&rport_info->dfx_counter->error_handle_result[UNF_SCSI_DEVICE_RESET_TYPE]);
		v_buff_out->unresult.session_cnt.target_reset_result =
			atomic_read(&rport_info->dfx_counter->error_handle_result[UNF_SCSI_TARGET_RESET_TYPE]);
		v_buff_out->unresult.session_cnt.bus_reset_result =
			atomic_read(&rport_info->dfx_counter->error_handle_result[UNF_SCSI_BUS_RESET_TYPE]);
		v_buff_out->unresult.session_cnt.virtual_reset_result =
			atomic_read(&rport_info->dfx_counter->error_handle_result[UNF_SCSI_VIRTUAL_RESET_TYPE]);

		v_buff_out->unresult.session_cnt.device_alloc =
			atomic_read(&rport_info->dfx_counter->device_alloc);
		v_buff_out->unresult.session_cnt.device_destroy =
			atomic_read(&rport_info->dfx_counter->device_destroy);
	}

	v_buff_out->unresult.session_cnt.target_id = rport_info->target_id;

	if ((rport_info->wwpn != INVALID_WWPN) && (rport_info->rport)) {
		v_buff_out->unresult.session_cnt.remote_port_wwpn =
						rport_info->wwpn;
		v_buff_out->unresult.session_cnt.remote_port_nportid =
						rport_info->rport->nport_id;
		v_buff_out->unresult.session_cnt.scsi_state =
					atomic_read(&rport_info->en_scsi_state);
		v_buff_out->unresult.session_cnt.remote_port_state =
					rport_info->rport->rp_state;
		v_buff_out->unresult.session_cnt.remote_port_scsiid =
					rport_info->rport->scsi_id;
		v_buff_out->unresult.session_cnt.remote_port_index =
					rport_info->rport->rport_index;

		if (rport_info->rport->lport) {
			v_buff_out->unresult.session_cnt.local_port_wwpn =
					rport_info->rport->lport->port_name;
			v_buff_out->unresult.session_cnt.local_port_nportid =
					rport_info->rport->local_nport_id;
			v_buff_out->unresult.session_cnt.local_port_ini_state =
					rport_info->rport->lport_ini_state;
			v_buff_out->unresult.session_cnt.local_port_state =
					rport_info->rport->lport->en_states;
		}
	}
}

static int unf_fc_session_scsi_cmd_in(
			struct unf_hinicam_pkg *v_input,
			struct unf_rport_scsi_id_image_s *scsi_image_table)
{
	unsigned int scsi_id = 0;
	unsigned int scsi_cmd_type = 0;
	int ret = RETURN_OK;

	struct hifc_adm_dfx_cmd_s *buff_out = NULL;
	struct unf_adm_cmd *buff_in = NULL;

	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE, v_input,
			return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE, scsi_image_table,
			return UNF_RETURN_ERROR);

	buff_in = (struct unf_adm_cmd *)v_input->buff_in;
	buff_out = (struct hifc_adm_dfx_cmd_s *)v_input->buff_out;

	scsi_id = buff_in->arg[2];
	scsi_cmd_type = buff_in->arg[3];

	if (scsi_id >= UNF_MAX_SCSI_ID || scsi_cmd_type >= UNF_MAX_SCSI_CMD)
		return UNF_RETURN_ERROR;

	if (scsi_image_table->wwn_rport_info_table[scsi_id].dfx_counter)
		buff_out->unresult.scsi_cmd_in =
			atomic64_read(&scsi_image_table->wwn_rport_info_table[scsi_id].dfx_counter->scsi_cmd_cnt[scsi_cmd_type]);

	return ret;
}

static int unf_fc_host_scsi_cmd_in_total(
			struct unf_hinicam_pkg *v_input,
			struct unf_rport_scsi_id_image_s *scsi_image_table)
{
	unsigned int scsi_id = 0;
	unsigned int scsi_cmd_type = 0;

	struct hifc_adm_dfx_cmd_s *buff_out = NULL;
	struct unf_adm_cmd *buff_in = NULL;

	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE, v_input,
			return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE, scsi_image_table,
			return UNF_RETURN_ERROR);

	buff_in = (struct unf_adm_cmd *)v_input->buff_in;
	buff_out = (struct hifc_adm_dfx_cmd_s *)v_input->buff_out;

	scsi_cmd_type = buff_in->arg[3];

	if (scsi_cmd_type >= UNF_MAX_SCSI_CMD)
		return UNF_RETURN_ERROR;

	for (scsi_id = 0; scsi_id < UNF_MAX_SCSI_ID; scsi_id++) {
		if (!scsi_image_table->wwn_rport_info_table[scsi_id].dfx_counter)
			continue;
		buff_out->unresult.scsi_cmd_in +=
			atomic64_read(&scsi_image_table->wwn_rport_info_table[scsi_id].dfx_counter->scsi_cmd_cnt[scsi_cmd_type]);
	}

	return RETURN_OK;
}

static int unf_fc_host_scsi_cmd_done_total(
			struct unf_hinicam_pkg *v_input,
			struct unf_rport_scsi_id_image_s *scsi_image_table)
{
	unsigned int scsi_id = 0;
	unsigned int io_return_value = 0;
	int ret = RETURN_OK;

	struct hifc_adm_dfx_cmd_s *buff_out = NULL;
	struct unf_adm_cmd *buff_in = NULL;

	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE, v_input,
			return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE, scsi_image_table,
			return UNF_RETURN_ERROR);

	buff_in = (struct unf_adm_cmd *)v_input->buff_in;
	buff_out = (struct hifc_adm_dfx_cmd_s *)v_input->buff_out;

	io_return_value = buff_in->arg[3];

	if (io_return_value >= UNF_MAX_IO_RETURN_VALUE)
		return UNF_RETURN_ERROR;

	for (scsi_id = 0; scsi_id < UNF_MAX_SCSI_ID; scsi_id++) {
		if (!scsi_image_table->wwn_rport_info_table[scsi_id].dfx_counter)
			continue;
		buff_out->unresult.scsi_cmd_done +=
			atomic64_read(&scsi_image_table->wwn_rport_info_table[scsi_id].dfx_counter->io_done_cnt[io_return_value]);
	}

	return ret;
}

static int unf_fc_session_scsi_cmd_done(
			struct unf_hinicam_pkg *v_input,
			struct unf_rport_scsi_id_image_s *scsi_image_table)
{
	unsigned int scsi_id = 0;
	unsigned int io_return_value = 0;
	int ret = RETURN_OK;

	struct hifc_adm_dfx_cmd_s *buff_out = NULL;
	struct unf_adm_cmd *buff_in = NULL;

	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE, v_input,
			return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE, scsi_image_table,
			return UNF_RETURN_ERROR);

	buff_in = (struct unf_adm_cmd *)v_input->buff_in;
	buff_out = (struct hifc_adm_dfx_cmd_s *)v_input->buff_out;

	scsi_id = buff_in->arg[2];
	io_return_value = buff_in->arg[3];

	if (scsi_id >= UNF_MAX_SCSI_ID ||
	    io_return_value >= UNF_MAX_IO_RETURN_VALUE)
		return UNF_RETURN_ERROR;

	if (scsi_image_table->wwn_rport_info_table[scsi_id].dfx_counter)
		buff_out->unresult.scsi_cmd_done =
			atomic64_read(&scsi_image_table->wwn_rport_info_table[scsi_id].dfx_counter->io_done_cnt[io_return_value]);

	return ret;
}

static int unf_get_io_dfx_statistics(struct unf_lport_s *v_lport,
				     struct unf_hinicam_pkg *v_input)
{
	int ret = RETURN_OK;
	unsigned int counter_mode = 0;
	struct hifc_adm_dfx_cmd_s *buff_out = NULL;
	struct unf_adm_cmd *buff_in = NULL;
	struct unf_admin_msg_head msg_head = { 0 };
	struct unf_rport_scsi_id_image_s *scsi_image_table = NULL;
	unsigned int scsi_id = 0;
	struct unf_lport_s *vport = NULL;
	unsigned int buff_flag = 0;

	buff_flag = (!v_input) || (!v_input->buff_out) ||
		    (!v_input->buff_in) || (!v_lport);
	if (buff_flag)
		return UNF_RETURN_ERROR;

	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE,
			v_input->in_size >= sizeof(struct unf_adm_cmd),
			return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE,
			*v_input->out_size >= sizeof(struct hifc_adm_dfx_cmd_s),
			return UNF_RETURN_ERROR);
	buff_in = (struct unf_adm_cmd *)v_input->buff_in;
	buff_out = (struct hifc_adm_dfx_cmd_s *)v_input->buff_out;
	msg_head.status = UNF_ADMIN_MSG_DONE;

	vport = unf_cm_lookup_vport_by_vp_index(
				v_lport, (unsigned short)(buff_in->arg[4]));
	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE, vport,
			return UNF_RETURN_ERROR);

	scsi_image_table = &vport->rport_scsi_table;
	FC_DRIVE_ACTION_CHECK((!scsi_image_table->wwn_rport_info_table),
			      (msg_head.status = UNF_ADMIN_MSG_FAILED),
			      (ret = UNF_RETURN_ERROR),
			      goto err);

	counter_mode = buff_in->arg[1];
	switch (counter_mode) {
	case FC_HOST_COUNTER:
		unf_fc_host_counter(vport, buff_out);
		break;
	case FC_SESSION_SCSI_CMD_IN:
		ret = unf_fc_session_scsi_cmd_in(v_input, scsi_image_table);
		break;
	case FC_HOST_SCSI_CMD_IN_TOTAL:
		ret = unf_fc_host_scsi_cmd_in_total(v_input, scsi_image_table);
		break;
	case FC_HOST_SCSI_CMD_DONE_TOTAL:
		ret = unf_fc_host_scsi_cmd_done_total(v_input,
						      scsi_image_table);
		break;
	case FC_SESSION_SCSI_CMD_DONE:
		ret = unf_fc_session_scsi_cmd_done(v_input, scsi_image_table);
		break;
	case FC_SESSION_COUNTER:
		scsi_id = buff_in->arg[2];
		FC_DRIVE_ACTION_CHECK((scsi_id >= UNF_MAX_SCSI_ID),
				      (msg_head.status = UNF_ADMIN_MSG_FAILED),
				      (ret = UNF_RETURN_ERROR),
				      goto err);
		unf_fc_session_counter(vport, scsi_id, buff_out);
		break;
	default:
		msg_head.status = UNF_ADMIN_MSG_FAILED;
		ret = UNF_RETURN_ERROR;
		break;
	}

	if (ret != RETURN_OK)
		return ret;

err:
	msg_head.size = sizeof(struct unf_admin_msg_head);
	*v_input->out_size = sizeof(struct hifc_adm_dfx_cmd_s);
	memcpy(buff_out, &msg_head, sizeof(struct unf_admin_msg_head));

	return ret;
}

static int unf_cm_switch_dif(unsigned int v_option,
			     unsigned int v_dix_ip_checksum)
{
#define UNF_WAIT_IO_COMPLETE_TIME_MS 5000
#define UNF_WAIT_ONE_TIME_MS 100
#define UNF_LOOP_TIMES (UNF_WAIT_IO_COMPLETE_TIME_MS / UNF_WAIT_ONE_TIME_MS)

	int ret = UNF_RETURN_ERROR;
	struct unf_lport_s *lport = NULL;
	unsigned long flags = 0;
	int enable_dif;
	unsigned int index;

	dix_flag = v_dix_ip_checksum ? UNF_TRUE : UNF_FALSE;

	enable_dif = (v_option >= UNF_ENABLE_DIF_DIX_PROT &&
		      v_option <= UNF_ENABLE_DIX_PROT);
	if (enable_dif) {
		dif_sgl_mode = UNF_TRUE;
		hifc_dif_enable = UNF_TRUE;
	}

	switch (v_option) {
	case UNF_DIF_ACTION_NONE:
		dif_sgl_mode = UNF_FALSE;
		hifc_dif_enable = UNF_FALSE;
		hifc_dif_type = 0;
		hifc_guard = 0;
		break;

	case UNF_ENABLE_DIF_DIX_PROT:
		hifc_dif_type = SHOST_DIF_TYPE1_PROTECTION |
				SHOST_DIX_TYPE1_PROTECTION;
		break;

	case UNF_ENABLE_DIF_PROT:
		hifc_dif_type = SHOST_DIF_TYPE1_PROTECTION;
		dif_sgl_mode = UNF_FALSE;
		break;

	case UNF_ENABLE_DIX_PROT:
		hifc_dif_type = SHOST_DIX_TYPE0_PROTECTION;
		break;

	default:
		return UNF_ADMIN_MSG_FAILED;
	}

	/* 1. Close Lport's SFP */
	spin_lock_irqsave(&global_lport_mgr.global_lport_list_lock, flags);
	list_for_each_entry(lport, &global_lport_mgr.list_lport_list_head,
			    entry_lport) {
		spin_unlock_irqrestore(&global_lport_mgr.global_lport_list_lock,
				       flags);

		ret = unf_cm_sfp_switch(lport->port_id, UNF_FALSE);
		if (ret != RETURN_OK) {
			UNF_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_REG_ATT,
				  UNF_ERR,
				  "[err]Port(0x%x) close SFP failed in DIF switch",
				  lport->port_id);

			return UNF_ADMIN_MSG_FAILED;
		}
		for (index = 0; index < UNF_LOOP_TIMES; index++) {
			if (unf_busy_io_completed(lport) == UNF_TRUE)
				break;
			msleep(UNF_WAIT_ONE_TIME_MS);
		}

		spin_lock_irqsave(&global_lport_mgr.global_lport_list_lock,
				  flags);
	}
	spin_unlock_irqrestore(&global_lport_mgr.global_lport_list_lock,
			       flags);

	/* 2. UnRegister the SCSI host of LPort, including its Vports */
	spin_lock_irqsave(&global_lport_mgr.global_lport_list_lock, flags);
	list_for_each_entry(lport, &global_lport_mgr.list_lport_list_head,
			    entry_lport) {
		spin_unlock_irqrestore(&global_lport_mgr.global_lport_list_lock,
				       flags);
		unf_unregister_scsi_host(lport);
		spin_lock_irqsave(&global_lport_mgr.global_lport_list_lock,
				  flags);
	}
	spin_unlock_irqrestore(&global_lport_mgr.global_lport_list_lock, flags);

	/* 3. Register the SCSI host of LPort, including its Vports */
	spin_lock_irqsave(&global_lport_mgr.global_lport_list_lock, flags);
	list_for_each_entry(lport, &global_lport_mgr.list_lport_list_head,
			    entry_lport) {
		spin_unlock_irqrestore(&global_lport_mgr.global_lport_list_lock,
				       flags);
		if (unf_register_scsi_host(lport) != RETURN_OK) {
			UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_REG_ATT,
				  UNF_WARN, "[warn]Port(0x%x) register scsi host failed in DIF switch",
				  lport->port_id);
			return UNF_ADMIN_MSG_FAILED;
		}
		spin_lock_irqsave(&global_lport_mgr.global_lport_list_lock,
				  flags);
	}
	spin_unlock_irqrestore(&global_lport_mgr.global_lport_list_lock, flags);

	/* 4. Open Lport's SFP */
	spin_lock_irqsave(&global_lport_mgr.global_lport_list_lock, flags);
	list_for_each_entry(lport, &global_lport_mgr.list_lport_list_head,
			    entry_lport) {
		spin_unlock_irqrestore(&global_lport_mgr.global_lport_list_lock,
				       flags);

		ret = unf_cm_sfp_switch(lport->port_id, UNF_TRUE);
		if (ret != RETURN_OK) {
			UNF_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_REG_ATT,
				  UNF_ERR,
				  "[err]Port(0x%x) reopen SFP failed in DIF switch",
				  lport->port_id);

			return UNF_ADMIN_MSG_FAILED;
		}

		spin_lock_irqsave(&global_lport_mgr.global_lport_list_lock,
				  flags);
	}
	spin_unlock_irqrestore(&global_lport_mgr.global_lport_list_lock, flags);

	return UNF_ADMIN_MSG_DONE;
}

static int unf_cm_switch_app_ref_escape(unsigned int v_option)
{
	switch (v_option) {
	case UNF_APP_REF_ESC_BOTH_NOT_CHECK:
		dif_app_esc_check = HIFC_DIF_APP_REF_ESC_NOT_CHECK;
		dif_ref_esc_check = HIFC_DIF_APP_REF_ESC_NOT_CHECK;
		break;

	case UNF_APP_ESC_CHECK:
		dif_app_esc_check = HIFC_DIF_APP_REF_ESC_CHECK;
		dif_ref_esc_check = HIFC_DIF_APP_REF_ESC_NOT_CHECK;
		break;

	case UNF_REF_ESC_CHECK:
		dif_app_esc_check = HIFC_DIF_APP_REF_ESC_NOT_CHECK;
		dif_ref_esc_check = HIFC_DIF_APP_REF_ESC_CHECK;
		break;

	case UNF_APP_REF_ESC_BOTH_CHECK:
		dif_app_esc_check = HIFC_DIF_APP_REF_ESC_CHECK;
		dif_ref_esc_check = HIFC_DIF_APP_REF_ESC_CHECK;
		break;

	default:
		dif_app_esc_check = HIFC_DIF_APP_REF_ESC_CHECK;
		dif_ref_esc_check = HIFC_DIF_APP_REF_ESC_CHECK;
		break;
	}

	return UNF_ADMIN_MSG_DONE;
}

static int unf_cm_select_dif_mode(struct unf_lport_s *v_lport,
				  struct unf_hinicam_pkg *v_input)
{
	unsigned int dif_mode = 0;
	unsigned int option = 0;
	unsigned int dix_ip_checksum = 0;
	struct unf_adm_cmd *buff_in = NULL;
	struct unf_adm_cmd *buff_out = NULL;
	struct unf_admin_msg_head msg_head = { 0 };

	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE, v_input,
			return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE, v_input->buff_out,
			return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE, v_input->buff_in,
			return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE,
			v_input->in_size >= sizeof(struct unf_adm_cmd),
			return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE,
			*v_input->out_size >= sizeof(struct unf_adm_cmd),
			return UNF_RETURN_ERROR);

	buff_in = (struct unf_adm_cmd *)v_input->buff_in;
	buff_out = (struct unf_adm_cmd *)v_input->buff_out;
	msg_head.status = UNF_ADMIN_MSG_DONE;
	dif_mode = buff_in->arg[0];
	option = buff_in->arg[1];
	dix_ip_checksum = buff_in->arg[2];

	UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_REG_ATT, UNF_MAJOR,
		  "[info]DIF mode(0x%x) sub option(0x%x 0x%x)",
		  dif_mode, option, dix_ip_checksum);

	switch (dif_mode) {
	case UNF_SWITCH_DIF_DIX:
		msg_head.status =
			(unsigned short)unf_cm_switch_dif(option,
							  dix_ip_checksum);
		break;

	case UNF_APP_REF_ESCAPE:
		msg_head.status =
			(unsigned short)unf_cm_switch_app_ref_escape(option);
		break;

	default:
		msg_head.status = UNF_ADMIN_MSG_FAILED;
		goto end;
	}

end:
	msg_head.size = sizeof(struct unf_admin_msg_head);
	*v_input->out_size = sizeof(struct unf_adm_cmd);
	memcpy(buff_out, &msg_head, sizeof(struct unf_admin_msg_head));

	return RETURN_OK;
}

static int unf_cm_set_dif(struct unf_lport_s *v_lport,
			  struct unf_hinicam_pkg *v_input)
{
	unsigned int dif_switch = 0;
	struct unf_adm_cmd *buff_in = NULL;
	struct unf_adm_cmd *buff_out = NULL;
	struct unf_admin_msg_head msg_head = { 0 };

	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE, v_input,
			return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE, v_input->buff_out,
			return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE, v_input->buff_in,
			return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE,
			v_input->in_size >= sizeof(struct unf_adm_cmd),
			return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE,
			*v_input->out_size >= sizeof(struct unf_adm_cmd),
			return UNF_RETURN_ERROR);
	buff_in = (struct unf_adm_cmd *)v_input->buff_in;
	buff_out = (struct unf_adm_cmd *)v_input->buff_out;
	msg_head.status = UNF_ADMIN_MSG_DONE;
	dif_switch = (buff_in->arg[0]) ?
		     UNF_ENABLE_DIF_DIX_PROT : UNF_DIF_ACTION_NONE;

	UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_REG_ATT, UNF_MAJOR,
		  "[info]DIF switch is 0x%x", dif_switch);

	if (dif_switch == UNF_ENABLE_DIF_DIX_PROT)
		msg_head.status = (unsigned short)unf_cm_switch_dif(dif_switch,
					UNF_ENABLE_IP_CHECKSUM);
	else
		msg_head.status = (unsigned short)unf_cm_switch_dif(dif_switch,
					UNF_DISABLE_IP_CHECKSUM);

	msg_head.size = sizeof(struct unf_admin_msg_head);
	*v_input->out_size = sizeof(struct unf_adm_cmd);
	memcpy(buff_out, &msg_head, sizeof(struct unf_admin_msg_head));

	return RETURN_OK;
}

static unsigned int unf_save_port_info(struct unf_lport_s *lport,
				       void *save_info_addr)
{
	unsigned int ret = UNF_RETURN_ERROR;

	UNF_CHECK_VALID(0x2271, UNF_TRUE, save_info_addr,
			return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(0x2271, UNF_TRUE, lport, return UNF_RETURN_ERROR);

	if (!lport->low_level_func.port_mgr_op.pfn_ll_port_config_set) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_EQUIP_ATT, UNF_MAJOR,
			  "Port(0x%x)'s corresponding function is NULL.",
			  lport->port_id);

		return ret;
	}

	ret = lport->low_level_func.port_mgr_op.pfn_ll_port_config_set(
		lport->fc_port,
		UNF_PORT_CFG_SAVE_HBA_INFO, (void *)save_info_addr);

	return ret;
}

static unsigned int unf_save_port_base_info(struct unf_lport_s *lport,
					    void *v_save_info)
{
	struct unf_save_info_head_s *save_info_head = v_save_info;
	struct unf_port_info_entry_s *sava_port_entry = NULL;
	struct unf_low_level_port_mgr_op_s *port_mgr = NULL;
	unsigned int cfg_speed = 0;
	unsigned int topo_cfg = 0;
	int fec = UNF_FALSE;
	int ret = UNF_RETURN_ERROR;

	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE, lport,
			return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE, save_info_head,
			return UNF_RETURN_ERROR);

	save_info_head->opcode = 0;
	/* write information to up */
	save_info_head->type = UNF_PORT_BASE_INFO; /* port base info */
	save_info_head->entry_num = 1;
	save_info_head->next = 0xffff;

	sava_port_entry = (struct unf_port_info_entry_s *)
			  ((void *)(save_info_head + 1));

	port_mgr = &lport->low_level_func.port_mgr_op;
	if (!port_mgr->pfn_ll_port_config_get) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_EQUIP_ATT, UNF_MAJOR,
			  "Port(0x%x)'s corresponding function is NULL.",
			  lport->nport_id);

		return UNF_RETURN_ERROR;
	}

	/* get Bbscn */
	sava_port_entry->bb_scn = unf_low_level_bbscn(lport);

	/* get speed */
	port_mgr->pfn_ll_port_config_get(lport->fc_port,
					 UNF_PORT_CFG_GET_SPEED_CFG,
					 (void *)&cfg_speed);
	sava_port_entry->speed = cfg_speed;

	/* get topo */
	port_mgr->pfn_ll_port_config_get(lport->fc_port,
					 UNF_PORT_CFG_GET_TOPO_CFG,
					 (void *)&topo_cfg);
	sava_port_entry->topo = topo_cfg;

	/* get fec */
	port_mgr->pfn_ll_port_config_get(lport->fc_port,
					 UNF_PORT_CFG_GET_FEC,
					 (void *)&fec);
	sava_port_entry->fec = fec;

	ret = (int)unf_save_port_info(lport, v_save_info);
	if (ret != RETURN_OK) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_EQUIP_ATT, UNF_WARN,
			  "[warn]Port(0x%x) send mailbox fail",
			  lport->port_id);

		return UNF_RETURN_ERROR;
	}

	return RETURN_OK;
}

unsigned int unf_cm_save_port_info(unsigned int v_port_id)
{
	unsigned int port_id = v_port_id;
	struct unf_lport_s *lport = NULL;
	struct unf_save_info_head_s *save_info = NULL;
	unsigned int ret = UNF_RETURN_ERROR;

	lport = unf_find_lport_by_port_id(port_id);
	if (!lport) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_EQUIP_ATT, UNF_ERR,
			  "[err]Port(0x%x) can not be found", port_id);

		return ret;
	}

	save_info = vmalloc(SAVE_PORT_INFO_LEN);
	if (!save_info) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_NORMAL, UNF_ERR,
			  "[err]Can't alloc buffer for saving port info");

		return ret;
	}

	/* 1 clean flush */
	memset(save_info, 0, SAVE_PORT_INFO_LEN);

	save_info->opcode = 2; /* notify up to clean flush */
	save_info->type = 0xf;
	save_info->entry_num = 0;
	save_info->next = 0xffff;

	ret = unf_save_port_info(lport, save_info);
	if (ret != RETURN_OK) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_EQUIP_ATT, UNF_MAJOR,
			  "[warn]Port(0x%x) send mailbox fail", lport->port_id);

		vfree(save_info);

		return ret;
	}

	/* 2 save port base information */
	memset(save_info, 0, SAVE_PORT_INFO_LEN);

	ret = unf_save_port_base_info(lport, save_info);
	if (ret != RETURN_OK) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_EQUIP_ATT, UNF_ERR,
			  "[err]Port(0x%x) save port base information failed",
			  lport->port_id);

		vfree(save_info);

		return ret;
	}

	vfree(save_info);

	return ret;
}

static void unf_handle_port_base_info(struct unf_lport_s *lport,
				      struct unf_port_info_entry_s *v_save_info)
{
	struct unf_port_info_entry_s *sava_port_entry = NULL;
	unsigned int ret = UNF_RETURN_ERROR;

	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE, lport, return);
	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE, v_save_info, return);

	sava_port_entry = v_save_info;

	UNF_CHECK_VALID(INVALID_VALUE32,
			UNF_TRUE,
			(sava_port_entry->topo == UNF_TOP_LOOP_MASK) ||
			(sava_port_entry->topo == UNF_TOP_P2P_MASK) ||
			(sava_port_entry->topo == UNF_TOP_AUTO_MASK),
			return);

	if (!lport->low_level_func.port_mgr_op.pfn_ll_port_config_set) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_EQUIP_ATT, UNF_ERR,
			  "Port(0x%x)'s corresponding function is NULL.",
			  lport->port_id);
		return;
	}

	ret = lport->low_level_func.port_mgr_op.pfn_ll_port_config_set(
		lport->fc_port,
		UNF_PORT_CFG_SET_HBA_BASE_INFO, (void *)sava_port_entry);

	if (ret != RETURN_OK) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_EQUIP_ATT, UNF_ERR,
			  "Cannot set port base info");
		return;
	}

	/* update bbsn cfg to Lport */
	lport->low_level_func.lport_cfg_items.bb_scn = sava_port_entry->bb_scn;

	lport->low_level_func.lport_cfg_items.port_topology =
		sava_port_entry->topo;
}

static unsigned int unf_recovery_save_info(struct unf_lport_s *lport,
					   void *v_save_info,
					   unsigned char v_type)
{
	struct unf_save_info_head_s *save_info_head = v_save_info;
	void *info_entry = NULL;
	int ret = 0;
	unsigned short next_flag = 0;
	unsigned char entry_num = 0;
	unsigned char index = 0;

	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE, lport,
			return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE, save_info_head,
			return UNF_RETURN_ERROR);

	do {
		memset(save_info_head, 0, SAVE_PORT_INFO_LEN);
		save_info_head->opcode = 1;
		/* read information from up */
		save_info_head->type = v_type;
		/* vport[qos] info */
		save_info_head->entry_num = 0xff;
		save_info_head->next = next_flag;

		ret = (int)unf_save_port_info(lport, save_info_head);
		if (ret != RETURN_OK) {
			UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_EQUIP_ATT,
				  UNF_WARN,
				  "[warn]Port(0x%x) send mailbox fail",
				  lport->port_id);

			return UNF_RETURN_ERROR;
		}

		next_flag = (unsigned short)save_info_head->next;
		entry_num = (unsigned char)save_info_head->entry_num;
		info_entry = save_info_head + 1;

		for (index = 0; index < entry_num; index++) {
			switch (v_type) {
			case UNF_PORT_BASE_INFO:
				unf_handle_port_base_info(lport, info_entry);
				info_entry = ((struct unf_port_info_entry_s *)
					      info_entry) + 1;
				break;

			default:
				UNF_TRACE(UNF_EVTLOG_DRIVER_ERR,
					  UNF_LOG_EQUIP_ATT,
					  UNF_ERR,
					  "[err]Port(0x%x) handle message failed",
					  lport->port_id);
				return UNF_RETURN_ERROR;
			}
		}

	} while (next_flag != 0xffff);

	return RETURN_OK;
}

unsigned int unf_cm_get_save_info(struct unf_lport_s *v_lport)
{
	struct unf_lport_s *lport = NULL;
	void *save_info = NULL;
	unsigned int ret = UNF_RETURN_ERROR;

	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE, v_lport,
			return UNF_RETURN_ERROR);

	lport = v_lport;
	save_info = vmalloc(SAVE_PORT_INFO_LEN);
	if (!save_info) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_NORMAL, UNF_ERR,
			  "[err]Can't alloc buffer for saving port info");

		return ret;
	}

	/* 1 get port base information */
	ret = unf_recovery_save_info(lport, save_info, UNF_PORT_BASE_INFO);
	if (ret != RETURN_OK) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_EQUIP_ATT, UNF_MAJOR,
			  "[warn]Port(0x%x) send mailbox fail", lport->port_id);

		vfree(save_info);

		return ret;
	}

	vfree(save_info);

	return ret;
}

int unf_get_link_lose_tmo(struct unf_lport_s *v_lport)
{
	unsigned int tmo_value = 0;

	if (!v_lport)
		return UNF_LOSE_TMO;

	tmo_value = atomic_read(&v_lport->link_lose_tmo);

	if (!tmo_value)
		tmo_value = UNF_LOSE_TMO;

	return (int)tmo_value;
}

int unf_get_link_lose_tmo_from_up(struct unf_lport_s *v_lport,
				  struct unf_flash_link_tmo_s *v_link_tmo)
{
	int ret = UNF_RETURN_ERROR;
	struct unf_flash_data_s flash_data;

	if (!v_lport || !v_link_tmo || (sizeof(struct unf_flash_data_s)
	    > HIFC_FLASH_DATA_MAX_LEN)) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_NORMAL, UNF_KEVENT,
			  "[warn]get flas link tmo param check fail");
		return ret;
	}
	memset(&flash_data, 0, sizeof(struct unf_flash_data_s));

	if (!v_lport->low_level_func.port_mgr_op.pfn_ll_port_config_get) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_NORMAL, UNF_KEVENT,
			  "[warn]link tmo fun null");
		return ret;
	}
	if (v_lport->low_level_func.port_mgr_op.pfn_ll_port_config_get(
		v_lport->fc_port,
		UNF_PORT_CFG_GET_FLASH_DATA_INFO, &flash_data) !=
	    RETURN_OK) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_NORMAL, UNF_KEVENT,
			  "[warn]get link tmo from up fail");
		return ret;
	}
	ret = RETURN_OK;
	memcpy(v_link_tmo, &flash_data.link_tmo, HIFC_FLASH_LINK_TMO_MAX_LEN);

	return ret;
}

void unf_init_link_lose_tmo(struct unf_lport_s *v_lport)
{
	struct unf_flash_link_tmo_s flash_link_tmo;
	unsigned int tmo;

	memset(&flash_link_tmo, 0, sizeof(struct unf_flash_link_tmo_s));

	if (!v_lport) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_EQUIP_ATT, UNF_MAJOR,
			  "[warn]int link tmo param check fail");
		return;
	}
	if ((unf_get_link_lose_tmo_from_up(v_lport, &flash_link_tmo) ==
	     RETURN_OK) &&
	    (flash_link_tmo.writeflag == HIFC_MGMT_TMO_MAGIC_NUM)) {
		tmo = (((unsigned int)flash_link_tmo.link_tmo3 << 24) |
				((unsigned int)flash_link_tmo.link_tmo2 << 16) |
				((unsigned int)flash_link_tmo.link_tmo1 << 8) |
				flash_link_tmo.link_tmo0);
		if (tmo > 600)
			unf_set_link_lose_tmo(v_lport, UNF_LOSE_TMO);
		else
			atomic_set(&v_lport->link_lose_tmo, (int)tmo);
	} else {
		unf_set_link_lose_tmo(v_lport, UNF_LOSE_TMO);
	}
}

unsigned int unf_register_scsi_host(struct unf_lport_s *v_lport)
{
	struct unf_host_param_s host_param = { 0 };
	unf_scsi_host_s **p_scsi_host = NULL;
	struct unf_lport_cfg_item_s *lport_cfg_items = NULL;

	UNF_CHECK_VALID(0x1359, TRUE, v_lport, return UNF_RETURN_ERROR);

	/* Point to -->> L_port->Scsi_host */
	p_scsi_host = &v_lport->host_info.p_scsi_host;

	lport_cfg_items = &v_lport->low_level_func.lport_cfg_items;
	host_param.can_queue = (int)lport_cfg_items->max_queue_depth;

	/* Performance optimization */
	host_param.cmnd_per_lun = UNF_MAX_CMND_PER_LUN;

	host_param.sg_table_size = UNF_MAX_DMA_SEGS;
	host_param.max_id = UNF_MAX_TARGET_NUMBER;
	host_param.max_lun = UNF_DEFAULT_MAX_LUN;
	host_param.max_channel = UNF_MAX_BUS_CHANNEL;
	host_param.max_cmnd_len = UNF_MAX_SCSI_CMND_LEN;  /* CDB-16 */
	host_param.dma_boundary = UNF_DMA_BOUNDARY;
	host_param.max_sectors = UNF_MAX_SECTORS;
	host_param.port_id = v_lport->port_id;
	host_param.lport = v_lport;
	host_param.pdev = &v_lport->low_level_func.dev->dev;

	UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_REG_ATT, UNF_INFO,
		  "[info]Port(0x%x) allocate scsi host: can queue(%u), command performance LUN(%u), max lun(%u)",
		  v_lport->port_id, host_param.can_queue,
		  host_param.cmnd_per_lun, host_param.max_lun);

	if (unf_alloc_scsi_host(p_scsi_host, &host_param) != RETURN_OK) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_REG_ATT, UNF_ERR,
			  "[err]Port(0x%x) allocate scsi host failed",
			  v_lport->port_id);

		return UNF_RETURN_ERROR;
	}

	UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_REG_ATT, UNF_KEVENT,
		  "[event]Port(0x%x) allocate scsi host(0x%x) succeed",
		  v_lport->port_id, UNF_GET_SCSI_HOST_ID(*p_scsi_host));

	return RETURN_OK;
}

void unf_unregister_scsi_host(struct unf_lport_s *v_lport)
{
	unf_scsi_host_s *p_scsi_host = NULL;
	unsigned int host_no = 0;

	UNF_REFERNCE_VAR(p_scsi_host);
	UNF_CHECK_VALID(0x1360, TRUE, v_lport, return);

	p_scsi_host = v_lport->host_info.p_scsi_host;

	if (p_scsi_host) {
		host_no = UNF_GET_SCSI_HOST_ID(p_scsi_host);
		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_REG_ATT, UNF_MAJOR,
			  "[event]Port(0x%x) starting unregister scsi host(0x%x)",
			  v_lport->port_id, host_no);

		unf_free_scsi_host(p_scsi_host);
		/* can`t set p_scsi_host for NULL,
		 * since it does`t alloc by itself
		 */
	} else {
		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_REG_ATT, UNF_KEVENT,
			  "[warn]Port(0x%x) unregister scsi host, invalid ScsiHost ",
			  v_lport->port_id);
	}

	UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_REG_ATT, UNF_MAJOR,
		  "[event]Port(0x%x) unregister scsi host(0x%x) succeed",
		  v_lport->port_id, host_no);

	v_lport->destroy_step = UNF_LPORT_DESTROY_STEP_12_UNREG_SCSI_HOST;

	UNF_REFERNCE_VAR(p_scsi_host);
	UNF_REFERNCE_VAR(host_no);
}

unsigned int unf_cm_clear_flush(unsigned int v_port_id)
{
	unsigned int port_id = v_port_id;
	struct unf_lport_s *lport = NULL;
	struct unf_save_info_head_s *save_info = NULL;
	unsigned int ret = UNF_RETURN_ERROR;

	lport = unf_find_lport_by_port_id(port_id);
	if (!lport) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_EQUIP_ATT, UNF_ERR,
			  "[err]Port(0x%x) can not be found", port_id);

		return ret;
	}

	save_info = vmalloc(SAVE_PORT_INFO_LEN);
	if (!save_info) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_NORMAL, UNF_ERR,
			  "[err]Can't alloc buffer for saving port info");

		return ret;
	}

	/* 1 clean flush */
	memset(save_info, 0, SAVE_PORT_INFO_LEN);

	save_info->opcode = 2; /* notify up to clean flush */
	save_info->type = 0xf;
	save_info->entry_num = 0;
	save_info->next = 0xffff;

	ret = unf_save_port_info(lport, save_info);
	if (ret != RETURN_OK) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_EQUIP_ATT, UNF_MAJOR,
			  "[warn]Port(0x%x) send mailbox fail", lport->port_id);

		vfree(save_info);

		return ret;
	}

	vfree(save_info);

	return ret;
}

static int unf_cm_save_data_mode(struct unf_lport_s *v_lport,
				 struct unf_hinicam_pkg *v_input)
{
	int ret = UNF_RETURN_ERROR;
	unsigned int save_data_mode = 0;
	unsigned int port_id = 0;
	void *out_buf = NULL;
	struct unf_adm_cmd *buff_in = NULL;
	struct unf_admin_msg_head msg_head = { 0 };

	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE, v_input,
			return UNF_RETURN_ERROR);
	out_buf = v_input->buff_out;
	buff_in = v_input->buff_in;
	port_id = v_lport->port_id;
	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE, out_buf,
			return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE, buff_in,
			return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE,
			v_input->in_size >= sizeof(struct unf_adm_cmd),
			return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE,
			*v_input->out_size >= sizeof(struct unf_adm_cmd),
			return UNF_RETURN_ERROR);

	save_data_mode = buff_in->arg[0];

	msg_head.status = UNF_ADMIN_MSG_DONE;

	if (save_data_mode == UNF_SAVA_INFO_MODE) {
		ret = (int)unf_cm_save_port_info(port_id);
		if (ret != RETURN_OK)
			msg_head.status = UNF_ADMIN_MSG_FAILED;
	} else if (save_data_mode == UNF_CLEAN_INFO_MODE) {
		ret = (int)unf_cm_clear_flush(port_id);
		if (ret != RETURN_OK)
			msg_head.status = UNF_ADMIN_MSG_FAILED;
	} else {
		UNF_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_REG_ATT, UNF_MAJOR,
			  "[err]This mode(0x%x) is unknown", save_data_mode);
		msg_head.status = UNF_ADMIN_MSG_FAILED;
	}

	msg_head.size = sizeof(struct unf_admin_msg_head);
	*v_input->out_size = sizeof(struct unf_adm_cmd);
	memcpy(out_buf, &msg_head, sizeof(struct unf_admin_msg_head));

	return ret;
}

int unf_cmd_adm_handler(void *v_lport, struct unf_hinicam_pkg *v_input)
{
	struct unf_lport_s *lport = NULL;
	int ret = UNF_RETURN_ERROR;
	enum unf_msg_format_e msg_formate;
	unsigned int index = 0;

	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE, v_lport,
			return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE, v_input,
			return UNF_RETURN_ERROR);
	lport = (struct unf_lport_s *)v_lport;
	msg_formate = v_input->msg_format;

	UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_REG_ATT, UNF_INFO,
		  "[info]Enter HIFC_Adm, msg_formate=0x%x, 0x%x",
		  msg_formate, *v_input->out_size);

	/* hifcadm event */
	while (index < (sizeof(unf_hifcadm_action) /
	       sizeof(struct unf_hifcadm_action_s))) {
		if ((msg_formate == unf_hifcadm_action[index].hifc_action) &&
		    unf_hifcadm_action[index].fn_unf_hifc_action) {
			ret = unf_hifcadm_action[index].fn_unf_hifc_action(lport, v_input);
			if (ret != RETURN_OK) {
				UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_EVENT,
					  UNF_WARN,
					  "[warn]Port(0x%x) process up msg(0x%x) failed",
					  lport->port_id, msg_formate);
			}
			return ret;
		}
		index++;
	}

	UNF_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_EVENT, UNF_KEVENT,
		  "[event]Port(0x%x) not support adm cmd, msg type(0x%x) ",
		  lport->port_id, msg_formate);

	return ret;
}
