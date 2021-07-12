// SPDX-License-Identifier: GPL-2.0
/* Huawei Hifc PCI Express Linux driver
 * Copyright(c) 2017 Huawei Technologies Co., Ltd
 *
 */

#include "unf_log.h"
#include "unf_common.h"
#include "unf_exchg.h"
#include "unf_rport.h"
#include "unf_service.h"
#include "unf_io.h"

#define UNF_DEL_XCHG_TIMER_SAFE(v_xchg) \
	do { \
		if (cancel_delayed_work(&((v_xchg)->timeout_work))) { \
			UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_IO_ATT, \
				  UNF_MAJOR, \
				  "Exchange(0x%p) is free, but timer is pending.", \
				  v_xchg); \
		} else { \
			UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_IO_ATT, \
				  UNF_CRITICAL, \
				  "Exchange(0x%p) is free, but timer is running.", \
				  v_xchg); \
		} \
	} while (0)

#define UNF_XCHG_IS_ELS_REPLY(v_xchg) \
	((((v_xchg)->cmnd_code & 0x0ffff) == ELS_ACC) ||  \
	(((v_xchg)->cmnd_code & 0x0ffff) == ELS_RJT))

static struct unf_ioflow_id_s io_stage[] = {
	{ "XCHG_ALLOC" },
	{ "TGT_RECEIVE_ABTS" },
	{ "TGT_ABTS_DONE" },
	{ "TGT_IO_SRR" },
	{ "SFS_RESPONSE" },
	{ "SFS_TIMEOUT" },
	{ "INI_SEND_CMND" },
	{ "INI_RESPONSE_DONE" },
	{ "INI_EH_ABORT" },
	{ "INI_EH_DEVICE_RESET" },
	{ "INI_EH_BLS_DONE" },
	{ "INI_IO_TIMEOUT" },
	{ "INI_REQ_TIMEOUT" },
	{ "XCHG_CANCEL_TIMER" },
	{ "XCHG_FREE_XCHG" },
	{ "SEND_ELS" },
	{ "IO_XCHG_WAIT" },
};

void unf_wakeup_scsi_task_cmnd(struct unf_lport_s *v_lport)
{
	struct list_head *node = NULL;
	struct list_head *next_node = NULL;
	struct unf_xchg_s *xchg = NULL;
	unsigned long hot_pool_lock_flags = 0;
	unsigned long xchg_flag = 0;
	struct unf_xchg_mgr_s *xchg_mgr = NULL;
	unsigned int i = 0;

	UNF_CHECK_VALID(0x850, UNF_TRUE, v_lport, return);

	for (i = 0; i < UNF_EXCHG_MGR_NUM; i++) {
		xchg_mgr = unf_get_xchg_mgr_by_lport(v_lport, i);

		if (!xchg_mgr) {
			UNF_TRACE(UNF_EVTLOG_DRIVER_INFO,
				  UNF_LOG_EVENT, UNF_MINOR,
				  "Can't find LPort(0x%x) MgrIdx %u exchange manager.",
				  v_lport->port_id, i);
			continue;
		}

		spin_lock_irqsave(&xchg_mgr->hot_pool->xchg_hot_pool_lock,
				  hot_pool_lock_flags);
		list_for_each_safe(node, next_node,
				   &xchg_mgr->hot_pool->ini_busylist) {
			xchg = list_entry(node, struct unf_xchg_s,
					  list_xchg_entry);

			spin_lock_irqsave(&xchg->xchg_state_lock, xchg_flag);
			if (INI_IO_STATE_UPTASK & xchg->io_state &&
			    (atomic_read(&xchg->ref_cnt) > 0)) {
				UNF_SET_SCSI_CMND_RESULT(xchg, UNF_IO_SUCCESS);
				up(&xchg->task_sema);
				UNF_TRACE(UNF_EVTLOG_DRIVER_INFO,
					  UNF_LOG_EVENT, UNF_MINOR,
					  "Wake up task command exchange(0x%p), Hot Pool Tag(0x%x).",
					  xchg, xchg->hot_pool_tag);
			}
			spin_unlock_irqrestore(&xchg->xchg_state_lock,
					       xchg_flag);
		}

		spin_unlock_irqrestore(&xchg_mgr->hot_pool->xchg_hot_pool_lock,
				       hot_pool_lock_flags);
	}
}

void unf_cm_xchg_mgr_abort_io_by_id(struct unf_lport_s *v_lport,
				    struct unf_rport_s *v_rport,
				    unsigned int v_sid, unsigned int v_did,
				    unsigned int v_extra_io_state)
{
	/*
	 * for target session: set ABORT
	 * 1. R_Port remove
	 * 2. Send PLOGI_ACC callback
	 * 3. RCVD PLOGI
	 * 4. RCVD LOGO
	 */
	UNF_CHECK_VALID(0x852, UNF_TRUE, v_lport, return);

	if (v_lport->xchg_mgr_temp.pfn_unf_xchg_mgr_io_xchg_abort) {
		/* The SID/DID of the Xchg is in reverse direction in
		 * different phases. Therefore, the reverse direction
		 * needs to be considered
		 */
		v_lport->xchg_mgr_temp.pfn_unf_xchg_mgr_io_xchg_abort(
							v_lport,
							v_rport,
							v_sid, v_did,
							v_extra_io_state);
		v_lport->xchg_mgr_temp.pfn_unf_xchg_mgr_io_xchg_abort(
							v_lport, v_rport,
							v_did, v_sid,
							v_extra_io_state);
	}
}

void unf_cm_xchg_mgr_abort_sfs_by_id(struct unf_lport_s *v_lport,
				     struct unf_rport_s *v_rport,
				     unsigned int v_sid, unsigned int v_did)
{
	UNF_CHECK_VALID(0x990, UNF_TRUE, v_lport, return);

	if (v_lport->xchg_mgr_temp.pfn_unf_xchg_mgr_sfs_xchg_abort) {
		/* The SID/DID of the Xchg is in reverse direction in different
		 * phases, therefore, the reverse direction
		 * needs to be considered
		 */
		v_lport->xchg_mgr_temp.pfn_unf_xchg_mgr_sfs_xchg_abort(v_lport,
								       v_rport,
								       v_sid,
								       v_did);
		v_lport->xchg_mgr_temp.pfn_unf_xchg_mgr_sfs_xchg_abort(v_lport,
								       v_rport,
								       v_did,
								       v_sid);
	}
}

void unf_cm_xchg_abort_by_lun(struct unf_lport_s *v_lport,
			      struct unf_rport_s *v_rport,
			      unsigned long long v_lun_id,
			      void *v_tm_xchg,
			      int v_abort_all_lun_flag)
{
	/*
	 * LUN Reset: set UP_ABORT tag, with:
	 * INI_Busy_list, IO_Wait_list,
	 * IO_Delay_list, IO_Delay_transfer_list
	 */
	void (*unf_xchg_abort_by_lun)(void*, void*, unsigned long long,
				      void*, int) = NULL;

	UNF_CHECK_VALID(0x853, UNF_TRUE, v_lport, return);

	unf_xchg_abort_by_lun =
		v_lport->xchg_mgr_temp.pfn_unf_xchg_abort_by_lun;
	if (unf_xchg_abort_by_lun) {
		unf_xchg_abort_by_lun((void *)v_lport, (void *)v_rport,
				      v_lun_id, v_tm_xchg,
				      v_abort_all_lun_flag);
	}
}

void unf_cm_xchg_abort_by_session(struct unf_lport_s *v_lport,
				  struct unf_rport_s *v_rport)
{
	void (*pfn_unf_xchg_abort_by_session)(void*, void*) = NULL;

	UNF_CHECK_VALID(0x853, UNF_TRUE, v_lport, return);

	pfn_unf_xchg_abort_by_session =
		v_lport->xchg_mgr_temp.pfn_unf_xchg_abort_by_session;
	if (pfn_unf_xchg_abort_by_session) {
		pfn_unf_xchg_abort_by_session((void *)v_lport,
					      (void *)v_rport);
	}
}

void *unf_cm_get_free_xchg(void *v_lport, unsigned int v_xchg_type)
{
	struct unf_lport_s *lport = NULL;
	struct unf_cm_xchg_mgr_template_s *xch_mgr_temp = NULL;

	UNF_CHECK_VALID(0x855, UNF_TRUE, unlikely(v_lport), return NULL);

	lport = (struct unf_lport_s *)v_lport;
	xch_mgr_temp = &lport->xchg_mgr_temp;

	/* Find the corresponding Lport Xchg management template. */
	UNF_CHECK_VALID(0x856, UNF_TRUE,
			unlikely(xch_mgr_temp->pfn_unf_xchg_get_free_and_init),
			return NULL);

	return xch_mgr_temp->pfn_unf_xchg_get_free_and_init(lport, v_xchg_type,
							    INVALID_VALUE16);
}

void unf_cm_free_xchg(void *v_lport, void *v_xchg)
{
	struct unf_lport_s *lport = NULL;
	struct unf_cm_xchg_mgr_template_s *xch_mgr_temp = NULL;

	UNF_CHECK_VALID(0x857, UNF_TRUE, unlikely(v_lport), return);
	UNF_CHECK_VALID(0x858, UNF_TRUE, unlikely(v_xchg), return);

	lport = (struct unf_lport_s *)v_lport;
	xch_mgr_temp = &lport->xchg_mgr_temp;
	UNF_CHECK_VALID(0x859, UNF_TRUE,
			unlikely(xch_mgr_temp->pfn_unf_xchg_release),
			return);

	/*
	 * unf_cm_free_xchg --->>> unf_free_xchg
	 * --->>> unf_xchg_ref_dec --->>> unf_free_fcp_xchg
	 * --->>> unf_done_ini_xchg
	 */
	xch_mgr_temp->pfn_unf_xchg_release(v_lport, v_xchg);
}

void *unf_cm_lookup_xchg_by_tag(void *v_lport, unsigned short v_hot_pool_tag)
{
	struct unf_lport_s *lport = NULL;
	struct unf_cm_xchg_mgr_template_s *xch_mgr_temp = NULL;

	UNF_CHECK_VALID(0x860, UNF_TRUE, unlikely(v_lport), return NULL);

	/* Find the corresponding Lport Xchg management template */
	lport = (struct unf_lport_s *)v_lport;
	xch_mgr_temp = &lport->xchg_mgr_temp;

	UNF_CHECK_VALID(0x861, UNF_TRUE,
			unlikely(xch_mgr_temp->pfn_unf_look_up_xchg_by_tag),
			return NULL);

	return xch_mgr_temp->pfn_unf_look_up_xchg_by_tag(v_lport,
							 v_hot_pool_tag);
}

void *unf_cm_lookup_xchg_by_id(void *v_lport, unsigned short v_ox_id,
			       unsigned int v_oid)
{
	struct unf_lport_s *lport = NULL;
	struct unf_cm_xchg_mgr_template_s *xch_mgr_temp = NULL;

	UNF_CHECK_VALID(0x862, UNF_TRUE, unlikely(v_lport), return NULL);

	lport = (struct unf_lport_s *)v_lport;
	xch_mgr_temp = &lport->xchg_mgr_temp;

	/* Find the corresponding Lport Xchg management template */
	UNF_CHECK_VALID(0x863, UNF_TRUE,
			unlikely(xch_mgr_temp->pfn_unf_look_up_xchg_by_id),
			return NULL);

	return xch_mgr_temp->pfn_unf_look_up_xchg_by_id(v_lport, v_ox_id,
							v_oid);
}

struct unf_xchg_s *unf_cm_lookup_xchg_by_cmnd_sn(
					void *v_lport,
					unsigned long long v_command_sn,
					unsigned int v_world_id)
{
	struct unf_lport_s *lport = NULL;
	struct unf_cm_xchg_mgr_template_s *xch_mgr_temp = NULL;
	struct unf_xchg_s *xchg = NULL;

	UNF_CHECK_VALID(0x864, UNF_TRUE, unlikely(v_lport), return NULL);

	lport = (struct unf_lport_s *)v_lport;
	xch_mgr_temp = &lport->xchg_mgr_temp;

	UNF_CHECK_VALID(
		0x865, UNF_TRUE,
		unlikely(xch_mgr_temp->pfn_unf_look_up_xchg_by_cmnd_sn),
		return NULL);

	xchg =
	(struct unf_xchg_s *)xch_mgr_temp->pfn_unf_look_up_xchg_by_cmnd_sn(
						lport, v_command_sn,
						v_world_id);

	return xchg;
}

static void unf_free_all_rsp_pages(struct unf_xchg_mgr_s *v_xchg_mgr)
{
	unsigned int buff_index;

	UNF_CHECK_VALID(0x868, UNF_TRUE, v_xchg_mgr, return);

	if (v_xchg_mgr->rsp_buf_list.buflist) {
		for (buff_index = 0; buff_index <
		     v_xchg_mgr->rsp_buf_list.buf_num;
		     buff_index++) {
			if (v_xchg_mgr->rsp_buf_list.buflist[buff_index].vaddr) {
				dma_free_coherent(
					&v_xchg_mgr->hot_pool->lport->low_level_func.dev->dev,
					v_xchg_mgr->rsp_buf_list.buf_size,
					v_xchg_mgr->rsp_buf_list.buflist[buff_index].vaddr,
					v_xchg_mgr->rsp_buf_list.buflist[buff_index].paddr);
				v_xchg_mgr->rsp_buf_list.buflist[buff_index].vaddr = NULL;
			}
		}

		kfree(v_xchg_mgr->rsp_buf_list.buflist);
		v_xchg_mgr->rsp_buf_list.buflist = NULL;
	}
}

static unsigned int unf_init_xchg(struct unf_lport_s *v_lport,
				  struct unf_xchg_mgr_s *v_xchg_mgr,
				  unsigned int v_xchg_sum,
				  unsigned int v_sfs_sum)
{
	struct unf_xchg_s *xchg_mem = NULL;
	union unf_sfs_u *sfs_mm_start = NULL;
	dma_addr_t sfs_dma_addr;
	struct unf_xchg_s *xchg = NULL;
	struct unf_xchg_free_pool_s *free_pool = NULL;
	unsigned int rsp_iu_nums_per_page = 0;
	unsigned int rsp_iu_size = 0;
	unsigned long flags = 0;
	unsigned int xchg_sum = 0;
	unsigned int i = 0;
	unsigned int rsp_iu_loop = 0;
	unsigned int buf_num;
	unsigned int buf_size;
	unsigned int curbuf_idx = 0;
	void *page_addr;
	dma_addr_t phy_addr;

	UNF_CHECK_VALID(0x871, UNF_TRUE, v_sfs_sum <= v_xchg_sum,
			return UNF_RETURN_ERROR);

	free_pool = &v_xchg_mgr->free_pool;
	xchg_sum = v_xchg_sum;
	xchg_mem = v_xchg_mgr->fcp_mm_start;
	xchg = xchg_mem;

	sfs_mm_start = (union unf_sfs_u *)v_xchg_mgr->sfs_mm_start;
	sfs_dma_addr = v_xchg_mgr->sfs_phy_addr;
	/* 1. Allocate the SFS UNION memory to each SFS XCHG
	 * and mount the SFS XCHG to the corresponding FREE linked list
	 */
	free_pool->total_sfs_xchg = 0;
	free_pool->sfs_xchg_sum = v_sfs_sum;
	for (i = 0; i < v_sfs_sum; i++) {
		INIT_LIST_HEAD(&xchg->list_xchg_entry);
		INIT_LIST_HEAD(&xchg->list_esgls);
		spin_lock_init(&xchg->xchg_state_lock);
		sema_init(&xchg->task_sema, 0);
		sema_init(&xchg->echo_info.echo_sync_sema, 0);

		spin_lock_irqsave(&free_pool->xchg_free_pool_lock, flags);
		xchg->fcp_sfs_union.sfs_entry.fc_sfs_entry_ptr = sfs_mm_start;
		xchg->fcp_sfs_union.sfs_entry.sfs_buff_phy_addr = sfs_dma_addr;
		xchg->fcp_sfs_union.sfs_entry.sfs_buff_len =
			 sizeof(*sfs_mm_start);
		list_add_tail(&xchg->list_xchg_entry,
			      &free_pool->list_sfs_xchg_list);
		free_pool->total_sfs_xchg++;
		spin_unlock_irqrestore(&free_pool->xchg_free_pool_lock, flags);
		sfs_mm_start++;
		sfs_dma_addr = sfs_dma_addr + sizeof(union unf_sfs_u);
		xchg++;
	}

	/*
	 * 2. Allocate RSP IU memory for each IO XCHG and mount IO
	 * XCHG to the corresponding FREE linked list
	 * The memory size of each RSP IU is rsp_iu_size.
	 */
	rsp_iu_size = (UNF_FCPRSP_CTL_LEN + UNF_MAX_RSP_INFO_LEN +
		      UNF_SCSI_SENSE_DATA_LEN);

	buf_size = BUF_LIST_PAGE_SIZE;
	if ((xchg_sum - v_sfs_sum) * rsp_iu_size < BUF_LIST_PAGE_SIZE)
		buf_size = (xchg_sum - v_sfs_sum) * rsp_iu_size;

	rsp_iu_nums_per_page = buf_size / rsp_iu_size;
	buf_num = (xchg_sum - v_sfs_sum) % rsp_iu_nums_per_page ?
		  (xchg_sum - v_sfs_sum) / rsp_iu_nums_per_page + 1 :
		  (xchg_sum - v_sfs_sum) / rsp_iu_nums_per_page;

	v_xchg_mgr->rsp_buf_list.buflist =
		(struct buff_list_s *)kmalloc(
					buf_num * sizeof(struct buff_list_s),
					GFP_KERNEL);
	v_xchg_mgr->rsp_buf_list.buf_num = buf_num;
	v_xchg_mgr->rsp_buf_list.buf_size = buf_size;

	UNF_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_REG_ATT, UNF_MAJOR,
		  "[info]Port(0x%x) buff num 0x%x buff size 0x%x",
		  v_lport->port_id, buf_num,
		  v_xchg_mgr->rsp_buf_list.buf_size);

	if (!v_xchg_mgr->rsp_buf_list.buflist) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_REG_ATT, UNF_WARN,
			  "[err]Allocate BigSfs pool buf list failed out of memory");
		goto free_buff;
	}
	memset(v_xchg_mgr->rsp_buf_list.buflist, 0,
	       buf_num * sizeof(struct buff_list_s));

	free_pool->total_fcp_xchg = 0;
	for (i = 0, curbuf_idx = 0; curbuf_idx < buf_num; curbuf_idx++) {
		page_addr = dma_alloc_coherent(
				&v_lport->low_level_func.dev->dev,
				v_xchg_mgr->rsp_buf_list.buf_size,
				&phy_addr, GFP_KERNEL);
		if (!page_addr)
			goto free_buff;

		memset(page_addr, 0, v_xchg_mgr->rsp_buf_list.buf_size);
		v_xchg_mgr->rsp_buf_list.buflist[curbuf_idx].vaddr = page_addr;
		v_xchg_mgr->rsp_buf_list.buflist[curbuf_idx].paddr = phy_addr;

		for (rsp_iu_loop = 0;
		     (rsp_iu_loop < rsp_iu_nums_per_page &&
		      i < xchg_sum - v_sfs_sum); rsp_iu_loop++) {
			INIT_LIST_HEAD(&xchg->list_xchg_entry);

			INIT_LIST_HEAD(&xchg->list_esgls);
			spin_lock_init(&xchg->xchg_state_lock);
			sema_init(&xchg->task_sema, 0);
			sema_init(&xchg->echo_info.echo_sync_sema, 0);

			/* alloc dma buffer for fcp_rsp_iu */
			spin_lock_irqsave(&free_pool->xchg_free_pool_lock,
					  flags);
			xchg->fcp_sfs_union.fcp_rsp_entry.fcp_rsp_iu =
				(struct unf_fcprsp_iu_s *)page_addr;
			xchg->fcp_sfs_union.fcp_rsp_entry.fcp_rsp_iu_phy_addr =
				phy_addr;
			list_add_tail(&xchg->list_xchg_entry,
				      &free_pool->list_free_xchg_list);
			free_pool->total_fcp_xchg++;
			spin_unlock_irqrestore(&free_pool->xchg_free_pool_lock,
					       flags);

			page_addr += rsp_iu_size;
			phy_addr += rsp_iu_size;
			i++;
			xchg++;
		}
	}

	free_pool->fcp_xchg_sum = free_pool->total_fcp_xchg;

	return RETURN_OK;
free_buff:
	unf_free_all_rsp_pages(v_xchg_mgr);
	return UNF_RETURN_ERROR;
}

static unsigned int unf_get_xchg_config_sum(struct unf_lport_s *v_lport,
					    unsigned int *v_xchg_sum)
{
	struct unf_lport_cfg_item_s *lport_cfg_items = NULL;

	lport_cfg_items = &v_lport->low_level_func.lport_cfg_items;

	/* It has been checked at the bottom layer.
	 * Don't need to check it again.
	 */
	*v_xchg_sum = lport_cfg_items->max_sfs_xchg + lport_cfg_items->max_io;
	if ((*v_xchg_sum / UNF_EXCHG_MGR_NUM) == 0 ||
	    lport_cfg_items->max_sfs_xchg / UNF_EXCHG_MGR_NUM == 0) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_REG_ATT, UNF_ERR,
			  "[err]Port(0x%x) Xchgsum(%u) or SfsXchg(%u) is less than ExchangeMgrNum(%u).",
			  v_lport->port_id, *v_xchg_sum,
			  lport_cfg_items->max_sfs_xchg,
			  UNF_EXCHG_MGR_NUM);
		return UNF_RETURN_ERROR;
	}

	if (*v_xchg_sum > (INVALID_VALUE16 - 1)) {
		/* If the format of ox_id/rx_id is exceeded,
		 * this function is not supported
		 */
		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_REG_ATT, UNF_ERR,
			  "Port(0x%x) Exchange num(0x%x) is Too Big.",
			  v_lport->port_id, *v_xchg_sum);

		return UNF_RETURN_ERROR;
	}

	return RETURN_OK;
}

static void unf_xchg_cancel_timer(void *v_xchg)
{
	struct unf_xchg_s *xchg = NULL;
	int need_dec_xchg_ref = UNF_FALSE;
	unsigned long flag = 0;

	UNF_CHECK_VALID(0x874, UNF_TRUE, v_xchg, return);
	xchg = (struct unf_xchg_s *)v_xchg;

	spin_lock_irqsave(&xchg->xchg_state_lock, flag);
	if (cancel_delayed_work(&xchg->timeout_work))
		need_dec_xchg_ref = UNF_TRUE;
	spin_unlock_irqrestore(&xchg->xchg_state_lock, flag);

	if (need_dec_xchg_ref == UNF_TRUE)
		unf_xchg_ref_dec(v_xchg, XCHG_CANCEL_TIMER);
}

void unf_show_all_xchg(struct unf_lport_s *v_lport,
		       struct unf_xchg_mgr_s *v_xchg_mgr)
{
	struct unf_lport_s *lport = NULL;
	struct unf_xchg_mgr_s *xchg_mgr = NULL;
	struct unf_xchg_s *xchg = NULL;
	struct list_head *xchg_node = NULL;
	struct list_head *next_xchg_node = NULL;
	unsigned long flags = 0;

	UNF_CHECK_VALID(0x879, UNF_TRUE, v_lport, return);
	UNF_CHECK_VALID(0x880, UNF_TRUE, v_xchg_mgr, return);

	UNF_REFERNCE_VAR(lport);
	UNF_REFERNCE_VAR(xchg);

	xchg_mgr = v_xchg_mgr;
	lport = v_lport;

	/* hot Xchg */
	spin_lock_irqsave(&xchg_mgr->hot_pool->xchg_hot_pool_lock, flags);

	UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_NORMAL, UNF_WARN,
		  "INI busy :");
	list_for_each_safe(xchg_node, next_xchg_node,
			   &xchg_mgr->hot_pool->ini_busylist) {
		xchg = list_entry(xchg_node, struct unf_xchg_s,
				  list_xchg_entry);
		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_NORMAL, UNF_MAJOR,
			  "0x%p---0x%x----0x%x----0x%x----0x%x----0x%x----0x%x----0x%x----0x%x----%llu.",
			  xchg,
			  (unsigned int)xchg->hot_pool_tag,
			  (unsigned int)xchg->xchg_type,
			  (unsigned int)xchg->ox_id,
			  (unsigned int)xchg->rx_id,
			  (unsigned int)xchg->sid,
			  (unsigned int)xchg->did,
			  atomic_read(&xchg->ref_cnt),
			  (unsigned int)xchg->io_state,
			  xchg->alloc_jif);
	}

	UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_NORMAL,
		  UNF_WARN, "SFS :");
	list_for_each_safe(xchg_node, next_xchg_node,
			   &xchg_mgr->hot_pool->sfs_busylist) {
		xchg = list_entry(xchg_node, struct unf_xchg_s,
				  list_xchg_entry);
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_NORMAL, UNF_WARN,
			  "0x%p---0x%x---0x%x----0x%x----0x%x----0x%x----0x%x----0x%x----0x%x----0x%x----%llu.",
			  xchg,
			  xchg->cmnd_code,
			  (unsigned int)xchg->hot_pool_tag,
			  (unsigned int)xchg->xchg_type,
			  (unsigned int)xchg->ox_id,
			  (unsigned int)xchg->rx_id,
			  (unsigned int)xchg->sid,
			  (unsigned int)xchg->did,
			  atomic_read(&xchg->ref_cnt),
			  (unsigned int)xchg->io_state,
			  xchg->alloc_jif);
	}

	UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_NORMAL, UNF_WARN,
		  "Destroy list.");
	list_for_each_safe(xchg_node, next_xchg_node,
			   &xchg_mgr->hot_pool->list_destroy_xchg) {
		xchg = list_entry(xchg_node, struct unf_xchg_s,
				  list_xchg_entry);
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_NORMAL, UNF_WARN,
			  "0x%p---0x%x----0x%x----0x%x----0x%x----0x%x----0x%x----0x%x----0x%x----%llu.",
			  xchg,
			  (unsigned int)xchg->hot_pool_tag,
			  (unsigned int)xchg->xchg_type,
			  (unsigned int)xchg->ox_id,
			  (unsigned int)xchg->rx_id,
			  (unsigned int)xchg->sid,
			  (unsigned int)xchg->did,
			  atomic_read(&xchg->ref_cnt),
			  (unsigned int)xchg->io_state,
			  xchg->alloc_jif);
	}
	spin_unlock_irqrestore(&xchg_mgr->hot_pool->xchg_hot_pool_lock, flags);

	UNF_REFERNCE_VAR(xchg);
	UNF_REFERNCE_VAR(lport);
}

static void unf_delay_work_del_syn(struct unf_xchg_s *v_xchg)
{
	struct unf_xchg_s *xchg = NULL;

	UNF_CHECK_VALID(0x884, UNF_TRUE, v_xchg, return);

	xchg = v_xchg;

	/* synchronous release timer */
	if (!cancel_delayed_work_sync(&xchg->timeout_work)) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_REG_ATT, UNF_MAJOR,
			  "Exchange(0x%p), State(0x%x) can't delete work timer, timer is running or no timer.",
			  xchg, xchg->io_state);
	} else {
		/* The reference count cannot be directly subtracted.
		 * This prevents the XCHG from being moved to the
		 * Free linked list when the card is unloaded.
		 */
		unf_cm_free_xchg(xchg->lport, xchg);
	}
}

static void unf_free_lport_sfs_xchg(struct unf_xchg_mgr_s *v_xchg_mgr,
				    int v_done_ini_flag)
{
	struct list_head *list = NULL;
	struct unf_xchg_s *xchg = NULL;
	unsigned long hot_pool_lock_flags = 0;

	UNF_REFERNCE_VAR(v_done_ini_flag);
	UNF_CHECK_VALID(0x887, UNF_TRUE, v_xchg_mgr, return);
	UNF_CHECK_VALID(0x888, UNF_TRUE, v_xchg_mgr->hot_pool, return);

	spin_lock_irqsave(&v_xchg_mgr->hot_pool->xchg_hot_pool_lock,
			  hot_pool_lock_flags);
	while (!list_empty(&v_xchg_mgr->hot_pool->sfs_busylist)) {
		list = (&v_xchg_mgr->hot_pool->sfs_busylist)->next;
		list_del_init(list);

		/* Prevent the xchg of the sfs from being accessed repeatedly.
		 * The xchg is first mounted to the destroy linked list.
		 */
		list_add_tail(list, &v_xchg_mgr->hot_pool->list_destroy_xchg);

		xchg = list_entry(list, struct unf_xchg_s, list_xchg_entry);
		spin_unlock_irqrestore(
			&v_xchg_mgr->hot_pool->xchg_hot_pool_lock,
			hot_pool_lock_flags);
		unf_delay_work_del_syn(xchg);

		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_REG_ATT, UNF_MAJOR,
			  "Free SFS Exchange(0x%p), State(0x%x), Reference count(%d), Start time(%llu).",
			  xchg, xchg->io_state, atomic_read(&xchg->ref_cnt),
			  xchg->alloc_jif);

		unf_cm_free_xchg(xchg->lport, xchg);

		spin_lock_irqsave(&v_xchg_mgr->hot_pool->xchg_hot_pool_lock,
				  hot_pool_lock_flags);
	}
	spin_unlock_irqrestore(&v_xchg_mgr->hot_pool->xchg_hot_pool_lock,
			       hot_pool_lock_flags);
}

static void unf_free_lport_destroy_xchg(struct unf_xchg_mgr_s *v_xchg_mgr)
{
#define UNF_WAIT_DESTROY_EMPTY_STEP_MS 1000
#define UNF_WAIT_IO_STATE_TGT_FRONT_MS (10 * 1000)

	struct unf_xchg_s *xchg = NULL;
	struct list_head *next_xchg_node = NULL;
	unsigned long hot_pool_lock_flags = 0;
	unsigned long xchg_flag = 0;

	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE, v_xchg_mgr, return);
	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE, v_xchg_mgr->hot_pool,
			return);

	/* In this case, the timer on the destroy linked list is deleted.
	 * You only need to check whether the timer is released
	 * at the end of the tgt.
	 */
	spin_lock_irqsave(&v_xchg_mgr->hot_pool->xchg_hot_pool_lock,
			  hot_pool_lock_flags);
	while (!list_empty(&v_xchg_mgr->hot_pool->list_destroy_xchg)) {
		next_xchg_node =
			(&v_xchg_mgr->hot_pool->list_destroy_xchg)->next;
		xchg = list_entry(next_xchg_node, struct unf_xchg_s,
				  list_xchg_entry);

		spin_lock_irqsave(&xchg->xchg_state_lock, xchg_flag);

		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_REG_ATT, UNF_MAJOR,
			  "Free Exchange(0x%p), Type(0x%x), State(0x%x), Reference count(%d), Start time(%llu)",
			  xchg, xchg->xchg_type, xchg->io_state,
			  atomic_read(&xchg->ref_cnt),
			  xchg->alloc_jif);

		spin_unlock_irqrestore(&xchg->xchg_state_lock, xchg_flag);
		spin_unlock_irqrestore(
			&v_xchg_mgr->hot_pool->xchg_hot_pool_lock,
			hot_pool_lock_flags);

		/* This interface can be invoked to ensure that
		 * the timer is successfully canceled
		 * or wait until the timer execution is complete
		 */
		unf_delay_work_del_syn(xchg);

		/*
		 * If the timer is canceled successfully, delete Xchg
		 * If the timer has burst, the Xchg may have been released,
		 * In this case, deleting the Xchg will be failed
		 */
		unf_cm_free_xchg(xchg->lport, xchg);

		spin_lock_irqsave(&v_xchg_mgr->hot_pool->xchg_hot_pool_lock,
				  hot_pool_lock_flags);
	};

	spin_unlock_irqrestore(&v_xchg_mgr->hot_pool->xchg_hot_pool_lock,
			       hot_pool_lock_flags);
}

static unsigned int unf_free_lport_xchg(struct unf_lport_s *v_lport,
					struct unf_xchg_mgr_s *v_xchg_mgr)
{
#define UNF_OS_WAITIO_TIMEOUT (10 * 1000)

	unsigned long free_pool_lock_flags = 0;
	int wait = UNF_FALSE;
	unsigned int total_xchg = 0;
	unsigned int total_xchg_sum = 0;
	unsigned int ret = RETURN_OK;
	unsigned long long timeout = 0;

	struct completion xchg_mgr_completion =
		COMPLETION_INITIALIZER(xchg_mgr_completion);

	UNF_CHECK_VALID(0x881, UNF_TRUE, v_lport, return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(0x882, UNF_TRUE, v_xchg_mgr, return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(0x883, UNF_TRUE, v_xchg_mgr->hot_pool,
			return UNF_RETURN_ERROR);
	UNF_REFERNCE_VAR(v_lport);

	unf_free_lport_sfs_xchg(v_xchg_mgr, UNF_FALSE);

	/* free INI Mode exchanges belong to L_Port */
	unf_free_lport_ini_xchg(v_xchg_mgr, UNF_FALSE);

	spin_lock_irqsave(&v_xchg_mgr->free_pool.xchg_free_pool_lock,
			  free_pool_lock_flags);
	total_xchg = v_xchg_mgr->free_pool.total_fcp_xchg +
		     v_xchg_mgr->free_pool.total_sfs_xchg;
	total_xchg_sum = v_xchg_mgr->free_pool.fcp_xchg_sum +
			 v_xchg_mgr->free_pool.sfs_xchg_sum;
	if (total_xchg != total_xchg_sum) {
		v_xchg_mgr->free_pool.xchg_mgr_completion =
			&xchg_mgr_completion;
		wait = UNF_TRUE;
	}
	spin_unlock_irqrestore(&v_xchg_mgr->free_pool.xchg_free_pool_lock,
			       free_pool_lock_flags);

	if (wait == UNF_TRUE) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_REG_ATT, UNF_MAJOR,
			  "[info]Port(0x%x) begin to wait for exchange manager completion(%ld) (0x%x:0x%x)",
			  v_lport->port_id, jiffies, total_xchg,
			  total_xchg_sum);

		unf_show_all_xchg(v_lport, v_xchg_mgr);

		timeout = wait_for_completion_timeout(
				v_xchg_mgr->free_pool.xchg_mgr_completion,
				msecs_to_jiffies(UNF_OS_WAITIO_TIMEOUT));
		if (timeout == 0)
			unf_free_lport_destroy_xchg(v_xchg_mgr);

		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_REG_ATT, UNF_MAJOR,
			  "[info]Port(0x%x) wait for exchange manager completion end",
			  v_lport->port_id);

		spin_lock_irqsave(&v_xchg_mgr->free_pool.xchg_free_pool_lock,
				  free_pool_lock_flags);
		v_xchg_mgr->free_pool.xchg_mgr_completion = NULL;
		spin_unlock_irqrestore(
			&v_xchg_mgr->free_pool.xchg_free_pool_lock,
			free_pool_lock_flags);
	}

	return ret;
}

void unf_free_lport_all_xchg(struct unf_lport_s *v_lport)
{
	struct unf_xchg_mgr_s *xchg_mgr;
	unsigned int i;

	UNF_CHECK_VALID(0x881, UNF_TRUE, v_lport, return);
	UNF_REFERNCE_VAR(v_lport);

	for (i = 0; i < UNF_EXCHG_MGR_NUM; i++) {
		xchg_mgr = unf_get_xchg_mgr_by_lport(v_lport, i);
		if (unlikely(!xchg_mgr)) {
			UNF_TRACE(UNF_EVTLOG_IO_ERR, UNF_LOG_IO_ATT, UNF_ERR,
				  "[err]Port(0x%x) hot pool is NULL",
				  v_lport->port_id);

			continue;
		}
		unf_free_lport_sfs_xchg(xchg_mgr, UNF_FALSE);

		/* free INI Mode exchanges belong to L_Port */
		unf_free_lport_ini_xchg(xchg_mgr, UNF_FALSE);

		unf_free_lport_destroy_xchg(xchg_mgr);
	}
}

void unf_free_lport_ini_xchg(struct unf_xchg_mgr_s *v_xchg_mgr,
			     int v_done_ini_flag)
{
	/*
	 * 1. L_Port destroy
	 * 2. AC power down
	 */
	struct list_head *list = NULL;
	struct unf_xchg_s *xchg = NULL;
	unsigned long hot_pool_lock_flags = 0;
	unsigned int up_status = 0;

	UNF_REFERNCE_VAR(v_done_ini_flag);
	UNF_CHECK_VALID(0x889, UNF_TRUE, v_xchg_mgr, return);
	UNF_CHECK_VALID(0x890, UNF_TRUE, v_xchg_mgr->hot_pool, return);

	spin_lock_irqsave(&v_xchg_mgr->hot_pool->xchg_hot_pool_lock,
			  hot_pool_lock_flags);
	while (!list_empty(&v_xchg_mgr->hot_pool->ini_busylist)) {
		/* for each INI busy_list (exchange) node */
		list = (&v_xchg_mgr->hot_pool->ini_busylist)->next;

		/* Put exchange node to destroy_list, prevent done repeatly */
		list_del_init(list);
		list_add_tail(list, &v_xchg_mgr->hot_pool->list_destroy_xchg);
		xchg = list_entry(list, struct unf_xchg_s, list_xchg_entry);
		if (atomic_read(&xchg->ref_cnt) <= 0)
			continue;
		spin_unlock_irqrestore(
			&v_xchg_mgr->hot_pool->xchg_hot_pool_lock,
			hot_pool_lock_flags);
		unf_delay_work_del_syn(xchg);

		/* In the case of INI done, the command should be set to fail
		 * to prevent data inconsistency caused by the return of OK
		 */
		up_status = unf_get_uplevel_cmnd_errcode(
				xchg->scsi_cmnd_info.err_code_table,
				xchg->scsi_cmnd_info.err_code_table_cout,
				UNF_IO_PORT_LOGOUT);

		if (xchg->io_state & INI_IO_STATE_UPABORT) {
			/*
			 * About L_Port destroy or AC power down:
			 * UP_ABORT ---to--->>> ABORT_Port_Removing
			 */
			up_status = UNF_IO_ABORT_PORT_REMOVING;
		}

		xchg->scsi_cmnd_info.result = up_status;
		up(&xchg->task_sema);

		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_REG_ATT, UNF_MAJOR,
			  "[info]Free INI exchange(0x%p) state(0x%x) reference count(%d) start time(%llu)",
			  xchg, xchg->io_state, atomic_read(&xchg->ref_cnt),
			  xchg->alloc_jif);

		unf_cm_free_xchg(xchg->lport, xchg);

		/* go to next INI busy_list (exchange) node */
		spin_lock_irqsave(&v_xchg_mgr->hot_pool->xchg_hot_pool_lock,
				  hot_pool_lock_flags);
	}
	spin_unlock_irqrestore(&v_xchg_mgr->hot_pool->xchg_hot_pool_lock,
			       hot_pool_lock_flags);
}

static void unf_free_all_big_sfs(struct unf_xchg_mgr_s *v_xchg_mgr)
{
	struct unf_xchg_mgr_s *xchg_mgr = v_xchg_mgr;
	struct unf_big_sfs_s *big_sfs = NULL;
	struct list_head *node = NULL;
	struct list_head *next_node = NULL;
	unsigned long flag = 0;
	unsigned int buff_index;

	UNF_CHECK_VALID(0x891, UNF_TRUE, xchg_mgr, return);

	/* Release the free resources in the busy state */
	spin_lock_irqsave(&xchg_mgr->st_big_sfs_pool.big_sfs_pool_lock, flag);
	list_for_each_safe(node, next_node,
			   &xchg_mgr->st_big_sfs_pool.list_busy_pool) {
		list_del(node);
		list_add_tail(node, &xchg_mgr->st_big_sfs_pool.list_free_pool);
	}

	list_for_each_safe(node, next_node,
			   &xchg_mgr->st_big_sfs_pool.list_free_pool) {
		list_del(node);
		big_sfs = list_entry(node, struct unf_big_sfs_s,
				     entry_big_sfs);
		if (big_sfs->vaddr)
			big_sfs->vaddr = NULL;
	}
	spin_unlock_irqrestore(&xchg_mgr->st_big_sfs_pool.big_sfs_pool_lock,
			       flag);

	if (xchg_mgr->big_sfs_buf_list.buflist) {
		for (buff_index = 0;
		     buff_index < xchg_mgr->big_sfs_buf_list.buf_num;
		     buff_index++) {
			if (xchg_mgr->big_sfs_buf_list.buflist[buff_index].vaddr) {
				kfree(xchg_mgr->big_sfs_buf_list.buflist[buff_index].vaddr);
				xchg_mgr->big_sfs_buf_list.buflist[buff_index].vaddr = NULL;
			}
		}

		kfree(xchg_mgr->big_sfs_buf_list.buflist);
		xchg_mgr->big_sfs_buf_list.buflist = NULL;
	}
}

static void unf_free_big_sfs_pool(struct unf_xchg_mgr_s *v_xchg_mgr)
{
	UNF_CHECK_VALID(0x892, UNF_TRUE, v_xchg_mgr, return);

	UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_REG_ATT, UNF_INFO,
		  "Free Big SFS Pool, Count(0x%x).",
		  v_xchg_mgr->st_big_sfs_pool.free_count);

	unf_free_all_big_sfs(v_xchg_mgr);
	v_xchg_mgr->st_big_sfs_pool.free_count = 0;

	if (v_xchg_mgr->st_big_sfs_pool.big_sfs_pool) {
		vfree(v_xchg_mgr->st_big_sfs_pool.big_sfs_pool);
		v_xchg_mgr->st_big_sfs_pool.big_sfs_pool = NULL;
	}
}

static void unf_free_xchg_mgr_mem(struct unf_lport_s *v_lport,
				  struct unf_xchg_mgr_s *v_xchg_mgr)
{
	struct unf_xchg_mgr_s *xchg_mgr = NULL;
	struct unf_xchg_s *xchg = NULL;
	unsigned int i = 0;
	unsigned int xchg_sum = 0;
	struct unf_xchg_free_pool_s *free_pool = NULL;

	UNF_CHECK_VALID(0x893, UNF_TRUE, v_xchg_mgr, return);

	xchg_mgr = v_xchg_mgr;

	/* Release the reserved Rsp IU Page */
	unf_free_all_rsp_pages(xchg_mgr);

	unf_free_big_sfs_pool(xchg_mgr);

	/* The sfs is released first, and the XchgMgr is allocated
	 * by the get free page.
	 * Therefore, the XchgMgr is compared with the '0'
	 */
	if (xchg_mgr->sfs_mm_start != 0) {
		dma_free_coherent(&v_lport->low_level_func.dev->dev,
				  xchg_mgr->sfs_mem_size,
				  xchg_mgr->sfs_mm_start,
				  xchg_mgr->sfs_phy_addr);
		xchg_mgr->sfs_mm_start = 0;
	}

	/* Release Xchg first */
	if (xchg_mgr->fcp_mm_start) {
		unf_get_xchg_config_sum(v_lport, &xchg_sum);
		xchg_sum = xchg_sum / UNF_EXCHG_MGR_NUM;

		xchg = xchg_mgr->fcp_mm_start;
		for (i = 0; i < xchg_sum; i++) {
			if (!xchg)
				break;
			xchg++;
		}

		vfree(xchg_mgr->fcp_mm_start);
		xchg_mgr->fcp_mm_start = NULL;
	}

	/* release the hot pool */
	if (xchg_mgr->hot_pool) {
		vfree(xchg_mgr->hot_pool);
		xchg_mgr->hot_pool = NULL;
	}

	free_pool = &xchg_mgr->free_pool;

	vfree(xchg_mgr);

	UNF_REFERNCE_VAR(xchg_mgr);
	UNF_REFERNCE_VAR(free_pool);
}

static void unf_free_xchg_mgr(struct unf_lport_s *v_lport,
			      struct unf_xchg_mgr_s *v_xchg_mgr)
{
	unsigned long flags = 0;
	unsigned int ret = UNF_RETURN_ERROR;

	UNF_CHECK_VALID(0x894, UNF_TRUE, v_lport, return);
	UNF_CHECK_VALID(0x895, UNF_TRUE, v_xchg_mgr, return);

	/* 1. At first, free exchanges for this Exch_Mgr */
	ret = unf_free_lport_xchg(v_lport, v_xchg_mgr);

	/* 2. Delete this Exch_Mgr entry */
	spin_lock_irqsave(&v_lport->xchg_mgr_lock, flags);
	list_del_init(&v_xchg_mgr->xchg_mgr_entry);
	spin_unlock_irqrestore(&v_lport->xchg_mgr_lock, flags);

	/* 3. free Exch_Mgr memory if necessary */
	if (ret == RETURN_OK) {
		/* free memory directly */
		unf_free_xchg_mgr_mem(v_lport, v_xchg_mgr);
	} else {
		/* Add it to Dirty list */
		spin_lock_irqsave(&v_lport->xchg_mgr_lock, flags);
		list_add_tail(&v_xchg_mgr->xchg_mgr_entry,
			      &v_lport->list_dirty_xchg_mgr_head);
		spin_unlock_irqrestore(&v_lport->xchg_mgr_lock, flags);

		/* Mark dirty flag */
		unf_cmmark_dirty_mem(v_lport,
				     UNF_LPORT_DIRTY_FLAG_XCHGMGR_DIRTY);
	}
}

void unf_free_all_xchg_mgr(struct unf_lport_s *v_lport)
{
	struct unf_xchg_mgr_s *xchg_mgr = NULL;
	unsigned long flags = 0;
	unsigned int i = 0;

	UNF_CHECK_VALID(0x896, UNF_TRUE, v_lport, return);

	/* for each L_Port->Exch_Mgr_List */
	spin_lock_irqsave(&v_lport->xchg_mgr_lock, flags);
	while (!list_empty(&v_lport->list_xchg_mgr_head)) {
		spin_unlock_irqrestore(&v_lport->xchg_mgr_lock, flags);

		xchg_mgr = unf_get_xchg_mgr_by_lport(v_lport, i);
		unf_free_xchg_mgr(v_lport, xchg_mgr);
		if (i < UNF_EXCHG_MGR_NUM)
			v_lport->p_xchg_mgr[i] = NULL;

		i++;
		/* go to next */
		spin_lock_irqsave(&v_lport->xchg_mgr_lock, flags);
	}
	spin_unlock_irqrestore(&v_lport->xchg_mgr_lock, flags);

	v_lport->destroy_step = UNF_LPORT_DESTROY_STEP_4_DESTROY_EXCH_MGR;
}

static unsigned int unf_init_xchg_mgr(struct unf_xchg_mgr_s *v_xchg_mgr)
{
	struct unf_xchg_mgr_s *xchg_mgr = NULL;

	UNF_CHECK_VALID(0x897, UNF_TRUE, v_xchg_mgr, return UNF_RETURN_ERROR);
	xchg_mgr = v_xchg_mgr;
	memset(xchg_mgr, 0, sizeof(struct unf_xchg_mgr_s));

	INIT_LIST_HEAD(&xchg_mgr->xchg_mgr_entry);
	xchg_mgr->mgr_type = UNF_XCHG_MGR_FC;
	xchg_mgr->min_xid = UNF_XCHG_MIN_XID;
	xchg_mgr->max_xid = UNF_XCHG_MAX_XID;
	xchg_mgr->fcp_mm_start = NULL;
	xchg_mgr->mem_size = sizeof(struct unf_xchg_mgr_s);
	return RETURN_OK;
}

static unsigned int unf_init_xchg_mgr_free_pool(
				struct unf_xchg_mgr_s *v_xchg_mgr)
{
	struct unf_xchg_free_pool_s *free_pool = NULL;
	struct unf_xchg_mgr_s *xchg_mgr = NULL;

	UNF_CHECK_VALID(0x898, UNF_TRUE, v_xchg_mgr, return UNF_RETURN_ERROR);
	xchg_mgr = v_xchg_mgr;

	free_pool = &xchg_mgr->free_pool;
	INIT_LIST_HEAD(&free_pool->list_free_xchg_list);
	INIT_LIST_HEAD(&free_pool->list_sfs_xchg_list);
	spin_lock_init(&free_pool->xchg_free_pool_lock);
	free_pool->fcp_xchg_sum = 0;
	free_pool->xchg_mgr_completion = NULL;

	return RETURN_OK;
}

static unsigned int unf_init_xchg_hot_pool(
			struct unf_lport_s *v_lport,
			struct unf_xchg_hot_pool_s *v_hot_pool,
			unsigned int v_xchg_sum)
{
	struct unf_xchg_hot_pool_s *hot_pool = NULL;

	UNF_CHECK_VALID(0x899, UNF_TRUE, v_hot_pool, return UNF_RETURN_ERROR);
	hot_pool = v_hot_pool;

	INIT_LIST_HEAD(&hot_pool->sfs_busylist);
	INIT_LIST_HEAD(&hot_pool->ini_busylist);
	spin_lock_init(&hot_pool->xchg_hot_pool_lock);
	INIT_LIST_HEAD(&hot_pool->list_destroy_xchg);
	hot_pool->total_xchges = 0;
	hot_pool->total_res_cnt = 0;
	hot_pool->wait_state = UNF_FALSE;
	hot_pool->lport = v_lport;

	/* Slab Pool Index */
	hot_pool->slab_next_index = 0;
	UNF_TOU16_CHECK(hot_pool->slab_total_sum, v_xchg_sum,
			return UNF_RETURN_ERROR);

	return RETURN_OK;
}

static unsigned int unf_alloc_and_init_big_sfs_pool(
				struct unf_lport_s *v_lport,
				struct unf_xchg_mgr_s *v_xchg_mgr)
{
	unsigned int i = 0;
	unsigned int size = 0;
	unsigned int align_size = 0;
	unsigned int npiv_cnt = 0;
	struct unf_big_sfs_pool_s *big_sfs_pool = NULL;
	struct unf_big_sfs_s *big_sfs_buf = NULL;
	unsigned int buf_total_size;
	unsigned int buf_num;
	unsigned int buf_cnt_perhugebuf;
	unsigned int alloc_idx;
	unsigned int curbuf_idx = 0;
	unsigned int curbuf_offset = 0;

	UNF_CHECK_VALID(0x900, UNF_TRUE, v_xchg_mgr, return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(0x901, UNF_TRUE, v_lport, return UNF_RETURN_ERROR);
	big_sfs_pool = &v_xchg_mgr->st_big_sfs_pool;

	INIT_LIST_HEAD(&big_sfs_pool->list_free_pool);
	INIT_LIST_HEAD(&big_sfs_pool->list_busy_pool);
	spin_lock_init(&big_sfs_pool->big_sfs_pool_lock);
	npiv_cnt = v_lport->low_level_func.support_max_npiv_num;

	/*
	 * The value*6 indicates GID_PT/GID_FT, RSCN, and ECHO
	 * Another command is received when a command is being responded
	 * A maximum of 20 resources are reserved for the RSCN.
	 * During the test, multiple rscn are found. As a result,
	 * the resources are insufficient and the disc fails.
	 */
	big_sfs_pool->free_count = (npiv_cnt + 1) * 6 + 20;
	big_sfs_buf = (struct unf_big_sfs_s *)vmalloc(
					big_sfs_pool->free_count
					* sizeof(struct unf_big_sfs_s));
	if (!big_sfs_buf) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_REG_ATT, UNF_ERR,
			  "Allocate Big SFS buf fail.");

		return UNF_RETURN_ERROR;
	}
	memset(big_sfs_buf, 0, big_sfs_pool->free_count *
	       sizeof(struct unf_big_sfs_s));
	v_xchg_mgr->mem_size +=
		(unsigned int)
		(big_sfs_pool->free_count * sizeof(struct unf_big_sfs_s));
	big_sfs_pool->big_sfs_pool = (void *)big_sfs_buf;

	/*
	 * Use the larger value of sizeof (struct unf_gif_acc_pld_s) and
	 * sizeof (struct unf_rscn_pld_s) to avoid the icp error.Therefore,
	 * the value is directly assigned instead of being compared.
	 */
	size = sizeof(struct unf_gif_acc_pld_s);
	align_size = ALIGN(size, PAGE_SIZE);

	buf_total_size = align_size * big_sfs_pool->free_count;

	v_xchg_mgr->big_sfs_buf_list.buf_size =
		buf_total_size > BUF_LIST_PAGE_SIZE ?
		BUF_LIST_PAGE_SIZE : buf_total_size;
	buf_cnt_perhugebuf =
		v_xchg_mgr->big_sfs_buf_list.buf_size / align_size;
	buf_num =
		big_sfs_pool->free_count % buf_cnt_perhugebuf ?
		big_sfs_pool->free_count / buf_cnt_perhugebuf + 1 :
		big_sfs_pool->free_count / buf_cnt_perhugebuf;

	v_xchg_mgr->big_sfs_buf_list.buflist =
		(struct buff_list_s *)kmalloc(
					buf_num * sizeof(struct buff_list_s),
					GFP_KERNEL);
	v_xchg_mgr->big_sfs_buf_list.buf_num = buf_num;

	if (!v_xchg_mgr->big_sfs_buf_list.buflist) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_REG_ATT, UNF_WARN,
			  "[err]Allocate BigSfs pool buf list failed out of memory");
		goto free_buff;
	}
	memset(v_xchg_mgr->big_sfs_buf_list.buflist, 0, buf_num *
	       sizeof(struct buff_list_s));
	for (alloc_idx = 0; alloc_idx < buf_num; alloc_idx++) {
		v_xchg_mgr->big_sfs_buf_list.buflist[alloc_idx].vaddr =
			kmalloc(v_xchg_mgr->big_sfs_buf_list.buf_size,
				GFP_ATOMIC);
		if (!v_xchg_mgr->big_sfs_buf_list.buflist[alloc_idx].vaddr)
			goto free_buff;

		memset(v_xchg_mgr->big_sfs_buf_list.buflist[alloc_idx].vaddr,
		       0, v_xchg_mgr->big_sfs_buf_list.buf_size);
	}

	for (i = 0; i < big_sfs_pool->free_count; i++) {
		if ((i != 0) && !(i % buf_cnt_perhugebuf))
			curbuf_idx++;

		curbuf_offset = align_size * (i % buf_cnt_perhugebuf);
		big_sfs_buf->vaddr =
		v_xchg_mgr->big_sfs_buf_list.buflist[curbuf_idx].vaddr +
		curbuf_offset;
		big_sfs_buf->size = size;
		v_xchg_mgr->mem_size += size;
		list_add_tail(&big_sfs_buf->entry_big_sfs,
			      &big_sfs_pool->list_free_pool);
		big_sfs_buf++;
	}

	UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_REG_ATT, UNF_MAJOR,
		  "[EVENT]Allocate BigSfs pool size:%d,uiAlignSize:%d,buf_num:%d,buf_size:%d",
		  size, align_size, v_xchg_mgr->big_sfs_buf_list.buf_num,
		  v_xchg_mgr->big_sfs_buf_list.buf_size);
	return RETURN_OK;
free_buff:
	unf_free_all_big_sfs(v_xchg_mgr);
	vfree(big_sfs_buf);
	big_sfs_pool->big_sfs_pool = NULL;
	return UNF_RETURN_ERROR;
}

/*
 * Function Name       : unf_free_one_big_sfs
 * Function Description: Put the big sfs memory in xchg back to bigsfspool
 * Input Parameters    : struct unf_xchg_s * v_xchg
 * Output Parameters   : N/A
 * Return Type         : static void
 */
static void unf_free_one_big_sfs(struct unf_xchg_s *v_xchg)
{
	unsigned long flag = 0;
	struct unf_xchg_mgr_s *xchg_mgr = NULL;

	UNF_CHECK_VALID(0x902, UNF_TRUE, v_xchg, return);
	xchg_mgr = v_xchg->xchg_mgr;
	UNF_CHECK_VALID(0x903, UNF_TRUE, xchg_mgr, return);
	if (!v_xchg->big_sfs_buf)
		return;

	if ((v_xchg->cmnd_code != NS_GID_PT) &&
	    (v_xchg->cmnd_code != NS_GID_FT) &&
	    (v_xchg->cmnd_code != ELS_ECHO) &&
	    (UNF_SET_ELS_ACC_TYPE(ELS_ECHO) != v_xchg->cmnd_code) &&
	    (v_xchg->cmnd_code != ELS_RSCN) &&
	    (UNF_SET_ELS_ACC_TYPE(ELS_RSCN) != v_xchg->cmnd_code)) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT,
			  UNF_MAJOR,
			  "Exchange(0x%p), Command(0x%x) big SFS buf is not NULL.",
			  v_xchg, v_xchg->cmnd_code);
	}

	spin_lock_irqsave(&xchg_mgr->st_big_sfs_pool.big_sfs_pool_lock, flag);
	list_del(&v_xchg->big_sfs_buf->entry_big_sfs);
	list_add_tail(&v_xchg->big_sfs_buf->entry_big_sfs,
		      &xchg_mgr->st_big_sfs_pool.list_free_pool);
	xchg_mgr->st_big_sfs_pool.free_count++;
	UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT, UNF_INFO,
		  "Free one big SFS buf(0x%p), Count(0x%x), Exchange(0x%p), Command(0x%x).",
		  v_xchg->big_sfs_buf->vaddr,
		  xchg_mgr->st_big_sfs_pool.free_count,
		  v_xchg, v_xchg->cmnd_code);
	spin_unlock_irqrestore(&xchg_mgr->st_big_sfs_pool.big_sfs_pool_lock,
			       flag);
}

static void unf_free_exchg_mgr_info(struct unf_lport_s *v_lport)
{
	unsigned int i;
	struct list_head *node = NULL;
	struct list_head *next_node = NULL;
	unsigned long flags = 0;
	struct unf_xchg_mgr_s *xchg_mgr = NULL;

	spin_lock_irqsave(&v_lport->xchg_mgr_lock, flags);
	list_for_each_safe(node, next_node, &v_lport->list_xchg_mgr_head) {
		list_del(node);
		xchg_mgr = list_entry(node, struct unf_xchg_mgr_s,
				      xchg_mgr_entry);
	}
	spin_unlock_irqrestore(&v_lport->xchg_mgr_lock, flags);

	for (i = 0; i < UNF_EXCHG_MGR_NUM; i++) {
		xchg_mgr = v_lport->p_xchg_mgr[i];

		if (xchg_mgr) {
			unf_free_big_sfs_pool(xchg_mgr);
			unf_free_all_rsp_pages(xchg_mgr);

			if (xchg_mgr->sfs_mm_start) {
				dma_free_coherent(
					&v_lport->low_level_func.dev->dev,
					xchg_mgr->sfs_mem_size,
					xchg_mgr->sfs_mm_start,
					xchg_mgr->sfs_phy_addr);
				xchg_mgr->sfs_mm_start = 0;
			}

			if (xchg_mgr->fcp_mm_start) {
				vfree(xchg_mgr->fcp_mm_start);
				xchg_mgr->fcp_mm_start = NULL;
			}

			if (xchg_mgr->hot_pool) {
				vfree(xchg_mgr->hot_pool);
				xchg_mgr->hot_pool = NULL;
			}

			vfree(xchg_mgr);
			v_lport->p_xchg_mgr[i] = NULL;
		}
	}
}

static unsigned int unf_alloc_and_init_xchg_mgr(struct unf_lport_s *v_lport)
{
	struct unf_xchg_mgr_s *xchg_mgr = NULL;
	struct unf_xchg_hot_pool_s *hot_pool = NULL;
	struct unf_xchg_s *xchg_mem = NULL;
	void *sfs_mm_start = 0;
	dma_addr_t sfs_phy_addr = 0;
	unsigned int xchg_sum = 0;
	unsigned int sfs_xchg_sum = 0;
	unsigned long flags = 0;
	unsigned int order = 0;
	unsigned int ret = UNF_RETURN_ERROR;
	unsigned int slab_num = 0;
	unsigned int i = 0;

	UNF_REFERNCE_VAR(order);
	/* SFS_EXCH + I/O_EXCH */
	ret = unf_get_xchg_config_sum(v_lport, &xchg_sum);
	if (ret != RETURN_OK) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_REG_ATT, UNF_MAJOR,
			  "Port(0x%x) can't get Exchange.",
			  v_lport->port_id);

		return UNF_RETURN_ERROR;
	}

	/* SFS Exchange Sum */
	sfs_xchg_sum = v_lport->low_level_func.lport_cfg_items.max_sfs_xchg /
		       UNF_EXCHG_MGR_NUM;

	xchg_sum = xchg_sum / UNF_EXCHG_MGR_NUM;
	slab_num = v_lport->low_level_func.support_max_xid_range /
		   UNF_EXCHG_MGR_NUM;
	for (i = 0; i < UNF_EXCHG_MGR_NUM; i++) {
		/* Alloc Exchange Manager */
		xchg_mgr = (struct unf_xchg_mgr_s *)
			   vmalloc(sizeof(struct unf_xchg_mgr_s));
		if (!xchg_mgr) {
			UNF_TRACE(UNF_EVTLOG_DRIVER_ERR,
				  UNF_LOG_REG_ATT, UNF_ERR,
				  "Port(0x%x) allocate Exchange Manager Memory Fail.",
				  v_lport->port_id);

			goto exit;
		}

		/* Init Exchange Manager */
		ret = unf_init_xchg_mgr(xchg_mgr);
		if (ret != RETURN_OK) {
			UNF_TRACE(UNF_EVTLOG_DRIVER_INFO,
				  UNF_LOG_REG_ATT, UNF_MAJOR,
				  "Port(0x%x) initialization Exchange Manager  unsuccessful.",
				  v_lport->port_id);

			goto free_xchg_mgr;
		}

		/* Initialize the Exchange Free Pool resource */
		ret = unf_init_xchg_mgr_free_pool(xchg_mgr);
		if (ret != RETURN_OK) {
			UNF_TRACE(UNF_EVTLOG_DRIVER_INFO,
				  UNF_LOG_REG_ATT, UNF_MAJOR,
				  "Port(0x%x) initialization Exchange Manager Free Pool  unsuccessful.",
				  v_lport->port_id);

			goto free_xchg_mgr;
		}

		/* Allocate memory for Hot Pool and Xchg slab */
		hot_pool = vmalloc(sizeof(struct unf_xchg_hot_pool_s) +
				   sizeof(struct unf_xchg_s *) * slab_num);
		if (!hot_pool) {
			UNF_TRACE(UNF_EVTLOG_DRIVER_ERR,
				  UNF_LOG_REG_ATT, UNF_ERR,
				  "Port(0x%x) allocate Hot Pool Memory Fail.",
				  v_lport->port_id);
			goto free_xchg_mgr;
		}

		memset(hot_pool, 0,
		       sizeof(struct unf_xchg_hot_pool_s) +
		       sizeof(struct unf_xchg_s *) * slab_num);
		xchg_mgr->mem_size +=
			(unsigned int)(sizeof(struct unf_xchg_hot_pool_s) +
			sizeof(struct unf_xchg_s *) * slab_num);

		/* Initialize the Exchange Hot Pool resource */
		ret = unf_init_xchg_hot_pool(v_lport, hot_pool, slab_num);
		if (ret != RETURN_OK)
			goto free_hot_pool;

		hot_pool->base += (unsigned short)(i * slab_num);
		/* Allocate the memory of all Xchg (IO/SFS) */
		xchg_mem = vmalloc(sizeof(struct unf_xchg_s) * xchg_sum);
		if (!xchg_mem) {
			UNF_TRACE(UNF_EVTLOG_DRIVER_ERR,
				  UNF_LOG_REG_ATT, UNF_ERR,
				  "Port(0x%x) allocate Exchange Memory Fail.",
				  v_lport->port_id);
			goto free_hot_pool;
		}
		memset(xchg_mem, 0, sizeof(struct unf_xchg_s) * xchg_sum);
		xchg_mgr->mem_size +=
			(unsigned int)(sizeof(struct unf_xchg_s) * xchg_sum);

		xchg_mgr->hot_pool = hot_pool;
		xchg_mgr->fcp_mm_start = xchg_mem;

		/* Allocate the memory used by the SFS Xchg
		 * to carry the ELS/BLS/GS command and response
		 */
		xchg_mgr->sfs_mem_size =
			(unsigned int)(sizeof(union unf_sfs_u) * sfs_xchg_sum);

		/* Apply for the DMA space for sending sfs frames.
		 * If the value of DMA32 is less than 4 GB,
		 * cross-4G problems will not occur
		 */
		order = (unsigned int)get_order(xchg_mgr->sfs_mem_size);

		sfs_mm_start = dma_alloc_coherent(
					&v_lport->low_level_func.dev->dev,
					xchg_mgr->sfs_mem_size,
					&sfs_phy_addr, GFP_KERNEL);
		if (!sfs_mm_start) {
			UNF_TRACE(UNF_EVTLOG_DRIVER_ERR,
				  UNF_LOG_REG_ATT, UNF_ERR,
				  "Port(0x%x) Get Free Pagers Fail, Order(%u).",
				  v_lport->port_id, order);
			goto free_xchg_mem;
		}
		memset(sfs_mm_start, 0, sizeof(union unf_sfs_u) * sfs_xchg_sum);
		xchg_mgr->mem_size += xchg_mgr->sfs_mem_size;
		xchg_mgr->sfs_mm_start = sfs_mm_start;
		xchg_mgr->sfs_phy_addr = sfs_phy_addr;

		/* The Xchg is initialized and mounted to the Free Pool */
		ret = unf_init_xchg(v_lport, xchg_mgr, xchg_sum, sfs_xchg_sum);
		if (ret != RETURN_OK) {
			UNF_TRACE(UNF_EVTLOG_DRIVER_INFO,
				  UNF_LOG_REG_ATT, UNF_MAJOR,
				  "Port(0x%x) initialization Exchange unsuccessful, Exchange Number(%u), SFS Exchange number(%u).",
				  v_lport->port_id, xchg_sum, sfs_xchg_sum);
			dma_free_coherent(&v_lport->low_level_func.dev->dev,
					  xchg_mgr->sfs_mem_size,
					  xchg_mgr->sfs_mm_start,
					  xchg_mgr->sfs_phy_addr);
			xchg_mgr->sfs_mm_start = 0;
			goto free_xchg_mem;
		}

		/* Apply for the memory used by GID_PT, GID_FT, and RSCN */
		ret = unf_alloc_and_init_big_sfs_pool(v_lport, xchg_mgr);
		if (ret != RETURN_OK) {
			UNF_TRACE(UNF_EVTLOG_DRIVER_ERR,
				  UNF_LOG_REG_ATT, UNF_ERR,
				  "Port(0x%x) allocate big SFS fail",
				  v_lport->port_id);

			unf_free_all_rsp_pages(xchg_mgr);
			dma_free_coherent(&v_lport->low_level_func.dev->dev,
					  xchg_mgr->sfs_mem_size,
					  xchg_mgr->sfs_mm_start,
					  xchg_mgr->sfs_phy_addr);
			xchg_mgr->sfs_mm_start = 0;
			goto free_xchg_mem;
		}

		spin_lock_irqsave(&v_lport->xchg_mgr_lock, flags);
		v_lport->p_xchg_mgr[i] = (void *)xchg_mgr;
		list_add_tail(&xchg_mgr->xchg_mgr_entry,
			      &v_lport->list_xchg_mgr_head);
		spin_unlock_irqrestore(&v_lport->xchg_mgr_lock, flags);

		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_REG_ATT, UNF_MAJOR,
			  "[info]Port(0x%x) ExchangeMgr:(0x%p),Base:(0x%x).",
			  v_lport->port_id, v_lport->p_xchg_mgr[i],
			  hot_pool->base);
	}

	UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_REG_ATT, UNF_INFO,
		  "Port(0x%x) allocate Exchange Manager size(0x%x).",
		  v_lport->port_id, xchg_mgr->mem_size);

	return RETURN_OK;

free_xchg_mem:
	vfree(xchg_mem);
free_hot_pool:
	vfree(hot_pool);
free_xchg_mgr:
	vfree(xchg_mgr);
exit:
	unf_free_exchg_mgr_info(v_lport);
	return UNF_RETURN_ERROR;
}

void unf_xchg_mgr_destroy(struct unf_lport_s *v_lport)
{
	UNF_CHECK_VALID(0x905, UNF_TRUE, v_lport, return);

	unf_free_all_xchg_mgr(v_lport);
}

unsigned int unf_alloc_xchg_resource(struct unf_lport_s *v_lport)
{
	UNF_CHECK_VALID(0x906, UNF_TRUE, v_lport, return UNF_RETURN_ERROR);

	INIT_LIST_HEAD(&v_lport->list_dirty_xchg_mgr_head);
	INIT_LIST_HEAD(&v_lport->list_xchg_mgr_head);
	spin_lock_init(&v_lport->xchg_mgr_lock);

	/* LPort Xchg Management Unit Allocation */
	if (unf_alloc_and_init_xchg_mgr(v_lport) != RETURN_OK)
		return UNF_RETURN_ERROR;

	return RETURN_OK;
}

void unf_destroy_dirty_xchg(struct unf_lport_s *v_lport, int v_show_only)
{
	unsigned int dirty_xchg = 0;
	struct unf_xchg_mgr_s *exch_mgr = NULL;
	unsigned long flags = 0;
	struct list_head *node = NULL;
	struct list_head *next_node = NULL;

	UNF_CHECK_VALID(0x908, UNF_TRUE, v_lport, return);

	if (v_lport->dirty_flag & UNF_LPORT_DIRTY_FLAG_XCHGMGR_DIRTY) {
		spin_lock_irqsave(&v_lport->xchg_mgr_lock, flags);
		list_for_each_safe(node, next_node,
				   &v_lport->list_dirty_xchg_mgr_head) {
			exch_mgr = list_entry(node, struct unf_xchg_mgr_s,
					      xchg_mgr_entry);
			spin_unlock_irqrestore(&v_lport->xchg_mgr_lock, flags);
			if (exch_mgr) {
				dirty_xchg =
					(exch_mgr->free_pool.total_fcp_xchg +
					exch_mgr->free_pool.total_sfs_xchg);

				UNF_TRACE(UNF_EVTLOG_DRIVER_INFO,
					  UNF_LOG_REG_ATT, UNF_MAJOR,
					  "[info]Port(0x%x) has %u dirty exchange(s)",
					  v_lport->port_id, dirty_xchg);

				unf_show_all_xchg(v_lport, exch_mgr);

				if (v_show_only == UNF_FALSE) {
					/* Delete Dirty Exchange Mgr entry */
					spin_lock_irqsave(
						&v_lport->xchg_mgr_lock,
						flags);
					list_del_init(
						&exch_mgr->xchg_mgr_entry);
					spin_unlock_irqrestore(
						&v_lport->xchg_mgr_lock,
						flags);

					/* Free Dirty Exchange Mgr memory */
					unf_free_xchg_mgr_mem(v_lport,
							      exch_mgr);
				}
			}
			spin_lock_irqsave(&v_lport->xchg_mgr_lock, flags);
		}
		spin_unlock_irqrestore(&v_lport->xchg_mgr_lock, flags);
	}

	UNF_REFERNCE_VAR(dirty_xchg);
}

struct unf_xchg_mgr_s *unf_get_xchg_mgr_by_lport(struct unf_lport_s *v_lport,
						 unsigned int v_idx)
{
	struct unf_xchg_mgr_s *xchg_mgr = NULL;
	unsigned long flags = 0;

	UNF_CHECK_VALID(0x909, UNF_TRUE, v_lport, return NULL);
	UNF_CHECK_VALID(0x910, UNF_TRUE, v_idx < UNF_EXCHG_MGR_NUM,
			return NULL);

	spin_lock_irqsave(&v_lport->xchg_mgr_lock, flags);
	xchg_mgr = v_lport->p_xchg_mgr[v_idx];
	spin_unlock_irqrestore(&v_lport->xchg_mgr_lock, flags);

	return xchg_mgr;
}

struct unf_xchg_hot_pool_s *unf_get_hot_pool_by_lport(
				struct unf_lport_s *v_lport,
				unsigned int v_mgr_idx)
{
	struct unf_xchg_mgr_s *xchg_mgr = NULL;
	struct unf_lport_s *lport = NULL;

	UNF_CHECK_VALID(0x910, UNF_TRUE, (v_lport), return NULL);

	lport = (struct unf_lport_s *)(v_lport->root_lport);

	UNF_CHECK_VALID(0x910, UNF_TRUE, (lport), return NULL);

	/* Get Xchg Manager */
	xchg_mgr = unf_get_xchg_mgr_by_lport(lport, v_mgr_idx);
	if (!xchg_mgr) {
		UNF_TRACE(UNF_EVTLOG_IO_INFO, UNF_LOG_IO_ATT, UNF_MAJOR,
			  "Port(0x%x) Exchange Manager is NULL.",
			  lport->port_id);

		return NULL;
	}

	/* Get Xchg Manager Hot Pool */
	return xchg_mgr->hot_pool;
}

static inline void unf_hot_pool_slab_set(
				struct unf_xchg_hot_pool_s *v_hot_pool,
				unsigned short v_slab_index,
				struct unf_xchg_s *v_xchg)
{
	UNF_CHECK_VALID(0x911, UNF_TRUE, v_hot_pool, return);

	v_hot_pool->xchg_slab[v_slab_index] = v_xchg;
}

static inline struct unf_xchg_s *unf_get_xchg_by_xchg_tag(
					struct unf_xchg_hot_pool_s *v_hot_pool,
					unsigned short v_slab_index)
{
	UNF_CHECK_VALID(0x912, UNF_TRUE, v_hot_pool, return NULL);

	return v_hot_pool->xchg_slab[v_slab_index];
}

static void *unf_lookup_xchg_by_tag(void *v_lport,
				    unsigned short v_hot_pool_tag)
{
	struct unf_lport_s *lport = NULL;
	struct unf_xchg_hot_pool_s *hot_pool = NULL;
	struct unf_xchg_s *xchg = NULL;
	unsigned long flags = 0;
	unsigned int exchg_mgr_idx = 0;
	struct unf_xchg_mgr_s *xchg_mgr = NULL;

	UNF_CHECK_VALID(0x913, UNF_TRUE, v_lport, return NULL);

	/* In the case of NPIV, v_pstLport is the Vport pointer,
	 * the share uses the ExchMgr of RootLport
	 */
	lport = ((struct unf_lport_s *)v_lport)->root_lport;
	UNF_CHECK_VALID(0x914, UNF_TRUE, lport, return NULL);

	exchg_mgr_idx = (v_hot_pool_tag * UNF_EXCHG_MGR_NUM) /
			lport->low_level_func.support_max_xid_range;
	if (unlikely(exchg_mgr_idx >= UNF_EXCHG_MGR_NUM)) {
		UNF_TRACE(UNF_EVTLOG_IO_ERR, UNF_LOG_IO_ATT, UNF_ERR,
			  "[err]Port(0x%x) Get ExchgMgr %u err",
			  lport->port_id, exchg_mgr_idx);

		return NULL;
	}

	xchg_mgr = lport->p_xchg_mgr[exchg_mgr_idx];

	if (unlikely(!xchg_mgr)) {
		UNF_TRACE(UNF_EVTLOG_IO_ERR, UNF_LOG_IO_ATT, UNF_ERR,
			  "[err]Port(0x%x) ExchgMgr %u is null",
			  lport->port_id, exchg_mgr_idx);

		return NULL;
	}

	hot_pool = xchg_mgr->hot_pool;

	if (unlikely(!hot_pool)) {
		UNF_TRACE(UNF_EVTLOG_IO_INFO, UNF_LOG_IO_ATT, UNF_MAJOR,
			  "Port(0x%x) Hot Pool is NULL.", lport->port_id);

		return NULL;
	}

	if (unlikely(v_hot_pool_tag >=
	    (hot_pool->slab_total_sum + hot_pool->base))) {
		UNF_TRACE(UNF_EVTLOG_IO_ERR, UNF_LOG_IO_ATT, UNF_ERR,
			  "[err]LPort(0x%x) can't Input Tag(0x%x), Max(0x%x).",
			  lport->port_id, v_hot_pool_tag,
			  (hot_pool->slab_total_sum + hot_pool->base));

		return NULL;
	}

	spin_lock_irqsave(&hot_pool->xchg_hot_pool_lock, flags);
	xchg = unf_get_xchg_by_xchg_tag(hot_pool,
					v_hot_pool_tag - hot_pool->base);
	spin_unlock_irqrestore(&hot_pool->xchg_hot_pool_lock, flags);

	return (void *)xchg;
}

static void *unf_find_xchg_by_oxid(void *v_lport, unsigned short v_oxid,
				   unsigned int v_oid)
{
	struct unf_xchg_hot_pool_s *hot_pool = NULL;
	struct unf_xchg_s *xchg = NULL;
	struct list_head *node = NULL;
	struct list_head *next_node = NULL;
	struct unf_lport_s *lport = NULL;
	unsigned long flags = 0;
	unsigned long xchg_flags = 0;
	unsigned int i = 0;

	UNF_CHECK_VALID(0x915, UNF_TRUE, (v_lport), return NULL);

	/* In the case of NPIV, the v_lport is the Vport pointer,
	 *  and the share uses the ExchMgr of the RootLport
	 */
	lport = ((struct unf_lport_s *)v_lport)->root_lport;
	UNF_CHECK_VALID(0x916, UNF_TRUE, (lport), return NULL);

	for (i = 0; i < UNF_EXCHG_MGR_NUM; i++) {
		hot_pool = unf_get_hot_pool_by_lport(lport, i);
		if (unlikely(!hot_pool)) {
			UNF_TRACE(UNF_EVTLOG_IO_INFO,
				  UNF_LOG_IO_ATT, UNF_MAJOR,
				  "Port(0x%x) MgrIdex %u Hot Pool is NULL.",
				  lport->port_id, i);
			continue;
		}

		spin_lock_irqsave(&hot_pool->xchg_hot_pool_lock, flags);

		/* 1. Traverse sfs_busy list */
		list_for_each_safe(node, next_node, &hot_pool->sfs_busylist) {
			xchg = list_entry(node, struct unf_xchg_s,
					  list_xchg_entry);
			spin_lock_irqsave(&xchg->xchg_state_lock, xchg_flags);
			if (UNF_CHECK_OXID_MATCHED(v_oxid, v_oid, xchg)) {
				atomic_inc(&xchg->ref_cnt);
				spin_unlock_irqrestore(&xchg->xchg_state_lock,
						       xchg_flags);
				spin_unlock_irqrestore(
					&hot_pool->xchg_hot_pool_lock, flags);
				return xchg;
			}
			spin_unlock_irqrestore(&xchg->xchg_state_lock,
					       xchg_flags);
		}

		/* 2. Traverse INI_Busy List */
		list_for_each_safe(node, next_node, &hot_pool->ini_busylist) {
			xchg = list_entry(node, struct unf_xchg_s,
					  list_xchg_entry);
			spin_lock_irqsave(&xchg->xchg_state_lock, xchg_flags);
			if (UNF_CHECK_OXID_MATCHED(v_oxid, v_oid, xchg)) {
				atomic_inc(&xchg->ref_cnt);
				spin_unlock_irqrestore(&xchg->xchg_state_lock,
						       xchg_flags);
				spin_unlock_irqrestore(
					&hot_pool->xchg_hot_pool_lock, flags);
				return xchg;
			}
			spin_unlock_irqrestore(&xchg->xchg_state_lock,
					       xchg_flags);
		}
		spin_unlock_irqrestore(&hot_pool->xchg_hot_pool_lock, flags);
	}

	return NULL;
}

static inline int unf_check_xchg_matched(struct unf_xchg_s *xchg,
					 unsigned long long v_command_sn,
					 unsigned int v_world_id)
{
	int matched = 0;

	matched = (v_command_sn == xchg->cmnd_sn);
	if (matched && (atomic_read(&xchg->ref_cnt) > 0))
		return UNF_TRUE;
	else
		return UNF_FALSE;
}

static void *unf_lookup_xchg_by_cmnd_sn(void *v_lport,
					unsigned long long v_command_sn,
					unsigned int v_world_id)
{
	struct unf_lport_s *lport = NULL;
	struct unf_xchg_hot_pool_s *hot_pool = NULL;
	struct list_head *node = NULL;
	struct list_head *next_node = NULL;
	struct unf_xchg_s *xchg = NULL;
	unsigned long flags = 0;
	unsigned int i;

	UNF_CHECK_VALID(0x919, UNF_TRUE, v_lport, return NULL);

	/* In NPIV, v_lport is a Vport pointer, and idle resources are
	 * shared by ExchMgr of RootLport.
	 * However, busy resources are mounted on each vport.
	 * Therefore, vport needs to be used.
	 */
	lport = (struct unf_lport_s *)v_lport;
	UNF_CHECK_VALID(0x920, UNF_TRUE, lport, return NULL);

	for (i = 0; i < UNF_EXCHG_MGR_NUM; i++) {
		hot_pool = unf_get_hot_pool_by_lport(lport, i);
		if (unlikely(!hot_pool)) {
			UNF_TRACE(UNF_EVTLOG_IO_ERR, UNF_LOG_IO_ATT, UNF_ERR,
				  "[err]Port(0x%x) hot pool is NULL",
				  lport->port_id);

			continue;
		}

		/* from busy_list */
		spin_lock_irqsave(&hot_pool->xchg_hot_pool_lock, flags);
		list_for_each_safe(node, next_node, &hot_pool->ini_busylist) {
			xchg = list_entry(node, struct unf_xchg_s,
					  list_xchg_entry);
			if (unf_check_xchg_matched(xchg, v_command_sn,
						   v_world_id)) {
				spin_unlock_irqrestore(
					&hot_pool->xchg_hot_pool_lock, flags);

				return xchg;
			}
		}

		/* vport: from destroy_list */
		if (lport != lport->root_lport) {
			list_for_each_safe(node, next_node,
					   &hot_pool->list_destroy_xchg) {
				xchg = list_entry(node, struct unf_xchg_s,
						  list_xchg_entry);
				if (unf_check_xchg_matched(xchg, v_command_sn,
							   v_world_id)) {
					spin_unlock_irqrestore(
						&hot_pool->xchg_hot_pool_lock,
						flags);

					UNF_TRACE(UNF_EVTLOG_IO_INFO,
						  UNF_LOG_IO_ATT, UNF_MAJOR,
						  "[info]Port(0x%x) lookup exchange from destroy list",
						  lport->port_id);

					return xchg;
				}
			}
		}

		spin_unlock_irqrestore(&hot_pool->xchg_hot_pool_lock, flags);
	}

	return NULL;
}

static inline unsigned int unf_alloc_hot_pool_slab(
				struct unf_xchg_hot_pool_s *v_hot_pool,
				struct unf_xchg_s *v_xchg,
				unsigned short v_rx_id)
{
	unsigned short slab_index = 0;

	UNF_CHECK_VALID(0x921, UNF_TRUE, v_hot_pool, return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(0x922, UNF_TRUE, v_xchg, return UNF_RETURN_ERROR);

	/* Check whether the hotpool tag is in the specified range sirt.
	 * If yes, set up the management relationship. If no,
	 * handle the problem according to the normal IO.
	 * If the sirt digitmap is used but the tag is occupied,
	 * it indicates that the I/O is discarded.
	 */

	v_hot_pool->slab_next_index =
		(unsigned short)v_hot_pool->slab_next_index;

	slab_index = v_hot_pool->slab_next_index;
	while (unf_get_xchg_by_xchg_tag(v_hot_pool, slab_index)) {
		slab_index++;
		slab_index = slab_index % v_hot_pool->slab_total_sum;

		/* Rewind occurs */
		if (slab_index == v_hot_pool->slab_next_index) {
			UNF_TRACE(UNF_EVTLOG_DRIVER_INFO,
				  UNF_LOG_EQUIP_ATT, UNF_MAJOR,
				  "There is No Slab At Hot Pool(0x%p) for xchg(0x%p).",
				  v_hot_pool, v_xchg);

			return UNF_RETURN_ERROR;
		}
	}

	unf_hot_pool_slab_set(v_hot_pool, slab_index, v_xchg);
	v_xchg->hot_pool_tag = slab_index + v_hot_pool->base;
	slab_index++;
	v_hot_pool->slab_next_index =
			slab_index % v_hot_pool->slab_total_sum;
	return RETURN_OK;
}

struct unf_esgl_page_s *unf_get_one_free_esgl_page(struct unf_lport_s *v_lport,
						   struct unf_xchg_s *v_xchg)
{
	struct unf_lport_s *lport = NULL;
	struct unf_esgl_s *esgl = NULL;
	struct unf_xchg_s *xchg = NULL;
	struct list_head *list_head = NULL;
	unsigned long flag = 0;

	UNF_CHECK_VALID(0x923, UNF_TRUE, v_lport, return NULL);
	UNF_CHECK_VALID(0x924, UNF_TRUE, v_xchg, return NULL);

	lport = v_lport;
	xchg = v_xchg;

	/* Obtain a new Esgl from the EsglPool and
	 * add it to the list_esgls of the Xchg
	 */
	spin_lock_irqsave(&lport->esgl_pool.esgl_pool_lock, flag);
	if (!list_empty(&lport->esgl_pool.list_esgl_pool)) {
		list_head = (&lport->esgl_pool.list_esgl_pool)->next;
		list_del(list_head);
		lport->esgl_pool.esgl_pool_count--;
		list_add_tail(list_head, &xchg->list_esgls);

		esgl = list_entry(list_head, struct unf_esgl_s, entry_esgl);
		atomic_inc(&xchg->esgl_cnt);
		spin_unlock_irqrestore(&lport->esgl_pool.esgl_pool_lock, flag);
	} else {
		UNF_TRACE(UNF_EVTLOG_IO_WARN, UNF_LOG_IO_ATT, UNF_WARN,
			  "[warn]Port(0x%x) esgl pool is empty",
			  lport->nport_id);

		spin_unlock_irqrestore(&lport->esgl_pool.esgl_pool_lock, flag);
		return NULL;
	}

	return &esgl->page;
}

void unf_release_esgls(struct unf_xchg_s *v_xchg)
{
	struct unf_lport_s *lport = NULL;
	struct list_head *list = NULL;
	struct list_head *list_tmp = NULL;
	unsigned long flag = 0;

	UNF_CHECK_VALID(0x925, UNF_TRUE, v_xchg, return);
	UNF_CHECK_VALID(0x926, UNF_TRUE, v_xchg->lport, return);

	if (atomic_read(&v_xchg->esgl_cnt) <= 0)
		return;

	/* In the case of NPIV, the Vport pointer is saved in v_pstExch,
	 * and the EsglPool of RootLport is shared.
	 */
	lport = (v_xchg->lport)->root_lport;
	UNF_CHECK_VALID(0x927, UNF_TRUE, (lport), return);

	spin_lock_irqsave(&lport->esgl_pool.esgl_pool_lock, flag);
	if (!list_empty(&v_xchg->list_esgls)) {
		list_for_each_safe(list, list_tmp, &v_xchg->list_esgls) {
			list_del(list);
			list_add_tail(list, &lport->esgl_pool.list_esgl_pool);
			lport->esgl_pool.esgl_pool_count++;
			atomic_dec(&v_xchg->esgl_cnt);
		}
	}
	spin_unlock_irqrestore(&lport->esgl_pool.esgl_pool_lock, flag);
}

static void unf_init_xchg_attribute(struct unf_xchg_s *v_xchg)
{
	unsigned long flags = 0;

	UNF_CHECK_VALID(0x973, UNF_TRUE, (v_xchg), return);

	spin_lock_irqsave(&v_xchg->xchg_state_lock, flags);
	v_xchg->xchg_mgr = NULL;
	v_xchg->free_pool = NULL;
	v_xchg->hot_pool = NULL;
	v_xchg->lport = NULL;
	v_xchg->rport = NULL;
	v_xchg->disc_rport = NULL;
	v_xchg->io_state = UNF_IO_STATE_NEW;
	v_xchg->io_send_stage = TGT_IO_SEND_STAGE_NONE;
	v_xchg->io_send_result = TGT_IO_SEND_RESULT_INVALID;
	v_xchg->io_send_abort = UNF_FALSE;
	v_xchg->io_abort_result = UNF_FALSE;
	v_xchg->abts_state = 0;
	v_xchg->ox_id = INVALID_VALUE16;
	v_xchg->abort_oxid = INVALID_VALUE16;
	v_xchg->rx_id = INVALID_VALUE16;
	v_xchg->sid = INVALID_VALUE32;
	v_xchg->did = INVALID_VALUE32;
	v_xchg->oid = INVALID_VALUE32;
	v_xchg->disc_port_id = INVALID_VALUE32;
	v_xchg->seq_id = INVALID_VALUE8;
	v_xchg->cmnd_code = INVALID_VALUE32;
	v_xchg->cmnd_sn = INVALID_VALUE64;
	v_xchg->data_len = 0;
	v_xchg->resid_len = 0;
	v_xchg->data_direction = DMA_NONE;
	v_xchg->hot_pool_tag = INVALID_VALUE16;
	v_xchg->big_sfs_buf = NULL;
	v_xchg->may_consume_res_cnt = 0;
	v_xchg->fact_consume_res_cnt = 0;
	v_xchg->io_front_jif = INVALID_VALUE64;
	v_xchg->ob_callback_sts = UNF_IO_SUCCESS;
	v_xchg->start_jif = 0;
	v_xchg->rport_bind_jifs = INVALID_VALUE64;
	v_xchg->scsi_id = INVALID_VALUE32;
	v_xchg->world_id = INVALID_VALUE32;

	memset(&v_xchg->seq, 0, sizeof(struct unf_seq_s));
	memset(&v_xchg->fcp_cmnd, 0, sizeof(struct unf_fcp_cmnd_s));
	memset(&v_xchg->scsi_cmnd_info, 0, sizeof(struct unf_scsi_cmd_info_s));
	memset(&v_xchg->abts_rsps, 0, sizeof(struct unf_abts_rsps_s));
	memset(&v_xchg->dif_info, 0, sizeof(struct dif_info_s));
	memset(v_xchg->private, 0,
	       (PKG_MAX_PRIVATE_DATA_SIZE * sizeof(unsigned int)));
	v_xchg->echo_info.echo_result = UNF_ELS_ECHO_RESULT_OK;
	v_xchg->echo_info.response_time = 0;

	if (v_xchg->xchg_type == UNF_XCHG_TYPE_INI) {
		if (v_xchg->fcp_sfs_union.fcp_rsp_entry.fcp_rsp_iu)
			memset(v_xchg->fcp_sfs_union.fcp_rsp_entry.fcp_rsp_iu,
			       0, sizeof(struct unf_fcprsp_iu_s));
	} else if (v_xchg->xchg_type == UNF_XCHG_TYPE_SFS) {
		if (v_xchg->fcp_sfs_union.sfs_entry.fc_sfs_entry_ptr) {
			memset(v_xchg->fcp_sfs_union.sfs_entry.fc_sfs_entry_ptr,
			       0, sizeof(union unf_sfs_u));
			v_xchg->fcp_sfs_union.sfs_entry.cur_offset = 0;
		}
	} else {
		UNF_TRACE(UNF_EVTLOG_IO_INFO, UNF_LOG_IO_ATT, UNF_MAJOR,
			  "Exchange Type(0x%x) SFS Union uninited.",
			  v_xchg->xchg_type);
	}
	v_xchg->xchg_type = UNF_XCHG_TYPE_INVALID;
	v_xchg->pfn_ob_callback = NULL;
	v_xchg->pfn_callback = NULL;
	v_xchg->pfn_free_xchg = NULL;

	atomic_set(&v_xchg->ref_cnt, 0);
	atomic_set(&v_xchg->esgl_cnt, 0);
	atomic_set(&v_xchg->delay_flag, 0);

	if (delayed_work_pending(&v_xchg->timeout_work))
		UNF_DEL_XCHG_TIMER_SAFE(v_xchg);

	spin_unlock_irqrestore(&v_xchg->xchg_state_lock, flags);
}

static void unf_add_back_to_fcp_list(
			struct unf_xchg_free_pool_s *v_free_pool,
			struct unf_xchg_s *v_xchg)
{
	unsigned long flags = 0;

	UNF_CHECK_VALID(0x928, UNF_TRUE, v_free_pool, return);
	UNF_CHECK_VALID(0x929, UNF_TRUE, v_xchg, return);

	unf_init_xchg_attribute(v_xchg);

	/* The released I/O resources are added to
	 * the queue tail to facilitate fault locating
	 */
	spin_lock_irqsave(&v_free_pool->xchg_free_pool_lock, flags);
	list_add_tail(&v_xchg->list_xchg_entry,
		      &v_free_pool->list_free_xchg_list);
	v_free_pool->total_fcp_xchg++;
	spin_unlock_irqrestore(&v_free_pool->xchg_free_pool_lock, flags);
}

static void unf_check_xchg_mgr_status(struct unf_xchg_mgr_s *v_xchg_mgr)
{
	unsigned long flags = 0;
	unsigned int total_xchg = 0;
	unsigned int total_xchg_sum = 0;

	UNF_CHECK_VALID(0x930, UNF_TRUE, v_xchg_mgr, return);

	spin_lock_irqsave(&v_xchg_mgr->free_pool.xchg_free_pool_lock, flags);

	total_xchg = v_xchg_mgr->free_pool.total_fcp_xchg +
		     v_xchg_mgr->free_pool.total_sfs_xchg;
	total_xchg_sum = v_xchg_mgr->free_pool.fcp_xchg_sum +
			 v_xchg_mgr->free_pool.sfs_xchg_sum;

	if ((v_xchg_mgr->free_pool.xchg_mgr_completion) &&
	    (total_xchg == total_xchg_sum)) {
		complete(v_xchg_mgr->free_pool.xchg_mgr_completion);
	}
	spin_unlock_irqrestore(&v_xchg_mgr->free_pool.xchg_free_pool_lock,
			       flags);
}

static void unf_free_fcp_xchg(struct unf_xchg_s *v_xchg)
{
	struct unf_xchg_free_pool_s *free_pool = NULL;
	struct unf_xchg_mgr_s *xchg_mgr = NULL;
	struct unf_lport_s *lport = NULL;
	struct unf_rport_s *rport = NULL;

	UNF_CHECK_VALID(0x932, UNF_TRUE, v_xchg, return);

	/* Releasing a Specified INI I/O and Invoking the scsi_done Process */
	unf_done_ini_xchg(v_xchg);
	free_pool = v_xchg->free_pool;
	xchg_mgr = v_xchg->xchg_mgr;
	lport = v_xchg->lport;
	rport = v_xchg->rport;

	atomic_dec(&rport->pending_io_cnt);
	/* Release the Esgls in the Xchg structure and
	 * return it to the EsglPool of the Lport
	 */
	unf_release_esgls(v_xchg);

	/* Mount I/O resources to the FCP Free linked list */
	unf_add_back_to_fcp_list(free_pool, v_xchg);

	/* The Xchg is released synchronously and then forcibly released to
	 * prevent the Xchg from accessing the Xchg in the normal I/O process
	 */
	if (unlikely(lport->b_port_removing == UNF_TRUE))
		unf_check_xchg_mgr_status(xchg_mgr);
}

static void unf_fc_abort_timeout_cmnd(struct unf_lport_s *v_lport,
				      struct unf_xchg_s *v_xchg)
{
	struct unf_lport_s *lport = v_lport;
	struct unf_xchg_s *xchg = v_xchg;
	struct unf_scsi_cmd_s scsi_cmnd = { 0 };
	unsigned long flag = 0;
	unsigned int timeout_value = 2000;
	unsigned int return_value = 0;
	struct unf_rport_scsi_id_image_s *scsi_image_table = NULL;

	UNF_CHECK_VALID(0x936, UNF_TRUE, v_lport, return);
	UNF_CHECK_VALID(0x937, UNF_TRUE, v_xchg, return);

	spin_lock_irqsave(&v_xchg->xchg_state_lock, flag);
	if (v_xchg->io_state & INI_IO_STATE_UPABORT) {
		spin_unlock_irqrestore(&v_xchg->xchg_state_lock, flag);

		UNF_TRACE(UNF_EVTLOG_IO_INFO, UNF_LOG_IO_ATT, UNF_MAJOR,
			  "LPort(0x%x) xchange(0x%p) OX_ID(0x%x), RX_ID(0x%x)  Cmdsn(0x%lx) has been aborted.",
			  lport->port_id, v_xchg, v_xchg->ox_id,
			  v_xchg->rx_id, (unsigned long)v_xchg->cmnd_sn);
		return;
	}
	v_xchg->io_state |= INI_IO_STATE_UPABORT;
	spin_unlock_irqrestore(&v_xchg->xchg_state_lock, flag);

	UNF_TRACE(UNF_EVTLOG_IO_INFO, UNF_LOG_NORMAL, UNF_KEVENT,
		  "LPort(0x%x) exchg(0x%p) OX_ID(0x%x) RX_ID(0x%x) Cmdsn(0x%lx) timeout abort it",
		  lport->port_id, v_xchg, v_xchg->ox_id,
		  v_xchg->rx_id, (unsigned long)v_xchg->cmnd_sn);

	lport->xchg_mgr_temp.pfn_unf_xchg_add_timer(
				(void *)v_xchg,
				(unsigned long)UNF_WAIT_ABTS_RSP_TIMEOUT,
				UNF_TIMER_TYPE_INI_ABTS);

	sema_init(&v_xchg->task_sema, 0);

	scsi_cmnd.scsi_id = xchg->scsi_cmnd_info.scsi_id;
	scsi_cmnd.upper_cmnd = xchg->scsi_cmnd_info.scsi_cmnd;
	scsi_cmnd.pfn_done = xchg->scsi_cmnd_info.pfn_done;
	scsi_image_table = &lport->rport_scsi_table;

	if (unf_send_abts(lport, v_xchg) != RETURN_OK) {
		UNF_TRACE(UNF_EVTLOG_IO_INFO, UNF_LOG_IO_ATT, UNF_MAJOR,
			  "LPort(0x%x) send ABTS, Send ABTS unsuccessful. Exchange OX_ID(0x%x), RX_ID(0x%x).",
			  lport->port_id, v_xchg->ox_id,
			  v_xchg->rx_id);
		lport->xchg_mgr_temp.pfn_unf_xchg_cancel_timer((void *)v_xchg);

		spin_lock_irqsave(&v_xchg->xchg_state_lock, flag);
		v_xchg->io_state &= ~INI_IO_STATE_UPABORT;
		spin_unlock_irqrestore(&v_xchg->xchg_state_lock, flag);
		/* The message fails to be sent.
		 * It is released internally and does not
		 * need to be released externally.
		 */
		return;
	}

	if (down_timeout(&v_xchg->task_sema,
			 (long long)msecs_to_jiffies(timeout_value))) {
		UNF_TRACE(UNF_EVTLOG_IO_WARN, UNF_LOG_IO_ATT, UNF_WARN,
			  "[warn]Port(0x%x) recv abts marker timeout,Exch(0x%p) OX_ID(0x%x) RX_ID(0x%x)",
			  lport->port_id, v_xchg,
			  v_xchg->ox_id, v_xchg->rx_id);
		lport->xchg_mgr_temp.pfn_unf_xchg_cancel_timer((void *)v_xchg);

		/* Cnacel the flag of INI_IO_STATE_UPABORT
		 * and process the io in TMF
		 */
		spin_lock_irqsave(&v_xchg->xchg_state_lock, flag);
		v_xchg->io_state &= ~INI_IO_STATE_UPABORT;
		spin_unlock_irqrestore(&v_xchg->xchg_state_lock, flag);

		return;
	}

	spin_lock_irqsave(&v_xchg->xchg_state_lock, flag);
	if ((v_xchg->ucode_abts_state == UNF_IO_SUCCESS) ||
	    (v_xchg->scsi_cmnd_info.result == UNF_IO_ABORT_PORT_REMOVING)) {
		spin_unlock_irqrestore(&v_xchg->xchg_state_lock, flag);

		UNF_TRACE(UNF_EVTLOG_IO_WARN, UNF_LOG_IO_ATT, UNF_MAJOR,
			  "[info]Port(0x%x) Send ABTS succeed and recv marker Exch(0x%p) OX_ID(0x%x) RX_ID(0x%x) marker status(0x%x)",
			  lport->port_id, v_xchg,
			  v_xchg->ox_id, v_xchg->rx_id,
			  v_xchg->ucode_abts_state);
		return_value = DID_BUS_BUSY;
		UNF_IO_RESULT_CNT(scsi_image_table, scsi_cmnd.scsi_id,
				  return_value);
		unf_complete_cmnd(&scsi_cmnd, DID_BUS_BUSY << 16);
		return;
	}
	spin_unlock_irqrestore(&v_xchg->xchg_state_lock, flag);
	lport->xchg_mgr_temp.pfn_unf_xchg_cancel_timer((void *)v_xchg);
	spin_lock_irqsave(&v_xchg->xchg_state_lock, flag);
	v_xchg->io_state &= ~INI_IO_STATE_UPABORT;
	spin_unlock_irqrestore(&v_xchg->xchg_state_lock, flag);
	UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_REG_ATT, UNF_WARN,
		  "[warn]Port(0x%x) send ABTS failed. Exch(0x%p) hot_tag(0x%x) ret(0x%x) v_xchg->io_state (0x%x)",
		  lport->port_id, v_xchg, v_xchg->hot_pool_tag,
		  v_xchg->scsi_cmnd_info.result, v_xchg->io_state);
}

static void unf_fc_ini_send_abts_timeout(struct unf_lport_s *lport,
					 struct unf_rport_s *rport,
					 struct unf_xchg_s *xchg)
{
	if (xchg->rport_bind_jifs == rport->rport_alloc_jifs &&
	    xchg->rport_bind_jifs != INVALID_VALUE64) {
		UNF_TRACE(UNF_EVTLOG_IO_WARN, UNF_LOG_IO_ATT, UNF_WARN,
			  "[warn]Port(0x%x) RPort(0x%x) Exch(0x%p) first time to send abts timeout, retry again OX_ID(0x%x) RX_ID(0x%x) state(0x%x)",
			  lport->port_id, rport->nport_id,
			  xchg, xchg->ox_id, xchg->rx_id, xchg->io_state);

		lport->xchg_mgr_temp.pfn_unf_xchg_add_timer(
				(void *)xchg,
				(unsigned long)UNF_WAIT_ABTS_RSP_TIMEOUT,
				UNF_TIMER_TYPE_INI_ABTS);

		if (unf_send_abts(lport, xchg) != RETURN_OK) {
			lport->xchg_mgr_temp.pfn_unf_xchg_cancel_timer(
								(void *)xchg);

			unf_abts_timeout_recovery_default(rport, xchg);

			unf_cm_free_xchg(lport, xchg);
		}
	} else {
		UNF_TRACE(UNF_EVTLOG_IO_WARN, UNF_LOG_IO_ATT, UNF_WARN,
			  "[warn]Port(0x%x) RPort(0x%x) Exch(0x%p) rport is invalid, exchg rport jiff(0x%llx 0x%llx), free exchange OX_ID(0x%x) RX_ID(0x%x) state(0x%x)",
			  lport->port_id, rport->nport_id, xchg,
			  xchg->rport_bind_jifs, rport->rport_alloc_jifs,
			  xchg->ox_id, xchg->rx_id, xchg->io_state);

		unf_cm_free_xchg(lport, xchg);
	}
}

static void unf_fc_ini_io_rec_wait_timeout(struct unf_lport_s *lport,
					   struct unf_rport_s *rport,
					   struct unf_xchg_s *xchg)
{
	unsigned long io_time_out = 0;

	if (xchg->rport_bind_jifs == rport->rport_alloc_jifs) {
		unf_send_rec(lport, rport, xchg);
		if (xchg->scsi_cmnd_info.abort_timeout > 0) {
			io_time_out =
				(xchg->scsi_cmnd_info.abort_timeout >
				UNF_REC_TOV) ?
				(xchg->scsi_cmnd_info.abort_timeout -
				UNF_REC_TOV) : 0;

			if (io_time_out > 0) {
				lport->xchg_mgr_temp.pfn_unf_xchg_add_timer(
							(void *)xchg,
							io_time_out,
							UNF_TIMER_TYPE_REQ_IO);
			} else {
				unf_fc_abort_timeout_cmnd(lport, xchg);
			}
		}
	} else {
		UNF_TRACE(UNF_EVTLOG_IO_WARN, UNF_LOG_IO_ATT, UNF_WARN,
			  "[warn]Port(0x%x) RPort(0x%x) Exch(0x%p) Rec timeout exchange OX_ID(0x%x) RX_ID(0x%x) state(0x%x), bindjifs(0x%llx)no eqal Rport alloc jifs(0x%llx)",
			  lport->port_id, rport->nport_id,
			  xchg, xchg->ox_id, xchg->rx_id,
			  xchg->io_state, xchg->rport_bind_jifs,
			  rport->rport_alloc_jifs);
	}
}

static void unf_fc_ini_io_xchg_timeout(struct work_struct *v_work)
{
	struct unf_xchg_s *xchg = NULL;
	struct unf_lport_s *lport = NULL;
	struct unf_rport_s *rport = NULL;
	unsigned long flags = 0;
	unsigned int ret = UNF_RETURN_ERROR;
	unsigned int port_valid_flag = 0;

	UNF_REFERNCE_VAR(ret);

	xchg = container_of(v_work, struct unf_xchg_s, timeout_work.work);
	UNF_CHECK_VALID(0x939, UNF_TRUE, xchg, return);

	ret = unf_xchg_ref_inc(xchg, INI_IO_TIMEOUT);
	UNF_CHECK_VALID(0x940, UNF_TRUE, ret == RETURN_OK, return);

	lport = xchg->lport;
	rport = xchg->rport;

	port_valid_flag = !lport || !rport;
	if (port_valid_flag) {
		unf_xchg_ref_dec(xchg, INI_IO_TIMEOUT);
		unf_xchg_ref_dec(xchg, INI_IO_TIMEOUT);

		return;
	}

	spin_lock_irqsave(&xchg->xchg_state_lock, flags);

	/* 1. for Send RRQ failed Timer timeout */
	if (INI_IO_STATE_RRQSEND_ERR & xchg->io_state) {
		spin_unlock_irqrestore(&xchg->xchg_state_lock, flags);

		UNF_TRACE(UNF_EVTLOG_IO_WARN, UNF_LOG_IO_ATT, UNF_WARN,
			  "[info]LPort(0x%x) RPort(0x%x) Exch(0x%p) had wait enough time for RRQ send failed OX_ID(0x%x) RX_ID(0x%x) state(0x%x)",
			  lport->port_id, rport->nport_id,
			  xchg, xchg->ox_id, xchg->rx_id, xchg->io_state);

		unf_cm_free_xchg(lport, xchg);
	}
	/* Second ABTS timeout and enter LOGO process */
	else if ((INI_IO_STATE_ABORT_TIMEOUT & xchg->io_state) &&
		 (!(ABTS_RESPONSE_RECEIVED & xchg->abts_state))) {
		spin_unlock_irqrestore(&xchg->xchg_state_lock, flags);

		UNF_TRACE(UNF_EVTLOG_IO_WARN, UNF_LOG_IO_ATT, UNF_WARN,
			  "[warn]Port(0x%x) RPort(0x%x) Exch(0x%p) had wait enough time for second abts send OX_ID(0x%x) RX_ID(0x%x) state(0x%x)",
			  lport->port_id, rport->nport_id,
			  xchg, xchg->ox_id, xchg->rx_id,
			  xchg->io_state);

		unf_abts_timeout_recovery_default(rport, xchg);

		unf_cm_free_xchg(lport, xchg);
	}
	/* First time to send ABTS, timeout and retry to send ABTS again */
	else if ((xchg->io_state & INI_IO_STATE_UPABORT) &&
		 (!(xchg->abts_state & ABTS_RESPONSE_RECEIVED))) {
		xchg->io_state |= INI_IO_STATE_ABORT_TIMEOUT;
		spin_unlock_irqrestore(&xchg->xchg_state_lock, flags);
		unf_fc_ini_send_abts_timeout(lport, rport, xchg);
	}
	/* 3. IO_DONE */
	else if ((xchg->io_state & INI_IO_STATE_DONE) &&
		 (xchg->abts_state & ABTS_RESPONSE_RECEIVED)) {
		/*
		 * for IO_DONE:
		 * 1. INI ABTS first timer time out
		 * 2. INI RCVD ABTS Response
		 * 3. Normal case for I/O Done
		 */
		/* Send ABTS & RCVD RSP & no timeout */
		spin_unlock_irqrestore(&xchg->xchg_state_lock, flags);

		/* Send RRQ */
		if (unf_send_rrq(lport, rport, xchg) == RETURN_OK) {
			UNF_TRACE(UNF_EVTLOG_IO_INFO, UNF_LOG_IO_ATT,
				  UNF_MAJOR,
				  "[info]LPort(0x%x) send RRQ succeed to RPort(0x%x) Exch(0x%p) OX_ID(0x%x) RX_ID(0x%x) state(0x%x)",
				  lport->port_id, rport->nport_id, xchg,
				  xchg->ox_id, xchg->rx_id, xchg->io_state);
		} else {
			UNF_TRACE(UNF_EVTLOG_IO_WARN, UNF_LOG_IO_ATT,
				  UNF_WARN,
				  "[warn]LPort(0x%x) can't send RRQ to RPort(0x%x) Exch(0x%p) OX_ID(0x%x) RX_ID(0x%x) state(0x%x)",
				  lport->port_id, rport->nport_id, xchg,
				  xchg->ox_id, xchg->rx_id, xchg->io_state);

			spin_lock_irqsave(&xchg->xchg_state_lock, flags);
			xchg->io_state |= INI_IO_STATE_RRQSEND_ERR;
			spin_unlock_irqrestore(&xchg->xchg_state_lock, flags);

			lport->xchg_mgr_temp.pfn_unf_xchg_add_timer(
				(void *)xchg,
				(unsigned long)UNF_WRITE_RRQ_SENDERR_INTERVAL,
				UNF_TIMER_TYPE_INI_IO);
		}
	} else if (xchg->io_state & INI_IO_STATE_REC_TIMEOUT_WAIT) {
		xchg->io_state &= ~INI_IO_STATE_REC_TIMEOUT_WAIT;
		spin_unlock_irqrestore(&xchg->xchg_state_lock, flags);
		unf_fc_ini_io_rec_wait_timeout(lport, rport, xchg);
	} else {
		/* 4. I/O Timer Timeout */
		/* vmware */
		spin_unlock_irqrestore(&xchg->xchg_state_lock, flags);

		unf_fc_abort_timeout_cmnd(lport, xchg);
	}

	unf_xchg_ref_dec(xchg, INI_IO_TIMEOUT);
	unf_xchg_ref_dec(xchg, INI_IO_TIMEOUT);

	UNF_REFERNCE_VAR(ret);
}

static inline struct unf_xchg_s *unf_alloc_io_xchg(
					struct unf_lport_s *v_lport,
					struct unf_xchg_mgr_s *v_xchg_mgr,
					unsigned int v_xchg_type,
					unsigned short v_rx_id)
{
	struct unf_xchg_s *xchg = NULL;
	struct list_head *list_node = NULL;
	struct unf_xchg_free_pool_s *free_pool = NULL;
	struct unf_xchg_hot_pool_s *hot_pool = NULL;
	unsigned long flags = 0;
	static atomic64_t s_exhg_id;

	void (*unf_fc_io_xchg_timeout)(struct work_struct *v_work) = NULL;

	UNF_CHECK_VALID(0x941, UNF_TRUE, v_xchg_mgr, return NULL);
	UNF_CHECK_VALID(0x942, UNF_TRUE, v_lport, return NULL);

	free_pool = &v_xchg_mgr->free_pool;
	hot_pool = v_xchg_mgr->hot_pool;
	UNF_CHECK_VALID(0x943, UNF_TRUE, free_pool, return NULL);
	UNF_CHECK_VALID(0x944, UNF_TRUE, hot_pool, return NULL);

	/* 1. Free Pool */
	spin_lock_irqsave(&free_pool->xchg_free_pool_lock, flags);
	if (unlikely(list_empty(&free_pool->list_free_xchg_list))) {
		UNF_TRACE(UNF_EVTLOG_IO_INFO, UNF_LOG_IO_ATT, UNF_INFO,
			  "Port(0x%x) have no Exchange anymore.",
			  v_lport->port_id);

		spin_unlock_irqrestore(&free_pool->xchg_free_pool_lock, flags);

		return NULL;
	}

	/* Select an idle node from free pool */
	list_node = (&free_pool->list_free_xchg_list)->next;
	list_del(list_node);
	free_pool->total_fcp_xchg--;
	spin_unlock_irqrestore(&free_pool->xchg_free_pool_lock, flags);

	xchg = list_entry(list_node, struct unf_xchg_s, list_xchg_entry);

	/*
	 * Hot Pool:
	 * When xchg is mounted to Hot Pool, the mount mode and release mode
	 * of Xchg must be specified and stored in the sfs linked list.
	 */
	flags = 0;
	spin_lock_irqsave(&hot_pool->xchg_hot_pool_lock, flags);
	if (unf_alloc_hot_pool_slab(hot_pool, xchg, v_rx_id) != RETURN_OK) {
		spin_unlock_irqrestore(&hot_pool->xchg_hot_pool_lock, flags);

		unf_add_back_to_fcp_list(free_pool, xchg);
		if (unlikely(v_lport->b_port_removing == UNF_TRUE))
			unf_check_xchg_mgr_status(v_xchg_mgr);

		return NULL;
	}

	list_add_tail(&xchg->list_xchg_entry, &hot_pool->ini_busylist);
	unf_fc_io_xchg_timeout = unf_fc_ini_io_xchg_timeout;

	spin_unlock_irqrestore(&hot_pool->xchg_hot_pool_lock, flags);

	/* 3. Exchange State */
	spin_lock_irqsave(&xchg->xchg_state_lock, flags);
	xchg->start_jif = atomic64_inc_return(&s_exhg_id);
	xchg->xchg_mgr = v_xchg_mgr;
	xchg->free_pool = free_pool;
	xchg->hot_pool = hot_pool;
	xchg->lport = v_lport;
	xchg->xchg_type = v_xchg_type;
	xchg->pfn_free_xchg = unf_free_fcp_xchg;
	xchg->io_state = UNF_IO_STATE_NEW;
	xchg->io_send_stage = TGT_IO_SEND_STAGE_NONE;
	xchg->io_send_result = TGT_IO_SEND_RESULT_INVALID;
	xchg->io_send_abort = UNF_FALSE;
	xchg->io_abort_result = UNF_FALSE;
	xchg->ox_id = INVALID_VALUE16;
	xchg->abort_oxid = INVALID_VALUE16;
	xchg->rx_id = INVALID_VALUE16;
	xchg->sid = INVALID_VALUE32;
	xchg->did = INVALID_VALUE32;
	xchg->oid = INVALID_VALUE32;
	xchg->seq_id = INVALID_VALUE8;
	xchg->cmnd_code = INVALID_VALUE32;
	xchg->data_len = 0;
	xchg->resid_len = 0;
	xchg->data_direction = DMA_NONE;
	xchg->may_consume_res_cnt = 0;
	xchg->fact_consume_res_cnt = 0;
	xchg->io_front_jif = 0;
	xchg->tmf_state = 0;
	xchg->ucode_abts_state = INVALID_VALUE32;
	xchg->abts_state = 0;
	xchg->rport_bind_jifs = INVALID_VALUE64;
	xchg->scsi_id = INVALID_VALUE32;
	xchg->world_id = INVALID_VALUE32;

	memset(&xchg->dif_control, 0, sizeof(struct unf_dif_control_info_s));
	memset(&xchg->req_sgl_info, 0, sizeof(struct unf_req_sgl_info_s));
	memset(&xchg->dif_sgl_info, 0, sizeof(struct unf_req_sgl_info_s));
	memset(&xchg->abts_rsps, 0, sizeof(struct unf_abts_rsps_s));
	xchg->scsi_cmnd_info.result = 0;

	xchg->private[PKG_PRIVATE_XCHG_ALLOC_TIME] =
		(unsigned int)atomic64_inc_return(&v_lport->exchg_index);
	if (xchg->private[PKG_PRIVATE_XCHG_ALLOC_TIME] == 0)
		xchg->private[PKG_PRIVATE_XCHG_ALLOC_TIME] =
		(unsigned int)atomic64_inc_return(&v_lport->exchg_index);

	atomic_set(&xchg->ref_cnt, 0);
	atomic_set(&xchg->delay_flag, 0);

	if (delayed_work_pending(&xchg->timeout_work))
		UNF_DEL_XCHG_TIMER_SAFE(xchg);

	INIT_DELAYED_WORK(&xchg->timeout_work, unf_fc_io_xchg_timeout);
	spin_unlock_irqrestore(&xchg->xchg_state_lock, flags);

	return xchg;
}

static void unf_add_back_to_sfs_list(
				struct unf_xchg_free_pool_s *v_free_pool,
				struct unf_xchg_s *v_xchg)
{
	unsigned long flags = 0;

	UNF_CHECK_VALID(0x945, UNF_TRUE, v_free_pool, return);
	UNF_CHECK_VALID(0x946, UNF_TRUE, v_xchg, return);

	unf_init_xchg_attribute(v_xchg);

	spin_lock_irqsave(&v_free_pool->xchg_free_pool_lock, flags);

	list_add_tail(&v_xchg->list_xchg_entry,
		      &v_free_pool->list_sfs_xchg_list);
	v_free_pool->total_sfs_xchg++;
	spin_unlock_irqrestore(&v_free_pool->xchg_free_pool_lock, flags);
}

static void unf_free_sfs_xchg(struct unf_xchg_s *v_xchg)
{
	struct unf_xchg_free_pool_s *free_pool = NULL;
	struct unf_xchg_mgr_s *xchg_mgr = NULL;
	struct unf_lport_s *lport = NULL;

	UNF_CHECK_VALID(0x947, UNF_TRUE, v_xchg, return);

	free_pool = v_xchg->free_pool;
	lport = v_xchg->lport;
	xchg_mgr = v_xchg->xchg_mgr;

	/* The memory is applied for when the GID_PT/GID_FT is sent.
	 * If no response is received, the GID_PT/GID_FT
	 * needs to be forcibly released.
	 */

	unf_free_one_big_sfs(v_xchg);

	unf_add_back_to_sfs_list(free_pool, v_xchg);

	if (unlikely(lport->b_port_removing == UNF_TRUE))
		unf_check_xchg_mgr_status(xchg_mgr);
}

static void unf_fc_xchg_add_timer(void *v_xchg,
				  unsigned long v_time_ms,
				  enum unf_timer_type_e v_en_time_type)
{
	unsigned long flag = 0;
	struct unf_xchg_s *xchg = NULL;
	unsigned long time_ms = v_time_ms;
	struct unf_lport_s *lport;

	UNF_CHECK_VALID(0x948, UNF_TRUE, v_xchg, return);
	xchg = (struct unf_xchg_s *)v_xchg;
	lport = xchg->lport;
	UNF_CHECK_VALID(0x948, UNF_TRUE, lport, return);

	/* update timeout */
	switch (v_en_time_type) {
	case UNF_TIMER_TYPE_INI_RRQ:
		time_ms = time_ms - UNF_INI_RRQ_REDUNDANT_TIME;
		UNF_TRACE(UNF_EVTLOG_IO_INFO, UNF_LOG_IO_ATT,
			  UNF_INFO, "INI RRQ Timer set.");
		break;

	case UNF_TIMER_TYPE_SFS:
		time_ms = time_ms + UNF_INI_ELS_REDUNDANT_TIME;
		UNF_TRACE(UNF_EVTLOG_IO_INFO, UNF_LOG_IO_ATT,
			  UNF_INFO, "INI ELS Timer set.");
		break;
	default:
		break;
	}

	/* The xchg of the timer must be valid.
	 * If the reference count of xchg is 0,
	 * the timer must not be added
	 */
	if (atomic_read(&xchg->ref_cnt) <= 0) {
		UNF_TRACE(UNF_EVTLOG_IO_INFO, UNF_LOG_IO_ATT, UNF_KEVENT,
			  "[warn]Abnormal Exchange(0x%p), Reference count(0x%x), Can't add timer.",
			  xchg, atomic_read(&xchg->ref_cnt));
		return;
	}

	/* Delay Work: Hold for timer */
	spin_lock_irqsave(&xchg->xchg_state_lock, flag);
	if (queue_delayed_work(lport->xchg_wq,
			       &xchg->timeout_work,
			       (unsigned long)
			       msecs_to_jiffies((unsigned int)time_ms))) {
		/* hold for timer */
		atomic_inc(&xchg->ref_cnt);
	}
	spin_unlock_irqrestore(&xchg->xchg_state_lock, flag);
}

static void unf_sfs_xchg_timeout(struct work_struct *v_work)
{
	struct unf_xchg_s *xchg = NULL;
	unsigned int ret = UNF_RETURN_ERROR;
	struct unf_lport_s *lport = NULL;
	struct unf_rport_s *rport = NULL;
	unsigned long flags = 0;

	UNF_CHECK_VALID(0x949, UNF_TRUE, v_work, return);
	xchg = container_of(v_work, struct unf_xchg_s, timeout_work.work);
	UNF_CHECK_VALID(0x950, UNF_TRUE, xchg, return);

	ret = unf_xchg_ref_inc(xchg, SFS_TIMEOUT);
	UNF_REFERNCE_VAR(ret);
	UNF_CHECK_VALID(0x951, UNF_TRUE, ret == RETURN_OK, return);

	spin_lock_irqsave(&xchg->xchg_state_lock, flags);
	lport = xchg->lport;
	rport = xchg->rport;
	spin_unlock_irqrestore(&xchg->xchg_state_lock, flags);

	unf_xchg_ref_dec(xchg, SFS_TIMEOUT);

	UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT, UNF_WARN,
		  "[warn]SFS Exch(%p) Cmnd(0x%x) IO Exch(0x%p) Sid_Did(0x%x:0x%x) HotTag(0x%x) State(0x%x) Timeout.",
		  xchg, xchg->cmnd_code, xchg->io_xchg, xchg->sid,
		  xchg->did, xchg->hot_pool_tag, xchg->io_state);

	spin_lock_irqsave(&xchg->xchg_state_lock, flags);
	if ((xchg->io_state & TGT_IO_STATE_ABORT) &&
	    (xchg->cmnd_code != ELS_RRQ) &&
	    (xchg->cmnd_code != ELS_LOGO)) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT, UNF_INFO,
			  "SFS Exch(0x%p) Cmnd(0x%x) Hot Pool Tag(0x%x) timeout, but aborted, no need to handle.",
			  xchg, xchg->cmnd_code, xchg->hot_pool_tag);
		spin_unlock_irqrestore(&xchg->xchg_state_lock, flags);

		unf_xchg_ref_dec(xchg, SFS_TIMEOUT);
		unf_xchg_ref_dec(xchg, SFS_TIMEOUT);

		return;
	}
	spin_unlock_irqrestore(&xchg->xchg_state_lock, flags);

	/* The sfs times out. If the sfs is ELS reply,
	 * go to unf_rport_error_recovery/unf_lport_error_recovery.
	 * Otherwise, go to the corresponding obCallback.
	 */
	if (UNF_XCHG_IS_ELS_REPLY(xchg) && (rport)) {
		if (rport->nport_id >= UNF_FC_FID_DOM_MGR)
			unf_lport_error_recovery(lport);
		else
			unf_rport_error_recovery(rport);
	} else if (xchg->pfn_ob_callback) {
		xchg->pfn_ob_callback(xchg);
	} else {
		/* Do nothing */
	}

	unf_xchg_ref_dec(xchg, SFS_TIMEOUT);
	unf_xchg_ref_dec(xchg, SFS_TIMEOUT);
}

static struct unf_xchg_s *unf_alloc_sfs_xchg(struct unf_lport_s *v_lport,
					     struct unf_xchg_mgr_s *v_xchg_mgr,
					     unsigned int v_xchg_type,
					     unsigned short v_rx_id)
{
	struct unf_xchg_s *xchg = NULL;
	struct list_head *list_node = NULL;
	struct unf_xchg_free_pool_s *free_pool = NULL;
	struct unf_xchg_hot_pool_s *hot_pool = NULL;
	unsigned long flags = 0;

	UNF_CHECK_VALID(0x952, UNF_TRUE, v_lport, return NULL);
	UNF_CHECK_VALID(0x953, UNF_TRUE, v_xchg_mgr, return NULL);
	free_pool = &v_xchg_mgr->free_pool;
	hot_pool = v_xchg_mgr->hot_pool;
	UNF_CHECK_VALID(0x954, UNF_TRUE, free_pool, return NULL);
	UNF_CHECK_VALID(0x955, UNF_TRUE, hot_pool, return NULL);

	/* Select an idle node from free pool */
	spin_lock_irqsave(&free_pool->xchg_free_pool_lock, flags);
	if (list_empty(&free_pool->list_sfs_xchg_list)) {
		UNF_TRACE(UNF_EVTLOG_IO_INFO, UNF_LOG_IO_ATT, UNF_MAJOR,
			  "Port(0x%x) have no Exchange anymore.",
			  v_lport->port_id);

		spin_unlock_irqrestore(&free_pool->xchg_free_pool_lock, flags);

		return NULL;
	}

	list_node = (&free_pool->list_sfs_xchg_list)->next;
	list_del(list_node);
	free_pool->total_sfs_xchg--;
	spin_unlock_irqrestore(&free_pool->xchg_free_pool_lock, flags);

	xchg = list_entry(list_node, struct unf_xchg_s, list_xchg_entry);

	/*
	 * The xchg is mounted to the Hot Pool.
	 * The mount mode and release mode of the xchg must be specified
	 * and stored in the sfs linked list.
	 */
	flags = 0;
	spin_lock_irqsave(&hot_pool->xchg_hot_pool_lock, flags);
	if (unf_alloc_hot_pool_slab(hot_pool, xchg, v_rx_id) != RETURN_OK) {
		spin_unlock_irqrestore(&hot_pool->xchg_hot_pool_lock, flags);

		unf_add_back_to_sfs_list(free_pool, xchg);
		if (unlikely(v_lport->b_port_removing == UNF_TRUE))
			unf_check_xchg_mgr_status(v_xchg_mgr);

		return NULL;
	}

	list_add_tail(&xchg->list_xchg_entry, &hot_pool->sfs_busylist);
	hot_pool->total_xchges++;
	spin_unlock_irqrestore(&hot_pool->xchg_hot_pool_lock, flags);

	spin_lock_irqsave(&xchg->xchg_state_lock, flags);
	xchg->free_pool = free_pool;
	xchg->hot_pool = hot_pool;
	xchg->lport = v_lport;
	xchg->xchg_mgr = v_xchg_mgr;
	xchg->pfn_free_xchg = unf_free_sfs_xchg;
	xchg->xchg_type = v_xchg_type;
	xchg->io_state = UNF_IO_STATE_NEW;
	xchg->scsi_cmnd_info.result = 0;
	xchg->ob_callback_sts = UNF_IO_SUCCESS;

	xchg->private[PKG_PRIVATE_XCHG_ALLOC_TIME] =
		(unsigned int)atomic64_inc_return(&v_lport->exchg_index);
	if (xchg->private[PKG_PRIVATE_XCHG_ALLOC_TIME] == 0)
		xchg->private[PKG_PRIVATE_XCHG_ALLOC_TIME] =
			(unsigned int)
			atomic64_inc_return(&v_lport->exchg_index);

	if (delayed_work_pending(&xchg->timeout_work))
		UNF_DEL_XCHG_TIMER_SAFE(xchg);

	INIT_DELAYED_WORK(&xchg->timeout_work, unf_sfs_xchg_timeout);
	spin_unlock_irqrestore(&xchg->xchg_state_lock, flags);

	return xchg;
}

static void *unf_get_new_xchg(void *v_lport, unsigned int v_xchg_type,
			      unsigned short v_rx_id)
{
	struct unf_lport_s *lport = NULL;
	struct unf_xchg_mgr_s *xchg_mgr = NULL;
	struct unf_xchg_s *xchg = NULL;
	unsigned int xchg_type = 0;
	unsigned short xchg_mgr_type;
	unsigned int rtry_cnt = 0;
	unsigned int last_exchg_mgr_idx;

	xchg_mgr_type = (v_xchg_type >> 16);
	xchg_type = v_xchg_type & 0xFFFF;
	UNF_CHECK_VALID(0x956, UNF_TRUE, v_lport, return NULL);

	/* In the case of NPIV, the v_lport is the Vport pointer,
	 * and the share uses the ExchMgr of the RootLport.
	 */
	lport = ((struct unf_lport_s *)v_lport)->root_lport;
	UNF_CHECK_VALID(0x957, UNF_TRUE, (lport), return NULL);

	if (unlikely((atomic_read(&lport->port_no_operater_flag) ==
		      UNF_LPORT_NOP) ||
		     (atomic_read(&((struct unf_lport_s *)v_lport)->port_no_operater_flag) ==
		      UNF_LPORT_NOP)))
		return NULL;

	last_exchg_mgr_idx =
		(unsigned int)atomic64_inc_return(&lport->last_exchg_mgr_idx);
try_next_mgr:
	rtry_cnt++;
	if (unlikely(rtry_cnt > UNF_EXCHG_MGR_NUM))
		return NULL;

	/* If Fixed mode,only use XchgMgr 0 */
	if (unlikely(xchg_mgr_type == UNF_XCHG_MGR_TYPE_FIXED))
		xchg_mgr = (struct unf_xchg_mgr_s *)lport->p_xchg_mgr[0];
	else
		xchg_mgr =
		(struct unf_xchg_mgr_s *)
		lport->p_xchg_mgr[last_exchg_mgr_idx % UNF_EXCHG_MGR_NUM];

	if (unlikely(!xchg_mgr)) {
		UNF_TRACE(UNF_EVTLOG_IO_ERR, UNF_LOG_IO_ATT, UNF_ERR,
			  "[err]Port(0x%x) get exchangemgr %u is null.",
			  lport->port_id,
			  last_exchg_mgr_idx % UNF_EXCHG_MGR_NUM);
		return NULL;
	}

	last_exchg_mgr_idx++;

	/* Allocate entries based on the Exchange type */
	switch (xchg_type) {
	case UNF_XCHG_TYPE_SFS:
		xchg = unf_alloc_sfs_xchg(v_lport, xchg_mgr, xchg_type,
					  INVALID_VALUE16);
		break;

	case UNF_XCHG_TYPE_INI:
		xchg = unf_alloc_io_xchg(v_lport, xchg_mgr, xchg_type,
					 INVALID_VALUE16);
		break;

	default:
		UNF_TRACE(UNF_EVTLOG_IO_INFO, UNF_LOG_IO_ATT, UNF_MAJOR,
			  "Port(0x%x) unwonted, Exchange type(0x%x).",
			  lport->port_id, xchg_type);
		break;
	}

	if (likely(xchg)) {
		xchg->ox_id = INVALID_VALUE16;
		xchg->abort_oxid = INVALID_VALUE16;
		xchg->rx_id = INVALID_VALUE16;
		xchg->debug_hook = UNF_FALSE;
		xchg->alloc_jif = jiffies;

		atomic_set(&xchg->ref_cnt, 1);
		atomic_set(&xchg->esgl_cnt, 0);
	} else {
		goto try_next_mgr;
	}

	return xchg;
}

static void unf_free_xchg(void *v_lport, void *v_xchg)
{
	struct unf_xchg_s *xchg = NULL;

	UNF_REFERNCE_VAR(v_lport);
	UNF_CHECK_VALID(0x958, UNF_TRUE, (v_xchg), return);

	xchg = (struct unf_xchg_s *)v_xchg;
	unf_xchg_ref_dec(xchg, XCHG_FREE_XCHG);
}

void unf_release_xchg_mgr_temp(struct unf_lport_s *v_lport)
{
	UNF_CHECK_VALID(0x960, UNF_TRUE, v_lport, return);

	if (v_lport->dirty_flag & UNF_LPORT_DIRTY_FLAG_XCHGMGR_DIRTY) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_REG_ATT, UNF_MAJOR,
			  "Port(0x%x) has dirty exchange, Don't release exchange manager template.",
			  v_lport->port_id);

		return;
	}

	memset(&v_lport->xchg_mgr_temp, 0,
	       sizeof(struct unf_cm_xchg_mgr_template_s));

	v_lport->destroy_step = UNF_LPORT_DESTROY_STEP_7_DESTROY_XCHG_MGR_TMP;
}

static void unf_xchg_abort_all_sfs_xchg(struct unf_lport_s *v_lport,
					int v_clean)
{
	struct unf_xchg_hot_pool_s *hot_pool = NULL;
	struct list_head *xchg_node = NULL;
	struct list_head *next_xchg_node = NULL;
	struct unf_xchg_s *xchg = NULL;
	unsigned long pool_lock_flags = 0;
	unsigned long xchg_lock_flags = 0;
	unsigned int i = 0;

	UNF_CHECK_VALID(0x961, UNF_TRUE, v_lport, return);
	for (i = 0; i < UNF_EXCHG_MGR_NUM; i++) {
		hot_pool = unf_get_hot_pool_by_lport(v_lport, i);
		if (unlikely(!hot_pool)) {
			UNF_TRACE(UNF_EVTLOG_IO_INFO, UNF_LOG_IO_ATT,
				  UNF_MAJOR,
				  "Port(0x%x) Hot Pool is NULL.",
				  v_lport->port_id);

			continue;
		}

		if (v_clean == UNF_FALSE) {
			spin_lock_irqsave(&hot_pool->xchg_hot_pool_lock,
					  pool_lock_flags);

			/* Clearing the SFS_Busy_list Exchange Resource */
			list_for_each_safe(xchg_node, next_xchg_node,
					   &hot_pool->sfs_busylist) {
				xchg = list_entry(xchg_node, struct unf_xchg_s,
						  list_xchg_entry);
				spin_lock_irqsave(&xchg->xchg_state_lock,
						  xchg_lock_flags);
				if (atomic_read(&xchg->ref_cnt) > 0)
					xchg->io_state |= TGT_IO_STATE_ABORT;
				spin_unlock_irqrestore(&xchg->xchg_state_lock,
						       xchg_lock_flags);
			}

			spin_unlock_irqrestore(&hot_pool->xchg_hot_pool_lock,
					       pool_lock_flags);
		} else {
			continue;
		}
	}
}

static void unf_xchg_abort_ini_io_xchg(struct unf_lport_s *v_lport,
				       int v_clean)
{
	/* Clean L_Port/V_Port Link Down I/O: Abort */
	struct unf_xchg_hot_pool_s *hot_pool = NULL;
	struct list_head *xchg_node = NULL;
	struct list_head *next_xchg_node = NULL;
	struct unf_xchg_s *xchg = NULL;
	unsigned long pool_lock_flags = 0;
	unsigned long xchg_lock_flags = 0;
	unsigned int io_state = 0;
	unsigned int i = 0;

	UNF_CHECK_VALID(0x962, UNF_TRUE, (v_lport), return);

	for (i = 0; i < UNF_EXCHG_MGR_NUM; i++) {
		hot_pool = unf_get_hot_pool_by_lport(v_lport, i);
		if (unlikely(!hot_pool)) {
			UNF_TRACE(UNF_EVTLOG_IO_WARN, UNF_LOG_IO_ATT,
				  UNF_WARN,
				  "[warn]Port(0x%x) hot pool is NULL",
				  v_lport->port_id);

			continue;
		}

		if (v_clean == UNF_FALSE) {
			spin_lock_irqsave(&hot_pool->xchg_hot_pool_lock,
					  pool_lock_flags);

			/* 1. Abort INI_Busy_List IO */
			list_for_each_safe(xchg_node, next_xchg_node,
					   &hot_pool->ini_busylist) {
				xchg = list_entry(xchg_node, struct unf_xchg_s,
						  list_xchg_entry);
				spin_lock_irqsave(&xchg->xchg_state_lock,
						  xchg_lock_flags);
				if (atomic_read(&xchg->ref_cnt) > 0)
					xchg->io_state |=
					INI_IO_STATE_DRABORT | io_state;
				spin_unlock_irqrestore(&xchg->xchg_state_lock,
						       xchg_lock_flags);
			}
			spin_unlock_irqrestore(&hot_pool->xchg_hot_pool_lock,
					       pool_lock_flags);
		} else {
			/* Do nothing, just return */
			continue;
		}
	}
}

static void unf_xchg_abort_all_xchg(void *v_lport,
				    unsigned int v_xchg_type,
				    int v_clean)
{
	struct unf_lport_s *lport = NULL;

	UNF_CHECK_VALID(0x964, UNF_TRUE, v_lport, return);
	lport = (struct unf_lport_s *)v_lport;

	switch (v_xchg_type) {
	case UNF_XCHG_TYPE_SFS:
		unf_xchg_abort_all_sfs_xchg(lport, v_clean);
		break;

	/* Clean L_Port/V_Port Link Down I/O: Abort */
	case UNF_XCHG_TYPE_INI:
		unf_xchg_abort_ini_io_xchg(lport, v_clean);
		break;

	default:
		UNF_TRACE(UNF_EVTLOG_IO_WARN, UNF_LOG_IO_ATT, UNF_WARN,
			  "[warn]Port(0x%x) unknown exch type(0x%x)",
			  lport->port_id, v_xchg_type);
		break;
	}
}

static void unf_xchg_abort_ini_send_tm_cmd(void *v_lport,
					   void *v_rport,
					   unsigned long long v_lun_id)
{
	/*
	 * LUN Reset: set UP_ABORT tag, with:
	 * INI_Busy_list, IO_Wait_list,
	 * IO_Delay_list, IO_Delay_transfer_list
	 */
	struct unf_lport_s *lport = NULL;
	struct unf_rport_s *rport = NULL;
	struct unf_xchg_hot_pool_s *hot_pool = NULL;
	struct list_head *node = NULL;
	struct list_head *next_node = NULL;
	struct unf_xchg_s *xchg = NULL;
	unsigned long flags = 0;
	unsigned long xchg_flag = 0;
	unsigned int i = 0;
	unsigned long long raw_lunid = 0;

	UNF_CHECK_VALID(0x981, UNF_TRUE, v_lport, return);
	UNF_CHECK_VALID(0x981, UNF_TRUE, v_rport, return);

	lport = ((struct unf_lport_s *)v_lport)->root_lport;
	UNF_CHECK_VALID(0x982, UNF_TRUE, (lport), return);
	rport = (struct unf_rport_s *)v_rport;

	for (i = 0; i < UNF_EXCHG_MGR_NUM; i++) {
		hot_pool = unf_get_hot_pool_by_lport(lport, i);
		if (unlikely(!hot_pool)) {
			UNF_TRACE(UNF_EVTLOG_IO_ERR, UNF_LOG_IO_ATT, UNF_ERR,
				  "[err]Port(0x%x) hot pool is NULL",
				  lport->port_id);
			continue;
		}

		spin_lock_irqsave(&hot_pool->xchg_hot_pool_lock, flags);

		/* 1. for each exchange from busy list */
		list_for_each_safe(node, next_node,
				   &hot_pool->ini_busylist) {
			xchg = list_entry(node, struct unf_xchg_s,
					  list_xchg_entry);

			raw_lunid = *(unsigned long long *)
				    (xchg->fcp_cmnd.lun) >> 16 &
				    0x000000000000ffff;
			if ((v_lun_id == raw_lunid) &&
			    (rport == xchg->rport)) {
				spin_lock_irqsave(&xchg->xchg_state_lock,
						  xchg_flag);
				xchg->io_state |= INI_IO_STATE_TMF_ABORT;
				spin_unlock_irqrestore(&xchg->xchg_state_lock,
						       xchg_flag);

				UNF_TRACE(UNF_EVTLOG_IO_INFO, UNF_LOG_IO_ATT,
					  UNF_MAJOR,
					  "[info]Exchange(%p) state(0x%x) S_ID(0x%x) D_ID(0x%x) tag(0x%x) abort by TMF CMD",
					  xchg, xchg->io_state, lport->nport_id,
					  rport->nport_id, xchg->hot_pool_tag);
			}
		}
		spin_unlock_irqrestore(&hot_pool->xchg_hot_pool_lock, flags);
	}
}

static void unf_xchg_abort_by_lun(void *v_lport,
				  void *v_rport,
				  unsigned long long v_lun_id,
				  void *v_tm_xchg,
				  int v_abort_all_lun_flag)
{
	/* ABORT: set UP_ABORT tag for target LUN I/O */
	struct unf_xchg_s *tm_xchg = (struct unf_xchg_s *)v_tm_xchg;

	UNF_TRACE(UNF_EVTLOG_IO_INFO, UNF_LOG_IO_ATT, UNF_MAJOR,
		  "[event]Port(0x%x) LUN_ID(0x%llx) TM_EXCH(0x%p) flag(%d)",
		  ((struct unf_lport_s *)v_lport)->port_id,
		  v_lun_id, v_tm_xchg, v_abort_all_lun_flag);

	/* for INI Mode */
	if (!tm_xchg) {
		/*
		 * LUN Reset: set UP_ABORT tag, with:
		 * INI_Busy_list, IO_Wait_list,
		 * IO_Delay_list, IO_Delay_transfer_list
		 */
		unf_xchg_abort_ini_send_tm_cmd(v_lport, v_rport, v_lun_id);

		return;
	}
}

static void unf_xchg_abort_ini_tmf_target_reset(void *v_lport, void *v_rport)
{
	/*
	 * LUN Reset: set UP_ABORT tag, with:
	 * INI_Busy_list, IO_Wait_list,
	 * IO_Delay_list, IO_Delay_transfer_list
	 */
	struct unf_lport_s *lport = NULL;
	struct unf_rport_s *rport = NULL;
	struct unf_xchg_hot_pool_s *hot_pool = NULL;
	struct list_head *node = NULL;
	struct list_head *next_node = NULL;
	struct unf_xchg_s *xchg = NULL;
	unsigned long flags = 0;
	unsigned long xchg_flag = 0;
	unsigned int i = 0;

	UNF_CHECK_VALID(0x981, UNF_TRUE, v_lport, return);
	UNF_CHECK_VALID(0x981, UNF_TRUE, v_rport, return);

	lport = ((struct unf_lport_s *)v_lport)->root_lport;
	UNF_CHECK_VALID(0x982, UNF_TRUE, (lport), return);
	rport = (struct unf_rport_s *)v_rport;

	for (i = 0; i < UNF_EXCHG_MGR_NUM; i++) {
		hot_pool = unf_get_hot_pool_by_lport(lport, i);
		if (unlikely(!hot_pool)) {
			UNF_TRACE(UNF_EVTLOG_IO_ERR, UNF_LOG_IO_ATT, UNF_ERR,
				  "[err]Port(0x%x) hot pool is NULL",
				  lport->port_id);
			continue;
		}

		spin_lock_irqsave(&hot_pool->xchg_hot_pool_lock, flags);

		/* 1. for each exchange from busy_list */
		list_for_each_safe(node, next_node,
				   &hot_pool->ini_busylist) {
			xchg = list_entry(node, struct unf_xchg_s,
					  list_xchg_entry);
			if (rport == xchg->rport) {
				spin_lock_irqsave(&xchg->xchg_state_lock,
						  xchg_flag);
				xchg->io_state |= INI_IO_STATE_TMF_ABORT;
				spin_unlock_irqrestore(&xchg->xchg_state_lock,
						       xchg_flag);

				UNF_TRACE(UNF_EVTLOG_IO_INFO, UNF_LOG_IO_ATT,
					  UNF_MAJOR,
					  "[info]Exchange(%p) state(0x%x) S_ID(0x%x) D_ID(0x%x) tag(0x%x) abort by TMF CMD",
					  xchg, xchg->io_state,
					  lport->nport_id,
					  rport->nport_id, xchg->hot_pool_tag);
			}
		}
		spin_unlock_irqrestore(&hot_pool->xchg_hot_pool_lock, flags);
	}
}

static void unf_xchg_abort_by_session(void *v_lport, void *v_rport)
{
	/*
	 * LUN Reset: set UP_ABORT tag, with:
	 * INI_Busy_list, IO_Wait_list,
	 * IO_Delay_list, IO_Delay_transfer_list
	 */
	UNF_TRACE(UNF_EVTLOG_IO_INFO, UNF_LOG_IO_ATT, UNF_MAJOR,
		  "[event]Port(0x%x) Rport(0x%x) start session reset with TMF",
		  ((struct unf_lport_s *)v_lport)->port_id,
		  ((struct unf_rport_s *)v_rport)->nport_id);

	unf_xchg_abort_ini_tmf_target_reset(v_lport, v_rport);
}

static void unf_ini_busy_io_xchg_abort(void *v_hot_pool, void *v_rport,
				       unsigned int v_sid, unsigned int v_did,
				       unsigned int v_extra_io_state)
{
	/*
	 * for target session: Set (DRV) ABORT
	 * 1. R_Port remove
	 * 2. Send PLOGI_ACC callback
	 * 3. RCVD PLOGI
	 * 4. RCVD LOGO
	 */
	struct unf_xchg_hot_pool_s *hot_pool = NULL;
	struct unf_xchg_s *xchg = NULL;
	struct list_head *xchg_node = NULL;
	struct list_head *next_xchg_node = NULL;
	struct unf_rport_s *rport = NULL;
	unsigned long xchg_lock_flags = 0;

	rport = (struct unf_rport_s *)v_rport;
	hot_pool = (struct unf_xchg_hot_pool_s *)v_hot_pool;

	/* ABORT INI IO: INI_BUSY_LIST */
	list_for_each_safe(xchg_node, next_xchg_node,
			   &hot_pool->ini_busylist) {
		xchg = list_entry(xchg_node, struct unf_xchg_s,
				  list_xchg_entry);

		spin_lock_irqsave(&xchg->xchg_state_lock, xchg_lock_flags);
		if ((v_did == xchg->did) && (v_sid == xchg->sid) &&
		    (rport == xchg->rport) &&
		    (atomic_read(&xchg->ref_cnt) > 0)) {
			xchg->scsi_cmnd_info.result =
					UNF_SCSI_HOST(DID_IMM_RETRY);
			xchg->io_state |= INI_IO_STATE_DRABORT;
			xchg->io_state |= v_extra_io_state;

			UNF_TRACE(UNF_EVTLOG_IO_INFO,
				  UNF_LOG_IO_ATT, UNF_MAJOR,
				  "[info]Abort INI:0x%p, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x, %llu.",
				  xchg,
				  (unsigned int)xchg->hot_pool_tag,
				  (unsigned int)xchg->xchg_type,
				  (unsigned int)xchg->ox_id,
				  (unsigned int)xchg->rx_id,
				  (unsigned int)xchg->sid,
				  (unsigned int)xchg->did,
				  (unsigned int)xchg->io_state,
				  atomic_read(&xchg->ref_cnt),
				  xchg->alloc_jif);
		}
		spin_unlock_irqrestore(&xchg->xchg_state_lock,
				       xchg_lock_flags);
	}
}

static void unf_xchg_mgr_io_xchg_abort(void *v_lport, void *v_rport,
				       unsigned int v_sid, unsigned int v_did,
				       unsigned int v_extra_io_state)
{
	/*
	 * for target session: set ABORT
	 * 1. R_Port remove
	 * 2. Send PLOGI_ACC callback
	 * 3. RCVD PLOGI
	 * 4. RCVD LOGO
	 */
	struct unf_xchg_hot_pool_s *hot_pool = NULL;
	struct unf_lport_s *lport = NULL;
	unsigned long pool_lock_flags = 0;
	unsigned int i = 0;

	UNF_CHECK_VALID(0x983, UNF_TRUE, v_lport, return);
	lport = ((struct unf_lport_s *)v_lport)->root_lport;
	UNF_CHECK_VALID(0x984, UNF_TRUE, lport, return);

	for (i = 0; i < UNF_EXCHG_MGR_NUM; i++) {
		hot_pool = unf_get_hot_pool_by_lport(lport, i);
		if (unlikely(!hot_pool)) {
			UNF_TRACE(UNF_EVTLOG_IO_WARN,
				  UNF_LOG_IO_ATT, UNF_WARN,
				  "[warn]Port(0x%x) hot pool is NULL",
				  lport->port_id);

			continue;
		}

		spin_lock_irqsave(&hot_pool->xchg_hot_pool_lock,
				  pool_lock_flags);

		/* 1. Clear INI (session) IO: INI Mode */
		unf_ini_busy_io_xchg_abort(hot_pool, v_rport, v_sid,
					   v_did, v_extra_io_state);

		spin_unlock_irqrestore(&hot_pool->xchg_hot_pool_lock,
				       pool_lock_flags);
	}
}

static void unf_xchg_mgr_sfs_xchg_abort(void *v_lport, void *v_rport,
					unsigned int v_sid, unsigned int v_did)
{
	struct unf_xchg_hot_pool_s *hot_pool = NULL;
	struct list_head *xchg_node = NULL;
	struct list_head *next_xchg_node = NULL;
	struct unf_xchg_s *xchg = NULL;
	struct unf_lport_s *lport = NULL;
	struct unf_rport_s *rport = NULL;
	unsigned long pool_lock_flags = 0;
	unsigned long xchg_lock_flags = 0;
	unsigned int i = 0;

	UNF_CHECK_VALID(0x991, UNF_TRUE, (v_lport), return);

	lport = ((struct unf_lport_s *)v_lport)->root_lport;
	UNF_CHECK_VALID(0x992, UNF_TRUE, (lport), return);

	for (i = 0; i < UNF_EXCHG_MGR_NUM; i++) {
		hot_pool = unf_get_hot_pool_by_lport(lport, i);
		if (!hot_pool) {
			UNF_TRACE(UNF_EVTLOG_IO_INFO,
				  UNF_LOG_IO_ATT, UNF_MAJOR,
				  "Port(0x%x) Hot Pool is NULL.",
				  lport->port_id);

			continue;
		}

		rport = (struct unf_rport_s *)v_rport;

		spin_lock_irqsave(&hot_pool->xchg_hot_pool_lock,
				  pool_lock_flags);

		/* Clear the SFS exchange of the corresponding connection */
		list_for_each_safe(xchg_node, next_xchg_node,
				   &hot_pool->sfs_busylist) {
			xchg = list_entry(xchg_node, struct unf_xchg_s,
					  list_xchg_entry);

			spin_lock_irqsave(&xchg->xchg_state_lock,
					  xchg_lock_flags);
			if ((v_did == xchg->did) && (v_sid == xchg->sid) &&
			    (rport == xchg->rport) &&
			    (atomic_read(&xchg->ref_cnt) > 0)) {
				xchg->io_state |= TGT_IO_STATE_ABORT;
				UNF_TRACE(UNF_EVTLOG_IO_INFO, UNF_LOG_IO_ATT,
					  UNF_MAJOR,
					  "Abort SFS:0x%p---0x%x----0x%x----0x%x----0x%x----0x%x----0x%x----0x%x----0x%x----%llu.",
					  xchg,
					  (unsigned int)xchg->hot_pool_tag,
					  (unsigned int)xchg->xchg_type,
					  (unsigned int)xchg->ox_id,
					  (unsigned int)xchg->rx_id,
					  (unsigned int)xchg->sid,
					  (unsigned int)xchg->did,
					  (unsigned int)xchg->io_state,
					  atomic_read(&xchg->ref_cnt),
					  xchg->alloc_jif);
			}
			spin_unlock_irqrestore(&xchg->xchg_state_lock,
					       xchg_lock_flags);
		}

		spin_unlock_irqrestore(&hot_pool->xchg_hot_pool_lock,
				       pool_lock_flags);
	}
}

unsigned int unf_init_xchg_mgr_temp(struct unf_lport_s *v_lport)
{
	UNF_CHECK_VALID(0x959, UNF_TRUE, v_lport, return UNF_RETURN_ERROR);

	v_lport->xchg_mgr_temp.pfn_unf_xchg_get_free_and_init =
						unf_get_new_xchg;
	v_lport->xchg_mgr_temp.pfn_unf_xchg_release = unf_free_xchg;
	v_lport->xchg_mgr_temp.pfn_unf_look_up_xchg_by_tag =
						unf_lookup_xchg_by_tag;
	v_lport->xchg_mgr_temp.pfn_unf_look_up_xchg_by_id =
						unf_find_xchg_by_oxid;
	v_lport->xchg_mgr_temp.pfn_unf_xchg_add_timer =
						unf_fc_xchg_add_timer;
	v_lport->xchg_mgr_temp.pfn_unf_xchg_cancel_timer =
						unf_xchg_cancel_timer;
	v_lport->xchg_mgr_temp.pfn_unf_xchg_abort_all_io =
						unf_xchg_abort_all_xchg;
	v_lport->xchg_mgr_temp.pfn_unf_look_up_xchg_by_cmnd_sn =
						unf_lookup_xchg_by_cmnd_sn;
	v_lport->xchg_mgr_temp.pfn_unf_xchg_abort_by_lun =
						unf_xchg_abort_by_lun;
	v_lport->xchg_mgr_temp.pfn_unf_xchg_abort_by_session =
						unf_xchg_abort_by_session;
	v_lport->xchg_mgr_temp.pfn_unf_xchg_mgr_io_xchg_abort =
						unf_xchg_mgr_io_xchg_abort;
	v_lport->xchg_mgr_temp.pfn_unf_xchg_mgr_sfs_xchg_abort =
						unf_xchg_mgr_sfs_xchg_abort;

	return RETURN_OK;
}

void unf_set_hot_pool_wait_state(struct unf_lport_s *v_lport,
				 enum int_e v_wait_state)
{
	struct unf_xchg_hot_pool_s *hot_pool = NULL;
	unsigned long pool_lock_flags = 0;
	unsigned int i = 0;

	UNF_CHECK_VALID(0x965, UNF_TRUE, v_lport, return);

	for (i = 0; i < UNF_EXCHG_MGR_NUM; i++) {
		hot_pool = unf_get_hot_pool_by_lport(v_lport, i);
		if (unlikely(!hot_pool)) {
			UNF_TRACE(UNF_EVTLOG_IO_WARN, UNF_LOG_IO_ATT,
				  UNF_WARN,
				  "[warn]Port(0x%x) hot pool is NULL",
				  v_lport->port_id);
			continue;
		}

		spin_lock_irqsave(&hot_pool->xchg_hot_pool_lock,
				  pool_lock_flags);
		hot_pool->wait_state = v_wait_state;
		spin_unlock_irqrestore(&hot_pool->xchg_hot_pool_lock,
				       pool_lock_flags);
	}
}

unsigned int unf_xchg_ref_inc(struct unf_xchg_s *v_xchg,
			      enum unf_ioflow_id_e v_io_stage)
{
	struct unf_xchg_hot_pool_s *hot_pool = NULL;
	unsigned long flags = 0;
	unsigned int ret = UNF_RETURN_ERROR;

	UNF_CHECK_VALID(0x967, UNF_TRUE, v_xchg, return UNF_RETURN_ERROR);

	if (unlikely(v_xchg->debug_hook == UNF_TRUE)) {
		UNF_TRACE(UNF_EVTLOG_IO_INFO, UNF_LOG_IO_ATT, UNF_MAJOR,
			  "[info]Xchg(0x%p) State(0x%x) SID_DID(0x%x_0x%x) OX_ID_RX_ID(0x%x_0x%x) AllocJiff(%llu) Refcnt(%d) Stage(%s)",
			  v_xchg, v_xchg->io_state, v_xchg->sid,
			  v_xchg->did, v_xchg->ox_id, v_xchg->rx_id,
			  v_xchg->alloc_jif, atomic_read(&v_xchg->ref_cnt),
			  io_stage[v_io_stage].stage);
	}

	hot_pool = v_xchg->hot_pool;
	UNF_CHECK_VALID(0x968, UNF_TRUE, hot_pool, return UNF_RETURN_ERROR);
	UNF_REFERNCE_VAR(v_io_stage);

	/* Exchange -> Hot Pool Tag check */
	if (unlikely((v_xchg->hot_pool_tag >=
		     (hot_pool->slab_total_sum + hot_pool->base)) ||
	    (v_xchg->hot_pool_tag < hot_pool->base))) {
		UNF_TRACE(UNF_EVTLOG_IO_ERR, UNF_LOG_IO_ATT, UNF_ERR,
			  "[err]Xchg(0x%p) S_ID(%xh) D_ID(0x%x) hot_pool_tag(0x%x) is bigger than slab total num(0x%x) base(0x%x)",
			  v_xchg, v_xchg->sid, v_xchg->did,
			  v_xchg->hot_pool_tag,
			  hot_pool->slab_total_sum + hot_pool->base,
			  hot_pool->base);

		return UNF_RETURN_ERROR;
	}

	/* atomic read & inc */
	spin_lock_irqsave(&v_xchg->xchg_state_lock, flags);
	if (unlikely(atomic_read(&v_xchg->ref_cnt) <= 0)) {
		ret = UNF_RETURN_ERROR;
	} else {
		if (unf_get_xchg_by_xchg_tag(hot_pool,
					     v_xchg->hot_pool_tag -
					     hot_pool->base) ==
		    v_xchg) {
			atomic_inc(&v_xchg->ref_cnt);
			ret = RETURN_OK;
		} else {
			ret = UNF_RETURN_ERROR;
		}
	}
	spin_unlock_irqrestore(&v_xchg->xchg_state_lock, flags);

	return ret;
}

void unf_xchg_ref_dec(struct unf_xchg_s *v_xchg,
		      enum unf_ioflow_id_e v_io_stage)
{
	/* Atomic dec ref_cnt & test, free exchange
	 * if necessary (ref_cnt==0)
	 */
	struct unf_xchg_hot_pool_s *hot_pool = NULL;
	void (*pfn_free_xchg)(struct unf_xchg_s *) = NULL;
	unsigned long flags = 0;
	unsigned long xchg_lock_flags = 0;

	UNF_CHECK_VALID(0x969, UNF_TRUE, (v_xchg), return);

	if (v_xchg->debug_hook == UNF_TRUE) {
		UNF_TRACE(UNF_EVTLOG_IO_INFO, UNF_LOG_IO_ATT, UNF_MAJOR,
			  "[info]Xchg(0x%p) State(0x%x) SID_DID(0x%x_0x%x) OXID_RXID(0x%x_0x%x) AllocJiff(%llu) Refcnt(%d) Statge %s",
			  v_xchg, v_xchg->io_state, v_xchg->sid,
			  v_xchg->did, v_xchg->ox_id, v_xchg->rx_id,
			  v_xchg->alloc_jif, atomic_read(&v_xchg->ref_cnt),
			  io_stage[v_io_stage].stage);
	}

	hot_pool = v_xchg->hot_pool;
	UNF_CHECK_VALID(0x970, UNF_TRUE, hot_pool, return);
	UNF_CHECK_VALID(0x970, UNF_TRUE,
			v_xchg->hot_pool_tag >= hot_pool->base, return);
	UNF_REFERNCE_VAR(v_io_stage);

	/*
	 * 1. Atomic dec & test
	 * 2. Free exchange if necessary (ref_cnt == 0)
	 */
	spin_lock_irqsave(&v_xchg->xchg_state_lock, xchg_lock_flags);
	if (atomic_dec_and_test(&v_xchg->ref_cnt)) {
		pfn_free_xchg = v_xchg->pfn_free_xchg;
		spin_unlock_irqrestore(&v_xchg->xchg_state_lock,
				       xchg_lock_flags);
		spin_lock_irqsave(&hot_pool->xchg_hot_pool_lock, flags);
		unf_hot_pool_slab_set(hot_pool,
				      v_xchg->hot_pool_tag - hot_pool->base,
				      NULL);
		/* Delete exchange list entry */
		list_del_init(&v_xchg->list_xchg_entry);
		hot_pool->total_xchges--;
		spin_unlock_irqrestore(&hot_pool->xchg_hot_pool_lock, flags);

		// unf_free_fcp_xchg --->>> unf_done_ini_xchg
		if (pfn_free_xchg)
			pfn_free_xchg(v_xchg);
	} else {
		spin_unlock_irqrestore(&v_xchg->xchg_state_lock,
				       xchg_lock_flags);
	}
}

bool unf_busy_io_completed(struct unf_lport_s *v_lport)
{
	struct unf_xchg_mgr_s *xchg_mgr = NULL;
	unsigned long pool_lock_flags = 0;
	unsigned int i;

	UNF_CHECK_VALID(0x5841, UNF_TRUE, v_lport, return UNF_TRUE);

	for (i = 0; i < UNF_EXCHG_MGR_NUM; i++) {
		xchg_mgr = unf_get_xchg_mgr_by_lport(v_lport, i);
		if (unlikely(!xchg_mgr)) {
			UNF_TRACE(UNF_EVTLOG_IO_WARN, UNF_LOG_IO_ATT, UNF_WARN,
				  "[warn]Port(0x%x) Exchange Manager is NULL",
				  v_lport->port_id);
			continue;
		}

		spin_lock_irqsave(&xchg_mgr->hot_pool->xchg_hot_pool_lock,
				  pool_lock_flags);
		if (!list_empty(&xchg_mgr->hot_pool->ini_busylist)) {
			UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_REG_ATT,
				  UNF_INFO, "[info]Port(0x%x) ini busylist is not empty.",
				  v_lport->port_id);

			spin_unlock_irqrestore(
					&xchg_mgr->hot_pool->xchg_hot_pool_lock,
					pool_lock_flags);
			return UNF_FALSE;
		}
		spin_unlock_irqrestore(
				&xchg_mgr->hot_pool->xchg_hot_pool_lock,
				pool_lock_flags);
	}
	return UNF_TRUE;
}
