// SPDX-License-Identifier: GPL-2.0
/* Huawei Hifc PCI Express Linux driver
 * Copyright(c) 2017 Huawei Technologies Co., Ltd
 *
 */

#include "unf_log.h"
#include "unf_common.h"
#include "unf_disc.h"
#include "unf_event.h"
#include "unf_lport.h"
#include "unf_rport.h"
#include "unf_exchg.h"
#include "unf_service.h"
#include "unf_portman.h"

#define UNF_LIST_RSCN_PAGE_CNT   2560
#define UNF_MAX_PORTS_PRI_LOOP   2
#define UNF_MAX_GS_SEND_NUM      8
#define UNF_OS_REMOVE_CARD_TIMEOUT (60 * 1000)

static void unf_set_disc_state(struct unf_disc_s *v_disc,
			       enum unf_disc_state_e v_en_states)
{
	UNF_CHECK_VALID(0x651, UNF_TRUE, v_disc, return);

	if (v_en_states != v_disc->en_states) {
		/* Reset disc retry count */
		v_disc->retry_count = 0;
	}

	v_disc->en_states = v_en_states;
}

static inline unsigned int unf_get_loop_map(struct unf_lport_s *v_lport,
					    unsigned char v_loop_map[],
					    unsigned int loop_map_size)
{
	struct unf_buf_s buf = { 0 };
	unsigned int ret = UNF_RETURN_ERROR;

	UNF_CHECK_VALID(
		0x652, UNF_TRUE,
		v_lport->low_level_func.port_mgr_op.pfn_ll_port_config_get,
		return UNF_RETURN_ERROR);

	buf.cbuf = v_loop_map;
	buf.buf_len = loop_map_size;

	ret = v_lport->low_level_func.port_mgr_op.pfn_ll_port_config_get(
		v_lport->fc_port,
		UNF_PORT_CFG_GET_LOOP_MAP,
		(void *)&buf);
	return ret;
}

static int unf_discover_private_loop(void *v_arg_in, void *v_arg_out)
{
	struct unf_lport_s *lport = (struct unf_lport_s *)v_arg_in;
	unsigned int ret = UNF_RETURN_ERROR;
	unsigned int i = 0;
	unsigned char loop_id = 0;
	unsigned int alpa_index = 0;
	unsigned char loop_map[UNF_LOOPMAP_COUNT];

	UNF_REFERNCE_VAR(v_arg_out);
	UNF_CHECK_VALID(0x653, UNF_TRUE, lport, return UNF_RETURN_ERROR);
	memset(loop_map, 0x0, UNF_LOOPMAP_COUNT);

	/* Get Port Loop Map */
	ret = unf_get_loop_map(lport, loop_map, UNF_LOOPMAP_COUNT);
	if (ret != RETURN_OK) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT,
			  UNF_WARN,
			  "[warn]Port(0x%x) get loop map failed",
			  lport->port_id);

		return UNF_RETURN_ERROR;
	}

	/* Check Loop Map Ports Count */
	if (loop_map[0] > UNF_MAX_PORTS_PRI_LOOP) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT, UNF_WARN,
			  "[warn]Port(0x%x) has more than %d ports(%u) in private loop",
			  lport->port_id, UNF_MAX_PORTS_PRI_LOOP,
			  loop_map[0]);

		return UNF_RETURN_ERROR;
	}

	/* AL_PA = 0 means Public Loop */
	if ((loop_map[1] == UNF_FL_PORT_LOOP_ADDR) ||
	    (loop_map[2] == UNF_FL_PORT_LOOP_ADDR)) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT, UNF_WARN,
			  "[warn]Port(0x%x) one or more AL_PA is 0x00, indicate it's FL_Port",
			  lport->port_id);

		return UNF_RETURN_ERROR;
	}

	/* Discovery Private Loop Ports */
	for (i = 0; i < loop_map[0]; i++) {
		alpa_index = i + 1;

		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT, UNF_INFO,
			  "[info]Port(0x%x) start to disc(0x%x) with count(0x%x)",
			  lport->port_id, loop_map[alpa_index], i);

		/* Check whether need delay to send PLOGI or not */
		loop_id = loop_map[alpa_index];
		unf_login_with_loop_node(lport, (unsigned int)loop_id);
	}

	return RETURN_OK;
}

static unsigned int unf_disc_start(void *v_lport)
{
	/*
	 * Call by:
	 * 1. Enter Private Loop Login
	 * 2. Analysis RSCN payload
	 * 3. SCR callback
	 **
	 * Doing:
	 * Fabric/Public Loop: Send GID_PT
	 * Private Loop: (delay to) send PLOGI or send LOGO immediately
	 * P2P: do nothing
	 */
	struct unf_lport_s *lport = (struct unf_lport_s *)v_lport;
	struct unf_rport_s *rport = NULL;
	struct unf_disc_s *disc = NULL;
	struct unf_cm_event_report *event = NULL;
	unsigned int ret = RETURN_OK;
	unsigned long flag = 0;
	enum unf_act_topo_e act_topo = UNF_ACT_TOP_UNKNOWN;

	UNF_CHECK_VALID(0x654, UNF_TRUE, v_lport, return UNF_RETURN_ERROR);
	act_topo = lport->en_act_topo;
	disc = &lport->disc;

	UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT, UNF_INFO,
		  "[info]LOGIN: Port(0x%x) with topo(0x%x) begin to discovery",
		  lport->port_id, act_topo);

	if ((act_topo == UNF_ACT_TOP_P2P_FABRIC) ||
	    (act_topo == UNF_ACT_TOP_PUBLIC_LOOP)) {
		/* 1. Fabric or Public Loop Topology: for directory server */
		/* 0xfffffc */
		rport = unf_get_rport_by_nport_id(lport,
						  UNF_FC_FID_DIR_SERV);
		if (!rport) {
			UNF_TRACE(UNF_EVTLOG_DRIVER_INFO,
				  UNF_LOG_LOGIN_ATT, UNF_WARN,
				  "[warn]Port(0x%x) unable to get SNS RPort(0xfffffc)",
				  lport->port_id);

			rport = unf_rport_get_free_and_init(
					lport,
					UNF_PORT_TYPE_FC,
					UNF_FC_FID_DIR_SERV);
			if (!rport)
				return UNF_RETURN_ERROR;
			rport->nport_id = UNF_FC_FID_DIR_SERV;
		}

		spin_lock_irqsave(&disc->rport_busy_pool_lock, flag);
		unf_set_disc_state(disc, UNF_DISC_ST_START);  /* disc start */
		unf_disc_state_ma(lport, UNF_EVENT_DISC_NORMAL_ENTER);
		spin_unlock_irqrestore(&disc->rport_busy_pool_lock, flag);

		/*
		 * NOTE: Send GID_PT
		 * The Name Server shall, when it receives a GID_PT request,
		 * return all Port Identifiers having registered support for
		 * the specified Port Type.
		 * One or more Port Identifiers, having registered as
		 * the specified Port Type, are returned.
		 */
		ret = unf_send_gid_pt(lport, rport);
		if (ret != RETURN_OK)
			unf_disc_error_recovery(lport);
	} else if (act_topo == UNF_ACT_TOP_PRIVATE_LOOP) {
		/* Private Loop: to thread process */
		event = unf_get_one_event_node(lport);
		UNF_CHECK_VALID(0x655, UNF_TRUE, NULL != event,
				return UNF_RETURN_ERROR);

		event->lport = lport;
		event->event_asy_flag = UNF_EVENT_ASYN;
		event->pfn_unf_event_task = unf_discover_private_loop;
		event->para_in = (void *)lport;

		unf_post_one_event_node(lport, event);
	} else {
		/* P2P toplogy mode: Do nothing */
		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT,
			  UNF_MAJOR,
			  "[info]Port(0x%x) with topo(0x%x) need do nothing",
			  lport->port_id, act_topo);
	}

	return ret;
}

static unsigned int unf_disc_stop(void *v_lport)
{
	/* Call by GID_ACC processer */
	struct unf_lport_s *lport = NULL;
	struct unf_lport_s *root_lport = NULL;
	struct unf_rport_s *sns_port = NULL;
	struct unf_disc_rport_s *disc_rport = NULL;
	struct unf_disc_s *disc = NULL;
	struct unf_disc_s *root_disc = NULL;
	struct list_head *node = NULL;
	unsigned long flag = 0;
	unsigned int ret = RETURN_OK;
	unsigned int nport_id = 0;

	UNF_CHECK_VALID(0x656, UNF_TRUE, v_lport, return UNF_RETURN_ERROR);

	lport = (struct unf_lport_s *)v_lport;
	disc = &lport->disc;
	root_lport = (struct unf_lport_s *)lport->root_lport;
	root_disc = &root_lport->disc;

	/* Get R_Port for Directory server */
	/* 0xfffffc */
	sns_port = unf_get_rport_by_nport_id(lport, UNF_FC_FID_DIR_SERV);
	if (!sns_port) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT, UNF_WARN,
			  "[warn]Port(0x%x) find fabric RPort(0xfffffc) failed",
			  lport->port_id);

		return UNF_RETURN_ERROR;
	}

	/* for R_Port from disc pool busy list */
	spin_lock_irqsave(&disc->rport_busy_pool_lock, flag);
	if (list_empty(&disc->disc_rport_mgr.list_disc_rport_busy)) {
		spin_unlock_irqrestore(&disc->rport_busy_pool_lock, flag);

		/* Empty and return directly */
		return RETURN_OK;
	}

	node = (&disc->disc_rport_mgr.list_disc_rport_busy)->next;
	do {
		/* Delete from Disc busy list */
		disc_rport = list_entry(node, struct unf_disc_rport_s,
					entry_rport);
		nport_id = disc_rport->nport_id;
		list_del_init(node);
		spin_unlock_irqrestore(&disc->rport_busy_pool_lock, flag);

		/* Add back to (free) Disc R_Port pool (list) */
		spin_lock_irqsave(&root_disc->rport_busy_pool_lock, flag);
		list_add_tail(node,
			      &root_disc->disc_rport_mgr.list_disc_rports_pool);
		spin_unlock_irqrestore(&root_disc->rport_busy_pool_lock, flag);

		/* Send GNN_ID to Name Server */
		ret = unf_get_and_post_disc_event(lport, sns_port, nport_id,
						  UNF_DISC_GET_NODE_NAME);
		if (ret != RETURN_OK) {
			UNF_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_LOGIN_ATT,
				  UNF_ERR,
				  "[err]Port(0x%x) add discovery event(0x%x) failed Rport(0x%x)",
				  lport->nport_id, UNF_DISC_GET_NODE_NAME,
				  nport_id);

			/* NOTE: go to next stage */
			unf_rcv_gnn_id_rsp_unknown(lport, sns_port,
						   nport_id);
		}

		spin_lock_irqsave(&disc->rport_busy_pool_lock, flag);
		node = (&disc->disc_rport_mgr.list_disc_rport_busy)->next;

	} while (node != &disc->disc_rport_mgr.list_disc_rport_busy);
	spin_unlock_irqrestore(&disc->rport_busy_pool_lock, flag);

	return ret;
}

static void unf_disc_callback(void *v_lport, unsigned int v_result)
{
	/* Do nothing */
	UNF_REFERNCE_VAR(v_lport);
	UNF_REFERNCE_VAR(v_result);
}

/*
 * Function Name       : unf_init_rport_pool
 * Function Description: Init R_Port (free) Pool
 * Input Parameters    : struct unf_lport_s *v_lport
 * Output Parameters   : N/A
 * Return Type         : unsigned int
 */
static unsigned int unf_init_rport_pool(struct unf_lport_s *v_lport)
{
	struct unf_rport_pool_s *rport_pool = NULL;
	struct unf_rport_s *rport = NULL;
	unsigned int ret = RETURN_OK;
	unsigned int i = 0;
	unsigned int bit_map_cnt = 0;
	unsigned long flag = 0;
	unsigned int max_login = 0;

	UNF_CHECK_VALID(0x657, UNF_TRUE, v_lport, return UNF_RETURN_ERROR);

	/* Init RPort Pool info */
	rport_pool = &v_lport->rport_pool;
	max_login = v_lport->low_level_func.lport_cfg_items.max_login;
	rport_pool->rport_pool_completion = NULL;
	rport_pool->rport_pool_count = max_login;
	spin_lock_init(&rport_pool->rport_free_pool_lock);
	INIT_LIST_HEAD(&rport_pool->list_rports_pool);  /* free RPort pool */

	/* 1. Alloc RPort Pool buffer/resource (memory) */
	rport_pool->rport_pool_add =
		vmalloc((size_t)(max_login * sizeof(struct unf_rport_s)));
	if (!rport_pool->rport_pool_add) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_LOGIN_ATT, UNF_ERR,
			  "[err]Port(0x%x) allocate RPort(s) resource failed",
			  v_lport->port_id);

		return UNF_RETURN_ERROR;
	}
	memset(rport_pool->rport_pool_add, 0,
	       (max_login * sizeof(struct unf_rport_s)));

	/* 2. Alloc R_Port Pool bitmap */
	bit_map_cnt = (v_lport->low_level_func.support_max_rport) /
			BITS_PER_LONG + 1;
	rport_pool->pul_rpi_bitmap = vmalloc((size_t)(bit_map_cnt *
					   sizeof(unsigned long)));
	if (!rport_pool->pul_rpi_bitmap) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_LOGIN_ATT, UNF_ERR,
			  "[err]Port(0x%x) allocate RPort Bitmap failed",
			  v_lport->port_id);

		vfree(rport_pool->rport_pool_add);
		rport_pool->rport_pool_add = NULL;
		return UNF_RETURN_ERROR;
	}
	memset(rport_pool->pul_rpi_bitmap, 0,
	       (bit_map_cnt * sizeof(unsigned long)));

	/* 3. Rport resource Management: Add Rports (buffer)
	 * to Rport Pool List
	 */
	rport = (struct unf_rport_s *)(rport_pool->rport_pool_add);
	spin_lock_irqsave(&rport_pool->rport_free_pool_lock, flag);
	for (i = 0; i < rport_pool->rport_pool_count; i++) {
		spin_lock_init(&rport->rport_state_lock);
		list_add_tail(&rport->entry_rport,
			      &rport_pool->list_rports_pool);
		sema_init(&rport->task_sema, 0);
		rport++;
	}
	spin_unlock_irqrestore(&rport_pool->rport_free_pool_lock, flag);

	return ret;
}

static void unf_free_rport_pool(struct unf_lport_s *v_lport)
{
	struct unf_rport_pool_s *rport_pool = NULL;
	int wait = UNF_FALSE;
	unsigned long flag = 0;
	unsigned int remain = 0;
	unsigned long long time_out = 0;
	unsigned int max_login = 0;
	unsigned int i;
	struct unf_rport_s *rport;

	struct completion rport_pool_completion =
		COMPLETION_INITIALIZER(rport_pool_completion);

	UNF_CHECK_VALID(0x671, UNF_TRUE, v_lport, return);
	UNF_REFERNCE_VAR(remain);

	rport_pool = &v_lport->rport_pool;
	max_login = v_lport->low_level_func.lport_cfg_items.max_login;

	spin_lock_irqsave(&rport_pool->rport_free_pool_lock, flag);
	if (max_login != rport_pool->rport_pool_count) {
		rport_pool->rport_pool_completion = &rport_pool_completion;
		remain = max_login - rport_pool->rport_pool_count;
		wait = UNF_TRUE;
	}
	spin_unlock_irqrestore(&rport_pool->rport_free_pool_lock, flag);

	if (wait == UNF_TRUE) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_REG_ATT, UNF_MAJOR,
			  "[info]Port(0x%x) begin to wait for RPort pool completion(%ld), remain(0x%x)",
			  v_lport->port_id, jiffies, remain);

		time_out = wait_for_completion_timeout(
			rport_pool->rport_pool_completion,
			msecs_to_jiffies(UNF_OS_REMOVE_CARD_TIMEOUT));
		if (time_out == 0)
			unf_cmmark_dirty_mem(
				v_lport,
				UNF_LPORT_DIRTY_FLAG_RPORT_POOL_DIRTY);

		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_REG_ATT, UNF_MAJOR,
			  "[info]Port(0x%x) wait for RPort pool completion end(%ld)",
			  v_lport->port_id, jiffies);

		spin_lock_irqsave(&rport_pool->rport_free_pool_lock, flag);
		rport_pool->rport_pool_completion = NULL;
		spin_unlock_irqrestore(&rport_pool->rport_free_pool_lock, flag);
	}

	rport = (struct unf_rport_s *)(rport_pool->rport_pool_add);
	for (i = 0; i < rport_pool->rport_pool_count; i++) {
		if (!rport)
			break;
		rport++;
	}

	if ((v_lport->dirty_flag &
	     UNF_LPORT_DIRTY_FLAG_RPORT_POOL_DIRTY) == 0) {
		vfree(rport_pool->rport_pool_add);
		rport_pool->rport_pool_add = NULL;	  /* R_Port pool */
		vfree(rport_pool->pul_rpi_bitmap);  /* R_Port bitmap */
		rport_pool->pul_rpi_bitmap = NULL;
	}
	UNF_REFERNCE_VAR(remain);
}

static void unf_init_rscn_node(struct unf_port_id_page_s *v_port_id_page)
{
	UNF_CHECK_VALID(0x658, UNF_TRUE, v_port_id_page, return);

	v_port_id_page->uc_addr_format = 0;
	v_port_id_page->uc_event_qualifier = 0;
	v_port_id_page->uc_reserved = 0;
	v_port_id_page->port_id_area = 0;
	v_port_id_page->port_id_domain = 0;
	v_port_id_page->port_id_port = 0;
}

struct unf_port_id_page_s *unf_get_free_rscn_node(void *v_rscn_mg)
{
	/* Call by Save RSCN Port_ID */
	struct unf_rscn_mg_s *rscn_mgr = NULL;
	struct unf_port_id_page_s *port_id_node = NULL;
	struct list_head *list_node = NULL;
	unsigned long flag = 0;

	UNF_CHECK_VALID(0x659, UNF_TRUE, v_rscn_mg, return NULL);
	rscn_mgr = (struct unf_rscn_mg_s *)v_rscn_mg;

	spin_lock_irqsave(&rscn_mgr->rscn_id_list_lock, flag);
	if (list_empty(&rscn_mgr->list_free_rscn_page)) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_EQUIP_ATT,
			  UNF_WARN,
			  "[warn]No RSCN node anymore");

		spin_unlock_irqrestore(&rscn_mgr->rscn_id_list_lock, flag);
		return NULL;
	}

	/* Get from list_free_RSCN_page */
	list_node = (&rscn_mgr->list_free_rscn_page)->next;
	list_del(list_node);
	rscn_mgr->free_rscn_count--;
	port_id_node = list_entry(list_node, struct unf_port_id_page_s,
				  list_node_rscn);
	unf_init_rscn_node(port_id_node);
	spin_unlock_irqrestore(&rscn_mgr->rscn_id_list_lock, flag);

	return port_id_node;
}

static void unf_release_rscn_node(void *v_rscn_mg,
				  void *v_port_id_node)
{
	/* Call by RSCN GID_ACC */
	struct unf_rscn_mg_s *rscn_mgr = NULL;
	struct unf_port_id_page_s *port_id_node = NULL;
	unsigned long flag = 0;

	UNF_CHECK_VALID(0x660, UNF_TRUE, v_rscn_mg, return);
	UNF_CHECK_VALID(0x661, UNF_TRUE, v_port_id_node, return);
	rscn_mgr = (struct unf_rscn_mg_s *)v_rscn_mg;
	port_id_node = (struct unf_port_id_page_s *)v_port_id_node;

	/* Back to list_free_RSCN_page */
	spin_lock_irqsave(&rscn_mgr->rscn_id_list_lock, flag);
	rscn_mgr->free_rscn_count++;
	unf_init_rscn_node(port_id_node);
	list_add_tail(&port_id_node->list_node_rscn,
		      &rscn_mgr->list_free_rscn_page);
	spin_unlock_irqrestore(&rscn_mgr->rscn_id_list_lock, flag);
}

static unsigned int unf_init_rscn_pool(struct unf_lport_s *v_lport)
{
	struct unf_rscn_mg_s *rscn_mgr = NULL;
	struct unf_port_id_page_s *port_id_page = NULL;
	unsigned int ret = RETURN_OK;
	unsigned int i = 0;
	unsigned long flag = 0;

	UNF_CHECK_VALID(0x662, UNF_TRUE, v_lport, return UNF_RETURN_ERROR);
	rscn_mgr = &v_lport->disc.rscn_mgr;

	/* Get RSCN Pool buffer */
	rscn_mgr->rscn_pool_add =
		vmalloc(UNF_LIST_RSCN_PAGE_CNT *
			sizeof(struct unf_port_id_page_s));
	if (!rscn_mgr->rscn_pool_add) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_REG_ATT, UNF_WARN,
			  "[warn]Port(0x%x) allocate RSCN pool failed",
			  v_lport->port_id);

		return UNF_RETURN_ERROR;
	}
	memset(rscn_mgr->rscn_pool_add, 0,
	       sizeof(struct unf_port_id_page_s) * UNF_LIST_RSCN_PAGE_CNT);

	spin_lock_irqsave(&rscn_mgr->rscn_id_list_lock, flag);
	port_id_page = (struct unf_port_id_page_s *)(rscn_mgr->rscn_pool_add);
	for (i = 0; i < UNF_LIST_RSCN_PAGE_CNT; i++) {
		/* Add tail to list_free_RSCN_page */
		list_add_tail(&port_id_page->list_node_rscn,
			      &rscn_mgr->list_free_rscn_page);

		rscn_mgr->free_rscn_count++;
		port_id_page++;
	}
	spin_unlock_irqrestore(&rscn_mgr->rscn_id_list_lock, flag);

	return ret;
}

static void unf_free_rscn_pool(struct unf_lport_s *v_lport)
{
	struct unf_disc_s *disc = NULL;

	UNF_CHECK_VALID(0x663, UNF_TRUE, v_lport, return);

	disc = &v_lport->disc;
	if (disc->rscn_mgr.rscn_pool_add) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT,
			  UNF_INFO,
			  "[info]Port(0x%x) free RSCN pool",
			  v_lport->nport_id);

		vfree(disc->rscn_mgr.rscn_pool_add);
		disc->rscn_mgr.rscn_pool_add = NULL;
	}
}

static unsigned int unf_init_rscn_mgr(struct unf_lport_s *v_lport)
{
	struct unf_rscn_mg_s *rscn_mgr = NULL;
	unsigned int ret = RETURN_OK;

	UNF_CHECK_VALID(0x664, UNF_TRUE, v_lport, return UNF_RETURN_ERROR);
	rscn_mgr = &v_lport->disc.rscn_mgr;

	/* free RSCN page list */
	INIT_LIST_HEAD(&rscn_mgr->list_free_rscn_page);
	/* busy RSCN page list */
	INIT_LIST_HEAD(&rscn_mgr->list_using_rscn_page);
	spin_lock_init(&rscn_mgr->rscn_id_list_lock);
	rscn_mgr->free_rscn_count = 0;
	rscn_mgr->pfn_unf_get_free_rscn_node = unf_get_free_rscn_node;
	rscn_mgr->pfn_unf_release_rscn_node = unf_release_rscn_node;

	ret = unf_init_rscn_pool(v_lport);
	return ret;
}

static void unf_destroy_rscn_mgr(struct unf_lport_s *v_lport)
{
	struct unf_rscn_mg_s *rscn_mgr = NULL;

	UNF_CHECK_VALID(0x665, UNF_TRUE, v_lport, return);
	rscn_mgr = &v_lport->disc.rscn_mgr;

	rscn_mgr->free_rscn_count = 0;
	rscn_mgr->pfn_unf_get_free_rscn_node = NULL;
	rscn_mgr->pfn_unf_release_rscn_node = NULL;

	unf_free_rscn_pool(v_lport);
}

static unsigned int unf_init_disc_rport_pool(struct unf_lport_s *v_lport)
{
	struct unf_disc_rport_mg_s *disc_mgr = NULL;
	struct unf_disc_rport_s *disc_rport = NULL;
	unsigned int i = 0;
	unsigned int max_login = 0;
	unsigned long flag = 0;

	UNF_CHECK_VALID(0x662, UNF_TRUE, v_lport, return UNF_RETURN_ERROR);
	max_login = v_lport->low_level_func.lport_cfg_items.max_login;
	disc_mgr = &v_lport->disc.disc_rport_mgr;

	/* Alloc R_Port Disc Pool buffer (address) */
	disc_mgr->disc_pool_add = vmalloc(max_login *
					   sizeof(struct unf_disc_rport_s));
	if (!disc_mgr->disc_pool_add) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_REG_ATT, UNF_WARN,
			  "[warn]Port(0x%x) allocate disc RPort pool failed",
			  v_lport->port_id);

		return UNF_RETURN_ERROR;
	}
	memset(disc_mgr->disc_pool_add, 0,
	       (max_login * sizeof(struct unf_disc_rport_s)));

	/* Add R_Port to (free) DISC R_Port Pool */
	spin_lock_irqsave(&v_lport->disc.rport_busy_pool_lock, flag);
	disc_rport = (struct unf_disc_rport_s *)(disc_mgr->disc_pool_add);
	for (i = 0; i < max_login; i++) {
		/* Add tail to list_disc_Rport_pool */
		list_add_tail(&disc_rport->entry_rport,
			      &disc_mgr->list_disc_rports_pool);

		disc_rport++;
	}
	spin_unlock_irqrestore(&v_lport->disc.rport_busy_pool_lock, flag);

	return RETURN_OK;
}

static void unf_free_disc_rport_pool(struct unf_lport_s *v_lport)
{
	struct unf_disc_s *disc = NULL;

	UNF_CHECK_VALID(0x663, UNF_TRUE, v_lport, return);

	disc = &v_lport->disc;
	if (disc->disc_rport_mgr.disc_pool_add) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT,
			  UNF_INFO,
			  "[info]Port(0x%x) free disc RPort pool",
			  v_lport->port_id);

		vfree(disc->disc_rport_mgr.disc_pool_add);
		disc->disc_rport_mgr.disc_pool_add = NULL;
	}
}

static int unf_discover_port_info(void *v_arg_in)
{
	struct unf_disc_gs_event_info *gs_info = NULL;
	unsigned int ret = UNF_RETURN_ERROR;
	struct unf_lport_s *lport = NULL;
	struct unf_rport_s *rport = NULL;

	UNF_CHECK_VALID(0x2250, UNF_TRUE, v_arg_in, return UNF_RETURN_ERROR);

	gs_info = (struct unf_disc_gs_event_info *)v_arg_in;
	lport = (struct unf_lport_s *)gs_info->lport;
	rport = (struct unf_rport_s *)gs_info->rport;

	switch (gs_info->entype) {
	case UNF_DISC_GET_PORT_NAME:
		ret = unf_send_gpn_id(lport, rport, gs_info->rport_id);
		if (ret != RETURN_OK) {
			UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT,
				  UNF_WARN,
				  "[warn]Port(0x%x) send GPN_ID failed RPort(0x%x)",
				  lport->nport_id, gs_info->rport_id);
			unf_rcv_gpn_id_rsp_unknown(lport, gs_info->rport_id);
		}
		break;
	case UNF_DISC_GET_FEATURE:
		ret = unf_send_gff_id(lport, rport, gs_info->rport_id);
		if (ret != RETURN_OK) {
			UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT,
				  UNF_WARN,
				  "[warn]Port(0x%x) send GFF_ID failed to get RPort(0x%x)'s feature",
				  lport->port_id, gs_info->rport_id);

			unf_rcv_gff_id_rsp_unknown(lport, gs_info->rport_id);
		}
		break;
	case UNF_DISC_GET_NODE_NAME:
		ret = unf_send_gnn_id(lport, rport, gs_info->rport_id);
		if (ret != RETURN_OK) {
			UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT,
				  UNF_WARN,
				  "[warn]Port(0x%x) GNN_ID send failed with NPort ID(0x%x)",
				  lport->port_id, gs_info->rport_id);

			/* NOTE: Continue to next stage */
			unf_rcv_gnn_id_rsp_unknown(lport, rport,
						   gs_info->rport_id);
		}
		break;
	default:
		UNF_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_NORMAL, UNF_ERR,
			  "[err]Send GS packet type(0x%x) is unknown",
			  gs_info->entype);
	}

	kfree(gs_info);

	return (int)ret;
}

unsigned int unf_get_and_post_disc_event(void *v_lport,
					 void *v_sns_port,
					 unsigned int v_nport_id,
					 enum unf_disc_type_e v_en_type)
{
	struct unf_disc_gs_event_info *gs_info = NULL;
	unsigned long flag = 0;
	struct unf_lport_s *root_lport = NULL;
	struct unf_lport_s *lport = NULL;
	struct unf_disc_manage_info_s *disc_info = NULL;

	UNF_CHECK_VALID(0x654, UNF_TRUE, v_lport, return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(0x654, UNF_TRUE, v_sns_port, return UNF_RETURN_ERROR);

	lport = (struct unf_lport_s *)v_lport;

	if (lport->link_up == UNF_PORT_LINK_DOWN)
		return RETURN_OK;

	root_lport = lport->root_lport;
	disc_info = &root_lport->disc.disc_thread_info;

	if (disc_info->b_thread_exit == UNF_TRUE)
		return RETURN_OK;

	gs_info = kmalloc(sizeof(struct unf_disc_gs_event_info), GFP_ATOMIC);
	if (!gs_info)
		return UNF_RETURN_ERROR;

	gs_info->entype = v_en_type;
	gs_info->lport = v_lport;
	gs_info->rport = v_sns_port;
	gs_info->rport_id = v_nport_id;

	INIT_LIST_HEAD(&gs_info->list_entry);

	spin_lock_irqsave(&disc_info->disc_event_list_lock, flag);
	list_add_tail(&gs_info->list_entry, &disc_info->list_head);
	spin_unlock_irqrestore(&disc_info->disc_event_list_lock, flag);
	wake_up_process(disc_info->data_thread);
	return RETURN_OK;
}

static int unf_disc_event_process(void *v_arg)
{
	struct list_head *node = NULL;
	struct unf_disc_gs_event_info *gs_info = NULL;
	unsigned long flags = 0;
	struct unf_disc_s *disc = (struct unf_disc_s *)v_arg;
	struct unf_disc_manage_info_s *disc_info = &disc->disc_thread_info;

	UNF_REFERNCE_VAR(v_arg);

	UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_REG_ATT,
		  UNF_INFO,
		  "Port(0x%x) enter discovery thread.",
		  disc->lport->port_id);

	while (!kthread_should_stop()) {
		if (disc_info->b_thread_exit == UNF_TRUE)
			break;

		spin_lock_irqsave(&disc_info->disc_event_list_lock, flags);
		if ((list_empty(&disc_info->list_head) == UNF_TRUE) ||
		    (atomic_read(&disc_info->disc_contrl_size) == 0)) {
			spin_unlock_irqrestore(&disc_info->disc_event_list_lock,
					       flags);

			set_current_state(TASK_INTERRUPTIBLE);
			schedule_timeout((long)msecs_to_jiffies(1000));
		} else {
			node = (&disc_info->list_head)->next;
			list_del_init(node);
			gs_info = list_entry(node,
					     struct unf_disc_gs_event_info,
					     list_entry);
			spin_unlock_irqrestore(&disc_info->disc_event_list_lock,
					       flags);
			unf_discover_port_info(gs_info);
		}
	}
	UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_EVENT,
		  UNF_MAJOR,
		  "Port(0x%x) discovery thread over.", disc->lport->port_id);

	return RETURN_OK;
}

void unf_flush_disc_event(void *v_disc, void *v_vport)
{
	struct unf_disc_s *disc = (struct unf_disc_s *)v_disc;
	struct unf_disc_manage_info_s *disc_info = NULL;
	struct list_head *list = NULL;
	struct list_head *list_tmp = NULL;
	struct unf_disc_gs_event_info *gs_info = NULL;
	unsigned long flag = 0;

	UNF_CHECK_VALID(0x2249, UNF_TRUE, v_disc, return);

	disc_info = &disc->disc_thread_info;

	spin_lock_irqsave(&disc_info->disc_event_list_lock, flag);
	list_for_each_safe(list, list_tmp, &disc_info->list_head) {
		gs_info = list_entry(list, struct unf_disc_gs_event_info,
				     list_entry);

		if (!v_vport || gs_info->lport == v_vport) {
			list_del_init(&gs_info->list_entry);
			kfree(gs_info);
		}
	}

	if (!v_vport)
		atomic_set(&disc_info->disc_contrl_size, UNF_MAX_GS_SEND_NUM);

	spin_unlock_irqrestore(&disc_info->disc_event_list_lock, flag);
}

void unf_disc_ctrl_size_inc(void *v_lport, unsigned int v_cmnd)
{
	struct unf_lport_s *lport = NULL;

	UNF_CHECK_VALID(0x2249, UNF_TRUE, v_lport, return);
	lport = (struct unf_lport_s *)v_lport;
	lport = lport->root_lport;
	UNF_CHECK_VALID(0x2249, UNF_TRUE, lport, return);

	if (atomic_read(&lport->disc.disc_thread_info.disc_contrl_size) ==
	    UNF_MAX_GS_SEND_NUM)
		return;

	if (v_cmnd == NS_GPN_ID || v_cmnd == NS_GNN_ID || v_cmnd == NS_GFF_ID)
		atomic_inc(&lport->disc.disc_thread_info.disc_contrl_size);
}

static void unf_destroy_disc_thread(void *v_disc)
{
	struct unf_disc_manage_info_s *disc_info = NULL;
	struct unf_disc_s *disc = (struct unf_disc_s *)v_disc;

	UNF_CHECK_VALID(0x2249, UNF_TRUE, disc, return);

	disc_info = &disc->disc_thread_info;

	disc_info->b_thread_exit = UNF_TRUE;
	unf_flush_disc_event(disc, NULL);

	wake_up_process(disc_info->data_thread);
	kthread_stop(disc_info->data_thread);
	disc_info->data_thread = NULL;

	UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_REG_ATT, UNF_MAJOR,
		  "Port(0x%x) destroy discovery thread succeed.",
		  disc->lport->port_id);
}

static unsigned int unf_create_disc_thread(void *v_disc)
{
	struct unf_disc_manage_info_s *disc_info = NULL;
	struct unf_disc_s *disc = (struct unf_disc_s *)v_disc;

	UNF_CHECK_VALID(0x2250, UNF_TRUE, disc, return UNF_RETURN_ERROR);

	/* If the thread cannot be found, apply for a new thread. */
	disc_info = &disc->disc_thread_info;

	memset(disc_info, 0, sizeof(struct unf_disc_manage_info_s));

	INIT_LIST_HEAD(&disc_info->list_head);
	spin_lock_init(&disc_info->disc_event_list_lock);
	atomic_set(&disc_info->disc_contrl_size, UNF_MAX_GS_SEND_NUM);

	disc_info->b_thread_exit = UNF_FALSE;
	disc_info->data_thread =
		kthread_create(unf_disc_event_process, disc,
			       "%x_DiscT", disc->lport->port_id);

	if (IS_ERR(disc_info->data_thread) || !disc_info->data_thread) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_ERR, UNF_LOG_REG_ATT, UNF_ERR,
			  "Port(0x%x) creat discovery thread(0x%p) unsuccessful.",
			  disc->lport->port_id, disc_info->data_thread);

		return UNF_RETURN_ERROR;
	}

	wake_up_process(disc_info->data_thread);

	UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_REG_ATT, UNF_INFO,
		  "Port(0x%x) creat discovery thread succeed.",
		  disc->lport->port_id);

	return RETURN_OK;
}

static void unf_disc_ref_cnt_dec(struct unf_disc_s *v_disc)
{
	unsigned long flags = 0;

	UNF_CHECK_VALID(0x669, UNF_TRUE, v_disc, return);

	spin_lock_irqsave(&v_disc->rport_busy_pool_lock, flags);
	if (atomic_dec_and_test(&v_disc->disc_ref_cnt)) {
		if (v_disc->disc_completion)
			complete(v_disc->disc_completion);
	}
	spin_unlock_irqrestore(&v_disc->rport_busy_pool_lock, flags);
}

static void unf_lport_disc_timeout(struct work_struct *v_work)
{
	struct unf_lport_s *lport = NULL;
	struct unf_rport_s *rport = NULL;
	struct unf_disc_s *disc = NULL;
	enum unf_disc_state_e en_state = UNF_DISC_ST_END;
	unsigned long flag = 0;

	UNF_CHECK_VALID(0x675, UNF_TRUE, v_work, return);

	disc = container_of(v_work, struct unf_disc_s, disc_work.work);
	if (!disc) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT, UNF_WARN,
			  "[warn]Get discover pointer failed");

		return;
	}

	lport = disc->lport;
	if (!lport) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT, UNF_WARN,
			  "[warn]Find Port by discovery work failed");

		unf_disc_ref_cnt_dec(disc);
		return;
	}

	spin_lock_irqsave(&disc->rport_busy_pool_lock, flag);
	en_state = disc->en_states;
	spin_unlock_irqrestore(&disc->rport_busy_pool_lock, flag);

	/* 0xfffffc */
	rport = unf_get_rport_by_nport_id(lport, UNF_FC_FID_DIR_SERV);
	if (!rport) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT, UNF_WARN,
			  "[warn]Port(0x%x) find fabric RPort failed",
			  lport->port_id);

		unf_disc_ref_cnt_dec(disc);
		return;
	}

	switch (en_state) {
	case UNF_DISC_ST_START:
		break;

	case UNF_DISC_ST_GIDPT_WAIT:
		(void)unf_send_gid_pt(lport, rport);
		break;

	case UNF_DISC_ST_GIDFT_WAIT:
		(void)unf_send_gid_ft(lport, rport);
		break;

	case UNF_DISC_ST_END:
		break;

	default:
		break;
	}

	unf_disc_ref_cnt_dec(disc);
}

unsigned int unf_init_disc_mgr(struct unf_lport_s *v_lport)
{
	struct unf_disc_s *disc = NULL;
	unsigned int ret = RETURN_OK;

	UNF_CHECK_VALID(0x666, UNF_TRUE, v_lport, return UNF_RETURN_ERROR);

	disc = &v_lport->disc;
	disc->max_retry_count = UNF_DISC_RETRY_TIMES;
	disc->retry_count = 0;
	disc->disc_flag = UNF_DISC_NONE;
	INIT_LIST_HEAD(&disc->list_busy_rports); /* busy RPort pool list */
	/* delete RPort pool list */
	INIT_LIST_HEAD(&disc->list_delete_rports);
	/* destroy RPort pool list */
	INIT_LIST_HEAD(&disc->list_destroy_rports);
	spin_lock_init(&disc->rport_busy_pool_lock);

	disc->disc_rport_mgr.disc_pool_add = NULL;
	/* free disc RPort pool */
	INIT_LIST_HEAD(&disc->disc_rport_mgr.list_disc_rports_pool);
	/* busy disc RPort pool */
	INIT_LIST_HEAD(&disc->disc_rport_mgr.list_disc_rport_busy);

	disc->disc_completion = NULL;
	disc->lport = v_lport;
	INIT_DELAYED_WORK(&disc->disc_work, unf_lport_disc_timeout);
	disc->unf_disc_temp.pfn_unf_disc_start = unf_disc_start;
	disc->unf_disc_temp.pfn_unf_disc_stop = unf_disc_stop;
	disc->unf_disc_temp.pfn_unf_disc_callback = unf_disc_callback;
	atomic_set(&disc->disc_ref_cnt, 0);

	/* Init RSCN Manager */
	ret = unf_init_rscn_mgr(v_lport);
	if (ret != RETURN_OK)
		return UNF_RETURN_ERROR;

	if (v_lport != v_lport->root_lport)
		return ret;

	ret = unf_create_disc_thread(disc);
	if (ret != RETURN_OK) {
		unf_destroy_rscn_mgr(v_lport);

		return UNF_RETURN_ERROR;
	}

	/* Init R_Port free Pool */
	ret = unf_init_rport_pool(v_lport);
	if (ret != RETURN_OK) {
		unf_destroy_disc_thread(disc);
		unf_destroy_rscn_mgr(v_lport);

		return UNF_RETURN_ERROR;
	}

	/* Init R_Port free disc Pool */
	ret = unf_init_disc_rport_pool(v_lport);
	if (ret != RETURN_OK) {
		unf_destroy_disc_thread(disc);
		unf_free_rport_pool(v_lport);
		unf_destroy_rscn_mgr(v_lport);

		return UNF_RETURN_ERROR;
	}

	return ret;
}

static void unf_wait_disc_complete(struct unf_lport_s *v_lport)
{
	struct unf_disc_s *disc = NULL;
	int wait = UNF_FALSE;
	unsigned long flag = 0;
	unsigned int ret = UNF_RETURN_ERROR;
	unsigned long long time_out = 0;

	struct completion disc_completion =
		COMPLETION_INITIALIZER(disc_completion);

	disc = &v_lport->disc;

	UNF_DELAYED_WORK_SYNC(ret, v_lport->port_id, &disc->disc_work,
			      "Disc_work");
	if (ret == RETURN_OK)
		unf_disc_ref_cnt_dec(disc);

	spin_lock_irqsave(&disc->rport_busy_pool_lock, flag);
	if (atomic_read(&disc->disc_ref_cnt) != 0) {
		disc->disc_completion = &disc_completion;
		wait = UNF_TRUE;
	}
	spin_unlock_irqrestore(&disc->rport_busy_pool_lock, flag);

	if (wait == UNF_TRUE) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_REG_ATT, UNF_MAJOR,
			  "[info]Port(0x%x) begin to wait for discover completion(0x%lx)",
			  v_lport->port_id, jiffies);

		time_out = wait_for_completion_timeout(
			disc->disc_completion,
			msecs_to_jiffies(UNF_OS_REMOVE_CARD_TIMEOUT));
		if (time_out == 0)
			unf_cmmark_dirty_mem(v_lport,
					     UNF_LPORT_DIRTY_FLAG_DISC_DIRTY);

		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_REG_ATT, UNF_MAJOR,
			  "[info]Port(0x%x) wait for discover completion end(0x%lx)",
			  v_lport->port_id, jiffies);

		spin_lock_irqsave(&disc->rport_busy_pool_lock, flag);
		disc->disc_completion = NULL;
		spin_unlock_irqrestore(&disc->rport_busy_pool_lock, flag);
	}
}

void unf_disc_mgr_destroy(void *v_lport)
{
	struct unf_disc_s *disc = NULL;
	struct unf_lport_s *lport = NULL;

	UNF_CHECK_VALID(0x672, UNF_TRUE, v_lport, return);
	lport = (struct unf_lport_s *)v_lport;

	disc = &lport->disc;
	disc->retry_count = 0;
	disc->unf_disc_temp.pfn_unf_disc_start = NULL;
	disc->unf_disc_temp.pfn_unf_disc_stop = NULL;
	disc->unf_disc_temp.pfn_unf_disc_callback = NULL;

	unf_free_disc_rport_pool(lport);
	unf_destroy_rscn_mgr(lport);
	unf_wait_disc_complete(lport);

	if (lport != lport->root_lport)
		return;

	unf_destroy_disc_thread(disc);
	unf_free_rport_pool(lport);
	lport->destroy_step = UNF_LPORT_DESTROY_STEP_6_DESTROY_DISC_MGR;
}

void unf_disc_error_recovery(void *v_lport)
{
	struct unf_rport_s *rport = NULL;
	struct unf_disc_s *disc = NULL;
	unsigned long delay = 0;
	unsigned long flag = 0;
	unsigned int ret = UNF_RETURN_ERROR;
	struct unf_lport_s *lport = NULL;

	UNF_CHECK_VALID(0x673, UNF_TRUE, v_lport, return);

	lport = (struct unf_lport_s *)v_lport;
	disc = &lport->disc;

	rport = unf_get_rport_by_nport_id(lport, UNF_FC_FID_DIR_SERV);
	if (!rport) {
		UNF_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_LOGIN_ATT, UNF_WARN,
			  "[warn]Port(0x%x) find RPort failed",
			  lport->port_id);
		return;
	}

	spin_lock_irqsave(&disc->rport_busy_pool_lock, flag);

	/* Delay work is pending */
	if (delayed_work_pending(&disc->disc_work)) {
		spin_unlock_irqrestore(&disc->rport_busy_pool_lock, flag);

		UNF_TRACE(UNF_EVTLOG_DRIVER_INFO, UNF_LOG_LOGIN_ATT, UNF_MAJOR,
			  "[info]Port(0x%x) disc_work is running and do nothing",
			  lport->port_id);
		return;
	}

	/* Continue to retry */
	if (disc->retry_count < disc->max_retry_count) {
		disc->retry_count++;
		delay = (unsigned long)lport->ed_tov;

		if (queue_delayed_work(unf_work_queue, &disc->disc_work,
				       (unsigned long)msecs_to_jiffies(
				       (unsigned int)delay))) {
			atomic_inc(&disc->disc_ref_cnt);
		}
		spin_unlock_irqrestore(&disc->rport_busy_pool_lock, flag);
	} else {
		/* Go to next stage */
		if (disc->en_states == UNF_DISC_ST_GIDPT_WAIT) {
			/* GID_PT_WAIT --->>> Send GID_FT */
			unf_disc_state_ma(lport, UNF_EVENT_DISC_RETRY_TIMEOUT);
			spin_unlock_irqrestore(&disc->rport_busy_pool_lock,
					       flag);

			while ((ret != RETURN_OK) &&
			       (disc->retry_count < disc->max_retry_count)) {
				ret = unf_send_gid_ft(lport, rport);
				disc->retry_count++;
			}
		} else if (disc->en_states == UNF_DISC_ST_GIDFT_WAIT) {
			/* GID_FT_WAIT --->>> Send LOGO */
			unf_disc_state_ma(lport, UNF_EVENT_DISC_RETRY_TIMEOUT);
			spin_unlock_irqrestore(&disc->rport_busy_pool_lock,
					       flag);
		} else {
			spin_unlock_irqrestore(&disc->rport_busy_pool_lock,
					       flag);
		}
	}
}

enum unf_disc_state_e unf_disc_stat_start(enum unf_disc_state_e v_old_state,
					  enum unf_disc_event_e v_en_event)
{
	enum unf_disc_state_e en_next_state = UNF_DISC_ST_END;

	if (v_en_event == UNF_EVENT_DISC_NORMAL_ENTER)
		en_next_state = UNF_DISC_ST_GIDPT_WAIT;
	else
		en_next_state = v_old_state;

	return en_next_state;
}

enum unf_disc_state_e unf_disc_stat_gid_pt_wait(
					enum unf_disc_state_e v_old_state,
					enum unf_disc_event_e v_en_event)
{
	enum unf_disc_state_e en_next_state = UNF_DISC_ST_END;

	switch (v_en_event) {
	case UNF_EVENT_DISC_FAILED:
		en_next_state = UNF_DISC_ST_GIDPT_WAIT;
		break;

	case UNF_EVENT_DISC_RETRY_TIMEOUT:
		en_next_state = UNF_DISC_ST_GIDFT_WAIT;
		break;

	case UNF_EVENT_DISC_SUCCESS:
		en_next_state = UNF_DISC_ST_END;
		break;

	case UNF_EVENT_DISC_LINKDOWN:
		en_next_state = UNF_DISC_ST_START;
		break;

	default:
		en_next_state = v_old_state;
		break;
	}

	return en_next_state;
}

enum unf_disc_state_e unf_disc_stat_gid_ft_wait(
					enum unf_disc_state_e v_old_state,
					enum unf_disc_event_e v_en_event)
{
	enum unf_disc_state_e en_next_state = UNF_DISC_ST_END;

	switch (v_en_event) {
	case UNF_EVENT_DISC_FAILED:
		en_next_state = UNF_DISC_ST_GIDFT_WAIT;
		break;

	case UNF_EVENT_DISC_RETRY_TIMEOUT:
		en_next_state = UNF_DISC_ST_END;
		break;

	case UNF_EVENT_DISC_SUCCESS:
		en_next_state = UNF_DISC_ST_END;
		break;

	case UNF_EVENT_DISC_LINKDOWN:
		en_next_state = UNF_DISC_ST_START;
		break;

	default:
		en_next_state = v_old_state;
		break;
	}

	return en_next_state;
}

enum unf_disc_state_e unf_disc_stat_end(enum unf_disc_state_e v_old_state,
					enum unf_disc_event_e v_en_event)
{
	enum unf_disc_state_e en_next_state = UNF_DISC_ST_END;

	if (v_en_event == UNF_EVENT_DISC_LINKDOWN)
		en_next_state = UNF_DISC_ST_START;
	else
		en_next_state = v_old_state;

	return en_next_state;
}

void unf_disc_state_ma(struct unf_lport_s *v_lport,
		       enum unf_disc_event_e v_en_event)
{
	struct unf_disc_s *disc = NULL;
	enum unf_disc_state_e en_old_state = UNF_DISC_ST_START;
	enum unf_disc_state_e en_next_state = UNF_DISC_ST_START;

	UNF_CHECK_VALID(0x674, UNF_TRUE, v_lport, return);

	disc = &v_lport->disc;
	en_old_state = disc->en_states;

	switch (disc->en_states) {
	case UNF_DISC_ST_START:
		en_next_state = unf_disc_stat_start(en_old_state, v_en_event);
		break;

	case UNF_DISC_ST_GIDPT_WAIT:
		en_next_state = unf_disc_stat_gid_pt_wait(en_old_state,
							  v_en_event);
		break;

	case UNF_DISC_ST_GIDFT_WAIT:
		en_next_state = unf_disc_stat_gid_ft_wait(en_old_state,
							  v_en_event);
		break;

	case UNF_DISC_ST_END:
		en_next_state = unf_disc_stat_end(en_old_state, v_en_event);
		break;

	default:
		en_next_state = en_old_state;
		break;
	}

	unf_set_disc_state(disc, en_next_state);
}
