/* SPDX-License-Identifier: GPL-2.0 */
/* Huawei Hifc PCI Express Linux driver
 * Copyright(c) 2017 Huawei Technologies Co., Ltd
 *
 */
#ifndef __UNF_DISC_H__
#define __UNF_DISC_H__

#define UNF_DISC_RETRY_TIMES 3
#define UNF_DISC_NONE        0
#define UNF_DISC_FABRIC      1
#define UNF_DISC_LOOP        2

enum unf_disc_state_e {
	UNF_DISC_ST_START = 0x3000,
	UNF_DISC_ST_GIDPT_WAIT,
	UNF_DISC_ST_GIDFT_WAIT,
	UNF_DISC_ST_END
};

enum unf_disc_event_e {
	UNF_EVENT_DISC_NORMAL_ENTER = 0x8000,
	UNF_EVENT_DISC_FAILED = 0x8001,
	UNF_EVENT_DISC_SUCCESS = 0x8002,
	UNF_EVENT_DISC_RETRY_TIMEOUT = 0x8003,
	UNF_EVENT_DISC_LINKDOWN = 0x8004
};

enum unf_disc_type_e {
	UNF_DISC_GET_PORT_NAME = 0,
	UNF_DISC_GET_NODE_NAME,
	UNF_DISC_GET_FEATURE
};

struct unf_disc_gs_event_info {
	void *lport;
	void *rport;
	unsigned int rport_id;
	enum unf_disc_type_e entype;
	struct list_head list_entry;
};

unsigned int unf_get_and_post_disc_event(void *v_lport,
					 void *v_sns_port,
					 unsigned int v_nport_id,
					 enum unf_disc_type_e v_en_type);

void unf_flush_disc_event(void *v_disc, void *v_vport);
void unf_disc_error_recovery(void *v_lport);
void unf_disc_mgr_destroy(void *v_lport);
void unf_disc_ctrl_size_inc(void *v_lport, unsigned int v_cmnd);

#endif
