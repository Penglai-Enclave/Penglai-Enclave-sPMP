/* SPDX-License-Identifier: GPL-2.0 */
/* Huawei Hifc PCI Express Linux driver
 * Copyright(c) 2017 Huawei Technologies Co., Ltd
 *
 */

#ifndef __HIFC_HBA_H__
#define __HIFC_HBA_H__

#include "unf_common.h"
#include "hifc_queue.h"
#include "hifc_api_cmd.h"
#include "hifc_mgmt.h"

#define HIFC_PCI_VENDOR_ID_MASK (0xffff)

#define HIFC_LOWLEVEL_DEFAULT_LOOP_BB_CREDIT 8
#define HIFC_LOWLEVEL_DEFAULT_32G_BB_CREDIT  255
#define HIFC_LOWLEVEL_DEFAULT_16G_BB_CREDIT  255
#define HIFC_LOWLEVEL_DEFAULT_842G_BB_CREDIT 255
#define HIFC_LOWLEVEL_DEFAULT_BB_SCN         0

#define HIFC_LOWLEVEL_DEFAULT_32G_ESCH_VALUE  28081
#define HIFC_LOWLEVEL_DEFAULT_16G_ESCH_VALUE  14100
#define HIFC_LOWLEVEL_DEFAULT_842G_ESCH_VALUE 7000
#define HIFC_LOWLEVEL_DEFAULT_ESCH_BUS_SIZE   0x2000

#define HIFC_SMARTIO_WORK_MODE_FC    0x1
#define UNF_FUN_ID_MASK              0x07
#define UNF_HIFC_FC                  0x01
#define UNF_HIFC_MAXNPIV_NUM         64
#define HIFC_MAX_COS_NUM             8
#define HIFC_PCI_VENDOR_ID_HUAWEI    0x19e5
#define HIFC_SCQ_CNTX_SIZE           32
#define HIFC_SRQ_CNTX_SIZE           64
#define HIFC_PORT_INIT_TIME_SEC_MAX  1

#define HIFC_PORT_NAME_LABEL         "hifc"
#define HIFC_PORT_NAME_STR_LEN       16
#define HIFC_MAX_PROBE_PORT_NUM      64
#define HIFC_PORT_NUM_PER_TABLE      64
#define HIFC_MAX_CARD_NUM            32
#define HIFC_HBA_PORT_MAX_NUM        HIFC_MAX_PROBE_PORT_NUM
/* Heart Lost Flag */
#define HIFC_EVENT_HEART_LOST        0

#define HIFC_GET_HBA_PORT_ID(__hba) ((__hba)->port_index)
#define HIFC_HBA_NOT_PRESENT(__hba) ((__hba)->dev_present == UNF_FALSE)

struct hifc_port_cfg_s {
	unsigned int port_id;    /* Port ID */
	unsigned int port_mode;  /* Port mode:INI(0x20) TGT(0x10) BOTH(0x30) */
	unsigned int port_topology;  /* Port topo:0x3:loop,0xc:p2p,0xf:auto */
	unsigned int port_alpa;       /* Port ALPA */
	unsigned int max_queue_depth;/* Max Queue depth Registration to SCSI */
	unsigned int sest_num;        /* IO burst num:512-4096 */
	unsigned int max_login;       /* Max Login Session.  */
	unsigned int node_name_hi;     /* nodename high 32 bits */
	unsigned int node_name_lo;     /* nodename low 32 bits */
	unsigned int port_name_hi;     /* portname high 32 bits */
	unsigned int port_name_lo;     /* portname low 32 bits */
	/* Port speed 0:auto 4:4Gbps 8:8Gbps 16:16Gbps */
	unsigned int port_speed;
	unsigned int interrupt_delay; /* Delay times(ms) in interrupt */
	unsigned int tape_support;    /* tape support */
};

#define HIFC_VER_INFO_SIZE 128
struct hifc_drv_version_s {
	char ver[HIFC_VER_INFO_SIZE];
};

struct hifc_card_info_s {
	unsigned int card_num : 8;
	unsigned int func_num : 8;
	unsigned int base_func : 8;
	/*
	 * Card type:UNF_FC_SERVER_BOARD_32_G(6) 32G mode,
	 * UNF_FC_SERVER_BOARD_16_G(7)16G mode
	 */
	unsigned int card_type : 8;
};

struct hifc_card_num_manage_s {
	int is_removing;
	unsigned int port_count;
	unsigned long long card_number;
};

struct hifc_led_state_s {
	unsigned char green_speed_led;
	unsigned char yellow_speed_led;
	unsigned char ac_led;
	unsigned char reserved;
};

enum hifc_queue_set_stage_e {
	HIFC_QUEUE_SET_STAGE_INIT = 0,
	HIFC_QUEUE_SET_STAGE_SCANNING,
	HIFC_QUEUE_SET_STAGE_FLUSHING,
	HIFC_QUEUE_SET_STAGE_FLUSHDONE,
	HIFC_QUEUE_SET_STAGE_BUTT
};

struct hifc_srq_delay_info_s {
	unsigned char srq_delay_flag; /* Check whether need to delay */
	unsigned char root_rq_rcvd_flag;
	unsigned short rsd;
	spinlock_t srq_lock;
	struct unf_frame_pkg_s pkg;
	struct delayed_work del_work;
};

struct hifc_fw_ver_detail_s {
	unsigned char ucode_ver[HIFC_VER_LEN];
	unsigned char ucode_compile_time[HIFC_COMPILE_TIME_LEN];
	unsigned char up_ver[HIFC_VER_LEN];
	unsigned char up_compile_time[HIFC_COMPILE_TIME_LEN];
	unsigned char boot_ver[HIFC_VER_LEN];
	unsigned char boot_compile_time[HIFC_COMPILE_TIME_LEN];
};

/* get wwpn and wwnn */
struct hifc_chip_info_s {
	unsigned char work_mode;
	unsigned char tape_support;
	unsigned long long wwpn;
	unsigned long long wwnn;
};

struct hifc_hba_s {
	struct pci_dev *pci_dev;
	void *hw_dev_handle;
	struct fc_service_cap fc_service_cap;
	struct hifc_scq_info_s scq_info[HIFC_TOTAL_SCQ_NUM];
	struct hifc_srq_info_s els_srq_info;
	/* PCI IO Memory */
	void __iomem *bar0;
	unsigned int bar0_len;

	struct hifc_root_info_s root_info;
	struct hifc_parent_queue_mgr_s *parent_queue_mgr;

	/* Link list Sq WqePage Pool */
	struct hifc_sq_wqe_page_pool_s sq_wpg_pool;

	enum hifc_queue_set_stage_e q_set_stage;
	unsigned int next_clearing_sq;
	unsigned int default_sq_id;
	/* Port parameters, Obtained through firmware */
	unsigned short q_s_max_count;
	unsigned char port_type;  /* FC  Port */
	unsigned char port_index; /* Phy Port */
	unsigned int default_scqn;

	unsigned char chip_type; /* chiptype:Smart or fc */
	unsigned char work_mode;
	struct hifc_card_info_s card_info;
	char port_name[HIFC_PORT_NAME_STR_LEN];
	unsigned int probe_index;

	unsigned short exit_base;
	unsigned short exit_count;
	unsigned short image_count;
	unsigned char vpid_start;
	unsigned char vpid_end;

	spinlock_t flush_state_lock;
	int in_flushing;

	struct hifc_port_cfg_s port_cfg; /* Obtained through Config */

	void *lport; /* Used in UNF level */

	unsigned char sys_node_name[UNF_WWN_LEN];
	unsigned char sys_port_name[UNF_WWN_LEN];

	struct completion hba_init_complete;
	struct completion mbox_complete;

	unsigned short removing;
	int sfp_on;
	int dev_present;
	int heart_status;
	spinlock_t hba_lock;
	unsigned int port_topo_cfg;
	unsigned int port_bbscn_cfg;
	unsigned int port_loop_role;
	unsigned int port_speed_cfg;
	unsigned int max_support_speed;

	unsigned char remote_rttov_tag;
	unsigned char remote_edtov_tag;
	unsigned short compared_bbscn;
	unsigned short remote_bbcredit;
	unsigned int compared_edtov_val;
	unsigned int compared_ratov_val;
	enum unf_act_topo_e active_topo;
	unsigned int active_port_speed;
	unsigned int active_rx_bb_credit;
	unsigned int active_bb_scn;
	unsigned int phy_link;
	unsigned int fcp_conf_cfg;
	/* loop */
	unsigned char active_al_pa;
	unsigned char loop_map_valid;
	unsigned char loop_map[UNF_LOOPMAP_COUNT];

	unsigned int cos_bit_map;
	atomic_t cos_rport_cnt[HIFC_MAX_COS_NUM];
	struct hifc_led_state_s led_states;
	unsigned int fec_status;
	struct workqueue_struct *work_queue;
	unsigned long long reset_time;
	struct hifc_srq_delay_info_s delay_info;
};

enum drv_port_entity_type_e {
	DRV_PORT_ENTITY_TYPE_PHYSICAL = 0,
	DRV_PORT_ENTITY_TYPE_VIRTUAL = 1,
	DRV_PORT_ENTITY_TYPE_BUTT
};

extern struct hifc_hba_s *hifc_hba[HIFC_HBA_PORT_MAX_NUM];
extern spinlock_t probe_spin_lock;
extern unsigned long probe_bit_map[HIFC_MAX_PROBE_PORT_NUM /
					HIFC_PORT_NUM_PER_TABLE];

unsigned int hifc_port_reset(struct hifc_hba_s *v_hba);
void hifc_flush_scq_ctx(struct hifc_hba_s *v_hba);
void hifc_set_hba_flush_state(struct hifc_hba_s *v_hba, int in_flush);
void hifc_get_total_probed_num(unsigned int *v_probe_cnt);

#endif
