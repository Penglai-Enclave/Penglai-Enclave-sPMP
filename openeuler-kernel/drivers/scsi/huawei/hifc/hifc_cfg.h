/* SPDX-License-Identifier: GPL-2.0 */
/* Huawei Hifc PCI Express Linux driver
 * Copyright(c) 2017 Huawei Technologies Co., Ltd
 *
 */

#ifndef __CFG_MGT_H__
#define __CFG_MGT_H__

enum {
	CFG_FREE = 0,
	CFG_BUSY = 1
};

/* FC */
#define FC_PCTX_SZ          256
#define FC_CCTX_SZ          256
#define FC_SQE_SZ           128
#define FC_SCQC_SZ          64
#define FC_SCQE_SZ          64
#define FC_SRQC_SZ          64
#define FC_SRQE_SZ          32

/* device capability */
struct service_cap {
	/* Host global resources */
	u16 host_total_function;
	u8 host_oq_id_mask_val;

	/* DO NOT get interrupt_type from firmware */
	enum intr_type interrupt_type;
	u8 intr_chip_en;

	u8 port_id;     /* PF/VF's physical port */
	u8 force_up;

	u8 timer_en;    /* 0:disable, 1:enable */

	u16 max_sqs;
	u16 max_rqs;

	/* For test */
	bool test_xid_alloc_mode;
	bool test_gpa_check_enable;

	u32 max_connect_num; /* PF/VF maximum connection number(1M) */
	/* The maximum connections which can be stick to cache memory, max 1K */
	u16 max_stick2cache_num;

	struct nic_service_cap nic_cap;           /* NIC capability */
	struct fc_service_cap fc_cap;             /* FC capability */
};

struct hifc_sync_time_info {
	u8 status;
	u8 version;
	u8 rsvd0[6];

	u64 mstime;
};

struct cfg_eq {
	enum hifc_service_type type;
	int eqn;
	int free; /* 1 - alocated, 0- freed */
};

struct cfg_eq_info {
	struct cfg_eq *eq;
	u8 num_ceq;
	u8 num_ceq_remain;
	/* mutex used for allocate EQs */
	struct mutex eq_mutex;
};

struct irq_alloc_info_st {
	enum hifc_service_type type;
	int free;                /* 1 - alocated, 0- freed */
	struct irq_info info;
};

struct cfg_irq_info {
	struct irq_alloc_info_st *alloc_info;
	u16 num_total;
	u16 num_irq_remain;
	u16 num_irq_hw;          /* device max irq number */

	/* mutex used for allocate EQs */
	struct mutex irq_mutex;
};

#define VECTOR_THRESHOLD	2

struct cfg_mgmt_info {
	struct hifc_hwdev *hwdev;
	struct service_cap  svc_cap;
	struct cfg_eq_info  eq_info;        /* EQ */
	struct cfg_irq_info irq_param_info; /* IRQ */
	u32 func_seq_num;                   /* temporary */
};

enum cfg_sub_cmd {
	/* PPF(PF) <-> FW */
	HIFC_CFG_NIC_CAP = 0,
	CFG_FW_VERSION,
	CFG_UCODE_VERSION,
	HIFC_CFG_FUNC_CAP,
	HIFC_CFG_MBOX_CAP = 6,
};

struct hifc_dev_cap {
	u8 status;
	u8 version;
	u8 rsvd0[6];

	/* Public resource */
	u8 sf_svc_attr;
	u8 host_id;
	u8 sf_en_pf;
	u8 sf_en_vf;

	u8 ep_id;
	u8 intr_type;
	u8 max_cos_id;
	u8 er_id;
	u8 port_id;
	u8 max_vf;
	u16 svc_cap_en;
	u16 host_total_func;
	u8 host_oq_id_mask_val;
	u8 max_vf_cos_id;

	u32 max_conn_num;
	u16 max_stick2cache_num;
	u16 max_bfilter_start_addr;
	u16 bfilter_len;
	u16 hash_bucket_num;
	u8 cfg_file_ver;
	u8 net_port_mode;
	u8 valid_cos_bitmap; /* every bit indicate cos is valid */
	u8 force_up;
	u32 pf_num;
	u32 pf_id_start;
	u32 vf_num;
	u32 vf_id_start;

	/* shared resource */
	u32 host_pctx_num;
	u8 host_sf_en;
	u8 rsvd2[3];
	u32 host_ccxt_num;
	u32 host_scq_num;
	u32 host_srq_num;
	u32 host_mpt_num;
	/* l2nic */
	u16 nic_max_sq;
	u16 nic_max_rq;
	u32 rsvd[46];
	/* FC */
	u32 fc_max_pctx;
	u32 fc_max_scq;
	u32 fc_max_srq;

	u32 fc_max_cctx;
	u32 fc_cctx_id_start;

	u8 fc_vp_id_start;
	u8 fc_vp_id_end;
	u16 func_id;
};
#endif
