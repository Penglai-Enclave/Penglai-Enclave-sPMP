/* SPDX-License-Identifier: GPL-2.0 */
/* Huawei Hifc PCI Express Linux driver
 * Copyright(c) 2017 Huawei Technologies Co., Ltd
 *
 */
#ifndef __HIFCOE_PARENT_CONTEXT_H__
#define __HIFCOE_PARENT_CONTEXT_H__

enum fc_parent_status_e {
	FCOE_PARENT_STATUS_INVALID = 0,
	FCOE_PARENT_STATUS_NORMAL,
	FCOE_PARENT_STATUS_CLOSING
};

#define HIFCOE_DOUBLE_SGL (1)
#define HIFCOE_SINGLE_SGL (0)

#define HIFCOE_DIX_ALGORITHM_IP  (1)
#define HIFCOE_DIX_ALGORITHM_CRC (0)

#define HIFCOE_PARENT_CONTEXT_KEY_ALIGN_SIZE (48)

#define HIFCOE_PARENT_CONTEXT_SRQ_QINFO_SIZE (8)
#define HIFCOE_PARENT_CONTEXT_TIMER_SIZE (32)  /* 24+2*N,N=timer count */
#define HIFCOE_RQ_FILLED_OFFSET \
	((u8)(u32)& \
	(((struct hifcoe_sw_section_s *)0x0)->occupy_by_rqe_filled_flag))
#define HIFCOE_RW_LOCK_AREA_OFFSET \
	((u8)(u32)&\
	(((struct hifcoe_sw_section_s *)0x0)->occupy_by_rw_lock_area))

/* "fqg_level_eventiq_info_s" should be care if MAX_EVENTIQ_LEVEL is larger
 * than 4
 */
#define MAX_EVENTIQ_LEVEL 4
#define MAX_EVENTIQ_LEVEL_SHIFT 2

#define SP_FEATRUE_EDTR 0x1
#define SP_FEATRUE_SEQ_CNT 0x2

#define MAX_PKT_SIZE_PER_DISPATCH (FC_PARENT_P->per_xmit_data_size)
#define MAX_PKT_SIZE_PER_DISPATCH_DIF_4K \
	(MAX_PKT_SIZE_PER_DISPATCH + ((MAX_PKT_SIZE_PER_DISPATCH >> 12) << 3))
#define MAX_PKT_SIZE_PER_DISPATCH_DIF_512B \
	(MAX_PKT_SIZE_PER_DISPATCH + ((MAX_PKT_SIZE_PER_DISPATCH >> 9) << 3))
#define MAX_PKT_SIZE_PER_DISPATCH_DIF(shift) \
	(MAX_PKT_SIZE_PER_DISPATCH +\
	((u32)((MAX_PKT_SIZE_PER_DISPATCH >> 9) >> (shift)) << 3))

/* immidiate data DIF info definition in parent context */
struct immi_dif_info_s {
	union {
		u32 value;
		struct {
#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
			u32 pdu_difx_cnt    :8;
			u32 sct_size        :1;/* Sector size, 1: 4K; 0: 512 */
			u32 dif_verify_type :2;     /* verify type */
			u32 dif_ins_rep_type:2;     /* ins&rep type */
			u32 io_1st_pdu      :1;
			/* Check blocks whose application tag contains
			 * 0xFFFF flag
			 */
			u32 difx_app_esc    :1;
			u32 difx_ref_esc    :1;
			/*
			 * Check blocks whose reference tag contains 0xFFFF flag
			 */
			u32 grd_ctrl        :3; /* The DIF/DIX Guard control */
			/* Bit 0: DIF/DIX guard verify algorithm control */
			u32 grd_agm_ctrl    :2;
			/*
			 * Bit 1: DIF/DIX guard replace or insert algorithm
			 * control
			 */
			u32 grd_agm_ini_ctrl :3;
			/* The DIF/DIX Reference tag control */
			u32 ref_tag_ctrl    :3;
			/* Bit 0: scenario of the reference tag verify mode */
			u32 ref_tag_mode    :2;
			/*
			 * Bit 1: scenario of the reference tag insert/replace
			 * mode
			 */
			 /* 0: fixed; 1: increasement;*/
			u32 app_tag_ctrl    :3;  /* DIF/DIX APP TAG Control */

#else
			u32 app_tag_ctrl    :3;  /* DIF/DIX APP TAG Control */
			/* Bit 0: scenario of the reference tag verify mode */
			u32 ref_tag_mode    :2;
			/*
			 * Bit 1: scenario of the reference tag insert/replace
			 * mode
			 */
			/* 0: fixed; 1: increasement;*/
			/* The DIF/DIX Reference tag control */
			u32 ref_tag_ctrl    :3;
			u32 grd_agm_ini_ctrl :3;
			/* Bit 0: DIF/DIX guard verify algorithm control */
			u32 grd_agm_ctrl    :2;
			/*
			 * Bit 1: DIF/DIX guard replace or insert algorithm
			 * control
			 */
			u32 grd_ctrl        :3; /* The DIF/DIX Guard control */
			/*
			 * Check blocks whose reference tag contains 0xFFFF flag
			 */
			u32 difx_ref_esc    :1;
			/*
			 * Check blocks whose application tag contains 0xFFFF
			 * flag
			 */
			u32 difx_app_esc    :1;
			u32 io_1st_pdu      :1;
			u32 dif_ins_rep_type:2;     /* ins&rep type  */
			u32 dif_verify_type :2;     /* verify type */
			u32 sct_size        :1; /* Sector size, 1: 4K; 0: 512 */
			u32 pdu_difx_cnt    :8;

#endif
		} info;
	} dif_dw3;

	union {
		u32 value;
		struct {
#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
			u32 difx_len        :11;    /* DIF/DIFX total length */
			u32 difx_en         :1;     /* DIF/DIFX enable flag */
			u32 rsv0            :4;
			u32 dif_cnt         :16;
#else
			u32 dif_cnt         :16;
			u32 rsv0            :4;
			u32 difx_en         :1;     /* DIF/DIFX enable flag */
			u32 difx_len        :11;    /* DIF/DIFX total length */
#endif
		} info;
	} dif_other;

	#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
		u32 rep_app_tag        :16;
		u32 cmp_app_tag        :16;
	#else
		u32 cmp_app_tag        :16;
		u32 rep_app_tag        :16;
	#endif
	/*
	 * The ref tag value for verify compare, do not support replace or
	 * insert ref tag
	 */
	u32 cmp_ref_tag;

#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
	u32 cmp_app_tag_msk        :16;
	u32 rsv1                   :16;
#else
	u32 rsv1                   :16;
	u32 cmp_app_tag_msk        :16;
#endif
};

/* parent context SW section definition: SW(80B) */
struct hifcoe_sw_section_s {
	/* RO fields */
	u32 scq_num_rcv_cmd;    /* scq number used for cmd receive */

#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
	u32 xid;                /* driver init */
#else
	struct {
		u32 xid     :13;
		u32 vport   :7;
		u32 csctrl  :8;
		u32 rsvd0   :4;
	} sw_ctxt_vport_xid;
#endif
	u32 cid;                /* ucode init */

	u16 conn_id;
	u16 immi_rq_page_size;

	u16 immi_taskid_min;
	u16 immi_taskid_max;

#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
	u32 vlan_id         : 16; /* Vlan ID */
	/* phycial port to receive and transmit packet. */
	u32 port_id         : 4;
	/*
	 * new srq offset. Ucode use new srq to receive els/gs with big payload.
	 */
	u32 rsvd1           : 5;
	u32 srr_support     : 2;  /* sequence retransmition support flag */
	u32 srv_type        : 5;
#else
	union {
		u32 pctxt_val0;
		struct {
			u32 srv_type        : 5;    /* driver init */
			/* sequence retransmition support flag */
			u32 srr_support     : 2;
			u32 rsvd1           : 5;
			u32 port_id         : 4;    /* driver init */
			u32 vlan_id         : 16;   /* driver init */
		} dw;
	} sw_ctxt_misc;
#endif

	u16 oqid_rd;
	u16 oqid_wr;
	u32 per_xmit_data_size;

	/* RW fields */
	u32 cmd_scq_gpa_h;
	u32 cmd_scq_gpa_l;
	/* E_D_TOV timer value: value should be set on ms by driver */
	u32 e_d_tov_timer_val;
	/*
	 * mfs unalined bytes of per 64KB dispatch; equal to
	 * "MAX_PKT_SIZE_PER_DISPATCH%info->parent->tx_mfs"
	 */
	u16 mfs_unaligned_bytes;
	u16 tx_mfs;             /* remote port max receive fc payload length */
	/* max data len allowed in xfer_rdy dis scenario*/
	u32 xfer_rdy_dis_max_len_remote;
	u32 xfer_rdy_dis_max_len_local;

#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
	/* Double or single SGL, 1: double; 0: single */
	u32 sgl_num                :1;
	u32 write_xfer_rdy         :1;   /* WRITE Xfer_Rdy disable or enable */
	u32 rec_support            :1;   /* REC support flag */
	u32 conf_support           :1;   /* Response confirm support flag */
	u32 vlan_enable            :1;   /* Vlan enable flag */
	u32 e_d_tov                :1;   /* E_D_TOV Resolution, 0: ms, 1: us*/
	/* seq_cnt, 1: increament support, 0: increament not support */
	u32 seq_cnt                :1;
	/* 0:Target, 1:Initiator, 2:Target&Initiator */
	u32 work_mode              :2;
	/* used for parent context cache Consistency judgment,1: done*/
	u32 flush_done             :1;
	u32 oq_cos_cmd             :3;   /* esch oq cos for cmd/xferrdy/rsp */
	u32 oq_cos_data            :3;   /* esch oq cos for data */
	u32 cos                    :3;   /* doorbell cos value */
	u32 status                 :8;   /* status of flow*/
	u32 rsvd4                  :2;
	u32 priority               :3;   /* vlan priority */
#else
	union {
		struct {
			u32 priority            : 3;  /* vlan priority */
			u32 rsvd4               : 2;
			u32 status              : 8;  /* status of flow*/
			u32 cos                 : 3;  /* doorbell cos value */
			u32 oq_cos_data         : 3;  /* esch oq cos for data */
			/* esch oq cos for cmd/xferrdy/rsp */
			u32 oq_cos_cmd          : 3;
			/*
			 * used for parent context cache Consistency judgment,
			 * 1: done
			 */
			u32 flush_done          : 1;
			/* 0:Target, 1:Initiator, 2:Target&Initiator */
			u32 work_mode           : 2;
			u32 seq_cnt             : 1;  /* seq_cnt */
			u32 e_d_tov             : 1;  /* E_D_TOV resolution */
			u32 vlan_enable         : 1;  /* Vlan enable flag */
			/* Response confirm support flag */
			u32 conf_support        : 1;
			u32 rec_support         : 1;  /* REC support flag */
			/* WRITE Xfer_Rdy disable or enable */
			u32 write_xfer_rdy      : 1;
			/* Double or single SGL, 1: double; 0: single */
			u32 sgl_num             : 1;
		} dw;
		u32 pctxt_val1;
	} sw_ctxt_config;
#endif
	/* immidiate data dif control info(20B) */
	struct immi_dif_info_s immi_dif_info;
};

struct hifcoe_hw_rsvd_queue_s {
	/* bitmap[0]:255-192 */
	/* bitmap[1]:191-128 */
	/* bitmap[2]:127-64  */
	/* bitmap[3]:63-0    */
	u64 seq_id_bitmap[4];
	struct {
		u64 last_req_seq_id : 8;
		u64 xid             : 20;
		u64 rsvd0           : 36;
	} wd0;
};

struct hifcoe_sq_qinfo_s {
	u64 rsvd_0         : 10;
	/* 0: get pmsn from queue header; 1: get pmsn from ucode */
	u64 pmsn_type      : 1;
	u64 rsvd_1         : 4;
	u64 cur_wqe_o      : 1; /* should be opposite from loop_o */
	u64 rsvd_2         : 48;

	u64 cur_sqe_gpa;
	u64 pmsn_gpa;           /* sq's queue header gpa */

	u64 sqe_dmaattr_idx : 6;
	u64 sq_so_ro        : 2;
	u64 rsvd_3          : 2;
	u64 ring            : 1; /* 0: link; 1: ring */
	u64 loop_o          : 1; /* init to be the first round o-bit */
	u64 rsvd_4          : 4;
	u64 zerocopy_dmaattr_idx : 6;
	u64 zerocopy_so_ro  : 2;
	u64 parity          : 8;
	u64 rsvd_5          : 26;
	u64 pcie_template   : 6;
};

struct hifcoe_cq_qinfo_s {
	u64 pcie_template_hi : 3;
	u64 parity_2        : 1;
	u64 cur_cqe_gpa     : 60;

	u64 pi              : 15;
	u64 pi_o            : 1;
	u64 ci              : 15;
	u64 ci_o            : 1;
	/* if init_mode = 2, is msi/msi-x; other the low-5-bit means c_eqn */
	u64 c_eqn_msi_x     : 10;
	u64 parity_1        : 1;
	/* 0: get ci from queue header; 1: get ci from ucode */
	u64 ci_type         : 1;
	u64 cq_depth        : 3; /* valid when ring = 1 */
	u64 armq            : 1; /* 0: IDLE state; 1: NEXT state */
	u64 cur_cqe_cnt     : 8;
	u64 cqe_max_cnt     : 8;

	u64 cqe_dmaattr_idx : 6;
	u64 cq_so_ro        : 2;
	u64 init_mode       : 2; /* 1: armQ; 2: msi/msi-x; others: rsvd */
	u64 next_o          : 1; /* next pate valid o-bit */
	u64 loop_o          : 1; /* init to be the first round o-bit */
	u64 next_cq_wqe_page_gpa : 52;

	u64 pcie_template_lo : 3;
	u64 parity_0        : 1;
	u64 ci_gpa          : 60; /* cq's queue header gpa */
};

struct hifcoe_scq_qinfo_s {
#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
	union {
		struct {
			u64 parity                 : 6;
			u64 rq_th2_preld_cache_num : 5;
			u64 rq_th1_preld_cache_num : 5;
			u64 rq_th0_preld_cache_num : 5;
			u64 rq_min_preld_cache_num : 4;
			u64 sq_th2_preld_cache_num : 5;
			u64 sq_th1_preld_cache_num : 5;
			u64 sq_th0_preld_cache_num : 5;
			u64 sq_min_preld_cache_num : 4;
			u64 scq_n           : 20; /* scq number */
		} info;

		u64 pctxt_val1;
	} hw_scqc_config;
#else
	union {
		struct {
			u64 scq_n           : 20; /* scq number */
			u64 sq_min_preld_cache_num : 4;
			u64 sq_th0_preld_cache_num : 5;
			u64 sq_th1_preld_cache_num : 5;
			u64 sq_th2_preld_cache_num : 5;
			u64 rq_min_preld_cache_num : 4;
			u64 rq_th0_preld_cache_num : 5;
			u64 rq_th1_preld_cache_num : 5;
			u64 rq_th2_preld_cache_num : 5;
			u64 parity                 : 6;
		} info;

		u64 pctxt_val1;
	} hw_scqc_config;
#endif
};

struct hifcoe_srq_qinfo_s {
#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
		u64 srqc_gpa         : 60;
		u64 parity           : 4;
#else
		u64 parity           : 4;
		u64 srqc_gpa         : 60;
#endif
};

/* here is the layout of service type 12/13 */
struct hifcoe_parent_context_s {
	u8 key[HIFCOE_PARENT_CONTEXT_KEY_ALIGN_SIZE];
	struct hifcoe_scq_qinfo_s resp_scq_qinfo;
	struct hifcoe_srq_qinfo_s imm_srq_info;
	struct hifcoe_sq_qinfo_s  sq_qinfo;
	u8 timer_section[HIFCOE_PARENT_CONTEXT_TIMER_SIZE];
	struct hifcoe_hw_rsvd_queue_s hw_rsvdq;
	struct hifcoe_srq_qinfo_s  els_srq_info;
	struct hifcoe_sw_section_s  sw_section;
};

#endif
