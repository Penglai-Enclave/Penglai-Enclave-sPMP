/* SPDX-License-Identifier: GPL-2.0 */
/* Huawei Hifc PCI Express Linux driver
 * Copyright(c) 2017 Huawei Technologies Co., Ltd
 *
 */

#ifndef __CQM_OBJECT_H__
#define __CQM_OBJECT_H__

#define CLA_TABLE_PAGE_ORDER (0)
#define CQM_4K_PAGE_ORDER (0)

#define CQM_CQ_DEPTH_MAX (32768)
#define CQM_CQ_DEPTH_MIN (256)
#define CQM_BAT_SIZE_FT_PF (192)

#define CQM_WQE_WF_LINK 1
#define CQM_WQE_WF_NORMAL 0
#define CQM_QUEUE_LINK_MODE 0
#define CQM_QUEUE_RING_MODE 1
#define CQM_4K_PAGE_SIZE 4096

#define CQM_SUCCESS 0
#define CQM_FAIL -1
#define CQM_QUEUE_TOE_SRQ_LINK_MODE 2
#define CQM_CMD_TIMEOUT 10000 /*ms*/

#define CQM_INDEX_INVALID ~(0U)
#define CQM_INDEX_RESERVED (0xfffff)  /* reserved by cqm alloc */

enum cqm_bat_entry_type_e {
	CQM_BAT_ENTRY_T_CFG = 0,
	CQM_BAT_ENTRY_T_HASH,
	CQM_BAT_ENTRY_T_QPC,
	CQM_BAT_ENTRY_T_SCQC,
	CQM_BAT_ENTRY_T_SRQC,
	CQM_BAT_ENTRY_T_MPT,
	CQM_BAT_ENTRY_T_GID,
	CQM_BAT_ENTRY_T_LUN,
	CQM_BAT_ENTRY_T_TASKMAP,
	CQM_BAT_ENTRY_T_L3I,
	CQM_BAT_ENTRY_T_CHILDC,
	CQM_BAT_ENTRY_T_TIMER,
	CQM_BAT_ENTRY_T_XID2CID,
	CQM_BAT_ENTRY_T_REORDER,

	CQM_BAT_ENTRY_T_INVALID = 0xff,
};

enum cqm_cmd_type_e {
	CQM_CMD_T_INVALID = 0,
	CQM_CMD_T_BAT_UPDATE,
	CQM_CMD_T_CLA_UPDATE,
	CQM_CMD_T_BLOOMFILTER_SET,
	CQM_CMD_T_BLOOMFILTER_CLEAR,
	CQM_CMD_T_COMPACT_SRQ_UPDATE,
	CQM_CMD_T_CLA_CACHE_INVALID,
	CQM_CMD_T_BLOOMFILTER_INIT,
	QM_CMD_T_MAX
};

/*linkwqe*/
#define CQM_LINK_WQE_CTRLSL_VALUE 2
#define CQM_LINK_WQE_LP_VALID 1
#define CQM_LINK_WQE_LP_INVALID 0
#define CQM_LINK_WQE_OWNER_VALID 1
#define CQM_LINK_WQE_OWNER_INVALID 0

/*CLA update mode*/
#define CQM_CLA_RECORD_NEW_GPA 0
#define CQM_CLA_DEL_GPA_WITHOUT_CACHE_INVALID 1
#define CQM_CLA_DEL_GPA_WITH_CACHE_INVALID 2

#define CQM_CLA_LVL_0 0
#define CQM_CLA_LVL_1 1
#define CQM_CLA_LVL_2 2

#define CQM_MAX_INDEX_BIT  19
#define CQM_CHIP_CACHELINE 256
enum cqm_cmd_ack_type_e {
	CQM_CMD_ACK_TYPE_CMDQ = 0,      /* ack: write back to cmdq */
	CQM_CMD_ACK_TYPE_SHARE_CQN = 1, /* ack report scq by root ctx  ctx */
	CQM_CMD_ACK_TYPE_APP_CQN = 2    /* ack report scq by parent ctx */
};

struct cqm_bat_entry_cfg_s {
	u32 cur_conn_num_h_4    :4;
	u32 rsv1                :4;
	u32 max_conn_num        :20;
	u32 rsv2                :4;

	u32 max_conn_cache      :10;
	u32 rsv3                :6;
	u32 cur_conn_num_l_16   :16;

	u32 bloom_filter_addr   :16;
	u32 cur_conn_cache      :10;
	u32 rsv4                :6;

	u32 bucket_num          :16;
	u32 bloom_filter_len    :16;
};

#define CQM_BAT_NO_BYPASS_CACHE 0
#define CQM_BAT_ENTRY_SIZE_256  0
#define CQM_BAT_ENTRY_SIZE_512  1
#define CQM_BAT_ENTRY_SIZE_1024 2

struct cqm_bat_entry_standerd_s {
	u32 entry_size          :2;
	u32 rsv1                :6;
	u32 max_number          :20;
	u32 rsv2                :4;

	u32 cla_gpa_h           :32;

	u32 cla_gpa_l           :32;

	u32 rsv3                :8;
	u32 z                   :5;
	u32 y                   :5;
	u32 x                   :5;
	u32 rsv24                :1;
	u32 bypass              :1;
	u32 cla_level           :2;
	u32 rsv5                :5;
};

struct cqm_bat_entry_taskmap_s {
	u32 gpa0_h;
	u32 gpa0_l;

	u32 gpa1_h;
	u32 gpa1_l;

	u32 gpa2_h;
	u32 gpa2_l;

	u32 gpa3_h;
	u32 gpa3_l;
};

struct cqm_cla_cache_invalid_cmd_s {
	u32 gpa_h;
	u32 gpa_l;
	u32 cache_size;/* CLA cache size=4096B */
};

struct cqm_cla_update_cmd_s {
	/* need to update gpa addr */
	u32 gpa_h;
	u32 gpa_l;

	/* update value */
	u32 value_h;
	u32 value_l;
};

struct cqm_bat_update_cmd_s {
#define CQM_BAT_MAX_SIZE 256
	u32 offset; /* byte offset,16Byte aligned */
	u32 byte_len; /* max size: 256byte */
	u8 data[CQM_BAT_MAX_SIZE];
};

struct cqm_handle_s;

struct cqm_linkwqe_s {
	u32 rsv1                :14;
	u32 wf                  :1;
	u32 rsv2                :14;
	u32 ctrlsl              :2;
	u32 o                   :1;

	u32 rsv3                :31;
	u32 lp                  :1;

	u32 next_page_gpa_h;
	u32 next_page_gpa_l;

	u32 next_buffer_addr_h;
	u32 next_buffer_addr_l;
};

struct cqm_srq_linkwqe_s {
	struct cqm_linkwqe_s linkwqe;
	/*add by wss for srq*/
	u32 current_buffer_gpa_h;
	u32 current_buffer_gpa_l;
	u32 current_buffer_addr_h;
	u32 current_buffer_addr_l;

	u32 fast_link_page_addr_h;
	u32 fast_link_page_addr_l;

	u32 fixed_next_buffer_addr_h;
	u32 fixed_next_buffer_addr_l;
};

union cqm_linkwqe_first_64b_s {
	struct cqm_linkwqe_s basic_linkwqe;
	u32 value[16];
};

struct cqm_linkwqe_second_64b_s {
	u32 rsvd0[4];
	u32 rsvd1[4];
	union {
		struct {
			u32 rsvd0[3];
			u32 rsvd1       :29;
			u32 toe_o       :1;
			u32 resvd2      :2;
		} bs;
		u32 value[4];
	} third_16B;

	union {
		struct {
			u32 rsvd0[2];
			u32 rsvd1       :31;
			u32 ifoe_o       :1;
			u32 rsvd2;
		} bs;
		u32 value[4];
	} forth_16B;

};

struct cqm_linkwqe_128b_s {
	union cqm_linkwqe_first_64b_s first_64b;
	struct cqm_linkwqe_second_64b_s second_64b;
};

s32 cqm_bat_init(struct cqm_handle_s *cqm_handle);
void cqm_bat_uninit(struct cqm_handle_s *cqm_handle);
s32 cqm_cla_init(struct cqm_handle_s *cqm_handle);
void cqm_cla_uninit(struct cqm_handle_s *cqm_handle);
s32 cqm_bitmap_init(struct cqm_handle_s *cqm_handle);
void cqm_bitmap_uninit(struct cqm_handle_s *cqm_handle);
s32 cqm_object_table_init(struct cqm_handle_s *cqm_handle);
void cqm_object_table_uninit(struct cqm_handle_s *cqm_handle);

#endif /* __CQM_OBJECT_H__ */
