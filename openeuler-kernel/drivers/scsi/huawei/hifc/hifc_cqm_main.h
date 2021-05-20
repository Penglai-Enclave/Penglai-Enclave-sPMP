/* SPDX-License-Identifier: GPL-2.0 */
/* Huawei Hifc PCI Express Linux driver
 * Copyright(c) 2017 Huawei Technologies Co., Ltd
 *
 */
#ifndef __CQM_MAIN_H__
#define __CQM_MAIN_H__

#define CHIPIF_SUCCESS   0
#define CQM_TIMER_ENABLE 1

enum cqm_object_type_e {
	CQM_OBJECT_ROOT_CTX = 0,
	CQM_OBJECT_SERVICE_CTX,
	CQM_OBJECT_NONRDMA_EMBEDDED_RQ = 10,
	CQM_OBJECT_NONRDMA_EMBEDDED_SQ,
	CQM_OBJECT_NONRDMA_SRQ,
	CQM_OBJECT_NONRDMA_EMBEDDED_CQ,
	CQM_OBJECT_NONRDMA_SCQ,
};

struct service_register_template_s {
	u32 service_type;
	u32 srq_ctx_size;       /* srq,scq context_size config */
	u32 scq_ctx_size;
	void *service_handle;   /* ceq/aeq callback fun */

	void (*aeq_callback)(void *service_handle, u8 event_type, u64 val);
};

struct cqm_service_s {
	bool has_register;
	void __iomem *hardware_db_vaddr;
	void __iomem *dwqe_vaddr;
	u32 buf_order;               /* size of per buf 2^buf_order page */
	struct service_register_template_s service_template;
};

struct cqm_func_capability_s {
	bool qpc_alloc_static;  /* Allocate qpc memory dynamicly/statically */
	bool scqc_alloc_static;
	u8 timer_enable;   /* whether timer enable */

	u32 flow_table_based_conn_number;
	u32 flow_table_based_conn_cache_number; /* Maximum number in cache */
	u32 bloomfilter_length; /* Bloomfilter table size, aligned by 64B */
	/* The starting position of the bloomfilter table in the cache */
	u32 bloomfilter_addr;
	u32 qpc_reserved;  /* Reserved bits in bitmap */
	u32 mpt_reserved;  /* There are also reserved bits in ROCE/IWARP mpt */
	/* All basic_size must be 2^n aligned */
	u32 hash_number;
	/* Number of hash buckets, BAT table fill size is
	 * aligned with 64 buckets, at least 64
	 */
	u32 hash_basic_size;
	/* Hash bucket size is 64B, including 5 valid
	 * entries and 1 nxt_entry
	 */
	u32 qpc_number;
	u32 qpc_basic_size;

	/* Note: for cqm specail test */
	u32 pagesize_reorder;
	bool xid_alloc_mode;
	bool gpa_check_enable;
	u32 scq_reserved;

	u32 mpt_number;
	u32 mpt_basic_size;
	u32 scqc_number;
	u32 scqc_basic_size;
	u32 srqc_number;
	u32 srqc_basic_size;

	u32 gid_number;
	u32 gid_basic_size;
	u32 lun_number;
	u32 lun_basic_size;
	u32 taskmap_number;
	u32 taskmap_basic_size;
	u32 l3i_number;
	u32 l3i_basic_size;
	u32 childc_number;
	u32 childc_basic_size;
	u32 child_qpc_id_start; /* Child ctx of FC is global addressing */
	/* The maximum number of child ctx in
	 * chip is 8096
	 */
	u32 childc_number_all_function;

	u32 timer_number;
	u32 timer_basic_size;
	u32 xid2cid_number;
	u32 xid2cid_basic_size;
	u32 reorder_number;
	u32 reorder_basic_size;
};

#define CQM_PF TYPE_PF
#define CQM_PPF TYPE_PPF
#define CQM_BAT_ENTRY_MAX  (16)
#define CQM_BAT_ENTRY_SIZE (16)

struct cqm_buf_list_s {
	void *va;
	dma_addr_t pa;
	u32 refcount;
};

struct cqm_buf_s {
	struct cqm_buf_list_s *buf_list;
	struct cqm_buf_list_s  direct;
	u32 page_number;    /* page_number=2^n buf_number */
	u32 buf_number;     /* buf_list node count */
	u32 buf_size;       /* buf_size=2^n PAGE_SIZE */
};

struct cqm_bitmap_s {
	ulong *table;
	u32 max_num;
	u32 last;
	/* The index that cannot be allocated is reserved in the front */
	u32 reserved_top;
	/* Lock for bitmap allocation */
	spinlock_t lock;
};

struct completion;
struct cqm_object_s {
	u32 service_type;
	u32 object_type;    /* context,queue,mpt,mtt etc */
	u32 object_size;
	/* for queue, ctx, MPT Byte */
	atomic_t refcount;
	struct completion free;
	void *cqm_handle;
};

struct cqm_object_table_s {
	struct cqm_object_s **table;
	u32 max_num;
	rwlock_t lock;
};

struct cqm_cla_table_s {
	u32 type;
	u32 max_buffer_size;
	u32 obj_num;
	bool alloc_static;     /* Whether the buffer is statically allocated */
	u32 cla_lvl;
	/* The value of x calculated by the cacheline, used for chip */
	u32 cacheline_x;
	/* The value of y calculated by the cacheline, used for chip */
	u32 cacheline_y;
	/* The value of z calculated by the cacheline, used for chip */
	u32 cacheline_z;
	/* The value of x calculated by the obj_size, used for software */
	u32 x;
	/* The value of y calculated by the obj_size, used for software */
	u32 y;
	/* The value of z calculated by the obj_size, used for software */
	u32 z;
	struct cqm_buf_s cla_x_buf;
	struct cqm_buf_s cla_y_buf;
	struct cqm_buf_s cla_z_buf;
	u32 trunk_order;/* A continuous physical page contains 2^order pages */
	u32 obj_size;
	/* Lock for cla buffer allocation and free */
	struct mutex lock;
	struct cqm_bitmap_s bitmap;
	/* The association mapping table of index and object */
	struct cqm_object_table_s obj_table;
};

typedef void (*init_handler)(void *cqm_handle,
			     struct cqm_cla_table_s *cla_table,
			     void *cap);

struct cqm_cla_entry_init_s {
	u32 type;
	init_handler cqm_cla_init_handler;
};

struct cqm_bat_table_s {
	u32 bat_entry_type[CQM_BAT_ENTRY_MAX];
	u8 bat[CQM_BAT_ENTRY_MAX * CQM_BAT_ENTRY_SIZE];
	struct cqm_cla_table_s entry[CQM_BAT_ENTRY_MAX];
	u32 bat_size;
};

struct cqm_handle_s {
	struct hifc_hwdev *ex_handle;
	struct pci_dev *dev;
	struct hifc_func_attr func_attribute;        /* vf or pf */
	struct cqm_func_capability_s func_capability;
	struct cqm_service_s service;
	struct cqm_bat_table_s bat_table;

	struct list_head node;
};

struct cqm_cmd_buf_s {
	void *buf;
	dma_addr_t dma;
	u16 size;
};

struct cqm_queue_header_s {
	u64 doorbell_record;
	u64 ci_record;
	u64 rsv1;      /* the share area bettween driver and ucode */
	u64 rsv2;      /* the share area bettween driver and ucode*/
};

struct cqm_queue_s {
	struct cqm_object_s  object;
	u32 index;      /* embedded queue QP has not index, SRQ and SCQ have */
	void *priv;     /* service driver private info */
	u32 current_q_doorbell;
	u32 current_q_room;
	/* nonrdma: only select q_room_buf_1 for q_room_buf */
	struct cqm_buf_s q_room_buf_1;
	struct cqm_buf_s q_room_buf_2;
	struct cqm_queue_header_s *q_header_vaddr;
	dma_addr_t q_header_paddr;
	u8 *q_ctx_vaddr;                /* SRQ and SCQ ctx space */
	dma_addr_t q_ctx_paddr;
	u32 valid_wqe_num;
	/*add for srq*/
	u8 *tail_container;
	u8 *head_container;
	u8 queue_link_mode;   /*link,ring */
};

struct cqm_nonrdma_qinfo_s {
	struct cqm_queue_s common;
	u32 wqe_size;
	/* The number of wqe contained in each buf (excluding link wqe),
	 * For srq, it is the number of wqe contained in 1 container
	 */
	u32 wqe_per_buf;
	u32 q_ctx_size;
	/* When different services use different sizes of ctx, a large ctx will
	 * occupy multiple consecutive indexes of the bitmap
	 */
	u32 index_count;
	u32 container_size;
};

/* service context, QPC, mpt */
struct cqm_qpc_mpt_s {
	struct cqm_object_s  object;
	u32 xid;
	dma_addr_t paddr;
	void *priv; /* service driver private info */
	u8 *vaddr;
};

struct cqm_qpc_mpt_info_s {
	struct cqm_qpc_mpt_s common;
	/* When different services use different sizes of QPC, large QPC/mpt
	 * will occupy multiple consecutive indexes of the bitmap
	 */
	u32 index_count;
};

#define CQM_ADDR_COMBINE(high_addr, low_addr) \
	((((dma_addr_t)(high_addr)) << 32) + ((dma_addr_t)(low_addr)))
#define CQM_ADDR_HI(addr)  ((u32)((u64)(addr) >> 32))
#define CQM_ADDR_LW(addr)  ((u32)((u64)(addr) & 0xffffffff))
#define CQM_HASH_BUCKET_SIZE_64 (64)
#define CQM_LUN_SIZE_8 (8)
#define CQM_L3I_SIZE_8 (8)
#define CQM_TIMER_SIZE_32 (32)
#define CQM_LUN_FC_NUM (64)
#define CQM_TASKMAP_FC_NUM (4)
#define CQM_L3I_COMM_NUM (64)
#define CQM_TIMER_SCALE_NUM (2*1024)
#define CQM_TIMER_ALIGN_WHEEL_NUM (8)
#define CQM_TIMER_ALIGN_SCALE_NUM \
	(CQM_TIMER_SCALE_NUM*CQM_TIMER_ALIGN_WHEEL_NUM)
#define CQM_FC_PAGESIZE_ORDER (0)
#define CQM_QHEAD_ALIGN_ORDER (6)

s32 cqm_mem_init(void *ex_handle);
void cqm_mem_uninit(void *ex_handle);
s32 cqm_event_init(void *ex_handle);
void cqm_event_uninit(void *ex_handle);
s32 cqm_db_init(void *ex_handle);
void cqm_db_uninit(void *ex_handle);
s32 cqm_init(void *ex_handle);
void cqm_uninit(void *ex_handle);
s32 cqm_service_register(void *ex_handle,
			 struct service_register_template_s *service_template);
void cqm_service_unregister(void *ex_handle);
s32 cqm_ring_hardware_db(void *ex_handle,
			 u32 service_type,
			 u8 db_count, u64 db);
s32 cqm_send_cmd_box(void *ex_handle, u8 ack_type, u8 mod, u8 cmd,
		     struct cqm_cmd_buf_s *buf_in,
		     struct cqm_cmd_buf_s *buf_out,
		     u32 timeout);
u8 cqm_aeq_callback(void *ex_handle, u8 event, u64 data);
void cqm_object_delete(struct cqm_object_s *object);
struct cqm_cmd_buf_s *cqm_cmd_alloc(void *ex_handle);
void cqm_cmd_free(void *ex_handle, struct cqm_cmd_buf_s *cmd_buf);
struct cqm_queue_s *cqm_object_fc_srq_create(
				void *ex_handle,
				enum cqm_object_type_e object_type,
				u32 wqe_number,
				u32 wqe_size,
				void *object_priv);
struct cqm_qpc_mpt_s *cqm_object_qpc_mpt_create(
					void *ex_handle,
					enum cqm_object_type_e object_type,
					u32 object_size,
					void *object_priv,
					u32 index);
struct cqm_queue_s *cqm_object_nonrdma_queue_create(
					void *ex_handle,
					enum cqm_object_type_e object_type,
					u32 wqe_number,
					u32 wqe_size,
					void *object_priv);

#define CQM_PTR_NULL(x) "%s: "#x" is null\n", __func__
#define CQM_ALLOC_FAIL(x) "%s: "#x" alloc fail\n", __func__
#define CQM_MAP_FAIL(x) "%s: "#x" map fail\n", __func__
#define CQM_FUNCTION_FAIL(x) "%s: "#x" return failure\n", __func__
#define CQM_WRONG_VALUE(x) "%s: "#x" %u is wrong\n", __func__, (u32)x

#define cqm_err(dev, format, ...)		\
	dev_err(dev, "[CQM]"format, ##__VA_ARGS__)
#define cqm_warn(dev, format, ...)		\
	dev_warn(dev, "[CQM]"format, ##__VA_ARGS__)
#define cqm_notice(dev, format, ...)		\
	dev_notice(dev, "[CQM]"format, ##__VA_ARGS__)
#define cqm_info(dev, format, ...)		\
	dev_info(dev, "[CQM]"format, ##__VA_ARGS__)
#define cqm_dbg(format, ...)

#define CQM_PTR_CHECK_RET(ptr, ret, desc) \
	do {\
		if (unlikely(NULL == (ptr))) {\
			pr_err("[CQM]"desc);\
			ret; \
		} \
	} while (0)

#define CQM_PTR_CHECK_NO_RET(ptr, desc, ret) \
	do {\
		if (unlikely((ptr) == NULL)) {\
			pr_err("[CQM]"desc);\
			ret; \
		} \
	} while (0)
#define CQM_CHECK_EQUAL_RET(dev_hdl, actual, expect, ret, desc) \
	do {\
		if (unlikely((expect) != (actual))) {\
			cqm_err(dev_hdl, desc);\
			ret; \
		} \
	} while (0)

#endif /* __CQM_MAIN_H__ */
