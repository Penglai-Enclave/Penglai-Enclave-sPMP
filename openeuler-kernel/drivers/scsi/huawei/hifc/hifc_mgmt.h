/* SPDX-License-Identifier: GPL-2.0 */
/* Huawei Hifc PCI Express Linux driver
 * Copyright(c) 2017 Huawei Technologies Co., Ltd
 *
 */

#ifndef HIFC_MGMT_H_
#define HIFC_MGMT_H_

#define HIFC_MSG_HEADER_MSG_LEN_SHIFT               0
#define HIFC_MSG_HEADER_MODULE_SHIFT                11
#define HIFC_MSG_HEADER_SEG_LEN_SHIFT               16
#define HIFC_MSG_HEADER_NO_ACK_SHIFT                22
#define HIFC_MSG_HEADER_ASYNC_MGMT_TO_PF_SHIFT      23
#define HIFC_MSG_HEADER_SEQID_SHIFT                 24
#define HIFC_MSG_HEADER_LAST_SHIFT                  30
#define HIFC_MSG_HEADER_DIRECTION_SHIFT             31
#define HIFC_MSG_HEADER_CMD_SHIFT                   32
#define HIFC_MSG_HEADER_PCI_INTF_IDX_SHIFT          48
#define HIFC_MSG_HEADER_P2P_IDX_SHIFT               50
#define HIFC_MSG_HEADER_MSG_ID_SHIFT                54

#define HIFC_MSG_HEADER_MSG_LEN_MASK                0x7FF
#define HIFC_MSG_HEADER_MODULE_MASK                 0x1F
#define HIFC_MSG_HEADER_SEG_LEN_MASK                0x3F
#define HIFC_MSG_HEADER_NO_ACK_MASK                 0x1
#define HIFC_MSG_HEADER_ASYNC_MGMT_TO_PF_MASK       0x1
#define HIFC_MSG_HEADER_SEQID_MASK                  0x3F
#define HIFC_MSG_HEADER_LAST_MASK                   0x1
#define HIFC_MSG_HEADER_DIRECTION_MASK              0x1
#define HIFC_MSG_HEADER_CMD_MASK                    0xFF
#define HIFC_MSG_HEADER_PCI_INTF_IDX_MASK           0x3
#define HIFC_MSG_HEADER_P2P_IDX_MASK                0xF
#define HIFC_MSG_HEADER_MSG_ID_MASK                 0x3FF

#define HIFC_MSG_HEADER_GET(val, member)            \
		(((val) >> HIFC_MSG_HEADER_##member##_SHIFT) &    \
		HIFC_MSG_HEADER_##member##_MASK)

#define HIFC_MSG_HEADER_SET(val, member)            \
		((u64)((val) & HIFC_MSG_HEADER_##member##_MASK) << \
		HIFC_MSG_HEADER_##member##_SHIFT)

#define HIFC_MGMT_WQ_NAME "hifc_mgmt"

/*CLP*/
enum clp_data_type {
	HIFC_CLP_REQ_HOST = 0,
	HIFC_CLP_RSP_HOST = 1
};

enum clp_reg_type {
	HIFC_CLP_BA_HOST = 0,
	HIFC_CLP_SIZE_HOST = 1,
	HIFC_CLP_LEN_HOST = 2,
	HIFC_CLP_START_REQ_HOST = 3,
	HIFC_CLP_READY_RSP_HOST = 4
};

/* cmd of mgmt CPU message for HW module */
enum hifc_mgmt_cmd {
	HIFC_MGMT_CMD_RESET_MGMT                = 0x0,
	HIFC_MGMT_CMD_START_FLR                 = 0x1,
	HIFC_MGMT_CMD_FLUSH_DOORBELL            = 0x2,
	HIFC_MGMT_CMD_CMDQ_CTXT_SET             = 0x10,
	HIFC_MGMT_CMD_VAT_SET                   = 0x12,
	HIFC_MGMT_CMD_L2NIC_SQ_CI_ATTR_SET      = 0x14,
	HIFC_MGMT_CMD_PPF_TMR_SET               = 0x22,
	HIFC_MGMT_CMD_PPF_HT_GPA_SET            = 0x23,
	HIFC_MGMT_CMD_RES_STATE_SET             = 0x24,
	HIFC_MGMT_CMD_FUNC_TMR_BITMAT_SET       = 0x32,
	HIFC_MGMT_CMD_CEQ_CTRL_REG_WR_BY_UP     = 0x33,
	HIFC_MGMT_CMD_MSI_CTRL_REG_WR_BY_UP,
	HIFC_MGMT_CMD_MSI_CTRL_REG_RD_BY_UP,
	HIFC_MGMT_CMD_FAULT_REPORT              = 0x37,
	HIFC_MGMT_CMD_HEART_LOST_REPORT         = 0x38,
	HIFC_MGMT_CMD_SYNC_TIME                 = 0x46,
	HIFC_MGMT_CMD_REG_READ                  = 0x48,
	HIFC_MGMT_CMD_L2NIC_RESET               = 0x4b,
	HIFC_MGMT_CMD_ACTIVATE_FW               = 0x4F,
	HIFC_MGMT_CMD_PAGESIZE_SET              = 0x50,
	HIFC_MGMT_CMD_GET_BOARD_INFO            = 0x52,
	HIFC_MGMT_CMD_WATCHDOG_INFO             = 0x56,
	HIFC_MGMT_CMD_FMW_ACT_NTC               = 0x57,
	HIFC_MGMT_CMD_PCIE_DFX_NTC              = 0x65,
	HIFC_MGMT_CMD_PCIE_DFX_GET              = 0x66,
	HIFC_MGMT_CMD_GET_HOST_INFO             = 0x67,
	HIFC_MGMT_CMD_GET_PHY_INIT_STATUS       = 0x6A,
	HIFC_MGMT_CMD_HEARTBEAT_EVENT           = 0x6C,
};

#define HIFC_CLP_REG_GAP                       0x20
#define HIFC_CLP_INPUT_BUFFER_LEN_HOST         2048UL
#define HIFC_CLP_OUTPUT_BUFFER_LEN_HOST        2048UL
#define HIFC_CLP_DATA_UNIT_HOST                4UL
#define HIFC_BAR01_GLOABAL_CTL_OFFSET          0x4000
#define HIFC_BAR01_CLP_OFFSET                  0x5000

#define HIFC_CLP_SRAM_SIZE_REG         (HIFC_BAR01_GLOABAL_CTL_OFFSET + 0x220)
#define HIFC_CLP_REQ_SRAM_BA_REG       (HIFC_BAR01_GLOABAL_CTL_OFFSET + 0x224)
#define HIFC_CLP_RSP_SRAM_BA_REG       (HIFC_BAR01_GLOABAL_CTL_OFFSET + 0x228)
#define HIFC_CLP_REQ_REG               (HIFC_BAR01_GLOABAL_CTL_OFFSET + 0x22c)
#define HIFC_CLP_RSP_REG               (HIFC_BAR01_GLOABAL_CTL_OFFSET + 0x230)
#define HIFC_CLP_REG(member)           (HIFC_CLP_##member##_REG)

#define HIFC_CLP_REQ_DATA              (HIFC_BAR01_CLP_OFFSET)
#define HIFC_CLP_RSP_DATA              (HIFC_BAR01_CLP_OFFSET + 0x1000)
#define HIFC_CLP_DATA(member)          (HIFC_CLP_##member##_DATA)

#define HIFC_CLP_SRAM_SIZE_OFFSET      16
#define HIFC_CLP_SRAM_BASE_OFFSET      0
#define HIFC_CLP_LEN_OFFSET            0
#define HIFC_CLP_START_OFFSET          31
#define HIFC_CLP_READY_OFFSET          31
#define HIFC_CLP_OFFSET(member)        (HIFC_CLP_##member##_OFFSET)

#define HIFC_CLP_SRAM_SIZE_BIT_LEN             0x7ffUL
#define HIFC_CLP_SRAM_BASE_BIT_LEN             0x7ffffffUL
#define HIFC_CLP_LEN_BIT_LEN                   0x7ffUL
#define HIFC_CLP_START_BIT_LEN                 0x1UL
#define HIFC_CLP_READY_BIT_LEN                 0x1UL
#define HIFC_CLP_MASK(member)                  (HIFC_CLP_##member##_BIT_LEN)

#define HIFC_CLP_DELAY_CNT_MAX                 200UL
#define HIFC_CLP_SRAM_SIZE_REG_MAX             0x3ff
#define HIFC_CLP_SRAM_BASE_REG_MAX             0x7ffffff
#define HIFC_CLP_LEN_REG_MAX                   0x3ff
#define HIFC_CLP_START_OR_READY_REG_MAX        0x1
#define HIFC_MGMT_CMD_UNSUPPORTED              0xFF

enum hifc_msg_direction_type {
	HIFC_MSG_DIRECT_SEND    = 0,
	HIFC_MSG_RESPONSE       = 1
};

enum hifc_msg_segment_type {
	NOT_LAST_SEGMENT = 0,
	LAST_SEGMENT     = 1,
};

enum hifc_mgmt_msg_type {
	ASYNC_MGMT_MSG  = 0,
	SYNC_MGMT_MSG   = 1,
};

enum hifc_msg_ack_type {
	HIFC_MSG_ACK = 0,
	HIFC_MSG_NO_ACK = 1,
};

struct hifc_recv_msg {
	void *msg;

	struct completion recv_done;

	u16 msg_len;
	enum hifc_mod_type mod;
	u8 cmd;
	u8 seq_id;
	u16 msg_id;
	int async_mgmt_to_pf;
};

struct hifc_msg_head {
	u8 status;
	u8 version;
	u8 resp_aeq_num;
	u8 rsvd0[5];
};

#define HIFC_COMM_SELF_CMD_MAX 8

struct comm_up_self_msg_sub_info {
	u8 cmd;
	comm_up_self_msg_proc proc;
};

struct comm_up_self_msg_info {
	u8 cmd_num;
	struct comm_up_self_msg_sub_info info[HIFC_COMM_SELF_CMD_MAX];
};

enum comm_pf_to_mgmt_event_state {
	SEND_EVENT_UNINIT = 0,
	SEND_EVENT_START,
	SEND_EVENT_FAIL,
	SEND_EVENT_TIMEOUT,
	SEND_EVENT_END,
};

enum hifc_mgmt_msg_cb_state {
	HIFC_MGMT_MSG_CB_REG = 0,
	HIFC_MGMT_MSG_CB_RUNNING,
};

struct hifc_clp_pf_to_mgmt {
	struct semaphore clp_msg_lock;
	void *clp_msg_buf;
};

struct hifc_msg_pf_to_mgmt {
	struct hifc_hwdev *hwdev;

	/* Async cmd can not be scheduling */
	spinlock_t async_msg_lock;
	struct semaphore sync_msg_lock;

	struct workqueue_struct *workq;

	void *async_msg_buf;
	void *sync_msg_buf;
	void *mgmt_ack_buf;

	struct hifc_recv_msg recv_msg_from_mgmt;
	struct hifc_recv_msg recv_resp_msg_from_mgmt;

	u16 async_msg_id;
	u16 sync_msg_id;

	struct hifc_api_cmd_chain *cmd_chain[HIFC_API_CMD_MAX];

	hifc_mgmt_msg_cb recv_mgmt_msg_cb[HIFC_MOD_HW_MAX];
	void *recv_mgmt_msg_data[HIFC_MOD_HW_MAX];
	unsigned long mgmt_msg_cb_state[HIFC_MOD_HW_MAX];

	struct comm_up_self_msg_info proc;

	/* lock when sending msg */
	spinlock_t sync_event_lock;
	enum comm_pf_to_mgmt_event_state event_flag;
};

struct hifc_mgmt_msg_handle_work {
	struct work_struct work;
	struct hifc_msg_pf_to_mgmt *pf_to_mgmt;
	void *msg;
	u16 msg_len;
	enum hifc_mod_type mod;
	u8 cmd;
	u16 msg_id;
	int async_mgmt_to_pf;
};

/* show each drivers only such as nic_service_cap,
 * toe_service_cap structure, but not show service_cap
 */
enum hifc_service_type {
	SERVICE_T_NIC = 0,

	SERVICE_T_FC = 5,

	SERVICE_T_MAX,

	/* Only used for interruption resource management,
	 * mark the request module
	 */
	SERVICE_T_INTF   = (1 << 15),
	SERVICE_T_CQM    = (1 << 16),
};

/*  NIC service capability
 *  1, The chip supports NIC RQ is 1K
 *  2, PF/VF RQ specifications:
 *   disable RSS:
 *	 disable VMDq: Each PF/VF at most 8 RQ
 *	 enable the VMDq: Each PF/VF at most 1K RQ
 *   enable the RSS:
 *	 disable VMDq: each PF at most 64 RQ, VF at most 32 RQ
 *	 enable the VMDq: Each PF/VF at most 1K RQ
 *
 *  3, The chip supports NIC SQ is 1K
 *  4, PF/VF SQ specifications:
 *   disable RSS:
 *	 disable VMDq: Each PF/VF at most 8 SQ
 *	 enable the VMDq: Each PF/VF at most 1K SQ
 *   enable the RSS:
 *	 disable VMDq: each PF at most 64 SQ, VF at most 32 SQ
 *	 enable the VMDq: Each PF/VF at most 1K SQ
 */
struct nic_service_cap {
	/* PF resources*/
	u16 max_sqs;
	u16 max_rqs;

	/* VF resources, vf obtain through the MailBox mechanism from
	 * according PF
	 */
	u16 vf_max_sqs;
	u16 vf_max_rqs;
	bool lro_en;    /* LRO feature enable bit*/
	u8 lro_sz;      /* LRO context space: n*16B */
	u8 tso_sz;      /* TSO context space: n*16B */

	u16 max_queue_allowed;
};

/* PF FC service resource structure defined*/
struct dev_fc_svc_cap {
	/* PF Parent QPC */
	u32 max_parent_qpc_num; /* max number is 2048*/

	/* PF Child QPC */
	u32 max_child_qpc_num;  /* max number is 2048*/

	/* PF SCQ */
	u32 scq_num;            /* 16 */

	/* PF supports SRQ*/
	u32 srq_num;            /* Number of SRQ is 2*/

	u8 vp_id_start;
	u8 vp_id_end;
};

/* FC services*/
struct fc_service_cap {
	struct dev_fc_svc_cap dev_fc_cap;

	/* Parent QPC */
	u32 parent_qpc_size;    /* 256B */

	/* Child QPC */
	u32 child_qpc_size;     /* 256B */

	/* SQ */
	u32 sqe_size;           /* 128B(in linked list mode)*/

	/* SCQ */
	u32 scqc_size;          /* Size of the Context 32B*/
	u32 scqe_size;          /* 64B */

	/* SRQ */
	u32 srqc_size;          /* Size of SRQ Context (64B)*/
	u32 srqe_size;          /* 32B */
};

bool hifc_support_fc(void *hwdev, struct fc_service_cap *cap);

/* Service interface for obtaining service_cap public fields*/
/* Obtain service_cap.host_oq_id_mask_val*/
u8 hifc_host_oq_id_mask(void *hwdev);

/* Obtain service_cap.dev_cap.max_sqs*/
u16 hifc_func_max_qnum(void *hwdev);

/* The following information is obtained from the bar space
 * which is recorded by SDK layer.
 * Here provide parameter query interface for service
 */
/* func_attr.glb_func_idx, global function index */
u16 hifc_global_func_id(void *hwdev);
/* func_attr.intr_num, MSI-X table entry in function*/
enum intr_type {
	INTR_TYPE_MSIX,
	INTR_TYPE_MSI,
	INTR_TYPE_INT,
	INTR_TYPE_NONE,
};

u8 hifc_pcie_itf_id(void *hwdev); /* func_attr.itf_idx, pcie interface index */

/* func_attr.func_type, 0-PF 1-VF 2-PPF */
enum func_type hifc_func_type(void *hwdev);

u8 hifc_ppf_idx(void *hwdev);

enum hifc_msix_state {
	HIFC_MSIX_ENABLE,
	HIFC_MSIX_DISABLE,
};

void hifc_set_msix_state(void *hwdev, u16 msix_idx,
			 enum hifc_msix_state flag);

/* Defines the IRQ information structure*/
struct irq_info {
	u16 msix_entry_idx; /* IRQ corresponding index number */
	u32 irq_id;         /* the IRQ number from OS */
};

int hifc_alloc_irqs(void *hwdev, enum hifc_service_type type, u16 req_num,
		    struct irq_info *irq_info_array, u16 *resp_num);
void hifc_free_irq(void *hwdev, enum hifc_service_type type, u32 irq_id);

int hifc_sync_time(void *hwdev, u64 time);
void hifc_disable_mgmt_msg_report(void *hwdev);
void hifc_set_func_deinit_flag(void *hwdev);
void hifc_flush_mgmt_workq(void *hwdev);
int hifc_global_func_id_get(void *hwdev, u16 *func_id);
u16 hifc_global_func_id_hw(void *hwdev);
int hifc_pf_to_mgmt_no_ack(void *hwdev, enum hifc_mod_type mod, u8 cmd,
			   void *buf_in, u16 in_size);
void hifc_mgmt_msg_aeqe_handler(void *handle, u8 *header, u8 size);
int hifc_pf_to_mgmt_init(struct hifc_hwdev *hwdev);
void hifc_pf_to_mgmt_free(struct hifc_hwdev *hwdev);
int hifc_pf_to_mgmt_sync(void *hwdev, enum hifc_mod_type mod, u8 cmd,
			 void *buf_in, u16 in_size, void *buf_out,
			 u16 *out_size, u32 timeout);
int hifc_pf_to_mgmt_async(void *hwdev, enum hifc_mod_type mod, u8 cmd,
			  void *buf_in, u16 in_size);
int hifc_pf_clp_to_mgmt(void *hwdev, enum hifc_mod_type mod, u8 cmd,
			const void *buf_in, u16 in_size,
			void *buf_out, u16 *out_size);
int hifc_clp_pf_to_mgmt_init(struct hifc_hwdev *hwdev);
void hifc_clp_pf_to_mgmt_free(struct hifc_hwdev *hwdev);

#endif
