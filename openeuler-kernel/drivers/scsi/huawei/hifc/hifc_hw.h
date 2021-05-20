/* SPDX-License-Identifier: GPL-2.0 */
/* Huawei Hifc PCI Express Linux driver
 * Copyright(c) 2017 Huawei Technologies Co., Ltd
 *
 */

#ifndef HIFC_HW_H_
#define HIFC_HW_H_

#ifndef __BIG_ENDIAN__
#define __BIG_ENDIAN__    0x4321
#endif

#ifndef __LITTLE_ENDIAN__
#define __LITTLE_ENDIAN__    0x1234
#endif

enum hifc_mod_type {
	HIFC_MOD_COMM = 0,    /* HW communication module */
	HIFC_MOD_L2NIC = 1,   /* L2NIC module*/
	HIFC_MOD_FCOE = 6,
	HIFC_MOD_CFGM = 7,    /* Configuration module */
	HIFC_MOD_FC = 10,
	HIFC_MOD_HILINK = 14,
	HIFC_MOD_HW_MAX = 16, /* hardware max module id */

	/* Software module id, for PF/VF and multi-host */
	HIFC_MOD_MAX,
};

struct hifc_cmd_buf {
	void *buf;
	dma_addr_t dma_addr;
	u16 size;
};

enum hifc_ack_type {
	HIFC_ACK_TYPE_CMDQ,
	HIFC_ACK_TYPE_SHARE_CQN,
	HIFC_ACK_TYPE_APP_CQN,
	HIFC_MOD_ACK_MAX = 15,
};

int hifc_msg_to_mgmt_sync(void *hwdev, enum hifc_mod_type mod, u8 cmd,
			  void *buf_in, u16 in_size,
			  void *buf_out, u16 *out_size, u32 timeout);

/* PF/VF send msg to uP by api cmd, and return immediately */
int hifc_msg_to_mgmt_async(void *hwdev, enum hifc_mod_type mod, u8 cmd,
			   void *buf_in, u16 in_size);

int hifc_api_cmd_write_nack(void *hwdev, u8 dest,
			    void *cmd, u16 size);

int hifc_api_cmd_read_ack(void *hwdev, u8 dest,
			  void *cmd, u16 size, void *ack, u16 ack_size);
/* PF/VF send cmd to ucode by cmdq, and return if success.
 * timeout=0, use default timeout.
 */
int hifc_cmdq_direct_resp(void *hwdev, enum hifc_ack_type ack_type,
			  enum hifc_mod_type mod, u8 cmd,
			  struct hifc_cmd_buf *buf_in,
			  u64 *out_param, u32 timeout);
/* 1. whether need the timeout parameter
 * 2. out_param indicates the status of the microcode processing command
 */

/* PF/VF send cmd to ucode by cmdq, and return detailed result.
 * timeout=0, use default timeout.
 */
int hifc_cmdq_detail_resp(void *hwdev, enum hifc_ack_type ack_type,
			  enum hifc_mod_type mod, u8 cmd,
			  struct hifc_cmd_buf *buf_in,
			  struct hifc_cmd_buf *buf_out, u32 timeout);

/* PF/VF send cmd to ucode by cmdq, and return immediately
 */
int hifc_cmdq_async(void *hwdev, enum hifc_ack_type ack_type,
		    enum hifc_mod_type mod, u8 cmd,
		    struct hifc_cmd_buf *buf_in);

int hifc_ppf_tmr_start(void *hwdev);
int hifc_ppf_tmr_stop(void *hwdev);

enum hifc_ceq_event {
	HIFC_CMDQ = 3,
	HIFC_MAX_CEQ_EVENTS = 6,
};

typedef void (*hifc_ceq_event_cb)(void *handle, u32 ceqe_data);
int hifc_ceq_register_cb(void *hwdev, enum hifc_ceq_event event,
			 hifc_ceq_event_cb callback);
void hifc_ceq_unregister_cb(void *hwdev, enum hifc_ceq_event event);

enum hifc_aeq_type {
	HIFC_HW_INTER_INT = 0,
	HIFC_MBX_FROM_FUNC = 1,
	HIFC_MSG_FROM_MGMT_CPU = 2,
	HIFC_API_RSP = 3,
	HIFC_API_CHAIN_STS = 4,
	HIFC_MBX_SEND_RSLT = 5,
	HIFC_MAX_AEQ_EVENTS
};

enum hifc_aeq_sw_type {
	HIFC_STATELESS_EVENT = 0,
	HIFC_STATEFULL_EVENT = 1,
	HIFC_MAX_AEQ_SW_EVENTS
};

typedef void (*hifc_aeq_hwe_cb)(void *handle, u8 *data, u8 size);
int hifc_aeq_register_hw_cb(void *hwdev, enum hifc_aeq_type event,
			    hifc_aeq_hwe_cb hwe_cb);
void hifc_aeq_unregister_hw_cb(void *hwdev, enum hifc_aeq_type event);

typedef u8 (*hifc_aeq_swe_cb)(void *handle, u8 event, u64 data);
int hifc_aeq_register_swe_cb(void *hwdev, enum hifc_aeq_sw_type event,
			     hifc_aeq_swe_cb aeq_swe_cb);
void hifc_aeq_unregister_swe_cb(void *hwdev, enum hifc_aeq_sw_type event);

typedef void (*hifc_mgmt_msg_cb)(void *hwdev, void *pri_handle,
	u8 cmd, void *buf_in, u16 in_size, void *buf_out, u16 *out_size);

int hifc_register_mgmt_msg_cb(void *hwdev,
			      enum hifc_mod_type mod, void *pri_handle,
			      hifc_mgmt_msg_cb callback);
void hifc_unregister_mgmt_msg_cb(void *hwdev, enum hifc_mod_type mod);

struct hifc_cmd_buf *hifc_alloc_cmd_buf(void *hwdev);
void hifc_free_cmd_buf(void *hwdev, struct hifc_cmd_buf *buf);

int hifc_alloc_db_addr(void *hwdev, void __iomem **db_base,
		       void __iomem **dwqe_base);
void hifc_free_db_addr(void *hwdev, void __iomem *db_base,
		       void __iomem *dwqe_base);

struct nic_interrupt_info {
	u32 lli_set;
	u32 interrupt_coalesc_set;
	u16 msix_index;
	u8 lli_credit_limit;
	u8 lli_timer_cfg;
	u8 pending_limt;
	u8 coalesc_timer_cfg;
	u8 resend_timer_cfg;
};

int hifc_get_interrupt_cfg(void *hwdev,
			   struct nic_interrupt_info *interrupt_info);

int hifc_set_interrupt_cfg(void *hwdev,
			   struct nic_interrupt_info interrupt_info);

/* The driver code implementation interface*/
void hifc_misx_intr_clear_resend_bit(void *hwdev,
				     u16 msix_idx, u8 clear_resend_en);

struct hifc_sq_attr {
	u8 dma_attr_off;
	u8 pending_limit;
	u8 coalescing_time;
	u8 intr_en;
	u16 intr_idx;
	u32 l2nic_sqn;
	u64 ci_dma_base;
};

int hifc_set_ci_table(void *hwdev, u16 q_id, struct hifc_sq_attr *attr);

int hifc_set_root_ctxt(void *hwdev, u16 rq_depth, u16 sq_depth, int rx_buf_sz);
int hifc_clean_root_ctxt(void *hwdev);
void hifc_record_pcie_error(void *hwdev);

int hifc_func_rx_tx_flush(void *hwdev);

int hifc_func_tmr_bitmap_set(void *hwdev, bool enable);

struct hifc_init_para {
	/* Record hifc_pcidev or NDIS_Adapter pointer address*/
	void *adapter_hdl;
	/* Record pcidev or Handler pointer address
	 * for example: ioremap interface input parameter
	 */
	void *pcidev_hdl;
	/* Record pcidev->dev or Handler pointer address which used to
	 * dma address application or dev_err print the parameter
	 */
	void *dev_hdl;

	void *cfg_reg_base;	/* Configure virtual address, bar0/1*/
	/* interrupt configuration register address, bar2/3 */
	void *intr_reg_base;
	u64 db_base_phy;
	void *db_base;	/* the doorbell address, bar4/5 higher 4M space*/
	void *dwqe_mapping;/* direct wqe 4M, follow the doorbell address space*/
	void **hwdev;
	void *chip_node;
	/* In bmgw x86 host, driver can't send message to mgmt cpu directly,
	 * need to trasmit message ppf mbox to bmgw arm host.
	 */
	void *ppf_hwdev;
};

#ifndef IFNAMSIZ
#define IFNAMSIZ    16
#endif
#define MAX_FUNCTION_NUM 512
#define HIFC_MAX_PF_NUM 16
#define HIFC_MAX_COS 8
#define INIT_FAILED 0
#define INIT_SUCCESS 1
#define MAX_DRV_BUF_SIZE 4096

struct hifc_cmd_get_light_module_abs {
	u8 status;
	u8 version;
	u8 rsvd0[6];

	u8 port_id;
	u8 abs_status; /* 0:present, 1:absent */
	u8 rsv[2];
};

#define SFP_INFO_MAX_SIZE 512
struct hifc_cmd_get_sfp_qsfp_info {
	u8 status;
	u8 version;
	u8 rsvd0[6];

	u8 port_id;
	u8 wire_type;
	u16 out_len;
	u8 sfp_qsfp_info[SFP_INFO_MAX_SIZE];
};

#define HIFC_MAX_PORT_ID                  4

struct hifc_port_routine_cmd {
	bool up_send_sfp_info;
	bool up_send_sfp_abs;

	struct hifc_cmd_get_sfp_qsfp_info sfp_info;
	struct hifc_cmd_get_light_module_abs abs;
};

struct card_node {
	struct list_head node;
	struct list_head func_list;
	char chip_name[IFNAMSIZ];
	void *log_info;
	void *dbgtool_info;
	void *func_handle_array[MAX_FUNCTION_NUM];
	unsigned char dp_bus_num;
	u8 func_num;
	struct attribute dbgtool_attr_file;

	bool cos_up_setted;
	u8 cos_up[HIFC_MAX_COS];
	bool ppf_state;
	u8 pf_bus_num[HIFC_MAX_PF_NUM];

	struct hifc_port_routine_cmd rt_cmd[HIFC_MAX_PORT_ID];

	/* mutex used for copy sfp info */
	struct mutex sfp_mutex;
};

enum hifc_hwdev_init_state {
	HIFC_HWDEV_NONE_INITED = 0,
	HIFC_HWDEV_CLP_INITED,
	HIFC_HWDEV_AEQ_INITED,
	HIFC_HWDEV_MGMT_INITED,
	HIFC_HWDEV_MBOX_INITED,
	HIFC_HWDEV_CMDQ_INITED,
	HIFC_HWDEV_COMM_CH_INITED,
	HIFC_HWDEV_ALL_INITED,
	HIFC_HWDEV_MAX_INVAL_INITED
};

enum hifc_func_cap {
	/* send message to mgmt cpu directly */
	HIFC_FUNC_MGMT = 1 << 0,
	/* setting port attribute, pause/speed etc. */
	HIFC_FUNC_PORT = 1 << 1,
	/* Enable SR-IOV in default */
	HIFC_FUNC_SRIOV_EN_DFLT = 1 << 2,
	/* Can't change VF num */
	HIFC_FUNC_SRIOV_NUM_FIX = 1 << 3,
	/* Fcorce pf/vf link up */
	HIFC_FUNC_FORCE_LINK_UP = 1 << 4,
	/* Support rate limit */
	HIFC_FUNC_SUPP_RATE_LIMIT = 1 << 5,
	HIFC_FUNC_SUPP_DFX_REG = 1 << 6,
	/* Support promisc/multicast/all-multi */
	HIFC_FUNC_SUPP_RX_MODE = 1 << 7,
	/* Set vf mac and vlan by ip link */
	HIFC_FUNC_SUPP_SET_VF_MAC_VLAN = 1 << 8,
	/* Support set mac by ifconfig */
	HIFC_FUNC_SUPP_CHANGE_MAC = 1 << 9,
	/* OVS don't support SCTP_CRC/HW_VLAN/LRO */
	HIFC_FUNC_OFFLOAD_OVS_UNSUPP = 1 << 10,
};

#define FUNC_SUPPORT_MGMT(hwdev)                \
	(!!(hifc_get_func_feature_cap(hwdev) & HIFC_FUNC_MGMT))
#define FUNC_SUPPORT_PORT_SETTING(hwdev)        \
	(!!(hifc_get_func_feature_cap(hwdev) & HIFC_FUNC_PORT))
#define FUNC_SUPPORT_DCB(hwdev)                 \
	(FUNC_SUPPORT_PORT_SETTING(hwdev))
#define FUNC_ENABLE_SRIOV_IN_DEFAULT(hwdev)     \
	(!!(hifc_get_func_feature_cap(hwdev) &  \
	    HIFC_FUNC_SRIOV_EN_DFLT))
#define FUNC_SRIOV_FIX_NUM_VF(hwdev)            \
	(!!(hifc_get_func_feature_cap(hwdev) &  \
	    HIFC_FUNC_SRIOV_NUM_FIX))
#define FUNC_SUPPORT_RX_MODE(hwdev)             \
	(!!(hifc_get_func_feature_cap(hwdev) &  \
	    HIFC_FUNC_SUPP_RX_MODE))
#define FUNC_SUPPORT_RATE_LIMIT(hwdev)          \
	(!!(hifc_get_func_feature_cap(hwdev) &  \
	    HIFC_FUNC_SUPP_RATE_LIMIT))
#define FUNC_SUPPORT_SET_VF_MAC_VLAN(hwdev)     \
	(!!(hifc_get_func_feature_cap(hwdev) &  \
	    HIFC_FUNC_SUPP_SET_VF_MAC_VLAN))
#define FUNC_SUPPORT_CHANGE_MAC(hwdev)          \
	(!!(hifc_get_func_feature_cap(hwdev) &  \
	    HIFC_FUNC_SUPP_CHANGE_MAC))
#define FUNC_FORCE_LINK_UP(hwdev)               \
	(!!(hifc_get_func_feature_cap(hwdev) &  \
	    HIFC_FUNC_FORCE_LINK_UP))
#define FUNC_SUPPORT_SCTP_CRC(hwdev)            \
	(!(hifc_get_func_feature_cap(hwdev) &   \
	   HIFC_FUNC_OFFLOAD_OVS_UNSUPP))
#define FUNC_SUPPORT_HW_VLAN(hwdev)             \
	(!(hifc_get_func_feature_cap(hwdev) &   \
	   HIFC_FUNC_OFFLOAD_OVS_UNSUPP))
#define FUNC_SUPPORT_LRO(hwdev)                 \
	(!(hifc_get_func_feature_cap(hwdev) &   \
	   HIFC_FUNC_OFFLOAD_OVS_UNSUPP))

int hifc_init_hwdev(struct hifc_init_para *para);
void hifc_free_hwdev(void *hwdev);
int hifc_stateful_init(void *hwdev);
void hifc_stateful_deinit(void *hwdev);
bool hifc_is_hwdev_mod_inited(void *hwdev, enum hifc_hwdev_init_state state);
u64 hifc_get_func_feature_cap(void *hwdev);
int hifc_slq_init(void *dev, int num_wqs);
void hifc_slq_uninit(void *dev);
int hifc_slq_alloc(void *dev, u16 wqebb_size, u16 q_depth,
		   u16 page_size, u64 *cla_addr, void **handle);
void hifc_slq_free(void *dev, void *handle);
u64 hifc_slq_get_addr(void *handle, u16 index);
u64 hifc_slq_get_first_pageaddr(void *handle);

typedef void (*comm_up_self_msg_proc)(void *handle, void *buf_in,
				      u16 in_size, void *buf_out,
				      u16 *out_size);
void hifc_comm_recv_mgmt_self_cmd_reg(void *hwdev, u8 cmd,
				      comm_up_self_msg_proc proc);
void hifc_comm_recv_up_self_cmd_unreg(void *hwdev, u8 cmd);

/* defined by chip */
enum hifc_fault_type {
	FAULT_TYPE_CHIP,
	FAULT_TYPE_UCODE,
	FAULT_TYPE_MEM_RD_TIMEOUT,
	FAULT_TYPE_MEM_WR_TIMEOUT,
	FAULT_TYPE_REG_RD_TIMEOUT,
	FAULT_TYPE_REG_WR_TIMEOUT,
	FAULT_TYPE_PHY_FAULT,
	FAULT_TYPE_MAX,
};

/* defined by chip */
enum hifc_fault_err_level {
	/* default err_level=FAULT_LEVEL_FATAL if
	 * type==FAULT_TYPE_MEM_RD_TIMEOUT || FAULT_TYPE_MEM_WR_TIMEOUT ||
	 * FAULT_TYPE_REG_RD_TIMEOUT || FAULT_TYPE_REG_WR_TIMEOUT ||
	 * FAULT_TYPE_UCODE
	 * other: err_level in event.chip.err_level if type==FAULT_TYPE_CHIP
	 */
	FAULT_LEVEL_FATAL,
	FAULT_LEVEL_SERIOUS_RESET,
	FAULT_LEVEL_SERIOUS_FLR,
	FAULT_LEVEL_GENERAL,
	FAULT_LEVEL_SUGGESTION,
	FAULT_LEVEL_MAX
};

enum hifc_fault_source_type {
	/* same as FAULT_TYPE_CHIP */
	HIFC_FAULT_SRC_HW_MGMT_CHIP = 0,
	/* same as FAULT_TYPE_UCODE */
	HIFC_FAULT_SRC_HW_MGMT_UCODE,
	/* same as FAULT_TYPE_MEM_RD_TIMEOUT */
	HIFC_FAULT_SRC_HW_MGMT_MEM_RD_TIMEOUT,
	/* same as FAULT_TYPE_MEM_WR_TIMEOUT */
	HIFC_FAULT_SRC_HW_MGMT_MEM_WR_TIMEOUT,
	/* same as FAULT_TYPE_REG_RD_TIMEOUT */
	HIFC_FAULT_SRC_HW_MGMT_REG_RD_TIMEOUT,
	/* same as FAULT_TYPE_REG_WR_TIMEOUT */
	HIFC_FAULT_SRC_HW_MGMT_REG_WR_TIMEOUT,
	HIFC_FAULT_SRC_SW_MGMT_UCODE,
	HIFC_FAULT_SRC_MGMT_WATCHDOG,
	HIFC_FAULT_SRC_MGMT_RESET = 8,
	HIFC_FAULT_SRC_HW_PHY_FAULT,
	HIFC_FAULT_SRC_HOST_HEARTBEAT_LOST = 20,
	HIFC_FAULT_SRC_TYPE_MAX,
};

struct hifc_fault_sw_mgmt {
	u8 event_id;
	u64 event_data;
};

union hifc_fault_hw_mgmt {
	u32 val[4];
	/* valid only type==FAULT_TYPE_CHIP */
	struct {
		u8 node_id;
		/* enum hifc_fault_err_level */
		u8 err_level;
		u16 err_type;
		u32 err_csr_addr;
		u32 err_csr_value;
		/* func_id valid only err_level==FAULT_LEVEL_SERIOUS_FLR
		 */
		u16 func_id;
		u16 rsvd2;
	} chip;

	/* valid only type==FAULT_TYPE_UCODE */
	struct {
		u8 cause_id;
		u8 core_id;
		u8 c_id;
		u8 rsvd3;
		u32 epc;
		u32 rsvd4;
		u32 rsvd5;
	} ucode;

	/* valid only type==FAULT_TYPE_MEM_RD_TIMEOUT ||
	 * FAULT_TYPE_MEM_WR_TIMEOUT
	 */
	struct {
		u32 err_csr_ctrl;
		u32 err_csr_data;
		u32 ctrl_tab;
		u32 mem_index;
	} mem_timeout;

	/* valid only type==FAULT_TYPE_REG_RD_TIMEOUT ||
	 * FAULT_TYPE_REG_WR_TIMEOUT
	 */
	struct {
		u32 err_csr;
		u32 rsvd6;
		u32 rsvd7;
		u32 rsvd8;
	} reg_timeout;

	struct {
		/* 0: read; 1: write */
		u8 op_type;
		u8 port_id;
		u8 dev_ad;
		u8 rsvd9;
		u32 csr_addr;
		u32 op_data;
		u32 rsvd10;
	} phy_fault;
};

/* defined by chip */
struct hifc_fault_event {
	/* enum hifc_fault_type */
	u8 type;
	u8 rsvd0[3];
	union hifc_fault_hw_mgmt event;
};

struct hifc_fault_recover_info {
	u8 fault_src; /* enum hifc_fault_source_type */
	u8 fault_lev; /* enum hifc_fault_err_level */
	u8 rsvd0[2];
	union {
		union hifc_fault_hw_mgmt hw_mgmt;
		struct hifc_fault_sw_mgmt sw_mgmt;
		u32 mgmt_rsvd[4];
		u32 host_rsvd[4];
	} fault_data;
};

struct hifc_dcb_state {
	u8 dcb_on;
	u8 default_cos;
	u8 up_cos[8];
};

enum link_err_type {
	LINK_ERR_MODULE_UNRECOGENIZED,
	LINK_ERR_NUM,
};

enum port_module_event_type {
	HIFC_PORT_MODULE_CABLE_PLUGGED,
	HIFC_PORT_MODULE_CABLE_UNPLUGGED,
	HIFC_PORT_MODULE_LINK_ERR,
	HIFC_PORT_MODULE_MAX_EVENT,
};

struct hifc_port_module_event {
	enum port_module_event_type type;
	enum link_err_type err_type;
};

struct hifc_event_link_info {
	u8 valid;
	u8 port_type;
	u8 autoneg_cap;
	u8 autoneg_state;
	u8 duplex;
	u8 speed;
};

struct hifc_mctp_host_info {
	u8 major_cmd;
	u8 sub_cmd;
	u8 rsvd[2];

	u32 data_len;
	void *data;
};

enum hifc_event_type {
	HIFC_EVENT_LINK_DOWN = 0,
	HIFC_EVENT_LINK_UP = 1,
	HIFC_EVENT_HEART_LOST = 2,
	HIFC_EVENT_FAULT = 3,
	HIFC_EVENT_NOTIFY_VF_DCB_STATE = 4,
	HIFC_EVENT_DCB_STATE_CHANGE = 5,
	HIFC_EVENT_FMW_ACT_NTC = 6,
	HIFC_EVENT_PORT_MODULE_EVENT = 7,
	HIFC_EVENT_MCTP_GET_HOST_INFO,
	HIFC_EVENT_MULTI_HOST_MGMT,
	HIFC_EVENT_INIT_MIGRATE_PF,
};

struct hifc_event_info {
	enum hifc_event_type type;
	union {
		struct hifc_event_link_info link_info;
		struct hifc_fault_event info;
		struct hifc_dcb_state dcb_state;
		struct hifc_port_module_event module_event;
		u8 vf_default_cos;
		struct hifc_mctp_host_info mctp_info;
	};
};

enum hifc_ucode_event_type {
	HIFC_INTERNAL_TSO_FATAL_ERROR = 0x0,
	HIFC_INTERNAL_LRO_FATAL_ERROR = 0x1,
	HIFC_INTERNAL_TX_FATAL_ERROR = 0x2,
	HIFC_INTERNAL_RX_FATAL_ERROR = 0x3,
	HIFC_INTERNAL_OTHER_FATAL_ERROR = 0x4,
	HIFC_NIC_FATAL_ERROR_MAX = 0x8,
};

typedef void (*hifc_event_handler)(void *handle,
		struct hifc_event_info *event);
/* only register once */
void hifc_event_register(void *dev, void *pri_handle,
			 hifc_event_handler callback);
void hifc_event_unregister(void *dev);

void hifc_detect_hw_present(void *hwdev);

void hifc_set_chip_absent(void *hwdev);

int hifc_get_chip_present_flag(void *hwdev);

void hifc_set_pcie_order_cfg(void *handle);

int hifc_get_mgmt_channel_status(void *handle);

struct hifc_board_info {
	u32 board_type;
	u32 port_num;
	u32 port_speed;
	u32 pcie_width;
	u32 host_num;
	u32 pf_num;
	u32 vf_total_num;
	u32 tile_num;
	u32 qcm_num;
	u32 core_num;
	u32 work_mode;
	u32 service_mode;
	u32 pcie_mode;
	u32 cfg_addr;
	u32 boot_sel;
	u32 board_id;
};

int hifc_get_board_info(void *hwdev, struct hifc_board_info *info);

int hifc_get_card_present_state(void *hwdev, bool *card_present_state);

#endif
