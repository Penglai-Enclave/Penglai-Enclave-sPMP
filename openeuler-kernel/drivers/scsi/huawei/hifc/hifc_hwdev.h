/* SPDX-License-Identifier: GPL-2.0 */
/* Huawei Hifc PCI Express Linux driver
 * Copyright(c) 2017 Huawei Technologies Co., Ltd
 *
 */

#ifndef HIFC_HWDEV_H_
#define HIFC_HWDEV_H_

/* to use 0-level CLA, page size must be: 64B(wqebb) * 4096(max_q_depth) */
#define HIFC_DEFAULT_WQ_PAGE_SIZE	0x40000
#define HIFC_HW_WQ_PAGE_SIZE		0x1000

#define HIFC_MSG_TO_MGMT_MAX_LEN		2016

#define HIFC_MGMT_STATUS_ERR_OK          0    /* Ok */
#define HIFC_MGMT_STATUS_ERR_PARAM       1    /* Invalid parameter */
#define HIFC_MGMT_STATUS_ERR_FAILED      2    /* Operation failed */
#define HIFC_MGMT_STATUS_ERR_PORT        3    /* Invalid port */
#define HIFC_MGMT_STATUS_ERR_TIMEOUT     4    /* Operation time out */
#define HIFC_MGMT_STATUS_ERR_NOMATCH     5    /* Version not match */
#define HIFC_MGMT_STATUS_ERR_EXIST       6    /* Entry exists */
#define HIFC_MGMT_STATUS_ERR_NOMEM       7    /* Out of memory */
#define HIFC_MGMT_STATUS_ERR_INIT        8    /* Feature not initialized */
#define HIFC_MGMT_STATUS_ERR_FAULT       9    /* Invalid address */
#define HIFC_MGMT_STATUS_ERR_PERM        10   /* Operation not permitted */
#define HIFC_MGMT_STATUS_ERR_EMPTY       11   /* Table empty */
#define HIFC_MGMT_STATUS_ERR_FULL        12   /* Table full */
#define HIFC_MGMT_STATUS_ERR_NOT_FOUND   13   /* Not found */
#define HIFC_MGMT_STATUS_ERR_BUSY        14   /* Device or resource busy */
#define HIFC_MGMT_STATUS_ERR_RESOURCE    15   /* No resources for operation */
#define HIFC_MGMT_STATUS_ERR_CONFIG      16   /* Invalid configuration */
#define HIFC_MGMT_STATUS_ERR_UNAVAIL     17   /* Feature unavailable */
#define HIFC_MGMT_STATUS_ERR_CRC         18   /* CRC check failed */
#define HIFC_MGMT_STATUS_ERR_NXIO        19   /* No such device or address */
#define HIFC_MGMT_STATUS_ERR_ROLLBACK    20   /* Chip rollback fail */
#define HIFC_MGMT_STATUS_ERR_LEN         32   /* Length too short or too long */
#define HIFC_MGMT_STATUS_ERR_UNSUPPORT   0xFF /* Feature not supported*/
/* Qe buffer relates define */

enum hifc_rx_buf_size {
	HIFC_RX_BUF_SIZE_32B = 0x20,
	HIFC_RX_BUF_SIZE_64B = 0x40,
	HIFC_RX_BUF_SIZE_96B = 0x60,
	HIFC_RX_BUF_SIZE_128B = 0x80,
	HIFC_RX_BUF_SIZE_192B = 0xC0,
	HIFC_RX_BUF_SIZE_256B = 0x100,
	HIFC_RX_BUF_SIZE_384B = 0x180,
	HIFC_RX_BUF_SIZE_512B = 0x200,
	HIFC_RX_BUF_SIZE_768B = 0x300,
	HIFC_RX_BUF_SIZE_1K = 0x400,
	HIFC_RX_BUF_SIZE_1_5K = 0x600,
	HIFC_RX_BUF_SIZE_2K = 0x800,
	HIFC_RX_BUF_SIZE_3K = 0xC00,
	HIFC_RX_BUF_SIZE_4K = 0x1000,
	HIFC_RX_BUF_SIZE_8K = 0x2000,
	HIFC_RX_BUF_SIZE_16K = 0x4000,
};

enum hifc_res_state {
	HIFC_RES_CLEAN = 0,
	HIFC_RES_ACTIVE = 1,
};

enum ppf_tmr_status {
	HIFC_PPF_TMR_FLAG_STOP,
	HIFC_PPF_TMR_FLAG_START,
};

struct cfg_mgmt_info;
struct hifc_hwif;
struct hifc_wqs;
struct hifc_aeqs;
struct hifc_ceqs;
struct hifc_msg_pf_to_mgmt;
struct hifc_cmdqs;

struct hifc_root_ctxt {
	u8 status;
	u8 version;
	u8 rsvd0[6];

	u16 func_idx;
	u16 rsvd1;
	u8 set_cmdq_depth;
	u8 cmdq_depth;
	u8 lro_en;
	u8 rsvd2;
	u8 ppf_idx;
	u8 rsvd3;
	u16 rq_depth;
	u16 rx_buf_sz;
	u16 sq_depth;
};

struct hifc_page_addr {
	void *virt_addr;
	u64 phys_addr;
};

#define HIFC_PCIE_LINK_DOWN             0xFFFFFFFF

#define HIFC_DEV_ACTIVE_FW_TIMEOUT      (35 * 1000)
#define HIFC_DEV_BUSY_ACTIVE_FW	0xFE

#define HIFC_HW_WQ_NAME                 "hifc_hardware"
#define HIFC_HEARTBEAT_PERIOD           1000
#define HIFC_HEARTBEAT_START_EXPIRE     5000

#define HIFC_CHIP_ERROR_TYPE_MAX        1024
#define HIFC_CHIP_FAULT_SIZE \
	(HIFC_NODE_ID_MAX * FAULT_LEVEL_MAX * HIFC_CHIP_ERROR_TYPE_MAX)

#define HIFC_CSR_DMA_ATTR_TBL_BASE      0xC80
#define HIFC_CSR_DMA_ATTR_TBL_STRIDE    0x4
#define HIFC_CSR_DMA_ATTR_TBL_ADDR(idx) \
		(HIFC_CSR_DMA_ATTR_TBL_BASE \
		+ (idx) * HIFC_CSR_DMA_ATTR_TBL_STRIDE)

/* MSI-X registers */
#define HIFC_CSR_MSIX_CNT_BASE          0x2004
#define HIFC_CSR_MSIX_STRIDE            0x8

#define HIFC_CSR_MSIX_CNT_ADDR(idx) \
	(HIFC_CSR_MSIX_CNT_BASE + (idx) * HIFC_CSR_MSIX_STRIDE)

enum hifc_node_id {
	HIFC_NODE_ID_IPSU = 4,
	HIFC_NODE_ID_MGMT_HOST = 21, /*Host CPU send API to uP */
	HIFC_NODE_ID_MAX = 22
};

#define HIFC_HWDEV_INIT_MODES_MASK      ((1UL << HIFC_HWDEV_ALL_INITED) - 1)

enum hifc_hwdev_func_state {
	HIFC_HWDEV_FUNC_INITED = HIFC_HWDEV_ALL_INITED,
	HIFC_HWDEV_FUNC_DEINIT,
	HIFC_HWDEV_STATE_BUSY = 31,
};

struct hifc_cqm_stats {
	atomic_t cqm_cmd_alloc_cnt;
	atomic_t cqm_cmd_free_cnt;
	atomic_t cqm_send_cmd_box_cnt;
	atomic_t cqm_db_addr_alloc_cnt;
	atomic_t cqm_db_addr_free_cnt;
	atomic_t cqm_fc_srq_create_cnt;
	atomic_t cqm_qpc_mpt_create_cnt;
	atomic_t cqm_nonrdma_queue_create_cnt;
	atomic_t cqm_qpc_mpt_delete_cnt;
	atomic_t cqm_nonrdma_queue_delete_cnt;
	atomic_t cqm_aeq_callback_cnt[112];
};

struct hifc_link_event_stats {
	atomic_t link_down_stats;
	atomic_t link_up_stats;
};

struct hifc_fault_event_stats {
	atomic_t chip_fault_stats[HIFC_NODE_ID_MAX][FAULT_LEVEL_MAX];
	atomic_t fault_type_stat[FAULT_TYPE_MAX];
	atomic_t pcie_fault_stats;
};

struct hifc_hw_stats {
	atomic_t heart_lost_stats;
	atomic_t nic_ucode_event_stats[HIFC_NIC_FATAL_ERROR_MAX];
	struct hifc_cqm_stats cqm_stats;
	struct hifc_link_event_stats link_event_stats;
	struct hifc_fault_event_stats fault_event_stats;
};

struct hifc_fault_info_node {
	struct list_head list;
	struct hifc_hwdev *hwdev;
	struct hifc_fault_recover_info info;
};

enum heartbeat_support_state {
	HEARTBEAT_NOT_SUPPORT = 0,
	HEARTBEAT_SUPPORT,
};

/* 25s for max 5 heartbeat event lost */
#define HIFC_HEARBEAT_ENHANCED_LOST    25000
struct hifc_heartbeat_enhanced {
	bool en; /* enable enhanced heartbeat or not */

	unsigned long last_update_jiffies;
	u32 last_heartbeat;

	unsigned long start_detect_jiffies;
};

#define HIFC_CMD_VER_FUNC_ID                   2
#define HIFC_GLB_DMA_SO_RO_REPLACE_ADDR        0x488C
#define HIFC_ICPL_RESERVD_ADDR                 0x9204

#define l2nic_msg_to_mgmt_sync(hwdev, cmd, buf_in, in_size, buf_out, out_size)\
	hifc_msg_to_mgmt_sync(hwdev, HIFC_MOD_L2NIC, cmd, \
			       buf_in, in_size, \
			       buf_out, out_size, 0)

struct hifc_hwdev {
	void *adapter_hdl;  /* pointer to hifc_pcidev or NDIS_Adapter */
	void *pcidev_hdl;   /* pointer to pcidev or Handler */
	void *dev_hdl;      /* pointer to pcidev->dev or Handler, for
			     * sdk_err() or dma_alloc()
			     */
	u32 wq_page_size;

	void *cqm_hdl;
	void *chip_node;

	struct hifc_hwif *hwif; /* include void __iomem *bar */
	struct cfg_mgmt_info *cfg_mgmt;
	struct hifc_wqs *wqs;   /* for FC slq */

	struct hifc_aeqs *aeqs;
	struct hifc_ceqs *ceqs;

	struct hifc_msg_pf_to_mgmt *pf_to_mgmt;
	struct hifc_clp_pf_to_mgmt *clp_pf_to_mgmt;

	struct hifc_cmdqs *cmdqs;

	struct hifc_page_addr page_pa0;
	struct hifc_page_addr page_pa1;

	hifc_event_handler event_callback;
	void *event_pri_handle;
	bool history_fault_flag;
	struct hifc_fault_recover_info history_fault;
	struct semaphore fault_list_sem;

	struct work_struct timer_work;
	struct workqueue_struct *workq;
	struct timer_list heartbeat_timer;
	/* true represent heartbeat lost, false represent heartbeat restore */
	u32 heartbeat_lost;
	int chip_present_flag;
	struct hifc_heartbeat_enhanced heartbeat_ehd;
	struct hifc_hw_stats hw_stats;
	u8 *chip_fault_stats;

	u32 statufull_ref_cnt;
	ulong func_state;

	u64 feature_cap; /* enum hifc_func_cap */

	/* In bmgw x86 host, driver can't send message to mgmt cpu directly,
	 * need to trasmit message ppf mbox to bmgw arm host.
	 */

	struct hifc_board_info board_info;
};

int hifc_init_comm_ch(struct hifc_hwdev *hwdev);
void hifc_uninit_comm_ch(struct hifc_hwdev *hwdev);

enum hifc_set_arm_type {
	HIFC_SET_ARM_CMDQ,
	HIFC_SET_ARM_SQ,
	HIFC_SET_ARM_TYPE_NUM,
};

/* up to driver event */
#define	HIFC_PORT_CMD_MGMT_RESET    0x0
struct hifc_vport_state {
	u8 status;
	u8 version;
	u8 rsvd0[6];

	u16 func_id;
	u16 rsvd1;
	u8 state;
	u8 rsvd2[3];
};

struct hifc_l2nic_reset {
	u8 status;
	u8 version;
	u8 rsvd0[6];

	u16 func_id;
	u16 reset_flag;
};

/* HILINK module interface */

/* cmd of mgmt CPU message for HILINK module */
enum hifc_hilink_cmd {
	HIFC_HILINK_CMD_GET_LINK_INFO       = 0x3,
	HIFC_HILINK_CMD_SET_LINK_SETTINGS   = 0x8,
};

enum hilink_info_print_event {
	HILINK_EVENT_LINK_UP = 1,
	HILINK_EVENT_LINK_DOWN,
	HILINK_EVENT_CABLE_PLUGGED,
	HILINK_EVENT_MAX_TYPE,
};

enum hifc_link_port_type {
	LINK_PORT_FIBRE = 1,
	LINK_PORT_ELECTRIC,
	LINK_PORT_COPPER,
	LINK_PORT_AOC,
	LINK_PORT_BACKPLANE,
	LINK_PORT_BASET,
	LINK_PORT_MAX_TYPE,
};

enum hilink_fibre_subtype {
	FIBRE_SUBTYPE_SR = 1,
	FIBRE_SUBTYPE_LR,
	FIBRE_SUBTYPE_MAX,
};

enum hilink_fec_type {
	HILINK_FEC_RSFEC,
	HILINK_FEC_BASEFEC,
	HILINK_FEC_NOFEC,
	HILINK_FEC_MAX_TYPE,
};

/* cmd of mgmt CPU message */
enum hifc_port_cmd {
	HIFC_PORT_CMD_SET_MAC                  = 0x9,
	HIFC_PORT_CMD_GET_AUTONEG_CAP          = 0xf,
	HIFC_PORT_CMD_SET_VPORT_ENABLE         = 0x5d,
	HIFC_PORT_CMD_UPDATE_MAC               = 0xa4,
	HIFC_PORT_CMD_GET_SFP_INFO             = 0xad,
	HIFC_PORT_CMD_GET_STD_SFP_INFO         = 0xF0,
	HIFC_PORT_CMD_GET_SFP_ABS              = 0xFB,
};

struct hi30_ffe_data {
	u8 PRE2;
	u8 PRE1;
	u8 POST1;
	u8 POST2;
	u8 MAIN;
};

struct hi30_ctle_data {
	u8 ctlebst[3];
	u8 ctlecmband[3];
	u8 ctlermband[3];
	u8 ctleza[3];
	u8 ctlesqh[3];
	u8 ctleactgn[3];
	u8 ctlepassgn;
};

#define HILINK_MAX_LANE		4

struct hilink_lane {
	u8 lane_used;
	u8 hi30_ffe[5];
	u8 hi30_ctle[19];
	u8 hi30_dfe[14];
	u8 rsvd4;
};

struct hifc_link_info {
	u8 vendor_name[16];
	/* port type:
	 * 1 - fiber; 2 - electric; 3 - copper; 4 - AOC; 5 - backplane;
	 * 6 - baseT; 0xffff - unknown
	 *
	 * port subtype:
	 * Only when port_type is fiber:
	 * 1 - SR; 2 - LR
	 */
	u32 port_type;
	u32 port_sub_type;
	u32 cable_length;
	u8 cable_temp;
	u8 cable_max_speed;      /* 1(G)/10(G)/25(G)... */
	u8 sfp_type;             /* 0 - qsfp; 1 - sfp */
	u8 rsvd0;
	u32 power[4];            /* uW; if is sfp, only power[2] is valid */

	u8 an_state;             /* 0 - off; 1 - on */
	u8 fec;                  /* 0 - RSFEC; 1 - BASEFEC; 2 - NOFEC */
	u16 speed;               /* 1(G)/10(G)/25(G)... */

	u8 cable_absent;         /* 0 - cable present; 1 - cable unpresent */
	u8 alos;                 /* 0 - yes; 1 - no */
	u8 rx_los;               /* 0 - yes; 1 - no */
	u8 pma_status;
	u32 pma_dbg_info_reg;    /* pma debug info:  */
	u32 pma_signal_ok_reg;   /* signal ok:  */

	u32 pcs_err_blk_cnt_reg; /* error block counter: */
	u32 rf_lf_status_reg;    /* RF/LF status: */
	u8 pcs_link_reg;         /* pcs link: */
	u8 mac_link_reg;         /* mac link: */
	u8 mac_tx_en;
	u8 mac_rx_en;
	u32 pcs_err_cnt;

	/* struct hifc_hilink_lane: 40 bytes */
	u8 lane1[40];            /* 25GE lane in old firmware */

	u8 rsvd1[266];           /* hilink machine state */

	u8 lane2[HILINK_MAX_LANE * 40]; /* max 4 lane for 40GE/100GE */

	u8 rsvd2[2];
};

struct hifc_hilink_link_info {
	u8 status;
	u8 version;
	u8 rsvd0[6];

	u16 port_id;
	u8 info_type; /* 1: link up  2: link down  3 cable plugged */
	u8 rsvd1;

	struct hifc_link_info info;

	u8 rsvd2[352];
};

int hifc_set_arm_bit(void *hwdev, enum hifc_set_arm_type q_type, u16 q_id);
void hifc_set_chip_present(void *hwdev);
void hifc_force_complete_all(void *hwdev);
void hifc_init_heartbeat(struct hifc_hwdev *hwdev);
void hifc_destroy_heartbeat(struct hifc_hwdev *hwdev);
u8 hifc_nic_sw_aeqe_handler(void *handle, u8 event, u64 data);
int hifc_l2nic_reset_base(struct hifc_hwdev *hwdev, u16 reset_flag);
int hifc_pf_msg_to_mgmt_sync(void *hwdev, enum hifc_mod_type mod, u8 cmd,
			     void *buf_in, u16 in_size,
			     void *buf_out, u16 *out_size, u32 timeout);
void hifc_swe_fault_handler(struct hifc_hwdev *hwdev, u8 level,
			    u8 event, u64 val);
bool hifc_mgmt_event_ack_first(u8 mod, u8 cmd);
int hifc_phy_init_status_judge(void *hwdev);
int hifc_api_csr_rd32(void *hwdev, u8 dest, u32 addr, u32 *val);
int hifc_api_csr_wr32(void *hwdev, u8 dest, u32 addr, u32 val);
void mgmt_heartbeat_event_handler(void *hwdev, void *buf_in, u16 in_size,
				  void *buf_out, u16 *out_size);
struct hifc_sge {
	u32 hi_addr;
	u32 lo_addr;
	u32 len;
};

void hifc_cpu_to_be32(void *data, int len);
void hifc_be32_to_cpu(void *data, int len);
void hifc_set_sge(struct hifc_sge *sge, dma_addr_t addr, u32 len);
#endif
