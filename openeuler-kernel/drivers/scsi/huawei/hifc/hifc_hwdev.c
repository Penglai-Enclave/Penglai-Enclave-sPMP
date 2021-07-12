// SPDX-License-Identifier: GPL-2.0
/* Huawei Hifc PCI Express Linux driver
 * Copyright(c) 2017 Huawei Technologies Co., Ltd
 *
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": [COMM]" fmt

#include <linux/kernel.h>
#include <linux/pci.h>
#include <linux/pci_regs.h>
#include <linux/types.h>
#include <linux/delay.h>
#include <linux/module.h>
#include <linux/completion.h>
#include <linux/semaphore.h>
#include <linux/interrupt.h>

#include "hifc_knl_adp.h"
#include "hifc_hw.h"
#include "hifc_hwdev.h"
#include "hifc_hwif.h"
#include "hifc_api_cmd.h"
#include "hifc_mgmt.h"
#include "hifc_eqs.h"
#include "hifc_wq.h"
#include "hifc_cmdq.h"
#include "hifc_hwif.h"

#define HIFC_DEAULT_EQ_MSIX_PENDING_LIMIT      0
#define HIFC_DEAULT_EQ_MSIX_COALESC_TIMER_CFG  0xFF
#define HIFC_DEAULT_EQ_MSIX_RESEND_TIMER_CFG   7
#define HIFC_FLR_TIMEOUT                       1000
#define HIFC_HT_GPA_PAGE_SIZE                  4096UL
#define HIFC_PPF_HT_GPA_SET_RETRY_TIMES        10
#define HIFC_GET_SFP_INFO_REAL_TIME            0x1
#define HIFC_GLB_SO_RO_CFG_SHIFT               0x0
#define HIFC_GLB_SO_RO_CFG_MASK                0x1
#define HIFC_DISABLE_ORDER                     0
#define HIFC_GLB_DMA_SO_RO_GET(val, member)    \
	(((val) >> HIFC_GLB_##member##_SHIFT) & HIFC_GLB_##member##_MASK)

#define HIFC_GLB_DMA_SO_R0_CLEAR(val, member)  \
	((val) & (~(HIFC_GLB_##member##_MASK << HIFC_GLB_##member##_SHIFT)))

#define HIFC_GLB_DMA_SO_R0_SET(val, member)    \
	(((val) & HIFC_GLB_##member##_MASK) << HIFC_GLB_##member##_SHIFT)

#define HIFC_MGMT_CHANNEL_STATUS_SHIFT         0x0
#define HIFC_MGMT_CHANNEL_STATUS_MASK          0x1
#define HIFC_ACTIVE_STATUS_MASK                0x80000000
#define HIFC_ACTIVE_STATUS_CLEAR               0x7FFFFFFF

#define HIFC_GET_MGMT_CHANNEL_STATUS(val, member)       \
	(((val) >> HIFC_##member##_SHIFT) & HIFC_##member##_MASK)

#define HIFC_CLEAR_MGMT_CHANNEL_STATUS(val, member)     \
	((val) & (~(HIFC_##member##_MASK << HIFC_##member##_SHIFT)))

#define HIFC_SET_MGMT_CHANNEL_STATUS(val, member)       \
	(((val) & HIFC_##member##_MASK) << HIFC_##member##_SHIFT)

#define HIFC_BOARD_IS_PHY(hwdev)                        \
		((hwdev)->board_info.board_type == 4 && \
		 (hwdev)->board_info.board_id == 24)

struct comm_info_ht_gpa_set {
	u8 status;
	u8 version;
	u8 rsvd0[6];
	u32 rsvd1;
	u32 rsvd2;
	u64 page_pa0;
	u64 page_pa1;
};

struct hifc_cons_idx_attr {
	u8        status;
	u8        version;
	u8        rsvd0[6];

	u16       func_idx;
	u8        dma_attr_off;
	u8        pending_limit;
	u8        coalescing_time;
	u8        intr_en;
	u16       intr_idx;
	u32       l2nic_sqn;
	u32       sq_id;
	u64       ci_addr;
};

struct hifc_clear_doorbell {
	u8        status;
	u8        version;
	u8        rsvd0[6];

	u16       func_idx;
	u8        ppf_idx;
	u8        rsvd1;
};

struct hifc_clear_resource {
	u8        status;
	u8        version;
	u8        rsvd0[6];

	u16       func_idx;
	u8        ppf_idx;
	u8        rsvd1;
};

struct hifc_msix_config {
	u8        status;
	u8        version;
	u8        rsvd0[6];

	u16       func_id;
	u16       msix_index;
	u8        pending_cnt;
	u8        coalesct_timer_cnt;
	u8        lli_tmier_cnt;
	u8        lli_credit_cnt;
	u8        resend_timer_cnt;
	u8        rsvd1[3];
};

enum func_tmr_bitmap_status {
	FUNC_TMR_BITMAP_DISABLE,
	FUNC_TMR_BITMAP_ENABLE,
};

struct hifc_func_tmr_bitmap_op {
	u8        status;
	u8        version;
	u8        rsvd0[6];

	u16       func_idx;
	u8        op_id;   /* 0:start; 1:stop */
	u8        ppf_idx;
	u32       rsvd1;
};

struct hifc_ppf_tmr_op {
	u8        status;
	u8        version;
	u8        rsvd0[6];

	u8        ppf_idx;
	u8        op_id;   /* 0: stop timer; 1:start timer */
	u8        rsvd1[2];
	u32       rsvd2;
};

struct hifc_cmd_set_res_state {
	u8        status;
	u8        version;
	u8        rsvd0[6];

	u16       func_idx;
	u8        state;
	u8        rsvd1;
	u32       rsvd2;
};

int hifc_hw_rx_buf_size[] = {
	HIFC_RX_BUF_SIZE_32B,
	HIFC_RX_BUF_SIZE_64B,
	HIFC_RX_BUF_SIZE_96B,
	HIFC_RX_BUF_SIZE_128B,
	HIFC_RX_BUF_SIZE_192B,
	HIFC_RX_BUF_SIZE_256B,
	HIFC_RX_BUF_SIZE_384B,
	HIFC_RX_BUF_SIZE_512B,
	HIFC_RX_BUF_SIZE_768B,
	HIFC_RX_BUF_SIZE_1K,
	HIFC_RX_BUF_SIZE_1_5K,
	HIFC_RX_BUF_SIZE_2K,
	HIFC_RX_BUF_SIZE_3K,
	HIFC_RX_BUF_SIZE_4K,
	HIFC_RX_BUF_SIZE_8K,
	HIFC_RX_BUF_SIZE_16K,
};

struct hifc_comm_board_info {
	u8        status;
	u8        version;
	u8        rsvd0[6];

	struct hifc_board_info info;

	u32       rsvd1[4];
};

#define PHY_DOING_INIT_TIMEOUT	(15 * 1000)

struct hifc_phy_init_status {
	u8        status;
	u8        version;
	u8        rsvd0[6];

	u8        init_status;
	u8        rsvd1[3];
};

enum phy_init_status_type {
	PHY_INIT_DOING = 0,
	PHY_INIT_SUCCESS = 1,
	PHY_INIT_FAIL = 2,
	PHY_NONSUPPORT = 3,
};

struct hifc_update_active {
	u8 status;
	u8 version;
	u8 rsvd0[6];

	u32 update_flag;
	u32 update_status;
};

struct hifc_mgmt_watchdog_info {
	u8 status;
	u8 version;
	u8 rsvd0[6];

	u32 curr_time_h;
	u32 curr_time_l;
	u32 task_id;
	u32 rsv;

	u32 reg[13];
	u32 pc;
	u32 lr;
	u32 cpsr;

	u32 stack_top;
	u32 stack_bottom;
	u32 sp;
	u32 curr_used;
	u32 peak_used;
	u32 is_overflow;

	u32 stack_actlen;
	u8 data[1024];
};

struct hifc_fmw_act_ntc {
	u8 status;
	u8 version;
	u8 rsvd0[6];

	u32 rsvd1[5];
};

#define HIFC_PAGE_SIZE_HW(pg_size)	((u8)ilog2((u32)((pg_size) >> 12)))

struct hifc_wq_page_size {
	u8        status;
	u8        version;
	u8        rsvd0[6];

	u16       func_idx;
	u8        ppf_idx;
	/* real_size=4KB*2^page_size, range(0~20) must be checked by driver */
	u8        page_size;

	u32       rsvd1;
};

#define MAX_PCIE_DFX_BUF_SIZE (1024)

struct hifc_pcie_dfx_ntc {
	u8 status;
	u8 version;
	u8 rsvd0[6];

	int len;
	u32 rsvd;
};

struct hifc_pcie_dfx_info {
	u8 status;
	u8 version;
	u8 rsvd0[6];

	u8 host_id;
	u8 last;
	u8 rsvd[2];
	u32 offset;

	u8 data[MAX_PCIE_DFX_BUF_SIZE];
};

struct hifc_reg_info {
	u8        status;
	u8        version;
	u8        rsvd0[6];

	u32       reg_addr;
	u32       val_length;

	u32       data[2];
};

#define HIFC_DMA_ATTR_ENTRY_ST_SHIFT                            0
#define HIFC_DMA_ATTR_ENTRY_AT_SHIFT                            8
#define HIFC_DMA_ATTR_ENTRY_PH_SHIFT                            10
#define HIFC_DMA_ATTR_ENTRY_NO_SNOOPING_SHIFT                   12
#define HIFC_DMA_ATTR_ENTRY_TPH_EN_SHIFT                        13

#define HIFC_DMA_ATTR_ENTRY_ST_MASK                             0xFF
#define HIFC_DMA_ATTR_ENTRY_AT_MASK                             0x3
#define HIFC_DMA_ATTR_ENTRY_PH_MASK                             0x3
#define HIFC_DMA_ATTR_ENTRY_NO_SNOOPING_MASK                    0x1
#define HIFC_DMA_ATTR_ENTRY_TPH_EN_MASK                         0x1

#define HIFC_DMA_ATTR_ENTRY_SET(val, member)           \
		(((u32)(val) & HIFC_DMA_ATTR_ENTRY_##member##_MASK) << \
			HIFC_DMA_ATTR_ENTRY_##member##_SHIFT)

#define HIFC_DMA_ATTR_ENTRY_CLEAR(val, member)         \
		((val) & (~(HIFC_DMA_ATTR_ENTRY_##member##_MASK        \
			<< HIFC_DMA_ATTR_ENTRY_##member##_SHIFT)))

#define HIFC_PCIE_ST_DISABLE                    0
#define HIFC_PCIE_AT_DISABLE                    0
#define HIFC_PCIE_PH_DISABLE                    0

#define PCIE_MSIX_ATTR_ENTRY                    0

#define HIFC_CHIP_PRESENT 1
#define HIFC_CHIP_ABSENT 0

struct hifc_cmd_fault_event {
	u8        status;
	u8        version;
	u8        rsvd0[6];

	struct hifc_fault_event event;
};

#define HEARTBEAT_DRV_MAGIC_ACK	0x5A5A5A5A

struct hifc_heartbeat_event {
	u8        status;
	u8        version;
	u8        rsvd0[6];

	u8        mgmt_init_state;
	u8        rsvd1[3];
	u32       heart; /* increased every event */
	u32       drv_heart;
};

static void hifc_set_mgmt_channel_status(void *handle, bool state)
{
	struct hifc_hwdev *hwdev = handle;
	u32 val;

	if (!hwdev || hifc_func_type(hwdev) == TYPE_VF ||
	    !(hwdev->feature_cap & HIFC_FUNC_SUPP_DFX_REG))
		return;

	val = hifc_hwif_read_reg(hwdev->hwif, HIFC_ICPL_RESERVD_ADDR);
	val = HIFC_CLEAR_MGMT_CHANNEL_STATUS(val, MGMT_CHANNEL_STATUS);
	val |= HIFC_SET_MGMT_CHANNEL_STATUS((u32)state, MGMT_CHANNEL_STATUS);

	hifc_hwif_write_reg(hwdev->hwif, HIFC_ICPL_RESERVD_ADDR, val);
}

static void hifc_enable_mgmt_channel(void *hwdev, void *buf_out)
{
	struct hifc_hwdev *dev = hwdev;
	struct hifc_update_active *active_info = buf_out;

	if (!active_info || hifc_func_type(hwdev) == TYPE_VF ||
	    !(dev->feature_cap & HIFC_FUNC_SUPP_DFX_REG))
		return;

	if ((!active_info->status) &&
	    (active_info->update_status & HIFC_ACTIVE_STATUS_MASK)) {
		active_info->update_status &= HIFC_ACTIVE_STATUS_CLEAR;
		return;
	}

	hifc_set_mgmt_channel_status(hwdev, false);
}

int hifc_set_wq_page_size(struct hifc_hwdev *hwdev, u16 func_idx,
			  u32 page_size);

#define HIFC_QUEUE_MIN_DEPTH            6
#define HIFC_QUEUE_MAX_DEPTH            12
#define HIFC_MAX_RX_BUFFER_SIZE         15

#define ROOT_CTX_QPS_VALID(root_ctxt)   \
		((root_ctxt)->rq_depth >= HIFC_QUEUE_MIN_DEPTH &&	\
		(root_ctxt)->rq_depth <= HIFC_QUEUE_MAX_DEPTH &&	\
		(root_ctxt)->sq_depth >= HIFC_QUEUE_MIN_DEPTH &&	\
		(root_ctxt)->sq_depth <= HIFC_QUEUE_MAX_DEPTH &&	\
		(root_ctxt)->rx_buf_sz <= HIFC_MAX_RX_BUFFER_SIZE)

struct hifc_mgmt_status_log {
	u8 status;
	const char *log;
};

struct hifc_mgmt_status_log mgmt_status_log[] = {
	{HIFC_MGMT_STATUS_ERR_PARAM, "Invalid parameter"},
	{HIFC_MGMT_STATUS_ERR_FAILED, "Operation failed"},
	{HIFC_MGMT_STATUS_ERR_PORT, "Invalid port"},
	{HIFC_MGMT_STATUS_ERR_TIMEOUT, "Operation time out"},
	{HIFC_MGMT_STATUS_ERR_NOMATCH, "Version not match"},
	{HIFC_MGMT_STATUS_ERR_EXIST, "Entry exists"},
	{HIFC_MGMT_STATUS_ERR_NOMEM, "Out of memory"},
	{HIFC_MGMT_STATUS_ERR_INIT, "Feature not initialized"},
	{HIFC_MGMT_STATUS_ERR_FAULT, "Invalid address"},
	{HIFC_MGMT_STATUS_ERR_PERM, "Operation not permitted"},
	{HIFC_MGMT_STATUS_ERR_EMPTY, "Table empty"},
	{HIFC_MGMT_STATUS_ERR_FULL, "Table full"},
	{HIFC_MGMT_STATUS_ERR_NOT_FOUND, "Not found"},
	{HIFC_MGMT_STATUS_ERR_BUSY, "Device or resource busy "},
	{HIFC_MGMT_STATUS_ERR_RESOURCE, "No resources for operation "},
	{HIFC_MGMT_STATUS_ERR_CONFIG, "Invalid configuration"},
	{HIFC_MGMT_STATUS_ERR_UNAVAIL, "Feature unavailable"},
	{HIFC_MGMT_STATUS_ERR_CRC, "CRC check failed"},
	{HIFC_MGMT_STATUS_ERR_NXIO, "No such device or address"},
	{HIFC_MGMT_STATUS_ERR_ROLLBACK, "Chip rollback fail"},
	{HIFC_MGMT_STATUS_ERR_LEN, "Length too short or too long"},
	{HIFC_MGMT_STATUS_ERR_UNSUPPORT, "Feature not supported"},
};

static void __print_status_info(struct hifc_hwdev *dev,
				enum hifc_mod_type mod, u8 cmd, int index)
{
	if (mod == HIFC_MOD_COMM) {
		sdk_err(dev->dev_hdl, "Mgmt process mod(0x%x) cmd(0x%x) fail: %s",
			mod, cmd, mgmt_status_log[index].log);
	} else if (mod == HIFC_MOD_L2NIC ||
		   mod == HIFC_MOD_HILINK) {
		sdk_err(dev->dev_hdl, "Mgmt process mod(0x%x) cmd(0x%x) fail: %s",
			mod, cmd, mgmt_status_log[index].log);
	}
}

static bool hifc_status_need_special_handle(enum hifc_mod_type mod,
					    u8 cmd, u8 status)
{
	if (mod == HIFC_MOD_L2NIC) {
		/* optical module isn't plugged in */
		if (((cmd == HIFC_PORT_CMD_GET_STD_SFP_INFO) ||
		     (cmd == HIFC_PORT_CMD_GET_SFP_INFO)) &&
		     (status == HIFC_MGMT_STATUS_ERR_NXIO))
			return true;

		if ((cmd == HIFC_PORT_CMD_SET_MAC ||
		     cmd == HIFC_PORT_CMD_UPDATE_MAC) &&
		     status == HIFC_MGMT_STATUS_ERR_EXIST)
			return true;
	}

	return false;
}

static bool print_status_info_valid(enum hifc_mod_type mod,
				    const void *buf_out)
{
	if (!buf_out)
		return false;

	if (mod != HIFC_MOD_COMM && mod != HIFC_MOD_L2NIC &&
	    mod != HIFC_MOD_HILINK)
		return false;

	return true;
}

static void hifc_print_status_info(void *hwdev, enum hifc_mod_type mod,
				   u8 cmd, const void *buf_out)
{
	struct hifc_hwdev *dev = hwdev;
	int i, size;
	u8 status;

	if (!print_status_info_valid(mod, buf_out))
		return;

	status = *(u8 *)buf_out;

	if (!status)
		return;

	if (hifc_status_need_special_handle(mod, cmd, status))
		return;

	size = sizeof(mgmt_status_log) / sizeof(mgmt_status_log[0]);
	for (i = 0; i < size; i++) {
		if (status == mgmt_status_log[i].status) {
			__print_status_info(dev, mod, cmd, i);
			return;
		}
	}

	if (mod == HIFC_MOD_COMM) {
		sdk_err(dev->dev_hdl, "Mgmt process mod(0x%x) cmd(0x%x) return driver unknown status(0x%x)\n",
			mod, cmd, status);
	} else if (mod == HIFC_MOD_L2NIC || mod == HIFC_MOD_HILINK) {
		sdk_err(dev->dev_hdl, "Mgmt process mod(0x%x) cmd(0x%x) return driver unknown status(0x%x)\n",
			mod, cmd, status);
	}
}

void hifc_set_chip_present(void *hwdev)
{
	((struct hifc_hwdev *)hwdev)->chip_present_flag = HIFC_CHIP_PRESENT;
}

void hifc_set_chip_absent(void *hwdev)
{
	struct hifc_hwdev *dev = hwdev;

	sdk_err(dev->dev_hdl, "Card not present\n");
	dev->chip_present_flag = HIFC_CHIP_ABSENT;
}

int hifc_get_chip_present_flag(void *hwdev)
{
	int flag;

	if (!hwdev)
		return -EINVAL;
	flag = ((struct hifc_hwdev *)hwdev)->chip_present_flag;
	return flag;
}

void hifc_force_complete_all(void *hwdev)
{
	struct hifc_hwdev *dev = (struct hifc_hwdev *)hwdev;
	struct hifc_recv_msg *recv_resp_msg;

	set_bit(HIFC_HWDEV_STATE_BUSY, &dev->func_state);

	if (hifc_func_type(dev) != TYPE_VF &&
	    hifc_is_hwdev_mod_inited(dev, HIFC_HWDEV_MGMT_INITED)) {
		recv_resp_msg = &dev->pf_to_mgmt->recv_resp_msg_from_mgmt;
		if (dev->pf_to_mgmt->event_flag == SEND_EVENT_START) {
			complete(&recv_resp_msg->recv_done);
			dev->pf_to_mgmt->event_flag = SEND_EVENT_TIMEOUT;
		}
	}

	/* only flush sync cmdq to avoid blocking remove */
	if (hifc_is_hwdev_mod_inited(dev, HIFC_HWDEV_CMDQ_INITED))
		hifc_cmdq_flush_cmd(hwdev,
				    &dev->cmdqs->cmdq[HIFC_CMDQ_SYNC]);

	clear_bit(HIFC_HWDEV_STATE_BUSY, &dev->func_state);
}

void hifc_detect_hw_present(void *hwdev)
{
	u32 addr, attr1;

	addr = HIFC_CSR_FUNC_ATTR1_ADDR;
	attr1 = hifc_hwif_read_reg(((struct hifc_hwdev *)hwdev)->hwif, addr);
	if (attr1 == HIFC_PCIE_LINK_DOWN) {
		hifc_set_chip_absent(hwdev);
		hifc_force_complete_all(hwdev);
	}
}

void hifc_record_pcie_error(void *hwdev)
{
	struct hifc_hwdev *dev = (struct hifc_hwdev *)hwdev;

	if (!hwdev)
		return;

	atomic_inc(&dev->hw_stats.fault_event_stats.pcie_fault_stats);
}

static inline void __set_heartbeat_ehd_detect_delay(struct hifc_hwdev *hwdev,
						    u32 delay_ms)
{
	hwdev->heartbeat_ehd.start_detect_jiffies =
					jiffies + msecs_to_jiffies(delay_ms);
}

static int __pf_to_mgmt_pre_handle(struct hifc_hwdev *hwdev,
				   enum hifc_mod_type mod, u8 cmd)
{
	if (hifc_get_mgmt_channel_status(hwdev)) {
		if (mod == HIFC_MOD_COMM || mod == HIFC_MOD_L2NIC)
			return HIFC_DEV_BUSY_ACTIVE_FW;
		else
			return -EBUSY;
	}

	/* Set channel invalid, don't allowed to send other cmd */
	if (mod == HIFC_MOD_COMM && cmd == HIFC_MGMT_CMD_ACTIVATE_FW) {
		hifc_set_mgmt_channel_status(hwdev, true);
		/* stop heartbeat enhanced detection temporary, and will
		 * restart in firmware active event when mgmt is resetted
		 */
		__set_heartbeat_ehd_detect_delay(hwdev,
						 HIFC_DEV_ACTIVE_FW_TIMEOUT);
	}

	return 0;
}

static void __pf_to_mgmt_after_handle(struct hifc_hwdev *hwdev,
				      enum hifc_mod_type mod, u8 cmd,
				      int sw_status, void *mgmt_status)
{
	/* if activate fw is failed, set channel valid */
	if (mod == HIFC_MOD_COMM &&
	    cmd == HIFC_MGMT_CMD_ACTIVATE_FW) {
		if (sw_status)
			hifc_set_mgmt_channel_status(hwdev, false);
		else
			hifc_enable_mgmt_channel(hwdev, mgmt_status);
	}
}

int hifc_pf_msg_to_mgmt_sync(void *hwdev, enum hifc_mod_type mod, u8 cmd,
			     void *buf_in, u16 in_size,
			     void *buf_out, u16 *out_size, u32 timeout)
{
	int err;

	if (!hwdev)
		return -EINVAL;

	if (!((struct hifc_hwdev *)hwdev)->chip_present_flag)
		return -EPERM;

	if (!hifc_is_hwdev_mod_inited(hwdev, HIFC_HWDEV_MGMT_INITED))
		return -EPERM;

	if (in_size > HIFC_MSG_TO_MGMT_MAX_LEN)
		return -EINVAL;

	err = __pf_to_mgmt_pre_handle(hwdev, mod, cmd);
	if (err)
		return err;

	err = hifc_pf_to_mgmt_sync(hwdev, mod, cmd, buf_in, in_size,
				   buf_out, out_size, timeout);
	__pf_to_mgmt_after_handle(hwdev, mod, cmd, err, buf_out);

	return err;
}

static bool is_sfp_info_cmd_cached(struct hifc_hwdev *hwdev,
				   enum hifc_mod_type mod, u8 cmd,
				   void *buf_in, u16 in_size,
				   void *buf_out, u16 *out_size)
{
	struct hifc_cmd_get_sfp_qsfp_info *sfp_info;
	struct hifc_port_routine_cmd *rt_cmd;
	struct card_node *chip_node = hwdev->chip_node;

	sfp_info = buf_in;
	if (!chip_node->rt_cmd || sfp_info->port_id >= HIFC_MAX_PORT_ID ||
	    *out_size < sizeof(*sfp_info))
		return false;

	if (sfp_info->version == HIFC_GET_SFP_INFO_REAL_TIME)
		return false;

	rt_cmd = &chip_node->rt_cmd[sfp_info->port_id];
	mutex_lock(&chip_node->sfp_mutex);
	memcpy(buf_out, &rt_cmd->sfp_info, sizeof(*sfp_info));
	mutex_unlock(&chip_node->sfp_mutex);

	return true;
}

static bool is_sfp_abs_cmd_cached(struct hifc_hwdev *hwdev,
				  enum hifc_mod_type mod, u8 cmd,
				  void *buf_in, u16 in_size,
				  void *buf_out, u16 *out_size)
{
	struct hifc_cmd_get_light_module_abs *abs;
	struct hifc_port_routine_cmd *rt_cmd;
	struct card_node *chip_node = hwdev->chip_node;

	abs = buf_in;
	if (!chip_node->rt_cmd || abs->port_id >= HIFC_MAX_PORT_ID ||
	    *out_size < sizeof(*abs))
		return false;

	if (abs->version == HIFC_GET_SFP_INFO_REAL_TIME)
		return false;

	rt_cmd = &chip_node->rt_cmd[abs->port_id];
	mutex_lock(&chip_node->sfp_mutex);
	memcpy(buf_out, &rt_cmd->abs, sizeof(*abs));
	mutex_unlock(&chip_node->sfp_mutex);

	return true;
}

static bool driver_processed_cmd(struct hifc_hwdev *hwdev,
				 enum hifc_mod_type mod, u8 cmd,
				 void *buf_in, u16 in_size,
				 void *buf_out, u16 *out_size)
{
	struct card_node *chip_node = hwdev->chip_node;

	if (mod == HIFC_MOD_L2NIC) {
		if (cmd == HIFC_PORT_CMD_GET_SFP_INFO &&
		    chip_node->rt_cmd->up_send_sfp_info) {
			return is_sfp_info_cmd_cached(hwdev, mod, cmd, buf_in,
						      in_size, buf_out,
						      out_size);
		} else if (cmd == HIFC_PORT_CMD_GET_SFP_ABS &&
			 chip_node->rt_cmd->up_send_sfp_abs) {
			return is_sfp_abs_cmd_cached(hwdev, mod, cmd, buf_in,
						     in_size, buf_out,
						     out_size);
		}
	}

	return false;
}

static int send_sync_mgmt_msg(void *hwdev, enum hifc_mod_type mod, u8 cmd,
			      void *buf_in, u16 in_size,
			      void *buf_out, u16 *out_size, u32 timeout)
{
	unsigned long end;

	end = jiffies + msecs_to_jiffies(HIFC_DEV_ACTIVE_FW_TIMEOUT);
	do {
		if (!hifc_get_mgmt_channel_status(hwdev) ||
		    !hifc_get_chip_present_flag(hwdev))
			break;

		msleep(1000);
	} while (time_before(jiffies, end));

	if (driver_processed_cmd(hwdev, mod, cmd, buf_in, in_size, buf_out,
				 out_size))
		return 0;

	return hifc_pf_msg_to_mgmt_sync(hwdev, mod, cmd, buf_in, in_size,
					 buf_out, out_size, timeout);
}

int hifc_msg_to_mgmt_sync(void *hwdev, enum hifc_mod_type mod, u8 cmd,
			  void *buf_in, u16 in_size,
			  void *buf_out, u16 *out_size, u32 timeout)
{
	struct hifc_hwdev *dev = hwdev;
	int err;

	if (!hwdev)
		return -EINVAL;

	if (!(dev->chip_present_flag))
		return -EPERM;

	err = send_sync_mgmt_msg(hwdev, mod, cmd, buf_in, in_size,
				 buf_out, out_size, timeout);

	hifc_print_status_info(hwdev, mod, cmd, buf_out);

	return err;
}

/* PF/VF send msg to uP by api cmd, and return immediately */
int hifc_msg_to_mgmt_async(void *hwdev, enum hifc_mod_type mod, u8 cmd,
			   void *buf_in, u16 in_size)
{
	int err;

	if (!hwdev)
		return -EINVAL;

	if (!(((struct hifc_hwdev *)hwdev)->chip_present_flag) ||
	    !hifc_is_hwdev_mod_inited(hwdev, HIFC_HWDEV_MGMT_INITED) ||
	    hifc_get_mgmt_channel_status(hwdev))
		return -EPERM;

	if (hifc_func_type(hwdev) == TYPE_VF) {
		err = -EFAULT;
		sdk_err(((struct hifc_hwdev *)hwdev)->dev_hdl,
			"Mailbox don't support async cmd\n");
	} else {
		err = hifc_pf_to_mgmt_async(hwdev, mod, cmd, buf_in, in_size);
	}

	return err;
}

int hifc_msg_to_mgmt_no_ack(void *hwdev, enum hifc_mod_type mod, u8 cmd,
			    void *buf_in, u16 in_size)
{
	struct hifc_hwdev *dev = hwdev;
	int err;

	if (!hwdev)
		return -EINVAL;

	if (!(dev->chip_present_flag))
		return -EPERM;

	err = hifc_pf_to_mgmt_no_ack(hwdev, mod, cmd, buf_in, in_size);

	return err;
}

/**
 * hifc_cpu_to_be32 - convert data to big endian 32 bit format
 * @data: the data to convert
 * @len: length of data to convert, must be Multiple of 4B
 **/
void hifc_cpu_to_be32(void *data, int len)
{
	int i, chunk_sz = sizeof(u32);
	u32 *mem = data;

	if (!data)
		return;

	len = len / chunk_sz;

	for (i = 0; i < len; i++) {
		*mem = cpu_to_be32(*mem);
		mem++;
	}
}

/**
 * hifc_cpu_to_be32 - convert data from big endian 32 bit format
 * @data: the data to convert
 * @len: length of data to convert
 **/
void hifc_be32_to_cpu(void *data, int len)
{
	int i, chunk_sz = sizeof(u32);
	u32 *mem = data;

	if (!data)
		return;

	len = len / chunk_sz;

	for (i = 0; i < len; i++) {
		*mem = be32_to_cpu(*mem);
		mem++;
	}
}

/**
 * hifc_set_sge - set dma area in scatter gather entry
 * @sge: scatter gather entry
 * @addr: dma address
 * @len: length of relevant data in the dma address
 **/
void hifc_set_sge(struct hifc_sge *sge, dma_addr_t addr, u32 len)
{
	sge->hi_addr = upper_32_bits(addr);
	sge->lo_addr = lower_32_bits(addr);
	sge->len  = len;
}

int hifc_set_ci_table(void *hwdev, u16 q_id, struct hifc_sq_attr *attr)
{
	struct hifc_cons_idx_attr cons_idx_attr = {0};
	u16 out_size = sizeof(cons_idx_attr);
	int err;

	if (!hwdev || !attr)
		return -EINVAL;

	err = hifc_global_func_id_get(hwdev, &cons_idx_attr.func_idx);
	if (err)
		return err;

	cons_idx_attr.dma_attr_off  = attr->dma_attr_off;
	cons_idx_attr.pending_limit = attr->pending_limit;
	cons_idx_attr.coalescing_time  = attr->coalescing_time;

	if (attr->intr_en) {
		cons_idx_attr.intr_en = attr->intr_en;
		cons_idx_attr.intr_idx = attr->intr_idx;
	}

	cons_idx_attr.l2nic_sqn = attr->l2nic_sqn;
	cons_idx_attr.sq_id = q_id;

	cons_idx_attr.ci_addr = attr->ci_dma_base;

	err = hifc_msg_to_mgmt_sync(hwdev, HIFC_MOD_COMM,
				    HIFC_MGMT_CMD_L2NIC_SQ_CI_ATTR_SET,
				    &cons_idx_attr, sizeof(cons_idx_attr),
				    &cons_idx_attr, &out_size, 0);
	if (err || !out_size || cons_idx_attr.status) {
		sdk_err(((struct hifc_hwdev *)hwdev)->dev_hdl,
			"Failed to set ci attribute table, err: %d, status: 0x%x, out_size: 0x%x\n",
			err, cons_idx_attr.status, out_size);
		return -EFAULT;
	}

	return 0;
}

static int hifc_set_cmdq_depth(struct hifc_hwdev *hwdev, u16 cmdq_depth)
{
	struct hifc_root_ctxt root_ctxt = {0};
	u16 out_size = sizeof(root_ctxt);
	int err;

	err = hifc_global_func_id_get(hwdev, &root_ctxt.func_idx);
	if (err)
		return err;

	root_ctxt.ppf_idx = hifc_ppf_idx(hwdev);

	root_ctxt.set_cmdq_depth = 1;
	root_ctxt.cmdq_depth = (u8)ilog2(cmdq_depth);

	err = hifc_msg_to_mgmt_sync(hwdev, HIFC_MOD_COMM,
				    HIFC_MGMT_CMD_VAT_SET,
				    &root_ctxt, sizeof(root_ctxt),
				    &root_ctxt, &out_size, 0);
	if (err || !out_size || root_ctxt.status) {
		sdk_err(hwdev->dev_hdl, "Failed to set cmdq depth, err: %d, status: 0x%x, out_size: 0x%x\n",
			err, root_ctxt.status, out_size);
		return -EFAULT;
	}

	return 0;
}

static u16 get_hw_rx_buf_size(int rx_buf_sz)
{
#define DEFAULT_RX_BUF_SIZE	((u16)0xB)
	u16 num_hw_types =
		sizeof(hifc_hw_rx_buf_size) /
		sizeof(hifc_hw_rx_buf_size[0]);
	u16 i;

	for (i = 0; i < num_hw_types; i++) {
		if (hifc_hw_rx_buf_size[i] == rx_buf_sz)
			return i;
	}

	pr_err("Chip can't support rx buf size of %d\n", rx_buf_sz);

	return DEFAULT_RX_BUF_SIZE;
}

int hifc_set_root_ctxt(void *hwdev, u16 rq_depth, u16 sq_depth, int rx_buf_sz)
{
	struct hifc_root_ctxt root_ctxt = {0};
	u16 out_size = sizeof(root_ctxt);
	int err;

	if (!hwdev)
		return -EINVAL;

	err = hifc_global_func_id_get(hwdev, &root_ctxt.func_idx);
	if (err)
		return err;

	root_ctxt.ppf_idx = hifc_ppf_idx(hwdev);

	root_ctxt.set_cmdq_depth = 0;
	root_ctxt.cmdq_depth = 0;

	root_ctxt.lro_en = 1;

	root_ctxt.rq_depth  = (u16)ilog2(rq_depth);
	root_ctxt.rx_buf_sz = get_hw_rx_buf_size(rx_buf_sz);
	root_ctxt.sq_depth  = (u16)ilog2(sq_depth);

	err = hifc_msg_to_mgmt_sync(hwdev, HIFC_MOD_COMM,
				    HIFC_MGMT_CMD_VAT_SET,
				    &root_ctxt, sizeof(root_ctxt),
				    &root_ctxt, &out_size, 0);
	if (err || !out_size || root_ctxt.status) {
		sdk_err(((struct hifc_hwdev *)hwdev)->dev_hdl,
			"Failed to set root context, err: %d, status: 0x%x, out_size: 0x%x\n",
			err, root_ctxt.status, out_size);
		return -EFAULT;
	}

	return 0;
}

int hifc_clean_root_ctxt(void *hwdev)
{
	struct hifc_root_ctxt root_ctxt = {0};
	u16 out_size = sizeof(root_ctxt);
	int err;

	if (!hwdev)
		return -EINVAL;

	err = hifc_global_func_id_get(hwdev, &root_ctxt.func_idx);
	if (err)
		return err;

	root_ctxt.ppf_idx = hifc_ppf_idx(hwdev);

	err = hifc_msg_to_mgmt_sync(hwdev, HIFC_MOD_COMM,
				    HIFC_MGMT_CMD_VAT_SET,
				    &root_ctxt, sizeof(root_ctxt),
				    &root_ctxt, &out_size, 0);
	if (err || !out_size || root_ctxt.status) {
		sdk_err(((struct hifc_hwdev *)hwdev)->dev_hdl,
			"Failed to set root context, err: %d, status: 0x%x, out_size: 0x%x\n",
			err, root_ctxt.status, out_size);
		return -EFAULT;
	}

	return 0;
}

static int wait_for_flr_finish(struct hifc_hwif *hwif)
{
	u32 cnt = 0;
	enum hifc_pf_status status;

	while (cnt < HIFC_FLR_TIMEOUT) {
		status = hifc_get_pf_status(hwif);
		if (status == HIFC_PF_STATUS_FLR_FINISH_FLAG) {
			hifc_set_pf_status(hwif, HIFC_PF_STATUS_ACTIVE_FLAG);
			return 0;
		}

		usleep_range(9900, 10000);
		cnt++;
	}

	return -EFAULT;
}

#define HIFC_WAIT_CMDQ_IDLE_TIMEOUT		5000

static int wait_cmdq_stop(struct hifc_hwdev *hwdev)
{
	enum hifc_cmdq_type cmdq_type;
	struct hifc_cmdqs *cmdqs = hwdev->cmdqs;
	u32 cnt = 0;
	int err = 0;

	if (!(cmdqs->status & HIFC_CMDQ_ENABLE))
		return 0;

	cmdqs->status &= ~HIFC_CMDQ_ENABLE;

	while (cnt < HIFC_WAIT_CMDQ_IDLE_TIMEOUT && hwdev->chip_present_flag) {
		err = 0;
		cmdq_type = HIFC_CMDQ_SYNC;
		for (; cmdq_type < HIFC_MAX_CMDQ_TYPES; cmdq_type++) {
			if (!hifc_cmdq_idle(&cmdqs->cmdq[cmdq_type])) {
				err = -EBUSY;
				break;
			}
		}

		if (!err)
			return 0;

		usleep_range(500, 1000);
		cnt++;
	}

	cmdq_type = HIFC_CMDQ_SYNC;
	for (; cmdq_type < HIFC_MAX_CMDQ_TYPES; cmdq_type++) {
		if (!hifc_cmdq_idle(&cmdqs->cmdq[cmdq_type]))
			sdk_err(hwdev->dev_hdl, "Cmdq %d busy\n", cmdq_type);
	}

	cmdqs->status |= HIFC_CMDQ_ENABLE;

	return err;
}

static int hifc_pf_rx_tx_flush(struct hifc_hwdev *hwdev)
{
	struct hifc_hwif *hwif = hwdev->hwif;
	struct hifc_clear_doorbell clear_db = {0};
	struct hifc_clear_resource clr_res = {0};
	u16 out_size, func_id;
	int err;
	int ret = 0;

	/* wait ucode stop I/O */
	msleep(100);

	err = wait_cmdq_stop(hwdev);
	if (err) {
		sdk_warn(hwdev->dev_hdl, "CMDQ is still working, please check CMDQ timeout value is reasonable\n");
		ret = err;
	}

	hifc_disable_doorbell(hwif);

	out_size = sizeof(clear_db);
	func_id = hifc_global_func_id_hw(hwdev);
	clear_db.func_idx = func_id;
	clear_db.ppf_idx  = HIFC_HWIF_PPF_IDX(hwif);

	err = hifc_msg_to_mgmt_sync(hwdev, HIFC_MOD_COMM,
				    HIFC_MGMT_CMD_FLUSH_DOORBELL, &clear_db,
				    sizeof(clear_db), &clear_db, &out_size, 0);
	if (err || !out_size || clear_db.status) {
		sdk_warn(hwdev->dev_hdl, "Failed to flush doorbell, err: %d, status: 0x%x, out_size: 0x%x\n",
			 err, clear_db.status, out_size);
		if (err)
			ret = err;
		else
			ret = -EFAULT;
	}

	hifc_set_pf_status(hwif, HIFC_PF_STATUS_FLR_START_FLAG);

	clr_res.func_idx = func_id;
	clr_res.ppf_idx  = HIFC_HWIF_PPF_IDX(hwif);

	err = hifc_msg_to_mgmt_no_ack(hwdev, HIFC_MOD_COMM,
				      HIFC_MGMT_CMD_START_FLR, &clr_res,
				      sizeof(clr_res));
	if (err) {
		sdk_warn(hwdev->dev_hdl, "Failed to notice flush message\n");
		ret = err;
	}

	err = wait_for_flr_finish(hwif);
	if (err) {
		sdk_warn(hwdev->dev_hdl, "Wait firmware FLR timeout\n");
		ret = err;
	}

	hifc_enable_doorbell(hwif);

	err = hifc_reinit_cmdq_ctxts(hwdev);
	if (err) {
		sdk_warn(hwdev->dev_hdl, "Failed to reinit cmdq\n");
		ret = err;
	}

	return ret;
}

int hifc_func_rx_tx_flush(void *hwdev)
{
	struct hifc_hwdev *dev = hwdev;

	if (!hwdev)
		return -EINVAL;

	if (!dev->chip_present_flag)
		return 0;

	return hifc_pf_rx_tx_flush(dev);
}

int hifc_get_interrupt_cfg(void *hwdev,
			   struct nic_interrupt_info *interrupt_info)
{
	struct hifc_hwdev *nic_hwdev = hwdev;
	struct hifc_msix_config msix_cfg = {0};
	u16 out_size = sizeof(msix_cfg);
	int err;

	if (!hwdev || !interrupt_info)
		return -EINVAL;

	err = hifc_global_func_id_get(hwdev, &msix_cfg.func_id);
	if (err)
		return err;

	msix_cfg.msix_index = interrupt_info->msix_index;

	err = hifc_msg_to_mgmt_sync(hwdev, HIFC_MOD_COMM,
				    HIFC_MGMT_CMD_MSI_CTRL_REG_RD_BY_UP,
				    &msix_cfg, sizeof(msix_cfg),
				    &msix_cfg, &out_size, 0);
	if (err || !out_size || msix_cfg.status) {
		sdk_err(nic_hwdev->dev_hdl, "Failed to get interrupt config, err: %d, status: 0x%x, out size: 0x%x\n",
			err, msix_cfg.status, out_size);
		return -EINVAL;
	}

	interrupt_info->lli_credit_limit = msix_cfg.lli_credit_cnt;
	interrupt_info->lli_timer_cfg = msix_cfg.lli_tmier_cnt;
	interrupt_info->pending_limt = msix_cfg.pending_cnt;
	interrupt_info->coalesc_timer_cfg = msix_cfg.coalesct_timer_cnt;
	interrupt_info->resend_timer_cfg = msix_cfg.resend_timer_cnt;

	return 0;
}

int hifc_set_interrupt_cfg(void *hwdev,
			   struct nic_interrupt_info interrupt_info)
{
	struct hifc_hwdev *nic_hwdev = hwdev;
	struct hifc_msix_config msix_cfg = {0};
	struct nic_interrupt_info temp_info;
	u16 out_size = sizeof(msix_cfg);
	int err;

	if (!hwdev)
		return -EINVAL;

	temp_info.msix_index = interrupt_info.msix_index;

	err = hifc_get_interrupt_cfg(hwdev, &temp_info);
	if (err)
		return -EINVAL;

	err = hifc_global_func_id_get(hwdev, &msix_cfg.func_id);
	if (err)
		return err;

	msix_cfg.msix_index = (u16)interrupt_info.msix_index;
	msix_cfg.lli_credit_cnt = temp_info.lli_credit_limit;
	msix_cfg.lli_tmier_cnt = temp_info.lli_timer_cfg;
	msix_cfg.pending_cnt = temp_info.pending_limt;
	msix_cfg.coalesct_timer_cnt = temp_info.coalesc_timer_cfg;
	msix_cfg.resend_timer_cnt = temp_info.resend_timer_cfg;

	if (interrupt_info.lli_set) {
		msix_cfg.lli_credit_cnt = interrupt_info.lli_credit_limit;
		msix_cfg.lli_tmier_cnt = interrupt_info.lli_timer_cfg;
	}

	if (interrupt_info.interrupt_coalesc_set) {
		msix_cfg.pending_cnt = interrupt_info.pending_limt;
		msix_cfg.coalesct_timer_cnt = interrupt_info.coalesc_timer_cfg;
		msix_cfg.resend_timer_cnt = interrupt_info.resend_timer_cfg;
	}

	err = hifc_msg_to_mgmt_sync(hwdev, HIFC_MOD_COMM,
				    HIFC_MGMT_CMD_MSI_CTRL_REG_WR_BY_UP,
				    &msix_cfg, sizeof(msix_cfg),
				    &msix_cfg, &out_size, 0);
	if (err || !out_size || msix_cfg.status) {
		sdk_err(nic_hwdev->dev_hdl, "Failed to set interrupt config, err: %d, status: 0x%x, out size: 0x%x\n",
			err, msix_cfg.status, out_size);
		return -EINVAL;
	}

	return 0;
}

#define	HIFC_MSIX_CNT_RESEND_TIMER_SHIFT		29
#define	HIFC_MSIX_CNT_RESEND_TIMER_MASK		0x7U

#define HIFC_MSIX_CNT_SET(val, member)		\
		(((val) & HIFC_MSIX_CNT_##member##_MASK) << \
		HIFC_MSIX_CNT_##member##_SHIFT)

void hifc_misx_intr_clear_resend_bit(void *hwdev, u16 msix_idx,
				     u8 clear_resend_en)
{
	struct hifc_hwif *hwif;
	u32 msix_ctrl = 0, addr;

	if (!hwdev)
		return;

	hwif = ((struct hifc_hwdev *)hwdev)->hwif;

	msix_ctrl = HIFC_MSIX_CNT_SET(clear_resend_en, RESEND_TIMER);

	addr = HIFC_CSR_MSIX_CNT_ADDR(msix_idx);

	hifc_hwif_write_reg(hwif, addr, msix_ctrl);
}

static int init_aeqs_msix_attr(struct hifc_hwdev *hwdev)
{
	struct hifc_aeqs *aeqs = hwdev->aeqs;
	struct nic_interrupt_info info = {0};
	struct hifc_eq *eq;
	u16 q_id;
	int err;

	info.lli_set = 0;
	info.interrupt_coalesc_set = 1;
	info.pending_limt = HIFC_DEAULT_EQ_MSIX_PENDING_LIMIT;
	info.coalesc_timer_cfg = HIFC_DEAULT_EQ_MSIX_COALESC_TIMER_CFG;
	info.resend_timer_cfg = HIFC_DEAULT_EQ_MSIX_RESEND_TIMER_CFG;

	for (q_id = 0; q_id < aeqs->num_aeqs; q_id++) {
		eq = &aeqs->aeq[q_id];
		info.msix_index = eq->eq_irq.msix_entry_idx;
		err = hifc_set_interrupt_cfg(hwdev, info);
		if (err) {
			sdk_err(hwdev->dev_hdl, "Set msix attr for aeq %d failed\n",
				q_id);
			return -EFAULT;
		}
	}

	return 0;
}

static int init_ceqs_msix_attr(struct hifc_hwdev *hwdev)
{
	struct hifc_ceqs *ceqs = hwdev->ceqs;
	struct nic_interrupt_info info = {0};
	struct hifc_eq *eq;
	u16 q_id;
	int err;

	info.lli_set = 0;
	info.interrupt_coalesc_set = 1;
	info.pending_limt = HIFC_DEAULT_EQ_MSIX_PENDING_LIMIT;
	info.coalesc_timer_cfg = HIFC_DEAULT_EQ_MSIX_COALESC_TIMER_CFG;
	info.resend_timer_cfg = HIFC_DEAULT_EQ_MSIX_RESEND_TIMER_CFG;

	for (q_id = 0; q_id < ceqs->num_ceqs; q_id++) {
		eq = &ceqs->ceq[q_id];
		info.msix_index = eq->eq_irq.msix_entry_idx;
		err = hifc_set_interrupt_cfg(hwdev, info);
		if (err) {
			sdk_err(hwdev->dev_hdl, "Set msix attr for ceq %d failed\n",
				q_id);
			return -EFAULT;
		}
	}

	return 0;
}

/**
 * set_pf_dma_attr_entry - set the dma attributes for entry
 * @hwdev: the pointer to hw device
 * @entry_idx: the entry index in the dma table
 * @st: PCIE TLP steering tag
 * @at:	PCIE TLP AT field
 * @ph: PCIE TLP Processing Hint field
 * @no_snooping: PCIE TLP No snooping
 * @tph_en: PCIE TLP Processing Hint Enable
 **/
static void set_pf_dma_attr_entry(struct hifc_hwdev *hwdev, u32 entry_idx,
				  u8 st, u8 at, u8 ph,
				  enum hifc_pcie_nosnoop no_snooping,
				  enum hifc_pcie_tph tph_en)
{
	u32 addr, val, dma_attr_entry;

	/* Read Modify Write */
	addr = HIFC_CSR_DMA_ATTR_TBL_ADDR(entry_idx);

	val = hifc_hwif_read_reg(hwdev->hwif, addr);
	val = HIFC_DMA_ATTR_ENTRY_CLEAR(val, ST)	&
		HIFC_DMA_ATTR_ENTRY_CLEAR(val, AT)	&
		HIFC_DMA_ATTR_ENTRY_CLEAR(val, PH)	&
		HIFC_DMA_ATTR_ENTRY_CLEAR(val, NO_SNOOPING)	&
		HIFC_DMA_ATTR_ENTRY_CLEAR(val, TPH_EN);

	dma_attr_entry = HIFC_DMA_ATTR_ENTRY_SET(st, ST)	|
			 HIFC_DMA_ATTR_ENTRY_SET(at, AT)	|
			 HIFC_DMA_ATTR_ENTRY_SET(ph, PH)	|
			 HIFC_DMA_ATTR_ENTRY_SET(no_snooping, NO_SNOOPING) |
			 HIFC_DMA_ATTR_ENTRY_SET(tph_en, TPH_EN);

	val |= dma_attr_entry;
	hifc_hwif_write_reg(hwdev->hwif, addr, val);
}

/**
 * dma_attr_table_init - initialize the the default dma attributes
 * @hwdev: the pointer to hw device
 * Return: 0 - success, negative - failure
 **/
static int dma_attr_table_init(struct hifc_hwdev *hwdev)
{
	int err = 0;

	set_pf_dma_attr_entry(hwdev, PCIE_MSIX_ATTR_ENTRY,
			      HIFC_PCIE_ST_DISABLE,
			      HIFC_PCIE_AT_DISABLE,
			      HIFC_PCIE_PH_DISABLE,
			      HIFC_PCIE_SNOOP,
			      HIFC_PCIE_TPH_DISABLE);

	return err;
}

static int resources_state_set(struct hifc_hwdev *hwdev,
			       enum hifc_res_state state)
{
	struct hifc_cmd_set_res_state res_state = {0};
	u16 out_size = sizeof(res_state);
	int err;

	err = hifc_global_func_id_get(hwdev, &res_state.func_idx);
	if (err)
		return err;

	res_state.state = state;

	err = hifc_msg_to_mgmt_sync(hwdev, HIFC_MOD_COMM,
				    HIFC_MGMT_CMD_RES_STATE_SET,
				    &res_state, sizeof(res_state),
				    &res_state, &out_size, 0);
	if (err || !out_size || res_state.status) {
		sdk_err(hwdev->dev_hdl, "Failed to set resources state, err: %d, status: 0x%x, out_size: 0x%x\n",
			err, res_state.status, out_size);
		return -EFAULT;
	}

	return 0;
}

static void comm_mgmt_msg_handler(void *hwdev, void *pri_handle, u8 cmd,
				  void *buf_in, u16 in_size, void *buf_out,
				  u16 *out_size)
{
	struct hifc_msg_pf_to_mgmt *pf_to_mgmt = pri_handle;
	u8 cmd_idx;
	u32 *mem;
	u16 i;

	for (cmd_idx = 0; cmd_idx < pf_to_mgmt->proc.cmd_num; cmd_idx++) {
		if (cmd == pf_to_mgmt->proc.info[cmd_idx].cmd) {
			if (!pf_to_mgmt->proc.info[cmd_idx].proc) {
				sdk_warn(pf_to_mgmt->hwdev->dev_hdl,
					 "PF recv up comm msg handle null, cmd(0x%x)\n",
					 cmd);
			} else {
				pf_to_mgmt->proc.info[cmd_idx].proc(hwdev,
					buf_in, in_size, buf_out, out_size);
			}

			return;
		}
	}

	sdk_warn(pf_to_mgmt->hwdev->dev_hdl, "Received mgmt cpu event: 0x%x\n",
		 cmd);

	mem = buf_in;
	for (i = 0; i < (in_size / sizeof(u32)); i++) {
		pr_info("0x%x\n", *mem);
		mem++;
	}

	*out_size = 0;
}

static int hifc_comm_aeqs_init(struct hifc_hwdev *hwdev)
{
	struct irq_info aeq_irqs[HIFC_MAX_AEQS] = {{0} };
	u16 num_aeqs, resp_num_irq = 0, i;
	int err;

	num_aeqs = HIFC_HWIF_NUM_AEQS(hwdev->hwif);
	if (num_aeqs > HIFC_MAX_AEQS) {
		sdk_warn(hwdev->dev_hdl, "Adjust aeq num to %d\n",
			 HIFC_MAX_AEQS);
		num_aeqs = HIFC_MAX_AEQS;
	}
	err = hifc_alloc_irqs(hwdev, SERVICE_T_INTF, num_aeqs, aeq_irqs,
			      &resp_num_irq);
	if (err) {
		sdk_err(hwdev->dev_hdl, "Failed to alloc aeq irqs, num_aeqs: %d\n",
			num_aeqs);
		return err;
	}

	if (resp_num_irq < num_aeqs) {
		sdk_warn(hwdev->dev_hdl, "Adjust aeq num to %d\n",
			 resp_num_irq);
		num_aeqs = resp_num_irq;
	}

	err = hifc_aeqs_init(hwdev, num_aeqs, aeq_irqs);
	if (err) {
		sdk_err(hwdev->dev_hdl, "Failed to init aeqs\n");
		goto aeqs_init_err;
	}

	set_bit(HIFC_HWDEV_AEQ_INITED, &hwdev->func_state);

	return 0;

aeqs_init_err:
	for (i = 0; i < num_aeqs; i++)
		hifc_free_irq(hwdev, SERVICE_T_INTF, aeq_irqs[i].irq_id);

	return err;
}

static void hifc_comm_aeqs_free(struct hifc_hwdev *hwdev)
{
	struct irq_info aeq_irqs[HIFC_MAX_AEQS] = {{0} };
	u16 num_irqs, i;

	clear_bit(HIFC_HWDEV_AEQ_INITED, &hwdev->func_state);

	hifc_get_aeq_irqs(hwdev, aeq_irqs, &num_irqs);
	hifc_aeqs_free(hwdev);
	for (i = 0; i < num_irqs; i++)
		hifc_free_irq(hwdev, SERVICE_T_INTF, aeq_irqs[i].irq_id);
}

static int hifc_comm_ceqs_init(struct hifc_hwdev *hwdev)
{
	struct irq_info ceq_irqs[HIFC_MAX_CEQS] = {{0} };
	u16 num_ceqs, resp_num_irq = 0, i;
	int err;

	num_ceqs = HIFC_HWIF_NUM_CEQS(hwdev->hwif);
	if (num_ceqs > HIFC_MAX_CEQS) {
		sdk_warn(hwdev->dev_hdl, "Adjust ceq num to %d\n",
			 HIFC_MAX_CEQS);
		num_ceqs = HIFC_MAX_CEQS;
	}

	err = hifc_alloc_irqs(hwdev, SERVICE_T_INTF, num_ceqs, ceq_irqs,
			      &resp_num_irq);
	if (err) {
		sdk_err(hwdev->dev_hdl, "Failed to alloc ceq irqs, num_ceqs: %d\n",
			num_ceqs);
		return err;
	}

	if (resp_num_irq < num_ceqs) {
		sdk_warn(hwdev->dev_hdl, "Adjust ceq num to %d\n",
			 resp_num_irq);
		num_ceqs = resp_num_irq;
	}

	err = hifc_ceqs_init(hwdev, num_ceqs, ceq_irqs);
	if (err) {
		sdk_err(hwdev->dev_hdl,
			"Failed to init ceqs, err:%d\n", err);
		goto ceqs_init_err;
	}

	return 0;

ceqs_init_err:
	for (i = 0; i < num_ceqs; i++)
		hifc_free_irq(hwdev, SERVICE_T_INTF, ceq_irqs[i].irq_id);

	return err;
}

static void hifc_comm_ceqs_free(struct hifc_hwdev *hwdev)
{
	struct irq_info ceq_irqs[HIFC_MAX_CEQS] = {{0} };
	u16 num_irqs;
	int i;

	hifc_get_ceq_irqs(hwdev, ceq_irqs, &num_irqs);
	hifc_ceqs_free(hwdev);
	for (i = 0; i < num_irqs; i++)
		hifc_free_irq(hwdev, SERVICE_T_INTF, ceq_irqs[i].irq_id);
}

static int hifc_comm_pf_to_mgmt_init(struct hifc_hwdev *hwdev)
{
	int err;

	if (hifc_func_type(hwdev) == TYPE_VF ||
	    !FUNC_SUPPORT_MGMT(hwdev))
		return 0; /* VF do not support send msg to mgmt directly */

	err = hifc_pf_to_mgmt_init(hwdev);
	if (err)
		return err;

	hifc_aeq_register_hw_cb(hwdev, HIFC_MSG_FROM_MGMT_CPU,
				hifc_mgmt_msg_aeqe_handler);

	hifc_register_mgmt_msg_cb(hwdev, HIFC_MOD_COMM,
				  hwdev->pf_to_mgmt, comm_mgmt_msg_handler);

	set_bit(HIFC_HWDEV_MGMT_INITED, &hwdev->func_state);

	return 0;
}

static void hifc_comm_pf_to_mgmt_free(struct hifc_hwdev *hwdev)
{
	if (hifc_func_type(hwdev) == TYPE_VF ||
	    !FUNC_SUPPORT_MGMT(hwdev))
		return;	/* VF do not support send msg to mgmt directly */

	hifc_unregister_mgmt_msg_cb(hwdev, HIFC_MOD_COMM);

	hifc_aeq_unregister_hw_cb(hwdev, HIFC_MSG_FROM_MGMT_CPU);

	hifc_pf_to_mgmt_free(hwdev);
}

static int hifc_comm_clp_to_mgmt_init(struct hifc_hwdev *hwdev)
{
	int err;

	if (hifc_func_type(hwdev) == TYPE_VF ||
	    !FUNC_SUPPORT_MGMT(hwdev))
		return 0;

	err = hifc_clp_pf_to_mgmt_init(hwdev);
	if (err)
		return err;

	set_bit(HIFC_HWDEV_CLP_INITED, &hwdev->func_state);

	return 0;
}

static void hifc_comm_clp_to_mgmt_free(struct hifc_hwdev *hwdev)
{
	if (hifc_func_type(hwdev) == TYPE_VF ||
	    !FUNC_SUPPORT_MGMT(hwdev))
		return;

	clear_bit(HIFC_HWDEV_CLP_INITED, &hwdev->func_state);
	hifc_clp_pf_to_mgmt_free(hwdev);
}

static int hifc_comm_cmdqs_init(struct hifc_hwdev *hwdev)
{
	int err;

	err = hifc_cmdqs_init(hwdev);
	if (err) {
		sdk_err(hwdev->dev_hdl, "Failed to init cmd queues\n");
		return err;
	}

	hifc_ceq_register_cb(hwdev, HIFC_CMDQ, hifc_cmdq_ceq_handler);

	err = hifc_set_cmdq_depth(hwdev, HIFC_CMDQ_DEPTH);
	if (err) {
		sdk_err(hwdev->dev_hdl, "Failed to set cmdq depth\n");
		goto set_cmdq_depth_err;
	}

	return 0;

set_cmdq_depth_err:
	hifc_cmdqs_free(hwdev);

	return err;
}

static void hifc_comm_cmdqs_free(struct hifc_hwdev *hwdev)
{
	hifc_ceq_unregister_cb(hwdev, HIFC_CMDQ);
	hifc_cmdqs_free(hwdev);
}

static int hifc_sync_mgmt_func_state(struct hifc_hwdev *hwdev)
{
	int err;

	hifc_set_pf_status(hwdev->hwif, HIFC_PF_STATUS_ACTIVE_FLAG);

	err = resources_state_set(hwdev, HIFC_RES_ACTIVE);
	if (err) {
		sdk_err(hwdev->dev_hdl,
			"Failed to set function resources state\n");
		goto resources_state_set_err;
	}

	hwdev->heartbeat_ehd.en = false;
	if (HIFC_FUNC_TYPE(hwdev) == TYPE_PPF) {
		/* heartbeat synchronize must be after set pf active status */
		hifc_comm_recv_mgmt_self_cmd_reg(
				hwdev, HIFC_MGMT_CMD_HEARTBEAT_EVENT,
				mgmt_heartbeat_event_handler);
	}

	return 0;

resources_state_set_err:
	hifc_set_pf_status(hwdev->hwif, HIFC_PF_STATUS_INIT);

	return err;
}

static void hifc_unsync_mgmt_func_state(struct hifc_hwdev *hwdev)
{
	hifc_set_pf_status(hwdev->hwif, HIFC_PF_STATUS_INIT);

	hwdev->heartbeat_ehd.en = false;
	if (HIFC_FUNC_TYPE(hwdev) == TYPE_PPF) {
		hifc_comm_recv_up_self_cmd_unreg(
				hwdev, HIFC_MGMT_CMD_HEARTBEAT_EVENT);
	}

	resources_state_set(hwdev, HIFC_RES_CLEAN);
}

int hifc_set_vport_enable(void *hwdev, bool enable)
{
	struct hifc_hwdev *nic_hwdev = (struct hifc_hwdev *)hwdev;
	struct hifc_vport_state en_state = {0};
	u16 out_size = sizeof(en_state);
	int err;

	if (!hwdev)
		return -EINVAL;

	err = hifc_global_func_id_get(hwdev, &en_state.func_id);
	if (err)
		return err;

	en_state.state = enable ? 1 : 0;

	err = l2nic_msg_to_mgmt_sync(hwdev, HIFC_PORT_CMD_SET_VPORT_ENABLE,
				     &en_state, sizeof(en_state),
				     &en_state, &out_size);
	if (err || !out_size || en_state.status) {
		sdk_err(nic_hwdev->dev_hdl, "Failed to set vport state, err: %d, status: 0x%x, out size: 0x%x\n",
			err, en_state.status, out_size);
		return -EINVAL;
	}

	return 0;
}

int hifc_l2nic_reset_base(struct hifc_hwdev *hwdev, u16 reset_flag)
{
	struct hifc_l2nic_reset l2nic_reset = {0};
	u16 out_size = sizeof(l2nic_reset);
	int err = 0;

	err = hifc_set_vport_enable(hwdev, false);
	if (err)
		return err;

	msleep(100);

	sdk_info(hwdev->dev_hdl, "L2nic reset flag 0x%x\n", reset_flag);

	err = hifc_global_func_id_get(hwdev, &l2nic_reset.func_id);
	if (err)
		return err;

	l2nic_reset.reset_flag = reset_flag;
	err = hifc_msg_to_mgmt_sync(hwdev, HIFC_MOD_COMM,
				    HIFC_MGMT_CMD_L2NIC_RESET, &l2nic_reset,
				    sizeof(l2nic_reset), &l2nic_reset,
				    &out_size, 0);
	if (err || !out_size || l2nic_reset.status) {
		sdk_err(hwdev->dev_hdl, "Failed to reset L2NIC resources, err: %d, status: 0x%x, out_size: 0x%x\n",
			err, l2nic_reset.status, out_size);
		return -EIO;
	}

	return 0;
}

static int hifc_l2nic_reset(struct hifc_hwdev *hwdev)
{
	return hifc_l2nic_reset_base(hwdev, 0);
}

static int __get_func_misc_info(struct hifc_hwdev *hwdev)
{
	int err;

	err = hifc_get_board_info(hwdev, &hwdev->board_info);
	if (err) {
		sdk_err(hwdev->dev_hdl, "Get board info failed\n");
		return err;
	}

	return 0;
}

static int init_func_mode(struct hifc_hwdev *hwdev)
{
	int err;

	err = __get_func_misc_info(hwdev);
	if (err) {
		sdk_err(hwdev->dev_hdl, "Failed to get function msic information\n");
		return err;
	}

	err = hifc_l2nic_reset(hwdev);
	if (err)
		return err;

	return 0;
}

static int __init_eqs_msix_attr(struct hifc_hwdev *hwdev)
{
	int err;

	err = init_aeqs_msix_attr(hwdev);
	if (err) {
		sdk_err(hwdev->dev_hdl, "Failed to init aeqs msix attr\n");
		return err;
	}

	err = init_ceqs_msix_attr(hwdev);
	if (err) {
		sdk_err(hwdev->dev_hdl, "Failed to init ceqs msix attr\n");
		return err;
	}

	return 0;
}

static int init_cmdqs_channel(struct hifc_hwdev *hwdev)
{
	u16 func_id;
	int err;

	dma_attr_table_init(hwdev);

	err = hifc_comm_ceqs_init(hwdev);
	if (err) {
		sdk_err(hwdev->dev_hdl, "Failed to init completion event queues\n");
		return err;
	}

	err = __init_eqs_msix_attr(hwdev);
	if (err)
		goto init_eqs_msix_err;

	/* set default wq page_size */
	hwdev->wq_page_size = HIFC_DEFAULT_WQ_PAGE_SIZE;

	err = hifc_global_func_id_get(hwdev, &func_id);
	if (err)
		goto get_func_id_err;

	err = hifc_set_wq_page_size(hwdev, func_id, hwdev->wq_page_size);
	if (err) {
		sdk_err(hwdev->dev_hdl, "Failed to set wq page size\n");
		goto init_wq_pg_size_err;
	}

	err = hifc_comm_cmdqs_init(hwdev);
	if (err) {
		sdk_err(hwdev->dev_hdl, "Failed to init cmd queues\n");
		goto cmdq_init_err;
	}

	set_bit(HIFC_HWDEV_CMDQ_INITED, &hwdev->func_state);

	return 0;

cmdq_init_err:
	if (HIFC_FUNC_TYPE(hwdev) != TYPE_VF)
		hifc_set_wq_page_size(hwdev, func_id, HIFC_HW_WQ_PAGE_SIZE);
init_wq_pg_size_err:
get_func_id_err:
init_eqs_msix_err:
	hifc_comm_ceqs_free(hwdev);

	return err;
}

static int init_mgmt_channel(struct hifc_hwdev *hwdev)
{
	int err;

	err = hifc_comm_clp_to_mgmt_init(hwdev);
	if (err) {
		sdk_err(hwdev->dev_hdl, "Failed to init clp\n");
		return err;
	}

	err = hifc_comm_aeqs_init(hwdev);
	if (err) {
		sdk_err(hwdev->dev_hdl, "Failed to init async event queues\n");
		goto aeqs_init_err;
	}

	err = hifc_comm_pf_to_mgmt_init(hwdev);
	if (err) {
		sdk_err(hwdev->dev_hdl, "Failed to init msg\n");
		goto msg_init_err;
	}

	return err;

msg_init_err:
	hifc_comm_aeqs_free(hwdev);

aeqs_init_err:
	hifc_comm_clp_to_mgmt_free(hwdev);

	return err;
}

/* initialize communication channel */
int hifc_init_comm_ch(struct hifc_hwdev *hwdev)
{
	int err;

	err = init_mgmt_channel(hwdev);
	if (err) {
		sdk_err(hwdev->dev_hdl, "Failed to init mgmt channel\n");
		return err;
	}

	err = init_func_mode(hwdev);
	if (err) {
		sdk_err(hwdev->dev_hdl, "Failed to init function mode\n");
		goto func_mode_err;
	}

	err = init_cmdqs_channel(hwdev);
	if (err) {
		sdk_err(hwdev->dev_hdl, "Failed to init cmdq channel\n");
		goto init_cmdqs_channel_err;
	}

	err = hifc_sync_mgmt_func_state(hwdev);
	if (err) {
		sdk_err(hwdev->dev_hdl, "Failed to synchronize mgmt function state\n");
		goto sync_mgmt_func_err;
	}

	err = hifc_aeq_register_swe_cb(hwdev, HIFC_STATELESS_EVENT,
				       hifc_nic_sw_aeqe_handler);
	if (err) {
		sdk_err(hwdev->dev_hdl,
			"Failed to register ucode aeqe handler\n");
		goto register_ucode_aeqe_err;
	}

	set_bit(HIFC_HWDEV_COMM_CH_INITED, &hwdev->func_state);

	return 0;

register_ucode_aeqe_err:
	hifc_unsync_mgmt_func_state(hwdev);
sync_mgmt_func_err:
	return err;

init_cmdqs_channel_err:

func_mode_err:
	return err;
}

static void __uninit_comm_module(struct hifc_hwdev *hwdev,
				 enum hifc_hwdev_init_state init_state)
{
	u16 func_id;

	switch (init_state) {
	case HIFC_HWDEV_COMM_CH_INITED:
		hifc_aeq_unregister_swe_cb(hwdev,
					   HIFC_STATELESS_EVENT);
		hifc_unsync_mgmt_func_state(hwdev);
		break;
	case HIFC_HWDEV_CMDQ_INITED:
		hifc_comm_cmdqs_free(hwdev);
		/* VF can set page size of 256K only, any other value
		 * will return error in pf, pf will set all vf's page
		 * size to 4K when disable sriov
		 */
		if (HIFC_FUNC_TYPE(hwdev) != TYPE_VF) {
			func_id = hifc_global_func_id_hw(hwdev);
			hifc_set_wq_page_size(hwdev, func_id,
					      HIFC_HW_WQ_PAGE_SIZE);
		}

		hifc_comm_ceqs_free(hwdev);

		break;
	case HIFC_HWDEV_MBOX_INITED:
		break;
	case HIFC_HWDEV_MGMT_INITED:
		hifc_comm_pf_to_mgmt_free(hwdev);
		break;
	case HIFC_HWDEV_AEQ_INITED:
		hifc_comm_aeqs_free(hwdev);
		break;
	case HIFC_HWDEV_CLP_INITED:
		hifc_comm_clp_to_mgmt_free(hwdev);
		break;
	default:
		break;
	}
}

#define HIFC_FUNC_STATE_BUSY_TIMEOUT	300
void hifc_uninit_comm_ch(struct hifc_hwdev *hwdev)
{
	enum hifc_hwdev_init_state init_state = HIFC_HWDEV_COMM_CH_INITED;
	int cnt;

	while (init_state > HIFC_HWDEV_NONE_INITED) {
		if (!test_bit(init_state, &hwdev->func_state)) {
			init_state--;
			continue;
		}
		clear_bit(init_state, &hwdev->func_state);

		cnt = 0;
		while (test_bit(HIFC_HWDEV_STATE_BUSY, &hwdev->func_state) &&
		       cnt++ <= HIFC_FUNC_STATE_BUSY_TIMEOUT)
			usleep_range(900, 1000);

		__uninit_comm_module(hwdev, init_state);

		init_state--;
	}
}

int hifc_slq_init(void *dev, int num_wqs)
{
	struct hifc_hwdev *hwdev = dev;
	int err;

	if (!dev)
		return -EINVAL;

	hwdev->wqs = kzalloc(sizeof(*hwdev->wqs), GFP_KERNEL);
	if (!hwdev->wqs)
		return -ENOMEM;

	err = hifc_wqs_alloc(hwdev->wqs, num_wqs, hwdev->dev_hdl);
	if (err) {
		sdk_err(hwdev->dev_hdl, "Failed to alloc wqs\n");
		kfree(hwdev->wqs);
		hwdev->wqs = NULL;
	}

	return err;
}

void hifc_slq_uninit(void *dev)
{
	struct hifc_hwdev *hwdev = dev;

	if (!hwdev)
		return;

	hifc_wqs_free(hwdev->wqs);

	kfree(hwdev->wqs);
}

int hifc_slq_alloc(void *dev, u16 wqebb_size, u16 q_depth, u16 page_size,
		   u64 *cla_addr, void **handle)
{
	struct hifc_hwdev *hwdev = dev;
	struct hifc_wq *wq;
	int err;

	if (!dev || !cla_addr || !handle)
		return -EINVAL;

	wq = kzalloc(sizeof(*wq), GFP_KERNEL);
	if (!wq)
		return -ENOMEM;

	err = hifc_wq_allocate(hwdev->wqs, wq, wqebb_size, hwdev->wq_page_size,
			       q_depth, 0);
	if (err) {
		sdk_err(hwdev->dev_hdl, "Failed to alloc wq\n");
		kfree(wq);
		return -EFAULT;
	}

	*cla_addr = wq->block_paddr;
	*handle = wq;

	return 0;
}

void hifc_slq_free(void *dev, void *handle)
{
	struct hifc_hwdev *hwdev = dev;

	if (!hwdev || !handle)
		return;

	hifc_wq_free(hwdev->wqs, handle);
	kfree(handle);
}

u64 hifc_slq_get_addr(void *handle, u16 index)
{
	if (!handle)
		return 0;	/* NULL of wqe addr */

	return (u64)hifc_get_wqebb_addr(handle, index);
}

u64 hifc_slq_get_first_pageaddr(void *handle)
{
	struct hifc_wq *wq = handle;

	if (!handle)
		return 0;	/* NULL of wqe addr */

	return hifc_get_first_wqe_page_addr(wq);
}

int hifc_func_tmr_bitmap_set(void *hwdev, bool en)
{
	struct hifc_func_tmr_bitmap_op bitmap_op = {0};
	u16 out_size = sizeof(bitmap_op);
	int err;

	if (!hwdev)
		return -EINVAL;

	err = hifc_global_func_id_get(hwdev, &bitmap_op.func_idx);
	if (err)
		return err;

	bitmap_op.ppf_idx = hifc_ppf_idx(hwdev);
	if (en)
		bitmap_op.op_id = FUNC_TMR_BITMAP_ENABLE;
	else
		bitmap_op.op_id = FUNC_TMR_BITMAP_DISABLE;

	err = hifc_msg_to_mgmt_sync(hwdev, HIFC_MOD_COMM,
				    HIFC_MGMT_CMD_FUNC_TMR_BITMAT_SET,
				    &bitmap_op, sizeof(bitmap_op),
				    &bitmap_op, &out_size, 0);
	if (err || !out_size || bitmap_op.status) {
		sdk_err(((struct hifc_hwdev *)hwdev)->dev_hdl,
			"Failed to set timer bitmap, err: %d, status: 0x%x, out_size: 0x%x\n",
			err, bitmap_op.status, out_size);
		return -EFAULT;
	}

	return 0;
}

int ppf_ht_gpa_set(struct hifc_hwdev *hwdev, struct hifc_page_addr *pg0,
		   struct hifc_page_addr *pg1)
{
	struct comm_info_ht_gpa_set ht_gpa_set = {0};
	u16 out_size = sizeof(ht_gpa_set);
	int ret;

	pg0->virt_addr = dma_alloc_coherent(hwdev->dev_hdl,
					    HIFC_HT_GPA_PAGE_SIZE,
					    &pg0->phys_addr, GFP_KERNEL);
	if (!pg0->virt_addr) {
		sdk_err(hwdev->dev_hdl, "Alloc pg0 page addr failed\n");
		return -EFAULT;
	}

	pg1->virt_addr = dma_alloc_coherent(hwdev->dev_hdl,
					    HIFC_HT_GPA_PAGE_SIZE,
					    &pg1->phys_addr, GFP_KERNEL);
	if (!pg1->virt_addr) {
		sdk_err(hwdev->dev_hdl, "Alloc pg1 page addr failed\n");
		return -EFAULT;
	}

	ht_gpa_set.page_pa0 = pg0->phys_addr;
	ht_gpa_set.page_pa1 = pg1->phys_addr;
	sdk_info(hwdev->dev_hdl, "PPF ht gpa set: page_addr0.pa=0x%llx, page_addr1.pa=0x%llx\n",
		 pg0->phys_addr, pg1->phys_addr);
	ret = hifc_msg_to_mgmt_sync(hwdev, HIFC_MOD_COMM,
				    HIFC_MGMT_CMD_PPF_HT_GPA_SET,
				    &ht_gpa_set, sizeof(ht_gpa_set),
				    &ht_gpa_set, &out_size, 0);
	if (ret || !out_size || ht_gpa_set.status) {
		sdk_warn(hwdev->dev_hdl, "PPF ht gpa set failed, ret: %d, status: 0x%x, out_size: 0x%x\n",
			 ret, ht_gpa_set.status, out_size);
		return -EFAULT;
	}

	hwdev->page_pa0.phys_addr = pg0->phys_addr;
	hwdev->page_pa0.virt_addr = pg0->virt_addr;

	hwdev->page_pa1.phys_addr = pg1->phys_addr;
	hwdev->page_pa1.virt_addr = pg1->virt_addr;

	return 0;
}

int hifc_ppf_ht_gpa_init(struct hifc_hwdev *hwdev)
{
	int ret;
	int i;
	int j;
	int size;

	struct hifc_page_addr page_addr0[HIFC_PPF_HT_GPA_SET_RETRY_TIMES];
	struct hifc_page_addr page_addr1[HIFC_PPF_HT_GPA_SET_RETRY_TIMES];

	size = HIFC_PPF_HT_GPA_SET_RETRY_TIMES * sizeof(page_addr0[0]);
	memset(page_addr0, 0, size);
	memset(page_addr1, 0, size);

	for (i = 0; i < HIFC_PPF_HT_GPA_SET_RETRY_TIMES; i++) {
		ret = ppf_ht_gpa_set(hwdev, &page_addr0[i], &page_addr1[i]);
		if (!ret)
			break;
	}

	for (j = 0; j < i; j++) {
		if (page_addr0[j].virt_addr) {
			dma_free_coherent(hwdev->dev_hdl,
					  HIFC_HT_GPA_PAGE_SIZE,
					  page_addr0[j].virt_addr,
					  page_addr0[j].phys_addr);
			page_addr0[j].virt_addr = NULL;
		}
		if (page_addr1[j].virt_addr) {
			dma_free_coherent(hwdev->dev_hdl,
					  HIFC_HT_GPA_PAGE_SIZE,
					  page_addr1[j].virt_addr,
					  page_addr1[j].phys_addr);
			page_addr1[j].virt_addr = NULL;
		}
	}

	if (i >= HIFC_PPF_HT_GPA_SET_RETRY_TIMES) {
		sdk_err(hwdev->dev_hdl, "PPF ht gpa init failed, retry times: %d\n",
			i);
		return -EFAULT;
	}

	return 0;
}

void hifc_ppf_ht_gpa_deinit(struct hifc_hwdev *hwdev)
{
	if (hwdev->page_pa0.virt_addr) {
		dma_free_coherent(hwdev->dev_hdl, HIFC_HT_GPA_PAGE_SIZE,
				  hwdev->page_pa0.virt_addr,
				  hwdev->page_pa0.phys_addr);
		hwdev->page_pa0.virt_addr = NULL;
	}

	if (hwdev->page_pa1.virt_addr) {
		dma_free_coherent(hwdev->dev_hdl, HIFC_HT_GPA_PAGE_SIZE,
				  hwdev->page_pa1.virt_addr,
				  hwdev->page_pa1.phys_addr);
		hwdev->page_pa1.virt_addr = NULL;
	}
}

static int set_ppf_tmr_status(struct hifc_hwdev *hwdev,
			      enum ppf_tmr_status status)
{
	struct hifc_ppf_tmr_op op = {0};
	u16 out_size = sizeof(op);
	int err = 0;

	if (!hwdev)
		return -EINVAL;

	if (hifc_func_type(hwdev) != TYPE_PPF)
		return -EFAULT;

	if (status == HIFC_PPF_TMR_FLAG_START) {
		err = hifc_ppf_ht_gpa_init(hwdev);
		if (err) {
			sdk_err(hwdev->dev_hdl, "PPF ht gpa init fail!\n");
			return -EFAULT;
		}
	} else {
		hifc_ppf_ht_gpa_deinit(hwdev);
	}

	op.op_id = status;
	op.ppf_idx = hifc_ppf_idx(hwdev);

	err = hifc_msg_to_mgmt_sync(hwdev, HIFC_MOD_COMM,
				    HIFC_MGMT_CMD_PPF_TMR_SET, &op,
				    sizeof(op), &op, &out_size, 0);
	if (err || !out_size || op.status) {
		sdk_err(hwdev->dev_hdl, "Failed to set ppf timer, err: %d, status: 0x%x, out_size: 0x%x\n",
			err, op.status, out_size);
		return -EFAULT;
	}

	return 0;
}

int hifc_ppf_tmr_start(void *hwdev)
{
	if (!hwdev) {
		pr_err("Hwdev pointer is NULL for starting ppf timer\n");
		return -EINVAL;
	}

	return set_ppf_tmr_status(hwdev, HIFC_PPF_TMR_FLAG_START);
}

int hifc_ppf_tmr_stop(void *hwdev)
{
	if (!hwdev) {
		pr_err("Hwdev pointer is NULL for stop ppf timer\n");
		return -EINVAL;
	}

	return set_ppf_tmr_status(hwdev, HIFC_PPF_TMR_FLAG_STOP);
}

int hifc_set_wq_page_size(struct hifc_hwdev *hwdev, u16 func_idx,
			  u32 page_size)
{
	struct hifc_wq_page_size page_size_info = {0};
	u16 out_size = sizeof(page_size_info);
	int err;

	page_size_info.func_idx = func_idx;
	page_size_info.ppf_idx = hifc_ppf_idx(hwdev);
	page_size_info.page_size = HIFC_PAGE_SIZE_HW(page_size);

	err = hifc_msg_to_mgmt_sync(hwdev, HIFC_MOD_COMM,
				    HIFC_MGMT_CMD_PAGESIZE_SET,
				    &page_size_info, sizeof(page_size_info),
				    &page_size_info, &out_size, 0);
	if (err || !out_size || page_size_info.status) {
		sdk_err(hwdev->dev_hdl, "Failed to set wq page size, err: %d, status: 0x%x, out_size: 0x%0x\n",
			err, page_size_info.status, out_size);
		return -EFAULT;
	}

	return 0;
}

bool hifc_mgmt_event_ack_first(u8 mod, u8 cmd)
{
	if ((mod == HIFC_MOD_COMM && cmd == HIFC_MGMT_CMD_GET_HOST_INFO) ||
	    (mod == HIFC_MOD_COMM && cmd == HIFC_MGMT_CMD_HEARTBEAT_EVENT))
		return false;

	if (mod == HIFC_MOD_COMM || mod == HIFC_MOD_L2NIC ||
	    mod == HIFC_MOD_HILINK)
		return true;

	return false;
}

#define FAULT_SHOW_STR_LEN 16

static void chip_fault_show(struct hifc_hwdev *hwdev,
			    struct hifc_fault_event *event)
{
	char fault_level[FAULT_LEVEL_MAX][FAULT_SHOW_STR_LEN + 1] = {
		"fatal", "reset", "flr", "general", "suggestion"};
	char level_str[FAULT_SHOW_STR_LEN + 1];
	struct hifc_fault_event_stats *fault;
	u8 node_id, level;
	u32 pos, base;

	fault = &hwdev->hw_stats.fault_event_stats;

	memset(level_str, 0, FAULT_SHOW_STR_LEN + 1);
	level = event->event.chip.err_level;
	if (level < FAULT_LEVEL_MAX)
		strncpy(level_str, fault_level[level],
			FAULT_SHOW_STR_LEN);
	else
		strncpy(level_str, "Unknown", FAULT_SHOW_STR_LEN);

	if (level == FAULT_LEVEL_SERIOUS_FLR) {
		sdk_err(hwdev->dev_hdl, "err_level: %d [%s], flr func_id: %d\n",
			level, level_str, event->event.chip.func_id);
		atomic_inc(&fault->fault_type_stat[event->type]);
	}
	sdk_err(hwdev->dev_hdl, "module_id: 0x%x, err_type: 0x%x, err_level: %d[%s], err_csr_addr: 0x%08x, err_csr_value: 0x%08x\n",
		event->event.chip.node_id,
		event->event.chip.err_type, level, level_str,
		event->event.chip.err_csr_addr,
		event->event.chip.err_csr_value);

	node_id = event->event.chip.node_id;
	atomic_inc(&fault->chip_fault_stats[node_id][level]);

	base = event->event.chip.node_id * FAULT_LEVEL_MAX *
	       HIFC_CHIP_ERROR_TYPE_MAX;
	pos = base + HIFC_CHIP_ERROR_TYPE_MAX * level +
	      event->event.chip.err_type;
	if (pos < HIFC_CHIP_FAULT_SIZE)
		hwdev->chip_fault_stats[pos]++;
}

static void fault_report_show(struct hifc_hwdev *hwdev,
			      struct hifc_fault_event *event)
{
	char fault_type[FAULT_TYPE_MAX][FAULT_SHOW_STR_LEN + 1] = {
		"chip", "ucode", "mem rd timeout", "mem wr timeout",
		"reg rd timeout", "reg wr timeout", "phy fault"};
	char type_str[FAULT_SHOW_STR_LEN + 1];
	struct hifc_fault_event_stats *fault;

	sdk_err(hwdev->dev_hdl, "Fault event report received, func_id: %d.\n",
		hifc_global_func_id(hwdev));

	memset(type_str, 0, FAULT_SHOW_STR_LEN + 1);
	if (event->type < FAULT_TYPE_MAX)
		strncpy(type_str, fault_type[event->type], FAULT_SHOW_STR_LEN);
	else
		strncpy(type_str, "Unknown", FAULT_SHOW_STR_LEN);

	sdk_err(hwdev->dev_hdl, "Fault type: %d [%s]\n", event->type, type_str);
	sdk_err(hwdev->dev_hdl, "Fault val[0]: 0x%08x, val[1]: 0x%08x, val[2]: 0x%08x, val[3]: 0x%08x\n",
		event->event.val[0], event->event.val[1], event->event.val[2],
		event->event.val[3]);

	fault = &hwdev->hw_stats.fault_event_stats;

	switch (event->type) {
	case FAULT_TYPE_CHIP:
		chip_fault_show(hwdev, event);
		break;
	case FAULT_TYPE_UCODE:
		atomic_inc(&fault->fault_type_stat[event->type]);

		sdk_err(hwdev->dev_hdl, "cause_id: %d, core_id: %d, c_id: %d, epc: 0x%08x\n",
			event->event.ucode.cause_id, event->event.ucode.core_id,
			event->event.ucode.c_id, event->event.ucode.epc);
		break;
	case FAULT_TYPE_MEM_RD_TIMEOUT:
	case FAULT_TYPE_MEM_WR_TIMEOUT:
		atomic_inc(&fault->fault_type_stat[event->type]);

		sdk_err(hwdev->dev_hdl, "err_csr_ctrl: 0x%08x, err_csr_data: 0x%08x, ctrl_tab: 0x%08x, mem_index: 0x%08x\n",
			event->event.mem_timeout.err_csr_ctrl,
			event->event.mem_timeout.err_csr_data,
			event->event.mem_timeout.ctrl_tab,
			event->event.mem_timeout.mem_index);
		break;
	case FAULT_TYPE_REG_RD_TIMEOUT:
	case FAULT_TYPE_REG_WR_TIMEOUT:
		atomic_inc(&fault->fault_type_stat[event->type]);
		sdk_err(hwdev->dev_hdl, "err_csr:       0x%08x\n",
			event->event.reg_timeout.err_csr);
		break;
	case FAULT_TYPE_PHY_FAULT:
		atomic_inc(&fault->fault_type_stat[event->type]);
		sdk_err(hwdev->dev_hdl, "op_type: %u, port_id: %u, dev_ad: %u, csr_addr: 0x%08x, op_data: 0x%08x\n",
			event->event.phy_fault.op_type,
			event->event.phy_fault.port_id,
			event->event.phy_fault.dev_ad,
			event->event.phy_fault.csr_addr,
			event->event.phy_fault.op_data);
		break;
	default:
		break;
	}
}

static void hifc_refresh_history_fault(struct hifc_hwdev *hwdev,
				       struct hifc_fault_recover_info *info)
{
	if (!hwdev->history_fault_flag) {
		hwdev->history_fault_flag = true;
		memcpy(&hwdev->history_fault, info,
		       sizeof(struct hifc_fault_recover_info));
	} else {
		if (hwdev->history_fault.fault_lev >= info->fault_lev)
			memcpy(&hwdev->history_fault, info,
			       sizeof(struct hifc_fault_recover_info));
	}
}

static void fault_event_handler(struct hifc_hwdev *hwdev, void *buf_in,
				u16 in_size, void *buf_out, u16 *out_size)
{
	struct hifc_cmd_fault_event *fault_event;
	struct hifc_event_info event_info;
	struct hifc_fault_info_node *fault_node;

	if (in_size != sizeof(*fault_event)) {
		sdk_err(hwdev->dev_hdl, "Invalid fault event report, length: %d, should be %ld.\n",
			in_size, sizeof(*fault_event));
		return;
	}

	fault_event = buf_in;
	fault_report_show(hwdev, &fault_event->event);

	if (hwdev->event_callback) {
		event_info.type = HIFC_EVENT_FAULT;
		memcpy(&event_info.info, &fault_event->event,
		       sizeof(event_info.info));

		hwdev->event_callback(hwdev->event_pri_handle, &event_info);
	}

	/* refresh history fault info */
	fault_node = kzalloc(sizeof(*fault_node), GFP_KERNEL);
	if (!fault_node) {
		sdk_err(hwdev->dev_hdl, "Malloc fault node memory failed\n");
		return;
	}

	if (fault_event->event.type <= FAULT_TYPE_REG_WR_TIMEOUT)
		fault_node->info.fault_src = fault_event->event.type;
	else if (fault_event->event.type == FAULT_TYPE_PHY_FAULT)
		fault_node->info.fault_src = HIFC_FAULT_SRC_HW_PHY_FAULT;

	if (fault_node->info.fault_src == HIFC_FAULT_SRC_HW_MGMT_CHIP)
		fault_node->info.fault_lev =
					fault_event->event.event.chip.err_level;
	else
		fault_node->info.fault_lev = FAULT_LEVEL_FATAL;

	memcpy(&fault_node->info.fault_data.hw_mgmt, &fault_event->event.event,
	       sizeof(union hifc_fault_hw_mgmt));
	hifc_refresh_history_fault(hwdev, &fault_node->info);

	down(&hwdev->fault_list_sem);
	kfree(fault_node);
	up(&hwdev->fault_list_sem);
}

static void heartbeat_lost_event_handler(struct hifc_hwdev *hwdev,
					 void *buf_in, u16 in_size,
					 void *buf_out, u16 *out_size)
{
	struct hifc_fault_info_node *fault_node;
	struct hifc_event_info event_info = {0};

	atomic_inc(&hwdev->hw_stats.heart_lost_stats);
	sdk_err(hwdev->dev_hdl, "Heart lost report received, func_id: %d\n",
		hifc_global_func_id(hwdev));

	if (hwdev->event_callback) {
		event_info.type = HIFC_EVENT_HEART_LOST;
		hwdev->event_callback(hwdev->event_pri_handle, &event_info);
	}

	/* refresh history fault info */
	fault_node = kzalloc(sizeof(*fault_node), GFP_KERNEL);
	if (!fault_node) {
		sdk_err(hwdev->dev_hdl, "Malloc fault node memory failed\n");
		return;
	}

	fault_node->info.fault_src = HIFC_FAULT_SRC_HOST_HEARTBEAT_LOST;
	fault_node->info.fault_lev = FAULT_LEVEL_FATAL;
	hifc_refresh_history_fault(hwdev, &fault_node->info);

	down(&hwdev->fault_list_sem);
	kfree(fault_node);
	up(&hwdev->fault_list_sem);
}

static void sw_watchdog_timeout_info_show(struct hifc_hwdev *hwdev,
					  void *buf_in, u16 in_size,
					  void *buf_out, u16 *out_size)
{
	struct hifc_mgmt_watchdog_info *watchdog_info;
	u32 *dump_addr, *reg, stack_len, i, j;

	if (in_size != sizeof(*watchdog_info)) {
		sdk_err(hwdev->dev_hdl, "Invalid mgmt watchdog report, length: %d, should be %ld.\n",
			in_size, sizeof(*watchdog_info));
		return;
	}

	watchdog_info = buf_in;

	sdk_err(hwdev->dev_hdl, "Mgmt deadloop time: 0x%x 0x%x, task id: 0x%x, sp: 0x%x\n",
		watchdog_info->curr_time_h, watchdog_info->curr_time_l,
		watchdog_info->task_id, watchdog_info->sp);
	sdk_err(hwdev->dev_hdl, "Stack current used: 0x%x, peak used: 0x%x, overflow flag: 0x%x, top: 0x%x, bottom: 0x%x\n",
		watchdog_info->curr_used, watchdog_info->peak_used,
		watchdog_info->is_overflow, watchdog_info->stack_top,
		watchdog_info->stack_bottom);

	sdk_err(hwdev->dev_hdl, "Mgmt pc: 0x%08x, lr: 0x%08x, cpsr:0x%08x\n",
		watchdog_info->pc, watchdog_info->lr, watchdog_info->cpsr);

	sdk_err(hwdev->dev_hdl, "Mgmt register info\n");

	for (i = 0; i < 3; i++) {
		reg = watchdog_info->reg + (u64)(u32)(4 * i);
		sdk_err(hwdev->dev_hdl, "0x%08x 0x%08x 0x%08x 0x%08x\n",
			*(reg), *(reg + 1), *(reg + 2), *(reg + 3));
	}

	sdk_err(hwdev->dev_hdl, "0x%08x\n", watchdog_info->reg[12]);

	if (watchdog_info->stack_actlen <= 1024) {
		stack_len = watchdog_info->stack_actlen;
	} else {
		sdk_err(hwdev->dev_hdl, "Oops stack length: 0x%x is wrong\n",
			watchdog_info->stack_actlen);
		stack_len = 1024;
	}

	sdk_err(hwdev->dev_hdl, "Mgmt dump stack, 16Bytes per line(start from sp)\n");
	for (i = 0; i < (stack_len / 16); i++) {
		dump_addr = (u32 *)(watchdog_info->data + ((u64)(u32)(i * 16)));
		sdk_err(hwdev->dev_hdl, "0x%08x 0x%08x 0x%08x 0x%08x\n",
			*dump_addr, *(dump_addr + 1), *(dump_addr + 2),
			*(dump_addr + 3));
	}

	for (j = 0; j < ((stack_len % 16) / 4); j++) {
		dump_addr = (u32 *)(watchdog_info->data +
			    ((u64)(u32)(i * 16 + j * 4)));
		sdk_err(hwdev->dev_hdl, "0x%08x ", *dump_addr);
	}

	*out_size = sizeof(*watchdog_info);
	watchdog_info = buf_out;
	watchdog_info->status = 0;
}

static void mgmt_watchdog_timeout_event_handler(struct hifc_hwdev *hwdev,
						void *buf_in, u16 in_size,
						void *buf_out, u16 *out_size)
{
	struct hifc_fault_info_node *fault_node;

	sw_watchdog_timeout_info_show(hwdev, buf_in, in_size,
				      buf_out, out_size);

	/* refresh history fault info */
	fault_node = kzalloc(sizeof(*fault_node), GFP_KERNEL);
	if (!fault_node) {
		sdk_err(hwdev->dev_hdl, "Malloc fault node memory failed\n");
		return;
	}

	fault_node->info.fault_src = HIFC_FAULT_SRC_MGMT_WATCHDOG;
	fault_node->info.fault_lev = FAULT_LEVEL_FATAL;
	hifc_refresh_history_fault(hwdev, &fault_node->info);

	down(&hwdev->fault_list_sem);
	kfree(fault_node);
	up(&hwdev->fault_list_sem);
}

static void mgmt_reset_event_handler(struct hifc_hwdev *hwdev,
				     void *buf_in, u16 in_size,
				     void *buf_out, u16 *out_size)
{
	sdk_info(hwdev->dev_hdl, "Mgmt is reset\n");

	/* mgmt reset only occurred when hot update or Mgmt deadloop,
	 * if Mgmt deadloop, mgmt will report an event with
	 * mod=0, cmd=0x56, and will reported fault to os,
	 * so mgmt reset event don't need to report fault
	 */
}

static void hifc_fmw_act_ntc_handler(struct hifc_hwdev *hwdev,
				     void *buf_in, u16 in_size,
				     void *buf_out, u16 *out_size)
{
	struct hifc_event_info event_info = {0};
	struct hifc_fmw_act_ntc *notice_info;

	if (in_size != sizeof(*notice_info)) {
		sdk_err(hwdev->dev_hdl, "Invalid mgmt firmware active notice, length: %d, should be %ld.\n",
			in_size, sizeof(*notice_info));
		return;
	}

	/* mgmt is active now, restart heartbeat enhanced detection */
	__set_heartbeat_ehd_detect_delay(hwdev, 0);

	if (!hwdev->event_callback)
		return;

	event_info.type = HIFC_EVENT_FMW_ACT_NTC;
	hwdev->event_callback(hwdev->event_pri_handle, &event_info);

	*out_size = sizeof(*notice_info);
	notice_info = buf_out;
	notice_info->status = 0;
}

static void hifc_pcie_dfx_event_handler(struct hifc_hwdev *hwdev,
					void *buf_in, u16 in_size,
					void *buf_out, u16 *out_size)
{
	struct hifc_pcie_dfx_ntc *notice_info = buf_in;
	struct hifc_pcie_dfx_info *dfx_info;
	u16 size = 0;
	u16 cnt = 0;
	u32 num = 0;
	u32 i, j;
	int err;
	u32 *reg;

	if (in_size != sizeof(*notice_info)) {
		sdk_err(hwdev->dev_hdl, "Invalid mgmt firmware active notice, length: %d, should be %ld.\n",
			in_size, sizeof(*notice_info));
		return;
	}

	dfx_info = kzalloc(sizeof(*dfx_info), GFP_KERNEL);
	if (!dfx_info) {
		sdk_err(hwdev->dev_hdl, "Malloc dfx_info memory failed\n");
		return;
	}

	((struct hifc_pcie_dfx_ntc *)buf_out)->status = 0;
	*out_size = sizeof(*notice_info);
	num = (u32)(notice_info->len / 1024);
	sdk_info(hwdev->dev_hdl, "INFO LEN: %d\n", notice_info->len);
	sdk_info(hwdev->dev_hdl, "PCIE DFX:\n");
	dfx_info->host_id = 0;
	for (i = 0; i < num; i++) {
		dfx_info->offset = i * MAX_PCIE_DFX_BUF_SIZE;
		if (i == (num - 1))
			dfx_info->last = 1;
		size = sizeof(*dfx_info);
		err = hifc_msg_to_mgmt_sync(hwdev, HIFC_MOD_COMM,
					    HIFC_MGMT_CMD_PCIE_DFX_GET,
					    dfx_info, sizeof(*dfx_info),
					    dfx_info, &size, 0);
		if (err || dfx_info->status || !size) {
			sdk_err(((struct hifc_hwdev *)hwdev)->dev_hdl,
				"Failed to get pcie dfx info, err: %d, status: 0x%x, out size: 0x%x\n",
				err, dfx_info->status, size);
			kfree(dfx_info);
			return;
		}

		reg = (u32 *)dfx_info->data;
		for (j = 0; j < 256; j = j + 8) {
			/*lint -save -e661 -e662*/
			sdk_info(hwdev->dev_hdl, "0x%04x: 0x%08x 0x%08x 0x%08x 0x%08x 0x%08x 0x%08x 0x%08x 0x%08x\n",
				 cnt, reg[j], reg[(u32)(j + 1)],
				 reg[(u32)(j + 2)], reg[(u32)(j + 3)],
				 reg[(u32)(j + 4)], reg[(u32)(j + 5)],
				 reg[(u32)(j + 6)], reg[(u32)(j + 7)]);
			/*lint -restore*/
			cnt = cnt + 32;
		}
		memset(dfx_info->data, 0, MAX_PCIE_DFX_BUF_SIZE);
	}
	kfree(dfx_info);
}

struct hifc_mctp_get_host_info {
	u8 status;
	u8 version;
	u8 rsvd0[6];

	u8 huawei_cmd;
	u8 sub_cmd;
	u8 rsvd[2];

	u32 actual_len;

	u8 data[1024];
};

static void hifc_mctp_get_host_info_event_handler(struct hifc_hwdev *hwdev,
						  void *buf_in, u16 in_size,
						  void *buf_out, u16 *out_size)
{
	struct hifc_event_info event_info = {0};
	struct hifc_mctp_get_host_info *mctp_out, *mctp_in;
	struct hifc_mctp_host_info *host_info;

	if (in_size != sizeof(*mctp_in)) {
		sdk_err(hwdev->dev_hdl, "Invalid mgmt mctp info, length: %d, should be %ld\n",
			in_size, sizeof(*mctp_in));
		return;
	}

	*out_size = sizeof(*mctp_out);
	mctp_out = buf_out;
	mctp_out->status = 0;

	if (!hwdev->event_callback) {
		mctp_out->status = HIFC_MGMT_STATUS_ERR_INIT;
		return;
	}

	mctp_in = buf_in;
	host_info = &event_info.mctp_info;
	host_info->major_cmd = mctp_in->huawei_cmd;
	host_info->sub_cmd = mctp_in->sub_cmd;
	host_info->data = mctp_out->data;

	event_info.type = HIFC_EVENT_MCTP_GET_HOST_INFO;
	hwdev->event_callback(hwdev->event_pri_handle, &event_info);

	mctp_out->actual_len = host_info->data_len;
}

char *__hw_to_char_fec[HILINK_FEC_MAX_TYPE] = {"RS-FEC", "BASE-FEC", "NO-FEC"};

char *__hw_to_char_port_type[LINK_PORT_MAX_TYPE] = {
	"Unknown", "Fibre", "Electric", "Direct Attach Copper", "AOC",
	"Back plane", "BaseT"
};

static void __get_port_type(struct hifc_hwdev *hwdev,
			    struct hifc_link_info *info, char **port_type)
{
	if (info->cable_absent) {
		sdk_info(hwdev->dev_hdl, "Cable unpresent\n");
		return;
	}

	if (info->port_type < LINK_PORT_MAX_TYPE)
		*port_type = __hw_to_char_port_type[info->port_type];
	else
		sdk_info(hwdev->dev_hdl, "Unknown port type: %u\n",
			 info->port_type);
	if (info->port_type == LINK_PORT_FIBRE) {
		if (info->port_sub_type == FIBRE_SUBTYPE_SR)
			*port_type = "Fibre-SR";
		else if (info->port_sub_type == FIBRE_SUBTYPE_LR)
			*port_type = "Fibre-LR";
	}
}

static void __print_cable_info(struct hifc_hwdev *hwdev,
			       struct hifc_link_info *info)
{
	char tmp_str[512] = {0};
	char tmp_vendor[17] = {0};
	char *port_type = "Unknown port type";
	int i;

	__get_port_type(hwdev, info, &port_type);

	for (i = sizeof(info->vendor_name) - 1; i >= 0; i--) {
		if (info->vendor_name[i] == ' ')
			info->vendor_name[i] = '\0';
		else
			break;
	}

	memcpy(tmp_vendor, info->vendor_name,
	       sizeof(info->vendor_name));
	snprintf(tmp_str, sizeof(tmp_str) - 1,
		 "Vendor: %s, %s, length: %um, max_speed: %uGbps",
		 tmp_vendor, port_type, info->cable_length,
		 info->cable_max_speed);
	if (info->port_type == LINK_PORT_FIBRE ||
	    info->port_type == LINK_PORT_AOC) {
		snprintf(tmp_str, sizeof(tmp_str) - 1,
			 "%s, %s, Temperature: %u", tmp_str,
			 info->sfp_type ? "SFP" : "QSFP", info->cable_temp);
		if (info->sfp_type) {
			snprintf(tmp_str, sizeof(tmp_str) - 1,
				 "%s, rx power: %uuW, tx power: %uuW",
				 tmp_str, info->power[0], info->power[1]);
		} else {
			snprintf(tmp_str, sizeof(tmp_str) - 1,
				 "%s, rx power: %uuw %uuW %uuW %uuW",
				 tmp_str, info->power[0], info->power[1],
				 info->power[2], info->power[3]);
		}
	}

	sdk_info(hwdev->dev_hdl, "Cable information: %s\n",
		 tmp_str);
}

static void __hi30_lane_info(struct hifc_hwdev *hwdev,
			     struct hilink_lane *lane)
{
	struct hi30_ffe_data *ffe_data;
	struct hi30_ctle_data *ctle_data;

	ffe_data = (struct hi30_ffe_data *)lane->hi30_ffe;
	ctle_data = (struct hi30_ctle_data *)lane->hi30_ctle;

	sdk_info(hwdev->dev_hdl, "TX_FFE: PRE1=%s%d; PRE2=%s%d; MAIN=%d; POST1=%s%d; POST1X=%s%d\n",
		 (ffe_data->PRE1 & 0x10) ? "-" : "",
		 (int)(ffe_data->PRE1 & 0xf),
		 (ffe_data->PRE2 & 0x10) ? "-" : "",
		 (int)(ffe_data->PRE2 & 0xf),
		 (int)ffe_data->MAIN,
		 (ffe_data->POST1 & 0x10) ? "-" : "",
		 (int)(ffe_data->POST1 & 0xf),
		 (ffe_data->POST2 & 0x10) ? "-" : "",
		 (int)(ffe_data->POST2 & 0xf));
	sdk_info(hwdev->dev_hdl, "RX_CTLE: Gain1~3=%u %u %u; Boost1~3=%u %u %u; Zero1~3=%u %u %u; Squelch1~3=%u %u %u\n",
		 ctle_data->ctlebst[0], ctle_data->ctlebst[1],
		 ctle_data->ctlebst[2], ctle_data->ctlecmband[0],
		 ctle_data->ctlecmband[1], ctle_data->ctlecmband[2],
		 ctle_data->ctlermband[0], ctle_data->ctlermband[1],
		 ctle_data->ctlermband[2], ctle_data->ctleza[0],
		 ctle_data->ctleza[1], ctle_data->ctleza[2]);
}

static void __print_hi30_status(struct hifc_hwdev *hwdev,
				struct hifc_link_info *info)
{
	struct hilink_lane *lane;
	int lane_used_num = 0, i;

	for (i = 0; i < HILINK_MAX_LANE; i++) {
		lane = (struct hilink_lane *)(info->lane2 + i * sizeof(*lane));
		if (!lane->lane_used)
			continue;

		__hi30_lane_info(hwdev, lane);
		lane_used_num++;
	}

	/* in new firmware, all lane info setted in lane2 */
	if (lane_used_num)
		return;

	/* compatible old firmware */
	__hi30_lane_info(hwdev, (struct hilink_lane *)info->lane1);
}

static void __print_link_info(struct hifc_hwdev *hwdev,
			      struct hifc_link_info *info,
			      enum hilink_info_print_event type)
{
	char *fec = "None";

	if (info->fec < HILINK_FEC_MAX_TYPE)
		fec = __hw_to_char_fec[info->fec];
	else
		sdk_info(hwdev->dev_hdl, "Unknown fec type: %u\n",
			 info->fec);

	if (type == HILINK_EVENT_LINK_UP || !info->an_state) {
		sdk_info(hwdev->dev_hdl, "Link information: speed %dGbps, %s, autoneg %s\n",
			 info->speed, fec, info->an_state ? "on" : "off");
	} else {
		sdk_info(hwdev->dev_hdl, "Link information: antoneg: %s\n",
			 info->an_state ? "on" : "off");
	}
}

static char *hilink_info_report_type[HILINK_EVENT_MAX_TYPE] = {
	"", "link up", "link down", "cable plugged"
};

void print_hilink_info(struct hifc_hwdev *hwdev,
		       enum hilink_info_print_event type,
		       struct hifc_link_info *info)
{
	__print_cable_info(hwdev, info);

	__print_link_info(hwdev, info, type);

	__print_hi30_status(hwdev, info);

	if (type == HILINK_EVENT_LINK_UP)
		return;

	if (type == HILINK_EVENT_CABLE_PLUGGED) {
		sdk_info(hwdev->dev_hdl, "alos: %u, rx_los: %u\n",
			 info->alos, info->rx_los);
		return;
	}

	sdk_info(hwdev->dev_hdl, "PMA ctrl: %s, MAC tx %s, MAC rx %s, PMA debug info reg: 0x%x, PMA signal ok reg: 0x%x, RF/LF status reg: 0x%x\n",
		 info->pma_status == 1 ? "off" : "on",
		 info->mac_tx_en ? "enable" : "disable",
		 info->mac_rx_en ? "enable" : "disable", info->pma_dbg_info_reg,
		 info->pma_signal_ok_reg, info->rf_lf_status_reg);
	sdk_info(hwdev->dev_hdl, "alos: %u, rx_los: %u, PCS block counter reg: 0x%x, PCS link: 0x%x, MAC link: 0x%x PCS_err_cnt: 0x%x\n",
		 info->alos, info->rx_los, info->pcs_err_blk_cnt_reg,
		 info->pcs_link_reg, info->mac_link_reg, info->pcs_err_cnt);
}

static void hifc_print_hilink_info(struct hifc_hwdev *hwdev, void *buf_in,
				   u16 in_size, void *buf_out, u16 *out_size)
{
	struct hifc_hilink_link_info *hilink_info = buf_in;
	struct hifc_link_info *info;
	enum hilink_info_print_event type;

	if (in_size != sizeof(*hilink_info)) {
		sdk_err(hwdev->dev_hdl, "Invalid hilink info message size %d, should be %ld\n",
			in_size, sizeof(*hilink_info));
		return;
	}

	((struct hifc_hilink_link_info *)buf_out)->status = 0;
	*out_size = sizeof(*hilink_info);

	info = &hilink_info->info;
	type = hilink_info->info_type;

	if (type < HILINK_EVENT_LINK_UP || type >= HILINK_EVENT_MAX_TYPE) {
		sdk_info(hwdev->dev_hdl, "Invalid hilink info report, type: %d\n",
			 type);
		return;
	}

	sdk_info(hwdev->dev_hdl, "Hilink info report after %s\n",
		 hilink_info_report_type[type]);

	print_hilink_info(hwdev, type, info);
}

static void __port_sfp_info_event(struct hifc_hwdev *hwdev,
				  void *buf_in, u16 in_size,
				  void *buf_out, u16 *out_size)
{
	struct hifc_cmd_get_sfp_qsfp_info *sfp_info = buf_in;
	struct hifc_port_routine_cmd *rt_cmd;
	struct card_node *chip_node = hwdev->chip_node;

	if (in_size != sizeof(*sfp_info)) {
		sdk_err(hwdev->dev_hdl, "Invalid sfp info cmd, length: %d, should be %ld\n",
			in_size, sizeof(*sfp_info));
		return;
	}

	if (sfp_info->port_id >= HIFC_MAX_PORT_ID) {
		sdk_err(hwdev->dev_hdl, "Invalid sfp port id: %d, max port is %d\n",
			sfp_info->port_id, HIFC_MAX_PORT_ID - 1);
		return;
	}

	if (!chip_node->rt_cmd)
		return;

	rt_cmd = &chip_node->rt_cmd[sfp_info->port_id];
	mutex_lock(&chip_node->sfp_mutex);
	memcpy(&rt_cmd->sfp_info, sfp_info, sizeof(rt_cmd->sfp_info));
	rt_cmd->up_send_sfp_info = true;
	mutex_unlock(&chip_node->sfp_mutex);
}

static void __port_sfp_abs_event(struct hifc_hwdev *hwdev,
				 void *buf_in, u16 in_size,
				 void *buf_out, u16 *out_size)
{
	struct hifc_cmd_get_light_module_abs *sfp_abs = buf_in;
	struct hifc_port_routine_cmd *rt_cmd;
	struct card_node *chip_node = hwdev->chip_node;

	if (in_size != sizeof(*sfp_abs)) {
		sdk_err(hwdev->dev_hdl, "Invalid sfp absent cmd, length: %d, should be %ld\n",
			in_size, sizeof(*sfp_abs));
		return;
	}

	if (sfp_abs->port_id >= HIFC_MAX_PORT_ID) {
		sdk_err(hwdev->dev_hdl, "Invalid sfp port id: %d, max port is %d\n",
			sfp_abs->port_id, HIFC_MAX_PORT_ID - 1);
		return;
	}

	if (!chip_node->rt_cmd)
		return;

	rt_cmd = &chip_node->rt_cmd[sfp_abs->port_id];
	mutex_lock(&chip_node->sfp_mutex);
	memcpy(&rt_cmd->abs, sfp_abs, sizeof(rt_cmd->abs));
	rt_cmd->up_send_sfp_abs = true;
	mutex_unlock(&chip_node->sfp_mutex);
}

static void mgmt_heartbeat_enhanced_event(struct hifc_hwdev *hwdev,
					  void *buf_in, u16 in_size,
					  void *buf_out, u16 *out_size)
{
	struct hifc_heartbeat_event *hb_event = buf_in;
	struct hifc_heartbeat_event *hb_event_out = buf_out;
	struct hifc_hwdev *dev = hwdev;

	if (in_size != sizeof(*hb_event)) {
		sdk_err(dev->dev_hdl, "Invalid data size from mgmt for heartbeat event: %d\n",
			in_size);
		return;
	}

	if (dev->heartbeat_ehd.last_heartbeat != hb_event->heart) {
		dev->heartbeat_ehd.last_update_jiffies = jiffies;
		dev->heartbeat_ehd.last_heartbeat = hb_event->heart;
	}

	hb_event_out->drv_heart = HEARTBEAT_DRV_MAGIC_ACK;

	hb_event_out->status = 0;
	*out_size = sizeof(*hb_event_out);
}

struct dev_event_handler {
	u8 mod;
	u8 cmd;
	void (*handler)(struct hifc_hwdev *hwdev, void *buf_in, u16 in_size,
			void *buf_out, u16 *out_size);
};

struct dev_event_handler dev_cmd_handler[] = {
	{
		.mod = HIFC_MOD_L2NIC,
		.cmd = HIFC_PORT_CMD_GET_SFP_INFO,
		.handler = __port_sfp_info_event,
	},

	{
		.mod = HIFC_MOD_L2NIC,
		.cmd = HIFC_PORT_CMD_GET_SFP_ABS,
		.handler = __port_sfp_abs_event,
	},

	{
		.mod	= HIFC_MOD_HILINK,
		.cmd	= HIFC_HILINK_CMD_GET_LINK_INFO,
		.handler = hifc_print_hilink_info,
	},

	{
		.mod	= HIFC_MOD_COMM,
		.cmd	= HIFC_MGMT_CMD_FAULT_REPORT,
		.handler = fault_event_handler,
	},

	{
		.mod	= HIFC_MOD_L2NIC,
		.cmd	= HIFC_MGMT_CMD_HEART_LOST_REPORT,
		.handler = heartbeat_lost_event_handler,
	},

	{
		.mod	= HIFC_MOD_COMM,
		.cmd	= HIFC_MGMT_CMD_WATCHDOG_INFO,
		.handler = mgmt_watchdog_timeout_event_handler,
	},

	{
		.mod	= HIFC_MOD_L2NIC,
		.cmd	= HIFC_PORT_CMD_MGMT_RESET,
		.handler = mgmt_reset_event_handler,
	},

	{
		.mod	= HIFC_MOD_COMM,
		.cmd	= HIFC_MGMT_CMD_FMW_ACT_NTC,
		.handler = hifc_fmw_act_ntc_handler,
	},

	{
		.mod	= HIFC_MOD_COMM,
		.cmd	= HIFC_MGMT_CMD_PCIE_DFX_NTC,
		.handler = hifc_pcie_dfx_event_handler,
	},

	{
		.mod	= HIFC_MOD_COMM,
		.cmd	= HIFC_MGMT_CMD_GET_HOST_INFO,
		.handler = hifc_mctp_get_host_info_event_handler,
	},

	{
		.mod	= HIFC_MOD_COMM,
		.cmd	= HIFC_MGMT_CMD_HEARTBEAT_EVENT,
		.handler = mgmt_heartbeat_enhanced_event,
	},
};

/* public process for this event:
 * pf link change event
 * pf heart lost event ,TBD
 * pf fault report event
 * vf link change event
 * vf heart lost event, TBD
 * vf fault report event, TBD
 */
static void _event_handler(struct hifc_hwdev *hwdev, enum hifc_mod_type mod,
			   u8 cmd, void *buf_in, u16 in_size,
			   void *buf_out, u16 *out_size)
{
	u32 i, size = sizeof(dev_cmd_handler) / sizeof(dev_cmd_handler[0]);

	if (!hwdev)
		return;

	*out_size = 0;

	for (i = 0; i < size; i++) {
		if (cmd == dev_cmd_handler[i].cmd &&
		    mod == dev_cmd_handler[i].mod) {
			dev_cmd_handler[i].handler(hwdev, buf_in, in_size,
						   buf_out, out_size);
			break;
		}
	}

	/* can't find this event cmd */
	if (i == size)
		sdk_warn(hwdev->dev_hdl, "Unsupported mod(%d) event cmd(%d) to process\n",
			 mod, cmd);
}

/* pf link change event */
static void pf_nic_event_handler(void *hwdev, void *pri_handle, u8 cmd,
				 void *buf_in, u16 in_size,
				 void *buf_out, u16 *out_size)
{
	_event_handler(hwdev, HIFC_MOD_L2NIC, cmd, buf_in, in_size,
		       buf_out, out_size);
}

static void pf_hilink_event_handler(void *hwdev, void *pri_handle, u8 cmd,
				    void *buf_in, u16 in_size,
				    void *buf_out, u16 *out_size)
{
	_event_handler(hwdev, HIFC_MOD_HILINK, cmd, buf_in, in_size,
		       buf_out, out_size);
}

/* pf fault report event */
void pf_fault_event_handler(void *hwdev, void *buf_in, u16 in_size,
			    void *buf_out, u16 *out_size)
{
	_event_handler(hwdev, HIFC_MOD_COMM, HIFC_MGMT_CMD_FAULT_REPORT,
		       buf_in, in_size, buf_out, out_size);
}

void mgmt_watchdog_event_handler(void *hwdev, void *buf_in, u16 in_size,
				 void *buf_out, u16 *out_size)
{
	_event_handler(hwdev, HIFC_MOD_COMM, HIFC_MGMT_CMD_WATCHDOG_INFO,
		       buf_in, in_size, buf_out, out_size);
}

void mgmt_fmw_act_event_handler(void *hwdev, void *buf_in, u16 in_size,
				void *buf_out, u16 *out_size)
{
	_event_handler(hwdev, HIFC_MOD_COMM, HIFC_MGMT_CMD_FMW_ACT_NTC,
		       buf_in, in_size, buf_out, out_size);
}

void mgmt_pcie_dfx_event_handler(void *hwdev, void *buf_in, u16 in_size,
				 void *buf_out, u16 *out_size)
{
	_event_handler(hwdev, HIFC_MOD_COMM, HIFC_MGMT_CMD_PCIE_DFX_NTC,
		       buf_in, in_size, buf_out, out_size);
}

void mgmt_get_mctp_event_handler(void *hwdev, void *buf_in, u16 in_size,
				 void *buf_out, u16 *out_size)
{
	_event_handler(hwdev, HIFC_MOD_COMM, HIFC_MGMT_CMD_GET_HOST_INFO,
		       buf_in, in_size, buf_out, out_size);
}

void mgmt_heartbeat_event_handler(void *hwdev, void *buf_in, u16 in_size,
				  void *buf_out, u16 *out_size)
{
	_event_handler(hwdev, HIFC_MOD_COMM, HIFC_MGMT_CMD_HEARTBEAT_EVENT,
		       buf_in, in_size, buf_out, out_size);
}

static void pf_event_register(struct hifc_hwdev *hwdev)
{
	if (hifc_is_hwdev_mod_inited(hwdev, HIFC_HWDEV_MGMT_INITED)) {
		hifc_register_mgmt_msg_cb(hwdev, HIFC_MOD_L2NIC,
					  hwdev, pf_nic_event_handler);
		hifc_register_mgmt_msg_cb(hwdev, HIFC_MOD_HILINK,
					  hwdev,
					  pf_hilink_event_handler);
		hifc_comm_recv_mgmt_self_cmd_reg(hwdev,
						 HIFC_MGMT_CMD_FAULT_REPORT,
						 pf_fault_event_handler);

		hifc_comm_recv_mgmt_self_cmd_reg(hwdev,
						 HIFC_MGMT_CMD_WATCHDOG_INFO,
						 mgmt_watchdog_event_handler);

		hifc_comm_recv_mgmt_self_cmd_reg(hwdev,
						 HIFC_MGMT_CMD_FMW_ACT_NTC,
						 mgmt_fmw_act_event_handler);
		hifc_comm_recv_mgmt_self_cmd_reg(hwdev,
						 HIFC_MGMT_CMD_PCIE_DFX_NTC,
						 mgmt_pcie_dfx_event_handler);
		hifc_comm_recv_mgmt_self_cmd_reg(hwdev,
						 HIFC_MGMT_CMD_GET_HOST_INFO,
						 mgmt_get_mctp_event_handler);
	}
}

void hifc_event_register(void *dev, void *pri_handle,
			 hifc_event_handler callback)
{
	struct hifc_hwdev *hwdev = dev;

	if (!dev) {
		pr_err("Hwdev pointer is NULL for register event\n");
		return;
	}

	hwdev->event_callback = callback;
	hwdev->event_pri_handle = pri_handle;

	pf_event_register(hwdev);
}

void hifc_event_unregister(void *dev)
{
	struct hifc_hwdev *hwdev = dev;

	hwdev->event_callback = NULL;
	hwdev->event_pri_handle = NULL;

	hifc_unregister_mgmt_msg_cb(hwdev, HIFC_MOD_L2NIC);
	hifc_unregister_mgmt_msg_cb(hwdev, HIFC_MOD_HILINK);
	hifc_comm_recv_up_self_cmd_unreg(hwdev,
					 HIFC_MGMT_CMD_FAULT_REPORT);
	hifc_comm_recv_up_self_cmd_unreg(hwdev,
					 HIFC_MGMT_CMD_WATCHDOG_INFO);
	hifc_comm_recv_up_self_cmd_unreg(hwdev,
					 HIFC_MGMT_CMD_FMW_ACT_NTC);
	hifc_comm_recv_up_self_cmd_unreg(hwdev,
					 HIFC_MGMT_CMD_PCIE_DFX_NTC);
	hifc_comm_recv_up_self_cmd_unreg(hwdev,
					 HIFC_MGMT_CMD_GET_HOST_INFO);
}

/* 0 - heartbeat lost, 1 - normal */
static u8 hifc_get_heartbeat_status(struct hifc_hwdev *hwdev)
{
	struct hifc_hwif *hwif = hwdev->hwif;
	u32 attr1;

	/* suprise remove should be set 1 */
	if (!hifc_get_chip_present_flag(hwdev))
		return 1;

	attr1 = hifc_hwif_read_reg(hwif, HIFC_CSR_FUNC_ATTR1_ADDR);
	if (attr1 == HIFC_PCIE_LINK_DOWN) {
		sdk_err(hwdev->dev_hdl, "Detect pcie is link down\n");
		hifc_set_chip_absent(hwdev);
		hifc_force_complete_all(hwdev);
	/* should notify chiperr to pangea
	 * when detecting pcie link down
	 */
		return 1;
	}

	return HIFC_AF1_GET(attr1, MGMT_INIT_STATUS);
}

static void hifc_heartbeat_event_handler(struct work_struct *work)
{
	struct hifc_hwdev *hwdev =
			container_of(work, struct hifc_hwdev, timer_work);
	u16 out = 0;

	_event_handler(hwdev, HIFC_MOD_L2NIC, HIFC_MGMT_CMD_HEART_LOST_REPORT,
		       NULL, 0, &out, &out);
}

static bool __detect_heartbeat_ehd_lost(struct hifc_hwdev *hwdev)
{
	struct hifc_heartbeat_enhanced *hb_ehd = &hwdev->heartbeat_ehd;
	u64 update_time;
	bool hb_ehd_lost = false;

	if (!hb_ehd->en)
		return false;

	if (time_after(jiffies, hb_ehd->start_detect_jiffies)) {
		update_time = jiffies_to_msecs(jiffies -
					       hb_ehd->last_update_jiffies);
		if (update_time > HIFC_HEARBEAT_ENHANCED_LOST) {
			sdk_warn(hwdev->dev_hdl, "Heartbeat enhanced lost for %d millisecond\n",
				 (u32)update_time);
			hb_ehd_lost = true;
		}
	} else {
		/* mgmt may not report heartbeart enhanced event and won't
		 * update last_update_jiffies
		 */
		hb_ehd->last_update_jiffies = jiffies;
	}

	return hb_ehd_lost;
}

static void hifc_heartbeat_timer_handler(struct timer_list *t)
{
	struct hifc_hwdev *hwdev = from_timer(hwdev, t, heartbeat_timer);

	if (__detect_heartbeat_ehd_lost(hwdev) ||
	    !hifc_get_heartbeat_status(hwdev)) {
		hwdev->heartbeat_lost = 1;
		queue_work(hwdev->workq, &hwdev->timer_work);
	} else {
		mod_timer(&hwdev->heartbeat_timer,
			  jiffies + msecs_to_jiffies(HIFC_HEARTBEAT_PERIOD));
	}
}

void add_to_timer(struct timer_list *timer, long period)
{
	if (!timer)
		return;

	add_timer(timer);
}

void delete_timer(struct timer_list *timer)
{
	if (!timer)
		return;

	del_timer_sync(timer);
}

void hifc_init_heartbeat(struct hifc_hwdev *hwdev)
{
	timer_setup(&hwdev->heartbeat_timer, hifc_heartbeat_timer_handler, 0);
	hwdev->heartbeat_timer.expires =
		jiffies + msecs_to_jiffies(HIFC_HEARTBEAT_START_EXPIRE);

	add_to_timer(&hwdev->heartbeat_timer, HIFC_HEARTBEAT_PERIOD);

	INIT_WORK(&hwdev->timer_work, hifc_heartbeat_event_handler);
}

void hifc_destroy_heartbeat(struct hifc_hwdev *hwdev)
{
	delete_timer(&hwdev->heartbeat_timer);
}

u8 hifc_nic_sw_aeqe_handler(void *handle, u8 event, u64 data)
{
	struct hifc_hwdev *hwdev =  (struct hifc_hwdev *)handle;
	u8 event_level = FAULT_LEVEL_MAX;

	switch (event) {
	case HIFC_INTERNAL_TSO_FATAL_ERROR:
	case HIFC_INTERNAL_LRO_FATAL_ERROR:
	case HIFC_INTERNAL_TX_FATAL_ERROR:
	case HIFC_INTERNAL_RX_FATAL_ERROR:
	case HIFC_INTERNAL_OTHER_FATAL_ERROR:
		atomic_inc(&hwdev->hw_stats.nic_ucode_event_stats[event]);
		sdk_err(hwdev->dev_hdl, "SW aeqe event type: 0x%x, data: 0x%llx\n",
			event, data);
		event_level = FAULT_LEVEL_FATAL;
		break;
	default:
		sdk_err(hwdev->dev_hdl, "Unsupported sw event %d to process.\n",
			event);
	}

	return event_level;
}

void hifc_set_pcie_order_cfg(void *handle)
{
	struct hifc_hwdev *hwdev = handle;
	u32 val;

	if (!hwdev)
		return;

	val = hifc_hwif_read_reg(hwdev->hwif,
				 HIFC_GLB_DMA_SO_RO_REPLACE_ADDR);

	if (HIFC_GLB_DMA_SO_RO_GET(val, SO_RO_CFG)) {
		val = HIFC_GLB_DMA_SO_R0_CLEAR(val, SO_RO_CFG);
		val |= HIFC_GLB_DMA_SO_R0_SET(HIFC_DISABLE_ORDER, SO_RO_CFG);
		hifc_hwif_write_reg(hwdev->hwif,
				    HIFC_GLB_DMA_SO_RO_REPLACE_ADDR, val);
	}
}

int hifc_get_board_info(void *hwdev, struct hifc_board_info *info)
{
	struct hifc_comm_board_info board_info = {0};
	u16 out_size = sizeof(board_info);
	int err;

	if (!hwdev || !info)
		return -EINVAL;

	err = hifc_msg_to_mgmt_sync(hwdev, HIFC_MOD_COMM,
				    HIFC_MGMT_CMD_GET_BOARD_INFO,
				    &board_info, sizeof(board_info),
				    &board_info, &out_size, 0);
	if (err || board_info.status || !out_size) {
		sdk_err(((struct hifc_hwdev *)hwdev)->dev_hdl,
			"Failed to get board info, err: %d, status: 0x%x, out size: 0x%x\n",
			err, board_info.status, out_size);
		return -EFAULT;
	}

	memcpy(info, &board_info.info, sizeof(*info));

	return 0;
}

int hifc_get_phy_init_status(void *hwdev,
			     enum phy_init_status_type *init_status)
{
	struct hifc_phy_init_status phy_info = {0};
	u16 out_size = sizeof(phy_info);
	int err;

	if (!hwdev || !init_status)
		return -EINVAL;

	err = hifc_msg_to_mgmt_sync(hwdev, HIFC_MOD_COMM,
				    HIFC_MGMT_CMD_GET_PHY_INIT_STATUS,
				    &phy_info, sizeof(phy_info),
				    &phy_info, &out_size, 0);
	if ((phy_info.status != HIFC_MGMT_CMD_UNSUPPORTED &&
	     phy_info.status) || err || !out_size) {
		sdk_err(((struct hifc_hwdev *)hwdev)->dev_hdl,
			"Failed to get phy info, err: %d, status: 0x%x, out size: 0x%x\n",
			err, phy_info.status, out_size);
		return -EFAULT;
	}

	*init_status = phy_info.init_status;

	return phy_info.status;
}

int hifc_phy_init_status_judge(void *hwdev)
{
	enum phy_init_status_type init_status;
	int ret;
	unsigned long end;

	/* It's not a phy, so don't judge phy status */
	if (!HIFC_BOARD_IS_PHY((struct hifc_hwdev *)hwdev))
		return 0;

	end = jiffies + msecs_to_jiffies(PHY_DOING_INIT_TIMEOUT);
	do {
		ret = hifc_get_phy_init_status(hwdev, &init_status);
		if (ret == HIFC_MGMT_CMD_UNSUPPORTED)
			return 0;
		else if (ret)
			return -EFAULT;

		switch (init_status) {
		case PHY_INIT_SUCCESS:
			sdk_info(((struct hifc_hwdev *)hwdev)->dev_hdl,
				 "Phy init is success\n");
			return 0;
		case PHY_NONSUPPORT:
			sdk_info(((struct hifc_hwdev *)hwdev)->dev_hdl,
				 "Phy init is nonsupport\n");
			return 0;
		case PHY_INIT_FAIL:
			sdk_err(((struct hifc_hwdev *)hwdev)->dev_hdl,
				"Phy init is failed\n");
			return -EIO;
		case PHY_INIT_DOING:
			msleep(250);
			break;
		default:
			sdk_err(((struct hifc_hwdev *)hwdev)->dev_hdl,
				"Phy init is invalid, init_status: %d\n",
				init_status);
			return -EINVAL;
		}
	} while (time_before(jiffies, end));

	sdk_err(((struct hifc_hwdev *)hwdev)->dev_hdl,
		"Phy init is timeout\n");

	return -ETIMEDOUT;
}

int hifc_get_mgmt_channel_status(void *handle)
{
	struct hifc_hwdev *hwdev = handle;
	u32 val;

	if (!hwdev)
		return true;

	if (hifc_func_type(hwdev) == TYPE_VF ||
	    !(hwdev->feature_cap & HIFC_FUNC_SUPP_DFX_REG))
		return false;

	val = hifc_hwif_read_reg(hwdev->hwif, HIFC_ICPL_RESERVD_ADDR);

	return HIFC_GET_MGMT_CHANNEL_STATUS(val, MGMT_CHANNEL_STATUS);
}

#define HIFC_RED_REG_TIME_OUT	3000

int hifc_read_reg(void *hwdev, u32 reg_addr, u32 *val)
{
	struct hifc_reg_info reg_info = {0};
	u16 out_size = sizeof(reg_info);
	int err;

	if (!hwdev || !val)
		return -EINVAL;

	reg_info.reg_addr = reg_addr;
	reg_info.val_length = sizeof(u32);

	err = hifc_pf_msg_to_mgmt_sync(hwdev, HIFC_MOD_COMM,
				       HIFC_MGMT_CMD_REG_READ,
				       &reg_info, sizeof(reg_info),
				       &reg_info, &out_size,
				       HIFC_RED_REG_TIME_OUT);
	if (reg_info.status || err || !out_size) {
		sdk_err(((struct hifc_hwdev *)hwdev)->dev_hdl,
			"Failed to read reg, err: %d, status: 0x%x, out size: 0x%x\n",
			err, reg_info.status, out_size);
		return -EFAULT;
	}

	*val = reg_info.data[0];

	return 0;
}

void hifc_swe_fault_handler(struct hifc_hwdev *hwdev, u8 level,
			    u8 event, u64 val)
{
	struct hifc_fault_info_node *fault_node;

	if (level < FAULT_LEVEL_MAX) {
		fault_node = kzalloc(sizeof(*fault_node), GFP_KERNEL);
		if (!fault_node) {
			sdk_err(hwdev->dev_hdl, "Malloc fault node memory failed\n");
			return;
		}

		fault_node->info.fault_src = HIFC_FAULT_SRC_SW_MGMT_UCODE;
		fault_node->info.fault_lev = level;
		fault_node->info.fault_data.sw_mgmt.event_id = event;
		fault_node->info.fault_data.sw_mgmt.event_data = val;
		hifc_refresh_history_fault(hwdev, &fault_node->info);

		down(&hwdev->fault_list_sem);
		kfree(fault_node);
		up(&hwdev->fault_list_sem);
	}
}

void hifc_set_func_deinit_flag(void *hwdev)
{
	struct hifc_hwdev *dev = hwdev;

	set_bit(HIFC_HWDEV_FUNC_DEINIT, &dev->func_state);
}

int hifc_get_card_present_state(void *hwdev, bool *card_present_state)
{
	u32 addr, attr1;

	if (!hwdev || !card_present_state)
		return -EINVAL;

	addr = HIFC_CSR_FUNC_ATTR1_ADDR;
	attr1 = hifc_hwif_read_reg(((struct hifc_hwdev *)hwdev)->hwif, addr);
	if (attr1 == HIFC_PCIE_LINK_DOWN) {
		sdk_warn(((struct hifc_hwdev *)hwdev)->dev_hdl, "Card is not present\n");
		*card_present_state = (bool)0;
	} else {
		*card_present_state = (bool)1;
	}

	return 0;
}

void hifc_disable_mgmt_msg_report(void *hwdev)
{
	struct hifc_hwdev *hw_dev = (struct hifc_hwdev *)hwdev;

	hifc_set_pf_status(hw_dev->hwif, HIFC_PF_STATUS_INIT);
}
