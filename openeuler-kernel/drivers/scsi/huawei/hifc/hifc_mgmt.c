// SPDX-License-Identifier: GPL-2.0
/* Huawei Hifc PCI Express Linux driver
 * Copyright(c) 2017 Huawei Technologies Co., Ltd
 *
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": [COMM]" fmt

#include <linux/types.h>
#include <linux/errno.h>
#include <linux/pci.h>
#include <linux/device.h>
#include <linux/spinlock.h>
#include <linux/completion.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/interrupt.h>
#include <linux/semaphore.h>

#include "hifc_knl_adp.h"
#include "hifc_hw.h"
#include "hifc_hwdev.h"
#include "hifc_hwif.h"
#include "hifc_api_cmd.h"
#include "hifc_mgmt.h"
#include "hifc_eqs.h"

#define BUF_OUT_DEFAULT_SIZE        1
#define SEGMENT_LEN                 48
#define MGMT_MSG_MAX_SEQ_ID         (ALIGN(HIFC_MSG_TO_MGMT_MAX_LEN, \
					   SEGMENT_LEN) / SEGMENT_LEN)

#define MAX_PF_MGMT_BUF_SIZE        2048UL
#define MGMT_MSG_SIZE_MIN           20
#define MGMT_MSG_SIZE_STEP          16
#define MGMT_MSG_RSVD_FOR_DEV       8
#define MGMT_MSG_TIMEOUT            5000 /* millisecond */
#define SYNC_MSG_ID_MASK            0x1FF
#define ASYNC_MSG_ID_MASK           0x1FF
#define ASYNC_MSG_FLAG              0x200
#define MSG_NO_RESP                 0xFFFF
#define MAX_MSG_SZ                  2016

#define MSG_SZ_IS_VALID(in_size)       ((in_size) <= MAX_MSG_SZ)

#define SYNC_MSG_ID(pf_to_mgmt)        ((pf_to_mgmt)->sync_msg_id)

#define SYNC_MSG_ID_INC(pf_to_mgmt)    (SYNC_MSG_ID(pf_to_mgmt) = \
			(SYNC_MSG_ID(pf_to_mgmt) + 1) & SYNC_MSG_ID_MASK)

#define ASYNC_MSG_ID(pf_to_mgmt)       ((pf_to_mgmt)->async_msg_id)

#define ASYNC_MSG_ID_INC(pf_to_mgmt)   (ASYNC_MSG_ID(pf_to_mgmt) = \
			((ASYNC_MSG_ID(pf_to_mgmt) + 1) & ASYNC_MSG_ID_MASK) \
			| ASYNC_MSG_FLAG)

static void pf_to_mgmt_send_event_set(struct hifc_msg_pf_to_mgmt *pf_to_mgmt,
				      int event_flag)
{
	spin_lock(&pf_to_mgmt->sync_event_lock);
	pf_to_mgmt->event_flag = event_flag;
	spin_unlock(&pf_to_mgmt->sync_event_lock);
}

/**
 * hifc_register_mgmt_msg_cb - register sync msg handler for a module
 * @hwdev:	the pointer to hw device
 * @mod: module in the chip that this handler will handle its sync messages
 * @pri_handle: pri handle function
 * @callback: the handler for a sync message that will handle messages
 * Return: 0 - success, negative - failure
 **/
int hifc_register_mgmt_msg_cb(void *hwdev, enum hifc_mod_type mod,
			      void *pri_handle, hifc_mgmt_msg_cb callback)
{
	struct hifc_msg_pf_to_mgmt *pf_to_mgmt;

	if (mod >= HIFC_MOD_HW_MAX || !hwdev)
		return -EFAULT;

	pf_to_mgmt = ((struct hifc_hwdev *)hwdev)->pf_to_mgmt;
	if (!pf_to_mgmt)
		return -EINVAL;

	pf_to_mgmt->recv_mgmt_msg_cb[mod] = callback;
	pf_to_mgmt->recv_mgmt_msg_data[mod] = pri_handle;

	set_bit(HIFC_MGMT_MSG_CB_REG, &pf_to_mgmt->mgmt_msg_cb_state[mod]);

	return 0;
}

/**
 * hifc_unregister_mgmt_msg_cb - unregister sync msg handler for a module
 * @hwdev: the pointer to hw device
 * @mod: module in the chip that this handler will handle its sync messages
 **/
void hifc_unregister_mgmt_msg_cb(void *hwdev, enum hifc_mod_type mod)
{
	struct hifc_msg_pf_to_mgmt *pf_to_mgmt;

	if (!hwdev || mod >= HIFC_MOD_HW_MAX)
		return;

	pf_to_mgmt = ((struct hifc_hwdev *)hwdev)->pf_to_mgmt;
	if (!pf_to_mgmt)
		return;

	clear_bit(HIFC_MGMT_MSG_CB_REG, &pf_to_mgmt->mgmt_msg_cb_state[mod]);

	while (test_bit(HIFC_MGMT_MSG_CB_RUNNING,
			&pf_to_mgmt->mgmt_msg_cb_state[mod]))
		usleep_range(900, 1000);

	pf_to_mgmt->recv_mgmt_msg_cb[mod] = NULL;
	pf_to_mgmt->recv_mgmt_msg_data[mod] = NULL;
}

void hifc_comm_recv_mgmt_self_cmd_reg(void *hwdev, u8 cmd,
				      comm_up_self_msg_proc proc)
{
	struct hifc_msg_pf_to_mgmt *pf_to_mgmt;
	u8 cmd_idx;

	if (!hwdev || !proc)
		return;

	pf_to_mgmt = ((struct hifc_hwdev *)hwdev)->pf_to_mgmt;
	if (!pf_to_mgmt)
		return;

	cmd_idx = pf_to_mgmt->proc.cmd_num;
	if (cmd_idx >= HIFC_COMM_SELF_CMD_MAX) {
		sdk_err(pf_to_mgmt->hwdev->dev_hdl,
			"Register recv up process failed(cmd=0x%x)\r\n", cmd);
		return;
	}

	pf_to_mgmt->proc.info[cmd_idx].cmd = cmd;
	pf_to_mgmt->proc.info[cmd_idx].proc = proc;

	pf_to_mgmt->proc.cmd_num++;
}

void hifc_comm_recv_up_self_cmd_unreg(void *hwdev, u8 cmd)
{
	struct hifc_msg_pf_to_mgmt *pf_to_mgmt;
	u8 cmd_idx;

	if (!hwdev)
		return;

	pf_to_mgmt = ((struct hifc_hwdev *)hwdev)->pf_to_mgmt;
	if (!pf_to_mgmt)
		return;

	cmd_idx = pf_to_mgmt->proc.cmd_num;
	if (cmd_idx >= HIFC_COMM_SELF_CMD_MAX) {
		sdk_err(pf_to_mgmt->hwdev->dev_hdl,
			"Unregister recv up process failed(cmd=0x%x)\r\n", cmd);
		return;
	}

	for (cmd_idx = 0; cmd_idx < HIFC_COMM_SELF_CMD_MAX; cmd_idx++) {
		if (cmd == pf_to_mgmt->proc.info[cmd_idx].cmd) {
			pf_to_mgmt->proc.info[cmd_idx].cmd = 0;
			pf_to_mgmt->proc.info[cmd_idx].proc = NULL;
			pf_to_mgmt->proc.cmd_num--;
		}
	}
}

/**
 * mgmt_msg_len - calculate the total message length
 * @msg_data_len: the length of the message data
 * Return: the total message length
 **/
static u16 mgmt_msg_len(u16 msg_data_len)
{
	/* u64 - the size of the header */
	u16 msg_size;

	msg_size = (u16)(MGMT_MSG_RSVD_FOR_DEV + sizeof(u64) + msg_data_len);

	if (msg_size > MGMT_MSG_SIZE_MIN)
		msg_size = MGMT_MSG_SIZE_MIN +
				ALIGN((msg_size - MGMT_MSG_SIZE_MIN),
				      MGMT_MSG_SIZE_STEP);
	else
		msg_size = MGMT_MSG_SIZE_MIN;

	return msg_size;
}

/**
 * prepare_header - prepare the header of the message
 * @pf_to_mgmt: PF to MGMT channel
 * @header: pointer of the header to prepare
 * @msg_len: the length of the message
 * @mod: module in the chip that will get the message
 * @ack_type: message ack type
 * @direction: the direction of the original message
 * @cmd: vmd type
 * @msg_id: message id
 **/
static void prepare_header(struct hifc_msg_pf_to_mgmt *pf_to_mgmt,
			   u64 *header, u16 msg_len, enum hifc_mod_type mod,
			   enum hifc_msg_ack_type ack_type,
			   enum hifc_msg_direction_type direction,
			   enum hifc_mgmt_cmd cmd, u32 msg_id)
{
	struct hifc_hwif *hwif = pf_to_mgmt->hwdev->hwif;

	*header = HIFC_MSG_HEADER_SET(msg_len, MSG_LEN) |
		HIFC_MSG_HEADER_SET(mod, MODULE) |
		HIFC_MSG_HEADER_SET(msg_len, SEG_LEN) |
		HIFC_MSG_HEADER_SET(ack_type, NO_ACK) |
		HIFC_MSG_HEADER_SET(0, ASYNC_MGMT_TO_PF) |
		HIFC_MSG_HEADER_SET(0, SEQID) |
		HIFC_MSG_HEADER_SET(LAST_SEGMENT, LAST) |
		HIFC_MSG_HEADER_SET(direction, DIRECTION) |
		HIFC_MSG_HEADER_SET(cmd, CMD) |
		HIFC_MSG_HEADER_SET(HIFC_PCI_INTF_IDX(hwif), PCI_INTF_IDX) |
		HIFC_MSG_HEADER_SET(hwif->attr.port_to_port_idx, P2P_IDX) |
		HIFC_MSG_HEADER_SET(msg_id, MSG_ID);
}

static void clp_prepare_header(struct hifc_hwdev *hwdev,
			       u64 *header, u16 msg_len, enum hifc_mod_type mod,
			       enum hifc_msg_ack_type ack_type,
			       enum hifc_msg_direction_type direction,
			       enum hifc_mgmt_cmd cmd, u32 msg_id)
{
	struct hifc_hwif *hwif = hwdev->hwif;

	*header = HIFC_MSG_HEADER_SET(msg_len, MSG_LEN) |
		HIFC_MSG_HEADER_SET(mod, MODULE) |
		HIFC_MSG_HEADER_SET(msg_len, SEG_LEN) |
		HIFC_MSG_HEADER_SET(ack_type, NO_ACK) |
		HIFC_MSG_HEADER_SET(0, ASYNC_MGMT_TO_PF) |
		HIFC_MSG_HEADER_SET(0, SEQID) |
		HIFC_MSG_HEADER_SET(LAST_SEGMENT, LAST) |
		HIFC_MSG_HEADER_SET(direction, DIRECTION) |
		HIFC_MSG_HEADER_SET(cmd, CMD) |
		HIFC_MSG_HEADER_SET(HIFC_PCI_INTF_IDX(hwif), PCI_INTF_IDX) |
		HIFC_MSG_HEADER_SET(hwif->attr.port_to_port_idx, P2P_IDX) |
		HIFC_MSG_HEADER_SET(msg_id, MSG_ID);
}

/**
 * prepare_mgmt_cmd - prepare the mgmt command
 * @mgmt_cmd: pointer to the command to prepare
 * @header: pointer of the header to prepare
 * @msg: the data of the message
 * @msg_len: the length of the message
 **/
static void prepare_mgmt_cmd(u8 *mgmt_cmd, u64 *header, const void *msg,
			     int msg_len)
{
	memset(mgmt_cmd, 0, MGMT_MSG_RSVD_FOR_DEV);

	mgmt_cmd += MGMT_MSG_RSVD_FOR_DEV;
	memcpy(mgmt_cmd, header, sizeof(*header));

	mgmt_cmd += sizeof(*header);
	memcpy(mgmt_cmd, msg, msg_len);
}

/**
 * send_msg_to_mgmt_async - send async message
 * @pf_to_mgmt: PF to MGMT channel
 * @mod: module in the chip that will get the message
 * @cmd: command of the message
 * @msg: the data of the message
 * @msg_len: the length of the message
 * @direction: the direction of the original message
 * @resp_msg_id: msg id to response for
 * Return: 0 - success, negative - failure
 **/
static int send_msg_to_mgmt_async(struct hifc_msg_pf_to_mgmt *pf_to_mgmt,
				  enum hifc_mod_type mod, u8 cmd,
				void *msg, u16 msg_len,
				enum hifc_msg_direction_type direction,
				u16 resp_msg_id)
{
	void *mgmt_cmd = pf_to_mgmt->async_msg_buf;
	struct hifc_api_cmd_chain *chain;
	u64 header;
	u16 cmd_size = mgmt_msg_len(msg_len);

	if (!hifc_get_chip_present_flag(pf_to_mgmt->hwdev))
		return -EFAULT;

	if (direction == HIFC_MSG_RESPONSE)
		prepare_header(pf_to_mgmt, &header, msg_len, mod, HIFC_MSG_ACK,
			       direction, cmd, resp_msg_id);
	else
		prepare_header(pf_to_mgmt, &header, msg_len, mod, HIFC_MSG_ACK,
			       direction, cmd, ASYNC_MSG_ID(pf_to_mgmt));

	prepare_mgmt_cmd((u8 *)mgmt_cmd, &header, msg, msg_len);

	chain = pf_to_mgmt->cmd_chain[HIFC_API_CMD_WRITE_ASYNC_TO_MGMT_CPU];

	return hifc_api_cmd_write(chain, HIFC_NODE_ID_MGMT_HOST, mgmt_cmd,
					cmd_size);
}

int hifc_pf_to_mgmt_async(void *hwdev, enum hifc_mod_type mod,
			  u8 cmd, void *buf_in, u16 in_size)
{
	struct hifc_msg_pf_to_mgmt *pf_to_mgmt;
	void *dev = ((struct hifc_hwdev *)hwdev)->dev_hdl;
	int err;

	pf_to_mgmt = ((struct hifc_hwdev *)hwdev)->pf_to_mgmt;

	/* Lock the async_msg_buf */
	spin_lock_bh(&pf_to_mgmt->async_msg_lock);
	ASYNC_MSG_ID_INC(pf_to_mgmt);

	err = send_msg_to_mgmt_async(pf_to_mgmt, mod, cmd, buf_in, in_size,
				     HIFC_MSG_DIRECT_SEND, MSG_NO_RESP);
	spin_unlock_bh(&pf_to_mgmt->async_msg_lock);

	if (err) {
		sdk_err(dev, "Failed to send async mgmt msg\n");
		return err;
	}

	return 0;
}

/**
 * send_msg_to_mgmt_sync - send async message
 * @pf_to_mgmt: PF to MGMT channel
 * @mod: module in the chip that will get the message
 * @cmd: command of the message
 * @msg: the msg data
 * @msg_len: the msg data length
 * @direction: the direction of the original message
 * @resp_msg_id: msg id to response for
 * Return: 0 - success, negative - failure
 **/
static int send_msg_to_mgmt_sync(struct hifc_msg_pf_to_mgmt *pf_to_mgmt,
				 enum hifc_mod_type mod, u8 cmd,
				void *msg, u16 msg_len,
				enum hifc_msg_ack_type ack_type,
				enum hifc_msg_direction_type direction,
				u16 resp_msg_id)
{
	void *mgmt_cmd = pf_to_mgmt->sync_msg_buf;
	struct hifc_api_cmd_chain *chain;
	u64 header;
	u16 cmd_size = mgmt_msg_len(msg_len);

	if (!hifc_get_chip_present_flag(pf_to_mgmt->hwdev))
		return -EFAULT;

	if (direction == HIFC_MSG_RESPONSE)
		prepare_header(pf_to_mgmt, &header, msg_len, mod, ack_type,
			       direction, cmd, resp_msg_id);
	else
		prepare_header(pf_to_mgmt, &header, msg_len, mod, ack_type,
			       direction, cmd, SYNC_MSG_ID_INC(pf_to_mgmt));

	if (ack_type == HIFC_MSG_ACK)
		pf_to_mgmt_send_event_set(pf_to_mgmt, SEND_EVENT_START);

	prepare_mgmt_cmd((u8 *)mgmt_cmd, &header, msg, msg_len);

	chain = pf_to_mgmt->cmd_chain[HIFC_API_CMD_WRITE_TO_MGMT_CPU];

	return hifc_api_cmd_write(chain, HIFC_NODE_ID_MGMT_HOST, mgmt_cmd,
					cmd_size);
}

static inline void msg_to_mgmt_pre(enum hifc_mod_type mod, void *buf_in)
{
	struct hifc_msg_head *msg_head;

	/* set aeq fix num to 3, need to ensure response aeq id < 3*/
	if (mod == HIFC_MOD_COMM || mod == HIFC_MOD_L2NIC) {
		msg_head = buf_in;

		if (msg_head->resp_aeq_num >= HIFC_MAX_AEQS)
			msg_head->resp_aeq_num = 0;
	}
}

int hifc_pf_to_mgmt_sync(void *hwdev, enum hifc_mod_type mod, u8 cmd,
			 void *buf_in, u16 in_size, void *buf_out,
			 u16 *out_size, u32 timeout)
{
	struct hifc_msg_pf_to_mgmt *pf_to_mgmt;
	void *dev = ((struct hifc_hwdev *)hwdev)->dev_hdl;
	struct hifc_recv_msg *recv_msg;
	struct completion *recv_done;
	ulong timeo;
	int err;
	ulong ret;

	msg_to_mgmt_pre(mod, buf_in);

	pf_to_mgmt = ((struct hifc_hwdev *)hwdev)->pf_to_mgmt;

	/* Lock the sync_msg_buf */
	down(&pf_to_mgmt->sync_msg_lock);
	recv_msg = &pf_to_mgmt->recv_resp_msg_from_mgmt;
	recv_done = &recv_msg->recv_done;

	init_completion(recv_done);

	err = send_msg_to_mgmt_sync(pf_to_mgmt, mod, cmd, buf_in, in_size,
				    HIFC_MSG_ACK, HIFC_MSG_DIRECT_SEND,
				    MSG_NO_RESP);
	if (err) {
		sdk_err(dev, "Failed to send sync msg to mgmt, sync_msg_id: %d\n",
			pf_to_mgmt->sync_msg_id);
		pf_to_mgmt_send_event_set(pf_to_mgmt, SEND_EVENT_FAIL);
		goto unlock_sync_msg;
	}

	timeo = msecs_to_jiffies(timeout ? timeout : MGMT_MSG_TIMEOUT);

	ret = wait_for_completion_timeout(recv_done, timeo);
	if (!ret) {
		sdk_err(dev, "Mgmt response sync cmd timeout, sync_msg_id: %d\n",
			pf_to_mgmt->sync_msg_id);
		hifc_dump_aeq_info((struct hifc_hwdev *)hwdev);
		err = -ETIMEDOUT;
		pf_to_mgmt_send_event_set(pf_to_mgmt, SEND_EVENT_TIMEOUT);
		goto unlock_sync_msg;
	}
	pf_to_mgmt_send_event_set(pf_to_mgmt, SEND_EVENT_END);

	if (!(((struct hifc_hwdev *)hwdev)->chip_present_flag)) {
		up(&pf_to_mgmt->sync_msg_lock);
		return -ETIMEDOUT;
	}

	if (buf_out && out_size) {
		if (*out_size < recv_msg->msg_len) {
			sdk_err(dev, "Invalid response message length: %d for mod %d cmd %d from mgmt, should less than: %d\n",
				recv_msg->msg_len, mod, cmd, *out_size);
			err = -EFAULT;
			goto unlock_sync_msg;
		}

		if (recv_msg->msg_len)
			memcpy(buf_out, recv_msg->msg, recv_msg->msg_len);

		*out_size = recv_msg->msg_len;
	}

unlock_sync_msg:
	up(&pf_to_mgmt->sync_msg_lock);

	return err;
}

static int __get_clp_reg(void *hwdev, enum clp_data_type data_type,
			 enum clp_reg_type reg_type, u32 *reg_addr)
{
	struct hifc_hwdev *dev = hwdev;
	u32 offset;

	offset = HIFC_CLP_REG_GAP * hifc_pcie_itf_id(dev);

	switch (reg_type) {
	case HIFC_CLP_BA_HOST:
		*reg_addr = (data_type == HIFC_CLP_REQ_HOST) ?
			     HIFC_CLP_REG(REQ_SRAM_BA) :
			     HIFC_CLP_REG(RSP_SRAM_BA);
		break;

	case HIFC_CLP_SIZE_HOST:
		*reg_addr = HIFC_CLP_REG(SRAM_SIZE);
		break;

	case HIFC_CLP_LEN_HOST:
		*reg_addr = (data_type == HIFC_CLP_REQ_HOST) ?
			     HIFC_CLP_REG(REQ) : HIFC_CLP_REG(RSP);
		break;

	case HIFC_CLP_START_REQ_HOST:
		*reg_addr = HIFC_CLP_REG(REQ);
		break;

	case HIFC_CLP_READY_RSP_HOST:
		*reg_addr = HIFC_CLP_REG(RSP);
		break;

	default:
		*reg_addr = 0;
		break;
	}
	if (*reg_addr == 0)
		return -EINVAL;

	*reg_addr += offset;

	return 0;
}

static inline int clp_param_valid(struct hifc_hwdev *hwdev,
				  enum clp_data_type data_type,
				  enum clp_reg_type reg_type)
{
	if (data_type == HIFC_CLP_REQ_HOST &&
	    reg_type == HIFC_CLP_READY_RSP_HOST)
		return -EINVAL;

	if (data_type == HIFC_CLP_RSP_HOST &&
	    reg_type == HIFC_CLP_START_REQ_HOST)
		return -EINVAL;

	return 0;
}

static u32 get_clp_reg_value(struct hifc_hwdev *hwdev,
			     enum clp_reg_type reg_type, u32 reg_addr)
{
	u32 reg_value;

	reg_value = hifc_hwif_read_reg(hwdev->hwif, reg_addr);

	switch (reg_type) {
	case HIFC_CLP_BA_HOST:
		reg_value = ((reg_value >>
			      HIFC_CLP_OFFSET(SRAM_BASE)) &
			      HIFC_CLP_MASK(SRAM_BASE));
		break;

	case HIFC_CLP_SIZE_HOST:
		reg_value = ((reg_value >>
			      HIFC_CLP_OFFSET(SRAM_SIZE)) &
			      HIFC_CLP_MASK(SRAM_SIZE));
		break;

	case HIFC_CLP_LEN_HOST:
		reg_value = ((reg_value >> HIFC_CLP_OFFSET(LEN)) &
			      HIFC_CLP_MASK(LEN));
		break;

	case HIFC_CLP_START_REQ_HOST:
		reg_value = ((reg_value >> HIFC_CLP_OFFSET(START)) &
			      HIFC_CLP_MASK(START));
		break;

	case HIFC_CLP_READY_RSP_HOST:
		reg_value = ((reg_value >> HIFC_CLP_OFFSET(READY)) &
			      HIFC_CLP_MASK(READY));
		break;

	default:
		break;
	}

	return reg_value;
}

static int hifc_read_clp_reg(struct hifc_hwdev *hwdev,
			     enum clp_data_type data_type,
			     enum clp_reg_type reg_type, u32 *read_value)
{
	u32 reg_addr;
	int err;

	err = clp_param_valid(hwdev, data_type, reg_type);
	if (err)
		return err;

	err = __get_clp_reg(hwdev, data_type, reg_type, &reg_addr);
	if (err)
		return err;

	*read_value = get_clp_reg_value(hwdev, reg_type, reg_addr);

	return 0;
}

static int __check_data_type(enum clp_data_type data_type,
			     enum clp_reg_type reg_type)
{
	if (data_type == HIFC_CLP_REQ_HOST &&
	    reg_type == HIFC_CLP_READY_RSP_HOST)
		return -EINVAL;
	if (data_type == HIFC_CLP_RSP_HOST &&
	    reg_type == HIFC_CLP_START_REQ_HOST)
		return -EINVAL;

	return 0;
}

static int __check_reg_value(enum clp_reg_type reg_type, u32 value)
{
	if (reg_type == HIFC_CLP_BA_HOST &&
	    value > HIFC_CLP_SRAM_BASE_REG_MAX)
		return -EINVAL;

	if (reg_type == HIFC_CLP_SIZE_HOST &&
	    value > HIFC_CLP_SRAM_SIZE_REG_MAX)
		return -EINVAL;

	if (reg_type == HIFC_CLP_LEN_HOST &&
	    value > HIFC_CLP_LEN_REG_MAX)
		return -EINVAL;

	if ((reg_type == HIFC_CLP_START_REQ_HOST ||
	     reg_type == HIFC_CLP_READY_RSP_HOST) &&
	    value > HIFC_CLP_START_OR_READY_REG_MAX)
		return -EINVAL;

	return 0;
}

static void hifc_write_clp_reg(struct hifc_hwdev *hwdev,
			       enum clp_data_type data_type,
			       enum clp_reg_type reg_type, u32 value)
{
	u32 reg_addr, reg_value;

	if (__check_data_type(data_type, reg_type))
		return;

	if (__check_reg_value(reg_type, value))
		return;

	if (__get_clp_reg(hwdev, data_type, reg_type, &reg_addr))
		return;

	reg_value = hifc_hwif_read_reg(hwdev->hwif, reg_addr);

	switch (reg_type) {
	case HIFC_CLP_LEN_HOST:
		reg_value = reg_value &
			    (~(HIFC_CLP_MASK(LEN) << HIFC_CLP_OFFSET(LEN)));
		reg_value = reg_value | (value << HIFC_CLP_OFFSET(LEN));
		break;

	case HIFC_CLP_START_REQ_HOST:
		reg_value = reg_value &
			    (~(HIFC_CLP_MASK(START) <<
			      HIFC_CLP_OFFSET(START)));
		reg_value = reg_value | (value << HIFC_CLP_OFFSET(START));
		break;

	case HIFC_CLP_READY_RSP_HOST:
		reg_value = reg_value &
			    (~(HIFC_CLP_MASK(READY) <<
			       HIFC_CLP_OFFSET(READY)));
		reg_value = reg_value | (value << HIFC_CLP_OFFSET(READY));
		break;

	default:
		return;
	}

	hifc_hwif_write_reg(hwdev->hwif, reg_addr, reg_value);
}

static int hifc_read_clp_data(struct hifc_hwdev *hwdev,
			      void *buf_out, u16 *out_size)
{
	int err;
	u32 reg = HIFC_CLP_DATA(RSP);
	u32 ready, delay_cnt;
	u32 *ptr = (u32 *)buf_out;
	u32 temp_out_size = 0;

	err = hifc_read_clp_reg(hwdev, HIFC_CLP_RSP_HOST,
				HIFC_CLP_READY_RSP_HOST, &ready);
	if (err)
		return err;

	delay_cnt = 0;
	while (ready == 0) {
		usleep_range(9000, 10000);
		delay_cnt++;
		err = hifc_read_clp_reg(hwdev, HIFC_CLP_RSP_HOST,
					HIFC_CLP_READY_RSP_HOST, &ready);
		if (err || delay_cnt > HIFC_CLP_DELAY_CNT_MAX) {
			sdk_err(hwdev->dev_hdl, "timeout with delay_cnt:%d\n",
				delay_cnt);
			return -EINVAL;
		}
	}

	err = hifc_read_clp_reg(hwdev, HIFC_CLP_RSP_HOST,
				HIFC_CLP_LEN_HOST, &temp_out_size);
	if (err)
		return err;

	if (temp_out_size > HIFC_CLP_SRAM_SIZE_REG_MAX || !temp_out_size) {
		sdk_err(hwdev->dev_hdl, "invalid temp_out_size:%d\n",
			temp_out_size);
		return -EINVAL;
	}

	*out_size = (u16)(temp_out_size & 0xffff);
	for (; temp_out_size > 0; temp_out_size--) {
		*ptr = hifc_hwif_read_reg(hwdev->hwif, reg);
		ptr++;
		reg = reg + 4;
	}

	hifc_write_clp_reg(hwdev, HIFC_CLP_RSP_HOST,
			   HIFC_CLP_READY_RSP_HOST, (u32)0x0);
	hifc_write_clp_reg(hwdev, HIFC_CLP_RSP_HOST,
			   HIFC_CLP_LEN_HOST, (u32)0x0);

	return 0;
}

static int hifc_write_clp_data(struct hifc_hwdev *hwdev,
			       void *buf_in, u16 in_size)
{
	int err;
	u32 reg = HIFC_CLP_DATA(REQ);
	u32 start = 1;
	u32 delay_cnt = 0;
	u32 *ptr = (u32 *)buf_in;

	err = hifc_read_clp_reg(hwdev, HIFC_CLP_REQ_HOST,
				HIFC_CLP_START_REQ_HOST, &start);
	if (err)
		return err;

	while (start == 1) {
		usleep_range(9000, 10000);
		delay_cnt++;
		err = hifc_read_clp_reg(hwdev, HIFC_CLP_REQ_HOST,
					HIFC_CLP_START_REQ_HOST, &start);
		if (err || delay_cnt > HIFC_CLP_DELAY_CNT_MAX)
			return -EINVAL;
	}

	hifc_write_clp_reg(hwdev, HIFC_CLP_REQ_HOST,
			   HIFC_CLP_LEN_HOST, in_size);
	hifc_write_clp_reg(hwdev, HIFC_CLP_REQ_HOST,
			   HIFC_CLP_START_REQ_HOST, (u32)0x1);

	for (; in_size > 0; in_size--) {
		hifc_hwif_write_reg(hwdev->hwif, reg, *ptr);
		ptr++;
		reg = reg + 4;
	}

	return 0;
}

static int hifc_check_clp_init_status(struct hifc_hwdev *hwdev)
{
	int err;
	u32 reg_value = 0;

	err = hifc_read_clp_reg(hwdev, HIFC_CLP_REQ_HOST,
				HIFC_CLP_BA_HOST, &reg_value);
	if (err || !reg_value) {
		sdk_err(hwdev->dev_hdl, "Wrong req ba value:0x%x\n", reg_value);
		return -EINVAL;
	}

	err = hifc_read_clp_reg(hwdev, HIFC_CLP_RSP_HOST,
				HIFC_CLP_BA_HOST, &reg_value);
	if (err || !reg_value) {
		sdk_err(hwdev->dev_hdl, "Wrong rsp ba value:0x%x\n", reg_value);
		return -EINVAL;
	}

	err = hifc_read_clp_reg(hwdev, HIFC_CLP_REQ_HOST,
				HIFC_CLP_SIZE_HOST, &reg_value);
	if (err || !reg_value) {
		sdk_err(hwdev->dev_hdl, "Wrong req size\n");
		return -EINVAL;
	}

	err = hifc_read_clp_reg(hwdev, HIFC_CLP_RSP_HOST,
				HIFC_CLP_SIZE_HOST, &reg_value);
	if (err || !reg_value) {
		sdk_err(hwdev->dev_hdl, "Wrong rsp size\n");
		return -EINVAL;
	}

	return 0;
}

static void hifc_clear_clp_data(struct hifc_hwdev *hwdev,
				enum clp_data_type data_type)
{
	u32 reg = (data_type == HIFC_CLP_REQ_HOST) ?
		   HIFC_CLP_DATA(REQ) : HIFC_CLP_DATA(RSP);
	u32 count = HIFC_CLP_INPUT_BUFFER_LEN_HOST / HIFC_CLP_DATA_UNIT_HOST;

	for (; count > 0; count--) {
		hifc_hwif_write_reg(hwdev->hwif, reg, 0x0);
		reg = reg + 4;
	}
}

int hifc_pf_clp_to_mgmt(void *hwdev, enum hifc_mod_type mod, u8 cmd,
			const void *buf_in, u16 in_size,
			void *buf_out, u16 *out_size)
{
	struct hifc_clp_pf_to_mgmt *clp_pf_to_mgmt;
	struct hifc_hwdev *dev = hwdev;
	u64 header;
	u16 real_size;
	u8 *clp_msg_buf;
	int err;

	clp_pf_to_mgmt = ((struct hifc_hwdev *)hwdev)->clp_pf_to_mgmt;
	clp_msg_buf = clp_pf_to_mgmt->clp_msg_buf;

	/*4 bytes alignment*/
	if (in_size % HIFC_CLP_DATA_UNIT_HOST)
		real_size = (in_size + (u16)sizeof(header)
		     + HIFC_CLP_DATA_UNIT_HOST);
	else
		real_size = in_size + (u16)sizeof(header);
	real_size = real_size / HIFC_CLP_DATA_UNIT_HOST;

	if (real_size >
	    (HIFC_CLP_INPUT_BUFFER_LEN_HOST / HIFC_CLP_DATA_UNIT_HOST)) {
		sdk_err(dev->dev_hdl, "Invalid real_size:%d\n", real_size);
		return -EINVAL;
	}
	down(&clp_pf_to_mgmt->clp_msg_lock);

	err = hifc_check_clp_init_status(dev);
	if (err) {
		sdk_err(dev->dev_hdl, "Check clp init status failed\n");
		up(&clp_pf_to_mgmt->clp_msg_lock);
		return err;
	}

	hifc_clear_clp_data(dev, HIFC_CLP_RSP_HOST);
	hifc_write_clp_reg(dev, HIFC_CLP_RSP_HOST,
			   HIFC_CLP_READY_RSP_HOST, 0x0);

	/*Send request*/
	memset(clp_msg_buf, 0x0, HIFC_CLP_INPUT_BUFFER_LEN_HOST);
	clp_prepare_header(dev, &header, in_size, mod, 0, 0, cmd, 0);

	memcpy(clp_msg_buf, &header, sizeof(header));
	clp_msg_buf += sizeof(header);
	memcpy(clp_msg_buf, buf_in, in_size);

	clp_msg_buf = clp_pf_to_mgmt->clp_msg_buf;

	hifc_clear_clp_data(dev, HIFC_CLP_REQ_HOST);
	err = hifc_write_clp_data(hwdev,
				  clp_pf_to_mgmt->clp_msg_buf, real_size);
	if (err) {
		sdk_err(dev->dev_hdl, "Send clp request failed\n");
		up(&clp_pf_to_mgmt->clp_msg_lock);
		return -EINVAL;
	}

	/*Get response*/
	clp_msg_buf = clp_pf_to_mgmt->clp_msg_buf;
	memset(clp_msg_buf, 0x0, HIFC_CLP_INPUT_BUFFER_LEN_HOST);
	err = hifc_read_clp_data(hwdev, clp_msg_buf, &real_size);
	hifc_clear_clp_data(dev, HIFC_CLP_RSP_HOST);
	if (err) {
		sdk_err(dev->dev_hdl, "Read clp response failed\n");
		up(&clp_pf_to_mgmt->clp_msg_lock);
		return -EINVAL;
	}

	real_size = (u16)((real_size * HIFC_CLP_DATA_UNIT_HOST) & 0xffff);
	if ((real_size <= sizeof(header)) ||
	    (real_size > HIFC_CLP_INPUT_BUFFER_LEN_HOST)) {
		sdk_err(dev->dev_hdl, "Invalid response size:%d", real_size);
		up(&clp_pf_to_mgmt->clp_msg_lock);
		return -EINVAL;
	}
	real_size = real_size - sizeof(header);
	if (real_size != *out_size) {
		sdk_err(dev->dev_hdl, "Invalid real_size:%d, out_size:%d\n",
			real_size, *out_size);
		up(&clp_pf_to_mgmt->clp_msg_lock);
		return -EINVAL;
	}

	memcpy(buf_out, (clp_msg_buf + sizeof(header)), real_size);
	up(&clp_pf_to_mgmt->clp_msg_lock);

	return 0;
}

/* This function is only used by txrx flush */
int hifc_pf_to_mgmt_no_ack(void *hwdev, enum hifc_mod_type mod, u8 cmd,
			   void *buf_in, u16 in_size)
{
	struct hifc_msg_pf_to_mgmt *pf_to_mgmt;
	void *dev = ((struct hifc_hwdev *)hwdev)->dev_hdl;
	int err = -EINVAL;

	if (!hifc_is_hwdev_mod_inited(hwdev, HIFC_HWDEV_MGMT_INITED)) {
		sdk_err(dev, "Mgmt module not initialized\n");
		return -EINVAL;
	}

	pf_to_mgmt = ((struct hifc_hwdev *)hwdev)->pf_to_mgmt;

	if (!MSG_SZ_IS_VALID(in_size)) {
		sdk_err(dev, "Mgmt msg buffer size: %d is not valid\n",
			in_size);
		return -EINVAL;
	}

	if (!(((struct hifc_hwdev *)hwdev)->chip_present_flag))
		return -EPERM;

	/* Lock the sync_msg_buf */
	down(&pf_to_mgmt->sync_msg_lock);

	err = send_msg_to_mgmt_sync(pf_to_mgmt, mod, cmd, buf_in, in_size,
				    HIFC_MSG_NO_ACK, HIFC_MSG_DIRECT_SEND,
				    MSG_NO_RESP);

	up(&pf_to_mgmt->sync_msg_lock);

	return err;
}

/**
 * api cmd write or read bypass defaut use poll, if want to use aeq interrupt,
 * please set wb_trigger_aeqe to 1
 **/
int hifc_api_cmd_write_nack(void *hwdev, u8 dest, void *cmd, u16 size)
{
	struct hifc_msg_pf_to_mgmt *pf_to_mgmt;
	struct hifc_api_cmd_chain *chain;

	if (!hwdev || !size || !cmd)
		return -EINVAL;

	if (!hifc_is_hwdev_mod_inited(hwdev, HIFC_HWDEV_MGMT_INITED) ||
	    hifc_get_mgmt_channel_status(hwdev))
		return -EPERM;

	pf_to_mgmt = ((struct hifc_hwdev *)hwdev)->pf_to_mgmt;
	chain = pf_to_mgmt->cmd_chain[HIFC_API_CMD_POLL_WRITE];

	if (!(((struct hifc_hwdev *)hwdev)->chip_present_flag))
		return -EPERM;

	return hifc_api_cmd_write(chain, dest, cmd, size);
}

int hifc_api_cmd_read_ack(void *hwdev, u8 dest, void *cmd, u16 size, void *ack,
			  u16 ack_size)
{
	struct hifc_msg_pf_to_mgmt *pf_to_mgmt;
	struct hifc_api_cmd_chain *chain;

	if (!hwdev || !cmd || (ack_size && !ack))
		return -EINVAL;

	if (!hifc_is_hwdev_mod_inited(hwdev, HIFC_HWDEV_MGMT_INITED) ||
	    hifc_get_mgmt_channel_status(hwdev))
		return -EPERM;

	pf_to_mgmt = ((struct hifc_hwdev *)hwdev)->pf_to_mgmt;
	chain = pf_to_mgmt->cmd_chain[HIFC_API_CMD_POLL_READ];

	if (!(((struct hifc_hwdev *)hwdev)->chip_present_flag))
		return -EPERM;

	return hifc_api_cmd_read(chain, dest, cmd, size, ack, ack_size);
}

static void __send_mgmt_ack(struct hifc_msg_pf_to_mgmt *pf_to_mgmt,
			    enum hifc_mod_type mod, u8 cmd, void *buf_in,
			    u16 in_size, u16 msg_id)
{
	u16 buf_size;

	if (!in_size)
		buf_size = BUF_OUT_DEFAULT_SIZE;
	else
		buf_size = in_size;

	spin_lock_bh(&pf_to_mgmt->async_msg_lock);
	/* MGMT sent sync msg, send the response */
	send_msg_to_mgmt_async(pf_to_mgmt, mod, cmd,
			       buf_in, buf_size, HIFC_MSG_RESPONSE,
			       msg_id);
	spin_unlock_bh(&pf_to_mgmt->async_msg_lock);
}

/**
 * mgmt_recv_msg_handler - handler for message from mgmt cpu
 * @pf_to_mgmt: PF to MGMT channel
 * @recv_msg: received message details
 **/
static void mgmt_recv_msg_handler(struct hifc_msg_pf_to_mgmt *pf_to_mgmt,
				  enum hifc_mod_type mod, u8 cmd, void *buf_in,
				  u16 in_size, u16 msg_id, int need_resp)
{
	void *dev = pf_to_mgmt->hwdev->dev_hdl;
	void *buf_out = pf_to_mgmt->mgmt_ack_buf;
	enum hifc_mod_type tmp_mod = mod;
	bool ack_first = false;
	u16 out_size = 0;

	memset(buf_out, 0, MAX_PF_MGMT_BUF_SIZE);

	if (mod >= HIFC_MOD_HW_MAX) {
		sdk_warn(dev, "Receive illegal message from mgmt cpu, mod = %d\n",
			 mod);
		goto resp;
	}

	set_bit(HIFC_MGMT_MSG_CB_RUNNING,
		&pf_to_mgmt->mgmt_msg_cb_state[tmp_mod]);

	if (!pf_to_mgmt->recv_mgmt_msg_cb[mod] ||
	    !test_bit(HIFC_MGMT_MSG_CB_REG,
		      &pf_to_mgmt->mgmt_msg_cb_state[tmp_mod])) {
		sdk_warn(dev, "Receive mgmt callback is null, mod = %d\n",
			 mod);
		clear_bit(HIFC_MGMT_MSG_CB_RUNNING,
			  &pf_to_mgmt->mgmt_msg_cb_state[tmp_mod]);
		goto resp;
	}

	ack_first = hifc_mgmt_event_ack_first(mod, cmd);
	if (ack_first && need_resp) {
		/* send ack to mgmt first to avoid command timeout in
		 * mgmt(100ms in mgmt);
		 * mgmt to host command don't need any response data from host,
		 * just need ack from host
		 */
		__send_mgmt_ack(pf_to_mgmt, mod, cmd, buf_out, in_size, msg_id);
	}

	pf_to_mgmt->recv_mgmt_msg_cb[tmp_mod](pf_to_mgmt->hwdev,
					pf_to_mgmt->recv_mgmt_msg_data[tmp_mod],
					cmd, buf_in, in_size,
					buf_out, &out_size);

	clear_bit(HIFC_MGMT_MSG_CB_RUNNING,
		  &pf_to_mgmt->mgmt_msg_cb_state[tmp_mod]);

resp:
	if (!ack_first && need_resp)
		__send_mgmt_ack(pf_to_mgmt, mod, cmd, buf_out, out_size,
				msg_id);
}

/**
 * mgmt_resp_msg_handler - handler for response message from mgmt cpu
 * @pf_to_mgmt: PF to MGMT channel
 * @recv_msg: received message details
 **/
static void mgmt_resp_msg_handler(struct hifc_msg_pf_to_mgmt *pf_to_mgmt,
				  struct hifc_recv_msg *recv_msg)
{
	void *dev = pf_to_mgmt->hwdev->dev_hdl;

	/* delete async msg */
	if (recv_msg->msg_id & ASYNC_MSG_FLAG)
		return;

	spin_lock(&pf_to_mgmt->sync_event_lock);
	if (recv_msg->msg_id == pf_to_mgmt->sync_msg_id &&
	    pf_to_mgmt->event_flag == SEND_EVENT_START) {
		complete(&recv_msg->recv_done);
	} else if (recv_msg->msg_id != pf_to_mgmt->sync_msg_id) {
		sdk_err(dev, "Send msg id(0x%x) recv msg id(0x%x) dismatch, event state=%d\n",
			pf_to_mgmt->sync_msg_id, recv_msg->msg_id,
			pf_to_mgmt->event_flag);
	} else {
		sdk_err(dev, "Wait timeout, send msg id(0x%x) recv msg id(0x%x), event state=%d!\n",
			pf_to_mgmt->sync_msg_id, recv_msg->msg_id,
			pf_to_mgmt->event_flag);
	}
	spin_unlock(&pf_to_mgmt->sync_event_lock);
}

static void recv_mgmt_msg_work_handler(struct work_struct *work)
{
	struct hifc_mgmt_msg_handle_work *mgmt_work =
		container_of(work, struct hifc_mgmt_msg_handle_work, work);

	mgmt_recv_msg_handler(mgmt_work->pf_to_mgmt, mgmt_work->mod,
			      mgmt_work->cmd, mgmt_work->msg,
			      mgmt_work->msg_len, mgmt_work->msg_id,
			      !mgmt_work->async_mgmt_to_pf);

	kfree(mgmt_work->msg);
	kfree(mgmt_work);
}

static bool check_mgmt_seq_id_and_seg_len(struct hifc_recv_msg *recv_msg,
					  u8 seq_id, u8 seg_len)
{
	if (seq_id > MGMT_MSG_MAX_SEQ_ID || seg_len > SEGMENT_LEN)
		return false;

	if (seq_id == 0) {
		recv_msg->seq_id = seq_id;
	} else {
		if (seq_id != recv_msg->seq_id + 1)
			return false;
		recv_msg->seq_id = seq_id;
	}

	return true;
}

/**
 * recv_mgmt_msg_handler - handler a message from mgmt cpu
 * @pf_to_mgmt: PF to MGMT channel
 * @header: the header of the message
 * @recv_msg: received message details
 **/
static void recv_mgmt_msg_handler(struct hifc_msg_pf_to_mgmt *pf_to_mgmt,
				  u8 *header, struct hifc_recv_msg *recv_msg)
{
	struct hifc_mgmt_msg_handle_work *mgmt_work;
	u64 mbox_header = *((u64 *)header);
	void *msg_body = header + sizeof(mbox_header);
	u8 seq_id, seq_len;
	u32 offset;
	u64 dir;

	/* Don't need to get anything from hw when cmd is async */
	dir = HIFC_MSG_HEADER_GET(mbox_header, DIRECTION);
	if (dir == HIFC_MSG_RESPONSE &&
	    HIFC_MSG_HEADER_GET(mbox_header, MSG_ID) & ASYNC_MSG_FLAG)
		return;

	seq_len = HIFC_MSG_HEADER_GET(mbox_header, SEG_LEN);
	seq_id  = HIFC_MSG_HEADER_GET(mbox_header, SEQID);

	if (!check_mgmt_seq_id_and_seg_len(recv_msg, seq_id, seq_len)) {
		sdk_err(pf_to_mgmt->hwdev->dev_hdl,
			"Mgmt msg sequence id and segment length check fail, front seq_id: 0x%x, current seq_id: 0x%x, seg len: 0x%x\n",
			recv_msg->seq_id, seq_id, seq_len);
		/* set seq_id to invalid seq_id */
		recv_msg->seq_id = MGMT_MSG_MAX_SEQ_ID;
		return;
	}

	offset  = seq_id * SEGMENT_LEN;
	memcpy((u8 *)recv_msg->msg + offset, msg_body, seq_len);

	if (!HIFC_MSG_HEADER_GET(mbox_header, LAST))
		return;

	recv_msg->cmd = HIFC_MSG_HEADER_GET(mbox_header, CMD);
	recv_msg->mod = HIFC_MSG_HEADER_GET(mbox_header, MODULE);
	recv_msg->async_mgmt_to_pf = HIFC_MSG_HEADER_GET(mbox_header,
							  ASYNC_MGMT_TO_PF);
	recv_msg->msg_len = HIFC_MSG_HEADER_GET(mbox_header, MSG_LEN);
	recv_msg->msg_id = HIFC_MSG_HEADER_GET(mbox_header, MSG_ID);
	recv_msg->seq_id = MGMT_MSG_MAX_SEQ_ID;

	if (HIFC_MSG_HEADER_GET(mbox_header, DIRECTION) ==
	    HIFC_MSG_RESPONSE) {
		mgmt_resp_msg_handler(pf_to_mgmt, recv_msg);
		return;
	}

	mgmt_work = kzalloc(sizeof(*mgmt_work), GFP_KERNEL);
	if (!mgmt_work) {
		sdk_err(pf_to_mgmt->hwdev->dev_hdl,
			"Allocate mgmt work memory failed\n");
		return;
	}

	if (recv_msg->msg_len) {
		mgmt_work->msg = kzalloc(recv_msg->msg_len, GFP_KERNEL);
		if (!mgmt_work->msg) {
			sdk_err(pf_to_mgmt->hwdev->dev_hdl, "Allocate mgmt msg memory failed\n");
			kfree(mgmt_work);
			return;
		}
	}

	mgmt_work->pf_to_mgmt = pf_to_mgmt;
	mgmt_work->msg_len = recv_msg->msg_len;
	memcpy(mgmt_work->msg, recv_msg->msg, recv_msg->msg_len);
	mgmt_work->msg_id = recv_msg->msg_id;
	mgmt_work->mod = recv_msg->mod;
	mgmt_work->cmd = recv_msg->cmd;
	mgmt_work->async_mgmt_to_pf = recv_msg->async_mgmt_to_pf;

	INIT_WORK(&mgmt_work->work, recv_mgmt_msg_work_handler);
	queue_work(pf_to_mgmt->workq, &mgmt_work->work);
}

/**
 * hifc_mgmt_msg_aeqe_handler - handler for a mgmt message event
 * @hwdev: the pointer to hw device
 * @header: the header of the message
 * @size: unused
 **/
void hifc_mgmt_msg_aeqe_handler(void *hwdev, u8 *header, u8 size)
{
	struct hifc_hwdev *dev = (struct hifc_hwdev *)hwdev;
	struct hifc_msg_pf_to_mgmt *pf_to_mgmt;
	struct hifc_recv_msg *recv_msg;
	bool is_send_dir = false;

	pf_to_mgmt = dev->pf_to_mgmt;

	is_send_dir = (HIFC_MSG_HEADER_GET(*(u64 *)header, DIRECTION) ==
		       HIFC_MSG_DIRECT_SEND) ? true : false;

	recv_msg = is_send_dir ? &pf_to_mgmt->recv_msg_from_mgmt :
		   &pf_to_mgmt->recv_resp_msg_from_mgmt;

	recv_mgmt_msg_handler(pf_to_mgmt, header, recv_msg);
}

/**
 * alloc_recv_msg - allocate received message memory
 * @recv_msg: pointer that will hold the allocated data
 * Return: 0 - success, negative - failure
 **/
static int alloc_recv_msg(struct hifc_recv_msg *recv_msg)
{
	recv_msg->seq_id = MGMT_MSG_MAX_SEQ_ID;

	recv_msg->msg = kzalloc(MAX_PF_MGMT_BUF_SIZE, GFP_KERNEL);
	if (!recv_msg->msg)
		return -ENOMEM;

	return 0;
}

/**
 * free_recv_msg - free received message memory
 * @recv_msg: pointer that holds the allocated data
 **/
static void free_recv_msg(struct hifc_recv_msg *recv_msg)
{
	kfree(recv_msg->msg);
}

/**
 * alloc_msg_buf - allocate all the message buffers of PF to MGMT channel
 * @pf_to_mgmt: PF to MGMT channel
 * Return: 0 - success, negative - failure
 **/
static int alloc_msg_buf(struct hifc_msg_pf_to_mgmt *pf_to_mgmt)
{
	int err;
	void *dev = pf_to_mgmt->hwdev->dev_hdl;

	err = alloc_recv_msg(&pf_to_mgmt->recv_msg_from_mgmt);
	if (err) {
		sdk_err(dev, "Failed to allocate recv msg\n");
		return err;
	}

	err = alloc_recv_msg(&pf_to_mgmt->recv_resp_msg_from_mgmt);
	if (err) {
		sdk_err(dev, "Failed to allocate resp recv msg\n");
		goto alloc_msg_for_resp_err;
	}

	pf_to_mgmt->async_msg_buf = kzalloc(MAX_PF_MGMT_BUF_SIZE, GFP_KERNEL);
	if (!pf_to_mgmt->async_msg_buf)	{
		err = -ENOMEM;
		goto async_msg_buf_err;
	}

	pf_to_mgmt->sync_msg_buf = kzalloc(MAX_PF_MGMT_BUF_SIZE, GFP_KERNEL);
	if (!pf_to_mgmt->sync_msg_buf)	{
		err = -ENOMEM;
		goto sync_msg_buf_err;
	}

	pf_to_mgmt->mgmt_ack_buf = kzalloc(MAX_PF_MGMT_BUF_SIZE, GFP_KERNEL);
	if (!pf_to_mgmt->mgmt_ack_buf)	{
		err = -ENOMEM;
		goto ack_msg_buf_err;
	}

	return 0;

ack_msg_buf_err:
	kfree(pf_to_mgmt->sync_msg_buf);

sync_msg_buf_err:
	kfree(pf_to_mgmt->async_msg_buf);

async_msg_buf_err:
	free_recv_msg(&pf_to_mgmt->recv_resp_msg_from_mgmt);

alloc_msg_for_resp_err:
	free_recv_msg(&pf_to_mgmt->recv_msg_from_mgmt);
	return err;
}

/**
 * free_msg_buf - free all the message buffers of PF to MGMT channel
 * @pf_to_mgmt: PF to MGMT channel
 **/
static void free_msg_buf(struct hifc_msg_pf_to_mgmt *pf_to_mgmt)
{
	kfree(pf_to_mgmt->mgmt_ack_buf);
	kfree(pf_to_mgmt->sync_msg_buf);
	kfree(pf_to_mgmt->async_msg_buf);

	free_recv_msg(&pf_to_mgmt->recv_resp_msg_from_mgmt);
	free_recv_msg(&pf_to_mgmt->recv_msg_from_mgmt);
}

/**
 * hifc_pf_to_mgmt_init - initialize PF to MGMT channel
 * @hwdev: the pointer to hw device
 * Return: 0 - success, negative - failure
 **/
int hifc_pf_to_mgmt_init(struct hifc_hwdev *hwdev)
{
	struct hifc_msg_pf_to_mgmt *pf_to_mgmt;
	void *dev = hwdev->dev_hdl;
	int err;

	pf_to_mgmt = kzalloc(sizeof(*pf_to_mgmt), GFP_KERNEL);
	if (!pf_to_mgmt)
		return -ENOMEM;

	hwdev->pf_to_mgmt = pf_to_mgmt;
	pf_to_mgmt->hwdev = hwdev;
	spin_lock_init(&pf_to_mgmt->async_msg_lock);
	spin_lock_init(&pf_to_mgmt->sync_event_lock);
	sema_init(&pf_to_mgmt->sync_msg_lock, 1);
	pf_to_mgmt->workq = create_singlethread_workqueue(HIFC_MGMT_WQ_NAME);
	if (!pf_to_mgmt->workq) {
		sdk_err(dev, "Failed to initialize MGMT workqueue\n");
		err = -ENOMEM;
		goto create_mgmt_workq_err;
	}

	err = alloc_msg_buf(pf_to_mgmt);
	if (err) {
		sdk_err(dev, "Failed to allocate msg buffers\n");
		goto alloc_msg_buf_err;
	}

	err = hifc_api_cmd_init(hwdev, pf_to_mgmt->cmd_chain);
	if (err) {
		sdk_err(dev, "Failed to init the api cmd chains\n");
		goto api_cmd_init_err;
	}

	return 0;

api_cmd_init_err:
	free_msg_buf(pf_to_mgmt);

alloc_msg_buf_err:
	destroy_workqueue(pf_to_mgmt->workq);

create_mgmt_workq_err:
	kfree(pf_to_mgmt);

	return err;
}

/**
 * hifc_pf_to_mgmt_free - free PF to MGMT channel
 * @hwdev: the pointer to hw device
 **/
void hifc_pf_to_mgmt_free(struct hifc_hwdev *hwdev)
{
	struct hifc_msg_pf_to_mgmt *pf_to_mgmt = hwdev->pf_to_mgmt;

	/* destroy workqueue before free related pf_to_mgmt resources in case of
	 * illegal resource access
	 */
	destroy_workqueue(pf_to_mgmt->workq);
	hifc_api_cmd_free(pf_to_mgmt->cmd_chain);
	free_msg_buf(pf_to_mgmt);
	kfree(pf_to_mgmt);
}

void hifc_flush_mgmt_workq(void *hwdev)
{
	struct hifc_hwdev *dev = (struct hifc_hwdev *)hwdev;

	flush_workqueue(dev->aeqs->workq);

	if (hifc_func_type(dev) != TYPE_VF &&
	    hifc_is_hwdev_mod_inited(hwdev, HIFC_HWDEV_MGMT_INITED))
		flush_workqueue(dev->pf_to_mgmt->workq);
}

int hifc_clp_pf_to_mgmt_init(struct hifc_hwdev *hwdev)
{
	struct hifc_clp_pf_to_mgmt *clp_pf_to_mgmt;

	clp_pf_to_mgmt = kzalloc(sizeof(*clp_pf_to_mgmt), GFP_KERNEL);
	if (!clp_pf_to_mgmt)
		return -ENOMEM;

	clp_pf_to_mgmt->clp_msg_buf = kzalloc(HIFC_CLP_INPUT_BUFFER_LEN_HOST,
					      GFP_KERNEL);
	if (!clp_pf_to_mgmt->clp_msg_buf) {
		kfree(clp_pf_to_mgmt);
		return -ENOMEM;
	}
	sema_init(&clp_pf_to_mgmt->clp_msg_lock, 1);

	hwdev->clp_pf_to_mgmt = clp_pf_to_mgmt;

	return 0;
}

void hifc_clp_pf_to_mgmt_free(struct hifc_hwdev *hwdev)
{
	struct hifc_clp_pf_to_mgmt *clp_pf_to_mgmt = hwdev->clp_pf_to_mgmt;

	kfree(clp_pf_to_mgmt->clp_msg_buf);
	kfree(clp_pf_to_mgmt);
}
