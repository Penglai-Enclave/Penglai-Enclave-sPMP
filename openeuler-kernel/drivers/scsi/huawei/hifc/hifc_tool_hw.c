// SPDX-License-Identifier: GPL-2.0
/* Huawei Hifc PCI Express Linux driver
 * Copyright(c) 2017 Huawei Technologies Co., Ltd
 *
 */
#define pr_fmt(fmt) KBUILD_MODNAME ": [COMM]" fmt

#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/netdevice.h>
#include <linux/interrupt.h>
#include <linux/pci.h>
#include <net/sock.h>

#include "hifc_knl_adp.h"
#include "hifc_hw.h"
#include "hifc_hwdev.h"
#include "hifc_hwif.h"
#include "hifc_api_cmd.h"
#include "hifc_mgmt.h"
#include "hifc_cfg.h"
#include "hifc_lld.h"
#include "hifc_sml.h"
#include "hifc_tool.h"

static atomic_t tool_used_cnt;

typedef int (*hw_driv_module)(void *hwdev, void *buf_in, u32 in_size,
			      void *buf_out, u32 *out_size);

struct hw_drv_module_handle {
	enum driver_cmd_type	driv_cmd_name;
	hw_driv_module		driv_func;
};

u8 hifc_physical_port_id(void *hwdev)
{
	struct hifc_hwdev *dev = hwdev;

	if (!dev) {
		pr_err("Hwdev pointer is NULL for getting physical port id\n");
		return 0;
	}
	return dev->cfg_mgmt->svc_cap.port_id;
}

int hifc_clp_to_mgmt(void *hwdev, enum hifc_mod_type mod, u8 cmd,
		     void *buf_in, u16 in_size,
		     void *buf_out, u16 *out_size)
{
	struct hifc_hwdev *dev = hwdev;
	int err;

	if (!dev)
		return -EINVAL;

	if (!dev->chip_present_flag)
		return -EPERM;

	if (!hifc_is_hwdev_mod_inited(hwdev, HIFC_HWDEV_CLP_INITED))
		return -EPERM;

	err = hifc_pf_clp_to_mgmt(dev, mod, cmd, buf_in,
				  in_size, buf_out, out_size);

	return err;
}

static int get_func_type(void *hwdev, void *buf_in, u32 in_size,
			 void *buf_out, u32 *out_size)
{
	u16 func_typ;

	func_typ = hifc_func_type(hwdev);
	if (!buf_out || *out_size != sizeof(u16)) {
		pr_err("Unexpect out buf size from user :%d, expect: %lu\n",
		       *out_size, sizeof(u16));
		return -EFAULT;
	}
	*(u16 *)buf_out = func_typ;
	return 0;
}

static int get_func_id(void *hwdev, void *buf_in, u32 in_size,
		       void *buf_out, u32 *out_size)
{
	u16 func_id;

	if (!buf_out || *out_size != sizeof(u16)) {
		pr_err("Unexpect out buf size from user :%d, expect: %lu\n",
		       *out_size, sizeof(u16));
		return -EFAULT;
	}

	func_id = hifc_global_func_id_hw(hwdev);
	*(u16 *)buf_out = func_id;
	*out_size = sizeof(u16);
	return 0;
}

static int get_drv_version(void *hwdev, void *buf_in, u32 in_size,
			   void *buf_out, u32 *out_size)
{
	struct drv_version_info *ver_info;
	char ver_str[MAX_VER_INFO_LEN] = {0};

	if (*out_size != sizeof(*ver_info)) {
		pr_err("Unexpect out buf size from user :%d, expect: %lu\n",
		       *out_size, sizeof(*ver_info));
		return -EFAULT;
	}
	snprintf(ver_str, sizeof(ver_str), "%s  %s",
		 HIFC_DRV_VERSION, __TIME_STR__);
	ver_info = (struct drv_version_info *)buf_out;
	memcpy(ver_info->ver, ver_str, sizeof(ver_str));

	return 0;
}

static int clear_hw_stats(void *hwdev, void *buf_in, u32 in_size,
			  void *buf_out, u32 *out_size)
{
	return 0;
}

static int get_hw_stats(void *hwdev, void *buf_in, u32 in_size,
			void *buf_out, u32 *out_size)
{
	return 0;
}

static void hifc_get_chip_fault_stats(const void *hwdev,
				      u8 *chip_fault_stats, int offset)
{
	int copy_len = offset + MAX_DRV_BUF_SIZE - HIFC_CHIP_FAULT_SIZE;

	if (offset < 0 || offset > HIFC_CHIP_FAULT_SIZE) {
		pr_err("Invalid chip offset value: %d\n",
		       offset);
		return;
	}

	if (offset + MAX_DRV_BUF_SIZE <= HIFC_CHIP_FAULT_SIZE)
		memcpy(chip_fault_stats,
		       ((struct hifc_hwdev *)hwdev)->chip_fault_stats + offset,
		       MAX_DRV_BUF_SIZE);
	else
		memcpy(chip_fault_stats,
		       ((struct hifc_hwdev *)hwdev)->chip_fault_stats + offset,
		       copy_len);
}

static int get_chip_faults_stats(void *hwdev, void *buf_in, u32 in_size,
				 void *buf_out, u32 *out_size)
{
	int offset = 0;
	struct chip_fault_stats *fault_info;

	if (!buf_in || !buf_out || *out_size != sizeof(*fault_info) ||
	    in_size != sizeof(*fault_info)) {
		pr_err("Unexpect out buf size from user :%d, expect: %lu\n",
		       *out_size, sizeof(*fault_info));
		return -EFAULT;
	}
	fault_info = (struct chip_fault_stats *)buf_in;
	offset = fault_info->offset;
	fault_info = (struct chip_fault_stats *)buf_out;
	hifc_get_chip_fault_stats(hwdev, fault_info->chip_faults, offset);

	return 0;
}

static int get_chip_id_test(void *hwdev, void *buf_in, u32 in_size,
			    void *buf_out, u32 *out_size)
{
	return 0;
}

static int get_single_card_info(void *hwdev, void *buf_in, u32 in_size,
				void *buf_out, u32 *out_size)
{
	if (!buf_in || !buf_out || in_size != sizeof(struct card_info) ||
	    *out_size != sizeof(struct card_info)) {
		pr_err("Unexpect out buf size from user :%d, expect: %lu\n",
		       *out_size, sizeof(struct card_info));
		return -EFAULT;
	}

	hifc_get_card_info(hwdev, buf_out);
	*out_size = in_size;
	return 0;
}

#define GET_FIRMWARE_ACTIVE_STATUS_TIMEOUT	30
static int get_firmware_active_status(void *hwdev, void *buf_in, u32 in_size,
				      void *buf_out, u32 *out_size)
{
	u32 loop_cnt = 0;

	while (loop_cnt < GET_FIRMWARE_ACTIVE_STATUS_TIMEOUT) {
		if (!hifc_get_mgmt_channel_status(hwdev))
			return 0;

		msleep(1000);
		loop_cnt++;
	}
	if (loop_cnt == GET_FIRMWARE_ACTIVE_STATUS_TIMEOUT)
		return -ETIMEDOUT;

	return 0;
}

static int get_device_id(void *hwdev, void *buf_in, u32 in_size,
			 void *buf_out, u32 *out_size)
{
	u16 dev_id;
	int err;

	if (!buf_out || !buf_in || *out_size != sizeof(u16) ||
	    in_size != sizeof(u16)) {
		pr_err("Unexpect out buf size from user :%d, expect: %lu\n",
		       *out_size, sizeof(u16));
		return -EFAULT;
	}

	err = hifc_get_device_id(hwdev, &dev_id);
	if (err)
		return err;

	*((u32 *)buf_out) = dev_id;
	*out_size = in_size;

	return 0;
}

bool hifc_is_in_host(void)
{
	struct card_node *chip_node;
	struct hifc_pcidev *dev;

	lld_dev_hold();
	list_for_each_entry(chip_node, &g_hinic_chip_list, node) {
		list_for_each_entry(dev, &chip_node->func_list, node) {
			if (test_bit(HIFC_FUNC_IN_REMOVE, &dev->flag))
				continue;

			if (dev->init_state > HIFC_INIT_STATE_PCI_INITED) {
				lld_dev_put();
				return true;
			}
		}
	}
	lld_dev_put();

	return false;
}

static int is_driver_in_vm(void *hwdev, void *buf_in, u32 in_size,
			   void *buf_out, u32 *out_size)
{
	bool in_host;

	if (!buf_out || (*out_size != sizeof(u8)))
		return -EINVAL;

	in_host = hifc_is_in_host();
	if (in_host)
		*((u8 *)buf_out) = 0;
	else
		*((u8 *)buf_out) = 1;

	return 0;
}

static int get_pf_id(void *hwdev, void *buf_in, u32 in_size,
		     void *buf_out, u32 *out_size)
{
	struct hifc_pf_info *pf_info;
	u32 port_id = 0;
	int err;

	if (!buf_out || (*out_size != sizeof(*pf_info)) ||
	    !buf_in || in_size != sizeof(u32))
		return -EINVAL;

	port_id = *((u32 *)buf_in);
	pf_info = (struct hifc_pf_info *)buf_out;
	err = hifc_get_pf_id(hwdev, port_id, &pf_info->pf_id,
			     &pf_info->isvalid);
	if (err)
		return err;

	*out_size = sizeof(*pf_info);

	return 0;
}

static struct hw_drv_module_handle hw_driv_module_cmd_handle[] = {
	{FUNC_TYPE,             get_func_type},
	{GET_FUNC_IDX,          get_func_id},
	{GET_DRV_VERSION,       get_drv_version},
	{GET_HW_STATS,          get_hw_stats},
	{CLEAR_HW_STATS,        clear_hw_stats},
	{GET_CHIP_FAULT_STATS,  get_chip_faults_stats},
	{GET_CHIP_ID,           get_chip_id_test},
	{GET_SINGLE_CARD_INFO,  get_single_card_info},
	{GET_FIRMWARE_ACTIVE_STATUS, get_firmware_active_status},
	{GET_DEVICE_ID,         get_device_id},
	{IS_DRV_IN_VM,          is_driver_in_vm},
	{GET_PF_ID,             get_pf_id},
};

int send_to_hw_driver(void *hwdev, struct msg_module *nt_msg,
		      void *buf_in, u32 in_size, void *buf_out, u32 *out_size)
{
	int index, num_cmds = sizeof(hw_driv_module_cmd_handle) /
				sizeof(hw_driv_module_cmd_handle[0]);
	enum driver_cmd_type cmd_type;
	int err = 0;

	if (!nt_msg) {
		pr_err("Input param invalid!\n");
		return -EINVAL;
	}
	cmd_type = (enum driver_cmd_type)(nt_msg->msg_formate);
	for (index = 0; index < num_cmds; index++) {
		if (cmd_type ==
			hw_driv_module_cmd_handle[index].driv_cmd_name) {
			err = hw_driv_module_cmd_handle[index].driv_func
					(hwdev, buf_in,
					 in_size, buf_out, out_size);
			break;
		}
	}

	if (index == num_cmds)
		return -EINVAL;

	return err;
}

typedef int (*sm_module)(void *hwdev, u32 id, u8 instance,
			 u8 node, struct sm_out_st *buf_out);

static int sm_rd32(void *hwdev, u32 id, u8 instance,
		   u8 node, struct sm_out_st *buf_out)
{
	u32 val1;
	int ret;

	ret = hifc_sm_ctr_rd32(hwdev, node, instance, id, &val1);
	if (ret) {
		pr_err("Get sm ctr information (32 bits)failed!\n");
		val1 = 0xffffffff;
	}

	buf_out->val1 = val1;

	return ret;
}

static int sm_rd64_pair(void *hwdev, u32 id, u8 instance,
			u8 node, struct sm_out_st *buf_out)
{
	u64 val1 = 0, val2 = 0;
	int ret;

	ret = hifc_sm_ctr_rd64_pair(hwdev, node, instance, id, &val1, &val2);
	if (ret) {
		pr_err("Get sm ctr information (64 bits pair)failed!\n");
		val1 = 0xffffffff;
	}

	buf_out->val1 = val1;
	buf_out->val2 = val2;

	return ret;
}

static int sm_rd64(void *hwdev, u32 id, u8 instance,
		   u8 node, struct sm_out_st *buf_out)
{
	u64 val1;
	int ret;

	ret = hifc_sm_ctr_rd64(hwdev, node, instance, id, &val1);
	if (ret) {
		pr_err("Get sm ctr information (64 bits)failed!\n");
		val1 = 0xffffffff;
	}
	buf_out->val1 = val1;

	return ret;
}

struct sm_module_handle {
	enum sm_cmd_type    sm_cmd_name;
	sm_module           sm_func;
};

struct sm_module_handle sm_module_cmd_handle[] = {
	{SM_CTR_RD32,		sm_rd32},
	{SM_CTR_RD64_PAIR,	sm_rd64_pair},
	{SM_CTR_RD64,		sm_rd64}
};

int send_to_sm(void *hwdev, struct msg_module *nt_msg, void *buf_in,
	       u32 in_size, void *buf_out, u32 *out_size)
{
	struct sm_in_st *sm_in = buf_in;
	struct sm_out_st *sm_out = buf_out;
	u32 msg_formate;
	int index, num_cmds = sizeof(sm_module_cmd_handle) /
				sizeof(sm_module_cmd_handle[0]);
	int ret = 0;

	if ((!nt_msg) || (!buf_in) || (!buf_out) ||
	    (in_size != sizeof(*sm_in)) ||
	    (*out_size != sizeof(*sm_out))) {
		pr_err("Input param invalid!\n");
		return -EINVAL;
	}

	msg_formate = nt_msg->msg_formate;
	for (index = 0; index < num_cmds; index++) {
		if (msg_formate == sm_module_cmd_handle[index].sm_cmd_name)
			ret = sm_module_cmd_handle[index].sm_func(hwdev,
						(u32)sm_in->id,
						(u8)sm_in->instance,
						(u8)sm_in->node, sm_out);
	}

	if (ret)
		pr_err("Get sm information fail!\n");

	*out_size = sizeof(struct sm_out_st);

	return ret;
}

static u32 get_up_timeout_val(enum hifc_mod_type mod, u8 cmd)
{
#define UP_UPDATEFW_TIME_OUT_VAL		20000U
	if (mod == HIFC_MOD_L2NIC && cmd == NIC_UP_CMD_UPDATE_FW)
		return UP_UPDATEFW_TIME_OUT_VAL;
	else
		return UP_COMP_TIME_OUT_VAL;
}

static int api_csr_write(void *hwdev, struct msg_module *nt_msg,
			 void *buf_in, u32 in_size, void *buf_out,
			 u32 *out_size)
{
	struct csr_write_st *csr_write_msg = (struct csr_write_st *)buf_in;
	int ret = 0;
	u32 rd_len;
	u32 rd_addr;
	u32 rd_cnt = 0;
	u32 offset = 0;
	u8 node_id;
	u32 i;
	u8 *data;

	if (!buf_in || in_size != sizeof(*csr_write_msg))
		return -EINVAL;

	rd_len = csr_write_msg->rd_len;
	rd_addr = csr_write_msg->addr;
	node_id = (u8)nt_msg->up_cmd.up_db.comm_mod_type;

	if (rd_len % 4) {
		pr_err("Csr length must be a multiple of 4\n");
		return -EFAULT;
	}

	rd_cnt = rd_len / 4;
	data = kzalloc(rd_len, GFP_KERNEL);
	if (!data) {
		pr_err("No more memory\n");
		return -EFAULT;
	}
	if (copy_from_user(data, (void *)csr_write_msg->data, rd_len)) {
		pr_err("Copy information from user failed\n");
		kfree(data);
		return -EFAULT;
	}

	for (i = 0; i < rd_cnt; i++) {
		ret = hifc_api_csr_wr32(hwdev, node_id,
					rd_addr + offset,
					*((u32 *)(data + offset)));
		if (ret) {
			pr_err("Csr wr fail, ret: %d, node_id: %d, csr addr: 0x%08x\n",
			       ret, rd_addr + offset, node_id);
			kfree(data);
			return ret;
		}
		offset += 4;
	}

	*out_size = 0;
	kfree(data);
	return ret;
}

static int api_csr_read(void *hwdev, struct msg_module *nt_msg,
			void *buf_in, u32 in_size, void *buf_out, u32 *out_size)
{
	struct up_log_msg_st *up_log_msg = (struct up_log_msg_st *)buf_in;
	int ret = 0;
	u32 rd_len;
	u32 rd_addr;
	u32 rd_cnt = 0;
	u32 offset = 0;
	u8 node_id;
	u32 i;

	if (!buf_in || !buf_out || in_size != sizeof(*up_log_msg) ||
	    *out_size != up_log_msg->rd_len)
		return -EINVAL;

	rd_len = up_log_msg->rd_len;
	rd_addr = up_log_msg->addr;
	node_id = (u8)nt_msg->up_cmd.up_db.comm_mod_type;

	rd_cnt = rd_len / 4;

	if (rd_len % 4)
		rd_cnt++;

	for (i = 0; i < rd_cnt; i++) {
		ret = hifc_api_csr_rd32(hwdev, node_id,
					rd_addr + offset,
					(u32 *)(((u8 *)buf_out) + offset));
		if (ret) {
			pr_err("Csr rd fail, err: %d, node_id: %d, csr addr: 0x%08x\n",
			       ret, node_id, rd_addr + offset);
			return ret;
		}
		offset += 4;
	}
	*out_size = rd_len;

	return ret;
}

int send_to_up(void *hwdev, struct msg_module *nt_msg, void *buf_in,
	       u32 in_size, void *buf_out, u32 *out_size)
{
	int ret = 0;

	if ((!nt_msg) || (!hwdev) || (!buf_in) || (!buf_out)) {
		pr_err("Input param invalid!\n");
		return -EINVAL;
	}

	if ((nt_msg->up_cmd.up_db.up_api_type == API_CMD) ||
	    (nt_msg->up_cmd.up_db.up_api_type == API_CLP)) {
		enum hifc_mod_type mod;
		u8 cmd;
		u32 timeout;

		mod = (enum hifc_mod_type)nt_msg->up_cmd.up_db.comm_mod_type;
		cmd = nt_msg->up_cmd.up_db.chipif_cmd;

		timeout = get_up_timeout_val(mod, cmd);

		if (nt_msg->up_cmd.up_db.up_api_type == API_CMD)
			ret = hifc_msg_to_mgmt_sync(hwdev, mod, cmd,
						    buf_in, (u16)in_size,
						    buf_out, (u16 *)out_size,
						    timeout);
		else
			ret = hifc_clp_to_mgmt(hwdev, mod, cmd,
					       buf_in, (u16)in_size,
					       buf_out, (u16 *)out_size);
		if (ret) {
			pr_err("Message to mgmt cpu return fail, mod: %d, cmd: %d\n",
			       mod, cmd);
			return ret;
		}

	} else if (nt_msg->up_cmd.up_db.up_api_type == API_CHAIN) {
		if (nt_msg->up_cmd.up_db.chipif_cmd == API_CSR_WRITE) {
			ret = api_csr_write(hwdev, nt_msg, buf_in,
					    in_size, buf_out, out_size);
			return ret;
		}

		ret = api_csr_read(hwdev, nt_msg, buf_in,
				   in_size, buf_out, out_size);
	}

	return ret;
}

int send_to_ucode(void *hwdev, struct msg_module *nt_msg, void *buf_in,
		  u32 in_size, void *buf_out, u32 *out_size)
{
	int ret = 0;

	if ((!nt_msg) || (!hwdev) || (!buf_in)) {
		pr_err("Input param invalid!\n");
		return -EINVAL;
	}

	if (nt_msg->ucode_cmd.ucode_db.ucode_imm) {
		ret = hifc_cmdq_direct_resp
			(hwdev, nt_msg->ucode_cmd.ucode_db.cmdq_ack_type,
			 nt_msg->ucode_cmd.ucode_db.comm_mod_type,
			 nt_msg->ucode_cmd.ucode_db.ucode_cmd_type,
			 buf_in, buf_out, 0);
		if (ret)
			pr_err("Send direct cmdq err: %d!\n", ret);
	} else {
		ret = hifc_cmdq_detail_resp
			(hwdev, nt_msg->ucode_cmd.ucode_db.cmdq_ack_type,
			 nt_msg->ucode_cmd.ucode_db.comm_mod_type,
			 nt_msg->ucode_cmd.ucode_db.ucode_cmd_type,
			 buf_in, buf_out, 0);
		if (ret)
			pr_err("Send detail cmdq err: %d!\n", ret);
	}

	return ret;
}

void hifc_tool_cnt_inc(void)
{
	atomic_inc(&tool_used_cnt);
}

void hifc_tool_cnt_dec(void)
{
	atomic_dec(&tool_used_cnt);
}

static bool __is_pcidev_match_chip_name(const char *ifname,
					struct hifc_pcidev *dev,
					struct card_node *chip_node,
					enum func_type type)
{
	if (!strncmp(chip_node->chip_name, ifname, IFNAMSIZ)) {
		if (type == TYPE_UNKNOWN) {
			if (dev->init_state < HIFC_INIT_STATE_HW_PART_INITED)
				return false;
		} else {
			if (dev->init_state >=
			    HIFC_INIT_STATE_HW_PART_INITED &&
			    hifc_func_type(dev->hwdev) != type)
				return false;
		}

		return true;
	}

	return false;
}

static struct hifc_pcidev *_get_pcidev_by_chip_name(char *ifname,
						    enum func_type type)
{
	struct card_node *chip_node;
	struct hifc_pcidev *dev;

	lld_dev_hold();
	list_for_each_entry(chip_node, &g_hinic_chip_list, node) {
		list_for_each_entry(dev, &chip_node->func_list, node) {
			if (test_bit(HIFC_FUNC_IN_REMOVE, &dev->flag))
				continue;

			if (__is_pcidev_match_chip_name(ifname, dev, chip_node,
							type)) {
				lld_dev_put();
				return dev;
			}
		}
	}

	lld_dev_put();

	return NULL;
}

static struct hifc_pcidev *hifc_get_pcidev_by_chip_name(char *ifname)
{
	struct hifc_pcidev *dev, *dev_hw_init;

	/* find hw init device first */
	dev_hw_init = _get_pcidev_by_chip_name(ifname, TYPE_UNKNOWN);
	if (dev_hw_init) {
		if (hifc_func_type(dev_hw_init->hwdev) == TYPE_PPF)
			return dev_hw_init;
	}

	dev = _get_pcidev_by_chip_name(ifname, TYPE_PPF);
	if (dev) {
		if (dev_hw_init && (dev_hw_init->init_state >= dev->init_state))
			return dev_hw_init;

		return dev;
	}

	dev = _get_pcidev_by_chip_name(ifname, TYPE_PF);
	if (dev) {
		if (dev_hw_init && (dev_hw_init->init_state >= dev->init_state))
			return dev_hw_init;

		return dev;
	}

	return NULL;
}

static struct hifc_pcidev *hifc_get_pcidev_by_ifname(char *ifname)
{
	struct hifc_pcidev *dev;

	/* support search hwdev by chip name, net device name,
	 * or fc device name
	 */
	/* Find pcidev by chip_name first */
	dev = hifc_get_pcidev_by_chip_name(ifname);
	if (dev)
		return dev;

	/* If ifname not a chip name,
	 * find pcidev by FC name or netdevice name
	 */
	return hifc_get_pcidev_by_dev_name(ifname);
}

void *hifc_get_hwdev_by_ifname(char *ifname)
{
	struct hifc_pcidev *dev;

	if (!ifname) {
		pr_err("Input param invalid!\n");
		return NULL;
	}

	dev = hifc_get_pcidev_by_ifname(ifname);
	if (dev)
		return dev->hwdev;

	return NULL;
}

enum hifc_init_state hifc_get_init_state_by_ifname(char *ifname)
{
	struct hifc_pcidev *dev;

	if (!ifname) {
		pr_err("Input param invalid!\n");
		return HIFC_INIT_STATE_NONE;
	}
	dev = hifc_get_pcidev_by_ifname(ifname);
	if (dev)
		return dev->init_state;

	pr_err("Can not get device %s\n", ifname);

	return HIFC_INIT_STATE_NONE;
}

void get_fc_devname(char *devname)
{
	struct card_node *chip_node;
	struct hifc_pcidev *dev;

	if (!devname) {
		pr_err("Input param invalid!\n");
		return;
	}

	lld_dev_hold();
	list_for_each_entry(chip_node, &g_hinic_chip_list, node) {
		list_for_each_entry(dev, &chip_node->func_list, node) {
			if (test_bit(HIFC_FUNC_IN_REMOVE, &dev->flag))
				continue;

			if (dev->init_state < HIFC_INIT_STATE_ALL_INITED)
				continue;

			if (dev->uld_dev) {
				strlcpy(devname, (char *)dev->uld_dev_name,
					IFNAMSIZ);
				lld_dev_put();
				return;
			}
		}
	}
	lld_dev_put();
}

void hifc_get_all_chip_id(void *id_info)
{
	struct nic_card_id *card_id = (struct nic_card_id *)id_info;
	struct card_node *chip_node;
	int i = 0;
	int id, err;

	if (!card_id) {
		pr_err("Input param invalid!\n");
		return;
	}

	lld_dev_hold();
	list_for_each_entry(chip_node, &g_hinic_chip_list, node) {
		err = sscanf(chip_node->chip_name, HIFC_CHIP_NAME "%d", &id);
		if (err < 0)
			pr_err("Failed to get hifc id\n");

		card_id->id[i] = id;
		i++;
	}
	lld_dev_put();
	card_id->num = i;
}

static struct card_node *hifc_get_chip_node_by_hwdev(const void *hwdev)
{
	struct card_node *chip_node = NULL;
	struct card_node *node_tmp = NULL;
	struct hifc_pcidev *dev;

	if (!hwdev)
		return NULL;

	lld_dev_hold();
	list_for_each_entry(node_tmp, &g_hinic_chip_list, node) {
		if (!chip_node) {
			list_for_each_entry(dev, &node_tmp->func_list, node) {
				if (test_bit(HIFC_FUNC_IN_REMOVE, &dev->flag))
					continue;

				if (dev->hwdev == hwdev) {
					chip_node = node_tmp;
					break;
				}
			}
		}
	}

	lld_dev_put();

	return chip_node;
}

int hifc_get_device_id(void *hwdev, u16 *dev_id)
{
	struct card_node *chip_node = NULL;
	struct hifc_pcidev *dev;
	u16 vendor_id = 0;
	u16 device_id = 0;

	if ((!dev_id) || (!hwdev)) {
		pr_err("Input param invalid!\n");
		return -ENODEV;
	}
	chip_node = hifc_get_chip_node_by_hwdev(hwdev);
	if (!chip_node)
		return -ENODEV;

	lld_dev_hold();
	list_for_each_entry(dev, &chip_node->func_list, node) {
		if (test_bit(HIFC_FUNC_IN_REMOVE, &dev->flag))
			continue;

		pci_read_config_word(dev->pcidev, 0, &vendor_id);
		if (vendor_id == HIFC_PCI_VENDOR_ID) {
			pci_read_config_word(dev->pcidev, 2, &device_id);
			break;
		}
	}
	lld_dev_put();
	*dev_id = device_id;

	return 0;
}

int hifc_get_pf_id(void *hwdev, u32 port_id, u32 *pf_id, u32 *isvalid)
{
	struct card_node *chip_node = NULL;
	struct hifc_pcidev *dev;

	if ((!isvalid) || (!pf_id) || (!hwdev)) {
		pr_err("Input param invalid!\n");
		return -ENODEV;
	}
	chip_node = hifc_get_chip_node_by_hwdev(hwdev);
	if (!chip_node)
		return -ENODEV;

	lld_dev_hold();
	list_for_each_entry(dev, &chip_node->func_list, node) {
		if (hifc_physical_port_id(dev->hwdev) == port_id) {
			*pf_id = hifc_global_func_id(dev->hwdev);
			*isvalid = 1;
			break;
		}
	}
	lld_dev_put();

	return 0;
}

bool hifc_is_valid_bar_addr(u64 offset)
{
	struct card_node *chip_node = NULL;
	struct hifc_pcidev *dev;

	lld_dev_hold();
	list_for_each_entry(chip_node, &g_hinic_chip_list, node) {
		list_for_each_entry(dev, &chip_node->func_list, node) {
			if (test_bit(HIFC_FUNC_IN_REMOVE, &dev->flag))
				continue;

			if (offset == pci_resource_start(dev->pcidev, 0)) {
				lld_dev_put();
				return true;
			}
		}
	}
	lld_dev_put();

	return false;
}

void hifc_get_card_func_info_by_card_name(
	const char *chip_name, struct hifc_card_func_info *card_func)
{
	struct card_node *chip_node = NULL;
	struct hifc_pcidev *dev;
	struct func_pdev_info *pdev_info;

	if ((!card_func) || (!chip_name)) {
		pr_err("Input param invalid!\n");
		return;
	}
	card_func->num_pf = 0;

	lld_dev_hold();
	list_for_each_entry(chip_node, &g_hinic_chip_list, node) {
		if (strncmp(chip_node->chip_name, chip_name, IFNAMSIZ))
			continue;

		list_for_each_entry(dev, &chip_node->func_list, node) {
			if (hifc_func_type(dev->hwdev) == TYPE_VF)
				continue;

			if (test_bit(HIFC_FUNC_IN_REMOVE, &dev->flag))
				continue;

			pdev_info = &card_func->pdev_info[card_func->num_pf];
			pdev_info->bar0_size = pci_resource_len(dev->pcidev, 0);
			pdev_info->bar0_phy_addr =
					pci_resource_start(dev->pcidev, 0);

			card_func->num_pf++;
			if (card_func->num_pf >= MAX_SIZE)
				break;
		}
	}

	lld_dev_put();
}

static bool __is_func_valid(struct hifc_pcidev *dev)
{
	if (test_bit(HIFC_FUNC_IN_REMOVE, &dev->flag))
		return false;

	if (dev->init_state < HIFC_INIT_STATE_HWDEV_INITED)
		return false;

	return true;
}

void hifc_get_card_info(void *hwdev, void *bufin)
{
	struct card_node *chip_node = NULL;
	struct card_info *info = (struct card_info *)bufin;
	struct hifc_pcidev *dev;
	u32 idx = 0;

	if ((!bufin) || (!hwdev)) {
		pr_err("Input param invalid!\n");
		return;
	}
	info->pf_num = 0;

	chip_node = hifc_get_chip_node_by_hwdev(hwdev);
	if (!chip_node)
		return;

	lld_dev_hold();
	list_for_each_entry(dev, &chip_node->func_list, node) {
		if (!__is_func_valid(dev))
			continue;

		strlcpy(info->pf[idx].name, dev->uld_dev_name, IFNAMSIZ);
		info->pf[idx].pf_type = (u32)BIT(SERVICE_T_FC);
		strlcpy(info->pf[idx].bus_info, pci_name(dev->pcidev),
			sizeof(info->pf[idx].bus_info));
		info->pf_num++;
		idx++;
	}
	lld_dev_put();
}
