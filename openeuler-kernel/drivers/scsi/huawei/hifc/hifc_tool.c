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
#include "hifc_hwif.h"
#include "hifc_api_cmd.h"
#include "hifc_mgmt.h"
#include "hifc_lld.h"
#include "hifc_dbgtool_knl.h"
#include "hifc_tool.h"
#include "hifc_portmng.h"

#define HIADM_DEV_PATH                 "/dev/hifc_dev"
#define HIADM_DEV_CLASS                "hifc_class"
#define HIADM_DEV_NAME                 "hifc_dev"

#define MAJOR_DEV_NUM                  921
#define	HIFC_CMDQ_BUF_MAX_SIZE         2048U
#define MSG_MAX_IN_SIZE                (2048 * 1024)
#define MSG_MAX_OUT_SIZE               (2048 * 1024)

static dev_t g_dev_id = {0};
static struct class *g_nictool_class;
static struct cdev g_nictool_cdev;

static int g_nictool_init_flag;
static int g_nictool_ref_cnt;

static void free_buff_in(void *hwdev, struct msg_module *nt_msg, void *buf_in)
{
	if (!buf_in)
		return;

	if (nt_msg->module == SEND_TO_UCODE)
		hifc_free_cmd_buf(hwdev, buf_in);
	else
		kfree(buf_in);
}

static int alloc_buff_in(void *hwdev, struct msg_module *nt_msg,
			 u32 in_size, void **buf_in)
{
	void *msg_buf;

	if (!in_size)
		return 0;

	if (nt_msg->module == SEND_TO_UCODE) {
		struct hifc_cmd_buf *cmd_buf;

		if (in_size > HIFC_CMDQ_BUF_MAX_SIZE) {
			pr_err("Cmdq in size(%u) more than 2KB\n", in_size);
			return -ENOMEM;
		}

		cmd_buf = hifc_alloc_cmd_buf(hwdev);
		if (!cmd_buf) {
			pr_err("Alloc cmdq cmd buffer failed in %s\n",
			       __func__);
			return -ENOMEM;
		}
		msg_buf = cmd_buf->buf;
		*buf_in = (void *)cmd_buf;
		cmd_buf->size = (u16)in_size;
	} else {
		if (in_size > MSG_MAX_IN_SIZE) {
			pr_err("In size(%u) more than 2M\n", in_size);
			return -ENOMEM;
		}
		msg_buf = kzalloc(in_size, GFP_KERNEL);
		*buf_in = msg_buf;
	}
	if (!(*buf_in)) {
		pr_err("Alloc buffer in failed\n");
		return -ENOMEM;
	}

	if (copy_from_user(msg_buf, nt_msg->in_buff, in_size)) {
		pr_err("%s:%d: Copy from user failed\n",
		       __func__, __LINE__);
		free_buff_in(hwdev, nt_msg, *buf_in);
		return -EFAULT;
	}

	return 0;
}

static void free_buff_out(void *hwdev, struct msg_module *nt_msg,
			  void *buf_out)
{
	if (!buf_out)
		return;

	if (nt_msg->module == SEND_TO_UCODE &&
	    !nt_msg->ucode_cmd.ucode_db.ucode_imm)
		hifc_free_cmd_buf(hwdev, buf_out);
	else
		kfree(buf_out);
}

static int alloc_buff_out(void *hwdev, struct msg_module *nt_msg,
			  u32 out_size, void **buf_out)
{
	if (!out_size)
		return 0;

	if (nt_msg->module == SEND_TO_UCODE &&
	    !nt_msg->ucode_cmd.ucode_db.ucode_imm) {
		struct hifc_cmd_buf *cmd_buf;

		if (out_size > HIFC_CMDQ_BUF_MAX_SIZE) {
			pr_err("Cmdq out size(%u) more than 2KB\n", out_size);
			return -ENOMEM;
		}

		cmd_buf = hifc_alloc_cmd_buf(hwdev);
		*buf_out = (void *)cmd_buf;
	} else {
		if (out_size > MSG_MAX_OUT_SIZE) {
			pr_err("out size(%u) more than 2M\n", out_size);
			return -ENOMEM;
		}
		*buf_out = kzalloc(out_size, GFP_KERNEL);
	}
	if (!(*buf_out)) {
		pr_err("Alloc buffer out failed\n");
		return -ENOMEM;
	}

	return 0;
}

static int copy_buf_out_to_user(struct msg_module *nt_msg,
				u32 out_size, void *buf_out)
{
	int ret = 0;
	void *msg_out;

	if (nt_msg->module == SEND_TO_UCODE &&
	    !nt_msg->ucode_cmd.ucode_db.ucode_imm)
		msg_out = ((struct hifc_cmd_buf *)buf_out)->buf;
	else
		msg_out = buf_out;

	if (copy_to_user(nt_msg->out_buf, msg_out, out_size))
		ret = -EFAULT;

	return ret;
}

static int __get_card_usr_api_chain_mem(int card_idx)
{
#define DBGTOOL_PAGE_ORDER 10

	unsigned char *tmp;
	int i;

	mutex_lock(&g_addr_lock);
	card_id = card_idx;
	if (!g_card_vir_addr[card_idx]) {
		g_card_vir_addr[card_idx] =
			(void *)__get_free_pages(GFP_KERNEL,
						 DBGTOOL_PAGE_ORDER);
		if (!g_card_vir_addr[card_idx]) {
			pr_err("Alloc api chain memory fail for card %d.\n",
			       card_idx);
			mutex_unlock(&g_addr_lock);
			return -EFAULT;
		}

		memset(g_card_vir_addr[card_idx], 0,
		       PAGE_SIZE * (1 << DBGTOOL_PAGE_ORDER));

		g_card_phy_addr[card_idx] =
			virt_to_phys(g_card_vir_addr[card_idx]);
		if (!g_card_phy_addr[card_idx]) {
			pr_err("phy addr for card %d is 0.\n", card_idx);
			free_pages((unsigned long)g_card_vir_addr[card_idx],
				   DBGTOOL_PAGE_ORDER);
			g_card_vir_addr[card_idx] = NULL;
			mutex_unlock(&g_addr_lock);
			return -EFAULT;
		}

		tmp = g_card_vir_addr[card_idx];
		for (i = 0; i < (1 << DBGTOOL_PAGE_ORDER); i++) {
			SetPageReserved(virt_to_page(tmp));
			tmp += PAGE_SIZE;
		}
	}
	mutex_unlock(&g_addr_lock);

	return 0;
}

static int get_card_func_info(char *dev_name, struct msg_module *nt_msg)
{
	struct hifc_card_func_info card_func_info = {0};
	int id, err;

	if (nt_msg->len_info.out_buff_len != sizeof(card_func_info) ||
	    nt_msg->len_info.in_buff_len != sizeof(card_func_info)) {
		pr_err("Invalid out_buf_size %d or Invalid in_buf_size %d, expect %lu\n",
		       nt_msg->len_info.out_buff_len,
		       nt_msg->len_info.in_buff_len,
		       sizeof(card_func_info));
		return -EINVAL;
	}

	err = memcmp(dev_name, HIFC_CHIP_NAME, strlen(HIFC_CHIP_NAME));
	if (err) {
		pr_err("Invalid chip name %s\n", dev_name);
		return err;
	}

	err = sscanf(dev_name, HIFC_CHIP_NAME "%d", &id);
	if (err < 0) {
		pr_err("Failed to get hifc id\n");
		return err;
	}

	if (id >= MAX_CARD_NUM) {
		pr_err("chip id %d exceed limit[0-%d]\n", id, MAX_CARD_NUM - 1);
		return -EINVAL;
	}

	hifc_get_card_func_info_by_card_name(dev_name, &card_func_info);

	if (!card_func_info.num_pf) {
		pr_err("None function found for %s\n", dev_name);
		return -EFAULT;
	}

	err = __get_card_usr_api_chain_mem(id);
	if (err) {
		pr_err("Faile to get api chain memory for userspace %s\n",
		       dev_name);
		return -EFAULT;
	}

	card_func_info.usr_api_phy_addr = g_card_phy_addr[id];

	/* Copy the dev_info to user mode */
	if (copy_to_user(nt_msg->out_buf, &card_func_info,
			 sizeof(card_func_info))) {
		pr_err("Copy dev_info to user fail\n");
		return -EFAULT;
	}

	return 0;
}

static bool is_mgmt_cmd_support(void *hwdev, unsigned int mod, u32 up_api_type)
{
	if (FUNC_SUPPORT_MGMT(hwdev)) {
		if (up_api_type == API_CLP) {
			if (!hifc_is_hwdev_mod_inited
					(hwdev, HIFC_HWDEV_CLP_INITED)) {
				pr_err("CLP have not initialized\n");
				return false;
			}
		} else if (!hifc_is_hwdev_mod_inited
					(hwdev, HIFC_HWDEV_MGMT_INITED)) {
			pr_err("MGMT have not initialized\n");
			return false;
		}
	} else if (!hifc_is_hwdev_mod_inited
					(hwdev, HIFC_HWDEV_MBOX_INITED)) {
		pr_err("MBOX have not initialized\n");
		return false;
	}

	return true;
}

static bool is_hwdev_cmd_support(unsigned int mod,
				 char *ifname, u32 up_api_type)
{
	void *hwdev;

	hwdev = hifc_get_hwdev_by_ifname(ifname);
	if (!hwdev) {
		pr_err("Can not get the device %s correctly\n", ifname);
		return false;
	}

	switch (mod) {
	case SEND_TO_UP:
	case SEND_TO_SM:
		return is_mgmt_cmd_support(hwdev, mod, up_api_type);
	case SEND_TO_UCODE:
		if (!hifc_is_hwdev_mod_inited(hwdev,
					      HIFC_HWDEV_CMDQ_INITED)) {
			pr_err("CMDQ have not initialized\n");
			return false;
		}
		break;

	default:
		return false;
	}

	return true;
}

static bool nictool_k_is_cmd_support(unsigned int mod,
				     char *ifname, u32 up_api_type)
{
	enum hifc_init_state init_state =
			hifc_get_init_state_by_ifname(ifname);

	if (init_state == HIFC_INIT_STATE_NONE)
		return false;

	if (mod == HIFCADM_FC_DRIVER) {
		if (init_state < HIFC_INIT_STATE_ALL_INITED) {
			pr_err("HIFC driver have not initialized\n");
			return false;
		}

		return true;
	} else if (mod >= SEND_TO_UCODE && mod <= SEND_TO_SM) {
		return is_hwdev_cmd_support(mod, ifname, up_api_type);
	} else if (mod == SEND_TO_HW_DRIVER) {
		if (init_state < HIFC_INIT_STATE_HWDEV_INITED) {
			pr_err("Hwdev have not initialized\n");
			return false;
		}

		return true;
	}

	return false;
}

static int alloc_tmp_buf(void *hwdev, struct msg_module *nt_msg, u32 in_size,
			 void **buf_in, u32 out_size, void **buf_out)
{
	int ret;

	ret = alloc_buff_in(hwdev, nt_msg, in_size, buf_in);
	if (ret) {
		pr_err("Alloc tool cmd buff in failed\n");
		return ret;
	}

	ret = alloc_buff_out(hwdev, nt_msg, out_size, buf_out);
	if (ret) {
		pr_err("Alloc tool cmd buff out failed\n");
		goto out_free_buf_in;
	}

	return 0;

out_free_buf_in:
	free_buff_in(hwdev, nt_msg, *buf_in);

	return ret;
}

static void free_tmp_buf(void *hwdev, struct msg_module *nt_msg,
			 void *buf_in, void *buf_out)
{
	free_buff_out(hwdev, nt_msg, buf_out);
	free_buff_in(hwdev, nt_msg, buf_in);
}

static int get_all_chip_id_cmd(struct msg_module *nt_msg)
{
	struct nic_card_id card_id;

	hifc_get_all_chip_id((void *)&card_id);

	if (copy_to_user(nt_msg->out_buf, &card_id, sizeof(card_id))) {
		pr_err("Copy chip id to user failed\n");
		return -EFAULT;
	}

	return 0;
}

static bool __is_pcidev_match_dev_name(const char *ifname,
				       struct hifc_pcidev *dev)
{
	if (!strncmp(dev->uld_dev_name, ifname, IFNAMSIZ))
		return true;

	if ((dev->uld_dev) && (strlen(ifname) == 0))
		return true;

	return false;
}

struct hifc_pcidev *hifc_get_pcidev_by_dev_name(char *ifname)
{
	struct card_node *chip_node;
	struct hifc_pcidev *dev;

	lld_dev_hold();
	list_for_each_entry(chip_node, &g_hinic_chip_list, node) {
		list_for_each_entry(dev, &chip_node->func_list, node) {
			if (test_bit(HIFC_FUNC_IN_REMOVE, &dev->flag))
				continue;

			if (__is_pcidev_match_dev_name(ifname, dev)) {
				lld_dev_put();
				return dev;
			}
		}
	}
	lld_dev_put();

	return NULL;
}

static void *get_support_uld_dev(struct msg_module *nt_msg)
{
	struct hifc_pcidev *dev;

	dev = hifc_get_pcidev_by_dev_name(nt_msg->device_name);

	if (dev)
		return dev->uld_dev;

	return NULL;
}

static int get_service_drv_version(void *hwdev, struct msg_module *nt_msg,
				   void *buf_in, u32 in_size, void *buf_out,
				   u32 *out_size)
{
	enum hifc_service_type type;
	int ret = 0;

	type = nt_msg->module - SEND_TO_SM;
	if (type != SERVICE_T_FC) {
		pr_err("err cmd type: %d\n", type);
		return ret;
	}
	*out_size = sizeof(struct drv_version_info);

	ret = hifc_adm(NULL, nt_msg->msg_formate, buf_in, in_size,
		       buf_out, out_size);
	if (ret)
		return ret;

	if (copy_to_user(nt_msg->out_buf, buf_out, *out_size))
		return -EFAULT;

	return ret;
}

int send_to_service_driver(struct msg_module *nt_msg, void *buf_in,
			   u32 in_size, void *buf_out, u32 *out_size)
{
	enum hifc_service_type type;
	void *uld_dev;
	int ret = -EINVAL;

	type = nt_msg->module - SEND_TO_SM;

	if (type == SERVICE_T_FC) {
		uld_dev = get_support_uld_dev(nt_msg);
		if (!uld_dev)
			return -EINVAL;
		ret = hifc_adm(uld_dev,
			       nt_msg->msg_formate,
			       buf_in, in_size, buf_out,
			       out_size);
	} else {
		pr_err("Ioctl input module id: %d is incorrectly\n",
		       nt_msg->module);
	}

	return ret;
}

static int nictool_exec_cmd(void *hwdev, struct msg_module *nt_msg,
			    void *buf_in, u32 in_size, void *buf_out,
			    u32 *out_size)
{
	int ret;

	switch (nt_msg->module) {
	case SEND_TO_HW_DRIVER:
		ret = send_to_hw_driver(hwdev, nt_msg, buf_in,
					in_size, buf_out, out_size);
		break;
	case SEND_TO_UP:
		ret = send_to_up(hwdev, nt_msg, buf_in,
				 in_size, buf_out, out_size);
		break;
	case SEND_TO_UCODE:
		ret = send_to_ucode(hwdev, nt_msg, buf_in,
				    in_size, buf_out, out_size);
		break;
	case SEND_TO_SM:
		ret = send_to_sm(hwdev, nt_msg, buf_in,
				 in_size, buf_out, out_size);
		break;
	default:
		ret = send_to_service_driver(nt_msg, buf_in, in_size, buf_out,
					     out_size);
		break;
	}

	return ret;
}

static bool hifc_is_special_handling_cmd(struct msg_module *nt_msg, int *ret)
{
	bool handled = true;

	if (nt_msg->module != SEND_TO_HW_DRIVER)
		return false;

	switch (nt_msg->msg_formate) {
	case GET_CHIP_ID:
		*ret = get_all_chip_id_cmd(nt_msg);
		break;
	case GET_CHIP_INFO:
		*ret = get_card_func_info(nt_msg->device_name, nt_msg);
		break;
	default:
		handled = false;
		break;
	}

	return handled;
}

static int do_nictool_ioctl_cmd(void *hwdev, struct msg_module *nt_msg)
{
	void *buf_out = NULL;
	void *buf_in = NULL;
	u32 out_size_expect;
	u32 out_size, in_size;
	int ret = 0;

	out_size_expect = nt_msg->len_info.out_buff_len;
	in_size = nt_msg->len_info.in_buff_len;

	ret = alloc_tmp_buf(hwdev, nt_msg, in_size,
			    &buf_in, out_size_expect, &buf_out);
	if (ret) {
		pr_err("Alloc tmp buff failed\n");
		return ret;
	}

	out_size = out_size_expect;

	if ((nt_msg->msg_formate == GET_DRV_VERSION) &&
	    (nt_msg->module == HIFCADM_FC_DRIVER)) {
		ret = get_service_drv_version(hwdev, nt_msg, buf_in,
					      in_size, buf_out, &out_size);
		goto out_free_buf;
	}

	ret = nictool_exec_cmd(hwdev, nt_msg, buf_in,
			       in_size, buf_out, &out_size);
	if (ret) {
		pr_err("nictool_exec_cmd failed, mod:%d msg_formate:%d\n",
		       nt_msg->module, nt_msg->msg_formate);
		goto out_free_buf;
	}

	if (out_size_expect && buf_out) {
		ret = copy_buf_out_to_user(nt_msg, out_size_expect, buf_out);
		if (ret)
			pr_err("Copy information to user failed\n");
	}
out_free_buf:
	free_tmp_buf(hwdev, nt_msg, buf_in, buf_out);

	return ret;
}

static long nictool_k_unlocked_ioctl(struct file *pfile,
				     unsigned int cmd, unsigned long arg)
{
	void *hwdev;
	struct msg_module nt_msg;
	int ret = 0;

	memset(&nt_msg, 0, sizeof(nt_msg));

	if (copy_from_user(&nt_msg, (void *)arg, sizeof(nt_msg))) {
		pr_err("Copy information from user failed\n");
		return -EFAULT;
	}

	/* end with '\0' */
	nt_msg.device_name[IFNAMSIZ - 1] = '\0';

	hifc_tool_cnt_inc();
	if (hifc_is_special_handling_cmd(&nt_msg, &ret))
		goto out_free_lock;

	if (nt_msg.module == HIFCADM_FC_DRIVER &&
	    nt_msg.msg_formate == GET_CHIP_ID)
		get_fc_devname(nt_msg.device_name);

	if (!nictool_k_is_cmd_support(nt_msg.module, nt_msg.device_name,
				      nt_msg.up_cmd.up_db.up_api_type)) {
		ret = -EFAULT;
		goto out_free_lock;
	}

	/* get the netdevice */
	hwdev = hifc_get_hwdev_by_ifname(nt_msg.device_name);
	if (!hwdev) {
		pr_err("Can not get the device %s correctly\n",
		       nt_msg.device_name);
		ret = -ENODEV;
		goto out_free_lock;
	}

	ret = do_nictool_ioctl_cmd(hwdev, &nt_msg);

out_free_lock:
	hifc_tool_cnt_dec();

	return (long)ret;
}

static int nictool_k_open(struct inode *pnode, struct file *pfile)
{
	return 0;
}

static ssize_t nictool_k_read(struct file *pfile, char __user *ubuf,
			      size_t size, loff_t *ppos)
{
	return 0;
}

static ssize_t nictool_k_write(struct file *pfile, const char __user *ubuf,
			       size_t size, loff_t *ppos)
{
	return 0;
}

static const struct file_operations fifo_operations = {
	.owner = THIS_MODULE,
	.open = nictool_k_open,
	.read = nictool_k_read,
	.write = nictool_k_write,
	.unlocked_ioctl = nictool_k_unlocked_ioctl,
	.mmap = hifc_mem_mmap,
};

int if_nictool_exist(void)
{
	struct file *fp = NULL;
	int exist = 0;

	fp = filp_open(HIADM_DEV_PATH, O_RDONLY, 0);
	if (IS_ERR(fp)) {
		exist = 0;
	} else {
		(void)filp_close(fp, NULL);
		exist = 1;
	}

	return exist;
}

/**
 * nictool_k_init - initialize the hw interface
 */
int nictool_k_init(void)
{
	int ret;
	struct device *pdevice;

	if (g_nictool_init_flag) {
		g_nictool_ref_cnt++;
		/* already initialized */
		return 0;
	}

	if (if_nictool_exist()) {
		pr_err("Nictool device exists\n");
		return 0;
	}

	/* Device ID: primary device ID (12bit) |
	 * secondary device number (20bit)
	 */
	g_dev_id = MKDEV(MAJOR_DEV_NUM, 0);

	/* Static device registration number */
	ret = register_chrdev_region(g_dev_id, 1, HIADM_DEV_NAME);
	if (ret < 0) {
		ret = alloc_chrdev_region(&g_dev_id, 0, 1, HIADM_DEV_NAME);
		if (ret < 0) {
			pr_err("Register nictool_dev fail(0x%x)\n", ret);
			return ret;
		}
	}

	/* Create equipment */
	/*lint -save -e160*/
	g_nictool_class = class_create(THIS_MODULE, HIADM_DEV_CLASS);
	/*lint -restore*/
	if (IS_ERR(g_nictool_class)) {
		pr_err("Create nictool_class fail\n");
		ret = -EFAULT;
		goto class_create_err;
	}

	/* Initializing the character device */
	cdev_init(&g_nictool_cdev, &fifo_operations);

	/* Add devices to the operating system */
	ret = cdev_add(&g_nictool_cdev, g_dev_id, 1);
	if (ret < 0) {
		pr_err("Add nictool_dev to operating system fail(0x%x)\n", ret);
		goto cdev_add_err;
	}

	/* Export device information to user space
	 * (/sys/class/class name/device name)
	 */
	pdevice = device_create(g_nictool_class, NULL,
				g_dev_id, NULL, HIADM_DEV_NAME);
	if (IS_ERR(pdevice)) {
		pr_err("Export nictool device information to user space fail\n");
		ret = -EFAULT;
		goto device_create_err;
	}

	g_nictool_init_flag = 1;
	g_nictool_ref_cnt = 1;

	pr_info("Register nictool_dev to system succeed\n");

	return 0;

device_create_err:
	cdev_del(&g_nictool_cdev);

cdev_add_err:
	class_destroy(g_nictool_class);

class_create_err:
	g_nictool_class = NULL;
	unregister_chrdev_region(g_dev_id, 1);

	return ret;
}

void nictool_k_uninit(void)
{
	if (g_nictool_init_flag) {
		if ((--g_nictool_ref_cnt))
			return;
	}

	g_nictool_init_flag = 0;

	if (!g_nictool_class || IS_ERR(g_nictool_class))
		return;

	cdev_del(&g_nictool_cdev);
	device_destroy(g_nictool_class, g_dev_id);
	class_destroy(g_nictool_class);
	g_nictool_class = NULL;

	unregister_chrdev_region(g_dev_id, 1);

	pr_info("Unregister nictool_dev succeed\n");
}
