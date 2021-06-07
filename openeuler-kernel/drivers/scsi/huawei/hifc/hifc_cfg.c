// SPDX-License-Identifier: GPL-2.0
/* Huawei Hifc PCI Express Linux driver
 * Copyright(c) 2017 Huawei Technologies Co., Ltd
 *
 */
#define pr_fmt(fmt) KBUILD_MODNAME ": [COMM]" fmt

#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/mutex.h>
#include <linux/device.h>
#include <linux/pci.h>
#include <linux/module.h>
#include <linux/completion.h>
#include <linux/semaphore.h>
#include <linux/vmalloc.h>

#include "hifc_knl_adp.h"
#include "hifc_hw.h"
#include "hifc_hwdev.h"
#include "hifc_hwif.h"
#include "hifc_cqm_main.h"
#include "hifc_api_cmd.h"
#include "hifc_hw.h"
#include "hifc_mgmt.h"
#include "hifc_cfg.h"

uint intr_mode;

int hifc_sync_time(void *hwdev, u64 time)
{
	struct hifc_sync_time_info time_info = {0};
	u16 out_size = sizeof(time_info);
	int err;

	time_info.mstime = time;
	err = hifc_msg_to_mgmt_sync(hwdev, HIFC_MOD_COMM,
				    HIFC_MGMT_CMD_SYNC_TIME, &time_info,
				    sizeof(time_info), &time_info, &out_size,
				    0);
	if (err || time_info.status || !out_size) {
		sdk_err(((struct hifc_hwdev *)hwdev)->dev_hdl,
			"Failed to sync time to mgmt, err: %d, status: 0x%x, out size: 0x%x\n",
			err, time_info.status, out_size);
	}

	return err;
}

static void parse_pub_res_cap(struct service_cap *cap,
			      struct hifc_dev_cap *dev_cap,
			      enum func_type type)
{
	cap->port_id = dev_cap->port_id;
	cap->force_up = dev_cap->force_up;

	pr_info("Get public resource capbility, force_up: 0x%x\n",
		cap->force_up);
	/* FC need max queue number, but max queue number info is in
	 * l2nic cap, we also put max queue num info in public cap, so
	 * FC can get correct max queue number info.
	 */
	cap->max_sqs = dev_cap->nic_max_sq + 1;
	cap->max_rqs = dev_cap->nic_max_rq + 1;

	cap->host_total_function = dev_cap->host_total_func;
	cap->host_oq_id_mask_val = dev_cap->host_oq_id_mask_val;
	cap->max_connect_num = dev_cap->max_conn_num;
	cap->max_stick2cache_num = dev_cap->max_stick2cache_num;

	pr_info("Get public resource capbility, svc_cap_en: 0x%x\n",
		dev_cap->svc_cap_en);
	pr_info("port_id=0x%x\n", cap->port_id);
	pr_info("Host_total_function=0x%x, host_oq_id_mask_val=0x%x\n",
		cap->host_total_function, cap->host_oq_id_mask_val);
}

static void parse_fc_res_cap(struct service_cap *cap,
			     struct hifc_dev_cap *dev_cap,
			     enum func_type type)
{
	struct dev_fc_svc_cap *fc_cap = &cap->fc_cap.dev_fc_cap;

	fc_cap->max_parent_qpc_num = dev_cap->fc_max_pctx;
	fc_cap->scq_num = dev_cap->fc_max_scq;
	fc_cap->srq_num = dev_cap->fc_max_srq;
	fc_cap->max_child_qpc_num = dev_cap->fc_max_cctx;
	fc_cap->vp_id_start = dev_cap->fc_vp_id_start;
	fc_cap->vp_id_end = dev_cap->fc_vp_id_end;

	pr_info("Get fc resource capbility\n");
	pr_info("Max_parent_qpc_num=0x%x, scq_num=0x%x, srq_num=0x%x, max_child_qpc_num=0x%x\n",
		fc_cap->max_parent_qpc_num, fc_cap->scq_num, fc_cap->srq_num,
		fc_cap->max_child_qpc_num);
	pr_info("Vp_id_start=0x%x, vp_id_end=0x%x\n",
		fc_cap->vp_id_start, fc_cap->vp_id_end);
}

static void parse_dev_cap(struct hifc_hwdev *dev,
			  struct hifc_dev_cap *dev_cap, enum func_type type)
{
	struct service_cap *cap = &dev->cfg_mgmt->svc_cap;

	/* Public resource */
	parse_pub_res_cap(cap, dev_cap, type);

	/* PPF managed dynamic resource */

	parse_fc_res_cap(cap, dev_cap, type);
}

static int get_cap_from_fw(struct hifc_hwdev *dev, enum func_type type)
{
	struct hifc_dev_cap dev_cap = {0};
	u16 out_len = sizeof(dev_cap);
	int err;

	dev_cap.version = HIFC_CMD_VER_FUNC_ID;
	err = hifc_global_func_id_get(dev, &dev_cap.func_id);
	if (err)
		return err;

	sdk_info(dev->dev_hdl, "Get cap from fw, func_idx: %d\n",
		 dev_cap.func_id);

	err = hifc_msg_to_mgmt_sync(dev, HIFC_MOD_CFGM, HIFC_CFG_NIC_CAP,
				    &dev_cap, sizeof(dev_cap),
				    &dev_cap, &out_len, 0);
	if (err || dev_cap.status || !out_len) {
		sdk_err(dev->dev_hdl,
			"Failed to get capability from FW, err: %d, status: 0x%x, out size: 0x%x\n",
			err, dev_cap.status, out_len);
		return -EFAULT;
	}

	parse_dev_cap(dev, &dev_cap, type);
	return 0;
}

static void fc_param_fix(struct hifc_hwdev *dev)
{
	struct service_cap *cap = &dev->cfg_mgmt->svc_cap;
	struct fc_service_cap *fc_cap = &cap->fc_cap;

	fc_cap->parent_qpc_size = FC_PCTX_SZ;
	fc_cap->child_qpc_size = FC_CCTX_SZ;
	fc_cap->sqe_size = FC_SQE_SZ;

	fc_cap->scqc_size = FC_SCQC_SZ;
	fc_cap->scqe_size = FC_SCQE_SZ;

	fc_cap->srqc_size = FC_SRQC_SZ;
	fc_cap->srqe_size = FC_SRQE_SZ;
}

static void cfg_get_eq_num(struct hifc_hwdev *dev)
{
	struct cfg_eq_info *eq_info = &dev->cfg_mgmt->eq_info;

	eq_info->num_ceq = dev->hwif->attr.num_ceqs;
	eq_info->num_ceq_remain = eq_info->num_ceq;
}

static int cfg_init_eq(struct hifc_hwdev *dev)
{
	struct cfg_mgmt_info *cfg_mgmt = dev->cfg_mgmt;
	struct cfg_eq *eq;
	u8 num_ceq, i = 0;

	cfg_get_eq_num(dev);
	num_ceq = cfg_mgmt->eq_info.num_ceq;

	sdk_info(dev->dev_hdl, "Cfg mgmt: ceqs=0x%x, remain=0x%x\n",
		 cfg_mgmt->eq_info.num_ceq, cfg_mgmt->eq_info.num_ceq_remain);

	if (!num_ceq) {
		sdk_err(dev->dev_hdl, "Ceq num cfg in fw is zero\n");
		return -EFAULT;
	}
	eq = kcalloc(num_ceq, sizeof(*eq), GFP_KERNEL);
	if (!eq)
		return -ENOMEM;

	for (i = 0; i < num_ceq; ++i) {
		eq[i].eqn = i;
		eq[i].free = CFG_FREE;
		eq[i].type = SERVICE_T_MAX;
	}

	cfg_mgmt->eq_info.eq = eq;

	mutex_init(&cfg_mgmt->eq_info.eq_mutex);

	return 0;
}

static int cfg_init_interrupt(struct hifc_hwdev *dev)
{
	struct cfg_mgmt_info *cfg_mgmt = dev->cfg_mgmt;
	struct cfg_irq_info *irq_info = &cfg_mgmt->irq_param_info;
	u16 intr_num = dev->hwif->attr.num_irqs;

	if (!intr_num) {
		sdk_err(dev->dev_hdl, "Irq num cfg in fw is zero\n");
		return -EFAULT;
	}
	irq_info->alloc_info = kcalloc(intr_num, sizeof(*irq_info->alloc_info),
				       GFP_KERNEL);
	if (!irq_info->alloc_info)
		return -ENOMEM;

	irq_info->num_irq_hw = intr_num;

	cfg_mgmt->svc_cap.interrupt_type = intr_mode;

	mutex_init(&irq_info->irq_mutex);

	return 0;
}

static int cfg_enable_interrupt(struct hifc_hwdev *dev)
{
	struct cfg_mgmt_info *cfg_mgmt = dev->cfg_mgmt;
	u16 nreq = cfg_mgmt->irq_param_info.num_irq_hw;

	void *pcidev = dev->pcidev_hdl;
	struct irq_alloc_info_st *irq_info;
	struct msix_entry *entry;
	u16 i = 0;
	int actual_irq;

	irq_info = cfg_mgmt->irq_param_info.alloc_info;

	sdk_info(dev->dev_hdl, "Interrupt type: %d, irq num: %d.\n",
		 cfg_mgmt->svc_cap.interrupt_type, nreq);

	switch (cfg_mgmt->svc_cap.interrupt_type) {
	case INTR_TYPE_MSIX:

		if (!nreq) {
			sdk_err(dev->dev_hdl, "Interrupt number cannot be zero\n");
			return -EINVAL;
		}
		entry = kcalloc(nreq, sizeof(*entry), GFP_KERNEL);
		if (!entry)
			return -ENOMEM;

		for (i = 0; i < nreq; i++)
			entry[i].entry = i;

		actual_irq = pci_enable_msix_range(pcidev, entry,
						   VECTOR_THRESHOLD, nreq);
		if (actual_irq < 0) {
			sdk_err(dev->dev_hdl, "Alloc msix entries with threshold 2 failed.\n");
			kfree(entry);
			return -ENOMEM;
		}

		nreq = (u16)actual_irq;
		cfg_mgmt->irq_param_info.num_total = nreq;
		cfg_mgmt->irq_param_info.num_irq_remain = nreq;
		sdk_info(dev->dev_hdl, "Request %d msix vector success.\n",
			 nreq);

		for (i = 0; i < nreq; ++i) {
			/* u16 driver uses to specify entry, OS writes */
			irq_info[i].info.msix_entry_idx = entry[i].entry;
			/* u32 kernel uses to write allocated vector */
			irq_info[i].info.irq_id = entry[i].vector;
			irq_info[i].type = SERVICE_T_MAX;
			irq_info[i].free = CFG_FREE;
		}

		kfree(entry);

		break;

	default:
		sdk_err(dev->dev_hdl, "Unsupport interrupt type %d\n",
			cfg_mgmt->svc_cap.interrupt_type);
		break;
	}

	return 0;
}

int hifc_alloc_irqs(void *hwdev, enum hifc_service_type type, u16 num,
		    struct irq_info *irq_info_array, u16 *act_num)
{
	struct hifc_hwdev *dev = hwdev;
	struct cfg_mgmt_info *cfg_mgmt;
	struct cfg_irq_info *irq_info;
	struct irq_alloc_info_st *alloc_info;
	int max_num_irq;
	u16 free_num_irq;
	int i, j;

	if (!hwdev || !irq_info_array || !act_num)
		return -EINVAL;

	cfg_mgmt = dev->cfg_mgmt;
	irq_info = &cfg_mgmt->irq_param_info;
	alloc_info = irq_info->alloc_info;
	max_num_irq = irq_info->num_total;
	free_num_irq = irq_info->num_irq_remain;

	mutex_lock(&irq_info->irq_mutex);

	if (num > free_num_irq) {
		if (free_num_irq == 0) {
			sdk_err(dev->dev_hdl,
				"no free irq resource in cfg mgmt.\n");
			mutex_unlock(&irq_info->irq_mutex);
			return -ENOMEM;
		}

		sdk_warn(dev->dev_hdl, "only %d irq resource in cfg mgmt.\n",
			 free_num_irq);
		num = free_num_irq;
	}

	*act_num = 0;

	for (i = 0; i < num; i++) {
		for (j = 0; j < max_num_irq; j++) {
			if (alloc_info[j].free == CFG_FREE) {
				if (irq_info->num_irq_remain == 0) {
					sdk_err(dev->dev_hdl, "No free irq resource in cfg mgmt\n");
					mutex_unlock(&irq_info->irq_mutex);
					return -EINVAL;
				}
				alloc_info[j].type = type;
				alloc_info[j].free = CFG_BUSY;

				irq_info_array[i].msix_entry_idx =
					alloc_info[j].info.msix_entry_idx;
				irq_info_array[i].irq_id =
					alloc_info[j].info.irq_id;
				(*act_num)++;
				irq_info->num_irq_remain--;

				break;
			}
		}
	}

	mutex_unlock(&irq_info->irq_mutex);
	return 0;
}

void hifc_free_irq(void *hwdev, enum hifc_service_type type, u32 irq_id)
{
	struct hifc_hwdev *dev = hwdev;
	struct cfg_mgmt_info *cfg_mgmt;
	struct cfg_irq_info *irq_info;
	struct irq_alloc_info_st *alloc_info;
	int max_num_irq;
	int i;

	if (!hwdev)
		return;

	cfg_mgmt = dev->cfg_mgmt;
	irq_info = &cfg_mgmt->irq_param_info;
	alloc_info = irq_info->alloc_info;
	max_num_irq = irq_info->num_total;

	mutex_lock(&irq_info->irq_mutex);

	for (i = 0; i < max_num_irq; i++) {
		if (irq_id == alloc_info[i].info.irq_id &&
		    type == alloc_info[i].type) {
			if (alloc_info[i].free == CFG_BUSY) {
				alloc_info[i].free = CFG_FREE;
				irq_info->num_irq_remain++;
				if (irq_info->num_irq_remain > max_num_irq) {
					sdk_err(dev->dev_hdl, "Find target,but over range\n");
					mutex_unlock(&irq_info->irq_mutex);
					return;
				}
				break;
			}
		}
	}

	if (i >= max_num_irq)
		sdk_warn(dev->dev_hdl, "Irq %d don`t need to free\n", irq_id);

	mutex_unlock(&irq_info->irq_mutex);
}

int init_cfg_mgmt(struct hifc_hwdev *dev)
{
	int err;
	struct cfg_mgmt_info *cfg_mgmt;

	cfg_mgmt = kzalloc(sizeof(*cfg_mgmt), GFP_KERNEL);
	if (!cfg_mgmt)
		return -ENOMEM;

	dev->cfg_mgmt = cfg_mgmt;
	cfg_mgmt->hwdev = dev;

	err = cfg_init_eq(dev);
	if (err) {
		sdk_err(dev->dev_hdl, "Failed to init cfg event queue, err: %d\n",
			err);
		goto free_mgmt_mem;
	}

	err = cfg_init_interrupt(dev);
	if (err) {
		sdk_err(dev->dev_hdl, "Failed to init cfg interrupt, err: %d\n",
			err);
		goto free_eq_mem;
	}

	err = cfg_enable_interrupt(dev);
	if (err) {
		sdk_err(dev->dev_hdl, "Failed to enable cfg interrupt, err: %d\n",
			err);
		goto free_interrupt_mem;
	}

	return 0;

free_interrupt_mem:
	kfree(cfg_mgmt->irq_param_info.alloc_info);

	cfg_mgmt->irq_param_info.alloc_info = NULL;

free_eq_mem:
	kfree(cfg_mgmt->eq_info.eq);

	cfg_mgmt->eq_info.eq = NULL;

free_mgmt_mem:
	kfree(cfg_mgmt);
	return err;
}

void free_cfg_mgmt(struct hifc_hwdev *dev)
{
	struct cfg_mgmt_info *cfg_mgmt = dev->cfg_mgmt;

	/* if the allocated resource were recycled */
	if (cfg_mgmt->irq_param_info.num_irq_remain !=
	    cfg_mgmt->irq_param_info.num_total ||
	    cfg_mgmt->eq_info.num_ceq_remain != cfg_mgmt->eq_info.num_ceq)
		sdk_err(dev->dev_hdl, "Can't reclaim all irq and event queue, please check\n");

	switch (cfg_mgmt->svc_cap.interrupt_type) {
	case INTR_TYPE_MSIX:
		pci_disable_msix(dev->pcidev_hdl);
		break;

	case INTR_TYPE_MSI:
		pci_disable_msi(dev->pcidev_hdl);
		break;

	case INTR_TYPE_INT:
	default:
		break;
	}

	kfree(cfg_mgmt->irq_param_info.alloc_info);
	cfg_mgmt->irq_param_info.alloc_info = NULL;

	kfree(cfg_mgmt->eq_info.eq);
	cfg_mgmt->eq_info.eq = NULL;

	kfree(cfg_mgmt);
}

int init_capability(struct hifc_hwdev *dev)
{
	int err;
	enum func_type type = HIFC_FUNC_TYPE(dev);
	struct cfg_mgmt_info *cfg_mgmt = dev->cfg_mgmt;

	cfg_mgmt->svc_cap.timer_en = 1;
	cfg_mgmt->svc_cap.test_xid_alloc_mode = 1;
	cfg_mgmt->svc_cap.test_gpa_check_enable = 1;

	err = get_cap_from_fw(dev, type);
	if (err) {
		sdk_err(dev->dev_hdl, "Failed to get PF/PPF capability\n");
		return err;
	}

	fc_param_fix(dev);

	if (dev->cfg_mgmt->svc_cap.force_up)
		dev->feature_cap |= HIFC_FUNC_FORCE_LINK_UP;

	sdk_info(dev->dev_hdl, "Init capability success\n");
	return 0;
}

void free_capability(struct hifc_hwdev *dev)
{
	sdk_info(dev->dev_hdl, "Free capability success");
}

bool hifc_support_fc(void *hwdev, struct fc_service_cap *cap)
{
	struct hifc_hwdev *dev = hwdev;

	if (!hwdev)
		return false;

	if (cap)
		memcpy(cap, &dev->cfg_mgmt->svc_cap.fc_cap, sizeof(*cap));

	return true;
}

u8 hifc_host_oq_id_mask(void *hwdev)
{
	struct hifc_hwdev *dev = hwdev;

	if (!dev) {
		pr_err("Hwdev pointer is NULL for getting host oq id mask\n");
		return 0;
	}
	return dev->cfg_mgmt->svc_cap.host_oq_id_mask_val;
}

u16 hifc_func_max_qnum(void *hwdev)
{
	struct hifc_hwdev *dev = hwdev;

	if (!dev) {
		pr_err("Hwdev pointer is NULL for getting function max queue number\n");
		return 0;
	}
	return dev->cfg_mgmt->svc_cap.max_sqs;
}

/* Caller should ensure atomicity when calling this function */
int hifc_stateful_init(void *hwdev)
{
	struct hifc_hwdev *dev = hwdev;
	int err;

	if (!dev)
		return -EINVAL;

	if (dev->statufull_ref_cnt++)
		return 0;

	err = cqm_init(dev);
	if (err) {
		sdk_err(dev->dev_hdl, "Failed to init cqm, err: %d\n", err);
		goto init_cqm_err;
	}

	sdk_info(dev->dev_hdl, "Initialize statefull resource success\n");

	return 0;

init_cqm_err:

	dev->statufull_ref_cnt--;

	return err;
}

/* Caller should ensure atomicity when calling this function */
void hifc_stateful_deinit(void *hwdev)
{
	struct hifc_hwdev *dev = hwdev;

	if (!dev || !dev->statufull_ref_cnt)
		return;

	if (--dev->statufull_ref_cnt)
		return;

	cqm_uninit(hwdev);

	sdk_info(dev->dev_hdl, "Clear statefull resource success\n");
}

bool hifc_is_hwdev_mod_inited(void *hwdev, enum hifc_hwdev_init_state state)
{
	struct hifc_hwdev *dev = hwdev;

	if (!hwdev || state >= HIFC_HWDEV_MAX_INVAL_INITED)
		return false;

	return !!test_bit(state, &dev->func_state);
}

static int hifc_os_dep_init(struct hifc_hwdev *hwdev)
{
	hwdev->workq = create_singlethread_workqueue(HIFC_HW_WQ_NAME);
	if (!hwdev->workq) {
		sdk_err(hwdev->dev_hdl, "Failed to initialize hardware workqueue\n");
		return -EFAULT;
	}

	sema_init(&hwdev->fault_list_sem, 1);

	return 0;
}

static void hifc_os_dep_deinit(struct hifc_hwdev *hwdev)
{
	destroy_workqueue(hwdev->workq);
}

static int __hilink_phy_init(struct hifc_hwdev *hwdev)
{
	int err;

	err = hifc_phy_init_status_judge(hwdev);
	if (err) {
		sdk_info(hwdev->dev_hdl, "Phy init failed\n");
		return err;
	}

	return 0;
}

static int init_hwdev_and_hwif(struct hifc_init_para *para)
{
	struct hifc_hwdev *hwdev;
	int err;

	if (!(*para->hwdev)) {
		hwdev = kzalloc(sizeof(*hwdev), GFP_KERNEL);
		if (!hwdev)
			return -ENOMEM;

		*para->hwdev = hwdev;
		hwdev->adapter_hdl = para->adapter_hdl;
		hwdev->pcidev_hdl = para->pcidev_hdl;
		hwdev->dev_hdl = para->dev_hdl;
		hwdev->chip_node = para->chip_node;

		hwdev->chip_fault_stats = vzalloc(HIFC_CHIP_FAULT_SIZE);
		if (!hwdev->chip_fault_stats)
			goto alloc_chip_fault_stats_err;

		err = hifc_init_hwif(hwdev, para->cfg_reg_base,
				     para->intr_reg_base,
				     para->db_base_phy, para->db_base,
				     para->dwqe_mapping);
		if (err) {
			sdk_err(hwdev->dev_hdl, "Failed to init hwif\n");
			goto init_hwif_err;
		}
	}

	return 0;

init_hwif_err:
	vfree(hwdev->chip_fault_stats);

alloc_chip_fault_stats_err:

	*para->hwdev = NULL;

	return -EFAULT;
}

static void deinit_hwdev_and_hwif(struct hifc_hwdev *hwdev)
{
	hifc_free_hwif(hwdev);

	vfree(hwdev->chip_fault_stats);

	kfree(hwdev);
}

static int init_hw_cfg(struct hifc_hwdev *hwdev)
{
	int err;

	err = init_capability(hwdev);
	if (err) {
		sdk_err(hwdev->dev_hdl, "Failed to init capability\n");
		return err;
	}

	err = __hilink_phy_init(hwdev);
	if (err)
		goto hilink_phy_init_err;

	return 0;

hilink_phy_init_err:
	free_capability(hwdev);

	return err;
}

/* Return:
 * 0: all success
 * >0: partitial success
 * <0: all failed
 */
int hifc_init_hwdev(struct hifc_init_para *para)
{
	struct hifc_hwdev *hwdev;
	int err;

	err = init_hwdev_and_hwif(para);
	if (err)
		return err;

	hwdev = *para->hwdev;

	/* detect slave host according to BAR reg */
	hwdev->feature_cap = HIFC_FUNC_MGMT | HIFC_FUNC_PORT |
		HIFC_FUNC_SUPP_RATE_LIMIT | HIFC_FUNC_SUPP_DFX_REG |
		HIFC_FUNC_SUPP_RX_MODE | HIFC_FUNC_SUPP_SET_VF_MAC_VLAN |
		HIFC_FUNC_SUPP_CHANGE_MAC;

	err = hifc_os_dep_init(hwdev);
	if (err) {
		sdk_err(hwdev->dev_hdl, "Failed to init os dependent\n");
		goto os_dep_init_err;
	}

	hifc_set_chip_present(hwdev);
	hifc_init_heartbeat(hwdev);

	err = init_cfg_mgmt(hwdev);
	if (err) {
		sdk_err(hwdev->dev_hdl, "Failed to init config mgmt\n");
		goto init_cfg_mgmt_err;
	}

	err = hifc_init_comm_ch(hwdev);
	if (err) {
		if (!(hwdev->func_state & HIFC_HWDEV_INIT_MODES_MASK)) {
			sdk_err(hwdev->dev_hdl, "Failed to init communication channel\n");
			goto init_comm_ch_err;
		} else {
			sdk_err(hwdev->dev_hdl, "Init communication channel partitail failed\n");
			return hwdev->func_state & HIFC_HWDEV_INIT_MODES_MASK;
		}
	}

	err = init_hw_cfg(hwdev);
	if (err) {
		sdk_err(hwdev->dev_hdl, "Failed to init hardware config\n");
		goto init_hw_cfg_err;
	}

	set_bit(HIFC_HWDEV_ALL_INITED, &hwdev->func_state);

	sdk_info(hwdev->dev_hdl, "Init hwdev success\n");

	return 0;

init_hw_cfg_err:
	return (hwdev->func_state & HIFC_HWDEV_INIT_MODES_MASK);

init_comm_ch_err:
	free_cfg_mgmt(hwdev);

init_cfg_mgmt_err:
	hifc_destroy_heartbeat(hwdev);
	hifc_os_dep_deinit(hwdev);

os_dep_init_err:
	deinit_hwdev_and_hwif(hwdev);
	*para->hwdev = NULL;

	return -EFAULT;
}

void hifc_free_hwdev(void *hwdev)
{
	struct hifc_hwdev *dev = hwdev;
	enum hifc_hwdev_init_state state = HIFC_HWDEV_ALL_INITED;
	int flag = 0;

	if (!hwdev)
		return;

	if (test_bit(HIFC_HWDEV_ALL_INITED, &dev->func_state)) {
		clear_bit(HIFC_HWDEV_ALL_INITED, &dev->func_state);

		/* BM slave function not need to exec rx_tx_flush */

		hifc_func_rx_tx_flush(hwdev);

		free_capability(dev);
	}
	while (state > HIFC_HWDEV_NONE_INITED) {
		if (test_bit(state, &dev->func_state)) {
			flag = 1;
			break;
		}
		state--;
	}
	if (flag) {
		hifc_uninit_comm_ch(dev);
		free_cfg_mgmt(dev);
		hifc_destroy_heartbeat(dev);
		hifc_os_dep_deinit(dev);
	}
	clear_bit(HIFC_HWDEV_NONE_INITED, &dev->func_state);

	deinit_hwdev_and_hwif(dev);
}

u64 hifc_get_func_feature_cap(void *hwdev)
{
	struct hifc_hwdev *dev = hwdev;

	if (!dev) {
		pr_err("Hwdev pointer is NULL for getting function feature capability\n");
		return 0;
	}

	return dev->feature_cap;
}
