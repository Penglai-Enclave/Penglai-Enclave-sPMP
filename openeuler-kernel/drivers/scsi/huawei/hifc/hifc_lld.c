// SPDX-License-Identifier: GPL-2.0
/* Huawei Hifc PCI Express Linux driver
 * Copyright(c) 2017 Huawei Technologies Co., Ltd
 *
 */
#define pr_fmt(fmt) KBUILD_MODNAME ": [COMM]" fmt

#include <linux/kernel.h>
#include <linux/pci.h>
#include <linux/device.h>
#include <linux/module.h>
#include <linux/io-mapping.h>
#include <linux/interrupt.h>
#include <linux/inetdevice.h>
#include <net/addrconf.h>
#include <linux/time.h>
#include <linux/timex.h>
#include <linux/rtc.h>
#include <linux/aer.h>
#include <linux/debugfs.h>

#include "hifc_knl_adp.h"
#include "hifc_hw.h"
#include "hifc_hwif.h"
#include "hifc_api_cmd.h"
#include "hifc_mgmt.h"
#include "hifc_lld.h"
#include "hifc_dbgtool_knl.h"
#include "hifc_tool.h"

#define HIFC_PCI_CFG_REG_BAR           0
#define HIFC_PCI_INTR_REG_BAR          2
#define HIFC_PCI_DB_BAR                4
#define HIFC_SECOND_BASE               1000
#define HIFC_SYNC_YEAR_OFFSET          1900
#define HIFC_SYNC_MONTH_OFFSET         1

#define HIFC_DRV_DESC "Huawei(R) Intelligent Network Interface Card Driver"
#define HIFCVF_DRV_DESC "Huawei(R) Intelligent Virtual Function Network Driver"

MODULE_AUTHOR("Huawei Technologies CO., Ltd");
MODULE_DESCRIPTION(HIFC_DRV_DESC);
MODULE_VERSION(HIFC_DRV_VERSION);
MODULE_LICENSE("GPL");

#define HIFC_EVENT_PROCESS_TIMEOUT	10000

#define FIND_BIT(num, n)        (((num) & (1UL << (n))) ? 1 : 0)
#define SET_BIT(num, n)         ((num) | (1UL << (n)))
#define CLEAR_BIT(num, n)       ((num) & (~(1UL << (n))))

#define MAX_CARD_ID             64
static u64 card_bit_map;
LIST_HEAD(g_hinic_chip_list);

enum hifc_lld_status {
	HIFC_NODE_CHANGE = BIT(0),
};

struct hifc_lld_lock {
	/* lock for chip list */
	struct mutex        lld_mutex;
	unsigned long       status;
	atomic_t            dev_ref_cnt;
};

struct hifc_lld_lock g_lld_lock;

#define WAIT_LLD_DEV_HOLD_TIMEOUT        (10 * 60 * 1000) /* 10minutes */
#define WAIT_LLD_DEV_NODE_CHANGED        (10 * 60 * 1000) /* 10minutes */
#define WAIT_LLD_DEV_REF_CNT_EMPTY       (2 * 60 * 1000)  /* 2minutes */

/* node in chip_node will changed, tools or driver can't get node
 * during this situation
 */
static void lld_lock_chip_node(void)
{
	u32 loop_cnt;

	mutex_lock(&g_lld_lock.lld_mutex);

	loop_cnt = 0;
	while (loop_cnt < WAIT_LLD_DEV_NODE_CHANGED) {
		if (!test_and_set_bit(HIFC_NODE_CHANGE, &g_lld_lock.status))
			break;

		loop_cnt++;

		if (loop_cnt % 10000 == 0)
			pr_warn("Wait for lld node change complete for %us\n",
				loop_cnt / 1000);

		usleep_range(900, 1000);
	}

	if (loop_cnt == WAIT_LLD_DEV_NODE_CHANGED)
		pr_warn("Wait for lld node change complete timeout when try to get lld lock\n");

	loop_cnt = 0;
	while (loop_cnt < WAIT_LLD_DEV_REF_CNT_EMPTY) {
		if (!atomic_read(&g_lld_lock.dev_ref_cnt))
			break;

		loop_cnt++;

		if (loop_cnt % 10000 == 0)
			pr_warn("Wait for lld dev unused for %us, reference count: %d\n",
				loop_cnt / 1000,
				atomic_read(&g_lld_lock.dev_ref_cnt));

		usleep_range(900, 1000);
	}

	if (loop_cnt == WAIT_LLD_DEV_REF_CNT_EMPTY)
		pr_warn("Wait for lld dev unused timeout\n");

	mutex_unlock(&g_lld_lock.lld_mutex);
}

static void lld_unlock_chip_node(void)
{
	clear_bit(HIFC_NODE_CHANGE, &g_lld_lock.status);
}

/* When tools or other drivers want to get node of chip_node, use this function
 * to prevent node be freed
 */
void lld_dev_hold(void)
{
	u32 loop_cnt = 0;

	/* ensure there have not any chip node in changing */
	mutex_lock(&g_lld_lock.lld_mutex);

	while (loop_cnt < WAIT_LLD_DEV_HOLD_TIMEOUT) {
		if (!test_bit(HIFC_NODE_CHANGE, &g_lld_lock.status))
			break;

		loop_cnt++;

		if (loop_cnt % 10000 == 0)
			pr_warn("Wait lld node change complete for %us\n",
				loop_cnt / 1000);

		usleep_range(900, 1000);
	}

	if (loop_cnt == WAIT_LLD_DEV_HOLD_TIMEOUT)
		pr_warn("Wait lld node change complete timeout when try to hode lld dev\n");

	atomic_inc(&g_lld_lock.dev_ref_cnt);

	mutex_unlock(&g_lld_lock.lld_mutex);
}

void lld_dev_put(void)
{
	atomic_dec(&g_lld_lock.dev_ref_cnt);
}

static void hifc_lld_lock_init(void)
{
	mutex_init(&g_lld_lock.lld_mutex);
	atomic_set(&g_lld_lock.dev_ref_cnt, 0);
}

extern int hifc_probe(struct hifc_lld_dev *lld_dev,
		      void **uld_dev, char *uld_dev_name);

static int attach_uld(struct hifc_pcidev *dev)
{
	void *uld_dev = NULL;

	int err;

	mutex_lock(&dev->pdev_mutex);

	if (dev->init_state < HIFC_INIT_STATE_HWDEV_INITED) {
		sdk_err(&dev->pcidev->dev, "SDK init failed, can not attach uld\n");
		err = -EFAULT;
		goto out_unlock;
	}

	err = hifc_stateful_init(dev->hwdev);
	if (err)
		goto out_unlock;

	err = hifc_probe(&dev->lld_dev, &uld_dev, dev->uld_dev_name);
	if (err || !uld_dev) {
		sdk_err(&dev->pcidev->dev,
			"Failed to add object for driver to pcie device\n");
		goto probe_failed;
	}

	dev->uld_dev = uld_dev;
	mutex_unlock(&dev->pdev_mutex);

	sdk_info(&dev->pcidev->dev,
		 "Attach  driver to pcie device succeed\n");
	return 0;

probe_failed:
	hifc_stateful_deinit(dev->hwdev);
out_unlock:
	mutex_unlock(&dev->pdev_mutex);

	return err;
}

extern void hifc_remove(struct hifc_lld_dev *lld_dev, void *uld_dev);

static void detach_uld(struct hifc_pcidev *dev)
{
	u32 cnt = 0;

	mutex_lock(&dev->pdev_mutex);

	while (cnt < HIFC_EVENT_PROCESS_TIMEOUT) {
		if (!test_and_set_bit(SERVICE_T_FC, &dev->state))
			break;
		usleep_range(900, 1000);
		cnt++;
	}

	hifc_remove(&dev->lld_dev, dev->uld_dev);
	dev->uld_dev = NULL;
	hifc_stateful_deinit(dev->hwdev);
	if (cnt < HIFC_EVENT_PROCESS_TIMEOUT)
		clear_bit(SERVICE_T_FC, &dev->state);

	sdk_info(&dev->pcidev->dev,
		 "Detach driver from pcie device succeed\n");
	mutex_unlock(&dev->pdev_mutex);
}

static void hifc_sync_time_to_fmw(struct hifc_pcidev *pdev_pri)
{
	struct tm tm = {0};
	u64 tv_msec;
	int err;

	tv_msec = ktime_to_ms(ktime_get_real());
	err = hifc_sync_time(pdev_pri->hwdev, tv_msec);
	if (err) {
		sdk_err(&pdev_pri->pcidev->dev, "Synchronize UTC time to firmware failed, errno:%d.\n",
			err);
	} else {
		time64_to_tm(tv_msec / MSEC_PER_SEC, 0, &tm);
		sdk_info(&pdev_pri->pcidev->dev, "Synchronize UTC time to firmware succeed. UTC time %ld-%02d-%02d %02d:%02d:%02d.\n",
			 tm.tm_year + HIFC_SYNC_YEAR_OFFSET,
			 tm.tm_mon + HIFC_SYNC_MONTH_OFFSET,
			 tm.tm_mday, tm.tm_hour,
			 tm.tm_min, tm.tm_sec);
	}
}

#define MAX_VER_FIELD_LEN        4
#define MAX_VER_SPLIT_NUM        4

struct mctp_hdr {
	u16        resp_code;
	u16        reason_code;
	u32        manufacture_id;

	u8        cmd_rsvd;
	u8        major_cmd;
	u8        sub_cmd;
	u8        spc_field;
};

struct mctp_bdf_info {
	struct mctp_hdr hdr; /* spc_field: pf index */
	u8        rsvd;
	u8        bus;
	u8        device;
	u8        function;
};

static void __mctp_set_hdr(struct mctp_hdr *hdr,
			   struct hifc_mctp_host_info *mctp_info)
{
	u32 manufacture_id = 0x07DB;

	hdr->cmd_rsvd = 0;
	hdr->major_cmd = mctp_info->major_cmd;
	hdr->sub_cmd = mctp_info->sub_cmd;
	hdr->manufacture_id = cpu_to_be32(manufacture_id);
	hdr->resp_code = cpu_to_be16(hdr->resp_code);
	hdr->reason_code = cpu_to_be16(hdr->reason_code);
}

static void __mctp_get_bdf(struct hifc_pcidev *pci_adapter,
			   struct hifc_mctp_host_info *mctp_info)
{
	struct pci_dev *pdev = pci_adapter->pcidev;
	struct mctp_bdf_info *bdf_info = mctp_info->data;

	bdf_info->bus = pdev->bus->number;
	bdf_info->device = (u8)(pdev->devfn >> 3);    /* 5bits in devfn */
	bdf_info->function = (u8)(pdev->devfn & 0x7); /* 3bits in devfn */

	memset(&bdf_info->hdr, 0, sizeof(bdf_info->hdr));
	__mctp_set_hdr(&bdf_info->hdr, mctp_info);
	bdf_info->hdr.spc_field =
		(u8)hifc_global_func_id_hw(pci_adapter->hwdev);

	mctp_info->data_len = sizeof(*bdf_info);
}

#define MCTP_PUBLIC_SUB_CMD_BDF        0x1

static void __mctp_get_host_info(struct hifc_pcidev *dev,
				 struct hifc_mctp_host_info *mctp_info)
{
#define COMMAND_UNSUPPORTED 3
	struct mctp_hdr *hdr;

	if (((((u16)mctp_info->major_cmd) << 8) | mctp_info->sub_cmd) ==
	    MCTP_PUBLIC_SUB_CMD_BDF) {
		__mctp_get_bdf(dev, mctp_info);
	} else {
		hdr = mctp_info->data;
		hdr->reason_code = COMMAND_UNSUPPORTED;
		__mctp_set_hdr(hdr, mctp_info);
		mctp_info->data_len = sizeof(*hdr);
	}
}

void *hifc_get_ppf_hwdev_by_pdev(struct pci_dev *pdev)
{
	struct hifc_pcidev *pci_adapter;
	struct card_node *chip_node;
	struct hifc_pcidev *dev;

	if (!pdev)
		return NULL;

	pci_adapter = pci_get_drvdata(pdev);
	if (!pci_adapter)
		return NULL;

	chip_node = pci_adapter->chip_node;
	lld_dev_hold();
	list_for_each_entry(dev, &chip_node->func_list, node) {
		if (dev->hwdev && hifc_func_type(dev->hwdev) == TYPE_PPF) {
			lld_dev_put();
			return dev->hwdev;
		}
	}
	lld_dev_put();

	return NULL;
}

void hifc_event(struct hifc_lld_dev *lld_dev, void *uld_dev,
		struct hifc_event_info *event);

void hifc_event_process(void *adapter, struct hifc_event_info *event)
{
	struct hifc_pcidev *dev = adapter;

	if (event->type == HIFC_EVENT_FMW_ACT_NTC)
		return hifc_sync_time_to_fmw(dev);
	else if (event->type == HIFC_EVENT_MCTP_GET_HOST_INFO)
		return __mctp_get_host_info(dev, &event->mctp_info);

	if (test_and_set_bit(SERVICE_T_FC, &dev->state)) {
		sdk_warn(&dev->pcidev->dev, "Event: 0x%x can't handler is in detach\n",
			 event->type);
		return;
	}

	hifc_event(&dev->lld_dev, dev->uld_dev, event);
	clear_bit(SERVICE_T_FC, &dev->state);
}

static int mapping_bar(struct pci_dev *pdev, struct hifc_pcidev *pci_adapter)
{
	u64 dwqe_addr;

	pci_adapter->cfg_reg_base = pci_ioremap_bar(pdev, HIFC_PCI_CFG_REG_BAR);
	if (!pci_adapter->cfg_reg_base) {
		sdk_err(&pci_adapter->pcidev->dev,
			"Failed to map configuration regs\n");
		return -ENOMEM;
	}

	pci_adapter->intr_reg_base = pci_ioremap_bar(pdev,
						     HIFC_PCI_INTR_REG_BAR);
	if (!pci_adapter->intr_reg_base) {
		sdk_err(&pci_adapter->pcidev->dev,
			"Failed to map interrupt regs\n");
		goto map_intr_bar_err;
	}

	pci_adapter->db_base_phy = pci_resource_start(pdev, HIFC_PCI_DB_BAR);
	pci_adapter->db_base = ioremap(pci_adapter->db_base_phy,
				       HIFC_DB_DWQE_SIZE);
	if (!pci_adapter->db_base) {
		sdk_err(&pci_adapter->pcidev->dev,
			"Failed to map doorbell regs\n");
		goto map_db_err;
	}

	dwqe_addr = pci_adapter->db_base_phy + HIFC_DB_DWQE_SIZE;

#if defined(__aarch64__)
	/* arm do not support call ioremap_wc() */
	pci_adapter->dwqe_mapping = __ioremap(dwqe_addr, HIFC_DB_DWQE_SIZE,
					      __pgprot(PROT_DEVICE_nGnRnE));
#else
	pci_adapter->dwqe_mapping = io_mapping_create_wc(dwqe_addr,
							 HIFC_DB_DWQE_SIZE);

#endif  /* end of "defined(__aarch64__)" */
	if (!pci_adapter->dwqe_mapping) {
		sdk_err(&pci_adapter->pcidev->dev, "Failed to io_mapping_create_wc\n");
		goto mapping_dwqe_err;
	}

	return 0;

mapping_dwqe_err:
	iounmap(pci_adapter->db_base);

map_db_err:
	iounmap(pci_adapter->intr_reg_base);

map_intr_bar_err:
	iounmap(pci_adapter->cfg_reg_base);

	return -ENOMEM;
}

static void unmapping_bar(struct hifc_pcidev *pci_adapter)
{
#if defined(__aarch64__)
	iounmap(pci_adapter->dwqe_mapping);
#else
	io_mapping_free(pci_adapter->dwqe_mapping);
#endif /* end of "defined(__aarch64__)" */

	iounmap(pci_adapter->db_base);
	iounmap(pci_adapter->intr_reg_base);
	iounmap(pci_adapter->cfg_reg_base);
}

static int alloc_chip_node(struct hifc_pcidev *pci_adapter)
{
	struct card_node *chip_node;
	unsigned char i;
	unsigned char parent_bus_number = 0;

	if  (!pci_is_root_bus(pci_adapter->pcidev->bus))
		parent_bus_number = pci_adapter->pcidev->bus->parent->number;

	if (parent_bus_number != 0) {
		list_for_each_entry(chip_node, &g_hinic_chip_list, node) {
			if (chip_node->dp_bus_num == parent_bus_number) {
				pci_adapter->chip_node = chip_node;
				return 0;
			}
		}
	}

	for (i = 0; i < MAX_CARD_ID; i++) {
		if (!FIND_BIT(card_bit_map, i)) {
			card_bit_map = (u64)SET_BIT(card_bit_map, i);
			break;
		}
	}

	if (i == MAX_CARD_ID) {
		sdk_err(&pci_adapter->pcidev->dev,
			"Failed to alloc card id\n");
		return -EFAULT;
	}

	chip_node = kzalloc(sizeof(*chip_node), GFP_KERNEL);
	if (!chip_node) {
		card_bit_map = CLEAR_BIT(card_bit_map, i);
		sdk_err(&pci_adapter->pcidev->dev,
			"Failed to alloc chip node\n");
		return -ENOMEM;
	}

	chip_node->dbgtool_attr_file.name = kzalloc(IFNAMSIZ, GFP_KERNEL);
	if (!(chip_node->dbgtool_attr_file.name)) {
		kfree(chip_node);
		card_bit_map = CLEAR_BIT(card_bit_map, i);
		sdk_err(&pci_adapter->pcidev->dev,
			"Failed to alloc dbgtool attr file name\n");
		return -ENOMEM;
	}

	/* parent bus number */
	chip_node->dp_bus_num = parent_bus_number;

	snprintf(chip_node->chip_name, IFNAMSIZ, "%s%d", HIFC_CHIP_NAME, i);
	snprintf((char *)chip_node->dbgtool_attr_file.name,
		 IFNAMSIZ, "%s%d", HIFC_CHIP_NAME, i);
	sdk_info(&pci_adapter->pcidev->dev,
		 "Add new chip %s to global list succeed\n",
		 chip_node->chip_name);

	list_add_tail(&chip_node->node, &g_hinic_chip_list);

	INIT_LIST_HEAD(&chip_node->func_list);
	pci_adapter->chip_node = chip_node;

	mutex_init(&chip_node->sfp_mutex);

	return 0;
}

static void free_chip_node(struct hifc_pcidev *pci_adapter)
{
	struct card_node *chip_node = pci_adapter->chip_node;
	u32 id;
	int err;

	if (list_empty(&chip_node->func_list)) {
		list_del(&chip_node->node);
		sdk_info(&pci_adapter->pcidev->dev,
			 "Delete chip %s from global list succeed\n",
			 chip_node->chip_name);
		err = sscanf(chip_node->chip_name, HIFC_CHIP_NAME "%u", &id);
		if (err < 0)
			sdk_err(&pci_adapter->pcidev->dev, "Failed to get hifc id\n");

		card_bit_map = CLEAR_BIT(card_bit_map, id);

		kfree(chip_node->dbgtool_attr_file.name);
		kfree(chip_node);
	}
}

static int config_pci_dma_mask(struct pci_dev *pdev)
{
	int err;

	err = pci_set_dma_mask(pdev, DMA_BIT_MASK(64));
	if (err) {
		sdk_warn(&pdev->dev, "Couldn't set 64-bit DMA mask\n");
		err = pci_set_dma_mask(pdev, DMA_BIT_MASK(32));
		if (err) {
			sdk_err(&pdev->dev, "Failed to set DMA mask\n");
			return err;
		}
	}

	err = pci_set_consistent_dma_mask(pdev, DMA_BIT_MASK(64));
	if (err) {
		sdk_warn(&pdev->dev,
			 "Couldn't set 64-bit coherent DMA mask\n");
		err = pci_set_consistent_dma_mask(pdev, DMA_BIT_MASK(32));
		if (err) {
			sdk_err(&pdev->dev,
				"Failed to set coherent DMA mask\n");
			return err;
		}
	}

	return 0;
}

static int hifc_pci_init(struct pci_dev *pdev)
{
	struct hifc_pcidev *pci_adapter = NULL;
	int err;

	pci_adapter = kzalloc(sizeof(*pci_adapter), GFP_KERNEL);
	if (!pci_adapter) {
		sdk_err(&pdev->dev,
			"Failed to alloc pci device adapter\n");
		return -ENOMEM;
	}
	pci_adapter->pcidev = pdev;
	mutex_init(&pci_adapter->pdev_mutex);

	pci_set_drvdata(pdev, pci_adapter);

	err = pci_enable_device(pdev);
	if (err) {
		sdk_err(&pdev->dev, "Failed to enable PCI device\n");
		goto pci_enable_err;
	}

	err = pci_request_regions(pdev, HIFC_DRV_NAME);
	if (err) {
		sdk_err(&pdev->dev, "Failed to request regions\n");
		goto pci_regions_err;
	}

	pci_enable_pcie_error_reporting(pdev);

	pci_set_master(pdev);

	err = config_pci_dma_mask(pdev);
	if (err)
		goto dma_mask_err;

	return 0;

dma_mask_err:
	pci_clear_master(pdev);
	pci_release_regions(pdev);

pci_regions_err:
	pci_disable_device(pdev);

pci_enable_err:
	pci_set_drvdata(pdev, NULL);
	kfree(pci_adapter);

	return err;
}

static void hifc_pci_deinit(struct pci_dev *pdev)
{
	struct hifc_pcidev *pci_adapter = pci_get_drvdata(pdev);

	pci_clear_master(pdev);
	pci_release_regions(pdev);
	pci_disable_pcie_error_reporting(pdev);
	pci_disable_device(pdev);
	pci_set_drvdata(pdev, NULL);
	kfree(pci_adapter);
}

static int hifc_func_init(struct pci_dev *pdev,
			  struct hifc_pcidev *pci_adapter)
{
	struct hifc_init_para init_para;

	int err;

	init_para.adapter_hdl = pci_adapter;
	init_para.pcidev_hdl = pdev;
	init_para.dev_hdl = &pdev->dev;
	init_para.cfg_reg_base = pci_adapter->cfg_reg_base;
	init_para.intr_reg_base = pci_adapter->intr_reg_base;
	init_para.db_base = pci_adapter->db_base;
	init_para.db_base_phy = pci_adapter->db_base_phy;
	init_para.dwqe_mapping = pci_adapter->dwqe_mapping;
	init_para.hwdev = &pci_adapter->hwdev;
	init_para.chip_node = pci_adapter->chip_node;
	init_para.ppf_hwdev = hifc_get_ppf_hwdev_by_pdev(pdev);
	err = hifc_init_hwdev(&init_para);
	if (err) {
		pci_adapter->hwdev = NULL;
		sdk_err(&pdev->dev, "Failed to initialize hardware device\n");
		return -EFAULT;
	}

	pci_adapter->init_state = HIFC_INIT_STATE_HWDEV_INITED;

	pci_adapter->lld_dev.pdev = pdev;
	pci_adapter->lld_dev.hwdev = pci_adapter->hwdev;

	hifc_event_register(pci_adapter->hwdev, pci_adapter,
			    hifc_event_process);

	hifc_sync_time_to_fmw(pci_adapter);

	lld_lock_chip_node();
	err = dbgtool_knl_init(pci_adapter->hwdev, pci_adapter->chip_node);
	if (err) {
		lld_unlock_chip_node();
		sdk_err(&pdev->dev, "Failed to initialize dbgtool\n");
		hifc_event_unregister(pci_adapter->hwdev);
		return err;
	}
	lld_unlock_chip_node();
	pci_adapter->init_state = HIFC_INIT_STATE_DBGTOOL_INITED;

	attach_uld(pci_adapter);

	sdk_info(&pdev->dev, "Pcie device probed\n");
	pci_adapter->init_state = HIFC_INIT_STATE_ALL_INITED;

	return 0;
}

static void hifc_func_deinit(struct pci_dev *pdev)
{
	struct hifc_pcidev *pci_adapter = pci_get_drvdata(pdev);

	/* When function deinit, disable mgmt initiative report events firstly,
	 * then flush mgmt work-queue.
	 */
	if (pci_adapter->init_state >= HIFC_INIT_STATE_ALL_INITED)
		detach_uld(pci_adapter);

	hifc_disable_mgmt_msg_report(pci_adapter->hwdev);
	if (pci_adapter->init_state >= HIFC_INIT_STATE_HW_PART_INITED)
		hifc_flush_mgmt_workq(pci_adapter->hwdev);

	hifc_set_func_deinit_flag(pci_adapter->hwdev);

	if (pci_adapter->init_state >= HIFC_INIT_STATE_DBGTOOL_INITED) {
		lld_lock_chip_node();
		dbgtool_knl_deinit(pci_adapter->hwdev, pci_adapter->chip_node);
		lld_unlock_chip_node();
		hifc_event_unregister(pci_adapter->hwdev);
	}

	if (pci_adapter->init_state >= HIFC_INIT_STATE_HW_IF_INITED) {
		/*Remove the current node from  node-list first,
		 * then it's safe to free hwdev
		 */
		lld_lock_chip_node();
		list_del(&pci_adapter->node);
		lld_unlock_chip_node();

		hifc_free_hwdev(pci_adapter->hwdev);
	}
}

static void remove_func(struct hifc_pcidev *pci_adapter)
{
	struct pci_dev *pdev = pci_adapter->pcidev;

	switch (pci_adapter->init_state) {
	case HIFC_INIT_STATE_ALL_INITED:
		/*lint -fallthrough*/

	case HIFC_INIT_STATE_DBGTOOL_INITED:
	case HIFC_INIT_STATE_HWDEV_INITED:
	case HIFC_INIT_STATE_HW_PART_INITED:
	case HIFC_INIT_STATE_HW_IF_INITED:
	case HIFC_INIT_STATE_PCI_INITED:
		set_bit(HIFC_FUNC_IN_REMOVE, &pci_adapter->flag);

		if (pci_adapter->init_state >= HIFC_INIT_STATE_HW_IF_INITED)
			hifc_func_deinit(pdev);

		lld_lock_chip_node();
		if (pci_adapter->init_state < HIFC_INIT_STATE_HW_IF_INITED)
			list_del(&pci_adapter->node);
		nictool_k_uninit();
		free_chip_node(pci_adapter);
		lld_unlock_chip_node();
		unmapping_bar(pci_adapter);
		hifc_pci_deinit(pdev);

		/*lint -fallthrough*/
		break;

	default:
		break;
	}
}

static void hifc_hwdev_remove(struct pci_dev *pdev)
{
	struct hifc_pcidev *pci_adapter = pci_get_drvdata(pdev);

	if (!pci_adapter)
		return;

	sdk_info(&pdev->dev, "Pcie device remove begin\n");

	if (pci_adapter->init_state >= HIFC_INIT_STATE_HW_IF_INITED)
		hifc_detect_hw_present(pci_adapter->hwdev);

	remove_func(pci_adapter);

	sdk_info(&pdev->dev, "Pcie device removed\n");
}

static int hifc_hwdev_probe(struct pci_dev *pdev,
			    const struct pci_device_id *id)
{
	struct hifc_pcidev *pci_adapter;
	int err;

	sdk_info(&pdev->dev, "Pcie device probe begin\n");

	err = hifc_pci_init(pdev);
	if (err)
		return err;

	pci_adapter = pci_get_drvdata(pdev);
	clear_bit(HIFC_FUNC_PRB_ERR, &pci_adapter->flag);
	clear_bit(HIFC_FUNC_PRB_DELAY, &pci_adapter->flag);
	err = mapping_bar(pdev, pci_adapter);
	if (err) {
		sdk_err(&pdev->dev, "Failed to map bar\n");
		goto map_bar_failed;
	}

	pci_adapter->id = *id;

	/* if chip information of pcie function exist,
	 * add the function into chip
	 */
	lld_lock_chip_node();
	err = alloc_chip_node(pci_adapter);
	if (err) {
		sdk_err(&pdev->dev,
			"Failed to add new chip node to global list\n");
		goto alloc_chip_node_fail;
	}
	err = nictool_k_init();
	if (err) {
		sdk_warn(&pdev->dev, "Failed to init nictool");
		goto init_nictool_err;
	}
	list_add_tail(&pci_adapter->node, &pci_adapter->chip_node->func_list);

	lld_unlock_chip_node();

	pci_adapter->init_state = HIFC_INIT_STATE_PCI_INITED;

	err = hifc_func_init(pdev, pci_adapter);
	if (err)
		goto func_init_err;

	return 0;

func_init_err:
	if (!test_bit(HIFC_FUNC_PRB_DELAY, &pci_adapter->flag))
		set_bit(HIFC_FUNC_PRB_ERR, &pci_adapter->flag);
	return 0;
init_nictool_err:
	free_chip_node(pci_adapter);
alloc_chip_node_fail:
	lld_unlock_chip_node();
	unmapping_bar(pci_adapter);

map_bar_failed:
	hifc_pci_deinit(pdev);

	sdk_err(&pdev->dev, "Pcie device probe failed\n");
	return err;
}

#define PCI_VENDOR_ID_HUAWEI        0x19e5
#define HIFC_DEV_ID_1822_8G         0x0212
#define HIFC_DEV_ID_1822_16G        0x0203
#define HIFC_DEV_ID_1822_32G        0x0202

/*lint -save -e133 -e10*/
static const struct pci_device_id hifc_pci_table[] = {
	{PCI_VDEVICE(HUAWEI, HIFC_DEV_ID_1822_8G), 0},
	{PCI_VDEVICE(HUAWEI, HIFC_DEV_ID_1822_16G), 0},
	{PCI_VDEVICE(HUAWEI, HIFC_DEV_ID_1822_32G), 0},
	{0, 0}
};

/*lint -restore*/
MODULE_DEVICE_TABLE(pci, hifc_pci_table);

static void hifc_shutdown(struct pci_dev *pdev)
{
	sdk_err(&pdev->dev, "Shutdown device\n");

	pci_disable_device(pdev);
}

static struct pci_driver hifc_driver = {
	.name          = HIFC_DRV_NAME,
	.id_table      = hifc_pci_table,
	.probe         = hifc_hwdev_probe,
	.remove        = hifc_hwdev_remove,
	.shutdown      = hifc_shutdown,
};

extern int hifc_init_module(void);
extern void hifc_exit_module(void);

static int __init hifc_lld_init(void)
{
	pr_info("%s - version %s\n", HIFC_DRV_DESC, HIFC_DRV_VERSION);

	hifc_lld_lock_init();

	hifc_init_module();

	return pci_register_driver(&hifc_driver);
}

static void __exit hifc_lld_exit(void)
{
	pci_unregister_driver(&hifc_driver);
	hifc_exit_module();
}

module_init(hifc_lld_init);
module_exit(hifc_lld_exit);
