/* SPDX-License-Identifier: GPL-2.0 */
/* Huawei Hifc PCI Express Linux driver
 * Copyright(c) 2017 Huawei Technologies Co., Ltd
 *
 */

#ifndef HIFC_LLD_H_
#define HIFC_LLD_H_
#include "unf_common.h"
#define HIFC_PCI_VENDOR_ID   (0x19e5)
#define HIFC_DRV_NAME        "hifc_sdk"
#define HIFC_CHIP_NAME       "hifc"
#define HIFC_DRV_VERSION     UNF_FC_VERSION

struct hifc_lld_dev {
	struct pci_dev *pdev;
	void *hwdev;
};

extern struct list_head g_hinic_chip_list;

/* Structure pcidev private*/
struct hifc_pcidev {
	struct pci_dev *pcidev;
	void *hwdev;
	struct card_node *chip_node;
	struct hifc_lld_dev lld_dev;
	/* Record the service object address,
	 * such as hifc_dev and toe_dev, fc_dev
	 */
	void *uld_dev;
	/* Record the service object name */
	char uld_dev_name[IFNAMSIZ];
	/* It is a the global variable for driver to manage
	 * all function device linked list
	 */
	struct list_head node;

	void __iomem *cfg_reg_base;
	void __iomem *intr_reg_base;
	u64 db_base_phy;
	void __iomem *db_base;

#if defined(__aarch64__)
	void __iomem *dwqe_mapping;
#else
	struct io_mapping *dwqe_mapping;
#endif
	/* lock for attach/detach uld */
	struct mutex pdev_mutex;

	u32 init_state;
	/* setted when uld driver processing event */
	unsigned long state;
	struct pci_device_id id;

	unsigned long flag;
};

enum {
	HIFC_FUNC_IN_REMOVE = BIT(0),
	HIFC_FUNC_PRB_ERR = BIT(1),
	HIFC_FUNC_PRB_DELAY = BIT(2),
};

enum hifc_init_state {
	HIFC_INIT_STATE_NONE,
	HIFC_INIT_STATE_PCI_INITED,
	HIFC_INIT_STATE_HW_IF_INITED,
	HIFC_INIT_STATE_HW_PART_INITED,
	HIFC_INIT_STATE_HWDEV_INITED,
	HIFC_INIT_STATE_DBGTOOL_INITED,
	HIFC_INIT_STATE_ALL_INITED,
};

void lld_dev_put(void);
void lld_dev_hold(void);

#endif
