// SPDX-License-Identifier: GPL-2.0
/* Huawei Hifc PCI Express Linux driver
 * Copyright(c) 2017 Huawei Technologies Co., Ltd
 *
 */
#define pr_fmt(fmt) KBUILD_MODNAME ": [COMM]" fmt

#include <linux/types.h>
#include <linux/pci.h>
#include <linux/delay.h>
#include <linux/module.h>
#include <linux/io-mapping.h>

#include "hifc_knl_adp.h"
#include "hifc_hw.h"
#include "hifc_hwdev.h"
#include "hifc_hwif.h"
#include "hifc_api_cmd.h"
#include "hifc_mgmt.h"
#include "hifc_eqs.h"

#define WAIT_HWIF_READY_TIMEOUT         10000
#define HIFC_SELFTEST_RESULT           0x883C

u32 hifc_hwif_read_reg(struct hifc_hwif *hwif, u32 reg)
{
	return be32_to_cpu(readl(hwif->cfg_regs_base + reg));
}

void hifc_hwif_write_reg(struct hifc_hwif *hwif, u32 reg, u32 val)
{
	writel(cpu_to_be32(val), hwif->cfg_regs_base + reg);
}

/**
 * hwif_ready - test if the HW initialization passed
 * @hwdev: the pointer to hw device
 * Return: 0 - success, negative - failure
 **/
static int hwif_ready(struct hifc_hwdev *hwdev)
{
	u32 addr, attr1;

	addr   = HIFC_CSR_FUNC_ATTR1_ADDR;
	attr1  = hifc_hwif_read_reg(hwdev->hwif, addr);

	if (attr1 == HIFC_PCIE_LINK_DOWN)
		return -EBUSY;

	if (!HIFC_AF1_GET(attr1, MGMT_INIT_STATUS))
		return -EBUSY;

	return 0;
}

static int wait_hwif_ready(struct hifc_hwdev *hwdev)
{
	ulong timeout = 0;

	do {
		if (!hwif_ready(hwdev))
			return 0;

		usleep_range(999, 1000);
		timeout++;
	} while (timeout <= WAIT_HWIF_READY_TIMEOUT);

	sdk_err(hwdev->dev_hdl, "Wait for hwif timeout\n");
	return -EBUSY;
}

/**
 * set_hwif_attr - set the attributes as members in hwif
 * @hwif: the hardware interface of a pci function device
 * @attr0: the first attribute that was read from the hw
 * @attr1: the second attribute that was read from the hw
 * @attr2: the third attribute that was read from the hw
 **/
static void set_hwif_attr(struct hifc_hwif *hwif, u32 attr0, u32 attr1,
			  u32 attr2)
{
	hwif->attr.func_global_idx = HIFC_AF0_GET(attr0, FUNC_GLOBAL_IDX);
	hwif->attr.port_to_port_idx = HIFC_AF0_GET(attr0, P2P_IDX);
	hwif->attr.pci_intf_idx = HIFC_AF0_GET(attr0, PCI_INTF_IDX);
	hwif->attr.vf_in_pf = HIFC_AF0_GET(attr0, VF_IN_PF);
	hwif->attr.func_type = HIFC_AF0_GET(attr0, FUNC_TYPE);

	hwif->attr.ppf_idx = HIFC_AF1_GET(attr1, PPF_IDX);

	hwif->attr.num_aeqs = BIT(HIFC_AF1_GET(attr1, AEQS_PER_FUNC));
	hwif->attr.num_ceqs = BIT(HIFC_AF1_GET(attr1, CEQS_PER_FUNC));
	hwif->attr.num_irqs = BIT(HIFC_AF1_GET(attr1, IRQS_PER_FUNC));
	hwif->attr.num_dma_attr = BIT(HIFC_AF1_GET(attr1, DMA_ATTR_PER_FUNC));
}

/**
 * get_hwif_attr - read and set the attributes as members in hwif
 * @hwif: the hardware interface of a pci function device
 **/
static void get_hwif_attr(struct hifc_hwif *hwif)
{
	u32 addr, attr0, attr1, attr2;

	addr   = HIFC_CSR_FUNC_ATTR0_ADDR;
	attr0  = hifc_hwif_read_reg(hwif, addr);

	addr   = HIFC_CSR_FUNC_ATTR1_ADDR;
	attr1  = hifc_hwif_read_reg(hwif, addr);

	addr   = HIFC_CSR_FUNC_ATTR2_ADDR;
	attr2  = hifc_hwif_read_reg(hwif, addr);

	set_hwif_attr(hwif, attr0, attr1, attr2);
}

void hifc_set_pf_status(struct hifc_hwif *hwif, enum hifc_pf_status status)
{
	u32 attr5 = HIFC_AF5_SET(status, PF_STATUS);
	u32 addr  = HIFC_CSR_FUNC_ATTR5_ADDR;

	hifc_hwif_write_reg(hwif, addr, attr5);
}

enum hifc_pf_status hifc_get_pf_status(struct hifc_hwif *hwif)
{
	u32 attr5 = hifc_hwif_read_reg(hwif, HIFC_CSR_FUNC_ATTR5_ADDR);

	return HIFC_AF5_GET(attr5, PF_STATUS);
}

enum hifc_doorbell_ctrl hifc_get_doorbell_ctrl_status(struct hifc_hwif *hwif)
{
	u32 attr4 = hifc_hwif_read_reg(hwif, HIFC_CSR_FUNC_ATTR4_ADDR);

	return HIFC_AF4_GET(attr4, DOORBELL_CTRL);
}

enum hifc_outbound_ctrl hifc_get_outbound_ctrl_status(struct hifc_hwif *hwif)
{
	u32 attr4 = hifc_hwif_read_reg(hwif, HIFC_CSR_FUNC_ATTR4_ADDR);

	return HIFC_AF4_GET(attr4, OUTBOUND_CTRL);
}

void hifc_enable_doorbell(struct hifc_hwif *hwif)
{
	u32 addr, attr4;

	addr = HIFC_CSR_FUNC_ATTR4_ADDR;
	attr4 = hifc_hwif_read_reg(hwif, addr);

	attr4 = HIFC_AF4_CLEAR(attr4, DOORBELL_CTRL);
	attr4 |= HIFC_AF4_SET(ENABLE_DOORBELL, DOORBELL_CTRL);

	hifc_hwif_write_reg(hwif, addr, attr4);
}

void hifc_disable_doorbell(struct hifc_hwif *hwif)
{
	u32 addr, attr4;

	addr = HIFC_CSR_FUNC_ATTR4_ADDR;
	attr4 = hifc_hwif_read_reg(hwif, addr);

	attr4 = HIFC_AF4_CLEAR(attr4, DOORBELL_CTRL);
	attr4 |= HIFC_AF4_SET(DISABLE_DOORBELL, DOORBELL_CTRL);

	hifc_hwif_write_reg(hwif, addr, attr4);
}

/**
 * set_ppf - try to set hwif as ppf and set the type of hwif in this case
 * @hwif: the hardware interface of a pci function device
 **/
static void set_ppf(struct hifc_hwif *hwif)
{
	struct hifc_func_attr *attr = &hwif->attr;
	u32 addr, val, ppf_election;

	/* Read Modify Write */
	addr  = HIFC_CSR_PPF_ELECTION_ADDR;

	val = hifc_hwif_read_reg(hwif, addr);
	val = HIFC_PPF_ELECTION_CLEAR(val, IDX);

	ppf_election =  HIFC_PPF_ELECTION_SET(attr->func_global_idx, IDX);
	val |= ppf_election;

	hifc_hwif_write_reg(hwif, addr, val);

	/* Check PPF */
	val = hifc_hwif_read_reg(hwif, addr);

	attr->ppf_idx = HIFC_PPF_ELECTION_GET(val, IDX);
	if (attr->ppf_idx == attr->func_global_idx)
		attr->func_type = TYPE_PPF;
}

/**
 * get_mpf - get the mpf index into the hwif
 * @hwif: the hardware interface of a pci function device
 **/
static void get_mpf(struct hifc_hwif *hwif)
{
	struct hifc_func_attr *attr = &hwif->attr;
	u32 mpf_election, addr;

	addr = HIFC_CSR_GLOBAL_MPF_ELECTION_ADDR;

	mpf_election = hifc_hwif_read_reg(hwif, addr);
	attr->mpf_idx = HIFC_MPF_ELECTION_GET(mpf_election, IDX);
}

/**
 * set_mpf - try to set hwif as mpf and set the mpf idx in hwif
 * @hwif: the hardware interface of a pci function device
 **/
static void set_mpf(struct hifc_hwif *hwif)
{
	struct hifc_func_attr *attr = &hwif->attr;
	u32 addr, val, mpf_election;

	/* Read Modify Write */
	addr  = HIFC_CSR_GLOBAL_MPF_ELECTION_ADDR;

	val = hifc_hwif_read_reg(hwif, addr);

	val = HIFC_MPF_ELECTION_CLEAR(val, IDX);
	mpf_election = HIFC_MPF_ELECTION_SET(attr->func_global_idx, IDX);

	val |= mpf_election;
	hifc_hwif_write_reg(hwif, addr, val);
}

static void init_db_area_idx(struct hifc_free_db_area *free_db_area)
{
	u32 i;

	for (i = 0; i < HIFC_DB_MAX_AREAS; i++)
		free_db_area->db_idx[i] = i;

	free_db_area->num_free = HIFC_DB_MAX_AREAS;

	spin_lock_init(&free_db_area->idx_lock);
}

static int get_db_idx(struct hifc_hwif *hwif, u32 *idx)
{
	struct hifc_free_db_area *free_db_area = &hwif->free_db_area;
	u32 pos;
	u32 pg_idx;

	spin_lock(&free_db_area->idx_lock);

retry:
	if (free_db_area->num_free == 0) {
		spin_unlock(&free_db_area->idx_lock);
		return -ENOMEM;
	}

	free_db_area->num_free--;

	pos = free_db_area->alloc_pos++;
	pos &= HIFC_DB_MAX_AREAS - 1;

	pg_idx = free_db_area->db_idx[pos];

	free_db_area->db_idx[pos] = 0xFFFFFFFF;

	/* pg_idx out of range */
	if (pg_idx >= HIFC_DB_MAX_AREAS)
		goto retry;

	spin_unlock(&free_db_area->idx_lock);

	*idx = pg_idx;

	return 0;
}

static void free_db_idx(struct hifc_hwif *hwif, u32 idx)
{
	struct hifc_free_db_area *free_db_area = &hwif->free_db_area;
	u32 pos;

	if (idx >= HIFC_DB_MAX_AREAS)
		return;

	spin_lock(&free_db_area->idx_lock);

	pos = free_db_area->return_pos++;
	pos &= HIFC_DB_MAX_AREAS - 1;

	free_db_area->db_idx[pos] = idx;

	free_db_area->num_free++;

	spin_unlock(&free_db_area->idx_lock);
}

void hifc_free_db_addr(void *hwdev, void __iomem *db_base,
		       void __iomem *dwqe_base)
{
	struct hifc_hwif *hwif;
	u32 idx;

	if (!hwdev || !db_base)
		return;

	hwif = ((struct hifc_hwdev *)hwdev)->hwif;
	idx = DB_IDX(db_base, hwif->db_base);

#if defined(__aarch64__)
	/* No need to unmap */
#else
	if (dwqe_base)
		io_mapping_unmap(dwqe_base);
#endif

	free_db_idx(hwif, idx);
}

int hifc_alloc_db_addr(void *hwdev, void __iomem **db_base,
		       void __iomem **dwqe_base)
{
	struct hifc_hwif *hwif;
	u64 offset;
	u32 idx;
	int err;

	if (!hwdev || !db_base)
		return -EINVAL;

	hwif = ((struct hifc_hwdev *)hwdev)->hwif;

	err = get_db_idx(hwif, &idx);
	if (err)
		return -EFAULT;

	*db_base = hwif->db_base + idx * HIFC_DB_PAGE_SIZE;

	if (!dwqe_base)
		return 0;

	offset = ((u64)idx) << PAGE_SHIFT;

#if defined(__aarch64__)
	*dwqe_base = hwif->dwqe_mapping + offset;
#else
	*dwqe_base = io_mapping_map_wc(hwif->dwqe_mapping, offset,
				       HIFC_DB_PAGE_SIZE);
#endif

	if (!(*dwqe_base)) {
		hifc_free_db_addr(hwdev, *db_base, NULL);
		return -EFAULT;
	}

	return 0;
}

void hifc_set_msix_state(void *hwdev, u16 msix_idx, enum hifc_msix_state flag)
{
	struct hifc_hwif *hwif;
	u32 offset = msix_idx * HIFC_PCI_MSIX_ENTRY_SIZE +
		     HIFC_PCI_MSIX_ENTRY_VECTOR_CTRL;
	u32 mask_bits;

	if (!hwdev)
		return;

	hwif = ((struct hifc_hwdev *)hwdev)->hwif;

	mask_bits = readl(hwif->intr_regs_base + offset);
	mask_bits &= ~HIFC_PCI_MSIX_ENTRY_CTRL_MASKBIT;
	if (flag)
		mask_bits |= HIFC_PCI_MSIX_ENTRY_CTRL_MASKBIT;

	writel(mask_bits, hwif->intr_regs_base + offset);
}

static void disable_all_msix(struct hifc_hwdev *hwdev)
{
	u16 num_irqs = hwdev->hwif->attr.num_irqs;
	u16 i;

	for (i = 0; i < num_irqs; i++)
		hifc_set_msix_state(hwdev, i, HIFC_MSIX_DISABLE);
}

static int wait_until_doorbell_and_outbound_enabled(struct hifc_hwif *hwif)
{
	enum hifc_doorbell_ctrl db_ctrl;
	enum hifc_outbound_ctrl outbound_ctrl;
	u32 cnt = 0;

	while (cnt < HIFC_WAIT_DOORBELL_AND_OUTBOUND_TIMEOUT) {
		db_ctrl = hifc_get_doorbell_ctrl_status(hwif);
		outbound_ctrl = hifc_get_outbound_ctrl_status(hwif);

		if (outbound_ctrl == ENABLE_OUTBOUND &&
		    db_ctrl == ENABLE_DOORBELL)
			return 0;

		usleep_range(900, 1000);
		cnt++;
	}

	return -EFAULT;
}

static void __print_selftest_reg(struct hifc_hwdev *hwdev)
{
	u32 addr, attr0, attr1;

	addr   = HIFC_CSR_FUNC_ATTR1_ADDR;
	attr1  = hifc_hwif_read_reg(hwdev->hwif, addr);

	if (attr1 == HIFC_PCIE_LINK_DOWN) {
		sdk_err(hwdev->dev_hdl, "PCIE is link down\n");
		return;
	}

	addr   = HIFC_CSR_FUNC_ATTR0_ADDR;
	attr0  = hifc_hwif_read_reg(hwdev->hwif, addr);
	if (HIFC_AF0_GET(attr0, FUNC_TYPE) != TYPE_VF &&
	    !HIFC_AF0_GET(attr0, PCI_INTF_IDX))
		sdk_err(hwdev->dev_hdl, "Selftest reg: 0x%08x\n",
			hifc_hwif_read_reg(hwdev->hwif,
					   HIFC_SELFTEST_RESULT));
}

/**
 * hifc_init_hwif - initialize the hw interface
 * @hwdev: the pointer to hw device
 * @cfg_reg_base: configuration base address
 * Return: 0 - success, negative - failure
 **/
int hifc_init_hwif(struct hifc_hwdev *hwdev, void *cfg_reg_base,
		   void *intr_reg_base, u64 db_base_phy,
		   void *db_base, void *dwqe_mapping)
{
	struct hifc_hwif *hwif;
	int err;

	hwif = kzalloc(sizeof(*hwif), GFP_KERNEL);
	if (!hwif)
		return -ENOMEM;

	hwdev->hwif = hwif;
	hwif->pdev = hwdev->pcidev_hdl;

	hwif->cfg_regs_base = cfg_reg_base;
	hwif->intr_regs_base = intr_reg_base;

	hwif->db_base_phy = db_base_phy;
	hwif->db_base = db_base;
	hwif->dwqe_mapping = dwqe_mapping;
	init_db_area_idx(&hwif->free_db_area);

	err = wait_hwif_ready(hwdev);
	if (err) {
		sdk_err(hwdev->dev_hdl, "Chip status is not ready\n");
		__print_selftest_reg(hwdev);
		goto hwif_ready_err;
	}

	get_hwif_attr(hwif);

	err = wait_until_doorbell_and_outbound_enabled(hwif);
	if (err) {
		sdk_err(hwdev->dev_hdl, "Hw doorbell/outbound is disabled\n");
		goto hwif_ready_err;
	}

	set_ppf(hwif);

	if (HIFC_IS_PPF(hwdev))
		set_mpf(hwif);

	get_mpf(hwif);

	disable_all_msix(hwdev);
	/* disable mgmt cpu report any event */
	hifc_set_pf_status(hwdev->hwif, HIFC_PF_STATUS_INIT);

	pr_info("global_func_idx: %d, func_type: %d, host_id: %d, ppf: %d, mpf: %d\n",
		hwif->attr.func_global_idx, hwif->attr.func_type,
		hwif->attr.pci_intf_idx, hwif->attr.ppf_idx,
		hwif->attr.mpf_idx);

	return 0;

hwif_ready_err:
	kfree(hwif);

	return err;
}

/**
 * hifc_free_hwif - free the hw interface
 * @hwdev: the pointer to hw device
 **/
void hifc_free_hwif(struct hifc_hwdev *hwdev)
{
	kfree(hwdev->hwif);
}

int hifc_dma_alloc_coherent_align(void *dev_hdl, u64 size, u64 align,
				  unsigned flag,
				  struct hifc_dma_addr_align *mem_align)
{
	void *vaddr, *align_vaddr;
	dma_addr_t paddr, align_paddr;
	u64 real_size = size;

	vaddr = dma_alloc_coherent(dev_hdl, real_size, &paddr, flag);
	if (!vaddr)
		return -ENOMEM;

	align_paddr = ALIGN(paddr, align);
	/* align */
	if (align_paddr == paddr) {
		align_vaddr = vaddr;
		goto out;
	}

	dma_free_coherent(dev_hdl, real_size, vaddr, paddr);

	/* realloc memory for align */
	real_size = size + align;
	vaddr = dma_alloc_coherent(dev_hdl, real_size, &paddr, flag);
	if (!vaddr)
		return -ENOMEM;

	align_paddr = ALIGN(paddr, align);
	align_vaddr = (void *)((u64)vaddr + (align_paddr - paddr));

out:
	mem_align->real_size = (u32)real_size;
	mem_align->ori_vaddr = vaddr;
	mem_align->ori_paddr = paddr;
	mem_align->align_vaddr = align_vaddr;
	mem_align->align_paddr = align_paddr;

	return 0;
}

void hifc_dma_free_coherent_align(void *dev_hdl,
				  struct hifc_dma_addr_align *mem_align)
{
	dma_free_coherent(dev_hdl, mem_align->real_size,
			  mem_align->ori_vaddr, mem_align->ori_paddr);
}

u16 hifc_global_func_id(void *hwdev)
{
	struct hifc_hwif *hwif;

	if (!hwdev)
		return 0;

	hwif = ((struct hifc_hwdev *)hwdev)->hwif;

	return hwif->attr.func_global_idx;
}

/**
 * get function id from register,used by sriov hot migration process
 * @hwdev: the pointer to hw device
 **/
u16 hifc_global_func_id_hw(void *hwdev)
{
	u32 addr, attr0;
	struct hifc_hwdev *dev;

	dev = (struct hifc_hwdev *)hwdev;
	addr   = HIFC_CSR_FUNC_ATTR0_ADDR;
	attr0  = hifc_hwif_read_reg(dev->hwif, addr);

	return HIFC_AF0_GET(attr0, FUNC_GLOBAL_IDX);
}

/**
 * get function id, used by sriov hot migratition process.
 * @hwdev: the pointer to hw device
 * @func_id: function id
 **/
int hifc_global_func_id_get(void *hwdev, u16 *func_id)
{
	*func_id = hifc_global_func_id(hwdev);
	return 0;
}

u8 hifc_pcie_itf_id(void *hwdev)
{
	struct hifc_hwif *hwif;

	if (!hwdev)
		return 0;

	hwif = ((struct hifc_hwdev *)hwdev)->hwif;

	return hwif->attr.pci_intf_idx;
}
EXPORT_SYMBOL(hifc_pcie_itf_id);

enum func_type hifc_func_type(void *hwdev)
{
	struct hifc_hwif *hwif;

	if (!hwdev)
		return 0;

	hwif = ((struct hifc_hwdev *)hwdev)->hwif;

	return hwif->attr.func_type;
}

u8 hifc_ppf_idx(void *hwdev)
{
	struct hifc_hwif *hwif;

	if (!hwdev)
		return 0;

	hwif = ((struct hifc_hwdev *)hwdev)->hwif;

	return hwif->attr.ppf_idx;
}
