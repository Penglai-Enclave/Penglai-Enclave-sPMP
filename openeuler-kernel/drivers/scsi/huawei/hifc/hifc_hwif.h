/* SPDX-License-Identifier: GPL-2.0 */
/* Huawei Hifc PCI Express Linux driver
 * Copyright(c) 2017 Huawei Technologies Co., Ltd
 *
 */

#ifndef HIFC_HWIF_H
#define HIFC_HWIF_H

#include "hifc_hwdev.h"

#define HIFC_WAIT_DOORBELL_AND_OUTBOUND_TIMEOUT 60000
#define HIFC_CSR_GLOBAL_BASE_ADDR               0x4000
/* HW interface registers */
#define HIFC_CSR_FUNC_ATTR0_ADDR                0x0
#define HIFC_CSR_FUNC_ATTR1_ADDR                0x4
#define HIFC_CSR_FUNC_ATTR2_ADDR                0x8
#define HIFC_CSR_FUNC_ATTR4_ADDR                0x10

#define HIFC_CSR_FUNC_ATTR5_ADDR                0x14
#define HIFC_PCI_MSIX_ENTRY_SIZE                16
#define HIFC_PCI_MSIX_ENTRY_VECTOR_CTRL	        12
#define HIFC_PCI_MSIX_ENTRY_CTRL_MASKBIT        1

/* total doorbell or direct wqe size is 512kB, db num: 128, dwqe: 128*/
#define HIFC_DB_DWQE_SIZE                       0x00080000
/* db/dwqe page size: 4K */
#define HIFC_DB_PAGE_SIZE                       0x00001000ULL
#define HIFC_DB_MAX_AREAS      (HIFC_DB_DWQE_SIZE / HIFC_DB_PAGE_SIZE)

#define HIFC_ELECTION_BASE                       0x200
#define HIFC_PPF_ELECTION_STRIDE                 0x4
#define HIFC_CSR_MAX_PORTS                       4
#define HIFC_CSR_PPF_ELECTION_ADDR               \
			(HIFC_CSR_GLOBAL_BASE_ADDR + HIFC_ELECTION_BASE)

#define HIFC_CSR_GLOBAL_MPF_ELECTION_ADDR           \
			(HIFC_CSR_GLOBAL_BASE_ADDR + HIFC_ELECTION_BASE + \
			HIFC_CSR_MAX_PORTS * HIFC_PPF_ELECTION_STRIDE)
#define DB_IDX(db, db_base)                         \
	((u32)(((ulong)(db) - (ulong)(db_base)) /   \
	HIFC_DB_PAGE_SIZE))

#define HIFC_AF0_FUNC_GLOBAL_IDX_SHIFT         0
#define HIFC_AF0_P2P_IDX_SHIFT                 10
#define HIFC_AF0_PCI_INTF_IDX_SHIFT            14
#define HIFC_AF0_VF_IN_PF_SHIFT                16
#define HIFC_AF0_FUNC_TYPE_SHIFT               24
#define HIFC_AF0_FUNC_GLOBAL_IDX_MASK          0x3FF
#define HIFC_AF0_P2P_IDX_MASK                  0xF
#define HIFC_AF0_PCI_INTF_IDX_MASK             0x3
#define HIFC_AF0_VF_IN_PF_MASK                 0xFF
#define HIFC_AF0_FUNC_TYPE_MASK                0x1

#define HIFC_AF0_GET(val, member)              \
	(((val) >> HIFC_AF0_##member##_SHIFT) & HIFC_AF0_##member##_MASK)

#define HIFC_AF1_PPF_IDX_SHIFT                  0
#define HIFC_AF1_AEQS_PER_FUNC_SHIFT            8
#define HIFC_AF1_CEQS_PER_FUNC_SHIFT            12
#define HIFC_AF1_IRQS_PER_FUNC_SHIFT            20
#define HIFC_AF1_DMA_ATTR_PER_FUNC_SHIFT        24
#define HIFC_AF1_MGMT_INIT_STATUS_SHIFT         30
#define HIFC_AF1_PF_INIT_STATUS_SHIFT           31

#define HIFC_AF1_PPF_IDX_MASK                   0x1F
#define HIFC_AF1_AEQS_PER_FUNC_MASK             0x3
#define HIFC_AF1_CEQS_PER_FUNC_MASK             0x7
#define HIFC_AF1_IRQS_PER_FUNC_MASK             0xF
#define HIFC_AF1_DMA_ATTR_PER_FUNC_MASK         0x7
#define HIFC_AF1_MGMT_INIT_STATUS_MASK          0x1
#define HIFC_AF1_PF_INIT_STATUS_MASK            0x1

#define HIFC_AF1_GET(val, member)                \
	(((val) >> HIFC_AF1_##member##_SHIFT) & HIFC_AF1_##member##_MASK)

#define HIFC_AF4_OUTBOUND_CTRL_SHIFT            0
#define HIFC_AF4_DOORBELL_CTRL_SHIFT            1
#define HIFC_AF4_OUTBOUND_CTRL_MASK             0x1
#define HIFC_AF4_DOORBELL_CTRL_MASK             0x1

#define HIFC_AF4_GET(val, member)                \
	(((val) >> HIFC_AF4_##member##_SHIFT) & HIFC_AF4_##member##_MASK)

#define HIFC_AF4_SET(val, member)                \
	(((val) & HIFC_AF4_##member##_MASK) << HIFC_AF4_##member##_SHIFT)

#define HIFC_AF4_CLEAR(val, member)              \
	((val) & (~(HIFC_AF4_##member##_MASK <<  \
	HIFC_AF4_##member##_SHIFT)))

#define HIFC_AF5_PF_STATUS_SHIFT                 0
#define HIFC_AF5_PF_STATUS_MASK                  0xFFFF

#define HIFC_AF5_SET(val, member)                \
	(((val) & HIFC_AF5_##member##_MASK) << HIFC_AF5_##member##_SHIFT)

#define HIFC_AF5_GET(val, member)                \
	(((val) >> HIFC_AF5_##member##_SHIFT) & HIFC_AF5_##member##_MASK)

#define HIFC_PPF_ELECTION_IDX_SHIFT              0
#define HIFC_PPF_ELECTION_IDX_MASK               0x1F

#define HIFC_PPF_ELECTION_SET(val, member)       \
	(((val) & HIFC_PPF_ELECTION_##member##_MASK) <<    \
		HIFC_PPF_ELECTION_##member##_SHIFT)

#define HIFC_PPF_ELECTION_GET(val, member)       \
	(((val) >> HIFC_PPF_ELECTION_##member##_SHIFT) &   \
		HIFC_PPF_ELECTION_##member##_MASK)

#define HIFC_PPF_ELECTION_CLEAR(val, member)     \
	((val) & (~(HIFC_PPF_ELECTION_##member##_MASK      \
		<< HIFC_PPF_ELECTION_##member##_SHIFT)))

#define HIFC_MPF_ELECTION_IDX_SHIFT             0
#define HIFC_MPF_ELECTION_IDX_MASK              0x1F

#define HIFC_MPF_ELECTION_SET(val, member)       \
	(((val) & HIFC_MPF_ELECTION_##member##_MASK) <<    \
		HIFC_MPF_ELECTION_##member##_SHIFT)

#define HIFC_MPF_ELECTION_GET(val, member)         \
	(((val) >> HIFC_MPF_ELECTION_##member##_SHIFT) &   \
		HIFC_MPF_ELECTION_##member##_MASK)

#define HIFC_MPF_ELECTION_CLEAR(val, member)     \
	((val) & (~(HIFC_MPF_ELECTION_##member##_MASK      \
		<< HIFC_MPF_ELECTION_##member##_SHIFT)))

#define HIFC_HWIF_NUM_AEQS(hwif)             ((hwif)->attr.num_aeqs)
#define HIFC_HWIF_NUM_CEQS(hwif)             ((hwif)->attr.num_ceqs)
#define HIFC_HWIF_PPF_IDX(hwif)              ((hwif)->attr.ppf_idx)
#define HIFC_PCI_INTF_IDX(hwif)              ((hwif)->attr.pci_intf_idx)

#define HIFC_FUNC_TYPE(dev)                  ((dev)->hwif->attr.func_type)
#define HIFC_IS_PPF(dev)                     (HIFC_FUNC_TYPE(dev) == TYPE_PPF)

enum hifc_pcie_nosnoop {
	HIFC_PCIE_SNOOP = 0,
	HIFC_PCIE_NO_SNOOP = 1,
};

enum hifc_pcie_tph {
	HIFC_PCIE_TPH_DISABLE = 0,
	HIFC_PCIE_TPH_ENABLE = 1,
};

enum hifc_pf_status {
	HIFC_PF_STATUS_INIT = 0X0,
	HIFC_PF_STATUS_ACTIVE_FLAG = 0x11,
	HIFC_PF_STATUS_FLR_START_FLAG = 0x12,
	HIFC_PF_STATUS_FLR_FINISH_FLAG = 0x13,
};

enum hifc_outbound_ctrl {
	ENABLE_OUTBOUND  = 0x0,
	DISABLE_OUTBOUND = 0x1,
};

enum hifc_doorbell_ctrl {
	ENABLE_DOORBELL  = 0x0,
	DISABLE_DOORBELL = 0x1,
};

struct hifc_free_db_area {
	u32 db_idx[HIFC_DB_MAX_AREAS];
	u32 num_free;
	u32 alloc_pos;
	u32 return_pos;
	/* spinlock for allocating doorbell area */
	spinlock_t      idx_lock;
};

enum func_type {
	TYPE_PF,
	TYPE_VF,
	TYPE_PPF,
	TYPE_UNKNOWN,
};

struct hifc_func_attr {
	u16 func_global_idx;
	u8 port_to_port_idx;
	u8 pci_intf_idx;
	u8 vf_in_pf;
	enum func_type func_type;

	u8 mpf_idx;

	u8 ppf_idx;

	u16 num_irqs;    /* max: 2 ^ 15 */
	u8 num_aeqs;     /* max: 2 ^ 3 */
	u8 num_ceqs;     /* max: 2 ^ 7 */

	u8 num_dma_attr; /* max: 2 ^ 6 */
};

struct hifc_hwif {
	u8 __iomem *cfg_regs_base;
	u8 __iomem *intr_regs_base;
	u64 db_base_phy;
	u8 __iomem *db_base;

#if defined(__aarch64__)
	void __iomem                    *dwqe_mapping;
#else
	struct io_mapping               *dwqe_mapping;
#endif
	struct hifc_free_db_area        free_db_area;
	struct hifc_func_attr           attr;
	void                            *pdev;
};

struct hifc_dma_addr_align {
	u32 real_size;
	void *ori_vaddr;
	dma_addr_t ori_paddr;
	void *align_vaddr;
	dma_addr_t align_paddr;
};

u32 hifc_hwif_read_reg(struct hifc_hwif *hwif, u32 reg);
void hifc_hwif_write_reg(struct hifc_hwif *hwif, u32 reg, u32 val);
void hifc_set_pf_status(struct hifc_hwif *hwif, enum hifc_pf_status status);
enum hifc_pf_status hifc_get_pf_status(struct hifc_hwif *hwif);
enum hifc_doorbell_ctrl
	hifc_get_doorbell_ctrl_status(struct hifc_hwif *hwif);
enum hifc_outbound_ctrl
	hifc_get_outbound_ctrl_status(struct hifc_hwif *hwif);
void hifc_enable_doorbell(struct hifc_hwif *hwif);
void hifc_disable_doorbell(struct hifc_hwif *hwif);
int hifc_init_hwif(struct hifc_hwdev *hwdev, void *cfg_reg_base,
		   void *intr_reg_base, u64 db_base_phy,
		   void *db_base, void *dwqe_mapping);
void hifc_free_hwif(struct hifc_hwdev *hwdev);
int hifc_dma_alloc_coherent_align(void *dev_hdl, u64 size, u64 align,
				  unsigned flag,
				  struct hifc_dma_addr_align *mem_align);
void hifc_dma_free_coherent_align(void *dev_hdl,
				  struct hifc_dma_addr_align *mem_align);
#endif
