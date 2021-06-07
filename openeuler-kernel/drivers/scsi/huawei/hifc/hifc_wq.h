/* SPDX-License-Identifier: GPL-2.0 */
/* Huawei Hifc PCI Express Linux driver
 * Copyright(c) 2017 Huawei Technologies Co., Ltd
 *
 */

#ifndef HIFC_WQ_H
#define HIFC_WQ_H

#define WQS_BLOCKS_PER_PAGE   4
#define WQ_SIZE(wq)           (u32)((u64)(wq)->q_depth * (wq)->wqebb_size)

#define	WQE_PAGE_NUM(wq, idx) (((idx) >> ((wq)->wqebbs_per_page_shift)) & \
				((wq)->num_q_pages - 1))

#define	WQE_PAGE_OFF(wq, idx)   ((u64)((wq)->wqebb_size) * \
			((idx) & ((wq)->num_wqebbs_per_page - 1)))

#define WQ_PAGE_ADDR_SIZE       sizeof(u64)
#define WQ_PAGE_ADDR_SIZE_SHIFT 3
#define WQ_PAGE_ADDR(wq, idx)		\
		(u8 *)(*(u64 *)((u64)((wq)->shadow_block_vaddr) + \
		(WQE_PAGE_NUM(wq, idx) << WQ_PAGE_ADDR_SIZE_SHIFT)))

#define WQ_BLOCK_SIZE                 4096UL
#define WQS_PAGE_SIZE                 (WQS_BLOCKS_PER_PAGE * WQ_BLOCK_SIZE)
#define WQ_MAX_PAGES                  (WQ_BLOCK_SIZE >> WQ_PAGE_ADDR_SIZE_SHIFT)

#define CMDQ_BLOCKS_PER_PAGE          8
#define CMDQ_BLOCK_SIZE               512UL
#define CMDQ_PAGE_SIZE                ALIGN((CMDQ_BLOCKS_PER_PAGE * \
						CMDQ_BLOCK_SIZE), PAGE_SIZE)

#define ADDR_4K_ALIGNED(addr)        (((addr) & 0xfff) == 0)

#define WQ_BASE_VADDR(wqs, wq)		\
		(u64 *)(((u64)((wqs)->page_vaddr[(wq)->page_idx])) \
				+ (wq)->block_idx * WQ_BLOCK_SIZE)

#define WQ_BASE_PADDR(wqs, wq)	(((wqs)->page_paddr[(wq)->page_idx]) \
				+ (u64)(wq)->block_idx * WQ_BLOCK_SIZE)

#define WQ_BASE_ADDR(wqs, wq)		\
		(u64 *)(((u64)((wqs)->shadow_page_vaddr[(wq)->page_idx])) \
				+ (wq)->block_idx * WQ_BLOCK_SIZE)

#define CMDQ_BASE_VADDR(cmdq_pages, wq)	\
			(u64 *)(((u64)((cmdq_pages)->cmdq_page_vaddr)) \
				+ (wq)->block_idx * CMDQ_BLOCK_SIZE)

#define CMDQ_BASE_PADDR(cmdq_pages, wq)	\
			(((u64)((cmdq_pages)->cmdq_page_paddr)) \
				+ (u64)(wq)->block_idx * CMDQ_BLOCK_SIZE)

#define CMDQ_BASE_ADDR(cmdq_pages, wq)	\
			(u64 *)(((u64)((cmdq_pages)->cmdq_shadow_page_vaddr)) \
				+ (wq)->block_idx * CMDQ_BLOCK_SIZE)

#define MASKED_WQE_IDX(wq, idx)	((idx) & (wq)->mask)

#define WQ_NUM_PAGES(num_wqs)	\
	(ALIGN((u32)num_wqs, WQS_BLOCKS_PER_PAGE) / WQS_BLOCKS_PER_PAGE)

#define MAX_WQE_SIZE(max_sge, wqebb_size)	\
			((max_sge <= 2) ? (wqebb_size) : \
			((ALIGN(((max_sge) - 2), 4) / 4 + 1) * (wqebb_size)))

struct hifc_free_block {
	u32	page_idx;
	u32	block_idx;
};

struct hifc_wq {
	/* The addresses are 64 bit in the HW */
	u64		block_paddr;
	u64		*shadow_block_vaddr;
	u64		*block_vaddr;

	u32		wqebb_size;
	u32		wq_page_size;
	u16		q_depth;
	u32		max_wqe_size;
	u32		num_wqebbs_per_page;

	/* performance: replace mul/div as shift;
	 * num_wqebbs_per_page must be power of 2
	 */
	u32		wqebbs_per_page_shift;
	u32		page_idx;
	u32		block_idx;

	u32		num_q_pages;

	struct hifc_dma_addr_align *mem_align;

	int		cons_idx;
	int		prod_idx;

	atomic_t	delta;
	u16		mask;

	u8		*shadow_wqe;
	u16		*shadow_idx;
};

struct hifc_cmdq_pages {
	/* The addresses are 64 bit in the HW */
	u64	cmdq_page_paddr;
	u64	*cmdq_page_vaddr;
	u64	*cmdq_shadow_page_vaddr;

	void	*dev_hdl;
};

struct hifc_wqs {
	/* The addresses are 64 bit in the HW */
	u64				*page_paddr;
	u64				**page_vaddr;
	u64				**shadow_page_vaddr;

	struct hifc_free_block	*free_blocks;
	u32				alloc_blk_pos;
	u32				return_blk_pos;
	int				num_free_blks;

	/* for allocate blocks */
	spinlock_t			alloc_blocks_lock;

	u32				num_pages;

	void				*dev_hdl;
};

void hifc_wq_wqe_pg_clear(struct hifc_wq *wq);

int hifc_cmdq_alloc(struct hifc_cmdq_pages *cmdq_pages,
		    struct hifc_wq *wq, void *dev_hdl,
		    int cmdq_blocks, u32 wq_page_size, u32 wqebb_size,
		    u16 q_depth, u32 max_wqe_size);

void hifc_cmdq_free(struct hifc_cmdq_pages *cmdq_pages,
		    struct hifc_wq *wq, int cmdq_blocks);

int hifc_wqs_alloc(struct hifc_wqs *wqs, int num_wqs, void *dev_hdl);

void hifc_wqs_free(struct hifc_wqs *wqs);

int hifc_wq_allocate(struct hifc_wqs *wqs, struct hifc_wq *wq,
		     u32 wqebb_size, u32 wq_page_size, u16 q_depth,
		     u32 max_wqe_size);

void hifc_wq_free(struct hifc_wqs *wqs, struct hifc_wq *wq);

void *hifc_get_wqebb_addr(struct hifc_wq *wq, u16 index);

u64 hifc_get_first_wqe_page_addr(struct hifc_wq *wq);

void *hifc_get_wqe(struct hifc_wq *wq, int num_wqebbs, u16 *prod_idx);

void hifc_put_wqe(struct hifc_wq *wq, int num_wqebbs);

void *hifc_read_wqe(struct hifc_wq *wq, int num_wqebbs, u16 *cons_idx);

#endif
