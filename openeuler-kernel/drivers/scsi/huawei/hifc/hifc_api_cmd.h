/* SPDX-License-Identifier: GPL-2.0 */
/* Huawei Hifc PCI Express Linux driver
 * Copyright(c) 2017 Huawei Technologies Co., Ltd
 *
 */

#ifndef HIFC_API_CMD_H_
#define HIFC_API_CMD_H_

#define HIFC_API_CMD_CELL_CTRL_CELL_LEN_SHIFT                   0
#define HIFC_API_CMD_CELL_CTRL_RD_DMA_ATTR_OFF_SHIFT            16
#define HIFC_API_CMD_CELL_CTRL_WR_DMA_ATTR_OFF_SHIFT            24
#define HIFC_API_CMD_CELL_CTRL_XOR_CHKSUM_SHIFT                 56

#define HIFC_API_CMD_CELL_CTRL_CELL_LEN_MASK                    0x3FU
#define HIFC_API_CMD_CELL_CTRL_RD_DMA_ATTR_OFF_MASK             0x3FU
#define HIFC_API_CMD_CELL_CTRL_WR_DMA_ATTR_OFF_MASK             0x3FU
#define HIFC_API_CMD_CELL_CTRL_XOR_CHKSUM_MASK                  0xFFU

#define HIFC_API_CMD_CELL_CTRL_SET(val, member) \
		((((u64)val) & HIFC_API_CMD_CELL_CTRL_##member##_MASK) << \
		HIFC_API_CMD_CELL_CTRL_##member##_SHIFT)

#define HIFC_API_CMD_DESC_API_TYPE_SHIFT                        0
#define HIFC_API_CMD_DESC_RD_WR_SHIFT                           1
#define HIFC_API_CMD_DESC_MGMT_BYPASS_SHIFT                     2
#define HIFC_API_CMD_DESC_RESP_AEQE_EN_SHIFT                    3
#define HIFC_API_CMD_DESC_PRIV_DATA_SHIFT                       8
#define HIFC_API_CMD_DESC_DEST_SHIFT                            32
#define HIFC_API_CMD_DESC_SIZE_SHIFT                            40
#define HIFC_API_CMD_DESC_XOR_CHKSUM_SHIFT                      56

#define HIFC_API_CMD_DESC_API_TYPE_MASK                         0x1U
#define HIFC_API_CMD_DESC_RD_WR_MASK                            0x1U
#define HIFC_API_CMD_DESC_MGMT_BYPASS_MASK                      0x1U
#define HIFC_API_CMD_DESC_RESP_AEQE_EN_MASK                     0x1U
#define HIFC_API_CMD_DESC_DEST_MASK                             0x1FU
#define HIFC_API_CMD_DESC_SIZE_MASK                             0x7FFU
#define HIFC_API_CMD_DESC_XOR_CHKSUM_MASK                       0xFFU
#define HIFC_API_CMD_DESC_PRIV_DATA_MASK                        0xFFFFFFU

#define HIFC_API_CMD_DESC_SET(val, member) \
		((((u64)val) & HIFC_API_CMD_DESC_##member##_MASK) << \
		HIFC_API_CMD_DESC_##member##_SHIFT)
#define HIFC_API_CMD_STATUS_HEADER_VALID_SHIFT                  0
#define HIFC_API_CMD_STATUS_HEADER_CHAIN_ID_SHIFT               16

#define HIFC_API_CMD_STATUS_HEADER_VALID_MASK                   0xFFU
#define HIFC_API_CMD_STATUS_HEADER_CHAIN_ID_MASK                0xFFU
#define HIFC_API_CMD_STATUS_HEADER_GET(val, member) \
	      (((val) >> HIFC_API_CMD_STATUS_HEADER_##member##_SHIFT) & \
	      HIFC_API_CMD_STATUS_HEADER_##member##_MASK)
#define HIFC_API_CMD_CHAIN_REQ_RESTART_SHIFT                    1
#define HIFC_API_CMD_CHAIN_REQ_RESTART_MASK                     0x1U
#define HIFC_API_CMD_CHAIN_REQ_WB_TRIGGER_MASK                  0x1U
#define HIFC_API_CMD_CHAIN_REQ_SET(val, member) \
	       (((val) & HIFC_API_CMD_CHAIN_REQ_##member##_MASK) << \
	       HIFC_API_CMD_CHAIN_REQ_##member##_SHIFT)

#define HIFC_API_CMD_CHAIN_REQ_GET(val, member) \
	      (((val) >> HIFC_API_CMD_CHAIN_REQ_##member##_SHIFT) & \
	      HIFC_API_CMD_CHAIN_REQ_##member##_MASK)

#define HIFC_API_CMD_CHAIN_REQ_CLEAR(val, member) \
	((val) & (~(HIFC_API_CMD_CHAIN_REQ_##member##_MASK \
		<< HIFC_API_CMD_CHAIN_REQ_##member##_SHIFT)))

#define HIFC_API_CMD_CHAIN_CTRL_RESTART_EN_SHIFT                1
#define HIFC_API_CMD_CHAIN_CTRL_XOR_ERR_SHIFT                   2
#define HIFC_API_CMD_CHAIN_CTRL_AEQE_EN_SHIFT                   4
#define HIFC_API_CMD_CHAIN_CTRL_AEQ_ID_SHIFT                    8
#define HIFC_API_CMD_CHAIN_CTRL_XOR_CHK_EN_SHIFT                28
#define HIFC_API_CMD_CHAIN_CTRL_CELL_SIZE_SHIFT                 30

#define HIFC_API_CMD_CHAIN_CTRL_RESTART_EN_MASK                 0x1U
#define HIFC_API_CMD_CHAIN_CTRL_XOR_ERR_MASK                    0x1U
#define HIFC_API_CMD_CHAIN_CTRL_AEQE_EN_MASK                    0x1U
#define HIFC_API_CMD_CHAIN_CTRL_AEQ_ID_MASK                     0x3U
#define HIFC_API_CMD_CHAIN_CTRL_XOR_CHK_EN_MASK                 0x3U
#define HIFC_API_CMD_CHAIN_CTRL_CELL_SIZE_MASK                  0x3U

#define HIFC_API_CMD_CHAIN_CTRL_SET(val, member) \
	(((val) & HIFC_API_CMD_CHAIN_CTRL_##member##_MASK) << \
	HIFC_API_CMD_CHAIN_CTRL_##member##_SHIFT)

#define HIFC_API_CMD_CHAIN_CTRL_CLEAR(val, member) \
	((val) & (~(HIFC_API_CMD_CHAIN_CTRL_##member##_MASK \
		<< HIFC_API_CMD_CHAIN_CTRL_##member##_SHIFT)))

#define HIFC_API_CMD_RESP_HEAD_VALID_MASK               0xFF
#define HIFC_API_CMD_RESP_HEAD_VALID_CODE               0xFF

#define HIFC_API_CMD_RESP_HEADER_VALID(val) \
		(((val) & HIFC_API_CMD_RESP_HEAD_VALID_MASK) == \
		HIFC_API_CMD_RESP_HEAD_VALID_CODE)
#define HIFC_API_CMD_STATUS_CONS_IDX_MASK               0xFFFFFFU
#define HIFC_API_CMD_STATUS_CONS_IDX_SHIFT              0
#define HIFC_API_CMD_STATUS_FSM_MASK                    0xFU
#define HIFC_API_CMD_STATUS_FSM_SHIFT                   24
#define HIFC_API_CMD_STATUS_CHKSUM_ERR_MASK             0x3U
#define HIFC_API_CMD_STATUS_CHKSUM_ERR_SHIFT            28
#define HIFC_API_CMD_STATUS_CPLD_ERR_MASK               0x1U
#define HIFC_API_CMD_STATUS_CPLD_ERR_SHIFT              30

#define HIFC_API_CMD_STATUS_GET(val, member) \
		(((val) >> HIFC_API_CMD_STATUS_##member##_SHIFT) & \
		HIFC_API_CMD_STATUS_##member##_MASK)

/* API CMD registers */
#define HIFC_CSR_API_CMD_BASE                   0xF000

#define HIFC_CSR_API_CMD_STRIDE                 0x100

#define HIFC_CSR_API_CMD_CHAIN_HEAD_HI_ADDR(idx) \
	(HIFC_CSR_API_CMD_BASE + 0x0 + (idx) * HIFC_CSR_API_CMD_STRIDE)

#define HIFC_CSR_API_CMD_CHAIN_HEAD_LO_ADDR(idx) \
	(HIFC_CSR_API_CMD_BASE + 0x4 + (idx) * HIFC_CSR_API_CMD_STRIDE)

#define HIFC_CSR_API_CMD_STATUS_HI_ADDR(idx) \
	(HIFC_CSR_API_CMD_BASE + 0x8 + (idx) * HIFC_CSR_API_CMD_STRIDE)

#define HIFC_CSR_API_CMD_STATUS_LO_ADDR(idx) \
	(HIFC_CSR_API_CMD_BASE + 0xC + (idx) * HIFC_CSR_API_CMD_STRIDE)

#define HIFC_CSR_API_CMD_CHAIN_NUM_CELLS_ADDR(idx) \
	(HIFC_CSR_API_CMD_BASE + 0x10 + (idx) * HIFC_CSR_API_CMD_STRIDE)

#define HIFC_CSR_API_CMD_CHAIN_CTRL_ADDR(idx) \
	(HIFC_CSR_API_CMD_BASE + 0x14 + (idx) * HIFC_CSR_API_CMD_STRIDE)

#define HIFC_CSR_API_CMD_CHAIN_PI_ADDR(idx) \
	(HIFC_CSR_API_CMD_BASE + 0x1C + (idx) * HIFC_CSR_API_CMD_STRIDE)

#define HIFC_CSR_API_CMD_CHAIN_REQ_ADDR(idx) \
	(HIFC_CSR_API_CMD_BASE + 0x20 + (idx) * HIFC_CSR_API_CMD_STRIDE)

#define HIFC_CSR_API_CMD_STATUS_0_ADDR(idx) \
	(HIFC_CSR_API_CMD_BASE + 0x30 + (idx) * HIFC_CSR_API_CMD_STRIDE)

enum hifc_api_cmd_chain_type {
	/* write command with completion notification */
	HIFC_API_CMD_WRITE                     = 0,
	/* read command with completion notification */
	HIFC_API_CMD_READ                      = 1,
	/* write to mgmt cpu command with completion  */
	HIFC_API_CMD_WRITE_TO_MGMT_CPU         = 2,
	/* multi read command with completion notification - not used */
	HIFC_API_CMD_MULTI_READ                = 3,
	/* write command without completion notification */
	HIFC_API_CMD_POLL_WRITE                = 4,
	/* read command without completion notification */
	HIFC_API_CMD_POLL_READ                 = 5,
	/* read from mgmt cpu command with completion */
	HIFC_API_CMD_WRITE_ASYNC_TO_MGMT_CPU   = 6,
	HIFC_API_CMD_MAX,
};

struct hifc_api_cmd_status {
	u64 header;
	u32 buf_desc;
	u32 cell_addr_hi;
	u32 cell_addr_lo;
	u32 rsvd0;
	u64 rsvd1;
};

/* HW struct */
struct hifc_api_cmd_cell {
	u64 ctrl;

	/* address is 64 bit in HW struct */
	u64 next_cell_paddr;

	u64 desc;

	/* HW struct */
	union {
		struct {
			u64 hw_cmd_paddr;
		} write;

		struct {
			u64 hw_wb_resp_paddr;
			u64 hw_cmd_paddr;
		} read;
	};
};

struct hifc_api_cmd_resp_fmt {
	u64 header;
	u64 rsvd[3];
	u64 resp_data;
};

struct hifc_api_cmd_cell_ctxt {
	struct hifc_api_cmd_cell *cell_vaddr;

	void *api_cmd_vaddr;

	struct hifc_api_cmd_resp_fmt *resp;

	struct completion done;
	int status;

	u32 saved_prod_idx;
};

struct hifc_api_cmd_chain_attr {
	struct hifc_hwdev *hwdev;
	enum hifc_api_cmd_chain_type chain_type;

	u32 num_cells;
	u16 rsp_size;
	u16 cell_size;
};

struct hifc_api_cmd_chain {
	struct hifc_hwdev *hwdev;
	enum hifc_api_cmd_chain_type chain_type;

	u32 num_cells;
	u16 cell_size;
	u16 rsp_size;

	/* HW members is 24 bit format */
	u32 prod_idx;
	u32 cons_idx;

	struct semaphore sem;
	/* Async cmd can not be scheduling */
	spinlock_t async_lock;

	dma_addr_t wb_status_paddr;
	struct hifc_api_cmd_status *wb_status;

	dma_addr_t head_cell_paddr;
	struct hifc_api_cmd_cell *head_node;

	struct hifc_api_cmd_cell_ctxt *cell_ctxt;
	struct hifc_api_cmd_cell *curr_node;

	struct hifc_dma_addr_align cells_addr;

	u8 *cell_vaddr_base;
	u64 cell_paddr_base;
	u8 *rsp_vaddr_base;
	u64 rsp_paddr_base;
	u8 *buf_vaddr_base;
	u64 buf_paddr_base;
	u64 cell_size_align;
	u64 rsp_size_align;
	u64 buf_size_align;
};

int hifc_api_cmd_write(struct hifc_api_cmd_chain *chain,
		       enum hifc_node_id dest, void *cmd, u16 size);

int hifc_api_cmd_read(struct hifc_api_cmd_chain *chain,
		      enum hifc_node_id dest, void *cmd, u16 size,
		      void *ack, u16 ack_size);

int hifc_api_cmd_init(struct hifc_hwdev *hwdev,
		      struct hifc_api_cmd_chain **chain);

void hifc_api_cmd_free(struct hifc_api_cmd_chain **chain);

#endif
