/* SPDX-License-Identifier: GPL-2.0 */
/* Huawei Hifc PCI Express Linux driver
 * Copyright(c) 2017 Huawei Technologies Co., Ltd
 *
 */

#ifndef HIFC_CMDQ_H_
#define HIFC_CMDQ_H_

#define HIFC_DB_OFF                     0x00000800

#define HIFC_SCMD_DATA_LEN              16

#define	HIFC_CMDQ_DEPTH                 4096

#define	HIFC_CMDQ_BUF_SIZE              2048U
#define HIFC_CMDQ_BUF_HW_RSVD           8
#define HIFC_CMDQ_MAX_DATA_SIZE	\
		(HIFC_CMDQ_BUF_SIZE - HIFC_CMDQ_BUF_HW_RSVD)
#define	WQ_PAGE_PFN_SHIFT               12
#define	WQ_BLOCK_PFN_SHIFT              9

#define WQ_PAGE_PFN(page_addr)          ((page_addr) >> WQ_PAGE_PFN_SHIFT)
#define WQ_BLOCK_PFN(page_addr)         ((page_addr) >> WQ_BLOCK_PFN_SHIFT)

enum hifc_cmdq_type {
	HIFC_CMDQ_SYNC,
	HIFC_CMDQ_ASYNC,
	HIFC_MAX_CMDQ_TYPES,
};

enum hifc_db_src_type {
	HIFC_DB_SRC_CMDQ_TYPE,
	HIFC_DB_SRC_L2NIC_SQ_TYPE,
};

enum hifc_cmdq_db_type {
	HIFC_DB_SQ_RQ_TYPE,
	HIFC_DB_CMDQ_TYPE,
};

/* CMDQ WQE CTRLS */
struct hifc_cmdq_header {
	u32 header_info;
	u32 saved_data;
};

struct hifc_scmd_bufdesc {
	u32 buf_len;
	u32 rsvd;
	u8 data[HIFC_SCMD_DATA_LEN];
};

struct hifc_lcmd_bufdesc {
	struct hifc_sge sge;
	u32 rsvd1;
	u64 saved_async_buf;
	u64 rsvd3;
};

struct hifc_cmdq_db {
	u32 db_info;
	u32 rsvd;
};

struct hifc_status {
	u32 status_info;
};

struct hifc_ctrl {
	u32 ctrl_info;
};

struct hifc_sge_resp {
	struct hifc_sge sge;
	u32 rsvd;
};

struct hifc_cmdq_completion {
	/* HW Format */
	union {
		struct hifc_sge_resp sge_resp;
		u64 direct_resp;
	};
};

struct hifc_cmdq_wqe_scmd {
	struct hifc_cmdq_header	header;
	struct hifc_cmdq_db db;
	struct hifc_status status;
	struct hifc_ctrl ctrl;
	struct hifc_cmdq_completion completion;
	struct hifc_scmd_bufdesc buf_desc;
};

struct hifc_cmdq_wqe_lcmd {
	struct hifc_cmdq_header	header;
	struct hifc_status status;
	struct hifc_ctrl ctrl;
	struct hifc_cmdq_completion completion;
	struct hifc_lcmd_bufdesc buf_desc;
};

struct hifc_cmdq_inline_wqe {
	struct hifc_cmdq_wqe_scmd wqe_scmd;
};

struct hifc_cmdq_wqe {
	/* HW Format */
	union {
		struct hifc_cmdq_inline_wqe inline_wqe;
		struct hifc_cmdq_wqe_lcmd wqe_lcmd;
	};
};

struct hifc_cmdq_arm_bit {
	u32 q_type;
	u32 q_id;
};

struct hifc_cmdq_ctxt_info {
	u64 curr_wqe_page_pfn;
	u64 wq_block_pfn;
};

struct hifc_cmdq_ctxt {
	u8 status;
	u8 version;
	u8 rsvd0[6];

	u16 func_idx;
	u8 cmdq_id;
	u8 ppf_idx;

	u8 rsvd1[4];

	struct hifc_cmdq_ctxt_info ctxt_info;
};

enum hifc_cmdq_status {
	HIFC_CMDQ_ENABLE = BIT(0),
};

enum hifc_cmdq_cmd_type {
	HIFC_CMD_TYPE_NONE,
	HIFC_CMD_TYPE_SET_ARM,
	HIFC_CMD_TYPE_DIRECT_RESP,
	HIFC_CMD_TYPE_SGE_RESP,
	HIFC_CMD_TYPE_ASYNC,
	HIFC_CMD_TYPE_TIMEOUT,
	HIFC_CMD_TYPE_FAKE_TIMEOUT,
};

struct hifc_cmdq_cmd_info {
	enum hifc_cmdq_cmd_type	cmd_type;

	struct completion *done;
	int *errcode;
	int *cmpt_code;
	u64 *direct_resp;
	u64 cmdq_msg_id;
};

struct hifc_cmdq {
	struct hifc_wq *wq;

	enum hifc_cmdq_type cmdq_type;
	int wrapped;

	/* spinlock for send cmdq commands */
	spinlock_t cmdq_lock;

	/* doorbell area */
	u8 __iomem *db_base;

	struct hifc_cmdq_ctxt cmdq_ctxt;

	struct hifc_cmdq_cmd_info *cmd_infos;

	struct hifc_hwdev *hwdev;
};

struct hifc_cmdqs {
	struct hifc_hwdev *hwdev;

	struct pci_pool *cmd_buf_pool;

	struct hifc_wq *saved_wqs;

	struct hifc_cmdq_pages cmdq_pages;
	struct hifc_cmdq cmdq[HIFC_MAX_CMDQ_TYPES];

	u32 status;
	u32 disable_flag;
};

void hifc_cmdq_ceq_handler(void *hwdev, u32 ceqe_data);

int hifc_reinit_cmdq_ctxts(struct hifc_hwdev *hwdev);

bool hifc_cmdq_idle(struct hifc_cmdq *cmdq);

int hifc_cmdqs_init(struct hifc_hwdev *hwdev);

void hifc_cmdqs_free(struct hifc_hwdev *hwdev);

void hifc_cmdq_flush_cmd(struct hifc_hwdev *hwdev,
			 struct hifc_cmdq *cmdq);

#endif
