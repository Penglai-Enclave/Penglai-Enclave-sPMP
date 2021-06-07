/* SPDX-License-Identifier: GPL-2.0 */
/* Huawei Hifc PCI Express Linux driver
 * Copyright(c) 2017 Huawei Technologies Co., Ltd
 *
 */

#ifndef __CHIPIF_SML_COUNTER_H__
#define __CHIPIF_SML_COUNTER_H__

#define CHIPIF_FUNC_PF  0
#define CHIPIF_FUNC_VF  1
#define CHIPIF_FUNC_PPF 2

#define CHIPIF_ACK 1
#define CHIPIF_NOACK 0

#define CHIPIF_SM_CTR_OP_READ 0x2
#define CHIPIF_SM_CTR_OP_READ_CLEAR 0x6
#define CHIPIF_SM_CTR_OP_WRITE 0x3

#define SMALL_CNT_READ_RSP_SIZE 16

/* request head */
union chipif_sml_ctr_req_head_u {
	struct {
		u32  pad:15;
		u32  ack:1;
		u32  op_id:5;
		u32  instance:6;
		u32  src:5;
	} bs;

	u32 value;
};

/* counter read request struct */
struct chipif_sml_ctr_rd_req_s {
	u32 extra;
	union chipif_sml_ctr_req_head_u head;
	u32 ctr_id;
	u32 initial;
	u32 pad;
};

/* counter read response union */
union ctr_rd_rsp_u {
	struct {
		u32 value1:16;
		u32 pad0:16;
		u32 pad1[3];
	} bs_ss16_rsp;

	struct {
		u32 value1;
		u32 pad[3];
	} bs_ss32_rsp;

	struct {
		u32 value1:20;
		u32 pad0:12;
		u32 value2:12;
		u32 pad1:20;
		u32 pad2[2];
	} bs_sp_rsp;

	struct {
		u32 value1;
		u32 value2;
		u32 pad[2];
	} bs_bs64_rsp;

	struct {
		u32 val1_h;
		u32 val1_l;
		u32 val2_h;
		u32 val2_l;
	} bs_bp64_rsp;

};

/* resopnse head */
union sml_ctr_rsp_head_u {
	struct {
		u32 pad:30; /* reserve */
		u32 code:2;  /* error code */
	} bs;

	u32 value;
};

/* counter write request struct */
struct chipif_sml_ctr_wr_req_s {
	u32 extra;
	union chipif_sml_ctr_req_head_u head;
	u32 ctr_id;
	u32 rsv1;
	u32 rsv2;
	u32 value1_h;
	u32 value1_l;
	u32 value2_h;
	u32 value2_l;
};

/* counter write response struct */
struct chipif_sml_ctr_wr_rsp_s {
	union sml_ctr_rsp_head_u head;
	u32 pad[3];
};

enum HIFC_CSR_API_DATA_OPERATION_ID {
	HIFC_CSR_OPERATION_WRITE_CSR = 0x1E,
	HIFC_CSR_OPERATION_READ_CSR = 0x1F
};

enum HIFC_CSR_API_DATA_NEED_RESPONSE_DATA {
	HIFC_CSR_NO_RESP_DATA = 0,
	HIFC_CSR_NEED_RESP_DATA = 1
};

enum HIFC_CSR_API_DATA_DATA_SIZE {
	HIFC_CSR_DATA_SZ_32 = 0,
	HIFC_CSR_DATA_SZ_64 = 1
};

struct hifc_csr_request_api_data {
	u32 dw0;

	union {
		struct {
			u32 reserved1:13;
			/* this field indicates the write/read data size:
			 * 2'b00: 32 bits
			 * 2'b01: 64 bits
			 * 2'b10~2'b11:reserved
			 */
			u32 data_size:2;
			/* this field indicates that requestor expect receive a
			 * response data or not.
			 * 1'b0: expect not to receive a response data.
			 * 1'b1: expect to receive a response data.
			 */
			u32 need_response:1;
			/* this field indicates the operation that the requestor
			 *  expected.
			 * 5'b1_1110: write value to csr space.
			 * 5'b1_1111: read register from csr space.
			 */
			u32 operation_id:5;
			u32 reserved2:6;
			/* this field specifies the Src node ID for this API
			 * request message.
			 */
			u32 src_node_id:5;
		} bits;

		u32 val32;
	} dw1;

	union {
		struct {
			/* it specifies the CSR address. */
			u32 csr_addr:26;
			u32 reserved3:6;
		} bits;

		u32 val32;
	} dw2;

	/* if data_size=2'b01, it is high 32 bits of write data. else, it is
	 * 32'hFFFF_FFFF.
	 */
	u32 csr_write_data_h;
	/* the low 32 bits of write data. */
	u32 csr_write_data_l;
};

int hifc_sm_ctr_rd32(void *hwdev, u8 node, u8 instance, u32 ctr_id, u32 *value);
int hifc_sm_ctr_rd64(void *hwdev, u8 node, u8 instance, u32 ctr_id, u64 *value);
int hifc_sm_ctr_rd64_pair(void *hwdev, u8 node, u8 instance,
			  u32 ctr_id, u64 *value1, u64 *value2);

#endif
