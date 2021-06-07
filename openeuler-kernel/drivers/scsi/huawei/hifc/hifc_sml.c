// SPDX-License-Identifier: GPL-2.0
/* Huawei Hifc PCI Express Linux driver
 * Copyright(c) 2017 Huawei Technologies Co., Ltd
 *
 */
#define pr_fmt(fmt) KBUILD_MODNAME ": [COMM]" fmt

#include <linux/types.h>
#include "hifc_knl_adp.h"
#include "hifc_hw.h"
#include "hifc_hwdev.h"
#include "hifc_sml.h"

#ifndef HTONL
#define HTONL(x) \
	((((x) & 0x000000ff) << 24) \
	| (((x) & 0x0000ff00) << 8) \
	| (((x) & 0x00ff0000) >> 8) \
	| (((x) & 0xff000000) >> 24))
#endif

static void sml_ctr_htonl_n(u32 *node, u32 len)
{
	u32 i;

	for (i = 0; i < len; i++) {
		*node = HTONL(*node);
		node++;
	}
}

static void hifc_sml_ctr_read_build_req(struct chipif_sml_ctr_rd_req_s *msg,
					u8 instance_id, u8 op_id,
					u8 ack, u32 ctr_id, u32 init_val)
{
	msg->head.value = 0;
	msg->head.bs.instance = instance_id;
	msg->head.bs.op_id = op_id;
	msg->head.bs.ack = ack;
	msg->head.value = HTONL(msg->head.value);

	msg->ctr_id = ctr_id;
	msg->ctr_id = HTONL(msg->ctr_id);

	msg->initial = init_val;
}

static void hifc_sml_ctr_write_build_req(struct chipif_sml_ctr_wr_req_s *msg,
					 u8 instance_id, u8 op_id,
					 u8 ack, u32 ctr_id,
					 u64 val1, u64 val2)
{
	msg->head.value = 0;
	msg->head.bs.instance = instance_id;
	msg->head.bs.op_id = op_id;
	msg->head.bs.ack = ack;
	msg->head.value = HTONL(msg->head.value);

	msg->ctr_id = ctr_id;
	msg->ctr_id = HTONL(msg->ctr_id);

	msg->value1_h = val1 >> 32;
	msg->value1_l = val1 & 0xFFFFFFFF;

	msg->value2_h = val2 >> 32;
	msg->value2_l = val2 & 0xFFFFFFFF;
}

/**
 * hifc_sm_ctr_rd32 - small single 32 counter read
 * @hwdev: the pointer to hw device
 * @node: the node id
 * @instance: instance value
 * @ctr_id: counter id
 * @value: read counter value ptr
 * Return: 0 - success, negative - failure
 */
int hifc_sm_ctr_rd32(void *hwdev, u8 node, u8 instance, u32 ctr_id, u32 *value)
{
	struct chipif_sml_ctr_rd_req_s req;
	union ctr_rd_rsp_u rsp;
	int ret;

	if (!hwdev || !value)
		return -EFAULT;

	hifc_sml_ctr_read_build_req(&req, instance, CHIPIF_SM_CTR_OP_READ,
				    CHIPIF_ACK, ctr_id, 0);

	ret = hifc_api_cmd_read_ack(hwdev, node, (u8 *)&req,
				    (unsigned short)sizeof(req),
				    (void *)&rsp, (unsigned short)sizeof(rsp));
	if (ret) {
		sdk_err(((struct hifc_hwdev *)hwdev)->dev_hdl,
			"Sm 32bit counter read fail, err(%d)\n", ret);
		return ret;
	}
	sml_ctr_htonl_n((u32 *)&rsp, 4);
	*value = rsp.bs_ss32_rsp.value1;

	return 0;
}

/**
 * hifc_sm_ctr_rd32_clear - small single 32 counter read and clear to zero
 * @hwdev: the pointer to hw device
 * @node: the node id
 * @instance: instance value
 * @ctr_id: counter id
 * @value: read counter value ptr
 * Return: 0 - success, negative - failure
 * according to ACN error code (ERR_OK, ERR_PARAM, ERR_FAILED...etc)
 */
int hifc_sm_ctr_rd32_clear(void *hwdev, u8 node, u8 instance,
			   u32 ctr_id, u32 *value)
{
	struct chipif_sml_ctr_rd_req_s req;
	union ctr_rd_rsp_u rsp;
	int ret;

	if (!hwdev || !value)
		return -EFAULT;

	hifc_sml_ctr_read_build_req(&req, instance,
				    CHIPIF_SM_CTR_OP_READ_CLEAR,
				    CHIPIF_ACK, ctr_id, 0);

	ret = hifc_api_cmd_read_ack(hwdev, node, (u8 *)&req,
				    (unsigned short)sizeof(req),
				    (void *)&rsp, (unsigned short)sizeof(rsp));

	if (ret) {
		sdk_err(((struct hifc_hwdev *)hwdev)->dev_hdl,
			"Sm 32bit counter clear fail, err(%d)\n", ret);
		return ret;
	}
	sml_ctr_htonl_n((u32 *)&rsp, 4);
	*value = rsp.bs_ss32_rsp.value1;

	return 0;
}

/**
 * hifc_sm_ctr_wr32 - small single 32 counter write
 * @hwdev: the pointer to hw device
 * @node: the node id
 * @instance: instance value
 * @ctr_id: counter id
 * @value: write counter value
 * Return: 0 - success, negative - failure
 */
int hifc_sm_ctr_wr32(void *hwdev, u8 node, u8 instance, u32 ctr_id, u32 value)
{
	struct chipif_sml_ctr_wr_req_s req;
	struct chipif_sml_ctr_wr_rsp_s rsp;

	if (!hwdev)
		return -EFAULT;

	hifc_sml_ctr_write_build_req(&req, instance, CHIPIF_SM_CTR_OP_WRITE,
				     CHIPIF_NOACK, ctr_id, (u64)value, 0ULL);

	return hifc_api_cmd_read_ack(hwdev, node, (u8 *)&req,
				     (unsigned short)sizeof(req), (void *)&rsp,
				     (unsigned short)sizeof(rsp));
}

/**
 * hifc_sm_ctr_rd64 - big counter 64 read
 * @hwdev: the pointer to hw device
 * @node: the node id
 * @instance: instance value
 * @ctr_id: counter id
 * @value: read counter value ptr
 * Return: 0 - success, negative - failure
 */
int hifc_sm_ctr_rd64(void *hwdev, u8 node, u8 instance, u32 ctr_id, u64 *value)
{
	struct chipif_sml_ctr_rd_req_s req;
	union ctr_rd_rsp_u rsp;
	int ret;

	if (!hwdev || !value)
		return -EFAULT;

	hifc_sml_ctr_read_build_req(&req, instance, CHIPIF_SM_CTR_OP_READ,
				    CHIPIF_ACK, ctr_id, 0);

	ret = hifc_api_cmd_read_ack(hwdev, node, (u8 *)&req,
				    (unsigned short)sizeof(req), (void *)&rsp,
				    (unsigned short)sizeof(rsp));
	if (ret) {
		sdk_err(((struct hifc_hwdev *)hwdev)->dev_hdl,
			"Sm 64bit counter read fail err(%d)\n", ret);
		return ret;
	}
	sml_ctr_htonl_n((u32 *)&rsp, 4);
	*value = ((u64)rsp.bs_bs64_rsp.value1 << 32) | rsp.bs_bs64_rsp.value2;

	return 0;
}

/**
 * hifc_sm_ctr_wr64 - big single 64 counter write
 * @hwdev: the pointer to hw device
 * @node: the node id
 * @instance: instance value
 * @ctr_id: counter id
 * @value: write counter value
 * Return: 0 - success, negative - failure
 */
int hifc_sm_ctr_wr64(void *hwdev, u8 node, u8 instance, u32 ctr_id, u64 value)
{
	struct chipif_sml_ctr_wr_req_s req;
	struct chipif_sml_ctr_wr_rsp_s rsp;

	if (!hwdev)
		return -EFAULT;

	hifc_sml_ctr_write_build_req(&req, instance, CHIPIF_SM_CTR_OP_WRITE,
				     CHIPIF_NOACK, ctr_id, value, 0ULL);

	return hifc_api_cmd_read_ack(hwdev, node, (u8 *)&req,
				     (unsigned short)sizeof(req), (void *)&rsp,
				     (unsigned short)sizeof(rsp));
}

/**
 * hifc_sm_ctr_rd64_pair - big pair 128 counter read
 * @hwdev: the pointer to hw device
 * @node: the node id
 * @instance: instance value
 * @ctr_id: counter id
 * @value1: read counter value ptr
 * @value2: read counter value ptr
 * Return: 0 - success, negative - failure
 */
int hifc_sm_ctr_rd64_pair(void *hwdev, u8 node, u8 instance,
			  u32 ctr_id, u64 *value1, u64 *value2)
{
	struct chipif_sml_ctr_rd_req_s req;
	union ctr_rd_rsp_u rsp;
	int ret;

	if (!hwdev || (0 != (ctr_id & 0x1)) || !value1 || !value2) {
		pr_err("Hwdev(0x%p) or value1(0x%p) or value2(0x%p) is NULL or ctr_id(%d) is odd number\n",
		       hwdev, value1, value2, ctr_id);
		return -EFAULT;
	}

	hifc_sml_ctr_read_build_req(&req, instance, CHIPIF_SM_CTR_OP_READ,
				    CHIPIF_ACK, ctr_id, 0);

	ret = hifc_api_cmd_read_ack(hwdev, node, (u8 *)&req,
				    (unsigned short)sizeof(req), (void *)&rsp,
				    (unsigned short)sizeof(rsp));
	if (ret) {
		sdk_err(((struct hifc_hwdev *)hwdev)->dev_hdl,
			"Sm 64 bit rd pair ret(%d)\n", ret);
		return ret;
	}
	sml_ctr_htonl_n((u32 *)&rsp, 4);
	*value1 = ((u64)rsp.bs_bp64_rsp.val1_h << 32) | rsp.bs_bp64_rsp.val1_l;
	*value2 = ((u64)rsp.bs_bp64_rsp.val2_h << 32) | rsp.bs_bp64_rsp.val2_l;

	return 0;
}

/**
 * hifc_sm_ctr_wr64_pair - big pair 128 counter write
 * @hwdev: the pointer to hw device
 * @node: the node id
 * @ctr_id: counter id
 * @instance: instance value
 * @value1: write counter value
 * @value2: write counter value
 * Return: 0 - success, negative - failure
 */
int hifc_sm_ctr_wr64_pair(void *hwdev, u8 node, u8 instance,
			  u32 ctr_id, u64 value1, u64 value2)
{
	struct chipif_sml_ctr_wr_req_s req;
	struct chipif_sml_ctr_wr_rsp_s rsp;

	/* pair pattern ctr_id must be even number */
	if (!hwdev || (0 != (ctr_id & 0x1))) {
		pr_err("Handle is NULL or ctr_id(%d) is odd number for write 64 bit pair\n",
		       ctr_id);
		return -EFAULT;
	}

	hifc_sml_ctr_write_build_req(&req, instance, CHIPIF_SM_CTR_OP_WRITE,
				     CHIPIF_NOACK, ctr_id, value1, value2);
	return hifc_api_cmd_read_ack(hwdev, node, (u8 *)&req,
				     (unsigned short)sizeof(req), (void *)&rsp,
				     (unsigned short)sizeof(rsp));
}

int hifc_api_csr_rd32(void *hwdev, u8 dest, u32 addr, u32 *val)
{
	struct hifc_csr_request_api_data api_data = {0};
	u32 csr_val = 0;
	u16 in_size = sizeof(api_data);
	int ret;

	if (!hwdev || !val)
		return -EFAULT;

	memset(&api_data, 0, sizeof(struct hifc_csr_request_api_data));
	api_data.dw0 = 0;
	api_data.dw1.bits.operation_id = HIFC_CSR_OPERATION_READ_CSR;
	api_data.dw1.bits.need_response = HIFC_CSR_NEED_RESP_DATA;
	api_data.dw1.bits.data_size = HIFC_CSR_DATA_SZ_32;
	api_data.dw1.val32 = cpu_to_be32(api_data.dw1.val32);
	api_data.dw2.bits.csr_addr = addr;
	api_data.dw2.val32 = cpu_to_be32(api_data.dw2.val32);

	ret = hifc_api_cmd_read_ack(hwdev, dest, (u8 *)(&api_data),
				    in_size, &csr_val, 4);
	if (ret) {
		sdk_err(((struct hifc_hwdev *)hwdev)->dev_hdl,
			"Read 32 bit csr fail, dest %d addr 0x%x, ret: 0x%x\n",
			dest, addr, ret);
		return ret;
	}

	*val = csr_val;

	return 0;
}

int hifc_api_csr_wr32(void *hwdev, u8 dest, u32 addr, u32 val)
{
	struct hifc_csr_request_api_data api_data;
	u16 in_size = sizeof(api_data);
	int ret;

	if (!hwdev)
		return -EFAULT;

	memset(&api_data, 0, sizeof(struct hifc_csr_request_api_data));
	api_data.dw1.bits.operation_id = HIFC_CSR_OPERATION_WRITE_CSR;
	api_data.dw1.bits.need_response = HIFC_CSR_NO_RESP_DATA;
	api_data.dw1.bits.data_size = HIFC_CSR_DATA_SZ_32;
	api_data.dw1.val32 = cpu_to_be32(api_data.dw1.val32);
	api_data.dw2.bits.csr_addr = addr;
	api_data.dw2.val32 = cpu_to_be32(api_data.dw2.val32);
	api_data.csr_write_data_h = 0xffffffff;
	api_data.csr_write_data_l = val;

	ret = hifc_api_cmd_write_nack(hwdev, dest, (u8 *)(&api_data), in_size);
	if (ret) {
		sdk_err(((struct hifc_hwdev *)hwdev)->dev_hdl,
			"Write 32 bit csr fail! dest %d addr 0x%x val 0x%x\n",
			dest, addr, val);
		return ret;
	}

	return 0;
}
