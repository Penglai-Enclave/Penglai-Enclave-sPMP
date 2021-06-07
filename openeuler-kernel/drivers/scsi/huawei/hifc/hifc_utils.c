// SPDX-License-Identifier: GPL-2.0
/* Huawei Hifc PCI Express Linux driver
 * Copyright(c) 2017 Huawei Technologies Co., Ltd
 *
 */
#include "hifc_utils.h"
#include "unf_log.h"
#include "unf_common.h"

void hifc_cpu_to_big64(void *v_addr, unsigned int size)
{
	unsigned int index = 0;
	unsigned int cnt = 0;
	unsigned long long *temp = NULL;

	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE,
			v_addr, dump_stack(); return);
	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE,
			(size % HIFC_QWORD_BYTE) == 0, dump_stack(); return);

	temp = (unsigned long long *)v_addr;
	cnt = HIFC_SHIFT_TO_U64(size);

	for (index = 0; index < cnt; index++) {
		*temp = cpu_to_be64(*temp);
		temp++;
	}
}

void hifc_big_to_cpu64(void *v_addr, unsigned int size)
{
	unsigned int index = 0;
	unsigned int cnt = 0;
	unsigned long long *tmp = NULL;

	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE,
			v_addr, dump_stack(); return);
	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE,
			(size % HIFC_QWORD_BYTE) == 0, dump_stack(); return);

	tmp = (unsigned long long *)v_addr;
	cnt = HIFC_SHIFT_TO_U64(size);

	for (index = 0; index < cnt; index++) {
		*tmp = be64_to_cpu(*tmp);
		tmp++;
	}
}

void hifc_cpu_to_big32(void *v_addr, unsigned int size)
{
	unf_cpu_to_big_end(v_addr, size);
}

void hifc_big_to_cpu32(void *v_addr, unsigned int size)
{
	if (size % UNF_BYTES_OF_DWORD)
		dump_stack();
	unf_big_end_to_cpu(v_addr, size);
}

unsigned int hifc_log2n(unsigned int val)
{
	unsigned int result = 0;
	unsigned int logn = (val >> 1);

	while (logn) {
		logn >>= 1;
		result++;
	}
	return result;
}
