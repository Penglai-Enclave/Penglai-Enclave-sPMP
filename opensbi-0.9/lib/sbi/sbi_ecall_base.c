/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2020 Western Digital Corporation or its affiliates.
 *
 * Authors:
 *   Anup Patel <anup.patel@wdc.com>
 *   Atish Patra <atish.patra@wdc.com>
 */

#include <sbi/sbi_ecall.h>
#include <sbi/sbi_ecall_interface.h>
#include <sbi/sbi_error.h>
#include <sbi/sbi_trap.h>
#include <sbi/sbi_version.h>
#include <sbi/riscv_asm.h>

// #include <sbi/sbi_console.h>

static int sbi_ecall_base_probe(unsigned long extid, unsigned long *out_val)
{
	struct sbi_ecall_extension *ext;

	ext = sbi_ecall_find_extension(extid);
	if (!ext) {
		*out_val = 0;
		return 0;
	}

	if (ext->probe)
		return ext->probe(extid, out_val);

	*out_val = 1;
	return 0;
}

/* Declare Penglai SM handlers here*/
// extern uintptr_t sm_mm_init(uintptr_t paddr, unsigned long size);
// extern uintptr_t sm_mm_extend(uintptr_t paddr, unsigned long size);
// extern uintptr_t sm_alloc_enclave_mem(uintptr_t mm_alloc_arg);
// extern uintptr_t sm_create_enclave(uintptr_t enclave_sbi_param);
// extern uintptr_t sm_run_enclave(uintptr_t* regs, unsigned long eid);
// extern uintptr_t sm_exit_enclave(uintptr_t* regs, unsigned long retval);

static int sbi_ecall_base_handler(unsigned long extid, unsigned long funcid,
				  const struct sbi_trap_regs *regs,
				  unsigned long *out_val,
				  struct sbi_trap_info *out_trap)
{
	int ret = 0;

	switch (funcid) {
	case SBI_EXT_BASE_GET_SPEC_VERSION:
		*out_val = (SBI_ECALL_VERSION_MAJOR <<
			   SBI_SPEC_VERSION_MAJOR_OFFSET) &
			   (SBI_SPEC_VERSION_MAJOR_MASK <<
			    SBI_SPEC_VERSION_MAJOR_OFFSET);
		*out_val = *out_val | SBI_ECALL_VERSION_MINOR;
		break;
	case SBI_EXT_BASE_GET_IMP_ID:
		*out_val = sbi_ecall_get_impid();
		break;
	case SBI_EXT_BASE_GET_IMP_VERSION:
		*out_val = OPENSBI_VERSION;
		break;
	case SBI_EXT_BASE_GET_MVENDORID:
		*out_val = csr_read(CSR_MVENDORID);
		break;
	case SBI_EXT_BASE_GET_MARCHID:
		*out_val = csr_read(CSR_MARCHID);
		break;
	case SBI_EXT_BASE_GET_MIMPID:
		*out_val = csr_read(CSR_MIMPID);
		break;
	case SBI_EXT_BASE_PROBE_EXT:
		ret = sbi_ecall_base_probe(regs->a0, out_val);
		break;
	// The following is the Penglai's Handler
	// case SBI_MM_INIT:
	//   ret = sm_mm_init(regs->a0, regs->a1);
	//   break;
	// case SBI_MEMORY_EXTEND:
	//   ret = sm_mm_extend(regs->a0, regs->a1);
	//   break;
	// case SBI_ALLOC_ENCLAVE_MM:
	//   ret = sm_alloc_enclave_mem(regs->a0);
	//   break;
	// case SBI_CREATE_ENCLAVE:
	//   ret = sm_create_enclave(regs->a0);
	//   break;
	// case SBI_RUN_ENCLAVE:
	//   ret = sm_run_enclave((uintptr_t *)regs, regs->a0);
	//   break;
	// case SBI_EXIT_ENCLAVE:
	//   ret = sm_exit_enclave((uintptr_t *)regs, regs->a0);
	//   break;
	default:
		ret = SBI_ENOTSUPP;
	}

	return ret;
}

struct sbi_ecall_extension ecall_base = {
	.extid_start = SBI_EXT_BASE,
	.extid_end = SBI_EXT_BASE,
	.handle = sbi_ecall_base_handler,
};
