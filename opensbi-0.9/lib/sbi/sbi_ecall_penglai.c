/*
 * Authors:
 *   Dong Du <Dd_nirvana@sjtu.edu.cn>
 *   Erhu Feng <2748250768@qq.com>
 */

#include <sbi/sbi_ecall.h>
#include <sbi/sbi_ecall_interface.h>
#include <sbi/sbi_error.h>
#include <sbi/sbi_trap.h>
#include <sbi/sbi_version.h>
#include <sbi/riscv_asm.h>
#include <sbi/sbi_console.h>
#include <sm/sm.h>


static int sbi_ecall_penglai_host_handler(unsigned long extid, unsigned long funcid,
		const struct sbi_trap_regs *regs, unsigned long *out_val,
		struct sbi_trap_info *out_trap)
{
	uintptr_t ret = 0;

	//csr_write(CSR_MEPC, regs->mepc + 4);
	((struct sbi_trap_regs *)regs)->mepc += 4;

	switch (funcid) {
		// The following is the Penglai's Handler
		case SBI_MM_INIT:
			ret = sm_mm_init(regs->a0, regs->a1);
			break;
		case SBI_MEMORY_EXTEND:
			ret = sm_mm_extend(regs->a0, regs->a1);
			break;
		case SBI_ALLOC_ENCLAVE_MM:
			ret = sm_alloc_enclave_mem(regs->a0);
			break;
		case SBI_CREATE_ENCLAVE:
			ret = sm_create_enclave(regs->a0);
			break;
		case SBI_RUN_ENCLAVE:
			ret = sm_run_enclave((uintptr_t *)regs, regs->a0);
			break;
		case SBI_ATTEST_ENCLAVE:
			ret = sm_attest_enclave(regs->a0, regs->a1, regs->a2);
			break;
		case SBI_STOP_ENCLAVE:
			ret = sm_stop_enclave((uintptr_t *)regs, regs->a0);
			break;
		case SBI_RESUME_ENCLAVE:
			ret = sm_resume_enclave((uintptr_t *)regs, regs->a0);
			break;
		case SBI_DESTROY_ENCLAVE:
			ret = sm_destroy_enclave((uintptr_t *)regs, regs->a0);
			break;
		default:
			sbi_printf("[Penglai@Monitor] host interface(funcid:%ld) not supported yet\n", funcid);
			ret = SBI_ENOTSUPP;
	}
	//((struct sbi_trap_regs *)regs)->mepc = csr_read(CSR_MEPC);
	//((struct sbi_trap_regs *)regs)->mstatus = csr_read(CSR_MSTATUS);
	*out_val = ret;
	return ret;
}

struct sbi_ecall_extension ecall_penglai_host = {
	.extid_start = SBI_EXT_PENGLAI_HOST,
	.extid_end = SBI_EXT_PENGLAI_HOST,
	.handle = sbi_ecall_penglai_host_handler,
};

static int sbi_ecall_penglai_enclave_handler(unsigned long extid, unsigned long funcid,
		const struct sbi_trap_regs *regs, unsigned long *out_val,
		struct sbi_trap_info *out_trap)
{
	uintptr_t ret = 0;

	//csr_write(CSR_MEPC, regs->mepc + 4);
	((struct sbi_trap_regs *)regs)->mepc += 4;

	switch (funcid) {
		// The following is the Penglai's Handler
		case SBI_EXIT_ENCLAVE:
			ret = sm_exit_enclave((uintptr_t *)regs, regs->a0);
			break;
		case SBI_ENCLAVE_OCALL:
			ret = sm_enclave_ocall((uintptr_t *)regs, regs->a0, regs->a1, regs->a2);
			break;
		default:
			sbi_printf("[Penglai@Monitor] enclave interface(funcid:%ld) not supported yet\n", funcid);
			ret = SBI_ENOTSUPP;
	}
	*out_val = ret;
	return ret;
}

struct sbi_ecall_extension ecall_penglai_enclave = {
	.extid_start = SBI_EXT_PENGLAI_ENCLAVE,
	.extid_end = SBI_EXT_PENGLAI_ENCLAVE,
	.handle = sbi_ecall_penglai_enclave_handler,
};
