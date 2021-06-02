#ifndef _SM_H
#define _SM_H

//#ifndef TARGET_PLATFORM_HEADER
//#error "SM requires to specify a certain platform"
//#endif

//#include TARGET_PLATFORM_HEADER
#include <sm/print.h>
#include <sm/platform/spmp/platform.h>
#include <stdint.h>
#include <sm/enclave_args.h>
#include <sm/ipi.h>

#define SM_BASE 0x80000000
#define SM_SIZE 0x200000

#define MAX_HARTS 8

//SBI_CALL NUMBERS
#define SBI_MM_INIT            100
#define SBI_CREATE_ENCLAVE      99
#define SBI_ATTEST_ENCLAVE      98
#define SBI_RUN_ENCLAVE         97
#define SBI_STOP_ENCLAVE        96
#define SBI_RESUME_ENCLAVE      95
#define SBI_DESTROY_ENCLAVE     94
#define SBI_ALLOC_ENCLAVE_MM    93
#define SBI_MEMORY_EXTEND       92
#define SBI_MEMORY_RECLAIM      91
#define SBI_ENCLAVE_OCALL       90
#define SBI_EXIT_ENCLAVE        89
#define SBI_DEBUG_PRINT         88

//Error code of SBI_ALLOC_ENCLAVE_MEM
#define ENCLAVE_NO_MEMORY       -2
#define ENCLAVE_ERROR           -1
#define ENCLAVE_SUCCESS          0
#define ENCLAVE_TIMER_IRQ        1

//error code of SBI_RESUME_RNCLAVE
#define RESUME_FROM_TIMER_IRQ    2000
#define RESUME_FROM_STOP         2003

void sm_init();

uintptr_t sm_mm_init(uintptr_t paddr, unsigned long size);

uintptr_t sm_mm_extend(uintptr_t paddr, unsigned long size);

uintptr_t sm_alloc_enclave_mem(uintptr_t mm_alloc_arg);

uintptr_t sm_create_enclave(uintptr_t enclave_create_args);

uintptr_t sm_attest_enclave(uintptr_t enclave_id, uintptr_t report, uintptr_t nonce);

uintptr_t sm_run_enclave(uintptr_t *regs, uintptr_t enclave_id);

uintptr_t sm_debug_print(uintptr_t *regs, uintptr_t enclave_id);

uintptr_t sm_stop_enclave(uintptr_t *regs, uintptr_t enclave_id);

uintptr_t sm_resume_enclave(uintptr_t *regs, uintptr_t enclave_id);

uintptr_t sm_destroy_enclave(uintptr_t *regs, uintptr_t enclave_id, uintptr_t destroy_flag);

uintptr_t sm_enclave_ocall(uintptr_t *regs, uintptr_t ocall_func_id, uintptr_t arg);

uintptr_t sm_exit_enclave(uintptr_t *regs, unsigned long retval);

uintptr_t sm_do_timer_irq(uintptr_t *regs, uintptr_t mcause, uintptr_t mepc);

int check_in_enclave_world();

#endif /* _SM_H */
