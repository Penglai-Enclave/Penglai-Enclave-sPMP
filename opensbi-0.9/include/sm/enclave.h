#ifndef _ENCLAVE_H
#define _ENCLAVE_H

#include <sbi/riscv_asm.h>
#include <sm/vm.h>
#include <sbi/riscv_encoding.h>
#include <sm/enclave_args.h>
#include <sbi/riscv_atomic.h>
#include <sm/thread.h>
#include <stdint.h>
#include <stddef.h>

#define ENCLAVES_PER_METADATA_REGION 128
#define ENCLAVE_METADATA_REGION_SIZE ((sizeof(struct enclave_t)) * ENCLAVES_PER_METADATA_REGION)

#define ENCLAVE_MODE 1

// define the time slice for an enclave
#define ENCLAVE_TIME_CREDITS 100000

struct link_mem_t
{
  unsigned long mem_size;
  unsigned long slab_size;
  unsigned long slab_num;
  char* addr;
  struct link_mem_t* next_link_mem;
};

typedef enum
{
  DESTROYED = -1,
  INVALID = 0,
  FRESH = 1,
  RUNNABLE,
  RUNNING,
  STOPPED,
} enclave_state_t;

/*
 * enclave memory [paddr, paddr + size]
 * free_mem @ unused memory address in enclave mem
 */
struct enclave_t
{
  unsigned int eid;
  enclave_state_t state;

  //memory region of enclave
  unsigned long paddr;
  unsigned long size;

  //address of left available memory in memory region
  unsigned long free_mem;

  //TODO: dynamically allocated memory
  unsigned long* enclave_mem_metadata_page;

  //root page table of enclave
  unsigned long* root_page_table;
  //root page table register for host
  unsigned long host_ptbr;
  //entry point of enclave
  unsigned long entry_point;

  //shared mem with kernel
  unsigned long kbuffer;
  unsigned long kbuffer_size;

  unsigned long* ocall_func_id;
  unsigned long* ocall_arg0;
  unsigned long* ocall_arg1;
  unsigned long* ocall_syscall_num;

  //shared memory with host
  unsigned long untrusted_ptr;
  unsigned long untrusted_size;

  //enclave thread context
  //TODO: support multiple threads
  struct thread_state_t thread_context;
};

struct cpu_state_t
{
  int in_enclave;
  int eid;
};

uintptr_t create_enclave(struct enclave_sbi_param_t create_args);
uintptr_t run_enclave(uintptr_t* regs, unsigned int eid);
uintptr_t stop_enclave(uintptr_t* regs, unsigned int eid);
uintptr_t destroy_enclave(uintptr_t* regs, unsigned int eid);
uintptr_t resume_enclave(uintptr_t* regs, unsigned int eid);
uintptr_t resume_from_stop(uintptr_t* regs, unsigned int eid);
uintptr_t exit_enclave(uintptr_t* regs, unsigned long retval);
uintptr_t do_timer_irq(uintptr_t* regs, uintptr_t mcause, uintptr_t mepc);

uintptr_t resume_from_ocall(uintptr_t* regs, unsigned int eid);
uintptr_t enclave_sys_write(uintptr_t *regs);
uintptr_t enclave_custom_ocall(uintptr_t *regs, uintptr_t ocall_buf_size);

int check_in_enclave_world();

#endif /* _ENCLAVE_H */
