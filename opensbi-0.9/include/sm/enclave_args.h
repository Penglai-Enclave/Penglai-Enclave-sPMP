#ifndef _ENCLAVE_ARGS_H
#define _ENCLAVE_ARGS_H
#include "thread.h"

struct mm_alloc_arg_t
{
  unsigned long req_size;
  uintptr_t resp_addr;
  unsigned long resp_size;
};

/*
 * enclave memory [paddr, paddr + size]
 * free_mem @ unused memory address in enclave mem
 */
struct enclave_sbi_param_t
{
  unsigned int *eid_ptr;
  unsigned long paddr;
  unsigned long size;
  unsigned long entry_point;
  unsigned long untrusted_ptr;
  unsigned long untrusted_size;
  unsigned long free_mem;
  unsigned long *ecall_arg0;
  unsigned long *ecall_arg1;
  unsigned long *ecall_arg2;
  unsigned long *ecall_arg3;
};

#endif /* _ENCLAVE_ARGS_H */
