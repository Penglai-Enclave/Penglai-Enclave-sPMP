#ifndef _ENCLAVE_ARGS_H
#define _ENCLAVE_ARGS_H
#include "thread.h"
#define HASH_SIZE              32
#define PRIVATE_KEY_SIZE       32
#define PUBLIC_KEY_SIZE        64
#define SIGNATURE_SIZE         64

#define MANU_PUB_KEY           (void*)((unsigned long)0x801ff000)
#define DEV_PUB_KEY            (MANU_PUB_KEY + PUBLIC_KEY_SIZE)
#define DEV_PRI_KEY            (DEV_PUB_KEY + PUBLIC_KEY_SIZE)
#define SM_PUB_KEY             (DEV_PRI_KEY + PRIVATE_KEY_SIZE)
#define SM_PRI_KEY             (SM_PUB_KEY + PUBLIC_KEY_SIZE)
#define SM_HASH                (SM_PRI_KEY + PRIVATE_KEY_SIZE)
#define SM_SIGNATURE           (SM_HASH + HASH_SIZE)

struct mm_alloc_arg_t
{
  unsigned long req_size;
  uintptr_t resp_addr;
  unsigned long resp_size;
};

// Attestation-related report
struct sm_report_t
{
  unsigned char hash[HASH_SIZE];
  unsigned char signature[SIGNATURE_SIZE];
  unsigned char sm_pub_key[PUBLIC_KEY_SIZE];
};

struct enclave_report_t
{
  unsigned char hash[HASH_SIZE];
  unsigned char signature[SIGNATURE_SIZE];
  uintptr_t nonce;
};

struct report_t
{
  struct sm_report_t sm;
  struct enclave_report_t enclave;
  unsigned char dev_pub_key[PUBLIC_KEY_SIZE];
};

struct prikey_t
{
  unsigned char dA[PRIVATE_KEY_SIZE];
};

struct pubkey_t
{
  unsigned char xA[PUBLIC_KEY_SIZE/2];
  unsigned char yA[PUBLIC_KEY_SIZE/2];
};

struct signature_t
{
  unsigned char r[PUBLIC_KEY_SIZE/2];
  unsigned char s[PUBLIC_KEY_SIZE/2];
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
  //enclave shared mem with kernel
  unsigned long kbuffer;
  unsigned long kbuffer_size;
  unsigned long *ecall_arg0;
  unsigned long *ecall_arg1;
  unsigned long *ecall_arg2;
  unsigned long *ecall_arg3;
};

#endif /* _ENCLAVE_ARGS_H */
