#ifndef  _PENGLAI_ENCLAVE_IOCTL
#define _PENGLAI_ENCLAVE_IOCTL
#include "penglai-enclave.h"
#include <linux/uaccess.h>
#include <linux/types.h>
#include <asm/timex.h>
#include <linux/types.h>

#define PENGLAI_ENCLAVE_IOC_CREATE_ENCLAVE \
	_IOR(PENGLAI_ENCLAVE_IOC_MAGIC, 0x00, struct penglai_enclave_user_param)
#define PENGLAI_ENCLAVE_IOC_RUN_ENCLAVE \
	_IOR(PENGLAI_ENCLAVE_IOC_MAGIC, 0x01, struct penglai_enclave_user_param)
#define PENGLAI_ENCLAVE_IOC_ATTEST_ENCLAVE \
	_IOR(PENGLAI_ENCLAVE_IOC_MAGIC, 0x02, struct penglai_enclave_ioctl_attest_enclave)
#define PENGLAI_ENCLAVE_IOC_STOP_ENCLAVE \
	_IOR(PENGLAI_ENCLAVE_IOC_MAGIC, 0x03, struct penglai_enclave_user_param)
#define PENGLAI_ENCLAVE_IOC_RESUME_ENCLAVE \
	_IOR(PENGLAI_ENCLAVE_IOC_MAGIC, 0x04, struct penglai_enclave_user_param)
#define PENGLAI_ENCLAVE_IOC_DESTROY_ENCLAVE \
	_IOW(PENGLAI_ENCLAVE_IOC_MAGIC, 0x05, struct penglai_enclave_user_param)
#define PENGLAI_ENCLAVE_IOC_DEBUG_PRINT \
	_IOW(PENGLAI_ENCLAVE_IOC_MAGIC, 0x06, struct penglai_enclave_user_param)


#define DEFAULT_CLOCK_DELAY 100000
#define DEFAULT_UNTRUSTED_PTR   0x0000001000000000
#define ENCLAVE_DEFAULT_KBUFFER_SIZE              0x1000UL
#define ENCLAVE_DEFAULT_KBUFFER         0xffffffe000000000UL

struct penglai_enclave_user_param
{
	unsigned long eid;
	unsigned long elf_ptr;
	long elf_size;
	long stack_size;
	unsigned long untrusted_mem_ptr;
	long untrusted_mem_size;
};

struct penglai_enclave_sbi_param
{
	unsigned int * eid_ptr;
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

typedef unsigned char byte;

#define MD_SIZE 64
#define MAX_ELF_SIZE 512*1024*1024
#define MAX_STACK_SIZE 64*1024*1024
#define MAX_UNTRUSTED_MEM_SIZE 16*1024*1024

//TODO: 64?
#define PRIVATE_KEY_SIZE       32
//TODO: 32?
#define PUBLIC_KEY_SIZE        64
#define HASH_SIZE              32
#define SIGNATURE_SIZE         64

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

struct signature_t
{
  unsigned char r[PUBLIC_KEY_SIZE/2];
  unsigned char s[PUBLIC_KEY_SIZE/2];
};

struct penglai_enclave_ioctl_attest_enclave
{
	unsigned long eid;
	unsigned long nonce;
	struct report_t report;
};

long penglai_enclave_ioctl(struct file* filep, unsigned int cmd, unsigned long args);

#endif
