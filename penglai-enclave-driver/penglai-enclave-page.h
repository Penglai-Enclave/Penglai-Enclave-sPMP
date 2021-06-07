#ifndef  _PENGLAI_ENCLAVE_PAGE
#define _PENGLAI_ENCLAVE_PAGE

#include <asm/sbi.h>
#include <asm/csr.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/uaccess.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/idr.h>
#include <linux/dma-mapping.h>
#include <linux/list.h>

#include <linux/file.h>
#include "riscv64.h"

typedef uintptr_t vaddr_t;
typedef uintptr_t paddr_t;
typedef unsigned long pt_entry_t;

#define RISCV_PT_SHIFT 12
#define RISCV_PT_LEVEL 3
#define RISCV_PT_LEVELBITS 9
#define RISCV_PTE_PERMBITS 10
#define RISCV_PT_SIZE (1 << RISCV_PT_SHIFT)
#define ENCLAVE_USER_PAGE PTE_D | PTE_A | PTE_R | PTE_X | PTE_W | PTE_U
#define ENCLAVE_STACK_PAGE PTE_D | PTE_A | PTE_R | PTE_W | PTE_U
#define ENCLAVE_UNTRUSTED_PAGE PTE_D | PTE_A | PTE_R | PTE_W | PTE_U

/* Abstract for enclave memory (secure memory) */
struct enclave_mem
{
  pt_entry_t* enclave_root_pt;
  struct list_head free_mem;
  unsigned long size;
  vaddr_t vaddr;
  paddr_t paddr;
};

typedef struct enclave_mem enclave_mem_t;

struct untrusted_mem
{
  vaddr_t addr;
  long size;
};

typedef struct untrusted_mem untrusted_mem_t;

/* Free memory list in-enclave */
struct free_mem_t 
{
  vaddr_t vaddr;
  struct list_head  free_mem_list;
};

vaddr_t enclave_alloc_page(enclave_mem_t* enclave_mem, vaddr_t vaddr, unsigned long flags);
void enclave_mem_int(enclave_mem_t* enclave_mem, vaddr_t vaddr, int size, paddr_t paddr);
vaddr_t get_free_mem(struct list_head* free_mem);
int enclave_mem_destroy(enclave_mem_t * enclave_mem);
vaddr_t map_va2pa(enclave_mem_t* enclave_mem, vaddr_t vaddr, paddr_t paddr, unsigned long flags);


#endif
