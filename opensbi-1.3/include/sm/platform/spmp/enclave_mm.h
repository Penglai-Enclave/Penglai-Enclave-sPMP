#ifndef _ENCLAVE_MM_H
#define _ENCLAVE_MM_H

#include <stdint.h>
#include <sm/pmp.h>
#include <sm/enclave.h>

#define N_PMP_REGIONS (NPMP - 3)

#define REGION_TO_PMP(region_idx) (region_idx + 1)
#define PMP_TO_REGION(pmp_idx) (pmp_idx - 1)

/*
 * Layout of free memory chunk
 * | struct mm_list_head_t | struct mm_list_t | 00...0 |
 * | struct mm_list_head_t | struct mm_list_t | 00...0 |
 * | struct mm_list_head_t | struct mm_list_t | 00...0 |
 */
struct mm_list_t
{
  int order;
  struct mm_list_t *prev_mm;
  struct mm_list_t *next_mm;
};

struct mm_list_head_t
{
  int order;
  struct mm_list_head_t *prev_list_head;
  struct mm_list_head_t *next_list_head;
  struct mm_list_t *mm_list;
};

#define MM_LIST_2_PADDR(mm_list) ((void*)(mm_list) - sizeof(struct mm_list_head_t))
#define PADDR_2_MM_LIST(paddr) ((void*)(paddr) + sizeof(struct mm_list_head_t))

struct mm_region_t
{
  int valid;
  uintptr_t paddr;
  unsigned long size;
  struct mm_list_head_t *mm_list_head;
};

#define region_overlap(pa0, size0, pa1, size1) (((pa0<=pa1) && ((pa0+size0)>pa1)) \
    || ((pa1<=pa0) && ((pa1+size1)>pa0)))

#define region_contain(pa0, size0, pa1, size1) (((unsigned long)(pa0) <= (unsigned long)(pa1)) \
    && (((unsigned long)(pa0) + (unsigned long)(size0)) >= ((unsigned long)(pa1) + (unsigned long)(size1))))

int grant_kernel_access(void* paddr, unsigned long size);

int grant_enclave_access(struct enclave_t* enclave);

int retrieve_kernel_access(void* paddr, unsigned long size);

int retrieve_enclave_access(struct enclave_t *enclave);

uintptr_t mm_init(uintptr_t paddr, unsigned long size);

void* mm_alloc(unsigned long req_size, unsigned long* resp_size);

int mm_free(void* paddr, unsigned long size);

void print_buddy_system();

#endif /* _ENCLAVE_MM_H */
