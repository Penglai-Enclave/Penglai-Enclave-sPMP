// See LICENSE for license details.

#ifndef _RISCV_SM_UTILS_H
#define _RISCV_SM_UTILS_H

#include <sbi/riscv_encoding.h>
#include <sm/vm.h>

void dump_pt(unsigned long *page_table, int level);

int copy_from_enclave(pte_t *enclave_root_pt, void* dest_pa, void* src_enclave_va, size_t size);

int copy_to_enclave(pte_t *enclave_root_pt, void* dest_enclave_va, void* src_pa, size_t size);

#endif
