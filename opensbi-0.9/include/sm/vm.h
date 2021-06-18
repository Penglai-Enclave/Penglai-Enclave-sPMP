#ifndef _VM_H
#define _VM_H

#include <sbi/riscv_encoding.h>
#include <stdint.h>

#define MEGAPAGE_SIZE ((uintptr_t)(RISCV_PGSIZE << RISCV_PGLEVEL_BITS))

#if __riscv_xlen == 64

# define SATP_MODE_CHOICE INSERT_FIELD(0, SATP64_MODE, SATP_MODE_SV39)
# define VA_BITS 39
# define GIGAPAGE_SIZE (MEGAPAGE_SIZE << RISCV_PGLEVEL_BITS)

#else

# define SATP_MODE_CHOICE INSERT_FIELD(0, SATP32_MODE, SATP_MODE_SV32)
# define VA_BITS 32
#endif

#endif
