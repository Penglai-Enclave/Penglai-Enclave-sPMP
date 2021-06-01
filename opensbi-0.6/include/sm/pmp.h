#ifndef _PMP_H
#define _PMP_H

#include <stdint.h>
#include "sbi/sbi_types.h"
#include "sbi/riscv_encoding.h"
#include "sbi/riscv_asm.h"

//number of PMP registers
#define NPMP 8

//already defined in machine/encoding.h
/*
//R/W/X/A/L field in PMP configuration registers
#define PMP_R     0x01
#define PMP_W     0x02
#define PMP_X     0x04
#define PMP_A     0x18
#define PMP_L     0x80

//encoding of A field in PMP configuration registers
#define PMP_TOR   0x08
#define PMP_NA4   0x10
#define PMP_NAPOT 0x18
*/
#define PMP_OFF   0x00
#define PMP_NO_PERM  0

//pmpfcg register's structure
//|63     56|55     48|47     40|39     32|31     24|23     16|15      8|7       0|
//| pmp7cfg | pmp6cfg | pmp5cfg | pmp4cfg | pmp3cfg | pmp2cfg | pmp1cfg | pmp1cfg |
#define PMP_PER_CFG_REG           8
#define PMPCFG_BIT_NUM            8
#define PMPCFG_BITS               0xFF

#define PMP_SET(num, cfg_index, pmpaddr, pmpcfg) do { \
  uintptr_t oldcfg = csr_read(CSR_PMPCFG##cfg_index); \
  pmpcfg |= (oldcfg & ~((uintptr_t)PMPCFG_BITS << (uintptr_t)PMPCFG_BIT_NUM*(num%PMP_PER_CFG_REG))); \
  asm volatile ("la t0, 1f\n\t" \
                "csrrw t0, mtvec, t0\n\t" \
                "csrw pmpaddr"#num", %0\n\t" \
                "csrw pmpcfg"#cfg_index", %1\n\t" \
                "sfence.vma\n\t"\
                ".align 2\n\t" \
                "1: csrw mtvec, t0 \n\t" \
                : : "r" (pmpaddr), "r" (pmpcfg) : "t0"); \
} while(0)

#define PMP_READ(num, cfg_index, pmpaddr, pmpcfg) do { \
  asm volatile("csrr %0, pmpaddr"#num : "=r"(pmpaddr) :); \
  asm volatile("csrr %0, pmpcfg"#cfg_index : "=r"(pmpcfg) :); \
} while(0)

struct pmp_config_t
{
  uintptr_t paddr;
  unsigned long size;
  uintptr_t perm;
  uintptr_t mode;
};

void set_pmp_and_sync(int pmp_idx, struct pmp_config_t);

void clear_pmp_and_sync(int pmp_idx);

void set_pmp(int pmp_idx, struct pmp_config_t);

void clear_pmp(int pmp_idx);

struct pmp_config_t get_pmp(int pmp_idx);

#endif /* _PMP_H */
