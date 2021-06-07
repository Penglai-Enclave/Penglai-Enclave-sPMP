#ifndef _SPMP_H
#define _SPMP_H
#define SPMP_ENABLED

#include <stdint.h>
#include <sbi/riscv_encoding.h>

//number of PMP registers
#define NSPMP 8

//R/W/X/A/L field in PMP configuration registers
#define SPMP_R     0x01
#define SPMP_W     0x02
#define SPMP_X     0x04
#define SPMP_A     0x18
#define SPMP_L     0x80

//encoding of A field in PMP configuration registers
#define SPMP_TOR   0x08
#define SPMP_NA4   0x10
#define SPMP_NAPOT 0x18
#define SPMP_OFF   0x00
#define SPMP_NO_PERM  0

//encoding of csr code
#define spmpaddr0        0x1b0
#define spmpaddr1        0x1b1
#define spmpaddr2        0x1b2
#define spmpaddr3        0x1b3
#define spmpaddr4        0x1b4
#define spmpaddr5        0x1b5
#define spmpaddr6        0x1b6
#define spmpaddr7        0x1b7
#define spmpcfg0         0x1a0

//set to 1 when spmp trap happened, remember to clear it after handle the trap
#define spmpexpt         0x145

//read spmpcfg & spmpaddr
#define read_spmpcfg(pmpc)   read_csr(pmpc)
#define read_spmpaddr(addr)  read_csr(addr)
#define read_spmpexpt(r)     read_csr(r)
#define set_spmpexpt(r, v)   write_csr(r, v)

//spmpfcg register's structure
//|63    56|55    48|47    40|39    32|31    24|23    16|15     8|7      0|
//|spmp7cfg|spmp6cfg|spmp5cfg|spmp4cfg|spmp3cfg|spmp2cfg|spmp1cfg|spmp1cfg|
#define SPMP_PER_CFG_REG           8
#define SPMPCFG_BIT_NUM            8
#define SPMPCFG_BITS               0xFF

#define _SPMP_SET(n, g, addr, pmpc) do { \
  asm volatile ("la t0, 1f\n\t" \
                "csrrw t0, mtvec, t0\n\t" \
                "csrw "#n", %0\n\t" \
                "csrw "#g", %1\n\t" \
                "sfence.vma\n\t"\
                ".align 2\n\t" \
                "1: csrw mtvec, t0 \n\t" \
                : : "r" (addr), "r" (pmpc) : "t0"); \
} while(0)

#define _SPMP_READ(n, g, addr, pmpc) do { \
  asm volatile("csrr %0, "#n : "=r"(addr) :); \
  asm volatile("csrr %0, "#g : "=r"(pmpc) :); \
} while(0)

#define SPMP_SET(n, g, addr, pmpc)  _SPMP_SET(n, g, addr, pmpc)
#define SPMP_READ(n, g, addr, pmpc) _SPMP_READ(n, g, addr, pmpc)

struct spmp_config_t
{
  uintptr_t paddr;
  unsigned long size;
  uintptr_t perm;
  uintptr_t mode;
};

void set_spmp(int spmp_idx, struct spmp_config_t);

void clear_spmp(int spmp_idx);

struct spmp_config_t get_spmp(int spmp_idx);

#endif /* _SPMP_H */
