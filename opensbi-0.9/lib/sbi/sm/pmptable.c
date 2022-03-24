#include <sm/pmp.h>
#include <stddef.h>
#include <sbi/sbi_pmp.h>
#include <sbi/sbi_console.h>
#include <sm/sm.h>

/*
 * PMPTables structures:
 * 	1. We use statically reserved data for the pmptables now
 * 	2. We use two PMPTables, each protects 16GB memory
 * */

/* pmpt1 for: [0x80000000,0x480000000]*/
static uintptr_t pmpt1_root[RISCV_PGSIZE / sizeof(uintptr_t)] __attribute__((aligned(RISCV_PGSIZE)));
static uintptr_t pmpt1_leaf[RISCV_PGSIZE / sizeof(uintptr_t)][RISCV_PGSIZE / sizeof(uintptr_t)] __attribute__((aligned(RISCV_PGSIZE)));

/* pmpt2 for: [0x480000000,0x880000000]*/
//uintptr_t pmpt2_root[RISCV_PGSIZE / sizeof(uintptr_t)] __attribute__((aligned(RISCV_PGSIZE)));
//uintptr_t pmpt2_leaf[RISCV_PGSIZE / sizeof(uintptr_t)][RISCV_PGSIZE / sizeof(uintptr_t)] __attribute__((aligned(RISCV_PGSIZE)));
//
void init_pmpt(){
	int count = RISCV_PGSIZE / sizeof(uintptr_t);
	int i,j;

	for (i=0; i<count; i++) {
		pmpt1_root[i] = ((uintptr_t)pmpt1_leaf[i] >> RISCV_PGSHIFT << PMPTE_PPN_SHIFT) | PTE_V;
		for (j=0; j<count; j++){
			// each physical page has 4bits, encoding as 0b1111, which has the full perm
			pmpt1_leaf[i][j] = 0xffffffffffffffff;
		}
	}

#define PMP_T 0x20 // the encoding is 0b10 0000
	/* We use the last three PMPs for PMPTable nwo, assuming 16 entries */
	uintptr_t lower_bound = 0x80000000 >> PMP_SHIFT;
	uintptr_t upper_bound = (0x80000000 + 0x400000000) >> PMP_SHIFT;
#define PMP_CONFIG_OFFSET(pmp_idx) ((uintptr_t)PMPCFG_BIT_NUM * (pmp_idx % PMP_PER_CFG_REG))
	uintptr_t pmptable_cfg = (PMP_A_TOR | PMP_R | PMP_W | PMP_X | PMP_T) << PMP_CONFIG_OFFSET(13);
	uintptr_t invalid_cfg = 0;
	uintptr_t root_pt_addr = ((uintptr_t)pmpt1_root) >> RISCV_PGSHIFT;

	printm("[Info@%s] lower:0x%lx, upper:0x%lx, table_base:0x%lx\n",
			__func__, lower_bound, upper_bound, root_pt_addr);

	set_pmp_reg(12, &lower_bound, &invalid_cfg);
	set_pmp_reg(13, &upper_bound, &pmptable_cfg);
	set_pmp_reg(14, &root_pt_addr, &invalid_cfg);
}
