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

	printm("[Dd@%s] count == %d\n", __func__, count);

	for (i=0; i<count; i++) {
		pmpt1_root[i] = ( ((uintptr_t)pmpt1_leaf[i]) >> RISCV_PGSHIFT << PMPTE_PPN_SHIFT) | PTE_V;
		for (j=0; j<count; j++){
			// each physical page has 4bits, encoding as 0b1111, which has the full perm
			pmpt1_leaf[i][j] = 0xffffffffffffffff;
		}
		//printm("[Dd@%s] pmpt_root[%d] == 0x%lx\n", __func__, i, pmpt1_root[i]);
	}



//#define PMP_T 0x20 // the encoding is 0b10 0000
	/* We use the last three PMPs for PMPTable nwo, assuming 16 entries */
	uintptr_t lower_bound = 0x400000000 >> PMP_SHIFT;
	uintptr_t upper_bound = (0x400000000 + 0x400000000) >> PMP_SHIFT;
	uintptr_t lower_bound2 = 0x0 >> PMP_SHIFT;
	uintptr_t upper_bound2 = (0x0 + 0x400000000) >> PMP_SHIFT;
#define PMP_CONFIG_OFFSET(pmp_idx) ((uintptr_t)PMPCFG_BIT_NUM * (pmp_idx % PMP_PER_CFG_REG))
	//uintptr_t pmptable_cfg = (PMP_A_TOR | PMP_R | PMP_W | PMP_X | PMP_T) << PMP_CONFIG_OFFSET(5);
	//uintptr_t invalid_cfg = 0;
	uintptr_t root_pt_addr = ((uintptr_t)pmpt1_root) >> RISCV_PGSHIFT;

	printm("[Info@%s] lower:0x%lx, upper:0x%lx, table_base:0x%lx\n",
			__func__, lower_bound, upper_bound, root_pt_addr);

  	struct pmp_config_t pmp_config;

	/* For lowerbound register */
  	pmp_config.paddr = lower_bound;
  	pmp_config.size = 0UL;
  	pmp_config.mode = PMP_OFF;
  	pmp_config.perm = 0UL; //PMP_R | PMP_W | PMP_X;
  	set_pmp_and_sync(4, pmp_config);

  	pmp_config.paddr = lower_bound2;
  	set_pmp_and_sync(7, pmp_config);

	/* For table base register */
  	pmp_config.paddr = root_pt_addr;
  	pmp_config.size = 0UL;
  	pmp_config.mode = PMP_OFF;
  	pmp_config.perm = 0UL; //PMP_R | PMP_W | PMP_X;
  	set_pmp_and_sync(6, pmp_config);

  	set_pmp_and_sync(9, pmp_config);

	/* For PMPTable register */
  	pmp_config.paddr = upper_bound;
  	pmp_config.size = 0UL;
  	pmp_config.mode = PMP_A_TOR;
  	pmp_config.perm = PMP_R | PMP_W | PMP_X | PMP_T;
  	set_pmp_and_sync(5, pmp_config);

  	pmp_config.paddr = upper_bound2;
  	set_pmp_and_sync(8, pmp_config);

	//set_pmp_reg(4, &lower_bound, &invalid_cfg);
	//set_pmp_reg(5, &upper_bound, &pmptable_cfg);
	//set_pmp_reg(6, &root_pt_addr, &invalid_cfg);
}
