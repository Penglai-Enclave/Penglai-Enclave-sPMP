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

static u64 dd_get_ticks(void)
{
	unsigned long n;
	__asm__ __volatile__("rdcycle %0" : "=r"(n));
	return n;
}

void pmpt_microbench(void);

/* pmpt2 for: [0x480000000,0x880000000]*/
//uintptr_t pmpt2_root[RISCV_PGSIZE / sizeof(uintptr_t)] __attribute__((aligned(RISCV_PGSIZE)));
//uintptr_t pmpt2_leaf[RISCV_PGSIZE / sizeof(uintptr_t)][RISCV_PGSIZE / sizeof(uintptr_t)] __attribute__((aligned(RISCV_PGSIZE)));
//
void init_pmpt(){
	int count = RISCV_PGSIZE / sizeof(uintptr_t);
	int i,j;

	pmpt_microbench();

	/* Enable HPM counters */
	csr_write(CSR_MCOUNTEREN, 0xffffffffffffffff);
	csr_write(CSR_SCOUNTEREN, -1);



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
	//uintptr_t upper_bound2 = (0x0 + 0x400000000) >> PMP_SHIFT;
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
  	set_pmp_and_sync(2, pmp_config);

  	pmp_config.paddr = lower_bound2;
  	set_pmp_and_sync(5, pmp_config);

	/* For table base register */
  	pmp_config.paddr = root_pt_addr;
  	pmp_config.size = 0UL;
  	pmp_config.mode = PMP_OFF;
  	pmp_config.perm = 0UL; //PMP_R | PMP_W | PMP_X;
  	set_pmp_and_sync(4, pmp_config);

  	set_pmp_and_sync(7, pmp_config);

	/* For PMPTable register */
  	pmp_config.paddr = upper_bound;
  	pmp_config.size = 0UL;
  	pmp_config.mode = PMP_A_TOR;
  	pmp_config.perm = PMP_R | PMP_W | PMP_X | PMP_T;
  	set_pmp_and_sync(3, pmp_config);

  	pmp_config.paddr = 0; //upper_bound2;
  	pmp_config.size = -1UL; //upper_bound2;
	pmp_config.mode = PMP_A_NAPOT;
  	pmp_config.perm = PMP_R | PMP_W | PMP_X | PMP_T;
  	set_pmp_and_sync(6, pmp_config);


	//set_pmp_reg(4, &lower_bound, &invalid_cfg);
	//set_pmp_reg(5, &upper_bound, &pmptable_cfg);
	//set_pmp_reg(6, &root_pt_addr, &invalid_cfg);
}

void pmp_switch_test(){
  	struct pmp_config_t pmp_config;
  	pmp_config.paddr = 0xdddd;
  	pmp_config.size = 0x4UL;
  	pmp_config.mode = PMP_OFF;
  	pmp_config.perm = PMP_R | PMP_W | PMP_X;
  	set_pmp(2, pmp_config);
  	set_pmp(3, pmp_config);
  	set_pmp(4, pmp_config);
  	set_pmp(5, pmp_config);
  	set_pmp(6, pmp_config);
  	set_pmp(7, pmp_config);
}

void pmpt_switch_test(){
  	struct pmp_config_t pmp_config;
  	pmp_config.paddr = 0xdddd; //assuming this as the pmptable addr
  	pmp_config.size = 0x4UL;
  	pmp_config.mode = PMP_OFF;
  	pmp_config.perm = PMP_R | PMP_W | PMP_X | PMP_T;
  	set_pmp(2, pmp_config);
  	set_pmp(3, pmp_config);
  	set_pmp(4, pmp_config);
  	set_pmp(5, pmp_config);
  	set_pmp(6, pmp_config);
  	set_pmp(7, pmp_config);
}

void pmp_alloc_region(){
  	struct pmp_config_t pmp_config;
  	pmp_config.paddr = 0x1000;
  	pmp_config.size = 0x100UL;
  	pmp_config.mode = PMP_A_NAPOT;
  	pmp_config.perm = PMP_R | PMP_W | PMP_X;
  	set_pmp_and_sync(2, pmp_config);
}

void pmp_free_region(){
  	struct pmp_config_t pmp_config;
  	pmp_config.paddr = 0x0;
  	pmp_config.size = 0x0UL;
  	pmp_config.mode = PMP_OFF;
  	pmp_config.perm = PMP_R | PMP_W | PMP_X;
  	set_pmp_and_sync(2, pmp_config);
}

/*
 * is_seg:
 * 	0: update an HPMP_Table only
 * 	1: update both seg and HPMP_Table
 * size:
 * 	the new region's size (unit is KB)
 * */
void pmpt_alloc_region(int is_seg, unsigned long size){
  	struct pmp_config_t pmp_config;
	// we should update the pmptable all the time for both seg and table choice
	int granule = 64;
	if (size>32768)
		granule = 327688;
	for (int i=0; i<size; i+=granule){ //each write can update 64KB pages (or <64KB pages)
		pmpt1_leaf[0][(i/granule)%512] = 0xffffffffffffffff;
		if (size-i<32768) granule = 64;
	}
	if (is_seg) {
		// in case of seg, we should also update a seg register
  		pmp_config.paddr = 0x1000;
  		pmp_config.size = size;
  		pmp_config.mode = PMP_A_NAPOT;
  		pmp_config.perm = PMP_R | PMP_W | PMP_X;
  		set_pmp_and_sync(2, pmp_config);
	}else{
  		set_pmp_and_sync(3, pmp_config);
	}

  	//pmp_config.paddr = 0x1000;
  	//pmp_config.size = size*1024;
  	//pmp_config.mode = PMP_NAPOT;
  	//pmp_config.perm = PMP_R | PMP_W | PMP_X | PMP_T;
}

void pmpt_free_region(int is_seg, unsigned long size){
  	struct pmp_config_t pmp_config;
	// we should update the pmptable all the time for both seg and table choice
	for (int i=0; i<size; i+=64) //each write can update 64KB pages (or <64KB pages)
		pmpt1_leaf[0][(i/64)%512] = 0x0;

	if (is_seg) {
		// in case of seg, we should also update a seg register
  		pmp_config.paddr = 0x1000;
  		pmp_config.size = size;
  		pmp_config.mode = PMP_OFF;
  		pmp_config.perm = PMP_R | PMP_W | PMP_X;
		//this will also sync TLBs with pmptables
  		set_pmp_and_sync(2, pmp_config);
	}else{
	  	set_pmp_and_sync(3, pmp_config);
	}
}



void pmpt_microbench(void){
	u64 begin_tick, end_tick, exe_ticks[100], avg_ticks;
	avg_ticks = 0;
	printm("[PMPT-Micro#1 PMP-switch (unit: cycles)]: ");
	for (int i=0; i<10; i++){
		begin_tick = dd_get_ticks();
		pmp_switch_test();
		end_tick = dd_get_ticks();
		exe_ticks[i] = end_tick - begin_tick;
		avg_ticks += exe_ticks[i];
		printm("%lu,", exe_ticks[i]);
	}
	printm("\n avg: %lu cycles\n", avg_ticks/10);

	avg_ticks = 0;
	printm("[PMPT-Micro#2 PMPT-switch (unit: cycles)]: ");
	for (int i=0; i<10; i++){
		begin_tick = dd_get_ticks();
		pmpt_switch_test();
		end_tick = dd_get_ticks();
		exe_ticks[i] = end_tick - begin_tick;
		avg_ticks += exe_ticks[i];
		printm("%lu,", exe_ticks[i]);
	}
	printm("\n avg: %lu cycles\n", avg_ticks/10);

	avg_ticks = 0;
	printm("[PMPT-Micro#3 PMP Alloc (unit: cycles)]: ");
	for (int i=0; i<16; i++){
		begin_tick = dd_get_ticks();
		pmp_alloc_region();
		end_tick = dd_get_ticks();
		exe_ticks[i] = end_tick - begin_tick;
		avg_ticks += exe_ticks[i];
		printm("%lu,", exe_ticks[i]);
	}
	printm("\n avg: %lu cycles\n", avg_ticks/16);

	avg_ticks = 0;
	printm("[PMPT-Micro#4 PMPT Alloc (unit: cycles)]: ");
	for (int i=0; i<100; i++){
		begin_tick = dd_get_ticks();
		if (i<16)
			pmpt_alloc_region(1, 256);
		else
			pmpt_alloc_region(0, 256);
		end_tick = dd_get_ticks();
		exe_ticks[i] = end_tick - begin_tick;
		avg_ticks += exe_ticks[i];
		printm("%lu,", exe_ticks[i]);
	}
	printm("\n avg: %lu cycles\n", avg_ticks/100);

	avg_ticks = 0;
	printm("[PMPT-Micro#5 PMP Free (unit: cycles)]: ");
	for (int i=0; i<16; i++){
		begin_tick = dd_get_ticks();
		pmp_free_region();
		end_tick = dd_get_ticks();
		exe_ticks[i] = end_tick - begin_tick;
		avg_ticks += exe_ticks[i];
		printm("%lu,", exe_ticks[i]);
	}
	printm("\n avg: %lu cycles\n", avg_ticks/16);

	avg_ticks = 0;
	printm("[PMPT-Micro#6 PMPT Free (unit: cycles)]: ");
	for (int i=0; i<100; i++){
		begin_tick = dd_get_ticks();
		if (i<16)
			pmpt_free_region(1, 256);
		else
			pmpt_free_region(0, 256);
		end_tick = dd_get_ticks();
		exe_ticks[i] = end_tick - begin_tick;
		avg_ticks += exe_ticks[i];
		printm("%lu,", exe_ticks[i]);
	}
	printm("\n avg: %lu cycles\n", avg_ticks/100);

	avg_ticks = 0;
	printm("[PMPT-Micro#7 PMPT Alloc with differnent size (unit: cycles)]: ");
	for (int i=0; i<6; i++){
		begin_tick = dd_get_ticks();
		pmpt_alloc_region(0, (1<<i)*1024);
		end_tick = dd_get_ticks();
		exe_ticks[i] = end_tick - begin_tick;
		avg_ticks += exe_ticks[i];
		printm("%lu,", exe_ticks[i]);
	}
	printm("\nend\n");
}
