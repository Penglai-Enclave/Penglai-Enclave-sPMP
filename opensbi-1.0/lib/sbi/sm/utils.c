/*
 * Author: Dong Du
 * */
#include <sbi/riscv_encoding.h>
#include <sbi/sbi_string.h>
#include <sbi/riscv_locks.h>
#include <sbi/sbi_console.h>
#include <sm/utils.h>
#include <sm/sm.h>

/*
 * Go through and dump a page table, used for debug
 * */
void dump_pt(unsigned long *page_table, int level)
{
	int l1, i;
	unsigned long* l1_pt = page_table;

	if (!l1_pt)
		return;

	//only consider sv39 now
	for (l1=0; l1<512; l1++){
		if (!(l1_pt[l1] & PTE_V)) //this entry is not valid
			continue;

		for (i=0; i<level; i++) printm("\t"); //space before entries
		printm("%d: 0x%lx, perm: 0x%lx\n",l1, l1_pt[l1], l1_pt[l1] & (PTE_R | PTE_W | PTE_X));
		if (!PTE_TABLE(l1_pt[l1])) // not page table page
			continue;

		if (level == 3) // the last level
			continue;

		//goto the next level
		dump_pt((unsigned long*) ((l1_pt[l1]>>PTE_PPN_SHIFT)<<RISCV_PGSHIFT), level+1);
	}

	return;
}
