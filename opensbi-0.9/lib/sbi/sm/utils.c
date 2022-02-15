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

static inline uintptr_t pte2pa(pte_t pte)
{
	return (pte >> PTE_PPN_SHIFT) << RISCV_PGSHIFT;
}

static inline int get_pt_index(uintptr_t vaddr, int level)
{
	int index = vaddr >> (VA_BITS - (level + 1)*RISCV_PGLEVEL_BITS);

	return index & ((1 << RISCV_PGLEVEL_BITS) - 1) ;
}

static pte_t* walk_enclave_pt(pte_t *enclave_root_pt, uintptr_t vaddr)
{
	pte_t *pgdir = enclave_root_pt;
	int i;
    int level = (VA_BITS - RISCV_PGSHIFT) / RISCV_PGLEVEL_BITS;
	for (i = 0; i < level - 1; i++)
	{
		int pt_index = get_pt_index(vaddr , i);
		pte_t pt_entry = pgdir[pt_index];
		if(unlikely(!PTE_TABLE(pt_entry)))
		{
			return 0;
		}
		pgdir = (pte_t *)pte2pa(pt_entry);
	}

	return &pgdir[get_pt_index(vaddr , level - 1)];
}

uintptr_t get_enclave_paddr_from_va(pte_t *enclave_root_pt, uintptr_t vaddr)
{
    pte_t *pte = walk_enclave_pt(enclave_root_pt, vaddr);
    if(!(*pte & PTE_V)){
        return 0;
    }
    uintptr_t pa = pte2pa(*pte) | (vaddr & ((1 << PAGE_SHIFT) - 1));
    return pa;
}

int copy_from_enclave(pte_t *enclave_root_pt, void* dest_pa, void* src_enclave_va, size_t size)
{
    uintptr_t src_pa;
    uintptr_t page_offset = (uintptr_t)src_enclave_va & ((1 << PAGE_SHIFT) - 1);
    uintptr_t page_left = PAGE_SIZE - page_offset;
    uintptr_t left_size = size;
    uintptr_t copy_size;
    if(page_left >= left_size){
        // do copy
        copy_size = left_size;
        src_pa = get_enclave_paddr_from_va(enclave_root_pt, (uintptr_t)src_enclave_va);
        if(src_pa == 0){
            sbi_printf("ERROR: va is not mapped\n");
            return -1;
        }
        sbi_memcpy(dest_pa, (void *)src_pa, copy_size);
    }
	else {
        // do left
        copy_size = page_left;
        src_pa = get_enclave_paddr_from_va(enclave_root_pt, (uintptr_t)src_enclave_va);
        if(src_pa == 0){
            sbi_printf("ERROR: va is not mapped\n");
            return -1;
        }
        sbi_memcpy(dest_pa, (void *)src_pa, copy_size);
        left_size -= page_left;
        src_enclave_va += page_left;
        dest_pa += page_left;
        // do while
        while(left_size > 0){
            copy_size = (left_size > PAGE_SIZE) ? PAGE_SIZE : left_size;
            src_pa = get_enclave_paddr_from_va(enclave_root_pt, (uintptr_t)src_enclave_va);
            if(src_pa == 0){
                sbi_printf("ERROR: va is not mapped\n");
                return -1;
            }
            sbi_memcpy(dest_pa, (void *)src_pa, copy_size);
            left_size -= copy_size;
            src_enclave_va += copy_size;
            dest_pa += page_left;
        }
    }

	return size;
}

int copy_to_enclave(pte_t *enclave_root_pt, void* dest_enclave_va, void* src_pa, size_t size)
{
	uintptr_t dest_pa;
    uintptr_t page_offset = (uintptr_t)dest_enclave_va & ((1 << PAGE_SHIFT) - 1);
    uintptr_t page_left = PAGE_SIZE - page_offset;
    uintptr_t left_size = size;
    uintptr_t copy_size;
    if(page_left >= left_size){
        // do copy
        copy_size = left_size;
        dest_pa = get_enclave_paddr_from_va(enclave_root_pt, (uintptr_t)dest_enclave_va);
        if(dest_pa == 0){
            sbi_printf("ERROR: va is not mapped\n");
            return -1;
        }
        sbi_memcpy((void *)dest_pa, src_pa, copy_size);
    }
	else {
        // do left
        copy_size = page_left;
        dest_pa = get_enclave_paddr_from_va(enclave_root_pt, (uintptr_t)dest_enclave_va);
        if(dest_pa == 0){
            sbi_printf("ERROR: va is not mapped\n");
            return -1;
        }
        sbi_memcpy((void *)dest_pa, src_pa, copy_size);
        left_size -= page_left;
        dest_enclave_va += page_left;
        src_pa += page_left;
        // do while
        while(left_size > 0){
            copy_size = (left_size > PAGE_SIZE) ? PAGE_SIZE : left_size;
            dest_pa = get_enclave_paddr_from_va(enclave_root_pt, (uintptr_t)dest_enclave_va);
            if(dest_pa == 0){
                sbi_printf("ERROR: va is not mapped\n");
                return -1;
            }
            sbi_memcpy((void *)dest_pa, src_pa, copy_size);
            left_size -= copy_size;
            dest_enclave_va += copy_size;
            src_pa += page_left;
        }
    }

	return size;
}
