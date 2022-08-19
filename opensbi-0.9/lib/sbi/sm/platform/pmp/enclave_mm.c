#include <sm/sm.h>
#include <sm/enclave.h>
#include <sm/platform/pmp/enclave_mm.h>
//#include <sm/atomic.h>
#include <sbi/riscv_atomic.h>
#include <sbi/riscv_locks.h>
//#include "mtrap.h"
#include <sm/math.h>
#include <sbi/sbi_string.h>

/*
 * Only NPMP-3 enclave regions are supported.
 * The last PMP is used to allow kernel to access memory.
 * The 1st PMP is used to protect security monitor from kernel.
 * The 2nd PMP is used to allow kernel to configure enclave's page table.
 * Othres, (NPMP-3) PMPs are for enclaves, i.e., secure memory
 *
 * TODO: this array can be removed as we can get
 * existing enclave regions via pmp registers
 */
static struct mm_region_t mm_regions[N_PMP_REGIONS];
static unsigned long pmp_bitmap = 0;
static spinlock_t pmp_bitmap_lock = SPIN_LOCK_INITIALIZER;


int check_mem_overlap(uintptr_t paddr, unsigned long size)
{
	unsigned long sm_base = SM_BASE;
	unsigned long sm_size = SM_SIZE;
	int region_idx = 0;

	//check whether the new region overlaps with security monitor
	if(region_overlap(sm_base, sm_size, paddr, size))
	{
		printm_err("pmp memory overlaps with security monitor!\r\n");
		return -1;
	}

	//check whether the new region overlap with existing enclave region
	for(region_idx = 0; region_idx < N_PMP_REGIONS; ++region_idx)
	{
		if(mm_regions[region_idx].valid
				&& region_overlap(mm_regions[region_idx].paddr, mm_regions[region_idx].size,
					paddr, size))
		{
			printm_err("pmp memory overlaps with existing pmp memory!\r\n");
			return -1;
		}
	}

	return 0;
}

int data_is_nonsecure(uintptr_t paddr, unsigned long size)
{
	return !check_mem_overlap(paddr, size);
}

uintptr_t copy_from_host(void* dest, void* src, size_t size)
{
	int retval = -1;
	//get lock to prevent TOCTTOU
	spin_lock(&pmp_bitmap_lock);

	//check data is nonsecure
	//prevent coping from memory in secure region
	if(data_is_nonsecure((uintptr_t)src, size))
	{
		sbi_memcpy(dest, src, size);
		retval = 0;
	}

	spin_unlock(&pmp_bitmap_lock);
	return retval;
}

uintptr_t copy_to_host(void* dest, void* src, size_t size)
{
	int retval = -1;
	spin_lock(&pmp_bitmap_lock);

	//check data is nonsecure
	//prevent coping from memory in secure region
	if(data_is_nonsecure((uintptr_t)dest, size))
	{
		sbi_memcpy(dest, src, size);
		retval = 0;
	}

	spin_unlock(&pmp_bitmap_lock);
	return retval;
}

int copy_word_to_host(unsigned int* ptr, uintptr_t value)
{
	int retval = -1;
	spin_lock(&pmp_bitmap_lock);

	//check data is nonsecure
	//prevent coping from memory in secure region
	if(data_is_nonsecure((uintptr_t)ptr, sizeof(unsigned int)))
	{
		*ptr = value;
		retval = 0;
	}

	spin_unlock(&pmp_bitmap_lock);
	return retval;
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

uintptr_t copy_from_enclave(pte_t *enclave_root_pt, void* dest_pa, void* src_enclave_va, size_t size)
{
	uintptr_t src_pa;
	uintptr_t page_offset = (uintptr_t)src_enclave_va & ((1 << PAGE_SHIFT) - 1);
	uintptr_t page_left = PAGE_SIZE - page_offset;
	uintptr_t left_size = size;
	uintptr_t copy_size;
	if (page_left >= left_size) {
		// do copy
		copy_size = left_size;
		src_pa = get_enclave_paddr_from_va(enclave_root_pt, (uintptr_t)src_enclave_va);
		if(src_pa == 0)
		{
			sbi_printf("ERROR: va is not mapped\n");
			return -1;
		}
		sbi_memcpy(dest_pa, (void *)src_pa, copy_size);
	}
	else {
		// do left
		copy_size = page_left;
		src_pa = get_enclave_paddr_from_va(enclave_root_pt, (uintptr_t)src_enclave_va);
		if(src_pa == 0)
		{
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
			if(src_pa == 0)
			{
				sbi_printf("ERROR: va is not mapped\n");
				return -1;
			}
			sbi_memcpy(dest_pa, (void *)src_pa, copy_size);
			left_size -= copy_size;
			src_enclave_va += copy_size;
			dest_pa += page_left;
		}
	}

	return 0;
}

uintptr_t copy_to_enclave(pte_t *enclave_root_pt, void* dest_enclave_va, void* src_pa, size_t size)
{
	uintptr_t dest_pa;
	uintptr_t page_offset = (uintptr_t)dest_enclave_va & ((1 << PAGE_SHIFT) - 1);
	uintptr_t page_left = PAGE_SIZE - page_offset;
	uintptr_t left_size = size;
	uintptr_t copy_size;
	if (page_left >= left_size) {
		// do copy in one time
		copy_size = left_size;
		dest_pa = get_enclave_paddr_from_va(enclave_root_pt, (uintptr_t)dest_enclave_va);
		if(dest_pa == 0)
		{
			sbi_printf("ERROR: va is not mapped\n");
			return -1;
		}
		sbi_memcpy((void *)dest_pa, src_pa, copy_size);
	}
	else {
		// do copy in the first page
		copy_size = page_left;
		dest_pa = get_enclave_paddr_from_va(enclave_root_pt, (uintptr_t)dest_enclave_va);
		if(dest_pa == 0)
		{
			sbi_printf("ERROR: va is not mapped\n");
			return -1;
		}
		sbi_memcpy((void *)dest_pa, src_pa, copy_size);
		left_size -= page_left;
		dest_enclave_va += page_left;
		src_pa += page_left;
		// do while for other pages
		while(left_size > 0){
			copy_size = (left_size > PAGE_SIZE) ? PAGE_SIZE : left_size;
			dest_pa = get_enclave_paddr_from_va(enclave_root_pt, (uintptr_t)dest_enclave_va);
			if(dest_pa == 0)
			{
				sbi_printf("ERROR: va is not mapped\n");
				return -1;
			}
			sbi_memcpy((void *)dest_pa, src_pa, copy_size);
			left_size -= copy_size;
			dest_enclave_va += copy_size;
			src_pa += page_left;
		}
	}

	return 0;
}

/*
 * Check the validness of the paddr and size
 * */
static int check_mem_size(uintptr_t paddr, unsigned long size)
{
	if((size == 0) || (size & (size - 1)))
	{
		printm_err("pmp size should be 2^power!\r\n");
		return -1;
	}

	if(size < RISCV_PGSIZE)
	{
		printm_err("pmp size should be no less than one page!\r\n");
		return -1;
	}

	if(paddr & (size - 1))
	{
		printm_err("pmp size should be %ld aligned!\r\n", size);
		return -1;
	}

	return 0;
}

/*
 * TODO: we should protect kernel temporal region with lock
 * 	 A possible malicious case:
 * 	 	kernel@Hart-0: acquire memory region, set to PMP-1
 * 	 	kernel@Hart-1: acquire memory region, set to PMP-1 <- this will overlap the prior region
 * 	 	kernel@Hart-0: release memory region <- dangerous behavior now
 * */

/**
 * \brief This function grants kernel (temporaily) access to allocated enclave memory
 * 	  for initializing enclave and configuring page table.
 */
int grant_kernel_access(void* req_paddr, unsigned long size)
{
	//pmp1 is used for allowing kernel to access enclave memory
	int pmp_idx = 1;
	struct pmp_config_t pmp_config;
	uintptr_t paddr = (uintptr_t)req_paddr;

	if(check_mem_size(paddr, size) != 0){
		printm("[Penglai Monitor@%s] check_mem_size failed\n", __func__);
		return -1;
	}

	pmp_config.paddr = paddr;
	pmp_config.size = size;
	pmp_config.perm = PMP_R | PMP_W | PMP_X;
	pmp_config.mode = PMP_A_NAPOT;
	set_pmp_and_sync(pmp_idx, pmp_config);

	return 0;
}

/*
 * This function retrieves kernel access to allocated enclave memory.
 */
int retrieve_kernel_access(void* req_paddr, unsigned long size)
{
	//pmp1 is used for allowing kernel to access enclave memory
	int pmp_idx = 1;
	struct pmp_config_t pmp_config;
	uintptr_t paddr = (uintptr_t)req_paddr;

	pmp_config = get_pmp(pmp_idx);

	if((pmp_config.mode != PMP_A_NAPOT) || (pmp_config.paddr != paddr) || (pmp_config.size != size))
	{
		printm_err("retrieve_kernel_access: error pmp_config\r\n");
		return -1;
	}

	clear_pmp_and_sync(pmp_idx);

	return 0;
}

//grant enclave access to enclave's memory
int grant_enclave_access(struct enclave_t* enclave)
{
	int region_idx = 0;
	int pmp_idx = 0;
	struct pmp_config_t pmp_config;

	if(check_mem_size(enclave->paddr, enclave->size) < 0)
		return -1;

	//set pmp permission, ensure that enclave's paddr and size is pmp legal
	//TODO: support multiple memory regions
	spin_lock(&pmp_bitmap_lock);
	for(region_idx = 0; region_idx < N_PMP_REGIONS; ++region_idx)
	{
		if(mm_regions[region_idx].valid && region_contain(
					mm_regions[region_idx].paddr, mm_regions[region_idx].size,
					enclave->paddr, enclave->size))
		{
			break;
		}
	}
	spin_unlock(&pmp_bitmap_lock);

	if(region_idx >= N_PMP_REGIONS)
	{
		printm_err("M mode: grant_enclave_access: can not find exact mm_region\r\n");
		return -1;
	}

	pmp_idx = REGION_TO_PMP(region_idx);
#if 0
	pmp_config.paddr = mm_regions[region_idx].paddr;
	pmp_config.size = mm_regions[region_idx].size;
#else
	//this enclave memory region could be less than the mm_region size
	pmp_config.paddr = enclave->paddr;
	pmp_config.size = enclave->size;
#endif
	pmp_config.perm = PMP_R | PMP_W | PMP_X;
	pmp_config.mode = PMP_A_NAPOT;

	/* Note: here we only set the PMP regions in local Hart*/
	set_pmp(pmp_idx, pmp_config);

	/*FIXME: we should handle the case that the PMP region contains larger region */
	if (pmp_config.paddr != enclave->paddr || pmp_config.size != enclave->size){
		printm("[Penglai Monitor@%s] warning, region != enclave mem\n", __func__);
		printm("[Penglai Monitor@%s] region: paddr(0x%lx) size(0x%lx)\n",
				__func__, pmp_config.paddr, pmp_config.size);
		printm("[Penglai Monitor@%s] enclave mem: paddr(0x%lx) size(0x%lx)\n",
				__func__, enclave->paddr, enclave->size);
	}

	return 0;
}

int retrieve_enclave_access(struct enclave_t *enclave)
{
	int region_idx = 0;
	int pmp_idx = 0;
	//struct pmp_config_t pmp_config;

	//set pmp permission, ensure that enclave's paddr and size is pmp legal
	//TODO: support multiple memory regions
	spin_lock(&pmp_bitmap_lock);
	for(region_idx = 0; region_idx < N_PMP_REGIONS; ++region_idx)
	{
		if(mm_regions[region_idx].valid && region_contain(
					mm_regions[region_idx].paddr, mm_regions[region_idx].size,
					enclave->paddr, enclave->size))
		{
			break;
		}
	}
	spin_unlock(&pmp_bitmap_lock);

	if(region_idx >= N_PMP_REGIONS)
	{
		printm_err("M mode: Error: %s\r\n", __func__);
		/* For Debug */
		for (region_idx = 0; region_idx < N_PMP_REGIONS; ++region_idx) {
			printm("[Monitor Debug@%s] mm_region[%d], valid(%d), paddr(0x%lx) size(0x%lx)\n",
					__func__, region_idx, mm_regions[region_idx].valid, mm_regions[region_idx].paddr,
					mm_regions[region_idx].size);
		}
		printm("[Monitor Debug@%s] enclave paddr(0x%lx) size(0x%lx)\n",
				__func__, enclave->paddr, enclave->size);

		return -1;
	}

	pmp_idx = REGION_TO_PMP(region_idx);

	// we can simply clear the PMP to retrieve the permission
	clear_pmp(pmp_idx);

	return 0;
}

uintptr_t mm_init(uintptr_t paddr, unsigned long size)
{
	uintptr_t retval = 0;
	int region_idx = 0;
	int pmp_idx =0;
	struct pmp_config_t pmp_config;

	//check align of paddr and size
	if(check_mem_size(paddr, size) < 0)
		return -1UL;

	//acquire a free enclave region
	spin_lock(&pmp_bitmap_lock);

	//check memory overlap
	//memory overlap should be checked after acquire lock
	if(check_mem_overlap(paddr, size) < 0)
	{
		retval = -1UL;
		goto out;
	}

	//alloc a free pmp
	for(region_idx = 0; region_idx < N_PMP_REGIONS; ++region_idx)
	{
		pmp_idx = REGION_TO_PMP(region_idx);
		if(!(pmp_bitmap & (1<<pmp_idx)))
		{
			//FIXME: we already have mm_regions[x].valid, why pmp_bitmap again
			pmp_bitmap |= (1 << pmp_idx);
			break;
		}
	}
	if(region_idx >= N_PMP_REGIONS)
	{
		retval = -1UL;
		goto out;
	}

	//set PMP to protect enclave memory region
	pmp_config.paddr = paddr;
	pmp_config.size = size;
	pmp_config.perm = PMP_NO_PERM;
	pmp_config.mode = PMP_A_NAPOT;
	set_pmp_and_sync(pmp_idx, pmp_config);

	//mark this region is valid and init mm_list
	mm_regions[region_idx].valid = 1;
	mm_regions[region_idx].paddr = paddr;
	mm_regions[region_idx].size = size;
	struct mm_list_t *mm_list = (struct mm_list_t*)PADDR_2_MM_LIST(paddr);
	mm_list->order = ilog2(size-1) + 1;
	mm_list->prev_mm = NULL;
	mm_list->next_mm = NULL;
	struct mm_list_head_t *mm_list_head = (struct mm_list_head_t*)paddr;
	mm_list_head->order = mm_list->order;
	mm_list_head->prev_list_head = NULL;
	mm_list_head->next_list_head = NULL;
	mm_list_head->mm_list = mm_list;
	mm_regions[region_idx].mm_list_head = mm_list_head;

out:
	spin_unlock(&pmp_bitmap_lock);
	return retval;
}

//NOTE: this function may modify the arg mm_list_head
//remember to acquire lock before calling this function
//be sure that mm_region does exist in mm_list and mm_list does exist in mm_lists
static int delete_certain_region(int region_idx, struct mm_list_head_t** mm_list_head, struct mm_list_t *mm_region)
{
	struct mm_list_t* prev_mm = mm_region->prev_mm;
	struct mm_list_t* next_mm = mm_region->next_mm;
	struct mm_list_head_t* prev_list_head = (*mm_list_head)->prev_list_head;
	struct mm_list_head_t* next_list_head = (*mm_list_head)->next_list_head;

	//delete mm_region from old mm_list
	//mm_region is in the middle of the mm_list
	if(prev_mm)
	{
		prev_mm->next_mm = next_mm;
		if(next_mm)
			next_mm->prev_mm = prev_mm;
	}
	//mm_region is in the first place of old mm_list
	else if(next_mm)
	{
		next_mm->prev_mm = NULL;
		struct mm_list_head_t* new_list_head = (struct mm_list_head_t*)MM_LIST_2_PADDR(next_mm);
		new_list_head->order = next_mm->order;
		new_list_head->prev_list_head = prev_list_head;
		new_list_head->next_list_head = next_list_head;
		new_list_head->mm_list = next_mm;
		if(prev_list_head)
			prev_list_head->next_list_head = new_list_head;
		else
			mm_regions[region_idx].mm_list_head = new_list_head;
		if(next_list_head)
			next_list_head->prev_list_head = new_list_head;

		*mm_list_head = new_list_head;
	}
	//mm_region is the only region in old mm_list
	else
	{
		if(prev_list_head)
			prev_list_head->next_list_head = next_list_head;
		else
			mm_regions[region_idx].mm_list_head = next_list_head;
		if(next_list_head)
			next_list_head->prev_list_head = prev_list_head;

		*mm_list_head = NULL;
	}

	return 0;
}

//remember to acquire a lock before calling this function
static struct mm_list_t* alloc_one_region(int region_idx, int order)
{
	if(!mm_regions[region_idx].valid || !mm_regions[region_idx].mm_list_head)
	{
		printm("M mode: alloc_one_region: m_regions[%d] is invalid/NULL\r\n", region_idx);
		return NULL;
	}

	struct mm_list_head_t *mm_list_head = mm_regions[region_idx].mm_list_head;
	while(mm_list_head && (mm_list_head->order < order))
	{
		mm_list_head = mm_list_head->next_list_head;
	}

	//current region has no enough free space
	if(!mm_list_head)
		return NULL;

	//pick a mm region from current mm_list
	struct mm_list_t *mm_region = mm_list_head->mm_list;

	//delete the mm region from current mm_list
	delete_certain_region(region_idx, &mm_list_head, mm_region);

	return mm_region;
}

//remember to acquire lock before calling this function
//be sure that mm_list_head does exist in mm_lists
static int merge_regions(int region_idx, struct mm_list_head_t* mm_list_head, struct mm_list_t *mm_region)
{
	if(region_idx<0 || region_idx>=N_PMP_REGIONS || !mm_list_head || !mm_region)
		return -1;
	if(mm_list_head->order != mm_region->order)
		return -1;

	struct mm_list_head_t* current_list_head = mm_list_head;
	struct mm_list_t* current_region = mm_region;
	while(current_list_head)
	{
		struct mm_list_t* buddy_region = current_list_head->mm_list;
		unsigned long paddr = (unsigned long)MM_LIST_2_PADDR(current_region);
		unsigned long buddy_paddr = (unsigned long)MM_LIST_2_PADDR(buddy_region);
		while(buddy_region)
		{
			buddy_paddr = (unsigned long)MM_LIST_2_PADDR(buddy_region);
			if((paddr | (1 << current_region->order)) == (buddy_paddr | (1 << current_region->order)))
				break;
			buddy_region = buddy_region->next_mm;
		}

		struct mm_list_head_t* new_list_head = (struct mm_list_head_t*)MM_LIST_2_PADDR(current_region);
		struct mm_list_head_t* prev_list_head = current_list_head->prev_list_head;
		struct mm_list_head_t* next_list_head = current_list_head->next_list_head;
		//didn't find buddy region, just insert this region in current mm_list
		if(!buddy_region)
		{
			current_region->prev_mm = NULL;
			current_region->next_mm = current_list_head->mm_list;
			current_list_head->mm_list->prev_mm = current_region;
			new_list_head->order = current_region->order;
			new_list_head->prev_list_head = prev_list_head;
			new_list_head->next_list_head = next_list_head;
			new_list_head->mm_list = current_region;

			if(prev_list_head)
				prev_list_head->next_list_head = new_list_head;
			else
				mm_regions[region_idx].mm_list_head = new_list_head;
			if(next_list_head)
				next_list_head->prev_list_head = new_list_head;

			break;
		}

		//found buddy_region, merge it and current region

		//first delete buddy_region from old mm_list
		//Note that this function may modify prev_list and next_list
		//but won't modify their positions relative to new mm_region
		delete_certain_region(region_idx, &current_list_head, buddy_region);

		//then merge buddy_region with current region
		int order = current_region->order;
		current_region = paddr < buddy_paddr ? PADDR_2_MM_LIST(paddr) : PADDR_2_MM_LIST(buddy_paddr);
		current_region->order = order + 1;
		current_region->prev_mm = NULL;
		current_region->next_mm = NULL;

		//next mm_list doesn't exist or has a different order, no need to merge
		if(!next_list_head || next_list_head->order != current_region->order)
		{
			//current_list_head may be NULL now after delete buddy region
			if(current_list_head)
				prev_list_head = current_list_head;
			new_list_head = (struct mm_list_head_t*)MM_LIST_2_PADDR(current_region);
			new_list_head->order = current_region->order;
			new_list_head->prev_list_head = prev_list_head;
			new_list_head->next_list_head = next_list_head;
			new_list_head->mm_list = current_region;

			if(prev_list_head)
				prev_list_head->next_list_head = new_list_head;
			else
				mm_regions[region_idx].mm_list_head = new_list_head;
			if(next_list_head)
				next_list_head->prev_list_head = new_list_head;

			break;
		}

		//continue to merge with next mm_list
		current_list_head = next_list_head;
	}

	return 0;
}

//remember to acquire lock before calling this function
static int insert_mm_region(int region_idx, struct mm_list_t* mm_region, int merge)
{
	if(region_idx<0 || region_idx>=N_PMP_REGIONS || !mm_regions[region_idx].valid || !mm_region)
		return -1;

	struct mm_list_head_t* mm_list_head = mm_regions[region_idx].mm_list_head;
	struct mm_list_head_t* prev_list_head = NULL;

	//there is no mm_list in current pmp_region
	if(!mm_list_head)
	{
		mm_list_head = (struct mm_list_head_t*)MM_LIST_2_PADDR(mm_region);
		mm_list_head->order = mm_region->order;
		mm_list_head->prev_list_head = NULL;
		mm_list_head->next_list_head = NULL;
		mm_list_head->mm_list = mm_region;
		mm_regions[region_idx].mm_list_head = mm_list_head;
		return 0;
	}

	//traversal from front to back
	while(mm_list_head && mm_list_head->order < mm_region->order)
	{
		prev_list_head = mm_list_head;
		mm_list_head = mm_list_head->next_list_head;
	}

	//found the exact mm_list
	int ret_val = 0;
	struct mm_list_head_t *new_list_head = (struct mm_list_head_t*)MM_LIST_2_PADDR(mm_region);
	if(mm_list_head && mm_list_head->order == mm_region->order)
	{
		if(!merge)
		{
			//insert mm_region to the first pos in mm_list
			mm_region->prev_mm = NULL;
			mm_region->next_mm = mm_list_head->mm_list;
			mm_list_head->mm_list->prev_mm = mm_region;

			//set mm_list_head
			struct mm_list_head_t* next_list_head = mm_list_head->next_list_head;
			new_list_head->order = mm_region->order;
			new_list_head->prev_list_head = prev_list_head;
			new_list_head->next_list_head = next_list_head;
			new_list_head->mm_list = mm_region;
			if(prev_list_head)
				prev_list_head->next_list_head = new_list_head;
			else
				mm_regions[region_idx].mm_list_head = new_list_head;
			if(next_list_head)
				next_list_head->prev_list_head = new_list_head;
		}
		else
		{
			//insert with merge
			ret_val = merge_regions(region_idx, mm_list_head, mm_region);
		}
	}
	//should create a new mm_list for this mm region
	//note that mm_list_head might be NULL
	else
	{
		new_list_head->order = mm_region->order;
		new_list_head->prev_list_head = prev_list_head;
		new_list_head->next_list_head = mm_list_head;
		new_list_head->mm_list = mm_region;
		if(prev_list_head)
			prev_list_head->next_list_head = new_list_head;
		else
			mm_regions[region_idx].mm_list_head = new_list_head;
		if(mm_list_head)
			mm_list_head->prev_list_head = new_list_head;
	}

	return ret_val;
}

//TODO: delete this function
void print_buddy_system()
{
	//spinlock_lock(&pmp_bitmap_lock);

	struct mm_list_head_t* mm_list_head = mm_regions[0].mm_list_head;
	printm("struct mm_list_head_t size is 0x%lx\r\n", sizeof(struct mm_list_head_t));
	printm("struct mm_list_t size is 0x%lx\r\n", sizeof(struct mm_list_t));
	while(mm_list_head)
	{
		printm("mm_list_head addr is 0x%ln, order is %d\r\n", (long int *)mm_list_head, mm_list_head->order);
		printm("mm_list_head prev is 0x%ln, next is 0x%ln, mm_list is 0x%ln\r\n",
				(long int *)mm_list_head->prev_list_head,
				(long int *)mm_list_head->next_list_head,
				(long int*)mm_list_head->mm_list);
		struct mm_list_t *mm_region = mm_list_head->mm_list;
		while(mm_region)
		{
			printm("  mm_region addr is 0x%ln, order is %d\r\n", (long int *)mm_region, mm_region->order);
			printm("  mm_region prev is 0x%ln, next is 0x%ln\r\n", (long int*)mm_region->prev_mm, (long int*)mm_region->next_mm);
			mm_region = mm_region->next_mm;
		}
		mm_list_head = mm_list_head->next_list_head;
	}

	//spinlock_unlock(&pmp_bitmap_lock);
}

void* mm_alloc(unsigned long req_size, unsigned long *resp_size)
{
	void* ret_addr = NULL;
	if(req_size == 0)
		return ret_addr;

	//TODO: reduce lock granularity
	spin_lock(&pmp_bitmap_lock);

	//print_buddy_system();

	unsigned long order = ilog2(req_size-1) + 1;
	for(int region_idx=0; region_idx < N_PMP_REGIONS; ++region_idx)
	{
		struct mm_list_t* mm_region = alloc_one_region(region_idx, order);

		//there is no enough space in current pmp region
		if(!mm_region)
			continue;

		while(mm_region->order > order)
		{
			//allocated mm region need to be split
			mm_region->order -= 1;
			mm_region->prev_mm = NULL;
			mm_region->next_mm = NULL;

			void* new_mm_region_paddr = MM_LIST_2_PADDR(mm_region) + (1 << mm_region->order);
			struct mm_list_t* new_mm_region = PADDR_2_MM_LIST(new_mm_region_paddr);
			new_mm_region->order = mm_region->order;
			new_mm_region->prev_mm = NULL;
			new_mm_region->next_mm = NULL;
			insert_mm_region(region_idx, new_mm_region, 0);
		}

		ret_addr = MM_LIST_2_PADDR(mm_region);
		break;
	}

	//print_buddy_system();

	spin_unlock(&pmp_bitmap_lock);

	if(ret_addr && resp_size)
	{
		*resp_size = 1 << order;
		sbi_memset(ret_addr, 0, *resp_size);
	}

	return ret_addr;
}

int mm_free(void* req_paddr, unsigned long free_size)
{
	//check this paddr is 2^power aligned
	uintptr_t paddr = (uintptr_t)req_paddr;
	unsigned long order = ilog2(free_size-1) + 1;
	unsigned long size = 1 << order;
	if(check_mem_size(paddr, size) < 0)
		return -1;

	int ret_val = 0;
	int region_idx = 0;
	struct mm_list_t* mm_region = PADDR_2_MM_LIST(paddr);
	mm_region->order = order;
	mm_region->prev_mm = NULL;
	mm_region->next_mm = NULL;

	spin_lock(&pmp_bitmap_lock);

	//print_buddy_system();

	for(region_idx=0; region_idx < N_PMP_REGIONS; ++region_idx)
	{
		if(mm_regions[region_idx].valid && region_contain(mm_regions[region_idx].paddr, mm_regions[region_idx].size, paddr, size))
		{
			break;
		}
	}
	if(region_idx >= N_PMP_REGIONS)
	{
		printm("mm_free: buddy system doesn't contain memory(addr 0x%lx, order %ld)\r\n", paddr, order);
		ret_val = -1;
		goto mm_free_out;
	}

	//check whether this region overlap with existing free mm_lists
	struct mm_list_head_t* mm_list_head = mm_regions[region_idx].mm_list_head;
	while(mm_list_head)
	{
		struct mm_list_t* mm_region = mm_list_head->mm_list;
		while(mm_region)
		{
			uintptr_t region_paddr = (uintptr_t)MM_LIST_2_PADDR(mm_region);
			unsigned long region_size = 1 << mm_region->order;
			if(region_overlap(paddr, size, region_paddr, region_size))
			{
				printm("mm_free: memory(addr 0x%lx order %ld) overlap with free memory(addr 0x%lx order %d)\r\n", paddr, order, region_paddr, mm_region->order);
				ret_val = -1;
				break;
			}
			mm_region = mm_region->next_mm;
		}
		if(mm_region)
			break;

		mm_list_head = mm_list_head->next_list_head;
	}
	if(mm_list_head)
	{
		goto mm_free_out;
	}

	//insert with merge
	ret_val = insert_mm_region(region_idx, mm_region, 1);
	if(ret_val < 0)
	{
		printm("mm_free: failed to insert mm(addr 0x%lx, order %ld)\r\n in mm_regions[%d]\r\n", paddr, order, region_idx);
	}

	//printm("after mm_free\r\n");
	//print_buddy_system();

mm_free_out:
	spin_unlock(&pmp_bitmap_lock);
	return ret_val;
}
