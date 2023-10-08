#include <sm/sm.h>
#include <sm/enclave.h>
#include <sm/platform/spmp/enclave_mm.h>
//#include <sm/atomic.h>
#include <sbi/riscv_atomic.h>
#include <sbi/riscv_locks.h>
//#include "mtrap.h"
#include <sm/math.h>
#include <sbi/sbi_string.h>

/*
 * Only NPMP-3 enclave regions are supported.
 * The last PMP is used to allow kernel to access memory.
 * The second to last PMP is used to protect security monitor from kernel.
 * The first PMP is used to allow kernel to configure enclave's page table.
 *
 * TODO: this array can be removed as we can get
 * existing enclave regions via pmp registers
 */
static struct mm_region_t mm_regions[N_PMP_REGIONS];
static unsigned long pmp_bitmap = 0;
static spinlock_t pmp_bitmap_lock = SPINLOCK_INIT;


static int check_mem_size(uintptr_t paddr, unsigned long size)
{
  if((size == 0) || (size & (size - 1)))
  {
    printm("pmp size should be 2^power!\r\n");
    return -1;
  }

  if(size < RISCV_PGSIZE)
  {
    printm("pmp size should be no less than one page!\r\n");
    return -1;
  }

  if(paddr & (size - 1))
  {
    printm("pmp size should be %d aligned!\r\n", size);
    return -1;
  }

  return 0;
}

/*
 * This function grants kernel access to allocated enclave memory
 * for initializing enclave and configuring page table.
 */
int grant_kernel_access(void* req_paddr, unsigned long size)
{
  //pmp0 is used for allowing kernel to access enclave memory
  int pmp_idx = 0;
  struct pmp_config_t pmp_config;
  uintptr_t paddr = (uintptr_t)req_paddr;

  if(check_mem_size(paddr, size) != 0)
    return -1;

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
#if 0
  //pmp0 is used for allowing kernel to access enclave memory
  int pmp_idx = 0;
  struct pmp_config_t pmp_config;
  uintptr_t paddr = (uintptr_t)req_paddr;

  pmp_config = get_pmp(pmp_idx);

  if((pmp_config.mode != PMP_NAPOT) || (pmp_config.paddr != paddr) || (pmp_config.size != size))
  {
    printm("retrieve_kernel_access: error pmp_config\r\n");
    return -1;
  }

  clear_pmp_and_sync(pmp_idx);

  return 0;
#else
  //FIXME(DD): we always allow kernel access the memory now
  return 0;
#endif
}

//grant enclave access to enclave's memory
int grant_enclave_access(struct enclave_t* enclave)
{
#if 0
  int region_idx = 0;
  int pmp_idx = 0;
  struct pmp_config_t pmp_config;
  struct spmp_config_t spmp_config;

  if(check_mem_size(enclave->paddr, enclave->size) < 0)
    return -1;

  //set pmp permission, ensure that enclave's paddr and size is pmp legal
  //TODO: support multiple memory regions
  spinlock_lock(&pmp_bitmap_lock);
  for(region_idx = 0; region_idx < N_PMP_REGIONS; ++region_idx)
  {
    if(mm_regions[region_idx].valid && region_contain(
          mm_regions[region_idx].paddr, mm_regions[region_idx].size,
          enclave->paddr, enclave->size))
    {
      break;
    }
  }
  spinlock_unlock(&pmp_bitmap_lock);

  if(region_idx >= N_PMP_REGIONS)
  {
    printm("M mode: grant_enclave_access: can not find exact mm_region\r\n");
    return -1;
  }

  pmp_idx = REGION_TO_PMP(region_idx);
  pmp_config.paddr = mm_regions[region_idx].paddr;
  pmp_config.size = mm_regions[region_idx].size;
  pmp_config.perm = PMP_R | PMP_W | PMP_X;
  pmp_config.mode = PMP_NAPOT;
  set_pmp(pmp_idx, pmp_config);

  spmp_config.paddr = enclave->paddr;
  spmp_config.size = enclave->size;
  spmp_config.perm = SPMP_R | SPMP_W | SPMP_X;
  spmp_config.mode = SPMP_NAPOT;
  set_spmp(0, spmp_config);

  spmp_config.paddr = mm_regions[region_idx].paddr;
  spmp_config.size = mm_regions[region_idx].size;
  spmp_config.perm = SPMP_NO_PERM;
  spmp_config.mode = SPMP_NAPOT;
  set_spmp(1, spmp_config);

  return 0;
#else
  /* FIXME(DD): do nothing on PMP now */
  return 0;
#endif
}

int retrieve_enclave_access(struct enclave_t *enclave)
{
  int region_idx = 0;
  int pmp_idx = 0;
  struct pmp_config_t pmp_config;

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

#if 0 //FIXME(DD): disable PMP ops now
  if(region_idx >= N_PMP_REGIONS)
  {
    printm("M mode: Error: retriece_enclave_access\r\n");
    return -1;
  }

  pmp_idx = REGION_TO_PMP(region_idx);
  pmp_config = get_pmp(pmp_idx);
  pmp_config.perm = PMP_NO_PERM;
  set_pmp(pmp_idx, pmp_config);

  clear_spmp(0);
  clear_spmp(1);
#endif

  return 0;
}

int check_mem_overlap(uintptr_t paddr, unsigned long size)
{
  unsigned long sm_base = SM_BASE;
  unsigned long sm_size = SM_SIZE;
  int region_idx = 0;

  //check whether the new region overlaps with security monitor
  if(region_overlap(sm_base, sm_size, paddr, size))
  {
    printm("pmp memory overlaps with security monitor!\r\n");
    return -1;
  }

  //check whether the new region overlap with existing enclave region
  for(region_idx = 0; region_idx < N_PMP_REGIONS; ++region_idx)
  {
    if(mm_regions[region_idx].valid
        && region_overlap(mm_regions[region_idx].paddr, mm_regions[region_idx].size,
          paddr, size))
    {
      printm("pmp memory overlaps with existing pmp memory!\r\n");
      return -1;
    }
  }

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
    printm("mm_list_head addr is 0x%lx, order is %d\r\n", mm_list_head, mm_list_head->order);
    printm("mm_list_head prev is 0x%lx, next is 0x%lx, mm_list is 0x%lx\r\n", mm_list_head->prev_list_head, mm_list_head->next_list_head, mm_list_head->mm_list);
    struct mm_list_t *mm_region = mm_list_head->mm_list;
    while(mm_region)
    {
      printm("  mm_region addr is 0x%lx, order is %d\r\n", mm_region, mm_region->order);
      printm("  mm_region prev is 0x%lx, next is 0x%lx\r\n", mm_region->prev_mm, mm_region->next_mm);
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

  //printm("before mm_alloc, req_order = %d\r\n", ilog2(req_size - 1) + 1);
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

  //printm("after mm_alloc\r\n");
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

  //printm("before mm_free, addr to free is 0x%lx, order is %d\r\n", paddr, order);
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
    printm("mm_free: buddy system doesn't contain memory(addr 0x%lx, order %d)\r\n", paddr, order);
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
        printm("mm_free: memory(addr 0x%lx order %d) overlap with free memory(addr 0x%lx order %d)\r\n", paddr, order, region_paddr, mm_region->order);
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
    printm("mm_free: failed to insert mm(addr 0x%lx, order %d)\r\n in mm_regions[%d]\r\n", paddr, order, region_idx);
  }

  //printm("after mm_free\r\n");
  //print_buddy_system();

mm_free_out:
  spin_unlock(&pmp_bitmap_lock);
  return ret_val;
}
