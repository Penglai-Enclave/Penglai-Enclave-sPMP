#include "penglai-enclave-page.h"

vaddr_t get_free_mem(struct list_head* free_mem)
{
  struct free_mem_t* page;
  vaddr_t vaddr;

  if(list_empty(free_mem))
  {
    printk("KERNEL MODULE: get_free_mem: No empty mem in enclave\n");
    return 0;
  }

  page = list_first_entry(free_mem, struct free_mem_t, free_mem_list);
  vaddr = page->vaddr;
  list_del(&page->free_mem_list);
  /* Free the free_mem_t struct */
  kfree(page);

  return vaddr;
}

static void put_free_page(struct list_head* free_mem, vaddr_t vaddr)
{
  struct free_mem_t* page = kmalloc(sizeof(struct free_mem_t),GFP_KERNEL);
  page->vaddr = vaddr;
  list_add_tail(&page->free_mem_list, free_mem);

  return;
}

void init_free_mem( struct list_head* free_mem, vaddr_t base, unsigned int count)
{
  vaddr_t cur;
  int i ;
  cur = base;
  for(i=0; i<count; i++)
  {
    put_free_page(free_mem, cur);
    cur += RISCV_PGSIZE;
  }

  return;
}

int clean_free_mem(struct list_head * free_mem)
{
  struct free_mem_t* page;
  while(!list_empty(free_mem))
  {
    page = list_first_entry(free_mem, struct free_mem_t, free_mem_list);
    list_del(&page->free_mem_list);
    /* Free the free_mem_t struct */
    kfree(page);
  }

  return 0;
}

static inline pt_entry_t pte_create(unsigned long ppn, int type)
{ 
  return (ppn << PTE_PPN_SHIFT) | PTE_V | type ;
}

static inline pt_entry_t ptd_create(unsigned long ppn)
{
  return pte_create(ppn, PTE_V);
}

static inline paddr_t pte2pa(pt_entry_t pte)
{
  return (pte >> RISCV_PTE_PERMBITS) << RISCV_PT_SHIFT;
}

static inline vaddr_t pte2va(pt_entry_t pte)
{
  return (vaddr_t)__va(pte2pa(pte));
}

static inline paddr_t va2ppn(vaddr_t vaddr)
{
  return __pa(vaddr) >> RISCV_PGSHIFT;
}

static inline paddr_t pa2ppn(paddr_t vaddr)
{
  return vaddr >> RISCV_PGSHIFT;
}

static inline int get_pt_index(vaddr_t vaddr, int level)
{
  int index = vaddr >> (VA_BITS - (level + 1)*RISCV_PGLEVEL_BITS);

  return index & ((1 << RISCV_PGLEVEL_BITS) - 1) ;
}

static  inline int create_ptd_page(struct list_head* free_mem,pt_entry_t * pte)
{
  vaddr_t addr = get_free_mem(free_mem);
  paddr_t addr_ppn;
  if(addr == 0)
    return -1;
  addr_ppn = va2ppn(addr);
  *pte = ptd_create(addr_ppn);

  return 0;
}

static pt_entry_t * walk_enclave_pt(struct list_head* free_mem, pt_entry_t* enclave_root_pt, vaddr_t vaddr, bool create)
{
  pt_entry_t* pgdir = enclave_root_pt;
  int i;

  for(i = 0; i < RISCV_PT_LEVEL-1 ; i++)
  {
    int pt_index = get_pt_index(vaddr, i);
    pt_entry_t pt_entry = pgdir[pt_index];
    if(unlikely(!(pt_entry & PTE_V)))
    {
      if(create)
      {
        if(create_ptd_page(free_mem, &pgdir[pt_index]) < 0)
          return NULL;
        else
          pt_entry = pgdir[pt_index];
      }
      else
        printk("KERNEL MODULE: walk_enclave_pt fault\n");                 
    }
    pgdir = (pt_entry_t*)pte2va(pt_entry);
  }

  return &pgdir[get_pt_index(vaddr, RISCV_PT_LEVEL-1)];
}

static inline pt_entry_t* clear_enclave_pt(pt_entry_t * enclave_root_pt, vaddr_t vaddr)
{
  pt_entry_t * pgdir = enclave_root_pt;
  int i;
  for (i = 0; i < RISCV_PT_LEVEL -1 ; i++)
  {
    int pt_index = get_pt_index(vaddr , i);
    pt_entry_t pt_entry = pgdir[pt_index];
    if(unlikely(!(pt_entry & PTE_V)))
    {
      return 0;      
    }
    pgdir = (pt_entry_t *)pte2va(pt_entry);
  }
  pgdir[get_pt_index(vaddr , RISCV_PT_LEVEL - 1)] = 0;

  return &pgdir[get_pt_index(vaddr , RISCV_PT_LEVEL - 1)];
}

vaddr_t enclave_alloc_page(enclave_mem_t*enclave_mem, vaddr_t vaddr, unsigned long flags)
{
  vaddr_t free_page = get_free_mem(&enclave_mem->free_mem);
  pt_entry_t *pte = walk_enclave_pt(&enclave_mem->free_mem, enclave_mem -> enclave_root_pt, vaddr, true);
  unsigned long ppn = va2ppn((vaddr_t)free_page);
  *pte = ptd_create(ppn) | flags | PTE_V;

  return free_page;
}

vaddr_t map_va2pa(enclave_mem_t* enclave_mem, vaddr_t vaddr, paddr_t paddr, unsigned long flags)
{
    pt_entry_t *pte = walk_enclave_pt(&enclave_mem->free_mem, enclave_mem -> enclave_root_pt, vaddr, true);
    unsigned long ppn = pa2ppn(paddr);
    *pte = ptd_create(ppn) | flags | PTE_V;
    return vaddr; 
}

void enclave_mem_int(enclave_mem_t* enclave_mem, vaddr_t vaddr, int size, paddr_t paddr)
{
  pt_entry_t *pte;
  init_free_mem(&enclave_mem->free_mem, vaddr, size / RISCV_PGSIZE);
  enclave_mem -> vaddr = vaddr;
  enclave_mem -> paddr = paddr;
  enclave_mem -> size = size;
  pte = (pt_entry_t *)get_free_mem(&enclave_mem->free_mem);
  enclave_mem -> enclave_root_pt = pte;
  /*
	FIXME: create two special pages in enclave(the record for dynamic allocation pages)
   */
  get_free_mem(&enclave_mem->free_mem);
}

int enclave_mem_destroy(enclave_mem_t * enclave_mem)
{
  clean_free_mem(&enclave_mem -> free_mem);
  /*
	FIXME: clear two special pages in enclave(the record for dynamic allocation pages)
  Need to reclaim enclave mem to kernel ?
    free_pages(enclave->addr, enclave->size)
    free_pages(enclave dynamic alloc pages, size)
  */
  return 0;
}
