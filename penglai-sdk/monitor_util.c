//FIXME:
//use mmap() and munmap() to map or unmap the page table in monitor
typedef unsigned long pt_entry_t;
#define PTE_V     0x001 // Valid
#define PTE_R     0x002 // Read
#define PTE_W     0x004 // Write
#define PTE_X     0x008 // Execute
#define PTE_U     0x010 // User
#define PTE_G     0x020 // Global
#define PTE_A     0x040 // Accessed
#define PTE_D     0x080 // Dirty
#define PTE_SOFT  0x300 // Reserved for Software

#define PTE_PPN_SHIFT 10
#define VA_BITS 39
#define RISCV_PGLEVEL_BITS 9
#define RISCV_PT_SHIFT 12
#define RISCV_PT_LEVEL 3
#define RISCV_PT_LEVELBITS 9
#define RISCV_PTE_PERMBITS 10
#define RISCV_PT_SIZE (1 << RISCV_PT_SHIFT)

static inline int get_pt_index(unsigned long addr, int level)
{
  int index = addr >> (VA_BITS - (level + 1)*RISCV_PGLEVEL_BITS);

  return index & ((1 << RISCV_PGLEVEL_BITS) - 1) ;
}

static inline pt_entry_t pte_create(unsigned long ppn, int type)
{ 
  return (ppn << PTE_PPN_SHIFT) | PTE_V | type ;
}

static inline pt_entry_t ptd_create(unsigned long ppn)
{
  return pte_create(ppn, PTE_V);
}

static inline unsigned long pte2pa(pt_entry_t pte)
{
  return (pte >> RISCV_PTE_PERMBITS) << RISCV_PT_SHIFT;
}

static inline pt_entry_t* clear_enclave_pt(pt_entry_t * enclave_root_pt, unsigned long addr)
{
  pt_entry_t * pgdir = enclave_root_pt;
  int i;
  for (i = 0; i < RISCV_PT_LEVEL -1 ; i++)
  {
    int pt_index = get_pt_index(addr , i);
    pt_entry_t pt_entry = pgdir[pt_index];
    if(unlikely(!(pt_entry & PTE_V)))
    {
      return 0;      
    }
    pgdir = (pt_entry_t *)pte2pa(pt_entry);
  }
  pgdir[get_pt_index(addr , RISCV_PT_LEVEL - 1)] = 0;

  return &pgdir[get_pt_index(addr , RISCV_PT_LEVEL - 1)];
}

//FIXME
//remove this  function in enclave.c
int unmap_one_page(enclave_t *enclave, unsigned long addr)
{
  pt_entry_t* pte = clear_enclave_pt(enclave->root_page_table, addr);
  return 0;
}

//FIXME
//remove this  function in enclave.c
int munmap(enclave_t *enclave, unsigned long  vaddr, unsigned long size)
{
  unsigned long va;
  unsigned long va_start = (unsigned long) vaddr;
  unsigned long va_end = (unsigned long)vaddr + size;

  for (va = va_start; va < va_end; va += RISCV_PT_SIZE) 
  {
    unmap_one_page(enclave, va);
  }
  return 0;
}

static  inline int create_ptd_page(unsigned long *free_mem,pt_entry_t *pte)
{
  unsigned long tmp = *free_mem;
  unsigned long free_ppn = (unsigned long)((*free_mem) >> RISCV_PT_SHIFT);
  *pte = ptd_create(free_ppn);
  *free_mem = tmp + RISCV_PT_SIZE;
  return 0;
}

static pt_entry_t * walk_enclave_pt(unsigned long *free_mem, pt_entry_t *enclave_root_pt, unsigned long  addr)
{
  pt_entry_t* pgdir = enclave_root_pt;
  int i;

  for(i = 0; i < RISCV_PT_LEVEL-1 ; i++)
  {
    int pt_index = get_pt_index(addr, i);
    pt_entry_t pt_entry = pgdir[pt_index];
    if(unlikely(!(pt_entry & PTE_V)))
    {
      if(create_ptd_page(free_mem, &pgdir[pt_index]) < 0)
        return NULL;
      else
        pt_entry = pgdir[pt_index];
            
    }
    pgdir = (pt_entry_t*)pte2pa(pt_entry);
  }

  return &pgdir[get_pt_index(addr, RISCV_PT_LEVEL-1)];
}

//FIXME
//remove this  function in enclave.c
int map_one_page(unsigned long  base, enclave_t *enclave,  unsigned long addr, unsigned long flags)
{
  if(enclave->free_mem >= enclave->paddr + enclave->size)
  {
    printm("M mode: no enough free memory for page table\r\n");
    return -1;
  }
  pt_entry_t* pte = __ept_walk_create(&(enclave->free_mem),
      enclave->root_page_table,
      addr);
  
   unsigned long page_addr = base;
  *pte = pte_create((page_addr) >> RISCV_PT_SHIFT, flags | PTE_V);
  return page_addr;
}

/* FIXME
remove this  function in enclave.c
vaddr @ virtual address
base @ physical address 
flags @ permission bits for page*/
int mmap(enclave_t *enclave, unsigned long  vaddr, unsigned long size, unsigned long base, unsigned long flags)
{
   unsigned long va;
   unsigned long va_start = vaddr;
   unsigned long va_end = vaddr + size ;

  for (va = va_start; va < va_end; va += RISCV_PT_SIZE) 
  {
    map_one_page(base,  enclave, va, flags);
    base += RISCV_PT_SIZE;
  }
  return 0;
}