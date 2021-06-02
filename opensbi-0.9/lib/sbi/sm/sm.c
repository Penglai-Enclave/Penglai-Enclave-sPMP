#include <sm/atomic.h>
#include <sm/sm.h>
#include <sm/pmp.h>
#include <sm/enclave.h>
#include <sm/math.h>

static int sm_initialized = 0;
static spinlock_t sm_init_lock = SPINLOCK_INIT;

void sm_init()
{
  platform_init();
}

uintptr_t sm_mm_init(uintptr_t paddr, unsigned long size)
{
  uintptr_t retval = 0;

  printm("[Penglai Monitor] %s invoked\r\n",__func__);

  printm("[Penglai Monitor] %s paddr:0x%x, size:0x%x\r\n",__func__, paddr, size);
  retval = mm_init(paddr, size);

  printm("[Penglai Monitor] %s ret:%d \r\n",__func__, retval);
  return retval;
}

uintptr_t sm_mm_extend(uintptr_t paddr, unsigned long size)
{
  uintptr_t retval = 0;
  printm("[Penglai Monitor] %s invoked\r\n",__func__);

  retval = mm_init(paddr, size);

  printm("[Penglai Monitor] %s return:%d\r\n",__func__, retval);
  return retval;
}

//TODO: delete this function
uintptr_t sm_debug_print(uintptr_t* regs, uintptr_t arg0)
{
  print_buddy_system();
  return 0;
}

uintptr_t sm_alloc_enclave_mem(uintptr_t mm_alloc_arg)
{
  struct mm_alloc_arg_t mm_alloc_arg_local;
  uintptr_t retval = 0;

  printm("[Penglai Monitor] %s invoked\r\n",__func__);

  retval = copy_from_host(&mm_alloc_arg_local,
      (struct mm_alloc_arg_t*)mm_alloc_arg,
      sizeof(struct mm_alloc_arg_t));
  if(retval != 0)
  {
    printm("M mode: sm_alloc_enclave_mem: unknown error happended when copy from host\r\n");
    return ENCLAVE_ERROR;
  }

  unsigned long resp_size = 0;
  void* paddr = mm_alloc(mm_alloc_arg_local.req_size, &resp_size);
  if(paddr == NULL)
  {
    printm("M mode: sm_alloc_enclave_mem: no enough memory\r\n");
    return ENCLAVE_NO_MEMORY;
  }

  //grant kernel access to this memory
  if(grant_kernel_access(paddr, resp_size) != 0)
  {
    printm("M mode: ERROR: faile to grant kernel access to pa 0x%lx, size 0x%lx\r\n", (unsigned long) paddr, resp_size);
    mm_free(paddr, resp_size);
    return ENCLAVE_ERROR;
  }

  mm_alloc_arg_local.resp_addr = (uintptr_t)paddr;
  mm_alloc_arg_local.resp_size = resp_size;

  copy_to_host((struct mm_alloc_arg_t*)mm_alloc_arg,
      &mm_alloc_arg_local,
      sizeof(struct mm_alloc_arg_t));

  printm("[Penglai Monitor] %s return:%d\r\n",__func__, retval);

  return ENCLAVE_SUCCESS;
}

uintptr_t sm_create_enclave(uintptr_t enclave_sbi_param)
{
  struct enclave_sbi_param_t enclave_sbi_param_local;
  uintptr_t retval = 0;

  printm("[Penglai Monitor] %s invoked\r\n",__func__);

  retval = copy_from_host(&enclave_sbi_param_local,
      (struct enclave_sbi_param_t*)enclave_sbi_param,
      sizeof(struct enclave_sbi_param_t));

  void* paddr = (void*)enclave_sbi_param_local.paddr;
  unsigned long size = (unsigned long)enclave_sbi_param_local.size;
  if(retrieve_kernel_access(paddr, size) != 0)
  {
    mm_free(paddr, size);
    return -1UL;
  }

  //TODO: not finished yet
  retval = create_enclave(enclave_sbi_param_local);


  printm("[Penglai Monitor] %s created return value:%d \r\n",__func__, retval);
  return retval;
}

uintptr_t sm_run_enclave(uintptr_t* regs, unsigned long eid)
{
  uintptr_t retval;
  printm("[Penglai Monitor] %s invoked, eid:%d\r\n",__func__, eid);

  retval = run_enclave(regs, (unsigned int)eid);

  printm("[Penglai Monitor] %s return: %d\r\n",__func__, retval);

  return retval;
}

uintptr_t sm_stop_enclave(uintptr_t* regs, unsigned long eid)
{
  uintptr_t retval;

  retval = stop_enclave(regs, (unsigned int)eid);

  return retval;
}

uintptr_t sm_resume_enclave(uintptr_t* regs, unsigned long eid)
{
  uintptr_t retval = 0;
  uintptr_t resume_func_id = regs[11];

  switch(resume_func_id)
  {
    case RESUME_FROM_TIMER_IRQ:
      //printm("resume from timer irq\r\n");
      //*HLS()->timecmp = regs[12];
      csr_read_clear(CSR_MIP, MIP_STIP);
      csr_read_set(CSR_MIE, MIP_MTIP);
      retval = resume_enclave(regs, eid);
      break;
    case RESUME_FROM_STOP:
      //printm("resume from stop\r\n");
      retval = resume_from_stop(regs, eid);
      break;
    default:
      break;
  }

  return retval;
}

uintptr_t sm_exit_enclave(uintptr_t* regs, unsigned long retval)
{
  uintptr_t ret;
  printm("[Penglai Monitor] %s invoked\r\n",__func__);

  ret = exit_enclave(regs, retval);

  printm("[Penglai Monitor] %s return: %d\r\n",__func__, ret);

  return ret;
}

uintptr_t sm_do_timer_irq(uintptr_t *regs, uintptr_t mcause, uintptr_t mepc)
{
  uintptr_t ret;

  ret = do_timer_irq(regs, mcause, mepc);

  return ret;
}
