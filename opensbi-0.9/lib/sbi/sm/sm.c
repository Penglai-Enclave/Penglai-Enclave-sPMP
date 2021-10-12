//#include <sm/atomic.h>
#include <sbi/riscv_atomic.h>
#include <sm/sm.h>
#include <sm/pmp.h>
#include <sm/enclave.h>
#include <sm/math.h>
#include <sbi/sbi_console.h>

//static int sm_initialized = 0;
//static spinlock_t sm_init_lock = SPINLOCK_INIT;

void sm_init()
{
  platform_init();
}

uintptr_t sm_mm_init(uintptr_t paddr, unsigned long size)
{
  uintptr_t retval = 0;

  printm("[Penglai Monitor] %s invoked\r\n",__func__);

  printm("[Penglai Monitor] %s paddr:0x%lx, size:0x%lx\r\n",__func__, paddr, size);
  /*DEBUG: Dump PMP registers here */
  dump_pmps();
  retval = mm_init(paddr, size);
  /*DEBUG: Dump PMP registers here */
  dump_pmps();

  printm("[Penglai Monitor] %s ret:%ld \r\n",__func__, retval);
  return retval;
}

uintptr_t sm_mm_extend(uintptr_t paddr, unsigned long size)
{
  uintptr_t retval = 0;
  printm("[Penglai Monitor] %s invoked\r\n",__func__);

  retval = mm_init(paddr, size);

  printm("[Penglai Monitor] %s return:%ld\r\n",__func__, retval);
  return retval;
}

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
    printm_err("M mode: sm_alloc_enclave_mem: unknown error happended when copy from host\r\n");
    return ENCLAVE_ERROR;
  }

  dump_pmps();
  unsigned long resp_size = 0;
  void* paddr = mm_alloc(mm_alloc_arg_local.req_size, &resp_size);
  if(paddr == NULL)
  {
    printm("M mode: sm_alloc_enclave_mem: no enough memory\r\n");
    return ENCLAVE_NO_MEMORY;
  }
  dump_pmps();

  //grant kernel access to this memory
  if(grant_kernel_access(paddr, resp_size) != 0)
  {
    printm_err("M mode: ERROR: faile to grant kernel access to pa 0x%lx, size 0x%lx\r\n", (unsigned long) paddr, resp_size);
    mm_free(paddr, resp_size);
    return ENCLAVE_ERROR;
  }

  mm_alloc_arg_local.resp_addr = (uintptr_t)paddr;
  mm_alloc_arg_local.resp_size = resp_size;

  retval = copy_to_host((struct mm_alloc_arg_t*)mm_alloc_arg,
      &mm_alloc_arg_local,
      sizeof(struct mm_alloc_arg_t));
  if(retval != 0)
  {
    printm_err("M mode: sm_alloc_enclave_mem: unknown error happended when copy to host\r\n");
    return ENCLAVE_ERROR;
  }

  printm("[Penglai Monitor] %s return:%ld\r\n",__func__, retval);

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
  if(retval != 0)
  {
    printm_err("M mode: sm_create_enclave: unknown error happended when copy from host\r\n");
    return ENCLAVE_ERROR;
  }

  void* paddr = (void*)enclave_sbi_param_local.paddr;
  unsigned long size = (unsigned long)enclave_sbi_param_local.size;
  if(retrieve_kernel_access(paddr, size) != 0)
  {
    mm_free(paddr, size);
    return -1UL;
  }

  retval = create_enclave(enclave_sbi_param_local);

  printm("[Penglai Monitor] %s created return value:%ld \r\n",__func__, retval);
  return retval;
}

uintptr_t sm_attest_enclave(uintptr_t eid, uintptr_t report, uintptr_t nonce)
{
  uintptr_t retval;
  printm("[Penglai Monitor] %s invoked, eid:%ld\r\n",__func__, eid);

  retval = attest_enclave(eid, report, nonce);

  printm("[Penglai Monitor] %s return: %ld\r\n",__func__, retval);

  return retval;
}

uintptr_t sm_run_enclave(uintptr_t* regs, unsigned long eid)
{
  uintptr_t retval;
  printm("[Penglai Monitor] %s invoked, eid:%ld\r\n",__func__, eid);

  retval = run_enclave(regs, (unsigned int)eid);

  printm("[Penglai Monitor] %s return: %ld\r\n",__func__, retval);

  return retval;
}

uintptr_t sm_stop_enclave(uintptr_t* regs, unsigned long eid)
{
  uintptr_t retval;
  printm("[Penglai Monitor] %s invoked, eid:%ld\r\n",__func__, eid);

  retval = stop_enclave(regs, (unsigned int)eid);

  printm("[Penglai Monitor] %s return: %ld\r\n",__func__, retval);
  return retval;
}

uintptr_t sm_resume_enclave(uintptr_t* regs, unsigned long eid)
{
  uintptr_t retval = 0;
  uintptr_t resume_func_id = regs[11];

  switch(resume_func_id)
  {
    case RESUME_FROM_TIMER_IRQ:
      retval = resume_enclave(regs, eid);
      break;
    case RESUME_FROM_STOP:
      retval = resume_from_stop(regs, eid);
      break;
    case RESUME_FROM_OCALL:
      retval = resume_from_ocall(regs, eid);
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

  printm("[Penglai Monitor] %s return: %ld\r\n",__func__, ret);

  return ret;
}

uintptr_t sm_enclave_ocall(uintptr_t* regs, uintptr_t ocall_id, uintptr_t arg0, uintptr_t arg1)
{
  uintptr_t ret = 0;
  switch(ocall_id)
  {
    case OCALL_SYS_WRITE:
      ret = enclave_sys_write(regs);
      break;
    default:
      printm_err("[Penglai Monitor@%s] wrong ocall_id(%ld)\r\n", __func__, ocall_id);
      ret = -1UL;
      break;
  }
  return ret;
}

/**
 * \brief This transitional function is used to destroy the enclave.
 *
 * \param regs The host reg.
 * \param enclave_eid The enclave id.
 */
uintptr_t sm_destroy_enclave(uintptr_t *regs, uintptr_t enclave_id)
{
  uintptr_t ret = 0;
  printm("[Penglai Monitor] %s invoked\r\n",__func__);

  ret = destroy_enclave(regs, enclave_id);

  printm("[Penglai Monitor] %s return: %ld\r\n",__func__, ret);

  return ret;
}

uintptr_t sm_do_timer_irq(uintptr_t *regs, uintptr_t mcause, uintptr_t mepc)
{
  uintptr_t ret;

  ret = do_timer_irq(regs, mcause, mepc);

  regs[10] = 0; //no errors in all cases for timer handler
  regs[11] = ret; //value
  return ret;
}
