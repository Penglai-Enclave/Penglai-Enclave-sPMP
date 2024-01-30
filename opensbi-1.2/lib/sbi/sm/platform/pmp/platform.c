#include "enclave_mm.c"
#include "platform_thread.c"

#include <sm/print.h>

unsigned long ALIGN_UP_POWER_OF_2(unsigned long size){
    if (size <= 0) return 1;
    if ((size & (size - 1)) == 0) return size;
    size |= size >> 1;
    size |= size >> 2;
    size |= size >> 4;
    size |= size >> 8;
    size |= size >> 16;
    size |= size >> 32;
    return size + 1;
}

int platform_init()
{
  struct pmp_config_t pmp_config;

  //Clear pmp1, this pmp is reserved for allowing kernel
  //to config page table for enclave in enclave's memory.
  //There is no need to broadcast to other hart as every
  //hart will execute this function.
  //clear_pmp(1);
  clear_pmp_and_sync(1);
  printm("[Penglai Monitor@%s] init platfrom and prepare PMP\n", __func__);
  //config the PMP 0 to protect security monitor
  pmp_config.paddr = (uintptr_t)SM_BASE;
  pmp_config.size = ALIGN_UP_POWER_OF_2((unsigned long)SM_SIZE);
  pmp_config.mode = PMP_A_NAPOT;
  pmp_config.perm = PMP_NO_PERM;
  set_pmp_and_sync(0, pmp_config);

  //config the last PMP to allow kernel to access memory
  pmp_config.paddr = 0;
  pmp_config.size = -1UL;
  pmp_config.mode = PMP_A_NAPOT;
  pmp_config.perm = PMP_R | PMP_W | PMP_X;
  //set_pmp(NPMP-1, pmp_config);
  set_pmp_and_sync(NPMP-1, pmp_config);

  printm("[Penglai Monitor@%s] setting initial PMP ready\n", __func__);
  return 0;
}