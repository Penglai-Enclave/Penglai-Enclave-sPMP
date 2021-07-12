#include "spmp.c"
#include "enclave_mm.c"
#include "ipi_handler.c"
#include "platform_thread.c"

#include <sm/print.h>

int platform_init()
{
  //Clear pmp0, this pmp is reserved for allowing kernel
  //to config page table for enclave in enclave's memory.
  //There is no need to broadcast to other hart as every
  //hart will execute this function.
  clear_pmp(0);

  //config the last PMP to allow kernel to access memory
  struct pmp_config_t pmp_config;
  pmp_config.paddr = 0;
  pmp_config.size = -1UL;
  pmp_config.mode = PMP_A_NAPOT;
  pmp_config.perm = PMP_R | PMP_W | PMP_X;
  set_pmp(NPMP-1, pmp_config);

  //config the last PMP to protect security monitor
  pmp_config.paddr = (uintptr_t)SM_BASE;
  pmp_config.size = (unsigned long)SM_SIZE;
  pmp_config.mode = PMP_A_NAPOT;
  pmp_config.perm = PMP_NO_PERM;
  set_pmp(NPMP-2, pmp_config);

  printm("[Penglai Monitor@%s] PMP is ready, now setup sPMP\n", __func__);

  //config the last sPMP to allow user to access memory
  struct spmp_config_t spmp_config;
  spmp_config.paddr = 0;
  spmp_config.size = -1UL;
  spmp_config.mode = SPMP_NAPOT;
  spmp_config.perm = SPMP_R | SPMP_W | SPMP_X;
  set_spmp(NSPMP-1, spmp_config);

  return 0;
}
