#include <sm/ipi.h>
#include <sm/pmp.h>

void handle_ipi_mail()
{
  char* mail_data = ipi_mail.data;
  int pmp_idx = 0;
  struct pmp_config_t pmp_config;
  //printm("hart%d: handle ipi event%x\r\n", read_csr(mhartid), ipi_mail.event);

  switch(ipi_mail.event)
  {
    case IPI_PMP_SYNC:
      pmp_config = *(struct pmp_config_t*)(ipi_mail.data);
      pmp_idx = *(int*)((void*)ipi_mail.data + sizeof(struct pmp_config_t));
      set_pmp(pmp_idx, pmp_config);
      break;
    default:
        break;
  }
}
