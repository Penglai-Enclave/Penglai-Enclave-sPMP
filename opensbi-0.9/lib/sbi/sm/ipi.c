//#include <sm/mtrap.h>
//#include <sm/fdt.h>
//#include <sm/disabled_hart_mask.h>
#include <sm/ipi.h>

//remember to acquire ipi_mail_lock before using this data struct
struct ipi_mail_t ipi_mail = {0,};

spinlock_t ipi_mail_lock = SPIN_LOCK_INITIALIZER;

//remember to acquire ipi_mail_lock before using this function
void send_and_sync_ipi_mail(uintptr_t dest_hart)
{
	/*
	 * FIXME: we do not support this function now
	 * */
#if 0
  //send IPIs to every other hart
  uintptr_t mask = hart_mask;
  mask &= dest_hart;
  for(uintptr_t i=0, m = mask; m; ++i, m>>=1)
  {
    if((m & 1) && (!((disabled_hart_mask >> i) & 1))
        && (i != read_csr(mhartid)))
    {
      //printm("hart%d: send to hart %d\r\n", read_csr(mhartid), i);
      atomic_or(&OTHER_HLS(i)->mipi_pending, IPI_MAIL);
      mb();
      *OTHER_HLS(i)->ipi = 1;
    }
  }

  //wait until all other harts have handled IPI
  uintptr_t incoming_ipi = 0;
  for(uintptr_t i=0, m=mask; m; ++i, m>>=1)
  {
    if((m & 1) && (!((disabled_hart_mask >> i) & 1))
        && (i != read_csr(mhartid)))
    {
      while(*OTHER_HLS(i)->ipi)
      {
        incoming_ipi |= atomic_swap(HLS()->ipi, 0);
      }
    }
  }

  //if we got an IPI, restore it
  if(incoming_ipi)
  {
    *HLS()->ipi = incoming_ipi;
    mb();
  }
#endif
}
