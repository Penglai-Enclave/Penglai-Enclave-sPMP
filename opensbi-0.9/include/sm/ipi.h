#ifndef _IPI_H
#define _IPI_H

//#include <sm/atomic.h>
#include <sbi/riscv_atomic.h>
#include <sbi/riscv_locks.h>

#define IPI_PMP_SYNC     0x1
//#include <string.h>
#include "stdint.h"
struct ipi_mail_t
{
  uintptr_t event;
  char data[40];
};

extern struct ipi_mail_t ipi_mail;

extern spinlock_t ipi_mail_lock;

void send_and_sync_ipi_mail(uintptr_t dest_hart);

#endif /* _IPI_H */
