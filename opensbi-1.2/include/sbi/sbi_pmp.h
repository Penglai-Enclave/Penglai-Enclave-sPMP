#ifndef __SBI_PMP_H__
#define __SBI_PMP_H__

#include <sm/pmp.h>
#include <sbi/sbi_types.h>
#include <sbi/sbi_hartmask.h>
struct sbi_scratch;
int sbi_pmp_init(struct sbi_scratch *scratch, bool cold_boot);
int sbi_send_pmp(ulong hmask, ulong hbase, struct pmp_data_t* pmp_data);
#endif
