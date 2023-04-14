#include <sbi/sbi_pmp.h>
#include <sbi/riscv_asm.h>
#include <sbi/riscv_atomic.h>
#include <sbi/riscv_barrier.h>
#include <sbi/sbi_error.h>
#include <sbi/sbi_fifo.h>
#include <sbi/sbi_hart.h>
#include <sbi/sbi_ipi.h>
#include <sbi/sbi_scratch.h>
#include <sbi/sbi_tlb.h>
#include <sbi/sbi_hfence.h>
#include <sbi/sbi_string.h>
#include <sbi/sbi_console.h>
#include <sbi/sbi_platform.h>
#include <sbi/sbi_hartmask.h>

static unsigned long pmp_data_offset;
static unsigned long pmp_sync_offset;

static void sbi_process_pmp(struct sbi_scratch *scratch)
{
	struct pmp_data_t *data = sbi_scratch_offset_ptr(scratch, pmp_data_offset);
	struct pmp_config_t pmp_config = *(struct pmp_config_t*)(data);
	struct sbi_scratch *rscratch = NULL;
	u32 rhartid;
	unsigned long *pmp_sync = NULL;
	int pmp_idx = data->pmp_idx_arg;
	set_pmp(pmp_idx, pmp_config);

	//sync
	sbi_hartmask_for_each_hart(rhartid, &data->smask) {
		rscratch = sbi_hartid_to_scratch(rhartid);
		if (!rscratch)
			continue;
		pmp_sync = sbi_scratch_offset_ptr(rscratch, pmp_sync_offset);
		while (atomic_raw_xchg_ulong(pmp_sync, 1));
	}
}

static int sbi_update_pmp(struct sbi_scratch *scratch,
			  struct sbi_scratch *remote_scratch,
			  u32 remote_hartid, void *data)
{
	struct pmp_data_t *pmp_data = NULL;
	int pmp_idx = 0;
	u32 curr_hartid = current_hartid();

	if (remote_hartid == curr_hartid) {
		//update the pmp register locally
		struct pmp_config_t pmp_config = *(struct pmp_config_t*)(data);
		pmp_idx = ((struct pmp_data_t *)data)->pmp_idx_arg;
		set_pmp(pmp_idx, pmp_config);
		return -1;
	}

	pmp_data = sbi_scratch_offset_ptr(remote_scratch, pmp_data_offset);
	//update the remote hart pmp data
	sbi_memcpy(pmp_data, data, sizeof(struct pmp_data_t));

	return 0;
}

static void sbi_pmp_sync(struct sbi_scratch *scratch)
{
	unsigned long *pmp_sync =
			sbi_scratch_offset_ptr(scratch, pmp_sync_offset);
	//wait the remote hart process the pmp signal
	while (!atomic_raw_xchg_ulong(pmp_sync, 0));
	return;
}

static struct sbi_ipi_event_ops pmp_ops = {
	.name = "IPI_PMP",
	.update = sbi_update_pmp,
	.sync = sbi_pmp_sync,
	.process = sbi_process_pmp,
};

static u32 pmp_event = SBI_IPI_EVENT_MAX;

int sbi_send_pmp(ulong hmask, ulong hbase, struct pmp_data_t* pmp_data)
{
	return sbi_ipi_send_many(hmask, hbase, pmp_event, pmp_data);
}

int sbi_pmp_init(struct sbi_scratch *scratch, bool cold_boot)
{
	int ret;
	struct pmp_data_t *pmpdata;
	unsigned long *pmp_sync;

	if (cold_boot) {
        //Define the pmp data offset in the scratch
		pmp_data_offset = sbi_scratch_alloc_offset(sizeof(*pmpdata));
		if (!pmp_data_offset)
			return SBI_ENOMEM;

		pmp_sync_offset = sbi_scratch_alloc_offset(sizeof(*pmp_sync));
		if (!pmp_sync_offset)
			return SBI_ENOMEM;

		pmpdata = sbi_scratch_offset_ptr(scratch,
						       pmp_data_offset);

		pmp_sync = sbi_scratch_offset_ptr(scratch,
						       pmp_sync_offset);

		*pmp_sync = 0;

		ret = sbi_ipi_event_create(&pmp_ops);
		if (ret < 0) {
			sbi_scratch_free_offset(pmp_data_offset);
			return ret;
		}
		pmp_event = ret;
	} else {
		//do nothing for warmboot
	}

	return 0;
}
