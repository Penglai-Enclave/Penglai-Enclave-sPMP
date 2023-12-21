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

#define MAGIC_NUM 30;
extern volatile unsigned long waiting_for_spinlock[MAX_HARTS];
extern volatile unsigned long wait_for_sync[MAX_HARTS];
extern volatile int skip_for_wait[MAX_HARTS][MAX_HARTS]; //slot: mark which rhart no reply
extern volatile int print_m_mode;
static unsigned long pmp_data_offset;
static unsigned long pmp_sync_offset;
static volatile u32 curr_skip_hartid =-1; //0:cur_remotehartid, 1:skip_hartid


static void sbi_process_pmp(struct sbi_scratch *scratch)
{
	struct pmp_data_t *data = sbi_scratch_offset_ptr(scratch, pmp_data_offset);
	struct pmp_config_t pmp_config = *(struct pmp_config_t*)(data);
	struct sbi_scratch *rscratch = NULL;
	u32 rhartid;
	unsigned long *pmp_sync = NULL;
	int pmp_idx = data->pmp_idx_arg;
	set_pmp(pmp_idx, pmp_config);

	ulong hartid = csr_read(CSR_MHARTID);
	//sync
	sbi_hartmask_for_each_hart(rhartid, &data->smask) {
		rscratch = sbi_hartid_to_scratch(rhartid);
		if (!rscratch)
			continue;
		if(print_m_mode && SYNC_DEBUG) sbi_printf("hart %ld process sync pmp\n", hartid);
		pmp_sync = sbi_scratch_offset_ptr(rscratch, pmp_sync_offset);
		if (skip_for_wait[rhartid][hartid] == 1)
		{
			*pmp_sync = 0;
			if (SYNC_DEBUG)
				sbi_printf("hart %ld no reply sync_pmp to %d\n",
					   hartid, rhartid);
			skip_for_wait[rhartid][hartid] = 0;
			continue;
		}
		
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

	wait_for_sync[curr_hartid] = IPI_PMP;
	curr_skip_hartid = remote_hartid;
	pmp_data = sbi_scratch_offset_ptr(remote_scratch, pmp_data_offset);
	//update the remote hart pmp data
	sbi_memcpy(pmp_data, data, sizeof(struct pmp_data_t));

	return 0;
}

static void sbi_pmp_sync(struct sbi_scratch *scratch)
{
	unsigned long *pmp_sync =
		sbi_scratch_offset_ptr(scratch, pmp_sync_offset);
	ulong hartid		 = csr_read(CSR_MHARTID);
	wait_for_sync[hartid] = IPI_PMP;

	u32 remote_hartid = curr_skip_hartid;

	if (remote_hartid != -1 && (wait_for_sync[remote_hartid] == IPI_TLB || waiting_for_spinlock[remote_hartid] == 1)){
		if (SYNC_DEBUG)
			sbi_printf("hart %ld skip wait %u sync pmp\n", hartid,
				   remote_hartid);
		curr_skip_hartid    = -1;
		atomic_raw_xchg_ulong(pmp_sync, 0);
		skip_for_wait[hartid][remote_hartid] = 1;
	} else {
		if (SYNC_DEBUG)
			sbi_printf("hart %ld wait %d sync pmp\n", hartid,
				   curr_skip_hartid);
		//wait the remote hart process the pmp signal
		int retry = MAGIC_NUM;
		while (!atomic_raw_xchg_ulong(pmp_sync, 0)) {
			/**
			 * This is used to handle the situation 
			 * where the remote enters m mode before 
			 * sending pmp sync, and the remote is in spin 
			 * lock after sending ipi.
			*/
			retry--;
			if (retry == 0) {
				retry = MAGIC_NUM;
				if (remote_hartid != -1 &&
				    (wait_for_sync[remote_hartid] == IPI_TLB ||
				     waiting_for_spinlock[remote_hartid] == 1)) {
					if (SYNC_DEBUG)
						sbi_printf(
							"hart %ld skip wait %u sync pmp\n",
							hartid, remote_hartid);
					curr_skip_hartid = -1;
					atomic_raw_xchg_ulong(pmp_sync, 0);
					skip_for_wait[hartid][remote_hartid] = 1;
					break;
				}
			}
			if (SYNC_DEBUG)
				sbi_printf("hart %ld wait %u sync pmp\n",
					   hartid, remote_hartid);
		};
	}
	wait_for_sync[hartid] = IPI_NONE;
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
	ulong hartid		 = csr_read(CSR_MHARTID);
	wait_for_sync[hartid] = IPI_PMP;
	if (SYNC_DEBUG)
		sbi_printf("hart %ld begin sync pmp\n", hartid);
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
