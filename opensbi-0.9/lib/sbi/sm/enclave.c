#include <sm/print.h>
#include <sm/enclave.h>
#include <sm/sm.h>
#include <sm/math.h>
#include <sbi/riscv_encoding.h>
#include <sbi/sbi_string.h>
#include <sbi/riscv_locks.h>
#include <sm/platform/pmp/platform.h>
#include <sm/utils.h>
#include <sbi/sbi_timer.h>
#include <sm/attest.h>
#include <sm/gm/SM3.h>

static struct cpu_state_t cpus[MAX_HARTS] = {{0,}, };

//spinlock
static spinlock_t enclave_metadata_lock = SPIN_LOCK_INITIALIZER;

//enclave metadata
struct link_mem_t* enclave_metadata_head = NULL;
struct link_mem_t* enclave_metadata_tail = NULL;

static void enter_enclave_world(int eid)
{
	cpus[csr_read(CSR_MHARTID)].in_enclave = ENCLAVE_MODE;
	cpus[csr_read(CSR_MHARTID)].eid = eid;

	platform_enter_enclave_world();
}

static int get_enclave_id()
{
	return cpus[csr_read(CSR_MHARTID)].eid;
}

static void exit_enclave_world()
{
	cpus[csr_read(CSR_MHARTID)].in_enclave = 0;
	cpus[csr_read(CSR_MHARTID)].eid = -1;

	platform_exit_enclave_world();
}

int check_in_enclave_world()
{
	if(!(cpus[csr_read(CSR_MHARTID)].in_enclave))
		return -1;

	if(platform_check_in_enclave_world() < 0)
		return -1;

	return 0;
}

static int check_enclave_authentication()
{
	if(platform_check_enclave_authentication() < 0)
		return -1;

	return 0;
}

static void switch_to_enclave_ptbr(struct thread_state_t* thread, uintptr_t ptbr)
{
	platform_switch_to_enclave_ptbr(thread, ptbr);
}

static void switch_to_host_ptbr(struct thread_state_t* thread, uintptr_t ptbr)
{
	platform_switch_to_host_ptbr(thread, ptbr);
}

struct link_mem_t* init_mem_link(unsigned long mem_size, unsigned long slab_size)
{
	struct link_mem_t* head;

	head = (struct link_mem_t*)mm_alloc(mem_size, NULL);

	if (head == NULL)
		return NULL;
	else
		sbi_memset((void*)head, 0, mem_size);

	head->mem_size = mem_size;
	head->slab_size = slab_size;
	head->slab_num = (mem_size - sizeof(struct link_mem_t)) / slab_size;
	void* align_addr = (char*)head + sizeof(struct link_mem_t);
	head->addr = (char*)size_up_align((unsigned long)align_addr, slab_size);
	head->next_link_mem = NULL;

	return head;
}

struct link_mem_t* add_link_mem(struct link_mem_t** tail)
{
	struct link_mem_t* new_link_mem;

	new_link_mem = (struct link_mem_t*)mm_alloc((*tail)->mem_size, NULL);

	if (new_link_mem == NULL)
		return NULL;
	else
		sbi_memset((void*)new_link_mem, 0, (*tail)->mem_size);

	(*tail)->next_link_mem = new_link_mem;
	new_link_mem->mem_size = (*tail)->mem_size;
	new_link_mem->slab_num = (*tail)->slab_num;
	new_link_mem->slab_size = (*tail)->slab_size;
	void* align_addr = (char*)new_link_mem + sizeof(struct link_mem_t);
	new_link_mem->addr = (char*)size_up_align((unsigned long)align_addr, (*tail)->slab_size);
	new_link_mem->next_link_mem = NULL;

	return new_link_mem;
}

int remove_link_mem(struct link_mem_t** head, struct link_mem_t* ptr)
{
	struct link_mem_t *cur_link_mem, *tmp_link_mem;
	int retval =0;

	cur_link_mem = *head;
	if (cur_link_mem == ptr)
	{
		*head = cur_link_mem->next_link_mem;
		mm_free(cur_link_mem, cur_link_mem->mem_size);
		return 1;
	}

	for (cur_link_mem = *head; cur_link_mem != NULL; cur_link_mem = cur_link_mem->next_link_mem)
	{
		if (cur_link_mem->next_link_mem == ptr)
		{
			tmp_link_mem = cur_link_mem->next_link_mem;
			cur_link_mem->next_link_mem = cur_link_mem->next_link_mem->next_link_mem;
			//FIXME
			mm_free(tmp_link_mem, tmp_link_mem->mem_size);
			return retval;
		}
	}

	return retval;
}

/*
 * alloc an enclave struct now, which is zeroed
 * Note: do not acquire metadata lock before the function!
 * */
static struct enclave_t* alloc_enclave()
{
	struct link_mem_t *cur, *next;
	struct enclave_t* enclave = NULL;
	int i, found, eid;

	spin_lock(&enclave_metadata_lock);

	//enclave metadata list hasn't be initialized yet
	if(enclave_metadata_head == NULL)
	{
		enclave_metadata_head = init_mem_link(ENCLAVE_METADATA_REGION_SIZE, sizeof(struct enclave_t));
		if(!enclave_metadata_head)
		{
			printm("[Penglai Monitor@%s] don't have enough mem\r\n", __func__);
			goto alloc_eid_out;
		}
		enclave_metadata_tail = enclave_metadata_head;
	}

	found = 0;
	eid = 0;
	for(cur = enclave_metadata_head; cur != NULL; cur = cur->next_link_mem)
	{
		for(i = 0; i < (cur->slab_num); i++)
		{
			enclave = (struct enclave_t*)(cur->addr) + i;
			if(enclave->state == INVALID)
			{
				sbi_memset((void*)enclave, 0, sizeof(struct enclave_t));
				enclave->state = FRESH;
				enclave->eid = eid;
				found = 1;
				break;
			}
			eid++;
		}
		if(found)
			break;
	}

	//don't have enough enclave metadata
	if(!found)
	{
		next = add_link_mem(&enclave_metadata_tail);
		if(next == NULL)
		{
			printm("[Penglai Monitor@%s] don't have enough mem\r\n", __func__);
			enclave = NULL;
			goto alloc_eid_out;
		}
		enclave = (struct enclave_t*)(next->addr);
		sbi_memset((void*)enclave, 0, sizeof(struct enclave_t));
		enclave->state = FRESH;
		enclave->eid = eid;
	}

alloc_eid_out:
	spin_unlock(&enclave_metadata_lock);
	return enclave;
}

static int free_enclave(int eid)
{
	struct link_mem_t *cur;
	struct enclave_t *enclave = NULL;
	int found, count, ret_val;

	spin_lock(&enclave_metadata_lock);

	found = 0;
	count = 0;
	for(cur = enclave_metadata_head; cur != NULL; cur = cur->next_link_mem)
	{
		if(eid < (count + cur->slab_num))
		{
			enclave = (struct enclave_t*)(cur->addr) + (eid - count);
			sbi_memset((void*)enclave, 0, sizeof(struct enclave_t));
			enclave->state = INVALID;
			found = 1;
			ret_val = 0;
			break;
		}
		count += cur->slab_num;
	}

	//haven't alloc this eid
	if(!found)
	{
		printm("[Penglai Monitor@%s] haven't alloc this eid\r\n", __func__);
		ret_val = -1;
	}

	spin_unlock(&enclave_metadata_lock);

	return ret_val;
}

struct enclave_t* get_enclave(int eid)
{
	struct link_mem_t *cur;
	struct enclave_t *enclave;
	int found, count;

	spin_lock(&enclave_metadata_lock);

	found = 0;
	count = 0;
	for(cur = enclave_metadata_head; cur != NULL; cur = cur->next_link_mem)
	{
		if(eid < (count + cur->slab_num))
		{
			enclave = (struct enclave_t*)(cur->addr) + (eid - count);
			found = 1;
			break;
		}

		count += cur->slab_num;
	}

	//haven't alloc this eid
	if(!found)
	{
		printm("[Penglai Monitor@%s]  haven't alloc this enclave\r\n", __func__);
		enclave = NULL;
	}

	spin_unlock(&enclave_metadata_lock);
	return enclave;
}

int swap_from_host_to_enclave(uintptr_t* host_regs, struct enclave_t* enclave)
{
	//grant encalve access to memory
	if(grant_enclave_access(enclave) < 0)
		return -1;

	//save host context
	swap_prev_state(&(enclave->thread_context), host_regs);

	//different platforms have differnt ptbr switch methods
	switch_to_enclave_ptbr(&(enclave->thread_context), enclave->thread_context.encl_ptbr);

	/*
	 * save host cache binding
	 * only workable when the hardware supports the feature
	 */
#if 0
	swap_prev_cache_binding(&enclave -> threads[0], read_csr(0x356));
#endif

	// disable interrupts
	swap_prev_mie(&(enclave->thread_context), csr_read(CSR_MIE));

	// clear pending interrupts
	csr_read_clear(CSR_MIP, MIP_MTIP);
	csr_read_clear(CSR_MIP, MIP_STIP);
	csr_read_clear(CSR_MIP, MIP_SSIP);
	csr_read_clear(CSR_MIP, MIP_SEIP);

	//disable interrupts/exceptions delegation
	swap_prev_mideleg(&(enclave->thread_context), csr_read(CSR_MIDELEG));
	swap_prev_medeleg(&(enclave->thread_context), csr_read(CSR_MEDELEG));

	// swap the mepc to transfer control to the enclave
	// This will be overwriten by the entry-address in the case of run_enclave
	//swap_prev_mepc(&(enclave->thread_context), csr_read(CSR_MEPC));
	swap_prev_mepc(&(enclave->thread_context), host_regs[32]);
	host_regs[32] = csr_read(CSR_MEPC); //update the new value to host_regs

	//set return address to enclave

	//set mstatus to transfer control to u mode
	uintptr_t mstatus = host_regs[33]; //In OpenSBI, we use regs to change mstatus
	mstatus = INSERT_FIELD(mstatus, MSTATUS_MPP, PRV_U);
	mstatus = INSERT_FIELD(mstatus, MSTATUS_FS, 0x3); // enable float
	host_regs[33] = mstatus;

	//mark that cpu is in enclave world now
	enter_enclave_world(enclave->eid);

	__asm__ __volatile__ ("sfence.vma" : : : "memory");

	return 0;
}

int swap_from_enclave_to_host(uintptr_t* regs, struct enclave_t* enclave)
{
	//retrieve enclave access to memory
	retrieve_enclave_access(enclave);

	//restore host context
	swap_prev_state(&(enclave->thread_context), regs);

	//restore host's ptbr
	switch_to_host_ptbr(&(enclave->thread_context), enclave->host_ptbr);

	//TODO: restore host cache binding
	//swap_prev_cache_binding(&(enclave->thread_context), );

	//restore interrupts
	swap_prev_mie(&(enclave->thread_context), csr_read(CSR_MIE));

	//restore interrupts/exceptions delegation
	swap_prev_mideleg(&(enclave->thread_context), csr_read(CSR_MIDELEG));
	swap_prev_medeleg(&(enclave->thread_context), csr_read(CSR_MEDELEG));

	//transfer control back to kernel
	//swap_prev_mepc(&(enclave->thread_context), read_csr(mepc));
	//regs[32] = (uintptr_t)(enclave->thread_context.prev_mepc); //In OpenSBI, we use regs to change mepc
	swap_prev_mepc(&(enclave->thread_context), regs[32]);
	regs[32] = csr_read(CSR_MEPC); //update the new value to host_regs

	//restore mstatus
#if 0
	uintptr_t mstatus = read_csr(mstatus);
	mstatus = INSERT_FIELD(mstatus, MSTATUS_MPP, PRV_S);
	write_csr(mstatus, mstatus);
#else
	uintptr_t mstatus = regs[33]; //In OpenSBI, we use regs to change mstatus
	mstatus = INSERT_FIELD(mstatus, MSTATUS_MPP, PRV_S);
	regs[33] = mstatus;
#endif

	//mark that cpu is out of enclave world now
	exit_enclave_world();

	__asm__ __volatile__ ("sfence.vma" : : : "memory");

	return 0;
}

uintptr_t create_enclave(struct enclave_sbi_param_t create_args)
{
	struct enclave_t* enclave;
	unsigned int eid;
	uintptr_t retval = 0;

	enclave = alloc_enclave();
	if(!enclave)
	{
		printm("[Penglai Monitor@%s] enclave allocation is failed \r\n", __func__);
		sbi_memset((void*)(create_args.paddr), 0, create_args.size);
		mm_free((void*)(create_args.paddr), create_args.size);
		return ENCLAVE_ERROR;
	}

	spin_lock(&enclave_metadata_lock);

	eid = enclave->eid;
	enclave->paddr = create_args.paddr;
	enclave->size = create_args.size;
	enclave->entry_point = create_args.entry_point;
	enclave->untrusted_ptr = create_args.untrusted_ptr;
	enclave->untrusted_size = create_args.untrusted_size;
	enclave->free_mem = create_args.free_mem;
	enclave->ocall_func_id = create_args.ecall_arg0;
	enclave->ocall_arg0 = create_args.ecall_arg1;
	enclave->ocall_arg1 = create_args.ecall_arg2;
	enclave->ocall_syscall_num = create_args.ecall_arg3;
	enclave->kbuffer = create_args.kbuffer;
	enclave->kbuffer_size = create_args.kbuffer_size;
	enclave->host_ptbr = csr_read(CSR_SATP);
	enclave->thread_context.encl_ptbr = (create_args.paddr >> (RISCV_PGSHIFT) | SATP_MODE_CHOICE);
	enclave->root_page_table = (unsigned long*)create_args.paddr;
	enclave->state = FRESH;

	//Dump the PT here, for debug
#if 0
	printm("[Penglai@%s], Dump PT for created enclave\n", __func__);
	dump_pt(enclave->root_page_table, 1);
#endif

	printm("[Penglai@%s] paddr:0x%lx, size:0x%lx, entry:0x%lx\n"
			"untrusted ptr:0x%lx host_ptbr:0x%lx, pt:0x%ln\n"
			"thread_context.encl_ptbr:0x%lx\n cur_satp:0x%lx\n",
			__func__, enclave->paddr, enclave->size, enclave->entry_point,
			enclave->untrusted_ptr, enclave->host_ptbr, enclave->root_page_table,
			enclave->thread_context.encl_ptbr, csr_read(CSR_SATP));

	// Calculate the enclave's measurement
	hash_enclave(enclave, (void*)(enclave->hash), 0);

	// TODO: verify hash and whitelist check

	// Check page table mapping secure and not out of bound
	retval = check_enclave_pt(enclave);
	if(retval != 0)
	{
		printm_err("M mode: create_enclave: check enclave page table failed, create failed\r\n");
		goto error_out;
	}

	retval = copy_word_to_host((unsigned int*)create_args.eid_ptr, enclave->eid);
	if(retval != 0)
	{
		printm_err("M mode: create_enclave: unknown error happended when copy word to host\r\n");
		goto error_out;
	}

	printm("[Penglai Monitor@%s] return eid:%d\n",
			__func__, enclave->eid);

	spin_unlock(&enclave_metadata_lock);
	return 0;

/*
 * If create failed for above reasons, secure memory and enclave struct
 * allocated before will never be used. So we need to free these momery.
 */
error_out:
	sbi_memset((void*)(enclave->paddr), 0, enclave->size);
	mm_free((void*)(enclave->paddr), enclave->size);

	spin_unlock(&enclave_metadata_lock);

	//free enclave struct
	free_enclave(eid); //the enclave state will be set INVALID here
	return ENCLAVE_ERROR;
}

uintptr_t run_enclave(uintptr_t* regs, unsigned int eid)
{
	struct enclave_t* enclave;
	uintptr_t retval = 0;

	enclave = get_enclave(eid);
	if (!enclave)
	{
		printm_err("[Penglai Monitor@%s] wrong enclave id\r\n", __func__);
		return -1UL;
	}

	spin_lock(&enclave_metadata_lock);

	if (enclave->state != FRESH)
	{
		printm_err("[Penglai Monitor@%s] enclave is not initialized or already used\r\n", __func__);
		retval = -1UL;
		goto run_enclave_out;
	}
	if (enclave->host_ptbr != csr_read(CSR_SATP))
	{
		printm_err("[Penglai Monitor@%s] enclave doesn't belong to current host process\r\n", __func__);
		retval = -1UL;
		goto run_enclave_out;
	}

	if (swap_from_host_to_enclave(regs, enclave) < 0)
	{
		printm("[Penglai Monitor@%s] enclave can not be run\r\n", __func__);
		retval = -1UL;
		goto run_enclave_out;
	}

	//swap_prev_mepc(&(enclave->thread_context), regs[32]);
	regs[32] = (uintptr_t)(enclave->entry_point); //In OpenSBI, we use regs to change mepc

	//TODO: enable timer interrupt
	csr_read_set(CSR_MIE, MIP_MTIP);

	//set default stack
	regs[2] = ENCLAVE_DEFAULT_STACK;

	//pass parameters
	regs[11] = (uintptr_t)enclave->entry_point;
	regs[12] = (uintptr_t)enclave->untrusted_ptr;
	regs[13] = (uintptr_t)enclave->untrusted_size;

	enclave->state = RUNNING;

run_enclave_out:
	spin_unlock(&enclave_metadata_lock);
	return retval;
}

uintptr_t stop_enclave(uintptr_t* regs, unsigned int eid)
{
	uintptr_t retval = 0;
	struct enclave_t *enclave = get_enclave(eid);
	if(!enclave)
	{
		printm_err("[Penglai Monitor@%s] wrong enclave id%d\r\n", __func__, eid);
		return -1UL;
	}

	spin_lock(&enclave_metadata_lock);

	if(enclave->host_ptbr != csr_read(CSR_SATP))
	{
		printm_err("[Penglai Monitor@%s] enclave doesn't belong to current host process\r\n", __func__);
		retval = -1UL;
		goto stop_enclave_out;
	}

	if(enclave->state <= FRESH)
	{
		printm_err("[Penglai Monitor@%s] enclave%d hasn't begin running at all\r\n", __func__, eid);
		retval = -1UL;
		goto stop_enclave_out;
	}

	if(enclave->state == STOPPED || enclave-> state == DESTROYED)
	{
		printm_err("[Penglai Monitor@%s] enclave%d already stopped/destroyed\r\n", __func__, eid);
		retval = -1UL;
		goto stop_enclave_out;
	}

	/* The real-stop happen when the enclave traps into the monitor */
	enclave->state = STOPPED;

stop_enclave_out:
	spin_unlock(&enclave_metadata_lock);
	return retval;
}

uintptr_t destroy_enclave(uintptr_t* regs, unsigned int eid)
{
	uintptr_t retval = 0;
	struct enclave_t *enclave = get_enclave(eid);
	if(!enclave)
	{
		printm_err("[Penglai Monitor@%s] wrong enclave id%d\r\n", __func__, eid);
		return -1UL;
	}

	spin_lock(&enclave_metadata_lock);

	if (enclave->host_ptbr != csr_read(CSR_SATP))
	{
		printm_err("[Penglai Monitor@%s] enclave doesn't belong to current host process"
				"enclave->host_ptbr:0x%lx, csr_satp:0x%lx\r\n", __func__, enclave->host_ptbr, csr_read(CSR_SATP));
		retval = -1UL;
		goto out;
	}

	if (enclave->state < FRESH)
	{
		printm_err("[Penglai Monitor@%s] enclave%d hasn't created\r\n", __func__, eid);
		retval = -1UL;
		goto out;
	}

	/*
	 * If the enclave is stopped or fresh, it will never goto the timer trap handler,
	 * we should destroy the enclave immediately
	 * */
	//if (enclave->state == STOPPED || enclave->state == FRESH) {
	if (enclave->state == FRESH) {
		sbi_memset((void*)(enclave->paddr), 0, enclave->size);
		mm_free((void*)(enclave->paddr), enclave->size);
		enclave->state = INVALID;

		spin_unlock(&enclave_metadata_lock);

		//free enclave struct
		retval = free_enclave(eid); //the enclave state will be set INVALID here
		return retval;
	}
	//FIXME: what if the enclave->state is RUNNABLE now?

	/* The real-destroy happen when the enclave traps into the monitor */
	enclave->state = DESTROYED;
out:
	spin_unlock(&enclave_metadata_lock);
	return retval;
}

uintptr_t resume_from_stop(uintptr_t* regs, unsigned int eid)
{
	uintptr_t retval = 0;
	struct enclave_t* enclave = get_enclave(eid);

	if (!enclave)
	{
		printm("[Penglai Monitor@%s] wrong enclave id%d\r\n", __func__, eid);
		return -1UL;
	}

	spin_lock(&enclave_metadata_lock);
	if(enclave->host_ptbr != csr_read(CSR_SATP))
	{
		printm("[Penglai Monitor@%s] enclave doesn't belong to current host process\r\n", __func__);
		retval = -1UL;
		goto resume_from_stop_out;
	}

	if(enclave->state != STOPPED)
	{
		printm("[Penglai Monitor@%s] enclave's state is not stopped\r\n", __func__);
		retval = -1UL;
		goto resume_from_stop_out;
	}

	enclave->state = RUNNABLE;
	printm("[Penglai Monitor@%s] encalve-%d turns to runnable now!\n", __func__, eid);

resume_from_stop_out:
	spin_unlock(&enclave_metadata_lock);
	return retval;
}

uintptr_t resume_enclave(uintptr_t* regs, unsigned int eid)
{
	uintptr_t retval = 0;
	struct enclave_t* enclave = get_enclave(eid);
	if(!enclave)
	{
		printm("[Penglai Monitor@%s]  wrong enclave id%d\r\n", __func__, eid);
		return -1UL;
	}

	spin_lock(&enclave_metadata_lock);

	if(enclave->host_ptbr != csr_read(CSR_SATP))
	{
		printm("[Penglai Monitor@%s]  enclave doesn't belong to current host process\r\n", __func__);
		retval = -1UL;
		goto resume_enclave_out;
	}

	if(enclave->state == STOPPED)
	{
		retval = ENCLAVE_TIMER_IRQ;
		goto resume_enclave_out;
	}

	if (enclave->state == DESTROYED) {
		sbi_memset((void*)(enclave->paddr), 0, enclave->size);
		mm_free((void*)(enclave->paddr), enclave->size);

		spin_unlock(&enclave_metadata_lock);

		//free enclave struct
		free_enclave(eid); //the enclave state will be set INVALID here
		return ENCLAVE_SUCCESS; //this will break the infinite loop in the enclave-driver
	}

	if(enclave->state != RUNNABLE)
	{
		printm("[Penglai Monitor@%s]  enclave%d is not runnable\r\n", __func__, eid);
		retval = -1UL;
		goto resume_enclave_out;
	}

	if(swap_from_host_to_enclave(regs, enclave) < 0)
	{
		printm("[Penglai Monitor@%s]  enclave can not be run\r\n", __func__);
		retval = -1UL;
		goto resume_enclave_out;
	}

	enclave->state = RUNNING;

	//regs[10] will be set to retval when mcall_trap return, so we have to
	//set retval to be regs[10] here to succuessfully restore context
	//TODO: retval should be set to indicate success or fail when resume from ocall
	retval = regs[10];

resume_enclave_out:
	spin_unlock(&enclave_metadata_lock);
	return retval;
}

uintptr_t attest_enclave(uintptr_t eid, uintptr_t report_ptr, uintptr_t nonce)
{
	struct enclave_t* enclave = NULL;
	int attestable = 1;
	struct report_t report;
	enclave = get_enclave(eid);
	spin_lock(&enclave_metadata_lock);

	if(!attestable)
	{
		sbi_printf("M mode: attest_enclave: enclave%ld is not attestable\n", eid);
		return -1UL;
	}

	sbi_memcpy((void*)(report.dev_pub_key), (void*)DEV_PUB_KEY, PUBLIC_KEY_SIZE);
	sbi_memcpy((void*)(report.sm.hash), (void*)SM_HASH, HASH_SIZE);
	sbi_memcpy((void*)(report.sm.sm_pub_key), (void*)SM_PUB_KEY, PUBLIC_KEY_SIZE);
	sbi_memcpy((void*)(report.sm.signature), (void*)SM_SIGNATURE, SIGNATURE_SIZE);

	update_enclave_hash((char *)(report.enclave.hash), (char *)enclave->hash, nonce);
	sign_enclave((void*)(report.enclave.signature), (void*)(report.enclave.hash), HASH_SIZE);
	report.enclave.nonce = nonce;

	copy_to_host((void*)report_ptr, (void*)(&report), sizeof(struct report_t));

	spin_unlock(&enclave_metadata_lock);
	return 0;
}

uintptr_t exit_enclave(uintptr_t* regs, unsigned long retval)
{
	int eid = get_enclave_id();
	struct enclave_t *enclave = NULL;
	if(check_in_enclave_world() < 0)
	{
		printm_err("[Penglai Monitor@%s] cpu is not in enclave world now\r\n", __func__);
		return -1;
	}
	printm_err("[Penglai Monitor@%s] retval of enclave is %lx\r\n", __func__, retval);

	enclave = get_enclave(eid);

	spin_lock(&enclave_metadata_lock);

	if(!enclave || check_enclave_authentication(enclave)!=0 || enclave->state != RUNNING)
	{
		printm_err("[Penglai Monitor@%s] current enclave's eid is not %d\r\n", __func__, eid);
		spin_unlock(&enclave_metadata_lock);
		return -1UL;
	}

	swap_from_enclave_to_host(regs, enclave);

	//free enclave's memory
	//TODO: support multiple memory region
	sbi_memset((void*)(enclave->paddr), 0, enclave->size);
	mm_free((void*)(enclave->paddr), enclave->size);

	spin_unlock(&enclave_metadata_lock);

	//free enclave struct
	free_enclave(eid);

	return 0;
}

uintptr_t enclave_sys_write(uintptr_t* regs)
{
	uintptr_t ret = 0;
	int eid = get_enclave_id();
	struct enclave_t* enclave = NULL;
	if(check_in_enclave_world() < 0)
	{
		printm_err("[Penglai Monitor@%s] check enclave world is failed\n", __func__);
		return -1;
	}

	enclave = get_enclave(eid);

	spin_lock(&enclave_metadata_lock);

	if(!enclave || check_enclave_authentication(enclave)!=0 || enclave->state != RUNNING)
	{
		ret = -1UL;
		printm_err("[Penglai Monitor@%s] check enclave authentication is failed\n", __func__);
		goto out;
	}

	uintptr_t ocall_func_id = OCALL_SYS_WRITE;
	copy_to_host((uintptr_t*)enclave->ocall_func_id, &ocall_func_id, sizeof(uintptr_t));

	swap_from_enclave_to_host(regs, enclave);
	enclave->state = RUNNABLE;
	ret = ENCLAVE_OCALL;
out:
	spin_unlock(&enclave_metadata_lock);
	return ret;
}

uintptr_t enclave_derive_seal_key(uintptr_t* regs, uintptr_t salt_va, uintptr_t salt_len,
	uintptr_t key_buf_va, uintptr_t key_buf_len)
{
	uintptr_t ret = 0;
	int eid = get_enclave_id();
	struct enclave_t *enclave = NULL;

	pte_t *enclave_root_pt;
	SM3_STATE hash_ctx;
	unsigned char salt_local[HASH_SIZE];
	unsigned char hash[HASH_SIZE];

	if(key_buf_len > HASH_SIZE || salt_len > HASH_SIZE)
	{
		printm("[Penglai Monitor@%s] Seal key length or Salt length can't bigger then SM3 Hash size(32)\n", __func__);
		return -1;
	}
	
	if(check_in_enclave_world() < 0)
	{
		printm_err("[Penglai Monitor@%s] check enclave world is failed\n", __func__);
		return -1;
	}

	enclave = get_enclave(eid);

	spin_lock(&enclave_metadata_lock);

	if(!enclave || check_enclave_authentication(enclave)!=0 || enclave->state != RUNNING)
	{
		ret = -1UL;
		printm_err("[Penglai Monitor@%s] check enclave authentication is failed\n", __func__);
		goto out;
	}

	enclave_root_pt = (pte_t*)(enclave->thread_context.encl_ptbr << RISCV_PGSHIFT);
	ret = copy_from_enclave(enclave_root_pt, salt_local, (void *)salt_va, salt_len);
	if(ret != 0)
	{
		ret = -1UL;
		printm_err("[Penglai Monitor@%s] unknown error happended when copy from enclave\n", __func__);
		goto out;
	}

	SM3_init(&hash_ctx);
	SM3_process(&hash_ctx, (unsigned char*)DEV_PRI_KEY, PRIVATE_KEY_SIZE);
	SM3_process(&hash_ctx, enclave->hash, HASH_SIZE);
	SM3_process(&hash_ctx, enclave->signer, HASH_SIZE);
	SM3_process(&hash_ctx, salt_local, salt_len);
	SM3_done(&hash_ctx, hash);

	ret = copy_to_enclave(enclave_root_pt, (void *)key_buf_va, hash, key_buf_len);
	if(ret != 0){
		ret = -1UL;
		printm_err("[Penglai Monitor@%s] unknown error happended when copy to enclave\n", __func__);
		goto out;
	}

out:
	spin_unlock(&enclave_metadata_lock);
	return ret;
}

uintptr_t enclave_user_defined_ocall(uintptr_t* regs, uintptr_t ocall_buf_size)
{
	uintptr_t ret = 0;
	int eid = get_enclave_id();
	struct enclave_t* enclave = NULL;
	if(check_in_enclave_world() < 0)
	{
		printm_err("[Penglai Monitor@%s] check enclave world is failed\n", __func__);
		return -1;
	}

	enclave = get_enclave(eid);

	spin_lock(&enclave_metadata_lock);

	if(!enclave || check_enclave_authentication(enclave)!=0 || enclave->state != RUNNING)
	{
		ret = -1UL;
		printm_err("[Penglai Monitor@%s] check enclave authentication is failed\n", __func__);
		goto out;
	}

	uintptr_t ocall_func_id = OCALL_USER_DEFINED;
	copy_to_host((uintptr_t*)enclave->ocall_func_id, &ocall_func_id, sizeof(uintptr_t));
	copy_to_host((uintptr_t*)enclave->ocall_arg0, &ocall_buf_size, sizeof(uintptr_t));

	swap_from_enclave_to_host(regs, enclave);
	enclave->state = RUNNABLE;
	ret = ENCLAVE_OCALL;
out:
	spin_unlock(&enclave_metadata_lock);
	return ret;
}

/*
 * Timer handler for penglai enclaves
 * In normal case, an enclave will pin a HART and run until it finished.
 * The exception case is timer interrupt, which will trap into monitor to
 * check current enclave states.
 *
 * If current enclave states is not Running or Runnable, it will be stoped/destroyed
 *
 * */
uintptr_t do_timer_irq(uintptr_t *regs, uintptr_t mcause, uintptr_t mepc)
{
	uintptr_t retval = 0;
	unsigned int eid = get_enclave_id();
	struct enclave_t *enclave = get_enclave(eid);
	if (!enclave)
	{
		printm("[Penglai Monitor@%s]  something is wrong with enclave%d\r\n", __func__, eid);
		return -1UL;
	}

	spin_lock(&enclave_metadata_lock);

	/*
	 * An enclave trapping into monitor should not have other states.
	 * This is guaranteed by concurrency control for life cycle management。
	 */
	if (enclave->state != RUNNING && enclave->state != DESTROYED &&
		enclave->state != STOPPED) {
		printm_err("[Penglai Monitor@%s]  Enclave(%d) state is wrong!\r\n", __func__, eid);
		retval = -1;
	}

	swap_from_enclave_to_host(regs, enclave);

	if (enclave->state == DESTROYED) {
		sbi_memset((void*)(enclave->paddr), 0, enclave->size);
		mm_free((void*)(enclave->paddr), enclave->size);

		spin_unlock(&enclave_metadata_lock);

		//free enclave struct
		retval = free_enclave(eid); //the enclave state will be set INVALID here

		retval = ENCLAVE_SUCCESS; //this means we will not run any more
		goto timer_irq_out;
	}else if (enclave->state == RUNNING) {
		enclave->state = RUNNABLE;

		retval = ENCLAVE_TIMER_IRQ;
	}else { // The case for STOPPED
		retval = ENCLAVE_TIMER_IRQ;
	}

	spin_unlock(&enclave_metadata_lock);

timer_irq_out:
	csr_read_clear(CSR_MIE, MIP_MTIP);
	csr_read_set(CSR_MIP, MIP_STIP);
	/*ret set timer now*/
	// sbi_timer_event_start(csr_read(CSR_TIME) + ENCLAVE_TIME_CREDITS);
	return retval;
}

uintptr_t resume_from_ocall(uintptr_t* regs, unsigned int eid)
{
	uintptr_t retval = 0;
	uintptr_t ocall_func_id = regs[12];
	struct enclave_t* enclave = NULL;

	enclave = get_enclave(eid);
	if(!enclave || enclave->host_ptbr != csr_read(CSR_SATP))
	{
		printm("M mode: %s wrong enclave id or enclave doesn't belong to current host process\n", __func__);
		return -1UL;
	}

	spin_lock(&enclave_metadata_lock);

	switch(ocall_func_id)
	{
		case OCALL_SYS_WRITE:
			retval = enclave->thread_context.prev_state.a0;
			break;
		case OCALL_USER_DEFINED:
			retval = enclave->thread_context.prev_state.a0;
			break;
		default:
			retval = 0;
			break;
	}

	spin_unlock(&enclave_metadata_lock);

	retval = resume_enclave(regs, eid);
	return retval;
}
