#include "penglai-enclave.h"
DEFINE_IDR(idr_enclave);
DEFINE_SPINLOCK(idr_enclave_lock);

/*
 * ACK (DD): the idr_alloc function is learned from keystone :)
 * */
unsigned int enclave_idr_alloc(enclave_t* enclave)
{
	unsigned int ueid;

	spin_lock_bh(&idr_enclave_lock);
	ueid = idr_alloc(&idr_enclave, enclave, ENCLAVE_IDR_MIN, ENCLAVE_IDR_MAX, GFP_KERNEL);
	spin_unlock_bh(&idr_enclave_lock);

	if (ueid < ENCLAVE_IDR_MIN || ueid >= ENCLAVE_IDR_MAX) {
		printk("KERNEL MODULE: failed to allocate UID\n");
		return 0;
	}

	return ueid;
}

enclave_t* enclave_idr_remove(unsigned int ueid)
{
	enclave_t* enclave;

	spin_lock_bh(&idr_enclave_lock);
	enclave = idr_remove(&idr_enclave, ueid);
	spin_unlock_bh(&idr_enclave_lock);

	return enclave;
}

enclave_t* get_enclave_by_id(unsigned int ueid)
{
	enclave_t* enclave;

	spin_lock_bh(&idr_enclave_lock);
	enclave = idr_find(&idr_enclave, ueid);
	spin_unlock_bh(&idr_enclave_lock);

	return enclave;
}

enclave_t* create_enclave(int total_pages)
{
	vaddr_t addr = 0;
	paddr_t pa = 0;
	enclave_t* enclave = kmalloc(sizeof(enclave_t), GFP_KERNEL);
	enclave_mem_t* enclave_mem = kmalloc(sizeof(enclave_mem_t), GFP_KERNEL);
	untrusted_mem_t* untrusted_mem = kmalloc(sizeof(untrusted_mem_t), GFP_KERNEL);
	require_sec_memory_t  require_sec_memory;

	int size;
	struct sbiret ret;
	unsigned long order = ilog2(total_pages-1) + 1;

	if(!enclave || !enclave_mem || !untrusted_mem)
	{
		printk("KERNEL MODULE: no enough kernel memory\n");
		goto free_enclave;
	}

	printk("[Penglai Driver@%s] total_pages:%d order:%ld\n",
			__func__, total_pages, order);
	//Note: SBI_SM_ALLOC_ENCLAVE_MEM's arg is the num of bytes instead of pages
	require_sec_memory.size = total_pages << RISCV_PGSHIFT;
	ret = SBI_CALL_1(SBI_SM_ALLOC_ENCLAVE_MEM, __pa(&require_sec_memory));
	pa = require_sec_memory.paddr;

	if (ret.error){
		printk("[Penglai SDK Driver Error@%s] alloc_enclave_mem error\n", __func__);
	}
	while(ret.value == ENCLAVE_NO_MEMORY)
	{
		//TODO: allocate certain memory region like sm_init instead of allocating size of one enclave
		addr = __get_free_pages(GFP_HIGHUSER, order);
		if(!addr)
		{
			printk("KERNEL MODULE: can not get free page which order is 0x%lx", order);
			goto free_enclave;
		}

		ret = SBI_CALL_2(SBI_SM_MEMORY_EXTEND, __pa(addr), 4096 * (1 << order) );
		if(ret.error)
		{
			printk("KERNEL MODULE: sbi call extend memory is failed\n");
			goto free_enclave;
		}

		//FIXME: use physical address
		//ret = SBI_CALL_1(SBI_SM_ALLOC_ENCLAVE_MEM, &require_sec_memory);
		ret = SBI_CALL_1(SBI_SM_ALLOC_ENCLAVE_MEM, __pa(&require_sec_memory));
		pa = require_sec_memory.paddr;
	}

	//if(ret < 0 && ret != ENCLAVE_NO_MEMORY)
	if(ret.value!=0 && ret.value != ENCLAVE_NO_MEMORY)
	{
		printk("KERNEL MODULE: [SBI_CALL]alloc enclave mem failed\n");
		goto free_enclave;
	}

	addr = (vaddr_t)__va(pa);
	size = require_sec_memory.resp_size;
	INIT_LIST_HEAD(&enclave_mem->free_mem);
	enclave_mem_int(enclave_mem, addr, size, __pa(addr));
	enclave->enclave_mem = enclave_mem;
	enclave->untrusted_mem = untrusted_mem;

	//TODO: create untrusted mem

	return enclave;

free_enclave:

	if(enclave) kfree(enclave);
	if(enclave_mem) kfree(enclave_mem);
	if(untrusted_mem) kfree(untrusted_mem);

	return NULL;
}

/*
 * This function should be called with enclave_big_lock acquired
 * */
int destroy_enclave(enclave_t* enclave)
{
	enclave_mem_t* enclave_mem;
	untrusted_mem_t* untrusted_mem;

	if(!enclave)
		return -1;

	enclave_mem = enclave->enclave_mem;
	untrusted_mem = enclave->untrusted_mem;
	enclave_mem_destroy(enclave_mem);

	kfree(enclave_mem);
	kfree(untrusted_mem);
	kfree(enclave);

	return 0;
}
