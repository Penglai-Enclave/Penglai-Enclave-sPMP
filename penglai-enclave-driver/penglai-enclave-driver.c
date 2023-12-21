#include <linux/mm.h>
#include <linux/file.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/miscdevice.h>
#include "penglai-enclave-driver.h"
#include "penglai-enclave-ioctl.h"

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("enclave_ioctl");
MODULE_AUTHOR("LuXu");
MODULE_VERSION("enclave_ioctl");

// #define PENGLAI_DEBUG
#ifdef PENGLAI_DEBUG
#define dprint(...) printk(__VA_ARGS__)
#else
#define dprint(...)
#endif

static int enclave_mmap(struct file* f,struct vm_area_struct *vma)
{
	return 0;
}

static const struct file_operations enclave_ops = {
	.owner = THIS_MODULE,
	.mmap = enclave_mmap,
	.unlocked_ioctl = penglai_enclave_ioctl
};

struct miscdevice enclave_dev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "penglai_enclave_dev",
	.fops = &enclave_ops,
	.mode = 0666,
};

//static int enclave_ioctl_init(void)
int enclave_ioctl_init(void)
{
	int ret;
	unsigned long addr;
	struct sbiret sbiret;
	printk("enclave_ioctl_init...\n");

	//register enclave_dev
	ret=misc_register(&enclave_dev);
	if(ret < 0)
	{
		printk("Enclave_driver: register enclave_dev failed!(ret:%d)\n",
				ret);
		goto deregister_device;
	}

	/* [Dd] Should we broadcast some states (e.g., PT_area region) to other harts? */
	/* [LX] sm will broadcast */
	addr = __get_free_pages(GFP_HIGHUSER, DEFAULT_SECURE_PAGES_ORDER);
	if(!addr)
	{
		printk("[Penglai KModule]: can not get free page which order is 0x%x", DEFAULT_SECURE_PAGES_ORDER);
		ret = -1;
		goto deregister_device;
	}

#if 1
	sbiret = SBI_CALL_2(SBI_SM_INIT, __pa(addr), 1 << (DEFAULT_SECURE_PAGES_ORDER + RISCV_PGSHIFT));
	ret = sbiret.value;
	//if(ret < 0)
	if(sbiret.error)
	{
		printk("[Penglai KModule]: sbi call mm_init is failed\n");
		goto deregister_device;
	}
#endif
	printk("[Penglai KModule] register_chrdev succeeded!\n");
	return 0;

deregister_device:
	misc_deregister(&enclave_dev);
	return ret;
}

//static void enclave_ioctl_exit(void)
void enclave_ioctl_exit(void)
{
	unsigned long addr, order, count;
	unsigned long *size_ptr = kmalloc(sizeof(unsigned long), GFP_KERNEL);
	
	struct sbiret sbiret;
	printk("enclave_ioctl_exit...\n");

	
	sbiret = SBI_CALL_2(SBI_SM_FREE_ENCLAVE_MEM, __pa(size_ptr), FREE_MAX_MEMORY);

	addr = (unsigned long)(sbiret.value);
	while (addr)
	{
		order = ilog2((*size_ptr) - 1) + 1;
		count = 0x1 << order;
		if (count != (*size_ptr) && (*size_ptr > 0))
		{
			printk("KERNEL MODULE:  the number of free pages is not exponential times of two\n");
			kfree(size_ptr);
			return;
		}
		printk("KERNEL MODULE:  free secmem:paddr:%lx, vaddr:%lx, order:%lu\n", addr, __va(addr), order);
		if ((*size_ptr) > 0)
		{
			free_pages((long unsigned int)__va(addr), (order - RISCV_PGSHIFT));
		}
		*size_ptr = 0;
		sbiret = SBI_CALL_2(SBI_SM_FREE_ENCLAVE_MEM, __pa(size_ptr), FREE_MAX_MEMORY);

		addr = (unsigned long)(sbiret.value);
	}

deregister_device:
	kfree(size_ptr);
	misc_deregister(&enclave_dev);
	return;
}

module_init(enclave_ioctl_init);
module_exit(enclave_ioctl_exit);
