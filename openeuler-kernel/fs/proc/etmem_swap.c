// SPDX-License-Identifier: GPL-2.0
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/proc_fs.h>
#include <linux/sched/mm.h>
#include <linux/mm.h>
#include <linux/swap.h>
#include <linux/mempolicy.h>
#include <linux/uaccess.h>
#include <linux/delay.h>

static ssize_t swap_pages_write(struct file *file, const char __user *buf,
				size_t count, loff_t *ppos)
{
	char *p, *data, *data_ptr_res;
	unsigned long vaddr;
	struct mm_struct *mm = file->private_data;
	struct page *page;
	LIST_HEAD(pagelist);
	int ret = 0;

	if (!mm || !mmget_not_zero(mm)) {
		ret = -ESRCH;
		goto out;
	}

	if (count < 0) {
		ret = -EOPNOTSUPP;
		goto out_mm;
	}

	data = memdup_user_nul(buf, count);
	if (IS_ERR(data)) {
		ret = PTR_ERR(data);
		goto out_mm;
	}

	data_ptr_res = data;
	while ((p = strsep(&data, "\n")) != NULL) {
		if (!*p)
			continue;

		ret = kstrtoul(p, 16, &vaddr);
		if (ret != 0)
			continue;
		/*If get page struct failed, ignore it, get next page*/
		page = get_page_from_vaddr(mm, vaddr);
		if (!page)
			continue;

		add_page_for_swap(page, &pagelist);
	}

	if (!list_empty(&pagelist))
		reclaim_pages(&pagelist);

	ret = count;
	kfree(data_ptr_res);
out_mm:
	mmput(mm);
out:
	return ret;
}

static int swap_pages_open(struct inode *inode, struct file *file)
{
	if (!try_module_get(THIS_MODULE))
		return -EBUSY;

	return 0;
}

static int swap_pages_release(struct inode *inode, struct file *file)
{
	module_put(THIS_MODULE);
	return 0;
}


extern struct file_operations proc_swap_pages_operations;

static int swap_pages_entry(void)
{
		proc_swap_pages_operations.owner = THIS_MODULE;
		proc_swap_pages_operations.write = swap_pages_write;
		proc_swap_pages_operations.open = swap_pages_open;
		proc_swap_pages_operations.release = swap_pages_release;

		return 0;
}

static void swap_pages_exit(void)
{
	memset(&proc_swap_pages_operations, 0,
			sizeof(proc_swap_pages_operations));
}

MODULE_LICENSE("GPL");
module_init(swap_pages_entry);
module_exit(swap_pages_exit);
