#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include <linux/pagemap.h>
#include <linux/pagevec.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/proc_fs.h>
#include <linux/kdev_t.h>
#include <linux/vmalloc.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include "internal.h"

static char *buf_dirty;	/* buffer to store number of dirty pages */
static unsigned long buf_size;	/* size of buffer in bytes */
static long buff_num;	/* size of buffer in number of pages */
static int buff_limit;	/* filter threshold of dirty pages*/

static struct proc_dir_entry *dirty_dir;

static struct mutex buff_used;	/* buffer is in used */
static struct mutex buff_lock;	/* lock when buffer is changed */
DEFINE_SPINLOCK(inode_sb_list_lock);

/* proc root directory */
#define DIRTY_ROOT "dirty"
/* proc file for buffer allocation and release */
#define DIRTY_SWITCH "buffer_size"
/* proc file to obtain diry pages of each inode */
#define DIRTY_PAGES "dirty_list"
/* proc file to filter result */
#define DIRTY_LIMIT "page_threshold"

#define MAX_BUFF_SIZE 102400
static void seq_set_overflow(struct seq_file *m)
{
	m->count = m->size;
}

static unsigned long dump_dirtypages_inode(struct inode *inode)
{
	struct pagevec pvec;
	unsigned long nr_dirtys = 0;
	unsigned int nr_pages;
	pgoff_t index = 0;

	pagevec_init(&pvec);

	while (1) {
		nr_pages = pagevec_lookup_range_tag(&pvec, inode->i_mapping,
				&index, (pgoff_t)-1, PAGECACHE_TAG_DIRTY);
		if (!nr_pages)
			break;

		pagevec_release(&pvec);
		cond_resched();

		nr_dirtys += nr_pages;
	}

	return nr_dirtys;
}

static char *inode_filename(struct inode *inode, char *tmpname)
{
	struct dentry *dentry;
	char *filename;

	dentry = d_find_alias(inode);
	if (!dentry)
		return ERR_PTR(-ENOENT);

	tmpname[PATH_MAX-1] = '\0';
	filename = dentry_path_raw(dentry, tmpname, PATH_MAX);

	dput(dentry);

	return filename;
}

static inline bool is_sb_writable(struct super_block *sb)
{
	if (sb_rdonly(sb))
		return false;

	if (sb->s_writers.frozen == SB_FREEZE_COMPLETE)
		return false;

	return true;
}

/*
 * dump_dirtypages_sb - dump the dirty pages of each inode in the sb
 * @sb the super block
 * @m the seq_file witch is initialized in proc_dpages_open
 *
 * For each inode in the sb, call dump_dirtypages_pages to get the number
 * of dirty pages. And use seq_printf to store the result in the buffer
 * if it's not less than the threshold. The inode in unusual state will
 * be skipped.
 */
static void dump_dirtypages_sb(struct super_block *sb, struct seq_file *m)
{
	struct inode *inode, *toput_inode = NULL;
	unsigned long nr_dirtys;
	const char *fstype;
	char *filename;
	char *tmpname;
	int limit = READ_ONCE(buff_limit);

	if (!is_sb_writable(sb))
		return;

	tmpname = kmalloc(PATH_MAX, GFP_KERNEL);
	if (!tmpname)
		return;

	spin_lock(&inode_sb_list_lock);
	list_for_each_entry(inode, &sb->s_inodes, i_sb_list) {
		spin_lock(&inode->i_lock);

		/*
		 * We must skip inodes in unusual state. We may also skip
		 * inodes without pages but we deliberately won't in case
		 * we need to reschedule to avoid softlockups.
		 */
		if ((inode->i_state & (I_FREEING|I_WILL_FREE|I_NEW)) ||
		    (inode->i_mapping->nrpages == 0 && !need_resched())) {
			spin_unlock(&inode->i_lock);
			continue;
		}
		__iget(inode);
		spin_unlock(&inode->i_lock);
		spin_unlock(&inode_sb_list_lock);

		cond_resched();

		nr_dirtys = dump_dirtypages_inode(inode);
		if (!nr_dirtys || nr_dirtys < limit)
			goto skip;

		filename = inode_filename(inode, tmpname);
		if (IS_ERR_OR_NULL(filename))
			filename = "unknown";

		if (sb->s_type && sb->s_type->name)
			fstype = sb->s_type->name;
		else
			fstype = "unknown";
		/*
		 * seq_printf return nothing, if the buffer is exhausted
		 * (m->size <= m->count), seq_printf will not store
		 * anything, just set m->count = m->size and return. In
		 * that case, log a warn message in buffer to remind users.
		 */
		if (m->size <= m->count) {
			seq_set_overflow(m);
			strncpy(m->buf+m->count-12, "terminated\n\0", 12);
			goto done;
		}
		seq_printf(m, "FSType: %s, Dev ID: %u(%u:%u) ino %lu, dirty pages %lu, path %s\n",
			fstype, sb->s_dev, MAJOR(sb->s_dev),
			MINOR(sb->s_dev), inode->i_ino,
			nr_dirtys, filename);
skip:
		iput(toput_inode);
		toput_inode = inode;
		spin_lock(&inode_sb_list_lock);
	}
	spin_unlock(&inode_sb_list_lock);
done:
	iput(toput_inode);
	kfree(tmpname);
}

static int proc_dpages_show(struct seq_file *m, void *v)
{
	iterate_supers((void *)dump_dirtypages_sb, (void *)m);
	return 0;
}


static ssize_t seq_read_dirty(
	struct file *file,
	char __user *buf,
	size_t size,
	loff_t *ppos)
{
	struct seq_file *m = (struct seq_file *)file->private_data;
	size_t copied = 0;
	size_t n;
	int err = 0;

	if (!mutex_trylock(&buff_used))
		return -EBUSY;
	/* don't allow buffer to change during read */
	mutex_lock(&buff_lock);
	if (m->count == 0) {
		memset(buf_dirty, 0, buf_size);
		if (!m->buf) {
			m->size = buf_size;
			m->buf = buf_dirty;
		}
		err = m->op->show(m, NULL);
		if (err < 0)
			goto done;
	}

	/* if buffer changed somehow */
	if (m->size != buf_size) {
		mutex_unlock(&buff_lock);
		mutex_unlock(&buff_used);
		return -EFAULT;
	}

	n = min(m->count - m->from, size);
	err = simple_read_from_buffer(buf, n,
		(loff_t *) &m->from, m->buf, m->count);
	if (err < 0) {
		err = -EFAULT;
		goto done;
	}
	copied += n;
done:
	if (!copied)
		copied = err;
	else
		*ppos += copied;

	mutex_unlock(&buff_lock);
	mutex_unlock(&buff_used);
	return copied;
}

static void free_buf_dirty(void)
{
	if (buf_dirty != NULL) {
		vfree(buf_dirty);
		buf_dirty = NULL;
		buf_size = 0;
	}
}
static ssize_t write_proc(
	struct file *filp,
	const char *buf,
	size_t count,
	loff_t *offp)
{
	char *msg;
	int ret = 0;
	long old_buff_num;

	if (!mutex_trylock(&buff_used))
		return -EBUSY;

	if (count > PAGE_SIZE) {
		ret = -EINVAL;
		goto error;
	}

	msg = kzalloc(PAGE_SIZE, GFP_KERNEL);
	if (!msg) {
		ret = -ENOMEM;
		goto error;
	}

	if (copy_from_user(msg, buf, count)) {
		ret = -EINVAL;
		goto free;
	}
	old_buff_num = buff_num;
	ret = kstrtol(msg, 10, &buff_num);
	if (ret != 0 || buff_num < 0 || buff_num > MAX_BUFF_SIZE) {
		buff_num = old_buff_num;
		ret = -EINVAL;
		goto free;
	}

	mutex_lock(&buff_lock);

	ret = count;
	if (buff_num == 0) {
		free_buf_dirty();
		goto out;
	}
	if (buff_num == old_buff_num)
		goto out;

	free_buf_dirty();
	buf_size = PAGE_SIZE * buff_num;
	buf_dirty = vzalloc(buf_size);

	if (!buf_dirty) {
		ret = -ENOMEM;
		goto out;
	}
out:
	mutex_unlock(&buff_lock);
free:
	kfree(msg);
error:
	mutex_unlock(&buff_used);
	return ret;
}

static int proc_dpages_open(struct inode *inode, struct file *filp)
{
	if (buf_dirty == NULL || buf_size == 0) {
		pr_warn("please allocate buffer before getting dirty pages\n");
		return -ENOMEM;
	}

	return single_open(filp, proc_dpages_show, NULL);

}

static int seq_release_dirty(struct inode *inode, struct file *file)
{
	struct seq_file *m = file->private_data;

	/* we don't want to free the buf */
	m->buf = NULL;
	single_release(inode, file);
	return 0;
}

static const struct proc_ops proc_dpages_operations = {
	.proc_open           = proc_dpages_open,
	.proc_read           = seq_read_dirty,
	.proc_release        = seq_release_dirty,
};

static int proc_switch_show(struct seq_file *m, void *v)
{
	seq_printf(m, "%ld\n", buff_num);
	return 0;
}

static int proc_limit_show(struct seq_file *m, void *v)
{
	seq_printf(m, "%d\n", READ_ONCE(buff_limit));
	return 0;
}

static int proc_switch_open(struct inode *inode, struct file *filp)
{
	return single_open(filp, proc_switch_show, NULL);
}

static int proc_limit_open(struct inode *inode, struct file *filp)
{
	return single_open(filp, proc_limit_show, NULL);
}

static ssize_t write_limit_proc(
	struct file *filp,
	const char *buf,
	size_t count,
	loff_t *offp)
{
	char *msg;
	int ret = 0;
	long temp;

	if (count > PAGE_SIZE) {
		ret = -EINVAL;
		goto error;
	}

	msg = kzalloc(PAGE_SIZE, GFP_KERNEL);
	if (!msg) {
		ret = -ENOMEM;
		goto error;
	}

	if (copy_from_user(msg, buf, count)) {
		ret = -EINVAL;
		goto free;
	}
	ret = kstrtol(msg, 10, &temp);
	if (ret != 0 || temp < 0 || temp > INT_MAX) {
		ret = -EINVAL;
		goto free;
	}

	WRITE_ONCE(buff_limit, temp);
	ret = count;

free:
	kfree(msg);
error:
	return ret;
}


static const struct proc_ops proc_switch_operations = {
	.proc_open           = proc_switch_open,
	.proc_read           = seq_read,
	.proc_write          = write_proc,
	.proc_lseek          = seq_lseek,
	.proc_release        = single_release,
};

static const struct proc_ops proc_limit_operations = {
	.proc_open           = proc_limit_open,
	.proc_read           = seq_read,
	.proc_write          = write_limit_proc,
	.proc_lseek          = seq_lseek,
	.proc_release        = single_release,
};


static int __init dpages_proc_init(void)
{
	static struct proc_dir_entry *proc_file;

	dirty_dir = proc_mkdir(DIRTY_ROOT, NULL);
	if (!dirty_dir)
		goto fail_dir;

	proc_file = proc_create(DIRTY_PAGES, 0440,
					dirty_dir, &proc_dpages_operations);
	if (!proc_file)
		goto fail_pages;

	proc_file = proc_create(DIRTY_SWITCH, 0640,
					dirty_dir, &proc_switch_operations);
	if (!proc_file)
		goto fail_switch;

	proc_file = proc_create(DIRTY_LIMIT, 0640,
					dirty_dir, &proc_limit_operations);
	if (!proc_file)
		goto fail_limit;

	mutex_init(&buff_used);
	mutex_init(&buff_lock);
	return 0;

fail_limit:
	remove_proc_entry(DIRTY_SWITCH, dirty_dir);
fail_switch:
	remove_proc_entry(DIRTY_PAGES, dirty_dir);
fail_pages:
	remove_proc_entry(DIRTY_ROOT, NULL);
fail_dir:
	return -ENOMEM;
}

static void dpages_proc_exit(void)
{
	mutex_lock(&buff_lock);
	free_buf_dirty();
	mutex_unlock(&buff_lock);
	remove_proc_entry(DIRTY_PAGES, dirty_dir);
	remove_proc_entry(DIRTY_SWITCH, dirty_dir);
	remove_proc_entry(DIRTY_LIMIT, dirty_dir);
	remove_proc_entry(DIRTY_ROOT, NULL);
}

module_init(dpages_proc_init);
module_exit(dpages_proc_exit);
