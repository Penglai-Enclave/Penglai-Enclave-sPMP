// SPDX-License-Identifier: GPL-2.0
/* filescontrol.c - Cgroup controller for open file handles.
 *
 * Copyright 2014 Google Inc.
 * Author: Brian Makin <merimus@google.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <linux/page_counter.h>
#include <linux/filescontrol.h>
#include <linux/cgroup.h>
#include <linux/export.h>
#include <linux/printk.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/seq_file.h>
#include <linux/fdtable.h>
#include <linux/sched/signal.h>
#include <linux/module.h>

#define FILES_MAX ULLONG_MAX
#define FILES_MAX_STR "max"

static bool no_acct;
struct cgroup_subsys files_cgrp_subsys __read_mostly;
EXPORT_SYMBOL(files_cgrp_subsys);

module_param(no_acct, bool, 0444);

struct files_cgroup {
	struct cgroup_subsys_state css;
	struct page_counter open_handles;
};

static inline struct files_cgroup *css_fcg(struct cgroup_subsys_state *css)
{
	return css ? container_of(css, struct files_cgroup, css) : NULL;
}

static inline struct page_counter *
css_res_open_handles(struct cgroup_subsys_state *css)
{
	return &css_fcg(css)->open_handles;
}

static inline struct files_cgroup *
files_cgroup_from_files(struct files_struct *files)
{
	return files->files_cgroup;
}


static struct cgroup_subsys_state *
files_cgroup_css_alloc(struct cgroup_subsys_state *parent_css)
{
	struct files_cgroup *parent_fcg;
	struct files_cgroup *fcg;

	parent_fcg = css_fcg(parent_css);
	fcg = kzalloc(sizeof(*fcg), GFP_KERNEL);
	if (!fcg)
		goto out;

	if (!parent_fcg) {
		page_counter_init(&fcg->open_handles, NULL);
		page_counter_set_max(&fcg->open_handles, FILES_MAX);
	} else {
		struct page_counter *p_counter = &parent_fcg->open_handles;

		page_counter_init(&fcg->open_handles, p_counter);
		page_counter_set_max(&fcg->open_handles, FILES_MAX);
	}
	return &fcg->css;

out:
	return ERR_PTR(-ENOMEM);
}

static void files_cgroup_css_free(struct cgroup_subsys_state *css)
{
	kfree(css_fcg(css));
}

u64 files_cgroup_count_fds(struct files_struct *files)
{
	int i;
	struct fdtable *fdt;
	int retval = 0;

	fdt = files_fdtable(files);
	for (i = 0; i < DIV_ROUND_UP(fdt->max_fds, BITS_PER_LONG); i++)
		retval += hweight64((__u64)fdt->open_fds[i]);
	return retval;
}

/*
 * If attaching this cgroup would overcommit the resource then deny
 * the attach. If not, attach the file resource into new cgroup.
 */
static int files_cgroup_can_attach(struct cgroup_taskset *tset)
{
	u64 num_files;
	bool can_attach;
	struct cgroup_subsys_state *to_css;
	struct cgroup_subsys_state *from_css;
	struct page_counter *from_res;
	struct page_counter *to_res;
	struct page_counter *fail_res;
	struct files_struct *files;
	struct task_struct *task = cgroup_taskset_first(tset, &to_css);

	to_res = css_res_open_handles(to_css);

	task_lock(task);
	files = task->files;
	if (!files || files == &init_files) {
		task_unlock(task);
		return 0;
	}

	from_css = &files_cgroup_from_files(files)->css;
	from_res = css_res_open_handles(from_css);

	spin_lock(&files->file_lock);
	num_files = files_cgroup_count_fds(files);
	page_counter_uncharge(from_res, num_files);

	if (!page_counter_try_charge(to_res, num_files, &fail_res)) {
		page_counter_charge(from_res, num_files);
		pr_err("Open files limit overcommited\n");
		can_attach = false;
	} else {
		css_put(from_css);
		css_get(to_css);
		task->files->files_cgroup = css_fcg(to_css);
		can_attach = true;
	}
	spin_unlock(&files->file_lock);
	task_unlock(task);
	return can_attach ? 0 : -ENOSPC;
}

int files_cgroup_alloc_fd(struct files_struct *files, u64 n)
{
	/*
	 * Kernel threads which are forked by kthreadd inherited the
	 * const files_struct 'init_files', we didn't wrap it so
	 * there's no associated files_cgroup.
	 *
	 *  Kernel threads always stay in root cgroup, and we don't
	 *  have limit for root files cgroup, so it won't hurt if
	 *  we don't charge their fds, only issue is that files.usage
	 *  won't be accurate in root files cgroup.
	 */
	if (!no_acct && files != &init_files) {
		struct page_counter *fail_res;
		struct files_cgroup *files_cgroup =
			files_cgroup_from_files(files);
		if (!page_counter_try_charge(&files_cgroup->open_handles,
				       n, &fail_res))
			return -ENOMEM;
	}
	return 0;
}
EXPORT_SYMBOL(files_cgroup_alloc_fd);

void files_cgroup_unalloc_fd(struct files_struct *files, u64 n)
{
	/*
	 * It's not charged so no need to uncharge, see comments in
	 * files_cgroup_alloc_fd.
	 */
	if (!no_acct && files != &init_files) {
		struct files_cgroup *files_cgroup =
		       files_cgroup_from_files(files);
		page_counter_uncharge(&files_cgroup->open_handles, n);
	}
}
EXPORT_SYMBOL(files_cgroup_unalloc_fd);

static u64 files_disabled_read(struct cgroup_subsys_state *css,
			       struct cftype *cft)
{
	return no_acct;
}

static int files_disabled_write(struct cgroup_subsys_state *css,
				    struct cftype *cft, u64 val)
{
	if (!val)
		return -EINVAL;
	no_acct = true;

	return 0;
}

static int files_limit_read(struct seq_file *sf, void *v)
{
	struct files_cgroup *fcg = css_fcg(seq_css(sf));
	struct page_counter *counter = &fcg->open_handles;
	u64 limit = counter->max;

	if (limit >= FILES_MAX)
		seq_printf(sf, "%s\n", FILES_MAX_STR);
	else
		seq_printf(sf, "%llu\n", limit);

	return 0;
}

static ssize_t files_limit_write(struct kernfs_open_file *of,
			char *buf, size_t nbytes, loff_t off)
{
	struct files_cgroup *fcg = css_fcg(of_css(of));
	u64 limit;
	int err;

	buf = strstrip((char *)buf);
	if (!strcmp(buf, FILES_MAX_STR)) {
		limit = FILES_MAX;
		goto set_limit;
	}

	err = kstrtoull(buf, 0, &limit);
	if (err)
		return err;

set_limit:
	/*
	 * Limit updates don't need to be mutex'd, since it isn't
	 * critical that any racing fork()s follow the new limit.
	 */
	page_counter_set_max(&fcg->open_handles, limit);
	return nbytes;
}


static u64 files_usage_read(struct cgroup_subsys_state *css,
			struct cftype *cft)
{
	struct files_cgroup *fcg = css_fcg(css);

	return page_counter_read(&fcg->open_handles);
}

static struct cftype files[] = {
	{
		.name = "limit",
		.seq_show  = files_limit_read,
		.write = files_limit_write,
		.flags = CFTYPE_NOT_ON_ROOT,
	},
	{
		.name = "usage",
		.read_u64 = files_usage_read,
	},
	{
		.name = "no_acct",
		.flags = CFTYPE_ONLY_ON_ROOT,
		.read_u64 = files_disabled_read,
		.write_u64 = files_disabled_write,
	},
	{ }
};

struct cgroup_subsys files_cgrp_subsys = {
	.css_alloc = files_cgroup_css_alloc,
	.css_free = files_cgroup_css_free,
	.can_attach = files_cgroup_can_attach,
	.legacy_cftypes = files,
	.dfl_cftypes = files,
};

/*
 * It could race against cgroup migration of current task, and
 * using task_get_css() to get a valid css.
 */
void files_cgroup_assign(struct files_struct *files)
{
	struct cgroup_subsys_state *css;

	if (files == &init_files)
		return;

	css = task_get_css(current, files_cgrp_id);
	files->files_cgroup = container_of(css, struct files_cgroup, css);
}

void files_cgroup_remove(struct files_struct *files)
{
	struct task_struct *tsk = current;
	struct files_cgroup *fcg;

	if (files == &init_files)
		return;

	task_lock(tsk);
	spin_lock(&files->file_lock);
	fcg = files_cgroup_from_files(files);
	css_put(&fcg->css);
	spin_unlock(&files->file_lock);
	task_unlock(tsk);
}
