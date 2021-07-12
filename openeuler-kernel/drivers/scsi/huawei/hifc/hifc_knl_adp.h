/* SPDX-License-Identifier: GPL-2.0 */
/* Huawei Hifc PCI Express Linux driver
 * Copyright(c) 2017 Huawei Technologies Co., Ltd
 *
 */

#ifndef HIFC_KNL_ADP_H_
#define HIFC_KNL_ADP_H_

#include <linux/types.h>
#include <linux/compiler.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/pci.h>
#include <linux/interrupt.h>
#include <linux/jiffies.h>
#include <linux/cpufreq.h>
#include <linux/semaphore.h>
#include <linux/sched.h>
#include <linux/kthread.h>
#include <linux/vmalloc.h>
#include <linux/version.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/delay.h>
#include <linux/workqueue.h>
#include <linux/scatterlist.h>
#include <scsi/scsi.h>
#include <scsi/scsi_host.h>
#include <scsi/scsi_device.h>
#include <scsi/scsi_cmnd.h>
#include <scsi/scsi_tcq.h>
#include <scsi/scsi_transport_fc.h>
#include <linux/sched/signal.h>

#define __TIME_STR__    "[compiled with the kernel]"

#define sdk_err(dev, format, ...)		\
	dev_err(dev, "[COMM]"format, ##__VA_ARGS__)
#define sdk_warn(dev, format, ...)		\
	dev_warn(dev, "[COMM]"format, ##__VA_ARGS__)
#define sdk_notice(dev, format, ...)		\
	dev_notice(dev, "[COMM]"format, ##__VA_ARGS__)
#define sdk_info(dev, format, ...)		\
	dev_info(dev, "[COMM]"format, ##__VA_ARGS__)

#endif
