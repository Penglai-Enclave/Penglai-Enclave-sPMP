/* SPDX-License-Identifier: GPL-2.0*/
/* Huawei HiNIC PCI Express Linux driver
 * Copyright(c) 2017 Huawei Technologies Co., Ltd
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 *
 */

#ifndef OSSL_KNL_H
#define OSSL_KNL_H

#include <linux/string.h>
#include <linux/pci.h>
#include <linux/device.h>
#include <linux/version.h>
#include <linux/ethtool.h>
#include <linux/fs.h>
#include <linux/kthread.h>
#include <net/checksum.h>
#include <net/ipv6.h>
#include <linux/if_vlan.h>
#include <linux/udp.h>
#include <linux/highmem.h>

#define sdk_err(dev, format, ...)		\
	dev_err(dev, "[COMM]" format, ##__VA_ARGS__)
#define sdk_warn(dev, format, ...)		\
	dev_warn(dev, "[COMM]" format, ##__VA_ARGS__)
#define sdk_notice(dev, format, ...)		\
	dev_notice(dev, "[COMM]" format, ##__VA_ARGS__)
#define sdk_info(dev, format, ...)		\
	dev_info(dev, "[COMM]" format, ##__VA_ARGS__)

#define nic_err(dev, format, ...)		\
	dev_err(dev, "[NIC]" format, ##__VA_ARGS__)
#define nic_warn(dev, format, ...)		\
	dev_warn(dev, "[NIC]" format, ##__VA_ARGS__)
#define nic_notice(dev, format, ...)		\
	dev_notice(dev, "[NIC]" format, ##__VA_ARGS__)
#define nic_info(dev, format, ...)		\
	dev_info(dev, "[NIC]" format, ##__VA_ARGS__)

#define nicif_err(priv, type, dev, fmt, args...)		\
	netif_level(err, priv, type, dev, "[NIC]" fmt, ##args)
#define nicif_warn(priv, type, dev, fmt, args...)		\
	netif_level(warn, priv, type, dev, "[NIC]" fmt, ##args)
#define nicif_notice(priv, type, dev, fmt, args...)		\
	netif_level(notice, priv, type, dev, "[NIC]" fmt, ##args)
#define nicif_info(priv, type, dev, fmt, args...)		\
	netif_level(info, priv, type, dev, "[NIC]" fmt, ##args)
#define nicif_dbg(priv, type, dev, fmt, args...)		\
	netif_level(dbg, priv, type, dev, "[NIC]" fmt, ##args)

#define tasklet_state(tasklet) ((tasklet)->state)

#endif /* OSSL_KNL_H */
