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

#ifndef HINIC_SRIOV_H
#define HINIC_SRIOV_H

enum hinic_sriov_state {
	HINIC_SRIOV_DISABLE,
	HINIC_SRIOV_ENABLE,
	HINIC_FUNC_REMOVE,
};

struct hinic_sriov_info {
	struct pci_dev *pdev;
	void *hwdev;
	bool sriov_enabled;
	unsigned int num_vfs;
	unsigned long state;
};

int hinic_pci_sriov_disable(struct pci_dev *dev);
int hinic_pci_sriov_enable(struct pci_dev *dev, int num_vfs);
int hinic_pci_sriov_configure(struct pci_dev *dev, int num_vfs);
int hinic_ndo_set_vf_mac(struct net_device *netdev, int vf, u8 *mac);
int hinic_ndo_set_vf_vlan(struct net_device *netdev, int vf, u16 vlan, u8 qos,
			  __be16 vlan_proto);

int hinic_ndo_get_vf_config(struct net_device *netdev, int vf,
			    struct ifla_vf_info *ivi);

int hinic_ndo_set_vf_spoofchk(struct net_device *netdev, int vf, bool setting);

int hinic_ndo_set_vf_trust(struct net_device *netdev, int vf, bool setting);

int hinic_ndo_set_vf_link_state(struct net_device *netdev, int vf_id, int link);

int hinic_ndo_set_vf_bw(struct net_device *netdev,
			int vf, int min_tx_rate, int max_tx_rate);
#endif
