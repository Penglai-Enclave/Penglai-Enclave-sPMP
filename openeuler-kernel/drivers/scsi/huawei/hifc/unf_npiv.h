/* SPDX-License-Identifier: GPL-2.0 */
/* Huawei Hifc PCI Express Linux driver
 * Copyright(c) 2017 Huawei Technologies Co., Ltd
 *
 */
#ifndef __NPIV_H__
#define __NPIV_H__

/* product VPORT configure */
struct vport_config_s {
	unsigned long long node_name;
	unsigned long long port_name;
	unsigned int port_mode; /* INI, TGT or both */
};

/* product Vport function */
#define PORTID_VPINDEX_MASK 0xff000000
#define PORTID_VPINDEX_SHIT 24
unsigned int unf_npiv_conf(unsigned int v_port_id, unsigned long long v_wwpn);
struct unf_lport_s *unf_create_vport(struct unf_lport_s *v_lport,
				     struct vport_config_s *v_vport_config);
unsigned int unf_delete_vport(unsigned int v_port_id, unsigned int v_vp_index);

/* Vport pool creat and release function */
unsigned int unf_init_vport_pool(struct unf_lport_s *v_lport);
void unf_free_vport_pool(struct unf_lport_s *v_lport);

/* Lport resigster stLPortMgTemp function */
void unf_vport_remove(void *v_vport);
void unf_vport_ref_dec(struct unf_lport_s *v_vport);

/* linkdown all Vport after receive linkdown event */
void unf_linkdown_all_vports(void *v_lport);
/* Lport receive Flogi Acc linkup all Vport */
void unf_linkup_all_vports(struct unf_lport_s *v_lport);
/* Lport remove delete all Vport */
void unf_destroy_all_vports(struct unf_lport_s *v_lport);
void unf_vport_fabric_logo(struct unf_lport_s *v_vport);
unsigned int unf_destroy_one_vport(struct unf_lport_s *v_vport);
struct unf_lport_s *unf_alloc_vport(struct unf_lport_s *v_lport,
				    unsigned long long v_wwpn);
unsigned int unf_drop_vport(struct unf_lport_s *v_vport);
void unf_link_down_one_vport(struct unf_lport_s *v_vport);
void *unf_lookup_vport_by_vp_index(void *v_lport, unsigned short v_vp_index);
void *unf_lookup_vport_by_port_id(void *v_lport, unsigned int v_port_id);
void *unf_lookup_vport_by_did(void *v_lport, unsigned int v_did);
void *unf_lookup_vport_by_wwpn(void *v_lport, unsigned long long v_wwpn);

#endif
