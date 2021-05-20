/* SPDX-License-Identifier: GPL-2.0 */
/* Huawei Hifc PCI Express Linux driver
 * Copyright(c) 2017 Huawei Technologies Co., Ltd
 *
 */
#ifndef __UNF_SERVICE_H__
#define __UNF_SERVICE_H__

extern unsigned int max_frame_size;

#define UNF_SET_ELS_ACC_TYPE(v_els_cmd) \
		((unsigned int)(v_els_cmd) << 16 | ELS_ACC)
#define UNF_SET_ELS_RJT_TYPE(v_els_cmd) \
		((unsigned int)(v_els_cmd) << 16 | ELS_RJT)

unsigned int unf_send_gid_ft(struct unf_lport_s *v_lport,
			     struct unf_rport_s *v_rport);
unsigned int unf_send_gid_pt(struct unf_lport_s *v_lport,
			     struct unf_rport_s *v_rport);
unsigned int unf_send_gpn_id(struct unf_lport_s *v_lport,
			     struct unf_rport_s *v_sns_port,
			     unsigned int v_nport_id);
unsigned int unf_send_gnn_id(struct unf_lport_s *v_lport,
			     struct unf_rport_s *v_sns_port,
			     unsigned int v_nport_id);
unsigned int unf_send_gff_id(struct unf_lport_s *v_lport,
			     struct unf_rport_s *v_sns_port,
			     unsigned int v_nport_id);
unsigned int unf_send_flogi(struct unf_lport_s *v_lport,
			    struct unf_rport_s *v_rport);
unsigned int unf_send_fdisc(struct unf_lport_s *v_lport,
			    struct unf_rport_s *v_rport);
unsigned int unf_send_plogi(struct unf_lport_s *v_lport,
			    struct unf_rport_s *v_rport);
unsigned int unf_send_prli(struct unf_lport_s *v_lport,
			   struct unf_rport_s *v_rport);
unsigned int unf_receive_els_pkg(void *v_lport,
				 struct unf_frame_pkg_s *v_fra_pkg);
unsigned int unf_send_rff_id(struct unf_lport_s *v_lport,
			     struct unf_rport_s *v_rport);
unsigned int unf_send_rft_id(struct unf_lport_s *v_lport,
			     struct unf_rport_s *v_rport);
unsigned int unf_send_logo(struct unf_lport_s *v_lport,
			   struct unf_rport_s *v_rport);
unsigned int unf_send_echo(struct unf_lport_s *v_lport,
			   struct unf_rport_s *v_rport,
			   unsigned int *v_time);
unsigned int unf_send_abts(struct unf_lport_s *v_lport,
			   struct unf_xchg_s *v_xchg);
unsigned int unf_send_scr(struct unf_lport_s *v_lport,
			  struct unf_rport_s *v_rport);
unsigned int unf_send_rrq(struct unf_lport_s *v_lport,
			  struct unf_rport_s *v_rport,
			  struct unf_xchg_s *v_xchg);
void unf_rport_immediate_linkdown(struct unf_lport_s *v_lport,
				  struct unf_rport_s *v_rport);
unsigned int unf_receive_bls_pkg(void *v_lport,
				 struct unf_frame_pkg_s *v_pkg);
struct unf_rport_s *unf_find_rport(struct unf_lport_s *v_lport,
				   unsigned int v_rport_nport_id,
				   unsigned long long v_port_name);
void unf_login_with_loop_node(struct unf_lport_s *v_lport, unsigned int alpa);
unsigned int unf_receive_gs_pkg(void *v_lport,
				struct unf_frame_pkg_s *v_fra_pkg);
void unf_rcv_gnn_id_rsp_unknown(struct unf_lport_s *v_lport,
				struct unf_rport_s *v_sns_port,
				unsigned int v_nport_id);
void unf_rcv_gpn_id_rsp_unknown(struct unf_lport_s *v_lport,
				unsigned int v_nport_id);
void unf_rcv_gff_id_rsp_unknown(struct unf_lport_s *v_lport,
				unsigned int v_nport_id);
unsigned int unf_release_rport_res(struct unf_lport_s *v_lport,
				   struct unf_rport_s *v_rport);

unsigned int unf_low_level_bbscn(struct unf_lport_s *v_lport);
unsigned int unf_send_els_done(void *v_lport, struct unf_frame_pkg_s *v_pkg);
unsigned int unf_send_rec(struct unf_lport_s *v_lport,
			  struct unf_rport_s *v_rport,
			  struct unf_xchg_s *v_xchg);

typedef int (*unf_evt_task)(void *v_arg_in, void *v_arg_out);

#endif /* __UNF_SERVICE_H__ */
