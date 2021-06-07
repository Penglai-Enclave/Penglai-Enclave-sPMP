/* SPDX-License-Identifier: GPL-2.0 */
/* Huawei Hifc PCI Express Linux driver
 * Copyright(c) 2017 Huawei Technologies Co., Ltd
 *
 */
#ifndef __UNF_IO__ABNORMAL_H__
#define __UNF_IO__ABNORMAL_H__

#define UNF_GET_LL_ERR(v_pkg)      ((v_pkg->status) >> 16)

void unf_process_scsi_mgmt_result(struct unf_frame_pkg_s *v_pkg,
				  struct unf_xchg_s *v_xchg);
unsigned int unf_hardware_start_io(struct unf_lport_s *v_lport,
				   struct unf_frame_pkg_s *v_pkg);

#endif
