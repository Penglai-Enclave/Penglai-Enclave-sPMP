/* SPDX-License-Identifier: GPL-2.0 */
/* Huawei Hifc PCI Express Linux driver
 * Copyright(c) 2017 Huawei Technologies Co., Ltd
 *
 */

#ifndef __HIFC_IO_H__
#define __HIFC_IO_H__

enum dif_mode_e {
	DIF_MODE_NONE = 0x0,
	DIF_MODE_INSERT = 0x1,
	DIF_MODE_REMOVE = 0x2,
	DIF_MODE_FORWARD_OR_REPLACE = 0x3
};

enum ref_tag_mode_e {
	BOTH_NONE = 0x0,
	RECEIVE_INCREASE = 0x1,
	REPLACE_INCREASE = 0x2,
	BOTH_INCREASE = 0x3
};

#define HIFC_DIF_DISABLE                                0
#define HIFC_DIF_ENABLE                                 1
#define HIFC_DIF_SECTOR_512B_MODE                       0
#define HIFC_DIF_SECTOR_4KB_MODE                        1
#define HIFC_DIF_GUARD_VERIFY_ALGORITHM_CTL_T10_CRC16   0x0
#define HIFC_DIF_GUARD_VERIFY_CRC16_REPLACE_IP_CHECKSUM 0x1
#define HIFC_DIF_GUARD_VERIFY_IP_CHECKSUM_REPLACE_CRC16 0x2
#define HIFC_DIF_GUARD_VERIFY_ALGORITHM_CTL_IP_CHECKSUM 0x3
#define HIFC_DIF_CRC_CS_INITIAL_CONFIG_BY_REGISTER      0
#define HIFC_DIF_CRC_CS_INITIAL_CONFIG_BY_BIT0_1        0x4

#define HIFC_DIF_GARD_REF_APP_CTRL_VERIFY     0x4
#define HIFC_DIF_GARD_REF_APP_CTRL_NOT_VERIFY 0x0
#define HIFC_DIF_GARD_REF_APP_CTRL_INSERT     0x0
#define HIFC_DIF_GARD_REF_APP_CTRL_DELETE     0x1
#define HIFC_DIF_GARD_REF_APP_CTRL_FORWARD    0x2
#define HIFC_DIF_GARD_REF_APP_CTRL_REPLACE    0x3

#define HIFC_DIF_ERROR_CODE_MASK 0xe
#define HIFC_DIF_ERROR_CODE_CRC  0x2
#define HIFC_DIF_ERROR_CODE_REF  0x4
#define HIFC_DIF_ERROR_CODE_APP  0x8

#define HIFC_DIF_SEND_DIFERR_PAYLOAD 0
#define HIFC_DIF_SEND_DIFERR_CRC     1
#define HIFC_DIF_SEND_DIFERR_APP     2
#define HIFC_DIF_SEND_DIFERR_REF     3
#define HIFC_DIF_RECV_DIFERR_ALL     4
#define HIFC_DIF_RECV_DIFERR_CRC     5
#define HIFC_DIF_RECV_DIFERR_APP     6
#define HIFC_DIF_RECV_DIFERR_REF     7

#define HIFC_SECT_SIZE_512            512
#define HIFC_SECT_SIZE_4096           4096
#define HIFC_SECT_SIZE_512_8          520
#define HIFC_SECT_SIZE_4096_8         4104
#define HIFC_CTRL_MASK                0x1f

unsigned int hifc_send_scsi_cmnd(void *v_hba, struct unf_frame_pkg_s *v_pkg);
unsigned int hifc_scq_recv_iresp(struct hifc_hba_s *v_hba,
				 union hifcoe_scqe_u *v_wqe);

#endif /* __HIFC_IO_H__ */
