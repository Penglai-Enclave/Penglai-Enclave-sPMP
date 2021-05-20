// SPDX-License-Identifier: GPL-2.0
/* Huawei Hifc PCI Express Linux driver
 * Copyright(c) 2017 Huawei Technologies Co., Ltd
 *
 */

#include "hifc_module.h"
#include "hifc_hba.h"
#include "hifc_service.h"
#include "hifc_io.h"

/* Whether to enable the payload printing
 * function depends on the content of exchange
 */
#ifdef HIFC_PRINT_PAYLOADINFO_ENABLE
#include "unf_exchg.h"
#endif

/* Set this parameter based on EDTOV 2S */
#define HIFC_IMMIDATA_ABORT_TIME 2000
#define hifc_fill_pkg_status(com_err_code, control, scsi_status) \
	(((unsigned int)(com_err_code) << 16) |\
	((unsigned int)(control) << 8) |\
	(unsigned int)(scsi_status))

unsigned int dif_protect_op_code = INVALID_VALUE32;
unsigned int dif_app_esc_check = HIFC_DIF_APP_REF_ESC_CHECK;
unsigned int dif_ref_esc_check = HIFC_DIF_APP_REF_ESC_CHECK;
unsigned int dif_sect_size;
unsigned int no_dif_sect_size;
unsigned int dix_flag;
unsigned int grd_ctrl;
unsigned int grd_agm_ctrl = HIFC_DIF_GUARD_VERIFY_ALGORITHM_CTL_T10_CRC16;
unsigned int cmp_app_tag_mask = 0xffff;
unsigned int ref_tag_mod = INVALID_VALUE32;
unsigned int rep_ref_tag;
unsigned short cmp_app_tag;
unsigned short rep_app_tag;

static void hifc_dif_err_count(struct hifc_hba_s *v_hba,
			       unsigned char v_dif_info)
{
	unsigned char dif_info = v_dif_info;

	HIFC_DIF_ERR_STAT(v_hba, HIFC_DIF_RECV_DIFERR_ALL);

	if (dif_info & HIFC_DIF_ERROR_CODE_CRC)
		HIFC_DIF_ERR_STAT(v_hba, HIFC_DIF_RECV_DIFERR_CRC);

	if (dif_info & HIFC_DIF_ERROR_CODE_APP)
		HIFC_DIF_ERR_STAT(v_hba, HIFC_DIF_RECV_DIFERR_APP);

	if (dif_info & HIFC_DIF_ERROR_CODE_REF)
		HIFC_DIF_ERR_STAT(v_hba, HIFC_DIF_RECV_DIFERR_REF);
}

static void hifc_build_no_dif_control(struct unf_frame_pkg_s *v_pkg,
				      struct hifcoe_fc_dif_info_s *v_dif_info)
{
	struct hifcoe_fc_dif_info_s *dif_info = v_dif_info;

	/* dif enable or disable */
	dif_info->wd0.difx_en = HIFC_DIF_DISABLE;

	dif_info->wd1.vpid = v_pkg->qos_level;
	dif_info->wd1.lun_qos_en = 0;
}

void hifc_dif_action_forward(struct hifcoe_fc_dif_info_s *v_dif_info_l1,
			     struct unf_dif_control_info_s *v_dif_ctrl_u1)
{
	v_dif_info_l1->wd0.grd_ctrl |=
	(v_dif_ctrl_u1->protect_opcode & UNF_VERIFY_CRC_MASK) ?
	HIFC_DIF_GARD_REF_APP_CTRL_VERIFY :
	HIFC_DIF_GARD_REF_APP_CTRL_NOT_VERIFY;

	v_dif_info_l1->wd0.grd_ctrl |= (v_dif_ctrl_u1->protect_opcode &
	UNF_REPLACE_CRC_MASK) ? HIFC_DIF_GARD_REF_APP_CTRL_REPLACE :
	HIFC_DIF_GARD_REF_APP_CTRL_FORWARD;

	v_dif_info_l1->wd0.ref_tag_ctrl |=
	(v_dif_ctrl_u1->protect_opcode & UNF_VERIFY_LBA_MASK) ?
	HIFC_DIF_GARD_REF_APP_CTRL_VERIFY :
	HIFC_DIF_GARD_REF_APP_CTRL_NOT_VERIFY;

	v_dif_info_l1->wd0.ref_tag_ctrl |=
	(v_dif_ctrl_u1->protect_opcode & UNF_REPLACE_LBA_MASK) ?
	HIFC_DIF_GARD_REF_APP_CTRL_REPLACE : HIFC_DIF_GARD_REF_APP_CTRL_FORWARD;

	v_dif_info_l1->wd1.app_tag_ctrl |= (v_dif_ctrl_u1->protect_opcode &
	UNF_VERIFY_APP_MASK) ? HIFC_DIF_GARD_REF_APP_CTRL_VERIFY :
	HIFC_DIF_GARD_REF_APP_CTRL_NOT_VERIFY;

	v_dif_info_l1->wd1.app_tag_ctrl |=
	(v_dif_ctrl_u1->protect_opcode & UNF_REPLACE_APP_MASK) ?
	HIFC_DIF_GARD_REF_APP_CTRL_REPLACE : HIFC_DIF_GARD_REF_APP_CTRL_FORWARD;
}

void hifc_dif_action_delete(struct hifcoe_fc_dif_info_s *v_dif_info_l1,
			    struct unf_dif_control_info_s *v_dif_ctrl_u1)
{
	v_dif_info_l1->wd0.grd_ctrl |=
	(v_dif_ctrl_u1->protect_opcode & UNF_VERIFY_CRC_MASK) ?
	HIFC_DIF_GARD_REF_APP_CTRL_VERIFY :
	HIFC_DIF_GARD_REF_APP_CTRL_NOT_VERIFY;
	v_dif_info_l1->wd0.grd_ctrl |= HIFC_DIF_GARD_REF_APP_CTRL_DELETE;

	v_dif_info_l1->wd0.ref_tag_ctrl |=
	(v_dif_ctrl_u1->protect_opcode & UNF_VERIFY_LBA_MASK) ?
	HIFC_DIF_GARD_REF_APP_CTRL_VERIFY :
	HIFC_DIF_GARD_REF_APP_CTRL_NOT_VERIFY;
	v_dif_info_l1->wd0.ref_tag_ctrl |= HIFC_DIF_GARD_REF_APP_CTRL_DELETE;

	v_dif_info_l1->wd1.app_tag_ctrl |=
	(v_dif_ctrl_u1->protect_opcode & UNF_VERIFY_APP_MASK) ?
	HIFC_DIF_GARD_REF_APP_CTRL_VERIFY :
	HIFC_DIF_GARD_REF_APP_CTRL_NOT_VERIFY;
	v_dif_info_l1->wd1.app_tag_ctrl |= HIFC_DIF_GARD_REF_APP_CTRL_DELETE;
}


static void hifc_convert_dif_action(
			struct unf_dif_control_info_s *v_dif_ctrl_u1,
			struct hifcoe_fc_dif_info_s *v_dif_info_l1)
{
	struct hifcoe_fc_dif_info_s *dif_info_l1 = NULL;
	struct unf_dif_control_info_s *dif_ctrl_u1 = NULL;

	dif_info_l1 = v_dif_info_l1;
	dif_ctrl_u1 = v_dif_ctrl_u1;

	switch (UNF_DIF_ACTION_MASK & dif_ctrl_u1->protect_opcode) {
	case UNF_DIF_ACTION_VERIFY_AND_REPLACE:
	case UNF_DIF_ACTION_VERIFY_AND_FORWARD:
		hifc_dif_action_forward(dif_info_l1, dif_ctrl_u1);
		break;

	case UNF_DIF_ACTION_INSERT:
		dif_info_l1->wd0.grd_ctrl |=
		HIFC_DIF_GARD_REF_APP_CTRL_NOT_VERIFY;
		dif_info_l1->wd0.grd_ctrl |=
		HIFC_DIF_GARD_REF_APP_CTRL_INSERT;
		dif_info_l1->wd0.ref_tag_ctrl |=
		HIFC_DIF_GARD_REF_APP_CTRL_NOT_VERIFY;
		dif_info_l1->wd0.ref_tag_ctrl |=
		HIFC_DIF_GARD_REF_APP_CTRL_INSERT;
		dif_info_l1->wd1.app_tag_ctrl |=
		HIFC_DIF_GARD_REF_APP_CTRL_NOT_VERIFY;
		dif_info_l1->wd1.app_tag_ctrl |=
		HIFC_DIF_GARD_REF_APP_CTRL_INSERT;
		break;

	case UNF_DIF_ACTION_VERIFY_AND_DELETE:
		hifc_dif_action_delete(dif_info_l1, dif_ctrl_u1);
		break;

	default:
		HIFC_TRACE(UNF_EVTLOG_IO_WARN, UNF_LOG_IO_ATT, UNF_WARN,
			   "Unknown dif protect opcode 0x%x",
			   dif_ctrl_u1->protect_opcode);
		break;
	}
}

void hifc_get_dif_info_l1(struct hifcoe_fc_dif_info_s *v_dif_info_l1,
			  struct unf_dif_control_info_s *v_dif_ctrl_u1)
{
	v_dif_info_l1->wd1.cmp_app_tag_msk = cmp_app_tag_mask;

	v_dif_info_l1->rep_app_tag = v_dif_ctrl_u1->app_tag;
	v_dif_info_l1->rep_ref_tag = v_dif_ctrl_u1->start_lba;

	v_dif_info_l1->cmp_app_tag = v_dif_ctrl_u1->app_tag;
	v_dif_info_l1->cmp_ref_tag = v_dif_ctrl_u1->start_lba;

	if (cmp_app_tag != 0)
		v_dif_info_l1->cmp_app_tag = cmp_app_tag;

	if (rep_app_tag != 0)
		v_dif_info_l1->rep_app_tag = rep_app_tag;

	if (rep_ref_tag != 0)
		v_dif_info_l1->rep_ref_tag = rep_ref_tag;
}

static void hifc_build_dif_control(struct hifc_hba_s *v_hba,
				   struct unf_frame_pkg_s *v_pkg,
				   struct hifcoe_fc_dif_info_s *v_dif_info_l1)
{
	struct hifcoe_fc_dif_info_s *dif_info_l1 = NULL;
	struct unf_dif_control_info_s *dif_ctrl_u1 = NULL;

	dif_info_l1 = v_dif_info_l1;
	dif_ctrl_u1 = &v_pkg->dif_control;

	/* dif enable or disable */
	dif_info_l1->wd0.difx_en = HIFC_DIF_ENABLE;

	dif_info_l1->wd1.vpid = v_pkg->qos_level;
	dif_info_l1->wd1.lun_qos_en = 0;

	/* 512B + 8 size mode */
	dif_info_l1->wd0.sct_size =
	(dif_ctrl_u1->flags & UNF_DIF_SECTSIZE_4KB) ?
	HIFC_DIF_SECTOR_4KB_MODE : HIFC_DIF_SECTOR_512B_MODE;

	no_dif_sect_size = (dif_ctrl_u1->flags & UNF_DIF_SECTSIZE_4KB) ?
	HIFC_SECT_SIZE_4096 : HIFC_SECT_SIZE_512;

	dif_sect_size = (dif_ctrl_u1->flags & UNF_DIF_SECTSIZE_4KB) ?
	HIFC_SECT_SIZE_4096_8 : HIFC_SECT_SIZE_512_8;

	/* The length is adjusted when the burst len is adjusted.
	 * The length is initialized to 0
	 */
	dif_info_l1->wd0.difx_len = 0;

	/* dif type 1 */
	dif_info_l1->wd0.dif_verify_type = dif_type;
	dif_info_l1->wd0.dif_ins_rep_type = dif_type;

	/* Check whether the 0xffff app or ref domain is isolated
	 * If all ff messages are displayed in type1 app, checkcheck sector
	 * v_dif_info_l1->wd0.difx_app_esc = HIFC_DIF_APP_REF_ESC_CHECK
	 */

	dif_info_l1->wd0.difx_app_esc = dif_app_esc_check;

	/* type1 ref tag If all ff is displayed, check sector is required */
	dif_info_l1->wd0.difx_ref_esc = dif_ref_esc_check;

	/* Currently, only t10 crc is supported */
	dif_info_l1->wd0.grd_agm_ctrl = 0;

	/* Set this parameter based on the values of bit zero and bit one.
	 * The initial value is 0, and the value is UNF_DEFAULT_CRC_GUARD_SEED
	 */
	dif_info_l1->wd0.grd_agm_ini_ctrl =
	HIFC_DIF_CRC_CS_INITIAL_CONFIG_BY_BIT0_1;
	dif_info_l1->wd1.app_tag_ctrl = 0;
	dif_info_l1->wd0.grd_ctrl = 0;
	dif_info_l1->wd0.ref_tag_ctrl = 0;

	/* Convert the verify operation, replace, forward, insert,
	 * and delete operations based on the actual operation code of
	 * the upper layer
	 */
	if (dif_protect_op_code != INVALID_VALUE32) {
		dif_ctrl_u1->protect_opcode = dif_protect_op_code |
		(dif_ctrl_u1->protect_opcode & UNF_DIF_ACTION_MASK);
	}

	hifc_convert_dif_action(dif_ctrl_u1, dif_info_l1);

	/* Address self-increase mode */
	dif_info_l1->wd0.ref_tag_mode = (dif_ctrl_u1->protect_opcode &
	UNF_DIF_ACTION_NO_INCREASE_REFTAG) ? (BOTH_NONE) : (BOTH_INCREASE);

	if (ref_tag_mod != INVALID_VALUE32)
		dif_info_l1->wd0.ref_tag_mode = ref_tag_mod;

	/* This parameter is used only when type 3 is set to 0xffff. */

	hifc_get_dif_info_l1(dif_info_l1, dif_ctrl_u1);
}

static unsigned int hifc_fill_external_sgl_page(
				struct hifc_hba_s *v_hba,
				struct unf_frame_pkg_s *v_pkg,
				struct unf_esgl_page_s *v_esgl_page,
				unsigned int sge_num,
				int v_direct,
				unsigned int context_id,
				unsigned int dif_flag)
{
	unsigned int ret = UNF_RETURN_ERROR;
	unsigned int index = 0;
	unsigned int sge_num_per_page = 0;
	unsigned int buffer_addr = 0;
	unsigned int buf_len = 0;
	char *buf = NULL;
	unsigned long phys = 0;
	struct unf_esgl_page_s *esgl_page = NULL;
	struct hifcoe_variable_sge_s *sge = NULL;

	esgl_page = v_esgl_page;
	while (sge_num > 0) {
		/* Obtains the initial address of the sge page */
		sge = (struct hifcoe_variable_sge_s *)esgl_page->page_address;

		/* Calculate the number of sge on each page */
		sge_num_per_page = (esgl_page->page_size) /
				sizeof(struct hifcoe_variable_sge_s);

		/* Fill in sgl page. The last sge of each page is link sge
		 * by default
		 */
		for (index = 0; index < (sge_num_per_page - 1); index++) {
			UNF_GET_SGL_ENTRY(ret, (void *)v_pkg, &buf,
					  &buf_len, dif_flag);
			if (ret != RETURN_OK)
				return UNF_RETURN_ERROR;
			phys = (unsigned long)buf;
			sge[index].buf_addr_hi = UNF_DMA_HI32(phys);
			sge[index].buf_addr_lo = UNF_DMA_LO32(phys);
			sge[index].wd0.buf_len = buf_len;
			sge[index].wd0.r_flag = 0;
			sge[index].wd1.extension_flag =
			HIFC_WQE_SGE_NOT_EXTEND_FLAG;
			sge[index].wd1.last_flag = HIFC_WQE_SGE_NOT_LAST_FLAG;

			/* parity bit */
			sge[index].wd1.buf_addr_gpa =
			(sge[index].buf_addr_lo >> 16);
			sge[index].wd1.xid = (context_id & 0x3fff);

			hifc_cpu_to_big32(&sge[index],
					  sizeof(struct hifcoe_variable_sge_s));

			sge_num--;
			if (sge_num == 0)
				break;
		}

		/* sge Set the end flag on the last sge of the page if all the
		 * pages have been filled.
		 */
		if (sge_num == 0) {
			sge[index].wd1.extension_flag =
			HIFC_WQE_SGE_NOT_EXTEND_FLAG;
			sge[index].wd1.last_flag = HIFC_WQE_SGE_LAST_FLAG;

			/* parity bit */
			buffer_addr = be32_to_cpu(sge[index].buf_addr_lo);
			sge[index].wd1.buf_addr_gpa = (buffer_addr >> 16);
			sge[index].wd1.xid = (context_id & 0x3fff);

			hifc_cpu_to_big32(&sge[index].wd1, HIFC_DWORD_BYTE);
		}
		/* If only one sge is left empty, the sge reserved on the page
		 * is used for filling.
		 */
		else if (sge_num == 1) {
			UNF_GET_SGL_ENTRY(ret, (void *)v_pkg, &buf,
					  &buf_len, dif_flag);
			if (ret != RETURN_OK)
				return UNF_RETURN_ERROR;

			phys = (unsigned long)buf;
			sge[index].buf_addr_hi = UNF_DMA_HI32(phys);
			sge[index].buf_addr_lo = UNF_DMA_LO32(phys);
			sge[index].wd0.buf_len = buf_len;
			sge[index].wd0.r_flag = 0;
			sge[index].wd1.extension_flag =
			HIFC_WQE_SGE_NOT_EXTEND_FLAG;
			sge[index].wd1.last_flag = HIFC_WQE_SGE_LAST_FLAG;

			/* parity bit */
			sge[index].wd1.buf_addr_gpa =
			(sge[index].buf_addr_lo >> 16);
			sge[index].wd1.xid = (context_id & 0x3fff);

			hifc_cpu_to_big32(&sge[index],
					  sizeof(struct hifcoe_variable_sge_s));

			sge_num--;
		} else {
		/* Apply for a new sgl page and fill in link sge */
			UNF_GET_FREE_ESGL_PAGE(esgl_page, v_hba->lport, v_pkg);
			if (!esgl_page) {
				HIFC_TRACE(UNF_EVTLOG_DRIVER_ERR,
					   UNF_LOG_REG_ATT, UNF_ERR, "Get free esgl page failed.");
				return UNF_RETURN_ERROR;
			}
			phys = esgl_page->esgl_phyaddr;
			sge[index].buf_addr_hi = UNF_DMA_HI32(phys);
			sge[index].buf_addr_lo = UNF_DMA_LO32(phys);

			/* For the cascaded wqe, you only need to enter the
			 * cascading buffer address and extension flag, and do
			 * not need to fill in other fields
			 */
			sge[index].wd0.buf_len = 0;
			sge[index].wd0.r_flag = 0;
			sge[index].wd1.extension_flag =
			HIFC_WQE_SGE_EXTEND_FLAG;
			sge[index].wd1.last_flag = HIFC_WQE_SGE_NOT_LAST_FLAG;

			/* parity bit */
			sge[index].wd1.buf_addr_gpa =
			(sge[index].buf_addr_lo >> 16);
			sge[index].wd1.xid = (context_id & 0x3fff);

			hifc_cpu_to_big32(&sge[index],
					  sizeof(struct hifcoe_variable_sge_s));
		}

		HIFC_TRACE(UNF_EVTLOG_IO_ERR, UNF_LOG_IO_ATT, UNF_INFO,
			   "Port(0x%x) SID(0x%x) DID(0x%x) RXID(0x%x) build esgl left sge num: %u.",
			   v_hba->port_cfg.port_id,
			   v_pkg->frame_head.csctl_sid,
			   v_pkg->frame_head.rctl_did,
			   v_pkg->frame_head.oxid_rxid,
			   sge_num);
	}

	return RETURN_OK;
}

static unsigned int hifc_build_local_dif_sgl(struct hifc_hba_s *v_hba,
					     struct unf_frame_pkg_s *v_pkg,
					     struct hifcoe_sqe_s *v_sqe,
					     int v_direct,
					     unsigned int v_bd_sge_num)
{
	unsigned int ret = UNF_RETURN_ERROR;
	char *buf = NULL;
	unsigned int buf_len = 0;
	unsigned long phys = 0;
	unsigned int dif_sge_place = 0;
	struct hifc_parent_sq_info_s *parent_sq = NULL;

	parent_sq = hifc_find_parent_sq_by_pkg((void *)v_hba, v_pkg);
	if (unlikely(!parent_sq)) {
		HIFC_TRACE(UNF_EVTLOG_IO_ERR, UNF_LOG_IO_ATT, UNF_ERR,
			   "Port(0x%x) send packet oxid_rxid(0x%x) fail, as sid_did(0x%x_0x%x)'s parent sq is null.",
			   v_hba->port_cfg.port_id,
			   v_pkg->frame_head.oxid_rxid,
			   v_pkg->frame_head.csctl_sid,
			   v_pkg->frame_head.rctl_did);

		return UNF_RETURN_ERROR;
	}

	/* DIF SGE must be followed by BD SGE */
	dif_sge_place = ((v_bd_sge_num <= v_pkg->entry_count) ?
			v_bd_sge_num : v_pkg->entry_count);

	/* The entry_count= 0 needs to be specially processed and does not
	 * need to be mounted. As long as len is set to zero, Last-bit is set
	 * to one, and E-bit is set to 0.
	 */
	if (v_pkg->dif_control.dif_sge_count == 0) {
		v_sqe->sge[dif_sge_place].buf_addr_hi = 0;
		v_sqe->sge[dif_sge_place].buf_addr_lo = 0;
		v_sqe->sge[dif_sge_place].wd0.buf_len = 0;
	} else {
		UNF_CM_GET_DIF_SGL_ENTRY(ret, (void *)v_pkg, &buf, &buf_len);
		if (ret != RETURN_OK) {
			HIFC_TRACE(UNF_EVTLOG_IO_ERR, UNF_LOG_IO_ATT, UNF_ERR, "DOUBLE DIF Get Dif Buf Fail.");
			return UNF_RETURN_ERROR;
		}

		phys = (unsigned long)buf;
		v_sqe->sge[dif_sge_place].buf_addr_hi = UNF_DMA_HI32(phys);
		v_sqe->sge[dif_sge_place].buf_addr_lo = UNF_DMA_LO32(phys);
		v_sqe->sge[dif_sge_place].wd0.buf_len = buf_len;
	}

	/* rdma flag. If the fc is not used, enter 0. */
	v_sqe->sge[dif_sge_place].wd0.r_flag = 0;

	/* parity bit */
	v_sqe->sge[dif_sge_place].wd1.buf_addr_gpa =
	(v_sqe->sge[dif_sge_place].buf_addr_lo >> 16);
	v_sqe->sge[dif_sge_place].wd1.xid = (parent_sq->context_id & 0x3fff);

	/* The local sgl does not use the cascading SGE. Therefore, the value
	 * of this field is always 0.
	 */
	v_sqe->sge[dif_sge_place].wd1.extension_flag =
	HIFC_WQE_SGE_NOT_EXTEND_FLAG;
	v_sqe->sge[dif_sge_place].wd1.last_flag = HIFC_WQE_SGE_LAST_FLAG;

	hifc_cpu_to_big32(&v_sqe->sge[dif_sge_place],
			  sizeof(struct hifcoe_variable_sge_s));

	return RETURN_OK;
}

static unsigned int hifc_build_external_dif_sgl(struct hifc_hba_s *v_hba,
						struct unf_frame_pkg_s *v_pkg,
						struct hifcoe_sqe_s *v_sqe,
						int v_direct,
						unsigned int v_bd_sge_num)
{
	unsigned int ret = UNF_RETURN_ERROR;
	struct unf_esgl_page_s *esgl_page = NULL;
	unsigned long phys = 0;
	unsigned int left_sge_num = 0;
	unsigned int dif_sge_place = 0;
	struct hifc_parent_sq_info_s *parent_sq = NULL;

	parent_sq = hifc_find_parent_sq_by_pkg((void *)v_hba, v_pkg);
	if (unlikely(!parent_sq)) {
		HIFC_TRACE(UNF_EVTLOG_IO_ERR, UNF_LOG_IO_ATT, UNF_ERR,
			   "Port(0x%x) send packet oxid_rxid(0x%x) fail, as sid_did(0x%x_0x%x)'s parent sq is null.",
			   v_hba->port_cfg.port_id,
			   v_pkg->frame_head.oxid_rxid,
			   v_pkg->frame_head.csctl_sid,
			   v_pkg->frame_head.rctl_did);

		return UNF_RETURN_ERROR;
	}

	/* DIF SGE must be followed by BD SGE */
	dif_sge_place = ((v_bd_sge_num <= v_pkg->entry_count) ?
	v_bd_sge_num : v_pkg->entry_count);

	/* Allocate the first page first */
	UNF_GET_FREE_ESGL_PAGE(esgl_page, v_hba->lport, v_pkg);
	if (!esgl_page) {
		HIFC_TRACE(UNF_EVTLOG_IO_ERR, UNF_LOG_IO_ATT, UNF_ERR, "DOUBLE DIF Get External Page Fail.");
		return UNF_RETURN_ERROR;
	}

	phys = esgl_page->esgl_phyaddr;

	/* Configuring the Address of the Cascading Page */
	v_sqe->sge[dif_sge_place].buf_addr_hi = UNF_DMA_HI32(phys);
	v_sqe->sge[dif_sge_place].buf_addr_lo = UNF_DMA_LO32(phys);

	/* Configuring Control Information About the Cascading Page */
	v_sqe->sge[dif_sge_place].wd0.buf_len = 0;
	v_sqe->sge[dif_sge_place].wd0.r_flag = 0;
	v_sqe->sge[dif_sge_place].wd1.extension_flag = HIFC_WQE_SGE_EXTEND_FLAG;
	v_sqe->sge[dif_sge_place].wd1.last_flag = HIFC_WQE_SGE_NOT_LAST_FLAG;

	/* parity bit */
	v_sqe->sge[dif_sge_place].wd1.buf_addr_gpa =
	(v_sqe->sge[dif_sge_place].buf_addr_lo >> 16);
	v_sqe->sge[dif_sge_place].wd1.xid = (parent_sq->context_id & 0x3fff);

	hifc_cpu_to_big32(&v_sqe->sge[dif_sge_place],
			  sizeof(struct hifcoe_variable_sge_s));

	/* Fill in the sge information on the cascading page */
	left_sge_num = v_pkg->dif_control.dif_sge_count;
	ret = hifc_fill_external_sgl_page(v_hba, v_pkg, esgl_page, left_sge_num,
					  v_direct, parent_sq->context_id,
					  UNF_TRUE);
	if (ret != RETURN_OK)
		return UNF_RETURN_ERROR;

	return RETURN_OK;
}

static unsigned int hifc_build_local_sgl(struct hifc_hba_s *v_hba,
					 struct unf_frame_pkg_s *v_pkg,
					 struct hifcoe_sqe_s *v_sqe,
					 int v_direct)
{
	unsigned int ret = UNF_RETURN_ERROR;
	char *buf = NULL;
	unsigned int buf_len = 0;
	unsigned int index = 0;
	unsigned long phys = 0;
	struct hifc_parent_sq_info_s *parent_sq = NULL;

	parent_sq = hifc_find_parent_sq_by_pkg((void *)v_hba, v_pkg);
	if (unlikely(!parent_sq)) {
		HIFC_TRACE(UNF_EVTLOG_IO_ERR, UNF_LOG_IO_ATT, UNF_ERR,
			   "[fail]Port(0x%x) send packet oxid_rxid(0x%x) fail, as sid_did(0x%x_0x%x)'s parent sq is null.",
			   v_hba->port_cfg.port_id,
			   v_pkg->frame_head.oxid_rxid,
			   v_pkg->frame_head.csctl_sid,
			   v_pkg->frame_head.rctl_did);

		return UNF_RETURN_ERROR;
	}

	for (index = 0; index < v_pkg->entry_count; index++) {
		UNF_CM_GET_SGL_ENTRY(ret, (void *)v_pkg, &buf, &buf_len);

		if (ret != RETURN_OK)
			return UNF_RETURN_ERROR;

		phys = (unsigned long)buf;

		v_sqe->sge[index].buf_addr_hi = UNF_DMA_HI32(phys);
		v_sqe->sge[index].buf_addr_lo = UNF_DMA_LO32(phys);
		v_sqe->sge[index].wd0.buf_len = buf_len;

		/* rdma flag. If the fc is not used, enter 0. */
		v_sqe->sge[index].wd0.r_flag = 0;

		/* parity bit */
		v_sqe->sge[index].wd1.buf_addr_gpa =
		(v_sqe->sge[index].buf_addr_lo >> 16);
		v_sqe->sge[index].wd1.xid = (parent_sq->context_id & 0x3fff);

		/* The local sgl does not use the cascading SGE. Therefore, the
		 * value of this field is always 0.
		 */
		v_sqe->sge[index].wd1.extension_flag =
		HIFC_WQE_SGE_NOT_EXTEND_FLAG;
		v_sqe->sge[index].wd1.last_flag = HIFC_WQE_SGE_NOT_LAST_FLAG;

		if (index == (v_pkg->entry_count - 1)) {
			/* Sets the last WQE end flag 1 */
			v_sqe->sge[index].wd1.last_flag =
			HIFC_WQE_SGE_LAST_FLAG;
		}

		hifc_cpu_to_big32(&v_sqe->sge[index],
				  sizeof(struct hifcoe_variable_sge_s));
	}

	/* Adjust the length of the BDSL field in the CTRL domain. */
	HIFC_ADJUST_DATA(v_sqe->ctrl_sl.ch.wd0.bdsl,
			 HIFC_BYTES_TO_QW_NUM((v_pkg->entry_count *
			 sizeof(struct hifcoe_variable_sge_s))));

	/* The entry_count= 0 needs to be specially processed and does not
	 * need to be mounted. As long as len is set to zero, Last-bit is set
	 * to one, and E-bit is set to 0.
	 */
	if (v_pkg->entry_count == 0) {
		v_sqe->sge[0].buf_addr_hi = 0;
		v_sqe->sge[0].buf_addr_lo = 0;
		v_sqe->sge[0].wd0.buf_len = 0;

		/* rdma flag. This field is not used in fc. Set it to 0. */
		v_sqe->sge[0].wd0.r_flag = 0;

		/* parity bit */
		v_sqe->sge[0].wd1.buf_addr_gpa =
		(v_sqe->sge[0].buf_addr_lo >> 16);
		v_sqe->sge[0].wd1.xid = (parent_sq->context_id & 0x3fff);

		/* The local sgl does not use the cascading SGE. Therefore,
		 * the value of this field is always 0.
		 */
		v_sqe->sge[0].wd1.extension_flag = HIFC_WQE_SGE_NOT_EXTEND_FLAG;
		v_sqe->sge[0].wd1.last_flag = HIFC_WQE_SGE_LAST_FLAG;

		hifc_cpu_to_big32(&v_sqe->sge[0],
				  sizeof(struct hifcoe_variable_sge_s));

		/* Adjust the length of the BDSL field in the CTRL domain. */
		HIFC_ADJUST_DATA(
			v_sqe->ctrl_sl.ch.wd0.bdsl,
			HIFC_BYTES_TO_QW_NUM(
				sizeof(struct hifcoe_variable_sge_s)));
	}

	return RETURN_OK;
}

static unsigned int hifc_build_external_sgl(struct hifc_hba_s *v_hba,
					    struct unf_frame_pkg_s *v_pkg,
					    struct hifcoe_sqe_s *v_sqe,
					    int v_direct,
					    unsigned int v_bd_sge_num)
{
	unsigned int ret = UNF_RETURN_ERROR;
	char *buf = NULL;
	struct unf_esgl_page_s *esgl_page = NULL;
	unsigned long phys = 0;
	unsigned int buf_len = 0;
	unsigned int index = 0;
	unsigned int left_sge_num = 0;
	unsigned int local_sge_num = 0;
	struct hifc_parent_sq_info_s *parent_sq = NULL;

	parent_sq = hifc_find_parent_sq_by_pkg((void *)v_hba, v_pkg);
	if (unlikely(!parent_sq)) {
		HIFC_TRACE(UNF_EVTLOG_IO_ERR, UNF_LOG_IO_ATT, UNF_ERR,
			   "Port(0x%x) send packet oxid_rxid(0x%x) fail, as sid_did(0x%x_0x%x)'s parent sq is null.",
			   v_hba->port_cfg.port_id,
			   v_pkg->frame_head.oxid_rxid,
			   v_pkg->frame_head.csctl_sid,
			   v_pkg->frame_head.rctl_did);

		return UNF_RETURN_ERROR;
	}

	/* Ensure that the value of v_bd_sge_num is greater than or equal to one
	 */
	local_sge_num = v_bd_sge_num - 1;

	for (index = 0; index < local_sge_num; index++) {
		UNF_CM_GET_SGL_ENTRY(ret, (void *)v_pkg, &buf, &buf_len);
		if (unlikely(ret != RETURN_OK))
			return UNF_RETURN_ERROR;
		phys = (unsigned long)buf;

		v_sqe->sge[index].buf_addr_hi = UNF_DMA_HI32(phys);
		v_sqe->sge[index].buf_addr_lo = UNF_DMA_LO32(phys);
		v_sqe->sge[index].wd0.buf_len = buf_len;

		/* RDMA flag, which is not used by FC. */
		v_sqe->sge[index].wd0.r_flag = 0;
		v_sqe->sge[index].wd1.extension_flag =
		HIFC_WQE_SGE_NOT_EXTEND_FLAG;
		v_sqe->sge[index].wd1.last_flag = HIFC_WQE_SGE_NOT_LAST_FLAG;

		/* parity bit */
		v_sqe->sge[index].wd1.buf_addr_gpa =
		(v_sqe->sge[index].buf_addr_lo >> 16);
		v_sqe->sge[index].wd1.xid = (parent_sq->context_id & 0x3fff);

		hifc_cpu_to_big32(&v_sqe->sge[index],
				  sizeof(struct hifcoe_variable_sge_s));
	}

	/* Allocating the first cascading page */
	UNF_GET_FREE_ESGL_PAGE(esgl_page, v_hba->lport, v_pkg);
	if (unlikely(!esgl_page))
		return UNF_RETURN_ERROR;

	phys = esgl_page->esgl_phyaddr;
	/* Adjust the length of the BDSL field in the CTRL domain. */
	HIFC_ADJUST_DATA(v_sqe->ctrl_sl.ch.wd0.bdsl,
			 HIFC_BYTES_TO_QW_NUM((v_bd_sge_num *
			 sizeof(struct hifcoe_variable_sge_s))));

	/* Configuring the Address of the Cascading Page */
	v_sqe->sge[index].buf_addr_hi = (u32)UNF_DMA_HI32(phys);
	v_sqe->sge[index].buf_addr_lo = (u32)UNF_DMA_LO32(phys);

	/* Configuring Control Information About the Cascading Page */
	v_sqe->sge[index].wd0.buf_len = 0;
	v_sqe->sge[index].wd0.r_flag = 0;
	v_sqe->sge[index].wd1.extension_flag = HIFC_WQE_SGE_EXTEND_FLAG;
	v_sqe->sge[index].wd1.last_flag = HIFC_WQE_SGE_NOT_LAST_FLAG;

	/* parity bit */
	v_sqe->sge[index].wd1.buf_addr_gpa =
	(v_sqe->sge[index].buf_addr_lo >> 16);
	v_sqe->sge[index].wd1.xid = (parent_sq->context_id & 0x3fff);

	hifc_cpu_to_big32(&v_sqe->sge[index],
			  sizeof(struct hifcoe_variable_sge_s));

	/* Calculate the number of remaining sge. */
	left_sge_num = v_pkg->entry_count - local_sge_num;

	/* Fill in the sge information on the cascading page. */
	ret = hifc_fill_external_sgl_page(v_hba, v_pkg, esgl_page,
					  left_sge_num, v_direct,
					  parent_sq->context_id,
					  UNF_FALSE);
	if (ret != RETURN_OK)
		return UNF_RETURN_ERROR;

	return RETURN_OK;
}

unsigned int hifc_build_sql_by_local_sge_num(struct unf_frame_pkg_s *v_pkg,
					     struct hifc_hba_s *v_hba,
					     struct hifcoe_sqe_s *v_sqe,
					     int v_direct,
					     unsigned int bd_sge_num)
{
	unsigned int ret = RETURN_OK;

	if (v_pkg->entry_count <= bd_sge_num) {
		ret = hifc_build_local_sgl(v_hba, v_pkg, v_sqe, v_direct);
	} else {
		ret = hifc_build_external_sgl(v_hba, v_pkg, v_sqe,
					      v_direct, bd_sge_num);
	}
	return ret;
}

unsigned int hifc_conf_dual_sgl_info(struct unf_frame_pkg_s *v_pkg,
				     struct hifc_hba_s *v_hba,
				     struct hifcoe_sqe_s *v_sqe,
				     int v_direct,
				     unsigned int bd_sge_num,
				     int double_sgl)
{
	unsigned int ret = RETURN_OK;

	if (double_sgl == UNF_TRUE) {
		/* Adjust the length of the DIF_SL field in the CTRL domain */
		HIFC_ADJUST_DATA(
			v_sqe->ctrl_sl.ch.wd0.dif_sl,
			HIFC_BYTES_TO_QW_NUM(
				sizeof(struct hifcoe_variable_sge_s)));

		if (v_pkg->dif_control.dif_sge_count <=
		HIFC_WQE_SGE_DIF_ENTRY_NUM) {
			ret = hifc_build_local_dif_sgl(v_hba, v_pkg, v_sqe,
						       v_direct, bd_sge_num);
		} else {
			ret = hifc_build_external_dif_sgl(v_hba, v_pkg, v_sqe,
							  v_direct, bd_sge_num);
		}
	}

	return ret;
}

static unsigned int hifc_build_sgl(struct hifc_hba_s *v_hba,
				   struct unf_frame_pkg_s *v_pkg,
				   struct hifcoe_sqe_s *v_sqe,
				   int v_direct,
				   unsigned int dif_flag)
{
	unsigned int ret = RETURN_OK;
	unsigned int bd_sge_num = HIFC_WQE_SGE_ENTRY_NUM;
	int double_sgl = UNF_FALSE;

	if ((dif_flag != 0) &&
	    (v_pkg->dif_control.flags & UNF_DIF_DOUBLE_SGL)) {
		bd_sge_num =
		HIFC_WQE_SGE_ENTRY_NUM - HIFC_WQE_SGE_DIF_ENTRY_NUM;
		double_sgl = UNF_TRUE;
	}

	/* Only one wqe local sge can be loaded. If more than one wqe local sge
	 * is used, use the esgl
	 */
	ret = hifc_build_sql_by_local_sge_num(v_pkg, v_hba, v_sqe,
					      v_direct, bd_sge_num);

	if (unlikely(ret != RETURN_OK))
		return ret;

	/* Configuring Dual SGL Information for DIF */
	ret = hifc_conf_dual_sgl_info(v_pkg, v_hba, v_sqe, v_direct,
				      bd_sge_num, double_sgl);

	return ret;
}

static void hifc_adjust_dix(struct unf_frame_pkg_s *v_pkg,
			    struct hifcoe_fc_dif_info_s *v_dif_info_l1,
			    unsigned char v_task_type)
{
	unsigned char task_type = v_task_type;
	struct hifcoe_fc_dif_info_s *dif_info_l1 = NULL;

	dif_info_l1 = v_dif_info_l1;

	if (dix_flag == 1) {
		if ((task_type == HIFC_SQE_FCP_IWRITE) ||
		    (task_type == HIFC_SQE_FCP_TRD)) {
			if ((UNF_DIF_ACTION_MASK &
			(v_pkg->dif_control.protect_opcode)) ==
			UNF_DIF_ACTION_VERIFY_AND_FORWARD) {
				dif_info_l1->wd0.grd_ctrl |=
				HIFC_DIF_GARD_REF_APP_CTRL_REPLACE;
				dif_info_l1->wd0.grd_agm_ctrl =
				HIFC_DIF_GUARD_VERIFY_IP_CHECKSUM_REPLACE_CRC16;
			}

			if ((UNF_DIF_ACTION_MASK &
			(v_pkg->dif_control.protect_opcode)) ==
			UNF_DIF_ACTION_VERIFY_AND_DELETE) {
				dif_info_l1->wd0.grd_agm_ctrl =
				HIFC_DIF_GUARD_VERIFY_IP_CHECKSUM_REPLACE_CRC16;
			}
		}

		if ((task_type == HIFC_SQE_FCP_IREAD) ||
		    (task_type == HIFC_SQE_FCP_TWR)) {
			if ((UNF_DIF_ACTION_MASK &
			(v_pkg->dif_control.protect_opcode)) ==
			UNF_DIF_ACTION_VERIFY_AND_FORWARD) {
				dif_info_l1->wd0.grd_ctrl |=
				HIFC_DIF_GARD_REF_APP_CTRL_REPLACE;
				dif_info_l1->wd0.grd_agm_ctrl =
				HIFC_DIF_GUARD_VERIFY_CRC16_REPLACE_IP_CHECKSUM;
			}

			if ((UNF_DIF_ACTION_MASK &
			(v_pkg->dif_control.protect_opcode)) ==
			UNF_DIF_ACTION_INSERT) {
				dif_info_l1->wd0.grd_agm_ctrl =
				HIFC_DIF_GUARD_VERIFY_CRC16_REPLACE_IP_CHECKSUM;
			}
		}
	}

	if (grd_agm_ctrl != 0)
		dif_info_l1->wd0.grd_agm_ctrl = grd_agm_ctrl;

	if (grd_ctrl != 0)
		dif_info_l1->wd0.grd_ctrl = grd_ctrl;
}

void hifc_get_dma_direction_by_fcp_cmnd(const struct unf_fcp_cmnd_s *v_fcp_cmnd,
					int *v_pi_dma_direction,
					unsigned char *v_task_type)
{
	if (UNF_FCP_WR_DATA & v_fcp_cmnd->control) {
		*v_task_type = HIFC_SQE_FCP_IWRITE;
		*v_pi_dma_direction = DMA_TO_DEVICE;
	} else if (UNF_GET_TASK_MGMT_FLAGS(v_fcp_cmnd->control) != 0) {
		*v_task_type = HIFC_SQE_FCP_ITMF;
		*v_pi_dma_direction = DMA_FROM_DEVICE;
	} else {
		*v_task_type = HIFC_SQE_FCP_IREAD;
		*v_pi_dma_direction = DMA_FROM_DEVICE;
	}
}

static void hifc_adjust_icmnd_burst_len(struct unf_frame_pkg_s *v_pkg,
					struct hifcoe_sqe_ts_s *v_sqe_ts,
					int direction)
{
	struct hifcoe_sqe_icmnd_s *icmnd = &v_sqe_ts->cont.icmnd;

	icmnd->info.dif_info.wd0.difx_len = 0;
}

static inline unsigned int hifc_build_cmnd_wqe(struct hifc_hba_s *v_hba,
					       struct unf_frame_pkg_s *v_pkg,
					       struct hifcoe_sqe_s *v_sge)
{
	unsigned int ret = RETURN_OK;
	int direction = 0;
	unsigned char task_type = 0;
	struct unf_fcp_cmnd_s *fcp_cmnd = NULL;
	struct hifcoe_sqe_s *sqe = v_sge;
	unsigned int dif_flag = 0;

	fcp_cmnd = v_pkg->fcp_cmnd;
	if (unlikely(!fcp_cmnd)) {
		UNF_TRACE(UNF_EVTLOG_IO_ERR, UNF_LOG_IO_ATT, UNF_ERR,
			  "[err]Package's FCP commond pointer is NULL.");

		return UNF_RETURN_ERROR;
	}

	hifc_get_dma_direction_by_fcp_cmnd(fcp_cmnd, &direction, &task_type);

	hifc_build_icmnd_wqe_ts_header(v_pkg, sqe, task_type,
				       v_hba->exit_base, v_hba->port_index);

	hifc_build_trd_twr_wqe_ctrls(v_pkg, sqe);

	hifc_build_icmnd_wqe_ts(v_hba, v_pkg, &sqe->ts_sl);

	if (task_type != HIFC_SQE_FCP_ITMF) {
		if (v_pkg->dif_control.protect_opcode == UNF_DIF_ACTION_NONE) {
			dif_flag = 0;
			hifc_build_no_dif_control(
					v_pkg,
					&sqe->ts_sl.cont.icmnd.info.dif_info);
		} else {
			dif_flag = 1;
			hifc_build_dif_control(
					v_hba, v_pkg,
					&sqe->ts_sl.cont.icmnd.info.dif_info);
			hifc_adjust_dix(
				v_pkg, &sqe->ts_sl.cont.icmnd.info.dif_info,
				task_type);
			hifc_adjust_icmnd_burst_len(v_pkg, &sqe->ts_sl,
						    direction);
		}
	}

	ret = hifc_build_sgl(v_hba, v_pkg, sqe, direction, dif_flag);

	return ret;
}

unsigned int hifc_send_scsi_cmnd(void *v_hba, struct unf_frame_pkg_s *v_pkg)
{
	struct hifc_hba_s *hba = NULL;
	struct hifc_parent_sq_info_s *parent_sq = NULL;
	unsigned int ret = UNF_RETURN_ERROR;
	struct hifcoe_sqe_s sqe;

	/* input param check */
	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE, v_hba,
	return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE, v_pkg,
	return UNF_RETURN_ERROR);
	UNF_CHECK_VALID(INVALID_VALUE32, UNF_TRUE,
	(UNF_GET_OXID(v_pkg) != INVALID_VALUE16), return UNF_RETURN_ERROR);

	HIFC_CHECK_PKG_ALLOCTIME(v_pkg);
	memset(&sqe, 0, sizeof(struct hifcoe_sqe_s));
	hba = v_hba;

	/* 1. find parent sq for scsi_cmnd(pkg) */
	parent_sq = hifc_find_parent_sq_by_pkg(hba, v_pkg);
	if (unlikely(!parent_sq))
		/* Do not need to print info */
		return UNF_RETURN_ERROR;

	v_pkg->qos_level += hba->vpid_start;

	/* 2. build cmnd wqe (to sqe) for scsi_cmnd(pkg) */
	ret = hifc_build_cmnd_wqe(hba, v_pkg, &sqe);
	if (unlikely(ret != RETURN_OK)) {
		HIFC_TRACE(UNF_EVTLOG_IO_INFO, UNF_LOG_IO_ATT, UNF_ERR,
			   "[fail]Port(0x%x) Build WQE failed, SID(0x%x) DID(0x%x) OXID(0x%x) pkg type(0x%x) hot pool tag(0x%x).",
			   hba->port_cfg.port_id, v_pkg->frame_head.csctl_sid,
			   v_pkg->frame_head.rctl_did, UNF_GET_OXID(v_pkg),
			   v_pkg->type, UNF_GET_XCHG_TAG(v_pkg));

		return ret;
	}

	/* 3. En-Queue Parent SQ for scsi_cmnd(pkg) sqe */
	ret = hifc_parent_sq_enqueue(parent_sq, &sqe);

	return ret;
}

static void hifc_ini_status_default_handler(struct hifcoe_scqe_iresp_s *v_iresp,
					    struct unf_frame_pkg_s *v_pkg)
{
	unsigned char control = 0;
	unsigned short com_err_code = 0;

	control = v_iresp->wd2.fcp_flag & HIFC_CTRL_MASK;

	if (v_iresp->fcp_resid != 0) {
		com_err_code = UNF_IO_FAILED;
		v_pkg->residus_len = v_iresp->fcp_resid;
	} else {
		com_err_code = UNF_IO_SUCCESS;
		v_pkg->residus_len = 0;
	}

	v_pkg->status = hifc_fill_pkg_status(com_err_code, control,
					       v_iresp->wd2.scsi_status);

	UNF_TRACE(UNF_EVTLOG_IO_INFO, UNF_LOG_IO_ATT, UNF_INFO,
		  "[info]Fill package with status: 0x%x, residus len: 0x%x",
		  v_pkg->status, v_pkg->residus_len);
}

void hifc_check_fcp_rsp_iu(struct hifcoe_scqe_iresp_s *v_iresp,
			   struct unf_frame_pkg_s *v_pkg)
{
	unsigned char scsi_status = 0;
	unsigned char control = 0;

	control = (unsigned char)v_iresp->wd2.fcp_flag;
	scsi_status = (unsigned char)v_iresp->wd2.scsi_status;

	/* FcpRspIU with Little End from IOB/WQE, to COM's pstPkg also */
	if (control & FCP_RESID_UNDER_MASK) {
		/* under flow: usually occurs in inquiry */
		UNF_TRACE(UNF_EVTLOG_IO_INFO, UNF_LOG_IO_ATT, UNF_INFO,
			  "[info]I_STS IOB posts under flow with residus len: %u, FCP residue: %u.",
			  v_pkg->residus_len, v_iresp->fcp_resid);

		if (v_pkg->residus_len != v_iresp->fcp_resid) {
			v_pkg->status = hifc_fill_pkg_status(UNF_IO_FAILED,
							       control,
							       scsi_status);
		} else {
			v_pkg->status =
			hifc_fill_pkg_status(UNF_IO_UNDER_FLOW,
					     control, scsi_status);
		}
	}

	if (control & FCP_RESID_OVER_MASK) {
		/* over flow: error happened */
		UNF_TRACE(UNF_EVTLOG_IO_WARN, UNF_LOG_IO_ATT, UNF_WARN,
			  "[warn]I_STS IOB posts over flow with residus len: %u, FCP residue: %u.",
			  v_pkg->residus_len, v_iresp->fcp_resid);

		if (v_pkg->residus_len != v_iresp->fcp_resid) {
			v_pkg->status = hifc_fill_pkg_status(UNF_IO_FAILED,
							       control,
							       scsi_status);
		} else {
			v_pkg->status = hifc_fill_pkg_status(UNF_IO_OVER_FLOW,
							       control,
							       scsi_status);
		}
	}

	v_pkg->unf_rsp_pload_bl.length = 0;
	v_pkg->unf_sense_pload_bl.length = 0;

	if (control & FCP_RSP_LEN_VALID_MASK) {
		/* dma by chip */
		v_pkg->unf_rsp_pload_bl.buffer_ptr = NULL;

		v_pkg->unf_rsp_pload_bl.length = v_iresp->fcp_rsp_len;
		v_pkg->byte_orders |= UNF_BIT_3;
	}

	if (control & FCP_SNS_LEN_VALID_MASK) {
		/* dma by chip */
		v_pkg->unf_sense_pload_bl.buffer_ptr = NULL;

		v_pkg->unf_sense_pload_bl.length = v_iresp->fcp_sns_len;
		v_pkg->byte_orders |= UNF_BIT_4;
	}
}

unsigned short hifc_get_com_err_code(struct unf_frame_pkg_s *v_pkg)
{
	unsigned short com_err_code = UNF_IO_FAILED;

	if (v_pkg->status_sub_code == DRV_DIF_CRC_ERR)
		com_err_code = UNF_IO_DIF_ERROR;
	else if (v_pkg->status_sub_code == DRV_DIF_LBA_ERR)
		com_err_code = UNF_IO_DIF_REF_ERROR;
	else
		com_err_code = UNF_IO_DIF_GEN_ERROR;
	return com_err_code;
}

void hifc_process_ini_fail_io(struct hifc_hba_s *v_hba,
			      struct hifcoe_scqe_iresp_s *v_iresp,
			      struct unf_frame_pkg_s *v_pkg)
{
	unsigned short com_err_code = UNF_IO_FAILED;
	unsigned char dif_info = 0;

	/* 1. error stats process */
	if (HIFC_GET_SCQE_STATUS((union hifcoe_scqe_u *)(void *)v_iresp) != 0) {
		switch (HIFC_GET_SCQE_STATUS(
			(union hifcoe_scqe_u *)(void *)v_iresp)) {
		/* DIF error process */
		case HIFC_COMPLETION_STATUS_DIF_ERROR:
			dif_info = (unsigned char)v_iresp->wd1.dif_info;
			v_pkg->status_sub_code =
			(dif_info & HIFC_DIF_ERROR_CODE_CRC) ?
			DRV_DIF_CRC_ERR : ((dif_info &
			HIFC_DIF_ERROR_CODE_REF) ?  DRV_DIF_LBA_ERR :
			((dif_info & HIFC_DIF_ERROR_CODE_APP) ?
			DRV_DIF_APP_ERR : 0));

			com_err_code = hifc_get_com_err_code(v_pkg);

			UNF_TRACE(UNF_EVTLOG_IO_ERR, UNF_LOG_IO_ATT, UNF_MAJOR,
				  "[err]Port(0x%x) INI io oxid(0x%x), rxid(0x%x) status with dif err(0x%x)",
				  v_hba->port_cfg.port_id, v_iresp->wd0.ox_id,
				  v_iresp->wd0.rx_id, dif_info);

			hifc_dif_err_count(v_hba, dif_info);
			break;

		/* I/O not complete: 1.session reset;  2.clear buffer */
		case FCOE_CQE_BUFFER_CLEAR_IO_COMPLETED:
		case FCOE_CQE_SESSION_RST_CLEAR_IO_COMPLETED:
		case FCOE_CQE_SESSION_ONLY_CLEAR_IO_COMPLETED:
		case FCOE_CQE_WQE_FLUSH_IO_COMPLETED:
			com_err_code = UNF_IO_CLEAN_UP;

			UNF_TRACE(UNF_EVTLOG_IO_WARN, UNF_LOG_IO_ATT, UNF_MAJOR,
				  "[warn]Port(0x%x) INI IO not complete, OX_ID(0x%x) RX_ID(0x%x) status(0x%x)",
				  v_hba->port_cfg.port_id, v_iresp->wd0.ox_id,
				  v_iresp->wd0.rx_id, com_err_code);
			break;

		/* any other: I/O failed --->>> DID error */
		default:
			com_err_code = UNF_IO_FAILED;
			break;
		}

		/* fill pkg status & return directly */
		v_pkg->status =
		hifc_fill_pkg_status(com_err_code, v_iresp->wd2.fcp_flag,
				     v_iresp->wd2.scsi_status);
		return;
	}

	/* 2. default stats process */
	hifc_ini_status_default_handler(v_iresp, v_pkg);

	/* 3. FCP RSP IU check */
	hifc_check_fcp_rsp_iu(v_iresp, v_pkg);
}

unsigned int hifc_scq_recv_iresp(struct hifc_hba_s *v_hba,
				 union hifcoe_scqe_u *v_wqe)
{
	struct hifcoe_scqe_iresp_s *iresp = NULL;
	struct unf_frame_pkg_s pkg;
	unsigned int ret = RETURN_OK;

	iresp = (struct hifcoe_scqe_iresp_s *)(void *)v_wqe;

	/* 1. Constraints: I_STS remain cnt must be zero */
	if (unlikely(HIFC_GET_SCQE_REMAIN_CNT(v_wqe) != 0)) {
		HIFC_TRACE(UNF_EVTLOG_IO_ERR, UNF_LOG_IO_ATT, UNF_ERR,
			   "[err]Port(0x%x) ini_wqe(OX_ID:0x%x RX_ID:0x%x) remain_cnt(0x%x) abnormal, status(0x%x)",
			   v_hba->port_cfg.port_id,
			   iresp->wd0.ox_id,
			   iresp->wd0.rx_id,
			   HIFC_GET_SCQE_REMAIN_CNT(v_wqe),
			   HIFC_GET_SCQE_STATUS(v_wqe));

		UNF_PRINT_SFS_LIMIT(UNF_MAJOR, v_hba->port_cfg.port_id, v_wqe,
				    sizeof(union hifcoe_scqe_u));

		/* return directly */
		return UNF_RETURN_ERROR;
	}

	memset(&pkg, 0, sizeof(struct unf_frame_pkg_s));
	pkg.private[PKG_PRIVATE_XCHG_ALLOC_TIME] = iresp->magic_num;

	/* 2. OX_ID validity check */
	if (likely(((unsigned short)iresp->wd0.ox_id >= v_hba->exit_base) &&
		   ((unsigned short)iresp->wd0.ox_id <
		   v_hba->exit_base + v_hba->exit_count))) {
		pkg.status = UNF_IO_SUCCESS;
		pkg.private[PKG_PRIVATE_XCHG_HOT_POOL_INDEX] =
		iresp->wd0.ox_id - v_hba->exit_base;
	} else {
		/* OX_ID error: return by COM */
		pkg.status = UNF_IO_FAILED;
		pkg.private[PKG_PRIVATE_XCHG_HOT_POOL_INDEX] = INVALID_VALUE16;

		HIFC_TRACE(UNF_EVTLOG_IO_ERR, UNF_LOG_IO_ATT, UNF_ERR,
			   "[err]Port(0x%x) ini_cmnd_wqe(OX_ID:0x%x RX_ID:0x%x) ox_id invalid, status(0x%x)",
			   v_hba->port_cfg.port_id,
			   iresp->wd0.ox_id,
			   iresp->wd0.rx_id,
			   HIFC_GET_SCQE_STATUS(v_wqe));

		UNF_PRINT_SFS_LIMIT(UNF_MAJOR, v_hba->port_cfg.port_id,
				    v_wqe, sizeof(union hifcoe_scqe_u));
	}

	/* 3. status check */
	if (unlikely(HIFC_GET_SCQE_STATUS(v_wqe) ||
		     (iresp->wd2.scsi_status != 0) ||
		     (iresp->fcp_resid != 0) ||
		     ((iresp->wd2.fcp_flag & HIFC_CTRL_MASK) != 0))) {
		HIFC_TRACE(UNF_EVTLOG_IO_INFO, UNF_LOG_IO_ATT, UNF_INFO,
			   "[warn]Port(0x%x) scq_status(0x%x) scsi_status(0x%x) fcp_resid(0x%x) fcp_flag(0x%x)",
			   v_hba->port_cfg.port_id, HIFC_GET_SCQE_STATUS(v_wqe),
			   iresp->wd2.scsi_status, iresp->fcp_resid,
			   iresp->wd2.fcp_flag);

		/* set pkg status & check fcp_rsp IU */
		hifc_process_ini_fail_io(v_hba, iresp, &pkg);
	}

	/* 4. LL_Driver ---to--->>> COM_Driver */
	UNF_LOWLEVEL_SCSI_COMPLETED(ret, v_hba->lport, &pkg);

	return ret;
}
