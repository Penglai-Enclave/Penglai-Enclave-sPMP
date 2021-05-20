/* SPDX-License-Identifier: GPL-2.0 */
/* Huawei Hifc PCI Express Linux driver
 * Copyright(c) 2017 Huawei Technologies Co., Ltd
 *
 */
#ifndef __UNF_IO_H__
#define __UNF_IO_H__

#define UNF_MAX_TARGET_NUMBER    2048
#define UNF_DEFAULT_MAX_LUN      0xFFFF
#define UNF_MAX_DMA_SEGS         0x400
#define UNF_MAX_SCSI_CMND_LEN    16
#define UNF_MAX_SECTORS          0xffff
#define UNF_MAX_BUS_CHANNEL      0
#define UNF_DMA_BOUNDARY         0xffffffffffffffff
#define UNF_MAX_CMND_PER_LUN     64 /* LUN max command */

#define NO_SENSE        0x00
#define RECOVERED_ERROR 0x01
#define NOT_READY       0x02
#define MEDIUM_ERROR    0x03
#define HARDWARE_ERROR  0x04
#define ILLEGAL_REQUEST 0x05
#define UNIT_ATTENTION  0x06
#define DATA_PROTECT    0x07
#define BLANK_CHECK     0x08
#define COPY_ABORTED    0x0a
#define ABORTED_COMMAND 0x0b
#define VOLUME_OVERFLOW 0x0d
#define MISCOMPARE      0x0e

#define UNF_GET_SCSI_HOST_ID_BY_CMND(pcmd)  ((pcmd)->scsi_host_id)
#define UNF_GET_SCSI_ID_BY_CMND(pcmd)       ((pcmd)->scsi_id)
#define UNF_GET_HOST_PORT_BY_CMND(pcmd)     ((pcmd)->drv_private)
#define UNF_GET_FCP_CMND(pcmd)              ((pcmd)->pcmnd[0])
#define UNF_GET_DATA_LEN(pcmd)              ((pcmd)->transfer_len)
#define UNF_GET_DATA_DIRECTION(pcmd)        ((pcmd)->data_direction)

#define UNF_GET_HOST_CMND(pcmd)             ((pcmd)->upper_cmnd)
#define UNF_GET_CMND_DONE_FUNC(pcmd)        ((pcmd)->pfn_done)
#define UNF_GET_SGL_ENTRY_BUF_FUNC(pcmd)    ((pcmd)->pfn_unf_ini_get_sgl_entry)
#define UNF_GET_SENSE_BUF_ADDR(pcmd)        ((pcmd)->sense_buf)
#define UNF_GET_ERR_CODE_TABLE(pcmd)        ((pcmd)->err_code_table)
#define UNF_GET_ERR_CODE_TABLE_COUNT(pcmd)  ((pcmd)->err_code_table_cout)

#define UNF_SET_HOST_CMND(pcmd, host_cmd)   ((pcmd)->upper_cmnd = (host_cmd))
#define UNF_SET_CMND_DONE_FUNC(pcmd, pfn)   ((pcmd)->pfn_done = (pfn))

#define UNF_SET_RESID(pcmd, id_len)         ((pcmd)->resid = (id_len))
#define UNF_SET_CMND_RESULT(pcmd, uiresult) ((pcmd)->result = ((int)uiresult))

#define UNF_DONE_SCSI_CMND(pcmd)            ((pcmd)->pfn_done(pcmd))

#define UNF_GET_CMND_SGL(pcmd)              ((pcmd)->sgl)
#define UNF_INI_GET_DIF_SGL(pcmd)           ((pcmd)->dif_control.dif_sgl)

unsigned int unf_ini_scsi_completed(void *v_lport,
				    struct unf_frame_pkg_s *v_pkg);
unsigned int unf_ini_get_sgl_entry(void *v_pkg, char **v_buf,
				   unsigned int *v_buf_len);
unsigned int unf_ini_get_dif_sgl_entry(void *v_pkg, char **v_buf,
				       unsigned int *v_buf_len);

void unf_complete_cmnd(struct unf_scsi_cmd_s *v_scsi_cmnd, unsigned int result);
void unf_done_ini_xchg(struct unf_xchg_s *v_xchg);
unsigned int unf_tmf_timeout_recovery_special(void *v_rport, void *v_xchg);
void unf_abts_timeout_recovery_default(void *v_rport, void *v_xchg);
int unf_cm_queue_command(struct unf_scsi_cmd_s *v_scsi_cmnd);
int unf_cm_eh_abort_handler(struct unf_scsi_cmd_s *v_scsi_cmnd);
int unf_cm_eh_device_reset_handler(struct unf_scsi_cmd_s *v_scsi_cmnd);
int unf_cm_target_reset_handler(struct unf_scsi_cmd_s *v_scsi_cmnd);
int unf_cm_bus_reset_handler(struct unf_scsi_cmd_s *v_scsi_cmnd);
struct unf_rport_s *unf_find_rport_by_scsi_id(
				struct unf_lport_s *v_lport,
				struct unf_ini_error_code_s *v_err_code_table,
				unsigned int v_err_code_table_cout,
				unsigned int v_scsi_id,
				unsigned int *v_scsi_result);

struct unf_lport_s *unf_find_lport_by_scsi_cmd(
					struct unf_scsi_cmd_s *v_scsi_cmnd);
void unf_tmf_abnormal_recovery(struct unf_lport_s *v_lport,
			       struct unf_rport_s *v_rport,
			       struct unf_xchg_s *v_xchg);
unsigned int unf_get_uplevel_cmnd_errcode(
				struct unf_ini_error_code_s *v_err_table,
				unsigned int v_err_table_count,
				unsigned int v_drv_err_code);

#endif
