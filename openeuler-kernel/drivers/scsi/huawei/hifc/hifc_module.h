/* SPDX-License-Identifier: GPL-2.0 */
/* Huawei Hifc PCI Express Linux driver
 * Copyright(c) 2017 Huawei Technologies Co., Ltd
 *
 */

#ifndef __HIFC_MODULE_H__
#define __HIFC_MODULE_H__
#include "unf_log.h"
#include "unf_common.h"
#include "hifc_utils.h"
#include "hifc_hba.h"

#define HIFC_SPEED_16G                  0x10
#define HIFC_SPEED_32G                  0x20
#define HIFC_MAX_PORT_NUM               HIFC_MAX_PROBE_PORT_NUM
#define HIFC_TASK_TYPE_STAT_NUM         128
#define HIFC_MAX_LINK_EVENT_CNT         4
#define HIFC_MAX_LINK_REASON_CNT        256

/* Declare the global function. */
extern struct unf_cm_handle_op_s hifc_cm_handle;
extern unsigned int max_speed;
extern unsigned int accum_db_num;
extern unsigned int wqe_page_size;
extern unsigned int dif_type;
extern unsigned int wqe_pre_load;
extern unsigned int combo_length_kb;
extern unsigned int cos_bit_map;

extern atomic64_t rx_tx_stat[HIFC_MAX_PORT_NUM][HIFC_TASK_TYPE_STAT_NUM];
extern atomic64_t rx_tx_err[HIFC_MAX_PORT_NUM][HIFC_TASK_TYPE_STAT_NUM];
extern atomic64_t scq_err_stat[HIFC_MAX_PORT_NUM][HIFC_TASK_TYPE_STAT_NUM];
extern atomic64_t aeq_err_stat[HIFC_MAX_PORT_NUM][HIFC_TASK_TYPE_STAT_NUM];
extern atomic64_t dif_err_stat[HIFC_MAX_PORT_NUM][HIFC_TASK_TYPE_STAT_NUM];
extern atomic64_t mail_box_stat[HIFC_MAX_PORT_NUM][HIFC_TASK_TYPE_STAT_NUM];
extern atomic64_t com_up_event_err_stat[HIFC_MAX_PORT_NUM][HIFC_TASK_TYPE_STAT_NUM];
extern unsigned long long link_event_stat[HIFC_MAX_PORT_NUM][HIFC_MAX_LINK_EVENT_CNT];
extern unsigned long long link_reason_stat[HIFC_MAX_PORT_NUM][HIFC_MAX_LINK_REASON_CNT];
extern atomic64_t up_err_event_stat[HIFC_MAX_PORT_NUM][HIFC_TASK_TYPE_STAT_NUM];
extern unsigned long long hba_stat[HIFC_MAX_PORT_NUM][HIFC_HBA_STAT_BUTT];

#define HIFC_LINK_EVENT_STAT(v_hba, link_ent) \
	(link_event_stat[(v_hba)->probe_index][link_ent]++)
#define HIFC_LINK_REASON_STAT(v_hba, link_rsn) \
	(link_reason_stat[(v_hba)->probe_index][link_rsn]++)
#define HIFC_HBA_STAT(v_hba, hba_stat_type) \
	(hba_stat[(v_hba)->probe_index][hba_stat_type]++)

#define HIFC_UP_ERR_EVENT_STAT(v_hba, err_type) \
	(atomic64_inc(&up_err_event_stat[(v_hba)->probe_index][err_type]))
#define HIFC_UP_ERR_EVENT_STAT_READ(probe_index, io_type) \
	(atomic64_read(&up_err_event_stat[probe_index][io_type]))
#define HIFC_DIF_ERR_STAT(v_hba, dif_err)	  \
	(atomic64_inc(&dif_err_stat[(v_hba)->probe_index][dif_err]))
#define HIFC_DIF_ERR_STAT_READ(probe_index, dif_err)  \
	(atomic64_read(&dif_err_stat[probe_index][dif_err]))

#define HIFC_IO_STAT(v_hba, io_type)	 \
	(atomic64_inc(&rx_tx_stat[(v_hba)->probe_index][io_type]))
#define HIFC_IO_STAT_READ(probe_index, io_type) \
	(atomic64_read(&rx_tx_stat[probe_index][io_type]))

#define HIFC_ERR_IO_STAT(v_hba, io_type)	 \
	(atomic64_inc(&rx_tx_err[(v_hba)->probe_index][io_type]))
#define HIFC_ERR_IO_STAT_READ(probe_index, io_type) \
	(atomic64_read(&rx_tx_err[probe_index][io_type]))

#define HIFC_SCQ_ERR_TYPE_STAT(v_hba, err_type)   \
	(atomic64_inc(&scq_err_stat[(v_hba)->probe_index][err_type]))
#define HIFC_SCQ_ERR_TYPE_STAT_READ(probe_index, io_type) \
	(atomic64_read(&scq_err_stat[probe_index][io_type]))
#define HIFC_AEQ_ERR_TYPE_STAT(v_hba, err_type)	  \
	(atomic64_inc(&aeq_err_stat[(v_hba)->probe_index][err_type]))
#define HIFC_AEQ_ERR_TYPE_STAT_READ(probe_index, io_type) \
	(atomic64_read(&aeq_err_stat[probe_index][io_type]))

#define HIFC_MAILBOX_STAT(v_hba, io_type)	\
	(atomic64_inc(&mail_box_stat[(v_hba)->probe_index][io_type]))

#define HIFC_COM_UP_ERR_EVENT_STAT(v_hba, err_type) \
	(atomic64_inc(&com_up_event_err_stat[(v_hba)->probe_index][err_type]))
#define HIFC_COM_UP_ERR_EVENT_STAT_READ(probe_index, err_type) \
	(atomic64_read(&com_up_event_err_stat[probe_index][err_type]))

/*
 *----------------------------------------------*
 * Define function *
 *----------------------------------------------
 */

#define UNF_LOWLEVEL_ALLOC_LPORT(v_lport, fc_port, stLowLevel)\
	do {\
		if (hifc_cm_handle.pfn_unf_alloc_local_port) { \
			v_lport = \
			hifc_cm_handle.pfn_unf_alloc_local_port((fc_port), \
								(stLowLevel));\
		} else {						\
			v_lport = NULL;					\
		}							\
	} while (0)

#define UNF_LOWLEVEL_RECEIVE_ELS_PKG(v_ret, fc_port, pkg)		\
	do {								\
		if (hifc_cm_handle.pfn_unf_receive_els_pkg) {\
			v_ret =\
				hifc_cm_handle.pfn_unf_receive_els_pkg(\
					(fc_port), (pkg));\
		} else {				\
			v_ret = UNF_RETURN_ERROR;	\
		}					\
	} while (0)

#define UNF_LOWLEVEL_SEND_ELS_DONE(v_ret, fc_port, pkg)	\
	do {						\
		if (hifc_cm_handle.pfn_unf_send_els_done) {\
			v_ret = hifc_cm_handle.pfn_unf_send_els_done((fc_port),\
								     (pkg)); \
		} else {				\
			v_ret = UNF_RETURN_ERROR;	\
		}					\
	} while (0)

#define UNF_LOWLEVEL_RECEIVE_GS_PKG(v_ret, fc_port, pkg)\
	do {						\
		if (hifc_cm_handle.pfn_unf_receive_gs_pkg) {\
			v_ret = hifc_cm_handle.pfn_unf_receive_gs_pkg(\
							(fc_port),\
							(pkg)); \
		} else {					\
			v_ret = UNF_RETURN_ERROR;		\
		}						\
	} while (0)

#define UNF_LOWLEVEL_GET_CFG_PARMS(v_ret,			\
	v_section_name,						\
	v_cfg_parm,						\
	v_cfg_value,						\
	v_item_num)						\
	do {							\
		if (hifc_cm_handle.pfn_unf_get_cfg_parms) {	\
			v_ret = (unsigned int)\
				hifc_cm_handle.pfn_unf_get_cfg_parms(\
				(v_section_name),		\
				(v_cfg_parm),			\
				(v_cfg_value),			\
				(v_item_num));			\
		} else {					\
			HIFC_TRACE(UNF_EVTLOG_DRIVER_WARN, UNF_LOG_REG_ATT,\
				UNF_WARN,\
				"Get config parameter function is NULL.");\
				v_ret = UNF_RETURN_ERROR;		\
		}							\
	} while (0)

#define UNF_LOWLEVEL_RELEASE_LOCAL_PORT(v_ret, lport)		\
	do {								\
		if (unlikely(!hifc_cm_handle.pfn_unf_release_local_port)) {\
			v_ret = UNF_RETURN_ERROR;			\
		} else {						\
			v_ret =\
				hifc_cm_handle.pfn_unf_release_local_port(\
						(lport));\
		}						\
	} while (0)

#define UNF_LOWLEVEL_TO_CM_HINICADM(v_ret, lport, pkg)		\
	do {							\
		if (unlikely(!hifc_cm_handle.pfn_unf_ioctl_to_com_handler)) {\
			v_ret = UNF_RETURN_ERROR;			\
		} else {						\
			v_ret = hifc_cm_handle.pfn_unf_ioctl_to_com_handler(\
							lport, pkg); \
		}						\
	} while (0)

#define UNF_CM_GET_SGL_ENTRY(v_ret, pkg, v_buf, v_buf_len)	\
	do {							\
		if (unlikely(!hifc_cm_handle.pfn_unf_cm_get_sgl_entry)) {\
			v_ret = UNF_RETURN_ERROR;			\
		} else {						\
			v_ret = hifc_cm_handle.pfn_unf_cm_get_sgl_entry(\
							pkg, v_buf, v_buf_len);\
		}						\
	} while (0)

#define UNF_CM_GET_DIF_SGL_ENTRY(v_ret, pkg, v_buf, v_buf_len)\
	do {							\
		if (unlikely(!hifc_cm_handle.pfn_unf_cm_get_dif_sgl_entry)) {\
			v_ret = UNF_RETURN_ERROR;			\
		} else {						\
			v_ret = hifc_cm_handle.pfn_unf_cm_get_dif_sgl_entry(\
								pkg,\
								v_buf,\
								v_buf_len);\
		}							\
	} while (0)

#define UNF_GET_SGL_ENTRY(v_ret, pkg, v_buf, v_buf_len, v_dif_flag)	\
	do {								\
		if (v_dif_flag) {					\
			UNF_CM_GET_DIF_SGL_ENTRY(v_ret, pkg, v_buf, v_buf_len);\
		} else {						\
			UNF_CM_GET_SGL_ENTRY(v_ret, pkg, v_buf, v_buf_len);\
		}							\
	} while (0)

#define UNF_GET_FREE_ESGL_PAGE(v_ret, lport, pkg)			\
	do {								\
		if (unlikely(!hifc_cm_handle.pfn_unf_get_one_free_esgl_page)) {\
			v_ret = NULL;					\
		} else {						\
			v_ret = hifc_cm_handle.pfn_unf_get_one_free_esgl_page(\
							lport, pkg); \
		}						\
	} while (0)

#define UNF_LOWLEVEL_SCSI_COMPLETED(v_ret, lport, pkg)			\
	do {								\
		if (unlikely(!hifc_cm_handle.pfn_unf_receive_ini_rsponse)) {\
			v_ret = UNF_RETURN_ERROR;			\
		} else {						\
			v_ret = hifc_cm_handle.pfn_unf_receive_ini_rsponse(\
							lport, pkg);\
		}						\
	} while (0)

#define UNF_LOWLEVEL_PORT_EVENT(v_ret, lport, v_events, v_input)\
	do {							\
		if (unlikely(!hifc_cm_handle.pfn_unf_fc_port_link_event)) {\
			v_ret = UNF_RETURN_ERROR;			\
		} else {						\
			v_ret = hifc_cm_handle.pfn_unf_fc_port_link_event(\
						lport, v_events, v_input);\
		}						\
	} while (0)

#define UNF_LOWLEVEL_RECEIVE_FC4LS_PKG(v_ret, fc_port, pkg)\
	do {						\
		if (hifc_cm_handle.pfn_unf_receive_fc4_pkg) {\
			v_ret = hifc_cm_handle.pfn_unf_receive_fc4_pkg(\
							(fc_port), (pkg));\
		} else {					\
			v_ret = UNF_RETURN_ERROR;		\
		}						\
	} while (0)

#define UNF_LOWLEVEL_SEND_FC4LS_DONE(v_ret, lport, pkg)		\
	do {							\
		if (hifc_cm_handle.pfn_unf_send_fc4_done) {\
			v_ret = hifc_cm_handle.pfn_unf_send_fc4_done(\
							(lport), (pkg));\
		} else {					\
			v_ret = UNF_RETURN_ERROR;		\
		}						\
	} while (0)

#define UNF_LOWLEVEL_RECEIVE_BLS_PKG(v_ret, lport, pkg)		\
	do {							\
		if (hifc_cm_handle.pfn_unf_receive_bls_pkg) {\
			v_ret = hifc_cm_handle.pfn_unf_receive_bls_pkg(\
						(lport), (pkg)); \
		} else {					\
			v_ret = UNF_RETURN_ERROR;		\
		}						\
	} while (0)

#define UNF_LOWLEVEL_RECEIVE_MARKER_STS(v_ret, lport, pkg)\
	do {						\
		if (hifc_cm_handle.pfn_unf_receive_marker_status) {\
			v_ret = hifc_cm_handle.pfn_unf_receive_marker_status(\
						(lport), (pkg));\
		} else {					\
			v_ret = UNF_RETURN_ERROR;		\
		}						\
	} while (0)

#define UNF_LOWLEVEL_RECEIVE_ABTS_MARKER_STS(v_ret, lport, pkg)	\
	do {							\
		if (hifc_cm_handle.pfn_unf_receive_abts_marker_status) {\
			v_ret =\
			hifc_cm_handle.pfn_unf_receive_abts_marker_status(\
						(lport), (pkg));\
		} else {					\
			v_ret = UNF_RETURN_ERROR;		\
		}						\
	} while (0)

#endif
