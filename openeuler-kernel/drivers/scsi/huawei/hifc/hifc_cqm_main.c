// SPDX-License-Identifier: GPL-2.0
/* Huawei Hifc PCI Express Linux driver
 * Copyright(c) 2017 Huawei Technologies Co., Ltd
 *
 */

#include <linux/sched.h>
#include <linux/pci.h>
#include <linux/module.h>
#include <linux/delay.h>
#include <linux/vmalloc.h>

#include "hifc_knl_adp.h"
#include "hifc_hw.h"
#include "hifc_hwdev.h"
#include "hifc_hwif.h"
#include "hifc_api_cmd.h"
#include "hifc_mgmt.h"
#include "hifc_cfg.h"
#include "hifc_cqm_object.h"
#include "hifc_cqm_main.h"

#define GET_MAX(a, b)  (((a) > (b)) ? (a) : (b))
#define GET_MIN(a, b)  (((a) < (b)) ? (a) : (b))

static void cqm_capability_init_check_ppf(void *ex_handle,
					  u32 *total_function_num)
{
	struct hifc_hwdev *handle = (struct hifc_hwdev *)ex_handle;
	struct service_cap *service_capability = &handle->cfg_mgmt->svc_cap;
	struct cqm_handle_s *cqm_handle = (struct cqm_handle_s *)
					  (handle->cqm_hdl);

	if (cqm_handle->func_attribute.func_type == CQM_PPF) {
		*total_function_num = service_capability->host_total_function;
		cqm_handle->func_capability.timer_enable =
						service_capability->timer_en;

		cqm_info(handle->dev_hdl, "Cap init: total function num 0x%x\n",
			 *total_function_num);
		cqm_info(handle->dev_hdl, "Cap init: timer_enable %d (1: enable; 0: disable)\n",
			 cqm_handle->func_capability.timer_enable);
	}
}

void cqm_test_mode_init(struct cqm_handle_s *cqm_handle,
			struct service_cap *service_capability)
{
	cqm_handle->func_capability.xid_alloc_mode =
				service_capability->test_xid_alloc_mode;
	cqm_handle->func_capability.gpa_check_enable =
				service_capability->test_gpa_check_enable;
}

static s32 cqm_service_capability_init_for_each(
				struct cqm_handle_s *cqm_handle,
				struct service_cap *service_capability)
{
	struct hifc_hwdev *handle = (struct hifc_hwdev *)cqm_handle->ex_handle;

	cqm_info(handle->dev_hdl, "Cap init: fc is valid\n");
	cqm_handle->func_capability.hash_number +=
		service_capability->fc_cap.dev_fc_cap.max_parent_qpc_num;
	cqm_handle->func_capability.hash_basic_size = CQM_HASH_BUCKET_SIZE_64;
	cqm_handle->func_capability.qpc_number +=
		service_capability->fc_cap.dev_fc_cap.max_parent_qpc_num;
	cqm_handle->func_capability.qpc_basic_size =
			GET_MAX(service_capability->fc_cap.parent_qpc_size,
				cqm_handle->func_capability.qpc_basic_size);
	cqm_handle->func_capability.qpc_alloc_static = true;
	cqm_handle->func_capability.scqc_number +=
			service_capability->fc_cap.dev_fc_cap.scq_num;
	cqm_handle->func_capability.scqc_basic_size =
			GET_MAX(service_capability->fc_cap.scqc_size,
				cqm_handle->func_capability.scqc_basic_size);
	cqm_handle->func_capability.srqc_number +=
			service_capability->fc_cap.dev_fc_cap.srq_num;
	cqm_handle->func_capability.srqc_basic_size =
			GET_MAX(service_capability->fc_cap.srqc_size,
				cqm_handle->func_capability.srqc_basic_size);
	cqm_handle->func_capability.lun_number = CQM_LUN_FC_NUM;
	cqm_handle->func_capability.lun_basic_size = CQM_LUN_SIZE_8;
	cqm_handle->func_capability.taskmap_number = CQM_TASKMAP_FC_NUM;
	cqm_handle->func_capability.taskmap_basic_size = PAGE_SIZE;
	cqm_handle->func_capability.childc_number +=
			service_capability->fc_cap.dev_fc_cap.max_child_qpc_num;
	cqm_handle->func_capability.childc_basic_size =
			GET_MAX(service_capability->fc_cap.child_qpc_size,
				cqm_handle->func_capability.childc_basic_size);
	cqm_handle->func_capability.pagesize_reorder = CQM_FC_PAGESIZE_ORDER;

	return CQM_SUCCESS;
}

s32 cqm_service_capability_init(struct cqm_handle_s *cqm_handle,
				struct service_cap *service_capability)
{
	cqm_handle->service.has_register = false;
	cqm_handle->service.buf_order = 0;

	if (cqm_service_capability_init_for_each(
				cqm_handle,
				service_capability) == CQM_FAIL)
		return CQM_FAIL;

	return CQM_SUCCESS;
}

/**
 * cqm_capability_init - Initialize capability of cqm function and service,
 * need to read information from the configuration management module
 * @ex_handle: handle of hwdev
 */
s32 cqm_capability_init(void *ex_handle)
{
	struct hifc_hwdev *handle = (struct hifc_hwdev *)ex_handle;
	struct service_cap *service_capability = &handle->cfg_mgmt->svc_cap;
	struct cqm_handle_s *cqm_handle = (struct cqm_handle_s *)
					  (handle->cqm_hdl);
	u32 total_function_num = 0;
	int err = 0;

	cqm_capability_init_check_ppf(ex_handle, &total_function_num);

	cqm_handle->func_capability.flow_table_based_conn_number =
			service_capability->max_connect_num;
	cqm_handle->func_capability.flow_table_based_conn_cache_number =
			service_capability->max_stick2cache_num;
	cqm_info(handle->dev_hdl, "Cap init: cfg max_conn_num 0x%x, max_cache_conn_num 0x%x\n",
		 cqm_handle->func_capability.flow_table_based_conn_number,
		 cqm_handle->func_capability.flow_table_based_conn_cache_number);

	cqm_handle->func_capability.qpc_reserved = 0;
	cqm_handle->func_capability.mpt_reserved = 0;
	cqm_handle->func_capability.qpc_alloc_static = false;
	cqm_handle->func_capability.scqc_alloc_static = false;

	cqm_handle->func_capability.l3i_number = CQM_L3I_COMM_NUM;
	cqm_handle->func_capability.l3i_basic_size = CQM_L3I_SIZE_8;

	cqm_handle->func_capability.timer_number = CQM_TIMER_ALIGN_SCALE_NUM *
						   total_function_num;
	cqm_handle->func_capability.timer_basic_size = CQM_TIMER_SIZE_32;

	if (cqm_service_capability_init(cqm_handle, service_capability) ==
	    CQM_FAIL) {
		cqm_err(handle->dev_hdl,
			CQM_FUNCTION_FAIL(cqm_service_capability_init));
		err = CQM_FAIL;
		goto out;
	}

	cqm_test_mode_init(cqm_handle, service_capability);

	cqm_info(handle->dev_hdl, "Cap init: pagesize_reorder %d\n",
		 cqm_handle->func_capability.pagesize_reorder);
	cqm_info(handle->dev_hdl, "Cap init: xid_alloc_mode %d, gpa_check_enable %d\n",
		 cqm_handle->func_capability.xid_alloc_mode,
		 cqm_handle->func_capability.gpa_check_enable);
	cqm_info(handle->dev_hdl, "Cap init: qpc_alloc_mode %d, scqc_alloc_mode %d\n",
		 cqm_handle->func_capability.qpc_alloc_static,
		 cqm_handle->func_capability.scqc_alloc_static);
	cqm_info(handle->dev_hdl, "Cap init: hash_number 0x%x\n",
		 cqm_handle->func_capability.hash_number);
	cqm_info(handle->dev_hdl, "Cap init: qpc_number 0x%x, qpc_reserved 0x%x\n",
		 cqm_handle->func_capability.qpc_number,
		 cqm_handle->func_capability.qpc_reserved);
	cqm_info(handle->dev_hdl, "Cap init: scqc_number 0x%x scqc_reserved 0x%x\n",
		 cqm_handle->func_capability.scqc_number,
		 cqm_handle->func_capability.scq_reserved);
	cqm_info(handle->dev_hdl, "Cap init: srqc_number 0x%x\n",
		 cqm_handle->func_capability.srqc_number);
	cqm_info(handle->dev_hdl, "Cap init: mpt_number 0x%x, mpt_reserved 0x%x\n",
		 cqm_handle->func_capability.mpt_number,
		 cqm_handle->func_capability.mpt_reserved);
	cqm_info(handle->dev_hdl, "Cap init: gid_number 0x%x, lun_number 0x%x\n",
		 cqm_handle->func_capability.gid_number,
		 cqm_handle->func_capability.lun_number);
	cqm_info(handle->dev_hdl, "Cap init: taskmap_number 0x%x, l3i_number 0x%x\n",
		 cqm_handle->func_capability.taskmap_number,
		 cqm_handle->func_capability.l3i_number);
	cqm_info(handle->dev_hdl, "Cap init: timer_number 0x%x\n",
		 cqm_handle->func_capability.timer_number);
	cqm_info(handle->dev_hdl, "Cap init: xid2cid_number 0x%x, reorder_number 0x%x\n",
		 cqm_handle->func_capability.xid2cid_number,
		 cqm_handle->func_capability.reorder_number);

	return CQM_SUCCESS;

out:
	if (cqm_handle->func_attribute.func_type == CQM_PPF)
		cqm_handle->func_capability.timer_enable = 0;

	return err;
}

/**
 * cqm_init - Initialize cqm
 * @ex_handle: handle of hwdev
 */
s32 cqm_init(void *ex_handle)
{
	struct hifc_hwdev *handle = (struct hifc_hwdev *)ex_handle;
	struct cqm_handle_s *cqm_handle = NULL;
	s32 ret = CQM_FAIL;

	CQM_PTR_CHECK_RET(ex_handle, return CQM_FAIL, CQM_PTR_NULL(ex_handle));

	cqm_handle = (struct cqm_handle_s *)kmalloc(sizeof(struct cqm_handle_s),
						    GFP_KERNEL | __GFP_ZERO);
	CQM_PTR_CHECK_RET(cqm_handle, return CQM_FAIL,
			  CQM_ALLOC_FAIL(cqm_handle));
	/* Clear memory to prevent other systems' memory from being cleared */
	memset(cqm_handle, 0, sizeof(struct cqm_handle_s));

	cqm_handle->ex_handle = handle;
	cqm_handle->dev = (struct pci_dev *)(handle->pcidev_hdl);

	handle->cqm_hdl = (void *)cqm_handle;

	/* Clear statistics */
	memset(&handle->hw_stats.cqm_stats, 0, sizeof(struct hifc_cqm_stats));

	/* Read information of vf or pf */
	cqm_handle->func_attribute = handle->hwif->attr;
	cqm_info(handle->dev_hdl, "Func init: function type %d\n",
		 cqm_handle->func_attribute.func_type);

	/* Read ability from configuration management module */
	ret = cqm_capability_init(ex_handle);
	if (ret == CQM_FAIL) {
		cqm_err(handle->dev_hdl,
			CQM_FUNCTION_FAIL(cqm_capability_init));
		goto err1;
	}

	/* Initialize entries of memory table such as BAT/CLA/bitmap */
	if (cqm_mem_init(ex_handle) != CQM_SUCCESS) {
		cqm_err(handle->dev_hdl, CQM_FUNCTION_FAIL(cqm_mem_init));
		goto err1;
	}

	/* Initialize event callback */
	if (cqm_event_init(ex_handle) != CQM_SUCCESS) {
		cqm_err(handle->dev_hdl, CQM_FUNCTION_FAIL(cqm_event_init));
		goto err2;
	}

	/* Initialize doorbell */
	if (cqm_db_init(ex_handle) != CQM_SUCCESS) {
		cqm_err(handle->dev_hdl, CQM_FUNCTION_FAIL(cqm_db_init));
		goto err3;
	}

	/* The timer bitmap is set directly from the beginning through CQM,
	 * no longer set/clear the bitmap through ifconfig up/down
	 */
	if (hifc_func_tmr_bitmap_set(ex_handle, 1) != CQM_SUCCESS) {
		cqm_err(handle->dev_hdl, "Timer start: enable timer bitmap failed\n");
		goto err5;
	}

	return CQM_SUCCESS;

err5:
	cqm_db_uninit(ex_handle);
err3:
	cqm_event_uninit(ex_handle);
err2:
	cqm_mem_uninit(ex_handle);
err1:
	handle->cqm_hdl = NULL;
	kfree(cqm_handle);
	return CQM_FAIL;
}

/**
 * cqm_uninit - Deinitialize the cqm, and is called once removing a function
 * @ex_handle: handle of hwdev
 */
void cqm_uninit(void *ex_handle)
{
	struct hifc_hwdev *handle = (struct hifc_hwdev *)ex_handle;
	struct cqm_handle_s *cqm_handle = NULL;
	s32 ret = CQM_FAIL;

	CQM_PTR_CHECK_NO_RET(ex_handle, CQM_PTR_NULL(ex_handle), return);

	cqm_handle = (struct cqm_handle_s *)(handle->cqm_hdl);
	CQM_PTR_CHECK_NO_RET(cqm_handle, CQM_PTR_NULL(cqm_handle), return);

	/* The timer bitmap is set directly from the beginning through CQM,
	 * no longer set/clear the bitmap through ifconfig up/down
	 */
	cqm_info(handle->dev_hdl, "Timer stop: disable timer\n");
	if (hifc_func_tmr_bitmap_set(ex_handle, 0) != CQM_SUCCESS)
		cqm_err(handle->dev_hdl, "Timer stop: disable timer bitmap failed\n");

	/* Stopping timer, release the resource
	 * after a delay of one or two milliseconds
	 */
	if ((cqm_handle->func_attribute.func_type == CQM_PPF) &&
	    (cqm_handle->func_capability.timer_enable == CQM_TIMER_ENABLE)) {
		cqm_info(handle->dev_hdl, "Timer stop: hifc ppf timer stop\n");
		ret = hifc_ppf_tmr_stop(handle);

		if (ret != CQM_SUCCESS) {
			cqm_info(handle->dev_hdl, "Timer stop: hifc ppf timer stop, ret=%d\n",
				 ret);
			/* The timer fails to stop
			 * and does not affect resource release
			 */
		}
		usleep_range(900, 1000);
	}

	/* Release hardware doorbell */
	cqm_db_uninit(ex_handle);

	/* Cancel the callback of chipif */
	cqm_event_uninit(ex_handle);

	/* Release all table items
	 * and require the service to release all objects
	 */
	cqm_mem_uninit(ex_handle);

	/* Release cqm_handle */
	handle->cqm_hdl = NULL;
	kfree(cqm_handle);
}

/**
 * cqm_mem_init - Initialize related memory of cqm,
 * including all levels of entries
 * @ex_handle: handle of hwdev
 */
s32 cqm_mem_init(void *ex_handle)
{
	struct hifc_hwdev *handle = (struct hifc_hwdev *)ex_handle;
	struct cqm_handle_s *cqm_handle = NULL;

	cqm_handle = (struct cqm_handle_s *)(handle->cqm_hdl);

	if (cqm_bat_init(cqm_handle) != CQM_SUCCESS) {
		cqm_err(handle->dev_hdl, CQM_FUNCTION_FAIL(cqm_bat_init));
		return CQM_FAIL;
	}

	if (cqm_cla_init(cqm_handle) != CQM_SUCCESS) {
		cqm_err(handle->dev_hdl, CQM_FUNCTION_FAIL(cqm_cla_init));
		goto err1;
	}

	if (cqm_bitmap_init(cqm_handle) != CQM_SUCCESS) {
		cqm_err(handle->dev_hdl, CQM_FUNCTION_FAIL(cqm_bitmap_init));
		goto err2;
	}

	if (cqm_object_table_init(cqm_handle) != CQM_SUCCESS) {
		cqm_err(handle->dev_hdl,
			CQM_FUNCTION_FAIL(cqm_object_table_init));
		goto err3;
	}

	return CQM_SUCCESS;

err3:
	cqm_bitmap_uninit(cqm_handle);
err2:
	cqm_cla_uninit(cqm_handle);
err1:
	cqm_bat_uninit(cqm_handle);
	return CQM_FAIL;
}

/**
 * cqm_mem_uninit - Deinitialize related memory of cqm,
 * including all levels of entries
 * @ex_handle: handle of hwdev
 */
void cqm_mem_uninit(void *ex_handle)
{
	struct hifc_hwdev *handle = (struct hifc_hwdev *)ex_handle;
	struct cqm_handle_s *cqm_handle = NULL;

	cqm_handle = (struct cqm_handle_s *)(handle->cqm_hdl);

	cqm_object_table_uninit(cqm_handle);
	cqm_bitmap_uninit(cqm_handle);
	cqm_cla_uninit(cqm_handle);
	cqm_bat_uninit(cqm_handle);
}

/**
 * cqm_event_init - Initialize the event callback of cqm
 * @ex_handle: handle of hwdev
 */
s32 cqm_event_init(void *ex_handle)
{
	struct hifc_hwdev *handle = (struct hifc_hwdev *)ex_handle;

	/* Register ceq and aeq callbacks with chipif */
	if (hifc_aeq_register_swe_cb(ex_handle,
				     HIFC_STATEFULL_EVENT,
				     cqm_aeq_callback) != CHIPIF_SUCCESS) {
		cqm_err(handle->dev_hdl, "Event: fail to register aeq callback\n");
		return CQM_FAIL;
	}

	return CQM_SUCCESS;
}

/**
 * cqm_event_uninit - Deinitialize the event callback of cqm
 * @ex_handle: handle of hwdev
 */
void cqm_event_uninit(void *ex_handle)
{
	(void)hifc_aeq_unregister_swe_cb(ex_handle, HIFC_STATEFULL_EVENT);
}

/**
 * cqm_db_addr_alloc - Apply for a page of hardware doorbell and dwqe,
 * with the same index, all obtained are physical addresses
 * each function has up to 1K
 * @ex_handle: handle of hwdev
 * @db_addr: the address of doorbell
 * @dwqe_addr: the address of dwqe
 */
s32 cqm_db_addr_alloc(void *ex_handle, void __iomem **db_addr,
		      void __iomem **dwqe_addr)
{
	struct hifc_hwdev *handle = (struct hifc_hwdev *)ex_handle;

	CQM_PTR_CHECK_RET(ex_handle, return CQM_FAIL, CQM_PTR_NULL(ex_handle));
	CQM_PTR_CHECK_RET(db_addr, return CQM_FAIL, CQM_PTR_NULL(db_addr));
	CQM_PTR_CHECK_RET(dwqe_addr, return CQM_FAIL, CQM_PTR_NULL(dwqe_addr));

	atomic_inc(&handle->hw_stats.cqm_stats.cqm_db_addr_alloc_cnt);

	return hifc_alloc_db_addr(ex_handle, db_addr, dwqe_addr);
}

/**
 * cqm_db_init - Initialize doorbell of cqm
 * @ex_handle: handle of hwdev
 */
s32 cqm_db_init(void *ex_handle)
{
	struct hifc_hwdev *handle = (struct hifc_hwdev *)ex_handle;
	struct cqm_handle_s *cqm_handle = NULL;
	struct cqm_service_s *service = NULL;

	cqm_handle = (struct cqm_handle_s *)(handle->cqm_hdl);

	/* Assign hardware doorbell for service */
	service = &cqm_handle->service;

	if (cqm_db_addr_alloc(ex_handle,
			      &service->hardware_db_vaddr,
			      &service->dwqe_vaddr) != CQM_SUCCESS) {
		cqm_err(handle->dev_hdl, CQM_FUNCTION_FAIL(cqm_db_addr_alloc));
		return CQM_FAIL;
	}

	return CQM_SUCCESS;
}

/**
 * cqm_db_addr_free - Release a page of hardware doorbell and dwqe
 * @ex_handle: handle of hwdev
 * @db_addr: the address of doorbell
 * @dwqe_addr: the address of dwqe
 */
void cqm_db_addr_free(void *ex_handle, void __iomem *db_addr,
		      void __iomem *dwqe_addr)
{
	struct hifc_hwdev *handle = (struct hifc_hwdev *)ex_handle;

	CQM_PTR_CHECK_NO_RET(ex_handle, CQM_PTR_NULL(ex_handle), return);

	atomic_inc(&handle->hw_stats.cqm_stats.cqm_db_addr_free_cnt);

	hifc_free_db_addr(ex_handle, db_addr, dwqe_addr);
}

/**
 * cqm_db_uninit - Deinitialize doorbell of cqm
 * @ex_handle: handle of hwdev
 */
void cqm_db_uninit(void *ex_handle)
{
	struct hifc_hwdev *handle = (struct hifc_hwdev *)ex_handle;
	struct cqm_handle_s *cqm_handle = NULL;
	struct cqm_service_s *service = NULL;

	cqm_handle = (struct cqm_handle_s *)(handle->cqm_hdl);

	/* Release hardware doorbell */
	service = &cqm_handle->service;

	cqm_db_addr_free(ex_handle, service->hardware_db_vaddr,
			 service->dwqe_vaddr);
}

/**
 * cqm_aeq_callback - cqm module callback processing of aeq
 * @ex_handle: handle of hwdev
 * @event: the input type of event
 * @data: the input data
 */
u8 cqm_aeq_callback(void *ex_handle, u8 event, u64 data)
{
#define CQM_AEQ_BASE_T_FC 48
#define CQM_AEQ_BASE_T_FCOE  56
	struct hifc_hwdev *handle = (struct hifc_hwdev *)ex_handle;
	struct cqm_handle_s *cqm_handle = NULL;
	struct cqm_service_s *service = NULL;
	struct service_register_template_s *service_template = NULL;
	u8 event_level = FAULT_LEVEL_MAX;

	CQM_PTR_CHECK_RET(ex_handle, return event_level,
			  CQM_PTR_NULL(ex_handle));

	atomic_inc(&handle->hw_stats.cqm_stats.cqm_aeq_callback_cnt[event]);

	cqm_handle = (struct cqm_handle_s *)(handle->cqm_hdl);
	CQM_PTR_CHECK_RET(cqm_handle, return event_level,
			  CQM_PTR_NULL(cqm_handle));

	if (event >= (u8)CQM_AEQ_BASE_T_FC &&
	    (event < (u8)CQM_AEQ_BASE_T_FCOE)) {
		service = &cqm_handle->service;
		service_template = &service->service_template;

		if (!service_template->aeq_callback) {
			cqm_err(handle->dev_hdl, "Event: service aeq_callback unregistered\n");
		} else {
			service_template->aeq_callback(
				service_template->service_handle, event, data);
		}

		return event_level;
	}

	cqm_err(handle->dev_hdl, CQM_WRONG_VALUE(event));
	return CQM_FAIL;
}

/**
 * cqm_service_register - Service driver registers callback template with cqm
 * @ex_handle: handle of hwdev
 * @service_template: the template of service registration
 */
s32 cqm_service_register(void *ex_handle,
			 struct service_register_template_s *service_template)
{
	struct hifc_hwdev *handle = (struct hifc_hwdev *)ex_handle;
	struct cqm_handle_s *cqm_handle = NULL;
	struct cqm_service_s *service = NULL;

	CQM_PTR_CHECK_RET(ex_handle, return CQM_FAIL, CQM_PTR_NULL(ex_handle));

	cqm_handle = (struct cqm_handle_s *)(handle->cqm_hdl);
	CQM_PTR_CHECK_RET(cqm_handle, return CQM_FAIL,
			  CQM_PTR_NULL(cqm_handle));
	CQM_PTR_CHECK_RET(service_template, return CQM_FAIL,
			  CQM_PTR_NULL(service_template));

	service = &cqm_handle->service;

	if (service->has_register == true) {
		cqm_err(handle->dev_hdl, "Service register: service has registered\n");
		return CQM_FAIL;
	}

	service->has_register = true;
	(void)memcpy((void *)(&service->service_template),
		     (void *)service_template,
		     sizeof(struct service_register_template_s));

	return CQM_SUCCESS;
}

/**
 * cqm_service_unregister - Service-driven cancellation to CQM
 * @ex_handle: handle of hwdev
 * @service_type: the type of service module
 */
void cqm_service_unregister(void *ex_handle)
{
	struct hifc_hwdev *handle = (struct hifc_hwdev *)ex_handle;
	struct cqm_handle_s *cqm_handle = NULL;
	struct cqm_service_s *service = NULL;

	CQM_PTR_CHECK_NO_RET(ex_handle, CQM_PTR_NULL(ex_handle), return);

	cqm_handle = (struct cqm_handle_s *)(handle->cqm_hdl);
	CQM_PTR_CHECK_NO_RET(cqm_handle, CQM_PTR_NULL(cqm_handle), return);

	service = &cqm_handle->service;

	service->has_register = false;
	memset(&service->service_template, 0,
	       sizeof(struct service_register_template_s));
}

/**
 * cqm_cmd_alloc - Apply for a cmd buffer, the buffer size is fixed at 2K,
 * the buffer content is not cleared, but the service needs to be cleared
 * @ex_handle: handle of hwdev
 */
struct cqm_cmd_buf_s *cqm_cmd_alloc(void *ex_handle)
{
	struct hifc_hwdev *handle = (struct hifc_hwdev *)ex_handle;

	CQM_PTR_CHECK_RET(ex_handle, return NULL, CQM_PTR_NULL(ex_handle));

	atomic_inc(&handle->hw_stats.cqm_stats.cqm_cmd_alloc_cnt);

	return (struct cqm_cmd_buf_s *)hifc_alloc_cmd_buf(ex_handle);
}

/**
 * cqm_cmd_free - Free a cmd buffer
 * @ex_handle: handle of hwdev
 * @cmd_buf: the cmd buffer which needs freeing memory for
 */
void cqm_cmd_free(void *ex_handle, struct cqm_cmd_buf_s *cmd_buf)
{
	struct hifc_hwdev *handle = (struct hifc_hwdev *)ex_handle;

	CQM_PTR_CHECK_NO_RET(ex_handle, CQM_PTR_NULL(ex_handle), return);
	CQM_PTR_CHECK_NO_RET(cmd_buf, CQM_PTR_NULL(cmd_buf), return);
	CQM_PTR_CHECK_NO_RET(cmd_buf->buf, CQM_PTR_NULL(buf), return);

	atomic_inc(&handle->hw_stats.cqm_stats.cqm_cmd_free_cnt);

	hifc_free_cmd_buf(ex_handle, (struct hifc_cmd_buf *)cmd_buf);
}

/**
 * cqm_send_cmd_box - Send a cmd in box mode,
 * the interface will hang the completed amount, causing sleep
 * @ex_handle: handle of hwdev
 * @ack_type: the type of ack
 * @mod: the mode of cqm send
 * @cmd: the input cmd
 * @buf_in: the input buffer of cqm_cmd
 * @buf_out: the output buffer of cqm_cmd
 * @timeout: exceeding the time limit will cause sleep
 */
s32 cqm_send_cmd_box(void *ex_handle, u8 ack_type, u8 mod, u8 cmd,
		     struct cqm_cmd_buf_s *buf_in,
		     struct cqm_cmd_buf_s *buf_out, u32 timeout)
{
	struct hifc_hwdev *handle = (struct hifc_hwdev *)ex_handle;

	CQM_PTR_CHECK_RET(ex_handle, return CQM_FAIL, CQM_PTR_NULL(ex_handle));
	CQM_PTR_CHECK_RET(buf_in, return CQM_FAIL, CQM_PTR_NULL(buf_in));
	CQM_PTR_CHECK_RET(buf_in->buf, return CQM_FAIL, CQM_PTR_NULL(buf));

	atomic_inc(&handle->hw_stats.cqm_stats.cqm_send_cmd_box_cnt);

	return hifc_cmdq_detail_resp(ex_handle, ack_type, mod, cmd,
				     (struct hifc_cmd_buf *)buf_in,
				     (struct hifc_cmd_buf *)buf_out, timeout);
}

/**
 * cqm_ring_hardware_db - Knock hardware doorbell
 * @ex_handle: handle of hwdev
 * @service_type: each kernel mode will be allocated a page of hardware doorbell
 * @db_count: PI exceeding 64b in doorbell[7:0]
 * @db: doorbell content, organized by the business,
 * if there is a small-end conversion, the business needs to be completed
 */
s32 cqm_ring_hardware_db(void *ex_handle, u32 service_type, u8 db_count, u64 db)
{
	struct hifc_hwdev *handle;
	struct cqm_handle_s *cqm_handle;
	struct cqm_service_s *service;

	handle = (struct hifc_hwdev *)ex_handle;
	cqm_handle = (struct cqm_handle_s *)(handle->cqm_hdl);
	service = &cqm_handle->service;

	/* Write all before the doorbell */
	wmb();
	*((u64 *)service->hardware_db_vaddr + db_count) = db;

	return CQM_SUCCESS;
}
