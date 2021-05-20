// SPDX-License-Identifier: GPL-2.0
/* Huawei Hifc PCI Express Linux driver
 * Copyright(c) 2017 Huawei Technologies Co., Ltd
 *
 */

#include <linux/types.h>
#include <linux/sched.h>
#include <linux/pci.h>
#include <linux/module.h>
#include <linux/vmalloc.h>
#include <linux/device.h>
#include <linux/gfp.h>
#include <linux/mm.h>

#include "hifc_knl_adp.h"
#include "hifc_hw.h"
#include "hifc_hwdev.h"
#include "hifc_hwif.h"
#include "hifc_api_cmd.h"
#include "hifc_mgmt.h"
#include "hifc_cfg.h"
#include "hifc_cqm_object.h"
#include "hifc_cqm_main.h"
#define common_section

#define CQM_MOD_CQM  8
#define CQM_HARDWARE_DOORBELL 1
/**
 * cqm_swab64 - Convert a memory block to another endian by 8 byte basis
 * @addr: start address of the memory block
 * @cnt: the number of 8 byte basis in the memory block
 */
void cqm_swab64(u8 *addr, u32 cnt)
{
	u32 i = 0;
	u64 *temp = (u64 *)addr;
	u64 value = 0;

	for (i = 0; i < cnt; i++) {
		value = __swab64(*temp);
		*temp = value;
		temp++;
	}
}

/**
 * cqm_swab32 - Convert a memory block to another endian by 4 byte basis
 * @addr: start address of the memory block
 * @cnt: the number of 4 byte basis in the memory block
 */
void cqm_swab32(u8 *addr, u32 cnt)
{
	u32 i = 0;
	u32 *temp = (u32 *)addr;
	u32 value = 0;

	for (i = 0; i < cnt; i++) {
		value = __swab32(*temp);
		*temp = value;
		temp++;
	}
}

/**
 * cqm_shift - Find the base logarithm of two
 * @data: the input data
 */
s32 cqm_shift(u32 data)
{
	s32 shift = -1;

	do {
		data >>= 1;
		shift++;
	} while (data);

	return shift;
}

/**
 * cqm_check_align - Check whether the data is aligned as the base of 2^n
 * @data: the input data
 */
bool cqm_check_align(u32 data)
{
	if (data == 0)
		return false;

	do {
		/* If data can be divided exactly by 2,
		 * it right shifts one bit
		 */
		if ((data & 0x1) == 0) {
			data >>= 1;
		} else {
		/* If data can not be divided exactly by 2
		 * it is not the base of 2^n,return false
		 */
			return false;
		}
	} while (data != 1);

	return true;
}

/**
 * cqm_kmalloc_align - Alloc memory whose start address is aligned as the basis
 * of 2^n
 * @size: the size of memory allocated
 * @flags: the type of memory allocated
 * @align_order: the basis for aligning
 */
static void *cqm_kmalloc_align(size_t size, gfp_t flags, u16 align_order)
{
	void *orig_addr = NULL;
	void *align_addr = NULL;
	void *index_addr = NULL;

	orig_addr = kmalloc(size + ((u64)1 << align_order) + sizeof(void *),
			    flags);
	if (!orig_addr)
		return NULL;

	index_addr = (void *)((char *)orig_addr + sizeof(void *));
	align_addr = (void *)((((u64)index_addr +
		((u64)1 << align_order) - 1) >> align_order) << align_order);

	/* Record the original memory address for memory release. */
	index_addr = (void *)((char *)align_addr - sizeof(void *));
	*(void **)index_addr = orig_addr;

	cqm_dbg("allocate %lu bytes aligned address: %p, original address: %p\n",
		size, align_addr, orig_addr);

	return align_addr;
}

/**
 * cqm_kfree_align - Free memory whose start address is aligned as the basis of
 * 2^n
 * @addr: aligned address which would be free
 */
static void cqm_kfree_align(void *addr)
{
	void *index_addr = NULL;

	/* Release original memory address */
	index_addr = (void *)((char *)addr - sizeof(void *));

	cqm_dbg("free aligned address: %p, original address: %p\n",
		addr, *(void **)index_addr);

	kfree(*(void **)index_addr);
}

/**
 * cqm_buf_alloc_page - Alloc total pages memory for buffers
 * @cqm_handle: handle of cqm
 * @buf: the buffer which needs allocating memory for
 */
s32 cqm_buf_alloc_page(struct cqm_handle_s *cqm_handle, struct cqm_buf_s *buf)
{
	struct hifc_hwdev *handle = cqm_handle->ex_handle;
	u32 order = 0;
	void *va = NULL;
	s32 i = 0;

	order = get_order(buf->buf_size);

	/*Here to allocate for every buffer's page for non-ovs*/
	for (i = 0; i < (s32)buf->buf_number; i++) {
		va = (void *)__get_free_pages(GFP_KERNEL | __GFP_ZERO, order);
		if (!va) {
			cqm_err(handle->dev_hdl, CQM_ALLOC_FAIL(buf_page));
			break;
		}
		/* Pages should be initialized to 0 after applied
		 * especially related to the hash table
		 */
		memset(va, 0, buf->buf_size);
		buf->buf_list[i].va = va;
	}

	if (i != buf->buf_number) {
		i--;
		for (; i >= 0; i--) {
			free_pages((ulong)(buf->buf_list[i].va), order);
			buf->buf_list[i].va = NULL;
		}
		return CQM_FAIL;
	}

	return CQM_SUCCESS;
}

/**
 * cqm_buf_alloc_map - Buffer pci mapping
 * @cqm_handle: handle of cqm
 * @buf: the buffer which needs map
 */
s32 cqm_buf_alloc_map(struct cqm_handle_s *cqm_handle, struct cqm_buf_s *buf)
{
	struct hifc_hwdev *handle = cqm_handle->ex_handle;
	struct pci_dev *dev = cqm_handle->dev;
	s32 i = 0;
	void *va = NULL;

	for (i = 0; i < (s32)buf->buf_number; i++) {
		va = buf->buf_list[i].va;
		buf->buf_list[i].pa =
			pci_map_single(dev, va, buf->buf_size,
				       PCI_DMA_BIDIRECTIONAL);
		if (pci_dma_mapping_error(dev, buf->buf_list[i].pa)) {
			cqm_err(handle->dev_hdl, CQM_MAP_FAIL(buf_list));
			break;
		}
	}

	if (i != buf->buf_number) {
		i--;
		for (; i >= 0; i--) {
			pci_unmap_single(dev, buf->buf_list[i].pa,
					 buf->buf_size, PCI_DMA_BIDIRECTIONAL);
		}
		return CQM_FAIL;
	}

	return CQM_SUCCESS;
}

/**
 * cqm_buf_alloc_direct - Buffer pci direct remapping
 * @cqm_handle: handle of cqm
 * @buf: the buffer which needs remap
 */
s32 cqm_buf_alloc_direct(struct cqm_handle_s *cqm_handle,
			 struct cqm_buf_s *buf, bool direct)
{
	struct hifc_hwdev *handle = cqm_handle->ex_handle;
	struct page **pages = NULL;
	u32 order = 0;
	u32 i = 0;
	u32 j = 0;

	order = get_order(buf->buf_size);

	if (direct == true) {
		pages = (struct page **)
			vmalloc(sizeof(struct page *) * buf->page_number);
		if (!pages) {
			cqm_err(handle->dev_hdl, CQM_ALLOC_FAIL(pages));
			return CQM_FAIL;
		}

		for (i = 0; i < buf->buf_number; i++) {
			for (j = 0; j < ((u32)1 << order); j++) {
				pages[(i << order) + j] = (struct page *)
					(void *)virt_to_page(
						(u8 *)(buf->buf_list[i].va) +
						(PAGE_SIZE * j));
			}
		}

		/*lint -save -e648
		 *Shield alarm for kernel functions' vmapping
		 */
		buf->direct.va = vmap(pages, buf->page_number,
				      VM_MAP, PAGE_KERNEL);
		/*lint -restore*/
		vfree(pages);
		if (!buf->direct.va) {
			cqm_err(handle->dev_hdl, CQM_MAP_FAIL(buf->direct.va));
			return CQM_FAIL;
		}
	} else {
		buf->direct.va = NULL;
	}

	return CQM_SUCCESS;
}

/**
 * cqm_buf_alloc - Allocate for buffer and dma for the struct cqm_buf_s
 * @cqm_handle: handle of cqm
 * @buf: the buffer which needs allocating memory for and dma
 */
s32 cqm_buf_alloc(struct cqm_handle_s *cqm_handle,
		  struct cqm_buf_s *buf, bool direct)
{
	struct hifc_hwdev *handle = cqm_handle->ex_handle;
	struct pci_dev *dev = cqm_handle->dev;
	u32 order = 0;
	s32 i = 0;

	order = get_order(buf->buf_size);

	/* Allocate for the descriptor space of buffer lists */
	buf->buf_list = (struct cqm_buf_list_s *)
			vmalloc(buf->buf_number *
			sizeof(struct cqm_buf_list_s));

	CQM_PTR_CHECK_RET(buf->buf_list, return CQM_FAIL,
			  CQM_ALLOC_FAIL(buf_list));
	memset(buf->buf_list, 0,
	       buf->buf_number * sizeof(struct cqm_buf_list_s));

	/* Allocate for every buffer's page */
	if (cqm_buf_alloc_page(cqm_handle, buf) == CQM_FAIL) {
		cqm_err(handle->dev_hdl, CQM_FUNCTION_FAIL(cqm_buf_alloc_page));
		goto err1;
	}

	/* Buffer pci remapping */
	if (cqm_buf_alloc_map(cqm_handle, buf) == CQM_FAIL) {
		cqm_err(handle->dev_hdl, CQM_FUNCTION_FAIL(cqm_buf_alloc_map));
		goto err2;
	}

	/* Buffer pci mapping */
	if (cqm_buf_alloc_direct(cqm_handle, buf, direct) == CQM_FAIL) {
		cqm_err(handle->dev_hdl,
			CQM_FUNCTION_FAIL(cqm_buf_alloc_direct));
		goto err3;
	}

	return CQM_SUCCESS;

err3:
	for (i = 0; i < (s32)buf->buf_number; i++) {
		pci_unmap_single(dev, buf->buf_list[i].pa, buf->buf_size,
				 PCI_DMA_BIDIRECTIONAL);
	}
err2:
	for (i = 0; i < (s32)buf->buf_number; i++) {
		free_pages((ulong)(buf->buf_list[i].va), order);
		buf->buf_list[i].va = NULL;
	}
err1:
	vfree(buf->buf_list);
	buf->buf_list = NULL;
	return CQM_FAIL;
}

/**
 * cqm_cla_cache_invalid - Set the chip logical address cache invalid
 * @cqm_handle: handle of cqm
 * @gpa: global physical address
 * @cache_size: chip cache size
 */
s32 cqm_cla_cache_invalid(struct cqm_handle_s *cqm_handle, dma_addr_t gpa,
			  u32 cache_size)
{
	struct hifc_hwdev *handle = cqm_handle->ex_handle;
	struct cqm_cmd_buf_s *buf_in = NULL;
	struct cqm_cla_cache_invalid_cmd_s *cmd = NULL;
	s32 ret = CQM_FAIL;

	buf_in = cqm_cmd_alloc((void *)(cqm_handle->ex_handle));
	CQM_PTR_CHECK_RET(buf_in, return CQM_FAIL,
			  CQM_ALLOC_FAIL(buf_in));
	buf_in->size = sizeof(struct cqm_cla_cache_invalid_cmd_s);

	/* Fill command format, and turn into big endian */
	cmd = (struct cqm_cla_cache_invalid_cmd_s *)(buf_in->buf);
	cmd->cache_size = cache_size;
	cmd->gpa_h = CQM_ADDR_HI(gpa);
	cmd->gpa_l = CQM_ADDR_LW(gpa);

	cqm_swab32((u8 *)cmd,
		   (sizeof(struct cqm_cla_cache_invalid_cmd_s) >> 2));

	/* cmdq send a cmd */
	ret = cqm_send_cmd_box((void *)(cqm_handle->ex_handle),
			       CQM_CMD_ACK_TYPE_CMDQ,
			       CQM_MOD_CQM, CQM_CMD_T_CLA_CACHE_INVALID,
			       buf_in, NULL, CQM_CMD_TIMEOUT);
	if (ret != CQM_SUCCESS) {
		cqm_err(handle->dev_hdl, CQM_FUNCTION_FAIL(cqm_send_cmd_box));
		cqm_err(handle->dev_hdl, "Cla cache invalid: cqm_send_cmd_box_ret=%d\n",
			ret);
		cqm_err(handle->dev_hdl, "Cla cache invalid: cla_cache_invalid_cmd: 0x%x 0x%x 0x%x\n",
			cmd->gpa_h, cmd->gpa_l, cmd->cache_size);
	}

	cqm_cmd_free((void *)(cqm_handle->ex_handle), buf_in);
	return ret;
}

/**
 * cqm_buf_free - Free buffer space and dma for the struct cqm_buf_s
 * @buf: the buffer which needs freeing memory for
 * @dev: specific pci device
 */
void cqm_buf_free(struct cqm_buf_s *buf, struct pci_dev *dev)
{
	u32 order = 0;
	s32 i = 0;

	order = get_order(buf->buf_size);

	if (buf->direct.va) {
		vunmap(buf->direct.va);
		buf->direct.va = NULL;
	}

	if (buf->buf_list) {
		for (i = 0; i < (s32)(buf->buf_number); i++) {
			if (buf->buf_list[i].va) {
				pci_unmap_single(dev, buf->buf_list[i].pa,
						 buf->buf_size,
						 PCI_DMA_BIDIRECTIONAL);
				free_pages((ulong)(buf->buf_list[i].va), order);
				buf->buf_list[i].va = NULL;
			}
		}

		vfree(buf->buf_list);
		buf->buf_list = NULL;
	}
}

/**
 * __free_cache_inv - Free cache and make buffer list invalid
 * @cqm_handle: handle of cqm
 * @buf: the buffer which needs freeing memory for
 * @inv_flag: invalid or not
 * @order:the basis for aligning
 * @buf_idx:buffer index
 */
static void __free_cache_inv(struct cqm_handle_s *cqm_handle,
			     struct cqm_buf_s *buf, s32 *inv_flag,
			     u32 order, s32 buf_idx)
{
	struct hifc_hwdev *handle = cqm_handle->ex_handle;

	if (handle->chip_present_flag) {
		*inv_flag = cqm_cla_cache_invalid(cqm_handle,
						  buf->buf_list[buf_idx].pa,
						  PAGE_SIZE << order);
		if (*inv_flag != CQM_SUCCESS) {
			cqm_err(handle->dev_hdl, "Buffer free: fail to invalid buf_list pa cache, inv_flag=%d\n",
				*inv_flag);
		}
	}

	pci_unmap_single(cqm_handle->dev, buf->buf_list[buf_idx].pa,
			 buf->buf_size, PCI_DMA_BIDIRECTIONAL);

	free_pages((unsigned long)(buf->buf_list[buf_idx].va), order);

	buf->buf_list[buf_idx].va = NULL;
}

/**
 * cqm_buf_free_cache_inv - Free cache and make buffer list invalid
 * @cqm_handle: handle of cqm
 * @buf: the buffer which needs freeing memory for
 * @inv_flag: invalid or not
 */
void cqm_buf_free_cache_inv(struct cqm_handle_s *cqm_handle,
			    struct cqm_buf_s *buf, s32 *inv_flag)
{
	u32 order = 0;
	s32 i = 0;

	order = get_order(buf->buf_size);

	if (buf->direct.va) {
		vunmap(buf->direct.va);
		buf->direct.va = NULL;
	}

	if (buf->buf_list) {
		for (i = 0; i < (s32)(buf->buf_number); i++) {
			if (buf->buf_list[i].va) {
				__free_cache_inv(cqm_handle, buf,
						 inv_flag, order, i);
			}
		}

		vfree(buf->buf_list);
		buf->buf_list = NULL;
	}
}

#define bat_cla_section

/**
 * cqm_bat_update - Send cmds to the tile to update the BAT table through cmdq
 * @cqm_handle: cqm handle
 * Return: 0 - success, negative - failure
 */
s32 cqm_bat_update(struct cqm_handle_s *cqm_handle)
{
	struct hifc_hwdev *handle = cqm_handle->ex_handle;
	struct cqm_cmd_buf_s *buf_in = NULL;
	s32 ret = CQM_FAIL;
	struct cqm_bat_update_cmd_s *bat_update_cmd = NULL;

	/* Allocate a cmd and fill */
	buf_in = cqm_cmd_alloc((void *)(cqm_handle->ex_handle));
	CQM_PTR_CHECK_RET(buf_in, return CQM_FAIL, CQM_ALLOC_FAIL(buf_in));
	buf_in->size = sizeof(struct cqm_bat_update_cmd_s);

	bat_update_cmd = (struct cqm_bat_update_cmd_s *)(buf_in->buf);
	bat_update_cmd->byte_len = cqm_handle->bat_table.bat_size;
	bat_update_cmd->offset = 0;
	memcpy(bat_update_cmd->data, cqm_handle->bat_table.bat,
	       bat_update_cmd->byte_len);

	/*Big endian conversion*/
	cqm_swab32((u8 *)bat_update_cmd,
		   sizeof(struct cqm_bat_update_cmd_s) >> 2);

	/* send a cmd */
	ret = cqm_send_cmd_box((void *)(cqm_handle->ex_handle),
			       CQM_CMD_ACK_TYPE_CMDQ, CQM_MOD_CQM,
			       CQM_CMD_T_BAT_UPDATE, buf_in,
			       NULL, CQM_CMD_TIMEOUT);
	if (ret != CQM_SUCCESS) {
		cqm_err(handle->dev_hdl, CQM_FUNCTION_FAIL(cqm_send_cmd_box));
		cqm_err(handle->dev_hdl, "Bat update: send_cmd_box ret=%d\n",
			ret);
		cqm_cmd_free((void *)(cqm_handle->ex_handle), buf_in);
		return CQM_FAIL;
	}

	/* Free a cmd */
	cqm_cmd_free((void *)(cqm_handle->ex_handle), buf_in);

	return CQM_SUCCESS;
}

s32 cqm_bat_init_ft(struct cqm_handle_s *cqm_handle,
		    struct cqm_bat_table_s *bat_table,
		    enum func_type function_type)
{
	struct hifc_hwdev *handle = cqm_handle->ex_handle;

	if (function_type == CQM_PF || function_type == CQM_PPF) {
		bat_table->bat_entry_type[0] = CQM_BAT_ENTRY_T_CFG;
		bat_table->bat_entry_type[1] = CQM_BAT_ENTRY_T_HASH;
		bat_table->bat_entry_type[2] = CQM_BAT_ENTRY_T_QPC;
		bat_table->bat_entry_type[3] = CQM_BAT_ENTRY_T_SCQC;
		bat_table->bat_entry_type[4] = CQM_BAT_ENTRY_T_LUN;
		bat_table->bat_entry_type[5] = CQM_BAT_ENTRY_T_TASKMAP;
		bat_table->bat_entry_type[6] = CQM_BAT_ENTRY_T_L3I;
		bat_table->bat_entry_type[7] = CQM_BAT_ENTRY_T_CHILDC;
		bat_table->bat_entry_type[8] = CQM_BAT_ENTRY_T_TIMER;
		bat_table->bat_entry_type[9] = CQM_BAT_ENTRY_T_XID2CID;
		bat_table->bat_entry_type[10] = CQM_BAT_ENTRY_T_REORDER;
		bat_table->bat_size = CQM_BAT_SIZE_FT_PF;
	} else {
		cqm_err(handle->dev_hdl, CQM_WRONG_VALUE(function_type));
		return CQM_FAIL;
	}

	return CQM_SUCCESS;
}

/**
 * cqm_bat_init - Initialize the BAT table, only select the items to be
 * initialized and arrange the entry order, the content of the BAT table entry
 * needs to be filled after the CLA allocation
 * @cqm_handle: cqm handle
 * Return: 0 - success, negative - failure
 */
s32 cqm_bat_init(struct cqm_handle_s *cqm_handle)
{
	struct cqm_bat_table_s *bat_table = &cqm_handle->bat_table;
	u32 i = 0;

	memset(bat_table, 0, sizeof(struct cqm_bat_table_s));

	/* Initialize the type of each bat entry */
	for (i = 0; i < CQM_BAT_ENTRY_MAX; i++)
		bat_table->bat_entry_type[i] = CQM_BAT_ENTRY_T_INVALID;

	if (cqm_bat_init_ft(cqm_handle, bat_table,
			    cqm_handle->func_attribute.func_type) == CQM_FAIL) {
		return CQM_FAIL;
	}

	return CQM_SUCCESS;
}

/**
 * cqm_bat_uninit - Deinitialize BAT table
 * @cqm_handle: cqm handle
 */
void cqm_bat_uninit(struct cqm_handle_s *cqm_handle)
{
	struct hifc_hwdev *handle = cqm_handle->ex_handle;
	struct cqm_bat_table_s *bat_table = &cqm_handle->bat_table;
	u32 i = 0;

	for (i = 0; i < CQM_BAT_ENTRY_MAX; i++)
		bat_table->bat_entry_type[i] = CQM_BAT_ENTRY_T_INVALID;

	memset(bat_table->bat, 0, CQM_BAT_ENTRY_MAX * CQM_BAT_ENTRY_SIZE);

	/* Notify the chip to refresh the BAT table */
	if (cqm_bat_update(cqm_handle) != CQM_SUCCESS)
		cqm_err(handle->dev_hdl, CQM_FUNCTION_FAIL(cqm_bat_update));
}

static void cqm_bat_config_entry_size(
			struct cqm_cla_table_s *cla_table,
			struct cqm_bat_entry_standerd_s *bat_entry_standerd)
{
	/* Except for QPC of 256/512/1024, the others are all cacheline 256B,
	 * and the conversion will be done inside the chip
	 */
	if (cla_table->obj_size > CQM_CHIP_CACHELINE) {
		if (cla_table->obj_size == 512) {
			bat_entry_standerd->entry_size = CQM_BAT_ENTRY_SIZE_512;
		} else {
			bat_entry_standerd->entry_size =
							CQM_BAT_ENTRY_SIZE_1024;
		}
		bat_entry_standerd->max_number =
			cla_table->max_buffer_size / cla_table->obj_size;
	} else {
		bat_entry_standerd->entry_size = CQM_BAT_ENTRY_SIZE_256;
		bat_entry_standerd->max_number =
			cla_table->max_buffer_size / CQM_CHIP_CACHELINE;
	}
}

void cqm_bat_fill_cla_std_entry(struct cqm_handle_s *cqm_handle,
				struct cqm_cla_table_s *cla_table,
				u8 *entry_base_addr, u32 entry_type,
				u8 gpa_check_enable)
{
	struct hifc_hwdev *handle = cqm_handle->ex_handle;
	struct cqm_bat_entry_standerd_s *bat_entry_standerd = NULL;
	dma_addr_t pa = 0;

	if (cla_table->obj_num == 0) {
		cqm_info(handle->dev_hdl, "Cla alloc: cla_type %u, obj_num=0, don't init bat entry\n",
			 cla_table->type);
		return;
	}

	bat_entry_standerd = (struct cqm_bat_entry_standerd_s *)entry_base_addr;
	cqm_bat_config_entry_size(cla_table, bat_entry_standerd);
	bat_entry_standerd->max_number =  bat_entry_standerd->max_number - 1;

	bat_entry_standerd->bypass = CQM_BAT_NO_BYPASS_CACHE;
	bat_entry_standerd->z = cla_table->cacheline_z;
	bat_entry_standerd->y = cla_table->cacheline_y;
	bat_entry_standerd->x = cla_table->cacheline_x;
	bat_entry_standerd->cla_level = cla_table->cla_lvl;

	if (cla_table->cla_lvl == CQM_CLA_LVL_0)
		pa = cla_table->cla_z_buf.buf_list[0].pa;
	else if (cla_table->cla_lvl == CQM_CLA_LVL_1)
		pa = cla_table->cla_y_buf.buf_list[0].pa;
	else
		pa = cla_table->cla_x_buf.buf_list[0].pa;

	bat_entry_standerd->cla_gpa_h = CQM_ADDR_HI(pa);
	if (entry_type == CQM_BAT_ENTRY_T_REORDER) {
		/* Reorder does not support GPA validity check */
		bat_entry_standerd->cla_gpa_l = CQM_ADDR_LW(pa);
	} else {
		/* GPA is valid when gpa[0]=1 */
		bat_entry_standerd->cla_gpa_l =
			CQM_ADDR_LW(pa) | gpa_check_enable;
	}
}

static void cqm_bat_fill_cla_cfg(struct cqm_handle_s *cqm_handle,
				 u8 *entry_base_addr)
{
	struct cqm_bat_entry_cfg_s *bat_entry_cfg =
		(struct cqm_bat_entry_cfg_s *)entry_base_addr;

	bat_entry_cfg->cur_conn_cache = 0;
	bat_entry_cfg->max_conn_cache =
		cqm_handle->func_capability.flow_table_based_conn_cache_number;
	bat_entry_cfg->cur_conn_num_h_4 = 0;
	bat_entry_cfg->cur_conn_num_l_16 = 0;
	bat_entry_cfg->max_conn_num =
		cqm_handle->func_capability.flow_table_based_conn_number;
	/* Align by 64 buckets, shift right 6 bits */
	if ((cqm_handle->func_capability.hash_number >> 6) != 0) {
		/* After shift right 6 bits, the value should - 1 for the hash
		 * value
		 */
		bat_entry_cfg->bucket_num =
			((cqm_handle->func_capability.hash_number >> 6) - 1);
	}
	if (cqm_handle->func_capability.bloomfilter_length != 0) {
		bat_entry_cfg->bloom_filter_len =
			cqm_handle->func_capability.bloomfilter_length - 1;
		bat_entry_cfg->bloom_filter_addr =
				cqm_handle->func_capability.bloomfilter_addr;
	}
}

static void cqm_bat_fill_cla_taskmap(struct cqm_handle_s *cqm_handle,
				     struct cqm_cla_table_s *cla_table,
				     u8 *entry_base_addr)
{
	struct hifc_hwdev *handle = cqm_handle->ex_handle;
	struct cqm_bat_entry_taskmap_s *bat_entry_taskmap =
			(struct cqm_bat_entry_taskmap_s *)entry_base_addr;
	if (cqm_handle->func_capability.taskmap_number != 0) {
		bat_entry_taskmap->gpa0_h =
			(u32)(cla_table->cla_z_buf.buf_list[0].pa >> 32);
		bat_entry_taskmap->gpa0_l =
			(u32)(cla_table->cla_z_buf.buf_list[0].pa & 0xffffffff);

		bat_entry_taskmap->gpa1_h =
			(u32)(cla_table->cla_z_buf.buf_list[1].pa >> 32);
		bat_entry_taskmap->gpa1_l =
			(u32)(cla_table->cla_z_buf.buf_list[1].pa & 0xffffffff);

		bat_entry_taskmap->gpa2_h =
			(u32)(cla_table->cla_z_buf.buf_list[2].pa >> 32);
		bat_entry_taskmap->gpa2_l =
			(u32)(cla_table->cla_z_buf.buf_list[2].pa & 0xffffffff);

		bat_entry_taskmap->gpa3_h =
			(u32)(cla_table->cla_z_buf.buf_list[3].pa >> 32);
		bat_entry_taskmap->gpa3_l =
			(u32)(cla_table->cla_z_buf.buf_list[3].pa & 0xffffffff);

		cqm_info(handle->dev_hdl, "Cla alloc: taskmap bat entry: 0x%x 0x%x, 0x%x 0x%x, 0x%x 0x%x, 0x%x 0x%x\n",
			 bat_entry_taskmap->gpa0_h, bat_entry_taskmap->gpa0_l,
			 bat_entry_taskmap->gpa1_h, bat_entry_taskmap->gpa1_l,
			 bat_entry_taskmap->gpa2_h, bat_entry_taskmap->gpa2_l,
			 bat_entry_taskmap->gpa3_h, bat_entry_taskmap->gpa3_l);
	}
}

/**
 * cqm_bat_fill_cla - Fill the base address of the cla table into the bat table
 * @cqm_handle: cqm handle
 */
void cqm_bat_fill_cla(struct cqm_handle_s *cqm_handle)
{
	struct cqm_bat_table_s *bat_table = &cqm_handle->bat_table;
	struct cqm_cla_table_s *cla_table = NULL;
	u32 entry_type = CQM_BAT_ENTRY_T_INVALID;
	u8 *entry_base_addr = NULL;
	u32 i = 0;
	u8 gpa_check_enable = cqm_handle->func_capability.gpa_check_enable;

	/* Fill each item according to the arranged BAT table */
	entry_base_addr = bat_table->bat;
	for (i = 0; i < CQM_BAT_ENTRY_MAX; i++) {
		entry_type = bat_table->bat_entry_type[i];
		if (entry_type == CQM_BAT_ENTRY_T_CFG) {
			cqm_bat_fill_cla_cfg(cqm_handle, entry_base_addr);
			entry_base_addr += sizeof(struct cqm_bat_entry_cfg_s);
		} else if (entry_type == CQM_BAT_ENTRY_T_TASKMAP) {
			cqm_bat_fill_cla_taskmap(cqm_handle,
						 &bat_table->entry[i],
						 entry_base_addr);
			entry_base_addr +=
					sizeof(struct cqm_bat_entry_taskmap_s);
		} else if ((entry_type == CQM_BAT_ENTRY_T_INVALID) ||
			 ((entry_type == CQM_BAT_ENTRY_T_TIMER) &&
			 (cqm_handle->func_attribute.func_type != CQM_PPF))) {
			/* When entry_type is invalid, or the timer entry under
			 * PF does not need to apply for memory and bat filling
			 */
			entry_base_addr += CQM_BAT_ENTRY_SIZE;
		} else {
			cla_table = &bat_table->entry[i];
			cqm_bat_fill_cla_std_entry(cqm_handle, cla_table,
						   entry_base_addr, entry_type,
						   gpa_check_enable);
			entry_base_addr +=
					sizeof(struct cqm_bat_entry_standerd_s);
		}
		/* Checks if entry_base_addr is out of bounds */
		if (entry_base_addr >=
		    (bat_table->bat + CQM_BAT_ENTRY_MAX * CQM_BAT_ENTRY_SIZE))
			break;
	}
}

static void cqm_cla_xyz_cacheline_lvl1(struct cqm_cla_table_s *cla_table,
				       u32 trunk_size)
{
	s32 shift = 0;

	if (cla_table->obj_size >= CQM_CHIP_CACHELINE) {
		cla_table->cacheline_z = cla_table->z;
		cla_table->cacheline_y = cla_table->y;
		cla_table->cacheline_x = cla_table->x;
	} else {
		shift = cqm_shift(trunk_size / CQM_CHIP_CACHELINE);
		cla_table->cacheline_z = shift ? (shift - 1) : (shift);
		cla_table->cacheline_y = CQM_MAX_INDEX_BIT;
		cla_table->cacheline_x = 0;
	}
}

s32 cqm_cla_xyz_lvl1(struct cqm_handle_s *cqm_handle,
		     struct cqm_cla_table_s *cla_table,
		     u32 trunk_size)
{
	struct hifc_hwdev *handle = cqm_handle->ex_handle;
	struct cqm_buf_s *cla_y_buf = NULL;
	struct cqm_buf_s *cla_z_buf = NULL;
	dma_addr_t *base = NULL;
	s32 shift = 0;
	u32 i = 0;
	s32 ret = CQM_FAIL;
	u8 gpa_check_enable = cqm_handle->func_capability.gpa_check_enable;

	if (cla_table->type == CQM_BAT_ENTRY_T_REORDER)
		gpa_check_enable = 0;

	cla_table->cla_lvl = CQM_CLA_LVL_1;

	shift = cqm_shift(trunk_size / cla_table->obj_size);
	cla_table->z = shift ? (shift - 1) : (shift);
	cla_table->y = CQM_MAX_INDEX_BIT;
	cla_table->x = 0;
	cqm_cla_xyz_cacheline_lvl1(cla_table, trunk_size);

	/* Allocate y buf space */
	cla_y_buf = &cla_table->cla_y_buf;
	cla_y_buf->buf_size = trunk_size;
	cla_y_buf->buf_number = 1;
	cla_y_buf->page_number = cla_y_buf->buf_number <<
				 cla_table->trunk_order;
	ret = cqm_buf_alloc(cqm_handle, cla_y_buf, false);

	CQM_CHECK_EQUAL_RET(handle->dev_hdl, ret, CQM_SUCCESS, return CQM_FAIL,
			    CQM_ALLOC_FAIL(lvl_1_y_buf));

	/* Allocate z buf space */
	cla_z_buf = &cla_table->cla_z_buf;
	cla_z_buf->buf_size = trunk_size;
	cla_z_buf->buf_number = ALIGN(cla_table->max_buffer_size, trunk_size) /
				trunk_size;
	cla_z_buf->page_number = cla_z_buf->buf_number <<
				 cla_table->trunk_order;
	/* Requires static allocation of all buffer space */
	if (cla_table->alloc_static == true) {
		if (cqm_buf_alloc(cqm_handle, cla_z_buf, false) == CQM_FAIL) {
			cqm_err(handle->dev_hdl, CQM_ALLOC_FAIL(lvl_1_z_buf));
			cqm_buf_free(cla_y_buf, cqm_handle->dev);
			return CQM_FAIL;
		}

		/* Fill gpa of z buf list into y buf */
		base = (dma_addr_t *)(cla_y_buf->buf_list->va);
		for (i = 0; i < cla_z_buf->buf_number; i++) {
			/*gpa[0]=1 means this GPA is valid*/
			*base = (cla_z_buf->buf_list[i].pa | gpa_check_enable);
			base++;
		}

		/* big-endian conversion */
		cqm_swab64((u8 *)(cla_y_buf->buf_list->va),
			   cla_z_buf->buf_number);
	} else {
	/* Only initialize and allocate buf list space, buffer spaces
	 * are dynamically allocated in service
	 */
		cla_z_buf->buf_list = (struct cqm_buf_list_s *)
				      vmalloc(cla_z_buf->buf_number *
				      sizeof(struct cqm_buf_list_s));

		if (!cla_z_buf->buf_list) {
			cqm_err(handle->dev_hdl, CQM_ALLOC_FAIL(lvl_1_z_buf));
			cqm_buf_free(cla_y_buf, cqm_handle->dev);
			return CQM_FAIL;
		}
		memset(cla_z_buf->buf_list, 0,
		       cla_z_buf->buf_number * sizeof(struct cqm_buf_list_s));
	}

	return CQM_SUCCESS;
}

static s32 cqm_cla_yz_lvl2_static(struct cqm_handle_s *cqm_handle,
				  struct cqm_buf_s *cla_y_buf,
				  struct cqm_buf_s *cla_z_buf,
				  u8 gpa_check_enable)
{
	struct hifc_hwdev *handle = cqm_handle->ex_handle;
	dma_addr_t *base = NULL;
	u32 i = 0;

	if (cqm_buf_alloc(cqm_handle, cla_z_buf, false) == CQM_FAIL) {
		cqm_err(handle->dev_hdl, CQM_ALLOC_FAIL(lvl_2_z_buf));
		return CQM_FAIL;
	}

	/* The virtual address of y buf is remapped for software access */
	if (cqm_buf_alloc(cqm_handle, cla_y_buf, true) == CQM_FAIL) {
		cqm_err(handle->dev_hdl, CQM_ALLOC_FAIL(lvl_2_y_buf));
		cqm_buf_free(cla_z_buf, cqm_handle->dev);
		return CQM_FAIL;
	}

	/* Fill gpa of z buf list into y buf */
	base = (dma_addr_t *)(cla_y_buf->direct.va);
	for (i = 0; i < cla_z_buf->buf_number; i++) {
		/*gpa[0]=1 means this GPA is valid*/
		*base = (cla_z_buf->buf_list[i].pa | gpa_check_enable);
		base++;
	}

	/* big-endian conversion */
	cqm_swab64((u8 *)(cla_y_buf->direct.va), cla_z_buf->buf_number);

	return CQM_SUCCESS;
}

static void cqm_cla_yz_lvl2_init_cacheline(struct cqm_cla_table_s *cla_table,
					   u32 trunk_size)
{
	s32 shift = 0;

	if (cla_table->obj_size >= CQM_CHIP_CACHELINE) {
		cla_table->cacheline_z = cla_table->z;
		cla_table->cacheline_y = cla_table->y;
		cla_table->cacheline_x = cla_table->x;
	} else {
		shift = cqm_shift(trunk_size / CQM_CHIP_CACHELINE);
		cla_table->cacheline_z = shift ? (shift - 1) : (shift);
		shift = cqm_shift(trunk_size / sizeof(dma_addr_t));
		cla_table->cacheline_y = cla_table->cacheline_z + shift;
		cla_table->cacheline_x = CQM_MAX_INDEX_BIT;
	}
}

s32 cqm_cla_xyz_lvl2(struct cqm_handle_s *cqm_handle,
		     struct cqm_cla_table_s *cla_table,
		     u32 trunk_size)
{
	struct hifc_hwdev *handle = cqm_handle->ex_handle;
	struct cqm_buf_s *cla_x_buf = NULL;
	struct cqm_buf_s *cla_y_buf = NULL;
	struct cqm_buf_s *cla_z_buf = NULL;
	dma_addr_t *base = NULL;
	s32 shift = 0;
	u32 i = 0;
	s32 ret = CQM_FAIL;
	u8 gpa_check_enable = cqm_handle->func_capability.gpa_check_enable;

	if (cla_table->type == CQM_BAT_ENTRY_T_REORDER)
		gpa_check_enable = 0;

	cla_table->cla_lvl = CQM_CLA_LVL_2;

	shift = cqm_shift(trunk_size / cla_table->obj_size);
	cla_table->z = shift ? (shift - 1) : (shift);
	shift = cqm_shift(trunk_size / sizeof(dma_addr_t));
	cla_table->y = cla_table->z + shift;
	cla_table->x = CQM_MAX_INDEX_BIT;

	cqm_cla_yz_lvl2_init_cacheline(cla_table, trunk_size);

	/* Allocate x buf space */
	cla_x_buf = &cla_table->cla_x_buf;
	cla_x_buf->buf_size = trunk_size;
	cla_x_buf->buf_number = 1;
	cla_x_buf->page_number = cla_x_buf->buf_number <<
				 cla_table->trunk_order;

	ret = cqm_buf_alloc(cqm_handle, cla_x_buf, false);
	CQM_CHECK_EQUAL_RET(handle->dev_hdl, ret, CQM_SUCCESS, return CQM_FAIL,
			    CQM_ALLOC_FAIL(lvl_2_x_buf));

	/* Allocate y buf and z buf space */
	cla_z_buf = &cla_table->cla_z_buf;
	cla_z_buf->buf_size = trunk_size;
	cla_z_buf->buf_number = ALIGN(cla_table->max_buffer_size, trunk_size) /
				trunk_size;
	cla_z_buf->page_number = cla_z_buf->buf_number <<
				 cla_table->trunk_order;

	cla_y_buf = &cla_table->cla_y_buf;
	cla_y_buf->buf_size = trunk_size;
	cla_y_buf->buf_number =
		(ALIGN(cla_z_buf->buf_number * sizeof(dma_addr_t),
		       trunk_size)) / trunk_size;

	cla_y_buf->page_number = cla_y_buf->buf_number <<
				 cla_table->trunk_order;

	/* Requires static allocation of all buffer space */
	if (cla_table->alloc_static == true) {
		if (cqm_cla_yz_lvl2_static(cqm_handle,
					   cla_y_buf,
					   cla_z_buf,
					   gpa_check_enable) == CQM_FAIL) {
			cqm_buf_free(cla_x_buf, cqm_handle->dev);
			return CQM_FAIL;
		}
		/* Fill gpa of y buf list into x buf */
		base = (dma_addr_t *)(cla_x_buf->buf_list->va);
		for (i = 0; i < cla_y_buf->buf_number; i++) {
			/* gpa[0]=1 means this GPA is valid */
			*base = (cla_y_buf->buf_list[i].pa | gpa_check_enable);
			base++;
		}

		/* big-endian conversion */
		cqm_swab64((u8 *)(cla_x_buf->buf_list->va),
			   cla_y_buf->buf_number);
	} else {
	/* Only initialize and allocate buf list space, buffer spaces
	 * are allocated in service
	 */
		cla_z_buf->buf_list = (struct cqm_buf_list_s *)
				      vmalloc(cla_z_buf->buf_number *
				      sizeof(struct cqm_buf_list_s));
		if (!cla_z_buf->buf_list) {
			cqm_err(handle->dev_hdl, CQM_ALLOC_FAIL(lvl_2_z_buf));
			cqm_buf_free(cla_x_buf, cqm_handle->dev);
			return CQM_FAIL;
		}
		memset(cla_z_buf->buf_list, 0,
		       cla_z_buf->buf_number * sizeof(struct cqm_buf_list_s));

		cla_y_buf->buf_list = (struct cqm_buf_list_s *)
				      vmalloc(cla_y_buf->buf_number *
				      sizeof(struct cqm_buf_list_s));

		if (!cla_y_buf->buf_list) {
			cqm_err(handle->dev_hdl, CQM_ALLOC_FAIL(lvl_2_y_buf));
			cqm_buf_free(cla_z_buf, cqm_handle->dev);
			cqm_buf_free(cla_x_buf, cqm_handle->dev);
			return CQM_FAIL;
		}
		memset(cla_y_buf->buf_list, 0,
		       cla_y_buf->buf_number * sizeof(struct cqm_buf_list_s));
	}

	return CQM_SUCCESS;
}

static s32 cqm_cla_xyz_check(struct cqm_handle_s *cqm_handle,
			     struct cqm_cla_table_s *cla_table)
{
	struct hifc_hwdev *handle = cqm_handle->ex_handle;

	if (cla_table->obj_num == 0) {
		/* If the capability is set to 0, the CLA does not need to be
		 * initialized and exits directly
		 */
		cqm_info(handle->dev_hdl, "Cla alloc: cla_type %u, obj_num=0, don't alloc buffer\n",
			 cla_table->type);
		return CQM_SUCCESS;
	}

	/* Check whether obj_size is aligned with 2^n, and error is reported in
	 * case of 0 and 1
	 */
	if (cqm_check_align(cla_table->obj_size) == false) {
		cqm_err(handle->dev_hdl, "Cla alloc: cla_type %u, obj_size 0x%x is not align on 2^n\n",
			cla_table->type, cla_table->obj_size);
		return CQM_FAIL;
	}

	return CQM_SUCCESS;
}

/**
 * cqm_cla_xyz - Calculate how many levels of cla tables and allocate space
 * for each level of cla tables
 * @cqm_handle: cqm handle
 * @cla_table: cla table
 * Return: 0 - success, negative - failure
 */
s32 cqm_cla_xyz(struct cqm_handle_s *cqm_handle,
		struct cqm_cla_table_s *cla_table)
{
	struct hifc_hwdev *handle = cqm_handle->ex_handle;
	struct cqm_buf_s *cla_z_buf = NULL;
	u32 trunk_size = 0;
	s32 ret = CQM_FAIL;

	if (cqm_cla_xyz_check(cqm_handle, cla_table) == CQM_FAIL)
		return CQM_FAIL;

	trunk_size = PAGE_SIZE << cla_table->trunk_order;

	if (trunk_size < cla_table->obj_size) {
		cqm_err(handle->dev_hdl, "Cla alloc: cla type %u, obj_size 0x%x is out of trunk size\n",
			cla_table->type, cla_table->obj_size);
		return CQM_FAIL;
	}

	/* Level 0 CLA: The buffer occupies little space, and can be assigned to
	 * cla_z_buf during initialization
	 */
	if (cla_table->max_buffer_size <= trunk_size) {
		cla_table->cla_lvl = CQM_CLA_LVL_0;

		cla_table->z = CQM_MAX_INDEX_BIT;
		cla_table->y = 0;
		cla_table->x = 0;

		cla_table->cacheline_z = cla_table->z;
		cla_table->cacheline_y = cla_table->y;
		cla_table->cacheline_x = cla_table->x;

		/* Allocate z buf space */
		cla_z_buf = &cla_table->cla_z_buf;
		cla_z_buf->buf_size = trunk_size;
		cla_z_buf->buf_number = 1;
		cla_z_buf->page_number =
			cla_z_buf->buf_number << cla_table->trunk_order;
		ret = cqm_buf_alloc(cqm_handle, cla_z_buf, false);
		CQM_CHECK_EQUAL_RET(
			handle->dev_hdl, ret, CQM_SUCCESS,
			return CQM_FAIL, CQM_ALLOC_FAIL(lvl_0_z_buf));

	} else if (cla_table->max_buffer_size <=
		  (trunk_size * (trunk_size / sizeof(dma_addr_t)))) {
	/* Level 1 CLA:  Cla_y_buf is allocated during initialization,
	 * and cla_z_buf can be allocated dynamically
	 */
		if (cqm_cla_xyz_lvl1(cqm_handle,
				     cla_table, trunk_size) == CQM_FAIL) {
			cqm_err(handle->dev_hdl,
				CQM_FUNCTION_FAIL(cqm_cla_xyz_lvl1));
			return CQM_FAIL;
		}
	} else if (cla_table->max_buffer_size <=
		   (trunk_size * (trunk_size / sizeof(dma_addr_t)) *
		   (trunk_size / sizeof(dma_addr_t)))) {
	/* Level 2 CLA: Cla_x_buf is allocated during initialization,
	 * and cla_y_buf and cla_z_buf can be dynamically allocated
	 */
		if (cqm_cla_xyz_lvl2(cqm_handle, cla_table, trunk_size) ==
		    CQM_FAIL) {
			cqm_err(handle->dev_hdl,
				CQM_FUNCTION_FAIL(cqm_cla_xyz_lvl2));
			return CQM_FAIL;
		}
	} else {
		cqm_err(handle->dev_hdl, "Cla alloc: cla max_buffer_size 0x%x exceeds support range\n",
			cla_table->max_buffer_size);
		return CQM_FAIL;
	}

	return CQM_SUCCESS;
}

static void cqm_bat_entry_hash_init(void *cqm_handle,
				    struct cqm_cla_table_s *cla_table,
				    void *cap)
{
	struct cqm_func_capability_s *capability =
					(struct cqm_func_capability_s *)cap;

	cla_table->trunk_order = capability->pagesize_reorder;
	cla_table->max_buffer_size = capability->hash_number *
				     capability->hash_basic_size;
	cla_table->obj_size = capability->hash_basic_size;
	cla_table->obj_num = capability->hash_number;
	cla_table->alloc_static = true;
}

static void cqm_bat_entry_qpc_init(void *cqm_handle,
				   struct cqm_cla_table_s *cla_table,
				   void *cap)
{
	struct cqm_handle_s *handle = (struct cqm_handle_s *)cqm_handle;
	struct hifc_hwdev *hwdev_handle = handle->ex_handle;
	struct cqm_func_capability_s *capability =
					(struct cqm_func_capability_s *)cap;

	cla_table->trunk_order = capability->pagesize_reorder;
	cla_table->max_buffer_size = capability->qpc_number *
				     capability->qpc_basic_size;
	cla_table->obj_size = capability->qpc_basic_size;
	cla_table->obj_num = capability->qpc_number;
	cla_table->alloc_static = capability->qpc_alloc_static;
	cqm_info(hwdev_handle->dev_hdl, "Cla alloc: qpc alloc_static=%d\n",
		 cla_table->alloc_static);
}

static void cqm_bat_entry_mpt_init(void *cqm_handle,
				   struct cqm_cla_table_s *cla_table,
				   void *cap)
{
	struct cqm_func_capability_s *capability =
					(struct cqm_func_capability_s *)cap;

	cla_table->trunk_order = capability->pagesize_reorder;
	cla_table->max_buffer_size = capability->mpt_number *
				     capability->mpt_basic_size;
	cla_table->obj_size = capability->mpt_basic_size;
	cla_table->obj_num = capability->mpt_number;
	cla_table->alloc_static = true;
}

static void cqm_bat_entry_scqc_init(void *cqm_handle,
				    struct cqm_cla_table_s *cla_table,
				    void *cap)
{
	struct cqm_handle_s *handle = (struct cqm_handle_s *)cqm_handle;
	struct hifc_hwdev *hwdev_handle = handle->ex_handle;
	struct cqm_func_capability_s *capability =
					(struct cqm_func_capability_s *)cap;

	cla_table->trunk_order = capability->pagesize_reorder;
	cla_table->max_buffer_size = capability->scqc_number *
				     capability->scqc_basic_size;
	cla_table->obj_size = capability->scqc_basic_size;
	cla_table->obj_num = capability->scqc_number;
	cla_table->alloc_static = capability->scqc_alloc_static;
	cqm_info(hwdev_handle->dev_hdl, "Cla alloc: scqc alloc_static=%d\n",
		 cla_table->alloc_static);
}

static void cqm_bat_entry_srqc_init(void *cqm_handle,
				    struct cqm_cla_table_s *cla_table,
				    void *cap)
{
	struct cqm_func_capability_s *capability =
					(struct cqm_func_capability_s *)cap;

	cla_table->trunk_order = capability->pagesize_reorder;
	cla_table->max_buffer_size = capability->srqc_number *
				     capability->srqc_basic_size;
	cla_table->obj_size = capability->srqc_basic_size;
	cla_table->obj_num = capability->srqc_number;
	cla_table->alloc_static = false;
}

static void cqm_bat_entry_gid_init(void *cqm_handle,
				   struct cqm_cla_table_s *cla_table,
				   void *cap)
{
	struct cqm_func_capability_s *capability =
					(struct cqm_func_capability_s *)cap;

	cla_table->max_buffer_size = capability->gid_number *
				     capability->gid_basic_size;
	cla_table->trunk_order = (u32)cqm_shift(
						ALIGN(
						cla_table->max_buffer_size,
						PAGE_SIZE) / PAGE_SIZE);
	cla_table->obj_size = capability->gid_basic_size;
	cla_table->obj_num = capability->gid_number;
	cla_table->alloc_static = true;
}

static void cqm_bat_entry_lun_init(void *cqm_handle,
				   struct cqm_cla_table_s *cla_table,
				   void *cap)
{
	struct cqm_func_capability_s *capability =
					(struct cqm_func_capability_s *)cap;

	cla_table->trunk_order = CLA_TABLE_PAGE_ORDER;
	cla_table->max_buffer_size = capability->lun_number *
				     capability->lun_basic_size;
	cla_table->obj_size = capability->lun_basic_size;
	cla_table->obj_num = capability->lun_number;
	cla_table->alloc_static = true;
}

static void cqm_bat_entry_taskmap_init(void *cqm_handle,
				       struct cqm_cla_table_s *cla_table,
				       void *cap)
{
	struct cqm_func_capability_s *capability =
					(struct cqm_func_capability_s *)cap;

	cla_table->trunk_order = CQM_4K_PAGE_ORDER;
	cla_table->max_buffer_size = capability->taskmap_number *
				     capability->taskmap_basic_size;
	cla_table->obj_size = capability->taskmap_basic_size;
	cla_table->obj_num = capability->taskmap_number;
	cla_table->alloc_static = true;
}

static void cqm_bat_entry_l3i_init(void *cqm_handle,
				   struct cqm_cla_table_s *cla_table,
				   void *cap)
{
	struct cqm_func_capability_s *capability =
					(struct cqm_func_capability_s *)cap;

	cla_table->trunk_order = CLA_TABLE_PAGE_ORDER;
	cla_table->max_buffer_size = capability->l3i_number *
				     capability->l3i_basic_size;
	cla_table->obj_size = capability->l3i_basic_size;
	cla_table->obj_num = capability->l3i_number;
	cla_table->alloc_static = true;
}

static void cqm_bat_entry_childc_init(void *cqm_handle,
				      struct cqm_cla_table_s *cla_table,
				      void *cap)
{
	struct cqm_func_capability_s *capability =
					(struct cqm_func_capability_s *)cap;

	cla_table->trunk_order = capability->pagesize_reorder;
	cla_table->max_buffer_size = capability->childc_number *
				     capability->childc_basic_size;
	cla_table->obj_size = capability->childc_basic_size;
	cla_table->obj_num = capability->childc_number;
	cla_table->alloc_static = true;
}

static void cqm_bat_entry_timer_init(void *cqm_handle,
				     struct cqm_cla_table_s *cla_table,
				     void *cap)
{
	struct cqm_func_capability_s *capability =
					(struct cqm_func_capability_s *)cap;

	cla_table->trunk_order = CQM_4K_PAGE_ORDER;
	cla_table->max_buffer_size = capability->timer_number *
						capability->timer_basic_size;
	cla_table->obj_size = capability->timer_basic_size;
	cla_table->obj_num = capability->timer_number;
	cla_table->alloc_static = true;
}

static void cqm_bat_entry_xid2cid_init(void *cqm_handle,
				       struct cqm_cla_table_s *cla_table,
				       void *cap)
{
	struct cqm_func_capability_s *capability =
					(struct cqm_func_capability_s *)cap;

	cla_table->trunk_order = capability->pagesize_reorder;
	cla_table->max_buffer_size = capability->xid2cid_number *
				     capability->xid2cid_basic_size;
	cla_table->obj_size = capability->xid2cid_basic_size;
	cla_table->obj_num = capability->xid2cid_number;
	cla_table->alloc_static = true;
}

static void cqm_bat_entry_reoder_init(void *cqm_handle,
				      struct cqm_cla_table_s *cla_table,
				      void *cap)
{
	struct cqm_func_capability_s *capability =
					(struct cqm_func_capability_s *)cap;

	cla_table->trunk_order = capability->pagesize_reorder;
	cla_table->max_buffer_size = capability->reorder_number *
				     capability->reorder_basic_size;
	cla_table->obj_size = capability->reorder_basic_size;
	cla_table->obj_num = capability->reorder_number;
	cla_table->alloc_static = true;
}

struct cqm_cla_entry_init_s cqm_cla_entry_init_tbl[] = {
	{CQM_BAT_ENTRY_T_HASH, cqm_bat_entry_hash_init},
	{CQM_BAT_ENTRY_T_QPC, cqm_bat_entry_qpc_init},
	{CQM_BAT_ENTRY_T_MPT, cqm_bat_entry_mpt_init},
	{CQM_BAT_ENTRY_T_SCQC, cqm_bat_entry_scqc_init},
	{CQM_BAT_ENTRY_T_SRQC, cqm_bat_entry_srqc_init},
	{CQM_BAT_ENTRY_T_GID, cqm_bat_entry_gid_init},
	{CQM_BAT_ENTRY_T_LUN, cqm_bat_entry_lun_init},
	{CQM_BAT_ENTRY_T_TASKMAP, cqm_bat_entry_taskmap_init},
	{CQM_BAT_ENTRY_T_L3I, cqm_bat_entry_l3i_init},
	{CQM_BAT_ENTRY_T_CHILDC, cqm_bat_entry_childc_init},
	{CQM_BAT_ENTRY_T_TIMER, cqm_bat_entry_timer_init},
	{CQM_BAT_ENTRY_T_XID2CID, cqm_bat_entry_xid2cid_init},
	{CQM_BAT_ENTRY_T_REORDER, cqm_bat_entry_reoder_init},
};

static struct cqm_cla_entry_init_s *cqm_get_cla_init_entry(
						struct cqm_handle_s *cqm_handle,
						u32 type)
{
	int i;
	struct cqm_cla_entry_init_s *entry = NULL;

	for (i = 0;
	     i < (sizeof(cqm_cla_entry_init_tbl) /
	     sizeof(struct cqm_cla_entry_init_s)); i++) {
		entry = &cqm_cla_entry_init_tbl[i];
		if (entry->type == type)
			return entry;
	}

	return NULL;
}

void cqm_cla_init_entry(struct cqm_handle_s *cqm_handle,
			struct cqm_cla_table_s *cla_table,
			struct cqm_func_capability_s *capability)
{
	struct cqm_cla_entry_init_s *entry;

	entry = cqm_get_cla_init_entry(cqm_handle, cla_table->type);
	if (entry && entry->cqm_cla_init_handler)
		entry->cqm_cla_init_handler(cqm_handle, cla_table, capability);
}

static s32 cqm_cla_fill_entry(struct cqm_handle_s *cqm_handle)
{
	struct hifc_hwdev *handle = cqm_handle->ex_handle;
	s32 ret = CQM_FAIL;

	/* After the allocation of CLA entry, fill in the BAT table */
	cqm_bat_fill_cla(cqm_handle);

	/* Notify the chip to refresh the BAT table */
	ret = cqm_bat_update(cqm_handle);
	if (ret != CQM_SUCCESS) {
		cqm_err(handle->dev_hdl, CQM_FUNCTION_FAIL(cqm_bat_update));
		return CQM_FAIL;
	}

	cqm_info(handle->dev_hdl, "Timer start: func_type=%d, timer_enable=%u\n",
		 cqm_handle->func_attribute.func_type,
		 cqm_handle->func_capability.timer_enable);

	if ((cqm_handle->func_attribute.func_type == CQM_PPF) &&
	    (cqm_handle->func_capability.timer_enable == CQM_TIMER_ENABLE)) {
		/* After the timer resource is allocated,
		 * the timer needs to be enabled
		 */
		cqm_info(handle->dev_hdl, "Timer start: hifc ppf timer start\n");
		ret = hifc_ppf_tmr_start((void *)(cqm_handle->ex_handle));
		if (ret != CQM_SUCCESS) {
			cqm_err(handle->dev_hdl, "Timer start: hifc ppf timer start, ret=%d\n",
				ret);
			return CQM_FAIL;
		}
	}
	return CQM_SUCCESS;
}

s32 cqm_cla_init(struct cqm_handle_s *cqm_handle)
{
	struct cqm_func_capability_s *capability = &cqm_handle->func_capability;
	struct  cqm_bat_table_s *bat_table = &cqm_handle->bat_table;
	struct cqm_cla_table_s *cla_table = NULL;
	s32 inv_flag = 0;
	u32 i = 0;
	u32 j = 0;

	for (i = 0; i < CQM_BAT_ENTRY_MAX; i++) {
		cla_table = &bat_table->entry[i];
		cla_table->type = bat_table->bat_entry_type[i];

		cqm_cla_init_entry(cqm_handle, cla_table, capability);

		/* Allocate CLA entry space of all levels */
		if ((cla_table->type >= CQM_BAT_ENTRY_T_HASH) &&
		    (cla_table->type <= CQM_BAT_ENTRY_T_REORDER)) {
			/* Only needs to allocate timer resources for PPF,
			 * 8 wheels * 2k scales * 32B * func_num, for PF, there
			 * is no need to allocate resources for the timer, nor
			 * to fill in the structure of the timer entry in the
			 * BAT table.
			 */
			if (!((cla_table->type == CQM_BAT_ENTRY_T_TIMER) &&
			      (cqm_handle->func_attribute.func_type
			      != CQM_PPF))) {
				if (cqm_cla_xyz(cqm_handle, cla_table) ==
				    CQM_FAIL)
					goto err;
			}
		}
		mutex_init(&cla_table->lock);
	}
	if (cqm_cla_fill_entry(cqm_handle) == CQM_FAIL)
		goto err;

	return CQM_SUCCESS;

err:
	for (j = 0; j < i; j++) {
		cla_table = &bat_table->entry[j];
		if (cla_table->type != CQM_BAT_ENTRY_T_INVALID) {
			cqm_buf_free_cache_inv(cqm_handle,
					       &cla_table->cla_x_buf,
					       &inv_flag);
			cqm_buf_free_cache_inv(cqm_handle,
					       &cla_table->cla_y_buf,
					       &inv_flag);
			cqm_buf_free_cache_inv(cqm_handle,
					       &cla_table->cla_z_buf,
					       &inv_flag);
		}
	}

	return CQM_FAIL;
}

void cqm_cla_uninit(struct cqm_handle_s *cqm_handle)
{
	struct cqm_bat_table_s *bat_table = &cqm_handle->bat_table;
	struct cqm_cla_table_s *cla_table = NULL;
	s32 inv_flag = 0;
	u32 i = 0;

	for (i = 0; i < CQM_BAT_ENTRY_MAX; i++) {
		cla_table = &bat_table->entry[i];
		if (cla_table->type != CQM_BAT_ENTRY_T_INVALID) {
			cqm_buf_free_cache_inv(cqm_handle,
					       &cla_table->cla_x_buf,
					       &inv_flag);
			cqm_buf_free_cache_inv(cqm_handle,
					       &cla_table->cla_y_buf,
					       &inv_flag);
			cqm_buf_free_cache_inv(cqm_handle,
					       &cla_table->cla_z_buf,
					       &inv_flag);
		}
	}
}

s32 cqm_cla_update(struct cqm_handle_s *cqm_handle,
		   struct cqm_buf_list_s *buf_node_parent,
		   struct cqm_buf_list_s *buf_node_child,
		   u32 child_index, u8 cla_update_mode)
{
	struct hifc_hwdev *handle = cqm_handle->ex_handle;
	struct cqm_cmd_buf_s *buf_in = NULL;
	struct cqm_cla_update_cmd_s *cmd = NULL;
	dma_addr_t pa = 0;
	s32 ret = CQM_FAIL;
	u8 gpa_check_enable = cqm_handle->func_capability.gpa_check_enable;

	buf_in = cqm_cmd_alloc((void *)(cqm_handle->ex_handle));
	CQM_PTR_CHECK_RET(buf_in, return CQM_FAIL, CQM_ALLOC_FAIL(buf_in));
	buf_in->size = sizeof(struct cqm_cla_update_cmd_s);

	/* Fill the command format and convert to big endian */
	cmd = (struct cqm_cla_update_cmd_s *)(buf_in->buf);

	pa = buf_node_parent->pa + (child_index * sizeof(dma_addr_t));
	cmd->gpa_h = CQM_ADDR_HI(pa);
	cmd->gpa_l = CQM_ADDR_LW(pa);

	pa = buf_node_child->pa;
	cmd->value_h = CQM_ADDR_HI(pa);
	cmd->value_l = CQM_ADDR_LW(pa);

	cqm_dbg("Cla alloc: cqm_cla_update, gpa=0x%x 0x%x, value=0x%x 0x%x, cla_update_mode=0x%x\n",
		cmd->gpa_h, cmd->gpa_l, cmd->value_h, cmd->value_l,
		cla_update_mode);

	/* CLA GPA check */
	if (gpa_check_enable) {
		switch (cla_update_mode) {
		/* gpa[0]=1 means this GPA is valid */
		case CQM_CLA_RECORD_NEW_GPA:
			cmd->value_l |= 1;
			break;
		/* gpa[0]=0 means this GPA is valid */
		case CQM_CLA_DEL_GPA_WITHOUT_CACHE_INVALID:
		case CQM_CLA_DEL_GPA_WITH_CACHE_INVALID:
			cmd->value_l &= (~1);
			break;
		default:
			cqm_err(handle->dev_hdl,
				"Cla alloc: cqm_cla_update, cqm_cla_update, wrong cla_update_mode=%u\n",
				cla_update_mode);
			break;
		}
	}

	cqm_swab32((u8 *)cmd, (sizeof(struct cqm_cla_update_cmd_s) >> 2));

	ret = cqm_send_cmd_box((void *)(cqm_handle->ex_handle),
			       CQM_CMD_ACK_TYPE_CMDQ,
			       CQM_MOD_CQM, CQM_CMD_T_CLA_UPDATE,
			       buf_in, NULL, CQM_CMD_TIMEOUT);
	if (ret != CQM_SUCCESS) {
		cqm_err(handle->dev_hdl, CQM_FUNCTION_FAIL(cqm_send_cmd_box));
		cqm_err(handle->dev_hdl,
			"Cla alloc: cqm_cla_update, cqm_send_cmd_box_ret=%d\n",
			ret);
		cqm_err(handle->dev_hdl, "Cla alloc: cqm_cla_update, cla_update_cmd: 0x%x 0x%x 0x%x 0x%x\n",
			cmd->gpa_h, cmd->gpa_l, cmd->value_h, cmd->value_l);
		cqm_cmd_free((void *)(cqm_handle->ex_handle), buf_in);
		return CQM_FAIL;
	}

	cqm_cmd_free((void *)(cqm_handle->ex_handle), buf_in);
	return CQM_SUCCESS;
}

/**
 * cqm_cla_alloc - Allocate a CLA trunk page
 * @cqm_handle: cqm handle
 * @cla_table: cla handle
 * @buf_node_parent: the parent node whose content is to be updated
 * @buf_node_child: the child node whose content is to be allocated
 * @child_index: child index
 * Return: 0 - success, negative - failure
 */
s32 cqm_cla_alloc(struct cqm_handle_s *cqm_handle,
		  struct cqm_cla_table_s *cla_table,
		  struct cqm_buf_list_s *buf_node_parent,
		  struct cqm_buf_list_s *buf_node_child, u32 child_index)
{
	struct hifc_hwdev *handle = cqm_handle->ex_handle;
	s32 ret = CQM_FAIL;

	/* Allocate trunk page */
	buf_node_child->va = (u8 *)__get_free_pages(GFP_KERNEL | __GFP_ZERO,
						    cla_table->trunk_order);
	CQM_PTR_CHECK_RET(buf_node_child->va, return CQM_FAIL,
			  CQM_ALLOC_FAIL(va));

	/* pci mapping */
	buf_node_child->pa =
		 pci_map_single(cqm_handle->dev, buf_node_child->va,
				PAGE_SIZE << cla_table->trunk_order,
				PCI_DMA_BIDIRECTIONAL);
	if (pci_dma_mapping_error(cqm_handle->dev, buf_node_child->pa)) {
		cqm_err(handle->dev_hdl, CQM_MAP_FAIL(buf_node_child->pa));
		goto err1;
	}

	/* Notify the chip of trunk_pa and
	 * let it fill in the cla table entry
	 */
	ret = cqm_cla_update(cqm_handle, buf_node_parent,
			     buf_node_child, child_index,
			     CQM_CLA_RECORD_NEW_GPA);
	if (ret != CQM_SUCCESS) {
		cqm_err(handle->dev_hdl, CQM_FUNCTION_FAIL(cqm_cla_update));
		goto err2;
	}

	return CQM_SUCCESS;

err2:
	pci_unmap_single(cqm_handle->dev, buf_node_child->pa,
			 PAGE_SIZE << cla_table->trunk_order,
			 PCI_DMA_BIDIRECTIONAL);
err1:
	free_pages((ulong)(buf_node_child->va), cla_table->trunk_order);
	buf_node_child->va = NULL;
	return CQM_FAIL;
}

void cqm_cla_free(struct cqm_handle_s *cqm_handle,
		  struct cqm_cla_table_s *cla_table,
		  struct cqm_buf_list_s *buf_node_parent,
		  struct cqm_buf_list_s *buf_node_child,
		  u32 child_index, u8 cla_update_mode)
{
	struct hifc_hwdev *handle = cqm_handle->ex_handle;

	cqm_dbg("Cla free: cla_update_mode=%u\n", cla_update_mode);

	if (cqm_cla_update(cqm_handle, buf_node_parent,
			   buf_node_child, child_index,
			   cla_update_mode) != CQM_SUCCESS) {
		cqm_err(handle->dev_hdl, CQM_FUNCTION_FAIL(cqm_cla_update));
		return;
	}

	if (cla_update_mode == CQM_CLA_DEL_GPA_WITH_CACHE_INVALID) {
		if (cqm_cla_cache_invalid(
			cqm_handle, buf_node_child->pa,
			PAGE_SIZE << cla_table->trunk_order) != CQM_SUCCESS) {
			cqm_err(handle->dev_hdl,
				CQM_FUNCTION_FAIL(cqm_cla_cache_invalid));
			return;
		}
	}

	/* Unblock the pci mapping of the trunk page */
	pci_unmap_single(cqm_handle->dev, buf_node_child->pa,
			 PAGE_SIZE << cla_table->trunk_order,
			 PCI_DMA_BIDIRECTIONAL);

	/* Free trunk page */
	free_pages((ulong)(buf_node_child->va), cla_table->trunk_order);
	buf_node_child->va = NULL;
}

/**
 * cqm_static_qpc_cla_get - When QPC is a static allocation, allocate the count
 * of buffer from the index position in the cla table without lock
 * @cqm_handle: cqm handle
 * @cla_table: cla handle
 * @index: the index of table
 * @count: the count of buffer
 * @pa: the physical address
 * Return: the virtual address
 */
u8 *cqm_static_qpc_cla_get(struct cqm_handle_s *cqm_handle,
			   struct cqm_cla_table_s *cla_table,
			   u32 index, u32 count, dma_addr_t *pa)
{
	struct hifc_hwdev *handle = cqm_handle->ex_handle;
	struct cqm_buf_s *cla_y_buf = &cla_table->cla_y_buf;
	struct cqm_buf_s *cla_z_buf = &cla_table->cla_z_buf;
	struct cqm_buf_list_s *buf_node_z = NULL;
	u32 x_index = 0;
	u32 y_index = 0;
	u32 z_index = 0;
	u32 trunk_size = PAGE_SIZE << cla_table->trunk_order;
	u8 *ret_addr = NULL;
	u32 offset = 0;

	if (cla_table->cla_lvl == CQM_CLA_LVL_0) {
		offset = index * cla_table->obj_size;
		ret_addr = (u8 *)(cla_z_buf->buf_list->va) + offset;
		*pa = cla_z_buf->buf_list->pa + offset;
	} else if (cla_table->cla_lvl == CQM_CLA_LVL_1) {
		z_index = index & ((1 << (cla_table->z + 1)) - 1);
		y_index = index >> (cla_table->z + 1);

		if (y_index >= cla_z_buf->buf_number) {
			cqm_err(handle->dev_hdl,
				"Static qpc cla get: index exceeds buf_number, y_index %u, z_buf_number %u\n",
				y_index, cla_z_buf->buf_number);
			return NULL;
		}
		buf_node_z = &cla_z_buf->buf_list[y_index];
		if (!buf_node_z->va) {
			cqm_err(handle->dev_hdl, "Cla get: static qpc cla_z_buf[%u].va=NULL\n",
				y_index);
			return NULL;
		}
		buf_node_z->refcount += count;
		offset = z_index * cla_table->obj_size;
		ret_addr = (u8 *)(buf_node_z->va) + offset;
		*pa = buf_node_z->pa + offset;
	} else {
		z_index = index & ((1 << (cla_table->z + 1)) - 1);
		y_index = (index >> (cla_table->z + 1)) &
			  ((1 << (cla_table->y - cla_table->z)) - 1);
		x_index = index >> (cla_table->y + 1);

		if ((x_index >= cla_y_buf->buf_number) ||
		    ((x_index * (trunk_size / sizeof(dma_addr_t)) + y_index) >=
		    cla_z_buf->buf_number)) {
			cqm_err(handle->dev_hdl,
				"Static qpc cla get: index exceeds buf_number,x_index %u, y_index %u, y_buf_number %u, z_buf_number %u\n ",
				x_index, y_index, cla_y_buf->buf_number,
				cla_z_buf->buf_number);
			return NULL;
		}

		buf_node_z = &(cla_z_buf->buf_list[x_index *
			     (trunk_size / sizeof(dma_addr_t)) + y_index]);
		if (!buf_node_z->va) {
			cqm_err(handle->dev_hdl, "Cla get: static qpc cla_z_buf.va=NULL\n");
			return NULL;
		}

		buf_node_z->refcount += count;
		offset = z_index * cla_table->obj_size;
		ret_addr = (u8 *)(buf_node_z->va) + offset;
		*pa = buf_node_z->pa + offset;
	}

	return ret_addr;
}

static s32 cqm_cla_get_level_two(struct cqm_handle_s *cqm_handle,
				 struct cqm_cla_table_s *cla_table,
				 u32 index, u32 count,
				 dma_addr_t *pa, u8 **ret_addr)
{
	struct hifc_hwdev *handle = cqm_handle->ex_handle;
	struct cqm_buf_s *cla_x_buf = &cla_table->cla_x_buf;
	struct cqm_buf_s *cla_y_buf = &cla_table->cla_y_buf;
	struct cqm_buf_s *cla_z_buf = &cla_table->cla_z_buf;
	struct cqm_buf_list_s *buf_node_x = NULL;
	struct cqm_buf_list_s *buf_node_y = NULL;
	struct cqm_buf_list_s *buf_node_z = NULL;
	u32 x_index = 0;
	u32 y_index = 0;
	u32 z_index = 0;
	u32 trunk_size = PAGE_SIZE << cla_table->trunk_order;
	u32 offset = 0;

	z_index = index & ((1 << (cla_table->z + 1)) - 1);
	y_index = (index >> (cla_table->z + 1)) &
		  ((1 << (cla_table->y - cla_table->z)) - 1);
	x_index = index >> (cla_table->y + 1);

	if ((x_index >= cla_y_buf->buf_number) ||
	    ((x_index * (trunk_size / sizeof(dma_addr_t)) + y_index) >=
	    cla_z_buf->buf_number)) {
		cqm_err(handle->dev_hdl,
			"Cla get: index exceeds buf_number, x_index %u, y_index %u, y_buf_number %u, z_buf_number %u\n",
			x_index, y_index, cla_y_buf->buf_number,
			cla_z_buf->buf_number);
		return CQM_FAIL;
	}

	buf_node_x = cla_x_buf->buf_list;
	buf_node_y = &cla_y_buf->buf_list[x_index];
	buf_node_z = &(cla_z_buf->buf_list[x_index *
		     (trunk_size / sizeof(dma_addr_t)) + y_index]);

	/* Y buf node does not exist, allocates y node page */
	if (!buf_node_y->va) {
		if (cqm_cla_alloc(
			cqm_handle, cla_table,
			buf_node_x, buf_node_y, x_index) == CQM_FAIL) {
			cqm_err(handle->dev_hdl,
				CQM_FUNCTION_FAIL(cqm_cla_alloc));
			return CQM_FAIL;
		}
	}

	/* Z buf node does not exist, allocates z node page */
	if (!buf_node_z->va) {
		if (cqm_cla_alloc(cqm_handle,
				  cla_table,
				  buf_node_y,
				  buf_node_z,
				  y_index) == CQM_FAIL) {
			cqm_err(handle->dev_hdl,
				CQM_FUNCTION_FAIL(cqm_cla_alloc));
			if (buf_node_y->refcount == 0) {
				/* Free y node, needs cache_invalid */
				cqm_cla_free(
					cqm_handle, cla_table,
					buf_node_x, buf_node_y, x_index,
					CQM_CLA_DEL_GPA_WITH_CACHE_INVALID);
			}
			return CQM_FAIL;
		}

		cqm_dbg("Cla get: 2L: y_refcount=0x%x\n", buf_node_y->refcount);
		/* Y buf node's reference count should be +1 */
		buf_node_y->refcount++;
	}

	cqm_dbg("Cla get: 2L: z_refcount=0x%x, count=0x%x\n",
		buf_node_z->refcount, count);
	buf_node_z->refcount += count;
	offset = z_index * cla_table->obj_size;
	*ret_addr = (u8 *)(buf_node_z->va) + offset;
	*pa = buf_node_z->pa + offset;

	return CQM_SUCCESS;
}

static s32 cqm_cla_get_level_one(struct cqm_handle_s *cqm_handle,
				 struct cqm_cla_table_s *cla_table,
				 u32 index, u32 count, dma_addr_t *pa,
				 u8 **ret_addr)
{
	struct hifc_hwdev *handle = cqm_handle->ex_handle;
	struct cqm_buf_s *cla_y_buf = &cla_table->cla_y_buf;
	struct cqm_buf_s *cla_z_buf = &cla_table->cla_z_buf;
	struct cqm_buf_list_s *buf_node_y = NULL;
	struct cqm_buf_list_s *buf_node_z = NULL;
	u32 y_index = 0;
	u32 z_index = 0;
	u32 offset = 0;

	z_index = index & ((1 << (cla_table->z + 1)) - 1);
	y_index = index >> (cla_table->z + 1);

	if (y_index >= cla_z_buf->buf_number) {
		cqm_err(handle->dev_hdl,
			"Cla get: index exceeds buf_number, y_index %u, z_buf_number %u\n",
			y_index, cla_z_buf->buf_number);
		return CQM_FAIL;
	}
	buf_node_z = &cla_z_buf->buf_list[y_index];
	buf_node_y = cla_y_buf->buf_list;

	/* Z buf node does not exist, first allocate the page */
	if (!buf_node_z->va) {
		if (cqm_cla_alloc(cqm_handle,
				  cla_table,
				  buf_node_y,
				  buf_node_z,
				  y_index) == CQM_FAIL) {
			cqm_err(handle->dev_hdl,
				CQM_FUNCTION_FAIL(cqm_cla_alloc));
				cqm_err(handle->dev_hdl,
					"Cla get: cla_table->type=%u\n",
					cla_table->type);
			return CQM_FAIL;
		}
	}

	cqm_dbg("Cla get: 1L: z_refcount=0x%x, count=0x%x\n",
		buf_node_z->refcount, count);
	buf_node_z->refcount += count;
	offset = z_index * cla_table->obj_size;
	*ret_addr = (u8 *)(buf_node_z->va) + offset;
	*pa = buf_node_z->pa + offset;

	return CQM_SUCCESS;
}

/**
 * cqm_cla_get - Allocate the count of buffer from the index position in the
 * cla table
 * @cqm_handle: cqm handle
 * @cla_table: cla table
 * @index: the index of table
 * @count: the count of buffer
 * @pa: the physical address
 * Return: the virtual address
 */
u8 *cqm_cla_get(struct cqm_handle_s *cqm_handle,
		struct cqm_cla_table_s *cla_table, u32 index,
		u32 count, dma_addr_t *pa)
{
	struct cqm_buf_s *cla_z_buf = &cla_table->cla_z_buf;
	u8 *ret_addr = NULL;
	u32 offset = 0;

	mutex_lock(&cla_table->lock);
	if (cla_table->cla_lvl == CQM_CLA_LVL_0) {
		/* Level 0 CLA pages are statically allocated */
		offset = index * cla_table->obj_size;
		ret_addr = (u8 *)(cla_z_buf->buf_list->va) + offset;
		*pa = cla_z_buf->buf_list->pa + offset;
	} else if (cla_table->cla_lvl == CQM_CLA_LVL_1) {
		if (cqm_cla_get_level_one(cqm_handle, cla_table,
					  index, count,
					  pa, &ret_addr) == CQM_FAIL) {
			mutex_unlock(&cla_table->lock);
			return NULL;
		}
	} else {
		if (cqm_cla_get_level_two(cqm_handle,
					  cla_table,
					  index,
					  count,
					  pa,
					  &ret_addr) == CQM_FAIL) {
			mutex_unlock(&cla_table->lock);
			return NULL;
		}
	}

	mutex_unlock(&cla_table->lock);
	return ret_addr;
}

/**
 * cqm_cla_put -Decrease the reference count of the trunk page, if it is reduced
 * to 0, release the trunk page
 * @cqm_handle: cqm handle
 * @cla_table: cla table
 * @index: the index of table
 * @count: the count of buffer
 */
void cqm_cla_put(struct cqm_handle_s *cqm_handle,
		 struct cqm_cla_table_s *cla_table,
		 u32 index, u32 count)
{
	struct hifc_hwdev *handle = cqm_handle->ex_handle;
	struct cqm_buf_s *cla_x_buf = &cla_table->cla_x_buf;
	struct cqm_buf_s *cla_y_buf = &cla_table->cla_y_buf;
	struct cqm_buf_s *cla_z_buf = &cla_table->cla_z_buf;
	struct cqm_buf_list_s *buf_node_x = NULL;
	struct cqm_buf_list_s *buf_node_y = NULL;
	struct cqm_buf_list_s *buf_node_z = NULL;
	u32 x_index = 0;
	u32 y_index = 0;
	u32 trunk_size = PAGE_SIZE << cla_table->trunk_order;

	/* Buffer is statically allocated,
	 * no need to control the reference count
	 */
	if (cla_table->alloc_static == true)
		return;

	mutex_lock(&cla_table->lock);

	if (cla_table->cla_lvl == CQM_CLA_LVL_1) {
		y_index = index >> (cla_table->z + 1);

		if (y_index >= cla_z_buf->buf_number) {
			cqm_err(handle->dev_hdl,
				"Cla put: index exceeds buf_number, y_index %u, z_buf_number %u\n",
				y_index, cla_z_buf->buf_number);
			cqm_err(handle->dev_hdl,
				"Cla put: cla_table->type=%u\n",
				cla_table->type);
			mutex_unlock(&cla_table->lock);
			return;
		}

		buf_node_z = &cla_z_buf->buf_list[y_index];
		buf_node_y = cla_y_buf->buf_list;

		/* When the z node page reference count is 0,
		 * release the z node page
		 */
		cqm_dbg("Cla put: 1L: z_refcount=0x%x, count=0x%x\n",
			buf_node_z->refcount, count);
		buf_node_z->refcount -= count;
		if (buf_node_z->refcount == 0) {
			/* Z node does not need cache invalid */
			cqm_cla_free(cqm_handle, cla_table, buf_node_y,
				     buf_node_z, y_index,
				     CQM_CLA_DEL_GPA_WITHOUT_CACHE_INVALID);
		}
	} else if (cla_table->cla_lvl == CQM_CLA_LVL_2) {
		y_index = (index >> (cla_table->z + 1)) &
			  ((1 << (cla_table->y - cla_table->z)) - 1);
		x_index = index >> (cla_table->y + 1);

		if ((x_index >= cla_y_buf->buf_number) ||
		    ((x_index * (trunk_size / sizeof(dma_addr_t)) + y_index) >=
		    cla_z_buf->buf_number)) {
			cqm_err(handle->dev_hdl,
				"Cla put: index exceeds buf_number, x_index %u, y_index %u, y_buf_number %u, z_buf_number %u\n",
				x_index, y_index, cla_y_buf->buf_number,
				cla_z_buf->buf_number);
			mutex_unlock(&cla_table->lock);
			return;
		}

		buf_node_x = cla_x_buf->buf_list;
		buf_node_y = &cla_y_buf->buf_list[x_index];
		buf_node_z = &(cla_z_buf->buf_list[x_index *
			     (trunk_size / sizeof(dma_addr_t)) + y_index]);
		cqm_dbg("Cla put: 2L: z_refcount=0x%x, count=0x%x\n",
			buf_node_z->refcount, count);

		/* When the z node page reference count is 0,
		 * release the z node page
		 */
		buf_node_z->refcount -= count;
		if (buf_node_z->refcount == 0) {
			cqm_cla_free(cqm_handle, cla_table, buf_node_y,
				     buf_node_z, y_index,
				     CQM_CLA_DEL_GPA_WITHOUT_CACHE_INVALID);

			/* When the y node page reference count is 0,
			 * release the y node page
			 */
			cqm_dbg("Cla put: 2L: y_refcount=0x%x\n",
				buf_node_y->refcount);
				buf_node_y->refcount--;
			if (buf_node_y->refcount == 0) {
				/* Y node needs cache invalid */
				cqm_cla_free(
					cqm_handle, cla_table, buf_node_x,
					buf_node_y, x_index,
					CQM_CLA_DEL_GPA_WITH_CACHE_INVALID);
			}
		}
	}

	mutex_unlock(&cla_table->lock);
}

/**
 * cqm_cla_table_get - Find the CLA table structure corresponding to a BAT entry
 * @bat_table: bat table
 * @entry_type: entry type
 * @count: the count of buffer
 * Return: the CLA table
 */
struct cqm_cla_table_s *cqm_cla_table_get(struct cqm_bat_table_s *bat_table,
					  u32 entry_type)
{
	struct cqm_cla_table_s *cla_table = NULL;
	u32 i = 0;

	for (i = 0; i < CQM_BAT_ENTRY_MAX; i++) {
		cla_table = &bat_table->entry[i];
		if (entry_type == cla_table->type)
			return cla_table;
	}

	return NULL;
}

#define bitmap_section

/**
 * __cqm_bitmap_init - Initialize a bitmap
 * @bitmap: cqm bitmap table
 * Return: 0 - success, negative - failure
 */
s32 __cqm_bitmap_init(struct cqm_bitmap_s *bitmap)
{
	spin_lock_init(&bitmap->lock);

	/* The max_num of bitmap is aligned by 8, and then shifted right by
	 * 3bits to get how many Bytes are needed
	 */
	bitmap->table =
		(ulong *)vmalloc((ALIGN(bitmap->max_num, 8) >> 3));
	CQM_PTR_CHECK_RET(bitmap->table, return CQM_FAIL,
			  CQM_ALLOC_FAIL(bitmap->table));
	memset(bitmap->table, 0, (ALIGN(bitmap->max_num, 8) >> 3));

	return CQM_SUCCESS;
}

static s32 cqm_bitmap_init_by_type(struct cqm_handle_s *cqm_handle,
				   struct cqm_cla_table_s *cla_table,
				   struct cqm_bitmap_s *bitmap)
{
	struct hifc_hwdev *handle = cqm_handle->ex_handle;
	struct cqm_func_capability_s *capability = &cqm_handle->func_capability;
	s32 ret = CQM_SUCCESS;

	switch (cla_table->type) {
	case  CQM_BAT_ENTRY_T_QPC:
		bitmap->max_num = capability->qpc_number;
		bitmap->reserved_top = capability->qpc_reserved;
		bitmap->last = capability->qpc_reserved;
		cqm_info(handle->dev_hdl, "Bitmap init: cla_table_type=%u, max_num=0x%x\n",
			 cla_table->type, bitmap->max_num);
		ret = __cqm_bitmap_init(bitmap);
		break;
	case  CQM_BAT_ENTRY_T_MPT:
		bitmap->max_num = capability->mpt_number;
		bitmap->reserved_top = capability->mpt_reserved;
		bitmap->last = capability->mpt_reserved;
		cqm_info(handle->dev_hdl, "Bitmap init: cla_table_type=%u, max_num=0x%x\n",
			 cla_table->type, bitmap->max_num);
		ret = __cqm_bitmap_init(bitmap);
		break;
	case  CQM_BAT_ENTRY_T_SCQC:
		bitmap->max_num = capability->scqc_number;
		bitmap->reserved_top = capability->scq_reserved;
		bitmap->last = capability->scq_reserved;
		cqm_info(handle->dev_hdl, "Bitmap init: cla_table_type=%u, max_num=0x%x\n",
			 cla_table->type, bitmap->max_num);
		ret = __cqm_bitmap_init(bitmap);
		break;
	case  CQM_BAT_ENTRY_T_SRQC:
		bitmap->max_num = capability->srqc_number;
		bitmap->reserved_top = 0;
		bitmap->last = 0;
		cqm_info(handle->dev_hdl, "Bitmap init: cla_table_type=%u, max_num=0x%x\n",
			 cla_table->type, bitmap->max_num);
		ret = __cqm_bitmap_init(bitmap);
		break;
	default:
		break;
	}

	return ret;
}

/**
 * cqm_bitmap_init - Initialize a bitmap
 * @cqm_handle: cqm handle
 * Return: 0 - success, negative - failure
 */
s32 cqm_bitmap_init(struct cqm_handle_s *cqm_handle)
{
	struct hifc_hwdev *handle = cqm_handle->ex_handle;
	struct cqm_bat_table_s *bat_table = &cqm_handle->bat_table;
	struct cqm_cla_table_s *cla_table = NULL;
	struct cqm_bitmap_s *bitmap = NULL;
	u32 i = 0;
	s32 ret = CQM_SUCCESS;

	for (i = 0; i < CQM_BAT_ENTRY_MAX; i++) {
		cla_table = &bat_table->entry[i];
		if (cla_table->obj_num == 0) {
			cqm_info(handle->dev_hdl, "Cla alloc: cla_type %u, obj_num=0, don't init bitmap\n",
				 cla_table->type);
			continue;
		}

		bitmap = &cla_table->bitmap;
		ret = cqm_bitmap_init_by_type(cqm_handle, cla_table, bitmap);
		if (ret != CQM_SUCCESS) {
			cqm_err(handle->dev_hdl, "Bitmap init: failed to init cla_table_type=%u, obj_num=0x%x\n",
				cla_table->type, cla_table->obj_num);
				goto err;
		}
	}

	return CQM_SUCCESS;

err:
	cqm_bitmap_uninit(cqm_handle);
	return CQM_FAIL;
}

/**
 * cqm_bitmap_uninit - Uninitialize a bitmap
 * @cqm_handle: cqm handle
 */
void cqm_bitmap_uninit(struct cqm_handle_s *cqm_handle)
{
	struct cqm_bat_table_s *bat_table = &cqm_handle->bat_table;
	struct cqm_cla_table_s *cla_table = NULL;
	struct cqm_bitmap_s *bitmap = NULL;
	u32 i = 0;

	for (i = 0; i < CQM_BAT_ENTRY_MAX; i++) {
		cla_table = &bat_table->entry[i];
		bitmap = &cla_table->bitmap;
		if (cla_table->type != CQM_BAT_ENTRY_T_INVALID) {
			if (bitmap->table) {
				vfree(bitmap->table);
				bitmap->table = NULL;
			}
		}
	}
}

/**
 * cqm_bitmap_check_range - Starting from begin, check whether count bits are
 * free in the table, required: 1. This set of bits cannot cross step, 2. This
 * group of bits must be 0
 * @table: bitmap table
 * @step: steps
 * @max_num: max num
 * @begin: begin position
 * @count: the count of bit to check
 * Return: If check valid return begin position
 */
u32 cqm_bitmap_check_range(const ulong *table, u32 step,
			   u32 max_num, u32 begin, u32 count)
{
	u32 i = 0;
	u32 end = (begin + (count - 1));

	/* Single bit is not checked */
	if (count == 1)
		return begin;

	/* End is out of bounds */
	if (end >= max_num)
		return max_num;

	/* Bit check, if there is a bit other than 0, return next bit */
	for (i = (begin + 1); i <= end; i++) {
		if (test_bit((s32)i, table))
			return i + 1;
	}

	/* Check if it is in a different step */
	if ((begin & (~(step - 1))) != (end & (~(step - 1))))
		return (end & (~(step - 1)));

	/* If check pass, return begin position */
	return begin;
}

static void cqm_bitmap_set_bit(struct cqm_bitmap_s *bitmap, u32 index,
			       u32 max_num, u32 count, bool update_last,
			       ulong *table)
{
	u32 i;

	/* Set 1 to the found bit and reset last */
	if (index < max_num) {
		for (i = index; i < (index + count); i++)
			set_bit(i, table);

		if (update_last) {
			bitmap->last = (index + count);
			if (bitmap->last >= bitmap->max_num)
				bitmap->last = bitmap->reserved_top;
		}
	}
}

/**
 * cqm_bitmap_alloc - Allocate a bitmap index, 0 and 1 should not be used, Scan
 * back from the place where you last applied, and needs to support the
 * application of a series of consecutive indexes, and should not to cross trunk
 * @table: bitmap table
 * @step: steps
 * @count: the count of bit to check
 * @update_last: update last
 * Return: Success - return the index, failure - return the max
 */
u32 cqm_bitmap_alloc(struct cqm_bitmap_s *bitmap, u32 step, u32 count,
		     bool update_last)
{
	u32 index = 0;
	u32 max_num = bitmap->max_num;
	u32 last = bitmap->last;
	ulong *table = bitmap->table;

	spin_lock(&bitmap->lock);

	/* Search for a free bit from the last position */
	do {
		index = find_next_zero_bit(table, max_num, last);
		if (index < max_num) {
			last = cqm_bitmap_check_range(table, step,
						      max_num, index, count);
		} else {
			break;
		}
	} while (last != index);

	/* The above search failed, search for a free bit from the beginning */
	if (index >= max_num) {
		last = bitmap->reserved_top;
		do {
			index = find_next_zero_bit(table, max_num, last);
			if (index < max_num) {
				last = cqm_bitmap_check_range(table, step,
							      max_num,
							      index, count);
			} else {
				break;
			}
		} while (last != index);
	}
	cqm_bitmap_set_bit(bitmap, index, max_num, count, update_last, table);
	spin_unlock(&bitmap->lock);
	return index;
}

/**
 * cqm_bitmap_alloc_reserved - Allocate the reserve bit according to index
 * @bitmap: bitmap table
 * @count: count
 * @index: the index of bitmap
 * Return: Success - return the index, failure - return the max
 */
u32 cqm_bitmap_alloc_reserved(struct cqm_bitmap_s *bitmap, u32 count, u32 index)
{
	ulong *table = bitmap->table;
	u32 ret_index = CQM_INDEX_INVALID;

	if ((index >= bitmap->reserved_top) || (index >= bitmap->max_num) ||
	    (count != 1)) {
		return CQM_INDEX_INVALID;
	}

	spin_lock(&bitmap->lock);

	if (test_bit(index, table)) {
		ret_index = CQM_INDEX_INVALID;
	} else {
		set_bit(index, table);
		ret_index = index;
	}

	spin_unlock(&bitmap->lock);
	return ret_index;
}

/**
 * cqm_bitmap_free - Release a bitmap index
 * @bitmap: bitmap table
 * @index: the index of bitmap
 * @count: count
 */
void cqm_bitmap_free(struct cqm_bitmap_s *bitmap, u32 index, u32 count)
{
	ulong i = 0;

	spin_lock(&bitmap->lock);

	for (i = index; i < (index + count); i++)
		clear_bit((s32)i, bitmap->table);

	spin_unlock(&bitmap->lock);
}

#define obj_table_section

/**
 * _cqm_object_table_init - Initialize a table of object and index
 * @cqm_handle: cqm handle
 * Return: 0 - success, negative - failure
 */
s32 __cqm_object_table_init(struct cqm_object_table_s *obj_table)
{
	rwlock_init(&obj_table->lock);

	obj_table->table = (struct cqm_object_s **)vmalloc(obj_table->max_num *
							   sizeof(void *));
	CQM_PTR_CHECK_RET(obj_table->table, return CQM_FAIL,
			  CQM_ALLOC_FAIL(table));
	memset(obj_table->table, 0, obj_table->max_num * sizeof(void *));
	return CQM_SUCCESS;
}

/**
 * cqm_object_table_init - Initialize the association table of object and index
 * @cqm_handle: cqm handle
 * Return: 0 - success, negative - failure
 */
s32 cqm_object_table_init(struct cqm_handle_s *cqm_handle)
{
	struct hifc_hwdev *handle = cqm_handle->ex_handle;
	struct cqm_func_capability_s *capability = &cqm_handle->func_capability;
	struct cqm_bat_table_s *bat_table = &cqm_handle->bat_table;
	struct cqm_cla_table_s *cla_table = NULL;
	struct cqm_object_table_s *obj_table = NULL;
	s32 ret = CQM_SUCCESS;
	u32 i = 0;

	for (i = 0; i < CQM_BAT_ENTRY_MAX; i++) {
		cla_table = &bat_table->entry[i];
		if (cla_table->obj_num == 0) {
			cqm_info(handle->dev_hdl,
				 "Obj table init: cla_table_type %u, obj_num=0, don't init obj table\n",
				 cla_table->type);
			continue;
		}

		obj_table = &cla_table->obj_table;

		switch (cla_table->type) {
		case  CQM_BAT_ENTRY_T_QPC:
			obj_table->max_num = capability->qpc_number;
			ret = __cqm_object_table_init(obj_table);
			break;
		case  CQM_BAT_ENTRY_T_MPT:
			obj_table->max_num = capability->mpt_number;
			ret = __cqm_object_table_init(obj_table);
			break;
		case  CQM_BAT_ENTRY_T_SCQC:
			obj_table->max_num = capability->scqc_number;
			ret = __cqm_object_table_init(obj_table);
			break;
		case  CQM_BAT_ENTRY_T_SRQC:
			obj_table->max_num = capability->srqc_number;
			ret = __cqm_object_table_init(obj_table);
			break;
		default:
			break;
		}

		if (ret != CQM_SUCCESS) {
			cqm_err(handle->dev_hdl,
				"Obj table init: failed to init cla_table_type=%u, obj_num=0x%x\n",
				cla_table->type, cla_table->obj_num);
			goto err;
		}
	}

	return CQM_SUCCESS;

err:
	cqm_object_table_uninit(cqm_handle);
	return CQM_FAIL;
}

/**
 * cqm_object_table_uninit - Deinitialize the association table of object and
 * index
 * @cqm_handle: cqm handle
 */
void cqm_object_table_uninit(struct cqm_handle_s *cqm_handle)
{
	struct cqm_bat_table_s *bat_table = &cqm_handle->bat_table;
	struct cqm_cla_table_s *cla_table = NULL;
	struct cqm_object_table_s *obj_table = NULL;
	u32 i = 0;

	for (i = 0; i < CQM_BAT_ENTRY_MAX; i++) {
		cla_table = &bat_table->entry[i];
		obj_table = &cla_table->obj_table;
		if (cla_table->type != CQM_BAT_ENTRY_T_INVALID) {
			if (obj_table->table) {
				vfree(obj_table->table);
				obj_table->table = NULL;
			}
		}
	}
}

/**
 * cqm_object_table_insert - Insert an object, turn off the soft interrupt
 * @cqm_handle: cqm handle
 * @object_table: object table
 * @index: the index of table
 * @obj: the object to insert
 * Return: 0 - success, negative - failure
 */
s32 cqm_object_table_insert(struct cqm_handle_s *cqm_handle,
			    struct cqm_object_table_s *object_table, u32 index,
			    struct cqm_object_s *obj)
{
	struct hifc_hwdev *handle = cqm_handle->ex_handle;

	if (index >= object_table->max_num) {
		cqm_err(handle->dev_hdl, "Obj table insert: index 0x%x exceeds max_num 0x%x\n",
			index, object_table->max_num);
		return CQM_FAIL;
	}

	write_lock(&object_table->lock);

	if (!object_table->table[index]) {
		object_table->table[index] = obj;
		write_unlock(&object_table->lock);
		return CQM_SUCCESS;
	}
	write_unlock(&object_table->lock);
	cqm_err(handle->dev_hdl, "Obj table insert: object_table->table[0x%x] has been inserted\n",
		index);
	return CQM_FAIL;
}

/**
 * cqm_object_table_remove - remove an object
 * @cqm_handle: cqm handle
 * @object_table: object table
 * @index: the index of table
 * @obj: the object to remove
 * Return: 0 - success, negative - failure
 */
void cqm_object_table_remove(struct cqm_handle_s *cqm_handle,
			     struct cqm_object_table_s *object_table,
			     u32 index, const struct cqm_object_s *obj)
{
	struct hifc_hwdev *handle = cqm_handle->ex_handle;

	if (index >= object_table->max_num) {
		cqm_err(handle->dev_hdl, "Obj table remove: index 0x%x exceeds max_num 0x%x\n",
			index, object_table->max_num);
		return;
	}

	write_lock(&object_table->lock);

	if ((object_table->table[index]) &&
	    (object_table->table[index] == obj)) {
		object_table->table[index] = NULL;
	} else {
		cqm_err(handle->dev_hdl, "Obj table remove: object_table->table[0x%x] has been removed\n",
			index);
	}

	write_unlock(&object_table->lock);
}

/**
 * cqm_srq_used_rq_delete - Delete rq in TOE SRQ mode
 * @object: cqm object
 */
void cqm_srq_used_rq_delete(struct cqm_object_s *object)
{
	struct cqm_queue_s *common = container_of(object, struct cqm_queue_s,
						  object);
	struct cqm_nonrdma_qinfo_s *qinfo = container_of(
						common,
						struct cqm_nonrdma_qinfo_s,
						common);
	u32 link_wqe_offset = qinfo->wqe_per_buf * qinfo->wqe_size;
	struct cqm_srq_linkwqe_s *srq_link_wqe = NULL;
	dma_addr_t addr;
	struct cqm_handle_s *cqm_handle = (struct cqm_handle_s *)
					  (common->object.cqm_handle);
	struct hifc_hwdev *handle = cqm_handle->ex_handle;

	/* The current SRQ solution does not support the case where RQ
	 * initialization without container, which may cause error when RQ
	 * resources are released. So RQ initializes with only one container,
	 * and releases only one contaienr when resourced are released.
	 */
	CQM_PTR_CHECK_NO_RET(
		common->head_container, "Rq del: rq has no contianer to release\n",
		return);

	/* Get current container pa from link wqe, and ummap it */
	srq_link_wqe = (struct cqm_srq_linkwqe_s *)(common->head_container +
		       link_wqe_offset);
	/* Convert only the big endian of the wqe part of the link */
	cqm_swab32((u8 *)(srq_link_wqe), sizeof(struct cqm_linkwqe_s) >> 2);

	addr = CQM_ADDR_COMBINE(srq_link_wqe->current_buffer_gpa_h,
				srq_link_wqe->current_buffer_gpa_l);
	if (addr == 0) {
		cqm_err(handle->dev_hdl, "Rq del: buffer physical addr is null\n");
		return;
	}
	pci_unmap_single(cqm_handle->dev, addr, qinfo->container_size,
			 PCI_DMA_BIDIRECTIONAL);

	/* Get current container va from link wqe, and free it */
	addr = CQM_ADDR_COMBINE(srq_link_wqe->current_buffer_addr_h,
				srq_link_wqe->current_buffer_addr_l);
	if (addr == 0) {
		cqm_err(handle->dev_hdl, "Rq del: buffer virtual addr is null\n");
		return;
	}
	kfree((void *)addr);
}

#define obj_intern_if_section

/**
 * cqm_qpc_mpt_bitmap_alloc - Apply index from bitmap when creating qpc or mpt
 * @object: cqm object
 * @cla_table: cla table
 * Return: 0 - success, negative - failure
 */
s32 cqm_qpc_mpt_bitmap_alloc(struct cqm_object_s *object,
			     struct cqm_cla_table_s *cla_table)
{
	struct cqm_handle_s *cqm_handle = (struct cqm_handle_s *)
					   object->cqm_handle;
	struct hifc_hwdev *handle = cqm_handle->ex_handle;
	struct cqm_qpc_mpt_s *common = container_of(object,
						    struct cqm_qpc_mpt_s,
						    object);
	struct cqm_qpc_mpt_info_s *qpc_mpt_info =
						container_of(
						common,
						struct cqm_qpc_mpt_info_s,
						common);
	struct cqm_bitmap_s *bitmap = &cla_table->bitmap;
	u32 index = 0;
	u32 count = 0;

	count = (ALIGN(object->object_size, cla_table->obj_size)) /
		cla_table->obj_size;
	qpc_mpt_info->index_count = count;

	if (qpc_mpt_info->common.xid == CQM_INDEX_INVALID) {
		/* Allocate index normally */
		index = cqm_bitmap_alloc(
				bitmap,
				1 << (cla_table->z + 1),
				count,
				cqm_handle->func_capability.xid_alloc_mode);
		if (index < bitmap->max_num) {
			qpc_mpt_info->common.xid = index;
		} else {
			cqm_err(handle->dev_hdl,
				CQM_FUNCTION_FAIL(cqm_bitmap_alloc));
			return CQM_FAIL;
		}
	} else {
		/* Allocate reserved index */
		index = cqm_bitmap_alloc_reserved(
						bitmap, count,
						qpc_mpt_info->common.xid);
		if (index != qpc_mpt_info->common.xid) {
			cqm_err(handle->dev_hdl,
				CQM_FUNCTION_FAIL(cqm_bitmap_alloc_reserved));
			return CQM_FAIL;
		}
	}

	return CQM_SUCCESS;
}

static struct cqm_cla_table_s *cqm_qpc_mpt_prepare_cla_table(
						struct cqm_object_s *object)
{
	struct cqm_handle_s *cqm_handle = (struct cqm_handle_s *)
					   object->cqm_handle;
	struct hifc_hwdev *handle = cqm_handle->ex_handle;
	struct cqm_bat_table_s *bat_table = &cqm_handle->bat_table;

	struct cqm_cla_table_s *cla_table = NULL;

	/* Get the corresponding cla table */
	if (object->object_type == CQM_OBJECT_SERVICE_CTX) {
		cla_table = cqm_cla_table_get(bat_table, CQM_BAT_ENTRY_T_QPC);
	} else {
		cqm_err(handle->dev_hdl, CQM_WRONG_VALUE(object->object_type));
		return NULL;
	}

	CQM_PTR_CHECK_RET(cla_table, return NULL,
			  CQM_FUNCTION_FAIL(cqm_cla_table_get));

	/* Allocate index for bitmap */
	if (cqm_qpc_mpt_bitmap_alloc(object, cla_table) == CQM_FAIL) {
		cqm_err(handle->dev_hdl,
			CQM_FUNCTION_FAIL(cqm_qpc_mpt_bitmap_alloc));
		return NULL;
	}

	return cla_table;
}

/**
 * cqm_qpc_mpt_create - Create qpc or mpt
 * @object: cqm object
 * Return: 0 - success, negative - failure
 */
s32 cqm_qpc_mpt_create(struct cqm_object_s *object)
{
	struct cqm_handle_s *cqm_handle = (struct cqm_handle_s *)
					  object->cqm_handle;
	struct hifc_hwdev *handle = cqm_handle->ex_handle;
	struct cqm_qpc_mpt_s *common =
			container_of(object, struct cqm_qpc_mpt_s, object);
	struct cqm_qpc_mpt_info_s *qpc_mpt_info =
			container_of(common, struct cqm_qpc_mpt_info_s, common);
	struct cqm_cla_table_s *cla_table = NULL;
	struct cqm_bitmap_s *bitmap = NULL;
	struct cqm_object_table_s *object_table = NULL;
	u32 index = 0;
	u32 count = 0;

	cla_table = cqm_qpc_mpt_prepare_cla_table(object);
	CQM_PTR_CHECK_RET(cla_table, return CQM_FAIL,
			  CQM_FUNCTION_FAIL(cqm_qpc_mpt_prepare_cla_table));

	bitmap = &cla_table->bitmap;
	index = qpc_mpt_info->common.xid;
	count = qpc_mpt_info->index_count;

	/* Find the trunk page from BAT/CLA and allocate the buffer, the
	 * business needs to ensure that the released buffer has been cleared
	 */
	if (cla_table->alloc_static == true) {
		qpc_mpt_info->common.vaddr =
			cqm_static_qpc_cla_get(cqm_handle, cla_table,
					       index, count, &common->paddr);
	} else {
		qpc_mpt_info->common.vaddr =
			cqm_cla_get(cqm_handle, cla_table,
				    index, count, &common->paddr);
	}
	if (!qpc_mpt_info->common.vaddr) {
		cqm_err(handle->dev_hdl, CQM_FUNCTION_FAIL(cqm_cla_get));
		cqm_err(handle->dev_hdl,
			"Qpc mpt init: qpc mpt vaddr is null, cla_table->alloc_static=%d\n",
			cla_table->alloc_static);
		goto err1;
	}

	/* Associate index with object, FC executes in interrupt context */
	object_table = &cla_table->obj_table;

	if (cqm_object_table_insert(cqm_handle, object_table, index, object) !=
	    CQM_SUCCESS) {
		cqm_err(handle->dev_hdl,
			CQM_FUNCTION_FAIL(cqm_object_table_insert));
		goto err2;
	}

	return CQM_SUCCESS;

err2:
	cqm_cla_put(cqm_handle, cla_table, index, count);
err1:
	cqm_bitmap_free(bitmap, index, count);
	return CQM_FAIL;
}

/**
 * cqm_qpc_mpt_delete - Delete qpc or mpt
 * @object: cqm object
 */
void cqm_qpc_mpt_delete(struct cqm_object_s *object)
{
	struct cqm_handle_s *cqm_handle = (struct cqm_handle_s *)
					  object->cqm_handle;
	struct hifc_hwdev *handle = cqm_handle->ex_handle;
	struct cqm_qpc_mpt_s *common = container_of(object,
						    struct cqm_qpc_mpt_s,
						    object);
	struct cqm_qpc_mpt_info_s *qpc_mpt_info = container_of(
						common,
						struct cqm_qpc_mpt_info_s,
						common);
	struct cqm_bat_table_s *bat_table = &cqm_handle->bat_table;
	struct cqm_cla_table_s *cla_table = NULL;
	struct cqm_bitmap_s *bitmap = NULL;
	struct cqm_object_table_s *object_table = NULL;
	u32 index = qpc_mpt_info->common.xid;
	u32 count = qpc_mpt_info->index_count;

	/* Find the response cla table */
	atomic_inc(&cqm_handle->ex_handle->hw_stats.cqm_stats.cqm_qpc_mpt_delete_cnt);

	if (object->object_type == CQM_OBJECT_SERVICE_CTX) {
		cla_table = cqm_cla_table_get(bat_table, CQM_BAT_ENTRY_T_QPC);
	} else {
		cqm_err(handle->dev_hdl, CQM_WRONG_VALUE(object->object_type));
		return;
	}

	CQM_PTR_CHECK_NO_RET(
		cla_table, CQM_FUNCTION_FAIL(cqm_cla_table_get), return);

	/* Disassociate index with object */
	object_table = &cla_table->obj_table;

	cqm_object_table_remove(cqm_handle, object_table, index, object);

	/* Wait for the completion and ensure that all references to the QPC
	 * are completed
	 */
	if (atomic_dec_and_test(&object->refcount)) {
		complete(&object->free);
	} else {
		cqm_err(handle->dev_hdl,
			"Qpc mpt del: object is referred by others, has to wait for completion\n");
	}

	/* The QPC static allocation needs to be non-blocking, and the service
	 * guarantees that the QPC is completed when the QPC is deleted
	 */
	if (cla_table->alloc_static == false)
		wait_for_completion(&object->free);
	/* Free qpc buffer */
	cqm_cla_put(cqm_handle, cla_table, index, count);

	/* Free index into bitmap */
	bitmap = &cla_table->bitmap;
	cqm_bitmap_free(bitmap, index, count);
}

/**
 * cqm_linkwqe_fill - Fill link wqe for non RDMA queue buffer
 * @buf: cqm buffer
 * @wqe_per_buf: not include link wqe
 * @wqe_size: wqe size
 * @wqe_number: not include link wqe
 * @tail: true linkwqe must be at the tail, false linkwqe may not be at the tail
 * @link_mode: link wqe mode
 */
void cqm_linkwqe_fill(struct cqm_buf_s *buf,
		      u32 wqe_per_buf,
		      u32 wqe_size,
		      u32 wqe_number,
		      bool tail,
		      u8 link_mode)
{
	struct cqm_linkwqe_s *wqe = NULL;
	struct cqm_linkwqe_128b_s *linkwqe = NULL;
	u8 *va = NULL;
	u32 i = 0;
	dma_addr_t addr;

	/* Except for the last buffer, the linkwqe of other buffers is directly
	 * filled to the tail
	 */
	for (i = 0; i < buf->buf_number; i++) {
		va = (u8 *)(buf->buf_list[i].va);

		if (i != (buf->buf_number - 1)) {
			wqe = (struct cqm_linkwqe_s *)(va + (u32)(wqe_size *
								wqe_per_buf));
			wqe->wf = CQM_WQE_WF_LINK;
			wqe->ctrlsl = CQM_LINK_WQE_CTRLSL_VALUE;
			wqe->lp = CQM_LINK_WQE_LP_INVALID;
			/* The Obit of valid link wqe needs to be set to 1, and
			 * each service needs to confirm that o-bit=1 means
			 * valid, o-bit=0 means invalid
			 */
			wqe->o = CQM_LINK_WQE_OWNER_VALID;
			addr = buf->buf_list[(u32)(i + 1)].pa;
			wqe->next_page_gpa_h = CQM_ADDR_HI(addr);
			wqe->next_page_gpa_l = CQM_ADDR_LW(addr);
		} else {
		/* The last buffer of Linkwqe must fill specially */
			if (tail == true) {
				/* Must be filled at the end of the page */
				wqe = (struct cqm_linkwqe_s *)(va +
				      (u32)(wqe_size * wqe_per_buf));
			} else {
				/* The last linkwqe is filled immediately after
				 * the last wqe
				 */
				wqe = (struct cqm_linkwqe_s *)
				      (va + (u32)(wqe_size *
				      (wqe_number - wqe_per_buf *
				      (buf->buf_number - 1))));
			}
			wqe->wf = CQM_WQE_WF_LINK;
			wqe->ctrlsl = CQM_LINK_WQE_CTRLSL_VALUE;

			/* In link mode, the last link wqe is invalid, In ring
			 * mode, the last link wqe is valid, pointing to the
			 * home page, and lp is set
			 */
			if (link_mode == CQM_QUEUE_LINK_MODE) {
				wqe->o = CQM_LINK_WQE_OWNER_INVALID;
			} else {
				/* The lp field of the last link_wqe is filled
				 * with 1,indicating that the o-bit is flipped
				 * from here
				 */
				wqe->lp = CQM_LINK_WQE_LP_VALID;
				wqe->o = CQM_LINK_WQE_OWNER_VALID;
				addr = buf->buf_list[0].pa;
				wqe->next_page_gpa_h = CQM_ADDR_HI(addr);
				wqe->next_page_gpa_l = CQM_ADDR_LW(addr);
			}
		}

		if (wqe_size == 128) {
		/* The 128B wqe before and after 64B have obit need to be
		 * assigned, For IFOE, 63th penultimate bit of last 64B is
		 * obit, for TOE, 157th penultimate bit of last 64B is obit
		 */
			linkwqe = (struct cqm_linkwqe_128b_s *)wqe;
			linkwqe->second_64b.third_16B.bs.toe_o =
						CQM_LINK_WQE_OWNER_VALID;
			linkwqe->second_64b.forth_16B.bs.ifoe_o =
						CQM_LINK_WQE_OWNER_VALID;

			/* big endian conversion */
			cqm_swab32((u8 *)wqe,
				   sizeof(struct cqm_linkwqe_128b_s) >> 2);
		} else {
			/* big endian conversion */
			cqm_swab32((u8 *)wqe,
				   sizeof(struct cqm_linkwqe_s) >> 2);
		}
	}
}

static s32 cqm_nonrdma_queue_ctx_create_srq(struct cqm_object_s *object)
{
	struct cqm_handle_s *cqm_handle = (struct cqm_handle_s *)
					  object->cqm_handle;
	struct hifc_hwdev *handle = cqm_handle->ex_handle;
	struct cqm_queue_s *common = container_of(object,
						  struct cqm_queue_s, object);
	struct cqm_nonrdma_qinfo_s *qinfo = container_of(
						common,
						struct cqm_nonrdma_qinfo_s,
						common);
	s32 shift = 0;

	shift = cqm_shift(qinfo->q_ctx_size);
	common->q_ctx_vaddr = (u8 *)cqm_kmalloc_align(
					qinfo->q_ctx_size,
					GFP_KERNEL | __GFP_ZERO,
					(u16)shift);
	if (!common->q_ctx_vaddr) {
		cqm_err(handle->dev_hdl, CQM_ALLOC_FAIL(q_ctx_vaddr));
		return CQM_FAIL;
	}

	common->q_ctx_paddr =
		pci_map_single(cqm_handle->dev, common->q_ctx_vaddr,
			       qinfo->q_ctx_size, PCI_DMA_BIDIRECTIONAL);
	if (pci_dma_mapping_error(cqm_handle->dev, common->q_ctx_paddr)) {
		cqm_err(handle->dev_hdl, CQM_MAP_FAIL(q_ctx_vaddr));
		cqm_kfree_align(common->q_ctx_vaddr);
		common->q_ctx_vaddr = NULL;
		return CQM_FAIL;
	}

	return CQM_SUCCESS;
}

static s32 cqm_nonrdma_queue_ctx_create_scq(struct cqm_object_s *object)
{
	struct cqm_handle_s *cqm_handle = (struct cqm_handle_s *)
					  object->cqm_handle;
	struct hifc_hwdev *handle = cqm_handle->ex_handle;
	struct cqm_queue_s *common = container_of(object,
						  struct cqm_queue_s,
						  object);
	struct cqm_nonrdma_qinfo_s *qinfo = container_of(
						common,
						struct cqm_nonrdma_qinfo_s,
						common);
	struct cqm_bat_table_s *bat_table = &cqm_handle->bat_table;
	struct cqm_cla_table_s *cla_table = NULL;
	struct cqm_bitmap_s *bitmap = NULL;
	struct cqm_object_table_s *object_table = NULL;

	/* Find the corresponding cla table */
	cla_table = cqm_cla_table_get(bat_table, CQM_BAT_ENTRY_T_SCQC);
	if (!cla_table) {
		cqm_err(handle->dev_hdl, CQM_FUNCTION_FAIL(cqm_cla_table_get));
		return CQM_FAIL;
	}

	/* Allocate index for bitmap */
	bitmap = &cla_table->bitmap;
	qinfo->index_count = (ALIGN(qinfo->q_ctx_size, cla_table->obj_size)) /
			     cla_table->obj_size;
	qinfo->common.index = cqm_bitmap_alloc(bitmap, 1 << (cla_table->z + 1),
	qinfo->index_count, cqm_handle->func_capability.xid_alloc_mode);
	if (qinfo->common.index >= bitmap->max_num) {
		cqm_err(handle->dev_hdl, CQM_FUNCTION_FAIL(cqm_bitmap_alloc));
		return CQM_FAIL;
	}

	/* Find the trunk page from BAT/CLA and allocate buffer */
	common->q_ctx_vaddr = cqm_cla_get(cqm_handle, cla_table,
					  qinfo->common.index,
					  qinfo->index_count,
					  &common->q_ctx_paddr);
	if (!common->q_ctx_vaddr) {
		cqm_err(handle->dev_hdl, CQM_FUNCTION_FAIL(cqm_cla_get));
		cqm_bitmap_free(bitmap, qinfo->common.index,
				qinfo->index_count);
		return CQM_FAIL;
	}

	/* Associate index with object */
	object_table = &cla_table->obj_table;

	if (cqm_object_table_insert(
		cqm_handle, object_table,
		qinfo->common.index, object) != CQM_SUCCESS) {
		cqm_err(handle->dev_hdl,
			CQM_FUNCTION_FAIL(cqm_object_table_insert));
		cqm_cla_put(cqm_handle, cla_table, qinfo->common.index,
			    qinfo->index_count);
		cqm_bitmap_free(bitmap, qinfo->common.index,
				qinfo->index_count);
		return CQM_FAIL;
	}

	return CQM_SUCCESS;
}

s32 cqm_nonrdma_queue_ctx_create(struct cqm_object_s *object)
{
	if (object->object_type == CQM_OBJECT_NONRDMA_SRQ)
		return cqm_nonrdma_queue_ctx_create_srq(object);
	else if (object->object_type == CQM_OBJECT_NONRDMA_SCQ)
		return cqm_nonrdma_queue_ctx_create_scq(object);

	return CQM_SUCCESS;
}

#define CQM_NORDMA_CHECK_WEQ_NUMBER(number) \
	(((number) < CQM_CQ_DEPTH_MIN) || ((number) > CQM_CQ_DEPTH_MAX))

/**
 * cqm_nonrdma_queue_create - Create queue for non RDMA service
 * @buf: cqm object
 * Return: 0 - success, negative - failure
 */
s32 cqm_nonrdma_queue_create(struct cqm_object_s *object)
{
	struct cqm_handle_s *cqm_handle = (struct cqm_handle_s *)
					  object->cqm_handle;
	struct hifc_hwdev *handle = cqm_handle->ex_handle;
	struct cqm_service_s *service = &cqm_handle->service;
	struct cqm_queue_s *common = container_of(object,
						  struct cqm_queue_s,
						  object);
	struct cqm_nonrdma_qinfo_s *qinfo = container_of(
						common,
						struct cqm_nonrdma_qinfo_s,
						common);
	struct cqm_buf_s *q_room_buf = &common->q_room_buf_1;
	u32 wqe_number = qinfo->common.object.object_size;
	u32 wqe_size = qinfo->wqe_size;
	u32 order = service->buf_order;
	u32 buf_number = 0;
	u32 buf_size = 0;
	bool tail = false;     /* Whether linkwqe is at the end of the page */

	/* When creating CQ/SCQ queue, the page size is 4k, linkwqe must be at
	 * the end of the page
	 */
	if (object->object_type == CQM_OBJECT_NONRDMA_SCQ) {
		/* Depth must be 2^n alignment, depth range is 256~32K */
		if (CQM_NORDMA_CHECK_WEQ_NUMBER(wqe_number)) {
			cqm_err(handle->dev_hdl, CQM_WRONG_VALUE(wqe_number));
			return CQM_FAIL;
		}
		if (cqm_check_align(wqe_number) == false) {
			cqm_err(handle->dev_hdl, "Nonrdma queue alloc: wqe_number is not align on 2^n\n");
			return CQM_FAIL;
		}

		order = CQM_4K_PAGE_ORDER; /* wqe page is 4k */
		tail = true;  /* linkwqe must be at the end of the page */
		buf_size = CQM_4K_PAGE_SIZE;
	} else {
		buf_size = PAGE_SIZE << order;
	}

	/* Calculate how many buffers are required, -1 is to deduct link wqe in
	 * a buf
	 */
	qinfo->wqe_per_buf = (buf_size / wqe_size) - 1;
	/* The depth from service includes the number of linkwqe */
	buf_number = ALIGN((wqe_size * wqe_number), buf_size) / buf_size;
	/* Allocate cqm buffer */
	q_room_buf->buf_number = buf_number;
	q_room_buf->buf_size = buf_size;
	q_room_buf->page_number = (buf_number << order);
	if (cqm_buf_alloc(cqm_handle, q_room_buf, false) == CQM_FAIL) {
		cqm_err(handle->dev_hdl, CQM_FUNCTION_FAIL(cqm_buf_alloc));
		return CQM_FAIL;
	}
	/* Fill link wqe, (wqe_number - buf_number) is the number of wqe without
	 * linkwqe
	 */
	cqm_linkwqe_fill(q_room_buf, qinfo->wqe_per_buf, wqe_size,
			 wqe_number - buf_number, tail,
			 common->queue_link_mode);

	/* Create queue header */
	qinfo->common.q_header_vaddr =
		(struct cqm_queue_header_s *)cqm_kmalloc_align(
			sizeof(struct cqm_queue_header_s),
			GFP_KERNEL | __GFP_ZERO, CQM_QHEAD_ALIGN_ORDER);
	if (!qinfo->common.q_header_vaddr) {
		cqm_err(handle->dev_hdl, CQM_ALLOC_FAIL(q_header_vaddr));
		goto err1;
	}

	common->q_header_paddr =
			pci_map_single(cqm_handle->dev,
				       qinfo->common.q_header_vaddr,
				       sizeof(struct cqm_queue_header_s),
				       PCI_DMA_BIDIRECTIONAL);
	if (pci_dma_mapping_error(cqm_handle->dev, common->q_header_paddr)) {
		cqm_err(handle->dev_hdl, CQM_MAP_FAIL(q_header_vaddr));
		goto err2;
	}

	/* Create queue ctx */
	if (cqm_nonrdma_queue_ctx_create(object) == CQM_FAIL) {
		cqm_err(handle->dev_hdl,
			CQM_FUNCTION_FAIL(cqm_nonrdma_queue_ctx_create));
		goto err3;
	}

	return CQM_SUCCESS;

err3:
	pci_unmap_single(cqm_handle->dev, common->q_header_paddr,
			 sizeof(struct cqm_queue_header_s),
			 PCI_DMA_BIDIRECTIONAL);
err2:
	cqm_kfree_align(qinfo->common.q_header_vaddr);
	qinfo->common.q_header_vaddr = NULL;
err1:
	cqm_buf_free(q_room_buf, cqm_handle->dev);
	return CQM_FAIL;
}

static void cqm_nonrdma_queue_free_scq_srq(struct cqm_object_s *object,
					   struct cqm_cla_table_s *cla_table)
{
	struct cqm_handle_s *cqm_handle = (struct cqm_handle_s *)
					  object->cqm_handle;
	struct cqm_queue_s *common = container_of(object,
						  struct cqm_queue_s,
						  object);
	struct cqm_nonrdma_qinfo_s *qinfo =
		container_of(common, struct cqm_nonrdma_qinfo_s, common);
	struct cqm_buf_s *q_room_buf = &common->q_room_buf_1;
	u32 index = qinfo->common.index;
	u32 count = qinfo->index_count;
	struct cqm_bitmap_s *bitmap = NULL;

	/* If it is in TOE SRQ mode, delete the RQ */
	if (common->queue_link_mode == CQM_QUEUE_TOE_SRQ_LINK_MODE) {
		cqm_dbg("Nonrdma queue del: delete srq used rq\n");
		cqm_srq_used_rq_delete(&common->object);
	} else {
		/* Free it if exists q room */
		cqm_buf_free(q_room_buf, cqm_handle->dev);
	}
	/* Free SRQ or SCQ ctx */
	if (object->object_type == CQM_OBJECT_NONRDMA_SRQ) {
		/* ctx of nonrdma's SRQ is applied independently */
		if (common->q_ctx_vaddr) {
			pci_unmap_single(cqm_handle->dev, common->q_ctx_paddr,
					 qinfo->q_ctx_size,
					 PCI_DMA_BIDIRECTIONAL);

		    cqm_kfree_align(common->q_ctx_vaddr);
		    common->q_ctx_vaddr = NULL;
		}
	} else if (object->object_type == CQM_OBJECT_NONRDMA_SCQ) {
		/* The ctx of SCQ of nonrdma is managed by BAT/CLA */
		cqm_cla_put(cqm_handle, cla_table, index, count);

		/* Release index into bitmap */
		bitmap = &cla_table->bitmap;
		cqm_bitmap_free(bitmap, index, count);
	}
}

/**
 * cqm_nonrdma_queue_delete - Free queue for non RDMA service
 * @buf: cqm object
 */
void cqm_nonrdma_queue_delete(struct cqm_object_s *object)
{
	struct cqm_handle_s *cqm_handle = (struct cqm_handle_s *)
					  object->cqm_handle;
	struct hifc_hwdev *handle = cqm_handle->ex_handle;
	struct cqm_queue_s *common = container_of(object,
						  struct cqm_queue_s, object);
	struct cqm_nonrdma_qinfo_s *qinfo = container_of(
						common,
						struct cqm_nonrdma_qinfo_s,
						common);
	struct cqm_bat_table_s *bat_table = &cqm_handle->bat_table;
	struct cqm_cla_table_s *cla_table = NULL;
	struct cqm_object_table_s *object_table = NULL;
	u32 index = qinfo->common.index;

	atomic_inc(&cqm_handle->ex_handle->hw_stats.cqm_stats.cqm_nonrdma_queue_delete_cnt);

	/* SCQ has independent SCQN association */
	if (object->object_type == CQM_OBJECT_NONRDMA_SCQ) {
		cla_table = cqm_cla_table_get(bat_table, CQM_BAT_ENTRY_T_SCQC);
		CQM_PTR_CHECK_NO_RET(
				cla_table,
				CQM_FUNCTION_FAIL(cqm_cla_table_get),
				return);

		/* index and object disassociate */
		object_table = &cla_table->obj_table;

		cqm_object_table_remove(cqm_handle, object_table,
					index, object);
	}

	/* Wait for the completion and ensure that all references to the QPC
	 * are completed
	 */
	if (atomic_dec_and_test(&object->refcount))
		complete(&object->free);
	else
		cqm_err(handle->dev_hdl, "Nonrdma queue del: object is referred by others, has to wait for completion\n");
	wait_for_completion(&object->free);

	/* Free it if exists q header */
	if (qinfo->common.q_header_vaddr) {
		pci_unmap_single(cqm_handle->dev, common->q_header_paddr,
				 sizeof(struct cqm_queue_header_s),
				 PCI_DMA_BIDIRECTIONAL);

		cqm_kfree_align(qinfo->common.q_header_vaddr);
		qinfo->common.q_header_vaddr = NULL;
	}
	cqm_nonrdma_queue_free_scq_srq(object, cla_table);
}

#define obj_extern_if_section

/**
 * cqm_object_qpc_mpt_create - Create QPC and MPT
 * @ex_handle: hw dev handle
 * @service_type: service type
 * @object_type: must be mpt and ctx
 * @object_size: the unit is byte
 * @object_priv: the private structure for service, can be NULL
 * @index: get the reserved qpn based on this value, if wants to automatically
 *         allocate it, the value should be CQM_INDEX_INVALID
 * Return: service ctx
 */
struct cqm_qpc_mpt_s *cqm_object_qpc_mpt_create(
				void *ex_handle,
				enum cqm_object_type_e object_type,
				u32 object_size, void *object_priv,
				u32 index)
{
	struct hifc_hwdev *handle = (struct hifc_hwdev *)ex_handle;
	struct cqm_handle_s *cqm_handle = NULL;
	struct cqm_qpc_mpt_info_s *qpc_mpt_info = NULL;
	s32 ret = CQM_FAIL;

	CQM_PTR_CHECK_RET(ex_handle, return NULL, CQM_PTR_NULL(ex_handle));

	atomic_inc(&handle->hw_stats.cqm_stats.cqm_qpc_mpt_create_cnt);

	cqm_handle = (struct cqm_handle_s *)(handle->cqm_hdl);
	CQM_PTR_CHECK_RET(cqm_handle, return NULL, CQM_PTR_NULL(cqm_handle));

	/* If service does not register, returns NULL */
	if (cqm_handle->service.has_register == false) {
		cqm_err(handle->dev_hdl, "service is not register");
		return NULL;
	}

	if (object_type != CQM_OBJECT_SERVICE_CTX) {
		cqm_err(handle->dev_hdl, CQM_WRONG_VALUE(object_type));
		return NULL;
	}

	qpc_mpt_info = (struct cqm_qpc_mpt_info_s *)
		       kmalloc(sizeof(struct cqm_qpc_mpt_info_s),
			       GFP_ATOMIC | __GFP_ZERO);
	CQM_PTR_CHECK_RET(qpc_mpt_info, return NULL,
			  CQM_ALLOC_FAIL(qpc_mpt_info));

	qpc_mpt_info->common.object.object_type = object_type;
	qpc_mpt_info->common.object.object_size = object_size;
	atomic_set(&qpc_mpt_info->common.object.refcount, 1);
	init_completion(&qpc_mpt_info->common.object.free);
	qpc_mpt_info->common.object.cqm_handle = cqm_handle;
	qpc_mpt_info->common.xid = index;
	qpc_mpt_info->common.priv = object_priv;

	ret = cqm_qpc_mpt_create(&qpc_mpt_info->common.object);
	if (ret == CQM_SUCCESS)
		return &qpc_mpt_info->common;

	cqm_err(handle->dev_hdl, CQM_FUNCTION_FAIL(cqm_qpc_mpt_create));
	kfree(qpc_mpt_info);
	return NULL;
}

/**
 * cqm_object_fc_srq_create - Create RQ for FC, the number of valid wqe in the
 * queue must be meet the incoming wqe number. Because linkwqe can only be
 * filled at the end of the page, the actual effective number exceeds demand,
 * need to inform the number of business creation.
 * @ex_handle: hw dev handle
 * @service_type: service type
 * @object_type: must be CQM_OBJECT_NONRDMA_SRQ
 * @wqe_number: valid wqe number
 * @wqe_size: wqe size
 * @object_priv: the private structure for service
 * Return: srq structure
 */
struct cqm_queue_s *cqm_object_fc_srq_create(
				void *ex_handle,
				enum cqm_object_type_e object_type,
				u32 wqe_number, u32 wqe_size,
				void *object_priv)
{
	struct cqm_nonrdma_qinfo_s *nonrdma_qinfo = NULL;
	struct hifc_hwdev *handle = (struct hifc_hwdev *)ex_handle;
	struct cqm_handle_s *cqm_handle = NULL;
	struct cqm_service_s *service = NULL;
	u32 valid_wqe_per_buffer = 0;
	u32 wqe_sum = 0; /* includes linkwqe, normal wqe */
	u32 buf_size = 0;
	u32 buf_num = 0;
	s32 ret = CQM_FAIL;

	CQM_PTR_CHECK_RET(ex_handle, return NULL, CQM_PTR_NULL(ex_handle));

	atomic_inc(&handle->hw_stats.cqm_stats.cqm_fc_srq_create_cnt);

	cqm_handle = (struct cqm_handle_s *)(handle->cqm_hdl);
	CQM_PTR_CHECK_RET(cqm_handle, return NULL, CQM_PTR_NULL(cqm_handle));

	/* service_type must be FC */
	if (cqm_handle->service.has_register == false) {
		cqm_err(handle->dev_hdl, "service is not register\n");
		return NULL;
	}

	/* wqe_size can not exceed PAGE_SIZE and should not be 0, and must be
	 * 2^n aligned.
	 */
	if ((wqe_size >= PAGE_SIZE) || (cqm_check_align(wqe_size) == false)) {
		cqm_err(handle->dev_hdl, CQM_WRONG_VALUE(wqe_size));
		return NULL;
	}

	/* FC's RQ is SRQ (unlike TOE's SRQ, fc is that all packets received by
	 * the stream will be put on the same rq, and TOE's srq is similar to
	 * rq's resource pool)
	 */
	if (object_type != CQM_OBJECT_NONRDMA_SRQ) {
		cqm_err(handle->dev_hdl, CQM_WRONG_VALUE(object_type));
		return NULL;
	}

	service = &cqm_handle->service;
	buf_size = PAGE_SIZE << (service->buf_order);
	valid_wqe_per_buffer = buf_size / wqe_size - 1; /* Minus 1 link wqe */
	buf_num = wqe_number / valid_wqe_per_buffer;
	if (wqe_number % valid_wqe_per_buffer != 0)
		buf_num++;

	/* Calculate the total number of all wqe */
	wqe_sum = buf_num * (valid_wqe_per_buffer + 1);
	nonrdma_qinfo = (struct cqm_nonrdma_qinfo_s *)
			kmalloc(sizeof(struct cqm_nonrdma_qinfo_s),
				GFP_KERNEL | __GFP_ZERO);

	CQM_PTR_CHECK_RET(nonrdma_qinfo, return NULL,
			  CQM_ALLOC_FAIL(nonrdma_qinfo));

	/* Initialize object members */
	nonrdma_qinfo->common.object.object_type = object_type;
	/* The total number of all wqe */
	nonrdma_qinfo->common.object.object_size = wqe_sum;
	atomic_set(&nonrdma_qinfo->common.object.refcount, 1);
	init_completion(&nonrdma_qinfo->common.object.free);
	nonrdma_qinfo->common.object.cqm_handle = cqm_handle;

	/* Initialize the doorbell used by the current queue, default is the
	 * hardware doorbell
	 */
	nonrdma_qinfo->common.current_q_doorbell = CQM_HARDWARE_DOORBELL;
	nonrdma_qinfo->common.queue_link_mode = CQM_QUEUE_RING_MODE;

	/* Initialize external public members */
	nonrdma_qinfo->common.priv = object_priv;
	nonrdma_qinfo->common.valid_wqe_num = wqe_sum - buf_num;

	/* Initialize internal private members */
	nonrdma_qinfo->wqe_size = wqe_size;
	/* The SRQ for FC, which needs to create ctx */
	nonrdma_qinfo->q_ctx_size = service->service_template.srq_ctx_size;

	ret = cqm_nonrdma_queue_create(&nonrdma_qinfo->common.object);
	if (ret == CQM_SUCCESS)
		return &nonrdma_qinfo->common;
	cqm_err(handle->dev_hdl,
		CQM_FUNCTION_FAIL(cqm_nonrdma_queue_create));
	kfree(nonrdma_qinfo);
	return NULL;
}

static int cqm_object_nonrdma_queue_create_check(
					void *ex_handle,
					enum cqm_object_type_e object_type,
					u32 wqe_size)
{
	struct hifc_hwdev *handle = (struct hifc_hwdev *)ex_handle;
	struct cqm_handle_s *cqm_handle = NULL;

	CQM_PTR_CHECK_RET(ex_handle, return CQM_FAIL, CQM_PTR_NULL(ex_handle));

	atomic_inc(&handle->hw_stats.cqm_stats.cqm_nonrdma_queue_create_cnt);

	cqm_handle = (struct cqm_handle_s *)(handle->cqm_hdl);
	CQM_PTR_CHECK_RET(cqm_handle, return CQM_FAIL,
			  CQM_PTR_NULL(cqm_handle));

	/* If service does not register, returns NULL */
	if (cqm_handle->service.has_register == false) {
		cqm_err(handle->dev_hdl, "service is not register\n");
		return CQM_FAIL;
	}
	/* Wqe size cannot exceed PAGE_SIZE, cannot be 0, and must be 2^n
	 * aligned. cqm_check_align check excludes 0, 1, non 2^n alignment
	 */
	if ((wqe_size >= PAGE_SIZE) || (cqm_check_align(wqe_size) == false)) {
		cqm_err(handle->dev_hdl, CQM_WRONG_VALUE(wqe_size));
		return CQM_FAIL;
	}

	/* Supported Nonrdma queue: RQ, SQ, SRQ, CQ, SCQ */
	if ((object_type < CQM_OBJECT_NONRDMA_EMBEDDED_RQ) ||
	    (object_type > CQM_OBJECT_NONRDMA_SCQ)) {
		cqm_err(handle->dev_hdl, CQM_WRONG_VALUE(object_type));
		return CQM_FAIL;
	}

	return CQM_SUCCESS;
}

/**
 * cqm_object_nonrdma_queue_create - Create queues for non-RDMA services
 * @ex_handle: hw dev handle
 * @service_type: service type
 * @object_type: can create embedded RQ/SQ/CQ and SRQ/SCQ
 * @wqe_number: wqe number, including link wqe
 * @wqe_size: wqe size, nust be 2^n
 * @object_priv: the private structure for service, can be NULL
 * Return: srq structure
 */
struct cqm_queue_s *cqm_object_nonrdma_queue_create(
					void *ex_handle,
					enum cqm_object_type_e object_type,
					u32 wqe_number, u32 wqe_size,
					void *object_priv)
{
	struct hifc_hwdev *handle = (struct hifc_hwdev *)ex_handle;
	struct cqm_handle_s *cqm_handle = NULL;
	struct cqm_nonrdma_qinfo_s *nonrdma_qinfo = NULL;
	struct cqm_service_s *service = NULL;
	s32 ret = CQM_FAIL;

	cqm_handle = (struct cqm_handle_s *)(handle->cqm_hdl);
	if (cqm_object_nonrdma_queue_create_check(ex_handle,
						  object_type,
						  wqe_size) == CQM_FAIL) {
		return NULL;
	}

	nonrdma_qinfo = (struct cqm_nonrdma_qinfo_s *)
			kmalloc(sizeof(struct cqm_nonrdma_qinfo_s),
				GFP_KERNEL | __GFP_ZERO);
	CQM_PTR_CHECK_RET(nonrdma_qinfo, return NULL,
			  CQM_ALLOC_FAIL(nonrdma_qinfo));

	/* Initialize object members */
	nonrdma_qinfo->common.object.object_type = object_type;
	nonrdma_qinfo->common.object.object_size = wqe_number;
	atomic_set(&nonrdma_qinfo->common.object.refcount, 1);
	init_completion(&nonrdma_qinfo->common.object.free);
	nonrdma_qinfo->common.object.cqm_handle = cqm_handle;

	/* Initialize the doorbell used by the current queue, default is the
	 * hardware doorbell
	 */
	nonrdma_qinfo->common.current_q_doorbell = CQM_HARDWARE_DOORBELL;
	nonrdma_qinfo->common.queue_link_mode = CQM_QUEUE_RING_MODE;

	/* Initialize external public members */
	nonrdma_qinfo->common.priv = object_priv;

	/* Initialize internal private members */
	nonrdma_qinfo->wqe_size = wqe_size;
	service = &cqm_handle->service;
	switch (object_type) {
	case CQM_OBJECT_NONRDMA_SCQ:
		nonrdma_qinfo->q_ctx_size =
				service->service_template.scq_ctx_size;
		break;
	case CQM_OBJECT_NONRDMA_SRQ:
		/* The creation for SRQ uses a dedicated interface */
		nonrdma_qinfo->q_ctx_size =
				service->service_template.srq_ctx_size;
		break;
	default:
		break;
	}

	ret = cqm_nonrdma_queue_create(&nonrdma_qinfo->common.object);
	if (ret == CQM_SUCCESS)
		return &nonrdma_qinfo->common;

	cqm_err(handle->dev_hdl,
		CQM_FUNCTION_FAIL(cqm_nonrdma_queue_create));
	kfree(nonrdma_qinfo);
	return NULL;
}

s32 cqm_qpc_mpt_delete_ret(struct cqm_object_s *object)
{
	u32 object_type = 0;

	object_type = object->object_type;
	switch (object_type) {
	case  CQM_OBJECT_SERVICE_CTX:
		cqm_qpc_mpt_delete(object);
		return CQM_SUCCESS;
	default:
		return CQM_FAIL;
	}
}

s32 cqm_nonrdma_queue_delete_ret(struct cqm_object_s *object)
{
	u32 object_type = 0;

	object_type = object->object_type;
	switch (object_type) {
	case  CQM_OBJECT_NONRDMA_SCQ:
	case  CQM_OBJECT_NONRDMA_SRQ:
		cqm_nonrdma_queue_delete(object);
		return CQM_SUCCESS;
	default:
		return CQM_FAIL;
	}
}

/**
 * cqm_object_nonrdma_queue_create - Delete the created object, the function
 * will sleep and wait for all operations on the object to complete before
 * returning
 * @object: cqm object
 */
void cqm_object_delete(struct cqm_object_s *object)
{
	struct cqm_handle_s *cqm_handle = NULL;
	struct hifc_hwdev *handle = NULL;

	CQM_PTR_CHECK_NO_RET(object, CQM_PTR_NULL(object), return);
	if (!object->cqm_handle) {
		pr_err("[CQM]Obj del: cqm_handle is null, refcount %d\n",
		       (int)object->refcount.counter);
		kfree(object);
		return;
	}
	cqm_handle = (struct cqm_handle_s *)object->cqm_handle;

	if (!cqm_handle->ex_handle) {
		pr_err("[CQM]Obj del: ex_handle is null, refcount %d\n",
		       (int)object->refcount.counter);
		kfree(object);
		return;
	}
	handle = cqm_handle->ex_handle;

	if (cqm_qpc_mpt_delete_ret(object) == CQM_SUCCESS) {
		kfree(object);
		return;
	}

	if (cqm_nonrdma_queue_delete_ret(object) == CQM_SUCCESS) {
		kfree(object);
		return;
	}

	cqm_err(handle->dev_hdl, CQM_WRONG_VALUE(object->object_type));
	kfree(object);
}
