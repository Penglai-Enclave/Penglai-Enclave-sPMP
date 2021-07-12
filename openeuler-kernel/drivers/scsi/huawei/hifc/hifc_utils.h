/* SPDX-License-Identifier: GPL-2.0 */
/* Huawei Hifc PCI Express Linux driver
 * Copyright(c) 2017 Huawei Technologies Co., Ltd
 *
 */

#ifndef __HIFC_UTILS_H__
#define __HIFC_UTILS_H__

#define UNF_ZERO    0
#define HIFC_BIT(n) (0x1UL << (n))
#define HIFC_BIT_0  HIFC_BIT(0)
#define HIFC_BIT_1  HIFC_BIT(1)
#define HIFC_BIT_2  HIFC_BIT(2)
#define HIFC_BIT_3  HIFC_BIT(3)
#define HIFC_BIT_4  HIFC_BIT(4)
#define HIFC_BIT_5  HIFC_BIT(5)
#define HIFC_BIT_6  HIFC_BIT(6)
#define HIFC_BIT_7  HIFC_BIT(7)
#define HIFC_BIT_8  HIFC_BIT(8)
#define HIFC_BIT_9  HIFC_BIT(9)
#define HIFC_BIT_10 HIFC_BIT(10)
#define HIFC_BIT_11 HIFC_BIT(11)
#define HIFC_BIT_12 HIFC_BIT(12)
#define HIFC_BIT_13 HIFC_BIT(13)
#define HIFC_BIT_14 HIFC_BIT(14)
#define HIFC_BIT_15 HIFC_BIT(15)
#define HIFC_BIT_16 HIFC_BIT(16)
#define HIFC_BIT_17 HIFC_BIT(17)
#define HIFC_BIT_18 HIFC_BIT(18)
#define HIFC_BIT_19 HIFC_BIT(19)
#define HIFC_BIT_20 HIFC_BIT(20)
#define HIFC_BIT_21 HIFC_BIT(21)
#define HIFC_BIT_22 HIFC_BIT(22)
#define HIFC_BIT_23 HIFC_BIT(23)
#define HIFC_BIT_24 HIFC_BIT(24)
#define HIFC_BIT_25 HIFC_BIT(25)
#define HIFC_BIT_26 HIFC_BIT(26)
#define HIFC_BIT_27 HIFC_BIT(27)
#define HIFC_BIT_28 HIFC_BIT(28)
#define HIFC_BIT_29 HIFC_BIT(29)
#define HIFC_BIT_30 HIFC_BIT(30)
#define HIFC_BIT_31 HIFC_BIT(31)

#define HIFC_GET_BITS(data, mask) ((data) & (mask))   /* Obtains the bit */
#define HIFC_SET_BITS(data, mask) ((data) |= (mask))  /* set the bit */
#define HIFC_CLR_BITS(data, mask) ((data) &= ~(mask)) /* clear the bit */

/* Byte alignment */
#define HIFC_ALIGN_N(n) __attribute__((__packed, __aligned(n)))
#define HIFC_ALIGN_1    HIFC_ALIGN_N(1)
#define HIFC_ALIGN_2    HIFC_ALIGN_N(2)
#define HIFC_ALIGN_4    HIFC_ALIGN_N(4)
#define HIFC_ALIGN_8    HIFC_ALIGN_N(8)

#define HIFC_ADJUST_ALIGN_4(n) ((n) - (n) % 4)

#define HIFC_LSB(x) ((unsigned char)(x))
#define HIFC_MSB(x) ((unsigned char)((unsigned short)(x) >> 8))

#define HIFC_LSW(x) ((unsigned short)(x))
#define HIFC_MSW(x) ((unsigned short)((unsigned int)(x) >> 16))

#define HIFC_LSD(x) ((unsigned int)((unsigned long long)(x)))
#define HIFC_MSD(x) ((unsigned int)((((unsigned long long)(x)) >> 16) >> 16))

#define HIFC_BYTES_TO_QW_NUM(x) ((x) >> 3)
#define HIFC_BYTES_TO_DW_NUM(x) ((x) >> 2)

#define UNF_GET_SHIFTMASK(__src, __shift, __mask)  \
	(((__src) & (__mask)) >> (__shift))
#define UNF_FC_SET_SHIFTMASK(__des, __val, __shift, __mask)\
	((__des) = \
		(((__des) & ~(__mask)) | (((__val) << (__shift)) & (__mask))))

/* D_ID */
#define UNF_FC_HEADER_DID_MASK                          0x00FFFFFF
#define UNF_FC_HEADER_DID_SHIFT                         0
#define UNF_FC_HEADER_DID_DWORD                         0
#define UNF_GET_FC_HEADER_DID(__pfcheader)\
	UNF_GET_SHIFTMASK(\
		((unsigned int *)(void *)__pfcheader)[UNF_FC_HEADER_DID_DWORD],\
		UNF_FC_HEADER_DID_SHIFT, UNF_FC_HEADER_DID_MASK)

#define UNF_SET_FC_HEADER_DID(__pfcheader, __val)\
	UNF_FC_SET_SHIFTMASK(\
		((unsigned int *)(void *)__pfcheader)[UNF_FC_HEADER_DID_DWORD],\
		__val, UNF_FC_HEADER_DID_SHIFT, UNF_FC_HEADER_DID_MASK)

/* R_CTL */
#define UNF_FC_HEADER_RCTL_MASK                         0xFF000000
#define UNF_FC_HEADER_RCTL_SHIFT                        24
#define UNF_FC_HEADER_RCTL_DWORD                        0
#define UNF_GET_FC_HEADER_RCTL(__pfcheader)\
	UNF_GET_SHIFTMASK(\
	((unsigned int *)(void *)__pfcheader)[UNF_FC_HEADER_RCTL_DWORD],\
	UNF_FC_HEADER_RCTL_SHIFT, UNF_FC_HEADER_RCTL_MASK)

#define UNF_SET_FC_HEADER_RCTL(__pfcheader, __val)\
	UNF_FC_SET_SHIFTMASK(\
	((unsigned int *)(void *)__pfcheader)[UNF_FC_HEADER_RCTL_DWORD],\
	__val, UNF_FC_HEADER_RCTL_SHIFT, UNF_FC_HEADER_RCTL_MASK)

/* S_ID */
#define UNF_FC_HEADER_SID_MASK                          0x00FFFFFF
#define UNF_FC_HEADER_SID_SHIFT                         0
#define UNF_FC_HEADER_SID_DWORD                         1
#define UNF_GET_FC_HEADER_SID(__pfcheader)\
	UNF_GET_SHIFTMASK(\
	((unsigned int *)(void *)__pfcheader)[UNF_FC_HEADER_SID_DWORD],\
	UNF_FC_HEADER_SID_SHIFT, UNF_FC_HEADER_SID_MASK)
#define UNF_SET_FC_HEADER_SID(__pfcheader, __val)\
	UNF_FC_SET_SHIFTMASK(\
	((unsigned int *)(void *)__pfcheader)[UNF_FC_HEADER_SID_DWORD],\
	__val, UNF_FC_HEADER_SID_SHIFT, UNF_FC_HEADER_SID_MASK)

/* CS_CTL */
#define UNF_FC_HEADER_CS_CTL_MASK                       0xFF000000
#define UNF_FC_HEADER_CS_CTL_SHIFT                      24
#define UNF_FC_HEADER_CS_CTL_DWORD                      1
#define UNF_GET_FC_HEADER_CS_CTL(__pfcheader)\
	UNF_GET_SHIFTMASK(\
	((unsigned int *)(void *)__pfcheader)[UNF_FC_HEADER_CS_CTL_DWORD],\
	UNF_FC_HEADER_CS_CTL_SHIFT, UNF_FC_HEADER_CS_CTL_MASK)

#define UNF_SET_FC_HEADER_CS_CTL(__pfcheader, __val)\
	UNF_FC_SET_SHIFTMASK(\
	((unsigned int *)(void *)__pfcheader)[UNF_FC_HEADER_CS_CTL_DWORD],\
	__val, UNF_FC_HEADER_CS_CTL_SHIFT, UNF_FC_HEADER_CS_CTL_MASK)

/* F_CTL */
#define UNF_FC_HEADER_FCTL_MASK                         0x00FFFFFF
#define UNF_FC_HEADER_FCTL_SHIFT                        0
#define UNF_FC_HEADER_FCTL_DWORD                        2
#define UNF_GET_FC_HEADER_FCTL(__pfcheader)\
	UNF_GET_SHIFTMASK(\
	((unsigned int *)(void *)__pfcheader)[UNF_FC_HEADER_FCTL_DWORD],\
	UNF_FC_HEADER_FCTL_SHIFT, UNF_FC_HEADER_FCTL_MASK)
#define UNF_SET_FC_HEADER_FCTL(__pfcheader, __val)\
	UNF_FC_SET_SHIFTMASK(\
	((unsigned int *)(void *)__pfcheader)[UNF_FC_HEADER_FCTL_DWORD],\
	__val, UNF_FC_HEADER_FCTL_SHIFT, UNF_FC_HEADER_FCTL_MASK)

/* TYPE */
#define UNF_FC_HEADER_TYPE_MASK                         0xFF000000
#define UNF_FC_HEADER_TYPE_SHIFT                        24
#define UNF_FC_HEADER_TYPE_DWORD                        2
#define UNF_GET_FC_HEADER_TYPE(__pfcheader)\
	UNF_GET_SHIFTMASK(\
	((unsigned int *)(void *)__pfcheader)[UNF_FC_HEADER_TYPE_DWORD],\
	UNF_FC_HEADER_TYPE_SHIFT, UNF_FC_HEADER_TYPE_MASK)

#define UNF_SET_FC_HEADER_TYPE(__pfcheader, __val)\
	UNF_FC_SET_SHIFTMASK(\
	((unsigned int *)(void *)__pfcheader)[UNF_FC_HEADER_TYPE_DWORD],\
	__val, UNF_FC_HEADER_TYPE_SHIFT, UNF_FC_HEADER_TYPE_MASK)

/* SEQ_CNT */
#define UNF_FC_HEADER_SEQ_CNT_MASK                      0x0000FFFF
#define UNF_FC_HEADER_SEQ_CNT_SHIFT                     0
#define UNF_FC_HEADER_SEQ_CNT_DWORD                     3
#define UNF_GET_FC_HEADER_SEQ_CNT(__pfcheader)\
	UNF_GET_SHIFTMASK(\
	((unsigned int *)(void *)__pfcheader)[UNF_FC_HEADER_SEQ_CNT_DWORD],\
	UNF_FC_HEADER_SEQ_CNT_SHIFT, UNF_FC_HEADER_SEQ_CNT_MASK)

#define UNF_SET_FC_HEADER_SEQ_CNT(__pfcheader, __val)\
	UNF_FC_SET_SHIFTMASK(\
	((unsigned int *)(void *)__pfcheader)[UNF_FC_HEADER_SEQ_CNT_DWORD],\
	__val, UNF_FC_HEADER_SEQ_CNT_SHIFT, UNF_FC_HEADER_SEQ_CNT_MASK)

/* DF_CTL */
#define UNF_FC_HEADER_DF_CTL_MASK                       0x00FF0000
#define UNF_FC_HEADER_DF_CTL_SHIFT                      16
#define UNF_FC_HEADER_DF_CTL_DWORD                      3
#define UNF_GET_FC_HEADER_DF_CTL(__pfcheader)\
	UNF_GET_SHIFTMASK(\
	((unsigned int *)(void *)__pfcheader)[UNF_FC_HEADER_DF_CTL_DWORD],\
	UNF_FC_HEADER_DF_CTL_SHIFT, UNF_FC_HEADER_DF_CTL_MASK)
#define UNF_SET_FC_HEADER_DF_CTL(__pfcheader, __val)\
	UNF_FC_SET_SHIFTMASK(\
	((unsigned int *)(void *)__pfcheader)[UNF_FC_HEADER_DF_CTL_DWORD],\
	__val, UNF_FC_HEADER_DF_CTL_SHIFT, UNF_FC_HEADER_DF_CTL_MASK)

/* SEQ_ID */
#define UNF_FC_HEADER_SEQ_ID_MASK                       0xFF000000
#define UNF_FC_HEADER_SEQ_ID_SHIFT                      24
#define UNF_FC_HEADER_SEQ_ID_DWORD                      3
#define UNF_GET_FC_HEADER_SEQ_ID(__pfcheader)\
	UNF_GET_SHIFTMASK(\
	((unsigned int *)(void *)__pfcheader)[UNF_FC_HEADER_SEQ_ID_DWORD],\
	UNF_FC_HEADER_SEQ_ID_SHIFT, UNF_FC_HEADER_SEQ_ID_MASK)
#define UNF_SET_FC_HEADER_SEQ_ID(__pfcheader, __val)\
	UNF_FC_SET_SHIFTMASK(\
	((unsigned int *)(void *)__pfcheader)[UNF_FC_HEADER_SEQ_ID_DWORD],\
	__val, UNF_FC_HEADER_SEQ_ID_SHIFT, UNF_FC_HEADER_SEQ_ID_MASK)

/* RX_ID */
#define UNF_FC_HEADER_RXID_MASK                         0x0000FFFF
#define UNF_FC_HEADER_RXID_SHIFT                        0
#define UNF_FC_HEADER_RXID_DWORD                        4
#define UNF_GET_FC_HEADER_RXID(__pfcheader)\
	UNF_GET_SHIFTMASK(\
	((unsigned int *)(void *)__pfcheader)[UNF_FC_HEADER_RXID_DWORD],\
	UNF_FC_HEADER_RXID_SHIFT, UNF_FC_HEADER_RXID_MASK)
#define UNF_SET_FC_HEADER_RXID(__pfcheader, __val)\
	UNF_FC_SET_SHIFTMASK(\
	((unsigned int *)(void *)__pfcheader)[UNF_FC_HEADER_RXID_DWORD],\
	__val, UNF_FC_HEADER_RXID_SHIFT, UNF_FC_HEADER_RXID_MASK)

/* OX_ID */
#define UNF_FC_HEADER_OXID_MASK                         0xFFFF0000
#define UNF_FC_HEADER_OXID_SHIFT                        16
#define UNF_FC_HEADER_OXID_DWORD                        4
#define UNF_GET_FC_HEADER_OXID(__pfcheader)\
	((unsigned short)UNF_GET_SHIFTMASK(\
	((unsigned int *)(void *)__pfcheader)[UNF_FC_HEADER_OXID_DWORD],\
	UNF_FC_HEADER_OXID_SHIFT\
	, UNF_FC_HEADER_OXID_MASK))

#define UNF_SET_FC_HEADER_OXID(__pfcheader, __val)\
	(UNF_FC_SET_SHIFTMASK(\
	((unsigned int *)(void *)__pfcheader)[UNF_FC_HEADER_OXID_DWORD],\
	__val, UNF_FC_HEADER_OXID_SHIFT, UNF_FC_HEADER_OXID_MASK))

/* PRLI PARAM 3 */
#define HIFC_PRLI_PARAM_WXFER_ENABLE_MASK               0x00000001
#define HIFC_PRLI_PARAM_WXFER_ENABLE_SHIFT              0
#define HIFC_PRLI_PARAM_WXFER_DWORD                     3
#define HIFC_GET_PRLI_PARAM_WXFER(__pfcheader)\
	UNF_GET_SHIFTMASK(\
	((unsigned int *)(void *)(__pfcheader))[HIFC_PRLI_PARAM_WXFER_DWORD],\
	HIFC_PRLI_PARAM_WXFER_ENABLE_SHIFT, HIFC_PRLI_PARAM_WXFER_ENABLE_MASK)

#define HIFC_PRLI_PARAM_CONF_ENABLE_MASK                0x00000080
#define HIFC_PRLI_PARAM_CONF_ENABLE_SHIFT               7
#define HIFC_PRLI_PARAM_CONF_DWORD                      3
#define HIFC_GET_PRLI_PARAM_CONF(__pfcheader)\
	UNF_GET_SHIFTMASK(\
	((unsigned int *)(void *)(__pfcheader))[HIFC_PRLI_PARAM_CONF_DWORD],\
	HIFC_PRLI_PARAM_CONF_ENABLE_SHIFT, HIFC_PRLI_PARAM_CONF_ENABLE_MASK)

#define HIFC_PRLI_PARAM_REC_ENABLE_MASK                 0x00000400
#define HIFC_PRLI_PARAM_REC_ENABLE_SHIFT                10
#define HIFC_PRLI_PARAM_CONF_REC                        3
#define HIFC_GET_PRLI_PARAM_REC(__pfcheader)\
	UNF_GET_SHIFTMASK(\
	((unsigned int *)(void *)(__pfcheader))[HIFC_PRLI_PARAM_CONF_REC],\
	HIFC_PRLI_PARAM_REC_ENABLE_SHIFT, HIFC_PRLI_PARAM_REC_ENABLE_MASK)

#define HIFC_WQE_TYPE_MASK                              0x000000FF
#define HIFC_WQE_TYPE_SHIFT                             0
#define HIFC_WQE_TYPE_DWORD                             0
#define HIFC_GET_WQE_TYPE_BE(__pfcheader)\
	UNF_GET_SHIFTMASK(\
	((unsigned int *)(void *)__pfcheader)[HIFC_WQE_TYPE_DWORD],\
	HIFC_WQE_TYPE_SHIFT, HIFC_WQE_TYPE_MASK)

#define HIFC_MAKE_64BIT_ADDR(__high32, __low32) \
	(unsigned long long)(((unsigned long long)(__high32) << 32) |\
	(unsigned long long)(__low32))

#define HIFC_TRACE(log_id, log_att, log_level, fmt, ...) \
	UNF_TRACE(log_id, log_att, log_level, fmt, ##__VA_ARGS__)

/* Valid check */
#define HIFC_CHECK(log_id, condition, fail_do)				\
	do {								\
		if (unlikely(!(condition))) {				\
			HIFC_TRACE((log_id), UNF_LOG_IO_ATT, UNF_ERR,	\
				"[err]Function:%s parameter check[%s] invalid",\
				__func__, #condition);			\
			fail_do;					\
		}							\
	} while (0)

#define PRINT_IN_MBOX(dbg_level, data, count)				\
	do {								\
		unsigned int index = 0;					\
		if ((dbg_level) <= unf_dbg_level) {			\
			printk("HIFC send inbound mailbox: ");		\
			for (index = 0; index < (count) / 4; index++) {	\
				printk("%08x ", \
				       (((unsigned int *)(data))[index]));\
			}						\
			printk("\n");					\
		}							\
	} while (0)
#define PRINT_OUT_MBOX(dbg_level, data, count)			\
	do {								\
		unsigned int index = 0;					\
		if ((dbg_level) <= unf_dbg_level) {			\
			printk("HIFC receive outbound mailbox: ");	\
			for (index = 0; index < (count) / 4; index++) {	\
				printk("%08x ",\
				       (((unsigned int *)(data))[index]));\
			}						\
			printk("\n");					\
		}							\
	} while (0)

#define PRINT_INBOUND_IOB(dbg_level, data, count)			\
	do {								\
		unsigned int index = 0;					\
		if ((dbg_level) <= unf_dbg_level) {			\
			printk("HIFC send inbound iob: ");		\
			for (index = 0; index < (count) / 4; index++) {	\
				printk("%08x ",\
				(((unsigned int *)(data))[index]));\
			}						\
			printk("\n");					\
		}							\
	} while (0)

#define PRINT_OUTBOUND_IOB(dbg_level, data, count)			\
	do {								\
		unsigned int index = 0;					\
		if ((dbg_level) <= unf_dbg_level) {			\
			printk("HIFC receive outbound iob: ");		\
			for (index = 0; index < (count) / 4; index++) {	\
				printk("%08x ",\
				(((unsigned int *)(data))[index]));\
			}						\
			printk("\n");					\
		}							\
	} while (0)
#define HIFC_REFERNCE_VAR(ref, cmp, ret)

#define RETURN_ERROR_S32        (-1)
#define UNF_RETURN_ERROR_S32    (-1)

enum HIFC_HBA_ERR_STAT_E {
	HIFC_STAT_CTXT_FLUSH_DONE = 0,
	HIFC_STAT_SQ_WAIT_EMPTY,
	HIFC_STAT_LAST_GS_SCQE,
	HIFC_STAT_SQ_POOL_EMPTY,
	HIFC_STAT_PARENT_IO_FLUSHED,
	HIFC_STAT_ROOT_IO_FLUSHED, /* 5 */
	HIFC_STAT_ROOT_SQ_FULL,
	HIFC_STAT_ELS_RSP_EXCH_REUSE,
	HIFC_STAT_GS_RSP_EXCH_REUSE,
	HIFC_STAT_SQ_IO_BUFFER_CLEARED,
	HIFC_STAT_PARENT_SQ_NOT_OFFLOADED, /* 10 */
	HIFC_STAT_PARENT_SQ_QUEUE_DELAYED_WORK,
	HIFC_STAT_PARENT_SQ_INVALID_CACHED_ID,
	HIFC_HBA_STAT_BUTT
};

#define HIFC_DWORD_BYTE         4
#define HIFC_QWORD_BYTE         8
#define HIFC_SHIFT_TO_U64(x)    ((x) >> 3)
#define HIFC_SHIFT_TO_U32(x)    ((x) >> 2)

void hifc_cpu_to_big64(void *v_addr, unsigned int size);
void hifc_big_to_cpu64(void *v_addr, unsigned int size);
void hifc_cpu_to_big32(void *v_addr, unsigned int size);
void hifc_big_to_cpu32(void *v_addr, unsigned int size);
unsigned int hifc_log2n(unsigned int val);

#endif /* __HIFC_UTILS_H__ */
