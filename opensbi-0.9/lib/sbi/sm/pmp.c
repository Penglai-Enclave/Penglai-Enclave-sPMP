#include <sm/pmp.h>
#include <stddef.h>
#include <sbi/sbi_pmp.h>
#include <sbi/sbi_console.h>
#include <sm/sm.h>

/**
 * \brief Set pmp and sync all harts.
 *
 * \param pmp_idx_arg The pmp index.
 * \param pmp_config_arg The pmp config.
 */
void set_pmp_and_sync(int pmp_idx_arg, struct pmp_config_t pmp_config_arg)
{
	struct pmp_data_t pmp_data;
	u32 source_hart = current_hartid();

	//set current hart's pmp
	set_pmp(pmp_idx_arg, pmp_config_arg);
	//sync all other harts
	SBI_PMP_DATA_INIT(&pmp_data, pmp_config_arg, pmp_idx_arg, source_hart);
	sbi_send_pmp(0xFFFFFFFF&(~(1<<source_hart)), 0, &pmp_data);
	return;
}

/**
 * \brief Clear pmp and sync all harts.
 *
 * \param pmp_idx_arg The pmp index.
 */
void clear_pmp_and_sync(int pmp_idx)
{
	struct pmp_config_t pmp_config = {0,};

	pmp_config.mode = PMP_OFF;
	set_pmp_and_sync(pmp_idx, pmp_config);

	return;
}

//TODO Only handle for the __riscv_64
void set_pmp_reg(int pmp_idx, uintptr_t* pmp_address, uintptr_t* pmp_config)
{
	uintptr_t tmp_pmp_address, tmp_pmp_config;
	tmp_pmp_address = *pmp_address;
	tmp_pmp_config = *pmp_config;
	switch(pmp_idx)
	{
		case 0:
			PMP_SET(0, 0, tmp_pmp_address, tmp_pmp_config);
			break;
		case 1:
			PMP_SET(1, 0, tmp_pmp_address, tmp_pmp_config);
			break;
		case 2:
			PMP_SET(2, 0, tmp_pmp_address, tmp_pmp_config);
			break;
		case 3:
			PMP_SET(3, 0, tmp_pmp_address, tmp_pmp_config);
			break;
		case 4:
			PMP_SET(4, 0, tmp_pmp_address, tmp_pmp_config);
			break;
		case 5:
			PMP_SET(5, 0, tmp_pmp_address, tmp_pmp_config);
			break;
		case 6:
			PMP_SET(6, 0, tmp_pmp_address, tmp_pmp_config);
			break;
		case 7:
			PMP_SET(7, 0, tmp_pmp_address, tmp_pmp_config);
			break;
		case 8:
			PMP_SET(8, 2, tmp_pmp_address, tmp_pmp_config);
			break;
		case 9:
			PMP_SET(9, 2, tmp_pmp_address, tmp_pmp_config);
			break;
		case 10:
			PMP_SET(10, 2, tmp_pmp_address, tmp_pmp_config);
			break;
		case 11:
			PMP_SET(11, 2, tmp_pmp_address, tmp_pmp_config);
			break;
		case 12:
			PMP_SET(12, 2, tmp_pmp_address, tmp_pmp_config);
			break;
		case 13:
			PMP_SET(13, 2, tmp_pmp_address, tmp_pmp_config);
			break;
		case 14:
			PMP_SET(14, 2, tmp_pmp_address, tmp_pmp_config);
			break;
		case 15:
			PMP_SET(15, 2, tmp_pmp_address, tmp_pmp_config);
			break;
		default:
			break;
	}
	*pmp_address = tmp_pmp_address;
	*pmp_config = tmp_pmp_config;
}

/**
 * \brief get pmp reg
 */
void get_pmp_reg(int pmp_idx, uintptr_t* pmp_address, uintptr_t* pmp_config)
{
	uintptr_t tmp_pmp_address=0, tmp_pmp_config=0;
	switch(pmp_idx)
	{
		case 0:
			PMP_READ(0, 0, tmp_pmp_address, tmp_pmp_config);
			break;
		case 1:
			PMP_READ(1, 0, tmp_pmp_address, tmp_pmp_config);
			break;
		case 2:
			PMP_READ(2, 0, tmp_pmp_address, tmp_pmp_config);
			break;
		case 3:
			PMP_READ(3, 0, tmp_pmp_address, tmp_pmp_config);
			break;
		case 4:
			PMP_READ(4, 0, tmp_pmp_address, tmp_pmp_config);
			break;
		case 5:
			PMP_READ(5, 0, tmp_pmp_address, tmp_pmp_config);
			break;
		case 6:
			PMP_READ(6, 0, tmp_pmp_address, tmp_pmp_config);
			break;
		case 7:
			PMP_READ(7, 0, tmp_pmp_address, tmp_pmp_config);
			break;
		case 8:
			PMP_READ(8, 2, tmp_pmp_address, tmp_pmp_config);
			break;
		case 9:
			PMP_READ(9, 2, tmp_pmp_address, tmp_pmp_config);
			break;
		case 10:
			PMP_READ(10, 2, tmp_pmp_address, tmp_pmp_config);
			break;
		case 11:
			PMP_READ(11, 2, tmp_pmp_address, tmp_pmp_config);
			break;
		case 12:
			PMP_READ(12, 2, tmp_pmp_address, tmp_pmp_config);
			break;
		case 13:
			PMP_READ(13, 2, tmp_pmp_address, tmp_pmp_config);
			break;
		case 14:
			PMP_READ(14, 2, tmp_pmp_address, tmp_pmp_config);
			break;
		case 15:
			PMP_READ(15, 2, tmp_pmp_address, tmp_pmp_config);
			break;
		default:
			break;
	}
	*pmp_address = tmp_pmp_address;
	*pmp_config = tmp_pmp_config;
}

/**
 * \brief set current hart's pmp
 *
 * \param pmp_idx the index of target PMP register
 * \param pmp_cfg the configuration of the PMP register
 */
void set_pmp(int pmp_idx, struct pmp_config_t pmp_cfg_t)
{
	uintptr_t pmp_address = 0;
	//uintptr_t old_config = 0;
#define PMP_CONFIG_OFFSET(pmp_idx) ((uintptr_t)PMPCFG_BIT_NUM * (pmp_idx % PMP_PER_CFG_REG))
	uintptr_t pmp_config = ((pmp_cfg_t.mode & PMP_A) | (pmp_cfg_t.perm & (PMP_R|PMP_W|PMP_X)))
		<< PMP_CONFIG_OFFSET(pmp_idx);

	switch(pmp_cfg_t.mode)
	{
		case PMP_A_NAPOT:
			if(pmp_cfg_t.paddr == 0 && pmp_cfg_t.size == -1UL)
				pmp_address = -1UL;
			else
				pmp_address = (pmp_cfg_t.paddr | ((pmp_cfg_t.size>>1)-1)) >> 2;
			break;
		case PMP_A_TOR:
			pmp_address = pmp_cfg_t.paddr;
			break;
		case PMP_A_NA4:
			pmp_address = pmp_cfg_t.paddr;
		case PMP_OFF:
			pmp_address = 0;
			break;
		default:
			pmp_address = 0;
			break;
	}
	set_pmp_reg(pmp_idx, &pmp_address, &pmp_config);

	return;
}

/**
 * \brief clear the configuration of a PMP register
 *
 * \param pmp_idx the index of target PMP register
 */
void clear_pmp(int pmp_idx)
{
	struct pmp_config_t pmp_cfg_t;

	pmp_cfg_t.mode = PMP_OFF;
	pmp_cfg_t.perm = PMP_NO_PERM;
	pmp_cfg_t.paddr = 0;
	pmp_cfg_t.size = 0;
	set_pmp(pmp_idx, pmp_cfg_t);

	return;
}

/**
 * \brief Get the configuration of a pmp register (pmp_idx)
 *
 * \param pmp_idx the index of target PMP register
 */
struct pmp_config_t get_pmp(int pmp_idx)
{
	struct pmp_config_t pmp = {0,};
	uintptr_t pmp_address = 0;
	uintptr_t pmp_config = 0;
	unsigned long order = 0;
	unsigned long size = 0;

	//set_pmp_reg(pmp_idx, &pmp_address, &pmp_config);
	get_pmp_reg(pmp_idx, &pmp_address, &pmp_config);


	pmp_config >>= (uintptr_t)PMPCFG_BIT_NUM * (pmp_idx % PMP_PER_CFG_REG);
	pmp_config &= PMPCFG_BITS;
	switch(pmp_config & PMP_A)
	{
		case PMP_A_NAPOT:
			while(pmp_address & 1)
			{
				order += 1;
				pmp_address >>= 1;
			}
			order += 3;
			size = 1 << order;
			pmp_address <<= (order-1);
			break;
		case PMP_A_NA4:
			size = 4;
			break;
		case PMP_A_TOR:
			break;
		case PMP_OFF:
			pmp_address = 0;
			size = 0;
			break;
	}

	pmp.mode = pmp_config & PMP_A;
	pmp.perm = pmp_config & (PMP_R | PMP_W | PMP_X);
	pmp.paddr = pmp_address;
	pmp.size = size;

	return pmp;
}

/**
 * \brief Dump PMP registers, only used for debug
 */
void dump_pmps(void)
{
	/*FIXME: we can have different number of PMP regions */
	int i;
	for (i=0; i<16; i++){
		struct pmp_config_t pmp = get_pmp(i);
		(void)pmp; //to ignore the unused variable warnings
		printm("[Debug:SM@%s] pmp_%d: mode(0x%lx) perm(0x%lx) paddr(0x%lx) size(0x%lx)\n",
				__func__, i, pmp.mode, pmp.perm, pmp.paddr, pmp.size);
	}
}
