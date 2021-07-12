/*
 * arch/arm/include/asm/hugetlb-2level.h
 *
 * Copyright (C) 2014 Linaro Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#ifndef _ASM_ARM_HUGETLB_2LEVEL_H
#define _ASM_ARM_HUGETLB_2LEVEL_H

#define __HAVE_ARCH_HUGE_PTEP_GET
static inline pte_t huge_ptep_get(pte_t *ptep)
{
	pmd_t pmd =  *((pmd_t *)ptep);
	pte_t retval;

	if (!pmd_val(pmd))
		return __pte(0);

	retval = __pte((pteval_t) (pmd_val(pmd) & HPAGE_MASK)
			| arm_hugepteprotval);

	if (pmd_exec(pmd))
		retval = pte_mkexec(retval);
	else
		retval = pte_mknexec(retval);

	if (pmd_young(pmd))
		retval = pte_mkyoung(retval);
	else
		retval = pte_mkold(retval);

	if (pmd_dirty(pmd))
		retval = pte_mkdirty(retval);
	else
		retval = pte_mkclean(retval);

	if (pmd_write(pmd))
		retval = pte_mkwrite(retval);
	else
		retval = pte_wrprotect(retval);

	if (pmd & PMD_SECT_BUFFERABLE)
		retval |= PMD_SECT_BUFFERABLE;
	else
		retval &= ~PMD_SECT_BUFFERABLE;

	if (pmd & PMD_SECT_CACHEABLE)
		retval |= PMD_SECT_CACHEABLE;
	else
		retval &= ~PMD_SECT_CACHEABLE;

	if (pmd & PMD_SECT_TEX(1))
		retval |= L_PTE_MT_DEV_SHARED;
	else
		retval &= ~L_PTE_MT_DEV_SHARED;

	if (pmd & PMD_SECT_S)
		retval |= L_PTE_SHARED;
	else
		retval &= ~(L_PTE_SHARED);

	if (pmd_protnone(pmd))
		retval = pte_mkprotnone(retval);
	else
		retval = pte_rmprotnone(retval);

	return retval;
}

#define __HAVE_ARCH_HUGE_SET_HUGE_PTE_AT
static inline void set_huge_pte_at(struct mm_struct *mm, unsigned long addr,
				   pte_t *ptep, pte_t pte)
{
	pmdval_t pmdval = (pmdval_t) pte_val(pte);
	pmd_t *pmdp = (pmd_t *) ptep;

	/* take the target address bits from the pte only */
	pmdval &= HPAGE_MASK;

	/*
	 * now use pmd_modify to translate the permission bits from the pte
	 * and set the memory type information.
	 */
	pmdval = pmd_val(pmd_modify(__pmd(pmdval), __pgprot(pte_val(pte))));

	__sync_icache_dcache(pte);

	set_pmd_at(mm, addr, pmdp, __pmd(pmdval));
}

static inline pte_t pte_mkhuge(pte_t pte) { return pte; }

#define __HAVE_ARCH_HUGE_PTEP_CLEAR_FLUSH
static inline void huge_ptep_clear_flush(struct vm_area_struct *vma,
					 unsigned long addr, pte_t *ptep)
{
	pmd_t *pmdp = (pmd_t *)ptep;

	pmd_clear(pmdp);
	flush_tlb_range(vma, addr, addr + HPAGE_SIZE);
}

#define __HAVE_ARCH_HUGE_PTEP_SET_WRPROTECT
static inline void huge_ptep_set_wrprotect(struct mm_struct *mm,
						unsigned long addr, pte_t *ptep)
{
	pmd_t *pmdp = (pmd_t *) ptep;

	set_pmd_at(mm, addr, pmdp, pmd_wrprotect(*pmdp));
}

#define __HAVE_ARCH_HUGE_PTEP_GET_AND_CLEAR
static inline pte_t huge_ptep_get_and_clear(struct mm_struct *mm,
						unsigned long addr, pte_t *ptep)
{
	pmd_t *pmdp = (pmd_t *)ptep;
	pte_t pte = huge_ptep_get(ptep);

	pmd_clear(pmdp);

	return pte;
}

#define __HAVE_ARCH_HUGE_PTEP_SET_ACCESS_FLAGS
static inline int huge_ptep_set_access_flags(struct vm_area_struct *vma,
						unsigned long addr, pte_t *ptep,
						pte_t pte, int dirty)
{
	int changed = !pte_same(huge_ptep_get(ptep), pte);

	if (changed) {
		set_huge_pte_at(vma->vm_mm, addr, ptep, pte);
		flush_tlb_range(vma, addr, addr + HPAGE_SIZE);
	}

	return changed;
}

#endif /* _ASM_ARM_HUGETLB_2LEVEL_H */
