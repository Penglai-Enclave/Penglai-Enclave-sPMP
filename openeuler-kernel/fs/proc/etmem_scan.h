/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _PAGE_IDLE_H
#define _PAGE_IDLE_H

#define SCAN_HUGE_PAGE		O_NONBLOCK	/* only huge page */
#define SCAN_SKIM_IDLE		O_NOFOLLOW	/* stop on PMD_IDLE_PTES */
#define SCAN_DIRTY_PAGE         O_NOATIME       /* report pte/pmd dirty bit */

enum ProcIdlePageType {
	PTE_ACCESSED,	/* 4k page */
	PMD_ACCESSED,	/* 2M page */
	PUD_PRESENT,	/* 1G page */

	PTE_DIRTY_M,
	PMD_DIRTY_M,

	PTE_IDLE,
	PMD_IDLE,
	PMD_IDLE_PTES,	/* all PTE idle */

	PTE_HOLE,
	PMD_HOLE,

	PIP_CMD,

	IDLE_PAGE_TYPE_MAX
};

#define PIP_TYPE(a)		(0xf & (a >> 4))
#define PIP_SIZE(a)		(0xf & a)
#define PIP_COMPOSE(type, nr)	((type << 4) | nr)

#define PIP_CMD_SET_HVA		PIP_COMPOSE(PIP_CMD, 0)

#ifndef INVALID_PAGE
#define INVALID_PAGE ~0UL
#endif

#ifdef CONFIG_ARM64
#define _PAGE_MM_BIT_ACCESSED 10
#else
#define _PAGE_MM_BIT_ACCESSED _PAGE_BIT_ACCESSED
#endif

#ifdef CONFIG_X86_64
#define _PAGE_BIT_EPT_ACCESSED	8
#define _PAGE_BIT_EPT_DIRTY		9
#define _PAGE_EPT_ACCESSED	(_AT(pteval_t, 1) << _PAGE_BIT_EPT_ACCESSED)
#define _PAGE_EPT_DIRTY (_AT(pteval_t, 1) << _PAGE_BIT_EPT_DIRTY)

#define _PAGE_EPT_PRESENT	(_AT(pteval_t, 7))

static inline int ept_pte_present(pte_t a)
{
	return pte_flags(a) & _PAGE_EPT_PRESENT;
}

static inline int ept_pmd_present(pmd_t a)
{
	return pmd_flags(a) & _PAGE_EPT_PRESENT;
}

static inline int ept_pud_present(pud_t a)
{
	return pud_flags(a) & _PAGE_EPT_PRESENT;
}

static inline int ept_p4d_present(p4d_t a)
{
	return p4d_flags(a) & _PAGE_EPT_PRESENT;
}

static inline int ept_pgd_present(pgd_t a)
{
	return pgd_flags(a) & _PAGE_EPT_PRESENT;
}

static inline int ept_pte_accessed(pte_t a)
{
	return pte_flags(a) & _PAGE_EPT_ACCESSED;
}

static inline int ept_pmd_accessed(pmd_t a)
{
	return pmd_flags(a) & _PAGE_EPT_ACCESSED;
}

static inline int ept_pud_accessed(pud_t a)
{
	return pud_flags(a) & _PAGE_EPT_ACCESSED;
}

static inline int ept_p4d_accessed(p4d_t a)
{
	return p4d_flags(a) & _PAGE_EPT_ACCESSED;
}

static inline int ept_pgd_accessed(pgd_t a)
{
	return pgd_flags(a) & _PAGE_EPT_ACCESSED;
}
#endif

extern struct file_operations proc_page_scan_operations;

#define PAGE_IDLE_KBUF_FULL	1
#define PAGE_IDLE_BUF_FULL	2
#define PAGE_IDLE_BUF_MIN	(sizeof(uint64_t) * 2 + 3)

#define PAGE_IDLE_KBUF_SIZE	8000

struct page_idle_ctrl {
	struct mm_struct *mm;
	struct kvm *kvm;

	uint8_t kpie[PAGE_IDLE_KBUF_SIZE];
	int pie_read;
	int pie_read_max;

	void __user *buf;
	int buf_size;
	int bytes_copied;

	unsigned long next_hva;		/* GPA for EPT; VA for PT */
	unsigned long gpa_to_hva;
	unsigned long restart_gpa;
	unsigned long last_va;

	unsigned int flags;
};

#endif
