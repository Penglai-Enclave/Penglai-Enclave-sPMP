#ifndef __ASM_EXTABLE_H
#define __ASM_EXTABLE_H

#ifndef __ASSEMBLY__

/*
 * The exception table consists of pairs of relative offsets: the first
 * is the relative offset to an instruction that is allowed to fault,
 * and the second is the relative offset at which the program should
 * continue. No registers are modified, so it is entirely up to the
 * continuation code to figure out what to do.
 */

struct exception_table_entry {
	int insn, fixup;
};

#define ARCH_HAS_RELATIVE_EXTABLE

extern int fixup_exception(struct pt_regs *regs);

	/*
	 * ex_entry - place-relative extable entry
	 */
asm(	".macro		ex_entry, insn, fixup		\n"
	".pushsection	__ex_table, \"a\", %progbits	\n"
	".align		3				\n"
	".long		\\insn - .			\n"
	".long		\\fixup - .			\n"
	".popsection					\n"
	".endm						\n");

#else

	/*
	 * ex_entry - place-relative extable entry
	 */
	.macro		ex_entry, insn, fixup
	.pushsection	__ex_table, "a", %progbits
	.align		3
	.long		\insn - .
	.long		\fixup - .
	.popsection
	.endm

#endif
#endif
