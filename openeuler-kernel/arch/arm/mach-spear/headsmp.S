/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * arch/arm/mach-spear13XX/headsmp.S
 *
 * Picked from realview
 * Copyright (c) 2012 ST Microelectronics Limited
 * Shiraz Hashim <shiraz.linux.kernel@gmail.com>
 */

#include <linux/linkage.h>
#include <linux/init.h>

#include <asm/assembler.h>

	__INIT

/*
 * spear13xx specific entry point for secondary CPUs. This provides
 * a "holding pen" into which all secondary cores are held until we're
 * ready for them to initialise.
 */
ENTRY(spear13xx_secondary_startup)
	mrc	p15, 0, r0, c0, c0, 5
	and	r0, r0, #15
	adr_l	r6, spear_pen_release
pen:	ldr	r7, [r6]
	cmp	r7, r0
	bne	pen

	/* re-enable coherency */
	mrc	p15, 0, r0, c1, c0, 1
	orr	r0, r0, #(1 << 6) | (1 << 0)
	mcr	p15, 0, r0, c1, c0, 1
	/*
	 * we've been released from the holding pen: secondary_stack
	 * should now contain the SVC stack for this core
	 */
	b	secondary_startup
ENDPROC(spear13xx_secondary_startup)
