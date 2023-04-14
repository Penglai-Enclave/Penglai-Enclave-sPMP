/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2019 Western Digital Corporation or its affiliates.
 *
 * Authors:
 *   Anup Patel <anup.patel@wdc.com>
 *   Nick Kossifidis <mick@ics.forth.gr>
 */

#include <sbi/riscv_asm.h>
#include <sbi/sbi_bitops.h>
#include <sbi/sbi_domain.h>
#include <sbi/sbi_hart.h>
#include <sbi/sbi_hsm.h>
#include <sbi/sbi_platform.h>
#include <sbi/sbi_system.h>
#include <sbi/sbi_ipi.h>
#include <sbi/sbi_init.h>

bool sbi_system_reset_supported(u32 reset_type, u32 reset_reason)
{
	if (sbi_platform_system_reset_check(sbi_platform_thishart_ptr(),
					    reset_type, reset_reason))
		return TRUE;

	return FALSE;
}

void __noreturn sbi_system_reset(u32 reset_type, u32 reset_reason)
{
	ulong hbase = 0, hmask;
	u32 cur_hartid = current_hartid();
	struct sbi_domain *dom = sbi_domain_thishart_ptr();
	struct sbi_scratch *scratch = sbi_scratch_thishart_ptr();

	/* Send HALT IPI to every hart other than the current hart */
	while (!sbi_hsm_hart_started_mask(dom, hbase, &hmask)) {
		if (hbase <= cur_hartid)
			hmask &= ~(1UL << (cur_hartid - hbase));
		if (hmask)
			sbi_ipi_send_halt(hmask, hbase);
		hbase += BITS_PER_LONG;
	}

	/* Stop current HART */
	sbi_hsm_hart_stop(scratch, FALSE);

	/* Platform specific reset if domain allowed system reset */
	if (dom->system_reset_allowed)
		sbi_platform_system_reset(sbi_platform_ptr(scratch),
					  reset_type, reset_reason);

	/* If platform specific reset did not work then do sbi_exit() */
	sbi_exit(scratch);
}
