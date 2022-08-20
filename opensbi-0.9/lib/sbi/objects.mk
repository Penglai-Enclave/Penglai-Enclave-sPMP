#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2019 Western Digital Corporation or its affiliates.
#
# Authors:
#   Anup Patel <anup.patel@wdc.com>
#

libsbi-objs-y += riscv_asm.o
libsbi-objs-y += riscv_atomic.o
libsbi-objs-y += riscv_hardfp.o
libsbi-objs-y += riscv_locks.o

libsbi-objs-y += sbi_bitmap.o
libsbi-objs-y += sbi_bitops.o
libsbi-objs-y += sbi_console.o
libsbi-objs-y += sbi_domain.o
libsbi-objs-y += sbi_ecall.o
libsbi-objs-y += sbi_ecall_base.o
libsbi-objs-y += sbi_ecall_hsm.o
libsbi-objs-y += sbi_ecall_legacy.o
libsbi-objs-y += sbi_ecall_pmu.o
libsbi-objs-y += sbi_ecall_replace.o
libsbi-objs-y += sbi_ecall_vendor.o
libsbi-objs-y += sbi_emulate_csr.o
libsbi-objs-y += sbi_fifo.o
libsbi-objs-y += sbi_hart.o
libsbi-objs-y += sbi_math.o
libsbi-objs-y += sbi_hfence.o
libsbi-objs-y += sbi_hsm.o
libsbi-objs-y += sbi_illegal_insn.o
libsbi-objs-y += sbi_init.o
libsbi-objs-y += sbi_ipi.o
libsbi-objs-y += sbi_misaligned_ldst.o
libsbi-objs-y += sbi_platform.o
libsbi-objs-y += sbi_pmu.o
libsbi-objs-y += sbi_scratch.o
libsbi-objs-y += sbi_string.o
libsbi-objs-y += sbi_system.o
libsbi-objs-y += sbi_timer.o
libsbi-objs-y += sbi_tlb.o
libsbi-objs-y += sbi_trap.o
libsbi-objs-y += sbi_unpriv.o
libsbi-objs-y += sbi_expected_trap.o
libsbi-objs-y += sbi_pmp.o

## Add by Dong Du
#  The Penglai related files here
libsbi-objs-y += sbi_ecall_penglai.o
libsbi-objs-y += sm/enclave.o
libsbi-objs-y += sm/pmp.o
libsbi-objs-y += sm/sm.o
libsbi-objs-y += sm/thread.o
libsbi-objs-y += sm/utils.o
libsbi-objs-y += sm/platform/pmp/platform.o
libsbi-objs-y += sm/attest.o

libsbi-objs-y += sm/gm/miracl/mrcore.o
libsbi-objs-y += sm/gm/miracl/mrarth0.o
libsbi-objs-y += sm/gm/miracl/mrarth1.o
libsbi-objs-y += sm/gm/miracl/mrarth2.o
libsbi-objs-y += sm/gm/miracl/mrcurve.o
libsbi-objs-y += sm/gm/miracl/mrxgcd.o
libsbi-objs-y += sm/gm/miracl/mrarth3.o
libsbi-objs-y += sm/gm/miracl/mrjack.o
libsbi-objs-y += sm/gm/miracl/mrbits.o
libsbi-objs-y += sm/gm/miracl/mrmonty.o
libsbi-objs-y += sm/gm/miracl/mrsroot.o
libsbi-objs-y += sm/gm/miracl/mrlucas.o
libsbi-objs-y += sm/gm/SM2_sv.o
libsbi-objs-y += sm/gm/SM3.o
