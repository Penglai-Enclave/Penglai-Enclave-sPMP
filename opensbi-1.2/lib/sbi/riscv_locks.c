/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2019 Western Digital Corporation or its affiliates.
 * Copyright (c) 2021 Christoph Müllner <cmuellner@linux.com>
 */

#include <sbi/riscv_barrier.h>
#include <sbi/riscv_locks.h>
#include <sbi/riscv_asm.h>
#include <sm/print.h>
#define MAX_HARTS 8
volatile long waiting_for_spinlock[MAX_HARTS] = { 0 };

static inline bool spin_lock_unlocked(spinlock_t lock)
{
	return lock.owner == lock.next;
}

bool spin_lock_check(spinlock_t *lock)
{
	RISCV_FENCE(r, rw);
	return !spin_lock_unlocked(*lock);
}

bool spin_trylock(spinlock_t *lock)
{
	unsigned long inc = 1u << TICKET_SHIFT;
	unsigned long mask = 0xffffu << TICKET_SHIFT;
	u32 l0, tmp1, tmp2;

	__asm__ __volatile__(
		/* Get the current lock counters. */
		"1:	lr.w.aq	%0, %3\n"
		"	slli	%2, %0, %6\n"
		"	and	%2, %2, %5\n"
		"	and	%1, %0, %5\n"
		/* Is the lock free right now? */
		"	bne	%1, %2, 2f\n"
		"	add	%0, %0, %4\n"
		/* Acquire the lock. */
		"	sc.w.rl	%0, %0, %3\n"
		"	bnez	%0, 1b\n"
		"2:"
		: "=&r"(l0), "=&r"(tmp1), "=&r"(tmp2), "+A"(*lock)
		: "r"(inc), "r"(mask), "I"(TICKET_SHIFT)
		: "memory");

	return l0 == 0;
}

void spin_lock(spinlock_t *lock)
{
	//for lock debug
	// u32 source_hart = current_hartid();
	// printm_nolock("[spin_lock@%u]try getlock\n",source_hart);
	unsigned long inc  = 1u << TICKET_SHIFT;
	unsigned long mask = 0xffffu;
	u32 l0, tmp1, tmp2;
	ulong hartid = csr_read(CSR_MHARTID);

    // 正在尝试获取锁之前标记
    waiting_for_spinlock[hartid] = 1;
	__asm__ __volatile__(
		/* Atomically increment the next ticket. */
		"	amoadd.w.aqrl	%0, %4, %3\n"

		/* Did we get the lock? */
		"	srli	%1, %0, %6\n"
		"	and	%1, %1, %5\n"
		"1:	and	%2, %0, %5\n"
		"	beq	%1, %2, 2f\n"

		/* If not, then spin on the lock. */
		"	lw	%0, %3\n"
		RISCV_ACQUIRE_BARRIER
		"	j	1b\n"
		"2:"
		: "=&r"(l0), "=&r"(tmp1), "=&r"(tmp2), "+A"(*lock)
		: "r"(inc), "r"(mask), "I"(TICKET_SHIFT)
		: "memory");
		
	waiting_for_spinlock[hartid] = 0;
	// printm_nolock("[spin_lock@%u]success getlock\n",source_hart);
}

void spin_unlock(spinlock_t *lock)
{
	ulong hartid = csr_read(CSR_MHARTID);
    waiting_for_spinlock[hartid] = 0;
	__smp_store_release(&lock->owner, lock->owner + 1);
}
