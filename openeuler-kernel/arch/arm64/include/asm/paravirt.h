/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_ARM64_PARAVIRT_H
#define _ASM_ARM64_PARAVIRT_H

#ifdef CONFIG_PARAVIRT
struct static_key;
extern struct static_key paravirt_steal_enabled;
extern struct static_key paravirt_steal_rq_enabled;

struct pv_time_ops {
	unsigned long long (*steal_clock)(int cpu);
};

struct pv_sched_ops {
	void (*queued_spin_lock_slowpath)(struct qspinlock *lock, u32 val);
	void (*queued_spin_unlock)(struct qspinlock *lock);

	void (*wait)(u8 *ptr, u8 val);
	void (*kick)(int cpu);

	bool (*vcpu_is_preempted)(int cpu);
};

struct paravirt_patch_template {
	struct pv_time_ops time;
	struct pv_sched_ops sched;
};

extern struct paravirt_patch_template pv_ops;

static inline u64 paravirt_steal_clock(int cpu)
{
	return pv_ops.time.steal_clock(cpu);
}

int __init pv_time_init(void);

int __init pv_sched_init(void);

__visible bool __native_vcpu_is_preempted(int cpu);
static inline bool pv_vcpu_is_preempted(int cpu)
{
	return pv_ops.sched.vcpu_is_preempted(cpu);
}

#if defined(CONFIG_SMP) && defined(CONFIG_PARAVIRT_SPINLOCKS)
void __init pv_qspinlock_init(void);
bool pv_is_native_spin_unlock(void);
static inline void pv_queued_spin_lock_slowpath(struct qspinlock *lock, u32 val)
{
	return pv_ops.sched.queued_spin_lock_slowpath(lock, val);
}

static inline void pv_queued_spin_unlock(struct qspinlock *lock)
{
	return pv_ops.sched.queued_spin_unlock(lock);
}

static inline void pv_wait(u8 *ptr, u8 val)
{
	return pv_ops.sched.wait(ptr, val);
}

static inline void pv_kick(int cpu)
{
	return pv_ops.sched.kick(cpu);
}
#else

#define pv_qspinlock_init() do {} while (0)

#endif /* SMP && PARAVIRT_SPINLOCKS */

#else

#define pv_time_init() do {} while (0)
#define pv_sched_init() do {} while (0)

#endif // CONFIG_PARAVIRT

#endif
