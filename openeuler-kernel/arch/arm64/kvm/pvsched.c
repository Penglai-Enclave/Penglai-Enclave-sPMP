// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright(c) 2019 Huawei Technologies Co., Ltd
 * Author: Zengruan Ye <yezengruan@huawei.com>
 */

#include <linux/arm-smccc.h>
#include <linux/kvm_host.h>

#include <asm/pvsched-abi.h>

#include <kvm/arm_hypercalls.h>

#include "trace.h"

void kvm_update_pvsched_preempted(struct kvm_vcpu *vcpu, u32 preempted)
{
	struct kvm *kvm = vcpu->kvm;
	u64 base = vcpu->arch.pvsched.base;
	u64 offset = offsetof(struct pvsched_vcpu_state, preempted);
	int idx;

	if (base == GPA_INVALID)
		return;

	/*
	 * This function is called from atomic context, so we need to
	 * disable page faults.
	 */
	pagefault_disable();

	idx = srcu_read_lock(&kvm->srcu);
	kvm_put_guest(kvm, base + offset, cpu_to_le32(preempted));
	srcu_read_unlock(&kvm->srcu, idx);

	pagefault_enable();
}

long kvm_pvsched_kick_vcpu(struct kvm_vcpu *vcpu)
{
	unsigned int vcpu_idx;
	long val = SMCCC_RET_NOT_SUPPORTED;
	struct kvm *kvm = vcpu->kvm;
	struct kvm_vcpu *target = NULL;

	vcpu_idx = smccc_get_arg1(vcpu);
	target = kvm_get_vcpu(kvm, vcpu_idx);
	if (!target)
		goto out;

	target->arch.pvsched.pv_unhalted = true;
	kvm_make_request(KVM_REQ_IRQ_PENDING, target);
	kvm_vcpu_kick(target);
	if (READ_ONCE(target->ready))
		kvm_vcpu_yield_to(target);

	val = SMCCC_RET_SUCCESS;
	trace_kvm_pvsched_kick_vcpu(vcpu->vcpu_id, target->vcpu_id);

out:
	return val;
}

long kvm_hypercall_pvsched_features(struct kvm_vcpu *vcpu)
{
	u32 feature = smccc_get_arg1(vcpu);
	long val = SMCCC_RET_NOT_SUPPORTED;

	switch (feature) {
	case ARM_SMCCC_HV_PV_SCHED_FEATURES:
	case ARM_SMCCC_HV_PV_SCHED_IPA_INIT:
	case ARM_SMCCC_HV_PV_SCHED_IPA_RELEASE:
	case ARM_SMCCC_HV_PV_SCHED_KICK_CPU:
		val = SMCCC_RET_SUCCESS;
		break;
	}

	return val;
}
