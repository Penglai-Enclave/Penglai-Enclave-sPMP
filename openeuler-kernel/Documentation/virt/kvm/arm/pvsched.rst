.. SPDX-License-Identifier: GPL-2.0

Paravirtualized sched support for arm64
=======================================

KVM/arm64 provides some hypervisor service calls to support a paravirtualized
sched.

Some SMCCC compatible hypercalls are defined:

* PV_SCHED_FEATURES:          0xC5000090
* PV_SCHED_IPA_INIT:          0xC5000091
* PV_SCHED_IPA_RELEASE:       0xC5000092
* PV_SCHED_KICK_CPU:          0xC5000093

The existence of the PV_SCHED hypercall should be probed using the SMCCC 1.1
ARCH_FEATURES mechanism before calling it.

PV_SCHED_FEATURES
    ============= ========    ==========
    Function ID:  (uint32)    0xC5000090
    PV_call_id:   (uint32)    The function to query for support.
    Return value: (int64)     NOT_SUPPORTED (-1) or SUCCESS (0) if the relevant
                              PV-sched feature is supported by the hypervisor.
    ============= ========    ==========

PV_SCHED_IPA_INIT
    ============= ========    ==========
    Function ID:  (uint32)    0xC5000091
    Return value: (int64)     NOT_SUPPORTED (-1) or SUCCESS (0) if the IPA of
                              this vCPU's PV data structure is shared to the
                              hypervisor.
    ============= ========    ==========

PV_SCHED_IPA_RELEASE
    ============= ========    ==========
    Function ID:  (uint32)    0xC5000092
    Return value: (int64)     NOT_SUPPORTED (-1) or SUCCESS (0) if the IPA of
                              this vCPU's PV data structure is released.
    ============= ========    ==========

PV_SCHED_KICK_CPU
    ============= ========    ==========
    Function ID:  (uint32)    0xC5000093
    Return value: (int64)     NOT_SUPPORTED (-1) or SUCCESS (0) if the vCPU is
                              kicked by the hypervisor.
    ============= ========    ==========

PV sched state
--------------

The structure pointed to by the PV_SCHED_IPA hypercall is as follows:

+-----------+-------------+-------------+-----------------------------------+
| Field     | Byte Length | Byte Offset | Description                       |
+===========+=============+=============+===================================+
| preempted |      4      |      0      | Indicates that the vCPU that owns |
|           |             |             | this struct is running or not.    |
|           |             |             | Non-zero values mean the vCPU has |
|           |             |             | been preempted. Zero means the    |
|           |             |             | vCPU is not preempted.            |
+-----------+-------------+-------------+-----------------------------------+

The preempted field will be updated to 0 by the hypervisor prior to scheduling
a vCPU. When the vCPU is scheduled out, the preempted field will be updated
to 1 by the hypervisor.

A vCPU of a paravirtualized guest that is busywaiting in guest kernel mode for
an event to occur (ex: a spinlock to become available) can execute WFI
instruction once it has busy-waited for more than a threshold time-interval.
Execution of WFI instruction would cause the hypervisor to put the vCPU to sleep
until occurrence of an appropriate event. Another vCPU of the same guest can
wakeup the sleeping vCPU by issuing PV_SCHED_KICK_CPU hypercall, specifying CPU
id (reg1) of the vCPU to be woken up.
