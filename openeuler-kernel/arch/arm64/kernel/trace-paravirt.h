/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright(c) 2019 Huawei Technologies Co., Ltd
 * Author: Zengruan Ye <yezengruan@huawei.com>
 */

#undef TRACE_SYSTEM
#define TRACE_SYSTEM paravirt

#if !defined(_TRACE_PARAVIRT_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_PARAVIRT_H

#include <linux/tracepoint.h>

TRACE_EVENT(kvm_kick_cpu,
	TP_PROTO(const char *name, int cpu, int target),
	TP_ARGS(name, cpu, target),

	TP_STRUCT__entry(
		__string(name, name)
		__field(int, cpu)
		__field(int, target)
	),

	TP_fast_assign(
		__assign_str(name, name);
		__entry->cpu = cpu;
		__entry->target = target;
	),

	TP_printk("PV qspinlock: %s, cpu %d kick target cpu %d",
		__get_str(name),
		__entry->cpu,
		__entry->target
	)
);

TRACE_EVENT(kvm_wait,
	TP_PROTO(const char *name, int cpu),
	TP_ARGS(name, cpu),

	TP_STRUCT__entry(
		__string(name, name)
		__field(int, cpu)
	),

	TP_fast_assign(
		__assign_str(name, name);
		__entry->cpu = cpu;
	),

	TP_printk("PV qspinlock: %s, cpu %d wait kvm access wfi",
		__get_str(name),
		__entry->cpu
	)
);

#endif /* _TRACE_PARAVIRT_H */

/* This part must be outside protection */
#undef TRACE_INCLUDE_PATH
#undef TRACE_INCLUDE_FILE
#define TRACE_INCLUDE_PATH ../../../arch/arm64/kernel/
#define TRACE_INCLUDE_FILE trace-paravirt

#include <trace/define_trace.h>
