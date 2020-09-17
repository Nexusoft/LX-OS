#ifndef __LINUX_SMP_H
#define __LINUX_SMP_H

#include <linux/config.h>

#ifdef CONFIG_SMP

#error "Sorry, no smp any more"

#else

#define smp_num_cpus				1
#define smp_processor_id()			0
#define hard_smp_processor_id()			0
#define smp_threads_ready			1
#define kernel_lock()
#define cpu_logical_map(cpu)			0
#define cpu_number_map(cpu)			0
#define smp_call_function(func,info,retry,wait)	({ 0; })
#define cpu_online_map				1

#endif
#endif
