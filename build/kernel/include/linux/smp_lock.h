#ifndef __LINUX_SMPLOCK_H
#define __LINUX_SMPLOCK_H

#include <linux/config.h>

#ifdef CONFIG_SMP
#error "no smp support yet"
// todo: implement using P() and V()
#else

#define lock_kernel()						do { } while(0)
#define unlock_kernel()						do { } while(0)
#define release_kernel_lock(task, cpu)		do { } while(0)
#define reacquire_kernel_lock(task)			do { } while(0)
#define kernel_locked() 1

#endif /* CONFIG_SMP */
#endif
