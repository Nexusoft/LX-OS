/** Nexus OS: thread support */

#ifndef __NEXUS_THREAD_H__
#define __NEXUS_THREAD_H__

#include <nexus/defs.h>
#include <nexus/machineprimitives.h>
#include <nexus/mem.h>
#include <nexus/ipd.h>
#include <nexus/queue.h>
#include <nexus/synch.h>
#include <nexus/transfer.h>
#include <nexus/thread-struct.h>

/// # of nexustime intervals a task may run for
#define SCHED_PREEMPTION_QUANTUM	1

static inline BasicThread * 
nexusthread_self(void) 
{
  return curt;
}

static inline IPD *
nexusthread_current_ipd(void) 
{
  if (curt)
    return curt->ipd;
  else
    return kernelIPD;
}

void nexusthread_enter_interrupt(BasicThread *t, InterruptState *is);
void nexusthread_exit_interrupt(BasicThread *t, InterruptState *is);

#define EVENT_CHANNEL_NONE (0)
void nexusthread_Xen_dispatchPendingEvent(BasicThread *t, InterruptState *is);

KThread *nexusthread_fork(proc_t proc, arg_t arg);
UThread *nexusuthread_create(unsigned int pc, unsigned int sp, IPD *ipd);

void nexusthread_start(BasicThread *t, int at_start);
void nexusthread_start_noint(BasicThread *t, int at_start);
void nexusthread_stop(void);

void nexusthread_kill(BasicThread *t);

void nexusthread_idle(void);

void nexusthread_yield(void);
void nexusthread_yield_noint(void);

/** Block caller until BasicThread exits, return value it exited with */
int nexusthread_wait(BasicThread *t);

/** put a thread to sleep for delta ticks. 
    @return -1 if thread is cancelled by kill. */
int nexusthread_sleep(int delta);
int nexusthread_sleep_ex(int delta, Sema *sleepsema);
int nexusthread_usleep(unsigned long usec);

void nexusthread_panicmode(void);

// Switch CPL1 stack
void nexusthread_switchXenStack(BasicThread *t, unsigned long ss, unsigned long esp);

/*
 *	Initialize the system to run the first nexusthread at
 *	mainproc(mainarg).  This procedure should be called from your
 *	main program with the callback procedure and argument specified
 *	as arguments.
 */
void nexusthread_init(void);

/* scheduler */

void nxsched_idleloop(void);
BasicThread *nxsched_schedule(void);
void nxsched_enqueue(BasicThread *t, int interrupt, int front);
void nxsched_dequeue(BasicThread *t);

int nxsched_process_setaccount(IPD *ipd, int account);
int nxsched_quantum_setaccount(int quantum, int account);
int nxsched_quantum_getaccount(int quantum);

/* cycle accounting */

void nexusthread_account_sum(void);

/* scheduling and thread info */

extern int nexusthread_account_show;		
int nexusthread_cpuload(void);
int nexusthread_setname(const char *name);
unsigned long long nexusthread_times(BasicThread *t, int do_process, int do_user);

extern uint64_t nexusthread_idle_now;
extern uint64_t nexusthread_idle_last;

#ifdef __NEXUSXEN__
#include "xen-defs.h"
#endif

void nexusthread_fpu_trap(void);

UserThreadState *thread_getUTS(BasicThread *t);
KernelThreadState *thread_getKTS(BasicThread *t);

////////  Preemptive multitasking support  ////////

extern volatile int preemption_enabled;

static inline int disable_preemption(void) 
{
  return swap((int *) &preemption_enabled, 0);
}

static inline int get_preemption(void) 
{
  return atomic_get((int *) &preemption_enabled);
}

static inline int restore_preemption(int level) 
{
  return swap((int *) &preemption_enabled, level);
}


////////  Unsorted (don't look here)  ////////

/// XXX remove after having idlgen stop generate calls
static inline void 
nexusthread_set_syscall_num(BasicThread *t, int callno)
{
}

static inline int 
nexusthread_get_syscall_num(BasicThread *t) 
{
    return -1;
}

#ifdef __NEXUSXEN__
int nexusthread_isXen(BasicThread *bt);
#endif

#endif /*__NEXUS_THREAD_H__ */

