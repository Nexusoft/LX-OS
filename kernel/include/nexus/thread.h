/** Nexus OS: thread support */

#ifndef __NEXUS_THREAD_H__
#define __NEXUS_THREAD_H__

#include <nexus/defs.h>
#include <nexus/machineprimitives.h>
#include <nexus/mem.h>
#include <nexus/queue.h>
#include <nexus/synch.h>
#include <nexus/transfer.h>
#include <nexus/thread-struct.h>

/** return the current thread cast to struct UThread. 
    calls nexuspanic if called with a kernelthread active */
static inline struct UThread *
nexusuthread_current(void)
{
	if (unlikely(!curt || curt->type != USERTHREAD))
		nexuspanic();

	return (UThread *) curt;
}

void nexusthread_impersonate_push(IPD *ipd);
IPD *nexusthread_impersonate_get(void);
void nexusthread_impersonate_pop(void);

IPD * nexusthread_get_ipd(BasicThread *t);

static inline IPD *
nexusthread_current_ipd(void) 
{
  if (curt)
    return nexusthread_get_ipd(curt);
  else
    return kernelIPD;
}

void nexusthread_del(BasicThread *dead);

/**
 *	Create and schedule a new thread of control so
 *	that it starts executing inside proc_t with
 *	initial argument arg.
 */
KThread *nexusthread_fork(proc_t proc, arg_t arg);

UThread * nexusuthread_create(Map *map, unsigned int pc, unsigned int sp, 
			      IPD *ipd, thread_callback_t pre_fork_hook, 
			      void *pre_fork_data);

void nexusthread_check_and_do_pending_kill(BasicThread *t);

extern unsigned int /* returns new sp */ map_push_main_args(Map *m, unsigned int sp, int argc, char **argv);

static inline void nexusthread_get_real(BasicThread *t) {
  atomic_increment(&t->ref_cnt, 1);
}

static inline void nexusthread_put_real(BasicThread *t) {
  int zero = atomic_decrement(&t->ref_cnt, 1);
  if(zero) {
    nexusthread_del(t);
  }
}

BasicThread * nexusthread_find(int id);

#define nexusthread_get(T) nexusthread_get_real(T)
#define nexusthread_put(T) nexusthread_put_real(T)

/*
 *	Return identity (Thread *) of caller thread.
 */
//extern KThread *nexusthread_self(void);

int            nexusthread_kid(BasicThread *);

typedef void (*Thread_Iterate_Func)(BasicThread *t, void *ctx);

Map *nexusthread_get_map(BasicThread *t);
int nexusthread_current_ipd_id(void);

int nexusthread_ipc_stack_depth(BasicThread *thread);
struct IPC_ClientContext *nexusthread_ipc_top_and_syscall_lock(BasicThread *_thread);

// push() & pop() don't do any allocation
// push(): push a new one onto linked list
#define nexusthread_ipc_push(X,Y)			\
  nexusthread_ipc_push_real(X, Y, __FILE__, __LINE__)
#define nexusthread_ipc_pop(X)			\
  nexusthread_ipc_pop_real(X, __FILE__, __LINE__)

void nexusthread_enter_interrupt(BasicThread *t, InterruptState *is);
void nexusthread_exit_interrupt(BasicThread *t, InterruptState *is);

#define EVENT_CHANNEL_NONE (0)
void nexusthread_Xen_dispatchPendingEvent(BasicThread *t, InterruptState *is);

/*
 *	Block the calling thread.
 *      Pass in the current interrupt level (found when the interrupts were
 *      disabled, before calling this function.
 */
void nexusthread_stop(void);

/*
 *	Kill a thread
 */
int nexusthread_kill(BasicThread *t);

/*
 *	Kill the calling thread.
 */
int nexusthread_exit(void);

/*
 *	Wake anyone waiting for calling thread (on waitsema).
 */
void nexusthread_notify(BasicThread *t);

/*
 *	Make t runnable, and optionally move to front of run queue.
 */
void nexusthread_start(BasicThread *t, int at_start);

/* only start thread if it has never been run before */
void nexusthread_start_if_not_run(UThread *t, void *unused);

/*
 *	Forces the caller to relinquish the processor and be put to the end of
 *	the ready queue.  Allows another thread to run.
 */
void nexusthread_yield(void);
void nexusthread_yield_i(void);

/** Block caller until BasicThread exits, return value it exited with */
int nexusthread_wait(BasicThread *t);

/** put a thread to sleep for delta ticks. 
    @return -1 if thread is cancelled by kill. */
int nexusthread_sleep(int delta);
int nexusthread_cancelsleep(BasicThread * t);
int nexusthread_block(int msecs);
void nexusthread_unblock(int thread);

char nexusthread_panicmode(void);

// Switch CPL1 stack
void nexusthread_switchXenStack(BasicThread *t, unsigned long ss, unsigned long esp);

/*
 *	Initialize the system to run the first nexusthread at
 *	mainproc(mainarg).  This procedure should be called from your
 *	main program with the callback procedure and argument specified
 *	as arguments.
 */
extern void nexusthread_init(proc_t mainproc, arg_t mainarg);

/* for debugging */
void nexusthread_dump(void);
void nexusthread_dump_regs_stack(BasicThread *t);

int nexusthread_move_to_intrqueue(int thread_id);

void print_all_threads(void);
void thread_dumpqueues(char * label);

void nexusthread_setBindNext(BasicThread *t, BasicThread *next);
BasicThread *nexusthread_getBindNext(BasicThread *t);

#ifdef __NEXUSXEN__
#include "xen-defs.h"
#endif

void nexusthread_fpu_trap(void);
int nexusthread_set_schedtype(BasicThread *t, int sched_type, void *sched_info);

UserThreadState *thread_getUTS(BasicThread *t);
KernelThreadState *thread_getKTS(BasicThread *t);

__u64 nexusthread_get_cycles(BasicThread *t);

void nexusthread_birth(void);

// debug stuff
void print_threads_mem(void);

// Preemption control

static inline int disable_preemption(void) {
  extern volatile int preemption_mask;
  int oldval = preemption_mask;
  atomic_write((int *)&preemption_mask, 0);
  return oldval;
}

static inline int get_preemption(void) {
  extern volatile int preemption_mask;
  return preemption_mask;
}

static inline void restore_preemption(int level) {
  extern volatile int preemption_mask;
  atomic_write((int*)&preemption_mask, level);
}

extern uint64_t nexusthread_idlecycles;
extern int nexusthread_idle_pct_sec;

#endif /*__NEXUS_THREAD_H__ */


