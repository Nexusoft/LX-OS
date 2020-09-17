#ifndef _THREAD_STRUCT_H_
#define _THREAD_STRUCT_H_

#include <nexus/config.h>
#include <nexus/clock.h>
#include <nexus/queue.h>
#include <nexus/transfer.h>
#include <nexus/syscall-defs.h>

typedef enum ThreadState {
  RUNNABLE,
  WAITING,
  DEAD,
  NOT_YET_RUN,
} ThreadState;

typedef enum ThreadType {
  USERTHREAD = 1,
  KERNELTHREAD
} ThreadType;

#define DOYIELD 0
#define DOSTOP 1

#define MAX_CALLSTACK 6

struct BasicThread {
  
  /* scheduler queue */
  void *next;
  void *prev;

  /* rpc server queue */
  struct QItem tqueue;

  int id;
  char *name;	 			/**< optional, for profiling */
  IPD *ipd;

  ThreadType type; 			/**< kernel or user? */
  ThreadState schedstate; 		/**< runnable, waiting, dead, etc. */
  int scheduled;			/**< currently waiting to run queue? */

  /* debug */
  int linuxcall;
  int debugval;

  /* cyclecounts (scheduling info) */
  unsigned long cycles;			/**< all cycles in epoch */
  unsigned long long cycles_total;	/**< all cycles in thread */
#if NXCONFIG_CYCLECOUNT_USER
  unsigned long cycles_user;		/**< all user cycles in epoch */
  unsigned long long cycles_utotal;	/**< all u. cycles in thread */
  unsigned long cycles_ustart;		/**< all u. cycles since call */
#endif

  /* synchronization */
  Sema *blocksema;			/**< a call to P(..) will set this */
  Alarm *sleepalarm;
  int timedout;

  /* system call handling */
  int pending_preempt;			/**< delay preempt in kernel */
  InterruptState *syscall_is; 		/**< syscall context, iff in call */

  void *callstack[MAX_CALLSTACK];	/**< Invoke(Sys) stack frames */
  int  callstack_len;

  void *syscall_result;			/**< fast way to pass result */
  int ipcResultCode;			/**< required by IDLgen */
  
  /* only for userthread */
  UserThreadState *uts;
  KThread *kthread; 	/* a kernel thread working on behalf of this user thread */
  unsigned int kernel_esp;

  /* only for userthread: RPC servers */
  Sema 		rpc_wait; 		/**< sema on which RecvCall waits */
  Sema 		rpc_ready; 		/**< sema that CallReturn signals */
  BasicThread *	rpc_caller;		/**< waiting client thread */
  
  /* only for kernel thread */
  KernelThreadState *kts;
  void *stackbase;  /* pointer to the allocated stack, used to free it */
};

/// Currently executing thread
extern BasicThread *curt;

#endif // _THREAD_STRUCT_H_

