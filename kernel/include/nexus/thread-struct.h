#ifndef _THREAD_STRUCT_H_
#define _THREAD_STRUCT_H_

#include <nexus/clock.h>
#include <nexus/syscall-defs.h>

typedef int Thread_ID;

extern BasicThread *curt;

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

struct IPC_Port;

struct IPC_ServerContext {
  Sema *mutex;
  BasicThread *caller;

#define CALLEESTATE_AVAILABLE (0)
#define CALLEESTATE_KILLED (1)
  int callee_state;
  Sema *call_sema_0;
};

// Note: No synchronization needed for most of client fields, since
// the client thread can only issue one IPC at a time

#define IPC_CLIENTCONTEXT_THREAD		(0)
#define IPC_CLIENTCONTEXT_MESSAGE	(1)
#define IPC_CLIENTCONTEXT_ANY	(3)

struct KernelTransferDesc {
  struct Map *map;
  struct TransferDesc desc;
};

/** Structure handed off from client to server and back during an RPC call.
    It is embedded in an IPCMsg in asynchronous calls and in an 
    IPC_ClientContext for synchronous ones. 
 
    XXX: cleanup much more. Especially tap and wrap stuff. */
struct IPC_CommonClientContext {
  struct {
    unsigned char owner_type;
    unsigned char num_transfer_descs;
    unsigned char num_wrappee_descs;
    unsigned char num_kernel_transfer_descs;
  };

// XXX: deprecated. remove if not used
#if 0
  union {
    struct {
    BasicThread *owner;
    } thread;
    struct {
    } message;
  } u;
  const IPC_CommonClientContext_OpTable *ops;
#endif

  struct IPC_Connection *connection;
  Sema callee_syscall_sema; // Used to provide mutual exclusion between different callee operations on the same call
  u64 seq;

  struct Map *transfer_map;
  // XXX if not used: delete: int transfer_len;
  struct TransferDesc transfer_descs[MAX_TRANSFERDESCS]; // 0-127
  // end of transfer fields

  // Snapshot of taps taken at call time, to prevent holding edge lock for a long time
  int num_taps; // num_taps is needed early in IPC_send to determine whether interposition is needed
  
  IPD *taplist_source_ipd, *taplist_dest_ipd;
  struct IPC_Port **taps;
#define MAX_FAST_TAP_LIST_LEN (4)
  struct IPC_Port *fast_taplist[MAX_FAST_TAP_LIST_LEN];
  // end of tap fields

  struct Map *wrappee_map;
// Descriptors are deallocated by whoever creates this context
  struct TransferDesc *wrappee_descs;
  struct KernelTransferDesc kernel_transfer_descs[4]; // 128+

};

struct IPC_ClientContext {
  
  // implements a linked list with the head at a server thread's ipc.client_top
  struct IPC_ClientContext *next;

  struct IPC_CommonClientContext common_ctx;
  Sema call_sema_1; // Used for barrier

  // XXX 3/12/07: Kernel becomes unstable if new fields are added here

  struct IPC_Port *dest_port; // IMPORTANT FOR syscall SECURITY!
  IPD *ipd;

  // this is a bit out of hand
  struct Map *message_map;

#define MAX_IPC_MESSAGE_LEN (1024)
#if (MAX_IPC_MESSAGE_LEN > PAGE_SIZE)
#error "ipc message len too big!"
#endif
#define MAX_FAST_TRANSFER_SIZE_PAGES (1)
#define MAX_FAST_TRANSFER_SIZE (MAX_FAST_TRANSFER_SIZE_PAGES * 4096)
  // kernel copy of message data. This is necessary to prevent a
  // race condition where there are multiple copies from user, and a
  // thread changes the value in between

  char *message_data; // kernel copy
  char *message; // original location
  int message_len;

  int result_code;
  int call_type;

  IPD *callee_ipd;

  int sync_refcnt;

  // Save the server thread ID to aid in debugging
  // For a kernel target, this is the kernel_handler()
  int server_thread_id;
  int last_syscall_locker;
};

struct IPC_Connection;

struct IPC_ClientContext *IPC_ClientContext_initNext(BasicThread *t, 
						     struct IPC_Connection *connection);
struct IPC_Port **IPC_CommonClientContext_allocTapList(IPC_CommonClientContext *common_ctx,
			       			       IPD *source_ipd, IPD *dest_ipd, 
						       int num_taps);

#define DOYIELD 0
#define DOSTOP 1

// A max IPC nesting depth of 16 in the kernel seems sufficient
struct IPC_Msg;
struct ThreadIPC {
  int stack_depth; // invariant: transfer_page_cache[stack_depth] is the next entry to use
  struct IPC_ClientContext *client_top;
  // IPC_ServerContext is only valid during RecvCall()
  struct IPC_ServerContext server;
  struct IPC_Msg *ipc_message_data; // pre-allocated, pre-initialized block for IPC message data
};

struct IPC_DispatchArgs {
  // Extra arguments to init_descriptors(), used during interposition upcall
  int in_use : 1;
  int intlevel : 1;
  struct Map *wrappee_map;
  struct TransferDesc *wrappee_descs; int num_wrappee_descs;
  struct KernelTransferDesc *kernel_descs; int num_kernel_descs;
};

#define PENDING_DONEXT (2)
#define PENDING_SET (1)

#define MAX_IPD_STACK (16)
#define IPD_STACK_BOTTOM (-1)

typedef int (*thread_callback_t)(BasicThread *t, void *);

/** On some occassions, threads in the kernel briefly execute code as if 
    they belong to a different process. The most common example is when
    an IPC caller needs to execute some code on behalf of the callee.
 
    This may be simpler than using interthread communication (is it?) */
struct ThreadPersonalityStack {
#define MAX_SCHIZO 8
	IPD *stack[MAX_SCHIZO];
	int index;	/* 0 denotes unused */
	struct Sema mutex;
};

/// XXX replace definition with embedded struct
#define BasicThread_DEFINITION 						\
    void *next;  /* used when queued up on the runq */			\
    void *prev;								\
									\
    int id;      /* id of the thread */					\
    int ref_cnt;							\
    IPD *ipd;								\
									\
    ThreadType type; /* is it a kernel thread or a user thread? */	\
    ThreadState schedstate; /* runnable, waiting, dead, etc. */		\
    									\
    Sema *blocksema;							\
    Sema *sleepsema;							\
    Alarm *sleepalarm;							\
    Sema *waitsema; /* owned by the waiter */				\
    									\
    /* These fields are used during syscall processing. 		\
       Pack them together */						\
    struct {								\
      int pending_kill;							\
      int in_syscall;							\
      int last_syscall;							\
      									\
      /* the IS of the pending trap */					\
      InterruptState *trap_is; 						\
      									\
      /* the IS of the pending syscall. 				\
	 Used when trap_is is overwritten by interrupt */ 		\
      InterruptState *syscall_is; 					\
    };									\
									\
    int interrupt_nesting;						\
									\
    int ipcResultCode;							\
    ThreadIPC ipc;							\
    struct IPC_DispatchArgs dispatch_args;				\
									\
    /* callbacks into (userlevel) device drivers */			\
    void (*notify_block)(BasicThread *t, void *args);			\
    int (*check_intr_queue)(BasicThread *t, void *args);		\
    int (*check_sched_to)(BasicThread *old, BasicThread *new, void *args);\
    void *callback_args;                                          	\
   									\
    struct SchedTypeInfo_Interval interval;                           	\
    int num_interval_slots; 						\
    int sched_type;                                                     \
    int start_tick;							\
									\
    struct ThreadPersonalityStack personality;

struct BasicThread {
  BasicThread_DEFINITION
};

struct KThread {
  BasicThread_DEFINITION

  KernelThreadState *kts;

  void *stackbase;  /* pointer to the allocated stack, used to free it */
  __u64 first_cycle; // first cycle of current quantum
  __u64 cycles_used; // number of TSC cycles where the process was scheduled
};

struct UThread {
  BasicThread_DEFINITION

  UserThreadState *uts;

  struct Map *map;	/* address map for this thread */
  thread_callback_t pre_fork_hook;
  void *pre_fork_data;
  KThread *kthread; 	/* a kernel thread working on behalf of this user thread */
  Queue *destq;

  unsigned int kernel_esp;

  int born;
  void (*dying)(void *arg);
  void *dyingarg;

  int in_sys_block;

  int exit_status;

  /** set when in fast system call, holds address where to put result */
  void *fast_syscall_result_dest;	
};

#endif // _THREAD_STRUCT_H_

