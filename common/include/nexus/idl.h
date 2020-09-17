#ifndef _IDL_H_
#define _IDL_H_

#include <nexus/ipc.h>	// IDL generates IPC stuff at top of header files
#include <nexus/syscall-defs.h>

// Definitions for Nexus IDL

#define INTERFACE_SUCCESS (0)
#define INTERFACE_LABELREJECT (1)
#define INTERFACE_BINDERROR (2)
#define INTERFACE_INTERPOSEDROP (3)
#define INTERFACE_NOSUCHMETHOD (4)
#define INTERFACE_MALFORMEDREQUEST (5)

typedef enum {
  SERVERPROCESSOR_SYNC,
  SERVERPROCESSOR_SYNC_FORK,
  SERVERPROCESSOR_ASYNC,
  SERVERPROCESSOR_ASYNC_AUTO_DONE,
} ServerProcessorType;

#define IS_ASYNC_PROCESSORTYPE(X)					\
  ((X) == SERVERPROCESSOR_ASYNC ||					\
   (X) == SERVERPROCESSOR_ASYNC_AUTO_DONE)

#define DEFAULT_PROCESSOR_HANDLE (INVALID_HANDLE)

typedef struct {
  struct ForkedInfo *is_forked;
} ServerProcessorData;

typedef union {
  void *caller_thread;
} KernelServerProcessorData;

#ifndef __NEXUSKERNEL__

extern int __errno_use_tls;
extern __thread int ___tls_ipcResultCode; // used to return exceptional IPC conditions
extern int ___shared_ipcResultCode;
#define __ipcResultCode (*({			\
			     int *__rv;		\
			     if(__errno_use_tls) {	\
			       __rv = &___tls_ipcResultCode;	\
			     } else {				\
			       __rv = &___shared_ipcResultCode;	\
			     }					\
			     __rv;				\
			   }))

#endif // __NEXUSKERNEL__

struct VarLen {
  void *data;
  int len;
  int desc_num; // used only on recipient side to describe which remote memory descriptor to use
};

// These MUST match the corresponding definitions in idlgen/main.cc!
#define RESULT_DESCNUM (0)
#define FIRST_ARG_DESCNUM (RESULT_DESCNUM+1)

#ifdef __NEXUSKERNEL__

#define CALLHANDLE_SYSCALL (-1)

struct IPC_Port;

int nexusthread_check_fastsyscall(BasicThread *t, Call_Handle call_handle);

#endif // __NEXUSKERNEL__

#define IS_SYSCALL_IPCPORT(X)		\
  (FIRST_SYSCALL_IPCPORT <= (X) && (X) <= LAST_SYSCALL_IPCPORT)

// deprecated, but generated in IDL. XXX: update idlgen and remove
#define IS_SYSCALL_IPC_CONNECTION_HANDLE(X) (0)

#endif // _IDL_H_

