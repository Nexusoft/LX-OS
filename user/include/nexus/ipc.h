#ifndef _USER_IPC_H_
#define _USER_IPC_H_

#include <nexus/commontypedefs.h>
#include <nexus/syscall-defs.h>
#include <nexus/transfer.h>

#ifndef IPD_ID_TYPEDEF
#define IPD_ID_TYPEDEF
typedef int IPD_ID;
#endif

#ifndef Thread_ID_TYPEDEF
#define Thread_ID_TYPEDEF
typedef int Thread_ID;
#endif

#ifndef Port_Num_TYPEDEF
#define Port_Num_TYPEDEF
typedef int Port_Num;
#endif

#ifndef Port_Handle_TYPEDEF
#define Port_Handle_TYPEDEF
typedef int Port_Handle;
#endif

#ifndef Connection_Handle_TYPEDEF
#define Connection_Handle_TYPEDEF
typedef int Connection_Handle;
#endif

#ifndef Call_Handle_TYPEDEF
#define Call_Handle_TYPEDEF
typedef int Call_Handle;
#endif

// same as in handle.h 
// luckily both have the same value
#ifndef INVALID_HANDLE
#define INVALID_HANDLE (-1)
#endif

//////// Connect

//////// Messaging

int IPC_recv(Port_Num ipc_oid, char *message, int *message_len);
void IPC_send(Port_Num ipc_oid, char *message, int message_len);
int ipc_send(long port, void *data, long dlen);
int ipc_recv(long port, void *buf, long blen);
int ipc_sendpage(int port, void *data);
int ipc_recvpage(int port, void **data);

// Support: datatransfer

char * ipctransfer_from(struct VarLen *remote, int len, int maxlen);
int    ipctransfer_to(struct VarLen *remote, char *data, int len);

//////// IPC Server Scheduling

int  ipc_server_listen(int len, int (*func)(void));
int  ipc_server_run(const char *name);
void ipc_server_list(void);

//////// Various (XXX call the janitor -- don't use any of this)

#ifndef printk
int printk(const char *fmt, ...);
#endif

// These are accessible in the handlers
extern __thread Port_Handle ipc_handler_port_handle;
extern __thread Port_Num ipc_handler_port_num;

struct PointerVector;

extern Port_Handle g_Wrap_port_handle;


typedef void (*IPC_CallHandler)(Call_Handle caller);
typedef int (*IPC_Bind_Handler)(Connection_Handle caller, Port_Handle *notification_port_handle);
typedef void (*IPC_Async_Handler)(IPD_ID source_ipd, Call_Handle call_handle, void *_ctx);

// XXX update callers to use ipc_server_run
static inline int 
IPCPort_set_handlers(Port_Handle port_handle, IPC_CallHandler call_handler, IPC_Bind_Handler bind_handler)
{
	return -1;
}

/// XXX update callers to use ipc_server_run
static inline int 
IPCPort_set_async_handler(Port_Handle port_handle, IPC_Async_Handler ipc_async_handler, void *_ctx)
{
	return -1;
}

#define __IPCPort_checkrange(num) \
  ((num < FIRST_IPCPORT || num > LAST_IPCPORT) && num != 0 && num != -1)	

#endif  // _USER_IPC_H_

