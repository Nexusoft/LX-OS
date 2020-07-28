#ifndef _USER_IPC_H_
#define _USER_IPC_H_

#include <nexus/commontypedefs.h>
#include <nexus/syscall-defs.h>
#include <nexus/transfer.h>

#ifndef OID_TYPEDEF
#define OID_TYPEDEF
typedef unsigned int OID;
#endif

#ifndef MSG_OID_TYPEDEF
#define MSG_OID_TYPEDEF
typedef OID MSG_OID;
#endif

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

#define OID_NONE (0)

//////// Control

void __ipc_init(void);

//////// Connect

Connection_Handle IPC_DoBind(Port_Num target);
Connection_Handle IPC_DoBindAccept(Port_Handle target);
Connection_Handle IPC_DoBind_notified(Port_Num target, Port_Handle tap_notification_port_handle);
Connection_Handle IPC_DoBindAccept_notified(Port_Handle target, Port_Num tap_notification_port);

//////// Messaging

MSG_OID IPC_recv(Port_Num ipc_oid, char *message, int *message_len);
void IPC_send(Port_Num ipc_oid, char *message, int message_len);

// source code -compatible with Nexus kernel
struct IPC_Msg {
  Port_Num port_num;
  Port_Handle port_handle;
  char *data;
  int data_len;

  struct {
    struct TransferDesc transfer_descs[MAX_TRANSFERDESCS];
    int num_transfer_descs;
  } common_ctx;
};

//////// IPC Server Scheduling

int  ipc_server_listen(int len, int (*func)(void));
int  ipc_server_run(const char *name);
void ipc_server_list(void);

//////// Various (XXX call the janitor -- don't use any of this)

int printf_failsafe(const char *format, ...);

#ifndef printk
int printk(const char *fmt, ...);
#endif

// Neither of these IPC_getWrap() accessors properly handle the case of multiple wrappers

// Copies the hash of the wrapper, if present to wrapper_hash
// Returns ipd id of wrapper if present
int IPC_getWrap(int target_ipd, char *wrapper_hash);

// Return non-zero IPD id of wrapper if wrapper with specified hash is present around target
// if check_hash == NULL, then no hash checking is performed; e.g. this function serves purely as lookup
int IPC_hasWrap(int target_ipd, const char *check_hash);

// These are accessible in the handlers
extern __thread Port_Handle ipc_handler_port_handle;
extern __thread Port_Num ipc_handler_port_num;

struct PointerVector;
typedef struct PatternInfo {
  int pattern_id;
  int data_port;
  int control_port;
  char expression[0];
} PatternInfo;

typedef struct PortInfo {
  int owner_ipd;
} PortInfo;

extern Port_Handle g_Wrap_port_handle;


//// Only used by netcomp
typedef struct IPC_Msg IPC_Msg;
int IPCMsg_copy_data(IPC_Msg *msg, Map *map, char *target, int len);
Port_Num CallHandle_to_Port_Num(Call_Handle call_handle);
IPC_Msg *CallHandle_to_IPC_Msg(Call_Handle call_handle);

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

#endif  // _USER_IPC_H_

