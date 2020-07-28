#ifndef _IPC_H_
#define _IPC_H_

typedef int Port_Num;

/// deprecated. used to be a direct index into a table of ports
//  now it is identical to Port_Num
typedef int Port_Handle;
typedef int Call_Handle;
typedef int Connection_Handle;

struct IPC_Port;

#include "mem.h"
#include "ipd.h"
#include "oid.h"
#include "machineprimitives.h"

#ifndef MSG_OID_TYPEDEF
#define MSG_OID_TYPEDEF
typedef OID MSG_OID;
#endif

int ipc_create_port(IPD *, Map *, struct IPC_Port **, Port_Num *);
int ipc_destroy_port(IPD *ipd, Port_Num channel_num);

struct IPC_Msg;
struct IPC_Connection;

Connection_Handle ipc_connect(IPD *ipd, Port_Num port_num);
void ipc_init(void);
void ipc_syscall_init(void);

int IPCPort_unittest(void);


// Entry point into interpose upcall code
int IPC_sendCallNotification(struct IPC_Port *target_channel, BasicThread *caller);

int IPC_TransferHelper(Call_Handle call_handle,
			      IPD *ipd,
			      Map *map,
			      int desc_num, unsigned int remote, void *local, int len,
			      int from_caller);
/**** Deprecated ********/

void IPCPort_makePermanent(IPC_Port *port);

#endif

