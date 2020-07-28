#ifndef _INTERPOSE_INVOCATION_H_
#define _INTERPOSE_INVOCATION_H_

// override IPC_Invoke() to directly call Dispatch_IEvent() without pushing a new cctx stack

#ifndef __NEXUSKERNEL__
#error "This file may only be included from the Nexus kernel!"
#endif

#include <nexus/ipc_private.h>

#define IPC_Invoke(PORTNUM, MESSAGE, MESSAGELEN, USER_DESCS, NUM_TRANSFER_DESCS) IPC_InvokeDirect(PORTNUM, MESSAGE, MESSAGELEN, USER_DESCS, NUM_TRANSFER_DESCS)
static inline int IPC_InvokeDirect(Port_Num port_num,
				   char *message, int message_len, 
				   struct TransferDesc *user_descs,
				   int num_transfer_descs) {
  IPC_Port *port = (IPC_Port *)port_num;
  assert(nexusthread_ipc_top(nexusthread_self())->common_ctx.connection == port->kernel_connection);
  
  int rv = Dispatch_IEvent(port->kernel_connection,
			 message, message_len,
			 user_descs, num_transfer_descs);
  return rv;
}
#endif // _INTERPOSE_INVOCATION_H_
