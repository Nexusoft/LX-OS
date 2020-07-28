/** Nexus OS: kernel versions of IPC support calls that the IDL expects.

    XXX: fix up the IDL and dumb wrappers that are not needed
 */

#include <nexus/defs.h>
#include <nexus/ipc.h>
#include "IPC.interface.h"
#include <nexus/mem.h>
#include <nexus/ipc_private.h>
#include <nexus/thread.h>
#include <nexus/thread-private.h>
#include <nexus/thread-inline.h>
#include <nexus/ipd.h>
#include <nexus/user_compat.h>

int __errno_use_tls = 0;
int __ipcResultCode = 0;

Port_Handle IPC_CreatePort(Port_Num *new_num) {
  return ipc_create_port(nexusthread_current_ipd(), NULL, NULL, new_num);
}

int IPC_DestroyPort(Port_Handle port_handle) {
  return ipc_destroy_port(nexusthread_current_ipd(), port_handle);
}

int IPC_CloseConnection(Connection_Handle conn_handle) {
  return IPC_CloseConnection_Handler(-1, -1, NULL, 0, conn_handle);
}

int IPCPort_set_handlers(Port_Handle port_handle, IPC_CallHandler call_handler, IPC_Bind_Handler bind_handler) {
  IPC_Port *port;
  IPD *ipd;

  port = IPCPort_find(port_handle);
  ipd = nexusthread_current_ipd();
  assert(ipd_is_kernel(ipd) && ipd != kernelIPD);

  IPCPort_setKernelHandlers(port, ipd, (KernelCallHandler)call_handler, (KernelBindHandler)bind_handler);
  IPCPort_put(port);
  return 0;
}

Connection_Handle IPC_DoBind(Port_Num target) {
	return ipc_connect(nexusthread_current_ipd(), target);
}

int IPCPort_set_async_handler(Port_Handle port_handle, IPC_Async_Handler handler, void *_ctx) {
  IPC_Port *port;

  port = IPCPort_find(port_handle);
  IPCPort_set_kernel_async_handler(port, (KernelAsyncHandler)handler, _ctx);
  IPCPort_put(port);
  return 0;
}

int IPC_GetMyIPD_ID(void) {
  IPD *ipd = nexusthread_current_ipd();
  assert(ipd_is_kernel(ipd));
  return ipd->id;
}

