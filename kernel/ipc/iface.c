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

int __ipcResultCode = 0;

int
IPC_CreatePort(int request) 
{
  return ipc_create_port(curt->ipd, NULL, request);
}

int 
IPC_DestroyPort(int port) 
{
  return ipc_destroy_port(curt->ipd, port);
}

int
IPC_Caller(void) 
{
  // a kernel service executes in the same thread as the client
  return curt->ipd->id;
}

/** Kernel version of IPC.sc:Send 
    may be called from interrupt context, where it may fail instead of block */
int
IPC_Send(int port_num, void *data, int dlen)
{
  int err;

  err = ipc_send(NULL, port_num, data, dlen);
  if (err != 1)
    gfree(data);

  return err == -1 ? -1 : 0;
}

/** Kernel version of IPC.sc:Recv 
    may NOT be called from interrupt context */
int
IPC_Recv(int port_num, void *buf, int blen)
{
  return ipc_recv(NULL, port_num, buf, blen, NULL);
}

int 
ipc_sendpage(int port, void *data)
{
  // NB: kernel virtual (vmem_heap) addresses cause instability. dunno why..
  //assert(data >= (void *) KERNELVADDR);

  return ipc_sendpage_impl(kernelMap, port, data);
}

int 
ipc_recvpage(int port, void **data)
{
  return ipc_recvpage_impl(kernelMap, port, data, NULL);
}

/** Equivalent of IPC.svc:Invoke for calls from within the kernel */
int 
IPC_Invoke(Connection_Handle port_num,
     char *message, int message_len, 
     struct TransferDesc *descs, int num_descs) 
{
  struct IPC_Invoke_Args args;
  int ret;
  
  args.portnum = port_num;
  args.msg = message;
  args.mlen = message_len;
  args.descs = descs;
  args.dnum = num_descs;

  assert(curt->callstack_len + 1 < MAX_CALLSTACK);
  curt->callstack[curt->callstack_len++] = &args;

  ret = rpc_invoke(port_num);

  curt->callstack_len--;
  return ret;
}

/** Equivalent of IPC.svc:RecvCall for calls from within the kernel 
    NB: #1 IDLGEN puts curt in the first argument
    NB: #2 system call handlers do NOT call RecvCall */
Call_Handle 
IPC_RecvCall(Port_Handle _target_thread, char *buf, 
       int *blen, CallDescriptor * cdesc) 
{
  return rpc_recvcall_kernel(buf, blen);
}


/** Equivalent of IPC.svc:CallReturn for calls from within the kernel */
int
IPC_CallReturn(Call_Handle call_handle) 
{
  return 0;
}

/** Equivalent of IPC.svc:TransferTo for calls from within the kernel 
    Even though it is called from the kernel, it may be part of a 
    system call: when the caller is. */
int 
IPC_TransferTo(Call_Handle call_handle, int desc_num, 
         void * local, unsigned long off, int len) 
{
  int ret;

  // system call and returncode descriptor?
  if (nexusthread_check_fastsyscall(curt, call_handle) && desc_num == 0) {
    memcpy(curt->syscall_result, local, len);
    return 0;
  }

  assert(len && curt && curt->callstack_len >= 1);
  return rpc_transfer(curt, desc_num, local, off, len, 0);
}

/** Equivalent of IPC.svc:TransferFrom for calls from within the kernel */
int 
IPC_TransferFrom(Call_Handle call_handle, int desc_num, 
     void * local, unsigned long off, int len) 
{
  assert(len && curt && curt->callstack_len >= 1);
  return rpc_transfer(curt, desc_num, local, off, len, 1);
}

/** Equivalent of IPC.svc:AsyncSend for calls from within the kernel 
    deprecated XXX remove as soon as kernel no longer uses services
 */
int IPC_AsyncSend(Connection_Handle conn_handle,
        void *message, int message_len,
        struct TransferDesc *descs,
        int num_transfer_descs) {
  printk("Warning: deprecated %s called\n", __FUNCTION__);
  assert(0);
  return -1;
}

