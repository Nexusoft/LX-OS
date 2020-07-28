/** NexusOS: implementation of the main IPC system call functions and
             kernel interfaces to allow IPC calls from the kernel. */

#include <nexus/synch-inline.h>
#include <nexus/galloc.h>
#include <nexus/dlist.h>
#include <Debug.interface.h>
#include <nexus/ipc_private.h>
#include <nexus/guard.h>

#include <nexus/IPC.interface.h>
#include <nexus/FS.kernel-interface.h>			// XXX remove. used during temporary hack session
#include <nexus/Console.interface.h>

#define ReturnError(errorcode) \
	*err = errorcode; return NULL;

void IPCMsg_put(IPC_Msg *msg);

int TransferDesc_process_copy_or_clone(struct TransferDesc *desc, int *p_need_get);

/// deprecated. XXX remove as soon as idlgen stops calling this
int IPC_userInit(void)
{
	return 0;
}

#define PER_IPC_NUM_PAGES (MAX_FAST_TRANSFER_SIZE_PAGES + 1)
struct IPC_ClientContext *IPC_ClientContext_new(BasicThread *t, IPC_Connection *connection) {
  IPC_ClientContext *cctx;
  
  cctx = gcalloc(1, sizeof(*cctx));

  cctx->server_thread_id = -1;
  cctx->last_syscall_locker = -1;
  cctx->sync_refcnt = 1;

  cctx->call_sema_1 = SEMA_INIT;
  sema_set_killable(&cctx->call_sema_1);
  
  cctx->message_data = getKernelPages(PER_IPC_NUM_PAGES);
  cctx->common_ctx.callee_syscall_sema = SEMA_MUTEX_INIT;

  return cctx;
}

/// found like this in thread-inline.h
//  XXX needs serious clean up. Not all cases are still in use
int
IPC_CommonClientContext_init_descriptors(IPC_CommonClientContext *common,
		Map *desc_map, Map *transfer_map,
		struct TransferDesc *descs, int num_transfer_descs,
		Map *wrappee_map,
		struct TransferDesc *wrappee_descs, int num_wrappee_descs,
		/* Kernel descriptors are copied */
		struct KernelTransferDesc *kernel_descs, int num_kernel_descs) {
  int i;
  common->num_transfer_descs = num_transfer_descs;

  if(copy_from_generic(desc_map, 
		       (char *)&common->transfer_descs[0], descs, 
		       sizeof(*descs) * common->num_transfer_descs)) {
    printk("access error while copying caller descriptors "
	   "(loc is %p, map is %p, num is %d)\n",
	   descs, desc_map, common->num_transfer_descs);
    show_stack(NULL);
    return -SC_ACCESSERROR;
  }
  // Filter out flags and perform virt to phys translation
  for(i=0; i < common->num_transfer_descs; i++) {
    struct TransferDesc *desc = &common->transfer_descs[i];
    desc->access &= ~TRANSFER_KERNEL_MODE_MASK;
    int need_get = 1;
    int orig_user_mode = 
      (desc->access & TRANSFER_USER_MODE_MASK) >> TRANSFER_USER_MODE_SHIFT;
    switch(orig_user_mode) {
    case IPC_MODE_NORMAL:
      common->transfer_map = transfer_map;
      break;
    case IPC_MODE_TRANSFERPAGE: {
      // If pages are physical, they are owned by kernel ; need to have transfer_map = NULL to have proper translation
      common->transfer_map = NULL;
      int phys_base;
      if( ( phys_base = fast_virtToPhys(transfer_map, desc->u.direct.base & PAGE_MASK, 1,
				 desc->access & IPC_WRITE) ) == 0 ) {
	printk_red("v2p(%p) translation error in init_descriptors!\n", desc->u.direct.base);
	return -SC_ACCESSERROR;
      }
      // Sanity check alignment
      if((desc->u.direct.base & PAGE_OFFSET_MASK) + desc->u.direct.length > PAGE_SIZE) {
	printk_red("TRANSFERPAGE crosses multiple pages!\n");
	return -SC_INVALID;
      }

      unsigned int paddr =
	phys_base + (desc->u.direct.base & PAGE_OFFSET_MASK);
      desc->u.direct.base = paddr;
      TransferDesc_set_kmode_physical(desc);
      break;
    }
    case IPC_MODE_COPY_TRANSFERED_DESC:
    case IPC_MODE_CLONE_TRANSFERED_DESC: {
      // If pages are physical, they are owned by kernel ; need to have transfer_map = NULL to have proper translation
      common->transfer_map = NULL;
      int rv = TransferDesc_process_copy_or_clone(desc, &need_get);
      if(rv < 0) {
	return rv;
      }
      break;
    }
    default:
      printk_red("unknown descriptor mode %d at %d\n", orig_user_mode, i);
      return -SC_INVALID;
    }
    if(need_get) {
      TransferDesc_get_phys_pages(&common->transfer_descs[i]);
    }
  }
  
  common->wrappee_map = wrappee_map;
  common->num_wrappee_descs = num_wrappee_descs;
  common->wrappee_descs = wrappee_descs;
  common->num_kernel_transfer_descs = num_kernel_descs;
  memcpy( &common->kernel_transfer_descs[0], kernel_descs,
	 num_kernel_descs * sizeof(kernel_descs[0]) );

  for(i=0; i < common->num_kernel_transfer_descs; i++) {
    TransferDesc_get_phys_pages(&common->kernel_transfer_descs[i].desc);
  }

  return 0;
}

/// XXX move to ipc.c, where ports and connections are (rename that to ipc/struct.c?)
IPC_Msg *IPCMsg_new(IPCMsg_Type type, IPC_Connection *connection, int len) {
  IPC_Msg *msg;

  msg = (IPC_Msg *) gcalloc(1, sizeof(IPC_Msg));
  msg->data = galloc(len);
  msg->type = type;
  msg->refcnt = 1;

  msg->common_ctx.callee_syscall_sema = SEMA_MUTEX_INIT;
  return msg;
}

/// XXX move to ipc.c, where ports and connections are (rename that to ipc/struct.c?)
static inline void IPCMsg_clean_common(IPC_Msg *msg) {
  assert(msg->refcnt == 0);
  if(msg->interpose.orig != NULL) {
    IPCMsg_put(msg->interpose.orig);
    msg->interpose.orig = NULL;
  }
}

/// XXX move to ipc.c, where ports and connections are (rename that to ipc/struct.c?)
void IPCMsg_normal_dealloc(IPC_Msg *msg) {
  IPCMsg_clean_common(msg);
  IPC_CommonClientContext_dealloc(&msg->common_ctx);

  gfree(msg->data);
  gfree(msg);
}

/// XXX move to ipc.c, where ports and connections are (rename that to ipc/struct.c?)
void IPCMsg_put(IPC_Msg *msg)
{
  int is_zero = atomic_subtract(&msg->refcnt, 1);

  // XXX remove when done
  assert(msg->refcnt >= 0);
  
  if (is_zero) 
  	IPCMsg_normal_dealloc(msg);
}

/// XXX move to ipc.c, where ports and connections are (rename that to ipc/struct.c?)
static inline 
void IPCMsg_fast_partial_init(IPC_Msg *msg, IPC_Connection *connection, IPCMsg_Type type, int message_len) {
  // partial initialization
  msg->type = type;
  msg->refcnt = 1;
  if (connection != NULL)
    IPCConnection_get(connection);

  // detect when we leak a reference
#ifndef FIXED
  printk("WARN: leaking connection\n");
#else
  assert(msg->common_ctx.connection == NULL);
#endif

  msg->common_ctx.connection = connection;  
  msg->interpose.orig = NULL;
  msg->interpose.next_tap_index = 0;
  msg->data_len = message_len;
}

/** IPC specific wrapper around nexusthread_impersonate_push:
    makes the caller thread temporarily execute as the callee */
static inline void
ipcconnection_impersonate_push(IPC_Connection *conn)
{
	assert(conn->dest_port->kernel_handler_ipd);
	nexusthread_impersonate_push(conn->dest_port->kernel_handler_ipd);
}

/** IPC specific wrapper around nexusthread_impersonate_pop */
static inline void
ipcconnection_impersonate_pop(void)
{
	nexusthread_impersonate_pop();
}

/** Only called from ..._queueNewMessage (since Tap is gone) */
static int 
__IPCConnection_queueMessage(IPC_Connection *connection, IPC_Msg *msg) {
  if (!connection->active)
    return -SC_NOTCONNECTED;

  if(connection->dest_port->kernel_async_handler == NULL) {
    BUG_ON_INTERRUPT();
    if(likely(connection->dest_port->state == IPCPORT_ACTIVE)) {
      uqueue_enqueue(connection->dest_port->recv_queue, msg);
      V_t(&connection->dest_port->recv_sema);
    }
  } else {
    // not very asynchronous, now is it?
    ipcconnection_impersonate_push(connection);
    Call_Handle h = ipd_addCall(nexusthread_current_ipd(), &msg->common_ctx);
    connection->dest_port->kernel_async_handler(msg->common_ctx.connection->source->id,
			   h, connection->dest_port->kernel_async_handler_ctx);
    ipcconnection_impersonate_pop();
  }
  return 0;
}

IPC_Msg *IPCConnection_queueNewMessage(IPC_Connection *connection,
				       IPCMsg_Type type,
				       IPD *ipd, Map *map,
				       char *message, int message_len,

				       Map *user_desc_map,
				       struct TransferDesc *user_descs, 
				       int num_transfer_descs,

				       int *err) {
  IPC_Msg *msg;
  int rv;

  BUG_ON_INTERRUPT();

  if (num_transfer_descs > MAX_TRANSFERDESCS) {
    printkx(PK_IPC, PK_WARN, "descriptor count exceeds maximum\n");
    ReturnError(SC_INVALID);
  }

  msg = IPCMsg_new(type, connection, message_len);
  msg->data_len = message_len;

  rv = IPC_CommonClientContext_init_descriptors(&msg->common_ctx, user_desc_map, 
		  				user_desc_map, user_descs, num_transfer_descs, 
						NULL, NULL, 0, NULL, 0);
  if (rv < 0) {
    IPCMsg_put(msg);
    ReturnError(-rv);
  }

  rv = copy_from_generic(map, msg->data, message, message_len);
  if (rv < 0) {
    IPCMsg_put(msg);
    ReturnError(SC_ACCESSERROR);
  }

  rv = __IPCConnection_queueMessage(connection, msg);
  if (rv < 0) {
    IPCMsg_put(msg);
    ReturnError(-rv);
  }

  *err = 0;
  return msg;
}

int 
IPCMsg_copy_data(IPC_Msg *msg, Map *map, char *target, int len) 
{
  assert(len <= msg->data_len);
  return copy_to_generic(map, target, msg->data, len);
}


/** Request handler helper. 
    Listens on a port for incoming requests and copies request to user. */
static IPC_Msg * __ipc_async_recv(IPC_Port *port, IPD *ipd, Map *map, 
		            char *msg_dest, int *message_len_p, int *err)
{
  IPC_Msg *msg;
  int len, rv;
 
  // wait for a message
  if (P_t(&port->recv_sema))  // killed 
    ReturnError(SC_INTERRUPTED);

  msg = uqueue_dequeue(port->recv_queue);
  assert(msg);
  msg->next = msg->prev = NULL;

  len = min(msg->data_len, *message_len_p);
  rv = copy_to_generic(map, msg_dest, msg->data, len);

  if (rv < 0) {
    IPCMsg_put(msg);
    ReturnError(SC_ACCESSERROR);
  }

  *message_len_p = len;
  *err = 0;
  return msg;
}

/** Main Implementation of IPC.svc's AsyncReceive.
    It is not used on calls coming from within the kernel.
 
    XXX: rename to better reflect its purpose */
Call_Handle 
ipc_async_recv(Port_Handle port_handle, IPD *ipd, Map *map, IPC_Msg **msg_p,
	 char *msg_dest, int *msg_dest_len,
	 struct TransferDesc *descriptors, int *ndesc) 
{
  IPC_Port *port;
  IPC_Msg *msg;
  int err;

  // integrity checks
  BUG_ON_INTERRUPT();
  assert(ipd && map);

  port = IPCPort_find(port_handle);
  if (!port)
    return -1;

  // carry out request
  msg = __ipc_async_recv(port, ipd, map, msg_dest, msg_dest_len, &err);
  if (!msg) {
    IPCPort_put(port);
    return -err;
  }

  // copy results to user
  *ndesc = msg->common_ctx.num_transfer_descs;
  if (descriptors) {
    err = copy_to_generic(map, descriptors, msg->common_ctx.transfer_descs, 
			  *ndesc * sizeof(struct TransferDesc));
    if (err) {
      IPCPort_put(port);
      return -err;
    }
  }

  *msg_p = msg;	// refcnt is now transferred to *msg_p
  IPCPort_put(port);
  return ipd_addCall(ipd, &msg->common_ctx);
}

/** Main Implementation of IPC.svc's AsyncDone.
    It is also used on calls coming from within the kernel.
 
    XXX: rename to better reflect its purpose */
int ipc_async_done(Call_Handle call_handle, enum IPC_AsyncDoneType done_type) {
  IPC_CommonClientContext *common;
  IPC_Msg *msg;

  common = ipd_findCall(nexusthread_current_ipd(), call_handle);
  ipd_delCall(nexusthread_current_ipd(), call_handle);
  assert(common);

  msg = CONTAINER_OF(IPC_Msg, common_ctx, common);
  IPCMsg_put(msg);
  return 0;
}

/** Simple {data, len} pair for communication between ipc_send and ipc_recv */
struct ipc_elem {
	void *data;
	int len;
	int caller_id;
};

/** Send a message to a port. 
    Do NOT call this function directly, use interface IPC_Send, instead.
 
    @return -1 on failure.
             0 on success if caller must free data
             1 on success if caller must treat data as being freed */
int
ipc_send(Map *caller_map, int port_num, char *data, int dlen)
{
	struct ipc_elem *elem;
	IPC_Port * port;
	int reuse;

	// find port
	port = IPCPort_find(port_num);
	if (!port || port->state != IPCPORT_ACTIVE)
		return -1;

	// create transmission structure to attach to queue
	elem = galloc(sizeof(*elem));
	elem->len = dlen;
	elem->caller_id = (curt && curt->ipd) ? curt->ipd->id : 0;
		
	// if kernel data: don't create a copy, take over control
	if (caller_map == kernelMap) {
		elem->data = data;
		reuse = 1;
	}
	else {
		elem->data = galloc(elem->len);
		if (copy_from_generic(caller_map, elem->data, data, dlen)) {
			printkx(PK_IPC, PK_WARN, "[ipc] copy failed");
			gfree(elem->data);
			gfree(elem);
			return -1;
		}
		reuse = 0;
	}

	// enqueue and wake callee
	BUG_ON_INTERRUPT();
	uqueue_enqueue(port->recv_queue2, elem);
	V(&port->recv_sema2);

	return reuse;
}

/** Kernel version of IPC.sc:Send */
int
IPC_Send(int port_num, void *data, int dlen)
{
	int err;
	err = ipc_send(kernelMap, port_num, data, dlen);
	if (err != 1)
		gfree(data);

	return err == 1 ? 0 : -1;
}

/** Block a thread listening on input on a port.
    Do NOT call this function directly, use interface IPC_Recv, instead.
    
    @return -1 on failure, or the number of bytes written to buf on success. */
int
ipc_recv(int port_num, char *buf, int blen, int *caller_id)
{
	struct ipc_elem *elem;
	IPC_Port * port;
	int len;

	// lookup port
	port = IPCPort_find(port_num);
	if (!port) {
		printkx(PK_IPC, PK_WARN, "[ipc] %s no port\n", __FUNCTION__);
		return -1;
	}

	// block waiting for data
	if (P(&port->recv_sema2)) {
		// thread killed
		return -1;
	}

	elem = uqueue_dequeue(port->recv_queue2);

	if (blen < elem->len) {
		printkx(PK_IPC, PK_WARN, "[ipc] %s out of room %d < %d\n", 
			__FUNCTION__, blen, elem->len);
		return -1;
	}

	// copy data
	if (copy_to_generic(port->ipd->map, buf, elem->data, elem->len)) {
		printkx(PK_IPC, PK_WARN, "[ipc] %s cp error\n", __FUNCTION__);
		return -1;
	}

	// set metadata
	len = elem->len;
	if (caller_id)
		*caller_id = elem->caller_id;

	gfree(elem->data);
	gfree(elem);

	return len;
}

/** Kernel version of IPC.sc:Recv */
int
IPC_Recv(int port_num, void *buf, int blen)
{
	return ipc_recv(port_num, buf, blen, NULL);
}

/** Main Implementation of IPC.svc's AsyncSend.
    It is also used on calls coming from within the kernel. */
int ipc_async_send(IPC_Connection *connection, IPD *ipd, Map *map,
	     char *message, int message_len,
	     Map *user_desc_map, 
	     struct TransferDesc *user_descs, int num_transfer_descs) {
  // printk_red("send(%d)", message_len);
  int rval = -1;
  int err = 0;

  IPC_Msg *msg = 
    IPCConnection_queueNewMessage(connection,
				  IPCMsg_Original, 
				  ipd, map,
				  message, message_len,
				  user_desc_map,
				  user_descs, num_transfer_descs,

				  &err);
  if(unlikely(msg == NULL)) {
    rval = -err;
    goto out;
  }
  IPCMsg_put(msg);
  rval = 0;

 out:
  return rval;
}

/** Main implementation of Invoke (RPC Call)
    Called from IPC.sc and from calls within the kernel

    XXX see if interaction with RecvCallHelper can be simplified
*/
int CallHelper(IPD *ipd, IPC_Connection *connection, 
	       struct IPC_ClientContext *cctx, Map *message_map, 
	       char *message, int message_len) {
  struct IPC_ServerContext *server_ctx;
  UThread *server_thread;
  IPC_Port *port;
  
  assert(connection->active);	// should have been verified by callers
  assert(cctx == nexusthread_ipc_top(nexusthread_self()));
  assert(connection->dest_port);

  port = connection->dest_port;
  cctx->dest_port = connection->dest_port;
  cctx->ipd = ipd;
  cctx->message_map = message_map;
  cctx->message = message;
  cctx->message_len = message_len;
  cctx->result_code = SC_NOERROR;

  // this is the only codepath between both user and kernel clients for both
  // user and kernel services. This is the sole policy enforcement point.
  // 
  // XXX somehow extract the parameter from the call that gives us an ID/handle
  if (nxguard_verify(connection->dest_port->port_num, 
		     message_map, message, message_len, ipd->id))
    return -SC_ACCESSERROR;

  // hand off request to the server
  // kernel or userspace server?
  if (port->kernel_call_handler) {
    cctx->server_thread_id = (int) port->kernel_call_handler;

    if (!IS_SYSCALL_IPCPORT(port->port_num)) {
      ipcconnection_impersonate_push(connection);
      port->kernel_call_handler(nexusthread_self());
      ipcconnection_impersonate_pop();
    } else {
      port->kernel_call_handler(nexusthread_self());
    }
  } 
  else {
again:
    server_thread = (UThread *) IPCPort_dequeueServerThread(port);
    if (!server_thread) // thread was killed
	    goto again;

    cctx->server_thread_id = nexusthread_id((BasicThread*) server_thread);
    server_ctx = nexusthread_ipc_server((BasicThread *) server_thread);

    // match server with caller
    // See comment in RecvCall for why this access needs to be serialized
    P(server_ctx->mutex);
    if (server_ctx->callee_state == CALLEESTATE_KILLED) {
      printk_red("%d.%d detected callee killed (callee went first), port = %d\n", 
		 ipd->id, nexusthread_self()->id, connection->dest_port->port_num);
      nexusthread_put((BasicThread *)server_thread);
      V(server_ctx->mutex);
      goto again;
    }

    server_ctx->caller = nexusthread_self();
    nexusthread_get((BasicThread*)server_ctx->caller);
    V(server_ctx->mutex);

    V(server_ctx->call_sema_0);

    if (P(&cctx->call_sema_1)) {
      nexusthread_put((BasicThread *)server_thread);
      IPCPort_addServerThread(port, (BasicThread *) server_thread); 
      return -SC_INTERRUPTED;
    }

    if (cctx->result_code == SC_PEERKILLED) {
      printk_red("detected callee killed (caller went first)!\n");
      assert(server_ctx->callee_state == CALLEESTATE_KILLED);
      nexusthread_put((BasicThread *)server_thread);
      IPCPort_addServerThread(port, (BasicThread *) server_thread); 
      goto again;
    }

    nexusthread_put((BasicThread *)server_thread);
    IPCPort_addServerThread(port, (BasicThread *) server_thread); 
  }
  // Done with call, cleanup

  return cctx->result_code;
}

/** Originally an interpositioning wrapper, it seems. 
    Only called from within the kernel, so we pass through.  */
int Dispatch_IEvent(IPC_Connection *connection, char *message, int message_len, struct TransferDesc *descs, int num_descs) {
  BasicThread *t = nexusthread_self();
  IPC_ClientContext *cctx = nexusthread_ipc_top(t);

  // descriptors come from the kernel (NULL resolves to kernel map)
  IPC_CommonClientContext_init_descriptors(&cctx->common_ctx, NULL, NULL, 
				           descs, num_descs,
				           NULL, NULL, 0, NULL, 0);

  return CallHelper(nexusthread_current_ipd(), connection, cctx, NULL, message,
		    message_len);
}

/** Equivalent of IPC.svc:RecvCall for calls from within the kernel */
Call_Handle IPC_RecvCall(Port_Handle _target_thread, char * message_dest, int * message_len_p, CallDescriptor * cdesc) {
  BasicThread *target_thread = (BasicThread *)_target_thread;
  struct IPC_ClientContext *cctx;
  int len;

  cctx = nexusthread_ipc_top(target_thread);
  len = min(*message_len_p, cctx->message_len);
  if (copy_from_generic(cctx->message_map, message_dest, cctx->message, len))
    nexuspanic();

  *message_len_p = len;

  assert(cctx->ipd); // eh? should we use this?
  return ipd_addCall(nexusthread_current_ipd(), &cctx->common_ctx);
}

/** Equivalent of IPC.svc:Invoke for calls from within the kernel */
int IPC_Invoke(Connection_Handle conn_handle,
	     char *message, int message_len, 
	     struct TransferDesc *descs, int num_descs) {

  IPC_ClientContext *client_cctx;
  IPC_Connection *connection;
  BasicThread *t;
  IPD *ipd;
  int rv;

  ipd = nexusthread_current_ipd();

  // this call (and the other kernel versions of IPC.svc) may only be called 
  // from kernel code. However, this does not mean that they must be called 
  // from kernel IPDs. It is possible for a user process to call a kernel 
  // function that calls one of these. Example: KernelFS_add_IPCPort
  //
  // therefore, do not restrict to kernel IPDs.
  //assert(ipd_is_kernel(ipd));

  t = nexusthread_self();
  assert(t);

  // XXX deprecated port->kernel_connection option.
  // remove if it never fires
  assert(!IS_KERNEL_CONNHANDLE(conn_handle));

  if (conn_handle == INVALID_HANDLE)
    return -SC_INVALID;

  connection = ipd_findConnection(ipd, conn_handle);
  if (!connection)
    return -SC_INVALID;

  if (!connection->active) {
    printk("Calling port %d with closed connection (handle %d)\n", 
	    connection->dest_port->port_num, conn_handle);
    nexuspanic();
    return -SC_INVALID;
  }

  client_cctx = IPC_ClientContext_new(t, connection);
  client_cctx->common_ctx.connection = connection;
  IPCConnection_get(connection);
  
  nexusthread_ipc_push(t, client_cctx);
  client_cctx->call_type = SYS_IPC_Invoke_CMD;

  rv = Dispatch_IEvent(connection, message, message_len, descs, num_descs);
  
  IPC_ClientContext *popped = nexusthread_ipc_pop(t);
  barrier();
  assert(client_cctx == popped);
  IPC_ClientContext_put(client_cctx);
  //IPC_ClientContext_put(popped); // twice? really??
  IPCConnection_put(connection);
  return rv;
}

// Wake up the client that is waiting on a synchronous that we just handled.
// Only called from ReturnHelper, i.e. from CallReturn.
//
// with the caching gone, the NULL assignment is probably no longer needed.
// XXX: remove and get the V in the right few places
static int 
DoReturn(IPD *ipd, Map *map, IPC_Port *port, struct IPC_ClientContext *cctx) {
  int in_kernel;

  assert(cctx->dest_port);
  in_kernel = IPCPort_isKernel(cctx->dest_port);
  cctx->dest_port = NULL;	/*prevent transfers, multiple returns from ocurring 
				  XXX: remove all this if the assert never fires */
  
  if (!in_kernel)
    V(&cctx->call_sema_1);

  return -SC_NOERROR;
}

/** Main Implementation of IPC.svc: CallReturn. 
    Also called from kernel calls */
int IPC_ReturnHelper(Call_Handle call_handle, IPD *ipd, Map *map) {
  int err = 0;

  struct IPC_CommonClientContext *common;
  struct IPC_ClientContext *client_cctx;

  common = ipd_findCall(ipd, call_handle);
  assert(common);
  ipd_delCall(ipd, call_handle);

  P(&common->callee_syscall_sema);
      
  client_cctx = CONTAINER_OF(IPC_ClientContext, common_ctx, common);
  assert(client_cctx->call_type == SYS_IPC_Invoke_CMD);
  err = DoReturn(ipd, map, NULL, client_cctx);

  V(&common->callee_syscall_sema);
  return err;
}

/// XXX: someone call the janitor
static int IPC_CommonClientContext_get_descriptor(IPC_CommonClientContext *common,
					    int desc_num, 
					    KernelTransferDesc *target_desc) {
  if (0 <= desc_num && desc_num < common->num_transfer_descs) {
    target_desc->map = common->transfer_map;
    target_desc->desc = common->transfer_descs[desc_num];
    return 0;
  } 
#ifdef DO_DEPRECATED_DESC
  else if(IS_WRAPPEE_DESCNUM(desc_num)) {
    desc_num = GET_WRAPPEE_DESCNUM(desc_num);
    if(desc_num >= common->num_wrappee_descs) {
      printk_red("%d.%d invalid wrappee descnum %d / %d\n", 
		 nexusthread_current_ipd()->id, nexusthread_self()->id,
		 desc_num, common->num_wrappee_descs);
      return -SC_INVALID;
    }
   
    target_desc->map = common->wrappee_map;
    target_desc->desc = common->wrappee_descs[desc_num];
  } 
  else if(IS_KERNEL_DESCNUM(desc_num)) {
    desc_num -= FIRST_KERNEL_DESCNUM;
    if(desc_num >= common->num_kernel_transfer_descs) {
      printk_red("invalid kernel descnum\n");
      return -SC_INVALID;
    }
    *target_desc = common->kernel_transfer_descs[desc_num];
  } 
#endif
  else {
#ifndef DO_DEPRECATED_DESC
    assert(!IS_KERNEL_DESCNUM(desc_num));
#endif
    printk_red("invalid descriptor %d\n", desc_num);
    return -SC_INVALID;
  }
}

/** Main Implementation of IPC.svc: TransferTo/TransferFrom.
    Is not used in calls from within the kernel
    
   XXX djwill: this should be changed so that the max transfer len is <= 4096 */
int IPC_TransferHelper(Call_Handle call_handle,
			      IPD *ipd,
			      Map *map,
			      int desc_num, unsigned int remote, void *local, int len,
			      int from_caller) {
  KernelTransferDesc kdesc;
  IPC_CommonClientContext *common;
  Map *dest_map;
  char *dest, *temp;
  int err, rv;

  if (!len)
    return 0;

  common = ipd_findCall(ipd, call_handle);
  assert(common);

  P(&common->callee_syscall_sema);

  // retrieve and verify descriptor
  rv = IPC_CommonClientContext_get_descriptor(common, desc_num, &kdesc);
  if (rv < 0) {
    V(&common->callee_syscall_sema);
    return rv;
  }

  if (!(kdesc.desc.access & (from_caller == 1 ? IPC_READ : IPC_WRITE))) {
    V(&common->callee_syscall_sema);
    return -SC_ACCESSERROR;
  }

  if ((void *) remote == DESCRIPTOR_START) {
    remote = kdesc.desc.u.direct.base;
    assert(len <= kdesc.desc.u.direct.length);
  }

  if (TransferDesc_get_kmode(&kdesc.desc) == IPC_KMODE_PHYSICAL)
    remote = PHYS_TO_VIRT(remote);

  // copy from user
  // for security, copy into and out of kernel
  temp = galloc(len);	
  if (from_caller == 1) {
    dest_map = map;
    dest = local;

    if (copy_from_generic(kdesc.map, temp, (char *)remote, len))
      goto error;
  }
  else {
    dest_map = kdesc.map;
    dest = (char *) remote;

    if (copy_from_generic(map, temp, local, len))
      goto error;
  }

  // copy to user
  err = transfer_user(dest_map, (unsigned int) dest, 
		      NULL, (unsigned int) temp, len);
  if (err)
    goto error;

  gfree(temp);
  V(&common->callee_syscall_sema);
  return SC_NOERROR;

error:
  gfree(temp);
  V(&common->callee_syscall_sema);
  return -SC_ACCESSERROR;
}

/** Open a connection from a process to a port.

    @return -1 on failure or a valid connection on success */
Connection_Handle
ipc_connect(IPD *ipd, Port_Num port_num)
{
	IPC_Connection *connection;
	IPC_Port *port, *unused;

	port = IPCPort_find(port_num);
	if (!port) {
		printkx(PK_IPC, PK_WARN, "[ipc] connect: no such port %d\n", port_num);
		return -1;
	}

	// ask the port's primitive guard if it is a kernel port.
	// user ports have no option to deny connections. This option is
	// gone because they never used it: DoBindAccept allways accepted.
	if (port->kernel_bind_handler &&
	    port->kernel_bind_handler(nexusthread_self(), &unused)) {
		printkx(PK_IPC, PK_WARN, "[ipc] connect: port %d refused\n", port_num);
		return -1;
	}

	// create the connection
	connection = IPCConnection_new(ipd, port, 0);
	IPCConnection_open(connection);
	return ipd_addConnection(ipd, connection, -1);
}

static void cleanup_ipc_server(BasicThread *t) {
  struct IPC_ServerContext *server_ctx = nexusthread_ipc_server(t);
  if(server_ctx->caller != NULL) {
    nexusthread_put(server_ctx->caller);
    server_ctx->caller = NULL;
  }
}

/** Simple two-step lookup. 
    IDL generates calls to this.
    This used to contain a hack, but now lost purpose.
    */
Port_Num CallHandle_to_Port_Num(IPD *ipd, Call_Handle call_handle) {
  IPC_CommonClientContext *cctx;

  cctx = ipd_findCall(ipd, call_handle);
  assert(cctx && cctx->connection && cctx->connection->dest_port); // XXX: remove
  return cctx->connection->dest_port->port_num;
}

/** Simple two-step lookup.
    This used to contain a hack, but now lost purpose.
    XXX: clean up */
IPC_Msg *
CallHandle_to_IPC_Msg(IPD *ipd, Call_Handle call_handle) 
{
  IPC_CommonClientContext *common;
  
  common = ipd_findCall(ipd, call_handle);
  assert(common);
  
  return CONTAINER_OF(IPC_Msg, common_ctx, common);
}

/** Tail of RecvCallHelper. 
    Only called directly from that function 
    or (deprecated) indirectly through RecvCallFork */
static Call_Handle
__RecvCallCont(IPC_Port *port, struct IPC_ServerContext *server_ctx,
	       char *msg_dest, int *message_len_p, unsigned int *ipd_id_p) {
  int msg_dest_len, transfer_len;
  BasicThread *self = nexusthread_self();
  IPD *ipd = nexusthread_current_ipd();
  Map *map = nexusthread_current_map();
  BasicThread *caller = server_ctx->caller;

  // XXX ASHIEH 10/15: top might be popped off if caller is killed!
  // Probably want to convert to use cctx directly
  struct IPC_ClientContext *cctx = nexusthread_ipc_top(caller);
  IPC_ClientContext_get(cctx);

  // copy message
  if(copy_from_generic(map, (char *)&msg_dest_len, message_len_p, 
		       sizeof(msg_dest_len))) {
    printk("error getting message len\n");
    goto access_error;
  }
  
  transfer_len = min(cctx->message_len, msg_dest_len);
  if(transfer_user(map, (unsigned int)msg_dest, 
		   cctx->message_map, (unsigned int)cctx->message,
		   transfer_len) != 0) {
    printk("Error transfering message data between maps (len %d)\n", transfer_len);
    goto access_error;
  }
  if (transfer_len != cctx->message_len)
    printk("warning: not all data returned in ipc_recvCall (%d %d)\n", transfer_len, cctx->message_len);

  // why?
  if(copy_to_generic(map, message_len_p, (char *)&transfer_len, sizeof(*message_len_p)) != 0) {
    printk("error writing message len\n");
    goto access_error;
  }

  assert(ipd_id_p != NULL);
  if(cctx->ipd != NULL) {
    *ipd_id_p = cctx->ipd->id;
  } else {
    *ipd_id_p = 0;
  }

  assert(cctx->common_ctx.num_transfer_descs < MAX_TRANSFERDESCS);

  cctx->result_code = SC_NOERROR;
  IPCPort_put(port);

  cleanup_ipc_server(self);
  IPC_ClientContext_put(cctx);
  return ipd_addCall(ipd, &cctx->common_ctx);

 access_error:
  IPCPort_put(port);
  IPC_ClientContext_put(cctx);
  return -SC_ACCESSERROR;
}


/** Serverside handler of IPC.svc's RecvCall and RecvCallFork for userspace services.
    Servers call RecvCall(Fork), which calls this function, which blocks in 
    addServerThread. Clients add a call context and call dequeueServerThread.*/
Call_Handle
RecvCallHelper(Port_Handle port_handle,
	       char *msg_dest, int *message_len_p,
	       unsigned int *ipd_id_p) {
  assert(port_handle >= 0);

  IPD *ipd = nexusthread_current_ipd();
  Map *map = nexusthread_current_map();
  BasicThread *self = nexusthread_self();
  IPC_Port *port = IPCPort_find(port_handle);
  BasicThread *caller = NULL;

#define DORETURN_ERROR(ERR)			\
  cctx->result_code = ERR;			\
  DoReturn(ipd, map, port, cctx);

#define RETURN_ERROR(X)				\
  do {						\
    cleanup_ipc_server(self);			\
    return -(X);				\
  } while(0)

  if(port == NULL) {
    printk("recvcall: Unknown port %d\n", port_handle);
    RETURN_ERROR(SC_INVALID);
  }
  if (port->ipd != ipd) {
    printk("recvcall: ipd (%d) does not match port (%d) ipd (%d)\n",
	   ipd->id, port->port_num, port->ipd->id);
    IPCPort_put(port);
    RETURN_ERROR(SC_ACCESSERROR);
  }

  IPCPort_addServerThread(port, self);

  // Need to put ref to the client thread. This is imbalanced (put in
  // RecvCallCont) on the normal path, but balanced (put in this
  // function) on the error path
  struct IPC_ServerContext *server_ctx = nexusthread_ipc_server(self);

  if(P(server_ctx->call_sema_0)) {
    // printk_red("callee killed, maybe before caller arrived\n");

    // It's possible that a caller has V'ed the server in the interim
    // Handling this case is tricky

    // We use serialization between this and the client
    // This restricts interleaving to 2 cases:
    // Case 1: Caller finishes mutex first
    //   In this case, return result code of SC_PEERKILLED to client via DoReturn()
    // Case 2: Callee finishes mutex first
    //   Caller detects callee_state == CALLEESTATE_KILLED, tries a different server thread

    // In both cases, the server thread is still effectively "on"
    // the receive queue, hence the invariant between receive queue
    // length and counting semaphore length is preserved
    P(server_ctx->mutex);
    server_ctx->callee_state = CALLEESTATE_KILLED;
    if(server_ctx->caller != NULL) {
      printk_red("caller actually arrived, will release from barrier\n");
      caller = server_ctx->caller;
      // XXX ASHIEH 10/15: top might be popped off if caller is killed!
      // Probably want to convert to use cctx directly
      struct IPC_ClientContext *cctx = nexusthread_ipc_top(caller);
      IPC_ClientContext_get(cctx);
      DORETURN_ERROR(SC_PEERKILLED);
      IPC_ClientContext_put(cctx);
    }
    V(server_ctx->mutex);
    IPCPort_put(port);

    IPCPort_rmServerThread(port, self);

    RETURN_ERROR(SC_INTERRUPTED);
  }

    return __RecvCallCont(port, server_ctx, msg_dest, message_len_p, ipd_id_p);
#undef RETURN_ERROR
}

int TransferDesc_process_copy_or_clone(struct TransferDesc *desc, int *p_need_get) {
  IPC_CommonClientContext *template;
  KernelTransferDesc template_kdesc;
  struct TransferDesc orig_desc;
  int orig_user_mode;
  
  orig_desc = *desc;
  template = ipd_findCall(nexusthread_current_ipd(), orig_desc.u.copy_or_clone.call_handle);
  orig_user_mode = TransferDesc_get_umode(desc);

  if (!template) {
    printk_red("clone or copy (%d): lookup failure\n", orig_user_mode);
    return -SC_INVALID;
  }
      
  memset(&template_kdesc, 0, sizeof(template_kdesc)); // to keep gcc happy
  IPC_CommonClientContext_get_descriptor(template,
					 orig_desc.u.copy_or_clone.desc_num, 
					 &template_kdesc);
  if(TransferDesc_get_kmode(&template_kdesc.desc) != IPC_KMODE_PHYSICAL) {
    printk_red("tried to clone or copy a descriptor that is not physical\n");
    goto out_put;
  }

  {
    int orig_access = 
      template_kdesc.desc.access & TRANSFER_ACCESS_MODE_MASK,
      new_access = 
      orig_desc.access & TRANSFER_ACCESS_MODE_MASK;
    if((new_access & orig_access) != new_access) {
      printk_red("new access mode is stronger than orig access mode!\n");
      goto out_put;
    }
  }

  int rel_end = orig_desc.u.copy_or_clone.rel_base + orig_desc.u.copy_or_clone.length;
  if( !(orig_desc.u.copy_or_clone.rel_base == 0 &&
       rel_end == template_kdesc.desc.u.direct.length) ) {
    printk_red("warning: descriptor sub-delegation not tested!\n");
  }

  if(rel_end > template_kdesc.desc.u.direct.length) {
    printk_red("relative end %d is greater than the length of template (%d), adjusting\n", 
	       rel_end, template_kdesc.desc.u.direct.length);
    rel_end = template_kdesc.desc.u.direct.length;
  }
  desc->u.direct.length = rel_end - orig_desc.u.copy_or_clone.rel_base;

  if(orig_user_mode == IPC_MODE_CLONE_TRANSFERED_DESC) {
    desc->u.direct.base = template_kdesc.desc.u.direct.base + orig_desc.u.copy_or_clone.rel_base;
  } else if(orig_user_mode == IPC_MODE_COPY_TRANSFERED_DESC) {
    // there is only one reference to these new phys pages
    *p_need_get = 0;
    int num_pages = 
      PAGE_ROUNDUP(template_kdesc.desc.u.direct.base + rel_end - 
		   (template_kdesc.desc.u.direct.base & PAGE_MASK) ) / PAGE_SIZE;
    assert(num_pages * PAGE_SIZE > desc->u.copy_or_clone.length);

    void *vaddr = getKernelPages(num_pages);
    int len = orig_desc.u.copy_or_clone.length;
    char *src = (void *) PHYS_TO_VIRT(template_kdesc.desc.u.direct.base + orig_desc.u.copy_or_clone.rel_base);

    desc->u.direct.base = VIRT_TO_PHYS(vaddr) + (template_kdesc.desc.u.direct.base & PAGE_OFFSET_MASK);
    memcpy((void *)PHYS_TO_VIRT(desc->u.direct.base), src, len);
  }
  TransferDesc_set_kmode_physical(desc);
  return 0;
 out_put:
  return -SC_INVALID;
}

/** Equivalent of IPC.svc:AsyncSend for calls from within the kernel */
int
IPC_CallReturn(Call_Handle call_handle) 
{
  if (nexusthread_check_fastsyscall(nexusthread_self(), call_handle))
    return 0;

  return IPC_ReturnHelper(call_handle, nexusthread_current_ipd(), NULL);
}

/** Equivalent of IPC.svc:TransferTo for calls from within the kernel */
int 
IPC_TransferTo(Call_Handle call_handle, int desc_num, 
	       unsigned int remote, void * local, int len) 
{
  BasicThread *t = nexusthread_self();

  if (nexusthread_check_fastsyscall(t, call_handle)) {
    // default options for services responding to RecvCall
    if(desc_num == RESULT_DESCNUM && remote == DESCRIPTOR_START)
      remote = (__u32) ((UThread *) t)->fast_syscall_result_dest;
    return poke_user(nexusthread_current_map(), remote, local, len);
  }

  return IPC_TransferHelper(call_handle,
			    nexusthread_current_ipd(), NULL,
			    desc_num, remote, local, len,
			    0);
}

/** Equivalent of IPC.svc:TransferFrom for calls from within the kernel */
int 
IPC_TransferFrom(Call_Handle call_handle, int desc_num, void * local, 
		 unsigned int remote, int len) 
{
  if (nexusthread_check_fastsyscall(nexusthread_self(), call_handle))
    return peek_user(nexusthread_current_map(), remote, local, len);

  return IPC_TransferHelper(call_handle,
			    nexusthread_current_ipd(), NULL,
			    desc_num, remote, local, len,
			    1);
}

/** Equivalent of IPC.svc:AsyncSend for calls from within the kernel */
int IPC_AsyncSend(Connection_Handle conn_handle,
	      void *message, int message_len,
	      struct TransferDesc *descs,
	      int num_transfer_descs) {
  IPD *ipd;
  IPC_Connection *connection;
  int rv;
  
  assert(conn_handle != INVALID_HANDLE);
  
  ipd = nexusthread_current_ipd();
  assert(ipd_is_kernel(ipd));

  connection = ipd_findConnection(ipd, conn_handle);
  assert(connection);

  rv = ipc_async_send(connection, ipd, NULL, message, message_len, NULL, descs, num_transfer_descs);

  IPCConnection_put(connection);
  return rv;
}

/** Equivalent of IPC.svc:AsyncDone for calls from within the kernel */
int IPC_AsyncDone(Call_Handle call_handle0, enum IPC_AsyncDoneType done_type) 
{
  return ipc_async_done(call_handle0, done_type);
}

