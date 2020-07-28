syscall IPC {
  decls {
    includefiles {
	"<nexus/defs.h>",
	"<nexus/syscall-defs.h>",
	"<nexus/syscalls.h>",
	"<nexus/transfer.h>",
	"<nexus/ipc.h>",
	"<nexus/hashtable.h>",
	"<nexus/util.h>",
    }

    enum PortCapability {
      IS_OWNER,
    };

    // convenience struct for passing arguments necessary for TransferFrom/To
    struct TransferContext {
      Call_Handle call_handle;
      struct VarLen *varlen;

      int user_data[2];
    };

    struct CallDescriptor {
      Call_Handle call_handle;
      IPD_ID ipd_id;
    };

    struct IPC_Connection;

    enum IPC_PrepDirection {
      IPC_PREP_INPUT,
      IPC_PREP_OUTPUT,
    };

    enum IPC_AsyncDoneType {
      IPC_ASYNC_DONE,
      IPC_ASYNC_PASSTHROUGH,
      IPC_ASYNC_DROP,
    };

    /** Return from an RPC-style call.

        If a service accepts an RPC request with IPC_RecvCall, it signals
        that it has completed the call by calling this function. 
     
        @param call_handle is the handle to the active call acquired 
	       with IPC_RecvCall 
        @return zero on success, unspecified failure otherwise */
    int IPC_CallReturn(Call_Handle call_handle);

    /** Transfer data to the other endpoint of an IPC connection
        
        @param call_handle must be a handle initialized e.g., by IPC_DoBind 
        @param desc num is the number of descriptors. 
	       for RPC replies, this is RESULT_DESCNUM
	@param remote is a pointer to the start of a descriptor array
	       for RPC replies, this is DESCRIPTOR_START
        @param local is the buffer to transfer
        @param len is the length of the buffer 
     
        @return zero on success, unspecified failure otherwise */
    int  IPC_TransferTo(Call_Handle call_handle, int desc_num, unsigned int remote, void * local, int len);

    /** Transfer data from the other endpoint of an IPC connection.
        Parameters, semantics and return value are identical to TransferTo */
    int  IPC_TransferFrom(Call_Handle call_handle, int desc_num, void * local, unsigned int remote, int len);

    int Dispatch_IEvent(struct IPC_Connection *connection, 
		    	char *message, int message_len, 
			struct TransferDesc *descs, int num_descs);

    // Deprecated. XXX:remove all traces once IDL generator no long depends on it
    struct ForkedInfo {
      int is_forked;
      Call_Handle call_handle;
    };

    typedef struct AsyncReceiveInfo {
      IPD_ID ipd_id;
      Call_Handle call_handle;
      int message_len;
      int num_transfer_descs;
    } AsyncReceiveInfo;

    typedef struct AsyncDoneSpec {
      Call_Handle call_handle;
      enum IPC_AsyncDoneType done_type;
    } AsyncDoneSpec;

    int IPC_AsyncDone(Call_Handle call_handle0, enum IPC_AsyncDoneType done_type);
  }

  decls __callee__ {
    includefiles {
      "<nexus/defs.h>",
	"<nexus/util.h>",
	"<nexus/ipc.h>",
	"<nexus/elf.h>",
	"<nexus/thread.h>",
	"<nexus/ipc_private.h>",
	"<nexus/clock.h>",
	"<nexus/util.h>",
	"<nexus/thread-private.h>",
	"<nexus/thread-inline.h>",
	"Debug.interface.h",
	"<nexus/syscall-private.h>",
	"Debug.interface.h",
	"<nexus/mem.h>",
    }
  }

  decls __caller__ {
    includefiles {"<stdlib.h>"}
  }

 /** Invoke a system call through the IPC layer
    
   Functionally identical to Invoke, except for interface modifiers.
   But the kernel routes calls to InvokeSys differently from those
   to Invoke, so do not call for anything but syscalls (and vice versa) */
  interface __NoGenErrno__ __BareCall__ int
    InvokeSys(Connection_Handle conn_handle,
	 char *message, int message_len,
	 struct TransferDesc *user_descs,
	    int num_transfer_descs) {

    return IPC_Invoke_Handler(ipd_id, call_handle, message_data, 0,
			      conn_handle, message, message_len, 
			      user_descs, num_transfer_descs);
  }

  /** Invoke a Service function through the IPC Layer

      @return the total length of the message if >= 0, or an error code */

  interface __BareCall__ int /* result code (negative), or total length of message */
    Invoke(Connection_Handle conn_handle,
	 char *message, int message_len,
	 struct TransferDesc *user_descs,
	 int num_transfer_descs) {
    struct IPC_ClientContext *client_cctx = NULL;
    IPD *ipd = nexusthread_current_ipd();
    Map *map = nexusthread_current_map();
    BasicThread *thread = nexusthread_self();
    int dbg = 0;
    int rval = -1;

    if(message_len > MAX_IPC_MESSAGE_LEN) {
      printk("Call message len > max\n");
      return -SC_INVALID;
    }

    if(num_transfer_descs > MAX_TRANSFERDESCS) {
      printk("Too many transfer descs\n");
      return -SC_INVALID;
    }

    IPC_Connection *connection = ipd_findConnection(ipd, conn_handle);
    if (!connection) {
      printk("Call: No connection found for conn handle %d (ipd=%d.%d)\n", conn_handle, ipd->id, nexusthread_self()->id);
      //nexusthread_dump_regs_stack(nexusthread_self());
      rval = -SC_INVALID;
      goto out_put;
    }
    if (!connection->active) {
      printk("Call: connection is not connected (ipd %d=> %d)!\n",
	     ipd->id, connection->dest_port->port_num);
      rval = -SC_NOTCONNECTED;
      goto out_put;
    }

    Map *message_map = NULL;

    client_cctx = IPC_ClientContext_new(thread, connection);
    nexusthread_ipc_push(thread, client_cctx);
    client_cctx->call_type = SYS_IPC_Invoke_CMD;

    /* There will be multiple accesses to this message. To avoid */
    /* inconsistencies due to multithreading (and hence security */
    /* problems), make one and only one copy. */
    if(peek_user(map, (unsigned)message, client_cctx->message_data, message_len) != 0) {
      printk("Call: error copying from user\n");
      rval = -SC_ACCESSERROR;
      goto out_put;
    }
    message = client_cctx->message_data;
    message_map = NULL;

    /* XXX can optimize this by bypassing the setup for a pass-through call  */
    IPC_CommonClientContext_init_descriptors(&client_cctx->common_ctx,
					     map, map, user_descs, num_transfer_descs,
					     NULL, NULL, 0, NULL, 0);

      if( (rval = CallHelper(ipd, connection, client_cctx, message_map,
			     message, message_len)) != 0) {
	goto out_put;
      }
  out_put:

    if(client_cctx != NULL) {
      IPC_ClientContext *popped = nexusthread_ipc_pop(thread);
      barrier(); // dealloc may wake up waiting server threads, which need to notice that the client has been popped
      assert(popped == client_cctx);
      IPC_ClientContext_put(client_cctx);
      IPC_ClientContext_put(popped);
    }
    if(connection != NULL) {
      IPCConnection_put(connection);
    }

    if(rval == -2 || dbg)printk("call returning %d\n", rval);
    return rval;
  }

  /** Variant of RecvCall that forks of a worker
      XXX remove as soon as IDL stop generating callers */
  interface __BareCall__ Call_Handle
    RecvCallAndFork(Port_Handle port_handle,
		    char *message_dest, int *message_len_p,
		    CallDescriptor *call_descriptor, struct ForkedInfo *forked) {
    printk("Warning: deprecated %s called\n", __FUNCTION__);
    assert(0);
    return -1;
  }

  /** Blocks until a request is made, then returns with the request data. */
  interface __BareCall__ Call_Handle
    RecvCall(Port_Handle port_handle,
	     char *message_dest, int *message_len_p,
	     CallDescriptor *call_descriptor) {

    CallDescriptor rv;
    int ret;

    rv.ipd_id = -1;
    rv.call_handle = RecvCallHelper(port_handle,
			            message_dest, message_len_p,
			            (unsigned int *) &rv.ipd_id);

    ret = poke_user(nexusthread_current_map(), (__u32) call_descriptor, 
		    &rv, sizeof(rv));

    if (rv.call_handle < 0)
      return rv.call_handle;

    if (ret)
	    return ret;

    return rv.call_handle;
  }

  interface __BareCall__ int /* result code */
    CallReturn(Call_Handle call_handle0 /* can't name this call_handle because that is the name of a built-in parameter */) {
    // Audit 5/31/2006: depends on IPC_ReturnHelper
#define CHECK_CALL_HANDLE(X) if(IS_KERNEL_CALLHANDLE(X)) {printk_red("user tried to pass in kernel direct call handle %p\n", (X)); return -SC_INVALID; }
    CHECK_CALL_HANDLE(call_handle0);
    return IPC_ReturnHelper(call_handle0,
			    nexusthread_current_ipd(), nexusthread_current_map());
  }

  interface __BareCall__ int /* result code */
    TransferFrom(Call_Handle call_handle0, int desc_num,
		 void *local, unsigned int remote, int len) {
    CHECK_CALL_HANDLE(call_handle0);
    return IPC_TransferHelper(call_handle0,
			  nexusthread_current_ipd(), nexusthread_current_map(),
			  desc_num, remote, local, len, 1);
  }

  interface __BareCall__ int /* result code */
    TransferTo(Call_Handle call_handle0, int desc_num,
	       unsigned int remote, void *local, int len) {
    CHECK_CALL_HANDLE(call_handle0);
    return IPC_TransferHelper(call_handle0,
			  nexusthread_current_ipd(), nexusthread_current_map(),
			  desc_num, remote, local, len,
			  0);
  }

  /** Open a connection to a port.
      Name is not ideal, should be OpenConnection */
  interface Connection_Handle
  BindRequest(Port_Num port_num) {
      return ipc_connect(nexusthread_current_ipd(), port_num);
  }

  interface int /* result code */
  CloseConnection(Connection_Handle conn_handle) {
    IPD *ipd = nexusthread_current_ipd();
    IPC_Connection *connection = 
      ipd_findConnection(ipd, conn_handle);
    if(connection == NULL) {
      printk_red("no connection %d, can't close\n", conn_handle);
      nexusthread_dump_regs_stack(nexusthread_self());
      return -SC_INVALID;
    }
    int rv = IPCConnection_close(connection);
    if(rv != 0) {
      return rv;
    }
    ipd_delConnection(ipd, conn_handle);
    IPCConnection_put(connection);
    return 0;
  }

  /* kwalsh: rename to GetOwner(port_num) */
  interface int
    CheckCap(Port_Num port_num, IPD_ID check_ipd_id, enum PortCapability cap) {
    // Audited 6/2/2006: arguments used safely
    /*
       	port_num: verifies that port_num refers to valid port
	check_ipd_id: verifies that it is valid ipd_id
	cap: switch catches invalid values (with default case)
		IS_OWNER: safe parameter accesses

    */
#define UNWIND(LEVEL, ERR) do { err = -ERR; goto err_ ## LEVEL; } while(0)
    int err;
    IPC_Port *port = IPCPort_find(port_num);

    if(port == NULL) {
      printk("%s: Unknown port %d\n", __FUNCTION__, port_num);
      UNWIND(preport, SC_INVALID);
    }

    IPD *check_ipd = ipd_find(check_ipd_id);
    if(check_ipd == NULL) {
      printk("ipd id %d does not correspond to actual ipd\n", check_ipd_id);
      UNWIND(port, SC_INVALID);
    }
    switch(cap) {
    case IS_OWNER:
      // printk("check: (%d) %d %d\n", port_num, check_ipd_id, port->ipd->id);
      err = (check_ipd_id == port->ipd->id);
      break;
    default:
      printk("Unknown capability %d\n", cap);
      UNWIND(port, SC_INVALID);
    }

  err_port:
      IPCPort_put(port);
  err_preport:
      return err;
  }

  interface IPD_ID GetMyIPD_ID(void) {
    return nexusthread_current_ipd()->id;
  }

  /* XXX deprecated due to weird calling convention and limited args support */
  interface IPD_ID /* IPD_ID */ FromElf(const char *name, int namelen,
				     const unsigned char *elf, int len,
				     const char *arg, int arglen) {
    if(namelen <= 0)
      return -SC_INVALID;
    if(len <= 0)
      return -SC_INVALID;
    if(arglen < 0)
      return -SC_INVALID;
    if(name == NULL)
      return -SC_INVALID;
    if(elf == NULL)
      return -SC_INVALID;
    if(arglen > 0 && arg == NULL)
      return -SC_INVALID;

    unsigned char *kname = (unsigned char *)galloc(namelen);
    unsigned char *kelf = (unsigned char *)galloc(len);
    char *karg = (char *)galloc(arglen+1);

    //printk_red("allocated %d %d %d\n", namelen, len, arglen);

    peek_user(nexusthread_current_map(), (unsigned int)name, kname, namelen);
    peek_user(nexusthread_current_map(), (unsigned int)elf, kelf, len);
    if (arglen > 0) peek_user(nexusthread_current_map(), (unsigned int)arg, karg, arglen);
    karg[arglen] = '\0';

    /* sanity check name and arg */
    if(find_badchar(kname, 0) != -1 || karg[arglen-1] != '\0'){
      printk_red("bad karg or kname %s\n", kname);
      gfree(kname);
      gfree(kelf);
      gfree(karg);
      return -1;
    }

    // count up the user args
    int uargs = 0, ulen = 0;
    while (ulen < arglen) {
      uargs++;
      ulen += strlen(karg + ulen) + 1;
    }

    char **kargs = galloc((1 + uargs) * sizeof(char *));
    kargs[0] = (char *)kname;
    uargs = 0;
    ulen = 0;
    while (ulen < arglen) {
      kargs[++uargs] = karg + ulen;
      ulen += strlen((char *)karg + ulen) + 1;
    }
    kargs[uargs] = NULL;

    UThread *thread = NULL;
    IPD *kipd = ipd_fromELF((unsigned char *) kname, (unsigned char *) kelf, 
		            len, 1 + uargs, kargs, 0, &thread);

    gfree(kname);
    gfree(kelf);
    gfree(karg);
    gfree(kargs);

    if(thread == NULL){
      printk_red("bad loadelf\n");
      //XXX cleanup
      //XXX ipd_destroy();
      //Map_destroy(kspace);
      return -1;
    }

    nexusthread_start((BasicThread *)thread, 0);
    return kipd->id;

  }

  interface int
  Exec(const unsigned char *elf, int len, const char *arg) {
	  return ipd_exec(elf, len, arg);
  }

    /** Acquire a port to listen on. 
        This is the Nexus IPC equivalent of bind() 
     
	@param new_num must hold a pointer to a Port_Num. 
	       if the value of new_num is not -1, it is interpreted as
	       a request for a specific port. In both cases, on return
	       it holds the value of the new port.

	       @return holds the same value as new_num, because
	       Port_Num and Port_Handle are now coalesced. 

	@return a valid port handle if greater than (or equal to?) zero,
	        an error otherwise */

  interface Port_Handle 
  CreatePort(Port_Num *new_num) {
    return ipc_create_port(nexusthread_current_ipd(), nexusthread_current_map(), 
		          NULL, new_num);
  }

    /** Close a port acquired with IPC_CreatePort. 
       
        @param oid must be an active port handle
        @return zero on success, all others are failure */
  interface int 
  DestroyPort(Port_Handle port_handle) {
    return ipc_destroy_port(nexusthread_current_ipd(), port_handle);
  }
  
  /** Send a message to a port. 
 
      @param data is the data to send. The block is not freed.
      @return 0 on success, -1 on failure. */
  interface int
  Send(int port_num, void *data, int dlen) {
	int err;

	err = ipc_send(nexusthread_current_map(), port_num, data, dlen);
	assert(err == -1 || err == 0); // XXX: remove if not triggered
	return err;
  }

  /** Block a thread listening on input on a port.

      On successful return, data will have been written into buf. If 
      buf is too small to hold an entire message, reception fails.
    
      @return -1 on failure, or number of bytes written to buf. */
  interface int
  Recv(int port_num, void *buf, int blen) {
	// XXX convention says copy_from_user blen and port_num
	return ipc_recv(port_num, buf, blen, NULL);
  }

  /** Recv, but also ask from the callers ipd->id */
  interface int
  RecvFrom(int port_num, void *buf, int blen, int *from) {
	  return ipc_recv(port_num, buf, blen, from);
  }

  interface  __BareCall__ 
     AsyncReceiveInfo AsyncReceive(Port_Handle port_handle,
			   char *user_message,
			   int max_message_len,
			   struct TransferDesc *user_transfer_descs /* [ MAX_TRANSFERDESCS] */) {
#ifdef DO_DEPRECATED_ASYNC
    /* Audited 5/11/2006 */
    /* Changed assert(0) on error to return error codes */
    IPC_Msg *msg;
    int num_transfer_descs = 0;
    Call_Handle h =
      ipc_async_recv(port_handle, nexusthread_current_ipd(), nexusthread_current_map(),
	       &msg,
	       user_message, &max_message_len,
	       user_transfer_descs,
	       &num_transfer_descs);
    // BUG: cannot return a stack variable.
    AsyncReceiveInfo rv = {
      .ipd_id = (msg != NULL ? msg->common_ctx.connection->source->id : IPD_INVALID),
      .call_handle = h,
      .message_len = max_message_len,
      .num_transfer_descs = num_transfer_descs,
    };
    if(msg != NULL) {
      IPCMsg_put(msg);
    }
    return rv;
#else
    printk("Warning: deprecated %s called\n", __FUNCTION__);
    assert(0);

    // bogus. never reached. keep compiler happy.
    AsyncReceiveInfo rv;
    memset(&rv, 0, sizeof(rv));
    return rv;
#endif
  }

  interface  __BareCall__ int AsyncDone_sys(Call_Handle call_handle0, enum IPC_AsyncDoneType done_type) {
#ifdef DO_DEPRECATED_ASYNC
    CHECK_CALL_HANDLE(call_handle0);
    return ipc_async_done(call_handle0, done_type);
#else
    printk("Warning: deprecated %s called\n", __FUNCTION__);
    return -1;
#endif
  }

  interface  __BareCall__ int AsyncSend(Connection_Handle conn_handle,
			void *user_message, int message_len,
			struct TransferDesc *user_descs,
			int num_transfer_descs) {
#ifdef DO_DEPRECATED_ASYNC
    /* Audited 5/11/2006 */
    /* rewrote ipc_async_send() to properly return error messages */
    /* potential resource exhaustion by sending messages */
    int foo;
    // tap-interpose will be invoked, and will touch these bytes
    // XXX can probably fix this thrashing with cache coloring
    prefetch_rw0((char *)&foo - L1_CACHE_BYTES);
    prefetch_rw0((char *)&foo - 2 * L1_CACHE_BYTES);

    IPC_Connection *connection = 
      ipd_findConnection(nexusthread_current_ipd(), conn_handle);
    if(unlikely(connection == NULL)) {
      printk("IPC_AsyncSend(): invalid port\n");
      return -SC_INVALID;
    }

    Map *m = nexusthread_current_map();
    int rv = ipc_async_send(connection,
		    nexusthread_current_ipd(), m,
		    user_message, message_len,
		    m, user_descs, num_transfer_descs);
    IPCConnection_put(connection);
    return rv;
#else
    printk("Warning: deprecated %s called\n", __FUNCTION__);
    return -1;
#endif
  }

  interface int IPD_GetName(IPD_ID the_ipd_id, char *namebuf, int maxnamelen)
  {
    IPD *ipd = ipd_find(the_ipd_id);
    if (!ipd) return -SC_INVALID;
    Map *map = nexusthread_current_map();
    if (poke_strncpy(map, (unsigned int)namebuf, ipd->name, maxnamelen) != 0) {
      return -SC_ACCESSERROR;
    } else {
      return 0;
    }
  }
}

