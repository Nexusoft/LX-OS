syscall IPC {
  decls {
    includefiles {
	"u:<stdlib.h>",
	"u:<unistd.h>",
	"u:<stdio.h>",
	"<nexus/defs.h>",
	"<nexus/syscall-defs.h>",
	"<nexus/syscalls.h>",
	"<nexus/transfer.h>",
	"<nexus/ipc.h>",
	"<nexus/hashtable.h>",
	"<nexus/util.h>",
    }

    struct CallDescriptor {
      Call_Handle call_handle;
      int ipd_id;
    };

    enum IPC_AsyncDoneType {
      IPC_ASYNC_DONE,
      IPC_ASYNC_PASSTHROUGH,
      IPC_ASYNC_DROP,
    };

    // Deprecated. XXX:remove all traces once IDL generator no long depends on it
    struct ForkedInfo {
      int is_forked;
      Call_Handle call_handle;
    };

    // Deprecated. XXX:remove all traces once IDL generator no long depends on it
    typedef struct AsyncReceiveInfo {
      IPD_ID ipd_id;
      Call_Handle call_handle;
      int message_len;
      int num_transfer_descs;
    } AsyncReceiveInfo;

    // Deprecated. XXX:remove all traces once IDL generator no long depends on it
    static inline int 
    IPC_AsyncDone(Call_Handle call_handle0, enum IPC_AsyncDoneType done_type) 
    {
      nxcompat_printf("Warning: deprecated %s called\n", __FUNCTION__);
      return -1;
    }

    // Deprecated. XXX:remove all traces once IDL generator no long depends on it
    static inline AsyncReceiveInfo 
    AsyncReceive(int port, char *msg, int mlen, struct TransferDesc *desc)
    {
	static AsyncReceiveInfo rv;
        return rv;	        
    }

    /** Create a local copy of the data in descriptor desc_id */
    static inline char *
    ipc_transferfrom(int desc_id, int len)
    {
  	extern int IPC_TransferFrom(Call_Handle deprecated, int desc_num,
	       			    void *local, unsigned long off, int len);
    	char * data;

  	data = nxcompat_alloc(len);
  	IPC_TransferFrom(0, desc_id, data, 0, len);
  	return data;
    }

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
	"<nexus/guard.h>",
	"<nexus/util.h>",
	"<nexus/thread-private.h>",
	"<nexus/thread-inline.h>",
	"Debug.interface.h",
	"<nexus/syscall-private.h>",
	"Debug.interface.h",
	"<nexus/mem.h>",
    }
  }

 /** Invoke a system call through the IPC layer 
      NB: parameters MUST be the same as for Invoke (see below) */
  interface __NoGenErrno__ __BareCall__ int
    InvokeSys(int portnum, char *msg, int mlen,
	      struct TransferDesc *descs, int dnum) 
  {
	  // never reached: SYS_IPC_InvokeSys_CMD is caught in syscall.c
	  return -1;
  }

  /** Invoke a Service function through the IPC Layer

      NB: parameters MUST be the same as for InvokeSys 
          (uses same backend in kernel/core/syscall.c)

      @return the total length of the message if >= 0, or an error code */
  interface __BareCall__ int /* result code (negative), or total length of message */
    Invoke(int portnum, char *msg, int mlen,
	   struct TransferDesc *descs, int dnum) 
  {
	  // never reached: SYS_IPC_Invoke_CMD is caught in syscall.c
	  return -1;
  }

  /** Blocks until a request is made, then returns with the request data. */
  interface Call_Handle
    RecvCall(int port, char *msg, int *mlen,
	     CallDescriptor *rv) 
  {
    rv->ipd_id = 0; // XXX deprecated
    rv->call_handle = rpc_recvcall_user(port, msg, mlen);

    return rv->call_handle;
  }

  /** Return from an RPC-style call.

      If a service accepts an RPC request with IPC_RecvCall, it signals
      that it has completed the call by calling this function. 
   
      @return zero on success, unspecified failure otherwise */
  interface int /* result code */
  CallReturn(Call_Handle deprecated) 
  {
    rpc_callreturn();
    return 0;
  }

  /** Return the ID of the process issuing an RPC request, or -1 on failure */
  interface int
  Caller(void) 
  {
    return rpc_caller();
  }

  /** Return the ID of the process listening on an IPC port, or -1 on failure */
  interface int
  Server(int ipc_port)
  {
    return ipc_server(ipc_port);
  }

  /** In an LRPC session, transfer data from the server to the client.
      Parameters, semantics and return value are identical to TransferTo */
  interface int
  TransferFrom(Call_Handle deprecated, int desc_num,
	       void *local, unsigned long off, int len) 
  {
    if (!curt->rpc_caller)
      return -SC_ACCESSERROR;

    return rpc_transfer(curt->rpc_caller, desc_num, local, off, len, 1);
  }

    /** Transfer data to the other endpoint of an IPC connection
        
        @param desc num is the number of descriptors. 
	       for RPC replies, this is RESULT_DESCNUM
        @param local is the buffer to transfer
        @param len is the length of the buffer 
     
        @return zero on success, unspecified failure otherwise */
  interface int
  TransferTo(Call_Handle deprecated, int desc_num,
	     void *local, unsigned long off, int len) 
  {
    if (!curt->rpc_caller)
      return -SC_ACCESSERROR;

    return rpc_transfer(curt->rpc_caller, desc_num, local, off, len, 0);
  }

  /** Copy VarLen data from an RPC call, like TransferFrom.
      It is used by a (trusted) guard for parameter inspection.

      Unlike TransferFrom, this can be called from a process not directly 
      involved in RPC. As a result, it is a possible privacy breach
      and must be guarded. */
  interface int
  TransferInterpose(int desc_num, void *local, 
		    int off, int len, int doread)
  {
    if (!len || !curt->rpc_caller)
    	return -SC_ACCESSERROR;
    
    int ret = rpc_transfer(curt->rpc_caller, desc_num, local, off, len, doread);

    // DEBUG XXX REMOVE
    printk_current("NXDEBUG: interposed pid=%d on pid=%d | ret=%d len=%d data=%c%c...\n", 
		    curt->ipd->id, curt->rpc_caller->ipd->id,
		    ret, len, ((char *) local)[0], ((char *) local)[1]);
    nexuspanic();
    return ret;
  }

  /** Copy serialized (i.e., not VarLen) data from an RPC call */
  interface int
  TransferParam(void *data, int off, int len)
  {
    return rpc_param(data, off, len);
  }

  interface int
  Poll(int port_num, int dir)
  {
	  return ipc_poll(port_num, dir);
  }

  /** Return number of bytes ready for immediate reading */
  interface unsigned long
  Available(int port_num)
  {
	  return ipc_available(port_num);
  }

  /** Wait for a number of ipc ports at once.
      See ipc_wait for more information */
  interface int
  Wait(long *portnums, char *results, int len)
  {
	if (!portnums || !results)
		return -1;

	return ipc_wait(portnums, results, len);
  }

  /** Wake up anyone waiting on this port */
  interface int
  Wake(long portnum, int direction)
  {
	  return ipc_wake(portnum, direction);
  }

  /** Attach to a process and interpose on all its calls */
  interface int
  Interpose(int pid, int port_num)
  {
	  struct IPC_Port *port;
	  IPD *ipd;
	  int ret;

	  port = IPCPort_find(port_num);
	  if (!port)
		  return -1;
	  // Block infinite recursion due to process
	  // interposing on its own Interpose[In|Out] call(s)
	  if (port->ipd->id == pid) {
	  	  IPCPort_put(port);
		  return -1;
	  }

	  ipd = ipd_find(pid);
	  if (!ipd)
		  ret = -1;
	  else
		  ret = nxkguard_interposition_set(port->ipd, port_num) ? 1 : 0;
	  IPCPort_put(port);
	  return ret;
  }

  /** Start an in-kernel reference monitor */
  interface int
  Refmon_Start(int id)
  {
	  return nxrefmon_start(id);
  }

  /** Start a new process */
  interface int
  Exec(const unsigned char *elf, int len, const char *arg, unsigned long flags)
  {
	  UThread *thread;

	  // build process
	  thread = ipd_load(elf, len, arg);
	  if (!thread)
		  return -1;

	  // execute
	  return elf_exec_direct(thread, flags);
  }

  /** Start a new process, caller interposes on all calls to child */
  interface int
  ExecInterposed(const unsigned char *elf, int len, 
		 const char *arg, unsigned long flags,
		 int interpose_port)
  {
	  UThread *thread;

	  // build process
	  thread = ipd_load(elf, len, arg);
	  if (!thread)
		  return -1;

	  if (nxkguard_interposition_set(thread->ipd, interpose_port)) {
		  ipd_kill(thread->ipd);
		  return -1;
	  }

	  // execute
	  return elf_exec_direct(thread, flags);
  }

  /** Wait for process to die */
  interface int
  WaitPid(int pid)
  {
	  return ipd_waitpid(pid);
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
  CreatePort(Port_Num new_num) 
  {
    return ipc_create_port(nexusthread_current_ipd(), 
		    	   curr_map, new_num);
  }

    /** Close a port acquired with IPC_CreatePort. 
       
        @param oid must be an active port handle
        @return zero on success, all others are failure */
  interface int 
  DestroyPort(Port_Handle port_handle) 
  {
    return ipc_destroy_port(nexusthread_current_ipd(), port_handle);
  }
  
  /** Send a message to a port. 
 
      @param data is the data to send. The block is not freed.
      @param dlen is datalen. if 0, call will block until queue is ready
      @return 0 on success, -1 on failure. */
  interface int
  Send(int port_num, void *data, int dlen) 
  {
	return ipc_send(curr_map, port_num, data, dlen);
  }

  /** Block a thread listening on input on a port.

      On successful return, data will have been written into buf. If 
      buf is too small to hold an entire message, reception fails.
    	
      @param blen is the buffer. if 0, call will block until data is available
      @return -1 on failure, or number of bytes written to buf. */
  interface int
  Recv(int port_num, void *buf, int blen) 
  {
	return ipc_recv(curr_map, port_num, buf, blen, NULL);
  }

  /** Recv, but also ask from the callers ipd->id */
  interface int
  RecvFrom(int port_num, void *buf, int blen, int *from) 
  {
	  return ipc_recv(curr_map, port_num, buf, blen, from);
  }

  /** Send one complete page. The page will be unmapped from the caller
      @param data must be page aligned 
   
      @return 0 on success, -1 on failure */
  interface int
  SendPage(int port_num, void *data)
  {
	  return ipc_sendpage_impl(curr_map, port_num, data);
  }

  /** Recv one complete page.
      Caller must release the page using Mem_FreePages, IPC_SendPage, etc.. 
    
      @param data must hold a pointer to receive the new vaddr
      @param caller is NULL or will hold the process calling SendPage
      @return 0 on success, -1 on failure (in which case data is undefined) */
  interface int
  RecvPage(int port_num, 
	   unsigned long /* (void **) but IDL does not support that */ data,
	   int *caller)
  {
	  return ipc_recvpage_impl(curr_map, port_num, (void **) data, caller);
  }
  
  interface  int 
  AsyncSend(Connection_Handle conn_handle, 
	    void *user_message, int message_len,
	    struct TransferDesc *user_descs, int num_transfer_descs) 
  {
    printk("Warning: deprecated %s called\n", __FUNCTION__);
    return -1;
  }
}

