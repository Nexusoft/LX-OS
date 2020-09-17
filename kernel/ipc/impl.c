/** NexusOS: implementation of the main IPC system call functions and
             kernel interfaces to allow IPC calls from the kernel. */

#include <nexus/defs.h>
#include <nexus/synch.h>
#include <nexus/galloc.h>
#include <nexus/ipc_private.h>
#include <nexus/guard.h>
#include <nexus/transfer.h>
#include <nexus/mem-private.h>

#include <nexus/IPC.interface.h>
#include <nexus/Console.interface.h>

/// deprecated. XXX remove as soon as idlgen stops calling this
int 
IPC_userInit(void)
{
	return 0;
}


////////  low-level packet based IPC  ////////

/** Simple {data, len} pair for communication between ipc_send and ipc_recv */
struct ipc_elem {
	struct QItem elem;

	void *data;
	int len;
	int off;
	int caller_id;
};

/** Send a message to a port. 
    Do NOT call this function directly, use interface IPC_Send, instead.
 
    @param send_map holds the user memory map or NULL if called from the kernel 
    @return -1 on failure.
             0 on success if caller must free data
             1 on success if caller must treat data as being freed */
int
ipc_send(Map *send_map, int port_num, void *data, int dlen)
{
	struct ipc_elem *elem;
	IPC_Port * port;
	int caller_id, reuse = -1, lvl;

	// sanity check (bound is rather arbitrary)
	if (unlikely(dlen > IPC_MAXSIZE)) {
		printk_current("[ipc] send out of bounds\n");
		return -1;
	}

	lvl = disable_intr();

	// identify caller
	if (!send_map)
		caller_id = 0;
	else
		caller_id = curt->ipd->id;

	// find port
  	if (ipcport_find_safe_noint(port_num, &port)) {
		restore_intr(lvl);
    		return -1;
	}

	// don't queue more than a fixed number of packets
	if (unlikely(port->recv_queue.len == IPCPORT_QUEUELEN)) {
		// in interrupt context: fail rather than block
		if (intcontext_check())
			return -1; // no restore_intr needed in INT
		else
			P_noint(&port->full_sema);
	}

	// return if nothing to transmit (just waiting)
	if (!dlen) {
		reuse = 0;
		goto cleanup;
	}

	// create transmission structure to attach to queue
	elem = gcalloc(1, sizeof(*elem));
	
	// if kernel logical address: don't create a copy, take over control
	if (!send_map) {
		elem->data = data;
		reuse = 1;
	}
	else {
		elem->data = galloc(dlen);
		if (unlikely(transfer(NULL, elem->data, send_map, data, dlen))) {
			printkx(PK_IPC, PK_WARN, "[ipc] copy failed");
			gfree(elem->data);
			gfree(elem);
			goto cleanup;
		}
		reuse = 0;
	}

	// fill in fields
	elem->len = dlen;
	elem->caller_id = caller_id;
		
	// optionally wake listeners (ipc_wait)
	if (port->notify_r) {
		port->notify_set |= IPC_READ;
		V_signal_noint(port->notify_r);
	}

	// enqueue and wake callee
	queue_append(&port->recv_queue, elem);
	if (port->recv_queue.len == 1)
		V_noint(&port->empty_sema);

cleanup:
	restore_intr(lvl);
    	IPCPort_put(port);
	return reuse;
}

/** Shared sub of ipc_recv and ipc_recvpage 
    @param nodata if set, data will not be dequeued */
static struct ipc_elem *
ipc_recv_elem(int port_num, int nodata, int continue_cached)
{
	IPC_Port * port;
	struct ipc_elem *elem;

	assert(check_intr() == 0);

	// lookup port
  	if (ipcport_find_safe_noint(port_num, &port))
    		return NULL;

	elem = NULL;

	// return partially read elem (if any)
	if (continue_cached && port->recv_elem) {
		elem = port->recv_elem;
		goto restore;
	}

	// block waiting for data
	assert(port);
	while (port->recv_queue.len == 0)
		P_noint(&port->empty_sema);
	assert(port->recv_queue.len > 0);

	// only polling 
	if (nodata) {
		elem = (void *) -1;
		goto restore;
	}
	// else dequeue
	else  {
		elem = queue_dequeue(&port->recv_queue);
		assert(elem && elem->caller_id >= 0 && 
		       elem->caller_id <= 10000 /* fairly arbitrary */);

		if (continue_cached)
			port->recv_elem = elem;

		// optionally wake listeners (ipc_wait)
		if (port->notify_w) {
			port->notify_set |= IPC_WRITE;
			V_signal_noint(port->notify_w);
		}

		// wake all listeners (warning: thundering herd)
		if (port->recv_queue.len == IPCPORT_QUEUELEN - 1)
			V_broadcast_noint(&port->full_sema);
	}

restore:
    	IPCPort_put(port);
	return elem;
}

/** Remove a cached (previously partially, now fully, read) element */
static void
ipc_recv_clearelem(int port_num)
{
	IPC_Port *port;

  	if (ipcport_find_safe(port_num, &port))
    		return;
	port->recv_elem = NULL;
    	IPCPort_put(port);
}

/** Block a thread listening on input on a port.
    Do NOT call this function directly, use interface IPC_Recv, instead.
    
    @param recv_map holds the user memory map or NULL if called from the kernel 
    @return -1 on failure, or the number of bytes written to buf on success. */
int
ipc_recv(Map *recv_map, int port_num, void *buf, int blen, int *caller_id)
{
	struct ipc_elem *elem;
	int len, ret, lvl;
	
	lvl = disable_intr();
	
	// get data
	elem = ipc_recv_elem(port_num, blen ? 0 : 1, 1);
	if (unlikely(!elem)) {
		restore_intr(lvl);
		return -1;
	}

	// return without data if only waiting
	if (unlikely(!blen)) {
		restore_intr(lvl);
		return 0;
	}

	// copy data
	len = min(elem->len - elem->off, blen);
	ret = transfer(recv_map, buf, NULL, elem->data + elem->off, len);
	if (unlikely(ret)) {
		printkx(PK_IPC, PK_WARN, "[ipc] %s cp error\n", __FUNCTION__);
		restore_intr(lvl);
		return -1;
	}
	elem->off += len;

	// set metadata
	if (caller_id)
		*caller_id = elem->caller_id;

	// clean 
	if (elem->off == elem->len) {
		gfree(elem->data);
		gfree(elem);
		ipc_recv_clearelem(port_num);
	}

	restore_intr(lvl);
	return len;
}

/** IPC.sc SendPage implementation 
    Do NOT mix SendPage with Recv, as the (de)allocators differ

    @param map holds the user memory map or NULL if called from the kernel 
 */
int 
ipc_sendpage_impl(Map *map, int port_num, void *data)
{
	unsigned long uvaddr;
	struct Page *page;
	int lvl, ret;

	assert(map);
	lvl = disable_intr();

	// only allow full pages
	uvaddr = (unsigned long) data;
	if (uvaddr & (PAGE_SIZE - 1)) {
		printkx(PK_IPC, PK_WARN, "[ipc] unaligned sendpage\n");
		restore_intr(lvl);
		return -1;
	}

	// translate
	if (uvaddr < KERNELVADDR)
		page = PHYS_TO_PAGE(fast_virtToPhys_locked(map, uvaddr, 0, 0));
	else
		page = VIRT_TO_PAGE(uvaddr);

	// unmap from sender domain
	assert(page->refcnt >= 1);
	if (uvaddr < KERNELVADDR) {
		// keep page refcnt >0 after removing it from user map
		page_get(page, kernelMap);  
		Map_free(map, uvaddr, 1); 
	}

	// send using standard IPC
	// NB: because map is NULL, ipc_send will not be able to set caller id 
	//     correctly for ipc_recvfrom
	ret = ipc_send(NULL, port_num, (void *) page, PAGE_SIZE) == 1 ? 0 : -1;
	
#ifndef NDEBUG
	map->account_mmap_send++; // accounting
#endif
	restore_intr(lvl);
	return ret;
}

/** IPC.sc RecvPage implementation 
    Do NOT mix Send with RecvPage, as the (de)allocators differ
 */
int
ipc_recvpage_impl(Map *map, int port_num, void **data, int *caller)
{
	struct ipc_elem *elem;
	struct Page *page;
	int lvl, ret = -1;

	assert(map);
	lvl = disable_intr();
	
	// acquire data
	elem = ipc_recv_elem(port_num, 0, 0);
	if (unlikely(!elem || elem->len != PAGE_SIZE)) {
		restore_intr(lvl);
		return -1;
	}

	// find an available virtual address in the user map
	page = (struct Page *) elem->data;

	if (map == kernelMap) {
		*data = (void *) VADDR(page);
	}
	else {
		*data = (void *) Map_insertNear(map, page, 1, 1, 1, vmem_heap);
		page_put(page, kernelMap); // inverse of page_get in .._sendpage_..
	}
	assert(page->refcnt >= 1);

	// set metadata
	if (caller)
		*caller = elem->caller_id;

	gfree(elem);
#ifndef NDEBUG
	map->account_mmap_recv++; // accounting
#endif

	restore_intr(lvl);
	return 0;
}


////////  polling and blocking  ////////

/** Helper. If do_async is true, test asynchronous notification alongside
    actual queues. Can say true even if no data is waiting (any more). 
 
    @return a combination of IPC_READ and IPC_WRITE */
static inline int
ipc_poll_noint(IPC_Port *port, char request, int do_async)
{
	int ret, qlen;
	
	assert(check_intr() == 0);
	
	// has an asynchronous notification (->notify) been signaled?
	// this will return true even if the queue has emptied in the meantime:
	// useful for waiting on keyboard input
	ret = 0;
	if (do_async && port->notify_set)
		ret = port->notify_set;
	
	// check actual queue state
	qlen = queue_length(&port->recv_queue);
	if ((request & IPC_READ) && (port->recv_elem || qlen))
		ret |= IPC_READ;
	if (request & IPC_WRITE) {
		if (likely(qlen < IPCPORT_QUEUELEN))
			ret |= IPC_WRITE;
		else
			// XXX wake up listener when port becomes writable again
			printk_red("[ipc] not writable\n");
	}

	return ret;
}

/** See if the port is ready for reading (without blocking): 
    recv() will complete without blocking
    @return 1 if data is waiting, 0 otherwise 
 
    NB: expects recv() to be willing to continue a cached item, if any */
int
ipc_poll(int port_num, int directions)
{
	IPC_Port *port;
	int ret, lvl;
	
	lvl = disable_intr();
  	if (ipcport_find_safe_noint(port_num, &port))
    		ret = -1;
	else
		ret = ipc_poll_noint(port, directions, 0);
	restore_intr(lvl);

	return ret;
}

/** Return the number of bytes that can be read 
    There is no equivalent for writing, as blocksize is unconstrained */
unsigned long
ipc_available(int port_num)
{
	IPC_Port * port;
	struct ipc_elem *elem;
	unsigned long len;
	int lvl;

	assert(check_intr() == 1);
  	if (ipcport_find_safe(port_num, &port))
    		return 0;
	
	lvl = disable_intr();
	if (port->recv_elem)
		len = port->recv_elem->len;
	else {
		elem = queue_gethead(&port->recv_queue);
		len = elem ? elem->len : 0;
	} 
	restore_intr(lvl);

	IPCPort_put(port);
	return len;
}

// remove callback from each port to us
static inline void 
ports_detach(IPC_Port **ports, int len)
{
	int i;

	for (i = 0; i < len; i++) {
		ports[i]->notify_w = NULL;
	       	ports[i]->notify_r = NULL;
	}
}

// create callback from each port to us (using a sema)
static inline int 
ports_attach(IPC_Port **ports, char *results, int len, Sema *sema)
{
	int i;

	for (i = 0; i < len; i++) {
		// NB: concurrent waiters on a single port are not allowed
		if (unlikely((ports[i]->notify_r && ports[i]->notify_r != sema) ||
		             (ports[i]->notify_w && ports[i]->notify_w != sema))) {
			printkx(PK_IPC, PK_WARN, "[ipc] double notification denied\n");
			ports_detach(ports, len);
			return -1;
		}

		if (results[i] & IPC_READ)  ports[i]->notify_r = sema;
		if (results[i] & IPC_WRITE) ports[i]->notify_w = sema;
	}

	return 0;
}

/** Test if any ports are ready
    if so, on return results marks all ready descriptors
    otherwise, results is left unchanged, to allow for a repeat call 
 
    @return -1 on error or number of ready ports */
static inline int 
ports_scan(IPC_Port **ports, char *results, int len) 
{
	char result;
	int i, ready = 0;

	for (i = 0; i < len; i++) {
		// safety check: don't handle dirty input
		assert(results[i] >= 0 && results[i] <= (IPC_READ | IPC_WRITE));

		result = ipc_poll_noint(ports[i], results[i], 1);
		if (result) {
			// first data at i: unmark all previous entries
			if (!ready) memset(results, 0, i);

			results[i] = result;
			ready++;
		}
		else {
			// if in 'return ready ports' mode, clear if no data
			if (ready)
				results[i] = 0;
		}
		
		ports[i]->notify_set = 0;
	}

	return ready;
}

/** Wait for any of the list of ports to be ready for reading.
    
    NB: note that only one ipc_wait client can wait on any port
        at the same time

    @param portnums is a list of ports 
    @param results is a list that specifies what to wait on prior to calling
           and what event(s) fired on return: IPC_READ and/or IPC_WRITE
    @param len is the length of both lists

    On return, each entry results[i] will be nonzero for each
               each entry ports[i] that is ready. Otherwise, 
	       it is zero.
    @return number of ready ports on succes or 
            -1 on failure, in which case results is undefined.
 */
int
ipc_wait(long *portnums, char *results, int len)
{
#define MAX_WAITLIST	(32)
	IPC_Port *ports[MAX_WAITLIST + 1];
	Sema ipc_blocksema = SEMA_INIT_SIGNAL;
	int i, ret, lvl;

	// sanity check
	if (unlikely(len > MAX_WAITLIST)) {
		printkx(PK_IPC, PK_WARN, "[ipc] wait list exceeds maximum\n");
		nexuspanic(); // DEBUG XXX REMOVE
		return -1;
	}

	lvl = disable_intr();
	
	// translate port numbers into ports
	for (i = 0; i < len; i++) {
		if (ipcport_find_safe_noint(portnums[i], &ports[i])) {
			printk_red("[ipc] no port %d at wait\n", portnums[i]);
			restore_intr(lvl);
			return 1;
		}
	}
	ret = ports_scan(ports, results, len);
	if (ret)
		goto done;
	
	// nothing ready? attach and start waiting
	ret = ports_attach(ports, results, len, &ipc_blocksema);
	if (ret) 
		goto done;
	P_noint(&ipc_blocksema);
	
	// awoken: scan again and detach
	ret = ports_scan(ports, results, len);
	ports_detach(ports, len);

done:
	for (i = 0; i < len; i++)
		IPCPort_put(ports[i]);
	restore_intr(lvl);
	return ret;
}

/** Wake waiters on the port
    Similar to what ipc_send and _recv do, but without transferring data

    @return 0 on success, -1 on error */
int 
ipc_wake(int portnum, int direction)
{
	IPC_Port * port;
	int lvl;

	lvl = disable_intr();
	if (ipcport_find_safe_noint(portnum, &port))
		return -1;

	port->notify_set |= direction;

	if (direction & IPC_READ && port->notify_r)
		V_signal_noint(port->notify_r);
	else if (direction & IPC_WRITE && port->notify_w)
		V_signal_noint(port->notify_w);
	
	restore_intr(lvl);
	return 0;
}


////////  RPC implementation (shared by IPC.sc and kernel iface)  ////////

int
ipc_server(int ipc_port)
{
	IPC_Port *port;
        int ret;

	if (ipcport_find_safe(ipc_port, &port))
		return -1;

	ret = port->ipd->id;
	IPCPort_put(port);

	return ret;
}
	
/** Main implementation of Invoke (RPC Call)
    Called from IPC.sc and from calls within the kernel
*/
static inline void
rpc_invoke_kernel(IPC_Port *port) 
{
  port->kernel_call_handler(curt);
}

static void
rpc_invoke_user(IPC_Port *port)
{
  UThread *server_thread;
  int lvl;

  lvl = disable_intr();
  
  // setup
  P_noint(&port->thread_sema);
  server_thread = queue_dequeue(&port->thread_queue);
  assert(server_thread);
  // adjust for offset of ->tqueue element with which thread was enqueued
  server_thread = (void *) ((unsigned long) server_thread) - offsetof(struct BasicThread, tqueue);
  assert(server_thread->id < 10000 /* fairly arbitrary sane value */);
  assert(server_thread->schedstate != DEAD);

  // wake up server and wait for reply
  server_thread->rpc_caller = curt;
  V_noint(&server_thread->rpc_wait);
  P_noint(&server_thread->rpc_ready);
  
  restore_intr(lvl);
}

int
rpc_invoke(int portnum) 
{
  IPC_Port *port;

  // call 
  port = IPCPort_find(portnum);
  if (!port)
    return -SC_ACCESSERROR;

  if (likely(port->kernel_call_handler != NULL))
    rpc_invoke_kernel(port);
  else
    rpc_invoke_user(port);

  // cleanup
  IPCPort_put(port);
  return 0;
}

/** Shared implementation of IPC.sc:RecvCall and iface.c:IPC_RecvCall */
static inline int
rpc_recvcall_sub(BasicThread *thread, char *buf, int *blen)
{
  struct IPC_Invoke_Args *args;
  int mlen, id;

  assert(thread);
  assert(thread->ipd);
  assert(thread->callstack_len >= 1);
  args = thread->callstack[thread->callstack_len - 1];

  if (thread != curt && thread->ipd->map) {
	Mem_mutex_lock();
  	args = Map_uvaddr_to_kvaddr(thread->ipd->map, args);
	Mem_mutex_unlock();
  }
  
  mlen = args->mlen;
  if (unlikely(!blen || *blen < mlen)) {
	  printk("[rpc] recvcall buffer too small\n");
	  return -1;
  }

  transfer(curr_map, buf, thread->ipd->map, args->msg, mlen);
  *blen = mlen;
  
  id = thread->ipd->id;
  return id;
}

int
rpc_recvcall_kernel(char *buf, int *blen)
{
  int lvl, ret;

  lvl = disable_intr();
  ret = rpc_recvcall_sub(curt, buf, blen);
  restore_intr(lvl);

  return ret;
}

/** Implementation of IPC.svc's IPC_RecvCall for userspace services.
    Services call this function, which blocks after registering to the port */
int
rpc_recvcall_user(int portnum, char *buf, int *blen) 
{
  IPC_Port *port;
  int ret, lvl;

  lvl = disable_intr();
  if (ipcport_find_safe_noint(portnum, &port) || port->ipd != curt->ipd) {
    restore_intr(lvl);
    return -SC_ACCESSERROR;
  }
  
  // register as handler
  queue_append(&port->thread_queue, &curt->tqueue);
  V_noint(&port->thread_sema);
  
  // wait for client to make request
  P_noint(&curt->rpc_wait);
  
  // handle request
  ret = rpc_recvcall_sub(curt->rpc_caller, buf, blen);
  restore_intr(lvl);

  IPCPort_put(port);
  return ret;
}

/** Implementation of IPC.svc: CallReturn and iface.c:IPC_CallReturn 
    Only called for user-level services (which block the client thread) */
void
rpc_callreturn(void) 
{
  curt->rpc_caller = NULL;
  V(&curt->rpc_ready);
}

/** Main Implementation of IPC.svc: TransferTo/TransferFrom.
    @param dnum is the descriptor number (in state)
           0 for the standard return buffer
	   N-1 for VarLen parameter N in the parameter list
    @param local is the address to copy to
    @param from_copy sets the direction */
int
rpc_transfer(BasicThread *caller, int dnum, 
	     void *local, int off, int len, int from)
{
  struct IPC_Invoke_Args *args;
  struct TransferDesc *desc;
  char *msg;
  void *data;
  int ret, lvl;

  lvl = disable_intr();

  // access arguments 
  assert(caller->callstack_len >= 1);
  args = caller->callstack[caller->callstack_len - 1];
  
  // we may be calling from another task: translate user address
  if (caller->ipd->map) {
	Mem_mutex_lock();
  	args = Map_uvaddr_to_kvaddr(caller->ipd->map, args);
	Mem_mutex_unlock();
  }

  // input checks
  if (unlikely(dnum >= args->dnum)) {
	  printkx(PK_GUARD, PK_WARN, "[rpc] transfer error: illegal desc.\n");
	  restore_intr(lvl);
	  return -SC_ACCESSERROR;
  }

  desc = &args->descs[dnum];
  if (caller->ipd->map)
  	desc = Map_uvaddr_to_kvaddr(caller->ipd->map, desc);

  // more input checks: block writing to read-only memory
  if (unlikely(from == 0 && desc->access == IPC_READ)) {
	  printkx(PK_GUARD, PK_WARN, "[rpc] write blocked\n");
	  restore_intr(lvl);
	  return -SC_ACCESSERROR;
  }

  if (unlikely((len < 0) || (off + len > desc->u.direct.length))) {
	  printkx(PK_GUARD, PK_WARN, "[rpc] transfer out of bounds (%d+%d > %d)\n", 
		  off, len, desc->u.direct.length);
	  restore_intr(lvl);
	  return -SC_NOMEM;
  }

  // set pointers to match direction
  data = (void *) desc->u.direct.base + off;
  if (from)
	  ret = transfer(curr_map, local, caller->ipd->map, data, len);
  else
	  ret = transfer(caller->ipd->map, data, curr_map, local, len);

  restore_intr(lvl);
  return ret ? -SC_ACCESSERROR : SC_NOERROR;
}

/** Copy parameters from the currently executing RPC call 
    All parameters are serialized. Copy any by giving the right offset
    @return 0 on success, -1 on failure */
int
rpc_param(void *data, int off, int len)
{
  struct IPC_Invoke_Args *args;
  BasicThread *caller;
  int lvl, ret = -1;

  lvl = disable_intr();

  // XXX one or two jumps in call stack?
  // (i.e., is a guard (1) or authority (2) calling?)
  caller = curt->rpc_caller;
  if (!caller)
    goto unlock;

  assert(caller->callstack_len);
  args = caller->callstack[caller->callstack_len - 1];
  if (args->mlen < off + len)
    goto unlock;

  transfer(curr_map, data, caller->ipd->map, args->msg + off, len);
  ret = 0;

unlock:
  restore_intr(lvl);
  return ret;
}

/** Return the ID of the process issuing an RPC request, or -1 on failure */
int
rpc_caller(void)
{
  BasicThread *caller;

  caller = curt->rpc_caller;
  return caller ? caller->ipd->id : -1;
}

////////  deprecated  ////////

#include <nexus/thread.h>

// generated by IDLGEN
int
nexusthread_check_fastsyscall(BasicThread *t, Call_Handle call_handle) 
{
  // when InvokeSys invokes a .sc system call it sets CALLHANDLE_SYSCALL
  // which is used to bypass some cross-space copies
  return (t->type == USERTHREAD && call_handle == CALLHANDLE_SYSCALL) ? 1 : 0;
}

