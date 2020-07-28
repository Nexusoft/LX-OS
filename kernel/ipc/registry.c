#include <nexus/defs.h>
#include <nexus/synch.h>
#include <nexus/synch-inline.h>
#include <nexus/mem.h>
#include <nexus/ipc.h>
#include <nexus/queue.h>
#include <nexus/test.h>
#include <nexus/syscalls.h>
#include <nexus/util.h>
#include <nexus/hashtable.h>
#include <nexus/ipc_private.h>
#include <nexus/kernelfs.h>
#include <nexus/thread.h>
#include <nexus/ipd.h>
#include <nexus/Debug.interface.h>

/******** IPC Ports ********/

/** The lookup table storing Port_Num to IPC_Port mappings. */
static struct HandleTable porttable;
static Sema porttable_mutex = SEMA_MUTEX_INIT;

/** sub of ipc_create_port: add the persistent kernel connection */
static void
__ipcport_connect_kernel(IPC_Port *port)
{
	IPC_Connection *conn;
	int rv;

	conn = IPCConnection_new(kernelIPD, port, 1);
	rv = IPCConnection_open(conn);

	port->kernel_connection = conn;

	if (unittest_active_early)
		assert(port->kernel_connection->refcnt == 1);
		// XXX find out if all is well in real scenario
		// assertion does not hold there
}		

static void
__ipcport_disconnect_kernel(IPC_Port *port)
{
	// disconnect from kernel
       	IPCConnection_close(port->kernel_connection);
  	IPCConnection_put(port->kernel_connection);
}

/** Create a new port.
  
    @param port_p will hold a pointer to the new port on return if not NULL
    @param new_num will hold the allocated unique number on return.
           if it is not zero on calling, the passed value is 
	   interpreted as a request.
 
    On return the reference count will already be 3 (in the common case).
    The close function ipc_destroy_port similarly decrements with 3.

    XXX make new_num a regular int. no need to return the value twice

    @return the new port number or -1 on error */
int 
ipc_create_port(IPD *ipd, Map *map, IPC_Port **port_p, Port_Num *new_num) 
{
	static Port_Num next_dynamic = FIRST_DYNAMIC_IPCPORT - FIRST_IPCPORT;
	IPC_Port *port;
	Port_Num num;

	// allocate a port
	port = gcalloc(1, sizeof(IPC_Port));

	// acquire a port number
	P(&porttable_mutex);
	if (new_num) {
		// sanity check
		if (*new_num > 20000) { // arbitrary number outside likely range
			printkx(PK_IPC, PK_WARN, "[ipc] illegal port %d requested\n", *new_num);
			return -1;
		}

		num = (*new_num) - FIRST_IPCPORT;
		// do not allow O as it overlaps with (deprecated) OID_NONE
		if (num <= 0 || HandleTable_find(&porttable, num))
			num = next_dynamic++;
	}
	else
		num = next_dynamic++;
	num = HandleTable_add_ext(&porttable, port, num);
	num += FIRST_IPCPORT;
	V(&porttable_mutex);

#ifndef NDEBUG
	// warn when a requested port was already taken
	if (new_num && *new_num > 0 && num != *new_num)
		printkx(PK_IPC, PK_DEBUG, "[ipc] received port %d, not %d\n", 
			num, *new_num);
#endif

	// initialize nonzero variables
	port->port_num = num;
	port->ipd = ipd;
	port->refcnt = 2; 	// one for the table and one for the caller
	port->state = IPCPORT_ACTIVE;
	port->mutex = SEMA_MUTEX_INIT;
	port->recv_sema = SEMA_INIT_KILLABLE;
	port->recv_sema2 = SEMA_INIT_KILLABLE;
	port->thread_sema = SEMA_INIT_KILLABLE;

	port->recv_queue = uqueue_new();
	port->recv_queue2 = uqueue_new();
	port->thread_queue = uqueue_new();

	// connect to kernel
	__ipcport_connect_kernel(port);		// increments refcount
  	KernelFS_add_IPCPort(port);

	// update call-by-reference parameters
	if (port_p)
		*port_p = port;	
	else
		IPCPort_put(port);
	if (new_num)
		*new_num = num;

	assert(!IPCPort_checkrange(num));
	return num;
}

/** Remove a port. 
    Called from IPCPort_Put when the reference count drops to zero.

    @return 0. This function does not check whether the port existed */
void IPCPort_do_destroy(IPC_Port *port) 
{
	BasicThread *t, *next_thread;
  
	assert(!port->refcnt);
	
	// system call ports should never die
	assert(!IS_SYSCALL_IPCPORT(port->port_num));

	KernelFS_del_IPCPort(port);	
	while ((t = uqueue_dequeue(port->thread_queue)) != NULL)
		nexusthread_put(t);

	uqueue_destroy(port->recv_queue);
	uqueue_destroy(port->thread_queue);
	gfree(port);
	
}

/** Mark a port as closed and flush all waiting messages.
    Contrary to what its name implies, this function does NOT destroy the 
    port. That occurs when the reference count drops to zero. 
 
    XXX rename 

    XXX remove IPCPort_(Create|Destroy)_generic and call ours directly

    @return 0 on success or -1 otherwise */
int ipc_destroy_port(IPD *ipd, Port_Num port_num)
{
	IPC_Port *port;
	IPC_Msg *msg;

	if (IPCPort_checkrange(port_num))
		return -1;

	// release port number
	P(&porttable_mutex);
	port = HandleTable_find(&porttable, port_num - FIRST_IPCPORT);
	HandleTable_delete(&porttable, port_num - FIRST_IPCPORT);
	V(&porttable_mutex);
	assert(port);
	
	port->state = IPCPORT_DESTROYED;
	
	__ipcport_disconnect_kernel(port);	// decrements refcnt

	// empty queue
	while ((msg = uqueue_dequeue(port->recv_queue)) != NULL)
		IPCMsg_put(msg);

	IPCPort_put(port);	// drop table reference
	IPCPort_put(port);	// drop ref acquired in .._find() 
	return 0;
}

/** Lookup a port by its number */
IPC_Port *IPCPort_find(Port_Num port_num) 
{
	IPC_Port * port;

	if (IPCPort_checkrange(port_num))
		return NULL;

	P(&porttable_mutex);
	port = HandleTable_find(&porttable, port_num - FIRST_IPCPORT);
	V(&porttable_mutex);

	if (port)
		IPCPort_get(port);
	return port;
}

/** Standard format unit test for IPC ports 
    XXX move tests to separate test subdir?

    @return 0 on success, -1 on error */
int
IPCPort_unittest(void)
{
	IPC_Port *port, *port2;
	Port_Num num, num2;
       
	//// 1: basic test
	
	// create
	num = ipc_create_port(kernelIPD, NULL, &port, NULL);
	if (num < 0) {
		printkx(PK_TEST, PK_WARNLOW, "[ipcport] could not create port\n");
		return -1;
	}
	assert(port->ipd);

	// find is skipped, because it triggers syscall_lookup for port 0

	// remove
	if (ipc_destroy_port(NULL, num)) {
		printkx(PK_TEST, PK_WARNLOW, "[ipcport] could not destroy port\n");
		return -1;
	}

	//// 2: test number preference and reference counting
	num = FIRST_DYNAMIC_IPCPORT;
	num2 = ipc_create_port(kernelIPD, NULL, &port, &num);
	if (num2 != num) {
		printkx(PK_TEST, PK_WARNLOW, "[ipcport] could not create chosen port\n");
		return -1;
	}
	assert(port->refcnt == 3);
	
	// find
	port2 = IPCPort_find(num);
	if (port2 != port) {
		printkx(PK_TEST, PK_WARNLOW, "[ipcport] could not find port\n");
		return -1;
	}
	assert(port->refcnt == 4);

	// remove
	if (ipc_destroy_port(NULL, num)) {
		printkx(PK_TEST, PK_WARNLOW, "[ipcport] could not destroy port\n");
		return -1;
	}
	assert(port->refcnt == 1);

	// find. should fail
	port2 = IPCPort_find(num);
	if (port2) {
		printkx(PK_TEST, PK_WARNLOW, "[ipcport] incorrectly found port\n");
		return -1;
	}
	
	//// 3: test port ranges
	if (IPCPort_checkrange(FIRST_IPCPORT))
		return -1;
	if (IPCPort_checkrange(LAST_IPCPORT))
	       return -1;

	if (!IPCPort_checkrange(LAST_IPCPORT + 1))
		return -1;
	if (!IPCPort_checkrange(FIRST_IPCPORT - 1))
		return -1;
	if (IPCPort_checkrange(0))
		return -1;
	if (IPCPort_checkrange(-1))
		return -1;

	IPCPort_put(port);
	return 0;
}

/** Make a thread wait on the listening queue of the given port */
void 
IPCPort_addServerThread(IPC_Port *port, BasicThread *t) 
{
  nexusthread_get(t);
  uqueue_enqueue(port->thread_queue, t);
  V(&port->thread_sema);
}

/** Remove a waiting thread from the given queue 
    @return 0 if deleted, 1 if was already killed */
int
IPCPort_rmServerThread(IPC_Port *port, BasicThread *t) 
{
  if (P(&port->thread_sema))
	  return 1; // thread was killed
  uqueue_delete(port->thread_queue, t);
  nexusthread_put(t);
  return 0;
}

/** Dequeue a thread from the port's waiting queue */
BasicThread *
IPCPort_dequeueServerThread(IPC_Port *port) 
{
  if (P(&port->thread_sema))
	  return NULL; // thread was killed
  return uqueue_dequeue(port->thread_queue);
}

void IPCPort_setKernelHandlers(IPC_Port *port, IPD *handler_ipd, 
			       KernelCallHandler call_handler, 
			       KernelBindHandler bind_handler) {
  port->kernel_handler_ipd = handler_ipd;
  port->kernel_call_handler = call_handler;
  port->kernel_bind_handler = bind_handler;
}

void IPCPort_set_kernel_async_handler(IPC_Port *port, KernelAsyncHandler kernel_async_handler, void *ctx) {
  port->kernel_async_handler = kernel_async_handler;
  port->kernel_async_handler_ctx = ctx;
}

void IPCPort_makePermanent(IPC_Port *port)
{
	// XXX: remove after removing call generation from IDL
}

int kernel_bind_accept_all(void *_t, IPC_Port **port) {
  *port = NULL;
  return 0;
}

int kernel_bind_accept_none(void *_t, IPC_Port **port) {
  *port = NULL;
  return -1;
}

/******** IPC Connections ********/

IPC_Connection *
IPCConnection_new(IPD *source, IPC_Port *dest_port, int is_kernel) 
{
  IPC_Connection *rv = gcalloc(1, sizeof(IPC_Connection));
  
  rv->dest_port = dest_port;
  rv->source = source;
  if (is_kernel)
    rv->kernel = 1;
  
  rv->server_mutex = SEMA_MUTEX_INIT;
  rv->client_mutex = SEMA_MUTEX_INIT;

  IPCPort_get(rv->dest_port);
  IPCConnection_get(rv);
  return rv;
}

void 
IPCConnection_destroy(IPC_Connection *connection) 
{
  IPCPort_put(connection->dest_port);

#ifndef NDEBUG
  if (connection->active) {
    printkx(PK_IPC, PK_WARN, "destroying an open connection\n");
    nexusthread_dump_regs_stack(nexusthread_self());
    nexuspanic();
  }
#endif

  gfree(connection);
}

void 
IPCConnection_get(IPC_Connection *connection) 
{
  atomic_increment(&connection->refcnt, 1);
}

void 
IPCConnection_put(IPC_Connection *connection) 
{
  int zero;
 
  zero = atomic_subtract(&connection->refcnt, 1);
  assert(connection->refcnt >= 0);

  if (zero)
    IPCConnection_destroy(connection);
}

int 
IPCConnection_open(IPC_Connection *connection) 
{
  if (connection->dest_port->state != IPCPORT_ACTIVE) 
    return -SC_PORTDESTROYED;

  assert(!connection->active);
  connection->active = 1;

  //KernelFS_IPCPort_addConnection(connection->dest_port, connection);
  return 0;
}

int 
IPCConnection_close(IPC_Connection *connection) 
{
  //KernelFS_IPCPort_delConnection(connection->dest_port, connection);
  assert(connection->active);
  connection->active = 0;
  return 0;
}

/******** IPC initialization ********/

void 
ipc_init(void) 
{
  // table is large and largely sparse.
  // XXX replace with hashtable 
  HandleTable_init(&porttable, LAST_IPCPORT - FIRST_IPCPORT + 1);
}

/** Generate ports for all system calls. 

    Initialization code in each .sc 'class' will set the port's 
    call handler to a local function */
void 
ipc_syscall_init(void) 
{
  int i;

  // Reserve entries for system call handlers
  for (i = FIRST_SYSCALL_IPCPORT; i <= LAST_SYSCALL_IPCPORT; i++) {
    // XXX remove and integrate with syscall_init
    int num = i;
    num = ipc_create_port(kernelIPD, NULL, NULL, &num);
    assert(num == i);
  }
}

