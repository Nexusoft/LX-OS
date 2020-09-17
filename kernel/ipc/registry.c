/** NexusOS: Accounting of IPC ports, connections and asynchronous messages */

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
#include <nexus/guard.h>
#include <nexus/thread.h>
#include <nexus/ipd.h>
#include <nexus/Debug.interface.h>

/******** IPC Ports ********/

/** The lookup table storing Port_Num to IPC_Port mappings. */
struct HashTable *porttable;
static int ports_active;	// counter, for debugging create/destroy

/** Find an available port
    must be called WITH handletable lock held 
 
    @return portnum - FIRST_PORT */
static int
ipc_get_dynamic_port(void)
{
    static int next_dynamic = FIRST_DYNAMIC_IPCPORT;

    while (hash_findItem(porttable, &next_dynamic)) {
        next_dynamic++;
        
	// detect wrap
        assert(next_dynamic <= LAST_IPCPORT);
    }
    
    return next_dynamic++;
}

/** Create a new port.
  
    @param new_num will hold the allocated unique number on return.
           if it is not zero on calling, the passed value is 
	   interpreted as a request.
 
    On return the reference count will already be 3 (in the common case).
    The close function ipc_destroy_port similarly decrements with 3.

    @return the new port number or -1 on error */
int 
ipc_create_port(IPD *ipd, Map *map, Port_Num new_num) 
{
	char cred[80];
	IPC_Port *port;
	int num, lvl;

	// allocate a port
	port = gcalloc(1, sizeof(IPC_Port));
	if (!port) {
		printkx(PK_IPC, PK_WARN, "[ipc] allocate port failed\n");
		return -1;
	}

	// acquire a port number
	lvl = disable_intr();
	if (new_num) {
        
		// sanity check
		if (IPCPort_checkrange(new_num)) { 
			printkx(PK_IPC, PK_WARN, "[ipc] illegal port %d requested\n", new_num);
			restore_intr(lvl);
			return -1;
		}

		num = new_num;
		if (hash_findItem(porttable, &num)) {
			printkx(PK_IPC, PK_WARN, "[ipc] port %d in use\n", new_num);
            		restore_intr(lvl);
			return -1;
        	}
	}
	else
        num = ipc_get_dynamic_port();
	hash_insert(porttable, &num, port);

	// initialize nonzero variables
	port->port_num = num;
	port->ipd = ipd;
	port->refcnt = 1; 
	port->mutex = SEMA_MUTEX_INIT;
	port->empty_sema = SEMA_INIT_KILLABLE;
	port->thread_sema = SEMA_INIT_KILLABLE;
	port->full_sema = SEMA_INIT_KILLABLE;

  	queue_initialize(&port->recv_queue);
	queue_initialize(&port->thread_queue);	

	// connect to kernel
	assert(!IPCPort_checkrange(num));

	ports_active++;
        restore_intr(lvl);
	return num;
}

/** Remove a port. 
    Called from IPCPort_put when the reference count drops to zero.

    @return 0. This function does not check whether the port existed */
void IPCPort_do_destroy(IPC_Port *port) 
{
	BasicThread *t, *next_thread;
	int lvl;
  
	// system call ports should never die
	assert(!IS_SYSCALL_IPCPORT(port->port_num));
	assert(!port->refcnt);

	lvl = disable_intr();
	while ((t = queue_dequeue(&port->thread_queue))) {}
	ports_active--;
	restore_intr(lvl);

	gfree(port);
}

/** Mark a port as closed and flush all waiting messages.
    Contrary to what its name implies, this function does NOT destroy the 
    port. That occurs when the reference count drops to zero. 
 
    @return 0 on success or -1 otherwise */
int ipc_destroy_port(IPD *ipd, Port_Num port_num)
{
	IPC_Port *port, *port2;
 	int lvl;

	if (IPCPort_checkrange(port_num))
		return -1;

	// release port number
	lvl = disable_intr();
	port = hash_delete(porttable, &port_num);
	assert(port && port->port_num == port_num);
	assert(!hash_findItem(porttable, &port_num));		// DEBUG: paranoid XXX REMOVE
	assert(!hash_findEntry(porttable, &port_num, NULL));	// DEBUG: paranoid XXX REMOVE
	assert(!IPCPort_find_noint(port_num));			// DEBUG: paranoid XXX REMOVE
	assert(ipcport_find_safe_noint(port_num, &port2));	// DEBUG: paranoid XXX REMOVE
	restore_intr(lvl);

	if (!port) {
		printk_current("[ipc] warning: no port %d to destroy (p=%d)\n", 
				port, curt && curt->ipd ? curt->ipd->id : 0);
		return -1;
	}
	
	IPCPort_put(port); 
	return 0;
}

/** Lookup a port by its number and increase reference count.
    Caller must call IPCPort_put to reverse refcnt. */
IPC_Port *IPCPort_find_noint(Port_Num port_num) 
{
	IPC_Port * port;

	if (unlikely(__IPCPort_checkrange(port_num)))
		return NULL;

	port = hash_findItem(porttable, &port_num);
	if (port)
		IPCPort_get(port);

	return port;
}

IPC_Port *IPCPort_find(Port_Num port_num)
{
	IPC_Port *port;
	int lvl;
	
	lvl = disable_intr();
	port = IPCPort_find_noint(port_num);
	restore_intr(lvl);

	return port;
}

#ifndef NDEBUG
/** Standard format unit test for IPC ports 
    @return 0 on success, -1 on error */
int
IPCPort_unittest(void)
{
	IPC_Port *port, *port2;
	Port_Num num, num2;
       	int portcount;

	//// 1: basic test
	// create
	portcount = ports_active;
	num = ipc_create_port(kernelIPD, NULL, 0);
	if (num < 0) {
		printkx(PK_TEST, PK_WARN, "[ipcport] could not create port\n");
		return -1;
	}
	port = IPCPort_find(num);
	assert(port->ipd);
	assert(port->refcnt == 2);
	IPCPort_put(port);
	assert(port->refcnt == 1);

	// find is skipped, because it triggers syscall_lookup for port 0

	// remove
	if (ipc_destroy_port(NULL, num)) {
		printkx(PK_TEST, PK_WARN, "[ipcport] could not destroy port\n");
		return -1;
	}
	assert(portcount == ports_active);

	//// 2: test number preference and reference counting
	num = FIRST_DYNAMIC_IPCPORT;
	num2 = ipc_create_port(kernelIPD, NULL, num);
	if (num2 != num) {
		printkx(PK_TEST, PK_WARN, "[ipcport] could not create chosen port\n");
		return -1;
	}
	port = IPCPort_find(num);
	assert(port->refcnt == 2);
	
	// find
	port2 = IPCPort_find(num);
	if (port2 != port) {
		printkx(PK_TEST, PK_WARN, "[ipcport] could not find port\n");
		return -1;
	}
	assert(port->refcnt == 3);
	IPCPort_put(port);
	IPCPort_put(port);
	assert(port->refcnt == 1);

	// remove
	if (ipc_destroy_port(NULL, num)) {
		printkx(PK_TEST, PK_WARN, "[ipcport] could not destroy port\n");
		return -1;
	}
	assert(portcount == ports_active);

	// find. should fail
	port2 = IPCPort_find(num);
	if (port2) {
		printkx(PK_TEST, PK_WARN, "[ipcport] incorrectly found port\n");
		return -1;
	}
	
	if (!ipcport_find_safe(num, &port2)) {
		printkx(PK_TEST, PK_WARN, "[ipcport] error at ipcport_find_safe");
		return -1;
	}

	//// 3: test port ranges
	if (IPCPort_checkrange(FIRST_IPCPORT))
		return -1;
	if (IPCPort_checkrange(LAST_IPCPORT))
	       return -1;
	if (!IPCPort_checkrange(LAST_IPCPORT + 1))
		return -1;
	if (IPCPort_checkrange(0))
		return -1;
	if (IPCPort_checkrange(-1))
		return -1;

	return 0;
}
#endif

void IPCPort_makePermanent(IPC_Port *port)
{
	// XXX: remove after removing call generation from IDL
}

void IPCPort_setKernelHandlers(IPC_Port *port, IPD *handler_ipd, 
			       KernelCallHandler call_handler, 
			       KernelBindHandler bind_handler) {
	// XXX: remove after removing call generation from IDL and
	port->kernel_call_handler = call_handler;
}

int kernel_bind_accept_all(void *_t, IPC_Port **port) {
  *port = NULL;
  return 0;
}

int kernel_bind_accept_none(void *_t, IPC_Port **port) {
  *port = NULL;
  return -1;
}

/******** IPC initialization ********/

void 
ipc_init(void) 
{
  // table is large and largely sparse.
  porttable = hash_new(2048, sizeof(int));
}

