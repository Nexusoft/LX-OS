#ifndef _IPC_PRIVATE_H
#define _IPC_PRIVATE_H

#include <nexus/test.h>
#include <nexus/bitmap.h>
#include <nexus/dlist.h>
#include <nexus/hashtable.h>
#include <nexus/thread-struct.h>
#include <nexus/IPC.interface.h>

// the maximum number of listeners on a semaphore
// this number limits concurrency in servers:
// when the number of elements on the listener queue exceeds this number,
// ipc_poll no longer marks the port as writable
#define IPCPORT_QUEUELEN 256

//////// Server Callbacks ////////////////

typedef int (*KernelBindHandler)(void *caller, struct IPC_Port **notification_port);
typedef void (*KernelCallHandler)(void *caller);
typedef void (*KernelAsyncHandler)(IPD_ID source_ipd, Call_Handle call_handle, void *_ctx);

extern struct HashTable *porttable;

//////// IPCPort ////////////////
//
// a point with a unique ID.
//
// ports have server threads that listen for bind and call requests

// Returns 0 if accept, -1 if reject

struct IPC_Port;
struct ipc_elem;

struct IPC_Port {
  
  int refcnt;
  Port_Num port_num;
  Sema mutex;			///< single lock on all IPCPort operations
  
  // asynchronous notification
  Sema *notify_r;
  Sema *notify_w;
  int notify_set;

  // server process 
  IPD *ipd;

  // synchronize ipc_send/ipc_recv
  Queue recv_queue;
  struct ipc_elem *recv_elem;	///< support partial reads: cache remainder
  Sema empty_sema;
  Sema full_sema;

  // threadpool for listening threads of user service 
  Queue thread_queue;
  Sema thread_sema;

  // callback for direct execution of kernel service
  KernelCallHandler kernel_call_handler;

};

IPC_Port *IPCPort_find_noint(Port_Num port_num);
IPC_Port *IPCPort_find(Port_Num port_num);

/** Get port with number port_num
    @return 0 on success, or -1 on failure */  
static inline int
__ipcport_find_safe(int num, IPC_Port **port, const char *fn, int noint)
{
	*port = noint ? IPCPort_find_noint(num) : IPCPort_find(num);
	if (unlikely(!(*port))) {
		if (!unittest_active) printkx(PK_IPC, PK_WARN, "[ipc] no port %d in %s\n", num, fn);
		return -1;
	}
#ifndef NDEBUG
	if (unlikely((*port)->port_num != num)) {
		printk_red("[ipc] BUG: port %d != %d (%p)\n", num, (*port)->port_num, *port);
		nexuspanic();
	}
	assert((*port)->port_num < (100 * 1000));
#endif

	return 0;
}
#define ipcport_find_safe_noint(num, port)	__ipcport_find_safe(num, port, __FUNCTION__, 1)
#define ipcport_find_safe(num, port)     	__ipcport_find_safe(num, port, __FUNCTION__, 0)

static inline IPC_Port *
IPCPort_get(IPC_Port *port) 
{
  if (unlikely(__IPCPort_checkrange(port->port_num)))
	  return NULL;

  atomic_addto(&port->refcnt, 1);
  return port;
}

static inline void 
IPCPort_put(IPC_Port *port) 
{
  void IPCPort_do_destroy(IPC_Port *port); // not for external use
  int zero, ret;

  if (unlikely(__IPCPort_checkrange(port->port_num)))
	  return;

  // Protect potential lookup against concurrent deallocation
  zero = atomic_subtract(&port->refcnt, 1);
  if (unlikely(port->refcnt < 0)) {
#ifdef NDEBUG
	  printk_red("BUG: double free of ipc port %d\n", port->port_num);
#endif
	  return;
  }

  if (unlikely(zero))
    IPCPort_do_destroy(port);
}

/** XXX all deprecated DO NOT USE. used by the damn IDL generator */
int IPC_Port_Send_checkAccess(IPD *ipd, IPC_Port *port);
void IPCPort_setKernelHandlers(IPC_Port *port, IPD *handler_ipd, KernelCallHandler call_handler, KernelBindHandler bind_handler);
void IPCPort_makePermanent(IPC_Port *port);
int kernel_bind_accept_all(void *_t, struct IPC_Port **notification_port);
int kernel_bind_accept_none(void *_t, struct IPC_Port **notification_port);


////////  rpc: clientside 

int rpc_invoke(int port);


////////  rpc: serverside  

int  rpc_recvcall_user(int portnum, char *buf, int *blen); 
int  rpc_recvcall_kernel(char *buf, int *blen);
void rpc_callreturn(void);


////////  low-level ipc

int ipc_send(Map *send_map, int port_num, void *data, int dlen);
int ipc_recv(Map *recv_map, int port_num, void *buf, int blen, int *caller_id);
int ipc_sendpage_impl(Map *map, int port_num, void *data);
int ipc_recvpage_impl(Map *map, int port_num, void **data, int *caller);

#endif // _IPC_PRIVATE_H

