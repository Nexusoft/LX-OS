#ifndef _IPC_PRIVATE_H
#define _IPC_PRIVATE_H

#include <nexus/bitmap.h>
#include <nexus/dlist.h>
#include <nexus/thread-struct.h>
#include <nexus/IPC.interface.h>

//////// Server Callbacks ////////////////

typedef int (*KernelBindHandler)(void *caller, struct IPC_Port **notification_port);
typedef void (*KernelCallHandler)(void *caller);
typedef void (*KernelAsyncHandler)(IPD_ID source_ipd, Call_Handle call_handle, void *_ctx);

//////// IPCPort ////////////////
//
// a point with a unique ID.
//
// ports have server threads that listen for bind and call requests
// clients can bind to a port and then send calls through an IPCConnection

// Returns 0 if accept, -1 if reject

struct IPC_Port;

// #define INVALID_PORT_NUM (-1)
struct _IPC_EdgeSet;
struct IPC_Msg;

typedef enum IPCPort_State {
  IPCPORT_ACTIVE,
  IPCPORT_DESTROYED,
} IPCPort_State;

// IPC_Port accepts messages and connections only if it is still in the active state
struct IPC_Port {
  
  int refcnt;
  IPCPort_State state;
  Port_Num port_num;
  Sema mutex;			///< single lock on all IPCPort operations

  // server process 
  IPD *ipd;

  // asynchronous I/O
  UQueue *recv_queue;
  Sema recv_sema;
  
  UQueue *recv_queue2;
  Sema recv_sema2;

  // user servers queue their worker threads here. on RecvCall they are awoken
  UQueue *thread_queue;
  Sema thread_sema;

  // XXX can we remove this superfluous ipd?
  // is used to fake non kernelIPD for in-kernel servers
  IPD *kernel_handler_ipd;
  KernelCallHandler kernel_call_handler;
  KernelBindHandler kernel_bind_handler;
  KernelAsyncHandler kernel_async_handler;
  void *kernel_async_handler_ctx;

  // XXX deprecated: remove
  // Fast lookup for edge set to use when sending messages from kernel
  // to user.
  //
  // Note that, to prevent this circular reference, the reference
  // counting for the kernel_connection is done specially:
  //
  // There is no refcnt from the kernel_connection to the IPC_Connection refcnt
  // All IPCConnection_gets() of the kernel_connection will increment
  // the reference count of the IPC_Port, rather than the connection
  // When the IPC_Port goes to 0, it deallocates the connection
  struct IPC_Connection *kernel_connection;
};

IPC_Port *IPCPort_find(Port_Num port_num);

/** verify that the parameter can be a valid pointer */
static inline int
IPCPort_checkrange(Port_Num num)
{
  if (unlikely(num < FIRST_IPCPORT || num > LAST_IPCPORT) &&
	       num != 0 && num != -1) {
#ifndef NDEBUG
    printkx(PK_IPC, PK_DEBUG, "port %d out of range [%d, %d]\n", num, 
	    FIRST_IPCPORT, LAST_IPCPORT);
#endif
    return 1;
  }
  return 0;
}

static inline IPC_Port *
IPCPort_get(IPC_Port *port) 
{
  if (IPCPort_checkrange(port->port_num))
	  return NULL;

  atomic_addto(&port->refcnt, 1);
  return port;
}

static inline void 
IPCPort_put(IPC_Port *port) 
{
  void IPCPort_do_destroy(IPC_Port *port); // not for external use
  int zero;

  if (IPCPort_checkrange(port->port_num))
	  return;

  // Protect potential lookup against concurrent deallocation
  zero = atomic_subtract(&port->refcnt, 1);
  assert(atomic_get(&port->refcnt) >= 0);

  if (unlikely(zero))
    IPCPort_do_destroy(port);
}

/** a server thread adds itself to a queue when it waits for incoming calls */
void IPCPort_addServerThread(IPC_Port *port, BasicThread *t);
int IPCPort_rmServerThread(IPC_Port *port, BasicThread *t);
BasicThread *IPCPort_dequeueServerThread(IPC_Port *port);

/** XXX all deprecated DO NOT USE */
int IPC_Port_Send_checkAccess(IPD *ipd, IPC_Port *port);
void IPCPort_setKernelHandlers(IPC_Port *port, IPD *handler_ipd, KernelCallHandler call_handler, KernelBindHandler bind_handler);
void IPCPort_set_kernel_async_handler(IPC_Port *port, KernelAsyncHandler kernel_async_handler, void *ctx);
static inline int IPCPort_isKernel(IPC_Port *port) 
{
  return port->kernel_call_handler != NULL;
}

//////// IPCConnection ////////////////
//
// A bond between two processes (IPDs) and a port
// Clients use connections to Invoke/TransferTo/TransferFrom/... a port

// There is one connection per <source_ipd, dest_ipd, port_num>
struct IPC_Connection {
  int refcnt;

  int active:1;				///< connection is available
  int kernel:1;				///< mark special 'kernel connection'

  IPC_Port *dest_port;			///< server port
  IPD *source; 				///< client process

  // Fields used by client
  struct {
    struct _IPC_EdgeSet *edge_set;
  } client;

  // Frequently-changing fields
  Sema server_mutex;
  Sema client_mutex;
};

typedef enum IPC_Role {
  IPCROLE_SERVER,
  IPCROLE_CLIENT,
  IPCROLE_INVALID,
} IPC_Role;

IPC_Connection *IPCConnection_new(IPD *source, IPC_Port *dest_port, int is_kernel);
void IPCConnection_destroy(IPC_Connection *connection);

int IPCConnection_open(IPC_Connection *connection);
int IPCConnection_close(IPC_Connection *connection);

void IPCConnection_get(IPC_Connection *connection);
void IPCConnection_put(IPC_Connection *connection);

//////// IPC Connect/Bind and Interposition ////////////////

Connection_Handle ipc_connect(IPD *ipd, Port_Num port_num);

int kernel_bind_accept_all(void *_t, struct IPC_Port **notification_port);
int kernel_bind_accept_none(void *_t, struct IPC_Port **notification_port);

extern IPC_CommonClientContext_OpTable IPC_CommonClientContext_Thread_ops;
int IPC_CommonClientContext_init_descriptors(IPC_CommonClientContext *common_ctx,
		Map *desc_map, Map *transfer_map,
		struct TransferDesc *descs, int num_transfer_descs,
		Map *wrappee_map,
		struct TransferDesc *wrappee_descs, int num_wrappee_descs,
		/* Kernel descriptors are copied */
		struct KernelTransferDesc *kernel_descs, int num_kernel_descs);

//////// IPC Implementation handlers ////////////////
//
// XXX needs serious cleanup: move code from IPC.sc and ipc/iface to ipc/impl

int CallHelper(IPD *ipd, IPC_Connection *connection,
	       struct IPC_ClientContext *cctx,
	       Map *message_map, char *message, int message_len);

struct IPC_ClientContext *IPC_ClientContext_new(BasicThread *t, 
						IPC_Connection *connection);

Call_Handle
RecvCallHelper(Port_Handle port_handle,
	       char *msg_dest, int *message_len_p,
	       unsigned int *ipd_id_p);

int IPC_ReturnHelper(Call_Handle call_handle, IPD *ipd, Map *map);

// (old) asynchronous ipc
Call_Handle ipc_async_recv(Port_Handle port_handle, IPD *ipd, Map *map,
		           struct IPC_Msg **msg_p,
		           char *message_dest, int *message_len,
		           struct TransferDesc *user_transfer_descs,
		           int *num_transfer_descs);

int ipc_async_send(struct IPC_Connection *connection, IPD *ipd, Map *map, 
	           char *message, int message_len,
	           Map *user_desc_map, struct TransferDesc *user_descs, int num_transfer_descs);

int ipc_async_done(Call_Handle call_handle, enum IPC_AsyncDoneType done_type);

// new packet-based ipc
int ipc_send(Map *caller_map, int port_num, char *data, int dlen);
int ipc_recv(int port_num, char *buf, int blen, int *caller_id);

//////// IPCMsg ////////////////

typedef enum {
  IPCMsg_Original,
  IPCMsg_Upcall,
} IPCMsg_Type;

// Max message length for a "fast" IPC_Msg
#define IPCMSG_FAST_LEN (2048)

#define FASTALLOCTYPE_NONE	(0)
#define FASTALLOCTYPE_THREAD	(1)
#define FASTALLOCTYPE_QUEUE	(2)

struct IPC_Msg {
  union {
    dlist_head link;
    struct {
      struct IPC_Msg *prev;
      struct IPC_Msg *next;
      void *list;
    };
  };
  // this is the first field that is accessed in recv fast path. Pack
  // them together as tightly as possible
  char *data;
  int data_len;
  int refcnt; // refcnt is accessed around same time as fast_alloc

  // Some of the first fields in common_ctx are used on receive path,
  // so keep in this location to preserve spatial locality with IPC_Msg
  IPC_CommonClientContext common_ctx;

  // end of fields that are accessed by recv fast path (actually, the
  // real end is somewhere at the front of common_ctx)
  unsigned char type;
  
  // Interposition fields
  // XXX: remove
  struct {
    struct IPC_Msg *orig;
    int next_tap_index;
  } interpose;
};

extern int dbg_ipc_find;

IPC_Msg *IPCMsg_new(IPCMsg_Type type, IPC_Connection *connection, int len);

static inline void 
IPCMsg_get(IPC_Msg *msg) 
{
  atomic_addto(&msg->refcnt, 1);
}
 
void IPCMsg_put(IPC_Msg *msg);

int IPCMsg_copy_data(IPC_Msg *msg, Map *map, char *target, int len);

int IPCConnection_queueMessage(IPC_Connection *connection, IPC_Msg *msg);
IPC_Msg *IPCConnection_queueNewMessage(IPC_Connection *connection,
				       IPCMsg_Type type, 
				       IPD *ipd, Map *map,
				       char *message, int message_len,

				       Map *desc_map,
				       struct TransferDesc *user_descs, 
				       int num_descs,

				       int *err);

#endif // _IPC_PRIVATE_H

