#include <errno.h>
#include <sys/errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include "nexus/syscalls.h"
#include <nexus/ipc.h>
#include <nexus/IPC.interface.h>
#include <assert.h>

#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <pthread.h>

#include <nexus/hashtable.h>
#include <nexus/sema.h>
#include <nexus/idl.h>
#include <nexus/handle.h>

int __thread ___tls_ipcResultCode;
int ___shared_ipcResultCode;


Connection_Handle IPC_DoBind(Port_Num target) {
  Connection_Handle conn_handle; 
  
  conn_handle = IPC_BindRequest(target);
  if (conn_handle < 0)
  	fprintf(stderr, "[ipc] failed to connect to port %d\n", target);
  return conn_handle;
}

Connection_Handle IPC_DoBindAccept(Port_Handle target) {
  return 0;	// trivially return since we accept all requests
}

// XXX: remove
Connection_Handle IPC_DoBind_notified(Port_Num target, Port_Handle tap_notification_port) {
  fprintf(stderr, "deprecated function %s called\n", __FUNCTION__);
  return INVALID_HANDLE;
}

// XXX: remove
Connection_Handle IPC_DoBindAccept_notified(Port_Handle target, Port_Handle tap_notification_port) {
  fprintf(stderr, "deprecated function %s called\n", __FUNCTION__);
  return INVALID_HANDLE;
}


static HandleTable *ipc_msg_table; // shadow of kernel table. handle => IPC_Msg
static Sema ipc_msg_table_mutex = SEMA_MUTEX_INIT;

__thread Port_Handle ipc_handler_port_handle;
__thread Port_Handle ipc_handler_port_num;

static void IPCMsg_destroy(IPC_Msg *m) {
  free(m->data);
  free(m);
}

static 
void MSGTable_add_new(Port_Num port_num, Port_Handle port_handle, 
		      Call_Handle call_handle, const char *data, int data_len,
		      struct TransferDesc transfer_descs[], int num_transfer_descs) {
  IPC_Msg *m = malloc(sizeof(IPC_Msg));
  m->port_num = port_num;
  m->port_handle = port_handle;
  m->data = malloc(data_len);
  memcpy(m->data, data, data_len);
  m->data_len = data_len;

  memcpy(m->common_ctx.transfer_descs, transfer_descs, 
	 num_transfer_descs * sizeof(struct TransferDesc));
  m->common_ctx.num_transfer_descs = num_transfer_descs;

  P(&ipc_msg_table_mutex);
  IPC_Msg *o = HandleTable_find(ipc_msg_table, call_handle);
  if(o != NULL) {
    printf("async ipc_msg table: %p found at %d, freeing\n", o, call_handle);
    IPCMsg_destroy(o);
    HandleTable_delete(ipc_msg_table, call_handle);
  }
  Handle h;
  h = HandleTable_add_ext(ipc_msg_table, m, call_handle);
  assert(h == call_handle);
  V_nexus(&ipc_msg_table_mutex);
}

static void MSGTable_clean(Call_Handle call_handle) {
  P(&ipc_msg_table_mutex);
  IPC_Msg *o = HandleTable_find(ipc_msg_table, call_handle);
  if(o != NULL) {
    IPCMsg_destroy(o);
    HandleTable_delete(ipc_msg_table, call_handle);
  }
  V_nexus(&ipc_msg_table_mutex);
}

void __ipc_init(void) {
  ipc_msg_table = HandleTable_new(32);
}

int IPC_AsyncDone(Call_Handle call_handle0, enum IPC_AsyncDoneType done_type) {
  MSGTable_clean(call_handle0);
  return IPC_AsyncDone_sys(call_handle0, done_type);
}

// CallHandle_to_*() only works if using the function-pointer API!
Port_Num CallHandle_to_Port_Num(Call_Handle call_handle) {
  Port_Num rv = INVALID_HANDLE;
  P(&ipc_msg_table_mutex);
  IPC_Msg *o = HandleTable_find(ipc_msg_table, call_handle);
  if(o != NULL) {
    rv = o->port_num;
  }
  V_nexus(&ipc_msg_table_mutex);
  return rv;
}

// XXX: remove
IPC_Msg *CallHandle_to_IPC_Msg(Call_Handle call_handle) {
  // N.B. This does not acquire reference counts, so the caller must
  // be careful not to reference IPC_Msg after deallocating it through
  // IPC_AsyncDone()
  P(&ipc_msg_table_mutex);
  IPC_Msg *o = HandleTable_find(ipc_msg_table, call_handle);
  V_nexus(&ipc_msg_table_mutex);
  return o;
}


int IPCMsg_copy_data(IPC_Msg *msg, Map *map, char *target, int len) {
  if(len > msg->data_len) {
    printf("IPCMsg_copy_data: len too long (%d > %d)!\n", len, msg->data_len);
    return -1;
  }
  memcpy(target, msg->data, len);
  return 0;
}

