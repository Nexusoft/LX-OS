/** NexusOS: userlevel IPC helpers */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <fcntl.h>
#include <pthread.h>
#include <errno.h>
#include <sys/errno.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <nexus/defs.h>
#include <nexus/hashtable.h>
#include <nexus/sema.h>
#include <nexus/syscalls.h>
#include <nexus/idl.h>
#include <nexus/handle.h>
#include <nexus/ipc.h>
#include <nexus/IPC.interface.h>

int __thread ___tls_ipcResultCode;
int ___shared_ipcResultCode;

#if NXCONFIG_FAST_IPC
int ipc_send(long port, void *data, long dlen)
{
	return nexuscall3(SYS_RAW_Send_CMD, port, (long) data, dlen);
}
int ipc_recv(long port, void *buf, long blen)
{
	return nexuscall3(SYS_RAW_Recv_CMD, port, (long) buf, blen);
}
int ipc_sendpage(int port, void *data)
{
	return nexuscall2(SYS_RAW_SendPage_CMD, port, (long) data);
}
int ipc_recvpage(int port, void **data)
{
	return nexuscall3(SYS_RAW_RecvPage_CMD, port, (long) data, NULL);
}
#else
int ipc_send(long port, void *data, long dlen)
{
	return IPC_Send(port, data, dlen);
}
int ipc_recv(long port, void *buf, long blen)
{
	return IPC_Recv(port, buf, blen);
}
int ipc_sendpage(int port, void *data)
{
	return IPC_SendPage(port, data);
}
int ipc_recvpage(int port, void **data)
{
	return IPC_RecvPage(port, (unsigned long) data, NULL);
}
#endif

/** Wrapper around IPC_TransferFrom 
    @return NULL on error or a pointer to data that the caller must free */
char * 
ipctransfer_from(struct VarLen *remote, int len, int maxlen)
{
	char *local;

	// check boundaries
	if (len > maxlen) {
		nxcompat_fprintf(stderr, "from: len\n");
		return NULL;
	}

	// copy data
	local = malloc(len);
	if (IPC_TransferFrom(0, remote->desc_num, local, 0, len)) {
		nxcompat_fprintf(stderr, "from: cp\n");
		return NULL;
	}

	return local;
}

int
ipctransfer_to(struct VarLen *remote, char *data, int len)
{
	  // transfer ciphertext to caller
	  if (IPC_TransferTo(0, remote->desc_num, data, 0, len)) {
		nxcompat_fprintf(stderr, "to: cp\n");
		return -1;
	  }
	  
	  return 0;
}

