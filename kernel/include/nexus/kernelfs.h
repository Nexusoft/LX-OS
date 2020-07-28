/** NexusOS: a procfs for Nexus. See .c file for more details */

#ifndef KERNELFS_H_
#define KERNELFS_H_

#include "ipc_private.h"

void KernelFS_mk(const char *name, const char *data, int dlen);

void KernelFS_addIPDNode(IPD *ipd);
void KernelFS_add_IPCPort(IPC_Port *channel);
void KernelFS_del_IPCPort(IPC_Port *channel);
void KernelFS_IPCPort_addConnection(IPC_Port *port, IPC_Connection *connection);

void KernelFS_setenv_bin(char *name, char *value, int len);
void KernelFS_setenv(char *name, char *value); 

#endif
