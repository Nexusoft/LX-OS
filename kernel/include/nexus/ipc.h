#ifndef _IPC_H_
#define _IPC_H_

typedef int Port_Num;

/// deprecated. used to be a direct index into a table of ports
//  now identical to Port_Num
typedef int Port_Handle;

/// deprecated. now always 1
typedef int Call_Handle;

typedef int Connection_Handle;

#include <nexus/machineprimitives.h>
#include <nexus/ipd.h>
#include <nexus/syscall-defs.h> // for FIRST_IPCPORT and friends

struct IPC_Port;

int ipc_server(int ipc_port);

int ipc_create_port(IPD *, Map *, Port_Num);
int ipc_destroy_port(IPD *ipd, Port_Num channel_num);

int ipc_poll(int port_num, int directions);
int ipc_wake(int portnum, int direction);
unsigned long ipc_available(int port_num);
int ipc_wait(long *portnums, char *results, int len);

void ipc_init(void);

int IPCPort_unittest(void);

int rpc_transfer(BasicThread *caller, int dnum, 
	         void *local, int off, int len, int from);
int rpc_param(void *data, int off, int len);
int rpc_caller(void);

#define __IPCPort_checkrange(num) (num < -1 || num > LAST_IPCPORT)	

/** verify that the parameter can be a valid pointer */
static inline int
IPCPort_checkrange(int portnum)
{
  // FIRST_IPCPORT == 0 and {0, -1} are also valid special values
  if (unlikely(__IPCPort_checkrange(portnum))) {
#ifndef NDEBUG
    printkx(PK_IPC, PK_DEBUG, "port %d out of range\n", portnum);				
#endif
    return 1;
  }

  return 0;
}

#endif

