/** NexusOS: (optional) in-kernel reference monitor(s) */

#include <nexus/defs.h>
#include <nexus/thread.h>
#include <nexus/guard.h>
#include <nexus/user_compat.h>
#include <nexus/syscall-defs.h>
#include <nexus/Guard.kernel-interface.h>

#include "../../common/refmon/vlance.c"
#include "../../common/refmon/lighty.c"
#include "../../common/refmon/strace.c"

struct interpose_args {
	int opcode;
	void *rbuf;
	struct nxguard_tuple tuple;
};

#define REFMON(name, fn_in, fn_out) \
									\
/** Callback called for Guard_Interpose[In|Out] calls to our port 	\
    Manual (faster) implementation of Guard.server.c, so that we 	\
    can support multiple reference monitors in the kernel, 		\
    each with its own interface */					\
static void								\
nxrefmon_##name(void *t) 						\
{									\
	struct interpose_args args;					\
	int ret[2], len;						\
									\
	/* set default Guard_InterposeIn_Result */			\
	ret[0] = INTERFACE_SUCCESS;					\
	ret[1] = AC_BLOCK_CACHE;					\
									\
	/* receive parameters */					\
	len = sizeof(args);						\
	if (rpc_recvcall_kernel((char *) &args, &len) < 0) {		\
		printk_red("NXDEBUG: recvcall buffer too small\n");	\
		nexuspanic();						\
	}								\
									\
	/* call */							\
	if (args.opcode == SYS_Guard_InterposeIn_CMD)			\
		ret[1] = fn_in(args.tuple);				\
	else								\
		ret[1] = fn_out(args.tuple);				\
									\
	/* return results */						\
	IPC_TransferTo(0, RESULT_DESCNUM, ret, 0, sizeof(ret));		\
	IPC_CallReturn(0);						\
}

REFMON(vlance, nxrefmon_vlance_in, nxrefmon_vlance_out);
REFMON(lighty, nxrefmon_lighty_in, nxrefmon_lighty_out);
REFMON(strace, nxrefmon_strace_in, nxrefmon_strace_out);

/** Start the reference monitor with the given ID
    @return the ipcport on which it listens, or -1 on failure */
int 
nxrefmon_start(int refmon_id)
{
	KernelCallHandler fn;
	IPC_Port *port;
	long portnum;

	// acquire port
	portnum = IPC_CreatePort(0);
	if (ipcport_find_safe(portnum, &port))
		return -1;
	
	// demultiplex request
	switch (refmon_id) {
		case 1: 	fn = nxrefmon_vlance; break;
		case 2: 	fn = nxrefmon_lighty; break;
		case 3: 	fn = nxrefmon_strace; break;
		default: 	return -1;
	}

	// register reference monitor at ipc port
	IPCPort_setKernelHandlers(port, kernelIPD, fn, 
				  kernel_bind_accept_all);
	
	IPCPort_put(port);
	return portnum;
}

