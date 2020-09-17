/** NexusOS: new guard using standard RPC
             (previous used a nonstandard protocol) */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <nexus/defs.h>
#include <nexus/ipc.h>
#include <nexus/log.h>
#include <nexus/test.h>
#include <nexus/guard.h>
#include <nexus/guard-impl.h>
#include <nexus/syscall-defs.h>

#include <nexus/IPC.interface.h>
#include <nexus/Debug.interface.h>
#include <nexus/GuardStd.interface.h>

/** XXX populate guard with default policies */
static void
init_policies(void)
{
}

/** If this is the system guard, notify the kernel:
    it will be blocked until the sytem guard is up */
static void
init_notifykernel(void)
{
	int port;

	if (getpid() == 1) {
		
		port = GuardStd_port_handle;
		if (IPC_Send(guard_init_port, &port, sizeof(port))) {
			printf("[guard] unrecoverable error: connect failed\n");
			abort();
		}
	}
}

int
main(int argc, char **argv)
{
	// log
	if (argc == 2 && !strcmp(argv[1], "--debug")) {
		nxlog_open(NULL);
		nxlog_level = 3;
		printf("[guard] DEBUG enabled\n");
	}
	else {
		nxlog_open("guard");
	}

	// init
	if (nxguardsvc_init())
		return 1;

	init_policies();
	if (ipc_server_run("GuardStd") < 0)
		return 1;

	// call
	init_notifykernel();
	printf("[guard] OK. Ready\n");
	while (1)
		sleep(3600);

	// not reached
	return 0;
}

