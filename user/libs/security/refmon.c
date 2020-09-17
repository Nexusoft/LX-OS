/** NexusOS: Shared reference monitor boilerplate */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <nexus/defs.h>
#include <nexus/test.h>
#include <nexus/sema.h>
#include <nexus/nexuscalls.h>

#include <nexus/IPC.interface.h>
#include <nexus/Guard.interface.h>

#define REFMON_THREADS 2

static Sema sema_guard = SEMA_INIT;
static Sema sema_mutex = SEMA_MUTEX_INIT;
static int in_use;

int (*callback_interposein)(struct nxguard_tuple);
int (*callback_interposeout)(struct nxguard_tuple);

int nxrefmon_interposein(struct nxguard_tuple tuple)
{
	return callback_interposein(tuple);
}

int nxrefmon_interposeout(struct nxguard_tuple tuple)
{
	return callback_interposeout(tuple);
}

static int
nxrefmon_exec(char *args[], int ipcport)
{
	int pid;
	
	// start child process
	pid = nxcall_exec_ex(args[0], args, NULL, ipcport);
	if (pid <= 0)
		ReturnError(1, "Exec failed");

	// wait for child
	waitpid(pid, NULL, 0);
	return 0;
}

/** Guard.svc callback thread */
static void *
guardthread(void *unused)
{
	P(&sema_guard);	// XXX race condition between P and actual start
	while(1)
		Guard_processNextCommand();
	return NULL;
}

/** Start a userspace reference monitor */
int
nxrefmon(char *args[], int (*fn_in)(struct nxguard_tuple),
                       int (*fn_out)(struct nxguard_tuple))
{
	pthread_t thread;
	int i;

	// can only support 1 refmon per process due to static vars, above
	P(&sema_mutex);
	if (in_use) {
		V_nexus(&sema_mutex);
		ReturnError(1, "[refmon] already in use\n");
	}
	in_use = 1;
	V_nexus(&sema_mutex);

	// set callbacks
	callback_interposein = fn_in;
	callback_interposeout = fn_out;
	
	// start interposition thread
	Guard_serverInit();
	for (i = 0; i < REFMON_THREADS; i++) {
		pthread_create(&thread, NULL, guardthread, NULL);
		V_nexus(&sema_guard);
	}

	return nxrefmon_exec(args, Guard_port_handle);
}

/** Start a kernel reference monitor */
int
nxrefmon_kernel(char *args[], int krefmon_id)
{
	int port, pid;

	// start kernel reference monitor
	port = IPC_Refmon_Start(krefmon_id);
	if (port < 0)
		ReturnError(1, "Error starting kernel DDRM\n");

	return nxrefmon_exec(args, port);
}

