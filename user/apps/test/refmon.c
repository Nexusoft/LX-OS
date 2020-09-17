/** NexusOS: trivial reference monitor */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <nexus/defs.h>
#include <nexus/test.h>
#include <nexus/nexuscalls.h>
#include <nexus/syscall-defs.h>

#include <nexus/Time.interface.h>
#include <nexus/Guard.interface.h>
#include <nexus/Debug.interface.h>
#include <nexus/Thread.interface.h>

// don't show output by default, because run at boot
#define dprintf(...)

static int count_null3, count_getticks, count_pid;
static Sema sema_guard = SEMA_INIT;

int 
nxrefmon_interposein(struct nxguard_tuple tuple)
{
	// allow cached: will only show once
	if (tuple.operation == SYS_Debug_Null3_CMD) {
		dprintf("@in:  null3 (opcode=%d)\n", tuple.operation);
		count_null3++;
		return AC_ALLOW_CACHE;
	}

	// allow notcached: will show everytime
	if (tuple.operation == SYS_Time_GetTicks_CMD) {
		dprintf("@in:  getticks (opcode=%d)\n", tuple.operation);
		count_getticks++;
		return AC_ALLOW_NOCACHE;
	}

	// block notcached
	if (tuple.operation == SYS_Thread_GetProcessID_CMD) {
		dprintf("@in:  getpid (opcode=%d)\n", tuple.operation);
		count_pid++;
		return AC_BLOCK_NOCACHE;
	}

	dprintf("@in:  %d\n", tuple.operation);
	return AC_ALLOW_NOCACHE;
}

int 
nxrefmon_interposeout(struct nxguard_tuple tuple)
{
	switch (tuple.operation) {
		case SYS_Debug_Null3_CMD:		count_null3++; break;
		case SYS_Time_GetTicks_CMD:		count_getticks++; break;
		case SYS_Thread_GetProcessID_CMD:	count_pid++; break;
	};
	dprintf("@out: %d\n", tuple.operation);
	return 0;
}

static void *
guardthread(void *unused)
{
	P(&sema_guard);	// XXX race condition between P and actual start
	while(1)
		Guard_processNextCommand();

	return NULL;
}

static int
child(void)
{
	Debug_Null3(5);
	Debug_Null3(5);
	Debug_Null3(5);
	Time_GetTicks();
	Time_GetTicks();
	Time_GetTicks();
	if (Thread_GetProcessID() > 0 ||
	    Thread_GetProcessID() > 0 ||
	    Thread_GetProcessID() > 0) {
		fprintf(stderr, "Block failed\n");
		return 1;
	}

	return 0;
}

int
main(int argc, char **argv)
{
	char *args[3];
	pthread_t thread;
	int pid, ret;

	// XXX for some reason, Exec fails on autostart
	test_skip_auto();

	if (argc == 2 && !strcmp(argv[1], "-c"))
		return child();

	// start interposition thread
	Guard_serverInit();
	pthread_create(&thread, NULL, guardthread, NULL);
	V_nexus(&sema_guard);

	// start child process
	args[0] = argv[0];
	args[1] = "-c";
	args[2] = NULL;
	pid = nxcall_exec_ex(args[0], args, NULL, Guard_port_handle);
	if (pid <= 0)
		ReturnError(1, "Exec failed");

	// wait for child
	waitpid(pid, &ret, 0);

	if (ret)
		ReturnError(1, "Child failed");
	if (count_null3 != 2 || count_getticks != 6 || count_pid != 3)
		ReturnError(1, "Interposition count incorrect");

	if (argc != 2) 
		printf("[test] OK\n");

	return 0;
}

