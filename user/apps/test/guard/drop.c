/** NexusOS: drop privileges demonstration */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <sys/types.h>

#include <nexus/defs.h>
#include <nexus/test.h>
#include <nexus/guard.h>
#include <nexus/guard-impl.h>
#include <nexus/nexuscalls.h>

#include <nexus/IPC.interface.h>
#include <nexus/Debug.interface.h>
#include <nexus/Thread.interface.h>

/** Introspect on kernel state to verify cache state */
static int
check_refmon(int expected_port)
{
	char name[40];
	int fd, len, port;

	snprintf(name, 39, "/proc/os/pid/%d/refmon", getpid());
	fd = open(name, O_RDONLY);
	if (fd < 0)
		ReturnError(1, "open refmon");

	len = read(fd, name, 39);
	if (len < 0)
		ReturnError(1, "read #1");
	name[len] = 0;

	port = atoi(name);
	close(fd);

	return port == expected_port ? 0 : 1;
}

static int
check_rcache(void)
{
	struct dcache_elem elem;
	char name[40];
	int i, fd, len;

	// open
	snprintf(name, 39, "/proc/os/pid/%d/rcache", getpid());
	fd = open(name, O_RDONLY);
	if (fd < 0)
		ReturnError(1, "open rcache");

	// read: check correctness of three expected cache entries
	for (i = 0; i < 3; i++) {
		len = read(fd, (char *) &elem, sizeof(elem));
		if (!len)
			break;
		if (len != sizeof(elem))
			ReturnError(1, "read failed");

		if (elem.tuple.operation == SYS_Debug_Null3_CMD) {
			i++;
			if (elem.decision != AC_BLOCK_CACHE)
				ReturnError(1, "block decision #1");
		}
		else if (elem.tuple.operation == SYS_Thread_GetProcessID_CMD) {
			i++;
			if (elem.decision != AC_BLOCK_CACHE)
				ReturnError(1, "block decision #2");
		}
		if (elem.tuple.operation == SYS_IPC_CreatePort_CMD) {
			i++;
			if (elem.decision != AC_ALLOW_CACHE)
				ReturnError(1, "allow decision #1");
		}
	}

	// close
	close(fd);
	return 0;
}

/** Drop a single privilege. Check that subsequent calls fail */
static int
test_dropprivilege(void)
{
	int ports[2];

	// specifically test IPC, as communication restrictions are vital
	ports[0] = IPC_CreatePort(0);
	ports[1] = IPC_CreatePort(1);

	// sanity check: test that all succeeds before drop priv
	if (Debug_Null3(10) != 10)
		ReturnError(1, "call before drop");
	if (IPC_Send(ports[0], "a", 2))
		ReturnError(1, "send(x) fails #1");
	if (IPC_Send(ports[1], "a", 2))
		ReturnError(1, "send(x) fails #2");

	// drop privileges
	if (Thread_DropPrivilege(SYS_Debug_Null3_CMD, 0, 0))
		ReturnError(1, "drop privilege");
	
	if (Thread_DropPrivilege(SYS_IPC_Send_CMD, 0, ports[1]))
		ReturnError(1, "drop privilege");
	if (Thread_DropPrivilege(SYS_IPC_Send_CMD, 0, ports[1]))
		ReturnError(1, "drop privilege");
	
	// try again
	if (Debug_Null3(10) == 10)
		ReturnError(1, "call after drop");
	if (IPC_Send(ports[0], "a", 2))
		ReturnError(1, "send(x) fails after drop send(y)");
	if (!IPC_Send(ports[1], "a", 2))
		ReturnError(1, "send(x) succeeds after drop send(x)");

	IPC_DestroyPort(ports[0]);
	IPC_DestroyPort(ports[1]);

	if (check_refmon(REFMON_PORT_ALLOWALL))
		ReturnError(1, "wrong refmon");
	if (check_rcache())
		ReturnError(1, "error in rcache");
	
	return 0;
}

/** Actual function that will drop all privileges but a select whitelist */
static int
child_recordprivileges(void)
{
	// record whitelist of allowed operations
	if (Thread_SetPrivileges_Start())
		ReturnError(1, "whitelist set");

	// record method #1: add an ALLOW entry to the cache by calling
	if (Thread_GetProcessID() < 0)
		ReturnError(1, "whitelist #1");
	
	// record method #2: add an ALLOW entry to the cache directly
	Thread_SetPrivilege(SYS_Debug_Null3_CMD, 0, 0);
	Thread_SetPrivilege(SYS_Console_PrintString_CMD, 0, 0);
	
	// set all subsequent calls to BLOCK
	if (Thread_SetPrivileges_Stop())
		ReturnError(1, "whitelist stop");

	// check that whitelisted calls succeeds
	if (Debug_Null3(10) != 10)
		ReturnError(1, "whitelist fails #1");
	if (Thread_GetProcessID() < 0)
		ReturnError(1, "whitelist fails #2");

	// check that others fails
	if (Thread_GetParentID() != -1)
		ReturnError(1, "whitelist fails #3");

	// XXX verify whitelist through introspection
	return 0;
}

static int
test_recordprivileges(char *execpath)
{
	char cmd[100];
	pid_t pid;
	int status;

	// must create child, because test_dropprivilege will already
	// have set a reference monitor that we cannot replace
	snprintf(cmd, 99, "%s --client", execpath);
	pid = nxcall_exec(cmd);
	if (pid < 1)
		ReturnError(1, "child exec");

	waitpid(pid, &status, 0);
	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
		ReturnError(1, "child exit");

	return 0;
}

int
main(int argc, char **argv)
{
	if (argc == 2 && !strcmp(argv[1], "--client"))
		return child_recordprivileges();

	if (test_dropprivilege())
		return 1;
	
	if (test_recordprivileges(argv[0]))
		return 1;
	
	if (!nxtest_isauto(argc, argv))
		printf("[test] OK. done\n");
	
	return 0;
}


