/** NexusOS: selftest for the guard: test the auth channel */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <nexus/defs.h>
#include <nexus/ipc.h>
#include <nexus/guard.h>
#include <nexus/test.h>
#include <nexus/sema.h>

#include <nexus/IPC.interface.h>
#include <nexus/Auth.interface.h>
#include <nexus/Guard.interface.h>

static Sema sema = SEMA_INIT;

int
auth_answer(const char *req, int pid)
{
	int arg;

	// this example authority uses sscanf to parse the expression
	// understand that this is WEAK with regard to whitespace, etc.
	if (sscanf(req, "authport = %d", &arg) != 1)
		ReturnError(-1, "test authority input");

	return (arg == Auth_port_handle) ? 1 : 0;
}

static void *
answerthread(void *unused)
{
	// initialize
	Auth_serverInit();
	if (nxguard_auth_register(default_guard_port, Auth_port_handle, "test"))
		ReturnError((void *) 1, "[auth] registration failed");
	V_nexus(&sema);

	// run: test involves two requests
	Auth_processNextCommand();
	Auth_processNextCommand();

	return NULL;
}

int
main(int argc, char **argv)
{
	pthread_t t;

	test_skip_auto();	// do not run at boot

	// start authority
	pthread_create(&t, NULL, answerthread, NULL);
	P(&sema);
	usleep(10000);	// slight race between V_nexus and Auth_processNextCommand, above

	// make guard issue testcalls to our authority
	if (Guard_TestAuth_ext(default_guard_port))
		ReturnError(1, "selftest failed\n");

	printf("[authtest] OK\n");
	return 0;
}

