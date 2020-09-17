/** NexusOS: selftest for the guard: test the cred, goal and upcall channels */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include <nexus/defs.h>
#include <nexus/test.h>
#include <nexus/ipc.h>
#include <nexus/guard.h>

#include <nexus/Debug.interface.h>
#include <nexus/IPC.interface.h>
#include <nexus/Thread.interface.h>

static int
test_key(void)
{
	static RSA *rsakey;
	
	rsakey = rsakey_create();
	if (!rsakey)
		ReturnError(1, "RSA key creation failed");

	if (nxguard_cred_add("true", rsakey))
		ReturnError(1, "add key-based credential failed");

	return 0;
}

int
main(int argc, char **argv)
{
	struct nxguard_object ob;
	char buf[100];
	int ret;

	test_skip_auto();
	if (!nxtest_isauto(argc, argv))
		fprintf(stderr, "WARN: may crash in OpenSSL: RAND_seed\n"
				"      only happens on repeat invocation (I don't know why)\n");

	nxguard_object_clear(&ob);	// this call has no object. set to NULL

	////  Test that access FAILS when told to ////

	// set block all policy
	if (nxguard_goal_set_str(SYS_Debug_Null3_CMD, &ob, "false"))
		ReturnError(1, "[test] Error: could not set policy");

	// call the function
	if (Debug_Null3(10) != -1)
		ReturnError(1, "[test] Error: NOT blocked #1");


	////  Test that access PASSES when told to ////
	
	// change policy
	snprintf(buf, 99, "process.%d says debug=1", Thread_GetProcessID());
	if (nxguard_goal_set_str(SYS_Debug_Null3_CMD, &ob, buf))
		ReturnError(1, "[test] set goal #2 failed");

// NB: with new automatic inference of trivial proofs (`assume <<goal>>')
//     this step is no longer needed. run test without
#if 0
	// supply a proof that leads to the goal
	snprintf(buf, 99, "assume process.%d says debug=1;", Thread_GetProcessID());
	if (nxguard_proof_set(SYS_Debug_Null3_CMD, &ob, buf))
		ReturnError(1, "[test] set proof failed");
	
	// call the function
	if (Debug_Null3(10) != -1)
		ReturnError(1, "[test] Error: NOT blocked #2");
#endif

	// add the credential needed for the one assumption
	if (nxguard_cred_add("debug=1", NULL))
		ReturnError(1, "[test] add cred failed");
	
	// call the function
	if (Debug_Null3(10) != 10)
		ReturnError(1, "[test] Error: blocked");

	// reset state
	if (nxguard_goal_set_str(SYS_Debug_Null3_CMD, &ob, NULL))
		ReturnError(1, "[test] set goal #2 failed");

	if (test_key())
		return 1;

	if (argc == 1) // not 'auto' call at boot
		printf("[guard] test passed OK\n");
	
	return 0;
}

