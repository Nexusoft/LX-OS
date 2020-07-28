/** NexusOS: selftest for the guard: test the cred, goal and upcall channels */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <nexus/defs.h>
#include <nexus/ipc.h>
#include <nexus/guard.h>
#include <nexus/test.h>

#include <nexus/IPC.interface.h>
#include <nexus/Thread.interface.h>

int
nxguard_upcall_open(void)
{
	int portnum;

	portnum = guard_upreply_port;
	portnum = IPC_CreatePort(&portnum);
	if (portnum != guard_upreply_port)
		ReturnError(-1, "[guard] could not acquire port\n");

	return 0;
}

/** Ask the guard whether to allow a call to go through.
    Normally, only the kernel is allowed to do this. */
int
nxguard_upcall(int subject, int operation, struct nxguard_object *object)
{
	struct guard_upcall_msg msg;
	int ret;

	msg.subject = subject;
	msg.operation = operation;
	memcpy(&msg.object, object, sizeof(msg.object));

	if (IPC_Send(guard_upcall_port, &msg, sizeof(msg))) 		
		ReturnError(-1, "[guard] send upcall error\n");
	
	if (IPC_Recv(guard_upreply_port, &ret, sizeof(ret)) != sizeof(ret))
		ReturnError(-1, "[guard] recv upcall error\n");

	printf("[guardcall] guard replied %s\n", ret == 0 ? "BLOCK" : "PASS");

	return 0;
}

int
main(int argc, char **argv)
{
	struct nxguard_object ob;
	RSA *key;
	int ret;

	test_skip_auto();

	key = rsakey_create();
	if (!key)
		return -1;

	if (nxguard_upcall_open())
		return -1;

	if (nxguard_cred_add("true", key))
		return -1;

printf("%s.%d \n", __FUNCTION__, __LINE__);
	ob.lower = ob.upper = 0;
	if (nxguard_goal_set(SYS_Thread_USleep_CMD, &ob, "kernel says true"))
		return 0;

printf("%s.%d \n", __FUNCTION__, __LINE__);
	if (nxguard_proof_set(SYS_Thread_USleep_CMD, &ob, "XXX eval"))
		return 0;

printf("%s.%d \n", __FUNCTION__, __LINE__);
	ret = nxguard_upcall(Thread_GetProcessID(), SYS_Thread_USleep_CMD, &ob);

printf("%s.%d \n", __FUNCTION__, __LINE__);
	RSA_free(key);
	printf("[guard] test passed OK\n");
	return 0;
}

