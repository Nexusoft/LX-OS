/** NexusOS: test Guard_SetGoal functionality 
 
    This file consists of two tests: setgoal and proofnowrite
 
    Setgoal demonstrates the application of access control on 
    authorization functions. The only way to increase privileges
    is to set a goal, therefore Nexus guards the Guard_SetGoal
    call. Setgoal tests that once a process adds an impossible
    guard on this call (+ specific operation), it can no longer
    change the goal on the selected operation.
    
    The getgoal test verifies correctness of the
    guard's getgoal operation for goal querying.
 
    ProofNoWrite goes one step further: it shows how a process can
    prove that it cannot perform a specific operation on any object.
    The behavior is needed to prove that a process cannot leak data.
    In the example, a child process drops write privileges on all
    files as well and simultaneously drops SetGoal privileges 
    on the 'write file' operation. This suffices to show that it
    can no longer use the write operation.

    XXX the current implementation is incorrect: it checks the 
    proofs, but caller can change these at any time. It should be:
    - caller sets proof on (caller, write, *) that fails
    - caller sets proof on (caller, setproof, write) that fails
    - goal (*, write, *) exists, so that a proof is required
    - caller cannot remove goal (*, write, *)
    but there is currently no access control on SetProof.

 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>

#include <nexus/defs.h>
#include <nexus/test.h>
#include <nexus/guard.h>
#include <nexus/rdtsc.h>
#include <nexus/nexuscalls.h>

#include <nexus/FS.interface.h>
#include <nexus/IPC.interface.h>
#include <nexus/Debug.interface.h>
#include <nexus/Thread.interface.h>

// blueprint for proofnowrite test
//            cannot write any and cannot change 'write any' privileges
//            see guard_authority_proof for further syntax information
#define fmt1		"(name.guard says proof.0.%d.0.0  = \"\")"
#define fmt2		"(name.guard says proof.0.%d.0.%d = \"\")"
#define fmt_goal	fmt1 "and" fmt2
#define fmt_proof	"assume " fmt1 ";\n" "assume " fmt2 ";\n" "andi;\n"

// blueprint for setgoal test
#define FMT_STGOAL	"name.guard says subject = %d"
#define FMT_STPROOF	"assume " FMT_STGOAL ";"

/** Return 1 if goal is set, 0 otherwise */
static int
test_getgoal_sub(int operation, struct nxguard_object *ob)
{
	char *goal;
	int ret;

	goal = nxguard_goal_get(operation, ob);
	ret = goal ? 1 : 0;
	if (goal)
		free(goal);

	return ret;
}

/** Test guard query interface: nxguard_getgoal */
static int 
test_getgoal(void)
{
	struct nxguard_object ob;
	
	ob.upper = 0;
	ob.lower = 0;

	if (Debug_Null3(10) != 10)
		ReturnError(1, "syscall failed #1");

	// verify that no prior goal has been set
	if (test_getgoal_sub(SYS_Debug_Null3_CMD, NULL))
		ReturnError(1, "goal set when not expected\n");

	// set impossible goal on Null3 call
	if (nxguard_goal_set_str(SYS_Debug_Null3_CMD, &ob, "false"))
		ReturnError(1, "set goal #1 failed\n");

	// verify that goal has been set correctly
	if (!test_getgoal_sub(SYS_Debug_Null3_CMD, NULL))
		ReturnError(1, "goal not set when expected\n");
	
	// verify that call now fails
	if (Debug_Null3(10) >= 0)
		ReturnError(1, "syscall failed #2");

	// reset state
	if (nxguard_goal_set_str(SYS_Debug_Null3_CMD, &ob, NULL))
		ReturnError(1, "clear goal failed\n");

	// verify that call succeeds again
	if (Debug_Null3(10) != 10)
		ReturnError(1, "syscall failed #3");

	return 0;
}

/** Verify that the child cannot change a goal once it has dropped privileges */
static int
test_setgoal_child(void)
{
	struct nxguard_object ob;
	char buf[100];
	int ret;

	ob.upper = 0;
	ob.lower = SYS_Debug_Null3_CMD;
	
	if (test_getgoal_sub(SYS_Guard_SetGoal_CMD, &ob))
		ReturnError(1, "goal get #1\n");

	// drop SetGoal privileges on object 'system call Debug_Null3()'
	// by setting goal to only allow access by previous process
	sprintf(buf, FMT_STGOAL, getpid() - 1);
	if (nxguard_goal_set_str(SYS_Guard_SetGoal_CMD, &ob, buf))
		ReturnError(1, "set goal #2 failed\n");

	// see that subsequent SetGoal on this object fails
	if (!nxguard_goal_set_str(SYS_Guard_SetGoal_CMD, &ob, NULL))
		ReturnError(1, "set goal succeeded when supposed to fail\n");
	
	return 0;
}

/** Verify access control on access control SetGoal operation:
    update the goal on a system call to deny-all and verify that
    cannot update a second time 
 
    NB: tests nxguard_goal_get at the same time 
  */
static int
test_setgoal(const char *filepath)
{
	struct nxguard_object ob;
	char buf[100];
	int pid, ret;

	ob.upper = 0;
	ob.lower = SYS_Debug_Null3_CMD;
	
	// start child process
	pid = nxcall_exec_ex(filepath, (char *[]) {(char *) filepath, "--child2", NULL}, NULL, 0);

	// wait for child to finish
	waitpid(pid, &ret, 0);
	if (ret)
		ReturnError(1, "child failed");

	if (!test_getgoal_sub(SYS_Guard_SetGoal_CMD, &ob))
		ReturnError(1, "goal get #4\n");

	// verify that policy blocks this process
	if (!nxguard_goal_set_str(SYS_Guard_SetGoal_CMD, &ob, NULL))
		ReturnError(1, "parent setgoal error #1\n");

	// set required proof: we are process N, where child was N+1
	sprintf(buf, FMT_STPROOF, getpid());
	if (nxguard_proof_set(SYS_Guard_SetGoal_CMD, &ob, buf))
		ReturnError(1, "set proof failed #2");

	// reset state (and verify that this process did not drop privileges)
	if (nxguard_goal_set_str(SYS_Guard_SetGoal_CMD, &ob, NULL))
		ReturnError(1, "parent setgoal error #2\n");
	
	return 0;
}

/** Child process that voluntarily drops privileges indefinitely */
static int
test_proofnonwrite_child(void)
{
	struct nxguard_object ob;
	char proof[150];

	// try to access guarded object (must fail)
	if (Debug_Null3(10) >= 0)
		ReturnError(1, "call failed #1");

	// insert proof for <me, write file, any> that says false
	ob.upper = 0;
	ob.lower = 0;
	if (nxguard_proof_set(SYS_FS_Write_CMD, &ob, NULL))
		ReturnError(1, "set proof failed #1");

	// insert proof for <me, setpolicy, write file> that says false
	ob.upper = 0;
	ob.lower = SYS_FS_Write_CMD;
	if (nxguard_proof_set(SYS_Guard_SetGoal_CMD, &ob, NULL))
		ReturnError(1, "set proof failed #2");
	
	// insert proof for <me, null3, any> 
	// that shows that <me> can never write to any file
	snprintf(proof, 149, fmt_proof, SYS_FS_Write_CMD,
		 SYS_Guard_SetGoal_CMD, SYS_FS_Write_CMD);
	ob.upper = 0;
	ob.lower = 0;
	if (nxguard_proof_set(SYS_Debug_Null3_CMD, &ob, proof))
		ReturnError(1, "set proof failed #3");

	// try to access guarded object (must pass)
	if (Debug_Null3(10) != 10)
		ReturnError(1, "call failed #2");

	// XXX verify that it fails when we set the wrong proof 
	return 0;
}

/** Test proof of dropped write privileges:
    The process will (need to) prove that it has dropped all
    fileserver write privileges indefinitely */
static int
test_proofofnowrite(const char *filepath)
{
	struct nxguard_object ob;
	char req[150];
	int pid, ret;

	// create goal 
	snprintf(req, 149, fmt_goal, SYS_FS_Write_CMD, 
		 SYS_Guard_SetGoal_CMD, SYS_FS_Write_CMD);

	// set goal
	nxguard_object_clear(&ob);
	if (nxguard_goal_set_str(SYS_Debug_Null3_CMD, &ob, req))
		ReturnError(1, "set goal in proof_nowrite");

	// start child process
	pid = nxcall_exec_ex(filepath, (char *[]) {(char *) filepath, "--child", NULL}, NULL, 0);

	// wait for child to finish
	waitpid(pid, &ret, 0);
	
	// reset goal
	if (nxguard_goal_set_str(SYS_Debug_Null3_CMD, &ob, NULL))
		ReturnError(1, "clear goal in proof_nowrite");
	
	if (ret)
		ReturnError(1, "child failed");

	return 0;
}

/** Test proof that all write operations write only safe data.
    In this test, safe constitutes a fixed string, but the idea
    is to restrict to a more flexible pattern (e.g., using a regex) */
static int
test_proofwritesafe(const char *filepath)
{
#define PWS_GOAL	"name.guard says param(1,0,4) = \"pass\"" 
#define PWS_PROOF	"assume " PWS_GOAL ";"

	const char filename[] = "gt.txt";
	struct nxguard_object ob;
	FSID root, file;

	// create testfile
	root = FSID_ROOT(KERNELFS_PORT);
	file = nexusfs_mk(root, filename, NULL); 
	if (!FSID_isFile(file))
		ReturnError(1, "mkfile");

	ob.upper = ob.lower = 0; 
	ob.fsid = file;

	// set goal
	if (nxguard_goal_set_str(SYS_FS_Write_CMD, &ob, PWS_GOAL))
		ReturnError(1, "set goal in proof_nowrite");

	// set proof
	if (nxguard_proof_set(SYS_FS_Write_CMD, &ob, PWS_PROOF))
		ReturnError(1, "set proof failed #2");

	if (FS_Write(file, 0, VARLENSTR("fail"), 5) == 5)
		ReturnError(1, "illegal write passed");

	if (FS_Write(file, 0, VARLENSTR("pass"), 5) != 5)
		ReturnError(1, "legal write blocked");

	if (nexusfs_unlink(root, filename))
		ReturnError(1, "rm");
	
	// reset goal
	if (nxguard_goal_set_str(SYS_FS_Write_CMD, &ob, NULL))
		ReturnError(1, "clear goal in proof_writesafe");
	
	return 0;
}

int
main(int argc, char **argv)
{
	// skip test during boottime autotesting
	test_skip_auto();

	// treat child processes differently
	if (argc == 2 && !strcmp(argv[1], "--child"))
		return test_proofnonwrite_child();
	if (argc == 2 && !strcmp(argv[1], "--child2"))
		return test_setgoal_child();

	printf("Nexus access control applied to access control calls demo\n");
	
	// XXX WARNING: fails if setgoal is not first test (but only on first invocation)
	if (test_setgoal(argv[0]))
		return 1;

	if (test_getgoal())
		return 1;

	// WARNING: this example does not actually drop privileges
	//          and is therefore NOT safe.
	if (test_proofofnowrite(argv[0]))
		return 1;
	
	if (test_proofwritesafe(argv[0]))
		return 1;

	printf("[test] OK\n");
	return 0;
}

