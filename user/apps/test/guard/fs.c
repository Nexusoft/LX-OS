/** NexusOS: practise FS access control using NAL 
             handoff ownership using nonces */

#include <nexus/fs.h>
#include <nexus/ipc.h>
#include <nexus/guard.h>
#include <nexus/test.h>

#include <nexus/FS.interface.h>
#include <nexus/IPC.interface.h>
#include <nexus/Debug.interface.h>
#include <nexus/Thread.interface.h>

#define FCONTENTS "testing NAL guard\n"
#define FMAXLEN 400

/** Attach a policy to an <object, operation> pair
    @param revision is a nonce, use 0 for the first version of an object */
static void
nxfile_setgoal(FSID file, int operation, const char *goal)
{
	struct nxguard_object object;
	char buf[FMAXLEN + 1];

	// write policy
	snprintf(buf, FMAXLEN, "ipc.%u.%llu.1 says %s", 
		 file.port, fsid_upper(&file), goal);

	// translate FSID into authorization object
	nxguard_object_clear(&object);
	object.fsid = file;

	// set policy
	if (nxguard_goal_set_str(operation, &object, buf))
		ReturnError(, "goal set");
}

/** Verify drop privilege functionality 
    Does not really belong in the FS tests, but I did not want to add
    yet another 2MB file to the initial ramdisk */
static int
test_dropprivilege(void)
{
	if (Debug_Null3(10) != 10)
		ReturnError(1, "drop privilege #1");

	if (Thread_DropPrivilege(SYS_Debug_Null3_CMD, 0, 0))
		ReturnError(1, "drop privilege #2");

	if (Debug_Null3(10) == 10)
		ReturnError(1, "drop privilege #3");

	// make sure that additional drops also succeed
	if (Thread_DropPrivilege(SYS_Debug_Null2_CMD, 0, 0))
		ReturnError(1, "drop privilege #4");

	return 0;
}

int
main(int argc, char **argv)
{
	struct nxguard_object object;
	Port_Num root_port;
	FSID root, dir, file;
	char buf[FMAXLEN];
	int ret;

	test_skip_auto();

	root_port = ipc_server_run("RamFS");
	root = FSID_ROOT(root_port);

	// create a file
	if (nexusfs_mount(FSID_EMPTY, root))
		ReturnError(1, "mount");

	dir = nexusfs_mkdir(root, "naltest");
	if (!FSID_isDir(dir))
		ReturnError(1, "mkdir");

	file = nexusfs_mk(dir, "naltest", FCONTENTS);
	if (!FSID_isFile(file))
		ReturnError(1, "mk");
	
	nxguard_object_clear(&object);
	object.fsid = file;
	
	////////  DEFAULT  ////////

	// read should succeed
	ret = FS_Read(file, 0, VARLEN(buf, FMAXLEN), FMAXLEN);
	if (ret <= 0 || strcmp(buf, FCONTENTS))
		ReturnError(1, "read #1");

	////////  DENY ALL  ////////

	// set policy
	nxfile_setgoal(file, SYS_FS_Read_CMD, "false");
	
	// try to read
	ret = FS_Read(file, 0, VARLEN(buf, FMAXLEN), FMAXLEN);
	if (ret >= 0)
		ReturnError(1, "read #2");

	////////  ALLOW ALL  ////////

	// set policy
	nxguard_goal_set_str(SYS_FS_Read_CMD, &object, NULL);
	
	// try to read
	ret = FS_Read(file, 0, VARLEN(buf, FMAXLEN), FMAXLEN);
	if (ret <= 0 || strcmp(buf, FCONTENTS))
		ReturnError(1, "read #3");

	////////  chmod(0400) test  ////////
	
	// set goal
	nxfile_setgoal(file, SYS_FS_Read_CMD, "read=1");
	
	// set proof
	snprintf(buf, FMAXLEN, "assume process.%d says read=1;\n"
			       "assume ipc.%u.%llu.1 says process.%d speaksfor ipc.%u.%llu.1;\n"
			       "delegate;\n"
			       "sfor read=1;\n"
			       "impe;\n",
			       Thread_GetProcessID(), 
			       file.port, fsid_upper(&file), 
			       Thread_GetProcessID(), 
			       file.port, fsid_upper(&file));
	nxguard_proof_set(SYS_FS_Read_CMD, &object, buf);

	// set credential
	nxguard_cred_add("read=1", NULL);

	ret = FS_Read(file, 0, VARLEN(buf, FMAXLEN), FMAXLEN);
	if (ret <= 0)
		ReturnError(1, "read #4");

// XXX currently, drops privileges on all not-yet-seen calls, including Thread_Exit
//     causes infinite loop when process ends as a result
#if 0
	// test drop privilege on other call:
	// may NOT drop privilege on this call
	if (test_dropprivilege())
		return 1;
	
	ret = FS_Read(file, 0, VARLEN(buf, FMAXLEN), FMAXLEN);
	if (ret <= 0)
		ReturnError(1, "read #4");
#endif

	// change goal back to block all
	nxfile_setgoal(file, SYS_FS_Read_CMD, "false");
	
	ret = FS_Read(file, 0, VARLEN(buf, FMAXLEN), FMAXLEN);
	if (ret > 0)
		ReturnError(1, "read #5");

	printf("[guard] fstest succeeded\n");

	return 0;
}

