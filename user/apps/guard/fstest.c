/** NexusOS: practise FS access control using NAL */

#include <nexus/fs.h>
#include <nexus/ipc.h>

#include <nexus/FS.interface.h>
#include <nexus/Debug.interface.h>
#include <nexus/Thread.interface.h>

#define ReturnError(stmt) 						\
	do { fprintf(stderr, "Error in %s at %d\n", stmt, __LINE__); 	\
	     return -1;							\
	} while(0)

#define FCONTENTS "testing NAL guard\n"
#define FMAXLEN 200

int
main(int argc, char **argv)
{
	Port_Num root_port;
	FSID root, dir, file;
	char buf[FMAXLEN];
	char policy[80], proof[400];
	int ret;

	// test against local FS server
	root_port = ipc_server_run("RamFS");
	if (root_port < 0) {
		fprintf(stderr, "Failed to create local FS\n");
		return 1;
	}
	root = FSID_ROOT(root_port);

	// create a file
	if (nexusfs_mount(FSID_EMPTY, root))
		ReturnError("mount");

	dir = nexusfs_mkdir(root, "naltest");
	if (!FSID_isDir(dir))
		ReturnError("mkdir");

	file = nexusfs_mk(dir, "naltest", FCONTENTS);
	if (!FSID_isFile(file))
		ReturnError("mk");

	//// verify that in default case owner may read
	ret = FS_Read(file, 0, (struct VarLen) {.data = buf, .len = FMAXLEN}, FMAXLEN);
	if (ret <= 0 || strcmp(buf, FCONTENTS))
		ReturnError("read #1");

	//// set deny policy and verify that owner may not read
	Debug_guard_chgoal(file, SYS_FS_Read_CMD, "false", 5);
	Debug_guard_chgoal(file, SYS_FS_Write_CMD, "false", 5);
	
	ret = FS_Read(file, 0, (struct VarLen) {.data = buf, .len = FMAXLEN}, FMAXLEN);
	if (ret > 0 && !strcmp(buf, FCONTENTS))
		ReturnError("read #3");

	//// set allow policy and verify that owner may read and write
	Debug_guard_chgoal(file, SYS_FS_Read_CMD, NULL, 0);
	Debug_guard_chgoal(file, SYS_FS_Write_CMD, NULL, 0);
	
	ret = FS_Read(file, 0, (struct VarLen) {.data = buf, .len = FMAXLEN}, FMAXLEN);
	if (ret <= 0 || strcmp(buf, FCONTENTS))
		ReturnError("read #2");

	ret = FS_Write(file, 0, (struct VarLen) {.data = "t", .len = 1}, 1);
	if (ret != 1)
		ReturnError("write #1");

	//// set S_IRUSR policy and verify that owner may only read
	snprintf(policy, 79, "file says true");
	Debug_guard_chgoal(file, SYS_FS_Read_CMD, policy, strlen(policy)); 
	Debug_guard_chgoal(file, SYS_FS_Write_CMD, "false", 5);
	// XXX insert premise:
	//     Debug_guard_addpremise("pid:%d speaksfor file", Thread_GetProcessID());
	
	snprintf(proof, 399, "assume pid:%d speaksfor file", Thread_GetProcessID());
	Debug_guard_chproof(proof, strlen(proof));
	ret = FS_Read(file, 0, (struct VarLen) {.data = buf, .len = FMAXLEN}, FMAXLEN);
	if (ret <= 0)
		ReturnError("read #4");

	ret = FS_Write(file, 0, (struct VarLen) {.data = "t", .len = 1}, 1);
	if (ret >= 0)
		ReturnError("write #2");

	//// verify that no process than that set in policy may read 
	// by setting permissions to owner +1
	// XXX insert premise:
	//     Debug_guard_addpremise("pid:%d speaksfor file", 1 + Thread_GetProcessID());
	// XXX remove previously inserted premise

	ret = FS_Read(file, 0, (struct VarLen) {.data = buf, .len = FMAXLEN}, FMAXLEN);
	if (ret >= 0)
		ReturnError("read #5");

	printf("[guard] fstest succeeded\n");
	return 0;
}

