/** NexusOS: disk quota authority 
 * 	     allows write if
 *           1. the account's total disk space is still within the its quota 
 *              after the write
 *           2. the calling process owns this file (i.e. only files created
 *              in the session can be written to)
 *           allows setting quota if
 *           1. every other account's quota will be guaranteed after the
 *              creation
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <nexus/defs.h>
#include <nexus/guard.h>
#include <nexus/test.h>
#include <nexus/fs.h>
#include <nexus/syscall-defs.h>

#include <nexus/FS.interface.h>
#include <nexus/IPC.interface.h>
#include <nexus/Auth.interface.h>
#include <nexus/Resource.interface.h>

int
auth_answer(const char *req, int pid)
{
	FSID fatfs_root;
	int ret, caller_id;
	char cmd[256];
	FSID node;

	fatfs_root = FSID_ROOT(FATFS_PORT);

	// this example authority uses sscanf to parse the expression
	// understand that this is FRAGILE with regard to whitespace, etc.
	if (sscanf(req, "name.quota says str(%s", cmd) != 1)
		ReturnError(0, "parse");

	// chops off the ')'
	cmd[strlen(cmd)-1] = '\0';

	if (IPC_TransferParam(&caller_id, -1, 0))
		ReturnError(0, "transfer caller id");

fprintf(stderr, "%s.%d\n", __FUNCTION__, __LINE__);
	if (!strcmp(cmd, "write") || !strcmp(cmd, "delete")) {
		int file_pos, file_cnt, file_size, file_inc, acc, valid_acc;
		int is_write = !strcmp(cmd, "write");

		if (is_write) {
			if (IPC_TransferParam(&node, 0, sizeof(FSID)))
				ReturnError(0, "transfer param 1");

			if (IPC_TransferParam(&file_pos, sizeof(FSID), sizeof(int)))
				ReturnError(0, "transfer param 2");

			if (IPC_TransferParam(&file_cnt, sizeof(FSID) + sizeof(int) +
			                      sizeof(struct VarLen), sizeof(int)))
				ReturnError(0, "transfer param 4");
		} 
		else {
			if (IPC_TransferParam(&node, sizeof(FSID), sizeof(FSID)))
				ReturnError(0, "transfer param 2");
		}

fprintf(stderr, "%s.%d\n", __FUNCTION__, __LINE__);
		acc = Resource_Account_ByProcess_ext(quota_ctrl_port, caller_id);
		if (acc < 0)
			ReturnError(0, "unknown process");

		valid_acc = Resource_Account_CheckInfo_ext(quota_ctrl_port, acc, VARLEN(&node, sizeof(FSID)));
		if (valid_acc < 1)
			ReturnError(0, "access denied\n");

		if (nexusfs_mount(FSID_EMPTY, fatfs_root))
			ReturnError(0, "mount");

		file_size = FS_Size(node);

		nexusfs_unmount(FSID_EMPTY, fatfs_root);

		if (file_size < 0)
			ReturnError(0, "unknown file size");
		
		if (is_write) {
			// how many bytes will really be added to my account
			file_inc = file_pos + file_cnt - file_size;
			// need to check quota
			if (file_inc > 0) {
				int allowed;
				allowed = Resource_Account_AddResource_ext(quota_ctrl_port, acc, file_inc);
				if (allowed < 0)
					ReturnError(0, "quota limit exceeded");
			}
		} 
		else if (!Resource_Account_AddInfo_ext(quota_ctrl_port, acc, 
						       VARLEN(&node, sizeof(FSID)))) {
			// remove this info from account
			if (Resource_Account_AddResource_ext(quota_ctrl_port, acc, -file_size) < 0)
				ReturnError(0, "unable to delete quota");
		}

	} 

	return 1;
}

int
main(int argc, char **argv)
{
	return nxguard_auth(default_guard_port, "quota", NULL);
}

