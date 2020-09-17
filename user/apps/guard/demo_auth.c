/** NexusOS: A few simple examples of how authorities are used:
             1) bureaucrat bases its decisions on the time of day 
 	     2) filefinal allows writing to a file until it starts with FINAL
	     3) quota tests writing to the fat32 partition with user-binded
	        space limits
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>

#include <openssl/rsa.h>

#include <nexus/fs.h>
#include <nexus/defs.h>
#include <nexus/test.h>
#include <nexus/guard.h>
#include <nexus/formula.h>
#include <nexus/syscall-defs.h>

#include <nexus/Resource.interface.h>
#include <nexus/FS.interface.h>
#include <nexus/Thread.interface.h>
#include <nexus/Debug.interface.h>

#define FILENAME	"fftest"
#define QUOTA    	1024
#define LINELEN  	256

/** Create a file, set access control to depend on what the 
    'filefinal' authority says, and write until blocked. */
static int
test_filefinal(void)
{
	struct nxguard_object object;
	char buf[LINELEN], buf2[LINELEN], filepath[255];
	FSID root, file;
	int ret, ilen, final;
	Form *formula;
	char *form, *pubkey;
	RSA *key;

	printf("[demo] writing until we write 'FINAL'\n");

	// mount fs
	root = FSID_ROOT(KERNELFS_PORT);
	if (nexusfs_mount(FSID_EMPTY, root))
		ReturnError(1, "mount");

	// create a file
	file = nexusfs_mk(root, FILENAME, "firstfile");
	if (!FSID_isFile(file))
		ReturnError(1, "mk");

	// load the key of the authority
	snprintf(filepath, 254, "/var/auth/ff");
	key = rsakey_public_import_file(filepath);
	if (!key)
		ReturnError(1, "load key");
	pubkey = rsakey_public_export(key);
	free(key);
	if (!pubkey)
		ReturnError(1, "extract key");

	// prepare proof and policy parameters
	snprintf(buf, LINELEN, "ipc.%u.<<%llx>> = writable\n",
		 file.port, fsid_upper(&file));

	nxguard_object_clear(&object);
	memcpy(&object.fsid, &file, sizeof(FSID));
	
	if (nxguard_goalproof_set("ff", SYS_FS_Write_CMD, &object, buf, 2))
		ReturnError(1, "setgoal");

	// file test specifics, not common credentials
	printf("NXDEBUG: use of Thread_GetProcessID in code below is almost certainly incorrect\n");

	// add credential that ff authority speaks for the file
	snprintf(buf, LINELEN, "ipc.%u.%llu says pem(%%{bytes:%d}) speaksfor ipc.%u.%llu",
		 file.port, fsid_upper(&file), Thread_GetProcessID(), 
		 file.port, fsid_upper(&file));
	formula = form_fmt(buf, pubkey);
	free(pubkey);
	form = form_to_pretty(formula, 0);

	if (nxguard_cred_add_raw(form))
		ReturnError(1, "add cred");

	free(form);
	form_free(formula);

	// NB: Nexus no longer allows deleting credentials
	// remove default credential that we as owner are given
#if 0
	snprintf(buf, LINELEN, "ipc.%u.%llu says process.%d speaksfor ipc.%u.%llu",
		 file.port, fsid_upper(&file), Thread_GetProcessID(), 
		 file.port, fsid_upper(&file));

	if (nxguard_cred_del_raw(buf))
		ReturnError(1, "del cred");*/
#endif

	printf("[demo] Write to the file. Give a string and press [enter]\n");
	printf("       To quit, write FINAL\n");
	final = 0;
	while (1) {
		// get input
		fprintf(stderr, "> ");
		if (!fgets(buf, 255, stdin))
			continue;
		ilen = strlen(buf);

		// sometimes (?) there's an extra \n. remove
		if (buf[ilen - 1] == '\n')
			buf[--ilen] = 0;
		
		// write and verify pass/fail is as expected
		ret = FS_Write(file, 0, (struct VarLen) {.data = buf, .len = ilen}, ilen);
		if (final) {
			if (ret != -1) {
				fprintf(stderr, "Write Error. Succeeded after FINAL\n");
				goto cleanup_file;
			}
			printf("OK. Write failed\n");
			break;
		}
		else {
			if (ret != ilen) {
				fprintf(stderr, "Write Error. Is the ff authority running?\n");
				goto cleanup_file;
			}
		}

		// read back and verify that it's the same
		ret = FS_Read(file, 0, (struct VarLen) {.data = buf2, .len = ilen}, ilen);
		if (ret != ilen || memcmp(buf, buf2, ret)) {
			fprintf(stderr, "Read Error. Read failed (%d=%d) (%s=%s)\n", 
			        ret, ilen, buf, buf2);
			goto cleanup_file;
		}

		// find out whether next write should pass or fail
		if (ilen >= 5 && !memcmp(buf, "FINAL", 5)) {
			printf("observed FINAL. Your next write will fail\n");
			final = 1;
		}

	} 

	if (nexusfs_unlink(root, FILENAME))
		ReturnError(1, "rm");

	return 0;

cleanup_file:
	if (nexusfs_unlink(root, FILENAME))
		ReturnError(1, "rm");

	return 1;
}

static int
test_bureaucrat(void)
{
	RSA *key;
	struct nxguard_object object;
	char *buf, buf2[256], *pubkey, *form;
	int ret, ilen, final;

	struct tm *split;
	time_t now;
	int working;

	printf("[demo] asking the bureaucrat to give access to a file\n");
	
	// read number of seconds since 1970
	now = time(NULL);
	if (now == (time_t) -1)
		ReturnError(0, "time()");

	// parse time into days, etc.
	split = localtime(&now);
	if (!split)
		ReturnError(0, "localtime()");

	// calculate whether the bureaucrat should be working
	working = split->tm_hour < 9 || (split->tm_hour > 16 && split->tm_min > 47) ? 0 : 1;

	// insert goal and proof 
	nxguard_object_clear(&object);
	if (nxguard_goalproof_set("bureaucrat", SYS_Debug_Null2_CMD, &object, "true", 2))
		ReturnError(1, "setgoal");

	// call the function
	ret = Debug_Null2(10);
	if (working) {
		if (ret != 10)
			ReturnError(1, "Working but failed\n");
	}
	else {
		if (ret == 10)
			ReturnError(1, "Not working but succeeded\n");
	}

	printf("[demo] ok. Bureaucrat is %sworking and did %sOK it\n",
	       working ? "" : "not ", ret == 10 ? "" : "not ");

	return 0;
}

/** Send all actions to a remote host */
static int
test_remote(const char *auth_type)
{
	struct nxguard_object object;
#define DOTEST 3
	char buf;
	int i;

	printf("[demo] setting all accesses to Debug_Null2 to be logged\n");
	
	// insert goal and proof 
	nxguard_object_clear(&object);
	if (nxguard_goalproof_set(auth_type, SYS_Debug_Null2_CMD, &object, "true", 2))
		ReturnError(1, "setgoal");

	printf("[demo] calling function the next %d times you press [enter]\n",
	       DOTEST);

	for (i = 0; i < DOTEST; i++) {
		while ((buf = getchar()) != '\n' && buf != EOF) {}

		// call the function
		if (Debug_Null2(10) != 10)
			ReturnError(1, "call failed");
		fprintf(stderr, "%d. OK\n", i);
	}

	return 0;
}

/** Setup account quota and perform a write that will succeed
    and a second write that will exceed the quota limit
    NB: no persistent storage, demo only works on files
    created in this session */

static int
test_quota(void)
{
	int acc;
	struct nxguard_object object;
	FSID fatfs_root = FSID_ROOT(FATFS_PORT), node;

	// mount fs
	if (nexusfs_mount(FSID_EMPTY, fatfs_root))
		ReturnError(1, "mount");

	// Setup my quota
	if ((acc = Resource_Account_New_ext(quota_ctrl_port, 10)) < 0)
		ReturnError(1, "create acccount");

	if (Resource_Account_AddProcess_ext(quota_ctrl_port, acc, Thread_GetProcessID()) < 0)
		ReturnError(1, "attach process");

	node = FS_Create(fatfs_root, (struct VarLen) {.data = "test", .len = 5}, FS_NODE_FILE);
	if (!FSID_isValid(node))
		ReturnError(1, "create");

	if (Resource_Account_AddInfo_ext(quota_ctrl_port, acc, (struct VarLen) {.data = (void *)&node, .len = sizeof(FSID)}))
		ReturnError(1, "register file");

	nxguard_object_clear(&object);
	object.fsid = node;
	if (nxguard_goalproof_set("quota", SYS_FS_Write_CMD, &object, "str(write)", 0))
		ReturnError(1, "write set proof");

	// Write that is < limit
	if (FS_Write(node, 0, (struct VarLen) {.data = "content", .len = 7}, 7) != 7)
		ReturnError(1, "write 1");

	// Write that is > limit
	if (FS_Write(node, 4, (struct VarLen) {.data = "overflow", .len = 8}, 8) == 8) 
		ReturnError(1, "write 2");

	if (nxguard_goalproof_set("quota", SYS_FS_Unlink_CMD, &object, "str(delete)", 0))
		ReturnError(1, "delete set proof");

	if (nexusfs_unlink(fatfs_root, "test"))
		ReturnError(1, "rm");

	nexusfs_unmount(FSID_EMPTY, fatfs_root);
	
	return 0;
}

int 
main(int argc, char **argv)
{
	// WARNING: requires 
	//            1. guard_auth_quota.app 
	//            2. FatFS with quota support enabled
	// XXX silently succeed if FatFS is not loaded
	if (test_quota())
		return 1;
	if (test_bureaucrat())
		return 1;

	if (test_filefinal())
		return 1;
	
	if (test_remote("log"))
		return 1;
	
	if (test_remote("ask"))
		return 1;

	printf("[demo] OK. passed all tests\n");
	return 0;
}

