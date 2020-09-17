/** NexusOS: proc filesystem selftest */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <nexus/fs.h>
#include <nexus/test.h>
#include <nexus/hashtable.h>
#include <nexus/nexuscalls.h>

#include <nexus/FS.interface.h>
#include <nexus/ProcFS.interface.h>

////////  Client Implementation  ////////

static int
__do_client(const char *filepath)
{
	char buf[10];
	int fd;

	fd = open(filepath, O_RDONLY);
	if (fd < 0)
		ReturnError(1, "open\n");

	if (read(fd, buf, 6) != 6)
		ReturnError(1, "read\n");

	if (memcmp(buf, "hello", 6))
		ReturnError(1, "data\n");

	if (close(fd))
		ReturnError(1, "close\n");

	return 0;
}

static int
do_client(void)
{
	char filepath[64];

	// read static file
	sprintf(filepath, "/proc/%d/static/child", getpid() - 1);
	if (__do_client(filepath))
		ReturnError(1, "static child");

	// read dynamic file
	sprintf(filepath, "/proc/%d/dynamic/file.0", getpid() - 1);
	if (__do_client(filepath))
		ReturnError(1, "dynamic child");

	// read hashtable entry
	sprintf(filepath, "/proc/%d/hash/hello", getpid() - 1);
	if (__do_client(filepath))
		ReturnError(1, "hashtable child");

	return 0;
}


////////  Server: procfs callbacks  ////////


static int testfs_read(struct dnode *dnode, char *buf, int off, int len);
static struct dnode * testfs_readdir(struct dnode *parent, int n);

/** child of dynamic dir */
static struct dnode dynchild;
static struct HashTable *dyntable;

static int
testfs_read(struct dnode *dnode, char *buf, int off, int len)
{
	if (off || len < 6)
		return -1;

	memcpy(buf, "hello", 6);
	return 6;
}

/** dynamic dir readdir */
static struct dnode *
testfs_readdir(struct dnode *parent, int n)
{
	// special case: init
	if (!dynchild.name) {
		dynchild.name = strdup("file.XXXXXXXXXX");
		dynchild.file.read = testfs_read;
	}

	sprintf(dynchild.name, "file.%d", n);

	// 50% chance of having a next sibling
	if (random() & 0x1)
		dynchild.next = NULL;
	else
		dynchild.next = &dynchild;

	return &dynchild;
}


////////  Server Implementation  ////////

static int
start_client(const char *execpath)
{
	char *argv[3];

	argv[0] = (char *) execpath;
	argv[1] = "--client";
	argv[2] = NULL;

	return nxcall_exec_ex(execpath, argv, NULL, 0);
}

static int
do_server(const char *execpath)
{
	FSID procnode;
	struct dnode *dir;
	int pid, ret;

	// start server
	procnode = nxcall_fsid_byname("/proc");
	if (!FSID_isDir(procnode))
		ReturnError(1, "lookup /proc");
	if (procfs_init(procnode))
		ReturnError(1, "procfs_init()");

	srandom(0);

	// add static dir 
	dir = procfs_createdir(NULL, "static");

	// add dynamic file
	procfs_createfile(dir, "child", testfs_read, NULL);

	// add dynamic dir
	dir = procfs_createdir_ex(NULL, "dynamic", NULL, testfs_readdir, NULL);

	// add dynamic hashtable dir
	dyntable = hash_new_vlen(10, hash_strlen);	// XXX memleak
	hash_insert(dyntable, "one",   "first");
	hash_insert(dyntable, "two",   "second");
	hash_insert(dyntable, "three", "third");
	hash_insert(dyntable, "hello", "hello");
	procfs_createdir_ex(NULL, "hash", dyntable, 
			    procfs_readdir_hash_string, 
			    procfs_read_string);

	// start client
	pid = start_client(execpath);
	if (pid < 0)
		ReturnError(1, "exec()");

	// wait for client to complete
	if (waitpid(pid, &ret, 0) != pid) 
		ReturnError(1, "waitpid()");
	if (ret)
		ReturnError(1, "child failed\n");

	// cleanup
	if (procfs_exit())
		ReturnError(1, "procfs_exit()");
	
	return 0;
}

int
main(int argc, char **argv)
{
	// for some reason, autotest at boot fails at exec()
	test_skip_auto();

	if (argc == 2 && !strcmp(argv[1], "--client"))
		return do_client();

	return do_server(argv[0]);
}

