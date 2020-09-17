/** NexusOS: Fat32 interface selftest */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <nexus/fs.h>
#include <nexus/test.h>
#include <nexus/nexuscalls.h>
#include <nexus/FatFS.interface.h>

#define FATFS_TEST_PORT 5000

////////  FatFS test implementation  ////////

#define MAXNAME 128

struct inode {
	char name[MAXNAME];
	struct inode *parent;
	struct inode *child; // stupid FS: only one child
};

// this is a test: only support a single dir and file
static struct inode *root, *onlydir, *onlyfile;

static char onlyfile_contents[4];

struct inode *
__inode_create_onlydir(const char *path)
{
	struct inode *child;

	child = calloc(1, sizeof(*child));
	strcpy(child->name, path);
	
	onlydir = child;
	return child;
}

struct inode *
__inode_create_onlyfile(const char *path)
{
	struct inode *child;

	child = calloc(1, sizeof(*child));
	strcpy(child->name, path);
	
	child->parent = onlydir;
	onlydir->child = child;

	onlyfile = child;
	return child;
}

void *
fl_fopen(const char *path, const char *modifiers)
{
	struct inode *inode;

	if (strcmp(path, "dir/file")) {
		fprintf(stderr, "open %s failed\n", path);
		return NULL;
	}

	// creat()
	if (!strcmp(modifiers, "w+"))
		return __inode_create_onlyfile(path);	
		
	// open existing
	inode = onlyfile;
	if (!inode)
		fprintf(stderr, "open %s failed\n", path);

	return inode;
}

void 
fl_fclose(void *file)
{
	// noop
}

int 
fl_fflush(void *file)
{
	// noop
	return 0;
}

int 
fl_fwrite(const void * data, int size, int count, void *file)
{
	if (count != 4)
		return -1;

	memcpy(onlyfile_contents, data, 4);
	return 4;
}

int 
fl_fread(void * data, int size, int count, void *file)
{
	if (count != 4)
		return -1;

	memcpy(data, onlyfile_contents, 4);
	return 4;
}

int 
fl_fseek(void *file, long offset, int origin)
{
	return 0;
}

int
fl_truncate(void *file, int newlength)
{
	return 0;
}

int 
fl_remove(const char * filename)
{
	struct inode *inode;

	if (strcmp(filename, "dir"))
		inode = onlydir;
	else
		inode = onlyfile;

	if (inode->parent)
		inode->parent->child = NULL;
	
	free(inode);
	return 0;
}

int 
fl_createdirectory(const char *path)
{
	if (__inode_create_onlydir(path))
		return 1;
	else
		return 0;
}

unsigned long 
fl_opendirectory(const char *filepath)
{
	return (unsigned long) onlydir;
}

int 
fl_getdirectory_n(const char *filepath, unsigned long offset, char *name)
{
	struct inode *inode;

	inode = onlydir;
	if (!inode)
		return 0;

	if (offset > 0 /* max 1 child */ || !inode->child)
		return 0;

	strcpy(name, inode->child->name);
	return 1;
}

int
fl_isdirectory(const char *parentpath, const char *filename)
{
	/* just one file */
	return 0;
}

unsigned long
fl_fcluster(void *file)
{
	return (unsigned long) file;
}

unsigned long
fl_fsize(void *file)
{
	return 10;
}

int 
fl_getpartitionsize(void)
{
	return 1 << 20;
}

static int
do_server(void)
{
	int i;

	FatFS_Init(FATFS_TEST_PORT, 0);

	// NB: handle exactly the number of requests issued by the client
	for (i = 0; i < 11; i++)
		FatFS_processNextCommand();

	FatFS_Exit();
	return 0;
}


////////  test client  ////////

static int
do_client(void)
{
	char name[8], out[4];
	FSID dir, file, file2;
	int i;

	// mount as root
	if (nexusfs_mount(FSID_EMPTY, FSID_ROOT(FATFS_TEST_PORT)))
		ReturnError(1, "mount()\n");
	
	// create dir
	dir = FS_Create(FSID_ROOT(FATFS_TEST_PORT), (struct VarLen) { .data = "dir", .len = 3}, FS_NODE_DIR);
	if (!FSID_isValid(dir))
		ReturnError(1, "mkdir()\n");

	// create file
	file = FS_Create(dir, (struct VarLen) { .data = "file", .len = 4}, FS_NODE_FILE);
	if (!FSID_isValid(file))
		ReturnError(1, "file()\n");

	// access dir and file 
	i = 0;
	while (FS_ReadDir(dir, (struct VarLen) { .data = name, .len = 8}, i)) { i++; }
	if (i != 1)
		ReturnError(1, "readdir()\n");

	if (FS_Write(file, 0, (struct VarLen) { .data = "aaaa", .len = 4}, 4) != 4)
		ReturnError(1, "write()\n");
	
	if (FS_Read(file, 0, (struct VarLen) { .data = out, .len = 4}, 4) != 4)
		ReturnError(1, "read()\n");
	
	if (memcmp(out, "aaaa", 4)) 
		ReturnError(1, "data corruption\n");

	if (FS_Size(file) != 10 /* hardcoded value above */ )
		ReturnError(1, "size()\n");

	// try a second file handle

	file2 = FS_Lookup(dir, (struct VarLen) { .data = "file", .len = 4}, 0);
	if (!FSID_equal(file, file2))
		ReturnError(1, "lookup()\n");

	if (FS_Read(file2, 0, (struct VarLen) { .data = out, .len = 4}, 4) != 4)
		ReturnError(1, "read()\n");
	
	if (memcmp(out, "aaaa", 4)) 
		ReturnError(1, "data corruption\n");

	// revert state

	if (FS_Unlink(dir, file))
		ReturnError(1, "rm()\n");

	if (FS_Unlink(FSID_EMPTY, dir))
		ReturnError(1, "rmdir()\n");

	return 0;
}

static void
start_client(const char *execpath)
{
	char *argv[3];

	argv[0] = (char *) execpath;
	argv[1] = "--client";
	argv[2] = NULL;

	nxcall_exec_ex(execpath, argv, NULL, 0);
}

////////  shared backed  ////////

int
main(int argc, char **argv)
{
	
	test_skip_auto();
	
	if (argc == 2 && !strcmp(argv[1], "--client"))
		return do_client();
	
	start_client(argv[0]);	
	return do_server();
}

