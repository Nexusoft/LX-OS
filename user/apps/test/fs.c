/** NexusOS: filesystem interface (FS.svc) regression test 
 
    It tests all calls in the FS interface against two 
    filesystems: a local RamFS and the kernel filesystem.
 */

#include <stdlib.h>
#include <stdio.h>

#include <nexus/fs.h>
#include <nexus/ipc.h>
#include <nexus/FS.interface.h>
#include <nexus/RamFS.interface.h>

// for posix IO tests
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

#define ReturnError(stmt) 						\
	do { fprintf(stderr, "Error in %s at %d\n", stmt, __LINE__); 	\
	     return -1;							\
	} while(0)

/** Perform standard actions on a filesystem 
 
    @return 0 on success, -1 on failure */
static int 
fs_test(FSID root)
{
	char buf[20], buf2[] = "Cruel World";
	FSID dir, file;
	int ret;

	// mount 
	if (nexusfs_mount(FSID_EMPTY, root))
		ReturnError("mount");

	// mkdir and creat. guard against overwriting
	dir = nexusfs_mkdir(root, "testdir");
	if (!FSID_isDir(dir))
		ReturnError("mkdir");

	file = nexusfs_mk(root, "testdir", "1");
	if (FSID_isFile(file))
		ReturnError("mk: overwriting dir");

	file = nexusfs_mk(dir, "testfile", "Hello World");
	if (!FSID_isFile(file))
		ReturnError("mk");

	file = nexusfs_mk(dir, "testfile", "1");
	if (FSID_isFile(file))
		ReturnError("mk: overwriting file");

	// lookup
	dir = nexusfs_lookup(root, "testdir");
	if (!FSID_isDir(dir))
		ReturnError("lookup");

	file = nexusfs_lookup(dir, "testfile");
	if (!FSID_isFile(file))
		ReturnError("lookup");

	// read, overwrite, append
	ret = FS_Read(file, 0, (struct VarLen) {.data = buf, .len = 20}, 20);
	if (ret != 12)
		ReturnError("read");
	
	ret = FS_Write(file, 0, (struct VarLen) {.data = buf, .len = ret}, ret);
	if (ret != 12)
		ReturnError("write over");

	ret = FS_Write(file, 6, (struct VarLen) {.data = buf2, .len = 11}, 11);
	if (ret != 11)
		ReturnError("write append");

	// file ops
	if (FS_Size(file) != 17)
		ReturnError("size");

	if (FS_Truncate(file, 0))
		ReturnError("truncate");

	if (FS_Size(file))
		ReturnError("size");

	if (FS_Pin(file))
		ReturnError("pin");
	
	if (FS_Unpin(file))
		ReturnError("unpin");

	if (FS_Sync(file))
		ReturnError("sync");

	// test mount (recursive mount if kernel fs)
	if (nexusfs_mount(dir, FSID_ROOT(KERNELFS_PORT)))
		ReturnError("mount #2");

	if (nexusfs_unmount(dir, FSID_ROOT(KERNELFS_PORT)))
		ReturnError("unmount #2");

	// dir ops
	if (FS_ReadDir(dir, (struct VarLen) {.data = buf, .len = 20}, 0) != 0)
		ReturnError("readdir");
	
	if (strcmp(buf, "testfile"))
		ReturnError("readdir data");

	// unlink
	if (nexusfs_unlink(dir, "testfile"))
		ReturnError("rm");

	if (nexusfs_unlink(root, "testdir"))
		ReturnError("rmdir");

	if (nexusfs_unmount(FSID_EMPTY, root))
		ReturnError("unmount");

	return 0;
}

int posixio_test(FSID root)
{
	struct stat _stat;
	char buf[20], in[] = "hello world", append[] = "cruel world";
	int fd;


	if (nexusfs_mount(FSID_EMPTY, root))
		ReturnError("mount");

	// open, write, close, read
	fd = open("testposix", O_CREAT | O_RDWR, 0600);
	if (fd < 0)
		ReturnError("posix: open");

	if (write(fd, in, 12) != 12)
		ReturnError("posix: write");

	if (close(fd))
		ReturnError("posix: close");

	// note that passing doesn't mean that stat works 100%.
	if (stat("testposix", &_stat))
		ReturnError("posix: stat");

	fd = open("testposix", O_CREAT | O_RDWR, 0600);
	if (fd < 0)
		ReturnError("posix: open");

	// note that passing doesn't mean that stat works 100%.
	if (fstat(fd, &_stat))
		ReturnError("posix: fstat");

	if (read(fd, buf, 20) != 12)
		ReturnError("posix: read");

	if (strcmp(in, buf))
		ReturnError("posix: data corruption");

	// seek, write, read
	if (lseek(fd, 6, SEEK_SET) != 6)
		ReturnError("posix: seek");

	if (write(fd, append, 11) != 11)
		ReturnError("posix: write #2");

	if (lseek(fd, -17, SEEK_END) != 0)
		ReturnError("posix: seek #2");

	if (read(fd, buf, 20) != 17)
		ReturnError("posix: read #2");

	if (memcmp(buf, "hello cruel world", 17))
		ReturnError("posix: data corruption #2");

	// cleanup
	if (close(fd))
		ReturnError("posix: close");

	if (unlink("testposix"))
		ReturnError("unlink");

	if (nexusfs_unmount(FSID_EMPTY, root))
		ReturnError("unmount");

	return 0;
}

int 
main(int argc, char **argv)
{
	Port_Num root_port;
	FSID root;
	double a, b;

	// test against local FS server
	root_port = ipc_server_run("RamFS");
	if (root_port < 0) {
		fprintf(stderr, "Failed to create local FS\n");
		return 1;
	}

	if (fs_test(FSID_ROOT(root_port)))
		return 1;

	if (posixio_test(FSID_ROOT(root_port)))
		return 1;

	// XXX no way to shut down an FS

	// test against kernel FS
	if (fs_test(FSID_ROOT(KERNELFS_PORT)))
		return 1;

	// start a RamFS under /mnt

	printf("[%s] OK.\n", argv[0]);
	return 0;
}

