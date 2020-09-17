/** NexusOS: filesystem interface (FS.svc) regression test 
 
    It tests all calls in the FS interface against two 
    filesystems: a local RamFS and the kernel filesystem.
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include <nexus/fs.h>
#include <nexus/ipc.h>
#include <nexus/test.h>
#include <nexus/FS.interface.h>
#include <nexus/RamFS.interface.h>
#include <nexus/Debug.interface.h>
#include <nexus/Thread.interface.h>

// for posix IO tests
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mman.h>

// for stresstest
#include <pthread.h>

/** Perform standard actions on a filesystem 
    @return 0 on success, -1 on failure */
static int 
fs_test(FSID root)
{
	char buf[20], buf2[] = "Cruel World";
	FSID dir, file, file2;
	int ret;

	// mkdir and creat. guard against overwriting
	dir = nexusfs_mkdir(root, "testdir");
	if (!FSID_isDir(dir))
		ReturnError(-1, "mkdir");

	file = nexusfs_mk(root, "testdir", "1");
	if (FSID_isFile(file))
		ReturnError(-1, "mk: overwritten dir");

	file = nexusfs_mk(dir, "testfile", "Hello World");
	if (!FSID_isFile(file))
		ReturnError(-1, "mk");

	file2 = nexusfs_mk(dir, "testfile", "1");
	if (FSID_isFile(file2))
		ReturnError(-1, "mk: overwriting file");

	if (nexusfs_rename(file, root, "othername"))
		ReturnError(-1, "rename: cross dir");

	// lookup
	dir = nexusfs_lookup(root, "testdir");
	if (!FSID_isDir(dir))
		ReturnError(-1, "lookup");

	file = nexusfs_lookup(dir, "testfile");
	if (FSID_isFile(file))
		ReturnError(-1, "lookup");

	file = nexusfs_lookup(root, "othername");
	if (!FSID_isFile(file))
		ReturnError(-1, "lookup");

	// read, overwrite, append
	ret = FS_Read(file, 0, (struct VarLen) {.data = buf, .len = 20}, 20);
	if (ret != 12)
		ReturnError(-1, "read");
	
	ret = FS_Write(file, 0, (struct VarLen) {.data = buf, .len = ret}, ret);
	if (ret != 12)
		ReturnError(-1, "write over");

	ret = FS_Write(file, 6, (struct VarLen) {.data = buf2, .len = 11}, 11);
	if (ret != 11)
		ReturnError(-1, "write append");

	// file ops
	if (FS_Size(file) != 17)
		ReturnError(-1, "size");

	if (FS_Truncate(file, 0))
		ReturnError(-1, "truncate");

	if (FS_Size(file))
		ReturnError(-1, "size");

	if (FS_Pin(file))
		ReturnError(-1, "pin");
	
	if (FS_Unpin(file, 0))
		ReturnError(-1, "unpin");

	if (FS_Sync(file))
		ReturnError(-1, "sync");

	// test (recursive) mount
	if (nexusfs_mount(dir, root))
		ReturnError(-1, "mount #2");

	if (nexusfs_unmount(dir, root))
		ReturnError(-1, "unmount #2");

	// dir ops
	if (FS_ReadDir(dir, (struct VarLen) {.data = buf, .len = 20}, 0) != -1)
		ReturnError(-1, "readdir");
      
	if (FS_ReadDir(root, (struct VarLen) {.data = buf, .len = 20}, 0) != 1)
		ReturnError(-1, "readdir");
	
	// unlink
	if (nexusfs_unlink(root, "othername"))
		ReturnError(-1, "rm");

	if (nexusfs_unlink(root, "testdir"))
		ReturnError(-1, "rmdir");

	return 0;
}

static int 
posixio_test(void)
{
	struct stat _stat;
	FILE *file;
	char buf[20], in[] = "hello world", append[] = "cruel world";
	int fd;

	// open, write, close, read
	fd = open("testposix-pre", O_CREAT | O_RDWR, 0600);
	if (fd < 0)
		ReturnError(-1, "posix: open");

	file = fdopen(fd, "w+");
	if (!file)
		ReturnError(-1, "posix: fdopen");

	if (write(fd, in, 12) != 12)
		ReturnError(-1, "posix: write");

	if (close(fd))
		ReturnError(-1, "posix: close");

	// rename
	if (rename("testposix-pre", "testposix"))
		ReturnError(-1, "rename");

	// note that passing doesn't mean that stat works 100%.
	if (stat("testposix", &_stat))
		ReturnError(-1, "posix: stat");

	if (_stat.st_size != 12)
		ReturnError(-1, "posix: stat size");

	fd = open("testposix", O_CREAT | O_RDWR, 0600);
	if (fd < 0)
		ReturnError(-1, "posix: open");

	// note that passing doesn't mean that stat works 100%.
	if (fstat(fd, &_stat))
		ReturnError(-1, "posix: fstat");

	if (read(fd, buf, 20) != 12)
		ReturnError(-1, "posix: read");

	if (strcmp(in, buf))
		ReturnError(-1, "posix: data corruption");

	// seek, write, read
	if (lseek(fd, 6, SEEK_SET) != 6)
		ReturnError(-1, "posix: seek");

	if (write(fd, append, 11) != 11)
		ReturnError(-1, "posix: write #2");

	if (lseek(fd, -17, SEEK_END) != 0)
		ReturnError(-1, "posix: seek #2");

	if (read(fd, buf, 20) != 17)
		ReturnError(-1, "posix: read #2");

	if (memcmp(buf, "hello cruel world", 17))
		ReturnError(-1, "posix: data corruption #2");

	if (close(fd))
		ReturnError(-1, "posix: close");

	// test append
	fd = open("testposix", O_APPEND | O_WRONLY);
	if (fd < 0)
		ReturnError(-1, "posix: open O_APPEND");

	if (write(fd, "ha", 2) != 2)
		ReturnError(-1, "posix: write @ append");

	if (stat("testposix", &_stat))
		ReturnError(-1, "posix: stat @ append");

	if (_stat.st_size != 19)
		ReturnError(-1, "posix: stat size @ append");

	// cleanup
	if (unlink("testposix"))
		ReturnError(-1, "unlink");

	return 0;
}

static int
fstream_test(void)
{
	FILE *file;

	file = fopen("fstream.test", "w");
	if (!file)
		ReturnError(-1, "fopen");

	if (fwrite("bla", 1, 4, file) != 4)
		ReturnError(-1, "fwrite");

	if (ftell(file) != 4)
		ReturnError(-1, "ftell");

	if (fflush(file))
		ReturnError(-1, "fflush");

	if (fclose(file))
		ReturnError(-1, "fclose");

	if (unlink("fstream.test"))
		ReturnError(-1, "unlink");

	return 0;
}

static int
posixio_urandom_test(void)
{
	int fd;
	char brandom[256];

	fd = open("/dev/urandom", O_RDONLY);
	if (fd < 0)
		ReturnError(-1, "urandom open");

	if (read(fd, brandom, sizeof(brandom)) != sizeof(brandom))
		ReturnError(-1, "urandom read");

	if (close(fd))
		ReturnError(-1, "urandom close");

	return 0;
}

static int
posixio_pipes_test(void)
{
	char buf[100];
	int fds[2];

	if (pipe(fds))
		ReturnError(-1, "pipe()");

	if (write(fds[1], "hello", 6) != 6)
		ReturnError(-1, "pipe write()\n");
	
	if (read(fds[0], buf, 100) != 6)
		ReturnError(-1, "pipe read()\n");

	if (strcmp(buf, "hello"))
		ReturnError(-1, "pipe data\n");

	if (close(fds[1]))
		ReturnError(-1, "pipe close #1\n");
	
	if (close(fds[0]))
		ReturnError(-1, "pipe close #2\n");

	return 0;
}

static int
posixio_nonblock_test(void)
{
	char filepath[] = "/tmp/testXXXXXX";
	char buf[10];
	int fds[2];

	if (pipe(fds))
		ReturnError(-1, "pipe()");

	if (fcntl(fds[1], F_SETFL, O_NONBLOCK))
		ReturnError(-1, "fcntl()");

	if (read(fds[0], buf, 10) != -1) 
		ReturnError(-1, "read()");
	
	if (errno != EAGAIN)
		ReturnError(-1, "read errno()");

	if (write(fds[1], "hello", 6) != 6)
		ReturnError(-1, "write()");

	if (read(fds[0], buf, 10) != 6)
		ReturnError(-1, "read() #2");

	if (strcmp(buf, "hello"))
		ReturnError(-1, "nonblock data");

	if (close(fds[0]))
		ReturnError(-1, "close() r");

	if (close(fds[1]))
		ReturnError(-1, "close() w");

	return 0;
}

/** special case: test /dev/urandom special file  
    (used by lighttpd) */
static int
fstream_urandom_test(void)
{
	FILE *frandom;
	char brandom[256];

	frandom = fopen("/dev/urandom", "rb");
	if (!frandom) 
		ReturnError(-1, "urandom open");

	if (fread(brandom, sizeof(brandom), 1, frandom) != 1)
		ReturnError(-1, "urandom read");

	if (fclose(frandom))
		ReturnError(-1, "urandom close");

	return 0;
}

static int
test_mmap_file(void)
{
	void *map;
	char block[20];
	off_t off;
	int fd, ret;

	fd = open("/bin/LICENSE", O_RDONLY);
	if (fd < 0)
		ReturnError(-1, "mmapfile: open");

	ret = lseek(fd, PAGESIZE, SEEK_SET);
	if (ret != PAGESIZE)
		ReturnError(-1, "mmapfile: lseek");

	ret = read(fd, block, 20);
	if (ret != 20)
		ReturnError(-1, "mmapfile: read");
	lseek(fd, 0, SEEK_SET);

	map = mmap(0, 8000, PROT_READ, 0, fd, PAGESIZE);
	if (map == MAP_FAILED)
		ReturnError(-1, "mmapfile: map");

	if (lseek(fd, 0, SEEK_CUR) != 0)
		ReturnError(-1, "mmapfile: filepos");

	if (memcmp(block, map, 20))
		ReturnError(-1, "mmapfile: data");

	if (munmap(map, 8000))
		ReturnError(-1, "munmap");

	if (close(fd))
		ReturnError(-1, "mmapfile: close");

	return 0;
}

static int 
do_test(void)
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
	if (nexusfs_mount(FSID_EMPTY, FSID_ROOT(root_port)))
		ReturnError(-1, "mount");

	if (fs_test(FSID_ROOT(root_port)))
		return 1;

	if (posixio_test())
		return 1;

	if (fstream_test())
		return 1;

	if (nexusfs_unmount(FSID_EMPTY, FSID_ROOT(root_port)))
		ReturnError(-1, "unmount");
	
	// test against kernel FS
	if (nexusfs_mount(FSID_EMPTY, FSID_ROOT(KERNELFS_PORT)))
		ReturnError(-1, "mount");

	if (fs_test(FSID_ROOT(KERNELFS_PORT)))
		return 1;
	
	if (posixio_urandom_test())
		return 1;

	if (posixio_pipes_test())
		return 1;

	if (posixio_nonblock_test())
		return 1;

#if 0
	if (fstream_urandom_test())
		return 1;
#endif
	extern int nxlibc_enable_mmap;
	nxlibc_enable_mmap = 1;

	if (test_mmap_file())
		return 1;

	if (nexusfs_unmount(FSID_EMPTY, FSID_ROOT(KERNELFS_PORT)))
		ReturnError(-1, "unmount");

	return 0;
}

#define NUM_THREAD	10
#define NUM_SECS 	10
static Sema sema_start;
static Sema sema_done;
static int dostop;

static void *
worker_stresstest(void *unused)
{
	char buf[100];
	int fd;

	P(&sema_start);
	while (!dostop) {
		fd = open("/bin/LICENSE", O_RDONLY);
		if (fd < 0)
			ReturnError((void *) -1, "open");

		if (lseek(fd, 6, SEEK_SET) != 6)
			ReturnError((void *) -1, "seek");

		if (read(fd, buf, 100) != 100)
			ReturnError((void *) -1, "read");

		if (close(fd))
			ReturnError((void *) -1, "close");
	}

	V_nexus(&sema_done);
	return NULL;
}

/** Concurrently access the file system in read-only mode */
static int
do_stresstest(void)
{
	pthread_t t;
	int i;

	printf("FS concurrent read stresstest\n\n"
	       "  threads = %d\n"
	       "  seconds = %d\n", NUM_THREAD, NUM_SECS);
	
	for (i = 0; i < NUM_THREAD; i++)
		pthread_create(&t, NULL, worker_stresstest, NULL);
	
	for (i = 0; i < NUM_THREAD; i++)
		V_nexus(&sema_start);

	sleep(NUM_SECS);
	dostop = 1;

	for (i = 0; i < NUM_THREAD; i++)
		P(&sema_done);

	return 0;
}

int 
main(int argc, char **argv)
{
	int ret;

	if (argc == 2 && !strcmp(argv[1], "-s"))
		ret = do_stresstest();
	else
		ret = do_test();

	if (ret)
		return 1;

	if (!nxtest_isauto(argc, argv))
		printf("[%s] OK.\n", argv[0]);

	return 0;
}

