/** NexusOS: FAT32 file server */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <fcntl.h>
#include <sys/mount.h>

#include <nexus/test.h>
#include <nexus/block.h>
#include <nexus/kshmem.h>
#include <nexus/rdtsc.h>
#include <nexus/fs_path.h>
#include <nexus/fs.h>
#include <nexus/ipc.h>
#include <nexus/guard.h>
#include <nexus/FatFS.interface.h>
#include <nexus/Resource_Disk.interface.h>

#include "fat_filelib.h"

#define IDE_DEVICE "/dev/block0"

#define MOUNTPOINT      	"/usr"
#define ROOTDIR			"/"
#define TESTDIR			"/test"
#define TESTFILE 		"/file.log"
#define TESTDIR2		"/test2"
#define TESTFILE1      		"/test1.txt"
#define TESTFILE2       	"/test2.txt"

static int media_fd = -1;

static int 
nxdev_init(void)
{
	media_fd = nxblock_client_open(IDE_DEVICE);
	return media_fd; 
}

static int read_cnt, write_cnt;

static int 
nxdev_read(unsigned long sector, unsigned long len, unsigned char *buffer)
{
	int ret = nxblock_client_read(media_fd, (void *)buffer, len, sector);
	read_cnt += ret;
    	return ret * FAT_SECTOR_SIZE;
}

static int 
nxdev_write(unsigned long sector, unsigned long len, unsigned char *buffer)
{
	int ret = nxblock_client_write(media_fd, (void *)buffer, len, sector);
	write_cnt += ret;
	return ret * FAT_SECTOR_SIZE;
}

static int file_wr_eval(int do_seq)
{
	FL_FILE *file1, *file2;
	int i;
	unsigned long count = 0, throughput;
	int result;
	uint64_t tend;

	// Create directory
	if (do_seq && fl_createdirectory(TESTDIR) <= 0) 
		ReturnError(1, "[test] create directory failed\n");

	// Create File
	file1 = fl_fopen(TESTDIR TESTFILE1, "a+");
	if (!file1)
        	ReturnError(1, "[test] create file failed\n");
	file2 = fl_fopen(TESTDIR TESTFILE2, "a+");
	if (!file2)
		ReturnError(1, "[test] create file failed\n");

	unsigned char data[FAT_SECTOR_SIZE];
	memset(data, 97, FAT_SECTOR_SIZE);

	tend = rdtsc64() + (NXCLOCK_RATE /10);	// wait for 100ms
	while (rdtsc64() < tend) {
		if (do_seq || count % 2) {
			if (fl_fwrite(data, 1, sizeof(data), file1) != sizeof(data)) {
				fl_fclose(file1);
				fl_remove(TESTDIR TESTFILE1);
				ReturnError(1, "[test] error at write -- 1\n");
            		}
			fl_fflush(file1);
		} else {
			if (fl_fwrite(data, 1, sizeof(data), file2) != sizeof(data)) {
				fl_fclose(file2);
				fl_remove(TESTDIR TESTFILE2);
				ReturnError(1, "[test] error at write -- 2\n");
			}
			fl_fflush(file2);
		}
		count++;
	}

	//printf("Total number of sectors written in WRITE %lu\n", count);
	// Calculate throughput per sec
	throughput = ((count*10*FAT_SECTOR_SIZE) / (1024)); 
	printf("\nHD IO Throughput for FS %s WRITEs is [%lu] KB/sec\n", (do_seq ? "Seq" : "Random"), throughput);
	fl_fclose(file1);
	fl_fclose(file2);

	return 0;
}

static int file_rd_eval(int do_seq)
{
	FL_FILE *file1, *file2;
	int i;
	unsigned long count = 0, throughput;
	int result;
	uint64_t tend;

	// Open Files for reading only
	file1 = fl_fopen(TESTDIR TESTFILE1, "r");
	if (!file1)
		ReturnError(1, "[test] create file failed\n");
	file2 = fl_fopen(TESTDIR TESTFILE2, "r");
	if (!file2)
		ReturnError(1, "[test] create file failed\n");
    
	// Repositioning their seek heads is necessary for testing
	file1->bytenum = 0;
	file2->bytenum = 0;
	unsigned char data[FAT_SECTOR_SIZE];
	memset(data, 0, FAT_SECTOR_SIZE);

	tend = rdtsc64() + (NXCLOCK_RATE /10);	// wait for 100ms

	while (rdtsc64() < tend) {
		if (do_seq || count % 2) {
			if (fl_fread(data, 1, sizeof(data), file1) != sizeof(data)) {
				fl_fclose(file1);
				fl_remove(TESTDIR TESTFILE1);
				ReturnError(1, "[test] error at read -- 1\n");
			}
		} else {
			if (fl_fread(data, 1, sizeof(data), file2) != sizeof(data)) {
				fl_fclose(file2);
				fl_remove(TESTDIR TESTFILE2);
				ReturnError(1, "[test] error at read -- 2\n");
			}
        	}
        	// Again, do not let it reach EOF ; its safe to take precaution here
        	// (although this safety mechanism must have been there in FS code )
		if (file1->bytenum + FAT_SECTOR_SIZE >= file1->filelength)
			file1->bytenum = 0;
		if (file2->bytenum + FAT_SECTOR_SIZE >= file2->filelength)
			file2->bytenum = 0;
		count++;
	}
	//printf("Total number of sectors written in READ %lu\n", count);
	// Calculate throughput per sec
	throughput = ((count*10*FAT_SECTOR_SIZE) / (1024)); 
	printf("\nHD IO Throughput for FS %s READs is [%lu] KB/sec\n", do_seq ? "Seq" : "Random", throughput);
	fl_fclose(file1);
	fl_fclose(file2);

	if (!do_seq) {
		fl_remove(TESTDIR TESTFILE1);
		fl_remove(TESTDIR TESTFILE2);
		fl_remove(TESTDIR);
	}

	return 0;
}

// Stress test for File System and Block IO
static int
nxfat32_testeval(void)
{
	if (file_wr_eval(1) || file_wr_eval(0))
		return 1;
	if (file_rd_eval(1) || file_rd_eval(0))
		return 1;

	return 0;
}

static int
nxfat32_selftest(void)
{
	FL_FILE *file;
	int i;

	unsigned char data[FAT_SECTOR_SIZE];
	memset(data, 2, FAT_SECTOR_SIZE);

	unsigned char read_data[FAT_SECTOR_SIZE];
	memset(read_data, 0, FAT_SECTOR_SIZE);

	printf("Listing Root directory... \n");
	fl_listdirectory(ROOTDIR);

	printf("\nCreating Sub directory... %s\n", TESTDIR);
	if (fl_createdirectory(TESTDIR) <= 0) 
	{
		printf("ERROR : Create directory %s failed\n", TESTDIR);
		return 1;
	}

	printf("\nCreating Sub directory... %s\n", TESTDIR2);
	if (fl_createdirectory(TESTDIR2) <= 0) 
	{
		printf("ERROR : Create directory %s failed\n", TESTDIR2);
		return 1;
	}
	printf("\nListing Root directory... \n");
	fl_listdirectory(ROOTDIR);

	// Create File
	file = fl_fopen(TESTDIR TESTFILE, "a+");
	if (file <= 0)
	{
		printf("Open Error\n");
		ReturnError(1, "[test] create file failed\n");
	}

	// Write some data
	if (fl_fwrite(data, 1, sizeof(data), file) != sizeof(data)) {
		fl_fclose(file);
		fl_remove(TESTDIR TESTFILE);
		printf("READ count, WRITE count = <%d, %d>\n", read_cnt, write_cnt);
		ReturnError(1, "[test] error at write\n");
	}
	fl_fflush(file);

	// Repositioning its seek head is necessary for testing
	file->bytenum = 0;
	// Read back the written data
	if (fl_fread(read_data, 1, sizeof(read_data), file) != sizeof(read_data)) {
		fl_fclose(file);
		fl_remove(TESTDIR TESTFILE);
		printf("READ count, WRITE count = <%d, %d>\n", read_cnt, write_cnt);
		ReturnError(1, "[test] error at read\n");
	} 

	// Verify correctness
	if (memcmp(read_data, data, sizeof(read_data))) {
		fl_fclose(file);
		fl_remove(TESTDIR TESTFILE);
		ReturnError(1, "[test] data mismatch error\n");
	} else
		printf("Data integrity of File %s Verified\n", file->filename);

	printf("\nListing Sub directory... %s\n", TESTDIR);
	fl_listdirectory(TESTDIR);

	// Cleanup
	fl_fclose(file);
	if (fl_remove(TESTDIR TESTFILE) < 0)
		printf("ERROR: Delete file failed\n");

	if (fl_remove(TESTDIR) < 0)
		printf("ERROR: Delete directory failed\n");

	if (fl_remove(TESTDIR2) < 0)
		printf("ERROR: Delete directory failed\n");

	// List root directory
	printf("\nListing root directory... \n");
	fl_listdirectory(ROOTDIR);
	return 0;
}

static int 
do_testmode(void)
{
	int ret;
	printf("Nexus Fat32 fileserver SELFTEST\n");
	
	if (nxfat32_selftest())
		return 1;
	if (nxfat32_testeval())
		return 1;

	return 0;
}

static void *
start_quota(void *arg)
{
	Resource_Disk_Init(fl_getpartitionsize());

	while (1)
		Resource_Disk_processNextCommand();

	// no destroy
	return NULL;
}

static int
do_servermode(int do_quota)
{
	char portstring[12];
	pthread_t thread;

	if (do_quota) {
		if (pthread_create(&thread, NULL, start_quota, NULL))
			ReturnError(1, "[fat32] Aborting: quota thread FAILED\n");

		printf("[fat32] quota system enabled\n");
	}
	else
		printf("[fat32] quota system disabled, use --quota to enable\n");

	FatFS_Init(FATFS_PORT, do_quota);

	snprintf(portstring, 11, "%d", FATFS_PORT);
	if (mount(portstring, MOUNTPOINT, "fatfs", 0, NULL))
		ReturnError(1, "[fat32] Aborting: mount FAILED\n");

	printf("[fat32] mounted at %s\n", MOUNTPOINT);
	while (1)
		FatFS_processNextCommand();
	
	FatFS_Exit();
	if (do_quota)
		pthread_join(thread, NULL);
	return 0;
}

int main(int argc, char **argv)
{
	int ret = 0;
	int do_quota = 0;
	// Open nexus device
	if (nxdev_init() == -1)
		ReturnError(1, "[fat32] media open failed\n");
	
	if (fl_attach_media(nxdev_read, nxdev_write) != FAT_INIT_OK)
		ReturnError(1, "[fat32] media attach failed\n");

	// run selftest
	if ((argc >= 2 && !strcmp(argv[1], "--test")) ||
	    (argc >= 3 && !strcmp(argv[2], "--test")))
		ret = do_testmode(); 
	if ((argc >= 2 && !strcmp(argv[1], "--quota")) ||
	    (argc >= 3 && !strcmp(argv[2], "--quota")))
	    	do_quota = 1;

	if (!ret)
		ret = do_servermode(do_quota);

	// cleanup
	fl_shutdown();
	return ret;
}
