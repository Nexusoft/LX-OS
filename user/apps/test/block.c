/** NexusOS: test blockdevice interface */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <nexus/block.h>
#include <nexus/nexuscalls.h>
// how often to run read/write test. set high for stresstesting
#define REPEAT	100

/// fake block device stores exactly 2 sectors
char buffer[1024];

static int
fake_read(unsigned long addr, unsigned long off, unsigned long len)
{
	if (!addr || off > 1 || len != 1) {
		fprintf(stderr, "read failed\n");
		return -1;
	}

	memcpy((void *) addr, buffer + (512 * off), 512);
	return 0;
}

static int 
fake_write(unsigned long addr, unsigned long off, unsigned long len)
{
	int i;

	if (!addr || off > 1 || len != 1) {
		fprintf(stderr, "write failed\n");
		return -1;
	}

	for (i = 0; i < 512; i++) {
		if (((char *) addr)[i] != 'a') {
			fprintf(stderr, "data corruption (server)\n");
			return -1;
		}
	}

	memcpy(buffer + (512 * off), (void *) addr, 512);
	return 0;
}

static struct nxblock_device_ops fake_ops ={
	.read = fake_read,
	.write = fake_write,
};

int
do_server(void)
{
	int fd, repeat;

	fd = nxblock_server_register("fake0");
	if (fd < 0) {
		fprintf(stderr, "register failed\n");
		return 1;
	}

	for (repeat = 0; repeat < REPEAT; repeat++) {
		// listen for exactly two requests: one write, one read
		if (nxblock_server_serve(fd, &fake_ops) ||
		    nxblock_server_serve(fd, &fake_ops)) {
			fprintf(stderr, "serve failed\n");
			return 1;
		}
	}

	nxblock_server_unregister(fd);
	printf("[server] OK\n");
	return 0;
}

int
do_client(void)
{
	char source[512];
	char dest[512];
	int fd, repeat;

	// open device file
	fd = nxblock_client_open("/dev/fake0");
	if (fd < 0) {
		fprintf(stderr, "could not open device file\n");
		return 1;
	}

	// prepare data
	memset(source, 'a', 512);
	
	for (repeat = 0; repeat < REPEAT; repeat++) {
		memset(dest, 'b', 512);

		// write to device
		if (nxblock_client_write(fd, source, 1, 1) != 1) {
			fprintf(stderr, "write failed\n");
			return 1;
		}

		// read from device
		if (nxblock_client_read(fd, dest, 1, 1) != 1) {
			fprintf(stderr, "read failed\n");
			return 1;
		}

		// verify data
		if (memcmp(source, dest, 512)) {
			fprintf(stderr, "data corruption\n");
			return 1;
		}
	}

	// close device
	if (nxblock_client_close(fd)) {
		fprintf(stderr, "close device file failed\n");
		return 1;
	}

	printf("[client] OK\n");
	return 0;
}

int
main(int argc, char **argv)
{
	// special case: server subprocess
	if (argc == 2 && !strcmp(argv[1], "--server"))
		return do_server();

	// skip autorun at boot
	if (argc == 2 && !strcmp(argv[1], "auto"))
		return 0;

	if (argc != 1) {
		fprintf(stderr, "Usage: %s\n", argv[0]);
		return 1;
	}

	argv[1] = "--server";
	argv[2] = NULL;
	nxcall_exec_ex(argv[0], argv, NULL, 0);
	sleep(1); // ugly, but effective

	return do_client();
}

