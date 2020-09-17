/** NexusOS: posix-layer benchmarking */

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#include <sys/stat.h>
#include <sys/types.h>

#include <nexus/test.h>
#include <nexus/profiler.h>

#define IOPREFIX	"[bench posix] "
#define NUMRUNS		1001

#define DO_PROCFS
#ifdef DO_PROCFS
#define FILEPATH	"/proc/os/sys/meminfo"
#else
#define FILEPATH	"/posixbench.remove"
#endif

struct nxmedian_data *opendata, *readdata, *writedata, *closedata;

/** wake up the CPU from low power mode */
static int
warm_up(void)
{
	uint64_t tend;

	printf(IOPREFIX "warming up..\n");
	tend = rdtsc64() + nxprofile_cpurate();
	while (rdtsc64() < tend) {};

	return 0;
}

/** test open and optionally open/read/write/close 
 
    @param readwrite: 	whether to read and write
    @param blocksize:	number of bytes per read or write. 
    			must be 0 if not reading or writing */
static int 
bench_fileio(int readwrite, int blocksize)
{
	char *buffer = NULL;
	int i, fd, ret;

	nxmedian_reset(opendata);
	nxmedian_reset(readdata);
	nxmedian_reset(writedata);
	nxmedian_reset(closedata);

	// create file for testing
#ifndef DO_PROCFS
	fd = open(FILEPATH, O_CREAT | O_WRONLY, 0644);
	if (fd < 0) {
		perror("open");
		fprintf(stderr, IOPREFIX "create at %d\n", __LINE__);
		return 1;
	}
	if (close(fd)) {
		fprintf(stderr, IOPREFIX "close #1\n");
		goto cleanup;
	}
#endif

	// open buffer, if reading and/or writing
	if (readwrite)
		buffer = malloc(blocksize);

	for (i = 0; i < NUMRUNS; i++) {

		// time open
		nxmedian_begin(opendata);
		fd = open(FILEPATH, O_RDWR);
		nxmedian_end(opendata);
		
		// do not time error handling
		if (fd < 0) {
			fprintf(stderr, IOPREFIX "open\n");
			goto cleanup;
		}

		if (readwrite) {
			// do not include ramfs reallocation overhead
			lseek(fd, 0, SEEK_SET);

#ifndef DO_PROCFS
			// time write
			nxmedian_begin(writedata);
			ret = write(fd, buffer, blocksize);
			nxmedian_end(writedata);

			if (ret != blocksize) {
				fprintf(stderr, IOPREFIX "write\n");
				close(fd);
				goto cleanup;
			}
			if (lseek(fd, SEEK_SET, 0)) {
				fprintf(stderr, IOPREFIX "lseek #1\n");
				close(fd);
				goto cleanup;
			}
#endif

			// time read
			nxmedian_begin(readdata);
			ret = read(fd, buffer, blocksize);
			nxmedian_end(readdata);

			if (ret != blocksize) {
				fprintf(stderr, IOPREFIX "read\n");
				close(fd);
				goto cleanup;
			}
			if (lseek(fd, SEEK_SET, 0)) {
				fprintf(stderr, IOPREFIX "lseek #2\n");
				close(fd);
				goto cleanup;
			}
		}

		// time close
		nxmedian_begin(closedata);
		ret = close(fd);
		nxmedian_end(closedata);

		if (ret) {
			fprintf(stderr, IOPREFIX "close #2\n");
			goto cleanup;
		}
	}

	// prettyprint
	nxmedian_show("open  ", opendata);
	nxmedian_write("/tmp/posix_open.data", blocksize, opendata);
	if (readwrite) {
		nxmedian_show("read  ", readdata);
#ifndef DO_PROCFS
		nxmedian_show("write ", writedata);
#endif
		nxmedian_write("/tmp/posix_read.data", blocksize, readdata);
		nxmedian_write("/tmp/posix_write.data", blocksize, writedata);
	}
	nxmedian_show("close ", closedata);
	nxmedian_write("/tmp/posix_close.data", blocksize, closedata);
	
	// cleanup
	if (buffer)
		free(buffer);
#ifndef DO_PROCSFS
	unlink(FILEPATH);
#endif
	return 0;

cleanup:
	if (buffer)
		free(buffer);
#ifndef DO_PROCSFS
	unlink(FILEPATH);
#endif
	return 1;
}

	
int
main(int argc, char **argv)
{
	int i;

	printf("Nexus posix benchmarks\n");
#ifndef __NEXUS__
	printf("NB: for fair comparison to RamFS, make sure to run tmpfs\n");
#endif
#ifdef DO_PROCSFS
	printf("    testing ProcFS\n");
#else
	printf("    testing RamFS\n");
#endif

	opendata = nxmedian_alloc(NUMRUNS);
	readdata = nxmedian_alloc(NUMRUNS);
	writedata = nxmedian_alloc(NUMRUNS);
	closedata = nxmedian_alloc(NUMRUNS);

	if (warm_up())
		return 1;

	printf("[test] null:  ");
	if (bench_fileio(0, 0))
		return 1;

#ifdef DO_PROCFS
	for (i = 0; i <= 4; i = i+4) {
#else
	for (i = 0; i <= 24; i = i+4) {
#endif
		printf("[test] 2^%dB:\n", i);
		if (bench_fileio(1, 1 << i))
			return 1;
	}

	nxmedian_free(closedata);
	nxmedian_free(writedata);
	nxmedian_free(readdata);
	nxmedian_free(opendata);

	printf(IOPREFIX "OK. finished all tests\n");
	return 0;
}

