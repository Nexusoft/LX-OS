/** NexusOS: posix-layer benchmarking */

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#include <sys/stat.h>
#include <sys/types.h>

#include <nexus/defs.h>
#include <nexus/profiler.h>

#define FNAME		"[bench posix] "
#define NUMRUNS		101
#define OPENFNAME	"/tmp/posixbench.remove"

struct nxmedian_data *totaldata;

/** wake up the CPU from low power mode */
static void
warm_up(void)
{
	uint64_t tend;

	printf(FNAME "warming up..\n");
	tend = rdtsc64() + (1 << 21);

	while (rdtsc64() < tend) {};
	printf(FNAME ".. ready\n");
}

/** test open and optionally open/read/write/close 
 
    @param readwrite: 	how often to read/lseek compared to open/close
    @param blocksize:	number of bytes per read or write. 
    			must be 0 if not reading or writing */
static int 
bench_fileio(int readwrite, int blocksize)
{
	char *buffer = NULL;
	int i, j, fd, ret;

	nxmedian_reset(totaldata);

	// create file for testing
	fd = open(OPENFNAME, O_CREAT | O_WRONLY, 0644);
	if (fd < 0) {
		fprintf(stderr, FNAME "create\n");
		return 1;
	}
	// write one byte
	if (blocksize && write(fd, bench_fileio, blocksize) != blocksize) {
		fprintf(stderr, FNAME "write #1\n");
		goto cleanup;
	}
	if (close(fd)) {
		fprintf(stderr, FNAME "close #1\n");
		goto cleanup;
	}

	// open buffer, if reading and/or writing
	if (readwrite)
		buffer = malloc(blocksize);

	for (i = 0; i < 2 * NUMRUNS; i++) {

		// time open
		nxmedian_begin(totaldata);
		fd = open(OPENFNAME, O_RDWR);
		if (unlikely(fd < 0)) {
			fprintf(stderr, FNAME "open\n");
			goto cleanup;
		}

		for (j = 0; j < readwrite; j++) {
			ret = read(fd, buffer, blocksize);
			if (unlikely(ret != blocksize)) {
				fprintf(stderr, FNAME "read #1\n");
				goto cleanup;
			}
			if (unlikely(lseek(fd, SEEK_SET, 0))) {
				fprintf(stderr, FNAME "lseek #1\n");
				goto cleanup;
			}
		}

		// time close
		ret = close(fd);
		nxmedian_end(totaldata);
		if (ret) {
			fprintf(stderr, FNAME "close #2\n");
			goto cleanup;
		}

		// paranoid (XXX remove)
		if (j != readwrite) {
			printf("ERROR #2");
			exit(1);
		}	

	}

	// prettyprint
	nxmedian_show("open  ", totaldata);
	nxmedian_write("/tmp/posix_total.data", blocksize, totaldata);
	
	// cleanup
	if (buffer)
		free(buffer);
	unlink(OPENFNAME);
	return 0;

cleanup:
	printf("ERROR\n");
	if (buffer)
		free(buffer);
	unlink(OPENFNAME);
	return 1;
}

	
int
main(int argc, char **argv)
{
	int i;

	printf("Nexus posix benchmarks\n");

	totaldata = nxmedian_alloc(NUMRUNS);

	warm_up();

	printf("[test] null:  ");
	if (bench_fileio(0, 0)) 
		return 1;

	for (i = 0; i <= 20; i ++) {
#ifdef SCALE_BYTESIZE
		printf("[test] 2^%2dB: ", i);
		if (bench_fileio(1, 1 << i))
			return 1;
#else
		printf("[test] %d * read: ", i);
		if (bench_fileio(i, 1))
			return 1;
#endif
	}

	nxmedian_free(totaldata);

	printf(FNAME "OK. finished all tests\n");
	return 0;
}

