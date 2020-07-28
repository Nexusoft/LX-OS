/** NexusOS: test standard LibC functionality */

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <malloc.h>
#include <sys/mman.h>

#define ReturnError(stmt) 						\
	do { fprintf(stderr, "Error in %s at %d\n", stmt, __LINE__); 	\
	     return -1;							\
	} while(0)

/** always succeeds... or crashes */
static int
test_malloc(void)
{
	char *block;
	int i;

	for (i = 0; i < 24; i += 2) {
		block = malloc(1 << i);
		if (!block)
			ReturnError("malloc");
		block = realloc(block, 1 << (i + 1));
		block[0] = 1;
		if (!block)
			ReturnError("realloc");
		free(block);

		block = memalign(12, 1 << i);
		if (!block)
			ReturnError("memalign");
		free(block);
	}

	return 0;
}

static int
test_env(void)
{
	if (clearenv())
		ReturnError("clearenv");
	if (unsetenv("newvar"))
		ReturnError("unsetenv #1");

	if (putenv("putvar=newval"))
		ReturnError("setenv");
	if (setenv("newvar", "newval", 1))
		ReturnError("setenv");

	if (getenv("nope"))
		ReturnError("getenv #1");
	if (!getenv("newvar"))
		ReturnError("getenv #2");

	if (unsetenv("newvar"))
		ReturnError("unsetenv #2");
	if (unsetenv("nonexistent"))
		ReturnError("unsetenv #3");

	return 0;
}

static int
test_mmap(void)
{
	char *buf;
	int blen;
	int i;

	for (i = 0; i < 24; i += 2) {
		blen = 1 << i;
		buf =  mmap(0, blen, PROT_READ | PROT_WRITE, 
			    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		if (buf == MAP_FAILED)
			ReturnError("mmap");

		// touch data
		if (buf[0] != 0 || buf[blen - 1] != 0)
			ReturnError("mmap dirty pages\n");
		buf[0] = 1;
		buf[blen - 1] = 1;
		if (buf[0] != 1 || buf[blen - 1] != 1)
			ReturnError("mmap data corruption\n");

		// munmap must support calls with unmapped regions
		if (munmap(0, blen))
			ReturnError("munmap outside region");

		// cannot verify smaller region unmaps: don't want to SEGV
		if (munmap(buf, blen))
			ReturnError("munmap");
	}

	return 0;
}

int test_fork(void)
{
	pid_t pid;

	pid = fork();
	if (pid < 0)
		ReturnError("fork");

	if (!pid) {
		printf("You murderer!\n");
		exit(0);
	}

	return 0;
}

int test_execve(void)
{
	return 0;
}

int 
main(int argc, char **argv)
{
	// obscure hack to allow the execve test to start a child.
	if (argc == 2) 
		return 0;

	if (test_malloc())
		return 1;

	if (test_env())
		return 1;

// XXX fork not yet supported
#if 0
	if (test_fork())
		return 1;
#endif

//	mmap disabled until we fix the assembly version in libc
//	if (test_mmap())
//		return 1;

	return 0;
}

