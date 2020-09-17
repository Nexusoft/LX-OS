/** NexusOS: test standard LibC functionality */

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <malloc.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <sys/wait.h>

#include <nexus/kshmem.h>
#include <nexus/rdtsc.h>
#include <nexus/test.h>
#include <nexus/syscalls.h>
#include <nexus/nexuscalls.h>
#include <nexus/IPC.interface.h>

static int
test_gettimeofday(void)
{
	struct timeval tv1, tv2;
	uint64_t tend;
	int64_t tdiff_us;

	if (gettimeofday(&tv1, NULL))
		ReturnError(-1,"gettimeofday returned error (#1)\n");
	
	tend = rdtsc64() + (NXCLOCK_RATE / 100);	// wait for 10ms
	while (rdtsc64() < tend) {};

	if (gettimeofday(&tv2, NULL))
		ReturnError(-1,"gettimeofday returned error (#2)\n");

	tdiff_us = ((int64_t) tv2.tv_sec  - tv1.tv_sec) * 1000 * 1000 +
		   ((int64_t) tv2.tv_usec - tv1.tv_usec);

	if (tdiff_us < 9000  /* nexustime-based results are a bit imprecise */ || 
	    tdiff_us > 20000 /* allow scheduler delay */) {
		printf("gettimeofday(): %lld != 10,000\n", tdiff_us);
		ReturnError(-1,"gettimeofday()");
	}

	return 0;
}

/** always succeeds... or crashes */
static int
test_malloc(void)
{
	char *block;
	int i;

	for (i = 0; i < 24; i += 2) {
		block = malloc(1 << i);
		if (!block)
			ReturnError(-1,"malloc");

		block = realloc(block, 1 << (i + 1));
		block[0] = 1;
		if (!block)
			ReturnError(-1,"realloc");
		free(block);

		block = memalign(12, 1 << i);
		if (!block)
			ReturnError(-1,"memalign");
		free(block);
	}
	return 0;
}

static int
test_env(void)
{
	if (clearenv())
		ReturnError(-1,"clearenv");
	if (unsetenv("newvar"))
		ReturnError(-1,"unsetenv #1");

	if (putenv("putvar=newval"))
		ReturnError(-1,"setenv");
	if (setenv("newvar", "newval", 1))
		ReturnError(-1,"setenv");

	if (getenv("nope"))
		ReturnError(-1,"getenv #1");
	if (!getenv("newvar"))
		ReturnError(-1,"getenv #2");

	if (unsetenv("newvar"))
		ReturnError(-1,"unsetenv #2");
	if (unsetenv("nonexistent"))
		ReturnError(-1,"unsetenv #3");

	return 0;
}

static int
test_mmap_anonymous(void)
{
	char *buf;
	int blen;
	int i;

	for (i = 0; i < 24; i += 2) {
		blen = 1 << i;
		buf =  mmap(0, blen, PROT_READ | PROT_WRITE, 
			    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		if (buf == MAP_FAILED)
			ReturnError(-1,"mmap");

		// touch data
		if (buf[0] != 0 || buf[blen - 1] != 0)
			ReturnError(-1,"mmap dirty pages\n");
		buf[0] = 1;
		buf[blen - 1] = 1;
		if (buf[0] != 1 || buf[blen - 1] != 1)
			ReturnError(-1,"mmap data corruption\n");

#if 0 // unsupported
		// munmap must support calls with unmapped regions
		if (munmap(0, blen))
			ReturnError(-1,"munmap outside region");
#endif

		// cannot verify smaller region unmaps: don't want to SEGV
		if (munmap(buf, blen))
			ReturnError(-1,"munmap");
	}

	return 0;
}

int test_fork(void)
{
	pid_t pid;
	int status;

	pid = fork();
	if (pid < 0)
		ReturnError(-1, "fork");

	if (!pid) {
		// warning: there is a race here. As Nexus knows no
		// process parents, it has no zombies. If child dies
		// before parent calls waitpid(), parent will not
		// receive the exitcode (which by then has gone lost)
		usleep(10000);
		exit(166);
	}

	waitpid(pid, &status, 0);
	if (!WIFEXITED(status) || WEXITSTATUS(status) != 166)
		ReturnError(-1, "fork status");
	
	return 0;
}

/** a child process that exists correctly */
static int
test_execve_child1(void)
{
	usleep(10000);
	return 0;
}

/** a child process that exists with a recognizable error code */
static int
test_execve_child2(void)
{
	usleep(10000);
	return 133;
}

/** Contrary to the name execve, this does not replace the calling process */
static int 
test_execve(const char *filepath)
{
	char *argv[3];
	int ret, pid;

	int do_test(const char *param, int expected_red) 
	{
		argv[0] = (char *) filepath;
		argv[1] = (char *) param;
		argv[2] = NULL;
		pid = nxcall_exec_ex(filepath, argv, NULL, 0);
		if (pid < 0)
			ReturnError(-1,"waitpid exec\n");
		if (waitpid(pid, &ret, 0) != pid)
			ReturnError(-1,"waitpid\n");
		if (WEXITSTATUS(ret) != expected_red)
			ReturnError(-1,"waitpid return value\n");
	
		return 0;
	}

	if (do_test("--child1", 0))
		return 1;

	if (do_test("--child2", 133))
		return 1;

	return 0;
}

static int 
test_stdio(void) 
{
	if (close(0))
		ReturnError(-1,"close stdin");
#if 0
	if (close(1))
		ReturnError(-1,"close stdout");
	if (close(2))
		ReturnError(-1,"close stderr");
#endif
	
	return 0;
}

extern int nxlibc_enable_mmap;

int 
main(int argc, char **argv)
{
	// special case: child process of execve test
	if (argc == 2 && strcmp(argv[1], "auto")) {
		if (!strcmp(argv[1], "--child1"))
			return test_execve_child1();
		if (!strcmp(argv[1], "--child2"))
			return test_execve_child2();

		return 1;
	}

	if (test_malloc())
		return 1;

	if (test_env())
		return 1;

	if (test_gettimeofday())
		return 1;

	nxlibc_enable_mmap = 1;

	if (test_mmap_anonymous())
		return 1;

	if (test_stdio())
		return 1;

	if (test_fork())
		return 1;
		
	// not an automatic test
	if (argc == 1) {
		if (test_execve(argv[0]))
			return 1;
		
		printf("[libc.test] OK\n");
	}
	
	return 0;
}

