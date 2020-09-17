/** NexusOS: benchmark basic context switching 
 
    XXX a lot of code in here is duplicated (copy/paste)
        it's throw away stuff, anyway
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>

#include <nexus/defs.h>
#include <nexus/sema.h>
#include <nexus/rdtsc.h>
#include <nexus/syscalls.h>
#include <nexus/profiler.h>

#include <nexus/Debug.interface.h>
#include <nexus/Thread.interface.h>

/// number of millions of cycles to each test for
#define RUNCYCLES	(100)

/** find maximum system call rate */
static int
bench_syscall(void)
{
	uint64_t profile[2];
	uint64_t tstart;

	printf("testing fast syscall throughput for %dM cycles\n", RUNCYCLES);

	nxprofile_init(profile);
	tstart = rdtsc64();
	while (rdtsc64() < tstart + (RUNCYCLES * (1ULL << 30))) {
		nexuscall0(SYS_RAW_Debug_Null_CMD);
		nxprofile_update(profile, "syscall fast");
	}

	return 0;
}

static int
bench_syscall_ipc(void)
{
	uint64_t profile[2];
	uint64_t tstart;

	printf("testing slow (IPC) syscall throughput for %dM cycles\n", RUNCYCLES);

	nxprofile_init(profile);
	tstart = rdtsc64();
	while (rdtsc64() < tstart + (RUNCYCLES * (1ULL << 30))) {
		Debug_Null(5);
		nxprofile_update(profile, "syscall slow");
	}

	return 0;
}

/** find maximum context switch rate */
static int
bench_yield(void)
{
	uint64_t profile[2];
	uint64_t tstart;

	printf("testing fast yield throughput for %dM cycles\n", RUNCYCLES);

	nxprofile_init(profile);
	tstart = rdtsc64();
	while (rdtsc64() < tstart + (RUNCYCLES * (1ULL << 30))) {
		thread_yield();
		nxprofile_update(profile, "bench");
	}

	printf("testing slow yield throughput for %dM cycles\n", RUNCYCLES);

	nxprofile_init(profile);
	tstart = rdtsc64();
	while (rdtsc64() < tstart + (RUNCYCLES * (1ULL << 30))) {
		Thread_Yield();
		nxprofile_update(profile, "bench");
	}

	return 0;
}

/** find maximum ping-pong switch rate using threads and semaphores */
static int
thread_pingpong_sema(void)
{
	Sema *semapair[2];
	pthread_t other;
	uint64_t profile[2];
	uint64_t tstart;
	int end = 0;

	void *
	thread_pingpong_other(void *unused)
	{
		while (!end) {
			V_nexus(semapair[0]);
			P(semapair[1]);
		}

		V_nexus(semapair[0]);
		return NULL;
	}

	semapair[0] = sema_new();
	semapair[1] = sema_new();

	pthread_create(&other, NULL, thread_pingpong_other, NULL);
	
	printf("testing semaphore throughput for %dM cycles\n", RUNCYCLES);
	nxprofile_init(profile);
	tstart = rdtsc64();
	while (rdtsc64() < tstart + (RUNCYCLES * (1ULL << 30))) {
		P(semapair[0]);
		V_nexus(semapair[1]);
		nxprofile_update(profile, "bench");
	}

	// wait till child has finished (because it uses our stack variables)
	end = 1;
	P(semapair[0]);

	return 0;
}

int
main(int argc, char **argv)
{
	if (bench_syscall())
		return 1;
	
	if (bench_yield())
		return 1;

	if (thread_pingpong_sema())
		return 1;

	return 0;
}

