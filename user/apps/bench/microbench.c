/** NexusOS: microbenchmarks */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sched.h>

#include <nexus/defs.h>
#include <nexus/test.h>
#include <nexus/profiler.h>

#ifdef __NEXUS__
#include <nexus/syscalls.h>
#include <nexus/Time.interface.h>
#include <nexus/Debug.interface.h>
#include <nexus/Thread.interface.h>
#else
#include <sys/syscall.h>
#endif

#define NUMRUNS 20001

struct nxmedian_data *mediandata;

/** wake up the CPU from low power mode */
static int
warm_up(void)
{
	uint64_t tend;

	tend = rdtsc64() + nxprofile_cpurate();
	while (rdtsc64() < tend) {};

	return 0;
}

/** default system call benchmark template */
#define BENCH_SIMPLE(name, call, ...) 					\
static int 								\
bench_##name(void)							\
{									\
	int i;								\
									\
	nxmedian_reset(mediandata);					\
									\
	for (i = 0; i < NUMRUNS; i++) {					\
		nxmedian_begin(mediandata);				\
		call(__VA_ARGS__);					\
		nxmedian_end(mediandata);				\
	}								\
									\
	nxmedian_show(#name, mediandata);				\
	nxmedian_write("/tmp/bench_" #name ".data", 0, mediandata);	\
	return 0;							\
}

static struct timeval tv;

/* The list of calls. Often, nexus and linux have different implementations */

#ifdef __NEXUS__
BENCH_SIMPLE(yield, 			thread_yield, 		);
BENCH_SIMPLE(Yield, 			Thread_Yield, 		);
BENCH_SIMPLE(nullcall, 			nexuscall0, 		SYS_RAW_Debug_Null_CMD);
BENCH_SIMPLE(nullcall_ipc, 		Debug_Null, 		0);
BENCH_SIMPLE(nullcall_blocked, 		Debug_Null2, 		0);
BENCH_SIMPLE(gettimeod_nocache, 	time_gettimeofday, 	&tv);
BENCH_SIMPLE(gettimeod_wrapped, 	Time_gettimeofday, 	&tv);
#else
BENCH_SIMPLE(yield, 			sched_yield, 		);
BENCH_SIMPLE(getpid_nocache, 		syscall,		SYS_getpid);
#endif
BENCH_SIMPLE(getpid, 			getpid, 		);
#ifdef __NEXUS__
BENCH_SIMPLE(getppid_nowrap, 		thread_getppid, 	);
#endif
BENCH_SIMPLE(getppid, 			getppid, 		);
BENCH_SIMPLE(gettimeofday, 		gettimeofday, 		&tv, NULL);

int
main(int argc, char **argv)
{
	printf("Nexus microbenchmarks\n");
#ifndef __NEXUS__
	printf("WARNING: cpufreq scaling and smp must be DISABLED\n\n");
#endif

	mediandata = nxmedian_alloc(NUMRUNS);

#if 0
#ifdef __NEXUS__
	// tests
	if (Debug_Null(10) != 10)
		ReturnError(1, "Debug_Null failed\n");

	if (Debug_Null2(10) >= 0)
		ReturnError(1, "Debug_Null2 failed\n");
#endif
#endif

	if (warm_up())
		return 1;

	if (bench_yield())
		return 1;
#ifdef __NEXUS__
	if (bench_Yield())
		return 1;
	if (bench_nullcall())
		return 1;
	if (bench_nullcall_ipc())
		return 1;
	if (bench_nullcall_blocked())
		return 1;
	if (bench_gettimeod_nocache())
		return 1;
	if (bench_gettimeod_wrapped())
		return 1;
#else
	if (bench_getpid_nocache())
		return 1;
#endif
	if (bench_getpid())
		return 1;
#ifdef __NEXUS__
	if (bench_getppid_nowrap())
		return 1;
#endif
	if (bench_getppid())
		return 1;
	if (bench_gettimeofday())
		return 1;

	nxmedian_free(mediandata);

	printf("[bench] OK. finished all tests\n");
	return 0;
}

