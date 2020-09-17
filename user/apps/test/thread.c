/** NexusOS: pthread implementation selftest */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>

#include <nexus/defs.h>
#include <nexus/test.h>
#include <nexus/sema.h>
#include <nexus/rdtsc.h>
#include <nexus/Thread.interface.h>

/// main parameter to set test duration of all tests
static int num_runs = 10;
#define sematimed_runs 	(num_runs / 4)

pthread_mutex_t *curmutex;
pthread_cond_t *curvar;
Sema runsema = SEMA_INIT;
int val;

static void *
pthread_child(void *mutex)
{
	int i;

	for (i = 0; i < num_runs * 10; i++) {
		pthread_mutex_lock(curmutex);
		val += 1;
		pthread_mutex_unlock(curmutex);
		
		// busy wait: be sure that _cond_wait has been called
		while (val != 3)
			Thread_Yield();

		pthread_mutex_lock(curmutex);
		if (val != 3) {
			val = 999;
			printf("bug in child\n");
			pthread_exit((void *) 1);
		}
		val = 4;
		pthread_cond_broadcast(curvar);
		pthread_mutex_unlock(curmutex);

		P(&runsema);
	}
	
	return NULL;
}

static int
pthread_test(void)
{
	pthread_t child;
	void * status;
	int i;

	// create a thread
	if (pthread_create(&child, NULL, pthread_child, NULL))
		ReturnError(1, "pthread create");

	for (i = 0; i < num_runs * 10; i++) {
		// use a mutex
		pthread_mutex_lock(curmutex);
		val += 1;
		pthread_mutex_unlock(curmutex);

		// busy wait: be sure that both threads have INCed
		while (val != 2) 
			Thread_Yield();

		// wait on a condition variable
		pthread_mutex_lock(curmutex);
		val = 3;
		pthread_cond_wait(curvar, curmutex);
		if (val != 4) {
			printf("@run %d val=%d\n", i, val);
			ReturnError(1, "pthread condvar");
		}
		pthread_mutex_unlock(curmutex);
		
		val = 0;
		V_nexus(&runsema);
	}

	return 0;
}

static Sema spawn_sema = SEMA_INIT;

static void *
spawn_child(void *unused)
{
	V_nexus(&spawn_sema);
	return NULL;
}

/** stress test thread creation/deletion by spawning many workers */
static int
spawn_test(void)
{
	pthread_t child;
	int i;

	for (i = 0; i < num_runs; i++) {
		// simulate some preemption
		if (!(i & 10))
			Thread_Yield();
		pthread_create(&child, NULL, spawn_child, NULL);
	}

	for (i = 0; i < num_runs; i++) 
		P(&spawn_sema);
	
	return 0;
}

/** test preemption by never relinquishing the CPU for a long time */
static int
preempt_test(void)
{
	uint64_t timestamp;

	timestamp = rdtsc64() + (10ULL * num_runs * 1000 * 1000);
	while (rdtsc64() < timestamp);	// spin, baby, spin!
	
	return 0;
}

static Sema sema1;
static Sema sema2;

static int pi;
static int do2;

static void *
sema_child(void *mutex)
{
	int i;

	for (i = 0; i < num_runs; i++) {
		V_nexus(&sema1);
		if (do2)
			P(&sema2);
	}

	return NULL;
}

/** Test nexus semaphores */
static int 
sema_test(void)
{
	pthread_t child;

	if (pthread_create(&child, NULL, sema_child, NULL))
		ReturnError(1, "pthread create");

	sema1 = SEMA_INIT;
	sema2 = SEMA_INIT;

	for (pi = 0; pi < num_runs; pi++) {
		P(&sema1);
		if (do2)
			V_nexus(&sema2);
	}

	return 0;
}

/** Test against erroneous timeouts */
static int
timeout_test(void)
{
	pthread_t child;
	int i, ret;

	void *
	timeout_child(void *arg)
	{
		int i;

		for (i = 0; i < sematimed_runs; i++) {
			P(&sema2);
			V_nexus(&sema1);
		}

		V_nexus(&sema2);
		return NULL;
	}

	sema1 = SEMA_INIT;
	sema2 = SEMA_INIT;

	if (pthread_create(&child, NULL, timeout_child, NULL))
		ReturnError(1, "pthread create");

	for (i = 0; i < sematimed_runs; i++) {
		V_nexus(&sema2);

		if (i & 2) {
			if (!P_timed(&sema1, 0))
				ReturnError(1, "timeout on indefinite wait");
		}
		else {
			uint64_t tdiff = rdtsc64();
			if (!P_timed(&sema1, 5000000)) {
				tdiff = rdtsc64() - tdiff;
				fprintf(stderr, "timeout on long wait: %llu cyc\n", tdiff);
				ReturnError(1, "timeout on long wait");
			}
		}
	}

	P(&sema2);
	return 0;
}

/** Test that timeouts occur correctly */
static int
timeout_test2(void)
{
	int i, ret;

	sema1 = SEMA_INIT;

	for (i = 0; i < sematimed_runs; i++) {
		uint64_t tdiff = rdtsc64();

		ret = P_timed(&sema1, 2);
		tdiff = rdtsc64() - tdiff;

		if (ret) {
			fprintf(stderr, "waited %llu cycles\n", tdiff);
			ReturnError(1, "no timeout on wait w/o unlock\n");
		}
	}

	return 0;
}


/** Verify that a lock is released on time */
static int
timeout_test3(void)
{
	uint64_t tsc;
	int i;

	sema1 = SEMA_INIT;
	for (i = 0; i< sematimed_runs; i++) {
		tsc = rdtsc64();
		P_timed(&sema1, 100);
		tsc = rdtsc64() - tsc;
		// HARDCODED assumption: ~3GHz processor
		if (tsc < 100 * 1000 || tsc > 50 * 1000 * 1000) {
			fprintf(stderr, "Sleep too imprecise: %llu\n", tsc);
			ReturnError(1, "Sleep too imprecise\n");
		}
	}

	return 0;
}

int 
main(int argc, char ** argv)
{
	unsigned long long tdiff = 0;
	int do_long_test = 0;

	// manual invocation? increase runtime
	if (argc != 2 || strcmp(argv[1], "auto"))
		do_long_test = 1;
	else
		do_long_test = 0;


	if (do_long_test) {
		printf("Running LONG test\n");
		num_runs *= 50;
		
		// only run long-running preemption test
		if (preempt_test())
			return 1;

		tdiff = rdtsc64();
	}

	if (sema_test())
		return 1;

	do2 = 1;
	if (sema_test())
		return 1;

	if (timeout_test())
		return 1;

	if (timeout_test2())
		return 1;
	
	if (timeout_test3())
		return 1;

	if (spawn_test())
		return 1;

	// pthread test

	curmutex = malloc(sizeof(*curmutex));
	curvar   = malloc(sizeof(*curvar));

	pthread_mutex_init(curmutex, NULL);
	pthread_cond_init(curvar, NULL);

	if (pthread_test())
		return 1;

	pthread_cond_destroy(curvar);
	pthread_mutex_destroy(curmutex);
	

	if (do_long_test) {
		tdiff = rdtsc64() - tdiff;
		tdiff = tdiff >> 20;
		printf("[test] took %lld Mcycles\n", tdiff);
	}

	if (argc == 1) // not 'auto' call at boot
		printf("[test] OK. Thread test passed\n");
	
	return 0;
}

