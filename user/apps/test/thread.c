/** NexusOS: pthread implementation selftest */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>

#include <nexus/defs.h>
#include <nexus/sema.h>
#include <nexus/rdtsc.h>
#include <nexus/Thread.interface.h>

#define ReturnError(stmt) 						\
	do { fprintf(stderr, "Error in %s at %d\n", stmt, __LINE__); 	\
	     return -1;							\
	} while(0)

pthread_mutex_t *curmutex;
pthread_cond_t *curvar;
Sema runsema = SEMA_INIT;
int val;

static void *
pthread_child(void *mutex)
{
	int i;

	for (i = 0; i < 1000; i++) {
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
		ReturnError("pthread create");

	for (i = 0; i < 100; i++) {
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
			printf("@run %d\n", i);
			ReturnError("pthread condvar");
		}
		pthread_mutex_unlock(curmutex);
		
		val = 0;
		V_nexus(&runsema);
	}

	return 0;
}

static int semaruns = 1000;
static int sematimedruns = 40;
static Sema sema1 = SEMA_INIT;
static Sema sema2 = SEMA_INIT;

static int pi;
static int do2;

static void *
sema_child(void *mutex)
{
	int i;

	for (i = 0; i < semaruns; i++) {
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
		ReturnError("pthread create");

	for (pi = 0; pi < semaruns; pi++) {
		P(&sema1);
		if (do2)
			V_nexus(&sema2);
	}

	return 0;
}

static void *
timeout_child(void *arg)
{
	int i;

	for (i = 0; i < sematimedruns; i++) {
		Thread_USleep(3000);
		V_nexus(&sema1);
	}

	V_nexus(&sema2);
	return NULL;
}

/** Test timeout feature of nexus semaphores */
static int
timeout_test(void)
{
	pthread_t child;
	int i, opt, ret;

	sema1 = SEMA_INIT;
	sema2 = SEMA_INIT;

	if (pthread_create(&child, NULL, timeout_child, NULL))
		ReturnError("pthread create");

	for (i = 0; i < sematimedruns; i++) {
		opt = i % 3;
		if (!opt) {
			ret = P_timed(&sema1, 0);
			if (!ret)
				ReturnError("timeout on indefinite wait\n");
		}
		else if (opt == 1)
			ret = P_timed(&sema1, 10000);
		else {
			ret = P_timed(&sema1, 1);
			if (ret)
				ReturnError("no timeout on on short wait\n");
		}
	}

	P(&sema2);
	return 0;
}

/** Verify that a lock is released on time */
static int
timeout_test2(void)
{
	uint64_t tsc;
	int i;

	sema1 = SEMA_INIT;
	for (i = 0; i< sematimedruns; i++) {
		tsc = rdtsc64();
		P_timed(&sema1, 3000);
		tsc = rdtsc64() - tsc;
		// HARDCODED assumption: ~3GHz processor
		if (tsc < 100 * 1000 || tsc > 20000 * 1000) {
			fprintf(stderr, "Sleep too imprecise: %llu\n", tsc);
			ReturnError("Sleep too imprecise\n");
		}
	}

	return 0;
}

int 
main(int argc, char ** argv)
{
	if (argc == 2) // stress test?
		semaruns *= 10;

	// sema test

	if (sema_test())
		return 1;

	do2 = 1;

	if (sema_test())
		return 1;

	if (timeout_test())
		return 1;

	if (timeout_test2())
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
	
	printf("[test] OK. Thread test passed\n");
	return 0;
}

