/** NexusOS: Test synchronization primitives */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>

#include <nexus/defs.h>
#include <nexus/sema.h>
#include <nexus/test.h>

#include <nexus/Debug.interface.h>
#include <nexus/Thread.interface.h>

static Sema donelock = SEMA_INIT;

static RWSema rwlock;
static volatile int rwlock_val;

static void *
worker_rwlock(void *data)
{
	int local_val;

	do {
		P_reader(&rwlock);
		local_val = rwlock_val;
		Thread_Yield();	// force collisions
		V_reader(&rwlock);
	} while (!local_val);

	V_nexus(&donelock);
	return NULL;
}

static int
test_rwlock(void)
{
	pthread_t pthread1, pthread2;
	int i, localdone;

	rwsema_set(&rwlock, 3);

	// create two readers, to test the shared read of rwlock
	pthread_create(&pthread1, NULL, worker_rwlock, (void *) 1);
	pthread_create(&pthread2, NULL, worker_rwlock, (void *) 2);
	pthread_create(&pthread2, NULL, worker_rwlock, (void *) 3);

	usleep(10);

	P_writer(&rwlock);
	rwlock_val = 1;
	Thread_Yield();
	V_writer(&rwlock);

	P(&donelock);
	P(&donelock);
	P(&donelock);

	return 0;
}

#define NUM_SEMA 5
static Sema semas[NUM_SEMA];
static Sema sema_workers;
static int dostop;
static int rounds;

static void *
worker_sema(void *_num)
{
	long num = (long) _num;

	// put all workers to sleep
	P(&semas[num % NUM_SEMA]);
	Thread_Yield();
	
	// wake them round robin
	while (!dostop) {
		V_nexus(&semas[(num + 1) % NUM_SEMA]);
		P(&semas[num % NUM_SEMA]);
	}
	
	// wake the server
	V_nexus(&semas[(num + 1) % NUM_SEMA]);
	V_nexus(&sema_workers);
	return NULL;
}

static int
test_sema(int msecs)
{
	pthread_t t;
	long i;

	for (i = 0; i < NUM_SEMA; i++)
		semas[i] = SEMA_INIT;
	sema_workers = SEMA_INIT;

	// start clients
	dostop = 0;
	for (i = 0; i < NUM_SEMA; i++)
		pthread_create(&t, NULL, worker_sema, (void *) i);

	// let them run
	V_nexus(&semas[0]);
	usleep(1000 * msecs);
	dostop = 1;
	
	// wait for them to die
	for (i = 0; i < NUM_SEMA; i++)
		P(&sema_workers);

	return 0;
}

/** Allocate a large number of semaphores:
    verify that kernel sema (re)allocation works correctly */
static int
test_sema_alloc(void)
{
	Sema *s[NXCONFIG_WAITQUEUE_COUNT], *s2;
	int i;

	// allocate a waitqueue
	Sema * __alloc_wq(void)
	{
		Sema *_s = sema_new();
		_s->value = -1;
		if (!V_nexus(_s))
			return _s;
		
		sema_destroy(_s);
		return NULL;
	}

	// exhaust waitqueue space
	for (i = 0; i < NXCONFIG_WAITQUEUE_COUNT - 1 /* because 0 never used */; i++) {
		s[i] = __alloc_wq();
		if (!s[i])
			ReturnError(1, "[alloc] V()");
	}

	// space exhausted: next alloc should fail
	s2 = __alloc_wq();
	if (s2)
		ReturnError(1, "[alloc] V() #2");
	
	// free one: next should succeed again
	sema_destroy(s[0]);
	s2 = __alloc_wq();
	if (!s2)
		ReturnError(1, "[alloc] V() #3");

	// free
	sema_destroy(s2);
	for (i = 1; i < NXCONFIG_WAITQUEUE_COUNT - 1; i++)
		sema_destroy(s[i]);

	return 0;
}

static int more_max = 10;
static Sema sem1 = SEMA_INIT;
static Sema sem2 = SEMA_INIT;
static Sema sem3 = SEMA_INIT;

static void *
worker_more(void *unused)
{
	int i, j;

	for (i = 0; i < more_max; i++) {
		for (j = 0; j < i; j++)
			P(&sem1);
		for (j = 0; j < i; j++)
			V_nexus(&sem2);
	}
	
	V_nexus(&sem2);
	return NULL;
}

static int 
test_sema_more(void)
{
	Sema sem;
        pthread_t t;
	int i, j;

	pthread_create(&t, NULL, worker_more, NULL);

	for (i = 0; i < more_max; i++) {
		for (j = 0; j < i; j++)
			V_nexus(&sem1);
		for (j = 0; j < i; j++)
			P(&sem2);
	}

	P(&sem2);
	return 0;
}

//// test_sema_more, but with parallel workers vying for the semaphores

static void *
worker_parallel(void *_num)
{
        long i, num = (long) _num;

	for (i = num; i < more_max; i++) {
		P(&sem1);
		V_nexus(&sem2);
	}
	
	V_nexus(&sem3);
	return NULL;
}

static int
test_sema_parallel(void)
{
	Sema sem;
        pthread_t t;
	long i, j;

        sem1 = SEMA_INIT;
        sem2 = SEMA_INIT;
	
        // start children
        for (i = 0; i < more_max; i++)
                pthread_create(&t, NULL, worker_parallel, (void *) i);

        // run test
	for (i = 0; i < more_max; i++) {
		for (j = 0; j <= i; j++)
			V_nexus(&sem1);
		for (j = 0; j <= i; j++)
			P(&sem2);
	}

        // wait for children
        for (i = 0; i < more_max; i++)
        	P(&sem3);
	return 0;
}

static void *
worker_simple(void *unused)
{
        while (!dostop) {
                P(&sem1);
                V_nexus(&sem2);
        }

        return NULL;
}

/// Have everyone contend for the same semaphore
static int
test_simple_parallel(void)
{
        pthread_t t;
        int i, max;

        sem1 = SEMA_INIT;
        sem2 = SEMA_INIT;
 
        dostop = 0;       
        for (i = 0; i < NUM_SEMA; i++)
                pthread_create(&t, NULL, worker_simple, (void *) i);

        max = 1000 * more_max;
        for (i = 0; i < max; i++) {
                V_nexus(&sem1);
                P(&sem2);
        }

        dostop = 1;

        // wake workers one last time
        for (i = 0; i < max; i++)
                V_nexus(&sem1);
        
        return 0;
}

int 
main(int argc, char **argv)
{
	int msecs;

	if (nxtest_isauto(argc, argv))
		msecs = 10;
	else if (argc == 2 && !strcmp(argv[1], "-s")) {
                printf("[stresstest] 100 seconds\n");
		msecs = 100000;
                more_max = 1000;
        }
        else
                msecs = 1000;

	// must be first: will exhaust waitqueue space
	if (test_sema_alloc())
		return 1;
	if (test_sema_more())
		return 1;
	if (test_sema_parallel())
		return 1;
        if (test_simple_parallel())
                return 1;
	if (test_sema(msecs))
		return 1;
	if (test_rwlock())
		return 1;
	
	if (argc == 1)
		printf("[sema] OK. test passed\n");
	return 0;
}

/* vim: set ts=8 sw=8 expandtab softtabstop=8 smartindent: */
