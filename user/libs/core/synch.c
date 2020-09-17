/** NexusOS: semaphores and other synchronization */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <sys/types.h>

#include <nexus/defs.h>
#include <nexus/sema.h>
#include <nexus/queue.h>
#include <nexus/syscalls.h>
#include <nexus/profiler.h>
#include <nexus/pthread-nexus.h>
#include <nexus/pthread-private.h>
#include <nexus/machine-structs.h>

#include <nexus/Thread.interface.h>
#include <nexus/Debug.interface.h>

/* spinlocks */

#if NXCONFIG_DEBUG_SPINLOCK
void
spinlock_ex(int *semalock, const char *function)
{
	int spincount = 0;
	
	while (swap((int *) semalock, 1) != 0) {
		assert((*semalock) == 1);
		if (!(++spincount % 100))
			fprintf(stderr, "thrashing in %s\n", function);
		thread_yield();
	}
}
#else
void 
spinlock(int *semalock)
{
	while (swap((int *) semalock, 1) != 0)
		thread_yield();
}
#endif

void 
spinunlock(int *semalock)
{
	assert((*semalock) == 1);
	*semalock = 0;
}

/** Update the sema value */
void 
sema_set(Sema *s, int value) 
{
	assert(value >= 0);
	*s = SEMA_INIT;
	s->value = value;
}

Sema *
sema_new_ex(int value)
{
	Sema * s;
	 
	s = calloc(1, sizeof(Sema));
	sema_set(s, value);
	return s;
}

Sema *
sema_new(void) 
{
	return sema_new_ex(0);
}

/** Deallocate state associated with statically alloc. semaphore */
int
sema_release(Sema *s)
{
	if (s->kqueue)
		return Thread_CondVar_Free(s->kqueue);
	else 
		return 0;
}

/** Deallocate dynamically allocated semaphore */
int
sema_destroy(Sema *s) 
{
	int ret;
	
	ret = sema_release(s);
	free(s);
	return ret;
}

/** @return 0 if acquired lock or 1 if not */
int
P_try(Sema *s)
{
	int val;

	val = atomic_get_and_addto(&s->lock, -1);
	if (val > 0)
		return 0;

	// failed. reincrement
	// in case of race:
	//   - with another P: signal the other waiter --> OK
	//   - with V: will unnecessarily signal --> OK
	if (atomic_get_and_addto(&s->lock, 1) < val - 1)
		thread_condvar_signal(NULL, &s->kqueue);
	return 1;
}

/** Temporarily release mutex while waiting on S */
int
P_ex(Sema *s, Sema *m, int usecs)
{
	return thread_condvar_wait(&s->value, &s->kqueue, usecs, 
			           &m->value, &m->kqueue);
}

/** P with an optional timeout
    @param usecs specifies the timeout or 0 for indefinite
    @return 0 if timed out, >0 if awoken (in time, should be #usec left, not yet true) */
int
P_timed(Sema *s, int usecs) 
{
#if 0
	// try to acquire without system call
	if (!P_try(s))
		return usecs;

	// on failure, acquire through syscall
#endif
	return thread_condvar_wait(&s->value, &s->kqueue, usecs, NULL, NULL);
}

int
P(Sema *s) 
{
	return P_timed(s, 0);
}

/** @return 1 is awoken someone, 0 if not */
int
V_nexus(Sema *s) 
{
	return thread_condvar_signal(&s->value, &s->kqueue);
}

#include "../../common/code/rwsema.c"

CondVar *
CondVar_new(void)
{
        return calloc(1, sizeof(struct CondVar));
}

void
CondVar_release(CondVar *var)
{
	// NB: not MT safe
	Thread_CondVar_Free(var->kqueue);
	var->kqueue = 0;
}

void 
CondVar_del(CondVar *var)
{
	Thread_CondVar_Free(var->kqueue);
	free(var);
}

/** Atomically start to wait on a condvar while temporarily (!) releasing a lock
  
    @return 1 if signaled, 0 if timed out 
    @param lock will be temporarily released as the caller waits for s
           on return, lock will again be LOCKED */
int
CondVar_timedwait(CondVar *var, Sema *lock, int usecs) 
{
	int ret;

	assert(lock->value <= 0); // must be a held mutex
	ret = thread_condvar_wait(NULL, &var->kqueue, usecs, 
			           &lock->value, &lock->kqueue);
	assert(lock->value <= 0); // must be a held mutex
	return ret;
}

void 
CondVar_wait(CondVar *var, Sema *lock) 
{
	CondVar_timedwait(var, lock, 0);
}

void 
CondVar_signal(CondVar *var) 
{
	thread_condvar_signal(NULL, &var->kqueue);
}

void 
CondVar_broadcast(CondVar *var) 
{
	Thread_CondVar_Broadcast(&var->kqueue);
}

