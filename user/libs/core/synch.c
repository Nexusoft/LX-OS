#include <stdio.h>
#include <assert.h>

#include <nexus/defs.h>
#include <nexus/sema.h>
#include <nexus/queue.h>
#include <nexus/pthread-nexus.h>
#include <nexus/pthread-private.h>

#include <nexus/Thread.interface.h>
#include <nexus/Debug.interface.h>

/* spinlocks */
void 
spinlock(int *semalock)
{
	while (atomic_test_and_set((int *) semalock) != 0)
		Thread_Yield();
}

void 
spinunlock(int *semalock)
{
	*semalock = 0;
}

Sema *
sema_new(void) 
{
	Sema *s;

	s = malloc( sizeof(Sema));
	*s = (Sema) SEMA_INIT;

	return s;
}

void 
sema_destroy_contents(Sema *s) 
{
#ifndef NDEBUG
	if (queue_length(&s->semaq) > 0)
		printf("Destroying a sema with waiting threads!\n");
#endif
}

void 
sema_destroy(Sema *s) 
{
	sema_destroy_contents(s);
	free(s);
}

/** Update the sema value */
void 
sema_set(Sema *s, int value) 
{
	atomic_swap((int*) &s->value, value);
}

/** Shared implementation of P and Condvar_wait 
    @param lock MUST already be held */
static int
P_inner(int *lock, Queue *queue, int usecs) 
{
	PThread *p = pthread_get_my_tcb();
	int ret;

	// adjust timeout granularity to msec
	if (usecs) {
		usecs /= 1000;
		if (!usecs)
			usecs = 1;
	}

	queue_append(queue, &p->sema_link);
	ret = Thread_Block(lock, usecs);
	// remove from queue if not V'd (timed out)
	if (ret == 0) {
		// race: no longer hold semalock. V could come in between
		// as a result, kernel may try to wake running thread: no biggie.
		// correct implementation needs nexusthread_sleep support
		spinlock(lock);
		queue_delete(queue, &p->sema_link);
		spinunlock(lock);
	}
	return ret;
}

/** Shared implementation of V and Condvar_signal 
    @return 0 if queue is empty or 1 if signaled someone */
static int
V_inner(Queue *queue)
{
	QItem *_t;

	// With timeouts, a P can have timed out and 
	// removed itself from the queue. This is not an error.
	if (queue_dequeue(queue, (void **) &_t) == -1) 
		return 0;
	
	_t->next = NULL;
	_t->prev = NULL;
	Thread_Unblock(pthread_threadid(LINK_PARENT(PThread, sema_link, _t)));
	return 1;
}

/** P with an optional timeout
    @param usecs specifies the timeout or 0 for indefinite
    @return 0 if timed out, >0 if awoken (in time, should be #usec left, not yet true) */
int
P_timed(Sema *s, int usecs) 
{
	spinlock(&s->semalock);
	
	if (--(s->value) >= 0) {
		spinunlock(&s->semalock);
		return 1;
	}

	return P_inner(&s->semalock, &s->semaq, usecs);
}

void
P(Sema *s) 
{
	P_timed(s, 0);
}

void 
V_nexus(Sema *s) 
{
	spinlock(&s->semalock);
	if (++s->value <= 0)
		V_inner(&s->semaq);
	spinunlock(&s->semalock);
}

CondVar *
CondVar_new(void)
{
	return calloc(1, sizeof(struct CondVar));
}

/** wait for a condition variable at most @param usecs
    @return 0 if timed out, 1 signalled */
int
CondVar_timedwait(CondVar *var, Sema *s, int usecs) 
{
	int ret;

	spinlock(&var->lock);

	V_nexus(s);
	ret = P_inner(&var->lock, &var->waiters, usecs);
	P(s);

	return ret;
}

void 
CondVar_wait(CondVar *var, Sema *s) 
{
	CondVar_timedwait(var, s, 0);
}

static int 
CondVar_signal_helper(CondVar *var) 
{
	return V_inner(&var->waiters);
}

void 
CondVar_signal(CondVar *var) 
{
	spinlock(&var->lock);
	CondVar_signal_helper(var);
	spinunlock(&var->lock);
}

void 
CondVar_broadcast(CondVar *var) 
{
	spinlock(&var->lock);
	while(CondVar_signal_helper(var)) {} // traverse list
	spinunlock(&var->lock);
}

