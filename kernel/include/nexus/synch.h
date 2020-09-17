/** NexusOS: kernel synchronization primitives */

#ifndef __SEMA_H__
#define __SEMA_H__

#include <nexus/defs.h>
#include <nexus/queue.h>

struct Sema {
  int value;
  Queue semaq;
  int max;	// (optional) maximum. Mutex max is 1, for instance
};

#define SEMA_MUTEX_INIT		(Sema) { 1, QUEUE_EMPTY, 1 }
#define SEMA_INIT_KILLABLE	(Sema) { 0, QUEUE_EMPTY, (1 << 20) /* INT_MAX */ }
#define SEMA_INIT_SIGNAL	(Sema) { 0, QUEUE_EMPTY, 1 }
#define SEMA_INIT		SEMA_INIT_KILLABLE

struct BasicThread;

Sema *sema_new(void);
Sema *sema_new_mutex(void);
Sema *sema_new_ex(int value);
void sema_initialize(Sema *s, int value);

void sema_dealloc(Sema *s);
void sema_destroy(Sema *s);


void P(Sema *s);
void P_noint(Sema *s);
int P_try(Sema *s);

BasicThread * V(Sema *s);
BasicThread * V_noint(Sema *s);
BasicThread * V_signal(Sema *S);
BasicThread * V_signal_noint(Sema *S);
int           V_broadcast_noint(Sema *s);

//// userspace locking support

int nxcondvar_wait(int *lock, unsigned int *wq, unsigned int usecs, 
	           int *release_val, unsigned int *release_wq);
int nxcondvar_signal(int *lock, unsigned int *wq);
int nxcondvar_broadcast(unsigned int *wq);

int nxwaitqueue_free(unsigned int wq);

#include <nexus/rwsema.h>

#endif

