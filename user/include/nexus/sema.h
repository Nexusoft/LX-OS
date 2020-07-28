/* Nexus OS
   Synchronization methods

   XXX rename to synch.h because this contains more than semaphores and
       this name matches the .c file and kernel fi;es
 */

#ifndef _SEMA_H_
#define _SEMA_H_

#include <nexus/queue.h>

typedef struct Sema {
  int value;
  Queue semaq;
  int semalock;
} Sema;

typedef struct CondVar CondVar;

struct CondVar {
  Queue waiters; // waiters
  int lock;
};

#define SEMA_INIT 	(Sema) { 0, QUEUE_EMPTY, 0 }
#define SEMA_INIT_ONE 	(Sema) { 1, QUEUE_EMPTY, 0 }
#define SEMA_MUTEX_INIT SEMA_INIT_ONE

#define CONDVAR_INIT { QUEUE_EMPTY, 0 }

/* spinlocks */
void spinlock(int *semalock);
void spinunlock(int *semalock);

/* atomic operations */
int atomic_test_and_set(int *t);
void atomic_clear(int *t);
int atomic_compare_and_swap(int* x, int oldval, int newval);
int atomic_swap(int* x, int newval);
unsigned int getesp(void);

/* semaphores */
Sema *sema_new(void);
void sema_destroy(Sema *s);
void sema_destroy_contents(Sema *s);
void sema_set(Sema *s, int value);
void P(Sema *s);
int  P_timed(Sema *s, int usecs);
void V_nexus(Sema *s);

void sema_dump(Sema *s);

/* condition variables */
CondVar *CondVar_new(void);
void CondVar_wait(CondVar *var, Sema *s);
int CondVar_timedwait(CondVar *var, Sema *s, int usecs);
void CondVar_signal(CondVar *var);
void CondVar_broadcast(CondVar *var);

#endif // _SEMA_H_

