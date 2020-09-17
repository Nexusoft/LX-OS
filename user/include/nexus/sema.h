/* Nexus OS
   Synchronization methods

   XXX rename to synch.h because this contains more than semaphores and
       this name matches the .c file and kernel fi;es
 */

#ifndef _SEMA_H_
#define _SEMA_H_

#include <nexus/config.h>
#include <nexus/queue.h>

typedef struct Sema {
  int value;
  int kqueue;
  int max;			// (optional) maximum: 1 for mutex, ..
  int lock;
} Sema;

#define NX_INT_MAX		(1 << 20)	// bypass include limits.h
#define SEMA_INIT		(Sema) {0, 0, NX_INT_MAX, 0}
#define SEMA_MUTEX_INIT		(Sema) {1, 0, 1, 0}

typedef struct CondVar {
  int kqueue;
} CondVar;
#define CONDVAR_INIT 		(CondVar) { 0 }

/* spinlocks */
#if NXCONFIG_DEBUG_SPINLOCK
void spinlock_ex(int *semalock, const char *function);
#define spinlock(x)		spinlock_ex(x, __FUNCTION__)
#else
void spinlock(int *semalock);
#define spinlock_ex(x, y)	spinlock(x)
#endif
void spinunlock(int *semalock);

/* atomic operations */
int atomic_test_and_set(int *t);
void atomic_clear(int *t);
int atomic_compare_and_swap(int* x, int oldval, int newval);
int atomic_swap(int* x, int newval);
unsigned int getesp(void);

/* semaphores */
Sema *sema_new(void);
Sema *sema_new_ex(int value);
void sema_set(Sema *s, int value);
int  sema_release(Sema *s);
int  sema_destroy(Sema *s);

int  P(Sema *s);
int  P_timed(Sema *s, int usecs);
int  P_try(Sema *s);
int  P_ex(Sema *s, Sema *m, int usecs);
int  V_nexus(Sema *s);

#include <nexus/rwsema.h>

/* condition variables */
CondVar *CondVar_new(void);
void CondVar_release(CondVar *var);
void CondVar_del(CondVar *var);

void CondVar_wait(CondVar *var, Sema *s);
int CondVar_timedwait(CondVar *var, Sema *s, int usecs);
void CondVar_signal(CondVar *var);
void CondVar_broadcast(CondVar *var);

#endif // _SEMA_H_

