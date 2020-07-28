#ifndef __SEMA_H__
#define __SEMA_H__

#include <nexus/defs.h>
#include <nexus/queue.h>

#define SEMATYPE_THREAD 	(0) // thread-only
#define SEMATYPE_GENERAL 	(1) // thread + IRQ context

struct Sema {
  // words are ordered in order of access in P()
  int is_killable : 1;
  int type : 2;
  int value;
  Queue semaq;
  // last_lock_thread is used to detect the current holder of a mutex
  // struct BasicThread *last_lock_thread;
};

#define SEMA_INIT					\
  (Sema) { 0, SEMATYPE_GENERAL, 0, QUEUE_EMPTY,  }
#define SEMA_MUTEX_INIT					\
  (Sema) { 0, SEMATYPE_GENERAL,	1, QUEUE_EMPTY,  }
#define SEMA_INIT_KILLABLE				\
  (Sema) { 1, SEMATYPE_GENERAL, 0, QUEUE_EMPTY,  }
#define SEMA_MUTEX_INIT_KILLABLE			\
  (Sema) { 1, SEMATYPE_GENERAL,	1, QUEUE_EMPTY,  }

struct BasicThread;

Sema *sema_new(void);

void sema_dealloc(Sema *s);
void sema_destroy(Sema *s);

// set semaphore to desired initial value
void sema_initialize(Sema *s, int value);

// Reset a semaphore to a new value, waking up all waiters
// Returns the number of awakened threads
int sema_reinitialize(Sema *s, int value);

// mark semaphore as one whose waiting threads can be killed at any time
void sema_set_killable(Sema *s);

void sema_set_type(Sema *s, int type);

static inline Sema *sema_new_mutex(void) {
  Sema *rv = sema_new();
  if(!rv) return 0;
  sema_initialize(rv, 1);
  return rv;
}


// returns 0 for success, -1 for pending kill

// Wake up all waiting threads. Used in cleanup code; use sparingly!
int sema_wake_all(Sema *s);

void sema_dump(Sema *s); // debugging


#endif

#ifdef NEED_SEMA_WAKEUP
#ifndef HAVE_SEMA_WAKEUP
#define HAVE_SEMA_WAKEUP
// only thread.c should call this
void sema_wakeup_thread(Sema *s, BasicThread *t);
#endif
#endif
