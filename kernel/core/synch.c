/** NexusOS: kernel implementation of synchronization operators (semaphores) */

#include <nexus/defs.h>
#include <nexus/test.h>
#include <nexus/queue.h>
#include <nexus/synch.h>
#include <nexus/synch-inline.h>
#include <nexus/thread.h>
#include <nexus/machineprimitives.h>

/** Allocate a waitqueue */
static inline int
nxwaitqueue_alloc(unsigned int *wq)
{
#define WQ_WRAP(x)  ((x) & (NXCONFIG_WAITQUEUE_COUNT - 1))
  int index;

  // find available semaphore
  index = curt->ipd->wq_last;
  do {
    index = WQ_WRAP(index + 1);

    // special case: do not use ID 0: that denotes an unallocated wq
    if (!index)
      index++;

    // special case: made full circle: all semas have been taken
    if (unlikely(index == curt->ipd->wq_last)) {
      if (!unittest_active)
        printk_red("[wqueue] out of semaphores for pid %d\n", curt->ipd->id);
      return 1;
    }
    

  } while (curt->ipd->wq_used[index]);
  
  // allocate  
  assert(index > 0);
  assert(index < NXCONFIG_WAITQUEUE_COUNT);
  *wq = index;
  curt->ipd->wq_last = index;
  curt->ipd->wq_used[index] = 1;

  return 0;
}

////////  support for nxwaitqueue: kernel counterparts to userspace semaphores
//
// NB: this is a bit of a misnomer: we use these as condition variables

/** Verify semaphore correctness. Assign new semaphore if value is 0.
    Must be called atomically (i.e., with ints disabled on uniprocessor)
    @return 0 on success, 1 on error */
static inline int
nxwaitqueue_check(unsigned int *wq)
{
  assert(check_intr() == 0);

  // sanity check
  if (unlikely(!wq || *wq >= NXCONFIG_WAITQUEUE_COUNT)) {
    printk_red("[wqueue] kernel semaphore error\n");
    return 1;
  }

  // if allocated: done
  if (likely(*wq))
    return 0;
    
  return nxwaitqueue_alloc(wq);
}

int
nxwaitqueue_free(unsigned int wq)
{
  if (unlikely(wq >= NXCONFIG_WAITQUEUE_COUNT)) {
    printk_red("[wq] out of bound in free\n");
    return -1;
  }
  
  if (likely(wq > 0))
    swap(&curt->ipd->wq_used[wq], 0);

  return 0;
}


////////  support for userspace locking

/** Go to sleep on waitqueue wq. Optionally release locks
    @param release_val: a mutex, if called for a condition variable
    @param release_wq: the wq from which to wake release_val waiters 
 
    On return, the release_lock (if any) will be reacquired (!) */
int
nxcondvar_wait(int *value, unsigned int *wq, unsigned int usecs, 
         int *release_val, unsigned int *release_wq)
{
  int delta, lvl, ret;

  lvl = disable_intr();
 
  // first parameter points to the semaphore VALUE if not CONFIG_SPINLOCKS 
  if (value) {
    assert(*value > -15); // XXX DEBUG: REMOVE (only a heuristic)
    if ((*value)-- > 0) {
      assert(!wq || curt->ipd->wq[*wq].semaq.len == 0);
      restore_intr(lvl);
      return usecs;
    }
    else
      if ((*value) < -1) assert(!wq || curt->ipd->wq[*wq].semaq.len > 0);
  }

  // verify (or acquire) waitqueue
  if (unlikely(nxwaitqueue_check(wq))) {
    nexuspanic(); // DEBUG XXX REMOVE
    restore_intr(lvl);
    return -1;
  }
    assert(wq && (*wq) >= 0 && (*wq) < NXCONFIG_WAITQUEUE_COUNT);
  
  // release lock (if any)
  if (release_wq) {
    if (unlikely(nxwaitqueue_check(release_wq))) {
      nexuspanic(); // DEBUG XXX REMOVE
      restore_intr(lvl);
      return -1;
    }

    assert(release_val && ((*release_val) <= 0));
    assert(release_wq && (*release_wq) >= 0 && (*release_wq) < NXCONFIG_WAITQUEUE_COUNT);
    if ((*release_val)++ < 0) {
      assert(curt->ipd->wq[*release_wq].semaq.len > 0);
      V_signal_noint(&curt->ipd->wq[*release_wq]);
    }
    else {
      assert(curt->ipd->wq[*release_wq].semaq.len == 0);
    }
  }

  // translate timeout [usec->ticks] and sleep
  delta = usecs ? max((1ULL * usecs * HZ) / (1000ULL * 1000), 1ULL) : 0;
  ret = nexusthread_sleep_ex(delta, &curt->ipd->wq[*wq]);
  
  // timeout ? did not get lock
  if (ret == 0 && value) 
    (*value)++;

  // reacquire lock (if any)
  /// nb: unlimited timeout on release_wq breaks semantics of timed call
  if (release_wq) {
    if ((*release_val)-- <= 0)
      nexusthread_sleep_ex(0, &curt->ipd->wq[*release_wq]);
  }

  assert(check_intr() == 0);
  restore_intr(lvl);
  assert(check_intr() == 1);
  return ret;
}

int
nxcondvar_signal(int *value, unsigned int *wq)
{
  int lvl, ret;

  lvl = disable_intr();
  
  if (value && (*value)++ >= 0) {
    assert(!wq || curt->ipd->wq[*wq].semaq.len == 0);
    restore_intr(lvl);
    return 0;
  }

  if (unlikely(nxwaitqueue_check(wq)))
    ret = -1;
  else {
    assert(wq && *wq < NXCONFIG_WAITQUEUE_COUNT);
    ret = V_signal_noint(&curt->ipd->wq[*wq]) ? 1 : 0;
  }

  restore_intr(lvl);
  return ret;
}

int
nxcondvar_broadcast(unsigned int *wq)
{
	int lvl, ret;

	lvl = disable_intr();
	if (nxwaitqueue_check(wq))
	  ret = -1;
	else
	  ret = V_broadcast_noint(&curt->ipd->wq[*wq]);
	restore_intr(lvl);
	return ret;
}

////////  regular semaphores

Sema *
sema_new_ex(int value) 
{
  Sema *s;

  s = gcalloc(1, sizeof(Sema));
  s->value = value;
  queue_initialize(&s->semaq);

  return s;
}

Sema *
sema_new_mutex(void) 
{
  return sema_new_ex(1);
}

Sema *
sema_new(void) 
{
  return sema_new_ex(0);
}

void 
sema_dealloc(Sema *s) 
{
  assert(queue_length(&s->semaq) == 0);  
}

void 
sema_destroy(Sema *s) 
{
  sema_dealloc(s);
  gfree(s);
}

void 
sema_initialize(Sema *s, int value) 
{
  atomic_write(&s->value, value);
}

/** Acquire lock without blocking
    @returns 0 if lock has been acquired, 1 otherwise */
int 
P_try(Sema *s)
{ 
  int ret, lvl;

  lvl = disable_intr();
  
  if (s->value <= 0)
    ret = 1;
  else {
    s->value--;
    ret = 0;
  }
  
  restore_intr(lvl);
  return ret;
}

inline void
P_noint(Sema *s)
{
  // before threads have been initialized? cannot block: oldval > 0
  assert(check_intr() == 0);
  assert(s && (curt || s->value > 0));
 
  if (atomic_get_and_addto(&s->value, -1) <= 0) {
    // add to sleeper queue
    assert(!curt->blocksema);  // paranoid XXX remove
    curt->blocksema = s;
    queue_append(&s->semaq, curt);
    assert(s->semaq.len > 0);  // paranoid XXX remove

    // sleep (will temporarily reenable interrupts)
    nexusthread_stop();
    assert(curt->schedstate != DEAD);
  }

  assert(check_intr() == 0);
}

/** Block until the sema is upped.
    @return 0 on success, or 1 if the thread must be killed */
void
P(Sema *s) 
{
  int lvl;

  lvl = disable_intr();
  P_noint(s);
  restore_intr(lvl);
}

inline BasicThread *
V_noint(Sema *s) 
{
  struct BasicThread *t = NULL;
  
  assert(check_intr() == 0);
  
retry:
  if (s->value++ < 0) {
    // wake a sleeper 
    t = queue_dequeue(&s->semaq);
    assert(t);

    // rare special case: waiting thread died
    if (t->schedstate == DEAD)
	    goto retry;
    
    assert(t->blocksema == s);
    t->blocksema = NULL;
    
    if (t->sleepalarm)
      deregister_alarm_noint(t->sleepalarm);

    // start it
    nexusthread_start_noint(t, 0);
  }
  
  return t;
}

/** Up a semaphore */
BasicThread *
V(Sema *s)
{
  BasicThread *ret;
  int lvl; 
  
  lvl = disable_intr();
  ret = V_noint(s);
  assert(s->value <= s->max);
  restore_intr(lvl);
  
  return ret;
}

/** Signal a condition variable: 
    behaves like a semaphore, but cannot increase beyond 0 (i.e., wait) */
inline BasicThread *
V_signal_noint(Sema *s)
{
  BasicThread *ret;
  
  assert(check_intr() == 0); 
  ret = V_noint(s);
  s->value = min(s->value, 0);
  
  return ret;
}

BasicThread *
V_signal(Sema *s)
{
  BasicThread *ret;
  int lvl;
 
  assert(check_intr() == 1); 
  lvl = disable_intr();
  ret = V_signal_noint(s);
  restore_intr(lvl);
  
  return ret;
}

/** Wake up all listeners.
    Interrupts MUST be disabled on call
    @return number of awoken threads */
int
V_broadcast_noint(Sema *s)
{
  BasicThread *ret;
  int i, waiters;
  
  assert(check_intr() == 0); 
  waiters = -s->value;
  for (i = 0; i < waiters; i++) {
    ret = V_noint(s);
    assert(ret);
  }
  
  assert(s->value == 0);
  return waiters;
}

#include "../../common/code/rwsema.c"

/* vim: set ts=2 sw=2 expandtab softtabstop=2 smartindent: */

