#ifndef _SYNCH_INLINE_H_
#define _SYNCH_INLINE_H_

#include <nexus/machineprimitives.h>
#include <nexus/thread.h>
#include <nexus/thread-inline.h>
#include <nexus/thread-private.h>

#include <nexus/synch.h>
static inline int sema_is_killable(Sema *s) {
  assert(s != NULL);
  return s->is_killable;
}

#define DO_TYPE_CHECK(S,T)				\
  if (unlikely((S)->type != (T))) {			\
    printk_red("sema 0x%p type mismatch @ %s %d (%d,%d)\n", S, \
	       __FUNCTION__, __LINE__,			\
	       (S)->type, (T));				\
    nexusthread_dump_regs_stack(nexusthread_self());	\
    nexussendlog("nexuslog.000");			\
    nexuspanic();					\
  }

int __P_generic(Sema *s, int is_int_version);

static inline int 
__P(Sema *s) {
  DO_TYPE_CHECK(s, SEMATYPE_GENERAL);
  return __P_generic(s, 1);
}

static inline int 
P(Sema *s) {
  return __P(s);
}

struct BasicThread * __V_generic(Sema *s, int is_int_version);

// Precondition to __V(): Interrupts are disabled
static inline struct BasicThread *
__V(Sema *s) {
  return __V_generic(s, 1);
}

static inline struct BasicThread *
V(Sema *s) {
  DO_TYPE_CHECK(s, SEMATYPE_GENERAL);
  BasicThread *t = __V(s);
  return t;
}

static inline int 
P_t(Sema *s) {
  DO_TYPE_CHECK(s, SEMATYPE_THREAD);
  BUG_ON_INTERRUPT();
  int level = disable_preemption();
  int rv = __P_generic(s, 0);
  restore_preemption(level);
  return rv;
}

static inline struct 
BasicThread *V_t(Sema *s) {
  DO_TYPE_CHECK(s, SEMATYPE_THREAD);
  BUG_ON_INTERRUPT();
  int level = disable_preemption();
  BasicThread *t = __V_generic(s, 0);
  restore_preemption(level);
  return t;
}

#endif // _SYNCH_INLINE_H_

