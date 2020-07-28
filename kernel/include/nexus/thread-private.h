#ifndef _NEXUS_THREAD_PRIVATE_H_
#define _NEXUS_THREAD_PRIVATE_H_

#include <nexus/ipc.h>
#include <nexus/idl.h>
#include <nexus/thread.h>

static inline int 
nexusthread_get_syscall_num(BasicThread *t) 
{
  if (t->type == USERTHREAD)
    return ((UThread *)t)->last_syscall;
  else
    return -1;
}

static inline int 
nexusthread_check_fastsyscall(BasicThread *t, Call_Handle call_handle) 
{
  if (t->type == USERTHREAD)
    return ((UThread *)t)->fast_syscall_result_dest && call_handle == CALLHANDLE_SYSCALL;
  else
    return 0;
}

#ifdef __NEXUSXEN__
static inline int 
nexusthread_isXen(BasicThread *bt) 
{
  struct UThread *ut;

  if (unlikely(bt->type != USERTHREAD))
    return 0;

  ut = (struct UThread *)bt;
  if (ut->ipd->type != XEN)
    return 0;

  return 1;
}
#endif

/* Thread kill support functions */
static inline int 
nexusthread_has_pending_kill(BasicThread *t) 
{
  return atomic_get(&t->pending_kill);
}

// Inline version
static inline int 
nexusthread_in_interrupt(BasicThread *t) 
{
  assert(t);
  return atomic_get(&t->interrupt_nesting) ? 1 : 0;
}

#define BUG_ON_INTERRUPT()					\
  if(unlikely(nexusthread_self() && nexusthread_in_interrupt(nexusthread_self()))) {	\
    printk_red("Cannot invoke this in interrupt context! %s:%d\n", __FILE__, __LINE__);	\
    show_trace(NULL);							\
    nexuspanic();						\
  }

#endif

