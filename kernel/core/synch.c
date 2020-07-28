/** NexusOS: kernel implementation of synchronization operators (semaphores) */

#include <nexus/defs.h>
#include <nexus/synch.h>
#include <nexus/synch-inline.h>
#include <nexus/thread-private.h>
#include <nexus/thread-inline.h>
#include <nexus/machineprimitives.h>

void sema_dump(Sema *s) {
  printk("{ %d, %d %d ",
	 s->value,
	 s->semaq.len, 
	 s->is_killable);
  queue_dump(&s->semaq);
  BasicThread *t = queue_gethead(&s->semaq);
  if(t != NULL) {
    printk("first tid = %d", t->id);
  }
  printk("}\n");
}

Sema *sema_new(void) {
  Sema *s;

  s = (Sema *)galloc(sizeof(Sema));
  queue_initialize(&s->semaq);
  s->value = 0;
  s->is_killable = 0;
  s->type = SEMATYPE_GENERAL;
  return s;
}

int thread_printer(BasicThread *thread, int *count_limit) {
  if(*count_limit < 5) {
    printk_green("%s %d.%d ", __FUNCTION__,
		 nexusthread_get_base_ipd(thread)->id,
		 thread->id);
  }
  return 0;
}

void sema_dealloc(Sema *s) {
  if(queue_length(&s->semaq) > 0) {
    printk_red("Destroying a sema with %d waiting threads!\n",
	       queue_length(&s->semaq));
    // queue_dump(&s->semaq);
    int count_limit = 0;
    queue_iterate(&s->semaq, (PFany) thread_printer, &count_limit);
    nexusthread_dump_regs_stack(nexusthread_self());
    nexuspanic();
  }
}

void sema_destroy(Sema *s) {
  sema_dealloc(s);
  gfree(s);
}

void sema_initialize(Sema *s, int value) {
  int intlevel = disable_intr();
  s->value = value;
  restore_intr(intlevel);
}

int sema_wake_all(Sema *s) {
  BasicThread *t;
  int num_awakened = 0;
  while(queue_dequeue(&s->semaq, (void **) &t) >= 0) {
    nexusthread_check_and_clear_sema(t, s);
    nexusthread_start(t, 0);
    num_awakened++;
  }
  return num_awakened;
}

int sema_reinitialize(Sema *s, int value) {
  assert(value >= 0);
  int intlevel = disable_intr();

  int num_awakened;
  num_awakened = sema_wake_all(s);
  s->value = value;
  restore_intr(intlevel);

  return num_awakened;
}

void sema_set_killable(Sema *s) {
  s->is_killable = 1;
}

void sema_set_type(Sema *s, int type) {
  assert(type == SEMATYPE_THREAD || type == SEMATYPE_GENERAL);
  s->type = type;
}

void sema_wakeup_thread(Sema *s, BasicThread *t) {
  int intlevel = disable_intr();

  if(queue_delete(&s->semaq, t) == -1) {
    printk("prep_kill: thread not on semaphore!\n");
    nexuspanic();
  }
  s->value = s->value + 1;
  nexusthread_check_and_clear_sema(t, s);
  nexusthread_start(t, 0);
  restore_intr(intlevel);
}

static inline __attribute__ ((always_inline)) 
  int P_block_generic(Sema *s, int is_int_version) {
  struct BasicThread *t = nexusthread_self();
  queue_append(&s->semaq, t);
  nexusthread_set_sema(t, s);

  // This code looks a bit complicated

  // The complexity is needed because a "is_int" (e.g. GENERAL)
  // semaphore might be called from preemption disabled context, and
  // vice versa. We do not want to screw up this other state.

  // always need interrupts disabled, preemption disabled on entry to
  // nexuthread_stop()
  if(is_int_version) {
    assert(check_intr() == 0);
    // ints already disabled on entry
    int level = disable_preemption();
    restore_preemption(1);
    assert(check_intr() == 0);
    nexusthread_stop();
    restore_preemption(level);
  } else {
    // in preemption version, need to disable and restore interrupts
    // across nexusthread_stop()
    int intlevel = disable_intr();
    // if intlevel == 0, something's very wrong: it means that P_t()
    // was called in interrupt context
    assert(intlevel == 1);
    restore_preemption(1);
    assert(check_intr() == 0);
    nexusthread_stop();
    restore_intr(intlevel);
  }

  // Interrupts are re-enabled after context switch back    
  if(unlikely(nexusthread_has_pending_kill(t))) {
    if(!nexusthread_in_interrupt(t) && sema_is_killable(s)) {
      // check to see if we were awaken as part of a pending kill
      // in case this is a counting semaphore, compensate for our decrement
      int intlevel = disable_intr();
      s->value = s->value + 1;
      restore_intr(intlevel);
      return 1;
    }
  }
  return 0;
}

int P_block_general(Sema *s) {
  return P_block_generic(s, 1);
}

int P_block_thread(Sema *s) {
  return P_block_generic(s, 0);
}

/** Block until the sema is upped.
    @return 0 on success, or 1 if the thread must be killed */
int __P_generic(Sema *s, int is_int_version) {
  struct BasicThread *t = nexusthread_self();

  assert(s != NULL);

  if (likely(t != NULL) && unlikely(nexusthread_has_pending_kill(t))) {
    if(!nexusthread_in_interrupt(t) && sema_is_killable(s)) {
      // If there is a pending kill, return right away with exception
      return 1;
    }
  }

  int oldval;
  int intlevel = 0; // intlevel is only used in is_int_version path, and is always initialized, so we never use the intlevel = 0
  if(is_int_version) {
    intlevel = disable_intr();
  }
  oldval = s->value;
  s->value--;
  if(oldval <= 0) {
    // P_block modifies s, so we need ints or preemption disabled
       int rv;
       if(is_int_version) {
	 // P_block_general() assumes that interrupts are disabled on entry
	 assert(check_intr() == 0);
	 rv = P_block_general(s);
       } else {
	 rv = P_block_thread(s);
       }
       // xxx do we really need to disable interrupts? No more changes to
       // P state at this point
       if(!is_int_version) {
	 // preemption version
	 disable_preemption();
       }
       if(rv != 0) {
	 // XXX shouldn't interrupts be restored at this point?
	 return rv;
       }
  }
  if(is_int_version) {
    restore_intr(intlevel);
  }

  return 0;
}

struct BasicThread *
__V_generic(Sema *s, int is_int_version) 
{
  struct BasicThread *t = NULL;

  int oldval;
  if(is_int_version) {
    oldval = atomic_get_and_addto(&s->value, 1);
  } else {
    oldval = s->value;
    s->value++;
  }
  if(oldval < 0) {
    int intlevel; intlevel = 0; // this is tricky. If is_int_version, the while() loop below will always save the intlevel

    // preemption version already has preemption disabled, so no need
    // to disable/restore
    if(is_int_version) {
      int rv;
      // since P() doesn't disable interrupts before decrement, there
      // is a potential race condition between the counter decrement
      // and the insertion onto the queue.

      // Spin until the queue has an element.
      // This should occur rarely
      while(1) {
	// keep looping until semaphore queue is non-empty in common
	// case, the counter / queue race is not triggered, so the
	// yield is not hit
	intlevel = disable_intr();
	rv = queue_dequeue(&s->semaq, (void **) &t);
	if(rv == 0) {
	  break;
	}
	printk_green("Y");
	restore_intr(intlevel);
	nexusthread_yield();
      }
    } else {
      // no race condition
      int rv;
      rv = queue_dequeue(&s->semaq, (void **) &t);
      assert(rv == 0);
    }

    nexusthread_check_and_clear_sema(t, s);
    nexusthread_start(t, 1);
    if(is_int_version) {
      restore_intr(intlevel);
    }
  }

  return t;
}

