#include <nexus/ddrm.h>
#include <nexus/thread-inline.h>
#include <nexus/synch-inline.h>
#include <nexus/djwilldbg.h>
#include <nexus/hashtable.h>
#include <nexus/task.h>

/* immediately while in interrupt context, reset the card, mark the
   flag so that reads and writes to the card no longer happen, and
   mark the ipd for death. */
static void ddrm_cleanup_intr(DDRM *ddrm) {
  /* this could be called from interrupt context or not */
  assert(check_intr() == 0); /* called from interrupt context */

  ddrm->dying = 1;
  ddrm->spec->reset_card(ddrm);

  /* mark threads for killing */
  task_sched((TaskFunc) ipd_killall, (void *)ddrm->ipd);
  /* make sure the interrupt thread can return to user */
  task_sched((TaskFunc) irq_event_produce, (void *) ddrm->event_queue);
}

/* This code is called when the time to handle an int (the quanta) is used up.
   It verifies that the int has been handled or kills the process. */
static int ddrm_check_intr_state(DDRM *ddrm, int irq) {
  int level, kill_ipd = 1;

  IRQFlagVal irqflag = ddrm->spec->get_irq_flag(irq);

  switch (irqflag) {
	  case IRQ_FLAG_CARD_NOT_CHECKED:
	  case IRQ_FLAG_MINE_NOT_ACKED:
	    break;
	  case IRQ_FLAG_NOT_MINE:
	  case IRQ_FLAG_MINE_ACKED:
	    kill_ipd = 0;
	    break;
	  default:
	    nexuspanic();
  };

  if (kill_ipd == 1)
    ddrm_cleanup_intr(ddrm);

  level = disable_intr();
  irq_done(irq); 
  restore_intr(level);

  ddrm->intr_quanta = 0;
  ddrm->intr_irq = 0;

  return kill_ipd;
}

/* This function may be called by the driver to give up its priority
   context early */
void 
ddrm_hint_intr_done(DDRM *ddrm, BasicThread *t, int irq) 
{
  if (ddrm->intr_quanta > 0)
    ddrm_check_intr_state(ddrm, irq);
}

/** when a thread is about to block, check that it handled ints */
void 
ddrm_notify_block(BasicThread *t, void *_ddrm) 
{
  DDRM *ddrm = _ddrm;

  if (ddrm->intr_quanta > 0)
    ddrm_check_intr_state(ddrm, ddrm->intr_irq);
}

/** Put this thread on the high-priority interrupt queue?
    only if it has interrupt quanta left*/
int 
ddrm_check_intr_queue(BasicThread *t, void *_ddrm) 
{
  DDRM *ddrm = _ddrm;

  /* this can be called from an interrupt, or if a thread calls a
     blocking syscall, so syscall or interrupt context */
  assert(check_intr() == 0);
  assert(ddrm->intr_quanta >= 0);

  // no time left.
  if (!ddrm->intr_quanta)
    return 0;

  ddrm->intr_quanta--;

  // no more time left. check that it's done
  if (!ddrm->intr_quanta) {
    ddrm_check_intr_state(ddrm, ddrm->intr_irq);
    return 0;
  }

  // ok. give it some more time
  return 1;
}

/* can have a sideeffect of changing the eip */
int ddrm_check_sched_to(BasicThread *old, BasicThread *new, void *unused)
{
  UThread *unew = (UThread *) new;
  DDRM *ddrm;
  int thread_id;

  // sanity checks
  assert(check_intr() == 0);
  assert(new && new->type == USERTHREAD);

  ddrm = unew->ipd->ddrm;
  assert(ddrm->kcli_ptr);

  /* if udev's 'virtual cli' is taken don't schedule any of its other threads */
  exception_memcpy(&thread_id, ddrm->kcli_ptr, sizeof(int));
  if (thread_id && thread_id != ddrm->interrupt_thread_id) {
    printkx(PK_DRIVER, PK_INFO, "[ddrm] skipping thread during cli\n");
    return 0;
  }

  return 1;
}

/* The driver's interrupt thread blocks here waiting for an interrupt. */
int ddrm_wait_for_intr(int irq) {
  DDRM *ddrm;
  int intlevel;

  /* sanity check input*/
  assert(check_intr() == 1);
  ddrm = nexusthread_current_ipd()->ddrm;
  if (!ddrm || ddrm->irq != irq)
    return -1;

  /* if the thread still has quanta on the interrupt queue, 
     take it off and check the state */
  if (ddrm->intr_quanta > 0) {
    ddrm->intr_quanta = 0;
    if (ddrm_check_intr_state(ddrm, irq))
      return 0;
  }

// occasionally, the network stack blocks. this crude measure fixes the race.
// NXDEBUG HACK XXX remove
#if 1
intlevel = disable_intr();
void enable_8259A_irq(unsigned int irq);
enable_8259A_irq(9);
restore_intr(intlevel);
#endif

  irq_event_consume_all(ddrm->event_queue);
  return 0;
}

/** Interrupt handler for IRQs registered by DDRMs */
int ddrm_intr(int irq, NexusDevice *nd) {
  DDRM *ddrm;
  int thread_id, ret;

  // sanity checks
  assert(nexusthread_in_interrupt(nexusthread_self()));
  assert(check_intr() == 0); /* called from interrupt context */

  ddrm = nd->data;
  if (ddrm->dying)
    return 0;
  
  ddrm->spec->set_irq_flag(irq, IRQ_FLAG_CARD_NOT_CHECKED);
  assert(ddrm->kcli_ptr);

  ret = exception_memcpy((char *)&thread_id, (char*)ddrm->kcli_ptr, sizeof(int));
  assert(ret == 0);

  if (thread_id == 0) { /* nobody has the cli */
    /* assert an interrupt thread has been set up */
    assert(ddrm->interrupt_thread_id != 0);
    assert(ddrm->kcli_ptr != 0);

    /* poke that the interrupt thread has the cli */
    ret = exception_memcpy((char*)ddrm->kcli_ptr, (char*)&ddrm->interrupt_thread_id, sizeof(int));
    assert(ret == 0);

    /* the thread to update is the interrupt thread */
    thread_id = ddrm->interrupt_thread_id;
    irq_event_produce(ddrm->event_queue);

  } else {
    /* there is now a pending interrupt */
    ret = exception_memcpy((char*)ddrm->kpending_intr_ptr, (char*)&thread_id, sizeof(int));  
    assert(ret == 0);
  }

  /* start the interrupt timer */
  ddrm->intr_quanta = IRQ_MAX_INTERRUPT_QUANTA;
  ddrm->intr_irq = irq;

  /* give interrupt priority to thread_id */
  nexusthread_move_to_intrqueue(thread_id);
  
  return 1;
}

