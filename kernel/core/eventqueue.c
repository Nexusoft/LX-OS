#include <nexus/synch-inline.h>
#include <nexus/thread-inline.h>
#include <nexus/eventqueue.h>
#include <nexus/djwilldbg.h>

struct IRQEventQueue{
  Sema *sema;
};

IRQEventQueue *irq_event_queue_new(void){
  IRQEventQueue *irqnew = (IRQEventQueue*)galloc(sizeof(IRQEventQueue));
  irqnew->sema = sema_new();
  return irqnew;
}

void irq_event_queue_destroy(IRQEventQueue *queue){
  sema_destroy(queue->sema);
}



#define CONSUME_BODY				\
  int P_block_general(Sema *s);			\
  struct BasicThread *t = nexusthread_self();	\
						\
  assert(irq != NULL);				\
  assert(irq->sema != NULL);			\
  assert(t != NULL);				\
  						\
  							\
  if(unlikely(nexusthread_has_pending_kill(t)))		\
    return 1;						\
  							\
  assert(check_intr() == 1);				\
  int intlevel = disable_intr();				\
								\
  int oldval = irq->sema->value--;				\
  printk_djwill("if %d <= 0, thread %d will wait\n", oldval, t->id);	\
  if(oldval <= 0) {					\
    assert(check_intr() == 0);				\
    int rv = P_block_general(irq->sema);		\
    assert(check_intr() == 0);				\
							\
    if(rv != 0)						\
      return rv;					\
  }
  
#define CONSUME_TAIL				\
						\
  restore_intr(intlevel);			\
  assert(check_intr() == 1);			\
						\
  return 0;					



int irq_event_consume_all(IRQEventQueue *irq){
  int dbg = 0;
  CONSUME_BODY;
  irq->sema->value = 0; /* act as if all events are handled */
  CONSUME_TAIL;
}
int irq_event_consume(IRQEventQueue *irq){
  int dbg = 0;
  CONSUME_BODY;
  CONSUME_TAIL;
}


/* This is called from interrupt context when an interrupt arrives. */
BasicThread *irq_event_produce(IRQEventQueue *irq) {
  assert(check_intr() == 0); /* interrupts are always off in this context */
  int dbg = 0;

  assert(irq != NULL);
  assert(irq->sema != NULL);

  BasicThread *t = NULL;

  int oldval = irq->sema->value++;

  if(oldval < 0) {
    int rv = queue_dequeue(&irq->sema->semaq, (void **) &t);
    assert(rv == 0);
    assert(t != NULL);

    nexusthread_check_and_clear_sema(t, irq->sema);
    nexusthread_start(t, 1);
    printk_djwill("eventqueue released thread %d oldval = %d\n", t->id, oldval);
    
  }

  printk_djwill("eventqueue released no one oldval = %d\n", oldval);

  return t;
}

void irq_event_empty(IRQEventQueue *irq){
  assert(check_intr() == 0); /* interrupts are always off in this context */

  BasicThread *t = NULL;

  do{
    queue_dequeue(&irq->sema->semaq, (void **) &t);
    if(t != NULL)
          nexusthread_start(t, 0);

  }while(t != NULL);

  return;
}
