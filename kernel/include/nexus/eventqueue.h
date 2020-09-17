#ifndef __EVENTQUEUE_H__
#define __EVENTQUEUE_H__

/* This is used in the handing off of IRQ's to user level drivers */

#include <nexus/thread.h>
#include <nexus/thread-struct.h>

/* number of clock interrupts before driver should be done acking interrupt. */
#define IRQ_MAX_INTERRUPT_QUANTA (2) 

IRQEventQueue *irq_event_queue_new(void);
void irq_event_queue_destroy(IRQEventQueue *queue);


/* Called from syscall context.  Interrupts can be on. */
int irq_event_consume(IRQEventQueue *irq);
int irq_event_consume_all(IRQEventQueue *irq);

/* Called from interrupt context.  Interrupts should be off. */
BasicThread *irq_event_produce(IRQEventQueue *s);

#endif

