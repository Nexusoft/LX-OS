/** NexusOS: device multiplexing */

#include <nexus/defs.h>
#include <nexus/machineprimitives.h>
#include <nexus/clock.h>
#include <nexus/synch.h>
#include <nexus/synch-inline.h>
#include <nexus/thread.h>
#include <nexus/device.h>
#include <nexus/queue.h>
#include <nexus/ipd.h>
#include <asm/hw_irq.h>
#include <nexus/rdtsc.h>
#include <nexus/mem.h>
#include <nexus/kbd.h>
#include <nexus/syscalls.h>

#include <nexus/djwilldbg.h>

/// number of times an IRQ has been dispatched and not yet acknowledged. 
static int irq_count[256]; 

/// interrupt handling routine lookup table
static int (*irq_handler[256])(void *);
static void *irq_handler_arg[256];
static Sema irq_sema[256];  

/** Take control of an irq 
    Does not support shared irqs */
int
nxirq_get(int irq, int (*func)(void *), void *arg)
{
	assert(irq != IRQ_NONE); // debug XXX remove

	if (irq_handler[irq]) {
		printk_red("[irq] %d already taken\n", irq);
		return 1;
	}

	irq_handler[irq] = func;
	irq_handler_arg[irq] = arg;
	enable_8259A_irq(irq);
	
	return 0;
}

void
nxirq_put(int irq)
{
	disable_8259A_irq(irq);
	irq_handler[irq] = NULL;
}

/** Acknowledge an interrupt */
void 
nxirq_done(int irq)
{
	assert(irq_count > 0);
	if (!--irq_count[irq])
		enable_8259A_irq(irq);
}

/** Acknowledge an interrupt and wait on the next */
void
nxirq_wait(int irq, int ack) 
{
	if (likely(ack))
  		nxirq_done(irq); 

	P(&irq_sema[irq]);
}

/** interrupt handler callback: wake up waiter */
int 
nxirq_wake(void *irq) 
{
	V(&irq_sema[(unsigned long) irq]);
  
	// force preemption, so that high-priority inthandling thread will run
	return 1;
}

/* return 1 if preemption is needed to handle irq */
static inline int 
deliver_irq(int irq) 
{
	int ret;

	if (unlikely(!irq_handler[irq])) {
		nxirq_done(irq);
        	return 0;
	}

	irq_count[irq]++;
	ret = irq_handler[irq](irq_handler_arg[irq]);

	// kernel irqs are acknowledged automatically
	// (user irqs are ack'ed in nxirq_wait)
	if (irq_handler[irq] != nxirq_wake)
		nxirq_done(irq);

	return ret;
}

void
nxirq_handle(int irq) 
{
  extern int nxkey_press;
  int preempt_needed;

  // normally, handle all except spurious interrupts
  if (likely(!mask_and_ack_8259A(irq))) {

  	  // in a panic, only handle keyboard interrupt (to reboot)
	  if (unlikely(!nxkey_press)) {
		nxkey_press = 1;
	  }
	  else {
		extern uint64_t sched_int;
		uint64_t tdiff;
		
	  	// call interrupt handler
		tdiff = rdtsc64();
	  	preempt_needed = deliver_irq(irq);
		sched_int += rdtsc64() - tdiff;

		// preempt thread if needed
	  	if (get_preemption() && preempt_needed) {
#if !NXCONFIG_PREEMPT_KERNEL
			// do not preempt if in syscall and not blocked
			if (curt->syscall_is && 
			    !curt->blocksema)
				swap(&curt->pending_preempt, 1);
			else
#endif
				nexusthread_yield_noint();
		}
	  }
  }
  else
	  printk_red("NXDEBUG: spurious IRQ %d\n", irq);
}

void
nxirq_init(void)
{
	int i;

	for (i = 0; i < 256; i++)
		irq_sema[i] = SEMA_INIT_KILLABLE;
}

void * __ioremap(unsigned long paddr, unsigned long size, unsigned long flags, int protect)
{
    	unsigned long pg_off, pg_vaddr;
   
    	pg_off = paddr & (PAGE_SIZE - 1);
    	pg_vaddr = Map_insertNear(/* curt ? curt->ipd->map : */ kernelMap, 
			          PHYS_TO_PAGE(paddr), PAGECOUNT(size), 1, 0, vmem_dev);

	flushglobalTLB();
    	return (void *) (pg_vaddr | pg_off);
}

void iounmap(void *addr) 
{
}

