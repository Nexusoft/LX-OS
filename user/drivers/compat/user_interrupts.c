/** Nexus OS: Userspace driver Interrupt API.
    Handles device interrupts that the kernel passes upwards. */

#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>

#include <nexus/defs.h>
#include <nexus/sema.h>

#include <nexus/Device.interface.h>
#include <nexus/Thread.interface.h>

struct ithread {
	int irq;
	void (*handler)(int, void *, void *);
	void *dev_id;
	Sema sema_ready;
};

void 
restore_intr(int lvl) 
{
	// This could be (and was) used to minimize user interrupt handling
	// turnaround time. The trick is to allow unmasking of the IRQ
	// before the interrupt handling thread returns to the kernel to
	// block on a semaphore. Assumption is that it savings of avoiding
	// sysenter+P(sema)+reschedule (in wait_for_intr) is considerable. 
	//
	// In the user interrupt handler, (interrupt_loop) clear a bit
	// before calling the device specific callback. This bit must be
	// shared with the true in-kernel interrupt handler. If an
	// interrupt occurs during processing, the kernel will toggle the
	// bit. On returning from the callback, interrupt_loop checks
	// the toggle. If set, the function continues looping, otherwise, it
	// returns to the kernel to go sleep on its semaphore until a new
	// interrupt arrives.
 	//
	// Historically, use appears to have been limited to the 
	// i810 audio driver. Modern NICs see little advantage, as they
	// operate asynchronously to the device using circular buffers,
	// instead of returning to wait after a fixed number (e.g., 1) of
	// packets
}

/** Disable interrupts
    @return 1 if they were already disabled, 0 otherwise */
int 
disable_intr(void) 
{
	return 0;
}

/* when wait for intr returns, we have cli */
static void *
interrupt_loop(void *voidargs) 
{
  struct ithread *args = voidargs;
  int ret;

  Thread_SetName("net.interrupt");

  // setup interrupt handler and register to kernel
  ret = Device_irq_get(args->irq);
  if (ret) {
    printk("[udev] error at registration. Aborting\n");
    exit(1);
  }

  // signal other thread that we are ready
  V_nexus(&args->sema_ready);

  Device_irq_wait(args->irq, 0);
  while (1) {
    args->handler(args->irq, args->dev_id, NULL);
    Device_irq_wait(args->irq, 1);
  }

  free(args);
  return NULL;
}

pthread_t 
start_interrupt_thread(unsigned int irq, 
		       void (*handler)(int, void *, void *),
		       void *dev_id) 
{
  struct ithread *args;
  
  args = malloc(sizeof(struct ithread));
  args->irq = irq; 
  args->handler = handler; 
  args->dev_id = dev_id;
  args->sema_ready = SEMA_INIT;

  pthread_t interrupt_thread;
  pthread_create(&interrupt_thread, NULL, interrupt_loop, args);

  // wait for thread to finish kernel registration
  P(&args->sema_ready);
  return 0;
}

