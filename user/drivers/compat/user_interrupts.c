/** Nexus OS: Userspace driver Interrupt API.
    Handles device interrupts that the kernel passes upwards. */

#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>
#include <nexus/sema.h>
#include <nexus/queue.h>
#include <nexus/interrupts.h>
#include <nexus/djwilldbg.h>
#include <nexus/pthread-private.h>
#include <nexus/Thread.interface.h>
#include <nexus/ddrm.interface.h>

#define nobody ((pthread_t) 0)
pthread_t cli_holder = nobody;
pthread_t pending_intr = nobody;

struct ithread {
  int irq;
  void (*handler)(int, void *, void *);
  void *dev_id;
  Sema sema_ready;
};

static struct ithread *int_args = NULL;

int disable_intr(void) {
  pthread_t me = pthread_self();

  if(cli_holder == me)
    return 1;
  
  nexus_cli();
  return 0;
}

void restore_intr(int lvl) {
  if(lvl == 0)
    nexus_sti();
}

/* nesting is not handled */
void nexus_cli(void) {
  pthread_t me = pthread_self();

  /* this will always succeed */
  atomic_swap((int *)&cli_holder, me);
  assert(cli_holder == me);
}

void nexus_sti(void) 
{
  while (1) {
    atomic_swap((int *)&cli_holder, pending_intr);

    if (cli_holder != pthread_self()) {
      /* I'm no longer handling interrupts */
      ddrm_sys_hint_intr_done(int_args->irq);
      break;
    }

    assert(int_args);
    pending_intr = nobody;

    int_args->handler(int_args->irq, int_args->dev_id, NULL);
  }
}

/* when wait for intr returns, we have cli */
static void *
interrupt_loop(void *voidargs) 
{
  struct ithread *args = voidargs;
  int_args = args;
  int ret;

  // setup interrupt handler and register to kernel
  ret = ddrm_sys_setup_interrupts(args->irq, args->irq);
  if (ret) {
    printk("[udev] error at registration. Aborting\n");
    exit(-1);
  }

  // signal other thread we are ready
  V_nexus(&args->sema_ready);

  while (1) {
    ret = ddrm_sys_wait_for_intr(args->irq);
    if (ret < 0) {
      printk("[udev] interrupt handling error. Aborting\n");
      exit(-1);
    }

    int_args->handler(int_args->irq, int_args->dev_id, NULL);
    nexus_sti();
  }

  free(voidargs);
  return NULL;
}

pthread_t 
start_interrupt_thread(unsigned int irq, void (*handler)(int, void *, void *),
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

