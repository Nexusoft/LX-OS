#include <nexus/ddrm.h>
#include <nexus/ddrmspec.h>
#include <nexus/synch-inline.h>
#include <nexus/eventqueue.h>
#include <nexus/djwilldbg.h>
#include <nexus/hashtable.h>


/* number of threads for thread hashtable */
#define NUM_THREAD_BUCKETS (32)

int ddrm_intr(int irq, NexusDevice *nd);
int ddrm_initted = 0;

/* Init the ddrm system.  This is for system-wide ddrm
   functionality. */
void ddrm_sys_init(void){
  ddrm_sys_pci_init();
  ddrm_sys_region_init();
  ddrm_initted = 1;
}


/* every IPD can have a DDRM registered to it */
static void
ipd_register_ddrm(IPD *ipd, DDRM *ddrm)
{
  assert(!ipd->ddrm);
  ipd->ddrm = ddrm;
}

static void
ipd_unregister_ddrm(IPD *ipd)
{
  assert(ipd->ddrm);
  ipd->ddrm = NULL;
}

DDRM *
ipd_get_ddrm(IPD *ipd) 
{
  return ipd->ddrm;
}

/* create is called by the interrupt thread */
DDRM *ddrm_create(DDRMSpec *spec, 
		  unsigned int cli_addr, 
		  unsigned int pending_intr_addr,
		  DeviceType type,
		  char *dev_name,
		  void (*card_cleanup)(void *arg),
		  void *card_cleanup_arg){
  assert(check_intr() == 1);   /* called from init syscall only */		  

  IPD *ipd = nexusthread_current_ipd();

  DDRM *newddrm = (DDRM *) gcalloc(1, sizeof(DDRM));
  newddrm->ipd = ipd;
  newddrm->spec = spec;

  newddrm->type = type;
  newddrm->dev_name = dev_name;
  newddrm->dying = 0;
  newddrm->interrupt_thread_id = 0;
  newddrm->card_cleanup = card_cleanup;
  newddrm->card_cleanup_arg = card_cleanup_arg;
  newddrm->nd = NULL;  /* This is set up when the device interrupt
			  thread is registered */

  /* can be peeked/poked on interrupt */
  Map *map = nexusthread_current_map();
  unsigned int cli_paddr = map_get_physical_address(map, cli_addr);
  unsigned int pending_paddr = map_get_physical_address(map, pending_intr_addr);
  newddrm->kcli_ptr = (int *)PHYS_TO_VIRT(cli_paddr);
  newddrm->kpending_intr_ptr = (int *)PHYS_TO_VIRT(pending_paddr);

  /* event_queue for interrupts to wait on */
  newddrm->event_queue = irq_event_queue_new();

  /* this has to happen before the scheduler callbacks are applied */
  ipd_register_ddrm(ipd, newddrm);

  return newddrm;
}

/* this is called from IPD_cleanup, when all threads are killed */
/* no threads are running, so no synchronization is needed */
void ddrm_cleanup(DDRM *ddrm){
  assert(!nexusthread_in_interrupt(nexusthread_self()));
  assert(check_intr() == 1); /* called from reaper thread */
  assert(ddrm != NULL);
  IPD *ipd = ddrm->ipd;
  int i;

  if(ddrm->nd) /* not initialized if intr thread isn't registered yet */
    nexus_unregister_device(ddrm->nd);
  ddrm->card_cleanup(ddrm->card_cleanup_arg);

  for(i = 0; i < ddrm->numregions; i++)
    ddrm_destroy_region(ddrm, ddrm->regions[i]);

  /* unregister all threads currently in ipd */
  ipd_unregister_ddrm(ipd);

  irq_event_queue_destroy(ddrm->event_queue);

  gfree(ddrm);

}

int ddrm_register_device_thread(BasicThread *thread, void *ddrm) {
  assert(check_intr() == 1); /* called from fork syscall, init */

  /* interrupts need to be off when messing with scheduler hooks */
  int lvl = disable_intr();
  thread->check_intr_queue	= ddrm_check_intr_queue;
  thread->notify_block		= ddrm_notify_block;
  thread->check_sched_to 	= ddrm_check_sched_to;
  thread->callback_args		= ddrm;
  restore_intr(lvl);
  
  return 0;
}

/* the interrupt thread should already be registered as a device thread */
int ddrm_register_device(DDRM *ddrm, int irq, int irqname) {
  static Sema __mutex = SEMA_MUTEX_INIT;

  if (!ddrm || ddrm->nd)
    return -1;

  // register thread (XXX find simpler atomic testandset)
  P(&__mutex);
  if (ddrm->interrupt_thread_id) {
  	V(&__mutex);
	return -1;
  }
  ddrm->interrupt_thread_id = nexusthread_self()->id;
  V(&__mutex);

  // register irq
  if (ddrm->spec->register_irq(irqname, irq) != DDRMSPEC_ALLOW) {
    assert(0); 
    return -1;
    /* XXX kill ipd */
  }

  // register device
  ddrm->irq = irq;
  ddrm->nd = nexus_register_device(ddrm->type, ddrm->dev_name, irq,
				   ddrm, ddrm_intr, NULL, DRIVER_USER);
  assert(ddrm->nd != NULL);
  return 0;
}


