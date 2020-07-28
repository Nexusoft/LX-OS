#ifndef __DDRM_H__
#define __DDRM_H__

#include <nexus/defs.h>
#include <nexus/x86_emulate.h>

#include <nexus/eventqueue.h>
#include <nexus/device.h>
#include <nexus/udevice.h>

#include <nexus/ddrmspec.h>
#include <nexus/pci.h>

/* private DDRM structure: don't directly access these fields */
#define MAX_DDRM_REGIONS (8)
struct DDRM{
  IPD *ipd;
  DDRMSpec *spec;
  
  struct HashTable *thread_table; /* accessible from intr context */
  
  int numregions;
  /* this list includes mmio, portio, and dmaable */
  /* XXX actually there could be a lot due to pci_alloc_consistent'ed pages */
  DDRMRegion *regions[MAX_DDRM_REGIONS];  /* This is a list because there
					     are expected to be very few
					     of these per IPD */
  
  int *kcli_ptr;
  int *kpending_intr_ptr;
  int interrupt_thread_id;
  int irq;			///< irq for this device

  int intr_quanta;		///< number of clock ticks to handle interrupt
  int intr_irq;			///< irq to handle. may not be the irq we're waiting for

  IRQEventQueue *event_queue;
  struct NexusDevice *nd;
  DeviceType type;
  char *dev_name;

  void (*card_cleanup)(void *arg);
  void *card_cleanup_arg;

  int dying;
};

typedef enum DDRM_REGION_TYPE DDRM_REGION_TYPE;
enum DDRM_REGION_TYPE{
  DDRM_REGION_TYPE_DMAABLE = 1,
  DDRM_REGION_TYPE_MMIO,
  DDRM_REGION_TYPE_PORTIO,
};

struct DDRMRegion{
  int index; /* private ddrm bookkeeping info */

  DDRM_REGION_TYPE type;
  int name;
  unsigned int uaddr;
  unsigned int rwaddr;
  unsigned int paddr;
  int len;

  int (*emulate_write)(DDRM *ddrm, unsigned long addr, 
		       unsigned long val, int bytes);
  int (*emulate_read)(DDRM *ddrm, unsigned long addr, 
		      unsigned long *val, int bytes);
};

/* Initialize system-wide ddrm state */
extern int ddrm_initted;
void ddrm_sys_init(void);
void ddrm_sys_region_init(void);
void ddrm_sys_pci_init(void);

/* IPD interface to add/remove/get DDRMs */
DDRM *ipd_get_ddrm(IPD *ipd);

/* cleanup - called from reaper thread */
void ddrm_cleanup(DDRM *ddrm);

/* create the top level ddrm */
DDRM *ddrm_create(DDRMSpec *spec, 
		  unsigned int cli_addr, 
		  unsigned int pending_intr_addr,
		  DeviceType type,
		  char *dev_name,
		  void (*card_cleanup)(void *arg),
		  void *card_cleanup_arg);
		  


/* create a memory region for mmio/portio/dmaable in a ddrm covering
   physical pages starting at paddr: implemented in ddrm_region.c*/
DDRMRegion *ddrm_create_region_mmio(DDRM *ddrm, int name, 
				    unsigned int paddr, int len);
DDRMRegion *ddrm_create_region_portio(DDRM *ddrm, int name, 
				      unsigned int paddr, int len);
DDRMRegion *ddrm_create_region_dmaable(DDRM *ddrm, int len, int contract);

DDRMRegion *ddrm_find_region_by_name(DDRM *ddrm, int name);
void ddrm_destroy_region(DDRM *ddrm, DDRMRegion *region);




/* interface to fit in with disassembler: implemented in ddrm_region.c */
int ddrm_read(enum x86_segment seg,
	      unsigned long vaddr,
	      unsigned long *val,
	      unsigned int bytes,
	      struct x86_emulate_ctxt *ctxt);
int ddrm_write(enum x86_segment seg,
	       unsigned long vaddr,
	       unsigned long val,
	       unsigned int bytes,
	       struct x86_emulate_ctxt *ctxt);



/* The driver's interrupt thread calls this to wait for another
   interrupt. */
int ddrm_wait_for_intr(int irq);
/* A non-interrupt thread handling an interrupt might call this when
   it's done */
void ddrm_hint_intr_done(DDRM *ddrm, BasicThread *t, int irq);


/* register thread as belonging to this ddrm */
int ddrm_register_device_thread(BasicThread *toregister, void *voidddrm);

/* Register the device. 
   Must be called from the uthread that will handle interrupts. */
int ddrm_register_device(DDRM *ddrm, int irq, int irqname);



/* scheduler interface: implemented in ddrm_intr.c */
void ddrm_notify_block(BasicThread *t, void *voidargs);
int ddrm_check_intr_queue(BasicThread *t, void *voidargs);
int ddrm_check_sched_to(BasicThread *old, BasicThread *new, void *voidargs);


/* interface for installing a ddrm on a pci device */
NexusPCIDev *ddrm_pci_init(NexusPCIDevID *match_ids, int numids,
			   DeviceType type,
			   unsigned int cli_addr, 
			   unsigned pending_intr_addr);
void ddrm_pci_reclaim(NexusPCIDev *dev);


#endif
