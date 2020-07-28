#include <nexus/defs.h>
#include <nexus/synch-inline.h>
#include <nexus/thread-inline.h>
#include <nexus/ddrm.h>
#include <nexus/io_instrument.h>
#include <nexus/djwilldbg.h>
/* defines from the driver needed for the chunk of code */
#define ENUM_ENGINE(PRE,DIG) 									\
enum {												\
	PRE##_BDBAR =	0x##DIG##0,		/* Buffer Descriptor list Base Address */	\
	PRE##_CIV =	0x##DIG##4,		/* Current Index Value */			\
	PRE##_LVI =	0x##DIG##5,		/* Last Valid Index */				\
	PRE##_SR =	0x##DIG##6,		/* Status Register */				\
	PRE##_PICB =	0x##DIG##8,		/* Position In Current Buffer */		\
	PRE##_PIV =	0x##DIG##a,		/* Prefetched Index Value */			\
	PRE##_CR =	0x##DIG##b		/* Control Register */				\
}

ENUM_ENGINE(OFF,0);	/* Offsets */
ENUM_ENGINE(PI,0);	/* PCM In */
ENUM_ENGINE(PO,1);	/* PCM Out */
ENUM_ENGINE(MC,2);	/* Mic In */

enum {
	GLOB_CNT =	0x2c,			/* Global Control */
	GLOB_STA = 	0x30,			/* Global Status */
	CAS	 = 	0x34			/* Codec Write Semaphore Register */
};

ENUM_ENGINE(MC2,4);     /* Mic In 2 */
ENUM_ENGINE(PI2,5);     /* PCM In 2 */
ENUM_ENGINE(SP,6);      /* S/PDIF */

enum {
	SDM =           0x80                    /* SDATA_IN Map Register */
};

/* interrupts for a dma engine */
#define DMA_INT_FIFO		(1<<4)  /* fifo under/over flow */
#define DMA_INT_COMPLETE	(1<<3)  /* buffer read/write complete and ioc set */
#define DMA_INT_LVI		(1<<2)  /* last valid done */
#define DMA_INT_CELV		(1<<1)  /* last valid is current */
#define DMA_INT_DCH		(1)	/* DMA Controller Halted (happens on LVI interrupts) */
#define DMA_INT_MASK (DMA_INT_FIFO|DMA_INT_COMPLETE|DMA_INT_LVI)

/* interrupts for the whole chip */
#define INT_SEC		(1<<11)
#define INT_PRI		(1<<10)
#define INT_MC		(1<<7)
#define INT_PO		(1<<6)
#define INT_PI		(1<<5)
#define INT_MO		(1<<2)
#define INT_NI		(1<<1)
#define INT_GPI		(1<<0)
#define INT_MASK (INT_SEC|INT_PRI|INT_MC|INT_PO|INT_PI|INT_MO|INT_NI|INT_GPI)

#define PCI_DEVICE_ID_SI_7012		0x7012



void i810_reset(DDRM *ddrm){
  assert(check_intr() == 0); /* called from interrupt context */	
  int dbg = 1;
  printk_djwill("resetting i810\n");

  DDRMRegion *region = ddrm_find_region_by_name(ddrm, 1);
  assert(region != NULL);

  extern int global_device_id;

  /* from following calls from i810_release */
#if 1
  /* stop adc */
  outb(0, region->rwaddr + PI_CR);
  // wait for the card to acknowledge shutdown
  while( inb(region->rwaddr + PI_CR) != 0 ) ;
  // now clear any latent interrupt bits (like the halt bit)
  if(global_device_id == PCI_DEVICE_ID_SI_7012)
    outb( inb(region->rwaddr + PI_PICB), region->rwaddr + PI_PICB );
  else
    outb( inb(region->rwaddr + PI_SR), region->rwaddr + PI_SR );
  outl( inl(region->rwaddr + GLOB_STA) & INT_PI, region->rwaddr + GLOB_STA);


  /* stop dac */
  outb(0, region->rwaddr + PO_CR);
  // wait for the card to acknowledge shutdown
  while( inb(region->rwaddr + PO_CR) != 0 ) ;
  // now clear any latent interrupt bits (like the halt bit)
  if(global_device_id == PCI_DEVICE_ID_SI_7012)
    outb( inb(region->rwaddr + PO_PICB), region->rwaddr + PO_PICB );
  else
    outb( inb(region->rwaddr + PO_SR), region->rwaddr + PO_SR );
  outl( inl(region->rwaddr + GLOB_STA) & INT_PO, region->rwaddr + GLOB_STA);

#endif
  /* clear interrupts */
  unsigned int status = inl(region->rwaddr + GLOB_STA);
  outl(status & INT_MASK, region->rwaddr + GLOB_STA);

  printk_djwill("regions->rwaddr = 0x%x uaddr=0x%x paddr=0x%x\n", 
		region->rwaddr, region->uaddr, region->paddr);
}
