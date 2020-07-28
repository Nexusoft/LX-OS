#ifndef __DDRMSPEC_H__
#define __DDRMSPEC_H__

/* This file is a placeholder while we figure out what the interface
   to a compiled spec from the kernel should be. */


/* interrupt handling */

typedef enum IRQFlagVal IRQFlagVal;
enum IRQFlagVal{
  IRQ_FLAG_NULL = 0,
  IRQ_FLAG_CARD_NOT_CHECKED = 1,
  IRQ_FLAG_NOT_MINE,
  IRQ_FLAG_MINE_ACKED,
  IRQ_FLAG_MINE_NOT_ACKED,
};

static inline char *IRQ_FLAG_STRING(IRQFlagVal irq){
  char *irqnames[5] = {"IRQ_FLAG_NULL",
		       "IRQ_FLAG_CARD_NOT_CHECKED",
		       "IRQ_FLAG_NOT_MINE",
		       "IRQ_FLAG_MINE_ACKED",
		       "IRQ_FLAG_MINE_NOT_ACKED"};
  return irqnames[irq];
}

#define DDRMSPEC_ALLOW 1
#define DDRMSPEC_DENY 0

struct DDRMSpec{
  /* give notice that a read/write to paddr is about to happen */
  int (*request_read)(int name, unsigned long paddr, unsigned int bytes);
  int (*request_write)(int name, unsigned long paddr, 
		       unsigned long val, unsigned int bytes);
  /* report the result of the read to the spec */
  int (*report_read)(int name, unsigned long paddr, 
		     unsigned long val, unsigned int bytes);
  
  /* The ddrm spec might want to keep track of the id, regions, and irqs */
  int (*register_device_id)(int device_id);
  int (*register_mmio)(int name, unsigned long paddr, unsigned int len);
  int (*register_portio)(int name, unsigned long paddr, unsigned int len);
  int (*register_dmaable)(int name, unsigned long paddr, unsigned int len,
			  int contract);
  int (*register_irq)(int name, int irqnum);

  /* The irq flag is an internal piece of state the compiled spec
     should keep track of. */
  int (*set_irq_flag)(int irqnum, IRQFlagVal state);
  IRQFlagVal (*get_irq_flag)(int irqnum);

  void (*reset_card)(struct DDRM *ddrm);
};

#endif

