#include <nexus/defs.h>
#include <nexus/ddrmspec.h>

#include <nexus/djwilldbg.h>

/* This file is a placeholder while we figure out what the interface
   to a compiled spec from the kernel should be. */

int samplespec_request_read(int name, unsigned long paddr, unsigned int bytes){
  int dbg = 0;
  printk_djwill("ddrm_request_read needs to perform spec checks (paddr=0x%lx bytes=%d)!\n", paddr, bytes);
  return DDRMSPEC_ALLOW;
}

int samplespec_report_read(int name, unsigned long paddr, 
			   unsigned long val, unsigned int bytes){
  int dbg = 0;
  printk_djwill("ddrm_report_read needs to perform spec checks (paddr=0x%lx val=0x%lx bytes=%d)!\n", paddr, val, bytes);
  return DDRMSPEC_ALLOW;
}

int samplespec_request_write(int name, unsigned long paddr, 
			     unsigned long val, unsigned int bytes){
  int dbg = 0;
  printk_djwill("ddrm_request_write needs to perform spec checks (paddr=0x%lx val=0x%lx bytes=%d)!\n", paddr, val, bytes);
  return DDRMSPEC_ALLOW;
}


int samplespec_register_portio(int name, unsigned long paddr, unsigned int len){
  int dbg = 0;
  printk_djwill("ddrm_register_portio %d needs to perform spec checks (paddr=0x%lx len=%d)!\n", name, paddr, len);
  return DDRMSPEC_ALLOW;
}

int samplespec_register_mmio(int name, unsigned long paddr, unsigned int len){
  int dbg = 0;
  printk_djwill("ddrm_register_mmio %d needs to perform spec checks (paddr=0x%lx len=%d)!\n", name, paddr, len);
  return DDRMSPEC_ALLOW;
}

int samplespec_register_dmaable(int name, unsigned long paddr, unsigned int len,
				int contract){
  int dbg = 0;
  printk_djwill("ddrm_register_dmaable %d needs to perform spec checks (paddr=0x%lx len=%d)!\n", name, paddr, len);
  return DDRMSPEC_ALLOW;
}

int samplespec_register_irq(int name, int irqnum){
  int dbg = 0;
  printk_djwill("ddrm_register_irq needs to perform spec checks (name=%d irqnum=%d)!\n", name, irqnum);
  return DDRMSPEC_ALLOW;
}

static IRQFlagVal irqflag = IRQ_FLAG_NULL;

int samplespec_set_irq_flag(int irqnum, IRQFlagVal state){
  int dbg = 0;
  printk_djwill("ddrm_set_irq_flag needs to perform spec checks (num=%d state=%s)!\n", irqnum, IRQ_FLAG_STRING(state));
  irqflag = state;
  return DDRMSPEC_ALLOW;
}

IRQFlagVal samplespec_get_irq_flag(int irqnum) {
  // XXX implement spec checks
  return IRQ_FLAG_MINE_ACKED;
}

void samplespec_reset_card(struct DDRM *ddrm){
  int dbg = 1;
  printk_djwill("not resetting card\n");
}

int global_device_id; /* XXX until we have a compiled spec, we just
			 use this global */
int samplespec_register_device_id(int device_id){
  global_device_id = device_id;
  return DDRMSPEC_ALLOW;
}

DDRMSpec sample_spec={
  .request_read = samplespec_request_read,
  .request_write = samplespec_request_write,
  .report_read = samplespec_report_read,
  .register_portio = samplespec_register_portio,
  .register_mmio = samplespec_register_mmio,
  .register_dmaable = samplespec_register_dmaable,
  .register_irq = samplespec_register_irq,
  .register_device_id = samplespec_register_device_id,
  .set_irq_flag = samplespec_set_irq_flag,
  .get_irq_flag = samplespec_get_irq_flag,
  .reset_card = samplespec_reset_card,
};

