syscall ddrm {

  decls __callee__ {
    includefiles { "<nexus/ddrm.h>" }
    includefiles { "<nexus/thread-inline.h>" }
    includefiles { "<nexus/djwilldbg.h>" }
  }

  interface int sys_setup_interrupts(int irq, int irqname) {
    DDRM *ddrm = nexusthread_current_ipd()->ddrm;

    if (!ddrm)
      return -SC_INVALID;

    return ddrm_register_device(ddrm, irq, irqname);
  }

  interface void sys_hint_intr_done(int irq) {
    DDRM *ddrm = nexusthread_current_ipd()->ddrm;

    if (ddrm && ddrm->irq == irq)
    	ddrm_hint_intr_done(ddrm, nexusthread_self(), irq);

    // we could opt to kill processes that try to send IRQs they do not own
  }

  interface int sys_wait_for_intr(int irq) {
    return ddrm_wait_for_intr(irq);
  }

  interface int sys_read(unsigned long vaddr, 
			 unsigned int bytes,
			 unsigned long *val) {
    unsigned long kval;
    int ret;
    
    ret = ddrm_read(0, vaddr, &kval, bytes, NULL);
    if (ret != X86EMUL_CONTINUE) {
      nxcompat_fprintf(stderr, "[ddrm] read blocked from 0x%lx\n", vaddr);
      return ret;
    }

    Map *map = nexusthread_current_map();
    return poke_user(map, (unsigned int) val, &kval, sizeof(unsigned long));
  }

  interface int sys_write(unsigned long vaddr,
			  unsigned int bytes,
			  unsigned long val){

    int ret = ddrm_write(0, vaddr, val, bytes, NULL);
    if (ret != X86EMUL_CONTINUE)
      nxcompat_fprintf(stderr, "[ddrm] write blocked to 0x%lx\n", vaddr);
    return ret;
  }

  interface int sys_allocate_memory(int size, int contract,
				    unsigned int *vaddr, unsigned int *paddr){
    IPD *ipd = nexusthread_current_ipd();
    Map *map = nexusthread_current_map();
    int ret;

    if (!ipd->ddrm)
      return -SC_NOTFOUND;

    DDRMRegion *reg = ddrm_create_region_dmaable(ipd->ddrm, size, contract);
    if (!reg) {
      printk_red("could not create region of len %d\n", size);
      return -SC_INVALID;
    }

    ret = poke_user(map, (unsigned int) vaddr, &reg->uaddr, sizeof(unsigned int));
    if (ret)
      return -SC_ACCESSERROR;		

    ret = poke_user(map, (unsigned int) paddr, &reg->paddr, sizeof(unsigned int));
    if (ret)
      return -SC_ACCESSERROR;		

    return 0;
  }
}

