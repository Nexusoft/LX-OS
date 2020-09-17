syscall Device {

  decls {
    includefiles { "<nexus/udevice.h>" }
  }

  decls __callee__ {
    includefiles { "<nexus/mem.h>",
   		   "<nexus/device.h>" }
  
    static inline unsigned long 
    __inb(unsigned int port) 
    {
      uint8_t _val = 0;

      asm("inb %w1,%b0" : "=a" (_val) : "Nd" (port)); 
      return _val & 0xff;
    }

    static inline unsigned long 
    __inw(unsigned int port) 
    {
      uint16_t _val = 0;
    
      asm("inw %w1,%w0" : "=a" (_val) : "Nd" (port)); 
      return _val & 0xffff;
    }
    
    static inline unsigned long 
    __inl(unsigned int port) 
    {
      uint32_t _val = 0;
      asm("inl %w1,%0"  : "=a" (_val) : "Nd" (port)); 
      return _val;
    }
  }

  interface int 
  irq_get(int irq) 
  {
    return nxirq_get(irq, nxirq_wake, (void *) irq);
  }

  interface void
  irq_wait(int irq, int ack)
  {
    nxirq_wait(irq, ack);
  }

  interface void
  irq_put(int irq)
  {
    nxirq_put(irq);
  }

  /** Allocate pages. These will be kernel mapped, 
      i.e., the process cannot read or write contents 
     
      @param phys contains the physical address of the requested page on success
             or is undefined if @return is NULL */
  interface unsigned long
  mem_alloc(int num_pages, unsigned long *paddr)
  {
    unsigned long vaddr;
    int lvl;

    if (num_pages > 100)
	return -1;

    lvl = disable_intr();

    // acquire 
    vaddr = Map_alloc(curr_map, num_pages, 1, 0, vmem_heap);
    assert(vaddr >= USERMMAPBEGIN);

    // getphysical
    if (vaddr)
    	*paddr = fast_virtToPhys_locked(curr_map, vaddr, 0, 1);

    restore_intr(lvl);
    return vaddr;
  }

  /** Setup a mapping from physical to virtual memory */
  interface unsigned long
  mem_map(unsigned long paddr, int len)
  {
    unsigned long pg_off, pg_vaddr;
   
    pg_off = paddr & (PAGE_SIZE - 1);
    pg_vaddr = Map_insertNear(curt->ipd->map, PHYS_TO_PAGE(paddr), PAGECOUNT(len), 1, 0, vmem_dev);
    return pg_vaddr | pg_off;
  }

  /** Read len bytes at virtual address vaddr
      @param vaddr is a pointer to !user memory */
  interface unsigned long
  mem_read(unsigned long vaddr, unsigned long len)
  {
    if (unlikely(vaddr + len > KERNELVADDR)) {
    	printk_red("[dev] out of bounds read %lx\n", vaddr);
	ipd_kill(curt->ipd);
    }
    
    switch (len) {
      case 1: return (*(unsigned char *) vaddr) & 0xff;
      case 2: return (*(unsigned short*) vaddr) & 0xffff;
      case 4: return *(unsigned long *) vaddr;
    }
      
    printk_red("[dev] incorrect read length. Aborting\n"); 
    ipd_kill(curt->ipd);
    return 0;
  }

  /** Write a value to protected kernel memory
      @param val holds a value if len is one of 1, 2 or 4,
             or a pointer otherwise */
  interface int
  mem_write(unsigned long vaddr, unsigned long len, unsigned long val)
  {
    int lvl;

    if (unlikely(vaddr + len > KERNELVADDR)) {
    	printk_red("[dev] out of bounds write %lx\n", vaddr);
	ipd_kill(curt->ipd);
    }
    
    switch (len) {
      case 1: *((unsigned char *) vaddr) = val & 0xff;   return 0;
      case 2: *((unsigned short*) vaddr) = val & 0xffff; return 0;
      case 4: *((unsigned long *) vaddr) = val;          return 0;
    }
    
    lvl = disable_intr();
    memcpy((void *) vaddr, (void *) val, len); 
    restore_intr(lvl);
    return 0;
  }

  /** @param val is a pointer to an unsigned long */
  interface unsigned long
  inb(unsigned short port)
  {
    return __inb(port);
  }

  /** @param val is a pointer to an unsigned long */
  interface unsigned long
  inw(unsigned short port)
  {
    return __inw(port);
  }

  /** @param val is a pointer to an unsigned long */
  interface unsigned long
  inl(unsigned short port)
  {
    return __inl(port);
  }

  /** @param val is an unsigned long */
  interface void
  outb(unsigned short port, unsigned long val)
  {
    asm("outb %b0,%w1" : : "a" (val), "Nd" (port));
  }

  /** @param val is an unsigned long */
  interface void
  outw(unsigned short port, unsigned long val)
  {
    asm("outw %w0,%w1" : : "a" (val), "Nd" (port));
  }

  /** @param val is an unsigned long */
  interface void
  outl(unsigned short port, unsigned long val)
  {
    asm("outl %0,%w1"  : : "a" (val), "Nd" (port));
  }

  /** Read pci configuration space (type 1) 
      Two ioport calls must be run uninterrupted, 
      therefore must be in kernel */
  interface unsigned long 
  pciconfig_read(unsigned long address, int len)
  {
    unsigned long ret;
    int lvl;

    lvl = disable_intr();
    outl(address & ~3, 0xCF8);

    switch (len) {
    case 1: ret = __inb(0xCFC + (address & 0x3)); break;
    case 2: ret = __inw(0xCFC + (address & 0x2)); break;
    case 4: ret = __inl(0xCFC); break;
    default: ret = 0;
    }

    restore_intr(lvl);
    return ret;
  }

  interface void 
  pciconfig_write(unsigned long address, int len, unsigned long value)
  {
    unsigned long lvl;

    lvl = disable_intr();
    outl(address & ~3, 0xCF8);

    switch (len) {
    case 1:  outb((uint8_t)  value & 0xff,   0xCFC + (address & 0x3));
    case 2:  outw((uint16_t) value & 0xffff, 0xCFC + (address & 0x2));
    case 4:  outl((uint32_t) value,          0xCFC);
    }

    restore_intr(lvl);
  }
}

