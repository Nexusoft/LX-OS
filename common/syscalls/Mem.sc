syscall Mem {

  decls __callee__ {
    includefiles { "<nexus/ipc.h>" }
    includefiles { "<nexus/defs.h>" }
    includefiles { "<nexus/syscall-defs.h>" }
    includefiles { "<nexus/thread.h>" }
    includefiles { "<nexus/thread-private.h>" } // only for nexusthread_isXen()
    includefiles { "<nexus/device.h>" }
    includefiles { "<nexus/ipd.h>" }
    includefiles { "<nexus/thread-inline.h>" }

    static unsigned long last_paddr;
  }

  /** Allocate a page. 
      To avoid conflicts with brk(), virtual addresses returned will
      always be greater than or equal to USERMMAPBEGIN. */
  interface unsigned long 
  GetPages(int numpgs, unsigned long hint) 
  {
    Map *map = nexusthread_current_map();
    unsigned long vaddr;
    int user;

#ifndef NDEBUG
    if (!map) // not a user thread
      nexuspanic();
#endif

    // forbid interference with sequentially growing heap
    if (hint < USERMMAPBEGIN)
      hint = USERMMAPBEGIN;

    user = (nexusthread_current_ipd()->type == NATIVE) ? 1 : 0;
    vaddr = map_page(map, nexusthread_current_ipd(), numpgs, 1, user, 0, 0, hint, 1);

    if (vaddr < USERMMAPBEGIN) {
	    printkx(PK_MEM, PK_ERR, "out of heap memory\n");
	    nexuspanic();
	    return -1;
    }
 
    return vaddr;
  }

  /** Same as GetPages, but with hardcoded hint for libc brk().
      The separate interface is to ensure that brk growing heap and
      arbitrary GetPages regions do not overlap.
   
      do NOT call this function from anything but brk() */
  interface unsigned long
  Brk(int numpgs, unsigned long brk)
  {
	Map *map = nexusthread_current_map();
	unsigned long vaddr;

	// first call from libc will always have argument zero
	if (!brk)
		brk = USERHEAPBEGIN;

	// forbid access to 'mmap' heap region
	if (brk >= USERMMAPBEGIN)
		brk = USERMMAPBEGIN - 1;

	vaddr = map_page(map, nexusthread_current_ipd(), numpgs, 
			 1, 1, 0, 0, brk, 1);

	if (vaddr >= USERMMAPBEGIN) {
		printkx(PK_MEM, PK_ERR, "out of linear heap memory\n");
		nexuspanic();
		return -1;
	}
 
	return vaddr;
  }

  interface int 
  FreePages(unsigned int vaddr, int numpgs) 
  {
	Map *m = nexusthread_current_map();
	unsigned long size = numpgs * PAGESIZE;

	if (vaddr + size > KERNELVADDR || size < 0) {
		printk_red("%s out of bounds: %p\n", __FUNCTION__, vaddr);
		return -SC_INVALID;
	}

	Mem_mutex_lock();
	unmap_pages(m, vaddr, numpgs);
	Mem_mutex_unlock();
	return 0;
  }  

  interface unsigned int 
  GetPhysicalAddress(void *vaddr, unsigned int size) 
  {
    unsigned int ret;
    IPD *ipd;

#ifndef NDEBUG
    if (vaddr + size > (void *) KERNELVADDR || size < 0) {
      printk_red("%s out of bounds: %p\n", __FUNCTION__, vaddr);
      return -SC_INVALID;
    }
#endif

    if ((unsigned) vaddr / PAGESIZE != ((unsigned) vaddr + size - 1) / PAGESIZE) {
      printk_red("dma region exceeds a page\n");
      return -SC_INVALID;
    }

    ipd = nexusthread_current_ipd();
    ret = map_get_physical_address(nexusthread_current_map(), (unsigned)vaddr);

    if (!ret) {
      printk_red("page not mapped\n");
      return -SC_INVALID;
    }

    last_paddr = ret;
    return ret;
  }

  interface void 
  MProtect(unsigned int addr, int len, int prot) 
  {
    Map_setProt(nexusthread_current_map(), addr, len, prot);
  }


}
