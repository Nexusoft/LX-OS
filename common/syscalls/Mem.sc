syscall Mem {

  decls __callee__ {
    includefiles { "<nexus/ipc.h>" }
    includefiles { "<nexus/defs.h>" }
    includefiles { "<nexus/syscall-defs.h>" }
    includefiles { "<nexus/thread.h>" }
    includefiles { "<nexus/thread-private.h>" } // only for nexusthread_isXen()
    includefiles { "<nexus/device.h>" }
    includefiles { "<nexus/ipd.h>" }
    includefiles { "<nexus/mem-private.h>" }
    includefiles { "<nexus/thread-inline.h>" }

  }

  /** Allocate a page. 

      @param hint may be NULL
      @return the address of the new set of pages or -1 on error.
      
      To avoid conflicts with brk(), virtual addresses returned will
      always be greater than or equal to USERMMAPBEGIN. */
  interface unsigned long 
  GetPages(int numpgs, unsigned long hint) 
  {
    unsigned long vaddr;
    int user;

    if (numpgs > 10000) {
    	printk_current("alloc %d pages exceeds boundary\n", numpgs);
	return -1;
    }

    user = (curt->ipd->type == NATIVE) ? 1 : 0;
    vaddr = Map_alloc(curr_map, numpgs, 1, user, vmem_heap);
    if (!vaddr) 
	 return -1;

#ifndef NDEBUG
    assert(vaddr >= USERMMAPBEGIN);
    curr_map->account_mmap_add += numpgs; // accounting
#endif
    return vaddr;
  }

  /** Release pages acquired with GetPages */
  interface int 
  FreePages(unsigned long vaddr, int numpgs) 
  {
	unsigned long size = numpgs * PAGESIZE;

	if (vaddr < USERMMAPBEGIN) {
	    printk_current("trying to unmap brk pages\n");
	    return -1;
	}
 
	if (vaddr + size > KERNELVADDR || size < 0) {
		printk_red("%s out of bounds: %p\n", __FUNCTION__, vaddr);
		return -SC_INVALID;
	}

#ifndef NDEBUG
	// accounting. debug XXX remove
	curr_map->account_mmap_del += numpgs; 
#endif

	Map_free(curr_map, vaddr, numpgs);
	return 0;
  }  

  /** Same as GetPages, but with hardcoded hint for libc brk().
      The separate interface is to ensure that brk growing heap and
      arbitrary GetPages regions do not overlap.
   
      do NOT call this function from anything but brk() */
  interface unsigned long
  Brk(int numpgs, unsigned long brk)
  {
	unsigned long vaddr;

	if (unlikely(!numpgs)) {
		printkx(PK_MEM, PK_ERR, "[mem] brk for zero pages\n");
		return 0;
	}

	// first call from libc will always have argument zero
	if (!brk)
		brk = USERHEAPBEGIN;

	// forbid access to 'mmap' heap region
	if (brk >= USERMMAPBEGIN)
		//brk = USERMMAPBEGIN - (numpgs << PAGE_SHIFT);
		brk = USERHEAPBEGIN;

	vaddr = Map_alloc(curr_map, numpgs, 1, 1, vmem_brk);
 
#ifndef NDEBUG
	assert(vaddr + (numpgs << PAGE_SHIFT) < USERMMAPBEGIN);
	curr_map->account_brk_add += numpgs; // accounting
#endif
	return vaddr;
  }

  /** Release pages acquired with Brk 
      Functionally identical to FreePages */
  interface int 
  UnBrk(unsigned long vaddr, int numpgs) 
  {
	unsigned long size = numpgs * PAGESIZE;

	if (vaddr >= USERMMAPBEGIN) {
	    printk_current("trying to unbrk mmapped pages\n");
	    return -1;
	}
 
	if (size < 0) {
		printk_red("%s out of bounds: %p\n", __FUNCTION__, vaddr);
		return -SC_INVALID;
	}

#ifndef NDEBUG
	// accounting. debug XXX remove
	curr_map->account_brk_del -= numpgs;
#endif

	Map_free(curr_map, vaddr, numpgs);
	return 0;
  }

  /** Translate a physical to a virtual address */
  interface unsigned int 
  GetPhysicalAddress(void *vaddr, unsigned int size) 
  {
#ifndef NDEBUG
    if (vaddr + size > (void *) KERNELVADDR || size < 0) {
      printk_red("%s out of bounds: %p\n", __FUNCTION__, vaddr);
      return -SC_INVALID;
    }
#endif

    return map_get_physical_address(curr_map, (unsigned) vaddr);
  }

  interface void 
  MProtect(unsigned int addr, int len, int prot) 
  {
	Map_setProt(curr_map, addr, len, prot);
  }

  /** Set the number of pages that other processes may map their contents to
      (number of pages that they may 'grant') 

      @param available is an absolute number if >=0 or 
                          an inverse offset if < 0: -5 means increase by 5 pages
   */
  interface void
  Set_GrantPages(unsigned int available) 
  {
	memmap_set_sharepages(available);
  }


  interface unsigned long
  Share_Pages(int pid, unsigned long vaddr, unsigned int npages, int writable)
  {
	return memmap_share_pages(pid, vaddr, npages, writable);
  }
}

