syscall SMR {
  decls __callee__ {
    includefiles { "<nexus/defs.h>", "<nexus/ipd.h>", "<nexus/mem.h>" }
    includefiles { "<nexus/thread-inline.h>" }
  }

  /* NOTE!!!!!

     There is a general robustness issue with these system calls. They
     are allowed to proceed without first verifying that they are
     operating on a SMR. This can potentially lead to unforseen memory
     map changes.
  */
  interface int Get_Bitmap(void *region, int len, int blocksize, unsigned char *bitmap) {
    // Audited 6/3/2006 by ashieh: argument use safe
    /*
      region, len: range is validated to restrict access to dirty bits
      belonging to the application

      len: len is used to drive a galloc (for kbitmap) ; this galloc
      is now checked for memory exhaustion

      blocksize: disallow 0 length to prevent divide by zero. 
      bitmap: written out with poke_user. Return value is checked.
     */
    unsigned char *kbitmap;
    Map *currentmap = nexusthread_current_map();
    int numpgs;
    int i;
    int offset;
    int err = 0;

    if(blocksize == 0) {
      printk_red("0 blocksize!\n");
      return -SC_INVALID;
    }

#if 0
    int blocks, bitmapsize, block;
    MemRegion *m = NULL;
    /* try to use region mapping before dirty bits */
    if((m = ipd_find_region(ipd, (unsigned int)region, len)) != NULL){
      poke_user(currentmap, bitmap, (char *)m->bitmap, m->bitmapsize);
      return;
    }

    /* XXX using dirty bits for this is at page rather than blocksize granularity */
    /* XXX also the dirty bits must be saved if used for anything else */
    blocks = (len + (blocksize - 1))/blocksize;
    bitmapsize = (blocks + 7)/8;
    kbitmap = (unsigned char *)galloc(bitmapsize * sizeof(unsigned char));
    memset(kbitmap, 0, bitmapsize);
#endif

    offset = ((unsigned int)region % PAGESIZE);
    numpgs = (len + offset)/PAGESIZE;

    if(!CHECK_USER_BASELIMIT(region, numpgs * PAGESIZE)) {
      printk_red("invalid base/limit for region during getbitmap!\n");
      return -SC_INVALID;
    }

    kbitmap = (unsigned char *)galloc(numpgs);  
    if(kbitmap == NULL) {
      return -SC_NOMEM;
    }
    int cnt = 0;
    for(i = 0; i < numpgs; i++){
      if(map_isdirty(currentmap, (unsigned int)region + (i * PAGESIZE))){
#if 0
	for(block = max((PAGESIZE * i - offset)/blocksize, 0); 
	    block < (PAGESIZE * (i + 1) - offset + blocksize -1)/blocksize;
	    block++){
	  kbitmap[block/8] |= 1 << (7 - (block % 8));
	}
#endif
	kbitmap[cnt++] = (unsigned int)region + (i * PAGESIZE);
	map_cleardirty(currentmap, (unsigned int)region + (i * PAGESIZE));
      }
    }

    //poke_user(currentmap, bitmap, (char *)kbitmap, bitmapsize);
    kbitmap[cnt++] = 0;
    if(poke_user(currentmap, (unsigned)bitmap, (char *)kbitmap, cnt * sizeof(unsigned int)) != 0) {
      err = -SC_INVALID;
    }
    gfree(kbitmap);
    return err;
  }

  interface unsigned int Remap_RO(char *vaddr, int size, void *timing_addr, unsigned int hint) {
    // Audited 6/3/2006 by ashieh: argument use safe
    /*
      	vaddr, size: verified to be within user address range
	timing_addr: accessed via peek/poke user, return value not checked
     */
    Map *m = nexusthread_current_map();
    unsigned int roaddr, offset;
    int numpgs;
    int dbg = 0;

    offset = ((unsigned)vaddr) % PAGESIZE;
    numpgs = (size + offset + PAGESIZE - 1) / PAGESIZE;

    if(!CHECK_USER_BASELIMIT(vaddr, numpgs * PAGESIZE)) {
      printk_red("invalid base/limit for region during remapro\n");
      return 0;
    }

    if(!CHECK_USER_BASELIMIT(hint, numpgs * PAGESIZE)) {
      hint = USERMMAPBEGIN;
    }

    roaddr = remap_user_page(m, numpgs, (unsigned) vaddr, 1, 1, 0, 1, 0, 0, hint);
			//			(unsigned) vaddr + size);
    if(roaddr == 0){
      printk_red("couldn't remapro 0x%x\n", vaddr);
      return 0;
    }
    if(dbg)
      printk_red("remapping %d pages at 0x%x to 0x%x-0x%x\n", numpgs, vaddr, roaddr, roaddr + PAGESIZE*numpgs);

    return roaddr;
  }

  interface int Unmap_RO(void *vaddr, int size) {
    // Audited 6/3/2006 by ashieh: argument use safe
    /*
      	vaddr, size: verified to lie within user address range
     */
    int numpgs;
    Map *m = nexusthread_current_map();
    unsigned int offset;

    offset = ((unsigned)vaddr) % PAGESIZE;
    numpgs = (size + offset + PAGESIZE - 1) / PAGESIZE;

    if(!CHECK_USER_BASELIMIT(vaddr, numpgs * PAGESIZE)) {
      return -SC_INVALID;
    }
    /* XXX user could crash kernel by unmapping some random thing */
    //printk_red("unmapping 0x%x %d, really %d pages at 0x%x\n", vaddr, size, numpgs, vaddr - offset);
    unmap_pages(m, (unsigned)vaddr - offset, numpgs);
    return 0;
  }

}
