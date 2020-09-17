
#include <nexus/defs.h>
#include <nexus/queue.h>
#include <nexus/mem.h>
#include <nexus/ipd.h>
#include <nexus/thread.h>
#include <nexus/idtgdt.h>
#include <nexus/synch.h>
#include <nexus/synch-inline.h>
#include <nexus/machineprimitives.h>
#include <nexus/initrd.h>
#include <nexus/profiler.h>
#include <nexus/util.h>
#include <nexus/bitmap.h>
#include <nexus/syscall-defs.h>
#include <nexus/mem-private.h>
#include <asm/pgtable.h>

// size of the frametable
// caution: MAXPAGES*PAGESIZE must be 1GB or less
#define MAXPAGES  256000 

#define PAGEDIROFFSET   22
#define PAGETABLEOFFSET 12
#define PAGEOFFSETMASK  0x3ff

unsigned long nexus_max_pfn;

//ensures atomic operations on Maps (map_page, unmap_page)
static Sema memMutex = SEMA_MUTEX_INIT; 
unsigned long nxmem_pages_used;
unsigned long nxmem_pages_total;

/** virtual address map of the kernel process */
Map __kernelMap;
Map *kernelMap = &__kernelMap;

/** table holding metadata on all physical pages ('frames') */
static Page _pages[MAXPAGES];
Page *frameTable = _pages;
u32 *machine_to_phys;

static int __memlvl, __memlvl_lock;
void 
Mem_mutex_lock(void) 
{
  __memlvl = disable_intr();  
  assert(swap(&__memlvl_lock, 1) == 0);	// no recursive calls allowed
  //P(&memMutex);
}

void 
Mem_mutex_unlock(void) 
{
  swap(&__memlvl_lock, 0);
  restore_intr(__memlvl);
  //V(&memMutex);
}

/// the kernel code+data is expected never to exceed 12MB.
//  WARNING: this is NOT enforced anywhere
static unsigned long
last_kernel_boot_page(void) 
{
  return 12 * (1 << 20) / PAGE_SIZE;
}

static unsigned long actual_e820_start;
int maxframenum = 0;

////////  debug output  ////////

/** Scan memory and calculate page ownership for each process */
static void 
mem_print_calc(int *p_util, int *p_total, int *ipd_table, int table_len) 
{
  int i, total, util;

  memset(ipd_table, 0, table_len * sizeof(ipd_table[0]));

  total = 0;
  util = 0;

  Mem_mutex_lock();
  for (i = actual_e820_start / PAGE_SIZE + 1; i < maxframenum; ++i) {
    total++;
    
    if (frameTable[i].ram && frameTable[i].alloc) {
	util++;
	
	if (frameTable[i].owner < table_len)
	  ipd_table[frameTable[i].owner]++;
    }
  }
  Mem_mutex_unlock();
  
  *p_total = total;
  *p_util = util;
}

/** Pretty print memory utilization */
void dump_page_utilization(void){
#define MAX_DUMP_IPD (80)
  Map *map;
  IPD *ipd;
  int table[MAX_DUMP_IPD + 1];
  int util, total, i;

  memset(table, 0, sizeof(table));
  mem_print_calc(&util, &total, table, MAX_DUMP_IPD);

  printk_current("[mem] process utilization. \n"
	 	 "  total: %12d pages\n"
	 	 "  used:  %12d pages\n\n", total, util);
  for (i = 0; i < MAX_DUMP_IPD; i++) {
    if (table[i]) {
      if (i == 0)
	      map = kernelIPD->map;
      else {
	      ipd = ipd_find(i);
	      if (ipd)
		      map = ipd->map;
	      else
		      map = NULL;
      }
      
      // not kernel (and not zombie)
      if (map)
	      printk_current("  process %2d: %7d pages (brk={+%ld,-%ld,=%ld}, mmap={+%ld,>%ld,<%ld,-%ld,=%ld), lost=%ld\n", 
			      i, table[i], 
			      map->account_brk_add, 
			      map->account_brk_del, 
			      map->account_brk_add - map->account_brk_del, 
			      map->account_mmap_add,
			      map->account_mmap_recv,
			      map->account_mmap_send,
			      map->account_mmap_del,
			      map->account_mmap_add + map->account_mmap_recv -
			      (map->account_mmap_send + map->account_mmap_del),
			      map->account_lost);
      else
	      printk_current("  process %2d: %7d pages\n", i, table[i]);
    }
  }
}

////////  page table lookup  ////////

/// Lookup a page directory entry by a virtual address
static struct DirectoryEntry *
vaddr_to_pde(struct Page *pdbr, unsigned long vaddr)
{
	return (DirectoryEntry *) (VADDR(pdbr) + (PDIR_OFFSET(vaddr) * sizeof(DirectoryEntry)));
}

/// Lookup a page directory entry by a virtual address
static struct PageTableEntry *
vaddr_to_pte(struct DirectoryEntry *pde, unsigned long vaddr)
{
	return (PageTableEntry*) ((unsigned long) PHYS_TO_VIRT(pde->physaddr << PAGE_SHIFT) + 
		                 (PTAB_OFFSET(vaddr) * sizeof(PageTableEntry)));
}

PageTableEntry *
fast_virtToPTE(Map *m, unsigned long vaddr, int user, int write)
{
  DirectoryEntry *pde;
  PageTableEntry *pte;
  
  pde = vaddr_to_pde(m->pdbr, vaddr);
  if (unlikely(!pde->present || (user && !pde->user) || (write && !pde->rw)))
    return NULL;
  if (unlikely(pde->bigpage))
    return NULL;
  pte = vaddr_to_pte(pde, vaddr);
  if (unlikely(!pte->present || (user && !pte->user) || (write && !pte->rw)))
    return NULL;

  return pte;
}

/** Translate virtual into physical address
    Mem_mutex MUST be held */
unsigned long
fast_virtToPhys_locked(Map *m, unsigned long vaddr, int user, int write) 
{
  DirectoryEntry *pde;
  PageTableEntry *pte;

  assert((vaddr & (PAGESIZE - 1)) == 0);
  
  if (!m)
    return VIRT_TO_PHYS(vaddr);

  if (user) {
    if (vaddr >= (unsigned) KERNELVADDR)
      ipd_kill(curt->ipd);

#ifdef __NEXUSXEN__
    // Allow transfers to any pages below KERNELVADDR in Xen mode
    if (m->owner && m->owner->type == XEN)
      user = 0;
#endif
  }

  pde = vaddr_to_pde(m->pdbr, vaddr);
  if (unlikely(!pde->present || (user && !pde->user) || (write && !pde->rw)))
    return 0;
  if (unlikely(pde->bigpage))
    return (pde->physaddr << PAGE_SHIFT) | (vaddr & ((1 << PDIR_SHIFT) - 1));
  pte = vaddr_to_pte(pde, vaddr);
  if (unlikely(!pte->present || (user && !pte->user) || (write && !pte->rw)))
    return 0;

  return pte->pagebase << PAGE_SHIFT;
}

/** Wrapper around fast_virtToPhys_locked that acquires lock */
unsigned long
fast_virtToPhys(Map *m, unsigned long vaddr, int user, int write)
{
    int ret;

    //assert(check_intr() == 1);
    Mem_mutex_lock();
    ret = fast_virtToPhys_locked(m, vaddr, user, write);
    Mem_mutex_unlock();

    return ret;
}

////////  physical page allocation  ////////

/** In frametable, mark pages as owned by process pid */
static void 
reserve_pages(int pgstart, int numpgs) 
{
    Page *page;
    int j;

    for (j = 0; j < numpgs; j++) {
      page = frameTable + pgstart + j;
      assert(page->alloc == 0);
      page->alloc = 1;
    }

    nxmem_pages_used += numpgs;
}

/** Acquire a physical page
  
    Warning: starts to acquire from physical address 0, regardless
    of destination (kernel or user). Since the physical memory is 
    mapped + KERNELVADDR into virtual address, it is possible
    to allocate so many pages in this mapping for user pages that
    we run out of pages in the statically mapped range
  
    Zeroes pages

    MUST call page_get on all freshly allocated pages
         either directly, or through Map_insert...

    MUST call with memMutex held 
 */
static Page *
nallocate_pages(int numpgs) 
{
  Page *pages;
  static int hint;
  unsigned long region;

  /** find a region of len pages between frames start and end 
      @return the region or -1 on failure */
  int find_region(int start, int end, int len)
  {
	  unsigned long counter;
	  int region, i;
	
	  counter = 0;
	  region = start;

	  for (i = start; i < end; i++) {
	    if (!frameTable[i].alloc && likely(frameTable[i].ram)) {
	      counter++;
	    }
	    else {
	      counter = 0;
	      region = i + 1;
	    }

	    if (counter == numpgs)
	      return region;
	  }
	  return -1;
  }

  // heuristic-driven search: start from the hint and optionally wrap
  region = find_region(hint, maxframenum, numpgs);
  if (unlikely(region == -1))
	  region = find_region(0, maxframenum, numpgs);
  if (unlikely(region == -1)) {
    // OOM: fail hard
    printk_current("Error. Out of memory (hint=%d max=%d req=%d)\n",
      	           hint, maxframenum, numpgs);
    // Release mutex so that fill_page_utilization() can execute
    Mem_mutex_unlock();
    //dump_page_utilization();
    dump_stack_current(NULL);
    nexuspanic();
    Mem_mutex_lock();
  }

  // reserve and save hint for next run
  reserve_pages(region, numpgs);
  hint = region + numpgs;
  
  // zero pages
  pages = &frameTable[region];
  pagememzero_n(VADDR(pages), numpgs);
  
  return pages;
}

/** Do NOT call directly. Use page_put instead
    MUST be called with memMutex held */
int 
nfree_page(Page *page) 
{

  assert(page - frameTable < maxframenum); // should be <= ?
  assert(page->alloc == 1);
  assert(page->refcnt == 0);

  // more users? 
#ifdef __NEXUSXEN__
  if (!FT_ISRDWR(page->type))
    // not yet capable of freeing these pages
    nexuspanic();

  if (machine_to_phys)
    machine_to_phys[PADDR(page) / PAGE_SIZE] = 0;
#endif

  page->alloc = 0;
  nxmem_pages_used--;
  return 0;
}


////////  page accounting  ////////

static int 
is_e820_page(unsigned int base) 
{
  return (unsigned)base < (unsigned)maxframenum;
}

void
page_get(struct Page *page, Map *map)
{
	assert(map);
	assert(page->refcnt >= 0);
	page->refcnt++;

	// first user is 'owner'
	// with page sharing, ownership is a vague term
	if (map->owner && !page->owner)
		page->owner = map->owner->id;

	map->numpgs++;
}

void
page_put(struct Page *page, Map *map)
{
	assert(map);
	//XXX reuse assert(page->refcnt > 0);
	assert(page->alloc == 1);
	
	if (map->owner && page->owner == map->owner->id)
		page->owner = 0;

	page->refcnt--;
	if (!page->refcnt) {
		nfree_page(page);
		assert(page->alloc == 0);
	}

	map->numpgs--;
}


////////  virtual memory map  ////////

void 
Map_setAnonCleanup(Map *space, IPD *owner) 
{
#ifdef __NEXUSXEN__
  space->owner = owner;
#endif
}

/** Create a copy of a virtual address space.
    Completely overwrites original map. 
    used in fork() */
int
Map_copyRW(Map *newmap, Map *source_map) 
{
  DirectoryEntry *pde, *src_pde;
  PageTableEntry *pte, *src_pte;
  unsigned long ptvirt, ptphys, src_ptphys;
  unsigned long data_virt, data_phys, src_data_phys;
  Page *ptpage, *src_ptpage, *src_data_page;
  int i, j, lvl;

  // ensure that the process(es) using source_map do not run
  lvl = disable_intr();

  // for each page directory entry below shared kernel memory
  for (i = 0; i < PDIR_OFFSET(PHYPAGEVADDR); i++) {
    
    // get PDE pointers
    src_pde = &((DirectoryEntry *) VADDR(source_map->pdbr))[i];
    pde =     &((DirectoryEntry *) VADDR(newmap->pdbr))[i];

    // copy PDE contents
    *pde = *src_pde;		
    if (!src_pde->present)
      continue;
    
    // create new page table page
    ptvirt = Map_alloc(newmap, 1, 1, 0, vmem_heap);
    ptphys = fast_virtToPhys_locked(newmap, ptvirt, 0, 0);
    ptpage = PHYS_TO_PAGE(ptphys);
    pde->physaddr = ptphys >> PAGE_SHIFT;

    src_ptphys = src_pde->physaddr << PAGE_SHIFT;
    src_ptpage = PHYS_TO_PAGE(src_ptphys);

    // for each page table entry
    for (j = 0; j < PTABLE_ENTRIES; j++) {

      // get PTE pointers
      pte =     &((PageTableEntry *) VADDR(ptpage))[j];
      src_pte = &((PageTableEntry *) VADDR(src_ptpage))[j];
      
      // copy PTE contents
      *pte = *src_pte;		
      if (!pte->present) 
        continue;

      src_data_phys = src_pte->pagebase << PAGE_SHIFT;
      src_data_page = PHYS_TO_PAGE(src_pte->pagebase << PAGE_SHIFT);
      if (!src_data_page->ram)
          continue;

	  // allocate page
      data_virt = Map_alloc(newmap, 1, pte->rw, pte->user, vmem_heap);
      data_phys = fast_virtToPhys_locked(newmap, data_virt, 0, 0);
      pte->pagebase = data_phys >> PAGE_SHIFT;
      
	  // copy data
	  memcpy((void *) PHYS_TO_VIRT(data_phys), 
             (void *) PHYS_TO_VIRT(src_data_phys), 
             PAGE_SIZE);
    }
  }

  restore_intr(lvl);
  return 0;
}

Page *
PDBR_getPagetable(Page *pdbr, unsigned int vaddr) 
{
  DirectoryEntry *pde; 

  pde = vaddr_to_pde(pdbr, vaddr);
  assert(pde->present);

  return &frameTable[pde->physaddr];
}

DirectoryEntry *
Map_getPDE(Map *m, unsigned int vaddr) 
{
  return vaddr_to_pde(m->pdbr, vaddr);
}

/** Remove an entire virtual address space  */
static void 
Map_freeAll_inner(Map *m)
{
  DirectoryEntry *pde;
  PageTableEntry *pte; 
  Page *page;
  void *ptepage;
  int i, j;

  // read CR3 pointer
  assert(m->pdbr);
  pde = (void *) VADDR(m->pdbr);
  
  // traverse the page directory up until the shared region (see Map_new)
  for (i = 0; i < NEXUS_START >> PDIR_SHIFT; i += sizeof(DirectoryEntry)) {
    pde++;
    if (pde->present && pde->user) {

      // fix if we start using big pages
      if (pde->bigpage)
      	nexuspanic();

      // traverse the pagetable
      ptepage = (void *) PHYS_TO_VIRT(pde->physaddr << PAGE_SHIFT);
      for (j = 0; j < PAGE_SIZE; j += sizeof(PageTableEntry)) {
        pte = ptepage + j;

        // remove the page (if user's)
        if (pte->present && pte->user && is_e820_page(pte->pagebase))
            page_put(PHYS_TO_PAGE(pte->pagebase << 12), m);
      }

      // release page table
      page_put(VIRT_TO_PAGE(ptepage), m);
    }
  }
  
  // release page directory    
  page_put(m->pdbr, m);
  m->pdbr = NULL;

#if 0
  // guard against memleaks
  if (m->numpgs)
    printkx(PK_MEM, PK_INFO, "[mem] pid=%d %d pages lost\n", 
	    m->owner->id, m->numpgs);
#endif
}

/** Release all pages in the map
    Unlike Map_free, does not update the virtual address pagetables, 
    but only releases refcount on the physical pages. */
static void 
Map_freeAll(Map *m) 
{
  Mem_mutex_lock();
  Map_freeAll_inner(m);
  Mem_mutex_unlock();

#ifdef __NEXUSXEN__
  // walk all (slow!) frames and deallocate those belonging to m
  if (0 /* m->clean_anon_pages */) {
    Page *page;
    int i;
    
    assert(m->owner); // only true for Xen processes
    Mem_mutex_lock();
    for (i = 0; i < maxframenum; i++) {
      
      page = &frameTable[i];
      if (page->alloc && page->owner == m->owner->id)
	page_put(page, m);
    }
    Mem_mutex_unlock();
  }
#endif

}

static void
Map_init(Map *map, IPD *ipd)
{
  memset(map, 0, sizeof(Map));

  map->hint.brk    = USERHEAPBEGIN;
  map->hint.mmap   = USERMMAPBEGIN;
  map->hint.dev    = PHYPAGEVADDR;
  map->hint.kernel = KERNELVADDR;

  map->owner = ipd;
}

/** MUST be called without memMutex */
Map *
Map_new(IPD *ipd) 
{
  void * vaddr_pdir, *vaddr_pdir_kern;
  unsigned long vaddr_off, vaddr_len;
  Map *map;

  map = galloc(sizeof(Map));
  Map_init(map, ipd);

  // initialize page directory
  Mem_mutex_lock();
  map->pdbr = nallocate_pages(1);
  page_get(map->pdbr, map);
   
  // copy pagedir entries of shared kernel region: everything from NEXUS_START
  // these pages are not reference counted (using page_get/page_put)
  // and must therefore NOT be freed on Map_free
  
  vaddr_pdir      = (void *) VADDR(map->pdbr);
  vaddr_pdir_kern = (void *) VADDR(kernelMap->pdbr);
  vaddr_off = NEXUS_START >> PDIR_SHIFT;
  vaddr_len = PAGE_SIZE - vaddr_off;
  memcpy(vaddr_pdir + vaddr_off, vaddr_pdir_kern + vaddr_off, vaddr_len);
  
  Mem_mutex_unlock();
  return map;
}

void 
Map_del(Map *m) 
{
  Map_freeAll(m);
  gfree(m);
}

Page *
Map_getRoot(Map *m) 
{
  return m->pdbr;
}

////////  virtual address space find/add/del   ////////

/* Search for a free virtual address space region starting from vaddrhint.
 
   Locking: call with memMutex held

   @param vaddr a hint where to start looking
   @param user, if set, will only return regions that are user accesible
   @param writer, if set, will only return regions that are user writable 
 
   @return user virtual address on success or 0 on failure */
static unsigned long
Map_findHole(Map *m, unsigned long vaddr, int n, int user, int writable)
{
  DirectoryEntry *pde;
  PageTableEntry *pte;
  unsigned long vpage, basevpage;

  if (!m)
    return 0;
  
  // no pdbr, then a new map and thus room at vaddrhint */
  if (!m->pdbr)
    return vaddr;
  
  // Operate on pages rather than addresses to avoid overflow
  vpage = basevpage = vaddr >> PAGE_SHIFT;

  // Check each page in sequence
  while (vpage < basevpage + n) {

    if (basevpage + n > PAGE_MAX)
	    return 0;

    // PDE 
    pde = vaddr_to_pde(m->pdbr, vpage << PAGE_SHIFT);
    if (!pde->present) {
      vpage = (PDIR_OFFSET(vpage * PAGESIZE) + 1) * PTABLE_ENTRIES;
      continue;
    }
    // large pages are not available for now
    if (pde->bigpage) {
      basevpage = vpage = (vpage + PDIR_ENTRIES - 1) / PDIR_ENTRIES * PDIR_ENTRIES;
      continue;
    }
    // access control must be at least as permissive as request to avoid traps
    if (m != kernelMap &&
        ((user && !pde->user) ||
	(writable && !pde->rw))) {
      basevpage = vpage = (PDIR_OFFSET(vpage * PAGESIZE) + 1) * PTABLE_ENTRIES;
      continue;
    }

    // PTE
    pte = vaddr_to_pte(pde, vpage << PAGE_SHIFT);
    if (pte->present) { 
      basevpage = vpage = vpage + 1;
      continue;
    }

    vpage++;
    
    // special case: search through memory
    if (unlikely(vpage == 0))
	    return 0;
  }

  return basevpage * PAGESIZE;
}

/** Insert a page at a given virtual memory address and insert refcount
    MUST be called with memMutex held */
unsigned long
Map_insertAt(Map *m, unsigned long paddr, int writable, int user, 
             int uncached, int writethrough, unsigned long vaddr)
{
  Page *page, *ptpage;
  DirectoryEntry *pde;
  PageTableEntry *pte;

  assert(m->pdbr);
  pde = vaddr_to_pde(m->pdbr, vaddr);

  // PDE
  if (!pde->present) {
    // allocate page table page
    ptpage = nallocate_pages(1);
    page_get(ptpage, m);

    pde->physaddr = (PADDR(ptpage) >> 12) & 0xfffff; // only the lower 20 bits are needed
    pde->rw = 1; 	// use only PTE for access permissions (XXX do we give user write access?? that would be BAD)
    pde->user = 1;	// use only PTE for access permissions
    pde->uncached = uncached;		// XXX does this really depend on the PTE setting?
    pde->writethrough = writethrough;
    pde->present = 1;

#ifdef __NEXUSXEN__
    if (0 /* request_for_ptable */) { // XXX reneable creation of PTABLE element
      ptpage->type = FT_PTABLE;
      ptpage->verified = 1;
    }
#endif
  } 
  else {
    if (pde->bigpage) {
      printkx(PK_MEM, PK_WARN, "[mem] bigpage, don't know what to do\n");
      return 0;
    }
    
    assert(!writable || pde->rw);
    assert(!user || pde->user);
  }

  // PTE
  pte = vaddr_to_pte(pde, vaddr);
  assert(!pte->present);
  
  pte->pagebase = (paddr >> 12) & 0xfffff;	// only need to store upper 20 bits
  pte->rw = writable;
  pte->user = user;
  pte->uncached = uncached;
  pte->writethrough = writethrough;

  // mark page as in use
  pte->present = 1;

  // HACK: this occurs with memory before video is initialized (XXX FIX)
  if (!PHYS_TO_PAGE(paddr)->alloc) {
  	PHYS_TO_PAGE(paddr)->alloc = 1;
	// ~1740 messages: printk("[mem] insert of unallocted page\n");
  }

  page_get(PHYS_TO_PAGE(paddr), m);
  return vaddr;
}

/** Call Map_insertAt for a range of pages 
    MUST call with memMutex held */
static void
Map_insertAtRange(Map *m, Page *pages, int npages, int writable, int user, 
		  unsigned long vcur)
{
  int i, nocache;

  // set memory to cacheable unless it is device mem
  if (vcur >= PHYPAGEVADDR && vcur < KERNELVADDR)
	  nocache = 1;
  else
	  nocache = 0;

  // insert 
  for (i = 0; i < npages; i++) {
    if (Map_insertAt(m, PADDR(pages), writable, user, 
		     nocache, nocache, vcur) != vcur) 
      printkx(PK_MEM, PK_WARN, "[mem] map physical failed\n");

    pages++;
    vcur += PAGESIZE;
  }
}

/** Insert a range of pages into a memory map near a virtual address
    Call WITHOUT Mem_mutex held

    @param vaddr must hold a hint where to insert; it may NOT be NULL.
    @return the virtual address of the new range */
unsigned long
Map_insertNear(Map *m, Page *pages, unsigned int npages, 
	       int writable, int user, enum vmemtype type) 
{
  unsigned long *vhint, vstart, vaddr_min, vaddr_max;

  // kernel logical allocation is not needed: use VADDR/PHYS_TO_VIRT
  assert(type != vmem_kernel);

  // select memory region to start searching in
  switch (type) {
  	case vmem_brk:		vhint = &m->hint.brk; break;
  	case vmem_heap:		vhint = &m->hint.mmap; break;
	case vmem_dev:		vhint = &m->hint.dev; break;
	case vmem_kernel:	vhint = &m->hint.kernel; break;
	default: 		nexuspanic(); return 0;
  };

  // set virtual range boundaries (brk, heap, ....)
  // allocation may not bleed into neighboring regions
  if (*vhint >= KERNELVADDR) {
	  vaddr_min = KERNELVADDR;
	  vaddr_max = (unsigned long) -1;
  }
  else if (*vhint >= PHYPAGEVADDR) {
	  vaddr_min = PHYPAGEVADDR;
	  vaddr_max = KERNELVADDR - 1;
  }
  else if (*vhint >= USERMMAPBEGIN) {
	  vaddr_min = USERMMAPBEGIN;
	  vaddr_max = PHYPAGEVADDR - 1;
  }
  else {
	  vaddr_min = USERHEAPBEGIN;
	  vaddr_max = USERMMAPBEGIN - 1;
  }

  // find a free virtual memory range
  Mem_mutex_lock();
  // 1. try to find a hole from allocation hint pmwards
  vstart = Map_findHole(m, *vhint, npages, user, writable);
  if (!vstart)
	  return 0;
  
  if (!vstart || vstart + (npages << PAGE_SHIFT) > vaddr_max ) {
	  
	  // 2. nothing found? try to find from start of region (wrap)
	  vstart = Map_findHole(m, vaddr_min, npages, user, writable);
	  if (!vstart || vstart + (npages << PAGE_SHIFT) > vaddr_max ) {
		  Mem_mutex_unlock();
	  	  printkx(PK_MEM, PK_WARN, "[mem] map exhausted\n");
	  	  return 0;
	  }
  }

  // insert pages in virtual memory map
  Map_insertAtRange(m, pages, npages, writable, user, vstart);
  flushTLB();
  Mem_mutex_unlock();
  
  // update hint
  *vhint = vstart + (npages << PAGE_SHIFT);
  return vstart;
}

/** Allocate new pages and map them into the given map.
 
    NB: currently, allocation fails if no physically contiguous region 
        of npages can be found. This is not necessary: the virtually
	contiguous region can be built from physically discont. sections.
 */
unsigned int
Map_alloc(Map *m, int npages, int writable, int user, enum vmemtype type)
{
  Page *pages;

#if 0
#ifndef NDEBUG
  // kernel heap is only accessible for threads belonging to process 0
  if (m == kernelMap && curt->ipd != kernelIPD) {
	  printk_red("BUG: kernel heap alloc in process [%d] %s\n", 
		     curt->ipd->id, curt->ipd->name);
	  nexuspanic();
  }
#endif
#endif

  // allocate
  Mem_mutex_lock();
  pages = nallocate_pages(npages);
  Mem_mutex_unlock();
 
  // kernel virtual (heap) causes instability. use logical for now
  // XXX fix properly
  if (m == kernelMap && type == vmem_heap)
	  type = vmem_kernel;

  if (type == vmem_kernel) {
	  // kernel logical: no map operation, but get pages
	  int i;

	  for (i = 0; i < npages; i++)
		  page_get(pages + i, kernelMap);
 	  return VADDR(pages);
  }
  else
  	  // virtual memory: add to map (and get pages)
	  return Map_insertNear(m, pages, npages, writable, user, type);
}

/** Allocate a single page and insert at a fixed virtual location */
unsigned int
Map_alloc_fixed(Map *map, int npages, int writable, int user, unsigned long vaddr)
{
  Page *pages;

  // only support user virtual memory
  assert(vaddr < KERNELVADDR);
  assert(map && map != kernelMap);

  // allocate
  Mem_mutex_lock();
  pages = nallocate_pages(npages);
  
  // insert into virtual memory
  Map_insertAtRange(map, pages, npages, writable, user, vaddr);
  Mem_mutex_unlock();

  return vaddr;
}

/** Remove a page from a virtual memory region and decrease refcount
    Inverse of Map_insertAt

    MUST be called with memMutex held */
int 
Map_remove(Map *m, unsigned int vaddr) 
{
  DirectoryEntry *pde;
  PageTableEntry *pte;
  Page *page;
 
  // kernel virtual or logical?
  if (vaddr < KERNELVADDR) {
	  // lookup physical page before removing virtual mapping  
	  page = PHYS_TO_PAGE(fast_virtToPhys_locked(m, vaddr, 0, 0));
	  
	  // remove virtual mapping
	  assert(m && m->pdbr);
	  pde = vaddr_to_pde(m->pdbr, vaddr);
	  assert(pde->present);
	  pte = vaddr_to_pte(pde, vaddr);
	  assert(pte->present);
  	  pte->present = 0;
  
  }
  else {
	  // no map to remove from
	  page = VIRT_TO_PAGE(vaddr);
  }

  // release physical page
  page_put(page, m);
  
  return 0;
}

/** Remove a mapping and free the underlying physical pages 
    Inverse of Map_alloc 
 
    NB: physical pages are freed (even though not shown explicitly)
        because Map_remove decrements reference count */
void 
Map_free(Map *m, unsigned long vaddr, int npages) 
{
  int i;

  Mem_mutex_lock();
  for (i = 0; i < npages; i++) {
    Map_remove(m, vaddr);
    vaddr += PAGE_SIZE;
  }
  Mem_mutex_unlock();

  flushTLB();
}


////////  [unstructured ...] ////////

/** Allocate shared kernel memory: 
    in the virtual range above KERNELVADDR
    and shared by all tasks

    Similar to Map_Alloc, but 
    - using a different vaddr range
    - no need to call Map_insert, as the mapping is fixed

    May NOT be called from interrupt context (because allocation can block)
    Exception: called during OS init when interrupts are still disabled
               that is the reason for the odd checks around Mem_mutex_lock
 */
void *
getKernelPages(int numpgs)
{
  Page *pages;
  int intlevel, i;

  // lock
  intlevel = check_intr();
  if (intlevel) Mem_mutex_lock();
  
  // allocate
  pages = nallocate_pages(numpgs);
  for (i = 0; i < numpgs; i++)
	page_get(pages + i, kernelMap);
  
  // unlock
  if (intlevel) Mem_mutex_unlock();
  kernelMap->numpgs += numpgs;

  return (void *) VADDR(pages);
}

/** Release shared kernel memory */
void 
freeKernelPages(void *vaddr, int numpgs)
{
  Page *pages;
  int i, lvl;

  assert(vaddr >= (void *) KERNELVADDR);
  kernelMap->numpgs -= numpgs;
  pages = VIRT_TO_PAGE(vaddr);
  
  lvl = disable_intr();
  for (i = 0; i < numpgs; i++)
	page_put(pages + i, kernelMap);
  restore_intr(lvl);
}

#ifdef __NEXUSXEN__
int freeKernelPages_Xen(IPD *owner, u32 paddr, int numpgs) 
{
  return 0;
}
#endif

/** Give another process (the one with pid) access to pages.
    Instead of temporarily storing the grant permission into a kernel list,
    this call immediately adds the mapping to the receiving process, iff
    that process has pages available for granting (ipd->grantpages != 0).

    WARNING: a malicious process C could guess the vaddr that a page from
    page A is mapped to in receiving process B. Depending on the higher
    layer protocol, it could then try to tell B to give it access (e.g.,
    write the block to its address space). Currently this hole is not
    exploitable, but watch out

    @return the virtual address in the receiving process
            or 0 on failure 
 */
unsigned long
memmap_share_pages(int pid, unsigned long vaddr, unsigned int npages, int writable)
{
	unsigned long paddr, vaddr_oth;
       	IPD *other;
	Map *map;

	map = nexusthread_current_map();
	assert(map && map != kernelMap);

	if (vaddr & (PAGE_SIZE - 1)) {
		printkx(PK_MEM, PK_DEBUG, "[mem] unaligned page grant denied\n");
		return 0;
	}

	other = ipd_find(pid);
	if (!other || other == kernelIPD) {
		printkx(PK_MEM, PK_DEBUG, "[mem] illegal process grant denied\n");
		return 0;
	}

	// verify that the process has room for grantable pages
	P(&other->mutex);
	if (other->grantpages < npages) {
		V(&other->mutex);
		printkx(PK_MEM, PK_DEBUG, "[mem] no room for grant\n");
		return 0;
	}
	other->grantpages -= npages;
  	other->map->account_mmap_recv += npages;
	V(&other->mutex);

	// find process map
	paddr = fast_virtToPhys(map, vaddr, 1, 0);
	if (!paddr) {
		printkx(PK_MEM, PK_DEBUG, "[mem] illegal address for sharing\n");
		return 0;
	}
	
	// insert into process map
	vaddr_oth = Map_insertNear(other->map, PHYS_TO_PAGE(paddr), npages, writable, 1, vmem_heap);
	if (!vaddr_oth) {
		// failure clean up 
		P(&other->mutex);
		other->grantpages += npages;
		other->map->account_mmap_recv -= npages;
		V(&other->mutex);
		printkx(PK_MEM, PK_DEBUG, "[mem] grant insert failed\n");
		return 0;
	}

	return vaddr_oth;
}

void
memmap_set_sharepages(int available)
{
	assert(curt && curt->ipd);
	
	// odd convention: < 0 means increase, >=0 means set 
	P(&curt->ipd->mutex);
	if (available < 0)
		curt->ipd->grantpages += -available;
	else
		curt->ipd->grantpages = available;
	V(&curt->ipd->mutex);
}

void Map_setProt(Map *m, unsigned int orig, int len, unsigned int prot){
  DirectoryEntry *pde;
  PageTableEntry *pte;
  unsigned int vaddr;

  for(vaddr = orig; vaddr < orig + len; vaddr += PAGESIZE){
    pde = vaddr_to_pde(m->pdbr, vaddr);
    if (pde->bigpage) {
      printk_red("Map_setProt(%p,%d) is big page!\n", orig, len);
      assert(0);
    }

    pte = vaddr_to_pte(pde, vaddr);
    pte->rw = (prot & PROT_WRITE) ? 1 : 0;
    if ((prot & PROT_READ) || pte->rw)
      pte->present = 1;
  }
  flushglobalTLB();
}

void Map_setPDBR(Map *m, Page *newPDBR) {
#ifdef __NEXUSXEN__
  // This is only supported for Xen IPDs
  m->pdbr = newPDBR;
#endif
}

/** On a context switch to a user thread, point the CR3 register 
    to that process's correct pagetables */
void 
Map_activate(Map *m, BasicThread *ut) 
{
  assert(m->pdbr);
  
  writecr3((PADDR(m->pdbr) & PAGE_MASK));
  
  // save curr_map for nexusthread_current_map()
  if (m != kernelMap)
    curr_map = m;
  else
    curr_map = NULL;

#ifdef __NEXUSXEN__
  if (unlikely(nexusthread_isXen(ut)))
    thread_Xen_vLDT_writeReal(ut);
#endif
}

/** On a switch to a kernel thread, 
    point the CR3 register to the kernelMap pagetable */
void Map_deactivate(void) {
  curr_map = kernelMap;
  writecr3((PADDR(kernelMap->pdbr) & PAGE_MASK));
}


////////  memcpy between user and kernel  ////////

/** Given a virtual address, find the corresponding physical address 
    Called by device drivers WITHOUT Mem_mutex and NOT in interrupt context */
unsigned int 
map_get_physical_address(Map *m, unsigned int vaddr) 
{
  unsigned long pg_off, pg_start;

  pg_off = vaddr % PAGESIZE;
  pg_start = vaddr - pg_off;

  return fast_virtToPhys(m, pg_start, 0, 0) + pg_off;
}

/** Translate a user virtual address to a kernel virtual address 
    Call with Mem_mutex held */
void *
Map_uvaddr_to_kvaddr(Map *map, void *uvaddr)
{
    unsigned long frame, page, p_off;

    if (!map || map == curr_map)
      return (void *) uvaddr;

    // split address in page address and page offset
    p_off = (unsigned long) uvaddr & (PAGESIZE - 1);
    page =  (unsigned long) uvaddr - p_off;

    // get the physical frame
    frame = fast_virtToPhys_locked(map, page, 0, 0);
    if (!frame)
        return (void *) -1;

    // return kernel virtual address
    return (void *) PHYS_TO_VIRT(frame) + p_off;
}

/** Transfer data between any pair of user or kernel address spaces.
    Map is the map to which a virtual address belongs, or 
           NULL for kernel logical addresses (>= KERNELVADDR)

    Copy based method */
int 
transfer(Map *m_dst, void *uv_dst, 
	 Map *m_src, const void *uv_src, int size)
{
  void *src_vaddr, *dst_vaddr;
  unsigned long src_off, dst_off, len, origsize = size;

  // Fast paths: all in (kernel or current)
  if ((!m_dst || m_dst == curr_map) && 
      (!m_src || m_src == curr_map)) {
    memcpy(uv_dst, uv_src, size);
    return 0;
  }

  Mem_mutex_lock();
  while (size) {
    // translate user virtual addresses to kernel addresses
    src_vaddr = Map_uvaddr_to_kvaddr(m_src, (void *) uv_src);
    dst_vaddr = Map_uvaddr_to_kvaddr(m_dst, uv_dst);
    if (unlikely(src_vaddr == (void *) -1 || dst_vaddr == (void *) -1)) {
      printk("Copy failed #1\n");
      Mem_mutex_unlock();
      return -1;
    }

    // calculate maximal length without crossing page boundaries
    src_off = (unsigned long) uv_src & (PAGE_SIZE - 1);
    dst_off = (unsigned long) uv_dst & (PAGE_SIZE - 1);
    len = nmin(PAGE_SIZE - src_off, PAGE_SIZE - dst_off);
    len = nmin(len, size);

    if (!len)
      break;

    // copy data
    memcpy((char *) dst_vaddr, (char *) src_vaddr, len);

    uv_src += len;
    uv_dst += len;
    size -= len;
  }
  Mem_mutex_unlock();
  
  return 0;
}

////////  init ////////

#include <asm/e820.h>

void zap_low_pages(void){
  __u32 *pdiraddr, *pde, vaddr;

  pdiraddr = (unsigned int *)PHYS_TO_VIRT(readcr3() & 0xfffff000);

  for (vaddr = 0; vaddr < KERNELVADDR; vaddr += PAGESIZE * 1024) {
    pde = &pdiraddr[vaddr >> PDIR_SHIFT];
    *pde = 0;
  }
  flushglobalTLB();
}

/** Initialize the pagetable of the initial kernel task */
void pagetable_init(void){
  DirectoryEntry *pde;
  unsigned int *dirbase, *direntry;
  unsigned int offset;
  unsigned long vaddr, end;

  dirbase = (unsigned int *) swapper_pg_dir;

  kernelMap->pdbr = PHYS_TO_PAGE(VIRT_TO_PHYS(swapper_pg_dir));
  kernelMap->pdbr->alloc = 1;

  if (nexus_max_pfn > 0x40000000)
	  nexuspanic();

  end = PHYS_TO_VIRT(nexus_max_pfn);
  direntry = dirbase + (KERNELVADDR >> 22);

  // enable large page and selective TLB flush support
  set_in_cr4(X86_CR4_PSE);
  set_in_cr4(X86_CR4_PGE);
  boot_cpu_data.wp_works_ok = 1;

  // setup all virtual memory from KERNELVADDR up until 4GB
  for (offset = (KERNELVADDR >> 22); offset < 1024 /* 4GB */ ; offset++) {
    vaddr = offset << 22;	// shift by 4MB
    if (end && vaddr >= end)
	    break;

    // initialize the 4MB kernel pagedir. 
    // This code is not very legible, but the PDE is filled in correctly
    // see for instance http://valhalla.bofh.pl/~l4mer/WDM/secureread/pde-pte.htm for PDE layout
    *direntry = (VIRT_TO_PHYS(vaddr)) | (1 << 8) | (1 << 7) | (1 << 6) | (1 << 5) | (1 << 1) | 1;
    direntry++;
  } 

  zap_low_pages(); /* call is moved to arch/i386/setup.c */
}

void 
nexus_mem_init(void) 
{
  unsigned long framenum, start, end;
  extern char _end;
  int i,j;

  // initialize the frame table
  nexus_max_pfn = 0;
  memset(frameTable, 0, MAXPAGES * sizeof(struct Page));

#ifdef __NEXUSXEN__
  for (i=0; i < MAXPAGES; i++)
	  frameTable[i].type = FT_NRDWR;
#endif

  //use map copied from BIOS e820
  for (i = 0; i < e820.nr_map; i++) {

    /* RAM? */
    if (e820.map[i].type != E820_RAM)
      continue;

    start = max((unsigned long)round((e820.map[i].addr + PAGESIZE - 1), PAGESIZE),
		(unsigned long)round((VIRT_TO_PHYS(&_end) + PAGESIZE - 1), PAGESIZE));   //round up
    end = min((unsigned long)round((e820.map[i].addr + e820.map[i].size), PAGESIZE),
			(unsigned long)(MAXPAGES*PAGESIZE)); //round down

    if (!actual_e820_start)
      actual_e820_start = start;

    for (j = start; j < end; j += PAGESIZE) {
      framenum = j / PAGESIZE;
      frameTable[framenum].ram = 1;
      maxframenum = max((unsigned long)maxframenum, framenum);
      nxmem_pages_total++;
    }

    if (end > nexus_max_pfn)
      nexus_max_pfn = end;
  }

  // mark physical pages that hold kernel unavailable for nallocate_..
  reserve_pages(0, last_kernel_boot_page());

  // mark physical pages that hold initrd unavailable for nallocate_..
  if (!initrd_start || initrd_start + initrd_size > PHYS_TO_VIRT(nexus_max_pfn)) {
	  // initrd goes beyond end of memory -- ignore it
	  initrd_start = 0;
  } else {
	  start = VIRT_TO_PHYS(initrd_start) / PAGE_SIZE;
	  end = (VIRT_TO_PHYS(initrd_start) + initrd_size + PAGE_SIZE - 1)/PAGE_SIZE;
	  reserve_pages(start, end - start + 1);
  }

  Map_init(kernelMap, kernelIPD);
  pagetable_init();
}

#ifdef __NEXUSXEN__

// page lookup by framenumber
Page *
Page_Xen_fromMFN_checked(__u32 mfn) 
{
  if (mfn >= maxframenum) {
    printk_red("bad mfn %u\n", mfn);
    return NULL;
  }
  return &frameTable[mfn];
}

Page *
Page_Xen_fromVirt_checked(Map *m, __u32 vaddr) 
{
  __u32 paddr;
 
  paddr = fast_virtToPhys(m, vaddr, 0, 0);
  if (!paddr) 
	  return NULL;

  return Page_Xen_fromMFN_checked(paddr >> PAGE_SHIFT);
}


/** Allocate Xen's machine-to-physical lookup table */
void xen_mem_init(void) 
{
  int numpages;
  
  numpages = XEN_MPT_LEN / PAGE_SIZE;

  machine_to_phys = getKernelPages(numpages);
  memset(machine_to_phys, 0, numpages);
}

/** Is a physical page accessible from userspace? */
static int 
Page_isKernelExport(Page *page) 
{
  __u32 paddr;
 
  paddr = PADDR(page);

  // nexustime page may be accessed
  if (paddr == VIRT_TO_PHYS(nexustime_page))
	  return 1;

  // machine-to-physical table may be accessed
  if (paddr >= VIRT_TO_PHYS(machine_to_phys) && 
      paddr < VIRT_TO_PHYS(machine_to_phys + XEN_MPT_LEN))
	  return 1;

  return 0;
}

int Page_checkXenPermissions(Page *page, u32 perm) {
  int result = 1;
  IPD *ipd = nexusthread_current_ipd();

  assert(ipd);

  // Any page is readable to its owner
  if(perm & PERM_READ) {
    if( Page_isKernelExport(page) ) {
      // OK to map in nexustime page
      result = result && 1;
    } else if(ipd->id != page->owner) {
      result = 0;
    }
  }
  // Only RDWR pages are writable
  if(perm & PERM_WRITE) {
    if(ipd->id != page->owner) {
      result = 0;
    }
    if(page->type != FT_RDWR) {
      result = 0;
    }
  }
  // Removed PIN permission, since it is not clean to do the full check here; rather, we do this in Page_pinToType()
  return result;
}

int verify_pte(__u32 val) {
  // offset is ignored
  PageTableEntry *pte = (PageTableEntry *)&val;
  if (pte->present) {
    if (pte->globalpage) {
      printk_red("global not allowed in ptable\n");
      goto invalid;
    }
    Page *dest = PHYS_TO_PAGE(pte->pagebase << PAGE_SHIFT);
      
    int check_perm = PERM_READ | (pte->rw ? PERM_WRITE : 0);
    if(!Page_checkXenPermissions(dest, check_perm)) {
      printk_red("target page %x not read / (writable?) (perm = %x)\n", 
		 pte->pagebase, check_perm);
      goto invalid;
    }
  }
  return 1;
 invalid:
  return 0;
}

int verify_ptable(Page *page) {
  if(page->type == FT_PTABLE && page->verified) {
    return 1;
  }
  PageTableEntry *pt = (PageTableEntry *)VADDR(page);
  int i;
  for(i=0; i < PTABLE_ENTRIES; i++) {
    if(0 && pt[i].present) {
      printk_red("  pt[%d]=%p\n", i, (void *)*(__u32*)&pt[i]);
    }
    if(!verify_pte(*(__u32*)&pt[i])) {
      printk_red("pte %d failed verification\n", i);
      goto invalid;
    }
  }
  return 1;
 invalid:
  return 0;
}

// Returns true if pde entry is OK. Used for checking PDE below NEXUS_START
static int verify_pde_low(Page *pdir_page, int offset, __u32 val, int get_ref) {
  DirectoryEntry *de = (DirectoryEntry *)&val;
  if(de->present) {
    if(de->globalpage) {
      printk_red("global not allowed\n");
      goto invalid;
    }
    if(de->bigpage) {
      printk_red("big page not allowed\n");
      goto invalid;
    }
    /* Verify that the target belongs to this domain, and is PTable */
    if(de->physaddr >= maxframenum) {
      printk_red("physical frame number > maximum frame number\n");
      goto invalid;
    }
    Page *dest = PHYS_TO_PAGE(de->physaddr << PAGE_SHIFT);
    if(!Page_checkXenPermissions(dest, PERM_READ)) {
      printk_red("target page %d not readable\n", de->physaddr);
      goto invalid; 
    }

    int is_loop = (pdir_page == dest);
    if(de->rw == 0 && de->user == 0 && 
       (dest->type == FT_PDIRECTORY || is_loop) ) {
      // printk_red("Using page directory special case\n");

      // Careful. If we were to call Page_Xen_Type_Get() on ourselves,
      // we can enter infinite recursion
      int break_recursion = (dest->type != FT_PDIRECTORY);
      if(!break_recursion) {
	int rv;
	rv = Page_Xen_Type_get(NULL, NULL, dest, FT_PDIRECTORY);
	assert(rv == 0);
      }
      if(get_ref) {
	// Check for loop
	if(is_loop) {
	  // Don't increment reference count for a self-loop
	  if(!break_recursion) {
	    Page_Xen_Type_put(NULL, NULL, dest, FT_PDIRECTORY);
	  }
	}
      } else {
	if(!break_recursion) {
	  Page_Xen_Type_put(NULL, NULL, dest, FT_PDIRECTORY);
	}
      }
    } else {
      if(Page_Xen_Type_get(NULL, NULL, dest, FT_PTABLE)) {
	printk_red("pdir verification: ptable at %d => %p invalid\n", 
		   offset, de->physaddr);
	goto invalid;
      }
      if(!get_ref) {
	Page_Xen_Type_put(NULL, NULL, dest, FT_PTABLE);
      }
    }
  }
  return 1;
 invalid:
  return 0;
}

static int verify_pde_high(int offset, __u32 val) {
  if(val != ((__u32 *)swapper_pg_dir)[offset]) {
    printk_red("pdir verification: does not match swapper_pg_dir at %d\n", offset);
    goto invalid;
  }
  return 1;
 invalid:
  return 0;
}

 int verify_pde(Page *pdir_page, BasicThread *t, 
		int offset, __u32 val, int get_ref) {
  const __u32 per_domain_pdoffset = 
    PDIR_OFFSET(NEXUS_DOMAIN_KERNELMAP_START);
  if(offset < PDIR_OFFSET(NEXUS_START)) {
    return verify_pde_low(pdir_page, offset, val, get_ref);
  } else {
    // Compare with swapper pgdir
    if(offset != per_domain_pdoffset) {
      return verify_pde_high(offset, val);
    } else {
      return thread_Xen_verifyDomainTablePDE(t, offset, val);
    }
  }
}

Page *put_pde(Page *page, int offset, __u32 val) {
  DirectoryEntry de;
  *(__u32*)&de = val;
  if(de.present) {
    Page *dest = &frameTable[de.physaddr];
    switch(dest->type) {
    case FT_PDIRECTORY:
      if(page != dest) {
	Page_Xen_Type_put(NULL, NULL, dest, FT_PDIRECTORY);
      }
      break;
    case FT_PTABLE:
      Page_Xen_Type_put(NULL, NULL, dest, FT_PTABLE);
      break;
    default:
      ASSERTNOTREACHED();
    }
    return dest;
  } else {
    return NULL;
  }
}

int verify_pdir(BasicThread *t, Page *page) {
  // PDIRs are valid if:
  // 1. Each valid entry validates as a PT
  // 2. Kernel entries are blank (to be filled in by Nexus)
  if(page->type == FT_PDIRECTORY && page->verified) {
    return 1;
  }

  DirectoryEntry *pdir = (DirectoryEntry *)VADDR(page);
  int i;
  for(i=0; i < PDIR_ENTRIES; i++) {
    if(!verify_pde(page, t, i, *(__u32*)&pdir[i], 1)) {
      printk_red("verification failed at %d\n", i);
      goto invalid;
    }
  }
  return 1;
 invalid:
  return 0;
}

// This function is copied from Xen
int check_and_fix_descriptor(unsigned long *d) {
#define BAD()						\
  do {							\
    printk_red("Seg bad at (%d), val is %p%p ",		\
	       __LINE__, (void*)d[1],(void*)d[0]);	\
    goto bad;						\
  } while(0)

  unsigned long base, limit, a = d[0], b = d[1];

  /* A not-present descriptor will always fault, so is safe. */
  if ( !(b & _SEGMENT_P) ) 
    goto good;

  /*
   * We don't allow a DPL of zero. There is no legitimate reason for 
   * specifying DPL==0, and it gets rather dangerous if we also accept call 
   * gates (consider a call gate pointing at another guestos descriptor with 
   * DPL 0 -- this would get the OS ring-0 privileges).
   */
  if ( (b & _SEGMENT_DPL) == 0 ) {
    // Nexus fixup: Flip DPL to 1
    printk_red("DPL flipped to 1\n");
    ((struct SegmentDescriptorHi *) &d[1])->dpl = GUEST_PL;
  }

  if ( !(b & _SEGMENT_S) )
    {
      /*
       * System segment:
       *  1. Don't allow interrupt or trap gates as they belong in the IDT.
       *  2. Don't allow TSS descriptors or task gates as we don't
       *     virtualise x86 tasks.
       *  3. Don't allow LDT descriptors because they're unnecessary and
       *     I'm uneasy about allowing an LDT page to contain LDT
       *     descriptors. In any case, Xen automatically creates the
       *     required descriptor when reloading the LDT register.
       *  4. We allow call gates but they must not jump to a private segment.
       */

      /* Disallow everything but call gates. */
      if ( (b & _SEGMENT_TYPE) != 0xc00 ) {
	BAD();
      }

      /* Can't allow far jump to a Xen-private segment. */
      if ( !VALID_CODESEL(a>>16) ) {
	BAD();
      }

      /* Reserved bits must be zero. */
      if ( (b & 0xe0) != 0 ) {
	BAD();
      }
        
      /* No base/limit check is needed for a call gate. */
      goto good;
    }
    
  /* Check that base is at least a page away from Nexus-private area. */
  base  = (b&(0xff<<24)) | ((b&0xff)<<16) | (a>>16);
  if ( base >= (NEXUS_START - PAGE_SIZE) ) {
    BAD();
  }

  /* Check and truncate the limit if necessary. */
  limit = (b&0xf0000) | (a&0xffff);
  limit++; /* We add one because limit is inclusive. */
  if ( (b & _SEGMENT_G) )
    limit <<= 12;

  if ( (b & (_SEGMENT_CODE | _SEGMENT_EC)) == _SEGMENT_EC )
    {
      /*
       * Grows-down limit check. 
       * NB. limit == 0xFFFFF provides no access      (if G=1).
       *     limit == 0x00000 provides 4GB-4kB access (if G=1).
       */
      if ( (base + limit) > base )
        {
	  limit = -(base & PAGE_MASK);
	  goto truncate;
        }
    }
  else
    {
      /*
       * Grows-up limit check.
       * NB. limit == 0xFFFFF provides 4GB access (if G=1).
       *     limit == 0x00000 provides 4kB access (if G=1).
       */
      if ( ((base + limit) <= base) || 
	   ((base + limit) > NEXUS_START) )
        {
	  limit = NEXUS_START - base;
        truncate:
	  if ( !(b & _SEGMENT_G) ) {
	    BAD(); /* too dangerous; too hard to work out... */
	  }
	  limit = (limit >> 12) - 1;
	  d[0] &= ~0x0ffff; d[0] |= limit & 0x0ffff;
	  d[1] &= ~0xf0000; d[1] |= limit & 0xf0000;
        }
    }

 good:
  return 1;
 bad:
  return 0;
}

static int verify_and_fix_page_segdesc(Page *page) {
  int i;
  unsigned long *descs = (unsigned long *)VADDR(page);
  for ( i = 0; i < 512; i++ ) {
    if ( unlikely(!check_and_fix_descriptor(&descs[i*2])) ) {
      printk_red("bad seg was at %d in page\n", i);
      return 0;
    }
  }
  return 1;
}

int verify_ldt(Page *page) {
  if(page->type == FT_LDT && page->verified) return 1;
  return verify_and_fix_page_segdesc(page);
}
int verify_gdt(Page *page) {
  if(page->type == FT_GDT && page->verified) return 1;
  return verify_and_fix_page_segdesc(page);
}

int 
Page_Xen_Type_pin(IPD *ipd, BasicThread *t, Page *page, __u32 pageType) 
{
	// NOOP: pages are always pinned in Nexus
	return 0;
}

void 
Page_Xen_Type_unpin(IPD *ipd, struct BasicThread *t, 
	            Page *page, __u32 pageType) 
{
	// NOOP: pages are always pinned in Nexus
}

int Page_Xen_Type_get(IPD *ipd, BasicThread *t, Page *page, int pageType) {
  // Do an ownership check if ipd != NULL
  if(!page->ram) {
    printk_red("Not ram page\n");
    return -1;
  }

  if(ipd != NULL) {
    if(ipd->id != page->owner) {
      printk_red("Target page has wrong owner\n");
      return -1;
    }
  }

  if(page->type == pageType && page->verified) {
    page->xenrefcnt++;
    return 0;
  }

  switch(page->type) {
  case FT_RDWR:
    assert(page->xenrefcnt == 0);
    switch(pageType) {
    case FT_PDIRECTORY: {
      if(!verify_pdir(t, page)) return -1;
      break;
    }
    case FT_PTABLE:
      if(!verify_ptable(page)) return -1;
      break;
    case FT_LDT:
      if(!verify_ldt(page)) return -1;
      break;
    case FT_GDT:
      if(!verify_gdt(page)) return -1;
      break;
    case FT_RDWR:
      // WRONG! Can only be transitioned to other types if there are no write references
      assert(0);
      break;
    default:
      assert(0);
    }
    break;
  default:
    if(pageType != FT_RDWR) {
      printk_red("Transition not allowed from %d to %d\n", page->type, pageType);
      return -1;
    }
  }
  if(pageType == FT_RDWR) {
    // WRONG: Cannot convert type to FT_RDWR if there are references!
    assert(0);
    page->verified = 0;
  }
  page->xenrefcnt++;
  page->type = pageType;
  page->verified = 1;
  return 0;
}

void Page_Xen_Type_put(IPD *ipd, BasicThread *t, Page *p, int frame_type) {
  assert(p->type == frame_type);
  assert(!ipd || ipd->id == p->owner);

  p->xenrefcnt--;
  if(!p->xenrefcnt) {

    // printk_red("Reseting page %x (type=%d) ", p - &frameTable[0], p->type);
    // Recursively put reference counts
    switch(p->type) {
    case FT_RDWR:
      // No type count should be kept for read/write pages
      assert(0);
      break;
    case FT_PDIRECTORY: {
      int i;
      DirectoryEntry *de = (DirectoryEntry *)VADDR(p);
      int child_put_count = 0;
      for(i = 0; i < PDIR_OFFSET(NEXUS_START); i++) {
	if(de[i].present) {
	  Page *child = &frameTable[de[i].physaddr];
	  // Check for Page directory special case

	  if(child->type == FT_PDIRECTORY) {
	    if(child != p) {
	      // Not a self-loop
	      Page_Xen_Type_put(ipd, t, child, FT_PDIRECTORY);
	    }
	    //ipd_fb_unmap(ipd ? ipd : nexusthread_current_ipd(), p);
	  } else {
	    Page_Xen_Type_put(ipd, t, child, FT_PTABLE);
	  }
	  child_put_count++;
	}
      }
      // printk_red("<< ChildPutCount = %d >>", child_put_count);
      break;
    }
    }
    p->type = FT_RDWR;
  }
}

int 
Map_getPageFlags(Map *m, unsigned int vaddr) 
{
  DirectoryEntry *pde;
  PageTableEntry *pte;
  int rval = 0;

  pde = vaddr_to_pde(m->pdbr, vaddr);
  if (unlikely(!pde->present))
    return PAGEFLAG_NULL;

  pte = vaddr_to_pte(pde, vaddr);
  if (!pte) 
    return PAGEFLAG_NULL;
  
  if (pte->rw)
    rval |= PAGEFLAG_WRITE;
  if (pte->uncached)
    rval |= PAGEFLAG_CACHEDISABLE;
  if (pte->user)
    rval |= PAGEFLAG_USER;
  if (pte->present)
    rval |= PAGEFLAG_PRESENT;
 
  return rval;
}

/** Setup initial pages (frame table types) for a Xen domain
    Xen requires typing pages to disallow r/w access to PTEs, PDEs, GDT, LDT */
int Map_Xen_initFTTypes(Map *m, IPD *ipd) {
  DirectoryEntry *pdes, *pde;
  PageTableEntry *ptes, *pte;
  Page *root, *ptpage, *page;
  int i, j;
  
  root = m->pdbr;
  if (root->type != FT_NRDWR) {
    printk_red("Map_Xen_initFTTypes(): Bad root type!\n");
    nexuspanic();
  }
  root->owner = ipd->id;
  root->type = FT_PDIRECTORY;
  root->verified = 1;
  root->xenrefcnt = 1;

  pdes = (DirectoryEntry *) VADDR(root);
  
  // walk all page directory entries
  for (i = 0; i < (NEXUS_START >> PDIR_SHIFT); i++) {
    pde = &pdes[i];
    if (pde->present) {
      ptpage = PHYS_TO_PAGE(pde->physaddr << PAGE_SHIFT);
      if (!(ptpage->type == FT_NRDWR || ptpage->type == FT_PTABLE)) {
	printk_red("[xen] pagetype error (pt)\n");
	return -1;
      }

      ptpage->owner = ipd->id;
      ptpage->type = FT_PTABLE;
      ptpage->verified = 1;

       
      // walk all page table entries
      // Make PTE pages FT_RDWR (why?)
      ptes = (PageTableEntry *) VADDR(ptpage);
      for (j = 0; j < PTABLE_ENTRIES; j++) {
	pte = &ptes[j];
	if (pte->present) {
	  page = PHYS_TO_PAGE(pte->pagebase << PAGE_SHIFT);

	  // This will happen for Nexus read-only data page
	  if (page->owner != ipd->id) {
	    printkx(PK_XEN, PK_INFO, "[xen] pagetype warning\n");
	    continue;
	  }
	  if (!(page->type == FT_NRDWR || page->type == FT_RDWR)) {
	    printk_red("[xen] pagetype error (regular)\n");
	    return -1;
	  }

	  page->type = FT_RDWR;
	  page->verified = 0; 
	}
      }
    }
  }

  return 0;
}

// ptr = the machine address of the page, i.e. << PAGE_SHIFT
// val = the virtual frame number
int m2p_update(IPD *ipd, __u32 ptr, __u32 val) {
  __u32 mfn = ptr >> PAGE_SHIFT;
  
  if (mfn >= (nexus_max_pfn >> PAGE_SHIFT)) {
    printk_red("[xen] frame out of bounds\n");
    return -1;
  }
  if (frameTable[mfn].owner != ipd->id) {
    printk_red("[xen] illegal update\n");
    return -1;
  }

  machine_to_phys[mfn] = val;
  return 0;
}

#endif /* __NEXUSXEN__ */

/** Backend for kernel heap allocator */
void *
kernel_mmap(int length)
{
	return getKernelPages(PAGECOUNT(length));
}

void * 
kernel_mremap(void)
{
	nexuspanic();
	return (void *) -1;
}

int 
kernel_munmap(void *addr, int length)
{
	assert(addr >= (void *) KERNELVADDR);
	freeKernelPages(addr, PAGECOUNT(length));
	return 0;
}

