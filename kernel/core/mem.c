#include <nexus/defs.h>
#include <nexus/queue.h>
#include <nexus/mem.h>
#include <nexus/ipd.h>
#include <nexus/thread.h>
#include <nexus/thread-private.h>
#include <nexus/idtgdt.h>
#include <nexus/synch.h>
#include <nexus/synch-inline.h>
#include <nexus/machineprimitives.h>
#include <nexus/log.h>
#include <nexus/initrd.h>
#include <asm/errno.h>

#include <nexus/util.h>
#include <nexus/bitmap.h>
#include <nexus/syscall-defs.h>
#include <nexus/stringbuffer.h>
#include <asm/pgtable.h>

int num_zapped_low_ptab = 0;
#include <nexus/malloc_checker.h>

int suppress_peek_user_error = 0;
int print_peek_user_count = 0;

// curr_map is defined in thread.c so that it has spatial locality with curt
extern Map *curr_map;

static __u32 last_kernel_boot_page(void) {
  // This number must be > _end and less than the number of pages
  // mapped in swapper_pg_dir. Otherwise, the allocator will not work
  // until the full page table is initialized.
#if 1
  return 8 * (1 << 20) / PAGE_SIZE;
#else // this code is preferable, but doesn't work
  extern char _end;
  return PAGE_ROUNDUP((unsigned long)&_end) / PAGE_SIZE;
#endif
}

#define BAD_FILL_CHAR (0xff)

#define MAXPAGES  256000 // caution: MAXPAGES*PAGESIZE must be 1GB or less

#define PAGEDIROFFSET   22
#define PAGETABLEOFFSET 12
#define PAGEOFFSETMASK  0x3ff

static Sema *memMutex; //ensures atomic operations on Maps (map_page, unmap_page)

void Mem_mutex_lock(void) {
  P(memMutex);
}
void Mem_mutex_unlock(void) {
  V(memMutex);
}

#include <nexus/mem-private.h>

typedef struct Qpage Qpage;
struct Qpage {
  QItem _link;
  Page *page;
};

Map *kernelMap;

Page _pages[MAXPAGES];
Page *frameTable = _pages;
u32 *machine_to_phys;

// These versions of Page_get() and Page_put() are for Nexus, not Xen apps
void Page_get(Page *page) {
  int err;
  err = atomic_increment_b_overflow(&page->pagerefcnt, 1);
  if(err) {
    printk_red("pagerefcnt overflow!\n");
    nexuspanic();
  }
}

int Page_put(Page *page) {
  return atomic_decrement_b_zero(&page->pagerefcnt, 1);
}

void Page_dump(Page *page) {
  printk_red("r=%d, type=%d, owner=%d, refcnt=%d, xenrefcnt=%d, verified=%d, acl=%d\n",
	     page->ram, page->type, page->owner, page->pagerefcnt,
	     page->xenrefcnt,
	     page->verified, page->acl);
}

Page *Page_Xen_fromMFN_checked(__u32 mfn) {
  if(mfn >= maxframenum) {
    printk_red("bad mfn %u\n", mfn);
    return NULL;
  }
  return &frameTable[mfn];
}

Page *Page_Xen_fromVirt_checked(Map *m, __u32 vaddr) {
  __u32 paddr = fast_virtToPhys_nocheck(m, vaddr);
  if(paddr == 0) return NULL;
  Page *p = Page_Xen_fromMFN_checked(paddr >> PAGE_SHIFT);
  return p;
}

void PTAB_dump(void *base) {
  PageTableEntry *pte = (PageTableEntry *)base;
  int i;
  for(i=0; i < PTABLE_ENTRIES; i++) {
    if(pte[i].present) {
      printk_green(" [%d] => %x ", i, pte[i].pagebase);
    }
  }
}

u32 actual_e820_start;

char phys_bitmap_data[4096*64];
struct Bitmap *phys_bitmap;

//int nphysframes = 0;
int maxframenum = 0;

static int is_e820_page(unsigned int base) {
  return (unsigned)base < (unsigned)maxframenum;
}


////////  init ////////

void frameTable_init(void) {
	int i;

	phys_bitmap = (struct Bitmap *) phys_bitmap_data;
	bitmap_init(phys_bitmap, MAXPAGES, sizeof(phys_bitmap_data));

	for(i=0; i < MAXPAGES; i++) {
		memset(&frameTable[i], 0, sizeof(frameTable[i]));
#ifdef __NEXUSXEN__
		frameTable[i].type = FT_NRDWR;
#endif
		frameTable[i].owner = IPD_NEXUS;
		bitmap_set(phys_bitmap, i);
	}
}


////////  debug output  ////////

void dump_max_page_util_gap(void){
  int i, cntr = 0;
  int maxgap = 0;
  int mismatch_count = 0;
  
  P(memMutex);
  for(i = actual_e820_start / PAGE_SIZE + 1; i < maxframenum; ++i){
    if(frameTable[i].ram) {
      if(frameTable[i].pagerefcnt >= 1) {
	maxgap = max(maxgap, cntr);
	cntr = 0;
      }else{
	cntr++;
      }
      if( (!! bitmap_test(phys_bitmap, i)) != (!! (frameTable[i].pagerefcnt != 0)) ) {
	mismatch_count++;
      }
    }
  }

  V(memMutex);

  printk_red("max gap = %d, mismatch_count  = %d\n",
	     max(maxgap,cntr), mismatch_count);
}

void fill_page_utilization(int *util, int *total, int *ipd_table, int table_len){
  int i;
  *util = 0; 
  *total = 0;
  P(memMutex);
  memset(ipd_table, 0, table_len * sizeof(ipd_table[0]));
  for(i = actual_e820_start / PAGE_SIZE + 1; i < maxframenum; ++i){
    *total = *total + 1;
    if(frameTable[i].ram) {
      // If the reference count is 0, then it might be owned by a Xen IPD
      if(frameTable[i].pagerefcnt >= 1 
#ifdef __NEXUSXEN__
	 || frameTable[i].type != FT_NRDWR
#endif
		      ) {
	*util = *util + 1;
	if(!bitmap_test(phys_bitmap, i)) {
	  printk_red("(-%d)", i);
	}
	int owner = frameTable[i].owner;
	if(owner < table_len) {
	  ipd_table[owner]++;
	}
      } else {
	if(bitmap_test(phys_bitmap, i)) {
	  printk_red("(+%d)", i);
	}
      }
    }
  }
  V(memMutex);
}

void dump_page_utilization(void){
#define MAX_DUMP_IPD (80)
  int table[MAX_DUMP_IPD + 1];
  memset(table, 0, sizeof(table));

  int util, total;
  fill_page_utilization(&util, &total, table, MAX_DUMP_IPD + 1);
  int i;
  printk_red("dumping page utilization:\n");
  for(i=0; i < MAX_DUMP_IPD / 4; i++) {
    printk_red("ipd %2d: %7d       ipd %2d: %7d       ipd %2d: %7d      ipd %2d: %7d\n",
			i, table[i],
			i+MAX_DUMP_IPD/4, table[i+MAX_DUMP_IPD/4],
			i+2*MAX_DUMP_IPD/4, table[i+2*MAX_DUMP_IPD/4],
			i+3*MAX_DUMP_IPD/4, table[i+3*MAX_DUMP_IPD/4]);
  }
  printk_red("%d / %d / %d pages used\n", util, total, maxframenum);
  dump_max_page_util_gap();
#undef MAX_DUMP_IPD
}

void dump_page_utilization_to_sb(struct StringBuffer *sb) {
#define MAX_DUMP (10000)
  static char line[1024];
  static int table[MAX_DUMP];
  memset(table, 0, sizeof(table));

  int util, total;
  fill_page_utilization(&util, &total, table, MAX_DUMP);
  int i;
  for(i=0; i < MAX_DUMP; i++) {
    if(table[i] > 0) {
      sprintf(line, "%d: %d\n", i, table[i]);
      SB_cat(sb, line);
    }
  }
  sprintf(line, "%d / %d / %d pages used\n", util, total, maxframenum);
  SB_cat(sb, line);
#undef MAX_DUMP
}

int get_page_utilization(int ipdid){
  int util, total;
  int *table = galloc(sizeof(int) * (ipdid + 1));
  fill_page_utilization(&util, &total, table, ipdid + 1);
  int val = table[ipdid];
  gfree(table);
  return val;
}

void pagesdump(int i, int numpgs){
  int k, j = 0;
  Page *page = NULL;
  for(k = 0; k < maxframenum && j < numpgs; ++k)
    page = &frameTable[i+k];
  if(page->ram) {
    printk("%d: %d\n", j, PADDR(page));
    j++;
  }
}

Page *get_blank_pages(int numpgs){
  Page *page;
  page = nallocate_pages(numpgs);
  pagememzero_n(VADDR(page), numpgs);

  return page;
}

void reserve_pages(int pgstart, int numpgs, u32 ipd_id) {
    int level = disable_intr();
    int j;

    for (j = 0; j < numpgs; ++j) {
      assert(frameTable[pgstart+j].pagerefcnt == 0);
      Page_get(&frameTable[pgstart+j]);
      bitmap_set(phys_bitmap, pgstart+j);
      frameTable[pgstart+j].owner = ipd_id;
    }
    restore_intr(level);
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
vaddr_to_pte_atonce(Map *m, unsigned int vaddr) 
{
  DirectoryEntry *pde;

  pde = vaddr_to_pde(m->pdbr, vaddr);
  if (unlikely(!pde->present))
    return NULL;
  if (unlikely(pde->bigpage))
    nexuspanic();

  return vaddr_to_pte(pde, vaddr);
}

unsigned int 
PDBR_virtToPhys_nocheck(Page *pdbr, unsigned int vaddr) 
{
  DirectoryEntry *pde;
  PageTableEntry *pte;

  pde = vaddr_to_pde(pdbr, vaddr);
  if (!pde->present)
    return 0;
  if(pde->bigpage) {
    printk("virttophys_nocheck called on big page!\n");
    return BIGPAGE_BASE(*(u32*)pde) + (BIGPAGE_OFFSET(vaddr) & ~0xfff);
  }

  pte = vaddr_to_pte(pde, vaddr);
  if (!pte->present)
    return 0;

  return pte->pagebase << PAGE_SHIFT;
}

unsigned int 
fast_virtToPhys_nocheck(Map *m, unsigned int vaddr) 
{
  if (unlikely(!m)) {
    assert((unsigned) vaddr > (unsigned) KERNELVADDR);
    return VIRT_TO_PHYS(vaddr);
  }

  return PDBR_virtToPhys_nocheck(m->pdbr, vaddr);
}

unsigned int 
fast_virtToPhys(Map *m, unsigned int vaddr, int user, int write) {
  DirectoryEntry *pde;
  PageTableEntry *pte;

  /* vaddr has to be aligned to a page number */
  assert((vaddr & (PAGESIZE - 1)) == 0);

  if (m == NULL)
    return VIRT_TO_PHYS(vaddr);

  if(user) {
    if(vaddr >= (unsigned)KERNELVADDR) {
      printk_red("user requested, but page too high (%p)\n", (void *) vaddr);
      nexusthread_dump_regs_stack(nexusthread_self());
      return 0;
    }
#ifdef __NEXUSXEN__
    if(m->owner != NULL && m->owner->type == XEN) {
      // Allow transfers to any pages below KERNELVADDR in Xen mode

      // XXX ASHIEH: This is not an appealing solution, since it does
      // not distinguish between the Xen user process, the Xen kernel,
      // and the Xen VMM. Better to check the cpuinfo part of KShmem
      user = 0;
    }
#endif
  }

  pde = vaddr_to_pde(m->pdbr, vaddr);
#define CHECK(ENT)					\
  if (!(ENT)->present) {				\
    printk("virttophys (%p): not present @ %d\n", (void *)vaddr, __LINE__);	\
    return 0;						\
  }							\
  if (user && !(ENT)->user) {				\
    printk("virttophys: wrong user flag @ %d\n", __LINE__);	\
    return 0;						\
  }							\
  if (write && !(ENT)->rw) {				\
    printk("virttophys: wrong rw permission flag @ %d\n", __LINE__);	\
    return 0;						\
  }
  
  CHECK(pde);
  if(pde->bigpage) {
    return (pde->physaddr << PAGE_SHIFT) | (vaddr & ((1 << PDIR_SHIFT) - 1));
  }

  pte = vaddr_to_pte(pde, vaddr);
  CHECK(pte);

#undef CHECK
  return pte->pagebase << PAGE_SHIFT;
}


////////  physical page allocation  ////////

static Page *
nallocate_page(void) 
{
  return nallocate_pages(1);
}

Page *nallocate_pages(int numpgs) {
  IPD *ipd = nexusthread_current_ipd();
  int level;
  int start, i, j;
  int cntr = 0, maxgap = 0;
  int dbg = 0;
  static int cursor = 0;

  level = disable_intr();

  /* wrap to make sure we didn't miss anything 
   
     XXX where do we wrap? it seems to me we just
         start from bitmap_find_first_zero twice */
  for (j = 0; j < 2; j++) { 
    for (start = i = bitmap_find_first_zero(phys_bitmap, cursor); i < maxframenum; ++i) {
      if(start == -1)
	break;
      if((frameTable[i].pagerefcnt >= 1) || (!frameTable[i].ram)){
	maxgap = max(maxgap, cntr);
	start = i+1;
	cntr = 0;
      }else{
	cntr++;
      }
      if(cntr == numpgs)
	break;
    }
    if(cntr == numpgs)
      break;
    cursor = 0;
    maxgap = max(maxgap, cntr);
    cntr = 0;
  }

  if (unlikely(cntr != numpgs)) {
#ifndef NDEBUG
    {
      printk_red("You have multiple axes (%d) in your head (maxgap=%d, ipd=%d, tried to alloc %d pages)\n",
		 numpgs, maxgap, ipd ? ipd->id : 0, numpgs);
      // Release mutex so that fill_page_utilization() can execute
      V(memMutex);
      dump_page_utilization();
      dump_stack();
      nexuspanic();
    }
#endif
    restore_intr(level);
    return NULL;
  }

  reserve_pages(start, numpgs, ipd ? ipd->id : 0);
  cursor = start + numpgs;
  restore_intr(level);
  Page *rv = &frameTable[start];
  return rv;
}

int nfree_page(Page *page) {
  if (page - frameTable >= maxframenum) {
    printk_red("nfree_page: bad frame number %p!\n", PADDR(page));
    nexuspanic();
  }

  if(page->pagerefcnt == 0) {
    printk_red("refcnt should not go below zero 0x%p (%d %p) ipd %d\n", page, 
	       page - frameTable, PADDR(page), nexusthread_current_ipd()->id);
    dump_stack();
    printk_red("looping");while(1);
    nexuspanic();
  }

  int zero = Page_put(page);

  if(zero) {
#ifdef __NEXUSXEN__
    if(!FT_ISRDWR(page->type)) {
      printk_red("Warning: Cannot yet free pages not of FT_RDWR (type = %d, owner = %d, ram = %d) @ %d! (looping XXX)\n", 
		 page->type, page->owner, page->ram, page - frameTable);
      for(;;);
      printk_red("prev/next type = %d %d\n", (page-1)->type, (page+1)->type);
      show_trace(NULL);
      // XXX This should call into appropriate deallocator
      return 0;
    }
#endif
    page->owner = IPD_NEXUS;
    machine_to_phys[PADDR(page) / PAGE_SIZE] = 0;
    bitmap_clear(phys_bitmap, PADDR(page) / PAGE_SIZE);
    return 1;
  }
  return 0;
}

int nfree_page_vaddr(unsigned int vaddr) {
  if(vaddr < KERNELVADDR) {
    printk_red("nfree_page_vaddr(%p): less than kernelvaddr!\n", vaddr);
    return 0;
  }
  Page *page = PHYS_TO_PAGE(VIRT_TO_PHYS(vaddr));
  return nfree_page(page);
}

////////  virtual memory map  ////////

Map *
Map_new(void) 
{
  Map *m;
 
  m = gcalloc(1, sizeof(Map));
  m->pagetables = queue_new();
  PointerVector_init(&m->allocated_vaddrs, 1024, 0);
  return m;
}

void Map_pagesused_inc(Map *m, int num){
  m->numpgs += num;
}
void Map_pagesused_dec(Map *m, int num){
  m->numpgs -= num;
}
int Map_pagesused(Map *m){
  return m->numpgs;
}

void 
Map_setAnonCleanup(Map *space, IPD *owner) 
{
  space->owner = owner;
  space->clean_anon_pages = 1;
}

void Map_up_active_thread_count(Map *m) {
  atomic_addto(&m->active_thread_count, 1);
}

int 
Map_down_active_thread_count(Map *m) 
{
  return atomic_subtractfrom(&m->active_thread_count, 1);
}

int 
Map_get_refcnt(Map *m)
{
  return m->refcnt;
}

int 
Map_get_active_thread_count(Map *m)
{
  return atomic_get(&m->active_thread_count);
}

static void 
Map_addDeallocHint(Map *m, unsigned int vaddr)
{
  PointerVector_append(&m->allocated_vaddrs, (void *)vaddr);
}

int Map_overlayRO(Map *target_map, Map *source_map);

static void Map_initPDBR(Map *m) {
  // Creates the pdbr of the map
  Map_pagesused_inc(m, 1);
  m->pdbr = nallocate_page();
  pagememzero_n(VADDR(m->pdbr), 1);
      
  /* copy the kernel directory entries to this directory set */
  pagememcpy(VADDR(m->pdbr), VADDR(kernelMap->pdbr), PAGESIZE); // XXX gross hack - egs
}

Map *Map_copyRW(Map *source_map) {
  Map *newmap = Map_new();
  Map_initPDBR(newmap);
  int pdoffset;
  int pde_copy_count = 0;
  int pte_copy_count = 0;
  int pte_present_count = 0;
  int skipped_count = 0;
  for(pdoffset=0; pdoffset < PDIR_OFFSET(PHYPAGEVADDR); pdoffset++) {
    DirectoryEntry *pde = 
      &((DirectoryEntry *)VADDR(newmap->pdbr))[pdoffset];
    DirectoryEntry *src_pde =
      &((DirectoryEntry *)VADDR(source_map->pdbr))[pdoffset];
    *pde = *src_pde;
    if(!pde->user && pde->physaddr != 0)
      printk_red("(%d-%d)", pdoffset, pde->physaddr);
    pde->physaddr = 0;

    if(pde->present) {
      pde_copy_count++;
      assert(src_pde->physaddr <= maxframenum);
      Page *src_ptpage = &frameTable[src_pde->physaddr];
      assert(src_ptpage->ram);
      Page *ptpage = nallocate_page();

      Map_pagesused_inc(newmap, 1);
      pde->physaddr = PADDR(ptpage) >> PAGE_SHIFT;

      int ptoffset;
      unsigned int first_vaddr = 0;
      unsigned int last_vaddr = 0;
      int print_limit = 0;
      for(ptoffset=0; ptoffset < PTABLE_ENTRIES; ptoffset++) {
	unsigned long vaddr = 
	  (pdoffset << PDIR_SHIFT) | (ptoffset << PTAB_SHIFT);
	PageTableEntry *pte = 
	  &((PageTableEntry *)VADDR(ptpage))[ptoffset];
	PageTableEntry *src_pte = 
	  &((PageTableEntry *)VADDR(src_ptpage))[ptoffset];
	*pte = *src_pte;
	pte->pagebase = 0;
	if(!PageTableEntry_checkAvailable(pte)) {
	  pte_copy_count++;
	  if(pte->present)
	    pte_present_count++;
	  // if page is allocated in source, allocate a copy in dest.
	  // this is not just a pte->present check, since the source
	  // page might be protected
	  assert(src_pte->pagebase != 0);
	  if(src_pte->pagebase > maxframenum) {
	    // printk_red("pagebase %d > %d! @ %p\n", src_pte->pagebase, maxframenum, vaddr);
	    skipped_count++;
	    PageTableEntry_makeAvailable(pte);
	    continue;
	  }
	  Page *src_dpage = &frameTable[src_pte->pagebase];
	  if(!src_ptpage->ram) {
	    printk_red("copyRW: skipping non-RAM page at %p\n", (void *)vaddr);
	    continue;
	  }

	  Map_pagesused_inc(newmap, 1);
	  Page *dpage = nallocate_page();
	  pte->pagebase = PADDR(dpage) >> PAGE_SHIFT;
	  memcpy((void *)VADDR(dpage), (void *)VADDR(src_dpage), PAGE_SIZE);
	  Map_addDeallocHint(newmap, vaddr);

	  // Print out copied ranges
	  if(last_vaddr != vaddr - PAGE_SIZE) {
	    if(0 && first_vaddr != 0 && print_limit < 100) {
	      printk_green("(%p-%p)", (void *)first_vaddr, (void *)(last_vaddr + PAGE_SIZE-1));
	      print_limit++;
	    }
	    first_vaddr = vaddr;
	  }
	  last_vaddr = vaddr;
	}
      }
    }
  }
  if(0) {
    printk_red("pdes copied %d, ptes copied %d, %d present, %d skipped\n",
	       pde_copy_count, pte_copy_count, pte_present_count, skipped_count);
  }
  return newmap;
}

#define MAP_OVERLAY_RO_OPTION 2

// Put mappings from source_map into target_map
int Map_overlayRO(Map *target_map, Map *source_map) {

  PointerVector_resize(&target_map->allocated_vaddrs, 
	max(PointerVector_len(&source_map->allocated_vaddrs), 
	PointerVector_len(&target_map->allocated_vaddrs)));

  DirectoryEntry *pde, *oldpde;
  PageTableEntry *pte, *oldpte;
  int diroffset;
  int pageoffset;
  Page *ptpage;

  int error_count = 0;
  int pte_skipped_count = 0;
#if MAP_OVERLAY_RO_OPTION == 1
  int pde_copied_count = 0;
#endif
  /* loop through directory entries under the copied kernel entries */
  int overlaid_page_count = 0;
  for(diroffset = 0; diroffset < ((KERNELVADDR >> 22) & 0x3ff); diroffset++){
    oldpde = (DirectoryEntry *) (VADDR(source_map->pdbr) + diroffset * sizeof(DirectoryEntry));
    pde = (DirectoryEntry *) (VADDR(target_map->pdbr) + diroffset * sizeof(DirectoryEntry));
    if(oldpde->present) {
      if(!pde->present) {
#if MAP_OVERLAY_RO_OPTION == 1
	// Option 1: create a new pagetable

	// if no existing pde, create a new one
	// printk_red("overlayro: pde %x already present!\n", diroffset);
	pde_copied_count++;
	ptpage = nallocate_page();

	Qpage *qpage = (Qpage *) galloc(sizeof(Qpage));
	qpage->page = ptpage;
	if (queue_append(target_map->pagetables, qpage) < 0)
	  printk("MEM: couldn't add pagetable page to queue\n");
	pagememzero_n(VADDR(ptpage), 1);

	pde->physaddr = (PADDR(ptpage) >> 12) & 0xfffff;
	pde->present = oldpde->present;
	pde->rw = 0;
	pde->user = oldpde->user;
	pde->uncached = oldpde->uncached;
	pde->writethrough = oldpde->writethrough;
#else
	// Option 2: Copy original pagetable, and rely on
	// interpretation of pde's RW flag
	Qpage *qpage = (Qpage *) galloc(sizeof(Qpage));
	ptpage = PHYS_TO_PAGE(oldpde->physaddr << 12);
	qpage->page = ptpage;
	if (queue_append(target_map->pagetables, qpage) < 0)
	  printk("MEM: couldn't add pagetable page to queue\n");

	Page_get(ptpage);

	pde->physaddr = oldpde->physaddr;
	pde->present = oldpde->present;
	pde->rw = 0;
	pde->user = oldpde->user;
	pde->uncached = oldpde->uncached;
	pde->writethrough = oldpde->writethrough;
	continue;
#endif
      } else {
	// otherwise, add entries to the existing pt
	ptpage = PHYS_TO_PAGE(pde->physaddr << 12);
      }

      /* loop through all pages in this directory */
      for(pageoffset = 0; pageoffset < PAGESIZE / sizeof(PageTableEntry); pageoffset++){
	oldpte = (PageTableEntry *)(PHYS_TO_VIRT(oldpde->physaddr << 12) + pageoffset * sizeof(PageTableEntry));
	pte = (PageTableEntry *)(VADDR(ptpage) + pageoffset * sizeof(PageTableEntry));
	// This direct reference to present bits is ok; we don't try to
	// preserve MProt status to the copied map
	if(oldpte->present){
	  if(pte->present) {
	    error_count++;
	    pte_skipped_count++;
	    // printk_red("overlayro: pte already present!\n");
	    continue;
	  }
	  // target pte not present ; start copying
	  if(!is_e820_page(oldpte->pagebase)) {
	    // not RAM page (probably hardware), skip
	    PageTableEntry_makeAvailable(pte);
	    continue;
	  }

	  Map_addDeallocHint(target_map, (diroffset << 22) | (pageoffset << 12));
	  Page_get(PHYS_TO_PAGE(oldpte->pagebase << 12));
	  pte->pagebase = oldpte->pagebase;
	  PageTableEntry_makePresent(pte);
	  pte->rw = 0;
	  pte->user = oldpte->user;
	  pte->uncached = oldpte->uncached;
	  pte->writethrough = oldpte->writethrough;
	  overlaid_page_count++;
	}
      }
    }
  }
#if 0
  RATE_LIMIT(printk_red("<<%d %d %d>>", 
	pde_copied_count, overlaid_page_count, pte_skipped_count));
#endif
  return error_count;
}

int Map_getType(Map *m) {
  return m->type;
}

Page *PDBR_getPagetable(Page *pdbr, unsigned int vaddr) {
  DirectoryEntry *pde; 

  pde = vaddr_to_pde(pdbr, vaddr);
  if (!pde->present) {
    printk_red("Map_getPageTable(): no ptable at %p!\n", (void *)vaddr);
    return NULL;
  } 

  return &frameTable[pde->physaddr];
}

Page *Map_getPagetable(Map *m, unsigned int vaddr) {
  assert(m->pdbr != NULL);
  return PDBR_getPagetable(m->pdbr, vaddr);
}

extern DirectoryEntry *Map_getPDE(Map *m, unsigned int vaddr) {
  assert(m->pdbr != NULL);
  return &((DirectoryEntry *)VADDR(m->pdbr))[PDIR_OFFSET(vaddr)];
}

PageTableEntry *Map_getPTE(Map *m, unsigned int vaddr) {
  Page *page = Map_getPagetable(m, vaddr);
  if(page == NULL) {
    return NULL;
  }
  return &((PageTableEntry*)VADDR(page))[PTAB_OFFSET(vaddr)];
}

static void Map_free_pages(Map *m) {
  DirectoryEntry *pde;
  PageTableEntry *pte;
  int numfreed = 0, realnumfreed = 0;
  int freed;
  unsigned int vaddr;
  
  // acquire the memory mutex because we might be called from
  // different contexts on the same map:

  // reaper thread when active thread count is 0, or Map_destroy()
  P(memMutex);

  int i;
  for(i=0; i < PointerVector_len(&m->allocated_vaddrs); i++) {
    vaddr = (unsigned int) PointerVector_nth(&m->allocated_vaddrs, i);

    if(vaddr < 8 * 1048576) {
      // workaround some weird low mappings
      continue;
    }
    
    pde = vaddr_to_pde(m->pdbr, vaddr);
    if((pde->present) && (pde->user)) {
      pte = vaddr_to_pte(pde, vaddr);
      if(PageTableEntry_checkPresent(pte) && (pte->user)){
	PageTableEntry_makeAvailable(pte);
	numfreed++;
	unsigned frame_base = pte->pagebase << 12;
	if(!is_e820_page(pte->pagebase)) continue;
	freed = nfree_page(PHYS_TO_PAGE(frame_base));
	realnumfreed += freed;
      }
    }
  }

  // nexuspanic();
  V(memMutex);
  PointerVector_truncate(&m->allocated_vaddrs);

  //Free page directory and page tables associated with m
  if (m->pdbr != NULL){
    nfree_page(m->pdbr);
  }
  Qpage *pt;
  while (queue_dequeue(m->pagetables, (void **) &pt) == 0){
    nfree_page(pt->page);
  }
  queue_destroy(m->pagetables);

  if(m->clean_anon_pages) {
    printk_red("Clean anon pages: really slow!\n");
    assert(m->owner != NULL);
    P(memMutex);
    int anon_count = 0;
    for(i=0; i < maxframenum; i++) {
      Page *page = &frameTable[i];
     
      page->pagerefcnt = 1;
#ifdef __NEXUSXEN__
      if(page->owner == m->owner->id) {
	// Zap the type of the page to avoid calling page destructor
	page->type = FT_RDWR;
	// zap the reference count
	if(! nfree_page(page)) {
	  printk_red("<anonfail>");
	}
	anon_count++;
      }
#endif
    }
    V(memMutex);
    printk_red("%d anonymous pages deallocated\n", anon_count);
  }
}

void 
Map_reap(Map *m) 
{
  Map_free_pages(m);
}

void Map_destroy(Map *m)
{
  int zero = atomic_subtract(&m->refcnt, 1);
  if (zero) {
    Map_free_pages(m);
    PointerVector_truncate(&m->allocated_vaddrs);
    gfree(m);
  }
}

////////  virtual address space find/add/del   ////////

/* Search for a free virtual address space region starting from vaddrhint.
   Can discern read-only and read-write (4MB) regions.
 
   @param user, if set, will only return regions that are user accesible
   @param writer, if set, will only return regions that are user writable */
static unsigned int 
memmap_get_region_ex(Map *m, unsigned int vaddr, int n, int user, int writable)
{
  DirectoryEntry *pde;
  PageTableEntry *pte;
  unsigned int vpage, basevpage;

  if (!m)
    return 0;
  
  // no pdbr, then a new map and thus room at vaddrhint */
  if (!m->pdbr)
    return vaddr;
  
  // Operate on pages rather than addresses to avoid overflow
  vpage = basevpage = vaddr / PAGESIZE;

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
    if (m != kernelMap && // nb: should also hold for kernel, but doesn't. XXX find out why
        ((user && !pde->user) ||
	(writable && !pde->rw))) {
      basevpage = vpage = (PDIR_OFFSET(vpage * PAGESIZE) + 1) * PTABLE_ENTRIES;
      continue;
    }

    // PTE
    pte = vaddr_to_pte(pde, vpage << PAGE_SHIFT);
    if (!PageTableEntry_checkAvailable(pte)) { 
      basevpage = vpage = vpage + 1;
      continue;
    }

    vpage++;
  }
  return basevpage * PAGESIZE;
}

/** See memmap_get_region_ex */
static unsigned int 
memmap_get_region(Map *m, unsigned int vaddrhint, int n)
{
  return memmap_get_region_ex(m, vaddrhint, n, 0, 0);
}

/** Create a copy of the page table element. 
    This is needed if access permissions differ. */
static void 
memmap_copy_pt(Map *m, DirectoryEntry *pde) 
{
  Page *old_pt, *new_pt;
  unsigned long index;
  index = pde->physaddr << PAGE_SHIFT;
  old_pt = PHYS_TO_PAGE(index);
  if (old_pt->pagerefcnt > 1) {

    // Copy-on-write semantics
    new_pt = nallocate_page();
    memcpy((void *) VADDR(new_pt), (void *) PHYS_TO_VIRT(index), PAGE_SIZE);
    pde->physaddr = (PADDR(new_pt) >> PAGE_SHIFT) & 0x3ff;

    // add to PDE/PTE queue
    Qpage *qpage = (Qpage *) galloc(sizeof(Qpage));
    qpage->page = old_pt;
    if (queue_append(m->pagetables, qpage) < 0)
      printk("MEM: couldn't add pagetable page to queue\n");
  }

}

/** Insert a page at or near a given virtual memory address */
unsigned int 
memmap_add_page(Map *m, int pin_new_ptab, unsigned int paddr, int writable, 
		int user, int uncached, int writethrough, unsigned int vaddr)
{
  Page *ptpage;
  DirectoryEntry *pde;
  PageTableEntry *pte;

  // no page directory base register yet? create this top-level element
  if (!m->pdbr)
    Map_initPDBR(m);

  pde = vaddr_to_pde(m->pdbr, vaddr);

  // PDE
  if (!pde->present) {

    // allocate page to hold the PDE
    Map_pagesused_inc(m, 1);
    ptpage = nallocate_page();
    pagememzero_n(VADDR(ptpage), 1);

    // add to list of all PDEs/PTEs for deallocation
    // XXX remove : can be learned by walking the tree
    Qpage *qpage = (Qpage *) galloc(sizeof(Qpage));
    qpage->page = ptpage;
    if (queue_append(m->pagetables, qpage) < 0)
      printk("MEM: couldn't add pagetable page to queue\n");

    pde->physaddr = (PADDR(ptpage) >> 12) & 0xfffff; // only the lower 20 bits are needed
    pde->rw = 1; 	// use only PTE for access permissions
    pde->user = 1;	// use only PTE for access permissions
    pde->uncached = uncached;
    pde->writethrough = writethrough;
    pde->present = 1;

#ifdef __NEXUSXEN__
    if(pin_new_ptab) {
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
    
    // PDE may not constraint access control. memmap_get_region_ex should
    // always return a virtual address that passes these asserts.
    assert(!writable || pde->rw);
    assert(!user || pde->user);
  }

  // PTE
  pte = vaddr_to_pte(pde, vaddr);
  if (!PageTableEntry_checkAvailable(pte)) { 
    printk("Double virtual address use detected at %u\n", vaddr);
    nexuspanic();	///< debug XXX remove.
    return 0;
  } 

  // write the PTE
  pte->pagebase = (paddr >> 12) & 0xfffff;	// only need to store upper 20 bits
  pte->rw = writable;
  pte->user = user;
  pte->uncached = uncached;
  pte->writethrough = writethrough;

  // add to queue of used pages. for dealloc at kill/exit
  // XXX remove. can be learned by walking the tree
  Map_addDeallocHint(m, vaddr);

  // mark page as in use
  PageTableEntry_makePresent(pte);

  return vaddr;
}

static int 
memmap_del_page(Map *m, unsigned int vaddr) {
  DirectoryEntry *pde;
  PageTableEntry *pte;

  if (!m->pdbr)
    return -1;

  pde = vaddr_to_pde(m->pdbr, vaddr);
  if (!pde->present)
    return -1;
    
  pte = vaddr_to_pte(pde, vaddr);
  PageTableEntry_makeAvailable(pte);
  return 0;
}


////////  [unstructured ...] ////////

#if 1
void test_double_map(Map *m){
  Page *p;
  unsigned int vaddr1, vaddr2;

  p = nallocate_page();
  /* the read only copy */
  vaddr1 = remap_physical_pages(m, PADDR(p), PAGESIZE, 0, 1);
  /* the rw supervisor copy */
  vaddr2 = remap_physical_pages(m, PADDR(p), PAGESIZE, 1, 0);

  printk("vaddr1=0x%x val=0x%x\n", vaddr1, *(unsigned int *)vaddr1);
  printk("vaddr2=0x%x val=0x%x\n", vaddr2, *(unsigned int *)vaddr2);
  *(unsigned int *)vaddr2 = 0xdeadbeef;
  printk("vaddr1=0x%x val=0x%x\n", vaddr1, *(unsigned int *)vaddr1);
  printk("vaddr2=0x%x val=0x%x\n", vaddr2, *(unsigned int *)vaddr2);
}
#endif

/** Remove a mapping and free the underlying physical page */
static void 
delete_from_map(Map *m, unsigned int virtaddr) 
{
  unsigned long paddr = fast_virtToPhys_nocheck(m, virtaddr);

  memmap_del_page(m, virtaddr);
  nfree_page(PHYS_TO_PAGE(paddr));
}


// map an already-allocated physical page into a contiguous virtual address range
unsigned int remap_physical_pages(Map *m, unsigned int paddr, unsigned int size,
				  int writable, int user) {
  unsigned int vaddrhint, ret, lastaddr, offset;
  int i, npages;

  /* only the kernel is allowed to remap device pages. */
  assert(m == kernelMap);

  // XXX enforce safety of the map physical page request
  P(memMutex);

  lastaddr = paddr + size - 1;
  offset = paddr & ~PAGE_MASK;
  paddr &= PAGE_MASK;
  size = PAGE_ALIGN(lastaddr) - paddr;
  npages = (size+PAGESIZE-1) / PAGESIZE;

  /* ioremaps on behalf of user level drivers are mapped in the heap */
  if(m == kernelMap)
    ret = vaddrhint = memmap_get_region_ex(m, PHYPAGEVADDR, npages, writable, user);
  else
    ret = vaddrhint = memmap_get_region_ex(m, USERHEAPBEGIN, npages, writable, user);

  if(ret == 0) {
    V(memMutex);
    return 0;
  }

  for(i = 0; i < npages; ++i) {
    int rv;
    rv = memmap_add_page(m, 0, paddr, writable, user, 1, 1, vaddrhint);
    assert(rv != 0);
    vaddrhint += PAGESIZE;
    paddr += PAGESIZE;
  }
  V(memMutex);
  return ret + offset;
}

/*
 * All of the kernel pages are already mapped, we just need to get
 * the specified number of pages
 */

void *getKernelPages(int numpgs){
  Page *pages;

  Map_pagesused_inc(kernelMap, numpgs);
  P(memMutex);
  pages = nallocate_pages(numpgs);
  V(memMutex);
  return (void *)VADDR(pages);
}

void freeKernelPages(void *vaddr, int numpgs){
  P(memMutex);
  int j;
  for(j=0; j < numpgs; j++) {
    nfree_page_vaddr((unsigned int)(vaddr + j * PAGE_SIZE));
  }
  V(memMutex);
}

int freeKernelPages_Xen(IPD *owner, u32 paddr, int numpgs) {
  // Used by Xen: Free the pages starting at vaddr. The page must have
  // reference count of 0, and be owned by ipd
  P(memMutex);
  int rv = 0;
  int j;
  for(j=0; j < numpgs; j++) {
    Page *page = PHYS_TO_PAGE(paddr + j * PAGE_SIZE);
    if(page->pagerefcnt != 1 || page->owner != owner->id) {
      printk_red("Bad refcnt or owner! %d @ %p (j=%d)\n", page->pagerefcnt, 
		 PADDR(page), j);
      rv = -SC_INVALID;
      goto out;
    }
    if(! nfree_page(page) ) {
      printk_red("Could not free page @ %p (j=%d)!\n", 
		 PADDR(page), j); 
      rv = -SC_ACCESSERROR;
      goto out;
    }
  }
 out:
  V(memMutex);
  return rv;
}

/* allocates as many as size physical pages at the hinted virtual address
   and returns the physical address of the first one.
*/
unsigned int 
map_physical_pages(Map *m, unsigned int npages, int writable, int user,
		   unsigned int *vaddrhintptr) 
{
  Page *pages, *page;
  unsigned int vaddrhint;
  int i;

  P(memMutex);

  // find a free virtual memory range
  *vaddrhintptr = vaddrhint = memmap_get_region_ex(m, *vaddrhintptr, npages, user, writable);

  // allocate
  Map_pagesused_inc(m, npages);
  pages = nallocate_pages(npages);
  
  page = pages;
  for(i = 0; i < npages; i++) {
    pagememzero_n(VADDR(page), 1);

    // insert page in virtual memory map
    if (memmap_add_page(m, 0, PADDR(page), writable, user, 1, 1, vaddrhint) != vaddrhint) {
      printkx(PK_MEM, PK_WARN, "[mem] map physical failed\n");
      return -1;
    }

    page++;
    vaddrhint += PAGESIZE;
  }
  V(memMutex);

  return PADDR(pages);
}

/*
 * given a virtual address, find the corresponding physical
 * address
 */
unsigned int map_get_physical_address(Map *m, unsigned int vaddr) {
  unsigned int offset;

  offset = vaddr % PAGESIZE;
  vaddr = round(vaddr, PAGESIZE);

  unsigned int paddr;
  P(memMutex);
  paddr = fast_virtToPhys_nocheck(m, vaddr);
  V(memMutex);
  return paddr + offset;
}

/* check if the dirty bit for the page containing the vaddr is on */
int map_isdirty(Map *m, unsigned int vaddr) {
  DirectoryEntry *pde;
  PageTableEntry *pte;

  pde = vaddr_to_pde(m->pdbr, vaddr);
  if(!pde->present) {
    //shouldn't happen
    return 0;
  }
  pte = vaddr_to_pte(pde, vaddr);
  if(!PageTableEntry_checkPresent(pte)) {
    //shouldn't happen
    return 0;
  } 
  if(pte->dirty){
    return 1;
  }
  return 0;
}
/* clear the dirty bit for the page containing the vaddr */
void map_cleardirty(Map *m, unsigned int vaddr) {
  DirectoryEntry *pde;
  PageTableEntry *pte;

  pde = vaddr_to_pde(m->pdbr, vaddr);
  if(!pde->present) {
    //shouldn't happen
    return;
  }
  pte = vaddr_to_pte(pde, vaddr);
  if(!PageTableEntry_checkPresent(pte)) {
    //shouldn't happen
    return;
  } 
  pte->dirty = 0;
}

unsigned int 
map_page_helper(Map *m, IPD *ipd, int npages, int writable, int user, 
		int uncached, int writethrough, unsigned int vaddrhint, 
		int zero) {
  Page *page;
  unsigned int ret;
  int i;

  ret = vaddrhint = memmap_get_region_ex(m, vaddrhint, npages, user, writable);
  if (!ret) {
    printkx(PK_MEM, PK_ERR, "out of memory\n");
    return 0;
  }

  // do not allow user pages to map above kernelvaddr
  if (user && vaddrhint + npages > KERNELVADDR) {
    printkx(PK_MEM, PK_ERR, "user address out of bounds\n");
    return 0;
  }

  for (i = 0; i < npages; ++i) {
    Map_pagesused_inc(m, 1);
    page = nallocate_page();

    if (ipd)
      page->owner = ipd->id;

#ifdef __NEXUSXEN__
    if(ipd->type == XEN)
      page->type = FT_RDWR;
#endif

    if (m == kernelMap) {
      vaddrhint = VADDR(page);
      if (i == 0)
	ret = vaddrhint;
    }

    int pin_new_ptab = (ipd) && ipd_isXen(ipd);
    if (memmap_add_page(m, pin_new_ptab, PADDR(page), writable, user, 
			      uncached, writethrough, vaddrhint) != vaddrhint) {
    	printkx(PK_MEM, PK_WARN, "[mem] not at hinted address\n");
    }
    if (zero)
      pagememzero_n(VADDR(page), 1);

    vaddrhint += PAGESIZE;
  }

  return ret;
}

unsigned int 
map_page(Map *m, IPD *ipd, int npages, int writable, int user, int uncached, 
         int writethrough, unsigned int vaddrhint, int zero) {
  unsigned int ret;

  P(memMutex);
  ret = map_page_helper(m, ipd, npages, writable, user, uncached, writethrough, vaddrhint, zero);
  V(memMutex);

#ifndef NDEBUG
  if (ret < vaddrhint)
    printkx(PK_MEM, PK_WARN, "map_page() wrapped around front hint\n");
#endif
  return ret;
}

void Map_setProt(Map *m, unsigned int orig, int len, unsigned int prot){
  DirectoryEntry *pde;
  PageTableEntry *pte;
  unsigned int vaddr;

  for(vaddr = orig; vaddr < orig + len; vaddr += PAGESIZE){
    pde = vaddr_to_pde(m->pdbr, vaddr);
    if(pde->bigpage) {
      printk_red("Map_setProt(%p,%d) is big page!\n", orig, len);
      assert(0);
    }

    pte = vaddr_to_pte(pde, vaddr);
    pte->rw = (prot & PROT_WRITE) ? 1 : 0;
    if((prot & PROT_READ) || pte->rw) {
      PageTableEntry_makePresent(pte);
    } else {
      PageTableEntry_makeUnpresentButProtected(pte);
    }
  }
  flushglobalTLB();
}


static unsigned int remap_page(Map *srcm, Map *dstm,
			int npages, u32 vaddr, int olduser, int oldwrite, 
			int writable, int user, int uncached, int writethrough, 
			u32 vaddrhint) {
  unsigned int ret, *physaddr;
  int i;
  unsigned int offset;
  
  offset = vaddr % PAGESIZE;
  vaddr -= offset;

  P(memMutex);

  /* make sure we have a vaddr to remap to */
  ret = vaddrhint = memmap_get_region(dstm, vaddrhint, npages);
  if(ret == 0)
    return 0;

  /* make sure physaddrs make sense */
  physaddr = (unsigned int *) galloc(npages * sizeof(unsigned int));
  for(i = 0; i < npages; ++i) {
    if(srcm == kernelMap)
      physaddr[i] = VIRT_TO_PHYS(vaddr + i*PAGESIZE);
    else
      physaddr[i] = fast_virtToPhys(srcm, vaddr + i*PAGESIZE, olduser, oldwrite);
    if(physaddr[i] == 0){
      gfree(physaddr);
      return 0;
    }
  }

  for(i = 0; i < npages; ++i) {
    ((PHYS_TO_PAGE(physaddr[i]))->pagerefcnt)++;

    /* this will never fail, since vaddrhint_check succeeded */
    memmap_add_page(dstm, 0, physaddr[i], 
			  writable, user, uncached, writethrough,
			  vaddrhint);

		/* done with the page at vaddrhint, on to the next page */
    vaddrhint += PAGESIZE;
  }
  V(memMutex);

  gfree(physaddr);
  return ret + offset;
}

/* remap a user page to another place in the same address space maybe
 * with different permissions */
unsigned int remap_user_page(Map *m,
			     int npages, u32 vaddr, int olduser, int oldwrite, 
			     int writable, int user, int uncached, int writethrough, 
			     u32 vaddrhint) {
  return remap_page(m, m, npages, vaddr, olduser, oldwrite, writable, user, 
		    uncached, writethrough, vaddrhint);
}

/* remap a kernel page readonly into a user process */
unsigned int remap_kernel_page_readonly(Map *dstm, int npages, u32 vaddr, u32 vhint){
  return remap_page(kernelMap, dstm, npages, vaddr, 0, 1, 0, 1, 0, 0, vhint);
}


int remap_vpage(Map *m, int npages, u32 vaddr_src, int writable, int user, int uncached, int writethrough, u32 vaddr_dest) {
  printk("remap_vpage: not tested\n");
  nexuspanic();
  int found;
  P(memMutex);

  if(vaddr_dest != memmap_get_region(m, vaddr_dest, npages)) {
    printk("remap page: page already mapped at %d!\n", vaddr_dest);
    return -1;
  }
  // Find the mapping corresponding to vaddr_src
  found = 0;
  V(memMutex);
  return 0;
}

/** Move a mapping from one virtual memory address space to another. */
Page *transfer_page(Map *dst_map, char *dst_addr, Map *src_map, char *src_addr, int replace) {
  printk_red("transfer_page() used; page ownership not preserved!\n");
  Page *destPage;
  P(memMutex);
  if(dst_map == kernelMap) {
    // Destination is kernel, transfer is the canonical address
    assert(dst_addr == NULL);
    unsigned int phys = fast_virtToPhys(src_map, (unsigned int)src_addr, 1, 1);
    if(phys == 0) {
      printk("transfer_page: invalid source\n");
      V(memMutex);
      return NULL;
    }
    destPage = PHYS_TO_PAGE(phys);
    if(destPage->pagerefcnt != 1) {
      printk("transfer_page: multiply mapped!\n");
      V(memMutex);
      return NULL;
    }

    Page_get(destPage);

    delete_from_map(src_map, (unsigned int)src_addr);
    goto finish; // XXX kwalsh: this is stupid use of goto -- restructure this function...
  }
  printk("unhandled transfer page case!\n");
  nexuspanic();
  return NULL;

 finish:
    // Give the user back a page
  if(replace) {
    int flags = Map_getPageFlags(src_map, (unsigned int)src_addr);
    int actual = map_page_helper(src_map, NULL, 1, (flags & PAGEFLAG_WRITE) ? 1 : 0, 1, 0, 0,
			  (unsigned int)src_addr, 1);
    if(actual != (int)src_addr) {
      printk_red("returning page did %p instead of %p\n", actual, src_addr);
      // nexuspanic();
    }
  }
  V(memMutex);
  return destPage;
}

void unmap_pages(Map *m, int v, int npages) {
  int i;

  for (i = 0; i < npages; i++)
    delete_from_map(m, v + (i << PAGE_SHIFT));

  flushTLB();
}

void Map_setPDBR(Map *m, Page *newPDBR) {
  // This is only supported for Xen IPDs
  assert(m->owner); ///< indicates Xen
  m->pdbr = newPDBR;
}

void Map_activate(Map *m, BasicThread *ut) {
  if(m->pdbr == 0) {
    printk("No pages have been mapped to this address space!\n");
    nexuspanic();
    return;
  }
  writecr3((PADDR(m->pdbr) & PAGE_MASK));
  // save curr_map for nexusthread_current_map()
  if(m != kernelMap) {
    curr_map = m;
  } else {
    curr_map = NULL;
  }
#ifdef __NEXUSXEN__
  if(nexusthread_isXen(ut)) {
    thread_Xen_vLDT_writeReal(ut);
  } else 
#endif
  {
    write_ldt(0,0);
  }

  IPD *ipd = nexusthread_get_base_ipd(ut);
  if(ipd_hasMappedFB(ipd)) {
    // We need to check on every activation since the active map when
    // switching to/from a Xen IPD might not be the map with a mapped
    // FB
    ipd_PDIR_activated(ipd, m);
  }
}

void Map_deactivate(void) {
  curr_map = kernelMap;
  writecr3((PADDR(kernelMap->pdbr) & PAGE_MASK));
}

int Map_isActivated(Map *m) {
  return readcr3() == PADDR(m->pdbr);
}

void Map_initializeSegmentHash(Map *space) {
  hash_init(space->segInfo.hash_ctx);
}

void Map_addSegmentHash(Map *space, u8 *data, u32 vaddr, u32 vlength, u32 flags) {
  hash_update(space->segInfo.hash_ctx, (char *)&vaddr, sizeof(vaddr));
  hash_update(space->segInfo.hash_ctx, (char *)&vlength, sizeof(vlength));
  hash_update(space->segInfo.hash_ctx, (char *)&flags, sizeof(flags));
  hash_update(space->segInfo.hash_ctx, data, vlength);
}

void Map_finalizeHash(Map *space) {
  hash_final(space->segInfo.hash_ctx, &space->segInfo.hash_value[0]);
}

void Map_wholeHash(Map *space, char *file, int len){
  sha1((unsigned char *) file, len, space->segInfo.hash_value);
}

void Map_copyHashFromPrecomputed(Map *space, const struct SegmentHashInfo *precomputed_hash) {
  memcpy(&space->segInfo, precomputed_hash, sizeof(*precomputed_hash));
}

void Map_copyHashToPrecomputed(const Map *space, struct SegmentHashInfo *precomputed_hash) {
  memcpy(precomputed_hash, &space->segInfo, sizeof(*precomputed_hash));
}

const char *Map_getHashValue(Map *space) {
  return (char *) space->segInfo.hash_value;
}

static void fixrange_init (unsigned long start, unsigned long end, unsigned int *dirbase)
{
  int offset;

  offset = ((start >> 22) & (1024 - 1));

  map_page(kernelMap, NULL, 1024 - offset, 1, 0, 0, 0, start, 1);
}

void zap_low_pages(void){
  __u32 *pdiraddr;

  pdiraddr = (unsigned int *)PHYS_TO_VIRT(readcr3() & 0xfffff000);

  __u32 vaddr;
  for(vaddr = 0; vaddr < KERNELVADDR; vaddr += PAGESIZE * 1024) {
    __u32 *pde = &pdiraddr[vaddr >> PDIR_SHIFT];
    // PageTableEntry *pte;
    if(((DirectoryEntry*)pde)->present) {
      num_zapped_low_ptab++;
    }
    *pde = 0;
  }
  flushglobalTLB();
}

/* insert a page directory entry for every address that will
 * eventually hold a device mapping so that the page tables for
 * devices are shared in kernel mode in every subsequent address
 * space regardless of how late they are added.*/
void init_device_region(void){
  Page *ptpage;
  DirectoryEntry *pde;
  int diroffset;
  unsigned int vaddr;

  for(vaddr = PHYPAGEVADDR; vaddr < KERNELVADDR; vaddr += (1 << PAGEDIROFFSET)){
    pde = vaddr_to_pde(kernelMap->pdbr, vaddr);

    if(!pde->present) {
      Map_pagesused_inc(kernelMap, 1);
      ptpage = nallocate_page();

      Qpage *qpage = (Qpage *) galloc(sizeof(Qpage));
      qpage->page = ptpage;
      if (queue_append(kernelMap->pagetables, qpage) < 0)
	printk("MEM: couldn't add pagetable page to queue\n");

      pagememzero_n(VADDR(ptpage), 1);
      pde->physaddr = (PADDR(ptpage) >> 12) & 0xfffff;
      pde->present = 1;
      pde->rw = 1;
      pde->user = 0;
      pde->uncached = 1;
      pde->writethrough = 1;
    }
  }
}

void pagetable_init(void){
  DirectoryEntry *pde;
  unsigned int *dirbase, *direntry;
  unsigned int offset, start_offset;
  unsigned long vaddr, end;

  dirbase = (unsigned int *)swapper_pg_dir;

  kernelMap->pdbr = PHYS_TO_PAGE(VIRT_TO_PHYS(swapper_pg_dir));
  kernelMap->pdbr->pagerefcnt = 1;

  if (nexus_max_pfn > 0x40000000)
	  nexuspanic();

  end = PHYS_TO_VIRT(nexus_max_pfn);
  start_offset = ((KERNELVADDR >> 22) & (1024 - 1));
  direntry = dirbase + start_offset;

  // enable large page and selective TLB flush support
  set_in_cr4(X86_CR4_PSE);
  set_in_cr4(X86_CR4_PGE);
  boot_cpu_data.wp_works_ok = 1;

  // XXX: how many 4MB PDEs do we setup? is this what we want?
  for (offset = start_offset; offset < 1024; offset++) {
    vaddr = offset << 22;	// shift by 4MB
    if (end && (vaddr >= end))
      break;

    // initialize the 4MB kernel pagedir. 
    // This code is not very legible, but the PDE is filled in correctly
    // see for instance http://valhalla.bofh.pl/~l4mer/WDM/secureread/pde-pte.htm for PDE layout
    *direntry = (VIRT_TO_PHYS(vaddr)) | (1 << 8) | (1 << 7) | (1 << 6) | (1 << 5) | (1 << 1) | 1;
    direntry++;
  } 

  /*
   * Fixed mappings, only the page table structure has to be
   * created - mappings will be set by set_fixmap():
   */
  vaddr = __fix_to_virt(__end_of_fixed_addresses - 1) & PMD_MASK;
  fixrange_init(vaddr, 0, dirbase);

  zap_low_pages(); /* call is moved to arch/i386/setup.c */
  init_device_region();
}

int map_contains_addr(Map *map, unsigned int addr){
  unsigned int rounded = addr & PAGE_MASK;
  if(fast_virtToPhys(map, rounded, 1, 1) == 0)
    return 0;
  return 1;
}

struct HashTable *varlen_table;

void log_varlen(int len) {
  if(nexusthread_current_ipd() != NULL && nexusthread_current_ipd()->id == 8) {
    if(varlen_table == NULL) {
      varlen_table = hash_new(100, sizeof(int));
    }
    int *count_p = hash_findItem(varlen_table, &len);
    if(count_p == NULL) {
      count_p = galloc(2 * sizeof(int));
      count_p[0] = len;
      count_p[1] = 0;
      hash_insert(varlen_table, &len, count_p);
    }
    count_p[1]++;
  }
}

int log_memcpy;
int exception_memcpy(void *dest, const void *src, int len) {
  /* returns 0 if success, nonzero if error */
  static int memcpy_count;
  memcpy_count++;
  if(log_memcpy && nexusthread_current_ipd() != NULL && 
     nexusthread_current_ipd()->id == 8) {
    int intlevel = disable_intr();
    nexuslog("%d.%d exception_memcpy(%d), memcpy count = %d\n", 
	     nexusthread_current_ipd()->id, nexusthread_self()->id, len,
	     memcpy_count);
    log_trace(NULL);

    if(0) {
      log_memcpy = 0;
      nexusthread_dump_regs_stack(nexusthread_self());
      log_memcpy = 1;
    }

    restore_intr(intlevel);
  }
  int rv;
  __asm__ ( 
	   "	movl	%%ecx,%%eax\n"
	   "	andl	$3,%%eax\n"			/* copy remaining bytes */
	   "	shrl	$2,%%ecx\n"			/* copy longword-wise */
	   "1:	rep movsl\n"
	   "	test $0x2, %%eax\n"
	   "	je 8f\n"
	   "2:	movsw\n"
	   "8:	test $0x1, %%eax\n"
	   "	je 9f\n"
	   "3:	movsb\n"
	   "9:\n"
	   "	xor %%eax,%%eax\n"
	   "99:\n"
	   /* end of function */

	   ".section __nexus_ex_table,\"a\"\n"

	   "	.int 1b\n"
	   "	.int 10f\n"

	   "	.int 2b\n"
	   "	.int 10f\n"

	   "	.int 3b\n"
	   "	.int 10f\n"
	   ".previous\n"
	   ".section .fixup, \"ax\"\n"
	   "10:\n"
	   "	movl $-1, %%eax\n"
	   "	jmp 99b\n"
	   ".previous\n"
	   : "=a" (rv) : "c" (len), "S" (src), "D"  (dest) );
    return rv;
}

// this version uses find_mapping (slow!)
int poke_user_slow(Map *m, unsigned int virtaddr, const void *data, int size) {
  unsigned int offset;
  unsigned int delta;
  
#ifndef NONEXUSDEBUG
//  printk("%s START  \n", __FUNCTION__);
//  nexusthread_sleep(500);
#endif

  P(memMutex);
  delta = virtaddr % PAGESIZE;
  if(delta > 0) {
    // the virtual adddress does not begin on a page boundary
    unsigned int paddr = fast_virtToPhys_nocheck(m, round(virtaddr, PAGESIZE));
    if(paddr == 0){
      printk("poke(@%d): 0x%x 0x%x\n", 
	     __LINE__, virtaddr, round(virtaddr, PAGESIZE));
      //page fault to get stack trace and panic
      *(int *)NULL = 1;
    }
    pagememcpy(PHYS_TO_VIRT(paddr) + delta, data, nmin(PAGESIZE - delta, size));

    // adjust the rest of the paramaters
    data += PAGESIZE - delta;
    size -= PAGESIZE - delta;
    virtaddr += PAGESIZE - delta;
  }
  if(size > 0) {
    // now the pointers should all be aligned to page boundaries
    for(offset = 0; offset < size; offset += PAGESIZE) {
      // find the page
      unsigned int paddr = fast_virtToPhys_nocheck(m, virtaddr+offset);
      if(paddr == 0){
	printk("poke(@%d): 0x%x 0x%x\n", __LINE__, virtaddr, virtaddr + offset);
	//page fault to get stack trace and panic
	*(int *)NULL = 1;
      }
      pagememcpy(PHYS_TO_VIRT(paddr), data + offset, nmin(PAGESIZE, size - offset));
    }
  }
  V(memMutex);

#ifndef NONEXUSDEBUG
//  printk_red("STOP\n");
//  nexusthread_sleep(500);
#endif

  return 0;
}

// this version walks page table

int peek_user_slow(Map *m, unsigned int virtaddr, void *data, int size) {
  unsigned int frame;
  unsigned int offset;
  unsigned int delta;

#ifndef NONEXUSDEBUG
//  printk("%s START\n", __FUNCTION__);
//  nexusthread_sleep(500);
#endif

  P(memMutex);
  delta = virtaddr % PAGESIZE;
  if(delta > 0) {
    // the virtual adddress does not begin on a page boundary
    frame = fast_virtToPhys(m, round(virtaddr, PAGESIZE), 1, 0);
    if(frame == 0){
      printk_red("peek: 0x%x 0x%x\n", virtaddr, round(virtaddr, PAGESIZE));
#ifndef NONEXUSDEBUG
//  printk("STOP\n");
//  nexusthread_sleep(500);
#endif

      V(memMutex);
      return -1;
    }
    // do the copy now
    pagememcpy(data, PHYS_TO_VIRT(frame) + delta, nmin(PAGESIZE - delta, size));
PROFILER_FLAG(peek_user_0);

    // adjust the rest of the paramaters
    data += PAGESIZE - delta;
    size -= PAGESIZE - delta;
    virtaddr += PAGESIZE - delta;
  }
  if(size > 0) {
    // now the pointers should all be aligned to page boundaries
    for(offset = 0; offset < size; offset += PAGESIZE) {
      // find the page
      frame = fast_virtToPhys(m, virtaddr+offset, 1, 0);
      if(frame == 0){
	V(memMutex);
#ifndef NONEXUSDEBUG
//  printk_red("STOP\n");
//  nexusthread_sleep(500);
#endif

	return -1;
      }
      // do the copy now
      pagememcpy(data + offset, PHYS_TO_VIRT(frame), nmin(PAGESIZE, size - offset));
PROFILER_FLAG(peek_user_1);
    }
  }
  V(memMutex);
#ifndef NONEXUSDEBUG
//  printk_red("STOP\n");
//  nexusthread_sleep(500);
#endif


  return 0;
}

int peek_strncpy(Map *m, unsigned int virtaddr, char *data, int max_size) {
  char c;
  int i = 0;
  data[max_size - 1] = '\0';
  for(i=0; i < max_size - 1; i++) {
    if(peek_user(m, virtaddr + i, &c, 1) != 0) {
      return -SC_ACCESSERROR;
    }
    data[i] = c;
    if(c == '\0') {
      break;
    }
  }
  if(i == max_size - 1) {
    printk_red("peek_strcpy(): not enough space for full userspace string\n");
    return -1;
  }
  return 0;
}

int poke_strncpy(Map *m, unsigned int virtaddr, char *data, int max_size) {
  int i;
  int done = 0;
  for(i=0; i < max_size; i++) {
    if(poke_user(m, virtaddr + i, data + i, 1) != 0) {
      return -SC_ACCESSERROR;
    }
    if(data[i] == '\0') {
      done = 1;
      break;
    }
  }
  if(i == max_size && !done) {
    printk_red("poke_strncpy(): not enough space for full string (max = %d, needed %d)\n", max_size, strlen(data));
    return -SC_NORESULTMEM;
  }
  return 0;
}

int peek_strlen(Map *m, unsigned int virtaddr) {
  int i;
  char c;
  for(i=0; ; i++) {
    if(peek_user(m, virtaddr + i, &c, 1) != 0) {
      return -SC_ACCESSERROR;
    }
    if(c == '\0') {
      return i;
    }
  }
}

char *peek_strdup(Map *map, unsigned int virtaddr, int *err) {
    int len = peek_strlen(map, virtaddr);
    *err = 0;
    if(len < 0) {
      *err = -SC_ACCESSERROR;
      return NULL;
    }
    char *name = galloc(len + 1);
    if(name == NULL) {
      *err = -SC_NOMEM;
      return NULL;
    }

    if(peek_user(map, virtaddr, name, len) != 0) {
      gfree(name);
      *err = -SC_ACCESSERROR;
      return NULL;
    }
    name[len] = '\0';
    return name;
}

extern int transfer_user(Map *m_dst, unsigned int virtaddr_dst, 
			 Map *m_src, unsigned int virtaddr_src,
			 int size) {
  unsigned int src_page, dst_page, src_vaddr = 0, dst_vaddr = 0;
  int src_new = 1, dst_new = 1;

  if(m_dst == NULL && m_src == NULL) {
    memcpy((void *)virtaddr_dst, (void *)virtaddr_src, size);
    return 0;
  }
  // Fast path optimizations
  if(m_dst == NULL && m_src == nexusthread_current_map()) {
    //printk("(fp0)");
    return peek_user_fast(virtaddr_src, (char *)virtaddr_dst, size);
  }
  if(m_src == NULL && m_dst == nexusthread_current_map()) {
    //printk("(fp1)");
    return poke_user_fast(virtaddr_dst, (char *)virtaddr_src, size);
  }
  if(m_src == nexusthread_current_map() && m_dst == nexusthread_current_map()) {
    //printk("(fp2)");
    return poke_user_fast(virtaddr_dst, (char *)virtaddr_src, size);
  }
  // "medium-fast": source or dest is current map
  // Still requires going through page table walk on at least one side, so do this with the loop
  int dst_medium_fast = 0,
    src_medium_fast = 0;
#ifdef DO_CRASH_AT_STACKCOPY
#if 1
  // Medium-fast path optimization
  if(m_dst == nexusthread_current_map()) {
    // printk("(mf0)");
    dst_medium_fast = 1;
  }
  if(m_src == nexusthread_current_map()) {
    // printk("(mf1)");
    src_medium_fast = 1;
  }
#endif
#endif

  while(size > 0) {
    if(src_new) {
      src_page = round(virtaddr_src, PAGESIZE);

      if(m_src != NULL || !src_medium_fast) {
	unsigned int src_frame = fast_virtToPhys(m_src, src_page, 1, 0);
	if(src_frame == 0) {
	  return -1;
	}
	src_vaddr = PHYS_TO_VIRT(src_frame);
      } else {
	src_vaddr = src_page;
      }

      src_new = 0;
    }
    if(dst_new) {
      dst_page = round(virtaddr_dst, PAGESIZE);

      if(m_dst != NULL || !dst_medium_fast) {
	unsigned int dst_frame = fast_virtToPhys(m_dst, dst_page, 1, 1);
	if(dst_frame == 0) {
	  return -1;
	}
	dst_vaddr = PHYS_TO_VIRT(dst_frame);
      } else {
	dst_vaddr = dst_page;
      }

      dst_new = 0;
    }
    int src_offset = virtaddr_src % PAGESIZE;
    int dst_offset = virtaddr_dst % PAGESIZE;
    int copy_amount = nmin(nmin(PAGESIZE - src_offset, PAGESIZE - dst_offset),
			   size);
#if 0
    printk("%d (%p,%d)(%p,%d) %d\n", size, virtaddr_src, src_offset, 
	   virtaddr_dst, dst_offset, copy_amount);
#endif
    if(!(src_medium_fast || dst_medium_fast)) {
      memcpy((char *)dst_vaddr + dst_offset, (char *)src_vaddr + src_offset, copy_amount);
    } else {
      if(exception_memcpy((char *)dst_vaddr + dst_offset, (char *)src_vaddr + src_offset, copy_amount) != 0) {
	printk("error while transferring from user\n");
	return -1;
      }
    }
    virtaddr_src += copy_amount;
    virtaddr_dst += copy_amount;
    size -= copy_amount;
    if(PAGESIZE - src_offset == copy_amount) {
      src_new = 1;
    }
    if(PAGESIZE - dst_offset == copy_amount) {
      dst_new = 1;
    }
  }
  return 0;
}

/*
 * Steal some pages so we can do our own memory management.
 */
#include <asm/e820.h>
void nexus_mem_init(void) {
  int i,j;
  extern char _end;

  frameTable_init();
  nexus_max_pfn = 0;

  //use map copied from BIOS e820
  for (i = 0; i < e820.nr_map; i++) {
    unsigned long start, end;
    /* RAM? */
    if (e820.map[i].type != E820_RAM)
      continue;

    start = max((unsigned long)round((e820.map[i].addr + PAGESIZE - 1), PAGESIZE),
		(unsigned long)round((VIRT_TO_PHYS(&_end) + PAGESIZE - 1), PAGESIZE));   //round up
    end = min((unsigned long)round((e820.map[i].addr + e820.map[i].size), PAGESIZE),
			(unsigned long)(MAXPAGES*PAGESIZE)); //round down
    if(actual_e820_start == 0) {
      actual_e820_start = start;
    }

    for(j = start; j < end; j += PAGESIZE) {
      u32 framenum = j / PAGESIZE;
      frameTable[framenum].ram = 1;
      bitmap_clear(phys_bitmap, framenum);
      maxframenum = max((unsigned long)maxframenum, (unsigned long)framenum);
    }

    if (end > nexus_max_pfn)
      nexus_max_pfn = end;
  }

  nexuslog("maxframenum = %d\n", maxframenum);

  reserve_pages(0, last_kernel_boot_page(), IPD_NEXUS);

  if (!initrd_start || initrd_start + initrd_size > PHYS_TO_VIRT(nexus_max_pfn)) {
	  // initrd goes beyond end of memory -- ignore it
	  initrd_start = 0;
  } else {
	  int start = VIRT_TO_PHYS(initrd_start) / PAGE_SIZE;
	  int end = (VIRT_TO_PHYS(initrd_start) + initrd_size + PAGE_SIZE - 1)/PAGE_SIZE;
	  reserve_pages(start, end - start + 1, IPD_NEXUS);
  }

  memMutex = sema_new();
  sema_initialize(memMutex, 1);

  kernelMap = Map_new();	// NB: ->owner cannot be set yet: no kernelIPD
}

#ifdef __NEXUSXEN__

// Beginning of Xen-specific code
void xen_mem_init(void) {
#if XEN_MPT_LEN % PAGE_SIZE != 0
#error "XEN_MPT_LEN must be a multiple of PAGE_SIZE!"
#endif
  int page_len = XEN_MPT_LEN / PAGE_SIZE;
  void *vaddr = getKernelPages(page_len);
  if(vaddr == NULL) {
    printk("Could not allocate space for MPT table!\n");
    nexuspanic();
  }
  machine_to_phys = vaddr;
  memset(machine_to_phys, 0, page_len);
}

int Page_isKernelExport(Page *page) {
  __u32 paddr = PADDR(page);
  return (paddr == VIRT_TO_PHYS(nexustime_page)) ||
    (VIRT_TO_PHYS(machine_to_phys) <= paddr && 
     paddr < VIRT_TO_PHYS(machine_to_phys + XEN_MPT_LEN));
}

int Page_checkXenPermissions(Page *page, u32 perm) {
  int result = 1;
  IPD *ipd = nexusthread_current_ipd();
  if(!ipd) {
    printk("page_checkpermissions: no current ipd!\n");
    nexuspanic();
  }

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
  if(pte->present) {
    if(pte->globalpage) {
      printk_red("global not allowed in ptable\n");
      goto invalid;
    }
    Page *dest = PHYS_TO_PAGE(pte->pagebase << PAGE_SHIFT);
      
    int check_perm = PERM_READ | (pte->rw ? PERM_WRITE : 0);
    if(!Page_checkXenPermissions(dest, check_perm)) {
      printk_red("target page %x not read / (writable?) (perm = %x)\n", 
		 pte->pagebase, check_perm);
      Page_dump(dest);
      goto invalid;
    }
  }
  return 1;
 invalid:
  return 0;
}

int verify_ptable(Page *page) {
#ifdef __NEXUSXEN__
  if(page->type == FT_PTABLE && page->verified) {
    return 1;
  }
#endif
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
    if(0) { // Xen code and linux set this bit...
      if(de->reserved) {
	printk_red("reserved must be 0 (val = %p)\n", (void*)val);
	goto invalid;
      }
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

int check_and_fix_descriptor(unsigned long *d) {
#define BAD()						\
  do {							\
    printk_red("Seg bad at (%d), val is %p%p ",		\
	       __LINE__, (void*)d[1],(void*)d[0]);	\
    goto bad;						\
  } while(0)

  // This function is copied from Xen
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

// Reference counting for Xen pages
int Page_Xen_Type_pin(IPD *ipd, BasicThread *t, Page *page, __u32 pageType) {
  // pinToType does an implicit recheck. Always call Type_get() to force this check
  int rv = Page_Xen_Type_get(ipd, t, page, pageType);
  if(rv != 0) {
    return rv;
  }
  int keep_ref = 0;

  if(!(page->xenrefcnt & PAGE_TYPE_PINNED)) {
    page->xenrefcnt |= PAGE_TYPE_PINNED;
    keep_ref = 1;
  }

  // Undo forced check if this was not the first PIN
  if(!keep_ref) {
    Page_Xen_Type_put(ipd, t, page, pageType);
  }
  // printk_red("after pin: %d", page->xenrefcnt & ~PAGE_TYPE_PINNED);
  return 0;
}

void Page_Xen_Type_unpin(IPD *ipd, struct BasicThread *t, 
			 Page *page, __u32 pageType) {
  assert(page->xenrefcnt & PAGE_TYPE_PINNED);
  page->xenrefcnt &= ~PAGE_TYPE_PINNED;
  Page_Xen_Type_put(ipd, t, page, pageType);
  // printk_red("(( unpin new refcnt %d )) ", page->xenrefcnt);
}

static void Page_Xen_incRefcnt(Page *p) {
  if( (p->xenrefcnt & ~PAGE_TYPE_PINNED) < PAGE_XEN_MAX_REFCNT) {
    p->xenrefcnt++;
  } else {
    printk_red("Page reference count saturated %d-%d!\n", 
	       p - &frameTable[0], p->type);
  }
}

static void Page_Xen_decRefcnt(Page *p) {
  if( (p->xenrefcnt & ~PAGE_TYPE_PINNED) > 0) {
    p->xenrefcnt--;
  } else {
    printk_red("Page reference count already at zero (p=%p, type = %d, owner = %d, cnt = %d)!\n", p, p->type, p->owner, p->xenrefcnt & ~PAGE_TYPE_PINNED);
    ASSERTNOTREACHED();
  }
}

// Page_Xen_Type_get_force() was a bad idea. It was used to allocate a
// page on behalf of the client (in particular, insert a new
// ptable). However, this is dangerous because the client has a fixed
// notion of the physical pages that it has. Arbitrarily giving it a
// new page can cause problems.

/*
int Page_Xen_Type_get_force(IPD *ipd, BasicThread *t, Page *page, int pageType) {
  page->type = pageType;
  Page_Xen_incRefcnt(page);
  return 0;
}
*/

int Page_Xen_Type_get(IPD *ipd, BasicThread *t, Page *page, int pageType) {
  // Do an ownership check if ipd != NULL
  if(!page->ram) {
    printk_red("Not ram page\n");
    return -EINVAL;
  }

  if(ipd != NULL) {
    if(ipd->id != page->owner) {
      printk_red("Target page has wrong owner\n");
      return -EINVAL;
    }
  }

  if(page->type == pageType && page->verified) {
    Page_Xen_incRefcnt(page);
    return 0;
  }

  switch(page->type) {
  case FT_RDWR:
    assert(page->xenrefcnt == 0);
    switch(pageType) {
    case FT_PDIRECTORY: {
      if(!verify_pdir(t, page)) return -EINVAL;
      page->u.fb.pdoffset = FB_INVALID_PDOFFSET;
      page->u.fb.is_mapped = 0;
      break;
    }
    case FT_PTABLE:
      if(!verify_ptable(page)) return -EINVAL;
      page->u.fb.is_mapped = 0;
      break;
    case FT_LDT:
      if(!verify_ldt(page)) return -EINVAL;
      break;
    case FT_GDT:
      if(!verify_gdt(page)) return -EINVAL;
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
      return -EINVAL;
    }
  }
  if(pageType == FT_RDWR) {
    // WRONG: Cannot convert type to FT_RDWR if there are references!
    assert(0);
    page->verified = 0;
  }
  Page_Xen_incRefcnt(page);
  page->type = pageType;
  page->verified = 1;
  return 0;
}

void Page_Xen_Type_put(IPD *ipd, BasicThread *t, Page *p, int frame_type) {
  assert(p->type == frame_type);
  Page_Xen_decRefcnt(p);

  assert(ipd == NULL || ipd->id == p->owner);

  if((p->xenrefcnt & ~PAGE_TYPE_PINNED) == 0) {
    assert(!(p->xenrefcnt & PAGE_TYPE_PINNED));

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

	  // printk_red(" (%d=> Put %x) ", i, de[i].physaddr);
	  // Page_dump(child);

	  if(child->type == FT_PDIRECTORY) {
	    if(child != p) {
	      // Not a self-loop
	      Page_Xen_Type_put(ipd, t, child, FT_PDIRECTORY);
	    }
	    ipd_fb_unmap(ipd ? ipd : nexusthread_current_ipd(), p);
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

// End of Xen-specific code

#endif /* __NEXUSXEN__ */

//// Map modification
static int Map_changePageFlags(Map *m, unsigned int vaddr, int flags) {
  assert(!(vaddr & (PAGESIZE - 1)));
  DirectoryEntry *pde;
  PageTableEntry *pte;

  pde = vaddr_to_pde(m->pdbr, vaddr);
#define CHECK(ENT)					\
  if(!(ENT)->present) {					\
    printk("changepageflags (%p): not present\n", (void *)vaddr);	\
    return -1;						\
  }							\

  CHECK(pde);
  if(pde->bigpage) {
    printk("bigpage not handled\n"); nexuspanic();
  }
  memmap_copy_pt(m, pde);

  pte = vaddr_to_pte(pde, vaddr);

  CHECK(pte);

  if(flags & PAGEFLAG_WRITE) {
    pte->rw = 1;
  } else {
    pte->rw = 0;
  }
  if(flags & PAGEFLAG_CACHEDISABLE) {
    pte->uncached = 1;
  } else {
    pte->uncached = 0;
  }
  if(flags & PAGEFLAG_USER) {
    pte->user = 1;
  } else {
    pte->user = 0;
  }
  return 0;
}

int Map_getPageFlags(Map *m, unsigned int vaddr) {
  int rval = 0;
  PageTableEntry *pte = vaddr_to_pte_atonce(m, vaddr);
  if(pte == NULL) return PAGEFLAG_NULL;
  if(pte->rw) {
    rval |= PAGEFLAG_WRITE;
  }
  if(pte->uncached) {
    rval |= PAGEFLAG_CACHEDISABLE;
  }
  if(pte->user) {
    rval |= PAGEFLAG_USER;
  }
  if(pte->present) {
    rval |= PAGEFLAG_PRESENT;
  }
  return rval;
}

int Map_changeRegionFlags(Map *m, unsigned int vaddr, int size, int mask, int flags) {
  u32 base = PAGE_ALIGN(vaddr);
  if(flags & PAGEFLAG_PRESENT) {
    printk_red("PAGEFLAG_PRESENT passed to changeRegionFlags!\n");
    flags &= ~PAGEFLAG_PRESENT;
  }
  while(base < vaddr + size) {
    int orig_flags = Map_getPageFlags(m, base);
    if(!(flags & PAGEFLAG_NULL)) {
      orig_flags &= ~mask;
      if(Map_changePageFlags(m, base, orig_flags | flags) != 0) {
	printk("error while changing region flags!\n");
	return -1;
      }
    }
    base += PAGE_SIZE;
  }
  return 0;
}

Page *Map_getRoot(Map *m) {
  return m->pdbr;
}

#ifdef __NEXUSXEN__

int Map_Xen_initFTTypes(Map *m, IPD *ipd) {
  // Mark all page table pages below KERNEL_VADDR with the appropriate
  // FT types.

  // They will start out validated since they came from Nexus
  Page *root = m->pdbr;
  if(root->type != FT_NRDWR) {
    printk_red("Map_Xen_initFTTypes(): Bad root type!\n");
    assert(0);
  }
  root->owner = ipd->id;
  root->type = FT_PDIRECTORY;
  root->verified = 1;
  root->xenrefcnt = 1;

  DirectoryEntry *pdes = (DirectoryEntry *) VADDR(root);
  int diroffset;
  int not_ptab_owner = 0;
  int not_dpage_owner = 0;
  for(diroffset = 0;
      diroffset < (NEXUS_START >> PDIR_SHIFT);
      diroffset++) {
    DirectoryEntry *pde = &pdes[diroffset];
    if(pde->present) {
      Page *ptpage = PHYS_TO_PAGE(pde->physaddr << PAGE_SHIFT);
      if(!(ptpage->type == FT_NRDWR || ptpage->type == FT_PTABLE)) {
	printk_red("Page type (%d) at %p (pde level %d) don't make sense\n",
		   ptpage->type, PADDR(ptpage), diroffset);
	return -1;
      }
      if(ptpage->owner != ipd->id) {
	// Take ownership of all pt pages
	ptpage->owner = ipd->id;
	not_ptab_owner++;
      }
      ptpage->type = FT_PTABLE;
      ptpage->verified = 1;

      // Make PTE pages FT_RDWR
      PageTableEntry *ptes = (PageTableEntry *) VADDR(ptpage);
      int ptoffset;
      for(ptoffset = 0; ptoffset < PTABLE_ENTRIES; ptoffset++) {
	PageTableEntry *pte = &ptes[ptoffset];
	if(pte->present) {
	  Page *dpage = PHYS_TO_PAGE(pte->pagebase << PAGE_SHIFT);

	  if(dpage->owner != ipd->id) {
	    printk_red("Page owner (pte level %d %d %x)=> "
		       "%p @ %p is %d, wanted %d\n",
		       diroffset, ptoffset, pte->pagebase,
		       (diroffset << PDIR_SHIFT) | (ptoffset << PAGE_SHIFT),
		       PADDR(dpage), dpage->owner, ipd->id);
	    printk_red("parent is %d , pte is %p ", ptpage - &frameTable[0], pte); Page_dump(ptpage);
	    // This will happen for Nexus read-only data page
	    not_dpage_owner++;
	    continue;
	  }

	  if(!(dpage->type == FT_NRDWR || dpage->type == FT_RDWR)) {
	    printk_red("Page type (%d) at %p (pte level %d %d) don't make sense\n",
		       dpage->type, PADDR(dpage), diroffset, ptoffset);
	    return -1;
	  }

	  // 12/4 If we were more clever, we could distinguish between
	  // FT_RDWR and FT_READ. It is unclear whether this extra
	  // functionality is needed.
	  dpage->type = FT_RDWR;
	  // no verification needed for RDWR, as there are no
	  // semantics for RDWR
	  dpage->verified = 0; 
	}
      }
    }
  }
  if(not_ptab_owner > 0 || not_dpage_owner > 0) {
    printk_red("InitFTTypes: %d, %d pages not owned\n", not_ptab_owner, not_dpage_owner);
  }
  return 0;
}

#endif /* __NEXUSXEN__ */

int m2p_update(IPD *ipd, __u32 ptr, __u32 val) {
  // ptr = the machine address of the page, i.e. << PAGE_SHIFT
  // val = the virtual frame number
  __u32 mfn = ptr >> PAGE_SHIFT;
  if(mfn >= (nexus_max_pfn >> PAGE_SHIFT)) {
    printk_red("mfn (%d) > max_pfn (%d)!\n", mfn, nexus_max_pfn);
    return -1;
  }
  if(frameTable[mfn].owner != ipd->id) {
    printk_red("mfn %d owned by %d, not %d (ptr=%p,val=%p)!\n", 
	       mfn, frameTable[mfn].owner, ipd->id,
	       (void *)ptr, (void *)val);
    return -1;
  }
  machine_to_phys[mfn] = val;
  return 0;
}

void check_multiple_mapping(Map *m, u32 vaddr) {
#define PING() printk_current("(%d)", __LINE__)
  printk_red("checking for multiple mappings\n");
  u32 phys = fast_virtToPhys_nocheck(m, vaddr);
  printk_red("vaddr = %p, phys = %p\n", vaddr, phys);
  int diroffset;
  Map *target_m;
#define NUM_MAPPINGS (20)
  int target_found = 0;
  int dup_count = 0;
  int i;
  for(i=1; i < NUM_MAPPINGS; i++) {
    int mapping_first = 1;
    IPD *ipd = ipd_find(i);
    if(ipd == NULL) continue;
    target_m = ipd->map;
    if(target_m == NULL) {
      printk_red("null map?");
      continue;
    }
    for(diroffset = 0; diroffset < PAGE_SIZE / sizeof(DirectoryEntry); diroffset++) {
      DirectoryEntry *pde = &((DirectoryEntry *)VADDR(target_m->pdbr))[diroffset];
      if(!pde->present) continue;
      int pageoffset;
      for(pageoffset = 0; pageoffset < PAGE_SIZE / sizeof(PageTableEntry); pageoffset++) {
	PageTableEntry *pte = 
	  &((PageTableEntry *)PHYS_TO_VIRT(pde->physaddr << 12))[pageoffset];
	if(!pte->present) continue;
	if(pte->pagebase << 12 == phys) {
	  u32 finger_vaddr = ((diroffset << 22) | ( pageoffset << 12));
	  printk_red("[%d:%p]", i, finger_vaddr);
	  int found_in_target = 0;
	  if(target_m == m && 
	     finger_vaddr == (vaddr & ~0x00000fff)) {
	    printk_current("found in target\n");
	    found_in_target = 1;
	    target_found = 1;
	  }
	  if(!found_in_target) {
	    if(mapping_first) {
	      printk_red("(%d:%p)", i, finger_vaddr);
	      mapping_first = 0;
	    }
	    dup_count++;
	  }
	}
      }
    }
  }
  printk_red("%d dups ", dup_count);
  if(!target_found) printk_red("target not found!");
  printk_red("\n");
}

const unsigned char guard_step = 3;

static unsigned char guard_init(unsigned char *dest) {
  __u32 dest_i = (__u32) dest;
  // try to prevent 2 guards for different addresses from being
  // identical
  return (unsigned char) 
    (dest_i ^ (dest_i >> 7) ^ (dest_i >> 17));
}

void write_guard(unsigned char *dest, int len) {
  int i;
  unsigned char guard_accum = guard_init(dest);
  for(i=0; i < len; i++) {
    dest[i] = guard_accum;
    guard_accum += guard_step;
  }
}

int check_guard_getpos(unsigned char *dest, int len, void **pos) {
  int i;
  unsigned char guard_accum = guard_init(dest);
  for(i=0; i < len; i++) {
    if(dest[i] != guard_accum) {
      if(1) {
	printk_red("guard mismatch @ %p[%d], word is %p, expect ", 
		   dest, i, (void *)*(int *)&dest[i]);
	int j;
	for(j=0; j < 4; j++) {
	  printk_red("%02x", (int)guard_accum);
	  guard_accum += guard_step;
	}
      }
      *pos = &dest[i];
      return 0;
    }
    guard_accum += guard_step;
  }
  return 1;
}

Map *nexusthread_current_map_extern(void) {
  return nexusthread_current_map();
}

void *gmorecore(int size) {
	static unsigned long program_break;
	unsigned long vaddr;
	Page *pages;
	int numpgs;

	if (nexusthread_self() && 
	    nexusthread_in_interrupt(nexusthread_self())) {
		printk("BUG: allocation in interrupt context\n");
		nexuspanic();
	}

	if (!size)
		return (void *) program_break;

	numpgs = ((size + PAGESIZE - 1) / PAGESIZE);
	
	// galloc is called once during kernelMap = Map_new()
	// don't have that call rely on kernelMap being ready
	if (kernelMap)
		Map_pagesused_inc(kernelMap, numpgs);

	// don't acquire memory lock
	// galloc() is sometimes called with the lock already held
	// XXX: fix. this is unsafe
	pages = nallocate_pages(numpgs);
	vaddr = VADDR(pages);

	// zero pages. not strictly necessary, but afraid to remove
	pagememzero_n(vaddr, numpgs);

	program_break = vaddr + (PAGESIZE * numpgs);
	return (void *) vaddr;
}

