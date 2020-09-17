/** NexusOS: memory handling */

#ifndef __NEXUSMEM_H__
#define __NEXUSMEM_H__

#include <nexus/defs.h>
#include <nexus/kshmem.h>
#include <linux/compiler.h> //for likely/unlikely

// Start of the supervisor region (only for Xen processes)
// Must also update MACH2PHYS_VIRT_START and xen-loader.x
#define NEXUS_VMM_START (0xB4000000)

////////  translation (phys, virt, page)  ////////

/// translate from pointer to page in pagetable to physical address
//  NB: address can be calculated from pageptr offset to frametable start
//      (as long as p is wordsize long)
#define PADDR(p) (((p) - frameTable) << ((u32) PAGE_SHIFT))

/// translate from pointer to page in pagetable to kernel logical address
#define VADDR(p) (KERNELVADDR + (unsigned int)(PADDR(p)))

#define PHYS_TO_VIRT(addr)  ((KERNELVADDR + ((unsigned int)(addr))))
#define VIRT_TO_PHYS(addr)  (((unsigned int)(addr)) - KERNELVADDR)

#define PHYS_TO_PAGE(a) ( &frameTable[(a) >> PAGE_SHIFT] )
#define VIRT_TO_PAGE(a) ( &frameTable[VIRT_TO_PHYS(a) >> PAGE_SHIFT] )

#define BIGPAGE_BASE(a) ((a) & 0xffc00000)
#define BIGPAGE_OFFSET(a) ((a) & ~0xffc00000)

#define USERCODESTART  0x08000000

#define USERSTACKSTART_MAIN_DEFAULT 0x90000000
#define USERSTACKSIZE_MAIN_DEFAULT  (32 << PAGE_SHIFT)

#include <asm/types.h>
#include "machineprimitives.h"

struct Page {
  __u8 refcnt; 				/* not used if acl exists (Xen mode) */
  __u16 owner; 				/* Primary owning IPD. */
  
  __u32 ram	: 1; 			/* e820 says this is ram */
  
  // Xen 
  __u32 alloc	: 1;			/* Allocated or free */
  __u32 type	: 3;
  __u32 verified: 1; 			/* Contents are verified */
  __u32 acl	: 1; 			/* whether acl exists */
 
   /** xenrefcnt stores Xen "type count". 
       If type count reaches 0, the type is reset to FT_RDWR.
       Type count reaching the limit is considered fatal. */
  __u8 xenrefcnt;
}; 

// flags in x86 PTE
#define PAGEFLAG_CACHEDISABLE 	(0x1)
#define PAGEFLAG_USER 		(0x2)
#define PAGEFLAG_WRITE 		(0x4)
#define PAGEFLAG_PRESENT 	(0x8) 
#define PAGEFLAG_NULL (0x80000000) // not present, either because present bit is flipped, or page directory entry is not present

#define PROT_READ       0x1             /* Page can be read.  */
#define PROT_WRITE      0x2             /* Page can be written.  */
#define PROT_EXEC       0x4             /* Page can be executed.  */
#define PROT_NONE       0x0             /* Page can not be accessed.  */

#define PERM_READ 	(0x1)
#define PERM_WRITE 	(0x2)
#define PERM_ADMIN 	(0x8)

/** Virtual memory regions: 
    brk:    grows linearly
    heap:   general allocator, from USERMMAPBEGIN and PHYPAGEVADDR 
    dev:    device io mem,     from PHYPAGEVADDR to KERNELVADDR
    kernel: kernel shared,     from KERNELVADDR to 4GB. this corresponds to 'logical mem' in Linux */
enum vmemtype {vmem_brk, vmem_heap, vmem_dev, vmem_kernel};

struct DirectoryEntry;
struct PageTableEntry;
struct BasicThread;
struct Map;

extern Map *kernelMap;
extern Page *frameTable;

unsigned long nxmem_pages_used;
unsigned long nxmem_pages_total;

// Accessor functions for memory mutex outside of mem.c
void Mem_mutex_lock(void);
void Mem_mutex_unlock(void);

#ifdef __NEXUSXEN__
Page *Page_Xen_fromMFN_checked(__u32 mfn);
Page *Page_Xen_fromVirt_checked(Map *m, __u32 vaddr);
int freeKernelPages_Xen(IPD *owner, u32 paddr, int num);
#endif

void *getKernelPages(int numpgs);
void freeKernelPages(void *vaddr, int num);

struct DirectoryEntry *Map_getPDE(Map *m, unsigned int vaddr);

// physical page reference counting
// do NOT use directly

void page_get(struct Page *page, Map *map);
void page_put(struct Page *page, Map *map);

////////  virtual memory map operations  ////////

Map *Map_new(IPD *ipd);
void Map_del(Map *m);

extern void Map_activate(Map *m, struct BasicThread *ut);
extern void Map_deactivate(void);

// allocate and free pages (and insert immediately into a map)

unsigned int Map_alloc(Map *map, int npages, int writable, int user, enum vmemtype type);
unsigned int Map_alloc_fixed(Map *map, int npages, int writable, int user, unsigned long vaddr);
void         Map_free(Map *map, unsigned long vaddr, int npages);

// add/remove pages

unsigned long Map_insertAt(Map *m, unsigned long paddr, int writable, int user, 
                           int uncached, int writethrough, unsigned long vaddr);
unsigned long Map_insertNear(Map *m, Page *pages, unsigned int npages, 
			     int writable, int user, enum vmemtype);
void Map_setPDBR(Map *m, Page *newPDBR);

// page sharing (between processes)

unsigned long memmap_share_pages(int pid, unsigned long vaddr, unsigned int npages, int writable);
void memmap_set_sharepages(int available);

// information lookup 

unsigned int map_get_physical_address(Map *m, unsigned int vaddr);
extern int Map_getPageFlags(Map *m, unsigned int vaddr);
extern Page *Map_getRoot(Map *m);

// unsorted

void * Map_uvaddr_to_kvaddr(Map *map, void *uvaddr);
int Map_copyRW(Map *newmap, Map *source_map);
extern void Map_setAnonCleanup(Map *space, IPD *owner);
extern Page *PDBR_getPagetable(Page *pdbr, unsigned int vaddr);

extern Map *curr_map;

static inline Map *
nexusthread_current_map(void) 
{
  return curr_map;
}


////////  init/exit  ////////

void iomem_init(void);
void nexus_mem_init(void);
void pagetable_init(void);

#ifdef __NEXUSXEN__
void xen_mem_init(void);
int Map_Xen_initFTTypes(Map *m, IPD *ipd);
#endif


////////  device IO regions  ////////

unsigned long iomem_get(unsigned long paddr, unsigned long len);


////////  unsorted  ////////

extern void dump_page_utilization(void);

PageTableEntry * fast_virtToPTE(Map *m, unsigned long vaddr, int user, int write);
unsigned long fast_virtToPhys_locked(Map *m, unsigned long vaddr, int user, int write);
unsigned long fast_virtToPhys(Map *m, unsigned long vaddr, int user, int write);

void Map_setProt(Map *m, unsigned int addr, int len, unsigned int prot);

extern int maxframenum;
extern u32 *machine_to_phys;

// Xen MMU interfaces

struct BasicThread;
int verify_pde(Page *pdir_page, struct BasicThread *t,
	       int offset, __u32 val, int get_ref);
int verify_pdir(struct BasicThread *t, Page *page);

// put_pde returns the destination page. Used for loop detection
Page *put_pde(Page *pdir_page, int offset, __u32 val);

int verify_pte(__u32 val);
int verify_ptable(Page *page);

int m2p_update(IPD *ipd, __u32 ptr, __u32 val);
int verify_ldt(Page *page);
int verify_gdt(Page *page);

int check_and_fix_descriptor(unsigned long *d);


////////  transfer between virtual memory maps  ////////

int transfer(Map *m_dest, void *uv_dest, 
	     Map *m_src,  const void *uv_src, int size);

static inline int 
peek_user(Map *m, unsigned int virtaddr, void *data, int size) 
{
  transfer(NULL, data, m, (void *) virtaddr, size);
  return 0;
}

static inline int 
poke_user(Map *m, unsigned int virtaddr, const void *data, int size) 
{
  transfer(m, (void *) virtaddr, NULL, data, size);
  return 0;
}

// XXX remove
static inline int 
copy_to_generic(Map *map, void *dest, const void *src, int len) 
{
  return poke_user(map, (unsigned int) dest, src, len);
}

// XXX remove
static inline int 
copy_from_generic(Map *map, void *dest, const void *src, int len) 
{
  return peek_user(map, (unsigned int) src, dest, len);
}

#endif /* __NEXUSMEM_H__ */

