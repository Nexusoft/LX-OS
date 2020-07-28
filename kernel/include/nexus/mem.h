#ifndef __NEXUSMEM_H__
#define __NEXUSMEM_H__

#include <nexus/defs.h>
#include <nexus/kshmem.h>
#include <linux/compiler.h> //for likely/unlikely
// Must also update MACH2PHYS_VIRT_START and xen-loader.x
#define NEXUS_VMM_START (0xB4000000)

#define PHYS_TO_PAGE(a) ( &frameTable[(a) / ((u32) PAGE_SIZE)] )
#define VIRT_TO_PAGE(a) ( &frameTable[VIRT_TO_PHYS(a) / ((u32) PAGE_SIZE)] )

#define PADDR(p) (((p) - frameTable) * ((u32) PAGE_SIZE))
#define VADDR(p) (KERNELVADDR + (unsigned int)(PADDR(p)))

#define PHYS_TO_VIRT(addr)  ((KERNELVADDR + ((unsigned int)(addr))))
#define VIRT_TO_PHYS(addr)  (((unsigned int)(addr)) - KERNELVADDR)

#define NPAGES_FROM_BYTES(b) ((b + PAGE_SIZE - 1)/PAGE_SIZE)

// check for base + limit < kernel_vaddr, and no wrap-around
#define CHECK_USER_BASELIMIT(B,L) \
	(((unsigned) (B)) < KERNELVADDR &&        \
	 ((unsigned) (B)) + (L) > ((unsigned) (B)) && \
	 ((unsigned) (B)) + (L) <= KERNELVADDR)

#define BIGPAGE_BASE(a) ((a) & 0xffc00000)
#define BIGPAGE_OFFSET(a) ((a) & ~0xffc00000)

#define USERCODESTART  0x08000000

#define USERSTACKSTART_MAIN_DEFAULT 0x90000000
//#define USERSTACKSTART 0x9000000
#define USERSTACKSIZE_MAIN_DEFAULT  (32 * 4096)
//#define USERSTACKSIZE (64 * 4096) // XXX ashieh 5/13/2006 increased stack size needed for lf_inputcounter

#define IPD_NEXUS (0)

#include <asm/types.h>
#include "machineprimitives.h"

#define PAGE_NUM_REFCNT_BITS 7
#define PAGE_TYPE_PINNED (1 << (PAGE_NUM_REFCNT_BITS - 1))
#define PAGE_XEN_MAX_REFCNT (PAGE_TYPE_PINNED - 1)
struct Page {
  __u32 ram		: 1; /* e820 says this is ram */
  __u32 type	: 3;
  __u32 owner	: NUM_IPD_ID_BITS; 	/* Primary owning IPD. Implies
			 * administrator */
  //__u32 pagerefcnt	: 7; /* not used if acl exists */
  __u32 verified	: 1; /* Contents are verified */
  __u32 acl		: 1; /* whether acl exists */

  __u8 xenrefcnt;
  __u8 pagerefcnt; /* not used if acl exists */
/* 
   xenrefcnt is used to store Xen "type count". 
   If type count reaches 0, the type is reset to FT_RDWR.
   Type count reaching the limit is considered fatal.

   Top bit is set if and only if guest has pinned the page. On
   transition from 0=>1, the type count is incremented. On transition
   from 1=>0, the type count is decremented.
*/

  union {
    struct {
#define FB_INVALID_PDOFFSET (0)
#define FB_NUM_LENGTH_BITS 11
#define FB_MAX_LEN (1 << FB_NUM_LENGTH_BITS)
      // We keep the pdoffset here rather than IPD because different
      // Xen apps in the same IPD may map frame buffer in different
      // places

      __u32 pdoffset : 10; // 0 = no mapped fb
      __u32 is_mapped:1; // used to catch MMU updates
    } fb;
  } u;
} __attribute__ ((packed));

#define PAGEFLAG_CACHEDISABLE (0x1)
#define PAGEFLAG_USER (0x2)
#define PAGEFLAG_WRITE (0x4)
#define PAGEFLAG_PRESENT (0x8) // Not allowed in changeRegionFlags
#define PAGEFLAG_NULL (0x80000000) // not present, either because present bit is flipped, or page directory entry is not present

void Page_dump(Page *page);

typedef enum MapType MapType;
enum MapType {
  MAP = 1,
  CHECKMAP
};

#define PROT_READ       0x1             /* Page can be read.  */
#define PROT_WRITE      0x2             /* Page can be written.  */
#define PROT_EXEC       0x4             /* Page can be executed.  */
#define PROT_NONE       0x0             /* Page can not be accessed.  */

#define ATT_CTXLEN (100) // XXX hack; kwalsh: why?
#define ATT_HASHLEN (20)

struct SegmentHashInfo {
  u8 hash_ctx[ATT_CTXLEN]; // XXX allocate this on heap so that it can be deallocated once the hash is finalized
  u8 hash_value[ATT_HASHLEN];
};

extern Page *frameTable;

struct BasicThread;

#define PERM_READ (0x1)
#define PERM_WRITE (0x2)
#define PERM_ADMIN (0x8)

// Accessor functions for memory mutex outside of mem.c
void Mem_mutex_lock(void);
void Mem_mutex_unlock(void);

// Page_checkXenPermissions takes into account the frame type
int Page_checkXenPermissions(Page *page, u32 perm);
Page *Page_Xen_fromMFN_checked(__u32 mfn);
Page *Page_Xen_fromVirt_checked(Map *m, __u32 vaddr);

#define pagememset(page,val,size) memset((void *)page,val,size)
#define pagememcpy(page1,page2,size) memcpy((void *)page1,(void*)page2,size)

extern Map *kernelMap;

extern void add_physical_page(int physaddr);

// nallocate_pages() does not acquire memmutex.
// it is generally not safe to call from outside mem.c
//
// DO NOT USE. It's only here for malloc.c
Page *nallocate_pages(int numpgs);

void *getKernelPages(int numpgs);
void freeKernelPages(void *vaddr, int num);

// Used by Xen: Free the pages starting at vaddr. The page must have
// reference count of 0, and be owned by ipd
int freeKernelPages_Xen(IPD *owner, u32 paddr, int num);

extern int nfree_page(Page *page);
extern int nfree_page_vaddr(unsigned int vaddr);
extern int nfree_page_paddr(unsigned int paddr);

extern Page *get_blank_pages(int numpgs);

extern Map *Map_new(void);

extern void Map_destroy(Map *m);

extern void Map_initializeSegmentHash(Map *space);
// Each time addSegmentHash is called, a structure of the form
// { u32 vaddr, u32 vlength, u32 flags, u8 data[vlength] }
// is added to the hash (Intel byte order)
extern void Map_addSegmentHash(Map *space, u8 *data, u32 vaddr, u32 vlength, u32 flags);
extern void Map_finalizeHash(Map *space);
extern void Map_wholeHash(Map *space, char *file, int len);
extern void Map_copyHashFromPrecomputed(Map *space, const struct SegmentHashInfo *precomputed_hash);
extern void Map_copyHashToPrecomputed(const Map *space, struct SegmentHashInfo *precomputed_hash);
Map *Map_copyRW(Map *source_map);

extern const char *Map_getHashValue(Map *space);

extern void Map_setAnonCleanup(Map *space, IPD *owner);

extern int Map_getType(Map *space);

extern Page *Map_getPagetable(Map *m, unsigned int vaddr);
extern Page *PDBR_getPagetable(Page *pdbr, unsigned int vaddr);

struct DirectoryEntry;
extern struct DirectoryEntry *Map_getPDE(Map *m, unsigned int vaddr);
struct PageTableEntry;
extern struct PageTableEntry *Map_getPTE(Map *m, unsigned int vaddr);

extern unsigned int map_physical_pages(Map *m, unsigned int npages, int writable, int user, unsigned int *vaddrhintptr);
extern unsigned int remap_physical_pages(Map *m, 
					 unsigned int paddr, unsigned int size, 
					 int writable, int user);
extern unsigned int remap_device_pages(unsigned int paddr, unsigned int size);

// Preferred interface for mapping pages
extern unsigned int map_page(Map *m, IPD *ipd, int npages, int writable, int user, int uncached, int writethrough, unsigned int vaddrhint, int zero);

// Low-level interface for adding pages to a map. Use sparingly.
extern unsigned int memmap_add_page(Map *m, int pin_pdir_type,
				    unsigned int paddr,
				    int writable, int user,
				    int uncached, int writethrough,
				    unsigned int vaddr);

// remap_vpage remaps an already-mapped page, adjusting the reference
// count. Returns non-zero on failure
extern int remap_vpage(Map *m, int npages, u32 vaddr_src, int writable, int user, int uncached, int writethrough, u32 vaddr_dest);

extern unsigned int map_get_physical_address(Map *m, unsigned int vaddr);

// Fine-grain control over error handling
extern int suppress_peek_user_error;
extern int print_peek_user_count;

extern int peek_strncpy(Map *m, unsigned int virtaddr, char *data, int max_size);
extern char *peek_strdup(Map *m, unsigned int virtaddr, int *err);
extern int peek_strlen(Map *m, unsigned int virtaddr);

extern int poke_strncpy(Map *m, unsigned int virtaddr, char *data, int max_size);

extern int transfer_user(Map *m_dest, unsigned int virtaddr_dest, 
			 Map *m_src, unsigned int virtaddr_src,
			 int size);

void map_cleardirty(Map *m, unsigned int vaddr);
int map_isdirty(Map *m, unsigned int vaddr);

/* check if a map contains an address */
int map_contains_addr(Map *map, unsigned int addr);

extern void nexus_mem_init(void);
extern void xen_mem_init(void);

extern void Map_setPDBR(Map *m, Page *newPDBR);
struct GDT_Descriptor;
extern void Map_activate(Map *m, struct BasicThread *ut);

extern void Map_deactivate(void);
int Map_isActivated(Map *m);

extern int  Map_get_refcnt(Map *m);
extern int Map_get_active_thread_count(Map *m);

extern void Map_up_active_thread_count(Map *m);
extern int /* ZF value */ Map_down_active_thread_count(Map *m);

extern void Map_reap(Map *m);

// Map_changePageFlags () is static because its functionality is
// subsumed by changeRegionFlags 

// extern int Map_changePageFlags(Map *m, unsigned int vaddr, int flags);
extern int Map_getPageFlags(Map *m, unsigned int vaddr);

// flags other than mask will not be changed
extern int Map_changeRegionFlags(Map *m, unsigned int vaddr, int size,
				 int mask, int flags);

// Return the root pointer to the page table (e.g., the pdbr)
extern Page *Map_getRoot(Map *m);

extern int Map_Xen_initFTTypes(Map *m, IPD *ipd);

/* for debugging: display number of pages used. */
extern void dump_page_utilization(void);
struct StringBuffer;
extern void dump_page_utilization_to_sb(struct StringBuffer *sb);
int get_page_utilization(int ipdid);

void Map_dump(Map *m);

// transfer_page does not flush the TLB
Page *transfer_page(Map *dst_map, char *dst_addr, Map *src_map, char *src_addr, int replace);

// N.B. unmap_pages() must be called with memMutex!
void unmap_pages(Map *m, int v, int npages);

unsigned int fast_virtToPhys(Map *m, unsigned int vaddr, int user, int write);
unsigned int fast_virtToPhys_nocheck(Map *m, unsigned int vaddr);
unsigned int PDBR_virtToPhys_nocheck(Page *pdbr, unsigned int vaddr);


/* remap a user page to another place in the same address space maybe
 * with different permissions */
unsigned int remap_user_page(Map *m,
			     int npages, u32 vaddr, int olduser, int oldwrite, 
			     int writable, int user, int uncached, int writethrough, 
			     u32 vaddrhint);
/* remap a kernel page readonly into a user process */
unsigned int remap_kernel_page_readonly(Map *dstm, int npages, u32 vaddr, u32 vhint);

extern int maxframenum;
extern u32 *machine_to_phys;

struct MemStats {
  int total_pages;
  int free_pages;
};

void get_mem_utilization(MemStats *stats);

void check_multiple_mapping(Map *m, u32 vaddr);

void Page_get(Page *page);

void pagetable_init(void);

void Map_pagesused_inc(Map *m, int num);
void Map_pagesused_dec(Map *m, int num);
int Map_pagesused(Map *m);


void Map_setProt(Map *m, unsigned int addr, int len, unsigned int prot);

// Debugging routines

void write_guard(unsigned char *dest, int len);
int check_guard_getpos(unsigned char *dest, int len, void **position);
static inline int check_guard(unsigned char *dest, int len) {
  void *ignored;
  return check_guard_getpos(dest, len, &ignored);
}

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


// inline functions

Map *nexusthread_current_map_extern(void);

static inline Map *
nexusthread_current_map(void) 
{
  extern Map *curr_map;
  return curr_map;
}


int exception_memcpy(void *dest, const void *src, int len);

// see kernel/test/mem.c for explanation and benchmark
// in short: these optimizations offer little gain and
// one (constant_...) has been shown buggy when using high addresses
#ifdef MEMCPY_OPTIMIZE
static inline int exception_memcpy_movs(char *dest, const char *src, int len);

#define INLINE

#define exception_memcpy_inline(dest, src, len) \
   exception_memcpy_movs((dest), (src), (len))

#define FIXUP_HANDLER					\
	   ".section .fixup, \"ax\"\n"					\
	   "10:\n"							\
	   "	movl $-1, %%eax\n"					\
	   "	jmp 99b\n"						\
	   ".previous\n"						\

// this is based on Linux constant_memcpy(). On IPC benchmark, it is
// faster to always use this one, rather than using the pure assembly
// exception_memcpy() code
static inline int constant_exception_memcpy_inline(char *dest, const char *src, int len) {
  // if(len <= 4) {  int rv = 0; memcpy(dest, src, len); return rv; }

  /* returns 0 if success, nonzero if error */

  // NB: This unrolling is faster than movsl on Pentium M
  int rv;
  int dummy;

#define SINGLE_COMMON(D, W,O,GOOD,HANDLER)				\
  __asm__ __volatile__ (						\
	"1:	mov" #W" %"#O"3, %"#O"1\n"				\
	"2: 	mov" #W" %"#O"1, %"#O"2\n"				\
	GOOD								\
	"99:\n"								\
	".section __nexus_ex_table,\"a\"\n"			\
								\
	"	.int 1b\n"					\
	"	.int 10f\n"					\
	"	.int 2b\n"					\
	"	.int 10f\n"					\
	".previous\n"					\
	HANDLER						\
	: "=r" (rv), "="#D (dummy),  "=m" (*dest) : "m" (*src) )
#define SINGLE(D,W,O) SINGLE_COMMON(D, W, O, "", FIXUP_HANDLER)
#define SINGLE_LAST(D,W,O) SINGLE_COMMON(D, W, O, "	xor %0,%0\n", FIXUP_HANDLER)

#define L()					\
  SINGLE(r,l,);					\
  dest += 4;					\
  src += 4;

  //#define BYTE q,b,b
  //#define WORD r,w,w
  //#define DWORD r,l,

  switch(len) {
  case 0:
    return 0;
  case 1:
    SINGLE_LAST(q,b,b);
    return rv;					
  case 2:					
    SINGLE_LAST(r,w,w);				
    return rv;					
  case 3:					
    SINGLE(r,w,w);				
    dest += 2;					
    src += 2;					
    SINGLE_LAST(q,b,b);				
    return rv;
  case 4:
    SINGLE_LAST(r,l,);
    return rv;
  case 8: // Invoke_FromIS return value size
    L();
    SINGLE_LAST(r,l,);
    return rv;
  case 12: // transfer descriptor
    L();
    L();
    SINGLE_LAST(r,l,);
    return rv;
  case 20: // AsyncReceive return value size
    L();
    L();
    L();
    L();
    SINGLE_LAST(r,l,);
    return rv;
  case 28: // transfer descriptor
    L();
    L();
    L();
    L();
    L();
    L();
    SINGLE_LAST(r,l,);
    return rv;
#if 0
  case 32: // transfer descriptor
    L();
    L();
    L();
    L();
    L();
    L();
    L();
    SINGLE_LAST(r,l,);
    return rv;
#endif
  default: ;
  }

  return exception_memcpy_movs(dest, src, len);
}

static inline int exception_memcpy_movs(char *dest, const char *src, int len) {
  int rv;
  int d1, d2;
#define COMMON(X)							\
  __asm__ __volatile__ (						\
			"1:	rep movsl\n"				\
			X						\
									\
			"	xor %%eax,%%eax\n"			\
			"99:\n"						\
			/* end of function */				\
									\
			".section __nexus_ex_table,\"a\"\n"		\
									\
			"	.int 1b\n"				\
			"	.int 10f\n"				\
									\
			"	.int 2b\n"				\
			"	.int 10f\n"				\
									\
			"	.int 3b\n"				\
			"	.int 10f\n"				\
			".previous\n"					\
			FIXUP_HANDLER					\
			: "=a" (rv), "=&S" (d1), "=&D" (d2) : "c" (len / 4), "1" ((long)src), "2"  ((long)dest) )
  switch (len % 4) {
  case 0: 
    COMMON("\n\t 2: ; \n 3: \n"); return rv;
  case 1: 
    COMMON("\n\t2: movsb \n\t3: \n"); return rv;
  case 2: 
    COMMON("\n\t2: movsw \n\t3: \n"); return rv;
  default: 
    COMMON("\n\t2: movsw\n\t3: movsb\n\t"); return rv;
  }
  return rv;
}

#undef ZEROTOTHREE
#undef L
#undef SINGLE
#undef LAST
#undef COMMON
#endif /* MEMCPY_OPTIMIZE */

#define PEEKPOKE_CHECK()						\
  (__virtaddr <= __virtaddr + __size && __virtaddr + __size < NEXUS_START)

int peek_user_slow(Map *m, unsigned int virtaddr, void *data, int size);
int poke_user_slow(Map *m, unsigned int virtaddr, const void *data, int size);

static inline int 
poke_user_fast(unsigned int __virtaddr, const void *data, int __size) 
{
#ifndef NDEBUG
  if(unlikely(!PEEKPOKE_CHECK()))
    nexuspanic();
#endif

#ifdef INLINE
  return exception_memcpy_inline((char *)__virtaddr, data, __size);
#else
  return exception_memcpy((char *)__virtaddr, data, __size);
#endif
}

// this version reads directly from the current map
static inline int 
peek_user_fast(unsigned int __virtaddr, void *data, int __size) 
{
#ifndef NDEBUG
  if(unlikely(!PEEKPOKE_CHECK()))
    nexuspanic();
#endif

#ifdef INLINE
  return exception_memcpy_inline(data, (char *)__virtaddr, __size);
#else
  return exception_memcpy(data, (char *)__virtaddr, __size);
#endif
}

static inline int 
peek_user(Map *m, unsigned int virtaddr, void *data, int size) 
{
  if (likely(nexusthread_current_map() == m))
    return peek_user_fast(virtaddr, data, size);
  else 
    return peek_user_slow(m, virtaddr, data, size);
}

static inline int 
poke_user(Map *m, unsigned int virtaddr, const void *data, int size) 
{
  if (likely(nexusthread_current_map() == m))
    return poke_user_fast(virtaddr, data, size);
  else 
    return poke_user_slow(m, virtaddr, data, size);
}

static inline int 
copy_to_generic(Map *map, void *dest, const void *src, int len) 
{
  if (map && map != kernelMap)
    return poke_user(map, (unsigned int) dest, (void *) src, len);
    
  memcpy(dest, src, len);
  return 0;
}

static inline int 
copy_from_generic(Map *map, void *dest, const void *src, int len) 
{
  if (map && map != kernelMap)
    return peek_user(map, (unsigned int) src, dest, len);

  memcpy(dest, src, len);
  return 0;
}

#undef INLINE

#endif /* __NEXUSMEM_H__ */

