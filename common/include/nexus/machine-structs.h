#ifndef _MACHINE_STRUCTS_H_
#define _MACHINE_STRUCTS_H_

#include <nexus/commontypedefs.h>
#include <nexus/segments.h>

/* PAGE_SHIFT determines the page size */
#define PDIR_SHIFT	22
#define PDIR_ENTRIES 	(1 << 10)

#define PTABLE_ENTRIES 	(1 << 10)

#define PTAB_SHIFT PAGE_SHIFT
#define PTAB_MASK (0x3ff << PTAB_SHIFT)

#define PAGE_SHIFT	12
#define PAGE_SIZE	(1UL << PAGE_SHIFT)
#define PAGE_MASK	(~(PAGE_SIZE-1))
#define PAGE_OFFSET_MASK	(PAGE_SIZE-1)

// The maximum virtual page #
#define PAGE_MAX ((1 << 20) - 1)

static inline unsigned int PDIR_OFFSET(unsigned int val) {
  return val >> PDIR_SHIFT;
}

static inline unsigned int PTAB_OFFSET(unsigned int val) {
  return (val & PTAB_MASK) >> PTAB_SHIFT;
}

/* These are bitmasks for the high 32 bits of a descriptor table entry. */
#define _SEGMENT_TYPE    (15<< 8)
#define _SEGMENT_EC      ( 1<<10) /* Expand-down or Conforming segment */
#define _SEGMENT_CODE    ( 1<<11) /* Code (vs data) segment for non-system
                                     segments */
#define _SEGMENT_S       ( 1<<12) /* System descriptor (yes iff S==0) */
#define _SEGMENT_DPL     ( 3<<13) /* Descriptor Privilege Level */
#define _SEGMENT_P       ( 1<<15) /* Segment Present */
#define _SEGMENT_DB      ( 1<<22) /* 16- or 32-bit segment */
#define _SEGMENT_G       ( 1<<23) /* Granularity */

struct DirectoryEntry {
  unsigned int present:1;
  unsigned int rw:1;
  unsigned int user:1;
  unsigned int writethrough:1;
  unsigned int uncached:1;
  unsigned int accessed:1;
  unsigned int reserved:1;
  unsigned int bigpage:1;
  unsigned int globalpage:1;
  unsigned int free:3;
  unsigned int physaddr:20;
} __attribute__((packed));

static inline unsigned int DirectoryEntry_to_u32(DirectoryEntry de) {
  return *(unsigned int *)&de;
}

static inline DirectoryEntry DirectoryEntry_invalid(void) {
  unsigned int v = 0;
  return *(DirectoryEntry *)&v;
}

struct PageTableEntry {
 // In general, do not directly access to present bit, must be through
 // PageTableEntry_* helpers
  // Xen guest page table checks are excepted
  unsigned int present:1;
  unsigned int rw:1;
  unsigned int user:1;
  unsigned int writethrough:1;
  unsigned int uncached:1;
  unsigned int accessed:1;
  unsigned int dirty:1;
  unsigned int reserved:1;
  unsigned int globalpage:1;
  unsigned int free:3;
  unsigned int pagebase:20;
} __attribute__((packed));

// Pinned, e.g. even if the present bit is cleared, this vaddr should not be used
#define PTE_FREE_PINNED (0x1)

static inline void PageTableEntry_makePresent(PageTableEntry *pte) {
  pte->present = 1;
  pte->free &= ~PTE_FREE_PINNED;
}

static inline void PageTableEntry_makeUnpresentButProtected(PageTableEntry *pte) {
  pte->present = 0;
  pte->free |= PTE_FREE_PINNED;
}

static inline void PageTableEntry_makeAvailable(PageTableEntry *pte) {
  pte->present = 0;
  pte->free &= ~PTE_FREE_PINNED;
}

static inline int PageTableEntry_checkPresent(PageTableEntry *pte) {
  return pte->present;
}

static inline int PageTableEntry_checkAvailable(PageTableEntry *pte) {
  return !pte->present && !(pte->free & PTE_FREE_PINNED);
}

static inline unsigned int PageTableEntry_to_u32(PageTableEntry pte) {
  return *(unsigned int *)&pte;
}

static inline int PageTableEntry_isFlushNeeded(PageTableEntry old, PageTableEntry new_ent) {
  // More restrictive, or different mapping, requires a flush

  return old.present && // If old was not present, then there is never need for flush
    !(old.rw == new_ent.rw && old.user == new_ent.user && 
      old.pagebase == new_ent.pagebase);
}

struct Selector {
  unsigned int rpl	:2;
  unsigned int ti	:1;
  unsigned int index	:13;
} __attribute__((packed));

static inline Selector Selector_from_u32(unsigned int source) {
  return *(Selector *)&source;
}

static inline unsigned int Selector_to_u32(Selector source) {
  return *(unsigned int *)&source;
}

/* These are bitmasks for the high 32 bits of a descriptor table entry. */
#define _SEGMENT_TYPE    (15<< 8)
#define _SEGMENT_EC      ( 1<<10) /* Expand-down or Conforming segment */
#define _SEGMENT_CODE    ( 1<<11) /* Code (vs data) segment for non-system
				     segments */
#define _SEGMENT_S       ( 1<<12) /* System descriptor (yes iff S==0) */
#define _SEGMENT_DPL     ( 3<<13) /* Descriptor Privilege Level */
#define _SEGMENT_P       ( 1<<15) /* Segment Present */
#define _SEGMENT_DB      ( 1<<22) /* 16- or 32-bit segment */
#define _SEGMENT_G       ( 1<<23) /* Granularity */



#define SEGMENT_DESCRIPTOR_HI(TYPE)		\
  TYPE base2:8;				\
  TYPE type:4;				\
  TYPE s:1;				\
  TYPE dpl:2;				\
  TYPE p:1;				\
  TYPE seglimit:4;			\
  TYPE avl:1;				\
  TYPE o:1;				\
  TYPE db:1;				\
  TYPE g:1;				\
  TYPE base:8

struct SegmentDescriptorHi {
  SEGMENT_DESCRIPTOR_HI(unsigned int);
} __attribute__((packed));

#define SEGMENT_DESCRIPTOR_LO(TYPE)	\
  TYPE limit:16;			\
  TYPE base3:16

struct SegmentDescriptorLo {
  SEGMENT_DESCRIPTOR_LO(unsigned int);
} __attribute__((packed));


struct SegmentDescriptor {
  SEGMENT_DESCRIPTOR_LO(unsigned long long);
  SEGMENT_DESCRIPTOR_HI(unsigned long long);
} __attribute__((packed));

#undef SEGMENT_DESCRIPTOR_HI
#undef SEGMENT_DESCRIPTOR_LO

#define SEGMENT_DESCRIPTOR_LIMIT(VAL)		\
  .limit = (VAL) & 0xffff,			\
    .seglimit = ((VAL) & 0xf0000) >> 16

#define SEGMENT_DESCRIPTOR_BASE(VAL)		\
  .base3 = ((VAL) & 0xff000000) >> 24, /* high */	\
    .base2 = ((VAL) & 0x00ff0000) >> 16, /* middle */		\
    .base = (VAL) & 0xffff /* low */				\

#define DEFINE_AB								\
  unsigned long a = ((unsigned long *)&desc)[0],			\
    b = ((unsigned long *)&desc)[1]

static inline int SegmentDescriptor_is32(SegmentDescriptor desc) {
  /* We only parse 32-bit page-granularity segments. */
  DEFINE_AB;
  a = a; // suppress warning;
  if ( (b & (_SEGMENT_P|_SEGMENT_S|_SEGMENT_DB|
	     _SEGMENT_G)) !=
       (_SEGMENT_P|_SEGMENT_S|_SEGMENT_DB|_SEGMENT_G) )
    {
      return 0;
    }
  return 1;
}
  
static inline unsigned long
SegmentDescriptor_get_base32(SegmentDescriptor desc, int *err) {
  DEFINE_AB;
  if(!SegmentDescriptor_is32(desc)) {
    *err = -1;
    return 0;
  }
  *err = 0;
  return (b&(0xff<<24)) | ((b&0xff)<<16) | (a>>16);
}
static inline unsigned long
SegmentDescriptor_get_limit32(SegmentDescriptor desc, int *err) {
  DEFINE_AB;
  if(!SegmentDescriptor_is32(desc)) {
    *err = -1;
    return 0;
  }
  *err = 0;
  return (((b & 0xf0000) | (a & 0x0ffff)) + 1) << 12;
}
#undef DEFINE_AB

// XXX ErrorCode is not tested
struct X86_ErrorCode {
  unsigned int is_ext:1;
  unsigned int is_idt:1;
  unsigned int is_ldt:1;
  unsigned int sel_index:13;
};

static inline X86_ErrorCode X86_ErrorCode_from_u32(unsigned int val) {
  return *(X86_ErrorCode *)&val;
}

#define MAX_IDT_ENTRIES (256)



struct IDTEntryHi{
  unsigned int reserved:8;
  unsigned int gatetype:3; 
  unsigned int d:1;
  unsigned int reserved2:1;
  unsigned int dpl:2;
  unsigned int p:1;
  unsigned int offset:16;
} __attribute__((packed));
struct IDTEntryLo{
  unsigned int offset:16;
  unsigned int selector:16;
} __attribute__((packed));

struct TSS{
  unsigned int ptl;
  unsigned int esp0;
  unsigned int ss0;
  unsigned int esp1;
  unsigned int ss1;
  unsigned int esp2;
  unsigned int ss2;
  unsigned int cr3;
  unsigned int eip;
  unsigned int eflags;
  unsigned int eax;
  unsigned int ecx;
  unsigned int edx;
  unsigned int ebx;
  unsigned int esp;
  unsigned int ebp;
  unsigned int esi;
  unsigned int edi;
  unsigned int es;
  unsigned int cs;
  unsigned int ss;
  unsigned int ds;
  unsigned int fs;
  unsigned int gs;
  unsigned int ldtsel;
  //unsigned int mbat;
  unsigned short T:1;
  unsigned short reserved12:15;
  unsigned short iomba;
} __attribute__((packed));

/* #PF error code values, from Xen */
#define PFEC_page_present   (1U<<0)
#define PFEC_write_access   (1U<<1)
#define PFEC_user_mode      (1U<<2)
#define PFEC_reserved_bit   (1U<<3)
#define PFEC_insn_fetch     (1U<<4) // Execute-disable fault

// Nexus architectural extension: trap is due to writable page table
#define PFEC_nexus_wr_ptable  (1U << 15)

// The exception vectors
#define INTERRUPT_PAGEFAULT (14)

struct IretFrame {
  unsigned int eip;
  unsigned int cs;
  unsigned int eflags;
  /* These are only present in inter-CPL traps */
  unsigned int esp;
  unsigned int ss;
} __attribute__ ((packed));


#define GDT_ENTRIES_PER_PAGE (PAGE_SIZE / sizeof(SegmentDescriptor))
#define LDT_ENTRIES_PER_PAGE (GDT_ENTRIES_PER_PAGE)
struct GDT_Descriptor {
  unsigned short limit; // in bytes, inclusive (e.g., this is the offset of the last byte)
  SegmentDescriptor *base_address; // Linear address (e.g. no segmentation, above paging)
} __attribute__ ((packed));

// Size of a full GDT, in pages
#define FULL_GDT_PAGESIZE (16)
#define FULL_LDT_PAGESIZE (16)

//
////// MTRRs
//

/*  These are the region types  */
#define MTRR_TYPE_UNCACHABLE 0
#define MTRR_TYPE_WRCOMB     1
/*#define MTRR_TYPE_         2*/
/*#define MTRR_TYPE_         3*/
#define MTRR_TYPE_WRTHROUGH  4
#define MTRR_TYPE_WRPROT     5
#define MTRR_TYPE_WRBACK     6
#define MTRR_NUM_TYPES       7

#define IA32_MTRR_DEF_TYPE (0x2ff)
#define IA32_MTRR_PHYSBASE(K) (0x200 + 2 * K)
#define IA32_MTRR_PHYSMASK(K) (IA32_MTRR_PHYSBASE(K) + 1)

#define NUM_MTRR (8)

struct MTRR_Base {
  unsigned long long type 	: 8;
  unsigned long long _unused0 	: 4;
  unsigned long long physaddr 	: 20;
  unsigned long long _unused1 	: 32;
} __attribute__ ((packed));

static inline struct MTRR_Base MTRR_Base_from_u32(unsigned int low, unsigned int high) {
  struct MTRR_Base b;
  ((unsigned int *)&b)[0] = low;
  ((unsigned int *)&b)[1] = high;
  return b;
}

struct MTRR_Mask {
  unsigned long long _unused0 	: 11;
  unsigned long long valid 	: 1;
  unsigned long long mask 	: 20;
  unsigned long long _unused1 	: 32;
} __attribute__ ((packed));

static inline struct MTRR_Mask MTRR_Mask_from_u32(unsigned int low, unsigned int high) {
  struct MTRR_Mask m;
  ((unsigned int *)&m)[0] = low;
  ((unsigned int *)&m)[1] = high;
  return m;
}

#define NUM_HW_BREAKPOINTS (4)
// Debug registers
#define DR_RW_EXEC 	0x00
#define DR_RW_DATAW 	0x01
#define DR_RW_IO 		0x02
#define DR_RW_DATARW 	0x03

#define DR_LEN_1 	0x00
#define DR_LEN_2 	0x01
// 2 is undefined or 8
#define DR_LEN_4 	0x03

// DR7: Breakpoint type control
struct DR7 {
  unsigned int l0:1;
  unsigned int g0:1;
  unsigned int l1:1;
  unsigned int g1:1;
  unsigned int l2:1;
  unsigned int g2:1;
  unsigned int l3:1;
  unsigned int g3:1;

  unsigned int le:1;
  unsigned int ge:1;

  unsigned int reserved0:3; // 001
  unsigned int gd:1;
  unsigned int reserved1:2; // 00

  unsigned int rw0:2;
  unsigned int len0:2;
  unsigned int rw1:2;
  unsigned int len1:2;
  unsigned int rw2:2;
  unsigned int len2:2;
  unsigned int rw3:2;
  unsigned int len3:2;
} __attribute__ ((packed));

struct DR6 {
  unsigned int b0:1;
  unsigned int b1:1;
  unsigned int b2:1;
  unsigned int b3:1;

  unsigned int reserved0:9; // 011111111
  unsigned int bd:1;
  unsigned int bs:1;
  unsigned int bt:1;
  unsigned int reserved1:16; // set to 1
} __attribute__ ((packed));


struct InterruptState { // must match the struct in x86_emulate.h; todo: merge them
  unsigned short gs, _pad1; // 0
  unsigned short fs, _pad2;
  unsigned short es, _pad3;
  unsigned short ds, _pad4;

  unsigned int ebx; // 16
  unsigned int ecx;
  unsigned int edx;
  unsigned int esi;
  unsigned int edi; // 32
  unsigned int ebp;
  unsigned int eax;

  unsigned short errorcode;
  unsigned short entry_vector; // Xen split the error code into 2 shorts
  unsigned int eip; // start of iret
  unsigned int cs;
  unsigned int eflags;
  /* start of user-mode activation */
  unsigned int esp;
  unsigned int ss;
} __attribute__ ((packed));

// Atomic operations

/* 
 * Atomically set the value pointed to be x to be newval, and return
 * the old value of x.
 */
static inline int swap(int* x, int newval) {
  __asm__ __volatile__ ( C_LOCK " xchgl %1, %0" : "=m" (*x), "+r" (newval));
  return newval;
}
 // swap low-order byte
extern int swapb(char* x, int newval);

static inline void atomic_write(int *x, int val) {
  __asm__ __volatile__ ( "movl %1, %0" : "=m" (*x) : "ri" (val));
}

static inline int atomic_get(int *x) {
  int rv;
  __asm__ __volatile__ ( "movl %1, %0" : "=r" (rv) : "m" (*x));
  return rv;
}

static inline void atomic_addto(int* x, int newval) {
  __asm__ __volatile__ ( C_LOCK " addl %1, %0" : "=m" (*x) : "ri" (newval));
}

static inline int atomic_get_and_addto(int* x, int newval) {
  __asm__ __volatile__ ( C_LOCK " xaddl %1, %0" : "=m" (*x), "+r" (newval));
  return newval;
}

static inline void atomic_increment(int* x, int newval) {
  atomic_addto(x, newval);
}

static inline int atomic_increment_b_overflow(unsigned char *x, int newval) {
  int rv = 0;
  __asm__ __volatile__ ( C_LOCK
			 "addb %b2, %b0\n"
			 "cmovo %3, %1" :
			 "=mb" (*x), "+r" (rv) :
			 "ri" (newval), "r" (1) );
  return rv;
}

static inline int atomic_decrement_b_zero(unsigned char *x, int newval) {
  int rv = 0;
  __asm__ __volatile__ ( C_LOCK 
			 "subb %b2, %b0\n"
			 "cmovz %3, %1" :
			 "=m" (*x), "+r" (rv) :
			 "ri" (newval), "r" (1) );
  return rv;
}


// returns true if 0
static inline int atomic_decrement(int* x, int newval) {
  int rv = 0;
  __asm__ __volatile__ ( C_LOCK " subl %2, %0\n"
			 "cmovz %3, %1" :
			 "=m" (*x), "+r" (rv) :
			 "ri" (newval), "r" (1) );
  return rv;
}
static inline int atomic_subtract(int* x, int newval) {
  return atomic_decrement(x, newval);
}
static inline int atomic_subtractfrom(int* x, int newval) { // same
  return atomic_decrement(x, newval);
}

#endif // _MACHINE_STRUCTS_H_
