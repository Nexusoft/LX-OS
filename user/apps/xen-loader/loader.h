#ifndef _LOADER_H_
#define _LOADER_H_

#include <inttypes.h>
#include <nexus/x86_emulate.h>
#include <stdlib.h>
#include "xen.h"
#include "xen-types.h"
#include <xen/arch-x86_32.h>
#include <nexus/machine-structs.h>
#include <assert.h>
#define ffs ffs_glibc
#include <string.h>
#undef ffs


#define MIN(X,Y) ( ((X) < (Y)) ? (X) : (Y) )
#define UNIMPLEMENTED() do { fprintf(stderr, "%s()!\n", __FUNCTION__); assert(0); } while(0)

#define __unused __attribute__ ((unused))

// Loader memory layout (11/25):
// B8000000 - Start of Nexus kernel memory area
// (B8000000-4096): Start of Nexus KShmem area (4 KB)

// B5D01000-B5D01FFF: shared info page
// B5D00000-B5D00FFF: Page directory
// B5C00000-B5CFFFFF: kseg area for "foreign mappings"
// B5800000-B5BFFFFF: Flattened page table (e.g. CR3 in pdir) (4MB)
// B5400000-B57FFFFF: P2M table (deallocated after load???) (4MB)
// B4400000-B53FFFFF: Code + Heap + Stack (16 MB)
// B4000000-B43FFFFF: M2P table (currently also P2M table during load process) 4MB

#define NEXUS_VMM_CODEHEAP_START		\
  (MACH2PHYS_VIRT_END)
#define NEXUS_VMM_CODEHEAP_END			\
  (NEXUS_VMM_CODEHEAP_START + 16 * (1 << 20))
#define NEXUS_VMM_PHYS2MACH_START		\
  (NEXUS_VMM_CODEHEAP_END)
#define NEXUS_VMM_PHYS2MACH_END			\
  (NEXUS_VMM_PHYS2MACH_START + 4 * (1 << 20))

#define NEXUS_VMM_PGTABLE_START			\
  (NEXUS_VMM_PHYS2MACH_END)
#define NEXUS_VMM_PGTABLE_END			\
  (NEXUS_VMM_PGTABLE_START + 4 * (1 << 20))

#if (NEXUS_VMM_PGTABLE_START >> PDIR_SHIFT) << PDIR_SHIFT != NEXUS_VMM_PGTABLE_START
#error "VMM_PGTABLE_START must be 4MB aligned!"
#endif

#define NEXUS_VMM_KSEG_START			\
  (NEXUS_VMM_PGTABLE_END)
#define KSEG_LEN 		(1 << 20)
#define NEXUS_VMM_KSEG_END			\
  (NEXUS_VMM_KSEG_START + KSEG_LEN)

#define NEXUS_VMM_PGDIR_START			\
  (NEXUS_VMM_KSEG_END)
#define NEXUS_VMM_PGDIR_END			\
  (NEXUS_VMM_PGDIR_START + PAGE_SIZE)

#define NEXUS_VMM_SHAREDINFO_START		\
  (NEXUS_VMM_PGDIR_END)
#define NEXUS_VMM_SHAREDINFO_END		\
  (NEXUS_VMM_SHAREDINFO_START + PAGE_SIZE)

#define VMM_PDOFFSET				\
  (HYPERVISOR_VIRT_START >> PDIR_SHIFT)
#define NUM_VMM_PTABS (16) // 64MB
#define HYPERVISOR_VIRT_END					\
  ( HYPERVISOR_VIRT_START + NUM_VMM_PTABS * (4 * (1 << 20)) )

#if NEXUS_VMM_PGDIR_END > HYPERVISOR_VIRT_END
#error "Out of hypervisor virtual address space!"
#endif

// Xen loader was forked from Xen 3.0.3-0

#define XEN_VERSION (3)
#define XEN_SUBVERSION (0)

#define __KERNEL__
#include <asm/pgtable.h>
#undef __KERNEL__

/* The following are page numbers, e.g. to convert to address, << PAGE_SHIFT */
// Machine Frame Number.
typedef uint32_t machfn_t;
// Pseudo-physical frame number
typedef uint32_t physfn_t;

/* The following are addresses */
// Machine, virtual, and (pseudo-)physical
typedef uint32_t maddr_t;
typedef uint32_t vaddr_t;
typedef uint32_t paddr_t;

static inline machfn_t maddr_to_machfn(maddr_t maddr) {
  return (machfn_t)(maddr >> PAGE_SHIFT);
}
static inline maddr_t machfn_to_maddr(machfn_t machfn) {
  return (maddr_t)(machfn << PAGE_SHIFT);
}

extern int gTotalVMPages;
extern maddr_t gPDBR;
extern unsigned int g_dom_id;

extern uint32_t gVMMPtable_checkVals[]; // the values that Directory entries pointing to VMM must match. There are NUM_VMM_PTABS of these
extern DirectoryEntry pdir_template[];

extern int num_mach2phys_pages;
extern machfn_t *phys2mach;
extern paddr_t *mach2phys;

extern vcpu_guest_context_t initial_cpu_ctx;

extern machfn_t shared_info_mfn;

extern unsigned long guest_pfault_handler_cs;
extern unsigned long guest_pfault_handler_eip;

static const shared_info_t *shared_info __unused = (shared_info_t *)
  NEXUS_VMM_SHAREDINFO_START;

// Nexus keyboard device handle
extern int kbdhandle;
extern int mouse_handle;

// The pfault handler is implemented in assembly
void vmm_pfault_handler_asm(void);

// Synchronize checkVals array and pdir_template. Can only be called
// after NEXUS_VMM_PGDIR_START is valid
void PDBR_sync(void);
void PDBR_switchto(machfn_t new_pdbr, int do_map_in);

static inline maddr_t VMM_pde_m(vaddr_t vaddr) {
  return gPDBR + (PDIR_OFFSET(vaddr)) * sizeof(DirectoryEntry);
}

static inline DirectoryEntry *VMM_pde_v(vaddr_t vaddr) {
  DirectoryEntry *pdes = (DirectoryEntry *)NEXUS_VMM_PGDIR_START;
  return &pdes[PDIR_OFFSET(vaddr)];
}

// Get the VMM pte responsible for vaddr
static inline PageTableEntry *VMM_pte_v(vaddr_t vaddr) {
  return ((PageTableEntry*)NEXUS_VMM_PGTABLE_START) +
    (vaddr >> PAGE_SHIFT);
}

static inline int VMM_pte_isPresent(vaddr_t vaddr) {
  // Order of evaluation is important. If the page containing this
  // part of the pgtable is not present, then accessing the pte will
  // page fault.
  return VMM_pde_v(vaddr)->present && // Is there a page table for this vaddr?
    VMM_pte_v(vaddr)->present; // Check this page table
}

static inline maddr_t VMM_pte_m_failsafe(vaddr_t vaddr) {
  int pd_offset = PDIR_OFFSET(vaddr);
  assert(	VMM_PDOFFSET <= pd_offset &&
	pd_offset < VMM_PDOFFSET + NUM_VMM_PTABS);
  maddr_t pt_base =
    gVMMPtable_checkVals[pd_offset - VMM_PDOFFSET] & PAGE_MASK;
  if(0) {
    printf("vaddr=%p pt_base=%p offset=%d(%lu-%lu)\n", (void *)vaddr, (void *)pt_base,
	   pd_offset, VMM_PDOFFSET, VMM_PDOFFSET + NUM_VMM_PTABS);
  }
  return pt_base + PTAB_OFFSET(vaddr) * sizeof(PageTableEntry);
}

static inline maddr_t VMM_pte_m(vaddr_t vaddr) {
  DirectoryEntry pde = *VMM_pde_v(vaddr);
  return (pde.physaddr << PAGE_SHIFT) |
    (PTAB_OFFSET(vaddr) * sizeof(PageTableEntry));
}

static inline DirectoryEntry VMM_DirectoryEntry(paddr_t target, int rw) {
  DirectoryEntry pde;
  pde.present = 1;
  pde.rw = rw;
  pde.user = 0;
  pde.writethrough = 0; pde.uncached = 0;
  pde.accessed = 0;
  pde.reserved = 0;
  pde.bigpage = 0;
  pde.globalpage = 0;
  pde.free = 0;
  pde.physaddr = target >> PAGE_SHIFT;
  return pde;
}

static inline PageTableEntry VMM_PageTableEntry(paddr_t target, int rw) {
  return
    ((PageTableEntry) {
      .present = 1,
      .rw = rw,
      .user = 0,
      .writethrough = 0,
      .uncached = 0,
      .accessed = 0,
      .dirty = 0,
      .reserved = 0,
      .globalpage = 0,
      .free = 0,
      .pagebase = target >> PAGE_SHIFT,
    });
}

// Get the physical address associated with a virtual address
static inline maddr_t VMM_virtToMach(vaddr_t vaddr) {
  PageTableEntry *pte = VMM_pte_v(vaddr);
  return (maddr_t)
    ((pte->pagebase << PAGE_SHIFT) | (vaddr & PAGE_OFFSET_MASK));
}

static inline uint32_t page_rounddown(uint32_t val) {
  return val & PAGE_MASK;
}

static inline uint32_t page_roundup(uint32_t val) {
  return (val + (PAGE_SIZE - 1)) & ~(PAGE_SIZE - 1);
}

// These routines are copied from Xen. Typechecking via guest handles
// is stripped off.

int copy_to_user(void *dest, void *src, unsigned len);
int copy_from_user(void *dest, void *src, unsigned len);

#define copy_to_guest(p, ptr, nr)                     \
    copy_to_guest_offset(p, 0, ptr, nr)

#define copy_from_guest(ptr, p, nr)                   \
    copy_from_guest_offset(ptr, p, 0, nr)

/*
 * Copy an array of objects to guest context via a guest handle,
 * specifying an offset into the guest array.
 */
#define copy_to_guest_offset(p, off, ptr, nr) ({	\
      const typeof(ptr) _x = p;				\
      const typeof(ptr) _y = (ptr);			\
      copy_to_user(_x+(off), _y, sizeof(*_x)*(nr));	\
    })

/*
 * Copy an array of objects from guest context via a guest handle,
 * specifying an offset into the guest array.
 */
#define copy_from_guest_offset(ptr, p, off, nr) ({	\
      const typeof(ptr) _x = p;				\
      const typeof(ptr) _y = (ptr);			\
      copy_from_user(_y, _x+(off), sizeof(*_x)*(nr));	\
    })


int nl_munmap(void *start, size_t length);

int Xen_MMU_Map(vaddr_t vaddr, machfn_t pfn, uint32_t perms);
int Xen_MMU_Map_rangeBase(vaddr_t vaddr,
		      machfn_t pfn_base, int num_pages,
		      uint32_t perms);
int Xen_MMU_Map_range(vaddr_t vaddr,
		      machfn_t *pfn_array, int num_pages,
		      uint32_t perms);
int Xen_MMU_Unmap(vaddr_t vaddr);
int Xen_MMU_Unmap_range(vaddr_t vaddr, int num_pages);

void PDIR_initHigh(DirectoryEntry *to);
int PDIR_checkHigh(DirectoryEntry *target);

int mmu_update_single(uint32_t ptr, uint32_t val);

// KSEG is region for typically temporary mappings. TLB invalidations
// are kept to a minimum.

DirectoryEntry allocate_new_ptable(int offset, int check);
DirectoryEntry lookup_ptable(vaddr_t vaddr, int can_allocate);

void flushTLB(void);
void flushTLB_one(vaddr_t va);
void setCR3(machfn_t new_pdir_mfn);

void KSEG_init(void);
//  Map in the physical addresses. Return the // virtual address
vaddr_t KSEG_map(machfn_t *mfns, int size);
vaddr_t KSEG_map_ro(machfn_t *mfns, int size);
// Undo a kseg map. paddr is for sanity check
void KSEG_unmap(vaddr_t vaddr);

/**
 * This function will create a domain for a paravirtualized Linux
 * using file names pointing to kernel and ramdisk
 *
 * @parm xc_handle a handle to an open hypervisor interface
 * @parm domid the id of the domain
 * @param image_name name of the kernel image file
 * @param ramdisk_name name of the ramdisk image file
 * @parm cmdline command line string
 * @parm flags domain creation flags
 * @parm store_evtchn the store event channel for this domain to use
 * @parm store_mfn returned with the mfn of the store page
 * @parm _console_evtchn the console event channel for this domain to use
 * @parm conole_mfn returned with the mfn of the console page
 * @return 0 on success, -1 on failure
 */
int xc_linux_build(int xc_handle,
                   uint32_t domid,
                   const char *image_name,
                   const char *ramdisk_name,
                   const char *cmdline,
                   const char *features,
                   unsigned long flags,
                   unsigned int store_evtchn,
                   unsigned long *store_mfn,
                   unsigned int _console_evtchn,
                   unsigned long *_console_mfn);

void __attribute__ ((noreturn)) switch_to(struct vcpu_guest_context *ctx);

void __attribute__ ((noreturn))
  switch_to_finalize_asm(struct vcpu_guest_context *ctx);


/* Interface to disassember for page faults */
void x86_emulate_enter_vmm(struct x86_emulate_ctxt *ctxt);
int x86_emulate_write_vmm(enum x86_segment seg,
			  unsigned long vaddr,
			  unsigned long val,
			  unsigned int bytes,
			  struct x86_emulate_ctxt *ctxt);
int x86_emulate_read_vmm(enum x86_segment seg,
			 unsigned long vaddr,
			 unsigned long *val,
			 unsigned int bytes,
			 struct x86_emulate_ctxt *ctxt);
int x86_emulate_cmpxchg_vmm(enum x86_segment seg,
			    unsigned long offset,
			    unsigned long old,
			    unsigned long new,
			    unsigned int bytes,
			    struct x86_emulate_ctxt *ctxt);

#endif // _LOADER_H_
