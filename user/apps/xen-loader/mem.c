#include "loader.h"
#include <string.h>
#include <inttypes.h>
#include <nexus/Xen.interface.h>
#include "xen-types.h"
#include "xen.h"
#include "hypercalls.h"
#include "tests.h"
#define PRINT printf

enum TLBFlushType {
  ALL,
  MULTI,
  LOCAL,
};

void flushTLB_helper(enum TLBFlushType ftype) {
  mmuext_op_t op;
  long cpu_mask = 0x1;

  switch(ftype) {
  case ALL:
    op = (mmuext_op_t){
      .cmd = MMUEXT_TLB_FLUSH_ALL,
    };
    break;
  case MULTI:
    op = (mmuext_op_t){
      .cmd = MMUEXT_TLB_FLUSH_MULTI,
      .arg2.vcpumask = &cpu_mask,
    };
    break;
  case LOCAL:
    op = (mmuext_op_t) {
      .cmd = MMUEXT_TLB_FLUSH_LOCAL,
    };
    break;
  }
  unsigned int done_count = 0;
  int rv = HYPERCALL_mmuext_op(&op, 1, &done_count, DOMID_SELF);
  assert(rv == 0);
}

void flushTLB(void) {
  flushTLB_helper(ALL);
}

void flushTLB_one(vaddr_t va) {
  mmuext_op_t op = {
    .cmd = MMUEXT_INVLPG_ALL,
    .arg1.linear_addr = va,
  };
  unsigned int done_count;
  int rv = HYPERCALL_mmuext_op(&op, 1, &done_count, DOMID_SELF);
  assert(rv == 0);
}

void setCR3(machfn_t new_pdir_mfn) {
  printf("Setting cr3 to %p\n", (void *)new_pdir_mfn);
  struct mmuext_op op = {
    .cmd = MMUEXT_NEW_BASEPTR,
    .arg1.mfn = new_pdir_mfn,
  };
  int rv = HYPERCALL_mmuext_op(&op, 1, NULL, DOMID_SELF);
  assert(rv == 0);
}

static inline vaddr_t KSEG_index_to_vaddr(int index) {
  return NEXUS_VMM_KSEG_START + index * PAGE_SIZE;
}

static inline int KSEG_vaddr_to_index(vaddr_t vaddr) {
  assert(NEXUS_VMM_KSEG_START <= vaddr && vaddr < NEXUS_VMM_KSEG_END);
  return (vaddr - NEXUS_VMM_KSEG_START) / PAGE_SIZE;
}

#define KSEG_PAGE_LEN (KSEG_LEN / PAGE_SIZE)
struct KSEG_Descriptor {
  int alloc_len;
} kseg_metadata[KSEG_PAGE_LEN];

void KSEG_init(void) {
  int i;
  for(i=0; i < KSEG_PAGE_LEN; i++) {
    kseg_metadata[i].alloc_len = 0;
  }
}

static vaddr_t KSEG_map_helper(machfn_t *pfn_array, int size, int flags) {
  // Invariant: entries above recycle_finger may be used without TLB flush
  static int recycle_finger = 0;
  int num_pages = page_roundup(size) / PAGE_SIZE;

  int try_num;
  int i, j; // position, in pages
  int found = 0;
  int alloc_index = -1;
  for(try_num = 0; try_num < 2 && !found; try_num++) {
    for(i=recycle_finger; i < KSEG_PAGE_LEN && !found; i++) {
      for(j=0; j < num_pages; j++) {
	int page_index = i + j;
	vaddr_t check_vaddr = KSEG_index_to_vaddr(page_index);
	PageTableEntry *check_pte = VMM_pte_v(check_vaddr);
	if(0) printf("Check (%d+%d=%d)=%p=%d\n",
	       i, j, i+j, check_pte, check_pte->present);
	if(check_pte->present) {
	  i = page_index;
	  goto continue_outer;
	}
      }
      alloc_index = i;
      found = 1;
    continue_outer:
      ;
    }

    if(!found) {
      flushTLB();
      recycle_finger = 0;
    }
  }
  // printf("found=%d, try_num = %d, alloc_index=%d\n", found, try_num, alloc_index);
  assert(found && alloc_index >= 0);
  assert(kseg_metadata[alloc_index].alloc_len == 0);

  vaddr_t map_at_addr = KSEG_index_to_vaddr(alloc_index);
  int rv = 
    Xen_MMU_Map_range(map_at_addr, pfn_array, num_pages, flags);
  assert(rv == 0);
  kseg_metadata[alloc_index].alloc_len = num_pages;
  recycle_finger = alloc_index + num_pages;

  // printf("KSEG(%p)=>%p\n", (void *)pfn_array[0], (void *)map_at_addr);
  return map_at_addr;
}

vaddr_t KSEG_map(machfn_t *pfn_array, int size) {
  return KSEG_map_helper(pfn_array, size, __PAGE_KERNEL);
}

vaddr_t KSEG_map_ro(machfn_t *pfn_array, int size) {
  return KSEG_map_helper(pfn_array, size, __PAGE_KERNEL_RO);
}

void KSEG_unmap(vaddr_t vaddr) {
  int free_index = KSEG_vaddr_to_index(vaddr);
  int num_pages_to_free = kseg_metadata[free_index].alloc_len;
  assert(num_pages_to_free > 0);

  int rv = Xen_MMU_Unmap_range(vaddr, num_pages_to_free);
  assert(rv == 0);
  kseg_metadata[free_index].alloc_len = 0;
}

static inline int check_address(void *addr, unsigned len) {
  // Don't do address checking, since VMM might invoke hypercalls which use these
  return 1;
  /*
    return !(addr >= VMM_START || (char *)addr + len > (char *)VMM_START ||
    (char *)addr + len < (char *)addr);
  */
}

int copy_to_user(void *dest, void *src, unsigned len) {
  if(!check_address(dest, len)) {
    printf("Copy_to_guest(%p,%p,%u) error!\n", dest, src, len);
    return -1;
  }
  memcpy(dest, src, len);
  return 0;
}

int copy_from_user(void *dest, void *src, unsigned len) {
  if(!check_address(src, len)) {
    printf("Copy_from_guest(%p,%p,%u) error!\n", dest, src, len);
    return -1;
  }
  memcpy(dest, src, len);
  return 0;
}

DirectoryEntry allocate_new_ptable(int offset, int check) {
  if(check) {
    assert(gPDBR != 0);
    DirectoryEntry *pdes = (DirectoryEntry *)NEXUS_VMM_PGDIR_START;
    if(pdes[offset].present) {
      printf("allocate_new_ptable(): entry already present!\n");
      return pdes[offset];
    }
  }

  paddr_t new_ptab = Xen_AllocPages(1);
  assert(new_ptab != 0);
  DirectoryEntry pde = VMM_DirectoryEntry(new_ptab, 1);
  int rv = mmu_update_single(gPDBR + offset, DirectoryEntry_to_u32(pde));
  if(rv != 0) {
    printf("Could not insert missing page table at %d for VMM!\n",
	   offset);
    assert(0);
  }
  return pde;
}

DirectoryEntry lookup_ptable(vaddr_t vaddr, int can_allocate) {
  DirectoryEntry *pde = VMM_pde_v(vaddr);
  int pdoffset = PDIR_OFFSET(vaddr);
  if(!pde->present) {
    if(!can_allocate) {
      printf("No ptable for vaddr, and not allowed to allocate a new one\n");
      return DirectoryEntry_invalid();
    }
    DirectoryEntry rv = allocate_new_ptable(pdoffset, 1);
    if(!rv.present) {
      printf("could not allocate new ptable!\n");
      assert(0);
    }
  }
  return *pde;
}

static void PDIR_copyHigh(DirectoryEntry *to, DirectoryEntry *from) {
  memcpy(&to[VMM_PDOFFSET], &from[VMM_PDOFFSET], 
	 (PDIR_ENTRIES - VMM_PDOFFSET) * sizeof(DirectoryEntry));
}

void PDBR_switchto(machfn_t new_pdbr, int do_map_in) {
  // gPDBR must be updated first, since many of the helper functions
  // rely on it
  gPDBR = new_pdbr;

  assert(do_map_in);
  if(do_map_in) {
    int rv;
    // We now have some reasonable checkVals[]
    PageTableEntry pte = VMM_PageTableEntry(gPDBR, 0);
    rv = mmu_update_single(VMM_pte_m_failsafe(NEXUS_VMM_PGDIR_START),
			   PageTableEntry_to_u32(pte));
    if(rv != 0) {
      printf("Could not map in pdir!\n");
      assert(0);
    }

    rv = mmu_update_single(VMM_pde_m(NEXUS_VMM_PGTABLE_START),
			   DirectoryEntry_to_u32(VMM_DirectoryEntry(gPDBR, 0)));
    if(rv != 0) {
      printf("Could not map in mapped page table!\n");
      assert(0);
    }
  }
}

void PDBR_sync(void) {
  int pdoffset;
  __u32 *pdes = (__u32 *)NEXUS_VMM_PGDIR_START;
  for(pdoffset = VMM_PDOFFSET; 
      pdoffset < VMM_PDOFFSET + NUM_VMM_PTABS; 
      pdoffset++) {
    gVMMPtable_checkVals[pdoffset - VMM_PDOFFSET] = pdes[pdoffset];
  }
  // Update pdir_template with new values
  PDIR_copyHigh(pdir_template, (DirectoryEntry *) pdes);
}

void PDIR_initHigh(DirectoryEntry *to) {
  PDIR_copyHigh(to, pdir_template);
}

int PDIR_checkHigh(DirectoryEntry *target) {
  int i;
  for(i=VMM_PDOFFSET; i < PDIR_ENTRIES; i++) {
    if(memcmp(&target[i], &pdir_template[i], sizeof(DirectoryEntry)) != 0) {
      printf("pdir check high failed at %d\n", i);
      return 0;
    }
  }
  return 1;
}

void x86_emulate_enter_vmm(struct x86_emulate_ctxt *ctxt) {
  // setup TLS register
  __asm__ ( "movl %0, %%gs" : : "r" (KSHMEM_GS) );
}

int x86_emulate_write_vmm(enum x86_segment seg,
			  unsigned long vaddr,
			  unsigned long val,
			  unsigned int bytes,
			  struct x86_emulate_ctxt *ctxt){
  // printf(")");

  if(Selector_from_u32(ctxt->regs->cs).rpl != 0x1) {
    printf("inter-domain vmm pfault should not be passed up!\n");
    assert(0);
  }

  /* The only time this is not true is if the segment base is weird (nonzero) */
  assert(vaddr == shared_info->vcpu_info[0].arch.cr2);


  // Only aligned, full word width writes are allowed.
  // It is not difficult to implement the other cases
  if(!(bytes == 4 && ((((unsigned long)vaddr) & 0x3) == 0))) {
    printf("pfault write assertion failed: bytes = %d (==4?) "
	   "vaddr = %p (word-aligned?) ;;; ", bytes, (void*)vaddr);
    printf("from <%x:%p>\n", ctxt->regs->cs, (void*)ctxt->regs->eip);
  }
  assert(bytes == 4 && ((((unsigned long)vaddr) & 0x3) == 0));

  mmu_update_t req = {
    .ptr = VMM_virtToMach((vaddr_t)vaddr) | 
    MMU_NORMAL_PT_UPDATE,
    .val = val,
  };
  // printf("Updating %p=>%p %x\n", (void *)loc, (void *)req.ptr, (int)req.val);
  unsigned int count;
  int rv = HYPERCALL_mmu_update(1, &req, 1, &count, DOMID_SELF);
  if(!(rv == 0 && count == 1)) {
    printf("Updating %p=>%p %x, rv %d count %d\n", 
	   (void *)(int)vaddr, (void *)(int)req.ptr, (int)req.val, rv, count);
  }
  assert(rv == 0 && count == 1);

  return X86EMUL_CONTINUE;
}
int x86_emulate_read_vmm(enum x86_segment seg,
			 unsigned long vaddr,
			 unsigned long *val,
			 unsigned int bytes,
			 struct x86_emulate_ctxt *ctxt){

  //printf("]");
  /* The only time this is not true is if the segment base is weird (nonzero) */
  assert(vaddr == shared_info->vcpu_info[0].arch.cr2);

  /* This is only designed to work with instructions that read and
     write where the write faults (e.g. inc).  It will get into an
     infinite loop? if called from a read fault. */

  assert(bytes == 4);
  *val = *(__u32 *)vaddr;

  return X86EMUL_CONTINUE;
}
int x86_emulate_cmpxchg_vmm(enum x86_segment seg,
				unsigned long offset,
				unsigned long old,
				unsigned long new,
				unsigned int bytes,
			    struct x86_emulate_ctxt *ctxt){
  // XXX This won't work for SMP since we're not actually doing an
  assert(old == *(int *)offset);
  // XCHG / Lock prefix handling. We can't do that because the MMU
  // update hypercall does not support XCHG, only Write.

  // If we ever need SMP, the hypercall will need to be added, or
  // we'll need to pull the writeable page table support into Nexus
  // printf(".");

  return x86_emulate_write_vmm(seg, offset, new, bytes, ctxt);
}
