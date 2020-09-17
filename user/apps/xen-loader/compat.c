#include "loader.h"
#include <inttypes.h>
#include <assert.h>
#include "xenctrl.h"
#include "xg_private.h"
#include "hypercalls.h"
#include <nexus/Mem.interface.h>

void *xc_map_foreign_range(int xc_handle, uint32_t dom,
                           int size, int prot,
                           unsigned long mfn) {
    // All are mapped as read/write, regardless of prot
    // printf("Page size: %d\n", page_roundup(size));
    void *addr = (void *)KSEG_map( (machfn_t *) &mfn, size);
    // printf("xc_map_foreign_range(%d)=>%p\n", size, addr);
    return addr;
}

int probe_bin(const char *image, unsigned long image_size,
              struct load_funcs *funcs) {
  PERROR("bin format images not supported by Nexus Xen loader!\n");
  return 0;
}

int nl_munmap(void *start, size_t length) {
    // printf("nl_munmap(%p,%d)\n", start, length);
    KSEG_unmap((vaddr_t) start);
    return 0;
}

int Xen_MMU_Map(vaddr_t vaddr, machfn_t pfn, uint32_t perms) {
    // This check is not strictly needed for correctness, but I don't
    // expect to use this function for any other type of virtual
    // address
    maddr_t paddr = pfn << PAGE_SHIFT;

    assert(HYPERVISOR_VIRT_START <= vaddr && vaddr < HYPERVISOR_VIRT_END);

    // Allocate a new page table if we don't have one already
    DirectoryEntry pde = lookup_ptable(vaddr, 1);
    assert(! (perms &
              ~(_PAGE_BIT_RW | _PAGE_BIT_USER |
                _PAGE_DIRTY | _PAGE_ACCESSED)) );

    // Sanity check the non-presence of the page
    if(VMM_pte_v(vaddr)->present) {
        printf("Xen_MMU_Map(%p): already present!\n", (void *)vaddr);
        return -1;
    }

    maddr_t ptr_l1 = pde.physaddr * PAGE_SIZE + 
        PTAB_OFFSET(vaddr) * sizeof(PageTableEntry);
    __u32 val_l1 =
        PageTableEntry_to_u32(VMM_PageTableEntry(paddr, 0)) | perms;

    return mmu_update_single(MMU_NORMAL_PT_UPDATE | ptr_l1, val_l1);
}

static int sanity_check_range(const char *caller, int check_sense,
                              vaddr_t vaddr, int num_pages) {
    int i;
    for(i=0; i < num_pages; i++) {
        int map_addr = vaddr + i * PAGE_SIZE;
        PageTableEntry *pte = VMM_pte_v(map_addr);
        int check_success = 
            (check_sense && pte->present) ||
            (!check_sense && !pte->present);
        if(!check_success) {
            printf("%s(@%d,%p), sanity range check failed!\n", 
                   caller, i, (void *) map_addr);
            return 0;
        }
    }
    return 1;
}

int Xen_MMU_Map_rangeBase(vaddr_t vaddr,
                          machfn_t pfn_base, int num_pages,
                          uint32_t perms) {
    int i;
    if(!sanity_check_range(__FUNCTION__, 0, vaddr, num_pages)) {
        return -1;
    }
    for(i=0; i < num_pages; i++) {
        Xen_MMU_Map(vaddr + i * PAGE_SIZE, pfn_base + i, perms);
    }
    return 0;
}

int Xen_MMU_Map_range(vaddr_t vaddr,
                      machfn_t *pfn_array, int num_pages,
                      uint32_t perms) {
    int i;
    if(!sanity_check_range(__FUNCTION__, 0, vaddr, num_pages)) {
        return -1;
    }

    // TODO: Change this to use MULTI hypercall
    for(i=0; i < num_pages; i++) {
        int map_addr = vaddr + i * PAGE_SIZE;
        int rv = Xen_MMU_Map(map_addr, pfn_array[i], perms);
        if(rv) {
            printf("Xen_MMU_Map_range(@%d), Xen_MMU_Map error!\n", i);
            return rv;
        }
    }
    return 0;
}


int Xen_MMU_Unmap(vaddr_t vaddr) {
    // This check is not strictly needed for correctness, but I don't
    // expect to use this function for any other type of virtual
    // address

    assert(HYPERVISOR_VIRT_START <= vaddr && vaddr < HYPERVISOR_VIRT_END);

    // Get PDE; don't bother allocating one if not present
    DirectoryEntry pde = lookup_ptable(vaddr, 0);
    if(!pde.present) {
        printf("Xen_MMU_Unmap(%p): no ptab\n", (void *)vaddr);
        return 0;
    }

    // Sanity check the presence of the page
    if(!VMM_pte_v(vaddr)->present) {
        printf("Xen_MMU_Map(%p): not present!\n", (void *)vaddr);
        return -1;
    }

    // erase entry
    maddr_t ptr_l1 = pde.physaddr * PAGE_SIZE + 
        PTAB_OFFSET(vaddr) * sizeof(PageTableEntry);

    return mmu_update_single(MMU_NORMAL_PT_UPDATE | ptr_l1, 0);
}

int Xen_MMU_Unmap_range(vaddr_t vaddr, int num_pages) {
  int i;
  if(!sanity_check_range(__FUNCTION__, 1, vaddr, num_pages)) {
      return -1;
  }

  // TODO: Rewrite this to use multi call
  for(i=0; i < num_pages; i++) {
      int rv = Xen_MMU_Unmap(vaddr + i * PAGE_SIZE);
      if(rv != 0) {
          printf("Xen_MMU_Unmap(@%d), unmap failure!\n", i);
          return rv;
      }
  }
  return 0;
}

int mmu_update_single(uint32_t ptr, uint32_t val) {
    mmu_update_t req = (mmu_update_t) {
        .ptr = ptr,
        .val = val,
    };
    return HYPERCALL_mmu_update(1, &req, 1, NULL, DOMID_SELF);
}

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
