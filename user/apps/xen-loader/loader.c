#include <stdio.h>
#include <nexus/tls.h>
#include <assert.h>
#include <nexus/Thread.interface.h>
#include <nexus/IPC.interface.h>
#include <nexus/Xen.interface.h>
#include <nexus/Console.interface.h>
#include <stdlib.h>

#include <errno.h>

#include <unistd.h> // for sleep()

#include <nexus/machine-structs.h> // for page table and descriptor structures

#include "loader.h"
#include "tests.h"
#include "hypercalls.h"

#define DEFAULT_VM_SIZE ((256 * (1 << 20)) / PAGE_SIZE)
//#define DEFAULT_VM_SIZE ((128 * (1 << 20)) / PAGE_SIZE)
//#define DEFAULT_VM_SIZE ((128 * (1 << 20)) / PAGE_SIZE)
//#define DEFAULT_VM_SIZE ((16 * (1 << 20)) / PAGE_SIZE)

int gTotalVMPages;
maddr_t gPDBR;
DirectoryEntry pdir_template[PDIR_ENTRIES];
uint32_t gVMMPtable_checkVals[NUM_VMM_PTABS];

void *VMM_START;
void *VMM_TEXT_END;

machfn_t *phys2mach;
int num_mach2phys_pages;
physfn_t *mach2phys = (paddr_t *) MACH2PHYS_VIRT_START;
vcpu_guest_context_t initial_cpu_ctx;
machfn_t shared_info_mfn;

unsigned int g_dom_id;

int mouse_handle;

static int P2M_totlen(void) {
  return gTotalVMPages * sizeof(phys2mach[0]);
}

void pre_main(void) {
  extern int _end; // End symbol from linker

  VMM_TEXT_END = &_end;
  printf("End at %p\n", VMM_TEXT_END);

  __errno_enable_tls = 0;

  // small delta to minimize waste of virtual address space
  __thread_global_stack_base = page_roundup((__u32) VMM_TEXT_END);
  __thread_global_stack_limit = __thread_global_stack_base + 1024 * PAGE_SIZE;

  // adjust data segment size
  __curbrk = __thread_global_stack_limit;
  
  // no longer needed is now forbidden by default
  // XXX remove
  //nexus_set_brk_forbid_wrap(1);

  if(Xen_PreInit() != 0) {
    printf("Xen_PreInit() failure\n");
    exit(-1);
  }
  // test_seg_regs();
  printf("done with pre-main\n");
}

void (*pre_main_hook)(void) = pre_main;

static void initialize_mem(int numpgs);
static void post_load_mem_cleanup(void);
static void vmm_pages_set_supervisor(void);

int main(int argc, char **argv) {
  NetComp_init();
  register_pf_handler_enter(x86_emulate_enter_vmm);
  register_pf_handler_write(x86_emulate_write_vmm);
  register_pf_handler_read(x86_emulate_read_vmm);
  register_pf_handler_cmpxchg(x86_emulate_cmpxchg_vmm);

  g_dom_id = IPC_GetMyIPD_ID();
  KSEG_init();

  __asm__ ( "movl $.text, %0" : "=r" (VMM_START));
  printf("VMM=[%p,%p)\n", VMM_START, VMM_TEXT_END);
  assert((void *)NEXUS_VMM_CODEHEAP_START <= VMM_START && 
	 VMM_TEXT_END < (void *)NEXUS_VMM_CODEHEAP_END);

  phys2mach = (machfn_t *) NEXUS_VMM_PHYS2MACH_START;

  char *test_malloc = malloc(3);
  if((void *) test_malloc < VMM_START) {
    printf("Test malloc => %p is outside of vmm region!\n", test_malloc);
    free(test_malloc);
    exit(-1);
  }

  if(argc == 1) {
    printf("xen-loader started with no arguments, assuming regression test\n");
    exit(0);
  }

  if(argc < 2) {
    printf("Usage: xen-loader <image_name> [<ramdisk_name>]\n");
    exit(-1);
  }

  char *image_name = argv[1];
  char *initrd_name;
  //char cmdline[] = "root=/dev/ram0 init=/bin/ash rw"; // "xencons=ttyS";
  char cmdline[] = "root=/dev/ram0 init=/nexus rw"; // "xencons=ttyS";
  char *features = NULL;

  unsigned long store_mfn;
  unsigned long console_mfn;
  int rv;

  if(argc >= 3) {
    initrd_name = argv[2];
  } else {
    initrd_name = NULL;
  }

  printf("About to make VMM pages owned by supervisor");
  initialize_mem(DEFAULT_VM_SIZE);
  printf("... done\n");
  printf("VMM pages set supervisor");
  vmm_pages_set_supervisor();
  printf("... done\n");

  shared_info_mfn = maddr_to_machfn(Xen_AllocPages(1));
  assert(shared_info_mfn != 0);
  Xen_RegisterSharedMFN(shared_info_mfn);
  // Map in shared info frame
  rv = Xen_MMU_Map(NEXUS_VMM_SHAREDINFO_START, shared_info_mfn,
		   __PAGE_KERNEL);
  assert(rv == 0);

  rv = xc_linux_build(-1, DOMID_SELF, 
		      image_name, initrd_name, // images
		      cmdline, features,  // command line and features
		      0 /* flags */,
		      EVTCHAN_STORE /* store evt chn */, &store_mfn,
		      EVTCHAN_CONSOLE /* console evtchn */, &console_mfn);
  printf("xc_linux_build() = %d\n", rv);
  post_load_mem_cleanup();

  printf("Rare mode");
  rv = Console_SetInputMode(kbdhandle, KBD_RARE);
  assert(rv == 0);

  printf("Initialize mouse\n");
  mouse_handle = Console_Mouse_Init();
  assert(mouse_handle >= 0);
  // should never reach this point
  printf("OK, now try to start the VM!\n");
  switch_to(&initial_cpu_ctx);
}

static void initialize_mem(int numpgs) {
  int i;
  memset(pdir_template, 0, sizeof(pdir_template));

  gTotalVMPages = numpgs;
  gPDBR = Xen_GetPDBR();
  {
    int rv;
    // bootstrapping requires existing contents of pdbr
    DirectoryEntry *pdbr_data = malloc(PAGE_SIZE);
    printf("trying to read pdbr into %p\n", pdbr_data);
    rv = Xen_ReadPDBR((char *)pdbr_data);
    assert(rv == 0);

    // Must load gVMMPtable asap, since it is needed for verification
    // in HYPERCALL_mmu_update

    // Sanity check: Xen page tables must be 4MB aligned
    assert( VMM_PDOFFSET << PDIR_SHIFT 
	   == HYPERVISOR_VIRT_START);
    for(i=0; i < NUM_VMM_PTABS; i++) {
      DirectoryEntry *pde = 
	&pdbr_data[VMM_PDOFFSET + i];

      if(i == PDIR_OFFSET(NEXUS_VMM_PGTABLE_START) - VMM_PDOFFSET) {
	// No default value for the mapped page table
	pde->present = 0;
      } else {
	if(!pde->present) {
	  // Need to allocate new page table page
	  if(0) {
	    printf("Allocating VMM page table page at %d %p\n", i, 
		   (void *)( (VMM_PDOFFSET + i) << PDIR_SHIFT) );
	  }
	  *pde = allocate_new_ptable((char *)pde - (char *)pdbr_data, 0);
	}
      }
      gVMMPtable_checkVals[i] = DirectoryEntry_to_u32(*pde);

      if(0) {
	printf("checkVal[%d] = %p\n", i, (void *) gVMMPtable_checkVals[i]);
      }
    }
    Xen_Set_VMM_PDIR(VMM_PDOFFSET, &gVMMPtable_checkVals[0], 
		     NUM_VMM_PTABS);

    PDBR_switchto(gPDBR, 1);
    // First mapping of PGDIR_START, so we can use it right away
    PDBR_sync();

    // we don't need this copy any more, since it is now mapped in
    free(pdbr_data);
  }
  printf("Done with mapping in gPDBR.\n");
  if(0) {
    run_pdir_map_tests();
  }

  // Allocate and map in P2M area for use during load
  int p2m_totlen = P2M_totlen();
  int num_p2m_pages = 
    page_roundup(p2m_totlen) / PAGE_SIZE;
  char *p2m_ptr = (char *)phys2mach;
  printf("Will allocate %d pages for p2m\n", num_p2m_pages);
  for(i=0; i < num_p2m_pages; i++) {
    paddr_t paddr = Xen_AllocPages(1);
    Xen_MMU_Map((vaddr_t) p2m_ptr, maddr_to_machfn(paddr), __PAGE_KERNEL);
    p2m_ptr += PAGE_SIZE;
  }

  memset(phys2mach, 0, p2m_totlen);

  // Allocate non-contiguous pages, and put them in p2m
  for(i=0; i < gTotalVMPages; i++) {
    paddr_t paddr = Xen_AllocPages(1);
    if(paddr == 0) {
      PERROR("Not enough memory to allocate VM pages!");
      exit(-1);
    }
    // Nexus physical becomes Nexus VMM machine
    phys2mach[i] = (machfn_t)(paddr >> PAGE_SHIFT);
  }
  p2m_mapping_dump();

  maddr_t mach_addr;
  int num_pages;
  int rv = Xen_GetMach2Phys(&mach_addr, &num_pages);
  assert(rv == 0);
  assert(num_pages <=
	 (MACH2PHYS_VIRT_END - MACH2PHYS_VIRT_START)
	 / PAGE_SIZE);

  num_mach2phys_pages = num_pages;
  rv = Xen_MMU_Map_rangeBase(MACH2PHYS_VIRT_START,
			     maddr_to_machfn(mach_addr), num_pages,
				 __PAGE_KERNEL_RO);

  assert(rv == 0);
  // Check the machine to phys table
  printf("M2P[%d] = %p\n", 0, (void *) mach2phys[0]);
}

static void post_load_mem_cleanup(void) {
  printf("Running post-load mem cleanup!\n");
  int num_p2m_pages = 
    page_roundup(P2M_totlen()) / PAGE_SIZE;
  void *p2m_ptr = phys2mach;

  int i;
  for(i=0; i < num_p2m_pages; i++) {
    maddr_t mach_addr = VMM_virtToMach((paddr_t)p2m_ptr);
    Xen_MMU_Unmap((paddr_t)p2m_ptr);
    Xen_FreePages((paddr_t)mach_addr, 1);
    p2m_ptr += PAGE_SIZE;
  }
}

static void vmm_pages_set_supervisor(void) {
  // Set both PDIR and PTAB to supervisor
  vaddr_t vaddr;
  for(vaddr = HYPERVISOR_VIRT_START; 
      vaddr < HYPERVISOR_VIRT_END; 
      vaddr += PAGE_SIZE) {
    maddr_t ptr = VMM_pte_m(vaddr);
    __u32 val = *(__u32 *)VMM_pte_v(vaddr);
    val &= ~_PAGE_USER;
    int rv = mmu_update_single(ptr, val);
    if(rv != 0) {
      printf("Could not mmu_update at %p (m=%p v=%p), val is %p!\n", 
	     (void *)vaddr, (void *)ptr, VMM_pte_v(vaddr), (void *)val);
      dump_checkvals();
    }
  }
}

void __attribute__ ((noreturn)) switch_to(struct vcpu_guest_context *ctx) {
  HYPERCALL_stack_switch(ctx->kernel_ss, ctx->kernel_sp);
  HYPERCALL_set_trap_table(ctx->trap_ctxt);
  HYPERCALL_set_callbacks(ctx->event_callback_cs, ctx->event_callback_eip,
	  ctx->failsafe_callback_cs, ctx->failsafe_callback_eip);

  printf("Will jump to %x:%p\n", ctx->user_regs.cs, (void *)ctx->user_regs.eip);

  setCR3(xen_cr3_to_pfn(ctx->ctrlreg[3]));

  printf("\n====== STARTING VM ======\n");

  switch_to_finalize_asm(ctx);
  // never reaches here
  assert(0);
}
