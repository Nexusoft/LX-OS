
#define __XEN_TOOLS__

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h> // for sleep()
#include <errno.h>
#include <assert.h>

#include <nexus/machine-structs.h> // for page table and descriptor structures
#include <nexus/tls.h>
#include <nexus/linuxcalls.h>

#include <nexus/Thread.interface.h>
#include <nexus/IPC.interface.h>
#include <nexus/Mem.interface.h>
#include <nexus/Xen.interface.h>
#include <nexus/Console.interface.h>
#include <nexus/Debug.interface.h>

#include "loader.h"
#include "tests.h"
#include "hypercalls.h"

//#define DEFAULT_VM_SIZE ((256 * (1 << 20)) / PAGE_SIZE)
#define DEFAULT_VM_SIZE ((64 * (1 << 20)) / PAGE_SIZE)

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

  __errno_enable_tls = 0;

  // small delta to minimize waste of virtual address space
  __thread_global_stack_base = page_roundup((__u32) VMM_TEXT_END);
  __thread_global_stack_limit = __thread_global_stack_base + (1024 * PAGE_SIZE);

  // adjust data segment size
  __curbrk = (void *) __thread_global_stack_limit;
 
  // switch to CPL1
  if (Xen_PreInit())
    exit(1);

  Debug_printk_msg("Pre...\n");
}

void (*pre_main_hook)(void) = pre_main;

static void initialize_mem(int numpgs);
static void post_load_mem_cleanup(void);
static void vmm_pages_set_supervisor(void);

int main(int argc, char **argv) {
  const char cmdline[] = "root=/dev/ram0 init=/nexus rw";
  char *initrd_name;
  unsigned long test_malloc, store_mfn, cons_mfn;
  int rv;

  register_pf_handler_enter(x86_emulate_enter_vmm);
  register_pf_handler_write(x86_emulate_write_vmm);
  register_pf_handler_read(x86_emulate_read_vmm);
  register_pf_handler_cmpxchg(x86_emulate_cmpxchg_vmm);

  g_dom_id = Thread_GetProcessID();
  KSEG_init();

  // assert that all code fits in the assigned CODEHEAP region
  __asm__ ( "movl $.text, %0" : "=r" (VMM_START));
  assert((void *)NEXUS_VMM_CODEHEAP_START <= VMM_START);
  assert(VMM_TEXT_END < (void *)NEXUS_VMM_CODEHEAP_END);

  phys2mach = (machfn_t *) NEXUS_VMM_PHYS2MACH_START;

  Debug_printk_msg("XXX reenable malloc support?\n");

  if (argc < 2 || argc > 3) {
    Debug_printk_msg("Usage: xen.app <image> [ramdisk]\n");
    Thread_Exit(1, 0, 0);
  }

  if (argc == 3)
    initrd_name = argv[2];
  else
    initrd_name = NULL;

  // make VMM pages owned by supervisor
  initialize_mem(DEFAULT_VM_SIZE);

  // set VMM pages to supervisor
  vmm_pages_set_supervisor();

  shared_info_mfn = maddr_to_machfn(Xen_AllocPages(1));
  assert(shared_info_mfn != 0);
  Xen_RegisterSharedMFN(shared_info_mfn);
  
  // Map in shared info frame
  if (Xen_MMU_Map(NEXUS_VMM_SHAREDINFO_START, shared_info_mfn,
		   __PAGE_KERNEL))
	  Thread_Exit(1, 0, 0);

  rv = xc_linux_build(-1, DOMID_SELF, 
		      argv[1], initrd_name, // images
		      cmdline, NULL,  // command line and features
		      0 /* flags */,
		      EVTCHAN_STORE /* store evt chn */, &store_mfn,
		      EVTCHAN_CONSOLE /* console evtchn */, &cons_mfn);

  Debug_printk_msg("TEST #E\n");
  post_load_mem_cleanup();
  Debug_printk_msg("TEST #F\n");

  rv = Console_SetInputMode(KBD_RARE);
  assert(rv == 0);

  mouse_handle = Console_Mouse_Init();
  assert(mouse_handle >= 0);
  
  switch_to(&initial_cpu_ctx);
}

static void initialize_mem(int numpgs) {
  DirectoryEntry *pde, *pdbr_data;
  maddr_t mach_addr;
  int num_pages, rv, i;

  gTotalVMPages = numpgs;
  gPDBR = Xen_GetPDBR();

  // bootstrapping requires existing contents of pdbr
  pdbr_data = (void *) Mem_GetPages(1, 0);
  rv = Xen_ReadPDBR((char *) pdbr_data);
  assert(rv == 0);

  // Sanity check: Xen page tables must be 4MB aligned
  assert(VMM_PDOFFSET << PDIR_SHIFT == HYPERVISOR_VIRT_START);
  
  // Must load gVMMPtable asap, since it is needed for verification
  // in HYPERCALL_mmu_update
  for (i = 0; i < NUM_VMM_PTABS; i++) {
    pde = &pdbr_data[VMM_PDOFFSET + i];

    if (i == (NEXUS_VMM_PGTABLE_START >> PDIR_SHIFT) - VMM_PDOFFSET)
      pde->present = 0; // No default value for the mapped page table
    else {
      if (!pde->present)
        *pde = allocate_new_ptable((char *) pde - (char *)pdbr_data, 0);
    }
    gVMMPtable_checkVals[i] = DirectoryEntry_to_u32(*pde);
  }

  Xen_Set_VMM_PDIR(VMM_PDOFFSET, &gVMMPtable_checkVals[0], NUM_VMM_PTABS);

  PDBR_switchto(gPDBR, 1);
  // First mapping of PGDIR_START, so we can use it right away
  PDBR_sync();

  // we don't need this copy any more, since it is now mapped in
  Mem_FreePages((unsigned long) pdbr_data, 1);

  // Allocate and map in P2M area for use during load
  int p2m_totlen = P2M_totlen();
  int num_p2m_pages = page_roundup(p2m_totlen) / PAGE_SIZE;
  char *p2m_ptr = (char *) phys2mach;
  for (i = 0; i < num_p2m_pages; i++) {
    paddr_t paddr = Xen_AllocPages(1);
    Xen_MMU_Map((vaddr_t) p2m_ptr, maddr_to_machfn(paddr), __PAGE_KERNEL);
    p2m_ptr += PAGE_SIZE;
  }

  memset(phys2mach, 0, p2m_totlen);

  // Allocate non-contiguous pages, and put them in p2m
  for(i=0; i < gTotalVMPages; i++) {
    paddr_t paddr = Xen_AllocPages(1);
    if(paddr == 0) {
      Debug_printk_msg("Not enough memory to allocate VM pages");
      Thread_Exit(1, 0, 0);
    }
    // Nexus physical becomes Nexus VMM machine
    phys2mach[i] = (machfn_t)(paddr >> PAGE_SHIFT);
  }

  if (Xen_GetMach2Phys(&mach_addr, &num_pages))
	  Thread_Exit(1, 0, 0);

  assert(num_pages <= (MACH2PHYS_VIRT_END - MACH2PHYS_VIRT_START) / PAGE_SIZE);

  num_mach2phys_pages = num_pages;
  if (Xen_MMU_Map_rangeBase(MACH2PHYS_VIRT_START, maddr_to_machfn(mach_addr), 
			    num_pages, __PAGE_KERNEL_RO))
	  Thread_Exit(1, 0, 0);
}

static void post_load_mem_cleanup(void) {
  void *p2m_ptr = phys2mach;
  maddr_t mach_addr;
  int num_p2m_pages, i; 

  num_p2m_pages = page_roundup(P2M_totlen()) / PAGE_SIZE;

  for (i = 0; i < num_p2m_pages; i++) {
    mach_addr = VMM_virtToMach((paddr_t) p2m_ptr);
    Xen_MMU_Unmap((paddr_t) p2m_ptr);
    Xen_FreePages((paddr_t) mach_addr, 1);
    p2m_ptr += PAGE_SIZE;
  }
}

static void vmm_pages_set_supervisor(void) {
  // Set both PDIR and PTAB to supervisor
  vaddr_t vaddr;

  for (vaddr = HYPERVISOR_VIRT_START; vaddr < HYPERVISOR_VIRT_END; vaddr += PAGE_SIZE) {
    maddr_t ptr = VMM_pte_m(vaddr);
    __u32 val = *(__u32 *) VMM_pte_v(vaddr);
    val &= ~_PAGE_USER;

    if (mmu_update_single(ptr, val)) {
      Debug_printk_msg("Could not mmu_update\n");
      Thread_Exit(1, 0, 0);
    }
  }
}

/** Load Xen virtual CPU0 context into VMM */
void __attribute__ ((noreturn)) switch_to(struct vcpu_guest_context *ctx) {
  HYPERCALL_stack_switch(ctx->kernel_ss, ctx->kernel_sp);
  HYPERCALL_set_trap_table(ctx->trap_ctxt);
  HYPERCALL_set_callbacks(ctx->event_callback_cs, ctx->event_callback_eip,
	  ctx->failsafe_callback_cs, ctx->failsafe_callback_eip);
  
  printf("almost STARTING VM\n");
  printf("Will jump to %x:%p\n", ctx->user_regs.cs, (void *)ctx->user_regs.eip);

  setCR3(xen_cr3_to_pfn(ctx->ctrlreg[3]));

  printf("\n====== STARTING VM ======\n");

  switch_to_finalize_asm(ctx);

  // never reaches here
  assert(0);
}

