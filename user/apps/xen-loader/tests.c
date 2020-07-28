#include <unistd.h> // for sleep()
#include "loader.h"
#include "tests.h"

maddr_t pgtable_l1;
maddr_t pgtable_l2;

void test_seg_regs(void) {
  __asm__ ( "movl %0, %%fs" : : "r" (0x0839));
  __asm__ ( "movl %0, %%gs" : : "r" (0x0839));
  dump_seg_regs();
}

void dump_seg_regs(void) {
  __u32 new_FS = 0;
  __u32 new_GS = 1;
  while(1) {
    // Check segment registers

#define CHECK_SEG(REGNAME)				\
    __asm__ __volatile__ (				\
			  "movl %%" #REGNAME ", %0" :	\
			  "=r" (new_##REGNAME) );	\
    printf("New " #REGNAME " is %x\n", new_##REGNAME);

#if 0
    CHECK_SEG(CS);
    CHECK_SEG(DS);
    CHECK_SEG(ES);
    CHECK_SEG(SS);
#endif
    CHECK_SEG(FS);
    CHECK_SEG(GS);

#undef CHECK_SEG
    sleep(1);
  }
}

void run_pdir_map_tests(void) {
  printf("Some select entries:\n");
  DirectoryEntry *pdes = (DirectoryEntry *)NEXUS_VMM_PGDIR_START;
  printf("pdes[0] = %p pdes[HYPERVISOR_VIRT_START] = %p pdes[kimage] = %p pdes[1023] = %p\n",
	 (void *)DirectoryEntry_to_u32(pdes[0]),
	 (void *)DirectoryEntry_to_u32(pdes[HYPERVISOR_VIRT_START >> PDIR_SHIFT]),
	 (void *)DirectoryEntry_to_u32(pdes[0xc0000000 >> PDIR_SHIFT]),
	 (void *)DirectoryEntry_to_u32(pdes[1023]));
  printf("Trying direct write to pdir\n");
  ((__u32 *)pdes)[0] = 0;
  printf("Direct write should not have passed!\n");
}

void dump_checkvals(void) {
  int i;
  for(i=0; i < NUM_VMM_PTABS; i++) {
    printf("checkval[%d] = %p\n", i, (void *)gVMMPtable_checkVals[i]);
  }
}

int sanity_check_m2p_consistency(void) {
  int i;
  for(i=0; i < gTotalVMPages; i++) {
    machfn_t mfn = phys2mach[i];
    assert(mfn < num_mach2phys_pages * PAGE_SIZE / sizeof(paddr_t));
    if(mach2phys[mfn] != i) {
      printf("m2p consistency failed at %i=>%p,%p\n",
	     i, (void *) mfn, (void *) mach2phys[mfn]);
      return 0;
    }
  }
  return 1;
}

void p2m_mapping_dump(void) {
  printf("phys2mach[0]=%d, mapping is %p\n",
	 phys2mach[0],
	 (void *)*(__u32 *) VMM_pte_v((vaddr_t) phys2mach));
}

int sanity_check_pdir(machfn_t pdir_mfn) {
  DirectoryEntry *pdir = (DirectoryEntry *)KSEG_map_ro(&pdir_mfn, 1);
  int rv = PDIR_checkHigh(pdir);
  KSEG_unmap((vaddr_t)pdir);
  return rv;
}

#define NUM_DUMP_ENTRIES (5)
void l1tab_dump(void *l1tab, int isVirt) {
  __u32 *vl1tab;
  if(isVirt) {
    vl1tab = l1tab;
  } else {
    machfn_t mfn = ((__u32)l1tab) >> PAGE_SHIFT;
    vl1tab = (__u32 *)KSEG_map_ro(&mfn, 1);
  }
  int i;
  printf("l1=%p\n", (void*) l1tab);
  int limit = NUM_DUMP_ENTRIES;
  for(i=0; i < PTABLE_ENTRIES; i++) {
    if(vl1tab[i] != 0) {
      printf("l1[%d]=>%p\n", i, (void*) vl1tab[i]);
      if(limit-- == 0) return;
    }
  }
}

void l2tab_dump(void *l2tab, int isVirt) {
  __u32 *vl2tab;
  if(isVirt) {
    vl2tab = l2tab;
  } else {
    machfn_t mfn = ((__u32)l2tab) >> PAGE_SHIFT;
    vl2tab = (__u32 *)KSEG_map_ro(&mfn, 1);
  }
  int i;
  printf("l2=%p\n", (void*) l2tab);
  int limit = NUM_DUMP_ENTRIES;
  for(i=0; i < PDIR_ENTRIES; i++) {
    if(vl2tab[i] != 0) {
      printf("l2[%d]=>%p\n", i, (void*) vl2tab[i]);
      if(limit-- == 0) return;
    }
  }
}

void pdir_dump(void) {
  DirectoryEntry *pdes = VMM_pde_v(0);
  int i;
  for(i=0; i < PDIR_ENTRIES; i++) {
    if(pdes[i].present) {
      printf("pde[%d]=%p", i, (void *)*(__u32*)&pdes[i]);
    }
  }
}

void mapdump(vaddr_t start, vaddr_t end) {
  start = page_rounddown(start);
  end = page_roundup(end);
  while(start != end) {
    if(VMM_pte_isPresent(start)) {
      PageTableEntry *pte = VMM_pte_v(start);
      if(0) {
	printf("(%p=>%p)", (void*)start, 
	       (void*)(pte->pagebase << PAGE_SHIFT));
      } else {
	printf("(%p=>%p)", (void*)start, 
	       (void*)*(__u32*)pte);
      }
    }
    start += PAGE_SIZE;
  }
}

struct HypercallTableEntry {
  char *name;
};

#define HYPERCALL(X)				\
  [__HYPERVISOR_##X] =				\
  ((struct HypercallTableEntry) {		\
    .name = #X					\
       }), 

struct HypercallTableEntry hypercall_table[] = {
  HYPERCALL(set_trap_table)
  HYPERCALL(mmu_update)
  HYPERCALL(set_gdt)
  HYPERCALL(stack_switch)
  HYPERCALL(set_callbacks)
  HYPERCALL(fpu_taskswitch)
  HYPERCALL(sched_op_compat)
  HYPERCALL(platform_op)
  HYPERCALL(set_debugreg)
  HYPERCALL(get_debugreg)
  HYPERCALL(update_descriptor)
  // gap
  HYPERCALL(memory_op)
  HYPERCALL(multicall)
  HYPERCALL(update_va_mapping)
  HYPERCALL(set_timer_op)
  HYPERCALL(event_channel_op_compat)
  HYPERCALL(xen_version)
  HYPERCALL(console_io)
  HYPERCALL(physdev_op_compat)
  HYPERCALL(grant_table_op)
  HYPERCALL(vm_assist)
  HYPERCALL(update_va_mapping_otherdomain)
  HYPERCALL(iret)
  HYPERCALL(vcpu_op)
  // gap
  HYPERCALL(mmuext_op)
  HYPERCALL(acm_op)
  HYPERCALL(nmi_op)
  HYPERCALL(sched_op)
  HYPERCALL(callback_op)
  HYPERCALL(xenoprof_op)
  HYPERCALL(event_channel_op)
  HYPERCALL(physdev_op)
  HYPERCALL(hvm_op)
  HYPERCALL(sysctl)
  HYPERCALL(domctl)

  HYPERCALL(getNexusVariables)
  HYPERCALL(vnet_init)
  HYPERCALL(vnet_send)
  HYPERCALL(vnet_has_pending_recv)
  HYPERCALL(vnet_recv)
  HYPERCALL(vnet_setup_irq)
};

#define NUM_HYPERCALL_RECORDS (32)
#define MAX_CALLSTACK (1)
struct HypercallRecord {
  int num;
  __u32 call_stack[MAX_CALLSTACK];
  int gs;
} record_entries[NUM_HYPERCALL_RECORDS];

int record_tail;

static void dump_hypercall_record_entry(struct HypercallRecord *record) {
  char *name;
  if(record->num >= 0 && record->num < sizeof(hypercall_table) / sizeof(hypercall_table[0])) {
    name = hypercall_table[record->num].name;
  } else {
    name = "OUT OF RANGE";
  }
  printf("%p (%x) => %d (%s)\n", (void *)record->call_stack[0], record->gs,
	 record->num, name);
}

typedef struct HypercallState {
  __u32 eax, 
    ebx, ecx, edx, esi, edi, ebp,

    _ebx, _ecx, _edx, _esi, _edi, _ebp,
    gs,

    return_addr;
} HypercallState;

void record_hypercall(HypercallState *hs) {
  struct HypercallRecord *new_entry = &record_entries[record_tail];
  new_entry->num = hs->eax;
  new_entry->call_stack[0] = hs->return_addr;
  new_entry->gs = hs->gs;
  record_tail = (record_tail + 1) % NUM_HYPERCALL_RECORDS;

  switch(new_entry->num) {
#if 0
  case 29: { // arch_sched_op
    static int limit = 0;
    limit++;
    if(limit > 100) {
      __asm__ ("ud2");
    }
    break;
  }
#endif
#if 1
  case 1: // mmu_update_guest
  case 14: // update_va_mapping
  case 26: // mmuext_op
  case 18: // console_io
  case 17: // xen_version, used to force callbacks
  case 13: // multicall
  case 15: // set_timer_op
  case 29: // arch_sched_op
  case 16: case 32: // event_channel_op and event_channel_op_compat
  case 10: // update descriptor
  case __HYPERVISOR_vnet_send:
  case __HYPERVISOR_vnet_has_pending_recv:
  case __HYPERVISOR_vnet_recv:
#endif
    // suppress printout for some common hypercalls
    break;
  default:
    dump_hypercall_record_entry(new_entry);
  }
}

void dump_hypercall_record(void) {
  int i;
  for(i=0; i < NUM_HYPERCALL_RECORDS; i++) {
    int real_index = (record_tail + 1 + i) % NUM_HYPERCALL_RECORDS;
    dump_hypercall_record_entry(&record_entries[real_index]);
  }
}
