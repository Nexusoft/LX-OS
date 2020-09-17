/** NexusOS: x86 specific initialization: IDT, GDT, TSS, LDT 
 
    IDT and GDT are required
    Nexus uses software task switching, so exposes only a single TSS to the CPU 
    Nexus does not use the LDT, but allows Xen guests to use them */

#include <nexus/defs.h>
#include <nexus/machineprimitives.h>
#ifdef __NEXUSXEN__
#include <nexus/xen-defs.h>
#else
#define NEXUS_DOMAIN_KERNELMAP_START	(KERNELVADDR - (1 << 22))
#endif
#include <asm/hw_irq.h>
#include <asm/segment.h>
#include <asm/processor.h>
#include <asm/system.h>
#include <nexus/thread.h>
#include <nexus/thread-inline.h>

#include <nexus/idtgdt.h>

#define NR_CPUS 1

unsigned char initial_fxstate[512] __attribute__ ((aligned (16)));
CPU_KernelState cpu_state[NR_CPUS] __attribute__ ((aligned (16)));

SegmentDescriptor * const nexus_gdt_table = 
  (SegmentDescriptor *)NEXUS_DOMAIN_KERNELMAP_START;

void *gdtr_base;


////////  Interrupt Descriptor Table  ////////

asmlinkage void divide_error(void);
asmlinkage void debug(void);
asmlinkage void nmi(void);
asmlinkage void int3(void);
asmlinkage void overflow(void);
asmlinkage void bounds(void);
asmlinkage void invalid_op(void);
asmlinkage void device_not_available(void);
// asmlinkage void double_fault(void);
asmlinkage void coprocessor_segment_overrun(void);
asmlinkage void invalid_TSS(void);
asmlinkage void segment_not_present(void);
asmlinkage void stack_segment(void);
asmlinkage void general_protection(void);
asmlinkage void page_fault(void);
asmlinkage void coprocessor_error(void);
asmlinkage void simd_coprocessor_error(void);
asmlinkage void alignment_check(void);
asmlinkage void spurious_interrupt_bug(void);
asmlinkage void machine_check(void);

asmlinkage void nexus_asm_divide_error(void);
asmlinkage void nexus_asm_debug(void);
asmlinkage void nexus_asm_nmi(void);
asmlinkage void nexus_asm_int3(void);
asmlinkage void nexus_asm_overflow(void);
asmlinkage void nexus_asm_bounds(void);
asmlinkage void nexus_asm_invalid_op(void);
asmlinkage void nexus_asm_device_not_available(void);
asmlinkage void nexus_asm_double_fault(void);
asmlinkage void nexus_asm_coprocessor_segment_overrun(void);
asmlinkage void nexus_asm_invalid_TSS(void);
asmlinkage void nexus_asm_segment_not_present(void);
asmlinkage void nexus_asm_stack_segment(void);
asmlinkage void nexus_asm_general_protection(void);
asmlinkage void nexus_asm_page_fault(void);
asmlinkage void nexus_asm_coprocessor_error(void);
asmlinkage void nexus_asm_simd_coprocessor_error(void);
asmlinkage void nexus_asm_alignment_check(void);
asmlinkage void nexus_asm_spurious_interrupt_bug(void);
asmlinkage void nexus_asm_machine_check(void);

asmlinkage void system_call(void);
#ifdef __NEXUSXEN__
asmlinkage void xen_systrap80(void);
#endif
asmlinkage void lcall27(void);

// the first argument selects the type of gate: trap, interrupt or task/call.
// 0/3 is the Descriptor Priority Level (AKA CPU `protection ring`)
#define TRAP 15, 0
#define INTR 14, 0
#define SYSTRAP 15, 3
#define CALL 12, 3

#define DEF_IDT(TYPE,DPL,__CS,EIP)						\
  unsigned int idtHi  = (((unsigned int) (EIP)) & 0xffff0000) | (1 << 15) | (((DPL) & 0x3) << 13) | (((TYPE) & 0xf) << 8); \
  unsigned int idtLo = (((__CS) & 0xffff) << 16) | (((unsigned int) (EIP)) & 0xffff);

void set_idt(unsigned int idtoffset, unsigned int type, unsigned int dpl, void *handler){
  DEF_IDT(type, dpl, KNEXUSCS, handler);
  put_idt((idtoffset * 8), idtLo, idtHi);
}

void init_idt(void)
{
  set_idt(0, TRAP, &nexus_asm_divide_error);
  set_idt(1, TRAP, &nexus_asm_debug);
  set_idt(2, INTR, &nexus_asm_nmi);
  set_idt(3, SYSTRAP, &nexus_asm_int3);	/* int3-5 can be called from all */
  set_idt(4, SYSTRAP, &nexus_asm_overflow);
  set_idt(5, SYSTRAP, &nexus_asm_bounds);
  set_idt(6, TRAP, &nexus_asm_invalid_op);
  set_idt(7, TRAP, &nexus_asm_device_not_available);
  set_idt(8, TRAP, &nexus_asm_double_fault);
  set_idt(9, TRAP, &nexus_asm_coprocessor_segment_overrun);
  set_idt(10, TRAP, &nexus_asm_invalid_TSS);
  set_idt(11, TRAP, &nexus_asm_segment_not_present);
  set_idt(12, TRAP, &nexus_asm_stack_segment);
  set_idt(13, TRAP, &nexus_asm_general_protection);
  set_idt(14, INTR, &nexus_asm_page_fault);
  set_idt(15, TRAP, &nexus_asm_spurious_interrupt_bug);
  set_idt(16, TRAP, &nexus_asm_coprocessor_error);
  set_idt(17, TRAP, &nexus_asm_alignment_check);
  set_idt(18, TRAP, &nexus_asm_machine_check);
  set_idt(19, TRAP, &nexus_asm_simd_coprocessor_error);

  // systemcall handler (0x82)
  set_idt(SYSCALL_VECTOR, SYSTRAP, &system_call);

  // Xen hypercall handler
#ifdef __NEXUSXEN__
  set_idt(LINUX_SYSCALL_VECTOR, SYSTRAP, &xen_systrap80);
#endif

}

void set_fast_trap(int vector, __u16 cs, unsigned long eip) {
#ifdef __NEXUSXEN__
  if(cs != 0) {
    DEF_IDT(15, 3, cs, eip);
    put_idt((vector * 8), idtLo, idtHi);
  } else {
    set_idt(vector, SYSTRAP, &xen_systrap80);
  }
#endif
}

////////  Task State Segment  ////////


#define NEXUS_TSS_OFFSET (FIRST_RESERVED_GDT_ENTRY + 8)
#define NEXUS_LDT_OFFSET (NEXUS_TSS_OFFSET + 1)

TSS *nexustss;

struct { TSS tss; char iomap[2]; } nexustss_data;

void ninit_tss(void){
  int iomap_len = 2;
  nexustss = &nexustss_data.tss;
  nexustss->ptl = 0;
  nexustss->esp0 = 0; 
  nexustss->ss0 = KNEXUSDS;
  nexustss->esp1 = 0;
  nexustss->ss1 = 0;
  nexustss->esp2 = 0;
  nexustss->ss2 = 0;
  nexustss->cr3 = 0;
  nexustss->eip = 0;
  nexustss->eflags = 0;
  nexustss->eax = 0;
  nexustss->ecx = 0;
  nexustss->edx = 0;
  nexustss->ebx = 0;
  nexustss->esp = 0;
  nexustss->ebp = 0;
  nexustss->esi = 0;
  nexustss->edi = 0;
  nexustss->es = 0;
  nexustss->cs = 0;
  nexustss->ss = 0;
  nexustss->ds = 0;
  nexustss->fs = 0;
  nexustss->gs = 0;
  nexustss->ldtsel = 0; //(NEXUS_LDT_OFFSET << 3);
  nexustss->T = 0;
  nexustss->reserved12 = 0;
  nexustss->iomba = 104;

  memset((char*)nexustss + nexustss->iomba, 0xff, iomap_len);

  //granularity 0 (on linux)
  //avl 0
  //limit 235 on linux... I don't think we need that much, maybe 100
  //p 1
  //dpl 0
  //type 1011 (b) if busy 1001 (9) if not... on my dump it's 1011 (b)
  __u8 limit = sizeof(struct TSS) + iomap_len - 1;
  unsigned int tssHi = (((unsigned int) nexustss) & 0xff000000) | (1 << 15) | (0x9 << 8) | ((((unsigned int) nexustss) >> 16) & 0xff);
  unsigned int tssLo = ((((unsigned int) nexustss) & 0xffff) << 16) | limit;
  
  // write the TSS entry to the GDT
  put_gdt((NEXUS_TSS_OFFSET * 8), tssLo, tssHi);
  write_tr(NEXUS_TSS_OFFSET << 3);
}


////////  Global Descriptor Table  ////////

void init_gdt(void){
  char val[8];
  __asm__ __volatile__ ( "sgdtl %0" : : "m" (val[0]) );
  gdtr_base = *(void **) (val + 2);

  // Zap boot selectors
  put_gdt((2 * 8), 0, 0);
  put_gdt((3 * 8), 0, 0);
  ninit_tss();
}

/// Switch GDT from boot_gdt (XXX bzImage specific?)
void switch_to_final_gdt(void) {
   unsigned long paddr, vaddr;
   int i, rv;

  for (i = 0; i <= LAST_RESERVED_GDT_ENTRY; i += GDT_ENTRIES_PER_PAGE) {
    paddr = VIRT_TO_PHYS(&boot_gdt_table[i]);
    vaddr = (__u32) &nexus_gdt_table[i];
    assert((paddr & PAGE_OFFSET_MASK) == 0 && (vaddr & PAGE_OFFSET_MASK) == 0);

    rv = Map_insertAt(kernelMap, paddr, 1, 0, 0, 0, vaddr);
    assert(rv == vaddr);
  }

  // Make sure MMU updates are visible
  mb();
  gdt_descr.base_address = &nexus_gdt_table[0];
  mb(); // Make sure new version of gdt_descr is visible
  write_gdtr(&gdt_descr);
}


////////  Local Descriptor Table  ////////

typedef struct ldtdesc ldtdesc;
struct ldtdesc{
  unsigned int lo;
  unsigned int hi;
};

void set_ldt(ldtdesc *ldtlocation, unsigned int type, unsigned int dpl, void *handler){
  unsigned int ldtHi  = (((unsigned int) handler) & 0xffff0000) | (1 << 15) | (dpl << 13) | (type << 8);  
  unsigned int ldtLo = (KNEXUSCS << 16) | (((unsigned int) handler) & 0xffff);
  ldtlocation->lo = ldtLo;
  ldtlocation->hi = ldtHi;
}

ldtdesc ldt = {0, 0};

/// Only used when XEN guest OSes require LDTs
void write_ldt(unsigned int base_address, int num_entries) {
  SegmentDescriptor *desc = &nexus_gdt_table[NEXUS_LDT_OFFSET];
  SegmentDescriptor update = {
    // byte granularity
    SEGMENT_DESCRIPTOR_BASE(base_address),
    SEGMENT_DESCRIPTOR_LIMIT(num_entries * sizeof(SegmentDescriptor) - 1),

    .type = 0x2,
    .s = 0,
    .dpl = 0x0,
    .p = 1,
    .avl = 0,
    .o = 0,
    .db = 0,
    .g = 0,
  };
  *desc = update;
  // Reload ldt
  mb();
  __asm__ __volatile__ ( "lldt %w0" : : "q" (NEXUS_LDT_OFFSET * 8) );
// old version, no longer accepted by gcc 4.3.3
// I left it here in case older gcc's don't accept the above
//  __asm__ __volatile__ ( "lldt %0" : : "m" (NEXUS_LDT_OFFSET * 8) );
}


////////  CPU Init  ////////

int nexus_sse_enabled;

int init_sse_cpu(void) 
{
  unsigned int info;
  unsigned int mxcsrval[2];
  // int i;

  // first initialize fpu
  finit_state();
  info = cpuid_edx(1);  //1 is the value for feature info

  if (((1 << 25) & info) == 0) {
    printk("processor does not support sse\n");
    return -1; //processor does not support sse
  }
  
  if (((1 << 24) & info) == 0) {
    printk("processor does not support fxsave or fxrstor\n");
    return -1; //no fxsave or fxrstor
  }

  //sse support will be turned on
  writecr4(readcr4() | (1<<9) | (1<<10));

  /* clear EM flag (bit 2), MP flag (bit 1) of cr0 */
  writecr0(readcr0() & ~(1<<2) & ~(1<<1));
  
  //set MXCSR bits
  mxcsrval[0] = 0x1f80; //the default
  mxcsrval[1] = 0x0;
  
  loadmxcsr(mxcsrval);
  return 0;
}

int init_sse(void){

  if (init_sse_cpu())
	  return -1;

  //initial_fxstate.cwd = 0x37f;
  //initial_fxstate.mxcsr = 0x1f80;

  memset(initial_fxstate, 0, 512);
  fxsave_registers(initial_fxstate);

  cpu_state[current_cpu()].in_interrupt = 0;

  nexus_sse_enabled = 1;
  return 0;
}


