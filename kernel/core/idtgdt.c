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

// the first argument selects the type of gate: trap, interrupt or task/call.
// 0/3 is the Descriptor Priority Level (AKA CPU `protection ring`)
#define TRAP 15, 0
#define INTR 14, 0
#define SYSTRAP 15, 3
#define CALL 12, 3

ldtdesc ldt = {0, 0};

#ifdef DIRECT_NEXUS_INTERRUPT

#define DEF_IDT(TYPE,DPL,__CS,EIP)						\
  unsigned int idtHi  = (((unsigned int) (EIP)) & 0xffff0000) | (1 << 15) | (((DPL) & 0x3) << 13) | (((TYPE) & 0xf) << 8); \
  unsigned int idtLo = (((__CS) & 0xffff) << 16) | (((unsigned int) (EIP)) & 0xffff);

void set_idt(unsigned int idtoffset, unsigned int type, unsigned int dpl, void *handler){
  DEF_IDT(type, dpl, KNEXUSCS, handler);
  put_idt((idtoffset * 8), idtLo, idtHi);
}

#else /* not DIRECT_NEXUS_INTERRUPT */
void *nexus_exception_table[NUM_EXCEPTIONS];

static void set_nexus_trap(int index, void *fn) 
{
  assert(index >= 0 && index < NUM_EXCEPTIONS);
  nexus_exception_table[index] = fn;
}
#endif /* not DIRECT_NEXUS_INTERRUPT */

void init_idt(void)
{

#if 0
  set_idt(0, TRAP, &divide_error);
  set_idt(1, TRAP, &debug);
  set_idt(2, INTR, &nmi);
  set_idt(3, SYSTRAP, &int3);	/* int3-5 can be called from all */
  set_idt(4, SYSTRAP, &overflow);
  set_idt(5, SYSTRAP, &bounds);
  set_idt(6, TRAP, &invalid_op);
  set_idt(7, TRAP, &device_not_available);
  set_idt(8, TRAP, &double_fault);
  set_idt(9, TRAP, &coprocessor_segment_overrun);
  set_idt(10, TRAP, &invalid_TSS);
  set_idt(11, TRAP, &segment_not_present);
  set_idt(12, TRAP, &stack_segment);
  set_idt(13, TRAP, &general_protection);
  set_idt(14, INTR, &page_fault);
  set_idt(15, TRAP, &spurious_interrupt_bug);
  set_idt(16, TRAP, &coprocessor_error);
  set_idt(17, TRAP, &alignment_check);
  set_idt(18, TRAP, &machine_check);
  set_idt(19, TRAP, &simd_coprocessor_error);
#else
#ifdef DIRECT_NEXUS_INTERRUPT
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
#else
  set_nexus_trap(0, &nexus_asm_divide_error);
  set_nexus_trap(1, &nexus_asm_debug);
  set_nexus_trap(2, &nexus_asm_nmi);
  set_nexus_trap(3, &nexus_asm_int3);	/* int3-5 can be called from all */
  set_nexus_trap(4, &nexus_asm_overflow);
  set_nexus_trap(5, &nexus_asm_bounds);
  set_nexus_trap(6, &nexus_asm_invalid_op);
  set_nexus_trap(7, &nexus_asm_device_not_available);
  set_nexus_trap(8, 0);
  set_nexus_trap(9, &nexus_asm_coprocessor_segment_overrun);
  set_nexus_trap(10, &nexus_asm_invalid_TSS);
  set_nexus_trap(11, &nexus_asm_segment_not_present);
  set_nexus_trap(12, &nexus_asm_stack_segment);
  set_nexus_trap(13, &nexus_asm_general_protection);
  set_nexus_trap(14, &nexus_asm_page_fault);
  set_nexus_trap(15, &nexus_asm_spurious_interrupt_bug);
  set_nexus_trap(16, &nexus_asm_coprocessor_error);
  set_nexus_trap(17, &nexus_asm_alignment_check);
  set_nexus_trap(18, &nexus_asm_machine_check);
  set_nexus_trap(19, &nexus_asm_simd_coprocessor_error);

  set_idt(0, TRAP, &divide_error);
  set_idt(1, TRAP, &debug);
  set_idt(2, INTR, &nmi);
  set_idt(3, SYSTRAP, &int3);	/* int3-5 can be called from all */
  set_idt(4, SYSTRAP, &overflow);
  set_idt(5, SYSTRAP, &bounds);
  set_idt(6, TRAP, &invalid_op);
  set_idt(7, TRAP, &device_not_available);
  set_idt(8, TRAP, &nexus_asm_double_fault);
  set_idt(9, TRAP, &coprocessor_segment_overrun);
  set_idt(10, TRAP, &invalid_TSS);
  set_idt(11, TRAP, &segment_not_present);
  set_idt(12, TRAP, &stack_segment);
  set_idt(13, TRAP, &general_protection);
  set_idt(14, INTR, &page_fault);
  set_idt(15, TRAP, &spurious_interrupt_bug);
  set_idt(16, TRAP, &coprocessor_error);
  set_idt(17, TRAP, &alignment_check);
  set_idt(18, TRAP, &machine_check);
  set_idt(19, TRAP, &simd_coprocessor_error);
#endif // DIRECT_NEXUS_INTERRUPT
#endif

  //SYSCALL_VECTOR is 0x82, set in linux include files
  set_idt(SYSCALL_VECTOR, SYSTRAP, &system_call);
#ifdef __NEXUSXEN__
  set_idt(LINUX_SYSCALL_VECTOR, SYSTRAP, &xen_systrap80);
#endif

  //XXX 
  // I don't set call gates for lcall7 and lcall27 in the ldt
  // because I don't understand the ldt yet.  One of them is used for shutdown.
  // they are still being initialized in traps.c 997
  // the code for whatever needs to be loaded in there I think
  //set_ldt(&ldt, CALL, lcall27);
  
}

void set_fast_trap(int vector, __u16 cs, unsigned long eip) {
  if(cs != 0) {
    DEF_IDT(15, 3, cs, eip);
    put_idt((vector * 8), idtLo, idtHi);
  } else {
#ifdef __NEXUSXEN__
    set_idt(vector, SYSTRAP, &xen_systrap80);
#endif
  }
}


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
  
  put_gdt((NEXUS_TSS_OFFSET * 8), tssLo, tssHi);
  write_tr(NEXUS_TSS_OFFSET << 3);
}

void init_gdt(void){
  //printk("GDT:  begin nexus init of gdt\n");
  char val[8];
  __asm__ __volatile__ ( "sgdtl %0" : : "m" (val[0]) );
  gdtr_base = *(void **) (val + 2);

  // Zap boot selectors
  put_gdt((2 * 8), 0, 0);
  put_gdt((3 * 8), 0, 0);
  ninit_tss();
}

void switch_to_final_gdt(void) {
  // Switch GDT from boot_gdt
  int i;
  for(i=0; i <= LAST_RESERVED_GDT_ENTRY; 
      i += GDT_ENTRIES_PER_PAGE) {
    __u32 paddr = VIRT_TO_PHYS(&boot_gdt_table[i]);
    __u32 vaddr = (__u32) &nexus_gdt_table[i];
    assert((paddr & PAGE_OFFSET_MASK) == 0 && 
	   (vaddr & PAGE_OFFSET_MASK) == 0);
    int rv;
    rv = memmap_add_page(kernelMap, 0, paddr, 1, 0, 0, 0, vaddr);
    assert(rv == vaddr);
  }

  // Make sure MMU updates are visible
  mb();
  gdt_descr.base_address = &nexus_gdt_table[0];
  mb(); // Make sure new version of gdt_descr is visible
  write_gdtr(&gdt_descr);
}

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

/* printing for debugging */
void print_gdt(void){
  int gdtr = read_gdtr();
  int i;
  SegmentDescriptorLo *lo;
  SegmentDescriptorHi *hi;

  printk("base is 0x%x limit is %x\n", gdtr, read_gdtr_limit());
  for (i = 0; i < 20; ++i) {
    lo = (SegmentDescriptorLo *) (gdtr + (i*8));
    hi = (SegmentDescriptorHi *) (gdtr + (i*8) + 4);
    printk("%d: p=%d base=0x%x, g=%d, s=%d, type=0x%x, avl=%d, limit=0x%x, dpl=0x%x\n", i, hi->p, ((hi->base << 24) | (hi->base2 << 16) | (lo->base3)), hi->g, hi->s, hi->type, hi->avl, ((hi->seglimit << 16) | (lo->limit)), hi->dpl); 
  }
}

void print_tss(void){
  unsigned int selector = read_tr();
  int gdtr = read_gdtr();
  int i;
  unsigned int base;
  SegmentDescriptorLo *lo;
  SegmentDescriptorHi *hi;
  
  printk("tss selector = 0x%x, index = 0x%x\n", selector, selector >> 3);
  printk("gdtr base is 0x%x limit is %x\n", gdtr, read_gdtr_limit());
  
  i = selector >> 3;
  lo = (SegmentDescriptorLo *) (gdtr + (i*8));
  hi = (SegmentDescriptorHi *) (gdtr + (i*8) + 4);
  
  base = ((hi->base << 24) | (hi->base2 << 16) | (lo->base3));
  printk("tss base is 0x%x\n", base);

  TSS *tss = (TSS *)base;
  printk("ptl = 0x%x, pdbr = 0x%x, eip = 0x%x\n", tss->ptl, tss->cr3, tss->eip);
  printk("esp0 = 0x%x esp1 = 0x%x esp2 = 0x%x\n", tss->esp0, tss->esp1, tss->esp2);
  printk("ss0 = 0x%x ss1 = 0x%x ss2 = 0x%x\n", tss->ss0, tss->ss1, tss->ss2);
  printk("cs = 0x%x ss = 0x%x ds = 0x%x\n", tss->cs, tss->ss, tss->ds);
  printk("ldt = 0x%x mbat = 0x%x\n", tss->ldtsel, *((unsigned int*)&tss->ldtsel + 1));
  printk("eflags=0x%x eax=0x%x ecx=0x%x edx=0x%x ebx=0x%x esp=0x%x ebp=0x%x esi=0x%x edi=0x%x es=0x%x cs=0x%x ss=0x%x ds=0x%x fs=0x%x\n",
	 tss->eflags, tss->eax, tss->ecx, tss->edx, tss->ebx, tss->esp, tss->ebp, tss->esi, tss->edi, tss->es, tss->cs, tss->ss, tss->ds, tss->fs);
}

void print_idt(void){
  int idtr = read_idtr();
  int i;
  IDTEntryLo *lo;
  IDTEntryHi *hi;

  printk("base is 0x%x limit is %x\n", idtr, read_idtr_limit());
  for (i = 0; i < 20; ++i) {
    lo = (IDTEntryLo *) (idtr + (i*8));
    hi = (IDTEntryHi *) (idtr + (i*8) + 4);
    printk("%d: p=%d type=0x%x, selector=0x%x, offsetlo=0x%x, offset=0x%x, d=%d, dpl=0x%x\n", 
	   i, hi->p, hi->gatetype, lo->selector, lo->offset, ((hi->offset << 16) | lo->offset), hi->d, hi->dpl); 
  }
  i=128; //int 0x80
  lo = (IDTEntryLo *) (idtr + (i*8));
  hi = (IDTEntryHi *) (idtr + (i*8) + 4);
  printk("%d: p=%d type=0x%x, selector=0x%x, offset=0x%x, d=%d, dpl=0x%x\n", i, hi->p, hi->gatetype, lo->selector, ((hi->offset << 16) | (lo->offset)), hi->d, hi->dpl); 
  
}

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

  /* qemd didn't have clflush, but we want to go ahead anyway */
#if 0
  if (((1 << 19) & info) == 0) {
    printk("processor does not support clflush\n");
    return -1; //no clflush
  }
#endif

  //sse support will be turned on
#if 0
  printk("0x%x\n", (1<<9));
  printk("0x%x\n", (1<<10));
  printk("0x%x\n", readcr4());
  printk("0x%x\n", readcr4() | (1<<9) | (1<<10));
#endif
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

#if 0
  printk("initial fxstate = ");
  for(i =0; i < 512; i++){
    printk("%02x ", initial_fxstate[i]);
  }
  printk("\n");
#endif
  
  nexus_sse_enabled = 1;
  return 0;
}
