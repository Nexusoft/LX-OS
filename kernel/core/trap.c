#include <nexus/defs.h>
#include <nexus/machineprimitives.h>
#include <nexus/clock.h>
#include <nexus/synch.h>
#include <nexus/synch-inline.h>
#include <nexus/thread.h>
#include <nexus/queue.h>
#include <nexus/device.h>
#include <nexus/ipd.h>
#include <asm/hw_irq.h>
#include <nexus/thread-private.h>
#include <nexus/devicelog.h>

extern int in_panic;
extern volatile int preemption_mask;

extern BasicThread *curt;
extern void keyboard_interrupt(int irq, void *dev_id, struct pt_regs *regs);
extern void nexusthread_kill_helper(BasicThread *t);

extern unsigned __start_nexus___ex_table;
extern unsigned __stop_nexus___ex_table;

extern unsigned __start___ex_table;
extern unsigned __stop___ex_table;

typedef int (*ExceptionHandler)(void);

int trap_bounce_to_user(InterruptState *is, int idx, unsigned int vaddr);

unsigned int last_eflags, last_top_eflags;
void *last_iret;

static inline ExceptionHandler search_nexus_exception_table(unsigned eip) {
  unsigned int *finger;

  for(finger = (unsigned int *)&__start_nexus___ex_table; 
      finger < (unsigned int *)&__stop_nexus___ex_table; 
      finger += 2) {
    if(eip == finger[0]) {
      return (ExceptionHandler) finger[1];
    }
  }
  printk("couldn't find exception entry\n");
  printk("last eflags = %x %x, iret = %p\n", last_eflags, last_top_eflags, last_iret);
  return NULL;
}

void kill_current_domain(void) {
  printk_current("Kill current domain (thread %d)\n", 
		 nexusthread_id(nexusthread_self()));
  ipd_killall(nexusthread_current_ipd());
  nexusthread_exit();
  nexuspanic();
}

void nexus_divide_error(InterruptState *is){
  nexusthread_enter_interrupt(curt, is);
  printk_current("NEXUS: divide_error\n");
  dump_regs_is(is);
  nexuspanic();
  nexusthread_exit_interrupt(curt, is);
}
void nexus_debug_intr(InterruptState *is){
  nexusthread_enter_interrupt(curt, is);
  breakpoint_handle_DB(is);
  nexusthread_exit_interrupt(curt, is);
}
void nexus_nmi(InterruptState *is){
  nexusthread_enter_interrupt(curt, is);
  printk_current("NEXUS: nmi\n");
  nexuspanic();
  nexusthread_exit_interrupt(curt, is);
}
void nexus_int3(InterruptState *is){	/* int3-5 can be called from all */
  nexusthread_enter_interrupt(curt, is);
  if(trap_bounce_to_user(is, 3 /* BREAKPOINT */, 0)) {
    nexusthread_exit_interrupt(curt, is);
    return;
  }
  nexusthread_dump_regs_stack(nexusthread_self());
  nexusthread_exit_interrupt(curt, is);
}
void nexus_overflow(InterruptState *is){
  nexusthread_enter_interrupt(curt, is);
  printk_current("NEXUS: overflow\n");
  nexuspanic();
  nexusthread_exit_interrupt(curt, is);
}
void nexus_bounds(InterruptState *is){
  nexusthread_enter_interrupt(curt, is);
  disable_intr();
  printk_current("BOUND ERROR\n");
  printk_current("eax=0x%x ebx=0x%x", is->eax, is->ebx);
  printk_current("ecx=0x%x edx=0x%x\n", is->ecx, is->edx);
  printk_current("esi=0x%x edi=0x%x", is->esi, is->edi);
  printk_current("ebp=0x%x esp=0x%x\n", is->ebp, is->esp);
  printk_current("ds=0x%x es=0x%x ss=0x%x eflags=0x%x\n", is->ds, is->es, is->ss, is->eflags);

  printk_current("cs=0x%x sp=0x%x pc=0x%x\n", is->cs, is->esp, is->eip);

  dump_stack();
  nexuspanic();
  nexusthread_exit_interrupt(curt, is);
}
void nexus_invalid_op(InterruptState *is){
  nexusthread_enter_interrupt(curt, is);
  //printk("General Protection Fault\n eax=0x%x ebx=0x%x ecx=0x%x edx=0x%x \n esi=0x%x edi=0x%x ebp=0x%x esp=0x%x \n ds=0x%x es=0x%x ss=0x%x eflags=0x%x\n", 
  //	 is->eax, is->ebx, is->ecx, is->edx, is->esi, is->edi, is->ebp, is->esp, is->ds, is->es, is->ss, is->eflags);
  printk_current("cr4 = 0x%x\n", readcr4());

  printk_current("Invalid Opcode Exception\n");
  printk_current("eax=0x%x ebx=0x%x", is->eax, is->ebx);
  printk_current("ecx=0x%x edx=0x%x\n", is->ecx, is->edx);
  printk_current("esi=0x%x edi=0x%x", is->esi, is->edi);
  printk_current("ebp=0x%x esp=0x%x\n", is->ebp, is->esp);
  printk_current("ds=0x%x es=0x%x ss=0x%x eflags=0x%x\n", is->ds, is->es, is->ss, is->eflags);

  printk_current("cs=%x sp=0x%x pc=0x%x\n", is->cs, is->esp, is->eip);

  dump_stack();
  disable_intr();
  nexuspanic();
  nexusthread_exit_interrupt(curt, is);
}
void nexus_device_not_available(InterruptState *is){
  nexusthread_enter_interrupt(curt, is);
  if(!TS_FPU_SWITCH) {
    printk_current("NEXUS: device_not_available\n");
    nexuspanic();
  } else {
    nexusthread_fpu_trap();
  }
  nexusthread_exit_interrupt(curt, is);
}
void nexus_double_fault(InterruptState *is){
  nexusthread_enter_interrupt(curt, is);
  printk_current("NEXUS: double_fault\n");
  nexuspanic();
  nexusthread_exit_interrupt(curt, is);
}
void nexus_coprocessor_segment_overrun(InterruptState *is){
  nexusthread_enter_interrupt(curt, is);
  printk_current("NEXUS: coprocessor_segment_overrun\n");
  nexuspanic();
  nexusthread_exit_interrupt(curt, is);
}
void nexus_invalid_TSS(InterruptState *is){
  nexusthread_enter_interrupt(curt, is);
  printk_current("NEXUS: invalid_TSS\n");
  nexuspanic();
  nexusthread_exit_interrupt(curt, is);
}
void nexus_segment_not_present(InterruptState *is){
  nexusthread_enter_interrupt(curt, is);
  printk_current("NEXUS: segment_not_present\n");
  nexuspanic();
  nexusthread_exit_interrupt(curt, is);
}
void nexus_stack_segment(InterruptState *is){
  nexusthread_enter_interrupt(curt, is);
  printk_current("NEXUS: stack_segment\n");
  nexuspanic();
  nexusthread_exit_interrupt(curt, is);
}

int trap_bounce_to_user(InterruptState *is, int idx, unsigned int vaddr) {
  unsigned int usertrap;
  IPD *ipd;
  
  ipd = nexusthread_current_ipd();
  if (!ipd) {
	  printk_red("trap_bounce_to_user(eip=%p vaddr=%p)", (void *)is->eip, (void*)vaddr);
	  printk_red("can't trap to userspace: there is no current ipd\n");
	  return 0;
  }

  usertrap = ipd_get_trap(ipd, idx);
  if (!usertrap) {
    printk_red("no user trap handler (ipd=%d thr=%d idx=%d)\n", ipd ? ipd->id : -1, 
	       nexusuthread_current() ? nexusuthread_current()->id : -1, idx);
    return 0;
  }

  /* push values onto user stack */
  __u32 esp = is->esp;
  
#define PUSH(X) do {							\
  esp -= sizeof(__u32);							\
  if(poke_user(nexusthread_current_map(), (__u32)esp, &X,		\
	       sizeof(__u32)) != 0) {					\
    printk_red("exception in handling trap_bounce_to_user (esp=%p, vaddr=%p)\n", \
	       (void *)esp, (void *)vaddr);				\
    dump_regs_is(is);							\
    dump_user_stack(is);						\
    return 0;								\
  }									\
} while(0)

  // use pseudo-hardware-trap style handling
  // Stack layout is:
  //	eflags
  //	cs
  //	exception_eip
  //	[errcode]

  PUSH(is->eflags);
  PUSH(is->cs); 
  PUSH(is->eip);
  int errcode = is->errorcode;
  if (idx == 8 || (10 <= idx && idx <= 14)) {
    PUSH(errcode);
  }

  is->esp = esp;
  is->eip = usertrap;
  return 1;
}

static inline int kernel_text_address(unsigned long addr)
{
        return (addr >= (unsigned long) &_stext &&
                addr <= (unsigned long) &_etext);
}

void nexus_gpf(InterruptState *is){
  nexusthread_enter_interrupt(curt, is);

  if(kernel_text_address(is->eip)) {
    printk_current("General Protection Fault ipd = %d thread = %d\n",
		   nexusthread_current_ipd() != NULL ? nexusthread_current_base_ipd()->id : 0,
		   nexusthread_self() != NULL ? nexusthread_id(nexusthread_self()) : -1);
    dump_regs_is(is);
    disable_intr();
    printk_current("GPF was in kernel\n");
    nexuspanic();
  } else {
    if (trap_bounce_to_user(is, 13 /* GENERAL PROTECTION VIOLATION */ , 0xdeadbeef)) { // kwalsh: why not a real address?
      nexusthread_exit_interrupt(curt, is);
      return;
    }
 
    // kill process
    printk_current("Segfault in process %d\n", nexusthread_current_ipd() ? 
		   nexusthread_current_ipd()->id : -1);
    ipd_killall(((UThread *) curt)->ipd);
    nexusthread_kill_helper(curt);
  }
}

int last_stack_depth;

void nexus_pfault(InterruptState *is){

  nexusthread_enter_interrupt(curt, is);
  unsigned char *op;
  int i;
#if 0
    struct x86_emulate_ctxt x86ctxt;
    struct x86_emulate_ops emuops;
    x86ctxt.regs = (struct cpu_user_regs_disas *)is;
    x86ctxt.mode = X86EMUL_MODE_PROT32;
    emuops.read = kernel_log_region_read;
    emuops.write = kernel_log_region_write;
    emuops.insn_fetch = x86_emulate_insn_fetch_default;
    emuops.cmpxchg = x86_emulate_cmpxchg_default;
    emuops.cmpxchg8b = x86_emulate_cmpxchg8b_default;
    if(x86_emulate_memop(&x86ctxt, &emuops) == X86EMUL_CONTINUE){
      nexusthread_exit_interrupt(curt, is);
      return;
    }
#endif

  /* Check U/S bit */
  // is->eip check verifies that the pfault occured in Nexus, rather than Xen
  if (!(is->errorcode & 0x4) && is->eip >= NEXUS_START) { 

    // Check exception table
    ExceptionHandler handler;
    
    handler = search_nexus_exception_table(is->eip);
    if (handler) {
      is->eip = (unsigned) handler;
      nexusthread_exit_interrupt(curt, is);
      return;
    }

    goto out;
  }

  if (trap_bounce_to_user(is, 14 /* PAGE FAULT */, readcr2())) {
    nexusthread_exit_interrupt(curt, is);
    return;
  }


 out:;

  if (kernel_text_address(is->eip)) {
    static int pfault_entry_count = 0;

    if (pfault_entry_count++ > 0) {
      // only allow one kernel page fault
      nexuspanic();
    }
  }
  suppress_peek_user_error = 1;
  print_peek_user_count = 1;

  unsigned int vaddr = readcr2();

  printk_current("Pagefault in process=%d (%s) thread=%d cs=0x%x ds=0x%x sp=0x%x pc=0x%x vaddr=0x%x\n", 
		 nexusthread_current_base_ipd() != NULL ? nexusthread_current_base_ipd()->id : 0, 
		 nexusthread_current_base_ipd() != NULL ? nexusthread_current_base_ipd()->name : "kernel", 
		 nexusthread_self() != NULL ? nexusthread_id(nexusthread_self()) : -1,
		 is->cs, is->ds, is->esp, is->eip, vaddr);
  dump_regs_is(is);
  printk_current("errorcode 0x%x fault caused by ", is->errorcode);

  printk_current("IS: %p, &eip: %p, %d\n", is, &is->eip, is->eip);
  printk_current("eip=0x%x at eip: ", is->eip);

  if(0) {
#define OPLEN (10)
    char op_temp[OPLEN];
    if(peek_user(nexusthread_current_map(), is->eip, op_temp, OPLEN)) {
      printk_current("error while copying from user\n");
    } else {
      op = op_temp;
      for(i = 0; i < OPLEN; i++)
	printk_current("0x%x ", *(op+i));
      printk_current("\n");
    }
    //nexusdumplog();
  }

  // dump_stack();
  if(kernel_text_address(is->eip)) {
//    printk_current("Page fault in kernel, TSS.esp0 = %p\n", nexustss->esp0);
    dump_stack();
    printk_red("trap esp");
    nexusthread_dump_regs_stack(nexusthread_self());
    nexuspanic();
  } else {
    dump_user_stack(is);
//  printk_current("Page fault in user (eip=%p), exiting process\n", 
//		    (void *)is->eip);
//    printk_current("in interrupt %d\n", nexusthread_in_interrupt(nexusthread_self()));

    suppress_peek_user_error = 0;
    nexusthread_kill_helper(curt);
    // should not reach this point
    nexuspanic();
  }

  suppress_peek_user_error = 0;
  nexusthread_exit_interrupt(curt, is);
  return;

}
void nexus_spurious_interrupt_bug(InterruptState *is){
  nexusthread_enter_interrupt(curt, is);
  printk_current("NEXUS: spurious_interrupt_bug\n");
  nexuspanic();
  nexusthread_exit_interrupt(curt, is);
}
void nexus_coprocessor_error(InterruptState *is){
  nexusthread_enter_interrupt(curt, is);
  printk_current("NEXUS: coprocessor_error\n");
  nexuspanic();
  nexusthread_exit_interrupt(curt, is);
}
void nexus_alignment_check(InterruptState *is){
  nexusthread_enter_interrupt(curt, is);
  printk_current("NEXUS: alignment_check\n");
  nexuspanic();
  nexusthread_exit_interrupt(curt, is);
}
void nexus_machine_check(InterruptState *is){
  nexusthread_enter_interrupt(curt, is);
  printk_current("NEXUS: machine_check\n");
  nexuspanic();
  nexusthread_exit_interrupt(curt, is);
}
void nexus_simd_coprocessor_error(InterruptState *is){
  nexusthread_enter_interrupt(curt, is);
  printk_current("NEXUS: simd_coprocessor_error\n");
  nexuspanic();
  nexusthread_exit_interrupt(curt, is);
}

static int preempt_nest_count = 0;

int irq_count[NUM_IRQS];

void nexus_irq(InterruptState *is){
  nexusthread_enter_interrupt(curt, is);

  int irq = is->errorcode & 0xff;
  if(irq < NUM_IRQS) {
    irq_count[irq]++;
  }
  
  int spurious = mask_and_ack_8259A(irq);
  if(in_panic && irq != 0x1) {
    // All IRQs other than keyboard are "spurious" (e.g. ignored) within a panic
    spurious = 1;
  }
  if (spurious) {
	  nexusthread_exit_interrupt(curt, is);
	  return;
  }

  int preempt_any = 0;
  if (irq == 0){
    preempt_any = nexus_timer(is);
    enable_8259A_irq(irq); 
  }else{
    preempt_any = deliver_irq(irq);
    /* device irqs are re-enabled from the dispatched top-halves */
  }

  if (preemption_enabled && preemption_mask && preempt_any) {
	preempt_nest_count++;
	nexusthread_yield_i();
	preempt_nest_count--;
  }
  assert(check_intr() == 0);
  nexusthread_exit_interrupt(curt, is);
}

// The trap handlers below are based on special-case handlers from Xen

asmlinkage void nexus_check_debug_intr(InterruptState *is)
{
  unsigned condition;
    __asm__ __volatile__("movl %%db6,%0" : "=r" (condition));

#ifdef __NEXUSXEN__
    if(inXenDomain()) {
      do_xen_debug(is, condition);
    } else 
#endif
    {
      nexus_debug_intr(is);
    }
}

// Int 2
asmlinkage void nexus_check_nmi(InterruptState *is) {
  printk("Got NMI\n");
  return;
}

// Int 3
asmlinkage void nexus_check_int3(InterruptState *is) {
#ifdef __NEXUSXEN__
    if(inXenDomain()) {
      do_xen_int3(is);
    } else 
#endif
    {
      nexus_int3(is);
    }
}

// Int 6: Invalid operand
asmlinkage void nexus_check_invalid_op(InterruptState *is) {
#ifdef __NEXUSXEN__
    if(inXenDomain()) {
      do_xen_invalid_op(is);
    } else 
#endif
    {
      nexus_invalid_op(is);
    }
}

// Int 7, Processor extension not available. 
// Triggered, for instance, by mplayer when it tries probes for CPU features
asmlinkage void nexus_check_device_not_available(InterruptState *is) {
#ifdef __NEXUSXEN__
  if(inXenDomain()) {
    do_xen_nm(is);
  } else 
#endif
  {
    nexus_device_not_available(is);
  }
}

// Int 8
asmlinkage void nexus_check_double_fault(InterruptState *is) {
  nexus_double_fault(is);
}

// Int 13
asmlinkage void nexus_check_gpf(InterruptState *is) {
#ifdef __NEXUSXEN__
  if(inXenDomain()) {
    do_xen_gpf(is);
  } else
#endif
  {
    nexus_gpf(is);
  }
}

// Int 14
asmlinkage void nexus_check_pfault(InterruptState *is) {
#ifdef __NEXUSXEN__
    if(inXenDomain() && is->eip < NEXUS_START) {
      if(0) {
	printk_red("not forwarding xen pfault to xen, is = %p\n", is);
	static int limit = 0;
	if(0 &&  limit++ > 2) {
	  printk_red("looping\n");
	  while(1);
	}
	goto nexus_pfault;
      }
      do_xen_pfault(is);
    } else {
    nexus_pfault:
#endif
      nexus_pfault(is);
#ifdef __NEXUSXEN__
    }
#endif
}

// Int 15
asmlinkage void nexus_check_spurious_interrupt_bug(InterruptState *is) {
#ifdef __NEXUSXEN__
    if(inXenDomain()) {
      // suppress
      return;
    } else 
#endif
    {
      nexus_spurious_interrupt_bug(is);
    }
}

enum TrapType {
  NEXUS,
  GUEST,
  IGNORE
};
static inline enum TrapType classify_trap(int number, const char *str, InterruptState *is, int error_code) {
#ifdef __NEXUSXEN__
  // Return 1 if needs to be handled by Nexus
  if(inXenDomain()) {
    if((is->cs & 3) == 0) {
      return NEXUS;
    }
    return GUEST;
  } else 
#endif
  {
    printk_red("ignoring trap %d (%s)\n", number, str);
    printk_current("errorcode 0x%x fault caused by ", is->errorcode);
    printk_current("IS: %p, &eip: %p, %d\n", is, &is->eip, is->eip);
    printk_current("eip=0x%x at eip: ", is->eip);
    // dump_regs_is(is);
    nexusthread_self()->trap_is = is;
    nexusthread_dump_regs_stack(nexusthread_self());
    nexusthread_self()->trap_is = NULL;
    // dump_stack();
	//nexuspanic();
    while(1) ;
    return IGNORE;
  }
}

// disables the xen option in the next macros if Xen is not compiled in.
#ifndef __NEXUSXEN__
#define pass_to_cpl1_trap(...)
#endif

// Code is based on Xen
#define DO_ERROR_NOCODE(NR, STR, NAME)				\
  asmlinkage void nexus_check_##NAME(InterruptState *is) {	\
    switch(classify_trap(NR,STR,is,0)) {				\
    case NEXUS: nexus_##NAME(is); break;				\
    case GUEST: pass_to_cpl1_trap(NR,0,NONE,STR,is); break;			\
    case IGNORE: break;							\
    }								\
  }

#define DO_ERROR(NR, STR, NAME)					\
  asmlinkage void nexus_check_##NAME(InterruptState *is) {	\
    switch(classify_trap(NR,STR,is,1)) {				\
    case NEXUS: nexus_##NAME(is); break;				\
    case GUEST: pass_to_cpl1_trap(NR,1,NONE,STR,is); break;			\
    case IGNORE: break;							\
    }								\
  }

DO_ERROR_NOCODE( 0, "divide error", divide_error);
// 1: debug
// 2: nmi
// 3: int3
DO_ERROR_NOCODE( 4, "overflow", overflow);
DO_ERROR_NOCODE( 5, "bounds", bounds);
// DO_ERROR_NOCODE( 6, "invalid operand", invalid_op);
// 7: device not available
// 8: double fault
DO_ERROR_NOCODE( 9, "coprocessor segment overrun", coprocessor_segment_overrun);
DO_ERROR(10, "invalid TSS", invalid_TSS);
DO_ERROR(11, "segment not present", segment_not_present);
DO_ERROR(12, "stack segment", stack_segment);
// 13: GPF
// 14: page fault
// 15: spurious
DO_ERROR_NOCODE(16, "fpu error", coprocessor_error);
DO_ERROR(17, "alignment check", alignment_check);
DO_ERROR(18, "machine check", machine_check);
DO_ERROR_NOCODE(19, "simd error", simd_coprocessor_error);

