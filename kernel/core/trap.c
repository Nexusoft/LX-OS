/** NexusOS: x86 trap handling */

#include <nexus/defs.h>
#include <nexus/machine-structs.h>
#include <nexus/machineprimitives.h>
#include <nexus/clock.h>
#include <nexus/synch.h>
#include <nexus/synch-inline.h>
#include <nexus/thread.h>
#include <nexus/queue.h>
#include <nexus/device.h>
#include <nexus/rdtsc.h>
#include <nexus/ipd.h>
#include <asm/hw_irq.h>
#include <nexus/thread-private.h>

////////  support functions  ////////

typedef int (*ExceptionHandler)(void);

/** Kill process and print trace */
static void 
segfault(InterruptState *is)
{
  if (curt->ipd && !swap(&curt->ipd->segfaulted, 1)) {
	  if (curt->name)
	 	 printk_red("\n[%s.%s] segfault\n", curt->ipd->name, curt->name);
	  else
	 	 printk_red("\n[%s.%d] segfault\n", curt->ipd->name, curt->id);
#ifndef NDEBUG
	  printk_red("         syscall=%d linuxcall=%d debugval=%d\n", 
			  curt->syscall_is ? (int) curt->syscall_is->eax : 0,
			  curt->linuxcall, curt->debugval);
#endif
	  dump_stack_current(is);
	  if (curt->ipd != kernelIPD)
  	  	ipd_kill_noint(curt->ipd);
  }
}

#ifdef __NEXUSXEN__
void 
kill_current_domain(void) 
{
  printk_red("[%d] kill XEN domain\n");
  ipd_kill(curt->ipd);
}
#endif

/** Lookup process specific trap handler. 
    @return 1 if found, 0 if not. */
int 
trap_bounce_to_user(InterruptState *is, int idx) 
{
  unsigned int usertrap;
  
  if (!curt || curt->type != USERTHREAD)
    return 0;
  
  usertrap = ipd_get_trap(curt->ipd, idx);
  if (!usertrap)
    return 0;

  /* push values onto user stack */
  __u32 esp = is->esp;
 
// XXX replace poke_user with simpler variant 
#if 0
#define PUSH(X) do {							\
  esp -= sizeof(__u32);							\
  *((u32 *) esp) = ((u32) X);
} while(0)
#else
#define PUSH(X) do {							\
  esp -= sizeof(__u32);							\
  if(poke_user(nexusthread_current_map(), (__u32)esp, &X,		\
	       sizeof(__u32)) != 0) {					\
    nexuspanic();							\
  }									\
} while(0)
#endif

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

static inline int 
kernel_text_address(unsigned long addr)
{
        return (addr >= (unsigned long) &_stext &&
                addr <= (unsigned long) &_etext);
}


////////  trap handlers  ////////

static void nxtrap_default(InterruptState *is, const char *msg)
{
  intcontext_enter();
  printk_current("[trap] %s\n", msg);
  dump_stack_current(is);
  nexuspanic();
  intcontext_exit();
}

void nexus_divide_error(InterruptState *is){
  nxtrap_default(is, "divide by zero");
}

void nexus_debug_intr(InterruptState *is){
  intcontext_enter();
  nxtrap_default(is, "NEXUS: breakpoint\n");
  intcontext_exit();
}
void nexus_nmi(InterruptState *is){
  nxtrap_default(is, "non maskable interrupt");
}
void nexus_int3(InterruptState *is){	/* int3-5 can be called from all */
  intcontext_enter();
  if(trap_bounce_to_user(is, 3 /* BREAKPOINT */)) {
    intcontext_exit();
    return;
  }
  printk_current("NEXUS: unhandled BREAK\n");
  dump_stack_current(is);
  nexuspanic();
  intcontext_exit();
}
void nexus_overflow(InterruptState *is){
  nxtrap_default(is, "overflow");
}
void nexus_bounds(InterruptState *is){
  nxtrap_default(is, "bounds");
}
void nexus_invalid_op(InterruptState *is){
  nxtrap_default(is, "invalid opcode");
}
void nexus_device_not_available(InterruptState *is){
  intcontext_enter();
  nexusthread_fpu_trap();
  intcontext_exit();
}
void nexus_double_fault(InterruptState *is){
  nxtrap_default(is, "double fault");
}
void nexus_coprocessor_segment_overrun(InterruptState *is){
  nxtrap_default(is, "coprocessor segment overrun");
}
void nexus_invalid_TSS(InterruptState *is){
  nxtrap_default(is, "invalid task state segment");
}
void nexus_segment_not_present(InterruptState *is){
  nxtrap_default(is, "segment not present");
}
void nexus_stack_segment(InterruptState *is){
  nxtrap_default(is, "stack segment");
}

void nexus_gpf(InterruptState *is) {
  intcontext_enter();
  if (!trap_bounce_to_user(is, 13 /* PFAULT */))
      segfault(is);
  intcontext_exit();
}

void nexus_pfault(InterruptState *is) {
  intcontext_enter();
  if (!trap_bounce_to_user(is, 14 /* PFAULT */))
      segfault(is);
  intcontext_exit();
}

void nexus_spurious_interrupt_bug(InterruptState *is){
  nxtrap_default(is, "spurious int");
}
void nexus_coprocessor_error(InterruptState *is){
  nxtrap_default(is, "coprocessor error");
}
void nexus_alignment_check(InterruptState *is){
  nxtrap_default(is, "alignment check exception");
}
void nexus_machine_check(InterruptState *is){
  nxtrap_default(is, "machine check exception");
}
void nexus_simd_coprocessor_error(InterruptState *is){
  nxtrap_default(is, "simd error");
}

/** Handle a hardware interrupt (IRQ)
    Note that IRQs 0x0-0xf are mapped to CPU interrupts 0x20-0x2f */
void nexus_irq(InterruptState *is) {
  intcontext_enter();
  nxirq_handle(is->errorcode & 0xff);
  intcontext_exit();
}

// The trap handlers below are based on special-case handlers from Xen

asmlinkage void nexus_check_debug_intr(InterruptState *is)
{
  unsigned condition;
    __asm__ __volatile__("movl %%db6,%0" : "=r" (condition));

#ifdef __NEXUSXEN__
    if(inXenDomain())
      do_xen_debug(is, condition);
    else 
#endif
      nexus_debug_intr(is);
}

// Int 2
asmlinkage void nexus_check_nmi(InterruptState *is) {
  printk("Got NMI\n");
  return;
}

// Int 3
asmlinkage void nexus_check_int3(InterruptState *is) {
#ifdef __NEXUSXEN__
    if(inXenDomain())
      do_xen_int3(is);
    else 
#endif
      nexus_int3(is);
}

// Int 6: Invalid operand
asmlinkage void nexus_check_invalid_op(InterruptState *is) {
#ifdef __NEXUSXEN__
    if(inXenDomain())
      do_xen_invalid_op(is);
    else 
#endif
      nexus_invalid_op(is);
}

// Int 7, Processor extension not available. 
// Triggered, for instance, by mplayer when it tries probes for CPU features
asmlinkage void nexus_check_device_not_available(InterruptState *is) {
#ifdef __NEXUSXEN__
  if(inXenDomain())
    do_xen_nm(is);
  else 
#endif
    nexus_device_not_available(is);
}

// Int 8
asmlinkage void nexus_check_double_fault(InterruptState *is) {
  nexus_double_fault(is);
}

// Int 13
asmlinkage void nexus_check_gpf(InterruptState *is) {
#ifdef __NEXUSXEN__
  if(inXenDomain())
    do_xen_gpf(is);
  else
#endif
    nexus_gpf(is);
}

// Int 14
asmlinkage void nexus_check_pfault(InterruptState *is) {
#ifdef __NEXUSXEN__
    if (inXenDomain() && is->eip < NEXUS_START)
      do_xen_pfault(is);
    else 
#endif
      nexus_pfault(is);
}

// Int 15
asmlinkage void nexus_check_spurious_interrupt_bug(InterruptState *is) {
#ifdef __NEXUSXEN__
    if(inXenDomain())
      // suppress
      return;
    else 
#endif
      nexus_spurious_interrupt_bug(is);
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
    if((is->cs & 3) == 0)
      return NEXUS;
    else
      return GUEST;
  } else 
#endif
  {
    printk_red("ignoring trap %d (%s)\n", number, str);
    nexuspanic();
    return -1; // not reached
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

