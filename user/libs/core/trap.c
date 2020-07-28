/** Nexus OS: configure the pagefault handler

    Used by userspace device drivers and Xen
  */
#include <stdio.h>
#include <stdlib.h>
#include <nexus/x86_emulate.h>
#include <nexus/machine-structs.h>
#include <nexus/Thread.interface.h>
#include <nexus/util.h>

#include <x86_emulate-code.c>

extern void *next_pf_handler;

extern void empty_pf_handler(struct InterruptState *regs);
extern void pf_handler(struct InterruptState *regs);
static int installed = 0;
static void *replaced_pf_handler;

static void init(void) {
  if (installed) return;
  replaced_pf_handler = (void*)Thread_RegisterTrap(14 /* PAGE FAULT */, pf_handler);
  installed = 1;
}

void x86_emulate_enter_default(struct x86_emulate_ctxt *ctxt) {
  // do nothing
}

/* the default emulation hooks always fail */
static int (*x86_emulate_write_ptr)(enum x86_segment seg,
				    unsigned long vaddr,
				    unsigned long val,
				    unsigned int bytes,
				    struct x86_emulate_ctxt *ctxt) 
  = &x86_emulate_write_default;
static int (*x86_emulate_read_ptr)(enum x86_segment seg,
				   unsigned long vaddr,
				   unsigned long *val,
				   unsigned int bytes,
				   struct x86_emulate_ctxt *ctxt) 
  = &x86_emulate_read_default;

static int (*x86_emulate_cmpxchg_ptr)(enum x86_segment seg,
				      unsigned long offset,
				      unsigned long old,
				      unsigned long new,
				      unsigned int bytes,
				      struct x86_emulate_ctxt *ctxt)
  = &x86_emulate_cmpxchg_default;



static void (*x86_emulate_enter_ptr)(struct x86_emulate_ctxt *ctxt)
  = x86_emulate_enter_default;



void register_pf_handler_enter(void (*func)(struct x86_emulate_ctxt *ctxt)) {
  init();
  x86_emulate_enter_ptr = func;
}

/* A user app can install a hook for the memory functions */
void register_pf_handler_read(int (*func)(enum x86_segment seg,
					   unsigned long vaddr,
					   unsigned long *val,
					   unsigned int bytes,
					   struct x86_emulate_ctxt *ctxt)){
  init();
  x86_emulate_read_ptr = func;
}

void register_pf_handler_write(int (*func)(enum x86_segment seg,
					   unsigned long vaddr,
					   unsigned long val,
					   unsigned int bytes,
					   struct x86_emulate_ctxt *ctxt)){
  init();
  x86_emulate_write_ptr = func;
}

void register_pf_handler_cmpxchg(int (*func)(enum x86_segment seg,
					     unsigned long offset,
					     unsigned long old,
					     unsigned long new,
					     unsigned int bytes,
					     struct x86_emulate_ctxt *ctxt)){
  init();
  x86_emulate_cmpxchg_ptr = func;
}



void dump_regs_is(InterruptState *is) {
  printf("eax=0x%x ebx=0x%x ", is->eax, is->ebx);
  printf("ecx=0x%x edx=0x%x\n", is->ecx, is->edx);
  printf("esi=0x%x edi=0x%x ", is->esi, is->edi);
  printf("ebp=0x%x esp=0x%x\n", is->ebp, is->esp);
  printf("ds=0x%x es=0x%x ss=0x%x fs=0x%x gs=0x%x eflags=0x%x\n", is->ds, is->es, is->ss, is->fs, is->gs, is->eflags);

  printf("cs=%x sp=0x%x pc=0x%x errorcode=0x%x entry_vector=%d\n", is->cs, is->esp, is->eip, is->errorcode, is->entry_vector);
}

/* Emulate the faulting op using the installed handler.  If no handler
   is specified, dump info and exit. */
void pf_handler_c(InterruptState *is){
  // Do NOT print anything, or use any TLS, until the
  // x86_emulate_enter_ptr() is called. That will break Xen.

  struct x86_emulate_ctxt x86ctxt;
  struct x86_emulate_ops emuops;
  x86ctxt.regs = (struct cpu_user_regs_disas *)is;
  x86ctxt.mode = X86EMUL_MODE_PROT32;
  emuops.read = x86_emulate_read_ptr;
  emuops.write = x86_emulate_write_ptr;
  emuops.insn_fetch = x86_emulate_insn_fetch_default;
  emuops.cmpxchg = x86_emulate_cmpxchg_ptr;
  emuops.cmpxchg8b = x86_emulate_cmpxchg8b_default;

  // 8/13/07 This hook is currently used to do TLS setup in Xen.
  x86_emulate_enter_ptr(&x86ctxt);
  if(x86_emulate_memop(&x86ctxt, &emuops) != X86EMUL_CONTINUE){
    if (replaced_pf_handler) {
      // already was some handler installed in kernel... try that one next
      next_pf_handler = replaced_pf_handler;
      return;
    } else {
      // no other handlers... just die
      printf("page fault: memop not handled\n");
      dump_stack_trace((unsigned int *)is->ebp);
      dump_regs_is(is);  
      exit(-1);
    }
  }
  next_pf_handler = empty_pf_handler; // trap was handled; do nothing more
}



