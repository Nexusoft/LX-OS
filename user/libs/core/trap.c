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

static int (*callback_read)(enum x86_segment, unsigned long, unsigned long *, 
		            unsigned int, struct x86_emulate_ctxt *);
static int (*callback_write)(enum x86_segment, unsigned long, unsigned long, 
		             unsigned int, struct x86_emulate_ctxt *);
static int (*callback_cmpxchg)(enum x86_segment, unsigned long, unsigned long, 
	 	               unsigned long, unsigned int, 
			       struct x86_emulate_ctxt *);
static void (*callback_enter)(struct x86_emulate_ctxt *);

static int 
demux_read(enum x86_segment seg, unsigned long vaddr, unsigned long *val, 
	   unsigned int bytes, struct x86_emulate_ctxt *ctxt) 
{
	if (!callback_read) {
		fprintf(stderr, "BUG: read trap handler missing\n");
		abort();
	}

	return callback_read(seg, vaddr, val, bytes, ctxt);
}

static int 
demux_write(enum x86_segment seg, unsigned long vaddr, unsigned long val, 
	    unsigned int bytes, struct x86_emulate_ctxt *ctxt) 
{
	if (!callback_write) {
		fprintf(stderr, "BUG: write trap handler missing\n");
		abort();
	}

	return callback_write(seg, vaddr, val, bytes, ctxt);
}

static int 
demux_cmpxchg(enum x86_segment seg, unsigned long offset, unsigned long old, 
	      unsigned long new, unsigned int bytes, 
	      struct x86_emulate_ctxt *ctxt)
{
	if (!callback_cmpxchg) {
		fprintf(stderr, "BUG: cmpxchg trap handler missing\n");
		abort();
	}
	return callback_cmpxchg(seg, offset, old, new, bytes, ctxt);
}

static void
demux_enter(struct x86_emulate_ctxt *ctxt)
{
	if (callback_enter) 
		callback_enter(ctxt);
}

void 
register_pf_handler_enter(void (*func)(struct x86_emulate_ctxt *ctxt)) 
{
  callback_enter = func;
}

void 
register_pf_handler_read(int (*func)(enum x86_segment seg,
					   unsigned long vaddr,
					   unsigned long *val,
					   unsigned int bytes,
					   struct x86_emulate_ctxt *ctxt)){
  callback_read = func;
}

void 
register_pf_handler_write(int (*func)(enum x86_segment seg,
					   unsigned long vaddr,
					   unsigned long val,
					   unsigned int bytes,
					   struct x86_emulate_ctxt *ctxt)){
  callback_write = func;
}

void 
register_pf_handler_cmpxchg(int (*func)(enum x86_segment seg,
					     unsigned long offset,
					     unsigned long old,
					     unsigned long new,
					     unsigned int bytes,
					     struct x86_emulate_ctxt *ctxt)){
  callback_cmpxchg = func;
}

/* Emulate the faulting op using the installed handler.  If no handler
   is specified, dump info and exit. */
void 
pagefault_handler(InterruptState *is)
{
  struct x86_emulate_ctxt x86ctxt;
  struct x86_emulate_ops emuops;

  // Do NOT print anything, or use any TLS, until the
  // x86_emulate_enter_ptr() is called. That will break Xen.

  // translate state to emulator
  x86ctxt.regs = 	(struct cpu_user_regs_disas *) is;
  x86ctxt.mode = 	X86EMUL_MODE_PROT32;

  // set callbacks from emulator
  emuops.read = 	demux_read;
  emuops.write = 	demux_write;
  emuops.cmpxchg = 	demux_cmpxchg;
  emuops.cmpxchg8b = 	x86_emulate_cmpxchg8b_default;
  emuops.insn_fetch = 	x86_emulate_insn_fetch_default;

  demux_enter(&x86ctxt);
  
  // emulate the pagefault causing operation:
  // learn the opcode and call the registered callback
  if (x86_emulate_memop(&x86ctxt, &emuops) != X86EMUL_CONTINUE) {
      fprintf(stderr, "[trap] memop not handled\n");
      abort();
  }
}

