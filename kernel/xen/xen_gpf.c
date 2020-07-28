#include <nexus/defs.h>
#include <asm/system.h>
#include <asm/processor.h>
#include <nexus/thread.h>
#include <nexus/thread-inline.h>
#include <nexus/xen-defs.h>
#include <nexus/x86_emulate.h>
#include <nexus/machineprimitives.h>

#include <linux/smp.h>

int dbg_resume = 0;
int g_num_seg_fixups;

int x86_emulate_insn_fetch_copy_from_user(enum x86_segment seg,
					  unsigned long offset,
					  unsigned long *val,
					  unsigned int bytes,
					  struct x86_emulate_ctxt *ctxt){
  SegmentDescriptor desc;
  if(Descriptor_from_Selector(Selector_from_u32(ctxt->regs->cs), &desc) < 0) {
    // this code should not be reached
    printk_red("%s:%d: invalid CS %x in insn fetch_copy_from_user???!\n",
	       __FILE__, __LINE__, ctxt->regs->cs);
    nexuspanic();
  }

  int err = 0;
  assert(desc.dpl >= 1);
  unsigned long base = SegmentDescriptor_get_base32(desc, &err);
  if(err != 0) {
    printk_red("%s:%d: Could not get seg base!\n", __FILE__, __LINE__);
    return X86EMUL_UNHANDLEABLE;
  }
  unsigned long limit = SegmentDescriptor_get_limit32(desc, &err);
  if(err != 0) {
    printk_red("%s:%d: Could not get seg limit!\n", __FILE__, __LINE__);
    return X86EMUL_UNHANDLEABLE;
  }

  if(base != 0) {
    // XXX This will change the first time we get a guest that has CS.base != 0
    printk_red("%s:%d: doesn't handle non-zero descriptor base\n",
	       __FILE__, __LINE__);
    return X86EMUL_UNHANDLEABLE;
  }
  // These error checks don't change
  unsigned long linear = base + offset;
  if(linear + bytes < linear) {
    printk_red("%s:%d: fetch wraparound\n", __FILE__, __LINE__);
    return X86EMUL_UNHANDLEABLE;
  }
  // XXX is limit exclusive?
  if(linear + bytes > base + limit) {
    printk_red("%s:%d: over limit\n", __FILE__, __LINE__);
    return X86EMUL_UNHANDLEABLE;
  }

  Map *map = nexusthread_current_map();

  int ret = peek_user(map, linear, val, bytes);
  if(ret < 0){
    printk_red("peek_user failed %s:%d\n", __FILE__, __LINE__);
    return X86EMUL_UNHANDLEABLE;
  }

  return X86EMUL_CONTINUE;
}


/* interface with the xen dissasembler */
int xen_gpf_segment_fixup(enum x86_segment seg,
			  unsigned long vaddr,
			  struct x86_emulate_ctxt *ctxt){
  Selector codesel = Selector_from_u32(ctxt->regs->cs);
  // Do %gs fixups for only guest userspace (CPL 2,3), that is fixups
  // will not happen for neither Xen VMM nor Xen guest OS.
  if(codesel.rpl > 1) {

    if(seg != x86_seg_gs){
	// If we ever run WINE, we'll need to put in support for PREFIX_FS
	printk_red("We only fix-up %gs override, everything else fails\n");
	return X86EMUL_UNHANDLEABLE;
    }

    unsigned long offset = vaddr;
    Selector sel = Selector_from_u32(ctxt->regs->gs);

    if(likely(xendom_fixup_seg(sel, offset) == 0)) {
      if(dbg_resume) {
	printk_red(" Resuming at %p (not advanced) ", ctxt->regs->eip);
      }
      // Have CPU re-execute instruction.  We don't detect GPF
      // livelock, but the checks inside xendom_fixup_seg() should
      // prevent it from happening
      g_num_seg_fixups++;
      return X86EMUL_CONTINUE;
    } else {
      printk_red(" unfixable segment override, offset = %p ", (void*)offset);
      return X86EMUL_UNHANDLEABLE;
    }
  }

  printk_red(" unfixable segment override, cs rpl(%d) != 2, 3\n", codesel.rpl);
  return X86EMUL_UNHANDLEABLE;
}

int xen_gpf_read(enum x86_segment seg,
		 unsigned long vaddr,
		 unsigned long *val,
		 unsigned int bytes,
		 struct x86_emulate_ctxt *ctxt){
  return xen_gpf_segment_fixup(seg, vaddr, ctxt);
}

int xen_gpf_write(enum x86_segment seg,
		  unsigned long vaddr,
		  unsigned long val,
		  unsigned int bytes,
		  struct x86_emulate_ctxt *ctxt){
  return xen_gpf_segment_fixup(seg, vaddr, ctxt);
}
int xen_gpf_cmpxchg(enum x86_segment seg,
		unsigned long offset,
		unsigned long old,
		unsigned long new,
		unsigned int bytes,
		struct x86_emulate_ctxt *ctxt){
  return xen_gpf_segment_fixup(seg, offset, ctxt);
}

int xen_gpf_cmpxchg8b(enum x86_segment seg,
		  unsigned long offset,
		  unsigned long old_lo,
		  unsigned long old_hi,
		  unsigned long new_lo,
		  unsigned long new_hi,
		  struct x86_emulate_ctxt *ctxt){
  return xen_gpf_segment_fixup(seg, offset, ctxt);
}

enum Registers{
  REG_EAX = 0x0,
  REG_ECX,
  REG_EDX,
  REG_EBX,
  REG_ESP,
  REG_EBP,
  REG_ESI,
  REG_EDI,
};

/* Decode a register into its contents */
static __u32 *regptr(InterruptState *is, unsigned char reg){
  switch(reg){
  case REG_EAX:
    return &is->eax;
  case REG_ECX:
    return &is->ecx;
  case REG_EDX:
    return &is->edx;
  case REG_EBX:
    return &is->ebx;
  case REG_ESP:
    return &is->esp;
  case REG_EBP:
    return &is->ebp;
  case REG_ESI:
    return &is->esi;
  case REG_EDI:
    return &is->edi;
  default:
    return NULL;
  }
}


#define PRIVILEGED_OP_SIZE (3)
#define PRIVILEGED_OP_IS_CRX(o)   ((o[0] == 0x0f) && \
				   ((o[1] == 0x22) || (o[1] == 0x20)) && \
				   ((o[2] & 0xc0) == 0xc0))

#define PRIVILEGED_OP_CR(o)      ((o[2] >> 3) & 0x7)
#define PRIVILEGED_OP_GPR(i,o)   (regptr(i, o[2] & 0x7))
#define PRIVILEGED_OP_DIR(o)     (o[1])

#define PRIVILEGED_OP_TO   (0x22)
#define PRIVILEGED_OP_FROM (0x20)


int emulate_privileged(InterruptState *is){
  unsigned char op[PRIVILEGED_OP_SIZE];
  Map *map = nexusthread_current_map();
  int ret;

  ret = peek_user(map, is->eip, op, PRIVILEGED_OP_SIZE);
  if(ret < 0){
    printk_red("peek_user failed %s:%d\n", __FILE__, __LINE__);
    return -1;
  }

  if(!PRIVILEGED_OP_IS_CRX(op)){
    printk_red("%s:%d op is not CRX!!\n 0x%02x 0x%02x 0x%02x\n", __FILE__, __LINE__, op[0], op[1], op[2]);
    return -1;
  }

  // The only type supported right now is OT_MOVCRX

  unsigned int cr = PRIVILEGED_OP_CR(op);
  unsigned int *gpr = PRIVILEGED_OP_GPR(is, op);
  unsigned int direction = PRIVILEGED_OP_DIR(op);
  
  switch(cr){
  case 0: {
    if(direction == PRIVILEGED_OP_TO) {
      // Copied from Xen
      __u32 new_val = *gpr;
      if ( (new_val ^ read_cr0()) & ~X86_CR0_TS ) {
	printk_red("Attempt to change unmodifiable CR0 flags.\n");
	goto unsupported;
      }
      xendom_fpu_taskswitch(new_val & X86_CR0_TS);
    } else {
      __u32 cr0_val = read_cr0();
      printk_red("(cr0=%p)", (void *)cr0_val);
      *gpr = cr0_val;
    }
    break;
  }
  case 3:
    if(direction == PRIVILEGED_OP_TO) {
      printk_red("Guest attempted to change CR3!\n");
      goto unsupported;
    } else {
      Map *map = nexusthread_current_map();
      // XXX might need xen_pfn_to_cr3
      __u32 cr3_val = PADDR(Map_getRoot(map));
      printk_red("(cr3=%p)", (void *)cr3_val);
      // printk_red("looping"); while(1);
      *gpr = cr3_val;
    }
    break;
  case 4: // Features register
    if(direction == PRIVILEGED_OP_TO) {
      // Xen disallows any change to cr4
      if( *gpr != (read_cr4() & ~(X86_CR4_PGE|X86_CR4_PSE)) ) {
	printk_red("Guest attempted to change CR4!\n");
	goto unsupported;
      }
    } else {
      // FROM
      // Xen does not export global or large pages to guests
      *gpr = read_cr4() & ~(X86_CR4_PGE|X86_CR4_PSE);
    }
    break;
  default:
    printk_red("Unsupported CR %d at %p\n", cr, (void *)is->eip);
    printk_red("looping"); while(1);
    goto unsupported;
  }

  is->eip += PRIVILEGED_OP_SIZE;

  return 0;

 unsupported:
  return -1;
}

void do_xen_gpf(InterruptState *is) {
  /* This function based heavily on equiv function in Xen */
  // struct UThread *ut = (struct UThread *)nexusthread_self();
  // #GP handling requires checking for handled kernel exceptions (NOT
  // IMPLEMENTED), and INT # instructions (which are virtualized)
  // printk_green("!!!");
  
  if ( is->errorcode & 1 )
    goto hardware_gp;

  if ( !GUEST_FAULT(is) ) {
    printk("gp in kernel\n");
    goto gp_in_kernel;
  }

  Selector codesel = Selector_from_u32(is->cs);

  if(codesel.rpl == 1){
    /* only do emulate_priv. on GPF for RPL 1 */
    if(emulate_privileged(is) >= 0){
      // emulate_privileged() runs the instruction. We want to keep
      // the changes to the CPU state
      goto emulated_privileged;
    }
    // fall through to mem emulation on error
    printk_green("EMUL failed, try patch\n");
  }

  InterruptState is_scratch = *is;

  /* We rerun the instruction after fixing the segment descriptor, so
     we operate only on a shadow of the state. On return, the
     instruction will be retried. */
  struct x86_emulate_ctxt x86ctxt;
  struct x86_emulate_ops emuops;
  x86ctxt.regs = (struct cpu_user_regs_disas *)&is_scratch;
  x86ctxt.mode = X86EMUL_MODE_PROT32;
  emuops.read = xen_gpf_read;
  emuops.write = xen_gpf_write;
  // can't use default, since we need to protect ourselves against faults
  emuops.insn_fetch = x86_emulate_insn_fetch_copy_from_user;
  emuops.cmpxchg = xen_gpf_cmpxchg;
  emuops.cmpxchg8b = xen_gpf_cmpxchg8b;
  if(x86_emulate_memop(&x86ctxt, &emuops) < 0){
    printk_red("emulate memop failed\n");
    goto pass_to_cpl1;
  }

 emulated_privileged:
  return;

 pass_to_cpl1:
  if(1) {
    printk_red("Eip: ");
    int i;
    for(i=0; i < 10; i++) {
      printk_current("%02x ", ((unsigned char *)is->eip)[i]);
    }
    dump_regs_is(is);
    if(0) { // Freeze guest, or pass up gpf?
      nexusthread_self()->trap_is = is;
      nexusthread_dump_regs_stack(nexusthread_self());
      if(0){
	printk_red("looping");
	while(1);
      }
    }
  }

  // No fixup, pass to userspace
  pass_to_cpl1_trap(13, 1, NONE,"gpf",is);
  ASSERTNOTREACHED();

 gp_in_kernel:
  // For now, no #GP fixups in kernel
  printk_red("unhandled kernel #GP\n");

 hardware_gp:
  printk_red("Nexus -- CPU%d GENERAL PROTECTION FAULT\n[error_code=%04x]\n",
	     smp_processor_id(), is->errorcode);
  dump_regs_is(is);
  nexuspanic();
  return;
}


