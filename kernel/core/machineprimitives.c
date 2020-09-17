/*
 *
 * This file implements some basic primitives, e.g. for manipulating stacks,
 * and performing atomic operations, to be used by the threads package, 
 * scheduler, and semaphore implementations.
 *
 */
#include <nexus/defs.h>
#include <nexus/machineprimitives.h>
#include <nexus/mem.h>
#include <nexus/mem-private.h>
#include <asm/mc146818rtc.h>
#include <nexus/thread.h>
#include <nexus/thread-inline.h>
#include <nexus/ipd.h>
#include <nexus/idtgdt.h>

#include <nexus/syscall-asm.h>
#include <nexus/syscalls.h>

#define PRINT printk_red
#undef PRINT

#include <nexus/ksymbols.h>

#define STACKSIZE_PAGES (4)
#define STACKSIZE               (STACKSIZE_PAGES << PAGE_SHIFT)
#define STACKALIGN              07

UserThreadState *UserThreadState_new(void) {
  char *orig = galloc(sizeof(UserThreadState) + 20);
  UserThreadState *cand = (UserThreadState*)((((__u32)(orig + 4) + 15) / 16) * 16);
  int adj = (char *)cand - orig;
  assert(adj >= sizeof(int));

  memset(cand, 0, sizeof(UserThreadState));
  cand->align_adj = adj;
  return cand;
}

void UserThreadState_copy(UserThreadState *dest, UserThreadState *src) {
  int align_adj = dest->align_adj;
  *dest = *src;
  dest->align_adj = align_adj;
}

void UserThreadState_destroy(UserThreadState *uts) {
  char *freeptr = (char*)uts;
  freeptr = freeptr - uts->align_adj;
  gfree(freeptr);
}

void UserThreadState_initFromIS(UserThreadState *uts, InterruptState *is) {
#define COPY(X) uts->X = is->X
  COPY(gs);
  COPY(fs);
  COPY(es);
  COPY(ds);

  COPY(ebx);
  COPY(ecx);
  COPY(edx);
  COPY(esi);
  COPY(edi);
  COPY(ebp);
  COPY(eax);

  COPY(errorcode);
  COPY(eip);
  COPY(cs);
  COPY(eflags);
  COPY(esp);
  COPY(ss);
#undef COPY
}

/*
 * See the architecture assembly file.
 */
void nexusthread_rootpanic(void){
  printk_red("nexusthread_root panic\n");
  nexuspanic();
}
asmlinkage int nexusthread_root(void);

/*
 * Initialize a stack.
 *	Stack frame is set up so that thread calls:
 *		initial_proc(initial_arg);
 *		body_proc(body_arg);
 *		finally_proc(finally_arg);
 */
void
nexusthread_initialize_state(KernelThreadState *kts, proc_t body_proc, arg_t body_arg,
			    proc_t finally_proc, arg_t finally_arg) {
  kts->eip = (unsigned int) nexusthread_root;
  kts->ebx = (unsigned int) body_proc;
  kts->edi = (unsigned int) body_arg;
  kts->esi = (unsigned int) finally_proc;
  kts->ebp = (unsigned int) finally_arg;
  kts->eflags = X86_EFLAGS_IF;

  kts->user_tcb = NULL;
  kts->fs = kts->gs = 0;

  memset(&kts->xen_regs, 0, sizeof(kts->xen_regs));
  kts->xen_regs.iopl = 1;
  memset(&kts->vm_assist, 0, sizeof(kts->vm_assist));
  memset(&kts->xen_gdt, 0, sizeof(kts->xen_gdt));
  memset(&kts->xen_ldt, 0, sizeof(kts->xen_ldt));
  kts->per_domain_ptable = NULL;
  kts->shared_info_mfn = 0;
  kts->traps = NULL;
  kts->event_state = NULL;
  kts->hasEventEdge = 0;
}

void 
nexusthread_initialize_ustate(UserThreadState *uts, unsigned int pc, unsigned int sp) {
  //XXX define segment numbers
  uts->eip = pc;
  uts->esp = sp;
  uts->ecx = 0xbeefdead;
  uts->es = UNEXUSDS;
  uts->ds = UNEXUSDS;
  uts->ss = UNEXUSDS;
  uts->cs = UNEXUSCS;
  uts->eflags = (1<<9) | (1<<1); // (1<<9) enables interrupts

  //uts->alignedfxstate = (unsigned char *)(((unsigned int)(uts->fxstate + 15)) & ~15);
  //printk("setting up fxstate\n");
  memcpy(uts->fxstate, initial_fxstate, 512);
}

void flushglobalTLB(void){
  writecr4(readcr4() & ~X86_CR4_PGE);  // turn off Page Global Enable bit in CR4
  flushTLB();
  writecr4(readcr4() |  X86_CR4_PGE); 
}

/** Fast restart by triggering triple-fault */
void machine_restart(void)
{
	uint64_t null_idtr = 0;

	__asm__ __volatile__ ("lidt %0\n"
			      "int3" :: "m" (null_idtr));
}

int nexuskthread_savestate_c1(KernelThreadState * kts) {
  __asm__ __volatile__ ( "movw %%fs, %0" : "=wr" (kts->fs));
  __asm__ __volatile__ ( "movw %%gs, %0" : "=wr" (kts->gs));
  return 1; // Return 1 on the first time through; when "return" happens due to restorestate, it will return 0
}

int restorestate_count;
void nexuskthread_restorestate(KernelThreadState * kts) {
  extern void nexuskthread_restorestate_asm(KernelThreadState *);

  set_local_tcb(kts->user_tcb);
  
  __asm__ __volatile__ ( "movw %0, %%fs" : : "wr" (kts->fs));
  __asm__ __volatile__ ( "movw %0, %%gs" : : "wr" (kts->gs));

  restorestate_count++;
  nexuskthread_restorestate_asm(kts);
}

void dump_selector(__u32 *gdt, short selector) {
  selector &= ~ 0x7;
  printk("%x:\n%08x\n%08x\n",
	 (int) selector,
	 gdt[selector / sizeof(int)],
	 gdt[selector / sizeof(int) + 1]);
}

void set_local_tcb(void *new_tcb) {
  // Must disable interrupts to prevent inconsistent GDT state
  int intlevel = disable_intr();
  __u16 selector = KSHMEM_GS;
  __u16 offset = selector & ~0x7;
  IPD *ipd = curt->ipd;
  int isXen = (ipd && ipd->type == XEN);
  __u32 base;
  __u32 len;

  // Modify GDT
  base = (__u32)new_tcb;
  if(!isXen) {
    len = 0xffffffff; // Supports tls-direct-seg-refs, e.g. negative TLS offsets
  } else {
    // Requires -mno-tls-direct-seg-refs (GCC4 option)
    len = XEN_LIMIT - base;
  }

  /* 
     Descriptor format
     = High =
     base(31:24)[31:24] ctl [23:20] seg limit [19:16]a 
     ctl [15:8] base(23:16)[7:0]
     = Low =
     base (15:0)[31:16] seg limit(15:0)[15:0]
   */
  __u32 high = 0x00c0f200; // data segment, cpl 3
  __u32 low = 0x00000000;
  len >>= 12; // convert length to pages
  high |= (base & (0xff << 24)) | 
    (len & (0xf << 16)) |
    ((base >> 16) & 0xff);
  low |= ((base & 0xffff) << 16) |
    (len & 0xffff);

  put_gdt(offset, low, high);

  restore_intr(intlevel);
}

void *get_local_tcb(void) {
  // Only use for debugging purposes!
  extern SegmentDescriptor *gdtr_base;
  __u16 selector = KSHMEM_GS;
  __u16 offset = selector & ~0x7;
  SegmentDescriptor desc = gdtr_base[offset / sizeof(SegmentDescriptor)];

  // (desc.seglimit << 16) | (desc.limit);
  return (void *) ((desc.base << 24) | (desc.base2 << 16) | desc.base3);
}

#ifdef __NEXUSXEN__
void sysenter_call_xen(InterruptState *is) {
  printk_red("Sysenter called from Xen! Pass to Xen\n");
  // CS:eip, SS of fault point are lost
  is->cs = 0;
  is->ss = 0;
  is->eip = 0;
  do_xen_sysenter(is);  // Never returns!
  assert(0);
}
#endif

void KernelThreadState_destroy(BasicThread *t, KernelThreadState *kts) {
#ifdef __NEXUSXEN__
  xendom_KTS_free(t, kts);
#endif
  gfree(kts);
}

