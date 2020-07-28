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

#if 0
/*
 * Used to initialize a thread's stack for the first context switch
 * to the thread.  The nexusthread_root procedure will be run with the
 * main and final procedures saved on the thread's stack
 */
typedef struct StackState StackState;
struct StackState {
  void *body_proc;            /* v1 or ebx */
  void *body_arg;             /* v2 or edi */
  void *finally_proc;         /* v3 or esi */
  void *finally_arg;          /* v4 or ebp */
  void *root_proc;            /* left on stack */
};
#endif

//#define STACKSIZE               (64 * 4096)
#define STACKSIZE_PAGES (4)
#define STACKSIZE               (STACKSIZE_PAGES * 4096)
#define STACKALIGN              07

#define UTS_GUARD (0)

UserThreadState *UserThreadState_new(void) {
  char *orig = galloc(sizeof(UserThreadState) + 20);
  UserThreadState *cand = (UserThreadState*)((((__u32)(orig + 4) + 15) / 16) * 16);
  int adj = (char *)cand - orig;
  assert(adj >= sizeof(int));

  if(UTS_GUARD) {
    // Write in guard value
    write_guard(orig, adj);
  }

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
  if(UTS_GUARD) {
    if(!check_guard(freeptr, uts->align_adj)) {
      printk_red("guard mismatch at %p!\n", uts);
    }
  }
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
 * Allocate a new stack.
 */
void nexusthread_allocate_stack(void **stackbase, unsigned int *stacktop) {
  *stackbase = (void *) getKernelPages(STACKSIZE_PAGES);

  if (!*stackbase)  {
    printk("CANNOT ALLOCATE A STACK!\n");
    return;
  }
  /* Stacks grow down, but malloc grows up. Compensate and word align
     (turn off low 2 bits by anding with ~3). */
  *stacktop = ((unsigned int)((char*)*stackbase + STACKSIZE - 1) & ~STACKALIGN);


  /* this 0xdeadbeef at the base of the stack can be checked to make sure
     that the kernel stack doesn't overflow
   */
  int i;
}

/* 
 * Free a stack - The stack cannot be used after this call.
 */
void nexusthread_free_stack(BasicThread *t, void *stackbase) {
  int i;
  for(i=0; i < STACKSIZE_PAGES; i++) {
    nfree_page_vaddr((unsigned int)(stackbase + i * PAGE_SIZE));
  }
}

/*
 * See the architecture assembly file.
 */
void nexusthread_rootpanic(void){
  printk("nexusthread_root panic\n");
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
  /*
   * Configure initial machine state so that this thread starts
   * running inside a wrapper procedure named nexusthread_root.
   * nexusthread_root will invoke the procedures in order, and
   * then halt.
   */
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


/* "warm" reboot (no memory testing etc) */
//static int reboot_mode = 0x1234;
/* "cold" reboot (with memory testing etc) */
static int reboot_mode = 0x0;

/* The following code and data reboots the machine by switching to real
   mode and jumping to the BIOS reset entry point, as if the CPU has
   really been reset.  The previous version asked the keyboard
   controller to pulse the CPU reset line, which is more thorough, but
   doesn't work with at least one type of 486 motherboard.  It is easy
   to stop this code working; hence the copious comments. */

static unsigned long long
real_mode_gdt_entries [3] =
{
	0x0000000000000000ULL,	/* Null descriptor */
	0x00009a000000ffffULL,	/* 16-bit real-mode 64k code at 0x00000000 */
	0x000092000100ffffULL	/* 16-bit real-mode 64k data at 0x00000100 */
};

static struct
{
	unsigned short       size __attribute__ ((packed));
	unsigned long long * base __attribute__ ((packed));
}
real_mode_gdt = { sizeof (real_mode_gdt_entries) - 1, real_mode_gdt_entries },
real_mode_idt = { 0x3ff, 0 };

/* This is 16-bit protected mode code to disable paging and the cache,
   switch to real mode and jump to the BIOS reset code.

   The instruction that switches to real mode by writing to CR0 must be
   followed immediately by a far jump instruction, which set CS to a
   valid value for real mode, and flushes the prefetch queue to avoid
   running instructions that have already been decoded in protected
   mode.

   Clears all the flags except ET, especially PG (paging), PE
   (protected-mode enable) and TS (task switch for coprocessor state
   save).  Flushes the TLB after paging has been disabled.  Sets CD and
   NW, to disable the cache on a 486, and invalidates the cache.  This
   is more like the state of a 486 after reset.  I don't know if
   something else should be done for other chips.

   More could be done here to set up the registers as if a CPU reset had
   occurred; hopefully real BIOSs don't assume much. */

static unsigned char real_mode_switch [] =
{
	0x66, 0x0f, 0x20, 0xc0,			/*    movl  %cr0,%eax        */
	0x66, 0x83, 0xe0, 0x11,			/*    andl  $0x00000011,%eax */
	0x66, 0x0d, 0x00, 0x00, 0x00, 0x60,	/*    orl   $0x60000000,%eax */
	0x66, 0x0f, 0x22, 0xc0,			/*    movl  %eax,%cr0        */
	0x66, 0x0f, 0x22, 0xd8,			/*    movl  %eax,%cr3        */
	0x66, 0x0f, 0x20, 0xc3,			/*    movl  %cr0,%ebx        */
	0x66, 0x81, 0xe3, 0x00, 0x00, 0x00, 0x60,	/*    andl  $0x60000000,%ebx */
	0x74, 0x02,				/*    jz    f                */
	0x0f, 0x09,				/*    wbinvd                 */
	0x24, 0x10,				/* f: andb  $0x10,al         */
	0x66, 0x0f, 0x22, 0xc0			/*    movl  %eax,%cr0        */
};
static unsigned char jump_to_bios [] =
{
	0xea, 0x00, 0x00, 0xff, 0xff		/*    ljmp  $0xffff,$0x0000  */
};
/*
 * Switch to real mode and then execute the code
 * specified by the code and length parameters.
 * We assume that length will aways be less that 100!
 */
void machine_restart(void)
{
	if (nexus_clear_screen)
		nexus_clear_screen();

	disable_intr();

	/* Write zero to CMOS register number 0x0f, which the BIOS POST
	   routine will recognize as telling it to do a proper reboot.  (Well
	   that's what this book in front of me says -- it may only apply to
	   the Phoenix BIOS though, it's not clear).  At the same time,
	   disable NMIs by setting the top bit in the CMOS address register,
	   as we're about to do peculiar things to the CPU.  I'm not sure if
	   `outb_p' is needed instead of just `outb'.  Use it to be on the
	   safe side.  (Yes, CMOS_WRITE does outb_p's. -  Paul G.)
	 */

	CMOS_WRITE(0x00, 0x8f);

	/* Remap the kernel at virtual address zero, as well as offset zero
	   from the kernel segment.  This assumes the kernel segment starts at
	   virtual address PAGE_OFFSET. */

	memcpy (swapper_pg_dir, swapper_pg_dir + USER_PGD_PTRS,
		sizeof (swapper_pg_dir [0]) * KERNEL_PGD_PTRS);

	/* Make sure the first page is mapped to the start of physical memory.
	   It is normally not mapped, to trap kernel NULL pointer dereferences. */

	pg0[0] = _PAGE_RW | _PAGE_PRESENT;

	/*
	 * Use `swapper_pg_dir' as our page directory.
	 */
	load_cr3(swapper_pg_dir);

	/* Write 0x1234 to absolute memory location 0x472.  The BIOS reads
	   this on booting to tell it to "Bypass memory test (also warm
	   boot)".  This seems like a fairly standard thing that gets set by
	   REBOOT.COM programs, and the previous reset routine did this
	   too. */

	*((unsigned short *)0x472) = reboot_mode;

	/* For the switch to real mode, copy some code to low memory.  It has
	   to be in the first 64k because it is running in 16-bit mode, and it
	   has to have the same physical and virtual address, because it turns
	   off paging.  Copy it near the end of the first page, out of the way
	   of BIOS variables. */

	memcpy ((void *) (0x1000 - sizeof (real_mode_switch) - 100),
		real_mode_switch, sizeof (real_mode_switch));
	memcpy ((void *) (0x1000 - 100), jump_to_bios, sizeof(jump_to_bios));

	/* Set up the IDT for real mode. */

	__asm__ __volatile__ ("lidt %0" : : "m" (real_mode_idt));

	/* Set up a GDT from which we can load segment descriptors for real
	   mode.  The GDT is not used in real mode; it is just needed here to
	   prepare the descriptors. */

	__asm__ __volatile__ ("lgdt %0" : : "m" (real_mode_gdt));

	/* Load the data segment registers, and thus the descriptors ready for
	   real mode.  The base address of each segment is 0x100, 16 times the
	   selector value being loaded here.  This is so that the segment
	   registers don't have to be reloaded after switching to real mode:
	   the values are consistent for real mode operation already. */

	__asm__ __volatile__ ("movl $0x0010,%%eax\n"
				"\tmovw %%ax,%%ds\n"
				"\tmovw %%ax,%%es\n"
				"\tmovw %%ax,%%fs\n"
				"\tmovw %%ax,%%gs\n"
				"\tmovw %%ax,%%ss" : : : "eax");

	/* Jump to the 16-bit code that we copied earlier.  It disables paging
	   and the cache, switches to real mode, and jumps to the BIOS reset
	   entry point. */

	__asm__ __volatile__ ("ljmp $0x0008,%0"
				:
				: "i" ((void *) (0x1000 - sizeof (real_mode_switch) - 100)));
}

void dump_regs_is(InterruptState *is) {
  printk_current("eax=0x%x ebx=0x%x ", is->eax, is->ebx);
  printk_current("ecx=0x%x edx=0x%x\n", is->ecx, is->edx);
  printk_current("esi=0x%x edi=0x%x ", is->esi, is->edi);
  printk_current("ebp=0x%x esp=0x%x\n", is->ebp, is->esp);
  printk_current("ds=0x%x es=0x%x ss=0x%x fs=0x%x gs=0x%x eflags=0x%x\n", is->ds, is->es, is->ss, is->fs, is->gs, is->eflags);

  printk_current("cs=%x sp=0x%x pc=0x%x errorcode=0x%x entry_vector=%d\n", is->cs, is->esp, is->eip, is->errorcode, is->entry_vector);
}

void dump_user_stack(InterruptState *is)
{
  dump_user_stack_map(nexusthread_current_ipd(), nexusthread_current_map(), is);
}

void dump_user_stack_map(IPD *ipd, Map *map, InterruptState *is)
{
  int *finger = (int *)is->esp;
  int i, zero_skip_count = 0;
  const int MAX_NUM_ZEROS = 32;

  printk_current("user stack (%p): ", is->esp);
  for(i=0; i < 32; i++, finger++) {
    unsigned int val;
    int bad_val = 0;
    if(peek_user(map, (unsigned int) finger, &val, sizeof(val)) != 0) {
      bad_val = 1;
    }

    if(!bad_val) {
      if(val == 0 && zero_skip_count < MAX_NUM_ZEROS) {
	zero_skip_count++;
	i--;
	continue;
      }

      if(zero_skip_count > 0) {
	printk_current("(0[%d]) ", zero_skip_count);
	zero_skip_count = 0;
      }

      printk_current("(%p) ", val);
    } else {
      printk_current("(ERR) ");
      break;
    }
  }

  // Again, with pointers into image
  if(0) {
    // ASHIEH: Keep this code around, since not all user code
    // will have frame pointers
    finger = (int *)is->esp;
    int num_calls = 0;
    const int CALL_LIMIT = 32;
    printk_current("\nUser calls: ");
    for(i=0; i < 1024 && num_calls < CALL_LIMIT; i++, finger++) {
      unsigned int val;
      if(peek_user(map, (unsigned int) finger, &val, sizeof(val)) != 0) {
	continue;
      }
      if( (0x08000000 <= val  && val < 0x09000000) ||
	  (0xb4000000 <= val && val <= 0xb4000000 + 4405740 + 100000) ) {
	printk_current("<%p> ", (void *)val);
	num_calls++;
      }
    }
  }

  const char *map_suffix = ".map";
  char *fname = galloc(strlen(ipd->name) + strlen(map_suffix) + 1);
  strcpy(fname, ipd->name);
  strcat(fname, map_suffix);
  SymTable *table = symtable_find(fname);
  gfree(fname);

  printk_current("\nEBP based user calls: ");
  if(table != NULL) { printk_current("\n"); }
  __u32 curr_ebp = is->ebp;
  for(i=0; i < 20 && curr_ebp; i++) {
    __u32 data[2];
    if(peek_user(map, curr_ebp,
		 &data[0], sizeof(data)) != 0) {
      printk_red("peek error at %p", (void *) curr_ebp);
      break;
    }
    void *code_addr = (void *)data[1];
    if(table == NULL) {
      printk_current("<%p> ", code_addr);
    } else {
      symtable_print_by_addr(table, code_addr);
    }
    curr_ebp = data[0];
  }
  if(table != NULL) { trace_pause(); }
  printk_current("\n");
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
  IPD *ipd = nexusthread_current_base_ipd();
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

void KernelThreadState_dump(KernelThreadState *kts) {
  printk_red("KTS (%p): ", kts);
#define PRINT(X) printk_red(#X "=%p ", (void *)(__u32)kts->X);
  PRINT(ebp);
  PRINT(esi);
  PRINT(edi);
  PRINT(ebx);
  PRINT(eip);
  PRINT(esp);

  PRINT(ss1);
  PRINT(esp1);

  PRINT(ss2);
  PRINT(esp2);

  PRINT(user_tcb); // Accessible via %gs
  PRINT(fs); PRINT(gs);

  if(0) {
    printk_red("pc = %p\n", (void *)*(int *)((char *)kts + 16));
    printk_red("\n");
    printk_red("looping\n");
    while(1);
  }
}

void KernelThreadState_destroy(BasicThread *t, KernelThreadState *kts) {
#ifdef __NEXUSXEN__
  xendom_KTS_free(t, kts);
#endif
  gfree(kts);
}

