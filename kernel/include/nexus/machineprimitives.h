#ifndef __NEXUSTHREADPRIMITIVES_H__
#define __NEXUSTHREADPRIMITIVES_H__

#include <nexus/defs.h>
#ifdef __NEXUSXEN__
#include <nexus/xen-syscalls.h>
#endif
//#include <nexus/mem.h> // for KSHMEM_VADDR
#include <nexus/segments.h>
#include <asm/bitops.h>
#include <asm/system.h>
#include <asm/processor.h>

#include <nexus/machine-structs.h>

#define NUM_EXCEPTIONS (32)
#define NUM_IRQS (256)
extern int irq_count[];

//XXX get rid of _t
typedef int (*proc_t)(void*);   /* generic function pointer */
typedef void *arg_t;             /* function argument */

extern unsigned char initial_fxstate[] __attribute__ ((aligned (16)));

extern GDT_Descriptor gdt_descr;
extern SegmentDescriptor boot_gdt_table[]; // the initial GDT, used during initial boot
extern SegmentDescriptor *const nexus_gdt_table; // Location of GDT during execution. The linear address never changes, but pages 0-13 are remapped on context switch to a Xen app

#define FXSTATE_SIZE (512)
// #define NR_CPUS (1)
#define current_cpu() (0)

struct FXState_Flags {
  int need_init;
  int need_restore;
};

struct BasicThread;
struct UThread;

#define TS_FPU_SWITCH (1)
struct CPU_KernelState {
  int int_mask;
  unsigned char interrupt_fxstate[FXSTATE_SIZE]__attribute__ ((aligned (16)));
  unsigned char app_fxstate[FXSTATE_SIZE]__attribute__ ((aligned (16)));
  // fxstate must be aligned, so put it at top of struct
  int in_interrupt;
#if 0 /* not needed for the slow fxsave (see kernel_fpu_begin below) */
  struct FXState_Flags sync; // process
  struct FXState_Flags async; // interrupt
#endif
  struct UThread *fxstate_owner;
}__attribute__ ((aligned (16)));

extern CPU_KernelState cpu_state[]__attribute__ ((aligned (16)));

#ifndef __IN_SETUP__
/*
 * Kernel threads need only save callee-save registers
 */
struct Page;
struct KernelThreadState {
  unsigned int ebp;
  unsigned int esi;
  unsigned int edi;
  unsigned int ebx;
  unsigned int eip;
  unsigned int esp;
  unsigned int eflags;
  // EAX, ECX, and EDX are caller saved

  /* the following are set by the kernel */

  // Fields above this point are referred to in asm.S! Don't change
  // order

  void *user_tcb; // Accessible via %gs
  unsigned short fs, gs;

  // Xen state

  struct {
    unsigned long event_selector;
    unsigned long event_address;

    unsigned long failsafe_selector;
    unsigned long failsafe_address;

    unsigned long nmi_selector;
    unsigned long nmi_address;
  } callbacks;

  unsigned short ss1;
  unsigned int esp1;

  unsigned short ss2;
  unsigned int esp2;

  // virtualized CPU registers for special case interrupt processing, context switch
  // These are not guaranteed to be up to date at all times
  struct {
    unsigned int dr6; // XXX Debug registers are not handled properly
    unsigned int cr2;

    unsigned int cr0; // Virtual CR0 state, saved & restored during
		      // context switch. Only some bits are valid, see
		      // xen-defs.h
    unsigned int iopl;
  } xen_regs;

  struct {
    __u32 mode; // Xen mode

#define MAX_VMM_PDIR_LEN (16)
    int pdoffset;
    unsigned int entries[MAX_VMM_PDIR_LEN];
    int len;
  } vm_assist;

  struct Page *per_domain_ptable; // physical address
  DirectoryEntry per_domain_pdeval;

  struct {
    struct Page *gdt_pages[FULL_GDT_PAGESIZE];

    unsigned long frame_list[FULL_GDT_PAGESIZE];
    int entries;
  } xen_gdt;

  struct {
    __u32 base; // linear address of base of LDT
    int num_entries;
  } xen_ldt;

  __u32 shared_info_mfn;

  struct NexusTrapInfo *traps; // The trap table resides in VMM r/w space. Entries are validated on every trap
  struct EventChannelState *event_state;
  int hasEventEdge;
};

void KernelThreadState_dump(KernelThreadState *kts);
void KernelThreadState_destroy(struct BasicThread *t, KernelThreadState *kts);
static inline void KernelThreadState_syncTSS(KernelThreadState *kts);

/* Note: InterruptState is now defined in common/machine-structs.h */
void dump_regs_is(InterruptState *is);

struct UserThreadState {
  // asm depends on the location and alignment of some of these fields
  unsigned int ecx;
  unsigned int edx;
  unsigned int eax;
  unsigned int ds;
  unsigned int es;
  unsigned int ebp;
  unsigned int esi;
  unsigned int edi;
  unsigned int ebx;
  unsigned int errorcode;
  unsigned int eip;
  unsigned int cs;
  unsigned int eflags;
  unsigned int esp;
  unsigned int ss;
  unsigned int fs;
  unsigned int gs;
  // end of assembly-dependent area
  unsigned char fxstate[FXSTATE_SIZE] __attribute__ ((aligned (16)));

  int align_adj; // alignment adjustment performed to make fxstate 16-aligned
};

UserThreadState *UserThreadState_new(void);
void UserThreadState_copy(UserThreadState *dest, UserThreadState *src);
void UserThreadState_destroy(UserThreadState *uts);
void UserThreadState_initFromIS(UserThreadState *uts, InterruptState *is);

extern TSS *nexustss;

static inline void KernelThreadState_syncTSS(KernelThreadState *kts) {
  nexustss->ss1 = kts->ss1;
  nexustss->esp1 = kts->esp1;
  nexustss->ss2 = kts->ss2;
  nexustss->esp2 = kts->esp2;
}

static inline void changeTSSesp0(__u32 new_esp) {
  nexustss->esp0 = new_esp;
}

//extern unsigned char initial_fxstate[] __attribute__ ((aligned (16)));

/*
 *	Allocate a fresh stack.  Stacks are said to grow "down" (from higher
 *  memory locations towards lower ones) on our version of the x86 and ARM
 *  architectures. 
 *	The bottom of the stack is returned in *stackbase; the top of
 *	the stack is returned in *stacktop.
 *
 *	-----------------
 *	|  stacktop	    |  <- next word pushed here
 *	|               |
 *	|               |
 *	|  stackbase    |  <- bottom of stack.
 *	-----------------
 */

extern void nexusthread_allocate_stack(void **stackbase,
				       unsigned int *stacktop);

/*
 *	Frees the stack at stackbase.  If the caller is running on the stack
 *	referenced by stackbase,
 *	then care must be taken to ensure that no other thread uses the same
 *	stack until the caller terminates.
 */
extern void nexusthread_free_stack(struct BasicThread *t, void * stackbase);

/*
 * 	Initialize the stackframe pointed to by *stacktop so that
 *	the thread running off of *stacktop will invoke:
 *		body_proc(body_arg);
 *		final_proc(final_arg);
 *
 *	The call to final_proc should be used for cleanup, since it is called
 *	when body_proc returns.  final_proc should not return; doing so will
 *	lead to undefined behavior and likely cause your system to crash.
 *
 *	body_proc and final_proc cannot be NULL. Passing invalid
 *      function pointers crashes the system.
 *
 *	This procedure changes the value of *stacktop.
 *
 */
extern void nexusthread_initialize_state(KernelThreadState *kts,
					proc_t body_proc,
					arg_t body_arg,
					proc_t final_proc,
					arg_t final_arg);

extern int nexuskthread_savestate(KernelThreadState *);

extern void nexuskthread_restorestate(KernelThreadState *);

extern void restoreustate(UserThreadState *);
extern void nexusthread_initialize_ustate(UserThreadState *uts, unsigned int pc, unsigned int sp);

extern void fxsave_registers(unsigned char *fxstate);
extern void fxrstor_registers(unsigned char *fxstate);
extern void finit_state(void);

extern void tss_init(void);

extern unsigned int readcr2(void);

extern unsigned int readcr0(void);
extern void writecr0(unsigned int);

/* cr3 is the page directory base register */
extern unsigned int readcr3(void);
extern void writecr3(unsigned int);

/* cr4 has some flags for sse */
extern unsigned int readcr4(void);
extern void writecr4(unsigned int);

/* mxcsr has floating-point mask bits */
extern void loadmxcsr(unsigned int *mxcsrval);

/* SYNCHRONIZATION PRIMITIVES */

/*
 *	Atomically test and set the value at l to 1.  Return old value.
 */
extern int atomic_test_and_set(int *l);

/*
 *	Atomically set the value at l to 0.
 */
extern void atomic_clear(int *l);

extern void nexushalt(void);
extern void machine_restart(void);

/*
 * Atomic compare and swap.
 * If the value pointed to by x is equal to oldval, then replace it with
 * newval; regardless of the result of the comparison, return the original
 * value of *x.
 */
extern int compare_and_swap(int* x, int oldval, int newval);

static inline int cpu_in_interrupt(void)
{
	return cpu_state[current_cpu()].in_interrupt ? 1 : 0;
}

/*
 * Disable interrupts.  Return the state of the Interrupt flag before the call.
 * This value determines whether or not interrupts were already disabled.
 * 1 == interrupts were enabled, 0 == interrupts were disabled.
 */
//extern int disable_intr(void);

static inline int disable_intr(void) {
  int rv;
  __asm__ __volatile__ 
    ("        pushfl\n"
     "	cli		#disable interrupts\n"
     "	popl %0	#get the EFLAGS off stack\n"
     "	\n"
     "	andl $512, %0		#and to get the IF from EFLAGS (9th bit)\n"
     "	shr $9, %0		#shift it right (now 1==IF_on 0==IF_off)\n"
     "				#IF_on means interrupts enabled\n"
     : "=r" (rv));
  return rv;
}

// extern void restore_intr(int);

static inline void restore_intr(int oldval) {
  if(oldval) {
    __asm__ __volatile__  ("	sti	#restore interrupts\n");
  }
}

static inline int check_intr(void) {
  int rv;
  __asm__ __volatile__ 
    (
     "pushfl		#put the EFLAGS register on stack so we can look at it\n"
     "popl %0	#get the EFLAGS off stack\n"
     "andl $512, %0		#and to get the IF from EFLAGS (9th bit)\n"
     "shr $9, %0		#shift it right (now 1==IF_on 0==IF_off)\n"
     "#IF_on means interrupts enabled\n" : "=r" (rv));
  return rv;
}

extern void enable_intr(void);

static inline int disable_ts(void) {
  int cr0_val = read_cr0();
  barrier();
  clts();
  return cr0_val;
}

static inline void restore_ts(int oldval) {
  barrier();
  if(oldval & X86_CR0_TS) {
    stts();
  } else {
    clts();
  }
}

static inline void write_gdtr(const GDT_Descriptor *desc) {
  __asm__ __volatile__ ( "lgdt %0" : : "m" (*desc) );
}

int read_gdtr(void);
int read_gdtr_limit(void);
unsigned int read_tr(void);
int read_idtr(void);
int read_idtr_limit(void);

void flushglobalTLB(void);
void flushTLB(void);

static inline void flushTLB_one(__u32 addr) {
  __asm__ __volatile__ 
    (
     "invlpg %0"
     : : "m" (*(char *)addr)
     );
}

static inline void invalidateTLB_Entry(void *source) {
  int ignored;
  __asm__ __volatile__ ( "invlpg %1" : "=memory" (ignored) : "m" (source));
}

#endif // __IN_SETUP__

//extern void nexus_startup(void);
extern int fpudebug;

static inline void kernel_fpu_begin(void) {
  cpu_state[current_cpu()].int_mask = disable_intr();
  unsigned char *save_target = cpu_state[current_cpu()].interrupt_fxstate;
  //if(fpudebug)printk_red("(fpu begin)");			
  clts();
  fxsave_registers(save_target);
  fxrstor_registers(initial_fxstate);
}

static inline void kernel_fpu_end(void) {
  fxrstor_registers(cpu_state[current_cpu()].interrupt_fxstate);
  restore_intr(cpu_state[current_cpu()].int_mask);
  stts();
}

#define STORE_FENCE()				\
  __asm__ __volatile__ (			\
			"  sfence \n" : :	\
			)

#define PRE_FPU()				\
  int ts = disable_ts();			\
  kernel_fpu_begin();

#define POST_FPU()				\
  kernel_fpu_end();				\
  restore_ts(ts);

// this routine came from Linux
// warning: this MOVNTQ is an SSE instruction. It will NOT work on P2 and older
static inline void pagememzero_n(unsigned int page, int num_pages) {
  assert(((unsigned) page) % PAGE_SIZE == 0);
  int page_num;
  int i;

  PRE_FPU();
  __asm__ __volatile__ (
			"  pxor %%mm0, %%mm0\n" : :
			);

  for(page_num = 0; page_num < num_pages; page_num++) {
    for(i=0;i<4096/64;i++)
      {
	__asm__ __volatile__ (
			      "  movntq %%mm0, (%0)\n"
			      "  movntq %%mm0, 8(%0)\n"
			      "  movntq %%mm0, 16(%0)\n"
			      "  movntq %%mm0, 24(%0)\n"
			      "  movntq %%mm0, 32(%0)\n"
			      "  movntq %%mm0, 40(%0)\n"
			      "  movntq %%mm0, 48(%0)\n"
			      "  movntq %%mm0, 56(%0)\n"
			      : : "r" (page) : "memory");
	page+=64;
      }
  }
  /* since movntq is weakly-ordered, a "sfence" is needed to become
   * ordered again.
   */
  STORE_FENCE();
  POST_FPU();
}

static inline void prefetch_rw0(void *dest) {
  // prefetch for read/write
  __asm__ __volatile__ ( "prefetcht0 %0 " : : "m" (*(char *)dest));
}
static inline void prefetch_rw1(void *dest) {
  // prefetch for read/write
  __asm__ __volatile__ ( "prefetcht1 %0 " : : "m" (*(char *)dest));
}

static inline void prefetch_nt(void *dest) {
  // non-temporal
  __asm__ __volatile__ ( "prefetchnta %0 " : : "m" (*(char *)dest));
}

#define PAGE_ROUNDUP(X)					\
  (((X) + PAGE_SIZE - 1) / PAGE_SIZE * PAGE_SIZE)

struct InterruptState;
void dump_user_stack(struct InterruptState *is);
struct Map;
void dump_user_stack_map(struct IPD *ipd, struct Map *map, InterruptState *is);
void dump_regs(void);

void set_local_tcb(void *new_tcb);

asmlinkage void sysenter_call(void);

// Assembler hack to get higher profiler resolution
#define PROFILER_FLAG(X)   __asm__ __volatile__ (".globl " #X "\n" #X ":");

#endif /* __NEXUSTHREADPRIMITIVES_H__ */

