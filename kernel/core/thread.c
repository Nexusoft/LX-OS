/** Nexus OS: kernel thread support */

#include <asm/hw_irq.h>
#include <asm/param.h>
#include <asm/io.h>
#include <asm/errno.h>
#include <linux/smp.h>

#include <nexus/defs.h>
#include <nexus/thread.h>
#define NEED_SEMA_WAKEUP
#include <nexus/synch.h>
#include <nexus/synch-inline.h>
#include <nexus/queue.h>
#include <nexus/mem.h>
#include <nexus/clock.h>
#include <nexus/idtgdt.h>
#include <nexus/device.h>
#include <nexus/ipd.h>
#include <nexus/syscalls.h>
#ifdef __NEXUSXEN__
#include <nexus/xen-syscalls.h>
#endif
#include <nexus/machineprimitives.h>
#include <nexus/thread-struct.h>
#include <nexus/thread-private.h>
#include <nexus/util.h>
#include <nexus/log.h>
#include <nexus/hashtable.h>
#include <nexus/task.h>
#include <nexus/net.h>
#include <nexus/ipc_private.h>
#include <nexus/ddrm.h>
#include <nexus/tftp.h>
#include <nexus/handle.h>

/// This number of deadbeefs are added to the base of the stack as a guard
#define STACK_GUARD_LEN (64)

static Queue run_queue = QUEUE_EMPTY;		///< default thread (not proc) runqueue
static Queue intr_queue = QUEUE_EMPTY;		///< interrupt queue
static Queue deficit_queue = QUEUE_EMPTY;	///< deficit queue, for reservations

BasicThread *curt;				///< current thread
Map *curr_map;					///< current map
volatile int preemption_mask = 1;		///< preemption toggle

int in_panic;					///< in panic mode, respond differently to IRQs
char in_panic_scancode;				///< the keyboard inthandler puts pressed key here

/// queue all threads ready to be reaped 
static UQueue *dead_thread_queue;
static Sema dead_thread_sema = SEMA_INIT; 

#define INTERVAL_LENGTH (10)
/// intervals implement cpu reservations 
struct BasicThread * intervals[INTERVAL_LENGTH];

/// Lookup from thread id to struct
struct HashTable *threadTable;
struct Sema threadTable_mutex = SEMA_MUTEX_INIT;
#define THREAD_TABLE_SIZE (8192)

/** Have a thread belonging to one process to act on behalf of another */
void
nexusthread_impersonate_push(IPD *ipd)
{
	BasicThread *t;

	t = nexusthread_self();
	assert(t);
	
	P(&t->personality.mutex);
	assert(t->personality.index < MAX_SCHIZO);
	t->personality.stack[t->personality.index] = ipd;
	t->personality.index++;
	V(&t->personality.mutex);
}

/** Read the top element of the personality stack (does not pop) */
IPD *
nexusthread_impersonate_get(void)
{
	BasicThread *t;
	IPD *ipd;

	t = nexusthread_self();
	assert(t);

	P(&t->personality.mutex);
	if (t->personality.index)
		ipd = t->personality.stack[t->personality.index - 1];
	else
		ipd = nexusthread_current_base_ipd(); /* stack bottom */
	V(&t->personality.mutex);

	return ipd;
}

/** Pop a personality from the stack */
void
nexusthread_impersonate_pop(void)
{
	BasicThread *t;

	t = nexusthread_self();
	assert(t);

	P(&t->personality.mutex);
	assert(t->personality.index);
	t->personality.index--;
	V(&t->personality.mutex);
}

/** return the IPD this process claims to be */
IPD *
nexusthread_get_ipd(BasicThread *t) 
{
  if (t->ipd == kernelIPD)
    return nexusthread_impersonate_get();
  else 
    return t->ipd;
}

static u64 nexusthread_scale_reservation(BasicThread *t, int num_ticks) {
  return (((u64) num_ticks) * (t->num_interval_slots * TSC_PER_TICK)) / INTERVAL_LENGTH;
}

static u64 nexusthread_get_deficit(BasicThread *t) {
  assert(t->sched_type == SCHEDTYPE_INTERVAL);
  int i;
  int interval_start = nexustime - (nexustime % INTERVAL_LENGTH);
  u64 wanted = 0;
  // N.B. only count the current interval, to prevent accumulation of
  // long-term deficit due to sleeps, locks, etc.
  
  for(i=max(interval_start, t->start_tick) - interval_start;
      interval_start + i < nexustime && i < INTERVAL_LENGTH; i++) {
    if(intervals[i] == t) {
      wanted += TSC_PER_TICK;
    }
  }
  long long result = wanted - nexusthread_get_cycles(t);
  if(result < 0) {
    return 0;
  } else {
    return result;
  }
}

int nexusthread_set_schedtype(BasicThread *t, int sched_type, void *sched_info) {

  // can only change from round robin
  assert(t->sched_type == SCHEDTYPE_ROUNDROBIN);

  switch(sched_type) {
  case SCHEDTYPE_INTERVAL: {
    struct SchedTypeInfo_Interval *info = 
      (struct SchedTypeInfo_Interval *) sched_info;
    assert(info->numerator < 1000);
    t->interval = *info;
    t->num_interval_slots = ( info->numerator * INTERVAL_LENGTH ) / 1000;

    // populate schedule
    int i;
    int err = 0;
    // mutex on intervals[]
    int intr_state = disable_intr();
    for(i=0; i < t->num_interval_slots; i++) {
      int want_position = i * (INTERVAL_LENGTH * 1000) / t->num_interval_slots / 1000;
      assert(0 <= want_position && want_position < INTERVAL_LENGTH);
      int found = 0;
      int j;
      for(j=0; j < INTERVAL_LENGTH; j++) {
        int pos = (want_position + j) % INTERVAL_LENGTH;
        if(intervals[pos] == NULL) {
          intervals[pos] = t;
          found = 1;
          break;
        }
      }
      if(!found) {
        printk_red("could not build schedule\n");
        err = -1;
        goto out;
      }
    }
    out:
    if(err != 0) {
      printk_red("cleaning up\n");
      int i;
      for(i=0; i < INTERVAL_LENGTH; i++) {
        if(intervals[i] == t) {
          intervals[i] = NULL;
        }
      }
      t->sched_type = SCHEDTYPE_ROUNDROBIN;
      t->num_interval_slots = 0;
    }
    t->sched_type = SCHEDTYPE_INTERVAL;
    printk("Successful new schedule\n");
    restore_intr(intr_state);
    return err;
    break;
  }
  case SCHEDTYPE_ROUNDROBIN:
    // fall through
  default:
    assert(0);
    return 0;
  }
}

/** Count the number of idle cycles (since last counter reset) */
uint64_t nexusthread_idlecycles;

/** Store the percentage of idle time in the last second */
int nexusthread_idle_pct_sec;

/** Spin down the CPU while idle */
static void
nexusthread_idle(void)
{
	uint64_t duration;

	duration = rdtsc64();
	enable_intr();
	asm volatile ("hlt");
	disable_intr();
	nexusthread_idlecycles += rdtsc64() - duration;
}

/** Sleep waiting for a keyboard character. 
    This special sleep function is used in asserts and panics

    @return the key pressed by the user */
char 
nexusthread_panicmode(void)
{
	// wait for keyboard interrupt (don't busy wait)
	in_panic = 1;	// tell keyboard int handler to special case
	nexusthread_idle();
	in_panic = 0;
	
	return in_panic_scancode;
}

void 
nexuspanicfn(const char *file, int line) 
{
	disable_intr();
	dump_stack();
	printk_red("NEXUS PANIC: Hit <ESC> to reboot... ");

	while (1) {
		if (nexusthread_panicmode() == REBOOT_SCANCODE)
			machine_restart();
	}
}

void 
assertlf(int linenum, const char *file) 
{
  BasicThread *t;

  // disable interrupts to prevent mixing of output with that of other thread
  disable_intr();

  printk_red("Assertion failed at %s:%d: ", file, linenum); 
  if (curt) {
	printk_red(" thread=%d", curt->id);
  	if (curt->ipd)
		printk_red(" process=%d", curt->ipd->id);
  }
  printk_red("\n");

  t = nexusthread_self();
  if (t) {
    if(t->trap_is)
      dump_regs_is(t->trap_is);
  }

  dump_stack();

  nexuspanicfn(file, linenum);
}

/*
 * This is the nexus thread scheduler.
 * Round robin.
 * The current thread's runnability state must be updated before
 * this function is invoked.
 */
static inline 
BasicThread * schednext(void) 
{
  BasicThread *new;
  
  while(1) {
    // 1. Interrupt queue
    if (!queue_dequeue(&intr_queue, (void **) &new)) {
      assert(new->schedstate == RUNNABLE);
      queue_delete(&run_queue, new);
      break;
    }
    // 2. Interval scheduler: check current slot
    int slot_num = nexustime % INTERVAL_LENGTH;
    if (intervals[slot_num]  && 
        intervals[slot_num]->schedstate == RUNNABLE) {
      new = intervals[slot_num];
      queue_delete(&run_queue, new);
      queue_delete(&deficit_queue, new);
      break;
    }
    // 3. Interval scheduler: find processes that haven't gotten enough ticks
    // XXX May want to process this as a priority queue for fairness, etc
    if (!queue_dequeue(&deficit_queue, (void **) &new)) {
      assert(new->schedstate == RUNNABLE);
      // check for oversized deficits
      if (nexusthread_get_deficit(new) >
          nexusthread_scale_reservation(new, 2 * HZ) ) {
        printk_red("Interval thread more than 2 seconds behind!\n");
      }
      break;
    }
    // 4. Finally, check the RR queue
    if(likely(!queue_dequeue(&run_queue, (void **) &new))) {
      assert(new->schedstate == RUNNABLE);
      break;
    }

    /* idle loop */
    preemption_enabled = 0;
    nexusthread_idle();
    preemption_enabled = 1;
  }

  assert(new->schedstate == RUNNABLE);
  return new;
}

static int 
kcheck_stack_overflow(KThread *t)
{
  int i;
  
  if (!t || !t->stackbase)
    return 0;
  
  for (i = 0; i < STACK_GUARD_LEN; i++) {
    if (*((unsigned int *)t->stackbase + i) != 0xdeadbeef) {
      printk_red("Kernel Stack Overflow (thread=%d base=0x%x, esp=0x%x)\n", 
		 t->id, t->stackbase, t->kts->esp);
      return -1;
    }
  }
  return 0;
}

int 
check_stack_overflow(BasicThread *t)
{
  int rv;

  if (t->type == USERTHREAD) {
    rv = kcheck_stack_overflow(((UThread *)t)->kthread);
    if(rv) {
      UThread *ut = (UThread *)t;
      printk_green("overflow ipd %d ", ut->ipd->id);
      nexusthread_dump_regs_stack(t);
      nexuspanic();
    }
  } else {
    rv = kcheck_stack_overflow((KThread *)t);
    assert(rv == 0);
  }
  return rv;
}

int switchnest = 0, badness = 0;
int thread_switchcount = 0;

static inline void 
nexusthread_add_to_runqueue(BasicThread *t, int at_front)
{
  Queue *queue;
  
  assert(check_intr() == 0);
  assert(t->schedstate == RUNNABLE);
  
  if (t->check_intr_queue && t->check_intr_queue(t, t->callback_args))
    queue = &intr_queue;
  else
    queue = &run_queue;

  if (at_front)
    queue_prepend(queue, t);
  else
    queue_append(queue, t);
}

// Top-level save routines must be implemented in assembly language to
// avoid clobbering saved registers and stack contents between save /
// restore
int nexuskthread_save(KThread *kt);
int nexusuthread_save(UThread *ut);

/** sub of nexuskthread_save: save state of a kernel thread (registers) */
KernelThreadState *nexuskthread_save_c0(KThread *kt) {
// debug code XXX remove
	if (!kt->kts)
		printk("failed for kernel thread %d\n", kt->id);
  assert(kt->kts != 0);
  kt->cycles_used += rdtsc64() - kt->first_cycle;
  return kt->kts;
}

/** restore state of a kernel thread (registers) */
void nexuskthread_restore(KThread *kt) {
  kt->first_cycle = rdtsc64();
  nexustss->ss1 = kt->kts->ss1;
  nexustss->esp1 = kt->kts->esp1;
  nexustss->ss2 = kt->kts->ss2;
  nexustss->esp2 = kt->kts->esp2;
  nexuskthread_restorestate(kt->kts);
}

/** sub of nexusuthread_save: save state of a user thread (registers) */
KThread *nexusuthread_save_c(UThread *ut) {
  if(!TS_FPU_SWITCH) {
     if(likely(sseOn)) {
      int ts = disable_ts();
      fxsave_registers(ut->uts->fxstate);
      restore_ts(ts);
    }
  }

#ifdef __NEXUSXEN__
  if(nexusthread_isXen((BasicThread *)ut)) {
    thread_Xen_switchOut((BasicThread *)ut);
  }
#endif
  return ut->kthread;
}

void nexusthread_fpu_trap(void) {
  clts();
  // Save registers to owner, and switch the owner
  UThread *owner = cpu_state[current_cpu()].fxstate_owner;
  if(owner != NULL) {
    fxsave_registers(owner->uts->fxstate);
    nexusthread_put((BasicThread *)owner);
  }

  assert(curt->type == USERTHREAD);
  cpu_state[current_cpu()].fxstate_owner = nexusuthread_current();
  nexusthread_get(curt);
  fxrstor_registers(nexusuthread_current()->uts->fxstate);
}

/** fill the interrupt state of a new thread ready to be born */
void 
fill_is(UserThreadState *uts, InterruptState *is) 
{

  __asm__ __volatile__ ( "movw %w0, %%fs" : : "wr" (uts->fs));
  __asm__ __volatile__ ( "movw %w0, %%gs" : : "wr" (uts->gs));

  is->gs = uts->gs;
  is->fs = uts->fs;
  is->es = uts->es;
  is->ds = uts->ds;

  is->ebx = uts->ebx;
  is->ecx = uts->ecx;
  is->edx = uts->edx;
  is->esi = uts->esi;
  is->edi = uts->edi;
  is->ebp = uts->ebp;
  is->eax = SYS_BIRTH;

  is->errorcode = uts->errorcode ;
  is->entry_vector = 0;
  is->eip = uts->eip;
  is->cs = uts->cs;
  is->eflags = uts->eflags;

  is->esp = uts->esp;
  is->ss = uts->ss;
}

/** various tasks that have to be performed before switching to usermode */
static void 
uthread_restore_helper(UThread *newu) 
{

  if (!TS_FPU_SWITCH) {
    if (likely(sseOn)) {
      int ts = disable_ts();
      fxrstor_registers(newu->uts->fxstate);
      restore_ts(ts);
    }
  }

  //set TSS
  KernelThreadState_syncTSS(newu->kthread->kts);
  changeTSSesp0(newu->kernel_esp);
  
  Map_activate(newu->map, (BasicThread *)newu);
  
  // Update the shared info page
#ifdef __NEXUSXEN__
  BasicThread *t = (BasicThread *)newu;
  if(nexusthread_isXen(t)) {
    thread_Xen_switchIn(t);
  }
#endif
}

/** switch to usermode. defined in asm.S */
extern void fake_up_syscall(UserThreadState *uts, int is_size);

static void nexusuthread_goto_user(UThread *ut) {
  assert(check_intr() == 1);

  // The goto user will restore interrupts
  disable_intr();
  uthread_restore_helper(ut);

  fake_up_syscall(ut->uts, sizeof(InterruptState));
}

static void switch_to_new_thread(BasicThread *new) {
 
  // update runqueue location of old thread
  if (curt->sched_type == SCHEDTYPE_INTERVAL) {
    int deficit = nexusthread_get_deficit(curt);

    // only count deficits > 4%
    if (curt->schedstate == RUNNABLE && deficit > TSC_PER_TICK / 25) {
      printk_red("deficit = %d\n", deficit);
      assert(!queue_find_eq(&run_queue, curt));
      queue_delete(&run_queue, curt);
      queue_append(&deficit_queue, curt);
    }
  }

  curt = new;

  // update the status of the last executing thread in the given ipd
  if (curt->type == USERTHREAD)
    curt->ipd->thread_latest = curt;

#ifdef __NEXUSXEN__
  if(inXenDomain()) {
      // Simplify handling of NM by always doing a full FPU context
      // switch to a Xen domain.  We can potentially do something more
      // efficient in the future.

    // This must occur AFTER curt (nexusthread_fpu_trap() depends on
    // curt having changed) and BEFORE uthread_restore_helper() (since
    // that restores the Nexus TS bit state.
    nexusthread_fpu_trap();
  }
  else
#endif
    stts();

  thread_switchcount++;
  if (new->type == USERTHREAD) {
    UThread *newu = (UThread *)new;
    uthread_restore_helper(newu);	// XXX called twice: once too many?
    new = (BasicThread*) newu->kthread;
  } else {
    // Traps in kernel context will get pushed onto current stack, so
    // esp0 value is irrelevant
    nexustss->esp0 = 0;
    // point back to the kernel's pdbr
    Map_deactivate();
  }

  // at this point, thread is always of type KERNELTHREAD
  nexuskthread_restore((KThread *) new);
  assert(0); 
}

static void nexusthread_switch(int stop) {
  BasicThread *old, *new;
  Map *oldmap;
  int ret;

  assert(check_intr() == 0);

  /*
    DOSTOP
    DOYIELD
  */
  old = curt;
  oldmap = nexusthread_get_map(curt);

  assert(oldmap);
  assert(PADDR(Map_getRoot(oldmap)) == readcr3());

  // Must update runnability state before calling schednext()
  if (stop == DOSTOP) {

    if (old->notify_block)
      old->notify_block(old, old->callback_args);
    assert(!queue_find_eq(&run_queue, old));
    old->schedstate = WAITING;
  } else {
    /* N.B. This also adds interval processes to RR */
    assert(old->schedstate == RUNNABLE);
    nexusthread_add_to_runqueue(old, 0);
  }

  new = NULL;
  while (new == NULL) {
    new = schednext();

    if (new && new->check_sched_to) {
      /* check if it is ok to yield to new */
      if (!new->check_sched_to(old, new, new->callback_args)) {
	/* scheduling this process is not allowed; try another */
	/* N.B. This also adds interval processes to RR */
	nexusthread_add_to_runqueue(new, 0);
	new = NULL;
      }
    }

    // don't switch to blocked thread. 
    // XXX update schednext never to return a thread in this state 
    if (new->blocksema)
      new = NULL;
  }

  // Integrity checks
  assert(new->schedstate == RUNNABLE);
  // new should no longer be on run queue or intr queue
  assert(queue_find_eq(&run_queue, new) == NULL);
  assert(queue_find_eq(&intr_queue, new) == NULL);
  assert(check_intr() == 0);

  // continue with existing thread
  if (unlikely(old == new)) {
  	assert((curt)->blocksema == NULL);
	return;
  }
  
  
  // save state and switch to new thread
  if (old->type == USERTHREAD)
	  ret = nexusuthread_save((UThread *) old);
  else
	  ret = nexuskthread_save((KThread *) old);

  if (ret)
	  switch_to_new_thread(new);
}

void nexusthread_dump_regs_stack(BasicThread *t) {
  InterruptState *is = t->trap_is ? t->trap_is : t->syscall_is;
  int intlevel = disable_intr();
  printk_red("thread=%d ", t->id);
  if(t->type == USERTHREAD) {
    IPD *target_ipd = t->ipd;
    printk_red("IPD=%d ", target_ipd->id);
    if(nexusthread_ipc_stack_depth(t) > 0) {
      struct IPC_ClientContext *cctx = nexusthread_ipc_top(t);
      printk_current("In server: %d (0x%x), top locker is %d ", cctx->server_thread_id, 
		     cctx->server_thread_id, cctx->last_syscall_locker);
    }
    if(is != NULL) {
      dump_regs_is(is);
      dump_user_stack_map(target_ipd, target_ipd->map, is);
    } else {
      printk_red("trap is is null");
    }
  }
  printk_current("kernel stack: "); show_thread_stack(t, NULL, NULL, 0);
  restore_intr(intlevel);
}

void nexusthread_notify(BasicThread *t) {
  if(t->waitsema) 
	  V(t->waitsema);
}

/** Prepare a thread for dying. 
    
    Do not call directly. 
    Use nexusthread_kill for user threads, 
    nexusthread_kill_helper for kernel threads 
 */
static void nexusthread_prepexit(BasicThread *t) {

 if (t->sleepalarm) {
    Alarm *a = t->sleepalarm;
    t->sleepalarm = NULL;
    deregister_alarm(a);
  }

  if(t->schedstate == DEAD) {
    // can happen if target exits before cleaner thread removes it
    // from the thread table, and the killing thread calls kill()
    return;
  }

  if(t->schedstate == RUNNABLE) {
    int ret;
    
    ret = queue_delete(&run_queue, t);
    if (ret < 0)
      ret = queue_delete(&intr_queue, t);
    assert(ret == 0 ||t == curt);
  }
  nexusthread_notify(t);
  t->schedstate = DEAD;
  if(queue_find_eq(&run_queue, t) ||queue_find_eq(&intr_queue, t))
	  assert(0);

  int stack_depth = nexusthread_ipc_stack_depth(t);
  if(stack_depth > 0) {
    assert(stack_depth == 1);
    struct IPC_ClientContext *cctx = nexusthread_ipc_pop(t);
    IPC_ClientContext_put(cctx);
  }

  nexusthread_put(t);
}

/** Kill a thread. 
    Differentiates between killing current or other thread */
void 
nexusthread_kill_helper(BasicThread *t) 
{
  int intlevel = disable_intr();
  
  assert(t->type == USERTHREAD);
  
  if (t == curt) {
    ((UThread *) t)->exit_status = -1;
    nexusthread_exit();
  } 
  else {
    nexusthread_prepexit(t);
  }

  restore_intr(intlevel);
}

// nexusthread_check_and_do_pending_kill() should only be called from
// system call exit, interrupt return (when thread is in userspace)
void
nexusthread_check_and_do_pending_kill(BasicThread *t) 
{
  assert(t->type == USERTHREAD);
  if (swap(&t->pending_kill, 0)) { 	// XXX why clear the pending kill?
    assert(t == curt);
    nexusthread_kill_helper(t);
  }
}

void nexusthread_enter_interrupt(BasicThread *t, InterruptState *is) {
  if (!t)
    return;

  atomic_increment(&t->interrupt_nesting, 1);
  cpu_state[current_cpu()].in_interrupt = 1;
  t->trap_is = is;
}

void nexusthread_exit_interrupt(BasicThread *t, InterruptState *is) {
  if (!t)
    return;

  t->trap_is = NULL;

  int zero = atomic_decrement(&t->interrupt_nesting, 1);
  if(zero && !atomic_get(&t->in_syscall)) {
    /* We're returning to user EIP ; this is a safe point to kill the app */
    nexusthread_check_and_do_pending_kill(t);

#ifdef __NEXUSXEN__
    if(nexusthread_isXen(t)) {
      // Might not return, depending on Xen event mask 
      nexusthread_Xen_dispatchPendingEvent(t, is);
    }
#endif
  }
  // exit needs to see the in_interrupt = 1 flag
  cpu_state[current_cpu()].in_interrupt = 0;
}

/** Kill a user thread */
int nexusthread_kill(BasicThread *t) {
  UThread *ut = (UThread *)t;
  /* Thread kill can only happen in well-defined places, for otherwise
     code such as allocator, semaphores (dangling locks) can be rudely
     interrupted and compromised.
     These are:
       1. In user code (e.g. not in a system call, not in an interrupt, not in initialization code)
       2. In the middle of blocking system calls, e.g. at killable P()

       Kills are queued until the above conditions are satisfied. Note
       that it is important to check for queued kills when
       transitioning from a disallowed to an allowed region, e.g.

       1. Exiting interrupts
       2. Exiting system clals
       3. In killable P()
       4. Finish initialization
  */
  if (t->type != USERTHREAD)
    return -EINVAL;

  assert(t != curt);

  if (atomic_get(&t->pending_kill) != 0)
    return 0;

  // Disable interrupts to prevent target from being scheduled while
  // we're examining it
  int intlevel = disable_intr();

  if(!atomic_get(&t->in_syscall) &&
     !nexusthread_in_interrupt(t)) {
    // In user process. Can kill now
    nexusthread_kill_helper(t);
  } 
  else {
    // special case: not in interrupt, and target is stopped
    if(ut->in_sys_block) {
      // XXX ASHIEH 5/31/06: This implements the same crazy semantics
      // as the old kernel semaphores, where the semaphore dies right
      // away without providing an opportunity to unwind.
      //
      // This should be changed to the same exception throwing style
      // as breaking kernel semaphores
      assert(atomic_get(&t->in_syscall));
      if(atomic_get(&t->interrupt_nesting) == 0) {
	// printk("Killing a sys blocked thread right away\n");
	nexusthread_kill_helper(t);
	// XXX should it not now go to restore_intr?
      }
    }

    // tell sleeping thread to exit on wakeup
    swap(&t->pending_kill, 1);
    if (t->blocksema && sema_is_killable(t->blocksema))
      sema_wakeup_thread(t->blocksema, t);
    else
	printkx(PK_THREAD, PK_DEBUG, "[thread] unkillable thread in process %d\n", t->ipd->id);
  }

  restore_intr(intlevel);
  return 0;
}

int nexusthread_exit0(void *arg) {
	return nexusthread_exit();
}

/** Exit the current thread */
int nexusthread_exit(void) {
  BasicThread *new;
  int intlevel;

  intlevel = disable_intr();

  if(curt->sleepalarm) {
    printk_current("Exiting thread has alarm!\n");
    nexuspanic();
  }

  nexusthread_prepexit(curt);

  new = schednext();
  switch_to_new_thread(new);
  nexuspanic();
  return 0;
}

/* This looks just like a syscall */
void nexusthread_birth(void) {
  assert(check_intr() == 1);

  UThread *me = (UThread *) nexusthread_self();
  assert(me->type == USERTHREAD);

  /* make sure a thread can only call born once */
  assert(!me->born);
  me->born = 1;

  if (me->pre_fork_hook != NULL) {
    assert(check_intr() == 1);
    me->pre_fork_hook((BasicThread *)me, me->pre_fork_data);
  }

}

static void nexusthread_init_ipc(BasicThread *t);

/** Initialize the shared elements of user and kernel threads.

    We rely on gcalloc for zeroed items and only init the others explicitly */
static void
nexusthread_init_basic(struct BasicThread *basic)
{
  static int idpool;

  basic->id = ++idpool;
  assert(idpool != 0);
  
  basic->sleepsema = sema_new();
  sema_set_killable(basic->sleepsema);

  basic->ref_cnt = 1;
  basic->in_syscall = 1;
  basic->sched_type = SCHEDTYPE_ROUNDROBIN;
  
  basic->personality.mutex = SEMA_MUTEX_INIT;

  nexusthread_init_ipc(basic);
}

static KThread *
nexuskthread_create(proc_t proc, arg_t arg) 
{
  KThread *newt;

  newt = gcalloc(1, sizeof(KThread));
  nexusthread_init_basic((BasicThread *) newt);
  
  newt->type = KERNELTHREAD;
  newt->kts = gcalloc(1, sizeof(KernelThreadState));
  newt->ipd = kernelIPD;
  kernelIPD->threadcount++;

  // initialize top of stack for first context switch
  nexusthread_allocate_stack(&newt->stackbase, &newt->kts->esp);
  nexusthread_initialize_state(newt->kts, proc, arg, nexusthread_exit0, NULL);

  P(&threadTable_mutex);
  hash_insert(threadTable, &newt->id, newt);
  V(&threadTable_mutex);

  return newt;
}

/** Allocate and initialize a user thread */
UThread *
nexusuthread_create(Map *map, unsigned int pc, unsigned int sp, IPD *ipd, 
		    thread_callback_t pre_fork_hook, void *pre_fork_data) {
  UThread *newt;

  assert(ipd);

  newt = gcalloc(1, sizeof(UThread));
  nexusthread_init_basic((BasicThread *) newt);
 
  newt->type = USERTHREAD;
  newt->uts = UserThreadState_new();
  
  // set process 
  newt->ipd = ipd;
  ipd->threadcount++;
  ipd_add_uthread(ipd, newt, &newt->id);
  
  // set memory map
  newt->map = map;
  Map_up_active_thread_count(map);

  newt->schedstate = NOT_YET_RUN;

  newt->pre_fork_hook = pre_fork_hook;
  newt->pre_fork_data = pre_fork_data;
  newt->kthread = nexuskthread_create((void*) nexusuthread_goto_user, newt);

  P(&threadTable_mutex);
  hash_insert(threadTable, &newt->id, newt);
  V(&threadTable_mutex);

  newt->kernel_esp = newt->kthread->kts->esp;

  // Reserve some stack space for interrupt state scratch area
  // Needed by Xen-style xen_regs layout for es,ds,fs,gs
  newt->kernel_esp -= 32;
  // store initial pc, sp etc in the state
  nexusthread_initialize_ustate(newt->uts, pc, sp);

#ifdef __NEXUSXEN__
  // If the IPD is xen, switch the initial segments
  if (ipd->type == XEN) {
	  newt->uts->ss = newt->uts->ds = newt->uts->es = KXENDS;
	  newt->uts->cs = KXENCS;
  }
#endif

  return newt;
}

int nexusthread_ipc_stack_depth(BasicThread *thread) {
  return thread->ipc.stack_depth;
}

struct IPC_ClientContext *
nexusthread_ipc_top_and_syscall_lock(BasicThread *thread) {
  struct IPC_ClientContext *rv = thread->ipc.client_top;

  if(0 && nexusthread_id(nexusthread_self()) == 443) {
    printk_red("curr locker = %d", rv->last_syscall_locker);
  }

  // Keep trying to acquire syscall lock. This is tricky because the
  // top of the stack might change while we're waiting!
  if(0 && (nexusthread_current_ipd()->id == 10 || nexusthread_current_ipd()->id == 11)) {
    printk_red("(sc lock try %d by %d)", thread->id, nexusthread_self()->id);
  }
  while(1) {
    if(rv == NULL) {
      return NULL;
    }

    P(&rv->common_ctx.callee_syscall_sema);
    if((thread->ipc.client_top == rv)) {
      break;
    }
    rv = thread->ipc.client_top;
  }
  if(0 && (nexusthread_current_ipd()->id == 10 || nexusthread_current_ipd()->id == 11)) {
    printk_green("(sc lock got %d by %d)", 
		 thread->id,
		 nexusthread_self()->id);
    if(149 == thread->id && 173 == nexusthread_self()->id) {
      int intlevel = disable_intr();
      show_stack(NULL);
      restore_intr(intlevel);
    }
  }
  rv->last_syscall_locker = nexusthread_id(nexusthread_self());
  return rv;
}

struct IPC_Port **
IPC_CommonClientContext_allocTapList(IPC_CommonClientContext *common_ctx,
			       IPD *source_ipd, IPD *dest_ipd, int num_taps) {
  common_ctx->taplist_source_ipd = source_ipd;
  common_ctx->taplist_dest_ipd = dest_ipd;

  common_ctx->num_taps = num_taps;
  if(num_taps > 0) {
    if(num_taps <= MAX_FAST_TAP_LIST_LEN) {
      common_ctx->taps = common_ctx->fast_taplist;
    } else {
      common_ctx->taps = gcalloc(num_taps, sizeof(void *));
    }
  }
  return common_ctx->taps;
}

static inline void
get_put_helper(int do_get, struct TransferDesc *desc) 
{
  if(TransferDesc_get_kmode(desc) == IPC_KMODE_PHYSICAL) {
    unsigned int page_base;
    for( page_base = desc->u.direct.base & PAGE_MASK ;
	page_base < desc->u.direct.base + desc->u.direct.length ;
	 page_base += PAGE_SIZE ) {
      Page *p = PHYS_TO_PAGE(page_base);
      if(do_get) {
	Page_get(p);
      } else {
	freeKernelPages((void *)VADDR(p), 1);
      }
    }
  }
}

void TransferDesc_get_phys_pages(struct TransferDesc *desc) {
  get_put_helper(1, desc);
}

static void TransferDesc_put_phys_pages(struct TransferDesc *desc) {
  get_put_helper(0, desc);
}

void IPC_CommonClientContext_clean(IPC_CommonClientContext *common_ctx) {
  // Return to a "clean" state
  if(common_ctx->connection != NULL) {
    IPCConnection_put(common_ctx->connection);
    common_ctx->connection = NULL;
  }

  if(common_ctx->num_taps > 0) {
    assert(common_ctx->taps != NULL);
    // printk_green("dealloc %p ", common_ctx->taps);
    int i;
    for(i=0; i < common_ctx->num_taps; i++) {
      IPCPort_put(common_ctx->taps[i]);
    }
    if(common_ctx->taps != common_ctx->fast_taplist) {
      gfree(common_ctx->taps);
    }
  }
  common_ctx->connection = NULL;
  common_ctx->num_taps = 0;
  common_ctx->taps = NULL;

  int i;
  for(i=0; i < common_ctx->num_transfer_descs; i++) {
    TransferDesc_put_phys_pages(&common_ctx->transfer_descs[i]);
  }
  for(i=0; i < common_ctx->num_kernel_transfer_descs; i++) {
    TransferDesc_put_phys_pages(&common_ctx->kernel_transfer_descs[i].desc);
  }
  common_ctx->num_transfer_descs = 0;
  common_ctx->num_kernel_transfer_descs = 0;
}

void IPC_CommonClientContext_dealloc(IPC_CommonClientContext *common_ctx) {
  IPC_CommonClientContext_clean(common_ctx);
  // There might be some waiting syscalls

  sema_wake_all(&common_ctx->callee_syscall_sema);
  sema_dealloc(&common_ctx->callee_syscall_sema);
  memset(&common_ctx->callee_syscall_sema, 0x3e, sizeof(common_ctx->callee_syscall_sema));
}

void IPC_ClientContext_dealloc(struct IPC_ClientContext *cctx) {
  IPC_CommonClientContext_dealloc(&cctx->common_ctx);
  gfree(cctx);
}

static void IPC_ServerContext_init(struct IPC_ServerContext *sctx) {
  sctx->mutex = sema_new_mutex();
  sctx->call_sema_0 = sema_new();
  sema_set_killable(sctx->call_sema_0);

  sctx->callee_state = CALLEESTATE_AVAILABLE;
}

static void IPC_ServerContext_dealloc(struct IPC_ServerContext *sctx) {
  sema_destroy(sctx->mutex);
  if(sctx->caller != NULL) {
    nexusthread_put((BasicThread*)sctx->caller);
  }
  sema_destroy(sctx->call_sema_0);
}

static void nexusthread_init_ipc(BasicThread *t) {
  IPC_ServerContext_init(&t->ipc.server);
}

/*
 *	Create and schedule a new thread of control so
 *	that it starts executing inside proc_t with
 *	initial argument arg.
 */
KThread *nexusthread_fork(proc_t proc, arg_t arg) {
  KThread *newt;

  newt = nexuskthread_create(proc, arg);
  nexusthread_start((BasicThread *)newt, 0);
  return newt;
}

/*
 *	Return identity of caller thread.
 */
BasicThread *
nexusthread_find(int id) 
{
  BasicThread *bt;

  P(&threadTable_mutex);
  bt = (BasicThread *) hash_findItem(threadTable, &id);
  if (bt) {
	  if (bt->type == USERTHREAD) {
		  // about to be reaped?
		  if (atomic_get(&bt->ref_cnt) == 0)
		  	bt = NULL;
		  else
		  	nexusthread_get(bt);
	  }
  }
  V(&threadTable_mutex);

  return bt;
}

/*
 *	Return Map of current thread if it is a user thread.
 */

Map *nexusthread_get_map(BasicThread *t) {
  if (t->type == USERTHREAD)
    return ((UThread *)t)->map;
  else
    return kernelMap;
}

int 
nexusthread_current_ipd_id(void) 
{
	IPD *ipd;

	if (!curt) 
    		return -1;

	return nexusthread_current_base_ipd()->id;
}

/* only move to intr_queue if it is already on the run queue (or running). */
int nexusthread_move_to_intrqueue(int thread_id) {
  BasicThread *t;
  int ret;

  assert(check_intr() == 0); /* called from interrupt context */

  t = (BasicThread *) hash_findItem(threadTable, &thread_id);
  assert(t);

  if (curt == t)
    return 0;

  if(!queue_find_eq(&run_queue, t))
    return -1;

  ret = queue_delete(&run_queue, t);
  assert(ret == 0);

  assert(t->schedstate == RUNNABLE);
  queue_append(&intr_queue, t);
  
  return 0;
}

void nexusthread_start(BasicThread *t, int at_front) {
  int intlevel = disable_intr();
  t->schedstate = RUNNABLE;
  nexusthread_add_to_runqueue(t, at_front);
  t->start_tick = nexustime;
  restore_intr(intlevel);
}

void nexusthread_start_if_not_run(UThread *t, void *unused){
  if (t->schedstate == NOT_YET_RUN)
    nexusthread_start((BasicThread *)t, 0);
}

/* Block the calling thread. */
void nexusthread_stop(void) {
  assert(check_intr() == 0);
  assert(get_preemption());
  nexusthread_switch(DOSTOP);
}


/*
 *	Forces the caller to relinquish the processor and be put to the end of
 *	the ready queue.  Allows another thread to run.
 */
void nexusthread_yield_i(void) {
   assert(check_intr() == 0);

  /* in case preemption happened when no one was runnable
   * we don't want lots of idle interrupt processes hanging around */
  if(curt->schedstate != RUNNABLE) {
    printk_red("preemption happened when no threads runnable");
    dump_stack();
    nexuspanic();
  }
  nexusthread_switch(DOYIELD);
  assert(check_intr() == 0);
}

void nexusthread_yield(void) {
  assert(check_intr() == 1);
  disable_intr();
  nexusthread_yield_i();
  enable_intr();
}

/* put a thread to sleep for delta ticks */
int nexusthread_sleep(int delta) {
  if (!curt) 
    return -1;

  if (!delta)
    return 0;

  assert(curt->sleepsema);
  curt->sleepalarm = register_alarm(delta, (void *)V, (void *)curt->sleepsema);
  if (P(curt->sleepsema)) {
    /* killed */
    deregister_alarm(curt->sleepalarm);
    curt->sleepalarm = NULL;
    return -1;
  }

  curt->sleepalarm = NULL;
  return 0;
}

/* Block a thread for up to delta ticks.
   Can be called with interrupts enabled

   @param userlock: a spinlock held from userspace, or NULL 
   @return 0 if timeout occurred or 1 if awoken from sleep */
int nexusthread_block(int msecs)
{
    int ret; 

    assert(curt && curt->type == USERTHREAD);

    if (msecs) {
      ret = nexusthread_sleep((msecs * 1000)/ USECPERTICK) ? 1 : 0;
    }
    else {
      ((UThread * ) curt)->in_sys_block = 1;
      nexusthread_stop();
      ((UThread *) curt)->in_sys_block = 0;
      ret = 1;
    }

done:
    return ret;
}

void nexusthread_unblock(int thread)
{
    BasicThread *t;
    int intlevel;

    t = nexusthread_find(thread);

    // sanity checks
    if (!t)
      return;
    if (t->type != USERTHREAD ||
        nexusthread_get_base_ipd(t) != nexusthread_current_ipd()) {
      nexusthread_put(t);
      return;
    }
    
    intlevel = disable_intr();

    // sleeping on timer or blocked onconditionally?
    if (t->sleepalarm)
	nexusthread_cancelsleep(t);
    else if (t->schedstate == WAITING) 
	nexusthread_start(t, 1);

    restore_intr(intlevel);
    nexusthread_put(t);
}

int nexusthread_cancelsleep(BasicThread * t) {
  struct Alarm *a;

  if (!t->sleepalarm) 
	  return -1;
  
  a = t->sleepalarm;
  t->sleepalarm = NULL;
  deregister_alarm_and_fire(a);

  return 0;
}

void nexusthread_dump(void) {
  printk("Current thread is %d, type %d\n", curt->id, curt->type);
}

/** schedule removal of a thread.
    may ONLY be called from nexusthread_put */
void 
nexusthread_del(BasicThread *dead) 
{
  int intlevel;

  assert(dead->ref_cnt == 0);
  assert(dead->id != 1);
  assert(dead->ipd && --dead->ipd->threadcount >= 0);

  intlevel = disable_intr();
  uqueue_enqueue(dead_thread_queue, dead);
  restore_intr(intlevel);
  V(&dead_thread_sema);
}

/** Callback function that destroys a thread. 
    Continues nexusthread_del's work from a dedicated reaper thread.
    Do NOT call directly*/
static void 
__nexusthread_del(BasicThread *dead) 
{
  // Clear thread from interval scheduler
  switch(dead->sched_type) {
  case SCHEDTYPE_INTERVAL: {
    // remove from intervals array
    int i;
    for(i = 0; i < INTERVAL_LENGTH; i++) {
      if (intervals[i] == dead)
        intervals[i] = NULL;
    }
    break;
  }
  case SCHEDTYPE_ROUNDROBIN:
    // nothing to do
    break;
  default:
    assert(0);
  }

  // release IPC contexts
  IPC_ServerContext_dealloc(&dead->ipc.server);
  int stack_depth = nexusthread_ipc_stack_depth(dead);
  if(stack_depth > 0) {
    assert(stack_depth == 1);
    struct IPC_ClientContext *cctx = nexusthread_ipc_pop(dead);
    IPC_ClientContext_put(cctx);
  }

  if (dead->type == USERTHREAD) {
    UThread *udead = (UThread *)dead;

    assert(!udead->waitsema);
    ipd_rm_uthread(udead->ipd, &udead->id);

    sema_destroy(udead->sleepsema);
    UserThreadState_destroy(udead->uts);

    Map_down_active_thread_count(udead->map);
    Map_destroy(udead->map);

    nexusthread_free_stack((BasicThread *)udead->kthread, udead->kthread->stackbase);
    KernelThreadState_destroy((BasicThread *)udead, udead->kthread->kts);

    P(&threadTable_mutex);
    hash_delete(threadTable, &udead->kthread->id);
    hash_delete(threadTable, &udead->id);
    V(&threadTable_mutex);

    gfree(udead->kthread);
  } 
  else {
    KThread *kdead = (KThread *)dead;
    nexusthread_free_stack((BasicThread *)kdead, kdead->stackbase);
    gfree(kdead->kts);
  }
  
  // Destroy process if this was the last thread
  if (!dead->ipd->threadcount)
    ipd_del(dead->ipd);

  gfree(dead);
}

/** Kernel tasks that reaps dead threads.
    Link between nexusthread_del and __nexusthread_del */
static int
nexusthread_reap_threads(void *unused)
{
	BasicThread *t;

	while (1) {
    		P(&dead_thread_sema);
		t = uqueue_dequeue(dead_thread_queue);
		assert(t);
#ifndef __NEXUSXEN__
		printk("REMINDER: not reaping. causes pgfault without XEN\n");
#else
      		__nexusthread_del(t);
#endif

		printkx(PK_THREAD, PK_DEBUG, "reaped thread %d\n", t->id);
	}

	// not reached
	return -1;
}

/*
 *	Initialize the system to run the first nexusthread at
 *	mainproc(mainarg). Must be called during kernel init 
 */
void nexusthread_init(proc_t mainproc, arg_t mainarg) {
  KThread *init;

  threadTable = hash_new(THREAD_TABLE_SIZE, sizeof(int));

  // setup the structures for this initial thread
  init = nexuskthread_create(NULL, NULL);
  init->schedstate = RUNNABLE;
  assert(init->id == 1);
  curt = (BasicThread *) init;

  // fork off timer thread
  nexusthread_fork(timer_worker, NULL);

  // fork of general purpose delayed task handlers
  task_init(); 

  // fork off reaper thread
  dead_thread_queue = uqueue_new();
  nexusthread_fork(nexusthread_reap_threads, NULL); 
  
  preemption_enabled = 1;
  nexusthread_yield();
 
  // start the init task
  mainproc(mainarg);

}

#ifndef NDEBUG 
///// Debugging code

static void print_thread_common(struct BasicThread *thread) {
  const char *state;

  switch(thread->schedstate) {
	case RUNNABLE	: state = "RUNNABLE"; break;
	case WAITING	: state = "WAITING"; break;
	case DEAD	: state = "DEAD"; break;
 	default		: assert(0); /* never reached */ return; 
  }
  printk_red("id=%d, pid=%d, state=%s, ", thread->id, 
	     thread->ipd ? thread->ipd->id : -1, state);
  // according to structure of nexusthread_switch, esp+24 is the return address
  switch(thread->type) {
  case USERTHREAD: 
  {
    struct UThread *uthread = (struct UThread *)thread;
    printk("kid: %d, eip: %x, stack_bottom: %x\n", uthread->kthread->id, 
	   uthread->kthread->kts->eip, uthread->kernel_esp);
    break;
  }
  case KERNELTHREAD:
  {
    struct KThread *kthread = (struct KThread *)thread;
    printk("eip: %x\n", kthread->kts->eip);
    break;
  }
  }
}

static int print_thread(void *_thread, void *ignored) {
  struct BasicThread *thread = (struct BasicThread *)_thread;
  switch(thread->type) {
  case USERTHREAD:
    printk_current("User thread {");
    print_thread_common(thread);
    break;
  case KERNELTHREAD:
    printk_current("Kernel thread {");
    print_thread_common(thread);
    break;
  }
  printk_current("}\n");
  return 0;
}

void nexusdumprunqueue(void) {
  int x;

  printk_current("Intr queue: ");
  queue_iterate(&intr_queue, print_thread, NULL);
  printk_current("Run queue: ");
  queue_iterate(&run_queue, print_thread, NULL);
  printk_current("\n");
  printk_current("Curt: %p - %d\n", curt, curt != NULL ? curt->id : -1);
  if(curt != NULL) {
    print_thread(curt, NULL);
  }
  printk_current("kernel stack is at %p\n", &x);
  nexus_timer(NULL);
}

void dump_current_thread(void) {
  if (curt)
    print_thread(curt, NULL);
}

void print_threads_mem(void){
  int i;
  Map *oldmap = NULL;
  for(i=0; i < 10000; i++) {
    BasicThread *bt = nexusthread_find(i);
    if(bt != NULL) {
      if(bt->type == USERTHREAD){
	UThread *ut = (UThread *)bt;
	if(ut->map != oldmap)
	  printk_red("ipd_id=%d, numpgs=%d\n", ut->ipd->id, Map_pagesused(ut->map));
	oldmap = ut->map;
      }
    }
  }
}

void print_all_threads(void) {
  int i;
  int do_print = 0;
  for(i=0; i < 10000; i++) {
    BasicThread *bt = nexusthread_find(i);
    if(bt != NULL) {
      if(bt->type == USERTHREAD) {
	do_print = 1;
	// XXX possible race condition
	nexusthread_put(bt);
      }
    }
  }
  for(i=0; i < 10000; i++) {
    BasicThread *bt = nexusthread_find(i);
    if(bt != NULL) {
      if(do_print) {
	if(bt->type == USERTHREAD)
	  print_thread(bt, 0);
      }
      if(bt->type == USERTHREAD) {
	nexusthread_put(bt);
      }
    }
  }
  if(do_print) {
          printk("=====\n");
  }
}

void thread_stack(int i) {
	BasicThread *bt = nexusthread_find(i);
	if (!bt) {
		printk("Thread[%d]: no such thread\n", i);
		return;
	}
	if (bt == curt) {
		printk("Thread[%d]: currently executing\n", i);
	} else if (bt->type == KERNELTHREAD) {
		printk("Thread[%d]: KERNELTHREAD\n", i);
		show_trace((unsigned long *)((KThread *)bt)->kts->esp);
	} else {
		printk("Thread[%d]: USERTHREAD\n", i);
		show_trace((unsigned long *)((UThread *)bt)->kernel_esp);
	}
}

static void selector_test(__u16 selector) {
	printk("Testing selectors %x\n", selector);
	printk("selector load/restore...");
	__u32 ignored1, ignored2, ignored3;

	__asm__ __volatile__ (
"mov %%ds, %%ebx\n"
"mov %%eax, %%ds\n"
"\n"
"mov %%ebx, %%eax\n"
"mov %%eax, %%ds\n"
: "=a" (ignored1), "=b" (ignored2) : "a" (selector) );
	printk("\n");

	printk("selector read...");
	__asm__ __volatile__ (
"mov %%ds, %%ecx\n"
"mov %%eax, %%ds\n"
"\n"
"/* Should page fault */\n"
"/* mov $0xaffffff0, %%eax */\n"
"mov $0xb7fffff0, %%eax\n"
"mov (%%eax), %%ebx\n"
"\n"
"/* Should gpf */\n"
"/* mov $0xafffffff, %%eax */\n"
"mov $0xb7ffffff, %%eax\n"
"mov (%%eax), %%ebx\n"
"\n"
"\n"
 "/* should pagefault */\n"
"mov $0x0, %%eax\n"
"mov (%%eax), %%ebx\n"
"\n"
"mov %%ecx, %%eax\n"
"mov %%eax, %%ds\n"
: "=a" (ignored1), "=b" (ignored2), "=c" (ignored3) : "a" (selector) );
}

void run_selector_tests(void) 
{
	/// all tests were disabled
}

#endif /* not NDEBUG */

/**************** Various ***************/

KernelThreadState *thread_getKTS(BasicThread *t) {
  if(t->type == KERNELTHREAD) {
    KThread *kt = (KThread *)t;
    return kt->kts;
  } else {
    UThread *ut = (UThread *)t;
    return ut->kthread->kts;
  }
}

__u64 nexusthread_get_cycles(BasicThread *t){
  if(t->type == KERNELTHREAD){
    KThread *kt = (KThread *)t;
    return kt->cycles_used;
  }else {
    UThread *ut = (UThread *)t;
    return ut->kthread->cycles_used;
  }
}

