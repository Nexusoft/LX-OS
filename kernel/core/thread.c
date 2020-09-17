#define DO_PARANOID/** Nexus OS: threads */

#include <asm/hw_irq.h>
#include <asm/param.h>
#include <asm/io.h>
#include <asm/errno.h>
#include <linux/smp.h>

#include <nexus/defs.h>
#include <nexus/thread.h>
#include <nexus/synch.h>
#include <nexus/synch-inline.h>
#include <nexus/queue.h>
#include <nexus/mem.h>
#include <nexus/profiler.h>
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
#include <nexus/net.h>
#include <nexus/ipc_private.h>
#include <nexus/handle.h>

#define STACKSIZE_PAGES (4)

////////  shared variables  ////////
// (keep these to a minum)

BasicThread *curt;			///< current thread
Map *curr_map;				///< current map

// preemption is off until explicitly turned on
volatile int preemption_enabled;

int nxkey_press = 1;			///< respond differently to IRQs

int nexusthread_account_show;		///< toggle cyclecount printing 

/// Queue all threads ready to be reaped 
static UQueue *dead_thread_queue;
static Sema dead_thread_sema = SEMA_INIT_KILLABLE; 

/// Lookup thread id to struct
struct HashTable *threadTable;
struct Sema threadTable_mutex = SEMA_MUTEX_INIT;

/// Rough idletime counters
uint64_t nexusthread_idle_now, nexusthread_idle_last;

////////  special operating modes (idle, ..)  ////////

/** Spin down the CPU while idle */
void
nexusthread_idle(void)
{
	uint64_t idle_start;

	idle_start = rdtsc64();
	enable_intr();
	asm volatile ("hlt");
	disable_intr();

	nexusthread_idle_now += rdtsc64() - idle_start;
}

/** Return CPU activity on a scale from 0 (idle) to 100 
    The value should not be interpreted to strictly as
    `idle percentage in the last second' or so. 
    For performance reasons, it's a rough estimate at best */
int 
nexusthread_cpuload(void)
{
	uint64_t idle_ratio;
	int load;

	idle_ratio = 100 * nexusthread_idle_last;
	idle_ratio /= nxclock_rate / HZ;

	load = 100 - idle_ratio;
	return load >= 0 ? load : 0;
}

/** Hang the system and wait for reboot */
void
nexusthread_panicmode(void)
{
	nxkey_press = 0;
	disable_preemption(); 	// don't switch tasks
	enable_intr();
	while (!nxkey_press) {
		// wait for keyboard interrupt
	}

	machine_restart();
}

/** Print a kernel Oops, hang the system, and wait for reboot */
void 
nexuspanicfn(const char *file, int line) 
{
	dump_stack_current(NULL);
	printk_red("[panic] Kernel hung.\n");
	while (1) {}
	//nexusthread_panicmode();
}

void 
assertlf(int linenum, const char *file) 
{
  // disable interrupts to prevent mixing of output with that of other thread
  disable_intr();

// DEBUG XXX REMOVE
#define DO_PARANOID
#ifdef DO_PARANOID
	  uint64_t tend;
	  printk_red("[assert] spinning...\n");
	  // sleep and print a bit
	  tend = rdtsc64() + (1ULL << 32);
	  while (rdtsc64() < tend) {}
#endif

  if (curt)
    printk_red("[%d] %s: Assertion failed at %s:%d in thr=%d\n", 
	       curt->ipd->id, curt->ipd->name, file, linenum, curt->id); 
  else
    printk_red("[0] kernel: Assertion failed at %s:%d in thr=0\n",
	       file, linenum);

  nexuspanicfn(file, linenum);
}

////////  task switching (low level)  ////////

// Top-level save routines must be implemented in assembly language to
// avoid clobbering saved registers and stack contents between save /
// restore
int nexuskthread_save(KThread *kt);
int nexusuthread_save(UThread *ut);

/** sub of nexuskthread_save: save state of a kernel thread (registers) */
KernelThreadState *nexuskthread_save_c0(KThread *kt) {
  return kt->kts;
}

/** restore state of a kernel thread (registers) */
void nexuskthread_restore(KThread *kt) {
  nexustss->ss1 = kt->kts->ss1;
  nexustss->esp1 = kt->kts->esp1;
  nexustss->ss2 = kt->kts->ss2;
  nexustss->esp2 = kt->kts->esp2;
  nexuskthread_restorestate(kt->kts);
}

#ifdef __NEXUSXEN__
int
nexusthread_isXen(BasicThread *bt) 
{
  return (unlikely(bt->type == USERTHREAD && bt->ipd->type == XEN)) ? 1 : 0;
}
#endif

/** sub of nexusuthread_save: save state of a user thread (registers) */
KThread *nexusuthread_save_c(UThread *ut) {

#ifdef __NEXUSXEN__
  if (unlikely(nexusthread_isXen((BasicThread *)ut)))
    thread_Xen_switchOut((BasicThread *)ut);
#endif

  return ut->kthread;
}

void nexusthread_fpu_trap(void) {
  UThread *owner;
  
  clts();
  
  // Save registers of old thread
  owner = cpu_state[current_cpu()].fxstate_owner;
  if (owner)
    fxsave_registers(owner->uts->fxstate);

    // switch to new thread
  assert(curt->type == USERTHREAD);
  cpu_state[current_cpu()].fxstate_owner = curt;
  fxrstor_registers(curt->uts->fxstate);
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

  is->errorcode = uts->errorcode;
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

  //set TSS
  KernelThreadState_syncTSS(newu->kthread->kts);
  changeTSSesp0(newu->kernel_esp);
  
  Map_activate(newu->ipd->map, (BasicThread *)newu);
  
  // Update the shared info page
#ifdef __NEXUSXEN__
  if (unlikely(nexusthread_isXen((BasicThread *) newu)))
    thread_Xen_switchIn((BasicThread *) newu);
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


////////  task switching (high level)  ////////

/** Switch to a new thread. 
    Locking: call with interrupts disabled. 
             they will be enabled in the new thread */
static void __attribute__((noreturn))
__nexusthread_switch_new(BasicThread *new) 
{
  assert(check_intr() == 0);
  curt = new;

#ifdef __NEXUSXEN__
  if(unlikely(inXenDomain())) {
      // Simplify handling of NM by always doing a full FPU context
      // switch to a Xen domain.  We can potentially do something more
      // efficient in the future.

    // This must occur 
    // AFTER curt because nexusthread_fpu_trap() requires curt == new and 
    // BEFORE uthread_restore_helper() as that restores the Nexus TS bit state

    nexusthread_fpu_trap();
  }
  else
#endif
    stts();	// have CPU notify if x87 FP was used
  
  if (new->type == USERTHREAD) {
    UThread *newu = (UThread *)new;
    uthread_restore_helper(newu);	// XXX called twice: once too many?
    new = (BasicThread*) newu->kthread;
  } 
  else {
    // Traps in kernel context will get pushed onto current stack, so
    // esp0 value is irrelevant
    nexustss->esp0 = 0;
    // point back to the kernel's pdbr
    Map_deactivate();
  }

  // at this point, thread is always of type KERNELTHREAD
  nexuskthread_restore((KThread *) new);

  // not reached
  nexuspanic();
  while (1) {}
}

#if NXCONFIG_PROFILE_SCHED
  static unsigned long sched_threadswitch;	///< total #switches
  static unsigned long sched_taskswitch;	///< #switches between tasks
  static unsigned long sched_noswitch;		///< #switches to same thread
  static unsigned long sched_yield, sched_stop, sched_sleep;
#endif
uint64_t sched_idle, sched_tswitch, sched_int;

/** Calculate totals for all threads and start a new timing epoch.
    For correct measurement, call with interrupts disabled. 
 
    XXX disable summing if nexusthread_account_show is disabled. */
void
nexusthread_account_sum(void)
{
	static uint64_t cycles_save;
	uint64_t cycles_now, cycles_counted, cycles_used;

	int __clear(void *_item, void *unused)
	{
		((BasicThread *)_item)->cycles = 0;
		return 0;
	}

	// function calling over all items (expensive)
	int __sum(void *_item, void *unused)
	{
		BasicThread *item = _item;

		if (unlikely(item->cycles > 1 << 23))
			printk_current("        %.3d.%c.%.3d: %lu mcyc (user=%lu%s%s)\n",
				       item->ipd->id, 
				       item->type == USERTHREAD ? 'u' : 'k',
		               	       item->id, 
				       item->cycles >> 20,
#if NXCONFIG_CYCLECOUNT_USER
				       item->cycles_user >> 20,
#else
				       0,
#endif
				       item->name ? " name=" : "",
				       item->name ? item->name : "");

#if NXCONFIG_CYCLECOUNT_USER
		cycles_used += item->cycles;
		item->cycles_user = item->cycles = 0;
#endif
		return 0;
	}

	cycles_now = rdtsc64();
	
	// four cases
	if (!cycles_save) {
		// (1) start reporting: clear state
		if (nexusthread_account_show) {
			cycles_save = cycles_now;
			hash_iterate(threadTable, __clear, NULL);
#if NXCONFIG_PROFILE_SCHED
			sched_threadswitch = sched_taskswitch = sched_noswitch = 0;
			sched_yield = sched_stop = sched_sleep = 0;
#endif
		}
		// (2) not reporting: NOOP
		return;

	}

	// (2) stop reporting: update reporting state
	if (!nexusthread_account_show) {
		cycles_save = 0;
		return;
	}

	// (3) save data and report
	cycles_counted = cycles_now - cycles_save;

	// iterate over entries
	cycles_used = 0;
	hash_iterate(threadTable, __sum, NULL);
	printk_current("        idle loop: %lu mcyc\n", sched_idle >> 20);

	// print epilogue
	printk_current("[sched] mcyc=%llu used=%llu idle=%llu sched=%llu int=%llu idleloop\n"
#if NXCONFIG_PROFILE_SCHED
		       " switch [th=%lu proc=%lu noswitch=%lu] method [yield=%lu stop=%lu sleep=%lu]\n"
#endif
			   ,
			   cycles_counted >> 20, 
			   cycles_used >> 20,
			   (cycles_counted - cycles_used) >> 20, 
			   sched_tswitch >> 20,
			   sched_int >> 20
#if NXCONFIG_PROFILE_SCHED
			   ,
			   sched_threadswitch,
			   sched_taskswitch,
			   sched_noswitch,
			   sched_yield,
			   sched_stop,
			   sched_sleep
#endif
			   );
	cycles_save = cycles_now;
#if NXCONFIG_PROFILE_SCHED
	sched_threadswitch = sched_taskswitch = sched_noswitch = 0;
	sched_yield = sched_stop = sched_sleep = 0;
#endif
	sched_int = sched_tswitch = sched_idle = 0;
}

int debug_noint;

/** Return the number of POSIX clock ticks (1M per sec) spent in
    the thread or process, depending on value of @param do_process */
unsigned long long
nexusthread_times(BasicThread *t, int do_process, int do_user)
{
	unsigned long long cycles;

	// obtain data for single thread
	if (!do_process)
#if NXCONFIG_CYCLECOUNT_USER
		cycles = do_user ? t->cycles_utotal : t->cycles_total;
#else
	{
		printk_red("[sched] WARN: times(2) requires CYCLECOUNT_USER");
		cycles = 0;
	}
#endif

	// obtain data for whole process
	else {
		int __sum(void *_item, void *unused)
		{
			BasicThread *item = _item;
#if NXCONFIG_CYCLECOUNT_USER
			cycles += do_user ? item->cycles_utotal : item->cycles_total;
#else
			cycles += do_user ? 0 : item->cycles_total;
#endif
			return 0;
		}

		cycles = 0;
  		P(&t->ipd->mutex);
		hash_iterate(t->ipd->uthreadtable, __sum, NULL);
		V(&t->ipd->mutex);
	}

	// convert to posix format
	cycles *= 1000 * 1000;	// # Posix 'clockticks'
	cycles /= nxclock_rate;
	return cycles;
}


/*
  DOSTOP
  DOYIELD
  
  can be called from alarm interrupt to preempt
  or as the result of syscall such as yield: 
  both int and non-int contexts
*/
static void 
nexusthread_switch(int stop) {
  static uint64_t cycles_last;
  extern unsigned long nexustime_last_switch;
  extern uint64_t cycles_idleloop;
  uint64_t cycles_cur, cdiff;
  BasicThread *old, *new;
  int ret;

  cycles_cur = rdtsc64();
  old = curt;

  assert(check_intr() == 0 &&
  	 ((stop == DOSTOP && (old->schedstate == WAITING || old->schedstate == DEAD)) || 
	  (stop == DOYIELD && old->schedstate == RUNNABLE)) &&
  	 !old->scheduled);
 
  // update runnability state before calling scheduler
  if (stop == DOYIELD)
    nxsched_enqueue(old, 0, 0);

  // Charge cycles when a thread retires
  //  Once per $timeunit, totals are made up,
  //  where $timeunit is set in the alarm interrupt handler (clock.c)
  if (likely(cycles_last)) {
  	cdiff = cycles_cur - cycles_last;

	// account all cycles since last switch to this thread
	old->cycles += (unsigned long) cdiff;
	old->cycles_total += cdiff;
	
#if NXCONFIG_CYCLECOUNT_USER
	// account all cycles in user component to this thread
	if (old->cycles_ustart && !old->syscall_is) {
		cdiff = cycles_cur - old->cycles_ustart;
		old->cycles_utotal += cdiff;
		old->cycles_user += cdiff;
		old->cycles_ustart = 0;
	}
#endif
  }

  new = nxsched_schedule();

#if NXCONFIG_PROFILE_SCHED
  sched_threadswitch++;
  if (new == old)
	  sched_noswitch++;
  else if (new->ipd == old->ipd)
	  sched_taskswitch++;
#endif
  
  // Integrity checks
  assert(new &&
         new->schedstate == RUNNABLE &&
  	 ! new->scheduled &&
  	 ! new->blocksema &&
  	 check_intr() == 0);

  // Start cycle counting when a thread is scheduled
  cycles_last = rdtsc64();
  nexustime_last_switch = nexustime;
  sched_tswitch += cycles_last - cycles_cur - cycles_idleloop;
#if NXCONFIG_CYCLECOUNT_USER
  if (!new->syscall_is)
	  new->cycles_ustart = cycles_last;
#endif

  // continue with existing thread
  if (unlikely(old == new))
	return;
  
  // save state and switch to new thread
  if (old->type == USERTHREAD)
	  ret = nexusuthread_save((UThread *) old);
  else
	  ret = nexuskthread_save((KThread *) old);

  if (ret)
	  __nexusthread_switch_new(new);
}


//////  Initialize and start  ////////

int
nexusthread_setname(const char *name)
{
	int len;

	len = strlen(name) + 1;
	if (len >= 100)
		return -1;

	if (curt->name)
		gfree(curt->name);

	curt->name = galloc(len);
	memcpy(curt->name, name, len);
	return 0;
}

/** Initialize the shared elements of user and kernel threads.
    We rely on gcalloc for zeroed items and only init the others explicitly */
static void
nexusthread_init_basic(struct BasicThread *basic)
{
  static int idpool;

  basic->id = ++idpool;
  assert(idpool != 0);
  
  basic->rpc_wait = SEMA_INIT_KILLABLE;
  basic->rpc_ready = SEMA_INIT_KILLABLE;
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
  newt->stackbase = (void *) getKernelPages(STACKSIZE_PAGES);
  newt->kts->esp = (unsigned int) (newt->stackbase + (STACKSIZE_PAGES << PAGE_SHIFT) - 1);

  nexusthread_initialize_state(newt->kts, proc, arg, (void *) nexusthread_kill, newt);

  P(&threadTable_mutex);
  hash_insert(threadTable, &newt->id, newt);
  V(&threadTable_mutex);

  return newt;
}

/** Allocate and initialize a user thread */
UThread *
nexusuthread_create(unsigned int pc, unsigned int sp, IPD *ipd) 
{
  UThread *newt;

  assert(ipd);

  newt = gcalloc(1, sizeof(UThread));
  nexusthread_init_basic((BasicThread *) newt);
 
  newt->type = USERTHREAD;
  newt->uts = UserThreadState_new();
  newt->schedstate = NOT_YET_RUN;
  newt->kthread = nexuskthread_create((void*) nexusuthread_goto_user, newt);

  // insert into process threadtable
  newt->ipd = ipd;
  P(&ipd->mutex);
  ipd->threadcount++;
  hash_insert(ipd->uthreadtable, &newt->id, newt);
  V(&ipd->mutex);
  
  // insert into global threadtable
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

////////  running and blocking  ////////

/** Like nexusthread_start, but call with interrupts disabled */
void
nexusthread_start_noint(BasicThread *t, int front)
{
  // NB: when threads are continuously put at the front, others may starve
  // as a result of strict round robin scheduling. 
  
  t->schedstate = RUNNABLE;
  nxsched_enqueue(t, 0, front);
}

/** Put a process on the runqueue
    May be called with interrupts on or off */
void 
nexusthread_start(BasicThread *t, int front) 
{
  int intlevel;
 
  intlevel = disable_intr();
  nexusthread_start_noint(t, front);
  restore_intr(intlevel);
}


////////  Stop and Yield  ////////

/** Put the calling thread in WAITING mode */
void 
nexusthread_stop(void) 
{
  assert(check_intr() == 0);
  if (curt->schedstate != DEAD)
    curt->schedstate = WAITING;
  nexusthread_switch(DOSTOP);
#if NXCONFIG_PROFILE_SCHED
  sched_stop++;
#endif

  assert(check_intr() == 0);
  assert(curt->schedstate == RUNNABLE);
}


/** Allow another thread to run */
void nexusthread_yield_noint(void) 
{
  nexusthread_switch(DOYIELD);
#if NXCONFIG_PROFILE_SCHED
  sched_yield++;
#endif
}

void nexusthread_yield(void) 
{
  disable_intr();
  nexusthread_yield_noint();
  enable_intr();
}

/** Put a thread to sleep for delta ticks.
    Call with interrupts already DISABLED

    @param delta if 0, no alarm will be registered
    @param lvl is -1 if ignored, or an interrupt level to which sleep_ex restores
           after (atomically) scheduling the sleep
    @return 0 if timed out, 1 if cancelled and -1 on error */
int 
nexusthread_sleep_ex(int delta, Sema *sleepsema) 
{
  assert(curt);
  assert(!curt->sleepalarm);
  assert(!curt->timedout);
  assert(check_intr() == 0);
 
  if (delta) 
  	curt->sleepalarm = register_alarm_noint(delta, (void *) V_signal, sleepsema);

#if NXCONFIG_PROFILE_SCHED
  sched_sleep++;
#endif

  P_noint(sleepsema);
  assert(check_intr() == 0);
  
  curt->sleepalarm = 0;	// happens when P fell through (sleepsema->val > 0)
  return swap(&curt->timedout, 0) ? 0 : 1;
}

/** Put a thread to sleep. 
    Must be an interruptible thread of course: call with interrupt ENABLED */
int
nexusthread_sleep(int delta)
{
  Sema sleepsema = SEMA_INIT_KILLABLE;
  int lvl, ret;

  assert(check_intr() == 1);
  lvl = disable_intr();
  
  ret = nexusthread_sleep_ex(delta, &sleepsema);

  assert(check_intr() == 0);
  assert(lvl == 1); // XXX simplify: remove lvl altogether
  restore_intr(lvl);
  return ret;
}

/** Sleep for at least the given number of usec. 
    Uses busy polling for very short delays, alarm for longer ones. */
int
nexusthread_usleep(unsigned long usec)
{
    uint64_t tend;
    int ticks;

    // if long timeout (at least one tick)
    ticks = usec / USECPERTICK;
    if (ticks)
	    return nexusthread_sleep(ticks);

    // if short timeout: busy poll using rdtsc()
    tend = rdtsc64() + (usec * (nxclock_rate / (1000 * 1000)));
    while (rdtsc64() < tend) {};
    
    return 0;
}


////////  exiting and killing  ////////

/** Main call to kill a thread. 
    can be called for any thread, including current */
void 
nexusthread_kill(BasicThread *t) 
{
  int lvl; 
 
  if (swap((int *) &t->schedstate, DEAD) == DEAD)
	  return;

  lvl = disable_intr();
  if (t->sleepalarm)
    deregister_alarm_noint(t->sleepalarm);

  nxsched_dequeue(t);
  uqueue_enqueue(dead_thread_queue, t);
  V(&dead_thread_sema);

  if (t == curt)
    __nexusthread_switch_new(nxsched_schedule()); // will not return

  restore_intr(lvl);
}

/** Callback function that cleans up a thread. 
    Do NOT call directly: call nexusthread_kill instead */
static void 
__nexusthread_kill(BasicThread *dead) 
{
  assert(check_intr() == 1);

  P(&threadTable_mutex);
  hash_delete(threadTable, &dead->id);
  V(&threadTable_mutex);

  // if in the middle of RPC 
  if (dead->type == USERTHREAD) {
    hash_delete(dead->ipd->uthreadtable, &dead->id);

    // XXX reenable: UserThreadState_destroy(dead->uts);
    if (dead->kthread->schedstate != DEAD)
      nexusthread_kill(dead->kthread);
  } 
  else {
    freeKernelPages(dead->stackbase, STACKSIZE_PAGES);
    gfree(dead->kts);
  }
  
   // Destroy process if this was the last thread
  if (dead->ipd != kernelIPD &&
      atomic_get_and_addto(&dead->ipd->threadcount, -1) == 1) {
    __ipd_kill(dead->ipd);
  }

  if (dead->name)
	  gfree(dead->name);
  gfree(dead);
}

/** Kernel tasks that reaps dead threads.
    Link between nexusthread_kill and __nexusthread_kill */
static int
nexusthread_killer(void *unused)
{
	BasicThread *t;

	while (1) {
		assert(check_intr() == 1);
    		P(&dead_thread_sema);
		
		disable_intr();
		t = uqueue_dequeue(dead_thread_queue);
		assert(t && t->id < 100000 /* arbitrary safe test */);
		enable_intr();
		
      		__nexusthread_kill(t);
	}

	// not reached
	return -1;
}

/*
 *	Initialize the system to run the first nexusthread at
 *	mainproc(mainarg). Must be called during kernel init 
 */
void 
nexusthread_init(void) 
{
  KThread *init;

  threadTable = hash_new(1024, sizeof(int));

  // setup the structures for this initial thread
  init = nexuskthread_create(NULL, NULL);
  init->schedstate = RUNNABLE;
  assert(init->id == 1);
  curt = (BasicThread *) init;

  // fork off reaper thread
  dead_thread_queue = uqueue_new();
  nexusthread_fork(nexusthread_killer, NULL); 
  nexusthread_fork(nxclock_thread, NULL);

  restore_preemption(1);
  assert(get_preemption());
  printk("enabled preemption\n");
}


////////  Other  ////////

KernelThreadState *
thread_getKTS(BasicThread *t) 
{
  if (t->type == KERNELTHREAD)
    return ((KThread *) t)->kts;
  else
    return ((UThread *) t)->kthread->kts;
}

