#include <nexus/defs.h>
#include <nexus/machineprimitives.h>
#include <nexus/thread.h>
#include <nexus/thread-private.h>
#include <nexus/thread-inline.h>
#include <nexus/clock.h>

#include <nexus/profile.h>
#include <nexus/ipd.h>

#include <nexus/rdtsc.h>
#include <asm/param.h>
#include <nexus/ksymbols.h>
#include <nexus/synch.h>
#include <nexus/synch-inline.h>

#include <nexus/djwilldbg.h>

int profile_enabled = 0;
struct ProfileEntry *profile_sample_data;
int profile_sample_count;
int profile_sample_maxcount = 100000;

Sema alarm_sema = SEMA_INIT_KILLABLE;

struct dlist_head_list alarmq;

// nexustime is on its own special page set up in head.S
//unsigned int nexustime;

 // preemption is off until it is turned on in nexusthread_init
// This is because preemption needs the runqueues initialized first
// Otherwise, a BlackSOD occurs
int preemption_enabled = 0;

// This is a frequently accessed global. Put it in thread.c with curt and curr_map
extern volatile int preemption_mask;
/* XXX a helper thread needs to periodically empty the expired alarm queue */

#if 0
int alarm_has_fired(Alarm *a) {
  return a->fired;
}
#endif

static int alarm_past(Alarm *a) {
  return a->alarmtime <= nexustime;
}

static void alarm_free(Alarm *a) {
  a->fired = 1;
  if(a->free_on_fire) {
    gfree(a);
  }
}

int 
nexus_timer(InterruptState *is) 
{
  struct dlist_head *link;
  const int QUANTUM_TICKS = 1; 
  static int last_preempt_tick;
  static int last_second;
  uint64_t __nexustime_tmp;

  // update nexustime
  __nexustime_tmp = rdtsc64();
  nexustime = ( __nexustime_tmp * HZ) / (TSCCONST * 1000000ULL);

  // do once-per-second operations
  if (nexustime > last_second + 1000) {
	// calculate the idle percentage over the last second
	unsigned long cycles = TSCCONST * 1000 * 1000ULL;
	cycles = (100 * nexusthread_idlecycles) / cycles;

	// update estimate and reset counter
	nexusthread_idle_pct_sec = (int) cycles;
	nexusthread_idlecycles = 0;
  	last_second = nexustime;
  }

  link = dlist_peek_front(&alarmq);
  if(link) {
    Alarm *a = CONTAINER_OF(Alarm, link, link);
    if(alarm_past(a))
      V(&alarm_sema);
  }

  if (likely(preemption_enabled && preemption_mask) && 
      nexustime - last_preempt_tick >= QUANTUM_TICKS) {
    last_preempt_tick = nexustime;
    return 1;
  }

  return 0;
}

#define PANIC(cause) do { printk_red("Error in %s:%d; %s\n", __FILE__, __LINE__, cause); dump_stack(); nexuspanic(); } while(0)

void register_alarm_helper(Alarm *a){
  int insert_succeeded = 0;
  int intlevel = disable_intr();
  struct dlist_head *link;

  Alarm *last = NULL;
  dlist_head_walk(&alarmq, link) {
    Alarm *ptr = CONTAINER_OF(Alarm, link, link);
    last = ptr;
    if(ptr->alarmtime > a->alarmtime) {
      /*
       * ptr now points just past the point where we need to insert
       */
      insert_succeeded = 1;
      dlist_insert(&a->link, link->prev, link);
      break;
    }
  }
  if(!insert_succeeded){
    dlist_insert_tail(&alarmq, &a->link);
  }

  restore_intr(intlevel);
}

void register_alarm_norelease(Alarm *a){
  a->caller = (void *)(&a)[-1];
  a->free_on_fire = 0;
  a->fired = 0;
  dlist_init_link(&a->link);
  register_alarm_helper(a);
}

/*
 * the alarm is supposed to go off in "atime" ticks in the future
 */
Alarm *register_alarm(int atime, void (*func)(void *arg), void *arg) {
  Alarm *a;

  a = (Alarm *) galloc(sizeof(Alarm));
  if (nexusthread_current_ipd())
	  a->ipd = nexusthread_current_ipd()->id;
  else
	  a->ipd = -1;
  a->func = func;
  a->arg = arg;
  a->fired = 0;
  a->alarmtime = nexustime + atime;
  dlist_init_link(&a->link);
  a->caller = (void *)(&atime)[-1]; // hack to get PC of caller
  a->free_on_fire = 1;

  register_alarm_helper(a);

  return a;
}

static inline int deregister_alarm_helper(Alarm *a, int fire) {
  int intlevel = disable_intr();


  if(a->fired) {
    restore_intr(intlevel);
    printk_red("deregistering alarm (%p) that has already fired!\n", a);
    return -1;
  }
  if(!dlist_islinked(&a->link)){
    restore_intr(intlevel);
    printk_red("Trying to deregister an unregistered alarm\n");
    return -1;
  }

  dlist_unlink(&a->link);
  if(fire) {
    a->func(a->arg);
  }
  
  /* thread this alarm into a queue of expired alarms */
  alarm_free(a);

  restore_intr(intlevel);
  return 0;
}
/*
 * get rid of an alarm that was scheduled to go off
 *   0 on success, -1 on failure to find the alarm
 */
int deregister_alarm(Alarm *a) {
  return deregister_alarm_helper(a,0);
}

/* Same as deregister alarm, except the alarm is fired on deregistration */
int deregister_alarm_and_fire(Alarm *a) {
  return deregister_alarm_helper(a,1);
}

void nexus_udelay(unsigned long usecs){
  __u64 currentTime = rdtsc64();
  __u64 stopTime = currentTime + TSCCONST * usecs;
  while(currentTime < stopTime) {
    currentTime = rdtsc64();
  }
}

int 
timer_worker(void *ctx) 
{
  Alarm *ptr;
  struct dlist_head *link;
  int intlevel;

  while(1) {
    if (P(&alarm_sema))
	    return 1;  // thread is killed

    intlevel = disable_intr(); // for dlist

    // each time an alarm fires handle all Alarms that are ready
    while(1) {
      
      // fetch first item
      link = dlist_peek_front(&alarmq);
      if (!link)
	break;

      ptr = CONTAINER_OF(Alarm, link, link);
      if (!alarm_past(ptr))
	break;
 
      // advance the alarmq over the alarm that we're about to fire
      // before it fires, as the firing may re-queue the alarm
      dlist_dequeue(&alarmq);
      restore_intr(intlevel);
          
      // call callback if caller still exists
      if (ptr->ipd >= 0 && ipd_find(ptr->ipd)) {
	ptr->func(ptr->arg);
	alarm_free(ptr);
      }
    
      intlevel = disable_intr();
    }
    restore_intr(intlevel);
  }
}

void 
nexus_timer_init(void) 
{
  dlist_init_head(&alarmq);
}

void set_tsc_const(char *opt) {
  int newval = TSCCONST_DEFAULT;
  sscanf(opt, "%d", &newval);
  printk("Setting timestamp counter to %d\n", newval);
  tsc_per_jiffie = newval;
}


/// Debugging output for alarm queues

static void alarm_dump(struct Alarm *a) {
  KSymbol *ks = ksym_find_by_addr(a->func);
  KSymbol *kt = ksym_find_by_addr(a->caller);
  //printk("%p = { .next = %p, .prev = %p, .alarmtime=%u, .fired = %d, .func = [<%x>] %s }\n",
	 //a, a->next, a->prev, a->alarmtime, a->fired, (int)a->func, (ks ? ks->name : "???"));
  printk("%p = { .alarmtime=%u, .fired = %d .func = [<%x>] %s by [<%x>] %s }\n",
	 a, a->alarmtime, a->fired, (int)a->func, (ks ? ks->name : "???"), (int)a->caller,
	 (kt ? kt->name : "???"));
}

static void dump_alarmq_helper(void) {
  int limit = 10;
  struct dlist_head *link;
  dlist_head_walk(&alarmq, link) {
    Alarm *ptr = CONTAINER_OF(Alarm, link, link);
    alarm_dump(ptr);
  }
  if(limit == 0) printk("limit reached\n");
}

int 
gettimeofday(struct nxtimeval *tv) 
{
    int seconds;
    int usecs;
    int time = nexustime;
    long long tsc = rdtsc64();
    
    seconds  = time;
    seconds *= USECPERTICK;
    seconds /= 1000000;

    usecs   = time * USECPERTICK;
    usecs  -= seconds * 1000000;

    seconds += ntp_offset;

    tv->tv_sec = seconds;
    tv->tv_usec = usecs;
    return 0;
}

