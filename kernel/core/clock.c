/** NexusOS: clock interrupt handling and alarm functionality */

#include <asm/param.h>

#include <nexus/defs.h>
#include <nexus/machineprimitives.h>
#include <nexus/thread.h>
#include <nexus/thread-private.h>
#include <nexus/thread-inline.h>
#include <nexus/clock.h>
#include <nexus/profiler.h>
#include <nexus/ipd.h>
#include <nexus/rdtsc.h>
#include <nexus/ksymbols.h>
#include <nexus/synch.h>
#include <nexus/synch-inline.h>
#include <nexus/screen.h>

//unsigned int nexustime;		// epoch counter increasing at HZ rate (defined in head.S)
//uint64_t nxclock_rate;		// clockrate (in cycles) (defined in head.S)
uint32_t nxclock_rate_hz;		// clockrate per nexustime increase

/** keep track of when a thread started, to be able to preempt it */ 
unsigned long nexustime_last_switch;

// XXX replace dlist with queue
static struct dlist_head_list alarmq;
static Sema alarm_sema = SEMA_INIT_KILLABLE;

#define PIT_CLOCK_TICK_RATE 1193182 /* Underlying HZ of 8254 counter */
#define CALIBRATE_TIME_POW  5
#define CALIBRATE_TIME_MSEC (1 << CALIBRATE_TIME_POW)
#define CALIBRATE_LATCH \
  ((PIT_CLOCK_TICK_RATE * CALIBRATE_TIME_MSEC + 1000/2)/1000)

/** Calculate the CPU kHZ rate 
    @return kilo(!) HZ */
unsigned long nxclock_calibrate(void)
{
  unsigned long long start, end;
  unsigned long count;
  u64 delta64;
  int i;
  unsigned long intlevel;

	inline void mach_prepare_counter(void)
	{
	  /* Set the Gate high, disable speaker */
	  outb((inb(0x61) & ~0x02) | 0x01, 0x61);

	  /*
	   * Now let's take care of CTC channel 2
	   *
	   * Set the Gate high, program CTC channel 2 for mode 0,
	   * (interrupt on terminal count mode), binary count,
	   * load 5 * LATCH count, (LSB and MSB) to begin countdown.
	   *
	   * Some devices need a delay here.
	   */
	  outb(0xb0, 0x43);                       /* binary, mode 0, LSB/MSB, Ch 2 */
	  outb_p(CALIBRATE_LATCH & 0xff, 0x42);   /* LSB of count */
	  outb_p(CALIBRATE_LATCH >> 8, 0x42);       /* MSB of count */
	}

	inline void mach_countup(unsigned long *count_p)
	{
	  unsigned long count = 0;
	  do {
	    count++;
	  } while ((inb_p(0x61) & 0x20) == 0);
	  *count_p = count;
	}

  intlevel = disable_intr();

  /* run 3 times to ensure the cache is warm */
  for (i = 0; i < 3; i++) {
    mach_prepare_counter();
    start = rdtsc64();
    mach_countup(&count);
    end = rdtsc64();
  }
  /*
   * Error: ECTCNEVERSET
   * The CTC wasn't reliable: we got a hit on the very first read,
   * or the CPU was so fast/slow that the quotient wouldn't fit in
   * 32 bits..
   */
  if (count <= 1)
    goto err;

  delta64 = end - start;

  /* cpu freq too fast: */
  if (delta64 > (1ULL<<32))
    goto err;

  /* cpu freq too slow: */
  if (delta64 <= CALIBRATE_TIME_MSEC)
    goto err;

  delta64 += CALIBRATE_TIME_MSEC >> 1; 		/* round for do_div */
  delta64 = delta64 >> CALIBRATE_TIME_POW;	

  restore_intr(intlevel);
  return (unsigned long) delta64;
err:
  restore_intr(intlevel);
  return 0;
}

/** Handle a clock interrupt: 
    if any alarms timed out, then wake the background thread
    @return 1 if the current thread has to relinquish the CPU, 0 if not */
int 
nxclock_interrupt(void *unused) 
{
  static int nexustime_last;
  struct dlist_head *link;

  // update nexustime: epoch that increases once per HZ
  // secs == (observed cycles) / (clockrate)
  // nexustime == secs * HZ
  nexustime = (rdtsc64() * HZ) / nxclock_rate;

  // do infrequent background operations
  if (unlikely(nexustime > nexustime_last + (HZ << 3))) {
        
	// calculate uses of all threads (if schedinfo is requested)
        nexusthread_account_sum();
        nexustime_last = nexustime;
  }

  // update idle count
  nexusthread_idle_last = nexusthread_idle_now;
  nexusthread_idle_now = 0;
  screen_redrawline(); // redraw to show current cpuload
  
  // if at least one alarm expired, schedule the timer worker to handle them
  link = dlist_peek_front(&alarmq);
  if (link && CONTAINER_OF(Alarm, link, link)->alarmtime <= nexustime)
  	V(&alarm_sema);

  // has the currently executing thread exceeded its quantum?
  if (likely(preemption_enabled) && 
      nexustime - nexustime_last_switch >= SCHED_PREEMPTION_QUANTUM)
  	return 1;
  else
  	return 0;
}

/*
 * the alarm is supposed to go off in "atime" ticks in the future
 */
Alarm *
register_alarm_noint(int atime, void (*func)(void *arg), void *arg) 
{
  struct dlist_head *link;
  Alarm *a;

  assert(check_intr() == 0); 
  
  // create alarm
  a = gcalloc(1, sizeof(Alarm));
  a->ipd = curt->ipd->id;
  a->thread = curt;
  a->func = func;
  a->arg = arg;
  a->alarmtime = nexustime + atime;
  dlist_init_link(&a->link);
  
  // register alarm
  dlist_head_walk(&alarmq, link) {
    if (CONTAINER_OF(Alarm, link, link)->alarmtime > a->alarmtime) {
      // ptr now points just past the point where we need to insert
      dlist_insert(&a->link, link->prev, link);
      return a;
    }
  }

  dlist_insert_tail(&alarmq, &a->link);
  return a;
}

Alarm *
register_alarm(int atime, void (*func)(void *arg), void *arg) 
{
  Alarm *alarm;
  int lvl;
 
  assert(check_intr() == 1); 
  lvl = disable_intr();
  alarm = register_alarm_noint(atime, func, arg);
  restore_intr(lvl);
  
  return alarm;
}

/* get rid of an alarm that was scheduled to go off
 *   0 on success, -1 on failure to find the alarm */
int 
deregister_alarm_noint(Alarm *a)
{
  assert(check_intr() == 0);
  assert(a && dlist_islinked(&a->link));
  
  dlist_unlink(&a->link);

  if (ipd_find(a->ipd))
    a->thread->sleepalarm = NULL;

  gfree(a);
  return 0;
}

int
deregister_alarm(Alarm *a)
{
  int ret, lvl;
  
  lvl = disable_intr();
  ret = deregister_alarm_noint(a);
  restore_intr(lvl);
  
  return ret;
}

/** Background thread that calls the functions for expired alarms */
int 
nxclock_thread(void *ctx) 
{
  Alarm *ptr;
  struct dlist_head *link;
  int intlevel;

  while(1) {
    
    P(&alarm_sema);
    intlevel = disable_intr(); // for dlist

    // handle all Alarms that have expired
    while(1) {
      
      // fetch first item
      link = dlist_peek_front(&alarmq);
      if (!link)
	break;

      ptr = CONTAINER_OF(Alarm, link, link);
      if (ptr->alarmtime > nexustime)
	break;
 
      // advance the alarmq over the alarm that we're about to fire
      // before it fires, as the firing may re-queue the alarm
      dlist_dequeue(&alarmq);
          
      // call callback if caller still exists
      if (ipd_find(ptr->ipd)) {
	if (ptr->thread->sleepalarm)
	ptr->thread->timedout = 1;
	ptr->thread->sleepalarm = NULL;	// block anyone from calling deregister_alarm
        restore_intr(intlevel);
	ptr->func(ptr->arg);
	gfree(ptr);
	intlevel = disable_intr();
      }
    }
    restore_intr(intlevel);
  }

  return 0;
}

void 
nxclock_init(void) 
{
  nxirq_get(0, nxclock_interrupt, NULL);
  dlist_init_head(&alarmq);
}


/** Busy wait */
void nexus_udelay(unsigned long usecs)
{
  __u64 currentTime = rdtsc64();
  __u64 stopTime = currentTime + ((nxclock_rate / (1000 * 1000)) * usecs);

  while(currentTime < stopTime)
    currentTime = rdtsc64();
}

//// Timekeeping

int 
gettimeofday(struct nxtimeval *tv) 
{
    unsigned long long cycles;
    long seconds;
    long usecs;

    cycles = rdtsc64();
    
    seconds = cycles / nxclock_rate;
    cycles  -= seconds * nxclock_rate;
    usecs   = cycles / (nxclock_rate / (1000 * 1000));

    seconds += ntp_offset;

    tv->tv_sec = seconds;
    tv->tv_usec = usecs;
    return 0;
}

int
gettimeofday_posix(void *user_tv)
{
    struct nxtimeval tv;
    
    gettimeofday(&tv);
    ((struct nxtimeval *) user_tv)->tv_sec = tv.tv_sec;
    ((struct nxtimeval *) user_tv)->tv_usec = tv.tv_usec;
    return 0;
}

