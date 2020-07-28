#ifndef __NEXUSCLOCK_H__
#define __NEXUSCLOCK_H__

#include <nexus/defs.h>
#include <nexus/rdtsc.h>
#include <nexus/dlist.h>

//////// Time ////////

#define USECPERTICK (1000000 / HZ)

// Warning: field lengths must correspond with userspace timeval
struct nxtimeval {
	long tv_sec;
	long tv_usec;
};

/// global time counter. in clockticks (HZ)
//  is available from userspace as NEXUSTIME
extern unsigned int nexustime;
extern unsigned int ntp_offset;

int gettimeofday(struct nxtimeval *tv);


//////// Alarms ////////

struct Alarm {
  struct dlist_head link;
  unsigned int alarmtime;  	///< absolute time at which the alarm is supposed to go off */
  int ipd;			///< process to wake up, or -1
  int fired; /* alarm is queued on the alarmq */
  int free_on_fire; /* alarm freeing is our responsibility */

  void (*func)(void *arg); /* function to call */
  void *arg;  /* argument to pass */
  void *caller; // debug: ptr to whoever registered the alarm
};

/** register an alarm to go off atime ticks in the future */
Alarm *register_alarm(int atime, void (*func)(void *arg), void *arg);
/*
 * Same deal, except everything's already in the data structure and it doesn't get released
 */
void register_alarm_norelease(Alarm *a);

/** get rid of an alarm that was scheduled to go off
    @return 0 on success, -1 on failure to find the alarm */
int deregister_alarm(Alarm *a);
int deregister_alarm_and_fire(Alarm *a);

/** initialize the clock subsystem */
void nexus_timer_init(void);

/** timer worker thread. start before using the timer */
int timer_worker(void *ctx);

struct InterruptState;
int nexus_timer(struct InterruptState *is);

void nexus_udelay(unsigned long usecs);

int preemption_enabled;

#endif

