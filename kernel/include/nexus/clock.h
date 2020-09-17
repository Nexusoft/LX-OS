#ifndef __NEXUSCLOCK_H__
#define __NEXUSCLOCK_H__

#include <asm/param.h>  // for HZ

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
extern uint64_t nxclock_rate;
extern uint32_t nxclock_rate_hz;
extern unsigned int  ntp_offset;

int gettimeofday(struct nxtimeval *tv);
int gettimeofday_posix(void *user_tv);


//////// Alarms ////////

struct Alarm {
  struct dlist_head link;
  unsigned int alarmtime;  	///< absolute time at which the alarm is supposed to go off */
  int ipd;			///< process to wake up, or -1
  struct BasicThread *thread;

  void (*func)(void *arg); 	/* function to call */
  void *arg;  			/* argument to pass */
};

/** register an alarm to go off atime ticks in the future */
Alarm *register_alarm_noint(int atime, void (*func)(void *arg), void *arg);
Alarm *register_alarm(int atime, void (*func)(void *arg), void *arg);

/** Remove an alarm from the alarm queue
    @return 0 on success, -1 on failure to find the alarm */
int deregister_alarm(Alarm *a);
int deregister_alarm_noint(Alarm *a);

/** initialize the clock subsystem */
void nxclock_init(void);
int  nxclock_thread(void *ctx);

unsigned long nxclock_calibrate(void);

#endif

