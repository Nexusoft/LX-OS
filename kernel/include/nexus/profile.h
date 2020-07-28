#ifndef _NEXUS_PROFILE_H_
#define _NEXUS_PROFILE_H_

extern unsigned int profile_syscall_info;
extern unsigned int profile_alt_info;

extern unsigned long long last_profile_time;
// signed to deal with random clock drifts
extern long long cumulative_missing_profile_cycles;

struct ProfileEntry {
  unsigned int ipd_id;
  unsigned int thread_id;
  unsigned int address;

  unsigned int syscall_info;
  unsigned int alt_info;
  unsigned int interval_info;
}  __attribute__((packed));

#endif // _PROFILE_H_
