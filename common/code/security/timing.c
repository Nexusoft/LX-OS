
#include <nexus/defs.h>
#include <nexus/timing.h>
#include <nexus/rdtsc.h>

#ifdef __NEXUSKERNEL__
#include <nexus/galloc.h>
#include <nexus/mem.h>
#include <nexus/thread.h>
#include <nexus/thread-inline.h>
#else
#include <stdlib.h>
#include <stdint.h>
#endif

struct TimingInterval {
  char *name;
  uint64_t timing_start;
  uint64_t timing_accum;
};

struct Timing {
  int num_intervals;
  struct TimingInterval *intervals;
};

struct Timing *timing_new(struct TimingSpec *specs, int num_specs) {
  struct Timing *rval = timing_new_anon(num_specs);

  int i;
  for(i=0; i < rval->num_intervals; i++) {
    rval->intervals[i].name = specs[i].spec_name;
  }
  return rval;
}

struct Timing *timing_new_anon(int num_specs) {
  struct Timing *rval = nxcompat_alloc(sizeof(struct Timing));
  rval->num_intervals = num_specs;
  rval->intervals = nxcompat_alloc(sizeof(struct TimingInterval) * num_specs);

  int i;
  for(i=0; i < rval->num_intervals; i++) {
    rval->intervals[i].name = "";
  }
  timing_reset(rval);
  return rval;
}

void timing_start(struct Timing *timing, int timing_name) {
  if(timing == NULL) return;
  if(timing_name >= timing->num_intervals) return;
  timing->intervals[timing_name].timing_start = rdtsc64();
}

void timing_end(struct Timing *timing, int timing_name) {
  if(timing == NULL) return;
  if(timing_name >= timing->num_intervals) return;
  uint64_t end_time = rdtsc64();
  timing->intervals[timing_name].timing_accum += 
    end_time - timing->intervals[timing_name].timing_start;
}

void timing_set(struct Timing *timing, int timing_name, uint64_t value) {
  if(timing == NULL) return;
  if(timing_name >= timing->num_intervals) return;
  timing->intervals[timing_name].timing_accum = value;
}

void timing_reset(struct Timing *timing) {
  int i;
  for(i=0; i < timing->num_intervals; i++) {
    timing->intervals[i].timing_start = 0;
    timing->intervals[i].timing_accum = 0;
  }
}

int timing_getData(struct Timing *timing, uint64_t *data) {
  int i;
  for(i=0; i < timing->num_intervals; i++) {
    data[i] = timing->intervals[i].timing_accum;
  }
  return timing->num_intervals;
}

void timing_start_spec(struct Timing *timing, int timing_name, uint64_t time) {
  timing->intervals[timing_name].timing_start = time;
}

void timing_end_spec(struct Timing *timing, int timing_name, uint64_t time) {
  timing->intervals[timing_name].timing_accum += time - timing->intervals[timing_name].timing_start;
}


#ifdef __NEXUSKERNEL__
#define MAX_RESULT_COUNT (32)

int ReadTimingsHelper(struct Timing *timing, char *dest) {
  uint64_t result_buf[MAX_RESULT_COUNT];
  int len = timing_getData(timing, result_buf);
  timing_reset(timing);
  assert(len <= MAX_RESULT_COUNT);

  poke_user(nexusthread_current_map(), (unsigned int)dest, result_buf, len * sizeof(uint64_t));
  return len;
}
#endif
