#ifndef NEXUS_TIMING_H
#define NEXUS_TIMING_H

#if defined(NEXUS_UDRIVER) || defined(__NEXUSKERNEL__)
#include <linux/types.h>
#else
#include <stdint.h>
#endif

//#endif

struct Timing;

struct TimingSpec {
	int identifier;
	char *spec_name;
};

struct Timing *timing_new(struct TimingSpec *specs, int num_specs);
struct Timing *timing_new_anon(int num_specs);

// XXX why the defines?
#if 1
void timing_start(struct Timing *timing, int timing_name);
void timing_end(struct Timing *timing, int timing_name);
#else
#define timing_start(X,Y) do { void *__foo; __foo = (X); } while(0)
#define timing_end(X,Y) do { void *__foo; __foo = (X); } while(0)
#endif

void timing_set(struct Timing *timing, int timing_name, uint64_t value);

void timing_start_spec(struct Timing *timing, int timing_name, uint64_t time);
void timing_end_spec(struct Timing *timing, int timing_name, uint64_t time);

void timing_reset(struct Timing *timing);
int timing_getData(struct Timing *timing, uint64_t *data);

int ReadTimingsHelper(struct Timing *timing, char *dest);

#endif // NEXUS_TIMING_H

