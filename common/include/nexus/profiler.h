/** NexusOS: low level profiling support 
 
    Consists of two independent profiling interfaces:
    - nxprofile can have state on the stack. calculates number of invocations
    - nxmedian keeps a list of measurements. calculates median, Q1 and Q3
  */

#ifndef NEXUS_PROFILE_H
#define NEXUS_PROFILE_H

#include <nexus/defs.h>
#include <nexus/rdtsc.h>

#define NUMSEC 4

unsigned long long nxprofile_cpurate(void);

static inline void
nxprofile_init(uint64_t * profile)
{
	// initialize accounting variables
	profile[0] = 0;			// 1st argument: #calls in epoch
	profile[1] = rdtsc64();		// 2nd argument: time since epoch start
}

// add another data point. calculates number of calls/epoch
static inline void 
nxprofile_update(uint64_t profile[2], const char *name)
{
	uint64_t tcur, hits;
	char magnitude;

	tcur = rdtsc64();
	profile[0]++;

	// epoch change (roughly) each second
	if (unlikely(tcur > profile[1] + (NUMSEC * nxprofile_cpurate()))) {
		hits = profile[0] / NUMSEC;
		if (hits >> 25) {
			magnitude = 'M';
			hits = hits >> 20;
		}
		else if (hits >> 15) {
			magnitude = 'K';
			hits = hits >> 10;
		}
		nxcompat_fprintf(stderr, "[prof:%s] %llu %ccalls/sec\n", 
				 name, hits, magnitude);
		profile[1] = tcur;
		profile[0] = 0;
	}
}

// add start of another test. calculates length of calls
static inline void
nxprofile_start(uint64_t profile[4])
{
	profile[0]++;				// profile[0] keeps number of calls in epoch
	profile[2] = rdtsc64();			// profile[2] keeps last start

	// special case: initialized as all 0
	if (unlikely(!profile[1]))
		profile[1] = profile[2];	// profile[1] keeps number of cycles
}

static inline void
nxprofile_finish(uint64_t profile[4], const char *name)
{
	uint64_t tcur;

	tcur = rdtsc64();
	profile[3] += rdtsc64() - profile[2];

	// epoch change (roughly) each four seconds
	if (likely(profile[0]) && 
	    unlikely(tcur > profile[1] + (NUMSEC * nxprofile_cpurate()))) {
		uint64_t ratio;
		char prefix;

		// pretty print 
		ratio = profile[3] / profile[0];
		if (ratio > (1 << 12)) {
			// mega
			if (ratio > (1 << 22)) {
				prefix = 'M';
				ratio = ratio >> 20;
			}
			// kilo
			else {
				prefix = 'K';
				ratio = ratio >> 10;
			}
		}
		// no magnitude size
		else
			prefix = ' ';

		nxcompat_fprintf(stderr, "[prof:%s] %llu %ccyc/call (%llu cycles, %llu calls)\n", 
				name, ratio, prefix, profile[3], profile[0]);
		
		profile[0] = 0;
		profile[1] = 0;
		profile[3] = 0;
	}
}


////////  NXMEDIAN: profiler with median calculation  ////////
//
// derived from another project, complements the above code

/** A list of latest measurements. 
    Wraps around, index always points to the next item to write. 
    Considered uninitialized if cycles[0] is 0 
 
    @param len does not have to be a power of two */
struct nxmedian_data {
	int index;
	int len;
	uint64_t cycles[];
};

/** fill in a measurement */
static inline void
nxmedian_set(struct nxmedian_data *data, uint64_t measurement)
{
	data->cycles[data->index] = measurement;
	data->index = (data->index + 1) % data->len;
}

/** start a new processor count calculation. */
static inline void 
nxmedian_begin(struct nxmedian_data *data)
{
	data->cycles[data->index] = rdtsc64();
}

/** close a processor count calculation. */
static inline void 
nxmedian_end(struct nxmedian_data *data)
{
	nxmedian_set(data, rdtsc64() - data->cycles[data->index]);
}

void nxmedian_show(const char *name, struct nxmedian_data *data);
int nxmedian_write(const char *filepath, long column1, 
	           struct nxmedian_data *sorted_data);

struct nxmedian_data * nxmedian_alloc(int len);
void nxmedian_reset(struct nxmedian_data *data);
void nxmedian_free(struct nxmedian_data *data);

#endif /* NEXUS_PROFILE_H */

