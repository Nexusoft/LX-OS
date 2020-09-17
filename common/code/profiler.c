/** NexusOS: profiling code, 
             takes CPU measurements and calculates median, Q1 and Q3 
 
    Derived from streamline (netstreamline.org) 
    NOT threadsafe (no locking to be fast) */

#ifndef __NEXUSKERNEL__
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

// for nxmedian_write
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#endif

#include <nexus/defs.h>
#include <nexus/rdtsc.h>
#include <nexus/profiler.h>

#ifdef __NEXUSKERNEL__

/** quicksort implementation from wikipedia.org, 
    because the kernel has no qsort 
 
    XXX run selftest in userspace, comparing output to libc implementation
 */
static void 
__qsort(uint64_t* low, uint64_t* high)
{
   /* We naively use the first value in the array as the pivot */
   /* this will not give good performance real usage */

   uint64_t * lowbound = low + 1;       /* the high boundary of the low subarray */
   uint64_t * highbound = high - 1;     /* the low boundary of the high subarray */
   uint64_t temp;

   while(lowbound <= highbound) /* partition the array */
   {
      if(*lowbound < *low)         /* compare to pivot */
        lowbound++;                /* move lowbound toward the middle */
      else
      {
         temp = *lowbound;         /* swap *lowbound and *highbound */
         *lowbound = *highbound;
         *highbound = temp;
         highbound--;              /* move highbound toward the middle */
      }
   }

   highbound++;                    /* move bounds back to the correct positions */
   lowbound--;

   temp = *low;                    /* move the pivot into the middle */
   *low = *lowbound;
   *lowbound = temp;

   if(low != lowbound)             /* recurse on the subarrays */
     __qsort(low, lowbound);
   if(high != highbound)
     __qsort(highbound, high);
}

#else
int qsort_cmp(const void *_a, const void *_b)
{
	const uint64_t *a = _a;
	const uint64_t *b = _b;

	if (unlikely(*a == *b))
		return 0;

	return (*a > *b) ? 1 : -1;
}
#endif

/** Calculate the median of a sorted list of items */
static inline uint64_t 
__median(int start, int stop, uint64_t* ldList)
{
	int middle_floor = start+(stop-start)/2;
	if ( (((stop-start) % 2) + 1) == 1)	// odd number of elements
		return ldList[middle_floor];
	else
		return ((uint64_t) ( ldList[middle_floor] + ldList[middle_floor + 1]) ) / 2;
}

/** Calculate the median, upper and lower quartiles of a sorted list of items */
static inline void
__quartiles(uint64_t *items, int ilen, uint64_t quartiles[3]) 
{
	int pivot = ilen / 2;

	quartiles[1] = __median(0,         ilen - 1, items);
	quartiles[2] = __median(pivot + 1, ilen - 1, items);

	// warning: it is a bad idea to use an even numbered list
	if (ilen % 2)
		quartiles[0] = __median(0, pivot - 1, items);
	else
		quartiles[0] = __median(1, pivot - 2 , items);
}

/** pretty print using G/M/K for magnitude 
    always displays at least 3 digits 
 
    warnign: @param Q may be modified */
static inline char 
__calc_magnitude(uint64_t *Q) 
{
	if (*Q >> 30) {
		*Q = *Q >> 20;
		return 'M';
	} 
	
	if (*Q >> 20) {
		*Q = *Q >> 10;
		return 'K';
	}
		
	return '_';
}

/** Calculate the median + mean and output information to the standard output queue. 
    Only call this with a fully populated list

    @param name: the label you want to print before the data */
void 
nxmedian_show(const char *name, struct nxmedian_data *data)
{
	double average, Q1pct, Q3pct;
	int j, last;
	char magnitude;
	uint64_t q[3];

	last = data->len - 1;

	/* calculate the median (and the lower and upper quartile) */
#ifdef __NEXUSKERNEL__
	__qsort(&data->cycles[0], &data->cycles[last]);
#else
	qsort(data->cycles, data->len, sizeof(uint64_t), qsort_cmp);
#endif
	__quartiles(data->cycles, data->len, q);

	/* calculate the average */
	average = 0;
	for (j=0; j < data->len; j++)
		average += data->cycles[j];
	average /= data->len;
	
	/* calculate the relative offsets between the quartiles */
	Q1pct = (((double) 100) / q[1]) * (q[1] - q[0]);
	Q3pct = (((double) 100) / q[1]) * (q[2] - q[1]);

	magnitude = __calc_magnitude(&q[0]);
	nxcompat_printf("%20s Q1=%10llu %c (-%.2f%%) ", name, q[0], magnitude, Q1pct);
	magnitude = __calc_magnitude(&q[1]);
	nxcompat_printf(     "Q2=%10llu %c (+%.2f%%) ", q[1], magnitude, Q3pct);
	magnitude = __calc_magnitude(&q[2]);
	nxcompat_printf(     "Q3=%10llu %c AVG=%.4g\n", q[2], magnitude, average);
}

#ifndef __NEXUSKERNEL__
/** Write single line of result to a file in gnuplot-compatible format
    Format is (index, q2!!, q1, q3)
    The median is the first element, in line with gnuplot's use of errorbars

    @param column:	the identifier for this datapoint (x-axis of a plot)
    @param sorted_data:	must be, as its name implies, sorted 
                        call nxmedian_show before nxmedian_write to sort

    @return 0 on success, -1 on error 
 */
int
nxmedian_write(const char *filepath, long column1, 
	       struct nxmedian_data *sorted_data)
{
	uint64_t q[3];
	char buf[80];
	int fd, ret;

	// open measurement file and seek to end
	fd = open(filepath, O_CREAT | O_WRONLY | O_APPEND, 0644);
	if (fd < 0)
		return 1;

	// calculate quartiles again
	__quartiles(sorted_data->cycles, sorted_data->len, q);

	// print in gnuplot format
	ret = snprintf(buf, 79, "%ld \t\t%lld \t%lld \t%lld\n", 
		       column1, q[1], q[0], q[2]);
	if (ret < 0 || ret == 79)
		goto error;

	// write and close file
	if (write(fd, buf, ret) != ret)
		goto error;
	if (close(fd))
		return 1;

	return 0;

error:
	close(fd);
	return 1;
}
#endif

struct nxmedian_data * 
nxmedian_alloc(int len)
{
	struct nxmedian_data *data;

	data = nxcompat_calloc(1, sizeof(struct nxmedian_data) + 
				 (sizeof(uint64_t) * len));
	data->len = len;
	data->index = 0;

	return data;
}

void nxmedian_reset(struct nxmedian_data *data)
{
	data->index = 0;
}

void nxmedian_free(struct nxmedian_data *data)
{
	nxcompat_free(data);
}

#ifdef __NEXUS__
#include <nexus/kshmem.h>

/** Read CPU frequency. 
    Nexus version: use NXCLOCK_RATE */
unsigned long long 
nxprofile_cpurate(void)
{
	return NXCLOCK_RATE;
}

#else

/** Read CPU frequency.
    Linux version: read sysfs 
    @return 0 on error */
unsigned long long 
nxprofile_cpurate(void)
{
	static unsigned long long rate;
	char strate[15];
	int fd;

	// cache result
	if (rate)
		return rate;

	// nothing cached. read from sysfs
	fd = open("/sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq", O_RDONLY);
	if (fd < 0)
		return 0;

	if (read(fd, strate, 14) <= 0)
		goto cleanup_error;

	if (sscanf(strate, "%llu", &rate) != 1)
		goto cleanup_error;

	if (close(fd))
		goto cleanup_error;
	
	rate *= 1000; // sysfs value is in KHz
	return rate;

cleanup_error:
	close(fd);
	fprintf(stderr, "%s rate read failed\n", __FUNCTION__);
	return 0;
}

#endif /* !NEXUS */

