#ifndef TIMING_MACRO_H
#define TIMING_MACRO_H

/*
 * A set of macros useful for detailed timing of functions. This code is
 * independent of the timing.[ch] style timing using timing_new,
 * timing_start, timing_end, etc.
 */

#ifdef DO_TIMING

#define PRINT_TIMING (1)
#define rdtsc64()							\
    ({									\
      long long v;							\
      __asm__ __volatile__("rdtsc" : "=a" (*(int*)&v), "=d" (*((int*)&v + 1)));	\
      v;								\
    })


#define TIME_STARTFUNC(MAXSAMPLES, INTERVAL)			\
    static int passes;					\
    int seg = 0;						\
    int __interval = INTERVAL;						\
    long long __samples[MAXSAMPLES];			\
    static struct {				\
      int startline, endline;			\
      long long total;				\
      int count;				\
    } stats[MAXSAMPLES];			\
    passes++;

#define TIME_START(X) do {			\
      stats[X].startline = __LINE__;		\
      __samples[X] = rdtsc64();			\
    } while(0)

#define TIME_END(X) do {			\
      stats[X].endline = __LINE__;		\
      stats[X].total += rdtsc64() - __samples[X];	\
      stats[X].count++;					\
    } while(0)

#define TIME_SEGFIRST() TIME_START(seg);
#define TIME_SEG() TIME_END(seg); seg++; TIME_START(seg); 
#define TIME_SEGLAST() TIME_END(seg);

#define TIME_ENDFUNC()					\
    do {						\
      if(PRINT_TIMING && passes > __interval) {				\
	int i;						\
	int total = 0;					\
	printk("%s:\n", __FUNCTION__);			\
	for(i=0; i < sizeof(stats) / sizeof(stats[0]); i++) {	\
	  if(stats[i].count > 0) {			\
	    printk("[%d (%d-%d)]: %d / %d = %d\n",		\
		   i,						\
		   stats[i].startline, stats[i].endline,	\
		   (int)stats[i].total, stats[i].count,		\
		   (int)stats[i].total / stats[i].count);		\
	    total += stats[i].total / stats[i].count;			\
	  }						\
	  stats[i].total = 0;				\
	  stats[i].count = 0;				\
	}						\
	passes = 0;					\
	printk("=== %d\n", total);			\
      }							\
    } while(0)

#else
#define TIME_STARTFUNC(MAXSAMPLES, INTERVAL)
#define TIME_START(X)
#define TIME_END(X)
#define TIME_SEGFIRST()
#define TIME_SEG()
#define TIME_SEGLAST()
#define TIME_ENDFUNC()
#endif

#endif
