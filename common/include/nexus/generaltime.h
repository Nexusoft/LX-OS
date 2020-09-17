#ifndef __GENERALTIME_H__
#define __GENERALTIME_H__

typedef char TimeString;

#define TIME_MIN_SIZE (2+2+2+2)
#define TIME_MAX_SIZE (4+2+2+2+2+2+1+10+1+4)

#ifndef __NEXUSKERNEL__
/* these functions are only available to user space */
void timestring_destroy(TimeString *t);
TimeString *timestring_create(int year, int month, int day, int hour, int min, int sec);
#endif

#endif
