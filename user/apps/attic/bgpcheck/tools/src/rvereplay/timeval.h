#ifndef TIMEVAL_H
#define TIMEVAL_H

#include <sys/time.h>

#ifdef __cplusplus
extern "C" {
#endif

void timeval_add_usec(struct timeval *tv, int usec);
int timeval_diff(struct timeval *a, struct timeval *b);   /* a - b */
void timeval_set(struct timeval *tv, int usec);
int timeval_after(struct timeval *a, struct timeval *b);  /* a > b */

#ifdef __cplusplus
}
#endif

#endif
