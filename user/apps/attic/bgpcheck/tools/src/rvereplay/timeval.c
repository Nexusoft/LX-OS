#include <sys/time.h>
#include "timeval.h"

void timeval_add_usec(struct timeval *tv, int usec) {
	tv->tv_usec += usec;
	while (tv->tv_usec >= 1000000)
		tv->tv_sec++, tv->tv_usec -= 1000000;
	while (tv->tv_usec < 0)
		tv->tv_sec--, tv->tv_usec += 1000000;
}

int timeval_diff(struct timeval *a, struct timeval *b) {
	return (a->tv_sec - b->tv_sec)*1000000 + (a->tv_usec - b->tv_usec);
}

void timeval_set(struct timeval *tv, int usec) {
	tv->tv_sec = usec / 1000000;
	tv->tv_usec = usec % 1000000;
}

int timeval_after(struct timeval *a, struct timeval *b) {
	return (a->tv_sec > b->tv_sec) || (a->tv_sec == b->tv_sec && a->tv_usec > b->tv_usec);
}
