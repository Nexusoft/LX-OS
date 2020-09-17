#ifndef __PTHREAD_NEXUS_H__
#define __PTHREAD_NEXUS_H__

#include <pthread.h>

typedef struct PThread PThread;
pthread_t pthread_self(void);
int pthread_nexusid(PThread *p);
void pthread_init_main(unsigned int stackbase);

#endif
