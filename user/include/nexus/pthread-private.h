#ifndef _PTHREAD_PRIVATE_H_
#define _PTHREAD_PRIVATE_H_

#include <stdint.h>

struct PThread_Stack {
  uint32_t first_page;
  int num_pages;
};

struct PThread {
  struct {
    struct PThread *next;
    struct PThread *prev;
  } sema_link; // also used for condition variable

  pthread_t threadid;
  pthread_attr_t attr;
  int canceltype;
  int cancelstate;
  int cancelreq;

  struct PThread_Stack stack;
};

struct PThread *pthread_get_my_tcb(void);
pthread_t pthread_threadid(struct PThread *p);

#endif // _PTHREAD_PRIVATE_H_

