/** NexusOS: small set of regression tests. 
 
    These are called from the unittest framework in test.c */

#include <nexus/defs.h>
#include <nexus/clock.h>
#include <nexus/thread.h>
#include <nexus/synch.h>
#include <nexus/synch-inline.h>

static int threadtesthelper(void *arg) {
  int *term_flag = (int*)arg;
  int total = 100;

  while(total--) {
    int j;
    for(j=0; j < 100; ++j) ;
    nexusthread_yield();
  }
  *term_flag = 1;
  return 0;
}

int run_preemption_test(void) {
  extern int preemption_enabled;

  if (preemption_enabled) {
    printkx(PK_TEST, PK_DEBUG, "Preemption enabled\n");
    return 0;
  } else {
    printkx(PK_TEST, PK_DEBUG, "Preemption not enabled\n");
    return 1;
  }
}

int run_thread_test(void) {
  int term0 = 0;
  int term1 = 0;
  nexusthread_fork(threadtesthelper, &term0); 
  nexusthread_fork(threadtesthelper, &term1); 
  for(;;) {
    if(term0 && term1) break;
    nexusthread_yield();
  }
  return 0;
}

struct PingPong {
  Sema *a, *b;
  int cycle_count;
} pingpong;

static int sema_thread1(void *arg) {
  int *done = (int*)arg;
  P(pingpong.a);
  V(pingpong.b);
  *done = 1;
  return 0;
}

static int sema_thread2(void *arg) {
  int *done = (int*)arg;
  __u64 start = rdtsc64();
  V(pingpong.a);
  P(pingpong.b);
  __u64 end = rdtsc64();
  pingpong.cycle_count = end - start;
  *done = 1;
  return 0;
}

int run_sema_pingpong_test(void) {
#define NUM_TESTS 2
  static int results[NUM_TESTS];
  int i;
  int result_count = 0;

  for(result_count = 0; result_count < NUM_TESTS; result_count++) {
    Sema *a = sema_new(), *b = sema_new();
    int done1 = 0, done2 = 0;
    pingpong.a = a;
    pingpong.b = b;
    nexusthread_fork(sema_thread1, &done1);
    nexusthread_fork(sema_thread2, &done2);

    for(;;) {
      if(done1 && done2) break;
      nexusthread_yield();
    }
    sema_destroy(a);
    sema_destroy(b);
    results[result_count] = pingpong.cycle_count;
  }

  int ping_pong_avg = 0;
  for(i=0; i < NUM_TESTS; i++)
    ping_pong_avg += results[i];
  

  printkx(PK_TEST, PK_DEBUG, 
	  "[test] sema pingpong: cycle count was %d = %d / %d\n", 
  	  ping_pong_avg / NUM_TESTS, ping_pong_avg, NUM_TESTS);
  return 0;
}

