#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>

#define THREAD_COUNT (8)
//#define NUM_ITERATIONS (100000000)
#define NUM_ITERATIONS (10000000)

struct Test {
  pthread_t test_thread;
  double seed;
  double check_result;
  double test_result;
  int done;
} tests[] = {
  { .seed = 10 }, 
  { .seed = 37 }, 
  { .seed = 73 }, 
  { .seed = 67 }, 
  { .seed = 23 }, 
  { .seed = 996 }, 
  { .seed = 7574 }, 
  { .seed = 1234 }, 
};

typedef struct Test Test;

double compute_series(double seed, int num_iterations) {
  // geometric series
  const double r = 1.0 / 2.0;
  double accum = seed;
  double r_n = r;
  int i;
  for(i=0; i < num_iterations; i++) {
    accum += seed * r_n;
    r_n *= r;
  }
  return accum;
}

int done_count = 0;
void *compute_thread(void *arg) {
  Test *spec = (Test *)arg;
  spec->test_result = compute_series(spec->seed, NUM_ITERATIONS);
  printf("Done computing %d, seed = %d\n", done_count++, (int)spec->seed);
  spec->done = 1;
  return NULL;
}

int main(int argc, char **argv) {
  int i;
  // Compute the results
  for(i=0; i < THREAD_COUNT; i++) {
    tests[i].check_result = compute_series(tests[i].seed, NUM_ITERATIONS);
    printf("Result[%d] = %d\n", i, (int)tests[i].check_result);
  }
  for(i=0; i < THREAD_COUNT; i++) {
    pthread_create(&tests[i].test_thread, NULL, compute_thread, &tests[i]);
  }

  // Busy-wait for result
  while(1) {
  again:
    sleep(1);
    for(i=0; i < THREAD_COUNT; i++) {
      if(!tests[i].done) goto again;
    }
    break;
  }

  int mismatch_count = 0;
  for(i=0; i < THREAD_COUNT; i++) {
    if(tests[i].test_result != tests[i].check_result) {
      printf("Result mismatch at %d (%x != %x)\n", i,
	     (int) tests[i].test_result, (int) tests[i].check_result);
      mismatch_count++;
    }
  }
  if(mismatch_count > 0) {
    printf("test failed, %d mismatch\n", mismatch_count);
    exit(-1);
  } else {
    printf("test succeeded\n");
    exit(0);
  }
}
