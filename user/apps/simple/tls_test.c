#include <stdio.h>
#include <unistd.h>
#include <pthread.h>
#include <assert.h>
#include <stdlib.h>
#include <nexus/sema.h>

void __attribute__((noinline)) print_array(int *array, int len) {
  int i;
  for(i=0; i < len; i++) {
    printf("%d ", array[i]);
  }
  printf("\n");
}

// #define SYNC_PRINT
#ifndef SYNC_PRINT
#define P(X) 
#define V_nexus(X) 
#endif

Sema *tls_print_sema;

int check_tls(int x) {
#define VAR1_VAL (10)
  static __thread int test_var; // -4
  static __thread int test_var1 = VAR1_VAL; // -8

  int i;
  int expect_var = -1;
  int expect_var1 = -1;
  P(tls_print_sema);
  printf("check_tls(%d)\n", x);
  V_nexus(tls_print_sema);
  for(i=0; i < 2; i++) {
    if(i == 0) {
      test_var = pthread_self();
      test_var1 *= test_var;
      expect_var = test_var;
      expect_var1 = VAR1_VAL * test_var;
    }
    P(tls_print_sema);
    printf("t=%d[%d,%d]: stack @ %p, tls @ %p %p, test_var1 = %d, test_var = %d\n",
	   (int) pthread_self(),
	   i,
	   x,
	   &x,
	   &test_var1, &test_var, test_var1, test_var);
    V_nexus(tls_print_sema);
    int *a0;
    a0 = &test_var;
    int *a1;
    a1 = &test_var1;

    // printf("%p  == %p ?\n", a1+1, a0); // tbss is above tdata
    // print_array(a1, 2);

    int rnd = drand48() * 1000000;
    if(i== 0) {
      // 3000000
      usleep(0 + rnd);
    }
  }
  if(test_var != expect_var) {
    P(tls_print_sema);
    printf("ERROR ! t=%d %p (%d) test_var = %d(%p), expect_var = %d, test_var1 = %d, expect_var1 = %d\n",
	   x, &x, (int) pthread_self(),
	   test_var, &test_var, expect_var,
	   test_var1, expect_var1);
    V_nexus(tls_print_sema);
  }
  assert(test_var == expect_var);
  assert(test_var1 == expect_var1);
  test_var = -test_var;
  test_var1 = -test_var1;
  // printf("exiting %d\n", pthread_self());
  return 0;
}

int main(int argc, char **argv) {
  if(argc == 1) {
    printf("(%d) TLS Null test: checking to see that compat library initialization code works\n", argc);
    return 0;
  } else {
#if 0
    tls_print_sema = sema_new();
    sema_initialize(tls_print_sema, 1);
#else
    Sema tls_print_sema_real = SEMA_MUTEX_INIT;
    tls_print_sema = &tls_print_sema_real;
#endif
    int num_threads = atoi(argv[1]);
    if(num_threads <= 0) num_threads = 4;
    printf(" TLS fork test, num_threads = %d\n", num_threads);
    int i;
    pthread_t *threads = malloc(sizeof(pthread_t) * num_threads);

    for(i=0;  i < num_threads; i++) {
      pthread_create(&threads[i], NULL, (void *(*)(void*)) check_tls, (void *) i);
    }
    check_tls(-1);
    // wait for all threads to finish
    sleep(5);
    printf("Done with tls_test\n");
    return 0;
  }
}
