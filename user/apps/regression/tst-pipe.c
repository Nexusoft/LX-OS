#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

// Write this many bytes
#define TEST_LEN 		(8192)
#define CHECK_LEN 	(10)


int pipes[2];
unsigned char *gen_pattern(int start, int len) {
  int i;
  unsigned char *rv = malloc(len);
  for(i=0; i < len; i++) {
    unsigned char check_val = start + i;
    rv[i] = check_val;
  }
  return rv;
}

int verify_generic(unsigned char *buf, int len, int gen_start) {
  int i;
  unsigned char *pattern = gen_pattern(gen_start, len);
  for(i=0; i < len; i++) {
    if(buf[i] != pattern[i]) {
      printf("verification failed at %d/%d (%x,%x)\n", i, len, pattern[i], buf[i]);
      free(pattern);
      return 0;
    }
  }
  free(pattern);
  return 1;
}
int verify(unsigned char *buf, int len) {
  return verify_generic(buf, len, 0);
}

typedef struct WriterContext {
  int delay;
  int write_len;
  int num_iterations;
  int gen_start;
} WriterContext;

WriterContext *make_context(int delay, int write_len, int num_iterations, int gen_start) {
  WriterContext *rv = malloc(sizeof(*rv));
  rv->delay = delay;
  rv->write_len = write_len;
  rv->num_iterations = num_iterations;
  rv->gen_start = gen_start;
  return rv;
}

void writer_thread_fn(void *_ctx) {
  WriterContext *ctx = _ctx;
  int i;
  sleep(ctx->delay);
  int pattern_start = 0;
  for(i=0; i < ctx->num_iterations; i++) {
    unsigned char *test_buf = gen_pattern(ctx->gen_start + i * ctx->write_len, ctx->write_len);
    if(write(pipes[1], test_buf, ctx->write_len) != ctx->write_len) {
      printf("Writer thread write failed\n");
      exit(-1);
    }
    free(test_buf);
  }
}

int recv_and_check(int len, int gen_start) {
  int err;
#define MAX_RECV_LEN (TEST_LEN)
  assert(len < MAX_RECV_LEN);
  unsigned char *recv_buf = malloc(MAX_RECV_LEN);
  memset(recv_buf, -1, sizeof(recv_buf));

  unsigned char *rbuf = recv_buf;
  int recv_tot = 0;
  while(recv_tot < len) {
    int amt = read(pipes[0], rbuf, len - recv_tot);
    if(amt < 0) {
      printf("receive and check recieved %d (%d < %d)\n", amt, recv_tot, len);
      err = 0;
      goto out;
    }
    recv_tot += amt;
    rbuf += amt;
  }
  assert(recv_tot == len);
  err = verify_generic(recv_buf, len, gen_start);
 out:
  free(recv_buf);
  return err;
}

int main(int argc, char **argv) {
  if(pipe(pipes) != 0) {
    printf("Could not create pipe!\n");
    return -1;
  }

  char *test_buf = gen_pattern(0, CHECK_LEN);

  // API check
  printf("Checking disallowed write\n");
  int err;
  if( !((err = write(pipes[0], test_buf, CHECK_LEN)) <= 0) ) {
    printf("Should not have been allowed to write to reader pipe (err = %d)\n", err);
    exit(-1);
  }
  printf("  passed\n");

  printf("Checking allowed read\n");
  if( !(write(pipes[1], test_buf, CHECK_LEN) == CHECK_LEN) ) {
    printf("Should have been allowed to write to reader pipe\n");
    exit(-1);
  }
  if( !recv_and_check(CHECK_LEN, 0) ) {
    printf("Did not receive from reader pipe\n");
    exit(-1);
  }
  printf("  passed\n");

  printf("Checking blocked allowed read\n");
  pthread_t writer_thread;
  pthread_create(&writer_thread, NULL,
		 writer_thread_fn, make_context(1, CHECK_LEN, 1, 0));
  if( !recv_and_check(CHECK_LEN, 0) ) {
    printf("Should have received %d bytes from reader pipe\n", CHECK_LEN);
    exit(-1);
  }
  printf("  passed\n");

  printf("Checking single read / write, overlap end of pipe\n");
  int base_size[] = { 5, 10, 25, 50, 100 };
  // Single read / write ; overlap end of pipe
  int i;
  for(i=0; i < sizeof(base_size) / sizeof(base_size[0]); i++) {
    int size = base_size[i];
    int num_iterations = TEST_LEN / size;
    int j;
    for(j=0; j < num_iterations; j++) {
      int start = j * 100;
      writer_thread_fn(make_context(0, size, 1, start));
      if( !recv_and_check(size, start)) {
	printf("Failed at %d, %d\n", size, j);
	exit(-1);
      }
    }
  }
  printf("  passed\n");

  printf("Checking multiple writes per read\n");
  for(i=0; i < sizeof(base_size) / sizeof(base_size[0]); i++) {
    int size = base_size[i];
    int num_iterations = TEST_LEN / size;
    int start = size;
    pthread_create(&writer_thread, NULL,
		   writer_thread_fn, make_context(0, size, num_iterations, start));
    if( !recv_and_check(size * num_iterations, start)) {
      printf("Failed at %d\n", size);
      exit(-1);
    }
  }
  printf("  passed\n");
  printf("Checking multiple reads per write\n");
  for(i=0; i < sizeof(base_size) / sizeof(base_size[0]); i++) {
    int size = base_size[i];
    int num_iterations = 2048 / size;
    int start = size;
    pthread_create(&writer_thread, NULL,
		   writer_thread_fn, make_context(0, num_iterations * size, 1, start));
    int j;
    for(j=0; j < num_iterations; j++) {
      if( !recv_and_check(size, start + j * size)) {
	printf("Failed at %d\n", size);
	exit(-1);
      }
    }
  }
  printf("  passed\n");
#if 0

  int multiplier = { 2, 3, 4, 5 };
  // Multiple writes per read

  // Multiple reads per write
#endif
  printf("Success!\n");
  return 0;
}
