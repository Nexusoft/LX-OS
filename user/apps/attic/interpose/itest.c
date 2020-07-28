#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <op_types.h>
#include <nexus/IPC.interface.h>
#include <nexus/ipc.h>
#include <nexus/transfer.h>
#include <nexus/interpose.h>
#include "../ipctest/PingPong.interface.h"

#include "InterposeGeneric.interface.h"

#define NUM_THREADS (4)
static pthread_t interpose_threads[NUM_THREADS];
static pthread_t async_interpose_threads[NUM_THREADS];

static void *processing_loop(void *ctx) { while(1) Interpose_processNextCommand(); }

static void *async_processing_loop(void *ctx) {
  while(1) InterposeGeneric_processNextCommand_ext(SERVERPROCESSOR_ASYNC, DEFAULT_PROCESSOR_HANDLE,
				     ((ServerProcessorData) { }));
}

void parse_cmdline(int ac, char **av);

int main(int argc, char **argv) {
  if(argc < 2) {
    printf("itest requires at least one argument (ipd_id to wrap)\n");
    exit(-1);
  }
  parse_cmdline(argc, argv);
  InterposeGeneric_serverInit();
  // PingPong_clientInit();
  int wrap_target = atoi(argv[1]);
  printf("Wrapping %d (%s)\n", wrap_target, argv[1]);

  int data_handle = IPC_Wrap(wrap_target);
  if(data_handle < 0) {
    printf("Wrap data handle error %d\n", data_handle);
    InterposeGeneric_serverDestroy();
    exit(-1);
  }

  printf("Wrap data handle is %d\n", data_handle);
  InterposeGeneric_setServerTarget(data_handle);

  printf("\n");
  int i;
  for(i=0; i < NUM_THREADS - 1; i++) {
    if(pthread_create(&interpose_threads[i], NULL, processing_loop, (void *) i)) {
      printf("could not fork processing thread %d\n", i);
    }
    printf("normal: %lu\n", interpose_threads[i]);

    if(pthread_create(&async_interpose_threads[i], NULL, async_processing_loop, (void *) i)) {
      printf("could not fork async processing thread %d\n", i);
    }
    printf("async: %lu\n", async_interpose_threads[i]);
  }
  while(1) {
    sleep(60);
  }


  //printf("sleeping for 60\n"); sleep(60); exit(-1);
  Interpose_serverDestroy();
  // PingPong_clientDestroy();
  return 0;
}
