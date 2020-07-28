#include "Sync.interface.h"
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h> // for sleep()
#include <nexus/IPC.interface.h>

Connection_Handle server_conn_handle;

static void *accept_loop(void *ctx) {
  printf("starting accept loop\n");
  printf("server port %d\n", Sync_server_port_num);
  server_conn_handle = IDL_BINDACCEPT(Sync);
  return NULL;
}
static void *server_loop(void *ctx) {
  Sync_processNextCommand();

  return NULL;
}

int main(int argc, char **argv) {
  pthread_t sync_accept_thread, server_thread;
  printf("sync ipc test, no ack\n");

  Sync_serverInit();
  pthread_create(&sync_accept_thread, NULL, accept_loop, NULL);
  pthread_create(&server_thread, NULL, server_loop, NULL);
  // wait for the server to fork
  sleep(1);
  Sync_clientInit();
  // wait for the server to finish
  sleep(1);

  printf("port_num = %d, client conn_handle = %d, server_conn_handle = %d\n", Sync_client_port_num, Sync_conn_handle, server_conn_handle);

  if(argc < 2) {
    printf("Not enough arguments!\n");
    exit(-1);
  }
  int test_num = atoi(argv[1]);
  switch(test_num) {
  case 0:
  case 1:
    {
    printf("Sync close connection test\n");
    printf("The next call should succeed\n");
    int rv;
    rv = Sync_Call();
    if(rv != 0) {
      printf("Call failed!\n");
      exit(-1);
    }
    if(test_num == 0) {
      printf("Closing client side conn handle\n");
      rv = IPC_CloseConnection(Sync_conn_handle);
    } else if(test_num == 1) {
      printf("Closing server side conn handle\n");
      rv = IPC_CloseConnection(server_conn_handle);
    } else {
      printf("Unknown test num %d!\n", test_num);
      exit(-1);
    }
    if(rv != 0) {
      printf("Error closing connection\n");
      exit(-1);
    }
    printf("The next call should fail\n");
    rv = Sync_Call();
    if(rv == 0) {
      printf("Call should have failed!\n");
      exit(-1);
    }
    printf("Test succeeded!\n");
    exit(0);
    break;
  }
  default:
    printf("Unknown test %d\n", test_num);
    exit(-1);
  }
  return -1;
}
