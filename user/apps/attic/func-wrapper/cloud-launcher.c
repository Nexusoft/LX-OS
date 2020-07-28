#include <openssl/ssl.h>
#include <openssl/err.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <assert.h>

#include <pthread.h>
#include <nexus/formula.h>
#include <nexus/IPC.interface.h>
#include "Cloud.interface.h"
#include "ssl.h"
#include "cloud.h"

int g_child_ipd;

SSL *data_ssl;

#define NUM_IPC_THREADS (4)
static pthread_t ipc_threads[NUM_IPC_THREADS];
static pthread_t accept_threads[NUM_IPC_THREADS];

static void *processing_loop_ipc(void *ctx) { while(1) Cloud_processNextCommand(); }
static void *accept_loop(void *ctx) { while(1) IDL_BINDACCEPT(Cloud); }  

#define PING() printf("(%d)\n", __LINE__)

int main(int argc, char **argv) {
  int i;
  if(argc < 2) {
    printf("Usage: cloud-launcher <port_num>\n");
    exit(-1);
  }
  int port_num = atoi(argv[1]);

  ssl_init();
  load_nexus_keys();

  Cloud_serverInit();
  for(i=0; i < NUM_IPC_THREADS - 1; i++) {
    if(pthread_create(&ipc_threads[i], NULL, processing_loop_ipc, (void *) i)) {
      printf("could not fork ipc processing thread %d\n", i);
    }
    if(pthread_create(&accept_threads[i], NULL, accept_loop, NULL)) {
      printf("could not fork accept thread %d\n", i);
    }
  }

  printf("Binding to socket %d\n", port_num);
  int listen_sock = socket(PF_INET, SOCK_STREAM, 0);
  struct sockaddr_in addr;
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = INADDR_ANY;
  addr.sin_port = htons(port_num);
  int err = bind(listen_sock, (struct sockaddr *)&addr, sizeof(addr));
  if(err != 0) {
    printf("Could not bind listen sock!\n");
    exit(-1);
  }
  err = listen(listen_sock, 4);
  assert(err == 0);

  struct sockaddr_in acceptaddr;
  int addrlen = sizeof(struct sockaddr_in);
  int data_sock;
  while(1) {
    data_sock = accept(listen_sock, (struct sockaddr*)&acceptaddr, (size_t*)&addrlen);
    if(data_sock > 0) {
      break;
    }
  }
  assert(data_sock > 0);

  data_ssl = SSL_new(server_ctx);
  printf("main ssl = %p, sock = %d\n", data_ssl, data_sock);
  SSL_set_fd(data_ssl, data_sock);
PING();
  SSL_accept(data_ssl);

  printf("Got connection\n");
  send_ssl_labels(data_ssl);
PING();

  printf("Receiving ELF from client\n");
  struct CloudStartHeader hdr;
  ssl_recv_all(data_ssl, &hdr, sizeof(hdr));
  printf("Executable length is %d, name is %s\n", hdr.exec_len, hdr.exec_name);
  unsigned char *buf = malloc(hdr.exec_len);
  ssl_recv_all(data_ssl, buf, hdr.exec_len);

  printf("Forking executable\n");

  char args[128];
  printf("Cloud port num = %d\n", Cloud_server_port_num);
  sprintf(args, "%d", Cloud_server_port_num);
  memcpy(args + strlen(args) + 1, hdr.arg, hdr.arg_len);
  int tot_len = strlen(args) + 1 + hdr.arg_len;

  g_child_ipd = IPC_FromElf(hdr.exec_name, strlen(hdr.exec_name) + 1,
		       buf, hdr.exec_len, 
		       args, tot_len);
  printf("IPD id is %d\n", g_child_ipd);
  
  // Protocol finishes once the cloud application
  while(!process_started) {
    sleep(1);
  }
  return 0;
}
