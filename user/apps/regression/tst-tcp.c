#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

int serversock;
int server_result = 0;
// test connect

int mode = 0;

// we might eventually test send and receive data, but connect already
// has bidirectional packet flow

const char *testbuf = "DEADBEEF";
void *server_thread_fn(void *_ctx) {
  struct sockaddr_in saddr;
  unsigned int size = sizeof(struct sockaddr_in);
  int connsock;
  do {
    // printf("(A)");
    connsock = accept(serversock, (struct sockaddr *)&saddr, &size);
    // printf("=>%d", connsock);
  } while(connsock < 0 && errno == EAGAIN);
  if(connsock < 0) {
    printf("Server could not accept %d\n", connsock);
    exit(-1);
  }
  printf("Server connected, got %d, %x:%d\n", connsock, htonl(saddr.sin_addr.s_addr), htons(saddr.sin_port));
  server_result = 1;

  int len = strlen(testbuf);
  if(send(connsock, testbuf, len, 0) < len) {
    printf("could not send data\n");
    exit(-1);
  }
  printf("sent data\n");

  if(mode == 0) {
    sleep(10);
    printf("Success!\n");
    exit(0);
  }
  return 0;
}

int server_port = 1500;

int main(int argc, char **argv) {
  // mode 0 = both
  // mode 1 = server only
  // mode 2 = client only
  if(argc >= 2) {
    mode = atoi(argv[1]);
  }
  if(argc >= 3) {
    server_port = atoi(argv[2]);
  }

  printf("Testing local connections\n");
  struct sockaddr_in saddr = {
    .sin_family = AF_INET,
    .sin_addr.s_addr = getmyinet_addr(), // INADDR_ANY,
    .sin_port = htons(server_port),
  };

  if(mode == 0 || mode == 1) {
    serversock = socket(PF_INET, SOCK_STREAM, 0);
    if(serversock <= 0) {
      printf("Could not open server socket!\n");
      exit(-1);
    }
    if(bind(serversock, (struct sockaddr *)&saddr, sizeof(saddr)) < 0) {
      printf("Could not bind server socket\n");
      exit(-1);
    }
    listen(serversock, 10);
    printf("Server is now listening at %d\n", server_port);

    pthread_t server_thread;
    if(pthread_create(&server_thread, NULL, server_thread_fn, NULL) != 0) {
      printf("Could not create server thread\n");
      exit(-1);
    }
  }

  if(mode == 0 || mode == 2) {
    printf("Trying to connect\n");
    int clientsock = socket(PF_INET, SOCK_STREAM, 0);
    if(connect(clientsock, (struct sockaddr *)&saddr, sizeof(saddr)) < 0) {
      printf("Could not connect server sock\n");
    }
    printf("Client connected\n");

    sleep(1);
    char data[128];
    int len = strlen(testbuf);
    printf("Client trying to read\n");
    if(recv(clientsock, data, len, 0) != len) {
      printf("Could not receive data!\n");
      exit(-1);
    }
    if(strncmp(testbuf, data, len) != 0) {
      printf("Did not receive correct data!n");
      exit(-1);
    }

    printf("Success!\n");
    exit(0);
  } else {
    sleep(20);
    printf("Server exited from main (should have been from thread)?\n");
    exit(-1);
  }
}
