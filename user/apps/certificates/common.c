#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h> 
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>

#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/bio.h>

#include <assert.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include <string.h>

int send_data(int fd, unsigned char *data, int len) {
  int n, sent = 0;

  while (sent < len) {
    n = send(fd, data + sent, len - sent, 0); 
    if (n < 0) {
      printf("Giving up on this connection after %d of %d bytes sent\n", sent, len);
      return -1;
    }
    sent += n;
  }

  return 0;
}

int init_server(int port) {
  struct sockaddr_in addr;
  int fd;
  
  fd = socket(PF_INET, SOCK_STREAM, 0);
  if (fd < 0) {
    perror("socket()");
    exit(1);
  }

  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  addr.sin_addr.s_addr = INADDR_ANY;
  
  if (bind(fd, (struct sockaddr *)&addr, sizeof(addr))) {
    perror("bind()");
    exit(1);
  }

  if (listen(fd, 4) < 0) {
    perror("listen()");
    exit(1);
  }

  printf("Listening on tcp port %d\n", port);
  return fd;
}

int server_wait(int s, int good, int bad) {
    int fd;
    
    fd = accept(s, NULL, NULL);
    if (fd < 0) {
      perror("could not accept connection");
      exit(1);
    }

    return fd;
}
