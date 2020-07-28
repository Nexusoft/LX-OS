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

#include <libtcpa/identity_private.h>
#include <libtcpa/keys.h>

#include <assert.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include <string.h>

#include <nexus/util.h>
#include <nexus/ca.h>

void debug_show_data(char *name, unsigned char *buf, int len, int show_hash, char *save_filename) {
  int i;

  if (name) printf("%s: ", name);
  if (len <= 20) {
    for(i = 0; i < 20; i++)
      printf("%02x ", buf[i]);
  } else {
    for(i = 0; i < 10; i++)
      printf("%02x ", buf[i]);
    printf("...");
    for(i = len-10; i < len; i++)
      printf("%02x ", buf[i]);
  }
  printf("\n");
  if (show_hash) {
    unsigned char hash[20];
    SHA1(buf, len, hash);
    printf("  (hash: ");
    for(i = 0; i < 20; i++)
      printf("%02x", hash[i]);
    printf(")\n");
  }
  if (save_filename) {
    if (!write_file(save_filename, buf, len))
      printf("  (saved in %s)\n", save_filename);
    else
      printf("  (error saving in %s)\n", save_filename);
  }
}

int send_data(int fd, unsigned char *data, int len) {
  int sent = 0;
  printf("Sending (%d bytes)...", len);
  fflush(stdout);
  while(sent < len) {
    int n = send(fd, data + sent, len - sent, 0); 
    if (n <= 0) {
      perror("sending");
      printf("Giving up on this connection after %d of %d bytes sent\n", sent, len);
      return -1;
    }
    sent += n;
    printf(".");
  fflush(stdout);
  }
  printf(" done\n");
  return 0;
}

int init_server(int port) {
  struct sockaddr_in addr;

  printf("Listening on port %d\n", port);
  int fd = socket(PF_INET, SOCK_STREAM, 0);

  addr.sin_addr.s_addr = 0;
  addr.sin_port = htons(port);
  int err = bind(fd, (struct sockaddr *)&addr, sizeof(addr));
  if(err < 0) {
    perror("could not bind to port");
    printf("exiting");
    exit(1);
  }

  err = listen(fd, 4);
  if(err < 0) {
    perror("could not listen on port");
    printf("exiting");
    exit(1);
  }

  printf("Going to background... ");
  fflush(stdout);
  daemon(1, 1);
  printf("ok\n");

  return fd;
}

int server_wait(int s, int good, int bad) {
    struct sockaddr_in addr;
    printf("So far: %d successful requests, %d failed requests\n", good, bad);
    printf("Waiting for connection... ");
    fflush(stdout);
    unsigned int len = sizeof(addr);
    int conn = accept(s, (struct sockaddr*)&addr, &len);
    if (conn < 0) {
      perror("could not accept connection");
      printf("exiting");
      exit(1);
    }

    printf("accepted connection from %s port %d\n",
	inet_ntoa(addr.sin_addr),
	ntohs(addr.sin_port));

    return conn;
}
