#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h> 
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <libgen.h>

#include "pzip.h"
#include "aas_send.h"

#include "aas_common.c"

int connectToTruDoc(const char *server_addr /* dot notation */, short server_port) {
  struct sockaddr_in addr = { 0 };

  int fd = socket(PF_INET, SOCK_STREAM, 0);
  int err = bind(fd, (struct sockaddr *)&addr, sizeof(addr));

  struct sockaddr_in dest;
  dest.sin_family = AF_INET;
  if (inet_aton(server_addr, &dest.sin_addr) == 0) {
    printf("invalid address: %s\n", server_addr);
    return -1;
  }

  printf("connecting to trudoc at %s:%d\n", server_addr, server_port);

  int port_last = server_port + 10;
  for (;;) {
    dest.sin_port = htons(server_port);
    err = connect(fd, (struct sockaddr *)&dest, sizeof(dest));
    if (err) {
      printf("failed to connect: errno = %d\n", errno);
      if (++server_port >= port_last) {
	printf("giving up\n");
	return -1;
      }
      continue;
    }
    break;
  }

  return fd;
}

int main(int ac, char **av) {

  if (ac < 4) {
    printf("usage: %s trudoc_server_ip output_file target_odf [src_odf ...]\n", av[0]);
    exit(1);
  }

  char *server_addr = av[1];
  char *outfile = av[2];
  char **infiles = av+3;
  int n = ac - 3;

  // construct 

  int fd = connectToTruDoc(server_addr, TRUDOC_SERVER_PORT);
  if (fd < 0) exit(1);

  send_string(fd, TRUDOC_HELLO);
  send_int(fd, n);
  while (n) {
    send_odf(fd, infiles[0]);
    infiles++;
    n--;
  }

  int err;
  if (read_int(fd, &err)) {
    printf("bad response\n");
    close(fd);
    exit(1);
  }

  if (err != 0) {
    printf("trudoc refuses to sign\n");
    close(fd);
    exit(1);
  }

  char *response;
  if (read_string(fd, &response)) {
    printf("bad response data\n");
    close(fd);
    exit(1);
  }

  int out = open(outfile, O_WRONLY | O_CREAT | O_TRUNC, 0770);
  if (out < 0) {
    printf("could not open: %s\n", outfile);
    close(fd);
    exit(1);
  }
  write(out, response, strlen(response));
  close(out);

  close(fd);

  printf("success\n");

  exit(0);
}
