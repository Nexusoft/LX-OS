#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

#include <nexus/formula.h>
#include <nexus/debug.h>


int main(int ac, char **av) {

  global_debug_level = DEBUG_LEVEL_INFO;

  // open a file, check the signature
  char *filename = av[1];
  if (!filename) {
    printf("usage: %s <filename> -- verify a signedformula stored in a file\n", av[0]);
    exit(1);
  }

  int fd = open(filename, 0);
  if (fd < 0) {
    printf("no file: %s\n", filename);
    exit(1);
  }

  char buf[5000];
  int len = read(fd, buf, sizeof(buf));
  if (len <= 0) {
    printf("no data: %d\n", len);
    exit(1);
  }

  SignedFormula *der = (SignedFormula *)buf;
  int derlen = der_msglen(der->body);
  printf("file contains %d bytes, %d of which are the formula\n", len, derlen);
  if (derlen > len) {
    printf("file appears truncated\n");
    exit(1);
  }

  if (signedform_verify(der) != 0) {
    printf("not a valid signedformula\n");
    exit (1);
  }

  return 0;
}

