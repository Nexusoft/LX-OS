#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>

/* inspired by nfs cache not getting trimmed when operating on big files */

#define BLOCK 4096

int main(int argc, char **argv){
  char *buf[BLOCK];

  printf("running fileread regression test\n");

  int fd = open("/nfs/fileread.text", O_RDONLY);
  if (fd < 0) {
    printf("open error\n");
    return -1;
  }

  printf("reading %d byte blocks:\n", BLOCK);
  int n = 0;
  for (;;) {
    int s = read(fd, buf, BLOCK);
    if (s < 0) { printf("read error: %d\n", s); break; }
    if (!s) { printf("eof\n"); break; }
    n += s;
    printf(".");
  }

  close(fd);

  printf("\nread %d bytes\n", n);

  return 0;
}
