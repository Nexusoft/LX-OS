#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>

/* inspired by memory leaks noticed when writing files of the same name but 
 * larger and larger sizes. */

#define KB (1024)
#define MB (1024 * 1024)
#define START_SIZE (1 * MB)
#define END_SIZE (8 * MB)
#define STEP (1 * MB)


int main(int argc, char **argv){
  int size;
  char *filename = "/nfs/filewrite.test";

  printf("running filewrite regression test\n");

  for(size = START_SIZE; size <= END_SIZE; size += STEP){
    char *file;
    int fd;

    file = (char *)malloc(size);

    fd = open(filename, O_CREAT|O_WRONLY|O_TRUNC);

    if(fd < 0){
      printf("open error\n");
      return -1;
    }

    if(write(fd, file, size) < 0){
      printf("write error\n");
      return -1;
    }

    close(fd);

    free(file);
  }

  printf("done with filewrite regression test\n");

  return 0;
}
