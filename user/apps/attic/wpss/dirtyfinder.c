#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <nexus/defs.h>
#include <nexus/tpmcompat.h>

#include "rwpss.h"

#define MB (1024 * 1024)
#define SIZE 128

int main(int argc, char **argv){
  unsigned char *reg;
  unsigned int *pagearray;
  int i;

  pagearray = (unsigned int *)malloc(SIZE * MB / PAGESIZE);
  reg = (unsigned char *)malloc(SIZE*MB);
  
  for(i = 0; i < 100; i++){
    get_region_bitmap(reg, SIZE * MB, 0, (unsigned char *)pagearray);

    printf("%lld\n",GET_TIME(t));
  }

  return 0;
}

