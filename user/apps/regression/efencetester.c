#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <nexus/mt19937ar.h>

#define MINSIZE (8192)
#define MAXSIZE (16 * 8192)

int main(int argc, char **argv){
  char *testbuf;

  if(argc != 2){
    printf("usage efencetester 0x7e575eed");
  }
  unsigned int seed = strtoul(argv[1], NULL, 16);
  pseudorand_init(seed);


  int size = pseudorand(MINSIZE, MAXSIZE);

  testbuf = (char *)malloc(size);
  
  memset(testbuf, 0, size);

  /* efence should catch this */
  //testbuf[size] = 0x0f;

  printf("exiting efencetester\n");

  return 0;
}
