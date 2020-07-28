#include <unistd.h>
#include <stdio.h>

int main(int argc, char **argv){

  printf("sleeping for 1 second\n");
  sleep(1);
  printf("finished sleeping\n");

  return 0;
}
