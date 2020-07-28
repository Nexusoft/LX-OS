#include <stdio.h>
#include <nexus/Profile.interface.h>

int main(int argc, char **argv){
  printf("Turning off profiler...");
  Profile_Enable(0);
  printf("Writing data... to %s\n", argv[1]);
  
  Profile_Dump(argv[1]);
  return 0;
}
