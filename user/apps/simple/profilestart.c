#include <stdio.h>
#include <nexus/Profile.interface.h>

int main(int argc, char **argv){
  printf("Turning on profiler...");
  Profile_Enable(1);
  printf("Done.");
  return 0;
}
