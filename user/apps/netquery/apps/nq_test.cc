#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#include <nq/netquery.h>
#include <nq/net.h>
#include <nq/scripting.hh>

int main(int argc, char **argv){
  FILE *init_scr;
  
#ifndef NQ_NO_NETWORK
  NQ_Net_set_localserver();
#endif
  
  printf("Initializing NetQuery...");
  NQ_init(0);
  printf("done\n");
  
  if(argc <= 1){
    printf("Usage: %s configfile\n", argv[0]);
    exit(0);
  }
  printf("Opening test script file...");
  init_scr = fopen(argv[1], "r");
  if(!init_scr){
    printf("Error: Can't open %s\n", argv[1]);
    exit(0);
  }
  printf("done\n");
  
  printf("Loading scripting interface...");
  NQ_Scripting_init();
  printf("done\n");
  
  printf("Running test script (%s):\n", argv[1]);
  NQ_Scripting_process(init_scr);
  
  return 0;
}
