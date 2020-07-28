#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
//#include <mplayer/malloc.h>
//#include <malloc.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#include <string>
#include <vector>
#include <assert.h>
#include "../include/util/getopt.h"
#include <netinet/in.h>
#include <arpa/inet.h>
#include <queue>
#include <pthread.h>
#include <sched.h>
extern "C" {
#include <nexus/Profile.interface.h>
#include <nexus/KernelFS.interface.h>
#include "../include/nbgp/bgp.h"
}
#include "../include/util/ghetto_pcap.h"
#include "../include/util/g_tl.h"
#include "../include/nbgp/nbgp.h"
#include "../include/util/common.h"
#include "../include/util/reassemble.h"
#include "../include/nbgp/bgpcheck.h"
#include "../include/util/safe_malloc.h"
#include "../include/runtime/minisocket.h"

extern "C" {
extern int writefile(char *filename, char *buffer, int size);
}

#define INITIAL_BUFFER_SIZE 100

int process_input(FILE *insource, Command_List *cmds){
  char *cmd = (char *)malloc(INITIAL_BUFFER_SIZE);
  char *err;
  int buff_sz = INITIAL_BUFFER_SIZE;
  int len;

  while(!feof(insource)){
    len = 0;
    while(!feof(insource) && (fread(&(cmd[len]), 1, 1, insource) > 0)) {
      if((cmd[len] == '\n') || (cmd[len] == '\r')){
        if(len > 0) break;
        else continue;
      }
      len++;
      if(len + 2 > buff_sz){
        buff_sz *= 2;
        cmd = (char *)realloc(cmd, buff_sz);
      }
    }
    cmd[len] = '\0';
    if((err = cmds->process_command(cmd)) != NULL){
      printf("Error: %s\n", err);
      exit(0);
    }
  } 
  free(cmd);
  if(ferror(insource)){
    printf("Error reading file\n");
    exit(0);
  }
  return 0;
}

int main(int argv, char **argc){
  FILE *init_scr; //SET THIS
  Command_List *cmds = new Command_List();
  
  printf("Initializing SSL\n");
  init_minisocket();
  
  printf("Opening config file\n");
  if((argv < 1) || (argc[1] == NULL)){
    printf("Usage: %s configfile\n", argc[0]);
    exit(0);
  }
  init_scr = fopen(argc[1], "r");
  if(!init_scr){
    printf("Error: Can't open %s\n", argc[1]);
    exit(0);
  }
  
  printf("Loading interface\n");
  install_nbgp_commands(cmds);
  
  printf("Running initialization script\n");
  process_input(init_scr, cmds);
  
  printf("Starting monitor\n");
  nbgp_monitor_loop();
}
