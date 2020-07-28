#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>

#include <nq/netquery.h>
#include <nq/net.h>
#include <nq/garbage.h>
#include <nq/scripting.hh>

#include <string>
#include <fstream>
#include <nq/marshall.hh>

using namespace std;

void print_all(void) {
  NQ_dump_stats();
  cout.flush();
  fflush(stdout);
  fsync(fileno(stdout));
}

void sig_print(int v) {
  printf("%lf: USR2 Dump Stats\n", doubleTime());
  print_all();
}
void sig_break(int v) {
  cerr << "Got break\n";
  exit(0);
}

int main(int argc, char **argv){
#ifdef NEXUS
  NQ_nexus_init();
#endif

  FILE *init_scr;
  signal(SIGINT, sig_break);
  signal(SIGUSR2, sig_print);
  atexit(print_all);

  int opt;
  short daemon_port = NQ_NET_DEFAULT_PORT;
  while( (opt = getopt(argc, argv, "p:s:grS")) != -1) {
    switch(opt) {
    case 'p':
      // Override port number
      daemon_port = atoi(optarg);
      printf("Using daemon port %d\n", daemon_port);
      break;
    case 's':
      NQ_Net_set_stats(atoi(optarg));
      break;
    case 'g':
      printf("Disabling garbage collection\n");
      NQ_GC_set_timeout(1000000000);
      break;
    case 'r':
      printf("Showing all rpcs\n");
      show_rpc_traffic = 1;
      break;
    case 'S':
      NQ_enable_periodic_stats();
      break;
    default:
      printf("UNKNOWN OPTION %c\n", (char) opt);
      exit(-1);
    }
  }
  
  printf("Initializing NetQuery...");
  NQ_init(daemon_port);
  printf("done\n");

#if 1
  printf("Disabling garbage collection\n");
  NQ_GC_set_timeout(1000000);
#endif

  printf("Opening config file...");
  if(argc - optind >= 1){
    init_scr = fopen(argv[optind], "r");
    if(!init_scr){
      printf("Error: Can't open %s\n", argv[optind]);
      exit(0);
    }
    printf("done\n");
    
    printf("Loading scripting interface...");
    NQ_Scripting_init();
    printf("done\n");
    
    printf("Running setup script (%s):\n", argv[0]);
    NQ_Scripting_process(init_scr);
  }

  printf("Outputting host\n");

#if 0
  NQ_Host h = NQ_Net_get_localhost();
  h.port = daemon_port;
  string principal_fname = NQ_Host_as_string(h) + ".principal";
  NQ_publish_principal(&NQ_default_owner, principal_fname.c_str());
#else
  NQ_publish_home_principal();
#endif

  while(1){
    sleep(10000);
  }
  
  return 0;
}
