#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>


#include <nq/netquery.h>
#include <nq/net.h>
#include <nq/garbage.h>

char *g_server_addr = "128.84.227.25";
short g_server_port = NQ_NET_DEFAULT_PORT;

std::vector<NQ_Attribute_Name *> attributes;

static int num_triggers = 1;

struct timeval start_time, stop_time;
unsigned int total_time = 0;
int *callback_ids;

void start_test(){
  gettimeofday(&start_time, NULL);
  printf("===> Starting test: %ld.%06ld sec\n", start_time.tv_sec, start_time.tv_usec);
}

void finish_test(){
  long int timediff;
  gettimeofday(&stop_time, NULL);
  
  printf("===> Finished test: %ld.%06ld sec\n", stop_time.tv_sec, stop_time.tv_usec);
  timediff = stop_time.tv_sec - start_time.tv_sec;
  timediff *= 1000*1000;
  timediff += stop_time.tv_usec;
  timediff -= start_time.tv_usec;
  total_time += timediff;
  printf("===> Total time: %ld usec\n", timediff);
}

int trigger_callback(NQ_Transaction transaction, NQ_Trigger_Description *trigger, NQ_Trigger_Upcall_Type type, int arg, void *userdata){
  int *id = (int *)userdata;
  printf("===> callback: %d\n", *id);
  return 1;
}

void run_trigger_create(int upcall_type){
  NQ_Transaction trans;
  NQ_Tuple tup;
  char *namebuf = "TestAtt";
  int x, len = strlen(namebuf)+1;
  NQ_Net_Batch *batch;
  NQ_Attribute_Name *name;
  NQ_Trigger *triggers = new NQ_Trigger[num_triggers];
  NQ_Trigger_Description desc;
  callback_ids = new int[num_triggers];
  NQ_Host peer;
  peer.addr = inet_addr(g_server_addr);
  peer.port = g_server_port;
  
  trans = NQ_Transaction_begin();
  tup = NQ_Tuple_create(trans, &NQ_default_owner);
  name = NQ_Attribute_Name_alloc(&peer, NQ_ATTRIBUTE_RAW, namebuf);
  NQ_Attribute_operate(trans, name, tup, NQ_OPERATION_WRITE, &namebuf, &len);
  NQ_Transaction_commit(trans);
  
  desc.name = name;
  desc.tuple = NQ_uuid_null;
  desc.type = NQ_TRIGGER_VALUECHANGED;
  desc.upcall_type = upcall_type;
  
  start_test();
  
  trans = NQ_Transaction_begin();
  batch = NQ_Net_Batch_create();
  for(x = 0; x < num_triggers; x++){
    callback_ids[x] = x;
    NQ_Batch_Trigger_create(trans, &NQ_default_owner, &desc, trigger_callback, &(callback_ids[x]), batch);
  }
  
  for(x = 0; x < num_triggers; x++){
    triggers[x] = NQ_Batch_Trigger_create_finish(trans, batch);
  }
  NQ_Net_Batch_block(batch);
  NQ_Transaction_commit(trans);
  
  finish_test();
  
  delete triggers;
  delete callback_ids;
}

int main(int argc, char **argv){  
  unsigned short server_port = NQ_NET_DEFAULT_PORT;
  int opt;
  
  while( (opt = getopt(argc, argv, "h:p:t:")) != -1 ) {
    switch(opt) {
    case 'h':
      g_server_addr = strdup(optarg);
      break;
    case 'p':
      server_port = atoi(optarg);
      break;
    case 't':
      num_triggers = atoi(optarg);
      break;
    default:
      printf("Unknown option\n");
      exit(-1);
    }
  }
  
  printf("Initializing NetQuery...");
  NQ_init(server_port);
  NQ_GC_set_timeout(60000);
  printf("done\n");
  
  run_trigger_create(NQ_TRIGGER_UPCALL_SYNC_VETO);
  
  return 0;
}
