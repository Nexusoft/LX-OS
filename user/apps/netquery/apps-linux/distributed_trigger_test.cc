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

#define UPDATE_SIZE 10

char *g_server_addr = "128.84.227.25";
short g_server_port = NQ_NET_DEFAULT_PORT;
NQ_Host g_server_peer;
short g_client_port = 5500;
int num_triggers = 10000;
int trigger_type = 1;
NQ_Attribute_Name **attributes;

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

void generate_random_data(char *buffer){
  unsigned int i;
  srand(time(NULL));
  for(i = 0; i < UPDATE_SIZE-1; ++i){
    buffer[i] = (char)((random()%26) + 'a');
  }
  buffer[i] = '\0';
}

int trigger_callback(NQ_Transaction transaction, NQ_Trigger_Description *trigger, NQ_Trigger_Upcall_Type type, int arg, void *userdata){
  int *id = (int *)userdata;
  if(*id == 0){
    printf("===> callback: %d\n", *id);
  }
  return 1;
}

void initialize_system(){
  int x;
  char buffer[100];
  
  callback_ids = new int[num_triggers];
  
  attributes = new NQ_Attribute_Name *[num_triggers];
  for(x = 0; x < num_triggers; x++){
    sprintf(buffer, "TestAtt%d", x);
    attributes[x] = NQ_Attribute_Name_alloc(&g_server_peer, NQ_ATTRIBUTE_RAW, buffer);
  }
}

void install_triggers(){
  int x;
  NQ_Transaction trans;
  NQ_Net_Batch *batch;
  NQ_Trigger_Description desc;
  NQ_Trigger *triggers = new NQ_Trigger[num_triggers];
  
  g_server_peer.addr = inet_addr(g_server_addr);
  g_server_peer.port = g_server_port;
  
  initialize_system();
  
  batch = NQ_Net_Batch_create();
  
  desc.tuple = NQ_uuid_null;
  desc.type = NQ_TRIGGER_VALUECHANGED;
  desc.upcall_type = trigger_type;

  start_test();
  
  trans = NQ_Transaction_begin();

  for(x = 0; x < num_triggers; x++){
    desc.name = attributes[x];
    callback_ids[x] = x;
    NQ_Batch_Trigger_create(trans, &NQ_default_owner, &desc, trigger_callback, &(callback_ids[x]), batch);
  }
  
  for(x = 0; x < num_triggers; x++){
    triggers[x] = NQ_Batch_Trigger_create_finish(trans, batch);
    assert(!NQ_UUID_eq_err(&triggers[x]));
  }
  NQ_Net_Batch_block(batch);
  NQ_Transaction_commit(trans);
  
  finish_test();
  
  while(1) sleep(1000);
}

void fire_triggers(){
  int x;
  NQ_Transaction trans;
  NQ_Net_Batch *op_batch, *commit_batch;
  char value[UPDATE_SIZE];
  NQ_Tuple tuple;
  
  printf("Preparing to fire triggers\n");
  
  g_server_peer = NQ_Net_get_localhost();
  g_client_port = NQ_NET_DEFAULT_PORT;
  
  initialize_system();
  generate_random_data(value);
  
  op_batch = NQ_Net_Batch_create();
  trans = NQ_Transaction_begin();
  tuple = NQ_Tuple_create(trans, &NQ_default_owner);
  for(x = 0; x < num_triggers; x++){
    char *valbuff = value;
    int vallen = UPDATE_SIZE;
    NQ_Batch_Attribute_operate(trans, attributes[x], tuple, NQ_OPERATION_WRITE, &valbuff, &vallen, op_batch, NULL, NULL);
  }
  NQ_Net_Batch_block(op_batch);
  NQ_Transaction_commit(trans);
  
  printf("Waiting for ready state (hit enter to continue)\n");
  while(getchar() != '\n');
  
  op_batch = NQ_Net_Batch_create();
  commit_batch = NQ_Net_Batch_create();
  
  start_test();
  trans = NQ_Transaction_begin();
  
  for(x = 0; x < num_triggers; x++){
    char *valbuff = value;
    int vallen = UPDATE_SIZE;
    NQ_Batch_Attribute_operate(trans, attributes[x], tuple, NQ_OPERATION_WRITE, &valbuff, &vallen, op_batch, NULL, NULL);
  }
  NQ_Net_Batch_block(op_batch);
  NQ_Transaction_commit(trans);

  finish_test();
}

int main(int argc, char **argv){
  int opt;
  enum { INSTALL_TRIGGERS, FIRE_TRIGGERS } client_mode = INSTALL_TRIGGERS;
  
  while( (opt = getopt(argc, argv, "s:p:c:ifa:t:")) != -1 ) {
    switch(opt){
    case 's':
      g_server_addr = strdup(optarg);
      break;
    case 'p':
      g_server_port = atoi(optarg);
      break;
    case 'c':
      g_client_port = atoi(optarg);
      break;
    case 'i':
      client_mode = INSTALL_TRIGGERS;
      break;
    case 'f':
      client_mode = FIRE_TRIGGERS;
      g_client_port = NQ_NET_DEFAULT_PORT;
      break;
    case 'a':
      num_triggers = atoi(optarg);
      break;
    case 't':
      trigger_type = atoi(optarg);
      break;
    default:
      printf("Unknown option\n");
      exit(-1);
    }
  }
  
  printf("Initializing NetQuery...\n");
  NQ_init(g_client_port);
  NQ_GC_set_timeout(60000);
  NQ_publish_home_principal();
  printf("done\n");
  
  switch(client_mode){
    case INSTALL_TRIGGERS:
      install_triggers();
      break;
    case FIRE_TRIGGERS:
      fire_triggers();
      break;
  }
  
  return 0;
}
