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

static unsigned int num_attributes;
static unsigned int num_tuples;
static unsigned int num_transactions;
static unsigned int num_updates;
static unsigned int num_bytes_perupdate;
static unsigned int num_threads;

std::vector<NQ_Tuple> tuples;
std::vector<NQ_Attribute_Name *> attributes;
struct timeval start_time, stop_time;
unsigned int total_time = 0;

void generate_random_data(char *buffer){
  unsigned int i;
  srand(time(NULL));
  for(i = 0; i < num_bytes_perupdate-1; ++i){
    buffer[i] = (char)((random()%26) + 'a');
  }
  buffer[i] = '\0';
}

void prepare_for_test(){
  NQ_Transaction transaction = NQ_Transaction_begin();
  NQ_Host peer;
  peer.addr = inet_addr(g_server_addr);
  peer.port = g_server_port;
  NQ_Principal *princ = NQ_get_home_principal(&peer);
  char namebuf[50];
  
  printf("===> Preparing for test: %d Attrs, %d Tuples, %d Transactions (batches of %d), %d Updates, %d Bytes per Update\n", num_attributes, num_tuples, num_transactions, (num_updates / num_transactions), num_updates, num_bytes_perupdate);
  
  unsigned int x;
  NQ_Net_Batch *batch = NQ_Net_Batch_create();
  for(x = 1; x <= num_tuples; x++){
    NQ_Batch_Tuple_create(transaction, princ, batch);
  }
  for(x = 1; x <= num_tuples; x++){
    NQ_Tuple newtuple = NQ_Batch_Tuple_create_finish(batch);
    assert(!NQ_Tuple_equals(newtuple, NQ_uuid_null));
    tuples.push_back(newtuple);
  }
  NQ_Net_Batch_block(batch); //shouldn't do anything, but hey.
  NQ_Transaction_commit(transaction);
  
  while(attributes.size() < num_attributes){
    sprintf(namebuf, "Att%ld", (long)attributes.size());
    attributes.push_back(NQ_Attribute_Name_alloc(&peer, NQ_ATTRIBUTE_RAW, namebuf));
  }
}
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
void test_timestamp(char *reason){
  long int timediff;
  struct timeval curr_time;
  gettimeofday(&curr_time, NULL);
  
  timediff = curr_time.tv_sec - start_time.tv_sec;
  timediff *= 1000*1000;
  timediff += curr_time.tv_usec;
  timediff -= start_time.tv_usec;
  printf("===> %s: %ld usec\n", reason, timediff);
}
void run_add_test_pipelined(){
  NQ_Transaction transaction;
  unsigned int ops_per_transaction = num_updates / num_transactions;
  unsigned int x, y;
  int attr, tuple;
  char *valbuff = new char[num_bytes_perupdate];
  int vallen = num_bytes_perupdate;
  NQ_Net_Batch *batch;

  prepare_for_test();
  start_test();
  
  for(x = 0; x < num_updates; x += y){
    transaction = NQ_Transaction_begin();
    printf("Creating batch update\n");
    batch = NQ_Net_Batch_create();
    printf("Operating %d times\n", ops_per_transaction);
    for(y = 0; (y+x < num_updates) && (y < ops_per_transaction); y++){
      attr = (y+x) % attributes.size();
      tuple = (y+x) % tuples.size();
      generate_random_data(valbuff);
      NQ_Batch_Attribute_operate(transaction, attributes[attr], tuples[tuple], NQ_OPERATION_WRITE, &valbuff, &vallen, batch, NULL, NULL);
    }
    printf("done.  Blocking for all to complete\n");
    NQ_Net_Batch_block(batch); //also destroys batch;
    printf("Committing transaction\n");
    NQ_Transaction_commit(transaction);
    printf("next transaction\n");
  }
  
  finish_test();
  delete valbuff;
}

#define REPEAT_MODE_DURATION 300

void *run_add_test_repeated(){
  NQ_Transaction transaction;
  char *valbuff = new char[num_bytes_perupdate];
  int vallen = num_bytes_perupdate;
  int err;
  int attr, tuple;
  
  prepare_for_test();
  start_test();
  
  printf("===> Hammer process spawned: running for %d seconds\n", REPEAT_MODE_DURATION);

  generate_random_data(valbuff);
  
  do {
    attr = random() % attributes.size();
    tuple = random() % tuples.size();
    transaction = NQ_Transaction_begin();
    err = NQ_Attribute_operate(transaction, attributes[attr], tuples[tuple], NQ_OPERATION_WRITE, &valbuff, &vallen);
    if(err < 0){
      printf("===> Hammer process got an error: %d on write\n", err);
      assert(0);
    }
    err = NQ_Transaction_commit(transaction);
    if(err < 0){
      printf("===> Hammer process got an error: %d on commit\n", err);
      assert(0);
    }
    gettimeofday(&stop_time, NULL);
  } while(stop_time.tv_sec < start_time.tv_sec + REPEAT_MODE_DURATION);
  
  printf("===> Hammer process finished cleanly\n");
  delete valbuff;
  return 0;
}

void *run_add_test_threaded_instance(void *dummy){
  NQ_Transaction transaction;
  char *valbuff = new char[num_bytes_perupdate];
  int vallen = num_bytes_perupdate;
  long unsigned int id = (long unsigned int)dummy;
  int err;
  
  generate_random_data(valbuff);
  transaction = NQ_Transaction_begin();
  assert(!NQ_UUID_eq(&transaction, &NQ_uuid_error));
  err = NQ_Attribute_operate(transaction, attributes[0], tuples[id], NQ_OPERATION_WRITE, &valbuff, &vallen);
  if(err != 0){
    printf("Operate error: %d\n", err);
  }
  err = NQ_Transaction_commit(transaction);
  if(err != 0){
    printf("Commit error: %d\n", err);
  }
  printf("Thread %ld finished\n", id);
  delete valbuff;
  return NULL;
}
void run_add_test_threaded(){
  pthread_t *threads;
  unsigned int i;

  threads = new pthread_t[num_threads];
  bzero(threads, sizeof(pthread_t) * num_threads);
  
  num_tuples = num_threads;
  
  printf("Threaded mode, active!\n");
  
  prepare_for_test();
  start_test();
  
  for(i = 0; i < num_threads; i++){
    pthread_create(&(threads[i]), NULL, run_add_test_threaded_instance, (void *)i);
  }
  for(i = 0; i < num_threads; i++){
    pthread_join(threads[i], NULL);
  }
  
  finish_test();
  delete threads;
}

void run_add_test(){
  NQ_Transaction transaction;
  unsigned int ops_per_transaction = num_updates / num_transactions;
  unsigned int x, y;
  int attr, tuple;
  std::string val;
  char *valbuff;
  int vallen;
  
  prepare_for_test();
  start_test();
  
  for(x = 0; x < num_updates; x += y){
    transaction = NQ_Transaction_begin();
    for(y = 0; (y+x < num_updates) && (y < ops_per_transaction); y++){
      val = "Value_" + (y+x);
      attr = random() % attributes.size();
      tuple = random() % tuples.size();
      valbuff = (char *)val.c_str();
      vallen = strlen(valbuff)+1;
      NQ_Attribute_operate(transaction, attributes[attr], tuples[tuple], NQ_OPERATION_WRITE, &valbuff, &vallen);
    }
    NQ_Transaction_commit(transaction);
  }
  
  finish_test();
}

int calls_back = 0;

int trigger_callback(NQ_Transaction transaction, NQ_Trigger_Description *trigger, NQ_Trigger_Upcall_Type type, int arg, void *userdata){
//  long int id = (long int)userdata;
//  printf("===> callback: %ld\n", id);
  calls_back++;
  return 1;
}

NQ_Trigger *install_triggers(int trigger_type){
  NQ_Trigger_Description desc;
  NQ_Transaction trans;
  NQ_Net_Batch *batch;
  NQ_Trigger *triggers = new NQ_Trigger[attributes.size()];
  unsigned int x;
  
  desc.tuple = NQ_uuid_null;
  desc.type = NQ_TRIGGER_VALUECHANGED;
  desc.upcall_type = trigger_type;

  batch = NQ_Net_Batch_create();
  trans = NQ_Transaction_begin();
  for(x = 0; x < attributes.size(); x++){
    desc.name = attributes[x];
    //printf("===> create: %d\n", x);
    NQ_Batch_Trigger_create(trans, &NQ_default_owner, &desc, trigger_callback, (void *)x, batch);
  }
  for(x = 0; x < attributes.size(); x++){
    triggers[x] = NQ_Batch_Trigger_create_finish(trans, batch);
  }
  NQ_Net_Batch_block(batch);
  NQ_Transaction_commit(trans);
  return triggers;
}

void run_transaction_test(int trigger_type){
  char *val = new char[num_bytes_perupdate];
  NQ_Transaction *transactions = new NQ_Transaction[num_transactions];
  NQ_Net_Batch *trans_batch, *op_batch, *commit_batch;
  unsigned int x;
  int err;
  int attr, tupl;
  NQ_Trigger *triggers = NULL;
  
  num_updates = num_attributes = num_tuples = num_transactions;
  generate_random_data(val);
  
  prepare_for_test();
  
  if(trigger_type != 0){
    triggers = install_triggers(trigger_type);
  }
  
  trans_batch = NQ_Net_Batch_create();
  op_batch = NQ_Net_Batch_create();
  commit_batch = NQ_Net_Batch_create();
  
  start_test();
  
  for(x = 0; x < num_transactions; x++){
    NQ_Batch_Transaction_begin(NQ_Net_get_localhost(), trans_batch);
  }
//  printf("Operating\n");
  for(x = 0; x < num_transactions; x++){
    char *valbuff = val;
    int vallen = num_bytes_perupdate;
    transactions[x] = NQ_Batch_Transaction_begin_finish(trans_batch);
//    if(x == 0){printf("Created: ");NQ_UUID_print(&transactions[x]);printf("\n");}
    assert(!NQ_UUID_eq_err(&transactions[x]));
    attr = x % attributes.size();
    tupl = x % tuples.size();
    err = NQ_Batch_Attribute_operate(transactions[x], attributes[attr], tuples[tupl], NQ_OPERATION_WRITE, &valbuff, &vallen, op_batch, NULL, NULL);
  }
//  printf("Committing\n");
  for(x = 0; x < num_transactions; x++){
    char *ret;
    int retlen;
    NQ_Batch_Attribute_operate_finish(&ret, &retlen, op_batch);
    if(ret){ free(ret); }
  }
  for(x = 0; x < num_transactions; x++){
    NQ_Batch_Transaction_commit(transactions[x], commit_batch);
  }
  NQ_Net_Batch_destroy(trans_batch);
  NQ_Net_Batch_block(op_batch);
  NQ_Net_Batch_block(commit_batch);
  
  finish_test();
  printf("===> %d calls back\n", calls_back);
  delete transactions;
  delete val;
  if(triggers){ delete triggers; }
}

int main(int argc, char **argv){  
  int opt;
  enum { 
    UPDATE_TEST_BASIC, 
    UPDATE_TEST_LOOPED, 
    UPDATE_TEST_TRANSACTION,
  } test_mode = UPDATE_TEST_BASIC;
  unsigned short server_port = 5500;
  int iterations = 1;
  int trigger_type = 0;
  
  num_attributes      = 1;
  num_tuples          = 1;
  num_transactions    = 1;
  num_updates         = 1;
  num_bytes_perupdate = 10;
  num_threads         = 1;
  
  while( (opt = getopt(argc, argv, "h:a:t:r:u:b:e:lp:ni:y:")) != -1 ) {
    switch(opt) {
    case 'h':
      g_server_addr = strdup(optarg);
      break;
    case 'a':
      num_attributes = atoi(optarg);
      break;
    case 't':
      num_tuples = atoi(optarg);
      break;
    case 'r':
      num_transactions = atoi(optarg);
      break;
    case 'u':
      num_updates = atoi(optarg);
      break;
    case 'b':
      num_bytes_perupdate = atoi(optarg);
      break;
    case 'e':
      num_threads = atoi(optarg);
      break;
    case 'l':
      num_threads = 0;
      test_mode = UPDATE_TEST_LOOPED;
      break;
    case 'p':
      server_port = atoi(optarg);
      break;
    case 'n':
      test_mode = UPDATE_TEST_TRANSACTION;
      break;
    case 'i':
      iterations = atoi(optarg);
      break;
    case 'y':
      trigger_type = atoi(optarg);
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
  for(int x = 0; x < iterations; x++){
    switch(test_mode){
      case UPDATE_TEST_BASIC:
        if(num_threads > 1){
          run_add_test_threaded();
        } else {
          run_add_test_pipelined();
        }
        break;
      case UPDATE_TEST_LOOPED:
        run_add_test_repeated();
        break;
      case UPDATE_TEST_TRANSACTION:
        run_transaction_test(trigger_type);
        break;
    }
  }  
  
  printf("===> All iterations finished: %d us\n", total_time);
  fprintf(stderr, "Test complete\n");
  return 0;
}
