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
short g_client_port = NQ_NET_DEFAULT_PORT;
NQ_Host g_server_peer;
NQ_Principal *g_server_principal;

static unsigned int num_attributes       = 1;
static unsigned int num_tuples           = 1;
static unsigned int ops_per_transaction  = 0;
static unsigned int num_ops              = 0;
static unsigned int num_bytes_per_op     = 10;
static unsigned int num_threads          = 1;
static unsigned int ops_in_flight        = 1;
static unsigned int trigger_type         = 0x08;

static enum {
  TEST_ATTR_WRITE,                //Hammer the server with write operations
  TEST_ATTR_READ,                 //Hammer the server with read operations
  TEST_TRIGGER_CREATE,            //Hammer the server with trigger create operations
  TEST_TRANSACTION_BASE,          //Hammer the server with transactions
  TEST_TRANSACTION_SYNC_VETO,     //Hammer the server with transactions (on elements with a veto trigger)
  TEST_TRANSACTION_ASYNC_VERDICT, //Hammer the server with transactions (on elements with an async verdict trigger)
  TEST_TRANSACTION_SYNC_VERDICT,  //Hammer the server with transactions (on elements with a sync verdict trigger)
  TEST_TRANSACTION_VETO_VETO,     //Hammer the server with transactions (on elements with two veto triggers)
  TEST_TRANSACTION_VERDICT_VETO,  //Hammer the server with transactions (on elements with veto and sync verdic triggers)
  TEST_TRANSACTION_VERDICT_S_A,   //Hammer the server with transactions (on elements with sync and async verdic triggers)
} test_type = TEST_ATTR_WRITE;

static NQ_Tuple           *tuples         = NULL;
static NQ_Attribute_Name **attributes     = NULL;
static char               *output_buffer  = NULL;

//////////// TEST INITIALIZATION FUNCTIONS

void initialize_globals(){
  unsigned int i;
  
  printf("Initializing NetQuery...");
  NQ_init(g_client_port);
  NQ_GC_set_timeout(60000);
  printf("done\n");
  
  g_server_peer.addr = inet_addr(g_server_addr);
  g_server_peer.port = g_server_port;

  g_server_principal = NQ_get_home_principal(&g_server_peer);
  
  output_buffer = new char[num_bytes_per_op];
  srand(time(NULL));
  for(i = 0; i < num_bytes_per_op-1; ++i){
    output_buffer[i] = (char)((random()%26) + 'a');
  }
  output_buffer[i] = '\0';
}

void initialize_tuples(){
  unsigned int x;
  
  tuples = new NQ_Tuple[num_tuples];
  
  NQ_Net_Batch *batch = NQ_Net_Batch_create();
  NQ_Transaction transaction = NQ_Transaction_begin();
  printf("===> Creating Tuples\n");
  for(x = 0; x < num_tuples; x++){
    NQ_Batch_Tuple_create(transaction, g_server_principal, batch);
  }
  for(x = 0; x < num_tuples; x++){
    tuples[x] = NQ_Batch_Tuple_create_finish(batch);
    assert(!NQ_Tuple_equals(tuples[x], NQ_uuid_null));
  }
  NQ_Net_Batch_block(batch); //shouldn't do anything, but hey.
  NQ_Transaction_commit(transaction);
}

void initialize_attributes(){
  char namebuf[50];
  unsigned int x,y;
  char *valbuff;
  int vallen;
  
  attributes = new NQ_Attribute_Name *[num_attributes];
  
  for(x = 0; x < num_attributes; x++){
    sprintf(namebuf, "Att%d", x);
    attributes[x] = NQ_Attribute_Name_alloc(&g_server_peer, NQ_ATTRIBUTE_RAW, namebuf);
  }
  
  printf("===> Creating Attributes\n");
  if(tuples){
    NQ_Net_Batch *batch = NQ_Net_Batch_create();
    NQ_Transaction transaction = NQ_Transaction_begin();
    for(y = 0; y < num_tuples; y++){
      for(x = 0; x < num_attributes; x++){
        valbuff = output_buffer;
        vallen = num_bytes_per_op;
        NQ_Batch_Attribute_operate(transaction, attributes[x], tuples[y], NQ_OPERATION_WRITE, &valbuff, &vallen, batch, NULL, NULL);
      }
    }
    NQ_Net_Batch_block(batch);
    NQ_Transaction_commit(transaction);
  }
}

static int triggers_fired = 0;
int test_trigger_callback(NQ_Transaction transaction, NQ_Trigger_Description *trigger, NQ_Trigger_Upcall_Type type, int arg, void *userdata){
  if(triggers_fired == 0){
    printf("===> Triggers ARE working!\n");
  }
  triggers_fired++;
  return 1;
}

void initialize_triggers(int *triggers){
  unsigned int x, i;
  printf("===> Creating Triggers\n");
  NQ_Net_Batch *batch = NQ_Net_Batch_create();
  NQ_Transaction transaction = NQ_Transaction_begin();
  NQ_Trigger_Description trigger;

  trigger.tuple = NQ_uuid_null;
  trigger.type = NQ_TRIGGER_VALUECHANGED;
  
  for(x = 0; x < num_attributes; x++){
    trigger.name = attributes[x%num_attributes];
    for(i = 0; triggers[i] != 0; i++){
      trigger.upcall_type = triggers[i];
      NQ_Batch_Trigger_create(transaction, g_server_principal, &trigger, &test_trigger_callback, NULL, batch);
    }
  }
  NQ_Net_Batch_block(batch);
  NQ_Transaction_commit(transaction);
}
//////////// TEST CODE

typedef void *(NQ_Test_Function)(NQ_Transaction transaction, int x, NQ_Net_Batch *batch);

void run_default_test(NQ_Test_Function test_begin, NQ_Test_Function test_commit){
  unsigned int x;
  NQ_Transaction transaction;
  NQ_Net_Batch *batch;
  
  transaction = NQ_Transaction_begin();
  batch = NQ_Net_Batch_create();

  for(x = 0; x < ops_in_flight; x++){
    test_begin(transaction, x, batch);
    if(ops_per_transaction != 0){
      if(x % ops_per_transaction == ops_per_transaction -1){
        NQ_Net_Batch_block(batch);
        NQ_Transaction_commit(transaction);
        transaction = NQ_Transaction_begin();
        batch = NQ_Net_Batch_create();
      }
    }
    if((num_ops != 0)&&(num_ops <= x)){
      return;
    }
  }
  printf("===> Max in-flight ops reached.  Steady state achieved (num_ops: %d, ops_in_flight: %d)\n", num_ops, ops_in_flight);
  while((num_ops == 0)||(num_ops > x)){
    test_begin(transaction, x, batch);
    test_commit(transaction, x, batch);
    if(ops_per_transaction != 0){
      if(x % ops_per_transaction == ops_per_transaction -1){
        NQ_Net_Batch_block(batch);
        NQ_Transaction_commit(transaction);
        transaction = NQ_Transaction_begin();
        batch = NQ_Net_Batch_create();
      }
    }
    x++;
  }
}

void *test_attr_write_begin(NQ_Transaction transaction, int x, NQ_Net_Batch *batch){
  char *valbuff = output_buffer;
  int vallen = num_bytes_per_op;

  NQ_Batch_Attribute_operate(transaction, attributes[x%num_attributes], tuples[x%num_tuples], NQ_OPERATION_WRITE, &valbuff, &vallen, batch, NULL, NULL);
  return NULL;
}
void *test_attr_write_commit(NQ_Transaction transaction, int x, NQ_Net_Batch *batch){
  char *valbuff = NULL;
  int vallen = 0;
  NQ_Batch_Attribute_operate_finish(&valbuff, &vallen, batch);
  return NULL;
}
void test_attr_write(void){
  printf("===> Preparing for write test\n");
  initialize_globals();
  initialize_tuples();
  initialize_attributes();
  
  
  printf("===> Write test starting\n");
  run_default_test(test_attr_write_begin, test_attr_write_commit);
}

void *test_attr_read_begin(NQ_Transaction transaction, int x, NQ_Net_Batch *batch){
  char *valbuff = NULL;
  int vallen = 0;

  NQ_Batch_Attribute_operate(transaction, attributes[x%num_attributes], tuples[x%num_tuples], NQ_OPERATION_READ, &valbuff, &vallen, batch, NULL, NULL);
  return NULL;
}
void *test_attr_read_commit(NQ_Transaction transaction, int x, NQ_Net_Batch *batch){
  char *valbuff = NULL;
  int vallen = 0;
  NQ_Batch_Attribute_operate_finish(&valbuff, &vallen, batch);
  assert(valbuff);
  assert(vallen == (int)num_bytes_per_op);
  free(valbuff);
  return NULL;
}
void test_attr_read(void){
  printf("===> Preparing for read test\n");
  initialize_globals();
  initialize_tuples();
  initialize_attributes();
  
  printf("===> Read test starting\n");
  run_default_test(test_attr_read_begin, test_attr_read_commit);
}

void *test_trigger_create_begin(NQ_Transaction transaction, int x, NQ_Net_Batch *batch){
  NQ_Trigger_Description trigger;
  trigger.name = attributes[x%num_attributes];
  trigger.tuple = tuples[x%num_tuples];
  trigger.type = NQ_TRIGGER_VALUECHANGED;
  trigger.upcall_type = trigger_type;
  
  NQ_Batch_Trigger_create(transaction, g_server_principal, &trigger, &test_trigger_callback, NULL, batch);
  return NULL;
}
void *test_trigger_create_commit(NQ_Transaction transaction, int x, NQ_Net_Batch *batch){
  NQ_Batch_Trigger_create_finish(transaction, batch);
  return NULL;
}
void test_trigger_create(void){
  printf("===> Preparing for trigger creation test\n");
  initialize_globals();
  initialize_tuples();
  initialize_attributes();
  
  printf("===> Trigger creation test starting\n");
  run_default_test(test_trigger_create_begin, test_trigger_create_commit);
  
}

typedef struct {
  NQ_Transaction *transactions;
  struct timeval *times;
  unsigned int    total_delta;
  unsigned int    started_ptr;
  unsigned int    issued_ptr;
  unsigned int    finished_ptr;
  unsigned int    committed_ptr;
  NQ_Net_Batch   *transact_batch;
  NQ_Net_Batch   *op_batch;
  NQ_Net_Batch   *commit_batch;
} Transaction_Test_State;

#define TRANSACTION_POLL_UDELAY 10

extern "C" int NQ_Net_Batch_finish(NQ_Net_Batch *batch, unsigned char **retdata, unsigned int *retlen, unsigned int *type);
void *transaction_commit_step(Transaction_Test_State *state){
  int printed_ready = 0;
  struct timeval now;
  while(1){
    unsigned char *valbuff = NULL;
    unsigned int vallen = 0;
    unsigned int type = 0;
    while(state->finished_ptr == state->committed_ptr){
      usleep(TRANSACTION_POLL_UDELAY);
    }
    NQ_Net_Batch_finish(state->commit_batch, &valbuff, &vallen, &type);
    gettimeofday(&now, NULL);
    state->total_delta += (now.tv_usec - state->times[state->committed_ptr].tv_usec) / 1000 + (now.tv_sec - state->times[state->committed_ptr].tv_sec) * 1000;
    state->times[state->committed_ptr] = now;
    NQ_Batch_Transaction_begin(NQ_Net_get_localhost(), state->transact_batch);
    if(valbuff) free(valbuff);
    assert(type == NQ_REQUEST_TRANSACTION_COMMIT | NQ_REQUEST_RESPONSE);
    state->committed_ptr = (state->committed_ptr + 1)%ops_in_flight;
    if(state->committed_ptr == 0){
      if(!printed_ready){
        printed_ready = 1;
        printf("===> Finished one round.  Steady state entered\n");
      }
      printf("Average transaction time: %d us\n", state->total_delta/ops_in_flight);
      state->total_delta = 0;
    }
  }
}
void *transaction_finish_step(Transaction_Test_State *state){
  int ret;
  while(1){
    char *valbuff = NULL;
    int vallen = 0;
    while(state->issued_ptr == state->finished_ptr){
      usleep(TRANSACTION_POLL_UDELAY);
    }
    if((ret = NQ_Batch_Attribute_operate_finish(&valbuff, &vallen, state->op_batch) & 0xffff)){
      printf("Error with batch attribute operate: %d\n", ret);
      assert(0);
    }
    NQ_Batch_Transaction_commit(state->transactions[state->finished_ptr], state->commit_batch);
    state->finished_ptr = (state->finished_ptr + 1)%ops_in_flight;
  }
}
void *transaction_issue_step(Transaction_Test_State *state){
  while(1){
    char *valbuff = output_buffer;
    int vallen = num_bytes_per_op;
    while(state->issued_ptr == state->started_ptr){
      usleep(TRANSACTION_POLL_UDELAY);
    }
    NQ_Batch_Attribute_operate(state->transactions[state->issued_ptr], attributes[state->issued_ptr % num_attributes], tuples[state->issued_ptr % num_tuples], NQ_OPERATION_WRITE, &valbuff, &vallen, state->op_batch, NULL, NULL);
    state->issued_ptr = (state->issued_ptr + 1)%ops_in_flight;
  }
}
void test_transaction(int *transaction_types){
  unsigned int x;
  Transaction_Test_State state;
  pthread_t issue_thread, finish_thread, commit_thread;
  
  bzero(&state, sizeof(Transaction_Test_State));
  state.transactions   = new NQ_Transaction[ops_in_flight];
  state.times          = new struct timeval[ops_in_flight];
  state.op_batch       = NQ_Net_Batch_create();
  state.commit_batch   = NQ_Net_Batch_create();
  state.transact_batch = NQ_Net_Batch_create();
  state.total_delta    = 0;
  
  initialize_globals();

  printf("===> Preparing for transaction creation test: {");
  for(x = 0; transaction_types[x] != 0; x++){
    printf(" 0x%03x", transaction_types[x]);
  }
  printf(" }\n");
  initialize_tuples();
  initialize_attributes();
  initialize_triggers(transaction_types);
  
  printf("===> Started transaction test\n");
  
  for(x = 0; x < ops_in_flight; x++){
    gettimeofday(&state.times[state.committed_ptr], NULL);
    NQ_Batch_Transaction_begin(NQ_Net_get_localhost(), state.transact_batch);
  }
  
  pthread_create(&issue_thread, NULL, (void * (*)(void *))&transaction_issue_step, &state);
  pthread_create(&finish_thread, NULL, (void * (*)(void *))&transaction_finish_step, &state);
  pthread_create(&commit_thread, NULL, (void * (*)(void *))&transaction_commit_step, &state);
  while(1){
    state.transactions[state.started_ptr] = NQ_Batch_Transaction_begin_finish(state.transact_batch);
    state.started_ptr = (state.started_ptr + 1)%ops_in_flight;
    while(state.started_ptr%ops_in_flight == state.committed_ptr){
      usleep(TRANSACTION_POLL_UDELAY);
    }
  }
}

//////////// TEST SUPPORT CODE

void select_test_type(char *strname){
  if(strcmp("write", strname) == 0){
    test_type = TEST_ATTR_WRITE;
  } else if(strcmp("read", strname) == 0){
    test_type = TEST_ATTR_READ;
  } else if(strcmp("trigger", strname) == 0){
    test_type = TEST_TRIGGER_CREATE;
  } else if(strcmp("tr_b", strname) == 0){
    test_type = TEST_TRANSACTION_BASE;
  } else if(strcmp("tr_v", strname) == 0){
    test_type = TEST_TRANSACTION_SYNC_VETO;
  } else if(strcmp("tr_a", strname) == 0){
    test_type = TEST_TRANSACTION_ASYNC_VERDICT;
  } else if(strcmp("tr_s", strname) == 0){
    test_type = TEST_TRANSACTION_SYNC_VERDICT;
  } else if(strcmp("tr_vv", strname) == 0){
    test_type = TEST_TRANSACTION_VETO_VETO;
  } else if(strcmp("tr_sv", strname) == 0){
    test_type = TEST_TRANSACTION_VERDICT_VETO;
  } else if(strcmp("tr_sa", strname) == 0){
    test_type = TEST_TRANSACTION_VERDICT_S_A;
  } else {
    printf("Unknown test type: '%s'\n", strname);
    exit(0);
  }
}

void start_test(){
  switch(test_type){
    case TEST_ATTR_WRITE:
      test_attr_write();
      break;
    case TEST_ATTR_READ:
      test_attr_read();
      break;
    case TEST_TRIGGER_CREATE:
      test_trigger_create();
      break;
    case TEST_TRANSACTION_BASE:
      test_transaction((int[]){0});
      break;
    case TEST_TRANSACTION_SYNC_VETO:
      test_transaction((int[]){1,0});
      break;
    case TEST_TRANSACTION_ASYNC_VERDICT:
      test_transaction((int[]){4,0});
      break;
    case TEST_TRANSACTION_SYNC_VERDICT:
      test_transaction((int[]){2,0});
      break;
    case TEST_TRANSACTION_VETO_VETO:
      test_transaction((int[]){1,1,0});
      break;
    case TEST_TRANSACTION_VERDICT_VETO:
      test_transaction((int[]){1,2,0});
      break;
    case TEST_TRANSACTION_VERDICT_S_A:
      test_transaction((int[]){2,4,0});
      break;
  }
}

int main(int argc, char **argv){
  int opt;
  
  while( (opt = getopt(argc, argv, "a:t:r:n:b:h:o:s:p:c:y:wm")) != -1 ) {
    switch(opt){
      case 'a': 
        num_attributes = atoi(optarg);
        break;
      case 't': 
        num_tuples = atoi(optarg);
        break;
      case 'r': 
        ops_per_transaction = atoi(optarg);
        break;
      case 'n': 
        num_ops = atoi(optarg);
        break;
      case 'b': 
        num_bytes_per_op = atoi(optarg);
        break;
      case 'h': 
        num_threads = atoi(optarg);
        break;
      case 'o': 
        ops_in_flight = atoi(optarg);
        break;
      case 's': 
        g_server_addr = strdup(optarg);
        break;
      case 'p': 
        g_server_port = atoi(optarg);
        break;
      case 'c': 
        g_client_port = atoi(optarg);
        break;
      case 'y':
        select_test_type(optarg);
        break;
      case 'w':
        NQ_Show_RPCs();
        break;
      case 'm':
        NQ_Local_Transaction_enable_fast_commit();
        break;
      default:
        printf("Unknown option : %c\n", opt);
        exit(0);
    }
  }
  
  start_test();
}
