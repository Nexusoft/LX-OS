#include <sys/wait.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fstream>
#include <signal.h>
#include <math.h>
#include <unistd.h>

#include <nq/netquery.h>
#include <nq/net.h>
#include <nq/garbage.h>
#include <nq/marshall.hh>
#include <getopt.h>

using namespace std;

bool start_client = false;
bool check_mode = false;

bool is_child = false;

bool save_send_times = false;

int num_subprocesses = 1;
int child_index = -1;
int num_actual_iterations = -1;
int time_limit = 0;
int request_rate = 0;
string server_prefix = "";

const int BURST_LENGTH = 1000;

vector<double> latency_data;
vector<double> send_time;

vector<double> sleep_time;
vector<double> burst_length;
vector<int> adjustments;

void sig_usr2(int v) {
  start_client = true;
}

double rate_interval() {
  return 1.0 / request_rate * 1e6;
}

void rate_delay(void) {
#if 1
  static int op_count;
  static double last_send_time;

  double curr_time = doubleTime();
  if(save_send_times) {
    send_time.push_back(curr_time);
  }
  op_count++;

  if(request_rate != 0) {
    if(op_count == 1) {
      last_send_time = curr_time;
    }
    if(op_count == BURST_LENGTH) {
      op_count = 0;
      double burst_duration = curr_time - last_send_time;
      double interval = 
	rate_interval() * BURST_LENGTH -  /* how long it was supposed to take */
	(burst_duration * 1e6); /* how long it actually took */
      assert(interval < 1e6);
      int adj = 0;
      if(interval > 0) {
	usleep((unsigned)interval);
      } else {
	if(0) {
	  adj = (int)(-interval / rate_interval());
	  assert(adj >= 0);
	  op_count -= adj;
	}
      }
      if(save_send_times) {
	sleep_time.push_back(interval);
	burst_length.push_back(burst_duration * 1e6);
	adjustments.push_back(adj);
      }
      last_send_time = 0;
    }
  }
#else
  static double last_send_time;
  double curr_time = doubleTime();
  int sleep_amount;
  if(last_send_time != 0) {
    sleep_amount = (int) ((rate_interval() - (curr_time - last_send_time)  * 1e6));
  } else {
    sleep_amount = (int) (rate_interval());
  }
  if(sleep_amount < 0) sleep_amount = 0;
  assert(sleep_amount  < 1e6);
  usleep(sleep_amount);
  last_send_time = curr_time;

  if(save_send_times) {
    send_time.push_back(curr_time);
  }
#endif
}

char *g_server_addr = "128.84.227.25";
short g_server_port = NQ_NET_DEFAULT_PORT;

struct Server {
  NQ_Host address;
  NQ_Principal *principal;
  Server(in_addr_t addr, short portnum) {
    address.addr = addr;
    address.port = portnum;
    principal = NQ_get_home_principal(&address);
    assert(principal != NULL);
  }
};

std::vector<Server> servers;

static unsigned int num_attributes;
static unsigned int num_tuples;
static unsigned int num_updates;

struct Tuple;

struct Checker {
  struct Stats {
    int num_good;
    int num_bad;
    Stats() : num_good(0), num_bad(0) { }
  };

  virtual bool run_check(Tuple *tuple, NQ_Transaction check_transaction, Stats *stats = NULL) = 0;
  virtual ~Checker() { }
};

struct Tuple {
  NQ_Tuple tid;
  std::vector<NQ_Attribute_Name *> attributes;
  Checker *checker;
  Tuple(NQ_Tuple _tid) : tid(_tid), checker(NULL) { }
  Tuple() : tid(NQ_uuid_null), checker(NULL) { }
};

std::vector<Tuple> tuples;

const char *spec_tid_fname = "tuples-attrs.tid";

void allowed_write_range(int *lower, int *count) {
  if(is_child) {
    int tstep = tuples.size() / num_subprocesses;
    *lower = tstep * child_index;
    *count = tstep;
  } else {
    *lower = 0;
    *count = tuples.size();
  }
}

int rand_range(int limit) {
    return (int) floor(limit * (rand() / (RAND_MAX + 1.0)));
}

void pick_update_indices(int *tuple_index_p, int *attr_index_p, bool for_write) {
  int tuple_index;
  int attr_index;
  if(!is_child || !for_write) {
    tuple_index = rand_range(tuples.size());
  } else {
    // slice space by tuple ID
    int tstep;
    int lower;
    allowed_write_range(&lower, &tstep);
    tuple_index = lower + rand_range(tstep);
  }
  Tuple *tuple = &tuples[tuple_index];
  attr_index = rand_range(tuple->attributes.size());
  *tuple_index_p = tuple_index;
  *attr_index_p = attr_index;
}

void write_spec(const string &prefix) {
  string fname(prefix + string("-") + spec_tid_fname);
  ofstream ofs(fname.c_str());
  if(!ofs) {
    cerr << "Could not open " << fname << " for output!\n";
    exit(-1);
  }
  file_marshall(tuples.size(), ofs);
  for(size_t i=0; i < tuples.size(); i++) {
    file_marshall(tuples[i].tid, ofs);
    file_marshall(tuples[i].attributes.size(), ofs);
    for(size_t j=0; j < tuples[i].attributes.size(); j++) {
#if 0
      file_marshall(*tuples[i].attributes[j], ofs);
#else
      file_marshall_flat_object(tuples[i].attributes[j]->owner->home, ofs);
      file_marshall((int32_t)tuples[i].attributes[j]->type, ofs);
      file_marshall(string(tuples[i].attributes[j]->name), ofs);
#endif
    }
  }
  ofs.close();
}

void read_spec(const string &prefix) {
  string fname(prefix + string("-") + spec_tid_fname);
  Transaction *t = NULL;
  ifstream ifs(fname.c_str());
  uint32_t num_tuples = 0;
  int total_num_attrs = 0;
  vector<unsigned char> all_data;
  get_all_file_data(ifs, all_data);
  CharVector_Iterator s = all_data.begin(), end = all_data.end();
  printf("file size = %d\n", end - s);

  num_tuples = *tspace_unmarshall(&num_tuples, *t, s, end);
  assert(num_tuples > 0);
  tuples.resize(num_tuples);
  // printf("Num tuples = %d\n", num_tuples);
  for(size_t i=0; i < num_tuples; i++) {
    uint32_t num_attrs = 0;
    tuples[i].tid = *tspace_unmarshall(&tuples[i].tid, *t, s, end);
    num_attrs = *tspace_unmarshall(&num_attrs, *t, s, end);

    assert(num_attrs >= 0);
    tuples[i].attributes.resize(num_attrs);
    // printf("Tid = "); NQ_UUID_print(&tuples[i].tid);
    // printf("num attrs = %d\n", num_attrs);
    for(size_t j=0; j < num_attrs; j++) {
#if 0
      tuples[i].attributes[j] = tspace_unmarshall(tuples[i].attributes[j], *t, s, end);
#else
      NQ_Host host = *unmarshall_flat_object<NQ_Host>(s, end);
      int32_t type = *tspace_unmarshall((int32_t *)0, *t, s, end);
      string name = *tspace_unmarshall((string *)0, *t, s, end);
      tuples[i].attributes[j] =
        NQ_Attribute_Name_alloc(&host, (NQ_Attribute_Type) type, name.c_str());
#endif
      total_num_attrs++;
    }
  }
  printf("Read %d tuples, %d attributes\n", num_tuples, total_num_attrs);
}

bool check_base_tuple_attr(NQ_Transaction t, Tuple *tuple, NQ_Attribute_Name *name) {
  char *valbuf = NULL;
  int vallen = 0;
  // XXX This code is used in the read benchmark. Be careful while modifying it
  int rv = NQ_Attribute_operate(t, &NQ_default_owner, name, tuple->tid, NQ_OPERATION_READ, &valbuf, &vallen, NULL);
  if(rv != 0) {
    printf("error accessing attribute!\n");
    return false;
  }
  if(! (vallen == (int)(strlen(name->name) + 1) && strcmp(name->name, valbuf) == 0) ) {
    printf("Tuple mismatch! %d %d %s %s \n",
           vallen, (int)strlen(name->name), name->name, valbuf);
    return false;
  } else {
    return true;
  }
}

void check_tuples(void) {
  NQ_Transaction t = NQ_Transaction_begin();
  for(size_t i=0; i < tuples.size(); i++) {
    Tuple *tuple = &tuples[i];
    for(size_t j=0; j < tuple->attributes.size(); j++) {
      NQ_Attribute_Name *name = tuple->attributes[j];
      if(!check_base_tuple_attr(t, tuple, name)) {
        printf("check_tuples: exiting due to mismatch\n");
        exit(-1);
      } 
    }
  }
  NQ_Transaction_commit(t);
}

void do_block(NQ_Net_Batch *batch) {
  printf("%lf: done.  Blocking for all to complete\n", doubleTime());
  NQ_Net_Batch_block(batch); //also destroys batch;
}

struct timeval start_time, stop_time;
unsigned int total_time = 0;

int num_bytes_perupdate = 10;

void generate_random_data(char *buffer){
  int i;
  srand(time(NULL));
  for(i = 0; i < num_bytes_perupdate-1; ++i){
    buffer[i] = (char)((random()%26) + 'a');
  }
  buffer[i] = '\0';
}

int next_attr_id = 0;
void prepare_for_test(void){
  NQ_Transaction transaction = NQ_Transaction_begin();
  assert(servers.size() >= 1);
  NQ_Host peer = servers[0].address;
  NQ_Principal *princ = servers[0].principal;
  char namebuf[50];
  
  printf("===> Preparing for test: %d Attrs, %d Tuples\n", 
         num_attributes, num_tuples);
  
  unsigned int x;
  NQ_Net_Batch *batch = NQ_Net_Batch_create();
  for(x = 1; x <= num_tuples; x++){
    NQ_Batch_Tuple_create(transaction, peer, princ, batch);
  }
  for(x = 1; x <= num_tuples; x++){
    NQ_Tuple newtuple = NQ_Batch_Tuple_create_finish(batch);
    assert( !NQ_Tuple_equals(newtuple, NQ_uuid_null) );
    tuples.push_back(Tuple(newtuple));
    Tuple *t = &tuples.back();
    for(size_t i = 0; i < num_attributes / num_tuples; i++) {
      sprintf(namebuf, "Att%d", next_attr_id++);
      NQ_Attribute_Name *name = 
        NQ_Attribute_Name_alloc(&peer, NQ_ATTRIBUTE_RAW, namebuf);
      t->attributes.push_back(name);
      NQ_Tuple_add_attribute(transaction, t->tid, name);

      char *valbuff = namebuf;
      int vallen = strlen(namebuf) + 1;
      NQ_Batch_Attribute_operate(transaction, &NQ_default_owner, name, t->tid, NQ_OPERATION_WRITE,
                                 &valbuff, &vallen, batch, NULL, NULL);
    }
  }
  NQ_Net_Batch_block(batch); //shouldn't do anything, but hey.
  if(NQ_Transaction_commit(transaction) != 0) {
    printf("Initialization error!\n");
    exit(-1);
  }
  printf("Initialized %d tuples, %d attrs\n", num_tuples, next_attr_id);
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

void do_tuple_create(Server *s, int count) {
  assert(time_limit == 0);
  assert(request_rate == 0);
  NQ_Transaction transaction;
  NQ_Net_Batch *batch;
  transaction = NQ_Transaction_begin();

  assert(servers.size() >= 1);
  printf("Creating batch update\n");

  batch = NQ_Net_Batch_create();
  for(int i=0; i < count; i++) {
    NQ_Batch_Tuple_create(transaction, s->address, s->principal, batch);
  }
  for(int i = 0; i < count; i++){
    NQ_Tuple newtuple = NQ_Batch_Tuple_create_finish(batch);
    assert(!NQ_UUID_eq_err(&newtuple));
  }
do_block(batch);  printf("Committing transaction\n");
  if(NQ_Transaction_commit(transaction) != 0) {
    printf("Error commiting transaction!\n");
    exit(-1);
  }
}

void do_tuple_create_latency(Server *s, int count) {
  assert(time_limit == 0);
  assert(request_rate == 0);
  NQ_Transaction transaction;
  transaction = NQ_Transaction_begin();

  assert(servers.size() >= 1);
  printf("Creating batch update\n");

  for(int i = 0; i < count; i++){
    double start = doubleTime();
    NQ_Tuple newtuple = NQ_Tuple_create(transaction, s->address, s->principal);
    double end = doubleTime();
    assert(!NQ_UUID_eq_err(&newtuple));
    latency_data.push_back(end - start);
  }
  printf("done.\n");
  printf("Committing transaction\n");
  if(NQ_Transaction_commit(transaction) != 0) {
    printf("Error commiting transaction!\n");
    exit(-1);
  }
}

vector<Tuple> tuples_to_delete;

void do_tuple_delete_prep(Server *s, int ignored_count) {
  assert(time_limit == 0);
  assert(request_rate == 0);
  int start, count;
  allowed_write_range(&start, &count);

  vector<Tuple> allowed_tuples(tuples.begin() + start, tuples.begin() + start + count);
  for(int i=0; i < count && allowed_tuples.size() > 0; i++) {
    int index = rand_range(allowed_tuples.size());
    tuples_to_delete.push_back(allowed_tuples[index]);
    allowed_tuples.erase(allowed_tuples.begin() + index);
  }
  printf("Will delete %d tuples\n", tuples_to_delete.size());
}

static bool check_all_tuples_deleted(NQ_Transaction check_transaction, int count) {
  assert(tuples_to_delete.size() > 0);
  printf("Making sure that tuples were really deleted\n");
  int bad_count = 0, good_count = 0;
  for(int i=0; i < count; i++) {
    Tuple *t = &tuples_to_delete[i];
    assert(t->attributes.size() > 0);
    if(check_base_tuple_attr(check_transaction, t, t->attributes[0])) {
      printf("error, tuple should not be present!\n");
      bad_count++;
    } else {
      good_count++;
    }
#if 0
    // check doesn't work due to poorly understood logic in NQ server delete,
    // which returns 0 in this case
    if(NQ_Tuple_delete(transaction, s->principal, tuples_to_delete[i].tid) == 0) {
      printf("error, should not be able to delete tuple!\n");
      bad_count++;
    } else {
      good_count++;
    }
#endif
  }
  printf("Good count = %d, bad count = %d\n", good_count, bad_count);
  return bad_count == 0;
}

void do_tuple_delete(Server *s, int count) {
  assert(time_limit == 0);
  assert(request_rate == 0);
  NQ_Transaction transaction;
  NQ_Net_Batch *batch;
  transaction = NQ_Transaction_begin();

  assert(servers.size() >= 1);
  assert(tuples_to_delete.size() <= (size_t)count);
  count = tuples_to_delete.size();

  printf("Creating batch update\n");
  batch = NQ_Net_Batch_create();

#if 1
  for(int i = 0; i < count; i++){
    NQ_Batch_Tuple_delete(transaction, s->principal, batch, tuples_to_delete[i].tid);
  }

  for(int i = 0; i < count; i++){
    int rv;
    rv = NQ_Batch_Tuple_delete_finish(batch);
    assert(rv == 0);
  }
do_block(batch);  if(check_mode) {
    printf("Checking same transaction\n");
    if(!check_all_tuples_deleted(transaction, count)) {
      printf("Error!\n");
      exit(-1);
    }
  }
#else
  for(int i = 0; i < count; i++){
    if(NQ_Tuple_delete(transaction, s->principal, tuples_to_delete[i].tid) != 0) {
      printf("error deleting tuple!\n");
    }
  }
#endif
  printf("Committing transaction\n");
  if(NQ_Transaction_commit(transaction) != 0) {
    printf("Error commiting transaction!\n");
    exit(-1);
  }
  num_actual_iterations = tuples_to_delete.size();
 
  if(check_mode) {
    printf("Checking next transaction\n");
    NQ_Transaction check_transaction;
    check_transaction = NQ_Transaction_begin();
    if(!check_all_tuples_deleted(check_transaction, count)) {
      printf("more than one error, bailing\n");
      exit(-1);
    }
    NQ_Transaction_commit(check_transaction);
  }
}

struct AttrSpec {
  Tuple tuple;
  NQ_Attribute_Name *name;
  AttrSpec(const Tuple &t, NQ_Attribute_Name *n) : tuple(t), name(n) { }
  AttrSpec() : name(NULL) { }
};

vector<AttrSpec> attributes_to_delete;

void do_attribute_delete_prep(Server *s, int ignored_count) {
  assert(time_limit == 0);
  assert(request_rate == 0);
  int start, count;
  allowed_write_range(&start, &count);

  vector<Tuple> allowed_tuples(tuples.begin() + start, tuples.begin() + start + count);
  
  for(int i=0; i < count && allowed_tuples.size() > 0; i++) {
    int index = rand_range(allowed_tuples.size());
    Tuple *t = &allowed_tuples[index];
    vector<NQ_Attribute_Name*>::iterator i =
      t->attributes.begin() + rand_range(t->attributes.size());
    attributes_to_delete.push_back(AttrSpec(*t, *i));
    t->attributes.erase(i);
    if(check_mode) {
      printf("picked '%s'\n", (*i)->name);
    }
    if(t->attributes.size() == 0) {
      printf("Removed all attributes\n");
      allowed_tuples.erase(allowed_tuples.begin() + index);
    }
  }
  printf("Will delete %d attributes\n", attributes_to_delete.size());
}

static bool check_all_attributes_deleted(NQ_Transaction check_transaction, int count) {
  assert(attributes_to_delete.size() > 0);
  printf("Making sure that attributes were really deleted\n");
  int bad_count = 0, good_count = 0;
  assert(count <= (int)attributes_to_delete.size());
  for(int i=0; i < count; i++) {
    AttrSpec *as = &attributes_to_delete[i];
    if(check_base_tuple_attr(check_transaction, &as->tuple, as->name)) {
      printf("error, tuple should not be present!\n");
      bad_count++;
    } else {
      good_count++;
    }
  }
  printf("Good count = %d, bad count = %d\n", good_count, bad_count);
  return bad_count == 0;
}

void do_attribute_delete(Server *s, int count) {
  assert(time_limit == 0);
  assert(request_rate == 0);
  NQ_Transaction transaction;
  NQ_Net_Batch *batch;
  transaction = NQ_Transaction_begin();

  assert(servers.size() >= 1);
  assert(attributes_to_delete.size() <= (size_t)count);
  count = attributes_to_delete.size();

  printf("Creating batch delete");
  batch = NQ_Net_Batch_create();

  for(int i = 0; i < count; i++){
    NQ_Batch_Tuple_remove_attribute(transaction,
                                    attributes_to_delete[i].tuple.tid, attributes_to_delete[i].name, batch);
  }
  printf("Done, waiting for ack\n");
  for(int i = 0; i < count; i++){
    int rv;
    rv = NQ_Batch_Tuple_remove_attribute_finish(batch);
    assert(rv == 0);
  }
  do_block(batch);
  if(check_mode) {
    printf("Checking same transaction\n");
    if(!check_all_attributes_deleted(transaction, count)) {
      printf("Error!\n");
      exit(-1);
    }
  }
  printf("Committing transaction\n");
  if(NQ_Transaction_commit(transaction) != 0) {
    printf("Error commiting transaction!\n");
    exit(-1);
  }
  num_actual_iterations = attributes_to_delete.size();
 
  if(check_mode) {
    printf("Checking next transaction\n");
    NQ_Transaction check_transaction;
    check_transaction = NQ_Transaction_begin();
    if(!check_all_attributes_deleted(check_transaction, count)) {
      printf("more than one error, bailing\n");
      exit(-1);
    }
    NQ_Transaction_commit(check_transaction);
  }
}

void do_attribute_create(Server *s, int count) {
  assert(time_limit == 0);
  assert(request_rate == 0);
  NQ_Transaction transaction;
  NQ_Net_Batch *batch;
  transaction = NQ_Transaction_begin();

  NQ_Host peer = s->address;

  assert(servers.size() >= 1);
  printf("Creating batch update\n");
  batch = NQ_Net_Batch_create();
  vector<AttrSpec> created;
  created.reserve(count);
  for(int i=0; i < count; i++) {
    int tuple_index, ignored;
    pick_update_indices(&tuple_index, &ignored, true);
    Tuple *t = &tuples[tuple_index];
    char namebuf[80];

    sprintf(namebuf, "Att-%s-%d-%d", server_prefix.c_str(), child_index, i);
    NQ_Attribute_Name *name = 
      NQ_Attribute_Name_alloc(&peer, NQ_ATTRIBUTE_RAW, namebuf);
    created.push_back(AttrSpec(*t, name));
    NQ_Tuple_add_attribute(transaction, t->tid, name);

    char *valbuff = namebuf;
    int vallen = strlen(namebuf) + 1;
    NQ_Batch_Attribute_operate(transaction, &NQ_default_owner, name, t->tid, NQ_OPERATION_WRITE,
                               &valbuff, &vallen, batch, NULL, NULL);
  }
  for(int i = 0; i < count; i++){
    char *valbuf = NULL;
    int vallen = 0;
    if(NQ_Batch_Attribute_operate_finish(&valbuf, &vallen, NULL, batch) != 0) {
      printf("Op error!\n");
      exit(-1);
    }
  }
  do_block(batch);
  printf("Committing transaction\n");
  if(NQ_Transaction_commit(transaction) != 0) {
    printf("Error commiting transaction!\n");
    exit(-1);
  }
  if(check_mode) {
    printf("Doing exhaustive check\n");
    NQ_Transaction check_transaction;
    check_transaction = NQ_Transaction_begin();
    for(size_t i = 0; i < created.size(); i++) {
      AttrSpec *a = &created[i];
      check_base_tuple_attr(check_transaction, &a->tuple, a->name);
      printf("checked %s\n", a->name->name);
    }
    NQ_Transaction_commit(check_transaction);
  }
}

/////////////////////

struct AttributeChecker : public Checker{
  struct AttributeSpec {
    bool modified;
    string value;
    AttributeSpec() : modified(false) { }
    void set(const string &v) { value = v; modified = true; }
  };
  vector<AttributeSpec> attribute_values;
  AttributeChecker(Tuple *tuple) {
    attribute_values.resize(tuple->attributes.size());
  }
  virtual bool run_check(Tuple *tuple, NQ_Transaction check_transaction, Stats *stats) {
    char *valbuf = NULL;
    int vallen = 0;
    int num_good = 0;
    int num_bad = 0;
    for(size_t i=0; i < tuple->attributes.size(); i++) {
      AttributeSpec *a = &attribute_values[i];
      if(!a->modified) {
        continue;
      }
      int rv = NQ_Attribute_operate(check_transaction, &NQ_default_owner, 
                                    tuple->attributes[i], tuple->tid,
                                    NQ_OPERATION_READ, &valbuf, &vallen, NULL);
      if(! (rv == 0 && valbuf != NULL && strcmp(valbuf, a->value.c_str()) == 0) ) {
        printf("error checking write\n");
        num_bad++;
      } else {
        printf("Checking '%s'", tuple->attributes[i]->name);
        NQ_UUID_print(&tuple->tid);
        printf("Value = '%s', check = '%s'\n", valbuf, a->value.c_str());
        num_good++;
      }
      if(valbuf != NULL) {
        free(valbuf);
      }
    }
    printf("Run check: %d good, %d bad\n", num_good, num_bad);
    if(stats != NULL) {
      stats->num_good += num_good;
      stats->num_bad += num_bad;
    }
    return num_bad == 0;
  }
};

#if 0
struct CheckEntry {
  Tuple *tuple;
  NQ_Attribute_Name *attr;
  string value;

  CheckEntry() : tuple(NULL), attr(NULL) { }
};
#endif

void do_attribute_update(Server *s, int count) {
  NQ_Transaction transaction;
  NQ_Net_Batch *batch;

  transaction = NQ_Transaction_begin();

  assert(servers.size() >= 1);
  printf("Creating batch update\n");
  batch = NQ_Net_Batch_create();
  double start_time = doubleTime();
  for(int i=0; i < count; i++) {
    // pick random tuple and attribute
    int tuple_index;
    int attr_index;
    pick_update_indices(&tuple_index, &attr_index, true);
    Tuple *tuple = &tuples[tuple_index];
    NQ_Attribute_Name *attr = tuple->attributes[attr_index];
    if(check_mode) {
      printf("Picked (%d,%d) = ", tuple_index, attr_index);
      NQ_UUID_print(&tuple->tid);
      printf("name='%s'\n", attr->name);
    }
    char val[80];
    char *valbuff = val;
    sprintf(valbuff, "%s-%d", attr->name, i);
    int vallen = strlen(valbuff) + 1;

    if(NQ_Batch_Attribute_operate(transaction, &NQ_default_owner, attr, tuple->tid, NQ_OPERATION_WRITE,
                                  &valbuff, &vallen, batch, NULL, NULL) != 0) {
      printf("Update error!\n");
      exit(-1);
    }

    if(check_mode) {
      AttributeChecker *c;
      if(tuple->checker == NULL) {
        tuple->checker = new AttributeChecker(tuple);
      }
      c = (AttributeChecker*)tuple->checker;
      assert(c != NULL && c->attribute_values.size() == tuple->attributes.size());
      assert(0 <= attr_index && attr_index < (int)c->attribute_values.size());
      c->attribute_values[attr_index].set(string(val));
    }
    rate_delay();
    if(time_limit != 0) {
      if(doubleTime() - start_time > time_limit) {
	printf("Time limit exceeded, executed %d/%d, wanted rate %d, got rate %lf\n", i, count, request_rate, ((double)i) / time_limit);
	break;
      }
    }
  }
  printf("XXX write does not call finish on every operation (should be OK)\n");

  do_block(batch);
  printf("Committing transaction\n");
  if(NQ_Transaction_commit(transaction) != 0) {
    printf("Error commiting transaction!\n");
    exit(-1);
  }
  if(check_mode) {
    printf("Running checks\n");
    NQ_Transaction check_transaction;
    check_transaction = NQ_Transaction_begin();
    
    Checker::Stats check_stats;
    for(size_t i=0; i < tuples.size(); i++) {
      Tuple *t = &tuples[i];
      if(t->checker != NULL) {
        if(!t->checker->run_check(t, check_transaction, &check_stats)) {
          printf("Check failed at %d\n", i);
        }
      }
    }
    printf("Total num good = %d, total num bad = %d\n", check_stats.num_good, check_stats.num_bad);
    if(check_stats.num_bad != 0) {
      printf("Detected some bads\n");
      exit(-1);
    }
    NQ_Transaction_commit(check_transaction);
  }
}

struct ReadOpRecord {
  Tuple *tuple;
  NQ_Attribute_Name *attr;
  ReadOpRecord() : tuple(NULL), attr(NULL) { }
};

void do_attribute_read(Server *s, int count) {
  assert(time_limit == 0);
  assert(request_rate == 0);
  NQ_Transaction transaction;
  NQ_Net_Batch *batch;

  transaction = NQ_Transaction_begin();

  assert(servers.size() >= 1);
  printf("Creating batch update\n");
  batch = NQ_Net_Batch_create();
  
  ReadOpRecord *records = new ReadOpRecord[count];
  for(int i=0; i < count; i++) {
    // pick random tuple and attribute
    int tuple_index;
    int attr_index;
    pick_update_indices(&tuple_index, &attr_index, false);
    Tuple *tuple = &tuples[tuple_index];
    NQ_Attribute_Name *attr = tuple->attributes[attr_index];
    records[i].tuple = tuple;
    records[i].attr = attr;
    if(0 && check_mode) {
      printf("Picked (%d,%d) = ", tuple_index, attr_index);
      NQ_UUID_print(&tuple->tid);
      printf("name='%s'\n", attr->name);
    }
    char *val = NULL;
    int vallen = 0;
    if(NQ_Batch_Attribute_operate(transaction, &NQ_default_owner, attr, tuple->tid, NQ_OPERATION_READ,
                                  &val, &vallen, batch, NULL, NULL) != 0) {
      printf("Read issue error!\n");
      exit(-1);
    }
  }

  printf("Batch finish & check\n");
  for(int i=0; i < count; i++) {
    char *valbuf = NULL;
    int vallen;
    if(NQ_Batch_Attribute_operate_finish(&valbuf, &vallen, NULL, batch) != 0) {
      printf("Op error @ %d !\n", i);
      exit(-1);
    }
    NQ_Attribute_Name *name = records[i].attr;
    if( ! (vallen == (int)(strlen(name->name) + 1) && strcmp(name->name, valbuf) == 0) ) {
      printf("Mismatch!\n");
      exit(-1);
    }
  }
  do_block(batch);
  printf("Committing transaction\n");
  if(NQ_Transaction_commit(transaction) != 0) {
    printf("Error commiting transaction!\n");
    exit(-1);
  }
  delete [] records;
}

void do_attribute_read_latency(Server *s, int count) {
  assert(time_limit == 0);
  assert(request_rate == 0);
  NQ_Transaction transaction;

  transaction = NQ_Transaction_begin();

  assert(servers.size() >= 1);
  printf("Creating batch update\n");

  for(int i=0; i < count; i++) {
    // pick random tuple and attribute
    int tuple_index;
    int attr_index;
    pick_update_indices(&tuple_index, &attr_index, false);
    Tuple *tuple = &tuples[tuple_index];
    NQ_Attribute_Name *attr = tuple->attributes[attr_index];
    if(1 && check_mode) {
      printf("Picked (%d,%d) = ", tuple_index, attr_index);
      NQ_UUID_print(&tuple->tid);
      printf("name='%s'\n", attr->name);
    }
    char *val = NULL;
    int vallen = 0;
    double start = doubleTime();
    if(NQ_Attribute_operate(transaction, &NQ_default_owner, attr, tuple->tid, NQ_OPERATION_READ,
			    &val, &vallen, NULL) != 0) {
      printf("Read error!\n");
    }
    double end = doubleTime();
    latency_data.push_back(end - start);
    if(!(val != NULL && strcmp(val, attr->name) == 0)) {
      printf("Value mismatch!\n");
      exit(-1);
    }
  }

  printf("done.\n");
  printf("Committing transaction\n");
  if(NQ_Transaction_commit(transaction) != 0) {
    printf("Error commiting transaction!\n");
    exit(-1);
  }
}

#if 0
    generate_random_data(valbuff);
    NQ_Batch_Attribute_operate(transaction, attributes[attr], tuples[tuple], NQ_OPERATION_WRITE, &valbuff, &vallen, batch, NULL, NULL);
  char *valbuff = new char[num_bytes_perupdate];
  int vallen = num_bytes_perupdate;
#endif

void run_add_test_pipelined(void (*op_func)(Server *, int), int count, void (*prep_func)(Server *, int)){
  if(prep_func) {
    prep_func(&servers[0], count);
  }
  start_test();

  fprintf(stderr, "Running test %p , %d times\n", op_func, count);
  op_func(&servers[0], count);
  finish_test();
}

#if 0
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
#endif

#if 0
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
#endif

void init_servers(void) {
  servers.push_back(Server(inet_addr(g_server_addr), g_server_port));
}

enum TestType {
  TUPLE_CREATE_TEST = 1,
  ATTR_UPDATE_TEST = 2,
  ATTR_READ_TEST = 3,

  TUPLE_DELETE_TEST = 4,

  ATTR_CREATE_TEST = 5,
  ATTR_DELETE_TEST = 6,
};

#define TIME_LIMIT (256)
#define RATE (257)
struct option longopts[] = {
  { "time-limit", 1, NULL, TIME_LIMIT },
  { "rate", 1, NULL, RATE },
  { 0 },
};

int main(int argc, char **argv){  
  int opt;
  unsigned short server_port = 5500;
  int iterations = 1;
  bool debug_mode = false;
  bool latency_test = false;
  bool want_do_periodic_stats = false;

  signal(SIGUSR2, sig_usr2);

  TestType test_type = TUPLE_CREATE_TEST;

  num_attributes      = 1;
  num_tuples          = 1;
  num_updates         = 1;
  num_bytes_perupdate = 10;

  while( (opt = getopt_long(argc, argv, "dn:h:a:t:r:u:b:e:P:p:i:y:c:zT:LS", longopts, NULL)) != -1 ) {
    switch(opt) {
    case 'd':
      debug_mode = true;
      break;
    case 'n':
      num_subprocesses = atoi(optarg);
      break;
    case 'h':
      g_server_addr = strdup(optarg);
      break;
    case 'a':
      num_attributes = atoi(optarg);
      break;
    case 't':
      num_tuples = atoi(optarg);
      break;
    case 'u':
      num_updates = atoi(optarg);
      break;
    case 'b':
      num_bytes_perupdate = atoi(optarg);
      break;
    case 'p':
      g_server_port = atoi(optarg);
      server_port = atoi(optarg) + 1000;
      break;
    case 'P':
      // server_prefix for logfile
      server_prefix = string(optarg);
      break;
    case 'i':
      iterations = atoi(optarg);
      break;
    case 'c':
      is_child = true;
      child_index = atoi(optarg);
      break;
    case 'z':
      printf("Doing exhaustive check\n");
      check_mode = true;
      break;
    case 'T':
      test_type = (TestType) atoi(optarg);
      break;
    case 'L':
      latency_test = true;
      break;
    case 'S':
      want_do_periodic_stats = true;
      break;
    case TIME_LIMIT:
      time_limit = atoi(optarg);
      break;
    case RATE:
      request_rate = atoi(optarg);
      break;
    default:
      printf("Unknown option\n");
      exit(-1);
    }
  }

  if(/*is_child && */want_do_periodic_stats) {
      NQ_enable_periodic_stats();
  }

  if(latency_test) {
    if(!(test_type == TUPLE_CREATE_TEST || 
                  test_type == ATTR_READ_TEST) ) {
      printf("Unsupported test type %d for latency experiment!\n", (int)test_type);
      exit(-1);
    }
    printf("Latency test: set one subprocess\n");
    num_subprocesses = 1;
  }

  if(debug_mode) {
    printf("Debug mode. Turning on checking, doing everything in one process\n");
    check_mode = true;
  }
  if(0) {
    printf("Forcing check_mode to false\n");
    check_mode = false;
  }

  printf("Initializing NetQuery...");
  if(is_child) {
    fprintf(stderr, "In child!\n");
    server_port += 1 + child_index;
  }
  //NQ_init(server_port);
  NQ_init(NQ_PORT_ANY);
  NQ_GC_set_timeout(60000);

  NQ_publish_home_principal();

  printf("done\n");
  init_servers();

  if(!is_child) {
    // SERVER
    prepare_for_test();
    write_spec(server_prefix);
#if 0
    fprintf(stderr, "exiting early\n");
    exit(-1);
#else
    if(debug_mode) {
      goto do_child;
    } else {
      fprintf(stderr, "Forking %d processes\n", num_subprocesses);
    }
#endif
    for(int i=0; i < num_subprocesses; i++) {
      if(fork() == 0) {
        char **new_args = new char*[argc + 3];
        memcpy(new_args, argv, argc * sizeof(argv[0]));
        string s = itos(i);
        new_args[argc] = "-c";
        new_args[argc + 1] = strdup(s.c_str());
        new_args[argc + 2] = NULL;
        execv(argv[0], new_args);
      }
    } 
  } else {
  do_child:
    // CHILD
    printf("Child\n");
    read_spec(server_prefix);
    // 
    if(check_mode) {
      printf("Checking tuples\n");
      check_tuples();
    }
    fprintf(stderr, "Client ready\n");
    if(!debug_mode) {
      while(!start_client) 
        { usleep(1000); }
    } else {
      printf("debug mode, skipping wait\n");
    }
    if(!debug_mode) {
      string buf0("/tmp/microbench-" + server_prefix + "-" + itos(child_index) + ".out");
      if(freopen(buf0.c_str(), "w", stdout) == NULL) {
        printf("error redirecting output\n");
      }
      string buf1("/tmp/microbench-" + server_prefix + "-" + itos(child_index) + ".err");
      if(freopen(buf1.c_str(), "w", stderr) == NULL) {
        printf("error redirecting err\n");
      }
      setlinebuf(stderr);
    }
    sync_to_second();
    fprintf(stderr, "%lf: Starting\n", doubleTime());
    void (*op_func)(Server *, int) = NULL;
    void (*prep_func)(Server *, int) = NULL;
    char *test_type_str = "(undef)";
    num_actual_iterations = iterations;
    if(latency_test) {
      switch(test_type) {
      case TUPLE_CREATE_TEST:
        test_type_str = "Tuple create latency";
        op_func = do_tuple_create_latency;
        break;
      case ATTR_READ_TEST:
        test_type_str = "Attr read latency";
        op_func = do_attribute_read_latency;
        break;
      default:
        printf("Unsupported latency test!\n");
        exit(-1);
      } 
      latency_data.reserve(iterations);
    } else {
      switch(test_type) {
      case TUPLE_CREATE_TEST:
        test_type_str = "Tuple create";
        op_func = do_tuple_create;
        break;
      case ATTR_UPDATE_TEST:
        test_type_str = "Attr update";
        op_func = do_attribute_update;
        break;
      case ATTR_READ_TEST:
        test_type_str = "Attr read";
        op_func = do_attribute_read;
        break;
      case TUPLE_DELETE_TEST:
        test_type_str = "Tuple delete";
        op_func = do_tuple_delete;
        prep_func = do_tuple_delete_prep;
        break;

      case ATTR_DELETE_TEST:
        test_type_str = "Attribute delete"; // write to non-existent attribute
        op_func = do_attribute_delete;
        prep_func = do_attribute_delete_prep;
        break;

      case ATTR_CREATE_TEST:
        test_type_str = "Attribute create"; // write to non-existent attribute
        op_func = do_attribute_create;
        break;

      default:
        printf("Unknown test type (%d)!\n", (int) test_type);
        exit(-1);
      }
    }
    printf("Test type: %s\n", test_type_str);

    run_add_test_pipelined(op_func, iterations, prep_func);
    printf("===> All iterations finished: %d us, %d iterations, %d actual iterations\n", total_time, iterations, num_actual_iterations);
    if(latency_test) {
      printf("====== Latency Data (in us) ======\n");
      for(size_t i=0; i < latency_data.size(); i++) {
        printf("[%d]: %lf\n", i, latency_data[i] * 1e6);
      }
    }
    if(save_send_times) {
      printf("====== Send time ======\n");
      printf("Interval = %lf\n", rate_interval());
      double first_time = -1;
      size_t j = 0;
      for(size_t i=0; i < send_time.size(); i++) {
	if(first_time < 0) {
	  first_time = send_time[i];
	}
	printf("%lf\n", send_time[i] - first_time);
	if( (i + 1) % BURST_LENGTH == 0 && j < sleep_time.size()) {
	  printf("\tSleep %lf, %lf, adj %d\n", sleep_time[j], burst_length[j], adjustments[j]);
	  j++;
	}
      }
    }

    assert(num_actual_iterations <= iterations);
    fflush(stdout);
    fflush(stderr);
    exit(0);
  }

  int good_count = 0;
  int err_count = 0;
  for(int i=0; i < num_subprocesses; i++) {
    printf("wait %d / %d\n", i, num_subprocesses);
    int status;
    int rv = wait(&status);
    if(rv < 0) {
      perror("Wait");
      err_count++;
    } else if(status != 0) {
      printf("subprocess %d returned %d\n", i, status);
      err_count++;
    } else {
      good_count++;
    }
  }
  fprintf(stderr, "Test complete good = %d, err = %d\n", good_count, err_count);
  printf("%lf: Test done\n", doubleTime());
  NQ_dump_stats();
  return 0;
}
