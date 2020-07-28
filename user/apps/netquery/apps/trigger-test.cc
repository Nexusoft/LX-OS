#include <nq/net.h>
#include <nq/netquery.h>
#include <nq/tuple.hh>
#include <nq/marshall.hh>
#include <getopt.h>
#include <string>
#include <fstream>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>


using namespace std;

const char *tid_fname = "triggertest.tid";
NQ_Principal *owner;

bool expected_verdict = true;

bool veto_one = false;

int op_count = 1;
int inner_op_count = 1;

#define INVALID_COUNT (-1)

struct Stats {
  int proposal_count;
  int async_verdict_count;
  int sync_verdict_count;
  int async_commit_done_count;

  Stats() : 
    proposal_count(0), 
    async_verdict_count(0), 
    sync_verdict_count(0),
    async_commit_done_count(0) {
  }

  void print() {
    printf(
	   "Proposal: %d\n"
	   "Async verdict: %d\n"
	   "Sync verdict: %d\n"
	   "commit count: %d\n"
	   , 

	   proposal_count,
	   async_verdict_count,
	   sync_verdict_count,
	   async_commit_done_count
	   );
  }

  bool match(const Stats &stats) {
    return 
      (proposal_count == INVALID_COUNT || 
       proposal_count == stats.proposal_count) &&
      (async_verdict_count == INVALID_COUNT || 
       async_verdict_count == stats.async_verdict_count) &&
      (sync_verdict_count == INVALID_COUNT || 
       sync_verdict_count == stats.sync_verdict_count) &&
      (async_commit_done_count == INVALID_COUNT || 
       async_commit_done_count == stats.async_commit_done_count);
  }
};

Stats stats, match_stats;

static NQ_UUID read_one_tid(const char *fname) {
  ifstream ifs(fname);
  if(!ifs.good()) {
    cerr << "Could not open site tid!\n";
    exit(-1);
  }
  NQ_UUID tid;
  vector<unsigned char> all_data;

  get_all_file_data(ifs, all_data);
  CharVector_Iterator s = all_data.begin(), end = all_data.end();

  tid = *tspace_unmarshall(&tid, *(Transaction *)NULL, s, end);

  ifs.close();
  return tid;
}

static bool trust_all(NQ_Tuple tid, KnownClass *obj_class) {
  return true;
}

bool trust_attrval_all(NQ_Attribute_Name *name, NQ_Tuple tid, NQ_Principal *principal) {
  return true;
}

struct T_Test : T_Tuple {
  T_int32 val;
  inline T_Test(Transaction &transaction) : 
    T_Tuple(transaction), val(this, "T_Test.val")
  { }

  inline T_Test(Transaction &transaction, const NQ_Tuple &tid) : 
    T_Tuple(transaction, tid), val(this, "T_Test.val")
  { }

  void tspace_create(void) 
    throw(NQ_Access_Exception) {
    tspace_create_generic("Test");
  }

};

#define FOR_ALL_CLASSES(M)		\
  M(Test);

FOR_ALL_CLASSES(TSPACE_DEFINE_CLASS);

typedef ExtRef<T_Test> TestRef;

void nq_init(const NQ_Host *home) {
  NQ_init(NQ_PORT_ANY);
  NQ_cpp_lib_init();
  if(home != NULL) {
    owner = NQ_get_home_principal((NQ_Host *)home);
  } else {
    owner = NQ_Principal_create();
    owner->home = NQ_default_owner.home;
  }

  FOR_ALL_CLASSES(TSPACE_ADD_CLASS);
}

static void load_and_add_trigger(Transaction &t, const char *tid_fname) ;
static int upcall(NQ_Transaction t_id, NQ_Trigger_Description *trigger, 
		  NQ_Trigger_Upcall_Type type, int arg, void *userdata);

static void modify_helper(bool do_real_commit, NQ_Host *home);
static void multi_modify_helper(bool do_real_commit, NQ_Host *home);

static inline string tuple_fname(NQ_Host *home) {
  return ("tuple." + itos(home->addr) + ":" + itos(home->port) + ".tid");
}

int main(int argc, char **argv) {
  bool use_async = false;
  int opt;

  NQ_Host home_real, *home = &home_real;
  bool set_host = false;

  memset(&home->addr, 0, sizeof(home->addr));
  home->port = NQ_NET_DEFAULT_PORT;

#define VETO (256)
#define SYNC (257)
#define ASYNC (258)

#define VETO_ONE (259)
#define EXPECT_FAIL (260)

#define DONE (261)

  static struct option long_options[] = {
    // options to check final state
    { "veto", 1, NULL, VETO },
    { "sync", 1, NULL, SYNC },
    { "async", 1, NULL, ASYNC },
    { "done", 1, NULL, DONE },

    { "vetoone", 0, NULL, VETO_ONE },
    { "expectfail", 0, NULL, EXPECT_FAIL },
    {0, 0, 0, 0}
  };
  match_stats.proposal_count = INVALID_COUNT;
  match_stats.async_verdict_count = INVALID_COUNT;
  match_stats.sync_verdict_count = INVALID_COUNT;
  while( (opt = getopt_long(argc, argv, "ak:h:p:c:", long_options, NULL)) != -1 ) {
    switch(opt) {
    case 'a':
      use_async = true;
      break;
    case 'k':
      op_count = atoi(optarg);
      break;
    case 'h':
      home->addr = inet_addr(optarg);
      set_host = true;
      break;
    case 'p':
      home->port = atoi(optarg);
      break;
    case VETO:
      match_stats.proposal_count = atoi(optarg);
      break;
    case SYNC:
      match_stats.sync_verdict_count = atoi(optarg);
      break;
    case ASYNC:
      match_stats.async_verdict_count = atoi(optarg);
      break;
    case DONE:
      match_stats.async_commit_done_count = atoi(optarg);
      break;
    case VETO_ONE:
      veto_one = true;
      break;
    case EXPECT_FAIL:
      printf("expect fail\n");
      expected_verdict = false;
      break;
    default:
      printf("Unknown option %c\n", opt);
      exit(-1);
    }
  }
  if(argc - optind == 0) {
    printf("Need at least one non-option argument\n");
    exit(-1);
  }

  if(!set_host) {
    home = NULL;
  }
  nq_init(home);

  int mode = atoi(argv[optind]);
  switch(mode) {
  case 0: {
    printf("creating tuple\n");
    Transaction t(trust_all, trust_attrval_all, owner->home, owner);
    T_Test *test;
    test = new T_Test(t);
    test->tspace_create();
    t.commit();

    {
      ofstream ofs(tid_fname);
      file_marshall(test->tid, ofs);
      cerr << "Wrote tid " << test->tid << "\n";
      ofs.close();
    }

    if(home != NULL) {
      ofstream ofs(tuple_fname(home).c_str());
      file_marshall(test->tid, ofs);
      cerr << "Wrote tid " << test->tid << "\n";
      ofs.close();
    }

    cerr << "Reloading\n";
    Transaction t1(trust_all, trust_attrval_all, owner->home, owner);
    TestRef ref(test->tid);
    test = ref.load(t1);
    cerr << "Val is " << test->val << "\n";
    t1.commit();
    break;
  }
  case 1: {
    Transaction t(trust_all, trust_attrval_all, owner->home, owner);
    load_and_add_trigger(t, tid_fname);
    t.commit();
    printf("Sleeping\n");
    sleep(10);
    break;
  }
  case 2: {
    printf("Modifying tuple, with commit\n");
    modify_helper(true, home);
    break;
  }
  case 5: {
    printf("Modifying tuple, multiple writes per transaction\n");
    inner_op_count = op_count;
    op_count = 1;
    modify_helper(true, home);
    break;
  }
  case 3: {
    printf("Modifying tuple, with abort\n");
    modify_helper(false, home);
    break;
  }
  case 4: {
    printf("Triggers on tuples stored on multiple servers\n");
    if(home == NULL) {
      printf("Host must be set!\n");
      exit(-1);
    }

    int ports[3] = { 7000, 7001, 7002 };
    for(int i=0; i < 3; i++) {
      NQ_Host h = *home;
      h.port = ports[i];
      NQ_Principal *p = NQ_get_home_principal((NQ_Host *)&h);

      Transaction t(trust_all, trust_attrval_all, p->home, p);
      load_and_add_trigger(t, tuple_fname(&h).c_str());
      t.commit();
    }
    printf("==> Sleeping\n");
    sleep(10);
    break;
  }

  case 6: {
    printf("Modifying tuples on multiple servers in one transaction, commit\n");
    multi_modify_helper(true, home);
    break;
  }
  case 7: {
    printf("Modifying tuples on multiple servers in one transaction, abort\n");
    multi_modify_helper(false, home);
    break;
  }

  default:
    printf("Unknown mode\n");
    exit(-1);
    break;
  }
  printf("Stats: "); stats.print();

  if(!match_stats.match(stats)) {
    printf("===> Stats mismatch!\n");
    exit(-1);
  } else {
    printf("===> Stats match!\n");
    exit(0);
  }
}


static void load_and_add_trigger(Transaction &t, const char *tid_fname) {
  printf("Trigger is loading from %s\n", tid_fname);
  TestRef ref(read_one_tid(tid_fname));
  cerr << "Trying to load " << ref.tid << "\n";
  T_Test *test;
  test = ref.load(t);

  printf("Adding %d triggers, val is %d\n", op_count, test->val.load());
  for(int i = 0; i < op_count; i++) {
    t.add_trigger(&test->val, NQ_TRIGGER_VALUECHANGED, 
		  NQ_TRIGGER_UPCALL_SYNC_VETO | 
		  NQ_TRIGGER_UPCALL_ASYNC_COMMIT_DONE,
		  upcall, NULL);
  }
}
static int upcall(NQ_Transaction t_id, NQ_Trigger_Description *trigger, 
		  NQ_Trigger_Upcall_Type type, int arg, void *userdata) {
  printf("trigger at %d, type = %d\n", trigger->name->owner->home.port, type);
  switch(type) {
  case NQ_TRIGGER_UPCALL_SYNC_VETO: {
    stats.proposal_count++;
    if(veto_one) {
      static bool vetoed = false;
      if(!vetoed) {
	printf("======= VETOING\n");
	vetoed = true;
	return 0;
      }
    }
    return 1;
  }
  case NQ_TRIGGER_UPCALL_SYNC_VERDICT: {
    if( (bool)arg != (bool)expected_verdict ) {
      printf("Sync verdict mismatch %d %d\n", arg, expected_verdict);
      exit(-1);
    }
    stats.sync_verdict_count++;
    return 1;
  }
  case NQ_TRIGGER_UPCALL_ASYNC_VERDICT: {
    if( (bool)arg != (bool)expected_verdict ) {
      printf("Async verdict mismatch\n");
      exit(-1);
    }
    stats.async_verdict_count++;
    return 1;
  }
  case NQ_TRIGGER_UPCALL_ASYNC_COMMIT_DONE: {
    stats.async_commit_done_count++;
    return 1;
  }
  default:
    assert(0);
  }
}

static void modify_helper(bool do_real_commit, NQ_Host *home) {
  TestRef ref(read_one_tid(tuple_fname(home).c_str()));
  for(int i=0; i < op_count; i++) {
    Transaction t(trust_all, trust_attrval_all, owner->home, owner);
    T_Test *test;
    test = ref.load(t);
    int oldval = test->val;
    printf("Old value = %d\n", oldval);
    for(int i=0; i < inner_op_count; i++) {
      test->val = oldval + 1;
    }
    if(do_real_commit) {
      printf("Commiting\n");
      try {
	t.commit();
      } catch(...) {
	printf("Got exception\n");
      }
    } else {
      t.abort();
    }
  }
  printf("===> Modification done\n");
}


static void multi_modify_helper(bool do_real_commit, NQ_Host *home) {
  Transaction t(trust_all, trust_attrval_all, owner->home, owner);

  int ports[3] = { 7000, 7001, 7002 };
  for(int i=0; i < 3; i++) {
    NQ_Host h = *home;
    h.port = ports[i];
    // NQ_Principal *p = NQ_get_home_principal((NQ_Host *)&h);
    TestRef ref(read_one_tid(tuple_fname(&h).c_str()));
    T_Test *test = ref.load(t);
    int oldval = test->val;
    test->val = oldval + 1;
    printf("New value = %d\n", test->val.load());
  }

  if(do_real_commit) {
    printf("Commiting\n");
    try {
      t.commit();
    } catch(...) {
      printf("Got exception\n");
    }
  } else {
    t.abort();
  }
}
