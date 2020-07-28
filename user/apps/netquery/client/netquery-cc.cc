#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <iostream>
#include <iomanip>
#include <string>
#include <fstream>
#include <execinfo.h>
#include <ext/hash_map>
#include <ext/hash_set>
#include <set>
#include <nq/netquery.h>
#include <nq/uuid.h>
#include <nq/marshall.hh>

#include <nq/socket.h>
#include <nq/transaction.h>
#include <nq/pickle.h>
#include <nq/attribute.h>
#include <nq/net.h>

#include <nq/util.hh>

#include <sys/time.h>

#define DEBUG_TX_MUTEX (0)

// Keep this short & simple. We might want to use the library in a
// pure C context (e.g. work around Nexus C++ performance problems)

#if 0
#define DEBUG_MESSAGES(X) do { X; } while(0)
#else
#define DEBUG_MESSAGES(X)
#endif

WG_PingInfo last_wg_ping;

double doubleTime() {
  struct timeval tv;
  gettimeofday(&tv, NULL);
  return tv.tv_sec + tv.tv_usec * 1e-6;
}

unsigned int ALAN_EPOCH = 1209671734;

double smallDoubleTime(void) {
  struct timeval tv;
  gettimeofday(&tv, NULL);
  return (double)(tv.tv_sec - ALAN_EPOCH) + (double)tv.tv_usec / 1e6;
}

#ifdef NET_DEBUG
#define REQUEST_LOG(a) { a }
#else
#define REQUEST_LOG(a)
#endif

using namespace __gnu_cxx;
using namespace std;
// C++ code for NetQuery

unsigned int NQ_Attribute_Name_hash(void *k){
  NQ_Attribute_Name *name = (NQ_Attribute_Name *)k;
  unsigned int ret = 0;
  ret ^= SuperFastHash((char *)name->owner->key.hash, name->owner->key.hash_len);
  ret ^= SuperFastHash(name->name, strlen(name->name));
  ret ^= name->type;
  return ret;
}

std::ostream &operator<<(std::ostream &os, const NQ_UUID &e) {
  os << "< home=" << NQ_Host_as_string(e.home) << " id= ";
  int i;
  for(i=0; i < UUIDBITS; i++) {
    os << std::setw(2) << std::setbase(16) << ((unsigned int)((unsigned char *)e.id)[i])  << std::setbase(10);
  }
  os << " type = " << e.type << " ";
  os << " >";
  return os;
}

std::ostream &operator<<(std::ostream &os, const NQ_Attribute_Name &name) {
  os << "owner: " << name.owner << " type " << name.type << " \"" << name.name << "\"";
  return os;
}

std::ostream &operator<<(std::ostream &os, const NQ_Host &h) {
  os << NQ_Host_as_string(h);
  return os;
}

std::ostream &operator<<(std::ostream &os, const NQ_Principal &p) {
  os << "princ(";
  if(&p == &NQ_principal_null) {
    os << "NULL";
  } else {
    for(int i=0; i < p.key.hash_len / 3; i++) {
      os << hex << (int)p.key.hash[i] << dec;
    }
  }
  os << ")";
  return os;
}

struct NQ_UUID_Table {
  typedef hash_map<NQ_UUID, void *, NQ_UUID_hash, NQ_UUID_equals> Map;
  Map map;
  pthread_mutex_t lock;

  NQ_UUID_Table() {
    pthread_mutex_init(&lock, NULL);
  }
};

NQ_UUID_Table *NQ_UUID_Table_new(void) {
  NQ_UUID_Table *ret = new NQ_UUID_Table();
  return ret;
}

void NQ_UUID_Table_destroy(NQ_UUID_Table *table) {
  delete table;
}

int NQ_UUID_Table_size(NQ_UUID_Table *table) {
  return table->map.size();
}

#if 0
void NQ_UUID_Table_dump(NQ_UUID_Table *table) {
  for(NQ_UUID_Table::Map::iterator i = table->map.begin();
      i != table->map.end(); ++i) {
    std::cerr << "(";
    std::cerr << i->first;
    std::cerr << "," << i->second << ")" << "\n";
  }
}
#endif

void NQ_UUID_Table_lock(NQ_UUID_Table *table){
  pthread_mutex_lock(&table->lock);
}
void NQ_UUID_Table_unlock(NQ_UUID_Table *table){
  pthread_mutex_unlock(&table->lock);
}

void *NQ_UUID_Table_find(NQ_UUID_Table *table, NQ_UUID *uuid) {
  void *ret = NULL;
  NQ_UUID_Table_lock(table);
  NQ_UUID_Table::Map::iterator i = table->map.find(*uuid);
  if(i != table->map.end() && i->first.type == uuid->type) {
    ret = i->second;
  }
  NQ_UUID_Table_unlock(table);
  return ret;
}

void NQ_UUID_Table_insert(NQ_UUID_Table *table, NQ_UUID *uuid, void *val) {
  NQ_UUID_Table_lock(table);
  table->map[*uuid] = val;
  NQ_UUID_Table_unlock(table);
}

void NQ_UUID_Table_delete(NQ_UUID_Table *table, NQ_UUID *uuid) {
  NQ_UUID_Table_lock(table);
  table->map.erase(*uuid);
  NQ_UUID_Table_unlock(table);
}

void NQ_UUID_Table_each(NQ_UUID_Table *table, NQ_Transaction transaction,
			NQ_UUID_Type type, PFany iterator, void *userdata){
  NQ_UUID_Table_lock(table);
  for(NQ_UUID_Table::Map::iterator i = table->map.begin();
      i != table->map.end(); ++i){
    iterator(i->second, userdata);
  }
  NQ_UUID_Table_unlock(table);
}

void NQ_Principal_print_iterator(NQ_Principal *p, void *arg){
  NQ_Principal_print_hash(p); printf("\n");
}

void NQ_Principal_print_allhashes(){
  assert(0);
}

struct NQ_Principal_hash {
  inline size_t operator()(const NQ_Principal *t) const  {
    return (size_t)SuperFastHash((const char *)t->key.hash, t->key.hash_len);
  }
};

struct NQ_Principal_equals {
  inline bool operator()(const NQ_Principal *l, const NQ_Principal *r) const {
    return 
      l->key.hash_len == r->key.hash_len &&
      0 == memcmp(l->key.hash, r->key.hash, l->key.hash_len);
  }
};

#if 0
int NQ_Principal_find(NQ_Principal *p, NQ_Principal_Query *q){
  return NQ_Host_eq(p->home, q->host) && EVP_PKEY_eq(p->id, q->pkey);
}
#endif

typedef hash_set<NQ_Principal*, NQ_Principal_hash, NQ_Principal_equals > PrincipalPool;
PrincipalPool principal_pool;

NQ_Principal *NQ_Principal_add(NQ_Principal *p) {
  PrincipalPool::iterator i = principal_pool.find(p);
  if(i == principal_pool.end()) {
    principal_pool.insert(p);
    return p;
  } else {
    free(p);
    return *i;
  }
}

static NQ_Principal *load_principal(string ifname);
char *NQ_Principal_hash_filename_helper(unsigned char *hash, int len);

NQ_Principal *NQ_Principal_find(unsigned char *hash, int len) {
  NQ_Principal p;
  memset(p.key.hash, 0, sizeof(p.key.hash));
  memcpy(p.key.hash, hash, len);
  p.key.hash_len = len;
  PrincipalPool::iterator i = principal_pool.find(&p);
  if(i == principal_pool.end()) {
    // cerr << "Checking filesystem\n";
    char *fname = NQ_Principal_hash_filename_helper(hash, len);
    NQ_Principal *rv = load_principal(string(fname));
    free(fname);
    if(rv == NULL) {
      cerr << "not found on filesystem\n";
    } else {
      // cerr << "found on filesystem\n";
    }
    return rv;
  }
  return *i;
}

void NQ_Principal_delete(NQ_Principal *principal){
  principal->references--;
  if(principal->references <= 0){  
    assert(principal_pool.find(principal) != principal_pool.end() && 
	   *principal_pool.find(principal) == principal);
    principal_pool.erase(principal);
    EVP_PKEY_free(principal->id);
    free(principal);
  }
}

 char *NQ_Principal_hash_filename_helper(unsigned char *hash, int len){
   unsigned char tmp_h[EVP_MAX_MD_SIZE];
   assert((unsigned) len <= sizeof(tmp_h));
   memset(tmp_h, 0, sizeof(tmp_h));

   memcpy(tmp_h, hash, len);

  unsigned i;
  int maxlen = sizeof(tmp_h) * 2 + strlen(".principal") + 1;
  // N.B. Use malloc, since this code is called from C
  char *fname = (char *)malloc(maxlen);
  fname[0] = '\0';
  for(i=0; i < (unsigned)len; i++) {
    sprintf(fname + strlen(fname), "%02x", ((unsigned char*)tmp_h)[i]);
  }
  strcat(fname, ".principal");
  assert(strlen(fname) <= (unsigned)maxlen - 1);
  return fname;

 }
char *NQ_Principal_hash_filename(NQ_Principal *principal){
  return NQ_Principal_hash_filename_helper(principal->key.hash, principal->key.hash_len);
}

/////////////////////////// UUIDSet

struct UUIDSet : public hash_set<NQ_UUID, NQ_UUID_hash, NQ_UUID_equals> {
};
UUIDSet *UUIDSet_new(void) {
  return new UUIDSet();
}
int UUIDSet_contains(UUIDSet *u_set, const NQ_UUID *p) {
  return u_set->find(*p) != u_set->end();
}
void UUIDSet_insert(UUIDSet *u_set, const NQ_UUID *p) {
  u_set->insert(*p);
}
void UUIDSet_erase(UUIDSet *u_set, const NQ_UUID *p) {
  u_set->erase(*p);
}
#if 0
void UUIDSet_iterate(UUIDSet *u_set, void (*fn)(const NQ_UUID *p)) {
  for(UUIDSet i = u_set->begin(); i != u_set->end(); i++) {
    fn(&*i);
  }
}
#endif
void UUIDSet_destroy(UUIDSet *u_set) {
  delete u_set;
}

/////////////////////////// NQ_TriggerSet

// Tuple UUID => hash of Trigger UUID
struct NQ_TriggerSet : hash_map<NQ_UUID, NQ_UUID_Table, NQ_UUID_hash, NQ_UUID_equals> {
  void dump() {
    for(iterator i = begin(); i != end(); i++) {
      cerr << "UUID hash = " << i->first << "\n";
      for(NQ_UUID_Table::Map::iterator j = i->second.map.begin(); j != i->second.map.end(); j++) {
	cerr << "\t Trigger hash = " << j->second <<"\n";
      }
    }
  }
};

NQ_TriggerSet *NQ_TriggerSet_new() {
  return new NQ_TriggerSet();
}

extern int dump_set;

void NQ_TriggerSet_match_and_fire(NQ_TriggerSet *u_set, const NQ_Transaction *transaction, const NQ_Tuple *tuple, NQ_Trigger_Type type) {
  NQ_TriggerSet::iterator i = u_set->find(*tuple);
  if(i == u_set->end()) {
    if(u_set->size() > 0 && dump_set) {
      u_set->dump();
    }
    return;
  }
  for(NQ_UUID_Table::Map::iterator j = i->second.map.begin();
      j != i->second.map.end(); j++) {
    NQ_Attribute_Trigger *trigger = (NQ_Attribute_Trigger *)j->second;
    if(NQ_Trigger_is_locally_valid(transaction, trigger)) {
      NQ_Trigger_defer(transaction, trigger->description, trigger->id, trigger->cb_id);
    }
  }
}

void NQ_TriggerSet_insert(NQ_TriggerSet *u_set, NQ_Attribute_Trigger *trigger) {
  (*u_set)[trigger->description->tuple].map[trigger->id] = trigger;
}
void NQ_TriggerSet_erase(NQ_TriggerSet *u_set, NQ_Attribute_Trigger *trigger) {
  (*u_set)[trigger->description->tuple].map.erase(trigger->id);
  // xxx erase the 2nd level hash_set as well??
}

int NQ_TriggerSet_size(NQ_TriggerSet *u_set) {
  return u_set->size();
}
void NQ_TriggerSet_destroy(NQ_TriggerSet *u_set) {
  delete u_set;
}

void NQ_TriggerSet_iterate(NQ_TriggerSet *set, void (*fn)(NQ_Tuple tid, NQ_UUID_Table *value, void *ctx), void *ctx) {
  for(NQ_TriggerSet::iterator i = set->begin(); i != set->end(); i++) {
    fn(i->first, &i->second, ctx);
  }
}

///////////////////////////

struct NQ_Attribute_Name_Set : public hash_map<NQ_Attribute_Name_C, int, NQ_Attribute_Name_C_hash, NQ_Attribute_Name_C_equals> {
};

NQ_Attribute_Name_Set *NQ_AttributeNameSet_new(void) {
  return new NQ_Attribute_Name_Set();
}

void NQ_AttributeNameSet_set(NQ_Attribute_Name_Set *set, const NQ_Attribute_Name *name, int value) {
  (*set)[NQ_Attribute_Name_C(name)] = value;
}

void NQ_AttributeNameSet_insert(NQ_Attribute_Name_Set *set, const NQ_Attribute_Name *name) {
  NQ_AttributeNameSet_set(set, name, 1);
}
void NQ_AttributeNameSet_erase(NQ_Attribute_Name_Set *set, const NQ_Attribute_Name *name) {
  set->erase(NQ_Attribute_Name_C(name));
}
int NQ_AttributeNameSet_contains(NQ_Attribute_Name_Set *set, const NQ_Attribute_Name *name) {
  NQ_Attribute_Name_Set::iterator i = set->find(NQ_Attribute_Name_C(name));
  if(i != set->end()) {
    assert(i->second != 0);
    return i->second;
  } else {
    return 0;
  }
}

void NQ_AttributeNameSet_iterate(NQ_Attribute_Name_Set *set, void (*fn)(void *ctx, const NQ_Attribute_Name *), void *ctx) {
  for(NQ_Attribute_Name_Set::iterator i = set->begin(); i != set->end(); i++) {
    fn(ctx, i->first.name);
  }
}
void NQ_AttributeNameSet_destroy(NQ_Attribute_Name_Set *set) {
  delete set;
}
int NQ_AttributeNameSet_size(NQ_Attribute_Name_Set *set) {
  return set->size();
}

///////////////////////////

string NQ_Host_as_string(const NQ_Host &h) {
  //return utos(h.addr) + ":" + itos(h.port);
  struct in_addr addr;
  addr.s_addr = h.addr;

  return string(inet_ntoa(addr)) + ":" + itos(h.port);
}

hash_map<NQ_Host, NQ_Principal *, NQ_Host_hash, NQ_Host_equals> home_map;

void NQ_publish_home_principal(void) {
  NQ_publish_principal(&NQ_default_owner,
		       (NQ_Host_as_string(NQ_Net_get_localhost()) + 
			".principal").c_str());
}

void NQ_publish_principal(NQ_Principal *p, const char *filename) {
  if(filename == NULL) {
    char *lname = NQ_Principal_hash_filename(p);
    ofstream os2(lname, ofstream::binary);
    file_marshall(*p, os2);
    os2.close();
    return;
  }
  cerr << "Exporting " << filename << "\n";
  ofstream os(filename, ofstream::binary);
  file_marshall(*p, os);
  os.close();

  char *lname = NQ_Principal_hash_filename(p);
#ifdef __LINUX__
  cerr << "Creating symlink " << filename << " => " << lname << "\n";
  unlink(lname);
  if(symlink(filename, lname) != 0) {
    perror("Symlink");
  }
#else
  cerr << "Outputting second copy to " << lname << "\n";
  ofstream os2(lname, ofstream::binary);
  file_marshall(*p, os2);
  os2.close();
#endif
  free(lname);
}

NQ_Principal *NQ_get_home_principal(NQ_Host *home) {
  static int count;
  if(count < 5) {
    // fprintf(stderr, "Warning: NQ_get_home_principal() uses file instead of nameserver!\n");
    count++;
  }
  if( home_map.find(*home) == home_map.end() ) {
    // Try to load from file
    printf("Importing: ");NQ_Host_print(*home);printf("\n");
    string ifname = NQ_Host_as_string(*home) + ".principal";
    NQ_Principal *rv = load_principal(ifname);
    if(rv != NULL) {
      home_map[*home] = rv;
    }
    return rv;
  } else {
    return home_map[*home];
  }
}

static NQ_Principal *load_principal(string ifname) {
  // cerr << "Loading principal from '" << ifname << "'\n";
  ifstream is(ifname.c_str(), ifstream::binary);
  vector<unsigned char> d0;
  get_all_file_data(is, d0);
  is.close();
  if(d0.size() == 0) {
    return NULL;
  }
  NQ_Principal *rv = NULL;
  CharVector_Iterator loc = d0.begin();
  rv = tspace_unmarshall(rv, *(Transaction *)NULL, loc, d0.end());
  if(rv != NULL) {
    // cerr << "Parsed principal from " << ifname << "\n";
    // cerr << " host is " << rv->home << "\n";
    return rv;
  } else {
    cerr << "Could not parse principal from " << ifname << "\n";
    return NULL;
  }
}

NQ_Principal *NQ_load_principal(const char *fname) {
  return load_principal(string(fname));
}

struct DeferredTrigger {
  NQ_Trigger_Description *desc;
  NQ_Trigger cb_id;

  DeferredTrigger(NQ_Trigger_Description *d, NQ_Trigger c) :
    desc(d), cb_id(c) 
  { }
  DeferredTrigger() {
    desc = NULL;
    cb_id = NQ_uuid_null;
  }
};

struct WaitGroup {
  enum State {
    CLOSED, // no messages can be sent, and no responses can be received
    OPEN, // allow more messages to be sent
    WAITING, // allow responses to be received
  };
  struct MapKey {
    NQ_Host host;
    int request_id;
    MapKey(const NQ_Host &h, int req) : host(h), request_id(req) { }
  };
  struct MapKey_hash {
    size_t operator()(const MapKey &m) const {
      const std::string key_str = NQ_Host_as_string(m.host) + itos(m.request_id);
      const char *str = key_str.c_str();
      return (size_t)SuperFastHash(str, strlen(str));
    }
  };

  struct MapKey_equals {
    bool operator()(const MapKey &l, const MapKey &r) const {
      return NQ_Host_eq(l.host,r.host) && l.request_id == r.request_id;
    }
  };

  struct Request {
    WaitGroup *group;
    WaitGroup_RequestHandler handler;
    int op, arg;
    void *ctx;
    Request(WaitGroup *g, WaitGroup_RequestHandler h, void *c, int o, int a) : 
      group(g), handler(h), op(o), arg(a), ctx(c)
      { }
    void run(int rv) {
      if(handler != NULL) {
	handler(group->m_transaction, ctx, op, arg, rv);
      }
    }
  };

  typedef hash_map<MapKey, Request *,
		   MapKey_hash, MapKey_equals> PendingRequestMap;

  NQ_Transaction_Real *m_transaction;
  int m_next_request_id;
  State m_state;
  PendingRequestMap m_pending_requests;
  WaitGroup_GroupHandler m_handler;
  WaitGroup_GroupHandler m_orig_handler;
  void *m_ctx;

  WaitGroup(NQ_Transaction_Real *t) : 
    m_transaction(t), 
    m_next_request_id(0), m_state(CLOSED), m_handler(NULL), m_orig_handler(NULL), m_ctx(NULL) {
  }

  void open(WaitGroup_GroupHandler handler, void *ctx) {
    if(!(m_state == CLOSED && m_pending_requests.size() == 0)) {
      cerr << "Looping\n";
      while(1) sleep(100);
    }
    assert(m_state == CLOSED && m_pending_requests.size() == 0);
    m_state = OPEN;
    m_handler = handler;
    m_ctx = ctx;
  }
  void close() {
    assert(m_state == OPEN);
    m_state = WAITING;
    check_and_finish();
  }

private:
  void check_and_finish() {
    assert(m_state == WAITING);
    // if all requests have completed, call the group continuation
    // printf("check_and_finish(%p) %d\n", this, (int)m_pending_requests.size());
    //printf("%d pending requests\n", m_pending_requests.size());
    if(m_pending_requests.size() == 0) {
      // printf("Group finished, handler = %p\n", m_handler);
      WaitGroup_GroupHandler handler = m_handler;
      void *ctx = m_ctx;

      m_state = CLOSED;
      m_handler = NULL;
      m_ctx = NULL;
      m_orig_handler = handler;
      // update state before calling handler so that it sees the right
      // state.
      if(handler != NULL) {
	handler(m_transaction, ctx);
      }
    }
  }

  /* request_id */ 
  int add_wait(const NQ_Host host, WaitGroup_RequestHandler handler,
	       void *ctx, unsigned int op, int arg) {
    assert(m_state == OPEN);
    int request_id = m_next_request_id++;
    m_pending_requests[MapKey(host, request_id)] = 
      new Request(this, handler, ctx, op, arg);
    return request_id;
  }

public:

  void issue(const NQ_Host host, // const NQ_Transaction &target_transaction,
	     WaitGroup_RequestHandler handler, 	     
	     void *ctx, unsigned int op, int arg) {
    int request_id = add_wait(host, handler, ctx, op, arg);

    DEBUG_MESSAGES(printf("\t%lf:WG_ISSUE(%d[%d])\n", doubleTime(), op, request_id));
    NQ_RingBuffer output;
    NQ_RingBuffer_init(&output);
    NQ_Request_pickle_uuid(&output, m_transaction->t);
    //NQ_Request_pickle_uuid(&output, target_transaction);
    NQ_Request_pickle_host(&output, NQ_Net_get_localhost());
    NQ_Request_pickle_int(&output, request_id);
    NQ_Request_pickle_int(&output, op);
    NQ_Request_pickle_int(&output, arg);
    REQUEST_LOG(printf("NQ_Net_Transaction_waitgroup issue(host:");NQ_Host_print(host);printf(", op:%x, arg:%d, request_id:%d)\n", op, arg, request_id););
    NQ_Request_issue_async(host, &output, NQ_REQUEST_TRANSACTION_R_WAITGROUP, 0);
    NQ_RingBuffer_destroy(&output);
    return;
  }

  static int trigger_op(NQ_Trigger_Upcall_Type type) {
    return NQ_TRANSACTION_WG_TRIGGER | ((int)type);
  }
  static void merge_veto(NQ_Transaction_Real *t, void *_ctx, int op, int arg, int rv) {
    NQ_Transaction_Commit_Step_Ctx *ctx = (NQ_Transaction_Commit_Step_Ctx *)_ctx;
    int old_result = ctx->result;
    ctx->result = old_result && rv;
    // printf("Merge veto %d %d => %d\n", old_result, rv, ctx->result);
  }
  static void ignore(NQ_Transaction_Real *t, void *_ctx, int op, int arg, int rv) {
    // NQ_Transaction_Commit_Step_Ctx *ctx = (NQ_Transaction_Commit_Step_Ctx *)_ctx;
    // printf("Sync ignore\n");
  }
  void trigger_fire(NQ_Trigger trigger_id, const DeferredTrigger &trigger, 
		    NQ_Trigger_Upcall_Type type, 
		    NQ_Transaction_Commit_Step_Ctx *ctx, unsigned int arg) {
    WaitGroup_RequestHandler handler = NULL;
    switch(type) {
    case NQ_TRIGGER_UPCALL_SYNC_VETO:
      cerr << "Trigger fire, VETO\n";
      handler = merge_veto;
      break;
    case NQ_TRIGGER_UPCALL_SYNC_VERDICT:
      cerr << "Trigger fire, VERDICT\n";
      handler = ignore;
      break;
    case NQ_TRIGGER_UPCALL_ASYNC_VERDICT:
    case NQ_TRIGGER_UPCALL_ASYNC_COMMIT_DONE:
      cerr << "Trigger fire, ASYNC\n";
      break;
    default:
      assert(0);
    }
    int request_id = -1;
    NQ_Host dest_host = trigger.cb_id.home;

    if(handler != NULL) {
      request_id = add_wait(dest_host, handler, ctx, trigger_op(type), arg);
    }

    // derived from NQ_Net_Trigger_fire();
    // Arg = verdict
    NQ_RingBuffer output;
  
    NQ_RingBuffer_init(&output);
    NQ_Request_pickle_uuid(&output, m_transaction->t);
    NQ_Request_pickle_int(&output, type);
    NQ_Request_pickle_host(&output, NQ_Net_get_localhost());
    NQ_Request_pickle_uuid(&output, trigger.cb_id);
    NQ_Request_pickle_int(&output, request_id);
    NQ_Request_pickle_int(&output, arg);
    REQUEST_LOG(printf("fire_trigger()\n"););
    NQ_Request_issue_async(dest_host, &output, NQ_REQUEST_TRIGGER_FIRE, 0);

    NQ_RingBuffer_destroy(&output);
  }

private:
  int handle_response(const NQ_Host host, int request_id, int rv) {
    MapKey key(host, request_id);
    PendingRequestMap::iterator i = 
      m_pending_requests.find(key);
    if(i == m_pending_requests.end()) {
      printf("No matching group request! (wanted %d)\n", request_id);
      return -1;
    }

    Request *req = i->second;
    m_pending_requests.erase(key);
    // printf("Got response, count is %d\n", (int)m_pending_requests.size());

    req->run(rv);
    delete req;

    check_and_finish();
    return 0;
  }

public:
  static int handle_response(NQ_Socket *sock, NQ_Request_Data *req) {
    int datalen = (int) req->header.length - (int) sizeof(NQ_Request_Header);
    unsigned char *data = req->data;
    NQ_Transaction transaction;
    NQ_Host correspondent;
    int request_id, rv;
    int err = 0;
    NQ_Transaction_Real *t;

    //fprintf(stderr, "%lf: handle_response, thread = %x\n", doubleTime(), (int)pthread_self());
    transaction = NQ_Request_unpickle_uuid(&data, &datalen, &err);
    if(err < 0) { err = -30; goto nq_waitgroup_handle_response_err; }
    correspondent = NQ_Request_unpickle_host(&data, &datalen, &err);
    if(err < 0){ err = -40; goto nq_waitgroup_handle_response_err; }
    
    request_id = NQ_Request_unpickle_int(&data, &datalen, &err);
    if(err < 0) { err = -50; goto nq_waitgroup_handle_response_err; }
    rv = NQ_Request_unpickle_int(&data, &datalen, &err);
    if(err < 0) { err = -60; goto nq_waitgroup_handle_response_err; }
    // printf("WaitGroup: response, dlen = %d, request_id = %d, rv = %d\n", datalen, request_id, rv);
    t = NQ_Transaction_get_any(transaction);
//    NQ_UUID_print(&transaction); printf("-> %p\n", t);
    if(!t) { err = -70; goto nq_waitgroup_handle_response_err; }

    if(DEBUG_TX_MUTEX) fprintf(stderr, "coord_lock(%p)\n", t);

    //  XXX Using t->mutex is a more fine-grained lock, but since handle_response() can potentially deallocate t, easier to use one global lock
    // XXX not tested / inspected to avoid deadlock
    pthread_mutex_lock(&t->mutex);
    // static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
    // pthread_mutex_lock(&lock);

    t->coordinator.wait_group->handle_response(correspondent, request_id, rv);
    if(DEBUG_TX_MUTEX) fprintf(stderr, "coord_unlock(%p)\n", t);
    // pthread_mutex_unlock(&lock);
    pthread_mutex_unlock(&t->mutex);
    NQ_Transaction_Real_put(t);
    return 0;

  nq_waitgroup_handle_response_err:
    // printf("WaitGroup: handle_response err %d\n", err);
    return -1;
  }
};

void WaitGroup_respond(const NQ_Host *host, NQ_Transaction t, const NQ_Request_Data *req, int request_id, int rv) {
//  DEBUG_MESSAGES(printf("\t%lf:WG_RESPOND(%d)\n", doubleTime(), request_id));
  NQ_RingBuffer output;
  NQ_RingBuffer_init(&output);
  NQ_Request_pickle_uuid(&output, t);
  NQ_Request_pickle_host(&output, NQ_Net_get_localhost());
  NQ_Request_pickle_int(&output, request_id);
  NQ_Request_pickle_int(&output, rv);

  // sock will be null for local requests that bypass the socket layer
  NQ_Request_issue_async(*host, &output, NQ_REQUEST_TRANSACTION_R_WAITGROUP_RESP, 0);
  NQ_RingBuffer_destroy(&output);
}

struct WaitGroupServer {
  NQ_Transaction_Real *m_transaction;
  WaitGroupServer(NQ_Transaction_Real *t) : m_transaction(t) 
  {  }

  int handle_request(NQ_Socket *sock, NQ_Request_Data *req, const NQ_Host *host, int request_id, unsigned int op, int arg) {
    NQ_Transaction_Commit_Step_Ctx *ctx = 
      NQ_Transaction_Commit_Step_Ctx_create(m_transaction->t, host, req, request_id, arg);
    int rv;
    // printf("\t%lf:WGServer_REQUEST(%d, id %d)\n", doubleTime(), op, request_id);
    switch(op) {
    case NQ_TRANSACTION_WG_START:
      WG_PING(request_id);
      rv = NQ_Local_Transaction_WG_commit_start(m_transaction, ctx);
      WG_PING(request_id);
      break;
    case NQ_TRANSACTION_WG_ADVANCE_TO_PROPOSAL:
      WG_PING(request_id);
      rv = NQ_Local_Transaction_WG_commit_propose(m_transaction, ctx);
      WG_PING(request_id);
      break;
    case NQ_TRANSACTION_WG_ADVANCE_TO_VERDICT:
      WG_PING(request_id);
      rv = NQ_Local_Transaction_WG_commit_verdict(m_transaction, ctx);
      WG_PING(request_id);
      break;
    case NQ_TRANSACTION_WG_FINALIZE:
      WG_PING(request_id);
      rv = NQ_Local_Transaction_WG_commit_finalize(m_transaction, ctx);
      WG_PING(request_id);
      break;
    case NQ_TRANSACTION_WG_DONE:
      WG_PING(request_id);
      rv = NQ_Local_Transaction_WG_commit_done(m_transaction, ctx);
      WG_PING(request_id);
      break;
    case NQ_TRANSACTION_WG_TEST:
      WG_PING(request_id);
      rv = NQ_Local_Transaction_WG_test(m_transaction, ctx);
      WG_PING(request_id);
      break;
    case NQ_TRANSACTION_WG_FAST_COMMIT:
      WG_PING(request_id);
      rv = NQ_Local_Transaction_WG_fast_commit(m_transaction, ctx);
      WG_PING(request_id);
      break;
    default:
      printf("Unknown WAIT_GROUP cmd %d\n", op);
      return -1;
    }
    // the Request response is sent by the handler, either immediately or in response to an event
    return rv;
  }

  static int handle_request(NQ_Socket *sock, NQ_Request_Data *req) {
    int datalen = (int)req->header.length - (int)sizeof(NQ_Request_Header);
    unsigned char *data = req->data;
    NQ_Transaction master_transaction = NQ_uuid_null;
    // NQ_Transaction target_transaction;
    NQ_Host correspondent;
    memset(&correspondent, 0, sizeof(correspondent));
    int err;
    int request_id = -1, op, arg;
    NQ_Transaction_Real *t;

    master_transaction = NQ_Request_unpickle_uuid(&data, &datalen, &err);
    if(err < 0){ err = -ERR_UNABLE_TO_UNPICKLE(0); goto nq_waitgroup_handle_err; }
    // target_transaction = NQ_Request_unpickle_uuid(&data, &datalen, &err);
    // if(err < 0){ err = -35; goto nq_waitgroup_handle_err; }
    correspondent = NQ_Request_unpickle_host(&data, &datalen, &err);
    if(err < 0){ err = -ERR_UNABLE_TO_UNPICKLE(1); goto nq_waitgroup_handle_err; }
    request_id = NQ_Request_unpickle_int(&data, &datalen, &err);
    if(err < 0){ err = -ERR_UNABLE_TO_UNPICKLE(2); goto nq_waitgroup_handle_err; }
    op = NQ_Request_unpickle_int(&data, &datalen, &err);
    if(err < 0){ err = -ERR_UNABLE_TO_UNPICKLE(3); goto nq_waitgroup_handle_err; }
    arg = NQ_Request_unpickle_int(&data, &datalen, &err);
    if(err < 0){ err = -ERR_UNABLE_TO_UNPICKLE(4); goto nq_waitgroup_handle_err; }

    REQUEST_LOG(printf("NQ_Net_Transaction_waitgroup handle (%d on %s@", op, name->name);NQ_Host_print(name->owner->home);printf(")\n"););

    t = NQ_Transaction_register_remote(master_transaction);
    if(!t) { err = -ERR_UNABLE_TO_RESOLVE_TRANS; goto nq_waitgroup_handle_err; }

    t->server.wait_group_server->handle_request(sock, req, &correspondent, request_id, op, arg);
    return 0;
  nq_waitgroup_handle_err:
    printf("waitgroup_handle err = %d\n", err);
    WaitGroup_respond(&correspondent, master_transaction, req, request_id, err);
    return -1;
  }
};

// C interfaces

// Verdict: 0 = true, !0 = false

void NQ_Transaction_Commit_Step_Ctx_handle_one(NQ_Transaction_Real *transaction, void *_ctx, int op, int arg, int rv) {
  NQ_Transaction_Commit_Step_Ctx *ctx = (NQ_Transaction_Commit_Step_Ctx *)_ctx;
  int old_result = ctx->result;
  ctx->result = old_result && !rv;
  // printf("Commit_Step_Ctx handle_one (%d && %d => %d)\n", old_result, !rv, ctx->result);
}

void NQ_Transaction_Commit_Step_Ctx_respond_group(NQ_Transaction_Real *transaction, void *_ctx) {
  NQ_Transaction_Commit_Step_Ctx *ctx = (NQ_Transaction_Commit_Step_Ctx *)_ctx;
  // printf("Commit_Step_Ctx Respond group %d %d\n", ctx->result, ctx->local_result);
  NQ_Commit_Server_respond(ctx, (ctx->result && ctx->local_result) ? 0 : -1);
}

////////////////////////////////////////////////
void NQ_Request_handle_one(NQ_Transaction_Real *transaction, void *_ctx, int op, int arg, int rv) {
  NQ_Request_Ctx *ctx = (NQ_Request_Ctx *)_ctx;
  int old_result = ctx->result;
  ctx->result = old_result && !rv;
  // printf("Request_handle_one (%d && %d => %d)\n", old_result, !rv, ctx->result);
}
void NQ_Request_respond_group(NQ_Transaction_Real *transaction, void *_ctx) {
  NQ_Request_Ctx *ctx = (NQ_Request_Ctx *)_ctx;
  // printf("Request Respond group %d %d\n", ctx->result, ctx->local_result);
  NQ_Request_respond(ctx->sock, NULL, ctx->req, 
		     (ctx->result && ctx->local_result) ? 0: -1 );
}

////////////////////////////////////////////////

WaitGroup *last_wg;
NQ_Transaction last_respond_transaction;
NQ_Host last_respond_host;
WaitGroup *WaitGroup_create(NQ_Transaction_Real *t) {
  return last_wg = new WaitGroup(t);
}

WaitGroupServer *WaitGroupServer_create(NQ_Transaction_Real *t) {
  return new WaitGroupServer(t);
}

void WaitGroup_open(NQ_Transaction_Real *t,
		     WaitGroup_GroupHandler handler, void *ctx) {
  if(DEBUG_TX_MUTEX) fprintf(stderr, "WG_open(%p)\n", t);
  pthread_mutex_lock(&t->mutex);
  t->coordinator.wait_group->open(handler, ctx);
}

WaitGroup last_wg_close(NULL);
void WaitGroup_close(NQ_Transaction_Real *t) {
  if(DEBUG_TX_MUTEX) fprintf(stderr, "WG_close(%p)\n", t);
  t->coordinator.wait_group->close();
  pthread_mutex_unlock(&t->mutex);

  last_wg_close = *t->coordinator.wait_group;
}

void WaitGroup_issue(NQ_Transaction_Real *t, 
		     const NQ_Host host,
		     WaitGroup_RequestHandler handler, void *ctx,
		     unsigned int op, int arg) {
  t->coordinator.wait_group->issue(host, handler, ctx, op, arg);
}

struct DeferredTriggers : 
  hash_map<NQ_Trigger, DeferredTrigger, NQ_UUID_hash> {
  NQ_Transaction_Real *transaction;
  DeferredTriggers(NQ_Transaction_Real *_t) : transaction(_t) { }
  void fire_all(NQ_Trigger_Upcall_Type type, NQ_Transaction_Commit_Step_Ctx *ctx, int arg) {
    int j = 0;
    for(iterator i = begin(); i != end(); i++, j++) {
      // printf("[%d]", j);
      transaction->coordinator.wait_group->trigger_fire(i->first, i->second, type, ctx, arg);
    }
    // printf("Firing all %p => %d\n", this, j);

    if(0 && j > 0 && NQ_Net_get_localhost().port < 8000) {
      printf("Firing all %p => %d\n", this, j);
    }
  }
};

DeferredTriggers *DeferredTriggers_create(NQ_Transaction_Real *t) {
  return new DeferredTriggers(t);
}

void DeferredTriggers_destroy(DeferredTriggers *t) {
  delete t;
}

void DeferredTriggers_fire_all(DeferredTriggers *t, NQ_Trigger_Upcall_Type type, 
			       NQ_Transaction_Commit_Step_Ctx *ctx, int arg) {
  t->fire_all(type, ctx, arg);
}

int DeferredTriggers_size(struct DeferredTriggers *t) {
  return t->size();
}

void NQ_Trigger_defer(const NQ_Transaction *t, NQ_Trigger_Description *desc, NQ_Trigger trigger_id, NQ_Trigger cb_id) {
  NQ_Transaction_Real *t_real = NQ_Transaction_get_any(*t);
  
  if(!t_real){ // the transaction  doesn't exist any more... 
    printf("Warning: Tried to install a trigger on a nonexistant transaction\n");
    return;
  }

  vector<DeferredTriggers*> dests;
  if(desc->upcall_type & NQ_TRIGGER_UPCALL_SYNC_VETO) {
    dests.push_back(t_real->sync_veto);
//    printf("NQ_TRIGGER_UPCALL_SYNC_VETO\n");
  }
  if(desc->upcall_type & NQ_TRIGGER_UPCALL_SYNC_VERDICT) {
    dests.push_back(t_real->sync_verdict);
//    printf("NQ_TRIGGER_UPCALL_SYNC_VERDICT\n");
  }
  if(desc->upcall_type & NQ_TRIGGER_UPCALL_ASYNC_VERDICT) {
    dests.push_back(t_real->async_verdict);
//    printf("NQ_TRIGGER_UPCALL_ASYNC_VERDICT\n");
  }
  if(desc->upcall_type & NQ_TRIGGER_UPCALL_ASYNC_COMMIT_DONE) {
    dests.push_back(t_real->commit_done);
//    printf("NQ_TRIGGER_UPCALL_ASYNC_COMMIT_DONE\n");
  }
  for(size_t i=0; i < dests.size(); i++) {
    (*dests[i])[trigger_id] = DeferredTrigger(desc, cb_id);
  }
  NQ_Transaction_Real_put(t_real);
}

void NQ_Request_Transaction_waitgroup_request(NQ_Socket *sock, NQ_Request_Data *req) {
  WaitGroupServer::handle_request(sock, req);
}

void NQ_Request_Transaction_waitgroup_resp(NQ_Socket *sock, NQ_Request_Data *req) {
  WaitGroup::handle_response(sock, req);
}

///////
// Bundles
// A bundle is a group of requests for which the client tries to send in bulk.
// The server likewise  tries to respond to the requests in a bundle in bulk.
// For every connection, there can be at most one simul. bundle

// Bundles are implemented with TCP_CORK & MSG_MORE

pthread_mutex_t bundle_mutex = PTHREAD_MUTEX_INITIALIZER;

typedef set<NQ_Peer *> PeerCollection;
int bundling_count = 0;
PeerCollection bundle_peers;

static void bundle_issue(NQ_Peer *peer, int request_id) {
  static bool output_inited;
  static NQ_RingBuffer output;
  if(!output_inited) {
    NQ_RingBuffer_init(&output);
  }
  NQ_Peer_issue_async(peer, &output, request_id, 0);
}

void NQ_Bundle_begin(void) {
  pthread_mutex_lock(&bundle_mutex);
  bundling_count++;
  pthread_mutex_unlock(&bundle_mutex);
}
int NQ_Bundle_check(NQ_Peer *peer) {
  int rv = 0;
  pthread_mutex_lock(&bundle_mutex);
  if(bundling_count > 0) {
    if(bundle_peers.find(peer) == bundle_peers.end()) {
      bundle_peers.insert(peer);
      rv = 1;
    }
  }
  pthread_mutex_unlock(&bundle_mutex);
  return rv;
}
void NQ_Bundle_end(void) {
  pthread_mutex_lock(&bundle_mutex);
  bundling_count--;
  assert(bundling_count >= 0);
  if(bundling_count == 0) {
    for(PeerCollection::iterator i=bundle_peers.begin(); i != bundle_peers.end(); i++) {
      NQ_Peer *peer = *i;
      bundle_issue(peer, NQ_REQUEST_BUNDLE_END);
    }
    bundle_peers.clear();
  }
  pthread_mutex_unlock(&bundle_mutex);
}

void NQ_Bundle_implicit_done(struct NQ_Peer *peer) {
  pthread_mutex_lock(&bundle_mutex);
  PeerCollection::iterator i =bundle_peers.find(peer);
  if(i != bundle_peers.end()) {
    bundle_peers.erase(i);
  }
  pthread_mutex_unlock(&bundle_mutex);
}

// Server handlers
// The  cork/uncork logic is in NQ_Request_respond
void NQ_Request_Bundle_begin(NQ_Socket *sock, NQ_Request_Data *req) {
  NQ_Request_respond(sock, NULL, req, 0);
}

void NQ_Request_Bundle_end(NQ_Socket *sock, NQ_Request_Data *req) {
  NQ_Request_respond(sock, NULL, req, 0);
}

void Principal::tspace_marshall(const Principal &p, std::vector<unsigned char> &buf) {
  marshall_flat_object(p, buf);
}

Principal *Principal::tspace_unmarshall(Transaction &transaction,
		  CharVector_Iterator &curr,
		  const CharVector_Iterator &end) {
  return unmarshall_flat_object<Principal>(curr, end);
}


Principal::operator NQ_Principal*() {
  return NQ_Principal_find(key.hash, key.hash_len);
}

NQ_Principal::operator Principal() {
  Principal p;
  p.home = home;
  p.key = key;
  return p;
}
