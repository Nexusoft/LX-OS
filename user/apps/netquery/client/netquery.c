#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <nq/netquery.h>
#include <nq/util.hh>
#include <nq/gcmalloc.h>
#include <nq/net.h>
#include <nq/garbage.h>
#include <nq/hashtable.h>
#include <nq/socket.h>
#include <nq/pickle.h>
#ifndef __NEXUS__
#include <malloc.h>
#endif
#include <pthread.h>
#include <execinfo.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <asm/param.h>

#if HZ != 100
#warning times could be wrong, only tested on system with HZ = 100.
#endif

#define HOOK_MALLOC (0)
#define RECORD_MALLOC_SIZE (0)

NQ_Stat NQ_stat;

int show_rpc_traffic = 0;

#if HOOK_MALLOC
void *(*old_malloc_hook)(size_t size, const void *caller);
void *(*old_realloc_hook)(void *ptr, size_t size, const void *caller);
void (*old_free_hook)(void *, const void *caller);

static void *count_malloc(size_t size, const void *caller);
static void *count_realloc(void *ptr, size_t size, const void *caller);
static void count_free(void *ptr, const void *caller);

void malloc_init(void) {
  old_malloc_hook = __malloc_hook;
  old_free_hook = __free_hook;
  old_realloc_hook = __realloc_hook;
  __malloc_hook = count_malloc;
  __free_hook = count_free;
  __realloc_hook = count_realloc;
}
void (*__malloc_initialize_hook) (void) = malloc_init;
#endif

////////////////////////////// NQ MANAGEMENT
void NQ_init(unsigned int my_ip, unsigned short port){
  srandom(time(NULL));
  NQ_Net_init(my_ip, port);
  OpenSSL_add_all_algorithms();
  OpenSSL_add_all_ciphers();
  OpenSSL_add_all_digests();
  NQ_UUID_init();
  NQ_Transaction_init();
  NQ_Attribute_init();
  NQ_GC_init();
  bzero(&NQ_stat, sizeof(NQ_Stat));

#ifndef NO_GC_MALLOC
  GC_INIT();
#endif
#ifdef __NEXUS__
  printf("cd /nfs /* for principals, etc */ \n");
  chdir("/nfs");
#endif
}

#ifndef NO_GC_MALLOC
void *malloc(size_t size) {
  return GC_malloc(size);
}
void free(void *ptr) {
  GC_free(ptr);
}
void *realloc(void *ptr, size_t size) {
  return GC_realloc((ptr), (size));
}
void *calloc(size_t size, size_t cnt) {
  void *rv = GC_malloc((size)*(cnt));
  memset(rv, 0, size * cnt);
  return rv;
}
#endif 

int new_count;
int delete_count;

// double counting: delete count will also go to free_count, etc
int malloc_count;
int free_count;

struct MallocEntry {
#define BACKTRACE_DEPTH (8)
  int size;
  void *location;
  void *backtrace[BACKTRACE_DEPTH];
};

struct FreeEntry {
  void *location;
  void *backtrace[BACKTRACE_DEPTH];
};

#ifdef __NEXUS__
#define NUM_MALLOC_ENTRIES (1)
#else
#define NUM_MALLOC_ENTRIES (10000000)
#endif

#if HOOK_MALLOC
// N.B. does not track realloc()
static struct MallocEntry malloc_entries[NUM_MALLOC_ENTRIES];
static struct FreeEntry free_entries[NUM_MALLOC_ENTRIES];
static int num_malloc_entries = 0;
static int num_free_entries = 0;

static pthread_mutex_t counter_mutex = PTHREAD_MUTEX_INITIALIZER;

static void *
count_malloc (size_t size, const void *caller)
{
  pthread_mutex_lock(&counter_mutex);
  void *result;
  /* Restore all old hooks */
  __malloc_hook = old_malloc_hook;
  __realloc_hook = old_realloc_hook;
  __free_hook = old_free_hook;
  /* Call recursively */

  if(RECORD_MALLOC_SIZE) {
    extern int malloc_count;
    assert(size > 0);
    malloc_count += size;
    void *rv = malloc(size + sizeof(int));
    *(int *)rv = size;
    result = (char *)rv + sizeof(int);
  } else {
    result = malloc(size);
  }

  if(num_malloc_entries < NUM_MALLOC_ENTRIES) {
    struct MallocEntry *ent = &malloc_entries[num_malloc_entries];
    ent->size = size;
    ent->location = result;
    memset(ent->backtrace, 0, sizeof(ent->backtrace));
    backtrace(ent->backtrace, BACKTRACE_DEPTH);
    num_malloc_entries++;
  }

  /* Restore our own hooks */
  __malloc_hook = count_malloc;
  __realloc_hook = count_realloc;
  __free_hook = count_free;
  pthread_mutex_unlock(&counter_mutex);
  return result;
}

static void *
count_realloc(void *ptr, size_t size, const void *caller)
{
  pthread_mutex_lock(&counter_mutex);
  void *result;
  /* Restore all old hooks */
  __malloc_hook = old_malloc_hook;
  __realloc_hook = old_realloc_hook;
  __free_hook = old_free_hook;
  /* Call recursively */

  if(RECORD_MALLOC_SIZE) {
    printf("realloc(%p,%d)\n", ptr, size);
    assert(size != 0 && ptr != NULL);
    free_count += *((int*)ptr - 1);
    malloc_count += size;
    result = realloc((char *)ptr - sizeof(int), size + sizeof(int));
    *(int*)result = size;
    result = (char *)result + sizeof(int);
  } else {
    result = realloc(ptr, size);
  }

  /* Restore our own hooks */
  __malloc_hook = count_malloc;
  __realloc_hook = count_realloc;
  __free_hook = count_free;
  pthread_mutex_unlock(&counter_mutex);
  return result;
}

static void 
count_free (void *ptr, const void *caller)
{
  pthread_mutex_lock(&counter_mutex);
  /* Restore all old hooks */
  __malloc_hook = old_malloc_hook;
  __realloc_hook = old_realloc_hook;
  __free_hook = old_free_hook;

  /* Call recursively */
  if(RECORD_MALLOC_SIZE) {
    if(ptr != NULL) {
      extern int free_count;
      free_count += *(int*)((char *)ptr - sizeof(int));
      free((char *)ptr - sizeof(int));
    }
  } else {
    free(ptr);
  }
  if(num_free_entries < NUM_MALLOC_ENTRIES) {
    struct FreeEntry *ent = &free_entries[num_free_entries];
    ent->location = ptr;
    memset(ent->backtrace, 0, sizeof(ent->backtrace));
    backtrace(ent->backtrace, BACKTRACE_DEPTH);
    num_free_entries++;
  }

  /* Restore our own hooks */
  __malloc_hook = count_malloc;
  __realloc_hook = count_realloc;
  __free_hook = count_free;
  pthread_mutex_unlock(&counter_mutex);
}

void print_backtrace(FILE *fp, void **trace) {
  int j;
  for(j = 0; j < BACKTRACE_DEPTH; j++) {
    if(trace[j] == NULL) {
      break;
    }
    fprintf(fp, "\t%p\n", trace[j]);
  }
  fprintf(fp, "\n");
}

void dump_memtrace(const char *fname) {
  printf("Dumping trace to '%s' ... ", fname);
  if(0) {
    printf("skipping\n");
    return;
  }
  int i;
  FILE *fp = fopen(fname, "w");
  for(i=0; i < num_malloc_entries; i++) {
    struct MallocEntry *ent = &malloc_entries[i];
    fprintf(fp, "M sz=%d loc=%p\n", ent->size, ent->location);
    print_backtrace(fp, ent->backtrace);
  }
  for(i=0; i < num_free_entries; i++) {
    struct FreeEntry *ent = &free_entries[i];
    fprintf(fp, "F loc=%p\n", ent->location);
    print_backtrace(fp, ent->backtrace);
  }
  fprintf(fp, "====EOF====\n");
  fclose(fp);
  printf("Dump done\n");
}

void stackdump_stderr(void) {
  fflush(stderr);
  void *buffer[16];
  memset(buffer, 0, sizeof(buffer));
  backtrace(buffer, 16);
  backtrace_symbols_fd(buffer, 16, fileno(stderr));
}
#else 
void dump_memtrace(const char *fname) {
  return;
}
#endif // HOOK_MALLOC

void NQ_cleanup(void){
  EVP_cleanup();
  NQ_UUID_cleanup();
}

void NQ_Show_RPCs(){
  show_rpc_traffic = 1;
}

////////////////////////////// NQ_Tuple

typedef NQ_Attribute_Name NQ_Tuple_Entry;

typedef struct NQ_Tuple_Real {
  NQ_UUID id;
  // struct hashtable *entries; // attributes
  NQ_Attribute_Name_Set *attr_names;
  NQ_Transaction delete_trans;
} NQ_Tuple_Real;

struct NameIteratorCtx {
  NQ_Tuple tid;
};
void cleanup_attr_name(void *_ctx, const NQ_Attribute_Name *name) {
  struct NameIteratorCtx *ctx = (struct NameIteratorCtx *)_ctx;
  NQ_Tuple_Attribute_Value_del(ctx->tid, (NQ_Attribute_Name *)name);
}

int NQ_Tuple_cleanup(NQ_Tuple_Real *r){
  NQ_UUID_release(r->id);
  struct NameIteratorCtx ctx = { .tid = r->id };
  // printf("Destroy %p\n", r->attr_names);
  NQ_AttributeNameSet_iterate(r->attr_names, cleanup_attr_name, &ctx);
  NQ_AttributeNameSet_destroy(r->attr_names);
  free(r);
  return 0;
}
//////////////////
int NQ_Tuple_create_commit(NQ_Transaction transaction, NQ_Tuple_Real *tuple, int revision){
  NQ_stat.server.create_tuple++;
  NQ_UUID_finalize(tuple->id);
  NQ_GC_register_tuple(tuple->id);
  return 0;
}
int NQ_Tuple_create_abort(NQ_Transaction transaction, NQ_Tuple_Real *tuple, int revision){
  //assert(NQ_UUID_eq(&NQ_uuid_error, &tuple->id));
  NQ_Tuple_cleanup(tuple);
  return 0;
}
NQ_Transaction_Step_Type NQ_Tuple_create_transaction = {
  .callbacks = {
    (NQ_Transaction_Callback)NQ_Tuple_create_commit, 
    (NQ_Transaction_Callback)NQ_Tuple_create_abort,
    NULL
  }
};
NQ_Tuple NQ_Local_Tuple_create(NQ_Transaction transaction, NQ_Principal *actor){
  NQ_Tuple_Real *tuple = malloc(sizeof(NQ_Tuple_Real));
  NQ_Tuple ret;
  bzero(tuple, sizeof(NQ_Tuple_Real));
  
  NQ_UUID_clr(&tuple->delete_trans);
  tuple->attr_names = NQ_AttributeNameSet_new();

  ret = NQ_UUID_alloc_trans(transaction, tuple, NQ_UUID_TUPLE);
  NQ_UUID_cpy(&tuple->id, &ret);
  NQ_Transaction_step(transaction, &NQ_Tuple_create_transaction, tuple, 0);
  //normally we'd register the tuple with the garbage collector here, but the transaction is
  //going to need to be touched repeatedly anyway... If we register it here... things get a little ugly
  //since the abort process is going to try to delete the tuple.  Just delay the registration until after
  //the transaction commits.
  
  return ret;
}
NQ_Tuple NQ_Tuple_create(NQ_Transaction transaction, NQ_Host home, NQ_Principal *actor){
  NQ_stat.client.create_tuple++;
  return NQ_Net_Tuple_create(transaction, home, actor);
}
////////////////
int NQ_Tuple_delete_commit(NQ_Transaction transaction, NQ_Tuple_Real *tuple, int revision){
  NQ_Tuple_cleanup(tuple);
  return 0;
}
int NQ_Tuple_delete_abort(NQ_Transaction transaction, NQ_Tuple_Real *tuple, int revision){
  NQ_UUID_clr(&tuple->delete_trans);
  return 0;
}
NQ_Transaction_Step_Type NQ_Tuple_delete_transaction = {
  .callbacks = {
    (NQ_Transaction_Callback)NQ_Tuple_delete_commit, 
    (NQ_Transaction_Callback)NQ_Tuple_delete_abort,
    NULL
  }
};
int NQ_Local_Tuple_delete(NQ_Transaction transaction, NQ_Principal *actor, NQ_Tuple a){
  NQ_Tuple_Real *r = NQ_UUID_lookup(a);
  if(r == NULL) return -1;
  
  if(!NQ_UUID_eq(&NQ_uuid_error, &r->delete_trans)){
    if(!NQ_Transaction_subseteq(r->delete_trans, transaction)){
      return -1;
    } else {
      return 0; //soon as this transaction completes, this guy goes boom anyway.
    }
  }
  
  NQ_UUID_cpy(&r->delete_trans, &transaction);
  NQ_Transaction_step(transaction, &NQ_Tuple_delete_transaction, r, 0);
  return 0;
}
int NQ_Local_Tuple_check_valid(NQ_Transaction transaction, NQ_Tuple *tuple) {
  NQ_Tuple_Real *r;
  r = NQ_UUID_lookup(*tuple);
  return(r != NULL && !NQ_UUID_eq(&r->delete_trans, &transaction) &&
         !(!NQ_UUID_eq(&NQ_uuid_error, &r->delete_trans) &&
           NQ_Transaction_subseteq(r->delete_trans, transaction)));
}
int NQ_Tuple_delete(NQ_Transaction transaction, NQ_Principal *actor, NQ_Tuple a){
  return NQ_Net_Tuple_delete(transaction, actor, a);
}
////////////////
int NQ_Tuple_equals(NQ_Tuple a, NQ_Tuple b){
  return NQ_UUID_eq(&a, &b);
}

int NQ_Tuple_find_attribute(NQ_Tuple_Entry *entry, NQ_Attribute_Name *name){
  return NQ_Attribute_Name_eq(name, name);
}

int NQ_Local_Tuple_add_attribute(NQ_Transaction transaction, NQ_Tuple tuple, NQ_Attribute_Name *name){
  NQ_Tuple_Real *r;
  
  r = NQ_UUID_lookup(tuple);
  
  if(!r) return -1;

  switch(NQ_AttributeNameSet_contains(r->attr_names, name)) {
  case 0: {
    NQ_AttributeNameSet_insert(r->attr_names, name);
    int rv = NQ_Tuple_Attribute_Value_new(transaction, tuple, name);
    if(rv == 0) {
      NQ_AttributeNameSet_set(r->attr_names, name, 2);
    } else {
      NQ_AttributeNameSet_erase(r->attr_names, name);
    }
    return rv;
  }
  case 1:
    // in the middle of insertion (this function is called from attr add code
    return 0;
  case 2:
    // already inserted
    printf("attr already exists!\n");
    return -1;
  default:
    assert(0);
    return -1;
  }
}
int NQ_Tuple_add_attribute(NQ_Transaction transaction, NQ_Tuple tuple, NQ_Attribute_Name *name){
  //Safe to go direct to local.  It doesn't block.
  if(NQ_Net_is_local(tuple.home)){
    return NQ_Local_Tuple_add_attribute(transaction, tuple, name);
  }
  return NQ_Net_Tuple_add_attribute(transaction, tuple, name);
}

int NQ_Local_Tuple_remove_attribute(NQ_Transaction transaction, NQ_Tuple tuple, NQ_Attribute_Name *name){
  NQ_Tuple_Real *r;
  
  r = NQ_UUID_lookup(tuple);
  
  if(!r) return -1;
  
  if(!NQ_AttributeNameSet_contains(r->attr_names, name)) {
    printf("could not find attr to delete\n");
    return -1;
  }
  NQ_AttributeNameSet_erase(r->attr_names, name);
  NQ_Tuple_Attribute_Value_del(tuple, name);
  return 0;
}
int NQ_Tuple_remove_attribute(NQ_Transaction transaction, NQ_Tuple tuple, NQ_Attribute_Name *name){
  return NQ_Net_Tuple_remove_attribute(transaction, tuple, name);
}

int NQ_Tuple_print_one(NQ_Tuple_Real *tuple, NQ_Transaction *transaction){
  printf("Tuple[");print_hex((unsigned char *)tuple->id.id, sizeof(tuple->id.id));printf("]");
  printf("\n");
  return 0;
}

void NQ_Tuple_print_all(NQ_Transaction transaction){
  NQ_UUID_each(transaction, NQ_UUID_TUPLE, (PFany)&NQ_Tuple_print_one, &transaction);
}

void NQ_Stat_print(NQ_Stat *stat) {
  printf("Client-side create_tuple: %d\n", stat->client.create_tuple);
  printf("Client-side attr_op: %d\n", stat->client.attr_op);
  printf("Server-side create_tuple: %d\n", stat->server.create_tuple);
  printf("Server-side attr_op: %d\n", stat->server.attr_op);
  printf("UUID_eq: %d yes, %d no\n", stat->uuid_eq_yes, stat->uuid_eq_no);
  printf("Transaction Stats: %d fast, %d normal\n", stat->fast_commit, stat->normal_commit);
  printf("Tx rpcs %d, Rx rpcs %d, Tx byte count %d, Rx byte count %d\n",
         stat->tx_rpc_count, stat->rx_rpc_count, stat->tx_byte_count, stat->rx_byte_count);

  printf("Tx remote rpcs %d, %d\n", stat->tx_remote_rpc_count, stat->rx_remote_rpc_count);

  printf("vsize = %lld\n\n", ProcStat_get_vsize(getpid()));
}

void NQ_dump_stats(void) {
  NQ_Stat_print(&NQ_stat);

  printf("Socket contention stats: read=%d write=%d\n", socket_stats.read_contended, socket_stats.write_contended);
  printf("Socket corked=%d uncorked=%d\n", socket_stats.corked, socket_stats.uncorked);
  printf("Trigger Stats: %d created, %d erased\n", trigger_stats.create, trigger_stats.erase);
}

void NQ_clear_stats(void) {
  memset(&NQ_stat, 0, sizeof(NQ_stat));
}

void NQ_nexus_init(void) {
  printf("Nexus compile, changing to /nfs/topo\n");
  if(chdir("/nfs/topo") != 0) {
    printf(" Could not open /nfs/topo!\n");
    exit(-1);
  }
}

struct AttributeContext {
  NQ_RingBuffer *output;
};

static void output_name(void *_ctx, const NQ_Attribute_Name *name) {
  struct AttributeContext *ctx = _ctx;
  NQ_Request_pickle_attribute_name(ctx->output, (NQ_Attribute_Name*)name);
}

int NQ_Local_Enumerate_Attributes(NQ_Tuple tuple, NQ_RingBuffer *output) {
  NQ_Tuple_Real *t = NQ_UUID_lookup(tuple);
  if(t == NULL) {
    fprintf(stderr, "Enumerate_Attributes(): Could not find tuple\n");
    return -1;
  }
  struct AttributeContext ctx = {
    .output = output,
  };
  int num_attrs = NQ_AttributeNameSet_size(t->attr_names);
  NQ_Request_pickle_int(output, num_attrs);
  NQ_AttributeNameSet_iterate(t->attr_names, output_name, &ctx);
  return 0;
}

int NQ_getenv_server(NQ_Host *h) {
  char *server = getenv("NQSERVER");
  if(server == NULL) {
    return -1;
  }
  char *sep = strchr(server, ':');
  if(sep == NULL) {
    return -1;
  }
  char *host = server;
  char *port = sep + 1;
  *sep = '\0';
  h->addr = inet_addr(host);
  h->port = atoi(port);
  return 0;
}

static pthread_t stats_thread;

void sync_to_second(void) {
  double curr_time = doubleTime();
  unsigned int usecs = 1e6 * (((long long) curr_time + 1) - curr_time);
  usleep(usecs);
}

static void *stats_thread_loop(void* ctx) {
  while(1) {
    double curr_time = doubleTime();
    printf("%lf: Stats Thread\n", curr_time);
    NQ_dump_stats();
    fflush(stdout);
    sync_to_second();
  }
  return NULL;
}

void NQ_enable_periodic_stats(void) {
  pthread_create(&stats_thread, NULL, stats_thread_loop, NULL);
}
