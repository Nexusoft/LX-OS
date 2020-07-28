#ifndef NETQUERY_H_SHIELD
#define NETQUERY_H_SHIELD

#ifdef __cplusplus
extern "C" {
#endif

// uninterpreted data   unsigned char *
// opaque pointer       void *
// string               char *
// return values
//    0       = success
//    -ERRNO  = error

#include <openssl/ssl.h>

#include <nq/queue.h>
#include <nq/uuid.h>

typedef NQ_UUID NQ_Tuple;

#define NQ_NET_DEFAULT_PORT 3359

#include <nq/transaction.h>
#include <nq/attribute.h> //also includes triggers

#include <netinet/in.h>

void NQ_init(unsigned int my_ip, unsigned short port);
void NQ_cleanup(void);
void NQ_nexus_init(void);
void NQ_Show_RPCs(void);

NQ_Tuple NQ_Tuple_create(NQ_Transaction transaction, NQ_Host home, NQ_Principal *actor);
NQ_Tuple NQ_Local_Tuple_create(NQ_Transaction transaction, NQ_Principal *actor);
int NQ_Tuple_delete(NQ_Transaction transaction, NQ_Principal *actor, NQ_Tuple a);
int NQ_Local_Tuple_delete(NQ_Transaction transaction, NQ_Principal *actor, NQ_Tuple a);
  int NQ_Local_Tuple_check_valid(NQ_Transaction transaction, NQ_Tuple *tuple);

//these should only be called internally.  Use NQ_Attribute_Operate instead.
int NQ_Local_Tuple_add_attribute(NQ_Transaction transaction, NQ_Tuple tuple, NQ_Attribute_Name *name);
int NQ_Tuple_add_attribute(NQ_Transaction transaction, NQ_Tuple tuple, NQ_Attribute_Name *name);
int NQ_Local_Tuple_remove_attribute(NQ_Transaction transaction, NQ_Tuple tuple, NQ_Attribute_Name *name);
int NQ_Tuple_remove_attribute(NQ_Transaction transaction, NQ_Tuple tuple, NQ_Attribute_Name *name);

  // low level api between tuple deletion and attribute deletion
  // this is a hack; gave up on making this transaction-safe, since we're getting rid of that
  int NQ_Tuple_Attribute_Value_new(NQ_Transaction transaction, NQ_Tuple tuple, NQ_Attribute_Name *name);
void NQ_Tuple_Attribute_Value_del(NQ_Tuple tuple, NQ_Attribute_Name *name);

int NQ_Tuple_equals(NQ_Tuple a, NQ_Tuple b);
void NQ_Tuple_print_all(NQ_Transaction transaction);

NQ_Principal *NQ_get_home_principal(NQ_Host *home);
void NQ_publish_home_principal();
void NQ_publish_principal(NQ_Principal *p, const char *filename);
NQ_Principal *NQ_load_principal(const char *fname);

struct NQ_UUID_Table;
typedef struct NQ_UUID_Table NQ_UUID_Table;
NQ_UUID_Table *NQ_UUID_Table_new(void);
void NQ_UUID_Table_destroy(NQ_UUID_Table *table);

int NQ_UUID_Table_size(NQ_UUID_Table *table);

void *NQ_UUID_Table_find(NQ_UUID_Table *table, NQ_UUID *uuid);
void NQ_UUID_Table_insert(NQ_UUID_Table *table, NQ_UUID *uuid, void *val);
void NQ_UUID_Table_delete(NQ_UUID_Table *table, NQ_UUID *uuid);
void NQ_UUID_Table_each(NQ_UUID_Table *table, NQ_Transaction transaction,
      NQ_UUID_Type type, PFany iterator, void *userdata);

NQ_Principal *NQ_Principal_add(NQ_Principal *p);
NQ_Principal *NQ_Principal_find(unsigned char *hash, int len);
char *NQ_Principal_hash_filename(NQ_Principal *principal);

  struct UUIDSet;
  typedef struct UUIDSet UUIDSet;
  UUIDSet *UUIDSet_new(void);
  int UUIDSet_contains(UUIDSet *set, const NQ_UUID *p);
  void UUIDSet_insert(UUIDSet *set, const NQ_UUID *p);
  void UUIDSet_erase(UUIDSet *set, const NQ_UUID *p);
  // void UUIDSet_iterate(UUIDSet *set, void (*fn)(const NQ_UUID *p));
  void UUIDSet_destroy(UUIDSet *set);

  struct NQ_TriggerSet;
  typedef struct NQ_TriggerSet NQ_TriggerSet;
  NQ_TriggerSet *NQ_TriggerSet_new();
  void NQ_TriggerSet_match_and_fire(NQ_TriggerSet *u_set, const NQ_Transaction *transaction, const NQ_Tuple *tuple, NQ_Trigger_Type type);
  void NQ_TriggerSet_insert(NQ_TriggerSet *u_set, NQ_Attribute_Trigger *trigger);
  void NQ_TriggerSet_erase(NQ_TriggerSet *u_set, NQ_Attribute_Trigger *trigger);
  void NQ_TriggerSet_destroy(NQ_TriggerSet *u_set);
  void NQ_TriggerSet_iterate(NQ_TriggerSet *set, void (*fn)(NQ_Tuple tid, NQ_UUID_Table *value, void *ctx), void *ctx);

  struct NQ_Attribute_Name_Set;
  typedef struct NQ_Attribute_Name_Set NQ_Attribute_Name_Set;
  NQ_Attribute_Name_Set *NQ_AttributeNameSet_new(void);
  // names are all copies in set
  void NQ_AttributeNameSet_insert(NQ_Attribute_Name_Set *, const NQ_Attribute_Name *);
  void NQ_AttributeNameSet_set(NQ_Attribute_Name_Set *set, const NQ_Attribute_Name *name, int value);
  void NQ_AttributeNameSet_erase(NQ_Attribute_Name_Set *, const NQ_Attribute_Name *);
  int NQ_AttributeNameSet_contains(NQ_Attribute_Name_Set *, const NQ_Attribute_Name *);
  void NQ_AttributeNameSet_iterate(NQ_Attribute_Name_Set *, void (*)(void *ctx, const NQ_Attribute_Name *), void *ctx);
  void NQ_AttributeNameSet_destroy(NQ_Attribute_Name_Set *);
  int NQ_AttributeNameSet_size(NQ_Attribute_Name_Set *);

typedef struct NQ_Stat {
  struct {
    int create_tuple;
    int attr_op;
  } client;

  struct {
    int create_tuple;
    int attr_op;
  } server;

  int uuid_eq_yes, uuid_eq_no;
  int fast_commit, normal_commit;

  int tx_rpc_count;
  int rx_rpc_count;
  int tx_byte_count;
  int rx_byte_count;

  int tx_remote_rpc_count;
  int rx_remote_rpc_count;
} NQ_Stat;
extern NQ_Stat NQ_stat;

extern int show_rpc_traffic;
uint64_t ProcStat_get_vsize(int pid);

void NQ_Stat_print(NQ_Stat *stat);
void NQ_dump_stats(void);
void NQ_clear_stats(void);
void NQ_print_sem_stats(void);
void NQ_enable_periodic_stats(void);
void sync_to_second(void);

double doubleTime(void);
double smallDoubleTime(void);

void dump_memtrace(const char *fname);
void stackdump_stderr(void);

int parse_addr_spec(const char *str, struct sockaddr_in *output);

int NQ_getenv_server(NQ_Host *h);

#ifdef __cplusplus
}

static inline void NQ_init(unsigned short port){ NQ_init(0, port); }
static inline void NQ_init(){ NQ_init(0, NQ_NET_DEFAULT_PORT); }

// Use garbage collector
// #define USE_GC

#ifdef USE_GC
#include <gc/gc_allocator.h>
#include <gc/gc_cpp.h>
#include <gc/gc.h>
#else
class gc {
};
#endif

#include <string>
#include <iostream>
#include <vector>
#include <stdint.h>
// ext/hash_fun.h is not compatible with gcc 3.2 libstdc++
//#include <ext/hash_fun.h>

#include <ext/hash_map>

#include <nq/util.hh>

void NQ_cpp_lib_init(void);
void NQ_transaction_init(void);
void NQ_net_elements_init(void);
void NQ_site_init(void);

std::ostream &operator<<(std::ostream &os, const NQ_Transaction &t);
std::ostream &operator<<(std::ostream &os, const NQ_UUID &e);
std::ostream &operator<<(std::ostream &os, const NQ_Attribute_Name &name);
std::ostream &operator<<(std::ostream &os, const NQ_Host &h);

template<class T> NQ_Attribute_Type tspace_get_attribute_type(void);

namespace __gnu_cxx {
  template<> struct hash<const NQ_UUID>
  {
    size_t operator()(const NQ_UUID & t) const {
      NQ_UUID l;
      memset(&l, 0, sizeof(l));
      l.home = t.home;
      memcpy(l.id, t.id, sizeof(l.id));
      l.type = t.type;
      return (size_t)SuperFastHash((const char *)&l, sizeof(l));
    }
  };

  template<> struct hash<const std::string>
  {
    size_t operator()(const std::string & s) const {
      return (size_t)SuperFastHash( s.c_str(), strlen(s.c_str()) );
    }
  };
};

static inline bool operator==(const NQ_Tuple &l, const NQ_Tuple &r) {
  return NQ_Tuple_equals(l, r);
}

static inline bool operator!=(const NQ_Tuple &l, const NQ_Tuple &r) {
  return !(l == r);
}

/* XXX This is almost exact copy of the other UUID hash function, except for ignoring the type field. Rename */
struct NQ_UUID_hash {
  inline size_t operator()(NQ_UUID t) const  {
    NQ_UUID l;
    memset(&l, 0, sizeof(l));
    l.home = t.home;
    memcpy(l.id, t.id, sizeof(l.id));
    // ignore type field
    l.type = NQ_UUID_TRANSACTION;
    return (size_t)SuperFastHash((const char *)&l, sizeof(l));
  }
};

struct NQ_UUID_equals {
  inline bool operator()(NQ_UUID l, NQ_UUID r) const {
    // Ignore type
    l.type = r.type;
    return l == r;
  }
};

static inline bool operator<(const NQ_Tuple &l, const NQ_Tuple &r) {
  /*
    NQ_Host home;
    char id[UUIDBITS];
    NQ_UUID_Type type;
  */
  return (l.home.addr < r.home.addr) ||
    (l.home.addr == r.home.addr && 
     (l.home.port < r.home.port || 
      (l.home.port == r.home.port && 
       (memcmp(l.id, r.id, sizeof(r.id)) < 0 ||
	(memcmp(l.id, r.id, sizeof(r.id)) == 0 && l.type < r.type)))));
}

std::string NQ_Host_as_string(const NQ_Host &h);

struct NQ_Host_hash {
  inline size_t operator()(const NQ_Host &h) const {
    const std::string host_str = NQ_Host_as_string(h);
    const char *str = host_str.c_str();
    return (size_t)SuperFastHash(str, strlen(str));
  }
};

struct NQ_Host_equals {
  inline bool operator()(const NQ_Host &l, const NQ_Host &r) const {
    return NQ_Host_eq(l,r);
  }
};

struct NQ_Attribute_Name_C {
  NQ_Attribute_Name *name;
  NQ_Attribute_Name_C(const NQ_Attribute_Name *src) {
    name = NQ_Attribute_Name_dup(src);
  }
  NQ_Attribute_Name_C(const NQ_Attribute_Name_C &src) {
    name = NQ_Attribute_Name_dup(src.name);
  }
  ~NQ_Attribute_Name_C() {
    NQ_Attribute_Name_free(name);
  }
};

struct NQ_Attribute_Name_C_hash {
  inline size_t operator()(const NQ_Attribute_Name_C &name) const  {
    size_t val = NQ_Attribute_Name_hash((void *)name.name);
    // printf("<HASH = %x>\n", val);
    return val;
  }
};

struct NQ_Attribute_Name_C_equals {
  inline bool operator()(const NQ_Attribute_Name_C &l, const NQ_Attribute_Name_C &r) const {
    // printf("<EQ>\n");
    return NQ_Attribute_Name_eq((NQ_Attribute_Name *)l.name, (NQ_Attribute_Name *)r.name);
  }
};

struct Transaction;

struct Principal {
  NQ_Host home;
  NQ_Principal_Key key;
  Principal() {
    home.addr = 0;
    home.port = 0;
    key.hash_len = 0;
    memset(key.hash, 0, sizeof(key.hash));
  }

  static void tspace_marshall(const Principal &p, std::vector<unsigned char> &buf);
  static Principal *tspace_unmarshall(Transaction &transaction,
				      CharVector_Iterator &curr,
				      const CharVector_Iterator &end);
  operator NQ_Principal*();
};

std::ostream &operator<<(std::ostream &os, const Principal &p);
std::ostream &operator<<(std::ostream &os, const NQ_Principal &p);

#include <ext/hash_set>

namespace NQ_Output {
  using namespace __gnu_cxx;

  // NQ_Attribute_Name_eq(NQ_Attribute_Name *a, NQ_Attribute_Name *b)
  inline void make_canonical(const NQ_Trigger_Desc_and_Dest &d, NQ_Trigger_Description *h) {
    memset(h, 0, sizeof(*h));
    h->type = d.desc->type;
    h->upcall_type = d.desc->upcall_type;
  }

  struct NQ_Trigger_Desc_and_Dest_hash {
    inline size_t operator()(const NQ_Trigger_Desc_and_Dest & d) const {
      NQ_Trigger_Description h;
      make_canonical(d, &h);
      
      hash<const NQ_UUID> tuple_hash;
      NQ_Attribute_Name_C_hash name_hash;

      return (size_t)SuperFastHash((const char *)&h, sizeof(h)) ^ 
	(d.desc->name != NULL ? name_hash(NQ_Attribute_Name_C(d.desc->name)) : 0) ^
	tuple_hash((const NQ_UUID &)d.cb_id);
      
    }
  };

  struct NQ_Trigger_Desc_and_Dest_equals {
    inline bool operator()(const NQ_Trigger_Desc_and_Dest &l, const NQ_Trigger_Desc_and_Dest &r) const {
      NQ_Trigger_Description l_h, r_h;
      make_canonical(l, &l_h);
      make_canonical(r, &r_h);

      NQ_Attribute_Name_C_equals name_equals;

      return memcmp(&l_h, &r_h, sizeof(l_h)) == 0 &&
	name_equals(l.desc->name, r.desc->name) &&
	l.cb_id == r.cb_id;
    }
  };

  struct NQ_Trigger_Description_Set : 
  hash_set<NQ_Trigger_Desc_and_Dest, NQ_Trigger_Desc_and_Dest_hash, NQ_Trigger_Desc_and_Dest_equals > {
    inline struct NQ_Trigger_Description_Set match(NQ_Attribute_Name *name) {
      struct NQ_Trigger_Description_Set filtered;
      for(NQ_Trigger_Description_Set::iterator i = begin();
	  i != end(); i++) {
	NQ_Attribute_Name_C_equals name_equals;
	if( name_equals(NQ_Attribute_Name_C((*i).desc->name), 
			NQ_Attribute_Name_C(name)) ) {
	  filtered.insert(*i);
	}
      }
      return filtered;
    }
  };

  struct OutputContext {
    NQ_Host home;
    struct TupleAlias {
      NQ_Tuple tuple;
      std::string name;
      TupleAlias() : tuple(NQ_uuid_null), name("(uninit)") { }
      TupleAlias(const NQ_Tuple &t, const std::string &n) : tuple(t), name(n) { }
    };
    std::vector<TupleAlias> tuple_aliases;

    hash_map<NQ_Tuple, NQ_Trigger_Description_Set, __gnu_cxx::hash<const NQ_UUID> > all_tuple_triggers;

    void add_tid_alias(const NQ_Tuple &tid, const std::string &name);

    std::string default_alias;
    bool show_speaker;
    bool show_tid;
    bool show_type;
    bool show_triggers;
    enum ParseType {
      ENUMERATE_ATTRIBUTES,
      REFLECTION,
    } parse_type;
    OutputContext(NQ_Host _home, const std::string &_default_alias = std::string("(remote)"), ParseType _type = ENUMERATE_ATTRIBUTES) : home(_home), default_alias(_default_alias), show_speaker(false), show_tid(false), show_type(false), show_triggers(false), parse_type(_type) {
    }

    void output_trigger(std::ostream &os, const NQ_Trigger_Desc_and_Dest &desc, bool show_tuple_name, bool show_attr_name);
    void output_tuple(std::ostream &os, NQ_Transaction transaction, NQ_Tuple TID);
    private:
    std::string tid_to_alias(NQ_Tuple tid);
  };
}

#endif

#endif
