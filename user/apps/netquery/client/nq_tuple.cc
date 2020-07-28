#include <typeinfo>
#include <ext/hash_fun.h>
#include <map>
#include <set>
#include <iostream>
#include <string>
#include <vector>
#include <iomanip>

#include <nq/netquery.h>
#include <nq/tuple.hh>
#include <nq/util.hh>
#include <nq/attribute.h>

using namespace std;

namespace NQ_DefaultValues {
  FixedBuffer empty_buffer(NULL, 0);
  std::string empty_string("");
  int32_t zero = 0;
  uint32_t uzero = 0;
  uint16_t uzero16 = 0;
  std::vector<unsigned char> empty_blob;
  Principal null_principal;
}

////////////////
// C++ definitions for C tspace interface
////////////////

template<> NQ_Attribute_Type tspace_get_attribute_type<int32_t>() {
  return NQ_ATTRIBUTE_RAW;
}

template<> NQ_Attribute_Type tspace_get_attribute_type<uint32_t>() {
  return NQ_ATTRIBUTE_RAW;
}

template<> NQ_Attribute_Type tspace_get_attribute_type<uint16_t>() {
  return NQ_ATTRIBUTE_RAW;
}

template<> NQ_Attribute_Type tspace_get_attribute_type<string>() {
  return NQ_ATTRIBUTE_RAW;
}


template<> NQ_Attribute_Type tspace_get_attribute_type<NQ_UUID>(void) {
  return NQ_ATTRIBUTE_RAW;
}

template<> NQ_Attribute_Type tspace_get_attribute_type<vector<unsigned char> >() {
  return NQ_ATTRIBUTE_RAW;
}


template<> NQ_Attribute_Type tspace_get_attribute_type<Principal>() {
  return NQ_ATTRIBUTE_RAW;
}

////////////////
// T_Tuple
////////////////

void T_Tuple_print(struct T_Tuple *t) {
  NQ_UUID_print(&t->tid);
}

#if 0
void T_Tuple::tspace_delete(void) throw(NQ_Access_Exception) {
}
#endif

void T_Tuple::add_attribute(const string &name, T_Attribute *new_attr) {
  if(name != new_attr->name->name) {
    cerr << "Warning: added an attribute with a non-matching name\n";
  }
  if(attribute_map.find(name) != attribute_map.end()) {
    cerr << "Warning: attribute with name " << name << " already in attribute map\n";
  }
  attribute_map[name] = new_attr;
}

void T_Tuple::tspace_create_generic(const string &class_name) throw(NQ_Access_Exception) {
  assert(!is_created);
  tid = transaction.create_tuple();
  is_created = true; // set to true here since the do_operation() calls from creating attributes will check that tuple is already created
  // cerr << "created " << tid << "\n";
  for(AttributeMap::iterator iter = attribute_map.begin(); 
      iter != attribute_map.end(); iter++) {
    (iter->second)->tspace_create();
  }
  class_type = class_name;
  transaction.set_tuple_shadow(this);
}

string T_Tuple::as_abbrv_str(void) {
  std::stringstream msg_buf;
  msg_buf <<  typeid(this).name() << " tid= " << tid;
  return msg_buf.str();
}

std::ostream &operator<<(std::ostream &os, const T_Tuple &tuple) {
  os << "<" << typeid(tuple).name() << " tid= " << tuple.tid << " ";

  for(T_Tuple::AttributeMap::const_iterator iter = tuple.attribute_map.begin(); 
      iter != tuple.attribute_map.end(); iter++) {
    os << iter->first << ": " << iter->second->as_str() << " ; \n";
  }
  os << ">";
  return os;
}

Transaction &get_transaction(T_Tuple *t) {
  return t->transaction;
}

////////////////
// T_GenericTuple
////////////////

void T_GenericTuple::tspace_create(void)
  throw(NQ_Access_Exception) {
  assert(0);
}

////////////////
// KnownClass
////////////////

__gnu_cxx::hash_map<const string, KnownClass *> KnownClass::map;

////////////////
// Attribute statistics
////////////////

struct TypeCount;
struct AttributeStats;
ostream &operator<<(ostream &os, const TypeCount &c);
ostream &operator<<(ostream &os, const AttributeStats &c);

struct TypeCount : public std::map<int, int> {
  inline void inc(int type) {
    if(find(type) == end()) {
      (*this)[type] = 0;
    }
    (*this)[type]++;
  }
  inline int count(int type) const {
    if(find(type) == end()) {
      return 0;
    }
    return find(type)->second;
  }
};

struct AttributeStats {
  TypeCount _new;
  TypeCount load;
  TypeCount store;
  TypeCount vec_load;
  TypeCount vec_store;
  TypeCount count;
  TypeCount num_elems;
  TypeCount other;

  TypeCount repeated_load;
  TypeCount repeated_num_elems;

  AttributeStats()  { }
  inline void record_new(int type) {
    _new.inc(type);
  }

  inline void record_load(int type) {
    load.inc(type);
  }
  inline void record_store(int type) {
    store.inc(type);
  }

  inline void record_vec_load(int type) {
    vec_load.inc(type);
  }
  inline void record_vec_store(int type) {
    vec_store.inc(type);
  }

  inline void record_count(int type) {
    count.inc(type);
  }

  inline void record_num_elems(int type) {
    num_elems.inc(type);
  }

  inline void record_other(int type) {
    other.inc(type);
  }

  inline void record_repeated_load(int type) {
    repeated_load.inc(type);
  }

  inline void record_repeated_num_elems(int type) {
    repeated_num_elems.inc(type);
  }
};

struct Spec {
  string name;
  const TypeCount *c;
  Spec(const string &name, const TypeCount *c) : name(name), c(c) { }
};

ostream &operator<<(ostream &os, const AttributeStats &c) {
  typedef set<int> IntSet;
  IntSet types;
  vector<Spec> specs;
  int total = 0;
#define S(N) specs.push_back(Spec(#N, &c.N))
  S(_new);
  S(load);
  S(store);
  S(vec_load);
  S(vec_store);
  S(count);
  S(num_elems);
  S(other);

  S(repeated_load);
  S(repeated_num_elems);
#undef S
  for(size_t i=0; i < specs.size(); i++) {
    for(TypeCount::const_iterator j = specs[i].c->begin();
	j != specs[i].c->end(); j++) {
      types.insert(j->first);
    }
  }
  for(IntSet::iterator j = types.begin(); j != types.end(); j++) {
    os << "Type(" << *j << "):\n";
    for(size_t i=0; i < specs.size(); i++) {
      int count = specs[i].c->count(*j);
      os << "\t" << specs[i].name << ": " << count << "\n";
      total += count;
    }
  }
  cerr << "Total is " << total << "\n";
  return os;
}

AttributeStats attr_stats;

void clear_attr_stats(void) {
  attr_stats = AttributeStats();
}

void dump_attr_stats(void) {
  cout << "Attribute stats: \n";
  cout << attr_stats << "\n";
}

////////////////
// T_Attribute
////////////////

/*
int NQ_Attribute_operate(
  NQ_Transaction transaction,
  NQ_Attribute_Name *name, NQ_Tuple tuple,
  NQ_Attribute_Operation op,
  char **iobuffer, int *iolength);
*/

T_Attribute::T_Attribute(T_Tuple *container, const string &str_name, NQ_Attribute_Type type, bool do_add) :
  container(container),
  name(NQ_Attribute_Name_alloc(&container->tid.home, type, str_name.c_str())),
  already_load(false), already_num_elems(false) {
  if(do_add) {
    container->add_attribute(str_name, this);
  }
  attr_stats.record_new(type);
}

T_Attribute::T_Attribute(T_Tuple *container, const NQ_Attribute_Name *name) :
  container(container), name(NQ_Attribute_Name_dup(name)),
  already_load(false), already_num_elems(false) {
  // Only str_name version currently supported
  assert(0);
  attr_stats.record_new(name->type);
}

int T_Attribute::do_operation(const NQ_Attribute_Operation &opcode, unsigned char **iobuffer, int *len, NQ_Principal **output_attributed_to) {
  assert(container->is_created);
  assert(container->tid != NQ_uuid_null);
  switch(opcode) {
  case NQ_OPERATION_LOAD_NTH:
    attr_stats.record_vec_load(name->type);
    break;
  case NQ_OPERATION_STORE_NTH:
    attr_stats.record_vec_store(name->type);
    break;
  case NQ_OPERATION_READ:
    attr_stats.record_load(name->type);
    if(already_load) {
      attr_stats.record_repeated_load(name->type);
    }
    already_load = true;
    break;
  case NQ_OPERATION_WRITE:
    attr_stats.record_store(name->type);
    break;
  case NQ_OPERATION_COUNT:
    attr_stats.record_count(name->type);
    break;
  case NQ_OPERATION_NUM_ELEMS:
    attr_stats.record_num_elems(name->type);
    if(already_num_elems) {
      attr_stats.record_repeated_num_elems(name->type);
    }
    already_num_elems = true;
    break;
  default:
    attr_stats.record_other(name->type);
    break;
  }
  return 
    container->transaction.attribute_operate(name, container->tid, opcode, (char **)iobuffer, len, output_attributed_to);
}

void T_Attribute::tspace_create_helper(void) {
  // No-op, since attributes are implicitly created on the first "write" operation
}

void T_Attribute::clear_global_stats(void) {
  unsigned char *buffer = NULL;
  int buffer_len = 0;
  do_operation(NQ_OPERATION_CLEAR_GLOBAL_STATS, &buffer, &buffer_len, NULL);
}
void T_Attribute::get_global_stats(NQ_Stat *stats) {
  // XXX probably could have passed arg directly down
  memset(stats, 0, sizeof(NQ_Stat));
  int len = 0;
  unsigned char *buf = NULL;
  do_operation(NQ_OPERATION_GET_GLOBAL_STATS, &buf, &len, NULL);
  if(buf != NULL) {
    memcpy(stats, buf, sizeof(NQ_Stat));
  }
}

void NQ_cpp_lib_init(void) {
  static bool initialized;
  if(initialized) {
    cerr << "called cpp initialization again!\n";
    return;
  }
  initialized = true;

  NQ_transaction_init();
  NQ_net_elements_init();
  NQ_site_init();
  cerr << "Warning: should initialize T_Class::self and T_Class::uuid\n";
}

std::ostream &operator<<(std::ostream &os, const Principal &p) {
  os << "[PRINCIPAL]";
  return os;
}
