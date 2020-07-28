#ifndef _NQ_ATTRIBUTE_HH_
#define  _NQ_ATTRIBUTE_HH_

#include <nq/netquery.h>
#include <nq/attribute.h>
#include <nq/transaction.hh>
#include <nq/marshall.hh>
#include <iostream>
#include <string>
// The name is constructed based on the owner of the container.

struct T_Tuple;
void T_Tuple_print(struct T_Tuple *t);

Transaction &get_transaction(T_Tuple *t);

void clear_attr_stats(void);
void dump_attr_stats(void);

struct T_Attribute : public gc {
  // container is a * because we sometimes have "anonymous" attributes
  // which are not part of containers
  T_Tuple *container; // need container initialized before name
  NQ_Attribute_Name *name;

  bool already_load, already_num_elems;

  // Most uses of attribute will infer the attribute owner from the
  // NQ_Home of the container
  T_Attribute(T_Tuple *container, const std::string &str_name, NQ_Attribute_Type type, bool do_add = true);
  T_Attribute(T_Tuple *container, const NQ_Attribute_Name *name);

  virtual ~T_Attribute() { }

  // Wrapper around NQ_Attribute_operation
  int do_operation(const NQ_Attribute_Operation &opcode, unsigned char **iobuffer, int *len, NQ_Principal **output_attributed_to);

  // create slot and initialize to default value
  virtual void tspace_create(void) throw(NQ_Access_Exception) = 0;

  // create just the "slot" for the attribute
  void tspace_create_helper(void);

  virtual std::string as_str(void) = 0;

  // XXX This is a hack
  void clear_global_stats(void);
  void get_global_stats(NQ_Stat *stats);

private:
  const T_Attribute &operator=(const T_Attribute &r) {
    // Statically detect any non-overloaded instances of assignment from a T_Attribute. 

    // This syntax is confusing, since it's unclear whether the
    // programmer wants to copy the T_Attribute, or to copy the
    // tuplespace value.

    // The convention is to assume that the tuplespace value is wanted
    assert(0);
  }
  // Same for  operator==
  const bool operator==(const T_Attribute &r) {
    assert(0);
  }
  const bool operator!=(const T_Attribute &r) {
    assert(0);
  }
};

template <class T_value, class T_impl>
struct SmartReference : public gc {
  T_impl *container;

  SmartReference(T_impl &container) : container(&container) { }

  // Could use the template version if we ever want to allow T_impl's
  // to overload assignment
  // template <class T> inline SmartReference &operator=(const T &rval) {
  inline SmartReference operator=(const T_value &rval) 
    throw(NQ_Access_Exception) {
    container->store(rval);
    return *this;
  };

  inline T_value load() 
    throw(NQ_Access_Exception) {
    return container->load();
  }
  // conversion operator to automatically convert to T_value in certain contexts
  inline operator T_value() {
    return load();
  };
#if 0
  // -> operator only makes sense in read-only mode for vector access
  inline const T_value *operator->() {
    return &load();
  }
#endif
};

template <class T, const T &default_creation_val>
struct T_Scalar : T_Attribute {
  // Most uses of attribute will infer the attribute owner from the
  // NQ_Home of the container
  T *cached_value;

  inline T_Scalar(T_Tuple *container, const std::string &str_name, bool do_add = true) :
    T_Attribute(container, str_name, tspace_get_attribute_type<T>(), do_add ),
    cached_value(NULL) { }

  inline T_Scalar(T_Tuple *container, const NQ_Attribute_Name *name) :
    T_Attribute(container, name),
    cached_value(NULL) { }

  virtual ~T_Scalar() { }

  inline void store(const T &val)
    throw(NQ_Access_Exception, NQ_API_Exception)
  {
    std::vector<unsigned char> data;
    tspace_marshall(val, data);
    unsigned char *buf = vector_as_ptr<unsigned char>(data);
    int len = data.size();
    int rv = do_operation(NQ_OPERATION_WRITE, &buf, &len, NULL);
    if(rv < 0) {
      throw NQ_Access_Exception("Could not do scalar store\n");
    }
    if(cached_value == NULL) {
      cached_value = new T(val);
    } else {
      *cached_value = val;
    }
  }

  inline T load(NQ_Principal **output_attributed_to = NULL)
    throw(NQ_Access_Exception, NQ_Schema_Exception)
  {
    if(cached_value != NULL) {
      return *cached_value;
    }
    unsigned char *buf = NULL;
    int len = 0;
    int rv = do_operation(NQ_OPERATION_READ, &buf, &len, output_attributed_to);
    if(rv < 0) {
      throw NQ_Access_Exception("Could not do scalar load\n");
    }
    std::vector<unsigned char> *v = array_as_vector(buf, len);
    free(buf);
    CharVector_Iterator begin = v->begin();
    T *val_p = ::tspace_unmarshall((T*) NULL, get_transaction(container), begin, v->end());
    cached_value = val_p;
    return *cached_value;
  }    

  inline const T_Scalar &operator=(const T &rval) {
    store(rval);
    return *this;
  };

  // Conversion operator
  inline operator T() {
    return load();
  }

  virtual void tspace_create(void) throw(NQ_Access_Exception) {
    tspace_create_helper();
    store(default_creation_val);
  }

  inline virtual std::string as_str(void) {
    std::stringstream msg_buf;
    msg_buf << load();
    return msg_buf.str();
  }
  bool operator==(const T_Scalar<T, default_creation_val> &r) {
    return load() == r.load();
  }
  bool operator!=(const T_Scalar<T, default_creation_val> &r) {
    return !(*this == r);
  }
};

struct FixedBuffer;

namespace NQ_DefaultValues {
  extern FixedBuffer empty_fixed_buffer;
  extern std::string empty_string;
  extern int32_t zero;
  extern uint32_t uzero;
  extern uint16_t uzero16;
  extern std::vector<unsigned char> empty_blob;
  extern Principal null_principal;
}

struct FixedBuffer {
  unsigned char *data;
  int len;
#if 0
  inline FixedBuffer(int len) : 
    data(new unsigned char[len]), len(len) {  }
#endif
  inline FixedBuffer(const unsigned char *init_data, int len) : 
    data(new unsigned char[len]), len(len) {
    memcpy(data, init_data, len);
  }

  static inline 
  FixedBuffer *tspace_unmarshall(Transaction &transaction, CharVector_Iterator &curr, 
				 const CharVector_Iterator &end) 
    throw(NQ_Schema_Exception)
  {
    // Consume full contents
    FixedBuffer *rv = new FixedBuffer(&*curr, &*end - &*curr);
    curr = end;
    return rv;
  }
};

// Reference to generic tuple
typedef T_Scalar<NQ_Tuple, NQ_uuid_null> T_TID;

// Reference to tuple of type T
// Extending T_Scalar<> makes the code very confusing. Instead,
// reimplement what we need (operator= and conversion operator)
template <class T>
struct T_Reference : T_Attribute {
  T_TID *t_tid; // if t_tid == NULL, then this reference is an anonymous value (e.g., from a set)

  T_Reference(T_Tuple *container, const std::string &str_name) :
    T_Attribute(container, str_name, NQ_ATTRIBUTE_RAW),
    t_tid(new T_TID(this->container, str_name, false))
  { }
  T_Reference(T_Tuple *container, const NQ_Attribute_Name *name) :
    T_Attribute(container, name),
    t_tid(new T_TID(this->container, this->name))
  { }

  virtual ~T_Reference() { }

  inline NQ_Tuple get_tid(NQ_Principal **p = NULL) const {
    return t_tid->load(p);
  }

  inline void store(const NQ_Tuple &tid) 
    throw(NQ_Access_Exception, NQ_API_Exception) 
  {
    if(t_tid != NULL) {
      t_tid->store(tid);
    } else {
      throw NQ_API_Exception("Cannot store to anon value reference!\n");
    }
  }

  inline void store(const T *val) 
    throw(NQ_Access_Exception, NQ_API_Exception) 
  {
    store(val->get_tid());
  }
  inline T* load(NQ_Principal **p = NULL) const
    throw(NQ_Access_Exception, NQ_Schema_Exception)
  {
    NQ_Tuple tid = get_tid(p);
    T_Tuple *shadow = get_transaction(this->container).get_tuple_shadow(tid);
    if(shadow == NULL) {
      if(tid != NQ_uuid_null) {
	std::cerr << "tid " << tid << " does not map to any object\n";
      }
      return NULL;
    }
    T *t = dynamic_cast<T*>(shadow);

    if(t == NULL) {
      throw NQ_Schema_Exception("Could not coerce to this type\n");
    }

    return t;
  }

  inline virtual const T_Reference &operator=(T * const &rval) 
    throw(NQ_Access_Exception) {
    store(rval);
    return *this;
  };
  // XXX Could also add operator= for assigning tid

  // Conversion operator
  inline operator T*() {
    return load();
  }

  virtual void tspace_create(void) throw(NQ_Access_Exception) {
    tspace_create_helper();
    store(NQ_uuid_null);
  }

  inline virtual std::string as_str(void) {
    std::stringstream msg_buf;
    msg_buf << "Ref(" << get_tid() << ")";
    return msg_buf.str();
  }
  const T_Reference<T> &operator=(const T_Reference<T> &r) {
    this->store(r.get_tid());
    return *this;
  }

  bool operator==(const T_Reference<T> &r) {
    return load() == r.load();
  }
  bool operator!=(const T_Reference<T> &r) {
    return !(*this == r);
  }
};

template <class T>
struct T_VectorOrTrie : T_Attribute {
  int cached_size;
  inline T_VectorOrTrie(T_Tuple *container, const std::string &str_name, NQ_Attribute_Type type) :
    T_Attribute(container, str_name, type),
    cached_size(-1) { }

  inline T_VectorOrTrie(T_Tuple *container, const NQ_Attribute_Name *name) :
    T_Attribute(container, name),
    cached_size(-1) { }

  inline void push_back(const T &v) {
    (*this)[size()] = v;
  }

  struct VectorContainerContext {
    T_VectorOrTrie &vec;
    int index;

    VectorContainerContext(T_VectorOrTrie &vec, int index) : 
      vec(vec), index(index) { }

    inline void store(const T &val) throw(NQ_Access_Exception) {
      std::vector<unsigned char> data;
      NQ_Store_Nth_Args args;
      args.index = index;

      vector_push(data, args);
      tspace_marshall(val, data);

      unsigned char *d = vector_as_ptr<unsigned char>(data);
      int len = data.size();
      int rv = vec.do_operation(NQ_OPERATION_STORE_NTH, &d, &len, NULL);
      if(rv < 0) {
	throw NQ_Access_Exception("Could not do vector store\n");
      }
      if(vec.cached_size >= 0 && index >= vec.cached_size) {
	// vector resize
	vec.cached_size = index + 1;
      }
    }
    inline T load(NQ_Principal **output_attributed_to = NULL) throw(NQ_Access_Exception) {
      NQ_Load_Nth_Args args;
      args.index = index;
      unsigned char *d = (unsigned char *)&args;
      int len = sizeof(args);
      int err = vec.do_operation(NQ_OPERATION_LOAD_NTH, &d, &len, output_attributed_to);
      if(err < 0) {
	throw NQ_Access_Exception("Could not do vector load\n");
      }
      std::vector<unsigned char> *v = array_as_vector(d, len);
      free(d);
      CharVector_Iterator begin = v->begin();
      return *::tspace_unmarshall((T*) NULL, get_transaction(vec.container), begin, v->end());
    }
  };

  inline SmartReference<T, VectorContainerContext> operator[](int index) {
    VectorContainerContext *ctx = new VectorContainerContext(*this, index);
    return SmartReference<T, VectorContainerContext>(*ctx);
  }
    
  inline void truncate(void) {
    unsigned char *d = NULL;
    int len = 0;
    int rv = do_operation(NQ_OPERATION_TRUNCATE, &d, &len, NULL);
    if(rv < 0) {
      throw NQ_Access_Exception("Could not do vector truncate\n");
    }
  }

  inline size_t size(NQ_Principal **output_attributed_to = NULL) {
    if(cached_size >= 0) {
      return cached_size;
    }
    struct NQ_Num_Elems_Result *res = NULL;
    int len = 0;
    int num_elems;
    unsigned char *_res;
    int rv = do_operation(NQ_OPERATION_NUM_ELEMS, &_res, &len, output_attributed_to);
    if(rv < 0) {
      throw NQ_Access_Exception("Could not do vector size\n");
    }
    res = (NQ_Num_Elems_Result *)_res;

    assert(sizeof(*res) == len);
    num_elems = res->num_elems;
    free(res);
    cached_size = num_elems;
    return num_elems;
  }

  virtual inline void tspace_create(void) throw(NQ_Access_Exception) {
    tspace_create_helper();

    int err;
    NQ_Create_Aggregate_Args args;
    args.element_size = tspace_marshall_size<T>();
    args.initial_capacity = 1;
    unsigned char *d = (unsigned char *)&args;
    int len = sizeof(args);
    err = do_operation(NQ_OPERATION_CREATE_AGGREGATE, &d, &len, NULL);
    if(err != 0) {
      throw NQ_Access_Exception("Could not create vector!\n");
    }
  }

  inline virtual std::string as_str(void) {
    std::stringstream msg_buf;
    size_t i;
    msg_buf << " {[\n";
    for(i=0; i < size(); i++) {
      try {
	T val = (*this)[i];
	msg_buf << "[" << i << "]: " << val;
      } catch(NQ_Access_Exception) {
	msg_buf << "err: undefined?";
      }
      msg_buf << "\n";
    }
    msg_buf << "]}\n";
    return msg_buf.str();
  }
};

template <class T>
struct T_Vector : public T_VectorOrTrie<T> {
  inline T_Vector(T_Tuple *container, const std::string &str_name) :
    T_VectorOrTrie<T>(container, str_name, NQ_ATTRIBUTE_VECTOR) { }

  inline T_Vector(T_Tuple *container, const NQ_Attribute_Name *name) :
    T_VectorOrTrie<T>(container, name) { }
};

template <class T>
struct TrieValue {
  NQ_FakeTrie_Header h;
  T val;
  inline TrieValue() { } // for vectors
  inline TrieValue(uint32_t prefix, int8_t prefix_len, const T &v) : 
    val(v) {
    h.prefix = prefix;
    h.prefix_len = prefix_len;
  }
  static inline 
  TrieValue *tspace_unmarshall(Transaction &transaction, CharVector_Iterator &curr, 
				 const CharVector_Iterator &end) 
    throw(NQ_Schema_Exception) {
    NQ_FakeTrie_Header h = *unmarshall_flat_object<NQ_FakeTrie_Header>(curr, end);
    T v = *::tspace_unmarshall((T*)NULL, transaction, curr, end);
    return new TrieValue(h.prefix, h.prefix_len, v);
  }
};

template <class T>
struct T_Trie : public T_VectorOrTrie<T> {
private:
  inline SmartReference<T, typename T_VectorOrTrie<T>::VectorContainerContext> operator[](int index);
  inline void push_back(const T &v);

public:
  inline T_Trie(T_Tuple *container, const std::string &str_name) :
    T_VectorOrTrie<T>(container, str_name, NQ_ATTRIBUTE_TRIE) { }

  inline T_Trie(T_Tuple *container, const NQ_Attribute_Name *name) :
    T_VectorOrTrie<T>(container, name) { }

  inline TrieValue<T> load(size_t index, NQ_Principal **output_attributed_to = NULL) throw(NQ_Access_Exception) {
    NQ_Load_Nth_Args args;
    args.index = index;
    unsigned char *d = (unsigned char *)&args;
    int len = sizeof(args);
    int err = T_VectorOrTrie<T>::do_operation(NQ_OPERATION_LOAD_NTH, &d, &len, output_attributed_to);
    if(err < 0) {
      throw NQ_Access_Exception("Could not do trie load\n");
    }
    std::vector<unsigned char> *v = array_as_vector(d, len);
    free(d);
    CharVector_Iterator begin = v->begin();
    return *::tspace_unmarshall((TrieValue<T>*) NULL, get_transaction(this->container), begin, v->end());
  }

  inline int lookup(uint32_t ip_prefix, T *output, NQ_Principal **output_attributed_to = NULL) throw(NQ_Access_Exception) {
    NQ_Trie_Index_Args args;
    args.prefix = ip_prefix;
    args.prefix_len = 32;

    unsigned char *d = (unsigned char *)&args;
    int len = sizeof(args);

    int rv = T_VectorOrTrie<T>::do_operation(NQ_OPERATION_LOOKUP, &d, &len, output_attributed_to);
    if(rv < 0) {
      throw NQ_Access_Exception("Could not do trie lookup\n");
    }
    if(len == 0) {
      // std::cerr << "couldn't find anything via trie\n";
      return -1;
    }
    std::vector<unsigned char> *v = array_as_vector(d, len);
    free(d);
    CharVector_Iterator begin = v->begin();
    *output = *::tspace_unmarshall((T*) NULL, get_transaction(this->container), begin, v->end());
    return 0;
  }
  void update(uint32_t ip_prefix, int8_t ip_prefix_len, const T &val, NQ_Principal **output_attributed_to = NULL) throw(NQ_Access_Exception) {
    std::vector<unsigned char> data;
    NQ_Trie_Index_Args args;
    args.prefix = ip_prefix;
    args.prefix_len = ip_prefix_len;
    vector_push(data, args);
    tspace_marshall(val, data);

    unsigned char *buf = vector_as_ptr<unsigned char>(data);
    int len = data.size();
    int rv = T_VectorOrTrie<T>::do_operation(NQ_OPERATION_UPDATE, &buf, &len, output_attributed_to);
    if(rv < 0) {
      throw NQ_Access_Exception("Could not do trie update\n");
    }
  }
  void erase(uint32_t ip_prefix, int8_t ip_prefix_len) throw(NQ_Access_Exception) {
    NQ_Trie_Index_Args args;
    args.prefix = ip_prefix;
    args.prefix_len = ip_prefix_len;

    unsigned char *buf = (unsigned char *)&args;
    int len = sizeof(args);
    int rv = T_VectorOrTrie<T>::do_operation(NQ_OPERATION_REMOVE, &buf, &len, NULL);
    if(rv < 0) {
      throw NQ_Access_Exception("Could not do trie erase\n");
    }
  }

  inline virtual std::string as_str(void) {
    return "<<TRIE>>";
  }

  inline size_t size(void) {
    // size caching is not implemented for FakeTrie
    this->cached_size = -1;
    return T_VectorOrTrie<T>::size();
  }
};

typedef  T_Scalar<int32_t, NQ_DefaultValues::zero > T_int32;
typedef  T_Scalar<uint32_t, NQ_DefaultValues::uzero > T_uint32;
typedef  T_Scalar<uint16_t, NQ_DefaultValues::uzero16 > T_uint16;
// Null-terminated string
typedef T_Scalar<std::string, NQ_DefaultValues::empty_string> T_string;
typedef T_Scalar<Principal, NQ_DefaultValues::null_principal> T_Principal;

static inline std::ostream &operator<<(std::ostream &os, const std::vector<unsigned char> &c) {
  for(size_t i=0; i < c.size(); i++) {
    os << c[i];
  }
  return os;
}
typedef T_Scalar<std::vector<unsigned char>, NQ_DefaultValues::empty_blob> T_blob;

// Raw, uninterpreted blob 
typedef T_Scalar<FixedBuffer, NQ_DefaultValues::empty_fixed_buffer> T_RawData;

// XXX set, trie
// "Internal" reference, tied to a transaction
template <class T>
struct Ref {
  T *val;

  Ref(Transaction &transaction, const NQ_Tuple &tid) {
    val = dynamic_cast<T*>(transaction.get_tuple_shadow(tid));
  }
  Ref(T *v) : val(v) { }

  static inline 
  Ref<T> *tspace_unmarshall(Transaction &transaction, CharVector_Iterator &curr, 
				 const CharVector_Iterator &end) 
    throw(NQ_Schema_Exception)
  {
    NQ_Tuple *anon_value = NULL;
    anon_value = ::tspace_unmarshall(anon_value, transaction, curr, end);
    return new Ref<T>(transaction, *anon_value);
  }

  static inline void tspace_marshall(const Ref<T> &val, std::vector<unsigned char> &buf) {
    ::tspace_marshall(val.val->get_tid(), buf);
  }

  static inline int tspace_marshall_size(void) {
    return ::tspace_marshall_size<NQ_Tuple>();
  }

  inline operator T *() {
    return load();
  }
  T *load() {
    return val;
  }
private:
  bool operator==(const Ref<T> &r) {
    // not implemented
    assert(0);
    return false;
  }
};

template <class T>
static inline std::ostream &operator<<(std::ostream &os, Ref<T> &elem) {
  T *loaded = elem.load();
  if(loaded == NULL) {
    std::cerr << "FOO";
  }
  os << "Type = " << ( (loaded != NULL) ? loaded->as_abbrv_str() : "(null)");
  return os;
}

// "External" reference, can persist across multiple transactions.
// Type-aware wrapper around UUID
template <class T>
struct ExtRef {
  NQ_UUID tid;
  ExtRef() : tid(NQ_uuid_null) { }
  ExtRef(NQ_UUID t) : tid(t) { }

  inline bool is_null() const {
    return tid == NQ_uuid_null;
  }

  inline T *load(Transaction &t) const {
    T *rv;
    t.find_tuple(rv, tid);
    return rv;
  }
  
  inline bool operator<(const ExtRef &r) const {
    return tid < r.tid;
  }

  inline bool operator==(const ExtRef &r) const {
    return tid == r.tid;
  }
  inline bool operator!=(const ExtRef &r) const {
    return !(tid == r.tid);
  }
};

template <class T>
ExtRef<T> ExtRefOf(T* t) {
  return ExtRef<T>(t->get_tid());
}

#endif //  _NQ_ATTRIBUTE_HH_
