#ifndef _NQ_TUPLE_HH_
#define _NQ_TUPLE_HH_

#include <vector>
//#include <ext/hash_fun.h>
#include <ext/hash_map>
#include <sstream>
#include <string>

#include <nq/netquery.h>
#include <nq/attribute.h>
#include <nq/exceptions.hh>
#include <nq/util.hh>
#include <nq/marshall.hh>
#include <nq/attribute.hh>

/////////////////////////////
/// NetQuery built-in attribute types
/// (e.g. Tuple, Vector, ... )
/////////////////////////////

// N.B. All virtual destructors are intentionally undefined, since we
// use a garbage collector.

struct Transaction;

// Every tuple has the following attributes
// ObjectInfo.ClassName : Class

struct T_Class;

struct T_Tuple : public gc {
  // must have tid before all attributes
  NQ_Tuple tid;
  // transaction and actor are inherited by tuples that are navigated
  // to from this tuple.
  Transaction &transaction; // can't switch transaction once created

  // Must have attribute map before all attributes so that it is
  // initialized early enough
  typedef __gnu_cxx::hash_map<const std::string, T_Attribute *> AttributeMap;
  AttributeMap attribute_map;

  // XXX this attribute should be
  // T_Reference<T_Class> class_type;
  T_string class_type;
  //// End of attributes

  bool is_created;

  inline NQ_Tuple get_tid(void) const {
    // XXX This hack is unsound (E.g. in multiple inheritance)
    if(this == NULL) {
      return NQ_uuid_null;
    }
    return tid;
  }

  inline T_Tuple(Transaction &transaction) :
    tid(NQ_UUID_localized_null(transaction.home)), 
    transaction(transaction),
    class_type(this, "ObjectInfo.class_type"),
    is_created(false)
  { }
  inline T_Tuple(Transaction &transaction, const NQ_Tuple &tid) : 
    tid(tid), 
    transaction(transaction),
    class_type(this, "ObjectInfo.class_type"),
    is_created(true)
  { }

  virtual ~T_Tuple() { }

  // tspace_ prefixed operations manipulate the tuplespace

  // Initialize from a template, and create a corresponding tuple
  virtual void tspace_create(void) throw(NQ_Access_Exception) = 0;
  void tspace_delete(void) throw(NQ_Access_Exception);

  void add_attribute(const std::string &name, T_Attribute *new_attr);
  void tspace_create_generic(const std::string &class_name) throw(NQ_Access_Exception);

  virtual std::string as_abbrv_str(void);
};

// T_GenericTuple is used to access the Tuple fields (e.g., ObjectInfo.class_type)
struct T_GenericTuple : T_Tuple {
  inline T_GenericTuple(Transaction &transaction) :
    T_Tuple(transaction)
  { }
  inline T_GenericTuple(Transaction &transaction, const NQ_Tuple &tid) : 
    T_Tuple(transaction, tid)
  { }
  virtual void tspace_create(void) throw(NQ_Access_Exception);
};

std::ostream &operator<<(std::ostream &os, const T_Tuple &tuple);

////// Registry and reflection

// Registry schema:
//   Each principal has a separate namespace, rooted at:
//   (principal, "Entries") : dictionary of name => RegistryEntry

#if 0 
// Not yet implemented! Need more tuplespace ADTs
struct T_RegistryEntry : T_Tuple {
  T_RawData raw_data;
  T_RegistryEntry(Transaction &transaction, const NQ_Tuple &tid) :
    T_Tuple(transaction, tid),
    raw_data("RegistryEntry.raw_data", this) { }
};

struct T_Registry : T_Tuple {
  T_RawData lookup(NQ_Principal *principal, const std::string &name);

  template<class T>
  T *lookup_as_tuple(NQ_Principal *principal, const std::string &name) {
    xxx;
    return ref.get();
  }
};
#endif

// Reflection information

#if 0
// ASHIEH: For when we switch to Tuples to identify classes, rather than strings
struct KnownClass;
struct T_Class : T_Tuple {
  KnownClass *local_class;
  virtual ~T_Class();

  virtual void tspace_create(void) throw(NQ_Access_Exception);
  static NQ_Tuple uuid;
  T_Class *self;
};
#endif

struct KnownClass {
  std::string name;
  virtual T_Tuple *create_object(Transaction &transaction, const NQ_Tuple &tid) = 0;
  KnownClass(const std::string &n) : name(n) { }
  virtual ~KnownClass() { }

  static __gnu_cxx::hash_map<const std::string, KnownClass *> map;
  static KnownClass *find(const std::string &name) {
    if(map.find(name) == map.end()) {
      return NULL;
    }
    return map[name];
  }
};

template <class T>
struct Class : KnownClass {
  Class(const std::string &n) : KnownClass(n) { }
  virtual ~Class() { }

  virtual T_Tuple *create_object(Transaction &transaction, const NQ_Tuple &tid) {
    return new T(transaction, tid);
  }

  static inline void add_new(const std::string &name) {
    KnownClass::map[name] = new Class(name);
  }
};

// Macros for defining classes

#define TSPACE_DEFINE_CLASS(CLASS)		\
  typedef Class<T_##CLASS> T_##CLASS##_Class;

#define TSPACE_ADD_CLASS(CLASS)			\
  T_##CLASS##_Class::add_new(#CLASS)

#endif // _NQ_TUPLE_HH_
