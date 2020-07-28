#ifndef _NQ_TRANSACTION_HH_
#define _NQ_TRANSACTION_HH_

#include <nq/netquery.h>
#include <nq/exceptions.hh>
#include <nq/net.h>

// Wrapper for Transaction. Used to record a unique T_Tuple for every NQ_Tuple

// XXX Since the underlying C API is in flux, Transaction does not
// attempt to wrap the full transaction API
struct T_Tuple;
struct T_Attribute;
class KnownClass;

struct Transaction;
struct DependencyTriggerSet {
  Transaction &transaction;
  NQ_Trigger_Callback cb;
  void *userdata;
  std::vector<NQ_Trigger> triggers;

  inline DependencyTriggerSet(Transaction &transaction, NQ_Trigger_Callback cb, void *userdata) :
    transaction(transaction), cb(cb), userdata(userdata)
  { }

  inline void add(NQ_Trigger trigger) {
    triggers.push_back(trigger);
  }
  void clear_all(Transaction *clear_transaction);
};

struct DependencyTriggerContext {
  DependencyTriggerSet *set;
  // void clear_all_triggers(void);
  inline DependencyTriggerContext(void) : set(NULL) { }
};

struct Transaction {
  enum TransactionType {
    FULL,
    WRAPPER, // This is a wrapper around a transaction object that we
	     // were passed. Not all features are supported
  };
  struct UndoLogEntry {
    virtual inline ~UndoLogEntry() { }
    virtual void undo(void) = 0;
  };

  typedef bool (TrustObjectFunc)(NQ_Tuple tid, KnownClass *obj_class);
  typedef bool (TrustAttributeValueFunc)(NQ_Attribute_Name *name, NQ_Tuple tid, NQ_Principal *principal);
  typedef std::vector<UndoLogEntry *> UndoLog;

  template <typename T> struct Snapshot : UndoLogEntry {
    T old_value;
    T &target;
    Snapshot(T &t) : old_value(t), target(t)
    { }
    virtual void undo(void) {
      target = old_value;
    }
  };

  template <typename T> 
  static inline Snapshot<T> *SnapshotOf(T &v) {
    return new Snapshot<T>(v);
  }

  enum OperationType {
    READ, WRITE, UNSPECIFIED,
  };
  static OperationType op_type_map[NQ_OPERATION_COUNT];

  TransactionType type;
  NQ_Transaction transaction;
  NQ_Host home;
  NQ_Principal *actor;

  struct Operation {
    NQ_Attribute_Name *name;
    NQ_Tuple tuple;
    NQ_Attribute_Operation op;
    Operation(NQ_Attribute_Name *name, NQ_Tuple tuple, NQ_Attribute_Operation op);
  };

  __gnu_cxx::hash_map<const NQ_Tuple, T_Tuple *> tuple_map;

  // Callback to determine how an object should be interpreted
  TrustObjectFunc *trust_object_func;
  TrustAttributeValueFunc *trust_attrval_func;

  std::vector<Operation *> operation_log;
  UndoLog undo_log;
  int disable_logging_count;

  bool do_batching;
  NQ_Net_Batch *batch;
  int curr_batch_count;

  // Create new transaction
  Transaction(TrustObjectFunc trust_fn, TrustAttributeValueFunc trust_attrval_fn, NQ_Host orig_home, NQ_Principal *actor = NULL, bool do_batching = false);
  // Wrap an existing transaction
  Transaction(NQ_Transaction existing, TrustObjectFunc trust_fn, TrustAttributeValueFunc trust_attrval_fn, NQ_Host orig_home, NQ_Principal *actor = NULL, bool do_batching = false);
  
  inline void switch_actor(NQ_Principal *actor) {
    this->actor = actor;
  }
  
  void set_tuple_shadow(T_Tuple *tuple);
  T_Tuple *get_tuple_shadow(const NQ_Tuple &tid);

  // Use reference-passing style to side-step lack of return-value
  // overload resolution & make call site code more succinct
  template <class T> 
  inline void find_tuple(T * &result, const NQ_Tuple &tid) throw (NQ_Access_Exception){
    T_Tuple *t = get_tuple_shadow(tid);
    if(t == NULL) {
      result = NULL;
      return;
    }
    result = dynamic_cast<T*>(t);
    if(result == NULL) {
      throw NQ_Access_Exception("Could not find tuple!\n");
    }
  }

  bool is_valid(void);

  // Wrappers around C api
  int attribute_operate(NQ_Attribute_Name *name, NQ_Tuple tuple, 
			NQ_Attribute_Operation op, 
			char **iobuffer, int *iolength, 
			NQ_Principal **output_attributed_to);
  NQ_Trigger add_trigger(const T_Attribute *attr, NQ_Trigger_Type type,
			 int upcall_type,
			 NQ_Trigger_Callback cb, void *userdata);

  void abort(void) throw(NQ_Transaction_Exception, NQ_API_Exception);
  void commit(void) throw(NQ_Transaction_Exception, NQ_API_Exception);
  NQ_Tuple create_tuple(void) throw(NQ_Access_Exception, NQ_API_Exception);

  inline void disable_logging(void) {
    disable_logging_count++;
  }
  inline void restore_logging(void) {
    disable_logging_count--;
  }
  // Use the transaction log to set a update trigger for all read values.
  // The set of triggers is stored into DependencyTriggerContext so that the
  // upcall can easily clear the triggers.


  inline int get_op_log_size() {
    return operation_log.size();
  }
  // Currently, this sets triggers on read dependencies
  // Returns operation log index
  void set_dependency_triggers(NQ_Trigger_Description *trigger_template,
			      NQ_Trigger_Callback cb, 
			      DependencyTriggerContext *userdata, int op_log_index = 0)
    throw(NQ_Access_Exception);

  // Record a local side effect. If the transaction fails, these side
  // effects are rolled back. The Undo Log is run backwards
  inline void undo_log_append(UndoLogEntry *entry) {
    if(type != FULL) {
      std::cerr << "Warning: transaction undo log may not be respected!\n";
    }
    undo_log.push_back(entry);
  }

  // Internal function: Called on voluntary and involuntary abort()
  void do_abort_actions(void);
  
  inline bool in_batch(void) {
    return batch != NULL;
  }
  void start_batch(void);
  bool finish_batch(void);
};

#endif // _NQ_TRANSACTION_HH_
