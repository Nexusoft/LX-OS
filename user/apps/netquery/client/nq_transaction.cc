#include <string>
#include <iostream>

#include <nq/tuple.hh>
#include <nq/transaction.hh>

Transaction::OperationType Transaction::op_type_map[NQ_OPERATION_COUNT];

using std::string;
using std::cout;
using std::cerr;

void DependencyTriggerSet::clear_all(Transaction *clear_transaction) {
  size_t j;
  assert(clear_transaction->is_valid());
  for(j=0; j < triggers.size(); j++) {
    int rv = NQ_Trigger_delete(clear_transaction->transaction, clear_transaction->actor, triggers[j]);
    if(rv != 0) {
      cerr << "error rolling back triggers\n";
    }
  }
}

////////////////
// Transaction
////////////////

Transaction::Operation::Operation(NQ_Attribute_Name *name, NQ_Tuple tuple, NQ_Attribute_Operation op) :
  name(NQ_Attribute_Name_dup(name)),
  tuple(tuple), 
  op(op)
{ }

#include <nq/net.h>
Transaction::Transaction(TrustObjectFunc trust_fn, TrustAttributeValueFunc trust_attrval_fn, NQ_Host orig_home, NQ_Principal *actor, bool do_batching) : 
  type(FULL), home(orig_home), actor(actor), trust_object_func(trust_fn), trust_attrval_func(trust_attrval_fn), disable_logging_count(1), do_batching(do_batching), batch(NULL) {
  // Insert built-in tuples
  // In particular, this prevents infinite recursion on T_Class creation

  // ASHIEH: For future design, when we use references in tuplespace
  // to name classes rather than strings

  // tuple_map[T_Class::uuid] = self;
  transaction = NQ_Transaction_begin();
  // cerr << "New transaction " << transaction << "\n";
  if(transaction == NQ_uuid_error) {
    cerr << "Transaction::Transaction(): Could not begin transaction\n";
    transaction = NQ_uuid_null;
  }
}

Transaction::Transaction(NQ_Transaction existing, TrustObjectFunc trust_fn, TrustAttributeValueFunc trust_attrval_fn, NQ_Host orig_home, NQ_Principal *actor, bool do_batching) : 
  type(WRAPPER), transaction(existing), home(orig_home), actor(actor), trust_object_func(trust_fn), trust_attrval_func(trust_attrval_fn), disable_logging_count(1), do_batching(do_batching), batch(NULL) {
}

void Transaction::set_tuple_shadow(T_Tuple *tuple) {
  assert(tuple->tid != NQ_uuid_null);
  tuple_map[tuple->tid] = tuple;
}

T_Tuple *Transaction::get_tuple_shadow(const NQ_Tuple &tid) {
  if(tid == NQ_uuid_null) {
    return NULL;
  }
  // Potential infinite rcursion on lookup of T_Class's tuple is
  // headed off by inserting the T_Class in the Transaction constructor
  if( tuple_map.find(tid) == tuple_map.end() ) {
    T_GenericTuple tuple(*this, tid);
    string class_name = "";
    try {
      class_name = tuple.class_type;
    } catch(NQ_Access_Exception e) {
      cerr << "get_tuple_shadow: could not read class type\n";
      return NULL;
    } catch (NQ_Schema_Exception e) {
      cerr << "get_tuple_shadow: schema error\n";
      return NULL;
    }
    struct KnownClass *local_class_type = KnownClass::find(class_name);
    if(local_class_type == NULL) {
      cerr << "Could not find class with name " << class_name << "\n";
      return NULL;
    }
    if(!trust_object_func(tid, local_class_type)) {
      cerr << "Not trusting class " << class_name << " for tuple " << tid << "\n";
      return NULL;
    }
    set_tuple_shadow(local_class_type->create_object(*this, tid));
  }
  return tuple_map[tid];
}

struct CopyState {
  char *iobuffer;
  int iolength;

  CopyState(char *buf, int len) {
    if(len > 0) {
      iobuffer = new char[len];
      memcpy(iobuffer, buf, len);
    } else {
      iobuffer = NULL;
    }
    iolength = len;
  }
  ~CopyState() {
    if(iobuffer != NULL) {
      delete [] iobuffer;
    }
  }

  static void handler(void *handler_state, NQ_Request_Pending_Status status) {
    CopyState *state = (CopyState *) handler_state;
    // printf("handler callback, state = %d\n", status);
    assert(status == NQ_STATUS_FINISHED);
    delete state;
  }
};

int Transaction::attribute_operate(NQ_Attribute_Name *name, NQ_Tuple tuple, 
				   NQ_Attribute_Operation op, 
				   char **iobuffer, int *iolength, NQ_Principal **output_attributed_to = NULL) {
  if(!is_valid()) {
    throw NQ_API_Exception("no valid current transaction\n");
  }
  bool check_if_trusted = false;
  NQ_Principal *attributed_to = NULL;
  if(output_attributed_to == NULL) {
    output_attributed_to = &attributed_to;
    check_if_trusted = true;
  }
  int rv;
  if(!do_batching) {
    rv = NQ_Attribute_operate(transaction, actor, name, tuple, op, iobuffer, iolength, output_attributed_to);
    assert(batch == NULL);
  } else {
    // Batch handling
    switch(op_type_map[op]) {
    case WRITE: {
      if(batch == NULL) {
	start_batch();
      }

      curr_batch_count++;
      CopyState *state = new CopyState(*iobuffer, *iolength);
      rv = NQ_Batch_Attribute_operate(transaction, actor, name, tuple, op, 
				      &state->iobuffer, &state->iolength, batch,
				      CopyState::handler, state);
      *iobuffer = NULL;
      *iolength = 0;
      break;
    }
    case READ: {
#if 0
      rv = NQ_Batch_Attribute_operate(transaction, name, tuple, op, 
				      iobuffer, iolength, batch,
				      NULL, NULL);
      if(!finish_batch()) {
	throw NQ_API_Exception("Batching error\n");
      }
#else
      rv = NQ_Attribute_operate(transaction, actor, name, tuple, 
				op, iobuffer, iolength,
				output_attributed_to);
      finish_batch();
#endif
      break;
    }
    default:
      assert(0);
    }
  }
  // Log operations, typically so that triggers can be installed later
  if(disable_logging_count <= 0) {
    // cerr << "op[" << operation_log.size() << "] = " << *name << "\n";
    operation_log.push_back( new Operation(name, tuple, op) );
  }
  if(check_if_trusted) {
    if(!trust_attrval_func(name, tuple, attributed_to)) {
      throw NQ_Trust_Exception("transaction::attribute_operate");
    }
  }
  return rv;
}


NQ_Trigger Transaction::add_trigger(const T_Attribute *attr, NQ_Trigger_Type type,
				    int upcall_type,
				    NQ_Trigger_Callback cb, void *userdata) {
  if(!is_valid()) {
    throw NQ_API_Exception("no valid current transaction\n");
  }
  // Use malloc because we are passing this down to C code
  NQ_Trigger_Description *desc = (NQ_Trigger_Description *)malloc(sizeof(*desc));
  desc->name = NQ_Attribute_Name_dup(attr->name);
  desc->tuple = attr->container->tid;
  desc->type = type;
  desc->upcall_type = upcall_type;
  NQ_Trigger trigger = NQ_Trigger_create(transaction, actor, desc, cb, userdata);
  if(NQ_UUID_eq_err(&trigger)) {
    cerr << "Trigger creation error!\n";
  }
  return trigger;
}

void Transaction::abort(void) 
  throw(NQ_Transaction_Exception, NQ_API_Exception) 
{
  if(!is_valid()) {
    throw NQ_API_Exception("no valid current transaction\n");
  }
  int err = NQ_Transaction_abort(transaction);
  if(err != 0) {
    throw NQ_AbortFailed_Exception(transaction, "no valid current transaction\n");
  }
  do_abort_actions();
}

void Transaction::commit(void) 
  throw(NQ_Transaction_Exception, NQ_API_Exception) 
{
  if(!is_valid()) {
    throw NQ_API_Exception("no valid current transaction\n");
  }
  if(!finish_batch()) {
    throw NQ_CommitFailed_Exception(transaction, "batched operation returned error\n");
  }
  int err = NQ_Transaction_commit(transaction);
  if(err != 0) {
    do_abort_actions();
    throw NQ_CommitFailed_Exception(transaction, "commit failed\n");
  }
}
NQ_Tuple Transaction::create_tuple(void) 
  throw(NQ_Access_Exception, NQ_API_Exception) 
{
  if(!is_valid()) {
    throw NQ_API_Exception("no valid current transaction\n");
  }
  NQ_Tuple new_tid = NQ_Tuple_create(transaction, home, actor);
  if(new_tid == NQ_uuid_error) {
    throw NQ_Access_Exception("Could not create new tuple\n");
  }
  return new_tid;
}

struct hash_desc {
  struct Packed_Description {
    NQ_Principal *owner;
    NQ_Attribute_Type attr_type;
    NQ_Tuple tuple;
    NQ_Trigger_Type trigger_type;
    int upcall_type;
    // name
  } __attribute((packed));
  size_t operator()(const NQ_Trigger_Description & unpacked) const {
    Packed_Description packed;
    memset(&packed, 0, sizeof(packed));
    packed.owner = unpacked.name->owner;
    packed.attr_type = unpacked.name->type;
    packed.tuple = unpacked.tuple;
    packed.trigger_type = unpacked.type;
    packed.upcall_type = unpacked.upcall_type;
    return (size_t)
      (SuperFastHash((const char *)&packed, sizeof(packed)) ^ 
       SuperFastHash(unpacked.name->name, strlen(unpacked.name->name)));
  }
};

struct eq_desc {
  bool operator()(const NQ_Trigger_Description & d0,
		  const NQ_Trigger_Description & d1)
  {
    return NQ_Attribute_Name_eq(d0.name, d1.name) && d0.tuple == d1.tuple && d0.type == d1.type && d0.upcall_type == d1.upcall_type;
  }
};

void Transaction::set_dependency_triggers(NQ_Trigger_Description *trigger_template,
					  NQ_Trigger_Callback cb, DependencyTriggerContext *userdata, int op_log_index) throw(NQ_Access_Exception) {
  if(!is_valid()) {
    throw NQ_API_Exception("no valid current transaction\n");
  }
  if(in_batch()) {
    finish_batch();
  }
  assert(userdata->set == NULL);

  NQ_Bundle_begin();
  NQ_Net_Batch *batch = NQ_Net_Batch_create();

  userdata->set = NULL;
  DependencyTriggerSet *trigger_set = 
    new DependencyTriggerSet(*this, cb, (void *)userdata);
  // Eliminate repeats to decrease notification traffic
  // We might also optimize away things like class_type check
  __gnu_cxx::hash_map<NQ_Trigger_Description, int, hash_desc, eq_desc > 
    repeat_map;

  size_t i;
  for(i=op_log_index; i < operation_log.size(); i++) {
    Operation *ent = operation_log[i];
    assert(0 <= ent->op && ent->op < NQ_OPERATION_COUNT);
    switch(op_type_map[ent->op]) {
    case READ: {
      // Use malloc because we are passing this down to C code
      NQ_Trigger_Description *desc = (NQ_Trigger_Description *)malloc(sizeof(*desc));
      *desc = *trigger_template;
      desc->name = ent->name;
      desc->tuple = ent->tuple;
      if(repeat_map.find(*desc) != repeat_map.end()) {
	free(desc);
	break;
      }
      NQ_Batch_Trigger_create(transaction, actor, desc, cb, userdata, batch);
      repeat_map[*desc] = 1;
      break;
    }
    default:
      continue;
    }
  }
  // Flush batch of triggers
  NQ_Bundle_end();

  for(i=0; i < repeat_map.size(); i++) {
      NQ_Trigger trigger = NQ_Batch_Trigger_create_finish(transaction, batch);
      if(trigger == NQ_uuid_error) {
	cerr << "error creating auto read trigger\n";
	// roll back all trigger installation
	trigger_set->clear_all(this);
	throw NQ_Access_Exception("read trigger");
      }
      // cerr << "[" << i << "] Trigger on " << ent->tuple << ", " << *ent->name <<"\n";
      trigger_set->add(trigger);
  }

  userdata->set = trigger_set;
  int rv = NQ_Net_Batch_block(batch);
  assert(rv == 0);

  // cout << "Set " <<  trigger_set->triggers.size() << " triggers, starting at " << op_log_index << "\n";
}


bool Transaction::is_valid(void) {
  return transaction != NQ_uuid_null;
}

void Transaction::do_abort_actions(void) {
  transaction = NQ_uuid_null;

  if(undo_log.size() > 0) {
    cerr << "Firing undo log, size = " << undo_log.size() << "\n";
  }
  for(UndoLog::reverse_iterator i = undo_log.rbegin();
      i != undo_log.rend(); ++i) {
    (*i)->undo();
  }
  undo_log.clear();
}

void Transaction::start_batch(void) {
  assert(batch == NULL);
  // printf("==> Start batch\n");
  NQ_Bundle_begin();
  batch = NQ_Net_Batch_create();
  curr_batch_count = 0;
}

bool Transaction::finish_batch() {
  // flush batch on read
  if(batch != NULL) {
    // printf("==> End batch, count = %d\n", curr_batch_count);
    assert(do_batching);
    NQ_Bundle_end();
    int err = NQ_Net_Batch_block(batch);
    // printf("batch destroy\n");
    NQ_Net_Batch_destroy(batch);
    batch = NULL;
    return err == 0;
  }
  return true;
}

void NQ_transaction_init(void) {
  int i;
  for(i=0; i < int(sizeof(Transaction::op_type_map) / 
		   sizeof(Transaction::op_type_map[0])); i++) {
    Transaction::op_type_map[i] = Transaction::UNSPECIFIED;
  }
  Transaction::op_type_map[NQ_OPERATION_READ] = Transaction::READ;
  Transaction::op_type_map[NQ_OPERATION_LOAD_NTH] = Transaction::READ;
  Transaction::op_type_map[NQ_OPERATION_COUNT] = Transaction::READ;
  Transaction::op_type_map[NQ_OPERATION_CONTAINS] = Transaction::READ;
  Transaction::op_type_map[NQ_OPERATION_NUM_ELEMS] = Transaction::READ;

  Transaction::op_type_map[NQ_OPERATION_WRITE] = Transaction::WRITE;
  Transaction::op_type_map[NQ_OPERATION_ADD] = Transaction::WRITE;
  Transaction::op_type_map[NQ_OPERATION_REMOVE] = Transaction::WRITE;
  Transaction::op_type_map[NQ_OPERATION_CREATE_AGGREGATE] = Transaction::WRITE;
  Transaction::op_type_map[NQ_OPERATION_STORE_NTH] = Transaction::WRITE;
  Transaction::op_type_map[NQ_OPERATION_TRUNCATE] = Transaction::WRITE;

  Transaction::op_type_map[NQ_OPERATION_LOOKUP] = Transaction::READ;
  Transaction::op_type_map[NQ_OPERATION_UPDATE] = Transaction::WRITE;
  Transaction::op_type_map[NQ_OPERATION_REMOVE] = Transaction::WRITE;
}
