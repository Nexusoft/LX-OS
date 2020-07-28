#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <stdint.h>

#include <arpa/inet.h>

#include <nq/queue.h>
#include <nq/netquery.h>
#include <nq/util.hh>
#include <nq/gcmalloc.h>
#include <nq/net.h>
#include <nq/remote_trigger.h>
#include <nq/garbage.h>
#include <nq/hashtable.h>
#include <nq/pickle.h>

struct NQ_Trigger_Stats trigger_stats = { -1, -1 };

Queue NQ_Attribute_Type_definitionlist;
struct hashtable *NQ_Attribute_values;

NQ_Attribute_Type_Definition 
  NQ_Attribute_Type_Raw, 
  NQ_Attribute_Type_Set, 
  NQ_Attribute_Type_Trie,
  NQ_Attribute_Type_Vector,
  NQ_Attribute_Type_FakeTrie;

NQ_Attribute_Operation_Call
  NQ_Attribute_Raw_read, NQ_Attribute_Raw_write;
NQ_Attribute_Operation_Call
  NQ_Attribute_Set_add, NQ_Attribute_Set_remove, NQ_Attribute_Set_contains;
NQ_Attribute_Operation_Call
  NQ_Attribute_Trie_add, NQ_Attribute_Trie_remove;
NQ_Attribute_Operation_Call 
  NQ_Attribute_Vector_create, NQ_Attribute_Vector_load_nth, NQ_Attribute_Vector_store_nth, NQ_Attribute_Vector_truncate, NQ_Attribute_Vector_num_elems;

NQ_Attribute_Operation_Call 
NQ_Attribute_Trie_create, NQ_Attribute_Trie_load_nth, NQ_Attribute_Trie_truncate, NQ_Attribute_Trie_num_elems, 
  NQ_Attribute_Trie_update, NQ_Attribute_Trie_lookup, NQ_Attribute_Trie_remove;

NQ_Attribute_Print_Call NQ_Attribute_Raw_print, NQ_Attribute_Set_print, NQ_Attribute_Trie_print, NQ_Attribute_Vector_print, NQ_Attribute_Trie_print;

#define I(F,FLAGS)				\
  ( (struct NQ_Attribute_Operation_Info) { .func = (F), .flags = (FLAGS)} )

void NQ_Attribute_init(void) {
  queue_initialize(&NQ_Attribute_Type_definitionlist);
  NQ_Attribute_values = create_hashtable(10000000, NQ_Attribute_Name_hash, (int (*) (void*,void*))NQ_Attribute_Name_eq);
  
  bzero(&NQ_Attribute_Type_Raw, sizeof(NQ_Attribute_Type_Definition));
  NQ_Attribute_Type_Raw.calls[NQ_OPERATION_READ] = 
    I(&NQ_Attribute_Raw_read, NQ_ATTRIBUTE_F_READ);
  NQ_Attribute_Type_Raw.calls[NQ_OPERATION_WRITE] = 
    I(&NQ_Attribute_Raw_write, NQ_ATTRIBUTE_F_WRITE);
  NQ_Attribute_Type_Raw.print_call = &NQ_Attribute_Raw_print;
  NQ_Attribute_Type_Raw.type = NQ_ATTRIBUTE_RAW;
  queue_append(&NQ_Attribute_Type_definitionlist, &NQ_Attribute_Type_Raw);

  bzero(&NQ_Attribute_Type_Set, sizeof(NQ_Attribute_Type_Definition));
  NQ_Attribute_Type_Set.calls[NQ_OPERATION_ADD] = 
    I(&NQ_Attribute_Set_add, NQ_ATTRIBUTE_F_WRITE);
  NQ_Attribute_Type_Set.calls[NQ_OPERATION_REMOVE] = 
    I(&NQ_Attribute_Set_remove, NQ_ATTRIBUTE_F_WRITE);
  NQ_Attribute_Type_Set.calls[NQ_OPERATION_CONTAINS] = 
    I(&NQ_Attribute_Set_contains, NQ_ATTRIBUTE_F_READ);
  NQ_Attribute_Type_Set.print_call = &NQ_Attribute_Set_print;
  NQ_Attribute_Type_Set.type = NQ_ATTRIBUTE_SET;
  queue_append(&NQ_Attribute_Type_definitionlist, &NQ_Attribute_Type_Set);

  bzero(&NQ_Attribute_Type_Vector, sizeof(NQ_Attribute_Type_Definition));
  NQ_Attribute_Type_Vector.calls[NQ_OPERATION_CREATE_AGGREGATE] = 
    I(&NQ_Attribute_Vector_create, NQ_ATTRIBUTE_F_WRITE);
  NQ_Attribute_Type_Vector.calls[NQ_OPERATION_LOAD_NTH] = 
    I(&NQ_Attribute_Vector_load_nth, NQ_ATTRIBUTE_F_READ);
  NQ_Attribute_Type_Vector.calls[NQ_OPERATION_STORE_NTH] = 
    I(&NQ_Attribute_Vector_store_nth, NQ_ATTRIBUTE_F_WRITE);
  NQ_Attribute_Type_Vector.calls[NQ_OPERATION_TRUNCATE] = 
    I(&NQ_Attribute_Vector_truncate, NQ_ATTRIBUTE_F_WRITE);
  NQ_Attribute_Type_Vector.calls[NQ_OPERATION_NUM_ELEMS] = 
    I(&NQ_Attribute_Vector_num_elems, NQ_ATTRIBUTE_F_READ);
  NQ_Attribute_Type_Vector.print_call = &NQ_Attribute_Vector_print;
  NQ_Attribute_Type_Vector.type = NQ_ATTRIBUTE_VECTOR;
  queue_append(&NQ_Attribute_Type_definitionlist, &NQ_Attribute_Type_Vector);

  bzero(&NQ_Attribute_Type_Trie, sizeof(NQ_Attribute_Type_Definition));
  NQ_Attribute_Type_Trie.calls[NQ_OPERATION_CREATE_AGGREGATE] = 
    I(&NQ_Attribute_Trie_create, NQ_ATTRIBUTE_F_WRITE);
  NQ_Attribute_Type_Trie.calls[NQ_OPERATION_LOAD_NTH] = 
    I(&NQ_Attribute_Trie_load_nth, NQ_ATTRIBUTE_F_READ);
  NQ_Attribute_Type_Trie.calls[NQ_OPERATION_TRUNCATE] = 
    I(&NQ_Attribute_Trie_truncate, NQ_ATTRIBUTE_F_WRITE);
  NQ_Attribute_Type_Trie.calls[NQ_OPERATION_NUM_ELEMS] = 
    I(&NQ_Attribute_Trie_num_elems, NQ_ATTRIBUTE_F_READ);

  NQ_Attribute_Type_Trie.calls[NQ_OPERATION_UPDATE] = 
    I(&NQ_Attribute_Trie_update, NQ_ATTRIBUTE_F_WRITE);
  NQ_Attribute_Type_Trie.calls[NQ_OPERATION_LOOKUP] = 
    I(&NQ_Attribute_Trie_lookup, NQ_ATTRIBUTE_F_READ);
  NQ_Attribute_Type_Trie.calls[NQ_OPERATION_REMOVE] = 
    I(&NQ_Attribute_Trie_remove, NQ_ATTRIBUTE_F_READ);

  NQ_Attribute_Type_Trie.print_call = &NQ_Attribute_Trie_print;
  NQ_Attribute_Type_Trie.type = NQ_ATTRIBUTE_TRIE;
  queue_append(&NQ_Attribute_Type_definitionlist, &NQ_Attribute_Type_Trie);
}

#undef I

///////////////////////////////////////// Management

typedef struct NQ_Attribute_Value_Table {
  struct NQ_Attribute_Value_Table *next, *prev;
  NQ_UUID_Table *val_table;
  NQ_TriggerSet *triggers;

  NQ_Attribute_Name name;
} NQ_Attribute_Value_Table;

typedef struct NQ_Attribute_Value {
  struct NQ_Attribute_Value *next, *prev;
  void *val;
  Queue triggers;
  NQ_Tuple tuple;
} NQ_Attribute_Value;

typedef struct NQ_Attribute_Trigger_Deletion {
  NQ_Transaction transaction;
  NQ_Attribute_Trigger *trigger;
} NQ_Attribute_Trigger_Deletion;

//typedef in attribute.h
struct NQ_Attribute_Trigger_Context {
  NQ_Attribute_Value *tuple_entry;
  NQ_Attribute_Value_Table *name_entry;
  NQ_Tuple tuple;
  NQ_Transaction transaction;
};

#define NQ_Attribute_Value_Size(a) \
  (sizeof(NQ_Attribute_Value)+20 + strlen(a->name) + 1)
 
int NQ_Attribute_Name_eq(NQ_Attribute_Name *a, NQ_Attribute_Name *b){
//  printf("Comparing: Attributes %s:%d(", a->name, a->type);
//  print_ip(a->owner->home);
//  printf(") and %s:%d(", b->name, b->type);
//  print_ip(b->owner->home);
//  printf(") (%d, %d, %d)\n", (a->type == b->type), (strcmp(a->name, b->name) == 0), NQ_Principal_eq(a->owner, b->owner));
  return (a->type == b->type) &&
    (strcmp(a->name, b->name) == 0) && 
    NQ_Principal_eq(a->owner, b->owner);
}
void NQ_Attribute_Name_cpy(NQ_Attribute_Name *dst, NQ_Attribute_Name *src){
  dst->owner = src->owner;
  NQ_Principal_reserve(dst->owner);
  dst->type = src->type;
  strcpy(dst->name, src->name);
}

static NQ_Attribute_Name *NQ_Attribute_Name_alloc_helper(const char *name) {
  return (NQ_Attribute_Name *)
    malloc(sizeof(NQ_Attribute_Name) + strlen(name) + 1);
}

NQ_Attribute_Name *NQ_Attribute_Name_alloc(NQ_Host *home, NQ_Attribute_Type type, const char *name) {
  NQ_Principal *p = NQ_get_home_principal(home);
  if(p == NULL) {
    fprintf(stderr, "NQ_Attribute_Name_alloc(): Bad home principal\n");
    return NULL;
  }
  NQ_Attribute_Name *aname = NQ_Attribute_Name_alloc_helper(name);
  aname->owner = p;
  NQ_Principal_reserve(p);
  aname->type = type;
  strcpy(aname->name, name);
  return aname;
}

NQ_Attribute_Name *NQ_Attribute_Name_dup(const NQ_Attribute_Name *name) {
  NQ_Attribute_Name *aname = NQ_Attribute_Name_alloc_helper(name->name);
  NQ_Attribute_Name_cpy(aname, (NQ_Attribute_Name*)name);
  return aname;
}

void NQ_Attribute_Name_free(NQ_Attribute_Name *name){
  NQ_Principal_delete(name->owner);
  free(name);
}

int NQ_Attribute_Value_find(NQ_Attribute_Value_Table *val, NQ_Attribute_Name *name){
  return NQ_Attribute_Name_eq(&val->name, name);
}
int NQ_Attribute_Tuple_find(NQ_Attribute_Value *val, NQ_Tuple *tuple){
//  print_hex((unsigned char *)&val->tuple, 8);
//  printf("=%s=", NQ_Tuple_equals(val->tuple, *tuple)?"^":"/");
//  print_hex((unsigned char *)tuple, 8);
//  printf("\n");
  return NQ_Tuple_equals(val->tuple, *tuple);
}

static void 
NQ_Attribute_Value_Table_add(NQ_Attribute_Value_Table *list, NQ_Attribute_Value *val) {
  NQ_UUID_Table_insert(list->val_table, &val->tuple, val);
}

void 
NQ_Tuple_Attribute_Value_del(NQ_Tuple tuple, NQ_Attribute_Name *name) {
  NQ_Attribute_Value_Table *tuples = hashtable_search(NQ_Attribute_values, name);
  if(tuples != NULL) {
    NQ_UUID_Table_delete(tuples->val_table, &tuple);
  }
}

static NQ_Attribute_Value *
NQ_Attribute_Value_Table_find(NQ_Transaction transaction, NQ_Attribute_Value_Table *list, NQ_Tuple *tuple) {
  assert(NQ_Local_Tuple_check_valid(transaction, tuple));
  return NQ_UUID_Table_find(list->val_table, tuple);
}

int NQ_Attribute_Type_find(NQ_Attribute_Type_Definition *def, NQ_Attribute_Type *type){
  return def->type == *type;
}

NQ_Attribute_Value_Table *NQ_Attribute_inittuples(NQ_Attribute_Name *name){
  NQ_Attribute_Value_Table *tuples = malloc(NQ_Attribute_Value_Size(name));
  bzero(tuples, NQ_Attribute_Value_Size(name));

  tuples->val_table = NQ_UUID_Table_new();
  tuples->triggers = NQ_TriggerSet_new();
  NQ_Attribute_Name_cpy(&tuples->name, name);
  hashtable_insert(NQ_Attribute_values, &tuples->name, tuples);
  return tuples;
}

NQ_Attribute_Value *NQ_Attribute_initvalue(NQ_Transaction transaction, NQ_Attribute_Value_Table *tuples, NQ_Tuple *tuple){
  NQ_Attribute_Value *val;
  
  if(NQ_Tuple_add_attribute(transaction, *tuple, &tuples->name) < 0) return NULL;
  
  val = malloc(sizeof(NQ_Attribute_Value));
  bzero(val, sizeof(NQ_Attribute_Value));
  queue_initialize(&val->triggers);
  NQ_UUID_cpy(&val->tuple, tuple);

  NQ_Attribute_Value_Table_add(tuples, val);
  return val;
}

static int
find_init_helper(NQ_Transaction transaction, NQ_Attribute_Name *name, NQ_Tuple tuple,
                 NQ_Attribute_Value_Table **tuples, 
                 NQ_Attribute_Value **val, 
                 NQ_Attribute_Trigger_Context *t_ctx, 
                 void **impl_value_p, int *found_old) {
  if(found_old != NULL) {
    *found_old = 0;
  }
  if((*tuples = hashtable_search(NQ_Attribute_values, name))){
    t_ctx->name_entry = *tuples;
    if((*val = NQ_Attribute_Value_Table_find(transaction, *tuples, &tuple))){
      t_ctx->tuple_entry = *val;
      *impl_value_p = (*val)->val;
      if(found_old != NULL) {
        *found_old = 1;
      }
    }
  }
  if(!*val){
    if(!*tuples){
      *tuples = NQ_Attribute_inittuples(name);
      t_ctx->name_entry = *tuples;
    }
    *val = NQ_Attribute_initvalue(transaction, *tuples, &tuple);
    if(!*val){
      return -4;
    }
    t_ctx->tuple_entry = *val;
  }
  return 0;
}

int NQ_Tuple_Attribute_Value_new(NQ_Transaction transaction, NQ_Tuple tuple, NQ_Attribute_Name *name) {
  NQ_Attribute_Value_Table *tuples = NULL;
  NQ_Attribute_Value *val = NULL;
  void *impl_value = NULL;
  int found_old;
  NQ_Attribute_Trigger_Context t_ctx = {NULL, NULL, tuple, transaction};
  int rv = find_init_helper(transaction, name, tuple, &tuples, &val, &t_ctx, &impl_value, &found_old);
  return ! (rv == 0 && found_old == 0);
}

int NQ_Local_Attribute_operate(
  NQ_Transaction transaction, 
  NQ_Principal *actor,
  NQ_Attribute_Name *name, NQ_Tuple tuple, 
  NQ_Attribute_Operation op, 
  char **iobuffer, int *iolength,
  NQ_Principal **output_attributed_to
  ){
  // printf("Operate(%d)   ", op);
  void *input = *iobuffer, *output = NULL, *impl_value = NULL;
  int input_len = *iolength, output_len = 0;
  NQ_Attribute_Value_Table *tuples = NULL;
  NQ_Attribute_Value *val = NULL;
  NQ_Attribute_Type_Definition *type = NULL;
  NQ_Attribute_Trigger_Context t_ctx = {NULL, NULL, tuple, transaction};
  int ret;
  
  // Check to see if opcode is special
  if(op == NQ_OPERATION_CLEAR_GLOBAL_STATS) {
    printf("Clearing NetQuery stats\n");
    NQ_clear_stats();
    return 0;
  } else if(op == NQ_OPERATION_GET_GLOBAL_STATS) {
    printf("Getting NetQuery stats\n");
    if(*iobuffer == NULL) {
      *iobuffer = malloc(sizeof(NQ_Stat));
      *iolength = sizeof(NQ_Stat);
    }
    assert(*iolength >= sizeof(NQ_Stat));
    *iolength = sizeof(NQ_Stat);
    memcpy(*iobuffer, &NQ_stat, sizeof(NQ_stat));
    return 0;
  }

  if((type = queue_find(&NQ_Attribute_Type_definitionlist, (PFany)NQ_Attribute_Type_find, &name->type))==NULL){
    return -2;
  }
  if(type->calls[op].func == NULL){
    return -3;
  }
  NQ_Transaction_Real *t = NQ_Transaction_get_any(transaction);
  if(t == NULL) {
    return -6;
  }
  if( t->commit_state == COMMITSTATE_DONE ||
      t->commit_state == COMMITSTATE_ERROR ||
      (t->commit_state != COMMITSTATE_EXECUTION && 
       (type->calls[op].flags & NQ_ATTRIBUTE_F_WRITE)) ) {
    printf("invalid op %d for state %d\n", op, t->commit_state);
    ret = -5;
    goto out;
  }
  
    
//  printf("NQ_attribute_operate('");print_hex((unsigned char *)&transaction, 8);
//  printf("', %s:%d, '", name->name, name->type);print_hex((unsigned char *)&tuple, 8);
//  printf("', %d, (%d bytes in))\n", op, *iolength);

  if(!NQ_Local_Tuple_check_valid(transaction, &tuple)) {
	  // printf("attr_operate: tuple is invalid\n");
	  ret = -1;
	  goto out;
  }
  if(( ret = find_init_helper(transaction, name, tuple, &tuples, &val, &t_ctx, &impl_value, NULL)) != 0) {
	  goto out;
  }
  
//  printf("precall, impl_value = %p\n", impl_value);
  if(output_attributed_to != NULL) {
    *output_attributed_to = NULL;
  }
  ret = type->calls[op].func(transaction, actor, &t_ctx, input, input_len, &output, &output_len, &impl_value, output_attributed_to);
//  printf("postcall, impl_value = %p\n", impl_value);
  
  val->val = impl_value;
  *iobuffer = output;
  *iolength = output_len;
  
out:
  return ret;
}
int NQ_Attribute_operate(
  NQ_Transaction transaction, 
  NQ_Principal *actor,
  NQ_Attribute_Name *name, NQ_Tuple tuple, 
  NQ_Attribute_Operation op, 
  char **iobuffer, int *iolength, 
  NQ_Principal **output_attributed_to
  ){
  NQ_stat.client.attr_op++;
  // printf("(op = %d)", op);
  int rv = NQ_Net_Attribute_operate(transaction, actor, name, tuple, op, iobuffer, iolength, output_attributed_to);
  if( (NQ_ATTR_GET_TX_STATE(rv) & NQ_ATTR_TX_STATE_VALID)) {
    NQ_Transaction_update_shadow_state(transaction, (NQ_ATTR_GET_TX_STATE(rv) & NQ_ATTR_TX_STATE_HAS_PENDING_TRIGGERS));
  }
  return NQ_ATTR_GET_ERRCODE(rv);
}

int NQ_Attribute_print(
  NQ_Transaction transaction, 
  NQ_Attribute_Name *name, NQ_Tuple tuple){
  
  NQ_Attribute_Type_Definition *type = NULL;
  NQ_Attribute_Value_Table *tuples = NULL;
  NQ_Attribute_Value *val = NULL;
  void *impl_value = NULL;
  
  if((type = queue_find(&NQ_Attribute_Type_definitionlist, (PFany)NQ_Attribute_Type_find, &name->type))==NULL){
    printf("[unknown attribute type: %d]", name->type);
    return -1;
  }
  
  if((tuples = hashtable_search(NQ_Attribute_values, name))){
    if((val = NQ_Attribute_Value_Table_find(transaction, tuples, &tuple))){
      impl_value = val->val;
    }
  }
  switch(name->type){
    case NQ_ATTRIBUTE_RAW:
      printf("raw");
      break;
    case NQ_ATTRIBUTE_SET:
      printf("set");
      break;
    case NQ_ATTRIBUTE_TRIE:
      printf("trie");
      break;
    case NQ_ATTRIBUTE_VECTOR:
      printf("vector");
      break;
  case NQ_ATTRIBUTE_FAKE_TRIE:
    printf("fake trie");
    break;
  case NQ_ATTRIBUTE_TYPE_COUNT:
    assert(!"NQ_ATTRIBUTE_TYPE_COUNT is not a valid attribute type");
  }
  printf("_%s = [", name->name);
  type->print_call(transaction, impl_value);
  printf("]");
  return 0;
}

///////////////////////////////////////// NETQUERY TRIGGERS

int NQ_Trigger_cleanup(NQ_Attribute_Trigger *trigger){
#if 0
  if(trigger->cleanup){
    trigger->cleanup(trigger->description, trigger->userdata);
  }
#endif
  
  NQ_UUID_release(trigger->id);
  if(trigger->name_attribute == NULL){
    assert(trigger->tuple_attribute);
    queue_delete(&trigger->tuple_attribute->triggers, trigger);
  } else {
    NQ_TriggerSet_erase(trigger->name_attribute->triggers, trigger);
  }
  UUIDSet_destroy(trigger->pending_deletes);
  if(trigger->description->name){
    NQ_Attribute_Name_free(trigger->description->name);
  }
  free(trigger->description);
  free(trigger);
  return 0;
}
#if 0
int NQ_Trigger_set_cleanup(NQ_Trigger trigger_id, NQ_Trigger_Cleanup cleanup){
  NQ_Attribute_Trigger *trigger;
  
  if(trigger_id.type == NQ_UUID_TRIGGER_REMOTE){
    return NQ_Remote_Trigger_set_cleanup(trigger_id, cleanup);
  }
  
  trigger = NQ_UUID_lookup(trigger_id);
  if(!trigger){
    return -1;
  }
  
  trigger->cleanup = cleanup;
  return 0;
}
#endif

int NQ_Trigger_create_commit(NQ_Transaction transaction, NQ_Attribute_Trigger *trigger, int revision){
  // clearing the transaction field makes the trigger visible to all transactions in the system
  NQ_UUID_clr(&trigger->transaction);
  NQ_GC_register_local_trigger(trigger->transaction);
  return 0;
}
int NQ_Trigger_create_abort(NQ_Transaction transaction, NQ_Attribute_Trigger *trigger, int revision){
  NQ_Trigger_cleanup(trigger);
  return 0;
}
NQ_Transaction_Step_Type NQ_Trigger_create_transaction = {
  .callbacks = {
    (NQ_Transaction_Callback)NQ_Trigger_create_commit, 
    (NQ_Transaction_Callback)NQ_Trigger_create_abort,
    NULL
  }
};
NQ_Trigger NQ_Local_Trigger_create(
  NQ_Transaction transaction, 
  NQ_Principal *actor, 
  NQ_Trigger_Description *description, NQ_Trigger cb_id){
  
  NQ_Attribute_Value_Table *tuples = NULL;
  NQ_Attribute_Value *val = NULL;
  NQ_Attribute_Trigger *trigger;
  NQ_Trigger ret;

  trigger = malloc(sizeof(NQ_Attribute_Trigger));
  bzero(trigger, sizeof(NQ_Attribute_Trigger));
  
  ret = NQ_UUID_alloc(trigger, NQ_UUID_TRIGGER);
  
  NQ_UUID_cpy(&trigger->transaction, &transaction);
  trigger->description = malloc(sizeof(NQ_Trigger_Description));
  memcpy(trigger->description, description, sizeof(NQ_Trigger_Description));
  if(description->name){
    trigger->description->name = NQ_Attribute_Name_dup(description->name);
  }

  NQ_UUID_cpy(&trigger->cb_id, &cb_id);
  NQ_UUID_cpy(&trigger->id, &ret);
  trigger->pending_deletes = UUIDSet_new();

  // xxx code is duplicated multiple times
  if(!(tuples = hashtable_search(NQ_Attribute_values, description->name))){
    tuples = NQ_Attribute_inittuples(description->name);
  }

  if(description->name){
    trigger->name_attribute = tuples;
    NQ_TriggerSet_insert(tuples->triggers, trigger);
  } else {
    //The trigger is on a specific tuple
    val = NQ_Attribute_Value_Table_find(transaction, tuples, &description->tuple);
    if(!val){
      free(NQ_UUID_release(ret));
      ret = NQ_uuid_error;
    } else {
      trigger->tuple_attribute = val;
      queue_append(&val->triggers, trigger);
    }
  }
  
  // printf("\tNew trigger: "); NQ_UUID_print(&ret); printf("\n");
  NQ_Transaction_step(transaction, &NQ_Trigger_create_transaction, trigger, 0);
  
  return ret;
}

NQ_Trigger NQ_Trigger_create(
  NQ_Transaction transaction, 
  NQ_Principal *actor, 
  NQ_Trigger_Description *description, NQ_Trigger_Callback cb, void *userdata){
  return NQ_Net_Trigger_create(transaction, actor, description, cb, userdata);
}

int NQ_Trigger_is_locally_valid(const NQ_Transaction *transaction, NQ_Attribute_Trigger *trigger){
  if(!NQ_Transaction_subseteq(trigger->transaction, *transaction)){
    return 0;
  }
  if(UUIDSet_contains(trigger->pending_deletes, transaction)) {
    return 0;
  }
  return 1;
}

int NQ_Trigger_delete_commit(NQ_Transaction transaction, NQ_Attribute_Trigger_Deletion *deletion, int revision){
  assert(deletion->trigger != NULL);
  NQ_Trigger_cleanup(deletion->trigger);
  free(deletion);
  return 0;
}

int NQ_Trigger_delete_abort(NQ_Transaction transaction, NQ_Attribute_Trigger_Deletion *deletion, int revision){
  assert(deletion->trigger != NULL);
  UUIDSet_erase(deletion->trigger->pending_deletes, &deletion->transaction);
  free(deletion);
  return 0;
}

NQ_Transaction_Step_Type NQ_Trigger_delete_transaction = {
  .callbacks = {
    (NQ_Transaction_Callback)NQ_Trigger_delete_commit, 
    (NQ_Transaction_Callback)NQ_Trigger_delete_abort,
    NULL
  }
};

int NQ_Local_Trigger_delete(
  NQ_Transaction transaction, 
  NQ_Principal *actor, 
  NQ_Trigger trigger_id){
  // printf("\tTrigger delete: "); NQ_UUID_print(&trigger_id); printf("\n");
  NQ_Attribute_Trigger_Deletion *deletion;
  
  NQ_Attribute_Trigger *trigger = NQ_UUID_lookup(trigger_id);
  if(trigger == NULL) return -1;
  if(!NQ_Trigger_is_locally_valid(&transaction, trigger)){
    return -2;
  }
  
  deletion = malloc(sizeof(NQ_Attribute_Trigger_Deletion));
  bzero(deletion, sizeof(NQ_Attribute_Trigger_Deletion));
  NQ_UUID_cpy(&deletion->transaction, &transaction);
  deletion->trigger = trigger;

  // pending_deletes was originally intended to support nested
  // transactions, hence the use of subseteq instead of subset to
  // check whether there is a relevant pending deletion.  The UUIDSet
  // supports only the eq check.
  assert(!NQ_UUID_eq(&deletion->transaction, &NQ_uuid_error));
  UUIDSet_insert(trigger->pending_deletes, &transaction);
  
  NQ_Transaction_step(transaction, &NQ_Trigger_delete_transaction, deletion, 0);

  return 0;
}
int NQ_Trigger_delete(
  NQ_Transaction transaction, 
  NQ_Principal *actor, 
  NQ_Trigger trigger_id){
  
  return NQ_Net_Trigger_delete(transaction, actor, trigger_id);
}

void NQ_Trigger_call_async(void *userdata){
  NQ_Trigger_Call_Data *data = userdata;
  
  // printf("NQ_Trigger_call_async(%p->%p)\n", data, data->call);
  int rv = data->call(data->transaction, data->description, 
		      data->fire_info->type, data->fire_info->arg, data->userdata);

  if(data->continuation != NULL) {
    // printf("call_async_cont()\n");
    data->continuation(data, rv);
  }
  free(data->fire_info);
  free(data);
}

void NQ_Trigger_issue(NQ_Trigger_Callback call, NQ_Transaction transaction, NQ_Trigger_Description *description, 
		      NQ_Trigger_Fire_Info *fire_info,
		      void *userdata, NQ_Trigger_Continuation cont){
  NQ_Trigger_Call_Data *data = malloc(sizeof(NQ_Trigger_Call_Data));
  bzero(data, sizeof(NQ_Trigger_Call_Data));
  
  data->call = call;
  data->transaction = transaction;
  data->description = description;

  data->fire_info = fire_info;
  data->userdata = userdata;
  data->continuation = cont;

  // printf("User_call_async(%p->%p)\n", data, data->call);
  NQ_user_call_async(NQ_Trigger_call_async, data);
}

static void NQ_Trigger_match_and_defer_one(
  NQ_Attribute_Trigger *trigger,
  NQ_Attribute_Trigger_Context *t_ctx,
  NQ_Trigger_Type type
  ){
  if(!(trigger->description->type == type)){
    return;
  }
  if(!NQ_UUID_eq(&trigger->description->tuple, &NQ_uuid_error)){
    if(!NQ_UUID_eq(&trigger->description->tuple, &t_ctx->tuple)){
      return;
    }
  }
  // this is less likely to fail, so put it second (the NQ_UUID_eq test is more selective)
  if(!NQ_Trigger_is_locally_valid(&t_ctx->transaction, trigger)){
    return;
  }

  //NQ_Trigger_defer(trigger->callback, t_ctx->transaction, trigger->description, trigger->userdata);
  NQ_Trigger_defer(&t_ctx->transaction, trigger->description, trigger->id, trigger->cb_id);
  // printf("===>Deferred trigger\n");
}
static void NQ_Trigger_match_and_defer_helper(
  Queue *trigger_list,
  NQ_Attribute_Trigger_Context *t_ctx,
  NQ_Trigger_Type type
  ){
  NQ_Attribute_Trigger *curr;
  int i, cnt = trigger_list->len;

  if(cnt == 0) {
    return;
  }
  
  for(i = 0, curr = queue_gethead(trigger_list); (i < cnt) && (curr != NULL) ; i++, curr = queue_getnext(curr)){
    NQ_Trigger_match_and_defer_one(curr, t_ctx, type);
  }
}

int NQ_Trigger_match_and_defer(
  NQ_Attribute_Trigger_Context *t_ctx,
  NQ_Trigger_Type type
  ){
  if(t_ctx->name_entry){
    //handle everything that might be appropriate for this guy
    NQ_TriggerSet_match_and_fire(t_ctx->name_entry->triggers, &t_ctx->transaction, &t_ctx->tuple, type);
    NQ_TriggerSet_match_and_fire(t_ctx->name_entry->triggers, &t_ctx->transaction, &NQ_uuid_null, type);
  }
  if(t_ctx->tuple_entry){
    NQ_Trigger_match_and_defer_helper(&t_ctx->tuple_entry->triggers, t_ctx, type);
  }
  return 0;
}

struct NQ_Attribute_Common_COW_Log;
struct NQ_Attribute_Common_COW_Record;

typedef struct NQ_Attribute_Common_COW_Record_Ops {
  void (*do_commit)(struct NQ_Attribute_Common_COW_Record *val);
  void (*do_dealloc)(struct NQ_Attribute_Common_COW_Record *val);
} NQ_Attribute_Common_COW_Record_Ops;

typedef struct NQ_Attribute_Common_COW_Record {
  struct NQ_Attribute_Common_COW_Record *next, *prev;
  struct NQ_Attribute_Common_COW_Log *target;
  NQ_Attribute_Common_COW_Record_Ops *ops;
  int already_on_writerecords;
  NQ_Transaction transaction;
  NQ_Principal *attributed_to;
} NQ_Attribute_Common_COW_Record;

void NQ_Attribute_Common_COW_Record_init(NQ_Attribute_Common_COW_Record *rec, struct NQ_Attribute_Common_COW_Log *target, NQ_Transaction transaction, NQ_Attribute_Common_COW_Record_Ops *ops, NQ_Principal *attributed_to) {
  rec->next = NULL;
  rec->prev = NULL;
  rec->target = target;
  rec->transaction = transaction;
  rec->ops = ops;
  rec->already_on_writerecords = 0;
  rec->attributed_to = attributed_to;
  if(rec->attributed_to != NULL) {
    NQ_Principal_reserve(rec->attributed_to);
  }
}

void NQ_Attribute_Common_COW_Record_dealloc(NQ_Attribute_Common_COW_Record *rec) {
  NQ_Principal_delete(rec->attributed_to);
}

typedef struct NQ_Attribute_Common_COW_Log {
  Queue writerecords;
  unsigned int revision;
  NQ_Attribute_Common_COW_Record *lastwrite;
} NQ_Attribute_Common_COW_Log;

void NQ_Attribute_Common_COW_Log_init(NQ_Attribute_Common_COW_Log *log) {
  queue_initialize(&log->writerecords);
  log->revision = 1;
  log->lastwrite = NULL;
}

static int Common_read_test(NQ_Transaction transaction, void *userdata, int revision){
  NQ_Attribute_Common_COW_Record *record = userdata;
  return ((revision == 0)||(record->target->revision > revision))?-1:0;
}
NQ_Transaction_Step_Type NQ_Attribute_Common_read_transaction = {
  .callbacks = { NULL, NULL, Common_read_test }
};

int NQ_Attribute_Common_COW_Record_find(NQ_Attribute_Common_COW_Record *record, NQ_Transaction *transaction){
  return NQ_Transaction_subseteq(record->transaction, *transaction);
}

NQ_Attribute_Common_COW_Record *
find_read_val(NQ_Attribute_Common_COW_Log *val, NQ_Transaction *transaction) {
  NQ_Attribute_Common_COW_Record *record;
  if(!(record = queue_find(&val->writerecords, (PFany)NQ_Attribute_Common_COW_Record_find, transaction))){
    if(val->lastwrite){
      // val committed by other transaction
      // printf("\tlast_write(%p) of (%p.%p)\n", val->lastwrite, val, &val->writerecords);
      record = val->lastwrite;
    } else {
      return NULL;
    }
  } // else == val written by this transaction
  // printf("\trecord by this trans %p of (%p.%p)\n", record, val, &val->writerecords);

  NQ_Transaction_step(*transaction, &NQ_Attribute_Common_read_transaction, record, val->revision);
  return record;
}

static int Common_COW_commit(NQ_Transaction transaction, void *userdata, int revision){
  NQ_Attribute_Common_COW_Record *val = userdata;
  // OK to clear writerecords ; the increment of revision informs the obsolete snapshots to not try to remove themselves from the list.
  // delete writerecord from queue to clear its ->next and ->prev fields
  queue_delete(&val->target->writerecords, val);
  queue_initialize(&val->target->writerecords);
  val->target->revision++;

  val->ops->do_commit(val);
  return 0;
}
static int Common_COW_abort(NQ_Transaction transaction, void *userdata, int revision){
  NQ_Attribute_Common_COW_Record *val = userdata;
  if(val->target->revision == revision){
    // printf("===> delete writerecords(%p)\n", &val->target->writerecords);
    queue_delete(&val->target->writerecords, val);
  }
  val->ops->do_dealloc(val);
  return 0;
}

// Is there a conflict with another write?
static int Common_COW_test(NQ_Transaction transaction, void *userdata, int revision){
  NQ_Attribute_Common_COW_Record *val = userdata;
  return (val->target->revision > revision) ? -1 : 0;
}
NQ_Transaction_Step_Type NQ_Attribute_Common_COW_transaction = {
  .callbacks = { Common_COW_commit, Common_COW_abort, Common_COW_test }
};

///////////////////////////////////////// RAW

typedef struct NQ_Attribute_Raw {
  NQ_Attribute_Common_COW_Log common;
} NQ_Attribute_Raw;

typedef struct NQ_Attribute_Raw_Write_Record {
  NQ_Attribute_Common_COW_Record common;
  int size;
  unsigned char data[0];
} NQ_Attribute_Raw_Write_Record;

static void raw_dealloc_from_common(struct NQ_Attribute_Common_COW_Record *val) {
  NQ_Attribute_Common_COW_Record_dealloc(val);
  free(CONTAINER_OF(NQ_Attribute_Raw_Write_Record, common, val));
}

static void raw_commit(struct NQ_Attribute_Common_COW_Record *val) {
  if(val->target->lastwrite != NULL){
    raw_dealloc_from_common(val->target->lastwrite);
  }
  val->target->lastwrite = val;
}
int NQ_Attribute_Raw_print_one(NQ_Attribute_Raw_Write_Record *record, void *dummy){
  if(record == NULL){ printf("[(null)]\n"); }
  else { NQ_UUID_print(&record->common.transaction); printf("\n"); }
  return 0;
}

void NQ_Attribute_Raw_print_all(NQ_Attribute_Raw *val){
  //printf("Attribute: current: "); NQ_Attribute_Raw_print_one(val->lastwrite, NULL);
  queue_iterate(&val->common.writerecords, (PFany)&NQ_Attribute_Raw_print_one, NULL);
}

int NQ_Attribute_Raw_Write_Record_find(NQ_Attribute_Raw_Write_Record *record, NQ_Transaction *transaction){
  //printf("Record_Find: "); NQ_UUID_print(&record->transaction); printf(" == "); NQ_UUID_print(transaction); printf("\n");
  return NQ_Transaction_subseteq(record->common.transaction, *transaction);
}

NQ_Attribute_Common_COW_Record_Ops Raw_ops = {
  .do_commit = raw_commit,
  .do_dealloc = raw_dealloc_from_common,
};

int NQ_Attribute_Raw_read(
  NQ_Transaction transaction,
  NQ_Principal *actor_principal,
  NQ_Attribute_Trigger_Context *t_ctx,
  void *input, int input_len,
  void **output, int *output_len,
  void **attr,
  NQ_Principal **output_attributed_to
  ){
  NQ_Attribute_Raw *val = *attr;
  NQ_Attribute_Common_COW_Record *common_record;
  NQ_Attribute_Raw_Write_Record *record;
  
    if(!*attr) {
    *output = NULL;
    *output_len = 0;
    *output_attributed_to = NULL;
    return -1;
  }

  
  if( (common_record = find_read_val(&val->common, &transaction)) == NULL ) {
    // val created, not committed
      *output = NULL;
    *output_len = 0;
    return -1;
  }
    record = 
    CONTAINER_OF( NQ_Attribute_Raw_Write_Record, common, common_record);

    *output = malloc(record->size);
  memcpy(*output, record->data, record->size);
  *output_len = record->size;

  NQ_Principal_reserve(common_record->attributed_to);
  *output_attributed_to = common_record->attributed_to;
  return 0;
}

// if record == NULL, then only fires trigger
void record_value_change(  NQ_Transaction transaction,
			   NQ_Attribute_Trigger_Context *t_ctx,
			   NQ_Attribute_Common_COW_Log *log, 
			   NQ_Attribute_Common_COW_Record *record) {
  assert(record != NULL);
  if(!record->already_on_writerecords) {
    queue_prepend(&log->writerecords, record);
    record->already_on_writerecords = 1;
  }
  NQ_Trigger_match_and_defer(t_ctx, NQ_TRIGGER_VALUECHANGED);
}

int NQ_Attribute_Raw_write(
  NQ_Transaction transaction,
  NQ_Principal *actor_principal,
  NQ_Attribute_Trigger_Context *t_ctx,
  void *input, int input_len, 
  void **output, int *output_len,
  void **attr,
  NQ_Principal **output_attributed_to
  ){
  NQ_Attribute_Raw *val = *attr;
  NQ_Attribute_Raw_Write_Record *record;
  
    if(!*attr){
    *attr = val = malloc(sizeof(NQ_Attribute_Raw));
    NQ_Attribute_Common_COW_Log_init(&val->common);
  }
    
  record = malloc(sizeof(NQ_Attribute_Raw_Write_Record)+input_len);
  bzero(record, sizeof(NQ_Attribute_Raw_Write_Record)+input_len);
  NQ_Attribute_Common_COW_Record_init(&record->common, &val->common, transaction, &Raw_ops, actor_principal);
  record->size = input_len;
  memcpy(record->data, input, input_len);
  
  NQ_Transaction_step(transaction, &NQ_Attribute_Common_COW_transaction,
		      &record->common, val->common.revision);

  record_value_change(transaction, t_ctx, &val->common, &record->common);

    *output = NULL;
  *output_len = 0;
  *output_attributed_to = NULL;
  return 0;
}

void NQ_Attribute_Raw_print(NQ_Transaction transaction, void *attr){
  NQ_Attribute_Raw *val = attr;
  NQ_Attribute_Raw_Write_Record *record;
  NQ_Attribute_Common_COW_Record *common_record;
  
  if(!attr) {
    printf("(null)");
    return;
  }
  
  if(!(common_record = queue_find(&val->common.writerecords, (PFany)NQ_Attribute_Common_COW_Record_find, &transaction))){
    if(val->common.lastwrite){
      common_record = val->common.lastwrite;
    } else {
      printf("(null)");
      return;
    }
  }
  record = CONTAINER_OF(NQ_Attribute_Raw_Write_Record, common, common_record);

  print_hex(record->data, record->size);  
}

///////////////////////////////////////// SET

typedef struct NQ_Attribute_Set {
  Queue entries;
  Queue operations;
} NQ_Attribute_Set;

typedef struct NQ_Attribute_Set_Operation NQ_Attribute_Set_Operation;

typedef struct NQ_Attribute_Set_Entry {
  struct NQ_Attribute_Set_Entry *next, *prev;
  char *value;
  int len;
  NQ_Attribute_Set *set;
  NQ_Attribute_Set_Operation *firstop;
} NQ_Attribute_Set_Entry;

struct NQ_Attribute_Set_Operation {
  struct NQ_Attribute_Set_Operation *next, *prev;
  char *value;
  int len;
  int true_if_add;
  NQ_Transaction transaction;
  NQ_Attribute_Set *set;
  NQ_Attribute_Set_Entry *original;
  NQ_Attribute_Set_Operation *nextop;
};

typedef struct NQ_Attribute_Set_Value {
  char *value;
  int len;
  NQ_Transaction transaction;
} NQ_Attribute_Set_Value;

int NQ_Attribute_Set_Entry_find(NQ_Attribute_Set_Entry *entry, NQ_Attribute_Set_Value *value){
  return (value->len == entry->len) && (memcmp(entry->value, value->value, value->len) == 0);
}

int NQ_Attribute_Set_Operation_find(NQ_Attribute_Set_Operation *entry, NQ_Attribute_Set_Value *value){
  if(NQ_Transaction_subseteq(entry->transaction, value->transaction)){
    if(entry->len == value->len){
      if(memcmp(entry->value, value->value, value->len) == 0){
        return 1;
      }
    }
  }
  return 0;
}

int NQ_Attribute_Set_get(NQ_Transaction transaction, NQ_Attribute_Set *set, char *value, int len){
  NQ_Attribute_Set_Value query = { value, len, transaction };
  NQ_Attribute_Set_Operation *op;
  NQ_Attribute_Set_Entry *entry;
  
  if((op = queue_find(&set->operations, (PFany)&NQ_Attribute_Set_Operation_find, &query))){
    if(op->true_if_add){
      return 1;
    } else {
      return 0;
    }
  }
  
  if((entry = queue_find(&set->entries, (PFany)&NQ_Attribute_Set_Entry_find, &query))){
    return 1;
  }
  return 0;
}

static int Set_add_commit(NQ_Transaction transaction, void *userdata, int revision){
  NQ_Attribute_Set_Operation *oprecord = userdata;
  NQ_Attribute_Set_Entry *entry;
  NQ_Attribute_Set_Value query = { oprecord->value, oprecord->len, transaction };
  
  if(queue_find(&oprecord->set->entries, (PFany)&NQ_Attribute_Set_Entry_find, &query)){
    queue_delete(&oprecord->set->operations, oprecord);
    free(oprecord->value);
  } else {
    entry = malloc(sizeof(NQ_Attribute_Set_Entry));
    bzero(entry, sizeof(NQ_Attribute_Set_Entry));
    entry->value = oprecord->value;
    entry->len = oprecord->len;
    entry->set = oprecord->set;
    queue_prepend(&oprecord->set->entries, entry);
  }
  free(oprecord);
  return 0;
}
static int Set_add_abort(NQ_Transaction transaction, void *userdata, int revision){
  NQ_Attribute_Set_Operation *oprecord = userdata;
  queue_delete(&oprecord->set->operations, oprecord);
  free(oprecord->value);
  free(oprecord);
  return 0;
}

NQ_Transaction_Step_Type NQ_Attribute_Set_add_transaction = {
  .callbacks = { Set_add_commit, Set_add_abort, NULL }
};

int NQ_Attribute_Set_add(
  NQ_Transaction transaction,
  NQ_Principal *actor_principal,
  NQ_Attribute_Trigger_Context *t_ctx,
  void *input, int input_len, 
  void **output, int *output_len,
  void **attr,
  NQ_Principal **output_attributed_to
  ){
  NQ_Attribute_Set *set = *attr;
  NQ_Attribute_Set_Entry *entry;
  NQ_Attribute_Set_Value query = { input, input_len, transaction };
  NQ_Attribute_Set_Operation *oprecord;
  
  *output = NULL;
  *output_len = 0;
  *output_attributed_to = NULL;

  if(set == NULL){
    set = *attr = malloc(sizeof(NQ_Attribute_Set));
    bzero(set, sizeof(NQ_Attribute_Set));
    queue_initialize(&set->entries);
    queue_initialize(&set->operations);
  }
  
  entry = queue_find(&set->entries, (PFany)&NQ_Attribute_Set_Entry_find, &query);
  
  if(entry) return 0; // it's already in
  
  oprecord = malloc(sizeof(NQ_Attribute_Set_Operation));
  bzero(oprecord, sizeof(NQ_Attribute_Set_Operation));
  oprecord->value = malloc(input_len);
  memcpy(oprecord->value, input, input_len);
  oprecord->len = input_len;
  oprecord->original = NULL;
  oprecord->true_if_add = 1;
  oprecord->set = set;
  
  NQ_Trigger_match_and_defer(t_ctx, NQ_TRIGGER_VALUECHANGED);
  
  NQ_Transaction_step(transaction, &NQ_Attribute_Set_add_transaction, oprecord, 0);
  
  return 0;
}

static int Set_remove_commit(NQ_Transaction transaction, void *userdata, int revision){
  NQ_Attribute_Set_Operation *oprecord = userdata, *curr;
  NQ_Attribute_Set_Entry *original = oprecord->original;
  
  if(original){
    for(curr = oprecord->original->firstop; curr != NULL; curr = curr->nextop){
      curr->original = NULL;
    }
    free(oprecord->original->value);
    free(oprecord->original);
  }
  free(oprecord->value);
  free(oprecord);
  
  return 0;
}
static int Set_remove_abort(NQ_Transaction transaction, void *userdata, int revision){
  NQ_Attribute_Set_Operation *oprecord = userdata, *curr;
  
  if(oprecord->original){
    for(curr = oprecord->original->firstop; curr != NULL; curr = curr->nextop){
      if(curr->nextop == oprecord){
        curr->nextop = oprecord->nextop;
      }
    }
  
  }
  free(oprecord->value);
  free(oprecord);
  
  return 0;
}

NQ_Transaction_Step_Type NQ_Attribute_Set_remove_transaction = {
  .callbacks = { Set_remove_commit, Set_remove_abort, NULL }
};

int NQ_Attribute_Set_remove(
  NQ_Transaction transaction,
  NQ_Principal *actor_principal,
  NQ_Attribute_Trigger_Context *t_ctx,
  void *input, int input_len, 
  void **output, int *output_len,
  void **attr,
  NQ_Principal **output_attributed_to
  ){
  NQ_Attribute_Set *set = *attr;
  NQ_Attribute_Set_Entry *entry;
  NQ_Attribute_Set_Value query = { input, input_len, transaction };
  NQ_Attribute_Set_Operation *oprecord;
  
  *output = NULL;
  *output_len = 0;
  *output_attributed_to = NULL;
  
  entry = queue_find(&set->entries, (PFany)&NQ_Attribute_Set_Entry_find, &query);
  oprecord = queue_find(&set->operations, (PFany)&NQ_Attribute_Set_Operation_find, &query);
  
  if(!entry){
    if(!oprecord){
      return 0; //it doesn't exist yet.
    } else if(!oprecord->true_if_add){
      return 0; //anything this transaction added has already been deleted
    }
  } else {
    if((oprecord)&&(!oprecord->true_if_add)){
      return 0; //already been deleted
    }
  }
  
  oprecord = malloc(sizeof(NQ_Attribute_Set_Operation));
  bzero(oprecord, sizeof(NQ_Attribute_Set_Operation));
  oprecord->value = malloc(input_len);
  memcpy(oprecord->value, input, input_len);
  oprecord->len = input_len;
  oprecord->set = set;
  oprecord->original = entry;
  oprecord->true_if_add = 0;
  
  if(entry){
    oprecord->nextop = entry->firstop;
    entry->firstop = oprecord;
  }
  
  NQ_Trigger_match_and_defer(t_ctx, NQ_TRIGGER_VALUECHANGED);
  
  NQ_Transaction_step(transaction, &NQ_Attribute_Set_remove_transaction, oprecord, 0);
  
  return 0;
}
static int Set_contains_test(NQ_Transaction transaction, void *userdata, int revision){
  NQ_Attribute_Set_Operation *oprecord = userdata, *curr;
  int ret = 0;
  
  if(oprecord->original){
    for(curr = oprecord->original->firstop; curr != NULL; curr = curr->nextop){
      if(curr->nextop == oprecord){
        curr->nextop = oprecord->nextop;
      }
    }
    ret = 1;
  } else {
    ret = (revision == NQ_Attribute_Set_get(transaction, oprecord->set, oprecord->value, oprecord->len));
  }
  free(oprecord->value);
  free(oprecord);
  
  return ret;
}

NQ_Transaction_Step_Type NQ_Attribute_Set_contains_transaction = {
  .callbacks = { NULL, NULL, Set_contains_test }
};
int NQ_Attribute_Set_contains(
  NQ_Transaction transaction,
  NQ_Principal *actor_principal,
  NQ_Attribute_Trigger_Context *t_ctx,
  void *input, int input_len, 
  void **output, int *output_len,
  void **attr,
  NQ_Principal **output_attributed_to
  ){
  NQ_Attribute_Set *set = *attr;
  NQ_Attribute_Set_Entry *entry = NULL;
  NQ_Attribute_Set_Value query = { input, input_len, transaction };
  NQ_Attribute_Set_Operation *oprecord;
  int ret = 0;
  
  *output = NULL;
  *output_len = 0;
  *output_attributed_to = NULL;
  fprintf(stderr, "XXX NQ_Attribute_Set_contains() does not support attribution\n");
  
  if(set == NULL) return -1;
  
  oprecord = queue_find(&set->operations, (PFany)&NQ_Attribute_Set_Operation_find, &query);
  //operations in this transaction trump whatever's globally visible.
  if(oprecord){
    if(!oprecord->true_if_add){
      // the most recent operation was a delete
      ret = 0;
    } else {
      // the most recent operation as an add
      ret = 1;
    }
  } else {
    entry = queue_find(&set->entries, (PFany)&NQ_Attribute_Set_Entry_find, &query);
    if(entry){
      ret = 1;
    } else {
      ret = 0;
    }
  }
  
  oprecord = malloc(sizeof(oprecord));
  bzero(oprecord, sizeof(oprecord));
  oprecord->value = malloc(input_len);
  memcpy(oprecord->value, input, input_len);
  oprecord->set = set;
  oprecord->original = entry;
  if(entry){
    oprecord->nextop = entry->firstop;
    entry->firstop = oprecord;
  }

  NQ_Transaction_step(transaction, &NQ_Attribute_Set_contains_transaction, oprecord, ret);
    
  return ret;
}
void NQ_Attribute_Set_print(NQ_Transaction transaction, void *attr){

}

///////////////////////////////////////// TRIE

#include "attribute_trie.c"

///////////////////////////////////////// VECTOR
typedef struct NQ_Attribute_Vector_Data {
  NQ_Attribute_Common_COW_Record common;
  size_t num_elems;
  size_t capacity;
  size_t elem_size; // can't keep information in NQ_Attribute_Vector without complicating abort

  // Data is of the form:
  // struct { int is_valid; char data[0]; }
  unsigned char *data;
} NQ_Attribute_Vector_Data;

typedef struct NQ_Attribute_Vector {
  NQ_Attribute_Common_COW_Log common;
  int type;
} NQ_Attribute_Vector;

static inline NQ_Attribute_Vector_Data *
NQ_Attribute_Vector_Data_new(NQ_Attribute_Vector *vec, NQ_Transaction transaction, NQ_Principal *actor, int elem_size, int num_elems);

static inline size_t NQ_Attribute_Vector_data_size(size_t elem_size, int num_elems);

static inline int *NQ_Attribute_Vector_nth_helper(NQ_Attribute_Vector *vec, NQ_Attribute_Vector_Data *vec_data, int nth) {
  return (int *) (vec_data->data + nth * (sizeof(int) + vec_data->elem_size));
}

static inline unsigned char *NQ_Attribute_Vector_nth(NQ_Attribute_Vector *vec, NQ_Attribute_Vector_Data *vec_data, int nth, int *is_valid) {
  int *valid_p = NQ_Attribute_Vector_nth_helper(vec, vec_data, nth);
  *is_valid = *valid_p;
  return (unsigned char *) (valid_p + 1);
}

static inline void NQ_Attribute_Vector_set_valid(NQ_Attribute_Vector *vec, NQ_Attribute_Vector_Data *vec_data, int nth, int valid) {
  int *valid_p = NQ_Attribute_Vector_nth_helper(vec, vec_data, nth);
  *valid_p = valid;
}

static void vec_dealloc(NQ_Attribute_Vector_Data *vec_data) {
  NQ_Attribute_Common_COW_Record_dealloc(&vec_data->common);
  free(vec_data->data);
  free(vec_data);
}

static void vec_dealloc_from_common(struct NQ_Attribute_Common_COW_Record *val) {
  vec_dealloc(CONTAINER_OF(NQ_Attribute_Vector_Data, common, val));
}

static void vec_commit(struct NQ_Attribute_Common_COW_Record *val) {
  // printf("vec_commit (%p)\n", val->target);
  if(val->target->lastwrite == NULL){
    assert(val->next == NULL && val->prev == NULL);
    val->target->lastwrite = val;
    return;
  }
  // Detect multiple free
  assert(val->target->lastwrite != val);
  NQ_Attribute_Vector_Data 
    *old_data = CONTAINER_OF(NQ_Attribute_Vector_Data, common, val->target->lastwrite);
  assert(val->target->lastwrite->next == NULL && val->target->lastwrite->prev == NULL);
  vec_dealloc(old_data);
  val->target->lastwrite = val;
}

// Get a copy of the vector for the local transaction

// Careful: Once a write copy is a created, a record_value_change() must be issued!
static NQ_Attribute_Vector_Data *
NQ_Attribute_Vector_get_transaction_copy(NQ_Attribute_Vector *val, NQ_Transaction transaction, NQ_Attribute_Trigger_Context *t_ctx, int for_write, NQ_Attribute_Common_COW_Record **record_ctx) {
  NQ_Attribute_Common_COW_Record *common_record =
    find_read_val(&val->common, &transaction);
  if(common_record == NULL) {
    printf("no initialized vector to copy from (%p), trans = ", &val->common); NQ_UUID_print(&transaction); printf("\n");
    return NULL;
  }
  NQ_Attribute_Vector_Data *vec_data =
    CONTAINER_OF(NQ_Attribute_Vector_Data, common, common_record);
  if(for_write) {
    if(common_record == val->common.lastwrite) {
      // Create a shadow object for this transaction
      NQ_Attribute_Vector_Data *old_vec_data = vec_data;
      vec_data = 
	NQ_Attribute_Vector_Data_new(val, transaction, old_vec_data->common.attributed_to, old_vec_data->elem_size, old_vec_data->capacity);
      vec_data->num_elems = old_vec_data->num_elems;
      memcpy(vec_data->data, old_vec_data->data, 
	     NQ_Attribute_Vector_data_size(vec_data->elem_size, vec_data->num_elems));
      common_record = &vec_data->common;

      // printf("vec stepped %p\n", &val->common);
      NQ_Transaction_step(transaction, &NQ_Attribute_Common_COW_transaction,
			  common_record, val->common.revision);
    } else {
      // else: using previously-instantiated copy for this transaction
    }
    *record_ctx = common_record;
  }

  return vec_data;
}

NQ_Attribute_Common_COW_Record_Ops Vector_ops = {
  .do_commit = vec_commit,
  .do_dealloc = vec_dealloc_from_common,
};

static inline size_t NQ_Attribute_Vector_data_size(size_t elem_size, int num_elems) {
  return num_elems * (sizeof(int) + elem_size);
}

static inline NQ_Attribute_Vector_Data *
NQ_Attribute_Vector_Data_new(NQ_Attribute_Vector *vec, NQ_Transaction transaction, NQ_Principal *actor, int elem_size, int num_elems) {
  NQ_Attribute_Vector_Data *new_vec_data = 
    (NQ_Attribute_Vector_Data *)malloc(sizeof(*new_vec_data));
  bzero(new_vec_data, sizeof(*new_vec_data));
  NQ_Attribute_Common_COW_Record_init(&new_vec_data->common, &vec->common, transaction, &Vector_ops, actor);
  new_vec_data->elem_size = elem_size;
  new_vec_data->num_elems = 0;
  new_vec_data->capacity = num_elems;
  int size = NQ_Attribute_Vector_data_size(elem_size, num_elems);
  new_vec_data->data = malloc(size);
  bzero(new_vec_data->data, size);
  return new_vec_data;
}

int NQ_Attribute_VectorOrTrie_create(
  NQ_Transaction transaction,
  NQ_Principal *actor,
  NQ_Attribute_Trigger_Context *t_ctx,
  void *input, int input_len, 
  void **output, int *output_len,
  void **attr,
  int type
  ){
  NQ_Create_Aggregate_Args *args;
  if(input_len < sizeof(NQ_Create_Aggregate_Args)) {
    fprintf(stderr, "arg length too short for create\n");
    return -1;
  }
  args = (NQ_Create_Aggregate_Args *) input;
  if(!(args->element_size > 0 && args->initial_capacity > 0)) {
    fprintf(stderr, "bad args to vector create\n");
    return -1;
  }

  switch(type) {
  case NQ_ATTRIBUTE_FAKE_TRIE:
    // Rewrite element size for trie to include header
    args->element_size += sizeof(NQ_FakeTrie_Header);
    break;
  case NQ_ATTRIBUTE_VECTOR:
    break;
  default:
    assert(0);
  }

  NQ_Attribute_Vector *val = *attr;
  if(val == NULL) {
    val = *attr = malloc(sizeof(NQ_Attribute_Vector));
    NQ_Attribute_Common_COW_Log_init(&val->common);
    val->type = type;
  }
  NQ_Attribute_Common_COW_Record *common_record =
    find_read_val(&val->common, &transaction);

  if(common_record == NULL) {
    NQ_Attribute_Vector_Data *new_vec_data =
      NQ_Attribute_Vector_Data_new(val, transaction, actor, args->element_size, args->initial_capacity);
    common_record = &new_vec_data->common;

    // printf("vec create %p, trans = ", &val->common); NQ_UUID_print(&transaction); printf("\n");
    NQ_Transaction_step(transaction, &NQ_Attribute_Common_COW_transaction,
			common_record, val->common.revision);

    record_value_change(transaction, t_ctx, &val->common, &new_vec_data->common);
  } else {
    fprintf(stderr, "Vector already created!\n");
    return -1;
  }

  *output = NULL;
  *output_len = 0;
  return 0;
}

int NQ_Attribute_Vector_create(
  NQ_Transaction transaction,
  NQ_Principal *actor_principal,
  NQ_Attribute_Trigger_Context *t_ctx,
  void *input, int input_len, 
  void **output, int *output_len,
  void **attr,
  NQ_Principal **output_attributed_to  ) {
  return NQ_Attribute_VectorOrTrie_create(transaction, actor_principal, t_ctx, input, input_len, output, output_len, attr, NQ_ATTRIBUTE_VECTOR);
}

int NQ_Attribute_Vector_load_nth(
  NQ_Transaction transaction,
  NQ_Principal *actor_principal,
  NQ_Attribute_Trigger_Context *t_ctx,
  void *input, int input_len, 
  void **output, int *output_len,
  void **attr,
  NQ_Principal **output_attributed_to  ){
  NQ_Load_Nth_Args *args = (NQ_Load_Nth_Args *) input;
  if(input_len < sizeof(*args)) {
    fprintf(stderr, "vector load nth args too short\n");
    return -1;
  }
  if(*attr == NULL) {
    fprintf(stderr, "vector not created\n");
    return -1;
  }
  NQ_Attribute_Vector *val = *attr;
  NQ_Attribute_Vector_Data *vec_data =
    NQ_Attribute_Vector_get_transaction_copy(val, transaction, t_ctx, 0, NULL);

  if(vec_data == NULL) {
    fprintf(stderr, "no value found for load_nth\n");
    return -1;
  }
  if(!((0 <= args->index) && (args->index < vec_data->num_elems))) {
    fprintf(stderr, "index out of range\n");
    return -1;
  }
  int is_valid;
  unsigned char *data =
    NQ_Attribute_Vector_nth(val, vec_data, args->index, &is_valid);
  if(!is_valid) {
    fprintf(stderr, "trying to load invalid value\n");
    return -1;
  }

  *output = malloc(vec_data->elem_size);
  memcpy(*output, data, vec_data->elem_size);
  *output_len = vec_data->elem_size;

  NQ_Principal_reserve(vec_data->common.attributed_to);
  *output_attributed_to = vec_data->common.attributed_to;

  return 0;
}

int NQ_Attribute_Vector_store_nth(
  NQ_Transaction transaction,
  NQ_Principal *actor_principal,
  NQ_Attribute_Trigger_Context *t_ctx,
  void *input, int input_len, 
  void **output, int *output_len,
  void **attr,
  NQ_Principal **output_attributed_to  ){
  NQ_Store_Nth_Args *args = (NQ_Store_Nth_Args *) input;
  if(input_len < sizeof(*args)) {
    fprintf(stderr, "vector store nth args too short\n");
    return -1;
  }
  if(*attr == NULL) {
    fprintf(stderr, "vector not created\n");
    return -1;
  }
  NQ_Attribute_Vector *vec = (NQ_Attribute_Vector *) *attr;
  if(args->index < 0) {
    fprintf(stderr, "index out of range\n");
    return -1;
  }

  unsigned char *input_data = (unsigned char *)(args + 1);
  int input_data_len = input_len - sizeof(NQ_Store_Nth_Args);

  NQ_Attribute_Common_COW_Record *record_ctx;
  NQ_Attribute_Vector_Data *vec_data =
    NQ_Attribute_Vector_get_transaction_copy(vec, transaction, t_ctx, 1, &record_ctx);
  if(vec_data == NULL) {
    fprintf(stderr, "could not find transaction copy\n");
    return -1;
  }
  // Do NOT bypass the record_value_change() call later in this function
  int err = 0;
  if(input_data_len != vec_data->elem_size) {
    // Defer error handling
    fprintf(stderr, "wrong element size\n");
    err = -1;
    input_data_len = 0;
  }
  if(args->index >= vec_data->capacity) {
    int new_capacity = vec_data->capacity * 2;
    while(new_capacity <= args->index) { new_capacity *= 2; }
    unsigned char *new_data = 
      malloc(NQ_Attribute_Vector_data_size(vec_data->elem_size, new_capacity));
    unsigned char *old_data = vec_data->data;
    memcpy(new_data, old_data, NQ_Attribute_Vector_data_size(vec_data->elem_size, vec_data->capacity));
    vec_data->data = new_data;
    vec_data->capacity = new_capacity;
    free(old_data);
  }
  if(args->index >= vec_data->num_elems) {
    int i;
    for(i = vec_data->num_elems; i < args->index; i++) {
      NQ_Attribute_Vector_set_valid(vec, vec_data, i, 0);
    }
    vec_data->num_elems = args->index + 1;
  }
  int is_valid;
  memcpy(NQ_Attribute_Vector_nth(vec, vec_data, args->index, &is_valid),
	 input_data, input_data_len);
  NQ_Attribute_Vector_set_valid(vec, vec_data, args->index, 1);

  // printf("vec value changed %p\n", &vec->common);
  record_value_change(transaction, t_ctx, &vec->common, record_ctx);

  *output = NULL;
  *output_len = 0;
  *output_attributed_to = NULL;
  return err;
}

int NQ_Attribute_Vector_truncate(
  NQ_Transaction transaction,
  NQ_Principal *actor_principal,
  NQ_Attribute_Trigger_Context *t_ctx,
  void *input, int input_len, 
  void **output, int *output_len,
  void **attr,
  NQ_Principal **output_attributed_to  ){
  if(*attr == NULL) {
    fprintf(stderr, "vector not created\n");
    return -1;
  }
  NQ_Attribute_Vector *vec = *attr;

  NQ_Attribute_Common_COW_Record *record_ctx;
  NQ_Attribute_Vector_Data *vec_data =
    NQ_Attribute_Vector_get_transaction_copy(vec, transaction, t_ctx, 1, &record_ctx);
  if(vec_data == NULL) {
    return -1;
  }

  vec_data->num_elems = 0;
  record_value_change(transaction, t_ctx, &vec->common, record_ctx);
  
  *output = NULL;
  *output_len = 0;
  return 0;
}

int NQ_Attribute_Vector_num_elems (
  NQ_Transaction transaction,
  NQ_Principal *actor_principal,
  NQ_Attribute_Trigger_Context *t_ctx,
  void *input, int input_len, 
  void **output, int *output_len,
  void **attr,
  NQ_Principal **output_attributed_to  ){
  if(*attr == NULL) {
    fprintf(stderr, "vector not created\n");
    return -1;
  }
  NQ_Attribute_Vector *vec = *attr;

  NQ_Attribute_Vector_Data *vec_data =
    NQ_Attribute_Vector_get_transaction_copy(vec, transaction, t_ctx, 0, NULL);

  if(vec_data == NULL) {
    fprintf(stderr, "no valid version of vector %p\n", &vec->common);
    return -1;
  }
  
  *output = malloc(sizeof(int));
  *(int*)*output = vec_data->num_elems;
  *output_len = sizeof(int);
  *output_attributed_to = NULL;
  return 0;
}

void NQ_Attribute_Vector_print(NQ_Transaction transaction, void *attr){
  assert(0);
}

struct EnumerateContext {
  int table_count;
  int value_count;
  NQ_RingBuffer *output;
  NQ_UUID_Table *table;
};

int process_value(void *entry, void *_ctx) {
  struct EnumerateContext *ctx = (struct EnumerateContext *)_ctx;
  NQ_Attribute_Value *value = (NQ_Attribute_Value *) entry;

  if( NQ_UUID_Table_find(ctx->table, &value->tuple) != NULL ) {
    // tuple already in table
    return 0;
  }
  NQ_UUID_Table_insert(ctx->table, &value->tuple, &value->tuple);
  ctx->value_count++;
  return 0;
}

int output_value(void *entry, void *_ctx) {
  NQ_RingBuffer *output = (NQ_RingBuffer *)_ctx;
  NQ_Tuple *tuple = (NQ_Tuple *) entry;
  NQ_Request_pickle_uuid(output, *tuple);
  return 0;
}

static void process_attribute_value_table(const void *key, void *entry, void *_ctx) {
  struct EnumerateContext *ctx = (struct EnumerateContext *)_ctx;
  NQ_Attribute_Value_Table *table = (NQ_Attribute_Value_Table *) entry;
  NQ_UUID_Table_each(table->val_table, NQ_uuid_null /* transaction */,
		     NQ_UUID_TUPLE, process_value, ctx);
  ctx->table_count++;
}

int NQ_Local_Enumerate_Tuples(NQ_RingBuffer *output) {
  struct EnumerateContext ctx = {
    .table_count = 0,
    .value_count = 0,
    .output = output,
    .table = NQ_UUID_Table_new(),
  };

  hashtable_iterate(NQ_Attribute_values, process_attribute_value_table, &ctx);

  int num_tuples = NQ_UUID_Table_size(ctx.table);
  assert(num_tuples == ctx.value_count);
  int check_val = hashtable_count(NQ_Attribute_values);
  assert(ctx.table_count == check_val);

  NQ_Request_pickle_int(output, num_tuples);
  NQ_UUID_Table_each(ctx.table, NQ_uuid_null, 
		     NQ_UUID_TUPLE, output_value, ctx.output);
  // printf("Table count = %d, value count = %d\n", ctx.table_count, ctx.value_count);

  NQ_UUID_Table_destroy(ctx.table);
  return 0;
}

struct EnumerateTriggersContext {
  int trigger_count;
  NQ_RingBuffer *output;
};

static int count_trigger_table(void *entry, void *_ctx) {
  struct EnumerateTriggersContext *ctx = (struct EnumerateTriggersContext *)_ctx;
  ctx->trigger_count++;
  return 0;
}

static void count_triggerset(NQ_Tuple tid, NQ_UUID_Table *table, void *_ctx) {
  struct EnumerateTriggersContext *ctx = (struct EnumerateTriggersContext *)_ctx;
  NQ_UUID_Table_each(table, NQ_uuid_null, NQ_UUID_TRIGGER, count_trigger_table, ctx);
}
static void count_total_triggers(const void *key, void *entry, void *_ctx) {
  struct EnumerateTriggersContext *ctx = (struct EnumerateTriggersContext *)_ctx;
  NQ_Attribute_Value_Table *table = (NQ_Attribute_Value_Table *) entry;
  NQ_TriggerSet_iterate(table->triggers, count_triggerset, ctx);
}

static int marshall_trigger_table(void *entry, void *_ctx) {
  NQ_RingBuffer *output = (NQ_RingBuffer *)_ctx;
  NQ_Attribute_Trigger *trigger = (NQ_Attribute_Trigger *) entry;
  NQ_Request_pickle_trigger_description(output, trigger->description);
  NQ_Request_pickle_uuid(output, trigger->cb_id);
  return 0;
}

static void marshall_triggerset(NQ_Tuple tid, NQ_UUID_Table *table, void *_ctx) {
  NQ_RingBuffer *output = (NQ_RingBuffer *)_ctx;
  NQ_UUID_Table_each(table, NQ_uuid_null, NQ_UUID_TRIGGER, marshall_trigger_table, output);
}

static void marshall_triggers(const void *key, void *entry, void *_ctx) {
  NQ_RingBuffer *output = (NQ_RingBuffer *)_ctx;
  NQ_Attribute_Value_Table *table = (NQ_Attribute_Value_Table *) entry;
  NQ_TriggerSet_iterate(table->triggers, marshall_triggerset, output);
}

int NQ_Local_Enumerate_Triggers(struct NQ_RingBuffer *output) {
  struct EnumerateTriggersContext ctx = {
    .trigger_count = 0,
    .output = output,
  };

  hashtable_iterate(NQ_Attribute_values, count_total_triggers, &ctx);

  int num_tuples = ctx.trigger_count;

  NQ_Request_pickle_int(output, num_tuples);
  hashtable_iterate(NQ_Attribute_values, marshall_triggers, output);
  // printf("Table count = %d, value count = %d\n", ctx.table_count, ctx.value_count);
  return 0;
}

int NQ_Enumerate_Tuples(NQ_Host host, NQ_Tuple **out, int *out_count) {
  return NQ_Net_Enumerate_Tuples(host, out, out_count);
}

int NQ_Enumerate_Attributes(NQ_Host host, NQ_Tuple tuple, NQ_Attribute_Name ***out, int *out_count) {
  return NQ_Net_Enumerate_Attributes(host, tuple, out, out_count);
}

int NQ_Enumerate_Triggers(NQ_Host host, NQ_Trigger_Desc_and_Dest **out, int *out_count) {
  return NQ_Net_Enumerate_Triggers(host, out, out_count);
}

#if 0
int NQ_Enumerate_Tuple_Triggers(NQ_Host host, NQ_Tuple tuple, NQ_Trigger_Desc_and_Dest **out, int *out_count) {
  return NQ_Net_Enumerate_Tuple_Triggers(host, tuple, out, out_count);
}
#endif

int dump_set;
