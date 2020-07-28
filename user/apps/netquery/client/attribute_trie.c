//
// A simple trie implementation.
// included in attribute.c
//

#include <nq/trie.h>
#include "fib_trie.h"

#define DO_INTEGRITY_CHECK (1)

typedef struct NQ_Attribute_Trie {
  NQ_Attribute_Common_COW_Log common;
  NQ_Trie *trie;
#if 0
  Queue tentative_ops;
#endif
} NQ_Attribute_Trie;

typedef struct NQ_Attribute_Trie_Data {
  NQ_Attribute_Common_COW_Record common;
  NQ_Attribute_Trie *parent;
  size_t elem_size;
  int is_truncated; // if truncated = 1, ignore parent->trie

  // Inserted + deleted are both always up to date. If something is deleted, it's added to deleted and removed from inserted
  // If something is inserted, it's removed from deleted and added to inserted

  NQ_Trie *inserted_trie;
  NQ_Trie *deleted_trie;
} NQ_Attribute_Trie_Data;

static void NQ_Attribute_Trie_Data_destroy(NQ_Attribute_Trie_Data *data);
static int NQ_Attribute_Trie_Data_num_elems(NQ_Attribute_Trie_Data *trie_data);

static void trie_dealloc_from_common(struct NQ_Attribute_Common_COW_Record *val) {
  NQ_Attribute_Common_COW_Record_dealloc(val);
  NQ_Attribute_Trie_Data *data = 
    CONTAINER_OF(NQ_Attribute_Trie_Data, common, val);
  NQ_Attribute_Trie_Data_destroy(data);
}

void free_entry(NQ_Trie_Entry *entry) {
  free(entry->value);
}

static void truncate_and_free(NQ_Trie *trie) {
  int i;
  NQ_Trie_Entry entry;
  for(i = 0; NQ_Trie_load_nth(trie, i, &entry) == 0; i++) {
    if(entry.value != NULL) {
      free(entry.value);
    }
  }
  NQ_Trie_truncate(trie);
}

static void trie_commit(struct NQ_Attribute_Common_COW_Record *val) {
  // printf("commit trie(%p)\n", val);
  if(val->target->lastwrite != NULL){
    trie_dealloc_from_common(val->target->lastwrite);
  }
  NQ_Attribute_Trie_Data *data = 
    CONTAINER_OF(NQ_Attribute_Trie_Data, common, val);

  if(data->is_truncated) {
    truncate_and_free(data->parent->trie);
    data->is_truncated = 0;
  }
  NQ_Trie_set_subtract(data->parent->trie, data->deleted_trie, free_entry);
  NQ_Trie_set_add(data->parent->trie, data->inserted_trie, free_entry);
  // truncate, but don't free contents (they were merged into the trie)
  NQ_Trie_truncate(data->deleted_trie);
  NQ_Trie_truncate(data->inserted_trie);
  val->target->lastwrite = val;
}

NQ_Attribute_Common_COW_Record_Ops Trie_ops = {
  .do_commit = trie_commit,
  .do_dealloc = trie_dealloc_from_common,
};

static NQ_Attribute_Trie_Data *
NQ_Attribute_Trie_Data_new(NQ_Attribute_Trie *val, NQ_Transaction transaction, NQ_Principal *actor, size_t elem_size) {
  NQ_Attribute_Trie_Data *new_data = 
    (NQ_Attribute_Trie_Data *)malloc(sizeof(*new_data));
  bzero(new_data, sizeof(*new_data));
  NQ_Attribute_Common_COW_Record_init(&new_data->common, &val->common, transaction, &Trie_ops, actor);

  // printf("parent = %p\n", val);
  new_data->parent = val;
  new_data->elem_size = elem_size;
  new_data->inserted_trie = NQ_Trie_new();
  new_data->deleted_trie = NQ_Trie_new();

  return new_data;
}

static void NQ_Attribute_Trie_Data_destroy(NQ_Attribute_Trie_Data *data) {
  NQ_Trie_delete(data->inserted_trie);
  NQ_Trie_delete(data->deleted_trie);
  free(data);
}

static NQ_Attribute_Trie_Data *
NQ_Attribute_Trie_Data_get_transaction_copy(NQ_Attribute_Trie *val, NQ_Transaction transaction,  NQ_Attribute_Trigger_Context *t_ctx, int for_write, NQ_Attribute_Common_COW_Record **record_ctx) {
  NQ_Attribute_Common_COW_Record *common_record =
    find_read_val(&val->common, &transaction);
  if(common_record == NULL) {
    printf("no initialized trie to copy from (%p), trans = ", &val->common); NQ_UUID_print(&transaction); printf("\n");
    return NULL;
  }

  NQ_Attribute_Trie_Data *trie_data =
    CONTAINER_OF(NQ_Attribute_Trie_Data, common, common_record);

  if(for_write) {
    if(common_record == val->common.lastwrite) {
      // Create a shadow object for this transaction
      NQ_Attribute_Trie_Data *old_trie_data = trie_data;
      // num_elems() is potentially slow O(n), but the following will
      // only be slow if assertion fails
      assert(NQ_Trie_num_elems(old_trie_data->inserted_trie) == 0 &&
             NQ_Trie_num_elems(old_trie_data->deleted_trie) == 0);
      trie_data = NQ_Attribute_Trie_Data_new(val, transaction, old_trie_data->common.attributed_to, old_trie_data->elem_size);
      common_record = &trie_data->common;

      // printf("vec stepped %p\n", &val->common);
      NQ_Transaction_step(transaction, &NQ_Attribute_Common_COW_transaction,
			  common_record, val->common.revision);
    } else {
      // else: using previously-instantiated copy for this transaction
    }
    if(record_ctx != NULL) {
      *record_ctx = common_record;
    }
  }
  return trie_data;
}

static void NQ_Attribute_Trie_Data_truncate(NQ_Attribute_Trie_Data *trie_data) {
  trie_data->is_truncated = 1;
  truncate_and_free(trie_data->inserted_trie);
  truncate_and_free(trie_data->deleted_trie);
}

static int NQ_Attribute_Trie_Data_num_elems(NQ_Attribute_Trie_Data *trie_data) {
  if(trie_data->is_truncated || 
     NQ_Trie_num_elems(trie_data->inserted_trie) > 0 ||
     NQ_Trie_num_elems(trie_data->deleted_trie) > 0) {
    printf("Unimplemented\n");
    return -1;
  } else {
    return NQ_Trie_num_elems(trie_data->parent->trie);
  }
}

NQ_Trie *load_nth_trie;
static int NQ_Attribute_Trie_Data_load_nth(NQ_Attribute_Trie_Data *trie_data, int index, NQ_Trie_Entry *entry) {
  if(trie_data->is_truncated ||
     NQ_Trie_num_elems(trie_data->inserted_trie) > 0 ||
     NQ_Trie_num_elems(trie_data->deleted_trie) > 0) {
    printf("Unimplemented\n");
    return -1;
  } else {
    load_nth_trie = trie_data->parent->trie;
    return NQ_Trie_load_nth(trie_data->parent->trie, index, entry);
  }
}

static int NQ_Attribute_Trie_Data_lookup(NQ_Attribute_Trie_Data *trie_data, uint32_t path, NQ_Trie_Entry *entry) {
  NQ_Trie_Entry parent, inserted;
  int found = 0;
  int found_parent = 
    (trie_data->is_truncated ? 
     0 : !NQ_Trie_lookup(trie_data->parent->trie, path, &parent));
  int found_inserted = 
    !NQ_Trie_lookup(trie_data->inserted_trie, path, &inserted);

  if(found_parent) {
    NQ_Trie_Entry deleted;
    if(!NQ_Trie_lookup_exact(trie_data->deleted_trie, parent.header.prefix, parent.header.prefix_len, &deleted)) {
      // found a matching deleted entry
      // SLOW PATH
      printf("Trie lookup slow path\n");
      int prefix_len = parent.header.prefix_len - 1;
      while(prefix_len > 0) {
        uint32_t prefix = path & ntohl(inet_make_mask(prefix_len));
        if(!NQ_Trie_lookup_exact(trie_data->parent->trie,
                                 prefix, prefix_len, &parent) &&
           NQ_Trie_lookup_exact(trie_data->deleted_trie,
                                prefix, prefix_len, &deleted)) {
          found = 1;
          break;
        }
        prefix_len--;
      }
    } else {
      found = 1;
    }
  }
  // if the inserted one is longer, take it
  // need to put this test 2nd in case the original one we found was deleted
  if(found) {
    // assign longest match to *entry
    if(found_inserted && inserted.header.prefix_len >= parent.header.prefix_len) {
      *entry = inserted;
    } else {
      *entry = parent;
    }
    return 0;
  } else {
    if(found_inserted) {
      *entry = inserted;
      return 0;
    } else {
      memset(entry, 0, sizeof(*entry));
      return -1;
    }
  }
}

static void NQ_Attribute_Trie_Data_update(NQ_Attribute_Trie_Data *trie_data, NQ_Trie_Index_Args *args, void *data) {
  // responsible for malloc & copying 

  NQ_Trie_Entry entry;
  NQ_Trie_remove(trie_data->deleted_trie, args->prefix, args->prefix_len);

  if(NQ_Trie_lookup_exact(trie_data->inserted_trie, args->prefix, args->prefix_len, &entry) == 0) {
    printf("overwrite existing entry\n");
    // remove existing entry
    free(entry.value);
  }
  entry.header = *args;
  entry.value = malloc(trie_data->elem_size);
  memcpy(entry.value, data, trie_data->elem_size);
  NQ_Trie_write(trie_data->inserted_trie, &entry);

  // printf("Malloc "); NQ_Trie_Entry_print(&entry);
}

static int NQ_Attribute_Trie_Data_remove(NQ_Attribute_Trie_Data *trie_data, NQ_Trie_Index_Args *args) {
  // This function is responsible for free
  NQ_Trie_Entry placeholder;
  placeholder.header = *args;
  placeholder.value = NULL;
  NQ_Trie_write(trie_data->deleted_trie, &placeholder);

  NQ_Trie_Entry entry;

  if(NQ_Trie_lookup_exact(trie_data->inserted_trie, args->prefix, args->prefix_len, &entry) == 0) {
    free(entry.value);
    NQ_Trie_remove(trie_data->inserted_trie, args->prefix, args->prefix_len);
  }
  return 0;
}

/////

int NQ_Attribute_Trie_create(
  NQ_Transaction transaction,
  NQ_Principal *actor_principal,
  NQ_Attribute_Trigger_Context *t_ctx,
  void *input, int input_len, 
  void **output, int *output_len,
  void **attr,
  NQ_Principal **output_attributed_to
  ) {
  NQ_Create_Aggregate_Args *args;
  if(input_len < sizeof(NQ_Create_Aggregate_Args)) {
    fprintf(stderr, "arg length too short for create\n");
    return -1;
  }
  args = (NQ_Create_Aggregate_Args *) input;
  if(!(args->element_size > 0 && args->initial_capacity > 0)) {
    fprintf(stderr, "bad args to trie create\n");
    return -1;
  }

  NQ_Attribute_Trie *val = *attr;
  if(val == NULL) {
    val = *attr = malloc(sizeof(NQ_Attribute_Trie));
    NQ_Attribute_Common_COW_Log_init(&val->common);
    val->trie = NQ_Trie_new();
  }
  NQ_Attribute_Common_COW_Record *common_record =
    find_read_val(&val->common, &transaction);

  if(common_record == NULL) {
    NQ_Attribute_Trie_Data *new_trie =
      NQ_Attribute_Trie_Data_new(val, transaction, actor_principal, args->element_size);
    common_record = &new_trie->common;

    // printf("vec create %p, trans = ", &val->common); NQ_UUID_print(&transaction); printf("\n");
    NQ_Transaction_step(transaction, &NQ_Attribute_Common_COW_transaction,
			common_record, val->common.revision);

    record_value_change(transaction, t_ctx, &val->common, &new_trie->common);
  } else {
    fprintf(stderr, "Trie already created!\n");
    return -1;
  }

  *output = NULL;
  *output_len = 0;
  return 0;
}

int NQ_Attribute_Trie_load_nth(
  NQ_Transaction transaction,
  NQ_Principal *actor_principal,
  NQ_Attribute_Trigger_Context *t_ctx,
  void *input, int input_len, 
  void **output, int *output_len,
  void **attr,
  NQ_Principal **output_attributed_to  ) {
  NQ_Load_Nth_Args *args = (NQ_Load_Nth_Args *) input;
  if(input_len < sizeof(*args)) {
    fprintf(stderr, "trie load nth args too short\n");
    return -1;
  }
  if(*attr == NULL) {
    fprintf(stderr, "trie not created\n");
    return -1;
  }
  NQ_Attribute_Trie *val = *attr;
  NQ_Attribute_Trie_Data *trie_data =
    NQ_Attribute_Trie_Data_get_transaction_copy(val, transaction, t_ctx, 0, NULL);

  if(trie_data == NULL) {
    fprintf(stderr, "no value found for trie load_nth\n");
    return -1;
  }
  if(args->index < 0) {
    fprintf(stderr, "index out of range\n");
    return -1;
  }
  // upper bounds check is done in lower layers of trie code
  NQ_Trie_Entry entry;
  int rv = NQ_Attribute_Trie_Data_load_nth(trie_data, args->index, &entry);
  if(rv) {
    fprintf(stderr, "trying to load invalid value\n");
    *output_len = 0;
    return -1;
  }

  int total_size = sizeof(entry.header) + trie_data->elem_size;
  *output = malloc(total_size);
  memcpy(*output, &entry.header, sizeof(entry.header));
  memcpy((char *)*output + sizeof(entry.header), entry.value, trie_data->elem_size);
  *output_len = total_size;

  NQ_Principal_reserve(trie_data->common.attributed_to);
  *output_attributed_to = trie_data->common.attributed_to;

  return 0;
}

int NQ_Attribute_Trie_truncate(
  NQ_Transaction transaction,
  NQ_Principal *actor_principal,
  NQ_Attribute_Trigger_Context *t_ctx,
  void *input, int input_len, 
  void **output, int *output_len,
  void **attr,
  NQ_Principal **output_attributed_to  ){
  if(*attr == NULL) {
    fprintf(stderr, "trie not created\n");
    return -1;
  }
  NQ_Attribute_Trie *trie = *attr;

  NQ_Attribute_Common_COW_Record *record_ctx;
  NQ_Attribute_Trie_Data *trie_data =
    NQ_Attribute_Trie_Data_get_transaction_copy(trie, transaction, t_ctx, 1, &record_ctx);
  if(trie_data == NULL) {
    return -1;
  }

  NQ_Attribute_Trie_Data_truncate(trie_data);
  record_value_change(transaction, t_ctx, &trie->common, record_ctx);
  
  *output = NULL;
  *output_len = 0;
  *output_attributed_to = NULL;
  return 0;
}

int NQ_Attribute_Trie_num_elems (
  NQ_Transaction transaction,
  NQ_Principal *actor_principal,
  NQ_Attribute_Trigger_Context *t_ctx,
  void *input, int input_len, 
  void **output, int *output_len,
  void **attr,
  NQ_Principal **output_attributed_to  ) {
  if(*attr == NULL) {
    fprintf(stderr, "trie not created\n");
    return -1;
  }
  NQ_Attribute_Trie *trie = *attr;

  NQ_Attribute_Trie_Data *trie_data =
    NQ_Attribute_Trie_Data_get_transaction_copy(trie, transaction, t_ctx, 0, NULL);

  if(trie_data == NULL) {
    fprintf(stderr, "no valid version of trie %p\n", &trie->common);
    return -1;
  }
  
  *output = malloc(sizeof(int));
  *(int*)*output = NQ_Attribute_Trie_Data_num_elems(trie_data);
  *output_len = sizeof(int);

  NQ_Principal_reserve(trie_data->common.attributed_to);
  *output_attributed_to = trie_data->common.attributed_to;

  // xxx reg read event;
  return 0;
}

int NQ_Attribute_Trie_lookup (
  NQ_Transaction transaction,
  NQ_Principal *actor_principal,
  NQ_Attribute_Trigger_Context *t_ctx,
  void *input, int input_len, 
  void **output, int *output_len,
  void **attr,
  NQ_Principal **output_attributed_to  ){
  NQ_Trie_Index_Args *args;
  NQ_Attribute_Trie_Data *trie_data;

  NQ_Attribute_Trie *trie = *attr;

  trie_data =
    NQ_Attribute_Trie_Data_get_transaction_copy(trie, transaction, t_ctx, 0, NULL);

  if(trie_data == NULL) {
    fprintf(stderr, "no valid version of trie %p\n", &trie->common);
    return -1;
  }

  args = (NQ_Trie_Index_Args *) input;
  if(input_len < sizeof(*args)) {
    fprintf(stderr, "trie args too short\n");
    return -1;
  }
  NQ_Trie_Entry entry;
  int rv = NQ_Attribute_Trie_Data_lookup(trie_data, args->prefix, &entry);
  if(!rv) {
#if 0
    printf("Lookup address: %p, len = %d, data = ", entry.value, trie_data->elem_size);
    print_hex(entry.value, trie_data->elem_size);
    printf("\n");
#endif

    *output_len = trie_data->elem_size;
    *output = malloc(*output_len);
    memcpy(*output, entry.value, *output_len);
  } else {
    // fprintf(stderr, "Could not find matching entry\n");
    // 0 = lookup failed
    *output_len = 0;
  }

  NQ_Principal_reserve(trie_data->common.attributed_to);
  *output_attributed_to = trie_data->common.attributed_to;

  return 0;
}

int NQ_Attribute_Trie_update (
  NQ_Transaction transaction,
  NQ_Principal *actor_principal,
  NQ_Attribute_Trigger_Context *t_ctx,
  void *input, int input_len, 
  void **output, int *output_len,
  void **attr,
  NQ_Principal **output_attributed_to  ){
  NQ_Trie_Index_Args *args;
  NQ_Attribute_Trie_Data *trie_data;

  NQ_Attribute_Trie *trie = *attr;

  trie_data =
    NQ_Attribute_Trie_Data_get_transaction_copy(trie, transaction, t_ctx, 1, NULL);

  if(trie_data == NULL) {
    fprintf(stderr, "no valid version of trie %p\n", &trie->common);
    return -1;
  }

  args = (NQ_Trie_Index_Args *) input;
  if(input_len < sizeof(*args) + trie_data->elem_size) {
    fprintf(stderr, "trie args + size too short for update\n");
    return -1;
  }
  NQ_Attribute_Trie_Data_update(trie_data, args, args + 1);
  *output_len = 0;
  *output_attributed_to = NULL;
  record_value_change(transaction, t_ctx, &trie->common, &trie_data->common);
  return 0;
}
 
int NQ_Attribute_Trie_remove (
  NQ_Transaction transaction,
  NQ_Principal *actor_principal,
  NQ_Attribute_Trigger_Context *t_ctx,
  void *input, int input_len, 
  void **output, int *output_len,
  void **attr,
  NQ_Principal **output_attributed_to  ){
  NQ_Trie_Index_Args *args;
  NQ_Attribute_Trie_Data *trie_data;

  NQ_Attribute_Trie *trie = *attr;

  trie_data =
    NQ_Attribute_Trie_Data_get_transaction_copy(trie, transaction, t_ctx, 1, NULL);

  if(trie_data == NULL) {
    fprintf(stderr, "no valid version of trie %p\n", &trie->common);
    return -1;
  }

  args = (NQ_Trie_Index_Args *) input;
  if(input_len < sizeof(*args)) {
    fprintf(stderr, "trie args + size too short for remove\n");
    return -1;
  }
  int rv = NQ_Attribute_Trie_Data_remove(trie_data, args);
  if(rv != 0) {
    printf("Trie update failure!\n");
  }
  *output_len = 0;
  *output_attributed_to = NULL;
  record_value_change(transaction, t_ctx, &trie->common, &trie_data->common);
  return rv;
}

void NQ_Attribute_Trie_print(NQ_Transaction transaction, void *attr){
  assert(0);
}
