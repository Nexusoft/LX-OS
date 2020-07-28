#ifndef NQ_ATTRIBUTE_H_SHIELD
#define NQ_ATTRIBUTE_H_SHIELD

typedef enum {
  NQ_ATTRIBUTE_RAW,
  NQ_ATTRIBUTE_SET,
  NQ_ATTRIBUTE_TRIE,
  NQ_ATTRIBUTE_VECTOR,
  NQ_ATTRIBUTE_FAKE_TRIE,
  
  NQ_ATTRIBUTE_TYPE_COUNT,
} NQ_Attribute_Type;

// Propagate any changes to NQ_Attribute_Name to
// NQ_Attribute_Name_alloc() and NQ_Attribute_Name_dup()
typedef struct NQ_Attribute_Name {
  NQ_Principal *owner;
  NQ_Attribute_Type type;
  char name[0];
} NQ_Attribute_Name;

int NQ_Attribute_Name_eq(NQ_Attribute_Name *a, NQ_Attribute_Name *b);
unsigned int NQ_Attribute_Name_hash(void *k);
NQ_Attribute_Name *NQ_Attribute_Name_alloc(NQ_Host *home, NQ_Attribute_Type type, const char *name);
NQ_Attribute_Name *NQ_Attribute_Name_dup(const NQ_Attribute_Name *name);
void NQ_Attribute_Name_free(NQ_Attribute_Name *name);

// This operation list neesd to be synchronized with op_type_map in
// nq_transaction.cc
typedef enum {
  NQ_OPERATION_READ,
  NQ_OPERATION_WRITE,
  NQ_OPERATION_ADD,
  NQ_OPERATION_REMOVE,
  NQ_OPERATION_CONTAINS,
  // Added by ashieh
  NQ_OPERATION_UPDATE,
  NQ_OPERATION_LOOKUP, // for indexed ADTs

  NQ_OPERATION_CREATE_AGGREGATE,
  NQ_OPERATION_NUM_ELEMS, // number of entries in the aggregate data structure

  // Ordered ADTs (e.g. vector)
  NQ_OPERATION_LOAD_NTH,
  NQ_OPERATION_STORE_NTH,
  NQ_OPERATION_TRUNCATE, // remove all elements

  // Special operations for stats gathering
  NQ_OPERATION_CLEAR_GLOBAL_STATS,
  NQ_OPERATION_GET_GLOBAL_STATS,

  // must be last:
  NQ_OPERATION_COUNT, // # of different operations
} NQ_Attribute_Operation;

#define NQ_ATTR_TX_STATE_VALID (0x1)
#define NQ_ATTR_TX_STATE_HAS_PENDING_TRIGGERS (0x2)

#define NQ_ATTR_BUILD_RESULT(ERR,TX_STATE) ((ERR & 0xffff) | (TX_STATE << 16))
#define NQ_ATTR_GET_TX_STATE(X) ((uint16_t)((X) >> 16))
#define NQ_ATTR_GET_ERRCODE(X) ((int16_t)((X) & 0xffff))

typedef struct NQ_Attribute_Trigger_Context NQ_Attribute_Trigger_Context;

typedef int (NQ_Attribute_Operation_Call)(
  NQ_Transaction transaction,
  NQ_Principal *actor_principal,
  NQ_Attribute_Trigger_Context *t_ctx,
  void *input, int input_len, 
  void **output, int *output_len,
  void **attr,
  NQ_Principal **output_attributed_to
  );
typedef void (NQ_Attribute_Print_Call)(NQ_Transaction transaction, void *attr);

typedef struct NQ_Create_Aggregate_Args {
  int element_size;
  int initial_capacity;
  // input: none
} NQ_Create_Aggregate_Args;

typedef struct NQ_Load_Nth_Args {
  int index;
  // output: data from vector
  // Throws error if element is undefined
} NQ_Load_Nth_Args;

typedef struct NQ_Store_Nth_Args {
  int index;
  // input: data to store to vector
} NQ_Store_Nth_Args;

typedef struct NQ_Num_Elems_Result {
  int num_elems;
} NQ_Num_Elems_Result;

typedef struct NQ_Trie_Index_Args {
  uint32_t prefix;
  int8_t prefix_len;
  // input: data to store to trie
} NQ_Trie_Index_Args;

typedef NQ_Trie_Index_Args NQ_FakeTrie_Header;

typedef NQ_Attribute_Operation_Call *NQ_Attribute_Operation_CallPtr;

typedef enum NQ_Attribute_Operation_Flags {
  NQ_ATTRIBUTE_F_READ = 0x1,
  NQ_ATTRIBUTE_F_WRITE = 0x2,
} NQ_Attribute_Operation_Flags;

typedef struct NQ_Attribute_Operation_Info {
  NQ_Attribute_Operation_CallPtr func;
  int flags; // OR of NQ_Attribute_Operation_Flags
} NQ_Attribute_Operation_Info;

typedef struct NQ_Attribute_Type_Definition {
  struct NQ_Attribute_Type_Definition *next, *prev;
  NQ_Attribute_Operation_Info calls[NQ_OPERATION_COUNT];
  NQ_Attribute_Print_Call *print_call;
  NQ_Attribute_Type type;
} NQ_Attribute_Type_Definition;

extern Queue NQ_Attribute_Type_definitionlist;

void NQ_Attribute_init(void);
int NQ_Attribute_operate(
  NQ_Transaction transaction, 
  NQ_Principal *actor,
  NQ_Attribute_Name *name, NQ_Tuple tuple, 
  NQ_Attribute_Operation op, 
  char **iobuffer, int *iolength,
  NQ_Principal **output_attributed_to);
int NQ_Local_Attribute_operate(
  NQ_Transaction transaction, 
  NQ_Principal *actor,
  NQ_Attribute_Name *name, NQ_Tuple tuple, 
  NQ_Attribute_Operation op, 
  char **iobuffer, int *iolength,
  NQ_Principal **output_attributed_to);
int NQ_Attribute_print(
  NQ_Transaction transaction, 
  NQ_Attribute_Name *name, NQ_Tuple tuple);

struct NQ_RingBuffer;
int NQ_Enumerate_Tuples(NQ_Host host, NQ_Tuple **out, int *out_count);

int NQ_Enumerate_Attributes(NQ_Host host, NQ_Tuple tuple, NQ_Attribute_Name ***out, int *out_count);

int NQ_Local_Enumerate_Tuples(struct NQ_RingBuffer *output);
int NQ_Local_Enumerate_Attributes(NQ_Tuple tuple, struct NQ_RingBuffer *output);

int NQ_Local_Enumerate_Triggers(struct NQ_RingBuffer *output);
int NQ_Local_Enumerate_Tuple_Triggers(NQ_Tuple tuple, struct NQ_RingBuffer *output);

// Propagate updates to Transaction::set_read_triggers() (hash
// function, instantiation from trigger_template)
typedef enum { NQ_TRIGGER_VALUECHANGED } NQ_Trigger_Type;
typedef enum { 
  NQ_TRIGGER_UPCALL_SYNC_VETO = 0x1,
  NQ_TRIGGER_UPCALL_SYNC_VERDICT = 0x2,
  NQ_TRIGGER_UPCALL_ASYNC_VERDICT = 0x4,

  // COMMIT_DONE: side-effects are now visible.
  // Similar to NQ_TRIGGER_UPCALL_ASYNC_VERDICT, but has different
  // barrier guarantees.
  NQ_TRIGGER_UPCALL_ASYNC_COMMIT_DONE = 0x8,
} NQ_Trigger_Upcall_Type;

typedef struct {
  // propagate changes to nq_shell.cc:__gnu_ext::hash<>
  NQ_Attribute_Name *name;
  NQ_Tuple tuple;
  NQ_Trigger_Type type;
  int upcall_type; // OR'ed together NQ_Trigger_Upcall_Type
  //parameters go here
} NQ_Trigger_Description;

struct NQ_Trigger_Call_Data;
typedef struct NQ_Trigger_Call_Data NQ_Trigger_Call_Data;
typedef NQ_UUID NQ_Trigger;

typedef void (*NQ_Trigger_Continuation)(NQ_Trigger_Call_Data *, int rv);
//The callback is expected to free the trigger description if necessary
typedef int (*NQ_Trigger_Callback)(NQ_Transaction transaction, NQ_Trigger_Description *trigger, NQ_Trigger_Upcall_Type type, int arg, void *userdata);
typedef int (*NQ_Trigger_Cleanup)(NQ_Trigger_Description *trigger, void *userdata);

typedef struct {
  NQ_Trigger_Description *desc;
  NQ_Trigger cb_id;
} NQ_Trigger_Desc_and_Dest;

int NQ_Enumerate_Triggers(NQ_Host host, NQ_Trigger_Desc_and_Dest **out, int *out_count);
int NQ_Enumerate_Tuple_Triggers(NQ_Host host, NQ_Tuple tuple, NQ_Trigger_Desc_and_Dest **out, int *out_count);

struct NQ_Request_Data;

typedef struct {
  // struct NQ_Socket *sock;
  NQ_Host host;
  struct NQ_Request_Data *req;
  NQ_Trigger trigger_id;
  NQ_Trigger_Upcall_Type type;
  int request_id;
  int arg;
} NQ_Trigger_Fire_Info;

struct NQ_Trigger_Call_Data {
  // passed to call_async
  NQ_Trigger_Callback call;
  NQ_Transaction transaction;
  NQ_Trigger_Description *description;

  NQ_Trigger_Fire_Info *fire_info;
  void *userdata;
  NQ_Trigger_Continuation continuation;
};

void NQ_Trigger_issue(NQ_Trigger_Callback call, NQ_Transaction transaction, NQ_Trigger_Description *description, 
		      NQ_Trigger_Fire_Info *fire_info,
		      void *userdata, NQ_Trigger_Continuation cont);

// Trigger description 
NQ_Trigger NQ_Trigger_create(
  NQ_Transaction transaction, 
  NQ_Principal *actor, 
  NQ_Trigger_Description *trigger, NQ_Trigger_Callback cb, void *userdata);
NQ_Trigger NQ_Local_Trigger_create(
  NQ_Transaction transaction, 
  NQ_Principal *actor, 
  NQ_Trigger_Description *description, NQ_Trigger cb_id);
int NQ_Trigger_delete(
  NQ_Transaction transaction, 
  NQ_Principal *actor, 
  NQ_Trigger trigger);
int NQ_Local_Trigger_delete(
  NQ_Transaction transaction, 
  NQ_Principal *actor, 
  NQ_Trigger trigger_id);
#if 0
int NQ_Trigger_set_cleanup(NQ_Trigger trigger_id, NQ_Trigger_Cleanup cleanup);
#endif

void NQ_Trigger_defer(const NQ_Transaction *t, NQ_Trigger_Description *desc,
		      NQ_Trigger trigger_id, NQ_Trigger cb_id);

struct NQ_Attribute_Value_Table;
struct NQ_Attribute_Value;
struct UUIDSet;

typedef struct NQ_Attribute_Trigger {
  struct NQ_Attribute_Trigger *next, *prev;
  NQ_Trigger id;
  NQ_Transaction transaction;
  NQ_Trigger_Description *description;
  NQ_Trigger_Callback callback;
#if 0
  NQ_Trigger_Cleanup cleanup;
  void *userdata;
#endif

  NQ_Trigger cb_id;
  struct NQ_Attribute_Value_Table *name_attribute;
  struct NQ_Attribute_Value *tuple_attribute;
  struct UUIDSet *pending_deletes;
} NQ_Attribute_Trigger;

int NQ_Trigger_is_locally_valid(const NQ_Transaction *transaction, NQ_Attribute_Trigger *trigger);

struct NQ_Trigger_Stats {
  int create;
  int erase;
};
extern struct NQ_Trigger_Stats trigger_stats;

#endif
