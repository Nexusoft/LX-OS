#ifndef GARBAGE_COLLECT_H_SHIELD
#define GARBAGE_COLLECT_H_SHIELD

#include <sys/time.h>
#include <nq/uuid.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*NQ_GC_Cleanup_FN)(void *ptr);

typedef struct NQ_GC_Reference {
  struct NQ_GC_Reference *next, *prev;
  NQ_GC_Cleanup_FN cleanup;
  void *ptr;
  time_t timeout;
} NQ_GC_Reference;

typedef unsigned int NQ_GC_Group;

void NQ_GC_init(void);
void NQ_GC_set_timeout(unsigned int newtimeout); //debug use only

NQ_GC_Reference *NQ_GC_register(NQ_GC_Cleanup_FN cleanup, void *ptr);
void NQ_GC_deregister(NQ_GC_Reference *ref);
void NQ_GC_touch(NQ_GC_Reference *ref);
int NQ_GC_collect(); //returns # of sec until next free is required

void NQ_GC_register_uuid(NQ_UUID uuid, NQ_GC_Cleanup_FN cleanup);
void NQ_GC_touch_uuid(NQ_UUID uuid);
void NQ_Local_GC_touch_uuid(NQ_UUID uuid);

void NQ_GC_register_tuple(NQ_Tuple tuple);
void NQ_GC_touch_tuple(NQ_Tuple tuple);
void NQ_Local_GC_touch_tuple(NQ_Tuple tuple);

void NQ_GC_register_attribute_value(NQ_Tuple tuple, NQ_Attribute_Name *name);
void NQ_GC_touch_attribute_value(NQ_Tuple tuple, NQ_Attribute_Name *name);
void NQ_Local_GC_touch_attribute_value(NQ_Tuple tuple, NQ_Attribute_Name *name);

void NQ_GC_register_remote_trigger(NQ_Trigger trigger);
void NQ_GC_touch_remote_trigger(NQ_Trigger trigger);
void NQ_Local_GC_touch_remote_trigger(NQ_Trigger trigger);
void NQ_GC_register_local_trigger(NQ_Trigger trigger);
void NQ_GC_touch_local_trigger(NQ_Trigger trigger);
void NQ_Local_GC_touch_local_trigger(NQ_Trigger trigger);
void NQ_GC_touch_trigger(NQ_Trigger trigger);

void NQ_GC_register_transaction(NQ_Transaction trigger);
void NQ_GC_touch_transaction(NQ_Transaction trigger);
void NQ_Local_GC_touch_transaction(NQ_Transaction trigger);

NQ_GC_Group NQ_GC_Group_create();
int NQ_GC_Group_register(NQ_GC_Group group_id, NQ_GC_Cleanup_FN cleanup, void *ptr);
int NQ_GC_Group_register_existing(NQ_GC_Group group_id, NQ_GC_Reference *ref);
int NQ_GC_Group_touch(NQ_GC_Group group_id);

#ifdef __cplusplus
}
#endif

#endif
