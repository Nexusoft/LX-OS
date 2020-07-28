#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <nq/netquery.h>
#include <nq/uuid.h>
#include <nq/attribute.h>
#include <nq/transaction.h>
#include <nq/garbage.h>
#include <nq/hashtable.h>
#include <nq/queue.h>
#include <nq/net.h>
#include <nq/remote_trigger.h>

static unsigned int NQ_GC_timeout_secs = 600;
static struct hashtable *gc_group_index;
static Queue gc_dump_queue;

void NQ_GC_set_timeout(unsigned int newtimeout){
  NQ_GC_timeout_secs = newtimeout;
}

unsigned int NQ_GC_Group_id_hash(void *key){
  //sigh... there's got to be a better way;
  unsigned long int ret = (unsigned long int)key;
  return (unsigned int)ret;
}
int NQ_GC_Group_id_eq(void *a, void *b){
  return a == b;
}

void NQ_GC_init(void){
  gc_group_index = create_hashtable(20, &NQ_GC_Group_id_hash, &NQ_GC_Group_id_eq);
  queue_initialize(&gc_dump_queue);
}

time_t NQ_GC_get_timeout(void){
  struct timeval now;
  gettimeofday(&now, NULL);
  return now.tv_sec + NQ_GC_timeout_secs;
}

NQ_GC_Reference *NQ_GC_register(NQ_GC_Cleanup_FN cleanup, void *ptr){
  NQ_GC_Reference *ref = malloc(sizeof(NQ_GC_Reference));
  bzero(ref, sizeof(NQ_GC_Reference));
  ref->cleanup = cleanup;
  ref->ptr = ptr;
  ref->timeout = NQ_GC_get_timeout();
  queue_append(&gc_dump_queue, ref);
  return ref;
}
void NQ_GC_deregister(NQ_GC_Reference *ref){
  queue_delete(&gc_dump_queue, ref);
  free(ref);
}
void NQ_GC_touch(NQ_GC_Reference *ref){
  queue_delete(&gc_dump_queue, ref);
  ref->timeout = NQ_GC_get_timeout();
  queue_append(&gc_dump_queue, ref);
}
int NQ_GC_collect(){
  struct timeval now;
  NQ_GC_Reference *ref;

  gettimeofday(&now, NULL);
  for(ref = queue_gethead(&gc_dump_queue); ref != NULL; ref = queue_gethead(&gc_dump_queue)){
    if(ref->timeout < now.tv_sec){
      queue_delete(&gc_dump_queue, ref);
      ref->cleanup(ref->ptr);
      free(ref);
    } else {
      break;
    }
  }
  if(ref != NULL){
//    printf("NQ_GC_collect() called: nothing to delete yet, but there will be in %ld sec\n", ref->timeout - now.tv_sec);
    return ref->timeout - now.tv_sec;
  } else {
//    printf("NQ_GC_collect() called: nothing to delete\n");
  }
  return -1;
}

//struct NQ_GC_Group_Data {
//  Queue elements;
//  NQ_GC_Reference *ref;
//} NQ_GC_Group_Data;
//
//void NQ_GC_Group_cleanup(NQ_GC_Group_Data *data){
//  NQ_GC_Reference *ref;
//  while(ref = queue_gethead(&data->elements)){
//    ref->cleanup(ref->ptr);
//    free(ref);
//  }
//}

extern void *NQ_UUID_lookup_helper(NQ_UUID value, NQ_UUID_ref **ref);

void NQ_GC_register_uuid(NQ_UUID uuid, NQ_GC_Cleanup_FN cleanup){
  NQ_UUID_ref *ref;
  if(!NQ_Net_is_local(uuid.home)) return;
  void *val = NQ_UUID_lookup_helper(uuid, &ref);
  if(!val){
    return; //UUID isn't valid.  silently fail?
  }
//  printf("UUID Registered with Garbage Collect: %p\n", ref);
  assert(!ref->gc_ref);
  ref->gc_ref = NQ_GC_register(cleanup, ref);
}

void NQ_Local_GC_touch_uuid(NQ_UUID uuid){
  NQ_UUID_ref *ref;
  assert(NQ_Net_is_local(uuid.home));
  void *val = NQ_UUID_lookup_helper(uuid, &ref);
  if(!val){
//    printf("Warning: trying to touch an invalid UUID\n");
    return; //UUID isn't valid.  silently fail?
  }
  assert(ref->gc_ref);
  NQ_GC_touch(ref->gc_ref);
}
void NQ_GC_touch_uuid(NQ_UUID uuid){
  NQ_Net_GC_touch_uuid(uuid);
}
#define INSTANTIATE_UUID_CLEANUP(name, vartype) \
  void NQ_GC_register_##name(vartype element){ \
    NQ_GC_register_uuid(element, (NQ_GC_Cleanup_FN)NQ_GC_cleanup_##name);\
  }\
  void NQ_Local_GC_touch_##name(vartype element){\
    NQ_Local_GC_touch_uuid(element);\
  }\
  void NQ_GC_touch_##name(vartype element){\
    NQ_Net_GC_touch_uuid(element);\
  }

typedef struct NQ_Tuple_Real NQ_Tuple_Real;
int NQ_Tuple_cleanup(NQ_Tuple_Real *r);
void NQ_GC_cleanup_tuple(NQ_UUID_ref *ref){
//  printf("Garbage Collect Cleaning tuple: %p\n", ref);
  ref->gc_ref = NULL;
  NQ_Tuple_cleanup(ref->val);
}
INSTANTIATE_UUID_CLEANUP(tuple, NQ_Tuple)

void NQ_GC_cleanup_remote_trigger(NQ_UUID_ref *ref){
  ref->gc_ref = NULL;
//  printf("Remote trigger being cleaned!\n");
  NQ_Remote_Trigger_delete(NQ_uuid_null, ref->id);
}
INSTANTIATE_UUID_CLEANUP(remote_trigger, NQ_Trigger)

void NQ_GC_cleanup_local_trigger(NQ_UUID_ref *ref){
  ref->gc_ref = NULL;
//  printf("Local trigger being cleaned!\n");
  NQ_Local_Trigger_delete(NQ_uuid_null, NULL, ref->id);
}
INSTANTIATE_UUID_CLEANUP(local_trigger, NQ_Trigger)

void NQ_GC_touch_trigger(NQ_Trigger trigger){
  NQ_Remote_Trigger *local = NQ_UUID_lookup(trigger);
  NQ_GC_touch_remote_trigger(local->id);
  NQ_GC_touch_local_trigger(local->remote_id);
}

void NQ_GC_cleanup_transaction_usercall(NQ_Transaction *t){
  NQ_Transaction_abort(*t);
  free(t);
//  printf("Transaction freed\n");
}
void NQ_GC_cleanup_transaction(NQ_UUID_ref *ref){
  NQ_Transaction *t = malloc(sizeof(NQ_Transaction));
  memcpy(t, &ref->id, sizeof(NQ_Transaction));
  //this... could be more efficient, but eh.
  //it's also a blocking call... so let's not schedule it in the server thread.
  ref->gc_ref = NULL;
//  printf("Scheduling transaction deletion: %p\n", ref);
  NQ_user_call_async((NQ_User_Async_Call)&NQ_GC_cleanup_transaction_usercall, t);
}
INSTANTIATE_UUID_CLEANUP(transaction, NQ_Transaction)

void NQ_GC_register_attribute_value(NQ_Tuple tuple, NQ_Attribute_Name *name){
  
}
void NQ_GC_touch_attribute_value(NQ_Tuple tuple, NQ_Attribute_Name *name){

}
void NQ_Local_GC_touch_attribute_value(NQ_Tuple tuple, NQ_Attribute_Name *name){

}






//NQ_GC_Group NQ_GC_Group_create(){
//  int x;
//  NQ_GC_Group id;
//  NQ_GC_Group_Data *data = malloc(sizeof(NQ_GC_Group_Data));
//  bzero(data, sizeof(NQ_GC_Group_Data));
//  queue_initialize(&data->elements);
//  
//  for(x = 0; x < 100; x++){
//    id = rand();
//    if(!hashtable_search(gc_group_index, id)){
//      hashtable_insert(gc_group_index, id, data);
//      data->ref = NQ_GC_register(
//    }
//  }
//  assert(!"Unable to find group ID!");
//}
//int NQ_GC_Group_register(NQ_GC_Group group_id, NQ_GC_Cleanup_FN *cleanup, void *ptr){
//  NQ_GC_Group_Data *data;
//  data = hashtable_search(gc_group_index, group_id);
//  if(!data){
//    return -1;
//  }
//  elements 
//}
//int NQ_GC_Group_touch(NQ_GC_Group group_id){
//
//}
