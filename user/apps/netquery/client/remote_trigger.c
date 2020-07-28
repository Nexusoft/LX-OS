//
// This is just a set of specialized triggers used to give the illusion that remote triggers are local.
// For the standard trigger implementation, see attribute.c
//
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <nq/netquery.h>
#include <nq/net.h>
#include <nq/socket.h>
#include <nq/uuid.h>
#include <nq/queue.h>
#include <nq/remote_trigger.h>
#include <nq/garbage.h>

typedef struct NQ_Remote_Trigger_Deletion {
  struct NQ_Remote_Trigger_Deletion *next, *prev;
  NQ_Remote_Trigger *trigger;
} NQ_Remote_Trigger_Deletion;

NQ_Trigger NQ_Remote_Trigger_start_create(NQ_Trigger_Description *description, NQ_Trigger_Callback cb, void *userdata){
  // printf("RemoteTrigger_start_create()\n");
  NQ_Remote_Trigger *trigger = malloc(sizeof(NQ_Remote_Trigger));
  NQ_Trigger id;
  bzero(trigger, sizeof(NQ_Remote_Trigger));
  
  trigger->description = malloc(sizeof(NQ_Trigger_Description));
  memcpy(trigger->description, description, sizeof(NQ_Trigger_Description));
  if(description->name){
    trigger->description->name = NQ_Attribute_Name_dup(description->name);
  }
  trigger->cb = cb;
  trigger->userdata = userdata;
  queue_initialize(&trigger->pending_deletions);
  id = NQ_UUID_alloc(trigger, NQ_UUID_TRIGGER_REMOTE);
  NQ_UUID_cpy(&trigger->id, &id);
  return id;
}

int NQ_Remote_Trigger_cleanup(NQ_Remote_Trigger *trigger){
  void *deletion;
  if(trigger->cleanup){
    trigger->cleanup(trigger->description, trigger->userdata);
  }
  while(queue_dequeue(&trigger->pending_deletions, &deletion) == 0){
    ((NQ_Remote_Trigger_Deletion *)deletion)->trigger = NULL;
  }
  NQ_UUID_release(trigger->id);
  if(trigger->description->name){
    NQ_Attribute_Name_free(trigger->description->name);
  }
  free(trigger->description);
  free(trigger);
  return 0;
}
#if 0
int NQ_Remote_Trigger_set_cleanup(NQ_Trigger trigger_id, NQ_Trigger_Cleanup cleanup){
  NQ_Remote_Trigger *trigger;
  
  trigger = NQ_UUID_lookup(trigger_id);
  if(!trigger){
    return -1;
  }
  
  trigger->cleanup = cleanup;
  return 0;
}
#endif
int NQ_Remote_Trigger_create_abort(NQ_Transaction transaction, NQ_Remote_Trigger *trigger, int revision){
  NQ_Remote_Trigger_cleanup(trigger);
  return 0;
}
NQ_Transaction_Step_Type NQ_Remote_Trigger_create_transaction = {
  .callbacks = {
    NULL, 
    (NQ_Transaction_Callback)NQ_Remote_Trigger_create_abort,
    NULL
  }
};
NQ_Trigger NQ_Remote_Trigger_finish_create(NQ_Transaction transaction, NQ_Trigger ret, NQ_Trigger state){
  //printf("Remote_Trigger_finish_create()\n");
  
  NQ_Remote_Trigger *trigger = NQ_UUID_lookup(state);
  if(!trigger){
    printf("invalid trigger\n");
    return NQ_uuid_null;
  }
  if(NQ_UUID_eq_err(&ret)){
    printf("invalid trigger response\n");
    NQ_Remote_Trigger_cleanup(trigger);
    return ret;
  }
  NQ_UUID_cpy(&trigger->remote_id, &ret);
  NQ_Transaction_step(transaction, &NQ_Remote_Trigger_create_transaction, trigger, 0);
  NQ_GC_register_remote_trigger(trigger->id);
  return trigger->id;
}

int NQ_Remote_Trigger_delete_commit(NQ_Transaction transaction, NQ_Remote_Trigger_Deletion *deletion, int revision){
  if(deletion->trigger){
    NQ_Remote_Trigger_cleanup(deletion->trigger);
  }
  free(deletion);
  return 0;
}

int NQ_Remote_Trigger_delete_abort(NQ_Transaction transaction, NQ_Remote_Trigger_Deletion *deletion, int revision){
  if(deletion->trigger){
    queue_delete(&deletion->trigger->pending_deletions, deletion);
  }
  free(deletion);
  return 0;
}

NQ_Transaction_Step_Type NQ_Remote_Trigger_delete_transaction = {
  .callbacks = {
    (NQ_Transaction_Callback)NQ_Remote_Trigger_delete_commit, 
    (NQ_Transaction_Callback)NQ_Remote_Trigger_delete_abort,
    NULL
  }
};

NQ_Trigger NQ_Remote_Trigger_delete(NQ_Transaction transaction, NQ_Trigger trigger_id){
  NQ_Remote_Trigger_Deletion *deletion;
  
  NQ_Remote_Trigger *trigger = NQ_UUID_lookup(trigger_id);
  if(!trigger){
    return NQ_uuid_error;
  }
  deletion = malloc(sizeof(NQ_Remote_Trigger_Deletion));
  bzero(deletion, sizeof(NQ_Remote_Trigger_Deletion));
  deletion->trigger = trigger;

  NQ_Transaction_step(transaction, &NQ_Remote_Trigger_delete_transaction, deletion, 0);
  return trigger->remote_id;
}

static void NQ_Remote_Trigger_respond(NQ_Trigger_Call_Data *call_data, int rv) {
  // printf("Remote_Trigger_respond(%d)\n", rv);
  WaitGroup_respond(&call_data->fire_info->host, call_data->transaction, call_data->fire_info->req, call_data->fire_info->request_id, rv);
}

int NQ_Remote_Trigger_fire(NQ_Transaction transaction, 
			   NQ_Trigger_Fire_Info *fire_info){
  NQ_Remote_Trigger *trigger = NQ_UUID_lookup(fire_info->trigger_id);
  NQ_Trigger_Continuation cont = NULL;
  switch(fire_info->type) {
    case NQ_TRIGGER_UPCALL_SYNC_VETO:
    case NQ_TRIGGER_UPCALL_SYNC_VERDICT:
      // N.B. The returned value for a SYNC_VERDICT is ignored by server, but the server is still waiting for a return value
      cont = NQ_Remote_Trigger_respond;
      break;
    case NQ_TRIGGER_UPCALL_ASYNC_VERDICT:
    case NQ_TRIGGER_UPCALL_ASYNC_COMMIT_DONE:
      cont = NULL;
      break;
  default:
    assert(0);
  }
  if(!trigger){
    // trigger might have been deleted locally
    // printf("remote_trigger_fire: could not find: %d\n", fire_info->request_id);
    if(cont){
      NQ_Trigger_Call_Data data;
      bzero(&data, sizeof(NQ_Trigger_Call_Data));
      data.call = NULL;
      data.transaction = transaction;
      data.fire_info = fire_info;
      data.continuation = cont;
      cont(&data, 0);
    }
    return -1;
  }
  NQ_Trigger_issue(trigger->cb, transaction, trigger->description, 
		   fire_info, trigger->userdata, cont);
  return 0;
}

NQ_Trigger NQ_Remote_Trigger_register(NQ_Transaction transaction, NQ_Principal *actor, NQ_Trigger_Description *description, NQ_Trigger cb_id){
  return NQ_Local_Trigger_create(transaction, actor, description, cb_id);
}

int NQ_Remote_Trigger_unregister(NQ_Transaction transaction, NQ_Principal *actor, NQ_Trigger trigger){
  return NQ_Local_Trigger_delete(transaction, actor, trigger);
}
