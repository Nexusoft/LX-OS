#ifndef REMOTE_TRIGGER_H_SHIELD
#define REMOTE_TRIGGER_H_SHIELD

typedef struct NQ_Remote_Trigger {
  NQ_Trigger_Callback cb;
  NQ_Trigger_Cleanup cleanup;
  void *userdata;
  NQ_Trigger id;
  NQ_Trigger remote_id;
  NQ_Trigger_Description *description;
  Queue pending_deletions;
} NQ_Remote_Trigger;


NQ_Trigger NQ_Remote_Trigger_start_create(NQ_Trigger_Description *description, NQ_Trigger_Callback cb, void *userdata);
NQ_Trigger NQ_Remote_Trigger_finish_create(NQ_Transaction transaction, NQ_Trigger ret, NQ_Trigger state);
NQ_Trigger NQ_Remote_Trigger_delete(NQ_Transaction transaction, NQ_Trigger trigger_id);
int NQ_Remote_Trigger_set_cleanup(NQ_Trigger trigger_id, NQ_Trigger_Cleanup cleanup);

int NQ_Remote_Trigger_fire(NQ_Transaction transaction, NQ_Trigger_Fire_Info *fire_info);

NQ_Trigger NQ_Remote_Trigger_register(NQ_Transaction transaction, NQ_Principal *actor, NQ_Trigger_Description *description, NQ_Trigger cb_id);
int NQ_Remote_Trigger_unregister(NQ_Transaction transaction, NQ_Principal *actor, NQ_Trigger trigger);

#endif
