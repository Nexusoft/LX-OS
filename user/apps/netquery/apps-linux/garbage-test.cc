#include <iostream>
#include <string.h>

#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <nq/netquery.h>
#include <nq/garbage.h>
#include <nq/net.h>

#define GC_TIMEOUT 5
#define GC_TOUCHTIME (GC_TIMEOUT-2)
#define GC_ABORTTIME (GC_TIMEOUT+2)

int test_trigger_cb(NQ_Transaction transaction, NQ_Trigger_Description *trigger, NQ_Trigger_Upcall_Type type, int arg, void *userdata){
  assert(!"No trigger should ever fire during this test!"); // if we're passed in a null, it means that the trigger should have been freed by now.
  return 0;
} 

void test_triggers(int should_touch, int cnt){
  int x; 
  NQ_Attribute_Name **att_names = new NQ_Attribute_Name*[cnt];
  NQ_Trigger *trigg = new NQ_Trigger[cnt];
  char tmpbuff[100];
  NQ_Host localhost = NQ_Net_get_localhost();
  localhost.port = NQ_NET_DEFAULT_PORT;
  NQ_Trigger_Description desc;
  
  struct timeval start, now;
  
  printf("test_triggers(%d, %d): Creating Attribute Names\n", should_touch, cnt);
  
  for(x = 0; x < cnt; x++){
    sprintf(tmpbuff, "Attribute-%d", x);
    att_names[x] = NQ_Attribute_Name_alloc(&localhost, NQ_ATTRIBUTE_RAW, tmpbuff);
  }
  
  desc.tuple = NQ_uuid_null;
  desc.type = NQ_TRIGGER_VALUECHANGED;
  desc.upcall_type = NQ_TRIGGER_UPCALL_SYNC_VETO;
  
  printf("test_triggers(%d, %d): Creating Triggers\n", should_touch, cnt);
  
  for(x = 0; x < cnt; x++){
    desc.name = att_names[x];
    trigg[x] = NQ_Trigger_create(NQ_uuid_null, &NQ_default_owner, &desc, &test_trigger_cb, NULL);
  }
  
  gettimeofday(&start, NULL);
  
  gettimeofday(&now, NULL);
  NQ_Net_nudge_pollthread();

  if(should_touch){
    while(now.tv_sec < (start.tv_sec + GC_TOUCHTIME)){
      printf("test_triggers(%d, %d): Waiting to touch triggers, sleeping for %ld\n", should_touch, cnt, start.tv_sec + GC_TOUCHTIME - now.tv_sec);
      sleep(start.tv_sec + GC_TOUCHTIME - now.tv_sec);
      gettimeofday(&now, NULL);
    }
    
    printf("test_triggers(%d, %d): Touching Triggers\n", should_touch, cnt);
    
    for(x = 0; x < cnt; x++){
      NQ_GC_touch_trigger(trigg[x]);
    }
    NQ_Net_nudge_pollthread();
  }
  
  while(now.tv_sec < (start.tv_sec + GC_ABORTTIME)){
    printf("test_triggers(%d, %d): Waiting for trigger expiration, sleeping for %ld\n", should_touch, cnt, start.tv_sec + GC_ABORTTIME - now.tv_sec);
    sleep(start.tv_sec + GC_ABORTTIME - now.tv_sec);
    gettimeofday(&now, NULL);
  }
  
  if(!should_touch){
    printf("test_triggers(%d, %d): Attempting to fire triggers\n", should_touch, cnt);
    NQ_Transaction trans = NQ_Transaction_begin();
    NQ_Tuple test = NQ_Tuple_create(trans, NQ_default_owner.home, &NQ_default_owner);
    
    for(x = 0; x < cnt; x++){
      char *dummy = "bob";
      int dummylen = strlen(dummy);
      NQ_Attribute_operate(trans, &NQ_default_owner, att_names[x], test, NQ_OPERATION_WRITE, &dummy, &dummylen, NULL);
    }
    NQ_Transaction_commit(trans);
  }
  
  printf("test_triggers(%d, %d): Cleaning up after the triggers\n", should_touch, cnt);
    
  for(x = 0; x < cnt; x++){
    if(NQ_Trigger_delete(NQ_uuid_null, &NQ_default_owner, trigg[x])){
      if(should_touch){
        printf("Transaction Test FAILED: Touched transaction was deleted.  id #%d\n", cnt);
        assert(0);
      }
    } else {
      if(!should_touch){
        printf("Transaction Test FAILED: Unouched transaction was NOT deleted.  id #%d\n", cnt);
        assert(0);
      }
    }
  }
  
  printf("test_triggers(%d, %d): Success!\n", should_touch, cnt);
  
  for(x = 0; x < cnt; x++){
    NQ_Attribute_Name_free(att_names[x]);
  }
  delete att_names;
  delete trigg;
}

void test_transactions(int should_touch, int cnt){
  int x; 
  NQ_Tuple *t = new NQ_Tuple[cnt];
  NQ_Transaction *trans = new NQ_Transaction[cnt];
  struct timeval start, now;
  
  gettimeofday(&start, NULL);
  
  printf("test_transactions(%d, %d): Creating Transactions\n", should_touch, cnt);
  
  for(x = 0; x < cnt; x++){
    trans[x] = NQ_Transaction_begin();
    t[x] = NQ_Tuple_create(trans[x], NQ_default_owner.home, &NQ_default_owner);
  }
  
  gettimeofday(&now, NULL);
  NQ_Net_nudge_pollthread();
  
  while(now.tv_sec < (start.tv_sec + GC_TOUCHTIME)){
    printf("test_transactions(%d, %d): Waiting to touch tuples, sleeping for %ld\n", should_touch, cnt, start.tv_sec + GC_TOUCHTIME - now.tv_sec);
    sleep(start.tv_sec + GC_TOUCHTIME - now.tv_sec);
    gettimeofday(&now, NULL);
  }
  for(x = 0; x < cnt; x++){
    NQ_GC_touch_tuple(t[x]);
  }
  if(should_touch){
    printf("test_transactions(%d, %d): Touching Transactions\n", should_touch, cnt);
    
    for(x = 0; x < cnt; x++){
      NQ_GC_touch_transaction(trans[x]);
    }
    NQ_Net_nudge_pollthread();
  }
  
  while(now.tv_sec < (start.tv_sec + GC_ABORTTIME)){
    printf("test_transactions(%d, %d): Waiting for transaction deletion, sleeping for %ld\n", should_touch, cnt, start.tv_sec + GC_ABORTTIME - now.tv_sec);
    sleep(start.tv_sec + GC_ABORTTIME - now.tv_sec);
    gettimeofday(&now, NULL);
  }
  
  printf("test_transactions(%d, %d): Attempting to commit\n", should_touch, cnt);
  
  for(x = 0; x < cnt; x++){
    if(NQ_Transaction_commit(trans[x])){
      if(should_touch){
        printf("Transaction Test FAILED: Touched transaction was deleted.  id #%d\n", cnt);
        assert(0);
      }
    } else {
      if(!should_touch){
        printf("Transaction Test FAILED: Unouched transaction was NOT deleted.  id #%d\n", cnt);
        assert(0);
      }
    }
    if(NQ_Tuple_delete(NQ_uuid_null, &NQ_default_owner, t[x])){
      if(should_touch){
        printf("Transaction Test FAILED: Tuple in touched transaction was deleted .  id #%d\n", cnt);
        assert(0);
      }
    } else {
      if(!should_touch){
        printf("Transaction Test FAILED: Tuple in untouched transaction was NOT deleted.  id #%d\n", cnt);
        assert(0);
      }
    }
    
  }
    
  printf("test_transactions(%d, %d): Success!\n", should_touch, cnt);
  
  delete t;
  delete trans;
}

void test_tuples(int should_touch, int cnt){
  int x; 
  NQ_Tuple *t = new NQ_Tuple[cnt];
  struct timeval start, now;
  
  gettimeofday(&start, NULL);
  
  printf("test_tuples(%d, %d): Creating Tuples\n", should_touch, cnt);
  
  for(x = 0; x < cnt; x++){
    t[x] = NQ_Tuple_create(NQ_uuid_null, NQ_default_owner.home, &NQ_default_owner);
  }
  
  gettimeofday(&now, NULL);
  NQ_Net_nudge_pollthread();
  
  if(should_touch){
  
    while(now.tv_sec < (start.tv_sec + GC_TOUCHTIME)){
      printf("test_tuples(%d, %d): Waiting to touch tuples, sleeping for %ld\n", should_touch, cnt, start.tv_sec + GC_TOUCHTIME - now.tv_sec);
      sleep(start.tv_sec + GC_TOUCHTIME - now.tv_sec);
      gettimeofday(&now, NULL);
    }
    
    printf("test_tuples(%d, %d): Touching Tuples\n", should_touch, cnt);
    
    for(x = 0; x < cnt; x++){
      NQ_GC_touch_tuple(t[x]);
    }
    NQ_Net_nudge_pollthread();
  }
  
  while(now.tv_sec < (start.tv_sec + GC_ABORTTIME)){
    printf("test_tuples(%d, %d): Waiting for tuple deletion, sleeping for %ld\n", should_touch, cnt, start.tv_sec + GC_ABORTTIME - now.tv_sec);
    sleep(start.tv_sec + GC_ABORTTIME - now.tv_sec);
    gettimeofday(&now, NULL);
  }
  
  printf("test_tuples(%d, %d): Attempting to manually delete\n", should_touch, cnt);
  
  for(x = 0; x < cnt; x++){
    if(NQ_Tuple_delete(NQ_uuid_null, &NQ_default_owner, t[x])){
      if(should_touch){
        printf("Tuple Test FAILED: Touched tuple was deleted.  id #%d\n", cnt);
        assert(0);
      }
    } else {
      if(!should_touch){
        printf("Tuple Test FAILED: Unouched tuple was NOT deleted.  id #%d\n", cnt);
        assert(0);
      }
    }
  }
    
  printf("test_tuples(%d, %d): Success!\n", should_touch, cnt);
  
  delete t;
}

int main(int argc, char **argv){  
  printf("Initializing NetQuery...");
  NQ_init(5500);
  NQ_publish_home_principal();
  NQ_GC_set_timeout(GC_TIMEOUT);
  printf("done\n");
  
//  test_tuples(0, 1);
//  test_tuples(0, 50);
//  test_tuples(1, 1);
//  test_tuples(1, 50);

//  test_transactions(0, 1);
//  test_transactions(0, 50);
//  test_transactions(1, 1);
//  test_transactions(1, 50);
  
  test_triggers(0, 1);
//  test_triggers(0, 50);
//  test_triggers(1, 1);
//  test_triggers(1, 50);
  
  
  printf("Garbage Collect: Test Complete!");
  exit(0);

  return 0;
}
