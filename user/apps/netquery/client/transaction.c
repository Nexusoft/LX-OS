#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <nq/netquery.h>
#include <nq/gcmalloc.h>
#include <nq/net.h>
#include <nq/pickle.h>
#include <nq/garbage.h>

#include <nq/hashtable.h>
#include <nq/util.hh>

#include <pthread.h>

#define CHECK_PERM(P,S)						\
  do{								\
    if(!(P)) {							\
      printf("Permission failed %s @ %d\n", #P, __LINE__);	\
    }								\
  } while(0)

static struct hashtable *remote_transactions;

void NQ_Transaction_uuid_release(NQ_Transaction_Real *t);

static void NQ_Transaction_Real_init(NQ_Transaction_Real *real_t, NQ_Transaction t, 
				NQ_Transaction_Type type) {
  queue_initialize(&real_t->steps);
  queue_initialize(&real_t->remotes);
  real_t->refcnt = 1;
  real_t->shadow_state.is_valid = 1;
  real_t->shadow_state.remotes_have_triggers = 0;
  real_t->type = type;
  real_t->t = t;

  real_t->commit_state = COMMITSTATE_EXECUTION;
  real_t->sync_veto = DeferredTriggers_create(real_t);
  real_t->sync_verdict = DeferredTriggers_create(real_t);
  real_t->async_verdict = DeferredTriggers_create(real_t);
  real_t->commit_done = DeferredTriggers_create(real_t);

  real_t->coordinator.wait_group = WaitGroup_create(real_t);
  real_t->server.wait_group_server = WaitGroupServer_create(real_t);

  real_t->mutex = ((pthread_mutex_t)PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP);
}

void NQ_Transaction_Real_get(NQ_Transaction_Real *t) {
  if(t->type == NQ_TRANSACTION_DEFAULT) {
    t->refcnt++;
    static int refcnt_overflow = 0;
    if(refcnt_overflow < 10) {
      // fprintf(stderr, "refcnt overflow!\n");
      refcnt_overflow += 1;
    }
  }
}

void NQ_Transaction_Real_put(NQ_Transaction_Real *t) {
  if(t->type == NQ_TRANSACTION_DEFAULT) {
    t->refcnt--;
    if(t->refcnt == 0) {
      fprintf(stderr, "Transaction dealloc\n");
      free(t);
    }
  }
}

struct NQ_Transaction_Remote {
  struct NQ_Transaction_Remote *next, *prev;
  NQ_Transaction_Real trans;
};

typedef struct NQ_Transaction_Remote_Reference {
  struct NQ_Transaction_Remote_Reference *next, *prev;
  NQ_Transaction_Real *trans;
  NQ_Host host;
} NQ_Transaction_Remote_Reference;

static unsigned int NQ_Transaction_Remote_hash(void *k){
  NQ_Transaction *ref = (NQ_Transaction *)k;
  int x;
  unsigned int ret = 0;
  for(x = 0; x < UUIDBITS; x++){
    ret = ((ret & 0xffffff) << 8) | ((ret & 0xff000000) >> 24);
    ret = ret ^ ref->id[x];
  }
  ret ^= ref->home.addr ^ ref->home.port;
//  printf("hashed to: %d\n", ret);
  return ret;
}

void NQ_Transaction_init(void){
  remote_transactions = create_hashtable(10000, NQ_Transaction_Remote_hash, (int (*) (void*,void*))NQ_UUID_eq);
}

NQ_Transaction_Remote *NQ_Transaction_Remote_get(NQ_Transaction t){
//  printf("get: ");NQ_UUID_print(&t);printf("\n");
  return hashtable_search(remote_transactions, &t);
}
//NQ_Transaction_register_remote() is the equivalent of NQ_Transaction_Remote_get_local()
//except that it will actively go out and set the transaction up remotely.  Use the latter unless
//you specifically need to know that the transaction doesn't exist yet.
NQ_Transaction_Real *NQ_Transaction_Remote_get_local(NQ_Transaction t){
  NQ_Transaction_Remote *r = NQ_Transaction_Remote_get(t);
  if(r){
    return &r->trans;
  } else {
    return NULL;
  }
}

NQ_Transaction_Real *NQ_Transaction_get_any(NQ_Transaction t){
  NQ_Transaction_Real *t_real;
  if(NQ_Net_is_local(t.home)){
    t_real = (NQ_Transaction_Real *)NQ_UUID_lookup(t);
  } else {
    t_real = NQ_Transaction_register_remote(t);
  }
  return t_real;
}

int NQ_Transaction_subseteq(NQ_Transaction big, NQ_Transaction little){
  return NQ_UUID_eq(&big, &NQ_uuid_error)||NQ_UUID_eq(&little, &big);
}

NQ_Transaction NQ_Local_Transaction_begin(void){
  NQ_Transaction_Real *real_t;
  NQ_Transaction t;
  
  real_t = malloc(sizeof(NQ_Transaction_Real));
  t = NQ_UUID_alloc(real_t, NQ_UUID_TRANSACTION);
  NQ_Transaction_Real_init(real_t, t, NQ_TRANSACTION_DEFAULT);
  // refcnt belongs to UUID table

//  printf("Beginning: ");NQ_UUID_print(&t);printf("\n");

  NQ_GC_register_transaction(t);
  
  return t;
}
NQ_Transaction NQ_Transaction_begin(void){
  return NQ_Net_Transaction_begin(NQ_Net_get_localhost());
}

static int NQ_Transaction_Finalize(NQ_Transaction transaction, NQ_Transaction_Real *t, NQ_Transaction_Callback_Type type){
  void *_s;
  while(queue_dequeue(&t->steps, &_s) == 0){
    NQ_Transaction_Step *s = _s;
    if(s->type->callbacks[type]){
      s->type->callbacks[type](transaction, s->data, s->revision);
    }
    free(s);
  }
  
  return 0;
}

int NQ_Transaction_start_remote(NQ_Transaction_Real *t, WaitGroup_RequestHandler handler, void *ctx, int op, int arg){
  NQ_Transaction_Remote_Reference *ref;
  // fprintf(stderr, "start remotes len = %d\n", t->remotes.len);
  for(ref = queue_gethead(&t->remotes); ref != NULL; ref = queue_getnext(ref)){
    WaitGroup_issue(t, ref->host, handler, ctx, op, arg);
  }
  return 0;
}

int NQ_Transaction_test_helper(NQ_Transaction transaction, NQ_Transaction_Real *t){
  NQ_Transaction_Step *s;

  for(s = queue_gethead(&t->steps); s != NULL; s = queue_getnext(s)){
    if( s->type->callbacks[NQ_TRANSACTION_CALLBACK_TEST] && 
        s->type->callbacks[NQ_TRANSACTION_CALLBACK_TEST](transaction, s->data, s->revision)){
      return -1;
    }
  }
  return 0;
}

#define ASSIGN_TEST() do { ctx->local_result = !NQ_Transaction_test_helper(t->t, t); } while(0)
void NQ_Transaction_test_common(NQ_Transaction_Real *t, NQ_Transaction_Commit_Step_Ctx *ctx, int ignored) {
  ASSIGN_TEST();
}

int NQ_Local_Transaction_test(NQ_Transaction transaction, NQ_Socket *sock, NQ_Request_Data *req){
  NQ_Transaction_Real *t;
  
  t = NQ_UUID_lookup(transaction);
  if(!t) {
    return -1;
  }
  
  NQ_Request_Ctx *ctx = NQ_Request_Ctx_create(transaction, sock, req);
  WaitGroup_open(t, NQ_Request_respond_group, ctx);

  ASSIGN_TEST();

  if(ctx->local_result){
    // only test remote if local succeeds
    // printf("Send WG_TEST\n");
    NQ_Transaction_start_remote(t, NQ_Request_handle_one, ctx,
				NQ_TRANSACTION_WG_TEST, 0);
  }
  WaitGroup_close(t);
  NQ_Transaction_Real_put(t);
  return 0;
}
int NQ_Transaction_test(NQ_Transaction transaction){
  return NQ_Net_Transaction_test(transaction);
}

int NQ_Local_Transaction_abort(NQ_Transaction transaction, NQ_Socket *sock, NQ_Request_Data *req){
  int ret = 0;
  NQ_Transaction_Real *t;

  t = NQ_UUID_lookup(transaction);
  if(t == NULL) {
    printf("Error looking up  transaction\n");
    return -1;
  }

  // Deallocate all pending triggers
  // XXX printf("Warning: Need to deallocate pending triggers list\n");
  // if(ret) return ret;

  ret = NQ_Transaction_Finalize(transaction, t, NQ_TRANSACTION_CALLBACK_ABORT);
  if(ret) goto out;

  NQ_Request_Ctx *ctx = NQ_Request_Ctx_create(transaction, sock, req);
  WaitGroup_open(t, NQ_Request_respond_group, ctx);
  NQ_Transaction_start_remote(t, NQ_Request_handle_one, ctx,
			      NQ_TRANSACTION_WG_FINALIZE,
			      0);
  WaitGroup_close(t);
out:
  NQ_Transaction_Real_put(t);
  return ret;
}
int NQ_Transaction_abort(NQ_Transaction transaction){
  return NQ_Net_Transaction_abort(transaction);
}

static int NQ_Transaction_fast_commit(NQ_Transaction_Real *t, NQ_Socket *sock, NQ_Request_Data *req);
static void NQ_Transaction_fast_commit_common(NQ_Transaction_Real *t, NQ_Transaction_Commit_Step_Ctx *ctx, int verdict);
static void NQ_Transaction_fast_commit_callback(NQ_Transaction_Real *t, void *_ctx);

// the callback ctx is allocated in start and deallocated after finalize
static int NQ_Transaction_commit_start(NQ_Transaction_Real *t, NQ_Socket *sock, NQ_Request_Data *req);
static void NQ_Transaction_commit_start_common(NQ_Transaction_Real *t, NQ_Transaction_Commit_Step_Ctx *ctx, int ignored);
static void NQ_Transaction_commit_start_callback(NQ_Transaction_Real *t, void *_ctx);

static void NQ_Transaction_commit_propose(NQ_Transaction_Real *t, NQ_Transaction_Commit_Step_Ctx *ctx);
static void NQ_Transaction_commit_propose_common(NQ_Transaction_Real *t, NQ_Transaction_Commit_Step_Ctx *ctx, int ignored);
static void NQ_Transaction_commit_propose_callback(NQ_Transaction_Real *t, void *_ctx);

static void NQ_Transaction_commit_verdict(NQ_Transaction_Real *t, NQ_Transaction_Commit_Step_Ctx *ctx);
static void NQ_Transaction_commit_verdict_common(NQ_Transaction_Real *t, NQ_Transaction_Commit_Step_Ctx *ctx, int verdict);
static void NQ_Transaction_commit_verdict_callback(NQ_Transaction_Real *t, void *_ctx);

static void NQ_Transaction_commit_finalize(NQ_Transaction_Real *t, NQ_Transaction_Commit_Step_Ctx *ctx);
static void NQ_Transaction_commit_finalize_common(NQ_Transaction_Real *t, NQ_Transaction_Commit_Step_Ctx *ctx, int verdict);
static void NQ_Transaction_commit_finalize_callback(NQ_Transaction_Real *t, void *_ctx);

// Commit_done is done asynchronously, so there is no callback
static void NQ_Transaction_commit_done_common(NQ_Transaction_Real *t, NQ_Transaction_Commit_Step_Ctx *ctx, int verdict);

void NQ_Transaction_Commit_Step_Ctx_reset(NQ_Transaction_Commit_Step_Ctx *step) {
  step->result = 1;
  step->local_result = 1;
}

NQ_Transaction_Commit_Step_Ctx *NQ_Transaction_Commit_Step_Ctx_create(NQ_Transaction t, const NQ_Host *host, NQ_Request_Data *req, int request_id, int arg) {
  // Step_Ctx is responsible for freeing req.
  NQ_Transaction_Commit_Step_Ctx *step = malloc(sizeof(*step));
  step->transaction = t;
  step->sock = NULL;
  if(host != NULL) {
    step->host = *host;
  } else {
    memset(&step->host, 0, sizeof(step->host));
  }
  step->req = req;
  step->verdict = 0;
  step->request_id = request_id;
  step->arg = arg;
  NQ_Transaction_Commit_Step_Ctx_reset(step);
  return step;
}

void NQ_Transaction_Commit_Step_Ctx_destroy(NQ_Transaction_Commit_Step_Ctx *step) {
  free(step->req);
  free(step);
}

NQ_Request_Ctx *NQ_Request_Ctx_create(NQ_Transaction t, struct NQ_Socket *sock, struct NQ_Request_Data *req) {
  NQ_Request_Ctx *rv = malloc(sizeof(NQ_Request_Ctx));
  rv->transaction = t;
  rv->local_result = 1;
  rv->result = 1;
  rv->sock = sock;
  rv->req = req;
  return rv;
}
void NQ_Request_Ctx_destroy(NQ_Request_Ctx *ctx) {
  if(ctx->req != NULL) {
    free(ctx->req);
  }
  free(ctx);
}

extern NQ_Transaction last_respond_transaction;
extern NQ_Host last_respond_host;

void NQ_Commit_Server_respond(NQ_Transaction_Commit_Step_Ctx *step, int rv) {
  WaitGroup_respond(&step->host, step->transaction, step->req, step->request_id, rv);
  last_respond_transaction = step->transaction;
  last_respond_host = step->host;
  // Request is deallocated by WaitGroup_respond
  step->req = NULL;
  NQ_Transaction_Commit_Step_Ctx_destroy(step);
}

static void NQ_Commit_Coordinator_respond(NQ_Transaction_Commit_Step_Ctx *ctx, int rv) {
  NQ_Request_respond(ctx->sock, NULL, ctx->req, rv);
}

static int NQ_Transaction_fast_commit(NQ_Transaction_Real *t, NQ_Socket *sock, NQ_Request_Data *req) {
  // printf("Fast commit!\n");
  assert(t->commit_state == COMMITSTATE_EXECUTION);

  NQ_Transaction_Commit_Step_Ctx *ctx = 
    NQ_Transaction_Commit_Step_Ctx_create(t->t, NULL, req, -1, -1);
  ctx->sock = sock;
  WaitGroup_open(t, NQ_Transaction_fast_commit_callback, ctx);
  NQ_Transaction_start_remote(t, NQ_Transaction_Commit_Step_Ctx_handle_one, ctx,
			      NQ_TRANSACTION_WG_FAST_COMMIT, 1);
  NQ_Transaction_fast_commit_common(t, ctx, 1);
  t->commit_state = COMMITSTATE_DONE;
  WaitGroup_close(t);
  return 0;
}

static void NQ_Transaction_fast_commit_common(NQ_Transaction_Real *t, NQ_Transaction_Commit_Step_Ctx *ctx, int verdict) {
  assert(verdict);
  assert(t->commit_state == COMMITSTATE_EXECUTION);
  t->commit_state = COMMITSTATE_FINALIZE_NEXT;
  NQ_Transaction_commit_finalize_common(t, ctx, verdict);
}

static void NQ_Transaction_fast_commit_callback(NQ_Transaction_Real *t, void *_ctx) {
  NQ_Transaction_Commit_Step_Ctx *ctx = (NQ_Transaction_Commit_Step_Ctx *)_ctx;
  // Return success (0)
  NQ_Commit_Coordinator_respond(ctx, 0);
  NQ_Transaction_uuid_release(t);
  WG_PING(ctx->request_id);
}

static int NQ_Transaction_commit_start(NQ_Transaction_Real *t, NQ_Socket *sock, NQ_Request_Data *req) {
  int rv = 0;
  if(t->commit_state != COMMITSTATE_EXECUTION) {
    printf("%d: Invalid commit state %d\n", __LINE__, t->commit_state);
    rv = -1;
    goto out;
  }
  NQ_Transaction_Commit_Step_Ctx *ctx = 
    NQ_Transaction_Commit_Step_Ctx_create(t->t, NULL, req, -1, -1);
  ctx->sock = sock;
  WaitGroup_open(t, NQ_Transaction_commit_start_callback, ctx);
  // printf("sending WG_START\n");
  NQ_Transaction_start_remote(t, NQ_Transaction_Commit_Step_Ctx_handle_one, ctx,
			      NQ_TRANSACTION_WG_START, 0);
  NQ_Transaction_commit_start_common(t, ctx, 0);
  t->commit_state = COMMITSTATE_PROPOSAL_NEXT;

  WaitGroup_close(t);
  // at top of every attribute write function, do a check on the transaction to see if modifications are allowed;
 out:
  return rv;
}

static void NQ_Transaction_commit_start_common(NQ_Transaction_Real *t, NQ_Transaction_Commit_Step_Ctx *ctx, int ignored) {
  // do nothing
  ctx->local_result = 1;

}
static void NQ_Transaction_commit_start_callback(NQ_Transaction_Real *t, void *_ctx) {
  NQ_Transaction_Commit_Step_Ctx *ctx = (NQ_Transaction_Commit_Step_Ctx *)_ctx;
  // printf("CommitStart callback: result = %d\n", ctx->result);
  int result = ctx->result && ctx->local_result;
  if(!result) {
    printf("commit_start_callback() error, exiting early\n");
    NQ_Commit_Coordinator_respond(ctx, -1);
    t->commit_state = COMMITSTATE_ERROR;
  } else {
    NQ_Transaction_Commit_Step_Ctx_reset(ctx);
    NQ_Transaction_commit_propose(t, ctx);
  }
  WG_PING(ctx->request_id);
}

static void NQ_Transaction_commit_propose(NQ_Transaction_Real *t, NQ_Transaction_Commit_Step_Ctx *ctx) {
  if(t->commit_state != COMMITSTATE_PROPOSAL_NEXT) {
    printf("%d: Invalid commit state %d\n", __LINE__, t->commit_state);
    NQ_Commit_Coordinator_respond(ctx, -1);
    return;
  }
  WaitGroup_open(t, NQ_Transaction_commit_propose_callback, ctx);

  // tell other NQ servers to start invoking their own proposals
  // printf("sending WG_ADVANCE_TO_PROPOSAL\n");
  NQ_Transaction_start_remote(t, NQ_Transaction_Commit_Step_Ctx_handle_one, ctx,
			      NQ_TRANSACTION_WG_ADVANCE_TO_PROPOSAL, 0);
  // parallelism: do local processing after starting remote servers so
  // local processing overlaps with send
  NQ_Transaction_commit_propose_common(t, ctx, 0);
  /* wait for our prosals, and for other NQ servers involved in
     transaction to get all of their proposals acked
     structured as non-blocking code
  */
  WaitGroup_close(t);
}

static void NQ_Transaction_commit_propose_common(NQ_Transaction_Real *t, NQ_Transaction_Commit_Step_Ctx *ctx, int ignored) {
//  printf("PROPOSE_COMMON\n");
  DeferredTriggers_fire_all(t->sync_veto, NQ_TRIGGER_UPCALL_SYNC_VETO, ctx, 0);
}

static void NQ_Transaction_commit_propose_callback(NQ_Transaction_Real *t, void *_ctx) {
  NQ_Transaction_Commit_Step_Ctx *ctx = (NQ_Transaction_Commit_Step_Ctx *)_ctx;
  // printf("Propose callback\n");
  t->commit_state = COMMITSTATE_VERDICT_NEXT;

  ctx->verdict = ctx->result && ctx->local_result;
  NQ_Transaction_Commit_Step_Ctx_reset(ctx);
  NQ_Transaction_commit_verdict(t, ctx);
  WG_PING(ctx->request_id);
}

static void NQ_Transaction_commit_verdict(NQ_Transaction_Real *t, NQ_Transaction_Commit_Step_Ctx *ctx) {
  if(t->commit_state != COMMITSTATE_VERDICT_NEXT) {
    printf("%d: Invalid commit state %d\n", __LINE__, t->commit_state);
    NQ_Commit_Coordinator_respond(ctx, -1);
    return;
  }
  WaitGroup_open(t, NQ_Transaction_commit_verdict_callback, ctx);

  // printf("sending WG_ADVANCE_TO_VERDICT\n");
  NQ_Transaction_start_remote(t, NQ_Transaction_Commit_Step_Ctx_handle_one, ctx,
			      NQ_TRANSACTION_WG_ADVANCE_TO_VERDICT, ctx->verdict);

  NQ_Transaction_commit_verdict_common(t, ctx, ctx->verdict);
  WaitGroup_close(t);
}

static void NQ_Transaction_commit_verdict_common(NQ_Transaction_Real *t, NQ_Transaction_Commit_Step_Ctx *ctx, int verdict) {
  // Send all synchronous notifications of verdict
  // printf("commit_verdict(%d)\n", verdict);
//  printf("COMMIT_VERDICT_COMMON\n");
  DeferredTriggers_fire_all(t->sync_veto, NQ_TRIGGER_UPCALL_SYNC_VERDICT, ctx, verdict);
  // On abort, only the sync notifications will have already been notified of the transaction, so don't need to send abort to verdict_*
  if(verdict) {
    DeferredTriggers_fire_all(t->sync_verdict, NQ_TRIGGER_UPCALL_SYNC_VERDICT, ctx, verdict);
    // Send all asynchronous notifications of verdict
    DeferredTriggers_fire_all(t->async_verdict, NQ_TRIGGER_UPCALL_ASYNC_VERDICT, ctx, verdict);
  }
}

static void NQ_Transaction_commit_verdict_callback(NQ_Transaction_Real *t, void *_ctx) {
  NQ_Transaction_Commit_Step_Ctx *ctx = (NQ_Transaction_Commit_Step_Ctx *)_ctx;
  // printf("Verdict callback\n");
  t->commit_state = COMMITSTATE_FINALIZE_NEXT;
  // ignore return value
  NQ_Transaction_Commit_Step_Ctx_reset(ctx);
  NQ_Transaction_commit_finalize(t, ctx);
  WG_PING(ctx->request_id);
}

static void NQ_Transaction_commit_finalize(NQ_Transaction_Real *t, NQ_Transaction_Commit_Step_Ctx *ctx) {
  if(t->commit_state != COMMITSTATE_FINALIZE_NEXT) {
    printf("%d: Invalid commit state %d\n", __LINE__, t->commit_state);
    NQ_Commit_Coordinator_respond(ctx, -1);
    return;
  }
  // printf("Finalizing\n");

  WaitGroup_open(t, NQ_Transaction_commit_finalize_callback, ctx);
  // printf("sending WG_FINALIZE\n");
  NQ_Transaction_start_remote(t, NQ_Transaction_Commit_Step_Ctx_handle_one, ctx,
			      NQ_TRANSACTION_WG_FINALIZE, ctx->verdict);

  NQ_Transaction_commit_finalize_common(t, ctx, ctx->verdict);
  WaitGroup_close(t);
}

static void NQ_Transaction_commit_finalize_common(NQ_Transaction_Real *t, NQ_Transaction_Commit_Step_Ctx *ctx, int verdict) { 
  // printf("Finalize verdict %s\n", verdict ? "commit" : "abort");
 if(verdict) {
   if(t->commit_state != COMMITSTATE_FINALIZE_NEXT) {
     printf("cannot finalize commit unless in COMMITSTATE_FINALIZE_NEXT (is %d)\n",
	    t->commit_state);
     return;
   }
 } else {
   if( !(t->commit_state == COMMITSTATE_FINALIZE_NEXT ||
	 t->commit_state == COMMITSTATE_EXECUTION) ) {
     printf("cannot finalize abort (state = %d)\n", t->commit_state);
     return;
   }
 }
  NQ_Transaction_Finalize(t->t, t, verdict ? 
			  NQ_TRANSACTION_CALLBACK_COMMIT : 
			  NQ_TRANSACTION_CALLBACK_ABORT);
  t->commit_state = COMMITSTATE_DONE_NEXT;
}

static void NQ_Transaction_commit_finalize_callback(NQ_Transaction_Real *t, void *_ctx) {
  NQ_Transaction_Commit_Step_Ctx *ctx = (NQ_Transaction_Commit_Step_Ctx *)_ctx;
  WG_PING(ctx->request_id);
  NQ_Commit_Coordinator_respond(ctx, ctx->verdict ? 0 : -1);

  WaitGroup_open(t, NULL, NULL);
  // fprintf(stderr, "sending WG_DONE\n");
  NQ_Transaction_start_remote(t, NULL, NULL,
			      NQ_TRANSACTION_WG_DONE, ctx->verdict);
  NQ_Transaction_commit_done_common(t, ctx, ctx->verdict);
  WaitGroup_close(t);

  // release can't be in common because we still need t after returning from common
  NQ_Transaction_uuid_release(t);
  WG_PING(ctx->request_id);
}

static void NQ_Transaction_commit_done_common(NQ_Transaction_Real *t, NQ_Transaction_Commit_Step_Ctx *ctx, int verdict) {
  // Always send a done to make regression tests slightly easier to write

  // We might be able to optimize this to avoid sending in some cases
  // (as in logic for commit_verdict_common)

  if(0 && NQ_Net_get_localhost().port < 8000) {
    printf("\tSending commit done; ");
    printf("Host is "); NQ_Host_print(NQ_Net_get_localhost());
  }
//  printf("COMMIT_DONE_COMMON\n");
  DeferredTriggers_fire_all(t->commit_done, NQ_TRIGGER_UPCALL_ASYNC_COMMIT_DONE, ctx, 1);
  t->commit_state = COMMITSTATE_DONE;
}

int NQ_Transaction_has_pending_triggers(NQ_Transaction_Real *t) {
  return DeferredTriggers_size(t->sync_veto) +
    DeferredTriggers_size(t->sync_verdict) +
    DeferredTriggers_size(t->async_verdict) +
    DeferredTriggers_size(t->commit_done) > 0;
}
static int nq_transaction_fast_commit_enabled = 0; //debug... Fast commit doesn't properly detect when triggers are installed
void NQ_Local_Transaction_enable_fast_commit(){
  nq_transaction_fast_commit_enabled = 1;
}
int NQ_Local_Transaction_commit(NQ_Transaction transaction, NQ_Socket *sock, NQ_Request_Data *req) {
  int rv;
  NQ_Transaction_Real *t;

  t = NQ_UUID_lookup(transaction);
  if(t == NULL) {
    printf("Error looking up  transaction\n");
    return -1;
  }

  if(nq_transaction_fast_commit_enabled
     && t->shadow_state.is_valid && !t->shadow_state.remotes_have_triggers && 
     !NQ_Transaction_has_pending_triggers(t)) {
    // N.B. Other fast commit modes are possible
    NQ_stat.fast_commit++;
    rv = NQ_Transaction_fast_commit(t, sock, req);
  } else {
    //printf("Slow commit!\n");
    NQ_stat.normal_commit++;
    rv = NQ_Transaction_commit_start(t, sock, req);
  }
  NQ_Transaction_Real_put(t);
  return rv;
}

static int NQ_Local_Transaction_WG_commit_generic
(NQ_Transaction_Real *t, NQ_Transaction_Commit_Step_Ctx *ctx, 
 const char *name,
 NQ_Transaction_Commit_State curr_state, NQ_Transaction_Commit_State next_state, 
 void (*func)(NQ_Transaction_Real *t, NQ_Transaction_Commit_Step_Ctx *ctx, int verdict)) {
  // printf("WG(%s)\n", name);
  if((curr_state != COMMITSTATE_ANY) && (t->commit_state != curr_state)) {
    printf("%s: Error (%d,%d)\n", name, t->commit_state, curr_state);
    printf("Error thread = %d\n", (int)pthread_self());
    return -1;
  }

  WaitGroup_open(t, NQ_Transaction_Commit_Step_Ctx_respond_group, ctx);

  func(t, ctx, ctx->arg);
  WaitGroup_close(t);
  if(curr_state != COMMITSTATE_ANY) {
    t->commit_state = next_state;
  }
  return 0;
}

int NQ_Local_Transaction_WG_commit_start(NQ_Transaction_Real *t, NQ_Transaction_Commit_Step_Ctx *ctx) {
  return NQ_Local_Transaction_WG_commit_generic
    (t, ctx, "COMMIT_START", 
     COMMITSTATE_EXECUTION, COMMITSTATE_PROPOSAL_NEXT,
     NQ_Transaction_commit_start_common);
}
int NQ_Local_Transaction_WG_commit_propose(NQ_Transaction_Real *t, NQ_Transaction_Commit_Step_Ctx *ctx) {
  return NQ_Local_Transaction_WG_commit_generic
    (t, ctx, "COMMIT_PROPOSE", 
     COMMITSTATE_PROPOSAL_NEXT, COMMITSTATE_VERDICT_NEXT,
     NQ_Transaction_commit_propose_common);
}

int NQ_Local_Transaction_WG_commit_verdict(NQ_Transaction_Real *t, NQ_Transaction_Commit_Step_Ctx *ctx) {
  // pass down arg
  return NQ_Local_Transaction_WG_commit_generic
    (t, ctx, "COMMIT_VERDICT", 
     COMMITSTATE_VERDICT_NEXT, COMMITSTATE_FINALIZE_NEXT,
     NQ_Transaction_commit_verdict_common);
}

int NQ_Local_Transaction_WG_commit_finalize(NQ_Transaction_Real *t, NQ_Transaction_Commit_Step_Ctx *ctx) {
  int rv = NQ_Local_Transaction_WG_commit_generic
    (t, ctx, "COMMIT_FINALIZE", 
     // start state checking is done in commit_finalize_common
     COMMITSTATE_ANY, COMMITSTATE_DONE_NEXT,
     NQ_Transaction_commit_finalize_common);
  return rv;
}

int NQ_Local_Transaction_WG_commit_done(NQ_Transaction_Real *t, NQ_Transaction_Commit_Step_Ctx *ctx) {
  int rv = NQ_Local_Transaction_WG_commit_generic
    (t, ctx, "COMMIT_DONE", 
     COMMITSTATE_DONE_NEXT, COMMITSTATE_DONE,
     NQ_Transaction_commit_done_common);
  // printf("CommitDone, releasing\n");
  NQ_Transaction_uuid_release(t);
  return rv;
}

int NQ_Local_Transaction_WG_test(NQ_Transaction_Real *t, NQ_Transaction_Commit_Step_Ctx *ctx) {
  return NQ_Local_Transaction_WG_commit_generic
    (t, ctx, "TEST", 
     COMMITSTATE_EXECUTION, COMMITSTATE_EXECUTION,
     NQ_Transaction_test_common);
}

int NQ_Local_Transaction_WG_fast_commit(NQ_Transaction_Real *t, NQ_Transaction_Commit_Step_Ctx *ctx) {
  return NQ_Local_Transaction_WG_commit_generic
    (t, ctx, "FAST_COMMIT", 
     COMMITSTATE_EXECUTION, COMMITSTATE_DONE,
     NQ_Transaction_fast_commit_common);
}

int NQ_Transaction_commit(NQ_Transaction transaction){
fprintf(stderr, "%lf: commit, thread = %x\n", doubleTime(), (int)pthread_self());
  int ret;
  ret = NQ_Net_Transaction_test(transaction);
  // printf("transaction test return: %d\n", ret);
  if(ret){
    //  error from test will signal error to caller
    NQ_Net_Transaction_abort(transaction);
  } else {
    ret = NQ_Net_Transaction_commit(transaction);
  }
  return ret;
}

void NQ_Transaction_uuid_release(NQ_Transaction_Real *t){
  void *ref;

  if(t){
    while(queue_dequeue(&t->remotes, &ref) == 0){
      free(ref);
    }

    DeferredTriggers_destroy(t->sync_veto);
    DeferredTriggers_destroy(t->sync_verdict);
    DeferredTriggers_destroy(t->async_verdict);
    DeferredTriggers_destroy(t->commit_done);

    switch(t->type) {
    case NQ_TRANSACTION_DEFAULT: {
      NQ_Transaction_Real *t1 = NQ_UUID_release(t->t);
      assert(t == t1);
      NQ_Transaction_Real_put(t);
      break;
    }
    case NQ_TRANSACTION_REMOTE: {
      NQ_Transaction_Remote *r = hashtable_remove(remote_transactions, &t->t);
//      printf("delete: ");NQ_UUID_print(&t->t);printf(", %p\n", r);
      // printf("release remote (%p)\n", r);
      free(r);
      break;
    }
    default:
      assert(0);
    }
  }
}
  
NQ_Transaction_Remote *NQ_Transaction_install_remote(NQ_Transaction t){
  NQ_Transaction_Remote *remote;
  remote = malloc(sizeof(NQ_Transaction_Remote));
  bzero(remote, sizeof(NQ_Transaction_Remote));

  NQ_Transaction_Real_init(&remote->trans, t, NQ_TRANSACTION_REMOTE);

//  printf("put: ");NQ_UUID_print(&t);printf(", %p\n", remote);
  hashtable_insert(remote_transactions, &remote->trans.t, remote);
  // printf("new remote = %p ", remote); NQ_UUID_print(&remote->trans.t); printf("\n");
  return remote;
}

NQ_Transaction_Real *NQ_Transaction_register_remote(NQ_Transaction t){
  NQ_Transaction_Remote *remote;
  if((remote = NQ_Transaction_Remote_get(t))){
    //we're already in the system.  No need to do anything further.
    // printf("already have remote trans %p for ", remote); NQ_UUID_print(&t); printf("\n");
    return &remote->trans;
  }
  
  // printf("\tsending register remote: ");NQ_UUID_print(&t);printf("\n");

  remote = NQ_Transaction_install_remote(t);
  // fprintf(stderr, "<R_REGISTER>\n");
  NQ_Net_Transaction_remote(t, t.home, NQ_REQUEST_TRANSACTION_R_REGISTER);
  return &remote->trans;
}

int NQ_Transaction_Remote_Reference_find(NQ_Transaction_Remote_Reference *ref, NQ_Host *host){
  return NQ_Host_eq(*host, ref->host);
}

int NQ_Transaction_Real_check_registered(NQ_Transaction_Real *transaction, NQ_Host host) {
  return queue_find(&transaction->remotes, (PFany)NQ_Transaction_Remote_Reference_find, &host) != NULL;
}
int NQ_Transaction_client_registered(NQ_Transaction t, NQ_Host host){
  if(NQ_Net_is_local(host)) return 0;
  NQ_Transaction_Real *transaction = NQ_UUID_lookup(t);
  if(!transaction){
    printf("\t\tNQ_Transaction_client_registered failed! uuid = "); NQ_UUID_print(&t); printf("\n");
    *(int*)0 = 0;
    printf("wedging\n");
    while(1);
    assert(0);
    return -1;
  }
  int rv = 0;
  if(!NQ_Transaction_Real_check_registered(transaction, host)) {
	  rv = 1;
  }
  NQ_Transaction_Real_put(transaction);
  return rv;
}

// NQ_Transaction_register_client(): locally instantiate the transaction
int NQ_Transaction_register_client(NQ_Transaction t, NQ_Host host){
  NQ_Transaction_Real *transaction;
  NQ_Transaction_Remote_Reference *ref;
  int err = 0;

  transaction = NQ_UUID_lookup(t);
  if(!transaction){
    printf("\t\tNQ_Transaction_register_client failed! uuid = "); NQ_UUID_print(&t); printf("\n");
    assert(0);
    return -1;
  }

  pthread_mutex_lock(&transaction->mutex);
  if(NQ_Transaction_Real_check_registered(transaction, host)) {
    // fprintf(stderr, "Already registered!\n");
    err = -1;
    goto out;
  }
  ref = malloc(sizeof(NQ_Transaction_Remote_Reference));
  bzero(ref, sizeof(NQ_Transaction_Remote_Reference));
  ref->trans = transaction;
  ref->host = host;
  queue_append(&transaction->remotes, ref);

#if 0
  static pthread_mutex_t reg_hack_mutex = PTHREAD_MUTEX_INITIALIZER;
  pthread_mutex_lock(&reg_hack_mutex);
  fprintf(stderr, "Remote len = %d, thread = %p\n", transaction->remotes.len, (void*)pthread_self());
  NQ_Host_fprint(stderr, host);
  stackdump_stderr();
  pthread_mutex_unlock(&reg_hack_mutex);
#endif

  int remote_state = transaction->commit_state;
  // This can happen in the middle of commit processing. In this case,
  // the remote transaction needs to be synced with the next state of
  // the local transaction.
  switch(remote_state) {
  case COMMITSTATE_PROPOSAL_NEXT:
    remote_state = COMMITSTATE_VERDICT_NEXT;
    break;
  case COMMITSTATE_VERDICT_NEXT:
    remote_state = COMMITSTATE_FINALIZE_NEXT;
    break;
  case COMMITSTATE_FINALIZE_NEXT:
    remote_state = COMMITSTATE_DONE_NEXT;
    break;
  }
  NQ_Net_Transaction_set_remote_state(transaction->t, host, remote_state);
 out:
  pthread_mutex_unlock(&transaction->mutex);
  NQ_Transaction_Real_put(transaction);
  return err;
}

int NQ_Local_Transaction_set_remote_state(NQ_Transaction transaction, int state) {
  assert(!NQ_Net_is_local(transaction.home));

  NQ_Transaction_Real *real = 
    NQ_Transaction_register_remote(transaction); // make sure remote is registered
  real->commit_state = state;
  return 0;
}

int NQ_Transaction_step(NQ_Transaction transaction, NQ_Transaction_Step_Type *type, void *data, int revision){
  NQ_Transaction_Step *s;
  NQ_Transaction_Real *t;
  
  //printf("Transaction_Step: %p\n", type);
  
  if(NQ_UUID_eq(&transaction, &NQ_uuid_error)){
    //not a transaction.  commit immediately.
    if(type->callbacks[NQ_TRANSACTION_CALLBACK_COMMIT]){
      type->callbacks[NQ_TRANSACTION_CALLBACK_COMMIT](transaction, data, revision);
    }
    return 0;
  }
  t = NQ_Transaction_get_any(transaction);
  if(!t) {
    // this error is not checked in enough places!
    printf("\n\n========== Unknown Transaction Taking Place! ===========\n");
    NQ_UUID_dump(NQ_uuid_error, NQ_UUID_TRANSACTION);
    printf("Current transaction: ");NQ_UUID_print(&transaction);printf("\n\n"); 
    assert(0);
    return -1;
  }
  
  s = malloc(sizeof(NQ_Transaction_Step));
  bzero(s, sizeof(NQ_Transaction_Step));
  s->data = data;
  s->revision = revision;
  s->type = type;
  
  //printf("=============>> TRANSACTION STEP: %p %p <<=============\n", type, data);
  
  queue_append(&t->steps, s);
  NQ_Transaction_Real_put(t);
  return 0;
}

void NQ_Transaction_update_shadow_state(NQ_Transaction transaction, int remote_has_triggers) {
  NQ_Transaction_Real *t_real;
#if 0
  if(remote_has_triggers) {
    printf("update shadow state!\n");
  }
#endif
  if(NQ_Net_is_local(transaction.home)) {
    t_real = (NQ_Transaction_Real *)NQ_UUID_lookup(transaction);
    t_real->shadow_state.remotes_have_triggers |= remote_has_triggers;
    NQ_Transaction_Real_put(t_real);
  } else {
    // Decide whether we should invalidate remote state
    if(remote_has_triggers) {
      NQ_Net_Transaction_invalidate_shadow_state(transaction);
    }
  }
}

int NQ_Local_Transaction_invalidate_shadow_state(NQ_Transaction transaction) {
  // printf("====> Invalidate shadow state!\n");
  NQ_Transaction_Real *t_real = NULL;
  if(NQ_Net_is_local(transaction.home)) {
    t_real = (NQ_Transaction_Real *)NQ_UUID_lookup(transaction);
  }
  if(t_real == NULL) {
    printf("NQ_Local_Transaction_invalidate_shadow_state: not found!\n");
    return -1;
  }
  if(t_real->commit_state != COMMITSTATE_EXECUTION) {
    // printf("NQ_Local_Transaction_invalidate_shadow_state: wrong state!\n");
    return -2;
  }
  printf("=====> Invalidating shadow state!\n");
  t_real->shadow_state.is_valid = 0;
  NQ_Transaction_Real_put(t_real);
  return 0;
}
