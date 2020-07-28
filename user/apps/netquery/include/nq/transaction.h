#ifndef NETQUERY_TRANSACTION_H_SHIELD
#define NETQUERY_TRANSACTION_H_SHIELD

#ifdef __cplusplus
extern "C" {
#endif

#include "attribute.h"
#include "uuid.h"
#include <pthread.h>

typedef int (*NQ_Transaction_Callback)(NQ_Transaction transaction, void *userdata, int revision);
typedef enum {
  NQ_TRANSACTION_CALLBACK_COMMIT, 
  NQ_TRANSACTION_CALLBACK_ABORT, 
  NQ_TRANSACTION_CALLBACK_TEST,
  NQ_TRANSACTION_CALLBACK_COUNT
} NQ_Transaction_Callback_Type;

typedef struct NQ_Transaction_Step_Type {
  NQ_Transaction_Callback callbacks[NQ_TRANSACTION_CALLBACK_COUNT];
} NQ_Transaction_Step_Type;

typedef struct NQ_Transaction_Step {
  struct NQ_Transaction_Step *next, *prev;
  NQ_Transaction_Step_Type *type;
  void *data;
  int revision;
} NQ_Transaction_Step;

typedef enum { NQ_TRANSACTION_DEFAULT, NQ_TRANSACTION_REMOTE,  } NQ_Transaction_Type;

struct NQ_Socket;
struct NQ_Request_Data;
typedef struct NQ_Transaction_Commit_Step_Ctx {
  // int pending;
  NQ_Transaction transaction;
  // local_result, result, and verdict are boolean values (1 = true/succeed, 0 = false/fail)
  int local_result;
  int result;
  int verdict;

  int request_id; // valid only for server-side

  int arg;

  // XXX: Host is only used on coordinator, sock is only used on servers (for request reply)
  union {
    NQ_Host host;
    struct NQ_Socket *sock;
  };

  struct NQ_Request_Data *req;
} NQ_Transaction_Commit_Step_Ctx;

typedef struct NQ_Request_Ctx {
  // int pending;
  NQ_Transaction transaction;
  // local_result, result, and verdict are boolean values (1 = true/succeed, 0 = false/fail)
  int local_result;
  int result;

  struct NQ_Socket *sock;
  struct NQ_Request_Data *req;
} NQ_Request_Ctx;


NQ_Transaction_Commit_Step_Ctx *NQ_Transaction_Commit_Step_Ctx_create
(NQ_Transaction t, const NQ_Host *host, struct NQ_Request_Data *req, int request_id, int arg);
void NQ_Transaction_Commit_Step_Ctx_destroy(NQ_Transaction_Commit_Step_Ctx *step);
void NQ_Commit_Server_respond(NQ_Transaction_Commit_Step_Ctx *step, int rv);

NQ_Request_Ctx *NQ_Request_Ctx_create(NQ_Transaction t, struct NQ_Socket *sock, struct NQ_Request_Data *req);
void NQ_Request_Ctx_destroy(NQ_Request_Ctx *ctx);

typedef enum NQ_Transaction_Commit_State {
  COMMITSTATE_EXECUTION, // "COMMITSTATE_START_NEXT"
  COMMITSTATE_PROPOSAL_NEXT,
  COMMITSTATE_VERDICT_NEXT,
  COMMITSTATE_FINALIZE_NEXT,

  COMMITSTATE_DONE_NEXT,
  COMMITSTATE_DONE,

  COMMITSTATE_ERROR,

  // never enters this state
  COMMITSTATE_ANY,
} NQ_Transaction_Commit_State;

struct DeferredTriggers;

  struct WaitGroupServer;
  struct WaitGroup;

typedef struct NQ_Transaction_Real {
  Queue steps;
  NQ_Transaction t;
  NQ_Transaction_Type type;
  Queue remotes;
  int refcnt;
  struct {
    int is_valid;
    int remotes_have_triggers;
  } shadow_state;

  pthread_mutex_t mutex;
  NQ_Transaction_Commit_State commit_state;
  struct {
    // int response;
    struct WaitGroupServer *wait_group_server;
  } server;

  struct {
    struct WaitGroup *wait_group;
  } coordinator;

  // shared state
  // Lists of deferred triggers
  struct DeferredTriggers *sync_veto;
  struct DeferredTriggers *sync_verdict;
  struct DeferredTriggers *async_verdict;
  struct DeferredTriggers *commit_done;
} NQ_Transaction_Real;

void NQ_Transaction_Real_get(NQ_Transaction_Real *);
void NQ_Transaction_Real_put(NQ_Transaction_Real *);

struct DeferredTriggers *DeferredTriggers_create(NQ_Transaction_Real *t);
void DeferredTriggers_destroy(struct DeferredTriggers *);
void DeferredTriggers_fire_all(struct DeferredTriggers *t, NQ_Trigger_Upcall_Type type, 
			       NQ_Transaction_Commit_Step_Ctx *ctx, int arg);
int DeferredTriggers_size(struct DeferredTriggers *t);

NQ_Transaction_Real *NQ_Transaction_Remote_get_local(NQ_Transaction t);
  // Get either local or remote
NQ_Transaction_Real *NQ_Transaction_get_any(NQ_Transaction t);

int NQ_Transaction_has_pending_triggers(NQ_Transaction_Real *t);

void NQ_Transaction_init(void);
void NQ_Local_Transaction_enable_fast_commit();

NQ_Transaction NQ_Transaction_begin(void);
int NQ_Transaction_abort(NQ_Transaction transaction);
int NQ_Transaction_commit(NQ_Transaction transaction);

int NQ_Transaction_allow_modify(NQ_Transaction transaction);

int NQ_Transaction_remote_test(NQ_Transaction t);
int NQ_Transaction_remote_commit(NQ_Transaction t);
int NQ_Transaction_remote_abort(NQ_Transaction t);

typedef struct NQ_Transaction_Remote NQ_Transaction_Remote;
NQ_Transaction_Remote *NQ_Transaction_install_remote(NQ_Transaction t);
NQ_Transaction_Real *NQ_Transaction_register_remote(NQ_Transaction t);
int NQ_Transaction_register_client(NQ_Transaction, NQ_Host host);
int NQ_Transaction_client_registered(NQ_Transaction t, NQ_Host host);

int NQ_Transaction_step(NQ_Transaction transaction, NQ_Transaction_Step_Type *type, void *data, int revision);
int NQ_Transaction_subseteq(NQ_Transaction transaction, NQ_Transaction sub);

//Don't call these.  They're internal functions only.
NQ_Transaction NQ_Local_Transaction_begin(void);
int NQ_Local_Transaction_abort(NQ_Transaction transaction, struct NQ_Socket *sock, struct NQ_Request_Data *req);
int NQ_Local_Transaction_commit(NQ_Transaction transaction, struct NQ_Socket *sock, struct NQ_Request_Data *req);

int NQ_Local_Transaction_WG_commit_start(NQ_Transaction_Real *t, NQ_Transaction_Commit_Step_Ctx *ctx);
int NQ_Local_Transaction_WG_commit_propose(NQ_Transaction_Real *t, NQ_Transaction_Commit_Step_Ctx *ctx);
int NQ_Local_Transaction_WG_commit_verdict(NQ_Transaction_Real *t, NQ_Transaction_Commit_Step_Ctx *ctx);
int NQ_Local_Transaction_WG_commit_finalize(NQ_Transaction_Real *t, NQ_Transaction_Commit_Step_Ctx *ctx);
  int NQ_Local_Transaction_WG_commit_done(NQ_Transaction_Real *t, NQ_Transaction_Commit_Step_Ctx *ctx);
int NQ_Local_Transaction_WG_test(NQ_Transaction_Real *t, NQ_Transaction_Commit_Step_Ctx *ctx);

int NQ_Local_Transaction_WG_fast_commit(NQ_Transaction_Real *t, NQ_Transaction_Commit_Step_Ctx *ctx);

int NQ_Local_Transaction_test(NQ_Transaction transaction, struct NQ_Socket *sock, struct NQ_Request_Data *req);
  // int NQ_Request_Transaction_step_finish(NQ_Socket *sock, NQ_Request_Data *req, int result);

void NQ_Local_Transaction_commit_proposal(NQ_Transaction_Real *t);

void NQ_Transaction_update_shadow_state(NQ_Transaction transaction, int remote_has_triggers);

int NQ_Local_Transaction_invalidate_shadow_state(NQ_Transaction transaction);

#ifdef __cplusplus
}
#endif

#endif
