#ifndef NQ_NET_H_SHIELD
#define NQ_NET_H_SHIELD

#include <nq/netquery.h>
#include <nq/socket.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ERR_NO_REQUESTS_LEFT        101
#define ERR_BATCH_READ_OUT_OF_ORDER 102
#define ERR_UNABLE_TO_RESOLVE_UUID  103
#define ERR_UNABLE_TO_RESOLVE_TRANS 104
#define ERR_UNABLE_TO_UNPICKLE(a)   (200+a)

#define NQ_REQUEST_MASK_DIRECTION (0x01)
#define NQ_REQUEST_REQUEST        (0x00)
#define NQ_REQUEST_RESPONSE       (0x01)

#define NQ_REQUEST_MASK_CLASS     (0xF0)
#define NQ_REQUEST_INTERNAL       (0x00)
#define NQ_REQUEST_ATTRIBUTE      (0x10)
#define NQ_REQUEST_TRANSACTION    (0x20)
#define NQ_REQUEST_TUPLE          (0x30)
#define NQ_REQUEST_TRIGGER        (0x40)
#define NQ_REQUEST_PRINCIPAL      (0x50)
#define NQ_REQUEST_GCOLLECT       (0x60)

#define NQ_REQUEST_BUNDLE       (0x70)


#define NQ_REQUEST_MASK_REQUEST           (0x0F01)
#define NQ_REQUEST_INTERNAL_HELLO         (NQ_REQUEST_INTERNAL|0x000)

#define NQ_REQUEST_ATTRIBUTE_OP           (NQ_REQUEST_ATTRIBUTE|0x100)
#define NQ_REQUEST_ENUMERATE_ATTRIBUTES           (NQ_REQUEST_ATTRIBUTE|0x200)

#define NQ_REQUEST_TUPLE_CREATE           (NQ_REQUEST_TUPLE|0x100)
#define NQ_REQUEST_TUPLE_DELETE           (NQ_REQUEST_TUPLE|0x200)
#define NQ_REQUEST_TUPLE_ADD_ATT          (NQ_REQUEST_TUPLE|0x300)
#define NQ_REQUEST_TUPLE_DEL_ATT          (NQ_REQUEST_TUPLE|0x400)

#define NQ_REQUEST_ENUMERATE_TUPLES          (NQ_REQUEST_TUPLE|0x800)

#define NQ_REQUEST_TRANSACTION_START      (NQ_REQUEST_TRANSACTION|0x100)
#define NQ_REQUEST_TRANSACTION_COMMIT     (NQ_REQUEST_TRANSACTION|0x200)
#define NQ_REQUEST_TRANSACTION_ABORT      (NQ_REQUEST_TRANSACTION|0x300)
#define NQ_REQUEST_TRANSACTION_TEST       (NQ_REQUEST_TRANSACTION|0x400)

// #define NQ_REQUEST_TRANSACTION_R_TEST     (NQ_REQUEST_TRANSACTION|0x500)
// #define NQ_REQUEST_TRANSACTION_R_COMMIT   (NQ_REQUEST_TRANSACTION|0x600)
// #define NQ_REQUEST_TRANSACTION_R_ABORT    (NQ_REQUEST_TRANSACTION|0x700)
#define NQ_REQUEST_TRANSACTION_R_REGISTER (NQ_REQUEST_TRANSACTION|0x800)

  // NQ_REQUEST_TRANSACTION_R_REGISTER_SET_STATE synchronizes the local
  // transaction's state with the remote's.
#define NQ_REQUEST_TRANSACTION_R_REGISTER_SET_STATE (NQ_REQUEST_TRANSACTION|0x900)

// #define NQ_REQUEST_TRANSACTION_R_TESTRESP (NQ_REQUEST_TRANSACTION|0x900)

#define NQ_REQUEST_TRANSACTION_R_WAITGROUP (NQ_REQUEST_TRANSACTION|0xa00)
#define NQ_REQUEST_TRANSACTION_R_WAITGROUP_RESP (NQ_REQUEST_TRANSACTION|0xb00)
#define NQ_REQUEST_TRANSACTION_R_PREREGISTER (NQ_REQUEST_TRANSACTION|0xc00)

#define NQ_REQUEST_TRANSACTION_INVALIDATE_SHADOWSTATE       (NQ_REQUEST_TRANSACTION|0xd00)


#define NQ_REQUEST_GCOLLECT_CREATE_GROUP        (NQ_REQUEST_GCOLLECT|0x000)
#define NQ_REQUEST_GCOLLECT_TOUCH_UUID          (NQ_REQUEST_GCOLLECT|0x100)
#define NQ_REQUEST_GCOLLECT_TOUCH_ATTRIBUTE     (NQ_REQUEST_GCOLLECT|0x200)

#define NQ_REQUEST_BUNDLE_BEGIN       (NQ_REQUEST_BUNDLE|0x000)
#define NQ_REQUEST_BUNDLE_END       (NQ_REQUEST_BUNDLE|0x100)

// argument opcode for NQ_REQUEST_TRANSACTION_R_WAITGROUP
#define NQ_TRANSACTION_WG_START 	(0x0)
#define NQ_TRANSACTION_WG_ADVANCE_TO_PROPOSAL 	(0x1)
#define NQ_TRANSACTION_WG_ADVANCE_TO_VERDICT 	(0x2) // one argument: verdict
#define NQ_TRANSACTION_WG_TEST 		(0x4)

#define NQ_TRANSACTION_WG_FINALIZE 		(0x5)  // one argument: verdict, e.g. commit = 1, abort = 0
#define NQ_TRANSACTION_WG_DONE 		(0x6) // deallocate transaction state: one argument, verdict commit = 1, abort = 0

#define NQ_TRANSACTION_WG_FAST_COMMIT 		(0x7) // Special case commit: no triggers

#define NQ_TRANSACTION_WG_TRIGGER	(0x80) // bitmask, used to allow triggers and other WG control messages to coexist in same table

#define NQ_REQUEST_TRIGGER_CREATE         (NQ_REQUEST_TRIGGER|0x000)
#define NQ_REQUEST_TRIGGER_DELETE         (NQ_REQUEST_TRIGGER|0x100)
#define NQ_REQUEST_TRIGGER_FIRE           (NQ_REQUEST_TRIGGER|0x200)
#define NQ_REQUEST_TRIGGER_BULK_CREATE         (NQ_REQUEST_TRIGGER|0x300)

#define NQ_REQUEST_ENUMERATE_TRIGGERS         (NQ_REQUEST_TRIGGER|0x400)
#define NQ_REQUEST_ENUMERATE_TUPLE_TRIGGERS         (NQ_REQUEST_TRIGGER|0x500)

#define NQ_PORT_ANY ((unsigned short)-1)

typedef enum { NQ_STATUS_UNTOUCHED, NQ_STATUS_ISSUED, NQ_STATUS_ERROR, NQ_STATUS_LOCAL, NQ_STATUS_REMOTE, NQ_STATUS_FINISHED } NQ_Request_Pending_Status;

void NQ_Net_init(unsigned int my_ip, unsigned short port);
void NQ_Net_start_daemon(int port);
void NQ_Net_set_server(unsigned int addr, unsigned short port);
void NQ_Net_set_localserver(void);

void NQ_Net_poll(int timeout);
void NQ_Net_nudge_pollthread();

#define NQ_PRINT_STATS_ATTR_OPS           (0x00001)
#define NQ_PRINT_STATS_TRIGGER_OPS        (0x00002)
void NQ_Net_set_stats(int stats);

void *NQ_Net_accept(NQ_Socket *server, NQ_Socket *sock);
void NQ_Net_data(NQ_Socket *sock);
void NQ_Net_error(NQ_Socket *sock);

NQ_Host NQ_Net_get_localhost(void);
int NQ_Net_is_local(NQ_Host addr);
void NQ_Host_print(NQ_Host host);
void NQ_Host_fprint(FILE *fp, NQ_Host host);
NQ_Host NQ_Net_get_sockhost(NQ_Socket *sock);

typedef void (*NQ_User_Async_Call)(void *userdata);
void NQ_user_call_async(NQ_User_Async_Call call, void *userdata);

struct NQ_Peer;
int NQ_Request_issue_async(NQ_Host host, NQ_RingBuffer *pickle, unsigned int type, int err);
int NQ_Peer_issue_async(struct NQ_Peer *peer, NQ_RingBuffer *pickle, unsigned int type, int err);
void NQ_Peer_cork(struct NQ_Peer *peer);
int NQ_Peer_uncork(struct NQ_Peer *peer);

  // don't pass down batch -- the batch operations are probably not re-entrant
typedef void (*NQ_Batch_Handler)(void *handler_state, NQ_Request_Pending_Status status);

typedef struct NQ_Net_Batch NQ_Net_Batch;

NQ_Net_Batch *NQ_Net_Batch_create();

//the number of ops pending completion.  (implementation is slow for now)
int NQ_Net_Batch_pending(NQ_Net_Batch *batch);
//whether or not the next _finish() operation will block
int NQ_Net_Batch_willblocknext(NQ_Net_Batch *batch);

//destroy the batch datastructure.  Block also waits for everything to complete.
int NQ_Net_Batch_block(NQ_Net_Batch *batch);
void NQ_Net_Batch_destroy(NQ_Net_Batch *batch);

// Remote function calls (pickle.c)
  NQ_Tuple NQ_Net_Tuple_create(NQ_Transaction transaction, NQ_Host home, NQ_Principal *actor);
  void NQ_Batch_Tuple_create(NQ_Transaction transaction, NQ_Host home, NQ_Principal *actor, NQ_Net_Batch *batch);
  NQ_Tuple NQ_Batch_Tuple_create_finish(NQ_Net_Batch *batch);

int NQ_Net_Tuple_delete(NQ_Transaction transaction, NQ_Principal *actor, NQ_Tuple tuple);
void NQ_Batch_Tuple_delete(NQ_Transaction transaction, NQ_Principal *actor, NQ_Net_Batch *batch, NQ_Tuple tuple);
int NQ_Batch_Tuple_delete_finish(NQ_Net_Batch *batch);

int NQ_Net_Tuple_add_attribute(NQ_Transaction transaction, NQ_Tuple tuple, NQ_Attribute_Name *name);
int NQ_Net_Tuple_remove_attribute(NQ_Transaction transaction, NQ_Tuple tuple, NQ_Attribute_Name *name);

void NQ_Batch_Tuple_remove_attribute(NQ_Transaction transaction, NQ_Tuple tuple, NQ_Attribute_Name *name, NQ_Net_Batch *batch);
int NQ_Batch_Tuple_remove_attribute_finish(NQ_Net_Batch *batch);

  int NQ_Net_Attribute_operate(NQ_Transaction transaction, NQ_Principal *actor, NQ_Attribute_Name *name, NQ_Tuple tuple, NQ_Attribute_Operation op, char **iobuffer, int *iolength, NQ_Principal **output_attributed_to);
int NQ_Batch_Attribute_operate(NQ_Transaction transaction, NQ_Principal *actor, NQ_Attribute_Name *name, NQ_Tuple tuple, NQ_Attribute_Operation op, char **iobuffer, int *iolength, NQ_Net_Batch *batch, NQ_Batch_Handler handler, void *handler_state);
int NQ_Batch_Attribute_operate_finish(char **iobuffer, int *iolength, NQ_Principal **output_attributed_to, NQ_Net_Batch *batch);

NQ_Transaction NQ_Net_Transaction_begin(NQ_Host host);
  void NQ_Batch_Transaction_begin(NQ_Host host, NQ_Net_Batch *batch);
  NQ_Transaction NQ_Batch_Transaction_begin_finish(NQ_Net_Batch *batch);
int NQ_Net_Transaction_test(NQ_Transaction transaction);
int NQ_Net_Transaction_abort(NQ_Transaction transaction);
  int NQ_Batch_Transaction_abort(NQ_Transaction transaction, NQ_Net_Batch *batch);
int NQ_Net_Transaction_commit(NQ_Transaction transaction);
  int NQ_Batch_Transaction_commit(NQ_Transaction transaction, NQ_Net_Batch *batch);
int NQ_Net_Transaction_remote(NQ_Transaction transaction, NQ_Host host, unsigned int op);
int NQ_Local_Transaction_set_remote_state(NQ_Transaction transaction, int state);
int NQ_Net_Transaction_set_remote_state(NQ_Transaction transaction, NQ_Host host, int state);
int NQ_Request_Transaction_set_remote_state(struct NQ_Socket *sock, struct NQ_Request_Data *req);

int NQ_Net_Transaction_invalidate_shadow_state(NQ_Transaction transaction);

NQ_Trigger NQ_Net_Trigger_create(NQ_Transaction transaction, NQ_Principal *actor, NQ_Trigger_Description *description, NQ_Trigger_Callback cb, void *userdata);

  void NQ_Batch_Trigger_create(NQ_Transaction transaction, NQ_Principal *actor, NQ_Trigger_Description *description, NQ_Trigger_Callback cb, void *userdata, NQ_Net_Batch *batch);
  NQ_Trigger NQ_Batch_Trigger_create_finish(NQ_Transaction transaction, NQ_Net_Batch *batch);
int NQ_Net_Trigger_delete(NQ_Transaction transaction, NQ_Principal *actor, NQ_Trigger trigger_id);

int NQ_Net_Enumerate_Tuples(NQ_Host host, NQ_Tuple **out, int *out_count);
int NQ_Net_Enumerate_Attributes(NQ_Host host, NQ_Tuple tuple, NQ_Attribute_Name ***out, int *out_count);
  int NQ_Net_Enumerate_Triggers(NQ_Host host, NQ_Trigger_Desc_and_Dest **out, int *out_count);

typedef void (*WaitGroup_RequestHandler)(NQ_Transaction_Real *transaction, void *ctx, int op, int arg, int rv);
typedef void (*WaitGroup_GroupHandler)(NQ_Transaction_Real *transaction, void *ctx);

void NQ_Transaction_Commit_Step_Ctx_handle_one(NQ_Transaction_Real *transaction, void *ctx, int op, int arg, int rv);
void NQ_Transaction_Commit_Step_Ctx_respond_group(NQ_Transaction_Real *transaction, void *ctx);

void NQ_Net_GC_touch_uuid(NQ_UUID uuid);
void NQ_Net_GC_touch_attribute_value(NQ_Tuple tuple, NQ_Attribute_Name *name);

void NQ_Bundle_begin(void);
int NQ_Bundle_check(struct NQ_Peer *peer);
void NQ_Bundle_end(void);
void NQ_Bundle_implicit_done(struct NQ_Peer *peer);

void NQ_Request_Bundle_begin(struct NQ_Socket *sock, struct NQ_Request_Data *req);
void NQ_Request_Bundle_end(struct NQ_Socket *sock, struct NQ_Request_Data *req);
void NQ_Request_Bundle_need_result(struct NQ_Socket *sock, struct NQ_Request_Data *req);

// Generic request responder, for NQ_Local_Transaction_test()
void NQ_Request_handle_one(NQ_Transaction_Real *transaction, void *ctx, int op, int arg, int rv);
void NQ_Request_respond_group(NQ_Transaction_Real *transaction, void *ctx);

struct WaitGroup *WaitGroup_create(NQ_Transaction_Real *t);
struct WaitGroupServer *WaitGroupServer_create(NQ_Transaction_Real *t);

void WaitGroup_open(NQ_Transaction_Real *t,
		    WaitGroup_GroupHandler handler, void *ctx);
void WaitGroup_close(NQ_Transaction_Real *t);
void WaitGroup_issue(NQ_Transaction_Real *t, 
		     const NQ_Host host,
		     WaitGroup_RequestHandler handler, void *ctx,
		     unsigned int op, int arg);
void WaitGroup_respond(const NQ_Host *host, NQ_Transaction t, const struct NQ_Request_Data *req, int request_id, int rv);

  // replaced by WaitGroupServer_trigger_fire: 
  //    int NQ_Net_Trigger_fire(NQ_Transaction transaction, NQ_Trigger trigger_id);
  //void WaitGroup_trigger_fire(NQ_Transaction_Real *t, NQ_Trigger trigger_id, 
  //NQ_Trigger_Upcall_Type type, 
  //NQ_Transaction_Commit_Step_Ctx *ctx, unsigned int arg);

void NQ_Request_Transaction_waitgroup_request(struct NQ_Socket *sock, struct NQ_Request_Data *req);
void NQ_Request_Transaction_waitgroup_resp(struct NQ_Socket *sock, struct NQ_Request_Data *req);

#ifdef __cplusplus
}
#endif

// #define PRINT_NET_SIZE(X, ...) printf("%lf: " X, float_time(), __VA_ARGS__)

#ifndef PRINT_NET_SIZE
#define PRINT_NET_SIZE(X, ...)
#else
#include <sys/time.h>
static inline double float_time(void) {
  struct timeval tv;
  gettimeofday(&tv, NULL);
  double t = tv.tv_sec;
  t += tv.tv_usec * 1e-6;
  return t;
}
#endif

#define DEBUG_POLL_EINTR (0)

#endif
