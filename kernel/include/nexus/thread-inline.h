#ifndef _THREAD_INLINE_H_
#define _THREAD_INLINE_H_
// Inline functions
#include <nexus/thread-struct.h>
#include <nexus/ipc_private.h>

static inline BasicThread *
nexusthread_self(void) 
{
  return curt;
}

static inline int 
nexusthread_self_id(void) 
{
  assert(curt);
  return curt->id;
}

/// XXX remove after having idlgen stop generate calls
static inline void 
nexusthread_set_syscall_num(BasicThread *t, int callno)
{
}

/** return the ipd of the current process.
 
    not to be confused with .._get_ipd, which returns its
    persona (a hack, see .._impersonate_push) */
static inline IPD *
nexusthread_get_base_ipd(BasicThread *t) 
{
  return t->ipd;
}

/** leftover from use of ipd stack; is now equivalent to .._get_ipd */
static inline IPD *
nexusthread_current_base_ipd(void) 
{
  if (curt)
    return nexusthread_get_base_ipd(curt);
  else
    return NULL;
}

// nexusthread_ipc_top() does not get a reference to the
// IPC_ClientContext, since a lot of code assumes that
// nexusthread_ipc_top() has no side effects
static inline struct IPC_ClientContext *nexusthread_ipc_top(BasicThread *thread) {
  if(thread->ipc.client_top == NULL) {
    printk_red("ipc top is null, depth supposedly %d\n", thread->ipc.stack_depth);
  }
  assert(thread->ipc.client_top != NULL);
  return thread->ipc.client_top;
}

static inline int nexusthread_id(BasicThread *t) {
  assert(t);
  return t->id;
}

static inline void IPC_ClientContext_get(struct IPC_ClientContext *cctx) {
  atomic_increment(&cctx->sync_refcnt, 1);
}

static inline void IPC_ClientContext_put(struct IPC_ClientContext *cctx) {
  if(atomic_decrement(&cctx->sync_refcnt, 1)) {
    void IPC_ClientContext_dealloc(struct IPC_ClientContext *cctx);
    IPC_ClientContext_dealloc(cctx);
  }
}

static inline void nexusthread_ipc_push_real(BasicThread *thread, struct IPC_ClientContext *client_ctx, const char *file, int line) {
  client_ctx->next = thread->ipc.client_top;
  thread->ipc.client_top = client_ctx;
  thread->ipc.stack_depth++;
  IPC_ClientContext_get(client_ctx);
}

static inline struct IPC_ClientContext *nexusthread_ipc_pop_real(BasicThread *thread, const char *file, int line) {
  assert(thread->ipc.client_top != NULL);
  struct IPC_ClientContext *rv = thread->ipc.client_top;
  thread->ipc.client_top = rv->next;
  thread->ipc.stack_depth--;

  return rv;
}

static inline struct IPC_ClientContext *nexusthread_ipc_next(BasicThread *thread) 
{
  assert(thread->ipc.client_top->next != NULL);
  return thread->ipc.client_top->next;
}

static inline struct IPC_ServerContext *nexusthread_ipc_server(BasicThread *thread) 
{
  return &thread->ipc.server;
}

static inline void nexusthread_set_sema(BasicThread *t, Sema *sem) 
{
  t->blocksema = sem;
}

static inline void nexusthread_check_and_clear_sema(BasicThread *t, Sema *sem) 
{
  assert(sem == t->blocksema);
  t->blocksema = NULL;
}

void IPC_CommonClientContext_clean(IPC_CommonClientContext *common_ctx);
void IPC_CommonClientContext_dealloc(IPC_CommonClientContext *common_ctx);

void TransferDesc_get_phys_pages(struct TransferDesc *desc);
#endif // _THREAD_INLINE_H_

