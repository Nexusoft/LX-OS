#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <pthread.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <netdb.h>
#include <semaphore.h>
#include <errno.h>

#include <nq/gcmalloc.h>
#include <nq/netquery.h>
#include <nq/net.h>
#include <nq/gcmalloc.h>
#include <nq/socket.h>
#include <nq/uuid.h>
#include <nq/util.hh>
#include <nq/hashtable.h>
#include <nq/garbage.h>
#include <nq/workqueue.h>

#include <nq/pickle.h>

//#define NET_DEBUG

#define REQUEST_LOCAL (0xdeadbeef)
//#define DEBUG_WAIT(X) X
#define DEBUG_WAIT(X) 

#ifdef NET_DEBUG
#define PING() printf("===========> %s:%d %s()\n", __FILE__, __LINE__, __FUNCTION__)
#else
#define PING() 
#endif

#define SHOW_ALL_RPC_TRAFFIC

void *debug_last_released_lock = NULL;

//connection_pool uses NQ_Socketpool locking
NQ_Socketpool *NQ_connection_pool = NULL; 

//peers is only accessed in the NetQuery socket polling thread
Queue *NQ_peers = NULL; 

//requests_pending is locked by net.c
NQ_Workqueue *requests_pending;

//nq_localhost is set once and once only.
// xxx NQ_NET_DEFAULT_PORT should be in network order
static NQ_Host nq_localhost = {0, NQ_NET_DEFAULT_PORT};
static int nq_force_net = 0;

typedef struct NQ_Peer {
  struct NQ_Peer *next, *prev;
  NQ_Socket *sock;
  NQ_Host id;
  Queue requests;
  unsigned int next_request;

  NQ_Principal *principal;
  int in_bundle;
} NQ_Peer;

NQ_Host NQ_Net_get_peer(NQ_Socket *sock){
  NQ_Peer *peer = NQ_Socket_userdata(sock);
  return peer->id;
}

int NQ_Peer_find(NQ_Peer *curr, NQ_Host *peer){
//  NQ_Host_print(curr->id);printf(" == ");NQ_Host_print(*peer);printf("\n");
  return NQ_Host_eq(curr->id, *peer);
}

int NQ_Peer_issue_async(NQ_Peer *peer, NQ_RingBuffer *pickle, unsigned int type, int err) {
  return NQ_Request_issue_async(peer->id, pickle, type, err);
}

static NQ_Workqueue *nq_user_call_queue;
static sem_t user_call_blocker;
static pthread_t nq_user_call_thread;
static pthread_t nq_server_thread;
static int nq_server_started = 0;

void *NQ_server_thread(void *dummy){
  while(1){
    NQ_Net_poll(10000);
  }
  return NULL;
}

void NQ_Net_start_server(){
  if(nq_server_started) return;
  pthread_create(&nq_server_thread, NULL, NQ_server_thread, NULL);
  nq_server_started = 1;
}

typedef struct NQ_User_Async_Call_Entry {
  struct NQ_User_Async_Call_Entry *next, *prev;
  NQ_User_Async_Call call;
  void *userdata;
} NQ_User_Async_Call_Entry;

void NQ_Net_set_server(unsigned int addr, unsigned short port){
  if(addr){
    nq_localhost.addr = addr;
  }
  if(port){
    nq_localhost.port = port;
  }
  nq_force_net = 1;
}

void NQ_Net_set_localserver(void){
  printf("Set local server is deprecated\n");
  assert(0);
  NQ_Net_set_server(0, 0);
}

void NQ_user_call_async(NQ_User_Async_Call call, void *userdata){
  NQ_User_Async_Call_Entry *entry = malloc(sizeof(NQ_User_Async_Call_Entry));
  bzero(entry, sizeof(NQ_User_Async_Call_Entry));
  
  entry->call = call;
  entry->userdata = userdata;
  
  NQ_Workqueue_insert(nq_user_call_queue, entry);
  int rv;
  rv = sem_post(&user_call_blocker);
  assert(rv == 0);
}

void *NQ_user_thread(void *dummy){
  NQ_User_Async_Call_Entry *entry;
  
  while(1){
    while(sem_wait(&user_call_blocker) != 0){
      if((errno != EINTR)&&(errno == EAGAIN)){
        perror("Semaphore error");
        assert(0);
      }
    }
    entry = NQ_Workqueue_remove(nq_user_call_queue);
    assert(entry);
    entry->call(entry->userdata);
    free(entry);
  }
  return NULL;
}

//unsigned int NQ_Net_get_localaddr_pcap(){
//  char error[PCAP_ERRBUF_SIZE];
//  pcap_if_t *firstdev, *currdev;
//  pcap_addr_t *addrinfo;
//  
//  if(pcap_findalldevs(&firstdev, error) < 0){
//    printf("Can't get device information: %s\n", error);
//    exit(1);
//  }
//  printf("Looking for local address\n");
//  for(currdev = firstdev; currdev != NULL; currdev = currdev->next){
//    if(currdev->flags == PCAP_IF_LOOPBACK){ continue; }
//    printf("Trying: %s: ", currdev->description);
//    for(addrinfo = currdev->addresses; addrinfo != NULL; addrinfo = addrinfo->next){
//      if((addrinfo->addr->s_addr != inet_addr("127.0.0.1")) && 
//         (addrinfo->addr->s_addr != inet_addr("255.255.255.255"))){
//        unsigned int ret = addrinfo->addr->s_addr;
//        pcap_freealldevs(firstdev);
//        return ret;
//      }
//    }
//  }
//  pcap_freealldevs(firstdev);
//  printf("Can't find a good IP address\n");
//  exit(1);
//  return 0;
//}
unsigned int NQ_Net_get_localaddr_dns(){
  char hostname[100];
  int retaddr = 0;
  if(!gethostname(hostname, sizeof(hostname))){
    struct hostent *hostent = gethostbyname(hostname);
    if(hostent){
      struct in_addr *addr = (struct in_addr *)hostent->h_addr;
      retaddr = addr->s_addr;
    }
  } 
  if(!retaddr) {
    printf("Can't get localhost (addr is %s)!", hostname);
    exit(1);
  }
  return retaddr;
}

void NQ_Net_init(unsigned int my_ip, unsigned short port){
  NQ_connection_pool = NQ_Socketpool_create(NQ_Net_accept, NQ_Net_data, NQ_Net_error);
  
  if(port != 0){
    printf("Listening on port %d\n", port);
    NQ_Socket *sock = NQ_Socket_listen(NQ_connection_pool, 
				       port != NQ_PORT_ANY ? port : 0,
				       NULL);
    if(sock == NULL) {
      fprintf(stderr, "Could not start listening on %d!\n", (int) port);
    }
    nq_localhost.port = NQ_Socket_peerport(sock);
    if(port != NQ_PORT_ANY) {
      assert(nq_localhost.port == port);
    }

    nq_force_net = 0;
  }
  
  NQ_peers = queue_new();
  
  requests_pending = NQ_Workqueue_create(100000);
  nq_user_call_queue = NQ_Workqueue_create(100000);
  assert(sem_init(&user_call_blocker, 0, 0) == 0);
  
  pthread_create(&nq_user_call_thread, NULL, NQ_user_thread, NULL);
  NQ_Net_start_server();
  nq_localhost.addr = my_ip;
  
  if(nq_localhost.addr == 0){
    nq_localhost.addr = NQ_Net_get_localaddr_dns();
    if(!nq_localhost.addr){
      printf("Can't get loalhost\n");
    }
  }
  printf("\nLocal Host: "); print_ip(nq_localhost.addr); printf(":%d\n", nq_localhost.port);
}

void NQ_Net_start_daemon(int port){
  assert(NQ_connection_pool != NULL);
}

struct NQ_Request_Pending {
  struct NQ_Request_Pending *next, *prev;
  sem_t blocker;
  NQ_Host target;
  NQ_Request_Header head;
  unsigned char *request;
  unsigned char *response;
  NQ_Request_Pending_Status status;
  int async;
  int blocking;
};

typedef struct NQ_Net_Batch_Request {
  struct NQ_Net_Batch_Request *next, *prev;
  NQ_Request_Pending request;
  void *state; // state is for Batch

  NQ_Batch_Handler handler;
  void *handler_state; // handler_state is for the handler
} NQ_Net_Batch_Request;

void NQ_Batch_Request_invoke_handler(NQ_Net_Batch_Request *req) {
  if(req->handler) {
    req->handler(req->handler_state, req->request.status);
    req->handler = NULL;
    req->handler_state = NULL;
  }
}

struct NQ_Net_Batch {
  Queue requests;
  pthread_mutex_t reader_lock; //synchronizes _issue and _finish requests.  _block and _destroy are NOT synched
                               //note that in the general case, both of these will be running in the same thread.
}; //already typedeffed in net.h

int NQ_Request_build(NQ_Host host, NQ_RingBuffer *pickle, unsigned int type, NQ_Request_Pending *req){
  bzero(req, sizeof(NQ_Request_Pending));
  req->target = host;  
  req->head.length = NQ_RingBuffer_data(pickle) + sizeof(NQ_Request_Header);
  req->head.type = type;
  req->head.error = 0;
  req->status = NQ_STATUS_UNTOUCHED;
  req->blocking = 0;
  if(NQ_RingBuffer_data(pickle) > 0){
    req->request = malloc(NQ_RingBuffer_data(pickle));
    NQ_RingBuffer_read(pickle, req->request, NQ_RingBuffer_data(pickle));
  }
  // printf("build: req = %p, target = %x\n", req, req->target);

  PING();
  return 0;
}

NQ_Net_Batch *NQ_Net_Batch_create(){
  NQ_Net_Batch *ret = malloc(sizeof(NQ_Net_Batch));
  bzero(ret, sizeof(NQ_Net_Batch));
  queue_initialize(&ret->requests);
  pthread_mutex_init(&ret->reader_lock, NULL);
  return ret;
}
int NQ_Net_Batch_pending(NQ_Net_Batch *batch){
  NQ_Net_Batch_Request *curr;
  int cnt = 0;
  for(curr = queue_gethead(&batch->requests); curr != NULL; curr = queue_getnext(curr)){
    if(curr->request.status != NQ_STATUS_FINISHED){
      cnt++;
    }
  }
  return cnt;
}
int g_req_wait_count;
int g_batch_wait0_count;
int g_batch_wait1_count;
int g_req_post_count;
int g_req_local_post_count;

void NQ_print_sem_stats(void) {
  printf("req_wait = %d, batch_wait0 = %d, batch_wait1 = %d, post = %d, local_post = %d\n",
         g_req_wait_count, g_batch_wait0_count, g_batch_wait1_count,
         g_req_post_count, g_req_local_post_count);
}

int NQ_Net_Batch_block(NQ_Net_Batch *batch){
  NQ_Net_Batch_Request *curr;
  int ret = 0;
  for(curr = queue_gethead(&batch->requests); curr != NULL; curr = (curr == NULL)?NULL:queue_getnext(curr)){
    while(curr->request.status != NQ_STATUS_FINISHED){
      if(curr->request.status == NQ_STATUS_ERROR){
        ret = -1;
        curr = NULL;
        break;
      }
      g_batch_wait0_count++;
      while(sem_wait(&curr->request.blocker) != 0){
        if((errno != EINTR)&&(errno == EAGAIN)){
          perror("Semaphore error");
          assert(0);
        }
      }
    }
    NQ_Batch_Request_invoke_handler(curr);
  }
  return ret;
}
int NQ_Net_Batch_willblocknext(NQ_Net_Batch *batch){
  NQ_Net_Batch_Request *req = queue_gethead(&batch->requests);
  return !((req->request.status == NQ_STATUS_FINISHED)||(req->request.status == NQ_STATUS_ERROR));
}
int NQ_Net_Batch_finish_stateful(NQ_Net_Batch *batch, unsigned char **retdata, unsigned int *retlen, unsigned int *type, void **state){
  NQ_Net_Batch_Request *req;
  void *tmp;
  int ret = 0;
  
  pthread_mutex_lock(&batch->reader_lock);
  if(!queue_dequeue(&batch->requests, &tmp) == 0){
    pthread_mutex_unlock(&batch->reader_lock);
    return -ERR_NO_REQUESTS_LEFT;
  }
  pthread_mutex_unlock(&batch->reader_lock);
  req = tmp;
  
  if(retdata){
    assert(retlen);
    assert(type);
    *retdata = NULL;
    *retlen = 0;
    *type = 0;
  }
  if(state){
    *state = NULL;
  }
  while(req->request.status != NQ_STATUS_FINISHED){
    if(req->request.status == NQ_STATUS_ERROR){
      ret = -1;
      break;
    }
    g_batch_wait1_count++;
    while(sem_wait(&req->request.blocker) != 0){
      if((errno != EINTR)&&(errno == EAGAIN)){
        perror("Semaphore error");
        assert(0);
      }
    }
  }
  NQ_Batch_Request_invoke_handler(req);
  
  sem_destroy(&req->request.blocker);
  if(req->request.request != NULL){
    free(req->request.request);
  }
  if((req->request.status == NQ_STATUS_FINISHED)){
    ret = req->request.head.error;
    if(retdata){
      *retdata = req->request.response;
      *retlen = req->request.head.length - sizeof(NQ_Request_Header);
      *type = req->request.head.type;
    }
    if(state){
      *state = req->state;
    }
  } else {
    if(req->request.response){
      free(req->request.response);
    }
  }
  
  free(req);
  
  return ret;
}
int NQ_Net_Batch_finish(NQ_Net_Batch *batch, unsigned char **retdata, unsigned int *retlen, unsigned int *type){
  return NQ_Net_Batch_finish_stateful(batch, retdata, retlen, type, NULL);
}
void NQ_Net_Batch_destroy(NQ_Net_Batch *batch){
  NQ_Net_Batch_Request *curr;
  void *tmp;
//  printf("Destructo mode, go!\n");
  while(queue_dequeue(&batch->requests, &tmp) == 0){
    curr = tmp;
    sem_destroy(&curr->request.blocker); //NQ_Net_poll will take us off the request list.
    if(curr->request.response != NULL){
      free(curr->request.response);
    }
    if(curr->request.request != NULL){
      free(curr->request.request);
    }
    // When a handler is fired, these fields are cleared. This
    // assertion detects when the handler was not fired
    assert(curr->handler == NULL && curr->handler_state == NULL);
    free(curr); 
  }
  pthread_mutex_destroy(&batch->reader_lock);
  free(batch);
}

int NQ_Request_issue_batch_stateful(NQ_Host host, NQ_RingBuffer *pickle, unsigned int type, int err, NQ_Net_Batch *batch, void *state, NQ_Batch_Handler handler, void *handler_state){
  NQ_Net_Batch_Request *req = malloc(sizeof(NQ_Net_Batch_Request));
  req->prev = req->next = NULL;
  NQ_Request_build(host, pickle, type, &req->request);
  req->request.async = 0;
  req->request.head.error = err;
  req->state = state;
  req->handler = handler;
  req->handler_state = handler_state;
  if(sem_init(&req->request.blocker, 0, 0) < 0){
    perror("ERROR");
    assert(0);
  }

  req->request.status = NQ_STATUS_ISSUED;
//  printf("Issuing: %p\n", &req->request);
  NQ_Workqueue_insert(requests_pending, &req->request);
  pthread_mutex_lock(&batch->reader_lock);
  queue_append(&batch->requests, req);
  pthread_mutex_unlock(&batch->reader_lock);
  NQ_Socketpool_unblock(NQ_connection_pool);
  return 0;
}

int NQ_Request_issue_batch(NQ_Host host, NQ_RingBuffer *pickle, unsigned int type, int err, NQ_Net_Batch *batch, NQ_Batch_Handler handler, void *handler_state){
  return NQ_Request_issue_batch_stateful(host, pickle, type, err, batch, NULL, handler, handler_state);
}

int NQ_Request_issue_async(NQ_Host host, NQ_RingBuffer *pickle, unsigned int type, int err){
  NQ_Request_Pending *req = malloc(sizeof(NQ_Request_Pending));
  NQ_Request_build(host, pickle, type, req);
  req->async = 1;
  req->head.error = err;
  req->status = NQ_STATUS_ISSUED;
  NQ_Workqueue_insert(requests_pending, req);

  NQ_Socketpool_unblock(NQ_connection_pool);
  return 0;
}

//ONLY CALL THIS FROM THE SERVER THREAD AS THE FIRST THING SENT OVER A SOCKET
int NQ_Net_hello(NQ_Socket *sock){
  unsigned char buffer[sizeof(NQ_Request_Header) + sizeof(NQ_Host)];
  NQ_Request_Header *head = (NQ_Request_Header *)buffer;
  NQ_Host *localhost = (NQ_Host *)(buffer+sizeof(NQ_Request_Header));
  
  head->length = sizeof(NQ_Request_Header) + sizeof(NQ_Host);
  head->type = NQ_REQUEST_INTERNAL_HELLO;
  head->error = 0;
  head->id = 0;
  
  *localhost = NQ_Net_get_localhost();
  
  NQ_Socket_write(sock, buffer, head->length);
  return 0;
}

int NQ_Request_issue(NQ_Host host, NQ_RingBuffer *pickle, unsigned int type, unsigned char **retdata, unsigned int *retlen){
  NQ_Request_Pending *req = malloc(sizeof(NQ_Request_Pending));
  int ret;
  
  NQ_Request_build(host, pickle, type, req);
  req->async = 0;
 
//  printf("----> preparing request for : %d=%d, %d=%d\n", req->target.addr, host.addr, req->target.port, host.port);
  
  if(sem_init(&req->blocker, 0, 0) < 0){
    perror("ERROR");
    assert(0);
  }
  
  req->status = NQ_STATUS_ISSUED;
  req->blocking = 1;
  NQ_Workqueue_insert(requests_pending, req);
  NQ_Socketpool_unblock(NQ_connection_pool);

  PING();
  DEBUG_WAIT(printf("W(%p)", &req->blocker));
  while(req->status != NQ_STATUS_FINISHED){
    // printf("waiting on %p\n", &req->blocker);
    g_req_wait_count++;
    while(sem_wait(&req->blocker) != 0){
      if((errno != EINTR)&&(errno == EAGAIN)){
        perror("Semaphore error");
        assert(0);
      }
    }

    // printf("REQ Wait done\n");
    // breakpoint();
    if(req->status == NQ_STATUS_ERROR){
      printf("Error, can't connect to host: ");NQ_Host_print(host);printf("\n");
      break;
    }
//    if(req->status == NQ_STATUS_ISSUED){
//      printf("ERROR! pthread_cond_wait returned... unexpectedly.  Resetting and trying again.\n");
//      pthread_cond_destroy(&req->blocker);
//      if(pthread_cond_init(&req->blocker, NULL) < 0){
//        perror("ERROR");
//        assert(0);
//      }
//    }
  }
  // printf("done waiting for %p\n", &req->blocker);

  sem_destroy(&req->blocker); //NQ_Net_poll will take us off the request list.
  if(!retdata){
    if(req->response != NULL){
      free(req->response);
    }
  } else {
    *retdata = req->response;
    *retlen = req->head.length - sizeof(NQ_Request_Header);
    assert((*retlen == 0)||req->response);
  }
  
  ret = req->head.error;
  if(req != NULL){
    if(req->request != NULL) {
      free(req->request);
    }
    free(req);
  }
  return ret;
}

//after calling NQ_Request_finish, you MUST call sem_post(&pending->blocker);
int NQ_Request_finish(NQ_Request_Pending *pending, NQ_Request_Data *req){
  PING();
  memcpy(&pending->head, &req->header, sizeof(NQ_Request_Header));
  PING();
  if(req->header.length > sizeof(NQ_Request_Header)){
  PING();
    pending->response = malloc(req->header.length - sizeof(NQ_Request_Header));
    memcpy(pending->response, req->data, req->header.length - sizeof(NQ_Request_Header));
  }
  PING();
  assert((pending->head.length == sizeof(NQ_Request_Header)) || (pending->response));
  pending->status = NQ_STATUS_FINISHED;
  debug_last_released_lock = &pending->blocker;

  return 0;
}

void NQ_Request_respond(NQ_Socket *sock, NQ_RingBuffer *buff, NQ_Request_Data *req, int error){
  NQ_Request_Data resp;
  int outlen;

  switch(req->header.type) {
  case NQ_REQUEST_BUNDLE_BEGIN:
    NQ_Socket_start_bundle(sock);
    return;
  case NQ_REQUEST_BUNDLE_END:
    NQ_Socket_finish_bundle(sock);
    return;
  default:
    ;
  }

  if(buff != NULL){
    outlen = NQ_RingBuffer_data(buff);
  } else {
    outlen = 0;
  }
  
  resp.header.length = outlen + sizeof(NQ_Request_Header);
  resp.header.type = req->header.type | NQ_REQUEST_RESPONSE;
  resp.header.id = req->header.id;
  resp.header.error = error;
  // printf("NQ_Request_respond(%x:%d, %d bytes, error: %d)\n", resp.header.type, resp.header.id, resp.header.length, resp.header.error);
  if(sock){
    if(!NQ_Socket_in_bundle(sock)) {
      NQ_Socket_write_start(sock);
    }
    NQ_Socket_write_partial(sock, (unsigned char *)&resp.header, sizeof(NQ_Request_Header));
  }
  
  if(outlen > 0){
    resp.data = malloc(outlen);
    NQ_RingBuffer_read(buff, resp.data, outlen);
  } else {
    resp.data = NULL;
  }
  if(sock){
    if(outlen > 0){
      NQ_Socket_write_partial(sock, resp.data, outlen);
    }
    if(!NQ_Socket_in_bundle(sock)) {
      NQ_Socket_write_flush(sock);
    }
  } else {
    NQ_Request_finish(req->localrequest, &resp);
    DEBUG_WAIT(printf("R(A=%p)", &req->localrequest->blocker));
    sem_post(&req->localrequest->blocker);
    g_req_local_post_count++;
  }
  free(resp.data);
}

NQ_Peer *NQ_Peer_make(NQ_Socket *sock){
  NQ_Peer *peer = malloc(sizeof(NQ_Peer));
  bzero(peer, sizeof(NQ_Peer));
  peer->sock = sock;
  queue_initialize(&peer->requests);
  queue_append(NQ_peers, peer);
  peer->principal = NULL;
//  NQ_Net_hello(sock, nq_localhost);
  return peer;
}

typedef struct NQ_Request_Deferred {
  struct NQ_Request_Deferred *next, *prev;
  NQ_Request_Data req;
  NQ_Socket *sock;
} NQ_Request_Deferred;

NQ_Request_Deferred *NQ_Request_defer(NQ_Socket *sock, NQ_Request_Data *req){
  //Defferred requests should only be necessary to look up data from a remote host.
  //If the request is local... why not just have the NQ_Net_foo() push the data
  //over the channel, or into a visible location?
  assert(!req->localrequest);
  int datalen = (int)req->header.length - (int)sizeof(NQ_Request_Header);
  unsigned char *data = req->data;
  NQ_Request_Deferred *def_req = malloc(sizeof(NQ_Request_Deferred));
  bzero(def_req, sizeof(NQ_Request_Deferred));
  memcpy(&(def_req->req.header), &req->header, sizeof(NQ_Request_Header));
  def_req->req.data = malloc(datalen);
  memcpy(def_req->req.data, data, datalen);
  def_req->sock = sock;
  return def_req;
}

int NQ_Request_demux(NQ_Socket *sock, NQ_Request_Data *req);
void NQ_Request_undefer(NQ_Request_Deferred *req){
  NQ_Request_demux(req->sock, &req->req);
  free(req->req.data);
  free(req);
}

#include "pickle.c"

NQ_Peer *NQ_Peer_get(NQ_Host host){
  NQ_Peer *peer = queue_find(NQ_peers, (PFany)&NQ_Peer_find, &host);
//  printf("looking for peer\n");
  if(!peer){
    //printf("didn't find peer, opening connection:"); print_ip(host.addr); printf(":%d\n", host.port);
    NQ_Socket *sock = NQ_Socket_connect(NQ_connection_pool, host.addr, host.port, NULL);
    if(!sock) { return NULL; }
//    printf("success!\n");
    peer = NQ_Peer_make(sock);
    peer->id = host;
    NQ_Socket_set_userdata(sock, peer);
    NQ_Net_hello(sock);
  }
  return peer;  
}

int NQ_Request_Pending_find(NQ_Request_Pending *curr, unsigned int *id){
  return curr->head.id == *id;
} 


static int attribute_op_count = 0, last_attribute_op_count = 0;
static int trigger_op_count = 0, last_trigger_op_count = 0;
static int r_register_op_count = 0;
static int transaction_start_op_count = 0;

NQ_Socket *last_req_sock;
int last_request_id;

int NQ_Request_demux(NQ_Socket *sock, NQ_Request_Data *req){
  PRINT_NET_SIZE("Client got id=%d type=%x len=%d\n", 
     req->header.id, req->header.type, req->header.length);

  if(req->header.type & NQ_REQUEST_MASK_DIRECTION){
    NQ_stat.rx_remote_rpc_count++;
    NQ_Request_Pending *pending;
    NQ_Peer *peer;
    
    assert(sock);
    
    peer = NQ_Socket_userdata(sock);
    
    pending = queue_find(&peer->requests, (PFany)&NQ_Request_Pending_find, &req->header.id);
    if(pending){
      NQ_Request_finish(pending, req);
      queue_delete(&peer->requests, pending);

      DEBUG_WAIT(printf("R(B=%p)", &pending->blocker));

      if(0) {
	static void *last_blocker = NULL;
	static int match_count = 0;
	if(last_blocker == &pending->blocker) {
	  printf("last blocker match, %p\n", last_blocker);
	  match_count++;
	  if(match_count > 3) {
	    printf("<<<< blocking >>>>\n");
	    while(1);
	  }
	} else {
	  match_count = 0;
	}
	last_blocker = &pending->blocker;
      }

      sem_post(&pending->blocker);
      g_req_post_count++;
    } else {
      assert(!"Got a response to a message that hasn't been sent");
    }
  } else {
    //a request (these functions are defined in pickle.c)
    if(show_rpc_traffic) {
      printf("Server got id=%d type=%x len=%d from %08x:%d\n", req->header.id, req->header.type, req->header.length, sock ? ntohl(NQ_Socket_peer(sock)) : -1, sock ? NQ_Socket_peerport(sock) : -1);
    }
    last_req_sock = sock;
    last_request_id = req->header.id;

    NQ_stat.rx_rpc_count++;
    switch(req->header.type){
      case NQ_REQUEST_INTERNAL_HELLO:
        NQ_Request_Internal_hello(sock, req);
        break;
      case NQ_REQUEST_ATTRIBUTE_OP:
        attribute_op_count ++;
        NQ_stat.server.attr_op ++;
        NQ_Request_Attribute_operate(sock, req);
        break;
      case NQ_REQUEST_ENUMERATE_ATTRIBUTES:
        NQ_Request_Enumerate_Attributes(sock, req);
        break;
      case NQ_REQUEST_TUPLE_CREATE:
        NQ_Request_Tuple_create(sock, req);
        break;
      case NQ_REQUEST_TUPLE_DELETE:
        NQ_Request_Tuple_delete(sock, req);
        break;
      case NQ_REQUEST_TUPLE_ADD_ATT:
        NQ_Request_Tuple_add_attribute(sock, req);
        break;
      case NQ_REQUEST_TUPLE_DEL_ATT:
        NQ_Request_Tuple_remove_attribute(sock, req);
        break;
      case NQ_REQUEST_ENUMERATE_TUPLES:
	NQ_Request_Enumerate_Tuples(sock, req);
        break;
      case NQ_REQUEST_TRANSACTION_START:
        transaction_start_op_count ++;
          NQ_Request_Transaction_begin(sock, req);
        break;
      case NQ_REQUEST_TRANSACTION_TEST:
        // fprintf(stderr, "TEST: id=%d type=%x len=%d from %08x:%d\n", req->header.id, req->header.type, req->header.length, sock ? ntohl(NQ_Socket_peer(sock)) : -1, sock ? NQ_Socket_peerport(sock) : -1);
        NQ_Request_Transaction_test(sock, req);
        break;
      case NQ_REQUEST_TRANSACTION_COMMIT:
        // printf("commit()\n");
          NQ_Request_Transaction_commit(sock, req);
        break;
      case NQ_REQUEST_TRANSACTION_ABORT:
          NQ_Request_Transaction_abort(sock, req);
        break;
      case NQ_REQUEST_TRANSACTION_R_REGISTER:
        r_register_op_count ++;
        NQ_Request_Transaction_remote(sock, req); //this'll parse the type out of the header
        break;
      case NQ_REQUEST_TRANSACTION_R_REGISTER_SET_STATE:
        NQ_Request_Transaction_set_remote_state(sock, req);
        break;

      case NQ_REQUEST_TRANSACTION_R_WAITGROUP:
	// printf("WG id=%d from %08x:%d\n", req->header.id, sock ? ntohl(NQ_Socket_peer(sock)) : -1, sock ? NQ_Socket_peerport(sock) : -1);
        NQ_Request_Transaction_waitgroup_request(sock, req);
        break;

      case NQ_REQUEST_TRANSACTION_R_WAITGROUP_RESP:
        // printf("WAITGROUP_resp\n");
        NQ_Request_Transaction_waitgroup_resp(sock, req);
        break;

      case NQ_REQUEST_TRIGGER_CREATE:
        trigger_op_count++;
        NQ_Request_Trigger_create(sock, req);
        break;

      case NQ_REQUEST_TRIGGER_DELETE:
        NQ_Request_Trigger_delete(sock, req);
        break;
      case NQ_REQUEST_TRIGGER_FIRE:
        printf("%d: Trigger Fire\n", getpid());
        NQ_Request_Trigger_fire(sock, req);
        break;
 
      case NQ_REQUEST_GCOLLECT_CREATE_GROUP:
        
        break;
      case NQ_REQUEST_GCOLLECT_TOUCH_UUID:
      case NQ_REQUEST_GCOLLECT_TOUCH_ATTRIBUTE:
        NQ_Request_GC_touch(sock, req);
        break;

    case NQ_REQUEST_BUNDLE_BEGIN:
      NQ_Request_Bundle_begin(sock, req);
      break;
    case NQ_REQUEST_BUNDLE_END:
      NQ_Request_Bundle_end(sock, req);
      break;

    case NQ_REQUEST_TRANSACTION_R_PREREGISTER:
      NQ_Request_Transaction_preregister(sock, req);
      break;
      
    case NQ_REQUEST_TRANSACTION_INVALIDATE_SHADOWSTATE:
      NQ_Request_Transaction_invalidate_shadow_state(sock, req);
      break;

    case NQ_REQUEST_ENUMERATE_TRIGGERS:
      NQ_Request_Enumerate_Triggers(sock, req);
      break;

    default:
      printf("Unknown request: %x\n", req->header.type);
    }
  }
  return 0;
}

int NQ_Request_handle(NQ_Socket *sock, int len){
  NQ_Request_Data req;

  int alloc_len = len-sizeof(NQ_Request_Header);
  if(alloc_len > 0) {
    req.data = malloc(alloc_len);
  } else {
    req.data = NULL;
  }

  req.localrequest = NULL;
  if(NQ_Socket_read(sock, (unsigned char *)&req.header, sizeof(NQ_Request_Header)) < 0){
    NQ_Net_error(sock);
    NQ_Socket_close(sock);
    return -1;
  }
//  printf("Accepting: %x, %d\n", req.header.type, req.header.length);
  if(NQ_Socket_read(sock, (unsigned char *)req.data, len-sizeof(NQ_Request_Header)) < 0){
    NQ_Net_error(sock);
    NQ_Socket_close(sock);
    return -1;
  }
  
  NQ_Request_demux(sock, &req);
  if(req.data != NULL) {
    free(req.data);
  }
  return 0;
}

static struct timeval last_stat_post_time = {0, 0};
static int should_print_stats;
static FILE *nq_stats_file = NULL;

void NQ_Net_set_stats(int stats){
  should_print_stats = stats;
}

void NQ_Net_print_stats(){
  if(!should_print_stats){
    return;
  }
  struct timeval stat_time;
  gettimeofday(&stat_time, NULL);
  
  if(stat_time.tv_sec != last_stat_post_time.tv_sec){
    if(nq_stats_file == NULL){
      nq_stats_file = stdout;//fopen("nq_stats.out", "w");
    }
    double delta = (double)(stat_time.tv_usec - last_stat_post_time.tv_usec) / 1000.0 + (double)(stat_time.tv_sec - last_stat_post_time.tv_sec) * 1000.0;
    last_stat_post_time = stat_time;
    fprintf(nq_stats_file, "%ld.%06ld: ", stat_time.tv_sec, stat_time.tv_usec);
    if(should_print_stats & NQ_PRINT_STATS_ATTR_OPS){
      fprintf(nq_stats_file, "(attr_ops: %d; %lf/s) ", attribute_op_count, ((double)(attribute_op_count - last_attribute_op_count)/delta) * 1000.0);
      last_attribute_op_count = attribute_op_count;
    }
    if(should_print_stats & NQ_PRINT_STATS_TRIGGER_OPS){
      fprintf(nq_stats_file, "(trigger_ops: %d; %lf/s) ", trigger_op_count, ((double)(trigger_op_count - last_trigger_op_count)/delta)*1000.0);
      last_trigger_op_count = trigger_op_count;
    }
    fprintf(nq_stats_file, "\n");
    fflush(nq_stats_file);
  }
}

static void send_bundle_cmd(NQ_Peer *peer, int type) {
  NQ_Request_Header header;
  header.length = sizeof(header);
  header.type = type;
  header.id = peer->next_request;
  peer->next_request++;
  header.error = 0;
  NQ_Socket_write_partial(peer->sock, (unsigned char *)&header, sizeof(NQ_Request_Header));
}

void NQ_Net_poll(int timeout){
  NQ_Request_Pending *req;
  NQ_Peer *peer;
  int async = 0;
#define PRINT_REQUEST()							\
  do {									\
    if(show_rpc_traffic) {						\
      printf("Send request id=%d type=%x len=%d %08x:%d\n", req->head.id, req->head.type, req->head.length, ntohl(req->target.addr), req->target.port); \
    }									\
  } while(0)

  //handle requests
  while((req = NQ_Workqueue_remove(requests_pending)) != NULL){
    async = req->async;
    NQ_stat.tx_rpc_count++;

    //printf("Getting peer\n");
    if(NQ_Net_is_local(req->target)){
      //printf("---- local request : %d, %d ----\n", req->target.addr, req->target.port);
      NQ_Request_Data localreq = {req->head, req->request, req};
      assert(req->status == NQ_STATUS_ISSUED);
      req->status = NQ_STATUS_LOCAL;
      DEBUG_WAIT(printf("L(%p @ %d)", &req->blocker, (int)pthread_self()));
      req->head.id = REQUEST_LOCAL;
      NQ_Request_demux(NULL, &localreq);
    } else {
      //printf("Pre get: "); print_ip(req->target.addr); printf(":%d\n", req->target.port);
      //printf("peer get: req = %p, target = %x\n", req, req->target);

      peer = NQ_Peer_get(req->target);
      //printf("finished get: %p\n", peer);
      NQ_stat.tx_remote_rpc_count++;
      if(!peer){
        req->head.error = -10;
        req->head.length = sizeof(NQ_Request_Header);
        req->response = NULL;
        req->status = NQ_STATUS_ERROR;
        //printf("releasing %p\n", &req->blocker);
        debug_last_released_lock = &req->blocker;
	PRINT_REQUEST();
	DEBUG_WAIT(printf("R(C=%p)", &req->blocker));
        sem_post(&req->blocker); //this will unblock the other thread.
      } else {
        // The socket lock is held during a bundle, so as to prevent the socket thread from running until the full bundle is enqueued
        if(!peer->in_bundle) {
          NQ_Socket_write_start(peer->sock);

          // XXX control of bundling should be popped up a level, to the request queue
          if(NQ_Bundle_check(peer)) {
            peer->in_bundle = 1;
            send_bundle_cmd(peer, NQ_REQUEST_BUNDLE_BEGIN);
            // printf("===> Bundle start <=== "); NQ_Host_print(peer->id); printf("\n");
          }
        }
        //the socket request list is only modified by the polling thread
        //consequently it doesn't need locking
        req->status = NQ_STATUS_REMOTE;
      
        req->head.id = peer->next_request;
        peer->next_request++;

	PRINT_REQUEST();
        NQ_Socket_write_partial(peer->sock, (unsigned char *)&req->head, sizeof(NQ_Request_Header));
        //printf("---- Actually sending request ----\n");
        //print_hex(req->request, req->head.length - sizeof(NQ_Request_Header));
        //printf("\n--------------------------\n");
        if(req->request){
          NQ_Socket_write_partial(peer->sock, (unsigned char *)req->request, req->head.length - sizeof(NQ_Request_Header));
        }
        if(!async){
          queue_append(&peer->requests, req);
        }

        if(peer->in_bundle) {
          if(req->head.type == NQ_REQUEST_BUNDLE_END || req->blocking) {
            if(req->blocking) {
              send_bundle_cmd(peer, NQ_REQUEST_BUNDLE_END);
              NQ_Bundle_implicit_done(peer);
              //printf("===> Bundle autoend <=== "); NQ_Host_print(peer->id); printf("\n");
            } else {
              //printf("===> Bundle end <=== "); NQ_Host_print(peer->id); printf("\n");
            }
            peer->in_bundle = 0;
            NQ_Socket_write_flush(peer->sock);
          }
        } else {
          NQ_Socket_write_flush(peer->sock);
        }
      }// else (!peer)
    }// else (NQ_Net_is_local(req->target))
    if(async){
      if(req->request){
        free(req->request);
      }
      free(req);
    }
  }
  
  int gc_timeout = NQ_GC_collect();
  
  if(gc_timeout >= 0){
    timeout = gc_timeout*1000 + 500;
  }
  
  NQ_Net_print_stats();
  
  NQ_Socket_poll(NQ_connection_pool, timeout);
#undef PRINT_REQUEST
}

void NQ_Net_nudge_pollthread(){
  NQ_Socketpool_unblock(NQ_connection_pool);
}

void *NQ_Net_accept(NQ_Socket *server, NQ_Socket *sock){
  NQ_Peer *peer;
  printf("Accepting connection \n");
  peer = NQ_Peer_make(sock);
  peer->id = (NQ_Host){NQ_Socket_peer(sock), 0};
  return peer;
}
void NQ_breakpoint(){
}
void NQ_Net_data(NQ_Socket *sock){
  NQ_Request_Header head;
//  printf("got some data: %d bytes buffered\n", NQ_Socket_data(sock));
  while(1){
    if(NQ_Socket_data(sock) < sizeof(NQ_Request_Header)){
//      printf("not enough for a header\n");
      break;
    }
    NQ_breakpoint();
    PING();
    NQ_Socket_peek(sock, (unsigned char *)&head, sizeof(NQ_Request_Header));
    PING();
    if(NQ_Socket_data(sock) < (head.length)){
//      printf("Not enough data for body: %d / %d\n", NQ_Socket_data(sock), head.length);
      break;
    }
    PING();
    if(NQ_Request_handle(sock, head.length) < 0){ //request_handle performs a read, skipping the appropriate length
      return;
    }
  }
}
void NQ_Net_error(NQ_Socket *sock){
  NQ_Peer *peer = NQ_Socket_userdata(sock);

  if(peer){
    NQ_Socket_set_userdata(sock, NULL);
    queue_delete(NQ_peers, peer);
    free(peer);
  }
}

NQ_Host NQ_Net_get_localhost(void){
  return nq_localhost;
}
NQ_Host NQ_Net_get_sockhost(NQ_Socket *sock){
  if(sock != NULL){
    return ((NQ_Peer *)NQ_Socket_userdata(sock))->id;
  } else {
    return NQ_Net_get_localhost();
  }
}

void NQ_Host_fprint(FILE *fp, NQ_Host host) {
  fprintf(fp, "[");fprint_ip(fp, host.addr);fprintf(fp, ":%d]", host.port);
}
void NQ_Host_print(NQ_Host host){
  NQ_Host_fprint(stdout, host);
}

int NQ_Net_is_local(NQ_Host addr){
  return (!nq_force_net) && NQ_Host_eq(addr, nq_localhost);
}

// Message Types:
//// Attribute Operation (return)
//// Transaction Test (return)
//// Transaction Abort (noreturn)
//// Transaction Commit (noreturn)
//// Tuple Create (return)
//// Tuple Delete (return)
//// Tuple Lookup
