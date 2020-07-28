#include <assert.h>
#include "../include/nbgp/nbgp.h"
#include "../include/util/common.h"

//set to 0 to disable
#define OVERLAY_USE_SSL 1

Overlay_Peer_Handler::Overlay_Peer_Handler(Overlay_Server_Handler *_server) : Runtime_Handler("Overlay_Peer_Handler") {
  as = 0;
  flags = 0;
  server = _server;
  test_rvqcnt = 0;
}

void Overlay_Peer_Handler::set_socket(Minisocket *_sock){
  sock = _sock;
  set_minisock(sock, OVERLAY_USE_SSL);
}
void Overlay_Peer_Handler::create_socket(unsigned short _as){
  as = _as;
  flags |= 0x02;
  printf("Connecting to : "); print_ip(server->get_ip(as), 1); printf(":%d\n", server->get_port(as));
  sock = create_minisock(server->get_ip(as), server->get_port(as), OVERLAY_USE_SSL);
}
void Overlay_Peer_Handler::hacked_connect(unsigned int ip, unsigned short port){
  as = 42;
  flags |= 0x02;
  printf("Connecting to : "); print_ip(ip, 1); printf(":%d\n", port);
  sock = create_minisock(ip, port, OVERLAY_USE_SSL);  
}

void Overlay_Peer_Handler::handle_minipipe(Minipipe *pipe, Runtime *runtime){
  char *msg;
  int len;
  overlay_msg_prefixpath *prepath;
  overlay_msg_join *join;
  
  len = pipe->read(&msg);
  
  assert(msg != NULL);
  
  switch(*(int *)msg){
    case OVERLAY_MSG_RVQ:
      prepath = (overlay_msg_prefixpath *)msg;
      assert(prepath->type == OVERLAY_MSG_RVQ);

      if(!server->got_rvq(prepath->path, prepath->prefix, prepath->prefixlen)){
        prepath->type = OVERLAY_MSG_BADRVQ;
        sock->write_sock(sizeof(overlay_msg_prefixpath), (char *)prepath);
      }
      break;
    case OVERLAY_MSG_JOIN:
      join = (overlay_msg_join *)msg;
      assert(join->type == OVERLAY_MSG_JOIN);
      //the first join message will always be from the peer
      if(!(flags & 0x02)){
        as = join->as;
        server->set_as(this, as);
        flags |= 0x02;
      }
      server->got_join(join->as, join->ip, join->port);
      break;
    case OVERLAY_MSG_WARN:
      prepath = (overlay_msg_prefixpath *)msg;
      assert(prepath->type == OVERLAY_MSG_WARN);
      if(test_rvqcnt > 0){
        test_rvqcnt --;
        if(test_rvqcnt > 0){
          prepath->type = OVERLAY_MSG_RVQ;
          sock->write_sock(len, msg);
          //bounce it back
        } else {
          //we're done counting
          printf("DEBUG: RVQ Test complete, %d us\n", stop_profile(test_start));
          sock->close_sock();
        }
        break; //don't process this message, it's just a test
      }
      server->got_warning(prepath->path, prepath->prefix, prepath->prefixlen);
      break;
    case OVERLAY_MSG_BADRVQ:
      prepath = (overlay_msg_prefixpath *)msg;
      assert(prepath->type == OVERLAY_MSG_BADRVQ);
      server->got_bad_rvq(prepath->path, prepath->prefix, prepath->prefixlen);
      break;
    case OVERLAY_MSG_GRASSROOTS: {
        Grassroots::RawData *gr_msg = new Grassroots::RawData((unsigned char*)&(msg[sizeof(int)]), len-sizeof(int));
        //XXX handle this!
        delete gr_msg;
      }
      break;
    case OVERLAY_MSG_TRIGGER_WARNING:
      prepath = (overlay_msg_prefixpath *)msg;
      //XXX FOR DEBUGGING PURPOSES ONLY
      prepath->type = OVERLAY_MSG_BADRVQ;
      sock->write_sock(len, msg);
      break;
    default:
      printf("Overlay message type: %d is invalid\n", (*(int *)msg));
      assert(!"Overlay got a message with an unknown type");
  }
  
  free(msg);
}
void Overlay_Peer_Handler::handle_sockready(Minisocket *_sock, Runtime *runtime){
  overlay_msg_join join;
  
  sock = _sock;

  join.type = OVERLAY_MSG_JOIN;
  join.as = server->my_as();
  join.ip = server->my_ip();
  join.port = server->my_port();
  
  sock->write_sock(sizeof(overlay_msg_join), (char *)&join);

  if(test_rvqcnt > 0){
    unsigned short path[4] = {1, 2, 3, 0};
    send_rvq(path, 0xffff0000, 16);
  }
  
  flags |= 0x01;
}

void Overlay_Peer_Handler::test_rvq_out(int cnt){
  test_rvqcnt = cnt;
  test_start = start_profile(0);
}

int routelen(unsigned short *route){
  int i;
  for(i = 0; route[i] != 0; i++);
  return i;
}

void Overlay_Peer_Handler::send_rvq(unsigned short *route, unsigned int prefix, int p_len){
  if(!sock) { printf("Socket not ready!\n"); return; };

  int pathlen = routelen(route);
  overlay_msg_prefixpath *prepath = (overlay_msg_prefixpath *)alloca(4 * sizeof(int) + pathlen * sizeof(short));
  prepath->type = OVERLAY_MSG_RVQ;
  prepath->prefix = prefix;
  prepath->prefixlen = p_len;
  prepath->pathlen = pathlen;
  memcpy(prepath->path, route, pathlen *sizeof(short));
  
  sock->write_sock(4 * sizeof(int) + pathlen * sizeof(short), (char *)prepath);
}
void Overlay_Peer_Handler::send_warning(unsigned short *route, unsigned int prefix, int p_len){
  if(!sock) { printf("Socket not ready!\n"); return; };
  
  int pathlen = routelen(route);
  overlay_msg_prefixpath *prepath = (overlay_msg_prefixpath *)alloca(4 * sizeof(int) + pathlen * sizeof(short));
  prepath->type = OVERLAY_MSG_WARN;
  prepath->prefix = prefix;
  prepath->prefixlen = p_len;
  prepath->pathlen = pathlen;
  memcpy(prepath->path, route, pathlen *sizeof(short));
  
  if(!sock->closed()){  
    sock->write_sock(4 * sizeof(int) + pathlen * sizeof(short), (char *)prepath);
  }
}
void Overlay_Peer_Handler::send_join(unsigned short _as, unsigned int _ip, unsigned short _port){
  overlay_msg_join join;
  
  if(!(flags & 0x01)) return;
  
  join.as = _as;
  join.ip = _ip;
  join.port = _port;
  join.type = OVERLAY_MSG_JOIN;
  
  sock->write_sock(sizeof(overlay_msg_join), (char *)&join);
}



Overlay_Server_Handler::Overlay_Server_Handler(unsigned short _as, unsigned int _ip, unsigned short _port) : Runtime_Handler("Overlay_Server_Handler") {
  memset(peers, 0, sizeof(Overlay_Peer) * 65536);
  as = _as;
  ip = _ip;
  port = _port;
  first_direct = NULL;
  dispatch = NULL;
}

void Overlay_Server_Handler::handle_accept(Minisocket *sock, Runtime *runtime){
  Overlay_Peer_Handler *peer = new Overlay_Peer_Handler(this);
  runtime->register_handler(peer);
  peer->set_socket(sock);
}
int Overlay_Server_Handler::handle_periodic(Runtime *runtime){
  return -1;
}

//peer management
void Overlay_Server_Handler::add_peer(BGP_Peer *peer){
  if(peers[peer->get_AS()].peer == NULL){
    peers[peer->get_AS()].ip = peer->get_ol_ip();
    peers[peer->get_AS()].port = peer->get_ol_port();
    get_runtime()->register_handler(get_channel(peer->get_AS()));
    peers[peer->get_AS()].next_direct = first_direct;
    first_direct = &(peers[peer->get_AS()]);
  }
}
Overlay_Peer_Handler *Overlay_Server_Handler::get_channel(unsigned short as){
  if(peers[as].peer == NULL){
    if(peers[as].ip != 0){
      peers[as].peer = new Overlay_Peer_Handler(this);
      peers[as].peer->create_socket(as);
    } else {
      return NULL;
    }
  }
  return peers[as].peer;
}

//peer messaging
void Overlay_Server_Handler::send_rvq(unsigned short *route, unsigned int prefix, int p_len){
  int i;
  Overlay_Peer_Handler *handler;
  //find the first participating host in the path other than ourselves
  for(i = 0; route[i] != 0; i ++){
    if(route[i] != as){
      if((handler = get_channel(route[i])) != NULL){
        handler->send_rvq(route, prefix, p_len);
        break;
      }
    }
  }
}
void Overlay_Server_Handler::send_warning(unsigned short *route, unsigned int prefix, int p_len){
  Overlay_Peer *curr = first_direct;
  while(curr != NULL){
    curr->peer->send_warning(route, prefix, p_len);
    curr = curr->next_direct;
  }
}
void Overlay_Server_Handler::send_join(short _as){
  Overlay_Peer *curr = first_direct;
  while(curr != NULL){
    curr->peer->send_join(_as, peers[_as].ip, peers[_as].port);
    curr = curr->next_direct;
  }
}

void Overlay_Server_Handler::got_bad_rvq(unsigned short *route, unsigned int prefix, int p_len){
  int i;
  printf("RVQ Response: WARNING! :");
  for(i = 0; route[i] != 0; i++){
    printf(" [%d]", route[i]);
  }
  printf("\n");

  //the dispatcher at the sender will send out a warning
}
void Overlay_Server_Handler::got_warning(unsigned short *route, unsigned int prefix, int p_len){
  int i;
  printf("Got message: WARNING! :");
  for(i = 0; route[i] != 0; i++){
    printf(" [%d]", route[i]);
  }
  printf("\n");
}
void Overlay_Server_Handler::got_join(unsigned short _as, unsigned int _ip, unsigned short _port){
  if(peers[_as].ip != 0){
    peers[_as].ip = _ip;
    peers[_as].port = _port;
    send_join(_as);
  }
}
int Overlay_Server_Handler::got_rvq(unsigned short *route, unsigned int prefix, int p_len){
  assert(dispatch);
  dispatch->rvq(prefix, p_len, route);
  return 0;
}

unsigned int Overlay_Server_Handler::get_ip(unsigned short _as){
  return peers[_as].ip;
}
unsigned short Overlay_Server_Handler::get_port(unsigned short _as){
  return peers[_as].port;
}
void Overlay_Server_Handler::set_as(Overlay_Peer_Handler *peer, unsigned short _as){
  if(peers[_as].peer == NULL){
    peers[_as].peer = peer;
  }
}

unsigned short Overlay_Server_Handler::my_as(){
  return as;
}
unsigned int Overlay_Server_Handler::my_ip(){
  return ip;
}
unsigned short Overlay_Server_Handler::my_port(){
  return port;
}
void Overlay_Server_Handler::test_rvq_out(int cnt){
  first_direct->peer->test_rvq_out(cnt);
}
void Overlay_Server_Handler::set_dispatcher(BGP_Dispatcher *_dispatch){
  dispatch = _dispatch;
}
