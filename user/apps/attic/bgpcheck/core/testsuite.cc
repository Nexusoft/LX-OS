#include <iostream>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <fcntl.h>
extern "C" {
#include <nexus/Thread.interface.h>
#include <nexus/Profile.interface.h>
}

#include "../include/nbgp/nbgp.h"
#include "../include/util/optionlist.h"
#include "../include/util/g_tl.h"
#include "../include/util/ghetto_pcap.h"
#include "../include/util/common.h"
#include "../include/util/reassemble.h"
#include "../include/nbgp/grassroots.h"
#include "../include/runtime/runtime.h"
#include "../include/runtime/pipedsocket.h"
#include "../include/nbgp/bgp.h"
#include "../include/nbgp/testsuite.h"
#include "../include/util/debug.h"

extern int BC_Database_Entry_Total_Size;
extern int BC_Advertisement_Total_Size;
extern int BC_Advertisement_Communities_Size;
extern int BC_Advertisement_ASPATH_Size;

//#define TEST_MONODIRECTIONAL
#define USE_PROFILER 0

//yoinked these enums and the msg_hdr struct from MRTd's io.h
enum MRT_MSG_TYPES {
   MSG_NULL,
   MSG_START,			/* sender is starting up */
   MSG_DIE,			/* receiver should shut down */
   MSG_I_AM_DEAD,		/* sender is shutting down */
   MSG_PEER_DOWN,		/* sender's peer is down */
   MSG_PROTOCOL_BGP,		/* msg is a BGP packet */
   MSG_PROTOCOL_RIP,		/* msg is a RIP packet */
   MSG_PROTOCOL_IDRP,		/* msg is an IDRP packet */
   MSG_PROTOCOL_RIPNG,		/* msg is a RIPNG packet */
   MSG_PROTOCOL_BGP4PLUS,	/* msg is a BGP4+ packet */
   MSG_PROTOCOL_BGP4PLUS_01,	/* msg is a BGP4+ (draft 01) packet */
   MSG_PROTOCOL_OSPF,		/* msg is an OSPF packet */
   MSG_TABLE_DUMP		/* routing table dump */
};

enum MRT_MSG_BGP_TYPES {
   MSG_BGP_NULL,
   MSG_BGP_UPDATE,	/* raw update packet (contains both with and ann) */
   MSG_BGP_PREF_UPDATE, /* tlv preferences followed by raw update */
   MSG_BGP_STATE_CHANGE,/* state change */
   MSG_BGP_SYNC,	/* sync point with dump */
   MSG_BGP_OPEN,
   MSG_BGP_NOTIFY,
   MSG_BGP_KEEPALIVE
};

#pragma pack(push, 1)
struct bgp_open_msg {
  unsigned char marker[16];
  unsigned short len;
  unsigned char type;
  unsigned char vers;
  unsigned short AS;
  unsigned short hold;
  unsigned int ID;
  unsigned char paramlen;
};
struct bgp_keepalive_msg {
  unsigned char marker[16];
  unsigned short len;
  unsigned char type;  
};
#pragma pack(pop)

Fake_Router::Fake_Router(BGP_Peer *_peer, Test_Handler *_handler) : Runtime_Handler("Test_Peer") {
  ip = _peer->get_ip();
  as = _peer->get_AS();
  enabled = 0;
  handler = _handler;
  agent_pipe = new Minipipe();
  handler_pipe = new Minipipe();
  outlen = inlen = 0;
  agent = new BGP_Interposition_Agent(_peer);
}

void Fake_Router_Socket_Ready(Pipedsocket *sock, Fake_Router *router){
  router->socketready(sock);
}

void Fake_Router::start_socketed(){
  int serv, client;
  struct sockaddr_in saddr, caddr;
  int len;
  
  printf("Creating BGP Server\n");
  serv = socket(AF_INET, SOCK_STREAM, 0);
	
  if(serv < 0){
    perror("Error: Unable to initialize server socket");
    exit(1);
  }
	
  int one = 1;
	
  bzero((char *)&saddr, sizeof(struct sockaddr_in));
  saddr.sin_addr.s_addr = INADDR_ANY;
  saddr.sin_port = htons(179);
  saddr.sin_family = AF_INET;
	
  if(bind(serv, (struct sockaddr *)&saddr, sizeof(struct sockaddr_in)) < 0){
    perror("Error: Unable to bind socket");
    exit(1);
  }
	
  if(listen(serv, 1) < 0){
    perror("Error: Unable to configure server socket for listening");
    exit(1);
  }
  
  len = sizeof(struct sockaddr_in);
  while((client = accept(serv, (struct sockaddr *)&caddr, (socklen_t *)&len)) < 0){
    if(errno != EAGAIN){
      perror("Error: Failed to accept\n");
       exit(1);
    }
  }
  
  enabled = 1;
  
  sock = new Pipedsocket(client, (pipedsocket_ready_callback*)&Fake_Router_Socket_Ready, this);
}
void Fake_Router::start_norouter(){
  enabled = 1;
  agent->set_peer_streams(handler_pipe, NULL, runtime);
  agent->set_router_streams(agent_pipe, NULL, runtime);
  handler->fake_router_ready();
}
  
void Fake_Router::handle_minipipe(Minipipe *pipe, Runtime *runtime){
  char *buff;
  int len;
  len = pipe->read(&buff);
  outlen += len;
  agent_pipe->write_malloced(buff, len);
}
int Fake_Router::handle_periodic(Runtime *runtime){
  if(sock){
    static bgp_keepalive_msg msg = {{0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff}, htons(sizeof(bgp_keepalive_msg)), 4};
    sock->write_sock(sizeof(bgp_keepalive_msg), (char *)&msg);
    return 1000*10;
  } else {
    return -1;
  }
}

void open_bgp(Pipedsocket *sock){
  bgp_open_msg msg;
  memset(msg.marker, 0xff, 16);
  msg.len = htons(sizeof(bgp_open_msg));
  msg.type = 1;
  msg.vers = 4;
  msg.AS = htons(1234);
  msg.hold = htons(1000);
  msg.ID = inet_addr("128.84.227.25");
  msg.paramlen = 0;
  sock->write_sock(sizeof(bgp_open_msg), (char *)&msg);
  msg.type = 4;
  msg.len = htons(sizeof(bgp_keepalive_msg));
  sock->write_sock(sizeof(bgp_keepalive_msg), (char *)&msg);
}

void Fake_Router::socketready(Pipedsocket *_sock){
  Minipipe *router_out = _sock->write_pipe(runtime);
  //NULL pipe will just result in outbound packets being discarded
  agent->set_peer_streams(handler_pipe, NULL, runtime);
  agent->set_router_streams(agent_pipe, router_out, runtime);
  handler->fake_router_ready();
  
  //the router's expecting a join message
  open_bgp(sock);
  set_periodic_time(1000*10);
}
void Fake_Router::write_data(char *_data, int len){
  if(enabled){
    inlen += len;
    char *data = (char *)malloc(len);
    memcpy(data, _data, len);
    handler_pipe->write_malloced(data, len);
  }
}
void Fake_Router::inject_outbound(char *_data, int len){
  if(enabled){
    outlen += len;
    char *data = (char *)malloc(len);
    memcpy(data, _data, len);
    agent_pipe->write_malloced(data, len);
  }
}
unsigned int Fake_Router::get_ip(){
  return ip;
}

void Fake_Router::print_stats(int i, FILE *out){
  if(enabled){
    fprintf(out, "PEER%d: %d bytes written, %d bytes read\n", i, inlen, outlen);
  }
}

Test_Handler::Test_Handler(char *type, Ghetto_Vector *_peers, Runtime *runtime) :
  Runtime_Handler(type), bytes(0), msgs(0), status_bytes(15*1024*1024), direction(0),
  indb(NULL), grassrootsdb(NULL), test_peer(NULL)
{
  BGP_Peer *peer;
  BGP_Interposition_Agent *agent;
  
  peers = new Fake_Router *[_peers->size()];
  peer_cnt = peer_rdy = 0;
  
  _peers->iterator_reset();
  for(peer = (BGP_Peer *)_peers->iterator_next(); peer != NULL; peer = (BGP_Peer *)_peers->iterator_next()){
    peers[peer_cnt] = new Fake_Router(peer, this);
    runtime->register_handler(peers[peer_cnt]);
    peer_cnt++;
  }
}

extern int debug_run_id; //
void Test_Handler::fake_router_ready(){
  int max = peer_cnt;
//  if((debug_run_id > 0)&&(debug_run_id < peer_cnt)){
//    max = debug_run_id;
//  }
  peer_rdy ++;
  //printf("%d/%d peers connected\n", peer_rdy, (debug_run_id>0)?debug_run_id:peer_cnt);
  if(peer_rdy >= max){
    printf("All peers connected, starting test\n");
    re_register();
  }
}

void Test_Handler::start(){
  int i, max = peer_cnt;
//  if((debug_run_id > 0)&&(debug_run_id < peer_cnt)){
//    max = debug_run_id;
//  }
  for(i = 0; i < max; i++){
    if(i >= peer_cnt) break;
    peers[i]->start_norouter();
  }
}

void Test_Handler::re_register(){ //it's a bit of a hack, but eh.
  runtime->trigger_event(this, RUNTIME_EVENT_TIMER, NULL);
}

void Test_Handler::dispatch_inbound(){
  direction = 0;
}
void Test_Handler::dispatch_outbound(){
  direction = 1;
}

void Test_Handler::dispatch_msg(char *msg, int len, unsigned int ip, int port){
  int i = 0;
  
  for(i = 0; i < peer_cnt; i++){
    if(peers[i]->get_ip() == ip){
      if(direction){
        peers[i]->inject_outbound(msg, len);
      } else {
        peers[i]->write_data(msg, len);
      }
      break;
    }
  }
//  if(i >= peer_cnt) {
//    printf("Error: Msg %s undefined peer ", 0?"to":"from"); print_ip(ip, 0); printf(":%d\n", port);
//    assert(0);
//  }
  bytes += len;
  msgs++;
  if(bytes/status_bytes > (bytes - len)/status_bytes){
    print_state();
  }
  
}


extern int BC_Database_Entry_Total_Size;
extern int BC_Advertisement_Total_Size;
extern int BC_Advertisement_Communities_Size;
extern int BC_Advertisement_ASPATH_Size;
void Test_Handler::print_state(){
  printf("%ld bytes read; %ld messages\n", bytes, msgs);
  printf("INDB: %dB total; %dB entries, %dB attributes (inc %dB ASPATH, %dB Communities)\n", 
    indb->calc_size(), BC_Database_Entry_Total_Size, BC_Advertisement_Total_Size,
    BC_Advertisement_Communities_Size, BC_Advertisement_ASPATH_Size);
  debug_print_state(stdout);
}

void Test_Handler::set_indb(BC_Database *_indb){
  indb = _indb;
}
void Test_Handler::set_grassroots(Grassroots *_grassrootsdb){
  grassrootsdb = _grassrootsdb;
}

void Test_Handler::set_test_peer(Overlay_Peer_Handler *_test_peer){
  test_peer = _test_peer;
}


void Test_Handler::complete(){
  printf("\n\n================\n");
  printf("Finished test!\n");
  printf("================\n\n");
  print_state();
  if(indb){
    dprintf("INDB: %dB total; %dB entries, %dB attributes (inc %dB ASPATH, %dB Communities)\n", 
      indb->calc_size(), BC_Database_Entry_Total_Size, BC_Advertisement_Total_Size,
      BC_Advertisement_Communities_Size, BC_Advertisement_ASPATH_Size);
  }
  if(grassrootsdb){
    dprintf("GrassrootsDB: %dB total\n", grassrootsdb->calc_size());
  }
  if(debug_file()){
    int i;
    for(i = 0; i < peer_cnt; i++){
      peers[i]->print_stats(i, debug_file());
    }
  }
  debug_file_state();
  Profile_Enable(0);
  printf("Writing %d bytes of profile data\n", write_profile("/nfs/testsuite.profile"));
  
  printf("\n\n================\n");
  printf("Timings written to disk.\n");
  printf("If someone reads this, please hit escape and restart me!\n");
  printf("================\n\n");
  
  if(test_peer){
    printf("\n================\n");
    printf("... but although someone seems to have set me up to test the overlay.  You should probably let that finish first.\n");
    printf("================\n\n");
    
    test_peer->hacked_connect(inet_addr("128.84.227.47"), 52982);
  }
  
  printf("================\n");
  printf("waaaaitaminute... I can restart myse....\n");
  Thread_Reboot();
}

MRTStream::MRTStream(int _f, Ghetto_Vector *_peers, unsigned int _my_as, Runtime *runtime) : 
  Test_Handler("MRTStream", _peers, runtime), f(new FileBuffer(_f, 2048)), target(0), target_port(0), my_as(_my_as) 
{
#ifdef TEST_MONODIRECTIONAL
  Profile_Enable(USE_PROFILER);
#endif
}
MRTStream::MRTStream(unsigned int addr, unsigned short port, Ghetto_Vector *_peers, unsigned int _my_as, Runtime *runtime) : 
  Test_Handler("MRTStream", _peers, runtime), f(new FileBuffer(addr, port, 4024)), target(addr), target_port(port+1), my_as(_my_as) 
{
  printf("Reading datastream from ");print_ip(addr, 1);printf(":%d\n", port);
#ifdef TEST_MONODIRECTIONAL
  Profile_Enable(USE_PROFILER);
#endif
}
MRTStream::~MRTStream(){
  //fclose(f);
  
}

int MRTStream::load_header(mrt_msg_hdr *hdr){
  if(f->get(hdr, sizeof(mrt_msg_hdr)) < (int)sizeof(mrt_msg_hdr)){
    return 0;
  }
  hdr->tstamp = ntohl(hdr->tstamp);
  hdr->type = ntohs(hdr->type);
  hdr->subtype = ntohs(hdr->subtype);
  hdr->length = ntohl(hdr->length);
  return 1;
}

void MRTStream::reset_for_outbound(){
  if(target){
    delete f;
    f = new FileBuffer(target, target_port, 4024);
  } else {
    f->reset();
  }
  dispatch_outbound();
  re_register();
  Profile_Enable(USE_PROFILER);
}

void MRTStream::prepend_as_to_attrs(unsigned char *msg, int len){ //len is 2 shorter than the length we've been allocated
  unsigned char *ptr = msg, *ptrb;
  int flags;
  int type = -1;
  int attrlen;
  while(1){
    assert(ptr <= msg+len);
    flags = ptr[0];
    type = ptr[1];
    if(type == 2){
      break;
    }
    if(flags & 0x10){
      attrlen = ntohs(*(unsigned short *)(&ptr[2]));
      ptr += 4 + attrlen;
    } else {
      attrlen = ptr[2];
      ptr += 3 + attrlen;
    }
  }
  assert(type == 2);
  if(flags & 0x10){
    *(unsigned short *)(&ptr[2]) = htons(ntohs(*(unsigned short *)(&ptr[2])) + 2);
    ptr += 4;
  } else {
    assert(ptr[2] < 254);
    ptr[2] += 2;
    ptr += 3;
  }
  
  ptr[1] += 1; //segment length field
  ptr += 2;
  
  //shift the rest of the message over 2
  for(ptrb = msg + len; ptrb >= ptr; ptrb--){
    ptrb[2] = ptrb[0];
  }
  
  *(unsigned short *)ptr = htons(my_as);
}

int MRTStream::prepend_comm_to_attrs(unsigned char *msg, int len){
  unsigned char *ptr = msg, *ptrb;
  int flags;
  int type = -1;
  int attrlen;
  while(1){
    if(ptr >= msg+len){
      ptr[0] = 0xc0;
      ptr[1] = 0x08;
      ptr[2] = 0x04;
      *((unsigned int *)&(ptr[3])) = ntohl(0x4BC90004);
      return 7;
    }
    flags = ptr[0];
    type = ptr[1];
    if(type == 8){
      break;
    }
    if(flags & 0x10){
      attrlen = ntohs(*(unsigned short *)(&ptr[2]));
      ptr += 4 + attrlen;
    } else {
      attrlen = ptr[2];
      ptr += 3 + attrlen;
    }
  }
  assert(type == 8);
  if(flags & 0x10){
    *((unsigned int *)&(ptr[4])) = ntohl(0x4BC90004);
  } else {
    *((unsigned int *)&(ptr[3])) = ntohl(0x4BC90004);
  }
  return 0;  
  
}

void MRTStream::load_dump(mrt_msg_hdr *hdr){
  char msg[500], *ptr;
  mrt_dump_hdr d_hdr;
  bgp_msg_hdr *bgp_top;
  int len, x;
  unsigned int addr;
  unsigned short *attrlen;
  
  ptr = msg;
  bgp_top = (bgp_msg_hdr*)ptr;
  
  if(f->get(&d_hdr, sizeof(mrt_dump_hdr)) < (int)sizeof(mrt_dump_hdr)){
    debug_stop_timing("MRT_NFS_READ", 0);
#ifndef TEST_MONODIRECTIONAL
    if(!direction) 
      reset_for_outbound();
    else 
#endif
      { delete f; f = NULL; complete(); }
    return;
  }
  
  len = 
    sizeof(bgp_msg_hdr) + sizeof(unsigned short) + sizeof(unsigned short) + ntohs(d_hdr.attrlen) + sizeof(unsigned char) + ((d_hdr.mask+7) / 8) + (direction * sizeof(unsigned short));
  if(len >= (int)sizeof(msg)){
    printf("len: %d; attrlen: %d, @msg %ld, byte %ld!\n", len, ntohs(d_hdr.attrlen), msgs, bytes);
    unsigned char *tmp = new unsigned char[ntohs(d_hdr.attrlen)];
    assert(f->get(tmp, ntohs(d_hdr.attrlen)) == ntohs(d_hdr.attrlen));
    bgp_print_hex(tmp, ntohs(d_hdr.attrlen));
    assert(len < (int)sizeof(msg));
  }
  
  memset(bgp_top->marker, 0xff, 16);
  bgp_top->type = 2;//update
  bgp_top->length = htons(len);
    ptr += sizeof(bgp_msg_hdr);

  
  *(unsigned short *)ptr = 0;
    ptr += sizeof(unsigned short);
  attrlen = (unsigned short *)ptr;
  *attrlen = htons(ntohs(d_hdr.attrlen) + (direction * sizeof(unsigned short)));
    ptr += sizeof(unsigned short);
  if(f->get(ptr, ntohs(d_hdr.attrlen)) < ntohs(d_hdr.attrlen)){
    debug_stop_timing("MRT_NFS_READ", 1);
    return;
  }
  if(direction) { 
    int commlen;
    prepend_as_to_attrs((unsigned char *)ptr, ntohs(d_hdr.attrlen)); 
    commlen = prepend_comm_to_attrs((unsigned char *)ptr, ntohs(d_hdr.attrlen));
    if(commlen > 0){
      len += commlen;
      bgp_top->length = htons(ntohs(bgp_top->length) + commlen);
      *attrlen = htons(ntohs(*attrlen) + commlen);
      ptr += commlen;
    }
  }
    ptr += ntohs(d_hdr.attrlen) + (direction * sizeof(unsigned short));
    
  *(unsigned char *)ptr = d_hdr.mask;
    ptr += sizeof(unsigned char);
  for(x = (int)d_hdr.mask, addr = ntohl(d_hdr.addr); x > 0; x -= 8, addr <<= 8){
    *(unsigned char *)ptr = (unsigned char)((addr >> 24) & 0xff);
      ptr += sizeof(unsigned char);
    if(ptr > msg+len){
      printf("error on ");print_ip(d_hdr.addr, 1);printf("/%d, x = %d\n", d_hdr.mask, x);
      assert(ptr <= msg+len);
    }
  }

  assert(ptr == msg+len);
  assert(hdr->length == sizeof(mrt_dump_hdr) + ntohs(d_hdr.attrlen));

  debug_stop_timing("MRT_NFS_READ", 1);
  
  dispatch_msg(msg, len, ntohl(d_hdr.peer_ip), 179);
}

#define UPDATE_BUFF_SZ 20000

void MRTStream::load_update(mrt_msg_hdr *hdr){
  static unsigned char *buffer = new unsigned char[UPDATE_BUFF_SZ];
  unsigned char *ptr = buffer+sizeof(bgp_msg_hdr);
  bgp_msg_hdr *bgp_hdr = (bgp_msg_hdr *)buffer;
  unsigned short len;
  unsigned int peer;
  
  hdr->length -= 4; // XXX hack to get the "peer" we send to into the MRT format
  if(f->get(&peer, 4) != 4){ return; }
  
  len = sizeof(bgp_msg_hdr) + hdr->length;
  
  memset(bgp_hdr->marker, 0xff, 16);
  bgp_hdr->length = htons(len);
  bgp_hdr->type = 2;
  if(len >= UPDATE_BUFF_SZ-10){
    printf("len: %d (%d bytes in)\n", len, f->read_cnt());
    assert(len < UPDATE_BUFF_SZ-10);
  }
  
  if(!direction){
    if(f->get(ptr, hdr->length) != (int)hdr->length){
      debug_stop_timing("MRT_NFS_READ", 1);

#ifndef TEST_MONODIRECTIONAL
      reset_for_outbound();
#else
      complete();
#endif
      return;
    }
  } else {
    int commlen, attrlen;
    if(f->get(ptr, 2) != 2){ 
      debug_stop_timing("MRT_NFS_READ", 1);
      return;
    } //withdrawn length
    assert(*(unsigned short *)ptr == 0); //shouldn't be anything withdrawn in this test
      ptr += 2;
    if(f->get(ptr, 2) != 2){ 
      debug_stop_timing("MRT_NFS_READ", 1);
      assert(0);
      return;
    } //attribute length
    
    attrlen = ntohs(*(unsigned short *)ptr);
    //printf("%d bytes of attributes (%d bytes read; ptr at %d)\n", attrlen, f->read_cnt(), ptr-buffer);
    
    if(f->get(ptr+2, attrlen) != attrlen){ 
      debug_stop_timing("MRT_NFS_READ", 1);
      assert(0);
      return;
    } //the actual attributes
    
    prepend_as_to_attrs(ptr+2, attrlen);
    commlen = prepend_comm_to_attrs(ptr+2, attrlen+2);
    bgp_hdr->length = htons(len + commlen + 2);
    *(unsigned short *)ptr = htons(attrlen + commlen + 2);
    ptr += 2 + attrlen + commlen + 2;
    //printf("%d bytes of attributes after modifications (%d bytes read; ptr at %d)\n", attrlen + commlen + 2, f->read_cnt(), ptr-buffer);
    
    //and finish off the rest of the buffer.
    if(f->get(ptr, hdr->length - (4+attrlen)) != (int)(hdr->length - (4+attrlen))) { 
      debug_stop_timing("MRT_NFS_READ", 1);
      assert(0);
      return;
    }
    ptr += (int)(hdr->length - (4+attrlen));
    
    //printf("%d bytes of prefixes read (%d bytes read; ptr at %d)\n", (int)(hdr->length - (4+attrlen)), f->read_cnt(), ptr-buffer);
    
  }
  debug_stop_timing("MRT_NFS_READ", 1);
  dispatch_msg((char *)buffer, ntohs(bgp_hdr->length), ntohl(peer), 179);
}

void MRTStream::dump_bytes(int len){
  f->skip(len);
}

int MRTStream::handle_periodic(Runtime *runtime){
  mrt_msg_hdr hdr;

  //printf("a\n");
  debug_start_timing("MRT_NFS_READ");
  if(load_header(&hdr)){
    //printf("msg: %d bytes\n", (int)hdr.length);
    switch(hdr.type){
      case MSG_NULL:
        dump_bytes(hdr.length);
        debug_stop_timing("MRT_NFS_READ", 1);
        break;
      case MSG_TABLE_DUMP:
        load_dump(&hdr);
        break;
      case MSG_PROTOCOL_BGP:
        if(hdr.subtype == 1){
          load_update(&hdr);
          break;
        }
      default:
        print_state();
        printf("mrt_type = %d; bytes read: %d, bytes written: %ld\n", hdr.type, f->read_cnt(), bytes);
        debug_stop_timing("MRT_NFS_READ", 1);
        assert(!"Unhandled Type");
    }
    re_register();
  } else {
    debug_stop_timing("MRT_NFS_READ", 0);
#ifndef TEST_MONODIRECTIONAL
    if(!direction) 
      reset_for_outbound();
    else 
#endif
      { delete f; f = NULL; complete(); }
  }
  
  
  return -1;
}

int mrt_load_update(FileBuffer *f, mrt_msg_hdr *hdr, unsigned char *buffer, unsigned int *bufferlen, unsigned int *peer){
  bgp_msg_hdr *bgp_hdr = (bgp_msg_hdr *)buffer;
  unsigned char *ptr = buffer+sizeof(bgp_msg_hdr);
  
  hdr->length -= 4;
  if(f->get(peer, sizeof(unsigned int)) < (int)sizeof(unsigned int)) return 0;
  
  assert(hdr->length < *bufferlen);
  *bufferlen = sizeof(bgp_msg_hdr) + hdr->length;
  
  memset(bgp_hdr->marker, 0xff, 16);
  bgp_hdr->length = htons(sizeof(bgp_msg_hdr) + hdr->length);
  bgp_hdr->type = 2;
  
  f->get(ptr, hdr->length);
  return 1;
}
int mrt_load_header(FileBuffer *f, mrt_msg_hdr *hdr){
  if(f->get(hdr, sizeof(mrt_msg_hdr)) < (int)sizeof(mrt_msg_hdr)){
    return 0;
  }
  hdr->tstamp = ntohl(hdr->tstamp);
  hdr->type = ntohs(hdr->type);
  hdr->subtype = ntohs(hdr->subtype);
  hdr->length = ntohl(hdr->length);
  return 1;
}
void mrt_finish_packet(BC_Database *indb, std::map<unsigned int,unsigned short> *AS_MAP, unsigned char *buffer, unsigned int buffsz, unsigned int peer){
  bgp_packet pkt;
  bgp_datasource ds;
  std::map<unsigned int,unsigned short>::iterator as;
  
  ds.type = (typeof(ds.type))2;
  ds.error = 0;
  ds.contents.buffer.cursor = 0;
  ds.contents.buffer.len = buffsz;
  ds.contents.buffer.buff = (char *)buffer;
  
  bgp_init_packet(&pkt);
  assert(bgp_read_packet(&ds, &pkt) == buffsz);
  
  as = AS_MAP->find(peer);
  if(as == AS_MAP->end()){
    assert(pkt.contents.UPDATE.as_path);
    assert(pkt.contents.UPDATE.as_path->list);
    (*AS_MAP)[peer] = pkt.contents.UPDATE.as_path->list[0];
    as = AS_MAP->find(peer);
    assert(as != AS_MAP->end());
  }
//  printf("(%d)\n", buffsz);
//  bgp_print_hex(buffer, buffsz);
//  bgp_print_packet(&pkt);
  indb->parse(&pkt, peer, as->second);
  
  bgp_cleanup_packet(&pkt);
}
void mrt_preload(unsigned int addr, unsigned short port, BC_Database *indb, unsigned short my_as){
  mrt_msg_hdr hdr;
  FileBuffer *f = new FileBuffer(addr, port, 4024);
  unsigned int peer;
  static unsigned char *buffer = new unsigned char[UPDATE_BUFF_SZ];
  unsigned int buffsz;
  std::map<unsigned int,unsigned short> AS_MAP;
  int not_finished = 1;
  
  printf("Starting DB Load");
  while(not_finished){
    buffsz = UPDATE_BUFF_SZ;
    if(mrt_load_header(f, &hdr)){
      switch(hdr.type){
        case MSG_PROTOCOL_BGP:
          if(hdr.subtype == 1){
            if(!mrt_load_update(f, &hdr, buffer, &buffsz, &peer)) not_finished = 0;
            mrt_finish_packet(indb, &AS_MAP, buffer, buffsz, peer);
            break;
          }
        default:
          printf("mrt_type = %d; bytes read: %d\n", hdr.type, f->read_cnt());
          debug_stop_timing("MRT_NFS_READ", 1);
          assert(!"Unhandled Type");
      }
    } else {
      not_finished = 0;
    }
  }
  
  printf("DB Load Finished: %dB total stored\n", indb->calc_size());
  delete f;
}

void fake_capture(Fake_Capture_Info *info){
  int sock;
  struct sockaddr_in saddr;
  char full_buff[5220+sizeof(int)+sizeof(Flow)];
  Flow *flow = (Flow *)&full_buff;
  int *len = (int *)&(full_buff[sizeof(Flow)]);
  char *buff = &(full_buff[sizeof(Flow)+sizeof(int)]);
  Minipipe *p2 = new Minipipe();
  unsigned int bytes_read = 0;
  char *tmp;
  int tmplen;

  assert((sock = socket(PF_INET, SOCK_STREAM, 0)) >= 0);
  saddr.sin_family = AF_INET;
  saddr.sin_addr.s_addr = info->debug_peer;
  saddr.sin_port = htons(179);
  printf("Connecting to peer "); print_ip(saddr.sin_addr.s_addr, 1); printf(":%d\n", ntohs(saddr.sin_port));
  assert(connect(sock, (struct sockaddr *)&saddr, sizeof(struct sockaddr_in)) == 0);
  printf("Connected\n");

  flow->from.port = saddr.sin_port;
  flow->to.port = saddr.sin_port;

  while(1){
    *len = recv(sock, buff, 5120, 0);
    //assert(len >= 0);
    if(*len > 0){
      bytes_read += *len;

      flow->from.addr.s_addr = info->my_ip;
      flow->to.addr = saddr.sin_addr;
      info->pipe->write(full_buff, sizeof(Flow) + sizeof(int) + *len);

      if(info->debug_mode){
        flow->from.addr = saddr.sin_addr;
        flow->to.addr.s_addr = info->my_ip;
        p2->write(full_buff, sizeof(Flow) + sizeof(int) + *len);
        
        if(bytes_read > info->debug_size){
          printf("Peer debug mode switching to outgoing packets: %d bytes (%d chunks)\n", bytes_read, p2->get_count());
          bytes_read = 0;
          while(p2->get_count() > 0){
            tmplen = p2->read(&tmp);
            info->pipe->write_malloced(tmp, tmplen);
          }
          return;
        }
      } else {
        if(bytes_read > info->debug_size){
          return;
        }
      }
    }
  }
}

void file_reader_thread(File_Reader_Info *info){
  unsigned int len[2];
  char *buffer;
  unsigned int tot = 0;
  struct timeval starttime, currtime;
  gettimeofday(&starttime, NULL);
  while(!feof(info->f)){
    if(fread(len, sizeof(int), 2, info->f) < 2){
      break;
    }
    assert(len[0] == len[1]);
    buffer = (char *)malloc(sizeof(char) * len[0]);
    if(fread(buffer, sizeof(char), len[0], info->f) < len[0]){
      break;
    }
    info->pipe->write_malloced(buffer, len[0]);
    if(info->delay){
      Thread_USleep(info->delay + (rand() % info->offset) - info->offset/2);
    }
    if(info->cap){
      while(info->pipe->get_bytes() > info->cap){
        Thread_USleep(1000);
      }
    }
    if((tot / (50*1024*1024)) != ((tot+len[0]) / (50*1024*1024))){
      gettimeofday(&currtime, NULL);
      if(currtime.tv_sec - starttime.tv_sec > 0){
        printf("%d bytes loaded (%d kbps)\n", tot+len[0], (50*1024*1024)/(int)(currtime.tv_sec - starttime.tv_sec));
      }
      while(info->pipe->get_bytes() > 0){
        Thread_USleep(1000);
      }
      gettimeofday(&starttime, NULL);
    }
    tot += len[0];
  }
  printf("reached end of stream!  Waiting for pipe to drain so I can test the db size\n");
  while(info->pipe->get_bytes() > 0){
    Thread_USleep(1000);
  }
  exit(0);
}

Minipipe *file_pipe(char *name, int delay, int offset){
  File_Reader_Info *info = new File_Reader_Info;
  pthread_t file_thread;
  
  info->f = fopen(name, "r");
  if(!info->f){
    delete info;
    return NULL;
  }
  info->pipe = new Minipipe();
  info->delay = 0;delay;
  info->offset = 0;offset;
  info->cap = 500*1024; //half a meg cache should keep it busy.
  pthread_create(&file_thread, NULL, (void *(*)(void *))file_reader_thread, info);
  return info->pipe;
}

//Minisocket *file_pipe(char *name, int delay, int offset){
//  int f;
//  Minisocket *s;
//  
//  f = open(name, O_RDONLY);
//  if(f < 0){
//    printf("Error opening file: %s\n", name);
//    exit(0);
//  }
//  
//  s = new Minisocket(f);
//  s->debug_add_delay_chance(offset, delay);
//  s->accept(NULL, NULL, 0);
//  return s;
//}

NBGP_Policy_Line *prefix_spec_needs_comm(char *prefix, unsigned short len, unsigned int num){
  Policy_Filter *fa;
  NBGP_Policy_Line *l;
  NBGP_AS_Policy_Set *as;
  Policy_Action act;
  
  l = new NBGP_Policy_Line();
  
  fa = new Policy_Filter();
  fa->type = FILTER_PSET;
  fa->d.p_set = new Prefix_Spec(new Prefix_Spec(ntohl(inet_addr(prefix)), len), PREFIX_INCLUSIVE_SPECIFICS);
  l->set_filter(fa);
  
  as = new NBGP_AS_Policy_Set();
  as->flags = NBGP_AS_ANY;
  l->add_as(as);
  
  act.field = PACTION_COMMUNITY;
  act.op = PACTION_OP_APPEND;
  act.value = (0x4BC90000|num);
  as->add_action(act);
  
  return l;
}

NBGP_Policy_Line *policy_any(){
  NBGP_Policy_Line *l;
  Policy_Filter *fa;
  NBGP_AS_Policy_Set *as;
  
  l = new NBGP_Policy_Line();

  fa = new Policy_Filter();
  fa->type = FILTER_ANY;
  l->set_filter(fa);
  
  as = new NBGP_AS_Policy_Set();
  as->flags = NBGP_AS_ANY;
  l->add_as(as);
  
  return l;
}

class NBGP_Timed_Policy : public NBGP_Policy {
 public:
  NBGP_Timed_Policy(char *_name) : NBGP_Policy(), debug_handle(debug_get_stateptr(_name)) { }
  
  virtual short ask(Policy_Question *q){
    short ret;
    if(debug_handle) debug_start_timing(debug_handle);
    ret = ask_real(q);
    if(debug_handle) debug_stop_timing(debug_handle, 1);
    return ret;
  }
  
 private:
  DebugState *debug_handle;
};
extern int debug_run_id;
NBGP_Policy *fake_policy(){
  if(debug_run_id > 40) return NULL;

  NBGP_Timed_Policy *p = new NBGP_Timed_Policy("POLICY_CHECK");
  
  p->add_export(policy_any());
  if(debug_run_id > 0){
    p->add_import(prefix_spec_needs_comm("40.253.21.0", 24, 4));
    p->add_import(prefix_spec_needs_comm("55.40.0.0", 16, 4));
  }
  if(debug_run_id > 10){
    p->add_import(prefix_spec_needs_comm("41.233.224.0", 20, 4));
    p->add_import(prefix_spec_needs_comm("32.97.198.0", 24, 4));
  }
  if(debug_run_id > 20){
    p->add_import(prefix_spec_needs_comm("24.139.85.0", 24, 4));
    p->add_import(prefix_spec_needs_comm("47.162.0.0", 16, 4));
    p->add_import(prefix_spec_needs_comm("43.224.0.0", 16, 4));
    p->add_import(prefix_spec_needs_comm("12.158.89.0", 24, 4));
  }
  if(debug_run_id > 30){
    p->add_import(prefix_spec_needs_comm("47.46.32.0", 23, 4));
    p->add_import(prefix_spec_needs_comm("24.75.194.0", 23, 4));
    p->add_import(prefix_spec_needs_comm("12.151.229.0", 24, 4));
    p->add_import(prefix_spec_needs_comm("12.28.222.0", 23, 4));
    p->add_import(prefix_spec_needs_comm("24.33.48.0", 20, 4));
    p->add_import(prefix_spec_needs_comm("12.50.109.0", 24, 4));
    p->add_import(prefix_spec_needs_comm("38.112.166.0", 24, 4));
  }
  
  
//  p->add_import(prefix_spec_needs_comm("24.121.93.0", 24, 4));
//  p->add_import(prefix_spec_needs_comm("139.225.0.0", 16, 4));
//  p->add_import(prefix_spec_needs_comm("139.223.0.0", 16, 4));
//  p->add_import(prefix_spec_needs_comm("139.222.0.0", 16, 4));
//  p->add_import(prefix_spec_needs_comm("139.191.0.0", 16, 4));
//  p->add_import(prefix_spec_needs_comm("76.8.65.0", 24, 4));
  
  return p;
}


