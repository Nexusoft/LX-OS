#include <iostream>
#include <vector>
#include <string>
#include <assert.h>
#include <getopt.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <queue>
#include <map>
#include <pthread.h>
#include <sched.h>
#include <unistd.h>
#include "../include/util/common.h"
extern "C" {
#include <nexus/Profile.interface.h>
#include "../include/nbgp/bgp.h"
extern int writefile(char *filename, char *buffer, int size);
}
#include "../include/util/g_tl.h"
#include "../include/nbgp/nbgp.h"
#include "../include/util/reassemble.h"
#include "../include/util/safe_malloc.h"
#include "../include/util/debug.h"

#pragma pack(push, 1)
typedef struct {
  unsigned int src_ip;
  unsigned int src_port;
  unsigned int dst_ip;
  unsigned int dst_port;
  int len;
} reassemble_header;
#pragma pack(pop)

#define ENABLE_PROFILER 0

Source_Handler::Source_Handler(Ghetto_Vector *peers_l, unsigned int ip_l, unsigned int AS_l, Minipipe *pipe_l) : Runtime_Handler(-1, pipe_l, "Source_Handler"){
  pipe = pipe_l;
  peers = peers_l;
  ip = ip_l;
  AS = AS_l;
  test_buffer = 0;
  eventsleft = 0;
  pr_time = 0;
}
Source_Handler::~Source_Handler(){
}
void Source_Handler::handle_minipipe(Minipipe *pipe, Runtime *runtime){
  char *data;
  reassemble_header *header;
  int len, i, outgoing = 0;
  unsigned int peer_ip = 0;
  BGP_Peer *peer;
  struct timeval start_time = { 0, 0 };
  unsigned int packets = 0;
  unsigned int delta;
  
  //printf("handle_minipipe()\n");
  eventsleft ++;

  if(test_buffer > 0){
    if(pipe->get_bytes() > (unsigned int)test_buffer){
      printf("Got %d(%d) bytes, %d chunks\n", pipe->get_bytes(), test_buffer, pipe->get_count());
      eventsleft = pipe->get_count();
      test_buffer = 0;
    } else {
      return;
    }
#ifdef ENABLE_PROFILER
    start_time = start_profile(1);
#else
    start_time = start_profile(0);
#endif
  }

  do {
    //printf("pipe->read\n");
    data = NULL;
    len = pipe->read(&data);
    
    if(len <= 0){
      //printf("Pipe event with no data!\n");
      //assert(data == NULL);
      break;
    }
    
    assert(data != NULL);
    assert(len > (int)sizeof(reassemble_header));
    
    header = (reassemble_header *)data;
    
    //XXX this needs to be handled more smoothly.
    assert(header->len >= 0); //- values mean dropped packets :(
    assert(len >= (int)header->len + (int)sizeof(reassemble_header));
    
    
    if(ntohl(header->src_ip) == ip){
      peer_ip = ntohl(header->dst_ip);
      outgoing = 1;
    } else if(ntohl(header->dst_ip) == ip){
      peer_ip = ntohl(header->src_ip);
      outgoing = 0;
    } else {
      printf("[[ %s -> %s ]]\n", ip2str(ntohl(header->src_ip)).c_str(), ip2str(ntohl(header->dst_ip)).c_str());
      assert(!"The filter let through a packet not meant for us!");
    }
    
    //printf("[[ %s -> %s ]]\n", ip2str(ntohl(header->src_ip)).c_str(), ip2str(ntohl(header->dst_ip)).c_str());
    //printf("%lx %s %lx\n", ip, outgoing?"-->":"<--", peer_ip);
    
    //now figure out where this packet goes
    //peers->debug();
    peers->iterator_reset();
    //printf("foo!  %d\n", peers->size());
    for(peer = (BGP_Peer *)peers->iterator_next(); peer != NULL; peer = (BGP_Peer *)peers->iterator_next()){
      //printf("Checking peer @ %0lx\n", peer);
      //printf("peer ip: %s =?= %s\n", ip2str(peer->get_ip()).c_str(), ip2str(peer_ip).c_str());
      
      //printf("checking %s == %s\n", ip2str(peer->get_ip()).c_str(), ip2str(peer_ip).c_str());
      if(peer->get_ip() == peer_ip){
        if(outgoing){
          //printf("outgoing!\n");
          if(test_buffer < 0){
            test_buffer = - test_buffer;
            printf("Got an outgiong packet; blocking buffer\n");
          }
          packets += peer->process_out_packet(&(data[sizeof(reassemble_header)]), header->len);
        } else {
          packets += peer->process_in_packet(&(data[sizeof(reassemble_header)]), header->len);
        }
        //printf("processed %d byte packet\n", header->len);
        break;
      }
    }
    if(peer == NULL){
      printf("[[ %s -> %s ]]\n", ip2str(ntohl(header->src_ip)).c_str(), ip2str(ntohl(header->dst_ip)).c_str());
      assert(!"Our monitored BGP client is communicating with a host it wasn't configured for");
    }

    safe_free(data);
    eventsleft--;
  } while (eventsleft > 0);
  //printf("done\n");

   if(pr_time && (test_buffer == 0)){
     delta = stop_profile(start_time);

     printf("DEBUG: %u messages in %uus (%uus/message)\n", packets, delta, delta/packets);
     pr_time = 0;

     printf("DEBUG: Dumping profiler data (%d bytes)\n", len);
     write_profile("test_overlay.prf");
     printf("DEBUG: Done dumping; goodbye\n");
     exit(0);
   }
}
Minipipe *Source_Handler::get_pipe(){
  //printf("pipe:%lx\n", (unsigned long)this->pipe);
  return this->pipe;
}

void Source_Handler::print_times(){
  pr_time = 1;
}
 
void Source_Handler::set_test_buffer_limit(int test_buffer_l){
  test_buffer = test_buffer_l;
  this->print_times();
}

///////////////////////////////// END SOURCE_HANDLER

BGP_Peer::BGP_Peer(unsigned int ip_l, unsigned int port_l, unsigned int AS_l, unsigned int my_AS_l, BC_Database *indb, unsigned int ol_ip_l, unsigned int ol_port_l) {
  ip = ip_l;
  AS = AS_l;
  port = port_l;
  ol_ip = ol_ip_l;
  ol_port = ol_port_l;
  out_cursor = in_cursor = 0;
  if(indb){
    checker = new BC_Checker(indb, AS_l, ip_l, my_AS_l);
  } else {
    checker = NULL;
  }
  in_pipe = new Minipipe();
  in_pipe->set_multithreaded(0); //we're running in a single thread here...
  out_pipe = new Minipipe();
  out_pipe->set_multithreaded(0);
  dispatch = NULL;
  bgp_init_packet(&packet);
}
BGP_Peer::~BGP_Peer(){
  bgp_cleanup_packet(&packet);
  delete out_pipe;
  delete in_pipe;
  delete checker;
}

Minipipe *BGP_Peer::get_pipe(int incoming){
  return incoming?in_pipe:out_pipe;
}
PIPE_TYPE BGP_Peer::make_bgp_datasource(int incoming){
  PIPE_TYPE pipe = (PIPE_TYPE)safe_malloc(sizeof(bgp_datasource));
  assert(pipe);

  pipe->type = (typeof(pipe->type))3; //c++ doesn't want to recognize the enumerator for this...
  pipe->error = 0;
  pipe->contents.vector.bcursor = 0;
  pipe->contents.vector.cursor = incoming?in_cursor:out_cursor;
  pipe->contents.vector.blen = 
    (get_pipe(incoming))->peek(&(pipe->contents.vector.buff), 
			      &(pipe->contents.vector.len));

  return pipe;
}
void BGP_Peer::complete_bytes(int incoming, int len, PIPE_TYPE completed){
  int i = 0;
  int base_len = len;
  Minipipe *pipe = get_pipe(incoming);
  int *lens = completed->contents.vector.len;
  int cursor = incoming?in_cursor:out_cursor;

  while(len > 0){
    if(len + cursor >= lens[i]){
      len -= lens[i] - cursor;
      cursor = 0;
      i++;
    } else {
      cursor += len;
      len = 0;
    }
  }
  
  //if(i != 0)
  //printf("Completed %d bytes; cursor at %d, Dumped %d messages\n", base_len, cursor, i);

  if(i > 0){
    pipe->drop(i);
  }
  
  safe_free(completed->contents.vector.buff);
  safe_free(completed->contents.vector.len);
  safe_free(completed);

  if(incoming){
    in_cursor = cursor;
  } else {
    out_cursor = cursor;
  }
}

unsigned int BGP_Peer::process_in_packet(char *data, int len){
  PIPE_TYPE pipe;
  int r_len, t_len;
  unsigned int total_messages = 0;
  
  assert(checker);
  
  //printf("---- start incoming ----\n");
  //bgp_print_hex((unsigned char *)data, len);
  //printf("\n---- stop incoming ----\n");
  in_pipe->write(data, len);

  //printf("making datasource\n");
  pipe = make_bgp_datasource(1);
 
  t_len = 0;

  //printf("datasource made: \n");

  while(1){
    //bgp_init_packet(&packet);
    
    //Dear Oliver or anyone maintaining this code.
    //If for some reason, you get the impression that packet is leaking memory because
    //it is neither getting initialized at the start of this function nor freed at the 
    //end, YOU ARE WRONG!  Packet is a class-variable, and bgp has been optimized to
    //re-use memory allocated by previous calls.  The speedup is quite noticeable, and
    //the fact that you're not re-allocating memory is a major plus.  
    //  -Oliver
    
    //printf("reading packet\n");
    r_len = bgp_read_packet(pipe, &packet);
    //printf("done reading\n");

    //printf("read %d byte message\n", r_len);
    //bgp_print_packet(&packet);
    //assert(0);
    
    t_len += r_len;
    if(pipe->error & ~DEBUG_DATA){
      printf("Error! : %d\n", pipe->error);
      bgp_print_hex((unsigned char *)data, len);
      debug_print_state(stdout);
      assert(0);
    }
    
    if((pipe->error) || (r_len == 0)){
      break; //this just means we're out of data
    }
    
    total_messages ++;

    //printf("parsing\n");
    //bc_log_prefix("140.134.0.0", 16); //enable to get debug output on this prefix
    checker->parse_incoming(&packet);
    bc_log_prefix_end();
    if(dispatch != NULL){
      dispatch->got_packet(&packet, get_AS(), get_ip());
    }
    //bgp_cleanup_packet(&packet);
    //printf("done parsing\n");
  }  

  //printf("parsed %d messages\n", total_messages);
  complete_bytes(1, t_len, pipe); //cleans up pipe as well
  return total_messages;
}

unsigned int BGP_Peer::process_out_packet(char *data, int len){
  PIPE_TYPE pipe;
  int r_len, t_len, i;
  bgp_as_path *bgp_path;
  bgp_ipmaskvec *prefix;
  int ads;
  unsigned int total_messages = 0;
  unsigned int total_ads = 0;
  unsigned short *path;
  int error;
  
  assert(checker);

#ifdef PROFILE_OUTGOING
  struct time_t start = profile_start();;
#endif

  //printf("---- start outgoing (%d) ----\n", len);
  //bgp_print_hex((unsigned char *)data, len);
  //printf("\n---- stop outgoing ----\n");

  out_pipe->write(data, len);
  pipe = make_bgp_datasource(0);
  
  t_len = 0;

  while(1){
    //bgp_init_packet(&packet);
    r_len = bgp_read_packet(pipe, &packet);
    
    //Dear Oliver or anyone maintaining this code.
    //If for some reason, you get the impression that packet is leaking memory because
    //it is neither getting initialized at the start of this function nor freed at the 
    //end, YOU ARE WRONG!  Packet is a class-variable, and bgp has been optimized to
    //re-use memory allocated by previous calls.  The speedup is quite noticeable, and
    //the fact that you're not re-allocating memory is a major plus.  
    //  -Oliver
    
    if(pipe->error & ~DEBUG_DATA){
      printf("Error! : %d\n", pipe->error);
      bgp_print_hex((unsigned char *)data, len);
      debug_print_state(stdout);
      assert(0);
    }
    
    t_len += r_len;
    if(pipe->error || (r_len == 0)){
      //bgp_cleanup_packet(&packet);
      break; //this just means we're out of data
    }

    if(packet.type != 2) { //we don't care about non-updates
      //bgp_cleanup_packet(&packet);
      continue;
    }

    if(dispatch != NULL){
      dispatch->sent_packet(&packet, get_AS(), get_ip());
    }
    
    if((error = checker->load_packet(&packet)) < 0){
      
      //If this returns an error, then there's some kind of problem with the AS_PATH.
      //It means all the adverts in this path are bad.
      bgp_print_packet(&packet);
      printf("AS_PATH formatting error in packet:%d\n", error);
      bgp_print_ip(get_ip()); printf(" ( AS %d )\n", get_AS());

      //bgp_print_packet(&packet);

      while(checker->ads_remaining() > 0){
        dispatch->report_ad(checker->last_prefix(), checker->last_prefix_len(), packet.contents.UPDATE.as_path);
        
        checker->skip_next_ad();
      }
      checker->finish_packet();
      assert(0);
    } else {
      ads = 0;
      total_messages ++;
      while(checker->ads_remaining() > 0){
        total_ads ++;
        ads ++;
        if((error = checker->check_next_ad())){
          if(error > 0){ //policy violation
            printf("Policy violation: Rule %d (Sending to : ", error);bgp_print_ip(get_ip());printf(")\n");
            if(dispatch)
              dispatch->report_policy(&packet, ads, error);
          } else { //safety violationi = 0;
            printf("Safety violation: Rule %d (Sending to : ", -error);bgp_print_ip(get_ip());printf(")\n");
            if(dispatch)
              dispatch->report_ad(checker->last_prefix(), checker->last_prefix_len(), packet.contents.UPDATE.as_path);
          }
          if(1){ //debugging.
            checker->print_path();
            checker->print_potentials();
            bgp_print_packet(&packet);
            assert(0);
          }
        }
      }
    }

    checker->finish_packet();
  }
  
  complete_bytes(0, t_len, pipe);//cleans up after pipe

#ifdef PROFILE_OUTGOING
  profile_count += total_messages;
  profile_time += stop_profile(start);
  profile_ads += total_ads;
    
  if(profile_count >= PROFILE_PCAP){
    printf("%u messages (%u ads) processed in %uus: %uus/message, %uus/ad\n", profile_count, proile_ads, profile_time, (profile_time/profile_count));
    profile_write("nbgp_profiler.out");
    profile_count = 0;
    profile_time = 0;
  }
#endif

  return total_messages;
}
unsigned int BGP_Peer::get_port(){
  return port;
}
unsigned int BGP_Peer::get_ip(){
  return ip;
}
unsigned int BGP_Peer::get_ol_port(){
  return ol_port;
}
unsigned int BGP_Peer::get_ol_ip(){
  return ol_ip;
}
unsigned int BGP_Peer::get_AS(){
  return AS;
}
BC_Checker *BGP_Peer::get_checker(){
  return checker;
}
void BGP_Peer::set_dispatcher(BGP_Dispatcher *_dispatch){
  dispatch = _dispatch;
}

///////////////////////////// BGP_INTERPOSITION_AGENT

BGP_Interposition_Agent::BGP_Interposition_Agent(BGP_Peer *_peer) :
  peer_mon(NULL), router_mon(NULL),
  peer_in(NULL), peer_out(NULL), router_in(NULL), router_out(NULL),
  peer(_peer) { }

void BGP_Interposition_Agent::set_peer_streams(Minipipe *in, Minipipe *out, Runtime *r){
  assert(peer_mon == NULL);
  
  peer_in = in;
  peer_out = out;
  peer_mon = new BGP_Interposition_Agent::Stream_Monitor(in, 0, this);
  r->register_handler(peer_mon);
}
void BGP_Interposition_Agent::set_router_streams(Minipipe *in, Minipipe *out, Runtime *r){
  assert(router_mon == NULL);
  
  router_in = in;
  router_out = out;
  router_mon = new BGP_Interposition_Agent::Stream_Monitor(in, 1, this);
  r->register_handler(router_mon);
}

void BGP_Interposition_Agent::peer_packet(){
  char *packet;
  int len, cnt;
  
  len = peer_in->read(&packet);
  
  //XXX should just block the packet(s) or kill the connection.
  //For testing purposes, we just blow up.
  debug_start_timing("INCOMING");
  assert((cnt = peer->process_in_packet(packet, len)) >= 0); 
  debug_stop_timing("INCOMING", cnt);
  
  if(router_out){
    router_out->write_malloced(packet, len);
  } else {
    free(packet);
  }
}
void BGP_Interposition_Agent::router_packet(){
  char *packet;
  int len, cnt;
  
  len = router_in->read(&packet);
  
  //XXX should just block the packet(s) or kill the connection.
  //For testing purposes, we just blow up.
  debug_start_timing("OUTGOING");
  assert((cnt = peer->process_out_packet(packet, len)) >= 0); 
  debug_stop_timing("OUTGOING", cnt);
  
  if(peer_out){
    peer_out->write_malloced(packet, len);
  } else {
    free(packet);
  }
}

BGP_Interposition_Agent::Stream_Monitor::Stream_Monitor(Minipipe *pipe, int _direction, BGP_Interposition_Agent *_parent) :
  Runtime_Handler(-1, pipe, "BGP_Interposition_Agent"), parent(_parent), direction(_direction) {}

void BGP_Interposition_Agent::Stream_Monitor::handle_minipipe(Minipipe *pipe, Runtime *runtime){
  if(direction) parent->router_packet();
  else          parent->peer_packet();
}

int accept_socket(unsigned short port){
  int serv, client;
  struct sockaddr_in saddr, caddr;
  int len;
  
  serv = socket(AF_INET, SOCK_STREAM, 0);
	
  if(serv < 0){
    perror("Error: Unable to initialize server socket");
    exit(1);
  }
	
  int one = 1;
	
  bzero((char *)&saddr, sizeof(struct sockaddr_in));
  saddr.sin_addr.s_addr = INADDR_ANY;
  saddr.sin_port = htons(port);
  saddr.sin_family = AF_INET;
	
  if(bind(serv, (struct sockaddr *)&saddr, sizeof(struct sockaddr_in)) < 0){
    perror("Error: Unable to bind socket");
      return -1;
  }
	
  if(listen(serv, 1) < 0){
    perror("Error: Unable to configure server socket for listening");
      return -1;
  }
  
  printf("waiting for incoming\n");
  len = sizeof(struct sockaddr_in);
  while((client = accept(serv, (struct sockaddr *)&caddr, (socklen_t *)&len)) < 0){
    if(errno != EAGAIN){
      perror("Error: Failed to accept\n");
      return -1;
    }
  }
  printf("connected incoming: "); print_ip(caddr.sin_addr.s_addr, 1); printf(":%d\n", ntohs(caddr.sin_port));
  
  return client;
}

int connect_socket(unsigned int ip, unsigned short port){
  int client;
  struct sockaddr_in caddr;
  int len;
  
  client = socket(AF_INET, SOCK_STREAM, 0);
  
  bzero((char *)&caddr, sizeof(struct sockaddr_in));
  caddr.sin_addr.s_addr = ip;
  caddr.sin_port = htons(port);
  caddr.sin_family = AF_INET;
  
  printf("connecting outgoing: "); print_ip(caddr.sin_addr.s_addr, 1); printf(":%d\n", ntohs(caddr.sin_port));
  if(connect(client, (struct sockaddr *)&caddr, sizeof(struct sockaddr_in)) < 0){
    perror("Error: Unable to connect socket");
      return -1;
  }
  
  return client;
}


BGP_Interposition_SimpleSocket::BGP_Interposition_SimpleSocket(BGP_Peer *_peer, unsigned short port, unsigned int target, unsigned int target_port, Runtime *r):
  BGP_Interposition_Agent(_peer), bgp_peer(NULL), bgp_router(NULL) 
{
  int sock;
  
  assert((sock = accept_socket(port)) >= 0);
  bgp_router = new Pipedsocket(sock);
  set_router_streams(bgp_router->read_pipe(), bgp_router->write_pipe(), r);
  
  assert((sock = connect_socket(target, target_port)) >= 0);
  bgp_peer = new Pipedsocket(sock);
  set_peer_streams(bgp_peer->read_pipe(), bgp_peer->write_pipe(), r);
  
  //the subsequent calls rev up the threads that read from the sockets.
  //consequently, we need the pipes all installed and ready to go, or else we might
  //miss some packets.
  bgp_router->initialize_all();
  bgp_peer->initialize_all();
}

