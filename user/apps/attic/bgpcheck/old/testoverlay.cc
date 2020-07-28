#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <assert.h>
#include "common.h"
#include "tunnel.h"
#include "proxycapture.h"
#include "test_handler.h"
#include "bgpcheck.h"

#define BREAKPOINT() asm("   int $3");

#define AIWENDIL_IP "128.84.227.43"
#define AIWENDIL_PORT 179
#define AIWENDIL_AS 180
#define AIWENDIL2_IP AIWENDIL_IP
#define AIWENDIL2_PORT 180
#define AIWENDIL3_IP AIWENDIL_IP
#define AIWENDIL3_PORT 181

#define CISCO_IP "128.84.227.28"
#define CISCO_AS 5040
#define LOKI_IP "128.84.227.47"
//peer 62.18.14.250
#define LOKI_AS 7018
#define PARIS_IP "128.84.227.54"
#define PARIS_AS 1706

//#define MY_IP LOKI_IP
//#define MY_AS LOKI_AS

//#define MY_IP CISCO_IP
//#define MY_AS CISCO_AS

//#define SOURCE_NLR
#ifndef SOURCE_NLR
#define FAKE_PEERS { "12.0.1.63",		\
      "129.250.0.11",				\
      "134.222.86.174",				\
      "137.164.16.12",				\
      "144.228.241.81",				\
      "147.28.7.1",				\
      "154.11.11.113",				\
      "157.130.10.233",				\
      "164.128.32.11",				\
      "167.142.3.6",				\
      "192.203.116.253",			\
      "192.5.4.246",				\
      "193.251.245.6",				\
      "194.85.4.55",				\
      "195.219.96.239",				\
      "195.22.216.188",				\
      "196.13.250.1",				\
      "196.7.106.245",				\
      "198.32.8.196",				\
      "202.232.0.3",				\
      "203.181.248.168",			\
      "203.62.252.26",				\
      "205.241.232.55",				\
      "206.186.255.223",			\
      "206.24.210.99",				\
      "207.45.223.244",				\
      "208.51.134.246",				\
      "208.51.134.253",				\
      "209.123.12.51",				\
      "209.161.175.4",				\
      "213.140.32.148",				\
      "213.200.87.254",				\
      "213.248.83.252",				\
      "216.18.31.102",				\
      "216.218.252.145",			\
      "217.75.96.60",				\
      "62.18.14.252",				\
      "62.72.136.2",				\
      "66.185.128.1",				\
      "81.209.156.1",				\
      }
#define FAKE_ASES  { 7018,			\
      2914,					\
      286,					\
      2152,					\
      1239,					\
      3130,					\
      852,					\
      701,					\
      3303,					\
      5056,					\
      22388,					\
      3557,					\
      5511,					\
      3277,					\
      6453,					\
      6762,					\
      2018,					\
      2905,					\
      11537,					\
      2497,					\
      7660,					\
      1221,					\
      11686,					\
      2493,					\
      3561,					\
      6453,					\
      3549,					\
      3549,					\
      8001,					\
      14608,					\
      12956,					\
      3257,					\
      1299,					\
      6539,					\
      6939,					\
      16150,					\
      12682,					\
      5413,					\
      1668,					\
      13237,					\
      }
#else
#define MY_IP "216.24.191.226"
#define MY_AS 19401
#define FAKE_PEERS { "216.24.191.225",		\
 	       "216.24.191.230",			\
 	       "216.24.191.224",			\
 	       "216.24.191.229",			\
 	       "216.24.191.228",			\
 	       "216.24.191.231",			\
 	       "216.24.191.227",			\
 	       "129.24.198.105",			\
 	       "192.43.217.137",			\
 	       }
 #define FAKE_ASES  { 19401,			\
 	       19401,				\
 	       19401,				\
 	       19401,				\
 	       19401,				\
 	       19401,				\
 	       19401,				\
 	       3388,				\
 	       14041,				\
 	       }
#endif

#define FAKE_PEER_COUNT (sizeof(fake_peer_ips)/sizeof(fake_peer_ips[1]))

#define NBGP_OVERLAY_PORT 52982

//#define START_OVERLAY 1
#define START_CAPTURE 1
//#define START_TUNNEL 1
#define FAKE_CAPTURE "128.84.227.47"
//#define START_POLICY 1
//#define REMOTE_SNIFFER "128.84.227.47"
//#define START_GDB_SERVER

#define FAKE_SNIFFED_PEER "12.0.1.63"
#define MY_AS 7018
#define MY_IP "128.84.227.47"

//only uncomment one of the following at a time
// the value of the parameters below is how much data to buffer before timing
#define TIME_PROCESS_IN (10 * 1000 * 1000)
//#define TIME_PROCESS_OUT (10 * 1000 * 1000)
//#define TIME_RVQ_OUT 1
//#define TIME_WARNING_OUT 1000
// the value of the parameters below is how many seconds to wait to trigger
//#define CALCULATE_DB_SIZE (10 * 60)

#include "ghetto_pcap.h"
#include "nbgp.h"
#include "reassemble.h"

#ifdef TIME_WARNING_OUT
#define TIME_RVQ_OUT TIME_WARNING_OUT
#endif

#ifdef TIME_PROCESS_OUT
#define TIME_PROCESS_IN (-TIME_PROCESS_OUT)
#endif


#ifdef FAKE_CAPTURE

void fake_capture(Minipipe *pipe){
  int sock;
  struct sockaddr_in saddr;
  char full_buff[5220+sizeof(int)+sizeof(Flow)];
  Flow *flow = (Flow *)&full_buff;
  int *len = (int *)&(full_buff[sizeof(Flow)]);
  char *buff = &(full_buff[sizeof(Flow)+sizeof(int)]);
#ifdef TIME_PROCESS_OUT
  Minipipe *p2 = new Minipipe();
#endif
  int bytes_read = 0;
  char *tmp;
  int tmplen;

  assert((sock = socket(PF_INET, SOCK_STREAM, 0)) >= 0);
  saddr.sin_family = AF_INET;
  saddr.sin_addr.s_addr = inet_addr(FAKE_CAPTURE);
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

      flow->from.addr.s_addr = inet_addr(FAKE_SNIFFED_PEER);
      flow->to.addr = saddr.sin_addr;
      pipe->write(full_buff, sizeof(Flow) + sizeof(int) + *len);

#ifdef TIME_PROCESS_OUT

       flow->from.addr = saddr.sin_addr;
       flow->to.addr.s_addr = inet_addr(FAKE_SNIFFED_PEER);
       p2->write(full_buff, sizeof(Flow) + sizeof(int) + *len);

       if(bytes_read > TIME_PROCESS_OUT){
         printf("Fake spoofer switching to outgoing packets: %d bytes (%d chunks)\n", bytes_read, p2->get_count());
         bytes_read = 0;
         while(p2->get_count() > 0){
           tmplen = p2->read(&tmp);
           pipe->write_malloced(tmp, tmplen);
         }
         return;
       }
#else
#ifdef TIME_PROCESS_IN
       if(bytes_read > TIME_PROCESS_IN){
         return;
       }
#endif
#endif
    }
  }
}

#endif

NBGP_Policy_Line *prefix_spec_needs_comm(char *prefix, unsigned short len, int num){
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

NBGP_Policy *load_policy(){
  NBGP_Policy *p = new NBGP_Policy();
  NBGP_Policy_Line *l;
  NBGP_AS_Policy_Set *as;
  Policy_Filter *fa, *fb, *fc;
  Policy_Action act;
  
  // ---- EXPORT ----
  l = new NBGP_Policy_Line();
  p->add_export(l);

  fa = new Policy_Filter();
  fa->type = FILTER_ANY;
  l->set_filter(fa);
  
  as = new NBGP_AS_Policy_Set();
  as->flags = NBGP_AS_ANY;
  l->add_as(as);
  
  // ---- IMPORT ----
  p->add_import(prefix_spec_needs_comm("140.45.0.0", 16, 1));
  p->add_import(prefix_spec_needs_comm("80.246.0.0", 20, 2));
  p->add_import(prefix_spec_needs_comm("140.35.0.0", 16, 3));
  p->add_import(prefix_spec_needs_comm("140.32.0.0", 16, 4));
  p->add_import(prefix_spec_needs_comm("140.31.0.0", 16, 5));
  p->add_import(prefix_spec_needs_comm("139.229.0.0", 16, 6));
  p->add_import(prefix_spec_needs_comm("139.225.0.0", 16, 7));
  p->add_import(prefix_spec_needs_comm("139.223.0.0", 16, 8));
  p->add_import(prefix_spec_needs_comm("139.222.0.0", 16, 9));
  p->add_import(prefix_spec_needs_comm("139.191.0.0", 16, 10));
 
  return p;
}

extern void tunnel_data(Tunnel *t, unsigned int sender, void *data, int datalen);
extern void tunnel_poll(Tunnel *t);
extern "C" {
extern void init_gdb_remote(int port, int activate);
}

#ifdef START_GDB_SERVER
int gdb_server_ready = 0;

void debug_main(void *dummy){
  init_gdb_remote(2000, 0);
  gdb_server_ready = 1;
  while(1);
}
#endif

int main(){
  printf("Entering main!\n");

  Runtime *runtime = new Runtime();
  Overlay_Server_Handler *server = NULL;
  BGP_Peer *loki1, *loki2, *cisco, *peer, *paris, *temp, *o_peer;
  Ghetto_Vector *bgp_peers = new Ghetto_Vector(10);
  char *filter;
  int c;
  pthread_t pcap_thread, tunnel1_t, tunnel2_t;
  pthread_attr_t pcap_thread_attr;
  reassemble_params *pcap_params;
  BGP_Dispatcher *dispatch = new BGP_Dispatcher();
  BC_Database *outdb = new BC_Database();
  char *fake_peer_ips[] = FAKE_PEERS;
  unsigned short fake_peer_as[] = FAKE_ASES;
  NBGP_Policy *policy = NULL;
#ifdef START_GDB_SERVER
  pthread_t debug_thread;
  pthread_create(&debug_thread, NULL, (void *(*)(void *))&debug_main, NULL);
  while(!gdb_server_ready);
  printf("break!");
  char *boom = NULL;
  (*boom) = 0;
#endif

  dispatch->set_router(inet_addr("128.84.227.47"), "supersecret", "admin", 19401);

  printf("Initializing debugger\n");

  printf("Initializing minisocket SSL\n");

  init_minisocket();
  
#ifdef START_POLICY
  printf("Preparing Policies\n");

  policy = load_policy();
#endif

  printf("Loading peers\n");

  //Define the port/addy pairs in the system (Peers/etc...)
  //this should eventually be replaced by a config file
  o_peer = new BGP_Peer(inet_addr("128.84.227.43"), NBGP_OVERLAY_PORT, AIWENDIL_AS, MY_AS);
  loki2 = new BGP_Peer(ntohl(inet_addr(LOKI_IP)), 180, LOKI_AS, MY_AS);
  //  loki1 = new BGP_Peer(ntohl(inet_addr(LOKI_IP)), 179, LOKI_AS, MY_AS);
  cisco = new BGP_Peer(ntohl(inet_addr(CISCO_IP)), 179, CISCO_AS, MY_AS);
  paris = new BGP_Peer(ntohl(inet_addr(PARIS_IP)), 179, PARIS_AS, MY_AS);
  //bgp_peers->push_back(loki1);
  //  loki1->set_dispatcher(dispatch);
  if(policy != NULL){
    loki2->get_checker()->set_policy(policy);
  }
  bgp_peers->push_back(loki2);
  loki2->set_dispatcher(dispatch);
  //bgp_peers->push_back(paris);
  //paris->set_dispatcher(dispatch);

  for(c = 0; c < FAKE_PEER_COUNT; c++){
    temp = new BGP_Peer(ntohl(inet_addr(fake_peer_ips[c])), 179, fake_peer_as[c], MY_AS);
    //print_ip(temp->get_ip(), 0); printf(":%d\n", 179);
    if(policy != NULL){
      temp->get_checker()->set_policy(policy);
    }
    bgp_peers->push_back(temp);
    //printf("Size up to %d\n", bgp_peers->size());
    temp->set_dispatcher(dispatch);
  }

  printf("%d peers loaded\n", bgp_peers->size());
  
  c = 0;

  //Overlay Server

#ifdef START_OVERLAY
  //the dispatcher expects an overlay, and the capture system expects a
  //dispatcher.  If we don't register the server with the handler 
  //or register any peers with the server, it won't do anything.
  server = new Overlay_Server_Handler(MY_AS, inet_addr(MY_IP), NBGP_OVERLAY_PORT);
  runtime->register_handler(server);
  server->add_peer(o_peer);
  dispatch->set_overlay(server);

#endif

  //dispatch->set_outgoing_db(outdb);
  
  //GCap Filter
  filter = NULL;
  for(c = 0; c < (int)bgp_peers->size(); c++){
    peer = (BGP_Peer *)bgp_peers->at(c);
    
    filter = gcap_addfilter(filter, peer->get_ip(), peer->get_port());
  }
  filter = gcap_addfilter(filter, ntohl(inet_addr(MY_IP)), 179);

#ifdef START_CAPTURE
  //Data Handler
#ifdef REMOTE_SNIFFER
  Minisocket *remote_sniffer = new Minisocket(inet_addr(REMOTE_SNIFFER), 179, NULL, NULL, 0);
  Minipipe *sourcePipe = remote_sniffer->read_pipe();
#else
  Minipipe *sourcePipe = new Minipipe();
#endif
  Source_Handler *source = new Source_Handler(bgp_peers, ntohl(inet_addr(MY_IP)), MY_AS, sourcePipe);
  runtime->register_handler(source);

#ifdef CALCULATE_DB_SIZE
  runtime->register_handler(new Test_Handler(((BGP_Peer *)bgp_peers->at(0))->get_checker(), sourcePipe, CALCULATE_DB_SIZE * 1000));
#endif

#ifdef TIME_PROCESS_IN
  source->set_test_buffer_limit(TIME_PROCESS_IN);
#endif

  //we've got this little bit here to simplify testing.  Rather than using
  //a 2nd thread to capture data via the sniffer, we can just capture a live
  //feed from some source (for example the oix burst app)

#ifdef FAKE_CAPTURE
  pthread_create(&pcap_thread, NULL, (void *(*)(void *))&fake_capture, sourcePipe); 
#else //FAKE_CAPTURE

#ifdef START_TUNNEL
  
  Tunnel *t1 = new Tunnel();
  t1->set_peer1(inet_addr(LOKI_IP), 179);
  t1->set_peer2(inet_addr(LOKI_IP), 180);
  t1->set_self(179);

  t1->set_userdata(loki2);
//   t1->set_userdata(sourcePipe);

  t1->set_callback(&tunnel_data);

  pthread_create(&tunnel1_t, NULL, (void*(*)(void*))&tunnel_poll, t1);

#else 

#ifndef REMOTE_SNIFFER
  //Capture thread
  pcap_params = (reassemble_params *)malloc(sizeof(reassemble_params));
  pcap_params->pipe = sourcePipe;
  pcap_params->filter = filter;
  pcap_params->device = NULL;
  pthread_attr_init(&pcap_thread_attr);
  pthread_create(&pcap_thread, &pcap_thread_attr, (void *(*)(void *))&reassemble_main, pcap_params);

#endif //ndef REMOTE_SNIFFER

#endif //START_TUNNEL
#endif //FAKE_CAPTURE
#endif //START_CAPTURE

#ifdef TIME_RVQ_OUT
  server->test_rvq_out(TIME_RVQ_OUT);
#endif

  printf("----- STARTING SCAN -----\n");

  runtime->start_runtime(); //this doesn't return

  return 0;
}

