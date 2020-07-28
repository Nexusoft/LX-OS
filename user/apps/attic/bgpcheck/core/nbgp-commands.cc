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
#include "../include/nbgp/testsuite.h"
#include "../include/util/debug.h"

/////////////////////////////////////// Compile Options

#define ENABLE_NBGP_DEBUG

/////////////////////////////////////// Globals

static int nbgp_commands_inited = 0;
static Ghetto_Vector *bgp_peers;
static BGP_Dispatcher *dispatch;
static BC_Database *indb;
static Runtime *runtime;
static Grassroots *grassrootsdb;
static Overlay_Server_Handler *overlay;
static unsigned short my_as = 0;
static unsigned int my_ip = 0;
static unsigned short my_port = 0;
static unsigned int debug_mode = 0;
static unsigned int debug_peer = 0;
static unsigned int debug_size = 0;

/////////////////////////////////////// Utility Functions

static char *make_gcap_filter(){
  char *filter;
  int c;
  BGP_Peer *peer;
  
  filter = NULL;
  for(c = 0; c < (int)bgp_peers->size(); c++){
    peer = (BGP_Peer *)bgp_peers->at(c);
    
    filter = gcap_addfilter(filter, peer->get_ip(), peer->get_port());
  }
  filter = gcap_addfilter(filter, ntohl(my_ip), 179);
  return filter;
}

class Grassroots_Periodic_Saver : public Runtime_Handler {
 public: //period is in msec
  Grassroots_Periodic_Saver(int _period, Grassroots *_gr, char *_savefile) : 
    Runtime_Handler(_period, NULL, "Grassroots_Periodic_Saver"),
    period(_period), gr(_gr), savefile(_savefile)
  {
    set_priority(0); //don't prempt anything else to save
  }
  
  virtual int handle_periodic(Runtime *runtime){
    gr->export_db_if_changed(savefile);
    return period;
  }
 private:
  int period;
  Grassroots *gr;
  char *savefile;
};

/////////////////////////////////////// Command Definitions

CMD_DEFUN(host){
  CMD_ARG_STR(prefix);
  CMD_ARG_INT(len);
  
  if(prefix == NULL){ return "'host' requirs a 'prefix' parameter"; }
  if(len == 0){ return "'host' requirs a 'len' parameter"; }
  if(my_as == 0){ return "'host' requires a previous 'monitor' statement"; }
  
  unsigned int prefix_n = inet_addr(prefix);
  unsigned int prefix_h = ntohl(prefix_n);
  
  BC_Advertisement *ad = new BC_Advertisement();
  ad->as_id = my_as;
  ad->as_ip = my_ip;
    
  indb->install(ad, prefix_h, len);
  
  return NULL;
}

CMD_DEFUN(peer){
  CMD_ARG_STR(ip);
  CMD_ARG_INT(port);
  CMD_ARG_INT(as);
  CMD_ARG_STR(ol_ip);
  CMD_ARG_INT(ol_port);
  BGP_Peer *tmp;
  
  if(ip == NULL){ return "'peer' requirs an 'ip' parameter"; }
  if(as == 0){ return "'peer' requires an 'as' parameter"; }
  if(my_as == 0){ return "'peer' requires a previous 'monitor' statement"; }
  if(ol_ip && !overlay){ return "'peer' requires a previous 'overlay' statement if an overlay ip has been specified"; }
  if(port == 0){ port = 179; }
  if(ol_port == 0){ ol_port = 52982; }
  
  tmp = new BGP_Peer(ntohl(inet_addr(ip)), port, as, my_as, indb, ol_ip?inet_addr(ol_ip):0, ol_port);
  bgp_peers->push_back(tmp);
  tmp->set_dispatcher(dispatch);
  
  //XXX this should be in a config file
  NBGP_Policy *policy;
  if((policy = fake_policy())){
    tmp->get_checker()->set_policy(policy);
  }
  
  printf("Loaded Peer: %s:%d (as %d)\n", ip, port, as);
  
  if(ol_ip){
    overlay->add_peer(tmp);
    printf("  ... and set up an overlay connection\n");
  }
  
  return NULL;
}

CMD_DEFUN(monitor){
  CMD_ARG_STR(ip);
  CMD_ARG_INT(port);
  CMD_ARG_INT(as);
  
  if(ip == NULL){ return "'monitor' requirs an 'ip' parameter"; }
  if(as == 0){ return "'monitor' requires an 'as' parameter"; }
  if(my_as != 0){ return "Only one 'monitor' statement may be present in an initialization script"; }
  
  my_ip = inet_addr(ip);
  my_as = as;
  my_port = port;
  
  printf("Monitoring Host: %s:%d (as %d)\n", ip, port, as);
  
  return NULL;
}

CMD_DEFUN(preload){
  CMD_ARG_STR(mrt);
  if(my_as == 0){ return "'preload' requires a prior 'monitor' statement"; }
  
  if(mrt){
    mrt_preload(inet_addr(mrt), 4129, indb, my_as);
  }
  return NULL;
}

CMD_DEFUN(capture){
  CMD_ARG_NULL(sniffer); //sniffer mode.
  CMD_ARG_NULL(interpose); //interposition mode
  CMD_ARG_STR(remote); //debug mode 1: connect to a remote sniffer
  CMD_ARG_STR(peer); //debug mode 2: connect directly as a bgp peer
  CMD_ARG_NULL(bidirectional);
  CMD_ARG_INT(port);
  CMD_ARG_STR(file);
  CMD_ARG_STR(gr_file);
  CMD_ARG_STR(mrt);
  CMD_ARG_STR(mrt_socket);
  Minipipe *sourcePipe;
  Source_Handler *source;
  
  if(sniffer){
    reassemble_params *pcap_params = (reassemble_params *)malloc(sizeof(reassemble_params));
    pthread_t pcap_thread;
    sourcePipe = new Minipipe();
    
    //set up processing
    source = new Source_Handler(bgp_peers, ntohl(my_ip), my_as, sourcePipe);
    runtime->register_handler(source);
    
    //set up the capture
    pcap_params->pipe = sourcePipe;
    pcap_params->filter = make_gcap_filter();
    pcap_params->device = NULL;
    pthread_create(&pcap_thread, NULL, (void *(*)(void *))&reassemble_main, pcap_params);
  } else if(interpose){ 
    printf("Waiting for server connection!\n");
    //XXX placeholder code
    bgp_peers->iterator_reset();
    BGP_Peer *peer = (BGP_Peer *)bgp_peers->iterator_next();
    
    BGP_Interposition_SimpleSocket *interposer = 
      new BGP_Interposition_SimpleSocket(peer, 2000, htonl(peer->get_ip()), 179, runtime);
  }
#ifdef ENABLE_NBGP_DEBUG
  else if(remote){
    //Minisockets create their own threads.  Setting up the Source Handler with the minisocket's pipe will
    //register the minisocket's pipe with the runtime handler, and since no writing is required, we don't need
    //to register the minisocket.
    if(port == 0){ port = 2001; }
    Minisocket *remote_sniffer = new Minisocket(inet_addr(remote), port, NULL, NULL, 0);
    sourcePipe = remote_sniffer->read_pipe();
    source = new Source_Handler(bgp_peers, ntohl(my_ip), my_as, sourcePipe);
    runtime->register_handler(source);
  } else if(peer){
    pthread_t pcap_thread;
    sourcePipe = new Minipipe();
    
    //set up processing
    source = new Source_Handler(bgp_peers, ntohl(my_ip), my_as, sourcePipe);
    runtime->register_handler(source);
    
    //set up the capture
    debug_peer = 0;
    debug_mode = bidirectional;
    debug_size = (10 * 1000 * 1000);
    pthread_create(&pcap_thread, NULL, (void *(*)(void *))&fake_capture, 
      new Fake_Capture_Info(
        sourcePipe, debug_peer, my_ip, debug_mode, debug_size
    ));
  } else if(file) {
    if(gr_file) {
      if(!overlay){ return "the 'gr_file' option requires a prior 'overlay' statement"; }
      Overlay_Peer_Handler *peer = new Overlay_Peer_Handler(overlay);
      runtime->register_handler(peer);
      peer->set_minipipe(file_pipe(gr_file, 50, 10));
    }
    sourcePipe = file_pipe(file, 50, 10); //50 +/-5 sec between messages
    source = new Source_Handler(bgp_peers, ntohl(my_ip), my_as, sourcePipe);
    runtime->register_handler(source);
  } else if(mrt){
    int input;
    input = open(mrt, O_RDONLY);
    if(input < 0){ return "Error opening MRT file"; }
    MRTStream *stream = new MRTStream(input, bgp_peers, my_as, runtime);
    if(grassrootsdb) stream->set_grassroots(grassrootsdb);
    if(indb) stream->set_indb(indb);
    runtime->register_handler(stream);
    stream->start();
  } else if(mrt_socket) {
    MRTStream *stream = new MRTStream(inet_addr(mrt_socket), 4129, bgp_peers, my_as, runtime);
    if(grassrootsdb) stream->set_grassroots(grassrootsdb);
    if(indb) stream->set_indb(indb);
    runtime->register_handler(stream);
    stream->start();
//    Overlay_Peer_Handler *peer = new Overlay_Peer_Handler(overlay);
//    runtime->register_handler(peer);
//    stream->set_test_peer(peer);
  } else {
    return "'capture' requires an argument";
  }
#else //ifdef ENABLE_NBGP_DEBUG
  else {
    return "debugging capture modes are not available in release builds\n";
  }
#endif //ifdef ENABLE_NBGP_DEBUG

  return NULL;
}

CMD_DEFUN(grassroots){
  CMD_ARG_STR(db);
  CMD_ARG_INT(save_every);
  
  if(db == NULL) { return "'grassroots' requires a 'db' parameter"; }
  if(my_as == 0) { return "'grassroots' requires a prior 'monitor' statment"; }
  
  printf("Initializing Grassroots database\n");
  grassrootsdb = new Grassroots(my_as);
  grassrootsdb->bootstrap(); //XXX try to load a save file if possible first.
  dispatch->set_grassroots(grassrootsdb);
  
  printf("Loading Grassroots DB from saved file at %s\n", db);
  
//  Profile_Enable(1);
  //XXX validating is somewhat slow.  We can test this separately.
  grassrootsdb->import_db_novalidate(db);
//  Profile_Enable(0);
//  write_profile("/nfs/grassroots.profile");
//  assert(0);

  if(save_every){
    printf("Saving Grassroots DB every %d msec\n", save_every);
    Grassroots_Periodic_Saver *saver = new Grassroots_Periodic_Saver(save_every, grassrootsdb, "/nfs/temp_grassroots.db");
    runtime->register_handler(saver);
  }
  return NULL;
}

CMD_DEFUN(overlay){
  CMD_ARG_STR(ip);
  CMD_ARG_INT(port);
  
  if(ip == NULL){ return "'overlay' requirs an 'ip' parameter"; }
  if(my_as == 0){ return "'overlay' requires a previous 'monitor' statement"; }
  if(port == 0){ port = 52982; }
  
  overlay = new Overlay_Server_Handler(my_as, inet_addr(ip), port);
  overlay->set_dispatcher(dispatch);
  runtime->register_handler(overlay);
  
  return NULL;
}

CMD_DEFUN(log){
  CMD_ARG_STR(file);
  CMD_ARG_STR(debug);
  
  if((file == NULL)&&(debug == NULL)){ return "'log' requirs a 'file' or a 'debug' parameter"; }
  
  if(file){
    dispatch->start_logging(file);
  }
  if(debug){
    enable_debug();
    debug_open_logset(debug);
  }
  return NULL;
}

CMD_DEFUN(policy){
  return NULL;  
}

/////////////////////////////////////// External Interface

void nbgp_monitor_loop(){
  runtime->start_runtime();
}

void install_nbgp_commands(Command_List *cmds){
  //initialize variables;
  if(!nbgp_commands_inited){
    init_minisocket();
    runtime = new Runtime();
    bgp_peers = new Ghetto_Vector(10);
    dispatch = new BGP_Dispatcher(runtime);
    indb = new BC_Database();
    dispatch->set_incoming_db(indb);
    grassrootsdb = NULL;
    overlay = NULL;
    nbgp_commands_inited = 1;
  }

  CMD_INSTALL(host);
    CMD_OPTION_STR(prefix);
    CMD_OPTION_INT(len);
  CMD_END();

  CMD_INSTALL(monitor);
    CMD_OPTION_STR(ip);
    CMD_OPTION_INT(port);
    CMD_OPTION_INT(as);
  CMD_END();
  
  CMD_INSTALL(peer);
    CMD_OPTION_STR(ip);
    CMD_OPTION_INT(port);
    CMD_OPTION_INT(as);
    CMD_OPTION_STR(ol_ip);
    CMD_OPTION_INT(ol_port);
  CMD_END();
  
  CMD_INSTALL(overlay);
    CMD_OPTION_STR(ip);
    CMD_OPTION_INT(port);
  CMD_END();
  
  CMD_INSTALL(preload);
    CMD_OPTION_STR(mrt);
  CMD_END();
  
  CMD_INSTALL(capture);
    CMD_OPTION_NULL(sniffer);       //sniffer mode.
    CMD_OPTION_NULL(interpose);
    CMD_OPTION_STR(remote);         //debug mode 1: connect to a remote sniffer
    CMD_OPTION_INT(port);
    CMD_OPTION_STR(peer);           //debug mode 2: connect directly as a bgp peer
    CMD_OPTION_NULL(bidirectional); //option for debug mode 2.  Reads
    CMD_OPTION_STR(file);           //debug mode 3: read from a file generated by bgpdump's -w
    CMD_OPTION_STR(gr_file);        //when in debug mode 3/4, also read grassroots data from bgpdump's -x
    CMD_OPTION_STR(mrt);            //debug mode 4: read a routeviews MRT file directly
    CMD_OPTION_STR(mrt_socket);
  CMD_END();
  
  CMD_INSTALL(grassroots);  
    CMD_OPTION_STR(db);
    CMD_OPTION_INT(save_every);
  CMD_END();
  
  CMD_INSTALL(log);
    CMD_OPTION_STR(file);
    CMD_OPTION_STR(debug);
  CMD_END();
  
  CMD_INSTALL(policy);
  CMD_END();
}
