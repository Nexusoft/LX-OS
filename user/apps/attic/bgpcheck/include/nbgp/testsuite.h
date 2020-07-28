#ifndef NBGP_TESTSUITE_H_SHIELD
#define NBGP_TESTSUITE_H_SHIELD

#include "../nbgp/bgpcheck.h"
#include "../util/filebuffer.h"
#include "../runtime/runtime.h"
#include "../runtime/pipedsocket.h"

#pragma pack(push, 1)
struct mrt_msg_hdr {
   time_t tstamp;		/* timestamp */
   u_short type;		/* msg type, one of MRT_MSG_TYPES */
   u_short subtype;		/* msg subtype, protocol-specific */
   u_long length;		/* length of data */
};

//this one's mine
struct bgp_msg_hdr {
  u_char marker[16];
  u_short length;
  u_char type;
};

struct mrt_dump_hdr {
  unsigned short view;
  unsigned short seq_no;
  unsigned long addr;
  unsigned char mask;
  unsigned char status;
  unsigned long originated;
  unsigned long peer_ip;
  unsigned short peer_as;
  unsigned short attrlen;
};

#pragma pack(pop)

struct File_Reader_Info {
  FILE *f;
  Minipipe *pipe;
  int delay;
  int offset;
  unsigned int cap;
};

struct Fake_Capture_Info {
  Minipipe *pipe;
  unsigned int debug_peer;
  unsigned int my_ip;
  unsigned int debug_mode;
  unsigned int debug_size;
  
  Fake_Capture_Info(Minipipe *_pipe, unsigned int _debug_peer, unsigned int _my_ip, unsigned int _debug_mode, unsigned int _debug_size) :
    pipe(_pipe), debug_peer(_debug_peer), my_ip(_my_ip), debug_mode(_debug_mode), debug_size(_debug_size) {}
};

class Test_Handler;

class Fake_Router : public Runtime_Handler {
 public:
  Fake_Router(BGP_Peer *_peer, Test_Handler *_handler);  
  virtual void handle_minipipe(Minipipe *pipe, Runtime *runtime);
  virtual int handle_periodic(Runtime *runtime);
  void socketready(Pipedsocket *_sock);
  unsigned int get_ip();
  void write_data(char *data, int len);
  void inject_outbound(char *data, int len);
  void start_socketed();
  void start_norouter();
  void print_stats(int i, FILE *out);
  
 private:
  unsigned int ip;
  unsigned short as;
  BGP_Interposition_Agent *agent;
  Test_Handler *handler;
  Pipedsocket *sock;
  Minipipe *agent_pipe;
  Minipipe *handler_pipe;
  int outlen, inlen;
  int enabled;
};

class Test_Handler : public Runtime_Handler {
 public:
  Test_Handler(char *type, Ghetto_Vector *_peers, Runtime *runtime);

  void start();
  void re_register();
  
  void dispatch_msg(char *msg, int len, unsigned int ip, int port);
  void print_state();
  
  void dispatch_inbound();
  void dispatch_outbound();
  
  void set_indb(BC_Database *_indb);
  void set_grassroots(Grassroots *_grassrootsdb);
  void set_test_peer(Overlay_Peer_Handler *_test_peer);
  void complete();
  void fake_router_ready();
  
 protected:
  Fake_Router **peers;
  
  long int bytes;
  long int msgs;
  long int status_bytes;
  char direction;
  int peer_cnt, peer_rdy;
  
  BC_Database *indb;
  Grassroots *grassrootsdb;
  Overlay_Peer_Handler *test_peer;
};

class MRTStream : public Test_Handler {
 public:
  MRTStream(int _f, Ghetto_Vector *_peers, unsigned int _my_as, Runtime *runtime);
  MRTStream(unsigned int addr, unsigned short port, Ghetto_Vector *_peers, unsigned int _my_as, Runtime *runtime);
  ~MRTStream();
  
  virtual int handle_periodic(Runtime *runtime);
  
  int load_header(mrt_msg_hdr *hdr);
  void load_dump(mrt_msg_hdr *hdr);
  void load_update(mrt_msg_hdr *hdr);
  void dump_bytes(int len);
  void reset_for_outbound();
  void prepend_as_to_attrs(unsigned char *msg, int len);
  int prepend_comm_to_attrs(unsigned char *msg, int len);
  
 private:
  char *readmsg(unsigned int *target, int *len);
  FileBuffer *f;
  unsigned int target;
  unsigned short target_port;
  unsigned int my_as;
};


void mrt_preload(unsigned int addr, unsigned short port, BC_Database *indb, unsigned short my_as);

void fake_capture(Fake_Capture_Info *info);
Minipipe *file_pipe(char *name, int delay, int offset);
void file_reader_thread(File_Reader_Info *info);
NBGP_Policy *fake_policy();
#endif
