#ifndef NBGP_H_SHIELD
#define NBGP_H_SHIELD

#include <deque>

extern "C"{
#include "../nbgp/bgp.h"
}
#include "../nbgp/bgpcheck.h"
#include "../runtime/runtime.h"
#include "../runtime/minipipe.h"
#include "../util/g_tl.h"
#include "../nbgp/policy_specification.h"
#include "../nbgp/grassroots.h"
#include "../util/optionlist.h"

#define NBGP_OVERLAY_PORT 52982

class BGP_Dispatcher;

class BGP_Peer {
 public:
  BGP_Peer(unsigned int ip_l, unsigned int port_l, unsigned int AS_l, unsigned int my_AS_l, BC_Database *indb, unsigned int ol_ip_l, unsigned int ol_port_l);
  ~BGP_Peer();

  // Overlay Implementation
  void set_dispatcher(BGP_Dispatcher *_dispatch);

  // capture implementation
  Minipipe *get_pipe(int incoming);
  PIPE_TYPE make_bgp_datasource(int incoming);
  void complete_bytes(int incoming, int len, PIPE_TYPE completed);

  unsigned int process_in_packet(char *data, int len);
  unsigned int process_out_packet(char *data, int len);
  
  unsigned int get_port();
  unsigned int get_ip();
  unsigned int get_ol_port();
  unsigned int get_ol_ip();
  unsigned int get_AS();

  BC_Checker *get_checker();

 private:
  Minipipe *in_pipe, *out_pipe;
  unsigned int ip, AS, port, ol_ip, ol_port;
  int out_cursor, in_cursor;
  BC_Checker *checker;
  BGP_Dispatcher *dispatch;
  bgp_packet packet;
};

///////////////////////////// END BGP_PEER

class Source_Handler : public Runtime_Handler {
 public:
  //Source_Handler takes control over peers_l, and will free it when it itself dies
  Source_Handler(Ghetto_Vector *peers_l, unsigned int ip_l, unsigned int AS_l, Minipipe *pipe_l);
  virtual ~Source_Handler();
  
  virtual void handle_minipipe(Minipipe *pipe, Runtime *runtime);
  
  Minipipe *get_pipe();

  //this function is for testing purposes.  When called, it blocks packet processing
  //until the buffer exceeds the number of bytes passed as a parameter to this function.
  //at that point the buffer is unblocked and processing continues as normal.
  void set_test_buffer_limit(int test_buffer_l);

  void print_times();

 private:
  Minipipe *pipe;
  Ghetto_Vector *peers;
  unsigned int ip, AS;
  int test_buffer;
  int pr_time;
  int eventsleft;
};

//////////////////////////////// END SOURCE_HANDLER

class BGP_Interposition_Agent {
 public:
  BGP_Interposition_Agent(BGP_Peer *_peer);
  
  void set_peer_streams(Minipipe *in, Minipipe *out, Runtime *r);
  void set_router_streams(Minipipe *in, Minipipe *out, Runtime *r);

  void peer_packet();
  void router_packet();

 private:
  class Stream_Monitor : public Runtime_Handler {
   public:
    Stream_Monitor(Minipipe *pipe, int _direction, BGP_Interposition_Agent *_parent);
   
    virtual void handle_minipipe(Minipipe *pipe, Runtime *runtime);
   
   private:
    BGP_Interposition_Agent *parent;
    int direction;
  };
  
  BGP_Interposition_Agent::Stream_Monitor *peer_mon, *router_mon;
  Minipipe *peer_in, *peer_out, *router_in, *router_out;
  BGP_Peer *peer;
};

class BGP_Interposition_SimpleSocket : public BGP_Interposition_Agent {
 public:
  BGP_Interposition_SimpleSocket(BGP_Peer *_peer, unsigned short port, unsigned int target, unsigned int target_port, Runtime *r);

 private:
  Pipedsocket *bgp_peer, *bgp_router;
};

//////////////////////////////// END BGP_Interposition_Agent

#define OVERLAY_MSG_RVQ        0
#define OVERLAY_MSG_JOIN       1
#define OVERLAY_MSG_WARN       2
#define OVERLAY_MSG_BADRVQ     3
#define OVERLAY_MSG_GRASSROOTS 4
#define OVERLAY_MSG_TRIGGER_WARNING 5

#pragma pack(push, 1)

struct overlay_msg_prefixpath {
  int type;
  int prefix;
  int prefixlen;
  int pathlen;
  unsigned short path[];
};

struct overlay_msg_join {
  int type;
  unsigned short as,port;
  unsigned int ip;
};

#pragma pack(pop)

class Overlay_Peer_Handler;

struct Overlay_Peer {
  unsigned int ip;
  unsigned short port;
  Overlay_Peer_Handler *peer;
  Overlay_Peer *next_direct;
};

class Overlay_Server_Handler : public Runtime_Handler {
  public:
    Overlay_Server_Handler(unsigned short _as, unsigned int _ip, unsigned short _port);
    
    virtual void handle_accept(Minisocket *sock, Runtime *runtime);
    virtual int handle_periodic(Runtime *runtime);

    //peer management
    void add_peer(BGP_Peer *peer);
    Overlay_Peer_Handler *get_channel(unsigned short as);
    unsigned int get_ip(unsigned short as);
    unsigned short get_port(unsigned short as);
    
    unsigned short my_as();
    unsigned int my_ip();
    unsigned short my_port();
    
    //peer messaging
    void send_rvq(unsigned short *route, unsigned int prefix, int p_len);
    void send_warning(unsigned short *route, unsigned int prefix, int p_len);
    void send_join(short as);
    void set_as(Overlay_Peer_Handler *peer, unsigned short as);
    void send_gr_delegation(Grassroots::RawData *data);
    
    void got_bad_rvq(unsigned short *route, unsigned int prefix, int p_len);
    void got_warning(unsigned short *route, unsigned int prefix, int p_len);
    void got_join(unsigned short _as, unsigned int _ip, unsigned short _port);
    int got_rvq(unsigned short *route, unsigned int prefix, int p_len);

    void test_rvq_out(int cnt);

    void set_dispatcher(BGP_Dispatcher *_dispatch);

  private:
    Overlay_Peer *first_direct;
    Overlay_Peer peers[65536];
    unsigned short as;
    unsigned int ip;
    unsigned short port;
    BGP_Dispatcher *dispatch;
};

class Overlay_Peer_Handler : public Runtime_Handler {
  public:
    Overlay_Peer_Handler(Overlay_Server_Handler *_server);
    
    void set_socket(Minisocket *_sock);
    void create_socket(unsigned short _as);
    void hacked_connect(unsigned int ip, unsigned short port);
    
    virtual void handle_minipipe(Minipipe *pipe, Runtime *runtime);
    virtual void handle_sockready(Minisocket *sock, Runtime *runtime);
    
    void send_rvq(unsigned short *route, unsigned int prefix, int p_len);
    void send_warning(unsigned short *route, unsigned int prefix, int p_len);
    void send_join(unsigned short _as, unsigned int _ip, unsigned short _port);
  
    void test_rvq_out(int cnt);

  private:
    Overlay_Server_Handler *server;
    Minisocket *sock;
    int as;
    short flags;
    int test_rvqcnt;
    struct timeval test_start;
};

class BGP_Dispatcher {
 public:
  BGP_Dispatcher(Runtime *_runtime);
  
  void start_logging(char *_logfile);
  void stop_logging(void);

  void set_overlay(Overlay_Server_Handler *_overlay);
  void set_incoming_db(BC_Database *_indb);
  void set_router(unsigned int _routerip, char *_routerpass, char *_routeruser, unsigned short _routeras);
  void set_grassroots(Grassroots *_grassrootsdb);

  void report_policy(bgp_packet *packet, int ad, int rule);
  void report_ad(unsigned int prefix, unsigned short prefixlen, bgp_as_path *base_path);
  void report_ad(unsigned int prefix, unsigned short prefixlen, unsigned short *path);
  void handle_reported(unsigned int prefix, unsigned short prefixlen, unsigned short *path);
  
  void rvq(unsigned int prefix, unsigned short prefixlen, unsigned short *path);
  void sent_packet(bgp_packet *packet, unsigned short peer, unsigned int peer_ip);
  void got_packet(bgp_packet *packet, unsigned short peer, unsigned int peer_ip);
 private:
  Overlay_Server_Handler *overlay;
  BC_Database *indb;
  Grassroots *grassrootsdb;
  Runtime *runtime;
  DebugState *debug_grassroots, *debug_outdb;
  
  unsigned int routerip;
  char *routerpass;
  char *routeruser;
  unsigned short routeras;
  int badcount;
  FILE *logfile;
  struct BGP_Recheck_Event {
    BGP_Recheck_Event(){ b_ads = NULL; }
    ~BGP_Recheck_Event();
    int validate(BGP_Dispatcher *owner);
    int timeleft();
  
    time_t trigger_time;
    std::vector<BC_Advertisement *> *b_ads;
    unsigned int prefix;
    unsigned short prefix_len;
  };
  class BGP_Recheck_Callback : public Runtime_Handler {
   public:
    BGP_Recheck_Callback(BGP_Dispatcher *_owner);
    virtual int handle_periodic(Runtime *runtime);
    void schedule(int time);
    
   private: 
    int scheduled;
    BGP_Dispatcher *owner;
  };
  std::deque<BGP_Recheck_Event *> pending_checks;
  BGP_Recheck_Callback *recheck_callback;
  
  // after <time> msec, validate() will be called on all elements of b_ads;
  // If any return false, their corresponding ad will be reported.
  void schedule_recheck(int time, std::vector<BC_Advertisement *> *b_ads, unsigned int prefix, unsigned short prefix_len);
  int finish_recheck(BGP_Recheck_Callback *cb);
};

#define PREFIX_SINGLE -1
#define PREFIX_NOOP 0
#define PREFIX_EXCLUSIVE_SPECIFICS 1
#define PREFIX_INCLUSIVE_SPECIFICS 2
#define PREFIX_RANGE_ONE 3
#define PREFIX_RANGE_MANY 4

struct Prefix_Spec {
  unsigned int prefix;
  short range_general, range_specific, delta;
  std::vector<Prefix_Spec *> set;
  int operand;
  
  void init_base();
  //Base
  Prefix_Spec(unsigned int _prefix, unsigned short _prefix_length);
  //Set (no-modifier)
  Prefix_Spec();
  //Operand
  Prefix_Spec(Prefix_Spec *spec, int _operand);
  //Range
  Prefix_Spec(Prefix_Spec *spec, short _start);
  Prefix_Spec(Prefix_Spec *spec, short _start, short _stop);
  
  ~Prefix_Spec();
  
  void add(Prefix_Spec *spec);
  
  short contains(unsigned int _prefix, unsigned short _prefix_length);
  short Prefix_Spec::contains(unsigned int _prefix, 
                              unsigned short prefix_length,
                              unsigned short _delta,
                              unsigned short restrict);
  short Prefix_Spec::set_contains(unsigned int _prefix, 
                                  unsigned short _prefix_length,
                                  unsigned short delta,
                                  unsigned short restrict);
};

#define PACTION_COMMUNITY 1
#define PACTION_LOCALPREF 2
#define PACTION_MED 3
#define PACTION_DROP 4

#define PACTION_OP_CMP_LT 1
#define PACTION_OP_CMP_GT 2
#define PACTION_OP_CMP_EQ 3
#define PACTION_OP_CMP_NEQ 4

#define PACTION_OP_SET 1
#define PACTION_OP_APPEND 2
#define PACTION_OP_REMOVE 3

struct Policy_Intermediate_State;

struct Policy_Action {
  int op;
  int field;
  unsigned int value;
  
  short packet_satisfies(bgp_packet *p);
  short match_community(unsigned int community);
  short match_localpref(unsigned int localpref);
  short match_med(unsigned int med);
  short match_question(Policy_Question *q, Policy_Intermediate_State *s);
};

#define REGEX_AS 1
#define REGEX_SET 2
#define REGEX_ISET 3
#define REGEX_SPECIAL 4
#define REGEX_RANGE 5
#define REGEX_URANGE 6
#define REGEX_OR 7

#define REGEX_SPECIAL_ANY 1
#define REGEX_SPECIAL_START 2
#define REGEX_SPECIAL_END 3

struct Policy_Regex {
  int type;
  unsigned short as;
  unsigned short range_max, range_min;
  std::vector<Policy_Regex *> children;
  Policy_Regex *next;
  
  void init_base();
  Policy_Regex(unsigned short _as);
  Policy_Regex(int _type, Policy_Regex *child);
  ~Policy_Regex();
  
  void add_child(Policy_Regex *child);
  void add_peer(Policy_Regex *peer);
  
  short next_cont(std::vector<unsigned short>::iterator path,  std::vector<unsigned short>::iterator begin, std::vector<unsigned short>::iterator end, std::vector<Policy_Regex *> *cont, Policy_Regex *step);
  short match(std::vector<unsigned short>::iterator path,  std::vector<unsigned short>::iterator begin, std::vector<unsigned short>::iterator end, std::vector<Policy_Regex *> *cont);
  
  short match(std::vector<unsigned short> path);
};

#define FILTER_AND 0
#define FILTER_OR 1
#define FILTER_NOT 2
#define FILTER_PSET 3
#define FILTER_ACTION 4
#define FILTER_ASPATH 5
#define FILTER_ANY 6

struct Policy_Intermediate_State {
  std::vector<Policy_Action> acts;
  
  void add(Policy_Action act);
  short match_community(unsigned int community);
  short match_med(int med);
  short match_localpref(int med); 
  short packet_satisfies(bgp_packet *p);
};

struct Policy_Filter {
  int type;
  
  union {
    struct {
      Policy_Filter *op1, *op2;
    } boolean_op;
    Prefix_Spec *p_set;
    Policy_Action *action;
    Policy_Regex *regex;
  } d;
  
  short match(Policy_Question *q, Policy_Intermediate_State *s);
};

#define NBGP_AS_ANY (0x01)

struct NBGP_AS_Policy_Set {
  std::vector<unsigned short> as;
  std::vector<Policy_Action> action;
  short flags;
  
  NBGP_AS_Policy_Set();
  
  void add_as(unsigned short _as);
  void add_action(Policy_Action _action);
  
  short match_as(unsigned short _as);
  short apply_actions(Policy_Intermediate_State *s); //returns 0 if should drop
  short check_actions(bgp_packet *p); //returns 0 if should drop
};

class NBGP_Policy_Line {
 public:
  NBGP_Policy_Line();
  ~NBGP_Policy_Line();
  
  void set_filter(Policy_Filter *_filter);
  void add_as(NBGP_AS_Policy_Set *_as_action);
  
  short match_import(Policy_Question *q, Policy_Intermediate_State *state);
  short match_export(Policy_Question *q, Policy_Intermediate_State *state);

 private:
  Policy_Filter *filter;
  std::vector<NBGP_AS_Policy_Set *> as_actions;
};

class NBGP_Policy : public Policy_Specification {
 public:
  NBGP_Policy();
  virtual ~NBGP_Policy();
  
  void add_export(NBGP_Policy_Line *line);
  void add_import(NBGP_Policy_Line *line);
  void add_policy(NBGP_Policy *p);
  
  short check_imports(Policy_Question *q, Policy_Intermediate_State *s);
  short check_exports(Policy_Question *q, Policy_Intermediate_State *s);
  
  virtual short ask(Policy_Question *q);
  short ask_real(Policy_Question *q);
  
  void install(BC_Checker *checker, Runtime *runtime);
  
 private:
  std::vector<NBGP_Policy_Line *> exports;
  std::vector<NBGP_Policy_Line *> imports;
  std::vector<NBGP_Policy *> policies;
  class Swapper : public Runtime_Handler {
    public:
    Swapper(Policy_Grouping *_policy, BC_Checker *_checker, int timeout);
    
    virtual int handle_periodic(Runtime *runtime);

    Policy_Grouping *policy;
    BC_Checker *checker;
  };
  Swapper *swap_in;
  
  
};

//////////////////////////////// END NBGP_POLICY

void install_nbgp_commands(Command_List *cmds);
void nbgp_monitor_loop();

//////////////////////////////// END NBGP_COMMANDS

#endif
