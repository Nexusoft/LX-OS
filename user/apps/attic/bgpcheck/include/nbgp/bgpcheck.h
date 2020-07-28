
#ifndef BGPCHECK_H_SHIELD
#define BGPCHECK_H_SHIELD

#include <vector>
#include <map>
extern "C" {
#include "../nbgp/bgp.h"
};
#include "../util/debug.h"

struct BC_Database_Entry;

#define INCLUDE_BGP_DB_PREFIX

#pragma pack(push, 1)

struct BC_Advertisement {
  unsigned short as_id;
  unsigned int as_ip;
  
  std::vector<unsigned int> communities;
  unsigned int nexthop;
  
  char refcnt;
  
  std::vector<unsigned short> as_path;
    
  BC_Advertisement();
  BC_Advertisement(BC_Advertisement *ad);
  
  int equals(BC_Advertisement *ad);
  int full_equals(BC_Advertisement *ad);
  void load_path(bgp_as_path *path);
  int check_path(bgp_as_path *path);
  unsigned short *dump_path();
  int validated();
  int withdrawn();
  void print_path();
  void print_path(FILE *f);
  
  void ref_up();
  void ref_down();
  
  int calc_size();
  unsigned int get_hash();
  
  struct LESS { int operator()(const BC_Advertisement *a, const BC_Advertisement *b); };
};

#define bc_adverts std::vector<BC_Advertisement *>
typedef struct BC_Database_Entry *BC_Database_Entry_ptr;

struct BC_Path_Store {
  BC_Path_Store *parent, *child, *peer;
  unsigned short as;
  
  int trace_path(unsigned short *s, int *i);
  int trace_path(unsigned short *s);
  int calc_size();
};

struct BC_Path_Ref {
  unsigned short as;
  BC_Path_Store *path;
};

struct BC_Database_Entry {
  std::vector<BC_Advertisement *> ad_list;
  BC_Path_Ref *forwards;
  unsigned short forwards_size;
#ifdef INCLUDE_BGP_DB_PREFIX
  unsigned int p_prefix;  //prefix is in host byte order.
  unsigned char p_depth;
#endif
  BC_Database_Entry_ptr next[2];
  
  BC_Database_Entry(BC_Database_Entry *parent, int bit);
  ~BC_Database_Entry();
  
  BC_Database_Entry *get(unsigned int prefix, int length);
  BC_Database_Entry *get(unsigned int prefix, int length, int create);
  void subdivide(unsigned int prefix, int length, BC_Advertisement *ad);
  void store(unsigned int prefix, int length, BC_Advertisement *ad);
  std::vector<BC_Advertisement *>::iterator contains(BC_Advertisement *ad);
  void lookup(unsigned int prefix, int length, bc_adverts *ret);
  int withdraw(unsigned int prefix, int length, unsigned short as_id, unsigned int as_ip);
  void print(unsigned int prefix, int length);
  void print(unsigned int prefix, int length, unsigned int curr_prefix, unsigned int curr_length);
  void forward(unsigned int prefix, int length, unsigned short as, BC_Path_Store *path);
  int check_forward(unsigned int prefix, int length, unsigned short *aspath);
  int calc_size();
};
#pragma pack(pop)

typedef BC_Database_Entry bc_prefix;

struct BC_Advertisement_Store {
#ifdef BC_ADVERTISEMENT_STORE_MAP
  std::map< BC_Advertisement *, 
            BC_Advertisement *, 
            BC_Advertisement::LESS> store;
  BC_Advertisement_Store() : store() {}
#else
#define BC_ADVERTISEMENT_HASH_SIZE (1024*1024)
  struct Entry {
    BC_Advertisement *ad;
    Entry *next;
  };
  Entry **store;
  int ads, maxheapsize, adsize;;
  BC_Advertisement_Store();
#endif
  
  BC_Advertisement *get_and_store(BC_Advertisement *ad);
  int calc_size();
};

class BC_Database {
 public:
  BC_Database(void);
  ~BC_Database(void);
  unsigned short verify(unsigned int prefix, int length, bgp_as_path *path, bc_adverts *ret);
  void install(BC_Advertisement *ad, unsigned int p_prefix, int p_depth);
  void parse(bgp_packet *packet, unsigned short source_as, unsigned int source_ip);
  
  void forward(bgp_packet *packet, unsigned short source_as);
  int check_forward(unsigned int prefix, int prefixlen, unsigned short *aspath);
  
  void print_potentials(unsigned int prefix, int length);
  void print_path(unsigned int prefix, int length);
  BC_Path_Store *store_path(bgp_as_path *path, int i, BC_Path_Store **curr, BC_Path_Store *parent);
  BC_Path_Store *store_path(bgp_as_path *path);
  
  int calc_size();
  
 private:
  BC_Database_Entry *root;
  BC_Advertisement_Store ad_store;
  BC_Path_Store *path_root;
  int size;
};

struct Policy_Grouping;
class Policy_Specification;

class BC_Checker {
 public:
  BC_Checker(BC_Database *_db, unsigned short _as_id, unsigned int _as_ip, unsigned short _my_as);
  ~BC_Checker();
  
  int load_packet(bgp_packet *_packet);
  int ads_remaining();
  void reset_ads();
  int check_next_ad();
  void skip_next_ad();
  unsigned int last_prefix();
  int last_prefix_len();
  void free_packet();
  void cleanup_packet();
  void finish_packet();
  
  void parse_incoming(bgp_packet *_packet);
  
  void print_potentials();
  void print_path();
  
  Policy_Grouping *set_policy(Policy_Grouping *_policy);
  Policy_Grouping *set_policy(Policy_Specification *_policy);
  void force_policy_swap(Policy_Grouping *_policy);
  int policy_pending();
  
 private:
  int detect_loops();
  
  unsigned short as_id;
  unsigned int as_ip;
  unsigned short my_as;
  BC_Database *db;
  DebugState *ds_inc, *ds_out;
  
  int ads_left;
  int ads_checked;
  bgp_packet *packet;
  bgp_ipmaskvec *prefix;
  bgp_ipmaskvec dummy;
  
  Policy_Grouping *policy;
  Policy_Grouping *next_policy;
};

void bc_log_prefix(char *prefix, int depth);
void bc_log_prefix_end();

#endif
