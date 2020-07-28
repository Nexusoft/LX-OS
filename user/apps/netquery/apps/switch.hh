#ifndef _SWITCH_HH_
#define _SWITCH_HH_

#include <linux/if_ether.h>
#include <arpa/inet.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <iomanip>

#include <string>
#include <set>
#include <vector>

#include <pthread.h>
#include <nq/attribute.hh>
#include <nq/site.hh>
#include <nq/net_elements.hh>

struct EtherDevBase;
struct PacketPump;
struct L2sec_AH;
struct AH_Key;
struct ARPRewrite;
struct SSL_Connection;

namespace eventxx {
  struct dispatcher;
};
struct SwitchPort {
  enum State {
    GETTING_IP,
    HAS_IP,
  };
  // typedef map<IP_Address, bool> PendingConnectMap;
  NQ_Tuple port_tid;
  NQ_Tuple switch_fw_table;
  int port_num;
  State m_switch_state;
  EtherDevBase *m_down;
  EtherDevBase *m_fabric_up;

  pthread_mutex_t l2sec_init_mutex;
  // IPC_ServiceDesc l2sec_desc;
  // PendingConnectMap pending_connects; // protected by l2sec_init_mutex
  NQ_Tuple peer_tid;
  bool has_pending_connect;
  AH_Key *key;

  PacketPump *down_to_up;
  PacketPump *up_to_down;
  ARPRewrite *arp_rewrite;

  inline SwitchPort(NQ_Tuple _tid, NQ_Tuple _fw_tid, int _num, EtherDevBase *down_dev) :
    port_tid(_tid), 
    switch_fw_table(_fw_tid),
    port_num(_num), 
    m_switch_state(GETTING_IP), 
    m_down(down_dev), 
    m_fabric_up(NULL),
    peer_tid(NQ_uuid_null),
    has_pending_connect(false),
    key(NULL),
    down_to_up(NULL), up_to_down(NULL), arp_rewrite(NULL) {
      pthread_mutex_init(&l2sec_init_mutex, NULL);
  }
  inline virtual ~SwitchPort() { }

  void new_state(State next_state);

  L2sec_AH *l2sec_downup;
  L2sec_AH *l2sec_updown;

  void l2sec_reset(IP_Address addr);
  void l2sec_enable(void);
  void l2sec_disable(void);
  void start_l2sec_setup_and_enable(void);

  bool nq_try_port_update(SSL_Connection *ssl, bool verify_result);
  void *do_l2sec_down_setup();

  void activate();
  void deactivate();

  void initialize_filter_chains_common(eventxx::dispatcher *d);
  virtual void initialize_filter_chains(eventxx::dispatcher *d) = 0;
};

struct ClientPort : public SwitchPort {
  inline ClientPort(NQ_Tuple _tid, NQ_Tuple _fw_tid, int _num, EtherDevBase *_down_dev) : SwitchPort(_tid, _fw_tid, _num, _down_dev) { }
  virtual void initialize_filter_chains(eventxx::dispatcher *d);
};

struct ExternalPort : public SwitchPort {
  inline ExternalPort(NQ_Tuple _tid, NQ_Tuple _fw_tid, int _num, EtherDevBase *_down_dev) : SwitchPort(_tid, _fw_tid, _num, _down_dev) { }
  virtual void initialize_filter_chains(eventxx::dispatcher *d);
};

static inline IP_Address make_ip(unsigned char a, unsigned char b, unsigned char c, unsigned char d) {
  //return (d << 24) | (c << 16) | (b << 8) | (a << 0);
  return (a << 24) | (b << 16) | (c << 8) | (d << 0);
}

static inline bool check_len(const unsigned char *data, const void *end, int len) {
  return ((const unsigned char *)end - data) <= len;
}
static inline bool check_ethhdr(const unsigned char *data, int len) {
  const struct ethhdr *eh = (const struct ethhdr *) data;
  return check_len(data, eh+1, len);
}
static inline bool check_iphdr(const unsigned char *data, int len) {
  if(!check_ethhdr(data, len)) {
    return false;
  }
  const struct ethhdr *eh = (const struct ethhdr *) data;
  const struct iphdr *ih = (const struct iphdr *) (eh + 1);
  return eh->h_proto == htons(ETH_P_IP) && check_len(data, (unsigned char *)ih + ih->ihl * 4, len);
}
static inline bool check_udphdr(const unsigned char *data, int len) {
  if(!check_iphdr(data, len)) {
    return false;
  }
  const struct ethhdr *eh = (const struct ethhdr *) data;
  const struct iphdr *ih = (const struct iphdr *) (eh + 1);
  const struct udphdr *uh = (const struct udphdr *) 
    ((unsigned char *) ih + ih->ihl * 4);
  return ih->protocol == IPPROTO_UDP && check_len(data, uh + 1, len);
}
static inline bool check_tcphdr(const unsigned char *data, int len) {
  if(!check_iphdr(data, len)) {
    return false;
  }
  const struct ethhdr *eh = (const struct ethhdr *) data;
  const struct iphdr *ih = (const struct iphdr *) (eh + 1);
  const struct tcphdr *th = (const struct tcphdr *) 
    ((unsigned char *) ih + ih->ihl * 4);
  return ih->protocol == IPPROTO_TCP && check_len(data, th + 1, len) &&
    check_len(data, (unsigned char *)th + th->doff * 4, len);
}

typedef std::set<MAC_Address> MAC_Table;

struct EtherDevBase {
  enum Flags {
    ERROR,
  };
  int m_flags;
  int m_fd;
  IP_Address m_ip_addr;
  std::string m_if_name;

  MAC_Table m_addr_table;

private:
  void common_init(void);
public:

  EtherDevBase(); 
  EtherDevBase(const std::string &if_name); 

  virtual ~EtherDevBase();

  int set_promisc(bool promisc);

  virtual int recv(unsigned char *buffer, int len) = 0;
  virtual int send(const unsigned char *buffer, int len) = 0;

  static bool registered_exit;
  typedef std::set<EtherDevBase *> EtherDevBaseSet;
  static EtherDevBaseSet all_devs;
  static void do_exit(void);

  void set_name(const std::string &if_name);
  void add_address(const MAC_Address &addr);
  bool has_address(const MAC_Address &addr);
};

struct EtherDev : EtherDevBase {
  int m_if_index;

  EtherDev(const std::string &if_name); 
  virtual ~EtherDev();

  virtual int recv(unsigned char *buffer, int len);
  virtual int send(const unsigned char *buffer, int len);
};

struct TapDev : EtherDevBase {
  TapDev(void);
  virtual ~TapDev();

  virtual int recv(unsigned char *buffer, int len);
  virtual int send(const unsigned char *buffer, int len);
};

struct FabricDev : EtherDevBase {
  int m_src_port_num;
  FabricDev(int port_num);
  virtual ~FabricDev();

  virtual int recv(unsigned char *buffer, int len);
  virtual int send(const unsigned char *buffer, int len);
};

void start_forwarding(int argc, char **argv);
void start_connect_only(void);

static inline unsigned short ip_checksum(void *_data, int len) {
  unsigned short *data = (unsigned short *)_data;
  long sum = 0;  /* assume 32 bit long, 16 bit short */

  while(len > 1){
    sum += *data++;
    
    if(sum & 0x80000000)   /* if high order bit set, fold */
      sum = (sum & 0xFFFF) + (sum >> 16);
    len -= 2;
  }

  if(len)       /* take care of left over byte */
    sum += (unsigned short) *(unsigned char *)data;
          
  while(sum>>16)
    sum = (sum & 0xFFFF) + (sum >> 16);

  return ~sum;
}

extern bool g_test_nq;
extern bool g_test_ssl;
extern bool g_test_handshake;
extern bool g_use_tcp_firewall;
extern IP_Port g_l2secd_server_port;
extern unsigned int g_next_ip_id;
extern bool g_test_tcp_forward;
extern std::vector<SwitchPort*> g_switch_ports;
extern ExtRef<T_Site> g_site_ref;
extern NQ_UUID g_switch_tid;
extern NQ_Tuple g_switch_fabric_tid;

#endif // _SWITCH_HH_
