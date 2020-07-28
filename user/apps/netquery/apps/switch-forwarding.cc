#include <sys/socket.h>
#include <poll.h>
#include <nexus/l2sec.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <linux/icmp.h>
#include <linux/udp.h>
#include <linux/ip.h>
#include <netdb.h>
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/ioctl.h>

#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include <linux/if.h>
#include <linux/if_tun.h>

#include <iostream>
#include <string>
#include <iomanip>
#include <list>
#include <map>
#include <ext/hash_set>
#include <ext/hash_map>

#include "switch-nq.hh"
#include "switch.hh"
#include "eventxx"
#include <nq/util.hh>
#include <nq/site.hh>
#include <nq/transaction.hh>
#include <nq/netquery.h>

#undef __USE_MISC
#include <net/if.h>

#include "l2sec-ipc.hh"

using namespace std;
using namespace __gnu_cxx;

#define IFCONFIG "/sbin/ifconfig"
#define ARPCMD "/sbin/arp"
//#define PING "/bin/ping"

#define PING()    fprintf(stderr, "<%d>", __LINE__)

#define BOOTPS (67)
#define BOOTPC (68)

#define KNOCK_PORT (3333)

// Keep TTL low ; some of the ICMPs we generate are bogus
#define ICMP_TTL (4)

bool g_test_nq = false;
bool g_test_ssl = false;
bool g_test_handshake = false;
bool g_use_tcp_firewall = false;

IP_Port g_test_ssl_port = 0;
bool g_test_tcp_forward = false;

int raw_ip_sock;
IP_Address local_ip_addr;
MAC_Address local_mac_addr;

IP_Address g_tftp_server_addr;
IP_Port g_tftp_server_port;
IP_Address g_dhcp_server_addr;
IP_Address g_trusted_server_addr;
IPC_ServiceDesc l2sec_desc;

IP_Port g_l2secd_server_port = KNOCK_PORT;

unsigned int g_next_ip_id;

vector<SwitchPort*> g_switch_ports;

pthread_mutex_t nq_update_mutex = PTHREAD_MUTEX_INITIALIZER;

void SwitchPort::activate() {
  cerr << "Activating port\n";

  l2sec_reset(m_down->m_ip_addr);
  l2sec_enable();
}

void SwitchPort::deactivate() {
  cerr << "Deactivating port\n";

  cerr << "xxx delete old host entry\n";

  l2sec_disable();
}

void print_packet(const unsigned char *buf, int packet_len);
void setup_local_networking(void);

void deliver_to_local_ip(const unsigned char *data, int len) {
  cerr << "Skipping local delivery\n";
  return;
  const struct iphdr *ih = (const struct iphdr *) data;
  struct sockaddr_in sa;

  sa.sin_addr.s_addr = ih->daddr;
  sa.sin_port = 0;
  sa.sin_family = AF_INET;

  cerr << "Local len=" << len << ", dest = " << setbase(16) << sa.sin_addr.s_addr << setbase(10) << "\n";
  print_packet(data, len);

  // xxx how to deal with local broadcast?
  int flags = 0;
  // flags |= MSG_DONTROUTE;
  // eacces
  int err = sendto(raw_ip_sock, data, len, flags, (struct sockaddr*) &sa,sizeof(sa));
  if(err < 0) {
    perror("local delivery failed");
    cerr << "errno = " << errno << "\n";
    return;
  }
}

void icmp_build(const struct icmphdr *icmp, const unsigned char *orig_pkt, unsigned char *pkt, int *len) {
  assert(*len >= ETH_FRAME_LEN);
  const struct ethhdr *eh = (const struct ethhdr *) orig_pkt;
  const struct iphdr *ih = (const struct iphdr *) (eh + 1);
  struct ethhdr *o_eh = (struct ethhdr *) pkt;
  local_mac_addr.set_buf(o_eh->h_source);
  memcpy(o_eh->h_dest, eh->h_source, ETH_ALEN);
  o_eh->h_proto = htons(ETH_P_IP);

  struct iphdr *o_iph = (struct iphdr *)(o_eh + 1);
  o_iph->ihl = sizeof(*o_iph) / 4;
  o_iph->version = 4;
  o_iph->tos = 0;
  // o_iph->tot_len = htons(xxx);
  o_iph->id = g_next_ip_id++;
  o_iph->frag_off = 0;
  o_iph->ttl = ICMP_TTL;
  o_iph->protocol = IPPROTO_ICMP;
  o_iph->check = 0;
  o_iph->saddr = htonl(local_ip_addr); // ih->daddr;
  o_iph->daddr = ih->saddr;

  // include copy of header + beginning of payload
  int msg_len = MIN(ih->ihl * 4 + 8, ntohs(ih->tot_len));

  struct icmphdr *o_icmp = (struct icmphdr *)(o_iph + 1);
  *o_icmp = *icmp;
  o_icmp->checksum = 0;

  unsigned char *payload = (unsigned char *) (o_icmp + 1),
    *payload_end = payload + msg_len;
  memcpy(payload, ih, msg_len);

  o_icmp->checksum = 
    ip_checksum(o_icmp, payload_end - (unsigned char *)o_icmp);

  o_iph->tot_len = htons(payload_end - (unsigned char *)o_iph);
  o_iph->check = ip_checksum(o_iph, sizeof(*o_iph));
  *len = payload_end - pkt;
}

#define BOOTP_OP_REQUEST (0x01)
#define BOOTP_OP_REPLY (0x02)
struct bootphdr {
	char op;
	char htype;
	char hlen;
	char hops;
	char xid[4];
	char secs[2];
	char flags[2];
	unsigned int ciaddr;
	unsigned int yiaddr;
	unsigned int siaddr;
	unsigned int giaddr;
	char chaddr[16];
	char server_hostname[64];
	char boot_filename[128];
	char dhcp_option_cookie[4]; // this and following are optional?
	char dhcp_option_tags[308]; // arbitrary length?
} __attribute__((packed));

#if 0
IP_Address resolve_ip(const string &s) {
  struct hostent *h = gethostbyname(s.c_str());
  if(h == NULL) {
    throw "Could not find host\n";
  }
  IP_Address rv;
  memcpy(&rv, h->h_addr, sizeof(rv));
  cerr << "Resolved " << s << " to " << rv << "\n";
  return rv;
}
#endif

namespace ARP {
  MAC_Address lookup(IP_Address addr) {
#if 0
    string cmdline = string(PING) + " " + itos(addr) + " -c 1";
    cerr << "Lookup => " << cmdline << "\n";
    system(cmdline);

    char tmpname[] = "ARPTMP-XXXXXX";
    int tmpfile = mkstemp(tmpname);
    cmdline = string(ARPCMD) + " -n > " + tmpname;
    cerr << "Lookup => " << cmdline << "\n";
    system(cmdline);
    close(tmpfile);
    unlink(tmpname);
#else
    static int limit = 5;
    if(limit > 0) {
      cerr << "Warning: Hard coded arp lookup\n";
      cerr << "Addr = " << setbase(16) << addr << setbase(10) << "\n";;
      limit--;
    }
    unsigned char dhcp_addr[] = { 0x00, 0x02, 0x55, 0xD4, 0xE5, 0xF4 };
    //unsigned char tftp_addr[] = { 0x00, 0x13, 0xD4, 0x4B, 0x4B, 0xFF };
    unsigned char tftp_addr[] = { 0x00, 0x15, 0x58, 0x38, 0xE1, 0x04 };
    unsigned char *a = NULL;
    if(addr == make_ip(128, 84, 227, 8)) {
      a = dhcp_addr;
    } else if(addr == make_ip(128,84,227,11)) {
      a = tftp_addr;
    }
    if(a == NULL) {
      throw "No match in hardcoded IP list\n";
    }
    return MAC_Address(a);
#endif
  }

  struct IPv4 {
  unsigned char		ar_sha[ETH_ALEN];	/* sender hardware address	*/
  unsigned int 		ar_sip;		/* sender IP address		*/
  unsigned char		ar_tha[ETH_ALEN];	/* target hardware address	*/
  unsigned int		ar_tip;		/* target IP address		*/
  } __attribute__ ((packed));
};

static inline bool check_arphdr(const unsigned char *data, int len) {
  const struct ethhdr *eh = (const struct ethhdr *) data;
  const struct arphdr *ah = (const struct arphdr *) (eh + 1);
  ARP::IPv4 *v4_hdr = (ARP::IPv4 *)  (ah + 1);
  return check_ethhdr(data, len) &&
    eh->h_proto == htons(ETH_P_ARP) &&
    check_len(data, v4_hdr + 1, len) &&
    ah->ar_hrd == htons(ARPHRD_ETHER);
}

void setup_local_networking(void) {
  // from http://packetstormsecurity.org/groups/horizon/congestant.c
  int on = 1;

  if( (raw_ip_sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0)
    {
      perror("socket");
      exit(1);
    }

  if (setsockopt(raw_ip_sock,IPPROTO_IP,IP_HDRINCL,&on,sizeof(on)) < 0) 
    {
      perror("setsockopt: IP_HDRINCL");
      exit(1);
    }

  if(setsockopt(raw_ip_sock, SOL_SOCKET, SO_BROADCAST, &on, sizeof(on)) < 0) {
    perror("setsockopt: so_broadcast");
    exit(1);
  }


  char name[128];
  if(gethostname(name, sizeof(name)) != 0) {
    perror("gethostname");
    exit(1);
  }
  struct hostent *ent = gethostbyname(name);
  if(ent == NULL) {
    perror("gethostbyname");
    exit(1);
  }
  unsigned int n_addr;
  memcpy(&n_addr, ent->h_addr, sizeof(n_addr));
  local_ip_addr = ntohl(n_addr);
  fprintf(stderr, "Got local ip address %08x\n", local_ip_addr);

  local_mac_addr = ARP::lookup(local_ip_addr);
}

bool EtherDevBase::registered_exit = false;
EtherDevBase::EtherDevBaseSet EtherDevBase::all_devs;

void EtherDevBase::do_exit(void) {
  cerr << "Exiting EtherDev\n";
  // make a copy, since delete will modify the map
  EtherDevBaseSet dev_map = all_devs;
  for(EtherDevBaseSet::iterator i = dev_map.begin();
      i != dev_map.end(); i++) {
    cerr << "do_exit(" << *i << ")\n";
    delete *i;
  }
  assert(all_devs.size() == 0);
}

void EtherDevBase::common_init(void) {
  m_flags = 0;
  m_fd = -1;
  m_ip_addr = 0;
  if(!registered_exit) {
    atexit(EtherDevBase::do_exit);
  }
  all_devs.insert(this);
}
EtherDevBase::EtherDevBase(const string &if_name) {
  set_name(if_name);
  common_init();
}

EtherDevBase::EtherDevBase() {
  common_init();
}

void EtherDevBase::set_name(const string &if_name) {
  m_if_name = if_name;
}

EtherDevBase::~EtherDevBase() {
  all_devs.erase(this);
}


int EtherDevBase::set_promisc(bool promisc) {
  string cmd = string(IFCONFIG) + " " + m_if_name + " " + (promisc ? "" : "-") + "promisc";
  // cerr << "CMD: " << cmd << "\n";
  int rv = system(cmd.c_str());
  if(rv == -1) {
    cerr << "set promisc error on " << m_if_name << "\n";
    return -1;
  }
  return WEXITSTATUS(rv);
}

void EtherDevBase::add_address(const MAC_Address &addr) {
  m_addr_table.insert(addr);
}

bool EtherDevBase::has_address(const MAC_Address &addr) {
  return addr.is_broadcast() || 
    m_addr_table.find(addr) != m_addr_table.end();
}

EtherDev::EtherDev(const string &if_name) :
  EtherDevBase(if_name), m_if_index(-1) {
  struct sockaddr_ll sockaddr;
  socklen_t len = sizeof(struct sockaddr_ll);

  m_fd = socket (PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
  if (m_fd == -1) {
    goto out_error;
  }

  // Obtain interface index number
  m_if_index = if_nametoindex (m_if_name.c_str());
  if(m_if_index == 0) {
    cerr << "Could not open etherdev!\n";
    goto out_error;
  }

  memset(&sockaddr, 0, sizeof (struct sockaddr_ll));
  sockaddr.sll_family = AF_PACKET;
  // ETH_P_ALL means listen to ALL ethernet protocols
  sockaddr.sll_protocol = htons(ETH_P_ALL);
  sockaddr.sll_ifindex = m_if_index;
  cerr << "Binding " << m_if_index << " to " << m_fd <<"\n";

  // Bind raw socket to ethernet device
  if (bind (m_fd, (struct sockaddr *)&sockaddr, len) == -1) {
    goto out_error;
  }
  fcntl(m_fd, F_SETFL, O_NONBLOCK);
  cerr << "EtherDev " << if_name << " => " << m_fd << "\n";
  return;
 out_error:
  m_flags |= ERROR;
  cerr << "Raw bind error\n";
  throw "eth create error";
  return;
}

EtherDev::~EtherDev() {
  if(!(m_flags & ERROR)) {
    set_promisc(false);
    close(m_fd);
  }
}

int EtherDev::recv(unsigned char *buffer, int len) {
  int length = 0; /*length of the received frame*/
  length = recvfrom(m_fd, buffer, ETH_FRAME_LEN, 0, NULL, NULL);
  if (length == -1) {
    if(errno != EAGAIN) {
      cerr << "Eth recv: Got error = " << errno << "\n";
    }
    return -1;
  }
  return length;
}

int EtherDev::send(const unsigned char *buffer, int len) {
  /* target address */
  struct sockaddr_ll socket_address;

  /*another pointer to ethernet header*/
  struct ethhdr *ethhdr = (struct ethhdr *)buffer;
  // unsigned char *data = (unsigned char *) (ethhdr + 1);
  int send_result = 0;

  /*prepare sockaddr_ll*/

  /*RAW communication*/
  socket_address.sll_family   = PF_PACKET;
  /*we don't use a protocoll above ethernet layer
    ->just use anything here*/
  socket_address.sll_protocol = htons(ETH_P_IP);

  /*index of the network device */
  socket_address.sll_ifindex  = m_if_index;

  /*ARP hardware identifier is ethernet*/
  socket_address.sll_hatype   = ARPHRD_ETHER;
	
  /*target is another host*/
  socket_address.sll_pkttype  = PACKET_OTHERHOST;

  /*address length*/
  socket_address.sll_halen    = ETH_ALEN;		
  memset(socket_address.sll_addr, 0, sizeof(socket_address.sll_addr));
  memcpy(socket_address.sll_addr, ethhdr->h_dest, ETH_ALEN);

  /*send the packet*/
  send_result = sendto(m_fd, buffer, len, 0, 
		       (struct sockaddr*)&socket_address, sizeof(socket_address));
  if (send_result == -1) {
    if(errno != EAGAIN) {
      cerr << "Could not send Eth packet of len " << len << " ! (errno = " << errno << ")\n";
      perror("eth send");
    }
    return -1;
  }
  return 0;
}

TapDev::TapDev(void) : EtherDevBase() {
  struct ifreq ifr;
  int fd, err;

  char dev[80] = "";

  if( (fd = open("/dev/net/tun", O_RDWR)) < 0 ) {
    throw "Could not open new tun location";
  }

  memset(&ifr, 0, sizeof(ifr));

  /* Flags: IFF_TUN   - TUN device (no Ethernet headers) 
   *        IFF_TAP   - TAP device  
   *
   *        IFF_NO_PI - Do not provide packet information  
   */ 
  //ifr.ifr_flags = IFF_TUN; 
  ifr.ifr_flags = IFF_TAP | IFF_NO_PI; 
  if( *dev )
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);

  if( (err = ioctl(fd, TUNSETIFF, (void *) &ifr)) < 0 ){
    close(fd);
    throw "Could not set tunnel device";
  }
  strcpy(dev, ifr.ifr_name);
  
  if(system((string("/sbin/ifconfig ") + dev + " up").c_str()) != 0) {
    throw "Could not enable device";
  }

  if(system((string("/usr/sbin/brctl addif mesh ") + dev).c_str()) != 0) {
    throw "Could not set mesh";
  }

  if(system((string("/sbin/ifconfig mesh mtu 1480")).c_str()) != 0) {
    throw "Could not set mesh mtu";
  }

  set_name(string(dev));
  m_fd = fd;
  cerr << "Got tap dev " << dev << "\n";
};

TapDev::~TapDev() {
  // do nothing
}

int TapDev::recv(unsigned char *buffer, int len) {
  int length = read(m_fd, buffer, len);
  if(length < 0) {
    if(errno != EAGAIN) {
      cerr << "Error not eagain: " << errno << "\n";
    }
  }
  return length;
}

int TapDev::send(const unsigned char *buffer, int len) {
  int send_result = write(m_fd, buffer, len);
  if (send_result == -1) {
    if(errno != EAGAIN) {
      cerr << "Could not send Eth packet! (errno = " << errno << ")\n";
    }
    return -1;
  }
  return 0;
}

struct MAC_Table_Entry {
  int dest_port_num; // destination port index
  int tspace_entry_index; // location in tuplespace forwarding table
  MAC_Table_Entry() :
    dest_port_num(-1), tspace_entry_index(-1) { }
  MAC_Table_Entry(int _port_num, int _entry_index) :
    dest_port_num(_port_num), tspace_entry_index(_entry_index) { }
};

typedef hash_map<MAC_Address, MAC_Table_Entry, MAC_Address_Hash> ForwardingTable;

ForwardingTable forwarding_table;

FabricDev::FabricDev(int port_num) : EtherDevBase(), m_src_port_num(port_num) {
  /* do nothing */
}

FabricDev::~FabricDev(){
  /* do nothing */
}

int FabricDev::recv(unsigned char *buffer, int len) {
  cerr << "FabricDev::recv() should not be called\n";
  assert(0);
}

void print_packet(const unsigned char *buf, int packet_len) {
  printf("Got packet: len = %d\n", packet_len);
  int i;
  for(i=0; i < MIN(64, packet_len); i++) {
    if( (i != 0) && (i % 16 == 0) ) {
      printf("\n");
    }
    printf("%02x ", buf[i]);
  }
  printf("\n");
}

enum FilterResult {
  ACCEPT,
  REJECT,
  HANDLED,
  NOVERDICT,
};

struct PacketFilter {
  virtual ~PacketFilter() { };
  virtual FilterResult operator() (const PacketPump &pump, const unsigned char *data, int len) = 0;
};

typedef list<PacketFilter *> PacketFilterChain;

struct PacketPump {
  PacketFilterChain m_filter_chain;
  PacketFilterChain m_output_chain;
  EtherDevBase *m_input;
  EtherDevBase *m_output;
  
  bool m_accept_all_mac;
  bool m_do_local_delivery;
  string m_dbg_name;
  bool m_installed;

  PacketPump(EtherDevBase *input, EtherDevBase *output, bool accept_all_mac, bool do_local_delivery, string dbg_name) : 
    m_input(input), m_output(output),
    m_accept_all_mac(accept_all_mac),
    m_do_local_delivery(do_local_delivery),
    m_dbg_name(dbg_name), m_installed(false) { }

  FilterResult run_chain(const unsigned char *buf, int packet_len, PacketFilterChain *chain, int *loc_p) {
    *loc_p = 0;
    for(PacketFilterChain::iterator i = chain->begin(); 
	i != chain->end(); i++, (*loc_p)++) {
      FilterResult verdict = (**i) (*this, buf, packet_len);
      switch( verdict ) {
      case ACCEPT:
      case REJECT:
      case HANDLED:
	return verdict;
      case NOVERDICT:
	continue;
      }
    }
    return NOVERDICT;
  }

  void operator() (int fd, eventxx::type event) {
    unsigned char buf[ETH_FRAME_LEN];
    // cerr << m_dbg_name << " got event for " << fd << "\n";
    assert(m_input->m_fd == fd);
    assert(event == eventxx::READ);

    int packet_len = m_input->recv(buf, ETH_FRAME_LEN);
    if(packet_len < 0) {
      cerr << "<err>";
      return;
    }
    process_packet(buf, packet_len);
  }

  void process_packet(const unsigned char *buf, int packet_len) {
    struct ethhdr *ethhdr = (struct ethhdr *)buf;
    MAC_Address src_addr(ethhdr->h_source);
    MAC_Address dest_addr(ethhdr->h_dest);
    m_input->add_address(src_addr);

    if( ! ( m_accept_all_mac || m_output->has_address(dest_addr) ) ) {
      //printf(m_dbg_name.c_str()); printf("Rejecting ");  dest_addr.print();
      return;
    }

    // Run filters here
    bool accept = false;
    int loc[2] = {-1,-1};
    vector<PacketFilterChain*> all_chains;
    all_chains.push_back(&m_filter_chain);
    all_chains.push_back(&m_output_chain);
    for(size_t i=0; i < all_chains.size(); i++) {
      FilterResult res = run_chain(buf, packet_len, all_chains[i], &loc[i]);
      switch(res) {
      case ACCEPT:
	// On accept, let the next chain handle it
	accept = true;
	continue;
      case REJECT:
	// On reject, don't process the next chain
	accept = false;
	goto done;
      case HANDLED:
	return;
      case NOVERDICT:
	break;
      }
    }
  done:
    //printf("%s: \n", m_dbg_name.c_str());
    //print_packet(buf, packet_len);

    if(accept || true) {
      if(!accept) {
	static int limit;
	if(limit < 5) {
	  cerr << "Ignoring drop\n";
	  limit++;
	}
      }
      //cerr << "Filter accepted!\n";
      //cerr << "(" << loc << ")";
      //int result = m_output->send(buf, ETH_FRAME_LEN);
      int result = m_output->send(buf, packet_len);
      if(result < 0) {
	// cerr << "Tx error!\n";
	return;
      }
    } else {
      cerr << m_dbg_name.c_str() << "\n";
      cerr << "Filter dropped@" << loc[0] << "," << loc[1] << "!\n";
      // print_packet(buf, packet_len);

      if(!dest_addr.is_broadcast() && ethhdr->h_proto == htons(ETH_P_IP)) {
	unsigned char pkt[ETH_FRAME_LEN];
	int len = ETH_FRAME_LEN;
	struct icmphdr icmp;
	memset(&icmp, 0, sizeof(icmp));
	icmp.type = ICMP_DEST_UNREACH;
	icmp.code = ICMP_HOST_ANO;

	icmp_build(&icmp, buf, pkt, &len);
	m_input->send(pkt, len);
      }
    }
  }
  void install(eventxx::dispatcher *d) {
    assert(!m_installed);
    eventxx::event<PacketPump > *e = 
      new eventxx::event<PacketPump >(m_input->m_fd, eventxx::READ | eventxx::PERSIST, *this);
    d->add(*e);
    m_installed = true;
  }

  FilterResult try_deliver_local(unsigned char *_data, int len) {
    assert(m_do_local_delivery);
    const unsigned char *data = _data;
    const struct ethhdr *eh = (const struct ethhdr *) data;
    const struct iphdr *ih = (const struct iphdr *) (eh + 1);
    check_iphdr(_data, len);

    if(ih->daddr == htonl(local_ip_addr) ||
       ih->daddr == htonl(INADDR_BROADCAST)) {
      deliver_to_local_ip((unsigned char *)ih, len - sizeof(struct ethhdr));
    }

    // don't keep processing packets destined for local IP
    if(ih->daddr == htonl(local_ip_addr)) {
      return HANDLED;
    }
    return NOVERDICT;
  }
};

void print_all(int severity, const char *str) {
  cerr << "<" << severity << ">: " << str << "\n";
}

enum FilterDirection {
  DOWN_TO_UP,
  UP_TO_DOWN,
};

struct AcceptAll : PacketFilter {
  FilterResult operator() (const PacketPump &pump, const unsigned char *data, int len) {
    return ACCEPT;
  }
};

struct FixLocalMAC : PacketFilter {
  FilterResult operator() (const PacketPump &pump, const unsigned char *data, int len) {
    // With all the NICs on the switch, Linux generates sometimes
    // generates ARP responses that direct IP packets to a ipfiltered
    // interface. This code forces the destination MAC to an
    // unfiltered interface.
    assert(check_ethhdr(data, len));
    struct ethhdr *eh = (struct ethhdr *) data;
    if( !(eh->h_proto == htons(ETH_P_IP) && check_iphdr(data, len) ) ) {
      return NOVERDICT;
    }
    const struct iphdr *ih = (const struct iphdr *) (eh + 1);
    if( ih->daddr == htonl(local_ip_addr) ) {
      local_mac_addr.set_buf(eh->h_dest);
    }
    return NOVERDICT;
  }
};

struct AcceptLocal : PacketFilter {
  FilterDirection m_direction;

  AcceptLocal(FilterDirection dir) : m_direction(dir) {
  }

  FilterResult operator() (const PacketPump &pump, const unsigned char *data, int len) {
    struct ethhdr *eh = (struct ethhdr *) data;
    if(eh->h_proto == htons(ETH_P_ARP)) {
      switch(m_direction) {
      case UP_TO_DOWN:
	// allow all arp from switch
	if(local_mac_addr == eh->h_source) {
	  cerr << "Accept local (arp)\n";
	  return ACCEPT;
	}
	break;
      case DOWN_TO_UP:
	// allow all arp to switch
	if(local_mac_addr == eh->h_dest) {
	  cerr << "Accept local (arp response)\n";
	  return ACCEPT;
	}
	break;
      }
      return NOVERDICT;
    }

    // Allow all traffic originating from localhost
    if(m_direction == UP_TO_DOWN) {
      const struct iphdr *ih = (const struct iphdr *) (eh + 1);
      if(!check_iphdr(data, len)) {
	return NOVERDICT;
      }
      if(local_mac_addr == eh->h_source && 
	 ih->saddr == htonl(local_ip_addr)) {
	//cerr << "Accept local (ip)\n";
	return ACCEPT;
      }
    }
    return NOVERDICT;
  }  
};

struct ARPSniffer : PacketFilter {
  // This filter does not modify the event stream, just learns IP <=> MAC mappings
  struct NQ_ARPEntry {
    MAC_Address mac_addr;
    int tspace_entry_index;
    NQ_ARPEntry() : mac_addr(), tspace_entry_index(-1) { }
    NQ_ARPEntry(MAC_Address _addr, int _index) : 
      mac_addr(_addr), tspace_entry_index(_index) { }
  };
  typedef map<IP_Address, NQ_ARPEntry> NQ_ARPTable;

  NQ_ARPTable m_arp_table;

  void print_arp_table();

  void update_mapping(IP_Address ip, MAC_Address mac) {
    NQ_ARPTable::iterator entry = m_arp_table.find(ip);
    try {
      Transaction t(trust_all, trust_attrval_all, switch_owner->home, switch_owner);
      T_SwitchFabric fabric(t, g_switch_fabric_tid);
      Switch sw(t, g_switch_tid);
      int tspace_index;
      T_ARPEntry *arp_entry = NULL;
      if(entry == m_arp_table.end()) {
	cerr << "Adding new ARP " << mac << " => " << ip << "\n";
	arp_entry = new T_ARPEntry(t);
	arp_entry->tspace_create();
	arp_entry->ip = ip;
	arp_entry->mac = mac;

	tspace_index = fabric.arp_table.size();
	cerr << "About to set tspace index of " << tspace_index << "\n";
	fabric.arp_table.push_back(arp_entry);
	m_arp_table[ip] = NQ_ARPEntry(mac, tspace_index);
      } else if(entry->second.mac_addr != mac) {
	cerr << "Updating ARP " << mac << " => " << ip << "\n";
	tspace_index = entry->second.tspace_entry_index;
	cerr << "Index is " << tspace_index << "\n";
	arp_entry = fabric.arp_table[tspace_index].load();
	assert(arp_entry->ip.load() == ip);
	arp_entry->mac = mac;
	entry->second.tspace_entry_index = tspace_index;
      }
      t.commit();
      if(arp_entry != NULL) {
	delete arp_entry;
      }
    } catch(...) {
      cerr << "Error while adding new ARP entry??? disallowed\n";
      exit(-1);
    }
  }

  FilterResult operator() (const PacketPump &pump, const unsigned char *_data, int len) {
    const unsigned char *data = _data;
    if(!check_arphdr(data, len)) {
      return NOVERDICT;
    }
    const struct ethhdr *eh = (const struct ethhdr *) data;
    const struct arphdr *ah = (const struct arphdr *) (eh + 1);
    ARP::IPv4 *v4_hdr = (ARP::IPv4 *)  (ah + 1);
 switch(ntohs(ah->ar_op)) {
    case ARPOP_REPLY:
      update_mapping(v4_hdr->ar_sip, MAC_Address(v4_hdr->ar_sha));
      update_mapping(v4_hdr->ar_tip, MAC_Address(v4_hdr->ar_tha));
      return NOVERDICT;
    default:
      return NOVERDICT;
    }
  }
};

void ARPSniffer::print_arp_table() {
  for(NQ_ARPTable::iterator entry = m_arp_table.begin();
      entry != m_arp_table.end(); entry++) {
    cerr << entry->first << ": " << entry->second.mac_addr << " (idx = " <<
      entry->second.tspace_entry_index << ")\n";
  }
}

struct ARPRewrite : PacketFilter {
  typedef map<IP_Address, MAC_Address> ARPTable;
  ARPTable m_arp_table;
  typedef vector<IP_Address> WhiteList;
  WhiteList whitelist;

  void add_entry(IP_Address ip) {
    m_arp_table[ip] = ARP::lookup(ip);
  }

  void add_entry(IP_Address ip, MAC_Address mac) {
    m_arp_table[ip] = mac;
  }

  void add_whitelist(IP_Address ip) {
    // cerr << "add whitelist\n";
    whitelist.push_back(ip);
  }

  FilterResult operator() (const PacketPump &pump, const unsigned char *_data, int len) {
    const unsigned char *data = _data;
    if(!check_arphdr(data, len)) {
      return NOVERDICT;
    }
    const struct ethhdr *eh = (const struct ethhdr *) data;
    const struct arphdr *ah = (const struct arphdr *) (eh + 1);
    if(ah->ar_op != htons(ARPOP_REQUEST)) {
      // cerr << "not arp request\n";
      return NOVERDICT;
    }
    ARP::IPv4 *v4_hdr = (ARP::IPv4 *)  (ah + 1);

    for(WhiteList::iterator i = whitelist.begin(); i != whitelist.end(); i++) {
      // cerr << "whitelist " << *i << ntohl(v4_hdr->ar_tip) << "\n";
      if(*i == ntohl(v4_hdr->ar_tip)) {
	cerr << "whitelist match\n";
	return ACCEPT;
      }
    }

    ARPTable::iterator i = m_arp_table.find(ntohl(v4_hdr->ar_tip));
    if(i != m_arp_table.end()) {
      MAC_Address mac_addr = i->second;
      // Do proxy arp for TFTP server to avoid having to handle ARP
      // cerr << "Doing proxy arp\n";

      // This code assumes that a bogus source MAC, which is used to
      // derive the dest MAC of the new packet, cannot trick the
      // pump into sending packets out the wrong interface / to the
      // wrong destination.
      unsigned char buf[ETH_FRAME_LEN];
      struct ethhdr *output_eh = (struct ethhdr *) buf;
      mac_addr.set_buf(output_eh->h_source);
      memcpy(output_eh->h_dest, eh->h_source, ETH_ALEN);
      output_eh->h_proto = htons(ETH_P_ARP);

      struct arphdr *output_ah = (struct arphdr *) (output_eh + 1);
      output_ah->ar_hrd = htons(ARPHRD_ETHER);
      output_ah->ar_pro = htons(ETH_P_IP);
      output_ah->ar_hln = ETH_ALEN;
      output_ah->ar_pln = 4; // ip address
      output_ah->ar_op = htons(ARPOP_REPLY);

      ARP::IPv4 *output_v4_hdr = (ARP::IPv4 *) 
	(unsigned char *)(output_ah + 1);
      mac_addr.set_buf(output_v4_hdr->ar_sha);
      output_v4_hdr->ar_sip = v4_hdr->ar_tip;
      memcpy(output_v4_hdr->ar_tha, v4_hdr->ar_sha, ETH_ALEN);
      output_v4_hdr->ar_tip = v4_hdr->ar_sip;

      int len = (unsigned char *)(output_v4_hdr + 1) - buf;
      pump.m_input->send(buf, len);
      return HANDLED;
    } else {
      cerr << "unrecognized arp\n";
      return NOVERDICT;
    }
  }
};

struct AcceptDHCP : PacketFilter {
  FilterDirection m_direction;
  IP_Address m_server_ip;

  MAC_Address m_server_mac;

  EtherDevBase *m_down;
  ARPRewrite *m_rewrite;

  SwitchPort *m_port;

  AcceptDHCP(FilterDirection dir, IP_Address server_ip, SwitchPort *_port, ARPRewrite *rewrite) :
    m_direction(dir), m_server_ip(server_ip), m_down(_port->m_down), m_rewrite(rewrite), m_port(_port) {
    m_server_mac = ARP::lookup(server_ip);
  }
  FilterResult operator() (const PacketPump &pump, const unsigned char *data, int len) {
    struct ethhdr *eh = (struct ethhdr *) data;
    const struct iphdr *ih = (const struct iphdr *) (eh + 1);
    const struct udphdr *uh = (const struct udphdr *) 
      ((unsigned char *) ih + ih->ihl * 4);
    if(!check_udphdr(data, len)) {
      return NOVERDICT;
    }

    switch(m_direction) {
    case DOWN_TO_UP: {
      MAC_Address dest_mac(eh->h_dest);
      if( !((ih->daddr == m_server_ip || ih->daddr == htonl(INADDR_BROADCAST)) &&
	    (uh->source == htons(BOOTPC) && uh->dest == htons(BOOTPS)) &&
	    (dest_mac == m_server_mac || dest_mac.is_broadcast()) ) ) {
	return NOVERDICT;
      }
      const struct bootphdr *bh = (const struct bootphdr *) (uh + 1);
      if(!check_len(data, bh + 1, len)) {
	cerr << "Bootp header too short!\n";
	return NOVERDICT;
      }
      if(bh->op == BOOTP_OP_REQUEST) {
	m_port->new_state(SwitchPort::GETTING_IP);
      }
      if( false && dest_mac.is_broadcast() ) {
	// rewriting causes problems when host doesn't yet know how to
	// route to this destination
	cerr << "Rewriting DHCP destination\n";
	m_server_mac.set_buf(eh->h_dest);
	return ACCEPT;
      }
      return ACCEPT;
    }
    case UP_TO_DOWN: {
      // we trust the UP network, so we don't do IP checking
      if( !(uh->source == htons(BOOTPS) && uh->dest == htons(BOOTPC)) ) {
	return NOVERDICT;
      }
      cerr << "*********** Received DHCP *********** \n";
      const struct bootphdr *bh = (const struct bootphdr *) (uh + 1);
      m_down->m_ip_addr = ntohl(bh->yiaddr);
      if(bh->op == BOOTP_OP_REPLY) {
	// XXX Hack. Original design reset to GETTING_IP on down to up
	// BOOTP request. However, with vmnet, these packets don't
	// show up.
	m_port->new_state(SwitchPort::GETTING_IP);
	m_port->new_state(SwitchPort::HAS_IP);
      }
      if(m_rewrite != NULL) {
	//m_rewrite->add_entry(m_down->m_ip_addr, MAC_Address((const unsigned char *)bh->chaddr));
	m_rewrite->add_whitelist(m_down->m_ip_addr);
      }
      return ACCEPT;
    }
    default:
      assert(0);
    }
    // not reached
    assert(0);
  }
};

struct IPIngress : PacketFilter {
  FilterResult operator() (const PacketPump &pump, const unsigned char *_data, int len) {
    if(!check_iphdr(_data, len)) {
      return NOVERDICT;
    }
    const unsigned char *data = _data;
    const struct ethhdr *eh = (const struct ethhdr *) data;
    const struct iphdr *ih = (const struct iphdr *) (eh + 1);

    if(!(ih->saddr == htonl(pump.m_input->m_ip_addr) || ih->saddr == 0)) {
      static int limit;
      if(limit < 5) {
	cerr << "Bad source address!\n";
	limit++;
      }
      return REJECT;
    }
    return NOVERDICT;
  }
};
struct AcceptTFTP : PacketFilter {
  // The TFTP filter allows all UDP traffic to and from the TFTP server
  FilterDirection m_direction;
  IP_Address m_server_ip;
  IP_Port m_server_port;

  MAC_Address m_server_mac;

  AcceptTFTP(FilterDirection dir, IP_Address server_ip, IP_Port server_port) :
    m_direction(dir), m_server_ip(server_ip), m_server_port(server_port) {
    m_server_mac = ARP::lookup(server_ip);
  }
  virtual ~AcceptTFTP() { /* do nothign */ }

  FilterResult operator() (const PacketPump &pump, const unsigned char *_data, int len) {
    struct ethhdr *eh = (struct ethhdr *) _data;
    const struct iphdr *ih = (const struct iphdr *) (eh + 1);
    const unsigned char *data = _data;
    if(!check_udphdr(data, len)) {
      return NOVERDICT;
    }

    bool accept = false;
    switch(m_direction) {
    case DOWN_TO_UP:
      if(ih->daddr == htonl(m_server_ip)) {
	// rewrite destination MAC
	m_server_mac.set_buf(eh->h_dest);
	accept = true;
      }
      break;
    case UP_TO_DOWN:
      // XXX This code does not verify that the packet was generated
      // by the local machine
      if(ih->saddr == htonl(m_server_ip) && 
	 m_server_mac == eh->h_source) {
	accept = true;
      }
      break;
    default:
      assert(0);
    }

    return accept ? ACCEPT : NOVERDICT;
  }
};

struct AcceptTCP : PacketFilter {
  enum MatchAgainst {
    SOURCE,
    DEST,
  };

  MatchAgainst m_match;
  IP_Address m_server_ip;
  IP_Port m_server_port; // port == 0 means wildcard

  AcceptTCP(MatchAgainst match, IP_Address server_ip, IP_Port server_port) : 
    m_match(match),
    m_server_ip(server_ip),
    m_server_port(server_port)
  {
    // do nothing
  }

  FilterResult operator() (const PacketPump &pump, const unsigned char *_data, int len) {
    struct ethhdr *eh = (struct ethhdr *) _data;
    const struct iphdr *ih = (const struct iphdr *) (eh + 1);
    const struct tcphdr *th = (const struct tcphdr *) 
      ((unsigned char *) ih + ih->ihl * 4);
    const unsigned char *data = _data;
    if(!check_tcphdr(data, len)) {
      return NOVERDICT;
    }

    IP_Address addr;
    IP_Port port;
    switch(m_match) {
    case SOURCE:
      addr = ntohl(ih->saddr);
      port = ntohs(th->source);
      break;
    case DEST:
      addr = ntohl(ih->daddr);
      port = ntohs(th->dest);
      break;
    default:
      assert(0);
    }
    if(m_server_ip == addr && (m_server_port == 0 || m_server_port == port) ) {
      return ACCEPT;
    } else {
      return NOVERDICT;
    }
  }
};

struct AcceptNexusBootd : PacketFilter {
  FilterDirection m_direction;

  AcceptNexusBootd(FilterDirection dir) : m_direction(dir) {
    // do nothing
  }
  FilterResult operator() (const PacketPump &pump, const unsigned char *_data, int len) {
    const unsigned char *data = _data;
    const struct ethhdr *eh = (const struct ethhdr *) data;
    const struct iphdr *ih = (const struct iphdr *) (eh + 1);
    const struct udphdr *uh = (const struct udphdr *) 
      ((unsigned char *) ih + ih->ihl * 4);

    if(!check_udphdr(data, len)) {
      return NOVERDICT;
    }
    IP_Port check_port = 0;
    switch(m_direction) {
    case DOWN_TO_UP:
      check_port = ntohs(uh->dest);
      break;
    case UP_TO_DOWN:
      check_port = ntohs(uh->source);
      break;
    default:
      assert(0);
    }
    if(8152 <= check_port && check_port <= 8161) {
      // cerr << "Nexusbootd udp packet\n";
      return ACCEPT;
    }
    return NOVERDICT;
  }
};

struct RejectBroadcast : PacketFilter {
  virtual ~RejectBroadcast() { /* do nothign */ }
  FilterResult operator() (const PacketPump &pump, const unsigned char *_data, int len) {
    const unsigned char *data = _data;
    const struct ethhdr *eh = (const struct ethhdr *) data;
    MAC_Address dest_addr(eh->h_dest);
    if(dest_addr.is_broadcast()) {
      cerr << "got broadcast packet, rejecting\n";
      return REJECT;
    }
    return NOVERDICT;
  }  
};

struct AH_Key {
  // HMAC-128
  static const unsigned int KEY_LEN;
  static const unsigned int MAC_LEN;

  unsigned char *m_key;
  HMAC_CTX m_hmac_ctx;

  AH_Key(void) {
    m_key = new unsigned char[KEY_LEN];
    memset(m_key, 0, KEY_LEN);
    HMAC_CTX_init(&m_hmac_ctx);
  }
  ~AH_Key() {
    HMAC_CTX_cleanup(&m_hmac_ctx);
    delete [] m_key;
  }
  void change_key(const void *key) {
    memcpy(m_key, key, KEY_LEN);
  }
  void compute_mac(const unsigned char *data, int len, unsigned char *output) {
    unsigned char mac[128];
    unsigned int md_len = sizeof(mac);
    HMAC(EVP_sha1(), m_key, KEY_LEN, data, len, mac, &md_len);
    assert(md_len >= MAC_LEN);
    memcpy(output, mac, MAC_LEN);
  }
};

const unsigned int AH_Key::KEY_LEN = L2SEC_KEYLEN;
const unsigned int AH_Key::MAC_LEN = L2SEC_MACLEN;

// Linux TCP wraparound arith functions
/*
 * The next routines deal with comparing 32 bit unsigned ints
 * and worry about wraparound (automatic with unsigned arithmetic).
 */

static inline int before(__u32 seq1, __u32 seq2)
{
        return (__s32)(seq1-seq2) < 0;
}

static inline int after(__u32 seq1, __u32 seq2)
{
        return (__s32)(seq2-seq1) < 0;
}


/* is s2<=s1<=s3 ? */
static inline int between(__u32 seq1, __u32 seq2, __u32 seq3)
{
        return seq3 - seq2 >= seq1 - seq2;
}


struct L2sec_AH : PacketFilter {
  FilterDirection m_direction;
  struct AH_Key *m_key;
  unsigned int m_seqnum;
  PacketPump *m_pump;

#define AH_WINDOW (1) // window size of 1
  unsigned int m_window_next;

  bool m_enabled;

  L2sec_AH(FilterDirection dir, PacketPump *pump) : 
    m_direction(dir), m_key(NULL), 
    m_seqnum(0), m_pump(pump), m_window_next(0),
    m_enabled(false) {
    reset();
  }
  FilterResult operator() (const PacketPump &pump, const unsigned char *_data, int len) {
    if(!m_enabled) {
      return NOVERDICT;
    }
    const int AUTH_FRAMELEN = ETH_FRAME_LEN - sizeof(struct l2sechdr);
    if(m_key == NULL) {
      return NOVERDICT;
    }
    const struct ethhdr *eh = (const struct ethhdr *) _data;
    struct l2sechdr *auth = NULL;
    assert(check_ethhdr(_data, len));
    switch(ntohs(eh->h_proto)) {
    case ETH_P_ARP: {
      if(!check_arphdr(_data, len)) {
	return NOVERDICT;
      }
      const struct arphdr *ah = (const struct arphdr *) (eh + 1);
      ARP::IPv4 *v4_hdr = (ARP::IPv4 *)  (ah + 1);
      auth = (struct l2sechdr *) (v4_hdr + 1);
      break;
    }
    case ETH_P_IP: {
      const struct iphdr *ih = (const struct iphdr *) (eh + 1);
      auth = (struct l2sechdr *) ((unsigned char *)ih + ntohs(ih->tot_len));
      break;
    }
    default:
      cerr << "unsupported ethernet type " << ntohs(eh->h_proto) << "\n";
      return NOVERDICT;
    }
    assert(auth != NULL);

    switch(m_direction) {
    case UP_TO_DOWN: {
      // Attach authenticator
      // cerr << "Up to down: append authenticator\n";
      if( len > AUTH_FRAMELEN ) {
	cerr << "Packet too long!\n";
	if(ntohs(eh->h_proto) == ETH_P_IP) {
	  // send back ICMP would fragment
	  unsigned char pkt[ETH_FRAME_LEN];
	  int len = ETH_FRAME_LEN;
	  struct icmphdr icmp;
	  memset(&icmp, 0, sizeof(icmp));
	  icmp.type = ICMP_DEST_UNREACH;
	  icmp.code = ICMP_FRAG_NEEDED;
	  icmp.un.frag.mtu = htons(AUTH_FRAMELEN - ETH_HLEN);

	  icmp_build(&icmp, _data, pkt, &len);
	  m_pump->m_input->send(pkt, len);
	}
	return HANDLED;
      }
      auth->seqnum = htonl(m_seqnum);
      m_seqnum += 1;
      const unsigned char *start = _data;
      int mac_len = (unsigned char *)&auth->auth[0] - start;
      unsigned char mac[128];
      m_key->compute_mac(start, mac_len, mac);
      memcpy(auth->auth, mac, AH_Key::MAC_LEN);
      // cerr << "old len = " << len << " new len = " << (len + sizeof(struct l2sechdr)) << "\n";;
      len += sizeof(struct l2sechdr);

      // cerr << "Wrapping\n";
      m_pump->m_output->send(_data, len);
      return HANDLED;
    }
    case DOWN_TO_UP: {
      // Accept only packets with the proper authenticator
      if(!check_len(_data, auth + 1, len)) {
	// cerr << "auth check: auth header past end of packet\n";
	// not REJECT, since this might be a packet without an
	// authenticator that would otherwise be accepted
	return NOVERDICT;
      }
      unsigned char mac[128];
      const unsigned char *start = _data;
      m_key->compute_mac(start, auth->auth - start, mac);
      if(memcmp(auth->auth, mac, AH_Key::MAC_LEN) != 0) {
	cerr << "MAC mismatch, seqnum = " << setbase(16) << auth->seqnum << setbase(10) << " \n";
	return REJECT;
      }
      unsigned int seqnum = ntohl(auth->seqnum);
      // Process sliding window. No reordering is accepted, since
      // we're on a point to point link
      if(seqnum == m_window_next || after(seqnum, m_window_next)) {
	m_window_next = seqnum + 1;
	// cerr << "Sequence good: " << m_window_next << ", " << seqnum << " \n";
	return NOVERDICT;
      } else {
	cerr << "Sequence mismatch: " << m_window_next << ", " << seqnum << " \n";
	return REJECT;
      }
    }
    default:
      assert(0);
    }
  }

  void set_key(AH_Key *k) {
    m_key = k;
  }
  void reset() {
    m_seqnum = 0;
    m_window_next = 0;
  }

  void enable() {
    m_enabled = true;
  }
  void disable() {
    m_enabled = false;
  }
};

struct TCP_Flow {
  uint32_t saddr;
  uint16_t sport;
  uint32_t daddr;
  uint16_t dport;
  TCP_Flow(uint32_t sa, uint16_t sp, uint32_t da, uint16_t dp) :
    saddr(sa), sport(sp), daddr(da), dport(dp) { }
  bool operator==(const TCP_Flow &other) const {
    return 
      saddr == other.saddr && sport == other.sport &&
      daddr == other.daddr && dport == other.dport;
  }
} __attribute__((packed));

ostream &operator<<(ostream &os, const TCP_Flow &flow) {
  NQ_Host src;
  NQ_Host dst;
  src.addr = flow.saddr;
  src.port = ntohs(flow.sport);
  dst.addr = flow.daddr;
  dst.port = ntohs(flow.dport);
  os << "[" << src << " => " << dst << "]";
  return os;
}

struct TCP_Flow_Hash {
   size_t operator()(const TCP_Flow &f) const {
    return (size_t)SuperFastHash((char*)&f, sizeof(f));
  }
};

typedef hash_set<TCP_Flow, TCP_Flow_Hash> TCP_Flow_Set;

struct TCP_Firewall : PacketFilter {
  TCP_Flow_Set allowed_flows;
  ClientPort *port;

  TCP_Firewall(ClientPort *_port) : port(_port)
  {
    // do nothing
  }

  FilterResult operator() (const PacketPump &pump, const unsigned char *_data, int len) {
    struct ethhdr *eh = (struct ethhdr *) _data;
    const struct iphdr *ih = (const struct iphdr *) (eh + 1);
    const struct tcphdr *th = (const struct tcphdr *) 
      ((unsigned char *) ih + ih->ihl * 4);
    const unsigned char *data = _data;
    if(!check_tcphdr(data, len)) {
      return NOVERDICT;
    }

    TCP_Flow flow(ih->saddr, th->source, ih->daddr, th->dest);
    if(allowed_flows.find(flow) != allowed_flows.end()) {
      return ACCEPT;
    } else {
      if(!g_test_tcp_forward) {
	cerr << "Doing tuplespace update for new TCP flow\n";
	try {
	  pthread_mutex_lock(&nq_update_mutex);
	  Transaction t(trust_all, trust_attrval_all, switch_owner->home, switch_owner);
	  T_FirewallTable switch_fw(t, port->switch_fw_table);
	  T_TCPFlowEntry *new_flow = new T_TCPFlowEntry(t);
	  new_flow->tspace_create();
	  new_flow->saddr = flow.saddr;
	  new_flow->sport = flow.sport;
	  new_flow->daddr = flow.daddr;
	  new_flow->dport = flow.dport;
	  switch_fw.entries.push_back(new_flow);
	  t.commit();
	  pthread_mutex_unlock(&nq_update_mutex);
	  // insert after accepted by commit
	  allowed_flows.insert(flow);
	  cerr << "TCP flow accepted\n";
	  return ACCEPT;
	} catch(...) {
	  cerr << "Error while adding new TCP flow, not accepting it\n";
	  pthread_mutex_unlock(&nq_update_mutex);
	  return NOVERDICT;
	}
      } else {
	cerr << "Testing TCP forwarding: accepting " << flow << "\n";
	allowed_flows.insert(flow);
	return ACCEPT;
      }
    }
  }
};


bool SwitchPort::nq_try_port_update(SSL_Connection *ssl, bool verify_result) {
  cerr << "Writing and connecting host\n";
  try {
    Transaction t(trust_all, trust_attrval_all, switch_owner->home, switch_owner);
    Host *host;
    try {
      host = new Host(t, peer_tid);
    } catch(...) {
      cerr << "Could not load host\n";
      throw "again";
    }
    cerr << "Host is " << peer_tid << " process list len = " << host->process_list->elems.size() << "\n";
    cerr << "Comparing SSL certificate stack with tuplespace stack\n";
    if(ssl != NULL) {
      cerr << "Verify size is " << ssl->verify_info.cert_chain.size() << "\n";
      // Compare the root
      cerr << "Tuplespace cert chain is " << host->composite_element->certificate_chain.size() << "\n";

      if( !(ssl->verify_info.cert_chain.size() >= 2 &&
	    host->composite_element->certificate_chain.size() >= 2)) {
	cerr << "Could not verify certificate chain " <<
	  ssl->verify_info.cert_chain.size() << " , " <<
	  host->composite_element->certificate_chain.size() << "\n";
	verify_result = false;
	goto done_verifying;
      }
      int ssl_pos = ssl->verify_info.cert_chain.size() - 1;
      int tspace_pos = host->composite_element->certificate_chain.size() - 1;
      for(int i=0; i < 2; i++) {
	DataBuffer d;
	x509_to_pem(ssl->verify_info.cert_chain[ssl_pos - i], d);
	d.push_back('\0');
	T_X509 *x509 = 
	  host->composite_element->certificate_chain[tspace_pos - i].load();

	if(strcmp((char *)vector_as_ptr(d), (char *)x509->val.load().c_str()) != 0) {
	  cerr << "Could not verify certificate chain at " << i << "\n";
	  verify_result = false;
	  goto done_verifying;
	}
      }
      cerr << "Certificate chain in tuplespace verified to match attaching host\n";
    }
  done_verifying:

    cerr << "XXX Need to verify that hash matches nq-exporter\n";
    cerr << "Host certificate chain size is now " << host->composite_element->certificate_chain.size() << "\n";

    cerr << "Connecting host to switch in tspace\n";
    T_Interface *port = new T_Interface(t, port_tid);
    port->external_connection = host->nic;
    port->external_connection_verified = verify_result;

    t.commit();
    // cerr << "Enable(): Done with tspace operations\n";
  } catch(NQ_Exception &e) {
    cerr << "\"" << e << "\" while writing host transaction, not enabling connection\n";
    goto finish_error;
  } catch(...) {
    cerr << "Generic error while writing host transaction, not enabling connection\n";
    goto finish_error;
  }
  cerr << "Updated NQ port\n";
  return true;
 finish_error:
  l2sec_disable();
  return false;
}

static void *do_l2sec_setup_thread(void *ctx) {
  SwitchPort *port = (SwitchPort*)ctx;
  // cerr << "l2sec setup thread\n";
  return port->do_l2sec_down_setup();
}

void *SwitchPort::do_l2sec_down_setup() {
  while(1) {
  again: ;

    int /*on=1, */off=0;
    int client_sock = tcp_socket(INADDR_ANY, 0, false);
    // ioctl(client_sock, FIONBIO, &on);
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htonl(m_down->m_ip_addr);
    server_addr.sin_port = htons(g_l2secd_server_port);
    cerr << "Try connect\n";
    int result = connect(client_sock, (struct sockaddr *) &server_addr, sizeof(server_addr));
    if(result < 0 && errno != EINPROGRESS) {
      cerr << "Error connecting: peer not responding to discovery request\n";
      sleep(10);
      continue;
    }
    struct pollfd pfd[1] = {
      { client_sock, POLLOUT, 0 }
    };
    int nfds = poll(pfd, 1, 5000);
    if( nfds <= 0 || !(pfd[0].revents & POLLOUT) ) {
      cerr << "Could not connect\n";
      goto again;
    }
    // restore blocking mode
    ioctl(client_sock, FIONBIO, &off);
    cerr << "Connected\n";

    L2Sec::Client *client = new L2Sec::Client(NULL, client_sock, server_addr);
    X509 *cert = client->get_peer_certificate();
    int verify_result = client->get_verify_result();
    cerr << "Peer certificate is " << cert << ", verified as " << verify_result <<"\n";

    if(verify_result != 0) {
      cerr << "Could not verify SSL certificate chain!\n";
    }

    peer_tid = client->GetTID(port_tid);
    assert(peer_tid != NQ_uuid_null);
    
    cerr << "Sleeping before reading host tuple\n";
    sleep(1);
    pthread_mutex_lock(&l2sec_init_mutex);
    if(!nq_try_port_update(client, verify_result)) {
      cerr << "Error updating NQ for new end host???\n";
      peer_tid = NQ_uuid_null;
      pthread_mutex_unlock(&l2sec_init_mutex);
      cerr << "Going back to connect\n";
      sleep(30); // hack to prevent looping
      goto again;
    }
    if(l2sec_updown != NULL) {
      // these are not allocated in ssl test
      l2sec_updown->enable();
      l2sec_downup->enable();
    }
    pthread_mutex_unlock(&l2sec_init_mutex);

    if(g_test_ssl) {
      cerr << "Test SSL, don't set key\n";
      client->write("A", 1);
      while(1) {
	sleep(1);
      }
      return NULL;
    }
    
    if(l2sec_updown != NULL) {
      cerr << "Set new key!\n";
      int rv = client->NewKey(key->m_key, L2SEC_KEYLEN);
      l2sec_updown->reset();
      l2sec_downup->reset();
      if(rv == 0) {
	l2sec_downup->enable();
	l2sec_updown->enable();
      } else {
	cerr << "Disabling l2sec checks because peer did not set key\n";
	l2sec_downup->disable();
	l2sec_updown->disable();
      }
      // XXX need to update the tuplespace to reflect l2sec enablement state
    }

    cerr << "************ Done with link setup! Client can now send data! ************ \n";
    
    return NULL;
  }
}

void SwitchPort::l2sec_reset(IP_Address addr) {
  pthread_mutex_lock(&l2sec_init_mutex);
  bool fixed_key = false;
  static bool generated_key = false;

  if(key == NULL) {
    key = new AH_Key();
  }
  if(!generated_key) {
    generated_key = true;
    unsigned char key_bytes[AH_Key::KEY_LEN];
    if(!fixed_key) {
      cerr << "Generating random key\n";
      RAND_bytes(key_bytes, AH_Key::KEY_LEN);
    } else {
      cerr << "Using fixed key\n";
      memset(key_bytes, 0xff, sizeof(key_bytes));
    }
    key->change_key(key_bytes);

    l2sec_updown->set_key(key);
    l2sec_downup->set_key(key);
  }

  l2sec_updown->reset();
  l2sec_downup->reset();
  pthread_mutex_unlock(&l2sec_init_mutex);
}

void SwitchPort::l2sec_enable(void) {
  start_l2sec_setup_and_enable();
}

void SwitchPort::l2sec_disable(void) {
  pthread_mutex_lock(&l2sec_init_mutex);
  try {
    pthread_mutex_lock(&nq_update_mutex);
    Transaction t(trust_all, trust_attrval_all, switch_owner->home, switch_owner);
    T_Interface *port = new T_Interface(t, port_tid);
    T_Interface *other = port->external_connection.load();
    if(other != NULL) {
      assert(peer_tid != NQ_uuid_null);
      Host new_host(t, peer_tid);
      if(new_host.nic != other) {
	cerr << "Host nic configuration changed???\n";
	t.abort();
	throw "Unexpected nic configuration\n";
      }
      cerr << "Clearing self and other\n";
      other->external_connection.store(NQ_uuid_null);
      port->external_connection.store(NQ_uuid_null);
      delete other;
    }
    t.commit();
    peer_tid = NQ_uuid_null;
    cerr << "Disable(): Done with tspace operations\n";
  } catch(...) {
    pthread_mutex_unlock(&nq_update_mutex);
    cerr << "Fatal error while detaching host???\n";
    exit(-1);
  }
  pthread_mutex_unlock(&nq_update_mutex);
  l2sec_updown->disable();
  l2sec_downup->disable();
  pthread_mutex_unlock(&l2sec_init_mutex);
}

ARPSniffer arp_sniffer;
void SwitchPort::initialize_filter_chains_common(eventxx::dispatcher *d) {
  cerr << "Common port num is " << port_num << "\n";
  assert(down_to_up == NULL && up_to_down == NULL && m_fabric_up == NULL && arp_rewrite == NULL);
  m_fabric_up = new FabricDev(port_num);
  down_to_up = new PacketPump(m_down, m_fabric_up, true, true, "down_to_up");
  up_to_down = new PacketPump(m_fabric_up, m_down, false, false, "up_to_down");

  down_to_up->m_filter_chain.push_back(&arp_sniffer);
  up_to_down->m_filter_chain.push_back(&arp_sniffer);
}

void ClientPort::initialize_filter_chains(eventxx::dispatcher *d) {
  const bool bypass_filter = false;

  initialize_filter_chains_common(d);

  // Initial state: Allow restricted DHCP, nexusbootd, and TFTP in
  // either direction.

  // We need to do this even though we trust the internal network --
  // though the internal network has no bad traffic, we can't let
  // any traffic leak across to an unauthorized host

  // Auth state: Allow packets with L2 MAC on down_to_up ; allow all packets from up_to_down

  arp_rewrite = new ARPRewrite();
  arp_rewrite->add_entry(g_dhcp_server_addr);
  arp_rewrite->add_entry(g_tftp_server_addr);

  l2sec_downup = new L2sec_AH(DOWN_TO_UP, NULL);
  l2sec_updown = new L2sec_AH(UP_TO_DOWN, up_to_down);

  if(bypass_filter) {
    cerr << "Bypassing filter\n";
  }

  TCP_Firewall *tcp_firewall = new TCP_Firewall(this);
  if(!bypass_filter) {
    down_to_up->m_filter_chain.push_back(arp_rewrite);
    down_to_up->m_filter_chain.push_back(new AcceptLocal(DOWN_TO_UP));
    down_to_up->m_filter_chain.push_back(new IPIngress());
    down_to_up->m_filter_chain.push_back(new AcceptDHCP(DOWN_TO_UP, g_dhcp_server_addr, this, NULL));
    down_to_up->m_filter_chain.push_back(new AcceptTFTP(DOWN_TO_UP, g_tftp_server_addr, g_tftp_server_port));
    down_to_up->m_filter_chain.push_back(new AcceptTCP(AcceptTCP::DEST, g_trusted_server_addr, 0));
    down_to_up->m_filter_chain.push_back(new AcceptNexusBootd(DOWN_TO_UP));
    down_to_up->m_filter_chain.push_back(l2sec_downup);
    // putting RejectBroadcast after l2sec processing results in
    // accepting broadcasts only if they are accepted by l2sec
    down_to_up->m_filter_chain.push_back(new RejectBroadcast());

    if(g_use_tcp_firewall) {
      down_to_up->m_filter_chain.push_back(tcp_firewall);
    }
  } else {
    down_to_up->m_filter_chain.push_back(new AcceptAll());
  }

  down_to_up->m_output_chain.push_back(new FixLocalMAC());

  if(!bypass_filter) {
    up_to_down->m_filter_chain.push_back(new AcceptLocal(UP_TO_DOWN));
    up_to_down->m_filter_chain.push_back(new AcceptDHCP(UP_TO_DOWN, g_dhcp_server_addr, this, arp_rewrite));
    up_to_down->m_filter_chain.push_back(new AcceptTFTP(UP_TO_DOWN, g_tftp_server_addr, g_tftp_server_port));
    up_to_down->m_filter_chain.push_back(new AcceptTCP(AcceptTCP::SOURCE, g_trusted_server_addr, 0));
    up_to_down->m_filter_chain.push_back(new AcceptNexusBootd(UP_TO_DOWN));

    if(g_use_tcp_firewall) {
      up_to_down->m_filter_chain.push_back(tcp_firewall);
    }
    // up_to_down->m_filter_chain.push_back(new RejectBroadcast());
  }

  // l2sec needs to be last in up/down direction because it handles the packet (i.e. encrypts & sends it), rather than pass through with NOVERDICT
  up_to_down->m_output_chain.push_back(l2sec_updown);

  down_to_up->install(d);
}

void ExternalPort::initialize_filter_chains(eventxx::dispatcher *d) {
  initialize_filter_chains_common(d);
  // no filter rules

  down_to_up->install(d);
}

void SwitchPort::start_l2sec_setup_and_enable(void) {
  cerr << "Starting l2sec thread\n";
  pthread_t setup_thread;
  pthread_create(&setup_thread, NULL, do_l2sec_setup_thread, this);
}

static inline void do_nq_test() {
  cerr << "Writing switch info\n";
  cerr << "Not updated to use new switchport design\n";
  ClientPort test_port(NQ_uuid_null, NQ_uuid_null, 0, NULL);
  bool success = test_port.nq_try_port_update(NULL, false);
  cerr << "Switch write success " << success << "\n";
  if(!success) {
    cerr << ">>>>>>>>>>>>>>>> Could not write switch!\n";
  }
  cerr << "Deactivating switch\n";
  test_port.deactivate();
  exit(success ? 0 : -1);
}

void start_forwarding(int argc, char **argv) {
  if(g_test_ssl) {
    cerr << "trying to connect to local l2secd\n";
    //start_l2sec_setup_and_enable();
    cerr << "Not updated to use new switchport design\n";
    ClientPort test_port(NQ_uuid_null, NQ_uuid_null, 0, NULL);
    test_port.start_l2sec_setup_and_enable();
    cerr << "sleeping forever\n";
    while(1) sleep(1);
    return;
  }

  setup_local_networking();

  if(argc < 4) {
    cerr << "Usage: <external if name> <tftp server ip> <tftp server port> <dhcp server ip> <trusted ip> \n";
    exit(-1);
  }
  g_tftp_server_addr = ntohl(inet_addr(argv[0]));
  g_tftp_server_port = atoi(argv[1]);

  g_dhcp_server_addr = ntohl(inet_addr(argv[2]));
  g_trusted_server_addr = ntohl(inet_addr(argv[3]));

  {
    struct in_addr addr;
    addr.s_addr = htonl(g_tftp_server_addr);
    cerr << "Tftp address " << inet_ntoa(addr) << " tftp port " << g_tftp_server_port << "\n";
  }

  eventxx::internal::event_set_log_callback(print_all);

  try {
    eventxx::dispatcher d;
    if(g_test_nq) {
      cerr << "Testing NetQuery\n";
      cerr << "sleeping\n";
      sleep(10);
      cerr << "firing\n";
      do_nq_test();
      return;
    }

    if(1) {
    for(size_t i = 0; i < g_switch_ports.size(); i++) {
      cerr << "Filter chain " << i << "\n";
      g_switch_ports[i]->initialize_filter_chains(&d);
    }
    } else {
      cerr << "only initializing 1\n";
      g_switch_ports[1]->initialize_filter_chains(&d);
    }

    cerr << "Starting event loop\n";
    // do_nq_test();
    int err = d.dispatch();
    cerr << "Got back from event loop, err = " << err << "\n";
  } catch(const char *exception) {
    cerr << "Caught " << exception << "\n";
  }
  exit(-1);
}

void start_connect_only(void) {
  cerr << "Not updated to use new switchport design\n";
  ClientPort test_port(NQ_uuid_null, NQ_uuid_null, 0, NULL);
  test_port.start_l2sec_setup_and_enable(/*connect_addr*/);
  while(1) {
    cerr << "Sleeping\n";
    sleep(15);
  }
}

int FabricDev::send(const unsigned char *buffer, int len) {
  // cerr << "FabricDev::send(), came from " << m_src_port_num << "\n";
  assert((size_t)len >= sizeof(struct ethhdr));
  const struct ethhdr *eh = (const struct ethhdr *) buffer;
  MAC_Address src(eh->h_source);
  MAC_Address dst(eh->h_dest);
  ForwardingTable::iterator ent = forwarding_table.find(src);
  if(ent == forwarding_table.end() || ent->second.dest_port_num != m_src_port_num ) {
    try {
      pthread_mutex_lock(&nq_update_mutex);
      Transaction t(trust_all, trust_attrval_all, switch_owner->home, switch_owner);
      T_SwitchFabric fabric(t, g_switch_fabric_tid);
      Switch sw(t, g_switch_tid);
      int tspace_index;
      if(ent == forwarding_table.end()) {
	cerr << "Adding new MAC mapping " << src << " => " << m_src_port_num << "\n";
	T_MACEntry *entry = new T_MACEntry(t);
	entry->tspace_create();
	entry->addr = src;
	entry->interface = sw.get_port(m_src_port_num);

	tspace_index = fabric.l2_forwarding_table.size();
	fabric.l2_forwarding_table.push_back(entry);
	delete entry;
      } else {
	cerr << "Redirecting MAC mapping " << src << " => " << m_src_port_num << "\n";
	cerr << "Not tested\n";
	assert(0);
	tspace_index = ent->second.tspace_entry_index;
	T_MACEntry *entry = fabric.l2_forwarding_table[tspace_index].load();
	assert(entry->addr.load() == src);
	entry->interface = sw.get_port(m_src_port_num);
	delete entry;
      }
      forwarding_table[src] = MAC_Table_Entry(m_src_port_num, tspace_index);
      t.commit();
      pthread_mutex_unlock(&nq_update_mutex);
    } catch(...) {
      cerr << "Error while adding new MAC source, not accepting it\n";
      pthread_mutex_unlock(&nq_update_mutex);
      return NOVERDICT;
    }
  }
  if(dst.is_broadcast()) {
    for(size_t i=0; i < g_switch_ports.size(); i++) {
      if((int)i == m_src_port_num) {
	continue;
      }
      g_switch_ports[i]->up_to_down->process_packet(buffer, len);
    }
    // cerr << "Forwarded broadcast packet\n";
    return 0;
  } else {
    ForwardingTable::iterator dst_ent = forwarding_table.find(dst);
    if(dst_ent == forwarding_table.end()) {
      if(0 && ntohs(eh->h_proto) == ETH_P_IP) {
	cerr << "Can't find destination " << dst << "!\n";
      }
      return -1;
    }
    unsigned dest = dst_ent->second.dest_port_num;
    assert(0 <= dest && dest < g_switch_ports.size());
    g_switch_ports[dest]->up_to_down->process_packet(buffer, len);
    // cerr << "Forwarded unicast packet to " << dest << "\n";
    return 0;
  }
}
