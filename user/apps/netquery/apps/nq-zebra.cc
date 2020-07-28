#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fstream>
#include <vector>
#include <poll.h>
#include <errno.h>

#include <utility>
#include <map>

#include <signal.h>

#include <nq/nq-zebra-interface.h>
#include <nq/site.hh>

#include <sched.h>

#define QUAGGA_NO_DEPRECATED_INTERFACES
#include "../quagga-0.99.8/lib/if.h"
#include "../quagga-0.99.8/lib/prefix.h"

#define NQ_DISCOVERY_PORT (3459)

//#define DBG_PRINT(X,...) fprintf(stderr, X, ## __VA_ARGS__ )
#define DBG_PRINT(X,...) fprintf(fib_output, X, ## __VA_ARGS__ )

using namespace std;

int g_use_netquery;
NQ_Principal *router_owner;
char *g_netquery_name;

ExtRef<T_SwitchFabric> g_fabric_ref;
ExtRef<T_Site> g_site_ref;

NQ_UUID router_tid;

IP_Address broadcast_addr(IP_Address addr, int prefix_len) {
  IP_Address mask = ntohl(((int)0x80000000) >> (prefix_len - 1));
  return (addr & mask) | (~mask);
}

char *IP_Address_to_str(IP_Address addr);

struct DiscoveryPacket {
  NQ_UUID tid;
  DiscoveryPacket(const NQ_UUID &_tid) : tid(_tid) { }
} __attribute__((packed));

struct InterfaceInfo {
  unsigned int ifindex;
  string name;
  ExtRef<T_Interface> ref;
  ExtRef<T_Interface> external_connection;

  struct Address;
  struct DiscoveryThreadCtx {
    InterfaceInfo *info;
    const Address &address;
    DiscoveryThreadCtx(InterfaceInfo *_info, const Address &_address) :
      info(_info), address(_address) { }
  };

  typedef IP_Address DiscoveryThreadKey; // ifindex and broadcast IP address (broadcast IP address determines the interface to which it is bound)
  typedef map<DiscoveryThreadKey, InterfaceInfo::DiscoveryThreadCtx*> DiscoveryThreadMap;

  static pthread_mutex_t discovery_thread_mutex;
  static DiscoveryThreadMap discovery_thread_map;

  static void *discovery_thread(void *_ctx);

  struct Address {
    IP_Address local_ip;
    IP_Address broadcast_ip;
    pthread_t neighbor_discovery_thread;
    Address(IP_Address local, IP_Address bcast) {
      local_ip = local;
      broadcast_ip = bcast;
      neighbor_discovery_thread = (pthread_t)-1;
    }
    void start_discovery(InterfaceInfo *info);
  };
  vector<Address *> addresses;

  InterfaceInfo(int num, const string &if_name, T_Interface *iface) {
    ifindex = num;
    name = if_name;
    ref = ExtRefOf(iface);
  }
};

typedef vector<InterfaceInfo*> InterfaceInfoVector;

pthread_mutex_t InterfaceInfo::discovery_thread_mutex = 
  ((pthread_mutex_t)PTHREAD_MUTEX_INITIALIZER);
InterfaceInfo::DiscoveryThreadMap InterfaceInfo::discovery_thread_map;

bool trust_all(NQ_Tuple tid, KnownClass *obj_class) {
  return true;
}
bool trust_attrval_all(NQ_Attribute_Name *name, NQ_Tuple tid, NQ_Principal *principal) {
	return true;
}

void create_router(void) {
  fprintf(stderr, "Creating router\n");

  Transaction t(trust_all, trust_attrval_all, router_owner->home, router_owner);
  T_Site *site = g_site_ref.load(t);
  Router *new_router = new Router(t, 0);

  g_fabric_ref = ExtRef<T_SwitchFabric>(new_router->fabric->tid);

  site->routers.push_back(Ref<T_CompositeElement>(new_router->composite_element));
  router_tid = new_router->composite_element->tid;

  string router_name;
  if(g_netquery_name != NULL) {
    router_name = string(g_netquery_name);
  } else {
    router_name = string("Unnamed");
  }
  string full_name = "Router-" + router_name;
  fprintf( stderr, "Setting name %s\n", full_name.c_str() );
  new_router->composite_element->common_name = full_name;

  t.commit();
  delete new_router;

  Transaction t1(trust_all, trust_attrval_all, router_owner->home, router_owner);
  site = g_site_ref.load(t1);
  printf("%d routers\n", (int) site->routers.size());
  t1.abort();


  if(g_netquery_name != NULL) {
    string fname = string("/nfs/") + string(g_netquery_name) + string(".router.tid");
    ofstream ofs( fname.c_str() );
    file_marshall(router_tid, ofs);
    cerr << "Wrote router tid " << router_tid << " to " << fname << "\n";
    ofs.close();
  }
}

Router *load_router(Transaction &t) {
  return new Router(t, router_tid);
}

struct nq_info_t {
private:
  Transaction *m_transaction;
  T_SwitchFabric *m_fabric;
  pthread_mutex_t m_mutex; // mutex is recursive to allow discovery threads to lock across a whole transaction
  InterfaceInfoVector m_interface_info;

  vector<T_Interface *> m_interfaces; // for current transaction m_transaction

  vector<unsigned char *> netlink_ops;

  int m_fib_op_count, m_fib_tot_count;

public:
  nq_info_t() : m_transaction(NULL), m_fib_op_count(0), m_fib_tot_count(0) {
    m_mutex = ((pthread_mutex_t)PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP);
  }
  void lock() {
    pthread_mutex_lock(&m_mutex);
  }
  void unlock() {
    pthread_mutex_unlock(&m_mutex);
  }
  Transaction *get_transaction() {
    if(m_transaction == NULL) {

// #define PING() printf("\t%lf: <%d>\n", doubleTime(), __LINE__)
#define PING()

      DBG_PRINT("===> OPENING <===\n");
      printf("%lf: Open Transaction\n", doubleTime());
PING();
      m_transaction = new Transaction(trust_all, trust_attrval_all, router_owner->home, router_owner, true);
      m_fabric = g_fabric_ref.load(*m_transaction);
PING();
      m_interfaces.clear();
PING();
      size_t i;
PING();
      for(i=0; i < m_interface_info.size(); i++) {
	m_interfaces.push_back(m_interface_info[i]->ref.load(*m_transaction));
      }
PING();
      // printf("started transaction and loaded fabric %p\n", m_fabric);
PING();
    }
    return m_transaction;
  }
  void commit() {
    if(m_transaction != NULL) {
      DBG_PRINT("===> COMMITTING <===\n");
      printf("%lf: Start commit Transaction\n", doubleTime());
PING();
      m_transaction->commit();
PING();

      if(netlink_ops.size() > 0) {
        //printf("Pushing updates (%d)\n", netlink_ops.size());
        nq_netlink_begin_batch ();
        m_fib_tot_count += netlink_ops.size();
        for(size_t i=0; i < netlink_ops.size(); i++) {
          unsigned char *pkt = netlink_ops[i];
          nq_netlink_talk(pkt);
          delete [] pkt;
        }
        nq_netlink_end_batch ();
        send_notification_msg("%lf: sent down %d", doubleTime(), netlink_ops.size());
        netlink_ops.clear();
PING();
      }

PING();

      m_fib_op_count = 0;

      delete m_transaction;
      delete m_fabric;
      m_transaction = NULL;
      m_fabric = NULL;
      printf("%lf: Commited TransactionA (fib_op_count = %d, fib_tot_count = %d)\n", doubleTime(), m_fib_op_count, m_fib_tot_count);
    }
  }
  void abort() {
    if(m_transaction != NULL) {
      m_transaction->abort();
      delete m_transaction;
      delete m_fabric;
      m_transaction = NULL;
      m_fabric = NULL;
      m_interfaces.clear();
    }
  }

  void process_entry(NQ_OpType op, NQ_FIBEntry *entry, const void *packet, int packet_len) {
    lock();
    get_transaction();
    DBG_PRINT("((not using flags))\n");
    m_fib_op_count++;
    switch(op) {
    case NQ_OP_NEWENTRY: {
      int if_num = entry->next_hop.if_num;
      T_Interface *iface;
      if(if_num == IFNUM_INVALID) {
	iface = NULL;
      } else {
	assert( if_num <= if_num && (size_t) if_num < m_interfaces.size() );
	iface = m_interfaces[if_num];
      }
      DBG_PRINT("adding forwarding entry %08x/%d\n", entry->prefix, entry->prefix_len);

      add_forwarding_entry(m_fabric, entry->prefix, entry->prefix_len,
			   iface);
      break;
    }
    case NQ_OP_DELENTRY:
      del_forwarding_entry(m_fabric, entry->prefix, entry->prefix_len);
      break;
    default:
      assert(0);
    }

    if(packet_len > 0) {
      unsigned char *new_pkt = new unsigned char[packet_len];
      memcpy(new_pkt, packet, packet_len);
      netlink_ops.push_back(new_pkt);
    }
    unlock();
  }

  void new_interface(struct interface *ifp) {
    lock();
    commit();
    DBG_PRINT("New interface, name = %s, index = %d\n", ifp->name, ifp->ifindex);
    assert(ifp->ifindex != IFINDEX_INTERNAL);

    Transaction *t = get_transaction();
    Router *r = load_router(*t);
    if(ifp->ifindex >= r->interfaces.size()) {
      while(r->interfaces.size() <= ifp->ifindex) {
	r->add_if();
      }
    }

    T_Interface *iface = r->get_if(ifp->ifindex);
    assert(strlen(iface->name.load().c_str()) == 0);
    string ifname(ifp->name);
    iface->name = ifname;

    m_interface_info.resize(r->interfaces.size());
    for(size_t i = 0; i < r->interfaces.size(); i++) {
      T_Interface *iface = r->get_if(i);
      if(iface != NULL) {
	if(m_interface_info[i] == NULL) {
	  // new entry
	  m_interface_info[i] = new InterfaceInfo(i, ifname, iface);
	}
	// check newly inserted entry as well as existing entries
	assert(m_interface_info[i]->ref == ExtRefOf(iface));
      } else {
	assert(m_interface_info[i]->ref == ExtRef<T_Interface>());
      }
    }

    delete r;

    commit();
    unlock();
  }

  void delete_interface(struct interface *ifp) {
    DBG_PRINT("delete_interface() not implemented/tested\n");
    // XXX need to remember that there are references to the InterfaceInfo objects
#if 0
    assert(0);

    lock();
    commit();

    assert(ifp->ifindex != IFINDEX_INTERNAL);

    Transaction *t = get_transaction();
    Router *r = load_router(*t);
    assert(ifp->ifindex < r->interfaces.size());
    commit();
    unlock();
#endif
  }

  void up_ipv4(struct interface *ifp, struct connected *ifc) {
    lock();
    assert(ifp->ifindex < m_interface_info.size());
    InterfaceInfo *if_info = m_interface_info[ifp->ifindex];
    assert(if_info != NULL);
    // add entry to addresses
    IP_Address local_addr = ifc->address->u.prefix4.s_addr;
    IP_Address bcast_addr = broadcast_addr(local_addr, ifc->address->prefixlen);
    DBG_PRINT("Local addr is %08x ; Broadcast addr is %08x\n",
	      local_addr, bcast_addr);

    InterfaceInfo::Address *addr_info = 
      new InterfaceInfo::Address(local_addr, bcast_addr);
    addr_info->start_discovery(if_info);
    if_info->addresses.push_back(addr_info);

    DBG_PRINT("Adding FIB entry\n");
    NQ_FIBEntry entry;
    entry.table = 0;
    entry.prefix = local_addr;
    entry.prefix_len = ifc->address->prefixlen;
    entry.metric = 0;
    entry.flags = 0;
    entry.next_hop.gateway = 0;
    entry.next_hop.if_num = ifp->ifindex;
    process_entry(NQ_OP_NEWENTRY, &entry, NULL, 0);

    unlock();
  }
  void down_ipv4(struct interface *ifp, struct connected *ifc) {
    cerr << "down_ipv4 not yet implemented!\n";
    // Fail silently
  }

  void interface_add_peer(InterfaceInfo *info, ExtRef<T_Interface> peer_ref) {
    // cerr << "Got TID " << peer_ref.tid << " from interface " << info->ifindex << "\n";
    if(peer_ref == info->ref) {
      // DBG_PRINT("%d: from local, ignoring\n", info->ifindex);
      return;
    }
    lock();
    if(info->external_connection != peer_ref) {
      DBG_PRINT("Commiting new peer for %d\n", info->ifindex);
      commit();
      Transaction *t = get_transaction();

      assert(info->ifindex < m_interfaces.size());
      m_interfaces[info->ifindex]->external_connection = peer_ref.load(*t);
      info->external_connection = peer_ref;

      cerr << "External connection = " << peer_ref.tid << "\n";

      commit();
    }
    unlock();
  }
};

nq_info_t g_nq_info_real, *g_nq_info = &g_nq_info_real;

void InterfaceInfo::Address::start_discovery(InterfaceInfo *info) {
  assert(neighbor_discovery_thread == (pthread_t)-1);
  DiscoveryThreadCtx *ctx = new DiscoveryThreadCtx(info, *this);
  DiscoveryThreadKey key = broadcast_ip;
  pthread_mutex_lock(&discovery_thread_mutex);
  if(discovery_thread_map.find(key) == discovery_thread_map.end()) {
    discovery_thread_map[key] = ctx;
    int rv = pthread_create(&neighbor_discovery_thread, NULL, discovery_thread, 
			    ctx);
    assert(rv == 0);
  } else {
    DBG_PRINT("==> Discovery thread already started for %s\n", IP_Address_to_str(local_ip));
    // on testbed, there could be many IP addresses with the same
    // discovery address. Allow this to occur if (local_ip ==
    // broadcast_ip), e.g. broadcast won't go anywhere
    assert(local_ip == broadcast_ip ||
           info->ifindex == discovery_thread_map[key]->info->ifindex);
  }
  pthread_mutex_unlock(&discovery_thread_mutex);
}

void printsig(int signo) {
  printf("Got signal %d\n", signo);
}

void *InterfaceInfo::discovery_thread(void *_ctx) {
  DiscoveryThreadCtx *ctx = (DiscoveryThreadCtx *)_ctx;
  DBG_PRINT("Starting discovery thread for if=%d %08x %08x\n", 
	    ctx->info->ifindex, ctx->address.local_ip, ctx->address.broadcast_ip);
  int snd_sock;
  struct sockaddr_in saddr;
  int rv;
  snd_sock = socket(PF_INET, SOCK_DGRAM, 0);
  assert(snd_sock > 0);
  saddr.sin_family = AF_INET;
  saddr.sin_port = 0; // any port
  saddr.sin_addr.s_addr = ctx->address.local_ip;

  int bind_tries = 0;
  while(1) {
    rv = bind(snd_sock, (struct sockaddr *)&saddr, sizeof(saddr));
    if(rv == 0) {
      break;
    }
  
    perror("send Bind error!");
    DBG_PRINT("Tried to bind send to %s, got err %d\n", 
	      IP_Address_to_str(saddr.sin_addr.s_addr), errno);
    if(bind_tries++ > 5) {
      DBG_PRINT("Bailing\n");
      exit(-1);
    }
    sleep(5);
  }

  int one = 1;
  rv = setsockopt(snd_sock, SOL_SOCKET, SO_BROADCAST, &one, sizeof(one));
  assert(rv == 0);

  // Set up broadcast receive
  int rcv_sock;
  struct sockaddr_in bcast_addr;
  rcv_sock = socket(PF_INET, SOCK_DGRAM, 0);

  bcast_addr.sin_family = AF_INET;
  bcast_addr.sin_port = ntohs(NQ_DISCOVERY_PORT);
  bcast_addr.sin_addr.s_addr = ctx->address.broadcast_ip; //INADDR_ANY;

  bind_tries = 0;
  while(1) {
    rv = bind(rcv_sock, (struct sockaddr *)&bcast_addr, sizeof(bcast_addr));
    if(rv == 0) {
      DBG_PRINT("Bind recv for %d to %s\n", ctx->info->ifindex, IP_Address_to_str(bcast_addr.sin_addr.s_addr));
      break;
    } else {
      perror("recv Bind error!");
      DBG_PRINT("Tried to bind recv to %s, got err %d\n", 
                IP_Address_to_str(bcast_addr.sin_addr.s_addr), errno);
      if(bind_tries++ > 5) {
        DBG_PRINT("Bailing\n");
        exit(-1);
      }
      sleep(5);
    }
  }

  rv = setsockopt(rcv_sock, SOL_SOCKET, SO_BROADCAST, &one, sizeof(one));
  assert(rv == 0);

  DiscoveryPacket pkt(ctx->info->ref.tid);
  double last_send_time = 0;
  while(1) {
    // periodically broadcast (advertise) the NQ tid of our interface
    // periodically save any heard advertisements
    if(doubleTime() - last_send_time > 0.100) {
      rv = sendto(snd_sock, &pkt, sizeof(pkt), 0,
                  (struct sockaddr *)&bcast_addr, sizeof(bcast_addr));
      last_send_time = doubleTime();
      if(rv <= 0) {
        perror("sendto");
        DBG_PRINT("Announcement error %d for %s ",
                  errno, IP_Address_to_str(saddr.sin_addr.s_addr));
        DBG_PRINT("to %s\n", IP_Address_to_str(bcast_addr.sin_addr.s_addr));
      } else {
#if 0
        DBG_PRINT("Sent %d from %s ", rv, IP_Address_to_str(saddr.sin_addr.s_addr));
        DBG_PRINT("to %s\n", IP_Address_to_str(bcast_addr.sin_addr.s_addr));
#endif
      }
    }

    struct pollfd fds[1];
    fds[0].fd = rcv_sock;
    fds[0].events = POLLIN;
    fds[0].revents = 0;

    int timeout = 1000;
    int count = poll(fds, 1, timeout);

    if(count < 0) {
      if(DEBUG_POLL_EINTR || errno != EINTR) {
        printf("%lf: Poll 1 returned %d\n", doubleTime(), count);
        printf("poll error:%s\n", strerror(errno));
      }
    }

    if(count > 0 && fds[0].revents & POLLIN) {
      char data[1500];
      struct sockaddr_in addr;
      socklen_t addr_len = sizeof(addr);
      while((rv = recvfrom(rcv_sock, data, sizeof(data), MSG_DONTWAIT,
			   (struct sockaddr *)&addr, &addr_len)) > 0) {
	if(rv < (int)sizeof(DiscoveryPacket)) {
	  DBG_PRINT("Packet too short!\n");
	  continue;
	}
	DiscoveryPacket *in_pkt = (DiscoveryPacket *)data;
	g_nq_info->interface_add_peer(ctx->info, ExtRef<T_Interface>(in_pkt->tid));
      }
      sleep(1);
    }
  }
}

void NQ_FIBEntry_print(int op, struct NQ_FIBEntry *entry) {
  char *prefix_str = 
    strdupa( IP_Address_to_str(entry->prefix) );
  char *gateway_str = 
    strdupa( IP_Address_to_str(entry->next_hop.gateway) );
  char flags_str[128] = "";

  if(entry->flags & NQ_FIBENTRY_BLACKHOLE) {
    strcat(flags_str + strlen(flags_str), "BLACKHOLE ");
  } else if(entry->flags & NQ_FIBENTRY_REJECT) {
    strcat(flags_str + strlen(flags_str), "REJECT ");
  } else if(entry->flags & NQ_FIBENTRY_RECURSIVE) {
    strcat(flags_str + strlen(flags_str), "RECURSIVE ");
  }
  DBG_PRINT("%lf: \t tab %d %s/%d => gw %s if %d (metric %d flags %s op = %d)\n",
            doubleTime(),
            entry->table, prefix_str, entry->prefix_len,
            gateway_str, entry->next_hop.if_num,
            entry->metric, flags_str,
            op);
}

char *IP_Address_to_str(IP_Address addr) {
  struct in_addr a;
  a.s_addr = addr;
  return inet_ntoa( a );
}

void nq_init(IP_Address addr, short port_num) {
  NQ_init(NQ_PORT_ANY);
  NQ_cpp_lib_init();
  // NQ_Net_set_localserver();

  NQ_Host home_real, *home = &home_real;
  home->addr = addr;
  home->port = port_num;

  if(home != NULL) {
    router_owner = NQ_get_home_principal((NQ_Host *)home);
  } else {
    router_owner = NQ_Principal_create();
    router_owner->home = NQ_default_owner.home;
  }

  ifstream ifs("/nfs/site.tid");
  if(!ifs.good()) {
    cerr << "Could not open site tid!\n";
    exit(-1);
  }
  NQ_UUID site_tid;
  vector<unsigned char> all_data;

  get_all_file_data(ifs, all_data);
  CharVector_Iterator s = all_data.begin(), end = all_data.end();

  site_tid = *tspace_unmarshall(&site_tid, *(Transaction *)NULL, s, end);

  ifs.close();

  g_site_ref = ExtRef<T_Site>(site_tid);
  cerr << "Testing site ref\n";
  Transaction *t = new Transaction(trust_all, trust_attrval_all, router_owner->home, router_owner);
  T_Site *site = g_site_ref.load(*t);
  if(site == NULL) {
    cerr << "Could not load site root object!\n";
    cerr << "TID = " << site_tid << "\n";
    exit(-1);
  }
  t->abort();
  delete site;

  create_router();

  printf("Done initializing NQ\n");
}

void NQ_FIBEntry_op(NQ_OpType op, NQ_FIBEntry *entry,
		    const void *packet, int packet_len) {
  // cerr << "fibentryop\n";
  DBG_PRINT("fibentry_op(%d)\n", op);
  // static int count = 0;
  //printf("[%d]\n", count++);
  //PING();
  g_nq_info->process_entry(op, entry, packet, packet_len);
  //PING();
}

void NQ_new_interface(struct interface *ifp) {
  g_nq_info->new_interface(ifp);
}

void NQ_up_ipv4(struct interface *ifp, struct connected *ifc) {
  g_nq_info->up_ipv4(ifp, ifc);
}

void NQ_down_ipv4(struct interface *ifp, struct connected *ifc) {
  g_nq_info->down_ipv4(ifp, ifc);
}


void NQ_delete_interface(struct interface *ifp) {
  g_nq_info->delete_interface(ifp);
}

void NQ_do_complete(void) {
  g_nq_info->lock();
  g_nq_info->commit();
  g_nq_info->unlock();
}

int __attribute__((weak)) nq_netlink_talk (void *n) {
  assert(0);
}

int __attribute__((weak)) nq_netlink_begin_batch (void);
int __attribute__((weak)) nq_netlink_end_batch (void);

struct sockaddr_in notification_target;
bool send_net_notifications = false;

static void send_net_notification(struct sockaddr_in dest, const char *msg) {
  // xxx could send this with normal tcp
  string cmdline = string("/usr/bin/nc ") + 
    inet_ntoa(dest.sin_addr) + " " + 
    itos(ntohs(dest.sin_port));
  printf("Notification command line '%s'\n", cmdline.c_str());
  FILE *fp = popen(cmdline.c_str(), "w");
  if(fp != NULL) {
    fputs(msg, fp);
    fprintf(fp, "\n");
    int status = pclose(fp);
    if(status != 0) {
      printf("Error sending notification message: status = %d\n", status);
    }
    printf("%lf: Sent notification '%s'\n", doubleTime(), msg);
  }
}

void send_notification_msg(const char *fmt, ...) {
  char buf[1024];
  va_list ap;
  va_start(ap, fmt);
  int n = vsnprintf(buf, sizeof(buf), fmt, ap);
  assert(n >= 0 && (size_t) n < sizeof(buf));

  printf("Notification: '%s'\n", buf);
  if(send_net_notifications) {
    send_net_notification(notification_target, buf);
  }
  puts(buf); // with newline
  fflush(stdout);
}

int register_notification_target(const char *str) {
  if(parse_addr_spec(optarg, &notification_target) == 0) {
    send_net_notifications = true;
    return 0;
  } else {
    return -1;
  }
}
