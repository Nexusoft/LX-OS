#include <stdint.h>
#include <vector>
#include <string>
#include <sstream>
#include <iostream>
#include <fstream>
#include <signal.h>

#include <nq/util.hh>
#include <nq/net.h>
#include <nq/site.hh>
#include <nq/netquery.h>
#include <nq/garbage.h>
#include "router.hh"

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <ext/hash_set>
#include <ext/hash_map>

#define TEST_PORTNUM (8888)

using namespace NQ_Flow_debug;
using namespace std;
using namespace __gnu_cxx;

unsigned int test_prefix; // test_prefix is a /16
vector<NQ_Tuple> *flows_to_clean;

ExtRef<T_Site> g_site_ref;
NQ_Principal *g_flow_principal;

typedef vector<T_Interface*> InterfaceVector;

typedef hash_set<string, __gnu_cxx::hash<const std::string> > StringSet;
typedef hash_map<string, NQ_UUID> HostMap;

void clear_global_stats(void) {
  Transaction t(trust_all, trust_attrval_all, g_flow_principal->home, g_flow_principal);
  T_Site *site = g_site_ref.load(t);
  site->hosts.clear_global_stats();
  t.abort();
}

void print_global_stats(void) {
  Transaction t(trust_all, trust_attrval_all, g_flow_principal->home, g_flow_principal);
  T_Site *site = g_site_ref.load(t);
  NQ_Stat global_stats;
  site->hosts.get_global_stats(&global_stats);
  t.abort();
  printf("Stats of server: \n");
  NQ_Stat_print(&global_stats);
  printf("=====\n");
}

void parse_vlan(const string &n, string *base_name, string *vlan_str) {
  *base_name = "";
  *vlan_str = "";
  char *name = strdupa(n.c_str());
  const char *bname = strtok(name, ".");
  const char *vstr = strtok(NULL, ".");
  if(bname != NULL) {
    *base_name = bname;
  }
  if(vstr != NULL) {
    *vlan_str = vstr;
  }
}

void find_router_lan_interfaces(Router *router, InterfaceVector *interfaces) {
  for(size_t j=0; j < router->get_num_if(); j++) {
    T_Interface *cand = router->get_if(j);
    string basename, vlan_str;
    parse_vlan(cand->name, &basename, &vlan_str);
    // cerr << "Basename " << basename << " vlan " << vlan_str/* << " " << vlan*/ <<"\n";
    if(basename == "" || vlan_str == "") {
      continue;
    }
    int vlan = atoi(vlan_str.c_str());
    if(vlan == 4092 || vlan == 4093) {
      interfaces->push_back(cand);
    }
  }
}

void find_site_lan_interfaces(T_Site *site, InterfaceVector *interfaces) {
  StringSet set; // detect & throw error upon repeated router
  for(size_t i=0; i < site->routers.size(); i++) {
    T_CompositeElement *comp = site->routers[i].load();
    string common_name = comp->common_name;
    if(set.find(common_name) != set.end()) {
      cerr << "Found a repeat of router \"" << common_name << "\"\n";
      exit(-1);
    } 
    set.insert(common_name);
    Router *router = new Router(site->transaction, comp->tid);
    find_router_lan_interfaces(router, interfaces);
  }
}

static char *IP_Address_to_str(unsigned int addr) {
  struct in_addr a;
  a.s_addr = addr;
  return inet_ntoa( a );
}

void cleanup_hosts(void) {
  int clean_count = 0, total_count = 0;
  Transaction transaction(trust_all, trust_attrval_all, g_flow_principal->home, g_flow_principal);
  T_Site *site = g_site_ref.load(transaction);
  
  InterfaceVector interfaces;
  find_site_lan_interfaces(site, &interfaces);

  for(size_t i=0; i < interfaces.size(); i++) {
    T_Interface *iface = interfaces[i];
    if(iface->external_connection != NULL) {
      // Unlink it
      cerr << "Unlinking " << iface->name.load() << " " << 
	iface->external_connection.load()->
	container.load()->common_name.load() << "\n";
      iface->external_connection.load()->external_connection = NULL;
      iface->external_connection = NULL;
      clean_count++;
    } else {
      cerr << "Not unlinking " << iface->name.load() << "\n";
    }
    total_count++;
  }

  transaction.commit();
  cerr << "Cleaned " << clean_count << " of " << total_count << "\n";
}

void sig_break(int v) {
  cerr << "Got break\n";
  exit(0);
}

void destroy_flows(vector<NQ_Tuple> *flows);
void exit_handler(void) {
  if(flows_to_clean != NULL) {
    cerr << "Clearing " << flows_to_clean->size() << " flows on exit\n";
    destroy_flows(flows_to_clean);
  }
}

void find_hosts(vector<NQ_UUID> *hosts) {
  Transaction transaction(trust_all, trust_attrval_all, g_flow_principal->home, g_flow_principal);
  T_Site *site = g_site_ref.load(transaction);
  InterfaceVector lan_interfaces;
  find_site_lan_interfaces(site, &lan_interfaces);

  for(size_t i=0; i < lan_interfaces.size(); i++) {
    T_Interface *iface = lan_interfaces[i]->external_connection;
    if(iface != NULL) {
      NQ_UUID host_tid = iface->container.load()->tid;
      cerr << "Found host " << host_tid << "\n";
      hosts->push_back( host_tid );
    }
  }
  transaction.abort();
}
void create_hosts(vector<NQ_UUID> *hosts) {
  Transaction transaction(trust_all, trust_attrval_all, g_flow_principal->home, g_flow_principal);
  T_Site *site = g_site_ref.load(transaction);

  InterfaceVector lan_interfaces;
  find_site_lan_interfaces(site, &lan_interfaces);

  for(size_t i=0; i < lan_interfaces.size(); i++) {
    assert(lan_interfaces[i]->external_connection == NULL);
    Host *h = new Host(transaction);
    hosts->push_back(h->composite_element->tid);

    string basename, vlan_str;
    parse_vlan(lan_interfaces[i]->name, &basename, &vlan_str);
    int vlan = atoi(vlan_str.c_str());
    int net = -1;
    if(vlan == 4092) {
      net = 1;
    } else if(vlan == 4093) {
      net = 2;
    }
    
    unsigned int prefix = test_prefix | htonl((net & 0xff) << 8);
    if(lan_interfaces[i]->external_connection != NULL) {
      cerr << "Interface " << basename << " already has connection! Overwriting\n";
    }

    cerr << "Adding host with prefix = " << IP_Address_to_str(prefix) << "\n";
    h->tcp_endpoint->id = IP_TCP(prefix, TEST_PORTNUM);
    lan_interfaces[i]->external_connection = h->nic;
    h->nic->external_connection = lan_interfaces[i];
  }
  transaction.commit();
}

void create_flows(const vector<NQ_UUID> &hosts, int num_iterations, vector<NQ_Tuple> *flows, bool do_analysis) {
  assert(hosts.size() == 2);
  Transaction t2(trust_all, trust_attrval_all, g_flow_principal->home, g_flow_principal);
  Host src(t2, hosts[0]), dst(t2, hosts[1]);
  T_Flow::RouteState route_state;
  for(int i=0; i < num_iterations; i++) {
    NQ_Tuple flow_tid;
    //printf("Iteration = %d\n", i);

    double startTime = smallDoubleTime();
    // printf("======= BEGIN =======\n");
    flow_tid = NQ_Flow_create( -1, g_flow_principal,
			       src.get_tcp_stack()->tid, src.get_nic()->external_connection.load()->tid, 
			       dst.get_tcp_stack()->id,
			       &route_state, do_analysis);
    // printf("======= END =======\n");
    double endTime = smallDoubleTime();
    flows->push_back(flow_tid);
    printf("Flow[%d]: %lf - %lf\n", i, startTime, endTime);

    //cerr << "Created flow " << flow_tid << ", state = " << route_state << "\n";
  }
  t2.abort();
}

void touch_table() {
  // Modify one of the routing tables
  vector< TrieValue<NQ_Tuple> > saved_entry;
  size_t num_entries;
  {
    cerr << "Overwriting routing table\n";
    Transaction t(trust_all, trust_attrval_all, g_flow_principal->home, g_flow_principal);
    T_Site *site = g_site_ref.load(t);
    T_CompositeElement *comp = site->routers[0].load();
    Router *router = new Router(t, comp->tid);

    num_entries = router->fabric->forwarding_table.size();

    for(size_t i = 0; i < num_entries; i++) {
      T_ForwardingEntry e = router->fabric->forwarding_table.load(i);
      saved_entry.resize(i + 1);
      saved_entry[i].h.prefix = e.h.prefix;
      saved_entry[i].h.prefix_len = e.h.prefix_len;
      saved_entry[i].val = e.val.load()->tid;
    }
    // could just call truncate, but this exercises the NQ server code more
    while(router->fabric->forwarding_table.size() > 0) {
      T_ForwardingEntry e = router->fabric->forwarding_table.load(0);
      router->fabric->forwarding_table.erase(e.h.prefix, e.h.prefix_len);
    }
    cerr << "Committing " << t.transaction << "\n";
    t.commit();
  }
  cerr << "Sleeping\n";
  sleep(5);
  cerr << "Statistics after deleting: " << flow_stats << "\n";
  {
    cerr << "Restoring routing table\n";
    Transaction t(trust_all, trust_attrval_all, g_flow_principal->home, g_flow_principal);
    T_Site *site = g_site_ref.load(t);
    T_CompositeElement *comp = site->routers[0].load();
    Router *router = new Router(t, comp->tid);
    assert(num_entries == saved_entry.size());
    for(size_t i = 0; i < num_entries; i++) {
      router->fabric->forwarding_table.update
	(saved_entry[i].h.prefix, saved_entry[i].h.prefix_len, 
	 Ref<T_Interface>(t, saved_entry[i].val));
    }
    t.commit();
  }
}

void destroy_flows(vector<NQ_Tuple> *flows) {
  for(size_t i=0; i < flows->size(); i++) {
    cerr << "[" << i << "]";
    int rv = NQ_Flow_destroy((*flows)[i]);
    if(rv != 0) {
      cerr << "Error destroying flow!\n";
    }
  }
}

int main(int argc, char **argv) {
  do_flow_maintenance = false;
  signal(SIGINT, sig_break);
  atexit(exit_handler);

  bool do_analysis = false;
  bool collect_server_stats = false;
  int opt;
  while( (opt = getopt(argc, argv, "ars")) != -1 ) {
    switch(opt) {
    case 'a':
      do_analysis = true;
      break;
    case 'r':
      printf("Showing all rpcs\n");
      show_rpc_traffic = 1;
      break;
    case 's':
      collect_server_stats = true;
      break;
    default:
      assert(0);
    }
  }

  int num_iterations = 1;
  test_prefix = inet_addr("10.255.0.0");
  if(ntohl(test_prefix) & 0xffff != 0) {
    printf("error: test prefix is not a /16!\n");
    exit(-1);
  }

  if(argc - optind < 3) {
    printf("Usage: flow-test <NQhost> <NQport> <mode>\n");
    exit(-1);
  }
  if(argc - optind >= 4) {
    num_iterations = atoi(argv[optind + 3]);
    printf("Num iterations is %d\n", num_iterations);
  }
  NQ_init(NQ_PORT_ANY);
  NQ_cpp_lib_init();
  // NQ_Net_set_localserver();

  printf("Disabling garbage collection\n");
  NQ_GC_set_timeout(1000000000);

  int mode;
  NQ_Host home;
  home.addr = inet_addr(argv[optind + 0]);
  home.port = atoi(argv[optind + 1]);
  mode = atoi(argv[optind + 2]);

  g_flow_principal = NQ_get_home_principal(&home);
  printf("Home ip: %08x:%d\n", htonl(g_flow_principal->home.addr), g_flow_principal->home.port);

  NQ_UUID site_tid= load_tid_from_file(string("/nfs/site.tid"));
  g_site_ref = ExtRef<T_Site>(site_tid);

  switch(mode) {
  case 0: {
    cerr << "Clean mode\n";
    // Look an interface name 3-digit vlan
    cleanup_hosts();
    break;
  }
  case 1: {
    cerr << "Attaching hosts and routing\n";

    cerr << "Cleaning up before experiment\n";
    cleanup_hosts();

    vector<NQ_UUID> hosts;
    vector<NQ_Tuple> flows;
    create_hosts(&hosts);
    clear_attr_stats();
    printf("Creating flows\n");
    create_flows(hosts, num_iterations, &flows, do_analysis);
    if(0) {
      Transaction t3(trust_all, trust_attrval_all, g_flow_principal->home, g_flow_principal);
      for(size_t i=0; i < flows.size(); i++) {
	NQ_Tuple flow_tid = flows[i];
	T_Flow *flow;
	t3.find_tuple(flow, flow_tid);
	if(flow != NULL) {
	  // cerr << "Flow is " << *flow << "\n";
	}
	if(i % 100 == 0) {
	  cerr << "[" << i << "]";
	}
      }
      t3.abort();
    }
    printf("Created flows\n");

    cout.flush();
    dump_attr_stats();
    cout.flush();

    cerr << "pre table touch; sleeping\n";
    sleep(2);
    touch_table();
    cerr << "sleeping\n";
    sleep(2);
    cerr << "Statistics after restoring: " << flow_stats << "\n";
    if(false) {
      cerr << "Cleaning up after experiment (detaching hosts)\n";
      cleanup_hosts();
      sleep(2);
      cerr << "Statistics after cleaning: " << flow_stats << "\n";
    }

    cerr << "Destroying flows\n";
    destroy_flows(&flows);
    if(!(
	 flow_stats.num_try_routes == 1 * num_iterations &&
	 flow_stats.num_good_routes == 1 * num_iterations &&
	 flow_stats.num_touched_flows == 2 * num_iterations &&
	 flow_stats.num_reroute == 2 * num_iterations &&
	 flow_stats.num_good_reroute == 1 * num_iterations)
       ) {
      cerr << "Stats mismatch!\n";
      exit(-1);
    }
    exit(0);
    break;
  }

  case 2: {
    vector<NQ_UUID> hosts;
    vector<NQ_Tuple> flows;
    find_hosts(&hosts);
    if(hosts.size() < 2) {
      cerr << "Hosts not yet created\n";
      exit(-1);
    }
    assert(hosts.size() == 2);

    if(collect_server_stats) {
      clear_global_stats();
    }

    printf("Creating %d flows at %lf\n", num_iterations, smallDoubleTime());
    create_flows(hosts, num_iterations, &flows, do_analysis);
    printf("Killing wireshark\n");
    system("killall -INT tshark");
    printf("Done creating flows at %lf\n", smallDoubleTime());
    printf("Trigger Stats: %d created, %d erased\n", trigger_stats.create, trigger_stats.erase);
    cout.flush();
    dump_attr_stats();
    cout << "Statistics: " << flow_stats << "\n";

    cout.flush();
    NQ_dump_stats();

    if(collect_server_stats) {
      print_global_stats();
    }

    fflush(stdout);
    flows_to_clean = &flows;
    // sleep(60);
  }
  case 3: {
    cerr << "Creating hosts\n";
    vector<NQ_UUID> hosts;
    cleanup_hosts();
    create_hosts(&hosts);
    exit(0);
  }
  case 4: {
    cerr << "Testing stats gathering\n";
    print_global_stats();
    printf("====> Clearing stats <====\n");
    clear_global_stats();
    printf("====> Stats again <====\n");
    print_global_stats();
    printf("====> Lots of operations <====\n");
    
    for(int i =0; i < 100; i++) {
      Transaction t(trust_all, trust_attrval_all, g_flow_principal->home, g_flow_principal);
      T_Site *site = g_site_ref.load(t);
      NQ_Stat global_stats;
      site->hosts.get_global_stats(&global_stats);
      t.abort();
    }
    print_global_stats();
    break;
  }
  default:
    printf("Unknown mode %d\n", mode);
    exit(-1);
  }
  exit(0);
}
