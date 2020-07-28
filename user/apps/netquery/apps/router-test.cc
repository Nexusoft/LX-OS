#include <stdint.h>
#include <vector>
#include <string>
#include <sstream>
#include <iostream>
#include <fstream>

#include <nq/util.hh>
#include <nq/net.h>
#include "router.hh"

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

using namespace NQ_Flow_debug;
using namespace std;

NQ_Principal *g_flow_principal;

#define IP0 (0x00000001)
#define IP1 (0x00000002)
#define IP2 (0x00000003)
#define IP3 (0x00000004)

#define PORT0 (0x100)
#define PORT1 (0x200)
#define PORT2 (0x300)
#define PORT3 (0x400)

void write_delim(vector<unsigned char> &v) {
  v.push_back(':');
  v.push_back(':');
}

void read_delim(CharVector_Iterator &curr, const CharVector_Iterator &end) {
  char data[3] = {0}, *p = data;
  while(curr != end && (p - data < 2)) {
    *p++ = *curr++;
  }
  assert(string(data) == "::");
}

struct Host_TIDs {
  NQ_Tuple tid, stack, ingress;
  EndpointIdentifier id;
  Host_TIDs(Host *h) {
    tid = h->composite_element->get_tid();
    stack = h->tcp_endpoint->get_tid();
    // ingress = h->nic->external_connection.load()->get_tid();
    ingress = h->nic->get_tid();
    id = h->tcp_endpoint->id;
  }
  // unmarshall version
  Host_TIDs()  : tid(NQ_uuid_null), stack(NQ_uuid_null), ingress(NQ_uuid_null)  {}

  void marshall(ostream &os) {
    os << "HOSTTID{\n";
    file_marshall(tid, os);
    file_marshall(stack, os);
    file_marshall(ingress, os);
    file_marshall(id, os);
    os << "}\n";
  }

  static Host_TIDs *unmarshall(CharVector_Iterator &curr, const CharVector_Iterator &end) {
    Host_TIDs *h = new Host_TIDs();
    /*    NQ_Tuple tid, stack, ingress;    EndpointIdentifier id; */

    string data = get_line(curr, end);
    assert(string(data) == "HOSTTID{");
    h->tid = *tspace_unmarshall(&h->tid, *(Transaction *)NULL, curr, end);
    h->stack = *tspace_unmarshall(&h->stack, *(Transaction *)NULL, curr, end);
    h->ingress = *tspace_unmarshall(&h->ingress, *(Transaction *)NULL, curr, end);
    h->id = *tspace_unmarshall(&h->id, *(Transaction *)NULL, curr, end);
    data = get_line(curr, end);
    assert(string(data) == "}");
    return h;
  }
};

ostream &operator<<(ostream &os, const Host_TIDs &r) {
  os << "\ttid: " << r.tid << "\n\tstack: " << r.tid << "\n\tingress: " << r.tid << "\n\tid " << r.id;
  return os;
}

ostream &operator<<(ostream &os, const Router_TIDs &r) {
  os << "\ttid: " << r.tid;
  return os;
}

std::vector<Host_TIDs *> host_tids;
std::vector<Router_TIDs *> router_tids;

void create_topology(void) {
  // Create the test topology
  Transaction *t0 = new Transaction(trust_all, trust_attrval_all, NQ_default_owner.home, &NQ_default_owner);
  Host *host0, *host1, *host2, *host3;
  Router *router0, *router1;
  host0 = new Host(*t0);
  host1 = new Host(*t0);
  host2 = new Host(*t0);
  host3 = new Host(*t0);
  router0 = new Router(*t0, 3);
  router1 = new Router(*t0, 3);

  // set up ip addresses;
  host0->tcp_endpoint->id = IP_TCP(IP0, PORT0);
  host1->tcp_endpoint->id = IP_TCP(IP1, PORT1);
  host2->tcp_endpoint->id = IP_TCP(IP2, PORT2);
  host3->tcp_endpoint->id = IP_TCP(IP3, PORT3);

  host0->composite_element->common_name = "Host0";
  host1->composite_element->common_name = "Host1";
  host2->composite_element->common_name = "Host2";
  router0->composite_element->common_name = "Router0";
  router1->composite_element->common_name = "Router1";

  // connect devices
  connect_interfaces(router0->get_if(0), host0->nic);
  connect_interfaces(router0->get_if(1), router1->get_if(0));
  connect_interfaces(router0->get_if(2), host3->nic);

  connect_interfaces(router1->get_if(1), host1->nic);
  connect_interfaces(router1->get_if(2), host2->nic);

  // set up forwarding table
  router0->add_forwarding_entry(IP0, 32, 0);
  router0->add_forwarding_entry(IP1, 32, 1);
  router0->add_forwarding_entry(IP2, 32, 1);

  router1->add_forwarding_entry(IP0, 32, 0);
  router1->add_forwarding_entry(IP1, 32, 1);
  router1->add_forwarding_entry(IP2, 32, 2);

  host_tids.push_back(new Host_TIDs(host0));
  host_tids.push_back(new Host_TIDs(host1));
  host_tids.push_back(new Host_TIDs(host2));
  t0->commit();
}

void simple_test(void) {
  error_on_upcall = true;
  create_topology();

  // Create flow
  Transaction *t = new Transaction(trust_all, trust_attrval_all, NQ_default_owner.home, &NQ_default_owner);
  T_Flow *flow;
  T_Flow::RouteState route_state;

  EndpointIdentifier dst = IP_TCP(IP1, PORT1);
  t->find_tuple(flow, NQ_Flow_create( -1, &NQ_default_owner, host_tids[0]->stack, host_tids[0]->ingress, dst , &route_state));
  cout << "Host 0 to host 1 flow:\n";
  cout << *flow;
  if(route_state != T_Flow::VALID_ROUTE) {
    cout << "Failure!\n";
    exit(-1);
  }
  cout << "Success!\n";

  cout << "Host 2 to Host 0 flow:\n";
  t->find_tuple(flow, NQ_Flow_create( -1, &NQ_default_owner, host_tids[2]->stack, host_tids[2]->ingress,
				      IP_TCP(IP0, PORT0), &route_state ) );
  if(route_state != T_Flow::VALID_ROUTE) {
    cout << "Failure!\n";
    exit(-1);
  }
  cout << "Success!\n";
  cout << *flow;

  cout << "Host 2 to Host 4 flow (Should not be able to find route):\n";
  t->find_tuple(flow, NQ_Flow_create( -1, &NQ_default_owner, host_tids[2]->stack, host_tids[2]->ingress, IP_TCP(IP3, PORT3), &route_state ));
  if(route_state == T_Flow::VALID_ROUTE) {
    cout << "Flow created???\n";
    cout << *flow;
    cout << "Failure!\n";
    exit(-1);
  } else {
    cout << "Success!!!\n";
  }
  exit(0);
}

uint32_t IP(int index) {
  return index;
}
EndpointIdentifier H(int index) {
  return IP_TCP(IP(index), index * 0x100);
}

void find_routers(Transaction *t, Router *router[4]) {
  int i;
  for(i=0; i < 4; i++) {
    router[i] = new Router(*t, router_tids[i]->tid);
  }
}

int clear_mode = 0;
void clear_paths(Transaction *t) {
  Router *router[4];
  find_routers(t, router);
  int i;
  if(clear_mode == 0) {
    for(i=0; i < 4; i++) {
      router[i]->clear_forwarding_entries();
    }
  } else {
    for(i=3; i >= 0; i--) {
      router[i]->clear_forwarding_entries();
    }
  }
}

#define NUM_HOSTS (2)
#define NUM_ROUTERS (4)

void establish_path_0(Transaction *t) {
  // set up forwarding table
  Router *router[NUM_ROUTERS];
  find_routers(t, router);
  router[0]->add_forwarding_entry(IP(1), 32, 1);
  router[1]->add_forwarding_entry(IP(1), 32, 1);
  router[2]->add_forwarding_entry(IP(1), 32, 2);
}

void create_notification_topology(void) {
  // Create the test topology
  Transaction *t0 = new Transaction(trust_all, trust_attrval_all, NQ_default_owner.home, &NQ_default_owner);
  Host *host[NUM_HOSTS];
  Router *router[NUM_ROUTERS];
  int i;
  for(i=0; i < NUM_HOSTS; i++) {
    host[i] = new Host(*t0);
    host[i]->tcp_endpoint->id = H(i);
    host[i]->composite_element->common_name = "Host" + itos(i);
  }
  for(i=0; i < NUM_ROUTERS; i++) {
    router[i] = new Router(*t0, 3);
    router[i]->composite_element->common_name = "Router" + itos(i);
  }

  /*
          R1
        /    \
H0 -- R0      R2 -- H1
        \    /
          R3
  */
  // connect devices
  connect_interfaces(host[0]->nic, router[0]->get_if(0));
  connect_interfaces(router[0]->get_if(1), router[1]->get_if(0));
  connect_interfaces(router[0]->get_if(2), router[3]->get_if(0));
  connect_interfaces(router[1]->get_if(1), router[2]->get_if(0));
  connect_interfaces(router[3]->get_if(1), router[2]->get_if(1));
  connect_interfaces(router[2]->get_if(2), host[1]->nic);

  for(i=0; i < NUM_HOSTS; i++) {
    host_tids.push_back(new Host_TIDs(host[i]));
  }
  for(i=0; i < NUM_ROUTERS; i++) {
    router_tids.push_back(new Router_TIDs(router[i]));
  }

  // set up forwarding table
  establish_path_0(t0);
  clear_paths(t0);
  establish_path_0(t0);

  t0->commit();
}

void save_topology_tids(const string &prefix) {
  size_t i;
  ofstream host_os((prefix + "-host.tid").c_str(), ofstream::binary);
  write_int(host_os, host_tids.size());
  for(i=0; i < host_tids.size(); i++) {
    host_tids[i]->marshall(host_os);
    cerr << "[" << i << "]" << *host_tids[i] << "\n";
  }
  host_os.close();

  ofstream routers_os((prefix + "-routers.tid").c_str(), ofstream::binary);
  write_int(routers_os, router_tids.size());
  for(i=0; i < router_tids.size(); i++) {
    router_tids[i]->marshall(routers_os);
    cerr << "[" << i << "]" << *router_tids[i] << "\n";
  }
  routers_os.close();
}

void load_topology_tids(const string &prefix) {
  size_t i;
  size_t num_tids;
  CharVector_Iterator begin;

  ifstream host_is((prefix + "-host.tid").c_str(), ifstream::binary);
  num_tids = read_int(host_is);

  vector<unsigned char> d0;
  get_all_file_data(host_is, d0);
  begin = d0.begin();
  for(i=0; i < num_tids; i++) {
    host_tids.push_back(Host_TIDs::unmarshall(begin, d0.end()));
    cerr << "[" << i << "]" << *host_tids[i] << "\n";
  }
  host_is.close();

  ifstream routers_is((prefix + "-routers.tid").c_str(), ifstream::binary);
  num_tids = read_int(routers_is);

  vector<unsigned char> d1;
  get_all_file_data(routers_is, d1);
  begin = d1.begin();
  for(i=0; i < num_tids; i++) {
    router_tids.push_back(Router_TIDs::unmarshall(begin, d1.end()));
    cerr << "[" << i << "]" << *router_tids[i] << "\n";
  }
  routers_is.close();
}

void notification_test(void) {
  create_notification_topology();

  // Create flow
  Transaction *t = new Transaction(trust_all, trust_attrval_all, NQ_default_owner.home, &NQ_default_owner);
  T_Flow *flow;
  T_Flow::RouteState route_state;

  NQ_Tuple good_flow_tid = 
    NQ_Flow_create( -1, &NQ_default_owner, host_tids[0]->stack, host_tids[0]->ingress, H(1), &route_state );
  t->find_tuple( flow, good_flow_tid );
  cout << *flow;
  if(route_state == T_Flow::VALID_ROUTE) {
    cout << "Host 0 to host 1 established\n";
  } else {
    cout << "Could not establish flow?\n";
    exit(-1);
  }

  // Break route:
  // 1. Clear routing table
  cout << "=============== Break routing ============\n";
  cout << "Clearing the routing table (should result in some notifications)\n";
  detected_dep_change = false;
  dep_change_success = false;
  Transaction *t0 = new Transaction(trust_all, trust_attrval_all, NQ_default_owner.home, &NQ_default_owner);
  clear_paths(t0);
  t0->commit();
  cout << "=================\n";
  cout << "CLEAR commited\n";
  if(!detected_dep_change) {
    cout << "Did not detect dependency change\n";
    cout << "FAILED!!!\n";
    exit(-1);
  } else {
    cout << "Trigger fired ; ";
    cout << (dep_change_success ? "dep change succeeded " :  "dep change FAILED") << "\n";
    cout << "Change detected, new route is \n";
    t->find_tuple( flow, good_flow_tid );
    cout << *flow;
  }
  // this should fail
  t->find_tuple( flow, NQ_Flow_create( -1, &NQ_default_owner, host_tids[0]->stack, host_tids[0]->ingress, H(1), &route_state) );

  if(route_state == T_Flow::VALID_ROUTE) {
    cout <<"did not fail where it should have\n";
    exit(-1);
  }
  cout << *flow;
  cout << "routing update verified (was not able to find route after routes were cleared)\n";

  // 2. Unplug destination

  // Change forwarding table
  // Replug interfaces
}

void *poll_thread(void *dummy){
  while(1){
    //printf("Preparing to poll\n");
    NQ_Net_poll(10000);
  }
  return NULL;
}

void start_net_client(void) {
  //pthread_t poller;
  NQ_Net_set_localserver();
  //pthread_create(&poller, NULL, &poll_thread, NULL);
}

struct EmulatorEndpoint {
  EndpointIdentifier id;
  ExtRef<T_ProtocolEndpoint> tcp_endpoint;
  typedef vector<ExtRef<T_Interface> > Interfaces;
  Interfaces interfaces;
  EmulatorEndpoint(const EndpointIdentifier &_id, ExtRef<T_ProtocolEndpoint> _tcp_endpoint) :
    id(_id), tcp_endpoint(_tcp_endpoint) { }
};

int main(int argc, char **argv) {
#ifdef NEXUS
  NQ_nexus_init();
#endif

  printf("entered main");
  NQ_init(0);
  NQ_cpp_lib_init();

  if(argc < 3) {
    cerr << "Usage: <mode> <file>\n";
    exit(-1);
  }

  g_flow_principal = &NQ_default_owner;

  int args_at = 3;
  string tid_prefix = argv[2];
  switch(atoi(argv[1])) {
  case 0:
    simple_test();
    break;
  case 1:
    clear_mode = 0;
    notification_test();
    break;
  case 2:
    clear_mode = 1;
    notification_test();
    break;

    ////
    // Network tests below
    // Execution order is 3, 5, 4
  case 3: {
    cerr << "Router topology init mode\n";
    start_net_client();
    create_notification_topology();
    cerr << "\n";
    save_topology_tids(tid_prefix);
    break;
  }
  case 4: {
    cerr << "Router topology clear mode\n";
    start_net_client();
    load_topology_tids(tid_prefix);
    Transaction *t0 = new Transaction(trust_all, trust_attrval_all, NQ_default_owner.home, &NQ_default_owner);
    clear_paths(t0);
    t0->commit();
    break;
  }
  case 5: {
    extern bool skip_flow_triggers;
    skip_flow_triggers = true;
    cerr << "Client mode\n";
    start_net_client();
    load_topology_tids(tid_prefix);
    NQ_Tuple good_flow_tid;
    T_Flow::RouteState route_state;

    detected_dep_change = false;
    dep_change_success = false;
    good_flow_tid = 
      NQ_Flow_create( -1, &NQ_default_owner, host_tids[0]->stack, host_tids[0]->ingress, H(1), &route_state );
    if(route_state != T_Flow::VALID_ROUTE) {
      cerr << "Could not create flow!\n";
      exit(-1);
    }
    while(1) {
      if(detected_dep_change) {
	if(dep_change_success) {
	  cerr << "dep changes succeeded\n";
	  exit(0);
	} else {
	  cerr << "dep did not succeed\n";
	  exit(-1);
	}
      }
      sleep(30);
    }
    break;
  }
  case 6: {
    cerr << "Client mode, for router emulator\n";
    do_print_routing = 1;

    typedef vector<EmulatorEndpoint> EmulatorEndpoints;
#ifdef NEXUS
    const int allow_server_override = 1;
#else
    const int allow_server_override = 0;
#endif
    if(allow_server_override && argc >= args_at + 2) {
      int dest_ip = inet_addr(argv[args_at]);
      int dest_port = atoi(argv[args_at+1]);
      printf("Using server "); print_ip(dest_ip); printf(":%d", dest_port);
      NQ_Net_set_server(dest_ip, dest_port);
      printf("\n");
    } else {
      printf("Using default local server (argc = %d, args_at + 2 = %d)\n",
	     argc, args_at + 2);
      start_net_client();
    }

    EmulatorRouters tids;
    EmulatorEndpoints tcp_endpoints;
    load_tids_from_emulator(tid_prefix, &tids);
    cerr << "new transaction...";
    Transaction *t0 = new Transaction(trust_all, trust_attrval_all, NQ_default_owner.home, &NQ_default_owner);
    cerr << " returned\n";
    for(EmulatorRouters::iterator i = tids.begin(); i != tids.end(); i++) {
      Router_TIDs *r_tid = i->second;
      router_tids.push_back(r_tid);

      // attach hosts to each router
      Router *r = new Router(*t0, r_tid->tid);

      tcp_endpoints.
	push_back( EmulatorEndpoint(r->tcp_endpoint->id, ExtRefOf(r->tcp_endpoint)) );
      for(std::vector<T_Interface*>::iterator 
	    i = r->interfaces.begin(); i != r->interfaces.end(); i++) {
	tcp_endpoints.back().interfaces.push_back(ExtRefOf(*i));
      }
      delete r;
    }
    t0->commit();
    delete t0;

    NQ_Tuple good_flow_tid;
    T_Flow::RouteState route_state;

    size_t s = 0;
    size_t t = 5;

    if(!allow_server_override) {
      if(argc >= args_at + 2) {
	s = atoi(argv[args_at]);
	t = atoi(argv[args_at + 1]);
	cout << "Routing between " << s << " and " << t << "\n";
      }
    }
    assert( s < tcp_endpoints.size() && t < tcp_endpoints.size() );
    assert( tcp_endpoints.size() == router_tids.size() );
    assert(tcp_endpoints[s].interfaces.size() >= 1);

    detected_dep_change = false;
    dep_change_success = false;

    good_flow_tid = 
      NQ_Flow_create( -1, &NQ_default_owner, tcp_endpoints[s].tcp_endpoint.tid,
		      tcp_endpoints[s].interfaces[0].tid, 
		      tcp_endpoints[t].id, &route_state );
    if(route_state != T_Flow::VALID_ROUTE) {
      cerr << "Could not create flow!\n";
      exit(-1);
    }
    do_print_routing = 0;
    Transaction *t1 = new Transaction(trust_all, trust_attrval_all, NQ_default_owner.home, &NQ_default_owner);
    T_Flow *flow;
    t1->find_tuple( flow, good_flow_tid );
    fflush(stdout);
    cout.flush();
    cout << "Flow:\n";
    cout << *flow;
    t1->abort();
    delete t1;

    break;
  }
  default:
    cerr << "Unknown mode!\n";
    exit(-1);
  }
}
