#include <stdio.h>
#include <iostream>
#include <nq/util.hh>
#include <nq/netquery.h>
#include <nq/policy.hh>
#include "router.hh"
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>


using namespace std;

NQ_Host data_home;
NQ_Principal *net_owner;

NQ_Principal *g_flow_principal = &NQ_default_owner;

void add_interface_alias(NQ_Output::OutputContext *ctx, T_Interface *interface) {
  ctx->add_tid_alias(interface->tid, "(" + interface->container.load()->common_name.load() + "'s " + interface->name.load() + ")");
}

int main(int argc, char **argv) {
#if 0
  while( (opt = getopt(argc, argv, "d")) != -1) {
    switch(opt) {
      break;
    default:
      break;
    }
  }
#endif
  if(argc < 2) {
    cerr << "usage: check-path <destination>\n";
    exit(-1);
  }
  string dest_addr_str = argv[1];
  in_addr_t dest_addr = inet_addr(argv[1]);

  if(NQ_getenv_server(&data_home) != 0) {
    cerr << "Could not load NQ server\n";
    exit(-1);
  }

  NQ_init(NQ_PORT_ANY);
  NQ_cpp_lib_init();

  NQ_publish_home_principal();

  net_owner = NQ_load_principal("/nfs/net-owner.principal");
  if(net_owner == NULL) {
    cerr << "Could not load principal for network owner\n";
    exit(-1);
  }

  Transaction t1(trust_all, trust_attrval_all, data_home, &NQ_default_owner);
  NQ_Tuple host_tid = NQ_get_host_tid();
  cerr << "Host tid is " << host_tid << "\n";
  Host host(t1, host_tid);
  EndpointIdentifier dst = IP_TCP(dest_addr, 0);
  T_Flow *flow = NULL;
  T_Flow::RouteState route_state;

  cerr << "Issuing ping command to destination\n";
  system(string("/bin/ping -c 1 -W 1 " + dest_addr_str).c_str());
  
  t1.find_tuple(flow, NQ_Flow_create(-1, &NQ_default_owner, host.tcp_endpoint->tid, host.nic->tid, dst, &route_state, true, true));
  if(flow == NULL) {
    cerr << "Could not initialize flow!\n";
    exit(-1);
  }
  
  NQ_Tuple flow_tid = NQ_uuid_null;
  if(flow != NULL) {
    flow_tid = flow->tid;
  }
  t1.commit();

  cerr << "Commit succeeded\n";
  if(flow != NULL && route_state == T_Flow::VALID_ROUTE) {
    cerr << "Path successfully traced\n";
    Transaction t2(trust_all, trust_attrval_all, data_home, &NQ_default_owner);
    t2.find_tuple(flow, flow_tid);
    assert(flow != NULL);

    cout << "Check Policy: Every router on path is owned by network owner\n";
    bool is_good = true;
    NQ_Output::OutputContext tid_context(data_home); // don't use for output; only to collect tid mappings
    size_t check_limit = flow->route.size() - 1; // last one is destination, which we don't care about
    for(size_t i=0; i < flow->route.size(); i++) {
      T_Tuple *_tuple = flow->route[i].load();
      T_CompositeElement *element = 
	dynamic_cast<T_CompositeElement *>(_tuple);
      T_Interface *interface = 
	dynamic_cast<T_Interface *>(_tuple);
      assert(element || interface);
      if(element != NULL) {
	if(i < check_limit) {
	  if(check_installed_by(&element->installed_by, net_owner) ) {
	    tid_context.add_tid_alias(element->installed_by.load()->tid, "&[Network owner]");
	  } else {
	    cout << "Element at " << i  << " not  installed by net owner!\n";
	    cout << "Element = " << element << " tid = " << element->tid << "\n";
	    is_good = false;
	  }
	}
	tid_context.add_tid_alias(element->tid, "(" + element->common_name.load() + ")");
      } else if(interface != NULL) {
	add_interface_alias(&tid_context, interface);
	add_interface_alias(&tid_context, interface->external_connection);
      }
    }
    if(is_good) {
      cout << "!!! Path meets policy !!!\n";
    } else {
      cout << "Path does not meet policy!\n";
    }

    cout << "Path: {\n";
    for(size_t i=0; i < flow->route.size(); i++) {
      T_Tuple *element = flow->route[i].load();
      //os << "[" << i << "]: " << *element->tid << "\n";
      cout << "[" << i << "]: ";
      NQ_Tuple el_tid = element->tid;
      NQ_Output::OutputContext output_context(el_tid.home, "()");
      output_context.tuple_aliases = tid_context.tuple_aliases;
      output_context.output_tuple(cout, t2.transaction, el_tid);
      cout << "\n";
    }
    cout << "}\n";

    t2.commit();
  } else {
    if(flow == NULL) {
      cerr << "Flow is null\n";
    }
    cerr << "Flow not created, state is \n";
    switch(route_state) {
    case T_Flow::NO_ROUTE:
      cerr << "NO_ROUTE";
      break;
    case T_Flow::VALID_ROUTE:
      cerr << "VALID_ROUTE";
      break;
    case T_Flow::UNCOMPUTED_ROUTE:
      cerr << "UNCOMPUTED_ROUTE";
      break;
    }
    cerr << "\n";
  }
  exit(0);
}
