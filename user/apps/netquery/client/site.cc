#include <nq/net_elements.hh>
#include <iostream>
#include <fstream>
#include <assert.h>
#include <inttypes.h>
#include <nq/util.hh>
#include <nq/site.hh>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>

#ifndef __LINUX__
extern "C" {
#include <nexus/KernelFS.interface.h>
#include <nexus/env.h>
}
#endif

using namespace std;

////////////// T_Site

void T_Site::tspace_create(void) 
  throw(NQ_Access_Exception) {
  tspace_create_generic("Site");
}

////////////// Host

Host::Host(Transaction &transaction) {
  composite_element = new T_CompositeElement(transaction);
  tcp_endpoint = new T_ProtocolEndpoint(transaction);
  nic = new T_Interface(transaction);
  process_list = new T_ProcessList(transaction);

  composite_element->tspace_create();
  tcp_endpoint->tspace_create();
  nic->tspace_create();
  process_list->tspace_create();

  tcp_endpoint->container = composite_element;

  nic->container = composite_element;
  nic->name = string("eth0");

  process_list->container = composite_element;

  tcp_endpoint->successors.push_back( Ref<T_PrimitiveElement>(nic) );
  nic->successors.push_back( Ref<T_PrimitiveElement>(tcp_endpoint) );
  composite_element->components.push_back( Ref<T_PrimitiveElement>(tcp_endpoint) );
  composite_element->components.push_back(  Ref<T_PrimitiveElement>(nic) );
  composite_element->components.push_back(  Ref<T_PrimitiveElement>(process_list) );
  composite_element->common_name.store(string("Host"));
}

Host::Host(Transaction &transaction, NQ_Tuple tid) {
  transaction.find_tuple(composite_element, tid);
  if(composite_element == NULL) {
    cerr << "can't load host composite tuple " << tid << "\n";
    throw NQ_Schema_Exception("Cannot load host tuple");
  }
  nic = NULL;
  tcp_endpoint = NULL;
  process_list = NULL;

  size_t i;
  for(i=0; i < composite_element->components.size(); i++) {
    T_PrimitiveElement *e = composite_element->components[i].load();

    T_Interface *interface = dynamic_cast<T_Interface *>(e);
    T_ProtocolEndpoint *t = dynamic_cast<T_ProtocolEndpoint *>(e);
    T_ProcessList *pl = dynamic_cast< T_ProcessList *>(e);
    // XXX this may not be precise enough
    if(interface != NULL) {
      assert(transaction.get_tuple_shadow(interface->tid) == interface);
      assert(nic == NULL);
      nic = interface;
    }
    if(t != NULL) {
      assert(tcp_endpoint == NULL);
      tcp_endpoint = t;
    }
    if(pl != NULL) {
      assert(process_list == NULL);
      process_list = pl;
    }
  }
}

// Local fields
T_ProtocolEndpoint *Host::get_tcp_stack(void) {
  return tcp_endpoint;
}
T_Interface *Host::get_nic(void) {
  return nic;
}


T_Process *Host::get_process(Transaction *t, ExtRef<T_ProcessList> _process_list, int id, bool create) {
  T_Process *rv = NULL;
  T_ProcessList *process_list = _process_list.load(*t);
  if(process_list->elems.size() > 30) {
    cerr << "Process list size too big for efficient get_process\n";
  }
  for(size_t i=0; i < process_list->elems.size(); i++) {
    T_Process *p = process_list->elems[i].load();
    if(p == NULL) {
      continue;
    }
    if(p != NULL && atoi(p->key.load().c_str()) == id) {
      rv = p;
      break;
    }
  }
  if(rv == NULL && create) {
    cerr << "Creating new process " << id << "\n";
    rv = new T_Process(process_list->transaction);
    rv->tspace_create();
    rv->key.store(itos(id));
    rv->container.store(process_list->container);
    process_list->elems.push_back(rv);
  }
  return rv;
}

////////////// Switch

Switch::Switch(Transaction &transaction, int num_interfaces) {
  composite_element = new T_CompositeElement(transaction);
  composite_element->tspace_create();

  fabric = new T_SwitchFabric(transaction);
  fabric->tspace_create();
  fabric->container = composite_element;    
  composite_element->components.push_back(fabric);

  tcp_endpoint = new T_ProtocolEndpoint(transaction);
  tcp_endpoint->tspace_create();
  tcp_endpoint->container = composite_element;
  composite_element->components.push_back(tcp_endpoint);

  composite_element->common_name.store(string("Switch"));

  firewall_table = NULL;

  int i;
  for(i=0; i < num_interfaces; i++) {
    add_port();
  }
}

Switch::Switch(Transaction &transaction, NQ_Tuple tid) {
  transaction.find_tuple(composite_element, tid);
  assert(composite_element != NULL);
  size_t i;
  fabric = NULL;
  tcp_endpoint = NULL;
  firewall_table = NULL;

  for(i=0; i < composite_element->components.size(); i++) {
    T_PrimitiveElement *e = composite_element->components[i].load();
    T_SwitchFabric *f = dynamic_cast<T_SwitchFabric *>(e);
    T_Interface *interface = dynamic_cast<T_Interface *>(e);
    T_ProtocolEndpoint *t = dynamic_cast<T_ProtocolEndpoint *>(e);
    T_Firewall *fw = dynamic_cast<T_Firewall *>(e);
    // XXX this may not be precise enough
    if(f != NULL) {
      assert(fabric == NULL);
      fabric = f;
    }
    if(interface != NULL) {
      assert(transaction.get_tuple_shadow(interface->tid) == interface);
      interfaces.push_back(interface);
    }
    if(t != NULL) {
      tcp_endpoint = t;
    }
    if(fw != NULL) {
      assert(firewall_table == NULL);
      firewall_table = fw->conntrack_table;
    }
  }
}

T_Interface *Switch::add_port(void) {
  // XXX current code only works if firewall is added after ports
  assert(this->firewall_table == NULL);

  T_Interface *interface = new T_Interface(composite_element->transaction);
  interface->tspace_create();
  interface->container = composite_element;

  interface->name = string("port-") + itos(interfaces.size());

  composite_element->components.push_back( Ref<T_PrimitiveElement>(interface) );
  interfaces.push_back(interface);

  // fabric->successors.push_back( Ref<T_PrimitiveElement>(interface) );
  // interface->successors.push_back( Ref<T_PrimitiveElement>(fabric) );

  // directly attach endpoint to all router interfaces
  tcp_endpoint->successors.push_back( Ref<T_PrimitiveElement>(interface) );
  interface->successors.push_back( Ref<T_PrimitiveElement>(tcp_endpoint) );

  return interface;
}

T_Interface *Switch::get_port(int interface_num) {
  assert(0 <= interface_num && interface_num < (int)interfaces.size());
  return interfaces[interface_num];
}

void Switch::add_firewall(void) {
  assert(this->firewall_table == NULL);
  T_Firewall *firewall = new T_Firewall(composite_element->transaction);
  firewall->tspace_create();

  this->firewall_table = new T_FirewallTable(composite_element->transaction);
  this->firewall_table->tspace_create();

  firewall->conntrack_table = this->firewall_table;
  firewall->container = composite_element;
  composite_element->components.push_back(firewall);

  firewall->successors.push_back(fabric);
  // splice this after every interface
  for(size_t i=0; i  <interfaces.size(); i++) {
    T_Interface *interface = interfaces[i];
    interface->successors.push_back(firewall);
  }
}

//
// Router
//

Router::Router(Transaction &transaction, int num_interfaces) {
  composite_element = new T_CompositeElement(transaction);
  fabric = new T_SwitchFabric(transaction);
  tcp_endpoint = new T_ProtocolEndpoint(transaction);

  composite_element->tspace_create();

  fabric->tspace_create();
  tcp_endpoint->tspace_create();

  fabric->container = composite_element;    
  tcp_endpoint->container = composite_element;

  composite_element->components.push_back(fabric);
  composite_element->components.push_back(tcp_endpoint);

  int i;
  for(i=0; i < num_interfaces; i++) {
    add_if();
  }
}

Router::Router(Transaction &transaction, NQ_Tuple tid) :
  composite_element(NULL), fabric(NULL), tcp_endpoint(NULL)
{
  transaction.find_tuple(composite_element, tid);
  assert(composite_element != NULL);
  // cerr << composite_element->components.size() << " components in the router " << composite_element->tid << "\n";
  size_t i;
  for(i=0; i < composite_element->components.size(); i++) {
    // cerr << "Looking for tid[" << i << "]\n";
    T_PrimitiveElement *e = composite_element->components[i].load();
    T_SwitchFabric *f = dynamic_cast<T_SwitchFabric *>(e);
    T_Interface *interface = dynamic_cast<T_Interface *>(e);
    T_ProtocolEndpoint *t = dynamic_cast<T_ProtocolEndpoint *>(e);
    // XXX this may not be precise enough
    if(f != NULL) {
      assert(fabric == NULL);
      fabric = f;
    } else if(interface != NULL) {
      assert(transaction.get_tuple_shadow(interface->tid) == interface);
      interfaces.push_back(interface);
    } else if(t != NULL) {
      tcp_endpoint = t;
    }
  }
}

T_Interface *Router::add_if(void) {
  T_Interface *interface = new T_Interface(composite_element->transaction);
  interface->tspace_create();
  interface->container = composite_element;
  composite_element->components.push_back( Ref<T_PrimitiveElement>(interface) );
  interfaces.push_back(interface);

  fabric->successors.push_back( Ref<T_PrimitiveElement>(interface) );
  interface->successors.push_back( Ref<T_PrimitiveElement>(fabric) );

  // directly attach endpoint to all router interfaces
  tcp_endpoint->successors.push_back( Ref<T_PrimitiveElement>(interface) );
  interface->successors.push_back( Ref<T_PrimitiveElement>(tcp_endpoint) );

  return interface;
}

T_Interface *Router::get_if(int interface_num) {
  assert(0 <= interface_num && interface_num < (int)interfaces.size());
  return interfaces[interface_num];
}

void Router::add_forwarding_entry(uint32_t ip_prefix, int32_t ip_prefix_len, int if_num) {
  ::add_forwarding_entry(fabric, ip_prefix, ip_prefix_len, get_if(if_num));
}

void Router::set_name(const string &str) {
  composite_element->common_name = str;
}

void Router::clear_forwarding_entries(void) {
  fabric->forwarding_table.truncate();
}

string IP_Address_to_string(unsigned int addr) {
  struct in_addr a;
  a.s_addr = addr;
  return string(inet_ntoa( a ));
}

static ostream &output_router_brief(ostream &os, T_CompositeElement *r) {
  os << " (\"" << r->common_name.load() << "\" " << r->tid << ")";
  return os;
}

static ostream &output_interface(ostream &os, T_Interface *iface) {
  if(iface != NULL) {
    output_router_brief((os << iface->name.load() << "@"), iface->container.load());
  } else {
    os << "(NULL)";
  }
  return os;
}

void Router::print(ostream &os) {
  output_router_brief((os << "Router "), composite_element) << "\n";
  os << "Interfaces: \n";
  for(size_t i = 0; i < interfaces.size(); i++) {
    T_Interface *iface = interfaces[i];
    output_interface((os << "\t[" << i << "]: " << iface->name.load() << " => "), iface->external_connection) << "\n";
  }
  os << "FIB: \n";
  for(size_t i = 0; i < fabric->forwarding_table.size(); i++) {
    T_ForwardingEntry entry = fabric->forwarding_table.load(i);
    T_Interface *iface = entry.val.load();
    output_interface((os << "\t" << IP_Address_to_string(entry.h.prefix) << "/" << (int)entry.h.prefix_len << " => " << iface->name.load() << " -- "),
		     iface->external_connection) << "\n";
  }
}

void add_forwarding_entry(T_SwitchFabric *fabric, uint32_t ip_prefix, int32_t ip_prefix_len, T_Interface *interface) {
  fabric->forwarding_table.update(ip_prefix, ip_prefix_len, Ref<T_Interface>(interface));
}

void del_forwarding_entry(T_SwitchFabric *fabric, uint32_t ip_prefix, int32_t ip_prefix_len) {
  printf("Delete forwarding entry not implemented!\n");
  // assert(0);
  printf("Skipping delete\n");
}

#define FOR_ALL_CLASSES(M)		\
  M(Site);

FOR_ALL_CLASSES(TSPACE_DEFINE_CLASS);

void NQ_site_init(void) {
  static bool initialized;
  if(initialized) {
    cerr << "called site initialization again!\n";
    return;
  }
  initialized = true;

  // Initialize known classes
  FOR_ALL_CLASSES(TSPACE_ADD_CLASS);
}

#ifdef __LINUX__
const char *host_export_fname = "/nfs/export-host.tid";
#endif

void NQ_export_host_tid(Host *host) {
  NQ_Tuple tid = host->composite_element->tid;
#ifdef __LINUX__
  cerr << "Writing host tid to " << host_export_fname << "\n";
  ofstream os(host_export_fname, ofstream::binary);
  file_marshall(tid, os);
  os.close();
#else
  cerr << "Writing host tid to environment\n";
  vector<unsigned char> v;
  tspace_marshall(tid, v);
  KernelFS_SetEnv("host_tid", (char *)vector_as_ptr(v), v.size());
#endif
}

#ifdef __LINUX__
char *get_raw_host_tid(int *len_p) {
  ifstream is(host_export_fname, ifstream::binary);
  vector<unsigned char> d0;
  get_all_file_data(is, d0);
  is.close();

  // convert to C array
  int len = d0.size();
  char *rv = (char *)malloc(len);
  memcpy(rv, vector_as_ptr(d0), len);
  *len_p = len;
  return rv;
}
#else
char *get_raw_host_tid(int *len) {
  return Env_get_value("host_tid", len);
}
#endif

NQ_Tuple NQ_get_host_tid(void) {
  int tid_len;
  char *tid_data = get_raw_host_tid(&tid_len);
  cerr << "tid_len = " << tid_len << "\n";
  assert(tid_len == sizeof(NQ_Tuple));
  DataBuffer rv((unsigned char *)tid_data, tid_len);
  CharVector_Iterator begin = rv.begin();
  NQ_Tuple *tuple;
  tuple = tspace_unmarshall( (NQ_Tuple*)0, *(Transaction *)0, begin, rv.end() );
  return *tuple;
}
