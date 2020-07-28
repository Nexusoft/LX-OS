#include <nq/net_elements.hh>
#include <iostream>
#include <assert.h>
#include <inttypes.h>
#include <nq/util.hh>
#include <arpa/inet.h>

using std::cerr;

template<>
NQ_Attribute_Type tspace_get_attribute_type<EndpointIdentifier>() {
  return NQ_ATTRIBUTE_RAW;
}

namespace NQ_DefaultValues {
  MAC_Address null_mac_address;
};

template<> NQ_Attribute_Type tspace_get_attribute_type<MAC_Address>() {
  return NQ_ATTRIBUTE_RAW;
}

//////////////
// T_CompositeElement
//////////////

std::string T_CompositeElement::as_abbrv_str(void) {
  std::stringstream msg_buf;
  msg_buf <<  typeid(this).name() << " tid= " << tid << " common_name = " << common_name.load();
  return msg_buf.str();
}

//////////////
// T_PrimitiveElement
//////////////

bool T_PrimitiveElement::check_local_delivery(const EndpointIdentifier &dest) {
  return false;
}

void T_PrimitiveElement::forward_to_successors(SimulateForwardingContext &ctx) {
  size_t i;
  for(i=0; i < successors.size(); i++) {
    ctx.simulate_next( successors[i].load() );
  }
}

void SimulateForwardingContext::simulate_next(T_PrimitiveElement *next) {
  if( loop_map.find(next->tid) == loop_map.end() ) {
    // element does not exist
    result.push_back(Ref<T_PrimitiveElement>(next));
    loop_map[next->tid] = next;
    next->simulate_forwarding(*this);
  } else {
    // cerr << "loop detected\n";
  }
}

//////////////
// T_ProtocolEndpoint
//////////////

void T_ProtocolEndpoint::tspace_create(void) 
  throw(NQ_Access_Exception) {
  tspace_create_generic("ProtocolEndpoint");
}

void T_ProtocolEndpoint::simulate_forwarding(SimulateForwardingContext &ctx) {
  // Do nothing
  return;
}

bool T_ProtocolEndpoint::check_local_delivery(const EndpointIdentifier &dest) {
  return ((EndpointIdentifier)this->id) == dest;
}

//////////////
// T_PrimitiveElement
//////////////

bool T_PrimitiveElement::is_interface(T_PrimitiveElement * const &x) {
  return dynamic_cast<const T_Interface *>(x) != NULL;
}

bool T_PrimitiveElement::is_endpoint(T_PrimitiveElement * const &x) {
  return dynamic_cast<const T_ProtocolEndpoint *>(x) != NULL;
}

//////////////
// T_Label
//////////////

void T_Label::tspace_create(void) 
  throw(NQ_Access_Exception) {
  tspace_create_generic("Label");
}

//////////////
// T_X509
//////////////

void T_X509::tspace_create(void) 
  throw(NQ_Access_Exception) {
  tspace_create_generic("X509");
}


//////////////
// T_Actor
//////////////

void T_Actor::tspace_create_finish(void) {
  assert(_entity != NULL);
  entity = _entity;
  _entity = NULL;
}

void T_Actor::tspace_create(void) 
  throw(NQ_Access_Exception) {
  tspace_create_generic("Actor");
  tspace_create_finish();
}

//////////////
// T_Organization
//////////////

void T_Organization::tspace_create(void) 
  throw(NQ_Access_Exception) {
  tspace_create_generic("Organization");
  tspace_create_finish();
}

//////////////
// T_CompositeElement
//////////////

int composite_element_count = 0;
void T_CompositeElement::tspace_create(void) 
  throw(NQ_Access_Exception) {
  tspace_create_generic("CompositeElement");
  composite_element_count++;
}

T_Interface *T_CompositeElement::simulate_forwarding(T_Interface *ingress, const EndpointIdentifier &dest) throw (NQ_Exception) {
  // cerr << "Forwarding at " << *this << "\n";
  if(this != ingress->container) {
    throw NQ_Schema_Exception("ingress container mismatch");
  }

  // N.B. Finger context of ingress and of container might be different
  SimulateForwardingContext fwd_ctx(dest);
  ingress->simulate_forwarding(fwd_ctx);

  std::vector<T_PrimitiveElement*> results = 
    filter_vector<T_PrimitiveElement *>(fwd_ctx.result, T_PrimitiveElement::is_interface);
  if(results.size() == 0) {
    // cerr << "simulate_forwarding did not find an interface\n";
    return NULL;
  }

  if(results.size() > 1) {
    cerr << "warning: forwarding got more than one egress interface, only one handled right now";
    throw NQ_Unimplemented_Exception("more than one egress interface");
  }
  T_Interface *interface = dynamic_cast<T_Interface *>(results[0]);
  assert(interface != NULL);
  return interface;
}

void T_CompositeElement::simulate_local_delivery(T_Interface *ingress, const EndpointIdentifier &dest, std::vector<T_ProtocolEndpoint*> &results) throw (NQ_Exception) {
  if(this != ingress->container) {
    throw NQ_Schema_Exception("ingress container mismatch");
  }

  // N.B. Finger context of ingress and of container might be different
  SimulateForwardingContext fwd_ctx(dest);
  ingress->simulate_forwarding(fwd_ctx);

  size_t i;
  int count = 0;
  for(i=0; i < fwd_ctx.result.size(); i++) {
    if( fwd_ctx.result[i]->is_endpoint() ) {
      T_ProtocolEndpoint *r = 
	dynamic_cast<T_ProtocolEndpoint *>(fwd_ctx.result[i]);
      assert(r != NULL);
      if(r->id.load() == dest) {
	results.push_back(r);
	count++;
      }
    }
  }
  if(count == 0) {
    // cerr << "simulate_local_delivery did not find matching endpoints\n";
  }
}

//////////////
// T_Interface
//////////////

void T_Interface::simulate_forwarding(SimulateForwardingContext &ctx) {
  forward_to_successors(ctx);
}

//////////////
// T_Interface
//////////////

void T_Interface::tspace_create(void) 
  throw(NQ_Access_Exception) {
  tspace_create_generic("Interface");
}

//////////////
// T_SwitchFabric
//////////////

void T_SwitchFabric::tspace_create(void) 
  throw(NQ_Access_Exception) {
  tspace_create_generic("SwitchFabric");
}

void T_SwitchFabric::simulate_forwarding(SimulateForwardingContext &ctx) {
  assert(ctx.dest.layers.size() >= 2);
  LayerIdentifier *mac = &ctx.dest.layers[0];
  const LayerIdentifier *ip = &ctx.dest.layers[1];
  assert(mac->type == LAYER_IDENTIFIER_ETH &&
	 ip->type == LAYER_IDENTIFIER_IP);

  size_t l2_tab_size = l2_forwarding_table.size();
  size_t arp_tab_size = arp_table.size();
  if(arp_tab_size > 0) { // XXX is this the proper logic to use?
    cerr << "Doing L2 address resolution\n";
    assert(mac != NULL);
    for(size_t i=0; i < arp_tab_size; i++) {
      T_ARPEntry *entry = arp_table[i].load();
      if(ip->data.ip.ip_address == entry->ip) {
	memcpy(mac->data.mac.mac_address, entry->mac.load().m_addr, 6);
	cerr << "ARP translated mac\n";
	break;
      }
    }
  }
  // check l2 first
  MAC_Address l2_dest(mac->data.mac.mac_address);
  if(l2_dest.is_valid() && l2_tab_size > 0) {
    // Has layer 2 header
    for(size_t i=0; i < l2_tab_size; i++) {
      T_MACEntry *entry = l2_forwarding_table[i].load();
      if(entry->addr.load() == l2_dest) {
	ctx.simulate_next(entry->interface.load());
	return;
      }
    }
    cerr << "no MAC match\n";
    return;
  } else {
    // IP forwarding
    T_Interface *best_match = NULL;
    Ref<T_Interface> iface(transaction, NQ_uuid_null);
    if(forwarding_table.lookup(ip->data.ip.ip_address, &iface) == 0) {
      best_match = iface.load();
    }
    if(best_match == NULL) {
      cerr << "No IP match\n";
      return;
    }
    ctx.simulate_next( best_match );
    return;
  }
  // should not be reached
  assert(0);
}

//////////////
// T_Flow
//////////////

void T_Flow::tspace_create(void) 
  throw(NQ_Access_Exception) {
  tspace_create_generic("Flow");
}

std::ostream &operator<<(std::ostream &os, T_Flow &flow) {
  T_ProtocolEndpoint *dest = flow.dest.load();
  os << "State " << flow.route_state << " Source: " << flow.source.load()->id.load() << "Dest: ";
  if(dest != NULL) {
    os << dest->id.load();
  } else {
    os << "(null)";
  }
  os << "\nRoute: {\n";

  size_t i;
  for(i=0; i < flow.route.size(); i++) {
    T_Tuple *tuple = flow.route[i].load();
    T_NetworkElement *element = dynamic_cast<T_NetworkElement *>(tuple);
    T_Interface *interface = dynamic_cast<T_Interface *>(tuple);
    os << "[" << i << "]: ";
    if(element != NULL) {
      os << *element << "\n";
    } else if(interface != NULL) {
      os << "[interface]" << "\n";
    } else {
      os << "[unsupported]" << "\n";
    }
  }
  os << "}\n";
  return os;
}

//////////////
// T_Process
//////////////

void T_Process::tspace_create(void) 
  throw(NQ_Access_Exception) {
  tspace_create_generic("Process");
  T_Actor *actor = new T_Actor(transaction, this);
  actor->tspace_create();
  this->actor = actor;
}

void T_Process::simulate_forwarding(SimulateForwardingContext &ctx) {
  // Do nothing
  return;
}

//////////////
//  T_PolicyEnforcer
//////////////

void T_PolicyEnforcer::tspace_create(void) 
  throw(NQ_Access_Exception) {
  T_Process::tspace_create();
  class_type = "PolicyEnforcer";
}

template<> void T_ProcessList::tspace_create(void) 
  throw(NQ_Access_Exception) {
  tspace_create_generic("ProcessList");
}

template<> void T_ProcessList::simulate_forwarding(SimulateForwardingContext &ctx) {
  // Do nothing
  return;
}

void T_TCPFlowEntry::tspace_create(void) 
  throw(NQ_Access_Exception) {
  tspace_create_generic("TCPFlowEntry");
}

void T_TCPFlowEntry::simulate_forwarding(SimulateForwardingContext &ctx) {
  return;
}

void T_Firewall::tspace_create(void) 
  throw(NQ_Access_Exception) {
  tspace_create_generic("Firewall");
}

void T_Firewall::simulate_forwarding(SimulateForwardingContext &ctx) {
  assert(successors.size() == 1);
  forward_to_successors(ctx);
  return;
}

void T_FirewallTable::tspace_create(void) 
  throw(NQ_Access_Exception) {
  tspace_create_generic("FirewallTable");
}

void T_MACEntry::tspace_create(void) throw(NQ_Access_Exception) {
  tspace_create_generic("MACEntry");
}
void T_MACEntry::simulate_forwarding(SimulateForwardingContext &ctx) {
  return;
}

void T_ARPEntry::tspace_create(void) throw(NQ_Access_Exception) {
  tspace_create_generic("ARPEntry");
  return;
}
void T_ARPEntry::simulate_forwarding(SimulateForwardingContext &ctx) {
  assert(0);
  return;
}


std::ostream &operator<<(std::ostream &os, const MAC_Address &v) {
  std::cout << "addr = ";
  for(size_t i=0; i < sizeof(v.m_addr); i++) {
    std::cout << std::hex << (int) v.m_addr[i] << std::dec << " ";
  }
  std::cout << "\n";
  return os;
}

//////////////
// Reflection initialization
//////////////

#define FOR_ALL_CLASSES(M)			\
  M(Flow);					\
  M(ProtocolEndpoint);			\
  M(CompositeElement);			\
  M(Interface);					\
  M(SwitchFabric);				\
  M(X509);				\
  M(Process);				\
  M(ProcessList);				\
  M(Label);				\
  M(TCPFlowEntry);				\
  M(Firewall);				\
  M(FirewallTable);				\
  M(Actor);				\
  M(Organization);				\
  M(PolicyEnforcer);				\
  M(MACEntry);				\
  M(ARPEntry);				\

FOR_ALL_CLASSES(TSPACE_DEFINE_CLASS);

// abstract: NetworkElement, PrimitiveElement, 

void NQ_net_elements_init(void) {
  static bool initialized;
  if(initialized) {
    cerr << "called elements initialization again!\n";
    return;
  }
  initialized = true;

  // Initialize known classes
  FOR_ALL_CLASSES(TSPACE_ADD_CLASS);
}
