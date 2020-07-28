#ifndef _NQ_NET_ELEMENTS_H_
#define _NQ_NET_ELEMENTS_H_

#include <vector>
#include <iostream>
#include <iomanip>
#include <stdint.h>

#include <ext/hash_map>
#include <nq/ip.hh>
#include <nq/tuple.hh>
#include <nq/attribute.hh>
#include <nq/util.hh>

typedef unsigned int IP_Address;
typedef unsigned short IP_Port;

namespace NQ_DefaultValues {
  extern MAC_Address null_mac_address;
}

typedef T_Scalar<MAC_Address, NQ_DefaultValues::null_mac_address> T_MAC_Address;
typedef T_Scalar<IP_Address, NQ_DefaultValues::uzero> T_IP_Address;

struct T_CompositeElement;

struct SimulateForwardingContext;
struct T_PrimitiveElement : T_Tuple {
  T_Vector< Ref<T_PrimitiveElement> > successors;
  T_Reference<T_CompositeElement> container;

  T_PrimitiveElement(Transaction &transaction) :
    T_Tuple(transaction),
    successors(this, "PrimitiveElement.successors"),
    container(this, "PrimitiveElement.container")
  { }

  T_PrimitiveElement(Transaction &transaction, const NQ_Tuple &tid) :
    T_Tuple(transaction, tid),
    successors(this, "PrimitiveElement.successors"),
    container(this, "PrimitiveElement.container")
  { }

  // Recursively try to "forward" packet to destination result
  // contains egress interfaces and local endpoints. Elements are
  // pushed onto &result by the predecessor (see code in
  // T_Interface::simulate_forwarding()

  void forward_to_successors(SimulateForwardingContext &ctx);

  virtual void simulate_forwarding(SimulateForwardingContext &ctx) = 0;
  virtual bool check_local_delivery(const EndpointIdentifier &dest);

  static bool is_interface(T_PrimitiveElement * const &x);
  static bool is_endpoint(T_PrimitiveElement * const &x);

  inline bool is_interface(void) {
    return T_PrimitiveElement::is_interface(this);
  }
  inline bool is_endpoint(void) {
    return T_PrimitiveElement::is_endpoint(this);
  }
};

struct T_Label : T_Tuple {
  T_string der; // DER format expression
  T_Label(Transaction &transaction) :
    T_Tuple(transaction),
    der(this, "Statement.der")
  { }
  T_Label(Transaction &transaction, const NQ_Tuple &tid) :
    T_Tuple(transaction, tid),
    der(this, "Statement.der")
  { }

  virtual void tspace_create(void) throw(NQ_Access_Exception);
};

struct SimulateForwardingContext {
  const EndpointIdentifier &orig_dest;
  EndpointIdentifier dest; // dest with translations
  std::vector< T_PrimitiveElement * > result;
  __gnu_cxx::hash_map<const NQ_Tuple, T_Tuple *> loop_map;

  SimulateForwardingContext(const EndpointIdentifier &_dest) : orig_dest(_dest)
    {
      // push on an invalid MAC header. This will be filled in during forwarding
      dest.layers.push_back( EthLayer(MAC_Address()) );
      for(size_t i=0; i < orig_dest.layers.size(); i++) {
	dest.layers.push_back(orig_dest.layers[i]);
      }
      assert(!MAC_Address(dest.layers[0].data.mac.mac_address).is_valid());
    }
  void simulate_next(T_PrimitiveElement *next);
};

struct T_ProtocolEndpoint : T_PrimitiveElement {
  T_EndpointIdentifier id;

  inline T_ProtocolEndpoint(Transaction &transaction) : 
    T_PrimitiveElement(transaction), 
    id(this, "ProtocolEndpoint.id") { }

  inline T_ProtocolEndpoint(Transaction &transaction, const NQ_Tuple &tid) : 
    T_PrimitiveElement(transaction, tid), 
    id(this, "ProtocolEndpoint.id") { }

  virtual void tspace_create(void) throw(NQ_Access_Exception);

  virtual void simulate_forwarding(SimulateForwardingContext &ctx);
  virtual bool check_local_delivery(const EndpointIdentifier &dest);
};

struct T_Interface;

struct T_NetworkElement : T_Tuple {

  T_NetworkElement(Transaction &transaction) :
    T_Tuple(transaction) { }
  T_NetworkElement(Transaction &transaction, const NQ_Tuple &tid) :
    T_Tuple(transaction, tid) { }

  // Route through the composite element, starting from ingress
  virtual T_Interface *simulate_forwarding(T_Interface *ingress, const EndpointIdentifier &dest) throw(NQ_Exception) = 0;

  // Check which local primitive elements handle the specified endpoint
  // xxx performance will be unacceptable with a large number of ports
  // unless this is indexed
  virtual void simulate_local_delivery(T_Interface *ingress,  const EndpointIdentifier &dest, std::vector<T_ProtocolEndpoint*> &results) throw(NQ_Exception) = 0;
};

struct T_X509 : T_Tuple {
  T_string val;
  T_X509(Transaction &transaction) :
    T_Tuple(transaction),
    val(this, "X509.val")
  { }
  T_X509(Transaction &transaction, const NQ_Tuple &tid) :
    T_Tuple(transaction, tid),
    val(this, "X509.val")
  { }

  virtual void tspace_create(void) throw(NQ_Access_Exception);
};

struct T_Actor : T_Tuple {
  T_Principal principal;
  T_Reference<T_Tuple> entity; // the entity that performs the actions

  T_Reference<T_Actor> installed_by;

private:
  T_Tuple *_entity;

public:
  inline T_Actor(Transaction &transaction, T_Tuple *_ent = NULL) :
    T_Tuple(transaction),
    principal(this, "Actor.principal"),
    entity(this, "Actor.entity"),
    installed_by(this, "Actor.installed_by"),
    _entity( (_ent != NULL) ? _ent : this) { }
  inline T_Actor(Transaction &transaction, const NQ_Tuple &tid) : 
    T_Tuple(transaction, tid),
    principal(this, "Actor.principal"),
    entity(this, "Actor.entity"),
    installed_by(this, "Actor.installed_by"),
    _entity(NULL) {
  }

  virtual void tspace_create(void) throw(NQ_Access_Exception);
  void tspace_create_finish(void);
};

struct T_CompositeElement : T_NetworkElement {
  T_Vector< Ref<T_PrimitiveElement> > components;
  T_string common_name;

  T_Reference<T_X509> identity; // identity

  // TODO Get rid of certificate_chain
  T_Vector< Ref<T_X509> > certificate_chain; // certificates potentially needed to check identity
  T_Vector< Ref<T_Label> > labels;

  T_Reference<T_Actor> installed_by;
  T_Reference<T_Actor> policy_enforced_by;

  inline T_CompositeElement(Transaction &transaction) : 
    T_NetworkElement(transaction), 
    components(this, "CompositeElement.components"),
    common_name(this, "CompositeElement.common_name"),
    identity(this, "CompositeElement.identity"),
    certificate_chain(this, "CompositeElement.certificate_chain"),
    labels(this, "CompositeElement.labels"),
    installed_by(this, "CompositeElement.installed_by"),
    policy_enforced_by(this, "CompositeElement.policy_enforced_by")
  { }
  inline T_CompositeElement(Transaction &transaction, const NQ_Tuple &tid) : 
    T_NetworkElement(transaction, tid), 
    components(this, "CompositeElement.components"),
    common_name(this, "CompositeElement.common_name"),
    identity(this, "CompositeElement.identity"),
    certificate_chain(this, "CompositeElement.certificate_chain"),
    labels(this, "CompositeElement.labels"),
    installed_by(this, "CompositeElement.installed_by"),
    policy_enforced_by(this, "CompositeElement.policy_enforced_by")
  { }

  virtual void tspace_create(void) throw(NQ_Access_Exception);

  virtual T_Interface *simulate_forwarding(T_Interface *ingress, const EndpointIdentifier &dest) throw(NQ_Exception);
  virtual void simulate_local_delivery(T_Interface *ingress, const EndpointIdentifier &dest, std::vector<T_ProtocolEndpoint*> &results) throw(NQ_Exception);

  virtual std::string as_abbrv_str(void);
};

struct T_Interface : T_PrimitiveElement {
  // MediaType media_type;
  // LinkState link_state;
  // AdminState admin_state;
  T_Reference<T_Interface> external_connection;
  T_int32 external_connection_verified;
  T_string name;

  inline T_Interface(Transaction &transaction) : 
    T_PrimitiveElement(transaction), 
    external_connection(this, "Interface.external_connection"),
    external_connection_verified(this, "Interface.external_connection_verified"),
    name(this, "Interface.name") { }

  inline T_Interface(Transaction &transaction, const NQ_Tuple &tid) : 
    T_PrimitiveElement(transaction, tid), 
    external_connection(this, "Interface.external_connection"),
    external_connection_verified(this, "Interface.external_connection_verified"),
    name(this, "Interface.name") { }

  virtual void tspace_create(void) throw(NQ_Access_Exception);

  virtual void simulate_forwarding(SimulateForwardingContext &ctx);
};

typedef TrieValue<Ref<T_Interface> > T_ForwardingEntry;

struct T_MACEntry : T_Tuple {
  T_MAC_Address addr;
  T_Reference<T_Interface> interface;

  inline T_MACEntry(Transaction &transaction) : 
    T_Tuple(transaction), 
    addr(this, "MACEntry.addr"),
    interface(this, "MACEntry.interface")
  { }

  inline T_MACEntry(Transaction &transaction, const NQ_Tuple &tid) : 
    T_Tuple(transaction, tid), 
    addr(this, "MACEntry.addr"),
    interface(this, "MACEntry.interface")
  { }

  virtual void tspace_create(void) throw(NQ_Access_Exception);
  virtual void simulate_forwarding(SimulateForwardingContext &ctx);
};

struct T_ARPEntry : T_Tuple {
  T_IP_Address ip;
  T_MAC_Address mac;

  inline T_ARPEntry(Transaction &transaction) : 
    T_Tuple(transaction), 
    ip(this, "ARPEntry.ip"),
    mac(this, "ARPEntry.mac")
  { }

  inline T_ARPEntry(Transaction &transaction, const NQ_Tuple &tid) : 
    T_Tuple(transaction, tid), 
    ip(this, "ARPEntry.ip"),
    mac(this, "ARPEntry.mac")
  { }

  virtual void tspace_create(void) throw(NQ_Access_Exception);
  virtual void simulate_forwarding(SimulateForwardingContext &ctx);
};

struct T_SwitchFabric : T_PrimitiveElement {
  // Invariant: Every interface referenced by forwarding_entry is in successors
  T_Trie< Ref<T_Interface> > forwarding_table;
  T_Vector< Ref<T_MACEntry> > l2_forwarding_table;
  T_Vector< Ref<T_ARPEntry> > arp_table;

  // Routers increment the forwarding_table_version on every write
  // Used to send new forwarding tables as deltas, rather than complete tables
  T_int32 forwarding_table_version;

  inline T_SwitchFabric(Transaction &transaction) : 
    T_PrimitiveElement(transaction), 
    forwarding_table(this, "SwitchFabric.forwarding_table"),
    l2_forwarding_table(this, "SwitchFabric.l2_forwarding_table"),
    arp_table(this, "SwitchFabric.arp_table"),
    forwarding_table_version(this, "SwitchFabric.forwarding_table_version")
  { }

  inline T_SwitchFabric(Transaction &transaction, const NQ_Tuple &tid) : 
    T_PrimitiveElement(transaction, tid), 
    forwarding_table(this, "SwitchFabric.forwarding_table"),
    l2_forwarding_table(this, "SwitchFabric.l2_forwarding_table"),
    arp_table(this, "SwitchFabric.arp_table"),
    forwarding_table_version(this, "SwitchFabric.forwarding_table_version")
  { }

  virtual void tspace_create(void) throw(NQ_Access_Exception);

  virtual void simulate_forwarding(SimulateForwardingContext &ctx);
};

struct T_TCPFlowEntry : T_Tuple {
  T_uint32 saddr;
  T_uint16 sport;
  T_uint32 daddr;
  T_uint16 dport;

  inline T_TCPFlowEntry(Transaction &transaction) : 
    T_Tuple(transaction), 
    saddr(this, "TCPFlowEntry.saddr"),
    sport(this, "TCPFlowEntry.sport"),
    daddr(this, "TCPFlowEntry.daddr"),
    dport(this, "TCPFlowEntry.dport")
  { }

  inline T_TCPFlowEntry(Transaction &transaction, const NQ_Tuple &tid) : 
    T_Tuple(transaction, tid), 
    saddr(this, "TCPFlowEntry.saddr"),
    sport(this, "TCPFlowEntry.sport"),
    daddr(this, "TCPFlowEntry.daddr"),
    dport(this, "TCPFlowEntry.dport")
  { }

  virtual void tspace_create(void) throw(NQ_Access_Exception);
  virtual void simulate_forwarding(SimulateForwardingContext &ctx);
};

struct T_FirewallTable : T_Tuple {
  T_Vector< Ref<T_TCPFlowEntry> > entries;

  inline T_FirewallTable(Transaction &transaction) : 
    T_Tuple(transaction),
    entries(this, "FirewallTable.entries")
  { }
  inline T_FirewallTable(Transaction &transaction, const NQ_Tuple &tid) : 
    T_Tuple(transaction, tid),
    entries(this, "FirewallTable.entries")
  { }

  virtual void tspace_create(void) throw(NQ_Access_Exception);
};

struct T_Firewall : T_PrimitiveElement {
  // XXX use indexed data structure
  T_Reference<T_FirewallTable> conntrack_table;

  inline T_Firewall(Transaction &transaction) : 
    T_PrimitiveElement(transaction), 
    conntrack_table(this,"Firewall.conntrack_table")
  { }

  inline T_Firewall(Transaction &transaction, const NQ_Tuple &tid) : 
    T_PrimitiveElement(transaction, tid), 
    conntrack_table(this,"Firewall.conntrack_table")
  { }

  virtual void tspace_create(void) throw(NQ_Access_Exception);
  virtual void simulate_forwarding(SimulateForwardingContext &ctx);
};

//////////////
/// NQ protocol elements
//////////////

/*
class Flow :
<
protocol : ProtocolLayer,
source : ProtocolEndpoint , dest : ProtocolEndpoint,
waypoints : NetworkElement, route : [ NetworkElement ]
>
*/

#define NQ_FLOW_HOPLIMIT (50)
struct T_Flow : T_Tuple {
  // for now, skip protocol layer
  T_Reference<T_ProtocolEndpoint> source;
  T_Reference<T_Interface> ingress;
 // The ingress point is where the source host enters the network
 // infrastructure. For instance, this could be its upstream Ethernet
 // switch. When flows are used for policy enforcement, NetQuery will
 // use ingress as a starting point from which it will insert a flow
 // creation guard.

  T_EndpointIdentifier dest_id;

  T_Reference<T_ProtocolEndpoint>dest;
  T_Vector< Ref<T_Tuple> > route;
  T_int32 route_state;
  T_int32 include_interfaces;

  enum RouteState {
    NO_ROUTE, VALID_ROUTE, UNCOMPUTED_ROUTE,
  };

  inline T_Flow(Transaction &transaction) : 
    T_Tuple(transaction), 
    source(this, "Flow.source"),
    ingress(this, "Flow.ingress"),
    dest_id(this, "Flow.dest_id"),
    dest(this, "Flow.dest"),
    route(this, "Flow.route"),
    route_state(this, "Flow.route_state"),
    include_interfaces(this, "Flow.include_interfaces") { }

  inline T_Flow(Transaction &transaction, const NQ_Tuple &tid) : 
    T_Tuple(transaction, tid),
    source(this, "Flow.source"),
    ingress(this, "Flow.ingress"),
    dest_id(this, "Flow.dest_id"),
    dest(this, "Flow.dest"),
    route(this, "Flow.route"),
    route_state(this, "Flow.route_state"),
    include_interfaces(this, "Flow.include_interfaces") { }

  virtual void tspace_create(void) throw(NQ_Access_Exception);

  inline void invalidate() {
    route_state = T_Flow::NO_ROUTE;
    route.truncate();
  }
};

struct T_Process : T_PrimitiveElement {
  T_string key; // unique id i.e. ipd id
  T_string name; // english name
  T_blob hash;
  T_Reference<T_Actor> actor;

  inline T_Process(Transaction &transaction) : 
    T_PrimitiveElement(transaction),
    key(this, "Process.key"),
    name(this, "Process.name"),
    hash(this, "Process.hash"),
    actor(this, "Process.actor") { }
  inline T_Process(Transaction &transaction, const NQ_Tuple &tid) :
    T_PrimitiveElement(transaction, tid),
    key(this, "Process.key"),
    name(this, "Process.name"),
    hash(this, "Process.hash"),
    actor(this, "Process.actor") { }

  virtual void tspace_create(void) throw(NQ_Access_Exception);
  virtual void simulate_forwarding(SimulateForwardingContext &ctx);
};

struct T_PolicyEnforcer : T_Process {
  T_string l2_policy;
  T_string l3_policy;

  inline T_PolicyEnforcer(Transaction &transaction) : 
    T_Process(transaction),
    l2_policy(this, "PolicyEnforcer.l2_policy"),
    l3_policy(this, "PolicyEnforcer.l3_policy") { }
  inline T_PolicyEnforcer(Transaction &transaction, const NQ_Tuple &tid) :
    T_Process(transaction, tid),
    l2_policy(this, "PolicyEnforcer.l2_policy"),
    l3_policy(this, "PolicyEnforcer.l3_policy") { }

  virtual void tspace_create(void) throw(NQ_Access_Exception);
};

struct T_Organization : T_Actor {
  T_string common_name;

  inline T_Organization(Transaction &transaction) : 
    T_Actor(transaction),
    common_name(this, "Organization.common_name")
  { }
  inline T_Organization(Transaction &transaction, const NQ_Tuple &tid) :
    T_Actor(transaction, tid),
    common_name(this, "Organization.common_name")
  { }

  virtual void tspace_create(void) throw(NQ_Access_Exception);
};

// T_ElementList is used as an index to speed up & simplify lookup of the elements within a CompositeElement
template <class Elem> struct T_ElementList : T_PrimitiveElement {
  T_Vector< Ref<Elem> > elems;

  inline T_ElementList(Transaction &transaction) : 
    T_PrimitiveElement(transaction), 
    elems(this, "ElementList.elems") { }
  inline T_ElementList(Transaction &transaction, const NQ_Tuple &tid) :
    T_PrimitiveElement(transaction, tid),
    elems(this, "ElementList.elems") { }

  virtual void tspace_create(void) throw(NQ_Access_Exception);
  virtual void simulate_forwarding(SimulateForwardingContext &ctx);
};

typedef T_ElementList<T_Process> T_ProcessList;

std::ostream &operator<<(std::ostream &os, T_Flow &flow);

void NQ_net_elements_init(void);

#endif // _NQ_NET_ELEMENTS_H_
