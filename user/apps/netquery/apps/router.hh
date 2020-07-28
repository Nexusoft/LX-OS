#include <string>
#include <vector>
#include <ext/hash_map>
#include <map>
#include <iostream>

#include <nq/netquery.h>
#include <nq/tuple.hh>
#include <nq/net_elements.hh>
#include <nq/ip.hh>
#include <nq/util.hh>
#include <nq/uuid.h>

#include <nq/site.hh>

void connect_interfaces(T_Interface *src, T_Interface *dest);

bool trust_all(NQ_Tuple tid, KnownClass *obj_class);
bool trust_attrval_all(NQ_Attribute_Name *name, NQ_Tuple tid, NQ_Principal *principal);

NQ_Tuple /* flow_tid */ 
NQ_Flow_create(int protocol, NQ_Principal *principal,
	       /* T_ProtocolEndpoint *src, T_Interface *ingress, */
	       NQ_Tuple src_tid, NQ_Tuple exit_interface_tid,
	       const EndpointIdentifier &dst, 
	       T_Flow::RouteState *route_state,
	       bool do_analysis = true, 
	       bool include_interfaces = false) throw(NQ_Exception);
int NQ_Flow_destroy(NQ_Tuple /* flow_tid */ flow_tid) throw(NQ_Exception);

struct FlowStatistics {
  int num_try_routes;
  int num_good_routes;
  int num_uncomputed_routes;

  int num_touched_flows; // 1 per transaction that modified any of the inputs of a flow
  int num_reroute;
  int num_good_reroute;

  int num_skipped_reroute;

  FlowStatistics() {
    num_try_routes = 0;
    num_good_routes = 0;

    num_touched_flows = 0;
    num_reroute = 0;
    num_good_reroute = 0;
    num_skipped_reroute = 0;
  }
};

std::ostream &operator<<(std::ostream &os, const FlowStatistics &stats);

extern FlowStatistics flow_stats;

extern bool error_on_upcall;

namespace NQ_Flow_debug {
  extern bool detected_dep_change;
  extern bool dep_change_success;
}

struct POP_Map {
  typedef __gnu_cxx::hash_map<const std::string, NQ_Host > LocationMap;
  LocationMap location_host_map;

  struct LineParser {
    POP_Map &c;
    LineParser(POP_Map &container) : 
      c(container) { }
    bool operator() (const std::string &line);
  };

  POP_Map(const std::string &ifname);
  const NQ_Host *find(const std::string &hostname) const;
};

struct Router_TIDs {
  NQ_Tuple tid;
  inline Router_TIDs(Router *r) : tid(r->composite_element->get_tid()) 
  { }
  inline Router_TIDs() : tid(NQ_uuid_null) {}

  void marshall(std::ostream &os);

  static Router_TIDs *unmarshall(CharVector_Iterator &curr, const CharVector_Iterator &end);
};

typedef std::map<int, Router_TIDs *> EmulatorRouters;

void load_tids_from_emulator(const std::string &fname, EmulatorRouters *tids);

static inline uint32_t ROUTERID_TO_IP(int R) {
  // Zero extend
  return ((uint32_t)R) & 0xffff;
}
static inline int IP_TO_ROUTERID(uint32_t I) {
  // Mask and sign extend
  return (int16_t)I;
}

extern int do_print_routing;
extern bool do_flow_maintenance;
extern NQ_Principal *g_flow_principal;
