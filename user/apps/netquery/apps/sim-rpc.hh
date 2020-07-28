#ifndef _SIM_RPC_HH_
#define _SIM_RPC_HH_

#include <nq/util.hh>
#include "sim-adapters.hh"
#include "eventqueue.hh"

struct RPC_Endpoint {
  EventQueue *sim_ctx;
  Topology *topo;
  uint32_t ip_location;

  RPC_Endpoint(EventQueue *s, Topology *t, uint32_t ip_loc) : 
    sim_ctx(s), topo(t), ip_location(ip_loc) { }
  // force this to be polymorphic
  virtual ~RPC_Endpoint() { }

  template<class T>
  void issue_rpc(T RPC) {
    uint32_t dest_ip = RPC.server->ip_location;
    RPC.client = this;
    sim_ctx->log_curr_event( "RPCIssue(" + RPC.to_string() + 
			     ")" ); // + ip_to_string(ip_location) + "=>" + ip_to_string(dest_ip) );
    topo->reliable_send_event(sim_ctx, 
			      IP_TO_VERTEX(topo, ip_location),
			      RPC.server->ip_location,
			      CheckIP(dest_ip, ReliableStream(RPC)));
  }
};

struct RPCContinuation {
  // Not polymorphic ; intended to be used purely by value
  RPC_Endpoint *client, *server;
  RPCContinuation(RPC_Endpoint *s) : client(NULL), server(s) { }

  void set_router(SimRouter *r) { }
  size_t compute_rpc_size(size_t payload_size) const {
    return payload_size;
  }
  void fail(std::ostream &os, double curr_time) {
    os << "RPC => FAIL";
  }

  // string to_string() const;
  // size_t size() const;
};

#endif
