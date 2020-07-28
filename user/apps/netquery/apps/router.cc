#include <stdint.h>
#include <vector>
#include <string>
#include <sstream>
#include <iostream>
#include <fstream>
#include <map>

#include "router.hh"
#ifdef __NEXUS__
#include <nq/nexus_file_util.hh>
#else
#include <nq/boost_util.hh>
#endif

#include <ext/hash_set>
#include <ext/hash_map>

using namespace __gnu_cxx;
using namespace std;

FlowStatistics flow_stats;

struct FlowDependencyChange;
typedef hash_map<NQ_Transaction, FlowDependencyChange*, NQ_UUID_hash, NQ_UUID_equals> FlowContextMap;
FlowContextMap flow_contexts;

bool do_flow_maintenance = true;
pthread_mutex_t flow_creation_lock = PTHREAD_MUTEX_INITIALIZER;

std::ostream &operator<<(std::ostream &os, const FlowStatistics &stats) {
  os << 
    " num_try_routes: " << stats.num_try_routes <<
    " ; num_good_routes: " << stats.num_good_routes <<
    " ; num_uncomputed_routes: " << stats.num_uncomputed_routes <<
    
    " ; num_touched_flows: " << stats.num_touched_flows << 
    " ; num_reroute: " << stats.num_reroute <<
    " ; num_good_reroute: " << stats.num_good_reroute <<
    " ; num_skipped_reroutes: " << stats.num_skipped_reroute;

  return os;
}

int do_print_routing = 0;
#define PRINT_NET_START(X) do { if(do_print_routing) { printf("===> \"%s\" START <===\n", #X); } } while (0)
#define PRINT_NET_END(X) do { if(do_print_routing) { printf("===> \"%s\" DONE <===\n", #X); } } while(0)

bool error_on_upcall = false;

void connect_interfaces(T_Interface *src, T_Interface *dest) {
  if(! ((src->external_connection == dest && dest->external_connection == src) ||
	(src->external_connection == NULL && dest->external_connection == NULL)) ) {
    cerr << "connect mismatch src=(" << dest << "," << src << ") dst=" << src->external_connection << " " << dest->external_connection << "\n";
    cerr << "S-" << src->transaction.transaction << " " << &src->transaction << "\n";
    cerr << "D-" << dest->transaction.transaction << " " << &dest->transaction << "\n";

    cerr << " src tid " << src->tid << "\n";
    if(src->external_connection != NULL) {
      cerr << " src ext tid " << src->external_connection.load()->tid << "\n";
      cerr << "SE+" << src->external_connection.load()->transaction.transaction <<
	" " << &src->external_connection.load()->transaction << "\n";
    } else {
      cerr << " src null ";
    }

    cerr << " dest tid " << dest->tid << "\n";
    if(dest->external_connection != NULL) {
      cerr << " dest ext tid " << dest->external_connection.load()->tid << "\n";
      cerr << "DE+" << dest->external_connection.load()->transaction.transaction <<
	" " << &src->external_connection.load()->transaction << "\n";
    } else {
      cerr << " dest null ";
    }
  }
  assert( (src->external_connection == dest && dest->external_connection == src) ||
	 (src->external_connection == NULL && dest->external_connection == NULL));
  src->external_connection = dest;
  dest->external_connection = src;
}

bool trust_all(NQ_Tuple tid, KnownClass *obj_class) {
  // trust everything
  return true;
}
bool trust_attrval_all(NQ_Attribute_Name *name, NQ_Tuple tid, NQ_Principal *principal) {
	  return true;
}



static int NQ_Flow_update_upcall(NQ_Transaction transaction, NQ_Trigger_Description *trigger, NQ_Trigger_Upcall_Type type, int arg, void *userdata);

struct FlowDependencyChange : DependencyTriggerContext {
  NQ_Tuple flow_tid;
  bool is_obsolete;
  bool cleared_triggers;

  // Information from current transaciton
  pthread_mutex_t mutex;

  typedef hash_set<NQ_Transaction, NQ_UUID_hash, NQ_UUID_equals> TransactionSet;

  TransactionSet active_transactions;

  inline FlowDependencyChange(T_Flow *flow) : 
    DependencyTriggerContext(), flow_tid(flow->tid), is_obsolete(false), cleared_triggers(false) {
    mutex = ((pthread_mutex_t)PTHREAD_MUTEX_INITIALIZER);
  }

  // Lock should not be held for long durations
  void lock() {
    pthread_mutex_lock(&mutex);
  }
  void unlock() {
    pthread_mutex_unlock(&mutex);
  }

  // Returns true if the transaction hasn't been seen before
  bool new_transaction(const NQ_Transaction &t) {
    if(active_transactions.find(t) != active_transactions.end()) {
      return false;
    }
    active_transactions.insert(t);
    
    if(0) {
      cerr << "new_transaction (" << this << ") " << t << "\n";
      cerr << "\t is new, size = " << num_active_transactions() << "\n";
    }

    if(num_active_transactions() > 1) {
      cerr << ">>>>>>>>>>>>>>>>> GOT SIMULTANEOUS TRIGGERS\n";
      cerr << ">>>>>>>>>>>>>>>>> GOT SIMULTANEOUS TRIGGERS\n";
      cerr << ">>>>>>>>>>>>>>>>> GOT SIMULTANEOUS TRIGGERS\n";
    }
    return true;
  }
  // Returns true if the transaction was found & deleted
  bool finish_transaction(const NQ_Transaction &t) {
    TransactionSet::iterator i = active_transactions.find(t);
    if(i != active_transactions.end()) {
      active_transactions.erase(i);
      if(0) {
	cerr << "Finish transaction(" << this << ") " << t << "\n";
	cerr << "\t Did erase, size = " << num_active_transactions() << "\n";
      }
      return true;
    }
    return false;
  }
  int num_active_transactions() {
    return active_transactions.size();
  }

  void clear_triggers(Transaction *t_write) {
    if(!cleared_triggers) {
      set->clear_all(t_write);
      cleared_triggers = true;
    } else {
      cerr << "triggers already cleared\n";
    }
  }
};

// Returns a new T_Flow that refers to the newly-created Flow tuple

/* 
 * Routing is sensitive to the starting location
 
 *  The flow creator (src->container) specifies the origin endpoint,
 *  and the ingress point into the routing infrastructure.  Ingress
 *  serves to drive the routing algorithm.
*/

// Must pass in UUID, rather than objects (e.g. T_ProtocolEndpoint)
// that are bound to transactions

#if 0
struct NQ_FlowCreation_Exception : NQ_Exception {
  NQ_FlowCreation_Exception(const std::string &str) : NQ_Exception(str) { }
};
#endif

static T_Flow::RouteState compute_path( Transaction &t,
	T_ProtocolEndpoint *src, T_Interface *ingress,
	const EndpointIdentifier &dst_addr,
	 // outputs
	T_ProtocolEndpoint * &dest_endpoint,
	vector<T_Tuple *> &path,
	bool include_interfaces) {
  if(ingress == NULL) {
    cerr << "compute_path(): Passed null ingress!\n";
    return T_Flow::NO_ROUTE;
  }
  // Verify that ingress is reachable from the host
  bool done = false;
  string err;

  path.clear();
  dest_endpoint = NULL;

#if 1
  // original check: host must pass interface of upstream router
  T_Interface *purported_host_interface = ingress->external_connection;
  if( purported_host_interface == NULL || 
      purported_host_interface->container != src->container ) {
    cerr << "ingress interface not connected to host!\n";
    goto no_route;
    // throw NQ_FlowCreation_Exception("ingress interface not connected to host!\n");
  }
#else
  if(ingress->container != src->container) {
    cerr << "ingress is not in same component as the source endpoint\n";
    goto no_route;
  }
#endif
  assert(path.size() == 0);
  if(include_interfaces) {
    path.push_back(ingress);
  }
  path.push_back( ingress->container );
  // cout << "Ingress : " << *(T_Tuple*)ingress << "\n";
  while(!done) {
    PRINT_NET_START(HOP);
    // cout << "Ingress : " << ingress->tid << "\n";
    // no circularity detector ; cap the allowed length of a route
    if(path.size() > NQ_FLOW_HOPLIMIT) {
      std::stringstream msg_buf("");
      msg_buf << "routing failure: exceeded hop limit ";
      err = msg_buf.str();
      goto no_route;
      // throw NQ_FlowCreation_Exception(msg_buf.str());
    }

    T_NetworkElement *current_element = ingress->container;
    T_Interface *egress =
      current_element->simulate_forwarding(ingress, dst_addr);
    if(egress != NULL) {
      // Advance the finger and push the element on the path
      T_Interface *next;
      next = egress->external_connection;
      if(next == NULL) {
	err = "routed to disconnected interface";
	goto no_route;
	// throw NQ_FlowCreation_Exception("routed to disconnected interface\n");
      }
      if(include_interfaces) {
	path.push_back(egress);
	path.push_back(next);
      }
      ingress = next;
      path.push_back( ingress->container );
    } else {
      std::vector<T_ProtocolEndpoint*> local_endpoints;
      current_element->simulate_local_delivery(ingress, dst_addr, local_endpoints);
      if(local_endpoints.size() == 0) {
	std::stringstream msg_buf("");
	msg_buf << "routing failure at " << *current_element << ": hit dead end without matching local delivery, path len = " << path.size() << "\n";
	err = msg_buf.str();
	goto no_route;
	// throw NQ_FlowCreation_Exception(msg_buf.str());
      }
      if(local_endpoints.size() > 1) {
	std::cerr << "Routing warning: Multiple matching endpoints at destination!\n";
      }
      dest_endpoint = local_endpoints[0];
      done = true;
    }
    PRINT_NET_END(HOP);
  }
 no_route:
  if(done) {
    return T_Flow::VALID_ROUTE;
  } else {
    // cerr << "Flow error = " << err << "\n";
    return T_Flow::NO_ROUTE;
  }
}

static void set_flow_path(T_Flow *new_flow, vector<T_Tuple *> &path) {
  size_t i;
  for(i=0; i < path.size(); i++) {
    new_flow->route.push_back(Ref<T_Tuple>(path[i]));
  }
}

bool skip_flow_triggers = false;
static void set_flow_triggers(Transaction *t, T_Flow *new_flow) {
  if(skip_flow_triggers) {
    cerr << "Skipping flow triggers\n";
    return;
  }
  FlowDependencyChange *change_ctx = new FlowDependencyChange(new_flow);
  flow_contexts[new_flow->tid] = change_ctx;

  NQ_Trigger_Description trigger_template;
  trigger_template.name = NULL;
  trigger_template.tuple = NQ_uuid_null;
  trigger_template.type = NQ_TRIGGER_VALUECHANGED;
  trigger_template.upcall_type = 
    NQ_TRIGGER_UPCALL_SYNC_VERDICT | NQ_TRIGGER_UPCALL_ASYNC_COMMIT_DONE;

  t->set_dependency_triggers(&trigger_template, NQ_Flow_update_upcall, change_ctx);
}

NQ_Tuple /* flow_tid */ 
NQ_Flow_create(int protocol, NQ_Principal *principal,
	       /* T_ProtocolEndpoint *src, T_Interface *ingress, */
	       NQ_Tuple src_tid, NQ_Tuple exit_interface_tid,
	       const EndpointIdentifier &dst, 
	       T_Flow::RouteState *route_state, bool do_analysis, bool include_interfaces) throw(NQ_Exception) {
  int retry_transaction = 1;
  *route_state = T_Flow::NO_ROUTE;
  NQ_Tuple flow_tid = NQ_uuid_null;

  while(retry_transaction) {
    pthread_mutex_lock(&flow_creation_lock);
    Transaction *t = new Transaction(trust_all, trust_attrval_all, principal->home, principal, true);
    T_ProtocolEndpoint *src;
    T_Interface *exit_interface;
    T_Interface *ingress;

    PRINT_NET_START(SETUP);
    t->find_tuple(src, src_tid);
    t->find_tuple(exit_interface, exit_interface_tid);
    ingress = exit_interface->external_connection;
    PRINT_NET_END(SETUP);

    try {
      flow_stats.num_try_routes++;

      T_Flow *new_flow = NULL;
      // Build route incrementally while adding triggers
      string err;

      // retry_transaction will be set to 1 in appropriate exception handler
      retry_transaction = 0;
      new_flow = new T_Flow(*t);
      new_flow->tspace_create();

      new_flow->source = src;
      new_flow->ingress = ingress;
      new_flow->dest = NULL;
      new_flow->dest_id = dst;
      new_flow->include_interfaces = include_interfaces ? 1 : 0;

      T_ProtocolEndpoint *dest_endpoint;
      vector<T_Tuple *> path;

      if(do_analysis) {
	t->restore_logging();
	*route_state = compute_path(*t, src, ingress, dst, 
				    dest_endpoint, path,
				    include_interfaces);
	t->disable_logging();
      } else {
	*route_state = T_Flow::UNCOMPUTED_ROUTE;
      }

      PRINT_NET_START(WRITE PATH);
      new_flow->route_state = *route_state;
      switch(*route_state) {
      case T_Flow::VALID_ROUTE:
	set_flow_path(new_flow, path);
	new_flow->dest = dest_endpoint;
	flow_stats.num_good_routes++;
	break;
      case T_Flow::UNCOMPUTED_ROUTE:
	flow_stats.num_uncomputed_routes++;
	break;
      default:
	new_flow->dest = NULL;
	break;
      }
      PRINT_NET_END(WRITE PATH);

      flow_tid = new_flow->tid;

      // The dependency tracking will tell us when the route we are using might change
      PRINT_NET_START(SET TRIGGERS);
      set_flow_triggers(t, new_flow);
      PRINT_NET_END(SET TRIGGERS);

      PRINT_NET_START(COMMIT);
      t->commit();
      PRINT_NET_END(COMMIT);
    }
    catch(NQ_CommitFailed_Exception &e) {
      std::cerr << "Route creation failed, trying again\n";
      retry_transaction = 1;
    } catch(NQ_Access_Exception &e) {
      std::cerr << "NQ_Flow_create() access control exception " << e << "\n";
      t->abort();
      throw;
    } catch(NQ_Exception &e) {
      std::cerr << "NQ_Flow_create() exception: " << e << "\n";
      t->abort();
      throw;
    } catch(...) {
      // rethrow all others
      std::cerr << "unknown exception\n";
      t->abort();
      throw;
    }
    pthread_mutex_unlock(&flow_creation_lock);
  }
  return flow_tid;
}

int NQ_Flow_destroy(NQ_Tuple /* flow_tid */ flow_tid) throw(NQ_Exception) {
  Transaction t(trust_all, trust_attrval_all, g_flow_principal->home, g_flow_principal);
  T_Flow *flow;
  t.find_tuple(flow, flow_tid);
  if(flow == NULL) {
    cerr << "NQ_Flow_destroy(): Could not find flow\n";
    t.abort();
    return -1;
  }
  FlowContextMap::iterator i = flow_contexts.find(flow_tid);
  if(i != flow_contexts.end()) {
    i->second->clear_triggers(&t);
  } else {
    cerr << "Flow destroy: no flow context???\n";
  }
  flow->invalidate();
  // flow->tspace_delete();
  t.commit();
  return 0;
}

// synchronous upcall
namespace NQ_Flow_debug {
  bool detected_dep_change = false;
  bool dep_change_success = false;
}

bool update_path(Transaction *t, NQ_Tuple flow_tid) {
  bool rv;
  T_Flow *flow;
  t->find_tuple(flow, flow_tid);

  T_ProtocolEndpoint *dest_endpoint;
  T_ProtocolEndpoint *source = flow->source;
  T_Interface *ingress = flow->ingress;
  vector<T_Tuple *> path;
  T_Flow::RouteState route_state;
  if(source == NULL || ingress == NULL) {
    cerr << "Bad source, ingress, or dest! " << source << " " << ingress << " " << "\n";
    return false;
  }
  t->restore_logging();
  route_state = compute_path(*t, source, ingress, flow->dest_id,
			     // outputs
			     dest_endpoint, path, flow->include_interfaces);
  t->disable_logging();
  flow->route_state = route_state;
  if(route_state == T_Flow::VALID_ROUTE) {
    T_ProtocolEndpoint *orig_dest = flow->dest;
    if(orig_dest != NULL && dest_endpoint != orig_dest) {
      cerr << "Endpoint changed during routing???\n";
      // we could goto done and commit an incomplete route, but it is
      // possible that this was intended by network operator
    }
    set_flow_path(flow, path);
    flow->dest = dest_endpoint;
    rv = true;
  } else {
    flow->dest = NULL;
    rv = false;
  }
  set_flow_triggers(t, flow);
  return rv;
}

using namespace NQ_Flow_debug;

/*
  For performance and simplicity, only the first upcall of a given type, for
  a given transaction, and given set of triggers actually causes a state
  change. All others are redundant.

  During the verdict upcall, we invalidate the flow. We recompute the
  flow upon receiving the done upcall.
*/

static int NQ_Flow_update_upcall(NQ_Transaction transaction, NQ_Trigger_Description *trigger, NQ_Trigger_Upcall_Type type, int arg, void *userdata) {
  int rval = 1;
  // cerr << "Got flow update upcall, type = " << type << "!\n";
  if(error_on_upcall) {
    cerr << "Should not have gotten upcall!\n";
    assert(0);
  }
  FlowDependencyChange *change_ctx;
  change_ctx = reinterpret_cast<FlowDependencyChange *>(userdata);

  change_ctx->lock();
  pthread_mutex_lock(&flow_creation_lock); // before first goto_outrelease

  if(change_ctx->is_obsolete) {
    if(type == NQ_TRIGGER_UPCALL_SYNC_VERDICT) {
      cerr << "VERDICT??? ";
      // this should not happen if we delete obsolete triggers from tuplespace
      // assert(0);
    }
    // cerr << "obsolete\n";
    rval = 1;
    goto out_release;
  }

  switch(type) {
  case NQ_TRIGGER_UPCALL_SYNC_VETO: {
    cerr << "Veto sync???\n";
    rval = 1;
    goto out_release;
  }
  case NQ_TRIGGER_UPCALL_SYNC_VERDICT: {
    // Process only once per transaction
    if(change_ctx->new_transaction(transaction)) {
      // cerr << "Detected new dependency change\n";
      detected_dep_change = true;
      assert(arg); // make sure this is a commit

      cerr << "================================\n";
      cerr << "Flow touched at " << smallDoubleTime() << ", revalidating, caused by transaction " << transaction << ", ctx = " << change_ctx << "\n";
      flow_stats.num_touched_flows++;
      bool match = false;

      Transaction *t_write;
      T_Flow *flow_write;
      t_write = new Transaction(trust_all, trust_attrval_all, g_flow_principal->home, g_flow_principal);
      t_write->find_tuple(flow_write, change_ctx->flow_tid);
      if(flow_write == NULL) {
	cerr << "Flow no longer exists\n";
	goto done;
      }

      if(!match) {
	// cerr << "Clearing old route\n";
	// Clear the old (obsolete) route, in case we encounter an error
	// while computing the new path
	flow_write->invalidate();
	flow_stats.num_reroute++;
      } else {
	// this path is no longer supported
	assert(0);
	cerr << "Old route OK\n";
      }

      dep_change_success = true;
    done: ;
      if(t_write != NULL) {
	t_write->commit();
      }
    }

    rval = 1;
    goto out_release;
  }
  case NQ_TRIGGER_UPCALL_ASYNC_COMMIT_DONE: {
    if(!change_ctx->finish_transaction(transaction)) {
      // cerr << "Change ctx no longer active\n";
      rval = 1;
      goto out_release;
    }

    if(do_flow_maintenance) {
      if(change_ctx->num_active_transactions() == 0) {
        Transaction t(trust_all, trust_attrval_all, g_flow_principal->home, g_flow_principal);
        //cerr << "Active transaction count reached 0 ; Rerouting due to transaction " << transaction << "\n";

        // cerr << "Clearing all triggers\n";
        change_ctx->clear_triggers(&t);

        if(update_path(&t, change_ctx->flow_tid)) {
          // cerr << "\tReroute succeeded!\n";
          flow_stats.num_good_reroute++;
        } else {
          //cerr << "\tReroute failed!\n";
        }
        t.commit();
        change_ctx->is_obsolete = true;
      }
    } else {
      flow_stats.num_skipped_reroute++;
    }
    rval = 1;
    goto out_release;
  }
  default:
    cerr << "Unknown upcall type " << type << "\n";
    assert(0);
  }

 out_release:
  pthread_mutex_unlock(&flow_creation_lock);
  change_ctx->unlock();
  return rval;
}

bool POP_Map::LineParser::operator() (const std::string &line) {
  vector<string> tok_list;
  split(line, " ", tok_list);
  if(tok_list.size() < 3) {
    return true;
  }
  NQ_Host h;
  h.addr = resolve_ip(tok_list[1]);
  h.port = atoi(tok_list[2].c_str());

  // cerr << "Adding new host " << line << " => " << NQ_Host_as_string(h) << "\n";
  c.location_host_map[tok_list[0]] = h;
  return true;
}

POP_Map::POP_Map(const string &ifname) {
  LineParser l(*this);
  forlines(ifname, l);
}

const NQ_Host *POP_Map::find(const string &hostname) const {
  if(location_host_map.find(hostname) == location_host_map.end()) {
    return NULL;
  }
  return &location_host_map.find(hostname)->second;
}

void Router_TIDs::marshall(ostream &os) {
  os << "ROUTERTID{\n";
  file_marshall(tid, os);
  os << "}\n";
}

Router_TIDs *Router_TIDs::unmarshall(CharVector_Iterator &curr, const CharVector_Iterator &end) {
  string data = get_line(curr, end);
  if(string(data) != "ROUTERTID{") {
    return NULL;
  }

  Router_TIDs *r = new Router_TIDs();
  r->tid = *tspace_unmarshall(&r->tid, *(Transaction *)NULL, curr, end);
  data = get_line(curr, end);
  assert(string(data) == "}");
  return r;
}

void load_tids_from_emulator(const string &fname, EmulatorRouters *tids) {
  ifstream is(fname.c_str(), ifstream::binary);
  vector<unsigned char> all_data;
  get_all_file_data(is, all_data);
  CharVector_Iterator s = all_data.begin(), end = all_data.end();
  
  int count = read_int(s, all_data.end());
  cerr << "Total is " << count << "\n";
  for(int i=0; i < count; i++) {
    int router_id = read_int(s, all_data.end());
    Router_TIDs *r_tid = Router_TIDs::unmarshall(s, end);
    assert(r_tid->tid != NQ_uuid_null);

    (*tids)[router_id] = r_tid;
  }
}
