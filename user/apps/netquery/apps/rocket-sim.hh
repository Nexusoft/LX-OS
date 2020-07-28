#ifndef _ROCKET_SIM_HH_
#define _ROCKET_SIM_HH_

#include "sim-rpc.hh"

#include <ext/hash_map>
#include <ext/hash_set>


typedef RPC_Endpoint NQ_Sim_TSpaceClient;

struct TriggerData {
  virtual ~TriggerData() { }
  virtual TriggerData *make_serverside_copy() = 0;
};

struct NQ_Sim_TSpaceServer : RPC_Endpoint {
  // router_id,  =>
  struct TriggerKey {
    int router_id;  // router->router_id of the source
    uint32_t ip_address;

    TriggerKey(int _router_id, uint32_t addr) : 
      router_id(_router_id), ip_address(addr) {
    }
  private:
    TriggerKey(int _router_id) : 
      router_id(_router_id), ip_address(INVALID_ADDR) {
    }
  public:
    TriggerKey() { }
    // Build a L1 key
    static TriggerKey build_L1(int _router_id) {
      return TriggerKey(_router_id);
    }

    struct L2_Hash {
      size_t operator() (const TriggerKey &_k) const {
	TriggerKey k;
	memset(&k, 0, sizeof(k));
	k.router_id = _k.router_id;
	k.ip_address = _k.ip_address;
	return SuperFastHash((const char *)&k, sizeof(k));
      }
    };

    struct L2_Equals {
      bool operator() (const TriggerKey &l, const TriggerKey &r) const {
	return l.router_id == r.router_id && l.ip_address == r.ip_address;
      }
    };

    bool operator==(const TriggerKey &r) const {
      return L2_Equals()(*this,r);
    }

    struct L1_Hash {
      size_t operator() (const TriggerKey &_k) const {
	return SuperFastHash((const char *)&_k.router_id, sizeof(_k.router_id));
      }
    };
    struct L1_Equals {
      bool operator() (const TriggerKey &l, const TriggerKey &r) const {
	return l.router_id == r.router_id;
      }
    };
  } __attribute__ ((packed));

  struct TriggerClient{
    TriggerData *client_userdata;
    TriggerData *server_userdata_copy;
    typedef void (*Upcall)(TriggerKey key, TriggerData *userdata);
    Upcall fire_trigger;

    TriggerClient() : 
      client_userdata(NULL), 
      server_userdata_copy(NULL), 
      fire_trigger(NULL) { }
    TriggerClient(TriggerData *d, Upcall u) : 
      client_userdata(d), 
      server_userdata_copy(NULL), // the copy is made explicitly
      fire_trigger(u) { }

    struct Hash {
      size_t operator() (const TriggerClient &h) const {
	TriggerClient c;
	memset(&c, 0, sizeof(c));
	c.client_userdata = h.client_userdata;
	// do not hash on server_userdata_copy
	c.fire_trigger = h.fire_trigger;
	return SuperFastHash((const char *)&c, sizeof(c));
      }
    };
    bool operator==(const TriggerClient &r) const {
      return client_userdata == r.client_userdata && fire_trigger == r.fire_trigger;
    }
  };
  
  struct RouterInfo {
    Topology::InterPOPGraph *routing_graph;
    RouterInfo() : routing_graph(NULL) { }
    void switch_routing_graph(Topology::InterPOPGraph *new_graph) {
      Topology::InterPOPGraph::get(new_graph);
      if(routing_graph != NULL) {
	Topology::InterPOPGraph::put(routing_graph);
      }
      routing_graph = new_graph;
    }
  };


  // N.B.: Only second within Level3 has a valid server_userdata_copy
  typedef __gnu_cxx::hash_map<TriggerClient, TriggerClient, TriggerClient::Hash > 
    TriggerDB_Level3;
  // need an extra level to reduce the # of times we match an update against a trigger
  typedef __gnu_cxx::hash_map<TriggerKey, TriggerDB_Level3,
			      TriggerKey::L2_Hash, TriggerKey::L2_Equals>
    TriggerDB_Level2;
  typedef __gnu_cxx::hash_map<TriggerKey, TriggerDB_Level2,
			      TriggerKey::L1_Hash, TriggerKey::L1_Equals> TriggerDB;

  typedef __gnu_cxx::hash_map<int /* router_id */, RouterInfo > RouterInfoDB;

  TriggerDB trigger_db;
  RouterInfoDB router_db;

  struct Stats {
    int num_adds;
    int num_dels;
    Stats() : num_adds(0), num_dels(0) { }
  } stats;

  NQ_Sim_TSpaceServer(EventQueue *s, Topology *t, uint32_t ip_loc) : RPC_Endpoint(s, t, ip_loc) { }

  void reset_stats() {
    memset(&stats, 0, sizeof(stats));
  }

  typedef __gnu_cxx::hash_map<TriggerClient, 
		   __gnu_cxx::hash_set<TriggerKey, TriggerKey::L2_Hash,
				       TriggerKey::L2_Equals >,
			      TriggerClient::Hash
			      > TriggerWorklist;
  // return count of triggers that fired
  int check_triggers_helper(int source_router_id, const FIBUpdates &mods, TriggerWorklist *to_send) {
    TriggerDB::iterator l1 = 
      trigger_db.find(TriggerKey::build_L1(source_router_id));
    if(l1 == trigger_db.end()) {
      return 0;
    }
    int num_matches = 0;
    for(TriggerDB_Level2::iterator l2 = l1->second.begin();
	l2 != l1->second.end(); l2++) {
      assert(l1->first == l2->first);
      const TriggerKey &key = l2->first;

      // Ugh, this is slow. We should probably convert mods to a trie
      // or other index. Might also compile a giant w_char (for 8-bit
      // cleanliness) regex as a hack.
      for(FIBUpdates::const_iterator j = mods.begin(); j != mods.end(); j++) {
	const ForwardingEntry &fe = *j;
	if(fe.match(key.ip_address)) {
	  for(TriggerDB_Level3::iterator l3 = l2->second.begin();
	      l3 != l2->second.end(); l3++) {
	    (*to_send)[l3->second].insert(key);
	    num_matches++;
	  }
	}
      }
    }
    return num_matches;
  }

  void update_router_db(int source_router_id, Topology::InterPOPGraph *inter_graph) {
    router_db[source_router_id].switch_routing_graph(inter_graph);
  }

  void check_triggers(int source_router_id, FIBUpdates *adds, FIBUpdates *dels) {
    stats.num_adds += adds->size();
    stats.num_dels += dels->size();

    TriggerWorklist to_send;
    int num_matches;
    num_matches = 
      check_triggers_helper(source_router_id, *adds, &to_send) + 
      check_triggers_helper(source_router_id, *dels, &to_send);

    for(TriggerWorklist::iterator l3 = to_send.begin();
	l3 != to_send.end(); l3++) {
      // code doesn't yet handle triggers that are installed on multiple key changes.
      // just need to add iteration over the hash_map.
      assert(l3->second.size() == 1);

      l3->first.fire_trigger(*l3->second.begin(), l3->first.server_userdata_copy);
    }

    if(num_matches > 0) {
      cerr << "***** @" << ip_location << "+" << stats.num_adds << "; -" << stats.num_dels << "\n";
      cerr << "***** Update from " << source_router_id << " matched " << num_matches << "\n";
    }
  }

  struct FIB_Update : RPCContinuation {
    int source_router_id;
    Topology::InterPOPGraph *routing_graph;
    FIBUpdates *additions;
    FIBUpdates *deletions;

    FIB_Update(NQ_Sim_TSpaceServer *s,
	       int from_router_id, Topology::InterPOPGraph *r_graph, 
	       FIBUpdates *adds, FIBUpdates *dels) :
      RPCContinuation(s), 
      source_router_id(from_router_id), routing_graph(r_graph),
      additions(adds), deletions(dels) {
      // additions and deletions now belong to *this 
      Topology::InterPOPGraph::get(routing_graph);
    }
    string to_string() const {
      return "FIB_Update(src_router=" + itos(source_router_id) + ")";
    }
    size_t size() const {
      return compute_rpc_size((additions->size() + deletions->size()) * sizeof((*additions)[0]));
    }

    void fail(std::ostream &os, double curr_time) {
      os << "FIBCHANGE => FAIL from " << source_router_id;
      Topology::InterPOPGraph::put(routing_graph);
    }

    static void print_updates(const FIBUpdates &arr) {
      for(FIBUpdates::const_iterator i = arr.begin();
	  i != arr.end(); i++) {
	cerr << " " << i->ip_prefix;
      }
    }

    void operator() (std::ostream &os, const EventQueue::Entry_base &event_entry) {
      os << "FIBCHANGE(+" << additions->size() << ",-" << deletions->size() << ") from " << source_router_id;
      if(additions->size() > 0 && additions->size() < 2) {
	std::cerr << "+";
	print_updates(*additions);
	std::cerr << "\n";
      }
      if(deletions->size() > 0 && deletions->size() < 2) {
	std::cerr << "- ";
	print_updates(*deletions);
	std::cerr << "\n";
      }
      NQ_Sim_TSpaceServer *tspace_server = 
	dynamic_cast<NQ_Sim_TSpaceServer *>(server);
      tspace_server->update_router_db(source_router_id, routing_graph);
      tspace_server->check_triggers(source_router_id, additions, deletions);

      delete additions;
      delete deletions;
    }
  };

  //  Returns the next router
  struct FIB_Query : RPCContinuation {
    struct Response;
    struct ResponseContext {
      virtual ~ResponseContext() { }
      virtual void return_value (double curr_time, const struct Response &) = 0;
    };

    int router_id; // query runs against state reported by this router
    int dest_ip;
    ResponseContext *response_ctx;

    size_t size() const {
      return compute_rpc_size(sizeof(router_id) + sizeof(dest_ip));
    }

    string to_string() const {
      return "FIB_Query(router_id=" + itos(router_id) + 
	",dest_ip=" + itos(dest_ip) + ")";
    }

    struct Response : RPCContinuation { 
      int next_router_id;
      ResponseContext *response_ctx;

      Response(RPC_Endpoint *_endpoint, int _next_router_id, ResponseContext *ctx) :
	RPCContinuation(_endpoint), 
	next_router_id(_next_router_id),
	response_ctx(ctx)
      { }
      void operator() (std::ostream &os, const EventQueue::Entry_base &event_entry) {
	response_ctx->return_value(event_entry.curr_time, *this);
      }
      size_t size() const {
	return compute_rpc_size(sizeof(next_router_id) + sizeof(int));
      }

      string to_string() const {
	return "FIB_QueryResponse(next_router_id=" + itos(next_router_id) + ")";
      }

    };

    FIB_Query(NQ_Sim_TSpaceServer *server,
	     int _router_id, int _dest_ip, ResponseContext *ctx) : 
      RPCContinuation(server),
      router_id(_router_id), dest_ip(_dest_ip),
      response_ctx(ctx)
      { }

    void operator() (std::ostream &os, const EventQueue::Entry_base &event_entry) {
      NQ_Sim_TSpaceServer *tspace_server = 
	dynamic_cast<NQ_Sim_TSpaceServer *>(server);
      RouterInfoDB::iterator it = tspace_server->router_db.find(router_id);
      assert(it != tspace_server->router_db.end());

      Topology::Graph::vertex_descriptor vertex;
      Link l;
      it->second.routing_graph->
	get_next_hop(ROUTERID_TO_VERTEX(tspace_server->topo, router_id),
		     dest_ip, &vertex, &l);
      tspace_server->issue_rpc( Response(client, VERTEX_TO_ROUTERID(tspace_server->topo, vertex), response_ctx) );
    }
  };

  struct TriggerOp : RPCContinuation {
    enum Op {
      REGISTER,
      UNREGISTER
    };
    struct TriggerKey key;
    Op op;
    struct TriggerClient *client;

    TriggerOp(NQ_Sim_TSpaceServer *s, Op o, TriggerKey k, TriggerClient *c) :
      RPCContinuation(s),
      key(k), op(o), client(c) { }

    void operator() (double curr_time) {
      cerr << "Trigger ops not implemented!\n";
      exit(-1);
    }
  };

  void add_trigger(TriggerKey key, TriggerClient client) {
    TriggerDB_Level3::value_type v(client, client);
    TriggerDB_Level3::iterator it;
    bool inserted;
    boost::tie(it, inserted) = trigger_db[key][key].insert(v);
    assert(inserted);
    it->second.server_userdata_copy = it->second.client_userdata->make_serverside_copy();
  }
  void delete_trigger(TriggerKey key, TriggerClient client) {
    TriggerDB_Level3::iterator it = trigger_db[key][key].find(client);
    if( it != trigger_db[key][key].end() ) {
      delete it->second.server_userdata_copy;
      trigger_db[key][key].erase(client);
    }
  }
};

#endif // _ROCKET_SIM_HH_
