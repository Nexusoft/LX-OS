//
//included in rocket-router.cc
//

Topology::POPInfoMap::iterator as_id_to_pop(Topology *topo, int as_index){
  assert(0); // ashieh: i don't think this is safe across hashtable insertions/resizes
  Topology::POPInfoMap::iterator pop_i;
  for(pop_i = topo->pop_info_map.begin(); pop_i != topo->pop_info_map.end(); pop_i++, --as_index) {
    if(as_index == 0) break;
  }
  return pop_i;
}

uint32_t get_netquery_server_for_router(Topology *topo, unsigned long router, NQ_Sim_TSpaceServer **tspace_server){
  *tspace_server = 
    topo->pop_info_map[topo->graph[router].router->location].nq_sim_server;
  return topo->pop_info_map[topo->graph[router].router->location].nq_server_host;
}

uint32_t get_netquery_server_for_router(Topology *topo, unsigned long router){
  NQ_Sim_TSpaceServer *ignored;
  return get_netquery_server_for_router(topo, router, &ignored);
}

bool check_backroute(Topology *topo, FullGraph *graph, unsigned long router, unsigned long server){
  FullGraph::DFSGraph T;
  vector<float> distance;
  vector<FullGraph::vertex_descriptor> pred;
  graph->shortest_paths_tree(router, T, distance, pred, false);
  return !isnan(distance[server]);
}

bool check_intra_pop_routing_2(Topology *topo, Topology::InterPOPGraph *pop_graph, FullGraph *graph, Topology::POPInfo *popinfo, SimRouter *server_r, Topology::IntraPOPGraph *ig, unsigned long source){
  double latency;
  unsigned long count = popinfo->routers.size();
  unsigned long i, errors = 0, router_v, server_v = server_r->vertex;
  uint32_t server = VERTEX_TO_IP(topo, server_r->vertex), router;
  PING();
  bool a, b;

  for(i = 0; i < count; i++){
  PING();
    router_v = popinfo->routers[i]->vertex;
    router = VERTEX_TO_IP(topo, router_v);
  PING();
    a = pop_graph->get_shortest_path_len(server_v, router, &latency);
    b = pop_graph->get_shortest_path_len(router_v, server, &latency);
    if(!(a&&b)){
      cerr << "(" << a << ", " << b << ")";
      errors ++;
    }
  }
  int frac_unroutable = 4;
  if(errors) {
    cerr << errors << "/" << count << " errors, threshold at "<<100/frac_unroutable<<"%(" << count/frac_unroutable << ")\n";
  }
  if(errors > count/frac_unroutable){
  PING();
    cerr << "bad!\n";
    return false;
  }
  PING();
  return true;
}

bool check_intra_pop_routing(Topology *topo, Topology::InterPOPGraph *pop_graph, FullGraph *graph, Topology::POPInfo *popinfo, SimRouter *server_r, Topology::IntraPOPGraph *ig, unsigned long source){
  unsigned long count = popinfo->routers.size();
  unsigned long i, errors = 0, router, server = server_r->vertex;
  
  PING();
  //grab the intra pop graph
  
  for(i = 0; i < count; i++){
  PING();
    router = popinfo->routers[i]->vertex;
  PING();
    if(!((*(*ig)[pop_graph->full_to_intra[server].vertex].fw_table)[pop_graph->full_to_intra[router].vertex].is_valid() && 
         (*(*ig)[pop_graph->full_to_intra[router].vertex].fw_table)[pop_graph->full_to_intra[server].vertex].is_valid())){
      errors++;
    }
  PING();
  }
  PING();
  int frac = 6;
  //if(errors) {
    //cerr << errors << "/" << count << " errors, threshold at "<<100/frac<<"%(" << count/frac << ")\n";
  //}
  if(errors > count/frac){
  PING();
    return false;
  }
  PING();
  return true;
}

void pick_NQ_host(Topology *topo, Topology::InterPOPGraph *pop_graph, FullGraph *graph, Topology::POPInfo *popinfo, std::string popname, EventQueue *sim_ctx, unsigned long source){
  unsigned long count = popinfo->routers.size();
  unsigned long host = (unsigned long)(drand48() * count);
  unsigned long attempts = 0;
  
  PING();
  Topology::IntraPOPGraph *ig = pop_graph->full_to_intra[popinfo->routers[host]->vertex].graph;
  while(!check_intra_pop_routing_2(topo, pop_graph, graph, popinfo, popinfo->routers[host], ig, source)){
  PING();
    host++;
    host%=count;
    attempts++;
    if(attempts >= count){
      cerr << "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n";
      cerr << "Warning: POP " << popname << " is incapable of hosting a NetQuery server\n";
      cerr << "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n";
      popinfo->nq_server_host = 0;
      // ASHIEH: This is now fatal, since we do preprocessing to prevent this
      exit(-1);
      return;
    }
    ig = pop_graph->full_to_intra[popinfo->routers[host]->vertex].graph;
  }
  cerr << popname << " is using router: " << popinfo->routers[host]->vertex << " at " << VERTEX_TO_IP(topo, popinfo->routers[host]->vertex) << endl;
  popinfo->nq_server_host = VERTEX_TO_IP(topo, popinfo->routers[host]->vertex);

  NQ_Sim_TSpaceServer *nq_sim_server = 
    new NQ_Sim_TSpaceServer(sim_ctx, topo, ROUTERID_TO_IP(popinfo->routers[host]->router_id));
  for(vector<SimRouter*>::iterator 
        j = popinfo->routers.begin();
      j != popinfo->routers.end(); j++) {
    (*j)->set_nq_sim_server(nq_sim_server);
    (*j)->init_nq_sim_client(sim_ctx);
  }
  popinfo->nq_sim_server = nq_sim_server;
}

void pick_NQ_hosts(Topology *topo, Topology::InterPOPGraph *pop_graph, FullGraph *graph, EventQueue *sim_ctx, unsigned long source){
  Topology::POPInfoMap::iterator pop_i;
  
  for(pop_i = topo->pop_info_map.begin(); pop_i != topo->pop_info_map.end(); pop_i++) {
  PING();
    pick_NQ_host(topo, pop_graph, graph, &pop_i->second, pop_i->first, sim_ctx, source);
  }
}

struct Routing_Sim_State {
  Topology *topo;
  struct ExecStack {
    typedef vector <RPC_Endpoint *> Stack;
    Stack stack;
    void push(RPC_Endpoint *e) {
      stack.push_back(e);
    }

    RPC_Endpoint *top() {
      assert(stack.size() >= 1);
      return stack.back();
    }
    RPC_Endpoint *pop() {
      assert(stack.size() >= 1);
      RPC_Endpoint *back = stack.back();
      stack.pop_back();
      return back;
    }

    template<class T>
    void issue_rpc(T RPC) {
      top()->issue_rpc(RPC);
    }
  };
  ExecStack exec;
};

struct NQFlowSimulation;

void trigger_fire(ostream &os, void *sim, int id);
struct NQTriggerInfo;
void trigger_start(NQ_Sim_TSpaceServer::TriggerKey key, TriggerData *info);
struct NQTriggerInfo : TriggerData {
  EventQueue *sim_ctx;
  Topology *topo;
  uint32_t target_ip;
  NQFlowSimulation *simulation;
  int id;
  SimRouter *router;
  uint32_t flow_destination;
  unsigned long observed;
  
  NQTriggerInfo(EventQueue *_sim_ctx, Topology *_topo, uint32_t _target_ip, NQFlowSimulation *_simulation, int _id, SimRouter *_router, uint32_t _flow_destination, unsigned long _observed) :
    sim_ctx(_sim_ctx), topo(_topo), target_ip(_target_ip), simulation(_simulation), 
    id(_id), router(_router), flow_destination(_flow_destination), observed(_observed) { }
  
  virtual TriggerData *make_serverside_copy() {
    NQTriggerInfo *info = new NQTriggerInfo(*this);
    return info;
  }

  void reg_trigger(void){
    NQ_Sim_TSpaceServer::TriggerKey key = NQ_Sim_TSpaceServer::TriggerKey(topo->graph[observed].router->router_id, flow_destination);
    NQ_Sim_TSpaceServer::TriggerClient client(this, trigger_start);
    router->nq_sim_server->add_trigger(key, client);
  }
  
  void print_vertex(void){
    cerr << observed;
  }
};

struct NQTriggerPacket {
  EventQueue *sim_ctx;
  Topology *topo;
  SimRouter *router;
  uint32_t target_ip;
  NQFlowSimulation *simulation;
  int id;
  
  NQTriggerPacket(NQTriggerInfo *info) :
    sim_ctx(info->sim_ctx), topo(info->topo), router(NULL), target_ip(info->target_ip), simulation(info->simulation), id(info->id) { }

  NQTriggerPacket(EventQueue *s, Topology *t, uint32_t t_ip, NQFlowSimulation *sim, int _id) :
    sim_ctx(s), topo(t), router(NULL), target_ip(t_ip), simulation(sim), id(_id) { }

  void set_router(SimRouter *r) {
    router = r;
  }
  void fail(ostream &os, float sim_time) { }
  void operator() (ostream &os, const EventQueue::Entry_base &event_entry) {
    //cerr << "NQ(" << router->router_id << "@" << sim_time << ")";
    if(router->is_local_ip(target_ip)) {
      trigger_fire(os, simulation, id);
    } else {
      topo->reliable_send_event(sim_ctx, router->vertex, target_ip, NQTriggerPacket(sim_ctx, topo, target_ip, simulation, id));
    }
  }
};

void trigger_start(NQ_Sim_TSpaceServer::TriggerKey key, TriggerData *tmp){
  NQTriggerInfo *info = (NQTriggerInfo *)tmp;
  info->topo->reliable_send_event(info->sim_ctx, IP_TO_VERTEX(info->topo, get_netquery_server_for_router(info->topo, IP_TO_VERTEX(info->topo, ROUTERID_TO_IP(key.router_id)))),
    info->target_ip,
    NQTriggerPacket(info)
  );
}

struct NQFlowSimulation {
  string flow_id;
  unsigned long s, t;
  NQ_Sim_TSpaceClient client;
  NQ_Sim_TSpaceServer *source_nq_server;

  typedef vector<SimRouter *> Path;
  struct PathIterationContext {
    const Path &path;
    Path::const_iterator path_loc;

    PathIterationContext(const Path &p) : path(p) {
      restart();
    }

    void restart() {
      path_loc = path.begin();
    }
    uint32_t current_hop() {
      assert(!at_end());
      return ROUTERID_TO_IP( (*path_loc)->router_id );
    }
    bool at_end() {
      return path_loc == path.end();
    }
    void advance() {
      assert(!at_end());
      path_loc++;
    }
  };
  Path path;
  PathIterationContext path_ctx;
  // xxx unsigned long current_hop;

  EventQueue *sim_ctx;
  Routing_Sim_State sim_state;
  SimRouter *curr_router;
  int request_responsecount;
  bool success;
  int trigger_iteration;

  NQFlowSimulation (string id, unsigned long _s, unsigned long _t, Routing_Sim_State _sim_state, EventQueue *_sim_ctx) :
    flow_id(id),
    s(_s), t(_t), 
    client(_sim_ctx, _sim_state.topo, VERTEX_TO_IP(_sim_state.topo, _s)),
    source_nq_server(NULL),
    path_ctx(path),
    sim_ctx(_sim_ctx), 
    sim_state(_sim_state),
    curr_router(NULL), 
    request_responsecount(0), 
    success(false), 
    trigger_iteration(0),
    create_flow_ctx(*this)
  { 
    cerr << "Creating a flow from " << s << " to " << t << "\n";
    get_netquery_server_for_router(sim_state.topo, s, &source_nq_server);
    assert(source_nq_server != NULL);
    sim_state.exec.push(&client);
  }

  struct CreateFlowContext : NQ_Sim_TSpaceServer::FIB_Query::ResponseContext {
    NQFlowSimulation &container;
    CreateFlowContext(NQFlowSimulation &_container) : 
      container(_container) { }
    virtual ~CreateFlowContext() { }
    virtual void return_value (double curr_time, const NQ_Sim_TSpaceServer::FIB_Query::Response &response) {
      container.build_path_resume(response.next_router_id);
    }
  };
  
  struct CreateFlow : RPCContinuation {
    /* source and destination */
    NQFlowSimulation *flow_sim;
    CreateFlow(NQ_Sim_TSpaceServer *nq_server, NQFlowSimulation *_flow_sim) :
      RPCContinuation(nq_server), flow_sim(_flow_sim)
    { }
    void operator() (std::ostream &os, const EventQueue::Entry_base &event_entry) {
      // os << "CreateFlow(id=" << flow_sim->flow_id << "), issued at " << event_entry.issue_time << " ";
      flow_sim->sim_state.exec.push(server);
      flow_sim->build_path_resume(VERTEX_TO_ROUTERID(flow_sim->sim_state.topo, flow_sim->s));
    }
    size_t size() const {
      // source & dest
      return compute_rpc_size( 2 * sizeof(uint32_t) );
    }

    string to_string() const {
      return "CreateFlow(flow=" + flow_sim->id_to_string() + ",s=" + 
	itos(VERTEX_TO_IP(flow_sim->sim_state.topo, flow_sim->s)) + 
	",t=" + itos(VERTEX_TO_IP(flow_sim->sim_state.topo, flow_sim->t)) +")" ;
    }
  };
  struct CreateFlowReturn : RPCContinuation {
    /* discovered path */
    NQFlowSimulation *flow_sim;
    CreateFlowReturn(NQ_Sim_TSpaceClient *client, NQFlowSimulation *_flow_sim) :
      RPCContinuation(client), flow_sim(_flow_sim) { }
    void operator() (std::ostream &os, const EventQueue::Entry_base &event_entry) {
      os << "CreateFlowReturn() ";
      RPC_Endpoint *e = flow_sim->sim_state.exec.pop();
      assert(e == client);
      flow_sim->create_flow_finish(os);
    }
    size_t size() const {
      // path length
      return compute_rpc_size( sizeof(uint32_t) * flow_sim->path.size() );
    }
    string to_string() const {
      return "CreateFlowReturn(flow=" + flow_sim->id_to_string() + ",path=" + flow_sim->path_to_string() + ")";
    }
  };

  struct RecursiveQuery : RPCContinuation {
    NQFlowSimulation *flow_sim;
    int next_router_id;
    RecursiveQuery(NQ_Sim_TSpaceServer *server, NQFlowSimulation *_flow_sim, int _next_router_id) :
      RPCContinuation(server), flow_sim(_flow_sim), next_router_id(_next_router_id) { }
    
    void operator() (std::ostream &os, const EventQueue::Entry_base &event_entry) {
      os << "RecursiveQuery(Flow " << flow_sim->flow_id << ")@" << server->ip_location << " ";
      flow_sim->sim_state.exec.push(server);
      flow_sim->build_path_resume_next(dynamic_cast<NQ_Sim_TSpaceServer *>(server), next_router_id);
    }
    size_t size() const {
      // path length
      return compute_rpc_size( sizeof(uint32_t) * flow_sim->path.size() );
    }
    string to_string() const {
      return "RecursiveQuery(flow=" + flow_sim->id_to_string() + 
	",next_router_id=" + itos(next_router_id) + 
	",path=" + flow_sim->path_to_string() + ")";
    }
  };

  struct RecursiveQueryDone : RPCContinuation {
    NQFlowSimulation *flow_sim;
    RecursiveQueryDone(NQ_Sim_TSpaceClient *client, NQFlowSimulation *_flow_sim) :
      RPCContinuation(client), flow_sim(_flow_sim) { }
    
    void operator() (std::ostream &os, const EventQueue::Entry_base &event_entry) {
      assert(server == flow_sim->source_nq_server);
      // pop until we have orig client and NQ server
      while(flow_sim->sim_state.exec.stack.size() > 2) {
	flow_sim->sim_state.exec.pop();
      }
      assert(flow_sim->sim_state.exec.top() == flow_sim->source_nq_server);
      flow_sim->build_path_resume_finish();
    }
    size_t size() const {
      // path length
      return compute_rpc_size( sizeof(uint32_t) * flow_sim->path.size() );
    }
    string to_string() const {
      return "RecursiveQueryDone(flow=" + flow_sim->id_to_string() + ",path=" + flow_sim->path_to_string() + ")";
    }
  };

  // XXX move Transaction RPCs to rocket-sim.hh?
  struct TransactionRPCReturn : RPCContinuation {
    string type_name;
    NQFlowSimulation *flow_sim;
    TransactionRPCReturn(RPC_Endpoint *client,
		   const string &_type_name,
		   NQFlowSimulation *_flow_sim) :
      RPCContinuation(client), type_name(_type_name), flow_sim(_flow_sim) { }
    void operator() (std::ostream &os, const EventQueue::Entry_base &event_entry) {
      flow_sim->transaction_test_returned(os, event_entry);
    }
    size_t size() const {
      // bool?
      return compute_rpc_size( sizeof(uint32_t) );
    }
    string to_string() const {
      return type_name + "Return(flow=" + flow_sim->id_to_string() + ")";
    }
  };

  struct TransactionRPC : RPCContinuation {
    // This executes on the NQ server
    string type_name;
    NQFlowSimulation *flow_sim;
    RPC_Endpoint *reply_to;
    TransactionRPC(NQ_Sim_TSpaceServer *server,
		   const string &_type_name,
		   RPC_Endpoint *_reply_to,
		   NQFlowSimulation *_flow_sim) :
      RPCContinuation(server), type_name(_type_name), flow_sim(_flow_sim), reply_to(_reply_to) {
    }

    void operator() (std::ostream &os, const EventQueue::Entry_base &event_entry) {
      cerr << "Transaction rpc " << type_name << "\n";
      if(reply_to == NULL) {
	reply_to = client;
      }
      server->issue_rpc(TransactionRPCReturn(reply_to, type_name, flow_sim));
    }
    size_t size() const {
      return compute_rpc_size( sizeof(uint32_t) );
    }
    string to_string() const {
      return type_name + "(flow=" + flow_sim->id_to_string() + ")";
    }
  };

  struct CommitTriggerRPCReturn : RPCContinuation {
    NQFlowSimulation *flow_sim;

    CommitTriggerRPCReturn(RPC_Endpoint *client,
			   NQFlowSimulation *_flow_sim) :
      RPCContinuation(client), flow_sim(_flow_sim) { }
    void operator() (std::ostream &os, const EventQueue::Entry_base &event_entry) {
      flow_sim->commit_returned(os, event_entry);
    }
    size_t size() const {
      // bool?
      return compute_rpc_size( sizeof(uint32_t) );
    }
    string to_string() const {
      return "CommitTriggerRPCReturn(flow=" + flow_sim->id_to_string() + ")";
    }
  };
  struct CommitTriggerRPC : RPCContinuation {
    // This executes on the NQ server
    NQFlowSimulation *flow_sim;
    vector<NQTriggerInfo*> triggers;
    CommitTriggerRPC(NQ_Sim_TSpaceServer *server,
		     NQFlowSimulation *_flow_sim, 
		     const vector<NQTriggerInfo*> &_triggers) :
      RPCContinuation(server), flow_sim(_flow_sim), triggers(_triggers) {
    }

    void operator() (std::ostream &os, const EventQueue::Entry_base &event_entry) {
      cerr << "Commit RPC\n";
      for(size_t i = 0; i < triggers.size(); i++) {
        NQTriggerInfo *trigger = triggers[i];
        cerr << "Installing triggers at " << server->ip_location << "(";
        trigger->print_vertex();
        cerr << ")\n";
        trigger->reg_trigger();
      }
      server->issue_rpc(CommitTriggerRPCReturn(client, flow_sim));
    }
    size_t size() const {
      // ???
      return compute_rpc_size( sizeof(uint32_t) );
    }
    string to_string() const {
      return "CommitTriggerRPC(flow=" + flow_sim->id_to_string() + ")";
    }
  };

  struct PathRPCGenerator {
    virtual ~PathRPCGenerator() { }

    typedef vector<void *> DataGroup;
    virtual void *gen_for_target(SimRouter *r) = 0;
    virtual void issue_group(NQ_Sim_TSpaceServer *server, RPC_Endpoint *reply_to, const DataGroup &group)= 0;
  };

  struct TransactionRPCGenerator : PathRPCGenerator {
    NQFlowSimulation *flow_sim;
    string type_name;
    TransactionRPCGenerator(NQFlowSimulation *_flow_sim, string _type_name) : 
      flow_sim(_flow_sim), type_name(_type_name) { }
    virtual ~TransactionRPCGenerator() { }
    virtual void *gen_for_target(SimRouter *r) {
      // do nothing
      return NULL;
    }
    virtual void issue_group(NQ_Sim_TSpaceServer *server, RPC_Endpoint *reply_to, const DataGroup &group) {
      // XXX eventually, need to write in the check or commit targets
      flow_sim->sim_state.exec.issue_rpc(TransactionRPC(server, type_name, reply_to, flow_sim));
    }
  };
  struct TransactionTestRPCGenerator : TransactionRPCGenerator {
    TransactionTestRPCGenerator(NQFlowSimulation *_flow_sim) :
      TransactionRPCGenerator(_flow_sim, "TransactionTest" ) { }
  };

  struct CommitTriggerRPCGenerator : PathRPCGenerator {
    NQFlowSimulation *flow_sim;
    CommitTriggerRPCGenerator(NQFlowSimulation *_flow_sim) : 
      flow_sim(_flow_sim) { }
    virtual void *gen_for_target(SimRouter *router) {
      // Update response count in the groups
      uint32_t target_ip = ROUTERID_TO_IP(router->router_id);
      NQTriggerInfo *info = 
	new NQTriggerInfo(flow_sim->sim_ctx, 
			  flow_sim->sim_state.topo, 
			  VERTEX_TO_IP(flow_sim->sim_state.topo, flow_sim->s), 
			  flow_sim, 
			  flow_sim->trigger_iteration, 
			  router, 
			  VERTEX_TO_IP(flow_sim->sim_state.topo, flow_sim->t),
			  IP_TO_VERTEX(flow_sim->sim_state.topo, target_ip));
      return info;
    }
    virtual void issue_group(NQ_Sim_TSpaceServer *server, RPC_Endpoint *reply_to, const DataGroup &group) {
      vector<NQTriggerInfo*> triggers;
      for(size_t i=0; i < group.size(); i++) {
	triggers.push_back( (NQTriggerInfo *) group[i] );
      }
      flow_sim->sim_state.exec.issue_rpc(CommitTriggerRPC(server, flow_sim, triggers));
    }
  };

  CreateFlowContext create_flow_ctx;
  void create_flow() {
    // Executes on client
    assert(sim_state.exec.top() == &client);

    path.clear();
    request_responsecount = 0;
    success = false;

    sim_state.exec.issue_rpc(CreateFlow(source_nq_server, this));
  }
  void create_flow_finish(ostream &os) {
    double shortest = -1;
    sim_state.topo->latest_converged->get_shortest_path_len(s,VERTEX_TO_IP(sim_state.topo, t),&shortest);
    os << " /* Flow " << flow_id << " created (latest converged latency=" << shortest << ") */ ";
    success = true;
  }

  void build_path_resume(int next_router_id) {
    // Executes on NQ server

    path.push_back(sim_state.topo->router_map[next_router_id]);
    if(next_router_id == VERTEX_TO_ROUTERID(sim_state.topo, t)) {
      // done
      cerr << "Done building path\n";

      if(g_do_recursive) {
	switch(g_flow_opt_level) {
	case 0:
	  sim_state.exec.issue_rpc(RecursiveQueryDone(source_nq_server, this));
	  break;
	case 1:
	  build_path_resume_finish();
	  break;
	default:
	  cerr << "Unknown flow opt level!\n";
	  exit(-1);
	}
      } else {
	build_path_resume_finish();
      }
    } else {
      NQ_Sim_TSpaceServer *nq_sim_server;
      get_netquery_server_for_router(sim_state.topo, ROUTERID_TO_VERTEX(sim_state.topo, next_router_id), &nq_sim_server);

      if(g_do_recursive) {
	sim_state.exec.issue_rpc(RecursiveQuery(nq_sim_server, this, next_router_id));
      } else {
	assert(sim_state.exec.top() == source_nq_server);
	build_path_resume_next(nq_sim_server, next_router_id);
      }
    }
  }

  // Common code to both recursive and iterative versions
  void build_path_resume_finish(void) {
    TransactionTestRPCGenerator gen(this);
    send_path_rpcs(&gen);
  }
  void build_path_resume_next(NQ_Sim_TSpaceServer *nq_sim_server, int next_router_id) {
    sim_state.exec.issue_rpc(NQ_Sim_TSpaceServer::FIB_Query(nq_sim_server, next_router_id, ROUTERID_TO_IP(sim_state.topo->graph[t].router->router_id), &create_flow_ctx));
  }
  
  void transaction_test_returned(std::ostream &os, const EventQueue::Entry_base &event_entry) {
    request_responsecount--;
    cerr << "Client " << path_ctx.current_hop() << " received a response for the transaction test (" << request_responsecount << " left)\n";

    os << " /* transaction verify response # " << request_responsecount << " */ ";
    assert(request_responsecount >= 0);
    if(request_responsecount == 0) {
      if(g_do_recursive && g_flow_opt_level == 1) {
	os << "RecursiveQueryImplicitDone(Flow " << flow_id << ")";
	while(sim_state.exec.stack.size() > 2) {
	  sim_state.exec.pop();
	}
	assert(sim_state.exec.top() == source_nq_server);
      }
      cerr << "Finished, proceeding to final commit\n";
      CommitTriggerRPCGenerator gen(this);
      send_path_rpcs(&gen);
    }
  }

  void commit_returned(std::ostream &os, const EventQueue::Entry_base &event_entry) {
    request_responsecount--;
    cerr << "Client " << path_ctx.current_hop() << " received a response for the transaction commit (" << request_responsecount << " left)\n";
    os << flow_id << " /* commit response # " << request_responsecount << " */ ";

    if(request_responsecount == 0) {
      cerr << "iteration: "<< trigger_iteration << "; " << sim_ctx->sim_time << " seconds elapsed\n";
      assert(sim_state.exec.stack.size() == 2 &&
	     sim_state.exec.top() == source_nq_server);
      sim_state.exec.issue_rpc(CreateFlowReturn(&client, this));
    }
  }

  void trigger_fire(ostream &os, int id){
    cerr << "Trigger fire (pre id check) " << id << " " << trigger_iteration << "\n";
    if(id < trigger_iteration){ 
      return; 
    }
    cerr << "Trigger fired!  Restarting the flow creation process for " << flow_id << "\n";
    os << "Trigger fire @ " << flow_id;
    trigger_iteration++;
    create_flow();
  }

  struct GroupMapEntry {
    NQ_Sim_TSpaceServer *nq_server;
    PathRPCGenerator::DataGroup data;
  };
  
  void send_path_rpcs(PathRPCGenerator *gen){
    request_responsecount = 0;
    path_ctx.restart();
    PathIterationContext p(path_ctx);

    // Accumulate triggers by netquery server. Hashmap contains the
    // head of the trigger list
    typedef __gnu_cxx::hash_map < uint32_t, GroupMapEntry > GroupMap;
    GroupMap groups;

    RPC_Endpoint *reply_to = NULL;
    if(g_do_recursive && g_flow_opt_level == 1) {
      reply_to = source_nq_server;
    }

    while( !p.at_end() ) {
      uint32_t target_ip = p.current_hop();
      SimRouter *router = sim_state.topo->find_router(IP_TO_ROUTERID(target_ip));

      uint32_t nq_server_ip = router->nq_sim_server->ip_location;
      groups[nq_server_ip].nq_server = router->nq_sim_server;
      groups[nq_server_ip].data.push_back(gen->gen_for_target(router));
      p.advance();
    }
    // one response per POP
    cerr << "sending to path: ";

    for(GroupMap::iterator it = groups.begin(); it != groups.end(); it++) {
      gen->issue_group(it->second.nq_server, reply_to, it->second.data);
      request_responsecount++;
    }
    cerr << "\n";
  }

  string id_to_string() const {
    return "Flow " + flow_id;
  }
  string path_to_string() const {
    string rv = "[";
    PathIterationContext p(path);
    while( !p.at_end() ) {
      uint32_t target_ip = p.current_hop();
      rv += itos(target_ip) + " ";
      p.advance();
    }
    rv += " ]";
    return rv;
  }
};

void trigger_fire(ostream &os, void *sim, int id){
  NQFlowSimulation *_sim = (NQFlowSimulation *)sim;
  _sim->trigger_fire(os, id);
}

struct SimulatedLinkFailure {
  EventQueue *sim_ctx;
  Topology *topo;
  Topology::Graph::vertex_descriptor s, t;
  
  SimulatedLinkFailure(Topology *_topo, EventQueue *_sim_ctx, Topology::Graph::vertex_descriptor _s, Topology::Graph::vertex_descriptor _t) : 
    sim_ctx(_sim_ctx), topo(_topo), s(_s), t(_t) { }
  
  void fail(ostream &os, float sim_time) { }
  void operator() (ostream &os, const EventQueue::Entry_base &event_entry) {
    cerr << "Removing edge (" << s << "," << t << ");\n";
    sim_remove_edge(sim_ctx, topo, s, t);
  }
};

bool pick_hosts_along_path(Routing_Sim_State *sim_state, unsigned long s, unsigned long t, unsigned long *a, unsigned long *b){
  std::vector<unsigned long> path;
  Link l;
  unsigned long current_hop = s;
  unsigned long chosen_hop;
  cerr << "Path: ";
  for(current_hop = s; current_hop != t;){
    path.push_back(current_hop);
    cerr << "[" << current_hop << 
      "(" << VERTEX_TO_ROUTERID(sim_state->topo, current_hop) << ")" "] ";
    unsigned int _current_hop;
    if( !sim_state->topo->latest_converged->get_next_hop(current_hop, ROUTERID_TO_IP(sim_state->topo->graph[t].router->router_id), &_current_hop, &l) ){
      cerr << "Error!  No path to destination.\n";
      return false;
    }
    current_hop = _current_hop;
  }
  path.push_back(t);
  cerr << "[" << t << "]\n";

  while(1) {
    chosen_hop = (long unsigned int) (drand48() * (path.size() - 1));
    assert(0 <= chosen_hop < path.size() - 1);
    *a = path[chosen_hop];
    *b = path[chosen_hop + 1];

    cerr << ">>>>>> Edge classifier: \n";
    cerr << "A = " << sim_state->topo->graph[*a].router->location << " ; " <<
      "B = " << sim_state->topo->graph[*b].router->location << "\n";

    if(sim_state->topo->graph[*a].router->location == sim_state->topo->graph[*b].router->location) {
      break;
    }
  }
  return true;
}

typedef vector<NQFlowSimulation*> FlowVector;
EventQueue *setup_test(Topology *topo, string popmap_fname);
void test_individual_creation(Topology *topo, EventQueue *sim_ctx);
void run_flow_creation(Topology *topo, EventQueue *sim_ctx, int num_creations);
void spawn_flow_creation(Topology *topo, EventQueue *sim_ctx, int num_creations, FlowVector *flows);

void sim_flow_creation_timing(Topology *topo, string popmap_fname){
  int count = g_test_count;
  cerr << "Flow creation routing test; starting " << count << " \n";
  EventQueue *sim_ctx = setup_test(topo, popmap_fname);
  run_flow_creation(topo, sim_ctx, count);
  delete sim_ctx;
}

EventQueue *setup_test(Topology *topo, string popmap_fname) {
  using namespace boost;

  POP_Map pop_name_map(popmap_fname);
  topo->decompose_into_pops();
  topo->set_pop_name_map(&pop_name_map);

  EventQueue *sim_ctx = new EventQueue("sim.log");

  vector<Topology::Graph::vertex_descriptor> nodes;
  Topology::Graph::vertex_iterator vi, end;
  for(tie(vi, end) = vertices(topo->graph); vi != end; ++vi) {
    nodes.push_back(*vi);
  }
  Topology::InterPOPGraph *inter_graph = topo->reroute_all();

  FullGraph full_graph;
  topo->extract_full_graph(full_graph);
  
  pick_NQ_hosts(topo, inter_graph, &full_graph, sim_ctx, 0);
 
  topo->propagate_linkstate_change(sim_ctx, inter_graph, nodes);
  topo->switch_routing_graph(inter_graph);
  Topology::InterPOPGraph::put(inter_graph);
  sim_ctx->run_all();
  
  cerr << "Picking random server pairs\n";

  sim_ctx->reset();
  return sim_ctx;
}

void test_individual_creation(Topology *topo, EventQueue *sim_ctx) {
  cerr << "Picking random server pairs\n";

  FullGraph full_graph;
  topo->extract_full_graph(full_graph);
  size_t N; N = num_vertices(full_graph);

  cerr << "\n\n===== Starting Test ======\n";
  for(int x = 0; x < 1; x++){
    unsigned long s, t, a, b;

    s = (unsigned long)(drand48() * N);
    t = (unsigned long)(drand48() * N);

    cerr << "Creating flow (";
    cerr << topo->graph[s].router->location << " to " << 
      topo->graph[t].router->location << ")\n";
    
    Routing_Sim_State state = { topo };
    NQFlowSimulation sim("single" + itos(x), s, t, state, sim_ctx);
    
    sim.create_flow();
    
    sim_ctx->run_all();
    if(pick_hosts_along_path(&state, s, t, &a, &b)) {
      sim_ctx->schedule_from_now(1000, SimulatedLinkFailure(topo, sim_ctx, a, b));
    } else {
      cerr << "No link removed\n";
    }
    sim_ctx->run_all();

    if(sim.success) {
      cerr << "\n\n===== Success ======\n";
    } else {
      cerr << "\n\n===== ERROR ======\n";
    }
    sim_ctx->reset();
  }
}

void run_flow_creation(Topology *topo, EventQueue *sim_ctx, int num_creations) {
  FlowVector all_flows;
  spawn_flow_creation(topo, sim_ctx, num_creations, &all_flows);

  sim_ctx->run_all();

  int success_count = 0;
  for(size_t i=0; i < all_flows.size(); i++) {
    NQFlowSimulation *sim = all_flows[i];
    cerr << "[" << i << "]: ";
    if(sim->success) {
      cerr << " ===== Success ======\n";
      success_count++;
    } else {
      cerr << " ===== ERROR ======\n";
    }
  }
  cerr << "Success: " << success_count << "/" << all_flows.size() << "\n";
}

void spawn_flow_creation(Topology *topo, EventQueue *sim_ctx, int num_creations, FlowVector *flows) {
  bool is_first = true;

  FullGraph full_graph;
  topo->extract_full_graph(full_graph);
  size_t N; N = num_vertices(full_graph);

  for(int x = 0; x < num_creations; x++){
    cerr << "\n\nIteration " << x << " \n";
    unsigned long s, t, a, b;
    s = (unsigned long)(drand48() * N);
    t = (unsigned long)(drand48() * N);
    cerr << "Creating flow (";
    cerr << topo->graph[s].router->location << " to " << 
      topo->graph[t].router->location << ")\n";
    
    Routing_Sim_State state = { topo };
    flows->push_back(new NQFlowSimulation(itos(x), s, t, state, sim_ctx));
    
    flows->back()->create_flow();
    
    if(g_do_deletion && is_first) {
      if(pick_hosts_along_path(&state, s, t, &a, &b)) {
	cerr << "Simulated link failure (" << a << "," << b << ")\n";
	sim_ctx->schedule_from_now(10000, SimulatedLinkFailure(topo, sim_ctx, a, b));
	is_first = false;
      }
    }
  }
}
