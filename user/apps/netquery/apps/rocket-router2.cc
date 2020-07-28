#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <set>
#include <algorithm>
#include <inttypes.h>
#include <fstream>
#include <math.h>
#include <signal.h>
#include <unistd.h>
#include <ext/hash_map>

#include <boost/graph/graph_traits.hpp>
#include <boost/graph/adjacency_list.hpp>
#include <boost/graph/dijkstra_shortest_paths.hpp>
#include <boost/graph/depth_first_search.hpp>

#include <nq/boost_util.hh>

#include <boost/iostreams/device/mapped_file.hpp>
#include <boost/regex.hpp>

#include <nq/net_elements.hh>
#include <nq/net.h>
#include <sys/time.h>
#include <unistd.h>

#include "router.hh"

#include "eventqueue.hh"
#include "fib-update-protocol.hh"

//#define PING() cerr << "===========> " << __FILE__ << ":" << __LINE__ << "      " << __FUNCTION__ << "()\n"
#define PING()

using std::map;
using std::set;
using std::cout;
using std::cerr;
using std::string;
using std::vector;
using std::endl;
using std::ofstream;
using std::ifstream;
using std::ostream;

using __gnu_cxx::hash_map;

NQ_Principal *g_flow_principal;

int g_server_port = 3359;

int g_test_count = 1000;
int g_seed = 100;
bool g_do_recursive = false;
bool g_do_deletion = false;
int g_flow_opt_level = 0;

bool do_real_tspace_update = true;
bool do_thread_slice = false;
bool do_valgrind = false;

bool generate_subgraph = false;
bool selective_export = true;
bool single_nq_server = true;

int thread_num_slices = 0;
int thread_slice_id = 0;

int num_unroutable_count = 0;

int fib_additions_count;
int fib_deletions_count;

enum CommitMode {
  ONE_PER_ROUTER,
  ONE_PER_POP,
  EXT_FIB_UPDATE,
} commit_mode = EXT_FIB_UPDATE; // ONE_PER_ROUTER;
//ONE_PER_POP;

// string _prefix("(\\d+) @(\\S+)(?: (\\+))?(?: (bb))?\\s+\\((\\d+)\\)(?: &(\\d+))?");
string _prefix("(\\d+)\\s+@(\\S+)(?:\\s+(\\+))?(?:\\s+(bb))?\\s+\\((\\d+)\\)(?: &(\\d+))?");
string _internal("<(\\d+)>");
string _external("\\{(-\\d+)\\}");

static string _line("^.+?$");
static const boost::regex line_pattern(_line);

const boost::regex rocket_prefix(_prefix);
const boost::regex rocket_internal(_internal);
const boost::regex rocket_external(_external);

string fib_update_proto_sock("/tmp/update.sock");

static int new_count = 0;
void* operator new(size_t n, int ignored) {
  new_count += n;
  return malloc(n);
}

double double_fromTime(const timeval &tv) {
  return tv.tv_sec + tv.tv_usec / 1000000.0;
}

void print_timestamp(const char *str) {
  cerr.flush();
  fprintf(stderr, "%lf: %s\n", doubleTime(), str);
  fflush(stderr);
}

bool almost_equal(double l, double r) {
  return fabs(l - r) < 0.00001;
}

void TIMESTAMP(void) {
  static timeval tv_first;
  static bool is_first = true;
  timeval tv;
  gettimeofday(&tv, NULL);
  if(is_first) {
    tv_first = tv;
    is_first = false;
  }
  cout << "@" << double_fromTime(tv) - double_fromTime(tv_first) << "\n";
}

string timestamp(void) {
  static timeval tv_first;
  static bool is_first = true;
  timeval tv;
  gettimeofday(&tv, NULL);
  if(is_first) {
    tv_first = tv;
    is_first = false;
  }
  return "@" + to_string(double_fromTime(tv) - double_fromTime(tv_first));
}

struct RocketPrefix {
  bool valid;
  int router_id;
  string location;
  bool dns_derived_location;
  bool is_backbone;
  vector<int> internal_neighbors;
  vector<int> external_neighbors;

  RocketPrefix(const string &str) {
    boost::smatch matches;
    bool m;
    if(! ( m = boost::regex_search(str, matches, rocket_prefix, boost::match_continuous ) ) ||
       matches.size() != 7) {
      // cout << "did not match, " << m << " match size is " << matches.size() << "\n";
      valid = false;
      return;
    }

    if(0) {
      size_t i;
      for(i=0 ; i < matches.size() ; i++) {
	cout << "[" << i << "] " << matches[i] << "\n";
      }
    }

    // xxx may need to adjust things up
    valid = true;
    router_id = atoi(matches[1].str().c_str());
    location = matches[2].str();
    dns_derived_location = matches[3].str() == "+";
    is_backbone = matches[4].str() == "bb";
    unsigned int internal_count = atoi(matches[5].str().c_str());
    unsigned int external_count = atoi(matches[6].str().c_str());

    boost::sregex_iterator ints(str.begin(), str.end(), rocket_internal);
    boost::sregex_iterator exts(str.begin(), str.end(), rocket_external);
    boost::sregex_iterator end;
    for( ; ints != end; ints++) {
      int neighbor = atoi((*ints)[1].str().c_str());
      internal_neighbors.push_back(neighbor);
    }

    for( ; exts != end; exts++) {
      int neighbor = atoi((*exts)[1].str().c_str());
      external_neighbors.push_back(neighbor);
    }
    if(false){
      if(internal_neighbors.size() != internal_count || 
         external_neighbors.size() != external_count) {
        cerr << "Input: " << str << "\n";
        cerr << "Size error: " << internal_neighbors.size() << ", " << internal_count <<
          " " << external_neighbors.size() << ", " << external_count << "\n";
      }
      assert(internal_neighbors.size() == internal_count);
      assert(external_neighbors.size() == external_count);
    }
  }
};

// Patterns for reading from latency file
string _loc("([^\\s\\d]+)(\\d+)");
const boost::regex latency_pattern(_loc + "\\s+" + _loc + "\\s+(\\d+)");

const float MIN_LATENCY = 1.0;
//const float MIN_LATENCY = 0.001;
const float LOCAL_LATENCY = MIN_LATENCY;

struct DistanceDB {
  // Table of pairwise distances
  // We abuse the type system by creating hash keys by string concatenation

  static string canonical_name(const string &s) {
      boost::regex regex("\\+");
      return boost::regex_replace(s, regex, "");
  }

  struct LocationPairKey {
    string first;
    string second;
    
    LocationPairKey(const string &l, const string &r) {
#if 0
      vector<string> s; s.push_back(canonical_name(l)); s.push_back(canonical_name(r));
      std::sort(s.begin(), s.end());
      first = s[0];
      second = s[1];
#else
      if(l.compare(r) <= 0) {
        first = l;
        second = r;
      } else {
        first = r;
        second = l;
      }
#endif
    }
    struct Hash {
      bool operator() (const LocationPairKey &k) const {
	string joined = k.first + "-" + k.second;
	// cerr << "Hash(" << joined << ")\n";
	return SuperFastHash(joined.c_str(), strlen(joined.c_str()));
      }
    };
    bool operator== (const LocationPairKey &r) const {
      return first == r.first && second == r.second;
    }
  };
  typedef hash_map<LocationPairKey, float, LocationPairKey::Hash> DistanceMap;
  DistanceMap map;

  typedef std::pair<float,bool> FloatRV;
  FloatRV find(const string &l, const string &r) const {
#if 1
    if(l == r) {
      return FloatRV(1.0, true);
    } else {
      return FloatRV(10.0, true);
    }
#else
    if(map.find(LocationPairKey(l,r)) == map.end()) {
      return FloatRV(0, false);
    } else {
      return FloatRV(map.find(LocationPairKey(l,r))->second, true);
    }
#endif
  }

  void add_distance(const string &l0, const string &l1, float distance) {
#if 1
    return;
#else
    map[LocationPairKey(l0, l1)] = max(distance, MIN_LATENCY);
    map[LocationPairKey(l0, l0)] = map[LocationPairKey(l1, l1)] = LOCAL_LATENCY;
#endif
  }

  // Action for latency computations from RocketFuel
  struct RocketFuelProcessor {
    DistanceDB &c;
    inline RocketFuelProcessor(DistanceDB &container) : c(container) { }
    bool operator() (std::string line) {
      boost::smatch matches;
      if(boost::regex_search(line, matches, latency_pattern, boost::match_continuous) && 
	 matches.size() == 6) {
	// cerr << "line match " << line << ":\n";
	float distance = atof(matches[5].str().c_str());
	c.add_distance(matches[1].str(), matches[3].str(), distance);
	// cerr << "ADD " << make_key(matches[1].str(), matches[3].str()) << "=> " << distance << "\n";
      }
      return true;
    }
  };

  // Computations from fixups
  struct FixFileProcessor {
    DistanceDB &c;
    inline FixFileProcessor(DistanceDB &container) : c(container) { }
    bool operator() (std::string line) {
      vector<string> tokens;
      vector<string> loc;
      string loc_str;
      float distance;

      split(line, " ", tokens);
      if(tokens.size() < 2) {
	cerr << "bad number of space sep toks\n";
	return true;
      }
      loc_str = tokens[0].c_str();
      split(loc_str, "-", loc);

      if(loc.size() != 2) {
	cerr << "could not split location\n";
	return true;
      }
      distance = atof(tokens[tokens.size()-1].c_str());
      c.add_distance(loc[0], loc[1], distance);
      // cerr << "added " << make_key(loc[0], loc[1]) << "=> " << distance << "\n";
      return true;
    }
  };

  DistanceDB(const string &loc_file, const string &fix_file) : map(1000) {
    RocketFuelProcessor a(*this);
    forlines(loc_file, a);

    FixFileProcessor b(*this);
    forlines(fix_file, b);
  }

  void print_all() {
    int count = 0;
    for(DistanceMap::iterator i = map.begin(); i != map.end(); ++i) {
      cerr << i->first.first << "-" << i->first.second << ": " << i->second << "\n";
      count++;
    }
    cerr << "Count is " << count << "\n";
  }
};

int num_routers_in_input;
int num_pruned_routers;

struct TestSpec {
  struct Processor {
    TestSpec &c;
    inline Processor(TestSpec &container) : c(container) { }
    hash_map<const string, bool> repeat_check;
    bool operator() (std::string line) {
      // <GlomName> <RouterIDs>+\n
      vector<string> tokens;
      string loc_str;

      split(line, " ", tokens);
      if(tokens.size() < 2) {
	cerr << "bad number of space sep toks\n";
	return true;
      }
      GlomSpec *glom = new GlomSpec(tokens[0]);
      cerr << "new glom " << glom->name << "\n";
      assert(repeat_check.find(string("xxx") /*glom->name*/) == repeat_check.end());
      repeat_check[glom->name] = true;
      for(size_t i=1 ; i < tokens.size(); i++) {
        int router_id = atoi(tokens[i].c_str());
        glom->routers.push_back(router_id);
        cerr << "added " << i << "\n";
        assert(!c.is_router_in_test(router_id));
        c.glom_index[router_id] = glom;
      }
      c.gloms.push_back(glom);
      return true;
    }
  };

  struct GlomSpec {
    GlomSpec(const string &n) : name(n) { }
    string name;
    vector<int> routers;
  };
  vector< GlomSpec *> gloms;
  typedef hash_map<int, GlomSpec *> GlomIndex;
  GlomIndex glom_index;

  TestSpec(const string &fname) {
    Processor a(*this);
    forlines(fname, a);
  }
  bool patch_prefix(RocketPrefix *prefix) {
    if(!generate_subgraph) {
      return true;
    }
    if(!is_router_in_test(prefix->router_id)) {
      // cerr << "router " << prefix->router_id << " not in glom spec\n";
      num_pruned_routers++;
      return false;
    }
    prefix->location = glom_index[prefix->router_id]->name;
    for(size_t i=0; i < prefix->external_neighbors.size(); i++) {
      assert(prefix->external_neighbors[i] <= 0);
    }
    vector<int> new_internal;
    new_internal.reserve(prefix->internal_neighbors.size());
    for(size_t i=0; i < prefix->internal_neighbors.size(); i++) {
      int neigh = prefix->internal_neighbors[i];
      if(!is_router_in_test(neigh)) {
        // cerr << "neighbor move to external " << neigh << "\n";
        prefix->external_neighbors.push_back(neigh);
      } else {
        new_internal.push_back(neigh);
      }
    }
    prefix->internal_neighbors = new_internal;
    return true;
  }
  bool is_router_in_test(int router_id) {
    return !(glom_index.find(router_id) == glom_index.end());
  }

  int num_routers_in_test(void) {
    return glom_index.size();
  }
};

TestSpec *test_spec = NULL;

bool filter_on_export(int router_id) {
  return selective_export && test_spec != NULL && !test_spec->is_router_in_test(router_id);
}

struct NameDB {
  typedef hash_map<int, string*> NameMap;
  NameMap map;

  string find(int router_id) const {
    if(map.find(router_id) == map.end()) {
      return "";
    } else {
      return *map.find(router_id)->second;
    }
  }

  struct NameProcessor {
    NameDB &c;
    inline NameProcessor(NameDB &container) : c(container) { }
    bool operator() (std::string line) {
      vector<string> tokens;
      split(line, " ", tokens);
      if(tokens.size() < 2) {
	cerr << "could not tokenize " << line << "\n";
	return true;
      }
      c.map[atoi(tokens[0].c_str())] = new string(tokens[1]);
      return true;
    }
  };

  NameDB(const string &name_file) {
    NameProcessor a(*this);
    forlines(name_file, a);
  }

  void print_all() {
    int count = 0;
    for(NameMap::iterator i = map.begin(); i != map.end(); ++i) {
      cerr << i->first << ": " << *i->second << "\n";
      count++;
    }
    cerr << "Count is " << count << "\n";
  }
};

std::ostream &operator<<(std::ostream &os, struct RocketPrefix &prefix) {
  os << "as num = " << prefix.router_id << 
    " location = " << prefix.location << 
    " dns_derived = " << prefix.dns_derived_location << 
    " is_backbone = " << prefix.is_backbone;
  os << " internal count = " << prefix.internal_neighbors.size() << " external count = " << prefix.external_neighbors.size() << "\n";
  return os;
}

struct compare_int {
  bool operator() (int x, int y) {
    return x < y;
  }
};
struct compare_uint {
  bool operator() (uint32_t x, uint32_t y) {
    return x < y;
  }
};

// Organize data by router schema, rather than plain graph

struct SimRouter;
struct Link;
struct Interface;

const int FAKE_DESCRIPTOR = 0xdeadbeef;
const uint32_t INVALID_ADDRESS = 0xdeadbeef;

struct SimRouterWrapper {
  SimRouter *router;
  bool saw_broadcast;
  SimRouterWrapper() : router(NULL) { }
  SimRouterWrapper(SimRouter *r) : router(r) { }
};

struct SimHost {
  ExtRef<T_CompositeElement> host;
  
  SimHost(Host *h) : host(h->composite_element->get_tid()) {
#if 0
    stack = h->tcp_endpoint->get_tid();
    ingress = h->nic->external_connection.load()->get_tid();
    id = h->tcp_endpoint->id;
#endif
  }

};

#define INTERFACE_NUMBITS 9
//#define INTERFACE_NUMBITS 11
struct FloydWarshall_Entry {
  enum {
    INVALID_WEIGHT = 0xff,
    INVALID_EGRESS = (1 << INTERFACE_NUMBITS) - 1,
  };
  uint8_t weight; // from float latency (7 bits is not enough)
  uint16_t egress:INTERFACE_NUMBITS; // egress interface
  // inline FloydWarshall_Entry(uint8_t l, uint8_t e) : weight(l), egress(e), has_external(false) { }
  inline FloydWarshall_Entry(void) : weight(INVALID_WEIGHT), egress(INVALID_EGRESS) { }
  inline bool is_valid(void) const {
    assert( (weight == INVALID_WEIGHT && egress == INVALID_EGRESS) ||
	    (weight != INVALID_WEIGHT && egress != INVALID_EGRESS) );
    return weight != INVALID_WEIGHT;
  }
} __attribute__((packed));

struct FloydWarshallNodeData {
  string name;
  vector<FloydWarshall_Entry> *fw_table;
  inline FloydWarshallNodeData() : fw_table(NULL) { }
  inline void fw_init(size_t size) {
    if(fw_table == NULL) {
      fw_table = new vector<FloydWarshall_Entry>(size);
    } else {
      fw_table->clear();
      fw_table->reserve(size);
      for(size_t i=0; i < size; i++) {
	fw_table->push_back(FloydWarshall_Entry());
      }
    }
  }
};

ostream &operator<< (ostream &os, const FloydWarshall_Entry &e) {
  os << ((int)e.weight) << " , " << e.egress;
  return os;
}
void print_fwtable(const vector<FloydWarshall_Entry> *table) {
  for(size_t i = 0; i < table->size(); i++) {
    cerr << "[" << i << "] " << (*table)[i] <<"\n";
  }
}

struct FloydWarshallEdgeData {
  enum {
    INVALID_INDEX = -1,
  };
  float cost;
  int egress;
  inline FloydWarshallEdgeData() : cost(NAN), egress(INVALID_INDEX) { }
};


struct RouterNodeData : FloydWarshallNodeData {
  SimRouter *router;
  RouterNodeData() : router(NULL) { }
  RouterNodeData(SimRouter *r) : router(r) { }
  bool is_virtual() {
    return router == NULL;
  }
};

struct RouterEdgeData;

template <class NodeData, class EdgeData>
// directed so that we can encode virtual routers to represent the boundary between POPs
struct RoutingGraph : boost::adjacency_list 
< boost::vecS /* out edge list */, boost::vecS /* vertex list */, 
  boost::directedS, NodeData, EdgeData > {
  void all_pairs_shortest_paths_fw(void) {
    using namespace boost;
    // N.B.: Have not tested Dijk with top-level topo

    // cerr << "All Top\n"; TIMESTAMP();
    // Initialize all tables
    RoutingGraph &graph = *this;

    int N = num_vertices(graph);
    int num_edges = 0;
    typename graph_traits<RoutingGraph>::vertex_iterator vi, vi_end;
    for(tie(vi,vi_end) = vertices(graph); vi != vi_end; ++vi) {
      const typename graph_traits<RoutingGraph>::vertex_descriptor s = *vi;

      graph[s].fw_init(N);
      vector<FloydWarshall_Entry> &fw_table = *graph[s].fw_table;
      typename graph_traits<RoutingGraph>::out_edge_iterator ei, ei_end;
      assert(out_degree(s, graph) < FloydWarshall_Entry::INVALID_EGRESS);
      for( tie(ei,ei_end) = out_edges(s, graph);
	   ei != ei_end ; ++ei) {
	const typename graph_traits<RoutingGraph>::vertex_descriptor t = target(*ei, graph);

	double rounded_cost = round(graph[*ei].cost);
	assert((int)t < (int)N);
	if(!(0 < (int)rounded_cost && rounded_cost < FloydWarshall_Entry::INVALID_WEIGHT)) {
	  cerr << this << " " <<*ei << "Rounded cost is " << rounded_cost << " orig " << graph[*ei].cost << "!";
	}
	assert(0 <= (int)rounded_cost && rounded_cost < FloydWarshall_Entry::INVALID_WEIGHT);
	assert(fw_table[t].weight == FloydWarshall_Entry::INVALID_WEIGHT);
	int weight = fw_table[t].weight = (uint16_t) rounded_cost;
	fw_table[t].egress = graph[*ei].egress;

	num_edges++;
	if(0) {
	  // Spot check data
	  cerr << "E(" << graph[s].name << "=>" << graph[t].name << ")=" << 
	    weight;
	  graph[*ei].debug_output(cerr);
	}
	if(0) {
	  cerr << "(" << s << "," << t << "): " << fw_table[t] << "\n";
	}
      }
    }
    //cerr << "Num FW edges: " << num_edges << "\n"; TIMESTAMP();

    int k;
    for(k=0; k < N; k++) {
      // cerr << "<" << k << ">";
      typename graph_traits<RoutingGraph>::edge_iterator ei, ei_end;
      for(int _i=0; _i < N; _i++) {
	for(int _j=0; _j < N; _j++) {
	  typename graph_traits<RoutingGraph>::vertex_descriptor i = _i, j = _j;
	  vector<FloydWarshall_Entry> 
	    &a_fw_table = *graph[i].fw_table,
	    &b_fw_table = *graph[k].fw_table;
	  // cerr << "(" << i << "," << j << ")" << "{" << src_fw_table[k].is_valid() << " " << b_fw_table[j].is_valid() <<"}";
	  if( !(a_fw_table[k].is_valid() && b_fw_table[j].is_valid()) ) {
	    continue;
	  }
	  int curr_weight = a_fw_table[j].weight;
	  int proposed_weight = (int)a_fw_table[k].weight +
	    (int)b_fw_table[j].weight;
	  // cerr << "[" << a_fw_table[j].is_valid() << " " << (proposed_weight < curr_weight) <<"]";
	  if(!a_fw_table[j].is_valid() || proposed_weight < curr_weight) {
	    a_fw_table[j].weight = (uint16_t)proposed_weight;
	    a_fw_table[j].egress = a_fw_table[k].egress;

	    if(0) {
	      cerr << "Relaxed (" << i << "," << j << ") to use " << k <<
		" " << curr_weight << " => " << proposed_weight << 
		"(" << (int)a_fw_table[k].weight << " + " <<
		(int)b_fw_table[j].weight << ")\n";
	    }
	    assert(proposed_weight < FloydWarshall_Entry::INVALID_WEIGHT);
	  }
	}
      }
    }

    int missing_count = 0;
    for(int _i=0; _i < N; _i++) {
      for(int _j=0; _j < N; _j++) {
	typename graph_traits<RoutingGraph>::vertex_descriptor i = _i, j = _j;
	vector<FloydWarshall_Entry> &fw_table = *graph[i].fw_table;
	if(!fw_table[j].is_valid()) {
	  missing_count++;
	}
      }
    }
    if(missing_count > 0) {
      cerr << "===> Can't route to " << missing_count << "\n";
    }
  }

  typedef boost::adjacency_list < boost::vecS, boost::vecS, boost::directedS /*, no_property, no_property */ >
    DFSGraph;

  struct RouteTreeVisitor : boost::default_dfs_visitor {
    vector<FloydWarshall_Entry> &fw_table;
    int egress;
    RouteTreeVisitor(vector<FloydWarshall_Entry> &tab, int e) : 
      fw_table(tab), egress(e) {
    }
    void discover_vertex(DFSGraph::vertex_descriptor u, const DFSGraph &g) {
      assert(fw_table[u].egress == FloydWarshall_Entry::INVALID_EGRESS);
      assert(fw_table[u].weight != FloydWarshall_Entry::INVALID_WEIGHT);
      assert(0 <= egress && egress < FloydWarshall_Entry::INVALID_EGRESS);

      fw_table[u].egress = egress;
    }
  };
  
  void shortest_paths_tree(typename RoutingGraph::vertex_descriptor s,
			   DFSGraph &T, vector<float> &distance,
			   vector<typename RoutingGraph::vertex_descriptor> &pred) {
    shortest_paths_tree(s, T, distance, pred, false);
  }
  void shortest_paths_tree(typename RoutingGraph::vertex_descriptor s,
			   DFSGraph &T, vector<float> &distance,
			   vector<typename RoutingGraph::vertex_descriptor> &pred, bool debug) {
    using namespace boost;
    RoutingGraph &G = *this;
    size_t N = num_vertices(G);
    distance.clear();
    distance.resize(N, NAN);
    pred.clear();
    pred.resize(N);

    dijkstra_shortest_paths( G, s,
			     distance_map(&distance[0]).
			     weight_map(get(&EdgeData::cost, G)).
			     predecessor_map(&pred[0]) );
    T = DFSGraph(N);
    G[s].fw_init(N);
    vector<FloydWarshall_Entry> &fw_table = *G[s].fw_table;
    assert( pred.size() == distance.size() && pred.size() == fw_table.size() );
    for(size_t j=0; j < pred.size(); j++) {
      if(pred[j] != j) {
	add_edge(pred[j], j, T);
	double rounded = round(distance[j]);
	fw_table[j].weight = (int)rounded;

	assert(0 <= (int)rounded && (int)rounded < FloydWarshall_Entry::INVALID_WEIGHT);
      }
    }
  }
  void all_pairs_shortest_paths_dijk(void) {
    using namespace boost;
    RoutingGraph &G = *this;
    size_t N = num_vertices(G);
    // cout << "Dijkstra shortest\n";
    typename RoutingGraph::vertex_iterator vi, end;
    for(tie(vi,end) = vertices(G); vi != end; vi++) {
      DFSGraph T;
      vector<float> distance;
      vector<typename RoutingGraph::vertex_descriptor> pred;
      shortest_paths_tree(*vi, T, distance, pred);

      vector<FloydWarshall_Entry> &fw_table = *G[*vi].fw_table;
      DFSGraph::out_edge_iterator ej, end;
      for(tie(ej,end) = out_edges((DFSGraph::vertex_descriptor)*vi, T); 
	  ej != end; ++ej) {
	DFSGraph::vertex_descriptor t = target(*ej, T);
	// cerr << "Target is " << t << "\n";
	vector<default_color_type> color_vec(N);

	// XXX with a custom Dijkstra iterator that builds trees + egress information, we can avoid this lookup cost
	typename RoutingGraph::edge_descriptor rg_e;
	bool present;
	tie(rg_e,present) = edge(source(*ej, T), target(*ej, T), G);
	assert(present);
	depth_first_visit(T, t, RouteTreeVisitor(fw_table, G[rg_e].egress), &color_vec[0] );
      }
      
      // Sanity check
      for(size_t j=0; j < pred.size(); j++) {
	assert( (pred[j] == j && !fw_table[j].is_valid()) || 
		(pred[j] != j && fw_table[j].is_valid()) );
      }
    }
  }
};

struct NQ_Sim_TSpaceServer;
struct Topology {
  typedef boost::adjacency_list < boost::vecS /* out edge list */, boost::vecS /* vertex list */, boost::bidirectionalS, SimRouterWrapper,
						   Link 
  > Graph;
  typedef map< int, SimRouter *, compare_int > SimRouterMap;
  typedef vector< SimHost * > HostVector;

  struct IntraPOPGraph;
  struct POPInfo {
    vector<SimRouter *> routers;
    uint32_t nq_server_host; //pick_NQ_hosts() fills this in randomly.
    NQ_Sim_TSpaceServer *nq_sim_server_host;

    NQ_Principal *principal;
    NQ_Sim_TSpaceServer *nq_sim_server;
    POPInfo() : nq_server_host(0), nq_sim_server_host(NULL), principal(NULL), nq_sim_server(NULL) { }
  };
  typedef hash_map<const string, POPInfo> POPInfoMap;

  struct POPTransactionMap : hash_map<const string, Transaction *> {
    void commit_and_delete_all() {
      for(iterator i = begin(); i != end(); ++i) {
	i->second->commit();
	delete i->second;
      }
      clear();
    }
  };

  POPInfoMap pop_info_map;
  inline int num_pops(void) const {
    return pop_info_map.size();
  }

  struct POPNodeData : FloydWarshallNodeData {
    IntraPOPGraph *intra_graph;
    vector<unsigned long> interface_target;
    
    POPNodeData() : intra_graph(NULL) { }
    POPNodeData(const string &n) : intra_graph(NULL) { name = n; }
  };

  struct POPEdgeData : FloydWarshallEdgeData {
    vector<Link> *links;

    inline POPEdgeData() : links(NULL) { }
    inline void init(void) {
      assert(links == NULL);
      links = new vector<Link>();
    }
    void debug_output(ostream &os) {
      os << " orig count " << links->size() << "\n";
    }
  };

  struct IntraPOPVertexInfo;
  struct InterPOPGraph : RoutingGraph<POPNodeData, POPEdgeData> {
    const Topology &container;
    typedef hash_map<const string, InterPOPGraph::vertex_descriptor> POPVertexMap;
    POPVertexMap pop_to_vertex;

    // Conversion table from Topology.graph vertices to IntraPop vertices
    vector<IntraPOPVertexInfo> full_to_intra;

    void (*put_handler)(InterPOPGraph *g);
    int refcnt; // refcnt is for leak detection

    static void get(InterPOPGraph *graph) {
      assert(graph->refcnt > 0);
      graph->refcnt++;
      // cerr << "<" << graph->refcnt << ">";
    }
    static void put(InterPOPGraph *graph) {
      assert(graph->refcnt > 0);
      graph->refcnt--;
      // cerr << "(" << graph->refcnt << ")";
      if(graph->refcnt == 0) {
	cerr << "Deallocating InterPOPGraph\n";
	if(graph->put_handler != NULL) {
	  graph->put_handler(graph);
	}
	delete graph;
      }
    }

    InterPOPGraph(const Topology &topo) : container(topo), full_to_intra(num_vertices(topo.graph)), put_handler(NULL), refcnt(1) {
    }
    ~InterPOPGraph() {
      assert(refcnt == 0);
    }
    void build_vertices(void) {
      for(POPInfoMap::const_iterator i = container.pop_info_map.begin();
	  i != container.pop_info_map.end(); i++) {
	InterPOPGraph::vertex_descriptor v = 
	  pop_to_vertex[i->first] = add_vertex(POPNodeData(i->first), *this);
	(*this)[v].intra_graph = new IntraPOPGraph();
      }
    }

    InterPOPGraph::vertex_descriptor translate_vertex(Graph::vertex_descriptor v);
    InterPOPGraph::vertex_descriptor translate_vertex(const string &s) {
      return pop_to_vertex[s];
    }
    inline POPNodeData get_node(const string &s) {
      return (*this)[translate_vertex(s)];
    }
    inline unsigned long if_to_target(vertex_descriptor v, int egress_if) {
      assert(0 <= egress_if && egress_if < (int)(*this)[v].interface_target.size());
      return (*this)[v].interface_target[egress_if];
    }

    bool get_shortest_path_len(Graph::vertex_descriptor s, uint32_t dest_ip, double *rv);

    bool get_next_hop(Graph::vertex_descriptor s, uint32_t target_ip, 
		      Graph::vertex_descriptor *t, Link *l);
    void print_next_hop(Graph::vertex_descriptor s, uint32_t target_ip);
  };
  struct IntraPOPGraph : RoutingGraph<RouterNodeData, RouterEdgeData> {
    // Every neighboring POP is represented by a virtual_vertex. Every
    // local router with a link to that POP is represented with a link
    // from that router to the virtual_vertex in the intra pop graph.

    // Maps between a pop number (neighbors only) and the local
    // routers that can get to them
    struct Border {
      struct RouterDesc {
	Graph::edge_descriptor orig_edge;
	RouterDesc() { }
	RouterDesc(Graph::edge_descriptor e) : orig_edge(e) { }
      };

      IntraPOPGraph *container;
      hash_map< IntraPOPGraph::vertex_descriptor, RouterDesc> routers;
      IntraPOPGraph::vertex_descriptor virtual_vertex;

#define INVALID_VERTEX INT_MAX

      Border() : container(NULL), virtual_vertex(INVALID_VERTEX) { }
      bool needs_init() {
	return virtual_vertex == INVALID_VERTEX;
      }
      void init(IntraPOPGraph &c, InterPOPGraph::vertex_descriptor v) {
	assert(needs_init());
	container = &c;
	virtual_vertex = add_vertex(c);
	c[virtual_vertex].name = "BORDER(" + itos(v) + ")";
      }
    };
    typedef map // hash_map // hash_map happens to be really slow for this
    < InterPOPGraph::vertex_descriptor, Border > POPBorderMap;
    POPBorderMap border_map;

    void dump_shortest_path_tree(vertex_descriptor v);
    bool is_border_vertex(vertex_descriptor v) {
      return (*this)[v].router == NULL;
    }
  };
  struct IntraPOPVertexInfo {
    enum { INVALID = 0xffffffff };
    IntraPOPGraph::vertex_descriptor vertex;
    IntraPOPGraph *graph;
    IntraPOPVertexInfo() : vertex(INVALID), graph(NULL) { }
  };

  DistanceDB distances;
  const NameDB &replacement_names;

  const POP_Map *pop_name_map;

  Graph graph;
  SimRouterMap router_map;
  HostVector hosts;

  map< uint32_t, SimRouter *, compare_uint> address_map;

  bool is_decomposed;
  bool init_done;
  bool has_distance_errs;
  int good_distance_count;
  int bad_distance_count;
  Topology(const DistanceDB &db, const NameDB &nm) : 
    distances(db), 
    replacement_names(nm), pop_name_map(NULL),
    is_decomposed(false), init_done(false), has_distance_errs(false),
    good_distance_count(0), bad_distance_count(0),
    latest_converged(NULL)
  { }

  void add_router(const RocketPrefix &prefix);
  void add_router(int router_id, const string &loc);
  void connect(Interface *src, Interface *dst);

  SimRouter *find_router(int router_id);

  void finish_init(void);
  bool check_integrity(void);

  void set_pop_name_map(const POP_Map *pop_name_map) {
    this->pop_name_map = pop_name_map;
  }
  void init_tuplespace(const string &tid_ofname);

  void build_pop_transaction_map(POPTransactionMap &output_map) {
    output_map.clear();
    for(POPInfoMap::iterator pop = pop_info_map.begin(); 
	pop != pop_info_map.end(); pop++) {
      NQ_Host *host = const_cast<NQ_Host *>(pop_name_map->find(pop->first));
      if(host == NULL) {
	cerr << "Could not find " << pop->first << "\n";
	exit(-1);
      }
      NQ_Principal *p = NQ_get_home_principal(host);
      pop->second.principal = p;

      assert(p != &NQ_default_owner);
      output_map[pop->first] = new Transaction(trust_all, trust_attrval_all, p->home, p);
    }
  }
  void load_from_tuplespace(const string &tid_ofname, POPTransactionMap &output_map);
  InterPOPGraph *reroute_all(void);
  void decompose_into_pops(void);
  int split_disconnected_pops(void);
  InterPOPGraph *build_hierarchical_pop_topology(void);
  void tspace_update_fib(InterPOPGraph *pop_graph);

  void assign_address(SimRouter *r);

  Graph::edge_iterator pick_random_edge(void) {
    int n = (int)(drand48() * num_edges(graph));
    assert(n < (int)num_edges(graph));
      Graph::edge_iterator ei, end;
      tie(ei,end) = edges(graph);
      for(int i = 0; i < n; i++) {
	ei++;
      }
      return ei;
  }

  void pick_random_edge(Graph::vertex_descriptor *s, Graph::vertex_descriptor *t) {
    Graph::edge_iterator ei = pick_random_edge();
    *s = source(*ei, graph);
    *t = target(*ei, graph);
  }

  void biased_pick_random_edge(Graph::vertex_descriptor *s, Graph::vertex_descriptor *t);

  void remove_edge(Topology::Graph::vertex_descriptor s, Topology::Graph::vertex_descriptor t) {
    Topology::Graph::edge_descriptor e;
    bool found;
    tie(e, found) = edge(s, t, graph);
    assert(found);
    cerr << "Removing " << e << "\n";
    boost::remove_edge(e, graph);
  }
  Topology *copy_and_remove_edge(Topology::Graph::vertex_descriptor s, Topology::Graph::vertex_descriptor t) {
    assert(is_decomposed);
    Topology *copy = new Topology(*this);
    copy->remove_edge(s,t);
    return copy;
  }
  void propagate_linkstate_change(EventQueue *sim_ctx, 
				  InterPOPGraph *inter_graph, 
				  const vector<Graph::vertex_descriptor> &nodes);

  template <typename G>
  void extract_full_graph(G &full_graph);

  // F is a functor of form void F(float edge_cost, Router *target);

  // This one is for unreliable broadcast
  template <typename F> 
  void apply_broadcast_event(struct EventQueue *sim_ctx,
			     Graph::vertex_descriptor s, F func);
  // This one is for unreliable unicast (IP)
  template <typename F>
  void forward_packet_event(struct EventQueue *sim_ctx, 
			    // source + destination
			    Graph::vertex_descriptor s, uint32_t dest_ip,
			    F func);

  InterPOPGraph *latest_converged;
  void switch_routing_graph(InterPOPGraph *new_graph) {
    InterPOPGraph::get(new_graph);
    if(latest_converged != NULL) {
      // get before put, in case new_graph == routing_graph
      InterPOPGraph::put(latest_converged);
    }
    latest_converged = new_graph;
  }

  // This one is for TCP. It uses the latest converged routing tables
  template <typename F>
  void reliable_send_event(struct EventQueue *sim_ctx, 
			   // source + destination
			   Graph::vertex_descriptor s, uint32_t dest_ip,
			   F func);
};

struct Link {
  // Graph "Edge"
  Topology::Graph::edge_descriptor edge;

  Interface *source;
  Interface *dest;
  float cost;

  Link() : source(NULL), dest(NULL), cost(NAN) { }
  Link(Interface &src, Interface &dst, float c) :
    source(&src), dest(&dst), cost(c) {
  }
};

struct RouterEdgeData : FloydWarshallEdgeData {
  Link link;
  RouterEdgeData(const Link &l) : link(l) {
    cost = link.cost;
    egress = link.source->if_num;
  }
  void debug_output(ostream &os) { }
};

struct DataIntegrityError {
  DataIntegrityError(const string &msg) { }
};

int num_routers;
int num_edges;

#define INVALID_ADDR (0)
static inline uint32_t VERTEX_TO_IP(Topology *topo, Topology::Graph::vertex_descriptor v);
static inline int VERTEX_TO_ROUTERID(Topology *topo, Topology::Graph::vertex_descriptor v) {
  return IP_TO_ROUTERID(VERTEX_TO_IP(topo, v));
}

static inline Topology::Graph::vertex_descriptor IP_TO_VERTEX(Topology *topo, uint32_t ip);

static inline Topology::Graph::vertex_descriptor ROUTERID_TO_VERTEX(Topology *topo, int router_id) {
  return IP_TO_VERTEX(topo, ROUTERID_TO_IP(router_id));
}

void Topology::biased_pick_random_edge(Graph::vertex_descriptor *s, Graph::vertex_descriptor *t) {
  // Pick a random edge based on nodes in test_spec
  assert(test_spec != NULL);
  vector<Graph::out_edge_iterator> edges;
  for(TestSpec::GlomIndex::iterator  i = test_spec->glom_index.begin();
      i != test_spec->glom_index.end(); i++) {
    Graph::out_edge_iterator ei, ei_end;
    for(tie (ei, ei_end) = out_edges(ROUTERID_TO_VERTEX(this, i->first), graph); ei != ei_end; ++ei) {
      edges.push_back(ei);
    }
  }
  int n = (int)(drand48() * edges.size());
  *s = source(*(edges[n]), graph);
  *t = target(*(edges[n]), graph);
}

// N.B.: PackedForwardingEntry routes to a _router_, rather than an IP
// prefix.  This reduces the amount of state that we need to keep in
// the router emulator.  When written to the tuplespace, the routing
// information is expanded out into a full trie.
struct PackedForwardingEntry {
  uint16_t interface:INTERFACE_NUMBITS;
  int16_t router_id;

  PackedForwardingEntry() {
    router_id = 0;
    interface = (uint16_t)-1;
  }
  PackedForwardingEntry(uint16_t _interface, int16_t _router_id) :
    interface(_interface), router_id(_router_id)
  {
    assert(_interface < 0x1ff);
  }

  bool operator<(const PackedForwardingEntry &f) const {
    return router_id < f.router_id || 
      (router_id == f.router_id && interface < f.interface);
  }

  bool operator==(const PackedForwardingEntry &f) const {
    return router_id == f.router_id && 
      interface == f.interface;
  }
} __attribute__ ((packed));

struct PackedForwardingTable : vector<PackedForwardingEntry> {
  SimRouter *container;
  PackedForwardingTable(SimRouter &c);
  void expand(ForwardingTable &output);
  void print(void);
};

void PackedForwardingTable::print(void) {
  for(iterator i = begin(); i != end(); i++) {
    cerr << "router_id=" << i->router_id << " interface=" << i->interface << "\n";
  }
}

#include "rocket-sim.hh"

struct SimRouter {
  // N.B. SimRouter always represents the topology as loaded from the file
  // E.g., if links are removed during routing, the changes are not
  // propagated down to the SimRouter *

  typedef vector<Interface *> InterfaceTable;

  Topology *topology;
  Topology::Graph::vertex_descriptor vertex;

  int router_id;
  string location;

  InterfaceTable interfaces;
  // Forwarding table is only valid in dijkstra mode
  ForwardingTable forwarding_table;
  // Packed forwarding table
  PackedForwardingTable commited_packed_forwarding_table;

  Router *tspace_router;
  ExtRef<T_SwitchFabric> fabric;

  ForwardingTable commited_forwarding_table;
  int forwarding_table_version; // if forwarding_table_version == fabric.forwarding_table_version, then fabric contains commited_forwarding_table

  bool wrote_tspace;
  Topology::InterPOPGraph *routing_graph;
  NQ_Sim_TSpaceClient *nq_sim_client;
  NQ_Sim_TSpaceServer *nq_sim_server;

  void substitute_name(void) {
    string replacement_name = topology->replacement_names.find(router_id);
    if(replacement_name != "") {
      /*
	cerr << "Replaced name: " << router_id << "@" << location <<
	" => " << replacement_name << "\n";
      */
      location = replacement_name;
    }
  }

#define INIT()					\
    commited_packed_forwarding_table(*this),	\
    tspace_router(NULL),			\
    forwarding_table_version(0),		\
    wrote_tspace(false),			\
    routing_graph(NULL),			\
    nq_sim_client(NULL),			\
    nq_sim_server(NULL)

  SimRouter(Topology *topo, const RocketPrefix &prefix) : 
    topology(topo), 
    vertex(FAKE_DESCRIPTOR),
    router_id(prefix.router_id), 
    location(prefix.location), 
    INIT()
  {

    assert(prefix.valid);
    num_routers++;

    size_t i;
    for(i=0; i < prefix.internal_neighbors.size(); i++) {
      int target = prefix.internal_neighbors[i];
      if(target == router_id) {
        cerr << "self loop " << router_id << "\n";
        continue;
      }
      interfaces.push_back(new Interface(*this, interfaces.size(), target));
    }
    for(i=0; i < prefix.external_neighbors.size(); i++) {
      int target = prefix.external_neighbors[i];
      if(target == router_id) {
        cerr << "self loop " << router_id << "\n";
        continue;
      }
      interfaces.push_back(new Interface(*this, interfaces.size(), target));
    }

    substitute_name();
  }
  SimRouter(Topology *topo, int router_id, const string &loc) :
    topology(topo), 
    router_id(router_id), location(loc), 
    INIT()
  {
    substitute_name();
  }
  ~SimRouter() {
  }

  bool is_external() {
    return router_id < 0;
  }

#if 0
  bool is_outside_export() {
    return router_id < 0 ||
      (test_spec != NULL && (generate_subgraph || selective_export) && !test_spec->is_router_in_test(router_id));
  }
#endif

  void finish_init(void) throw (DataIntegrityError) {
    size_t i;
    topology->assign_address(this);
    for(i=0; i < interfaces.size(); i++) {
      int target_id = interfaces[i]->peer_router_id;
      assert(target_id != router_id);
      SimRouter *r = topology->find_router(target_id);
      bool is_external = false;
      if(r == NULL) {
        topology->add_router(target_id, "external");
        r = topology->find_router(target_id);
        assert( r->is_external() );
        // cerr << "New external router " << target_id << "\n";
        topology->assign_address(r);
        is_external = true;
      }
      if(!r->is_external()) {
	// Interfaces already created on peer ; find matching one interface
	size_t j;
	bool found = false;
	// int found_count = 0;
	for(j=0; j < r->interfaces.size(); j++) {
	  if(r->interfaces[j]->peer_router_id == router_id) {
            topology->connect(interfaces[i], r->interfaces[j]);
            found = true;
            break;
	  }
	}
	if(found == false) {
	  throw DataIntegrityError("Could not find peer interface to connect to\n");
	}
      } else {
	// External router ; need to add an interface
	Interface *interface = new Interface(*r, r->interfaces.size(), router_id);
	topology->connect(interfaces[i], interface);
	topology->connect(interface, interfaces[i]);
	r->interfaces.push_back(interface);
        // cerr << "external " << target_id <<  " adding interface " << interface << "\n";
      }
    }
  }

  bool check_data_integrity(void) const {
    size_t i;
    for(i=0; i < interfaces.size(); i++) {
      if(!(interfaces[i]->peer_interface->peer_interface == interfaces[i] &&
	   topology->find_router(interfaces[i]->peer_router_id) == 
	   &interfaces[i]->peer_interface->owner)) {
	   return false;
	 }
    }
    return true;
  }

  template <class InputTable, class Updates>
  static void table_difference(const InputTable &commited_table, 
			       const InputTable &updated_table, 
			       Updates *additions, Updates *deletions) {
    std::set_difference( commited_table.begin(),
			 commited_table.end(),
			 updated_table.begin(),
			 updated_table.end(),
			 std::back_insert_iterator< Updates >(*deletions));
    std::set_difference( updated_table.begin(),
			 updated_table.end(),
			 commited_table.begin(),
			 commited_table.end(),
			 std::back_insert_iterator< Updates >(*additions));
  }

  void tspace_write_fib(Transaction *t, 
                        ForwardingTable &commited_table, 
                        const ForwardingTable &updated_table) {
    T_SwitchFabric *t_fabric = NULL;
    if(t != NULL) {
      t_fabric = this->fabric.load(*t);
      if(t_fabric->forwarding_table_version != forwarding_table_version) {
        cerr << "version mismatch, must rewrite everything\n";
        commited_table.clear();
      }
      forwarding_table_version = max(forwarding_table_version + 1,
                                     t_fabric->forwarding_table_version + 1);
    } else {
      assert(commit_mode == EXT_FIB_UPDATE);
    }
    FIBUpdates additions, deletions;
    table_difference(commited_table, updated_table, &additions, &deletions);
    // Perform sanity check
#if 0
    if(true) {
      ForwardingTable table = commited_table;
      for(FIBUpdates::iterator i = deletions.begin(); 
	  i != deletions.end(); i++) {
	table.erase(i->first);
      }
      for(FIBUpdates::iterator i = additions.begin(); 
	  i != additions.end(); i++) {
	table[i->first] = true;
      }
      if(table != updated_table) {
	cerr << "error: additions and deletions do not generate the desired table!\n";
      }
      if(table.size() != updated_table.size()) {
	cerr << "error: table size mismatch!\n";
      }
      int count = 0;
      for(ForwardingTable::const_iterator i = table.begin(),
	    j = updated_table.begin();
	  i != table.end() && j != updated_table.end(); i++, j++) {
	if(*i != *j) {
	  cerr << "error: additions and deletions do not generate the desired table! "
	    "count = " << count <<  "\n";
	  break;
	}
	count++;
      }
    }
#endif

    // cerr << "Writing out delta (size is +" << additions.size() << " -" << deletions.size() << " ) \n";    
    
    // Until we get trie, or similar data structure, we can't do a real write-out
    if(false) {
      cerr << "XXX did not actually do partial out, doing complete instead\n";
      t_fabric->forwarding_table.truncate();
      for(ForwardingTable::const_iterator i = updated_table.begin(); 
          i != updated_table.end(); i++) {
        ::add_forwarding_entry(t_fabric, i->ip_prefix, i->ip_prefix_len, 
                               i->interface->tspace_interface.load(*t));
      }
      t_fabric->forwarding_table_version = forwarding_table_version;
    } else {
      if(commit_mode != EXT_FIB_UPDATE) {
        cerr << "non external incremental updates not implemented!\n";
        exit(-1);
      } else {
        // cerr << doubleTime() << ": issuing update\n";
        int err;
        if(true) {
          err = FIBUpdate_issue_Update(router_id, additions, deletions, false);
        } else {
          cerr << "Skipping update issue\n";
        }
        fib_additions_count += additions.size();
        fib_deletions_count += deletions.size();
        // cerr << doubleTime() << ": Back from update, result = " << err << "\n";
      }
    }
  }

  void compute_fib(Topology::InterPOPGraph *pop_graph, 
		  PackedForwardingTable &updated_packed_table) {
    Topology::IntraPOPGraph *ig = pop_graph->full_to_intra[vertex].graph;
    assert(pop_graph->get_node(location).intra_graph == ig);
    
    Topology::IntraPOPGraph::vertex_descriptor my_intra_vertex = 
      pop_graph->full_to_intra[vertex].vertex;
    const vector<FloydWarshall_Entry> &fw_table = 
      * (((*ig)[my_intra_vertex]).fw_table);
    const vector<FloydWarshall_Entry> &pop_fw_table = 
      *pop_graph->get_node(location).fw_table;

    // cout << "<" << router_id << ">";

    int border_router_err = 0;
    int border_router_success = 0;
    for(Topology::POPInfoMap::const_iterator i = topology->pop_info_map.begin();
	i != topology->pop_info_map.end(); i++) {
      const vector<SimRouter *> &tgt_pop_router_vec = i->second.routers;
      if(location == i->first) {
	// Use local routing table
	// cout << "Adding local pop " << location << "\n";
	int count = 0;
	for(size_t j = 0; j < tgt_pop_router_vec.size(); j++) {
	  SimRouter *router = tgt_pop_router_vec[j];
	  Topology::IntraPOPGraph::vertex_descriptor v = 
	    pop_graph->full_to_intra[router->vertex].vertex;
	  assert(pop_graph->full_to_intra[router->vertex].graph == ig);
	  assert(0 <= v && v < num_vertices(*ig));
	  assert(v < fw_table.size());

	  if(fw_table[v].is_valid()) {
	    updated_packed_table.
	      push_back(PackedForwardingEntry(fw_table[v].egress, router->router_id));
	    count++;
	  }
	}
	// cout << count << " entries, " << tgt_pop_router_vec.size() << " routers\n";
      } else {
	// Route to target POP
	Topology::InterPOPGraph::vertex_descriptor t = 
	  pop_graph->translate_vertex(i->first);
	assert(0 <= t && t < pop_fw_table.size());
	if(!pop_fw_table[t].is_valid()) {
	  //cout << "Could not route to " << i->first << " from " << location << "\n";
	  num_unroutable_count++;
	  continue;
	}
	Topology::InterPOPGraph::vertex_descriptor next_hop_pop = 
	  pop_graph->if_to_target(pop_graph->translate_vertex(location), 
				pop_fw_table[t].egress);
	if(0) {
	  cout << "InterPOP To " << i->first << " from " << location << " using " << next_hop_pop <<
	    "(" << (*pop_graph)[next_hop_pop].name << ")\n";
	}
	assert(ig->border_map.find(next_hop_pop) != ig->border_map.end()); 
	assert(ig->border_map[next_hop_pop].virtual_vertex < fw_table.size());

	const Topology::IntraPOPGraph::Border &border = 
	  ig->border_map[next_hop_pop];
	int interface = fw_table[border.virtual_vertex].egress;
	assert(0 <= interface);

	if(interface == FloydWarshall_Entry::INVALID_EGRESS) {
	  if(0) {
	  cout << "Could not route to any border router from " <<
	    pop_graph->full_to_intra[vertex].vertex << "\n";
	  cout << " border vertex is " << border.virtual_vertex << " for " << 
	    next_hop_pop << " \n";
	  }
	  border_router_err++;
	  continue;
	}

	if((size_t)interface >= interfaces.size()) {
	  assert(border.routers.find(my_intra_vertex) != border.routers.end());
	  cout << "Routing to border from external router\n";
	  Topology::Graph::edge_descriptor edge = 
	    border.routers.find(my_intra_vertex)->second.orig_edge;
	  Interface *if_src = topology->graph[edge].source;
	  interface = if_src->if_num;
	}
	border_router_success++;

	int count = 0;
	for(size_t j = 0; j < tgt_pop_router_vec.size(); j++) {
	  SimRouter *router = tgt_pop_router_vec[j];
	  updated_packed_table.
	    push_back(PackedForwardingEntry(interface, router->router_id));
	  count++;
	}
	// cerr << count << " entries, " << tgt_pop_router_vec.size() << " routers\n";
      }
    }
    if(0 && border_router_err > 0) {
      cout << " FIB build Border router err count " << border_router_err << " success count " << border_router_success <<  "\n";
    }
    std::sort(updated_packed_table.begin(), updated_packed_table.end());
  }
  
  void update_fib_helper(Transaction *t, Topology::InterPOPGraph *pop_graph, bool do_tspace) {
    // Expand the multi-level routing information into a packed forwarding table
    if(do_tspace) {
      if(t != NULL) {
        t->undo_log_append(Transaction::SnapshotOf(commited_packed_forwarding_table));
        t->undo_log_append(Transaction::SnapshotOf(forwarding_table_version));
      } else {
        assert(commit_mode == EXT_FIB_UPDATE);
      }
    }

    PackedForwardingTable updated_packed_table(*this);
    compute_fib(pop_graph, updated_packed_table);

    ForwardingTable commited_table;
    ForwardingTable updated_table;

    static int count = 0;
    bool do_print = false;
    if(count++ % 100 == 0) {
      do_print = true;
    }
    if(do_print) {
      cout << "R" << router_id << " "; TIMESTAMP(); cout << " is # " << count << "\n";
    }
    commited_packed_forwarding_table.expand(commited_table);
    updated_packed_table.expand(updated_table);
    if(do_print) {
      cout << "Expanded "; TIMESTAMP();
    }
    if(do_tspace) {
      //tspace_write_fib(t, commited_table, updated_table);
      tspace_write_fib(t, commited_forwarding_table, updated_table);
      commited_forwarding_table = updated_table;
    } else {
      // cout << "Skipping update send\n";
    }
    if(do_print) {
      TIMESTAMP(); cout << "\n";
    }
  }

  void update_fib(Topology::InterPOPGraph *pop_graph) {
    update_fib_helper(NULL, pop_graph, false);
  }

  void tspace_update_fib(Transaction &t, Topology::InterPOPGraph *pop_graph) {
    // cerr << "XXX Refactored, need to test\n";
    if(filter_on_export(router_id)) {
      return;
    }
    update_fib_helper(&t, pop_graph, do_real_tspace_update);
  }

  void tspace_switch_transaction(Transaction &t) {
    // Precondition: Old transaction has expired
    Router *old_router = tspace_router;
    tspace_router = new Router(t, old_router->composite_element->tid);
    // XXX ASHIEH: memory leak ; I'm not sure if this is safe to delete here ; will clean up later 
    // delete old_router;
  }

  void init_tspace_refs(Router *t_router) {
    tspace_router = t_router;

    fabric = ExtRefOf(t_router->fabric);
    forwarding_table.clear();
    commited_forwarding_table = forwarding_table;
    commited_packed_forwarding_table.clear();
    t_router->fabric->forwarding_table.truncate();
    t_router->fabric->forwarding_table_version = 
      forwarding_table_version;

    assert(interfaces.size() == t_router->interfaces.size());
    size_t j;
    for(j=0; j < interfaces.size(); j++) {
      assert(interfaces[j]->if_num == (int)j);
      interfaces[j]->tspace_interface = ExtRefOf(t_router->get_if(j));
    }
  }

  void init_nq_sim_client(EventQueue *sim_ctx) {
    assert(nq_sim_client == NULL);
    nq_sim_client = 
      new NQ_Sim_TSpaceClient(sim_ctx, topology, ROUTERID_TO_IP(router_id));
  }
  void set_nq_sim_server(NQ_Sim_TSpaceServer *nq) {
    nq_sim_server = nq;
  }
  void switch_routing_graph(Topology::InterPOPGraph *new_graph) {
    Topology::InterPOPGraph::get(new_graph);
    if(routing_graph != NULL) {
      // get before put, in case new_graph == routing_graph
      Topology::InterPOPGraph::put(routing_graph);
    }

    if(nq_sim_server != NULL) {
      assert(nq_sim_client != NULL);
      // Push any table updates to tuplespace server
      PackedForwardingTable additions(*this), deletions(*this);
      PackedForwardingTable updated_packed_table(*this);
      compute_fib(new_graph, updated_packed_table);
      SimRouter::table_difference(commited_packed_forwarding_table, 
				  updated_packed_table,
				  &additions, &deletions);
      if(additions.size() + deletions.size() > 0) {
	//cerr << "fib update at " << router_id << " " << 
	//  additions.size() << " "  << deletions.size() << "\n";
	FIBUpdates *adds = new FIBUpdates, *dels = new FIBUpdates;
	additions.expand(*adds);
	deletions.expand(*dels);
	nq_sim_client->
	  issue_rpc(NQ_Sim_TSpaceServer::
		    FIB_Update(nq_sim_server, router_id, new_graph, adds, dels));
      }

      commited_packed_forwarding_table = updated_packed_table;
    } else {
      // cerr << "No NQ server for " << router_id << "\n";
    }

    routing_graph = new_graph;
  }

  bool is_local_ip(uint32_t ip_addr) {
    return ROUTERID_TO_IP(router_id) == ip_addr;
  }
};

Interface::Interface (SimRouter &o, int num, int p_id): 
  owner(o), if_num(num), peer_interface(NULL), peer_router_id(p_id)
{
  assert(o.router_id != peer_router_id);
}


PackedForwardingTable::PackedForwardingTable(SimRouter &c) : container(&c) {
  reserve(boost::num_vertices(container->topology->graph));
}

void PackedForwardingTable::expand(ForwardingTable &output) {
  // mutation version. Should be more efficient when unoptimized.
  // N.B. Expand must generate sorted output
  output.clear();
  output.reserve(size());
  for(iterator i = begin(); i != end(); i++) {
    int ip_prefix_len = 32;
    uint32_t ip_prefix = ROUTERID_TO_IP(i->router_id);
    output.push_back(ForwardingEntry(ip_prefix_len, ip_prefix, 
				     container->interfaces[i->interface]));
  }
}

static inline uint32_t VERTEX_TO_IP(Topology *topo, Topology::Graph::vertex_descriptor v) {
  return ROUTERID_TO_IP(topo->graph[v].router->router_id);
}

static inline Topology::Graph::vertex_descriptor IP_TO_VERTEX(Topology *topo, uint32_t ip) {
  return topo->router_map[IP_TO_ROUTERID(ip)]->vertex;
}

T_Interface *Interface::tspace_get() {
  return owner.tspace_router->get_if(if_num);
}

void Topology::add_router(const RocketPrefix &prefix) {
  assert(find_router(prefix.router_id) == NULL);
  // cerr << "Added router " << prefix.router_id << "\n";
  SimRouter *r = new SimRouter(this, prefix);
  Graph::vertex_descriptor v = 
    boost::add_vertex(SimRouterWrapper(r), graph);
  r->vertex = v;
  router_map[prefix.router_id] = r;
}
void Topology::add_router(int router_id, const string &loc) {
  SimRouter *r = new SimRouter(this, router_id, loc);
  Graph::vertex_descriptor v = 
    boost::add_vertex(SimRouterWrapper(r), graph);
  r->vertex = v;
  router_map[router_id] = r;
}

void Topology::connect(Interface *src, Interface *dst) {
  src->peer_interface = dst;
  Graph::edge_descriptor e;
  bool added;
  float distance;
  bool valid;
  boost::tie(distance, valid) = distances.find(src->owner.location, dst->owner.location);
  if(!valid) {
    cerr << "Could not find distance for " << src->owner.location << "::::" << dst->owner.location << "\n";
    distance = 1000000;
    has_distance_errs = true;
    bad_distance_count++;
  } else {
    good_distance_count++;
  }
  tie(e, added) = 
    boost::add_edge(src->owner.vertex, dst->owner.vertex, 
		    Link(*src, *dst, distance),
		    graph);
  graph[e].edge = e;
  assert(added);
  num_edges++;
}

SimRouter *Topology::find_router(int router_id) {
  SimRouterMap::iterator iter = router_map.find(router_id);
  if(iter == router_map.end()) {
    return NULL;
  } else {
    return iter->second;
  }
}

void Topology::finish_init(void) {
  SimRouterMap orig_map = router_map; // finish init may add external routers; don't process them
  int loc = 0;
  for(SimRouterMap::iterator iter = 
	orig_map.begin();
      iter != orig_map.end(); ++iter) {
    iter->second->finish_init();
    loc++;
  }
  init_done = true;
}
bool Topology::check_integrity(void) {
  int last_num = 0;
  for(SimRouterMap::iterator iter = 
	router_map.begin();
      iter != router_map.end(); ++iter) {
    if(last_num != 0 && iter->first != last_num + 1) {
      // cout << "Discontinuity at " << last_num << ", " << iter->first << "\n";
    }
    last_num = iter->first;
    if(!iter->second->check_data_integrity()) {
      return false;
    }
  }
  return true;
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
  NQ_init(g_server_port);
  //pthread_create(&poller, NULL, &poll_thread, NULL);
}

void Topology::init_tuplespace(const string &tid_ofname) {
  assert(pop_name_map != NULL);
  assert(init_done);
  assert(pop_info_map.size() > 0);

  vector<SimRouter*> all_routers;
  int total_written_count = 0;

  cerr << "Writing nodes to tspace " << timestamp() << "\n";
  POPTransactionMap pop_tr_map;
  hash_map<const string, int> pop_written_count;
  build_pop_transaction_map(pop_tr_map);

  // Write in any order at a time
  bool break_early = false;
  for(SimRouterMap::iterator iter = 
	router_map.begin();
      iter != router_map.end(); ++iter) {
    SimRouter *router = iter->second;

    if(filter_on_export(router->router_id)) {
      continue;
    }

    if(total_written_count % 100 == 0) {
      cerr << "wrote " << total_written_count << " of " << router_map.size() << "\n";
      if(break_early && total_written_count > 0) {
        cerr << "Breaking early\n";
        break;
      }
    }
    assert(!router->wrote_tspace);
    router->wrote_tspace = true;
    pop_written_count[router->location]++;
    total_written_count++;

    Router *t_router = 
      new Router(*pop_tr_map[router->location], (int) router->interfaces.size());
    t_router->set_name(itos(router->router_id) + "@" + router->location);
    t_router->tcp_endpoint->id = 
      IP_TCP( ROUTERID_TO_IP(router->router_id), 0x100 );
    all_routers.push_back(router);

    router->init_tspace_refs(t_router);
    // cout << "(" << router->router_id << ")" ;
  }

  if( !selective_export && !break_early && (int)router_map.size() != total_written_count) {
    cerr << "Router map and total written mismatch. Count comparison: " << router_map.size() << " " << total_written_count << "\n";
    cerr << "exiting\n";
    exit(-1);
  }
  cerr << "Generated routers\n" << timestamp();

  cerr << "Writing out tid file\n";
  ofstream os(tid_ofname.c_str(), ifstream::binary);
  write_int(os, all_routers.size());
  for(size_t i=0; i < all_routers.size(); i++) {
    Router_TIDs tid(all_routers[i]->tspace_router);
    write_int(os, all_routers[i]->router_id);
    tid.marshall(os);
  }
  os.close();

  for(POPTransactionMap::iterator i = pop_tr_map.begin();
      i != pop_tr_map.end(); ++i) {
    int count = pop_written_count[i->first];
    cerr << "Wrote " << count << " to " << i->first << "\n";
    pop_written_count[i->first] = 0;
    if(count > 0) {
      // cerr << "nonzero Breakpoint\n";
    }
    i->second->commit();
    delete i->second;
    cerr << "Commited " << i->first << timestamp() << "\n";
  }

  // Need to commit all of those before writing edges in later
  // transaction, since writing the edges requires loading some of the
  // previously-written values.
  cerr << "Generating edges\n" << timestamp();
  int count = 0;
  
  // Write in a single transaction. The object system will write to a
  // slot that is named by the parent tuple

  Transaction *t = new Transaction(trust_all, trust_attrval_all, NQ_default_owner.home, &NQ_default_owner);
  for(SimRouterMap::iterator i = router_map.begin();
      i != router_map.end(); ++i) {
    SimRouter *router = i->second;
    if(router->tspace_router != NULL) {
      router->tspace_switch_transaction(*t);
    }
  }

  for(SimRouterMap::iterator i = router_map.begin();
      i != router_map.end(); ++i) {
    SimRouter *router = i->second;
    SimRouter::InterfaceTable::iterator j;
    if(router->tspace_router == NULL) {
      continue;
    }
    for(j = router->interfaces.begin(); 
	j != router->interfaces.end(); ++j) {
      // cerr << "Connecting " << router->router_id << " to " << (*j)->peer_router_id << "\n";
      if((*j)->peer_interface->owner.tspace_router == NULL) {
        continue;
      }
      connect_interfaces( (*j)->tspace_get(), (*j)->peer_interface->tspace_get() );
      count++;
      if(count % 1000 == 0) {
	cerr << "(" << count << ")" << timestamp() << "\n";
      }
    }
  }
  cerr << "Generated edges\n";
  t->commit();

  if(1)  {
    cerr << "Writing out site\n";
    ifstream ifs("/nfs/site.tid");
    if(!ifs.good()) {
      cerr << "Could not open site tid!\n";
      exit(-1);
    }
    NQ_UUID site_tid;
    vector<unsigned char> all_data;
    get_all_file_data(ifs, all_data);
    CharVector_Iterator s = all_data.begin(), end = all_data.end();

    site_tid = *tspace_unmarshall(&site_tid, *(Transaction *)NULL, s, end);

    ifs.close();

    t = new Transaction(trust_all, trust_attrval_all, NQ_default_owner.home, &NQ_default_owner);
    ExtRef<T_Site> site_ref = ExtRef<T_Site>(site_tid);
    T_Site *site = site_ref.load(*t);
    if(site != NULL) {
      for(size_t i=0; i < all_routers.size(); i++) { 
        Router *r = all_routers[i]->tspace_router;
        site->routers.push_back(Ref<T_CompositeElement>(r->composite_element));
      }
      cerr << "Done writing out site\n";
    } else {
      cerr << "Could not load site root!\n";
    }
    t->commit();
  }
}

void Topology::load_from_tuplespace(const string &tid_ofname, POPTransactionMap &output_map) {
  cerr << "loading from tuplespace\n";

  build_pop_transaction_map(output_map);

  EmulatorRouters routers;
  load_tids_from_emulator(tid_ofname, &routers);
  for(EmulatorRouters::iterator i = routers.begin(); i != routers.end(); i++) {
    int router_id = i->first;
    Router_TIDs *r_tid = i->second;
    SimRouter *router = router_map[router_id];
    router->init_tspace_refs(new Router(*output_map[router->location], r_tid->tid));
    delete r_tid;
  }

  cerr << "Done loading from tuplespace\n";
}

void Topology::decompose_into_pops(void) {
  // Clear existing mapping
  for(POPInfoMap::iterator iter = pop_info_map.begin();
      iter != pop_info_map.end(); iter++) {
    iter->second.routers.clear();
  }

  is_decomposed = true;
  for(SimRouterMap::iterator iter = router_map.begin();
      iter != router_map.end(); ++iter) {
    SimRouter *router = iter->second;
    pop_info_map[router->location].routers.push_back(router);
  }
}

Topology::InterPOPGraph *Topology::reroute_all(void) {
  cout << "Rerouting top level\n";
  TIMESTAMP();
  InterPOPGraph *inter_graph = build_hierarchical_pop_topology();
  inter_graph->all_pairs_shortest_paths_fw();
  TIMESTAMP();

  int tot_vertices = 0, tot_edges = 0;
  InterPOPGraph::vertex_iterator v, end;
  tie (v, end) = vertices(*inter_graph);
  for(; v != end; v++) {
    // xxx dump size of each pop vertices and edges;
    IntraPOPGraph *ig = (*inter_graph)[*v].intra_graph;
    //cout << "Intra Graph for " << (*inter_graph)[*v].name << 
    //  " N = " << num_vertices(*ig) << " E = " << boost::num_edges(*ig) << "\n";
    tot_vertices += num_vertices(*ig);
    tot_edges += boost::num_edges(*ig);

    ig->all_pairs_shortest_paths_dijk();
    // cerr << timestamp();
  }
  cerr << timestamp() << "Total: N = " << tot_vertices << " E = " << tot_edges << "\n";
  return inter_graph;
}

Topology::InterPOPGraph::vertex_descriptor 
Topology::InterPOPGraph::translate_vertex(Graph::vertex_descriptor v) {
  return pop_to_vertex[container.graph[v].router->location];
}

bool Topology::InterPOPGraph::get_shortest_path_len(Graph::vertex_descriptor s, uint32_t dest_ip, double *rv) {
  Graph::vertex_descriptor finger = s;
  int target_router_id = IP_TO_ROUTERID(dest_ip);
  double latency = 0;
  bool reached;
  while( !(reached = (container.graph[finger].router->router_id == target_router_id)) ) {
    Link l;
    if( !get_next_hop(finger, dest_ip, &finger, &l) ) {
      break;
    }
    latency += l.cost;
  }
  if(!reached) {
    //cerr << "Could not send reliably from " << s << " to " << dest_ip << ", got to vertex " << finger << "\n";
    return false;
  }
  *rv = latency;
  return true;
}

//#define GNH_PING() PING()
#define GNH_PING()
// get_next_hop() uses *this for routing information, rather than the
// graph embedded in the specified router
bool Topology::InterPOPGraph::get_next_hop(Topology::Graph::vertex_descriptor s, uint32_t target_ip, Graph::vertex_descriptor *t, Link *l) {
  using namespace boost;

  GNH_PING();

  const Graph &graph = container.graph;
  GNH_PING();
  SimRouter *r = graph[s].router;
  GNH_PING();
  InterPOPGraph *inter_graph = this;

  GNH_PING();
  if(0) {
    cerr << "<" << s << "," << inter_graph->full_to_intra[s].vertex <<
      "," << r->router_id << ">";
  }
  GNH_PING();
  PackedForwardingTable packed_table(*r);
  ForwardingTable table;
  GNH_PING();
  r->compute_fib(inter_graph, packed_table);
  packed_table.expand(table);
  GNH_PING();

  for(size_t j = 0; j < table.size(); j++) {
  GNH_PING();
    if(table[j].match(target_ip)) {
  GNH_PING();
      int next = table[j].interface->peer_interface->owner.vertex;
      Graph::edge_descriptor e;
      bool found;
      tie(e, found) = edge(s, next, graph);
      assert(found);
      *t = next;
      *l = graph[e];
      return true;
    }
  }
  return false;
}

void Topology::InterPOPGraph::print_next_hop(Graph::vertex_descriptor s, uint32_t target_ip)  {
  Graph::vertex_descriptor t;
  Link l;
  if(get_next_hop(s, target_ip, &t, &l)) {
    cerr << "Next hop from vertex " << s << " to IP " << target_ip << " is " << t << ", cost " << l.cost << "\n";
  } else {
    cerr << "No next hop from " << s << " to IP\n";
  }
}

// Build graph for top level of 2 level topology
Topology::InterPOPGraph *
Topology::build_hierarchical_pop_topology(void) {
  using namespace boost;
  assert(is_decomposed);

  // The constructor
  InterPOPGraph *out_graph = new InterPOPGraph(*this);
  out_graph->build_vertices();

  vector<IntraPOPVertexInfo> &full_to_intra = out_graph->full_to_intra;
  
  IntraPOPGraph *first = NULL;
  for(POPInfoMap::iterator i = pop_info_map.begin();
      i != pop_info_map.end(); i++) {
    IntraPOPGraph *ig = out_graph->get_node(i->first).intra_graph;
      vector<SimRouter *> &router_vec = i->second.routers;
      if(first == NULL) first = ig;

      for(size_t j = 0; j < router_vec.size(); j++) {
	SimRouter *router = router_vec[j];
	full_to_intra[router->vertex].vertex = add_vertex(RouterNodeData(router), *ig);
	full_to_intra[router->vertex].graph = ig;
      }
  }

  Graph::edge_iterator e, end;
  for(tie (e, end) = edges(graph); e != end; e++) {
    // First if-statement fills in Intra information
    if( full_to_intra[source(*e,graph)].graph ==
	full_to_intra[target(*e,graph)].graph ) {
      // Edge is within same graph ; add to Intra graph
      IntraPOPGraph::vertex_descriptor 
	s = full_to_intra[source(*e,graph)].vertex,
	t = full_to_intra[target(*e,graph)].vertex;
      IntraPOPGraph &intra_graph = *full_to_intra[target(*e,graph)].graph;

      IntraPOPGraph::edge_descriptor rg_e;
      bool added;
      tie(rg_e, added) = add_edge(s, t, RouterEdgeData(graph[*e]), intra_graph);
      assert(added);
    } else {
      // Edge is between POPs; populate the border_map
      InterPOPGraph::vertex_descriptor 
	t = out_graph->translate_vertex(target(*e,graph));
      IntraPOPGraph &intra_graph = *full_to_intra[source(*e,graph)].graph;
      IntraPOPGraph::Border &border = intra_graph.border_map[t];
      if(border.needs_init()) {
	border.init(intra_graph, t);
      }
      IntraPOPGraph::vertex_descriptor 
	s = full_to_intra[source(*e,graph)].vertex;
      border.routers[s] = IntraPOPGraph::Border::RouterDesc(*e);

      IntraPOPGraph::edge_descriptor rg_e;
      bool added;
      tie(rg_e, added) = add_edge(s, border.virtual_vertex, RouterEdgeData(graph[*e]), intra_graph);
      assert(added);
    }
    
    // Add to Inter graph
    InterPOPGraph::vertex_descriptor 
	s = out_graph->translate_vertex(source(*e,graph)),
	t = out_graph->translate_vertex(target(*e,graph));
    InterPOPGraph::edge_descriptor rg_e;
    bool present;
    tie(rg_e, present) = edge(s, t, *out_graph);
    if(!present) {
      bool added;
      tie (rg_e, added) = add_edge(s, t, POPEdgeData(), *out_graph);
      assert(added);
      (*out_graph)[rg_e].init();
    }
    (*out_graph)[rg_e].links->push_back(graph[*e]);
    if(isnan((*out_graph)[rg_e].cost)) {
      (*out_graph)[rg_e].cost = graph[*e].cost;
    } else {
      if((*out_graph)[rg_e].cost != graph[*e].cost) {
	cerr << "Graph cost mismatch! " << rg_e << ": " << 
	  (*out_graph)[rg_e].cost << " ; " << *e << ": " << graph[*e].cost;
      }
    }
  }

  InterPOPGraph::vertex_iterator vi, v_end;
  for( tie(vi, v_end) = vertices(*out_graph) ; vi != v_end; vi++ ) {
    InterPOPGraph::out_edge_iterator ei, e_end;
    for( tie(ei, e_end) = out_edges(*vi,*out_graph); ei != e_end; ei++ ){
      (*out_graph)[*ei].egress = (*out_graph)[*vi].interface_target.size();
      (*out_graph)[*vi].interface_target.push_back( target(*ei, *out_graph) );
    }
  }
  return out_graph;
}

void Topology::tspace_update_fib(Topology::InterPOPGraph *pop_graph) {
  fib_additions_count = 0;
  fib_deletions_count = 0;
  cerr.flush();
  fprintf(stderr, "%lf: Starting fib update\n", doubleTime());
  fflush(stderr);
  // cerr << doubleTime() << ": Starting fib update\n"; 

  // Use one transaction per router
  cerr << "Using one transaction for all routers\n";
  Transaction *t = NULL;
#if 0
  if(commit_mode == ONE_BIG_COMMIT) {
    t = new Transaction(trust_all, trust_attrval_all, NQ_default_owner.home, &NQ_default_owner);
  }
#endif
  
  int interleave = 0;
  for(Topology::POPInfoMap::iterator pop_i =
	pop_info_map.begin();
      pop_i != pop_info_map.end(); pop_i++, interleave++) {
    if(do_thread_slice && ((interleave % thread_num_slices) != thread_slice_id)) {
      continue;
    }
    if(do_valgrind) {
      // skip some work
      cerr << "=====> FAST VALGRIND MODE. Only running a few iterations\n";
      if(interleave == 0) {
	cerr << "Skipping the first one\n";
	continue;
      }
      if(interleave == 3) {
	cerr << "Force end\n";
	break;
      }
    }

    if(commit_mode == ONE_PER_POP) {
      t = new Transaction(trust_all, trust_attrval_all, NQ_default_owner.home, &NQ_default_owner);
    }
    int count = 0;
    for(vector<SimRouter *>::iterator j = pop_i->second.routers.begin();
	j != pop_i->second.routers.end(); j++, count++) {
      SimRouter *router = *j;
      if(commit_mode == ONE_PER_ROUTER) {
	t = new Transaction(trust_all, trust_attrval_all, NQ_default_owner.home, &NQ_default_owner);
      }
      if(t != NULL) {
        t->switch_actor(pop_info_map[router->location].principal);
      } else {
        assert(commit_mode == EXT_FIB_UPDATE);
      }
      /*
      cout << "Updating " << router->router_id << " " << 
	count << " of " << pop_i->second.routers.size() <<
	"\n=========\n";
      */
      router->tspace_update_fib(*t, pop_graph);
      if(commit_mode == ONE_PER_ROUTER) {
	t->commit();
	delete t;
      }
      if(do_valgrind && count >= 1) {
	cerr << "Valgrind stopping after 5 in pop\n";
	break;
      }
    }
    if(commit_mode == ONE_PER_POP) {
      cout << "Commited " << pop_i->first << timestamp() << "\n";
      t->commit();
      delete t;
    }
  }
#if 0
  if(commit_mode == ONE_BIG_COMMIT) {
    t->commit();
    delete t;
  }
#endif
  if(commit_mode == EXT_FIB_UPDATE) {
    if(do_real_tspace_update) {
      cerr << "About to issue all commands\n";
      FIBUpdate_issue_CommitAll();
    }
  }
  cerr.flush();
  fprintf(stderr, "%lf: Done with fib update\n", doubleTime());
  fflush(stderr);
  // cerr << doubleTime() << ": Done with fib update\n"; 

  cerr << "FIB Added " << fib_additions_count << "\n";
  cerr << "FIB Deleted " << fib_deletions_count << "\n";
}

void Topology::assign_address(SimRouter *r) {
  uint32_t address;
  if(r->is_external()) {
    address = 1000000 + (uint32_t) -r->router_id;
  } else {
    address = r->router_id;
  }
  assert(address_map.find(address) == address_map.end());
  address_map[r->router_id] = r;
}

typedef RoutingGraph<FloydWarshallNodeData, FloydWarshallEdgeData> FullGraph;

template <typename G>
void Topology::extract_full_graph(G &full_graph) {
  full_graph.clear();
  Topology::Graph::edge_iterator ei, end;
  for(tie(ei,end) = edges(graph); ei != end; ++ei) {
    Topology::Graph::vertex_descriptor 
      s = source(*ei, graph), t = target(*ei, graph);
    typename G::edge_descriptor e;
    bool added;
    tie(e,added) = add_edge(s, t, full_graph);
    assert(added);
    full_graph[e].cost = graph[*ei].cost;
  }
}

struct UpdateInterGraphAndBroadcast {
  EventQueue *sim_ctx;
  Topology *topo;
  Topology::InterPOPGraph *inter_graph;
  SimRouter *router;

  UpdateInterGraphAndBroadcast(EventQueue *s, Topology *t, Topology::InterPOPGraph *i) :
    sim_ctx(s), topo(t), inter_graph(i), router(NULL) {
    Topology::InterPOPGraph::get(inter_graph);
  }
  UpdateInterGraphAndBroadcast(const UpdateInterGraphAndBroadcast & r) :
    sim_ctx(r.sim_ctx),
    topo(r.topo),
    inter_graph(r.inter_graph),
    router(r.router) {
    Topology::InterPOPGraph::get(inter_graph);
  }
  ~UpdateInterGraphAndBroadcast() {
    Topology::InterPOPGraph::put(inter_graph);
  }

  // NOT IMPLEMENTED
private:
  void operator=(void *r) {
    assert(0);
  }
public:

  void set_router(SimRouter *r) {
    router = r;
  }
  void operator() (ostream &os, const EventQueue::Entry_base &event_entry) {
    // cerr << "Updating inter graph at " << router->router_id << " @" << sim_time << "\n";

    if(!topo->graph[router->vertex].saw_broadcast) {
      topo->graph[router->vertex].saw_broadcast = true;
      router->switch_routing_graph(inter_graph);
      // cerr << "Broadcasting at " << router->vertex << "\n";
      // can't pass in *this; that will copy the visitor flags, and screw up the refcnt
      os << "IGPUpdate(size=" << "?" << ")";
      topo->
	apply_broadcast_event(sim_ctx, router->vertex, 
			      UpdateInterGraphAndBroadcast(sim_ctx, topo, inter_graph));
    } else {
      // cerr << "NB(" << router->vertex << ")\n";
    }

    // This assertion can fire if the "one topo change at a time" rule is violated
    assert(router->routing_graph == inter_graph);
  }
};

void Topology::propagate_linkstate_change(EventQueue *sim_ctx, 
					  Topology::InterPOPGraph *new_inter_graph, const vector<Topology::Graph::vertex_descriptor> &nodes) {
  Topology::Graph::vertex_iterator vi, end;
  for(tie(vi,end) = boost::vertices(graph); vi != end; ++vi) {
    graph[*vi].saw_broadcast = false;
  }
  for(size_t i=0; i < nodes.size(); i++) {
    Graph::vertex_descriptor n = nodes[i];
    apply_broadcast_event(sim_ctx, n, 
			  UpdateInterGraphAndBroadcast(sim_ctx, this, new_inter_graph));
  }
}

template <typename F> 
void Topology::apply_broadcast_event(EventQueue *sim_ctx,
				     Topology::Graph::vertex_descriptor s, 
				     F func) {
  Graph::out_edge_iterator ei, end;
  for(tie(ei,end) = out_edges(s, graph); ei != end; ei++) {
    // cerr << "C@" << s << "=" << graph[*ei].cost << "\n";
    func.set_router(graph[target(*ei, graph)].router);
    sim_ctx->schedule_from_now(graph[*ei].cost, func);
  }
}

template <typename F>
void Topology::forward_packet_event(struct EventQueue *sim_ctx, 
			  // source + destination
			  Topology::Graph::vertex_descriptor s, uint32_t target_ip,
			  F func) {
  InterPOPGraph *inter_graph = graph[s].router->routing_graph;
  Link l;
  Topology::Graph::vertex_descriptor t;
  if(inter_graph->get_next_hop(s, target_ip, &t, &l)) {
    func.set_router(&l.dest->owner);
    sim_ctx->schedule_from_now(l.cost, func);
  } else {
    cerr << "<packet dropped at " << s << " trying to get to " << target_ip << ">";
  }
}

// This one is for TCP. It uses the latest converged routing tables
template <typename F>
void Topology::reliable_send_event(struct EventQueue *sim_ctx, 
			 // source + destination
			 Topology::Graph::vertex_descriptor s, uint32_t dest_ip,
			 F func) {
  double latency;
  if(!latest_converged->get_shortest_path_len(s, dest_ip, &latency)) {
    // cerr << "Could not send event reliably from " << s << " to " << dest_ip << "\n";
    sim_ctx->fail(func);
    return;
  }
  sim_ctx->log_curr_event("ReliableSend(" + itos(VERTEX_TO_IP(this, s)) + "=>" + ip_to_string(dest_ip) + ",delay=" + dtos(latency) + ")");

  int router_id = IP_TO_ROUTERID(dest_ip);
  assert( router_map.find(router_id) != router_map.end() );
  func.set_router(router_map[router_id]);
  sim_ctx->schedule_from_now(latency, func);
}

int valid_count = 0;

Topology *load_topology(const string &topo_fname, const DistanceDB &distances) {
  // snippet from http://girtby.net/archives/2007/10/9/wide-finder-in-c
  NameDB *names = new NameDB(topo_fname + ".unknown");
  // names->print_all();

  Topology *topo = new Topology(distances, *names);

  boost::smatch matches;
  boost::iostreams::mapped_file_source mf(topo_fname);
  boost::cregex_iterator lines(mf.begin(), mf.end(), line_pattern);
  boost::cregex_iterator end;
  bool found_invalid_prefix = false;
  vector<RocketPrefix> prefixes;
  for( ; lines != end; lines++) {
    string curr_line = string((*lines)[0]);
    RocketPrefix prefix = RocketPrefix(curr_line);
    if(!prefix.valid) {
      // cerr << "Found invalid? valid count = " << valid_count << "\n";
      // cerr << "===> " << curr_line << "\n";
      found_invalid_prefix = true;
    } else {
      if(test_spec != NULL) {
        num_routers_in_input++;
        if(!test_spec->patch_prefix(&prefix)) {
          // cerr << "testspec says skip " << prefix.router_id << "\n";
          continue;
        }
      }
      topo->add_router(prefix);
      valid_count++;
    }
    // cout << prefix;
  }
  cout << "Finishing initialization\n";

  topo->finish_init();
  if(topo->has_distance_errs) {
    cout << "Errors in topo distance!\n";
    cout << "good: " << topo->good_distance_count << " bad: " << 
      topo->bad_distance_count;
    exit(-1);
  }
  cout << num_routers << " routers ; " << num_edges << " edges ; \n";
  cout << "Checking data integrity\n";
  if(!topo->check_integrity()) {
    cerr << "Data integrity check failed\n";
    exit(-1);
  }
  // Decompose each POP into connected components
  topo->decompose_into_pops();
  topo->split_disconnected_pops();
  // recompute the decomposition
  topo->decompose_into_pops();
  
  if(topo->split_disconnected_pops() != 0) {
    cerr << "Still found some disconnected POPs!\n";
    exit(-1);
  }

  return topo;
}

// Split all disconnected components
// Returns number of split pops
int Topology::split_disconnected_pops(void) {
  cerr << "Splitting POPs\n";
  using namespace boost;
  int split_count = 0;

  Topology::InterPOPGraph *inter_graph = build_hierarchical_pop_topology();
  Topology::InterPOPGraph::vertex_iterator vi, v_end;
  for(tie(vi,v_end) = vertices(*inter_graph); vi != v_end; vi++) {
    Topology::IntraPOPGraph *intra_graph = (*inter_graph)[*vi].intra_graph;

    vector< vector<SimRouter *> > components;
    int N = num_vertices(*intra_graph);
    vector<bool> connected(N);

    Topology::IntraPOPGraph::vertex_iterator vj, end;
    for(tie(vj,end) = vertices(*intra_graph); vj != end; vj++) {
      if( connected[*vj] || intra_graph->is_border_vertex(*vj) ) {
	continue;
      }
      components.push_back(vector<SimRouter *>());

      vector<default_color_type> color_vec(N);
      depth_first_visit( *intra_graph, *vj, default_dfs_visitor(), &color_vec[0] );

      // Decompose into connected components. Also, mark visited nodes
      // so that we only run DFS once
      for(size_t i=0; i < color_vec.size(); i++) {
	SimRouter *r = (*intra_graph)[i].router;
	if(r != NULL && // is real router, not virtual node
	   color_vec[i] == black_color) {
	  assert(!connected[i]);
	  connected[i] = true;

	  components.back().push_back(r);
	}
      }
    }
    assert(components.size() > 0 && components[0].size() > 0);
    int total_routers = 0;
    for(size_t i=0; i < components.size(); i++) {
      assert(components[i].size() > 0);
      total_routers += components[i].size();
    }
    if(components.size() > 1) {
      split_count++;
      string pop_location = components[0].front()->location;
      cerr << "Node " << *vi << "(" << pop_location << ") has " << components.size() << " components, " << total_routers << " total routers\n";
      vector <string> all_pop_locations;
      all_pop_locations.push_back(pop_location);
      
      DistanceDB old_db = distances;
      string orig_cname = DistanceDB::canonical_name(pop_location);
      typedef hash_map<const string /* other */, double /* distance */> Matches;
      Matches matches;

      // Create a new entry for every original entry
      for(DistanceDB::DistanceMap::iterator 
	    it = old_db.map.begin(); it != old_db.map.end(); it++) {
	string other("");
	if(it->first.first == orig_cname) {
	  other = it->first.second;
	} else if(it->first.second == orig_cname) {
	  other = it->first.first;
	}
	if(other != "") {
	  assert(matches.find(other) == matches.end());
	  matches[other] = it->second;
	}
      }
      for(size_t i=1; i < components.size(); i++) {
	// Create a new POP name for additional components
	string component_name = pop_location + "(" + itos(i) + ")";
	all_pop_locations.push_back(component_name);

	string cname = DistanceDB::canonical_name(component_name);
	for(Matches::iterator it = matches.begin(); it != matches.end(); it++) {
	  distances.add_distance(component_name, it->first, it->second);
	}
	for(vector<SimRouter *>::iterator 
	      j = components[i].begin(); j != components[i].end(); j++) {
	  assert((*j)->location == pop_location);
	  (*j)->location = component_name;
	}
      }
      // Add distances between added components
      // cerr << "adding distances, total = " << all_pop_locations.size() * all_pop_locations.size() << "\n";
      for(size_t i=0; i < all_pop_locations.size(); i++) {
	for(size_t j=0; j < all_pop_locations.size(); j++) {
	  string s0 = all_pop_locations[i], s1 = all_pop_locations[j];
	  distances.add_distance(s0, s1, LOCAL_LATENCY);
	  // cerr << "Adding " << s0 << "," << s1 << " " << LOCAL_LATENCY << "\n";
	}
        // cerr << i << "/" << all_pop_locations.size() << "\n";
      }
    }
  }
  return split_count;
}

#if 0
// Fragment for generating access host
  for(SimRouterMap::iterator i = router_map.begin();
      i != router_map.end(); ++i) {
    SimRouter *router = i->second;
    if(router->is_external()) {
      T_Interface *new_if = router->tspace_router->add_if();
      Host *host = new Host(*t);
      hosts.push_back(new SimHost(host));
    }
  }
  cout << "Generated access hosts\n";
#endif

void sig_break(int v) {
  cerr << "Got break\n";
  NQ_dump_stats();
  cout.flush();
  exit(0);
}

void test_edge_removal(Topology *topo, int mode);
void test_force_disconnect(Topology *topo);
void test_conversions(void);
void sim_remove_edge(EventQueue *sim_ctx, Topology *topo, Topology::Graph::vertex_descriptor s, Topology::Graph::vertex_descriptor t);

#include "sim_flow_creation.cc"

void sim_ip_forwarding(EventQueue *sim_ctx, Topology *topo,
		       Topology::Graph::vertex_descriptor s,
		       uint32_t target_ip);

struct PingResult {
  double latency;
  bool valid;
  PingResult() : latency(NAN), valid(false) { }
  void set(double l) {
    latency = l;
    valid = true;
  }
};

ostream &operator<<(ostream &os, const PingResult &pr) {
  if(pr.valid) {
    os << pr.latency;
  } else {
    os << "Could not reach dest!\n";
  }
  return os;
}

PingResult *sim_ping(EventQueue *sim_ctx, Topology *topo,
		     uint32_t source_ip, uint32_t target_ip);

void add_test_triggers(Topology *topo, EventQueue *sim_ctx, int *counter,
		       int simulation_seed, string test_spec);
void remove_test_triggers(Topology *topo);

int main(int argc, char **argv) {
#ifdef __OPTIMIZE__
  cout << "Optimized build!\n";
#else
  cout << "Unoptimized build!\n";
#endif
  // show_rpc_traffic = 1;
  // Catch SIGINT to make sure gmon.out is written
  signal(SIGINT, sig_break);
  atexit(NQ_dump_stats);
  NQ_init(0);
  NQ_cpp_lib_init();

  int opt;
  string nq_hostname = gethostname();
  bool skip_tuplespace_load = false;
  int num_link_failures = 0;
  int failure_magnitude = 10;
  while( (opt = getopt(argc, argv, "h:p:s:vn:S:RO:DF:M:")) != -1) {
    switch(opt) {
    case 'h':
      nq_hostname = optarg;
      break;
    case 'p':
      g_server_port = atoi(optarg);
      break;
    case 'n':
      g_test_count = atoi(optarg);
      break;
    case 'S':
      g_seed = atoi(optarg);
      break;
    case 'R':
      cerr << "Doing recursive query execution\n";
      g_do_recursive = true;
      break;
    case 'D':
      cerr << "Doing deletion\n";
      g_do_deletion = true;
      break;
    case 'O':
      g_flow_opt_level = atoi(optarg);
      cerr << "Optimization level " << g_flow_opt_level << "\n";
      // O1: Last recursive server sends the commit check at the same
      // time that the response is sent to the initial client; the
      // commit response is to be sent back to the initial client

      break;
    case 'v':
      do_valgrind = true;
      break;
    case 's':
      // "Slice" some loops for coarse-level parallelism.
      if(strlen(optarg) == 3 && optarg[1] == ':') {
	char *arg = strdup(optarg);
	arg[1] = '\0';
	thread_slice_id = atoi(arg);
	thread_num_slices = atoi(arg+2);
	if(thread_slice_id >= 0 && thread_num_slices >= 0 && thread_slice_id < thread_num_slices) {
	  do_thread_slice = true;
	  cerr << "Slicing " << thread_slice_id << "/" << thread_num_slices << "\n";
	}
	free(arg);
      }
      if(!do_thread_slice) {
	cerr << "Not doing thread slicing due to arg error\n";
      }
      break;
    case 'F':
      num_link_failures = atoi(optarg);
      cerr << "Runnign with " << num_link_failures << " failures\n";
      break;
    case 'M':
      failure_magnitude = atoi(optarg);
      cerr << "Failure magnitude = " << failure_magnitude << "\n";
      break;
    default:
      printf("Unknown option %c\n", opt);
      exit(-1);
    }
  }

  g_flow_principal = NULL;

  cerr << "Using " << g_seed << " as seed\n";
  srand48(g_seed);

  if(!(optind+2 < argc)) {
    cout << "not enough args " << optind << " " << argc << "\n";
    exit(-1);
  }
  int mode = atoi(argv[optind]);
  string topo_file = argv[optind+1];
  string loc_file = argv[optind+2];

  cerr << "Mode = " << mode << " topo = " << topo_file << " loc = " << loc_file << "\n";

  if(optind+3 < argc) {
    string testspec_file = argv[optind+3];
    test_spec = new TestSpec(testspec_file);
    cerr << "Test spec = " << testspec_file << "\n";
  } else {
    test_spec = NULL;
    cerr << "No test spec\n";
  }

  DistanceDB *distances = 
    new DistanceDB(loc_file, "loc-fixfile.txt");
  //distances->print_all();


  Topology *topo;
  topo = load_topology(topo_file, *distances);

  string popmap_fname("pop.portmap");
  string tid_ofname("all-pop.tid");

  cerr << "Num pruned routers " << num_pruned_routers <<
    " num in input " << num_routers_in_input << " num in spec " << (test_spec ? test_spec->num_routers_in_test() : -1) << "\n";
  extern int composite_element_count;
  switch(mode) {
  case 0: {
    cerr << "Generating pop map\n";
    ofstream pop_file(popmap_fname.c_str());
    map<string /* location */, int /* count */ > all_locs;
    for(Topology::SimRouterMap::iterator i = topo->router_map.begin();
	i != topo->router_map.end(); i++) {
      string loc = i->second->location;
      if(all_locs.find(loc) == all_locs.end()) {
	all_locs[loc] = 0;
      }
      all_locs[loc] = all_locs[loc] + 1;
    }
    int pop_port_num = 9000;
    map<string /* geo location */, int /* port */> port_map;
    for(map<string,int>::iterator i = all_locs.begin();
	i != all_locs.end(); i++) {
      string str = i->first;
      char *str_c = strdup(str.c_str());
      char *ptr = strchr(str_c,'(');
      if(ptr != NULL) *ptr = '\0';
      str = string(str_c);
      cerr << " Converted " << i->first << " to " << str << "\n";
      int port_num;
      if(port_map.find(str) == port_map.end()) {
        port_num = port_map[str] = pop_port_num;
        if(!single_nq_server) {
          cerr << "port incr\n";
          pop_port_num += 1;
        }
      } else {
        port_num = port_map[str];
      }
      
      pop_file << i->first << " " << nq_hostname << " "<< port_num << "\n";
      free(str_c);
    }
    pop_file.close();
    break;
  }
  case 1: {
    cerr << "Constructing topology at all pops and outputting TID index\n";
    start_net_client();

    POP_Map pop_name_map(popmap_fname);
    topo->set_pop_name_map(&pop_name_map);
    topo->init_tuplespace(tid_ofname);
    cerr << "Composite element count = " << composite_element_count << "\n";
    break;
  }
  case 2: {
    start_net_client();
    all_pop_local:
    cerr << "Composite element count = " << composite_element_count << "\n";

    cerr << "Update protocol " << "\n";
    if(!fork()) {
      string cmdline = string("/bin/bash -c '(killall fib-updater ; ./fib-updater " + 
                              fib_update_proto_sock +
                              ") > fib-update.out 2> fib-update.err' ");
#if 0
      int stdout_redir = open("fib-update.out", O_CREAT | O_WRONLY);
      int stderr_redir = open("fib-update.err", O_CREAT | O_WRONLY);
      if(stdout_redir < 0 || stderr_redir < 0) {
        cerr << "Error openign stdout or stderr\n";
      }
#endif
      exit(system(cmdline.c_str()));
    }
    while(1) {
      sleep(2);
      cerr << "Trying to connect\n";
      if(FIBUpdate_connect(fib_update_proto_sock) == 0) {
        cerr << "Successfully connected\n";
        break;
      }
    }
    FIBUpdate_issue_LoadSpec(tid_ofname);

    cerr << "Starting router emulation\n";
    POP_Map pop_name_map(popmap_fname);
    topo->set_pop_name_map(&pop_name_map);

    if(!skip_tuplespace_load) {
      Topology::POPTransactionMap pop_tr_map;
      topo->load_from_tuplespace(tid_ofname, pop_tr_map);
      pop_tr_map.commit_and_delete_all();
    }

    double start_time = doubleTime();
    print_timestamp("Start reroute all\n");
    Topology::InterPOPGraph *ig;
    ig = topo->reroute_all();
    double end_time = doubleTime();
    int run_count = 1;
    cerr << "Done with reroute_all(),  " << num_unroutable_count << "\n";
    cerr << "Time each is " << (end_time - start_time) / run_count << "\n";
    print_timestamp("Finish reroute all\n");
    print_timestamp("Start initial fib update\n");
    topo->tspace_update_fib(ig);
    print_timestamp("End initial fib update\n");
    for(int i=0; i < num_link_failures; i++) {
      Topology::Graph::vertex_descriptor s, t;
      cerr << "Failure " << i << " of " << num_link_failures << "\n";
      for(int j=0; j < failure_magnitude; j++) {
        if(false) {
          topo->biased_pick_random_edge(&s,&t);
          cerr << "biased random edge\n";
        } else {
          topo->pick_random_edge(&s,&t);
          cerr << "random edge\n";
        }
        topo->remove_edge(s,t);
        cerr << "Removing (" << s << "," << t << ")\n";
      }
      cerr.flush();

      print_timestamp("Start failure reroute all\n");
      Topology::InterPOPGraph *ig = topo->reroute_all();
      print_timestamp("End failure reroute all\n");

      print_timestamp("Start of failure fib update\n");
      topo->tspace_update_fib(ig);
      print_timestamp("End of failure fib update\n");
    }
    cerr << "Done with all tests\n";
    break;
  }
  case 3: {
    cerr << "Big test\n";
    // start_net_client();
    string tid_ofname("all-pop.tid");

    POP_Map pop_name_map(popmap_fname);
    topo->set_pop_name_map(&pop_name_map);
    
    Topology::InterPOPGraph *ig; ig = topo->reroute_all();
    topo->init_tuplespace(tid_ofname);
    // topo->tspace_update_fib(ig);
    cerr<< "looping after loading topo. Get the memory utilization\n";
    while(1);
    exit(-1);
    break;
  }
  case 4: {
    using namespace boost;
    cerr << "Sample-based routing test\n";
    start_net_client();
    POP_Map pop_name_map(popmap_fname);
    topo->set_pop_name_map(&pop_name_map);
    Topology::InterPOPGraph *inter_graph;
    inter_graph = topo->reroute_all();
    cerr << "Done with reroute_all()\n";
    cerr << "Picking random server pairs\n";
    FullGraph full_graph;
    topo->extract_full_graph(full_graph);
    size_t N; N = num_vertices(full_graph);
    int match_count = 0, unmatch_count = 0;
    float total_delta = 0, max_delta = 0;
    for(int i = 0; i < 10000; i++) {
      TIMESTAMP();
      unsigned s;
      unsigned t;
      if(i % 2 == 0) {
        cerr << "Any POPs (";
        s = (unsigned long)(drand48() * N);
        t = (unsigned long)(drand48() * N);
        cerr << topo->graph[s].router->location << " to " << 
          topo->graph[t].router->location << ")\n";
      } else {
        cerr << "Within POP ";
        int as_index = (int) (drand48() * topo->num_pops());
        Topology::POPInfoMap::iterator pop_i;
        for(pop_i = topo->pop_info_map.begin();
            pop_i != topo->pop_info_map.end(); pop_i++, --as_index) {
          if(as_index == 0) break;
        }
        cerr << pop_i->first << "\n";
        int _s = (int) (drand48() * pop_i->second.routers.size()),
          _t = (int) (drand48() * pop_i->second.routers.size());
        s = pop_i->second.routers[_s]->vertex;
        t = pop_i->second.routers[_t]->vertex;
      }
      FullGraph::DFSGraph T;
      vector<float> distance;
      vector<FullGraph::vertex_descriptor> pred;
      full_graph.shortest_paths_tree(s, T, distance, pred);
      bool has_dijk_route = !isnan(distance[t]);

      // Simulate forwarding with hierarchical generator
      uint32_t target_ip = ROUTERID_TO_IP(topo->graph[t].router->router_id);
      
      bool has_route = true;
      unsigned long finger = s;
      float hier_cost = 0;
      cerr << s << " to " << t << ":\n";
      while(has_route && finger != t) {
        //inter_graph->full_to_intra[finger].graph->dump_shortest_path_tree(inter_graph->full_to_intra[finger].vertex);
        has_route = false;
        SimRouter *r = topo->graph[finger].router;
        cerr << "<" << finger << "," << inter_graph->full_to_intra[finger].vertex <<
          "," << r->router_id << ">";
        PackedForwardingTable packed_table(*r);
        ForwardingTable table;
        r->compute_fib(inter_graph, packed_table);
        packed_table.expand(table);
        for(size_t j = 0; j < table.size(); j++) {
          if(table[j].match(target_ip)) {
            int next = table[j].interface->peer_interface->owner.vertex;
            FullGraph::edge_descriptor e;
            bool found;
            tie(e, found) = edge(finger, next, full_graph);
            assert(found);
            hier_cost += full_graph[e].cost;

            finger = next;
            has_route = true;
            break;
          }
        }
      }
      cerr << "\n";
      bool has_hier_route = (finger == t);

      if(has_dijk_route) {
        cerr << "Has DIJK route, cost is " << distance[t] << "\n";
      } else {
        cerr << "Does not have DIJK route\n";
      }
      if(has_hier_route) {
	cerr << "Has Hier route, cost is " << hier_cost << "\n";
	double shortest_fast;
	bool found = 
	  inter_graph->get_shortest_path_len(s, target_ip, &shortest_fast);
	assert(found);
	if(almost_equal(shortest_fast, hier_cost)) {
	  cerr << "Did not match the cost from the tables!: " << shortest_fast << ", " << hier_cost << "\n";
	}
      } else {
        cerr << "Does not have Hier route\n";
      }

      if( (has_hier_route && has_dijk_route) ||
          (!has_hier_route && !has_dijk_route) ) {
        match_count++;
        float delta = fabs(hier_cost - distance[t]);
        total_delta += delta;
        max_delta = max(max_delta, delta);
      } else {
        unmatch_count++;
      }
    }
    cerr << match_count << " matches, " << unmatch_count << " unmatches, total delta=" << total_delta << ", max delta=" << max_delta << "\n";
    break;
  }
  case 5: {
    skip_tuplespace_load = true;
    do_real_tspace_update = false;
    goto all_pop_local;
    break;
  }
  case 20: {
    cerr << "Flow creation timing\n";
    
    sim_flow_creation_timing(topo, popmap_fname);
    
  }
  break;
  case 10: {
    using namespace boost;
    cerr << "Routing dynamics test\n";

    POP_Map pop_name_map(popmap_fname);
    topo->set_pop_name_map(&pop_name_map);

    EventQueue sim_ctx("sim.log");

    vector<Topology::Graph::vertex_descriptor> nodes;

    // Instantiate a NQ_Client on every router
    for(Topology::SimRouterMap::iterator 
	  i = topo->router_map.begin();
	i != topo->router_map.end(); ++i) {
      i->second->init_nq_sim_client(&sim_ctx);
    }


    // Pick router to be NQ server
    for(Topology::POPInfoMap::iterator 
	  pop_i = topo->pop_info_map.begin();
	pop_i != topo->pop_info_map.end(); pop_i++) {
      bool found = false;
      int local_router_id;
      for(vector<SimRouter*>::iterator 
	    j = pop_i->second.routers.begin();
	  j != pop_i->second.routers.end(); j++) {
	if((*j)->router_id > 0) {
	  local_router_id = (*j)->router_id;
	  found = true;
	  break;
	}
      }
      assert(found);

      NQ_Sim_TSpaceServer *nq_sim_server = 
	new NQ_Sim_TSpaceServer(&sim_ctx, topo, ROUTERID_TO_IP(local_router_id));
      pop_i->second.nq_sim_server = nq_sim_server;
      for(vector<SimRouter*>::iterator 
	    j = pop_i->second.routers.begin();
	  j != pop_i->second.routers.end(); j++) {
	(*j)->set_nq_sim_server(nq_sim_server);
      }
    }

    Topology::Graph::vertex_iterator vi, end;
    for(tie(vi, end) = vertices(topo->graph); vi != end; ++vi) {
      nodes.push_back(*vi);
    }
    Topology::InterPOPGraph *inter_graph = topo->reroute_all();
    topo->propagate_linkstate_change(&sim_ctx, inter_graph, nodes);
    topo->switch_routing_graph(inter_graph);
    Topology::InterPOPGraph::put(inter_graph);
    sim_ctx.run_all();
    sim_ctx.log_curr_event("DONE WITH INITIALIZATION\n");

    // Topology is now initialized
    if(0) {
      test_edge_removal(topo, 0);
      test_edge_removal(topo, 1);
    }
    if(0) {
      test_force_disconnect(topo);
    }
    if(0) {
      test_conversions();
    }

    unsigned s, t;
    FullGraph full_graph;
    topo->extract_full_graph(full_graph);
    size_t N; N = num_vertices(full_graph);
    s = (unsigned long)(drand48() * N);
    t = (unsigned long)(drand48() * N);
    cerr << topo->graph[s].router->location << " to " << 
      topo->graph[t].router->location << ")\n";
    uint32_t source_ip = VERTEX_TO_IP(topo, s);
    uint32_t target_ip = VERTEX_TO_IP(topo, t);

    cerr << "First simulated ping (before changing topo)\n";
    PingResult *res = sim_ping(&sim_ctx, topo, source_ip, target_ip);
    sim_ctx.run_all();
    cerr << "Ping result: " << *res;
    delete res; res = NULL;

    cerr << "IP forwarding: ";
    sim_ip_forwarding(&sim_ctx, topo, s, target_ip);
    sim_ctx.run_all();

    cerr << "Adding test triggers\n";
    int counter = 0;
    add_test_triggers(topo, &sim_ctx, &counter,
		      g_seed, topo_file + " " + loc_file);

    for(int i = 0; i < 3; i++) {
      Topology::Graph::vertex_descriptor s, t;
      topo->pick_random_edge(&s,&t);
      cerr << "Removing edge (" << s << "," << t << ");\n";

      sim_remove_edge(&sim_ctx, topo, s, t);
      sim_ctx.run_all();
      cerr << "Converged at " << sim_ctx.sim_time << "\n";
      // Topology::InterPOPGraph *ig; ig = topo->reroute_all();
      if(i == 0) {
	cerr << "Got " << counter << " trigger upcalls\n";
	assert(counter > 0);
	remove_test_triggers(topo);
      } else {
	// make sure there are no more upcalls after the counter is removed
	assert(counter == 0);
      }
    }
    remove_test_triggers(topo);

    // Discrete-time version of forwarding. Copy-paste from other code

    FullGraph::DFSGraph T;
    vector<float> distance;
    vector<FullGraph::vertex_descriptor> pred;
    full_graph.shortest_paths_tree(s, T, distance, pred);
    bool has_dijk_route = !isnan(distance[t]);

    double start_time = sim_ctx.sim_time;
    sim_ip_forwarding(&sim_ctx, topo, s, target_ip);
    sim_ctx.run_all();

    // sim will stop when packet arrives
    double arrival_time = sim_ctx.sim_time;
    cerr << "Started at " << start_time << " arrived at " << arrival_time << "\n";
    if(has_dijk_route) {
      cerr << "Has DIJK route, cost is " << distance[t] << "\n";
    } else {
      cerr << "Does not have DIJK route\n";
    }
    res = sim_ping(&sim_ctx, topo, s, target_ip);
    sim_ctx.run_all();
    cerr << "Ping result: " << *res;

    break;
  }
  default:
    cerr << "Unknown router mode\n";
    break;
  }

  cerr << "New bytes: " << new_count << "\n";
}

void Topology::IntraPOPGraph::dump_shortest_path_tree(vertex_descriptor v) {
  DFSGraph T;
  vector<float> distance;
  vector<vertex_descriptor> pred;
  IntraPOPGraph &graph = *this;

  // shortest_paths_tree will overwrite the old table; back it up
  vector<FloydWarshall_Entry> old_fw_table = *graph[v].fw_table;

  int intra_N; intra_N = num_vertices(graph);
  shortest_paths_tree(v, T, distance, pred);
	  
  DFSGraph::edge_iterator ei, end;
  for(tie(ei,end)=edges(T); ei != end; ++ei) {
    cerr << *ei << "\n";
  }

  *graph[v].fw_table = old_fw_table;
}

void test_edge_removal(Topology *topo, int mode) {
  cerr << "Testing copy then edge removal\n";
  if(mode == 0) {
    Topology copy = *topo;
    // Pick a random edge to delete
    Topology::Graph::edge_iterator ei = copy.pick_random_edge();
    Topology::Graph::edge_descriptor e = *ei;
  
    cerr << "Removing " << *ei << " from copy\n";
    Topology::Graph::edge_descriptor test_e;
    Topology::Graph::vertex_descriptor 
      s = source(e, copy.graph),
      t = target(e, copy.graph);
    bool found;
    tie(test_e, found) = edge(s, t, topo->graph);
    assert(found);
    tie(test_e, found) = edge(s, t, copy.graph);
    assert(found);
    remove_edge(*ei, copy.graph);

    // should be removed from new graph, but not from old graph
    tie(test_e, found) = edge(s, t, topo->graph);
    assert(found);
    tie(test_e, found) = edge(s, t, copy.graph);
    assert(!found);
  } else {
    Topology::Graph::vertex_descriptor s, t;
    Topology::Graph::edge_descriptor test_e;
    bool found;
    topo->pick_random_edge(&s, &t);
    tie(test_e, found) = edge(s, t, topo->graph);
    assert(found);

    Topology &copy = *topo->copy_and_remove_edge(s,t);
    tie(test_e, found) = edge(s, t, topo->graph);
    assert(found);
    tie(test_e, found) = edge(s, t, copy.graph);
    assert(!found);
  }
  cerr << "passed all tests\n";
}

void dealloc_container(Topology::InterPOPGraph *inter_graph) {
  Topology *topo = const_cast<Topology *>(&inter_graph->container);
  cerr << "Deallocating topo\n";
  delete topo;
}

Interface *
fib_get_next_hop(Topology *topo, Topology::InterPOPGraph *ig, Topology::Graph::vertex_descriptor s, uint32_t ip_address) {
  SimRouter *r = topo->graph[s].router;
  PackedForwardingTable packed_table(*r);
  ForwardingTable table;
  r->compute_fib(ig, packed_table);
  packed_table.expand(table);
  return table.lookup(ip_address);
}

void sim_remove_edge(EventQueue *sim_ctx, Topology *topo,
			   Topology::Graph::vertex_descriptor s,
			   Topology::Graph::vertex_descriptor t) {
  // N.B.: This algorithm only works in the special case where one edge is removed at a time!
  topo->remove_edge(s, t);
  Topology::InterPOPGraph *inter_graph = topo->reroute_all();
  inter_graph->translate_vertex(s);

  // inter_graph->put_handler = dealloc_container;
  vector<Topology::Graph::vertex_descriptor> nodes;
  nodes.push_back(s);
  nodes.push_back(t);
  topo->propagate_linkstate_change(sim_ctx, inter_graph, nodes);

  topo->switch_routing_graph(inter_graph);
  Topology::InterPOPGraph::put(inter_graph);
  // new_topo does not leak ; it is referenced by inter_graph, and
  // will be deallocated when the refcnt hits 0
}

struct ForwardPacket {
  EventQueue *sim_ctx;
  Topology *topo;
  SimRouter *router;
  uint32_t target_ip;

  ForwardPacket(EventQueue *s, Topology *t, uint32_t ip) :
    sim_ctx(s), topo(t), router(NULL), target_ip(ip) { }

  void set_router(SimRouter *r) {
    router = r;
  }
  void operator() (ostream &os, const EventQueue::Entry_base &event_entry) {
    cerr << "F(" << router->router_id << "@" << event_entry.curr_time << ")";
    os << "FWDRX(size=" << "?" << ")";
    if(router->is_local_ip(target_ip)) {
      cerr << "Arrived\n";
    } else {
      topo->
	forward_packet_event(sim_ctx, router->vertex, target_ip,
			     ForwardPacket(sim_ctx, topo, target_ip));
    }
  }
};

void sim_ip_forwarding(EventQueue *sim_ctx, Topology *topo,
		       Topology::Graph::vertex_descriptor s,
		       uint32_t target_ip) {
  topo->
    forward_packet_event(sim_ctx, s, target_ip,
			 ForwardPacket(sim_ctx, topo, target_ip));
}

struct Continuation {
  EventQueue *sim_ctx;
  Topology *topo;
  SimRouter *router;

  Continuation(EventQueue *s, Topology *t) :
    sim_ctx(s), topo(t), router(NULL) { }

  void set_router(SimRouter *r) {
    router = r;
  }
#if 0
  // these can't be implemented as virtual functions, as the function
  // object will be copied multiple times
  virtual void operator() (float sim_time) = 0;
  virtual void issue() = 0;
#endif
};

struct IPContinuation : Continuation {
  uint32_t sender_ip;
  uint32_t exec_ip; // ip on which continuation is to execute
  IPContinuation(EventQueue *s, Topology *t, uint32_t e_ip, uint32_t s_ip) :
    Continuation(s,t),
    sender_ip(s_ip), 
    exec_ip(e_ip) { }
  void check_event() {
    assert(router->is_local_ip(exec_ip));
  }
};

void CheckIPWrapper::set_router(SimRouter *r) {
  event_ip = ROUTERID_TO_IP(r->router_id);
}

template<class T>
void issue_reliably(uint32_t exec_ip, T c) {
  c.sender_ip = exec_ip;
  c.topo->reliable_send_event(c.sim_ctx, 
			      c.topo->router_map[IP_TO_ROUTERID(exec_ip)]->vertex,
			      c.exec_ip, c);
}

struct Ping : IPContinuation {
  double issue_time;
  PingResult *result;
  Ping(EventQueue *s, Topology *t,
       uint32_t exec_ip, uint32_t sender_ip,
       PingResult *r) :
    IPContinuation(s, t, exec_ip, sender_ip), issue_time(NAN), result(r) {
  }
  void fail(ostream &os, float sim_time) {
    os << "Ping failed\n";
  }

  void operator() (ostream &os, const EventQueue::Entry_base &event_entry) {
    check_event();
    cerr << "PingOperation(" << router->router_id << "@" << event_entry.curr_time << ")";
    cerr << "RTT is " << (event_entry.curr_time - issue_time) << "\n";
    result->set(event_entry.curr_time - issue_time);
  }
  void sim_do(uint32_t target_ip);
};

struct PingEcho : IPContinuation {
  Ping caller;
  PingEcho(const Ping &caller, uint32_t exec_ip) :
    IPContinuation(caller.sim_ctx, caller.topo, exec_ip, INVALID_ADDR),
    caller(caller) { }

  void fail(ostream &os, float sim_time) {
    os << "PingEcho failed\n";
  }

  void operator() (ostream &os, const EventQueue::Entry_base &event_entry) {
    check_event();
    cerr << "PingEcho(" << router->router_id << "@" << event_entry.curr_time << ")";
    // Schedule the caller's response
    issue_reliably(exec_ip, caller);
  }
};

void Ping::sim_do(uint32_t dest_ip) {
  issue_time = sim_ctx->sim_time;
  issue_reliably(exec_ip, PingEcho(*this, dest_ip));
}

PingResult *sim_ping(EventQueue *sim_ctx, Topology *topo,
	      uint32_t source_ip, uint32_t target_ip) {
  cerr << "Sending ping from " << source_ip << " to " << target_ip << "\n";
  PingResult *res = new PingResult;
  // Ping is running on source_ip ; expects to have been called from dest_ip
  Ping(sim_ctx, topo, source_ip, INVALID_ADDR, res).sim_do(target_ip);
  return res;
}

void test_force_disconnect(Topology *topo) {
  cerr << "Testing force disconnect\n";
  // - Compute shortest path tree
  // - Delete a link, within the shortest path tree, from the original graph
  // - The link should not be present in any of the decomposition graphs
  // (( Might need a helper function that translates descriptors of different graphs ))
  // - Recompute shortest path. This new tree should not use the link.
}

void test_conversions(void) {
  cerr << "Testing conversions and helper functions\n";
  int test[] = { -100, 10, -20, 300 };
  for(int i=0; i < 4; i++) {
    int id1 = test[i];
    int ip = ROUTERID_TO_IP(test[i]);
    int id2 = IP_TO_ROUTERID(ip);
    cerr << id1 << " => " << ip << " => " << id2 << "\n";
    assert(id1 == id2);
  }
}

// void upcall(xxx);

struct TriggerTest {
  NQ_Sim_TSpaceServer::TriggerKey key;
  NQ_Sim_TSpaceServer::TriggerClient client;
};
vector<TriggerTest> added_triggers;

void add_test_triggers(Topology *topo, EventQueue *sim_ctx, int *counter,
		       int simulation_seed, string test_spec) {
  // This experiment is tuned for simulation seed 100 & these test files
  assert(simulation_seed == 100 && 
	 test_spec == "/home/ashieh/nexus-files/rocketfuel/2002/rocket/1755-patched.cch "
	 "/home/ashieh/nexus-files/rocketfuel/2002/weights/1755/latencies.intra");
  *counter = 0;
  cerr << "ADD DOES NOTHING\n";
  return;
// 65483
  // TriggerClient(xxx)
  for(Topology::POPInfoMap::iterator 
	j = topo->pop_info_map.begin();
      j != topo->pop_info_map.end(); ++j) {
    assert(0);
  }
}

void remove_test_triggers(Topology *topo) {
  for(vector<TriggerTest>::iterator 
	i = added_triggers.begin();
      i != added_triggers.end(); i++) {
    for(Topology::POPInfoMap::iterator 
	  j = topo->pop_info_map.begin();
	j != topo->pop_info_map.end(); ++j) {
      j->second.nq_sim_server->delete_trigger(i->key, i->client);
    }
  }
}
