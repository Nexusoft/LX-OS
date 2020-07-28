#include <iostream>
#include <string>
#include <sys/types.h>
#include <sys/socket.h>
#include <ext/hash_map>
#include <linux/un.h>
#include "fib-update-protocol.hh"
#include "router.hh"
#include <nq/transaction.hh>
#include <nq/uuid.h>
#include <nq/site.hh>
#include <signal.h>
#include <map>

#define MAX(X,Y) (((X) > (Y)) ? (X) : (Y))

bool use_batch = true;
bool use_one_transaction = true;

using namespace __gnu_cxx;
using namespace std;

NQ_Principal *g_flow_principal;
static Transaction *global_transaction;

struct NQ_ServerInfo {
  NQ_Host host;
  Transaction *transaction;
  NQ_Principal *principal;
  NQ_ServerInfo() : transaction(NULL) { }

  void init(const NQ_Host &h) {
    host = h;
    principal = NQ_get_home_principal(&host);
    transaction = NULL;
  }
  Transaction **_get_transaction(void) {
    if(use_one_transaction) {
      return &global_transaction;
    } else {
      return &transaction;
    }
  }
  Transaction *get_transaction(void) {
    Transaction **t = _get_transaction();
    if(*t == NULL) {
      cerr << doubleTime() << ": Transaction opened @" << host << "\n";
      *t = new Transaction(trust_all, trust_attrval_all, principal->home, principal, use_batch);
    }
    return *t;
  }
  bool has_pending_transaction(void) {
    Transaction **t = _get_transaction();
    return *t != NULL;
  }
  void finish_transaction(void) {
    Transaction **t = _get_transaction();
    if(*t != NULL) {
      (*t)->commit();
      cerr << doubleTime() << ": Transaction committed @" << host << "\n";
      delete *t;
      *t = NULL;
    }
  }
};

typedef hash_map< NQ_Host, NQ_ServerInfo, NQ_Host_hash, NQ_Host_equals> ServerInfoMap;
ServerInfoMap nq_server_info;

bool loaded_topo = false;

struct Topology {
  struct Router {
    int router_id;
    NQ_Tuple composite_tid;
    NQ_Tuple switch_fabric_tid;
    NQ_ServerInfo *home_info;

    Router(int _router_id, NQ_Tuple _tid) : router_id(_router_id), composite_tid(_tid) {
      home_info = &nq_server_info[composite_tid.home];
      home_info->init(composite_tid.home);

      Transaction *t = new Transaction(trust_all, trust_attrval_all, home_info->principal->home, home_info->principal, false);
      ::Router *r = new ::Router(*t, composite_tid);
      assert(r != NULL);
      switch_fabric_tid = r->fabric->tid;
      t->commit();
      // cerr << "Loaded switch fabric tid " << switch_fabric_tid << "\n";
      delete r;

      assert(NQ_Host_eq(composite_tid.home, switch_fabric_tid.home));
    }

    int send_trie_op(
                     NQ_Attribute_Operation operation, const ForwardingEntry &entry,
                     bool include_tid, NQ_Tuple interface_tid) {
      Transaction *t = home_info->get_transaction();
      NQ_Attribute_Name *fabric_attr_name = 
        NQ_Attribute_Name_alloc(&home_info->host,
                                NQ_ATTRIBUTE_TRIE,
                                "SwitchFabric.forwarding_table");

      std::vector<unsigned char> data;
      data.reserve(sizeof(NQ_Trie_Index_Args) + sizeof(NQ_Tuple));
      NQ_Trie_Index_Args args;
      args.prefix = entry.ip_prefix;
      args.prefix_len = entry.ip_prefix_len;
      vector_push(data, args);
      if(include_tid) {
        tspace_marshall(interface_tid, data);
      }
      unsigned char *buf = vector_as_ptr<unsigned char>(data);
      char *buf1 = (char *)buf;
      int vallen = data.size();
      int rv = t->attribute_operate(fabric_attr_name, switch_fabric_tid, 
                                    operation,
                                    &buf1, &vallen, NULL);
      buf = (unsigned char *)buf1;
      NQ_Attribute_Name_free(fabric_attr_name);
      return rv;
    }
  };
  struct RouterPtr {
    Router *_;
    RouterPtr() : _(NULL) { }
  };
  typedef map<int, RouterPtr> RouterMap;
  RouterMap router_map;

  void send_update(int router_id, const vector<FIBUpdateTID> &additions,
                   const vector<FIBUpdateTID> &deletions) {
    Router *router = get_router(router_id);
    assert(router != NULL);

    for(size_t i=0; i < additions.size(); i++) {
      int rv = router->send_trie_op(NQ_OPERATION_UPDATE, additions[i].entry,
                             true, additions[i].tid);
      if(rv != 0) {
        cerr << "error updating forwarding table!\n";
      }
    }

    for(size_t i=0; i < deletions.size(); i++) {
      int rv = router->send_trie_op(NQ_OPERATION_REMOVE, deletions[i].entry,
                             false, NQ_uuid_null);
      if(rv != 0) {
        cerr << "error updating forwarding table!\n";
      }
    }
  }

  Router *get_router(int router_id) {
    RouterMap::iterator i;
    if((i = router_map.find(router_id)) == router_map.end()) {
      return NULL;
    }
    return i->second._;
  }
  void add_router(int router_id, const NQ_Tuple &tid) {
    if(get_router(router_id) != NULL) {
      cerr << "Router already added!\n";
      exit(-1);
    }
    router_map[router_id]._ = new Router(router_id, tid);
  }
} *topology;

void load_from_tuplespace(const string &tid_ofname) {
  cerr << "loading from tuplespace '" << tid_ofname << "'\n";

  topology = new Topology();
  EmulatorRouters routers;
  load_tids_from_emulator(tid_ofname, &routers);
  for(EmulatorRouters::iterator i = routers.begin(); i != routers.end(); i++) {
    int router_id = i->first;
    Router_TIDs *r_tid = i->second;
#if 0
    SimRouter *router = router_map[router_id];
    router->init_tspace_refs(new Router(*output_map[router->location], r_tid->tid));
#endif
    topology->add_router(router_id, r_tid->tid);
  }
  cerr << "Done loading from tuplespace\n";
}

void sig_break(int v) {
  cerr << "Got break\n";
  NQ_dump_stats();
  cout.flush();
  exit(0);
}

int main(int argc, char **argv) {
  signal(SIGINT, sig_break);
  atexit(NQ_dump_stats);

  if(argc <= 1) {
    printf("need to pass in socket location\n");
    exit(-1);
  }
  NQ_init(0);
  NQ_cpp_lib_init();
  string sock_fname = argv[1];

  if(FIBUpdate_init_sock(sock_fname) != 0) {
    cerr << "Could not create socket in updater\n";
    exit(-1);
  }

  if (listen(fib_sock, 5) == -1) {
    perror("listen");
    exit(1);
  }

  cerr << "Use batch : "  << use_batch << "\n";
  cerr << "Use one txn : "  << use_one_transaction << "\n";

  while(1) {
    int client_sock;
    struct sockaddr_un remote;
    socklen_t len = sizeof(remote);
    if ((client_sock = accept(fib_sock, (struct sockaddr *)&remote, &len)) == -1) {
      perror("accept");
      exit(1);
    }
    cerr << "Accepted client\n";
    while(1) {
      FIBUpdate_Request header;
      int rv = FIBUpdate_recv_all(client_sock, &header, sizeof(header));
      if(rv == -1) {
        cerr << "otehr side gone\n";
        exit(-1);
      }
      int result = 0;
      if(true) {
        cerr << "Got request " << header.type << "\n";
      switch(header.type) {
      case LOADSPEC: {
        struct LoadSpec spec;
        FIBUpdate_recv_all(client_sock, &spec, sizeof(spec));
        string fname(spec.topo_fname);
        cerr << "Loading tids from " << fname << "\n";
        load_from_tuplespace(fname);
        break;
      }
      case UPDATEFIB: {
        struct UpdateSpec spec;
        FIBUpdate_recv_all(client_sock, &spec, sizeof(spec));
        cerr << "Got fib update " << spec.num_adds << " adds " << spec.num_dels << " dels\n";
        FIBUpdateTID ent;
        vector<FIBUpdateTID> additions, deletions;
        for(int i=0; i < spec.num_adds; i++) {
          FIBUpdate_recv_all(client_sock, &ent, sizeof(ent));
          additions.push_back(ent);
        }
        for(int i=0; i < spec.num_dels; i++) {
          FIBUpdate_recv_all(client_sock, &ent, sizeof(ent));
          deletions.push_back(ent);
        }
        topology->send_update(spec.router_id, additions, deletions);
        break;
      }
      case COMMITALL: {
        cerr << "Got commit all request\n";
        int num_commits = 0;
        for(ServerInfoMap::iterator i = nq_server_info.begin();
            i != nq_server_info.end(); i++) {
          NQ_ServerInfo *info = &i->second;
          if(info->has_pending_transaction()) {
            info->finish_transaction();
            num_commits++;
          }
        }
        cerr << "Did " << num_commits << " commits\n";
        break;
      }
      default:
        cerr << "invalid msg type " << header.type << "\n";
        exit(-1);
      }
      } else {
        cerr << "skipping all requests\n";
      }
      FIBUpdate_respond(client_sock, result, header.seqnum);
    }
  }
}
