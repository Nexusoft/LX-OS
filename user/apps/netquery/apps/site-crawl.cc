#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <nq/net.h>
#include <nq/uuid.h>
#include <nq/site.hh>
#include <nq/marshall.hh>
#include <iostream>
#include <fstream>

using namespace std;

ExtRef<T_Site> g_site_ref;

static bool trust_all(NQ_Tuple tid, KnownClass *obj_class) {
  return true;
}

bool trust_attrval_all(NQ_Attribute_Name *name, NQ_Tuple tid, NQ_Principal *principal) {
  return true;
}

int main(int argc, char **argv) {
  if(argc < 4) {
    printf("Usage: site-crawl <host> <port> <mode>\n");
    exit(-1);
  }
  NQ_init(NQ_PORT_ANY);
  NQ_cpp_lib_init();
  // NQ_Net_set_localserver();

  int mode;
  NQ_Host home;
  home.addr = inet_addr(argv[1]);
  home.port = atoi(argv[2]);
  mode = atoi(argv[3]);

  NQ_Principal *p2 = NQ_get_home_principal(&home);
  printf("Home ip: %08x:%d\n", htonl(p2->home.addr), p2->home.port);

  NQ_UUID site_tid= load_tid_from_file(string("/nfs/site.tid"));
  g_site_ref = ExtRef<T_Site>(site_tid);
  Transaction t(trust_all, trust_attrval_all, p2->home, p2);
  T_Site *site = g_site_ref.load(t);

  switch(mode) {
  case 0: {
    printf("Crawling from router index\n");
    for(size_t i=0; i < site->routers.size(); i++) {
      T_CompositeElement *comp = site->routers[i].load();
      Router *r = new Router(t, comp->tid);
      r->print(cout);
      cout << "================\n";
    }
    break;
  }
  default:
    printf("unknown mode %d\n", mode);
    exit(-1);
  }
  t.abort();
  exit(0);
}
