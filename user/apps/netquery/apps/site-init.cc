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

static bool trust_all(NQ_Tuple tid, KnownClass *obj_class) {
  return true;
}
bool trust_attrval_all(NQ_Attribute_Name *name, NQ_Tuple tid, NQ_Principal *principal) {
	  return true;
}

int main(int argc, char **argv) {
  if(argc < 3) {
    printf("Usage: site-init <host> <port>\n");
    exit(-1);
  }
  NQ_init(NQ_PORT_ANY);
  NQ_cpp_lib_init();
  // NQ_Net_set_localserver();

  NQ_Host home;
  home.addr = inet_addr(argv[1]);
  home.port = atoi(argv[2]);

  NQ_Principal *p2 = NQ_get_home_principal(&home);
  printf("Home ip: %08x:%d\n", htonl(p2->home.addr), p2->home.port);
  
  NQ_Tuple tid;
  ExtRef<T_Site> site_ref;
  Transaction *t1 = new Transaction(trust_all, trust_attrval_all, p2->home, p2);
  T_Site *site = new T_Site(*t1);
  site->tspace_create();
  tid = site->tid;
  site_ref = ExtRefOf(site);
  t1->commit();
  delete t1;

  ofstream ofs("/nfs/site.tid");
  file_marshall(tid, ofs);
  cerr << "Wrote tid " << tid << "\n";
  ofs.close();
  if(!ofs) {
    cerr << "Error writing tid!\n";
    exit(-1);
  }

  cerr << "Trying to load object\n";
  // use different principal. It should not matter.
  t1 = new Transaction(trust_all, trust_attrval_all, p2->home, p2);
  site = site_ref.load(*t1);
  printf("Sizes = %d, %d\n", (int) site->switches.size(), (int) site->routers.size());
  t1->abort();
  delete t1;
  if(site == NULL) {
    cerr << "Could not load object back!\n";
    exit(-1);
  }
  cerr << "Reloaded successfully\n";
  exit(0);
}
