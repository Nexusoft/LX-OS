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
    printf("Usage: net-operator <host> <port>\n");
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
  
  NQ_publish_principal(&NQ_default_owner, "network-operator.principal");
  cout << ">>> Operator home principal: " << *p2 << "\n";
  cout << ">>> Operator principal: " << NQ_default_owner << "\n";

  ExtRef<T_Site> site_ref;
  NQ_UUID site_tid= load_tid_from_file(string("/nfs/site.tid"));
  site_ref = ExtRef<T_Site>(site_tid);

  // XXX why export 2x?
  NQ_publish_principal(&NQ_default_owner, "/nfs/net-owner.principal");

  Transaction t1(trust_all, trust_attrval_all, home, &NQ_default_owner);
  T_Organization *org = new T_Organization(t1);
  org->tspace_create();
  org->common_name = "Network Operator";
  org->principal = (Principal)NQ_default_owner;

  T_Site *site = site_ref.load(t1);

  for(size_t i=0; i < site->switches.size(); i++) {
    T_CompositeElement *comp = site->switches[i].load();
    comp->installed_by = org;
    cout << "Installed switch " << comp->tid << "\n";
    T_Actor *enforcer = comp->policy_enforced_by.load();
    if(enforcer != NULL) {
      cout << "Installed enforcer " << enforcer->tid << "\n";
      enforcer->installed_by = org;
    }
  }
  for(size_t i=0; i < site->routers.size(); i++) {
    T_CompositeElement *comp = site->routers[i].load();
    comp->installed_by = org;
    cout << "Installed router " << comp->tid << "\n";
  }

  t1.commit();

  exit(0);
}
