#include <iostream>

using namespace std;

#include <nq/netquery.h>
#include <nq/transaction.hh>
#include <nq/net_elements.hh>
#include <nq/net.h>

#include "router.hh"

void start_net_client(void) {
  NQ_Net_set_localserver();
}

int main(int argc, char **argv) {
  int i;
  
  NQ_init(0);
  NQ_cpp_lib_init();

  start_net_client();

  NQ_Host host;
  host.addr = NQ_Net_get_localhost().addr; host.port = 9000;
  NQ_Principal *p = NQ_get_home_principal(&host);
  if(p == NULL) {
    cerr << "Could not load principal\n";
    exit(-1);
  }

  for(i = 1; i < 100; i++){
    printf("===================== %d =========================\n", i);
    Transaction *t = new Transaction(trust_all, trust_attrval_all, p);
    cerr << "Storing (recursive)\n";
    T_Interface *nic = new T_Interface(*t);
    nic->tspace_create();
    ExtRef<T_Interface> ref = ExtRefOf(nic);
  
    t->commit();
  
    cerr << "Commited\n";
  
    cerr << "Loading (recursive)\n";
    t = new Transaction(trust_all, trust_attrval_all, p);
    nic = ref.load(*t);
    cerr << "Got " << nic << "\n";
    t->commit();
    if(nic == NULL) {
      cerr << "Error!\n";
      exit(-1);
    } else {
      cerr << "Success!\n";
    }
  }
}
