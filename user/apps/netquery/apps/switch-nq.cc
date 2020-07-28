#include <fstream>

using namespace std;

#include <nq/net.h>
#include <nq/site.hh>
#include <nq/nexus_file_util.hh>
#include <nq/marshall.hh>

#include "switch-nq.hh"

#include "ssl.hh"

ExtRef<T_Site> g_site_ref;

NQ_Principal *switch_owner;

void switch_nq_init(short server_port_num, NQ_Host home, NQ_Principal *principal) {
  NQ_init(server_port_num);
  NQ_cpp_lib_init();
  // NQ_Net_set_localserver();

  if(principal == NULL) {
    switch_owner = NQ_get_home_principal(&home);
  } else {
    switch_owner = principal;
  }
  NQ_publish_principal(switch_owner, NULL);

  ifstream ifs("/nfs/site.tid");
  if(!ifs.good()) {
    cerr << "Could not open site tid!\n";
    exit(-1);
  }
  NQ_UUID site_tid;
  DataBuffer all_data;

  get_all_file_data(ifs, all_data);
  CharVector_Iterator s = all_data.begin(), end = all_data.end();

  site_tid = *tspace_unmarshall(&site_tid, *(Transaction *)NULL, s, end);

  ifs.close();

  g_site_ref = ExtRef<T_Site>(site_tid);
  cerr << "Testing site ref\n";
  Transaction *t = new Transaction(trust_all, trust_attrval_all, home, switch_owner);
  T_Site *site = g_site_ref.load(*t);
  if(site == NULL) {
    cerr << "Could not load site root object!\n";
    cerr << "TID = " << site_tid << "\n";
    exit(-1);
  }
  t->abort();
  delete site;
}

bool trust_all(NQ_Tuple tid, KnownClass *obj_class) {
  return true;
}

bool trust_attrval_all(NQ_Attribute_Name *name, NQ_Tuple tid, NQ_Principal *principal) {
  return true;
}
