#include <nq/util.hh>
#include <nq/netquery.h>
#include <nq/policy.hh>
#include <nq/policy.hh>

#include <iostream>

using namespace std;

bool check_installed_by(T_Reference<T_Actor> *installed_by, NQ_Principal *installer) {
  NQ_Principal *installed_by_attributed_to = NULL;
  NQ_Principal *actor_principal = NULL, *actor_attributed_to = NULL;
  T_Actor *actor = NULL; 
  actor = installed_by->load(&installed_by_attributed_to);
  if(installed_by_attributed_to == NULL) {
    cerr << "no attribution info\n";
    return false;
  }
  if(actor == NULL) {
    cerr << "no installed_by info\n";
    return false;
  }
  // check: principal == actor->principal == installer
  actor_principal = (NQ_Principal *)actor->principal.load(&actor_attributed_to);
  if(actor_principal == NULL) {
    cerr << "No actor\n";
    return false;
  }
  if(actor_principal != actor_attributed_to) {
    cerr << "Warning: actor->principal not attributed to self\n";
    cerr << "Ignoring error\n";
    // return false;
  }
  if(installed_by_attributed_to != actor_principal) {
    cerr << "attributed to wrong source\n";
    return false;
  }
  if(actor_principal != installer) {
    cerr << "installed by wrong principal, wanted " << *actor << ", "
	 << " got " << *installed_by_attributed_to << "\n";
    return false;
  }
  return true;
}
