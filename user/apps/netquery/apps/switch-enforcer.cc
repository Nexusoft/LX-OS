#include <iostream>
#include <set>
#include <algorithm>
#include <fstream>

#include <pthread.h>
#include <getopt.h>
#include "switch-nq.hh"

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <nq/site.hh>

#include "ssl.hh"

const char *root_ca_name = "/C=US/ST=New York/L=Ithaca/O=Cornell University Nexus/OU=NONE/CN=Nexus Vetting CA";
char *root_ca_pem;

enum Host_Policy {
  ACCEPT_ALL,
  ACCEPT_TPM,
  REJECT_ALL,
};

Host_Policy g_host_policy = ACCEPT_TPM;

enum TCP_Policy {
  TCP_ACCEPT_ALL,
  TCP_IGNORE_ONE,
};

uint32_t g_blacklisted_address = INADDR_NONE;
TCP_Policy g_TCP_policy = TCP_ACCEPT_ALL;

using namespace std;

typedef ExtRef<T_CompositeElement> SwitchRef;

struct SwitchRefLess {
  bool operator() (const SwitchRef &l, const SwitchRef &r) const {
    return l.tid < r.tid;
  }
};

typedef set<SwitchRef, SwitchRefLess> SwitchSet;
typedef vector< SwitchRef > SwitchVector;
SwitchSet curr_switches;

NQ_Trigger_Description default_trigger_template;

NQ_Host data_home;
NQ_Principal *&enforcer_principal = switch_owner;
NQ_Tuple switch_enforcer_tid;

static int switch_index_change(NQ_Transaction t_id, NQ_Trigger_Description *trigger, 
			NQ_Trigger_Upcall_Type type, int arg, void *userdata);
static int switch_change(NQ_Transaction t_id, NQ_Trigger_Description *trigger,
			 NQ_Trigger_Upcall_Type type, int arg, void *userdata);

struct SwitchTriggerContext : DependencyTriggerContext {
  pthread_mutex_t mutex;
  SwitchRef ref;
  vector<NQ_Trigger> triggers;

  enum State {
    ACTIVE,
    INACTIVE, // a new trigger has been installed; ignore all further triggers
  } state;
  SwitchTriggerContext(Transaction &t, const SwitchRef &r) : 
    ref(r), state(ACTIVE) {
    mutex = ((pthread_mutex_t)PTHREAD_ERRORCHECK_MUTEX_INITIALIZER_NP);
  }
};

struct SwitchIndexTriggerContext : DependencyTriggerContext {
  pthread_mutex_t mutex;
  SwitchSet new_set;

  enum State {
    ACTIVE,
    INACTIVE, // a new trigger has been installed; ignore all further triggers
  } state;
  SwitchIndexTriggerContext(Transaction &t) : 
    state(ACTIVE) {
    mutex = ((pthread_mutex_t)PTHREAD_ERRORCHECK_MUTEX_INITIALIZER_NP);
  }
};

void SwitchSet_from_index(Transaction *t, SwitchSet *output) {
  T_Site *site = g_site_ref.load(*t);
  output->clear();
  size_t i;

  for(i=0; i < site->switches.size(); i++) {
    output->insert(ExtRef<T_CompositeElement>(site->switches[i].load().load()->get_tid()));
  }
  cerr << "index size is " << site->switches.size() << "\n";
}

template <typename F>
void for_each(Transaction *t, const SwitchSet *switch_set, F fn) {
  int count = 0;
  for(SwitchSet::const_iterator i = switch_set->begin();
      i != switch_set->end(); i++, count++) {
    fn(t, *i);
    cerr << "[" << count << "]";
  }
}

template <typename A, typename F>
bool check_all(Transaction *t, bool auto_add, const A *switch_aggr, F fn) {
  for(typename A::const_iterator i = switch_aggr->begin();
      i != switch_aggr->end(); i++) {

    const SwitchRef &s_ref = *i;
    if(s_ref.tid == NQ_uuid_null) {
      cerr << "got null in check_all\n";
      continue;
    }

    if(!fn(t, s_ref, auto_add)) {
      return false;
    }
  }
  return true;
}

ostream &operator<<(ostream &os, T_TCPFlowEntry &flow) {
  NQ_Host src;
  NQ_Host dst;
  src.addr = flow.saddr;
  src.port = ntohs(flow.sport);
  dst.addr = flow.daddr;
  dst.port = ntohs(flow.dport);
  os << "[" << src << " => " << dst << "]";
  return os;
}

static bool check_switch_helper(Transaction *t, Switch *s_obj) {
  // should accept all switches that have no enabled ports
  for(size_t i=0; i < s_obj->interfaces.size(); i++) {
    T_Interface *interface = s_obj->interfaces[i];
    if(interface->external_connection != NULL) {
      T_CompositeElement *peer;
      peer = interface->external_connection.load()->container;
      cerr << "Found a peer connected to a switch port!\n";
      switch(g_host_policy) {
      case ACCEPT_ALL:
	// check next one
	continue;
      case ACCEPT_TPM: {
	cerr << "TPM cert len = " << peer->certificate_chain.size() << "\n";
	T_X509 *t_x509 = NULL;
	if(peer->certificate_chain.size() >= 1) {
	  t_x509 = peer->certificate_chain[peer->certificate_chain.size() - 1].load().load();
	}
	if(t_x509 == NULL) {
	  cerr << "bad chain\n";
	  return false;
	}
	string pem = t_x509->val;

	// cerr << "Pem =\n" << pem << "\n";
	// Compare entire certificate PEM
	// Signature verification is done by switchd
	if(strcmp(root_ca_pem, pem.c_str()) != 0) {
	  cerr << "Root CA mismatch " << (int)strlen(root_ca_pem) << "," << strlen(pem.c_str()) << ")!\n";
	  return false;
	}
	
	cerr << "Root CA match (" << strlen(root_ca_pem) << "," << strlen(pem.c_str()) << ")!\n";
	cerr << "XXX Need to verify full certificate chain\n";

	// convert peer into a host
	cerr << "Checking process list of host " << peer->tid << "\n";
	Host new_host(*t, peer->tid);
	bool found = false;
	cerr << "Process list len = " << new_host.process_list->elems.size() << "\n";
	for(size_t i=0; i < new_host.process_list->elems.size(); i++) {
	  T_Process *process = new_host.process_list->elems[i].load();
	  cerr << "Process [" << i << "]: " << process->name.load() << "\n";
	  if(process->name.load() == "virus-check") {
	    found = true;
	    break;
	  }
	}
	if(!found) {
	  cerr << "Could not find virus scan process, rejecting\n";
	  return false;
	}
	cerr << "Found virus scan process, continuing onto the next switch/interface\n";
	continue;
      }
      case REJECT_ALL:
	return false;
      default:
	assert(0);
      }
    }
  }
  if(s_obj->firewall_table != NULL) {
    T_Vector< Ref<T_TCPFlowEntry> > &table = s_obj->firewall_table->entries;
    cerr << "Checking firewall table\n";
    cerr << "XXX slow algorithm, " << table.size() << " entries\n";
    // use ref here to make overloaded [] syntax easier to follow
    for(size_t i=0; i < table.size() ; i++) {
      T_TCPFlowEntry *flow = table[i].load();
      cerr << "[" << i << "]: " << *flow << "\n";
      switch(g_TCP_policy) {
      case TCP_IGNORE_ONE:
	if( flow->daddr == g_blacklisted_address || 
	    flow->saddr == g_blacklisted_address ) {
	  cerr << "Blacklisted address, rejecting tuplespace update!!!\n";
	  return false;
	}
	break;
      case TCP_ACCEPT_ALL:
	break;
      default:
	assert(0);
      }
    }
  }
  cerr << "****** Done checking switch. Everything good. Allow state change! *****\n";
  return true;
}

void add_annotations(const SwitchRef &s_ref) {
  Transaction t(trust_all, trust_attrval_all, data_home, enforcer_principal);
  // add enforcement annotation
  Switch *s_obj = new Switch(t, s_ref.tid);
  T_PolicyEnforcer *enforcer = dynamic_cast<T_PolicyEnforcer *>(t.get_tuple_shadow(switch_enforcer_tid));
  if(enforcer == NULL) {
    cerr << "Could not load enforcer object from tuplespace\n";
    exit(-1);
  }
  cerr << "Adding enforcement annotations to " << s_obj->composite_element->tid;
  cerr << " " << " enforcer is " << enforcer->actor.load()->tid << ", entity is " << enforcer->actor.load()->entity.load()->tid << "\n";

  cerr << "Real policy write\n";
  s_obj->composite_element->policy_enforced_by = enforcer->actor;
  t.commit();
}

template <typename A>
void add_annotations_to_all(const A *switch_set) {
  for(typename A::const_iterator i = switch_set->begin();
      i != switch_set->end();
      i++) {
    add_annotations(*i);
  }
}

bool check_switch(Transaction *t, const SwitchRef &s_ref, bool auto_add_triggers) {
  int start_pos;
  start_pos = t->get_op_log_size();
  Switch *s_obj = new Switch(*t, s_ref.tid);
  bool rv = check_switch_helper(t, s_obj);

  if(auto_add_triggers) {
    cerr << "Starting switch trigger log at " << start_pos << "\n";
    t->set_dependency_triggers(&default_trigger_template, switch_change, 
			       new SwitchTriggerContext(*t, s_ref), start_pos);
  }
  return rv;
}

#define OPT_TCP_IGNORE_ONE (256)
struct option longopts[] = {
  { "tcp-ignore-one" , 1, NULL, OPT_TCP_IGNORE_ONE },  
  { 0 },
};

string l2_policy_as_string() {
  switch(g_host_policy) {
  case ACCEPT_ALL:
    return "ACCEPT_ALL";
  case REJECT_ALL:
    return "REJECT_ALL";
  case ACCEPT_TPM:
    return "ACCEPT_TPM";
  default:
    return "UNKNOWN";
  }
}
string l3_policy_as_string() {
  switch(g_TCP_policy) {
  case TCP_ACCEPT_ALL:
    return "ACCEPT_ALL";
  case TCP_IGNORE_ONE:
    return "IGNORE_ONE";
  default:
    return "UNKNOWN";
  }
}

int main(int argc, char **argv) {
  memset(&default_trigger_template, 0, sizeof(default_trigger_template));
  default_trigger_template.type = NQ_TRIGGER_VALUECHANGED;
  //default_trigger_template.upcall_type = NQ_TRIGGER_UPCALL_SYNC_VERDICT;
  default_trigger_template.upcall_type = NQ_TRIGGER_UPCALL_SYNC_VETO;

  ifstream ifs("/nfs/nexusca.crt");
  DataBuffer root_ca;
  get_all_file_data(ifs, root_ca);
  root_ca.push_back('\0');
  root_ca_pem = strdup((char *)vector_as_ptr(root_ca));

  setvbuf(stdout, NULL, _IOLBF, 0);

  bool set_host = false;

  memset(&data_home.addr, 0, sizeof(data_home.addr));
  data_home.port = NQ_NET_DEFAULT_PORT;

  int opt;
  int longindex;
  while( (opt = getopt_long(argc, argv, "h:p:art", longopts, &longindex)) != -1 ) {
    switch(opt) {
    case 'h':
      data_home.addr = inet_addr(optarg);
      set_host = true;
      break;
    case 'p':
      data_home.port = atoi(optarg);
      break;
    case 'a':
      g_host_policy = ACCEPT_ALL;
      break;
    case 'r':
      g_host_policy = REJECT_ALL;
      break;
    case 't':
      g_host_policy = ACCEPT_TPM;
      break;
    case OPT_TCP_IGNORE_ONE:
      g_TCP_policy = TCP_IGNORE_ONE;
      g_blacklisted_address = inet_addr(optarg);
      cerr << "TCP ignore policy, dropping everything to/from " << IP_Address_to_string(g_blacklisted_address) << "\n";
      break;
    default:
      printf("Unknown option %d '%c'\n", opt, opt);
      exit(-1);
    }
  }
  printf("Enforcer policy: ");
  switch(g_host_policy) {
    case ACCEPT_ALL:
      printf("===========\nAccept all mode\n===========\n");
      break;
    case REJECT_ALL:
      printf("===========\nReject all mode\n===========\n");
      break;
    case ACCEPT_TPM:
      printf("===========\nAccept only TPM mode\n===========\n");
      break;
  }
  if(!set_host) {
    cerr << "Host not set!\n";
    exit(-1);
  }

  switch_nq_init(0, data_home, &NQ_default_owner);

  Transaction t0(trust_all, trust_attrval_all, data_home, enforcer_principal);
  cerr << "Creating policy enforcer\n";
  T_PolicyEnforcer enforcer(t0);
  enforcer.tspace_create();

  // initialization
  enforcer.key = string("Linux-") + itos(getpid());
  enforcer.name = "Switch enforcer";
  T_Actor *actor = enforcer.actor;
  actor->principal = (Principal) *enforcer_principal;

  // set policy
  enforcer.l2_policy = l2_policy_as_string();
  enforcer.l3_policy = l3_policy_as_string();

  switch_enforcer_tid = enforcer.tid;
  t0.commit();

  cerr << "Doing initial check and trigger set creation\n";
  // Need to run as "default_owner" to get trigger to deliver to us
  Transaction t(trust_all, trust_attrval_all, data_home, enforcer_principal);
  t.restore_logging();
  int start_pos;
  start_pos = t.get_op_log_size();

  SwitchSet_from_index(&t, &curr_switches);
  t.set_dependency_triggers(&default_trigger_template, switch_index_change, 
			    new SwitchIndexTriggerContext(t), start_pos);

  add_annotations_to_all(&curr_switches);
  if(!check_all(&t, true, &curr_switches, check_switch)) {
    cerr << "Switch already in disallowed state!\n";
    exit(-1);
  }

  cerr << "tid0: " << t.transaction << "\n";

  t.commit();

  while(1) {
    cerr << "Sleeping to wait for events\n";
    sleep(60);
  }
  return 0;
}

enum UpdateState {
  UPDATE_REJECTED,
  UPDATE_ACCEPTED,
};
UpdateState last_state;

static void compute_switch_sets(Transaction *t, bool auto_add, SwitchSet *new_set, SwitchVector *added_switches) {
  // Allow only one state change at a time
  // The mutex is locked here, and released once the verdict
  // update the index
  int start_pos;
  start_pos = t->get_op_log_size();
  SwitchSet_from_index(t, new_set);
  // Add triggers on new elements
  set_difference(new_set->begin(), new_set->end(), 
		 curr_switches.begin(), curr_switches.end(),
		 std::back_insert_iterator< SwitchVector >(*added_switches) );

  if(auto_add) {
    t->set_dependency_triggers(&default_trigger_template, switch_index_change,
			      new SwitchIndexTriggerContext(*t), start_pos);
  }
}

static int switch_index_change(NQ_Transaction t_id, NQ_Trigger_Description *trigger, 
			       NQ_Trigger_Upcall_Type type, int arg, void *userdata) {
  switch(type) {
  case NQ_TRIGGER_UPCALL_SYNC_VETO: {
    cerr << "Switch index change veto\n";
    cerr << "Got switch index change\n";

    SwitchIndexTriggerContext *ctx = (SwitchIndexTriggerContext *) userdata;
    pthread_mutex_lock(&ctx->mutex);
    if(ctx->state != SwitchIndexTriggerContext::ACTIVE) {
      cerr << "Obsolete context\n";
      pthread_mutex_unlock(&ctx->mutex);
      return 1;
    }

    Transaction t_read(t_id, trust_all, trust_attrval_all, data_home, enforcer_principal);
    SwitchSet new_set;
    SwitchVector added_switches;
    compute_switch_sets(&t_read, false, &new_set, &added_switches);

    add_annotations_to_all(&added_switches);

    int rv = 0;
    if( check_all(&t_read, false, &added_switches, check_switch) ) {
      last_state = UPDATE_ACCEPTED;
      rv = 1;
    } else {
      cerr << "New switch in bad configuration\n";
      // no commit phase
      last_state = UPDATE_REJECTED;
      rv = 0;
    }
    pthread_mutex_unlock(&ctx->mutex);
    return rv;
  }
  case NQ_TRIGGER_UPCALL_SYNC_VERDICT: {
    cerr << "Switch index change upcall sync verdict: " << arg << "\n";
    if(arg) {
      cerr << "Disabling previous trigger context\n";
      SwitchIndexTriggerContext *ctx = (SwitchIndexTriggerContext *) userdata;
      pthread_mutex_lock(&ctx->mutex);

      if(ctx->state == SwitchIndexTriggerContext::ACTIVE) {
	ctx->state = SwitchIndexTriggerContext::INACTIVE;
	Transaction t_read(t_id, trust_all, trust_attrval_all, data_home, enforcer_principal);
	t_read.restore_logging();

	SwitchSet new_set;
	SwitchVector added_switches;
	compute_switch_sets(&t_read, true, &new_set, &added_switches);
	// check all again. we do this to get side effect of adding the triggers
	check_all(&t_read, true, &added_switches, check_switch);
      }
      pthread_mutex_unlock(&ctx->mutex);
    }
    return 0;
  }
  default: {
    cerr << "Switch change " << type << "\n";
    return 0;
  }
  }
}

static int switch_change(NQ_Transaction t_id, NQ_Trigger_Description *trigger, 
			 NQ_Trigger_Upcall_Type type, int arg, void *userdata) {
  switch(type) {
  case NQ_TRIGGER_UPCALL_SYNC_VETO: {
    // trigger->tuple is not the top level of the switch
    cerr << "Switch change veto\n";
    SwitchTriggerContext *ctx = (SwitchTriggerContext *)userdata;
    SwitchRef s_ref = ctx->ref;
    Transaction t(t_id, trust_all, trust_attrval_all, data_home, enforcer_principal);
    cerr << "Checking new switch state\n";
    if(!check_switch(&t, s_ref, false)) {
      cerr << "Rejecting new switch\n";
      return 0;
    } else {
      cerr << "Accepting new switch\n";
      return 1;
    }
    // Don't modify the transaction
  }
  case NQ_TRIGGER_UPCALL_SYNC_VERDICT: {
    // Create new triggers, and schedule deletion of existing
    // triggers. We can't delete the triggers now due to the pending
    // transaction.

    // It is OK to ignore all future triggers. The enforcer will be
    // correct as long as
    cerr << "Switch change verdict: " << arg << "\n";

    SwitchTriggerContext *ctx = (SwitchTriggerContext *)userdata;
    pthread_mutex_lock(&ctx->mutex);
    if(ctx->state == SwitchTriggerContext::ACTIVE) {
      if(arg) {
	// Change to switch. Create a new set of triggers in case
	// there are new ports, etc.
	cerr << "Adding new triggers for modified switch\n";
	cerr << "XXX Need to get rid of old triggers on switch\n";

	SwitchRef s_ref = ctx->ref;
	Transaction t_read(t_id, trust_all, trust_attrval_all, data_home, enforcer_principal);
	t_read.restore_logging();

	// Check the switch just to get side effect for the attributes that are read
	check_switch(&t_read, s_ref, true);
	ctx->state = SwitchTriggerContext::INACTIVE;
      }
    }
    pthread_mutex_unlock(&ctx->mutex);
    return 0;
  }
  default: {
    cerr << "Switch change " << type << "\n";
    return 0;
  }
  }
}
