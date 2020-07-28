#include <unistd.h>
#include <signal.h>
#include <iostream>
#include <openssl/evp.h>
#include <nq/net.h>
#include <nq/site.hh>
#include <nq/nexus_file_util.hh>
#include <nq/marshall.hh>

#include <fstream>

#include <map>
using namespace std;

#include "switch.hh"
#include "switch-nq.hh"
#include "ssl.hh"

NQ_UUID g_switch_tid;
NQ_UUID g_switch_fabric_tid;
IP_Address connect_addr;

extern int do_pingpong_check;

enum SwitchMode {
  SWITCH,
  CONNECT_ONLY,
};

struct SwitchTransitions {
  struct Transition {
    int m_old_state, m_new_state;
    inline Transition(int old_state, int new_state) :
      m_old_state(old_state), m_new_state(new_state) {
      // do nothing
    }
    bool operator<(const Transition &other) const {
      return m_old_state < other.m_old_state ||
	(m_old_state == other.m_old_state && 
	 m_new_state < other.m_new_state);
    }
  };

  typedef void (SwitchPort::*Action)(void);
  typedef map<Transition, Action> TransitionFunction;
  
  TransitionFunction m_transition_function;
  inline SwitchTransitions() {
    m_transition_function[Transition(SwitchPort::GETTING_IP, SwitchPort::HAS_IP)] =
      &SwitchPort::activate;
    m_transition_function[Transition(SwitchPort::HAS_IP, SwitchPort::GETTING_IP)] = 
      &SwitchPort::deactivate;
  }

  void apply(int old_state, int new_state, SwitchPort *ctx) {
    TransitionFunction::iterator i = 
      m_transition_function.find(Transition(old_state, new_state));
    if( i != m_transition_function.end() ) {
      (ctx->*(i->second))();
    }
  }
};

SwitchTransitions switch_transitions;

void SwitchPort::new_state(State next_state) {
  State old_state = m_switch_state;
  m_switch_state = next_state;
  cerr << "State change of " << this << ": " << old_state << " => " << next_state << "\n";
  switch_transitions.apply(old_state, next_state, this);
}

void sig_break(int v) {
  cerr << "Got break\n";
  exit(0);
}

struct PortSpec {
  string dev_name;
  PortSpec(const string &s) : dev_name(s) { }
};

int main(int argc, char **argv) {
  int opt;
  extern int show_rpc_traffic;
  show_rpc_traffic = 0;

  NQ_Host home_real, *home = &home_real;
  bool set_host = false;

  memset(&home->addr, 0, sizeof(home->addr));
  home->port = NQ_NET_DEFAULT_PORT;
  SwitchMode mode = SWITCH;

  vector<PortSpec> port_specs;

  while( (opt = getopt(argc, argv, "nt:h:p:c:P:fFd:")) != -1 ) {
    switch(opt) {
    case 'n':
      g_test_nq = true;
      break;
    case 't':
      g_test_ssl = true;
      g_l2secd_server_port = atoi(optarg);
      cerr << "Testing ssl, server port is " << g_l2secd_server_port << "\n";
      break;
    case 'h':
      home->addr = inet_addr(optarg);
      set_host = true;
      break;
    case 'p':
      home->port = atoi(optarg);
      cerr << "Set port " << home->port << "\n";
      break;
    case 'c':
      cerr << "Testing connect to client mode\n";
      mode = CONNECT_ONLY;
      connect_addr = ntohl(inet_addr(optarg));
      g_test_handshake = true;
      break;
    case 'P':
      g_l2secd_server_port = atoi(optarg);
      break;
    case 'f':
      g_use_tcp_firewall = true;
      break;
    case 'F':
      g_use_tcp_firewall = true;
      g_test_tcp_forward = true;
      cerr << "Testing TCP forwarding\n";
      break;
    case 'd':
      // do sanity check to make sure no devs have been repeated
      for(size_t i=0; i < port_specs.size(); i++) {
	if(port_specs[i].dev_name == string(optarg)) {
	  cerr << "Device \"" << optarg << "\" repeated\n";
	  exit(-1);
	}
      }
      port_specs.push_back(PortSpec(optarg));
      break;
    default:
      printf("Unknown option %d '%c'\n", opt, opt);
      exit(-1);
    }
  }
  OpenSSL_add_all_algorithms();
  OpenSSL_add_all_ciphers();
  OpenSSL_add_all_digests();
  ssl_init();

  if(!set_host) {
    home = NULL;
  }
  switch_nq_init(NQ_PORT_ANY, *home);

  cerr << "Creating switch entry\n";
  Transaction *t = new Transaction(trust_all, trust_attrval_all, switch_owner->home, switch_owner);
  cerr << "xxx not removing old switch entry\n";
  T_Site *site = g_site_ref.load(*t);
  // Port 0 = down, port 1 = up
  Switch *new_switch = new Switch(*t, port_specs.size() + 1);
  site->switches.push_back(Ref<T_CompositeElement>(new_switch->composite_element));
  g_switch_tid = new_switch->composite_element->tid;
  g_switch_fabric_tid = new_switch->fabric->tid;

  cerr << "New switch tid " << g_switch_tid << 
    ", vec size is " << site->switches.size() << "\n";

  new_switch->add_firewall();

  if(argc - optind < 1) {
    cerr << "not enough arguments for external dev name\n";
    exit(-1);
  }
  const char *ext_name = argv[optind];
  EtherDevBase *ext_dev;
  cerr << "Using external device " << ext_name << "\n";
  if(string(ext_name) == string("TAP")) {
    cerr << "Creating TapDev\n";
    ext_dev = new TapDev();
  } else {
    cerr << "Creating EtherDev\n";
    ext_dev = new EtherDev(string(ext_name));
  }
  ext_dev->set_promisc(true);

  {
    T_Interface *interface = new_switch->get_port(0);
    g_switch_ports.push_back(
			     new ExternalPort(
					      interface->tid,
					      new_switch->firewall_table->tid,
					      (int)0,
					      ext_dev
					      ));
    interface->name =  interface->name.load() + "-" + ext_name;
  }

  for(size_t i = 0; i < port_specs.size(); i++) {
    EtherDev *int_dev = new EtherDev(port_specs[i].dev_name);
    int_dev->set_promisc(true);
    int index = i+1;
    cerr << "Adding " << port_specs[i].dev_name << " at port " << index << "\n";
    T_Interface *interface = new_switch->get_port(index);
    g_switch_ports.push_back(
	     new ClientPort(
			    interface->tid,
			    new_switch->firewall_table->tid,
			    index, 
			    int_dev
			    ));
    interface->name =  interface->name.load() + "-" + port_specs[i].dev_name;
  }
  t->commit();
  cerr << "Done with commit\n";


  signal(SIGINT, sig_break);
  switch(mode) {
  case SWITCH:
    start_forwarding(argc - optind - 1, argv + optind + 1);
    break;
  case CONNECT_ONLY:
    start_connect_only();
    break;
  default:
    assert(0);
  }
  exit(0);
}
