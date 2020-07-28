#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <pthread.h>

#include "eventxx"
#include "switch.hh"

#include <nq/util.hh>
#include <nq/netquery.h>
#include <nq/policy.hh>
#include <nexus/l2sec.h>

#ifndef __LINUX__
extern "C" {
#include <nexus/Net.interface.h>
#include <nexus/env.h>
}
#endif

#include <openssl/ssl.h>
#include <iostream>

using namespace std;

static bool trust_all(NQ_Tuple tid, KnownClass *obj_class) {
  return true;
}

bool trust_attrval_all(NQ_Attribute_Name *name, NQ_Tuple tid, NQ_Principal *principal) {
	  return true;
}

#include "ssl.hh"
#include "ipc.hh"

#include "l2sec-ipc.hh"

int g_server_port = 3333;
IP_Address g_server_addr = INADDR_LOOPBACK;

bool g_need_negotiate = true;
bool g_check_switch_policy = false;

IPC_ServiceDesc l2sec_desc;

int set_l2sec_key(const unsigned char *key, int key_len);

NQ_Tuple switch_interface_tid = NQ_uuid_null;
NQ_Tuple host_tid = NQ_uuid_null;

NQ_Principal *net_owner;

NQ_Host data_home;

static bool try_nq_external_connect(NQ_Tuple my_host_tid, NQ_Tuple interface_tid, bool set_host = true) {
  try {
    Transaction t1(trust_all, trust_attrval_all, data_home, &NQ_default_owner);

    cerr << "Switch integrity check #1: proper owner\n";
    T_Interface *switch_interface = new T_Interface(t1, interface_tid);
    Switch *s;
    if(switch_interface == NULL) {
      cerr << "Could not load inteface\n";
      goto abort;
    }
    cerr << "switch tid " << switch_interface->container.load()->tid << "\n";
    s = new Switch(t1, switch_interface->container.load()->tid);

    if(!check_installed_by(&s->composite_element->installed_by, net_owner)) {
      cerr << "switch not installed by net owner\n";
      goto abort;
    }
    cerr << "Switch integrity check #1 passed\n";

    if(set_host) {
      Host h(t1, my_host_tid);
      h.nic->external_connection = switch_interface;
    }
    if(g_check_switch_policy) {
      cerr << "Switch integrity check #2: proper switch access control policy\n";
      NQ_Principal *p = NULL;
      // XXX policy should be factored out into trust functions
      T_Actor *enforcer = s->composite_element->policy_enforced_by.load(&p);
      if(enforcer == NULL) {
	cerr << "No enforcer\n";
	goto abort;
      }
      NQ_Principal *enforcer_principal = enforcer->principal.load();
      if(!(p == enforcer_principal && 
	   check_installed_by(&enforcer->installed_by, net_owner)) ) {
	cerr << "enforcer not installed by net owner " << 
	  (p == enforcer_principal ? 1 : 0) << " X\n";
	goto abort;
      }
      T_PolicyEnforcer *policy_enforcer = dynamic_cast<T_PolicyEnforcer *>(enforcer->entity.load());
      if(policy_enforcer == NULL) {
	cerr << "Unknown kind of policy enforcer\n";
	goto abort;
      }
      if(!(policy_enforcer->l2_policy.load(&p) == "ACCEPT_TPM" && 
	   p == enforcer_principal) ) {
	cerr << "Bad l2 policy: \"" << policy_enforcer->l2_policy.load() << "\", " << *p << "\n";
	goto abort;
      }
      cerr << "Switch integrity check #2 passed\n";
    }

    t1.commit();
    cerr << "Switch integrity check passed: was installed by network operator\n";
    return true;
  abort:
    t1.abort();
    return false;
  }  catch(NQ_Exception &e) {
    cerr << "exn " << e << "\n";
    return false;
  } catch(...) {
    cerr << "Set key: transaction error\n";
    return false;
  }
}

namespace L2Sec {

  struct GetTIDHandler : IPC_ServiceDesc::CommandDesc {
    inline GetTIDHandler() : CommandDesc(CMD_GetTID) { /* do nothing */ }
    virtual ~GetTIDHandler() { /* do nothing */ }
    virtual void unmarshall_and_do(IPC_ServerInstance *instance, int data_offset) const {
      NQ_Tuple *tuple;
      size_t req_size = tspace_marshall_size<NQ_Tuple>();
      char *data = new char[req_size];
      size_t len = instance->peek_command(data, data_offset, req_size);
      if(len != req_size) {
	return;
      }
      DataBuffer input((unsigned char *)data, req_size);
      delete [] data;
      CharVector_Iterator begin = input.begin(), end = input.end();
      
      tuple = tspace_unmarshall( (NQ_Tuple*)0, *(Transaction *)NULL, begin, end);
      cerr << "Server got tid " << *tuple << "\n";
      cerr << "Sending back TID\n";
      switch_interface_tid = *tuple;

      DataBuffer rv;
      tspace_marshall(host_tid, rv);

      cerr << "Tid to send is " << host_tid << "\n";
      instance->finish_command(req_size); // no arguments to command
      instance->send_response(rv);
    }
  };

  struct NewKeyHandler : IPC_ServiceDesc::CommandDesc {
    inline NewKeyHandler() : CommandDesc(CMD_NewKey) { /* do nothing */ }
    virtual ~NewKeyHandler() { /* do nothing */ }
    virtual void unmarshall_and_do(IPC_ServerInstance *instance, int data_offset) const {
      Header header;
      int len = instance->peek_command(&header, data_offset, sizeof(header));
      if(len != sizeof(header)) {
	// not enough data
	return;
      }
      data_offset += sizeof(header);
      if(!(0 < header.key_length && header.key_length <= L2SEC_KEYLEN)) {
	THROW("Bad command: key length");
      }
      unsigned char key_data[L2SEC_KEYLEN];
      if(instance->peek_command(key_data, data_offset, header.key_length) != header.key_length) {
	return;
      }

      if(!try_nq_external_connect(host_tid, switch_interface_tid)) {
	cerr << "Not setting key\n";
	return;
      }

      int retval = set_l2sec_key(key_data, header.key_length);
      g_need_negotiate = false;

      DataBuffer rv;
      Response resp;
      resp.val = retval;
      vector_push(rv, resp);
      instance->finish_command(sizeof(header) + header.key_length);
      instance->send_response(rv);
    }
  };
}

unsigned char test_key[16] = {
  0xff, 0xff, 0xff, 0xff, 
  0xff, 0xff, 0xff, 0xff, 
  0xff, 0xff, 0xff, 0xff, 
  0xff, 0xff, 0xff, 0xff, 
};

int set_l2sec_key(const unsigned char *key, int key_len) {
  cerr << "Got key, len = " << key_len << "\n";
#ifndef __LINUX__
  int rv = Net_set_l2sec_key((unsigned char *)key, 16);
  if(rv == 0) {
    printf("L2sec key set!\n");
    return 0;
  } else {
    printf("L2sec key could not be set!\n");
    return -1;
  }
#else
  cerr << "Linux version, not setting l2sec key!\n";
  return 1;
#endif // __LINUX__
}

pthread_t client_thread;

void *self_test_client_thread(void *ignored) {
 try {
  eventxx::dispatcher client_d;

  cerr << "Client thread\n";
  int client_sock = tcp_socket(INADDR_ANY, 0, false);
  struct sockaddr_in server_addr;
  server_addr.sin_family = AF_INET;
  server_addr.sin_addr.s_addr = htonl(g_server_addr);
  server_addr.sin_port = htons(g_server_port);
  int result = connect(client_sock, (struct sockaddr *) &server_addr, sizeof(server_addr));
  if(result < 0 && errno != EINPROGRESS) {
    cerr << "could not open test connection";
    exit(-1);
  }

  L2Sec::Client *client = new L2Sec::Client(&client_d, client_sock, server_addr);
  client->GetTID(NQ_uuid_null);
  client->NewKey(test_key, L2SEC_KEYLEN);
  cerr << "Got back from new key\n";
  // fall off end of thread without deallocating
 } catch(char *c) {
   cerr << "Client got err " << c << "\n";
 } catch(string s) {
  cerr << "Main got s err " << s << "\n";
 }
 return NULL;
}

static void start_server(void) {
  eventxx::dispatcher d;
  cerr << "Starting server\n";
  int listen_sock = tcp_socket(INADDR_ANY, g_server_port, true);

  l2sec_desc.add_command(new L2Sec::NewKeyHandler());
  l2sec_desc.add_command(new L2Sec::GetTIDHandler());
  IPC_Server l2sec_server(&l2sec_desc, listen_sock, &d);
  cerr << "Dispatcher = " << &d << "\n";

  d.dispatch();
  cerr << "returned from dispatch\n";
  exit(-1);
}

static void linux_test(int is_server) {
  try {

    if(is_server) {
      start_server();
    } else {
      cerr << "Starting client\n";
      self_test_client_thread(NULL);
      //pthread_create(&client_thread, NULL, self_test_client_thread, NULL);
    }
  } catch(char *c) {
    cerr << "Main got err " << c << "\n";
  } catch(string s) {
    cerr << "Main got s err " << s << "\n";
  }
}

int main(int argc, char **argv) {
#ifndef __LINUX__
  chdir("/nfs");
#endif
  net_owner = NQ_load_principal("/nfs/net-owner.principal");
  if(net_owner == NULL) {
    cerr << "Could not load principal for network owner\n";
    exit(-1);
  }

  int opt;
  bool connect_only_test = false;
  while( (opt = getopt(argc, argv, "Ckp:d:S")) != -1) {
    switch(opt) {
    case 'C':
      // only supported under Linux
      connect_only_test = true; // i.e. no switch functionality, just used to test IPC
      break;
    case 'p':
      g_server_port = atoi(optarg);
      cerr << "Using server port " << g_server_port << "\n";
      break;
    case 'd': {
      in_addr_t addr = inet_addr(optarg);
      g_server_addr = ntohl(addr);
      cerr << "Using target address " << optarg << "\n";
      break;
    }
    case 'k': {
      cerr << "Omitting part of certificate chain. Should cause handshake to fail\n";
      g_dbg_omit_nsk = true;
      break;
    }
    case 'S':
      cerr << "Checking switch enforcer policy\n";
      g_check_switch_policy = true;
      break;
    default:
      cerr << "unknown option!\n";
      assert(0);
    }
  }

  NQ_init(NQ_PORT_ANY);
  NQ_cpp_lib_init();

  ssl_init();

  NQ_publish_home_principal();
  NQ_publish_principal(&NQ_default_owner, "l2secd.principal");

  if(connect_only_test) {
#ifndef __LINUX__
    cerr << "only supported under linux\n";
    assert(0);
#endif
    if(argc - optind < 2) {
      cerr << "Usage: l2secd <server ip> <server port>\n";
      exit(-1);
    }
    NQ_Host home;
    home.addr = inet_addr(argv[optind]);
    home.port = atoi(argv[optind + 1]);

    data_home = home;
    if(0) {
      ExtRef<T_Site> site_ref;
      NQ_UUID site_tid= load_tid_from_file(string("/nfs/site.tid"));
      site_ref = ExtRef<T_Site>(site_tid);
      cerr << "Site tid = " << site_tid << "\n";
      cerr << "Host " << home << "\n";

      Transaction t1(trust_all, trust_attrval_all, home, &NQ_default_owner);
      T_Site *site = site_ref.load(t1);
      assert(site != NULL);

      Switch *s = new Switch(t1, site->switches[0].load().load()->tid);
      NQ_Tuple interface_tid = s->interfaces[0]->tid;
      t1.commit();

      if(try_nq_external_connect(NQ_uuid_null, interface_tid, false)) {
	cerr << "test succeeded!\n";
      } else {
	cerr << "test failed!\n";
      }
    } else {
      // old test case
      g_ssl_always_accept = true;
      if(argc - optind < 3) {
	cerr << "Usage: l2secd [-p port] <server ip> <server port> <server=1,client=0>\n";
	exit(-1);
      }
      int is_server = atoi(argv[optind + 2]);
      linux_test(is_server);
    }
  }
  if(NQ_getenv_server(&data_home) != 0) {
    cerr << "Could not load NQ server\n";
    exit(-1);
  }

  host_tid = NQ_get_host_tid();
  cerr << "Host tid is " << host_tid << "\n";

  start_server();
  // should not reach here
  assert(0);
}
