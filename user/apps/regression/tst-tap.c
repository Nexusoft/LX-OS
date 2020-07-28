#include <stdio.h>
#include <nexus/IPC.interface.h>
#include <nexus/Debug.interface.h>
#include <nexus/Thread.interface.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include "../tap-test/all-null.h"
#include <nexus/test-support.h>

#include "../nameserver/NS.interface.h"
#include "TapNotification_RejectAll.interface.h"

// Unit tests, e.g. reference counting, proper deallocation

Port_Handle port_handle;
Port_Num port_num;

int conn_count = 0;
#define NUM_CONNS (2)
Connection_Handle conn_handle[NUM_CONNS];

#define VETO_SERVER_NAME "TST-TAP-VETO"

// can be modified by diff threads
volatile Port_Handle accept_taps_handler;

int ignore_limit = 0;
static void *do_accept(void *_ignored) {
  while(ignore_limit || conn_count < NUM_CONNS) {
    printf("accept thread %d, port = %d,%d\n", (int)pthread_self(), 
	   accept_taps_handler, g_Wrap_port_handle);
    Port_Handle handle = IPC_DoBindAccept_notified(port_handle, accept_taps_handler);
    printf("accepted %d, count = %d\n", handle, conn_count);
    if(conn_count < NUM_CONNS) {
      conn_handle[conn_count] = handle;
    }
    conn_count += 1;
  }
  printf("end of accept loop\n");
  return NULL;
}

static void fork_accept_thread(int _ignore_limit) {
  pthread_t accept_thread;
  ignore_limit = _ignore_limit;
  printf("accepting at port %d\n", port_num);
  pthread_create(&accept_thread, NULL, do_accept, NULL);
}

void dump_counter(IPC_Counters *counters) {
  printf("{ Counters: conn %d all conn %d }", counters->IPC_Connection, 
	 counters->IPC_AllConnection);
}

void dump_current_counter(void) {
  IPC_Counters counters;
  Debug_get_ipc_counters(&counters);
  printf("Current counter: conn %d all conn %d\n",
	 counters.IPC_Connection, counters.IPC_AllConnection);
}

int VETO_VALUE = -255;
static void clean_veto_log(void) {
  Regtest_write_result(ALL_NULL_VETO_FNAME, VETO_VALUE, "CLEARED");
}

#define PING() printf("(%d)", __LINE__)
static void do_veto_check(Port_Num test_port_num, Port_Handle taps_handler) {
  // clean
  clean_veto_log();
  sleep(1); // wait for interposition; probably unnecessary
  int c0 = IPC_DoBind_notified(test_port_num, taps_handler);
  PING();
  if(c0 < 0) {
    printf("Error binding (%d)\n", c0);
    exit(-1);
  }
  PING();
  char comment[80] = "";
  int res = Regtest_read_result(ALL_NULL_VETO_FNAME, comment);
  PING();
  printf("Got comment \"%s\" from output file\n", comment);
  PING();
  if(res < 0) {
    printf("Failed with %d\n", res);
    exit(-1);
  }
  PING();
  printf("Succeeded\n");
  exit(0);
}

int main(int argc, char **argv) {
  IPC_Counters init_counters;
  if(argc < 2) {
    printf("Not enough arguments!\n");
    exit(-1);
  }

  // N.B. First Binds must always succeed, so use an accept all taps handler (the default one)
  accept_taps_handler = g_Wrap_port_handle;

  Debug_get_ipc_counters(&init_counters);

  port_handle = IPC_CreatePort(&port_num);
  fork_accept_thread(0);

  printf("main thread = %d\n", (int)pthread_self());
  int i;
  for(i=0; i < NUM_CONNS; i++) {
    int c1 = IPC_DoBind(port_num);
    assert(c1 >= 0);
    sleep(1); // make sure the accept thread gets to set async_conn_handle before we print it out
    printf("c1 = %d, conn_handle = %d\n", conn_handle[i], c1);
  }

  TapNotification_RejectAll_initializeNotificationHandler();
  Port_Handle reject_all_taps_handler = g_TapNotification_RejectAll_port_handle;

  int test_num = atoi(argv[1]);
  int rv;
  switch(test_num) {
  case 0:
    printf("Close test\n");
    printf("Initial counter state\n");
    dump_current_counter();
    rv = IPC_CloseConnection(conn_handle[0]);
    if(rv != 0) {
      printf("error closing connection\n");
      exit(-1);
    }
    rv = IPC_CloseConnection(conn_handle[1]);
    if(rv != 0) {
      printf("error closing connection\n");
      exit(-1);
    }
    IPC_Counters post_close_counters;
    Debug_get_ipc_counters(&post_close_counters);

    printf("Counter values: conn %d all conn %d\n conn %d all conn %d\n",
	   init_counters.IPC_Connection, init_counters.IPC_AllConnection,
	   post_close_counters.IPC_Connection, post_close_counters.IPC_AllConnection);
    if(post_close_counters.IPC_AllConnection != init_counters.IPC_AllConnection + 2) {
      printf("Something is wrong with kernel refcnts (%d, %d)\n",
	     post_close_counters.IPC_AllConnection, init_counters.IPC_AllConnection);
      exit(-1);
    }
    printf("success\n");
    exit(0);
    break;
  case 1:
    printf("Destroy port (tests kernel port deallocation)\n");
    rv = IPC_DestroyPort(port_handle);
    if(rv != 0) {
      printf("error destroying poinrt\n");
      exit(-1);
    }
    // for now, just checks that this doesn't crash
    printf("success\n");
    exit(0);
  case 2:
    printf("IPD full cleanup test\n");
    IPC_Counters pre_fork_counters;
    IPC_Counters post_fork_counters;
    Debug_get_ipc_counters(&pre_fork_counters);
#define MAXELFLEN (8 * (1 << 20))
    unsigned char *elf_buf = malloc(MAXELFLEN);
    char *elf_arg = "1";
    char *elf_kname = "tst-tapfork";
    int fd = open("/nfs/tst-tap", O_RDONLY);
    if(fd < 0) {
      printf("error openning tap test file\n");
      exit(-1);
    }
    int elf_len = read(fd, elf_buf, MAXELFLEN);
    if(elf_len == MAXELFLEN) {
      printf("elf file too big!\n");
      exit(-1);
    }
    printf("Forking process\n");
    IPC_FromElf(elf_kname, strlen(elf_kname) + 1, 
		elf_buf, elf_len, 
		elf_arg, strlen(elf_arg) + 1);
    sleep(5);
    Debug_get_ipc_counters(&post_fork_counters);
    printf("After forking process\n");
    printf("Pre fork: "); dump_counter(&pre_fork_counters); printf("\n");
    printf("Post fork: "); dump_counter(&post_fork_counters); printf("\n");

    // allow some range of allowed values ; this is due to refs to connection by tcpmgr
    if(pre_fork_counters.IPC_AllConnection + 1 < post_fork_counters.IPC_AllConnection) {
      printf("All connection mismatch\n");
      exit(-1);
    }
    if(pre_fork_counters.IPC_Connection + 6 < post_fork_counters.IPC_Connection) {
      printf("Alloc'ed connection mismatch\n");
      exit(-1);
    }
    printf("OK\n");
    exit(0);
    break;

    // Note that the veto tests need to be launched with the correct
    // corresponding wrapper

  case 3: {
    // wrap with all-null 1
    printf("Check for working veto (kernel)\n");
    do_veto_check(VETO_TEST_PORT, g_Wrap_port_handle);
    // should not reach here
    assert(0);
    break;
  }
  case 4:
    // wrap with all-null 0
    printf("Check for no veto (kernel)\n");
    do_veto_check(NO_VETO_TEST_PORT, g_Wrap_port_handle);
    break;
    
  case 5: {
    printf("Veto user client, always reject taps\n");
    // run with all-null 1, either server
    Port_Num server_port_num = NS_SimpleLookup(VETO_SERVER_NAME);
    if(server_port_num <= 0) {
      printf("Could not find server port!\n");
      exit(-1);
    }
    printf("will connect to %d\n", server_port_num);
    do_veto_check(server_port_num, reject_all_taps_handler);
    break;
  }
    // There are 4 combinations of veto/noveto servers/clients
  case 6: {
    printf("Veto user client, always accept taps\n");
    Port_Num server_port_num = NS_SimpleLookup(VETO_SERVER_NAME);
    if(server_port_num <= 0) {
      printf("Could not find server port!\n");
      exit(-1);
    }
    printf("will connect to %d\n", server_port_num);
    do_veto_check(server_port_num, g_Wrap_port_handle);
    break;
  }
  case 7: {
    printf("Veto user server, always reject taps\n");
    accept_taps_handler = reject_all_taps_handler;
    fork_accept_thread(1);

    struct NS_SimpleRegisterCtx *register_ctx = 
      NS_SimpleRegister(VETO_SERVER_NAME, port_num);
    Thread_Notify(0);
    // test should be done within 10 seconds
    //#define DURATION (10)
#define DURATION (10000)
    sleep(DURATION);
    printf("server exiting\n");
    exit(0);
    break;
  }
  case 8: {
    printf("veto server, always accept taps\n");
    accept_taps_handler = g_Wrap_port_handle;
    fork_accept_thread(1);

    struct NS_SimpleRegisterCtx *register_ctx = 
      NS_SimpleRegister(VETO_SERVER_NAME, port_num);
    Thread_Notify(0);
    // test should be done within 10 seconds
    sleep(DURATION);
    printf("server exiting\n");
    exit(0);
#undef DURATION
  }
  default:
    printf("Unknown test %d!\n", test_num);
    exit(-1);
  }
  return 0;
}
