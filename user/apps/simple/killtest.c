#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>

#include <nexus/ipc.h>
#include <nexus/debug.h>

#include <nexus/Thread.interface.h>
#include <nexus/Debug.interface.h>
#include <nexus/IPC.interface.h>
#include <nexus/Log.interface.h>


#define KILLTEST_LOG_NAME "RegressionLog"
#define KILLTEST_LOG_LEN (4096)

Port_Num test_port_num;
Port_Handle test_port_handle;
Connection_Handle test_conn_handle;

static void *fork_accept(void *ctx) {
  Port_Handle port_handle = (Port_Handle) ctx;
  int conn_handle = IPC_DoBindAccept(port_handle);
  printf("server conn handle is %d (from %d)\n", conn_handle, port_handle);
  return NULL;
}

static Port_Handle register_open_channel(Port_Num *port_num_p, Connection_Handle *conn_handle_p) {
  int val = 0;
  pthread_t accept_thread;
  Port_Handle rv = IPC_CreatePort(port_num_p);

  // fork a thread to accept one request. Note that this test doesn't
  // work if someone else happens to bind to the service at this point!!!
  pthread_create(&accept_thread, NULL, fork_accept, (void *)rv);
  *conn_handle_p = IPC_DoBind(*port_num_p);
  printf("open channel %d, port handle %d, conn handle %d\n", 
	 *port_num_p, rv, *conn_handle_p);

  return rv;
}

void *fork0(void *arg) {
  printf("before sleep\n");
  sleep(1000);
  printf("end of %s\n", __FUNCTION__);
  return NULL;
}

void *fork_IPC_Call(void *arg) {
  printf("before IPC_Call of %d\n", test_conn_handle);
  char *msg = "MESSAGE";
  char result[128];
  int result_len = 0;
  struct TransferDesc descs[] = {
    { 
	.access = IPC_WRITE,
	.u.direct.base = (unsigned int)result,
	.u.direct.length = sizeof(result),
    }
  };
  int rv = IPC_Invoke(test_conn_handle, msg, strlen(msg), descs, 1);
  printf("IPC call rv = %d\n", rv);
  printf("caller done\n");
  return NULL;
}

int do_return = 0;

void *fork_IPC_RecvCall(void *arg) {
  printf("before IPC_RecvCall\n");
  char *msg = "MESSAGE";
  char message[128];
  int message_len = sizeof(message);
  CallDescriptor cdesc;
  int rv = IPC_RecvCall(test_port_handle,
			message, &message_len,
			&cdesc);
  printf("IPC recvcall rv = %d\n", rv);
  if(do_return) {
    rv = IPC_CallReturn(rv);
    printf("IPC return rv = %d\n", rv);
  }
  return NULL;
}

pthread_t test_basic_thread;

void do_test_basic(int disable, int do_sleep) {
  Debug_ForkDelay(disable);
  pthread_t thread;
  pthread_create(&thread, NULL, fork0, NULL);
  if(do_sleep) sleep(1);

  printf("kill\n");
  Thread_Kill(thread);
  printf("after kill\n");
  Debug_ForkDelay(0);

  test_basic_thread = thread;
  sleep(10); // force cleaner thread to run
}

struct {
  pthread_t recv_thread;
  pthread_t call_thread;
} test_call;

void do_test_call(int start_receiver, int return_p) {
  if(start_receiver) {
    pthread_t recv_thread;
    // Debug_RecvCallDelay(1);
    do_return = return_p;
    pthread_create(&recv_thread, NULL, fork_IPC_RecvCall, NULL);
    test_call.recv_thread = recv_thread;
  }

  pthread_t thread;
  pthread_create(&thread, NULL, fork_IPC_Call, NULL);

  sleep(5);
  printf("kill\n");
  Thread_Kill(thread);
  printf("After kill\n");

  test_call.call_thread = thread;

  sleep(3); // force cleaner thread to run
}

void do_test_recvcall(void) {
  pthread_t thread;
  pthread_create(&thread, NULL, fork_IPC_RecvCall, NULL);
  sleep(2);
  printf("Call kill\n");
  Thread_Kill(thread);
  printf("After call kill\n");
  IPC_DestroyPort(test_port_handle);

  test_call.recv_thread = thread;
  sleep(3); // force cleaner thread to run
}

int bind_request_success = 0;
int bind_request_finish = 0;

void *fork_BindRequest(void *ctx) {
  printf("Calling request\n");
  int rv = IPC_BindRequest(test_port_handle);
  printf("Request => %d\n", rv);
  if(rv >= 0) {
    bind_request_success = 1;
  }
  bind_request_finish = 1;
  return NULL;
}

void *fork_AcceptRequest(void *ctx) {
  printf("Calling acceptRequest\n");
  int rv = IPC_BindAcceptRequest(test_port_handle);
  printf("AcceptRequest => %d (%d)\n", rv, (int)pthread_self());
  return NULL;
}

void do_test_bindrequest(void) {
  pthread_t thread;
  pthread_create(&thread, NULL, fork_BindRequest, NULL);
  sleep(2);
  printf("Call kill\n");
  Thread_Kill(thread);
  printf("After call kill\n");
  IPC_DestroyPort(test_port_handle);
  test_call.call_thread = thread;
  sleep(3); // force cleaner thread to run
}

void do_test_acceptrequest(int server_count, int start_client) {
  int i;
  for(i=1; i < server_count; i++) {
    pthread_t server_thread;
    pthread_create(&server_thread, NULL, fork_AcceptRequest, NULL);
    printf("forked additional server %d\n", (int)server_thread);
  }

  // server threads are used in LIFO order, so start the one of interest last
  pthread_t thread;
  pthread_create(&thread, NULL, fork_AcceptRequest, NULL);
  test_call.recv_thread = thread;
  sleep(2); // let server threads run until blocking

  // kill server thread ; the interleaving hack will force the kill to
  // be fully processed after client goes

  printf("Call kill\n");
  Thread_Kill(thread);
  printf("After call kill\n");

  if(start_client) {
    pthread_t client_thread;
    printf("Starting client\n");
    pthread_create(&client_thread, NULL, fork_BindRequest, NULL);
    test_call.call_thread = client_thread;
  }
  sleep(2);

  sleep(3); // let client run before unregistering test channel
  IPC_DestroyPort(test_port_handle);
  sleep(3); // force cleaner thread to run
}

static void run_test_request_generic(int testnum, int server_count, int serialize_order, char *kill_location);

static void log_top(int testnum) {
  Log_Create(KILLTEST_LOG_NAME, KILLTEST_LOG_LEN);
  printf("KillTest(%d) {\n", testnum);
}

static void log_bottom(int testnum, int code) {
  printf("} => %d\n", code);
  int exit_val = code ? 0 : 1;
  printf("exiting with %d\n", exit_val);
  exit(exit_val);
}

void prep_regression(void) {
  Debug_CleanCount_clear();
  Debug_KillLog_clear();
}

static int g_test_success;

#define INIT_SUCCEED() g_test_success = 1
#define UPDATE_SUCCEED(PRED)					\
  if(g_test_success && !(PRED)) {				\
    g_test_success = 0;						\
    printf("\t!(" #PRED ")\n");	\
  }

static void check_killlog_entry(int entry, int id, char *kill_location) {
  struct KillLog_UserEntry ent = Debug_KillLog_getEntry(entry);
  printf("ent = {%d %s}, match = {%d %s}\n", ent.id, ent.desc, id, kill_location);
  UPDATE_SUCCEED(ent.id == id);
  UPDATE_SUCCEED(strcmp(ent.desc, kill_location) == 0);
}

static void print_kill_log(void) {
  int log_len = Debug_KillLog_getLen();
    
  printf("log_len = %d\n", log_len);
  int i;
  for(i=0; i < log_len; i++) {
    struct KillLog_UserEntry ent = Debug_KillLog_getEntry(i);
    printf("%d=>%s\n", ent.id, ent.desc);
  }
}

static void check_test_basic(int testnum, char *kill_location, int syscall_exit) {
  int clean_count = Debug_CleanCount_get();
  log_top(testnum);

  INIT_SUCCEED();

  printk("clean_count = %d, want 1\n", clean_count);

  UPDATE_SUCCEED(clean_count == 1);
  int log_len = Debug_KillLog_getLen();
  print_kill_log();

  if(!syscall_exit) {
    UPDATE_SUCCEED(log_len == 1);
    check_killlog_entry(0, test_basic_thread, kill_location);
  } else {
    UPDATE_SUCCEED(log_len == 2);
    check_killlog_entry(0, test_basic_thread, kill_location);
    check_killlog_entry(1, test_basic_thread, KILL_LOCATION_EXIT_SYSCALL);
  }
  log_bottom(testnum, g_test_success);
}

static void check_test_helper(int testnum, int thread,
			      char *kill_location, int num_servers,
			      int (*post_helper)(void)) {
  int clean_count = Debug_CleanCount_get();
  log_top(testnum);

  INIT_SUCCEED();

  int target = (1 + num_servers);
  printk("clean_count = %d, want %d\n", clean_count, target);

  UPDATE_SUCCEED(clean_count == (1 + num_servers));

  int log_len = Debug_KillLog_getLen();
  print_kill_log();

  UPDATE_SUCCEED(log_len == 2);
  check_killlog_entry(0, thread, kill_location);
  check_killlog_entry(1, thread, KILL_LOCATION_EXIT_SYSCALL);

  if(post_helper) {
    UPDATE_SUCCEED(post_helper());
  }
  log_bottom(testnum, g_test_success);
}

int check_bind_request_success(void) {
  return bind_request_success;
}

int check_bind_request_not_finished(void) {
  return !bind_request_finish;
}

static void check_test_call(int testnum, char *kill_location, int has_server) {
  check_test_helper(testnum, test_call.call_thread, kill_location, has_server ? 1 : 0, NULL);
}

static void check_test_recvcall(int testnum, char *kill_location, int has_server) {
  check_test_helper(testnum, test_call.recv_thread, kill_location, has_server ? 1 : 0, NULL);
}

int main(int argc, char **argv) {
  printf("entered killtest\n");
  if(argc < 2) {
    printf("killtest <testnum>\n");
    exit(-1);
  }
  int testnum = atoi(argv[1]);

  switch(testnum) {
  case 0: { // dump regression log to tftp server
    int len = Log_GetLen(KILLTEST_LOG_NAME) + 1;
    char *data = malloc(len);
    Log_GetData(KILLTEST_LOG_NAME, data, len);
    printf("%s\n", data);
    char *log_fname = "killtest.log";
    writefile(log_fname, data, strlen(data));
    free(data);
    Log_Clear(KILLTEST_LOG_NAME);
    printf("Wrote %s\n", log_fname);
    exit(0);
    break;
  }
  case 1: {
    printf("Kill newly created thread test\n");
    prep_regression();

    do_test_basic(1, 0);

    check_test_basic(testnum, KILL_LOCATION_GOTO_USER, 0);
    break;
  }
  case 3:
    printf("Kill sleeping thread test\n");
    prep_regression();
    do_test_basic(0, 1);

    check_test_basic(testnum, KILL_LOCATION_SLEEPSEMA, 1);

    break;

    // Call tests
  case 5: {
    printf("caller count sema\n");
    test_port_handle = register_open_channel(&test_port_num, &test_conn_handle);
    printf("channel is %d\n", test_port_handle);
    prep_regression();
    do_test_call(0, 0);
    check_test_call(testnum, KILL_LOCATION_SERVER_SLOT_SEMA, 0);
    break;
  }
  case 6:
    printf("caller barrier sema, no return; should kill in-progress call\n");
    test_port_handle = register_open_channel(&test_port_num, &test_conn_handle);
    printf("channel is %d\n", test_port_handle);
    prep_regression();
    do_test_call(1, 0);
    check_test_call(testnum, KILL_LOCATION_PRE_RETURN, 1);
    break;
  case 7:
    printf("caller barrier sema, return; return should beat kill\n");
    printf("This doesn't actually test anything useful\n");
    test_port_handle = register_open_channel(&test_port_num, &test_conn_handle);
    printf("channel is %d\n", test_port_handle);
    do_test_call(1, 1);
    break;
  case 8:
    printf("callee barrier sema\n");
    test_port_handle = register_open_channel(&test_port_num, &test_conn_handle);
    printf("channel is %d\n", test_port_handle);
    prep_regression();
    do_test_recvcall();
    check_test_recvcall(testnum, KILL_LOCATION_RECVCALL_BARRIER, 0);
    break;

    //// Bind kill tests

    // BindRequest
  case 20:
    printf("Caller kill at bind_count_sema (only thread; semaphore counter should be OK afterward)\n");
    test_port_handle = register_open_channel(&test_port_num, &test_conn_handle);
    prep_regression();
    do_test_bindrequest();
    check_test_helper(testnum, test_call.call_thread, KILL_LOCATION_BIND_COUNT, 0, check_bind_request_not_finished);
    break;
  case 21:
    printf("Callee killed at bind_sema (no clients)\n");
    test_port_handle = register_open_channel(&test_port_num, &test_conn_handle);
    prep_regression();
    do_test_acceptrequest(1, 0);
    check_test_helper(testnum, test_call.recv_thread, KILL_LOCATION_BIND_ACCEPT_BARRIER_1, 0, 
		      NULL);
    break;
  case 22:
    printf("Callee killed at bind_sema (no clients), then client arrives and hits invalid channel. This test intentionally leaks a channel due to hung client\n");
    test_port_handle = register_open_channel(&test_port_num, &test_conn_handle);
    prep_regression();
    do_test_acceptrequest(1, 1);
    check_test_helper(testnum, test_call.recv_thread, KILL_LOCATION_BIND_ACCEPT_BARRIER_1, 0,
		      check_bind_request_not_finished);
    break;
  case 23: {
    printf("Callee killed at bind_sema (before client runs rendez), and should block. ");
    int server_count = 1;
    int serialize_order = 2;
    char *kill_location = KILL_LOCATION_BIND_ACCEPT_BARRIER_1;
    rendez_resume:
    test_port_handle = register_open_channel(&test_port_num, &test_conn_handle);
    printf("server count = %d\n", server_count);
    Debug_BindSerializeOrder(serialize_order);
    if(server_count == 1) {
      printf("Client should retry, and block\n");
    }
    prep_regression();
    do_test_acceptrequest(server_count, 1);
    int server_count_adj;
    if(server_count == 1) {
      // 1 server - 1 client that never finishes
      server_count_adj = 0;
    } else {
      // k servers + 1 client that finishes
      server_count_adj = server_count;
    }
    check_test_helper(testnum, test_call.recv_thread, kill_location, server_count_adj,
		      server_count > 1 ? check_bind_request_success : check_bind_request_not_finished);
    Debug_BindSerializeOrder(0);
    break;
  case 24:
    printf("Callee killed at bind_sema (before client runs rendez). Should retry, and find 2nd server\n");
    server_count = 2;
    serialize_order = 2;
    kill_location = KILL_LOCATION_BIND_ACCEPT_BARRIER_1;
    goto rendez_resume;
    break;
  case 25:
    printf("Callee killed at bind_sema (after client runs rendez). Client should retry, and block\n");
    server_count = 1;
    serialize_order = 1;
    kill_location = KILL_LOCATION_BIND_ACCEPT_BARRIER_0;
    goto rendez_resume;
    break;
  case 26:
    printf("Callee killed at bind_sema (after client runs rendez). Client should retry, and function for 2nd server\n");
    server_count = 2;
    serialize_order = 1;
    kill_location = KILL_LOCATION_BIND_ACCEPT_BARRIER_0;
    goto rendez_resume;
    break;
  }
  case 99:
    printf("Intentional failure\n");
    exit(-1);
    break;
  default:
    printf("Unknown testnum %d!\n", testnum);
    break;
  }
  return 0;
}
