#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <assert.h>
#include <nexus/LabelStore.interface.h>

#ifndef __LINUX__
#include "nexus/IPC.interface.h"
#include "WrapStream.interface.h"
#include "FuncInterposeDriver.interface.h"
#endif

#include <openssl/ssl.h>
#include <openssl/err.h>

#include "exec-func.h"
#include "ssl.h"

#define LOCAL_ADDR (0)
#define USE_TCP (0)

#ifdef __LINUX__
    int (*recv_fn)(char *target, int maxlen);
    int (*send_fn)(const char *target, int maxlen);
    int (*close_fn)(void);
#endif

#ifndef __LINUX__
#define NUM_IPC_THREADS (4)
static pthread_t ipc_threads[NUM_IPC_THREADS];
static pthread_t accept_threads[NUM_IPC_THREADS];

#define NUM_RM_THREADS (4)
static pthread_t rm_threads[NUM_RM_THREADS];

extern Port_Handle *interpose_port_handle_p;

static void *processing_loop_rm(void *ctx) { while(1) FuncInterposeDriver_processNextCommand(); }
static void *processing_loop_ipc(void *ctx) { while(1) WrapStream_processNextCommand(); }
static void *accept_loop(void *ctx) { while(1) IDL_BINDACCEPT(WrapStream); }  

void start_wrapper_threads(void) {
  int i;
  for(i=0; i < NUM_RM_THREADS; i++) {
    if(pthread_create(&rm_threads[i], NULL, processing_loop_rm, (void *) i)) {
      printf("could not fork rm processing thread %d\n", i);
    }
  }
}
FSID store;
FSID hashcred_id;
SignedFormula *nsk_label;
SignedFormula *hashcred;
SignedFormula *sslkey_binding;
#endif

int dbg = 1;
#define printf_dbg(x...) if(dbg)printf(x)
                                                                                                                                         
char *target_name;
int run_program(char *program, int ac, char **av, char **r_cmdstr);

static SSL *data_ssl;
int data_sock = -1;
int g_child_ipd = -1;

#define DUMP_ERRS()				\
  printf("<<<%d>>>\n", __LINE__);			\
  ERR_print_errors_fp(stdout);


int recv_tcp(char *target, int maxlen) {
  return recv(data_sock, target, maxlen, 0);
}
int send_tcp(const unsigned char *target, int maxlen) {
  return send(data_sock, target, maxlen, 0);
}
int close_tcp(void) {
  int err = close(data_sock);
  data_sock = -1;
  if(err != 0) {
    printf("could not close tcp socket!\n");
  }
  return err;
}

int recv_ssl(char *target, int maxlen) {
  return SSL_read(data_ssl, target, maxlen);
}

int send_ssl(const unsigned char *target, int maxlen) {
  return SSL_write(data_ssl, target, maxlen);
}

int close_ssl(void) {
  return SSL_shutdown(data_ssl);
}

int main(int argc, char **argv) {
  if(!USE_TCP) {
    ssl_init();
#ifndef __LINUX__
    load_nexus_keys();
#else
    load_linux_keys();
#endif
  }

  if(0) {
    char *r_cmd_str;
    char *args[1] = { "100" };
    run_program("calc-taxes", 1, args, &r_cmd_str);
    printf("Ran program\n");
    exit(0);
  }
  int i;
  printf_dbg("exec-func\n");
  if(argc < 3) {
    printf("exec_func: <listen port #> <executable to wrap> \n");
    exit(-1);
  }
  int port_num = atoi(argv[1]);
  char *prog_name;
  prog_name = argv[2];

#ifndef __LINUX__
  FuncInterposeDriver_serverInit();

  // create labelstore
  char *store_name = "public_labels";
  printf("Creating Label Store (%s)... ", store_name);
  store = LabelStore_Store_Create(store_name);
  if (!FSID_isValid(store)) { printf("error\n"); exit(1); }
  printf("done\n");

  int nsk_len;
  nsk_label = (SignedFormula *)read_file("/nfs/nexus.nsk.signed", &nsk_len);

  printf("Asking for a label from nexus...\n");
  hashcred_id = LabelStore_Nexus_Label(store, 1, "hashcred", NULL, NULL);
  if (!FSID_isValid(hashcred_id)) { printf("error\n"); exit(1); }
  hashcred = malloc(4096);
  int hashcred_len = LabelStore_Label_Externalize(hashcred_id, (char *)hashcred, 4096, NULL);
  if(hashcred_len > 4096) { printf("not enough space for cred!\n");  exit(-1); }

  printf("Asking for label binding pubkey\n");
  Formula *ssl_stmt = form_bind_cert_pubkey(server_cert);
  FSID sslkey_binding_id = 
    LabelStore_Label_Create(store, "sslkey_binding", ssl_stmt, NULL);
  sslkey_binding = malloc(4096);
  int ssl_cred_len = LabelStore_Label_Externalize(sslkey_binding_id, (char *)sslkey_binding, 4096, NULL);
  if(ssl_cred_len > 4096) { printf("formula too long!\n"); exit(-1); }

  WrapStream_serverInit();

 for(i=0; i < NUM_IPC_THREADS - 1; i++) {
    if(pthread_create(&ipc_threads[i], NULL, processing_loop_ipc, (void *) i)) {
      printf("could not fork ipc processing thread %d\n", i);
    }
    if(pthread_create(&accept_threads[i], NULL, accept_loop, NULL)) {
      printf("could not fork accept thread %d\n", i);
    }

  }
#endif // __LINUX__

  printf("Initialization done\n");

  printf("Waiting for connection\n");


  printf("Binding to socket %d\n", port_num);
  int listen_sock = socket(PF_INET, SOCK_STREAM, 0);
  struct sockaddr_in addr;
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = LOCAL_ADDR;
  addr.sin_port = htons(port_num);
  int err = bind(listen_sock, (struct sockaddr *)&addr, sizeof(addr));
  if(err != 0) {
    printf("Could not bind listen sock!\n");
    exit(-1);
  }
  err = listen(listen_sock, 4);
  assert(err == 0);

  struct sockaddr_in acceptaddr;
  int addrlen = sizeof(struct sockaddr_in);
  while(1) {
    data_sock = accept(listen_sock, (struct sockaddr*)&acceptaddr, (size_t*)&addrlen);
    if(data_sock > 0) {
      break;
    }
  }
  assert(data_sock > 0);

  /*
    eventually, set these up for ssl;

    extern int (*recv_fn)(char *target, int maxlen);
    extern int (*send_fn)(const char *target, int maxlen);
    extern int (*close_fn)(void);
  */
  if(USE_TCP) {
    recv_fn = recv_tcp;
    send_fn = send_tcp;
    close_fn = close_tcp;
  } else {
    // SSL

    data_ssl = SSL_new(server_ctx);
DUMP_ERRS();
    SSL_set_fd(data_ssl, data_sock);
DUMP_ERRS();
    SSL_accept(data_ssl);
DUMP_ERRS();

    recv_fn = recv_ssl;
    send_fn = send_ssl;
    close_fn = close_ssl;
  }

  printf("Got connection\n");

#ifndef __LINUX__
  char *r_cmd_str;
  char *args[1];
  args[0] = malloc(80);
  sprintf(args[0], "%d", WrapStream_server_port_num);

  printf("Forking subprocess\n");

  if( (g_child_ipd = run_program(prog_name, 1, args, &r_cmd_str)) <= 0) {
    printf("Could not start '%s'!\n", prog_name);
    exit(-1);
  }

  // this one also becomes a processing thread
  processing_loop_ipc((void*)i);
  exit(0);
#else
  int data = 0xdeadbeef;

  if( (err = recv_fn((char *)&data, sizeof(data))) != sizeof(data)) {
    printf("Receive error!\n");
    int extended_err = SSL_get_error(data_ssl, err);
    ERR_print_errors_fp(stdout);
    printf("Extended ssl err = %x\n", extended_err);
    printf("Probably bad data is %x\n", data);
    exit(-1);
  }
  printf("SSL received %d\n", data);
  exit(0);
#endif // __LINUX__
}

#ifndef __LINUX__
int run_program(char *program, int ac, char **av, char **r_cmdstr) {
  int elflen;
  unsigned char *elf = read_file_dir("/nfs", program, &elflen);
  if (!elf) {
    printf("command not found: %s\n", program);
    return -1;
  }
#if 0
  char *cmdstr = *r_cmdstr = malloc(1024);
  sprintf(cmdstr, "/nfs/%s", program);
  char argstr[1024];
  // new style  fork, with multiple argument parsing. not yet backported
  int i, arglen = 0;
  for (i = 0; i < ac; i++) {
    sprintf(cmdstr+strlen(cmdstr), " '%s'", av[i]);
    strcpy(argstr+arglen, av[i]);
    arglen += strlen(av[i]) + 1;
  }
  assert(arglen < 1024);
  IPD_ID child = IPC_FromElf(program, strlen(program)+1, elf, elflen, argstr, arglen);
  return child;
#else
  char *argstr;
  int arglen;
  assert(ac <= 1);
  if(ac == 0) {
    argstr = NULL;
    arglen = 0;
  } else {
    argstr = av[0];
    arglen = strlen(argstr) + 1;
  }
  printf("arg = %s, arglen = %d\n", argstr, arglen);
  IPD_ID child = IPC_FromElf(program, strlen(program)+1, elf, elflen, argstr, arglen);
  return child;
#endif
}
#endif
