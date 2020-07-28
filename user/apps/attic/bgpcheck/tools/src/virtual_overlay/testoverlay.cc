#include <iostream>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <assert.h>

#include "../../../include/runtime/minisslsocket.h"
#define MY_AS 42
#define OTHER_AS 69

#define OVERLAY_MSG_RVQ 0
#define OVERLAY_MSG_JOIN 1
#define OVERLAY_MSG_WARN 2
#define OVERLAY_MSG_BADRVQ 3
#define OVERLAY_MSG_TRIGGER_WARNING 5

#pragma pack(push, 1)

struct overlay_msg_prefixpath {
  int type;
  int prefix;
  int prefixlen;
  int pathlen;
  unsigned short path[];
};

struct overlay_msg_join {
  int type;
  unsigned short as,port;
  unsigned int ip;
};

#pragma pack(pop)

Minisslsocketserver *server;
Minisslsocket *sock;

void build_prefix_strings();
int iteration_cnt = -1;
int iteration_total_cnt = -1;
struct timeval start_time;
int test_prefix_cnt;
unsigned int *test_prefix_addrs;
unsigned short *test_prefix_masks;

void send_rvq(Minipipe *pipe){
  int prefix = iteration_cnt % test_prefix_cnt;
  overlay_msg_prefixpath *prepath = (overlay_msg_prefixpath *)alloca(4 * sizeof(int) + 4 * sizeof(short));
  prepath->type = OVERLAY_MSG_TRIGGER_WARNING;
  prepath->prefix = test_prefix_addrs[prefix];
  prepath->prefixlen = test_prefix_masks[prefix];
  prepath->pathlen = 4;
  prepath->path[0] = 1;
  prepath->path[1] = 2;
  prepath->path[2] = 3;
  prepath->path[3] = 4;
  sock->write_sock(4 * sizeof(int) + 4 * sizeof(short), (char *)prepath);
}

struct timeval *timings;

int continue_test(Minipipe *pipe){
  if(iteration_cnt > 0){
    iteration_cnt--;
    gettimeofday(&timings[iteration_cnt],NULL);
    send_rvq(pipe);
    return 1;
  }
  if(iteration_cnt == 0){
    gettimeofday(&timings[iteration_cnt],NULL);
    int diff_sec, diff_usec;
    diff_sec = timings[iteration_cnt].tv_sec - start_time.tv_sec;
    if(timings[iteration_cnt].tv_usec >= start_time.tv_usec){
      diff_usec = timings[iteration_cnt].tv_usec - start_time.tv_usec;
    } else {
      diff_sec -= 1;
      diff_usec = 1000000 + timings[iteration_cnt].tv_usec - start_time.tv_usec;
    }
    printf("%d iterations: %d.%06d seconds\n", iteration_total_cnt, diff_sec, diff_usec);
    int i;
    FILE *datafile;
    datafile = fopen("timings.dump", "w");
    for(i = 0; i < iteration_total_cnt; i++){
      fprintf(datafile, "%ld.%06d\n", timings[i].tv_sec, (int)timings[i].tv_usec);
    }
    fclose(datafile);
  }
  return 0;
}

void start_test(int iterations){
  build_prefix_strings();
  gettimeofday(&start_time, NULL);
  iteration_total_cnt = iteration_cnt = iterations;
  timings = new struct timeval[iterations];
}

void pipe_data(Minipipe *pipe){
  char *data;
  overlay_msg_join *join;
  overlay_msg_prefixpath *error;
  int len;
  int x;

  len = pipe->read(&data);
  join = (overlay_msg_join *)data;

  switch(join->type){
  case OVERLAY_MSG_JOIN:
    assert(len == sizeof(overlay_msg_join));
    start_test(100000);
    if(continue_test(pipe)) break;
    printf("Got Join: 0x%08x:%d (AS %d)\n", join->ip, join->port, join->as);
    break;
  case OVERLAY_MSG_WARN:
  case OVERLAY_MSG_BADRVQ:
    assert(len >= (int)sizeof(overlay_msg_prefixpath));
    error = (overlay_msg_prefixpath *)data;
    if(continue_test(pipe)) break;
    printf("Got Warning: 0x%08x/%d", error->prefix, error->prefixlen);
    for(x = 0; x < error->pathlen; x++){
      printf(" [%d]", error->path[x]);
    }
    printf("\n");
    break;
  }

  free(data);
}

void socket_accepted(Minisslsocket *_sock, void *dummy){
  Minipipe *pipe;
  sock = _sock;

  pipe = sock->read_pipe();
  pipe->set_signal((minipipe_signal)&pipe_data, pipe);
}

void socket_ready(Minisslsocket *_sock, void *dummy){
  sock = _sock;
  printf("Got connection!\n");
  sock->accept(&socket_accepted, NULL);
  printf("Accepted connection!\n");
}

void start_server(char *addy){
  init_minisslsocket();

  if(addy == NULL){
    server = new Minisslsocketserver(52982);
  
    server->start_listen(&socket_ready, NULL);
  } else {
    sock = new Minisslsocket(inet_addr(addy), 52982, &socket_accepted, NULL);
  }
  
  while(1);
}

#ifndef DONT_USE_TEST_OVERLAY_MAIN

int main(int argc, char **argv){
  if(argc <= 1){
    start_server(NULL);
  } else {
    start_server(argv[1]);
  }
  return 0;
}

#endif

char *test_prefix_strings[] = {
"116.92.0.0/16","199.63.1.0/24","199.63.3.0/24","202.0.161.0/24","202.14.68.0/24","202.64.0.0/16","202.64.0.0/18","202.64.10.0/24","202.64.16.0/20","202.64.21.0/24","202.64.25.0/24","202.64.32.0/20","202.64.33.0/24","202.64.34.0/24","202.64.36.0/24","202.64.41.0/24","202.64.47.0/24","202.64.48.0/20","202.64.50.0/24","202.64.51.0/24","202.64.52.0/24","202.64.56.0/24","202.64.59.0/24","202.64.61.0/24","202.64.64.0/19","202.64.64.0/20","202.64.64.0/24","202.64.70.0/24","202.64.78.0/24","202.64.80.0/20","202.64.83.0/24","202.64.85.0/24","202.64.89.0/24","202.64.90.0/24","202.64.93.0/24","202.64.96.0/19","202.64.97.0/24","202.64.101.0/24","202.64.102.0/24","202.64.103.0/24","202.64.105.0/24","202.64.109.0/24","202.64.112.0/20","202.64.112.0/24","202.64.116.0/24","202.64.119.0/24","202.64.122.0/24","202.64.128.0/17","202.64.128.0/19","202.64.129.0/24","202.64.131.0/24","202.64.132.0/24","202.64.133.0/24","202.64.137.0/24","202.64.139.0/24","202.64.142.0/24","202.64.143.0/24","202.64.147.0/24","202.64.148.0/24","202.64.158.0/24","202.64.159.0/24","202.64.160.0/20","202.64.161.0/24","202.64.167.0/24","202.64.182.0/24","202.64.185.0/24","202.64.186.0/24","202.64.187.0/24","202.64.188.0/24","202.64.192.0/18","202.64.192.0/24","202.64.205.0/24","202.64.206.0/24","202.64.213.0/24","202.64.224.0/24","202.64.227.0/24","202.64.228.0/24","202.64.229.0/24","202.64.230.0/24","202.64.231.0/24","202.64.247.0/24","202.64.248.0/24","202.69.0.0/22","202.73.240.0/20","202.73.240.0/24","202.73.241.0/24","202.73.242.0/24","202.73.243.0/24","202.73.244.0/24","202.73.248.0/24","202.73.249.0/24","202.73.251.0/24","202.73.252.0/24","202.73.253.0/24","202.134.60.0/22","210.17.128.0/17","210.17.128.0/19","210.17.128.0/20","210.17.128.0/24","210.17.132.0/24","210.17.135.0/24","210.17.136.0/24","210.17.139.0/24","210.17.140.0/24","210.17.143.0/24","210.17.144.0/20","210.17.155.0/24","210.17.157.0/24","210.17.159.0/24","210.17.160.0/19","210.17.166.0/24","210.17.168.0/24","210.17.172.0/24","210.17.173.0/24","210.17.192.0/20","210.17.192.0/22","210.17.199.0/24","210.17.200.0/22","210.17.225.0/24","210.17.231.0/24","210.17.232.0/24","210.17.238.0/24","210.17.242.0/24","210.17.243.0/24","210.17.250.0/24","210.17.253.0/24","220.232.128.0/17","220.232.128.0/20","220.232.129.0/24","220.232.131.0/24","220.232.136.0/24","220.232.140.0/24","220.232.142.0/24","220.232.148.0/24","220.232.176.0/20","220.232.178.0/24","220.232.184.0/24","220.232.187.0/24","220.232.190.0/24","220.232.191.0/24","220.232.192.0/18","220.232.192.0/24","220.232.193.0/24","220.232.194.0/24","220.232.196.0/24","220.232.197.0/24","220.232.198.0/24","220.232.200.0/24","220.232.202.0/24","220.232.204.0/24","220.232.209.0/24","220.232.215.0/24","220.232.216.0/24","220.232.224.0/24","220.232.231.0/24","220.232.240.0/24","220.232.241.0/24","220.232.252.0/24"};

void build_prefix_strings(){
  test_prefix_cnt = sizeof(test_prefix_strings)/sizeof(test_prefix_strings[0]);
  test_prefix_addrs = new unsigned int[test_prefix_cnt];
  test_prefix_masks = new unsigned short[test_prefix_cnt];
  unsigned int a, b, c, d, mask;
  for(int i = 0; i < test_prefix_cnt; i++){
    sscanf(test_prefix_strings[i], "%d.%d.%d.%d/%d", &a, &b, &c, &d, &mask);
    test_prefix_masks[i] = mask;
    test_prefix_addrs[i] = ((a & 0xff) << 24) | ((b & 0xff) << 16) | ((c & 0xff) << 8) | ((d & 0xff) << 0);
    printf("Loaded test peer %x/%d\n", test_prefix_addrs[i], test_prefix_masks[i]);
  }
}
