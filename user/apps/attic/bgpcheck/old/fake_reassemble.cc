#include <iostream>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "fake_reassemble.h"
#include "g_tl.h"
#include "safe_malloc.h"
#include "reassemble.h"
#include "common.h"

Reassemble_Faker::Reassemble_Faker(Minipipe *pipe, unsigned int src_ip, int src_port)
{
  outpipe = pipe;
  printf("Connecting to : "); print_ip(src_ip, 1); printf(":%d\n", src_port);
  create_minisock(src_ip, src_port, 0);//no SSL on this socket
  ip = src_ip;
  port = (unsigned short)src_port;
}

void Reassemble_Faker::handle_minipipe(Minipipe *pipe, Runtime *runtime){
  char *data;
  int len;
  char *buffer;
  Flow flow;
  flow.from.addr.s_addr = ip;
  flow.from.port = port;
  flow.to.addr.s_addr = ip;
  flow.to.port = port;

  len = pipe->read(&data);

  printf("BGP source sent %d bytes\n");

  buffer = (char *)safe_malloc(sizeof(char) * len + sizeof(Flow) + sizeof(int));
  memcpy(&(buffer[0]), &flow, sizeof(flow));
  memcpy(&(buffer[sizeof(Flow)]), &len, sizeof(int));
  memcpy(&(buffer[sizeof(Flow) + sizeof(int)]), data, sizeof(char) * len);

  outpipe->write_malloced(buffer, len*sizeof(char) + sizeof(Flow) + sizeof(int));
  safe_free(data);
}
void Reassemble_Faker::handle_sockready(Minisocket *sock, Runtime *runtime){
  printf("Connected to the bgp source\n");
  //we don't particularly care about this... we're reading only
}
