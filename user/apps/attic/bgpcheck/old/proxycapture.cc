#include <iostream>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "g_tl.h"
#include "tunnel.h"
#include "proxycapture.h"
#include "minipipe.h"
#include "reassemble.h"
#include "nbgp.h"

void tunnel_data(Tunnel *t, unsigned int sender, void *data, int datalen){
  ((BGP_Peer *)t->userdata())->process_in_packet((char *)data, datalen);

  // void *buff = malloc(datalen + sizeof(Flow) + sizeof(int));
//   void *databuff = &(((char *)buff)[sizeof(Flow) + sizeof(int)]);
//   int *size = (int *)&(((char *)buff)[sizeof(Flow)]);
//   Flow *flow = (Flow *)buff;

//   if(t->get_peer1() == sender){
//     flow->from.addr.s_addr = t->get_peer1();
//     flow->from.port = t->get_peer1port();
//     flow->to.addr.s_addr = t->get_peer2();
//     flow->to.port = t->get_peer2port();
//   } else {
//     flow->to.addr.s_addr = t->get_peer1();
//     flow->to.port = t->get_peer1port();
//     flow->from.addr.s_addr = t->get_peer2();
//     flow->from.port = t->get_peer2port();
//   }

//   *size = datalen;
//   memcpy(databuff, data, datalen);

//   ((Minipipe *)t->userdata())->write_malloced((char *)buff, datalen+sizeof(Flow)+sizeof(int));
}

void tunnel_poll(Tunnel *t){
  t->loop();
}
