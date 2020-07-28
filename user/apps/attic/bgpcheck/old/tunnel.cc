#include <iostream>
#include "tunnel.h"
#include "common.h"

#define BUFFER_SIZE 1024

Tunnel::Tunnel(){
  set_peer1(0, 0);
  set_peer2(0, 0);
  set_self(0);
  set_callback(NULL);

  buff = (char *)malloc(BUFFER_SIZE);
  
  listensock = sock1 = sock2 = NULL;
}

void Tunnel::set_peer1(unsigned int peer, unsigned short port){
  peer1 = peer;
  peer1Port = port;
}
void Tunnel::set_peer2(unsigned int peer, unsigned short port){
  peer2 = peer;
  peer2Port = port;
}
void Tunnel::set_self(unsigned short port){
  myport = port;
}
void Tunnel::set_callback(tunnel_data_callback _cback){
  cback = _cback;
}

void Tunnel::poll(){
  if(sock1 == NULL){
    printf("Connecting to "); print_ip(peer1, 1); printf(": %d\n", peer1Port);
    sock1 = new Socket();
    assert(sock1->connect_s(peer1, peer1Port) == 0);
  }
  if(sock2 == NULL){
    printf("Connecting to "); print_ip(peer2, 1); printf(": %d\n", peer2Port);
    sock2 = new Socket();
    assert(sock2->connect_s(peer2, peer2Port) == 0);
  }

//   printf("poll!\n");
//   if(listensock == NULL){
//     listensock = new Socket();
//     assert(listensock->accept_s(myport) == 0);
//     if(listensock->get_peer() == peer1){
//       printf("Connected from peer 1: "); 
//       print_ip(listensock->get_peer(), 1); printf("->");
//       print_ip(peer2, 1); printf("\n");
//       sock1 = listensock;
//       sock2 = new Socket();
//       assert(sock2->connect_s(peer2, peer2Port) == 0);
//       printf("connected to peer 2\n");
//     } else if(listensock->get_peer() == peer2){
//       printf("Connected from peer 2: "); 
//       print_ip(listensock->get_peer(), 1); printf("->");
//       print_ip(peer1, 1); printf("\n");
//       sock2 = listensock;
//       sock1 = new Socket();
//       assert(sock1->connect_s(peer1, peer1Port) == 0);
//       printf("connected to peer 1\n");
//     } else {
//       printf("Connected from unknown peer: "); 
//       print_ip(listensock->get_peer(), 1); printf("->?\n");
//       printf("My known peers are: "); 
//       print_ip(peer1, 1); printf(" and ");
//       print_ip(peer2, 1); printf("\n");
//       delete listensock;
//       listensock = NULL;
//     }
//   } else {
  int len = BUFFER_SIZE;
    len = sock1->recv_s(buff, len);
    if(len > 0){
      //      printf("read %d bytes from 1\n", len);
      cback(this, peer1, buff, len);
      //            printf("writing to 2\n");
      sock2->send_s(buff, len);
      //            printf("wrote to 2\n");
    } else {
      if(sock1->eof()){
        delete sock1;
        delete sock2;
        listensock = sock1 = sock2 = NULL;
      }
    }
    len = BUFFER_SIZE;
    //    len = sock2->recv_s(buff, len);
    len = 0;
    if(len > 0){
      //printf("read %d bytes from 2\n", len);
      cback(this, peer2, buff, len);
      //printf("writing to 2\n");
      sock1->send_s(buff, len);
      //printf("wrote to 2\n");
    } else {
      if(sock2->eof()){
        delete sock1;
        delete sock2;
        listensock = sock1 = sock2 = NULL;
      }
    }    
//   }
}
void Tunnel::loop(){
  while(1) poll();
}

unsigned int Tunnel::get_peer1(){
  return peer1;
}
unsigned short Tunnel::get_peer1port(){
  return peer1Port;
}
unsigned int Tunnel::get_peer2(){
  return peer2;
}
unsigned short Tunnel::get_peer2port(){
  return peer2Port;
}

void Tunnel::set_userdata(void *_userdata){
  userdata_v = _userdata;
}
void *Tunnel::userdata(){
  return userdata_v;
}
