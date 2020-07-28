#include <iostream>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>
#include "../include/runtime/socket.h"

Socket::Socket(){
  peer = 0;
  port = 0;
  closed = 1;
  sock = -1;
  polldata = NULL;
}
Socket::~Socket(){
  if(sock > 0){
    close_s();
  }
}

void Socket::set_polldata(struct pollfd *_polldata){
  polldata = _polldata;
  if(polldata){
    polldata->fd = sock;
    polldata->events = POLLRDNORM | POLLWRNORM | POLLERR | POLLHUP;
  }
}

short Socket::check_polldata(short event, short def){
  if(polldata)
    return polldata->revents & event;
  else
    return def;
}

int Socket::accept_s(unsigned short _port){
  struct sockaddr_in saddr;
  socklen_t addrlen = sizeof(struct sockaddr_in);
  int err;
  int srv;
  
  if((srv = socket(PF_INET, SOCK_STREAM, 0)) < 0){
    return srv;
  }
  memset(&saddr, 0, sizeof(sockaddr_in));
  saddr.sin_family = AF_INET;
  saddr.sin_port = htons(_port);
  saddr.sin_addr.s_addr = INADDR_ANY;
  printf("binding!");
  if((err = bind(srv, (struct sockaddr *)&saddr, sizeof(struct sockaddr_in))) < 0){
    printf("Bind failed!\n");
    return err;
  }
  if((err = listen(srv, 1)) < 0){
    printf("Listen failed!\n");
    return err;
  }
  printf("Starting accept on port %d\n", _port);
  while((sock = accept(srv, (struct sockaddr *)&saddr, &addrlen)) < 0) {
    addrlen = sizeof(struct sockaddr_in);
    sleep(5);
  }
  printf("accept done!\n");

//   if((sock = accept(srv, (struct sockaddr *)&saddr, &addrlen)) < 0){
//     return sock;
//   }
  
  close(srv);
  
  peer = saddr.sin_addr.s_addr;
  port = saddr.sin_port;
  
  closed = 0;
  //  fcntl(sock, F_SETFL, O_NONBLOCK);
  
  return 0;
}
int Socket::connect_s(unsigned int _peer, unsigned short _port){
  struct sockaddr_in saddr;
  int err;
  
  if((sock = socket(PF_INET, SOCK_STREAM, 0)) < 0){
    return sock;
  }
  memset(&saddr, 0, sizeof(sockaddr_in));
  saddr.sin_family = AF_INET;
  saddr.sin_port = port = htons(_port);
  saddr.sin_addr.s_addr = peer = _peer;
  if((err = connect(sock, (struct sockaddr *)&saddr, sizeof(struct sockaddr_in))) != 0){
    return err;
  }
  closed = 0;
  //  fcntl(sock, F_SETFL, O_NONBLOCK);
  return 0;
}
int Socket::send_s(void *data, int len){
  int sent, tot = 0;
  while(check_polldata(POLLWRNORM, 1) && (len > 0) && !eof()){
    sent = send(sock, data, len, 0);
    if(sent > 0){
      data = &(((char *)data)[sent]);
      len -= sent;
      tot += sent;
    } else {
      printf("error in send!\n");
      close_s();
      tot = -1;
    }
  }
  return tot;
}
int Socket::recv_s(void *buff, int buffsz){
  int recved = 0;
  //  printf("Recv: %d, %d, %d; ", check_polldata(POLLRDNORM, 1), !eof(), (recved == 0));
  //  while(check_polldata(POLLRDNORM, 1) && !eof() && (recved == 0)){
  recved = recv(sock, buff, buffsz, 0);
    //  }
  //printf("done: %d\n", recved);
  return recved;
}
int Socket::close_s(){
  int ret = close(sock);
  closed = 1;
  return ret;
}

unsigned int Socket::get_peer(){
  return peer;
}
unsigned short Socket::get_port(){
  return port;
}

int Socket::eof(){
  if(!closed && check_polldata(POLLERR | POLLHUP, 0)){
    close_s();
  }
  return closed;
}
