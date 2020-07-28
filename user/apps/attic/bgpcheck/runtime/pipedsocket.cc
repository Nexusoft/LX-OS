#include <iostream>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>
#include <assert.h>
#include <openssl/err.h>
extern "C" {
#include <nexus/Thread.interface.h>
}

#include "../include/runtime/runtime.h"
#include "../include/runtime/pipedsocket.h"
#include "../include/util/common.h"
#include "../include/util/safe_malloc.h"

void start_pipedsocketthread(Pipedsocket *sock){
  sock->reader_thread();
}

Pipedsocket::Pipedsocket(unsigned int _host, int _port, pipedsocket_ready_callback *_cback, void *_userdata){
  sock = -1;
  host = _host;
  port = _port;
  cback = _cback;
  closed_cback = NULL;
  userdata = _userdata;
  w_pipe = NULL;
  pipe = new Minipipe();
  ready = 0;
  initialize_all();
}
Pipedsocket::Pipedsocket(int _sock, pipedsocket_ready_callback *_cback, void *_userdata){
  sock = _sock;
  host = 0;
  port = 0;
  cback = _cback;
  closed_cback = NULL;
  userdata = _userdata;
  w_pipe = NULL;
  pipe = new Minipipe();
  ready = 0;
  initialize_all();
}
Pipedsocket::Pipedsocket(int _sock){
  sock = _sock;
  host = 0;
  port = 0;
  cback = NULL;
  closed_cback = NULL;
  userdata = NULL;
  w_pipe = NULL;
  pipe = new Minipipe();
  ready = 0;
}
void Pipedsocket::set_closed_cback(pipedsocket_ready_callback *_cback, void *_userdata){
  closed_cback = _cback;
  closed_userdata = _userdata;
}

Pipedsocket::~Pipedsocket(){
  
}
void Pipedsocket::initialize_all(){
  //  printf("Creating thread!\n");
  pthread_create(&reader, NULL, (void*(*)(void*))start_pipedsocketthread, this);
  //  printf("Done creating!\n");
}

struct PipedsocketSignalData {
  Minipipe *pipe;
  Pipedsocket *sock;
  
  PipedsocketSignalData(Pipedsocket *_sock, Minipipe *_pipe) : pipe(_pipe), sock(_sock) {}
};

void Pipedsocket_Write_Signal(PipedsocketSignalData *data){
  char *buff;
  int len;
  
  if((len = data->pipe->read(&buff)) > 0){
    data->sock->write_sock(len, buff);
  }
}

Minipipe *Pipedsocket::write_pipe(){
  return write_pipe(NULL);
}
Minipipe *Pipedsocket::write_pipe(Runtime *r){
  if(!w_pipe){
    w_pipe = new Minipipe();
    w_pipe->set_signal((minipipe_signal)&Pipedsocket_Write_Signal, new PipedsocketSignalData(this, w_pipe));
  }
  return w_pipe;
}

Minipipe *Pipedsocket::read_pipe(){
  return pipe;
}

int Pipedsocket::write_sock(int len, char *buff){
  assert(ready);
  return write(sock, buff, len);
}

int Pipedsocket::closed(){
  return sock < 0;
}
void Pipedsocket::reader_thread(){
  int len;
  char data[500];
  int err;
  
  //is the socket open
  //  printf("reader thread!\n");
  if(sock < 0){
    sockaddr_in saddr;
    memset(&saddr, 0, sizeof(struct sockaddr_in));
    
    //    printf("Getting socket: %d\n", sock);
    sock = socket(PF_INET, SOCK_STREAM, 0);
    if(sock < 0){
      return;
    }
    //    printf("Connecting socket : %d\n", sock);
    saddr.sin_port = htons(port);
    saddr.sin_addr.s_addr = host;
    saddr.sin_family = AF_INET;
    if((err = connect(sock, (struct sockaddr *)&saddr, sizeof(sockaddr_in))) < 0){
      perror("error!\n");
      printf("Uh, oh: %08x:%d (%d)\n", host, port, errno);
      close(sock);
      sock = -1;
      return;
    }

    //    printf("Socket Connected\n");
  }
  
  //those should block, so we've now got a nice happy ssl connection up.
  ready = 1;
  if(cback != NULL){
    cback(this, userdata);
  }
  
    //printf("Callback done\n");
  
  //and start processing
  while(sock >= 0){
    len = read(sock, data, sizeof(data));
    if(len > 0){
      pipe->write(data, len);
    }
    if(len < 0){
      sock = len;
      break;
    }
  }
  if(closed_cback != NULL){
    closed_cback(this, closed_userdata);
  }
  while(1); //Nexus doesn't like thread death.
}

void Pipedsocket::close_sock(){
  int tmpsock = sock;
  sock = -1;
  close(tmpsock); 
}

