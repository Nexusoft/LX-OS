#ifndef TUNNEL_HEADER_SHIELD
#define TUNNEL_HEADER_SHIELD

#include "socket.h"

#define MD5TCP_MAX_SIZE 8192

class Tunnel;

typedef void (*tunnel_data_callback)(Tunnel *sock, unsigned int sender, void *data, int datalen);

class Tunnel {
 public:
  Tunnel();
  
  void set_peer1(unsigned int peer, unsigned short port);
  void set_peer2(unsigned int peer, unsigned short port);
  void set_self(unsigned short port);
  void set_callback(tunnel_data_callback _cback);

  void set_userdata(void *_userdata);
  void *userdata();
  
  void poll();
  void loop();

  unsigned int get_peer1();
  unsigned short get_peer1port();
  unsigned int get_peer2();
  unsigned short get_peer2port();
  
 private:
  void *userdata_v;
  unsigned int myport;
  unsigned int peer1;
  unsigned short peer1Port;
  unsigned int peer2;
  unsigned short peer2Port;
  char *buff;

  tunnel_data_callback cback;
  
  Socket *sock1, *sock2, *listensock;
};



#endif
