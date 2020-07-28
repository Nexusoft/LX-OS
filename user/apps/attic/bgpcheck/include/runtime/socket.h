#ifndef SOCKET_HEADER_SHIELD
#define SOCKET_HEADER_SHIELD

#include <poll.h>

class Socket {
 public:
	Socket();
  virtual ~Socket();
	
	void set_polldata(struct pollfd *_polldata);
	short check_polldata(short event, short def);
	
  virtual int accept_s(unsigned short _port);
  virtual int connect_s(unsigned int _peer, unsigned short _port);
  virtual int send_s(void *data, int len);
  virtual int recv_s(void *buff, int buffsz);
  virtual int close_s();
  
  unsigned int get_peer();
  unsigned short get_port();
  
  int eof();

 protected:
  unsigned int peer;
  unsigned short port;
  int closed;
  struct pollfd *polldata;
  
  int sock;
};

#endif
