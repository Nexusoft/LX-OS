#ifndef MINISOCKET_H_SHIELD
#define MINISOCKET_H_SHIELD

#include "minipipe.h"
#include <openssl/ssl.h>

void init_minisslsocket();

class Minisslsocket;

typedef void (minissl_ready_callback)(Minisslsocket *sock, void *userdata);

class Minisslsocket {
  public:
    Minisslsocket(unsigned int host, int port, minissl_ready_callback *cback, void *_userdata);
    Minisslsocket(int _sock);
    ~Minisslsocket();
    
    void accept(minissl_ready_callback *cback, void *_userdata);
    
    Minipipe *read_pipe();
    int write_sock(int len, char *buff);
    
    void initialize_all();
    void reader_thread();
    
    int closed();
    
  private:
  	int sock;
	SSL *conn;
	pthread_t reader;
	Minipipe *pipe;
	unsigned int host;
	int port;
	int ready;
	minissl_ready_callback *cback;
	void *userdata;
};

class Minisslsocketserver {
  public:
    Minisslsocketserver(int port);
    ~Minisslsocketserver();
	
    void start_listen(minissl_ready_callback *_cback, void *_userdata);
    void reader_thread();
    
  private:
  	int port;
	minissl_ready_callback *cback;
	void *userdata;
	pthread_t reader;
};

#endif
