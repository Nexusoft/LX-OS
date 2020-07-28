#ifndef MINISOCKET_H_SHIELD
#define MINISOCKET_H_SHIELD

#include "../runtime/minipipe.h"
#include <openssl/ssl.h>

void init_minisocket();

class Minisocket;
class Runtime;

typedef void (minissl_ready_callback)(Minisocket *sock, void *userdata);

class Minisocket {
  public:
  Minisocket(unsigned int host, int port, minissl_ready_callback *cback, void *_userdata, int _ssl);
    Minisocket(int _sock);
    ~Minisocket();

    void accept(minissl_ready_callback *cback, void *_userdata, int _ssl);
    
    void set_closed_cback(minissl_ready_callback *_cback, void *_userdata);
    
    Minipipe *read_pipe();
    Minipipe *write_pipe(Runtime *r);
    int write_sock(int len, char *buff);
    
    void initialize_all();
    void reader_thread();
    
    void close_sock();

    int closed();
    
    //add a random chance for a delay after every message
    //time is in usec, chance is in 1/100 of a %.  (chance = 100 -> 1% of messages will be delayed)
    void debug_add_delay_chance(int _random_delay_offset, int _random_delay_time);
   
  private:
    int ssl;
    int sock;
    SSL *conn;
    BIO *io;
    pthread_t reader;
    Minipipe *pipe, *w_pipe;
    unsigned int host;
    int port;
    int ready;
    minissl_ready_callback *cback;
    minissl_ready_callback *closed_cback;
    void *userdata;
    void *closed_userdata;
    int random_delay_offset;
    int random_delay_time;
};

class Minisocketserver {
  public:
    Minisocketserver(int port);
    ~Minisocketserver();
	
    void start_listen(minissl_ready_callback *_cback, void *_userdata);
    void reader_thread();
    
  private:
  	int port;
	minissl_ready_callback *cback;
	void *userdata;
	pthread_t reader;
};

#endif
