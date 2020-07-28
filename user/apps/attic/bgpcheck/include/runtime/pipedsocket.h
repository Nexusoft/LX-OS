#ifndef PIPEDSOCKET_H_SHIELD
#define PIPEDSOCKET_H_SHIELD

#include "../runtime/minipipe.h"
#include <openssl/ssl.h>

class Pipedsocket;
class Runtime;

typedef void (pipedsocket_ready_callback)(Pipedsocket *sock, void *userdata);

class Pipedsocket {
  public:
    Pipedsocket(unsigned int host, int port, pipedsocket_ready_callback *cback, void *_userdata);
    Pipedsocket(int _sock, pipedsocket_ready_callback *cback, void *_userdata);
    
    //this constructor doesn't automatically rev up the reader thread.
    //when using it, you MUST call initialize_all() before expecting to read anything.
    Pipedsocket(int _sock);
    ~Pipedsocket();
    
    void set_closed_cback(pipedsocket_ready_callback *_cback, void *_userdata);
    
    Minipipe *read_pipe();
    Minipipe *write_pipe();
    Minipipe *write_pipe(Runtime *r);
    int write_sock(int len, char *buff);
    
    void initialize_all();
    void reader_thread();
    
    void close_sock();

    int closed();
   
  private:
    int sock;
    pthread_t reader;
    Minipipe *pipe, *w_pipe;
    unsigned int host;
    int port;
    int ready;
    pipedsocket_ready_callback *cback;
    pipedsocket_ready_callback *closed_cback;
    void *userdata;
    void *closed_userdata;
};

#endif
