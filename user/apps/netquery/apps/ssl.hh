#ifndef _SSL_HH_
#define _SSL_HH_

#include <openssl/ssl.h>
#include <assert.h>
#include <netinet/in.h>
#include <vector>

#include "eventxx"
#include <iostream>
#include <nq/util.hh>

#define SKIP(X) do { std::cerr << "Not doing " << #X << "\n"; } while(0)
#define THROW(X) do { std::cerr << "Throwing \"" << X << "\"\n"; throw X; } while(0)

struct SSL_Listener;
struct SSL_Connection;

template <typename CB>
static inline void register_ssl_once(SSL_Connection *c, int ssl_err, CB &cb);

struct SSL_Connection {
  int m_fd;
  SSL *m_ssl;
  eventxx::dispatcher *m_dispatcher;
  struct sockaddr_in m_peer_addr;
  int m_last_err;

  bool m_blocking;

  struct VerifyInfo {
    std::vector<X509*> cert_chain;
  } verify_info;

protected:
  SSL_Connection(SSL_CTX *ctx, eventxx::dispatcher *dispatcher, int fd, const struct sockaddr_in &addr, bool blocking = false);
public:
  virtual ~SSL_Connection();

  int write(const void *dest, int len);
  int read(void *dest, int len);
  int read(DataBuffer *data_buf, int len); // appends to end of data buffer
  int shutdown();

  int get_error();

  X509 *get_peer_certificate(void);
  int get_verify_result(void);
};

struct SSL_ServerConnection : SSL_Connection {
  SSL_ServerConnection(SSL_Listener *parent, int fd, const struct sockaddr_in &addr, bool blocking);
  virtual ~SSL_ServerConnection();

  typedef void (SSL_ServerConnection::* EventHandler)(int, eventxx::type);
  typedef struct eventxx::mem_cb<SSL_ServerConnection, EventHandler> EventCallback;
  EventCallback m_continue_accept_callback;

  SSL_Listener *m_parent; // parent is only valid during accept handshake
  void continue_accept();
  void continue_accept_event(int fd, eventxx::type type);
};

struct SSL_ClientConnection : SSL_Connection {
  SSL_ClientConnection(eventxx::dispatcher *dispatcher, int fd, const struct sockaddr_in &addr, bool blocking);
  virtual ~SSL_ClientConnection();

  typedef void (SSL_ClientConnection::* EventHandler)(int, eventxx::type);
  typedef struct eventxx::mem_cb<SSL_ClientConnection, EventHandler> EventCallback;
  EventCallback m_continue_connect_callback;

  int connect();
  void continue_connect();
  void continue_connect_event(int fd, eventxx::type type);

  virtual void connected() = 0;
};

struct SSL_Listener {
  int m_fd;
  eventxx::dispatcher *m_dispatcher;

  SSL_Listener(int fd, eventxx::dispatcher *dispatcher);
  virtual ~SSL_Listener();
  
  typedef struct eventxx::mem_cb<SSL_Listener, void (SSL_Listener::*)(int, eventxx::type)> EventCallback;

  EventCallback m_listen_callback;
  eventxx::event<EventCallback> m_listen_event;

  void new_connection_handler(int fd, eventxx::type type); // this is tied to eventxx::READ on the listen socket

  // upcall
  virtual void accepted_connection(SSL_ServerConnection *new_conn) = 0;
};

template <typename CB>
static inline void register_ssl_once(SSL_Connection *c, int ssl_err, CB &cb) {
  int val = 0;
  switch(ssl_err) {
  case SSL_ERROR_WANT_READ:
    val = eventxx::READ;
    break;
  case SSL_ERROR_WANT_WRITE:
    val = eventxx::WRITE;
    break;
  default:
    assert(0);
  }
  assert(val != 0);
  std::cerr << "Adding callback at fd=" << c->m_fd << " val= " << val << " " << &cb << " to " << c->m_dispatcher << "\n";
  c->m_dispatcher->add_once(c->m_fd, (eventxx::type)val, cb);
}

void ssl_init(void);

extern bool g_dbg_omit_nsk;
extern bool g_ssl_always_accept;

X509 *pem2x509(const unsigned char *pem, int len);
void x509_to_pem(X509 *x509, DataBuffer &d);

#endif // _SSL_HH_
