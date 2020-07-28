#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>

#include <iostream>
#include <fstream>

#include "ssl.hh"
#include <nq/util.hh>

#ifndef __LINUX__
extern "C" {
#include <nexus/generaltime.h>
#include <nexus/vkey.h>
#include <nexus/env.h>
};
#endif // __LINUX__

#define CA_LIST "/nfs/CAfile.pem"

using namespace std;

bool g_dbg_omit_nsk = false;
bool g_ssl_always_accept = true;

const int BACKLOG = 10;

static SSL_CTX *server_ctx;
static SSL_CTX *client_ctx;

static int mydata_index = 0;

static int verify_callback(int preverify_ok, X509_STORE_CTX *ctx)
{
  // cerr << "Called verify_callback\n";
  char    buf[256];
  X509   *err_cert;
  int     err, depth;
  SSL    *ssl;
  SSL_Connection::VerifyInfo *mydata;

  err_cert = X509_STORE_CTX_get_current_cert(ctx);
  err = X509_STORE_CTX_get_error(ctx);
  depth = X509_STORE_CTX_get_error_depth(ctx);

  /*
   * Retrieve the pointer to the SSL of the connection currently treated
   * and the application specific data stored into the SSL object.
   */
  ssl = (SSL *) X509_STORE_CTX_get_ex_data(ctx, SSL_get_ex_data_X509_STORE_CTX_idx());
  mydata = (SSL_Connection::VerifyInfo *)SSL_get_ex_data(ssl, mydata_index);

  X509_NAME_oneline(X509_get_subject_name(err_cert), buf, 256);

  /*
   * Catch a too long certificate chain. The depth limit set using
   * SSL_CTX_set_verify_depth() is by purpose set to "limit+1" so
   * that whenever the "depth>verify_depth" condition is met, we
   * have violated the limit and want to log this error condition.
   * We must do it here, because the CHAIN_TOO_LONG error would not
   * be found explicitly; only errors introduced by cutting off the
   * additional certificates would be logged.
   */
#if 0
  if (depth > mydata->verify_depth) {
    preverify_ok = 0;
    err = X509_V_ERR_CERT_CHAIN_TOO_LONG;
    X509_STORE_CTX_set_error(ctx, err);
  }
#endif
  printf("\tdepth=%d:%s\n", depth, buf);
  mydata->cert_chain.resize( std::max( (size_t)(depth + 1), mydata->cert_chain.size() ) );
  mydata->cert_chain[depth] = err_cert;
  if (!preverify_ok) {
    printf("verify error:num=%d:%s\n", err,
	   X509_verify_cert_error_string(err));
  }

  /*
   * At this point, err contains the last verification error. We can use
   * it for something special
   */
  if (!preverify_ok && (err == X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT))
    {
      X509_NAME_oneline(X509_get_issuer_name(ctx->current_cert), buf, 256);
      printf("issuer= %s\n", buf);
    }

  if(!preverify_ok && g_ssl_always_accept) {
    printf("cert verification failed, but accepting anyway\n");
    return 1;
  }

  if (0) {
    printf("callback continuing\n");
    return 1;
  } else {
    return preverify_ok;
  }
}

static void print_ciphers(SSL *ssl) {
  int i;
  for(i=0; ; i++) {
    const char *n = SSL_get_cipher_list(ssl, i);
    if(n == NULL) {
      break;
    }
    cerr << "[" << i <<"] = " << n << "\n";
  }
}

SSL_Listener::SSL_Listener(int fd, eventxx::dispatcher *dispatcher) : 
  m_fd(fd), m_dispatcher(dispatcher),
  m_listen_callback(*this, &SSL_Listener::new_connection_handler),
  m_listen_event(m_fd, eventxx::READ | eventxx::PERSIST, m_listen_callback) {

  int rv = listen(fd, BACKLOG);
  assert(rv == 0);
  m_dispatcher->add(m_listen_event);
}

SSL_Listener::~SSL_Listener() {
  // do nothing
}

void SSL_Listener::new_connection_handler(int fd, eventxx::type type) {
  cerr << "new connection handler\n";
  assert(m_fd == fd);
  struct sockaddr_in addr;
  socklen_t len = sizeof(addr);
  int new_fd = accept(m_fd, (struct sockaddr *)&addr, &len);
  if(new_fd < 0) {
    cerr << "new_connection_handler(): no new connection\n";
    return;
  }
  SSL_ServerConnection *new_conn;

  new_conn = new SSL_ServerConnection(this, new_fd, addr, false);
  // don't call accepted() here ; that waits until after the server
  // connection finishes SSL accept
}

///////// SSL_Connection

SSL_Connection::SSL_Connection(SSL_CTX *ctx, eventxx::dispatcher *dispatcher, int fd, const struct sockaddr_in &addr, bool blocking) :
  m_fd(fd), m_ssl(NULL), m_dispatcher(dispatcher), m_peer_addr(addr), m_last_err(0), m_blocking(blocking) {
  m_ssl = SSL_new(ctx);
  if(SSL_set_fd(m_ssl, m_fd) == 0) {
    cerr << "error setting fd for SSL connection";
    THROW("error setting fd for SSL connection");
  }
  if(!m_blocking) {
    int err = fcntl(m_fd, F_SETFL, O_NONBLOCK);
    assert(err == 0);
  }
  SSL_set_ex_data(m_ssl, 0, &verify_info);
}

SSL_Connection::~SSL_Connection() {
  // do nothing
}

int SSL_Connection::write(const void *dest, int len) {
  return m_last_err = SSL_write(m_ssl, dest, len);
}
int SSL_Connection::read(void *dest, int len) {
  return m_last_err = SSL_read(m_ssl, dest, len);
}
int SSL_Connection::read(DataBuffer *data_buf, int len) {
  size_t orig_size = data_buf->size();
  data_buf->resize(orig_size + len);
  int read_len = read(&*(data_buf->end() - len), len);
  if(read_len <= 0) {
    data_buf->resize(orig_size);
  } else {
    data_buf->resize(read_len);
  }
  return read_len;
}
int SSL_Connection::shutdown() {
  return m_last_err = SSL_shutdown(m_ssl);
}
int SSL_Connection::get_error() {
  return SSL_get_error(m_ssl, m_last_err);
}

X509 *SSL_Connection::get_peer_certificate(void) {
  return SSL_get_peer_certificate(m_ssl);
}

int SSL_Connection::get_verify_result(void) {
  return SSL_get_verify_result(m_ssl);
}

///////// SSL_ServerConnection

SSL_ServerConnection::SSL_ServerConnection(SSL_Listener *parent, int fd, const struct sockaddr_in &addr, bool blocking) : 
  SSL_Connection(server_ctx, parent->m_dispatcher, fd, addr, blocking),
  m_continue_accept_callback(*this, &SSL_ServerConnection::continue_accept_event),
  m_parent(parent)
{
  continue_accept();
}

SSL_ServerConnection::~SSL_ServerConnection() {
  // do nothing
}

void SSL_ServerConnection::continue_accept_event(int fd, eventxx::type) {
  cerr << "continue accept\n";
  continue_accept();
}

void SSL_ServerConnection::continue_accept(void) {
  int err = SSL_accept(m_ssl);
  if(err == 1) {
    m_parent->accepted_connection(this);
  } else {
    int extended_err = SSL_get_error(m_ssl, err);
    switch(extended_err) {
    case SSL_ERROR_WANT_READ:
    case SSL_ERROR_WANT_WRITE:
      register_ssl_once(this, extended_err, m_continue_accept_callback);
      break;
    default: {
      ERR_print_errors_fp(stderr);
      print_ciphers(m_ssl);
      cerr << " accept err " << extended_err << "\n";
      THROW("continue accept event error");
    }
    }
  }
}

///////// SSL_ClientConnection

SSL_ClientConnection::SSL_ClientConnection(eventxx::dispatcher *dispatcher, int fd, const struct sockaddr_in &addr, bool blocking) :
  SSL_Connection(client_ctx, dispatcher, fd, addr, blocking),
  m_continue_connect_callback(*this, &SSL_ClientConnection::continue_connect_event) {
  connect();
}

SSL_ClientConnection::~SSL_ClientConnection() {
  // do nothing
}

int SSL_ClientConnection::connect(void) {
  return SSL_connect(m_ssl);
}

void SSL_ClientConnection::continue_connect(void) {
  int err = SSL_connect(m_ssl);
  if(err == 1) {
    connected();
  } else {
    assert(!m_blocking); // should not get error in blocking code
    int extended_err = SSL_get_error(m_ssl, err);
    switch(extended_err) {
    case SSL_ERROR_WANT_READ:
    case SSL_ERROR_WANT_WRITE:
      register_ssl_once(this, extended_err, m_continue_connect_callback);
      break;
    default:
      ERR_print_errors_fp(stderr);
      THROW("continue connect event error");
    }
  }
}

void SSL_ClientConnection::continue_connect_event(int fd, eventxx::type type) {
  assert(fd == m_fd);
  continue_connect();
}

void cerr_exit(const char *s) {
  cerr << s;
  exit(-1);
}

static int password_cb(char *buf,int num,
		       int rwflag,void *userdata)
{
  const char *pass = "foobar";
  if(num < (int) (strlen(pass)+1) )
    return(0);

  strcpy(buf,pass);
  return(strlen(pass));
}

#define ERROR() do { cerr << "Error at " << __LINE__ << "\n"; } while(0)

EVP_PKEY *pem2key(unsigned char *pem){
  BIO *tmp = BIO_new_mem_buf(pem, -1);
  EVP_PKEY *ret = PEM_read_bio_PrivateKey(tmp, NULL, NULL, NULL);
  BIO_free(tmp);
  return ret;
}

X509 *pem2x509(const unsigned char *pem, int len){
  BIO *tmp = BIO_new_mem_buf((unsigned char *)pem, len);
  X509 *ret = PEM_read_bio_X509(tmp, NULL, NULL, NULL);
  BIO_free(tmp);
  return ret;
}

X509 *pem2x509(const DataBuffer &d){
  return pem2x509(vector_as_ptr(d), d.size());
}

void x509_to_pem(X509 *x509, DataBuffer &d) {
  BIO *tmp = BIO_new(BIO_s_mem());
  if(!PEM_write_bio_X509(tmp, x509)) {
    cerr << "Could not convert x509 to PEM!\n";
    assert(0);
  }
  char *p;
  long len = BIO_get_mem_data(tmp, &p);
  vector_push(d, (unsigned char *)p, len);
  BIO_free(tmp);
}

static void load_linux_keys(void) {
  const char *cert_file = "spamfree.crt";
  const char *privkey_file = "spamfree.key";

  /* Load our keys and certificates*/
  if(!(SSL_CTX_use_certificate_chain_file(server_ctx, cert_file)))
    cerr_exit("Can't read certificate file");

  SSL_CTX_set_default_passwd_cb(server_ctx, password_cb);
  if(!(SSL_CTX_use_PrivateKey_file(server_ctx, privkey_file,SSL_FILETYPE_PEM)))
    cerr_exit("Can't read key file");
}

static inline void read_file_all(const char *filename, DataBuffer *d) {
  const int CHUNK_SIZE = 1024;
  cerr << "Reading from " << filename << "\n";
  ifstream ifs(filename);
  if(!ifs.good()) {
    cerr << "Could not open " << filename << "\n";
    THROW("Could not open file!\n");
  }
  while(!ifs.eof()) {
    d->resize(d->size() + CHUNK_SIZE);
    ifs.read((char *)&*(d->end() - CHUNK_SIZE), CHUNK_SIZE);
    int amount = ifs.gcount();
    d->resize(d->size() - (CHUNK_SIZE - amount));
  }
  ifs.close();
}

static inline void write_file_all(const char *filename, const unsigned char *data, int len) {
  cerr << "Writing to " << filename << "\n";
  ofstream ofs(filename);
  if(!ofs.good()) {
    cerr << "Could not open " << filename << " for write\n";
    THROW("Could not open!\n");
  }
  ofs.write((const char *)data, len);
  ofs.close();
}

#ifndef __LINUX__
static void load_nexus_keys(void) {
  // Get NSK 
  DataBuffer nsk_crt_pem;
  DataBuffer nsk_ser;
  DataBuffer ca_crt_pem;
  DataBuffer nexusca_crt_pem;
  read_file_all("/nfs/nexus.nsk.crt", &nsk_crt_pem);
  read_file_all("/nfs/nexus.nsk", &nsk_ser);
  read_file_all("/nfs/ca.crt", &ca_crt_pem);
  read_file_all("/nfs/nexusca.crt", &nexusca_crt_pem);

  X509 *nsk_crt = pem2x509(nsk_crt_pem);
  VKey *nsk_vkey = vkey_deserialize( (char *)vector_as_ptr(nsk_ser), nsk_ser.size() );
  if(nsk_vkey == NULL) {
    cerr << "Could not deserialize saved nsk!\n";
    THROW("Bad NSK\n");
  }
  X509 *ca_crt = pem2x509(ca_crt_pem);
  X509 *nexusca_crt = pem2x509(nexusca_crt_pem);

  TimeString *starttime = timestring_create(2005, 6, 13, 18, 0, 0);
  TimeString *endtime = timestring_create(2010, 6, 14, 18, 0, 0);
  VKey *sig_vkey = vkey_create(VKEY_TYPE_PAIR, ALG_RSA_SHA1);
    
  int len = vkey_nsk_certify_key_len(nsk_vkey, sig_vkey, starttime, endtime);
  unsigned char *x509_buf = new unsigned char[len];
  vkey_nsk_certify_key(nsk_vkey, sig_vkey, starttime, endtime, (char *)x509_buf, &len);
  DataBuffer sig_crt_pem(x509_buf, len);
  RSA *sig_rsa = vkey_openssl_export(sig_vkey);
  X509 *sig_crt = pem2x509(sig_crt_pem);

  if(0) {
    cerr << "sig_crt = " << sig_crt << "\n";
    cerr << "nsk_crt = " << nsk_crt << "\n";
    cerr << "ca_crt = " << ca_crt << "\n";
    cerr << "nexusca_crt = " << nexusca_crt << "\n";
  }

  if(!SSL_CTX_use_certificate(server_ctx, sig_crt)) { ERROR(); }
  if(g_dbg_omit_nsk) {
    cerr << "Omitting NSK and NexusCA from cert chain\n";
  } else {
    if(!SSL_CTX_add_extra_chain_cert(server_ctx, nsk_crt)) { ERROR(); }
    if(!SSL_CTX_add_extra_chain_cert(server_ctx, nexusca_crt)) { ERROR(); }
  }
  if(0) {
    // this chain starts from platform CA, not privacy CA
    if(!SSL_CTX_add_extra_chain_cert(server_ctx, ca_crt)) { ERROR(); }
  }

  EVP_PKEY *sig_key = EVP_PKEY_new();
  if(!EVP_PKEY_set1_RSA(sig_key, sig_rsa)){ ERROR(); }
  if(!SSL_CTX_use_PrivateKey(server_ctx, sig_key)) { ERROR(); }
}
#endif // __LINUX__

void ssl_init(void) {
  OpenSSL_add_all_algorithms();
  OpenSSL_add_all_ciphers();
  OpenSSL_add_all_digests();
  SSL_library_init();
  SSL_load_error_strings();

  mydata_index = SSL_get_ex_new_index(0, (void *)"mydata index", NULL, NULL, NULL);

  server_ctx = SSL_CTX_new(SSLv3_server_method());
  client_ctx = SSL_CTX_new(SSLv3_client_method());

  SSL_CTX_set_verify(server_ctx, 
		     //SSL_VERIFY_NONE,
		     SSL_VERIFY_PEER,
		     verify_callback);

  SSL_CTX_set_verify(client_ctx,
		     //SSL_VERIFY_NONE,
		     SSL_VERIFY_PEER,
		     verify_callback);

#ifdef __LINUX__
  load_linux_keys();
#else
  load_nexus_keys();
#endif


  if(!(SSL_CTX_load_verify_locations(client_ctx, CA_LIST,0)))
    cerr_exit("Can't read CA list");
  if(!(SSL_CTX_load_verify_locations(server_ctx, CA_LIST,0)))
    cerr_exit("Can't read CA list");
}
