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

#include "../include/runtime/minisocket.h"
#include "../include/runtime/runtime.h"
#include "../include/util/common.h"
#include "../include/util/safe_malloc.h"

#include "../include/util/nexusbio.h"

//#define DISABLE_SSL

SSL_CTX *root_ctx = NULL;
X509 *root_cert = NULL;
X509 *x509_nexus_cert, *x509_tpm_cert, *x509_ca_cert;
EVP_PKEY *pkey;

#include "../include/enc/debugcerts.h"

int verify_cert(int preverify_ok, X509_STORE_CTX *cert){
  //  printf("Verifying certificate (always true)\n");
  return 1;
  return preverify_ok;
  // magical tls magic
}

RSA *make_tempkey(SSL *ssl, int exp, int keylength){
  printf("Generating temp key! (%d)\n", keylength);
  return RSA_generate_key(keylength, 17, NULL, NULL);
}

void init_rootcert(){
  //RSA *rkey;
  //X509_NAME *issuer, *subject;
  BIO *tmp;

  printf("MINISOCK: Generating Public Key\n");

  tmp = BIO_new_mem_buf(pem_privkey, -1);
  pkey = PEM_read_bio_PrivateKey(tmp, NULL, NULL, NULL);
  BIO_free(tmp);
  
  printf("MINISOCK: Generating Certificates \n");

  //dummy certificates for now
  tmp = BIO_new_mem_buf(pem_cert, -1);
  root_cert = PEM_read_bio_X509(tmp, NULL, NULL, NULL);

  tmp = BIO_new_mem_buf(nexus_cert, -1);
  x509_nexus_cert = PEM_read_bio_X509(tmp, NULL, NULL, NULL);
  BIO_free(tmp);

  tmp = BIO_new_mem_buf(tpm_cert, -1);
  x509_tpm_cert = PEM_read_bio_X509(tmp, NULL, NULL, NULL);
  BIO_free(tmp);

  tmp = BIO_new_mem_buf(ca_cert, -1);
  x509_ca_cert = PEM_read_bio_X509(tmp, NULL, NULL, NULL);
  BIO_free(tmp);
}

void init_minisocket(){
  int ret;

  printf("MINISOCK: Loading SSL error strings\n");
  
  SSL_load_error_strings();
  
  printf("Loading ciphers\n");
  
  SSL_library_init();
  
  printf("MINISOCK: Creating SSL context\n");

  root_ctx = SSL_CTX_new(SSLv3_method());

  if(!root_ctx){
    ERR_print_errors_fp(stderr);
    assert(!"boom!");
  }
  
  printf("MINISOCK: Setting SSL callbacks\n");
  
  SSL_CTX_set_verify(root_ctx, 
    SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
                         //Server verifies client as well
//    SSL_VERIFY_NONE,   //Client side verification only
    &verify_cert);
  SSL_CTX_set_tmp_rsa_callback(root_ctx, &make_tempkey);

  init_rootcert();
  
  printf("MINISOCK: Installing Certificates\n");

  if(!SSL_CTX_use_certificate(root_ctx, root_cert)){
    printf("SSL certificate assignment failed!  %s\n", ERR_error_string(ERR_get_error(), NULL));
    assert(!"boom!");
  }

  if(!(ret = SSL_CTX_add_extra_chain_cert(root_ctx, x509_nexus_cert))){
    int err = ERR_get_error();
    printf("SSL certificate append failed (nexus): %d!  %d:%s\n", ret, err, ERR_error_string(err, NULL));
    assert(!"boom!");
  }
  
  if(!SSL_CTX_add_extra_chain_cert(root_ctx, x509_tpm_cert)){
    printf("SSL certificate append failed (tpm)!  %s\n", ERR_error_string(ERR_get_error(), NULL));
    assert(!"boom!");
  }
  
  if(!SSL_CTX_add_extra_chain_cert(root_ctx, x509_ca_cert)){
    printf("SSL certificate append failed (ca)!  %s\n", ERR_error_string(ERR_get_error(), NULL));
    assert(!"boom!");
  }
  
  if(!SSL_CTX_use_PrivateKey(root_ctx, pkey)){
    printf("SSL private key assignment failed!  %s\n", ERR_error_string(ERR_get_error(), NULL));
    assert(!"boom!");
  }

  // this is where the certificate creation would go...
}

void start_socketthread(Minisocket *sock){
  sock->reader_thread();
}

Minisocket::Minisocket(unsigned int _host, int _port, minissl_ready_callback *_cback, void *_userdata, int _ssl){
  random_delay_offset = 0;
  random_delay_time = 0;
  sock = -1;
  host = _host;
  port = _port;
  cback = _cback;
  closed_cback = NULL;
  userdata = _userdata;
  ssl = _ssl;
  w_pipe = NULL;
  initialize_all();
}
Minisocket::Minisocket(int _sock){
  random_delay_offset = 0;
  random_delay_time = 0;
  sock = _sock;
  cback = NULL;
  closed_cback = NULL;
  w_pipe = NULL;
}
void Minisocket::accept(minissl_ready_callback *_cback, void *_userdata, int _ssl){
  cback = _cback;
  userdata = _userdata;
  ssl = _ssl;
  initialize_all();
}
void Minisocket::set_closed_cback(minissl_ready_callback *_cback, void *_userdata){
  closed_cback = _cback;
  closed_userdata = _userdata;
}

Minisocket::~Minisocket(){
  
}
void Minisocket::initialize_all(){
  conn = NULL;
  pipe = new Minipipe();
  ready = 0;
  //  printf("Creating thread!\n");
  pthread_create(&reader, NULL, (void*(*)(void*))start_socketthread, this);
  //  printf("Done creating!\n");
}

class Pipe_Router : public Runtime_Handler {
 public:
  Pipe_Router(Minipipe *_pipe, Minisocket *_sock) : Runtime_Handler(-1, _pipe, "Minisocket Pipe_Router"), sock(_sock) { }
  
  virtual void handle_minipipe(Minipipe *pipe, Runtime *runtime){
    char *buff;
    int len;
    
    assert((len = pipe->read(&buff)) >= 0);
    
    sock->write_sock(len, buff);
  }
  
 private:
  Minisocket *sock;
};

Minipipe *Minisocket::write_pipe(Runtime *r){
  if(!w_pipe){
    w_pipe = new Minipipe();
    Pipe_Router *pr = new Pipe_Router(w_pipe, this);
    r->register_handler(pr);
  }
  return w_pipe;
}

Minipipe *Minisocket::read_pipe(){
  return pipe;
}

int Minisocket::write_sock(int len, char *buff){
  assert(ready);

  char *fullbuff = (char *)alloca(len + 2*sizeof(uint32_t));
  memcpy(fullbuff, &len, sizeof(uint32_t));
  memcpy(fullbuff+sizeof(uint32_t), &len, sizeof(uint32_t));
  memcpy(fullbuff+2*sizeof(uint32_t), buff, len);

  //  printf("writing %d bytes: ssl=%s\n", len, ssl?"on":"off");

  if(ssl){
    return SSL_write(conn, fullbuff, len + 2 * sizeof(uint32_t));
  } else {
    //return send(sock, fullbuff, len+2*sizeof(uint32_t), 0);
    return write(sock, fullbuff, len+2*sizeof(uint32_t));
  }
}

int Minisocket::closed(){
  return sock < 0;
}

int blockingread(int sock, void *ptr, int len){
  int left, tot = len;
  for(;len > 0;){
    //printf("recv()\n");
    //left = recv(sock, ptr, len, 0);
    left = read(sock, ptr, len);
    //printf("(blocking)Read: %d\n", left);
    if(left < 0){
      return left;
    }
    if(left == 0){
      return -1;
    }
    len -= left;
    ptr = ((char *)ptr) + left;
  }
  return tot;
}

int blockingread(SSL *conn, void *ptr, int len){
  int left, tot = len;
  for(;len > 0;){
    left = SSL_read(conn, ptr, sizeof(uint32_t) * 2);
    //printf("(blocking ssl)Read: %d\n", left);
    if(left < 0){
      ERR_print_errors_fp(stderr);
      printf("can't read data: %s\n", ERR_error_string(ERR_get_error(), NULL));
      assert(0);
      return left;
    }
    len -= left;
    ptr = ((char *)ptr) + left;
  }
  return tot;
}

void Minisocket::reader_thread(){
  uint32_t len[2];
  char *data;
  int client = 0;
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
    
    client = 1;
  }


  if(ssl){
    //    printf("Connection open; activating SSL\n");
    
    //now create the SSL connection...
    conn = SSL_new(root_ctx);
    if(!conn){
      printf("SSL creation failed!\n");//%s\n", ERR_error_string(ERR_get_error(), NULL));
      ERR_print_errors_fp(stderr);
      assert(!"boom!");
    }
    
    io = BIO_new(Nexus_Sock_BIO());
    BIO_set_fd(io, sock, 1);
    SSL_set_bio(conn, io, io);
    
    //    printf("SSL ready, starting handshake\n");
    
    //not that it matters, but there may be a slight optimization if
    //the server initiates the ssl handshake... it's the client that
    //will usually need to authenticate to the server.
    if(!client){
      //send(sock, "hello", 6, 0);
      if((err = SSL_accept(conn)) <= 0){
        printf("can't accept : (%d) %s\n", SSL_get_error(conn, err), ERR_error_string(ERR_get_error(), NULL));
      }
    } else {
      if((err = SSL_connect(conn)) <= 0){
        printf("can't connect : (%d) %s\n", SSL_get_error(conn, err), ERR_error_string(SSL_get_error(conn, err), NULL));
      }
    }
    
    //    printf("handshake done\n");
  }// if(ssl)

  
  //those should block, so we've now got a nice happy ssl connection up.
  ready = 1;
  if(cback != NULL){
    cback(this, userdata);
  }
  
    //printf("Callback done\n");
  
  //and start processing
  while(sock >= 0){
    //    printf("reading: %d\n", ssl);
    if(ssl){
      if((err = blockingread(conn, len, sizeof(uint32_t) *2) ) != sizeof(uint32_t)*2){ 
        ERR_print_errors_fp(stderr);
        assert(0);
        perror("can't read length\n"); 
        break; 
      } else { 
        //printf ("read %d bytes\n", err);
      } 
    } else {
      if((err = blockingread(sock, len, sizeof(uint32_t) *2) ) != sizeof(uint32_t)*2){ 
        perror("can't read length\n"); 
        break; 
      } else { 
        //printf ("read %d bytes\n", err);
      } 
      
    }
    if(len[0] != len[1]){  
      printf("invalid length read : %d(%d):%d(%d)\n", len[0], sizeof(len[0]), len[1], sizeof(len[0])); 
      break; 
    }
    //printf("reading %d bytes\n", len[0]);
    data = (char *)safe_malloc(len[0]);
        //printf("reading %d bytes of data\n", len[0]);
    if(ssl){
      if(blockingread(conn, data, len[0]) <= 0){  
        printf("can't read data\n"); 
        break; 
      }
    } else {
      if(blockingread(sock, data, len[0]) <= 0){  
        printf("can't read data\n"); 
        break; 
      }
    }

    //    printf("read %d bytes of data\n", len[0]);
    pipe->write_malloced(data, len[0]);
    if(random_delay_time){
      Thread_USleep(random_delay_time + (rand()%(random_delay_offset)) - (random_delay_offset/2));
    }
  }
  if(closed_cback != NULL){
    closed_cback(this, closed_userdata);
  }
  sock = -1;
  while(1); //Nexus doesn't like thread death.
}

void Minisocket::close_sock(){
  int tmpsock = sock;
  sock = -1;
  close(tmpsock); 
}

void Minisocket::debug_add_delay_chance(int _random_delay_offset, int _random_delay_time){
  srand(time(NULL));
  random_delay_offset = _random_delay_offset;
  random_delay_time = _random_delay_time;
}

void start_serversocketthread(Minisocketserver *sock){
  sock->reader_thread();
}

Minisocketserver::Minisocketserver(int _port){
  port = _port;
}
Minisocketserver::~Minisocketserver(){
  
}

void Minisocketserver::start_listen(minissl_ready_callback *_cback, void *_userdata){
  cback = _cback;
  userdata = _userdata;
  assert(cback);
  pthread_create(&reader, NULL, (void*(*)(void*))start_serversocketthread, this);
}

void Minisocketserver::reader_thread(){
  struct sockaddr_in saddr, caddr;
  int sock = socket(PF_INET, SOCK_STREAM, 0), client;
  int caddrlen;
  
  printf("server: %d\n", sock);
  
  memset(&saddr, 0, sizeof(struct sockaddr_in));
  
  saddr.sin_port = htons(port);
  saddr.sin_addr.s_addr = INADDR_ANY;
  saddr.sin_family = AF_INET;
  
  bind(sock, (struct sockaddr *)&saddr, sizeof(struct sockaddr_in));
  listen(sock, 10);
  
  while(1){
    client = accept(sock, (struct sockaddr *)&caddr, (socklen_t *)&caddrlen);
    printf("Accepted a connection\n");
    cback(new Minisocket(client), userdata);
  }
}
