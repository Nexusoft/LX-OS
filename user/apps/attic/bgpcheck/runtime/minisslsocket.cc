#include <iostream>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <assert.h>
#include <openssl/err.h>

#include "../include/runtime/minisslsocket.h"
#include "../include/util/common.h"
#include "../include/util/safe_malloc.h"

#define DISABLE_SSL

SSL_CTX *root_ctx = NULL;
X509 *root_cert = NULL;
EVP_PKEY *pkey;

char *pem_privkey = "-----BEGIN RSA PRIVATE KEY-----\n\
MIICXgIBAAKBgQDhkgF8vmk/b+J5A/M+jRNVT7y5kq6wT4iv5/hiegfpHsgcWm4t\n\
adAhn8FXzTHPgB0uEvJkyPLlfKLwAQ0UF1X8v5XoWXVO8IxAV1MR4LoGKCnLEpbY\n\
LCNyC9y/t8Y7QKWnjSAOWQKBgTzVF/tjzCOPSerPljHzmiVf7yeu3XxNlwIDAQAB\n\
AoGAZNDn30QPMC4mb2Xnkp5k9K01sU8wylZRxiUMa58U6Ak88Qct1RhE0LJhLIfm\n\
alJdOFl5grgZb538CP6/RKqFYCGWSnyTukXblUal1LnQcicBQpIYHrkg1+2iuCyv\n\
tzaVU93NVmhnJ/7WoOYOrUOmkBXVRFVPSCzYQUlSmwtvd4kCQQD6lKOW1g7/wg+5\n\
TypizwnVivJO5tuk4biJctV8LyqFzR7drU8Orud0Aso00wwT1QrOb+102M1k5gU/\n\
C9hwh4TtAkEA5nLlLFr3YrujB3GNNkIR9XDjK6auGC0z8TrVubdi5lA0i5qrUC+k\n\
c8HzNrbwmF0q+UUmKBBXfbk9U1pwLWUwEwJBALTmtAdD+EYaAqIEjhQRZgcdLXta\n\
3Pz22/OWzJq/rlI0WHEvGiD+kifFj9d8+X4j0o5gbaxqjDWofecbFSGAJK0CQQCi\n\
vRacCS1Uex95HTZUz7mw82Rpqg6doiZhP2Q4/4mHDbLdt38tZEelO50O0Yf8gSbc\n\
23lDp66xaUQmfeJkHGYjAkEAqw7WCW88KPk2lZJc3PoKTVuYbi8yZlAU/Ki2BImp\n\
gNfBL2ERTImKtyNeZd6to1G+6d6GKmG7z4ZmhGiG5LGLeA==\n\
-----END RSA PRIVATE KEY-----";

char *pem_cert = "-----BEGIN CERTIFICATE-----\n\
MIICxTCCAi6gAwIBAgIJAO0gcg+aeTE3MA0GCSqGSIb3DQEBBQUAMEwxCzAJBgNV\n\
BAYTAkdCMRIwEAYDVQQIEwlCZXJrc2hpcmUxEDAOBgNVBAcTB05ld2J1cnkxFzAV\n\
BgNVBAoTDk15IENvbXBhbnkgTHRkMB4XDTA2MTIxMzE3NDg1MVoXDTA3MDExMjE3\n\
NDg1MVowTDELMAkGA1UEBhMCR0IxEjAQBgNVBAgTCUJlcmtzaGlyZTEQMA4GA1UE\n\
BxMHTmV3YnVyeTEXMBUGA1UEChMOTXkgQ29tcGFueSBMdGQwgZ8wDQYJKoZIhvcN\n\
AQEBBQADgY0AMIGJAoGBAOGSAXy+aT9v4nkD8z6NE1VPvLmSrrBPiK/n+GJ6B+ke\n\
yBxabi1p0CGfwVfNMc+AHS4S8mTI8uV8ovABDRQXVfy/lehZdU7wjEBXUxHgugYo\n\
KcsSltgsI3IL3L+3xjtApaeNIA5ZAoGBPNUX+2PMI49J6s+WMfOaJV/vJ67dfE2X\n\
AgMBAAGjga4wgaswHQYDVR0OBBYEFGYbXvarQxNzttCPxrwv0QxkSNctMHwGA1Ud\n\
IwR1MHOAFGYbXvarQxNzttCPxrwv0QxkSNctoVCkTjBMMQswCQYDVQQGEwJHQjES\n\
MBAGA1UECBMJQmVya3NoaXJlMRAwDgYDVQQHEwdOZXdidXJ5MRcwFQYDVQQKEw5N\n\
eSBDb21wYW55IEx0ZIIJAO0gcg+aeTE3MAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcN\n\
AQEFBQADgYEAZL0p5T1eEU3JDtXht5XkHUKbk4fMhKaSB2/Es9XYAsjGncu/+1yr\n\
0ntdguZQMFfkED2Foy3xDIIFO/TAw8wT38crmP5LzqTO5sERacF7PV1gC1y+dt2F\n\
qJxPy2bv8wvIyolYgjSFuk/3xxY6fZg+DhMbM/HvRtwmXLPo3WlKHQU=\n\
-----END CERTIFICATE-----";

int verify_cert(int preverify_ok, X509_STORE_CTX *cert){
  printf("Verifying certificate (always true)\n");
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

  printf("Generating Public Key\n");

  //get a public key
  
  //pkey = EVP_PKEY_new();
  //assert(pkey);
  //rkey = RSA_generate_key(1024, 3, NULL, NULL);
  //assert(rkey);
  //assert(EVP_PKEY_assign_RSA(pkey, rkey));

  tmp = BIO_new_mem_buf(pem_privkey, -1);
  pkey = PEM_read_bio_PrivateKey(tmp, NULL, NULL, NULL);
  BIO_free(tmp);
  
  printf("Generating Certificate \n");

  tmp = BIO_new_mem_buf(pem_cert, -1);
  root_cert = PEM_read_bio_X509(tmp, NULL, NULL, NULL);

  //create an issuer name
//   issuer = X509_NAME_new();
//   X509_NAME_add_entry_by_txt(issuer, "n", MBSTRING_ASC, (unsigned char *)"bob", -1, -1, 0);

//   //create a object name
//   subject = X509_NAME_new();
//   X509_NAME_add_entry_by_txt(subject, "n", MBSTRING_ASC, (unsigned char *)"tim", -1, -1, 0);

//   //create the certificate
//   root_cert = X509_new();
//   assert(root_cert);
//   X509_set_issuer_name(root_cert, subject);
//   X509_set_subject_name(root_cert, subject);
//   X509_set_pubkey(root_cert, pkey);
//   X509_sign(root_cert, pkey, EVP_md5());
}

void init_minisslsocket(){
  printf("Loading error strings\n");
  
  SSL_load_error_strings();
  
  printf("Loading ciphers\n");
  
  SSL_library_init();
  
  printf("Creating context\n");

  root_ctx = SSL_CTX_new(SSLv2_method());

  if(!root_ctx){
    ERR_print_errors_fp(stderr);
    assert(!"boom!");
  }
  
  printf("Ignoring verification\n");
  
  SSL_CTX_set_verify(root_ctx, SSL_VERIFY_NONE, &verify_cert);
  SSL_CTX_set_tmp_rsa_callback(root_ctx, &make_tempkey);

  init_rootcert();

  if(!SSL_CTX_use_certificate(root_ctx, root_cert)){
    printf("SSL certificate assignment failed!  %s\n", ERR_error_string(ERR_get_error(), NULL));
    assert(!"boom!");
  }
  
  if(!SSL_CTX_use_PrivateKey(root_ctx, pkey)){
    printf("SSL private key assignment failed!  %s\n", ERR_error_string(ERR_get_error(), NULL));
    assert(!"boom!");
  }

  // this is where the certificate creation would go...
}

void start_socketthread(Minisslsocket *sock){
  sock->reader_thread();
}

Minisslsocket::Minisslsocket(unsigned int _host, int _port, minissl_ready_callback *_cback, void *_userdata){
  sock = -1;
  host = _host;
  port = _port;
  cback = _cback;
  userdata = _userdata;
  initialize_all();
}
Minisslsocket::Minisslsocket(int _sock){
  sock = _sock;
}
void Minisslsocket::accept(minissl_ready_callback *_cback, void *_userdata){
  cback = _cback;
  userdata = _userdata;
  initialize_all();
}

Minisslsocket::~Minisslsocket(){
  
}
void Minisslsocket::initialize_all(){
  conn = NULL;
  pipe = new Minipipe();
  ready = 0;
  printf("Creating thread!\n");
  pthread_create(&reader, NULL, (void*(*)(void*))start_socketthread, this);
  printf("Done creating!\n");
}

Minipipe *Minisslsocket::read_pipe(){
  return pipe;
}

int Minisslsocket::write_sock(int len, char *buff){
  assert(ready);

  char *fullbuff = (char *)alloca(len + 2*sizeof(uint32_t));
  memcpy(fullbuff, &len, sizeof(uint32_t));
  memcpy(fullbuff+sizeof(uint32_t), &len, sizeof(uint32_t));
  memcpy(fullbuff+2*sizeof(uint32_t), buff, len);

  printf("writing %d bytes\n", len);

#ifdef DISABLE_SSL
  return write(sock, fullbuff, len+2*sizeof(uint32_t));
#else
  return SSL_write(conn, fullbuff, len + 2 * sizeof(uint32_t));
#endif
}

int Minisslsocket::closed(){
  return sock < 0;
}

int blockingread(int sock, void *ptr, int len){
  int left, tot = len;
  for(;len > 0;){
    left = read(sock, ptr, len);
    printf("(blocking)Read: %d\n", left);
    if(left < 0){
      return left;
    }
    len -= left;
    ptr = ((char *)ptr) + left;
  }
  return tot;
#if 0
    if(SSL_read(conn, data, sizeof(uint32_t) * 2) <= 0){ 
      ERR_print_errors_fp(stderr);
      printf("can't read data: %s\n", ERR_error_string(ERR_get_error(), NULL));
      break; 
    }
#endif
}

void Minisslsocket::reader_thread(){
  uint32_t len[2];
  char *data;
  int client = 0;
  int err;
  
  //is the socket open
  printf("reader thread!\n");
  if(sock < 0){
    sockaddr_in saddr;
    memset(&saddr, 0, sizeof(struct sockaddr_in));
    
    printf("Getting socket: %d, %d\n", sock, errno);
    sock = socket(PF_INET, SOCK_STREAM, 0);
    if(sock < 0){
      return;
    }
    printf("Connecting socket : %d (%d), %d\n", sock, errno, AF_INET);
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
    printf("Socket Connected\n");
    
    client = 1;
  }


#ifndef DISABLE_SSL
  printf("Connection open; activating SSL\n");
  
  //now create the SSL connection...
  conn = SSL_new(root_ctx);
  if(!conn){
    printf("SSL creation failed!\n");//%s\n", ERR_error_string(ERR_get_error(), NULL));
    ERR_print_errors_fp(stderr);
    assert(!"boom!");
  }
  
  if(SSL_set_fd(conn, sock) <= 0){
    printf("can't set fd : (%d)%s\n", err, ERR_error_string(ERR_get_error(), NULL));
  }

  printf("SSL ready, starting handshake\n");
  
  //not that it matters, but there may be a slight optimization if
  //the server initiates the ssl handshake... it's the client that
  //will usually need to authenticate to the server.
  if(!client){
    //send(sock, "hello", 6, 0);
    if((err = SSL_accept(conn)) <= 0){
      printf("can't accept : (%d)%s\n", SSL_get_error(conn, err), ERR_error_string(ERR_get_error(), NULL));
    }
  } else {
    if(SSL_connect(conn) < 0){
      printf("can't connect : (%d)%s\n", err, ERR_error_string(ERR_get_error(), NULL));
    }
  }
  
  printf("handshake done\n");
#endif
  
  //those should block, so we've now got a nice happy ssl connection up.
  ready = 1;
  if(cback != NULL){
    cback(this, userdata);
  }
  
  printf("Callback done\n");
  
  //and start processing
  while(sock >= 0){
    printf("reading\n");
    if((err = blockingread(sock, len, sizeof(uint32_t) *2)) != sizeof(uint32_t)*2){ 
      perror("NOSSL: can't read length\n"); 
      break; 
    } else { 
      printf ("read %d bytes\n", err);
    } 
    if(len[0] != len[1]){  
#ifndef DISABLE_SSL
      ERR_print_errors_fp(stderr);
#endif
      printf("invalid length read : %d(%ld):%d(%ld)\n", len[0], sizeof(len[0]), len[1], sizeof(len[0])); 
      break; 
    }
    data = (char *)safe_malloc(len[0]);
    printf("reading %d bytes of data\n", len[0]);
    if(blockingread(sock, data, len[0]) <= 0){  
      printf("can't read data\n"); 
      break; 
    }
    printf("read %d bytes of data\n", len[0]);
    pipe->write_malloced(data, len[0]);
  }

  close(sock);
  sock = -1;
}

void start_serversocketthread(Minisslsocketserver *sock){
  sock->reader_thread();
}

Minisslsocketserver::Minisslsocketserver(int _port){
  port = _port;
}
Minisslsocketserver::~Minisslsocketserver(){
  
}

void Minisslsocketserver::start_listen(minissl_ready_callback *_cback, void *_userdata){
  cback = _cback;
  userdata = _userdata;
  assert(cback);
  pthread_create(&reader, NULL, (void*(*)(void*))start_serversocketthread, this);
}

void Minisslsocketserver::reader_thread(){
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
    cback(new Minisslsocket(client), userdata);
  }
}
