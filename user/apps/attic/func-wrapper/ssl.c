#include <openssl/ssl.h>
#include <openssl/err.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <assert.h>

#include <nexus/util.h>

#ifndef __LINUX__
#include <nexus/vkey.h>
#include <nexus/util.h>
#include <nexus/LabelStore.interface.h>
#endif

#include "ssl.h"

#define SAVE_ALL_LABELS (1)
SSL_CTX *server_ctx;
SSL_CTX *client_ctx;
int mydata_index;
X509 *server_cert;

static int dbg = 1;

#define ERROR() do { printf("Error at %d\n", __LINE__); exit(-1); } while(0)

static int password_cb(char *buf,int num,
		       int rwflag,void *userdata)
{
  const char *pass = "foobar";
  if(num < (int) (strlen(pass)+1) )
    return(0);

  strcpy(buf,pass);
  return(strlen(pass));
}

void load_file_key(char *basename) {
  char cert_file[80];
  char privkey_file[80];
  sprintf(cert_file, "%s.crt", basename);
  sprintf(privkey_file, "%s.key", basename);

  /* Load our keys and certificates*/
  if(!(SSL_CTX_use_certificate_chain_file(server_ctx, cert_file))) {
    printf("Can't read certificate file");
    exit(-1);
  }

  SSL_CTX_set_default_passwd_cb(server_ctx, password_cb);
  if(!(SSL_CTX_use_PrivateKey_file(server_ctx, privkey_file,SSL_FILETYPE_PEM))) {
    printf("Can't read key file");
    exit(-1);
  }
}

void load_linux_keys(void) {
  const char *cert_file = "spamfree.crt";
  const char *privkey_file = "spamfree.key";

  /* Load our keys and certificates*/
  if(!(SSL_CTX_use_certificate_chain_file(server_ctx, cert_file))) {
    printf("Can't read certificate file");
    exit(-1);
  }

  SSL_CTX_set_default_passwd_cb(server_ctx, password_cb);
  if(!(SSL_CTX_use_PrivateKey_file(server_ctx, privkey_file,SSL_FILETYPE_PEM))) {
    printf("Can't read key file");
    exit(-1);
  }
  printf("Linux keys loaded\n");
}

X509 *pem2x509(const unsigned char *pem, int len){
  BIO *tmp = BIO_new_mem_buf((unsigned char *)pem, len);
  X509 *ret = PEM_read_bio_X509(tmp, NULL, NULL, NULL);
  BIO_free(tmp);
  return ret;
}

#ifndef __LINUX__
void load_nexus_keys(void) {
#if 0
  // 2/25: NSK / CA code is fubar
  int nsk_crt_len;
  int nsk_vkey_len;
  // Get NSK 
  char *nsk_crt_data = read_file("/nfs/nexus.nsk.crt", &nsk_crt_len);
  char *nsk_vkey_data = read_file("/nfs/nexus.nsk", &nsk_vkey_len);

  X509 *nsk_crt = pem2x509(nsk_crt_data, nsk_crt_len);
  VKey *nsk_vkey = vkey_deserialize( nsk_vkey_data, nsk_vkey_len );
  if(nsk_vkey == NULL) {
    printf("Could not deserialize saved nsk!\n");
    ERROR();
  }

  TimeString *starttime = timestring_create(2005, 6, 13, 18, 0, 0);
  TimeString *endtime = timestring_create(2010, 6, 14, 18, 0, 0);
  printf("Creating key\n");
  VKey *sig_vkey = vkey_create(VKEY_TYPE_PAIR, ALG_RSA_SHA1);
  RSA *sig_rsa = vkey_openssl_export(sig_vkey);
    
  int len = vkey_nsk_certify_key_len(nsk_vkey, sig_vkey, starttime, endtime);
  unsigned char *x509_buf = malloc(len);
  vkey_nsk_certify_key(nsk_vkey, sig_vkey, starttime, endtime, (char *)x509_buf, &len);
  X509 *sig_crt = pem2x509(x509_buf, len);

  if(!SSL_CTX_use_certificate(server_ctx, sig_crt)) { ERROR(); }

  EVP_PKEY *sig_key = EVP_PKEY_new();
  if(!EVP_PKEY_set1_RSA(sig_key, sig_rsa)){ ERROR(); }
  if(!SSL_CTX_use_PrivateKey(server_ctx, sig_key)) { ERROR(); }
#else
  const char *cert_file = "/nfs/func-wrapper.crt";
  const char *privkey_file = "/nfs/func-wrapper.key";

  /* Load our keys and certificates*/
  if(!(SSL_CTX_use_certificate_chain_file(server_ctx, cert_file))) {
    printf("Can't read certificate file");
    exit(-1);
  }

  int crt_len;
  unsigned char *crt_data = read_file((char *)cert_file, &crt_len);
  server_cert = pem2x509(crt_data, crt_len);

  SSL_CTX_set_default_passwd_cb(server_ctx, password_cb);
  if(!(SSL_CTX_use_PrivateKey_file(server_ctx, privkey_file,SSL_FILETYPE_PEM))) {
    printf("Can't read key file");
    exit(-1);
  }
#endif
  printf("Done loading keys\n");
}
#endif // __LINUX__

static int verify_callback(int preverify_ok, X509_STORE_CTX *ctx)
{
  printf("SSL verify called, always returns true\n");
  return 1;
}

void ssl_init(void) {
  static int ssl_initialized;
  if(ssl_initialized) {
    return;
  }
  ssl_initialized = 1;

  OpenSSL_add_all_algorithms();
  OpenSSL_add_all_ciphers();
  OpenSSL_add_all_digests();
  SSL_library_init();
  SSL_load_error_strings();

  mydata_index = SSL_get_ex_new_index(0, (void *)"mydata index", NULL, NULL, NULL);

  server_ctx = SSL_CTX_new(SSLv3_server_method());
  client_ctx = SSL_CTX_new(SSLv3_client_method());

  // auto-renegotiate on read/write
  SSL_CTX_set_mode(server_ctx, SSL_MODE_AUTO_RETRY);
  SSL_CTX_set_mode(client_ctx, SSL_MODE_AUTO_RETRY);

  SSL_CTX_set_verify(server_ctx, 
		     SSL_VERIFY_NONE,
		     //SSL_VERIFY_PEER,
		     verify_callback);
  SSL_CTX_set_verify(client_ctx, 
		     SSL_VERIFY_NONE,
		     //SSL_VERIFY_PEER,
		     verify_callback);
  printf("Init errors = {\n");
  ERR_print_errors_fp(stdout);
  printf("}\n");
}

static SSL *ssl_bind(uint16_t server_port, int *sock_p) {
  ssl_init();

  int err;
  struct sockaddr_in addr;
  int sock = socket(PF_INET, SOCK_STREAM, 0);
  int i;
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = INADDR_ANY;
  addr.sin_port = server_port;
  err = bind(sock, (struct sockaddr *)&addr, sizeof(addr));
  assert(err == 0);

  SSL *data_ssl = SSL_new(client_ctx);
  printf("Set FD: ssl = %p, sock = %d\n", data_ssl, sock);
  SSL_set_fd(data_ssl, sock);
  if(sock_p != NULL) {
    *sock_p = sock;
  }
  printf("Back from set fd\n");
  return data_ssl;
}

SSL *ssl_connect(uint32_t server_addr, uint16_t server_port) {
  int sock;
  SSL *data_ssl = ssl_bind(0, &sock); // any port
  int err;
  struct sockaddr_in dest;
  dest.sin_family = AF_INET;
  dest.sin_addr.s_addr = htonl(server_addr);
  dest.sin_port = htons(server_port);
  err = connect(sock, (struct sockaddr *)&dest, sizeof(dest));
  SSL_connect(data_ssl);
  return data_ssl;
}

int ssl_send_all(SSL *ssl, const void *data, int len) {
  const char *databuf = data;
  int totalwrite = 0, numwrite = 0;

  if(dbg)printf("writing...");
  while(totalwrite < len){
    numwrite = SSL_write(ssl, databuf + totalwrite, len - totalwrite);
    if(numwrite <= 0){
      printf("couldn't write data; got %d so far\n", totalwrite);
      return -1;
    }
    totalwrite += numwrite;
  }
  if(dbg)printf("done writing\n");
  assert(totalwrite == len);
  return totalwrite;
}

int ssl_recv_all(SSL *ssl, void *data, int len) {
  char *databuf = data;
  int totalread = 0, numread = 0;

  if(dbg)printf("reading...");
  while(totalread < len){
    numread = SSL_read(ssl, databuf + totalread, len - totalread);
    if(numread <= 0){
      printf("couldn't read data; got %d so far\n", totalread);
      return -1;
    }
    totalread += numread;
  }
  if(dbg)printf("done reading\n");
  assert(totalread == len);
  return totalread;
}

SignedFormula *recv_label(SSL *ssl) {
  int len;
  ssl_recv_all(ssl, (char *)&len, sizeof(len));
  SignedFormula *f = malloc(len);
  ssl_recv_all(ssl, f, len);
  if(signedform_verify(f) != 0) {
    printf("label sig verification failed\n");
    free(f);
    return NULL;
  }

  if(SAVE_ALL_LABELS) {
    static int label_count = 0;
    char fname[80];
    sprintf(fname, "/tmp/label-%d", label_count);
    write_file(fname, f->body, len);
    label_count++;
  }
  return f;
}

void send_label(SSL *ssl, SignedFormula *formula) {
  int len = der_msglen(formula->body);
  ssl_send_all(ssl, (char *)&len, sizeof(len));
  ssl_send_all(ssl, formula->body, len);
}

struct AuthData auth_data;

void load_auth_data(void) {
  if(auth_data.loaded) {
    printf("auth data already loaded\n");
    return;
  }
  auth_data.loaded = 1;
  // Load CA and PCR data
  // Extract it from a signed NSK formula
  SignedFormula *signed_nsk;
  Form *nsk_form = read_signed_file("/nfs", "func-wrapper-auth.signed", &signed_nsk);
  Form *nsk; // ignored
  if(nsk_form == NULL) {
    printf("Could not get good values for CA pubkey and PCRs\n");
    exit(-1);
  }
  auth_data.nexusca = NULL;
  auth_data.pcrs = NULL;
  if(form_scan(nsk_form, "der(%{term}) says pcrs(%{term}) = %{term}", // = %{term}
	       &auth_data.nexusca, &nsk, &auth_data.pcrs) != 0) {
    printf("Could not extract CA and PCRs\n");
    exit(-1);
  }
  int hash_len;
  unsigned char *hash_data = read_file("/nfs/HASHES", &hash_len);
  assert(hash_len % 40 == 0);
  int i;
  auth_data.num_hash_entries = hash_len / 40;
  auth_data.hash_entries = 
    malloc(auth_data.num_hash_entries * sizeof(struct HashEntry));
  for(i=0; i < auth_data.num_hash_entries; i++) {
    memcpy(auth_data.hash_entries[i].execname, hash_data + i * 40, 20);
    memcpy(auth_data.hash_entries[i].hash, hash_data + i * 40 + 20, 20);

    if(0) {
      printf("Hash[%d] of %s: ", i, auth_data.hash_entries[i].execname);
      hexdump(auth_data.hash_entries[i].hash, 20); printf("\n");
    }
  }
}

int auth_data_hash_check(char *hash_val, char *wanted_name) {
  int i;
  for(i=0; i < auth_data.num_hash_entries; i++) {
    if(memcmp(auth_data.hash_entries[i].hash, hash_val, 20) == 0) {
      return strcmp(wanted_name, auth_data.hash_entries[i].execname);
    }
  }
  return -1;
}

// SSL connections always start with 3 labels: NSK, SSLKey, Hash cred
SignedFormula *nsk_label;
SignedFormula *sslkey_binding;
SignedFormula *hashcred;

Form *nexusca;
Form *nsk;
Form *pcrs;
Form *ssl_endpoint_ipd_prin;

int parse_boothash(SignedFormula *cred, Form **nsk, Form **ipd, char *hash_val) {
  Form *this_nsk = NULL;
  Form *this_wrapper_ipd = NULL;
  char *_hash_val;
  if(form_scan(form_from_der(signedform_get_formula(cred)),
	       "der(%{term}) says BootHash(%{term}) = %{bytes:20}", 
	       &this_nsk, &this_wrapper_ipd, &_hash_val) != 0) {
    return -1;
  }
  *nsk = this_nsk;
  *ipd = this_wrapper_ipd;
  memcpy(hash_val, _hash_val, 20);
  free(_hash_val);
  return 0;
}

int verify_ssl_labels(SSL *data_ssl) {
  load_auth_data();
  nsk_label = recv_label(data_ssl);
  sslkey_binding = recv_label(data_ssl);
  hashcred = recv_label(data_ssl);

  if( !(nsk_label != NULL && sslkey_binding != NULL && hashcred != NULL)) {
    printf("Label signature verification failed\n");
    return -1;
  }

  // General: Verify that all NSK keys are identical
  // 1: Veify that signer CA key and PCRs are valid
#define CHECK_NSK()					\
    if(form_cmp(this_nsk, nsk) != 0) {			\
      printf("label did not match nsk\n");		\
      printf("%s\n", form_to_pretty(this_nsk, 1000));	\
      printf("%s\n", form_to_pretty(nsk, 1000));	\
      return -1;					\
    }

  Form *tax_engine_ipd_prin;

  printf("Verifying NSK key\n");
  form_scan(form_from_der(signedform_get_formula(nsk_label)),
	    "der(%{term}) says pcrs(der(%{term})) = %{term}",
	    &nexusca, &nsk, &pcrs);
  if(form_cmp(nexusca, auth_data.nexusca) != 0) {
    printf("CA mismatch\n");
    return -1;
  }
  if(form_cmp(pcrs, auth_data.pcrs) != 0) {
    printf("PCR mismatch\n");
    return -1;
  }

  // 2: SSL connection == SSL binding key
  printf("Verifying ssl key\n");
  {
    Form *this_nsk = NULL;
    Form *ipd_prin0 = NULL, *ipd_prin1 = NULL;
    Form *stmt = NULL;
    Form *ssl_key = NULL;
    if(form_scan(form_from_der(signedform_get_formula(sslkey_binding)),
		 "der(%{term}) says %{Stmt}",
		 &this_nsk, &stmt) != 0) {
      printf("could not parse certificate label\n");
      return -1;
    }
    if(form_scan(stmt, "%{term} says %{term} speaksfor %{term}", 
		 &ipd_prin0, &ssl_key, &ipd_prin1) != 0) {
      printf("could not parse certificate label\n");
      return -1;
    }
    ssl_endpoint_ipd_prin = ipd_prin0;

    CHECK_NSK();
    if(form_cmp(ipd_prin0, ipd_prin1) != 0) {
      printf("malformed SSL delegation\n");
      return -1;
    }
    X509 *peer_cert = SSL_get_peer_certificate(data_ssl);
    unsigned char *key = (unsigned char *) der_key_from_cert(peer_cert);
    Form *computed_ssl_key = term_fmt("der(%{bytes})", key, der_msglen(key));
    free(key);
    if(form_cmp(ssl_key, computed_ssl_key) != 0) {
      printf("ssl key mismatch\n");
      printf("%s\n", form_to_pretty(ssl_key, 1000));
      printf("%s\n", form_to_pretty(computed_ssl_key, 1000));
      return -1;
    }
    form_free(computed_ssl_key);
  }
  // 3: Verify boothash #1 = SSL endpoint
  {
    printf("Verifying that boothash#1 corresponds to SSL endpoint\n");
    Form *this_nsk = NULL;
    Form *this_endpoint_ipd = NULL;
    char hash_val[20];
    if(parse_boothash(hashcred, &this_nsk, &this_endpoint_ipd, hash_val) != 0) {
      printf("Error: could not parse wrapper hash\n");
      return -1;
    }
    if(form_cmp(this_nsk, nsk) != 0) {
      printf("Error: nsk mismatch\n");
      return -1;
    }
    if(form_cmp(this_endpoint_ipd, ssl_endpoint_ipd_prin) != 0) {
      printf("Error: ipd mismatch\n");
      return -1;
    }
  }
  return 0;
}

#ifndef __LINUX__

FSID store;
SignedFormula *nsk_label;
SignedFormula *hashcred;
SignedFormula *sslkey_binding;

void labelstore_init(void) {
  static int labels_initialized;
  if(labels_initialized) {
    return;
  }
  char *store_name = "public_labels";
  printf("Creating Label Store (%s)... ", store_name);
  store = LabelStore_Store_Create(store_name);
  if (!FSID_isValid(store)) { printf("error\n"); exit(1); }
  printf("done\n");

  int nsk_len;
  nsk_label = (SignedFormula *)read_file("/nfs/nexus.nsk.signed", &nsk_len);

  FSID hashcred_id = LabelStore_Nexus_Label(store, 1, "hashcred", NULL, NULL);
  if (!FSID_isValid(hashcred_id)) { printf("error\n"); exit(1); }
  hashcred = malloc(4096);
  int hashcred_len = LabelStore_Label_Externalize(hashcred_id, (char *)hashcred, 4096, NULL);
  if(hashcred_len > 4096) { printf("not enough space for cred!\n");  exit(-1); }

  labels_initialized = 1;
}

void send_ssl_labels(SSL *ssl) {
  labelstore_init();

  printf("Asking for label binding pubkey\n");
  if(server_cert == NULL) {
    printf("No server certificate; can't send SSL labels!\n");
    exit(-1);
  }
  Formula *ssl_stmt = form_bind_cert_pubkey(server_cert);
  FSID sslkey_binding_id = 
    LabelStore_Label_Create(store, "sslkey_binding", ssl_stmt, NULL);
  sslkey_binding = malloc(4096);
  int ssl_cred_len = LabelStore_Label_Externalize(sslkey_binding_id, (char *)sslkey_binding, 4096, NULL);
  if(ssl_cred_len > 4096) { printf("formula too long!\n"); exit(-1); }

  send_label(ssl, nsk_label);
  send_label(ssl, sslkey_binding);
  send_label(ssl, hashcred);
}
#endif

#if 0
    if(auth_data_hash_check(hash_val, "exec-func")) {
      printf("bad hash\n");
      printf("%s\n", form_to_pretty(form_from_der(signedform_get_formula(hashcred)), 1000));
      return -1;
    }
#endif
