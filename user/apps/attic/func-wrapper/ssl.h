#ifndef _SSL_H_
#define _SSL_H_

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <nexus/formula.h>
#include <stdint.h>

struct HashEntry {
  char execname[20];
  char hash[20];
};

struct AuthData {
  int loaded;
  Form *nexusca;
  Form *pcrs;
  int num_hash_entries;
  struct HashEntry *hash_entries;
};

// labels for SSL connection
extern SignedFormula *nsk_label;
extern SignedFormula *sslkey_binding;
extern SignedFormula *hashcred;

// Extracted fields from SSL connection
Form *nexusca;
Form *nsk;
Form *pcrs;
Form *ssl_endpoint_ipd_prin;

extern struct AuthData auth_data;

void ssl_init(void);
void load_linux_keys(void);
void load_nexus_keys(void);

SSL *ssl_connect(uint32_t server_addr, uint16_t server_port);
int ssl_send_all(SSL *ssl, const void *data, int len);
int ssl_recv_all(SSL *ssl, void *data, int len);

// recv_label also verifies the signature
SignedFormula *recv_label(SSL *ssl);
void send_label(SSL *ssl, SignedFormula *formula);

void load_auth_data(void);
// check good hash database to see if hash corresponds to exec "wanted_name"
int auth_data_hash_check(char *hash_val, char *wanted_name);
int verify_ssl_labels(SSL *ssl);
void send_ssl_labels(SSL *ssl);

int parse_boothash(SignedFormula *cred, Form **nsk, Form **ipd, char *hash_val);

extern SSL_CTX *server_ctx;
extern SSL_CTX *client_ctx;
extern X509 *server_cert;

#endif // _SSL_H_
