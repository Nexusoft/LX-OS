#include <stdlib.h>
#include "SpamFreeAttestationService.interface.h"
#include "sfaservice.h"
#include <nexus/Thread.interface.h>

#include  <openssl/bio.h>
#include  <openssl/err.h>
#include  <openssl/rsa.h>
#include  <openssl/pem.h>

#include  <nexus/debug.h>

#include <assert.h>

EVP_PKEY *spamkey; // must be RSA
#define SPAMKEY_SIG_LEN (4096 / 8)

// cert (and stack of certs) for spamkey
X509 *spamkey_cert;
STACK_OF(X509) *spamkey_certstack;

int next_nonce = 1234;
int require_numlines = 1;

void openssl_print_error(void) {
	printf("error = %s\n", ERR_error_string(ERR_get_error(), NULL));
}

// todo: pull in key & cert generation code from old email

int load_spamkey(char *spamkey_filename, char *passwd) {
  BIO *key_bio = BIO_new_file(spamkey_filename, "rb");
  spamkey = PEM_read_bio_PrivateKey(key_bio, NULL, NULL, passwd);
  if(!spamkey) {
    printf("sfaservice: Could not read private spamkey\n");
    openssl_print_error();
    return -1;
  }
  BIO_free(key_bio);
  return 0;
}

int load_sfas_certs(char *spamkey_cert_filename, char *sfas_ca_filename) {
  BIO *ca_crt_bio = BIO_new_file(sfas_ca_filename, "rb");
  X509 *ca_cert = PEM_read_bio_X509(ca_crt_bio, NULL, NULL, NULL);
  if(!ca_cert) {
    printf("sfaservice: Could not load SpamFreeAttestation CA certificate!\n");
    openssl_print_error();
    return -1;
  }

  spamkey_certstack = sk_X509_new_null();
  if(!sk_X509_push(spamkey_certstack, ca_cert)) {
    openssl_print_error();
    return -1;
  }

  BIO *key_crt_bio = BIO_new_file(spamkey_cert_filename, "rb");
  spamkey_cert = PEM_read_bio_X509(key_crt_bio, NULL, NULL, NULL);
  if(!spamkey_cert) {
    printf("sfaservice: could not load spamkey certificate\n");
    openssl_print_error();
    return -1;
  }

  BIO_free(ca_crt_bio);
  BIO_free(key_crt_bio);

  return 0;
}


pthread_t accept_thread;

static void *accept_loop(void *ctx) {
  //printf("starting accept loop\n");
  while(1) {
    int id;
    if((id = IPC_BindAcceptRequest(SpamFreeAttestationService_port_handle)) < 0) {
      printf("bindaccept error: %d\n", id);
      exit(-1);
    }
    printf("binding id %d\n", id);

    int err;
    if( (err = IPC_BindLabel(id)) != 0) {
      printf("bind label error %d\n", err);
      exit(-1);
    }
    if( (err = IPC_BindCommit(id, g_Wrap_port_handle)) != 0) {
      printf("commit returned error %d\n", err);
    }
  }
}

int main(int argc, char **argv) {
  gdb_init_remote(0, 0);

  printf("Spam-Free Attestation Service -- initializing server\n");

  if (argc > 1 && !strcmp(argv[1], "-ignorenumlines")) {
    require_numlines = 0;
    printf("Changing policy to ignore number of lines typed\n");
  } else {
    printf("Policy requires %d lines to be typed\n", require_numlines);
  }

  // init openssl
  ERR_load_crypto_strings();
  OpenSSL_add_all_digests();
  OpenSSL_add_all_algorithms();
 
  // load spamkey 
  if (load_spamkey("/nfs/spamfree.key", "foobar")) {
    exit(1);
  }
  if (load_sfas_certs("/nfs/spamfree.crt", "/nfs/spamfree-ca.crt")) {
    exit(1);
  }

  printf("Ready\n");

  SpamFreeAttestationService_serverInit();
  pthread_create(&accept_thread, NULL, accept_loop, NULL);

  // notify that we are ready
  Thread_Notify(0);

  while(1) {
    SpamFreeAttestationService_processNextCommand();
  }
}
