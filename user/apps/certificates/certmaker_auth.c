/** NexusOS: Generate an Authority Credential */

#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h> 
#include <netinet/in.h>
#include <errno.h>

#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/bio.h>

#include <libtcpa/keys.h>

#include <assert.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include <string.h>

#include <nexus/ca.h>

int main(int argc, char **argv){
  X509 *skel = X509_new();

  if(argc != 3){
    printf("usage: nexuscertskeleton privatekey.pem pubkey.pem\n");
    exit(-1);
  }

  char *privfile = argv[1];
  char *pubfile = argv[2];

  FILE *privfp = fopen(privfile, "r");
  EVP_PKEY *privkey = PEM_read_PrivateKey(privfp, NULL, NULL, NULL);

  FILE *pubfp = fopen(pubfile, "r");
  EVP_PKEY *pubkey = PEM_read_PUBKEY(pubfp, NULL, NULL, NULL);

  RSA *privrsa = EVP_PKEY_get1_RSA(privkey);
  RSA *pubrsa = EVP_PKEY_get1_RSA(pubkey);

  unsigned char modulus[RSA_MODULUS_BYTE_SIZE];
  int moduluslen;
  BN_bn2bin(pubrsa->n, modulus);
  moduluslen = BN_num_bytes(pubrsa->n);
  
  BIO *extbio = BIO_new_file("certs/skel.cnf", "r");
  generate_credential(skel, pubrsa, privrsa, "Trusted Nexus", NULL, "skeleton.crt", "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef");
  BIO_free(extbio);

  return 0;
}
