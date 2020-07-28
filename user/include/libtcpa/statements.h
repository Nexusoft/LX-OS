#ifndef __LIBTCPA_STATEMENTS_H__
#define __LIBTCPA_STATEMENTS_H__

#include <openssl/rsa.h>

typedef struct SignedTwelf{
  int totallen;
  unsigned char signerkey[RSA_MODULUS_BYTE_SIZE];
  unsigned char sig[TCPA_SIG_SIZE];
  int len;
  char statement[0];
}SignedTwelf;


/* pretty print a signed twelf statement */
void SignedTwelf_dump(SignedTwelf *s);


SignedTwelf *SignedTwelf_new(char *twelfptr, int twelflen, RSA *key);
void SignedTwelf_free(SignedTwelf *s);

#endif
