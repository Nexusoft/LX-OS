#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <crypto/aes.h>
#include <nexus/mt19937ar.h>
#include <assert.h>

#include <libtcpa/keys.h>


/* XXX This test always fails because these libtcpa functions put in the
   default exponent */
int main(int argc, char **argv){
  if(argc != 2){
    printf("usage: tpmstructtest 0x5eed");
  }
  int i;

  unsigned int seed = strtoul(argv[1], NULL, 16);
  pseudorand_init(seed);

  PubKeyData pubkey, pubkey2;
  unsigned char pubkeybuf[TCPA_PUBKEY_SIZE];

  memset(&pubkey, 0, sizeof(PubKeyData));
  memset(&pubkey2, 0, sizeof(PubKeyData));
  pubkey.algorithm = pseudorand(1, 10000);
  pubkey.encscheme = (unsigned short)pseudorand(1, 10000);
  pubkey.sigscheme = (unsigned short)pseudorand(1, 10000);
  pubkey.keybitlen = pseudorand(1, 10000);
  pubkey.numprimes = pseudorand(1, 10000);
  pubkey.expsize = RSA_EXPONENT_BYTE_SIZE;
  for(i = 0; i < RSA_EXPONENT_BYTE_SIZE; i++)
    pubkey.exponent[i] = (unsigned char)pseudorand(1, 256);
  pubkey.keylength = RSA_MODULUS_BYTE_SIZE;
  for(i = 0; i < RSA_MODULUS_BYTE_SIZE; i++)
    pubkey.modulus[i] = (unsigned char)pseudorand(1, 256);
  BuildPubKey(pubkeybuf, &pubkey);
  ExtractPubKey(&pubkey2, pubkeybuf);
  if(memcmp(&pubkey, &pubkey2, sizeof(PubKeyData)) != 0){
    printf("difference on line: %d\n",__LINE__);
    return -1;
  }

  printf("success!\n");
  return 0;
}
