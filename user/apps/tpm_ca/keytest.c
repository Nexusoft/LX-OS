#include <stdlib.h>
#include <stdio.h>
#include <openssl/rsa.h>

int main(int argc, char **argv){
  RSA *key = RSA_generate_key(2048, 65537, NULL, NULL);
  printf("modulus size=%d\n", BN_num_bytes(key->n));
  printf("public size=%d\n", BN_num_bytes(key->e));
  printf("private size=%d\n", BN_num_bytes(key->e));
  return 0;
}
