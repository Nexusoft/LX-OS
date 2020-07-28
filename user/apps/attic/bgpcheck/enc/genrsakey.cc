#include <iostream>

extern "C" {
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/engine.h>
#include <openssl/blowfish.h>
}

#include <assert.h>

int main(){
  RSA *rsa = RSA_new();
  BIGNUM *e = NULL;
  
  BN_dec2bn(&e, "17");

  RSA_generate_key_ex(rsa, 1024, e, NULL);
  
  printf("n: %s\n", BN_bn2dec(rsa->n));
  printf("e: %s\n", BN_bn2dec(rsa->e));
  printf("d: %s\n", BN_bn2dec(rsa->d));
  printf("p: %s\n", BN_bn2dec(rsa->p));
  printf("q: %s\n", BN_bn2dec(rsa->q));
  printf("dmp1: %s\n", BN_bn2dec(rsa->dmp1));
  printf("dmp2: %s\n", BN_bn2dec(rsa->dmq1));
  printf("iqmp: %s\n", BN_bn2dec(rsa->iqmp));
  assert(rsa);


}
