#include <iostream>
#include <openssl/pem.h>


#include "../include/enc/openssl_compat.h"

int OK_pubkey_export(EVP_PKEY *key, char **output){
  char *retptr;
  int retlen;
  BIO *mem_b = BIO_new(BIO_s_mem());
  
  PEM_write_bio_PUBKEY(mem_b, key);
  
  retlen = BIO_get_mem_data(mem_b, &retptr);
  *output = new char[retlen];
  memcpy(*output, retptr, retlen);
  
  BIO_free(mem_b);
  return retlen;
}

EVP_PKEY *OK_pubkey_import(char *input, int len){
  BIO *mem_b = BIO_new_mem_buf(input, len);
  EVP_PKEY *pubkey;
  
  pubkey = PEM_read_bio_PUBKEY(mem_b, NULL, NULL, NULL);
  
  BIO_free(mem_b);
  return pubkey;
}

int OK_privkey_export(EVP_PKEY *key, char **output){
  char *retptr;
  int retlen;
  BIO *mem_b = BIO_new(BIO_s_mem());
  
  PEM_write_bio_PrivateKey(mem_b, key, NULL, NULL, 0, NULL, (void *)"dummy_passphrase");
  
  retlen = BIO_get_mem_data(mem_b, &retptr);
  *output = new char[retlen];
  memcpy(*output, retptr, retlen);
  
  BIO_free(mem_b);
  return retlen;
}

EVP_PKEY *OK_privkey_import(char *input, int len){
  BIO *mem_b = BIO_new_mem_buf(input, len);
  EVP_PKEY *pubkey;
  
  pubkey = PEM_read_bio_PUBKEY(mem_b, NULL, NULL, (void *)"dummy_passphrase");
  
  BIO_free(mem_b);
  return pubkey;
}

EVP_PKEY *OK_privkey_create(){
  RSA *newkey;
  EVP_PKEY *sslkey;
  
  sslkey = EVP_PKEY_new();
  newkey = RSA_generate_key(1024, 3, NULL, NULL);
  EVP_PKEY_assign_RSA(sslkey, newkey);
  
  return sslkey;
}

EVP_PKEY *OK_privkey_dup(EVP_PKEY *oldkey){
  RSA *keydata = EVP_PKEY_get1_RSA(oldkey);
  EVP_PKEY *sslkey;
  
  sslkey = EVP_PKEY_new();
  EVP_PKEY_assign_RSA(sslkey, keydata);
  
  return sslkey;
}
