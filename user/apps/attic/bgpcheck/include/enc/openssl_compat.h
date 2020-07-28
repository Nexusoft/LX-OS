#ifndef OPENSSL_COMPAT_H_SHIELD
#define OPENSSL_COMPAT_H_SHIELD

#include <openssl/crypto.h>
#include <openssl/evp.h>

int OK_pubkey_export(EVP_PKEY *key, char **output);
EVP_PKEY *OK_pubkey_import(char *input, int len);
int OK_privkey_export(EVP_PKEY *key, char **output);
EVP_PKEY *OK_privkey_import(char *input, int len);
EVP_PKEY *OK_privkey_create();
EVP_PKEY *OK_privkey_dup(EVP_PKEY *oldkey);

#endif
