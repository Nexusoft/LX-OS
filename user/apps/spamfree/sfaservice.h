#ifndef _SFASERVICE_H_
#define _SFASERVICE_H_

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

// these have to be here, becuase the idl generator chokes on STACK_OF(...)

// key associated with "spamfree" property
extern EVP_PKEY *spamkey; // must be RSA
#define SPAMKEY_SIG_LEN (4096 / 8)

// cert (and stack of certs) for spamkey
extern X509 *spamkey_cert;
extern STACK_OF(X509) *spamkey_certstack;

extern int next_nonce;
extern int require_numlines;

#endif // _SFASERVICE_H_
