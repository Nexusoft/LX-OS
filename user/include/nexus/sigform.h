/** NexusOS: support for signed DER-encoded NAL formulas */

#ifndef NEXUS_USER_SIGFORM_H
#define NEXUS_USER_SIGFORM_H

#include <openssl/rsa.h>

// The statement S is always in one of two form:
//  - K says S2
//  - K.subname1...subnameN says S2
// In both cases, key K is the public half of the key that produced the
// signature. After validating the signature, the statement S can be taken at
// face value. This is because the public half always appears as the left-most
// term in the statement that was signed.

void *sigform_create(void *der, RSA *key);
int sigform_verify(void *signed_der);

void * sigform_get_formula(void *signed_der);
void * sigform_get_sig(void *signed_der, int *siglen);

#endif /* NEXUS_USER_SIGFORM_H */

