#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/objects.h>
#include <openssl/buffer.h>

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/rand.h>

X509_NAME *create_x509_issuer_name(const char *country,
				   const char *organization, const char *cn);
X509_NAME *create_x509_email_name(const char *address, const char *cn);
X509 *X509_generate(X509_NAME *subject_name, EVP_PKEY **pkey_rv);
RSA *RSA_generate(void);
void nexus_cert_init(void);
void X509_print_cert(X509 *x509);
