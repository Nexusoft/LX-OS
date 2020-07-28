#ifndef __IDENTITY_COMPAT_H__
#define __IDENTITY_COMPAT_H__

#include <openssl/rsa.h>
#include <libtcpa/identity_private.h>

#define IDENTITY_COMPAT_ASYMBLOB_LEN  TCPA_ENC_SIZE 
#define IDENTITY_COMPAT_SYMBLOB_LEN   TCPA_IDENTITY_RESP_SIZE
#define IDENTITY_COMPAT_DECRYPTED_LEN TCPA_ENC_SIZE
#define IDENTITY_COMPAT_CERT_LEN      TCPA_IDENTITY_RESP_SIZE

int tpmidentity_send_receive(unsigned char *reqbuf, int reqlen, 
			     RSA *pubkey,
			     const char *ca_addr, short ca_port,
			     unsigned char *asymblob, int *asymbloblen,
			     unsigned char *symblob, int *symbloblen);

int tpmidentity_get_cred(unsigned char *decrypt, int decryptlen,
			 unsigned char *symblob, int symbloblen,
			 unsigned char *cert, int *certlen);

unsigned char *tpmidentity_get_nexus_cred(unsigned char *req, int reqlen,
					  const char *nca_addr, short nca_port,
					  unsigned char *aikpem, int aikpemlen,
					  int *nskcredlen, int *nsksformlen);


#endif
