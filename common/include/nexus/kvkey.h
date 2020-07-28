#ifndef __KVKEY_H__
#define __KVKEY_H__

#include <nexus/commontypedefs.h>
#include <nexus/formula.h>
#include <libtcpa/tpm.h>
#include <libtcpa/keys.h>

typedef enum AlgType{
  ALG_NONE,
  ALG_RSA_MD2,
  ALG_RSA_MD5,
  ALG_RSA_SHA1,
  ALG_DSA_SHA1,
  ALG_RSA_ENCRYPT,
#define ALG_DEFAULT ALG_NONE
}AlgType;

int alg_encode(unsigned char *buf, int len, AlgType algtype);
AlgType alg_decode(unsigned char **der, unsigned char *end);

/* this data structure must be flat */
struct KVKey_public {
  AlgType algtype;
  /* make into a union if we have other types of keys */
  int moduluslen;
  unsigned char modulus[RSA_MAX_MODULUS_BYTE_SIZE]; // only the first moduluslen bytes are used
  // exponent is RSA_DEFAULT_EXPONENT_ARRAY = {0x10 0x00 0x01} = 65537
  // exponent len is RSA_EXPONENT_BYTE_SIZE = 3 bytes
};

#ifdef __NEXUSKERNEL__

#include <crypto/rsa.h>

// returns 0 if signature is valid, <0 on error
int kvkey_verify(KVKey_public *pubkey,
    unsigned char *msg, unsigned int msglen,
    unsigned char *sig, unsigned int siglen);
KVKey_public *kvkey_deserialize_pub(unsigned char *der, int len);
unsigned char *kvkey_serialize_pub(KVKey_public *pubkey);
int kvkey_export_public(KVKey_public *pubkey, rsa_context *ctx);
int kvkey_encrypt(KVKey_public *pubkey, unsigned char *clear, int clen,
	       /* user output : */ unsigned char *user_encbuf, int *user_elen);

#endif


/* note: following structs need to mesh with those in user/compat/vkey.c */

struct KVKey_nrk {
  KVKey_public pub;
  unsigned char wrappednrk[TPMKEY_WRAPPED_SIZE];
};

struct KVKey_nsk {
  KVKey_public pub;
  unsigned char wrappednsk[TPMKEY_WRAPPED_SIZE];
};

// this must be identical to above two; all three should go away, or this should
// just be a union
struct KVKey_tpm {
  KVKey_public pub;
  unsigned char wrappedkey[TPMKEY_WRAPPED_SIZE];
};

#ifdef __NEXUSKERNEL__
KVKey_nsk *nsk_deserialize(unsigned char *buf, int len);
int nsk_sign_len(KVKey_nsk *nsk);
int nsk_sign(KVKey_nsk *nsk,
    char *msg, unsigned int msglen,
    char *sig, unsigned int siglen);

#include <nexus/formula.h>
SignedFormula *formula_sign(Formula *f, KVKey_nsk *key);

#endif

Form *kvkey_prin(KVKey_public *pubkey);

#endif
