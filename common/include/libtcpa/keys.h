/****************************************************************************/
/*                                                                          */
/* KEYS.H 08 Apr 2003                                                       */
/*                                                                          */
/* This file is copyright 2003 IBM. See "License" for details               */
/****************************************************************************/
#ifndef KEYS_H
#define KEYS_H

#include <libtcpa/tpm.h>
#include <crypto/aes.h>


#define TPMKEY_WRAPPED_SIZE (sizeof(KeyData)) 

/* the max sizes for certain ready-for-tpm structures */
#define TCPA_ASYM_PARM_SIZE  (24 + RSA_EXPONENT_BYTE_SIZE)
#define TCPA_SYM_PARM_SIZE   (24 + AES_IV_SIZE)
#define TCPA_PUBKEY_SIZE     (TCPA_ASYM_PARM_SIZE + 4 + RSA_MODULUS_BYTE_SIZE)
#define TCPA_SYM_KEY_SIZE    (AES_MAX_KEYSIZE + 8)

//#define TCPA_CERTIFY_INFO_SIZE (TCPA_VERSION_SIZE + 7 + TCPA_ASYM_PARM_SIZE + TCPA_HASH_SIZE + TCPA_NONCE_SIZE + 5)
//#define TCPA_CERTIFY_INFO_SIZE (TCPA_VERSION_SIZE + 7 + TCPA_ASYM_PARM_SIZE + TCPA_HASH_SIZE + TCPA_NONCE_SIZE + 5 + TCPA_MAX_PCRINFO_SIZE)
#define TCPA_CERTIFY_INFO_SIZE (124)
#define TCPA_CERTIFY_REQ_SIZE (sizeof(CertifyKeyData))

#define DEFAULT_RSA_BITLEN    (2048)
#define DEFAULT_RSA_EXPONENT  (65537)
extern unsigned char rsa_default_exponent_array_g[];
#define DEFAULT_RSA_EXPONENT_ARRAY  (rsa_default_exponent_array_g)

typedef struct SymKeyData{
  unsigned int algorithm;
  unsigned short encscheme;
  unsigned short sigscheme;
  unsigned int keylength;
  unsigned int blocksize;
  unsigned int ivsize;
  unsigned char IV[AES_IV_SIZE];
  unsigned char key[AES_MAX_KEYSIZE];
}SymKeyData;

//#include <openssl/rsa.h>
typedef struct PubKeyData PubKeyData;
struct PubKeyData {
    unsigned int algorithm;
    unsigned short encscheme;
    unsigned short sigscheme;
    unsigned int keybitlen;
    unsigned int numprimes;
    unsigned int expsize;
    unsigned char exponent[RSA_EXPONENT_BYTE_SIZE];
    unsigned int keylength;
    unsigned char modulus[RSA_MODULUS_BYTE_SIZE];
    unsigned int pcrinfolen;
    unsigned char pcrinfo[256];
};

typedef struct TPM_PubKey TPM_PubKey;
struct TPM_PubKey{
  /* TCPA_Key Parms */
  unsigned int algorithm;
  unsigned short encscheme;
  unsigned short sigscheme;
  unsigned int parmsize;
  /* TCPA_Key Parms->parms*/
  unsigned int keybitlen;
  unsigned int numprimes;
  unsigned int expsize;
  unsigned char exponent[RSA_EXPONENT_BYTE_SIZE];
  /* TCPA_StorePubkey */
  unsigned int keylength;
  unsigned char modulus[RSA_MODULUS_BYTE_SIZE];
};

typedef struct KeyData KeyData;
struct KeyData{
    unsigned char version[TCPA_VERSION_SIZE];
    unsigned short keyusage;
    unsigned int keyflags;
    unsigned char authdatausage;
    PubKeyData pub;
    unsigned int privkeylen;
    unsigned char encprivkey[1024];
};

typedef struct CertifyKeyData CertifyKeyData;
struct CertifyKeyData{
  unsigned char version[TCPA_VERSION_SIZE];
  unsigned short keyusage;
  unsigned int keyflags;
  unsigned char authdatausage;
  PubKeyData pub;
  unsigned char nonce[TCPA_NONCE_SIZE];
  unsigned char parentpcr;
  unsigned int pcrinfolen;
  unsigned char pcrinfo[256];
  unsigned char sig[TCPA_SIG_SIZE];
};

//12
typedef struct TPMKeyParms TPMKeyParms;
struct TPMKeyParms {
   unsigned int algorithmID;
   unsigned short encScheme;
   unsigned short sigScheme;
   unsigned int parmSize;
   unsigned char parms[0];
};
typedef struct TPMStorePubKey TPMStorePubKey;
struct TPMStorePubKey{
   unsigned int keyLength;
   unsigned char key[0];
};

#pragma pack(1)
//4
typedef struct TPMStructVer TPMStructVer;
struct TPMStructVer{
   unsigned char major;
   unsigned char minor;
   unsigned char revMajor;
   unsigned char revMinor;
};
#pragma pack()

#pragma pack(1)
typedef struct TPMCertifyInfoHdr TPMKeyHdr;
typedef struct TPMCertifyInfoHdr TPMCertifyInfoHdr;
struct TPMCertifyInfoHdr{
  TPMStructVer version;
  unsigned short keyUsage;
  unsigned int keyFlags;
  unsigned char authDataUsage;
  unsigned char algorithmParms[0];
};
#pragma pack()

#pragma pack(1)
typedef struct TPMCertifyInfoTail TPMCertifyInfoTail;
struct TPMCertifyInfoTail{
  unsigned char pubKeyDigest[TCPA_HASH_SIZE];
  unsigned char data[TCPA_HASH_SIZE];
  unsigned char parentPCRStatus;
  unsigned int PCRInfoSize;
  unsigned char PCRInfo[0];
};
#pragma pack()

#ifdef __NEXUSKERNEL__
int KeyExtract(unsigned char *keybuff, KeyData *k);
int PubKeyExtract(unsigned char *pkeybuff, PubKeyData *k, int pcrpresent);
int BuildKey(unsigned char *buffer, KeyData *k);
int KeySize(unsigned char *keybuff);
int PubKeySize(unsigned char *keybuff, int pcrpresent);
#else
/* USER ONLY */
#include <openssl/rsa.h>

int pubkeydata_from_rsa(RSA *rsa, PubKeyData *pub);
RSA *rsa_from_pubkeydata(PubKeyData *k);
int pubkeydata_from_pem(const char *filename, PubKeyData *pub);
int pem_from_pubkeydata(PubKeyData *pub, const char *filename);
#endif

void create_pubkey(PubKeyData *new_key, unsigned char *modulus, short es, short ss);

/* functions to get and put a struct from/to ready-for-tpm form */
int BuildPubKeyParms(unsigned char *buffer, PubKeyData *key);
int ExtractPubKeyParms(PubKeyData *key, unsigned char *buffer);
int BuildPubKey(unsigned char *buffer, PubKeyData *key);
int ExtractPubKey(PubKeyData *key, unsigned char *buffer);
int BuildSymKeyParms(unsigned char *buffer, SymKeyData *key);
int ExtractSymKeyParms(SymKeyData *key, unsigned char *buffer);
int BuildSymKey(unsigned char *buffer, SymKeyData *key);
int ExtractSymKey(SymKeyData *key, unsigned char *buffer);

int BuildCertifyKeyReq(unsigned char *buffer, CertifyKeyData *certify);
int ExtractCertifyKeyReq(CertifyKeyData *certify, unsigned char *buffer);
int BuildCertifyKeyInfo(unsigned char *buffer, CertifyKeyData *certify);
int ExtractCertifyKeyData(CertifyKeyData *certify, unsigned char *buffer, 
			  PubKeyData *key, unsigned char *sig);


#endif
