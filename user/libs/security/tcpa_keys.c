
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <arpa/inet.h>

#include <libtcpa/buildbuff.h>
#include <libtcpa/keys.h>

#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#include <libtcpa/keys-code.c>

/* construct the exact structure to check the signature over from a
   certifyKeyData */
int BuildCertifyKeyInfo(unsigned char *buffer, CertifyKeyData *certify){
  unsigned char keyhash[TCPA_HASH_SIZE];
  unsigned char parms[TCPA_ASYM_PARM_SIZE];
  int parmslen, bytes;

  SHA1(certify->pub.modulus, certify->pub.keylength, keyhash);
  parmslen = BuildPubKeyParms(parms, &certify->pub);

  bytes = buildbuff("% S L o % % % o @", buffer,
		    TCPA_VERSION_SIZE, certify->version,
		    certify->keyusage,
		    certify->keyflags,
		    certify->authdatausage,
		    parmslen, parms,
		    TCPA_HASH_SIZE, keyhash,
		    TCPA_NONCE_SIZE, certify->nonce,
		    certify->parentpcr,
		    certify->pcrinfolen, certify->pcrinfo);
  return bytes;
}

RSA *rsa_from_pubkeydata(PubKeyData *k)
{
  RSA *rsa;
  BIGNUM *mod;
  BIGNUM *exp;

  /* create the necessary structures */
  rsa = RSA_new();
  mod = BN_new();
  exp = BN_new();
  if (rsa == NULL || mod == NULL || exp == NULL)
    return NULL;
  /* convert the raw public key values to BIGNUMS */
  BN_bin2bn(k->modulus, k->keylength, mod);
  BN_bin2bn(k->exponent, k->expsize, exp);
  /* set up the RSA public key structure */
  rsa->n = mod;
  rsa->e = exp;

  return rsa;
}

int pubkeydata_from_rsa(RSA *rsa, PubKeyData *pub){
  int moduluslen = BN_num_bytes(rsa->n);
  printf("moduluslen = %d %d\n", moduluslen, RSA_size(rsa));
  if(moduluslen > RSA_MODULUS_BYTE_SIZE){
    printf("not enough space in tcpa structure (have %d, needed %d)!!\n", 
      RSA_MODULUS_BYTE_SIZE, moduluslen);
    return -1;
  }
  BN_bn2bin(rsa->n, pub->modulus);
  pub->keylength = moduluslen;

  int exponentlen = BN_num_bytes(rsa->e);
  printf("exponentlen = %d\n", exponentlen);
  if(exponentlen != RSA_EXPONENT_BYTE_SIZE){
    printf("exponent doesn't have correct len!! (%d != %d)\n", 
      exponentlen, RSA_EXPONENT_BYTE_SIZE);
    return -1;
  }
  BN_bn2bin(rsa->e, pub->exponent);
  pub->expsize = exponentlen;
  
  pub->numprimes = RSA_NUMPRIMES;
  pub->keybitlen = RSA_size(rsa) * 8;
  pub->sigscheme = TCPA_SS_NONE;
  pub->encscheme = TCPA_ES_RSAESOAEP_SHA1_MGF1;  /* public keys will always be 
                   used for encryption, not 
                   signing */
  pub->algorithm = TCPA_ALG_RSA;

  return 0;
}

/* formatting help */
int pubkeydata_from_pem(const char *filename, PubKeyData *pub){
  //TCPA_Enc_Scheme encScheme, TCPA_Sig_Scheme sigScheme){
  EVP_PKEY *pkey;
  RSA *rsa;
  FILE *fp;
  int ret;

  fp = fopen(filename, "r");
  printf("fopened %s\n", filename);
  pkey = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
  printf("got pubkey\n");
  rsa = EVP_PKEY_get1_RSA(pkey);
  printf("got rsa\n");

  ret = pubkeydata_from_rsa(rsa, pub);

  fclose(fp);

  return ret;
}

int pem_from_pubkeydata(PubKeyData *pub, const char *filename){
  RSA *rsa = rsa_from_pubkeydata(pub);
  EVP_PKEY *pkey = EVP_PKEY_new();
  FILE *fp;
  int ret;
  fp = fopen(filename, "w");
  //ret = PEM_write_RSAPublicKey(fp, rsa);
  EVP_PKEY_set1_RSA(pkey, rsa);
  ret = PEM_write_PUBKEY(fp, pkey);
  fclose(fp);
  EVP_PKEY_free(pkey);
  return ret;
}


