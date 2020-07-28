#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>

#include <nexus/vkey.h> 
#include <nexus/kvkey.h> 
#include <nexus/nrk.interface.h> 
#include <nexus/nsk.interface.h> 
#include <nexus/IPC.interface.h>
#include <nexus/LabelStore.interface.h>

#include <nexus/identity_compat.h> /* XXX interface with old
					     library which should be
					     cleaned up.  Then this
					     header file can
					     dissapear. */

#include <libtcpa/tpm.h>  /* rsa/tcpa constants in here */
#include <libtcpa/keys.h> /* nsk wrapped size.. should be cleaned up */

#include <nexus/generaltime.h> 

#include <nexus/util.h>
#include <assert.h>
#include <string.h>

#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/objects.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/evp.h>

/* to contact ca's */
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <nexus/base64.h>

#define LOCAL_DEBUG_LEVEL DEBUG_LEVEL_WARN
#include <nexus/debug.h>


/* private vkey type definitions */

struct VKey_public{
  VKeyType type;
  KVKey_public pub;
  // optional private data follows
} /* typedef'd to VKey in vkey.h */;

// subtypes of vkey_public: start of these must match VKey_public
typedef struct VKey_pair{
  VKeyType type;
  KVKey_public pub;
  unsigned char privexp[RSA_PRIVEXP_BYTE_SIZE];
  unsigned char prime1[RSA_PRIVEXP_BYTE_SIZE/2];
  unsigned char prime2[RSA_PRIVEXP_BYTE_SIZE/2];
  unsigned char exp1[RSA_PRIVEXP_BYTE_SIZE/2];
  unsigned char exp2[RSA_PRIVEXP_BYTE_SIZE/2];
  unsigned char coef[RSA_PRIVEXP_BYTE_SIZE/2];
}VKey_pair;

typedef struct VKey_nsk{
  VKeyType type;
  KVKey_nsk nsk; // pub is inside nsk
}VKey_nsk;

typedef struct VKey_nrk{
  VKeyType type;
  KVKey_nrk nrk; // pub is inside nrk
}VKey_nrk;

VKeyType vkey_get_type(VKey *vkey) {
  return vkey->type;
}

AlgType vkey_get_algo(VKey *vkey) {
  return vkey->pub.algtype;
}

void vkey_set_algo(VKey *vkey, AlgType algtype) {
  vkey->pub.algtype = algtype;
}

/* Internal debug function to print key. */
static void vkey_dump(VKey *vkey){
  printf("vkey 0x%p (%s):\n", vkey, (vkey->type == VKEY_TYPE_PUBLIC)?"PUBLIC":
	 ((vkey->type == VKEY_TYPE_PAIR)?"PAIR":
	  ((vkey->type == VKEY_TYPE_NSK)?"NSK":
	   ((vkey->type == VKEY_TYPE_NRK)?"NRK":
	    "UNKNOWN"))));
  printf("  algtype = %d\n", vkey->pub.algtype); 
  printf("  moduluslen = %d\n", vkey->pub.moduluslen);
  printf("  public modulus: ");
  PRINT_BYTES(vkey->pub.modulus, 20);
  printf("...\n");
  if(vkey->type == VKEY_TYPE_PAIR){
    printf("  private expont: ");
    PRINT_BYTES(((VKey_pair *)vkey)->privexp, 20);
    printf("...\n");
  }
  printf("\n");
}


/* Create vkey of type type. */
VKey *vkey_create(VKeyType type, AlgType algtype /* only used for VKEY_TYPE_PAIR */ ){
  switch(type){
  case VKEY_TYPE_PUBLIC:
    FAILRETURN(NULL, "Cannot create a key of type \"public\"");
  case VKEY_TYPE_PAIR:
    {
      VKey *vkey = NULL;

      dprintf(INFO, "vkey: generating rsa key with exp %d (len %d)\n", RSA_DEFAULT_EXPONENT_LONG, RSA_MODULUS_BYTE_SIZE);
      RSA *rsa = RSA_generate_key(RSA_MODULUS_BIT_SIZE, RSA_DEFAULT_EXPONENT_LONG, NULL, NULL);

      BN_free(rsa->p);
      BN_free(rsa->q);
      BN_free(rsa->dmp1);
      BN_free(rsa->dmq1);
      BN_free(rsa->iqmp);
      rsa->p = rsa->q = rsa->dmp1 = rsa->dmq1 = rsa->iqmp = NULL;

      if(DEBUG_INFO){
	BIO *bio = BIO_new_fp(stdout, BIO_NOCLOSE);
	RSA_print(bio, rsa, 0);
	dprintf(INFO, "VKEY: rsa generated: 0x%p\n", rsa);
      }
      vkey = vkey_openssl_import(rsa);
      vkey->pub.algtype = algtype;

      RSA_free(rsa);
  
      return vkey;
    }
    break;
  case VKEY_TYPE_NSK:
    {
      VKey_nsk *nsk = (VKey_nsk *)malloc(sizeof(VKey_nsk));
      nsk->type = VKEY_TYPE_NSK;
      int ret = nsk_create(&nsk->nsk);
  
      if(ret < 0){
	free(nsk);
	FAILRETURN(NULL, "problem creating nsk");
      }

      if (DEBUG_INFO) vkey_dump((VKey *)nsk);

      return (VKey *)nsk;
    }
    break;
  case VKEY_TYPE_NRK:
    {
      VKey_nrk *nrk = (VKey_nrk *)malloc(sizeof(VKey_nrk));
      nrk->type = VKEY_TYPE_NRK;
      int ret = nrk_create(&nrk->nrk);
  
      if(ret < 0){
	free(nrk);
	FAILRETURN(NULL, "problem creating nrk");
      }
  
      return (VKey *)nrk;
    }
    break;
  default:
    FAILRETURN(NULL, "can't create unknown key type");
    break;
  }
}

/* Free vkey memory. */
void vkey_destroy(VKey *vkey){
  free(vkey);
}

// vkey serialization (only pair is here, rest is in common/code/kvkey-code.c)
// VKEY_TYPE_PUBLIC is serialized as SubjectPublicKeyInfo and PKCS#1 (DER format):
//   SubjectPublicKeyInfo ::= SEQUENCE {
//     algorithm	  AlgorithmIdentifier,	-- always rsaEncrypt or sha1WithRSAEncrypt
//     subjectPublicKey	  BIT STRING,		-- always a DER encoded RSAPublicKey
//   }
//   RSAPublicKey ::= SEQUENCE {
//     modulus		  INTEGER,  -- n
//     publicExponent	  INTEGER,  -- e
//   }
// VKEY_TYPE_PAIR is serialized as PKCS#1 / PKCS#8 (DER format):
//   RSAPrivateKey ::= SEQUENCE {
//     version		  Version,  -- always equals two-prime(0)
//     modulus		  INTEGER,  -- n
//     publicExponent	  INTEGER,  -- e
//     privateExponent	  INTEGER,  -- d
//     prime1		  INTEGER,  -- p
//     prime2		  INTEGER,  -- q
//     exponent1	  INTEGER,  -- d mod (p-1)
//     exponent2	  INTEGER,  -- d mod (q-1) 
//     coefficient	  INTEGER,  -- (inverse of q) mod p
//     otherPrimeInfos	  OtherPrimeInfos OPTIONAL  -- always absent
//   }
// VKEY_TYPE_NSK is serialized in our own format:
//   NSKWrappedPrivateKey ::= SEQUENCE {
//     version		  INTEGER,		-- always equals 1
//     public		  SubjectPublicKeyInfo, -- algtype and public keys
//     wrappednsk	  OCTETSTRING		-- encrypted nsk (with a policy)
//   }
// VKEY_TYPE_NRK is serialized in our own format:
//   NSKWrappedPrivateKey ::= SEQUENCE {
//     version		  INTEGER,		-- always equals 2
//     public		  SubjectPublicKeyInfo, -- algtype and public keys
//     wrappednrk	  OCTETSTRING		-- encrypted nrk
//   }
//
// vkey deserialization:
// outer should always be a sequence of 2 or more elements
// first element is an OID ==> always VKEY_TYPE_PUBLIC
// first element is INTEGER 0 ==> always VKEY_TYPE_PAIR
// first element is INTEGER 1 ==> always VKEY_TYPE_NSK
// first element is INTEGER 2 ==> always VKEY_TYPE_NRK
//
// Note: The serializations of VKEY_TYPE_PUBLIC and VKEY_TYPE_PAIR are identical
// to the serialization used by openssl and many other tools. 

#include <../../../common/code/kvkey-code.c>

static int pair_encode(unsigned char *buf, int len, VKey_pair *pair) {
  int bodylen = 0;
  bodylen += der_biguint_encode(buf, len-bodylen, pair->coef, sizeof(pair->coef));
  bodylen += der_biguint_encode(buf, len-bodylen, pair->exp2, sizeof(pair->exp2));
  bodylen += der_biguint_encode(buf, len-bodylen, pair->exp1, sizeof(pair->exp1));
  bodylen += der_biguint_encode(buf, len-bodylen, pair->prime2, sizeof(pair->prime2));
  bodylen += der_biguint_encode(buf, len-bodylen, pair->prime1, sizeof(pair->prime1));
  bodylen += der_biguint_encode(buf, len-bodylen, pair->privexp, sizeof(pair->privexp));
  bodylen += der_biguint_encode(buf, len-bodylen,
      RSA_DEFAULT_EXPONENT_ARRAY, RSA_EXPONENT_BYTE_SIZE);
  bodylen += der_biguint_encode(buf, len-bodylen, pair->pub.modulus, pair->pub.moduluslen);
  bodylen += der_integer_encode(buf, len-bodylen, 0); // version
  return bodylen + der_tag_encode(buf, len-bodylen, bodylen, DER_ASN1_SEQUENCE);
}

int vkey_encode(char *buf, int len, VKey *vkey, int public_only) {
  if (public_only || (vkey->type == VKEY_TYPE_PUBLIC))
    return pub_encode(buf, len, &vkey->pub);
  else if (vkey->type == VKEY_TYPE_PAIR)
    return pair_encode(buf, len, (VKey_pair *)vkey);
  else if (vkey->type == VKEY_TYPE_NSK)
    return nsk_encode(buf, len, &((VKey_nsk *)vkey)->nsk);
  else if (vkey->type == VKEY_TYPE_NRK)
    return nrk_encode(buf, len, &((VKey_nrk *)vkey)->nrk);
  else
    FAILRETURN(-1, "unknown vkey type");
}

char *vkey_serialize(VKey *vkey, int public_only) {
  int len = vkey_encode(NULL, 0, vkey, public_only);
  if (len < 0) FAILRETURN(NULL, "could not determine vkey serialized length");
  char *buf = malloc(len);
  if (!buf) FAILRETURN(NULL, "malloc failed");
  int written = vkey_encode(buf, len, vkey, public_only);
  assert(written == len && der_msglen(buf) == len);
  return buf;
}

#define BIGUINT_DECODE(der, end, buf) \
{ \
  int size = sizeof(buf); \
  if (biguint_decode(der, end, buf, &size)) FAILRETURN(-1, "expected der INTEGER"); \
  if (size < sizeof(buf)) { /* zero extend */ \
    int prefix = sizeof(buf)-size; \
    memmove(buf+prefix, buf, size); \
    memset(buf, 0, prefix); \
  } \
} 

// precondition: sequence header and version is already stripped
static int pair_demangle(unsigned char **der, unsigned char *end, VKey_pair *pair) {
  pair->pub.algtype = ALG_NONE;
  if (pub_ne_decode(der, end, &pair->pub)) FAILRETURN(-1, "could not decode public (n,e) values");
  BIGUINT_DECODE(der, end, pair->privexp);
  BIGUINT_DECODE(der, end, pair->prime1);
  BIGUINT_DECODE(der, end, pair->prime2);
  BIGUINT_DECODE(der, end, pair->exp1);
  BIGUINT_DECODE(der, end, pair->exp2);
  BIGUINT_DECODE(der, end, pair->coef);
  return 0;
}
#undef BIGUINT_DECODE

VKey *vkey_decode(unsigned char **der, unsigned char *end) {
  VKey *vkey;
  unsigned char *orig = *der;
  int asntag = der_unwrap(der, end, &end);
  if (asntag != DER_ASN1_SEQUENCE) FAILRETURN(NULL, "expected der SEQUENCE, got 0x%x", asntag);
  if (*der == end) FAILRETURN(NULL, "junk at end of vkey encoding");
  int err;

  asntag = (*der)[0]; // peek at next tag
  if (asntag == DER_ASN1_OBJECTIDENTIFIER) {
    vkey = malloc(sizeof(VKey));
    vkey->type = VKEY_TYPE_PUBLIC;
    *der = orig; // back up: pub_decode will unwrap the sequence start again
    err = pub_decode(der, end, &vkey->pub);
  } else {
    unsigned char *endbody;
    if (der_unwrap(der, end, &endbody) != DER_ASN1_INTEGER) FAILRETURN(NULL, "expected der INTEGER");
    int ver;
    if (der_integer_demangle(der, endbody, &ver)) FAILRETURN(NULL, "bad integer encoding");
    switch(ver) {
      case 0:
	vkey = malloc(sizeof(VKey_pair));
	vkey->type = VKEY_TYPE_PAIR;
	err = pair_demangle(der, end, (VKey_pair *)vkey);
	break;
      case 1:
	vkey = malloc(sizeof(VKey_nsk));
	vkey->type = VKEY_TYPE_NSK;
	err = nsk_demangle(der, end, &((VKey_nsk *)vkey)->nsk);
	break;
      case 2:
	vkey = malloc(sizeof(VKey_nrk));
	vkey->type = VKEY_TYPE_NRK;
	err = nrk_demangle(der, end, &((VKey_nrk *)vkey)->nrk);
	break;
      default:
	FAILRETURN(NULL, "unknown key type-tag (%d)", ver);
    }
  }
  if (err || *der != end) {
    free(vkey);
    FAILRETURN(NULL, "error, or junk at end of vkey encoding");
  }
  return vkey;
}

VKey *vkey_deserialize(char *buf, int len) {
  if (len < 2 || len != der_msglen(buf))
    FAILRETURN(NULL, "buffer length or der length is invalid");
  return vkey_decode((unsigned char **)&buf, buf + len);
}


/* Return the type of k (public, pair, or nsk). */
VKeyType vkey_type(VKey *k){
  return k->type;
}


int vkey_sign_len(VKey *vkey){
  /* XXX check alg type on key. */
  return TCPA_SIG_SIZE;
}

int vkey_sign(VKey *vkey, unsigned char *m, unsigned int m_len,
	      unsigned char *sig, int *siglen){

  if(vkey->type != VKEY_TYPE_PAIR)
    FAILRETURN(-1, "vkey_sign only works for key pairs");
  if(vkey_sign_len(vkey) > *siglen)
    FAILRETURN(-1, "bad siglen");


  RSA *key = vkey_openssl_export(vkey);

  unsigned char tmphash[TCPA_HASH_SIZE];
  /* XXX check alg type on key */
  SHA1(m, m_len, tmphash);

  if(DEBUG_INFO){
    int i;
    printf("hash: ");
    for(i = 0; i < TCPA_HASH_SIZE; i++)
      printf("%02x ", tmphash[i]);
    printf("\n");
  }


  /* XXX check alg type on key */
  int tmp_siglen = TCPA_SIG_SIZE;
  int ret = RSA_sign(NID_sha1, tmphash, TCPA_HASH_SIZE, sig, &tmp_siglen, key);
  RSA_free(key);

  if(ret != 1)
    FAILRETURN(-1, "RSA_sign failed");

  *siglen = tmp_siglen;

  return 0;
}


int vkey_verify(VKey *vkey, unsigned char *m, unsigned int m_len, 
		unsigned char *sig, int siglen){
  RSA *key = vkey_openssl_export(vkey);
  int ret;

  unsigned char tmphash[TCPA_HASH_SIZE];
  SHA1(m, m_len, tmphash);

  if(DEBUG_INFO){
    int i;
    printf("hash: ");
    for(i = 0; i < TCPA_HASH_SIZE; i++)
      printf("%02x ", tmphash[i]);
    printf("\n");
  }

  ret =  RSA_verify(NID_sha1, tmphash, TCPA_HASH_SIZE, sig, siglen, key);
  if(ret != 1){
    ERR_load_crypto_strings();
    ERR_print_errors_fp(stdout);
  }

  RSA_free(key);
  return (ret == 1)?0:-1;
}


int vkey_seal_data_len(VKey *resealerpubkey, 
		    int secretlen, 
		    _Policy *unsealpolicy, _Policy *resealpolicy){
  return vkey_encrypt_len(resealerpubkey, NULL,
			  sizeof(SealBundle) + secretlen + _Policy_len(unsealpolicy) + _Policy_len(resealpolicy));
}
int vkey_seal_data(VKey *resealerpubkey, 
	      unsigned char *secret, int secretlen,
	      _Policy *unsealpolicy,
	      _Policy *resealpolicy,
	      /* output: */
	      unsigned char *sealeddata, int *sealeddatalen){
  int ret;

  /* create bundle */ 
  int unsealpolicybufsize = _Policy_len(unsealpolicy);
  int resealpolicybufsize = _Policy_len(resealpolicy);
  SealBundle *bundle = (SealBundle *)malloc(sizeof(SealBundle) + unsealpolicybufsize + resealpolicybufsize + secretlen);
  bundle->secretlen = secretlen;
  bundle->unsealpolicylen = unsealpolicybufsize;
  bundle->resealpolicylen = resealpolicybufsize;
  memcpy(SEALBUNDLE_SECRET(bundle), secret, secretlen);
  _Policy_serialize(unsealpolicy, SEALBUNDLE_UNSEALPOLICY(bundle), &bundle->unsealpolicylen);
  _Policy_serialize(resealpolicy, SEALBUNDLE_RESEALPOLICY(bundle), &bundle->resealpolicylen);

  /* seal to resealerpubkey */
  ret = vkey_encrypt(resealerpubkey, 
		     (unsigned char *)bundle, SEALBUNDLE_LEN(bundle),
		     sealeddata, sealeddatalen);

  /* sanity check len */
  assert(*sealeddatalen == vkey_seal_data_len(resealerpubkey, 
					   secretlen, 
					   unsealpolicy, resealpolicy));

  free(bundle);
  return ret;
}

int vkey_nrk_unseal_data(VKey *vnrk, unsigned char *sealeddata, int sealeddatalen, 
			   unsigned char *unsealeddata, int *unsealeddatalen,
			   _Grounds *pg){
  int ret;

  if(vnrk->type != VKEY_TYPE_NRK)
    FAILRETURN(-1, "vkey_nrk_unseal_data only works with NRKs");

  VKey_nrk *nrk = (VKey_nrk *)vnrk;

  /* unseal from local platform */
  dprintf(INFO, "calling unseal..");
  ret = nrk_unseal(&nrk->nrk,
		   sealeddata, sealeddatalen,
		   pg,
		   unsealeddata, unsealeddatalen);
  dprintf(INFO, "%d\n", ret);
  if(ret < 0)
    FAILRETURN(-1, "nrk_unseal failed");

  return 0;
}

int vkey_user_unseal_data(VKey *unwrapprivkey,
			    unsigned char *sealeddata, int sealeddatalen, 
			    /* output: */
			    unsigned char *unsealeddata, int *unsealeddatalen,
			    _Policy **unsealpolicy, _Policy **resealpolicy) {
  //XXX check type of key?

  int len = vkey_decrypt_len(unwrapprivkey, sealeddata, sealeddatalen);
  assert(len > sizeof(SealBundle));
  SealBundle *bundle = malloc(len);
  int ret = vkey_decrypt(unwrapprivkey,
		     sealeddata, sealeddatalen,
		     (unsigned char *)bundle, &len);
  assert(len > sizeof(SealBundle));

  if(*unsealeddatalen < bundle->secretlen)
    FAILRETURN(-1, "buffer to small for unsealed data");

  *unsealeddatalen = bundle->secretlen;
  memcpy(unsealeddata, SEALBUNDLE_SECRET(bundle), bundle->secretlen);

  if (unsealpolicy) {
    len = bundle->unsealpolicylen;
    *unsealpolicy = malloc(len);
    _Policy_deserialize(*unsealpolicy, &len, SEALBUNDLE_UNSEALPOLICY(bundle), len);
  }

  if (resealpolicy) {
    len = bundle->resealpolicylen;
    *resealpolicy = malloc(len);
    _Policy_deserialize(*resealpolicy, &len, SEALBUNDLE_RESEALPOLICY(bundle), len);
  }

  free(bundle);

  return 0;
}

VKey *vkey_nrk_unseal(VKey *nrk, unsigned char *sealeddata, int sealeddatalen, 
		      _Grounds *pg){
  int maxdatalen = sealeddatalen;
  int len = maxdatalen;
  
  unsigned char *buf = malloc(len);
  int ret = vkey_nrk_unseal_data(nrk, sealeddata, sealeddatalen, 
				   buf, &len, pg);

  if(ret < 0){
    free(buf);
    FAILRETURN(NULL, "problem unsealing buffer with nrk (ret=%d)", ret);
  }
  assert(len <= maxdatalen);

  VKey *new = vkey_deserialize(buf, len);
  free(buf);

  return new;
}

int vkey_nrk_reseal(VKey *vnrk, VKey *anystoragepub,
		      unsigned char *sealeddata, int sealeddatalen, 
		      unsigned char *resealeddata, int *resealeddatalen, 
		      _Grounds *pg){
  if (vnrk->type != VKEY_TYPE_NRK)
    return -VKEY_ERR_WRONGTYPE;
  KVKey_nrk *nrk = &((VKey_nrk *)vnrk)->nrk;
  return nrk_reseal(nrk, &anystoragepub->pub,
			  sealeddata, sealeddatalen,
			  resealeddata, resealeddatalen,
			  pg);
}

VKey *vkey_user_unseal(VKey *unwrapprivkey,
		       unsigned char *sealeddata, int sealeddatalen,
		       _Policy **unsealpolicy, _Policy **resealpolicy) {
  int maxdatalen = sealeddatalen;
  int len = maxdatalen;

  unsigned char *buf = malloc(len);
  int ret = vkey_user_unseal_data(unwrapprivkey, 
				    sealeddata, sealeddatalen, 
				    buf, &len,
				    unsealpolicy, resealpolicy);
  if(ret < 0){
    free(buf);
    FAILRETURN(NULL, "problem unsealing buffer (ret=%d)", ret);
  }
  assert(len <= maxdatalen);

  VKey *new = vkey_deserialize(buf, len);
  free(buf);

  return new;
}

int vkey_seal_len(VKey *resealerpubkey, VKey *vkey, _Policy *unsealpolicy, _Policy *resealpolicy) {
  int len = vkey_encode(NULL, 0, vkey, 0);
  if (len < 0) FAILRETURN(-1, "could not get vkey encoded length");
  return vkey_seal_data_len(resealerpubkey, len, unsealpolicy, resealpolicy);
}

int vkey_seal(VKey *resealerpubkey, 
	      VKey *vkey, 
	      _Policy *unsealpolicy, _Policy *resealpolicy,
	      /* output: */
	      unsigned char *sealeddata, int *sealeddatalen){
  unsigned char *serialized = vkey_serialize(vkey, 0);
  if (!serialized)
    FAILRETURN(-1, "could not serialize vkey");
  int ret = vkey_seal_data(resealerpubkey,
			serialized, der_msglen(serialized),
			unsealpolicy, resealpolicy, 
			sealeddata, sealeddatalen);
  free(serialized);
  return ret;
}


/* import/export to openssl */
VKey *vkey_openssl_import(RSA *key){
  unsigned char exponent[RSA_EXPONENT_BYTE_SIZE];

  /* ensure the RSA key is of the limited type we support */
  /* VKEYs could be easily extended to other types of RSA keys */
  if(BN_num_bytes(key->n) != RSA_MODULUS_BYTE_SIZE)
    FAILRETURN(NULL, "unimplemented (%d byte modulus)", BN_num_bytes(key->n));
  if(BN_num_bytes(key->e) != RSA_EXPONENT_BYTE_SIZE)
    FAILRETURN(NULL, "unimplemented (%d byte exponent)", BN_num_bytes(key->e));
  if(key->d && BN_num_bytes(key->d) > RSA_PRIVEXP_BYTE_SIZE)
    FAILRETURN(NULL, "unimplemented (%d byte priv exponent)", BN_num_bytes(key->d));

  BN_bn2bin(key->e, exponent);
  if(memcmp(exponent, RSA_DEFAULT_EXPONENT_ARRAY, RSA_EXPONENT_BYTE_SIZE) != 0)
    FAILRETURN(NULL, "wrong RSA exponent");

  VKeyType newtype = (key->d ? VKEY_TYPE_PAIR : VKEY_TYPE_PUBLIC);

  VKey *new;
  if(newtype == VKEY_TYPE_PAIR){
    VKey_pair *newpair = (VKey_pair *)malloc(sizeof(VKey_pair));
    newpair->type = VKEY_TYPE_PAIR;
    newpair->pub.moduluslen = RSA_PRIVEXP_BYTE_SIZE;

    /* include leading zeros */
    int offset = RSA_PRIVEXP_BYTE_SIZE - BN_num_bytes(key->d);
    memset(newpair->privexp, 0, offset);
    BN_bn2bin(key->d, newpair->privexp + offset);

    new = (VKey *)newpair;
  }else{
    new = (VKey *)malloc(sizeof(VKey));
    new->type = VKEY_TYPE_PUBLIC;
  }

  /* include leading zeros */
  int off = RSA_PRIVEXP_BYTE_SIZE - BN_num_bytes(key->n);
  memset(new->pub.modulus, 0, off);
  BN_bn2bin(key->n, new->pub.modulus + off);
  new->pub.moduluslen = RSA_MODULUS_BYTE_SIZE;

  if (DEBUG_INFO){
    unsigned char tmphash[TCPA_HASH_SIZE];
    SHA1((unsigned char *)new, sizeof(VKey), tmphash);
    
    BIO *bio = BIO_new_fp(stdout, BIO_NOCLOSE);
    RSA_print(bio, key, 0);
    //BN_print(bio, key->n);

    printf("key imported: ");
    PRINT_HASH(tmphash);

    vkey_dump(new);
  }

  new->pub.algtype = ALG_NONE;

  return new;
}
RSA *vkey_openssl_export(VKey *key){

  RSA *new = RSA_new();

  new->n = BN_new();
  new->e = BN_new();
  new->d = NULL;

  BN_bin2bn(RSA_DEFAULT_EXPONENT_ARRAY, RSA_EXPONENT_BYTE_SIZE, new->e);
  BN_bin2bn(key->pub.modulus, RSA_MODULUS_BYTE_SIZE, new->n);
  
  if(key->type == VKEY_TYPE_PAIR){
    new->d = BN_new();
    BN_bin2bn(((VKey_pair *)key)->privexp, RSA_PRIVEXP_BYTE_SIZE, new->d);
  }

  if (DEBUG_INFO){
    unsigned char tmphash[TCPA_HASH_SIZE];
    SHA1((unsigned char *)key, sizeof(VKey), tmphash);
    
    printf("key to export: ");
    PRINT_HASH(tmphash);

    vkey_dump(key);
    
    BIO *bio = BIO_new_fp(stdout, BIO_NOCLOSE);
    RSA_print(bio, new, 0);
    //BN_print(bio, new->n);
  }

  return new;
}


static int asym_encrypt_helper(VKey *vkey, 
			       unsigned char *from, int flen, 
			       unsigned char *to, int tolen){
  unsigned char padded[RSA_MODULUS_BYTE_SIZE];
  unsigned char tcpa_oaep_pad_str[] = { 'T', 'C', 'P', 'A' };
  int ret;

  assert(tolen == RSA_ENC_SIZE);

  /* encrypt symmetric keys with private key */
  ret = RSA_padding_add_PKCS1_OAEP(padded, RSA_MODULUS_BYTE_SIZE,
				   from, flen,
				   tcpa_oaep_pad_str,
				   sizeof tcpa_oaep_pad_str);
  if (ret == 0)
    FAILRETURN(-1, "could not add rsa PKCS#1 OAEP padding");
  
  if(DEBUG_INFO){
    unsigned char tmpbuf[RSA_MODULUS_BYTE_SIZE];
    int i;
    for(i = 0; i < RSA_MODULUS_BYTE_SIZE; i++)
      if(padded[i] != 0)
	break;
  
    ret = RSA_padding_check_PKCS1_OAEP(tmpbuf, RSA_MODULUS_BYTE_SIZE,
				       padded+i, RSA_MODULUS_BYTE_SIZE-i,
				       RSA_MODULUS_BYTE_SIZE,
				       tcpa_oaep_pad_str,
				       sizeof tcpa_oaep_pad_str);
    printf("checking padding during encrypt %d\n", ret);
    if(ret < 0){
      ERR_load_crypto_strings();
      ERR_print_errors_fp(stdout);
    }
    assert(ret >= 0);

    printf("padded: ");
    PRINT_BYTES(padded, 20);
    printf("...\n");

  }


  RSA *key = vkey_openssl_export(vkey);
  
  tolen = RSA_public_encrypt(RSA_MODULUS_BYTE_SIZE, padded, to,
				   key, RSA_NO_PADDING);

  assert(tolen == RSA_ENC_SIZE);
  RSA_free(key);

  if(DEBUG_INFO){
    printf("encrypted: ");
    PRINT_BYTES(to, 20);
    printf("...\n");
  }
  
  return 0;
}
static int asym_decrypt_helper(VKey *vkey, unsigned char *from, int flen,
			       unsigned char *to, unsigned int tolen){
  unsigned char padded[RSA_MODULUS_BYTE_SIZE];
  unsigned char tcpa_oaep_pad_str[] = { 'T', 'C', 'P', 'A' };
  int ret;

  RSA *key = vkey_openssl_export(vkey);

  if(DEBUG_INFO){
    unsigned char tmphash[TCPA_HASH_SIZE];
    printf("decrypting: ");
    PRINT_BYTES(from, 20);
    printf("...\n");
    SHA1(from, flen, tmphash);
    PRINT_HASH(tmphash);
  }

  int len = RSA_private_decrypt(flen, from, padded,
				key, RSA_NO_PADDING);
  assert(len == RSA_MODULUS_BYTE_SIZE);
  RSA_free(key);

  
  if(DEBUG_INFO){
    printf("padded: ");
    PRINT_BYTES(padded, 20);
    printf("...\n");
  }

  int i;
  for(i = 0; i < RSA_MODULUS_BYTE_SIZE; i++)
    if(padded[i] != 0)
      break;
  
  ret = RSA_padding_check_PKCS1_OAEP(to, tolen,
				     padded + i, RSA_MODULUS_BYTE_SIZE - i,
				     RSA_MODULUS_BYTE_SIZE,
				     tcpa_oaep_pad_str,
				     sizeof tcpa_oaep_pad_str);
  if(ret < 0){
    if (DEBUG_WARN) {
      ERR_load_crypto_strings();
      ERR_print_errors_fp(stdout);
    }
    FAILRETURN(-1, "padding check failed");
  }

  return 0;
}

int vkey_encrypt_len(VKey *vkey, unsigned char *clear, int clearlen){
  if(clearlen < AES_BLOCK_SIZE)
    return sizeof(KEncBuf);
  else
    return sizeof(KEncBuf) + clearlen;
}
int vkey_encrypt(VKey *vkey, 
		 unsigned char *clear, int clen, 
		 /* output: */
		 unsigned char *encbuf, 
		 /* input/output: */
		 int *elen){
  int ret;

  if(clen <= 0)
    FAILRETURN(-1, "bad clen in encrypt");

  /* special case for super small encryptions - just use asym. key */
  if(clen + sizeof(TPMSealHdr) < RSA_MAX_CLEAR_SIZE){
    dprintf(INFO, "elen = %d, size = %d\n", *elen, sizeof(KEncBuf));
    
    if(*elen < sizeof(KEncBuf))
      return -VKEY_ERR_OUTSPACE;


    unsigned char *hdrclear = (unsigned char *)malloc(clen + sizeof(TPMSealHdr));
    int hdrclen = clen + sizeof(TPMSealHdr);

    init_tpmhdr((TPMSealHdr *)hdrclear);
    memcpy(hdrclear + sizeof(TPMSealHdr), clear, clen);
    
    KEncBuf *enc = (KEncBuf *)encbuf;
    enc->datalen = hdrclen;
    enc->privenclen = RSA_ENC_SIZE;

    ret = asym_encrypt_helper(vkey, hdrclear, hdrclen, enc->privenc, RSA_ENC_SIZE);
    free(hdrclear);

    assert(enc->datalen == hdrclen);

    dprintf(INFO, "asym_encrypt ret = %d\n", ret);

    if(ret < 0){
      FAILRETURN(-1, "asym_encrypt_helper failed");
    }
    return 0;
  }else{
    /* general case - use AES key to encrypt data, private key to encrypt aes key */
    /* XXX add info into an AESKeyBuf about which type of sym. alg */
    /* XXX take a look at privacy ca request for this */
    AESKeyBuf aeskey;
    init_tpmhdr(&aeskey.tpmhdr);
    RAND_bytes((unsigned char *)aeskey.key, AES_INDIRECTION_KEYSIZE);
    RAND_bytes((unsigned char *)aeskey.iv, AES_INDIRECTION_IVSIZE);

    if(*elen < sizeof(KEncBuf) + clen)
      return -VKEY_ERR_OUTSPACE;

    KEncBuf *enc = (KEncBuf *)encbuf;
    enc->datalen = clen;
    enc->privenclen = RSA_ENC_SIZE;
    ret = asym_encrypt_helper(vkey, 
			      (unsigned char *)&aeskey, sizeof(AESKeyBuf), 
			      enc->privenc, RSA_ENC_SIZE);
    assert(enc->datalen == clen);
    if(ret < 0){
      FAILRETURN(-1, "asym_encrypt_helper failed");
    }

    /* encrypt data with aes key */
    int len = clen;
    nexus_cbc_encrypt(clear, clen,
		      enc->encdata, &len,
		      aeskey.key, AES_DEFAULT_KEYSIZE,
		      aeskey.iv, AES_IV_SIZE);
    assert(len == clen);
    
    return 0;
  }
}

int vkey_decrypt_len(VKey *vkey, unsigned char *sealeddata, int enclen){
  if(((KEncBuf *)sealeddata)->datalen < RSA_MAX_CLEAR_SIZE)
    return ((KEncBuf *)sealeddata)->datalen - sizeof(TPMSealHdr);
  return ((KEncBuf *)sealeddata)->datalen;
}
int vkey_decrypt(VKey *vkey, 
		 unsigned char *enc, int elen, 
		 /* output: */
		 unsigned char *clear, 
		 /* input/output: */
		 int *clen){
  int ret;

  if(vkey->type != VKEY_TYPE_PAIR)
    return -VKEY_ERR_WRONGTYPE;

  KEncBuf *src = (KEncBuf *)enc;

  /* special case for very small data */
  if(src->datalen < RSA_MAX_CLEAR_SIZE){
    if(*clen < src->datalen - sizeof(TPMSealHdr))
      return -VKEY_ERR_OUTSPACE;

    int tmpbuflen = src->datalen;
    unsigned char *tmpbuf = (unsigned char *)malloc(tmpbuflen);

    ret = asym_decrypt_helper(vkey, src->privenc, RSA_ENC_SIZE, tmpbuf, tmpbuflen);
    
    if(ret < 0){
      free(tmpbuf);
      return ret;
    }
    
    *clen = tmpbuflen - sizeof(TPMSealHdr);
    memcpy(clear, tmpbuf + sizeof(TPMSealHdr), *clen);

    free(tmpbuf);
  } else {
    /* general case uses aes key */
    if(*clen < src->datalen)
      return -VKEY_ERR_OUTSPACE;


    AESKeyBuf aeskey;
    ret = asym_decrypt_helper(vkey, src->privenc, RSA_ENC_SIZE, 
			      (unsigned char *)&aeskey, sizeof(AESKeyBuf));
    if(ret < 0)
      return ret;
    
    /* aes decrypt */
    nexus_cbc_decrypt(src->encdata, src->datalen,
		      clear, clen,
		      aeskey.key, AES_DEFAULT_KEYSIZE,
		      aeskey.iv, AES_IV_SIZE);
  } 
  
  return -VKEY_ERR_SUCCESS;
}










#define PEMHDR "-----BEGIN CERTIFICATE-----\n"
#define PEMFTR "-----END CERTIFICATE-----\n"
#define PEMHDRLEN strlen(PEMHDR)
#define PEMFTRLEN strlen(PEMFTR)
#define OPENSSL_FOLD (64)

/* XXX move these functions somewhere */
static int fold_len(int orig, int num){
  int newlines = (orig - 1)/num;
  return orig + newlines + 1;
}
static int fold(char *str, int num, char *dst, int dstlen){
  int orig = strlen(str);
  int newlines = (orig - 1)/num;
  if(dstlen < orig + newlines + 1)
    FAILRETURN(-1, "problem folding");
  int i;
  int off = 0;
  for(i = 0; i <= newlines; i++){
    int tocopy = min(num, orig + newlines - off);
    memcpy(dst + off, str + (i * num), tocopy);
    off += tocopy;
    dst[off] = '\n';
    off++;
  }
  dst[off] = '\0';

  return 0;
}

static int vkey_x509_pemify(unsigned char *der, int derlen, char *x509, int *x509len){
  char *unfolded = (char *)malloc(BASE64_LENGTH(derlen)+1);
  base64_encode(der, derlen, unfolded, BASE64_LENGTH(derlen)+1);

  strcpy(x509, PEMHDR);
  int ret = fold(unfolded, OPENSSL_FOLD, x509 + PEMHDRLEN, *x509len - PEMHDRLEN);
  if(ret < 0)
    FAILRETURN(-1, "could not fold message");
  int len = strlen(x509);
  if(len + PEMFTRLEN >= *x509len)
    FAILRETURN(-1, "problem of some kind");
  strcpy(x509 + len, PEMFTR);
  *x509len = len + PEMFTRLEN + 1;
  x509[*x509len - 1] = '\0';

  free(unfolded);
  return 0;
}


int vkey_user_certify_key_len(VKey *usersigpair, VKey *anypub, 
			      unsigned char *serialnum, int serialnumlen,
			      char *iss_countryname, char *iss_statename,
			      char *iss_localityname, char *iss_orgname,
			      char *iss_orgunit, char *iss_commonname,
			      char *subj_countryname, char *subj_statename,
			      char *subj_localityname, char *subj_orgname,
			      char *subj_orgunit, char *subj_commonname,
			      TimeString *starttime, TimeString *endtime){
  if(usersigpair->type != VKEY_TYPE_PAIR)
    FAILRETURN(-1, "vkey_user_certify_key_len only works on type PAIR");

  int len = construct_x509(serialnum, serialnumlen,
			   usersigpair->pub.algtype,
			
			   iss_countryname, iss_statename,
			   iss_localityname, iss_orgname,
			   iss_orgunit, iss_commonname,
			
			   starttime, endtime,
			   anypub->pub.algtype,
			
			   anypub->pub.modulus, anypub->pub.moduluslen,
			   //XXX get pub exp from vkey struct
			   RSA_DEFAULT_EXPONENT_ARRAY, RSA_EXPONENT_BYTE_SIZE,
			
			   subj_countryname, subj_statename,
			   subj_localityname, subj_orgname,
			   subj_orgunit, subj_commonname,
			
			   anypub->pub.moduluslen, //siglen
			   NULL, 0);
  return PEMHDRLEN + PEMFTRLEN
    + fold_len(BASE64_LENGTH(len), OPENSSL_FOLD)
    + 1; /* add one for terminator */
}
int vkey_user_certify_key(VKey *usersigpair, VKey *anypub, 
			  unsigned char *serialnum, int serialnumlen,
			  char *iss_countryname, char *iss_statename,
			  char *iss_localityname, char *iss_orgname,
			  char *iss_orgunit, char *iss_commonname,
			  char *subj_countryname, char *subj_statename,
			  char *subj_localityname, char *subj_orgname,
			  char *subj_orgunit, char *subj_commonname,
			  TimeString *starttime, TimeString *endtime,
			  char *x509, int *x509len){

  if(usersigpair->type != VKEY_TYPE_PAIR)
    FAILRETURN(-1, "vkey_user_certify_key only works on type PAIR");
  //XXX check alg type is one we know
  
  int neededlen = vkey_user_certify_key_len(usersigpair, anypub, 
					    serialnum, serialnumlen,
					    iss_countryname, iss_statename,
					    iss_localityname, iss_orgname,
					    iss_orgunit, iss_commonname,
					    subj_countryname, subj_statename,
					    subj_localityname, subj_orgname,
					    subj_orgunit, subj_commonname,
					    starttime, endtime);

  if(*x509len < neededlen)
    FAILRETURN(-1, "x509 length too small ");


  int derlen = construct_x509(serialnum, serialnumlen,
			      usersigpair->pub.algtype,
			   iss_countryname, iss_statename,
			   iss_localityname, iss_orgname,
			   iss_orgunit, iss_commonname,
			   starttime, endtime,
			   anypub->pub.algtype,
			   anypub->pub.modulus, anypub->pub.moduluslen,
			   //XXX get pub exp from vkey struct
			   RSA_DEFAULT_EXPONENT_ARRAY, RSA_EXPONENT_BYTE_SIZE,
			   subj_countryname, subj_statename,
			   subj_localityname, subj_orgname,
			   subj_orgunit, subj_commonname,
			   anypub->pub.moduluslen, //siglen
			   NULL, 0);
  assert(derlen != 0);
  
  unsigned char *der = (unsigned char *)malloc(derlen);

  int reallen = construct_x509(serialnum, serialnumlen,
			       usersigpair->pub.algtype,
			       
			       iss_countryname, iss_statename,
			       iss_localityname, iss_orgname,
			       iss_orgunit, iss_commonname,
			       
			       starttime, endtime,
			       anypub->pub.algtype,
			       
			       anypub->pub.modulus, anypub->pub.moduluslen,
			       //XXX get pub exp from vkey struct
			       RSA_DEFAULT_EXPONENT_ARRAY, RSA_EXPONENT_BYTE_SIZE,
			       
			       subj_countryname, subj_statename,
			       subj_localityname, subj_orgname,
			       subj_orgunit, subj_commonname,
			       
			       anypub->pub.moduluslen,//siglen
			       der, derlen);
  assert(reallen == derlen);

  int msglen, siglen;
  unsigned char *msg = parsex509_getmsg(der, &msglen);
  unsigned char *sig = parsex509_getsig(der, &siglen);

  int ret = vkey_sign(usersigpair, msg, msglen, sig, &siglen);
  if(ret < 0)
    FAILRETURN(-1, "vkey_sign failed");


  ret = vkey_x509_pemify(der, derlen, x509, x509len);
  assert(ret == 0);
  free(der);

  return 0;
}
int vkey_nsk_certify_key_len(VKey *nsk, VKey *anypub, 
			     TimeString *starttime, TimeString *endtime){
  if(nsk->type != VKEY_TYPE_NSK)
    FAILRETURN(-1, "vkey_nsk_certify_key_len only works on NSKs");

  VKey_nsk *vnsk = (VKey_nsk *)nsk;
  int len = nsk_certify_x509_len(&anypub->pub,
				 &vnsk->nsk,
				 (char *)starttime, strlen(starttime) + 1,
				 (char *)endtime, strlen(endtime) + 1);
  

  return PEMHDRLEN + PEMFTRLEN
    + fold_len(BASE64_LENGTH(len), OPENSSL_FOLD) 
    + 1; /* add one for terminator. */
}

int vkey_nsk_certify_key(VKey *nsk, VKey *anypub, 
			 TimeString *starttime, TimeString *endtime,
			 char *x509, int *x509len){
  if(nsk == NULL)
    FAILRETURN(-1, "nsk is NULL!!");
  if(nsk->type != VKEY_TYPE_NSK)
    FAILRETURN(-1, "nsk_certify_key only works for NSKs");
  if(*x509len < vkey_nsk_certify_key_len(nsk, anypub, starttime, endtime))
    FAILRETURN(-1, "x509 length was too small");

  VKey_nsk *vnsk = (VKey_nsk *)nsk;
  int ncertlen = nsk_certify_x509_len(&anypub->pub,
				      &vnsk->nsk,
				      (char *)starttime, strlen(starttime) + 1,
				      (char *)endtime, strlen(endtime) + 1);
  int x509derlen = ncertlen;
  unsigned char *x509der = (unsigned char *)malloc(x509derlen);

  int ret = nsk_certify_x509(&anypub->pub,
			     &vnsk->nsk,
			     (char *)starttime, strlen(starttime) + 1,
     			     (char *)endtime, strlen(endtime) + 1,
			     x509der, &x509derlen);

  if(ret < 0)
    FAILRETURN(-1, "nsk_certify_x509 failed (ret=%d)", ret);

  ret = vkey_x509_pemify(x509der, x509derlen, x509, x509len);
  free(x509der);

  assert(*x509len = vkey_nsk_certify_key_len(nsk, anypub, starttime, endtime));
  
  if(ret < 0)
    FAILRETURN(-1, "vkey_nsk_certify_key_len failed (ret=%d)", ret);

  return 0;
}

struct aik_nsk_cert_ctx {
  int wrappedaiklen;
  unsigned char wrappedaik[TPMKEY_WRAPPED_SIZE];
  int aikcertlen;
  unsigned char *aikcert;
  int nsrkcertlen;
  unsigned char *nsrkcert;
};

static int vkey_privacy_cert(char *cax509pem, int cax509pemlen, struct aik_nsk_cert_ctx *ctx) {
  BIO *stmtbio = BIO_new_mem_buf(cax509pem, cax509pemlen);
  X509 *cax509 = PEM_read_bio_X509_AUX(stmtbio, NULL, NULL, NULL);
  EVP_PKEY *pkey = X509_get_pubkey(cax509);
  RSA *pubkey = EVP_PKEY_get1_RSA(pkey);

  int extid = X509_get_ext_by_NID(cax509, NID_subject_alt_name, -1);
  X509_EXTENSION *ext = X509_get_ext(cax509, extid);
  if(!ext) FAILRETURN(-1, "subject alt name extension not found");
  ASN1_OCTET_STRING *asn = X509_EXTENSION_get_data(ext);
  if(!asn) FAILRETURN(-1, "bad subject alt name extention");

  char *dns = NULL; 
  char *uri = NULL; 
  unsigned int ca_addr = 0;
  short ca_port = 0;
  parse_subjaltname(&dns, &uri, &ca_addr, M_ASN1_STRING_data(asn));
  dprintf(WARN, "dns=%s uri=%s ip=0x%x\n", dns, uri, ca_addr);

  if(ca_addr == 0){
    if(!dns)
      FAILRETURN(-1, "one of dns or ip must be present in subject alt name");
    dprintf(INFO, "dnsname = %s\n", dns);
    struct hostent *ent = gethostbyname(dns);
    ca_addr = *(unsigned int *)(ent->h_addr);
  }
  if(uri != NULL){
    char *ptr = strstr(uri, "//");
    ptr += 2; /* skip over "//" */
    char *portptr = strchr(ptr, ':');
    portptr += 1; /* skip over ':' */
    ca_port = (short)atoi(portptr);
  }
  
  dprintf(WARN, "ca_addr=0x%x ca_port = %d\n", ca_addr, ca_port);

  VKey *capubkey = vkey_openssl_import(pubkey);
  capubkey->pub.algtype = ALG_RSA_ENCRYPT; 

  int reqlen = nsk_request_tpm_certification_len(&capubkey->pub);
  unsigned char *reqbuf = (unsigned char *)malloc(reqlen);

  dprintf(WARN, "about to call with 0x%p\n", &capubkey->pub);

  vkey_dump(capubkey);  
  ctx->wrappedaiklen = TPMKEY_WRAPPED_SIZE;
  int ret = nsk_request_tpm_certification(&capubkey->pub,
				      ctx->wrappedaik, &ctx->wrappedaiklen,
				      reqbuf, &reqlen);

  if(ret < 0)
    FAILRETURN(-1, "nsk_request_tpm_certification failed (ret=%d)", ret);

  if(DEBUG_INFO){
    unsigned char *proof = reqbuf;

    PubKeyData reqpubkey;
    pubkeydata_from_rsa(pubkey, &reqpubkey);

    IdentityProofData dbgproof;
    IdentityContentsData id;
    unsigned char idcontents[TCPA_IDCONTENTS_SIZE];
    ExtractIdentityProof(&dbgproof, proof);
    fillIdentityContentsData(&id, dbgproof.labelArea, dbgproof.labelSize,
			     &reqpubkey, &dbgproof.identityKey);
    int size = BuildIdentityContents(idcontents, &id);
    unsigned char hash[TCPA_HASH_SIZE];
    SHA1(idcontents, size, hash);
    printf("idcontents (len=%d) hash:", size);
    PRINT_HASH(hash);
    writefile("idcontents.bin", idcontents, size);
    SHA1(dbgproof.idbinding, dbgproof.idbindingSize, hash);
    printf("idbinding (len=%d) hash:", dbgproof.idbindingSize);
    writefile("idbinding.bin", dbgproof.idbinding, dbgproof.idbindingSize);
    PRINT_HASH(hash);
    SHA1((unsigned char *)&dbgproof.identityKey, sizeof(PubKeyData), hash);
    printf("idpubkeydata (len=%d) hash:", sizeof(PubKeyData));
    writefile("idpubkeydata.bin", &dbgproof.identityKey, sizeof(PubKeyData));
    PRINT_HASH(hash);
    //PRINT_BYTES((unsigned char *)&dbgproof.identityKey, sizeof(PubKeyData));
    //printf("\n");
    /* check the signature of chosenid by idkey */
    RSA *pubidkey = rsa_from_pubkeydata(&dbgproof.identityKey);
    SHA1(idcontents, size, hash);
    int ret = RSA_verify(NID_sha1, hash, TCPA_HASH_SIZE,
			 dbgproof.idbinding, dbgproof.idbindingSize, pubidkey);
    if(ret != 1){
      printf("identity binding signature didn't match ret=%d\n", ret);
      ERR_load_crypto_strings();
      ERR_print_errors_fp(stdout);
      printf("either you have the wrong public EK in your tpm_platform.crt\n");
      printf(" - you can run 'get_pubek /nfs/ek.public.pem' to write your actual pubek to disk\n");
      printf(" - then run 'openssl asn1dump -strparse 19 -in /tftpboot-${username}/ek.public.pem' to see it\n");
      printf(" - and compare with 'openssl x509 -text -in /tftpboot-${username}/tpm_platform.crt\n");
      printf("OR, you have the wrong TPM version in your kernel or userspace code\n");
      printf(" - userspace is using tpm version %d.%d.%d.%d\n",
	  tcpa_version_buf_g[0], tcpa_version_buf_g[1], tcpa_version_buf_g[2], tcpa_version_buf_g[3]); 
      printf(" - kernel is using tpm version ... ??\n");
      printf(" - you can run 'tpmdemo' from the kernel shell to see the actual version of your tpm\n");
      return -1;
    }
  }


  /* ---- interface with the old library -------- */
  unsigned char asymblob[IDENTITY_COMPAT_ASYMBLOB_LEN];
  int asymbloblen = IDENTITY_COMPAT_ASYMBLOB_LEN;
  unsigned char symblob[IDENTITY_COMPAT_SYMBLOB_LEN];
  int symbloblen = IDENTITY_COMPAT_ASYMBLOB_LEN;
  unsigned char cert[IDENTITY_COMPAT_CERT_LEN];
  int certlen = IDENTITY_COMPAT_CERT_LEN;

  ret = tpmidentity_send_receive(reqbuf, reqlen, pubkey, 
				 (unsigned char *)&ca_addr, ca_port,
				 asymblob, &asymbloblen,
				 symblob, &symbloblen);
  if(ret < 0)
    FAILRETURN(-1, "tpmidentity_send_receive failed (ret=%d)", ret);
  /* ---- end interface with the old library ---- */



  int decryptlen = nsk_unlock_tpm_certification_len();
  unsigned char *decrypt = (unsigned char *)malloc(decryptlen);

  nsk_unlock_tpm_certification(ctx->wrappedaik, ctx->wrappedaiklen,
			       asymblob, asymbloblen,
			       decrypt, &decryptlen);



  /* ---- interface with the old library -------- */
  tpmidentity_get_cred(decrypt, decryptlen,
		       symblob, symbloblen,
		       cert, &certlen);
  /* ---- end interface with the old library ---- */

  dprintf(INFO, "certlen = %d", certlen);
  
  free(decrypt);
  BIO_free(stmtbio);
  X509_free(cax509);
  EVP_PKEY_free(pkey);
  RSA_free(pubkey);
  vkey_destroy(capubkey);

  ctx->aikcertlen = certlen;
  ctx->aikcert = malloc(certlen);
  memcpy(ctx->aikcert, cert, certlen);
  
  return 0;
}

unsigned char *vkey_get_remote_certification(VKey *vnsrk, 
					     char *ncax509pem, 
					     int ncax509pemlen,
					     char *cax509pem,  //XXX take out these args 
					     int cax509pemlen,
					     int *outlen, int *outlen2){
  int ret;
  unsigned char *retptr;

  if(vnsrk->type != VKEY_TYPE_NSK && vnsrk->type != VKEY_TYPE_NRK)
    FAILRETURN(NULL, "vkey_get_remote_certification only supported for NSKs and NRKs");

  /* XXX if we are having two CA's, then it makes sense to also expose
     the AIK instead of hiding it from the user in this way.  That
     would allow an AIK to be created and used for multiple NSK
     certifications, saving the effort in getting a new AIK.

     If we only have a single CA, this AIK hiding makes questionably
     more sense.
  */

  struct aik_nsk_cert_ctx ctx;
  memset(&ctx, 0, sizeof(ctx));

  if (vkey_privacy_cert(cax509pem, cax509pemlen, &ctx))
      FAILRETURN(NULL, "problem getting privacy cert");

  BIO *stmtbio = BIO_new_mem_buf(ncax509pem, ncax509pemlen);
  X509 *cax509 = PEM_read_bio_X509_AUX(stmtbio, NULL, NULL, NULL);
  EVP_PKEY *pkey = X509_get_pubkey(cax509);
  RSA *pubkey = EVP_PKEY_get1_RSA(pkey);

  int extid = X509_get_ext_by_NID(cax509, NID_subject_alt_name, -1);
  X509_EXTENSION *ext = X509_get_ext(cax509, extid);
  if(!ext) FAILRETURN(NULL, "subject alt name extention not found");
  ASN1_OCTET_STRING *asn = X509_EXTENSION_get_data(ext);
  if(!asn) FAILRETURN(NULL, "bad subject alt name extension");

  char *dns = NULL; 
  char *uri = NULL; 
  unsigned int ca_addr = 0;
  short ca_port = 0;
  parse_subjaltname(&dns, &uri, &ca_addr, M_ASN1_STRING_data(asn));
  dprintf(WARN, "dns=%s uri=%s ip=0x%x\n", dns, uri, ca_addr);

  if(ca_addr == 0){
    if(!dns)
      FAILRETURN(NULL, "either dns or ip must be present in subject alt name extension");
    dprintf(WARN, "dnsname = %s\n", dns);
    struct hostent *ent = gethostbyname(dns);
    ca_addr = *(unsigned int *)(ent->h_addr);
  }
  if(uri != NULL){
    char *ptr = strstr(uri, "//");
    ptr += 2; /* skip over "//" */
    char *portptr = strchr(ptr, ':');
    portptr += 1; /* skip over ':' */
    ca_port = (short)atoi(portptr);
  }
  
  dprintf(WARN, "ca_addr=0x%x ca_port = %d\n", ca_addr, ca_port);

  int reqlen = nsk_request_nexus_certification_len();
  unsigned char *req = (unsigned char *)malloc(reqlen);

  KVKey_tpm *nsrk;
  int is_nrk = (vnsrk->type == VKEY_TYPE_NRK);
  if (!is_nrk) {
    KVKey_nsk *nsk = &((VKey_nsk *)vnsrk)->nsk;
    nsrk = (KVKey_tpm *)nsk;
  } else {
    KVKey_nrk *nrk = &((VKey_nrk *)vnsrk)->nrk;
    nsrk = (KVKey_tpm *)nrk;
  }
  printf("... reqlen = %d\n", reqlen);
  printf("... certify_req_size+8*20+1 = %d\n", TCPA_CERTIFY_REQ_SIZE + 8*20+1);
  printf("... identity_req_size+8*20+1 = %d\n", TCPA_IDENTITY_REQ_SIZE + 8*20+1);
  
  ret = nsk_or_nrk_request_nexus_certification(ctx.wrappedaik, ctx.wrappedaiklen,
					nsrk, is_nrk, req, &reqlen);
  if(ret != 0){
    retptr = NULL;
    dprintf(WARN, "problem getting nsk certification, is_nrk = %d\n", is_nrk);
    goto get_remote_out;
  }


  int sformlen;
  /* ---- interface with the old library -------- */
  ctx.nsrkcert = tpmidentity_get_nexus_cred(req, reqlen,
					    (unsigned char *)&ca_addr, ca_port,
					    ctx.aikcert, ctx.aikcertlen,
					    &ctx.nsrkcertlen, &sformlen);
  dprintf(INFO, "tpmidentity_get_nexus_cred returned 0x%p\n", ctx.nsrkcert);
  /* ---- end interface with the old library ---- */
  
  if(ctx.nsrkcert == NULL){
    retptr = NULL;
    dprintf(WARN, "problem getting nexus cred \n");
    goto get_remote_out;
  }

  *outlen = ctx.nsrkcertlen;
  *outlen2 = sformlen;
  retptr = ctx.nsrkcert;

 get_remote_out:
  BIO_free(stmtbio);
  X509_free(cax509);
  EVP_PKEY_free(pkey);
  RSA_free(pubkey);
  free(req);
  free(ctx.aikcert);
  
  return retptr;
}

VKey *get_default_nsk(void) {
  VKey *nsk = NULL;
  int fd = open(NEXUS_DEFAULT_NSK_PATH, O_RDONLY);
  if (fd > 0) {
    int len = 5000;
    unsigned char *buf = (unsigned char *)malloc(len);
    len = read(fd, buf, len);
    if (len > 0)
      nsk = vkey_deserialize(buf, len);
    if (!nsk)
      dprintf(WARN, "vkey.c: warning -- default nsk found on disk (%s) was corrupt\n", NEXUS_DEFAULT_NSK_PATH);
    free(buf);
    close(fd);
  } else {
    dprintf(WARN, "vkey.c: warning -- no default nsk found on disk (%s)\n", NEXUS_DEFAULT_NSK_PATH);
  }
  return nsk;
}

void set_current_nsk(VKey *nsk) {
  if (!nsk || nsk->type != VKEY_TYPE_NSK) return;
  nsk_set_local(&((VKey_nsk *)nsk)->nsk);
}

char *der_key_from_cert(struct x509_st *x) {
  char *modulus = malloc(4096);
  EVP_PKEY *pkey = X509_get_pubkey(x);
  RSA *rsa = EVP_PKEY_get1_RSA(pkey);
  assert(rsa != NULL); // == NULL if wrong algtype

  int modulus_len = BN_bn2bin(rsa->n, modulus);
  assert(modulus_len > 0);
  // XXX is this the right endianness?
  int len = der_pub_encode(NULL, 0, modulus, modulus_len, ALG_RSA_SHA1);
  char *key = malloc(len);
  der_pub_encode(key, len, modulus, modulus_len, ALG_RSA_SHA1);
  free(modulus);
  return key;
}

Formula *form_bind_cert_pubkey(struct x509_st *x) {
#define PING() printf("(%d)\n", __LINE__);
  static Form *principal;
  if(principal == NULL) {
    int len;
    Formula *_principal = malloc(4096);
    len = LabelStore_Get_IPD_Name(IPC_GetMyIPD_ID(), (char *)_principal, 4096, NULL);
    assert(len <= 4096);
    principal = form_from_der(_principal);
    free(_principal);
  }

  char *key = der_key_from_cert(x);
  Formula *rv;
 printf("key = %p, body = %p\n", key, principal);
 Form *_rv = form_fmt("der(%{bytes}) speaksfor %{term}", key, der_msglen(key), principal); 
  rv = form_to_der(_rv);
  form_free(_rv);
  free(key);
  return rv;
  //   xxx kvkey_serialize_pub(&nsk->pub);
}
