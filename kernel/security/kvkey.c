#include <crypto/rsa.h>
#include <libtcpa/tcpa.h> // for RAND_bytes

#include <nexus/defs.h>
#include <nexus/kvkey.h>
#include <nexus/nrk.interface.h> // for KEncBuf -- should be in kvkey?
#include <nexus/user_compat.h>
#include <nexus/x509parse.h> // for OBJID's

#define LOCAL_DEBUG_LEVEL DEBUG_LEVEL_WARN
#include <nexus/debug.h>

#include <kvkey-code.c>

KVKey_public *kvkey_deserialize_pub(unsigned char *der, int len) {
  if (len < 2 || len != der_msglen(der))
    return NULL;
  unsigned char *end = der + len;
  KVKey_public *pub = nxcompat_alloc(sizeof(KVKey_public));
  if (pub_decode(&der, end, pub) || der != end) {
    nxcompat_free(pub);
    return NULL;
  }
  return pub;
}

unsigned char *kvkey_serialize_pub(KVKey_public *pubkey) {
  int len = pub_encode(NULL, 0, pubkey);
  if (len <= 0) return NULL;
  unsigned char *buf = nxcompat_alloc(len);
  pub_encode(buf, len, pubkey);
  return buf;
}

KVKey_nsk *nsk_decode(unsigned char **der, unsigned char *end) {
  int asntag = der_unwrap(der, end, &end);
  if (asntag != DER_ASN1_SEQUENCE) FAILRETURN(NULL, "expected der SEQUENCE, got 0x%x", asntag);
  if (*der == end) FAILRETURN(NULL, "junk at end of vkey encoding");
  int err;

  unsigned char *endbody;
  if (der_unwrap(der, end, &endbody) != DER_ASN1_INTEGER) FAILRETURN(NULL, "expected der INTEGER");
  int ver;
  if (der_integer_demangle(der, endbody, &ver)) FAILRETURN(NULL, "bad integer encoding");
  if (ver != 1) FAILRETURN(NULL, "expected type tag NSK, got %d\n", ver);
  KVKey_nsk *nsk = nxcompat_alloc(sizeof(KVKey_nsk));
  err = nsk_demangle(der, end, nsk);
  if (err || *der != end) {
    nxcompat_free(nsk);
    FAILRETURN(NULL, "error, or junk at end of vkey encoding");
  }
  return nsk;
}

KVKey_nsk *nsk_deserialize(unsigned char *buf, int len) {
  if (len < 2 || len != der_msglen(buf))
    FAILRETURN(NULL, "buffer length or der length is invalid");
  return nsk_decode(&buf, buf + len);
}

int kvkey_verify(KVKey_public *pubkey,
    unsigned char *msg, unsigned int msglen,
    unsigned char *sig, unsigned int siglen)
{
  int algo;
  unsigned char digest[TCPA_HASH_SIZE];
  int digestlen = TCPA_HASH_SIZE;;
  switch(pubkey->algtype) {
    case ALG_RSA_MD2:
    //case ALG_RSA_MD4:
    case ALG_RSA_MD5:
      //algo = RSA_MD2/4/5;
      return -1;
    case ALG_RSA_SHA1:
      algo = RSA_SHA1;
      {
	struct sha1_ctx sha;
	sha1_init(&sha);
	sha1_update(&sha, msg, msglen);
	sha1_final(&sha, digest);
      }
      break;
    default:
      return -1;
  }

  if (algo != RSA_SHA1)
    return -1;

  rsa_context *rsa = nxcompat_alloc(sizeof(rsa_context));
  memset(rsa, 0, sizeof(rsa_context));
  rsa->len = pubkey->moduluslen;

  int ret;
  if ((ret = mpi_import(&rsa->N, pubkey->modulus, pubkey->moduluslen))) goto cleanup;
  if ((ret = mpi_import(&rsa->E, RSA_DEFAULT_EXPONENT_ARRAY, RSA_EXPONENT_BYTE_SIZE))) goto cleanup;
  if ((ret = rsa_pkcs1_verify(rsa, algo, digest, digestlen, sig, siglen))) goto cleanup;

cleanup:
  rsa_free(rsa);
  nxcompat_free(rsa);
  return ret;
}

int kvkey_encrypt(KVKey_public *pubkey, unsigned char *clear, int clen,
	       /* user output : */ unsigned char *user_encbuf, int *user_elen) {
  KEncBuf *enc = NULL;
  int elen = 0;
  unsigned char tcpa_oaep_pad_str[] = { 'T', 'C', 'P', 'A' };
  Map *map = nexusthread_current_map();

  peek_user(map, (unsigned int)user_elen, &elen, sizeof(int));

  if (clen <= 0) FAILRETURN(-NRK_ERR_PARAM, "empty cleartext buffer");

  int hdrclen = clen + sizeof(TPMSealHdr);

  if (hdrclen < RSA_MAX_CLEAR_SIZE) {

    /* special case for small encryptions - just use asym. key */
    
    if (elen < sizeof(KEncBuf)) FAILRETURN(-1, "encryption buffer smaller than minimum"); 
    elen = sizeof(KEncBuf);
    enc = galloc(elen);

    unsigned char *hdrclear = galloc(hdrclen);

    init_tpmhdr((TPMSealHdr *)hdrclear);
    memcpy(hdrclear + sizeof(TPMSealHdr), clear, clen);

    enc->datalen = hdrclen;
    enc->privenclen = RSA_ENC_SIZE;

    rsa_context ctx;
    if (kvkey_export_public(pubkey, &ctx)) FAILRETURN(-1, "can't export vkey into RSA format");
    int err = rsa_oaep_encrypt(&ctx,
			  hdrclear, hdrclen,
			  enc->privenc, RSA_ENC_SIZE,
			  tcpa_oaep_pad_str, 4);
    rsa_free(&ctx);

    gfree(hdrclear);
    if (err) FAILRETURN(-1, "rsa_oaep_encrypt failed");

  } else {

    /* general case - use AES key to encrypt data, private key to encrypt aes key */
    /* XXX add info into an AESKeyBuf about which type of sym. alg */
    /* XXX take a look at privacy ca request for this */

    AESKeyBuf aeskey;
    init_tpmhdr(&aeskey.tpmhdr);
    RAND_bytes((unsigned char *)aeskey.key, AES_INDIRECTION_KEYSIZE);
    RAND_bytes((unsigned char *)aeskey.iv, AES_INDIRECTION_IVSIZE);

    if (elen < sizeof(KEncBuf) + clen) FAILRETURN(-1, "encryption buffer too small");
    elen = sizeof(KEncBuf) + clen;

    enc = galloc(elen);
    enc->datalen = clen;
    enc->privenclen = RSA_ENC_SIZE;

    rsa_context ctx;
    if (kvkey_export_public(pubkey, &ctx)) FAILRETURN(-1, "can't export vkey into RSA format");
    int err = rsa_oaep_encrypt(&ctx,
			  (unsigned char *)&aeskey, sizeof(AESKeyBuf), 
			  enc->privenc, RSA_ENC_SIZE,
			  tcpa_oaep_pad_str, 4);
    rsa_free(&ctx);
    if (err) FAILRETURN(-1, "rsa_oaep_encrypt failed");

    /* encrypt data with aes key */
    int len = clen;
    nexus_cbc_encrypt(clear, clen,
		      enc->encdata, &len,
		      aeskey.key, AES_DEFAULT_KEYSIZE,
		      aeskey.iv, AES_IV_SIZE);
    assert(len == clen);
  }

  peek_user(map, (unsigned int)user_elen, &elen, sizeof(int));
  poke_user(map, (unsigned int)user_encbuf, enc, elen);
  return 0;
}

int kvkey_export_public(KVKey_public *pubkey, rsa_context *ctx)
{
  memset(ctx, 0, sizeof(rsa_context));
  ctx->len = pubkey->moduluslen;

  int ret;
  if ((ret = mpi_import(&ctx->N, pubkey->modulus, pubkey->moduluslen))) {
    rsa_free(ctx);
    FAILRETURN(-1, "mp_import failed for modulus");
  }
  if ((ret = mpi_import(&ctx->E, RSA_DEFAULT_EXPONENT_ARRAY, RSA_EXPONENT_BYTE_SIZE))) {
    rsa_free(ctx);
    FAILRETURN(-1, "mp_import failed for exponent");
  }

  return 0;
}

Form *kvkey_prin(KVKey_public *pubkey) {
  if (!pubkey) return NULL;
  char *buf = kvkey_serialize_pub(pubkey);
  if (!buf) return term_fmt("anonymous");
  Form *prin = term_fmt("der(%{bytes})", buf, der_msglen(buf));
  nxcompat_free(buf);
  return prin;
}
