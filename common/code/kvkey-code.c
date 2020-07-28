
// vkey serialization:
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
// to the serialization used by openssl.

int alg_encode(unsigned char *buf, int len, AlgType algtype) {
  switch (algtype) {
#define CASE(t) case ALG_##t: return der_oid_encode(buf, len, OBJID_##t, OBJID_##t##_LEN);
    CASE(RSA_MD2)
    CASE(RSA_MD5)
    CASE(RSA_SHA1)
    CASE(DSA_SHA1)
    CASE(RSA_ENCRYPT)
    case ALG_NONE:
    default:
      FAILRETURN(-1, "bad algtype");
#undef CASE
  }
}

static int pub_encode(unsigned char *buf, int len, KVKey_public *pub) {
  return der_pub_encode(buf, len, pub->modulus, pub->moduluslen, pub->algtype);
}

#ifndef __NEXUSKERNEL__
// kernel will need these, but does not need them yet

static int nsk_encode(unsigned char *buf, int len, KVKey_nsk *nsk) {
  int bodylen = 0, sublen = 0;
  bodylen += der_octets_encode(buf, len, nsk->wrappednsk, sizeof(nsk->wrappednsk));
  bodylen += sublen = pub_encode(buf, len-bodylen, &nsk->pub);
  if (sublen < 0) FAILRETURN(-1, "can't encode nsk");
  bodylen += der_integer_encode(buf, len-bodylen, 1);
  return bodylen + der_tag_encode(buf, len-bodylen, bodylen, DER_ASN1_SEQUENCE);
}

static int nrk_encode(unsigned char *buf, int len, KVKey_nrk *nrk) {
  int bodylen = 0, sublen = 0;
  bodylen += der_octets_encode(buf, len, nrk->wrappednrk, sizeof(nrk->wrappednrk));
  bodylen += sublen = pub_encode(buf, len-bodylen, &nrk->pub);
  if (sublen < 0) FAILRETURN(-1, "can't encode nrk");
  bodylen += der_integer_encode(buf, len-bodylen, 2);
  return bodylen + der_tag_encode(buf, len-bodylen, bodylen, DER_ASN1_SEQUENCE);
}
#endif


AlgType alg_decode(unsigned char **der, unsigned char *end) {
  int asntag = der_unwrap(der, end, &end);
  if (asntag != DER_ASN1_OBJECTIDENTIFIER) return ALG_NONE;
  int len = end - *der;
  *der += len;
#define CASE(t) if (len == OBJID_##t##_LEN && !memcmp(end - len, OBJID_##t, len)) return ALG_##t;
  CASE(RSA_MD2)
  CASE(RSA_MD5)
  CASE(RSA_SHA1)
  CASE(DSA_SHA1)
  CASE(RSA_ENCRYPT)
  return ALG_NONE;
#undef CASE
}

// 0 on success, -1 on error
static int biguint_decode(unsigned char **der, unsigned char *end, unsigned char *bigint, int *maxlen) {
  int asntag = der_unwrap(der, end, &end);
  if (asntag != DER_ASN1_INTEGER) FAILRETURN(-1, "expected der INTEGER, got 0x%x", asntag);
  return der_biguint_demangle(der, end, bigint, maxlen);
}


static int pub_ne_decode(unsigned char **der, unsigned char *end, KVKey_public *pub) {
  char exp[RSA_EXPONENT_BYTE_SIZE];
  int mlen = sizeof(pub->modulus);
  if (biguint_decode(der, end, pub->modulus, &mlen)) FAILRETURN(-1, "can't decode modulus");
  // make sure it is a reasonable key size
  if (mlen != sizeof(pub->modulus)) // todo: handle other key sizes
    FAILRETURN(-1, "modulus of unexpected size (%d bytes)", mlen);

  int explen = sizeof(exp);
  if (biguint_decode(der, end, (unsigned char *)exp, &explen)) FAILRETURN(-1, "can't decode exponent");
  if (explen != sizeof(exp)) // todo: handle other key sizes
    FAILRETURN(-1, "exponent of unexpected size (%d bytes)", explen);
  if (memcmp(exp, RSA_DEFAULT_EXPONENT_ARRAY, sizeof(exp))) FAILRETURN(-1, "wrong exponent");

  pub->moduluslen = mlen;
  return 0;
}

// precondition: sequence header is NOT already stripped
static int pub_decode(unsigned char **der, unsigned char *end, KVKey_public *pub) {
  int asntag = der_unwrap(der, end, &end);
  if (asntag != DER_ASN1_SEQUENCE) FAILRETURN(-1, "expected der SEQUENCE, got 0x%x", asntag);
  pub->algtype = alg_decode(der, end);
  if (pub->algtype == ALG_NONE) FAILRETURN(-1, "bad algtype");
  unsigned char *endbody;
  asntag = der_unwrap(der, end, &endbody);
  if (endbody != end) FAILRETURN(-1, "junk at end of public");
  if (asntag != DER_ASN1_BITSTRING) FAILRETURN(-1, "expected der BITSTRING, got 0x%x", asntag);
  // next byte had better be a zero, then we delve into the bitstring
  if (*der == end) FAILRETURN(-1, "unexpected end");
  if (**der != 0) FAILRETURN(-1, "BITSTRING should have zero unused bits, but has %d", **der);
  (*der)++;
  // inside bitstring should be a sequence
  if (der_unwrap(der, end, &endbody) != DER_ASN1_SEQUENCE) FAILRETURN(-1, "expected SEQUENCE, got 0x%x", asntag);
  if (endbody != end) FAILRETURN(-1, "junk at end of public (n,e) bitstring");
  if (pub_ne_decode(der, end, pub)) FAILRETURN(-1, "can't decode (n,e) for public");
  if (*der != endbody) FAILRETURN(-1, "junk at end of public stuff");
  return 0;
}

// precondition: sequence header and version is already stripped
static int nsk_demangle(unsigned char **der, unsigned char *end, KVKey_nsk *nsk) {
  if (pub_decode(der, end, &nsk->pub)) FAILRETURN(-1, "can't decode public");
  int asntag = der_unwrap(der, end, &end);
  if (asntag != DER_ASN1_OCTETSTRING) FAILRETURN(-1, "expected OCTETSTRING, got 0x%x", asntag);
  int len = end - *der;
  if (len != sizeof(nsk->wrappednsk)) FAILRETURN(-1, "wrong length for wrappednsk");
  memcpy(nsk->wrappednsk, *der, len);
  *der += len;
  return 0;
}

#ifndef __NEXUSKERNEL__ // not yet used by kernel -- but likely will be someday
// precondition: sequence header and version is already stripped
static int nrk_demangle(unsigned char **der, unsigned char *end, KVKey_nrk *nrk) {
  if (pub_decode(der, end, &nrk->pub)) FAILRETURN(-1, "can't decode public");
  int asntag = der_unwrap(der, end, &end);
  if (asntag != DER_ASN1_OCTETSTRING) FAILRETURN(-1, "expected OCTETSTRING, got 0x%x", asntag);
  int len = end - *der;
  if (len != sizeof(nrk->wrappednrk)) FAILRETURN(-1, "wrong length for wrappednrk");
  memcpy(nrk->wrappednrk, *der, len);
  *der += len;
  return 0;
}
#endif

