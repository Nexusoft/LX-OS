/** NexusOS: support for signed DER-encoded NAL formulas */

#include <openssl/rsa.h>
#include <openssl/sha.h>

#include <nexus/guard.h>
#include <nexus/formula.h>
#include <nexus/der.h>
#include <nexus/pem.h>
#include <nexus/test.h>

// format:
//   SEQUENCE {
//    "signedformula"
//    formula_der
//    SEQUENCE { signature_bitstring }
//  }
// Signature is over formula_der (and also the auto-delegation bit, if we add
// that feature). formula_der should always encode a formula of the form
// "K says ..." or "K.n1.n2...nN says ..." or similar, so a pubkey can be
// extracted via form_get_speaker_pubkey(). This pubkey must match the key used
// to sign.

/** Extract the public key of a speaker from "speaker says S" */
static Form *
form_get_speaker_pubkey(Form *f) 
{
  if (f->tag != F_STMT_SAYS) 
  	return NULL;
  
  f = f->left;
  while (f->tag == F_TERM_CSUB || f->tag == F_TERM_OSUB) 
          f = f->left;

  if (f->tag != F_TERM_PEM && f->tag != F_TERM_DER) 
	  return NULL;

  return f;
}

/** Split a signed formula in a DER-encoded NAL statement and a signature */
static int 
signedform_parse(void *signed_der, Formula **f, 
	         char **sig, int *siglen) 
{
  unsigned char *der, *end, *endstr;
  int len;

  der = signed_der;
  end = der + der_msglen(der);
  
  if (der_unwrap(&der, end, &end) != DER_ASN1_SEQUENCE)
    ReturnError(-1, "expected asn1 SEQUENCE");
  if (der_unwrap(&der, end, &endstr) != DER_ASN1_PRINTABLESTRING)
    ReturnError(-1, "expected PRINTABLESTRING");
  
  len = endstr - der;
  if (len != strlen("signedformula") || strncmp(der, "signedformula", len))
    ReturnError(-1, "not a signed formula");
  der = endstr; // advance past string

  // next is formula sequence
  if (der + 2 >= end || der[0] != DER_ASN1_SEQUENCE)
    ReturnError(-1, "expected asn1 SEQUENCE for formula");

  *f = (Formula *)der;
  der = der + der_msglen(der); // advance past formula

  // unwrap SEQUENCE { signature_bitstring }
  if (der_unwrap(&der, end, &endstr) != DER_ASN1_SEQUENCE)
    ReturnError(-1, "expected asn1 SEQUENCE for signature");
  if (endstr != end)
    ReturnError(-1, "unexpected junk after SEQUENCE for signature");

  // pull out the signaure
  if (der_unwrap((unsigned char **)&der, (unsigned char *)end, (unsigned char **)&end) != DER_ASN1_BITSTRING)
    return -1;
  if (end - der <= 1)
    return -1; // missing signature

  if (der[0] != 0)
    return -1; // should have zero unused bits
  der++;

  *siglen = end - der;
  *sig = der;
  return 0;
}

/** Retrieve the DER-encoded formula
    does not allocate memory: returns a pointer inside signed_der */
void *
sigform_get_formula(void *signed_der) 
{
  Formula *f;
  char *sig;
  int siglen;

  return signedform_parse(signed_der, &f, &sig, &siglen) ? NULL : f;
}

/** Retrieve the signature
    does not allocate memory: returns a pointer inside signed_der */
void *
sigform_get_sig(void *signed_der, int *siglen) 
{
  Formula *f;
  char *sig;

  return signedform_parse(signed_der, &f, &sig, siglen) ? NULL : sig;
}
  
/** check the signature on signedformula
    @eturns 0 on success, <0 on error */
int 
sigform_verify(char *signed_der) 
{
  Formula *f;
  Form *fm, *fpubkey;
  RSA *key;
  char *sig, digest[20]; 
  int siglen, ret;
  
  // extract components {formula, signature} from signed formula
  if (signedform_parse(signed_der, &f, &sig, &siglen))
    ReturnError(-1, "signed formula is malformed");
  fm = form_from_der(f);
  if (!fm)
    ReturnError(-1, "formula that was signed is malformed");
  fpubkey = form_get_speaker_pubkey(fm);
  if (!fpubkey) {
    form_free(fm);
    ReturnError(-1, "formula not of form ``pem(0xab..) says S''");
  }

  // recreate key. handle both DER and PEM keys
  if (fpubkey->tag != F_TERM_PEM) 
    ReturnError(-1, "not a PEM key");
  key = rsakey_public_import(fpubkey->left->data);
  if (!key)
    ReturnError(-1, "not a valid PEM key");

  // hash and verify
  SHA1(f->body, der_msglen(f->body), digest);
  ret = nxguard_sdigest_verify(digest, key, sig, siglen);
  
  // cleanup
  form_free(fm);
  return ret;
}

static int 
sigform_encode(unsigned char *buf, int len, unsigned char *der, 
	       unsigned char *sig, int siglen)
{
  // last goes the sig
  int bodylen = der_bitstring_encode(buf, len, sig, siglen, 0);
  bodylen += der_tag_encode(buf, len-bodylen, bodylen, DER_ASN1_SEQUENCE);
  bodylen += der_cat(buf, len-bodylen, der, der_msglen(der));
  return bodylen + sequence_start(buf, len-bodylen, bodylen, "signedformula");
}

/// create a signed formula
void *
sigform_create(void *der, RSA *key) 
{
  char *signed_der, sig[SDIGEST_LEN], digest[20];
  int len, siglen;
 
  // create signature
  SHA1(der, der_msglen(der), digest);
  siglen = nxguard_sdigest_create(digest, key, sig);
  if (siglen < 0) {
  	fprintf(stderr, "cannot create sdigest\n");
	return NULL;
  }

  // dryrun: determine size
  len = sigform_encode(NULL, 0, der, sig, siglen);
  
  // real run: generate signed DER formula
  signed_der = nxcompat_alloc(len);
  sigform_encode(signed_der, len, der, sig, siglen);

  return signed_der;
}

