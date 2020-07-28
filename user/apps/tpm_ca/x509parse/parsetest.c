#include <openssl/pem.h>
#include <string.h>

#include "x509parse.h"
#include "x509parse_private.h" /* just to test the new construction */

#define MAXLEN 4096

/* debug function to recalculate the signature for comparison's sake,
 * to make sure the tbscertificate that we are signing is the correct
 * structure. */
void fill_sig(const char *filename, unsigned char *buf){
  EVP_PKEY *pkey;
  RSA *rsa;
  FILE *fp;

  fp = fopen(filename, "r");
  printf("fopened %s\n", filename);
  pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
  printf("got privkey\n");
  rsa = EVP_PKEY_get1_RSA(pkey);
  printf("got rsa\n");


  int datalen;
  unsigned char *data = parsex509_getmsg(buf, &datalen);

  
  int siglen;
  unsigned char *sig = parsex509_getsig(buf, &siglen);


  /* check signature */
  unsigned char tmphash[20];
  SHA1(data, datalen, tmphash);
  int sigret = RSA_sign(NID_sha1, tmphash, 20, sig, (unsigned int *)&siglen, rsa);
  printf("sigret = %d\n", sigret);
  
  if(0){
    int i;
    printf("sig:\n");
    for(i = 0; i < siglen; i++)
      printf("%02x ", sig[i]);
    printf("\n");
  }
}


int main(int argc, char **argv){

  if(argc != 3){
    printf("usage: x509parse <filename> <privkey for sig check>\n");
    return -1;
  }

  unsigned char buf[MAXLEN];
  int buflen;

  BIO *bio = BIO_new_file(argv[1], "r");
  BIO *b64 = BIO_new(BIO_f_base64());
  BIO_push(b64, bio);

  buflen = BIO_read(b64, buf, MAXLEN);
  BIO_free(b64);
  BIO_free(bio);

  ParsedX509 *x509;

  x509 = parse_x509(buf, buflen);
  if(x509 == NULL){
    printf("error parsing!\n");
    return -1;
  }
  
  printf("success parsing!\n");

  //  if(dbg)
  //print_sig(argv[2], x509.tbscert.data, x509.tbscert.datalen);

  //unsigned char *buf1 = parsex509_gettbs(x509);
  //buflen = parsex509_gettbslen(x509);

  unsigned char *buf2 = (unsigned char *)malloc(buflen);
  memset(buf2, 0, buflen);

  //int clen = construct_x509(x509, NULL, 0);
  int clen = construct_x509(x509->tbscert.serialnum.num, x509->tbscert.serialnum.len,
			    x509->tbscert.algid,
			    x509->tbscert.issuer.data, x509->tbscert.issuer.datalen,
			    x509->tbscert.validity.starttime,
			    x509->tbscert.validity.endtime,
			    x509->tbscert.subjectpubkey.subjectalg,
			    x509->tbscert.subjectpubkey.modulus,
			    x509->tbscert.subjectpubkey.moduluslen,
			    x509->tbscert.subjectpubkey.pubexp,
			    x509->tbscert.subjectpubkey.pubexplen,
			    x509->tbscert.subject.data, x509->tbscert.subject.datalen,
			    256,
			    NULL, 0);
  if(clen != buflen){
    printf("wrong len construct(%d) != buflen(%d) !!!\n", clen, buflen);
  }

  //int len = construct_x509(x509, buf2, buflen);
  int len = construct_x509(x509->tbscert.serialnum.num, x509->tbscert.serialnum.len,
			   x509->tbscert.algid,
			   x509->tbscert.issuer.data, x509->tbscert.issuer.datalen,
			   x509->tbscert.validity.starttime,
			   x509->tbscert.validity.endtime,
			   x509->tbscert.subjectpubkey.subjectalg,
			   x509->tbscert.subjectpubkey.modulus,
			   x509->tbscert.subjectpubkey.moduluslen,
			   x509->tbscert.subjectpubkey.pubexp,
			   x509->tbscert.subjectpubkey.pubexplen,
			   x509->tbscert.subject.data, x509->tbscert.subject.datalen,
			   256,
			   buf2, clen);
  if(len != buflen){
    printf("error constructing len=%d, should be %d\n", len, buflen);
    int i;
    for(i = 0; i < clen; i++)
      printf("%02x", buf2[i]);
    printf("\n");
    return -1;
  }
  
  fill_sig(argv[2], buf2);

  if(memcmp(buf2, buf, buflen) != 0){
  //if(memcmp(buf2, buf1, buflen) != 0){
    printf("buffers differ.  new buf:\n");

    int i;
    for(i = 0; i < buflen; i++)
      printf("%02x ", buf2[i]);
    printf("\n");
    return -1;
  }
  printf("success constructing!\n");

  return 0;
}

