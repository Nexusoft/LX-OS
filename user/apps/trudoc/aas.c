#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "odf_sign.h"

#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

char *aas_cert, *aas_key;
int aas_cert_len, aas_key_len;

#define AAS_CERT_PATH "/home/kwalsh/xml/stupid.cert"
#define AAS_KEY_PATH "/home/kwalsh/xml/stupid.key"

int aas_load_keys(void) {
  FILE *f;
  unsigned char *p;
  f = fopen(AAS_CERT_PATH, "r");
  if (!f) return 1;
  X509 *x = PEM_read_X509(f, NULL, NULL, NULL);
  if (!x) return 1;
  aas_cert_len = i2d_X509(x, NULL);
  p = (unsigned char *)(aas_cert = malloc(aas_cert_len));
  i2d_X509(x, &p);
  fclose(f);

  f = fopen(AAS_KEY_PATH, "r");
  if (!f) return 1;
  RSA *r = PEM_read_RSAPrivateKey(f, NULL, NULL, NULL);
  if (!r) return 1;
  aas_key_len = i2d_RSAPrivateKey(r, NULL);
  p = (unsigned char *)(aas_key = malloc(aas_key_len));
  i2d_RSAPrivateKey(r, &p);
  fclose(f);

  return 0;
}

int main(int ac, char **av) {
  int i, j;

  if (ac < 1) {
    printf("usage: aas output_file target_odf src1_odf src2_odf ... srcN_odf\n");
    return 1;
  }

  char *outfilename = av[1];

  printf("reading target doc: %s\n", av[2]);
  struct doc *doc = docsigs_parse(av[2]);
  if (!doc) return 1;

  printf("content digest starts with %02x %02x %02x\n", (unsigned char)doc->content_digest[0], (unsigned char)doc->content_digest[1], (unsigned char)doc->content_digest[2]);

  //printf("verifying target doc signatures\n");
  //docsigs_verify_all(doc);

  struct xn *xn = odf_parse(doc->content_xml);
  xn_print(xn, 0);

  printf("content digest starts with %02x %02x %02x\n", (unsigned char)doc->content_digest[0], (unsigned char)doc->content_digest[1], (unsigned char)doc->content_digest[2]);

  int nsrc = ac-3;
  printf("reading %d sources docs\n", nsrc);
  struct doc **src = (nsrc ? malloc(sizeof(struct doc *) * nsrc) : NULL);
  struct xn **xn_src = (nsrc ? malloc(sizeof(struct xn *) * nsrc) : NULL);
  for (i = 0; i < nsrc; i++) {
    printf("reading source doc %d: %s\n", i+1, av[3+i]);
    src[i] = docsigs_parse(av[3+i]);
    if (!src[i]) return 1;
    printf("verifying source doc %d\n", i+1);
    docsigs_verify_all(src[i]);
    xn_src[i] = odf_parse(src[i]->content_xml);
    if (!xn_src[i]) return 1;
    xn_print(xn_src[i], 0);
  }

  //docsigs_writefile(doc, stdout);
  //docsigs_sign(...);
  //docsigs_writefile(doc, stdout);

  PointerVector v;
  PointerVector_init(&v, 4, POINTERVECTOR_ORDER_PRESERVING);

  xq_find(&v, xn);

  printf("content digest starts with %02x %02x %02x\n", (unsigned char)doc->content_digest[0], (unsigned char)doc->content_digest[1], (unsigned char)doc->content_digest[2]);

  char *txt = xn_text(xn);
  printf("text: %s\n", txt);

  char **src_hash = (nsrc ? malloc(sizeof(char *) * nsrc) : NULL);
  for (i = 0; i < nsrc; i++) {
    src_hash[i] = malloc(41);
    for (j = 0; j < 20; j++) {
      sprintf(src_hash[i]+2*j, "%02x", (int)(unsigned char)src[i]->content_digest[j]);
    }
    printf("source %d hash is %s\n", i+1, src_hash[i]);
  }

  int matches = 0;
 
  int n = PointerVector_len(&v);
  printf("document contains %d quotes\n", n);
  for (i = 0; i < n; i++) {
    struct xq *xq = PointerVector_nth(&v, i);
    xq_print(xq);
    printf("hash of quote is: %s\n", xq->dochash);
    for (j = 0; j < nsrc; j++) {
      if (!strcmp(xq->dochash, src_hash[j])) {
	printf("source %d has the right hash\n", j+1);
	int pos = xq_match(xq, xn_src[j]);
	if (pos < 0) {
	  printf(" --> quote not found in source document\n");
	} else {
	  printf(" --> quote found in source document: offset %d\n", pos);
	  matches++;
	}
	break;
      }
    }
    if (j >= nsrc) {
      printf(" --> no source documents appear to match\n");
    }
  }

  printf("content digest starts with %02x %02x %02x\n", (unsigned char)doc->content_digest[0], (unsigned char)doc->content_digest[1], (unsigned char)doc->content_digest[2]);
  printf("%d of %d quotes verified using %d source documents\n", matches, n, nsrc);

  if (matches == n) {

    if (aas_load_keys()) {
      printf("problem loading aas keys\n");
      return 1;
    }
    printf("content digest starts with %02x %02x %02x\n", (unsigned char)doc->content_digest[0], (unsigned char)doc->content_digest[1], (unsigned char)doc->content_digest[2]);

    if (docsigs_sign(doc, aas_cert, aas_cert_len, aas_key, aas_key_len)) {
      printf("problem signing\n");
      return 1;
    }
    FILE *outfile = (!strcmp(outfilename, "-") ? stdout : fopen(outfilename, "w"));
    if (!outfile) {
      printf("problem opening output file\n");
      return 1;
    }
    if (docsigs_writefile(doc, outfile)) {
      printf("problem writing output\n");
      return 1;
    }
    fclose(outfile);
    printf("content digest starts with %02x %02x %02x\n", (unsigned char)doc->content_digest[0], (unsigned char)doc->content_digest[1], (unsigned char)doc->content_digest[2]);

    printf("wrote new document signatures to %s\n", outfilename);
  }

  return 0;
}

