#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

#include "odf_sign.h"
#include "pzip.h"

#include <nexus/base64.h>

#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/objects.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/evp.h>


void debug_sha(char *msg, unsigned char *digest) {
  int i;
  if (msg) printf("%s", msg);
  for (i = 0; i < 20; i++) printf("%02x", (int)digest[i]);
  if (msg) printf("\n");
}

// only for text files
char *getfile(char *dir, char *name)
{
  char path[256];
  if (strlen(dir) + strlen(name) + 1 >= sizeof(path))
    return NULL;
  sprintf(path, "%s/%s", dir, name);

  int fd = open(path, O_RDONLY);
  if (fd < 0)
    return NULL;

  int max = 4096, n = 0, r = 0;
  char *data = malloc(max);
  while ((r = read(fd, data+n, max-n-1)) > 0) {
    n += r;
    if (n == max-1) {
      max += 4096;
      data = realloc(data, max);
    }
  }
  data[n] = '\0';
  return data;
}


void docsig_free(struct docsig *dogsigs) {
  // free certs
}

void docsigs_free(struct doc *doc) {
  // free sigs, xml
}

// match input against a string, then skip over it; returns the new input ptr
char *skip(char *in, char *match) {
  if (!in) return NULL;
  int n = strlen(match);
  if (strncmp(in, match, n)) return NULL;
  else return in + n;
}

// copy the chars up to '<' into a new buffer and return it; modify input ptr
// also strips '\n' from string
char *yank_str(char **in) {
  int i, n;
  for (i = 0, n = 0; (*in)[i] && (*in)[i] != '<'; i++)
    if ((*in)[i] != '\n') n++;
  if (!(*in)[i]) return NULL;
  char *ret = malloc(n + 1);
  for (i = 0, n = 0; (*in)[i] && (*in)[i] != '<'; i++)
    if ((*in)[i] != '\n') ret[n++] = (*in)[i];
  ret[n] = '\0';
  *in += i;
  return ret;
}

// decode the chars up to '<' into a [new] buffer and return it; modify input ptr
char *yank_pem(char **in, char *dest, int *len) {
  char *encoded = yank_str(in);
  if (!encoded) return NULL;
  if (strlen(encoded) < 3) {
    free(encoded);
    return NULL;
  }
  int slen = strlen(encoded);
  int n = (slen/4) * 3;
  if (encoded[slen-1] == '=') n--;
  if (encoded[slen-2] == '=') n--;
  if (*len >= 0 && *len < n) {
    *len = n;
    return NULL;
  }
  *len = n;
  char *mine = NULL;
  if (!dest)
    mine = dest = malloc(n);
  if (!base64_decode(encoded, strlen(encoded), dest, (unsigned int *)&n)) {
    free(encoded);
    if (mine) free(mine);
    return NULL;
  }
  free(encoded);
  return dest;
}


void docsigs_date_digest(struct docsig *docsig, char *md) {
  SHA_CTX ctx;
  SHA_Init(&ctx);

#define SHA_cat(str) do { char *s = str; SHA1_Update(&ctx, s, strlen(s)); } while (0)
  SHA_cat("<SignatureProperty xmlns=\"http://www.w3.org/2000/09/xmldsig#\" Id=\"");
  SHA_cat(docsig->target);
  SHA_cat("\" Target=\"#");
  SHA_cat(docsig->id);
  SHA_cat("\"><dc:date xmlns:dc=\"http://purl.org/dc/elements/1.1/\">");
  SHA_cat(docsig->date);
  SHA_cat("</dc:date></SignatureProperty>");
#undef SHA_cat

  SHA1_Final(md, &ctx);
}

void docsigs_digest(struct docsig *docsig, char *md) {
  SHA_CTX ctx;
  SHA_Init(&ctx);
  char pem[40];

#define SHA_cat(str) do { char *s = str; SHA1_Update(&ctx, s, strlen(s)); } while (0)
  SHA_cat("<SignedInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\">");
  SHA_cat("<CanonicalizationMethod Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315\"></CanonicalizationMethod>");
  SHA_cat("<SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"></SignatureMethod>");

#define SHA_cat_ref(basename) do { \
  SHA_cat("<Reference URI=\"" #basename ".xml\">"); \
   SHA_cat("<Transforms><Transform Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315\"></Transform></Transforms>"); \
   SHA_cat("<DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"></DigestMethod>"); \
   base64_encode(docsig->parent->basename##_digest, 20, pem, 40); \
   SHA_cat("<DigestValue>"); SHA_cat(pem); SHA_cat("</DigestValue>"); \
  SHA_cat("</Reference>"); } while (0)

  SHA_cat_ref(content);
  SHA_cat_ref(styles);
  SHA_cat_ref(meta);
  SHA_cat_ref(settings);

#undef SHA_cat_ref

  SHA_cat("<Reference URI=\"#"); SHA_cat(docsig->target); SHA_cat("\">");
   SHA_cat("<DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"></DigestMethod>");
   base64_encode(docsig->sd_digest, 20, pem, 40);
   SHA_cat("<DigestValue>"); SHA_cat(pem); SHA_cat("</DigestValue>");
  SHA_cat("</Reference>");
  SHA_cat("</SignedInfo>");
#undef SHA_cat

  SHA1_Final(md, &ctx);
}


#define FAIL(msg...) do { printf(msg); printf("\n"); return NULL; } while (0)
char *check_ref(char *xml, char *uri, char *sha1digest) {
  int is_local = !uri[0];
  if (is_local) {
    xml = skip(xml, "<Reference URI=\"#");
    if (!xml || strlen(xml) < 67)
      FAIL("expected reference to a local target");
    strncpy(uri, xml, 67);
    uri[67] = '\0';
    xml += 67;
    xml = skip(xml, "\">");
    if (!xml) FAIL("expected reference to a local target");
    printf("found reference to local element %s\n", uri);
  } else {
    xml = skip(skip(skip(xml, "<Reference URI=\""), uri), "\">");
    if (!xml) FAIL("expected reference to %s", uri);
    xml = skip(xml, "<Transforms>");
    xml = skip(xml, "<Transform Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315\"></Transform>");
    xml = skip(xml, "</Transforms>");
  }
  xml = skip(xml, "<DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"></DigestMethod>");
  xml = skip(xml, "<DigestValue>");
  if (!xml) FAIL("malformed reference to %s", uri);

  char digest[20];
  int len = 20;
  if (!yank_pem(&xml, digest, &len) || len != 20) FAIL("missing or malformed digest");
  
  xml = skip(xml, "</DigestValue>");
  xml = skip(xml, "</Reference>");
  if (!xml) FAIL("malformed digest for %s", uri);

  printf("computed digest for %s: ", uri); debug_sha(NULL, digest); printf("\n");

  if (!is_local) {
    if (memcmp(sha1digest, digest, 20)) {
      debug_sha("expected digest: ", sha1digest);
      debug_sha("computed digest: ", digest);
      FAIL("digest mismatch for %s", uri);
    }
  } else {
    memcpy(sha1digest, digest, 20);
  }

  return xml;
}
#undef FAIL

#define FAIL(msg) do { docsig_free(docsig); printf(msg); printf("\n"); *docsigs_xml = xml; return NULL; } while (0)
struct docsig *docsig_parse(char **docsigs_xml, struct doc *parent) {
  char *xml = *docsigs_xml;

  struct docsig *docsig = malloc(sizeof(struct docsig));
  memset(docsig, 0, sizeof(struct docsig));
  docsig->parent = parent;

  xml = skip(xml, "<Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\" Id=\"");
  if(!xml) FAIL("couldn't parse signature header");
  strncpy(docsig->id, xml, 67);
  if (docsig->id[66] == '\0') FAIL("couldn't parse signature ID");
  docsig->id[67] = '\0';
  xml += 67;
  xml = skip(xml, "\">");
  if (!xml) FAIL("couldn't parse signature ID close tag");

  xml = skip(xml, "<SignedInfo>");
  xml = skip(xml, "<CanonicalizationMethod Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315\"></CanonicalizationMethod>");
  xml = skip(xml, "<SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"></SignatureMethod>");
  if(!xml) FAIL("couldn't parse signed info header");

  xml = check_ref(xml, "content.xml", parent->content_digest);
  xml = !xml ? xml :  check_ref(xml, "styles.xml", parent->styles_digest);
  xml = !xml ? xml : check_ref(xml, "meta.xml", parent->meta_digest);
  xml = !xml ? xml : check_ref(xml, "settings.xml", parent->settings_digest);
  xml = !xml ? xml : check_ref(xml, docsig->target, docsig->sd_digest);
  xml = skip(xml, "</SignedInfo>");
  if (!xml) FAIL("couldn't parse signed info");

  docsigs_digest(docsig, docsig->digest);

  xml = skip(xml, "<SignatureValue>");
  if (!xml) FAIL("couldn't parse signed value");
  docsig->siglen = sizeof(docsig->sig);
  if (!yank_pem(&xml, docsig->sig, &docsig->siglen)) FAIL("missing or malformed signature value");
  xml = skip(xml, "</SignatureValue>");

  xml = skip(xml, "<KeyInfo><X509Data><X509IssuerSerial>");

  xml = skip(xml, "<X509IssuerName>");
  if (!xml) FAIL("couldn't parse issuer name");
  char *name = yank_str(&xml);
  if (!name) FAIL("missing or malformed issuer name");
  if (strlen(name) >= sizeof(docsig->issuername)) {
    free(name);
    FAIL("issuer name too large");
  }
  strcpy(docsig->issuername, name);
  free(name);
  xml = skip(xml, "</X509IssuerName>");
 
  xml = skip(xml, "<X509SerialNumber>");
  if (!xml) FAIL("couldn't parse serial number");
  char *serno = yank_str(&xml);
  if (!serno) FAIL("missing serial number");
  if (strlen(serno) >= sizeof(docsig->serno)) {
    free(serno);
    FAIL("serial number too big");
  }
  strcpy(docsig->serno, serno);
  xml = skip(xml, "</X509SerialNumber>");

  xml = skip(xml, "</X509IssuerSerial>");
  if (!xml) FAIL("couldn't parse issuer and serial number");

  char *xml_mark = xml;
  while (*xml && strncmp(xml, "</X509Data>", strlen("</X509Data>"))) {
    if (!strncmp(xml, "<X509Certificate>", strlen("<X509Certificate>"))) docsig->ncert++;
    xml++;
  }
  if (docsig->ncert > 0) {
    docsig->certs = malloc(sizeof(char *) * (docsig->ncert+1));
    memset(docsig->certs, 0, sizeof(char *) * (docsig->ncert+1));
    docsig->certlen = malloc(sizeof(int) * (docsig->ncert+1));
    memset(docsig->certlen, 0, sizeof(int) * (docsig->ncert+1));
    xml = xml_mark;
    int i;
    for (i = 0; i < docsig->ncert; i++) {
      xml = skip(xml, "<X509Certificate>");
      if (!xml) FAIL("couldn't parse X509 certificate");
      int len = -1;
      char *cert = yank_pem(&xml, NULL, &len);
      if (!cert) FAIL("malformed or missing certificate");
      docsig->certs[i] = cert;
      docsig->certlen[i] = len;
      xml = skip(xml, "</X509Certificate>");
      while (xml && xml[0] == '\n') xml++;
    }
  }

  xml = skip(xml, "</X509Data></KeyInfo>");

  xml = skip(xml, "<Object>");
  xml = skip(xml, "<SignatureProperties>");
  if (!xml) FAIL("couldn't signature properties object header");
  xml = skip(skip(skip(skip(skip(xml, "<SignatureProperty Id=\""), docsig->target), "\" Target=\"#"), docsig->id), "\">");
  if (!xml) FAIL("couldn't signature properties object");
  xml = skip(xml, "<dc:date xmlns:dc=\"http://purl.org/dc/elements/1.1/\">");
  if (!xml) FAIL("couldn't parse date");
  char *date = yank_str(&xml);
  if (!date) FAIL("missing date");
  if (strlen(date) >= sizeof(docsig->date)) {
    free(date);
    FAIL("malformed date");
  }
  strcpy(docsig->date, date);
  xml = skip(xml, "</dc:date>");
  xml = skip(xml, "</SignatureProperty>");
  if (!xml) FAIL("malformed signature property ending");

  char sp_digest[20];
  docsigs_date_digest(docsig, sp_digest);
  if (memcmp(sp_digest, docsig->sd_digest, 20)) {
    debug_sha("expected digest was: ", docsig->sd_digest);
    debug_sha("computed digest was: ", sp_digest);
    FAIL("mismatch on date stamp digest");
  }

  xml = skip(xml, "</SignatureProperties></Object></Signature>");
  if (!xml) FAIL("malformed ending");

  *docsigs_xml = xml; 
  return docsig;
}
#undef FAIL

#define FAIL(msg) do { printf(msg); printf("\n"); return NULL; } while (0)
static struct doc *docsigs_prep(char *xml, struct doc *doc) {
  if(!doc->content_xml) FAIL("couldn't find content.canonical.xml");
  if(!doc->styles_xml) FAIL("couldn't find styles.canonical.xml");
  if(!doc->meta_xml) FAIL("couldn't find meta.canonical.xml");
  if(!doc->settings_xml) FAIL("couldn't find settings.canonical.xml");

  SHA1(doc->content_xml, strlen(doc->content_xml), doc->content_digest);
  SHA1(doc->styles_xml, strlen(doc->styles_xml), doc->styles_digest);
  SHA1(doc->meta_xml, strlen(doc->meta_xml), doc->meta_digest);
  SHA1(doc->settings_xml, strlen(doc->settings_xml), doc->settings_digest);

  debug_sha("expected digest for content.xml: ", doc->content_digest);
  debug_sha("expected digest for styles.xml: ", doc->styles_digest);
  debug_sha("expected digest for meta.xml: ", doc->meta_digest);
  debug_sha("expected digest for settings.xml: ", doc->settings_digest);

  if(!xml) {
    printf("document has no signatures\n");
    return doc;
  }

  // this won't show up in the canonical version
  //xml = skip(xml, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
  //if(!xml) FAIL("couldn't parse xml version tag");

  xml = skip(xml, "<document-signatures xmlns=\"http://openoffice.org/2004/documentsignatures\">");
  if(!xml) FAIL("couldn't parse signatures header");

  while (!strncmp(xml, "<Signature ", strlen("<Signature "))) {
    struct docsig *sig = docsig_parse(&xml, doc);
    if (!sig) FAIL("couldn't parse signature");
    doc->nsigs++;
    sig->parent = doc;
    sig->next = doc->sigs;
    doc->sigs = sig;
  }

  xml = skip(xml, "</document-signatures>");
  if (!xml) FAIL("malformed document signatures ending");
  if (*xml) FAIL("junk after signatures");

  return doc;
}
#undef FAIL

struct doc *docsigs_parse(char *odf) {

  struct doc *doc = malloc(sizeof(struct doc));
  memset(doc, 0, sizeof(struct doc));

  //char *xml = getfile(odf, "META-INF/documentsignatures.xml");
  char *xml = getfile(odf, "META-INF/documentsignatures.canonical.xml");

  // load the files once 
  doc->content_xml = getfile(odf, "content.canonical.xml");
  doc->styles_xml = getfile(odf, "styles.canonical.xml");
  doc->meta_xml = getfile(odf, "meta.canonical.xml");
  doc->settings_xml = getfile(odf, "settings.canonical.xml");

  return docsigs_prep(xml, doc);
}

struct doc *docsigs_parse_pzip(char *zip, int zlen) {

  struct doc *doc = malloc(sizeof(struct doc));
  memset(doc, 0, sizeof(struct doc));

  //char *xml = punzip(zip, zlen, "META-INF/documentsignatures.xml");
  char *xml = punzip(zip, zlen, "META-INF/documentsignatures.canonical.xml");

  // load the files once 
  doc->content_xml = punzip(zip, zlen, "content.canonical.xml");
  doc->styles_xml = punzip(zip, zlen, "styles.canonical.xml");
  doc->meta_xml = punzip(zip, zlen, "meta.canonical.xml");
  doc->settings_xml = punzip(zip, zlen, "settings.canonical.xml");

  return docsigs_prep(xml, doc);
}

int docsigs_verify_one(struct docsig *sig) {
  if (!sig) return 1;

  printf("verifying signature:\n issuer: %s\n", sig->issuername);
  debug_sha(" digest: ", sig->digest);

  if (!sig->ncert) {
    printf("no certificates available\n");
    return 1;
  }
  /* if (sig->ncert != 1) {
    printf("too many certificates (%d) available\n", sig->ncert);
    return 1;
  } */

  unsigned char *cert = sig->certs[0];
  X509 *x509 = d2i_X509(NULL, &cert, sig->certlen[0]);
  if (!x509) {
    printf("can't parse x509 cert\n");
    ERR_load_crypto_strings();
    long e;
    while ((e = ERR_get_error())) {
      char *msg = ERR_error_string(e, NULL);
      printf("> %s\n", msg);
    }
    ERR_free_strings();
    return 1;
  }
  EVP_PKEY *pkey = X509_get_pubkey(x509);
  RSA *pubkey = EVP_PKEY_get1_RSA(pkey);

  if (RSA_verify(NID_sha1, sig->digest, 20, sig->sig, sig->siglen, pubkey) != 1) {
    printf("signature does not verify\n");
    return 1;
  } else {
    printf("signature verifies\n");
    return 0;
  }
}

int docsigs_verify_all(struct doc *doc) {
  if (!doc) return 1;
  int ret = 0;

  printf("document has %d signatures\n", doc->nsigs);
  struct docsig *sig;
  int i = doc->nsigs;
  for (sig = doc->sigs; sig; sig = sig->next) {
    printf("[%d] ", i--);
    if (docsigs_verify_one(sig) != 0)
      ret = 1;
  }

  return ret;
}

int docsigs_sign(struct doc *doc, char *cert, int cert_len, char *privkey, int privkey_len) {

  struct docsig *sig = malloc(sizeof(struct docsig));
  memset(sig, 0, sizeof(struct docsig));
  sig->parent = doc;

  struct timeval tv;
  gettimeofday(&tv, NULL);

  time_t t = time(NULL);
  struct tm *tm = gmtime(&t);

  sprintf(sig->date, "%4d-%02d-%02dT%02d:%02d:%02d",
      tm->tm_year+1900, tm->tm_mon, tm->tm_mday, tm->tm_hour, tm->tm_min, tm->tm_sec);
  sprintf(sig->id, "ID_1234%030u%030u", (int)tv.tv_sec, (int)tv.tv_usec);
  sprintf(sig->target, "ID_5678%030u%030u", (int)tv.tv_sec, (int)tv.tv_usec);

  sig->ncert = 1;
  sig->certlen = malloc(sizeof(int));
  sig->certs = malloc(sizeof(char *));
  sig->certlen[0] = cert_len;
  sig->certs[0] = malloc(cert_len);
  memcpy(sig->certs[0], cert, cert_len);

  sprintf(sig->serno, "%d", 12345);

  unsigned char *cc = cert;
  X509 *x509 = d2i_X509(NULL, &cc, cert_len);
  if (!x509) {
    docsig_free(sig);
    printf("could not parse x509\n");
    return 1;
  }

  X509_NAME *name = X509_get_subject_name(x509);

  BIO *bio = BIO_new(BIO_s_mem());
  X509_NAME_print_ex(bio, name, 0, XN_FLAG_RFC2253);

  int n = BIO_gets(bio, sig->issuername, sizeof(sig->issuername));
  BIO_free(bio);
  if (n <= 0 || n >= sizeof(sig->issuername)) {
    docsig_free(sig);
    printf("x509 subject name invalid\n");
    return 1;
  }
  
  n = strlen("emailAddress=");
  if (!strncmp(sig->issuername, "emailAddress=", n)) {
    memmove(sig->issuername+2, sig->issuername + n, strlen(sig->issuername + n) + 1);
    sig->issuername[0] = 'E';
    sig->issuername[1] = '=';
  }

  docsigs_date_digest(sig, sig->sd_digest);
  docsigs_digest(sig, sig->digest);
  const unsigned char *pp = privkey;
  RSA *rsa = d2i_RSAPrivateKey(NULL, &pp, privkey_len);
  if (!rsa) {
    docsig_free(sig);
    printf("can't get private key\n");
    return 1;
  }
  sig->siglen = RSA_size(rsa);
  if (sig->siglen > sizeof(sig->sig)) {
    docsig_free(sig);
    printf("bad private key size\n");
    return 1;
  }
  //sig->sig = malloc(sig->siglen);

  if (RSA_sign(NID_sha1, sig->digest, 20, sig->sig, &sig->siglen, rsa) != 1) {
    docsig_free(sig);
    return 1;
  }

  sig->parent = doc;
  doc->nsigs++;
  sig->next = doc->sigs;
  doc->sigs = sig;
  return 0;
}

int docsig_ref_write(struct docsig *sig, char *uri, char *md, int is_local, char *xml, int len) {
  char pem[40];
  int out = 0;
  base64_encode(md, 20, pem, 40);
  printf("md="); debug_sha(0, md); printf(" uri=%s pem=%s\n", uri, pem);
  if (is_local) {
    out += snprintf(xml+out, (len<out?0:len-out), "<Reference URI=\"#%s\">", uri);
  } else {
    out += snprintf(xml+out, (len<out?0:len-out), "<Reference URI=\"%s\">", uri);
    out += snprintf(xml+out, (len<out?0:len-out), "<Transforms><Transform Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315\"/></Transforms>");
  }
  out += snprintf(xml+out, (len<out?0:len-out), "<DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/>");
  out += snprintf(xml+out, (len<out?0:len-out), "<DigestValue>%s</DigestValue>", pem);
  out += snprintf(xml+out, (len<out?0:len-out), "</Reference>");
  return out;
}

int snprintf_wrap(char *xml, int len, char *s, int w) {
  int out = 0;
  int j, n = strlen(s);
  for (j = 0; j < n; j += w) {
    if (n-j > w) {
      // kwalsh: snprintf(..., "%*s", width, str) seems broken:
      // it returns strlen(s) instead of max(strlen(s), width)
      //out += snprintf(xml+out, (len<out?0:len-out), "%*s", w, s+j);
      snprintf(xml+out, (len<out?0:len-out), "%*s", w, s+j);
      out += w;
      out += snprintf(xml+out, (len<out?0:len-out), "\n");
    } else {
      out += snprintf(xml+out, (len<out?0:len-out), "%s", s+j);
    }
  }
  return out;
}

int docsig_write(struct docsig *docsig, char *xml, int len) {
  int out = 0;
  if (!docsig) return out;
  if (docsig->next) out += docsig_write(docsig->next, xml+out, len-out);

  out += snprintf(xml+out, (len<out?0:len-out), "<Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\" Id=\"%s\">", docsig->id);

  out += snprintf(xml+out, (len<out?0:len-out), "<SignedInfo>");
  out += snprintf(xml+out, (len<out?0:len-out), "<CanonicalizationMethod Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315\"/>");
  out += snprintf(xml+out, (len<out?0:len-out), "<SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"/>");
  out += docsig_ref_write(docsig, "content.xml", docsig->parent->content_digest, 0, xml+out, len-out);
  out += docsig_ref_write(docsig, "styles.xml", docsig->parent->styles_digest, 0, xml+out, len-out);
  out += docsig_ref_write(docsig, "meta.xml", docsig->parent->meta_digest, 0, xml+out, len-out);
  out += docsig_ref_write(docsig, "settings.xml", docsig->parent->settings_digest, 0, xml+out, len-out);
  out += docsig_ref_write(docsig, docsig->target, docsig->sd_digest, 1, xml+out, len-out);
  out += snprintf(xml+out, (len<out?0:len-out), "</SignedInfo>");

  char pem[500];
  base64_encode(docsig->sig, docsig->siglen, pem, 500);
  out += snprintf(xml+out, (len<out?0:len-out), "<SignatureValue>");
    out += snprintf_wrap(xml+out, len-out, pem, 64);
    out += snprintf(xml+out, (len<out?0:len-out), "</SignatureValue>");

  out += snprintf(xml+out, (len<out?0:len-out), "<KeyInfo><X509Data><X509IssuerSerial>");
  out += snprintf(xml+out, (len<out?0:len-out), "<X509IssuerName>%s</X509IssuerName>", docsig->issuername);
  out += snprintf(xml+out, (len<out?0:len-out), "<X509SerialNumber>%s</X509SerialNumber>", docsig->serno);
  out += snprintf(xml+out, (len<out?0:len-out), "</X509IssuerSerial>");

  int i;
  for (i = 0; i < docsig->ncert; i++) {
    char *cert = NULL;
    base64_encode_alloc(docsig->certs[i], docsig->certlen[i], &cert);
    out += snprintf(xml+out, (len<out?0:len-out), "<X509Certificate>");
    out += snprintf_wrap(xml+out, len-out, cert, 64);
    out += snprintf(xml+out, (len<out?0:len-out), "</X509Certificate>\n");
  }
  out += snprintf(xml+out, (len<out?0:len-out), "</X509Data></KeyInfo>");

  out += snprintf(xml+out, (len<out?0:len-out), "<Object><SignatureProperties>");
  out += snprintf(xml+out, (len<out?0:len-out), "<SignatureProperty Id=\"%s\" Target=\"#%s\">", docsig->target, docsig->id);
  out += snprintf(xml+out, (len<out?0:len-out), "<dc:date xmlns:dc=\"http://purl.org/dc/elements/1.1/\">%s</dc:date>", docsig->date);
  out += snprintf(xml+out, (len<out?0:len-out), "</SignatureProperty>");
  out += snprintf(xml+out, (len<out?0:len-out), "</SignatureProperties></Object></Signature>");

  return out;
}

int docsigs_write(struct doc *doc, char *xml, int len) {
  int out = 0;

  out += snprintf(xml+out, (len<out?0:len-out),  "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
  out += snprintf(xml+out, (len<out?0:len-out),  "<document-signatures xmlns=\"http://openoffice.org/2004/documentsignatures\">");

  out += docsig_write(doc->sigs, xml+out, len-out);

  out += snprintf(xml+out, (len<out?0:len-out),  "</document-signatures>");
  return out;
}

char *docsigs_writestr(struct doc *doc) {
  int len = docsigs_write(doc, NULL, 0) + 1;
  if (len <= 0) return NULL;
  char *buf = malloc(len+1);
  int len2 = docsigs_write(doc, buf, len+1) + 1;
  assert(len == len2);
  buf[len] = '\0';
  return buf;
}

int docsigs_writefile(struct doc *doc, FILE *file) {
  char *str = docsigs_writestr(doc);
  if (!str) return 1;
  fprintf(file, "%s", str);
  free(str);
  return 0;
}

int docsigs_writefd(struct doc *doc, int fd) {
  char *str = docsigs_writestr(doc);
  if (!str) return 1;
  write(fd, str, strlen(str));
  free(str);
  return 0;
}
