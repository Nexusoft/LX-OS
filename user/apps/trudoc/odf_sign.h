#ifndef _ODF_SIGN_
#define _ODF_SIGN_

#include <stdlib.h>
#include <nexus/vector.h>

// an xml document node
struct xn {
  struct xn *sib; // sibling
  char *tag; // tag of this node, or NULL for cdata
  char *arg; // args for this node, or contents for cdata
  int s, e;
  struct xn *son; // list of child nodes
};

// a single signature on an odf document
struct docsig {
  int ncert;
  char **certs; // null terminated list of pointers
  int *certlen; // null terminated list of lengths
  char id[68]; // "ID_" + 64 chars + '\0'
  char target[68]; // "ID_" + 64 chars + '\0'
  char sd_digest[20]; // digest of the signature date block
  char date[30];
  int siglen;
  char sig[1024];
  char issuername[400];
  char digest[20];
  char serno[64];

  struct doc *parent;
  struct docsig *next;
};

// an odf document with zero or more signatures
struct doc {
  char content_digest[20], styles_digest[20], meta_digest[20], settings_digest[20];
  char *content_xml, *styles_xml, *meta_xml, *settings_xml;
  int nsigs;
  struct docsig *sigs;
};

struct doc *docsigs_parse(char *odf);
struct doc *docsigs_parse_pzip(char *zip, int zlen);

void docsigs_digest(struct docsig *docsig, char *md);

int docsigs_verify_one(struct docsig *docsig); // returns 0 if this sig verifies
int docsigs_verify_all(struct doc *doc); // returns 0 if all sigs verify

int docsigs_sign(struct doc *doc, /*X509*/ char *cert, int cert_len, /*RSA*/ char *privkey, int privkey_len);

int docsigs_write(struct doc *doc, char *buf, int buflen);
char *docsigs_writestr(struct doc *doc);
int docsigs_writefile(struct doc *doc, FILE *file);
int docsigs_writefd(struct doc *doc, int fd);

void docsigs_free(struct doc *doc);

struct xn *xn_parse(char *any_xml);
struct xn *odf_parse(char *content_xml);
struct xn *docbook_parse(char *docbook_xml);

void xn_free(struct xn *xn);
char *xn_tostring(struct xn *xn, int canonical);
void xn_print(struct xn *xn, int canonical);
char *xn_text(struct xn *xn);
int xn_match(struct xn *xq, struct xn *xn);

struct xq {
  struct xn *body, *attrib;
  int attested, malformed;
  char dochash[41];
  char author[500];
  char date[64];
  char restrictions[500];
  char *originaltext;
};

void xq_find(PointerVector *v, struct xn *xn);
void xq_print(struct xq *xq);
int xq_match(struct xq *xq, struct xn *xn);

void xq_free(struct xq *xq);

#endif //_ODF_SIGN_
