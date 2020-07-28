#ifndef __X509PARSE_H__
#define __X509PARSE_H__

/* XXX rename kvkey to vkey-common or something */
#include <nexus/kvkey.h> /* for AlgType */

/* Algorithm identifiers */

// we can define these as anonymous arrays: ((char[]){0x2a, 0x86, ..., 0x02})
//  - these have run-time overhead (each use turns into a bunch of "mov"
//  instructions to build the array on the stack)
// or we can define these as anonymous strings: "\x2a\x86 ...\x02"
//  - these have no overhead, they live in the static data segment
#define OBJID_RSA_MD2              ((unsigned char[]){0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x02})
#define OBJID_RSA_MD2_LEN          9
#define OBJID_RSA_MD5              ((unsigned char[]){0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x04})
#define OBJID_RSA_MD5_LEN          9
#define OBJID_RSA_SHA1             ((unsigned char[]){0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x05})
#define OBJID_RSA_SHA1_LEN         9
#define OBJID_DSA_SHA1             ((unsigned char[]){0x2a, 0x86, 0x48, 0xce, 0x38, 0x04, 0x03})
#define OBJID_DSA_SHA1_LEN         7

#define OBJID_RSA_ENCRYPT          ((unsigned char[]){0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01})
#define OBJID_RSA_ENCRYPT_LEN      9

#define OBJID_NAME_COUNTRYNAME      ((unsigned char[]){0x55, 0x04, 0x06})
#define OBJID_NAME_COUNTRYNAME_LEN  3
#define OBJID_NAME_STATENAME        ((unsigned char[]){0x55, 0x04, 0x08})
#define OBJID_NAME_STATENAME_LEN    3
#define OBJID_NAME_LOCALITYNAME     ((unsigned char[]){0x55, 0x04, 0x07})
#define OBJID_NAME_LOCALITYNAME_LEN 3
#define OBJID_NAME_ORGNAME          ((unsigned char[]){0x55, 0x04, 0x0a})
#define OBJID_NAME_ORGNAME_LEN      3
#define OBJID_NAME_ORGUNIT          ((unsigned char[]){0x55, 0x04, 0x0b})
#define OBJID_NAME_ORGUNIT_LEN      3
#define OBJID_NAME_COMMONNAME       ((unsigned char[]){0x55, 0x04, 0x03})
#define OBJID_NAME_COMMONNAME_LEN   3


/* Construct a ASN.1 DER encoded X509 and place it in buf. If there
   isn't enough space in buf, return the number of bytes that the
   function needed. */
int construct_x509(unsigned char *serialnum, int serialnumlen,
		   AlgType iss_alg,
			  char *iss_countryname, char *iss_statename,
			  char *iss_localityname, char *iss_orgname,
			  char *iss_orgunit, char *iss_commonname,
		   char *starttime, char *endtime,
		   AlgType subj_alg,
		   unsigned char *subj_modulus, int subj_moduluslen,
		   unsigned char *subj_pubexp, int subj_pubexplen,
			  char *subj_countryname, char *subj_statename,
			  char *subj_localityname, char *subj_orgname,
			  char *subj_orgunit, char *subj_commonname,
		   int siglen,
		   unsigned char *buf, int buflen);


/* parse an ASN.1 DER encoded X509 from buf. */
ParsedX509 *parse_x509(unsigned char *buf, int buflen);


unsigned char *parsex509_getmsg(unsigned char *buf, int *msglen);
unsigned char *parsex509_getsig(unsigned char *buf, int *siglen);



/* XXX the abstraction is broken so that we can parse just the subject
   alt name that we got from openssl in vkey.c.  At some point,
   parsing x509s (including extensions) will all be done by our X509
   parser, and this abstraction break will not be necessary */
int parse_subjaltname(char **dns, char **uri, unsigned int *ip, unsigned char *buf);

#endif
