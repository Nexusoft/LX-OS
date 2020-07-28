#ifndef __X509PARSE_PRIVATE_H__
#define __X509PARSE_PRIVATE_H__

#include "x509parse.h"

/* identifier octet */
#define MASK_TYPE              0x1f
#define MASK_CLASS             0xc0
#define MASK_SEQTYPE           0x20

#define TYPE_INTEGER 	       0x02
#define TYPE_BIT_STRING        0x03
#define TYPE_OCTET_STRING      0x04
#define TYPE_NULL 	       0x05
#define TYPE_OBJECT_IDENTIFIER 0x06
#define TYPE_SEQUENCE          0x10
#define TYPE_SET               0x11
#define TYPE_PRINTABLESTRING   0x13
#define TYPE_T61String 	       0x14
#define TYPE_IA5String 	       0x16
#define TYPE_UTCTIME 	       0x17
#define TYPE_GENERALIZEDTIME   0x18

#define CLASS_UNIVERSAL	       0x00
#define CLASS_APPLICATION      0x40
#define CLASS_CONTEXT_SPECIFIC 0x80
#define CLASS_PRIVATE          0xc0

#define SEQ_PRIMITIVE          0x00
#define SEQ_CONSTRUCTED        0x20

/* length octet */
#define MASK_SHORT_LEN         0x7f
#define MASK_LONG_FORM         0x80


static unsigned char version_1[] = {0xa0, 0x03, 0x02, 0x01, 0x00};
static unsigned char version_2[] = {0xa0, 0x03, 0x02, 0x01, 0x01};
static unsigned char version_3[] = {0xa0, 0x03, 0x02, 0x01, 0x02};

#define VERSION1 version_1
#define VERSION2 version_2
#define VERSION3 version_3
#define VERSIONLEN 5

#define CONSTRUCT_VERSION_EXPLICITLY 0

/* Parts of Distinguished Names */
static unsigned char objid_name_countryname[] = {0x55, 0x04, 0x06};
static unsigned char objid_name_statename[] = {0x55, 0x04, 0x08};
static unsigned char objid_name_localityname[] = {0x55, 0x04, 0x07};
static unsigned char objid_name_orgname[] = {0x55, 0x04, 0x0a};
static unsigned char objid_name_orgunit[] = {0x55, 0x04, 0x0b};
static unsigned char objid_name_commonname[] = {0x55, 0x04, 0x03};

#define OBJID_NAME_COUNTRYNAME      objid_name_countryname             
#define OBJID_NAME_COUNTRYNAME_LEN  3
#define OBJID_NAME_STATENAME        objid_name_statename             
#define OBJID_NAME_STATENAME_LEN    3
#define OBJID_NAME_LOCALITYNAME     objid_name_localityname             
#define OBJID_NAME_LOCALITYNAME_LEN 3
#define OBJID_NAME_ORGNAME          objid_name_orgname             
#define OBJID_NAME_ORGNAME_LEN      3
#define OBJID_NAME_ORGUNIT          objid_name_orgunit             
#define OBJID_NAME_ORGUNIT_LEN      3
#define OBJID_NAME_COMMONNAME       objid_name_commonname             
#define OBJID_NAME_COMMONNAME_LEN   3


/* Algorithm identifiers */
static unsigned char objid_rsa_md2[] = {0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x02};
static unsigned char objid_rsa_md5[] = {0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x04};
static unsigned char objid_rsa_sha1[] = {0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x05};
static unsigned char objid_dsa_sha1[] = {0x2a, 0x86, 0x48, 0xce, 0x38, 0x04, 0x03};

#define OBJID_RSA_MD2              objid_rsa_md2
#define OBJID_RSA_MD2_LEN          9
#define OBJID_RSA_MD5              objid_rsa_md5
#define OBJID_RSA_MD5_LEN          9
#define OBJID_RSA_SHA1             objid_rsa_sha1
#define OBJID_RSA_SHA1_LEN         9
#define OBJID_DSA_SHA1             objid_dsa_sha1
#define OBJID_DSA_SHA1_LEN         7

static unsigned char objid_rsa_encrypt[] = {0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01};

#define OBJID_RSA_ENCRYPT              objid_rsa_encrypt
#define OBJID_RSA_ENCRYPT_LEN          9

#define GENERALIZEDTIMESIZE 14


/* XXX get rid of this type of struct */
typedef struct SerialNum{
  int len;
  unsigned char *num;
}SerialNum;

typedef struct BitString{
  int datalen;
  unsigned char *data;
}BitString;

typedef struct Name{
  int datalen;
  unsigned char *data;
}Name;

typedef struct Validity{
  unsigned char starttype;
  char *starttime;
  unsigned char endtype;
  char *endtime;
}Validity;


typedef struct PubKey{
  AlgType subjectalg;
  int moduluslen;
  unsigned char *modulus;
  int pubexplen;
  unsigned char *pubexp;
}PubKey;

typedef struct TBSCertificate{

  int version;
  SerialNum serialnum;
  AlgType algid;
  Name issuer;
  Validity validity;
  Name subject;
  PubKey subjectpubkey;


  int datalen;
  unsigned char *data;
}TBSCertificate;

struct ParsedX509{
  TBSCertificate tbscert;
  AlgType algid;
  BitString sig;
};


ParsedX509 *parsedx509_new(void);
void parsedx509_free(ParsedX509 *x509);


#endif
