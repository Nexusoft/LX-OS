#ifndef __X509PARSE_PRIVATE_H__
#define __X509PARSE_PRIVATE_H__

#include "x509parse.h"

/* identifier octet */
#define MASK_TYPE              0x1f
#define MASK_CLASS             0xc0
#define MASK_SEQTYPE           0x20

#define TYPE_BOOLEAN 	       0x01
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


#define VERSION1   ((char[]){0xa0, 0x03, 0x02, 0x01, 0x00})
#define VERSION2   ((char[]){0xa0, 0x03, 0x02, 0x01, 0x01})
#define VERSION3   ((char[]){0xa0, 0x03, 0x02, 0x01, 0x02})
#define VERSIONLEN 5

#define CONSTRUCT_VERSION_EXPLICITLY 0

#define GENERALIZEDTIMESIZE 14

/* subjectaltname defines */
#define SUBJALTNAME_TYPE_DNS 0x82
#define SUBJALTNAME_TYPE_URI 0x86
#define SUBJALTNAME_TYPE_IP  0x87

#define OBJID_basicConstraints ((unsigned char[]) { 0x55, 0x1d, 0x13 } )


/* XXX get rid of this type of struct */
struct SerialNum{
  int len;
  unsigned char *num;
};

struct BitString{
  int datalen;
  unsigned char *data;
};

struct Name{
  int datalen;
  unsigned char *data;
};

struct Validity{
  unsigned char starttype;
  char *starttime;
  unsigned char endtype;
  char *endtime;
};


struct PubKey{
  AlgType subjectalg;
  int moduluslen;
  unsigned char *modulus;
  int pubexplen;
  unsigned char *pubexp;
};

struct TBSCertificate{

  int version;
  SerialNum serialnum;
  AlgType algid;
  Name issuer;
  Validity validity;
  Name subject;
  PubKey subjectpubkey;


  int datalen;
  unsigned char *data;
};

struct ParsedX509{
  TBSCertificate tbscert;
  AlgType algid;
  BitString sig;
};


ParsedX509 *parsedx509_new(void);
void parsedx509_free(ParsedX509 *x509);


#endif
