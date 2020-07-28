#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "x509parse_private.h"

typedef struct ToBuildTBS{
  int version;
  int serialnumlen;
  unsigned char *serialnum;

  AlgType iss_alg;

  int iss_namelen;
  unsigned char *iss_name;

  char *iss_countryname;
  char *iss_statename;
  char *iss_localityname;
  char *iss_orgname;
  char *iss_orgunit;
  char *iss_commonname;

  unsigned char starttype;
  char *starttime;
  unsigned char endtype;
  char *endtime;

  AlgType subj_alg;
  int subj_moduluslen;
  unsigned char *subj_modulus; 
  int subj_pubexplen;
  unsigned char *subj_pubexp; 

  int subj_namelen;
  unsigned char *subj_name;

  char *subj_countryname;
  char *subj_statename;
  char *subj_localityname;
  char *subj_orgname;
  char *subj_orgunit;
  char *subj_commonname;

}ToBuildTBS;

/* XXX change this to #include <nexus/util.h> on move to nexus
 * min()/max() macros that also do
 * strict type-checking.. See the
 * "unnecessary" pointer comparison.
 */
#define min(x,y) ({ \
	const typeof(x) _x = (x);	\
	const typeof(y) _y = (y);	\
	(void) (&_x == &_y);		\
	_x < _y ? _x : _y; })

#define max(x,y) ({ \
	const typeof(x) _x = (x);	\
	const typeof(y) _y = (y);	\
	(void) (&_x == &_y);		\
	_x > _y ? _x : _y; })

#define isdigit(x)  ((x >= '0') && (x <= '9'))


static void constructer_current_view(char *func, unsigned char *buf, int buflen){
  int dbg = 0;

  if(dbg && buf != NULL){
    printf("constructing %s: view: 0x%p(%d): ", func, buf, buflen);
#if 1
    printf("%02x ", buf[buflen]);
    printf("%02x ", buf[buflen + 1]);
    printf("%02x ", buf[buflen + 2]);
    printf("%02x ", buf[buflen + 3]);
    printf("%02x ", buf[buflen + 4]);
    printf("%02x ", buf[buflen + 5]);
#endif
    printf("...\n");
  }
}

/* WARNING: this macro depends on local variable and parameter names */
#define TLEN (buflen - written) /* The remaining length at the front
				   of the buffer that should be
				   checked before actual writes. */



/* The length is specified in one or more octets, depending on a bit
 * set in the first octet.  This implementation assumes the length
 * will only take up to 4 octets. */
static int construct_length(int len, unsigned char *buf, int buflen){
  int written = 0;

  /* short lengths are a single byte */
  if((len & MASK_SHORT_LEN) == len){
    if(TLEN > 0)
      buf[TLEN -1] = (unsigned char)(len & MASK_SHORT_LEN);
    written += 1;

    return written;
  }

  int numoctets;

  if(len <= 0xff)
    numoctets = 1;
  else if(len <= 0xffff)
    numoctets = 2;
  else if(len <= 0xffffff)
    numoctets = 3;
  else if(len <= 0xffffffff)
    numoctets = 4;
  else{
    /* XXX >4 long form not implemented */
    printf("XXX Long form not implemented %s %d\n", __FILE__, __LINE__);
    return -1;
  }

  if(TLEN >= numoctets){
    int i;
    unsigned int size = len;
    for(i = 1; i <= numoctets; i++){
      buf[TLEN - i] = (size & 0xff);
      size = size >> 8;
    }
  }
  written += numoctets;

  if(TLEN > 0)
    buf[TLEN -1 ] = numoctets | MASK_LONG_FORM;
  written += 1;

  return numoctets + 1;
}


/* This function constructs a header of type bit string. */
static int construct_bit_string(int bslen, unsigned char *buf, int buflen){
  int written = 0;
  
  if(TLEN > 0)
    buf[TLEN - 1] = 0; /* unused bit byte is not supported */
  written += 1;
  
  int totallen = bslen + 1; /* include unused bit byte */
  written += construct_length(totallen, buf, TLEN);

  if(TLEN > 0)
    buf[TLEN - 1] = TYPE_BIT_STRING;
  written += 1;
      
  return written;
}

/* Construct a printable string from str */
static int construct_printablestring(char *str, unsigned char *buf, int buflen){
  int written = 0;
  
  int len = strlen(str);

  if(TLEN >= len)
    memcpy(&buf[TLEN - len], str, len);
  written += len;

  written += construct_length(len, buf, TLEN);

  if(TLEN > 0)
    buf[TLEN - 1] = TYPE_PRINTABLESTRING; 
  written += 1;

  return written;
}

/* pretty much the same as a sequence. */
static int construct_set(int len, unsigned char class, unsigned char type, 
			      unsigned char *buf, int buflen){
  int written = 0;

  written += construct_length(len, buf, TLEN);
  
  if(TLEN > 0)
    buf[TLEN - 1] = class | type | TYPE_SET;
  written += 1;

  return written;
}

/* A sequence is one of the ASN.1 primitive types.  It is followed by
 * a length that corresponds to the length of the sequence. */
static int construct_sequence(int len, unsigned char class, unsigned char type, 
			      unsigned char *buf, int buflen){
  int written = 0;

  written += construct_length(len, buf, TLEN);
  
  if(TLEN > 0)
    buf[TLEN - 1] = class | type | TYPE_SEQUENCE;
  written += 1;

  return written;
}


static int construct_null(unsigned char *buf, int buflen){
  int written = 0;

  if(TLEN >= 2){
    buf[TLEN - 2] = TYPE_NULL;
    buf[TLEN - 1] = 0;
  }
  written += 2;

  return written;
}

/* construct an object */
static int construct_object(unsigned char *objptr, int objlen, unsigned char *buf, int buflen){
  int written = 0;

  if(TLEN >= objlen)
    memcpy(&buf[TLEN - objlen], objptr, objlen);
  written += objlen;


  written += construct_length(objlen, buf, TLEN);

  if(TLEN > 0)
    buf[TLEN - 1] = TYPE_OBJECT_IDENTIFIER;
  written += 1;
  
  return written;
}

/* There are only four different types of signature algorithms, one
 * implemented type of encryption algorithm.  Check to see which
 * algorithm is specified and catch the null if necessary. */
static int construct_alg_id(AlgType *obj, unsigned char *buf, int buflen){
  int written = 0;

  /* rsa algorithms have a null at the end, dsa has nothing */
  if(*obj != ALG_DSA_SHA1)
    written += construct_null(buf, TLEN);

  unsigned char *objptr;
  int objlen;

  switch(*obj){
  case ALG_NONE:
    return -1;
    break;
  case ALG_RSA_MD2:
    objptr = OBJID_RSA_MD2;
    objlen = OBJID_RSA_MD2_LEN;
    break;
  case ALG_RSA_MD5:
    objptr = OBJID_RSA_MD5;
    objlen = OBJID_RSA_MD5_LEN;
    break;
  case ALG_RSA_SHA1:
    objptr = OBJID_RSA_SHA1;
    objlen = OBJID_RSA_SHA1_LEN;
    break;
  case ALG_DSA_SHA1:
    objptr = OBJID_DSA_SHA1;
    objlen = OBJID_DSA_SHA1_LEN;
    break;
  case ALG_RSA_ENCRYPT:
    objptr = OBJID_RSA_ENCRYPT;
    objlen = OBJID_RSA_ENCRYPT_LEN;
    break;
  };

  written += construct_object(objptr, objlen, buf, TLEN);

  return written;
}


/* The signature algorithm informs us which hash algorithm was used
 * before the signature.  A lot of the standard x509s (ca self-signed)
 * use md5, but Nexus CAs use sha1.  This function also constructs an
 * identifier for the encryption algorithm. */
static int construct_alg(AlgType *alg, unsigned char *buf, int buflen){
  int written = 0;

  written += construct_alg_id(alg, buf, TLEN);

  written += construct_sequence(written, CLASS_UNIVERSAL, SEQ_CONSTRUCTED, buf, TLEN);

  return written;
}


/* Construct an int type from a byte array and length.  This is used
 * for the most part for a public key modulus or other big numbers
 * like that.  */
static int construct_int(int numlen, unsigned char *num, 
			 unsigned char *buf, int buflen){
  int written = 0;

  if(TLEN >= numlen)
    memcpy(&buf[TLEN - numlen], num, numlen);
  written += numlen;

  written += construct_length(numlen, buf, TLEN);

  if(TLEN > 0)
    buf[TLEN -1] = TYPE_INTEGER;
  written += 1;

  return written;
}



/* The public key is inside a bitstring, and consists of a sequence of
 * two ints: the modulus and the public exponent. This is only for RSA
 * public keys. */
static int construct_pubkeydata(ToBuildTBS *tbs, unsigned char *buf, int buflen){
  int written = 0;

  written += construct_int(tbs->subj_pubexplen, tbs->subj_pubexp, buf, TLEN);
  constructer_current_view("built pubexp", buf, TLEN);
  written += construct_int(tbs->subj_moduluslen, tbs->subj_modulus, buf, TLEN);
  constructer_current_view("built modulus", buf, TLEN);
  written += construct_sequence(written, CLASS_UNIVERSAL, SEQ_CONSTRUCTED, buf, TLEN);
  constructer_current_view("built seq", buf, TLEN);
  written += construct_bit_string(written, buf, TLEN);
  constructer_current_view("built bs", buf, TLEN);

  return written;
}


/* The public key is a sequence of an algorithm identifier and a
   bitstring containing algorithm specific info (like modulus and
   public exponent for RSA).  Only RSA is supported.  */
static int construct_pubkey(ToBuildTBS *tbs, unsigned char *buf, int buflen){
  int written = 0;

  written += construct_pubkeydata(tbs, buf, TLEN);
  written += construct_alg(&tbs->subj_alg, buf, TLEN);
  written += construct_sequence(written, CLASS_UNIVERSAL, SEQ_CONSTRUCTED, buf, TLEN);

  return written;
}

static unsigned char time_type(char *time){
  int i;
  for(i = 0; i < strlen(time); i++){
    if(!isdigit(time[i]))
      break;
  }
  if(i < GENERALIZEDTIMESIZE)
    return TYPE_UTCTIME;
  else
    return TYPE_GENERALIZEDTIME;
}


/* The validity consists of two UTCTYPE or GENERALIZEDTIME structures.
 * XXX The parse/construct UTC/GENERALIZEDTIME should probably be
 * moved out into a common function. */
static int construct_validity(char *starttime, char *endtime, unsigned char *buf, int buflen){
  int written = 0;
  int len;
  

  len = strlen(endtime);
  if(TLEN >= len)
    memcpy(&buf[TLEN - len], endtime, len);
  written += len;

  written += construct_length(len, buf, TLEN);
  
  if(TLEN > 0)
    buf[TLEN - 1] = time_type(endtime);
  written += 1;

  len = strlen(starttime);
  if(TLEN >= len)
    memcpy(&buf[TLEN - len], starttime, len);
  written += len;

  written += construct_length(len, buf, TLEN);
  
  if(TLEN > 0)
    buf[TLEN - 1] = time_type(starttime);
  written += 1;

  written += construct_sequence(written, CLASS_UNIVERSAL, SEQ_CONSTRUCTED, buf, TLEN);

  return written;
}

/* The name is currently unparsed, and so also unparsed in the
 * construction.  XXX This may have to change to get to the common
 * name. */
#if 0
static int construct_name(unsigned char *name, int namelen, unsigned char *buf, int buflen){
  int written = 0;

  if(TLEN >= namelen)
    memcpy(&buf[TLEN - namelen], name, namelen);
  written += namelen;

  return written;
}
#endif

static int construct_namepart(char *str, unsigned char *objptr, int objlen, 
			      unsigned char *buf, int buflen){
  int written = 0;

  written += construct_printablestring(str, buf, TLEN);
  written += construct_object(objptr, objlen, buf, TLEN);
  written += construct_sequence(written, CLASS_UNIVERSAL, SEQ_CONSTRUCTED, buf, TLEN);
  written += construct_set(written, CLASS_UNIVERSAL, SEQ_CONSTRUCTED, buf, TLEN);

  return written;
}


static int construct_name(char *countryname, char *statename, char *localityname, 
			  char *orgname, char *orgunit, char *commonname,
			  unsigned char *buf, int buflen){
  int written = 0;

  written += construct_namepart(commonname, OBJID_NAME_COMMONNAME, OBJID_NAME_COMMONNAME_LEN, buf, TLEN);
  written += construct_namepart(orgunit, OBJID_NAME_ORGUNIT, OBJID_NAME_ORGUNIT_LEN, buf, TLEN);
  written += construct_namepart(orgname, OBJID_NAME_ORGNAME, OBJID_NAME_ORGNAME_LEN, buf, TLEN);
  written += construct_namepart(localityname, OBJID_NAME_LOCALITYNAME, OBJID_NAME_LOCALITYNAME_LEN, buf, TLEN);
  written += construct_namepart(statename, OBJID_NAME_STATENAME, OBJID_NAME_STATENAME_LEN, buf, TLEN);
  written += construct_namepart(countryname, OBJID_NAME_COUNTRYNAME, OBJID_NAME_COUNTRYNAME_LEN, buf, TLEN);

  written += construct_sequence(written, CLASS_UNIVERSAL, SEQ_CONSTRUCTED, buf, TLEN);

  return written;
}



/* The serial number is just an integer.  XXX should merge with
 * construct/parse int.  */
static int construct_serialnum(ToBuildTBS *tbs, unsigned char *buf, int buflen){
  int written = 0;
  
  if(TLEN >= tbs->serialnumlen)
    memcpy(&buf[TLEN - tbs->serialnumlen], tbs->serialnum, tbs->serialnumlen);
  written += tbs->serialnumlen;

  written += construct_length(tbs->serialnumlen, buf, TLEN);

  if(TLEN > 0)
    buf[TLEN - 1] = TYPE_INTEGER;
  written += 1;

  return written;
}


/* The version number can be omitted if it is version 1, otherwise it
 * can only be of a prescribed form of 3 encodings. */
static int construct_version(int version, unsigned char *buf, int buflen){
  int written = 0;

  switch(version){
  case 1:
    if(CONSTRUCT_VERSION_EXPLICITLY){
      if(TLEN >= VERSIONLEN)
	memcmp(&buf[TLEN - VERSIONLEN], VERSION1, VERSIONLEN);
      written += VERSIONLEN;
    }
    else
      written = 0; /* version 1 is the default and does not need to be
		      present */
    break;
  case 2:
    if(TLEN >= VERSIONLEN)
      memcmp(&buf[TLEN - VERSIONLEN], VERSION2, VERSIONLEN);
    written += VERSIONLEN;
    break;
  case 3:
    if(TLEN >= VERSIONLEN)
      memcmp(&buf[TLEN - VERSIONLEN], VERSION3, VERSIONLEN);
    written += VERSIONLEN;
    break;
  };

  return written;
}


/* The text of the x509 certificate that the signature is over is
 * called the tbscertificate.  */
static int construct_tbs_certificate(ToBuildTBS *tbs, unsigned char *buf, int buflen){
  int written = 0;

  written += construct_pubkey(tbs, buf, TLEN);
  constructer_current_view("built pubkey", buf, TLEN);

  written += construct_name(tbs->subj_countryname, 
			    tbs->subj_statename,
			    tbs->subj_localityname,
			    tbs->subj_orgname,
			    tbs->subj_orgunit,
			    tbs->subj_commonname,
			    buf, TLEN);
  //written += construct_name(tbs->subj_name, tbs->subj_namelen, buf, TLEN);
  constructer_current_view("built subj name", buf, TLEN);

  written += construct_validity(tbs->starttime, tbs->endtime, buf, TLEN);
  constructer_current_view("built validity name", buf, TLEN);

  written += construct_name(tbs->iss_countryname, 
			    tbs->iss_statename,
			    tbs->iss_localityname,
			    tbs->iss_orgname,
			    tbs->iss_orgunit,
			    tbs->iss_commonname,
			    buf, TLEN);
  //written += construct_name(tbs->iss_name, tbs->iss_namelen, buf, TLEN);
  constructer_current_view("built issuer name", buf, TLEN);

  written += construct_alg(&tbs->iss_alg, buf, TLEN);
  constructer_current_view("built alg", buf, TLEN);

  written += construct_serialnum(tbs, buf, TLEN);
  constructer_current_view("built serialnum", buf, TLEN);

  written += construct_version(tbs->version, buf, TLEN);
  constructer_current_view("built version", buf, TLEN);

  written += construct_sequence(written, CLASS_UNIVERSAL, SEQ_CONSTRUCTED, buf, TLEN);
  constructer_current_view("built sequence", buf, TLEN);

  return written;
}

#if 0
/* construct an X509 from a parsed X509 */
int construct_x509(ParsedX509 *x509, unsigned char *buf, int buflen){
  int written = 0;

  /* copy in the sig */
  int copylen = max(min(x509->sig.datalen, buflen), 0);
  memcpy(&buf[TLEN - x509->sig.datalen], x509->sig.data, copylen);
  written += x509->sig.datalen;

  /* construct the bit string header for the sig */
  written += construct_bit_string(x509->sig.datalen, buf, TLEN);

  /* construct the signature alg info */
  written += construct_alg(&x509->algid, buf, TLEN);

  /* construct the certificate data */
  written += construct_tbs_certificate(&x509->tbscert, buf, TLEN);
  
  /* construct sequence header */
  written += construct_sequence(written, CLASS_UNIVERSAL, SEQ_CONSTRUCTED, buf, TLEN);

  return written;
}
#endif



int construct_x509(unsigned char *serialnum, int serialnumlen,
		   AlgType iss_alg,
		   unsigned char *iss_name, int iss_namelen,
		   char *starttime, char *endtime,
		   AlgType subj_alg,
		   unsigned char *subj_modulus, int subj_moduluslen,
		   unsigned char *subj_pubexp, int subj_pubexplen,
		   unsigned char *subj_name, int subj_namelen,
		   int siglen,
		   unsigned char *buf, int buflen){
  ToBuildTBS tobuild;
  
  tobuild.version = 1;
  tobuild.serialnumlen = serialnumlen;
  tobuild.serialnum = serialnum;

  tobuild.iss_alg = iss_alg;

  tobuild.iss_namelen = iss_namelen;
  tobuild.iss_name = iss_name;

  tobuild.iss_countryname = "US";
  tobuild.iss_statename = "New York";
  tobuild.iss_localityname = "Ithaca";
  tobuild.iss_orgname = "Cornell University Nexus";
  tobuild.iss_orgunit = "NONE";
  tobuild.iss_commonname = "TPM Privacy CA";

  tobuild.starttime = starttime;
  tobuild.endtime = endtime;

  tobuild.subj_alg = subj_alg;
  tobuild.subj_moduluslen = subj_moduluslen;
  tobuild.subj_modulus = subj_modulus; 
  tobuild.subj_pubexplen = subj_pubexplen;
  tobuild.subj_pubexp = subj_pubexp; 

  tobuild.subj_namelen = subj_namelen;
  tobuild.subj_name = subj_name;

  tobuild.subj_countryname = "US";
  tobuild.subj_statename = "New York";
  tobuild.subj_localityname = "Ithaca";
  tobuild.subj_orgname = "Cornell University Nexus";
  tobuild.subj_orgunit = "NONE";
  tobuild.subj_commonname = "TPM Privacy CA";

  int written = 0;

  /* don't actually put in the signature (we don't know it yet) */
  written += siglen;

  /* construct the bit string header for the sig */
  written += construct_bit_string(siglen, buf, TLEN);

  /* construct the signature alg info */
  written += construct_alg(&tobuild.iss_alg, buf, TLEN);

  /* construct the cert */
  written += construct_tbs_certificate(&tobuild, buf, TLEN);

  /* construct sequence header */
  written += construct_sequence(written, CLASS_UNIVERSAL, SEQ_CONSTRUCTED, buf, TLEN);

  return written;
}
