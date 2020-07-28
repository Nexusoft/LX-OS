#ifndef __X509PARSE_H__
#define __X509PARSE_H__

typedef struct ParsedX509 ParsedX509;

typedef enum AlgType{
  ALG_NONE,
  ALG_RSA_MD2,
  ALG_RSA_MD5,
  ALG_RSA_SHA1,
  ALG_DSA_SHA1,
  ALG_RSA_ENCRYPT,
}AlgType;


/* construct a ASN.1 DER encoded X509 and place it in buf. */
//int construct_x509(ParsedX509 *x509, unsigned char *buf, int buflen);
int construct_x509(unsigned char *serialnum, int serialnumlen,
		   AlgType iss_alg,
		   unsigned char *iss_name, int iss_namelen,
		   char *starttime, char *endtime,
		   AlgType subj_alg,
		   unsigned char *subj_modulus, int subj_moduluslen,
		   unsigned char *subj_pubexp, int subj_pubexplen,
		   unsigned char *subj_name, int subj_namelen,
		   int siglen,
		   unsigned char *buf, int buflen);

/* parse an ASN.1 DER encoded X509 from buf. */
ParsedX509 *parse_x509(unsigned char *buf, int buflen);


unsigned char *parsex509_getmsg(unsigned char *buf, int *msglen);
unsigned char *parsex509_getsig(unsigned char *buf, int *siglen);

#endif
