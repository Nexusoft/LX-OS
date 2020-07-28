#ifndef _NEXUS_DER_H_
#define _NEXUS_DER_H_

#ifdef __NEXUSKERNEL__
#include <linux/string.h>
#else
#include <string.h>
#endif

// DER encode and decode helper routines.
// See formula.c for an example of how to use these. Encoding, in particular, is
// easiest done backwards.

/* DER tags */

#define DER_ASN1_INTEGER 0x02
#define DER_ASN1_BITSTRING 0x03 // we only partially support bitstrings with unused bits
#define DER_ASN1_OCTETSTRING 0x04
#define DER_ASN1_OBJECTIDENTIFIER 0x06
#define DER_ASN1_PRINTABLESTRING 0x13
#define DER_ASN1_ASCIISTRING 0x16
#define DER_ASN1_SEQUENCE 0x30


/* DER encoding */
/* NOTE: ALL the der_*_encode routines and der_cat write at the END of the
 * buffer provided, not the start. */

// write an already-encoded der message into a buffer (essentially just memcpy)
int der_cat(unsigned char *buf, int len, unsigned char *der, int derlen);

// write just a header (tag and body length)
int der_tag_encode(unsigned char *buf, int len, int bodylen, int tag); 

// write a header (with specified tag) and body (with specified bytes)
// optionally, if prefix is non null, it is prepended to the body before writing
int der_array_encode0(unsigned char *buf, int len, unsigned char *data, int datalen, int tag, unsigned char *prefix);

// write a header (with specified tag) and body (with specified bytes)
static inline int der_array_encode(unsigned char *buf, int len, unsigned char *data, int datalen, int tag) {
  return der_array_encode0(buf, len, data, datalen, tag, 0);
}



// write a PRINTABLESTRING
static inline int der_printable_encode(unsigned char *buf, int len, char *str) {
  return der_array_encode(buf, len, (unsigned char *)str, strlen(str), DER_ASN1_PRINTABLESTRING);
}

// write an ASCIISTRING
static inline int der_ascii_encode(unsigned char *buf, int len, char *str) {
  return der_array_encode(buf, len, (unsigned char *)str, strlen(str), DER_ASN1_ASCIISTRING);
}

// write an OCTETSTRING
static inline int der_octets_encode(unsigned char *buf, int len, unsigned char *data, int datalen) {
  return der_array_encode(buf, len, data, datalen, DER_ASN1_OCTETSTRING);
}

// write a BISTRING (any unused bits in the data array must be cleared already)
// precondition: 0 <= unusedbits < 8
static inline int der_bitstring_encode(unsigned char *buf, int len, unsigned char *data, int datalen, int unusedbits) {
  unsigned char prefix = (unusedbits & 0xff);
  return der_array_encode0(buf, len, data, datalen, DER_ASN1_BITSTRING, &prefix);
}

// write an OID
static inline int der_oid_encode(unsigned char *buf, int len, unsigned char *oid, int oidlen) {
  return der_array_encode(buf, len, oid, oidlen, DER_ASN1_OBJECTIDENTIFIER);
}

// write a big unsigned INTEGER (prepending a zero byte if needed)
int der_biguint_encode(unsigned char *buf, int len, unsigned char *bigint, int bigintlen);

// write an INTEGER
int der_integer_encode(unsigned char *buf, int len, int value);


/* DER decoding */

int der_hdrlen(const unsigned char *der); // length of der message header (input must be 2 byte minimum)
int der_bodylen(const unsigned char *der); // length of der message body (input must be der_hdrlen minimum)
int der_msglen(const unsigned char *der); // total length of der message (input must be der_hdrlen minimum)
int der_msglen_u(const unsigned char *uder); // total length of user-space der message (uses peek_user)

// strip off a der header and return the tag (and the end-of-body pointer)
// endbody may not equal end, since the input der message might contain a
// multiple der objects
int der_unwrap(unsigned char **der, unsigned char *end, unsigned char **endbody);

// strip off an INTEGER body, and update the pointer (no error checking)
int der_integer_demangle(unsigned char **der, unsigned char *end, int *val);

// strip off a big unsigned INTEGER body, and update the pointer (no error checking)
// returns 0 on success, and sets bigintlen to the actual length, filling in bigint
int der_biguint_demangle(unsigned char **der, unsigned char *end, unsigned char *bigint, int *bigintlen);

char *der_string_demangle(unsigned char **der, unsigned char *end);

// strip off an ASCIISTRING body, and update the pointer (no error checking)
static inline char *der_ascii_demangle(unsigned char **der, unsigned char *end) { return der_string_demangle(der, end); }

// strip off a PRINTABLESTRING body, and update the pointer (no error checking)
static inline char *der_printable_demangle(unsigned char **der, unsigned char *end) { return der_string_demangle(der, end); }

// strip off an OCTETSTRING body, and update the pointer (no error checking)
unsigned char *der_octets_demangle(unsigned char **der, unsigned char *end, int *octetlen);

// strip off an BITSTRING body, and update the pointer (no error checking)
unsigned char *der_bitstring_demangle(unsigned char **der, unsigned char *end, int *bitstringlen, int *unusedbits);


#endif //_NEXUS_DER_H_
