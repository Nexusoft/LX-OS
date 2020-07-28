/** NexusOS: DER encoding of NAL statements. */

int der_cat(unsigned char *buf, int len, unsigned char *der, int derlen) {
  if (len > derlen)
    memcpy(buf+len-derlen, der, derlen);
  else if (len > 0)
    memcpy(buf, der, len);
  return derlen;
}

static inline void byte_cat(unsigned char *buf, int len, int byte) {
  if (len > 0)
    buf[len-1] = (char)(byte&0xff);
}


// write a start tag and length field
int der_tag_encode(unsigned char *buf, int len, int bodylen, int tag) {
  int n = 0;
  if (bodylen <= 0x7f) {
    byte_cat(buf, len-n, bodylen); n++;
  } else if (bodylen <= 0xff) {
    byte_cat(buf, len-n, bodylen); n++;
    byte_cat(buf, len-n, 0x81); n++;
  } else if (bodylen <= 0xffff) {
    byte_cat(buf, len-n, bodylen & 0xff); n++;
    byte_cat(buf, len-n, bodylen >> 8); n++;
    byte_cat(buf, len-n, 0x82); n++;
  } else if (bodylen <= 0xffffff) {
    byte_cat(buf, len-n, bodylen & 0xff); n++;
    byte_cat(buf, len-n, (bodylen >> 8) & 0xff); n++;
    byte_cat(buf, len-n, bodylen >> 16); n++;
    byte_cat(buf, len-n, 0x83); n++;
  } else {
    byte_cat(buf, len-n, bodylen & 0xff); n++;
    byte_cat(buf, len-n, (bodylen >> 8) & 0xff); n++;
    byte_cat(buf, len-n, (bodylen >> 16) & 0xff); n++;
    byte_cat(buf, len-n, bodylen >> 24); n++;
    byte_cat(buf, len-n, 0x84); n++;
  }
  byte_cat(buf, len-n, tag); n++;
  return n;
}

int der_array_encode0(unsigned char *buf, int len, unsigned char *data, int datalen, int tag, unsigned char *prefix) {
  int written = 0;
  int i;
  for (i = datalen-1; i >= 0; i--) {
    byte_cat(buf, len-written, data[i]);
    written++;
  }
  if (prefix) {
    byte_cat(buf, len-written, *prefix);
    written++;
  }
  written += der_tag_encode(buf, len-written, written, tag);
  return written;
}

int der_biguint_encode(unsigned char *buf, int len, unsigned char *bigint, int bigintlen) {
  // drop leading zero bytes
  while (bigintlen && (bigint[0] == 0)) { bigint++; bigintlen--; }
  unsigned char zero = 0;
  if (bigintlen == 0 || bigint[0] & 0x80)
    return der_array_encode0(buf, len, bigint, bigintlen, DER_ASN1_INTEGER, &zero);
  else
    return der_array_encode0(buf, len, bigint, bigintlen, DER_ASN1_INTEGER, NULL);
}


int der_integer_encode(unsigned char *buf, int len, int value) {
  int i;
  int n;
  if ((value & 0xffffff80) == 0) n = 1;
  else if ((value & 0xffff8000) == 0) n = 2;
  else if ((value & 0xff800000) == 0) n = 3;
  else if ((value | 0x000000ff) == -1) n = 1;
  else if ((value | 0x0000ffff) == -1) n = 2;
  else if ((value | 0x00ffffff) == -1) n = 3;
  else n = 4;
  for (i = 0; i < n; i++) {
    byte_cat(buf, len-i, value & 0xff);
    value = value >> 8;
  }
  byte_cat(buf, len-n, n);
  byte_cat(buf, len-n-1, DER_ASN1_INTEGER);
  return n+2;
}

// input der must be at least 2 bytes long
int der_hdrlen(const unsigned char *der) {
  unsigned int byte = ((unsigned int)der[1]) & 0xff;
  return (byte & 0x80) ? 2+(byte & 0x7f) : 2;
}

// input der must be at least der_hdrlen() bytes long
int der_bodylen(const unsigned char *der) {
  int i, len = 0, n = der_hdrlen(der);
  assert(2 <= n && n <= 6);
  if (n == 2)
    return der[1];
  for (i = 2; i < n; i++) {
    unsigned int byte = ((unsigned int)der[i]) & 0xff;
    len = (len << 8) + byte;
  }
  return len;
}

// input der must be at least der_hdrlen() bytes long
int der_msglen(const unsigned char *der) {
  return der_hdrlen(der) + der_bodylen(der);
}

#ifdef __NEXUSKERNEL__
// version of der_msglen() that uses peek_user
int der_msglen_u(const unsigned char *uder) {
  // We don't support der buffers less than 6 bytes.
  // And, the first 6 bytes are sufficient for decoding the length.
  char first[6];
  if (peek_user(nexusthread_current_map(), (unsigned int)uder, first, 6))
    return 0;
  return der_msglen(first);
}
#endif

int der_unwrap(unsigned char **der, unsigned char *end, unsigned char **endbody) {
  int len = end - *der;
  if (len < 2) return -1;
  int tag = (*der)[0];

  int hdrlen = der_hdrlen(*der);
  if (len < hdrlen) return -1;

  int bodylen = der_bodylen(*der);
  if (len < hdrlen + bodylen) return -1;

  *der += hdrlen;
  *endbody = *der + bodylen;
  return tag;
}

int der_integer_demangle(unsigned char **der, unsigned char *end, int *val) {
  int len = end - *der;
  *val = 0;
  switch (len) {
    case 4:
      *val = ((unsigned int)*(*der)++) & 0xff;
      // fall through
    case 3:
      *val = (((unsigned int)*(*der)++) & 0xff) | ( *val << 8);
      // fall through
    case 2:
      *val = (((unsigned int)*(*der)++) & 0xff) | ( *val << 8);
      // fall through
    case 1:
      *val = (((unsigned int)*(*der)++) & 0xff) | ( *val << 8);
      return 0;
    default:
      return -1; 
  }
}

char *der_string_demangle(unsigned char **der, unsigned char *end) {
  int len = end - *der;
  if (len < 0) return NULL;
  char *str = nxcompat_alloc(len+1);
  memcpy(str, *der, len);
  str[len] = '\0';
  *der += len;
  return str;
}

unsigned char *der_octets_demangle(unsigned char **der, unsigned char *end, int *octetlen) {
  int len = end - *der;
  if (len < 0) return NULL;
  if (len == 0) {
    // empty sequence -- but our nxcompat_alloc fails when size is zero
    unsigned char *str = nxcompat_alloc(1);
    *str = 0; // contents don't matter
    return str;
  }
  unsigned char *str = nxcompat_alloc(len);
  memcpy(str, *der, len);
  *der += len;
  *octetlen = len;
  return str;
}

unsigned char *der_bitstring_demangle(unsigned char **der, unsigned char *end, int *bitstringlen, int *unusedbits) {
  int len = end - *der;
  if (len < 1) // illegal: missing body
    return NULL;
  if ((*der)[0] & 0xf8) // illegal: unusedbits > 7
    return NULL;
  if (len == 1 && (*der)[0] != 0) // illegal: empty but unusedbits > 0
    return NULL;
  if (unusedbits)
    *unusedbits = (*der)[0];
  else if ((*der)[0])
    return NULL; // caller was expecting zero unusedbits
  if (len == 1) {
    // empty sequence -- but our nxcompat_alloc fails when size is zero
    unsigned char *str = nxcompat_alloc(1);
    *str = 0; // contents don't matter
    return str;
  }
  unsigned char *str = nxcompat_alloc(len-1);
  memcpy(str, *der + 1, len-1);
  *der += len;
  *bitstringlen = len-1;
  return str;
}

int der_biguint_demangle(unsigned char **der, unsigned char *end, unsigned char *bigint, int *maxlen) {
  int len = end - *der;
  if (len <= 0) return -1;
  if (len > 1 && (*der)[0] == 0) { len--; (*der)++; } // drop a single leading zero
  if (len > *maxlen) return -1;
  memcpy(bigint, *der, len);
  *maxlen = len;
  *der += len;
  return 0;
}

/* These are totally wrong --- the length fields use an alternative encoding,
 * not the continuation bit like an OID would use.  They are kept here for now,
 * in case we want to use OIDs later. */
#if 0
int der_bodylen(char *der) {
	int len = 0;
	int i = 1;
	int byte;
	do {
		byte = ((unsigned int)der[i++]) & 0xff;
		len = (len << 7) + (byte & 0x7f);
	} while (byte & 0x80);
	return len;
}

int tag_encode(char *buf, int len, int bodylen, int tag) {
	int n = 0;
	do {
		int rem = bodylen >> 7;
		if (rem != 0)
			byte_cat(buf, len-n, (bodylen & 0x7f) | 0x80);
		else
			byte_cat(buf, len-n, (bodylen & 0x7f) | 0x00);
		bodylen = rem;
		n++;
	} while (bodylen != 0);
	byte_cat(buf, len-n, tag);
	return n+1;
}
#endif

