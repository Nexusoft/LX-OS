//#include <stdlib.h>
//#include <stdio.h>
//#include <string.h>

#include <nexus/defs.h> // safe to include in all environments

static int dbg = 0;


typedef enum ParseAlgType ParseAlgType;
enum ParseAlgType{
  PARSE_ALG_ENC,
  PARSE_ALG_SIG,
};


void parser_current_view(char *func, unsigned char *buf){
  if(dbg){
    printf("parsing %s: view: ", func);
    printf("%02x ", buf[0]);
    printf("%02x ", buf[1]);
    printf("%02x ", buf[2]);
    printf("%02x ", buf[3]);
    printf("%02x ", buf[4]);
    printf("%02x ", buf[5]);
    printf("...\n");
  }
}

/* the length is specified in one or more octets, depending on a bit
 * set in the first octet.  This implementation only parses lengths
 * that take up to 4 octets. */
static int parse_length(int *len, unsigned char *buf){
  if((buf[0] & MASK_LONG_FORM) == 0){
    *len = (int)buf[0];
    return 1;
  }
  int numoctets = buf[0] & ~MASK_LONG_FORM;

  if(numoctets > 4){
    /* XXX >4 long form not implemented */
    printf("XXX Long form not implemented %s %d\n", __FILE__, __LINE__);
    return -1;
  }
  
  int i;
  unsigned int size = 0;;
  for(i = 0; i < numoctets; i++){
    unsigned int tmp = buf[1 + i];
    size = size << 8;
    size |= tmp;
  }
  *len = size;

  return numoctets + 1;
}


/* A sequence is one of the ASN.1 primitive types.  It is followed by
 * a length that corresponds to the length of the sequence. */
static int parse_sequence(int *seqlen, unsigned char *buf){
  unsigned char tagtype = buf[0] & MASK_TYPE;

  if(dbg)
    printf("parsing sequence 0x%02x, tagtype=0x%02x ", buf[0], tagtype);

  if(tagtype != TYPE_SEQUENCE){
    printf("error parsing sequence tagtype %02x (expected %02x) %s:%d\n", 
	   tagtype, TYPE_SEQUENCE, __FILE__, __LINE__);
    return -1;
  }

  //s->seqtype = buf[0] & MASK_SEQTYPE;
  //s->class = buf[0] & MASK_CLASS;

  int off = parse_length(seqlen, &buf[1]);

  if(dbg)
    printf("seqlen = %d\n", *seqlen);

  return off + 1;
}


/* Version number is either omitted, or v1, v2, or v3.  We explicitly
   check for the three options. */
static int parse_version(int *version, unsigned char *buf){

  int len = VERSIONLEN;
  *version = 1; /* by default the version is v1 */


  if(memcmp(buf, VERSION1, VERSIONLEN) == 0)
    *version = 1;
  else if(memcmp(buf, VERSION2, VERSIONLEN) == 0)
    *version = 2;
  else if(memcmp(buf, VERSION3, VERSIONLEN) == 0)
    *version = 3;
  else
    len = 0; /* it's ok for the version not to be present */
  
  return len;
}


/* The serial number is just an integer.  XXX should merge with
 * construct/parse int.  */
static int parse_serialnum(SerialNum *num, unsigned char *buf){
  unsigned char tagtype = buf[0] & MASK_TYPE;
  int offset = 1;

  if(tagtype != TYPE_INTEGER){
    printf("error parsing serialnum tagtype %02x (expected %02x) %s:%d\n", 
	   tagtype, TYPE_INTEGER, __FILE__, __LINE__);
    return -1;
  }

  int off = parse_length(&num->len, buf + offset);
  if(off < 0)
    return -1;
  offset += off;
  
  num->num = (unsigned char *)nxcompat_alloc(num->len);
  memcpy(num->num, buf + offset, num->len);

  return offset + num->len;
}


/* The name doesnt get parsed yet.  XXX It will probably have to if we
   want to fill in common name/etc. */
static int parse_name(Name *name, unsigned char *buf){
  int off;
  int offset = 0;

  int seqlen;
  off = parse_sequence(&seqlen, buf);
  if(off < 0)
    return -1;
  offset = off;

  name->datalen = seqlen + off;
  name->data = (unsigned char *)nxcompat_alloc(name->datalen);
  memcpy(name->data, buf, name->datalen);
  
  return name->datalen;
}



/* The validity consists of two UTCTYPE or GENERALIZEDTIME structures.
 * XXX The parse/construct UTC/GENERALIZEDTIME should probably be
 * moved out into a common function. */
static int parse_validity(Validity *validity, unsigned char *buf){
  int off;
  int offset = 0;
  int len;

  int seqlen;
  off = parse_sequence(&seqlen, buf);
  if(off < 0)
    return -1;
  offset += off;

  validity->starttype = buf[offset] & MASK_TYPE;
  if((validity->starttype != TYPE_UTCTIME) &&
     (validity->starttype != TYPE_GENERALIZEDTIME)){
    printf("Wrong type for validity: 0x%02x (expected 0x%02x or 0x%02x) %s:%d",
	   validity->starttype, TYPE_UTCTIME, TYPE_GENERALIZEDTIME, 
	   __FILE__, __LINE__);
    return -1;
  }
  offset += 1;

  off = parse_length(&len, buf + offset);
  if(off < 0)
    return -1;
  offset += off;
  
  validity->starttime = (char *)nxcompat_alloc(len + 1);
  strncpy(validity->starttime, (char *)buf + offset, len);
  validity->starttime[len] = '\0';
  offset += len;

  validity->endtype = buf[offset] & MASK_TYPE;
  if((validity->endtype != TYPE_UTCTIME) &&
     (validity->endtype != TYPE_GENERALIZEDTIME)){
    printf("Wrong type for validity: 0x%02x (expected 0x%02x or 0x%02x) %s:%d",
	   validity->endtype, TYPE_UTCTIME, TYPE_GENERALIZEDTIME, 
	   __FILE__, __LINE__);
    return -1;
  }
  offset += 1;

  off = parse_length(&len, buf + offset);
  if(off < 0)
    return -1;
  offset += off;
  
  validity->endtime = (char *)nxcompat_alloc(len + 1);
  strncpy(validity->endtime, (char *)buf + offset, len);
  validity->endtime[len] = '\0';
  offset += len;

  if(dbg)
    printf("validity start time = %s, end time = %s\n", validity->starttime, validity->endtime);

  return offset;
}


/* An ASN.1 null consists of the NULL identifier, followed by a zero
 * byte. Only RSA algs use the null. */
static int parse_null(unsigned char *buf){
  parser_current_view("null", buf);

  unsigned char tagtype = buf[0] & MASK_TYPE;

  if(tagtype != TYPE_NULL){
    printf("error parsing null tagtype %02x (expected %02x) %s:%d\n", 
	   tagtype, TYPE_NULL, __FILE__, __LINE__);
    return -1;
  }

  if(buf[1] != 0)
    return -1;

  return 2;
}


/* There are only four different types of signature algorithms.  Check
 * to see which algorithm is specified and catch the null if
 * necessary. 
 */
static int parse_alg_id(AlgType *obj, unsigned char *buf, ParseAlgType sig){
  parser_current_view("alg_id", buf);

  unsigned char tagtype = buf[0] & MASK_TYPE;
  int offset = 0;
  int off;

  if(tagtype != TYPE_OBJECT_IDENTIFIER){
    printf("error parsing objid tagtype %02x (expected %02x) %s:%d\n", 
	   tagtype, TYPE_OBJECT_IDENTIFIER, __FILE__, __LINE__);
    return -1;
  }
  offset += 1;

  int objlen;
  off = parse_length(&objlen, &buf[offset]);
  if(off <= 0)
    return -1;
  offset += off;

  int objstart = offset;

  if(dbg)
    printf("at buf: %02x %02x %02x %02x\n", buf[offset], buf[offset+1], buf[offset+2], buf[offset+3]);

  *obj = ALG_NONE;
  if(sig == PARSE_ALG_SIG){
    if(memcmp(buf + offset, OBJID_RSA_MD2, OBJID_RSA_MD2_LEN) == 0){
      *obj = ALG_RSA_MD2;
      offset += OBJID_RSA_MD2_LEN;
    }else if(memcmp(buf + offset, OBJID_RSA_MD5, OBJID_RSA_MD5_LEN) == 0){
      *obj = ALG_RSA_MD5;
      offset += OBJID_RSA_MD5_LEN;
    }else if(memcmp(buf + offset, OBJID_RSA_SHA1, OBJID_RSA_SHA1_LEN) == 0){
      *obj = ALG_RSA_SHA1;
      offset += OBJID_RSA_SHA1_LEN;
    }else if(memcmp(buf + offset, OBJID_DSA_SHA1, OBJID_DSA_SHA1_LEN) == 0){
      *obj = ALG_DSA_SHA1;
      offset += OBJID_DSA_SHA1_LEN;
    }

    if(dbg)
      printf("*obj = %d, offset-objstart=%d, objlen=%d offset=%d objstart=%d\n", 
	     *obj, offset-objstart, objlen, offset, objstart);

    /* rsa algorithms have a null at the end, dsa has nothing */
    if(*obj != ALG_DSA_SHA1){
      off = parse_null(&buf[offset]);
      if(off < 0)
	return -1;
      offset += off;
    }
  }else{
    if(memcmp(buf + offset, OBJID_RSA_ENCRYPT, OBJID_RSA_ENCRYPT_LEN) == 0){
      *obj = ALG_RSA_ENCRYPT;
      offset += OBJID_RSA_ENCRYPT_LEN;
      off = parse_null(&buf[offset]);
      if(off < 0)
	return -1;
      offset += off;
    }
  }

  return offset;
}


/* The signature algorithm informs us which hash algorithm was used
 * before the signature.  A lot of the standard x509s (ca self-signed)
 * use md5, but Nexus CAs use sha1. */
static int parse_alg(AlgType *alg, unsigned char *buf, ParseAlgType sig){
  int off;
  int offset = 0;

  if(dbg)
    printf("*****parsing %s alg\n", (sig == 1)?"sig":"enc");

  int seqlen;
  off = parse_sequence(&seqlen, buf);
  if(off <= 0)
    return -1;
  offset += off;

  if(dbg)
    printf("off(%d)+seqlen(%d)=%d\n", off, seqlen, seqlen + off);

  off = parse_alg_id(alg, buf + offset, sig);
  if(off <= 0)
    return -1;
  offset += off;

  if(dbg){
    printf("offset = %d\n", offset);
    printf("at buf: %02x %02x %02x %02x\n", buf[offset], buf[offset+1], buf[offset+2], buf[offset+3]);
  }

  return offset;
}

static int parse_bit_string_hdr(int *datalen, unsigned char *buf){
  unsigned char tagtype = buf[0] & MASK_TYPE;

  if(dbg)
    printf("parsing bitstring 0x%02x, tagtype=0x%02x ", buf[0], tagtype);

  if(tagtype != TYPE_BIT_STRING){
    printf("error parsing bit string tagtype %02x (expected %02x) %s:%d\n", 
	   tagtype, TYPE_BIT_STRING, __FILE__, __LINE__);
    return -1;
  }

  int offset = 1;
  int bytes;
  int off = parse_length(&bytes, &buf[1]);
  if(off <= 0)
    return -1;
  offset += off;
  
  int unusedbits = buf[offset];
  if(unusedbits != 0){
    /* XXX unused bits not supported */ 
    printf("XXX unused bits not supported %d, %s %d\n", 
	   unusedbits, __FILE__, __LINE__);
    return -1;
  }
  offset += 1;

  *datalen = bytes - 1;

  return offset;
}

/* An ASN.1 bitstring type has a length and an extra byte identifying
 * how many bits over an octet the bitstring is.  We don't support any
 * nonzero value for this. */
static int parse_bit_string(BitString *bs, unsigned char *buf){
  int off;
  int offset = 0;

  off = parse_bit_string_hdr(&bs->datalen, buf);
  if(off < 0)
    return -1;
  offset += off;

  if(dbg)
    printf("sig length = %d\n", bs->datalen);
  
  bs->data = (unsigned char *)nxcompat_alloc(bs->datalen);
  memcpy(bs->data, buf+offset, bs->datalen);

  return offset + bs->datalen;
}


/* Parse an int into an array, len combination.  The ints we run into
   are large, like an rsa public key modulus. */
static int parse_int(int *numlen, unsigned char **num, unsigned char *buf){
  unsigned char tagtype = buf[0] & MASK_TYPE;
  int offset = 0;
  int off;
  parser_current_view("int", buf);

  if(tagtype != TYPE_INTEGER){
    return -1;
  }
  offset += 1;
  
  off = parse_length(numlen, buf + offset);
  if(off < 0)
    return -1;
  offset += off;

  
  *num = (unsigned char *)nxcompat_alloc(*numlen);
  memcpy(*num, buf + offset, *numlen);

  return offset + *numlen;
}


/* The public key is inside a bitstring, and consists of a sequence of
 * two ints: the modulus and the public exponent. This is only for RSA
 * public keys. */
static int parse_pubkeydata(PubKey *key, unsigned char *buf){
  BitString pubkey;
  int pubkeyseqlen;
  parser_current_view("pubkeydata", buf);

  int ret = parse_bit_string(&pubkey, buf);
  if(ret < 0)
    return -1;

  int off, offset = 0;

  off = parse_sequence(&pubkeyseqlen, pubkey.data);
  if(off < 0)
    return -1;
  offset += off;

  off = parse_int(&key->moduluslen, &key->modulus, pubkey.data + offset);
  if(off < 0)
    return -1;
  offset += off;

  if(dbg){
    printf("moduluslen = %d\n", key->moduluslen);
    printf("modulus = \n");
    int i;
    for(i = 0; i < key->moduluslen; i++){
      printf("%02x ", key->modulus[i]);
    }
    printf("\n");
  }

  off = parse_int(&key->pubexplen, &key->pubexp, pubkey.data + offset);
  if(off < 0)
    return -1;
  offset += off;

  if(dbg)
    printf("pubexplen = %d\n", key->pubexplen);

  if(offset != pubkey.datalen){
    printf("sanity check offset(%d)=datalen(%d) failed %s:%d\n", 
	   offset, pubkey.datalen, __FILE__, __LINE__);
    return -1;
  }
  return ret;
}


/* The public key is a sequence of an algorithm identifier and a
   bitstring containing algorithm specific info (like modulus and
   public exponent for RSA).  Only RSA is supported.  */
static int parse_pubkey(PubKey *key, unsigned char *buf){
  parser_current_view("alg_id", buf);

  int off;
  int offset = 0;
  int seqlen;

  off = parse_sequence(&seqlen, buf);
  if(off < 0)
    return -1;
  offset += off;

  off = parse_alg(&key->subjectalg, buf + offset, PARSE_ALG_ENC);
  if(off < 0)
    return -1;
  offset += off;

  off = parse_pubkeydata(key, buf + offset);
  if(off < 0)
    return -1;
  offset += off;

  return offset;
}

/* The text of the x509 certificate that the signature is over is
 * called the tbscertificate.  */
static int parse_tbs_certificate(TBSCertificate *tbs, unsigned char *buf){
  int off;
  int offset = 0;

  if(dbg)
    printf("*****parsing tbs\n");

  int tbsseqlen;
  off = parse_sequence(&tbsseqlen, buf);
  if(off <= 0)
    return -1;
  offset += off;
  int seqlen = off;

  /* copy DER encoded cert that signature is over */
  if(dbg)
    printf("tbssequencelen = %d\n", tbsseqlen);

  tbs->datalen = tbsseqlen + off;
  tbs->data = (unsigned char *)nxcompat_alloc(tbs->datalen);
  memcpy(tbs->data, buf, tbs->datalen);

  //return off + tbsseqlen;


  /* parse internals of certificate */
  off = parse_version(&tbs->version, buf + offset);
  if(off < 0)
    return -1;
  offset += off;

  off = parse_serialnum(&tbs->serialnum, buf + offset);
  if(off < 0)
    return -1;
  offset += off;

  off = parse_alg(&tbs->algid, buf + offset, PARSE_ALG_SIG);
  if(off < 0)
    return -1;
  offset += off;

  off = parse_name(&tbs->issuer, buf + offset);
  if(off < 0)
    return -1;
  offset += off;

  off = parse_validity(&tbs->validity, buf + offset);
  if(off < 0)
    return -1;
  offset += off;

  off = parse_name(&tbs->subject, buf + offset);
  if(off < 0)
    return -1;
  offset += off;

  off = parse_pubkey(&tbs->subjectpubkey, buf + offset);
  if(off < 0)
    return -1;
  offset += off;

  if(dbg){
    printf("%d left in tbs cert to parse\n", seqlen + tbsseqlen - offset);
    printf("  at buf: %02x %02x %02x %02x\n", buf[offset], buf[offset+1], buf[offset+2], buf[offset+3]);
  }

  if(offset != seqlen + tbsseqlen){
    printf("sanity check offset(%d)=seqlen(%d) failed %s:%d\n", 
	   offset, seqlen + tbsseqlen, __FILE__, __LINE__);
    return -1;
  }

  return seqlen + tbsseqlen;
}


/* The x509 structure is an ASN.1 sequence of three things, the
 * certificate data, the algorithm info for the signature, and the
 * signature. */
ParsedX509 *parse_x509(unsigned char *buf, int buflen){
  int offset = 0;
  int off;
  int seqlen;

  ParsedX509 *x509 = nxcompat_alloc(sizeof(ParsedX509));

  /* parse sequence header */
  off = parse_sequence(&seqlen, buf);
  if(off <= 0)
    goto parse_x509_err;
  offset += off;

  /* parse the certificate data */
  off = parse_tbs_certificate(&x509->tbscert, buf + offset);
  if(off <= 0)
    goto parse_x509_err;
  if(dbg)
    printf("offset = %d off = %d\n", offset, off);
  offset += off;

  /* parse the signature alg info */
  off = parse_alg(&x509->algid, buf + offset, PARSE_ALG_SIG);
  if(off <= 0)
    goto parse_x509_err;
  offset += off;

  /* parse the sig */
  off = parse_bit_string(&x509->sig, buf + offset);
  if(off <= 0)
    goto parse_x509_err;
  offset += off;

  if(offset != buflen)
    printf("didn't parse entire buffer (%d/%d)\n", offset, buflen);

  return x509;

 parse_x509_err:
  parsedx509_free(x509);
  return NULL;
}

ParsedX509 *parsedx509_new(void){
  ParsedX509 *x509 = (ParsedX509 *)nxcompat_alloc(sizeof(ParsedX509));
  memset(x509, 0, sizeof(ParsedX509));
  return x509;
}
void parsedx509_free(ParsedX509 *x509){
  if(x509->tbscert.data != NULL)
    nxcompat_free(x509->tbscert.data);
  if(x509->sig.data != NULL)
    nxcompat_free(x509->sig.data);
  nxcompat_free(x509);
}

unsigned char *parsex509_getmsg(unsigned char *buf, int *msglen){
  int off;
  int totallen;

  off = parse_sequence(&totallen, buf);
  if(off <= 0)
    return NULL;

  unsigned char *ptr = buf + off;

  int seqlen;
  off = parse_sequence(&seqlen, ptr);
  if(off <= 0)
    return NULL;

  *msglen = seqlen + off;
  return ptr;
}

unsigned char *parsex509_getsig(unsigned char *buf, int *siglen){
  int msglen, off;
  unsigned char *ptr;
  AlgType sigalg;
  
  ptr = parsex509_getmsg(buf, &msglen);
  if(ptr == NULL)
    return NULL;
  ptr += msglen;

  off = parse_alg(&sigalg, ptr, PARSE_ALG_SIG);
  if(off < 0)
    return NULL;
  ptr += off;

  
  off = parse_bit_string_hdr(siglen, ptr);
  if(off < 0)
    return NULL;

  return ptr + off;
}





/* XXX not integrated into full parser yet */
static int parse_subjaltname_internals(char **dns, char **uri, unsigned int *ip, int maxlen, unsigned char *buf){
  int len;
  int off = 0;
  char *target;
  while(off < maxlen){
    switch(buf[off]){
    case SUBJALTNAME_TYPE_DNS:
      off += 1;
      off += parse_length(&len, buf+off);
      target = (char *)nxcompat_alloc(len + 1);
      memcpy(target, buf + off, len);
      target[len] = 0;
      off += len;

      *dns = target;
      break;
    case SUBJALTNAME_TYPE_URI:
      off += 1;
      off += parse_length(&len, buf+off);
      target = (char *)nxcompat_alloc(len + 1);
      memcpy(target, buf + off, len);
      target[len] = 0;
      off += len;

      *uri = target;
      break;
    case SUBJALTNAME_TYPE_IP:
      off += 1;
      off += parse_length(&len, buf+off);
      if(len != sizeof(unsigned int))
	printf("wrong length IP address %d!", len);
      *ip = *(unsigned int *)(buf+off);
      off += sizeof(unsigned int);
      break;
    default:
      printf("unknown subjaltname type 0x%02x\n", buf[off]);
      return -1;
    }
  }
  return off;
}

/* XXX make static when combined */
int parse_subjaltname(char **dns, char **uri, unsigned int *ip, unsigned char *buf){
  int seqlen;
  int off = 0;

  off += parse_sequence(&seqlen , buf);
  off += parse_subjaltname_internals(dns, uri, ip, seqlen, buf + off);

  return off;
}

