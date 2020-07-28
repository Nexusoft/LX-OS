unsigned char rsa_default_exponent_array_g[] = {0x01,0x00,0x01};

/* the build functions use libtcpa's buildbuff to put the structure
 * into the format that the TPM expects (Network byte order, etc)
 */
const char *build_pubkeyparms_fmt = "L S S L L L @";
const char *build_pubkey_fmt      = "% @";
const char *build_symkeyparms_fmt = "L S S L L L @";

int BuildPubKeyParms(unsigned char *buffer, PubKeyData *key){
  int keyparmlen;

  keyparmlen = buildbuff(build_pubkeyparms_fmt, buffer,
			 key->algorithm,
			 key->encscheme,
			 key->sigscheme,
			 /* XXX
			  * key->expsize + 3*sizeof(unsigned int)
			  * For some reason, the tpm expects the exponent
			  * to be left out (length 0) */
			 3*sizeof(unsigned int), /* parmsize */
			 key->keybitlen,
			 key->numprimes,
			 /* XXX
			  * key->expsize, key->exponent */
			 0);

  return keyparmlen;
}

int ExtractPubKeyParms(PubKeyData *key, unsigned char *buffer){
  int parmsize; /* trash */
  
  int bytes = readbuff(build_pubkeyparms_fmt, buffer,
		       &key->algorithm,
		       &key->encscheme,
		       &key->sigscheme,
		       &parmsize, 
		       &key->keybitlen,
		       &key->numprimes,
		       &key->expsize, key->exponent);

  /* XXX for some reason the tpm does not fill in the exponent, but
   * 65537 is the default */
  if(key->expsize == 0){
    key->expsize = 3;
    key->exponent[0] = 0x01;
    key->exponent[1] = 0x00;
    key->exponent[2] = 0x01;
  }
  

  return bytes;
}


int ExtractCertifyKeyData(CertifyKeyData *certify, unsigned char *buffer, 
		      PubKeyData *key, unsigned char *sig){
  const char *build_certifykey_fmt = "% S L o";

  int versionsize = TCPA_VERSION_SIZE;
  int bytes = readbuff(build_certifykey_fmt, buffer,
		       &versionsize, certify->version,
		       &certify->keyusage,
		       &certify->keyflags,
		       &certify->authdatausage);
  bytes += ExtractPubKeyParms(&certify->pub, buffer + bytes);
  
  assert(key->algorithm == certify->pub.algorithm);
  assert(key->encscheme == certify->pub.encscheme);
  assert(key->sigscheme == certify->pub.sigscheme);
  assert(key->keybitlen == certify->pub.keybitlen);
  assert(key->numprimes == certify->pub.numprimes);
  assert(key->expsize == certify->pub.expsize);
  assert(memcmp(key->exponent, certify->pub.exponent, key->expsize) == 0);

  /* ignore hash of key, we'll put the whole pubkeydata in */
  bytes += TCPA_HASH_SIZE;

  memcpy(certify->nonce, buffer + bytes, TCPA_NONCE_SIZE);
  bytes += TCPA_NONCE_SIZE;

  certify->parentpcr = *(buffer + bytes);
  bytes += sizeof(char);

  /* pcr info struct will not use the one in pubkey */
  certify->pcrinfolen = ntohl(*(unsigned int *)(buffer + bytes));
  bytes += sizeof(int);

  memcpy(certify->pcrinfo, buffer + bytes, certify->pcrinfolen);
  bytes += certify->pcrinfolen;

  /* fill in the supplied signature */
  memcpy(certify->sig, sig, TCPA_SIG_SIZE);

  /* fill in the rest of the key */
  memcpy(&certify->pub, key, sizeof(PubKeyData));

  return bytes;
}

int BuildCertifyKeyReq(unsigned char *buffer, CertifyKeyData *certify){
  unsigned char pubkey[TCPA_PUBKEY_SIZE];

  int pubkeylen = BuildPubKey(pubkey, &certify->pub);

  const char *build_certkeyreq_fmt = "% S L o % @ % o %";
  int certifylen = buildbuff(build_certkeyreq_fmt, buffer,
			     TCPA_VERSION_SIZE, certify->version, 
			     certify->keyusage,
			     certify->keyflags,
			     certify->authdatausage,
			     pubkeylen, pubkey,
			     certify->pcrinfolen, certify->pcrinfo,
			     TCPA_NONCE_SIZE, certify->nonce,
			     certify->parentpcr,
			     TCPA_SIG_SIZE, certify->sig);
  return certifylen;
}
int ExtractCertifyKeyReq(CertifyKeyData *certify, unsigned char *buffer){
  int bytes;
  
  int versionlen = TCPA_VERSION_SIZE;
  bytes = readbuff("% S L o", buffer,
		   &versionlen, &certify->version,
		   &certify->keyusage,
		   &certify->keyflags,
		   &certify->authdatausage);

  bytes += ExtractPubKey(&certify->pub, buffer + bytes);

  int noncelen = TCPA_NONCE_SIZE;
  int siglen = TCPA_SIG_SIZE;
  bytes += readbuff("@ % o %", buffer + bytes,
		    &certify->pcrinfolen, certify->pcrinfo,
		    &noncelen, &certify->nonce,
		    &certify->parentpcr,
		    &siglen, &certify->sig);
  
  return bytes;
}


int BuildPubKey(unsigned char *buffer, PubKeyData *key){
  unsigned char parms[TCPA_ASYM_PARM_SIZE];
  int parmlen, keylen;

  parmlen = BuildPubKeyParms(parms, key);
  assert(parmlen <= sizeof(parms));

  keylen = buildbuff(build_pubkey_fmt, buffer,
		     parmlen, parms,
		     key->keylength, key->modulus);
  
  return keylen;
}

int ExtractPubKey(PubKeyData *key, unsigned char *buffer){
  int parmsize = ExtractPubKeyParms(key, buffer);

  int bytes = readbuff(build_pubkey_fmt, buffer,
		       &parmsize, NULL,
		       &key->keylength, key->modulus);

  return bytes;
}

int BuildSymKeyParms(unsigned char *buffer, SymKeyData *key){
  int keyparmlen;

  keyparmlen = buildbuff(build_symkeyparms_fmt, buffer,
			 key->algorithm,
			 key->encscheme,
			 key->sigscheme,
			 key->ivsize + 3*sizeof(unsigned int), /* parmsize */
			 key->keylength,
			 key->blocksize,
			 key->ivsize, key->IV);

  return keyparmlen;
}

int ExtractSymKeyParms(SymKeyData *key, unsigned char *buffer){
  int parmsize; /* trash */

  int bytes = readbuff(build_symkeyparms_fmt, buffer,
		       &key->algorithm,
		       &key->encscheme,
		       &key->sigscheme,
		       &parmsize, 
		       &key->keylength,
		       &key->blocksize,
		       &key->ivsize, key->IV);

  return bytes;
}

int BuildSymKey(unsigned char *buffer, SymKeyData *key){
  const char *build_symkey_fmt      = "L S S %";
  int keylen;

  keylen = buildbuff(build_symkey_fmt, buffer,
		     key->algorithm,
		     key->encscheme,
		     key->keylength,
		     key->keylength, key->key);
  return keylen;
}

int ExtractSymKey(SymKeyData *key, unsigned char *buffer){
  const char ext_symkey_fmt[]      = "L S S";
  unsigned short keylength;

  int bytes = readbuff(ext_symkey_fmt, buffer,
		       &key->algorithm,
		       &key->encscheme,
		       &keylength);

  key->keylength = keylength;
  memcpy(key->key, buffer + bytes, key->keylength);

  return bytes + key->keylength;
}

