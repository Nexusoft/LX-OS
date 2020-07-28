#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h> //XXX for roundup
#include <sys/socket.h> /* for tcp socket to ca */
#include <netinet/in.h>

#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include <libtcpa/buildbuff.h>
#include <libtcpa/identity_private.h>

#include <nexus/defs.h>
#include <nexus/util.h>
#include <nexus/tpmcompat.h>
#include <nexus/Debug.interface.h>
#include <nexus/Crypto.interface.h>
#include <nexus/Attestation.interface.h>

#include <libtcpa/identity-code.c>

/* XXX where should it go or should it exist at all? */
unsigned char tcpa_version_buf_g[TCPA_VERSION_SIZE];

enum IDENTITY_ERRORS{
  ERR_IDENTITY_CA = 1,
  ERR_IDENTITY_MAKEID,
  
};

#define MAX_IDBINDING_SIZE (1024)


/* the generate functions generate new data to fill the struct with,
 * the fill functions fill in a new structure with various parameters.
 */

void generateSymKeyData(SymKeyData *new){
  new->algorithm = TCPA_ALG_AES;
  new->encscheme = TCPA_ES_NONE; /* XXX what should the scheme be */
  new->sigscheme = TCPA_SS_NONE; 
  new->keylength = AES_DEFAULT_KEYSIZE;
  new->blocksize = AES_BLOCK_SIZE;
  new->ivsize = AES_IV_SIZE;
  RAND_bytes(new->IV, AES_IV_SIZE); 
  RAND_bytes(new->key, AES_DEFAULT_KEYSIZE); 
}

int fillIdentityProofData(IdentityProofData *new,
			   char *idname, int idnamelen,
			   char *idbinding, int idbindingsize,
			   PubKeyData *idkey, 
			   char *ek_cert, char *conf_cert, char *platform_cert){
  int ekfd, conffd, platformfd;
  int eklen, conflen, platformlen;
  
  printf("cert files: %s %s %s\n", ek_cert, conf_cert, platform_cert);

  ekfd = open(ek_cert, O_RDONLY);
  printf("ekfd = %d ", ekfd);
  if(ekfd <= 0)
    eklen = 0;
  else
    eklen = lseek(ekfd, 0, SEEK_END);

  printf("eklen = %d ", eklen);

  conffd = open(conf_cert, O_RDONLY);
  printf("conffd = %d ", conffd);
  if(conffd <= 0)
    conflen = 0;
  else
    conflen = lseek(conffd, 0, SEEK_END);

  printf("conflen = %d ", conflen);

  platformfd = open(platform_cert, O_RDONLY);
  printf("platform = %d ", platformfd);
  if(platformfd <= 0)
    platformlen = 0;
  else
    platformlen = lseek(platformfd, 0, SEEK_END);
  
  printf("platformlen = %d ", platformlen);

  if(eklen > MAX_CRED_LEN){
    printf("ek cert too long");
    return -1;
  }
  if(platformlen > MAX_CRED_LEN){
    printf("platform cert too long");
    return -1;
  }
  if(conflen > MAX_CRED_LEN){
    printf("conf cert too long");
    return -1;
  }

  printf("len = %d\n", eklen);

  new->labelSize = idnamelen;
  new->idbindingSize = idbindingsize;
  new->endorsementSize = eklen;
  new->platformSize = platformlen;
  new->conformanceSize = conflen;

  memcpy(&new->identityKey, idkey, sizeof(PubKeyData));
  memcpy(new->labelArea, idname, idnamelen);
  memcpy(new->idbinding, idbinding, idbindingsize);

  int len;
  lseek(ekfd, 0, SEEK_SET);
  len = read(ekfd, new->endorsementCred, eklen);
  assert(eklen == len);

  lseek(platformfd, 0, SEEK_SET);
  len = read(platformfd, new->platformCred, platformlen);
  assert(platformlen == len);

  lseek(conffd, 0, SEEK_SET);
  len = read(conffd, new->conformanceCred, conflen);
  assert(conflen == len);

  unsigned char hash[20];
  SHA1(new->endorsementCred, new->endorsementSize, hash);
  int i;
  printf("endorsement hash: ");
  for(i = 0; i < 20; i++)
    printf("%02x ", hash[i]);
  printf("\n");
  printf("first bytes: ");
  for(i = 0; i < 20; i++)
    printf("%02x ", new->endorsementCred[i]);
  printf("\n");
  printf("last bytes: ");
  for(i = 20; i > 0; i--)
    printf("%02x ", new->endorsementCred[eklen - i - 1]);
  printf("\n");


  return 0;
}

int fillIdentityReqData(IdentityReqData *new,
			char *idname, int idnamelen,
			char *idbinding, int idbindingsize,
			PubKeyData *idkey, PubKeyData *cakey, 
			char *ek_cert, char *conf_cert, char *platform_cert){

  int ret = fillIdentityProofData(&new->proof, 
				  idname, idnamelen,
				  idbinding, idbindingsize,
				  idkey, ek_cert, conf_cert, platform_cert);
  memcpy(&new->pubkey, cakey, sizeof(PubKeyData));
  generateSymKeyData(&new->symkey);

  return ret;
}

int fillIdentityRespData(IdentityRespData *new,
			 PubKeyData *idkey,
			 X509 *cert, RSA *pubek){
  memcpy(&new->idkey, idkey, sizeof(PubKeyData));
  generateSymKeyData(&new->symkey);
  new->cert = cert;
  new->pubek = pubek;
  return 0;
}
			  
/* the recv functions just parse the structures enough to get them off the wire */
int recvall(int fd, char *buf, int size){
  int bytes = 0;
  while(bytes < size) {
    int rv = recv(fd, buf + bytes, size - bytes, 0);
    if(rv < 0) {
      printf("recvall(): error %d! (errno = %d)\n", rv, errno);
      printf("fatal error on connection\n");
      printf("exiting\n");
      exit(-1);
    }
    bytes += rv;
  }
  return bytes;
}

int sendall(int fd, unsigned char *data, int len) {
  int bytes = 0;
  while(bytes < len) {
    int rv = send(fd, data + bytes, len - bytes, 0); 
    if (rv <= 0) {
      printf("sendall(): error %d! (errno = %d)\n", rv, errno);
      printf("fatal error on connection\n");
      printf("exiting\n");
      exit(-1);
    }
    bytes += rv;
  }
  return bytes;
}

int RecvKeyParms(int fd, unsigned char *buf){
  int trash;
  short shorttrash;
  int parmsize;
  int subtotal = 0;

  subtotal += recvall(fd, buf, 2 * sizeof(int) + 2 * sizeof(short));
  
  readbuff("L S S L", buf,
	  &trash,
	  &shorttrash,
	  &shorttrash,
	  &parmsize);

  subtotal += recvall(fd, buf + subtotal, parmsize);
  
  return subtotal;
}

int RecvIdentityReq(int fd, unsigned char *buf){
  int asymsize;
  int symsize;
  int subtotal = 0;

  subtotal = recvall(fd, buf, 2 * sizeof(int));

  readbuff("L L", buf,
	   &asymsize, 
	   &symsize);
  
  subtotal += RecvKeyParms(fd, buf + subtotal);
  subtotal += RecvKeyParms(fd, buf + subtotal);

  subtotal += recvall(fd, buf + subtotal, asymsize + symsize);

  return subtotal;
}

int RecvPubKey(int fd, unsigned char *buf){
  int subtotal = 0;

  subtotal += RecvKeyParms(fd, buf + subtotal);
  subtotal += recvall(fd, buf + subtotal, sizeof(int));
  
  int keylen;
  readbuff("L", buf + subtotal - sizeof(int), &keylen);
  printf("keylen = %d\n", keylen);

  subtotal += recvall(fd, buf + subtotal, keylen);

  printf("pubkey subtotal=%d\n", subtotal);
  return subtotal;
}

int RecvCertifyReq(int fd, unsigned char *buf){
  int subtotal = 0;

  subtotal += recvall(fd, buf, TCPA_VERSION_SIZE);
  subtotal += recvall(fd, buf + subtotal, sizeof(short)+sizeof(int)+sizeof(char));
  subtotal += RecvPubKey(fd, buf + subtotal);
  subtotal += recvall(fd, buf + subtotal, sizeof(int));

  int pcrinfolen;
  readbuff("L", buf + subtotal - sizeof(int), &pcrinfolen);
  printf("pcrinfolen = %d\n", pcrinfolen);
  
  subtotal += recvall(fd, buf + subtotal, pcrinfolen);
  subtotal += recvall(fd, buf + subtotal, TCPA_NONCE_SIZE);
  subtotal += recvall(fd, buf + subtotal, sizeof(char));
  subtotal += recvall(fd, buf + subtotal, TCPA_SIG_SIZE);

  subtotal += recvall(fd, buf + subtotal, 8*20 + 1);
  printf("certifyreq subtotal=%d\n", subtotal);
  return subtotal;
}

int RecvAIKCert(int fd, unsigned char *buf){
  int certlen;

  recvall(fd, (unsigned char *)&certlen, sizeof(int));
  printf("certlen = %d\n", certlen);
  certlen = ntohl(certlen);
  printf("certlen = %d\n", certlen);
  
  return recvall(fd, buf, certlen);
}
//XXX this version should go
int RecvAsymCaContents(int fd, unsigned char *buf){
  int subtotal = 0;
  int asymsize;

  printf("getting len\n");
  subtotal += recvall(fd, buf, sizeof(int));
  
  int len = readbuff("L", buf,
		     &asymsize);
  assert(len == sizeof(int));

  printf("len =%d (%d)\n", asymsize, ntohl(asymsize));
  subtotal += recvall(fd, buf + subtotal, asymsize);

  return subtotal;
}
/* XXX this version does not include the length in the result buffer. */
int RecvAsymCaContents2(int fd, unsigned char *buf){
  int subtotal = 0;
  int asymsize;
  int tmpint;

  printf("getting len\n");
  subtotal += recvall(fd, (unsigned char *)&tmpint, sizeof(int));
  
  asymsize = ntohl(tmpint);

  printf("len =%d (%d)\n", asymsize, ntohl(asymsize));

  return recvall(fd, buf, asymsize);
}

int RecvSymCaContents(int fd, unsigned char *buf){
  int subtotal = 0;
  int certsize;

  subtotal += recvall(fd, buf, sizeof(int));

  readbuff("L", buf,
	   &certsize);

  subtotal += RecvKeyParms(fd, buf + subtotal);

  subtotal += recvall(fd, buf + subtotal, certsize);
  
  return subtotal;
}



/* the build functions use libtcpa's buildbuff to put the structure
 * into the format that the TPM expects (Network byte order, etc)
 */
unsigned char build_idproof_fmt[]     = "% L L L L L % % % % % %";

int BuildIdentityContents(unsigned char *buffer, IdentityContentsData *data){
  int dbg = 1;
  unsigned char build_idcontents_fmt[]     = "% L % %";
  unsigned char chosenid[TCPA_HASH_SIZE];
  unsigned char idkey[TCPA_PUBKEY_SIZE];

  int size = BuildChosenIdHash(chosenid, data);
  assert(size == TCPA_HASH_SIZE);

  int keysize = BuildPubKey(idkey, &data->idkey);
  assert(keysize <= TCPA_PUBKEY_SIZE);

#if 0
  int i;
  printf("idkey:     ");
  for (i = 0; i < keysize; i++)
    printf("%02x ", idkey[i]);
  printf("\n");
#endif
  if(dbg){
    unsigned char tmphash[TCPA_HASH_SIZE];
    SHA1(idkey, keysize, tmphash);
    printf("id pubkey (%d) has hash:", keysize);
    //PRINT_BYTES(idkey, keysize);
    PRINT_HASH(tmphash);
  }

  printf("%s:%d:tcpa version %d %d %d %d\n", __FILE__, __LINE__, TCPA_VERSION[0], TCPA_VERSION[1], TCPA_VERSION[2], TCPA_VERSION[3]);
  int ret = buildbuff(build_idcontents_fmt, buffer,
		      TCPA_VERSION_SIZE, TCPA_VERSION,
		      TPM_ORD_MakeIdentity,
		      TCPA_HASH_SIZE, chosenid,
		      keysize, idkey);
  return ret;
}


int BuildIdentityProof(unsigned char *buffer, IdentityProofData *proof){
  unsigned char keybuf[TCPA_PUBKEY_SIZE];
  int keybuflen, prooflen;

  keybuflen = BuildPubKey(keybuf, &proof->identityKey);
  assert(keybuflen <= TCPA_PUBKEY_SIZE);

  printf("%s:%d:tcpa version %d %d %d %d\n", __FILE__, __LINE__, TCPA_VERSION[0], TCPA_VERSION[1], TCPA_VERSION[2], TCPA_VERSION[3]);
  prooflen = buildbuff(build_idproof_fmt, buffer,
		       TCPA_VERSION_SIZE, TCPA_VERSION, /* XXX put this in struct */
		       proof->labelSize, 
		       proof->idbindingSize, 
		       proof->endorsementSize,
		       proof->platformSize, 
		       proof->conformanceSize,
		       keybuflen, keybuf,
		       proof->labelSize, proof->labelArea,
		       proof->idbindingSize, proof->idbinding,
		       proof->endorsementSize, proof->endorsementCred,
		       proof->platformSize, proof->platformCred,
		       proof->conformanceSize, proof->conformanceCred);
  return prooflen;
}

int ExtractIdentityProof(IdentityProofData *proof, unsigned char *buffer){

  unsigned char *pubkeyptr = buffer + TCPA_VERSION_SIZE + (5 * sizeof(unsigned int));
  int pubkeylen = ExtractPubKey(&proof->identityKey, pubkeyptr);
  
  int versionsize = TCPA_VERSION_SIZE;
  int bytes = readbuff(build_idproof_fmt, buffer,
		       &versionsize, TCPA_VERSION, /* XXX put this in struct */
		       &proof->labelSize,
		       &proof->idbindingSize, 
		       &proof->endorsementSize,
		       &proof->platformSize, 
		       &proof->conformanceSize,
		       &pubkeylen, NULL,
		       &proof->labelSize, proof->labelArea,
		       &proof->idbindingSize, proof->idbinding,
		       &proof->endorsementSize, proof->endorsementCred,
		       &proof->platformSize, proof->platformCred,
		       &proof->conformanceSize, proof->conformanceCred);
  return bytes;
}

int BuildIdentityReq(unsigned char *buffer, IdentityReqData *req){
  unsigned char build_idreq_fmt[] = "L L % % % %";
  unsigned char asymalg[TCPA_ASYM_PARM_SIZE];
  unsigned char symalg[TCPA_SYM_PARM_SIZE];
  unsigned char symkey[TCPA_SYM_KEY_SIZE];
  unsigned char proof[TCPA_PROOF_SIZE + (AES_BLOCK_SIZE - (TCPA_PROOF_SIZE % AES_BLOCK_SIZE))];
  int asymalglen, symalglen, symkeylen, prooflen;

  asymalglen = BuildPubKeyParms(asymalg, &req->pubkey);
  assert(asymalglen <= TCPA_ASYM_PARM_SIZE);

  symalglen = BuildSymKeyParms(symalg, &req->symkey);
  assert(symalglen <= TCPA_SYM_PARM_SIZE);

  symkeylen = BuildSymKey(symkey, &req->symkey);
  assert(symkeylen <= TCPA_SYM_KEY_SIZE);

  prooflen = BuildIdentityProof(proof, &req->proof);
  assert(prooflen <= sizeof(proof));

  /* encrypt symkey with CA's public key */
  RSA *rsaca = rsa_from_pubkeydata(&req->pubkey);

  printf("symkeylen = %d, (key size = %d)\n", symkeylen, RSA_size(rsaca));

  unsigned char *asymblob = (unsigned char *)malloc(symkeylen + RSA_ENC_SIZE);
  int asymbloblen = RSA_public_encrypt(symkeylen, symkey,
				       asymblob, 
				       rsaca, RSA_PKCS1_OAEP_PADDING);
  printf("asymblob was %d\n", asymbloblen);
  assert(asymbloblen <= symkeylen + RSA_ENC_SIZE);

  if(asymbloblen < 0){
    ERR_load_crypto_strings();
    ERR_print_errors_fp(stdout);
  }

  /* encrypt proof with symkey */
  /* leave room for enc overhead */
  int symbloblen = prooflen + (AES_BLOCK_SIZE - (prooflen % AES_BLOCK_SIZE));
  unsigned char * symblob = (unsigned char *)malloc(symbloblen);
  printf("symbloblen = %d (prooflen = %d)\n", symbloblen, prooflen);
  nexus_cbc_encrypt(proof, symbloblen,
		    symblob, &symbloblen,
		    req->symkey.key, req->symkey.blocksize,
		    req->symkey.IV, req->symkey.ivsize);


  printf("about to buildbuf %d (line %d)\n", asymbloblen + symbloblen, __LINE__);

  int reqsize = buildbuff(build_idreq_fmt, buffer,
			  asymbloblen, 
			  symbloblen,
			  asymalglen, asymalg, 
			  symalglen, symalg,
			  asymbloblen, asymblob, 
			  symbloblen, symblob);
  
  free(asymblob);
  free(symblob);

  return reqsize;
}

/* ExtractIdentityReq is the only Extract function that needs an extra argument
 * to get the private key of the CA */
int ExtractIdentityReq(IdentityReqData *req, unsigned char *buffer, RSA *priv){
  int dbg = 1;
  unsigned char build_idreq_fmt[] = "L L % % % %";
  int asymbloblen, symbloblen; /* filled in with readbuff */

  /* encrypted contents read with readbuf */
  unsigned char asymblob[TCPA_SYM_KEY_SIZE + RSA_ENC_SIZE];
  unsigned char symblob[TCPA_PROOF_SIZE + (AES_BLOCK_SIZE - (TCPA_PROOF_SIZE % AES_BLOCK_SIZE))];

  /* decrypted contents before being extracted into structs */
  int symkeylen, symkeylen2;
  unsigned char symkeybuf[TCPA_SYM_KEY_SIZE];
  int prooflen, prooflen2;
  unsigned char proof[TCPA_PROOF_SIZE + (AES_BLOCK_SIZE - (TCPA_PROOF_SIZE % AES_BLOCK_SIZE))];
  
  /* extract the parms straight away */
  unsigned char *asymalgptr = buffer + (2 * sizeof(unsigned long));
  int asymalglen = ExtractPubKeyParms(&req->pubkey, asymalgptr);
  unsigned char *symalgptr = buffer + asymalglen + (2 * sizeof(unsigned long));
  int symalglen = ExtractSymKeyParms(&req->symkey, symalgptr);

  int bytes = readbuff(build_idreq_fmt, buffer,
		       &asymbloblen,
		       &symbloblen,
		       &asymalglen, NULL,
		       &symalglen, NULL,
		       &asymbloblen, asymblob,
		       &symbloblen, symblob);

  if(dbg){
    unsigned char tmphash[TCPA_HASH_SIZE];
    SHA1(asymblob, asymbloblen, tmphash);
    printf("req asymblob (len=%d) hash:", asymbloblen);
    PRINT_HASH(tmphash);
    int i;
    for (i = 0; i < asymbloblen; i++)
      printf("%02x ", asymblob[i]);
    printf("\n");
    SHA1(symblob, symbloblen, tmphash);
    printf("req symblob (len=%d) hash:", symbloblen);
    PRINT_HASH(tmphash);
  }


  /* decrypt symkey with CA's private key */
  /* XXX check alg parms */
  symkeylen = RSA_private_decrypt(asymbloblen, asymblob, 
				      symkeybuf, priv, RSA_PKCS1_OAEP_PADDING);
  if(symkeylen < 0){
    ERR_load_crypto_strings();
    ERR_print_errors_fp(stdout);
    printf("could not load private key\n");
  }

  if(dbg){
    unsigned char tmphash[TCPA_HASH_SIZE];
    memset(tmphash, 0, TCPA_HASH_SIZE);
    SHA1(symkeybuf, symkeylen, tmphash);
    printf("symkey was (len=%d) hash:", symkeylen);
    PRINT_HASH(tmphash);
  }

  symkeylen2 = ExtractSymKey(&req->symkey, symkeybuf);
  if (dbg)
    printf("symkey2 was (len=%d)\n", symkeylen2);
  assert(symkeylen == symkeylen2);
  

  /* decrypt proof */
  /* XXX check alg parms */
  prooflen = TCPA_PROOF_SIZE + (AES_BLOCK_SIZE - (TCPA_PROOF_SIZE % AES_BLOCK_SIZE));

  nexus_cbc_decrypt(symblob, symbloblen,
		    proof, &prooflen,
		    req->symkey.key, req->symkey.blocksize, 
		    req->symkey.IV, req->symkey.ivsize);

  if(dbg){
    unsigned char tmphash[TCPA_HASH_SIZE];
    SHA1(proof, prooflen, tmphash);
    printf("extracted proof (len=%d) with hash:", prooflen);
    PRINT_HASH(tmphash);
  }

  prooflen2 = ExtractIdentityProof(&req->proof, proof);

  //printf("prooflen = %d prooflen2 =%d\n", prooflen, prooflen2);
  //assert(prooflen == prooflen2);

  pubkeydata_from_rsa(priv, &req->pubkey);

  return bytes;
}


/* this version of ExtractIdentityReq is for debugging to make sure
 * our symkey encryption is sane */
int ExtractIdentityReq_debug(IdentityReqData *req, unsigned char *buffer, SymKeyData *key){
  unsigned char build_idreq_fmt[] = "L L % % % %";
  int asymbloblen, symbloblen; /* filled in with readbuff */

  /* encrypted contents read with readbuf */
  unsigned char asymblob[TCPA_SYM_KEY_SIZE + RSA_ENC_SIZE];
  unsigned char symblob[TCPA_PROOF_SIZE + (AES_BLOCK_SIZE - (TCPA_PROOF_SIZE % AES_BLOCK_SIZE))];

  /* decrypted contents before being extracted into structs */
  int prooflen, prooflen2;
  unsigned char proof[TCPA_PROOF_SIZE + (AES_BLOCK_SIZE - (TCPA_PROOF_SIZE % AES_BLOCK_SIZE))];
  
  /* extract the parms straight away */
  unsigned char *asymalgptr = buffer + (2 * sizeof(unsigned long));
  int asymalglen = ExtractPubKeyParms(&req->pubkey, asymalgptr);
  unsigned char *symalgptr = buffer + asymalglen + (2 * sizeof(unsigned long));
  int symalglen = ExtractSymKeyParms(&req->symkey, symalgptr);

  int bytes = readbuff(build_idreq_fmt, buffer,
		       &asymbloblen,
		       &symbloblen,
		       &asymalglen, NULL,
		       &symalglen, NULL,
		       &asymbloblen, asymblob,
		       &symbloblen, symblob);

  memcpy(&req->symkey, key, sizeof(SymKeyData));

  /* decrypt proof */
  /* XXX check alg parms */
  prooflen = TCPA_PROOF_SIZE + (AES_BLOCK_SIZE - (TCPA_PROOF_SIZE % AES_BLOCK_SIZE));

  nexus_cbc_decrypt(symblob, symbloblen,
		    proof, &prooflen,
		    req->symkey.key, req->symkey.blocksize, 
		    req->symkey.IV, req->symkey.ivsize);

  prooflen2 = ExtractIdentityProof(&req->proof, proof);

  return bytes;
}



int BuildIdentityResp(unsigned char *buffer, IdentityRespData *resp){
  unsigned char build_idresp_fmt[] = "L %";
  unsigned char asymcontents[TCPA_SYM_KEY_SIZE + TCPA_HASH_SIZE];
  unsigned char idkey[TCPA_PUBKEY_SIZE];
  int asymlen, idkeylen;
  int ret;

  int i;
  /* put asymcontents in first */

  idkeylen = BuildPubKey(idkey, &resp->idkey);
  asymlen = BuildSymKey(asymcontents, &resp->symkey);
#if 0
  printf("symkey: ");
  for(i = 0; i < asymlen; i++){
    printf("%02x ", asymcontents[i]);
  }
  printf("\n");
#endif

  SHA1(idkey, idkeylen, asymcontents + asymlen);

#if 0
  printf("hash: ");
  for(i = 0; i < TCPA_HASH_SIZE; i++){
    printf("%02x ", asymcontents[i + asymlen]);
  }
  printf("\n");
#endif

  asymlen += TCPA_HASH_SIZE;

#if 0
  printf("entire: ");
  for(i = 0; i < asymlen; i++){
    printf("%02x ", asymcontents[i]);
  }
  printf("\n");
#endif

  /* Need to give the TCPA OAEP padding parameter */
  int tcpapadlen = 4;
  char tcpapad[4];
  tcpapad[0] = 'T';
  tcpapad[1] = 'C';
  tcpapad[2] = 'P';
  tcpapad[3] = 'A';
  //tcpapad[4] = '\0';
  int pubeklen = BN_num_bytes(resp->pubek->n);
  printf("pubeklen=%d\n", pubeklen);
  int padlen = pubeklen;
  int unpadlen = pubeklen;
  unsigned char *padbuf = (unsigned char *)malloc(padlen);
  unsigned char *unpadbuf = (unsigned char *)malloc(unpadlen);

  ret = RSA_padding_add_PKCS1_OAEP(padbuf, padlen, 
				   asymcontents, asymlen, 
				   tcpapad, tcpapadlen);
			     
  if(ret == 0){
    printf("couldn't add padding\n");
    assert(0);
  }
  for(i = 0; i < padlen; i++)
    if(padbuf[i] != 0)
      break;

  ret = RSA_padding_check_PKCS1_OAEP(unpadbuf, unpadlen, 
				     padbuf + i, padlen - i, 
				     pubeklen, 
				     tcpapad, tcpapadlen);

  printf("ret = %d\n", ret);
  if(ret < 0){
    printf("couldn't check padding");
    ERR_load_crypto_strings();
    ERR_print_errors_fp(stdout);
    assert(0);
  }
  printf("check succeeded!\n");



  int asymbloblen = RSA_public_encrypt(padlen, padbuf,
				       buffer + sizeof(int),
				       resp->pubek, RSA_NO_PADDING);
  if(asymbloblen < 0){
    printf("couldn't encrypt\n");
    ERR_load_crypto_strings();
    ERR_print_errors_fp(stdout);
    assert(0);
  }

  printf("asymbloblen = %d\n", asymbloblen);
  printf("asymbloblen = 0x%x\n", htonl(asymbloblen));


  unsigned char tmphash[TCPA_HASH_SIZE];
  SHA1(buffer + sizeof(int), asymbloblen, tmphash);
  printf("hash of asymblob: ");
  //int i;
  for(i = 0; i < TCPA_HASH_SIZE; i++)
    printf("%02x", tmphash[i]);
  printf("\n");

  ret = buildbuff("L", buffer, asymbloblen);
  assert(ret = sizeof(int));

  unsigned char *ptr = buffer + asymbloblen + sizeof(int);
  

  unsigned char symparms[TCPA_SYM_PARM_SIZE];
  int symparmlen = BuildSymKeyParms(symparms, &resp->symkey);
  assert(symparmlen <= sizeof(symparms));

  /* we'll have the bio grow from zero */
  BIO *cert = BIO_new(BIO_s_mem());
  char *certbuf = NULL;
  PEM_write_bio_X509(cert, resp->cert);
  int certsize = BIO_get_mem_data(cert, &certbuf);
  printf("certsize = %d\n", certsize);

  unsigned char certhash[TCPA_HASH_SIZE];
  SHA1(certbuf, certsize, certhash);
  printf("certhash: ");
  for(i = 0; i < TCPA_HASH_SIZE; i++){
    printf("%02x ", certhash[i]);
  }
  printf("\n");

  int startlen = buildbuff(build_idresp_fmt, ptr,
			   certsize,
			   symparmlen, symparms);
  assert(startlen == symparmlen + sizeof(int));

  int targetsize = certsize;

  /* symmetric encryption */
  nexus_cbc_encrypt(certbuf, certsize,
		    ptr+ startlen, &targetsize,
		    resp->symkey.key, resp->symkey.blocksize,
		    resp->symkey.IV, resp->symkey.ivsize);
  assert(targetsize == certsize);
  
  assert(*(unsigned int *)buffer = htonl(asymbloblen));

  return startlen + targetsize + asymbloblen + sizeof(int);
}

#define NEXUSCA_CLIENT_PORT (1178)
#define PRIVACY_CLIENT_PORT (1179)

int connectToCA(short localport, const char *server_addr, short destport) {
  int fd = socket(PF_INET, SOCK_STREAM, 0);
  assert(fd);

  struct sockaddr_in addr;
  addr.sin_addr.s_addr = 0;
  addr.sin_port = htons(localport);
  int err = bind(fd, (struct sockaddr *)&addr, sizeof(addr));
  if (err) {
    printf("could not bind to local address\n");
    return 0;
  }

  struct sockaddr_in dest;
  dest.sin_family = AF_INET;
  memcpy(&dest.sin_addr.s_addr, server_addr, 4);
  dest.sin_port = htons(destport);
  err = connect(fd, (struct sockaddr *)&dest, sizeof(dest));
  if (err) {
    printf("failed to connect to remote certificate authority at %d.%d.%d.%d:%d\n",
	0xff&server_addr[0], 0xff&server_addr[1],
	0xff&server_addr[2], 0xff&server_addr[3], destport);
    return 0;
  }

  return fd;
}

void sendIdentityRequest(int fd, unsigned char *buf, int buflen){
  if(buf == NULL) 
    return;

  {
    unsigned char tmp[20];
    int i;
    SHA1(buf, buflen, tmp);
    printf("sending hash: ");
    for(i = 0; i < 20; i++){
      printf("%02x ", tmp[i]);
    }
    printf("\n");
    
    printf("dumping buffer");
    Debug_KernelTftp("tcptest.send", strlen("tcptest.send"), buf, buflen);
  }  
  
  sendall(fd, buf, buflen);
}

int ExtractSymCaBlob(SymCaBlob *blob, unsigned char *buffer){
  int bytes;

  blob->blobsize = ntohl(*(int *)buffer);
  bytes = sizeof(int);

  bytes += ExtractSymKeyParms(&blob->symkey, buffer + sizeof(int));
  memcpy(blob->blob, buffer + bytes, blob->blobsize);

  return bytes + blob->blobsize;
}











/* Compat for new code.  This entire library in this file should be
 * cleaned up at some point.
 */
int BuildIdentityReq_from_tpm_certification(unsigned char *buffer,
					    unsigned char *proof, int prooflen,
					    RSA *rsaca);
int tpmidentity_send_receive(unsigned char *reqbuf, int reqlen, 
			     RSA *pubkey,
			     const char *ca_addr, short ca_port,
			     unsigned char *asymblob, int *asymbloblen,
			     unsigned char *symblob, int *symbloblen){
  unsigned char encbuf[TCPA_IDENTITY_REQ_SIZE];
  int enclen = BuildIdentityReq_from_tpm_certification(encbuf, 
						       reqbuf, reqlen, 
						       pubkey);
  if(enclen <= 0)
    return -1;

  int fd = connectToCA(PRIVACY_CLIENT_PORT, ca_addr, ca_port);
  if(fd == 0)
    return -1;

  sendIdentityRequest(fd, encbuf, enclen);
  
  printf("going to receive ca contents (fd = %d)\n", fd);

  *asymbloblen = RecvAsymCaContents2(fd, asymblob);
  printf("got %d bytes of asym\n", *asymbloblen);
  *symbloblen = RecvSymCaContents(fd, symblob);
  printf("got %d bytes of sym\n", *symbloblen);
  
  
  close(fd);
  return 0;
}

int tpmidentity_get_cred(unsigned char *decrypt, int decryptlen,
			 unsigned char *symblob, int symbloblen,
			 unsigned char *cert, int *certlen){
  SymCaBlob sym;

  int dlen = ExtractSymKey(&sym.symkey, decrypt);
  assert(dlen == decryptlen);

  int extractsize = ExtractSymCaBlob(&sym, symblob);
  assert(extractsize == symbloblen);

  printf("extractsize=%d, symbloblen=%d, sym.blobsize=%d\n", extractsize, symbloblen, sym.blobsize);

  nexus_cbc_decrypt(sym.blob, sym.blobsize,
		    cert, certlen,
		    sym.symkey.key, sym.symkey.blocksize,
		    sym.symkey.IV, sym.symkey.ivsize);

  return 0;
}


/* XXX this is a hack to get back into the messy tpmidentity library
 * code after using the new kernel interface.
 */
int BuildIdentityReq_from_tpm_certification(unsigned char *buffer,
					    unsigned char *proof, int prooflen,
					    RSA *rsaca){
  int dbg = 1;
  unsigned char build_idreq_fmt[] = "L L % % % %";
  unsigned char asymalg[TCPA_ASYM_PARM_SIZE];
  unsigned char symalg[TCPA_SYM_PARM_SIZE];
  unsigned char symkey[TCPA_SYM_KEY_SIZE];
  int asymalglen, symalglen, symkeylen;


  if(dbg){
    unsigned char tmphash[TCPA_HASH_SIZE];
    SHA1(proof, prooflen, tmphash);
    printf("building proof (len=%d) with hash:", prooflen);
    PRINT_HASH(tmphash);
  }


  PubKeyData reqpubkey;
  pubkeydata_from_rsa(rsaca, &reqpubkey);

  SymKeyData reqsymkey;
  generateSymKeyData(&reqsymkey);

  asymalglen = BuildPubKeyParms(asymalg, &reqpubkey);
  assert(asymalglen <= TCPA_ASYM_PARM_SIZE);

  symalglen = BuildSymKeyParms(symalg, &reqsymkey);
  assert(symalglen <= TCPA_SYM_PARM_SIZE);

  symkeylen = BuildSymKey(symkey, &reqsymkey);
  assert(symkeylen <= TCPA_SYM_KEY_SIZE);


  /* encrypt symkey with CA's public key */
  printf("symkeylen = %d, (key size = %d)\n", symkeylen, RSA_size(rsaca));

  unsigned char *asymblob = (unsigned char *)malloc(symkeylen + RSA_ENC_SIZE);
  int asymbloblen = RSA_public_encrypt(symkeylen, symkey,
				       asymblob, 
				       rsaca, RSA_PKCS1_OAEP_PADDING);
  printf("asymblob was %d\n", asymbloblen);
  assert(asymbloblen <= symkeylen + RSA_ENC_SIZE);

  if(asymbloblen < 0){
    ERR_load_crypto_strings();
    ERR_print_errors_fp(stdout);
  }

  /* encrypt proof with symkey */
  /* leave room for enc overhead */
  int symbloblen = prooflen + (AES_BLOCK_SIZE - (prooflen % AES_BLOCK_SIZE));
  unsigned char * symblob = (unsigned char *)malloc(symbloblen);
  printf("symbloblen = %d (prooflen = %d)\n", symbloblen, prooflen);
  //nexus_cbc_encrypt(proof, symbloblen,
  nexus_cbc_encrypt(proof, prooflen,
		    symblob, &symbloblen,
		    reqsymkey.key, reqsymkey.blocksize,
		    reqsymkey.IV, reqsymkey.ivsize);
  printf("symbloblen = %d (prooflen = %d)\n", symbloblen, prooflen);

  printf("about to buildbuf %d (line %d)\n", asymbloblen + symbloblen, __LINE__);


  if(dbg){
    unsigned char tmphash[TCPA_HASH_SIZE];
    SHA1(symkey, symkeylen, tmphash);
    printf("symkey was (len=%d) hash:", symkeylen);
    PRINT_HASH(tmphash);
    SHA1(asymblob, asymbloblen, tmphash);
    printf("req asymblob (len=%d) hash:", asymbloblen);
    PRINT_HASH(tmphash);
    SHA1(symblob, symbloblen, tmphash);
    printf("req symblob (len=%d) hash:", symbloblen);
    PRINT_HASH(tmphash);
  }



  int reqsize = buildbuff(build_idreq_fmt, buffer,
			  asymbloblen, 
			  symbloblen,
			  asymalglen, asymalg, 
			  symalglen, symalg,
			  asymbloblen, asymblob, 
			  symbloblen, symblob);
  

  free(asymblob);
  free(symblob);

  return reqsize;
}


unsigned char *tpmidentity_get_nexus_cred(//unsigned char *wrappednsk, int wrappednsklen,
					  unsigned char *req, int reqlen,
					  //unsigned char *sig, int siglen,
					  const char *nca_addr, short nca_port,
					  unsigned char *aikpem, int aikpemlen,
					  int *nskcredlen, int *nsksformlen){
  int fd = connectToCA(NEXUSCA_CLIENT_PORT, nca_addr, nca_port);
  if (fd == 0)
    return NULL;

  /* send certifykeyreq, certlen, and aikcert */
  int sendlen = htonl(aikpemlen);

  sendall(fd, req, reqlen);
  sendall(fd, (char *)&sendlen, sizeof(int));
  sendall(fd, aikpem, aikpemlen);

  printf("receiving nexus key cert size\n");
  recvall(fd, (unsigned char *)nskcredlen, sizeof(int));
  printf("received nexus key cert size = %d\n", *nskcredlen);
  *nskcredlen = ntohl(*nskcredlen);
  printf("received nexus key cert size = %d\n", *nskcredlen);
  if(*nskcredlen == -1){
    printf("error from nexus ca!!\n");
    return NULL;
  }
  printf("receiving nexus key signedformula size\n");
  recvall(fd, (unsigned char *)nsksformlen, sizeof(int));
  printf("received nexus key signedformula size = %d\n", *nsksformlen);
  *nsksformlen = ntohl(*nsksformlen);
  printf("received nexus key signedformula size = %d\n", *nsksformlen);
  if(*nsksformlen == -1){
    printf("error from nexus ca!!\n");
    return NULL;
  }
  unsigned char *nskcred = (unsigned char *)malloc(*nskcredlen + *nsksformlen);

  recvall(fd, nskcred, *nskcredlen + *nsksformlen);

  printf("received key cert, len=%d\n", *nskcredlen + *nsksformlen);

  close(fd);

  return nskcred;
}
