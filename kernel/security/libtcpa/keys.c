/****************************************************************************/
/*                                                                          */
/*                         TCPA Key Handling Routines                       */
/*                                                                          */
/* This file is copyright 2003 IBM. See "License" for details               */
/****************************************************************************/

#include <nexus/defs.h>
#include <libtcpa/tcpa.h>
#include <libtcpa/keys.h>
#include <libtcpa/hmac.h>
#include <libtcpa/oiaposap.h>
#include <libtcpa/buildbuff.h>

//#include <openssl/rsa.h>
//#include <openssl/bn.h>
//#include <openssl/rand.h>

PubKeyData CAKeyData;
int ca_set = 0;

unsigned char tcpadata_keys[TCPA_MAX_BUFF_SIZE];
unsigned char kparmbuf[TCPA_MAX_BUFF_SIZE];

# define RANDMAX 32749
# define RANDB 921

#include <../code/libtcpa/keys-code.c>


#if 0
//int rand_tpm(unsigned char *array, int bytes){
int RAND_bytes(unsigned char *array, int bytes){
  unsigned char *buf = (unsigned char *)galloc(bytes + 14);
  int ret = 0;
  int recv = 0;
  int bytesrecv = 0;

  //printk_red("RAND bytes being called!!!");
  //dump_stack();
  //nexuspanic();

  while(bytesrecv < bytes){
    *(unsigned short *)buf = htons(TPM_TAG_RQU_COMMAND);
    *(unsigned int *)&buf[2] = htonl(14);
    *(unsigned int *)&buf[6] = htonl(TPM_ORD_GetRandom);
    *(unsigned int *)&buf[10] = htonl(bytes - bytesrecv);

#if 0
    {
      int i;
      printk("buf to send: ");
      for(i = 0; i < 14; i++){
	printk("%02x ", buf[i]);
      }
      printk("\n");
    }
#endif

    ret = TPM_Transmit(buf, "Get Random");
    if(ret != 0){
      gfree(buf);
      return 0;
    }
    recv = ntohl(*(unsigned int*)(buf + 10));
    memcpy(array + bytesrecv, (buf + 14), recv);
    bytesrecv += recv;
  }
  gfree(buf);

  return bytesrecv;
}
#else
// holy crap: someone please change this, and implement a real random number
// generator (in both kernel and userspace).  how about: read initial seeds from
// tpm generator, then feed to Blum Blum Shub (or something else). For non
// crypto use, use Mersenne Twister or something similar, perhaps.
int RAND_bytes(unsigned char *array, int size){
  static int randlast = 0; // XXX need a better source of initial randomness
  int i;
  
  //printk_red("RAND_bytes array=0x%x, size=%d\n", array, size);

  //XXX need a better PRNG
  for (i = 0; i < size; i++)
    array[i] = (randlast = (randlast * RANDB +1) % RANDMAX);
  
  return 1;
}
#endif

int TPM_GetPubKey(unsigned int keyhandle, unsigned char *keyauth,
		  unsigned char *keydata, unsigned int *keydatalen){
  unsigned char evennonce[TCPA_NONCE_SIZE];
  unsigned char nonceodd[TCPA_NONCE_SIZE];
  unsigned int authhandle;
  unsigned char auth[TCPA_HASH_SIZE];
  unsigned char c;
  unsigned int ret;

  unsigned int ordinal, keyhdle;
  unsigned char *data;
  unsigned char getpubkey_fmt[] = "00 C2 T l l l % o %";

  //unsigned char pubkeyhash[TCPA_HASH_SIZE];
  //int i;
  unsigned int paramsize, keysize;

  if(keyhandle == 0 || keyauth == NULL)
    return -1;
  
  ret = TPM_OIAP(&authhandle, evennonce);
  if(ret) return ret;

  ordinal = htonl(TPM_ORD_GetPubKey);
  keyhdle = htonl(keyhandle);
  
  RAND_bytes(nonceodd, TCPA_NONCE_SIZE);
  c = 0;

  ret = authhmac(auth, keyauth, TCPA_HASH_SIZE, evennonce, nonceodd, c,
		 4, &ordinal,
		 0, 0);
  if(ret < 0){
    TPM_Terminate_Handle(authhandle);
    return -1;
  }

  data = galloc(TCPA_MAX_BUFF_SIZE);
  /* 00 C3 T l l l % o % */
  ret = buildbuff(getpubkey_fmt, data,
		  ordinal,
		  keyhdle,
		  htonl(authhandle),
		  TCPA_NONCE_SIZE, nonceodd,
		  c,
		  TCPA_HASH_SIZE, auth);
  if (ret <= 0) {
    gfree(data);
    TPM_Terminate_Handle(authhandle);
    return -1;
  }

  printk("transmitting GetPubKey request\n");
  ret = TPM_Transmit(data, "GetPubKey");
  
  TPM_Terminate_Handle(authhandle);
  if (ret != 0){
    gfree(data);
    return ret;
  }
  
  paramsize = ntohl(*(unsigned int *)(data + TCPA_PARAMSIZE_OFFSET));
  keysize = paramsize - 10 - TCPA_NONCE_SIZE - TCPA_HASH_SIZE - 1;
  ret = checkhmac1(data, ordinal, nonceodd, 
		   keyauth, TCPA_HASH_SIZE,
		   keysize, TCPA_DATA_OFFSET,
		   0, 0);
  printk("paramsize=%d keysize=%d\n", paramsize, keysize);

  if (ret != 0){
    gfree(data);
    printk("hmac check failed!\n");
    return -1;
  }
  
  memcpy(keydata, data + TCPA_DATA_OFFSET, keysize);
  *keydatalen = keysize;
#if 0
  TPMKeyParms *parms = (TPMKeyParms *)(data + TCPA_DATA_OFFSET);
  TPMStorePubKey *pub = (TPMStorePubKey *)(parms->parms + ntohl(parms->parmSize));
  
  printk("hashing pub key: ");
  sha1(pub->key, ntohl(pub->keyLength), pubkeyhash);
  for (i = 0; i < TCPA_HASH_SIZE; i++)
    printk("%02x ", pubkeyhash[i]);
  printk("\n");
#endif
  gfree(data);
  return 0;
}

/****************************************************************************/
/*                                                                          */
/* Read the TCPA Endorsement public key                                     */
/*                                                                          */
/****************************************************************************/
uint32_t TPM_ReadPubek(PubKeyData * k)
{
    unsigned char read_pubek_fmt[] = "00 c1 T 00 00 00 7c %";
    unsigned char nonce[TCPA_HASH_SIZE];
    uint32_t ret;

    /* check input argument */
    if (k == NULL)
        return -1;
    /* generate random nonce */
    ret = RAND_bytes(nonce, TCPA_NONCE_SIZE);
    //ret = get_random_bytes(nonce, TCPA_NONCE_SIZE);
  

    if (ret != 1)
        return 1;
    /* copy Read PubKey request template to buffer */
    ret = buildbuff(read_pubek_fmt, tcpadata_keys, TCPA_HASH_SIZE, nonce);
    if (ret <= 0)
        return 1;
    ret = TPM_Transmit(tcpadata_keys, "TPM_ReadPubek");
    if (ret)
        return ret;

    PubKeyExtract(tcpadata_keys + TCPA_DATA_OFFSET, k, 0);

    return 0;
}

/****************************************************************************/
/*                                                                          */
/* Create and Wrap a Key                                                    */
/*                                                                          */
/* The arguments are...                                                     */
/*                                                                          */
/* keyhandle is the TCPA_KEY_HANDLE of the parent key of the new key        */
/*           0x40000000 for the SRK                                         */
/* keyauth   is the authorization data (password) for the parent key        */
/* newauth   is the authorization data (password) for the new key           */
/* migauth   is the authorization data (password) for migration of the new  */
/*           key, or NULL if the new key is not migratable                  */
/*           all authorization values must be 20 bytes long                 */
/* keyparms  is a pointer to a keydata structure with parms set for the new */
/*           key                                                            */
/* key       is a pointer to a keydata structure returned filled in         */
/*           with the public key data for the new key                       */
/*                                                                          */
/****************************************************************************/
uint32_t TPM_CreateWrapKey(uint32_t keyhandle,
                           unsigned char *keyauth,
                           unsigned char *newauth,
                           unsigned char *migauth,
                           KeyData *keyparms, 
			   KeyData *key)
{
    unsigned char create_key_fmt[] = "00 c2 T l l % % % l % o %";
    unsigned char *encauth1 = (unsigned char *)galloc(TCPA_HASH_SIZE);
    unsigned char *encauth2 = (unsigned char *)galloc(TCPA_HASH_SIZE);
    unsigned char *xorwork = (unsigned char *)galloc(TCPA_HASH_SIZE * 2);
    unsigned char *xorhash = (unsigned char *)galloc(TCPA_HASH_SIZE);
    unsigned char *nonceodd = (unsigned char *)galloc(TCPA_NONCE_SIZE);
    unsigned char *pubauth = (unsigned char *)galloc(TCPA_HASH_SIZE);
    osapsess *sess = (osapsess *)galloc(sizeof(osapsess));



    uint32_t ret;
    int i;
    unsigned char c;
    uint32_t ordinal;
    uint32_t keyhndl;
    uint16_t keytype;
    int kparmbufsize;
    int datalen;
    

    /* check input arguments */
    if (keyauth == NULL || newauth == NULL || keyparms == NULL || key == NULL){
      printk("0x%p 0x%p 0x%p 0x%p\n", keyauth, newauth, keyparms, key);
      ret = -1;
      goto createwrapkey_free;
    }
    if (keyhandle == 0x40000000)        /* SRK */
        keytype = 0x0004;
    else
        keytype = 0x0001;
    /* generate odd nonce */
    RAND_bytes(nonceodd, TCPA_NONCE_SIZE);
    /* Open OSAP Session */
    ret = TPM_OSAP(sess, keyauth, keytype, keyhandle);
    if (ret){
      goto createwrapkey_free;
    }
    /* calculate encrypted authorization value for new key */
    memcpy(xorwork, sess->ssecret, TCPA_HASH_SIZE);
    memcpy(xorwork + TCPA_HASH_SIZE, sess->enonce, TCPA_HASH_SIZE);
    sha1(xorwork, TCPA_HASH_SIZE * 2, xorhash);
    for (i = 0; i < TCPA_HASH_SIZE; ++i)
        encauth1[i] = xorhash[i] ^ newauth[i];
    /* calculate encrypted authorization value for migration of new key */
    if (migauth != NULL) {
        memcpy(xorwork, sess->ssecret, TCPA_HASH_SIZE);
        memcpy(xorwork + TCPA_HASH_SIZE, nonceodd, TCPA_HASH_SIZE);
        sha1(xorwork, TCPA_HASH_SIZE * 2, xorhash);
        for (i = 0; i < TCPA_HASH_SIZE; ++i)
            encauth2[i] = xorhash[i] ^ migauth[i];
    } else
        memset(encauth2, 0, TCPA_HASH_SIZE);
    /* move Network byte order data to variables for hmac calculation */
    ordinal = htonl(0x1F);
    keyhndl = htonl(keyhandle);
    c = 0;
    /* convert keyparm structure to buffer */
    kparmbufsize = BuildKey(kparmbuf, keyparms);
    if (kparmbufsize < 0) {
	ret = -1;
	goto createwrapkey_terminatehdl;
    }
    /* calculate authorization HMAC value */
    ret = authhmac(pubauth, sess->ssecret, TCPA_HASH_SIZE, sess->enonce,
                   nonceodd, c, 4, &ordinal, TCPA_HASH_SIZE,
                   encauth1, TCPA_HASH_SIZE, encauth2, kparmbufsize,
                   kparmbuf, 0, 0);
    if (ret < 0) {
	ret = -1;
	goto createwrapkey_terminatehdl;
    }
    /* build the request buffer */
    ret = buildbuff(create_key_fmt, tcpadata_keys,
                    ordinal,
                    keyhndl,
                    TCPA_HASH_SIZE, encauth1,
                    TCPA_HASH_SIZE, encauth2,
                    kparmbufsize, kparmbuf,
                    sess->handle,
                    TCPA_NONCE_SIZE, nonceodd, c, TCPA_HASH_SIZE, pubauth);
    if (ret <= 0) {
      printk("TPM_CreateWrapKey: buildbuf failed\n");
      ret = -1;
      goto createwrapkey_terminatehdl;
    }
    /* transmit the request buffer to the TPM device and read the reply */
    ret = TPM_Transmit(tcpadata_keys, "CreateWrapKey");
    if (ret != 0) {
      goto createwrapkey_terminatehdl;
    }
    kparmbufsize = KeySize(tcpadata_keys + TCPA_DATA_OFFSET);
    ret = checkhmac1(tcpadata_keys, ordinal, nonceodd, sess->ssecret,
                     TCPA_HASH_SIZE, kparmbufsize, TCPA_DATA_OFFSET, 0, 0);
    if (ret != 0) {
      printk("TPM_CreateWrapKey: checkhmac1 failed\n");
      goto createwrapkey_terminatehdl;
    }
  
    datalen = ntohl(*(int *)(tcpadata_keys + TCPA_PARAMSIZE_OFFSET));

    /* convert the returned key to a structure */
    KeyExtract(tcpadata_keys + TCPA_DATA_OFFSET, (KeyData *)key);

    ret = 0;

 createwrapkey_terminatehdl:
    TPM_Terminate_Handle(sess->handle);
 createwrapkey_free:
    gfree(encauth1);
    gfree(encauth2);
    gfree(xorwork);
    gfree(xorhash);
    gfree(nonceodd);
    gfree(pubauth);
    gfree(sess);


    return ret;
}

/****************************************************************************/
/*                                                                          */
/* Load a new Key into the TPM                                              */
/*                                                                          */
/* The arguments are...                                                     */
/*                                                                          */
/* keyhandle is the TCPA_KEY_HANDLE of parent key for the new key           */
/*           0x40000000 for the SRK                                         */
/* keyauth   is the authorization data (password) for the parent key        */
/* keyparms  is a pointer to a keydata structure with all data  for the new */
/*           key                                                            */
/* newhandle is a pointer to a 32bit word which will receive the handle     */
/*           of the new key                                                 */
/*                                                                          */
/****************************************************************************/

uint32_t TPM_LoadKey(uint32_t keyhandle, unsigned char *keyauth,
                     KeyData *keyparms, uint32_t *newhandle)
{
    unsigned char load_key_fmt[] = "00 c2 T l l % l % o %";
    unsigned char nonceodd[TCPA_NONCE_SIZE];
    unsigned char evennonce[TCPA_NONCE_SIZE];
    unsigned char pubauth[TCPA_HASH_SIZE];
    uint32_t ret;
    unsigned char c;
    uint32_t ordinal;
    uint32_t keyhndl;
    uint32_t authhandle;
    int kparmbufsize;

    /* check input arguments */
    if (keyauth == NULL || keyparms == NULL || newhandle == NULL)
        return 1;
    /* generate odd nonce */
    RAND_bytes(nonceodd, TCPA_NONCE_SIZE);
    /* Open OIAP Session */
    ret = TPM_OIAP(&authhandle, evennonce);
    if (ret != 0)
        return ret;
    /* move Network byte order data to variables for hmac calculation */
    ordinal = htonl(0x20);
    keyhndl = htonl(keyhandle);
    c = 0;
    /* convert keyparm structure to buffer */
    kparmbufsize = BuildKey(kparmbuf, keyparms);
    if (kparmbufsize < 0) {
        TPM_Terminate_Handle(authhandle);
        return 1;
    }
    /* calculate authorization HMAC value */
    ret = authhmac(pubauth, keyauth, TCPA_HASH_SIZE, evennonce, nonceodd,
                   c, 4, &ordinal, kparmbufsize, kparmbuf, 0, 0);
    if (ret < 0) {
        TPM_Terminate_Handle(authhandle);
        return 1;
    }
    /* build the request buffer */
    ret = buildbuff(load_key_fmt, tcpadata_keys,
                    ordinal,
                    keyhndl,
                    kparmbufsize, kparmbuf,
                    htonl(authhandle),
                    TCPA_NONCE_SIZE, nonceodd, c, TCPA_HASH_SIZE, pubauth);
    if (ret <= 0) {
        TPM_Terminate_Handle(authhandle);
        return 1;
    }
    /* transmit the request buffer to the TPM device and read the reply */
    ret = TPM_Transmit(tcpadata_keys, "LoadKey");
    if (ret != 0) {
        TPM_Terminate_Handle(authhandle);
        return ret;
    }
    TPM_Terminate_Handle(authhandle);
    ret = checkhmac1(tcpadata_keys, ordinal, nonceodd, keyauth,
                     TCPA_HASH_SIZE, 4, TCPA_DATA_OFFSET, 0, 0);
    if (ret != 0)
        return 1;
    *newhandle = ntohl(*(uint32_t *) (tcpadata_keys + TCPA_DATA_OFFSET));
    return 0;
}

uint32_t TPM_LoadKeyBlob(uint32_t keyhandle, unsigned char *keyauth,
                     unsigned char *keyblob, unsigned int keybloblen, uint32_t *newhandle)
{
    unsigned char load_key_fmt[] = "00 c2 T l l % l % o %";
    unsigned char nonceodd[TCPA_NONCE_SIZE];
    unsigned char evennonce[TCPA_NONCE_SIZE];
    unsigned char pubauth[TCPA_HASH_SIZE];
    uint32_t ret;
    unsigned char c;
    uint32_t ordinal;
    uint32_t keyhndl;
    uint32_t authhandle;
    char *tempbuf;

    printk("0x%x 0x%p 0x%p 0x%x\n", keyhandle, keyauth, keyblob, keybloblen);

    /* check input arguments */
    if (keyauth == NULL || keyblob == NULL || newhandle == NULL || keybloblen==0)
        return 1;
    /* generate odd nonce */
    RAND_bytes(nonceodd, TCPA_NONCE_SIZE);
    /* Open OIAP Session */
    ret = TPM_OIAP(&authhandle, evennonce);
    if (ret != 0)
        return ret;
    /* move Network byte order data to variables for hmac calculation */
    ordinal = htonl(TPM_ORD_LoadKey);
    keyhndl = htonl(keyhandle);
    c = 0;

    /* calculate authorization HMAC value */
    ret = authhmac(pubauth, keyauth, TCPA_HASH_SIZE, evennonce, nonceodd,
                   c, 4, &ordinal, keybloblen, keyblob, 0, 0);
    if (ret < 0) {
        TPM_Terminate_Handle(authhandle);
        return 1;
    }

    tempbuf = galloc(TCPA_MAX_BUFF_SIZE);

    /* build the request buffer */
    ret = buildbuff(load_key_fmt, tempbuf,
                    ordinal,
                    keyhndl,
                    keybloblen, keyblob,
                    htonl(authhandle),
                    TCPA_NONCE_SIZE, nonceodd, c, TCPA_HASH_SIZE, pubauth);
    if (ret <= 0) {
        TPM_Terminate_Handle(authhandle);
	gfree(tempbuf);
        return 1;
    }
    printk("about to transmit\n");
    /* transmit the request buffer to the TPM device and read the reply */
    ret = TPM_Transmit(tempbuf, "LoadKey");
    if (ret != 0) {
        TPM_Terminate_Handle(authhandle);
	gfree(tempbuf);
        return ret;
    }
    TPM_Terminate_Handle(authhandle);
    ret = checkhmac1(tempbuf, ordinal, nonceodd, keyauth,
                     TCPA_HASH_SIZE, 4, TCPA_DATA_OFFSET, 0, 0);
    if (ret != 0){
      gfree(tempbuf);
      return 1;
    }
    *newhandle = ntohl(*(uint32_t *) (tempbuf + TCPA_DATA_OFFSET));
    gfree(tempbuf);
    return 0;
}

/****************************************************************************/
/*                                                                          */
/* Evict (delete) a  Key from the TPM                                       */
/*                                                                          */
/* The arguments are...                                                     */
/*                                                                          */
/* keyhandle is the TCPA_KEY_HANDLE of the key to be evicted                */
/*                                                                          */
/****************************************************************************/
uint32_t TPM_EvictKey(uint32_t keyhandle)
{
    unsigned char evict_key_fmt[] = "00 c1 T 00 00 00 22 L";
    uint32_t ret;

    ret = buildbuff(evict_key_fmt, tcpadata_keys, keyhandle);
    ret = TPM_Transmit(tcpadata_keys, "TPM_EvictKey");
    return ret;
}

/****************************************************************************/
/*                                                                          */
/* Create a TCPA_KEY buffer from a keydata structure                        */
/*                                                                          */
/****************************************************************************/
int BuildKey(unsigned char *buffer, KeyData * k)
{
    unsigned char build_key_fmt[] = "% S L o L S S L L L L @ @ @";
    int ret;

    ret = buildbuff(build_key_fmt, buffer,
                    4, k->version,
                    k->keyusage,
                    k->keyflags,
                    k->authdatausage,
                    k->pub.algorithm,
                    k->pub.encscheme,
                    k->pub.sigscheme,
                    12,
                    k->pub.keybitlen,
                    k->pub.numprimes,
                    0,
                    k->pub.pcrinfolen, k->pub.pcrinfo,
                    k->pub.keylength, k->pub.modulus,
                    k->privkeylen, k->encprivkey);
    return ret;
}

int BuildFakeKey(unsigned char *buffer, KeyData * k)
{
  unsigned char build_key_fmt[] = "% S L o L S S L L L L @ @ @";
  int ret;

  ret = buildbuff(build_key_fmt, buffer,
                    4, k->version,
                    k->keyusage,
                    k->keyflags,
                    k->authdatausage,
                    k->pub.algorithm,
                    k->pub.encscheme,
                    k->pub.sigscheme,
                    12,
                    k->pub.keybitlen,
                    k->pub.numprimes,
                    0,
                    0, k->pub.pcrinfo,
                    0, k->pub.modulus,
                    0, k->encprivkey);
    return ret;
}


/****************************************************************************/
/*                                                                          */
/* Walk down the TCPA_Key Structure extracting information                  */
/*                                                                          */
/****************************************************************************/
int KeyExtract(unsigned char *keybuff, KeyData * k)
{
    int offset;
    int pubkeylen;

    /* fill in  keydata structure */
    offset = 0;
    memcpy(k->version, keybuff + offset, sizeof(k->version));
    offset += 4;
    k->keyusage = ntohs(*(uint16_t *) (keybuff + offset));
    offset += 2;
    k->keyflags = ntohl(*(uint32_t *) (keybuff + offset));
    offset += 4;
    k->authdatausage = keybuff[offset];
    offset += 1;
    pubkeylen = PubKeyExtract(keybuff + offset, &(k->pub), 1);
    offset += pubkeylen;
    k->privkeylen = ntohl(*(uint32_t *) (keybuff + offset));
    offset += 4;
    if (k->privkeylen > 0 && k->privkeylen <= 1024)
        memcpy(k->encprivkey, keybuff + offset, k->privkeylen);
    offset += k->privkeylen;
    return offset;
}

/****************************************************************************/
/*                                                                          */
/* Walk down the TCPA_PUBKey Structure extracting information               */
/*                                                                          */
/****************************************************************************/
int PubKeyExtract(unsigned char *keybuff, PubKeyData * k, int pcrpresent)
{
    uint32_t parmsize;
    uint32_t pcrisize;
    int offset;

    offset = 0;
    k->algorithm = ntohl(*(uint32_t *) (keybuff + offset));
    offset += 4;
    k->encscheme = ntohs(*(uint16_t *) (keybuff + offset));
    offset += 2;
    k->sigscheme = ntohs(*(uint16_t *) (keybuff + offset));
    offset += 2;
    parmsize = ntohl(*(uint32_t *) (keybuff + offset));
    offset += 4;
    if (k->algorithm == 0x00000001 && parmsize > 0) {   /* RSA */
        k->keybitlen = ntohl(*(uint32_t *) (keybuff + offset));
        offset += 4;
        k->numprimes = ntohl(*(uint32_t *) (keybuff + offset));
        offset += 4;
        k->expsize = ntohl(*(uint32_t *) (keybuff + offset));
        offset += 4;
    } else {
        offset += parmsize;
    }


    if (k->expsize != 0){
      memcpy(k->exponent, keybuff + offset, k->expsize);
      offset += k->expsize;
    }else {
      // printk_red("Extracting weird exponent!!!!\n");
      /* XXX what is this? */
      k->exponent[0] = 0x01;
      k->exponent[1] = 0x00;
      k->exponent[2] = 0x01;
      k->expsize = 3;
    }


    /* a TCPA_KEY puts pcr info in betweeen the parms and modulus */
    if (pcrpresent) {
        pcrisize = ntohl(*(uint32_t *) (keybuff + offset));
        offset += 4;
        if (pcrisize > 0 && pcrisize <= 256)
            memcpy(k->pcrinfo, keybuff + offset, pcrisize);
        offset += pcrisize;
        k->pcrinfolen = pcrisize;
    }
    k->keylength = ntohl(*(uint32_t *) (keybuff + offset));
    offset += 4;
    if (k->keylength > 0 && k->keylength <= 256)
        memcpy(k->modulus, keybuff + offset, k->keylength);
    offset += k->keylength;
    return offset;
}

/****************************************************************************/
/*                                                                          */
/* Get the size of a TCPA_KEY                                               */
/*                                                                          */
/****************************************************************************/
int KeySize(unsigned char *keybuff)
{
    int offset;
    int privkeylen;

    offset = 0 + 4 + 2 + 4 + 1;
    offset += PubKeySize(keybuff + offset, 1);
    privkeylen = ntohl(*(uint32_t *) (keybuff + offset));
    offset += 4 + privkeylen;
    return offset;
}

/****************************************************************************/
/*                                                                          */
/* Get the size of a TCPA_PUBKEY                                            */
/*                                                                          */
/****************************************************************************/
int PubKeySize(unsigned char *keybuff, int pcrpresent)
{
    uint32_t parmsize;
    uint32_t pcrisize;
    uint32_t keylength;

    int offset;

    offset = 0 + 4 + 2 + 2;
    parmsize = ntohl(*(uint32_t *) (keybuff + offset));
    offset += 4;
    offset += parmsize;
    if (pcrpresent) {
        pcrisize = ntohl(*(uint32_t *) (keybuff + offset));
        offset += 4;
        offset += pcrisize;
    }
    keylength = ntohl(*(uint32_t *) (keybuff + offset));
    offset += 4;
    offset += keylength;
    return offset;
}

void create_pubkey(PubKeyData *new, unsigned char *modulus, short es, short ss){
  new->algorithm = TCPA_ALG_RSA;
  new->encscheme = es;
  new->sigscheme = ss;
  new->keybitlen = RSA_MODULUS_BIT_SIZE;   
  new->numprimes = RSA_NUMPRIMES;       
  new->expsize = RSA_EXPONENT_BYTE_SIZE;         
  memcpy(new->exponent, RSA_DEFAULT_EXPONENT_ARRAY, RSA_EXPONENT_BYTE_SIZE);
  memcpy(new->modulus, modulus, RSA_MODULUS_BYTE_SIZE);
  new->keylength = RSA_MODULUS_BYTE_SIZE;
  new->pcrinfolen = 0;      
}


#if 0
/****************************************************************************/
/*                                                                          */
/* Convert a TCPA public key to an OpenSSL RSA public key                   */
/*                                                                          */
/****************************************************************************/
RSA *convpubkey(PubKeyData * k)
{
    RSA *rsa;
    BIGNUM *mod;
    BIGNUM *exp;

    /* create the necessary structures */
    rsa = RSA_new();
    mod = BN_new();
    exp = BN_new();
    if (rsa == NULL || mod == NULL || exp == NULL)
        return NULL;
    /* convert the raw public key values to BIGNUMS */
    BN_bin2bn(k->modulus, k->keylength, mod);
    BN_bin2bn(k->exponent, k->expsize, exp);
    /* set up the RSA public key structure */
    rsa->n = mod;
    rsa->e = exp;
    return rsa;
}
#endif
