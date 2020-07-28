/****************************************************************************/
/*                                                                          */
/*                           SEAL/UNSEAL routines                           */
/*                                                                          */
/* This file is copyright 2003 IBM. See "License" for details               */
/****************************************************************************/
#include <nexus/defs.h>
#include <libtcpa/tcpa.h>
#include <libtcpa/pcrs.h>
#include <libtcpa/hmac.h>
#include <libtcpa/oiaposap.h>
#include <libtcpa/buildbuff.h>

unsigned char tcpadata_seal[TCPA_MAX_BUFF_SIZE];

/****************************************************************************/
/*                                                                          */
/* Seal a data object with caller Specified PCR infro                       */
/*                                                                          */
/* The arguments are...                                                     */
/*                                                                          */
/* keyhandle is the TCPA_KEY_HANDLE of the key used to seal the data        */
/*           0x40000000 for the SRK                                         */
/* pcrinfo   is a pointer to a TCPA_PCR_INFO structure containing           */
/*           a bit map of the PCR's to seal the data to, and a              */
/*           pair of TCPA_COMPOSITE_HASH values for the PCR's               */
/* pcrinfosize is the length of the pcrinfo structure                       */
/* keyauth   is the authorization data (password) for the key               */
/* dataauth  is the authorization data (password) for the data being sealed */
/*           both authorization values must be 20 bytes long ?              */
/* data      is a pointer to the data to be sealed                          */
/* datalen   is the length of the data to be sealed (max 256?)              */
/* blob      is a pointer to an area to received the sealed blob            */
/*           it should be long enough to receive the encrypted data         */
/*           which is 256 bytes, plus some overhead. 512 total recommended? */
/* bloblen   is a pointer to an integer which will receive the length       */
/*           of the sealed blob                                             */
/*                                                                          */
/****************************************************************************/
uint32_t TPM_Seal(uint32_t keyhandle,
                  unsigned char *pcrinfo, uint32_t pcrinfosize,
                  unsigned char *keyauth,
                  unsigned char *dataauth,
                  unsigned char *data, unsigned int datalen,
                  unsigned char *blob, unsigned int *bloblen)
{
    unsigned char seal_fmt[] = "00 C2 T l l % @ @ l % o %";
    unsigned char encauth[TCPA_HASH_SIZE];
    unsigned char pubauth[TCPA_HASH_SIZE];
    unsigned char xorwork[TCPA_HASH_SIZE * 2];
    unsigned char xorhash[TCPA_HASH_SIZE];
    unsigned char nonceodd[TCPA_NONCE_SIZE];
    osapsess sess;
    uint32_t ret;
    int i;
    unsigned char c;
    uint32_t ordinal;
    uint32_t pcrsize;
    uint32_t datsize;
    uint32_t keyhndl;
    uint16_t keytype;
    int sealinfosize;
    int encdatasize;
    int storedsize;

    /* check input arguments */
    if(datalen > 256)
      return 1;
    if (keyauth == NULL || dataauth == NULL || data == NULL
        || blob == NULL)
        return 1;
    if (pcrinfosize != 0 && pcrinfo == NULL)
        return 1;
    if (keyhandle == 0x40000000)
        keytype = 0x0004;
    else
        keytype = 0x0001;
    /* Open OSAP Session */
    ret = TPM_OSAP(&sess, keyauth, keytype, keyhandle);
    if (ret)
        return ret;
    /* calculate encrypted authorization value */
    memcpy(xorwork, sess.ssecret, TCPA_HASH_SIZE);
    memcpy(xorwork + TCPA_HASH_SIZE, sess.enonce, TCPA_HASH_SIZE);
    sha1(xorwork, TCPA_HASH_SIZE * 2, xorhash);
    RAND_bytes(nonceodd, TCPA_NONCE_SIZE);
    /* move Network byte order data to variables for hmac calculation */
    ordinal = htonl(0x17);
    datsize = htonl(datalen);
    keyhndl = htonl(keyhandle);
    pcrsize = htonl(pcrinfosize);
    c = 0;
    /* encrypt data authorization key */
    for (i = 0; i < TCPA_HASH_SIZE; ++i)
        encauth[i] = xorhash[i] ^ dataauth[i];
    /* calculate authorization HMAC value */
    if (pcrinfosize == 0) {
        /* no pcr info specified */
        ret = authhmac(pubauth, sess.ssecret, TCPA_HASH_SIZE,
                       sess.enonce, nonceodd, c, 4,
                       &ordinal, TCPA_HASH_SIZE, encauth, 4,
                       &pcrsize, 4, &datsize, datalen, data, 0, 0);
    } else {
        /* pcr info specified */
        ret = authhmac(pubauth, sess.ssecret, TCPA_HASH_SIZE,
                       sess.enonce, nonceodd, c, 4,
                       &ordinal, TCPA_HASH_SIZE, encauth, 4,
                       &pcrsize, pcrinfosize, pcrinfo, 4,
                       &datsize, datalen, data, 0, 0);
    }
    if (ret < 0) {
        TPM_Terminate_Handle(sess.handle);
        return 1;
    }
    /* build the request buffer */
    ret = buildbuff(seal_fmt, tcpadata_seal,
                    ordinal,
                    keyhndl,
                    TCPA_HASH_SIZE, encauth,
                    pcrinfosize, pcrinfo,
                    datalen, data,
                    sess.handle,
                    TCPA_NONCE_SIZE, nonceodd, c, TCPA_HASH_SIZE, pubauth);
    if (ret <= 0) {
        TPM_Terminate_Handle(sess.handle);
        return 1;
    }
    /* transmit the request buffer to the TPM device and read the reply */
    ret = TPM_Transmit(tcpadata_seal, "Seal");
    if (ret != 0) {
        TPM_Terminate_Handle(sess.handle);
        return ret;
    }
    /* calculate the size of the returned Blob */
    sealinfosize = ntohl(*(uint32_t *) (tcpadata_seal + TCPA_DATA_OFFSET + 4));
    encdatasize = ntohl(*(uint32_t *) (tcpadata_seal +
                                       TCPA_DATA_OFFSET + 4 + 4 +
                                       sealinfosize));
    storedsize = 4 + 4 + sealinfosize + 4 + encdatasize;
    /* check the HMAC in the response */
    ret = checkhmac1(tcpadata_seal, ordinal, nonceodd, sess.ssecret,
                     TCPA_HASH_SIZE, storedsize, TCPA_DATA_OFFSET, 0, 0);
    if (ret != 0) {
        TPM_Terminate_Handle(sess.handle);
        return 1;
    }
    /* copy the returned blob to caller */
    if(*bloblen < storedsize){
      TPM_Terminate_Handle(sess.handle);
      return 1;
    }
    memcpy(blob, tcpadata_seal + TCPA_DATA_OFFSET, storedsize);
    *bloblen = storedsize;
    TPM_Terminate_Handle(sess.handle);
    return 0;
}

/****************************************************************************/
/*                                                                          */
/* Seal a data object with current PCR information                          */
/*                                                                          */
/* The arguments are...                                                     */
/*                                                                          */
/* keyhandle is the TCPA_KEY_HANDLE of the key used to seal the data        */
/*           0x40000000 for the SRK                                         */
/* pcrmap    is a 32 bit integer containing a bit map of the PCR register   */
/*           numbers to be used when sealing. e.g 0x0000001 specifies       */
/*           PCR 0. 0x00000003 specifies PCR's 0 and 1, etc.                */
/* keyauth   is the authorization data (password) for the key               */
/* dataauth  is the authorization data (password) for the data being sealed */
/*           both authorization values must be 20 bytes long ?              */
/* data      is a pointer to the data to be sealed                          */
/* datalen   is the length of the data to be sealed (max 256?)              */
/* blob      is a pointer to an area to received the sealed blob            */
/*           it should be long enough to receive the encrypted data         */
/*           which is 256 bytes, plus some overhead. 512 total recommended? */
/* bloblen   is a pointer to an integer which will receive the length       */
/*           of the sealed blob                                             */
/*                                                                          */
/****************************************************************************/
uint32_t TPM_Seal_CurrPCR(uint32_t keyhandle, uint32_t pcrmap,
                         unsigned char *keyauth,
                         unsigned char *dataauth,
                         unsigned char *data, unsigned int datalen,
                         unsigned char *blob, unsigned int *bloblen)
{
    uint32_t ret;
    unsigned char pcrinfo[MAXPCRINFOLEN];
    uint32_t pcrlen;

    ret = GenPCRInfo(pcrmap, pcrinfo, &pcrlen);
    return TPM_Seal(keyhandle, pcrinfo, pcrlen,
                    keyauth, dataauth, data, datalen, blob, bloblen);
}

/****************************************************************************/
/*                                                                          */
/* Unseal a data object                                                     */
/*                                                                          */
/* The arguments are...                                                     */
/*                                                                          */
/* keyhandle is the TCPA_KEY_HANDLE of the key used to seal the data        */
/*           0x40000000 for the SRK                                         */
/* keyauth   is the authorization data (password) for the key               */
/* dataauth  is the authorization data (password) for the data being sealed */
/*           both authorization values must be 20 bytes long ?              */
/* blob      is a pointer to an area to containing the sealed blob          */
/* bloblen   is the length of the sealed blob                               */
/* rawdata   is a pointer to an area to receive the unsealed data (max 256?)*/
/* datalen   is a pointer to a int to receive the length of the data        */
/*                                                                          */
/****************************************************************************/
#define RETURN_UNSEAL(x)			\
  do{						\
    if((x) != 0)				\
      printk_red("%s:%s:%d\n",__FILE__, __FUNCTION__, __LINE__);	\
    return (x);							\
  }while(0)

uint32_t TPM_Unseal(uint32_t keyhandle,
                    unsigned char *keyauth,
                    unsigned char *dataauth,
                    unsigned char *blob, unsigned int bloblen,
                    unsigned char *rawdata, unsigned int *datalen)
{
    unsigned char unseal_fmt[] = "00 C3 T l l % L % o % L % o %";
    unsigned char nonceodd[TCPA_NONCE_SIZE];
    unsigned char enonce1[TCPA_NONCE_SIZE];
    unsigned char enonce2[TCPA_NONCE_SIZE];
    unsigned char authdata1[TCPA_HASH_SIZE];
    unsigned char authdata2[TCPA_HASH_SIZE];
    uint32_t ret;
    unsigned char c;
    uint32_t ordinal;
    uint32_t keyhndl;
    uint32_t authhandle1;
    uint32_t authhandle2;

    /* check input arguments */
    if (keyauth == NULL || dataauth == NULL || rawdata == NULL
        || blob == NULL)
      RETURN_UNSEAL(1);
    /* open TWO OIAP sessions, one for the Key and one for the Data */
    ret = TPM_OIAP(&authhandle1, enonce1);
    if (ret)
      RETURN_UNSEAL(ret);
    ret = TPM_OIAP(&authhandle2, enonce2);
    if (ret)
      RETURN_UNSEAL(ret);
    /* move data to Network byte order variables for HMAC calculation */
    ordinal = htonl(0x18);
    keyhndl = htonl(keyhandle);
    /* generate odd nonce */
    RAND_bytes(nonceodd, TCPA_NONCE_SIZE);
    c = 0;
    /* calculate KEY authorization HMAC value */
    ret = authhmac(authdata1, keyauth, TCPA_HASH_SIZE, enonce1, nonceodd,
                   c, 4, &ordinal, bloblen, blob, 0, 0);
    if (ret < 0) {
        TPM_Terminate_Handle(authhandle1);
        TPM_Terminate_Handle(authhandle2);
        RETURN_UNSEAL(1);
    }
    /* calculate DATA authorization HMAC value */
    ret = authhmac(authdata2, dataauth, TCPA_HASH_SIZE, enonce2,
                   nonceodd, c, 4, &ordinal, bloblen, blob, 0, 0);
    if (ret < 0) {
        TPM_Terminate_Handle(authhandle1);
        TPM_Terminate_Handle(authhandle2);
        RETURN_UNSEAL(-1);
    }
    /* build the request buffer */
    ret = buildbuff(unseal_fmt, tcpadata_seal,
                    ordinal,
                    keyhndl,
                    bloblen, blob,
                    authhandle1,
                    TCPA_NONCE_SIZE, nonceodd,
                    c,
                    TCPA_HASH_SIZE, authdata1,
                    authhandle2,
                    TCPA_NONCE_SIZE, nonceodd,
                    c, TCPA_HASH_SIZE, authdata2);

    if (ret <= 0) {
        TPM_Terminate_Handle(authhandle1);
        TPM_Terminate_Handle(authhandle2);
        RETURN_UNSEAL(1);
    }
    /* transmit the request buffer to the TPM device and read the reply */
    ret = TPM_Transmit(tcpadata_seal, "Unseal");
    if (ret != 0) {
        TPM_Terminate_Handle(authhandle1);
        TPM_Terminate_Handle(authhandle2);
        RETURN_UNSEAL(ret);
    }
    /* XXX TODO !!!!!!!!!!!!!!!!
       check HMAC in response
     */
    /* copy decrypted data back to caller */
    int decryptsize = ntohl(*(uint32_t *) (tcpadata_seal + TCPA_DATA_OFFSET));
    if(decryptsize > *datalen){
      TPM_Terminate_Handle(authhandle1);
      TPM_Terminate_Handle(authhandle2);
      RETURN_UNSEAL(1);
    }
    *datalen = decryptsize;
    memcpy(rawdata, tcpadata_seal + TCPA_DATA_OFFSET + 4, *datalen);
    TPM_Terminate_Handle(authhandle1);
    TPM_Terminate_Handle(authhandle2);
    RETURN_UNSEAL(0);
}



int TPM_UnBind(unsigned int keyhandle,
	       unsigned char *keyauth,
	       unsigned char *blob, unsigned int bloblen,
	       unsigned char *out, unsigned int *outlen){
  int dbg = 0;

  if(keyauth == NULL)
    return -1;
  if(blob == NULL)
    return -1;
  if(bloblen <= 0)
    return -1;

  int ret;
  unsigned int authhandle;
  unsigned char enonce[TCPA_NONCE_SIZE];
  unsigned char nonceodd[TCPA_NONCE_SIZE];
  unsigned char authdata[TCPA_HASH_SIZE];

  ret = TPM_OIAP(&authhandle, enonce);
  if(ret != 0){
    printk_red("couldn't oiap(ret = %d)%s:%s:%d\n",
	       ret, __FILE__, __FUNCTION__, __LINE__); 
    return -1;
  }

  /* move data to network byte order for HMAC calculation */
  unsigned int nw_ordinal = htonl(TPM_ORD_UnBind);
  unsigned int nw_bloblen = htonl(bloblen);

  /* generate odd nonce */
  RAND_bytes(nonceodd, TCPA_NONCE_SIZE);
  unsigned char c = 0;  /* continue session = 0 */

  ret = authhmac(authdata, keyauth, TCPA_HASH_SIZE, enonce, nonceodd, c,
		sizeof(unsigned int), &nw_ordinal,
		sizeof(unsigned int), &nw_bloblen,
		bloblen, blob,
		0, 0);
  if(ret < 0){
    printk_red("couldn't calculate authmac(ret = %d)%s:%s:%d\n",
	       ret, __FILE__, __FUNCTION__, __LINE__); 
    TPM_Terminate_Handle(authhandle);
    return -1;
  }

  if(dbg)
    printk_red("building UnBind request bloblen=%d\n", bloblen);
  /* build request */
  unsigned char unbind_fmt[] = "00 C2 T l L @ L % o %";
  unsigned char *reqbuf = (unsigned char *)galloc(TCPA_MAX_BUFF_SIZE);
  ret = buildbuff(unbind_fmt, reqbuf,
		  nw_ordinal,
		  keyhandle,
		  bloblen, blob,
		  authhandle,
		  TCPA_NONCE_SIZE, nonceodd,
		  c,
		  TCPA_HASH_SIZE, authdata);

  if(ret < 0){
    printk_red("couldn't build buff (ret = %d)%s:%s:%d\n",
	       ret, __FILE__, __FUNCTION__, __LINE__); 
    TPM_Terminate_Handle(authhandle);
    gfree(reqbuf);
    return -1;
  }
  
  
  /* transmit request */
  ret = TPM_Transmit(reqbuf, "UnBind");
  if(ret != 0){
    printk_red("couldn't unbind (ret = %d)%s:%s:%d\n",
	       ret, __FILE__, __FUNCTION__, __LINE__); 
    TPM_Terminate_Handle(authhandle);
    gfree(reqbuf);
    return -1;
  }

  int outdatalen = ntohl(*(unsigned int *)(reqbuf + TCPA_DATA_OFFSET));

  /* check hmac on response */
  ret = checkhmac1(reqbuf, TPM_ORD_UnBind, nonceodd, keyauth, TCPA_HASH_SIZE,
		   sizeof(unsigned int), TCPA_DATA_OFFSET,
		   outdatalen, TCPA_DATA_OFFSET + sizeof(unsigned int),
		   0,0);
  if(ret < 0){
    printk_red("couldn't check hmac (ret = %d)%s:%s:%d\n",
	       ret, __FILE__, __FUNCTION__, __LINE__); 
    TPM_Terminate_Handle(authhandle);
    gfree(reqbuf);
    return -1;
  }
	     

  if(dbg)
    printk_red("outlen (%d < %d)%s:%s:%d\n",
	       *outlen, outdatalen, __FILE__, __FUNCTION__, __LINE__); 
  if(*outlen < outdatalen){
    printk_red("not enough outlen (%d < %d)%s:%s:%d\n",
	       *outlen, outdatalen, __FILE__, __FUNCTION__, __LINE__); 
    TPM_Terminate_Handle(authhandle);
    gfree(reqbuf);
    return -1;
  }
    
  *outlen = outdatalen;
  memcpy(out, reqbuf + TCPA_DATA_OFFSET + sizeof(unsigned int), outdatalen);

  gfree(reqbuf);
  return 0;
}
