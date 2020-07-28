#include <nexus/defs.h>
#include <libtcpa/tcpa.h>
#include <libtcpa/hmac.h>
#include <libtcpa/buildbuff.h>
//#include "oiaposap.h"

char *ownerpass = "egs";
char *srkpass = "egs";

typedef struct Session Session;
struct Session{
  unsigned char nonceEven[TCPA_NONCE_SIZE];
  unsigned char nonceEvenOSAP[TCPA_NONCE_SIZE];
  unsigned char authdata[TCPA_HASH_SIZE];
  unsigned char ssecret[TCPA_HASH_SIZE];
  unsigned int handle;
};

Session sess[2];

void dumpSession(Session *s){
  int i;
  printk("Session: handle = %d\n", s->handle);
  printk("nonceEven:     ");
  for (i = 0; i < TCPA_HASH_SIZE; i++)
    printk("%02x ", s->nonceEven[i]);
  printk("\n");
  printk("nonceEvenOSAP: ");
  for (i = 0; i < TCPA_HASH_SIZE; i++)
    printk("%02x ", s->nonceEvenOSAP[i]);
  printk("\n");
  printk("authdata:      ");
  for (i = 0; i < TCPA_HASH_SIZE; i++)
    printk("%02x ", s->authdata[i]);
  printk("\n");
  printk("ssecret:       ");
  for (i = 0; i < TCPA_HASH_SIZE; i++)
    printk("%02x ", s->ssecret[i]);
  printk("\n");
}

int makeIdentity(unsigned char *blob, int size){
  unsigned int ordinal = ntohl(*((unsigned int *)&blob[6]));
  unsigned char *identityAuth = &blob[10];
  unsigned char *labelPrivCADigest = &blob[30];

  unsigned char *kparmbuf = &blob[50];
  
  unsigned int srkAuthHandle = ntohl(*((unsigned int *)&blob[size - 90]));
  unsigned char *srknonceOdd = &blob[size - 86];
  unsigned char sc = blob[size - 66];  
  unsigned char *srkAuth = &blob[size - 65];

  unsigned int authHandle = ntohl(*((unsigned int *)&blob[size - 45]));
  unsigned char *nonceOdd = &blob[size - 41];
  unsigned char oc = blob[size - 21];  
  unsigned char *ownerAuth = &blob[size - 20];

  unsigned char authresult[TCPA_HASH_SIZE];
  KeyData idKey;
  unsigned int osess, srksess;
  int ret, i;

  int kparmbufsize = size - 50 - 90;
  KeyExtract(kparmbuf, &idKey);
  
  if (idKey.pub.algorithm == 0x00000001){ // algorithm is RSA key
    if (idKey.pub.keybitlen != 2048){
      printk("invalid key not implemented\n");
      return -1;
    }
  }
  
  /* verify owner session */
  if (sess[0].handle == authHandle)
    osess = 0;
  else if(sess[1].handle == authHandle)
    osess = 1;
  else{ 
    printk("owner keyhandle invalid\n");
    buildbuff("STL", blob, TPM_TAG_RSP_AUTH2_COMMAND, TPM_INVALID_KEYHANDLE);
    return 0;
  }
  
  dumpSession(&sess[osess]);
  printk("nonceOdd:      ");
  for (i = 0; i < TCPA_HASH_SIZE; i++)
    printk("%02x ", nonceOdd[i]);
  printk("\n");
  
  ordinal = htonl(ordinal);
  printk("oc = %02x ordinal = 0x%x\n", oc, ordinal); 
  printk("identityAuth:  ");
  for (i = 0; i < TCPA_HASH_SIZE; i++)
    printk("%02x ", identityAuth[i]);
  printk("\n");
  printk("CADigest:      ");
  for (i = 0; i < TCPA_HASH_SIZE; i++)
    printk("%02x ", labelPrivCADigest[i]);
  printk("\n");
  printk("kparmbuf:      ");
  for (i = 0; i < kparmbufsize; i++)
    printk("%02x ", kparmbuf[i]);
  printk("\n");
  ret = authhmac(authresult, sess[osess].ssecret, TCPA_HASH_SIZE, 
		 sess[osess].nonceEven, nonceOdd, oc, 
		 4, &ordinal, 
		 TCPA_HASH_SIZE, identityAuth,
		 TCPA_HASH_SIZE, labelPrivCADigest,
		 kparmbufsize, kparmbuf,
		 0,0);

  printk("authresult:    ");
  for (i = 0; i < TCPA_HASH_SIZE; i++)
    printk("%02x ", authresult[i]);
  printk("\n");
  printk("ownerauth:     ");
  for (i = 0; i < TCPA_HASH_SIZE; i++)
    printk("%02x ", ownerAuth[i]);
  printk("\n");
  
  for(i = 0; i < TCPA_HASH_SIZE; i++){
    if (authresult[i] != ownerAuth[i]){
      printk("owner auth failed\n");
      buildbuff("STL", blob, TPM_TAG_RSP_AUTH2_COMMAND, TPM_AUTHFAIL);
      return 0;
    }
  }

  /* verify srk session */
  if (sess[0].handle == srkAuthHandle)
    srksess = 0;
  else if(sess[1].handle == srkAuthHandle)
    srksess = 1;
  else{  
    printk("srk keyhandle invalid\n");
    buildbuff("STL", blob, TPM_TAG_RSP_AUTH2_COMMAND, TPM_INVALID_KEYHANDLE);
    return 0;
  }
  
  ret = authhmac(authresult, sess[srksess].ssecret, TCPA_HASH_SIZE, 
		 sess[srksess].nonceEven, srknonceOdd, sc, 
		 4, &ordinal, 
		 TCPA_HASH_SIZE, identityAuth,
		 TCPA_HASH_SIZE, labelPrivCADigest,
		 kparmbufsize, kparmbuf,
		 0,0);
  
  for(i = 0; i < TCPA_HASH_SIZE; i++){
    if (authresult[i] != srkAuth[i]){
      printk("srk auth failed\n");
      buildbuff("STL", blob, TPM_TAG_RSP_AUTH2_COMMAND, TPM_AUTHFAIL);
      return 0;
    }
  }

  printk("both sessions ok\n");
  return -1;

}

#define OSAPDEBUG 0
int osap(unsigned char *blob, int size){
  /* incoming operands */
  unsigned short entityType = ntohs(*((unsigned short*)&blob[10]));
  //unsigned int entityValue = ntohl(*((unsigned int*)&blob[12]));
  unsigned char *nonceOddOSAP = &blob[16];

  int currentsess = 0;
  int ret = 0;
  int i = 0;
  
  if (sess[0].handle == 0){
    RAND_bytes((unsigned char *)&sess[0].handle, 4);
    currentsess = 0;
  }else if (sess[1].handle == 0){
    RAND_bytes((unsigned char *)&sess[1].handle, 4);
    currentsess = 1;
  }else{
    ret = TPM_SIZE; //not enough handles
    printk("out of space for OSAP: not implemented\n");
    return -1;
  }
    
  switch (entityType){
  case TPM_ET_KEYHANDLE:
    printk("OSAP keyhandle unimplemented\n");
    return -1;
    break;
  case TPM_ET_OWNER:
    sha1(ownerpass, strlen(ownerpass), sess[currentsess].authdata);
    printk("owner starting OSAP session\n");
    break;
  case TPM_ET_SRK:
    sha1(srkpass, strlen(srkpass), sess[currentsess].authdata);
    printk("srk starting OSAP session\n");
    break;
  case TPM_ET_COUNTER:
    printk("OSAP counter unimplemented\n");
    return -1;
    break;
  case TPM_ET_NV:
    printk("OSAP nv unimplemented\n");
    return -1;
    break;
  default:
    printk("unimplemented (and unknown) OSAP entityType %d\n", entityType);
    return -1;
    break;
  };
  
  RAND_bytes(sess[currentsess].nonceEven, TCPA_NONCE_SIZE);
  RAND_bytes(sess[currentsess].nonceEvenOSAP, TCPA_NONCE_SIZE);

  rawhmac(sess[currentsess].ssecret, sess[currentsess].authdata, TCPA_HASH_SIZE, 
	  TCPA_NONCE_SIZE, sess[currentsess].nonceEvenOSAP,
	  TCPA_NONCE_SIZE, nonceOddOSAP, 
	  0,0);

  if (OSAPDEBUG){
    printk("Session ssecret:\n");
    for (i = 0; i < TCPA_HASH_SIZE; i++)
      printk("%02x ", sess[currentsess].ssecret[i]);
    printk("\nSession authdata:\n");
    for (i = 0; i < TCPA_HASH_SIZE; i++)
      printk("%02x ", sess[currentsess].authdata[i]);
    printk("\n handle = %d, currentsess = %d\n", sess[currentsess].handle, currentsess);
  }

  buildbuff("STLL%%", blob, 
	    TPM_TAG_RSP_COMMAND, ret, sess[currentsess].handle, 
	    TCPA_NONCE_SIZE, sess[currentsess].nonceEven,
	    TCPA_NONCE_SIZE, sess[currentsess].nonceEvenOSAP);
  
  return 0;
}

uint32_t TPM_Transmit_Emu(unsigned char *blob, char *msg){
  uint32_t size, ret;

  size = ntohl(*(uint32_t *) & blob[TCPA_PARAMSIZE_OFFSET]);

  switch(ntohl(*(unsigned int*)&blob[TCPA_ORDINAL_OFFSET])){
  case TPM_ORD_MakeIdentity:
    ret = makeIdentity(blob, size);
    break;
  case TPM_ORD_OSAP:
    ret = osap(blob, size);
    break;
  default:
    printk("TPM Function %d not emulated\n", ntohl(*(unsigned int*)&blob[TCPA_ORDINAL_OFFSET]));
    return -1;
  };

  ret = ntohl(*(uint32_t *) & blob[TCPA_RETURN_OFFSET]);
  if (ret)
    printk("TPM_transmit_Emu %s failed with error %d\n", msg, ret);
  return (ret);
}

uint32_t TPM_OSAP_Emu(osapsess *sess, unsigned char *key, uint16_t etype,
                  uint32_t evalue)
{
    unsigned char osap_open_fmt[] = "00 C1 T 00 00 00 0B S L %";
    unsigned char tcpadata[TCPA_MAX_BUFF_SIZE];
    uint32_t ret;

    if (key == NULL)
        return 1;
    RAND_bytes(sess->ononceOSAP, TCPA_NONCE_SIZE);
    ret = buildbuff(osap_open_fmt, tcpadata, etype, evalue,
                    TCPA_NONCE_SIZE, sess->ononceOSAP);
    if (ret <= 0)
        return 1;
    ret = TPM_Transmit_Emu(tcpadata, "OSAP");
    if (ret)
        return ret;
    sess->handle = ntohl(*(uint32_t *) (tcpadata + TCPA_DATA_OFFSET));
    memcpy(sess->enonce, &(tcpadata[TCPA_DATA_OFFSET + 4]),
           TCPA_NONCE_SIZE);
    memcpy(sess->enonceOSAP,
           &(tcpadata[TCPA_DATA_OFFSET + 4 + TCPA_NONCE_SIZE]),
           TCPA_NONCE_SIZE);
    ret = rawhmac(sess->ssecret, key, TCPA_HASH_SIZE, TCPA_NONCE_SIZE,
                  sess->enonceOSAP, TCPA_NONCE_SIZE, sess->ononceOSAP, 0,
                  0);
    return ret;
}

