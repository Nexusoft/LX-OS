#include <nexus/defs.h>
#include <libtcpa/tcpa.h>
#include <libtcpa/keys.h>
#include <libtcpa/hmac.h>
#include <libtcpa/oiaposap.h>
#include <libtcpa/buildbuff.h>

void dumpTPMCertifyInfoTail(TPMCertifyInfoTail* t){
  int i;
  
  printk("pubKeyDig:   ");
  for (i = 0; i < TCPA_HASH_SIZE; i++)
    printk("0x%02x ", t->pubKeyDigest[i]);
  printk("\n");
  printk("data:        ");
  for (i = 0; i < TCPA_HASH_SIZE; i++)
    printk("0x%02x ", t->data[i]);
  printk("\n");
  printk("parentPCR:   0x%02x\n", t->parentPCRStatus);
  printk("PCRInfoSz:   0x%08x\n", ntohl(t->PCRInfoSize));
}
void dumpTPMKeyParms(TPMKeyParms *k){
  int i;

  printk("  algorID:   0x%08x\n", ntohl(k->algorithmID));
  printk("  encScheme: 0x%04x\n", ntohs(k->encScheme));
  printk("  encScheme: 0x%04x\n", ntohs(k->sigScheme));
  printk("  parmSize:  0x%08x\n", ntohl(k->parmSize));
  printk("  parms:     ");
  for(i = 0; i < ntohl(k->parmSize); i++)
    printk("0x%02x ", k->parms[i]);
  printk("\n");
  dumpTPMCertifyInfoTail((TPMCertifyInfoTail *)&k->parms[i]);
}
void dumpTPMStructVer(TPMStructVer *s){
  printk("version:   0x%02x ", s->major); 
  printk("0x%02x ", s->minor); 
  printk("0x%02x ", s->revMajor); 
  printk("0x%02x\n", s->revMinor);
} 
void dumpTPMCertifyInfoHdr(TPMCertifyInfoHdr *chdr){
  dumpTPMStructVer(&chdr->version);
  printk("keyUsage:  0x%04x\n", ntohs(chdr->keyUsage)); 
  printk("keyFlags:  0x%08x\n", ntohl(chdr->keyFlags)); 
  printk("authDataU: 0x%02x\n", chdr->authDataUsage); 
  dumpTPMKeyParms((TPMKeyParms *)chdr->algorithmParms);
}

uint32_t TPM_CertifyKey(unsigned int keyhandle, unsigned char *keyauth,
			unsigned int certhandle, unsigned char *certauth,
			unsigned char *antiReplay,
			unsigned char *sig, unsigned int *siglen,
			unsigned char *ckresult, unsigned int *cklen){
  unsigned char certifyKey_fmt[] = "00 C3 T l l l % l % o % l % o %";
  unsigned char c;

  uint32_t ordinal;
  uint32_t ret;
  unsigned int keyhdle, certhdle;

  unsigned char nonceodd[TCPA_NONCE_SIZE];
  unsigned int authhandle1;
  unsigned int authhandle2;
  unsigned char evennonce1[TCPA_NONCE_SIZE];
  unsigned char evennonce2[TCPA_NONCE_SIZE];
  unsigned char auth1[TCPA_HASH_SIZE];
  unsigned char auth2[TCPA_HASH_SIZE];

  unsigned char *certifyKeyData;

  TPMCertifyInfoHdr *chdr;
  TPMCertifyInfoTail *ctail;
  TPMKeyParms *keyparms;
  unsigned int csize;
  unsigned int *odsizeptr;    
  unsigned int odsize;
  unsigned char *outdata;

  unsigned char temphash[TCPA_HASH_SIZE];
  int i;

  /* check input arguments */
  if (keyhandle == 0 || keyauth == NULL ||
      certhandle == 0 || certauth == NULL || 
      antiReplay == NULL)
    return -1;

  ret = TPM_OIAP(&authhandle1, evennonce1);
  if(ret) return ret;
  ret = TPM_OIAP(&authhandle2, evennonce2);
  if(ret) {
    TPM_Terminate_Handle(authhandle1);
    return ret;
  }

  ordinal = htonl(TPM_ORD_CertifyKey);
  keyhdle = htonl(keyhandle);
  certhdle = htonl(certhandle);
    
  /* generate odd nonce */
  RAND_bytes(nonceodd, TCPA_NONCE_SIZE);
  c = 0;

  /* calculate authorization HMAC value */
  ret = authhmac(auth1, certauth, TCPA_HASH_SIZE, evennonce1, nonceodd, c, 
		 4, &ordinal, 
		 TCPA_NONCE_SIZE, antiReplay, 
		 0, 0);
  if (ret < 0) {
    TPM_Terminate_Handle(authhandle1);
    TPM_Terminate_Handle(authhandle2);
    return -1;
  }
  ret = authhmac(auth2, keyauth, TCPA_HASH_SIZE, evennonce2, nonceodd, c, 
		 4, &ordinal, 
		 TCPA_NONCE_SIZE, antiReplay, 
		 0, 0);
  if (ret < 0) {
    TPM_Terminate_Handle(authhandle1);
    TPM_Terminate_Handle(authhandle2);
    return -1;
  }

  certifyKeyData = galloc(TCPA_MAX_BUFF_SIZE);
  /* build the request buffer */
  /* s T l l l % l % o % l % o % */
  ret = buildbuff(certifyKey_fmt, certifyKeyData,
		  /* TPM_TAG_RQU_AUTH2_COMMAND, */
		  ordinal,
		  certhdle,
		  keyhdle,
		  TCPA_NONCE_SIZE, antiReplay,
		  htonl(authhandle1),
		  TCPA_NONCE_SIZE, nonceodd, 
		  c, 
		  TCPA_HASH_SIZE, auth1,
		  htonl(authhandle2),
		  TCPA_NONCE_SIZE, nonceodd, 
		  c, 
		  TCPA_HASH_SIZE, auth2);

  if (ret <= 0) {
    gfree(certifyKeyData);
    TPM_Terminate_Handle(authhandle1);
    TPM_Terminate_Handle(authhandle2);
    return -1;
  }

  /* transmit the request buffer to the TPM device and read the reply */
  printk("transmitting the certifyKey request 0x%p\n", certifyKeyData);

  ret = TPM_Transmit(certifyKeyData, "CertifyKey");
  
  TPM_Terminate_Handle(authhandle1);
  TPM_Terminate_Handle(authhandle2);
  
  if (ret != 0) {
    gfree(certifyKeyData);
    return ret;
  }

  chdr = (TPMCertifyInfoHdr *)(certifyKeyData + TCPA_DATA_OFFSET);
  keyparms = (TPMKeyParms *) chdr->algorithmParms;
  ctail = (TPMCertifyInfoTail *)(keyparms->parms + ntohl(keyparms->parmSize));
  csize = sizeof(TPMCertifyInfoHdr) 
    + sizeof(TPMKeyParms) 
    + ntohl(keyparms->parmSize) 
    + sizeof(TPMCertifyInfoTail) 
    + ntohl(ctail->PCRInfoSize);
  
  odsizeptr = (unsigned int *)(certifyKeyData + TCPA_DATA_OFFSET + csize);
  odsize = ntohl(*odsizeptr);
  outdata = (unsigned char*)odsizeptr + sizeof(unsigned int);

#if 0
  //dumpTPMCertifyInfoHdr(chdr);
  printk("sizeof(HDR)=%d sizeof(KeyParms)=%d sizeof(TAIL)=%d parmSize=%d\n", sizeof(TPMCertifyInfoHdr), sizeof(TPMKeyParms), sizeof(TPMCertifyInfoTail), ntohl(keyparms->parmSize));
  printk("parmsize=%d csize=%d, odsize=%d\n", ntohl(keyparms->parmSize), csize, odsize);
#endif

  sha1(outdata, odsize, temphash);
  printk("nskkeycertsig %d: ", odsize);
  for (i = 0; i < odsize; i++)
    printk("%02x ", outdata[i]);
  printk("\n");
  printk("nskkeycertsig hash: ");
  for (i = 0; i < 20; i ++)
    printk("%02x ", temphash[i]);
  printk("\n");


  /* check the HMACs in the response */
  ret = checkhmac2(certifyKeyData, ordinal, nonceodd, 
		   certauth, TCPA_HASH_SIZE,
		   keyauth, TCPA_HASH_SIZE, 
		   csize, TCPA_DATA_OFFSET,
		   4, TCPA_DATA_OFFSET + csize,
		   odsize, TCPA_DATA_OFFSET + csize + 4, 
		   0, 0);
  if (ret != 0){
    gfree(certifyKeyData);
    printk("hmac check failed!\n");
    return -1;
  }
  memcpy(sig, outdata, odsize);
  *siglen = odsize;
    
  memcpy(ckresult, certifyKeyData + TCPA_DATA_OFFSET, csize);
  *cklen = csize;

  gfree(certifyKeyData);
  return 0;
}
