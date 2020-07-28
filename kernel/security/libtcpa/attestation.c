  
#include <nexus/defs.h>
#include <libtcpa/tcpa.h>
#include <libtcpa/hmac.h>
#include <libtcpa/oiaposap.h>
#include <libtcpa/buildbuff.h>
#include <libtcpa/identity_private.h>
#include <libtcpa/keys.h>

//#include <nexus/attchain.h> // XXX for opass
//#include <nexus/thread-inline.h>
#include <nexus/util.h> // for PRINT_HASH (debugging)

/* TPM_MakeIdentity
 *
 * TPM_TAG tag = TPM_TAG_RQU_AUTH2_COMMAND = 0x00C3 
 * TPM_COMMAND_CODE ordinal = TPM_ORD_MakeIdentity = 0x00000079
 * 
 */

//#define EMU  /* Use Emulator */
#undef EMU /* Don't use Emulator */

#ifdef EMU
#define OSAP TPM_OSAP_Emu
#define TRANSMIT TPM_Transmit_Emu
#else
#define OSAP TPM_OSAP
#define TRANSMIT TPM_Transmit
#endif

int TPM_MakeIdentity(unsigned char *passhash, 
		     unsigned char *srkpasshash, 
		     unsigned char *ownpasshash, 
		     char *identitylabel, int idlabelsize, 
		     PubKeyData *cakey,
		     KeyData *keyparms,
		     unsigned char *idbind, int *idbindlen){
  /* the kernel stack should not get too big with temp structures for the TPM */
#define MAKEIDENTITY_FREE do{			\
    gfree(srksess);				\
    gfree(ownsess);				\
    gfree(xorwork);				\
    gfree(xorhash);				\
    gfree(srkresult);				\
    gfree(ownresult);				\
    gfree(ownencauth);				\
    gfree(labelPrivCADigest);			\
    gfree(ownnonceodd);				\
    gfree(srknonceodd);				\
    gfree(chosenid);				\
    gfree(makeIDBuffer);			\
    gfree(kparmbuf2);				\
    gfree(id);					\
  }while(0)
  int dbg = 0;

  if(0){
    printk_red("idpubkeydata before creation:\n");
    PRINT_BYTES((unsigned char *)&keyparms->pub, sizeof(PubKeyData));
    printk_red("\n");
  }

  int i;
  unsigned char makeidentity_fmt[] = "00 c3 T l % % % l % o %  l % o %";
  uint32_t ordinal = htonl(TPM_ORD_MakeIdentity);
  int bufsize = idlabelsize + TCPA_PUBKEY_SIZE;
  uint32_t ret;
  int kparmbufsize;

  int c = 0;

  
  if(dbg)
    printk("MakeIdentity\n");

  /* check input arguments */
  if (passhash == NULL || identitylabel  == NULL || srkpasshash == NULL || ownpasshash == NULL)
    return -1;
   
  /* allocate all structures needed for MakeID */
  osapsess *srksess = (osapsess *)galloc(sizeof(osapsess));		
  osapsess *ownsess = (osapsess *)galloc(sizeof(osapsess));		
  unsigned char *xorwork = (unsigned char *)galloc(TCPA_HASH_SIZE * 2); 
  unsigned char *xorhash = (unsigned char *)galloc(TCPA_HASH_SIZE);	
  unsigned char *srkresult = (unsigned char *)galloc(TCPA_HASH_SIZE);	
  unsigned char *ownresult = (unsigned char *)galloc(TCPA_HASH_SIZE);	
  unsigned char *ownencauth = (unsigned char *)galloc(TCPA_HASH_SIZE); 
  unsigned char *labelPrivCADigest = (unsigned char *)galloc(TCPA_HASH_SIZE); 
  unsigned char *ownnonceodd = (unsigned char *)galloc(TCPA_NONCE_SIZE); 
  unsigned char *srknonceodd = (unsigned char *)galloc(TCPA_NONCE_SIZE); 
  unsigned char *chosenid = (unsigned char *)galloc(bufsize);
  unsigned char *makeIDBuffer = (unsigned char *)galloc(TCPA_MAX_BUFF_SIZE);
  unsigned char *kparmbuf2 = (unsigned char *)galloc(TCPA_MAX_BUFF_SIZE);
  IdentityContentsData *id = (IdentityContentsData *)galloc(sizeof(IdentityContentsData));


  /* coalesce the info for the call to the TPM */
  /* XXX why isn't this done earlier */
  fillIdentityContentsData(id, identitylabel, idlabelsize, cakey, NULL);
  BuildChosenIdHash(labelPrivCADigest, id);

  /* build the keybuffer ready for the tpm */
  kparmbufsize = BuildKey(kparmbuf2, keyparms);
  if (kparmbufsize < 0) {
    printk("kparmbufsize < 0\n");
    MAKEIDENTITY_FREE;
    return 1;
  }

  /* Owner authorization */
  ret = OSAP(ownsess, ownpasshash, 0x0002, 0x40000001); 
  if (ret){
    MAKEIDENTITY_FREE;
    return ret;
  }

  /* calculate encrypted authorization value */
  memcpy(xorwork, ownsess->ssecret, TCPA_HASH_SIZE);  
  memcpy(xorwork + TCPA_HASH_SIZE, ownsess->enonce, TCPA_HASH_SIZE);
  sha1(xorwork, TCPA_HASH_SIZE * 2, xorhash);
  RAND_bytes(ownnonceodd, TCPA_NONCE_SIZE);
  /* encrypt data authorization key */
  for (i = 0; i < TCPA_HASH_SIZE; ++i)
    ownencauth[i] = xorhash[i] ^ passhash[i];

  if(dbg){
    printk("Owner Session: handle = %d\n", ownsess->handle);
    printk("nonceEven:     ");
    for (i = 0; i < TCPA_HASH_SIZE; i++)
      printk("%02x ", ownsess->enonce[i]);
    printk("\n");
    printk("ssecret:       ");
    for (i = 0; i < TCPA_HASH_SIZE; i++)
      printk("%02x ", ownsess->ssecret[i]);
    printk("\n");
    printk("ononce:        ");
    for (i = 0; i < TCPA_HASH_SIZE; i++)
      printk("%02x ", ownnonceodd[i]);
    printk("\n");

    printk("oc = %02x ordinal = 0x%x\n", c, ordinal); 
    printk("identityAuth:  ");
    for (i = 0; i < TCPA_HASH_SIZE; i++)
      printk("%02x ", ownencauth[i]);
    printk("\n");
    printk("CADigest:      ");
    for (i = 0; i < TCPA_HASH_SIZE; i++)
      printk("%02x ", labelPrivCADigest[i]);
    printk("\n");
    printk("kparmbuf:      ");
    for (i = 0; i < kparmbufsize; i++)
      printk("%02x ", kparmbuf2[i]);
    printk("\n");
  }

  ret = authhmac(ownresult, ownsess->ssecret, TCPA_HASH_SIZE, 
		 ownsess->enonce, ownnonceodd, c, 
		 4, &ordinal, 
		 TCPA_HASH_SIZE, ownencauth,
		 TCPA_HASH_SIZE, labelPrivCADigest,
		 kparmbufsize, kparmbuf2,
		 0,0);



  if(dbg){
    printk("ownresult:     ");
    for (i = 0; i < TCPA_HASH_SIZE; i++)
      printk("%02x ", ownresult[i]);
    printk("\n");
  }

  if (ret < 0) {
    printk("own authmac < 0\n");
    TPM_Terminate_Handle(ownsess->handle);
    MAKEIDENTITY_FREE;
    return 1;
  }


  /* SRK authorization */
  //ret = TPM_OIAP(&srkhandle, enonce); 
  ret = OSAP(srksess, srkpasshash, 0x0004, 0x40000000); 
  if (ret){
    MAKEIDENTITY_FREE;
    return ret;
  }
  RAND_bytes(srknonceodd, TCPA_NONCE_SIZE);

#if 0
  /* Using OIAP for srk authorization */
  ret = authhmac(srkresult, srkpasshash, TCPA_HASH_SIZE, 
		 enonce, srknonceodd, c, 
		 4, &ordinal, 
		 TCPA_HASH_SIZE, ownencauth,
		 TCPA_HASH_SIZE, labelPrivCADigest,
		 kparmbufsize, kparmbuf2,
		 0,0);
#endif

  ret = authhmac(srkresult, srksess->ssecret, TCPA_HASH_SIZE, 
		 srksess->enonce, srknonceodd, c, 
		 4, &ordinal, 
		 TCPA_HASH_SIZE, ownencauth,
		 TCPA_HASH_SIZE, labelPrivCADigest,
		 kparmbufsize, kparmbuf2,
		 0,0);

  if (ret < 0) {
    printk("srk authmac < 0\n");
    TPM_Terminate_Handle(srksess->handle);
    TPM_Terminate_Handle(ownsess->handle);
    MAKEIDENTITY_FREE;
    return 1;
  }

  /* build the request buffer */
  //00 c3 T l % % % l % o % l % o %
  ret = buildbuff(makeidentity_fmt, makeIDBuffer,
		  ordinal,
		  TCPA_HASH_SIZE, ownencauth,
		  TCPA_HASH_SIZE, labelPrivCADigest,
		  kparmbufsize, kparmbuf2,
		  htonl(srksess->handle), 
		  TCPA_NONCE_SIZE, srknonceodd, 
		  c,
		  TCPA_HASH_SIZE, srkresult,
		  htonl(ownsess->handle), 
		  TCPA_NONCE_SIZE, ownnonceodd,
		  c, 
		  TCPA_HASH_SIZE, ownresult);

  if (ret <= 0) {
    printk("buildbuff <= 0\n");
    TPM_Terminate_Handle(srksess->handle);
    TPM_Terminate_Handle(ownsess->handle);
    MAKEIDENTITY_FREE;
    return 1;
  }


  /* transmit the request buffer to the TPM device and read the reply */
  ret = TRANSMIT(makeIDBuffer, "MakeIdentity");
  if (ret != 0) {
    printk("TPM_Transmit fail\n");
    TPM_Terminate_Handle(srksess->handle);
    TPM_Terminate_Handle(ownsess->handle);
    MAKEIDENTITY_FREE;
    return ret;
  }

  if(dbg)
    printk("transmit successful\n");

  //XXX checkhmac ret = checkhmac1(makeIDBuffer, ordinal, );

  int keysize = KeyExtract(makeIDBuffer + TCPA_DATA_OFFSET, keyparms);

  if(0){
    printk_red("idkeytcpakey:");
    PRINT_BYTES(makeIDBuffer + TCPA_DATA_OFFSET, keysize);
    printk_red("\n");
  }

  int idsize = ntohl(*(int *)(makeIDBuffer + TCPA_DATA_OFFSET + keysize));
  if(*idbindlen < idsize){
    printk_red("not enough room for idbinding %d < %d\n", *idbindlen, idsize);
    MAKEIDENTITY_FREE;
    return 1;
  }
  if(dbg){
    printk_red("idsize = %d, hash: ", idsize);
    unsigned char tmphash[TCPA_HASH_SIZE];
    sha1(makeIDBuffer + TCPA_DATA_OFFSET + keysize + sizeof(int), idsize, tmphash);
    PRINT_HASH(tmphash);
  }
  *idbindlen = idsize;
  memcpy(idbind, makeIDBuffer + TCPA_DATA_OFFSET + keysize + sizeof(int), idsize);

  TPM_Terminate_Handle(srksess->handle);
  TPM_Terminate_Handle(ownsess->handle);

  MAKEIDENTITY_FREE;
  return 0;
}


void calculate_encauth(unsigned char *ownencauth, osapsess *ownsess, 
		       unsigned char *opass){
  unsigned char xorwork[TCPA_HASH_SIZE * 2];
  unsigned char xorhash[TCPA_HASH_SIZE];
  int i;

  memcpy(xorwork, ownsess->ssecret, TCPA_HASH_SIZE);  
  memcpy(xorwork + TCPA_HASH_SIZE, ownsess->enonce, TCPA_HASH_SIZE);
  sha1(xorwork, TCPA_HASH_SIZE * 2, xorhash);

  for (i = 0; i < TCPA_HASH_SIZE; ++i)
    ownencauth[i] = xorhash[i] ^ opass[i];
}


/* note: OSAP does not seem to work for this command */
int TPM_ActivateIdentity(//SymKeyData *symkey, 
			 KeyData *idkey, 
			 unsigned char *blob, int bloblen,
			 unsigned char *clear, int *clearlen){
#define ACTIVATEIDENTITY_FREE do{		\
    gfree(ownnonceodd);				\
    gfree(ownhmac);				\
    gfree(ownnonceeven);			\
    gfree(idnonceodd);				\
    gfree(idhmac);				\
    gfree(idnonceeven);				\
    gfree(buffer);				\
  }while(0)

  int dbg = 0;
  unsigned char *opass = get_opass();
  unsigned char *spass = get_spass();

  unsigned int idhandle;
  int ret;

  assert(idkey != NULL);

  if(dbg)
    printk_red("activate identity bloblen = %d idkey = 0x%p\n", bloblen, idkey);

  unsigned char *ownnonceodd = (unsigned char *)galloc(TCPA_NONCE_SIZE);
  unsigned char *ownhmac = (unsigned char *)galloc(TCPA_HASH_SIZE);
  unsigned char *ownnonceeven = (unsigned char *)galloc(TCPA_NONCE_SIZE);
  unsigned char *idnonceodd = (unsigned char *)galloc(TCPA_NONCE_SIZE);
  unsigned char *idhmac = (unsigned char *)galloc(TCPA_HASH_SIZE);
  unsigned char *idnonceeven = (unsigned char *)galloc(TCPA_NONCE_SIZE);
  unsigned char *buffer = (unsigned char *)galloc(TCPA_MAX_BUFF_SIZE);

  if(dbg){
    unsigned char tmphash[TCPA_HASH_SIZE];
    sha1(blob, bloblen, tmphash);
    printk_red("hash of asymblob: ");
    int i;
    for(i = 0; i < TCPA_HASH_SIZE; i++)
      printk_red("%02x", tmphash[i]);
    printk_red("\n");
  }

  /* load the identity key into the tpm.  SRK is the parent key */
  ret = TPM_LoadKey(TPM_KH_SRK, spass, idkey, &idhandle);
  if(ret != 0){
    printk("could not load id key (%d)!!!", ret);
    ACTIVATEIDENTITY_FREE;
    return -1;
  }


  if(dbg)
    printk_red("loaded tpm key handle = 0x%x idkey = 0x%p\n", idhandle, idkey);


  int cont = 0;
  unsigned int hmac_ordinal = htonl(TPM_ORD_ActivateIdentity);
  unsigned int hmac_bloblen = htonl(bloblen);

  /* Owner authorization */
  unsigned int ownauthhdl;
  RAND_bytes(ownnonceodd, TCPA_NONCE_SIZE);
  ret = TPM_OIAP(&ownauthhdl, ownnonceeven);
  if(ret != 0){
    printk("could not do oiap (%d)\n!!!", ret);
    ACTIVATEIDENTITY_FREE;
    return -1;
  }

  ret = authhmac(ownhmac, opass, TCPA_HASH_SIZE, 
		 ownnonceeven, ownnonceodd, cont,
		 sizeof(int), &hmac_ordinal,
		 sizeof(int), &hmac_bloblen,
		 bloblen, blob,
		 0,0);

  if(ret != 0){
    printk("could not get owner hmac (%d)\n!!!", ret);
    ACTIVATEIDENTITY_FREE;
    return -1;
  }

  //unsigned char ownencauth[TCPA_HASH_SIZE];
  //calculate_encauth(ownencauth, &ownsess, opass);

  /* idkey authorization */
  unsigned int idauthhdl;
  RAND_bytes(idnonceodd, TCPA_NONCE_SIZE);
  ret = TPM_OIAP(&idauthhdl, idnonceeven);
  if(ret != 0){
    printk("could not do oiap (%d)\n!!!", ret);
    ACTIVATEIDENTITY_FREE;
    return -1;
  }

  ret = authhmac(idhmac, spass, TCPA_HASH_SIZE, 
		 idnonceeven, idnonceodd, cont,
		 sizeof(int), &hmac_ordinal,
		 sizeof(int), &hmac_bloblen,
		 bloblen, blob,
		 0,0);

  if(ret != 0){
    printk("could not get id hmac (%d)!!!\n", ret);
    ACTIVATEIDENTITY_FREE;
    return -1;
  }
  
  
  //unsigned char activateid_fmt[] = "S T L L @ L % o % L % o %";
  unsigned char activateid_fmt[] = "00 c3 T L L @ L % o % L % o %";
  memset(buffer, 0, TCPA_MAX_BUFF_SIZE);

  ret = buildbuff(activateid_fmt, buffer,
		  //TPM_TAG_RQU_AUTH2_COMMAND,
		  TPM_ORD_ActivateIdentity,
		  idhandle,
		  bloblen, blob,
		  idauthhdl, //idsess.handle, 
		  TCPA_NONCE_SIZE, idnonceodd,
		  cont,
		  TCPA_HASH_SIZE, idhmac, 
		  ownauthhdl, //ownsess.handle,
		  TCPA_NONCE_SIZE, ownnonceodd,
		  cont,
		  TCPA_HASH_SIZE, ownhmac);

  if(ret <= 0){
    printk("build buff failed (%d)!!!\n", ret);
    ACTIVATEIDENTITY_FREE;
    return -1;
  }

  if(dbg)
    printk_red("going to transmit\n");
  ret = TRANSMIT(buffer, "ActivateIdentity");

  if(dbg)
    printk_red("transmitted\n");

  if(ret != 0){
    printk_red("TPM_Transmit failed (%d)!!!\n", ret);
    ACTIVATEIDENTITY_FREE;
    return -1;
  }

  // XXX check hmac

  SymKeyData *symkey = (SymKeyData *)galloc(sizeof(SymKeyData));

  int newlen = ExtractSymKey(symkey, buffer + TCPA_DATA_OFFSET);

  if(dbg)
    printk_red("newlen = %d symkeylen=%d\n", newlen, sizeof(SymKeyData));

  gfree(symkey);

  if(*clearlen < newlen){
    ACTIVATEIDENTITY_FREE;
    return -1;
  }

  if(dbg)
    printk_red("extract symkey done\n");

  *clearlen = newlen;
  memcpy(clear, buffer + TCPA_DATA_OFFSET, newlen);

  ACTIVATEIDENTITY_FREE;
  return 0;
}
