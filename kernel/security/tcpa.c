/****************************************************************************/
/*                                                                          */
/*                      TCPA simple Demonstration Program                   */
/*                                                                          */
/*  This file is copyright 2003 IBM. See "License" for details              */
/****************************************************************************/

#include <nexus/defs.h>
#include <libtcpa/tcpa.h>

#include <nexus/thread.h>
#include <nexus/thread-inline.h>
#include <nexus/kernelfs.h>

// TCPA version of by TPM chip. Discovered after driver load. Passed to userspace.
unsigned char tcpa_version_buf_g[TCPA_VERSION_SIZE] = {0,0,0,0};

/* return -1 on error, 0 otherwise */
int tcpademo(void)
{
    PubKeyData pubek;
    unsigned int slots;
    unsigned int pcrs;
    unsigned short num;
    unsigned int keys[256];
    unsigned char pcr_data[20];
    int major, minor, version, rev, i, j;

    if (TPM_Reset())
        return -1;
    printk("TPM successfully reset\n");

    if (TPM_GetCapability_Version(&major,&minor,&version,&rev))
      return -1;
    printk("TPM version %d.%d.%d.%d\n",major,minor,version,rev);

    if(TPM_GetCapability_Pcrs(&pcrs))
      return -1;
    printk("%d PCR registers are available\n",pcrs);
    for(i=0;i<pcrs;i++){ 
      if(TPM_PcrRead((unsigned int)i,pcr_data))
	  return -1;      
	printk("PCR-%02d: ",i);
        for(j=0;j<20;j++)
            printk("%02X ",pcr_data[j]);
        printk("\n");
    }

    if(TPM_GetCapability_Slots(&slots))
      return -1;
    printk("%d Key slots are available\n",slots);

    if(TPM_GetCapability_Key_Handle(&num, keys))
      return -1;
    if(num==0)
        printk("No keys are loaded\n");
    else 
        for(i=0;i<num;i++)
            printk("Key Handle %04X loaded\n",keys[i]);

    if (TPM_ReadPubek(&pubek))
      return -1;

    printk("algorithm 0x%x\n", pubek.algorithm);
    printk("encscheme 0x%x\n", pubek.encscheme);
    printk("sigscheme 0x%x\n", pubek.sigscheme);
    printk("keybitlen %d\n", pubek.keybitlen);
    printk("numprimes %d\n", pubek.numprimes);
    printk("expsize %d\n", pubek.expsize);
    printk("keylength%d\n", pubek.keylength);

    return 0;
}

int signfile(unsigned int handle, char *password, char *databuff, int datalen) {
    unsigned int ret;
    unsigned int parhandle;         /* handle of parent key */
    unsigned char passhash[20]; /* hash of parent key password */
    unsigned char datahash[20]; /* hash of data file */
    unsigned char sig[4096];    /* resulting signature */
    unsigned int siglen;        /* signature length */
    int i;

    parhandle = handle;
    sha1(password, strlen(password), passhash);
    sha1(databuff, datalen, datahash);

#if 0
    for(i = 0; i < 20; ++i)
      printk(" 0x%x", passhash[i]);
#endif
 
    ret = TPM_Sign(parhandle,   /* Key Handle */
                   passhash,    /* key Password */
                   datahash, sizeof(datahash),  /* data to be signed, length */
                   sig, &siglen       /* buffer to receive sig, length */
		   );
    if (ret != 0) {
        printk("Error %d from TPM_Sign\n", ret);
	return ret;
    }

    for(i = 0; i < siglen; ++i) {
      printk(" 0x%x", sig[i]);
      if((i % 8) == 0)
	printk("\n");
    }
    printk("\n");

    return 0;
}


typedef struct Key Key;
struct Key{
  Key *next;
  Key *prev;
  char keyname[256];
  KeyData q;  
};

Key *keyqueuehead = NULL;
Key *keyqueuetail = NULL;

/*
 * Return Key with name keyname.
 */
Key *find_key(char *keyname){
  Key *ptr;
  
  for(ptr = keyqueuehead; ptr != NULL; ptr = ptr->next){
    if (strncmp(keyname, ptr->keyname, strlen(keyname)) == 0)
      return ptr;
  }
  return NULL;
}

int createaik(char *identitylabel, int idlabelsize, PubKeyData *cakey, 
	      KeyData *idkey, unsigned char *idbind, int *idbindlen)
{
  assert(identitylabel != NULL);
  assert(cakey != NULL);
  assert(idkey != NULL);

  printk("creating aik %s\n", identitylabel);

  idkey->version[0] = 1;           /* Version 1.1.0.6 */
  idkey->version[1] = 1;
  idkey->version[2] = 0;
  idkey->version[3] = 6;
  idkey->keyusage = 0x0012;        /* key Usage - 0x0010 = signing */
                              /*             0x0011 = storage */
                              /*             0x0012 = identity */
  idkey->keyflags = 0;             /* key flags - none */
  idkey->authdatausage = 0x01;     /* key requires authorization (password) */
  idkey->privkeylen = 0;           /* no private key specified here */
  idkey->pub.algorithm = 0x00000001;       /* key algorithm 1 = RSA */
  idkey->pub.encscheme = 0x0001;   /* encryption scheme 1 = NONE - signing key */
  /*                   3   rsastorage */
  idkey->pub.sigscheme = 0x0002;   /*  2 == signature scheme RSA/SHA1  */
  /* 1 == none, (storage key) */
  idkey->pub.keybitlen = 2048;     /* RSA modulus size 2048 bits */
  idkey->pub.numprimes = 2;        /* required */
  idkey->pub.expsize = 0;          /* RSA exponent - default 0x010001 */
  idkey->pub.keylength = 0;        /* key not specified here */
  idkey->pub.pcrinfolen = 0;       /* no PCR's used at this time */

  //memset(&k,0xf0, sizeof(k));
 
  unsigned char *opass = get_opass();
  unsigned char *spass = get_spass();

  int ret = TPM_MakeIdentity(spass, spass, opass,
			     identitylabel, idlabelsize, 
			     cakey, idkey, 
			     idbind, idbindlen);
  if(ret != 0){
    printk_red("MAKEID ret == %d\n", ret);
    ret = -1;
  }
  return ret;

}

/*
 * create a storage key and add it to the keyqueue
 * <parent key handle in hex> 
 * <parent key password> 
 * <new key name> 
 * <new key password>
 */

int createKey(unsigned int parenthandle, char *parentpw, char *keypw, 
		     KeyData *keybuf, unsigned int pcrmap, short signing)
{
  unsigned char *pcrinfo = (unsigned char *)galloc(MAXPCRINFOLEN);
    unsigned int ret;      /* handle of parent key */
    unsigned int pcrlen;
    KeyData k;                    /* keydata structure for input key parms */
    
    // Get the PCRs to bind the key to
    ret = GenPCRInfo(pcrmap, pcrinfo, &pcrlen);

    switch(signing){
    case TPM_KEY_SIGNING:
      k.pub.encscheme = 0x0001;   /* encryption scheme 1 = NONE - signing key */
      k.pub.sigscheme = 0x0002;   /*  2 == signature scheme RSA/SHA1  */
      break;
    case TPM_KEY_STORAGE:
    case TPM_KEY_BIND:
      k.pub.encscheme = 0x0003;   /* encryption scheme 3   rsastorage */
      k.pub.sigscheme = 0x0001;   /* 1 == none, (storage key) */
      break;
    default:
      gfree(pcrinfo);
      printk_red("error.. creating key of wrong type? %d\n", signing);
      return -1;
    };
    k.keyusage = signing;        
    printk_red("encscheme: 0x%04x sigscheme: 0x%04x keyusage: 0x%04x\n", 
	       k.pub.encscheme, k.pub.sigscheme, k.keyusage);


    k.version[0] = 1;           /* Version 1.1.0.6 */
    k.version[1] = 1;
    k.version[2] = 0;
    k.version[3] = 6;

    k.keyflags = 0;             /* key flags - none */
    k.authdatausage = 0x01;     /* key requires authorization (password) */
    k.privkeylen = 0;           /* no private key specified here */
    k.pub.algorithm = 0x00000001;       /* key algorithm 1 = RSA */
    k.pub.keybitlen = 2048;     /* RSA modulus size 2048 bits */
    k.pub.numprimes = 2;        /* required */
    k.pub.expsize = 0;          /* RSA exponent - default 0x010001 */
    k.pub.keylength = 0;        /* key not specified here */
    k.pub.pcrinfolen = pcrlen; 
    memcpy(k.pub.pcrinfo, pcrinfo, pcrlen); 

    printk_red("creating wrap key");
    ret = TPM_CreateWrapKey(parenthandle, parentpw, keypw, NULL, 
			    &k, keybuf);
    printk_red("created wrap key ret=%d", ret);
    if (ret != 0) {
      printk("Error %d from TPM_CreateKey\n", ret);
      gfree(pcrinfo);
      return ret;
    }

    gfree(pcrinfo);
    return ret;
}

/*
 * Load a key into TPM with name keyname
 * parenthandle - <parent key handle in hex> 
 * parentpw     - <parent key password> 
 * keyname      - <key name>
 */
int loadkey(unsigned int parenthandle, char *parentpw, char *keyname)
{
    unsigned int ret;      /* handle of parent key */
    unsigned char hashpass1[20];  /* hash of parent key password */
    unsigned int newhandle;       /* generated key handle */
    Key *key;

    sha1(parentpw, strlen(parentpw), hashpass1);

    /* load in struct q from keyname */
    key = find_key(keyname);
    ret = TPM_LoadKey(parenthandle, hashpass1, &key->q, &newhandle);
    if (ret != 0) {
      printk("Error %d from TPM_LoadKey\n", ret);
      return -1;
    }
    printk("loaded key %s, returned handle %04x\n", keyname, newhandle);
    return newhandle;
}


/* 
 * Evict loaded key with handle handle (hex) from TPM.
 * Returns -1 on error, 0 on success.
 */
int evictkey(unsigned int handle)
{
    unsigned int ret;
    printk("evicting key %x\n", handle);

    ret = TPM_EvictKey(handle);
    if (ret != 0) {
      printk("Error %d from TPM_EvictKey\n", ret);
      return ret;
    }
    return ret;
}

/* 
 * Evict all loaded keys from TPM.
 * Returns -1 on error, 0 on success.
 */
int evictall(void)
{
    unsigned short num;
    unsigned int keys[256];
    int i;

    if(TPM_GetCapability_Key_Handle(&num, keys))
      return -1;
    
    for(i=0;i<num;i++){
      printk("Key Handle %04X being evicted\n",keys[i]);
      TPM_EvictKey(keys[i]);
    }

    return 0;
}


/*
 * Seal a Data buffer
 * <key handle in hex> 
 * <key password> 
 * <data password> 
 * <input buffer> 
 * <output buffer>
 */
int sealbuffer(unsigned int keyhandle, char *keypw, char *datapw, 
	       char *databuff, unsigned int datalen, char *out){
    unsigned int ret;
    unsigned int bloblen;        /* blob length */

    if (datalen > 256) {
        printk("Data file too large for seal operation\n");
	return 0;
    }

    ret = TPM_Seal_CurrPCR(keyhandle,         /* KEY Entity Value */
                          0x0000007D,        /* specify PCR registers 0-6 */
                          keypw,         /* Key Password */
                          datapw,         /* new blob password */
                          databuff, datalen, /* data to be sealed, length */
                          out, &bloblen    /* buffer to receive result, len */
			  );
    if (ret != 0) {
        printk("Error %d from TPM_Seal\n", ret);
        return 0;
    }
    
    return bloblen;
}

/*
 * Unseal a Data buffer.
 */
int unsealbuffer(unsigned int keyhandle, char *keypw, char *datapw, 
	       unsigned char *blob, unsigned int bloblen, unsigned char *out){
    unsigned int ret;
    unsigned int datalen;           /* blob length */

    ret = TPM_Unseal(keyhandle,          /* KEY Entity Value */
                     keypw,          /* Key Password */
                     datapw,          /* blob password */
                     blob, bloblen,      /* encrypted blob, blob length */
                     out, &datalen  /* buffer for decrypted data, len */
		     );
    if (ret != 0) {
        printk("Error %d from TPM_Unseal\n", ret);
	return 0;
    }

    return datalen;
}

int tcpa_discover_version(void) {
  int major, minor, version, rev;
  if (TPM_GetCapability_Version(&major,&minor,&version,&rev)) {
    tcpa_version_buf_g[0] = tcpa_version_buf_g[1] =
      tcpa_version_buf_g[2] = tcpa_version_buf_g[3] = 0;
    printk("TPM version unavailable\n");
    return -1;
  }
  tcpa_version_buf_g[0] = (major & 0xff);
  tcpa_version_buf_g[1] = (minor & 0xff);
  tcpa_version_buf_g[2] = (version & 0xff);
  tcpa_version_buf_g[3] = (rev & 0xff);

  char tmp[80];
  sprintf(tmp, "%d.%d.%d.%d", TCPA_VERSION[0], TCPA_VERSION[1], TCPA_VERSION[2], TCPA_VERSION[3]);
  printk("TPM version %s\n", tmp);

  KernelFS_setenv("tcpa_version", tmp);

  return 0;
}
