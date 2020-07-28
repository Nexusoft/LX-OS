#include <crypto/aes.h>
#include <libtcpa/tcpa.h>

#include <nexus/defs.h>
#include <nexus/synch.h>
#include <nexus/synch-inline.h>
#include <nexus/syscalls.h>
#include <nexus/tftp.h>
#include <nexus/policy.h>
#include <nexus/encblocks.h>
#include <nexus/hashtree.h>
#include <nexus/vdir.h>
#include <nexus/elf.h>

#define PCRMASK 0x0000007d
#define TAKE_OWNER_PROCESS "ownership.app"

unsigned char spass[TCPA_HASH_SIZE];

#define DBGVDIR (0)
int dbg = 0; /* override dbg to print debug info for only one function. */
#define VPRINT(x...) if(dbg||DBGVDIR)printk_red(x)

#define ERRPRINT(x...) printk_red(x);
#define VERROR(x...) do{ERRPRINT("VDIR: ")ERRPRINT(x)}while(0)

/* XXX The max of 32 can't be increased without increasing the size of
 * the bitmap array... 
 */
#define MAXVDIRS (32)
#define MAXVKEYS (32)
#define MAX_NAME_LEN (256)
#define MAX_POLICYLEN (4)
#define MAX_BLOB_LEN (1024) /* the size of an encrypted vkey */

#define BLOCKSIZE (183)

#define dirname(x) ((x == 0)?"VDIR.0":"VDIR.1")
#define NUMDIRS (2)

typedef struct VDIR VDIR;
typedef struct VKEY VKEY;

struct VDIR{
  POLICY write_policy;
  POLICY read_policy;
  POLICY destroy_policy;
  char name[MAX_NAME_LEN];
  unsigned char value[TCPA_HASH_SIZE];
}__attribute__((packed)); 

/* VKEYs are implemented as a small RWPSS suitable for storing an AES
 * key.  On an encrypt(archive) operation, the buffer is hashed, then
 * put into the value field, and on a decrypt(retrieve) operation, the
 * hash is checked.  So a VKEY really acts as both an encryption key
 * and a VDIR for integrity.
 */
#define MAXKEYSIZE (48)
struct VKEY{
  POLICY write_policy;
  POLICY read_policy;
  POLICY destroy_policy;
  char name[MAX_NAME_LEN];
  unsigned char value[MAXKEYSIZE];
}__attribute__((packed)); 

#define INDEXTOHANDLE(x) (x+1)
#define HANDLETOINDEX(x) (x-1)

#define ENCKEYLEN (312)
#define AESKEYLEN (32)
#define TWEAKKEYLEN (16)
#define TWEAKLEN (16)

typedef struct VDIRstate VDIRstate;
struct VDIRstate{
  unsigned char opass[TCPA_HASH_SIZE];
  unsigned int bootnum;
  unsigned int bitmap[2];
  VDIR vdirs[MAXVDIRS];
  VKEY vkeys[MAXVKEYS];
}__attribute__((packed));

typedef struct EncVDIRstate EncVDIRstate;
struct EncVDIRstate{
  unsigned char enckey[ENCKEYLEN];
  unsigned char encstate[sizeof(VDIRstate)];
}__attribute__((packed));

/* the vdirstate is protected through the DIRS */
//VDIRstate vstate;
EncVDIRstate *encvstate;
int currentdir = 0;

static int g_VDIR_isInitialized = 0;

#define CHECK_INITIALIZED()						\
  if(!g_VDIR_isInitialized) {						\
    printk_red("%s(): VDIR/VKey not initalized\n", __FUNCTION__);	\
    return -SC_INVALID;							\
  }

/* these locks aren't in the VDIR structure because we don't want them
 * included in the hash of the VDIRs because the pointers change */
Sema *vdirlock[MAXVDIRS];
Sema *vdirindex;

Sema *vkeylock[MAXVKEYS];
Sema *vkeyindex;

Sema *archivelock;

EncBlocks *vstate;
Hashtree *hashtree;
Keys *keys;


#define VSTATE ((VDIRstate *)encblocks_getbuf(PLAIN, vstate))
#define BLOCKS_TOUCH(a,s)						\
  do{									\
    unsigned char *changedp;						\
    int changedsize;								\
    VPRINT("touching size=%d 0x%p\n", s, (unsigned char *)a);		\
    assert(((unsigned int)a >= (unsigned int)VSTATE));			\
    assert(((unsigned int)a < (unsigned int)VSTATE + sizeof(VDIRstate)));	\
    encblocks_set_bitmap(vstate, (unsigned char *)a, s, &changedp, &changedsize); \
    ht_set_bitmap(hashtree, changedp, changedsize);					\
  }while(0)

void dumpVDIRs(void){
  int i,j;
  printk("VDIRS: ");
  for(i = 0; i < MAXVDIRS; i++)
    printk("%c", (((0x00000001 << i) & VSTATE->bitmap[0]) == 0)?'0':'1');
  printk("\n");
  for(i = 0; i < MAXVDIRS; i++){
    if(((0x00000001 << i) & VSTATE->bitmap[0]) != 0){
      printk("%d. %s: ", i, VSTATE->vdirs[i].name);
      for(j = 0; j < TCPA_HASH_SIZE; j++)
	printk("%02x ", VSTATE->vdirs[i].value[j]);
      printk("\n");
    }
  }
  printk("VKEYS: ");
  for(i = 0; i < MAXVKEYS; i++)
    printk("%c", (((0x00000001 << i) & VSTATE->bitmap[1]) == 0)?'0':'1');
  printk("\n");
  for(i = 0; i < MAXVKEYS; i++){
    if(((0x00000001 << i) & VSTATE->bitmap[1]) != 0){
      printk("%d. %s: ", i, VSTATE->vkeys[i].name);
      for(j = 0; j < MAXKEYSIZE; j++)
	printk("%02x ", VSTATE->vkeys[i].value[j]);
      printk("\n");
    }
  }
}

#define getvdirindex(n) getvindex(0,n)
#define getvkeyindex(n) getvindex(1,n)
#define vdir_release_index(i) release_index(i,0)
#define vkey_release_index(i) release_index(i,1)
#define vdir_check_index(i) checkvindex(i,0)
#define vkey_check_index(i) checkvindex(i,1)

#define VLOCK (which?vkeyindex:vdirindex)
#define MAXES (which?MAXVKEYS:MAXVDIRS)

/* XXX change this to use the hashtables in util.c */
/* hopefully a simple hash will make lookup fast enough */
static int getstringhash(char *s, int max){
  int hval = 0, n, i; 
  int primes[10] = {2053,3181,4231,5443,6221,7867,2297,421,71,7919};

  n = strlen(s);
  for(i = 0; i < n; i++)
    hval += (s[i] * primes[i % 10]) % max;
  return (hval + max) % max;
}

/* check bitmap to find an empty VDIR slot in the list */
static int getvindex(int which, char *name){
  int ret = -1;
  int i, j, off;
  
  off = getstringhash(name, MAXES);
  P(VLOCK);
  for(j = 0; j < MAXES; j++){
    i = (j + off) % MAXES;
    if (((0x00000001 << i) & VSTATE->bitmap[which]) == 0){
      VSTATE->bitmap[which] |= (0x00000001 << i);
      BLOCKS_TOUCH(&VSTATE->bitmap[which], sizeof(VSTATE->bitmap[which]));
      ret = i;
      break;
    }
  }
  V(VLOCK);
  
  return ret;
}

/* mark this index in the bitmap as empty */
static void release_index(int i, int which){
  P(VLOCK);
  VSTATE->bitmap[which] &= ~(1 << i);
  BLOCKS_TOUCH(&VSTATE->bitmap[which], sizeof(VSTATE->bitmap[which]));
  V(VLOCK);
}
/* check if a vdir is presently used */
static int checkvindex(int i, int which){
  int ret = 0;
  
  P(VLOCK);
  if (((0x00000001 << i) & VSTATE->bitmap[which]) == 0)
    ret = -1;
  V(VLOCK);
  
  return ret;
}
static int vdir_archive(void);
int shell_archivevdir(int ac, char **av) {
    BLOCKS_TOUCH(VSTATE, sizeof(VDIRstate));
	vdir_archive();
	return 0;
}
DECLARE_SHELL_COMMAND(archivevdir, shell_archivevdir, "-- archive VDIRs to disk");

static int vdir_archive(void){
  unsigned char tmphash[TCPA_HASH_SIZE];
  unsigned char *roothash;
  int ret;
  int dbg = 0;

  if(DISABLE_TPM){
    VPRINT("vdir_archive: TPM DISABLED\n");
    return 0;
  }

  encblocks_update(CIPHER, vstate);

  roothash = ht_update_hashtree(hashtree);
  if(dbg){
    int i;
    sha1((char *)encvstate, sizeof(EncVDIRstate), tmphash);
    VPRINT("vdir_archive: straight hash (enc):");
    for(i = 0; i < TCPA_HASH_SIZE; i++){
      VPRINT(" %02x", tmphash[i]);
    }
    VPRINT("\n");
    sha1((char *)VSTATE, sizeof(VDIRstate), tmphash);
    VPRINT("vdir_archive: straight hash (unenc):");
    for(i = 0; i < TCPA_HASH_SIZE; i++){
      VPRINT(" %02x", tmphash[i]);
    }
    VPRINT("\n");
  }

  P(archivelock);

  currentdir = (currentdir + 1) % NUMDIRS;


  if(dbg){
    VPRINT("vdir_archive: writing TPM:");
    int i;
    for(i = 0; i < TCPA_HASH_SIZE; i++){
      VPRINT(" %02x", roothash[i]);
    }
    VPRINT("\n");
  }

  ret = TPM_DirWriteAuth(currentdir, roothash, VSTATE->opass);


  if(ret != 0){
    VERROR("could not write to dir %d\n", currentdir);
    V(archivelock);
    return -1;
  }

  /* in case we die during a tftp write the backup vdirs are there */
  if(send_file(dirname(currentdir), (char *)encvstate, sizeof(EncVDIRstate))){
    VERROR("could not send file %s\n", dirname(currentdir));
    V(archivelock);
    return -1;
  }


  /* zero out old dir */
  memset(tmphash, 0, TCPA_HASH_SIZE);
  VPRINT("vdir_archive: writing TPM 2\n");
  ret = TPM_DirWriteAuth(((currentdir + NUMDIRS - 1) % NUMDIRS), tmphash, VSTATE->opass);


  if(ret != 0){
    VERROR("could not write to dir %d\n", ((currentdir + NUMDIRS - 1) % NUMDIRS));
    V(archivelock);
    return -1;
  }

  V(archivelock);
  
  return 0;
}

/* no locks needed, this is only on init */
static int vdir_retrieve(void){
  int size;
  char *buf;
  unsigned char tmphash[TCPA_HASH_SIZE];
  unsigned char *dirptr;
  unsigned char dirread[TCPA_HASH_SIZE + TCPA_DATA_OFFSET];
  int i;
  int dbg = 0;

  if(DISABLE_TPM){
    return -1;
  }


  TPM_DirRead(0, dirread, TCPA_HASH_SIZE + TCPA_DATA_OFFSET);

  dirptr = dirread + TCPA_DATA_OFFSET;

  currentdir = 1;
  VPRINT("dir 0: ");
  for(i = 0; i < TCPA_HASH_SIZE; i++){
    VPRINT("0x%x ", dirptr[i]);
    if (dirptr[i] != 0){
      currentdir = 0;
      break;
    }
  }  
  VPRINT("\n");

  /* if currentdir is 0, check that VDIR.0 matches DIR 0 
   *    if it doesn't match, go on to currentdir = 1 
   * if currentdir is 1, get dir contents and check VDIR.1 matches DIR 1 
   */
  for(; currentdir < 2; currentdir++){
    if(currentdir == 1){
      TPM_DirRead(currentdir, dirread, TCPA_HASH_SIZE + TCPA_DATA_OFFSET);
    }

    buf = fetch_file(dirname(currentdir), &size);
    if(buf == NULL){
      VERROR("can't read file %s\n", dirname(currentdir));
      currentdir = 1;
      continue;
    }

    if(size == sizeof(EncVDIRstate)){
      hashtree = ht_create_hashtree(buf, size, BLOCKSIZE);
      ht_build_hashtree(hashtree, 0, size);
      if(dbg){
	sha1(buf, size, tmphash);
	VPRINT("vdir_retrieve: straight hash (enc):");
	for(i = 0; i < TCPA_HASH_SIZE; i++){
	  VPRINT(" %02x", tmphash[i]);
	}
	VPRINT("\n");
      }

      if(memcmp(ht_get_root(hashtree), dirptr, TCPA_HASH_SIZE) == 0){
	encvstate = (EncVDIRstate *)buf;

	vstate = encblocks_create_from_buf(CIPHER, sizeof(VDIRstate),
					   BLOCKSIZE, 0, sizeof(VDIRstate),
					   encvstate->encstate);
	keys = encblocks_get_keys(vstate);

	if(dbg){
	  sha1(encvstate->enckey, ENCKEYLEN, tmphash);
	  int i;
	  VPRINT("sealed was: ");
	  for(i = 0; i < TCPA_HASH_SIZE; i++)
	    VPRINT("%02x ", tmphash[i]);
	  VPRINT("\n");
	}

	if(dbg){
	  printk_red("sealed data = ");
	  int i;
	  for(i = 0; i < 20; i++)
	    printk_red("%02x ", encvstate->enckey[i]);
	  printk_red("\n");
	}

	/* Make sure vdirs were left by Nexus (identified by hash in PCRs) */
	/* pcr info is the header of the sealed blob */
	TPMPCRInfo mypcrs;
	TPMPCRInfo *sealedpcrs = (TPMPCRInfo *)(encvstate->enckey + TCPA_VERSION_SIZE + sizeof(int));
	int pcrslen = sizeof(TPMPCRInfo);
	GenPCRInfo(PCRMASK, (unsigned char *)&mypcrs, &pcrslen);
	assert(pcrslen == sizeof(TPMPCRInfo));
	
	if(memcmp(mypcrs.digestAtCreation, sealedpcrs->digestAtCreation, TCPA_HASH_SIZE) != 0){
	  VERROR("vdirs weren't sealed by Nexus!!\n sealed(creation):");
	  for(i = 0; i < TCPA_HASH_SIZE; i++)
	    printk_red("%02x ", sealedpcrs->digestAtCreation[i]);
	  printk_red("\n sealed(release ):");
	  for(i = 0; i < TCPA_HASH_SIZE; i++)
	    printk_red("%02x ", sealedpcrs->digestAtRelease[i]);
	  printk_red("\n mypcrs(creation):");
	  for(i = 0; i < TCPA_HASH_SIZE; i++)
	    printk_red("%02x ", mypcrs.digestAtCreation[i]);
	  printk_red("\n mypcrs(release ):");
	  for(i = 0; i < TCPA_HASH_SIZE; i++)
	    printk_red("%02x ", mypcrs.digestAtRelease[i]);
	  printk_red("\n");

	  ht_destroy_hashtree(hashtree);
	  encblocks_destroy(vstate);
	  gfree(buf);
	  continue;
	}

	int keyslen = sizeof(Keys);
	int ret = TPM_Unseal(TPM_KH_SRK, spass, spass, encvstate->enckey, 
			     ENCKEYLEN, (unsigned char *)keys, &keyslen);

	if(dbg){
	  sha1((unsigned char *)keys, keyslen, tmphash);
	  int i;
	  VPRINT("unsealed was (%d): ", keyslen);
	  for(i = 0; i < TCPA_HASH_SIZE; i++)
	    VPRINT("%02x ", tmphash[i]);
	  VPRINT("\n");
	}

	if(dbg){
	  int i;
	  VPRINT("keys: ");
	  for(i = 0; i < sizeof(Keys); i++)
	    VPRINT("%02x ", ((unsigned char *)keys)[i]);
	  VPRINT("\n");
	}

	encblocks_activate_keys(vstate);
	encblocks_compute(PLAIN, vstate, 0, sizeof(VDIRstate));

	if(dbg){
	  sha1((char *)VSTATE, sizeof(VDIRstate), tmphash);
	  VPRINT("vdir_retrieve: straight hash (unenc):");
	  for(i = 0; i < TCPA_HASH_SIZE; i++){
	    VPRINT(" %02x", tmphash[i]);
	  }
	  VPRINT("\n");
	}
	
	if(ret != 0){
	  VERROR("couldn't retrieve vdir key!!\n");
	  ht_destroy_hashtree(hashtree);
	  encblocks_destroy(vstate);
	  gfree(buf);
	  continue;
	}
	return 0;
      }
      ht_destroy_hashtree(hashtree);
    }else
      VERROR("size didn't match!!\n");
    gfree(buf);
  }
  
  /* neither one matches.  retrieve failed. */
  currentdir = 1;
  return -1;
}

/* The following functions make up the vdir/vkey interface */

/* Return handle to a vdir/vkey corresponding to name. 
 * (XXX DoS: one process taking up all names for vdirs) 
 */
unsigned int vdir_lookup(char *name){
  CHECK_INITIALIZED();

  int i, j, off;

  off = getstringhash(name, MAXVDIRS);
  for(j = 0; j < MAXVDIRS; j++){
    i = (j + off) % MAXVDIRS;
    P(vdirlock[i]);
    if((vdir_check_index(i) >= 0) && (strncmp(name, VSTATE->vdirs[i].name, min((int)(strlen(name)+1), MAX_NAME_LEN)) == 0)){
      V(vdirlock[i]);
      VPRINT("match: \"%s\" \"%s\"\n", name, VSTATE->vdirs[i].name);
  
      return INDEXTOHANDLE(i);
    }
    V(vdirlock[i]);
  }
  
  return 0;
}

unsigned int vkey_lookup(char *name){
  CHECK_INITIALIZED();

  int i, j, off;
  VPRINT("match: \"%s\" \"%s\"\n", name, "?");  

  off = getstringhash(name, MAXVKEYS);
  for(j = 0; j < MAXVKEYS; j++){
    i = (j + off) % MAXVKEYS;
    P(vkeylock[i]);
    if((vkey_check_index(i) >= 0) && (strncmp(name, VSTATE->vkeys[i].name, min((int)(strlen(name)+1), MAX_NAME_LEN)) == 0)){
      V(vkeylock[i]);
      VPRINT("match: \"%s\" \"%s\"\n", name, VSTATE->vkeys[i].name);

      return INDEXTOHANDLE(i);
    }
    V(vkeylock[i]);
  }

  return 0;
}


/* debug functions to free up a name */
void vdir_clear_dbg(char *name){
  unsigned int hdl = vdir_lookup(name);
  if(hdl == 0) {
    printk("No VDIR at %s\n", name);
    return;
  }
  int index = HANDLETOINDEX(hdl);
  P(vdirlock[index]);
  vdir_release_index(index);
  V(vdirlock[index]);
  printk("Cleared VDIR %s\n", name);
}
void vkey_clear_dbg(char *name){
  unsigned int hdl = vkey_lookup(name);
  if(hdl == 0) {
    printk("No VKEY at %s\n", name);
    return;
  }
  int index = HANDLETOINDEX(hdl);
  P(vkeylock[index]);
  vkey_release_index(index);
  V(vkeylock[index]);
  printk("Cleared VKEY %s\n", name);
}



/* Destroy a vdir/vkey if the appropriate grounds are presented.
 * Implemented by simply marking the vdir/vkey as available in the
 * bitmap.
 */
int vdir_destroy(unsigned int handle, GROUNDS destroy_grounds){
  CHECK_INITIALIZED();

  VDIR *vdir;
  int index = HANDLETOINDEX(handle);
  int err = 0;
  if(index >= MAXVDIRS || index < 0) {
    return -1;
  }

  P(vdirlock[index]);

  vdir = &(VSTATE->vdirs[index]);

  if (guard_convinced(&vdir->destroy_policy, destroy_grounds)) {
    vdir_release_index(index);
  } else {
    err = -1;
  }
  
  vdir_archive();
  V(vdirlock[index]);

  return err;
}

int vkey_destroy(unsigned int handle, GROUNDS destroy_grounds){
  CHECK_INITIALIZED();

  VKEY *vkey;
  int index = HANDLETOINDEX(handle);
  int err = 0;
  if(index >= MAXVKEYS || index < 0) {
    return -1;
  }

  P(vkeylock[index]);

  vkey = &(VSTATE->vkeys[index]);

  if (guard_convinced(&vdir->destroy_policy, destroy_grounds)) {
    vkey_release_index(index);
  } else {
    err = -1;
  }
  
  V(vkeylock[index]);

  return err;
}


/* Create a vdir/vkey and associate the policies required for
 * operations.  A vkey needs a key created (could be a pre-generated
 * key) in addition to the implicit 20 byte VDIR used to tamperproof
 * whatever is encrypted with the key.
 */
unsigned int vdir_create(char *name, 
			 unsigned char *initval, int initlen,
			 POLICY write_policy, POLICY read_policy, POLICY destroy_policy){
  CHECK_INITIALIZED();

  unsigned int myindex;
  VDIR *new;
  
  VPRINT("vdir_create: %s\n", name);

  if(initlen != TCPA_HASH_SIZE)
    return 0;

  if(vdir_lookup(name) > 0){
    VERROR("VDIR can't be created (name collision %s)\n", name);
    return 0;
  }

  if((myindex = getvdirindex(name)) < 0){
    VERROR("VDIR can't be created (list is full)\n", name);
    return 0;
  }

  new = &VSTATE->vdirs[myindex];

  P(vdirlock[myindex]);

  new->write_policy = write_policy;
  new->read_policy = read_policy;
  new->destroy_policy = destroy_policy;

  strncpy(new->name, name, min((int)(strlen(name) + 1), MAX_NAME_LEN));
  memcpy(new->value, initval, TCPA_HASH_SIZE);

  BLOCKS_TOUCH(new, sizeof(VDIR));

  V(vdirlock[myindex]);

  if(!DISABLE_TPM){
    if(vdir_archive() < 0){
      vdir_release_index(myindex);
      VERROR("VIR archive failed after create\n");
      return 0;
    }
  }
  return INDEXTOHANDLE(myindex);
}

unsigned int vkey_create(char *name, 
			 unsigned char *initval, int initlen,
			 /* unsigned char *out, int *outlen,*/
			 POLICY write_policy, POLICY read_policy, POLICY destroy_policy){
  CHECK_INITIALIZED();

  unsigned int myindex;
  VKEY *new;
  int ret;

  VPRINT("vkey_create: %s", name);
  if(DISABLE_TPM)
    return 0;

  if(initlen > MAXKEYSIZE){
    VERROR("Key is too large!  max=%d\n", MAXKEYSIZE);
    return 0;
  }

  if(vkey_lookup(name) > 0){
    VERROR("VKEY can't be created (name collision %s)\n", name);
    return 0;
  }
  
  if((myindex = getvkeyindex(name)) < 0){
    VERROR("VKEY can't be created (list is full)\n", name);
    return 0;
  }

  new = &VSTATE->vkeys[myindex];

  P(vkeylock[myindex]);

  new->write_policy = write_policy;
  new->read_policy = read_policy;
  new->destroy_policy = destroy_policy;

  strncpy(new->name, name, min((int)(strlen(name) + 1), MAX_NAME_LEN));

  BLOCKS_TOUCH(new, sizeof(VKEY));
  
  memcpy(new->value, initval, initlen); // kwalsh: bug? should be *before* blocks_touch?!?

  int dbg_i;
  for(dbg_i = 0; dbg_i < 20; dbg_i++)
    VPRINT("%02x ", new->value[dbg_i]);
  VPRINT("\n");

  ret = vdir_archive();
  if(ret < 0) {
    vkey_release_index(myindex);
    V(vkeylock[myindex]);
    return -ERR_VKEY_ARCHIVE;
  }

  V(vkeylock[myindex]);

  return INDEXTOHANDLE(myindex);
}


/* Check authorization of requesting principal, then write.  VKEYs
 * have an implicit vdir associated with them which prevents something
 * stored with a vkey from being replayed.  Basically it's a small
 * RWPSS.
 */
int vdir_write(unsigned int handle, unsigned char *data, GROUNDS write_grounds) {
  CHECK_INITIALIZED();

  VDIR *vdir;
  int index = HANDLETOINDEX(handle); 
  if(index >= MAXVDIRS || index < 0) {
    return -1;
  }

  VPRINT("writing vdir %d\n", index);

  P(vdirlock[index]);
  vdir = &(VSTATE->vdirs[index]);

  if (!guard_convinced(&vdir->write_policy, write_grounds)) {
    V(vdirlock[index]);
    return -SC_NOPERM;
  }

  memcpy(vdir->value, data, TCPA_HASH_SIZE);
  BLOCKS_TOUCH(vdir->value, TCPA_HASH_SIZE);

  vdir_archive();

  V(vdirlock[index]);
  
  return 0;
}
int vkey_write(unsigned int handle, 
	       unsigned char *data, int datalen, 
	       /* unsigned char *out, int *outlen, */
	       GROUNDS write_grounds) {
  CHECK_INITIALIZED();
  VKEY *vkey;
  //unsigned int tpmhandle;
  int index = HANDLETOINDEX(handle); 
  int ret;
  //unsigned char *output;

  if(DISABLE_TPM)
    return -SC_INVALID;

  if(index >= MAXVKEYS || index < 0) {
    return -SC_INVALID;
  }

  if((datalen > MAXKEYSIZE)||(datalen < 0)){
    return -SC_INVALID;
  }

  P(vkeylock[index]);
  vkey = &(VSTATE->vkeys[index]);

  if (!guard_convinced(&vdir->write_policy, write_grounds)) {
    V(vkeylock[index]);
    return -SC_NOPERM;
  }

  memcpy(vkey->value, data, datalen);
  BLOCKS_TOUCH(vkey->value, datalen);

  ret = vdir_archive();
  if(ret < 0){
    V(vkeylock[index]);
    return -ERR_VKEY_ARCHIVE;
  }
  
  V(vkeylock[index]);
  
  return ret;
}


/* Check authorization of requesting principal, then read.  VKEYs
 * check their implicit vdir for vkey RWPSS semantics.
 */
int vdir_read(unsigned int handle, unsigned char *buffer, GROUNDS read_grounds) {
  CHECK_INITIALIZED();
  VDIR *vdir;
  int index = HANDLETOINDEX(handle);
  if(index >= MAXVDIRS || index < 0) {
    return -1;
  }

  P(vdirlock[index]);
  vdir = &(VSTATE->vdirs[index]);

  if (!guard_convinced(&vdir->read_policy, read_grounds)) {
    V(vdirlock[index]);
    return -SC_NOPERM;
  }

  memcpy(buffer, vdir->value, TCPA_HASH_SIZE);
  BLOCKS_TOUCH(vdir->value, TCPA_HASH_SIZE);

  V(vdirlock[index]);

  return 0;
}

int vkey_read(unsigned int handle, 
	      /* unsigned char *encdata, int encdatalen,*/
	      unsigned char *out, int *outlen, 
	      GROUNDS read_grounds) {
  CHECK_INITIALIZED();
  VKEY *vkey;
  int index = HANDLETOINDEX(handle);
  //unsigned int tpmhandle;
  //unsigned char tmphash[TCPA_HASH_SIZE];
  //unsigned char *output;
  //int ret;

  if(DISABLE_TPM){
    VERROR("TPM disabled!\n");
    *outlen = 0;
    return -SC_INVALID;
  }

  if(index >= MAXVKEYS || index < 0) {
    VERROR("%s wrong index %d\n", __FUNCTION__, index);
    *outlen = 0;
    return -SC_INVALID;
  }

  if((*outlen > MAXKEYSIZE) || (*outlen < 0)){
    VERROR("%s outlen not right size 0 < %d < %d\n", __FUNCTION__,  *outlen, MAXKEYSIZE);
    *outlen = 0;
    return -SC_INVALID;
  }

  P(vkeylock[index]);
  vkey = &(VSTATE->vkeys[index]);

  if (!guard_convinced(&vdir->read_policy, read_grounds)) {
    VERROR("policy check failed %s %s %d!\n", __FILE__, __FUNCTION__, __LINE__);
    V(vkeylock[index]);
    *outlen = 0;
    return -SC_NOPERM;
  }

  memcpy(out, vkey->value, *outlen);
    
  V(vkeylock[index]);

  return 0;
}

int takeowner_syscall = 0;
int takeowner_result = 0;
Sema *takeowner_sema;

unsigned char *get_opass(void){
  if(!g_VDIR_isInitialized)
    printk_red("%s(): VDIR/VKey not initalized\n", __FUNCTION__);	
  return VSTATE->opass;
}
unsigned char *get_spass(void){
  return spass;
}
unsigned int get_bootnum(void){
  if(!g_VDIR_isInitialized)
    printk_red("%s(): VDIR/VKey not initalized\n", __FUNCTION__);	
  return VSTATE->bootnum;
}

static void 
bin_to_hex(char *dest, const char *src, int len) {
  int i;
  for(i=0; i < len; i++) {
    sprintf(dest + i * 2, "%02x", ((unsigned char *)src)[i]);
  }
}


/* fork the trusted process to provide take ownership request */
int fork_owner(void){
  int ac = 3;
  char *av[3];
  char opasstxt[TCPA_HASH_SIZE * 2 + 1];
  char spasstxt[TCPA_HASH_SIZE * 2 + 1];

  bin_to_hex(opasstxt, VSTATE->opass, TCPA_HASH_SIZE);
  bin_to_hex(spasstxt, spass, TCPA_HASH_SIZE);

  int i;
  for(i = 0; i < TCPA_HASH_SIZE; i++)
    printk("%02x", VSTATE->opass[i]);
  printk("\n");
  printk("new opass = %s, new spass = %s", opasstxt, spasstxt);

  av[0] = TAKE_OWNER_PROCESS;
  av[1] = opasstxt;
  av[2] = spasstxt;

  takeowner_syscall = 1; /* enable syscall temporarily */
  takeowner_sema = sema_new();

  //UThread *ownerthread = 
  printk("exec'ing %s\n", av[0]);
  UThread *ut = elf_load(av[0], 0, ac, av);
  nexusthread_start((BasicThread *)ut, 0);
  P(takeowner_sema);

  takeowner_syscall = 0;
  return takeowner_result;
}

/* init the vdir system */
void vdir_init(void){
  int i;
  int dbg = 0;

  printk_red("VDIR_INIT\n");

  /* lock for the new vdir handle */
  vdirindex = sema_new();
  sema_initialize(vdirindex, 1);
  vkeyindex = sema_new();
  sema_initialize(vkeyindex, 1);

  /* locks for vdirs */
  for(i = 0; i < MAXVDIRS; i++){
    vdirlock[i] = sema_new();
    sema_initialize(vdirlock[i], 1);
    vkeylock[i] = sema_new();
    sema_initialize(vkeylock[i], 1);
  }
  
  archivelock = sema_new();
  sema_initialize(archivelock, 1);

#if 0
  /* XXX where does ownerpass come from */
  char *tpm_passwd = "egs";
  sha1(tpm_passwd, strlen(tpm_passwd), opass);
#endif

  char *srkpasswd = "Nexus";
  sha1(srkpasswd, strlen(srkpasswd), spass);

  if(vdir_retrieve() < 0){
    VERROR("retrieve of vdirs failed, creating new vstate...\n");
    encvstate = (EncVDIRstate *)galloc(sizeof(EncVDIRstate));

    vstate = encblocks_create(PLAIN, sizeof(VDIRstate), BLOCKSIZE, 
			      0, sizeof(VDIRstate));
    encblocks_zero(PLAIN, vstate);

    VERROR("generating new owner password: ");
    RAND_bytes(VSTATE->opass, TCPA_HASH_SIZE);
    for(i = 0; i < TCPA_HASH_SIZE; i++)
      printk("%02x", VSTATE->opass[i]);
    printk("\n");

    VERROR("attempting to take ownership. This may take a while...\n");
    if(fork_owner() != 0){
      VERROR("TPM already has an owner.  Reboot and manually clear TPM from BIOS. On the ThinkCentre, this means rebooting with Enter held down to get physical presence, then going to the security setting and clearing the TPM keys.\n");
      for(;;);
    }

    encblocks_generate_keys(vstate);
    encblocks_activate_keys(vstate);
    encblocks_compute_to_buf(CIPHER, vstate, 0, sizeof(VDIRstate), 
			     encvstate->encstate);
    keys = encblocks_get_keys(vstate);
    if(dbg){
      int i;
      VPRINT("keys: ");
      for(i = 0; i < sizeof(Keys); i++)
	VPRINT("%02x ", ((unsigned char *)keys)[i]);
      VPRINT("\n");
    }

    if(dbg){
      unsigned char tmphash[TCPA_HASH_SIZE];
      int i;
      sha1((unsigned char *)keys, sizeof(Keys), tmphash);
      VPRINT("unsealed was: ");
      for(i = 0; i < TCPA_HASH_SIZE; i++)
	VPRINT("%02x ", tmphash[i]);
      VPRINT("\n");
    }

    int outlen = ENCKEYLEN;
    int ret = TPM_Seal_CurrPCR(TPM_KH_SRK, PCRMASK, spass, spass, 
			       (unsigned char *)keys, sizeof(Keys), 
			       encvstate->enckey, &outlen);

    if(dbg){
      unsigned char tmphash[TCPA_HASH_SIZE];
      int i;
      sha1(encvstate->enckey, outlen, tmphash);
      VPRINT("sealed was: ");
      for(i = 0; i < TCPA_HASH_SIZE; i++)
	VPRINT("%02x ", tmphash[i]);
      VPRINT("\n");
    }

    if(ret != 0){
      VERROR("could not seal vdir key");
      return;
    }
    assert(outlen == ENCKEYLEN);
    VERROR("generated and sealed new vdir key\n");

    hashtree = ht_create_hashtree((unsigned char *)encvstate, sizeof(EncVDIRstate), BLOCKSIZE);
    ht_build_hashtree(hashtree, 0, sizeof(EncVDIRstate));
    VPRINT("hashtree=0x%p\n", hashtree);

    VSTATE->bootnum = 0;
  }
  BLOCKS_TOUCH(&VSTATE->bootnum, sizeof(int));
  VSTATE->bootnum++;

  vdir_archive();

  g_VDIR_isInitialized = 1;
  
}

/* a rough test to check that integrity is being maintained */
int test_vdir(int argc, char **argv){
#if 0
  if(hashtree)
    ht_destroy_hashtree(hashtree);
  if(vstate)
    encblocks_destroy(vstate);
#endif

  unsigned int randoff;  


  // hack: avoid crash on non-TPM box. 
  // XXX find cleaner solution
  if (!g_VDIR_isInitialized) {
	  printk_red("[tpm] not initialized\n");
	  return -1;
  }

  RAND_bytes((unsigned char *)&randoff, 4);
  randoff = randoff % sizeof(VDIRstate);
  
  int ret; 
  
  VDIRstate *copy = galloc(sizeof(VDIRstate));
  memcpy(copy, VSTATE, sizeof(VDIRstate));

  /* no write */
  ret = vdir_archive();
  if(ret < 0){
    printk_red("Couldn't archive!!!\n");
    return -1;
  }

  if(memcmp(copy, VSTATE, sizeof(VDIRstate)) != 0){
    printk_red("VSTATE corrupted!!!(1)\n");
    return -1;
  }

  ret = vdir_retrieve();
  if(ret < 0){
    printk_red("Couldn't retrieve!!!\n");
    return -1;
  }

  if(memcmp(copy, VSTATE, sizeof(VDIRstate)) != 0){
    printk_red("VSTATE corrupted!!!(2)\n");
    return -1;
  }

  /* authorized write */
  ((unsigned char *)VSTATE)[randoff] = 0xfe;
  memcpy(copy, VSTATE, sizeof(VDIRstate));

  BLOCKS_TOUCH(VSTATE + randoff, sizeof(char));
  ret = vdir_archive();
  if(ret < 0){
    printk_red("Couldn't archive 2!!!\n");
    return -1;
  }

  if(memcmp(copy, VSTATE, sizeof(VDIRstate)) != 0){
    printk_red("VSTATE corrupted!!!(3)\n");
    return -1;
  }

  ret = vdir_retrieve();
  if(ret < 0){
    printk_red("Couldn't retrieve 2!!!\n");
    return -1;
  }

  if(memcmp(copy, VSTATE, sizeof(VDIRstate)) != 0){
    printk_red("VSTATE corrupted!!!(4)\n");
    return -1;
  }

  /* unauthorized write */
  ((char *)encvstate)[randoff + 312] = 0xfe;
  if(send_file(dirname(currentdir), (char *)encvstate, sizeof(EncVDIRstate))){
    printk_red("Couldn't send 1!!!\n");
    return -1;
  }
  if(send_file(dirname((currentdir + 1) % NUMDIRS), (char *)encvstate, sizeof(EncVDIRstate))){
    printk_red("Couldn't send 2!!!\n");
    return -1;
  }
  ret = vdir_retrieve();
  if(ret >= 0){
    printk_red("Shouldn't have retrieved!!!\n");
    return -1;
  }

  printk_red("Success!! done.\n");
  return 0;
}
