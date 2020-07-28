#include <assert.h>
#include <string.h>

#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/objects.h>

#include <nexus/init.h>
#include <nexus/timing.h>
#include <nexus/policy.h>
#include <nexus/types.h>
#include <nexus/env.h>

#include <nexus/Thread.interface.h>
#include <nexus/Debug.interface.h>
#include <nexus/SMR.interface.h>
#include <nexus/VDIR.interface.h>
#include <nexus/VKey.interface.h>

#include <nexus/tpmcompat.h>


/* for WPSS/RWPSS */

enum VDIR_KERNEL_TIMING{
  TIMING_RWPSS_KERNEL_ARCHIVE = 0,
  TIMING_RWPSS_KERNEL_ARCHIVE_VDIR_SHA,
  TIMING_RWPSS_KERNEL_ARCHIVE_VDIR_DIR,
  TIMING_RWPSS_KERNEL_ARCHIVE_VDIR_TFTP,
  TIMING_RWPSS_KERNEL_ARCHIVE_VDIR_ZERO_DIR,

  TIMING_RWPSS_KERNEL_RETRIEVE_VDIR_SHA,
  TIMING_RWPSS_KERNEL_RETRIEVE_VDIR_DIR,
  TIMING_RWPSS_KERNEL_RETRIEVE_VDIR_TFTP,

  TIMING_RWPSS_KERNEL_READ_VDIR,
  TIMING_RWPSS_KERNEL_READ_VKEYOLD,
  TIMING_RWPSS_KERNEL_WRITE_VDIR,
  TIMING_RWPSS_KERNEL_WRITE_VKEYOLD,
  TIMING_RWPSS_KERNEL_LOOKUP_VDIR,
  TIMING_RWPSS_KERNEL_LOOKUP_VKEYOLD,
  TIMING_RWPSS_KERNEL_DESTROY_VKEYOLD,
  TIMING_RWPSS_KERNEL_DESTROY_VDIR,

  TIMING_RWPSS_KERNEL_CREATE_VDIR,
  TIMING_RWPSS_KERNEL_CREATE_VKEYOLD,
  TIMING_RWPSS_KERNEL_CREATE_VKEYOLD_KEY,

  TIMING_RWPSS_KERNEL_LABELING_WRITE,
  TIMING_RWPSS_KERNEL_LABELING_READ,

  TIMING_RWPSS_KERNEL_REMAP_INSERT,
  TIMING_RWPSS_KERNEL_REMAP_VIRTTOPHYS,
  TIMING_RWPSS_KERNEL_REMAP_ADDPAGE,

  TIMING_RWPSS_KERNEL_SIZE,
};

struct Timing *vdirtimings = NULL;
void vdir_init_timings(void){
  vdirtimings = timing_new_anon(TIMING_RWPSS_KERNEL_SIZE);
}
struct Timing *vdir_get_timings(int *numtimings){
  *numtimings = TIMING_RWPSS_KERNEL_SIZE;
  return vdirtimings;
}

/* find out where was touched to add those blocks to the todo list */
void get_region_bitmap(unsigned char *reg, int len, int blocksize, unsigned char *bitmap){
  SMR_Get_Bitmap(reg, len, blocksize, bitmap);
  return;
}

/* remap this region as readonly and get address of readonly mapping */
unsigned int readonlyhint = 0x40000000;
unsigned int remap_readonly(unsigned int rwvaddr, int size){
  unsigned int ret;
  ret = readonlyhint = (unsigned)SMR_Remap_RO((char *)rwvaddr, size, (void *)vdirtimings, readonlyhint);
  return ret;
}

void unmap_readonly(unsigned char *rovaddr, int size){
  SMR_Unmap_RO(rovaddr, size);
  return;
}

void killcache(void){
  Debug_KillCache();
}

VDIR vdir_create(char *name, 
		 unsigned char *initval, int initlen, 
		 POLICY write_policy, POLICY read_policy, POLICY destroy_policy) {
  return VDIR_Create(name, 
		     initval, initlen, 
		     write_policy,
		     read_policy,
		     destroy_policy,
		     (void*)vdirtimings);
}
VDIR vdir_lookup(char *name) {
  return VDIR_Lookup(name, (void*)vdirtimings);
}

int vdir_destroy(VDIR v, GROUNDS destroy_grounds) {
  if(v == 0)
    return -1;
  return VDIR_Destroy(v, destroy_grounds, (void*)vdirtimings);
}

int vdir_rebind(VDIR v, char *name, GROUNDS destroy_grounds) {
  printf("VDIR Rebind not implemented!\n");
  return -1;
}

int vdir_write(VDIR v, unsigned char *data, GROUNDS write_grounds) {
  return VDIR_Write(v, write_grounds, data, (void*)vdirtimings);
}

int vdir_read(VDIR v, unsigned char *data, GROUNDS read_grounds) {
  return VDIR_Read(v, read_grounds, data, (void*)vdirtimings);
}

int dbg_vkeyold_calls = 0;

VKEYOLD vkeyold_create(char *name, 
		 unsigned char *src, int srclen,
		 /* unsigned char *dest, int *destlen,*/
		 POLICY write_policy, POLICY read_policy, POLICY destroy_policy) {
  VKEYOLD ret;

  if(dbg_vkeyold_calls){
    int i;
    printf("%s src: ", __FUNCTION__);
    for(i = 0; i < 30; i++){
      printf("%02x ", src[i]);
    }
    printf("\n");
  }

  ret = VKey_Create(name, 
		     src, srclen,
		    /*dest, destlen,*/
		     write_policy,
		     read_policy,
		     destroy_policy,
		     (void*)vdirtimings);

#if 0
  if(dbg_vkeyold_calls){
    int i;
    printf("%s dst: ", __FUNCTION__);
    for(i = 0; i < 30; i++){
      printf("%02x ", dest[i]);
    }
    printf("\n");
  }
#endif 

  return ret;
}
VKEYOLD vkeyold_lookup(char *name) {
  return VKey_Lookup(name, (void*)vdirtimings);
}
int vkeyold_destroy(VKEYOLD v, GROUNDS destroy_grounds) {
  if(v == 0)
    return -1;
  return VKey_Destroy(v, destroy_grounds, (void*)vdirtimings);
}
int vkeyold_write(VKEYOLD v, 
	       unsigned char *data, int datalen, 
	       /* unsigned char *result, int maxresultlen, */
	       GROUNDS write_grounds) {
  int ret;

  if(dbg_vkeyold_calls){
    int i;
    printf("%s data: ", __FUNCTION__);
    for(i = 0; i < 30; i++){
      printf("%02x ", data[i]);
    }
    printf("\n");
  }

  ret = VKey_Write(v, 
		   write_grounds,
		   data, datalen, 
		   /* result, maxresultlen, */
		   (void*)vdirtimings);

#if 0
  if(dbg_vkeyold_calls){
    int i;
    printf("%s resu: ", __FUNCTION__);
    for(i = 0; i < 30; i++){
      printf("%02x ", result[i]);
    }
    printf("\n");
  }
#endif
  return ret;
}
int vkeyold_read(VKEYOLD v, 
	      /* unsigned char *enc, int enclen, */
	      unsigned char *dest, int maxdestlen, 
	      GROUNDS read_grounds) {
  int ret;

#if 0
  if(dbg_vkeyold_calls){
     int i;
     printf("%s enc: ", __FUNCTION__);
     for(i = 0; i < 30; i++){
       printf("%02x ", enc[i]);
     }
     printf("\n");
  }
#endif 

  ret = VKey_Read(v, read_grounds,
		  /* enc, enclen, */
		  dest, maxdestlen, (void*)vdirtimings);

  if(dbg_vkeyold_calls){
    int i;
    printf("%s dst: ", __FUNCTION__);
    for(i = 0; i < 30; i++){
      printf("%02x ", dest[i]);
    }
    printf("\n");
  }

  return ret;
}

/** Learn the TPM version from the environment. */
void tpmcompat_init(void) {
  int i;
  if (__disable_filesystem) {
    printf("tpmcompat: skipping init (because file systems are disabled)\n");
    return;
  }
  char *version_data = Env_get_value("tcpa_version", NULL);
  if(version_data == NULL) {
    printf("tpmcompat: could not read version data!\n");
    return;
  }
  int version_pos = 0;
  char *pos = version_data;
  while(pos != NULL && version_pos < TCPA_VERSION_SIZE) {
    char *tok_start = strsep(&pos, ".");
    TCPA_VERSION[version_pos++] = atoi(tok_start);
  }
  free(version_data);
  if(version_pos < TCPA_VERSION_SIZE) {
    printf("tpmcompat: not enough digits for version (%d)!\n", version_pos);
    memset(TCPA_VERSION, 0, TCPA_VERSION_SIZE);
    return;
  }
  printf("%s:%d:tcpa version %d %d %d %d\n", __FILE__, __LINE__, TCPA_VERSION[0], TCPA_VERSION[1], TCPA_VERSION[2], TCPA_VERSION[3]);

}
