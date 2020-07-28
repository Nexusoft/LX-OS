#ifndef __VDIR_H__
#define __VDIR_H__

#include <nexus/policy.h>

enum VDirKeyType{
  VDIR_TYPE = 1,
  VKEY_TYPE,
};
typedef enum VDirKeyType VDirKeyType;

enum VDirKeyError{
  ERR_VKEY_CREATE = 1,
  ERR_VKEY_HASH,
  ERR_VKEY_SEAL,
  ERR_VKEY_UNSEAL,
  ERR_VKEY_ARCHIVE,
};

void vdir_init(void);

unsigned int vdir_create(char *name, 
			 unsigned char *initval, int initlen,
			 POLICY write_policy, POLICY read_policy, POLICY destroy_policy);
int vdir_destroy(unsigned int handle, GROUNDS destroy_grounds);
unsigned int vdir_lookup(char *name);
int vdir_write(unsigned int handle, unsigned char *data, GROUNDS write_grounds);
int vdir_read(unsigned int handle, unsigned char *buffer, GROUNDS read_grounds);

unsigned int vkey_create(char *name, 
			 unsigned char *initval, int initlen,
			 /* unsigned char *out, int *outlen,*/
			 POLICY write_policy, POLICY read_policy, POLICY destroy_policy);


int vkey_destroy(unsigned int handle, GROUNDS destroy_grounds);
unsigned int vkey_lookup(char *name);
int vkey_write(unsigned int handle, unsigned char *data, int datalen, 
	       /* unsigned char *out, int *outlen, */
	       GROUNDS write_grounds);
int vkey_read(unsigned int handle, /* unsigned char *encdata, int encdatalen,*/
	      unsigned char *out, int *outlen, GROUNDS read_grounds);

void vdir_clear_dbg(char *name);
void vkey_clear_dbg(char *name);


unsigned int sys_vdirkeycreate(VDirKeyType which, 
			       char *user_name,
			       unsigned char *src, int srclen,
			       /*unsigned char *dest, int *destlen,*/
			       POLICY write_policy, POLICY read_policy, POLICY destroy_policy,
			       void *timing);
unsigned int sys_vdirkeylookup(char *user_name, VDirKeyType which, void *timing);
int sys_vdirkeydestroy(int handle, GROUNDS destroy_grounds, 
		       VDirKeyType which, void *timing);

#endif
