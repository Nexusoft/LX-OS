#ifndef __TPMCOMPAT_H__
#define __TPMCOMPAT_H__

#include <nexus/timing.h>

#include <libtcpa/keys.h>


/******* WPSS support functions *******/
#include <nexus/policy.h>


/* for hastree */
void get_region_bitmap(unsigned char *reg, int len, 
		       int blocksize, unsigned char *bitmap);
unsigned int remap_readonly(unsigned int rwvaddr, int size);
void unmap_readonly(unsigned char *rovaddr, int size);
//int region_map(int len, unsigned int *rovaddr, unsigned int *rwvaddr);

/* vdir interface */

typedef unsigned int VDIR;
typedef unsigned int VKEY;
typedef unsigned int VKEYOLD;

VDIR vdir_create(char *name, 
		 unsigned char *initval, int initlen,
		 POLICY write_policy, POLICY read_policy, POLICY destroy_polidy);

VDIR vdir_lookup(char *name);
int vdir_destroy(VDIR v, GROUNDS destroy_grounds);

// Rebind not implemented!!!
int vdir_rebind(VDIR v, char *name, GROUNDS destroy_grounds);
int vdir_write(VDIR v, unsigned char *data, GROUNDS write_grounds);
int vdir_read(VDIR v, unsigned char *data, GROUNDS read_grounds);

VKEYOLD vkeyold_create(char *name, 
		 unsigned char *initval, int initlen,
		 /* unsigned char *out, int *outlen,*/
		 POLICY write_policy, POLICY read_policy, POLICY destroy_policy);

VKEYOLD vkeyold_lookup(char *name);
int vkeyold_destroy(VDIR v, GROUNDS destroy_grounds);
int vkeyold_write(VKEYOLD v, 
	       unsigned char *data, int datalen, 
	       /* unsigned char *result, int resultlen, */
	       GROUNDS write_grounds);
int vkeyold_read(VKEYOLD v, 
	      /* unsigned char *data, int datalen, */
	      unsigned char *result, int resultlen, 
	      GROUNDS read_grounds);

void tpmcompat_init(void);

#endif
