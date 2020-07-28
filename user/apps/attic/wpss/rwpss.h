#ifndef __RWPSS_H__
#define __RWPSS_H__

#include <nexus/timing.h>
#include <nexus/policy.h>
#include <nexus/types.h>

enum WPSSTYPE{
  WPSS_RW = 1,
  WPSS_W,
};

typedef enum WPSSTYPE WPSSTYPE;

void init_AES(void);
int encryptAES(unsigned char *key, int keylen, unsigned char **encreg, int *encsize, unsigned char *reg, int size);
int decryptAES(unsigned char *key, int keylen, unsigned char *encreg, int encsize, unsigned char *reg, int *size);

typedef struct WPSS WPSS;
int rw_wpss_archive(WPSS *w, GROUNDS archive_grounds);
//WPSS *rw_wpss_retrieve(char **addr, int len, int *maxlen, char *name, GROUNDS retrieve_grounds, WPSSTYPE type, int num_updates, int blocksize, int suboffset, int sublen);
int rw_wpss_destroy(WPSS *w, GROUNDS destroy_grounds);
void rw_wpss_free(WPSS *w);

WPSS *smr_map(int fd, char *name, GROUNDS retrieve_grounds, 
	      char **addr, int suboffset, int sublen);
WPSS *rw_wpss_retrieve(int fd, char *name, GROUNDS retrieve_grounds, 
		       unsigned char **addr, int suboffset, int sublen);

WPSS *smr_create(int fd, int len, char *name, 
		 POLICY archive_policy, POLICY retrieve_policy, POLICY destroy_policy, /* ACLs */
		 GROUNDS flush_grounds, /* XXX is this really needed? */
		 int num_updates, 
		 WPSSTYPE type, 
		 char **addr);
WPSS *rw_wpss_create(int fd, unsigned char **addr, int len, char *name, 
		     POLICY archive_policy, POLICY retrieve_policy, POLICY destroy_policy, /* ACLs */
		     GROUNDS flush_grounds, WPSSTYPE type, int num_updates, 
		     int blocksize);

int smr_sync(WPSS *w, GROUNDS archive_grounds);
int smr_destroy(WPSS *w, GROUNDS destroy_grounds);

int rw_wpss_destroy_no_handle(int fd, char *file, GROUNDS destroy_grounds);
int rw_wpss_get_dataoff(WPSS *w);

void rw_wpss_notify_write(WPSS *w, unsigned char *addr, int size);


/* read the wpss header from fd and return the length if it is a wpss */
int rw_wpss_retrieve_datalen(int fd);

#include <nexus/hashtree.h>
Hashtree *rw_wpss_get_ht(WPSS *w);

int rw_wpss_get_sublen(WPSS *w);

/* timing info */
void rwpss_init_timings(void);
int rwpss_get_timing_data(u64 **data);
void rwpss_free_timings(u64 *data);

#endif
