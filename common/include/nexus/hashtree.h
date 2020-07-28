#ifndef __HASHTREE_H__
#define __HASHTREE_H__

#include <nexus/timing.h>
#include <nexus/commontypedefs.h>

/* timings */
void ht_init_timings(void);
struct Timing *ht_get_timings(int *numtimings);

Hashtree *ht_create_hashtree(unsigned char *reg, int len, int blocksize);
Hashtree *ht_create_hashtree_to_buf(unsigned char *reg, int len, int blocksize, unsigned char *buf, int *buflen);

int ht_build_hashtree(Hashtree *new_tree, int suboffset, int sublen);

void ht_destroy_hashtree(Hashtree *ht);

void ht_round_to_block(int blocksize, int *suboff, int *sublen);
int ht_get_size(int len, int blocksize);
unsigned char *ht_get_root(Hashtree *ht);

void ht_set_bitmap(Hashtree *ht, unsigned char *addr, int len);
unsigned char *ht_update_hashtree(Hashtree *ht);

void dump_ht_dot(Hashtree *ht, char *filename);

#define OPT_BLOCKSIZE 175

#define HT_MAPPED_BITMAP (1)
#define HT_DIRECT_BITMAP (0)

#endif

