/* This is a regression test which builds a hashtree up to 1 MB in
 * size (picked randomly) and then does a sequence of operations
 * checking that the root hash remains consistent.
 * 1. update with no changes should not change hash
 * 2. update after changes should change hash
 * 3. building a subsection should not change hash
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <nexus/hashtree.h>
#include "../wpss/blocksize.h"
#include <nexus/mt19937ar.h>
#include <openssl/sha.h>
#include <assert.h>

#ifndef rdtsc
#define rdtsc(low,high) __asm__ __volatile__("rdtsc" : "=a" (low), "=d" (high))
#endif

#define LEN 8192

//unsigned char region[LEN];

#define DUMP(x...) dump_ht_dot(x)
//#define DUMP(x...) do{}while(0)

#define max(a,b) ((a)>(b) ? (a) : (b))

unsigned char newhash[20];
unsigned char createhash[20];
unsigned char newcreate[20];
unsigned char straighthash[20];

//#define SIZE (256 * 1024 * 1024)
#define MINSIZE (1024)
#define MAXSIZE (1024 * 1024)

#define PRINT_HASH(h)				\
  do{						\
    int i;					\
    for(i = 0; i < 20; i++)			\
      printf("%02x ", (h)[i]);			\
    printf("\n");				\
  }while(0)

int main(int argc, char **argv){
  int i, secretsize;
  unsigned char *region, *hashptr, *malloced;
  Hashtree *h;
  int loc, writes;
  int blocksize;
  int len, start, end;
  int numblocks;
  int ret;

  if(argc != 2){
    printf("usage: %s 0x5eed\n", argv[0]);
    return -1;
  }

  unsigned int seed = strtoul(argv[1], NULL, 16);
  pseudorand_init(seed);

  secretsize = pseudorand(MINSIZE, MAXSIZE);
  writes = pseudorand(1, secretsize);

  printf("hashtree test size %d\n", secretsize);
  printf("hashtree test %d (%d writes)\n", secretsize, writes);
  printf("RUNNING HASHTREE TEST.  mallocing %d\n", secretsize);

  malloced = region = (unsigned char *)malloc(secretsize);
  memset(malloced, 0, secretsize);

  region = malloced;

  SHA1(region, secretsize, straighthash);
  printf("straight hash: ");
  PRINT_HASH(straighthash);




  /* create opt hashtree */
  blocksize = blocksize_get_opt(secretsize, 1);
  h = ht_create_hashtree(region, secretsize, blocksize);
  if(h == NULL){
    printf("hashtree couldn't be created\n");
    exit(-1);
  }
  ret = ht_build_hashtree(h, 0, secretsize);
  if(ret < 0){
    printf("hashtree couldn't be built\n");
    exit(-1);
  }
  hashptr = ht_get_root(h);
  memcpy(createhash,hashptr,20);

  printf("ht created is: ");
  PRINT_HASH(createhash);




  /* update after no writes should be the same*/

  hashptr = ht_update_hashtree(h);
  memcpy(newhash,hashptr,20);

  printf("ht no updates is: ");
  PRINT_HASH(newhash);

  assert(memcmp(createhash, newhash,20) == 0);




  /* perform writes, update and check that hash changed */

  for(i = 0; i < writes; i++){
    loc = pseudorand(0, secretsize);
    region[loc] = '5';
    ht_set_bitmap(h,&region[loc],sizeof(char));
  }

  SHA1(region, secretsize, straighthash);
  printf("straight hash after %d writes: ", writes);
  PRINT_HASH(straighthash);

  hashptr = ht_update_hashtree(h);
  memcpy(newhash,hashptr,20);

  printf("ht updated after writes is: ");
  PRINT_HASH(newhash);

  assert(memcmp(createhash,newhash,20) != 0);





  /* partial retrieve testing that hash is the same*/
  len = secretsize;
  blocksize = blocksize_get_opt(len, 1);
  numblocks = len/blocksize;
      
  start = pseudorand(0,len - 1);
  end = pseudorand(start,len);

#if 0
  h2 = ht_create_hashtree(region, len, blocksize);
  if(h2 == NULL){
    printf("hashtree couldn't be created\n");
    exit(-1);
  }
#endif
  if(ht_build_hashtree(h,start,end - start) < 0){
    printf("hashtree couldn't be built: start=%d len=%d\n", start, end - start);
    exit(-1);
  }
	    
  hashptr = ht_get_root(h);
  memcpy(newcreate,hashptr,20);

  printf("ht root of newly created: ");
  PRINT_HASH(newcreate);

  if(memcmp(newcreate,newhash,20) != 0){
    printf("start=%d end=%d\n",start,end);
  }
  assert(memcmp(newcreate,newhash,20) == 0);



  /* clean up */
  //ht_destroy_hashtree(h2);

  ht_destroy_hashtree(h);

  free(malloced);
  printf("hashtree test done (success)\n");
  return 0;
}
