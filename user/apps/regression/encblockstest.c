/* this regression test tests an encblocks */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <nexus/mt19937ar.h>

#include <openssl/sha.h>

#include <nexus/encblocks.h>

#define MINSIZE (4096)
#define MAXSIZE (1024 * 1024)

#define MINBLOCK (32)
#define MAXBLOCK 

Keys savedkeys;

unsigned char plainhash[20];
unsigned char cipherhash[20];
unsigned char plaincheckhash[20];
unsigned char ciphercheckhash[20];

int main(int argc, char **argv){
  int ret;
  unsigned char *plaincheck;
  unsigned char *ciphercheck;

  if(argc != 2){
    printf("usage: encblockstest 0x5eed\n");
    exit(-1);
  }
  unsigned int seed = strtoul(argv[1], NULL, 16);
  pseudorand_init(seed);
  
  int size = pseudorand(MINSIZE, MAXSIZE);
  int blocksize = pseudorand(MINBLOCK, size/(MINSIZE/MINBLOCK));

  blocksize = size = 32;

  /* create original encblocks */
  EncBlocks *enc = encblocks_create(PLAIN, size, blocksize, 0, size);
  if(enc == NULL)assert(0);

  ret = encblocks_generate_keys(enc);
  if(ret != 0)assert(0);

  ret = encblocks_activate_keys(enc);
  if(ret != 0)assert(0);

  ret = encblocks_compute(CIPHER, enc, 0, size);
  if(ret != 0)assert(0);

  plaincheck = (unsigned char *)malloc(size);
  ciphercheck = (unsigned char *)malloc(size);

  /* save copies of the plaintext and ciphertext */
  memcpy(plaincheck, encblocks_getbuf(PLAIN,enc), size);
  memcpy(ciphercheck, encblocks_getbuf(CIPHER,enc), size);
  memcpy(&savedkeys, encblocks_get_keys(enc), sizeof(Keys));
  
  encblocks_destroy(enc);
  
  /* see if we can reconstruct plaintext from ciphertext */
  enc = encblocks_create(CIPHER, size, blocksize, 0, size);
  if(enc == NULL)assert(0);

  memcpy(encblocks_getbuf(CIPHER,enc), ciphercheck, size);
  memcpy(encblocks_get_keys(enc), &savedkeys, sizeof(Keys));
  ret = encblocks_activate_keys(enc);
  if(ret != 0)assert(0);

  ret = encblocks_compute(PLAIN, enc, 0, size);
  if(ret != 0)assert(0);

  int sizecheck = size;
  SHA1(encblocks_getbuf(PLAIN, enc), sizecheck, plainhash);
  SHA1(plaincheck, sizecheck, plaincheckhash);

  assert(memcmp(plainhash, plaincheckhash, 20) == 0);

  printf("success. done.\n");
  exit(0);
}
