#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <crypto/aes.h>
#include <nexus/mt19937ar.h>
#include <assert.h>

#define MAXLEN (1024 * 1024)
#define MINLEN (150)
#define KEYLEN (32)

#define TWEAKSIZE (16)
#define KTWEAKSIZE (16)

unsigned char *plain;
unsigned char *cipher;
unsigned char *plain2;

unsigned char tmpkey1[KEYLEN] = {1,1,1,1,1,1,1,1,
			      1,1,1,1,1,1,1,1,
			      1,1,1,1,1,1,1,1,
			      1,1,1,1,1,1,1,1};

unsigned char tmpkey2[KTWEAKSIZE] = {2,2,2,2,2,2,2,2,
			      2,2,2,2,2,2,2,2};

unsigned char tmptweak[TWEAKSIZE] = {3,3,3,3,3,3,3,3,
			       3,3,3,3,3,3,3,3};

unsigned char badkey1[KEYLEN] = {0x01, 0x9a, 0xe6, 0xff, 0xed, 0x4d, 0x5c, 0x1c, 0x77, 0x48, 0x32, 0x68, 0xb5, 0x9d, 0xd8, 0x8a, 0xef, 0x8f, 0x96, 0x84, 0xd6, 0xcf, 0x40, 0xb0, 0xed, 0x07, 0xf2, 0x9a, 0x8c, 0x3a, 0xb8, 0x43};
unsigned char badkey2[KEYLEN] = {0x00, 0xf6, 0x45, 0x94, 0x37, 0x34, 0xc5, 0xd3, 0xf0, 0xc8, 0xfe, 0x04, 0x73, 0x2c, 0x60, 0x8f};
unsigned char badtweak[KEYLEN] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

#if 0
int parse_args(int argc, char **argv){
  
  if(argc < 3)
    usage_err();
  int i;
  for(i = 1; i < argc; i++){
    /* get options */
    if(argv[i][0] == '-'){
      char *option = &((argv[i])[1]);
      if(OPTION("key"))
    }
  }
}
#endif

int main(int argc, char **argv){
  int i,j;
  unsigned char *key1 = tmpkey1, *key2 = tmpkey2, *tweak = tmptweak;


  if(argc != 2){
    printf("usage: cryptotest 0x5eed");
  }

  unsigned int seed = strtoul(argv[1], NULL, 16);
  pseudorand_init(seed);
  int size = pseudorand(MINLEN, MAXLEN);

  plain = malloc(size);
  cipher = malloc(size);
  plain2 = malloc(size);

  assert(plain != NULL);
  assert(cipher != NULL);
  assert(plain2 != NULL);

  for(i = 0; i < KEYLEN/4; i++)
    *(unsigned int *)&key1[i * 4] = genrand_int32();
  for(i = 0; i < TWEAKSIZE/4; i++){
    *(unsigned int *)&key2[i * 4] = genrand_int32();
    *(unsigned int *)&tweak[i * 4] = genrand_int32();
  }

  int k;
  for(k = 0; k < size/4; k++){
    plain[k] = 0xff & genrand_int32();
  }
  
#if 0
  size = 32;
  memset(plain, 0, size);
  key1 = badkey1;
  key2 = badkey2;
  tweak = badtweak;
#endif

  printf("starting cryptotest using len=%d\n", size);
  printf("key1  = ");
  for(i = 0; i < KEYLEN; i++)
    printf("%02x ", key1[i]);
  printf("\n");

  printf("key2  = ");
  for(i = 0; i < KTWEAKSIZE; i++)
    printf("%02x ", key2[i]);
  printf("\n");

  printf("tweak = ");
  for(i = 0; i < TWEAKSIZE; i++)
    printf("%02x ", tweak[i]);
  printf("\n");

  nexus_aes_init();

  for(j = 0; j < 2; j++){
    if(j >= 1){
      printf("aes-tbc trial\n");
    }if(j == 0){
      printf("aes-cbc trial\n");
    }

    printf("plain  = ");
    for(i = 0; i < 20; i++){
      printf("%02x ", plain[i]);
    }
    printf("\n");

    int len = size;

    if(j >= 1){
      tbc_encrypt(plain, size,
		  cipher, &len,
		  key1, KEYLEN,
		  tweak, TWEAKSIZE,
		  key2, KTWEAKSIZE);
    }
    if(j == 0){
      nexus_cbc_encrypt(plain, size,
		  cipher, &len,
		  key1, KEYLEN,
		  tweak, TWEAKSIZE);
    }

    printf("encrypted %d to %d bytes\n", size, len);

    printf("cipher = ");
    for(i = 0; i < 20; i++){
      printf("%02x ", cipher[i]);
    }
    printf("\n");

    //len = size;

    if(j >= 1){
      tbc_decrypt(cipher, size,
		  plain2, &len,
		  key1, KEYLEN,
		  tweak, TWEAKSIZE,
		  key2, KTWEAKSIZE);
    }
    if(j == 0){
      nexus_cbc_decrypt(cipher, size,
		  plain2, &len,
		  key1, KEYLEN,
		  tweak, TWEAKSIZE);
    }

    printf("decrypted %d to %d bytes\n", size, len);

    printf("plain2 = ");
    for(i = 0; i < 20; i++){
      printf("%02x ", plain2[i]);
    }
    printf("\n");

    for(i = 0; i < size; i++){
      if(plain[i] != plain2[i]){
	printf("decryption failed!!! byte %d\n", i);
	return -1;
      }
    }

  }

  return 0;
}
