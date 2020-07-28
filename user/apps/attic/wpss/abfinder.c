#include <stdio.h>
#include <string.h>
#include <openssl/sha.h>
#include <nexus/mt19937ar.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>



#define SIZE 268435456
//#define SIZE 40
//#define NUMPOINTS 20
#define NUMPOINTS 20
#define TRIALS 10000

#define SHA1_ctx(s,l,d)						\
  do{								\
    SHA_CTX SHA_CTX_new;					\
    memcpy(&SHA_CTX_new, &initialctx, sizeof(SHA_CTX));         \
    SHA1_Update(&SHA_CTX_new, (s), (l));			\
    SHA1_Final((d), &SHA_CTX_new);				\
  }while(0)

SHA_CTX initialctx;
unsigned char bigbuf[SIZE + 2];
char outbuf[10 * NUMPOINTS * TRIALS];
unsigned char tmphash[20];
char filename[32];

int main(int argc, char **argv){
  int off=0;
  int i;
  int blocksize;
  unsigned int loc;

  printf("starting\n");

  init_genrand(143);
  SHA1_Init(&initialctx);

  for(blocksize = 1; blocksize <= 8192; blocksize++){
    for(i = 0; i< TRIALS; i++){
      unsigned char *ptr;
      loc = (unsigned int)genrand_int32();
      loc = loc % TRIALS;
      ptr = bigbuf + loc*blocksize;
      SHA1_ctx(ptr,blocksize,tmphash);
    }
    //printf(".");
    off += sprintf(outbuf + off, "%d %lld\n", blocksize, GET_TIME(t1)/(TRIALS*3));
    if(blocksize % 1024 == 0){
      sprintf(filename,"SHA_timings_small%d",blocksize);
      //writefile("SHA_timings_small_rand", outbuf, off);
      int fd = open("SHA_timings_small_rand", O_CREAT | O_RDWR | O_TRUNC);
      write(fd, outbuf, off);
      fsync(fd);
      close(fd);
    }
  }
  

  printf("done\nwriting file..");
  printf("done\n");
  return 0;
}
