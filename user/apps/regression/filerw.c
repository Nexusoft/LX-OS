#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <nexus/mt19937ar.h>

/* inspired by getting different values from writing and reading a
 * file */

#define TRIALS (20)

int fd, fdpos;
int FILESIZE;
static unsigned char *wfile;
static unsigned char *rfile;
static int debug = 0;

void show(char *name, unsigned char *buf, int len) {
  int j;
  printf("%s = ", name);
  for(j = 0; j < len; j++) printf("%02x ", buf[j]);
  printf("\n");
}

int trial;

void check(int pos, int len) {
    int need_seek = (fdpos != pos);
    if (need_seek)
      lseek(fd, pos, SEEK_SET);
    read(fd, rfile+pos, len);
    fdpos = pos + len;

    if(debug){
      printf("reading %d bytes at offset %d%s:\n", len, pos, need_seek ? " (needed seek)" : "");
      show("rfile", rfile, FILESIZE);
    }

    if (memcmp(wfile+pos, rfile+pos, len)) {
      printf("error: got wrong value from read in trial %d\n", trial);
      int i;
      for (i = 0; i < len; i++) {
	if (wfile[pos+i] != rfile[pos+i]) {
	  printf("  at offset %d (0x%x) got %02x instead of %02x\n",
	      pos+i, pos+i,
	      (unsigned int)(unsigned char)rfile[pos+i],
	      (unsigned int)(unsigned char)wfile[pos+i]);
	  break;
	}
      }
      printf("regression test failed!\n");
      exit(1);
    }
}


int main(int argc, char **argv){
  char *filename = "/nfs/filerw.test.bin";
  int j;

  FILESIZE = 256;
  int seed = 1234;
  if (argc > 1) FILESIZE = atoi(argv[1]);
  if (argc > 2) filename = argv[2];
  if (argc > 3) seed = atoi(argv[3]);
  if (FILESIZE <= 0 || argc > 4) {
    printf("usage: filerw [count [filename [seed]]]\n");
    return 1;
  }

  init_genrand(seed);

  wfile = malloc(FILESIZE);
  memset(wfile, 0, FILESIZE);
  rfile = malloc(FILESIZE);
  memset(rfile, 0, FILESIZE);

  printf("running filerw regression test\n");

  if (debug) {
    show("wfile", wfile, FILESIZE);
    show("rfile", rfile, FILESIZE);
  }

  fd = open(filename, O_CREAT|O_WRONLY|O_TRUNC);
  fdpos = 0;
  if(fd < 0) {
    printf("open error: %s\n", filename);
    return -1;
  }

  for(trial = 0; trial < TRIALS; trial++){
    unsigned int  modder = FILESIZE - sizeof(unsigned int);
    unsigned int pos = ((genrand_int32() % modder) + modder) % modder;
    unsigned int val = genrand_int32();

    *((unsigned int *)&(wfile[pos])) = val;

    if(debug) {
      printf("writing %d bytes at offset %d: %x\n", sizeof(unsigned int), pos, val);
      show("wfile", wfile, FILESIZE);
    }

    if (trial % 2) {
      lseek(fd, 0, SEEK_SET);
      if(write(fd, wfile, FILESIZE) < 0){
	printf("write error\n");
	return -1;
      }
      fdpos = FILESIZE;
    } else {
      lseek(fd, pos, SEEK_SET);
      if(write(fd, wfile + pos, sizeof(unsigned int)) < 0) {
	printf("write error\n");
	return -1;
      }
      fdpos = pos + sizeof(unsigned int);
    }

    fsync(fd);

    // check 3 bytes (forcing seeks)
    check(2, 1);
    check(1, 1);
    check(0, 1);

    // check 3 bytes (without seek)
    check(1, 1);
    check(2, 1);
    check(3, 1);

    // check whole file
    check(0, FILESIZE);
  }
  close(fd);

  printf("done with filerw regression test\n");

  return 0;
}
