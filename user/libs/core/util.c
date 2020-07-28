
// this file pulls in the implementations for lots of common utility classes

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdint.h>
#include <stdarg.h>
#include <sys/types.h>
#include <dirent.h>

#include <nexus/tls.h>
#include <nexus/util.h>
#include <nexus/queue.h>
#include <nexus/hashtable.h>
#include <nexus/bitmap.h>
#include <nexus/vector.h>
#include <nexus/stringbuffer.h>
#include <nexus/handle.h>
#include <nexus/debug.h>

#include <openssl/sha.h>

#include <util-code.c>
#include <queue-code.c>
#include <hashtable-code.c>
#include <bitmap-code.c>
#include <vector-code.c>
#include <stringbuffer-code.c>
#include <mt19937ar-code.c>
#include <handle-code.c>

int dump_stack_trace_array(unsigned long *addrs, int numaddrs){
  unsigned int *fp;
  unsigned int ra;
  int i = 0;

  __asm("movl %%ebp,%%eax;":"=a"(fp));

  do{
    //printf("current ebp = 0x%p\n", fp);
    //printf("    old ebp = 0x%x\n", *fp);
    if(i >= numaddrs)
      break;
    ra = *(fp + 1);
    if(ra > 0x08000000){
      //printf("0x%x ", ra);
      addrs[i++] = ra;
    }
    fp = (unsigned int *)*fp;
  }while((ra > 0x08000000) && ((unsigned int)fp > 0x90000000));

  return i;
}

void dump_stack_trace(unsigned int *ebp){
  unsigned int *fp = ebp;
  unsigned int ra;

  printf("Stack trace\n");
  __asm("movl %%ebp,%%eax;":"=a"(fp));
  //printf("fp = 0x%p ebp = 0x%p\n", fp, ebp);
  if(ebp != NULL)
    fp = ebp;

  unsigned int firstaddr;
  __asm__("mov $.text, %0":"=r"(firstaddr));
  printf("firstaddr = 0x%x\n", firstaddr);

  do{
    ra = *(fp + 1);
    printf("0x%x ", ra);
    fp = (unsigned int *)*fp;
  }while((ra > firstaddr) && 
	 ((unsigned int)fp > 0x90000000) && ((unsigned int)fp < 0xc0000000) &&
	 (ra != (unsigned int)FIRST_COMMON_USER_FUNCTION));

  printf("<end>\n");
}

unsigned char *read_file(char *fname, int *len) {
  return read_file_dir(NULL, fname, len);
}

unsigned char *read_file_dir(char *dirname, char *fname, int *len)
{
  if (len) *len = 0;

  char *path = fname;
  if (dirname) {
    path = malloc(strlen(dirname) + 1 + strlen(fname) + 1);
    sprintf(path, "%s/%s", dirname, fname);
  }

  FILE *f = fopen(path, "r");
  if (dirname) free(path);
  if (!f) return NULL;

  fseek(f, 0, SEEK_END);
  int n = ftell(f);
  fseek(f, 0, SEEK_SET);
  if (n < 0) {
    fclose(f);
    return NULL;
  }

  unsigned char *buf = malloc(n+1);
  int m = (n > 0 ? fread(buf, n, 1, f) : 1);
  fclose(f);
  if (m != 1) {
    free(buf);
    return NULL;
  }
  buf[n] = '\0';
  if (len) *len = n;
  return buf;
}

int write_file(char *fname, unsigned char *data, int len) {
  return write_file_dir(NULL, fname, data, len);
}

int write_file_dir(char *dirname, char *fname, unsigned char *data, int len)
{
  char *path = fname;
  if (dirname) {
    path = malloc(strlen(dirname) + 1 + strlen(fname) + 1);
    sprintf(path, "%s/%s", dirname, fname);
  }

  FILE *f = fopen(path, "w");
  if (dirname) free(path);
  if (!f) return -1;

  int m = (len > 0 ? fwrite(data, len, 1, f) : 1);
  fclose(f);
  return (m != 1 ? -1 : 0);
}

int is_directory(char *dirname, char *fname) {
  char *path = fname;
  if (dirname) {
    path = malloc(strlen(dirname) + 1 + strlen(fname) + 1);
    sprintf(path, "%s/%s", dirname, fname);
  }
  DIR *d = opendir(path);
  int ret = (d ? 1 : 0);
  if (d) closedir(d);
  if (dirname) free(path);
  return ret;
}

char *file_hash(char *dirname, char *fname) {
  int len;
  unsigned char *buf = read_file_dir(dirname, fname, &len);
  if (!buf) return NULL;

  unsigned char *h = malloc(20);
  SHA1(buf, len, h);
  free(buf);
  return (char *) h;
}

