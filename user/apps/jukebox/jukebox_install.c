#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <nexus/util.h>
#include "../wpss/rwpss.h"
#include <nexus/Profile.interface.h>

POLICY my_policy = POLITE_REQUESTORS_ONLY;
GROUNDS my_grounds = PRETTY_PLEASE;

#define DEFAULT_SIZE (8192)
#define DEFAULT_NUM_UPDATES (1)
//#define DEFAULT_BLOCKSIZE (0)
#define DEFAULT_BLOCKSIZE (4096)

/* this doesn't do anything policy-wise yet, just create and archive an
 * empty rwpss to test with*/

int main(int argc, char **argv){
  printf("jukebox_install %s to %s counter %s\n", argv[1], argv[2], argv[3]);
  char *srcfile = argv[1];
  char *dstfile = argv[2];
  int counter = atoi(argv[3]);
  int ret;

#if 1
  int srcfd = open(srcfile, O_RDONLY);
  printf("lseek srcfd %d SEEK_END %d SEEK_SET %d\n", srcfd, SEEK_END, SEEK_SET);
  int len = lseek(srcfd, 0, SEEK_END);
  lseek(srcfd, 0, SEEK_SET);
  printf("len = %d\n", len);

  char *buffer = (char *)malloc(len);
    
  int dstfd = open(dstfile, O_RDWR|O_CREAT);

  unsigned char *addr;
  WPSS *wpss = rw_wpss_create(dstfd, &addr, len, dstfile, 
			my_policy, my_policy, my_policy, my_policy, 
			WPSS_RW, 
			DEFAULT_NUM_UPDATES, 
			DEFAULT_BLOCKSIZE);
  printf("wpss = 0x%p addr =0x%p\n", wpss, addr);
  if(wpss == NULL) {
    printf("WPSS not created, exiting\n");
    exit(-1);
  }
  int readlen = read(srcfd, buffer, len);
  printf("read %d into buffer\n", readlen);
  memcpy(addr,buffer,len);
  printf("read %d into rwpss\n", readlen);
  Profile_Enable(1);
  ret = rw_wpss_archive(wpss, my_grounds);
  Profile_Enable(0);
  Profile_Dump("install.profile");
  printf("archived, ret = %d\n", ret);
  close(srcfd);
  printf("closed srcfd %d\n", srcfd);

  close(dstfd);
#endif

  unsigned char *caddr;
  char *cname = get_string_ext(NULL,dstfile,".counter");
  int cfd = open(cname, O_RDWR|O_CREAT);
  WPSS *cwpss = rw_wpss_create(cfd, &caddr, sizeof(int), cname,
			       my_policy, my_policy, my_policy, my_policy,
			       WPSS_W,
			       1,
			       sizeof(int));
  printf("wpss = 0x%p addr =0x%p\n", cwpss, caddr);
  memcpy(caddr, &counter, sizeof(int));
  printf("copied number %d\n", *(int *)caddr);
  ret = rw_wpss_archive(cwpss, my_grounds);
  printf("archived, ret = %d\n", ret);

  put_string_ext(cname);

  close(cfd);

  return 0;
}
