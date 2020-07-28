#include<stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "rwpss.h"
#include <nexus/timing.h>
#include <nexus/Debug.interface.h>

/* pseudo-random number generator */
#include <nexus/mt19937ar.h>

/* needed because direct bitmap ht update style breaks ht abstraction. */
#include "hashtree.h"

#define RWPSSTEST_TIMING 0

enum RWPSSTEST_TIMINGS{
  TIMING_RWPSSTEST_CREATE_W=0,
  TIMING_RWPSSTEST_ARCHIVE_W,
  TIMING_RWPSSTEST_RETRIEVE_W,
  TIMING_RWPSSTEST_WRITE,
  TIMING_RWPSSTEST_DESTROY_W,

  TIMING_RWPSSTEST_SIZE,
};

#define TIMING_RESET(x) if(RWPSSTEST_TIMING)timing_reset(x)
#define TIMING_START(x,y) if(RWPSSTEST_TIMING)timing_start(x,y)
#define TIMING_END(x,y) if(RWPSSTEST_TIMING)timing_end(x,y)

#ifndef rdtsc
#define rdtsc(low,high) __asm__ __volatile__("rdtsc" : "=a" (low), "=d" (high))
#endif

#define DBGRWPSSTEST 1
#define DBGPRINT(x...) if(DBGRWPSSTEST)printf(x)

#define PSSTYPE "WPSS"

#define MB (1024*1024)
#define TOTAL (64*MB + 100*MB)

POLICY archive_policy, retrieve_policy, destroy_policy;
GROUNDS archive_grounds, retrieve_grounds, destroy_grounds;

char wpssname[256];
char rwpssname[256];
char dumpname[256];



/* XXX fix
void write_out_timings(struct Timing *timing, char *s, int size, int writes, int trial){
  int dumpoff = 0;
  char *dumpbuf;
  int dumpbuflen = (TIMING_SIZE + 1) * 32;

  dumpbuf = malloc(dumpbuflen + 32);

  memset(dumpname, 0, 256);
  sprintf(dumpname, "TEST_dump_%s_%d_%d_%d", s, size, writes, trial);
  dumpoff += sprintf(dumpbuf, "%d %d ", writes, size);
  dump_timing(timing, TIMING_SIZE, dumpbuf + dumpoff, &dumpbuflen);
  dumpoff += dumpbuflen;
  dumpoff += sprintf(dumpbuf + dumpoff, "\n");
  writefile(dumpname, dumpbuf, dumpoff);
  free(dumpbuf);
}
*/

void parse_args(int argc, char **argv,
		int *blocksize, int *writes, int *oldtrial,
		int *secretsize_start, int *secretsize_end, int *inc, int *dec, 
		int *retroffset, int *retrofflen, int *divinc, int *mulinc){
  int logscale = 0;
  int i;

  for(i = 0; i < argc; i++){
    printf("argv[%d] = %s\n", i, argv[i]);
    if(strcmp("logscale", argv[i]) == 0){
      logscale = 1;
    }else{
      if(i + 1 >= argc){
	printf("usage: rwpsstest <SIZE_START s1> <SIZE_END s2> <INC i> <DEC i> <TRIALS t> <logscale> <BS blocksize> <WRITES writes>");
	exit(-1);
      }
      else if(strcmp("BS",argv[i]) == 0){
	if(!(strcmp("OPT",argv[i+1]) == 0)){
	  *blocksize = atoi(argv[++i]);
	}
      }
      else if(strcmp("WRITES",argv[i]) == 0){
	*writes = atoi(argv[++i]);
      }
      else if(strcmp("TRIALS",argv[i]) == 0){
	*oldtrial = atoi(argv[++i]);
      }
      else if(strcmp("SIZE_START",argv[i]) == 0){
	*secretsize_start = atoi(argv[++i]);
      }
      else if(strcmp("SIZE_END",argv[i]) == 0){
	*secretsize_end = atoi(argv[++i]);
      }
      else if(strcmp("INC",argv[i]) == 0){
	*inc = atoi(argv[++i]);
	*dec = -1;
      }
      else if(strcmp("DEC",argv[i]) == 0){
	*inc = atoi(argv[++i]);
	*dec = 1;
      }
      else if(strcmp("RETROFF",argv[i]) == 0){
	*retroffset = atoi(argv[++i]);
      }
      else if(strcmp("RETRLEN",argv[i]) == 0){
	*retrofflen = atoi(argv[++i]);
      }
    }
  }

  /* more input parsing */
  if(logscale == 0){
    *divinc = 1;
    *mulinc = 1;
  }else{
    if(*dec == 1){
      *divinc = *inc;
      *mulinc = 1;
    }else{
      *divinc = 1;
      *mulinc = *inc;
    }
    *inc = 0;
  }

}

int main(int argc, char **argv){
  int fd, ret, writes=0, i;
  WPSS *hdl;
  struct Timing *timing;
  int oldwrites, trial = 0;
  int secretsize = 0;
  int secretsize_start = 0;
  int secretsize_end = 0;
  int oldtrial = 0;
  int blocksize = 0;
  int inc = 0;
  int divinc = 0;
  int mulinc = 0;
  int dec = 0;
  int retroffset = 0,retrofflen = 0;
  unsigned char *bigptr;

  printf("%p\n",&fd);

  parse_args(argc, argv,
	     &blocksize, &writes, &oldtrial,
	     &secretsize_start, &secretsize_end, &inc, &dec, 
	     &retroffset, &retrofflen, &divinc, &mulinc);

  if(RWPSSTEST_TIMING){
    timing = timing_new_anon(TIMING_RWPSSTEST_SIZE);
    //XXX malloc_set_timings has disappeared - now only alan's malloc timings remain
    //malloc_set_timings(timing);  
  }

  DBGPRINT("RWPSSTEST\n");

  archive_policy = retrieve_policy = destroy_policy = POLITE_REQUESTORS_ONLY;
  archive_grounds = retrieve_grounds = destroy_grounds = PRETTY_PLEASE;

#if 0
  /* XXX calling the TPM for rand slows down EVERYTHING */
  unsigned int seed;
  nexusrand((unsigned char *)&seed, sizeof(unsigned int));
  seed = seed % 256;
  printf("SEED is %d\n", seed);
  init_genrand(seed);
#else
  unsigned int seed;
  unsigned int trash;
  rdtsc(seed, trash);
  init_genrand(seed);
#endif

  printf("(pages used = %d)\n", Debug_PagesUsed());

  //printf("rwpsstest: %s BS=%d WRITES=%d TRIALS=%d\n",(logscale)?"logscale":"",blocksize,writes,oldtrial);
  //printf("for(secretsize = %d; %ssecretsize >= %s%d; secretsize = %d*secretsize/%d + %d)\n",
  //secretsize_start, (dec==-1)?"-":"", (dec==-1)?"-":"", secretsize_end, mulinc,divinc, dec * -1 * inc);

  oldwrites = writes;

  for(secretsize = secretsize_start; dec * (secretsize - secretsize_end) >= 0; secretsize = mulinc * secretsize / divinc + -1 * dec * inc){
    printf("secretsize = %d\n", secretsize);
    //for(secretsize = 256 * 1024 * 1024; secretsize >= 16*1024 *1024; secretsize-= 16*1024*1024){
    //oldwrites = writes = secretsize/2000;
    for(writes = 1; writes <= oldwrites; writes += max(oldwrites/20,1)){
    //for(writes = oldwrites + 1; writes > 0; writes -= oldwrites/20){
    //for(writes = oldwrites + 1 - oldwrites/20; writes == oldwrites + 1 - oldwrites/20; writes -= oldwrites/20){
    //for(writes = oldwrites; writes == oldwrites; writes++){
      memset(rwpssname, 0, 256);
      sprintf(rwpssname, "/nfs/TEST_RWPSS_%d_%d.rwpss", secretsize, writes);
      memset(wpssname, 0, 256);
      sprintf(wpssname, "/nfs/TEST_WPSS_%d_%d.rwpss", secretsize, writes);

      /* reset all timings */
      TIMING_RESET(timing);

      printf("creating WPSS\n");
      fd = open(wpssname, O_CREAT|O_WRONLY|O_TRUNC);

      TIMING_START(timing, TIMING_RWPSSTEST_CREATE_W);

      hdl = rw_wpss_create(fd, &bigptr, secretsize, wpssname, 
			   archive_policy, retrieve_policy, destroy_policy, 
			   destroy_grounds, WPSS_W, writes, blocksize);

      TIMING_END(timing, TIMING_RWPSSTEST_CREATE_W);
      DBGPRINT("created WPSS with handle 0x%p\n", hdl);
      //write_out_timings(timing, "create", secretsize, writes, 0);

      if(hdl == NULL){
	printf("create failed, exiting..\n");
	exit(-1);
      }
      
      DBGPRINT("first archive (pages used = %d)\n", Debug_PagesUsed());
      TIMING_RESET(timing);
      TIMING_START(timing, TIMING_RWPSSTEST_ARCHIVE_W);

      ret = rw_wpss_archive(hdl, archive_grounds);//, timing);

      TIMING_END(timing, TIMING_RWPSSTEST_ARCHIVE_W);
      //write_out_timings(timing, "firstarchive", secretsize, writes, 0);

      rw_wpss_free(hdl);//, timing);

      for(trial = 1; trial <= oldtrial; trial++){
	printf("retrieving wpss offset=%d len=%d\n",retroffset, min(retrofflen,secretsize));
	TIMING_RESET(timing);    
	TIMING_START(timing, TIMING_RWPSSTEST_RETRIEVE_W);	
	printf("bigptr was 0x%p\n", bigptr);
	hdl = rw_wpss_retrieve(fd, wpssname, retrieve_grounds, &bigptr, retroffset, min(retrofflen,secretsize));//, timing);
	printf("bigptr now 0x%p\n", bigptr);
	TIMING_END(timing, TIMING_RWPSSTEST_RETRIEVE_W);
	//write_out_timings(timing, (hdl == NULL)?"retrievefail":"retrieve", secretsize, writes, trial);

	if(hdl == NULL){
	  printf("failed, exiting..\n");
	  exit(-1);
	}
	printf("(pages used = %d)\n", Debug_PagesUsed());
	TIMING_RESET(timing);
	/* Perform writes to region */
	printf("starting %d writes\n", writes);
	for(i = 0; i < writes; i++){
	  unsigned int loc;
	  unsigned char locval;

	  //nexusrand((unsigned char *)&loc, sizeof(unsigned int));
	  loc = (unsigned int)genrand_int32();
	  DBGPRINT("origloc=0x%x retrofflen=%d retroffset=%d\n", loc, retrofflen,retroffset);
	  loc = (loc % (min(retrofflen,secretsize))) + retroffset;
	  locval = 0xff & (loc % 256);
	  DBGPRINT("loc = 0x%x, locval = %02x, &ptr[loc]=0x%p", loc, locval, &bigptr[loc]);
    
	  printf("writing %d to 0x%p\n", 0x5, &bigptr[loc]);
	  //TIMING_START(timing, TIMING_RWPSSTEST_WRITE);
	  //bigptr[loc] = locval;
	  bigptr[loc] = 0x5;

	  if(HT_DIRECT_BITMAP){
	      ht_set_bitmap(rw_wpss_get_ht(hdl), &bigptr[loc], sizeof(char));
	  }

	  //TIMING_END(timing, TIMING_RWPSSTEST_WRITE);
	}
	printf("finished %d writes\n", writes);
	//write_out_timings(timing, "write", secretsize, writes, trial);

	TIMING_RESET(timing);
	DBGPRINT("wrote to wpss (pages used = %d)\n", Debug_PagesUsed());
	TIMING_START(timing, TIMING_RWPSSTEST_ARCHIVE_W);
	ret = rw_wpss_archive(hdl, archive_grounds);//, timing);
	TIMING_END(timing, TIMING_RWPSSTEST_ARCHIVE_W);
	//write_out_timings(timing, "archive", secretsize, writes, trial);
      
	/* free wpss (but leave vdir) so that it does a retrieve next time */
	rw_wpss_free(hdl);//, timing);
	printf("archive returned %d\n", ret);
	//}
	//}
#if 0
	TIMING_RESET(timing);
	TIMING_START(timing, TIMING_RWPSSTEST_DESTROY_W);
	rw_wpss_destroy(hdl, archive_grounds, timing);
	TIMING_END(timing, TIMING_RWPSSTEST_DESTROY_W);
	//write_out_timings(timing, "destroy", secretsize, writes, trial);
#endif
      }
    }
  }
  return 0;
}

