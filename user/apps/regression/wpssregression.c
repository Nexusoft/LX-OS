/* This regression test tests the wpss. 
 * 1. create a new wpss of random size (max MAXSIZE).
 * 2. archive it.
 * 3. flush cached copy of region wpss_free
 * 4. retrieve it and check it matches what was archived via a hash.
 * 5. write to it.
 * 6. archive it.
 * 7. flush cached copy of region
 * 8. retrieve it and check it matches what was archived via a hash.
 * 9. file system write (outside the rwpsslib interface) to modify region (unauthorized!)
 * 10. flush cached copy of region
 * 11. retrieve it and make sure the retrieve fails
 * 12. destroy the wpss
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <openssl/sha.h>
#include <unistd.h>
//#include <nexus/malloc_checker.h>
#include <nexus/mt19937ar.h>
#include <nexus/util.h>
#include <apps/wpss/rwpss.h>

char *FILENAME;

#define MINSIZE (1024)
//#define MAXSIZE (4096)
#define MAXSIZE ((1024 * 1024) * 1)

#define SUBREGION_TESTS (10)

#if 0 /* the tests didn't test the right thing... */
#define HAND_TESTS 2  /* hand picked malicious tests for subregion tests. */
                      /* MALICIOUSi is executed every HAND_TESTS + 1 iterations */
#define MALICIOUS1 1 
#define MALICIOUS2 2 
#endif

#define ERRPRINT(x...) printf(x)

/* Retrieve region and check hashes.  The hashes are end-to-end so
 * should never fail.  If a failure was going to happen, it would have
 * happened inside the library. */
int shouldneverhappen = 0;
static WPSS *retrieve_check(int fd, char *file, unsigned char **ptr, 
			    GROUNDS retrieve_grounds, GROUNDS destroy_grounds,
			    int suboffset, int sublen, unsigned char *hashval){
  unsigned char hashvalcmp[20];
  WPSS *wpss;

  wpss = rw_wpss_retrieve(fd, file, retrieve_grounds, ptr, suboffset, sublen);
  if(wpss == NULL){
    ERRPRINT("retrieve of region from offset=%d len=%d failed!!!\n", 
	     suboffset, sublen);
    return NULL;
  }
  //printf("retrieved: %02x %02x %02x ... %02x %02x %02x\n", (*ptr)[0], (*ptr)[1], (*ptr)[2], (*ptr)[sublen - 3], (*ptr)[sublen - 2], (*ptr)[sublen - 1]);
  SHA1(*ptr, sublen, hashvalcmp);
  if(memcmp(hashval, hashvalcmp, 20) != 0){
    ERRPRINT("retrieve of region from offset=%d len=%d hash mismatch!!!\n", 
	   suboffset, sublen);
    rw_wpss_destroy(wpss, destroy_grounds);
    shouldneverhappen = 1;
    return NULL;
  }
  printf("success! (hash = %02x %02x %02x ...)\n", hashval[0], hashval[1], hashval[2]);
  return wpss;
}

#define usage_err()						\
  do{								\
    ERRPRINT("usage: wpssregression <wpss|rpwss> <0x5eed>\n");	\
    ERRPRINT("       [-file f] [-nowrites] [-sublen x] [-suboff y]\n");	\
    return -1;							\
  }while(0)

//12a17d


unsigned int seed = 0;
WPSSTYPE type;
int option_quick = 0;
int option_nowrite = 0;
int option_suboffset = 0;
int option_sublen = 0;
int option_size = 0;
int option_writes = -1;

#define OPTION(x) (strncmp(option, x, strlen(x)) == 0)
int parse_args(int argc, char**argv){
  int seed_init = 0;
  int type_init = 0;

  if((argc < 3))
    usage_err();

  FILENAME = "/nfs/wpssregression.wpss";

  int i;
  for(i = 1; i < argc; i++){
    /* get options */
    if(argv[i][0] == '-'){
      char *option = &((argv[i])[1]);
      if(OPTION("nowrite"))
	option_nowrite = 1;
      else if(OPTION("suboff")){
	if(i + 1 >= argc)
	  usage_err();
	option_suboffset = atoi(argv[++i]);
      }else if(OPTION("sublen")){
	if(i + 1 >= argc)
	  usage_err();
	option_sublen = atoi(argv[++i]);
      }else if(OPTION("writes")){
	if(i + 1 >= argc)
	  usage_err();
	option_writes = atoi(argv[++i]);
      }else if(OPTION("file")){
	if(i + 1 >= argc)
	  usage_err();
	FILENAME = argv[++i];
      }else{
	ERRPRINT("unrecognized option: %s\n", option);
	usage_err();
      }
      continue;
    }
    /* get seed */
    if((argv[i][0] == '0') && (argv[i][1] == 'x')){
      seed = strtoul(argv[i], NULL, 16);
      seed_init = 1;
      continue;
    }
    if(strncmp(argv[i], "rwpss", strlen("rwpss")) == 0){
      type = WPSS_RW;
      type_init = 1;
      continue;
    }
    if(strncmp(argv[i], "wpss", strlen("wpss")) == 0){
      type = WPSS_W;
      type_init = 1;
      continue;
    }
    if(strncmp(argv[i], "quick", strlen("quick")) == 0){
      option_quick = 1;
      continue;
    }
    usage_err();
  }

  if((seed_init == 0) || (type_init == 0)){
    usage_err();
  }
  return 0;
}

#if 0
/* was going to write more failures out... may as well just do one test at a time */
#define EXITMSGSIZE 256
char exitmsg[EXITMSGSIZE]
#define exit_write_failure(i,s,o,l,m)		
  
void write_fail(int size, int suboff, int sublen, int i, char *fmt, ...){
  
  va_list args;
  va_start(args, fmt);
  vsnprintf(exitmsg, EXITMSGSIZE, fmt, args);
  va_end(args);
}
#endif

//malloc_write_record();			
#define RETURN(x)				\
  do{						\
    int y = x;					\
    if (y != 0) printf("regression test fails (error = %d)!!!\n", y); \
    return y;					\
  }while(0)

int main(int argc, char **argv){
  unsigned char *region;
  unsigned char hashval[20];
  WPSS *wpss;
  int fd;
  int dbg = 0;

  //malloc_record_enable();
  parse_args(argc, argv);

  pseudorand_init(seed);

  /* pick a size at random at most MAXSIZE, at least MINSIZE and a
   * number of writes at most .1 percent of MAXSIZE */
  int size = pseudorand(MINSIZE, MAXSIZE);
  int percent = (MAXSIZE) / 1000;
  int writes = (option_writes == -1)?pseudorand(1, max(percent, 1)):option_writes;


  /* get a pseudo-random offset and len based on the seed */
  int suboffset = 0;
  int sublen = size;

  printf("WPSS regression test using seed 0x%x type=%s\n", seed, (type==WPSS_W)?"wpss":"rwpss");
  printf("pseudorand params: size=%10d writes=%10d suboff=%10d sublen=%10d\n", size, writes, suboffset, sublen);

  /* the options can over-ride the pseudo-rand parameters */
  size = (option_size == 0)?size:option_size;
  suboffset = option_suboffset;
  sublen = (option_sublen == 0)?sublen:min(size, option_sublen - suboffset);

  printf("overridden params: size=%10d writes=%10d suboff=%10d sublen=%10d\n", size, writes, suboffset, sublen);

  POLICY archive_policy, retrieve_policy, destroy_policy;
  archive_policy = retrieve_policy = destroy_policy = POLITE_REQUESTORS_ONLY;
  GROUNDS archive_grounds, retrieve_grounds, destroy_grounds;
  archive_grounds = retrieve_grounds = destroy_grounds = PRETTY_PLEASE;

  /* first time do full region, subsequent times do subregions */
  int i,j;
  for(i = 0; i < SUBREGION_TESTS + 1; i++){
    printf("\ntesting with suboffset=%d sublen=%d of %d byte region\n", suboffset, sublen, size);


    /* create wpss */
    fd = open(FILENAME, O_CREAT|O_RDWR|O_TRUNC);
    if(fd == -1){
      ERRPRINT("problem creating file %s!!!\n", FILENAME);
      RETURN(-1);
    }
    wpss = rw_wpss_create(fd, &region, size, FILENAME, 
			  archive_policy, retrieve_policy, destroy_policy, destroy_grounds,
			  type, writes, 0);
    if(wpss == NULL){
      ERRPRINT("problem creating wpss!!!\n");
      RETURN(-1);
    }
    int dataoff = rw_wpss_get_dataoff(wpss);


    /* test archive and retrieve with no writes */
    if(dbg)
      printf("region=0x%p, region+suboffset=0x%p sublen=%d region+len=0x%p\n", region, region+suboffset, sublen, region+size);

    SHA1(region + suboffset, sublen, hashval);

    if(dbg){
      printf("original:  %02x %02x %02x ... %02x %02x %02x\n", region[suboffset], region[suboffset + 1], region[suboffset + 2], region[suboffset + sublen - 3], region[suboffset + sublen - 2], region[suboffset + sublen - 1]);
    }
    
    printf("retreive after no writes should have hash %02x %02x %02x...\n", hashval[0], hashval[1], hashval[2]);

    rw_wpss_archive(wpss, archive_grounds);
    rw_wpss_free(wpss);
    wpss = retrieve_check(fd, FILENAME, &region, retrieve_grounds, destroy_grounds, suboffset, sublen, hashval);
    if(wpss == NULL){
      rw_wpss_destroy_no_handle(fd, FILENAME, destroy_grounds);
      RETURN(-1);
    }

    if(dbg)
      printf("retrieved region 0x%p-0x%p\n", region, region + sublen);

    if(option_nowrite != 1){
      /* test archive and retrieve with write authorized writes */
      for(j = 0; j < writes; j++){
	int loc = pseudorand(0, sublen - 1);
	char val = (char)pseudorand(0x00, 0xff);
	region[loc] = val;
	if(HT_DIRECT_BITMAP)
	  rw_wpss_notify_write(wpss, region+loc, sizeof(char));
      }
    }

    SHA1(region, sublen, hashval);

    printf("retreive after %d writes should have hash %02x %02x %02x...\n", writes, hashval[0], hashval[1], hashval[2]);
    rw_wpss_archive(wpss, archive_grounds);
    rw_wpss_free(wpss);
    wpss = retrieve_check(fd, FILENAME, &region, retrieve_grounds, destroy_grounds, suboffset, sublen, hashval);
    if(wpss == NULL){
      rw_wpss_destroy_no_handle(fd, FILENAME, destroy_grounds);
      RETURN(-1);
    }


    if(option_nowrite != 1){
      /* test retrieve with one unauthorized write */
      int unauthfd = open(FILENAME, O_RDWR);
      char val;
      int loc = pseudorand(dataoff + suboffset, dataoff + suboffset + sublen - 1);

      /* XXX not the right place for this 

      the malicious test should be a false negative by writing on a half block,
      but it shouldn't happen now.  hopefully, if there are any more corner cases,
      they'll show up through random number picks.

      if(i % (HAND_TESTS + 1) == MALICIOUS1)
      loc = max(dataoff, dataoff + suboffset - 1);
      if(i % (HAND_TESTS + 1) == MALICIOUS2)
      loc = min(dataoff + size, dataoff + suboffset + sublen + 1);
      */

      lseek(unauthfd, loc, SEEK_SET);
      read(unauthfd, &val, sizeof(char));
      val++;
      lseek(unauthfd, loc, SEEK_SET);
      write(unauthfd, &val, sizeof(char));
      fsync(unauthfd);
      close(unauthfd);


#if 1
      unauthfd = open(FILENAME, O_RDONLY);
      unsigned char *unauth = (unsigned char *)malloc(sublen);
      unsigned char unauthhash[20];
      lseek(unauthfd, dataoff + suboffset, SEEK_SET);
      read(unauthfd, unauth, sublen);
      if(dbg)
	printf("hashing %d bytes at 0x%p: ", sublen, unauth);
      SHA1(unauth, sublen, unauthhash);
      printf("hash of unauth is %02x %02x %02x...\n", unauthhash[0], unauthhash[1], unauthhash[2]);
      close(unauthfd);
      //free(unauth);
#endif


    
      printf("retreive after %d unauthorized writes should fail (test %d)\n", 1, i);
      wpss = retrieve_check(fd, FILENAME, &region, retrieve_grounds, destroy_grounds, suboffset, sublen, hashval);
      if(shouldneverhappen){
	ERRPRINT("retrieve backup should have failed!!!\n");
	rw_wpss_destroy_no_handle(fd, FILENAME, destroy_grounds);
	RETURN(-1);
      } 
    }

    /* destroy region (and free up the vdirs, etc) */
    rw_wpss_destroy_no_handle(fd, FILENAME, destroy_grounds);

    close(fd);

    /* get a new offset and len for next time around */
    suboffset = pseudorand(0, size - 4);
    sublen = pseudorand(4, size - suboffset);

    //malloc_write_record();			
    if (option_quick)
      break;
  }

  printf("regression test successful\n");

  RETURN(0);
}

