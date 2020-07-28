#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>
#include <stdlib.h>
#include <fcntl.h>
#include <nexus/timing.h>
#include <unistd.h>
#include <sys/mman.h>
#include <assert.h>

#include "../../compat/tpmcompat.h"
#include <nexus/hashtree.h>
#include <nexus/encblocks.h>
#include <nexus/util.h>
#include "blocksize.h"
#include "rwpss.h"
#include <nexus/SMR.interface.h>
#include <nexus/x86_emulate.h>
#include <openssl/sha.h>

#define NOWRITEFILE (1)
#define DBGRWPSS (0)

#if 0
#define HTTP
#ifdef HTTP
#define file_to_buffer(x...) mapfile_to_buffer_http(x)
#else
#define file_to_buffer(x...) mapfile_to_buffer(x)
#endif
#else
//fake writes
#define file_to_buffer(x...) 0
#endif

#if 1
#define unmap_readonly_macro(x...) unmap_readonly(x)
#else
#define unmap_readonly_macro(x...) do{}while(0)
#endif

#define ERRPRINT(x...) printf(x);

#define ENCKEYSIZE (1024)

enum RETRIEVE_TIMING{
  RT_hdrs = 0,                 /* 0 */
  RT_region_new,               /* 1 */
  RT_vdir_lookup,              /* 2 */
  RT_vdir_read,                /* 3 */
  RT_encblocks_create,         /* 4 */
  RT_io_data,                  /* 5 */
  RT_dbg1,                     /* 6 */
  RT_io_ht,                    /* 7 */
  RT_dbg2,                     /* 8 */
  RT_ht_create,                /* 9 */
  RT_dbg3,                     /* 10 */
  RT_ht_build,                 /* 11 */
  RT_dbg4,                     /* 12 */
  RT_hash_cmp,                 /* 13 */
  RT_vkeyold_lookup,              /* 14 */
  RT_io_enckey,                /* 15 */
  RT_vkeyold_read,                /* 16 */
  RT_encblocks_compute,        /* 17 */
  RT_readonly,                 /* 18 */

  RT_SIZE,
};

enum RWPSS_TIMING{
  TIMING_RWPSS_RETRIEVE_MAP=0,
  TIMING_RWPSS_RETRIEVE_VDIR,
  TIMING_RWPSS_RETRIEVE_VKEYOLD,
  TIMING_RWPSS_RETRIEVE_VDIR_LOOKUP,
  TIMING_RWPSS_RETRIEVE_VKEYOLD_LOOKUP,
  TIMING_RWPSS_RETRIEVE_IO_W,
  TIMING_RWPSS_RETRIEVE_IO_RW,
  TIMING_RWPSS_RETRIEVE_HT,
  TIMING_RWPSS_RETRIEVE_AES,
  
  TIMING_RWPSS_DESTROY_VDIR,
  TIMING_RWPSS_DESTROY_VKEYOLD,
  TIMING_RWPSS_DESTROY_HT,

  TIMING_RWPSS_CREATE_MAP,
  TIMING_RWPSS_CREATE_VDIR,
  TIMING_RWPSS_CREATE_VKEYOLD,
  TIMING_RWPSS_CREATE_HT,

  TIMING_RWPSS_ARCHIVE_VDIR,
  TIMING_RWPSS_ARCHIVE_VKEYOLD,
  TIMING_RWPSS_ARCHIVE_HT,
  TIMING_RWPSS_ARCHIVE_IO,
  TIMING_RWPSS_ARCHIVE_AES,

  TIMING_RWPSS_SIZE,
};

struct Timing *rwpsstiming = NULL;
struct Timing *retrieve_times = NULL;
void rwpss_init_timings(void){
  ht_init_timings();
  rwpsstiming = timing_new_anon(TIMING_RWPSS_SIZE);
  retrieve_times = timing_new_anon(RT_SIZE);
}
struct Timing *rwpss_get_timings(int *numtimings){
  *numtimings = TIMING_RWPSS_SIZE;
  return rwpsstiming;
}
int rwpss_get_timing_data(u64 **data){
  *data = (u64 *)malloc(sizeof(RT_SIZE * sizeof(u64)));
  timing_getData(retrieve_times, *data);
  return RT_SIZE;
}
void rwpss_free_timings(u64 *data){
  free(data);
}

typedef struct WPSSHdr WPSSHdr;
struct WPSSHdr{
  WPSSTYPE type;
  int len;
  int blocksize;
  int num_updates;
  /* int enckeylen;*/
};

/* macros to dissect a WPSSHdr of the disk representation */
#define HDRLEN(r)   (sizeof(WPSSHdr))
#define EKEYLEN(r)   (0) /* ((r)->enckeylen) */
#define HTLEN(r)    (ht_get_size((r)->len, (r)->blocksize))
#define DATALEN(r)  ((r)->len)
#define TOTALLEN(r) (HDRLEN(r) + EKEYLEN(r) + HTLEN(r) + DATALEN(r))

#define HDROFF(r)   (0)
#define EKEYOFF(r)  (HDRLEN(r)  + HDROFF(r))
#define HTOFF(r)    (EKEYLEN(r) + EKEYOFF(r))
#define DATAOFF(r)  (HTLEN(r)   + HTOFF(r))

/* macros to point to the buffers in a WPSS struct */
#define HDRBUF(w)   ((unsigned char *)(w))
#define EKEYBUF(w)  (NULL)/* ((w)->enckey) */
#define HTBUF(w)    ((w)->htbuf)
#define DATABUF(w)  ((w)->diskfmt)

#define DATAFORDISK(w) ((w->type == WPSS_RW)?				\
			encblocks_getbuf(CIPHER,w->encblocks):		\
			encblocks_getbuf(PLAIN,w->encblocks))
#define DATAFROMDISK(w) (DATAFORDISK(w))
#define DATAFORHT(w) (DATAFORDISK(w))

#define RETRIEVE_TYPE(w) ((w->type == WPSS_RW)?(CIPHER):(PLAIN))
#define ARCHIVE_TYPE(w) (RETRIEVE_TYPE(w))

typedef enum WrittenState WrittenState;
enum WrittenState{
  WRITTEN = 1,
  NOT_WRITTEN,
};

void dumphdr(WPSSHdr *hdr){
  //printf("type=%s len=%d bs=%d num=%d enkeylen=%d\n", (hdr->type == WPSS_RW)?"RWPSS":"WPSS", hdr->len, hdr->blocksize, hdr->num_updates, hdr->enckeylen);
  printf("type=%s len=%d bs=%d num=%d\n", (hdr->type == WPSS_RW)?"RWPSS":"WPSS", hdr->len, hdr->blocksize, hdr->num_updates);
}

struct WPSS{
  /* start WPSS Hdr */
  WPSSTYPE type;  
  int len;
  int blocksize;
  int num_updates;
  /* int enckeylen;*/
  /* end WPSS Hdr */

  char *name;
  int fd;

  VDIR vdir;
  VKEYOLD vkeyold;

  unsigned char *roaddr;
  unsigned char *rwaddr;

  int suboffset;
  int sublen;

  Hashtree *ht;
  unsigned char *htbuf;

  Keys keys;
  EncBlocks *encblocks;
  /* unsigned char *enckey;*/

  WrittenState written;
};

typedef struct WPSSListItem WPSSListItem;
struct WPSSListItem{
  WPSSListItem *next;
  WPSSListItem *prev;
  WPSS *this;
};
WPSSListItem *wpss_head;

int rw_wpss_get_sublen(WPSS *w){
  return w->sublen;
}

/* utility function to find a WPSS from this session based on addr and len */
static WPSS *find_wpss(unsigned char *addr, int len){
  WPSSListItem *ptr = wpss_head;

  while(ptr != NULL){
    if(((unsigned int)addr >= (unsigned int)ptr->this->roaddr) && 
       ((unsigned int)addr + len <= (unsigned int)ptr->this->roaddr + ptr->this->len))
      return ptr->this;
    ptr = ptr->next;
  }

  return NULL;
}

void rw_wpss_notify_write(WPSS *w, unsigned char *addr, int size){
  int changedsize;
  unsigned char *changedptr;

  //printf("%s: 0x%p-0x%p wrote=0x%p\n", __FUNCTION__, w->rwaddr, w->rwaddr+w->sublen, addr);

  //printf("wrote 0x%p-0x%p for encblocks\n", addr, addr+size);
  encblocks_set_bitmap(w->encblocks, addr, size, &changedptr, &changedsize);
  //printf("wrote 0x%p-0x%p for ht\n", changedptr, changedptr+changedsize);

  if(w->type == WPSS_W){
    ht_set_bitmap(w->ht, addr, size);
  }else{
    ht_set_bitmap(w->ht, changedptr, changedsize);
  }
}

#if 0
/* perform a write to the rw mapping of the region, and mark the block
 * for hashtree update. */
int write_update(unsigned int addr, unsigned int val, unsigned int size){
  WPSS *w;
  unsigned int offset;
  int i;
  int dbg = 0;

  if(dbg)printf("write update 0x%x 0x%x %d\n", addr, val, size);

  w = find_wpss((char *)addr, size);
  if(w == NULL){
    ERRPRINT("No WPSS found for 0x%x, %d\n", addr, size);
    return -1;
  }

  offset = (unsigned int)addr - (unsigned int)w->roaddr;

  if(dbg)printf("to 0x%p\n", w->rwaddr + offset);

  if(size == sizeof(char))
    *(w->rwaddr + offset) = val & 0xff;
  else if(size == sizeof(int))
    *(unsigned int *)(w->rwaddr + offset) = val;
  else{
    for(i = 0; i < size; i += sizeof(int))
      *(unsigned int *)(w->rwaddr + offset + i) = val;
  }

  rw_wpss_notify_write(w, w->rwaddr + offset, size);

  return 0;
}
#endif

int x86_emulate_read_rwpss(enum x86_segment seg,
			   unsigned long vaddr,
			   unsigned long *val,
			   unsigned int bytes,
			   struct x86_emulate_ctxt *ctxt){
  /* This is only designed to work with instructions that read and
     write where the write faults (e.g. inc).  It will get into an
     infinite loop? if called from a read fault. */

  return x86_emulate_do_read(vaddr, val, bytes);
}
int x86_emulate_write_rwpss(enum x86_segment seg,
			    unsigned long addr,
			    unsigned long val,
			    unsigned int size,
			    struct x86_emulate_ctxt *ctxt){
  WPSS *w;
  int dbg = 0;

  if(dbg)printf("write update 0x%lx 0x%lx %d\n", addr, val, size);

  w = find_wpss((unsigned char *)addr, size);
  if(w == NULL){
    ERRPRINT("No WPSS found for 0x%lx, %d\n", addr, size);
    return X86EMUL_UNHANDLEABLE;
  }

  int offset = (unsigned int)addr - (unsigned int)w->roaddr;
  unsigned char *target = (unsigned char *)w->rwaddr + offset;

  if(dbg)printf("to 0x%p\n", w->rwaddr + offset);

  int ret = x86_emulate_do_write((unsigned long)target, val, size);

  if(ret != X86EMUL_CONTINUE)
    return ret;

  rw_wpss_notify_write(w, w->rwaddr + offset, size);

  return X86EMUL_CONTINUE;
}

/* utility function that mallocs a name with a suffix */
static char *create_namestring(char *name, char *suf){
  int namelen;
  char *newname;

  namelen = strlen(name) + strlen(suf) + 1;
  newname = (char *)malloc(namelen);
  strncpy(newname, name, strlen(name));
  strncpy(newname + strlen(name), suf, strlen(suf));
  newname[namelen - 1] = '\0';
  
  return newname;
}
static void free_namestring(char *name){
  free(name);
}

/* to make sure we read all len bytes */
static int read_all(int fd, unsigned char *databuf, int len){
    int totalread = 0, numread = 0;					   
    int dbg = 0;

    if(dbg)printf("reading...");
    while(totalread < len){						   
      numread = read(fd, databuf, len);					   
      if(numread <= 0){							   
	ERRPRINT("couldn't get data from file; got %d so far\n", totalread); 
	return -1;							   
      }									   
      totalread += numread;						   
    }				
    if(dbg)printf("done reading\n");					   
    return 0;
}


/* to support abstraction-breaking notification of updates to region */
Hashtree *rw_wpss_get_ht(WPSS *w){return w->ht;}


/* copy backup data on top of old data */
void rwpss_copy_from_backup(WPSS *w, int backfd){
  BackupBlock block;
  int numread = 0, totalread = 0;
  int dbg = 0;

  for(;;){
    unsigned char *tmpbuf;
    numread = read(backfd, &block, sizeof(BackupBlock));

    if(dbg){
      totalread += numread;
      printf("read hdr %d total %d\n", numread, totalread);
    }

    if(numread != sizeof(BackupBlock)){
      if(dbg)
	printf("read %d!!!\n", numread);
      break;
    }

    tmpbuf = (unsigned char *)malloc(block.len);
    numread = read(backfd, tmpbuf, block.len);

    if(dbg){
      totalread += numread;
      printf("read data %d total %d\n", numread, totalread);
    }

    if(numread != block.len){
      printf("read %d, should have %d!!!\n", numread, block.len);
      break;
    }

    if(dbg)
      printf("overwriting offset %d len %d\n", block.offset, block.len);

    lseek(w->fd, block.offset, SEEK_SET);
    write(w->fd, tmpbuf, block.len);
    
    free(tmpbuf);
  }
  fsync(w->fd);
}

#define BACKUPNAMELEN(w) (strlen((w)->name) + strlen(".backup") + 1)
#define GET_BACKUPNAME(w, n)					\
  do{								\
    strcpy((n), (w)->name);					\
    strcpy((n) + strlen(w->name), ".backup");			\
    (n)[BACKUPNAMELEN(w) - 1] = 0;				\
  }while(0);


/* Archiving the region involves updating the hashtree and placing the
 * hash in the vdir.  XXX writing must be atomic (use vdir_rebind)
 */
int rw_wpss_archive(WPSS *w, GROUNDS archive_grounds) {
  unsigned char *tmphash;
  int written = 0;
  int dbg = 0;

  /* if we have never written the region to disk, don't bother with the backup */
  if(w->written == WRITTEN){
    char *backupname = (char *)malloc(BACKUPNAMELEN(w));
    GET_BACKUPNAME(w, backupname);

    int backupfd, backupoffset;
    
    backupfd = open(backupname, O_CREAT|O_TRUNC|O_RDWR);
    free(backupname);

    backupoffset = 0;
    
    /* encrypt touched blocks (if rwpss) and write backup block to backupfd */
    backupoffset += encblocks_update_backup(ARCHIVE_TYPE(w), w->encblocks, 
					    backupfd, DATAOFF(w));

    timing_start(rwpsstiming, TIMING_RWPSS_ARCHIVE_HT);
    tmphash = ht_update_hashtree(w->ht);
    timing_end(rwpsstiming, TIMING_RWPSS_ARCHIVE_HT);

    /* write out new hashtree to backup log */
    BackupBlock backup;
    backup.offset = HTOFF(w);
    backup.len = HTLEN(w);
    lseek(backupfd, backupoffset, SEEK_SET);
    backupoffset += write(backupfd, &backup, sizeof(BackupBlock));
    lseek(backupfd, backupoffset, SEEK_SET);
    backupoffset += write(backupfd, HTBUF(w), HTLEN(w));

    fsync(backupfd);

    /* write new value to vdir */
    timing_start(rwpsstiming, TIMING_RWPSS_ARCHIVE_VDIR);
    if(vdir_write(w->vdir, tmphash, archive_grounds) < 0){
      ERRPRINT("VDIR write failed!!!!");
      return -1;
    }
    timing_end(rwpsstiming, TIMING_RWPSS_ARCHIVE_VDIR);

    lseek(backupfd, 0, SEEK_SET);
    rwpss_copy_from_backup(w, backupfd);
    close(backupfd);
  }
  if(w->written == NOT_WRITTEN){
    /* only write out header and encryption keys once */

    if(dbg)printf("seek to %d, write 0x%p %d\n", HDROFF(w), HDRBUF(w), HDRLEN(w));

    lseek(w->fd, HDROFF(w), SEEK_SET);
    written += write(w->fd, HDRBUF(w), HDRLEN(w));

#if 0
    if(w->type == WPSS_RW){
      if(dbg)printf("seek to %d, write 0x%p %d\n", EKEYOFF(w), EKEYBUF(w), EKEYLEN(w));
      lseek(w->fd, EKEYOFF(w), SEEK_SET);
      written += write(w->fd, EKEYBUF(w), EKEYLEN(w));
    }
#endif

    /* need to compute and write the entire region */
    written = encblocks_writeall(ARCHIVE_TYPE(w), w->encblocks, w->fd, DATAOFF(w));

    timing_start(rwpsstiming, TIMING_RWPSS_ARCHIVE_HT);
    tmphash = ht_update_hashtree(w->ht);
    timing_end(rwpsstiming, TIMING_RWPSS_ARCHIVE_HT);

    if(dbg)printf("seek to %d, write 0x%p %d\n", HTOFF(w), HTBUF(w), HTLEN(w));
    lseek(w->fd, HTOFF(w), SEEK_SET);
    written += write(w->fd, HTBUF(w), HTLEN(w));

    if(dbg)printf("synching...");
    fsync(w->fd);
    if(dbg)printf("synched.\n");
    w->written = WRITTEN;

    /* write new value to vdir */
    timing_start(rwpsstiming, TIMING_RWPSS_ARCHIVE_VDIR);
    if(vdir_write(w->vdir, tmphash, archive_grounds) < 0){
      ERRPRINT("VDIR write failed!!!!");
      return -1;
    }
    timing_end(rwpsstiming, TIMING_RWPSS_ARCHIVE_VDIR);
  }

  return 0;
}

/* If retrieving a WPSS, fetch the file into the specified location,
 * construct a hashtree and check that the root matches the hash
 * stored in the vdir.  If retrieving a RWPSS, fetch the encrypted AES
 * key and decrypt it with the VKEYOLD (the hash of the unencrypted AES
 * key is checked in the kernel on a VKEYOLD operation to prevent replay
 * of an encrypted blob).  Fetch the encrypted memory region, decrypt
 * if with the AES key, construct the hashtree and check the root
 * hash.
 */


/* After region new, the only things that need to be created/retrieved are: 
 * 1. Encblocks               VDIR
 * 2. Keys                    Encblocks
 * 3. VKEYOLDs                   hashtree
 * 4. hashtree                Vkeyolds
 * 5. VDIR                    Keys
 * 6. readonly                readonly
 */
static WPSS *region_new(WPSSHdr *hdr, char *name, int fd, int suboffset, int sublen){
  int blocksize;
  int len;
  WPSS *new;
  int dbg = 0;

  if(hdr->blocksize == 0)
    blocksize = blocksize_get_opt(hdr->len, hdr->num_updates);
  else
    blocksize = hdr->blocksize;
  
  if(hdr->type == WPSS_RW){
    len = hdr->len = encblocks_round_len(hdr->len, blocksize);
    blocksize = encblocks_check_blocksize(blocksize);
  }else{
    len = hdr->len;
  }

  if(dbg)printf("%s: got %d as a blocksize\n", __FUNCTION__, blocksize);
  if(dbg)printf("%s: got %d as a len\n", __FUNCTION__, len);

  if(suboffset > len){
    ERRPRINT("Trying to retrieve offset %d greater than len %d!!!", suboffset, len);
    return NULL;
  }

  /* round the suboffset and sublen to lie on hashtree block boundaries */
  ht_round_to_block(blocksize, &suboffset, &sublen);
  sublen = min(sublen, DATALEN(hdr) - suboffset);

  /* new struct */
  new = (WPSS *)malloc(sizeof(WPSS));
  new->type = hdr->type;
  new->len = len;
  new->blocksize = blocksize;
  new->num_updates = hdr->num_updates;
  /* new->enckeylen = 0;*/

  new->name = (char *)malloc(strlen(name) + 1);
  strncpy(new->name, name, strlen(name));
  new->name[strlen(name)] = '\0';
  new->fd = dup(fd);

  new->vdir = 0;
  new->vkeyold = 0;

  new->roaddr = NULL;
  new->rwaddr = NULL;

  new->suboffset = suboffset;
  new->sublen = sublen;

  new->ht = NULL;
  new->htbuf = (unsigned char *)malloc(HTLEN(new));

  new->encblocks = NULL;
  /*
  if(new->type == WPSS_RW){
    new->enckeylen = hdr->enckeylen;
    new->enckey = (unsigned char *)malloc(new->enckeylen);
  }
  */
  return new;
}

/* destroy a region and release resources (even if only partially built) */
static void region_destroy(WPSS *w, GROUNDS flush_grounds){
  if (!w)
    return;
  switch(w->type){
  case WPSS_RW:
    if (w->vkeyold) vkeyold_destroy(w->vkeyold, flush_grounds);
    // fall through
  case WPSS_W:
    if (w->roaddr) unmap_readonly(w->roaddr, w->sublen);
    if (w->fd >= 0) close(w->fd);
    if (w->ht) ht_destroy_hashtree(w->ht);
    if (w->encblocks) encblocks_destroy(w->encblocks);
    if (w->vdir) vdir_destroy(w->vdir, flush_grounds);
    free(w);
    break;
  default:
    assert(0);
  }
}

int rw_wpss_get_dataoff(WPSS *w){
  return DATAOFF(w);
}

/* add the new wpss to a list that is searched through for the
   corresponding wpss on a page fault */
void wpss_list_add(WPSS *new){
  WPSSListItem *listitem;
  int dbg = 0;

  if(dbg)printf("Adding new wpss for 0x%p, %d", new->rwaddr, new->len);
  listitem = (WPSSListItem *)malloc(sizeof(WPSSListItem));
  listitem->next = wpss_head;
  listitem->prev = NULL;
  listitem->this = new;
  if(wpss_head != NULL)
    wpss_head->prev = listitem;
  wpss_head = listitem;
}

/* remap region of size sublen at origaddr to *roaddr */
static int rwpss_setup_readonly(WPSS *new, unsigned char *origaddr, 
				unsigned char **roaddr, unsigned char **rwaddr, 
				int sublen){
  int dbg = 0;
  *rwaddr = origaddr;

  timing_start(rwpsstiming, TIMING_RWPSS_RETRIEVE_MAP);

  if(dbg)printf("*rwaddr=0x%p, sublen=%d (0x%p)\n", *rwaddr, sublen, *rwaddr + sublen);
  if(dbg)printf("mapping %d at 0x%p (0x%p)\n", sublen, *rwaddr, *rwaddr +  sublen);

  *roaddr = (unsigned char *)remap_readonly((unsigned int)*rwaddr, sublen);
  if(*roaddr == NULL)
    return -1;
  timing_end(rwpsstiming, TIMING_RWPSS_RETRIEVE_MAP);

  //register_pf_write(write_update);
  if(dbg)printf("registering pf handler\n");
  register_pf_handler_write(x86_emulate_write_rwpss);
  register_pf_handler_read(x86_emulate_read_rwpss);
  //SMR_RegisterTrap(pf_handler);
  if(dbg)printf("mapped %d roaddr=0x%p-0x%p rwaddr=0x%p-0x%p\n", sublen, *roaddr, *roaddr+sublen, *rwaddr, *rwaddr+sublen);

  wpss_list_add(new);

  return 0;
}

int check_wpss_hdr(WPSSHdr *hdr){
  if((hdr->type != WPSS_RW) && (hdr->type != WPSS_W))
    return -1;
  if(hdr->len < 1)
    return -1;
  if(hdr->blocksize < 1)
    return -1;
  if(hdr->num_updates < 1)
    return -1;
  return 0;
}

unsigned char datacheckhash[20];

int rw_wpss_retrieve_datalen(int fd){
  WPSSHdr tmphdr;
  int dbg = 0;

  /* get wpss hdr */
  lseek(fd, 0, SEEK_SET);
  if(dbg)printf("reading hdr: ");
  if(read_all(fd, (unsigned char *)&tmphdr, sizeof(WPSSHdr)) < 0)
    return -1;

  if(check_wpss_hdr(&tmphdr) < 0){
    ERRPRINT("trying to retrieve something not a wpss!\n");
    return -1;
  }

  return tmphdr.len;
}


WPSS *rw_wpss_retrieve_helper(int fd, char *name, GROUNDS retrieve_grounds, 
		       unsigned char **addr, int suboffset, int sublen, 
		       int secondtry){
  WPSS *new;
  char *vdirname;
  unsigned char vdirdata[TCPA_HASH_SIZE];
  WPSSHdr tmphdr;
  int dbg = 0;
 
  timing_start(retrieve_times, RT_hdrs);

  if(sublen <= 0){
    ERRPRINT("trying to retrieve a region of length %d\n", sublen);
    return NULL;
  }

  /* get wpss hdr */
  lseek(fd, 0, SEEK_SET);
  if(dbg)printf("reading hdr: ");
  if(read_all(fd, (unsigned char *)&tmphdr, sizeof(WPSSHdr)) < 0)
    return NULL;

  if(check_wpss_hdr(&tmphdr) < 0){
    ERRPRINT("trying to retrieve something not a wpss!\n");
    return NULL;
  }

  timing_end(retrieve_times, RT_hdrs);
  timing_start(retrieve_times, RT_region_new);

  /* create new struct */
  new = region_new(&tmphdr, name, fd, suboffset, sublen);
  if(new == NULL)
    return NULL;

  timing_end(retrieve_times, RT_region_new);
  timing_start(retrieve_times, RT_vdir_lookup);

  /* lookup vdir */
  vdirname = create_namestring(name, ".VDIR");
  if(dbg)printf("looking up vdir %s...", vdirname);
  new->vdir = vdir_lookup(vdirname);
  if(new->vdir == 0){
    ERRPRINT("RETRIEVE: didn't find vdir %s\n", vdirname);
    free_namestring(vdirname);
    region_destroy(new, NULL_GROUNDS);
    return 0;
  }
  if(dbg)printf("found vdir %d\n", new->vdir);

  timing_end(retrieve_times, RT_vdir_lookup);
  timing_start(retrieve_times, RT_vdir_read);

  /* read vdir value */
  if(vdir_read(new->vdir, vdirdata, retrieve_grounds) < 0){
    ERRPRINT("RETRIEVE: couldn't read vdir %d %s\n", new->vdir, vdirname);
    free_namestring(vdirname);
    region_destroy(new, NULL_GROUNDS);
    return 0;
  }
  free_namestring(vdirname);
  if(dbg)printf("read vdir %02x %02x %02x...", vdirdata[0], vdirdata[1], vdirdata[2]);

  timing_end(retrieve_times, RT_vdir_read);
  timing_start(retrieve_times, RT_encblocks_create);

  /* create some encblocks and read the data into the cipher or plain buffer */
  if(dbg)printf("encblocks: len=%d blocksize=%d suboffset=%d sublen=%d\n", new->len, new->blocksize, new->suboffset, new->sublen);
  new->encblocks = encblocks_create(RETRIEVE_TYPE(new), new->len, 
				    new->blocksize, new->suboffset, new->sublen);

  timing_end(retrieve_times, RT_encblocks_create);
  timing_start(retrieve_times, RT_io_data);

  lseek(fd, DATAOFF(new) + new->suboffset, SEEK_SET);

  if(dbg)
    printf("reading data: from offset %d + %d, len = %d to 0x%p\n", DATAOFF(new), new->suboffset, new->sublen, DATAFROMDISK(new));

  if(read_all(fd, DATAFROMDISK(new), new->sublen) < 0){
    region_destroy(new, NULL_GROUNDS);
    return NULL;
  }

  timing_end(retrieve_times, RT_io_data);
  timing_start(retrieve_times, RT_dbg1);

  if(dbg){
    SHA1(DATAFROMDISK(new), new->sublen, datacheckhash);
    printf("data hash on retr = offset=%d len=%d %02x %02x %02x ...\n", new->suboffset, new->sublen, datacheckhash[0], datacheckhash[1], datacheckhash[2]);
  }

  timing_end(retrieve_times, RT_dbg1);
  timing_start(retrieve_times, RT_io_ht);

  /* read the hashtree into buffer */
  lseek(fd, HTOFF(new), SEEK_SET);
  if(dbg)printf("reading ht: ");
  if(read_all(fd, new->htbuf, HTLEN(new)) < 0){
    region_destroy(new, NULL_GROUNDS);
    return NULL;
  }

  timing_end(retrieve_times, RT_io_ht);
  timing_start(retrieve_times, RT_dbg2);

  if(dbg){
    unsigned char htcheckhash[20];
    SHA1(new->htbuf, HTLEN(new), htcheckhash);
    printf("ht hash on retr = %02x %02x %02x ...\n", htcheckhash[0], htcheckhash[1], htcheckhash[2]);
  }

  timing_end(retrieve_times, RT_dbg2);
  timing_start(retrieve_times, RT_ht_create);

  /* build hashtree */
  int htlen = HTLEN(new);
  new->ht = ht_create_hashtree_to_buf(DATAFROMDISK(new) - new->suboffset, new->len, 
				      new->blocksize, new->htbuf, &htlen);

  timing_end(retrieve_times, RT_ht_create);
  timing_start(retrieve_times, RT_dbg3);

  if(dbg){
    unsigned char htcheckhash[20];
    SHA1(new->htbuf, HTLEN(new), htcheckhash);
    printf("ht hash on retr = %02x %02x %02x ...\n", htcheckhash[0], htcheckhash[1], htcheckhash[2]);
  }

  assert(htlen == HTLEN(new));

  timing_end(retrieve_times, RT_dbg3);
  timing_start(retrieve_times, RT_ht_build);

  ht_build_hashtree(new->ht, new->suboffset, new->sublen);

  timing_end(retrieve_times, RT_ht_build);
  timing_start(retrieve_times, RT_dbg4);

  if(dbg){
    unsigned char htcheckhash[20];
    SHA1(new->htbuf, HTLEN(new), htcheckhash);
    printf("ht hash on retr = %02x %02x %02x ...\n", htcheckhash[0], htcheckhash[1], htcheckhash[2]);
  }

  timing_end(retrieve_times, RT_dbg4);
  timing_start(retrieve_times, RT_hash_cmp);

  /* check hashes */
  unsigned char *regionhash = ht_get_root(new->ht);
  if(memcmp(vdirdata, regionhash, TCPA_HASH_SIZE) != 0){
    if(!secondtry){
      /* maybe it was a crash before log was written on top */
      ERRPRINT("Retrieve failed.. attempting to use backup\n");
      char *backupname = (char *)malloc(BACKUPNAMELEN(new));
      GET_BACKUPNAME(new, backupname);

      int backupfd = open(backupname, O_RDONLY);
      free(backupname);

      rwpss_copy_from_backup(new, backupfd);
      region_destroy(new, NULL_GROUNDS);
      
      return rw_wpss_retrieve_helper(fd, name, retrieve_grounds, addr, 
				     suboffset, sublen, 1);
    }

    ERRPRINT("RETRIEVE: hashes didn't match %02x %02x %02x ... != %02x %02x %02x ...\n", regionhash[0], regionhash[1], regionhash[2], vdirdata[0], vdirdata[1], vdirdata[2]);
    region_destroy(new, NULL_GROUNDS);
    return NULL;
  }

  timing_end(retrieve_times, RT_hash_cmp);

  /* get vkeyold to decrypt keys */
  if(new->type == WPSS_RW){

    timing_start(retrieve_times, RT_vkeyold_lookup);

    char *vkeyoldname;
    vkeyoldname = create_namestring(name, ".VKEYOLD");
    new->vkeyold = vkeyold_lookup(vkeyoldname);
    if(new->vkeyold == 0){
      ERRPRINT("RETRIEVE: didn't find vkeyold %s\n", vkeyoldname);
      free_namestring(vkeyoldname);
      region_destroy(new, NULL_GROUNDS);
      return 0;
    }

    timing_end(retrieve_times, RT_vkeyold_lookup);
    timing_start(retrieve_times, RT_io_enckey);

    /* get enckey from disk */
#if 0
    lseek(fd, EKEYOFF(new), SEEK_SET);
    if(dbg)printf("reading ht: ");
    if(read_all(fd, new->enckey, new->enckeylen) < 0){
      region_destroy(new, NULL_GROUNDS);
      return NULL;
    }
#endif

    timing_end(retrieve_times, RT_io_enckey);
    timing_start(retrieve_times, RT_vkeyold_read);

    if(vkeyold_read(new->vkeyold, 
		 /*new->enckey, new->enckeylen, */
		 (unsigned char *)encblocks_get_keys(new->encblocks), sizeof(Keys), 
		 retrieve_grounds) < 0){
      ERRPRINT("RETRIEVE: couldn't read vkeyold %d %s\n", new->vkeyold, vkeyoldname);
      free_namestring(vkeyoldname);
      region_destroy(new, NULL_GROUNDS);
    }

    timing_end(retrieve_times, RT_vkeyold_read);
    timing_start(retrieve_times, RT_encblocks_compute);

    free_namestring(vkeyoldname);
    encblocks_activate_keys(new->encblocks);

    /* decrypt subregion*/
    encblocks_compute(PLAIN, new->encblocks, new->suboffset, new->sublen);

    timing_end(retrieve_times, RT_encblocks_compute);
  }

  timing_start(retrieve_times, RT_readonly);

  if(HT_MAPPED_BITMAP){
    int ret;
    ret = rwpss_setup_readonly(new, encblocks_getbuf(PLAIN, new->encblocks), 
			       &new->roaddr, &new->rwaddr, 
			       new->sublen);
    if(ret < 0){
      region_destroy(new, NULL_GROUNDS);
      return NULL;
    }

    *addr = new->roaddr;
  }else{
    *addr = new->rwaddr = encblocks_getbuf(PLAIN, new->encblocks);
  }
  
  /* add to the pointer to get to the non-rounded offset */
  *addr += suboffset - new->suboffset;
  new->written = WRITTEN;

  timing_end(retrieve_times, RT_readonly);

  return new;
}

WPSS *rw_wpss_retrieve(int fd, char *name, GROUNDS retrieve_grounds, 
		       unsigned char **addr, int suboffset, int sublen){
  return rw_wpss_retrieve_helper(fd, name, retrieve_grounds, addr, suboffset, sublen, 0);
}

/* Destroy a WPSS/RWPSS and free all kernel structures that it holds.
 * An RWPSS has both a vdir and vkeyold to destroy, a WPSS just has a
 * vdir.  
 */
int rw_wpss_destroy(WPSS *w, GROUNDS destroy_grounds){
  int ret = 0;

  if(w->type == WPSS_RW){
    timing_start(rwpsstiming, TIMING_RWPSS_DESTROY_VKEYOLD);
    if((w->vkeyold == 0) || (vkeyold_destroy(w->vkeyold, destroy_grounds) < 0))
      ret = -1;
    timing_end(rwpsstiming, TIMING_RWPSS_DESTROY_VKEYOLD);
  }


  timing_start(rwpsstiming, TIMING_RWPSS_DESTROY_VDIR);
  if((w->vdir == 0) || (vdir_destroy(w->vdir, destroy_grounds) < 0))
    ret = -1;
  timing_end(rwpsstiming, TIMING_RWPSS_DESTROY_VDIR);


  rw_wpss_free(w);


  return ret;
}

int rw_wpss_destroy_no_handle(int fd, char *file, GROUNDS destroy_grounds){
  char *vdirname;
  char *vkeyoldname;
  int ret;
  VDIR v;
  int dbg = 0;

  vdirname = create_namestring(file, ".VDIR");
  v = vdir_lookup(vdirname);
  free_namestring(vdirname);

  if(dbg)printf("found vdir = 0x%x\n", v);

  ret = vdir_destroy(v, destroy_grounds);

  if(dbg)printf("vdir_destroy returned %d\n", ret);


  vkeyoldname = create_namestring(file, ".VKEYOLD");
  v = vkeyold_lookup(vkeyoldname);
  free_namestring(vkeyoldname);

  if(v != 0){
    ret = vkeyold_destroy(v, destroy_grounds);
    if(dbg)printf("vkeyold_destroy returned %d\n", ret);
  }

  return ret;
}



/* free but don't destroy wpss */
/* XXX flush from file cache */
void rw_wpss_free(WPSS *w){
  int dbg = 0;

  if(dbg)printf("%s: unmapping readonly 0x%p %d\n", __FUNCTION__, w->roaddr, w->sublen);

  if(HT_MAPPED_BITMAP){
    unmap_readonly(w->roaddr, w->sublen);
  }

#if 0
  if(dbg)printf("%s: freeing enckey 0x%p\n", __FUNCTION__, w->enckey);

  if(w->type == WPSS_RW){
    if(w->enckey != NULL)
      free(w->enckey);
  }
#endif

  if(dbg)printf("%s: ht destroy 0x%p\n", __FUNCTION__, w->ht);

  timing_start(rwpsstiming, TIMING_RWPSS_DESTROY_HT);
  ht_destroy_hashtree(w->ht);
  timing_end(rwpsstiming, TIMING_RWPSS_DESTROY_HT);

  if(dbg)printf("%s: free htbuf 0x%p %d\n", __FUNCTION__, w->htbuf, HTLEN(w));
  /* XXX is this right?*/
  free(w->htbuf);

  if(dbg)printf("%s: destroy encblocks 0x%p\n", __FUNCTION__, w->encblocks);

  encblocks_destroy(w->encblocks);


  if(dbg)printf("%s: free name 0x%p\n", __FUNCTION__, w->name);

  close(w->fd);

  free(w->name);
  free(w);
}


/* Create a WPSS/RWPSS by allocating a vdir, creating a hashtree over
 * the region, and in the case of a RWPSS, creating an AES key and
 * allocating a vkeyold.
 */

/* XXX From the paper this is SMR_create(fs, len, name, acls, n, enc,
 *     addr*) that creates a region of length len and protects it by a
 *     num_updates=n hashtree and stores it on fs with name, then sets
 *     addr to point to it.
 */
WPSS *rw_wpss_create(int fd, unsigned char **addr, int len, char *name, 
		     POLICY archive_policy, POLICY retrieve_policy, POLICY destroy_policy,
		     GROUNDS flush_grounds, WPSSTYPE type, int num_updates, 
		     int blocksize){
  WPSS *new;
  WPSSHdr tmphdr = {.type = type,
		    .len = len,
		    .blocksize = blocksize,
		    .num_updates = num_updates,
		    /*.enckeylen = ENCKEYSIZE*/};
  int dbg = 0;

  new = region_new(&tmphdr, name, fd, 0, tmphdr.len);
  if(dbg)printf("%s:%s:%d\n",__FILE__,__FUNCTION__,__LINE__);
  new->encblocks = encblocks_create(PLAIN, new->len, new->blocksize, new->suboffset, new->sublen);
  if(dbg)printf("%s:%s:%d\n",__FILE__,__FUNCTION__,__LINE__);

  /* create a vkeyold */
  if(type == WPSS_RW){
    char *vkeyoldname;
    if(dbg)printf("%s:%s:%d\n",__FILE__,__FUNCTION__,__LINE__);
    vkeyoldname = create_namestring(name, ".VKEYOLD");
    if(dbg)printf("%s:%s:%d\n",__FILE__,__FUNCTION__,__LINE__);

    encblocks_generate_keys(new->encblocks);
    if(dbg)printf("%s:%s:%d\n",__FILE__,__FUNCTION__,__LINE__);
    encblocks_activate_keys(new->encblocks);
    if(dbg)printf("%s:%s:%d\n",__FILE__,__FUNCTION__,__LINE__);
    encblocks_compute(CIPHER, new->encblocks, new->suboffset, new->sublen);
    if(dbg)printf("%s:%s:%d\n",__FILE__,__FUNCTION__,__LINE__);

    if(dbg)printf("creating new vkeyold...");
    timing_start(rwpsstiming, TIMING_RWPSS_CREATE_VKEYOLD);
    new->vkeyold = vkeyold_create(vkeyoldname, 
			    (unsigned char *)encblocks_get_keys(new->encblocks), sizeof(Keys), 
			    /* new->enckey, &new->enckeylen,*/
			    archive_policy, retrieve_policy, destroy_policy);
    if(dbg)printf("%s:%s:%d\n",__FILE__,__FUNCTION__,__LINE__);
    if(dbg)printf("%d %s\n", new->vkeyold, vkeyoldname);
    free_namestring(vkeyoldname);
    timing_end(rwpsstiming, TIMING_RWPSS_CREATE_VKEYOLD);

    if(new->vkeyold == 0){
      region_destroy(new, flush_grounds);
      ERRPRINT("Could not get VKEYOLD!\n");
      return NULL;
    }

  }
  
  if(dbg)printf("%s:%s:%d\n",__FILE__,__FUNCTION__,__LINE__);

  int htlen = HTLEN(new);
  if(dbg)printf("%s:%s:%d\n",__FILE__,__FUNCTION__,__LINE__);
  new->ht = ht_create_hashtree_to_buf(DATAFORDISK(new), new->len, 
				      new->blocksize, new->htbuf, &htlen);
  if(dbg)printf("%s:%s:%d\n",__FILE__,__FUNCTION__,__LINE__);
  assert(htlen == HTLEN(new));
  if(dbg)printf("%s:%s:%d\n",__FILE__,__FUNCTION__,__LINE__);
  ht_build_hashtree(new->ht, 0, new->len);

  if(dbg)printf("%s:%s:%d\n",__FILE__,__FUNCTION__,__LINE__);

  /* create a vdir */
  timing_start(rwpsstiming, TIMING_RWPSS_CREATE_VDIR);
  char *vdirname;
  vdirname = create_namestring(name, ".VDIR");
  if(dbg)printf("creating vdir name %s\n",vdirname);
  if(dbg)printf("%s:%s:%d\n",__FILE__,__FUNCTION__,__LINE__);
  new->vdir = vdir_create(vdirname, ht_get_root(new->ht), TCPA_HASH_SIZE, archive_policy, retrieve_policy, destroy_policy);
  if(dbg)printf("%s:%s:%d\n",__FILE__,__FUNCTION__,__LINE__);
  free_namestring(vdirname);
  timing_end(rwpsstiming, TIMING_RWPSS_CREATE_VDIR);
  if(new->vdir == 0){
    region_destroy(new, flush_grounds);
    ERRPRINT("Could not get VDIR!\n");
    return NULL;
  }

  if(dbg)printf("%s:%s:%d\n",__FILE__,__FUNCTION__,__LINE__);

  if(HT_MAPPED_BITMAP){
    int ret;
    if(dbg)printf("%s:%s:%d\n",__FILE__,__FUNCTION__,__LINE__);
    ret = rwpss_setup_readonly(new, encblocks_getbuf(PLAIN, new->encblocks), 
			       &new->roaddr, &new->rwaddr, 
			       new->len);
    if(ret < 0){
      region_destroy(new, flush_grounds);
      return NULL;
    }

    *addr = new->roaddr;
  }else{
    *addr = new->rwaddr = encblocks_getbuf(PLAIN, new->encblocks);
  }
  if(dbg)printf("%s:%s:%d\n",__FILE__,__FUNCTION__,__LINE__);
  new->written = NOT_WRITTEN;

  return new;
}

