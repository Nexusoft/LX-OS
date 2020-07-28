#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "../wpss/rwpss.h"
#include <nexus/util.h>
#include <nexus/fs_mountpool.h>
#include <nexus/Thread.interface.h>
#include "Jukeboxctl.interface.h"
#include "jukebox.h"
#include "jukeboxctl.h"
#include "Jukebox.interface.h"

/* Jukebox implements a sort of loopback filesystem. It begins with a known
 * root, which can be anything, but is presumably "/nfs" or even "/".
 * For every fake_id we give out, we keep real_id, the underlying FSID somewhere
 * below root.
 * For Read(fake_id), we call wpss_retrieve(Read(real_id)).
 * For ReadDir(fake_id), we call ReadDir(real_id)
 * For Lookup(fake_id, name), we call real_id2=Lookup(real_id, name), then return fake_id2
 * For all others we return unsupported (the default)
 */

enum JUKEBOX_ERRORS {
  JUKEBOX_ACCESSERROR = 5000,
  JUKEBOX_CREATEERROR,
};

#define printf_dbg(x...) do { if(dbg)printf(x); } while (0)
int dbg = 1;

typedef struct JukeboxNode {
  FSID fake_id, real_id, real_parent_id;
  char *real_filename /*needed to find counter*/;
  char *real_filepath /*needed for vdirs*/;
} JukeboxNode;

typedef struct Counter {
  int val;
} Counter;

#define NUM_LOOKUPS (64)
struct HashTable *lookups; /* id ==> JukeboxNode */
struct HashTable *rlookups; /* real_id ==> JukeboxNode */

JukeboxNode *jukebox_node_priv(FSID fake_id) {
  return (JukeboxNode *)hash_findItem(lookups, &fake_id);
}
JukeboxNode *jukebox_node_pub(FSID real_id) {
  return (JukeboxNode *)hash_findItem(rlookups, &real_id);
}

// need mutex, but who cares
int next_id = 0;
JukeboxNode *jukebox_node_new(FSID real_id, JukeboxNode *parent, char *name) {
  JukeboxNode *juke = malloc(sizeof(JukeboxNode));
  juke->real_id = real_id;
  juke->real_parent_id = (parent ? parent->real_id : FSID_INVALID);
  juke->fake_id = (FSID){ .port = Jukebox_server_port_num, .nodetype = real_id.nodetype, .nodeid = next_id++ };
  juke->real_filename = strdup(name);
  juke->real_filepath = get_string_ext((parent ? parent->real_filepath : ""), "/", name);
  printf_dbg("Node_lookup_jukebox: adding new node %s:0x%p\n", juke->real_filepath, juke);
  hash_insert(lookups, &juke->fake_id, juke);
  hash_insert(rlookups, &juke->real_id, juke);
  return juke;
}

int decrement_counter(JukeboxNode *juke) {
#ifdef RETURN
#undef RETURN
#endif
#define RETURN(r)				\
  do{						\
    if (fd>0) close(fd);			\
    put_string_ext(filename);			\
    return r;					\
  }while(0)

  int fd;
  // todo: should really have some better way of getting from a known FSID to a fd
  // (here we know FSID of parent and can easily get FSID of counter too)
  char *filename = get_string_ext(NULL,juke->real_filepath,".counter");
  int ret = -1;
  WPSS *wpss;

  fd = open(filename, O_RDWR);
  if(fd == -1){
    printf("counter file %s not found\n", filename);
    RETURN(-1);
  }

  unsigned char *addr;
  wpss = rw_wpss_retrieve(fd, filename, 
			  PRETTY_PLEASE, &addr, 0, sizeof(Counter));
  if(wpss == NULL){
    printf("retrieve of counter file %s failed\n", filename);
    RETURN(-1);
  }
  
  Counter *c = (Counter *)addr;
  printf("counter val = %d\n", c->val);
  if(c->val >= 0) {
    ret = c->val--;
  }

  int arch = rw_wpss_archive(wpss, PRETTY_PLEASE);
  if(arch < 0){
    printf("archive of counter file %s failed\n", filename);
    RETURN(-1);
  }
    
  rw_wpss_free(wpss);
  
  RETURN(ret);
}

int jukebox_read(IPD_ID ipd_id, Call_Handle call_handle,
		      FSID target_node, int file_position,
		      /* __output__ */ struct VarLen dest, int count) {
  int dbg = 0;
  int dbg_visits = 0;

  printf_dbg("DAN: %s %d %d bytes (visit %d)\n", __FUNCTION__, __LINE__, count, dbg_visits);

  if(!jukebox_check_ipd(ipd_id)){
    printf("IPD has not been authenticated, so may not have proper refmon!!\n");
    return -JUKEBOX_ACCESSERROR;
  }

  unsigned char *addr;
  WPSS *wpss;
  JukeboxNode *juke = jukebox_node_priv(target_node);
  int fd;
  int dbg_timings = 0;

  printf_dbg("opening...\n");
  //todo: should really use real_id here, instead of resolving path again
  fd = open(juke->real_filepath, O_RDWR);
  printf_dbg("retrieving...");

  /* POLICY: block 1 can only be read k times */
  if(file_position == 0){
    int count;
    if((count = decrement_counter(juke)) < 0){
      printf("counter has expired for %s\n", juke->real_filename);
      return -JUKEBOX_ACCESSERROR;
    }
    if(count%4 == 0){
      printf("jukebox: %s: counter = %d\n", juke->real_filename, count/4);
    }
  }

  if(dbg_timings)
    rwpss_init_timings();

  printf_dbg("fd=%d, name=%s, file_pos=%d, count=%d\n", fd, juke->real_filename, file_position, count);

  wpss = rw_wpss_retrieve(fd, juke->real_filepath, 
			  PRETTY_PLEASE, &addr, file_position, count);
  if(dbg_timings){
    u64 *timings;
    int time_num = rwpss_get_timing_data(&timings);
    int time_i;
    for(time_i = 0; time_i < time_num; time_i++)
      printf("%d: %lld\n", time_i, timings[time_i]);
    //rwpss_free_timings(timings);
  }

  printf_dbg("wpss = 0x%p\n", wpss);
  close(fd);

  if(!wpss)
    return -JUKEBOX_ACCESSERROR;

  if(IPC_TransferTo(call_handle, dest.desc_num, (unsigned)dest.data, 
		    addr, count) != 0) {
    printf("read access error\n");
    return -FS_ACCESSERROR;
  }

  rw_wpss_free(wpss);

  return count;
}

FSID jukebox_lookup(FSID parent_node, char *filename, int resolve_mounts) {
  char *pathname;
  JukeboxNode *parent, *juke;
  int dbg = 0;

  printf_dbg("Node_lookup_jukebox: filename = %s\n", filename);

  parent = jukebox_node_priv(parent_node);
  if (!parent)
    return FSID_ERROR(FS_INVALID);

  FSID real_id = mountpool_lookup(0, parent->real_id, filename);
  if (FSID_getError(real_id))
    return real_id;

  /* should really do something smarter to check if underlying file changed */
  juke = jukebox_node_pub(real_id);
  if (!juke) juke = jukebox_node_new(real_id, parent, filename);
  return juke->fake_id;
}


#define NUM_IPC_THREADS (3)
static pthread_t ipc_threads[NUM_IPC_THREADS];
static pthread_t accept_threads[NUM_IPC_THREADS];
static pthread_t ipc_threads2[NUM_IPC_THREADS];
static pthread_t accept_threads2[NUM_IPC_THREADS];

static void *processing_loop(void *ctx) { while(1) { Jukebox_processNextCommand(); } }
static void *accept_loop(void *ctx) { while(1) { IDL_BINDACCEPT(Jukebox); printf("accepted new connection (jukeboxl)...\n"); } }
static void *processing_loop2(void *ctx) { while(1) { Jukeboxctl_processNextCommand(); } }
static void *accept_loop2(void *ctx) { while(1) { IDL_BINDACCEPT(Jukeboxctl); printf("accepted new connection (jukeboxctl)...\n"); } }

int main(int ac, char **av) {
  char *mount_path = NULL;
  char *real_path = NULL;

  printf("-------------------------------------------\n");
  printf("Jukebox -- loopback filesystem for DRM demo\n");
  printf("-------------------------------------------\n");

  ac--; av++;
  while (ac > 1) {
    if (!strcmp(av[0], "-mount"))
      mount_path = av[1];
    else if (!strcmp(av[0], "-name"))
      Custom_Jukebox_svc_name = av[1];
    else if (!strcmp(av[0], "-target"))
      real_path = av[1];
    else {
      printf("usage:\n\tjukebox [-mount filesystem_path] [-name ns_name] -target target_path\n");
      exit(1);
    }
    ac -= 2;
    av += 2;
  }
  if (ac || !real_path) {
    printf("usage:\n\tjukebox [-mount filesystem_path] [-name ns_name] -target target_path\n");
    exit(1);
  }

  lookups = hash_new(NUM_LOOKUPS, sizeof(FSID));
  rlookups = hash_new(NUM_LOOKUPS, sizeof(FSID));

  int fd = open(real_path, O_DIRECTORY);
  if (fd <= 0) {
    printf("can not open the real directory: %s\n", real_path);
    exit(1);
  }
  FSID real_id = fsid_from_fd(fd);
  close(fd);


  /* we have to mount before we chroot... even though jukebox isn't ready yet */
  Jukeboxctl_serverInit(); // can happen any time
  Jukebox_serverInit(); // must happen before mount, so that we know the port number
  if (mount_path) {
    if (mount(mount_path, FSID_ROOT(Jukebox_server_port_num)))
      printf("could not mount jukebox (target %s) as %s\n", real_path, mount_path);
    else
      printf("mounted jukebox (target %s) as %s\n", real_path, mount_path);
  }

  /* if (nexus_chroot(real_id)) {
    printf("cannot chroot to %s\n", real_path);
    exit(1);
  } 
  jukebox_node_new(real_id, NULL, "");
  */

  /* suppose real_path = "/nfs", mount_path = "/jukebox"
   * we can use chroot("/nfs"), real_path = "", then open("foo.counter"); this is safest;
   * or we can use real_path = "/nfs", then open("/nfs/foo.counter"); 
   * latter is slightly easier at the moment.
   */
  jukebox_node_new(real_id, NULL, strdup(real_path+1)); // name = "nfs" leads to real_path = "/nfs"

  int i;
  for(i=0; i < NUM_IPC_THREADS; i++) {
    if(pthread_create(&ipc_threads[i], NULL, processing_loop, (void *) i)) {
      printf("could not fork processing thread %d\n", i);
    }
    if(pthread_create(&accept_threads[i], NULL, accept_loop, (void *) i)) {
      printf("could not fork accept thread %d\n", i);
    }
    if(pthread_create(&ipc_threads2[i], NULL, processing_loop2, (void *) i)) {
      printf("could not fork processing thread %d\n", i);
    }
    if(pthread_create(&accept_threads2[i], NULL, accept_loop2, (void *) i)) {
      printf("could not fork accept thread %d\n", i);
    }
  }

  // signal that we are ready
  Thread_Notify(0);

  processing_loop(NULL);
  return 0;
}
