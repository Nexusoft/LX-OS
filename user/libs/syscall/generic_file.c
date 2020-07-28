/** NexusOS: This file implements the demultiplexing code for file descriptors, and
             juggles between sockets, the console, the keyboard, files (aka posixfile),
             and a few special case devices (audio, random, ..)
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/uio.h>

#include <nexus/queue.h>
#include <nexus/vector.h>
#include <nexus/hashtable.h>
#include <nexus/sema.h>
#include <nexus/linuxcalls_io.h>
#include <nexus/machine-structs.h>
#include <nexus/init.h>

#include <nexus/Console.interface.h>
#include <nexus/Thread.interface.h>

#include "io.private.h"

#define Error(STR,...) fprintf(stderr, STR,##__VA_ARGS__)

/* some functions have a 64 after them for longer file sizes and offsets 
 * which aren't supported */
#define WARN_ON_UNIMPLEMENTED64 (1)
#define FAIL_ON_UNIMPLEMENTED64 (1)
#define UNIMPLEMENTED64  do{						\
    if(WARN_ON_UNIMPLEMENTED64 || FAIL_ON_UNIMPLEMENTED64)			\
      printf("COMPAT: %s not implemented64!! (%s,%d)\n", __FUNCTION__, __FILE__, __LINE__); \
    if(FAIL_ON_UNIMPLEMENTED64)						\
      assert(0);							\
  }while(0)


#define WARN_ON_UNIMPLEMENTED (1)
#define FAIL_ON_UNIMPLEMENTED (1)
#define UNIMPLEMENTED  do{						\
    if(WARN_ON_UNIMPLEMENTED || FAIL_ON_UNIMPLEMENTED)			\
      printf("COMPAT: %s not implemented!! (%s,%d)\n", __FUNCTION__, __FILE__, __LINE__); \
    if(FAIL_ON_UNIMPLEMENTED)						\
      assert(0);							\
  }while(0)

static Sema fd_table_mutex = SEMA_MUTEX_INIT;
struct HashTable *fd_table; // int => GenericDescriptor
static int next_fh;

extern GenericDescriptor_operations File_ops;
extern GenericDescriptor_operations Dir_ops;
extern GenericDescriptor_operations UserAudio_ops;
extern GenericDescriptor_operations Stdin_ops;
extern GenericDescriptor_operations Stdout_ops;
extern GenericDescriptor_operations Stderr_ops;
extern GenericDescriptor_operations random_ops;
extern GenericDescriptor_operations urandom_ops;

extern GenericDescriptor_operations socket_ops;

extern GenericDescriptor_operations pipe_ops;


static void GenericDescriptor_assignHandle_specific(GenericDescriptor *d, int fd);
static GenericDescriptor *GenericDescriptor_new(const GenericDescriptor_operations *ops);

// XXX wrap implementation init routines in here (__posixfile_init)
void generic_file_init(void) {
  fd_table = hash_new(128, sizeof(int));

  GenericDescriptor *d;
  d = GenericDescriptor_new(&Stdin_ops);
  GenericDescriptor_assignHandle_specific(d, STDIN_FILENO /* 0 */);
  d = GenericDescriptor_new(&Stdout_ops);
  GenericDescriptor_assignHandle_specific(d, STDOUT_FILENO /* 1 */);
  d = GenericDescriptor_new(&Stderr_ops);
  GenericDescriptor_assignHandle_specific(d, STDERR_FILENO /* 2 */);
}

static void GenericDescriptor_get(GenericDescriptor *desc);
void GenericDescriptor_put(GenericDescriptor *desc);

// precondition: fd_table_mutex is acquired
static GenericDescriptor *__GenericDescriptor_find(int fd) {
  GenericDescriptor *desc = hash_findItem(fd_table, &fd);
  if(desc == NULL){ 
    return NULL;
  }
  GenericDescriptor_get(desc);
  return desc;
}

GenericDescriptor *GenericDescriptor_find(int fd) {
  GenericDescriptor *rv;
  P(&fd_table_mutex);
  rv = __GenericDescriptor_find(fd);
  V_nexus(&fd_table_mutex);
  return rv;
}

static void GenericDescriptor_get(GenericDescriptor *d) {
  atomic_addto(&d->refcnt, 1);
}

void GenericDescriptor_put(GenericDescriptor *d) {
  atomic_subtractfrom(&d->refcnt, 1);
  if(d->refcnt == 0) {
    d->ops->destroy(d);
    free(d);
  }
}

// Precondition: fd_table_mutex is held
static void GenericDescriptor_assignHandle_specific(GenericDescriptor *d, int fd) {
  assert(hash_findItem(fd_table, &fd) == NULL);
  hash_insert(fd_table, &fd, d);
  GenericDescriptor_get(d);
}

static int __GenericDescriptor_assignHandle(GenericDescriptor *d) {
  int fh;
  while(1) {
    fh = next_fh++;
    if(next_fh < 0) {
      next_fh = 0;
    }
    if(hash_findItem(fd_table, &fh) == NULL) {
      GenericDescriptor_assignHandle_specific(d, fh);
      break;
    }
  }
  return fh;
}

// XXX: Unlike assignHandle(), unassignHandle() DOES NOT want the fd
// table semaphore held.
// This is because we want to avoid holding the semaphore across the
// PUT operation, which might block
static void GenericDescriptor_unassignHandle(int fd) {
  P(&fd_table_mutex);
  void *prev, *entry = hash_findEntry(fd_table, &fd, &prev);
  GenericDescriptor *desc = hash_entryToItem(entry);
  hash_deleteEntry(fd_table, entry, prev);
  V_nexus(&fd_table_mutex);
  GenericDescriptor_put(desc);
}


static GenericDescriptor *GenericDescriptor_new(const GenericDescriptor_operations *ops) {
  GenericDescriptor *d = malloc(sizeof(GenericDescriptor));
  memset(d, 0, sizeof(GenericDescriptor));

  d->ops = ops;
  return d;
}

int nxlibc_syscall_open(const char *pathname, int flags, int mode) {
  GenericDescriptor *d;

  // XXX This is a hack. Should add support for special nodes into the filesystem
  if(pathname == NULL) {
    errno = EFAULT;
    return -1;
  }

  if(strcmp(pathname, "/dev/dsp") == 0){
    d = GenericDescriptor_new(&UserAudio_ops);
  } else if(strcmp(pathname, "/dev/random") == 0){
    d = GenericDescriptor_new(&random_ops);
  } else if(strcmp(pathname, "/dev/urandom") == 0){
    d = GenericDescriptor_new(&urandom_ops);
  } else {
    d = GenericDescriptor_new(&File_ops);
  }

  P(&fd_table_mutex);
  int fd = __GenericDescriptor_assignHandle(d);
  V_nexus(&fd_table_mutex);

  if(d->ops->open(d, pathname, flags, mode) == 0) {
    return fd;
  } else {
    // Error("open handler \"%s\" failed\n", pathname);
    // N.B. deallocation occurs at a lower call level: unassign will
    // implicitly free the memory
    GenericDescriptor_unassignHandle(fd);
    return -1;
  }
}

int nxlibc_syscall_pipe(int filedes[2]) {
  // filedes[0] := reading
  // filedes[1] := writing
  GenericDescriptor *reader = GenericDescriptor_new(&pipe_ops),
    *writer = GenericDescriptor_new(&pipe_ops);
  pipe_init(reader, writer);
  filedes[0] = __GenericDescriptor_assignHandle(reader);
  filedes[1] = __GenericDescriptor_assignHandle(writer);
  return 0;
}

int nxlibc_syscall_accept(int fd, struct sockaddr *addr, socklen_t *addrlen) {
  GenericDescriptor *d = GenericDescriptor_find(fd);

  void *private;
  int err = d->ops->accept(d, addr, addrlen, &private);
  GenericDescriptor_put(d);
  if(err == 0) {
    GenericDescriptor *nd = GenericDescriptor_new(d->ops);
    nd->private = private;
    
    P(&fd_table_mutex);
    int fd = __GenericDescriptor_assignHandle(nd);
    V_nexus(&fd_table_mutex);
    return fd;
  } else {
    return -1;
  }
}

int nxlibc_syscall_socket(int domain, int type, int protocol) {
  int fd;

  // verify type
  if (domain != PF_INET ||
      (type != SOCK_STREAM && type != SOCK_DGRAM && type != SOCK_RAW)) {
    Error("socket(..): Unknown type (%d,%d,%d)\n", domain, type, protocol);
    errno = EINVAL;
    return -1;
  }

  // have lwip create socket
  GenericDescriptor *d = GenericDescriptor_new(&socket_ops);
  if (d->ops->socket(d, domain, type, protocol) != 0) {
    GenericDescriptor_put(d);
    return -1;
  } 
  
  // assign file descriptor
  P(&fd_table_mutex);
  fd = __GenericDescriptor_assignHandle(d);
  V_nexus(&fd_table_mutex);
  return fd;
}

int nxlibc_syscall_dup(int oldfd) {
  GenericDescriptor *d;
  int newfd;

  P(&fd_table_mutex);
  d = __GenericDescriptor_find(oldfd);
  if(d == NULL) {
    errno = EBADF;
    V_nexus(&fd_table_mutex);
    return -1;
  }
  newfd = __GenericDescriptor_assignHandle(d);
  V_nexus(&fd_table_mutex);
  return newfd;
}

int nxlibc_syscall_dup2(int oldfd, int newfd)
{
  GenericDescriptor *nd, *od;

  P(&fd_table_mutex);

  // verify that oldfd is a valid descriptor
  od = __GenericDescriptor_find(oldfd);
  if (!od) {
	errno = EBADF;
	V_nexus(&fd_table_mutex);
	return -1;
  }

  // close whatever newfd pointed to, if anything
  if (newfd >= 0) {
	  nd = __GenericDescriptor_find(newfd);
	  if (nd) {
	      V_nexus(&fd_table_mutex);
	      GenericDescriptor_unassignHandle(newfd); 
	      P(&fd_table_mutex);
	  }
  }

  GenericDescriptor_assignHandle_specific(od, newfd);
  V_nexus(&fd_table_mutex);

  return newfd;
}

/** dummy umask implementation */
int nxlibc_syscall_umask(int mask)
{
  return 022;
}
 
/** XXX fill in correct size for file inodes */
static void __allstat_stub(struct stat *buf)
{
  memset(buf, 0, sizeof(struct stat));

  buf->st_mode = 0777;
  buf->st_nlink = 1;
  buf->st_size = 666;
  buf->st_blksize = 512;
  buf->st_blocks  = 2;
}

/** XXX fill in correct size for file inodes */
static void __allstat64_stub(struct stat64 *buf)
{
  memset(buf, 0, sizeof(struct stat64));

  buf->st_mode = 0777;
  buf->st_nlink = 1;
  buf->st_size = 666;
  buf->st_blksize = 512;
  buf->st_blocks  = 2;
}

/** shared between fstat and fstat64 */
static int __stat_stub(const char *path)
{
  DIR *dir;

  // find out if node is a directory (roundabout way)
  // NB: this requires read access, while stat does not.
  dir = nxlibc_syscall_opendir(path);
  if (dir) {
    nxlibc_syscall_closedir(dir);
    return 1;
  }
  return 0;
}

/** stat stub: always returns the same information  */
int nxlibc_syscall_stat(const char *path, struct stat *buf)
{
  __allstat_stub(buf);
  if (__stat_stub(path))
	buf->st_mode |= S_IFDIR;
  return 0;
}

/** stat64 stub: always returns the same information */
int nxlibc_syscall_stat64(const char *path, struct stat64 *buf)
{
  __allstat64_stub(buf);
  if (__stat_stub(path))
	buf->st_mode |= S_IFDIR;
  return 0;
}

/** shared between fstat and fstat64 */
static int __fstat_stub(int fd)
{ 
  GenericDescriptor *d;

  P(&fd_table_mutex);
  d = __GenericDescriptor_find(fd);
  V_nexus(&fd_table_mutex);
  if (!d) {
	errno = EBADF;
	return -1;
  }

  return 0;
}

/** fstat stub */
int nxlibc_syscall_fstat(int fd, struct stat *buf)
{
  if (__fstat_stub(fd))
	  return -1;

  __allstat_stub(buf);
  return 0;
}

/** fstat64 stub */
int nxlibc_syscall_fstat64(int fd, struct stat64 *buf)
{
  if (__fstat_stub(fd))
	  return -1;

  __allstat64_stub(buf);
  return 0;
}

#define DISPATCH_GENERIC(IS_SOCK, RT, BAD_RV, NAME, AFTER_OP, ARGS, ...)	\
  RT nxlibc_syscall_##NAME(int fd, ## __VA_ARGS__) {	\
    RT rv;						\
    GenericDescriptor *d = GenericDescriptor_find(fd);	\
    if(d == NULL) {					\
      errno = EBADF;					\
      return BAD_RV;					\
    }							\
    if(d->ops->NAME == NULL) {					\
      rv = d->ops->unsupported(d, #NAME, IS_SOCK);		\
    } else {						\
      rv = d->ops->NAME ARGS;		\
    }							\
    AFTER_OP;						\
    /* note: put is done in the DISPATCH AFTER_OP */	\
    return rv;						\
  }


#define DISPATCH_FILE(RT, BAD_RV, NAME, ARGS, ...)			\
  DISPATCH_GENERIC(0, RT,BAD_RV,NAME,					\
	   GenericDescriptor_put(d), ARGS, ##__VA_ARGS__);

#define DISPATCH_SOCK(RT, BAD_RV, NAME, ARGS, ...)			\
  DISPATCH_GENERIC(1, RT,BAD_RV,NAME,					\
	   GenericDescriptor_put(d), ARGS, ##__VA_ARGS__);
  

DISPATCH_FILE(ssize_t, -1, read, (d, buf, count), void *buf, size_t count);
DISPATCH_FILE(ssize_t, -1, write, (d, buf, count), const void *buf, size_t count);

DISPATCH_GENERIC(0, int, -1, close, 
		 do { 
		   GenericDescriptor_put(d);
		   GenericDescriptor_unassignHandle(fd);
		 } while(0),
		 (d));

DISPATCH_FILE(int, -1, ioctl, (d, flag, data), int flag, void *data);
DISPATCH_FILE(int, -1, fsync, (d));
DISPATCH_FILE(__off_t, -1, lseek, (d, offset, whence), __off_t offset, int whence);
DISPATCH_FILE(int, -1, fcntl, (d, cmd, arg), int cmd, long arg);

// XXX Nexus open64 does not implement ellipsis (...) correctly
int nxlibc_syscall_open64(const char *pathname, int flags, int mode) {
  return nxlibc_syscall_open(pathname, flags, mode);
}
int nxlibc_syscall_lseek64(int fildes, int offset, int whence) {
  return nxlibc_syscall_lseek(fildes, offset, whence);
}

DISPATCH_SOCK(int, -1, connect, (d, serv_addr, addrlen), 
	 const struct sockaddr *serv_addr, socklen_t addrlen);
DISPATCH_SOCK(int, -1, getsockname, (d, name, namelen),
	      struct sockaddr *name, socklen_t *namelen);
DISPATCH_SOCK(int, -1, setsockopt, (d, level, optname, optval, optlen),
	      int  level,  int  optname,  const  void  *optval, socklen_t optlen);

DISPATCH_SOCK(int, -1, bind, (d, my_addr, addrlen),
	 const struct sockaddr *my_addr, socklen_t addrlen);
DISPATCH_SOCK(int, -1, listen, (d, backlog), int backlog);

DISPATCH_SOCK(ssize_t, -1, recvfrom, (d, buf, len, flags, from, fromlen),
	 void *buf, size_t len, int flags, 
	 struct sockaddr *from, socklen_t *fromlen );
DISPATCH_SOCK(ssize_t, -1, sendto, (d, buf, len, flags, to, tolen),
	 const void *buf, size_t len, int flags,
	 const struct sockaddr *to, socklen_t tolen );
DISPATCH_SOCK(int, -1, _poll, (d, events, revents), 
	 short events, short *revents);

ssize_t nxlibc_syscall_send(int sockfd, const void *buf, size_t len, int flags) {
  return sendto(sockfd, buf, len, flags, NULL, 0);
}

ssize_t nxlibc_syscall_recv(int sockfd, void *buf, size_t len, int flags) {
  return recvfrom(sockfd, buf, len, flags, NULL, 0);
}

///// 

struct poll_info {
  int lock;
  int done;
  int id;
  struct timeval timeout;
};

struct poll_event {
  GenericDescriptor *fd;
  short event;
};

struct poll_registration {
  struct poll_registration *next;
  struct poll_registration *prev;
  struct poll_info *info;
  struct poll_event event;
};

static Queue *registration_queue = NULL;
static int registration_lock = 0;

static void Poll_lock(void){
  spinlock(&registration_lock);
}

static void Poll_unlock(void){
  spinunlock(&registration_lock);
}

static void Poll_enter(void){
  Poll_lock();
  if(registration_queue == NULL){
    registration_queue = queue_new();
    queue_initialize(registration_queue);
  }
}

static void Poll_exit(void){
  Poll_unlock();
}

static int Poll_make_timeout(struct timeval *t, int timeout){
  if(timeout == 0){
    t->tv_sec = 0;
    t->tv_usec = 0;
  }

  if(gettimeofday(t, NULL) != 0){
    return -1;
  }
  
  t->tv_sec += (timeout / 1000) + (((timeout % 1000) + (t->tv_usec/1000))/1000);
  t->tv_usec += (timeout % 1000)*1000;
  
  return 0;
}

static int Poll_check_timeout(struct timeval *check){
  struct timeval now;
  
  if(gettimeofday(&now, NULL) != 0){
    return -1;
  }
  
  if((now.tv_sec > check->tv_sec) || 
    ((now.tv_sec == check->tv_sec) &&
    (now.tv_usec >= check->tv_usec))){
    return 0;   
  } else {
    return ((check->tv_sec - now.tv_sec) * 1000 * 1000) + (check->tv_usec - now.tv_usec);
  }
}

static int Poll_equals_event(struct poll_registration *item, struct poll_event *event){
  return  (item->event.fd == event->fd) &&
          (item->event.event & event->event);
}

static int Poll_equals_info(struct poll_registration *item, struct poll_info *info){
  return item->info == info;
}

static void Poll_remove_descriptor(struct poll_info *info){
  assert(registration_lock);
  struct poll_registration *next, *reg = queue_gethead(registration_queue);
  while(reg != NULL){
    next = queue_getnext(reg);
    if(Poll_equals_info(reg, info)){
      queue_delete(registration_queue, reg);
    }
    //memory cleanup unnecessary, these entries are allocated on the stack!
    reg = next;
  }
}

// XXX replace with Sema
static void Poll_wakeup(struct poll_info *info){
  assert(registration_lock);
  if(!info->done){
    //This will only be set if another thread got to wakeup() before we did. 
    //If so, our job is done.  Otherwise...
    info->done = 1;
    //unblocking takes place in one of two different ways, depending on timeout
    if(info->timeout.tv_sec == 0 && info->timeout.tv_usec == 0){
printf("NXDEBUG: unexpected wakeup\n");
      Thread_Unblock(info->id);
    } else {
      Thread_CancelSleep(info->id);
    }
  }
}

// XXX replace with Sema
static void Poll_sleep(struct poll_info *info, int timeout){
  assert(registration_lock);
  info->done = 0;
  if(timeout == 0){
    Thread_Block((unsigned int *) &registration_lock, 0);
  } else {
    Thread_UnlockAndUSleep(timeout, (unsigned int *) &registration_lock);
  }
  Poll_lock();
  info->done = 1;
}

void Poll_notify(GenericDescriptor *fd, short event){
  struct poll_registration *reg;
  struct poll_event evt;
  Poll_enter();
  
  evt.fd = fd;
  evt.event = event;
  
  reg = queue_find(registration_queue, (PFany)&Poll_equals_event, &evt);
  if(reg != NULL){
    //We could be getting a delayed notification.  No biggie.  We can safely ignore it.
    //On the other hand, if it's valid...
    Poll_wakeup(reg->info);
  }

  Poll_exit();
}

// this should clearly not be here, but we cannot import the lwip socket header
int lwip_select(int maxfdp1, fd_set *readset, fd_set *writeset, 
		fd_set *exceptset, struct timeval *timeout);

/** Select that (WARNING) only works for reading from stdin. */
int 
nxlibc_syscall_select(int n, fd_set *readfds, fd_set *writefds, 
		     fd_set *exceptfds, struct timeval *timeout)
{
	if (n < 0) {
		errno = EINVAL;
		return -1;
	}

	if (FD_ISSET(STDIN_FILENO, readfds)) {
		// if keyboard mode is set to KBD_RAW, this function will
		// check for individual characters, regardless of its name
		if (Console_HasLine(kbdhandle))
			return 1;
		else
			return 0;
	}

	/* HACK if it isn't stdin, hope for the best that these are sockets */

	// have to translate all fds to lwip fds
	// slow and ugly. XXX cleanly integrate lwip fds with those of genericfs
	{
		fd_set lw_readfds, lw_writefds, lw_exceptfds;
		char reverse_lookup[200]; // ugly HACK: look up desc->priv to desc id
		GenericDescriptor *desc;
		int lw_n, i, ret, set;

		FD_ZERO(&lw_readfds);
		FD_ZERO(&lw_writefds);
		FD_ZERO(&lw_exceptfds);

		if (n >= 200)
			return -1;	// may not exceed reverse lookup

		lw_n = 0;
		for (i = 0; i < n; i++) {
			set = 0;
			desc = __GenericDescriptor_find(i);
			if (!desc)
				continue;
			if (readfds && FD_ISSET(i, readfds)) {
				FD_SET((long) desc->private, &lw_readfds);
				set = 1;
			}
			if (writefds && FD_ISSET(i, writefds)) {
				FD_SET((long) desc->private, &lw_writefds);
				set = 1;
			}
			if (exceptfds && FD_ISSET(i, exceptfds)) {
				FD_SET((long) desc->private, &lw_exceptfds);
				set = 1;
			}

			if (set) {
				reverse_lookup[(long) desc->private] = i;
				if ((long) desc->private >= lw_n)
					lw_n = (long) desc->private + 1;
			} 
		}

		ret = lwip_select(lw_n, &lw_readfds, &lw_writefds, &lw_exceptfds, timeout);
		if (readfds)
			FD_ZERO(readfds);
		if (writefds)
			FD_ZERO(writefds);
		if (exceptfds)
			FD_ZERO(exceptfds);
		if (ret > 0) {
			for (i = 0; i < lw_n; i++) {
				if (FD_ISSET(i, &lw_readfds)) {
					FD_SET(reverse_lookup[i],  readfds);
					set = 1;
				}
				if (FD_ISSET(i, &lw_writefds)) {
					FD_SET(reverse_lookup[i], writefds);
					set = 1;
				}
				if (FD_ISSET(i, &lw_exceptfds)) {
					FD_SET(reverse_lookup[i], exceptfds);
					set = 1;
				}
			}
		}
		return ret;
	}
}

int nxlibc_syscall_poll(struct pollfd *fds, nfds_t nfds, int timeout) {
  int x;
  int found = 0, ret = -1;
  struct poll_info pollinfo;
  struct poll_registration *reg = alloca(nfds * sizeof(struct poll_registration));
  
  memset(&pollinfo, 0, sizeof(struct poll_info));
  
  if((ret = Poll_make_timeout(&(pollinfo.timeout), timeout)) != 0){
    return ret;
  }
  
  pollinfo.id = Thread_GetID();
  pollinfo.done = 1;
  
  Poll_enter();
  for(x = 0; x < nfds; x++){
    reg[x].next = NULL;
    reg[x].prev = NULL;
    reg[x].info = &pollinfo;
    reg[x].event.fd = GenericDescriptor_find(fds[x].fd);
    reg[x].event.event = fds[x].events;

    queue_append(registration_queue, &(reg[x]));
  }

  while(1){
    pollinfo.done = 1;

    found = 0;
    for(x = 0; x < nfds; x++){
      fds[x].revents = 0;
      if(nxlibc_syscall__poll(fds[x].fd, fds[x].events, &(fds[x].revents)) > 0){
	static int limit = 0;
	if(limit < 5) {
	  printf("F(%d)[%x,%x]\n", fds[x].fd, fds[x].events, fds[x].revents);
	  limit++;
	}
        found++;
      }
    }
    if((found > 0) || 
      (timeout < 0) || 
      //check timeout returns the usec to the timeout, 0 if the timeout is past
      //or -1 if an error occured
      ((timeout = Poll_check_timeout(&(pollinfo.timeout))) <= 0)){
      if(timeout < 0){
        ret = timeout;
      } else {
        ret = found;
      }
      break;
    }
    
    //timeout was converted to usec by Poll_check_timeout above.
    Poll_sleep(&pollinfo, timeout);
  }
  
  Poll_remove_descriptor(&pollinfo);

  for(x = 0; x < nfds; x++){
    GenericDescriptor_put(reg[x].event.fd);
  }

  Poll_exit();
  return ret;
}

ssize_t nxlibc_syscall_writev(int fd, const struct iovec *iov, int iovcnt) {
  int i;
  int count = 0;
  for(i=0; i < iovcnt; i++) {
    int rv = write(fd, iov[i].iov_base, iov[i].iov_len);
    if(rv < 0) {
      printf("writev error at iov %d\n", i);
      return rv;
    }
    count += rv;
  }
  return count;
}


