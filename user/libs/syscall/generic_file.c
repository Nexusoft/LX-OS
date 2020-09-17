/** NexusOS: This file implements the demultiplexing code for file descriptors, and
             juggles between sockets, the console, the keyboard, files (aka posixfile),
             and a few special case devices (audio, random, ..)

			 GenericFile is Nexus's equivalent to Linux VFS
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <pthread.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <nexus/queue.h>
#include <nexus/vector.h>
#include <nexus/hashtable.h>
#include <nexus/sema.h>
#include <nexus/linuxcalls_io.h>
#include <nexus/machine-structs.h>
#include <nexus/init.h>
#include <nexus/fs.h>
#include <nexus/fs_path.h>
#include <nexus/util.h>
#include <nexus/rdtsc.h>
#include <nexus/nexuscalls.h>

#include <nexus/FS.interface.h>
#include <nexus/IPC.interface.h>
#include <nexus/Mem.interface.h>
#include <nexus/Console.interface.h>
#include <nexus/Thread.interface.h>
#include <nexus/LockBox.interface.h>

#include "io.private.h"

static Sema fd_table_mutex = SEMA_MUTEX_INIT;
struct HashTable *fd_table; // int => GenericDescriptor

extern GenericDescriptor_operations File_ops;
extern GenericDescriptor_operations UserAudio_ops;
extern GenericDescriptor_operations Stdin_ops;
extern GenericDescriptor_operations Stdout_ops;
extern GenericDescriptor_operations Stderr_ops;
extern GenericDescriptor_operations random_ops;
extern GenericDescriptor_operations urandom_ops;
extern GenericDescriptor_operations pipe_ops;
extern GenericDescriptor_operations socket_ops;
extern GenericDescriptor_operations nxlocalsock_ops;

// select the next file descriptor to hand out
static int max_fd = -1;
static int clean_fd = -1;

////////  forward declarations  ////////

static void nxdesc_sethandle(GenericDescriptor *d, int fd);
static GenericDescriptor *nxdesc_new(const GenericDescriptor_operations *ops);
static int nxdesc_poll(int fd, int directions);


////////  support functions  ////////

// XXX wrap implementation init routines in here (__posixfile_init)
void generic_file_init(void) {
  fd_table = hash_new(128, sizeof(int));

  GenericDescriptor *d;
  d = nxdesc_new(&Stdin_ops);
  nxdesc_sethandle(d, STDIN_FILENO /* 0 */);
  d = nxdesc_new(&Stdout_ops);
  nxdesc_sethandle(d, STDOUT_FILENO /* 1 */);
  d = nxdesc_new(&Stderr_ops);
  nxdesc_sethandle(d, STDERR_FILENO /* 2 */);
}

static void 
nxdesc_get(GenericDescriptor *d) 
{
  atomic_addto(&d->refcnt, 1);
}

/** Find without acquiring or locking the fd table */
static GenericDescriptor *
__nxdesc_find_noacquire(int fd) 
{
  return hash_findItem(fd_table, &fd);
}

/** Find and acquire without locking the fd table */
static GenericDescriptor *
__nxdesc_find(int fd) 
{
  GenericDescriptor *desc;

  desc = __nxdesc_find_noacquire(fd);
  if (!desc) 
    return NULL;
  
  nxdesc_get(desc);
  return desc;
}

/** Find and acquire while locking the fd table */
GenericDescriptor *
nxdesc_find(int fd) 
{
  GenericDescriptor *rv;
  
  P(&fd_table_mutex);
  rv = __nxdesc_find(fd);
  V_nexus(&fd_table_mutex);
  
  return rv;
}

void nxdesc_put(GenericDescriptor *d) {
  atomic_subtractfrom(&d->refcnt, 1);
  if (d->refcnt == 0) {
    if (d->ops->destroy)
      d->ops->destroy(d);
    if (d->pathname)
      free(d->pathname);
    free(d);
  }
}

// Precondition: fd_table_mutex is held
static void nxdesc_sethandle(GenericDescriptor *d, int fd) {
  if (hash_findItem(fd_table, &fd) != NULL) {
		assert(0);
	return;
  }
  hash_insert(fd_table, &fd, d);
  nxdesc_get(d);
}

/** Nonblocking IO handler
    @return 0 if call can continue and may block.
    Otherwise, return -1 and set errno correctly */
static inline int
nxdesc_mayblock(GenericDescriptor *d, int dir)
{
	if (d->nonblock && d->ops->poll && d->ops->poll(d, dir) == 0)
		return -1;
	else
		return 0;
}

static int 
assign_filedescriptor(void)
{
	// first try to reuse a previously handed-out and reclaimed fd
	// we don't keep all fds in a bitmap
	if (clean_fd >= 0)
		return clean_fd--;
	else
		return ++max_fd;
}

static void 
unassign_filedescriptor(int fd)
{
	if (fd == clean_fd + 1)
		clean_fd++;

	if (fd == max_fd)
		max_fd--;
}

static int 
__nxdesc_new(GenericDescriptor *d) 
{
  int fh;

  while(1) {
    fh = assign_filedescriptor();
    if(hash_findItem(fd_table, &fh) == NULL) {
      nxdesc_sethandle(d, fh);
      break;
    }
  }
  return fh;
}

static GenericDescriptor *
nxdesc_new(const GenericDescriptor_operations *ops) 
{
  GenericDescriptor *d;
  
  d = calloc(1, sizeof(*d));
  d->ops = ops;
  return d;
}

// NB: Unlike new(), del() DOES NOT want the fd
// table semaphore held.
// This is because we want to avoid holding the semaphore across the
// PUT operation, which might block
static void nxdesc_del(int fd) {
  GenericDescriptor *desc = NULL;
  void *prev, *entry;
  
  unassign_filedescriptor(fd);
  
  P(&fd_table_mutex);
  entry = hash_findEntry(fd_table, &fd, &prev);
  if (entry) {
		desc = hash_entryToItem(entry);
		hash_deleteEntry(fd_table, entry, prev);
  }
  V_nexus(&fd_table_mutex);
  
  if (desc)
		nxdesc_put(desc);
}


////////  Posix IO implementations

int 
nxlibc_syscall_open(const char *pathname, int flags, int mode) 
{
  GenericDescriptor *d;
  int fd, ret;

  if (!pathname)
    return -EFAULT;

	// XXX hack. Should use device inodes
	if (!strcmp(pathname, "/dev/dsp"))
		d = nxdesc_new(&UserAudio_ops);
	else if (!strcmp(pathname, "/dev/random"))
		d = nxdesc_new(&random_ops);
	else if (!strcmp(pathname, "/dev/urandom"))
		d = nxdesc_new(&urandom_ops);
	else 
		d = nxdesc_new(&File_ops);

  d->pathname = strdup(pathname);
  
  // call subsystem
  ret = d->ops->open(d, pathname, flags, mode);
  if (ret) {
    nxdesc_put(d);	
    return ret;
  }
  
  // acquire descriptor
  P(&fd_table_mutex);
  fd = __nxdesc_new(d);
  V_nexus(&fd_table_mutex);

  return fd;
}

/** Open a pipe. 
    The current implementation does not enforce the unidirectional
    nature of filedes[0] and filedes[1] */
int 
nxlibc_syscall_pipe(int filedes[2]) 
{
  GenericDescriptor *d;
  int fd, ret;

  d = nxdesc_new(&pipe_ops);
  ret = d->ops->open(d, NULL, 0, 0);
  if (ret) {
		nxdesc_put(d);
		return ret;
  }

  P(&fd_table_mutex);
  filedes[0] = __nxdesc_new(d);
  filedes[1] = __nxdesc_new(d);
  V_nexus(&fd_table_mutex);
  
  return 0;
}

int 
nxlibc_syscall_accept(int fd, struct sockaddr *addr, socklen_t *addrlen) 
{
  GenericDescriptor *nd, *d;
  void *private;
  int err;
  
  // call accept() implementation
  d = nxdesc_find(fd);
  if (!d)
		return -EBADF;
  if (nxdesc_mayblock(d, IPC_READ))
	return -EAGAIN;

  err = d->ops->accept(d, addr, addrlen, &private);
  nxdesc_put(d);
  
  if (err)
    return err;

  // create structure for child connection
  nd = nxdesc_new(d->ops);
  nd->private = private;

  // acquire file descriptor
  P(&fd_table_mutex);
  fd = __nxdesc_new(nd);
  V_nexus(&fd_table_mutex);

  return fd;
}

int 
nxlibc_syscall_socket(int domain, int type, int protocol) 
{
  GenericDescriptor *d;
  int fd, ret;

  // select implementation by domain
  if (domain == PF_INET)
		d = nxdesc_new(&socket_ops);
  else if (domain == PF_UNIX)
		d = nxdesc_new(&nxlocalsock_ops);
  else {
			fprintf(stderr, "socket(..): Unknown type (%d,%d,%d)\n", domain, type, protocol);
			return -EINVAL;
  }

  // create socket
  ret = d->ops->socket(d, domain, type, protocol);
  if (ret) {
    nxdesc_put(d);
    return ret;
  } 
  
  // assign file descriptor
  P(&fd_table_mutex);
  fd = __nxdesc_new(d);
  V_nexus(&fd_table_mutex);

  return fd;
}

int nxlibc_syscall_dup(int oldfd) {
  GenericDescriptor *d;
  int newfd;

  P(&fd_table_mutex);
  d = __nxdesc_find(oldfd);
  if (!d) {
    V_nexus(&fd_table_mutex);
    return -EBADF;
  }

  newfd = __nxdesc_new(d);
  V_nexus(&fd_table_mutex);
  return newfd;
}

int nxlibc_syscall_dup2(int oldfd, int newfd)
{
  GenericDescriptor *nd, *od;

  P(&fd_table_mutex);

  // verify that oldfd is a valid descriptor
  od = __nxdesc_find(oldfd);
  if (!od) {
	V_nexus(&fd_table_mutex);
	return -EBADF;
  }

  // close whatever newfd pointed to, if anything
  if (newfd >= 0) {
		nd = __nxdesc_find(newfd);
		if (nd) {
				V_nexus(&fd_table_mutex);
				nxdesc_del(newfd); 
				P(&fd_table_mutex);
		}
  }

  nxdesc_sethandle(od, newfd);
  V_nexus(&fd_table_mutex);

  return newfd;
}

/** dummy umask implementation */
int nxlibc_syscall_umask(int mask)
{
  return 022;
}
 
/** dummy statfs */
int nxlibc_syscall_statfs(const char *path, struct statfs *buf)
{
#define NFS_SUPER_MAGIC       0x6969
	
	IOTRACE_MSG(-1, "stat %s", path);
	memset(buf, 0, sizeof(*buf));

	// XXX make configurable depending on real FS
	buf->f_type = NFS_SUPER_MAGIC;	
	buf->f_frsize = buf->f_bsize = 512;
	buf->f_blocks = 1 << 30;
	buf->f_bfree = 1 << 29;
	buf->f_bavail = 1 << 29;
	buf->f_files = 1 << 20;
	buf->f_ffree = 1 << 19;
	buf->f_namelen = 256;

	return 0;
}

/** shared between stat implementations */
static int __allstat_stub(const char *pathname, struct stat *buf)
{
  Path path;
  FSID inode;
  unsigned long size;

  memset(buf, 0, sizeof(struct stat));

  buf->st_mode = 0777;
  buf->st_nlink = 1;
  
  // lookup the inode. succeed if all exists except the basename
  if (Path_resolve1(&path, &curr_directory, pathname))
	return -ENOTDIR;

  // see if the basename exists
  inode = Path_last(&path)->node;
  if (!FSID_isValid(inode)) {
		Path_clear(&path);
		return -ENOENT;
  }

  // ask FS for metadata
  buf->st_dev  = inode.port;
  buf->st_ino = (ino_t) fsid_upper(&inode);
  if (FSID_isDir(inode)) {
		buf->st_mode = S_IFDIR;
  }
  else {
			buf->st_mode = S_IFREG;
		size = FS_Size_ext(inode.port, inode);
		assert(size >= 0);
		buf->st_size = size;
		buf->st_blksize = 1 << 9;	// XXX allow FS to set
		buf->st_blocks = size >> 9;
  }

  Path_clear(&path);
  return 0;
}

/** stat stub: always returns the same information  */
int nxlibc_syscall_stat(const char *pathname, struct stat *buf)
{
  return __allstat_stub(pathname, buf);
}

/** fstat stub */
int nxlibc_syscall_fstat(int fd, struct stat *buf)
{
  GenericDescriptor *d;

  IOTRACE_MSG(fd, "fstat %d", fd);
  P(&fd_table_mutex);
  d = __nxdesc_find(fd);
  V_nexus(&fd_table_mutex);

  if (!d)
	return -EBADF;

  // not a posixfile? 
  // probably stdio. XXX send to implementation
  if (!d->pathname) {
		buf->st_mode = S_IFCHR;
	buf->st_size = 0;
	buf->st_blksize = 1;
	buf->st_blocks = 0;
	return 0;
  }

  return __allstat_stub(d->pathname, buf);
}

#ifdef DO_LARGE_FILE

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

/** stat64 stub: always returns the same information */
int nxlibc_syscall_stat64(const char *path, struct stat64 *buf)
{
  IOTRACE_MSG(-1, "stat64 %s", path);
  __allstat64_stub(buf);
  if (__stat_stub(path))
	buf->st_mode |= S_IFDIR;
  return 0;
}

/** fstat64 stub */
int nxlibc_syscall_fstat64(int fd, struct stat64 *buf)
{
  int ret;

  IOTRACE_MSG(fd, "fstat64 %d", fd);
  ret = __fstat_stub(fd);
  if (ret)
		return ret;

  __allstat64_stub(buf);
  return 0;
}

#endif /* DO_LARGE_FILE */

ssize_t 
nxlibc_syscall_pread(int fd, void *buf, size_t count, off_t off)
{
	GenericDescriptor *d;
	int ret;

	d = nxdesc_find(fd);
	if (!d)
		return -EBADF;
	if (d->lockbox) {
		fprintf(stderr, "%s.%d lockbox not supported\n", __FUNCTION__, __LINE__);
		return -EINVAL;
	}
	if (nxdesc_mayblock(d, IPC_READ))
		return -EAGAIN;

	if (d->ops->pread) 
		ret = d->ops->pread(d, buf, count, off);
	else
		ret = -EINVAL;

		IOTRACE_MSG(fd, "pread %s.%d off=%lu len=%u ret=%d", d->ops->name, fd, off, count, ret);
	nxdesc_put(d);
	return ret;
}

/** Read data
    Optionally decrypts using lockbox */
ssize_t 
nxlibc_syscall_read(int fd, void *buf, size_t count)
{
	GenericDescriptor *d;
	int ret;

	d = nxdesc_find(fd);
	if (!d)
		return -EBADF;

	if (nxdesc_mayblock(d, IPC_READ)) {
		return -EAGAIN;
	}

	// decrypt? fetch cryptext in temporary buffer
	if (d->key_index)
		ret = nxfile_enc_read(d, buf, count);
	else if (d->ops->read)
			ret = d->ops->read(d, buf, count);
	else
		ret = -EINVAL;

		IOTRACE_MSG(fd, "read %s.%d len=%u ret=%d", d->ops->name, fd, count, ret);
	nxdesc_put(d);
	return ret;
}

ssize_t
nxlibc_syscall_pwrite(int fd, const void *buf, size_t count, off_t off)
{
	GenericDescriptor *d;
	int ret;

	// fetch file structure
	d = nxdesc_find(fd);
	if (!d)
		return -EBADF;
	if (d->key_index) {
		fprintf(stderr, "[fd] no pwrite on lockbox\n");
		return -EINVAL;
	}
	if (nxdesc_mayblock(d, IPC_WRITE))
		return -EAGAIN;

		if (d->ops->write)
		ret = d->ops->pwrite(d, buf, count, off);
	else
		ret = -EINVAL;

		IOTRACE_MSG(fd, "read %s.%d len=%u ret=%d", d->ops->name, fd, count, ret);

	nxdesc_put(d);
	return ret;
}

ssize_t
nxlibc_syscall_write(int fd, const void *buf, size_t count)
{
	GenericDescriptor *d;
	int ret;

	// fetch file structure
	d = nxdesc_find(fd);
	if (!d)
		return -EBADF;
	if (nxdesc_mayblock(d, IPC_WRITE))
		return -EAGAIN;

	// write (optionally encrypt)
	if (d->key_index)
		ret = nxfile_enc_write(d, buf, count);
	else if (d->ops->write)
			ret = d->ops->write(d, buf, count);
	else
		ret = -EINVAL;

	nxdesc_put(d);
	return ret;
}

int
nxlibc_syscall_close(int fd)
{
	GenericDescriptor *d;
	int ret = 0;

	d = nxdesc_find(fd);
	if (!d)
		return -EBADF;

	// (optional) signature generation
	if (d->sign_index && nxfile_sig_gen(d, d->sign_index))
		ret = -EIO;

	// call subsystem
	if (d->ops->close)
		d->ops->close(d);
	else
		d->ops->unsupported(d, "close", 0);

	// release descriptor
	nxdesc_del(fd);
	nxdesc_put(d);
	return ret;
}

int
nxlibc_syscall_ioctl(int fd, int flag, void *data)
{
	GenericDescriptor *d;
	int ret;

	IOTRACE_MSG(fd, "ioctl cmd %d", flag);
	d = nxdesc_find(fd);
	if (!d)
		return -EBADF;

	// call subsystem
	if (d->ops->ioctl)
		ret = d->ops->ioctl(d, flag, data);
	else
		ret = d->ops->unsupported(d, "ioctl", 0);

	// release descriptor
	nxdesc_put(d);
	return ret;
}

int
nxlibc_syscall_fsync(int fd)
{ 
	GenericDescriptor *d;
	int ret;

	IOTRACE_MSG(fd, "fsync %d", fd);
	d = nxdesc_find(fd);
	if (!d)
		return -EBADF;

	// call subsystem
	if (d->ops->ioctl)
		ret = d->ops->fsync(d);
	else
		ret = d->ops->unsupported(d, "fsync", 0);

	// release descriptor
	nxdesc_put(d);
	return ret;
}

off_t 
nxlibc_syscall_lseek(int fd, off_t offset, int whence)
{
	GenericDescriptor *d;
	int ret;

	d = nxdesc_find(fd);
	if (!d)
		return -EBADF;

	// call subsystem
	if (d->ops->ioctl)
		ret = d->ops->lseek(d, offset, whence);
	else
		ret = d->ops->unsupported(d, "lseek", 0);

	// release descriptor
        IOTRACE_MSG(fd, "lseek %d off=%lu whence=%d ret=%d", fd, offset, whence, ret);
	nxdesc_put(d);
	return ret;
}

/** fcntl() support for encryption (using lockbox, nexus specific) */
static int
__syscall_fcntl_crypto(GenericDescriptor *d, int cmd, long _arg)
{
	unsigned long arg = _arg;
  int index;

	// disconnect from old box (if any)
#ifndef UTOPIA
	// XXX DEBUG: cannot yet dis/reconnect arbitrarily
	int old_lockbox = d->lockbox;
	int new_lockbox = ((arg >> 16) & 0xffff);
	assert(!old_lockbox || !new_lockbox || new_lockbox == old_lockbox);
#endif

	index = arg & 0xffff;
	if (!index) {
		fprintf(stderr, "[crypto] illegal index %d\n", index);
		return -1;
	}

	// extract values
	d->lockbox  = (arg >> 16) & 0xffff;
	if (cmd == F_SETENC)
		d->key_index = index;
	else if (cmd == F_SIGN)
		d->sign_index = index;

	if (!d->lockbox)
		return 0;

	// connect
#ifndef UTOPIA
	// existing connection? have not disconnected, so cannot reconnect
	if (old_lockbox)
		return 0;
#endif

	// calculate 
	if (cmd == F_SIGNED) 
		return nxfile_sig_check(d, index);
	else
		return 0;
}

int
nxlibc_syscall_fcntl(int fd, int cmd, long arg)
{
	GenericDescriptor *d;
	int done = 0, ret = 0; 

	IOTRACE_MSG(fd, "fcntl %d cmd %d", fd, cmd);
	d = nxdesc_find(fd);
	if (!d)
		return -EBADF;

	// handle flags governed by genericfs
	if (cmd == F_SETFL) {
		d->nonblock = arg & O_NONBLOCK ? 1 : 0;
		done = 1;
	}
	else if (cmd == F_SETFD) {
		d->cloexec = arg & FD_CLOEXEC ? 1 : 0;
		done = 1;
	}
	else if (cmd == F_GETFD) {
		ret = d->cloexec ? FD_CLOEXEC : 0;
		done = 1;
	}
	
	// anything else to do?
	if (!done) {
		
		// choose a lockbox and key index?
		if (cmd == F_SETENC || cmd == F_SIGN || cmd == F_SIGNED)
			ret =  __syscall_fcntl_crypto(d, cmd, arg);
		else if (d->ops->fcntl)
			ret = d->ops->fcntl(d, cmd, arg);
		else
			ret =  d->ops->unsupported(d, "fcntl", 0);
	}

	nxdesc_put(d);
	return ret;
}

#ifdef DO_LARGE_FILE

// XXX Nexus open64 does not implement ellipsis (...) correctly
int 
nxlibc_syscall_open64(const char *pathname, int flags, int mode) 
{
  return nxlibc_syscall_open(pathname, flags, mode);
}

int 
nxlibc_syscall_lseek64(int fildes, int offset, int whence) 
{
  return nxlibc_syscall_lseek(fildes, offset, whence);
}

#endif

#define nxlibc_DEMUX(RT, NAME, ARGS, ...)	\
  RT nxlibc_syscall_##NAME(int fd, ## __VA_ARGS__) {	\
    RT rv;						\
    GenericDescriptor *d;													\
    d = nxdesc_find(fd);                                \
    if (!d)						\
      return -EBADF;					\
    if(!d->ops->NAME)					\
      rv = d->ops->unsupported(d, #NAME, 0);		\
    else						\
      rv = d->ops->NAME ARGS;				\
    nxdesc_put(d);					\
    return rv;						\
  }

nxlibc_DEMUX(int, connect, (d, serv_addr, addrlen), 
	 const struct sockaddr *serv_addr, socklen_t addrlen);
nxlibc_DEMUX(int, getsockname, (d, name, namelen),
				struct sockaddr *name, socklen_t *namelen);
nxlibc_DEMUX(int, setsockopt, (d, level, optname, optval, optlen),
				int  level,  int  optname,  const  void  *optval, socklen_t optlen);

nxlibc_DEMUX(int, bind, (d, my_addr, addrlen),
	 const struct sockaddr *my_addr, socklen_t addrlen);
nxlibc_DEMUX(int, listen, (d, backlog), int backlog);

ssize_t
nxlibc_syscall_sendto(int sockfd, const void *buf, size_t len, int flags,
					const struct sockaddr *to, socklen_t tolen)
{
	GenericDescriptor *d;
	ssize_t rv;

	d = nxdesc_find(sockfd);
	if (!d)
		return -EBADF;

	if (nxdesc_mayblock(d, IPC_WRITE))
		return -EAGAIN;

	if (!d->ops->sendto)
		rv = d->ops->unsupported(d, "sendto", 0);
	else
		rv = d->ops->sendto(d, buf, len, flags, to, tolen);
	
	IOTRACE_MSG(sockfd, "sendto %d len=%d ret=%d", sockfd, len, rv);
	nxdesc_put(d);
	return rv;
}

ssize_t 
nxlibc_syscall_send(int sockfd, const void *buf, size_t len, int flags) 
{
	return nxlibc_syscall_sendto(sockfd, buf, len, flags, NULL, 0);
}

ssize_t
nxlibc_syscall_recvfrom(int sockfd, void *buf, size_t len, int flags,
						struct sockaddr *to, socklen_t *tolen)
{
	GenericDescriptor *d;
	ssize_t rv;

	d = nxdesc_find(sockfd);
	if (!d)
		return -EBADF;

	if (nxdesc_mayblock(d, IPC_READ))
		return -EAGAIN;

	if (!d->ops->recvfrom)
		rv = d->ops->unsupported(d, "recvfrom", 0);
	else
		rv = d->ops->recvfrom(d, buf, len, flags, to, tolen);
	
	IOTRACE_MSG(sockfd, "recvfrom %d len=%d ret=%d", sockfd, len, rv);
	nxdesc_put(d);
	return rv;
}

ssize_t 
nxlibc_syscall_recv(int sockfd, void *buf, size_t len, int flags) 
{
  return nxlibc_syscall_recvfrom(sockfd, buf, len, flags, NULL, 0);
}

/** select(..)

    For reading, can combine file descriptors of various backends 
    (unixsock, net, ...), but there may be exceptions. 
 
    Does NOT handle write or exception requests
    Does NOT handle timeouts, unless all fd_sets are NULL
 */
int 
nxlibc_syscall_select(int n, fd_set *readfds, fd_set *writefds, 
				 fd_set *exceptfds, struct timeval *timeout)
{
#define MAXNUM	16
	long ports[MAXNUM];
	int fds[MAXNUM];
	char res[MAXNUM];
	char res_use[MAXNUM];
	long port;
	int i, len, ret;

	// validate input
	if (n < 0)
		return -EINVAL;
	
	if (n >= FD_SETSIZE) {
		fprintf(stderr, "select(): descriptors exceed FD_SETSIZE\n");
		return -EINVAL;
	}

	// special case: used as high-resolution timer
	if (n == 0 && timeout) {
		Thread_USleep((timeout->tv_sec * 1000000) + timeout->tv_usec);
		return 0;
	}

	// timeouts are not supported
	// XXX fix
	if (timeout) {}

	// translate into portlist for IPC_Wait
	len = 0;
	for (i = 0; i < n; i++) {
		res[len] = 0;

		// read
		if (readfds && FD_ISSET(i, readfds)) {
			res[len] |= IPC_READ; 
		}

		// write
		if (writefds && FD_ISSET(i, writefds)) {
			res[len] |= IPC_WRITE; 
		}

		// exception: allowed but never fired

		// if read or write, set other parameters
		if (res[len]) {

			// safety: note that MAXNUM is actually never allowed
			if (len == MAXNUM) {
				fprintf(stderr, "select(): boundary exceeded\n");
				return -EINVAL;
			}

			// set port
			ports[len] = nxfile_port(i);
			if (ports[len] == -1)
				return -EBADF;

			fds[len] = i;
			len++;
		}
	}

	if (exceptfds)
		FD_ZERO(exceptfds);
	
	// poll using IPC_Wait
	// loop, because we must verify descriptors and verification may fail
	do {
		if (readfds)
			FD_ZERO(readfds);
		if (writefds)
			FD_ZERO(writefds);
		
		// wait
		memcpy(res_use, res, len);
		ret = IPC_Wait(ports, res_use, len);

		if (ret < 0)
			return -ENOMEM; // general 'internal error' value

		// poll descriptors to verify that data is waiting
		// this is necessary because network packets at the IPC layer
		// do not necessarily translate into data at the TCP layer
		ret = 0;
		for (i = 0; i < len; i++) {
			if (res_use[i]) {
				int isset = 0;

				if ((res_use[i] & IPC_READ)) {
					if (nxdesc_poll(fds[i], IPC_READ)) {
						FD_SET(fds[i], readfds);
						isset = 1;
					}
				} 
				if ((res_use[i] & IPC_WRITE)) {
					if (nxdesc_poll(fds[i], IPC_WRITE)) {
						FD_SET(fds[i], writefds);
						isset = 1;
					}
				}
				ret += isset;
			}
		}
	
	} while (!ret);
	
	IOTRACE_MSG(-1, "select ret=%d", ret);
	return ret;
}

ssize_t
nxlibc_syscall_writev(int fd, const struct iovec *iov, int iovcnt) 
{
  int i, rv, count = 0;

  for (i = 0; i < iovcnt; i++) {
    rv = write(fd, iov[i].iov_base, iov[i].iov_len);
    if (rv < 0) {
      fprintf(stderr, "[fd] writev error at iovec %d\n", i);
      return rv;
    }

    count += rv;
  }
	
  IOTRACE_MSG(fd, "writev %d iovcount=%d bytecount=%d", fd, iovcnt, count);
  return count;
}

ssize_t 
nxlibc_syscall_readlink(const char *path, char *buf, size_t bufsiz) 
{
	// XXX properly handle symlink files
	return -EINVAL;
}

// mmap can cause all kinds of weird bugs. We disable it by default
// to enable in an app, declare this extern and set it to 1
int 
nxlibc_enable_mmap;

/** Dumb (!) mmap implementation.
    This version does not use any kernel support: it allocates pages
    and COPIES in the contents from the files. This is hideously slow,
    but at least it allows applications that use mmap() to work. 
 */
void * 
nxlibc_syscall_mmap(void *addr, size_t length, int prot, int flags, 
							int fd, off_t offset)
{
	off_t old_offset;
	int numpg, i, ret;

		IOTRACE_MSG(fd, "mmap fd=%d", fd);
	if (!nxlibc_enable_mmap) {
		fprintf(stderr, "mmap() called. Aborting\n");
		abort();
	}

	if (offset & (PAGESIZE - 1))
		return MAP_FAILED;

	if (!length)
		return MAP_FAILED;

	// filter out unsupported options
	if (prot == PROT_NONE || 
			(flags & ~(MAP_ANONYMOUS | MAP_PRIVATE | MAP_SHARED))) {
		fprintf(stderr, "mmap(): unimplemented feature\n");
		return MAP_FAILED;
	}
	
	// getpages at addr (or anywhere if NULL) 
	// append one page with metadata 
	numpg = (length >> PAGE_SHIFT) + ((length & (PAGE_SIZE - 1)) ? 1 : 0);
	addr = (void *) Mem_GetPages(numpg + 1, (unsigned long) addr);
	if (addr == MAP_FAILED) {
		fprintf(stderr, "mmap(): no pages\n");
		return MAP_FAILED;
	}

	// save protection, to know what to do at unmap.
	// clearly, without kernel protection, this is not safe
	memcpy(addr + length, &prot, sizeof(prot));
	memcpy(addr + length + sizeof(prot), &flags, sizeof(flags));

	if (!(flags & MAP_ANONYMOUS)) {
		
		// save offset and move
		old_offset = nxlibc_syscall_lseek(fd, 0, SEEK_CUR);
		nxlibc_syscall_lseek(fd, offset, SEEK_SET);

		// copy data (SLOW)
		for (i = 0; i < numpg; i++) {
			ret = nxlibc_syscall_read(fd, addr + (i << PAGE_SHIFT), 
							PAGESIZE);
			if (ret < 0 ||
					/* last page may be partially filled */ 
					(ret != PAGESIZE && i < numpg - 1)) {
				Mem_FreePages((unsigned long) addr, numpg + 1);
				return MAP_FAILED;
			}
		}

		// reposition offset
		nxlibc_syscall_lseek(fd, old_offset, SEEK_SET);
	}

	return addr;
}

/** Remove memory mappings. 
    This version is UNSAFE in that it removes all allocated pages 
    in a region, not just those pages allocated for mmap(). 

    it is not supposed to be an error if the region did not contain 
    mmapped pages, but we do not support that behavior, because we
    store metadata at the end of the region.
 */
int 
nxlibc_syscall_munmap(void *addr, size_t length)
{
	int prot, flags, numpg;

		IOTRACE_MSG(-1, "munmap %u", length);
	if (((unsigned long) addr) & (PAGESIZE - 1))
		return -EINVAL;

	if (!length)
		return -EINVAL;

	// read metadata
	memcpy(&prot, addr + length, sizeof(prot));
	memcpy(&flags, addr + length + sizeof(prot), sizeof(flags));

	// XXX have to store changes. Use SMR_GetBitmap()
	if (!flags /* not ANONYMOUS or PRIVATE? write back */ && 
			prot & PROT_WRITE) {
		fprintf(stderr, "munmap(): unimplemented feature\n");
	}

	// dealloc
	numpg = length >> PAGE_SHIFT;
	Mem_FreePages((unsigned long) addr, numpg + 1);

	return 0;
}

int 
nxlibc_syscall_access(const char *pathname, int mode)
{
	Path path;
	int ret;

			if (!Path_resolve1(&path, &curr_directory, pathname)) {
		fprintf(stderr, "[fd] warning: bypassing access() for %s\n", pathname);
		return R_OK | W_OK | X_OK;
		return -EACCES;
	}
	Path_clear(&path);

	// XXX: bypassing Posix permissions. Everyone has complete access
	return R_OK | W_OK | X_OK;
}

int 
nxlibc_syscall_fdatasync(int fd)
{
	return nxlibc_syscall_fsync(fd);
}

int 
nxlibc_syscall_link(const char *srcname, const char *dstname)
{
	FSID source, target, targetdir;
	Path path;

	// lookup source
	if (Path_resolve(&path, &curr_directory, srcname))
		return -ENOENT;

	source = Path_last(&path)->node;
	if (!FSID_isFile(source)) {
		if (FSID_isDir(source))
			return -EPERM;  // according to linux manpage
		else
			return -ENOENT;
	}

	// lookup dest
	if (Path_resolve1(&path, &curr_directory, dstname))
		return -ENOENT;

	target = Path_last(&path)->node;
	if (FSID_isValid(target))
		return -EEXIST;

	// verify dest parent
	targetdir = Path_lastparent(&path)->node;
	if (!FSID_isDir(targetdir))
		return -ENOTDIR;

	// verify source and dest mountpoints
	if (targetdir.port != source.port)
		return -EXDEV;

	target = FS_Link_ext(targetdir.port, targetdir, source);
	if (FSID_equal(target, FSID_ERROR(FS_UNSUPPORTED)))
		return -EPERM;

	return 0;
}

////////  Non-Posix support functions

/** @return the IPC port corresponding to a file object or -1 on failure */
int nxfile_port(int fd)
{
	GenericDescriptor *d;
	int port;

	d = nxdesc_find(fd);
	if (!d)
		return -EBADF;

	if (!d->ops->port)
		return -EINVAL;

	port = d->ops->port(d);
	nxdesc_put(d);

	return port;
}

/** Find out if a socket can be read without blocking.
    See definition of poll_on_select for more information

    @param directions is a boolean or of IPC_READ and IPC_WRITE
    @return 1 if data ready, 0 if not, -1 on error */
static int 
nxdesc_poll(int fd, int directions)
{
	GenericDescriptor *d;

	d = nxdesc_find(fd);
	if (!d)
		return -EBADF;

	// no poll callback? that implies that the request can be serviced
	if (!d->ops->poll_on_select) 
		return directions;
	
	assert(d->ops->poll);
	return d->ops->poll(d, directions);
}

/* vim: set ts=2 sw=2: */
