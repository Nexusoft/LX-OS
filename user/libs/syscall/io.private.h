/** Nexus OS: Internal implementation header for IO service 
              providers (pipes, files, ...).
    
 */

#ifndef __NEXUS_USER_IO_PRIV_H__
#define __NEXUS_USER_IO_PRIV_H__

#include <sys/types.h>
#include <dirent.h>
#include <unistd.h>
#include <poll.h>

#include <nexus/linuxcalls_io.h>

typedef struct GenericDescriptor_operations GenericDescriptor_operations;

typedef struct GenericDescriptor {
  const GenericDescriptor_operations *ops;
  int refcnt;

  void *private;
  int type;		// only used for sockets
} GenericDescriptor;

struct sockaddr;

struct GenericDescriptor_operations {
  //
  // MANDATORY HOOKS
  //

  // Unsupported is called when an operation is set to NULL
  int (*unsupported)(GenericDescriptor *d, const char *opname, int is_sock_op);

  // open() fills in private field on success, does not allocate private field on failure

  // The return value for open and socket are not the same as posix: -1 = error, 0 = success ; the
  // file descriptor is returned by the Generic version on success.
  int (*open)(GenericDescriptor *d, const char*filename, int flags, mode_t mode);
  int (*socket)(GenericDescriptor *d, int domain, int type, int protocol);
  int (*getsockname)(GenericDescriptor *d, struct sockaddr *name, socklen_t *namelen);
  int (*setsockopt)(GenericDescriptor *d, int  level,  int  optname,  const  void  *optval,
		    socklen_t optlen);

  //  destroy() deallocates private field. It is called when the descriptor refcnt reaches 0. Contrast with close()
  int (*destroy)(GenericDescriptor *d);

  //
  // OPTIONAL HOOKS
  //

 // For the most part, these operations are slight deltas from the POSIX
  // standard equivalents. However, some are more generic.

  // from posix

  // 
  // Open()-like operations
  // Like open(), these fill in private field on success, does not allocate private field on failure
  DIR * (*opendir)(GenericDescriptor *d, int fd, const char *dirname);

  // Other operations
  ssize_t (*read)(GenericDescriptor *d, void *buf, size_t count);
  ssize_t (*write)(GenericDescriptor *d, const void *buf, size_t count);
  int (*close)(GenericDescriptor *d);
  int (*ioctl)(GenericDescriptor *d, int flag, void *data);
  int (*dup)(GenericDescriptor *d);
  int (*fsync)(GenericDescriptor *d);
  __off_t (*lseek)(GenericDescriptor *d, __off_t offset, int whence);

  // Non posix, but used to implement
  int (*size)(GenericDescriptor *d);

  int (*fcntl)(GenericDescriptor *d, int cmd, long arg);
  /*
    int (*open64)(const char *pathname, int flags);
    int (*lseek64)(int fildes, int offset, int whence);
  */

  // From TCP

  int (*connect)(GenericDescriptor *d,
		 const struct sockaddr *serv_addr, socklen_t addrlen);
  int (*bind)(GenericDescriptor *d,
	      const struct sockaddr *my_addr, socklen_t addrlen);
  int (*listen)(GenericDescriptor *d, int backlog);
  int (*accept)(GenericDescriptor *d, struct sockaddr *addr, socklen_t *addrlen, 
		void **new_priv);
  ssize_t (*recvfrom)(GenericDescriptor *d, void *buf, size_t len, int flags, 
		      struct sockaddr *from, socklen_t *fromlen);
  ssize_t (*sendto)(GenericDescriptor *d, const void *buf, size_t len, int flags,
		    const struct sockaddr *to, socklen_t tolen);

  // From UDP

  // _poll() is NOT the poll() syscall, but rather a hook used to implement it.  It should:
  //  1 - Check to see if there are pending events on this descriptor.
  //      If so, _poll() should return 1 and set revents appropriately.
  //  2 - Signal that the application is interested in polling this descriptor.
  //      After _poll() returns, the descriptor implementation should asynchronously call 
  //      Poll_notify() defined in poll_impl.h when events occur.  Poll_notify() is a no-op 
  //      if the descriptor is not currently being polled, but the implementation need not 
  //      call it before the first call to _poll() (this one, not the syscall) is called.
  //events and revents are in the format used by the poll() syscall.
  //_poll()'s implementation must be fast, as it executes while a global lock is held.
  //_poll() should NOT call Poll_notify();
  int (*_poll)(GenericDescriptor *d, short events, short *revents);
};

// Use GenericDescriptor_find() and GenericDescriptor_put() sparingly outside of generic_file.c!
GenericDescriptor *GenericDescriptor_find(int fd);
void GenericDescriptor_put(GenericDescriptor *d);


void Poll_notify(GenericDescriptor *fd, short event);
int Poll_start(struct pollfd *fds, nfds_t nfds, int timeout);

void pipe_init(GenericDescriptor *reader, GenericDescriptor *writer);

#endif // __NEXUS_USER_IO_PRIV_H__
