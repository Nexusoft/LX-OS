/** Nexus OS: Internal implementation header for IO service 
              providers (pipes, files, ...).
    
 */

#ifndef __NEXUS_USER_IO_PRIV_H__
#define __NEXUS_USER_IO_PRIV_H__

#include <stdint.h>
#include <sys/select.h>
#include <sys/types.h>
#include <dirent.h>
#include <unistd.h>
#include <poll.h>

#include <nexus/linuxcalls_io.h>

typedef struct GenericDescriptor_operations GenericDescriptor_operations;

typedef struct GenericDescriptor {
  const GenericDescriptor_operations *ops;
  int refcnt;

  char *pathname;
  void *private;
  int type;		///< only used for sockets
  int port;		///< has a port been set? only used for sockets
  int nonblock:1;
  int cloexec:1;	///< warning: FD_CLOEXEC applies to descriptor, not underlying item (think of dup())

  // encryption and signing by calling lockbox (LockBox.svc)
  uint16_t lockbox;	///< holds the ipcport of the lockbox
  uint16_t key_index;	///< holds the encryption key index in the lockbox
  uint16_t sign_index;	///< holds the signature index in the lockbox

} GenericDescriptor;

struct sockaddr;

struct GenericDescriptor_operations {
  //
  // MANDATORY HOOKS
  //

  char *name;

  // set to true if a descriptor of this type has to be verified using ->poll()
  // each time that select wakes up for it:
  // used in networking to check whether TCP has data when IP receives a packet
  int poll_on_select;

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
  ssize_t (*pread)(GenericDescriptor *d, void *buf, size_t count, off_t off);
  ssize_t (*pwrite)(GenericDescriptor *d, const void *buf, size_t count, off_t off);
  ssize_t (*read)(GenericDescriptor *d, void *buf, size_t count);
  ssize_t (*write)(GenericDescriptor *d, const void *buf, size_t count);
  int (*close)(GenericDescriptor *d);
  int (*ioctl)(GenericDescriptor *d, int flag, void *data);
  int (*dup)(GenericDescriptor *d);
  int (*fsync)(GenericDescriptor *d);
  __off_t (*lseek)(GenericDescriptor *d, __off_t offset, int whence);
  int (*fcntl)(GenericDescriptor *d, int cmd, long arg);


  //// Networking

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


  //// Non-Posix extensions

  // (optional) nonblocking peek to see if data is ready for reading.
  // returns 0 if not ready, 1 if ready for reading and 2 if ready for writing
  //         where returnvalue is masked by directions
  int (*poll)(GenericDescriptor *d, int directions);

  // lookup IPC port underlying a descriptor
  // if unimplemented, a read on the descriptor must return without blocking
  int (*port)(GenericDescriptor *d);
  
  int (*size)(GenericDescriptor *d);
};

//// descriptor lookup

GenericDescriptor *nxdesc_find(int fd);
void nxdesc_put(GenericDescriptor *d);

//// encryption support

ssize_t nxfile_enc_read(GenericDescriptor *d, void *buf, size_t count);
ssize_t nxfile_enc_write(GenericDescriptor *d, const void *buf, size_t count);
int nxfile_sig_gen(GenericDescriptor *d, int index);
int nxfile_sig_check(GenericDescriptor *d, int index);

#ifndef NDEBUG
// debug: tracing IO is (unfortunately) frequently required
//        change PID to matching process to enable tracing
#define IOTRACE_PID -1

#define IOTRACE_MSG(FD, __MSG__, ...) \
	do { 								\
		if (getpid() == IOTRACE_PID && 				\
		    (FD < 1 || FD > 2) /* no stdout/err: recursion */ ) \
			fprintf(stderr, "[io] %.25s.%.3d" __MSG__ "\n", \
			        __FUNCTION__, __LINE__, __VA_ARGS__);	\
	} while (0);
#else
#define IOTRACE_MSG(...)
#endif

#endif // __NEXUS_USER_IO_PRIV_H__

