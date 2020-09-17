/** Nexus OS: symbols exposed to Libc that implement common 
              Linux IO system calls 

    except for the prefix 'nxlibc_syscall' these should match
    the Posix definition (or Linux, if not a Posix call)
 */

#ifndef __NEXUS_USER_IO_H__
#define __NEXUS_USER_IO_H__

/** type definitions ****/

#include <poll.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/vfs.h>

/** fs operations ****/

int nxlibc_syscall_mkdir(const char *name, mode_t mode);

/* directory operations */

DIR * nxlibc_syscall_opendir(const char *dirname);
struct dirent *nxlibc_syscall_readdir(DIR *dirstream);
void nxlibc_syscall_rewinddir(DIR *dir);
int nxlibc_syscall_closedir(DIR *dirstream);
int nxlibc_syscall_chdir(const char *filename);
char * nxlibc_syscall_getcwd(char *buf, int size);

/** file operations ****/

int nxlibc_syscall_access(const char *pathname, int mode);
int nxlibc_syscall_link(const char *srcname, const char *dstname);
int nxlibc_syscall_open(const char *pathname, int flags, int mode);
int nxlibc_syscall_pipe(int filedes[2]);
int nxlibc_syscall_dup(int oldfd);
int nxlibc_syscall_dup2(int oldfd, int newfd);
int nxlibc_syscall_chmod(const char *pathname, mode_t mode);
int nxlibc_syscall_rename(const char *oldpathstr, const char *newpathstr);
int nxlibc_syscall_stat(const char *path, struct stat *buf);
int nxlibc_syscall_statfs(const char *path, struct statfs *buf);
int nxlibc_syscall_umask(int mask);
int nxlibc_syscall_unlink(const char *pathname);
int nxlibc_syscall_rmdir(const char *dirname);
ssize_t nxlibc_syscall_readlink(const char *path, char *buf, size_t bufsiz);

/** open file operations ****/

ssize_t nxlibc_syscall_pread(int fd, void *buf, size_t count, off_t off);
ssize_t nxlibc_syscall_pwrite(int fd, const void *buf, size_t count, off_t off);
ssize_t nxlibc_syscall_read(int fd, void *buf, size_t count);
ssize_t nxlibc_syscall_write(int fd, const void *buf, size_t count);
ssize_t nxlibc_syscall_writev(int fd, const struct iovec *iov, int iovcnt);
int nxlibc_syscall_close(int fd);
int nxlibc_syscall_ioctl(int fd, int flag, void *data);
int nxlibc_syscall_fsync(int fd);
int nxlibc_syscall_fdatasync(int fd);
__off_t nxlibc_syscall_lseek(int fd, __off_t offset, int whence);
int nxlibc_syscall_fcntl(int fd, int cmd, long arg);
int nxlibc_syscall_fstat(int fd, struct stat *buf);

void * nxlibc_syscall_mmap(void *addr, size_t length, int prot, int flags, 
			   int fd, off_t offset);
int nxlibc_syscall_munmap(void *addr, size_t length);

/** socket state operations ****/

int nxlibc_syscall_socket(int domain, int type, int protocol);
int nxlibc_syscall_connect(int fd, const struct sockaddr *serv_addr, 
			   socklen_t addrlen);
int nxlibc_syscall_bind(int fd, const struct sockaddr *my_addr, socklen_t addrlen);
int nxlibc_syscall_listen(int fd, int backlog);
int nxlibc_syscall_accept(int fd, struct sockaddr *addr, socklen_t *addrlen);
int nxlibc_syscall_getsockname(int fd, struct sockaddr *name, socklen_t *namelen);
int nxlibc_syscall_getsockopt(int sockfd, int level, int optname,
			      void *optval, socklen_t *optlen);
int nxlibc_syscall_setsockopt(int fd, int level, int optname, const void *optval, 
		    	      socklen_t optlen);
int nxlibc_syscall_shutdown(int sockfd, int how);
int nxlibc_syscall_getpeername(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
int nxlibc_syscall_socketcall(int call, unsigned long *args);

/** socket read/write operations ****/

ssize_t nxlibc_syscall_recvfrom(int fd, void *buf, size_t len, int flags, 
		                struct sockaddr *from, socklen_t *fromlen);
ssize_t nxlibc_syscall_sendto(int fd, const void *buf, size_t len, int flags, 
			      const struct sockaddr *to, socklen_t tolen);
ssize_t nxlibc_syscall_send(int sockfd, const void *buf, size_t len, int flags);
ssize_t nxlibc_syscall_recv(int sockfd, void *buf, size_t len, int flags);

/** polling calls ****/

int nxlibc_syscall_select(int n, fd_set *readfds, fd_set *writefds, 
		          fd_set *exceptfds, struct timeval *timeout);

/** 64 bit versions ****/

// use only when uclibc is built with UCLIBC_HAS_LFS (large file support)
#ifdef DO_LARGE_FILE
int nxlibc_syscall_open64(const char *pathname, int flags, int mode);
int nxlibc_syscall_stat64(const char *path, struct stat64 *buf);
int nxlibc_syscall_lseek64(int fildes, int offset, int whence);
#endif

/** not calls, support code (don't look here) ****/

void generic_file_init(void);
void posix_file_init(void);

#endif // __NEXUS_USER_IO_H__

