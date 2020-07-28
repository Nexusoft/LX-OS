/** Nexus OS: system call implementations

    See .c file for goal and implementation explanation
    See linux manpages for interface definitions
 */

#ifndef NEXUS_USER_LINUXCALLS_H
#define NEXUS_USER_LINUXCALLS_H

#include <time.h>
#include <unistd.h>
#include <signal.h>
#include <sys/time.h>
#include <sys/types.h>

/** process ****/

int nxlibc_syscall_getpid(void);
long nxlibc_syscall_fork(void);
long nxlibc_syscall_execve(const char * filepath, char **argv, char **env);
void nxlibc_syscall_do_exit(int i);

/** time ****/

unsigned int nxlibc_syscall_sleep(unsigned int seconds);
int nxlibc_syscall_usleep(__useconds_t usec);
int nxlibc_syscall_nanosleep(const struct timespec *req, struct timespec *rem);
int nxlibc_syscall_gettimeofday(struct timeval *tv, void *tz);
time_t nxlibc_syscall_time(time_t *t);

/** memory ****/

int nxlibc_syscall_brk(void *addr);
int nxlibc_syscall_mprotect(const void *addr, size_t len, int prot) ;
int nxlibc_syscall_mlock(const void *addr, size_t len) ;
int nxlibc_syscall_munlock(const void *addr, size_t len);

/** access control ****/

int nxlibc_syscall_setuid(__uid_t u);
int nxlibc_syscall_setfsuid(int fsuid);
int nxlibc_syscall_setgid(__gid_t g);
int nxlibc_syscall_setfsgid(int fsgid);

int nxlibc_syscall_setuid32(__uid_t u);
int nxlibc_syscall_setfsuid32(int fsuid);
int nxlibc_syscall_setgid32(__gid_t g);
int nxlibc_syscall_setfsgid32(int fsgid);

__gid_t nxlibc_syscall_getegid(void);
__uid_t nxlibc_syscall_geteuid(void);
__uid_t nxlibc_syscall_getuid(void);
__gid_t nxlibc_syscall_getgid(void);

__gid_t nxlibc_syscall_getegid32(void);
__uid_t nxlibc_syscall_geteuid32(void);
__uid_t nxlibc_syscall_getuid32(void);
__gid_t nxlibc_syscall_getgid32(void);

/** signal handling ****/

int nxlibc_syscall_sigaction(int signum, const struct sigaction *act,
			     struct sigaction *oldact);
sighandler_t nxlibc_syscall_signal(int signum, sighandler_t handler);

/** not posix, but similar DEPRECATED calls. don't rely on these ****/

int writefile(const char *filename, const void *buffer, int size);
void nexus_blit(unsigned int width, unsigned int height, unsigned char *data);
void kbd_raw_mode(void);

#endif /* NEXUS_USER_LINUXCALLS_H */

