/** NexusOS: uClibc system call demultiplexer 
    Nexus intercepts the system calls and handles them 
    in userspace as much as possible */

#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <sys/syscall.h>

#include <nexus/defs.h>
#include <nexus/linuxcalls.h>
#include <nexus/linuxcalls_io.h>

#include <nexus/Debug.interface.h>
#include <nexus/Thread.interface.h>
#include <nexus/Console.interface.h>

int nxcall_debug;

/** Write out the errorcode without using higher level snprintf
    as that would cause a resursive call */
static void
__print_error(const char *pre, int syscall_no, const char *post)
{
	char syscall_nostr[] = "000";

	// convert the system call code to a string
	if (syscall_no >= 100)
		syscall_nostr[0] = '0' + (syscall_no / 100);
	if (syscall_no >= 10)
		syscall_nostr[1] = '0' + (syscall_no % 100) / 10;
	syscall_nostr[2] = '0' + syscall_no % 10;

	// write to the screen
	Console_PrintString((char *) pre, strlen(pre));
	Console_PrintString((char *) syscall_nostr, 3);
	Console_PrintString((char *) post, strlen(post));
}

/** Handle an unimplemented syscall. 
    In good Unix fashion we break hard and noisily */
static void 
abort_syscall(long int nr)
{
	__print_error("NXLIBC ERROR: syscall #", nr, " not supported. Aborting\n");
	nxlibc_syscall_do_exit(1);
}

/** On unimportant syscalls, make noise, but continue. */
static void 
skip_syscall(long int nr)
{
	__print_error("NXLIBC WARNING: syscall #", nr, " not supported. Skipping\n");
}

/** Intercept system calls and redirect the ones that nexus implements there.
    
    @param argcount is the number of used arguments or -1 if unknown
    @return is return of the call if taken, -1 if skipped and
    the function does not return on aborted calls. */
long int 
nxlibc_intercept_syscall (long int nr, int argcount, va_list arglist)
{
#define MAX_ARGCOUNT 6 // need not be higher than what libc can issue

	unsigned long args[MAX_ARGCOUNT], ret = -1;
	int i;

#ifndef NDEBUG
	/* trace all library calls */
	Debug_LinuxCall(nr, 1);
	if (unlikely(nxcall_debug)) __print_error("NXLIBC call #", nr, "\n");
#endif

	/* if number of arguments is unknown we copy all, which is slow and 
	   may try to touch illegal addresses (segfaulting, unlikely). */
	if (argcount == -1)
		argcount = MAX_ARGCOUNT;

	/* fetch args */
	for (i = 0; i < argcount; i++)
		args[i] = va_arg(arglist, unsigned long);

	switch (nr) {
		/**** handled calls: forward call ********/
		
		/** Non I/O system calls *****/

		case __NR_exit : 	nxlibc_syscall_do_exit((long) args[0]); break;

		/* memory */

		case __NR_brk : 	ret = (long) nxlibc_syscall_brk((void *) args[0]); break;
		case __NR_mprotect:	ret = (long) nxlibc_syscall_mprotect((const void *) args[0], 
									      (size_t) args[1], (int) args[2]); break;
		case __NR_mlock: 	ret = (long) nxlibc_syscall_mlock((const void *) args[0], (size_t) args[1]); break;
		case __NR_munlock: 	ret = (long) nxlibc_syscall_munlock((const void *) args[0], (size_t) args[1]); break;

		/* process */

		case __NR_getpid:	ret = (long) nxlibc_syscall_getpid(); break;
		case __NR_getppid:	ret = (long) nxlibc_syscall_getppid(); break;
		case __NR_fork:		ret = (long) nxlibc_syscall_fork(); break;
		case __NR_execve:	ret = (long) nxlibc_syscall_execve((const char *) args[0], (char **) args[1], 
									   (char **) args[2]); break;
		case __NR_waitpid:	ret = (long) nxlibc_syscall_waitpid((long) args[0], (int *) args[1], 
									    (long) args[2]); break;
		case __NR_wait4:	ret = (long) nxlibc_syscall_wait4((long) args[0], (int *) args[1], 
									  (long) args[2], (void *) args[3]); break;
		case __NR_getrlimit:	ret = (long) nxlibc_syscall_getrlimit((int) args[0], (struct rlimit *) args[1]); break;
		case __NR_ugetrlimit:	ret = (long) nxlibc_syscall_ugetrlimit((int) args[0], (struct rlimit *) args[1]); break;
		case __NR_setrlimit:	ret = (long) nxlibc_syscall_setrlimit((int) args[0], (const struct rlimit *) args[1]); break;
		case __NR_times:	ret = (long) nxlibc_syscall_times((struct tms *) args[0]); break;
		case __NR_getpriority:	ret = (long) nxlibc_syscall_getpriority((int) args[0], (int) args[1]); break;
		case __NR_setpriority:	ret = (long) nxlibc_syscall_setpriority((int) args[0], (int) args[1], (int) args[2]); break;

		/** time ****/

		case __NR_nanosleep:	ret = (long) nxlibc_syscall_nanosleep((const struct timespec *) args[0], 
									       (struct timespec *) args[1]); break;
		case __NR_gettimeofday:	ret = (long) nxlibc_syscall_gettimeofday((struct timeval *) args[0], 
										  (void *) args[1]); break;
		case __NR_time:		ret = (long) nxlibc_syscall_time((time_t *) args[0]); break;

		/** access control ****/

		case __NR_getuid:	ret = (long) nxlibc_syscall_getuid(); break;
		case __NR_geteuid:	ret = (long) nxlibc_syscall_geteuid(); break;
		case __NR_getgid:	ret = (long) nxlibc_syscall_getgid(); break;
		case __NR_getegid:	ret = (long) nxlibc_syscall_getegid(); break;

		case __NR_getuid32:	ret = (long) nxlibc_syscall_getuid32(); break;
		case __NR_geteuid32:	ret = (long) nxlibc_syscall_geteuid32(); break;
		case __NR_getgid32:	ret = (long) nxlibc_syscall_getgid32(); break;
		case __NR_getegid32:	ret = (long) nxlibc_syscall_getegid32(); break;

		case __NR_setuid:	ret = (long) nxlibc_syscall_setuid((__uid_t) args[0]); break;
		case __NR_setfsuid:	ret = (long) nxlibc_syscall_setfsuid((int) args[0]); break;
		case __NR_setgid:	ret = (long) nxlibc_syscall_setgid((__gid_t) args[0]); break;
		case __NR_setfsgid:	ret = (long) nxlibc_syscall_setfsgid((int) args[0]); break;

		case __NR_setuid32:	ret = (long) nxlibc_syscall_setuid32((__uid_t) args[0]); break;
		case __NR_setfsuid32:	ret = (long) nxlibc_syscall_setfsuid32((int) args[0]); break;
		case __NR_setgid32:	ret = (long) nxlibc_syscall_setgid32((__gid_t) args[0]); break;
		case __NR_setfsgid32:	ret = (long) nxlibc_syscall_setfsgid32((int) args[0]); break;

		/** signal handling ****/
		case __NR_rt_sigaction:
		case __NR_sigaction:	ret = (long) nxlibc_syscall_sigaction((int) args[0], 
									       (const struct sigaction *) args[1],
									       (struct sigaction *) args[2]); break;
		case __NR_rt_sigprocmask: ret = (long) nxlibc_syscall_rt_sigprocmask((int) args[0], 
							  			     (sigset_t *) args[1], 
							  			     (sigset_t *) args[2], 
										     (size_t) args[3]); break;
		case __NR_sigprocmask:	ret = (long) nxlibc_syscall_sigprocmask((int) args[0], 
										 (const sigset_t *) args[1], 
									         (sigset_t *) args[2]); break;
		case __NR_signal:	ret = (long) nxlibc_syscall_signal((int) args[0], 
									    (sighandler_t) args[1]); break;
#if 0
		case __NR_kill:		ret = (long) nxlibc_syscall_kill((int) args[0], 
									  (int) args[1]); break;
#else
		case __NR_kill:	Debug_printk_msg("XXX KILL DETECTED", (int) args[0]); 
				Debug_printk_msg("XXX KILL #2", (int) args[1]);
				{
					unsigned long ebp;
  					asm("movl %%ebp, %0" : "=g" (ebp));
					Debug_Trace(ebp);
				}
				ret = 0; break;
#endif

		/** other ****/
		
		case __NR_uname:	ret = (long) nxlibc_syscall_uname((void *) args[0]); break;

		/** I/O system calls ****/

		/* IO: filesystem operations */

		case __NR_mkdir : 	ret = (long) nxlibc_syscall_mkdir((const char *) args[0], (mode_t) args[1]); break;

		/* IO: directory operations */

		case __NR_readdir:	ret = (long) nxlibc_syscall_readdir((DIR *) args[0]); break;
		case __NR_chdir:	ret = (long) nxlibc_syscall_chdir((const char *) args[0]); break;
		case __NR_getcwd:	ret = (long) nxlibc_syscall_getcwd((char *) args[0], (int) args[1]); break;

		/* IO: file operations */

		case __NR_readlink:	ret = (long) nxlibc_syscall_readlink((const char *) args[0], (char *) args[1],
									      (int) args[2]); break;
		case __NR_access:	ret = (long) nxlibc_syscall_access((const char *) args[0], (int) args[1]);
		case __NR_link:		ret = (long) nxlibc_syscall_link((const char *) args[0], 
									  (const char *) args[1]); break;
		case __NR_open:		ret = (long) nxlibc_syscall_open((const char *) args[0], 
									  (int) args[1], (int) args[2]); break;
		case __NR_pipe:		ret = (long) nxlibc_syscall_pipe((int*) args[0]); break;
		case __NR_dup:		ret = (long) nxlibc_syscall_dup((int) args[0]); break;
		case __NR_dup2:		ret = (long) nxlibc_syscall_dup2((int) args[0], (int) args[1]); break;
		case __NR_chmod:	ret = (long) nxlibc_syscall_chmod((const char *) args[0], (mode_t) args[1]); break;
		case __NR_stat:		
		case __NR_lstat:	ret = (long) nxlibc_syscall_stat((const char *) args[0], 
                                                              (struct stat *) args[1]); break;
		//case __NR_stat64:		
		//case __NR_lstat64:	ret = (long) nxlibc_syscall_stat64((const char *) args[0], (struct stat64 *) args[1]);
		case __NR_fstat:	ret = (long) nxlibc_syscall_fstat((int) args[0], (struct stat *) args[1]); break;
		//case __NR_fstat64:	ret = (long) nxlibc_syscall_fstat64((int) args[0], (struct stat64 *) args[1]);
		case __NR_statfs:	ret = (long) nxlibc_syscall_statfs((void *) args[0], (void *) args[1]); break;
		case __NR_umask:	ret = (long) nxlibc_syscall_umask((int) args[0]); break;
		case __NR_unlink:	ret = (long) nxlibc_syscall_unlink((const char *) args[0]); break;
		case __NR_rmdir:	ret = (long) nxlibc_syscall_rmdir((const char *) args[0]); break;
		case __NR_rename:	ret = (long) nxlibc_syscall_rename((const char *) args[0], (const char *) args[1]); break;
		/* IO: open file operations */

		case __NR_pread:	ret = (long) nxlibc_syscall_pread((int) args[0], (void *) args[1], 
									   (size_t) args[2], (off_t) args[3]); break;
		case __NR_pwrite:	ret = (long) nxlibc_syscall_pwrite((int) args[0], (const void *) args[1], 
									    (size_t) args[2], (off_t) args[3]); break;
		case __NR_read:		ret = (long) nxlibc_syscall_read((int) args[0], (void *) args[1], 
									  (size_t) args[2]); break;
		case __NR_write:	ret = (long) nxlibc_syscall_write((int) args[0], (const void *) args[1], 
									   (size_t) args[2]); break;
		case __NR_writev:	ret = (long) nxlibc_syscall_writev((int) args[0], 
									    (const struct iovec *) args[1], 
									    (int) args[2]); break;
		case __NR_close:	ret = (long) nxlibc_syscall_close((int) args[0]); break;

		case __NR_ioctl: 	ret = (long) nxlibc_syscall_ioctl((int) args[0], (int) args[1], 
									   (void *) args[2]); break;
		case __NR_fsync:	ret = (long) nxlibc_syscall_fsync((int) args[0]); break;

		case __NR_fdatasync:	ret = (long) nxlibc_syscall_fdatasync((int) args[0]); break;

		case __NR_lseek:	ret = (long) nxlibc_syscall_lseek((int) args[0], (__off_t) args[1], 
									   (int) args[2]); break;
		case __NR_fcntl:	ret = (long) nxlibc_syscall_fcntl((int) args[0], (int) args[1], 
									   (long) args[2]); break;
		case __NR_fcntl64:	ret = (long) nxlibc_syscall_fcntl((int) args[0], (int) args[1], 
									   (long) args[2]); break;

		/* IO: socket state operations */

		case __NR_socket:	ret = (long) nxlibc_syscall_socket((int) args[0], (int) args[1], 
									    (int) args[2]); break;
		case __NR_connect:	ret = (long) nxlibc_syscall_connect((int) args[0], 
									     (const struct sockaddr *) args[1], 
									     (socklen_t) args[2]); break;
		case __NR_bind:		ret = (long) nxlibc_syscall_bind((int) args[0], 
									  (const struct sockaddr *) args[1], 
									  (socklen_t) args[2]); break;
		case __NR_listen:	ret = (long) nxlibc_syscall_listen((int) args[0], (int) args[1]); break;
		case __NR_accept:	ret = (long) nxlibc_syscall_accept((int) args[0], 
									    (struct sockaddr *) args[1], 
									    (socklen_t *) args[2]); break;
		case __NR_getsockname:	ret = (long) nxlibc_syscall_getsockname((int) args[0], 
										 (struct sockaddr *) args[1], 
										 (socklen_t *) args[2]); break;
		case __NR_setsockopt:	ret = (long) nxlibc_syscall_setsockopt((int) args[0], (int) args[1], 
										(int) args[2], (const void *) args[3], 
										(socklen_t) args[4]); break;

		/* IO: socket read/write operations */

		case __NR_send:		ret = (long) nxlibc_syscall_send((int) args[0], (const void *) args[1], 
			    						  (size_t) args[2], (int) args[3]); break;
		case __NR_recv:		ret = (long) nxlibc_syscall_recv((int) args[0], (void *) args[1], 
			    						  (size_t) args[2], (int) args[3]); break;
		case __NR_recvfrom:	ret = (long) nxlibc_syscall_recvfrom((int) args[0], (void *) args[1], 
									      (size_t) args[2], (int) args[3], 
							                      (struct sockaddr *) args[4], 
									      (socklen_t *) args[5]); break;
		case __NR_sendto:	ret = (long) nxlibc_syscall_sendto((int) args[0], (const void *) args[1], 
								            (size_t) args[2], (int) args[3], 
								            (const struct sockaddr *) args[4], 
								            (socklen_t) args[5]); break;

		/* IO: polling calls */

		case __NR__newselect:
		case __NR_select:	ret = (long) nxlibc_syscall_select((int) args[0], (fd_set *) args[1], 
									    (fd_set *) args[2], (fd_set*) args[3],
									    (struct timeval *) args[4]); break;

		/* IO: other */

		case __NR_socketcall: 	ret = (long) nxlibc_syscall_socketcall((int) args[0], 
										(unsigned long *) args[1]); break;

		/**** skipped calls: warn and continue ********/

		// NB: currently no skipped items

		/**** all other calls: make noise and abort ********/
		default 	:	abort_syscall(nr); break;
	}
	
#ifndef NDEBUG
	if (unlikely(nxcall_debug)) __print_error("NXLIBC ret =", ret, "\n");
	Debug_LinuxCall(-nr, 1);
#endif

	return ret;
}

