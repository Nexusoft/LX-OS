/** NexusOS: nxlibc_syscall sytem call interface regression test.

             Tests all EXCEPT calls working on file descriptors and sockets.
 	     Assumes stdio functionality is correct. */

#include <stdio.h>
#include <sys/mman.h>

#include <nexus/linuxcalls.h>

#define ContinueError(stmt) 							\
	fprintf(stderr, "Warning: failed at %s at %d\n", stmt, __LINE__);

#define ReturnError(stmt) 							\
	do { fprintf(stderr, "Error: failed %s at %d\n", stmt, __LINE__); 	\
	     return -1;								\
	} while(0)


/** standard format test application:
    @return 0 on success, -1 on failure */
int 
main(int argc, char **argv)
{
	struct timespec ts;
	struct timeval tv1, tv2;
	char *data;
	__uid_t uid;
	__gid_t gid;
	int ret;

	// process
	if (nxlibc_syscall_getpid() <= 0)
		ReturnError("getpid");

	// time
	if (nxlibc_syscall_gettimeofday(&tv1, NULL))
		ReturnError("gettimeofday #1");

	ts.tv_sec = 0;
	ts.tv_nsec = 100;
	if (nxlibc_syscall_nanosleep(&ts, NULL) < 0)
		ReturnError("nanosleep");

	if (nxlibc_syscall_gettimeofday(&tv2, NULL))
		ReturnError("gettimeofday #2");

	if (tv2.tv_sec < tv1.tv_sec || 
	    (tv2.tv_sec == tv1.tv_sec && tv2.tv_usec < tv1.tv_usec))
		ContinueError("gettimeofday #3");

	// uid/gid
	uid = nxlibc_syscall_getuid();
	gid = nxlibc_syscall_getgid();

	if (nxlibc_syscall_setuid(uid + 1))
		ReturnError("setuid");
	
	if (nxlibc_syscall_getuid() != uid + 1)
		ReturnError("getuid");

	// memory
	extern void *__curbrk;
	if (nxlibc_syscall_brk(__curbrk + (1 << 22)))
		ReturnError("brk");
	
	if (nxlibc_syscall_mprotect(__curbrk - 10, 10, PROT_READ | PROT_WRITE))
		ReturnError("mprotect");

	if (nxlibc_syscall_mlock(__curbrk - 10, 10))
		ReturnError("mlock");

	if (nxlibc_syscall_munlock(__curbrk - 10, 10))
		ReturnError("munlock");

	// exit
	printf("[%s] OK.\n", argv[0]);
	nxlibc_syscall_do_exit(0);

	// should not be reached
	ReturnError("exit");
	return 1;
}

