/** Nexus OS: system call implementations

    For its userspace environment, nexus relies partly on libc. This,
    in turn requires Nexus to implement some common Linux system calls.
    Which it doesn't. 

    Instead, we implement these as userspace functions that call the
    actual Nexus system calls when needed and patch libc to divert
    its syscalls to these wrappers.

    To avoid symbol clashing and keep call order understandable, all 
    these fake Linux system calls have the prefix

      nxlibc_syscall_
 
 */

#include <stdarg.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <openssl/rand.h>

#include <nexus/defs.h>
#include <nexus/init.h>
#include <nexus/vector.h>
#include <nexus/devop.h>
#include <nexus/util.h>
#include <nexus/timing.h>
#include <nexus/kshmem.h>
#include <nexus/vkey.h>
#include <nexus/debug.h>
#include <nexus/env.h>
#include <nexus/ipc.h>

#include <nexus/Debug.interface.h>
#include <nexus/Crypto.interface.h>
#include <nexus/Mem.interface.h>
#include <nexus/Audio.interface.h>
#include <nexus/Thread.interface.h>
#include <nexus/Console.interface.h>
#include <nexus/IPC.interface.h>
#include <nexus/Time.interface.h>

#include <nexus/linuxcalls_io.h>	// because execve needs it
#include <nexus/linuxcalls.h>

unsigned int 
nxlibc_syscall_sleep(unsigned int seconds) 
{
	Thread_USleep(seconds * 1000000);
	return 0;
};

int 
nxlibc_syscall_usleep(__useconds_t usec) 
{
	Thread_USleep(usec);
	return 0;
}

void 
nxlibc_syscall_do_exit(int i) 
{
	Thread_KillAll();		// first kill all other threads
	Thread_Exit(i, 0, 0);		// then go gracefully ourselves
}

/*** current program break. 
     Also access from libc, so do not change */

extern void *__curbrk;

/** Unix (not Posix) call to increase data segment size 
 
    @return On success, the location of the previous program
            break, which then act as pointer into the freshly
	    allocated region. On failure, (void *) -1.

    This sbrk does not implement negative increments, but
    does support sbkr(0)
 */
int
nxlibc_syscall_brk(void *addr) 
{
	void *newpgs;
	unsigned long numpgs;
	int ret;

	/* even round up and return a page when address is equal to 
	   __curbrk. Appears required by uclibc:sbrk() */
	if (unlikely(addr < __curbrk)) {
		// XXX call Mem_FreePages and succeed
		return -1;
	}

	/* calculate number of pages and allocate */
	numpgs = ((addr - __curbrk) + PAGESIZE - 1) / PAGESIZE;
	newpgs = (void *) Mem_Brk(numpgs, (int) __curbrk);
	
	if (!newpgs)
		return -1;

	if (newpgs < __curbrk) {
		printf("%s: detected wrap around brk: %p < %p. dropping\n",
		       __FUNCTION__, newpgs, __curbrk);
		return -1;
	}

	__curbrk = newpgs + (numpgs * PAGESIZE);
	return 0;
}

long 
nxlibc_syscall_fork(void)
{
	int err;
	
	err = Thread_ForkProcess();
	if (err < 0)
		errno = EAGAIN;
	return err;
}

/** This does NOT implement standard execve: the new process does not
    replace the caller. */
long 
nxlibc_syscall_execve(const char * filepath, char **argv, char **env)
{
	struct stat stats;
	char *file, *args;
	int size;
	int fd, ret, alen, i, curlen;

	fd = nxlibc_syscall_open(filepath, O_RDONLY, 0);
	if (fd < 0)
		return -1;
	
// XXX implement this correctly
#if 0
	printf("stat not implemented correctly. have to fail\n");
	return -1;

	if (fstat(fd, &stats))
		return -1;

	if (!S_ISREG(stats.st_mode)) {
		errno = EACCES;
		return -1;
	}

	file = malloc(stats.st_size);
	
	// XXX support interrupts and continue reading
	if (nxlibc_syscall_read(fd, file, stats.st_size) != stats.st_size)
		return -1;

#else
#define MAXFILESIZE (1 << 24)
	// HACK: overprovision
	file = malloc(MAXFILESIZE);
	if (!file)
		return -1;

	size = nxlibc_syscall_read(fd, file, MAXFILESIZE);
	if (size == -1 || size == MAXFILESIZE)
		return -1;

#endif

	// serialize arguments into one long string
	// first calculate string length
	alen = 0;
	for (i = 0; argv[i]; i++)
		alen += strlen(argv[i]) + 1;

	// then copy each argument into the string
	args = malloc(alen + 1);
	alen = 0;
	for (i = 0; argv[i]; i++) {
		curlen = strlen(argv[i]);
		memcpy(args + alen, argv[i], curlen);
		args[alen + curlen] = ' ';
		alen += curlen + 1;
	}
	args[alen] = '\0';

	// XXX support env. variables (PATH, FLAGS, LANG, PWD, HOME, ...)
	ret = IPC_Exec(file, size, args);

	free(args);
	free(file);

	return ret;
}

static int uid = 0, gid = 0;

int 
nxlibc_syscall_setfsuid(int fsuid) 
{
	int ret;

	ret = uid;
	uid = fsuid;

	return ret;
}

int nxlibc_syscall_setfsuid32(int fsuid)
{
	return nxlibc_syscall_setfsuid(fsuid);
}

int nxlibc_syscall_setfsgid(int fsgid)
{
	int ret;
	
	ret = gid;
	gid = fsgid;

	return ret;
};

int nxlibc_syscall_setfsgid32(int fsgid)
{
	return nxlibc_syscall_setfsgid(fsgid);
}


int nxlibc_syscall_setuid(__uid_t u) 
{
  uid = u;
  return 0;
}

int nxlibc_syscall_setuid32(__uid_t g)
{
	return nxlibc_syscall_setuid(g);
}

int nxlibc_syscall_setgid(__gid_t g) 
{
  gid = g;
  return 0;
}

int nxlibc_syscall_setgid32(__gid_t g)
{
	return nxlibc_syscall_setgid(g);
}

__gid_t nxlibc_syscall_getegid(void){ return gid; }
__gid_t nxlibc_syscall_getegid32(void){ return gid; }
__uid_t nxlibc_syscall_geteuid(void){ return uid; }
__uid_t nxlibc_syscall_geteuid32(void){ return uid; }
__uid_t nxlibc_syscall_getuid(void){ return uid; }
__uid_t nxlibc_syscall_getuid32(void){ return uid; }
__gid_t nxlibc_syscall_getgid(void){ return gid; }
__gid_t nxlibc_syscall_getgid32(void){ return gid; }

int nxlibc_syscall_nanosleep(const struct timespec *req, struct timespec *rem){
  int i;

  if (req == NULL)
    return -1;

  //XXX nanosecond precision?
  for (i = 0; i < req->tv_sec; i++)
    Thread_USleep(1000000);

  if (rem) {
    rem->tv_sec = 0;
    rem->tv_nsec = 0;
  }

  return 0;
}

int 
nxlibc_syscall_gettimeofday(struct timeval *tv, void *tz)
{
#define NO_NEXUSTIME	// seems very imprecise: 250ms became 2ms in one case
#ifndef NO_NEXUSTIME
static int debugNEXUSTIME;
	// read time from the special segment that holds kernel var nexustime
	static int usecpertick = 0;
	unsigned long long seconds, usecs;

	if (usecpertick == 0)
		usecpertick = Time_GetUSECPERTICK();

debugNEXUSTIME++;
	seconds = debugNEXUSTIME * usecpertick;
	usecs   = seconds % 1000000;
	seconds -= usecs;
	seconds /= 1000000;
	seconds += 100; // hack: don't let it be 0. XXX remove 

	tv->tv_sec = seconds;
	tv->tv_usec = usecs;
#else
	// ask the kernel
	Time_gettimeofday(tv);
#endif
	return 0;
}

time_t 
nxlibc_syscall_time(time_t *t)
{
	struct timeval tv;

	if (nxlibc_syscall_gettimeofday(&tv, NULL)) {
		errno = EFAULT;
		return -1;
	}
	
	if (t)
		*t = tv.tv_sec;

	return tv.tv_sec; // we're gonna party like it's 1970
}

int 
nxlibc_syscall_mprotect(const void *addr, size_t len, int prot) 
{
	Mem_MProtect((unsigned int) addr, len, prot);
	return 0;
}

// mlock() is a no-op with non-paged Nexus
int 
nxlibc_syscall_mlock(const void *addr, size_t len) 
{
	return 0;
}

// munlock() is a no-op with non-paged Nexus
int 
nxlibc_syscall_munlock(const void *addr, size_t len)
{
	return 0;
}

int 
nxlibc_syscall_getpid(void) 
{
	// XXX should return process ID, not thread ID
	return pthread_self();
}


/**** signal handling ****/

// keep a copy of the current (dummy) signaling state for each signal
static struct sigaction nxlibc_sigaction[30];
static sighandler_t nxlibc_sighandler[30];

/** mostly unimplemented sigaction. supports saving and restoring state */
int
nxlibc_syscall_sigaction(int signum, const struct sigaction *act,
		 	 struct sigaction *oldact)
{
	if (signum == SIGSTOP || signum == SIGKILL) {
		errno = EINVAL;
		return -1;
	}

	if (oldact)
		memcpy(oldact, nxlibc_sigaction + signum, sizeof(struct sigaction));

	if (act)
		memcpy(nxlibc_sigaction + signum, oldact, sizeof(struct sigaction));

	return 0;
}

sighandler_t
nxlibc_syscall_signal(int signum, sighandler_t handler)
{
	sighandler_t oldhandler; 

	if (signum == SIGSTOP || signum == SIGKILL) {
		errno = EINVAL;
		return SIG_ERR;
	}

	oldhandler = nxlibc_sighandler[signum];
	nxlibc_sighandler[signum] = handler;

	if (!oldhandler) // hack: unitialized means SIG_DFL
		return SIG_DFL;
	else
		return oldhandler;
}

/**** deprecated stuff waiting for the janitor. 
      don't look here unless you enjoy taking out the garbage ********/

/* XXX: remove this useless wrapper 
        is unfortunately called many times */
int __attribute__((deprecated)) 
writefile(const char *filename, const void *buffer, int size)
{
	fprintf(stderr, "%s: deprecated\n", __FUNCTION__);
	return -1;
}

