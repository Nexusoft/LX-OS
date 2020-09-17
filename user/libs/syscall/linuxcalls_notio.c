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
#include <signal.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/times.h>
#include <openssl/rand.h>

#include <nexus/defs.h>
#include <nexus/init.h>
#include <nexus/vector.h>
#include <nexus/devop.h>
#include <nexus/util.h>
#include <nexus/timing.h>
#include <nexus/kshmem.h>
#include <nexus/ipc.h>
#include <nexus/rdtsc.h>

#include <nexus/Debug.interface.h>
#include <nexus/Mem.interface.h>
#include <nexus/Thread.interface.h>
#include <nexus/Console.interface.h>
#include <nexus/IPC.interface.h>
#include <nexus/Time.interface.h>

#include <nexus/linuxcalls_io.h>	// because execve needs it
#include <nexus/linuxcalls.h>

#include "io.private.h"

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
	Thread_Exit(i, 0, 0);		// then go gracefully ourselves
}

/** Unix (not Posix) call to increase data segment size 
 
    This sbrk does not implement negative increments, but
    does support sbrk(0)
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
//		fprintf(stderr, "tried to lower brk (%p %p)\n", addr, __curbrk);
		// XXX call Mem_FreePages and succeed
		return -1;
	}

	/* should not happen */
	if (unlikely(!addr))
		addr += 1;

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
	int i;
	
	err = syscall_fork();
	if (err < 0)
		return -EAGAIN;
	
	return err;
}

/** Shared implementation of exec() and execve() 
    @param interpose_port enables interpositioning if > 0
           HACK: it enables wait-for-completion if < 0 
 
    @return process id >= 0 on success, 
            -EACCES if process could not be started, or
            process errorcode 
            (note that a process errorcode of -EACCES is wrongly 
             interpreted as a 'did not start' failure) */
static long
nxcall_exec_sub(const char *filepath, char *args, const char **env, 
		int interpose_port)
{
	struct stat stats;
	char *file;
	int fd, ret, off, curlen, size;

	// verify executable
	fd = nxlibc_syscall_open(filepath, O_RDONLY, 0);
	if (fd < 0)
		return -EACCES;
	
	if (fstat(fd, &stats))
		return -EACCES;

	if (!S_ISREG(stats.st_mode))
		return -EACCES;

	// allocate room for image
	file = malloc(stats.st_size);
	
	off = 0;
	while (off < stats.st_size) {
		curlen = nxlibc_syscall_read(fd, file + off, 
					     stats.st_size - off);
		if (curlen < 0)
			goto cleanup_error;
		if (!curlen)
			break;
		off += curlen;
	}
	size = off;

	// XXX support env. variables (USER, PATH, PWD, HOME, FLAGS, LANG, ...)
	if (interpose_port > 0)
		ret = IPC_ExecInterposed(file, size, args, 0, interpose_port);
	else
		ret = IPC_Exec(file, size, args, interpose_port);

	free(file);
	return ret;

cleanup_error:
	free(file);
	return -EACCES;
}

/** Execute a command in a separate process.
    
    WARNING: odd return convention (unfortunately necessary)
    @return the process id, 
    	    -1 if the child has already completed or
            -2 on error 
 */
long
nxcall_exec(const char *command)
{
	char filepath[512], *params;

	params = strchr(command + 1, ' ');
	if (!params)
		return nxcall_exec_sub(command, (char *) command, NULL, 0);
		
	// extract argv[0] and call
	memcpy(filepath, command, params - command);
	filepath[params - command] = 0;
	return nxcall_exec_sub(filepath, (char *) command, NULL, 0);
}

long 
nxcall_exec_ex(const char * filepath, char **argv, char **env, 
		       int interpose_port)
{
	char *args;
	long ret;
	int alen, i, curlen;

	// serialize arguments 
	// 1: calculate string length
	alen = 1; // '\0'
	for (i = 0; argv[i]; i++)
		alen += strlen(argv[i]) + 1;

	// 2: copy each argument into the string
	args = malloc(alen + 1);
	alen = 0;
	for (i = 0; argv[i]; i++) {
		curlen = strlen(argv[i]);
		memcpy(args + alen, argv[i], curlen);
		args[alen + curlen] = ' ';
		alen += curlen + 1;
	}
	args[alen] = '\0';

	ret = nxcall_exec_sub(filepath, args, NULL, interpose_port);
	
	free(args);
	return ret;
}

/** Does not overwrite process, but spawns child and waits on its result */
long
nxlibc_syscall_execve(const char * filepath, char **argv, char **env)
{
    int ret, status;
    
    ret = nxcall_exec_ex(filepath, argv, env, 0);
    if (ret < 0)
        return -1;

    fprintf(stderr, "sysexecve wait\n");
    nxlibc_syscall_waitpid(ret, &status, 0);
    fprintf(stderr, "sysexecve ret=%d\n", WEXITSTATUS(status));
    exit(WEXITSTATUS(status));
}

int
nxlibc_syscall_waitpid(int pid, int *status, int options)
{
	int ret;

	// input validation
	if (pid <= 0) {
		fprintf(stderr, "[waitpid] not supported: pid <= 0\n");
		return -1;
	}
	if (options) {
		fprintf(stderr, "[waitpid] warning: unhandled option\n");
	}

	// wait (currently for any process, no concept of children)
	ret = IPC_WaitPid(pid);

	if (status)
		// bits 0-7h: signal? set to 0 for normal exit (WIFEXITED)
		// bits 8-Fh: low-order 8 bits of returncode (WEXITSTATUS)
		*status = (ret & 0xff) << 8;

	return pid;
}

int
nxlibc_syscall_wait4(int pid, int *status, int options, void *rusage)
{
	if (rusage) {
		memset(rusage, 0, sizeof(*rusage));
		fprintf(stderr, "warning: rusage not implemented in wait4\n");
	}

	return nxlibc_syscall_waitpid(pid, status, options);
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
//#define NO_NEXUSTIME
#ifndef NO_NEXUSTIME 
	unsigned long long cycles;
	long seconds;
	long usecs;

	cycles = rdtsc64();

	// XXX fairly expensive calculation
	seconds = cycles / NXCLOCK_RATE;
	cycles  -= seconds * NXCLOCK_RATE;
	usecs   = cycles / (NXCLOCK_RATE / (1000 * 1000));

	seconds += NTP_OFFSET;

	tv->tv_sec = seconds;
	tv->tv_usec = usecs;
	return 0;
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
	return Thread_GetProcessID();
}

// stupid implementation: each process is its own parent
// (because we do not have real job control right now)
int 
nxlibc_syscall_getppid(void) 
{
	return Thread_GetProcessID();
}


/**** signal handling ****/

// keep a copy of the current (dummy) signaling state for each signal
static struct sigaction nxlibc_sigaction[30];
static sighandler_t nxlibc_sighandler[30];
static sigset_t nxlibc_sigset;

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

/** dummy kill
    pretend to succeed (may cause strange app. behavior) */
int
nxlibc_syscall_kill(pid_t pid, int sig)
{
	return 0;
}

/** Note that we do not actually /implement/ signals */
int 
nxlibc_syscall_sigprocmask(int how, const sigset_t *set, sigset_t * oldset)
{
	int i;

	if (set) {
		switch (how) {
		case SIG_BLOCK:	  
			for (i = 0; i < _SIGSET_NWORDS; i++)
				nxlibc_sigset.__val[i] |= set->__val[i];    
		break;
		case SIG_UNBLOCK:
			for (i = 0; i < _SIGSET_NWORDS; i++)
				nxlibc_sigset.__val[i] &= ~(set->__val[i]);
		break;
		case SIG_SETMASK: memcpy(&nxlibc_sigset, set, sizeof(*set));     
		break;
		};
	}

	if (oldset) 
		*oldset = nxlibc_sigset;

	return 0;
}

long 
nxlibc_syscall_rt_sigprocmask(int how, sigset_t *set, sigset_t *oset, 
			      size_t sigsetsize)
{
	if (sigsetsize == sizeof(sigset_t))	// regular size?
		return nxlibc_syscall_sigprocmask(how, set, oset);
	
	errno = EINVAL;	
	return -1;
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

int 
nxlibc_syscall_uname(struct utsname *buf)
{
	/** Copy no more than the fieldlength */
	void uname_safecopy(char *field, const char *in, size_t fieldlen)
	{
		int len;

		len = strlen(in);
		if (len >= fieldlen)
			len = fieldlen - 1;

		memcpy(field, in, len);
		field[len] = 0;
	}

	uname_safecopy(buf->sysname, "Nexus", sizeof(buf->sysname));
	uname_safecopy(buf->release, "1.0", sizeof(buf->release));
	uname_safecopy(buf->version, __DATE__, sizeof(buf->version));
	
	// XXX use a TPM AIK for this
	uname_safecopy(buf->machine, "unknown", sizeof(buf->machine));
	
	uname_safecopy(buf->nodename, "unknown", sizeof(buf->nodename));
#ifdef _GNU_SOURCE
	uname_safecopy(buf->domainname, "unknown", sizeof(buf->domainname));
#endif

	return 0;
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

/** 'new' getrlimit, with larger RLIM_INFINITY */
int
nxlibc_syscall_ugetrlimit(int resource, struct rlimit * rlim)
{
	// no limits have been implemented
	rlim->rlim_cur = RLIM_INFINITY;
	rlim->rlim_max = RLIM_INFINITY;

	return 0;
}

/** 'old' getrlimit, with smaller RLIM_INFINITY */
int
nxlibc_syscall_getrlimit(int resource, struct rlimit * rlim)
{
	// XXX uclibc does not seem to define the older, smaller, version
	return nxlibc_syscall_ugetrlimit(resource, rlim);
}

int
nxlibc_syscall_setrlimit(int resource, const struct rlimit * rlim)
{
	// no limits have been implemented, but continue with 'success'
	return 0;
}

// XXX actually influence scheduler (but that's currently a simple RR)
static int static_priority;

int
nxlibc_syscall_getpriority(int which, int who)
{
	return static_priority;
}

int 
nxlibc_syscall_setpriority(int which, int who, int prio)
{
	static_priority = prio;
	return 0;
}

clock_t
nxlibc_syscall_times(struct tms *buf)
{
	unsigned long long total, utotal;
 
	total  = Thread_Times(1, 0);
	utotal = Thread_Times(1, 1);

	fprintf(stderr," NXDEBUG: times reports %llu msec (%llu user)\n", total / 1000, utotal / 1000);
	
	buf->tms_utime = utotal;
	buf->tms_stime = total - utotal;
	buf->tms_cutime = 0;
	buf->tms_cstime = 0;

	return total;
}

/* vim: set ts=8 sw=8: */

