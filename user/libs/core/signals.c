/** NexusOS: Posix Signals 

    Implementation peculiarities:
    - uses a background thread to implement asynchronous handler callback
    - does not wake up blocked calls (read, write, ...) to send -EINTR:
      acts as if SA_RESTART has been set

*/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>


//// set callback

sighandler_t 
nxlibc_syscall_signal(int signum, sighandler_t handler)
{
}

int
nxlibc_syscall_sigaction(int signum, const struct sigaction *act,
		         struct sigaction *oldact)
{
}

nxlibc_syscall_sigaltstack(const stack_t *ss, stack_t *oss)
{
	fprintf(stderr, "[signal] unsupported %s called\n");
	return -ENOMEM;
}

int
nxlibc_syscall_signalfd4(int fd, const sigset_t *mask, int flags)
{
	fprintf(stderr, "[signal] unsupported %s called\n");
	return -ENOMEM;
}

int
nxlibc_syscall_signalfd(int fd, const sigset_t *mask)
{
	return nxlibc_syscall_signalfd4(fd, mask, 0);
}

int
nxlibc_syscall_sigpending(sigset_t *set)
{
}

int
nxlibc_syscall_sigprocmask(int how, const sigset_t *set, sigset_t *oldset) 
{
}

int __attribute__((noreturn))
nxlibc_syscall_sigreturn(unsigned long __unused)
{
	// noop. does not return
}

rt_sigaction(2)    
rt_sigpending(2)   
rt_sigprocmask(2)  
rt_sigqueueinfo(2) 
rt_sigreturn(2)    
rt_sigsuspend(2)   


//// synchronous waiting on signals

/** Suspend process until a signal arrives */
int
nxlibc_syscall_pause(void)
{
}

/** Like pause, but only wait for a non-masked signals */
int
nxlibc_syscall_sigsuspend(const sigset_t *mask)
{
}

/** Wait for a signal to arrive */
int 
nxlibc_syscall_sigwaitinfo(const sigset_t *set, siginfo_t *info)
{
}

int 
nxlibc_syscall_sigtimedwait(const sigset_t *set, siginfo_t *info,
                            const struct timespec *timeout)
{
}

rt_sigtimedwait(2) 


//// send signals

/** Send a signal to a process */
int
nxlibc_syscall_kill(int pid, int signum)
{
	if (pid <= 0) {
		fprintf(stderr, "[signal] kill to group not supported\n");
		return -ESRCH;
	}
}

/** Send kill signal to a specific thread (not supported) */
tgkill

/** Deprecated precursor to tgkill */
tkill


/** realtime-signals: enqueue */
int 
sigqueue(pid_t pid, int sig, const union sigval value)
{
}


//// alarm handling

setitimer
getitimer
timer_create
timer_create(2)    
timer_delete(2)    
timer_getoverrun(2)
timer_gettime(2)   
timer_settime(2)   
timerfd_create(2)  
timerfd_gettime(2) 
timerfd_settime(2) 




