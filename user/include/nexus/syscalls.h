/** Nexus OS: function around system calling */

#ifndef _NEXUS_USER_SYSCALLS_H_
#define _NEXUS_USER_SYSCALLS_H_

#include <nexus/defs.h> 	// for 'likely'
#include <nexus/syscall-defs.h>

/** switch between sysenter and int 80 system calling. needed for Xen */
extern int __syscall_use_sysenter;

/** main system call function */
static inline int 
nexuscall5(int syscallno, int arg1, int arg2, int arg3, int arg4, int arg5) 
{
#define CONSTRAINTS5											\
    "=a" (rval), "=b" (ignore1), "=c" (ignore2), "=d" (ignore3), "=S" (ignore4), "=D" (ignore5)  : 	\
    "a" (syscallno), "c" (arg1), "d" (arg2), "b" (arg3), "S" (arg4), "D" (arg5) : 			\
    "memory"

	int rval, ignore1, ignore2, ignore3, ignore4, ignore5;

	if (likely(__syscall_use_sysenter))
		__asm __volatile__ ("call sysenter_stub " : CONSTRAINTS5);
	else 
		__asm __volatile__ ("int $0x82 " : CONSTRAINTS5);

	return rval;
#undef CONSTRAINTS5
}

/* separate 2 argument system call function. 
 
   This case is called most often (as a result of wrapping most system calls 
   and calling IPC_InvokeSys) warranting a more optimized version.*/
static inline int 
nexuscall2(int syscallno, int arg1, int arg2) 
{
#define CONSTRAINTS2 "=a" (rval), "=c" (ignore2), "=d" (ignore3) : "a" (syscallno), "c" (arg1), "d" (arg2) : "memory"

	int rval, ignore2, ignore3;

	if (likely(__syscall_use_sysenter))
		__asm __volatile__ ("call sysenter_stub " : CONSTRAINTS2);
	else 
		__asm __volatile__ ("int $0x82 " : CONSTRAINTS2);

	return rval;
#undef CONSTRAINTS2
}


static inline int
nexuscall0(int syscallno)
{
	int rval;

#define CONSTRAINTS2 "=a" (rval)  : "a" (syscallno)
	if (likely(__syscall_use_sysenter))
		__asm __volatile__ ("call sysenter_stub " : CONSTRAINTS2);
	else 
		__asm __volatile__ ("int $0x82 " : CONSTRAINTS2);
#undef CONSTRAINTS2

	return rval;
}

#define nexuscall4(num, arg1, arg2, arg3, arg4)	nexuscall5(num, arg1, arg2, arg3, arg4, -1)
#define nexuscall3(num, arg1, arg2, arg3) 	nexuscall5(num, arg1, arg2, arg3, -1, -1)
#define nexuscall1(num, arg1) 			nexuscall2(num, arg1, -1)

static inline int thread_yield(void)
{
	return nexuscall0(SYS_RAW_Thread_Yield_CMD);
}

/** For benchmarking */
static inline int thread_getppid(void)
{
	return nexuscall0(SYS_RAW_Thread_GetParentID_CMD);
}

static inline int thread_condvar_wait(int *lock, unsigned int *kqueue, unsigned int usecs, 
		                      int *release_val, unsigned int *release_kqueue)
{
	return nexuscall5(SYS_RAW_CondVar_Wait_CMD, (long) lock, (long) kqueue, 
			  (long) usecs, (long) release_val, (long) release_kqueue);
}

static inline int thread_condvar_signal(int *lock, unsigned int *kqueue)
{
	return nexuscall2(SYS_RAW_CondVar_Signal_CMD, (long) lock, (long) kqueue);
}

static inline int time_gettimeofday(void *tv)
{
	return nexuscall1(SYS_RAW_Time_gettimeofday_CMD, (long) tv);
}

static inline int syscall_fork(void)
{
	return nexuscall0(SYS_RAW_Process_Fork_CMD);
}		

#endif // _NEXUS_USER_SYSCALLS_H_

