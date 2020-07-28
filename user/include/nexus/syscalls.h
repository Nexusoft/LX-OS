/** Nexus OS: function around system calling */

#ifndef _NEXUS_USER_SYSCALLS_H_
#define _NEXUS_USER_SYSCALLS_H_

#include <nexus/defs.h> 	// for 'likely'
#include <nexus/syscall-defs.h>

/** switch between sysenter and int 80 system calling. needed for Xen */
extern int __syscall_use_sysenter;

// XXX deprecated?
#ifdef XENLINUX_CALLS
#include <sys/ioctl.h>
#include <stdio.h>
#include <errno.h>

extern int nexus_call_fd;

static inline int 
nexuscall5(int syscallno, int arg1, int arg2, int arg3, int arg4, int arg5) 
{
  struct NIOC_Args arg = {
    .syscallno = syscallno,
    .arg1 = arg1,
    .arg2 = arg2,
    .arg3 = arg3,
    .arg4 = arg4,
    .arg5 = arg5,
  };
  return ioctl(nexus_call_fd, NIOC_NEXUSCALL, &arg);
}

#else

/* only write the assembly constraints once */
#define CONSTRAINTS5											\
    "=a" (rval), "=b" (ignore1), "=c" (ignore2), "=d" (ignore3), "=S" (ignore4), "=D" (ignore5)  : 	\
    "a" (syscallno), "c" (arg1), "d" (arg2), "b" (arg3), "S" (arg4), "D" (arg5) : 			\
    "memory"

/** main system call function */
static inline int 
nexuscall5(int syscallno, int arg1, int arg2, int arg3, int arg4, int arg5) 
{
	int rval, ignore1, ignore2, ignore3, ignore4, ignore5;

	if (likely(__syscall_use_sysenter))
		__asm __volatile__ ("call sysenter_stub " : CONSTRAINTS5);
	else 
		__asm __volatile__ ("int $0x82 " : CONSTRAINTS5);

	return rval;
}

#undef CONSTRAINTS5

// XXX integrate with constraints5
#define CONSTRAINTS2											\
    "=a" (rval), "=b" (ignore1), "=c" (ignore2), "=d" (ignore3), "=S" (ignore4), "=D" (ignore5)  : 	\
      "a" (syscallno), "c" (arg1), "d" (arg2) :								\
    "memory"

/* separate 2 argument system call function. 
 
   This case is called most often (as a result of wrapping most system calls 
   and calling IPC_InvokeSys) warranting a more optimized version.*/
static inline int 
nexuscall2(int syscallno, int arg1, int arg2) 
{
	int rval, ignore1, ignore2, ignore3, ignore4, ignore5;

	if(__syscall_use_sysenter)
		__asm __volatile__ ("call sysenter_stub " : CONSTRAINTS2);
	else 
		__asm __volatile__ ("int $0x82 " : CONSTRAINTS2);

	return rval;
}

#undef CONSTRAINTS2

#endif /* XENLINUX_CALLS */

#define nexuscall4(num, arg1, arg2, arg3, arg4)	nexuscall5(num, arg1, arg2, arg3, arg4, -1)
#define nexuscall3(num, arg1, arg2, arg3) 	nexuscall5(num, arg1, arg2, arg3, -1, -1)
#define nexuscall1(num, arg1) 			nexuscall5(num, arg1, -1, -1, -1, -1)
#define nexuscall0(num) 			nexuscall5(num, -1, -1, -1, -1, -1)

#endif // _NEXUS_USER_SYSCALLS_H_

