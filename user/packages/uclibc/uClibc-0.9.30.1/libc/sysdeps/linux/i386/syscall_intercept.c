
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <sys/syscall.h>


extern long int nxlibc_intercept_syscall(long int nr, int argc, va_list args);

/** Intercept system calls and redirect them to the nexus libraries.
    
    @param argcount is the number of used arguments or -1 if unknown
    @return is return of the call if taken, -1 if skipped and
    the function does not return on aborted calls. */
long int 
intercept_syscall (long int nr, int argcount, ...)
{
	long int ret;
	va_list arglist;

	/* fetch args */
	va_start(arglist, argcount);
	ret = nxlibc_intercept_syscall(nr, argcount, arglist);
	va_end(arglist);

	return ret;
}

/** most (all) libc callers use macros that bypass this call, 
    but we still have to support it. */
#define syscall(nr, ...) intercept_syscall(nr, -1, __VA_ARGS__)

