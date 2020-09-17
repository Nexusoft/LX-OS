/** Nexus OS: Define symbols that userspace drivers can access
    (as they're linked against libnexus-*), but for which they
    cannot include the libc header files (due to collisions with
    symbols defined by Linux headers) */

#ifndef _LIBC_PROTOS_H_
#define _LIBC_PROTOS_H_

// These includes are safe, because they are neither user nor kernel:
// they come from gcc.
#include <stddef.h>
#include <stdarg.h>

// Prototypes of standard C library functions. Used in strange
// environments, such as __KERNEL__, where the full C include files
// have conflicting definitions.

void *memalign(size_t boundary, size_t size);
void *malloc(size_t size);
void free(void *ptr);
void exit(int status);
#define assert
int printf(const char *format, ...);
int vprintf(const char *format, va_list ap);

// Prototypes of Nexus functionality for which we do not want
// to include user headerfiles

static inline void 
nx_udriver_panic(const char *fmt)
{
	printf("PANIC (%s) in userdriver at %s:%d\n",
	       fmt, __FILE__, __LINE__); 	
	exit(1);
}

void dump_stack_trace(unsigned int *ebp);

#endif // _LIBC_PROTOS_H_
