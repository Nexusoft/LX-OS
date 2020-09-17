/** NexusOS version of mmap */

#include "linuxcalls_io.h"

__ptr_t mmap(__ptr_t addr, size_t len, int prot,
	     int flags, int fd, __off_t offset)
{
	return nxlibc_syscall_mmap(addr, len, prot, flags, fd, offset);
}

// used internally
__ptr_t __GI_mmap(__ptr_t addr, size_t len, int prot,
	          int flags, int fd, __off_t offset) 
{
	return nxlibc_syscall_mmap(addr, len, prot, flags, fd, offset);
}


