/** Nexus OS: kernel allocator

    New version uses dlmalloc underneath */

#ifndef __ALLOC_H__
#define __ALLOC_H__

#include <stddef.h>	// for size_t. can be safely compiled into kernel 

void* dlmalloc(size_t);
void  dlfree(void*);
void* dlrealloc(void*, size_t);
void* dlcalloc(size_t, size_t);

#define galloc(size) dlmalloc(size)
#define gfree(ptr) dlfree(ptr)
#define grealloc(ptr, size) dlrealloc(ptr, size)
#define gcalloc(nmemb, size) dlcalloc(nmemb, size)

/** kernel version of sbrk().
    DO NOT USE directly. Use galloc() instead */
void *gmorecore(int size);

#endif /* __ALLOC_H__ */

