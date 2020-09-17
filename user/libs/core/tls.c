/* Nexus OS
   Thread local storage support 
 
   XXX explain what's really done and why
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

#include <nexus/Thread.interface.h>
#include <nexus/kshmem.h>
#include <nexus/segments.h>
#include <nexus/types.h>
#include <nexus/x86_emulate.h>

// This struct is tricky to get right
// self needs to line up with %gs:0, for gcc (& (address of) will break 
//    if this invariant is violated)
// So, self needs to be at the end of the data structure, and be at 
// sizeof(ThreadCB) - sizeof(void *)
//
// Add new fields to the front (e.g. lowest addresses), and make sure things
// are properly aligned!
//
// Easy test case: Do & of __thread variable, check sanity of value
struct ThreadCB {
  void *self; // set to self to support computing & on  __thread variable in gcc
};

int __errno_use_tls = 0; // private
int __errno_enable_tls = 1;

int __thread ___tls_errno = 2;
int ___shared_errno = 2;

/** Switch between sysenter and int80 system call methods
    
    Doesn't really belong here, but I won't make a separate 
    syscall.c file just for this 
 */
int __syscall_use_sysenter = 1;

int *
__errno_location(void) 
{
	if (__errno_use_tls)
		return &___tls_errno;
	else
		return &___shared_errno;
}

#define PT_TLS	7

KShSegment *KShSegment_findTLS(void) {
  KShMem *shmem = (KShMem *) KSHMEM_VADDR;
  assert(0 < shmem->num_segments &&
	 shmem->num_segments <= KSHSEGMENT_MAX_NUM);
  int i;
  for(i=0; i < shmem->num_segments; i++) {
    KShSegment *segment = &shmem->segments[i];
    if(0) {
      printf("Seg[%d / %d] = { %p %u %d %x }\n", 
	     i, shmem->num_segments,
	     (void *)segment->vaddr, 
	     (unsigned int)segment->vlength,
	     (int)segment->align,
	     (int) segment->type);
    }
    if(segment->type == PT_TLS) {
      return segment;
    }
  }
  return NULL;
}

// N.B. Be careful with syscalls (e.g. printing) !
// tls_*() are called from restricted (no TLS) environments!

static int tls_round(KShSegment *seg, uint32_t x) {
  return (x + seg->align - 1) / seg->align * seg->align;
}

// returns the new stack position
void *tls_computeLen(void *stackpos) {
  
  // alignment will be done by 
  KShSegment *seg = KShSegment_findTLS();
  int len = sizeof(struct ThreadCB); // must have enough space for ThreadCB
  if(seg == NULL) {
    // printf("computeLen: TLS not found\n");
    return (char *)stackpos - len;
  }

  len += tls_round(seg, seg->vlength);
  unsigned long tls_pos = (unsigned long) ((char *)stackpos - len);
  tls_pos -= tls_pos % seg->align;
  return (char *)tls_pos;
}

// _target is a pointer to the bottom of the area
void tls_setup(char *_target) {
  assert( (((uint32_t)_target) & 0x3) == 0);

  // The TLS data is below the ThreadCB
  KShSegment *seg = KShSegment_findTLS();

  int total_len = 0, memcpy_len = 0;
  char *memcpy_src = NULL;

  if (seg) {
    total_len = tls_round(seg, seg->vlength);
    memcpy_src = (void *)seg->vaddr;
    memcpy_len = seg->dlength;
  }

  memcpy(_target, memcpy_src, memcpy_len);
  memset(_target + memcpy_len, 0, total_len - memcpy_len);

  struct ThreadCB *target = (struct ThreadCB *)(_target + total_len);
  assert( (((uint32_t)target) & 0x3) == 0);
  assert((void *)&target->self == (void*)target);
  
  if (!seg)
    // intentionally break any references to self
    target->self = NULL;
  else
    target->self = (void *)&target->self;
  Thread_SetMyTCB(target);
  
  /* Now it is OK to use __thread variables */
}

