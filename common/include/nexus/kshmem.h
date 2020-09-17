/** NexusOS: shared memory regions between kernel and userspace 
             both parties must agree on the contents 
		
	     in particular, KSHMEM_VADDR has to be synchronized with where the 
	     kernel expects it. That is set in kernel/include/nexus/syscall-asm.h
 
             one page holds nexustime, nxclock_rate and ntp_offset 
	     the other stores register values during sysenter/sysexit
	         and communicates KShSegments
 */

#ifndef _KSHMEM_H_
#define _KSHMEM_H_

#include <nexus/commontypedefs.h>

// Start of shared kernel region.
// Everything from this address UP is mapped into all tasks (as supervisor)
#define KERNELVADDR 0xC0000000UL

// Start if device region
// Device memory is mapped in this region
#define PHYPAGEVADDR 0xB8000000UL
#define NEXUS_START (PHYPAGEVADDR)

// Location for CPU-specific values, e.g. %gs:0, the pointer to the
// current thread's TCB

// XXX 1 << 12 should be PAGE_SIZE, but it is not defined for userspace
#define KSHMEM_VADDR (NEXUS_START - 1*(1 << 12))
#define NEXUSTIME_VADDR (NEXUS_START - 2*(1 << 12))

/// number of epochs since boot. Similar to a jiffie in Linux
#define NEXUSTIME 	(*((unsigned int volatile*)  ((unsigned long) NEXUSTIME_VADDR)))

/// number of CPU cycles per second
//  portability warning: on 64-bit platforms, NXCLOCK_RATE will incorrectly use 128 bits
#define NXCLOCK_RATE 	(*((unsigned long long volatile*) (((unsigned long) NEXUSTIME_VADDR) + 4)))

/// offset to system time received from a Network Time Protocol (NTP) server
#define NTP_OFFSET 	(*((unsigned int volatile*) (((unsigned long) NEXUSTIME_VADDR) + 12)))

#define KSHSEGMENT_MAX_NUM (16)
struct KShSegment {
  // This is a clone of ElfSeg
  unsigned int	type;
  unsigned int	flags;
  unsigned long	daddr;			/* Disk address */
  unsigned long	vaddr;			/* Virtual address */
  unsigned long	paddr;			/* Physical address (not used) */
  unsigned long	dlength;		/* Size on disk */
  unsigned long	vlength;		/* Size in core */
  unsigned long	align;			/* Alignment on disk and in core */
};

struct KShMem {
  char sysenter_stub[32]; /* XXX these must be the first things in the struct */
  char sysexit_stub[32];  /* or else syscall-asm.h will be offset */
  int num_segments;
  KShSegment segments[KSHSEGMENT_MAX_NUM];
};

#define SYSENTER_STUB_C ((__u32)&((KShMem *)KSHMEM_VADDR)->sysenter_stub)
#define SYSEXIT_STUB_C ((__u32)&((KShMem *)KSHMEM_VADDR)->sysexit_stub)

#define NUM_IPD_ID_BITS 12
#define MAX_IPD_ID (1 << NUM_IPD_ID_BITS)

#endif // _KSHMEM_H_

