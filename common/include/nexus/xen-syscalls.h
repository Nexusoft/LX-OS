#ifndef _XEN_SYSCALLS_H
#define _XEN_SYSCALLS_H

#include "../nexus/segments.h"

#ifndef PACKED
#define PACKED __attribute__((packed))
#endif

// Definitions for GET/SET interrupt state

#define XEN_GLOBAL_INTR (-1)

// Definitions for SET trap table

#ifdef __NEXUSKERNEL__
// XXX ugly hack to check whether we're in Nexus or in Xen
typedef unsigned long memory_t;   /* Full-sized pointer/address/memory-size. */
typedef unsigned long cpureg_t;   /* Full-sized register.                    */
#else
#include <asm/types.h>
#include <public/arch-x86_32.h>
#endif

#if 0
typedef struct {
    u8       vector;  /* 0: exception vector                              */
    u8       flags;   /* 1: 0-3: privilege level; 4: clear event enable?  */
    u16      cs;      /* 2: code selector                                 */
    memory_t address; /* 4: code address                                  */
} PACKED nexus_trap_info_t; /* 8 bytes */
#endif

struct NexusTrapInfo {
  /* u8 dpl; */
  u8 pending;
  u16      cs;      /* 2: code selector                                 */
  memory_t address; /* 4: code address                                  */
} PACKED;


struct NexusMachineState {
  int vif; /* "virtual irq flag": universal mask for softirqs. 
	      The name is inspired by the VIF flag in V8086 mode, 
	      but has nothing else to do with it.
	   1 for on, 0 for off. */
  __u32 soft_irq_enable_mask; /* bitmask for softirqs. 1 for on, 0 for off. */
  u32 cr2;
};

/* Frame table types. Used in FrameTable, and for pin_to_type
 * syscall */
#define FT_PDIRECTORY 	(0)
#define FT_PTABLE	(1)
#define FT_LDT 		(2)
#define FT_GDT 		(3)
#define FT_RDWR		(4) // Xen RDWR ; set if there is at least one write reference to page in validated page tables
#define FT_READ		(5) // Xen READ ; set if there are only read references to page in validated page tables
#define FT_NRDWR	(6) // "Normal Nexus" RDWR

/* A 'normal' page: either not Xen-specific, or a Xen RW page */
#define FT_ISRDWR(TYPE) ((TYPE) == FT_RDWR || (TYPE) == FT_NRDWR)

#endif // _XEN_SYSCALLS_H
