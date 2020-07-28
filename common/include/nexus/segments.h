#ifndef SEGMENTS_H
#define SEGMENTS_H

/* These segments must be included in entry.S an assembly file, so only defines can
 * be in here.
 */

// ARCH_X86_32 might be included from XenLinux header files, so be
// careful about what gets compiled
#ifndef _ARCH_X86_32
#define __KERNEL_BOOT_CS  0x10
#define __KERNEL_BOOT_DS  0x18

#define __KERNEL_CS	0xe008
#define __KERNEL_DS	0xe010

#define __USER_CS	0xe02b
#define __USER_DS	0xe033
#endif

#define KNEXUSCS	__KERNEL_CS
#define KNEXUSDS	__KERNEL_DS

#define UNEXUSCS	0xe01b
#define UNEXUSDS	0xe023

#define KXENCS	0xe029
#define KXENDS	0xe031

#define UXENCS	__USER_CS
#define UXENDS	__USER_DS

#define XEN_LIMIT 0xb7ffffff

// TLS uses one unique selector for all CPUs. The GDT for each CPU
// differs in the corresponding descriptor entry.
#define KSHMEM_GS (0xe03b)

#define NR_RESERVED_GDT_ENTRIES    40

// Xen GDT entries must be on a separate page from guest entries
#define FIRST_RESERVED_GDT_PAGE  14
#define FIRST_RESERVED_GDT_BYTE  (FIRST_RESERVED_GDT_PAGE * 4096)
#define FIRST_RESERVED_GDT_ENTRY (FIRST_RESERVED_GDT_BYTE / 8)

#define LAST_RESERVED_GDT_ENTRY    \
          (FIRST_RESERVED_GDT_ENTRY + NR_RESERVED_GDT_ENTRIES - 1)

#ifdef CONFIG_SMP
//disabled: clashes with asm/atomic.h and appears unused
//#define LOCK lock
#define C_LOCK "lock "
#else
#define A_LOCK 
#define C_LOCK 
#endif

#endif

