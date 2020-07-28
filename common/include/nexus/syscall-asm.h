#ifndef _SYSCALL_ASM_H_
#define _SYSCALL_ASM_H_

// SYSENTER_STUB_ADDR offset must be synchronized with kshmem.h !
// assert in kernel/nexus/syscalls.c assures this
#define SYSENTER_STUB_ADDR (0xB8000000 - (1 << 12))

#define SYSEXIT_STUB_ADDR (SYSENTER_STUB_ADDR + 32)

#define TLS_RESERVE 20

#endif // _SYSCALL_ASM_H_
