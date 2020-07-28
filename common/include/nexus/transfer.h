#ifndef TRANSFER_H_
#define TRANSFER_H_

#ifndef __NEXUSKERNEL__
#ifdef NEXUS_UDRIVER
#include <nexus/libc-protos.h>
#else
#include <stdlib.h>
#include <stdio.h>
#endif
#endif

#define MAX_TRANSFERDESCS (16)

// Descriptors for use during interposed transfer
#define FIRST_KERNEL_DESCNUM (128)
#define ACCUM_DESCNUM (128)
#define DEST_DESCNUM (ACCUM_DESCNUM + 1)
#define IS_KERNEL_DESCNUM(X) ((X) >= ACCUM_DESCNUM)

enum TransferPerm {
  IPC_READ = 0x1,
  IPC_WRITE = 0x2,
  // physical page is transferred to kernel. The descriptor acquires a reference to the page
};

enum TransferMode {
  IPC_MODE_NORMAL = 0,
  IPC_MODE_TRANSFERPAGE = 1,

  IPC_MODE_CLONE_TRANSFERED_DESC = 2,
  // N.B. Copy preserves alignment
  IPC_MODE_COPY_TRANSFERED_DESC = 3,
};

enum KernelTransferMode {
  IPC_KMODE_PHYSICAL = 1,
};

#define TRANSFER_ACCESS_MODE_MASK (0xf)
#define TRANSFER_KERNEL_MODE_MASK (0xf00)
#define TRANSFER_KERNEL_MODE_SHIFT (8)
#define TRANSFER_USER_MODE_MASK (0xf0)
#define TRANSFER_USER_MODE_SHIFT (4)

struct TransferDesc {
  int access; // TransferPerm bits (:4)
  //int mode : 4;
  //int kernel_mode : 4;
  union {
    struct { // compatibility, unqualified anon union
      unsigned int base;
      unsigned int length;
    } direct; // kernel only internally uses these

    struct {
      unsigned int rel_base;
      unsigned int length;

      unsigned int call_handle;
      unsigned int desc_num;
    } copy_or_clone; // these are used only in the initial call
  }u;
};


static inline void TransferDesc_set_kmode_physical(struct TransferDesc *desc) {
  desc->access |= IPC_KMODE_PHYSICAL << TRANSFER_KERNEL_MODE_SHIFT;
}

static inline int TransferDesc_get_kmode(struct TransferDesc *desc) {
  return (desc->access & TRANSFER_KERNEL_MODE_MASK) >> 
    TRANSFER_KERNEL_MODE_SHIFT;
}

static inline int TransferDesc_get_umode(struct TransferDesc *desc) {
  return (desc->access & TRANSFER_USER_MODE_MASK) >> 
    TRANSFER_USER_MODE_SHIFT;
}

// TransferDesc_get_base() and TransferDesc_get_len() have almost identical structure

// TransferDesc_get_base() returns the base of a descriptor within the
// kernel, or when passed to RecvCall() / AsyncRecv(). It is not
// designed to work with descriptors that are passed down into
// Invoke() or AsyncSend().

static inline unsigned int TransferDesc_get_base(struct TransferDesc *desc) {
#ifdef __NEXUSKERNEL__
  // kernel only uses direct version
  return desc->u.direct.base;
#else
  if(TransferDesc_get_kmode(desc) == IPC_KMODE_PHYSICAL) {
    return desc->u.direct.base;
  }
  switch(TransferDesc_get_umode(desc)) {
  case IPC_MODE_NORMAL:
    return desc->u.direct.base;
    break;
  case IPC_MODE_TRANSFERPAGE:
  case IPC_MODE_CLONE_TRANSFERED_DESC:
  case IPC_MODE_COPY_TRANSFERED_DESC:
  default:
    // unsupported, should have had physical bit set
#ifndef __NEXUSKERNEL__
#ifndef NEXUS_UDRIVER
    fprintf(stderr, "unsupported TransferDesc_get_base()\n");
#endif
    exit(1);
#else
    // force a crash in the kernel
    *(char *)0 = 0;
#endif
    return 0;
  }
#endif
}

static inline unsigned int TransferDesc_get_length(struct TransferDesc *desc) {
#ifdef __NEXUSKERNEL__
  // kernel only uses direct version
  return desc->u.direct.length;
#else
  if(TransferDesc_get_kmode(desc) == IPC_KMODE_PHYSICAL) {
    return desc->u.direct.length;
  }
  switch(TransferDesc_get_umode(desc)) {
  case IPC_MODE_NORMAL:
    return desc->u.direct.length;
    break;
  case IPC_MODE_TRANSFERPAGE:
  case IPC_MODE_CLONE_TRANSFERED_DESC:
  case IPC_MODE_COPY_TRANSFERED_DESC:
  default:
    // unsupported, should have had physical bit set
#ifndef NEXUS_UDRIVER
    printf("unsupported TransferDesc_get_length()\n");
#endif
    exit(1);
    return 0;
  }
#endif
}


// DESCRIPTOR_START is passed to TransferFrom() / TransferTo() to specify the beginning of the descriptor as the target
#define DESCRIPTOR_START (0)

#endif // TRANSFER_H_
