/** NexusOS: a procfs for Nexus. See .c file for more details */

#ifndef KERNELFS_H_
#define KERNELFS_H_

#include "ipd.h"

/** get a file from /bin (which is itself derived from initrd) */
char * KernelFS_get_bin(const char *name, int *dlen);

#endif
