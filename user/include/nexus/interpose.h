/** NexusOS: Interposition interface: 
    allow a process to start a child process and listen on all calls */

#ifndef NEXUS_USER_INTERPOSE_H
#define NEXUS_USER_INTERPOSE_H

#include <nexus/guard.h>

// DEPRECATED
int nxinterpose(int argc, char **argv, int (*callback)(char *, int));

int nxrefmon(char *args[], int (*fn_in)(struct nxguard_tuple),
                           int (*fn_out)(struct nxguard_tuple));
int nxrefmon_kernel(char *args[], int krefmon_id);

#endif /* NEXUS_USER_INTERPOSE_H */

