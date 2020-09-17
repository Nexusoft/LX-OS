/** NexusOS: attestation by the kernel */

#ifndef NEXUS_KERNEL_ATTEST_H
#define NEXUS_KERNEL_ATTEST_H

/// insert credential 'process:$current speaksfor sha1(..)' into guard
int nxattest_sha1_addcred(void);

/// return current process's sha1
int nxattest_sha1_get(int pid, char * user_sha1);
int nxattest_sha1_getcert(int pid, char * filepath);

/// kernel says process says sha1(S1, S2, .., Sn)
int nxattest_sha1_says(IPD *ipd, char **stmts, char *filepath, int cert);

int nxattest_sched_quantum(int quantum);

#endif /* NEXUS_KERNEL_ATTEST_H */

