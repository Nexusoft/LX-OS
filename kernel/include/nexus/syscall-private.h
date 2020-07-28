#ifndef _SYSCALL_PRIVATE_H_
#define _SYSCALL_PRIVATE_H_
int setup_syscall_stub(Map *m);
void populate_syscall_conn_table(IPD *ipd);
void populate_kernelIPD_syscall_conn_table(IPD *ipd);
#endif // _SYSCALL_PRIVATE_H_
