#ifndef _NEXUS_HYPERCALLS_H_
#define _NEXUS_HYPERCALLS_H_

long HYPERCALL_xen_version(int cmd, void *arg);
long HYPERCALL_mmu_update(int fromVMM, 
                         mmu_update_t *ureqs, unsigned int count,
                         unsigned int *pdone, unsigned int dom_id);

long HYPERCALL_mmuext_op(struct mmuext_op *ops, unsigned int count,
                        unsigned int *pdone, unsigned int foreigndom);

long HYPERCALL_set_trap_table(struct trap_info *table);
long HYPERCALL_set_callbacks (unsigned long event_selector,
                             unsigned long event_address,
                             unsigned long failsafe_selector,
                             unsigned long failsafe_address);
long HYPERCALL_stack_switch(unsigned long ss, unsigned long esp);

// Assembly stubs
extern char hypercall_stub[];
extern char hypercall_stub_end[];
extern char hypercall_iret_stub[];
extern char hypercall_iret_stub_end[];

#endif //  _NEXUS_HYPERCALLS_H_
