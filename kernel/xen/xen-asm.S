#include <asm/errno.h>

#define NR_hypercalls 64

.text
	.globl num_hypercalls
.align 4 
num_hypercalls:	.long NR_hypercalls

.data

.globl hypercall_table

hypercall_table:	
  .long Xen_H_set_trap_table_Handler
  .long Xen_H_mmu_update_Handler
  .long Xen_H_set_gdt_Handler
  .long Xen_H_stack_switch_Handler
  .long Xen_H_set_callbacks_Handler
  .long Xen_H_fpu_taskswitch_Handler
  .long Xen_H_arch_sched_op_compat_Handler
  .long Xen_H_platform_op_Handler
  .long Xen_H_set_debugreg_Handler
  .long Xen_H_get_debugreg_Handler
  .long Xen_H_update_descriptor_Handler
  .long Xen_H_ni_hypercall_Handler
  .long Xen_H_memory_op_Handler
  .long Xen_H_multicall_Handler
  .long Xen_H_update_va_mapping_Handler
  .long Xen_H_set_timer_op_Handler
  .long Xen_H_event_channel_op_compat_Handler
  .long Xen_H_xen_version_Handler
  .long Xen_H_console_io_Handler
  .long Xen_H_physdev_op_compat_Handler
  .long Xen_H_grant_table_op_Handler
  .long Xen_H_vm_assist_Handler
  .long Xen_H_update_va_mapping_otherdomain_Handler
  .long Xen_H_iret_Handler
  .long Xen_H_vcpu_op_Handler
  .long Xen_H_ni_hypercall_Handler
  .long Xen_H_mmuext_op_Handler
  .long Xen_H_acm_op_Handler
  .long Xen_H_nmi_op_Handler
  .long Xen_H_arch_sched_op_Handler
  .long Xen_H_callback_op_Handler
  .long Xen_H_xenoprof_op_Handler
  .long Xen_H_event_channel_op_Handler
  .long Xen_H_physdev_op_Handler
  .long Xen_H_hvm_op_Handler
  .long Xen_H_sysctl_Handler
  .long Xen_H_domctl_Handler
        .rept NR_hypercalls-((.-hypercall_table)/4)
        .long Xen_H_ni_hypercall_Handler
        .endr

// Make these global to catch symbol name collisions with Xen.sc
#define HYPERCALL_NI(X)		\
	.globl X ;	\
	X:	movl $-ENOSYS, %eax ; ret

HYPERCALL_NI(Xen_H_ni_hypercall_Handler)

HYPERCALL_NI(Xen_H_acm_op_Handler)
HYPERCALL_NI(Xen_H_arch_sched_op_compat_Handler)
HYPERCALL_NI(Xen_H_console_io_Handler)
HYPERCALL_NI(Xen_H_domctl_Handler)
HYPERCALL_NI(Xen_H_event_channel_op_compat_Handler)
HYPERCALL_NI(Xen_H_get_debugreg_Handler)
HYPERCALL_NI(Xen_H_grant_table_op_Handler)
HYPERCALL_NI(Xen_H_hvm_op_Handler)
HYPERCALL_NI(Xen_H_iret_Handler)
HYPERCALL_NI(Xen_H_memory_op_Handler)
HYPERCALL_NI(Xen_H_nmi_op_Handler)
HYPERCALL_NI(Xen_H_physdev_op_compat_Handler)
HYPERCALL_NI(Xen_H_platform_op_Handler)
HYPERCALL_NI(Xen_H_set_debugreg_Handler)
HYPERCALL_NI(Xen_H_sysctl_Handler)
HYPERCALL_NI(Xen_H_update_va_mapping_Handler)
HYPERCALL_NI(Xen_H_update_va_mapping_otherdomain_Handler)
HYPERCALL_NI(Xen_H_vcpu_op_Handler)
HYPERCALL_NI(Xen_H_xenoprof_op_Handler)
HYPERCALL_NI(Xen_H_xen_version_Handler)
