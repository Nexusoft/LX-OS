#include <asm/errno.h>
#include <nexus/segments.h>
#include "offsets.h"
#define NR_hypercalls 70

.globl hypercall_stub
.globl hypercall_stub_end

	// Need indirect jump, since it is position-independent
	// We can save this jump by adding a more sophisticated stub generator
#define JUMP_TO_GENERIC jmp *generic_hypercall_ptr

hypercall_stub:
	// Precondition:	 Hypercall number in eax
	JUMP_TO_GENERIC
	ud2 // should not reach here
hypercall_stub_end:

        /*
         * HYPERVISOR_iret (#23) is special because it doesn't return and expects a
         * special stack frame. Guests jump at this transfer point instead of
         * calling it.
         */
.globl hypercall_iret_stub
.globl hypercall_iret_stub_end
hypercall_iret_stub:
	pushl %eax
	movl $23, %eax// Hypercall # in %eax
	JUMP_TO_GENERIC
	ud2 // should not get here
hypercall_iret_stub_end:

generic_hypercall_ptr:
	.long generic_hypercall

//void generic_hypercall_byArray(long op, long a0, long a1, long a2, long a3, long a4, long a5);
	
.globl generic_hypercall_byArray

#define HYPERCALL_SAVEREGS() \
	pushl %ebp ; \
	pushl %edi ; \
	pushl %esi ; \
	pushl %edx ; \
	pushl %ecx ; \
	pushl %ebx

#define HYPERCALL_RESTOREREGS() \
	popl %ebx ; \
	popl %ecx ; \
	popl %edx ; \
	popl %esi ; \
	popl %edi ; \
	popl %ebp

generic_hypercall_byArray:
	HYPERCALL_SAVEREGS()

	movl 24+4(%esp), %eax // opcode
	movl 24+8(%esp), %ebx
	movl 24+12(%esp), %ecx
	movl 24+16(%esp), %edx
	movl 24+20(%esp), %esi
	movl 24+24(%esp), %edi
	movl 24+28(%esp), %ebp
	call generic_hypercall
	HYPERCALL_RESTOREREGS()
	ret

generic_hypercall:
	// Save
	pushl %gs
	// Nexus TLS is usable from within VMM
	pushl $KSHMEM_GS
	popl %gs

	// We need two copies of the registers on the stack ;  
	// the argument stack might be modified by the callee
	
	// This copy of registers is for restore
	HYPERCALL_SAVEREGS()
	// This copy of registers is the argument stack for the call
	HYPERCALL_SAVEREGS()

	cmpl $NR_hypercalls, %eax 
	jae bad_hypercall 
	pushl %eax 
	pushl %esp 
	call record_hypercall 
	addl $4, %esp 
	popl %eax 
	call *hypercall_table(,%eax,4)

	addl $24, %esp
	
return_to_user:
	// Restore
	HYPERCALL_RESTOREREGS()

	popl %gs
	ret

bad_hypercall:
	movl $-ENOSYS, %eax
	jmp return_to_user

hypercall_table:	
        .long HYPERCALL_set_trap_table     /*  0 */
        .long HYPERCALL_mmu_update_guest
        .long HYPERCALL_set_gdt
        .long HYPERCALL_stack_switch
        .long HYPERCALL_set_callbacks
        .long HYPERCALL_fpu_taskswitch     /*  5 */
        .long HYPERCALL_arch_sched_op_compat
        .long HYPERCALL_platform_op
        .long HYPERCALL_set_debugreg
        .long HYPERCALL_get_debugreg
        .long HYPERCALL_update_descriptor  /* 10 */
        .long HYPERCALL_ni_hypercall
        .long HYPERCALL_memory_op
        .long HYPERCALL_multicall
        .long HYPERCALL_update_va_mapping
        .long HYPERCALL_set_timer_op       /* 15 */
        .long HYPERCALL_event_channel_op_compat
        .long HYPERCALL_xen_version
        .long HYPERCALL_console_io
        .long HYPERCALL_physdev_op_compat
        .long HYPERCALL_grant_table_op     /* 20 */
        .long HYPERCALL_vm_assist
        .long HYPERCALL_update_va_mapping_otherdomain
        .long HYPERCALL_iret
        .long HYPERCALL_vcpu_op
        .long HYPERCALL_ni_hypercall       /* 25 */
        .long HYPERCALL_mmuext_op
        .long HYPERCALL_acm_op
        .long HYPERCALL_nmi_op
        .long HYPERCALL_arch_sched_op
        .long HYPERCALL_callback_op        /* 30 */
        .long HYPERCALL_xenoprof_op
        .long HYPERCALL_event_channel_op
        .long HYPERCALL_physdev_op
        .long HYPERCALL_hvm_op
        .long HYPERCALL_sysctl             /* 35 */
        .long HYPERCALL_domctl
        .long HYPERCALL_ni_hypercall
        .long HYPERCALL_ni_hypercall
        .long HYPERCALL_ni_hypercall
        .long HYPERCALL_ni_hypercall /* 40 */
        .long HYPERCALL_ni_hypercall
        .long HYPERCALL_ni_hypercall
        .long HYPERCALL_ni_hypercall
        .long HYPERCALL_ni_hypercall
        .long HYPERCALL_ni_hypercall /* 45 */
        .long HYPERCALL_ni_hypercall
        .long HYPERCALL_ni_hypercall
        .long HYPERCALL_ni_hypercall
        .long HYPERCALL_ni_hypercall
        .long HYPERCALL_ni_hypercall /* 50 */
        .long HYPERCALL_ni_hypercall
        .long HYPERCALL_ni_hypercall
        .long HYPERCALL_ni_hypercall
        .long HYPERCALL_ni_hypercall
        .long HYPERCALL_ni_hypercall /* 55 */
        .long HYPERCALL_ni_hypercall
        .long HYPERCALL_ni_hypercall
        .long HYPERCALL_ni_hypercall
        .long HYPERCALL_ni_hypercall
        .long HYPERCALL_getNexusVariables /* 60 */
        .long HYPERCALL_VNet_Init /* 61 */
        .long HYPERCALL_VNet_Send /* 62 */
        .long HYPERCALL_VNet_HasPendingRecv /* 63 */
        .long HYPERCALL_VNet_Recv /* 64 */
        .long HYPERCALL_VNet_SetupIRQ /* 65 */
        .rept NR_hypercalls-((.-hypercall_table)/4)
        .long HYPERCALL_ni_hypercall
        .endr

// Context switch code for jumping to kernel
// void __attribute__ ((noreturn))
//	switch_to_finalize_asm(struct vcpu_guest_context *ctx);

.globl switch_to_finalize_asm
switch_to_finalize_asm: // 19 - 3 fields to restore
	movl 4(%esp), %eax
	fxrstor vcpu_guest_context__fpu_ctxt__x(%eax)
	lea vcpu_guest_context__user_regs(%eax), %eax
	movl cpu_user_regs__ebx(%eax), %ebx
	movl cpu_user_regs__ecx(%eax), %ecx
	movl cpu_user_regs__edx(%eax), %edx
	movl cpu_user_regs__esi(%eax), %esi
	movl cpu_user_regs__edi(%eax), %edi
	movl cpu_user_regs__ebp(%eax), %ebp

	movw cpu_user_regs__es(%eax), %es
	movw cpu_user_regs__fs(%eax), %fs
	movw cpu_user_regs__gs(%eax), %gs

	// Struct ordering is wrong for lss!
	movl cpu_user_regs__esp(%eax), %esp
	movw cpu_user_regs__ss(%eax), %ss

	/*
	iret expects:
	EFLAGS
	CS
	EIP
	*/
	
	pushl cpu_user_regs__eflags(%eax)
	pushl cpu_user_regs__cs(%eax)
	pushl cpu_user_regs__eip(%eax)
	pushw cpu_user_regs__ds(%eax)
	movl cpu_user_regs__eax(%eax), %eax
	popw %ds

	iret


//unsigned long guest_pfault_handler_cs;
//unsigned long guest_pfault_handler_eip;

// CS is higher than EIP in memory for ljmp *
.data
.globl guest_pfault_handler_cs
.globl guest_pfault_handler_eip
.align 4
guest_pfault_handler:
guest_pfault_handler_eip:	.long 0
guest_pfault_handler_cs:	.long 0

.text
.globl vmm_pfault_handler_asm
// void vmm_pfault_handler(IretFrame *exception_frame, unsigned int error_code, Regs *regs)

pf_handler_popfl:
	popfl
	jmp pf_handler
	
vmm_pfault_handler_asm:
	// Iret frame + error code is on stack

	// vmm_pfault_handler() only handles page table writes. Determine this via error code

	pushfl // testl will trash flags
	// XXX 1 << 15 is PFEC_nexus_wr_ptable (machine-structs.h)
	// need to refactor machine-structs.h to include here
	testl $(1 << 15), 4(%esp)
	jnz pf_handler_popfl 
	popfl
	ljmp *guest_pfault_handler
	ud2 // should not return

