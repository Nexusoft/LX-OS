/*
 *  linux/arch/i386/entry.S
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 */

/*
 * entry.S contains the system-call and fault low-level handling routines.
 * This also contains the timer-interrupt handler, as well as all interrupts
 * and faults that can result in a task-switch.
 *
 * NOTE: This code handles signal-recognition, which happens every time
 * after a timer-interrupt and after each system call.
 *
 * I changed all the .align's to 4 (16 byte alignment), as that's faster
 * on a 486.
 *
 * Stack layout in 'ret_from_system_call':
 * 	ptrace needs to have all regs on the stack.
 *	if the order here is changed, it needs to be
 *	updated in fork.c:copy_process, signal.c:do_signal,
 *	ptrace.c and ptrace.h
 *
 *	 0(%esp) - %ebx
 *	 4(%esp) - %ecx
 *	 8(%esp) - %edx
 *       C(%esp) - %esi
 *	10(%esp) - %edi
 *	14(%esp) - %ebp
 *	18(%esp) - %eax
 *	1C(%esp) - %ds
 *	20(%esp) - %es
 *	24(%esp) - orig_eax
 *	28(%esp) - %eip
 *	2C(%esp) - %cs
 *	30(%esp) - %eflags
 *	34(%esp) - %oldesp
 *	38(%esp) - %oldss
 *
 * "current" is in register %ebx during any slow entries.
 */
#include <nexus/segments.h>
//#include <asm/segment.h>
#include <linux/linkage.h>
#include <nexus/syscall-asm.h>
#include <nexus/asm-offsets.h>
#include <nexus/ipd-asm.h>
		
	// 44 %ss:
	// movl xxx, %ss:XXX(%esp)
// Some reordering to help prefetch cache lines
#define TRAPSAVE_REGS	\
	movl %edi, %ss:32(%esp); 		  		\
	/* prefetch segment register */	\
	movl %ss:(nexus_gdt_table + (KNEXUSDS & ~0x3)), %edi ; 	\
1:	movl $KNEXUSDS,%edi; 	  		\
	movw %gs, %ss:0(%esp); \
	movw %fs, %ss:4(%esp);\
	movw %es, %ss:8(%esp); \
	movw %ds, %ss:12(%esp); \
	movl %ebx, %ss:16(%esp); 		  		\
	movl %ecx, %ss:20(%esp); 		  		\
	movl %edx, %ss:24(%esp); 		  		\
	movl %esi, %ss:28(%esp); 		  		\
	movl %ebp, %ss:36(%esp); 		  		\
	movl %eax, %ss:40(%esp);	\
	movl %edi,%ds;   	  		\
	movl %edi,%es;              		\
        pushl %esp;  /* put a pointer to the saved state on the stack */

#define TRAPSAVE				\
	subl $44, %esp		;  \
	TRAPSAVE_REGS

#define TRAPSAVE_MORE(K)				\
	subl $(44+K), %esp		;  \
	TRAPSAVE_REGS


/* Reorder to help prefetch cachelines */
#define TRAPRESTORE									      \
	movl 36(%esp), %edi; 		  		\
	movw 12(%esp), %es; \
	movl 20(%esp), %ebx; 		  		\
	movl 24(%esp), %ecx; 		  		\
	movl 28(%esp), %edx; 		  		\
	movl 32(%esp), %esi; 		  		\
	movl 40(%esp), %ebp; 		  		\
	movl 44(%esp), %eax; 		  		\
	movw 16(%esp), %ds; \
	addl $44+8, %esp /* discard the argument, error code or empty space from the stack */
			
ENTRY(nexus_asm_divide_error) /* Interrupt 0 */
#ifdef DIRECT_NEXUS_INTERRUPT
     	cld
	subl $4, %esp # move the stack to make up for lack of error code
	movw $0, 2(%esp)
	TRAPSAVE
#endif
	call nexus_check_divide_error
	TRAPRESTORE
	iret

ENTRY(nexus_asm_debug) /* Interrupt 1 */
#ifdef DIRECT_NEXUS_INTERRUPT
     	cld
	subl $4, %esp # move the stack to make up for lack of error code
	movw $1, 2(%esp)
	TRAPSAVE	
#endif
	call nexus_check_debug_intr
	TRAPRESTORE
	iret
	
ENTRY(nexus_asm_nmi) /* Interrupt 2 XXX*/
#ifdef DIRECT_NEXUS_INTERRUPT
	cld
	subl $4, %esp # move the stack to make up for lack of error code
	movw $2, 2(%esp)
	TRAPSAVE	
#endif
	call nexus_check_nmi
	TRAPRESTORE
	iret

ENTRY(nexus_asm_int3) /* Interrupt 3 */
#ifdef DIRECT_NEXUS_INTERRUPT
     	cld
	subl $4, %esp # move the stack to make up for lack of error code
	movw $3, 2(%esp)
	TRAPSAVE	
#endif
	call nexus_check_int3
	TRAPRESTORE
	iret

ENTRY(nexus_asm_overflow) /* Interrupt 4 */
#ifdef DIRECT_NEXUS_INTERRUPT
     	cld
	subl $4, %esp # move the stack to make up for lack of error code
	movw $4, 2(%esp)
	TRAPSAVE	
#endif
	call nexus_check_overflow
	TRAPRESTORE
	iret

ENTRY(nexus_asm_bounds) /* Interrupt 5 */
#ifdef DIRECT_NEXUS_INTERRUPT
     	cld
	subl $4, %esp # move the stack to make up for lack of error code
	movw $5, 2(%esp)
	TRAPSAVE	
#endif
	call nexus_check_bounds
	TRAPRESTORE
	iret

ENTRY(nexus_asm_invalid_op) /* Interrupt 6 */
#ifdef DIRECT_NEXUS_INTERRUPT
	cld
	subl $4, %esp # move the stack to make up for lack of error code
	movw $6, 2(%esp)
	TRAPSAVE	
#endif
	call nexus_check_invalid_op
	TRAPRESTORE
	iret

ENTRY(nexus_asm_device_not_available) /* Interrupt 7 */
#ifdef DIRECT_NEXUS_INTERRUPT
	cld
	subl $4, %esp # move the stack to make up for lack of error code
	movw $7, 2(%esp)
	TRAPSAVE	
#endif
	call nexus_check_device_not_available
	TRAPRESTORE
	iret

ENTRY(nexus_asm_double_fault) /* Interrupt 8 */
#ifdef DIRECT_NEXUS_INTERRUPT
	cld
	# a 0 is on top of the stack 
	movw $8, 2(%esp)
	TRAPSAVE	
#endif
	call nexus_check_double_fault
	TRAPRESTORE
	iret
	
ENTRY(nexus_asm_coprocessor_segment_overrun) /* Interrupt 9 */
#ifdef DIRECT_NEXUS_INTERRUPT
     	cld
	subl $4, %esp # move the stack to make up for lack of error code
	movw $9, 2(%esp)
	TRAPSAVE	
#endif
	call nexus_check_coprocessor_segment_overrun
	TRAPRESTORE
	iret

ENTRY(nexus_asm_invalid_TSS) /* Interrupt 10 */
#ifdef DIRECT_NEXUS_INTERRUPT
	cld
	# errorcode is on top of the stack 
	movw $10, 2(%esp)
	TRAPSAVE	
#endif
	call nexus_check_invalid_TSS
	TRAPRESTORE
	iret

ENTRY(nexus_asm_segment_not_present) /* Interrupt 11 */
#ifdef DIRECT_NEXUS_INTERRUPT
	cld
	# errorcode is on top of the stack 
	movw $11, 2(%esp)
	TRAPSAVE	
#endif
	call nexus_check_segment_not_present
	TRAPRESTORE
	iret

ENTRY(nexus_asm_stack_segment) /* Interrupt 12 */
#ifdef DIRECT_NEXUS_INTERRUPT
	cld
	# errorcode is on top of the stack 
	movw $12, 2(%esp)
	TRAPSAVE	
#endif
	call nexus_check_stack_segment
	TRAPRESTORE
	iret
	
ENTRY(nexus_asm_general_protection) /* Interrupt 13 */
#ifdef DIRECT_NEXUS_INTERRUPT
	cld
	# the error code is on the stack
	movw $13, 2(%esp)
	TRAPSAVE
#endif
	call nexus_check_gpf
	TRAPRESTORE
	iret
	
ENTRY(nexus_asm_page_fault) /* Interrupt 14 */
#ifdef DIRECT_NEXUS_INTERRUPT
	cld
	# the error code is on the stack
	movw $14, 2(%esp)
	TRAPSAVE
#endif
	call nexus_check_pfault
	TRAPRESTORE
	iret

ENTRY(nexus_asm_spurious_interrupt_bug) /* Interrupt 15 (XXX what is this?) */
#ifdef DIRECT_NEXUS_INTERRUPT
	cld
	subl $4, %esp # move the stack to make up for lack of error code
	movw $15, 2(%esp)
	TRAPSAVE	
#endif
	call nexus_check_spurious_interrupt_bug
	TRAPRESTORE
	iret

ENTRY(nexus_asm_coprocessor_error) /* Interrupt 16 */
#ifdef DIRECT_NEXUS_INTERRUPT
	cld
	subl $4, %esp # move the stack to make up for lack of error code
	movw $16, 2(%esp)
	TRAPSAVE	
#endif
	call nexus_check_coprocessor_error
	TRAPRESTORE
	iret

ENTRY(nexus_asm_alignment_check) /* Interrupt 17 */
#ifdef DIRECT_NEXUS_INTERRUPT
	cld
	# the error code (always 0) is on the stack
	movw $17, 2(%esp)
	TRAPSAVE
#endif
	call nexus_check_alignment_check
	TRAPRESTORE
	iret

ENTRY(nexus_asm_machine_check) /* Interrupt 18 (XXX when does this happen?) */
#ifdef DIRECT_NEXUS_INTERRUPT
	cld
	subl $4, %esp # move the stack to make up for lack of error code
	movw $18, 2(%esp)
	TRAPSAVE	
#endif
	call nexus_check_machine_check
	TRAPRESTORE
	iret

ENTRY(nexus_asm_simd_coprocessor_error) /* Interrupt 19 */
#ifdef DIRECT_NEXUS_INTERRUPT
	cld
	subl $4, %esp # move the stack to make up for lack of error code
	movw $19, 2(%esp)
	TRAPSAVE	
#endif
	call nexus_check_simd_coprocessor_error
	TRAPRESTORE
	iret	
	
ENTRY(system_call) /* Interrupt 0x82 */
	cld
	subl $4, %esp # there is no error code for system call, move stack ptr
	movw $0x82, 2(%esp)
	TRAPSAVE
	call  nexus_syscall
ENTRY(system_call_exit) /* Entry point for INT82 style exit from sysenter */
	TRAPRESTORE
	iret

ENTRY(xen_systrap80) /* Interrupt 0x80 */
	cld
	subl $4, %esp # there is no error code for system call, move stack ptr
#ifdef __NEXUSXEN__
	movw $0x80, 2(%esp)
	TRAPSAVE
	call  do_xen_systrap
	TRAPRESTORE
#endif
	iret

.align 16
ENTRY(sysenter_call)
	/* The first 2 instructions have strange stack semantics */

	/* SYSENTER does not know about threads, yet we have to keep
	separate kernel stacks for separate threads. We might take an
	interrupt here, so we need a CPL0 stack.

	It also enters with IF=0, so we will need to STI once it is safe

	This is what we do:

	1. Use SYSENTER MSR to set up ESP to point to a standard interrupt stack
	2. The 1st movl will fixup the ESP to the per-thread stack
	Thereafter, interrupts will use the thread-specific stack.
	3. STI
	*/

	# Unlike int82, we enter with interrupts disabled

	cld
	# Switch to thread-specific stack in nexustss.esp0 (sysenter starts with NULL as esp)
	# We need %ss override since DS is not set up until TRAPSAVE
	movl %ss:nexustss_data+4, %esp
	sti

	pushfl

	# End of stack twilight zone (e.g. we have a stack that is good for interrupts and for processing this syscall)

	TRAPSAVE_MORE(20)
	movw $0x82, 4+InterruptState__entry_vector(%esp)

	# %ds and %es are now OK

#define FLAG_LOC 68
	# Mix together Xen check 
	// if(nexusthread_current_ipd()->type == XEN)
	# and eflags copy
	# and IS INIT
	movl curt, %edx /* XEN */
	movl FLAG_LOC(%esp), %eax # move flags /* EFLAGS */
	movl UThread__ipd(%edx), %edx /* XEN */
	movl %eax, (FLAG_LOC - 8)(%esp) /* EFLAGS */

	// Set IS->CS:EIP
	// Set IS->SS:ESP
	movl 4+InterruptState__ebp(%esp), %eax /* IS INIT */
	movl $SYSEXIT_STUB_ADDR, 4+InterruptState__eip(%esp) /* IS INIT */
	movl $UNEXUSDS, 4+InterruptState__ss(%esp) /* IS INIT */
	movl %eax, 4+InterruptState__esp(%esp) /* IS INIT */

	cmpl $IPDType_XEN, IPD__type(%edx) /* XEN */
	movl $UNEXUSCS, 4+InterruptState__cs(%esp) /* IS INIT */
	// Save eflags in %esi, which is callee-saved
	movl 4+InterruptState__eflags(%esp), %esi /* EFLAG SAVE */
#ifdef __NEXUSXEN__
	je sysenter_call_xen // tail call /* XEN */
#endif
#if 0
  is->eip = SYSEXIT_STUB_ADDR;
  is->cs = UNEXUSCS;
  is->esp = is->ebp; // esp was saved in ebp
  is->ss = UNEXUSDS;
  int saved_eflags = is->eflags;
  nexus_syscall()
  if(likely(is->eip == SYSEXIT_STUB_ADDR && is->cs == UNEXUSCS && 
	    is->eflags == saved_eflags && is->ss == UNEXUSDS)) {
	// normal return
}
#endif
	call nexus_syscall

	// Check if we need to iret
	cmpl $SYSEXIT_STUB_ADDR, 4+InterruptState__eip(%esp)
	jne system_call_exit
	// do these in order that they appear in InterruptState
	cmpw $UNEXUSCS, 4+InterruptState__cs(%esp)
	jne system_call_exit
	cmpl %esi, 4+InterruptState__eflags(%esp)
	jne system_call_exit
	cmpw $UNEXUSDS, 4+InterruptState__ss(%esp)
	jne system_call_exit

	TRAPRESTORE
	movl $SYSEXIT_STUB_ADDR, %edx // EIP
	movl 12(%esp), %ecx // ESP
	sysexit

crash:	
	movl %eax, 0 # force page fault

ENTRY(nexus_interrupt)
	cld
	# the irq handler that called us left the irq number on top of the stack
	TRAPSAVE
	call  nexus_irq	
	TRAPRESTORE
	iret


/* These templates are copied to kshmem */
ENTRY(sysenter_stub_template)
	pushl %ebp
	movl %esp, %ebp
	sysenter
	# never reaches this
ENTRY(sysenter_stub_template_end)

ENTRY(sysexit_stub_template)
	popl %ebp
	ret
ENTRY(sysexit_stub_template_end)

ENTRY(int82_stub_template)
	int $0x82
	ret
ENTRY(int82_stub_template_end)

ENTRY(dump_regs)
	// XXX This trashes %ebp
	push %ebp
	movl %esp, %ebp
	// 6 words not saved by trapsave (starts at errorcode)
	pushl $0  // ss
	pushl %esp  // esp
	pushfl // eflags
	pushl %cs
	pushl 4(%ebp)
	pushl $0 // error code & entry_vectorc

	TRAPSAVE
	call dump_regs_is
	movl %ebp, %esp
	popl %ebp
	ret
