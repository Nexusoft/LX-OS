#include <nexus/syscall-asm.h>
.globl tls_setup_and_start
/* .globl fork_and_setup_tls */

/* Maximum of 2 arguments */
/* int tls_setup_and_start(void *target, __u32 arg0, __u32 arg1, void (*continuation)(void *rv from target)); */
	/* Adjust length of stack */
/* this is the first function getting called.  If you change it, change
 * the stop condition for dump_stack_trace and FIRST_COMMON_USER_FUNCTION */
tls_setup_and_start:
	lea -4(%esp), %eax
	pushl %eax
	call tls_computeLen
	addl $4, %esp
	/* new stack position now in %eax */

	/* Save %esp, then adjust by TLS length */
	/* Must happen before %ebp set */

	pushl %ebp
	movl %esp, %ebp

	/* Save space for call to tls_setup  */
	movl %eax, %esp
	/* Copy of stack, below TLS  */
	subl $TLS_RESERVE, %esp

	/* Copy target function address */
	movl 8(%ebp), %eax
	movl %eax, 4(%esp)
	/* Copy arguments to main */
	movl 12(%ebp), %eax
	movl %eax, 8(%esp)
	movl 16(%ebp), %eax
	movl %eax, 12(%esp)

	/* Copy continuation address */
	movl 20(%ebp), %eax
	movl %eax, 16(%esp)

	lea TLS_RESERVE(%esp), %eax
	movl %eax, 0(%esp) /* Base address of TLS */
	call tls_setup
	/* Pop arg */
	addl $4, %esp

	popl %eax
	/* %eax contains target, main args now back at top of stack */
	call *%eax
	addl $8, %esp

	/* Top of stack now contains continuation address */
	popl %edx /* use edx because it is caller-saved */
	test %edx,%edx
	jz no_cont
	pushl %eax /* Continuation expects return value as argument */
	call *%edx
no_cont:	
	
	/* Rebalance stack */
	movl %ebp, %esp
	popl %ebp
	ret

/* int start_main(int argc, char **argv); */
	// strictly speaking, this doesn't need to be written in assembly
start_main_asm:
	movl $main, %eax
	pushl %eax
	call tls_setup_and_start
	addl $4, %esp
	ret

.globl sysenter_stub
sysenter_stub =  SYSENTER_STUB_ADDR
