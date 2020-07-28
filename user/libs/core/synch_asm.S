#include <linux/linkage.h>
	.text
	.globl atomic_test_and_set
	.globl atomic_clear
	.globl atomic_compare_and_swap
	.globl atomic_swap
	.globl getesp
	.globl getebp	
	
atomic_test_and_set:
	movl 4(%esp), %ecx
	movl $1, %eax
	lock xchgl %eax, 0(%ecx)
	ret

atomic_clear:	
	movl 4(%esp), %ecx
	movl $0, 0(%ecx)
		
atomic_compare_and_swap:	
	movl 4(%esp), %edx
	movl 8(%esp), %eax
	movl 12(%esp), %ecx
	lock cmpxchgl %ecx, 0(%edx)
	ret
	
atomic_swap:	
	movl 4(%esp), %ecx
	movl 8(%esp), %eax
	lock xchgl %eax, 0(%ecx)
	
getesp:
	movl %esp, %eax
	ret

