#include <linux/linkage.h>
.data
.text
.globl pf_handler

pf_handler:	
  /* save registers and give a pointer to InterruptState */
  subl $44, %esp
  /* Alan says these moves are faster than pushes */
  movw %gs, %ss:0(%esp)
  movw %fs, %ss:4(%esp)
  movw %es, %ss:8(%esp)
  movw %ds, %ss:12(%esp)
  movl %ebx, %ss:16(%esp)
  movl %ecx, %ss:20(%esp)
  movl %edx, %ss:24(%esp)
  movl %esi, %ss:28(%esp)
  movl %edi, %ss:32(%esp)
  movl %ebp, %ss:36(%esp)
  movl %eax, %ss:40(%esp)
  /* eflags, cs, eip, and errcode are on the stack from the kernel */
  pushl %esp  /* put a pointer to the saved state on the stack */

  call pagefault_handler

  movl 36(%esp), %edi	/* restore registers */
  movw 12(%esp), %es
  movl 20(%esp), %ebx
  movl 24(%esp), %ecx
  movl 28(%esp), %edx
  movl 32(%esp), %esi
  movl 40(%esp), %ebp
  movl 44(%esp), %eax
  movw 16(%esp), %ds
  movw 4(%esp), %gs
  movw 8(%esp), %fs

  addl $44, %esp /* pop saved registers */

  addl $8, %esp /* pop errorcode (always present for page fault) */
  iret		/* this will do the popflags and return */

