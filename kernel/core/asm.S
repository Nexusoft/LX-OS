.text
#include <linux/config.h>
#include <linux/threads.h>
#include <linux/linkage.h>
#include <asm/segment.h>
#include <nexus/segments.h>
#include <asm/page.h>
#include <asm/pgtable.h>
#include <asm/desc.h>

ENTRY(nexusthread_root)
      sti			;
		/* edi, ebx, ebp, esi are all callee-saved */
      pushl %edi		# push the arg to the main proc
      call *%ebx		# call main proc

      pushl %ebp		# push the arg to the clean-up proc
      call *%esi		# call the clean-up
	
	# Should never get here
	jmp nexusthread_rootpanic

#define OLDSPPTR 4			
#define NEWSPPTR 8

#define EBP 0
#define ESI 4
#define EDI 8
#define EBX 12
#define EIP 16
#define ESP 20
#define EFLAGS 24


ENTRY(nexuskthread_save)
	pushl 4(%esp)
	call nexuskthread_save_c0
	addl $4,%esp
	movl %eax, 4(%esp)
	jmp nexuskthread_savestate /* tailcall */

ENTRY(nexusuthread_save)
	pushl 4(%esp)
	call nexusuthread_save_c
	addl $4, %esp
	movl %eax, 4(%esp)
	jmp nexuskthread_save /* tailcall */
	
#if 0
ENTRY(nexuskthread_savestate)
      movl 4(%esp), %eax #; Get the pointer to the area where we are going to save the thread state

      // flags first to avoid changing the flags before saving
      pushfl
      popl EFLAGS(%eax)
      movl  0(%esp), %ecx #; Get the caller's PC
      movl  %ecx, EIP(%eax)     # ;  save the pc
      movl  %ebp, EBP(%eax)     #; Save the ebp, esi, edi, and ebx in area
      movl  %esi, ESI(%eax)     #;
      movl  %edi, EDI(%eax)     #;
      movl  %ebx, EBX(%eax)     #;
      movl  %esp, ESP(%eax)     #; save the old sp

      jmp nexuskthread_savestate_c1 # tail call
      // movl $1, %eax	 #;  return 1 on the first time through
      // ret

ENTRY(nexuskthread_restorestate_asm)
   /* accessible only from nexuskthread_restorestate */
pushfl
popl %ecx
movl %ecx, last_top_eflags
	
      movl 4(%esp), %eax #; Get the pointer to the area where we are going to restore the thread state from

      movl  EBP(%eax), %ebp     #; restore the ebp, esi, edi, and ebx from area
      movl  ESI(%eax), %esi     #;
      movl  EDI(%eax), %edi     #;
      movl  EBX(%eax), %ebx     #;
      movl  ESP(%eax), %esp     #; restore the old sp

	/* build IRET stack */
      addl $4, 0(%esp) #	;  wipe out old return PC
      movl EFLAGS(%eax), %ecx
movl %ecx, last_eflags /* xxx record info for debugging */
      pushl %ecx
      pushl $__KERNEL_CS
      movl  EIP(%eax), %ecx
      pushl %ecx

movl %ecx, last_iret /* xxx record info for debugging */
      movl $0, %eax	#;  return 0 on the second time through
      iret
#endif

ENTRY(nexuskthread_savestate)
      movl 4(%esp), %eax #; Get the pointer to the area where we are going to save the thread state

      movl  0(%esp), %ecx #; Get the caller's PC
      movl  %ecx, EIP(%eax)     # ;  save the pc
      movl  %ebp, EBP(%eax)     #; Save the ebp, esi, edi, and ebx in area
      movl  %esi, ESI(%eax)     #;
      movl  %edi, EDI(%eax)     #;
      movl  %ebx, EBX(%eax)     #;
      movl  %esp, ESP(%eax)     #; save the old sp

      jmp nexuskthread_savestate_c1 # tail call
      // movl $1, %eax	 #;  return 1 on the first time through
      // ret

ENTRY(nexuskthread_restorestate_asm)
   /* accessible only from nexuskthread_restorestate */
      movl 4(%esp), %eax #; Get the pointer to the area where we are going to restore the thread state from

      movl  EBP(%eax), %ebp     #; restore the ebp, esi, edi, and ebx from area
      movl  ESI(%eax), %esi     #;
      movl  EDI(%eax), %edi     #;
      movl  EBX(%eax), %ebx     #;
      movl  ESP(%eax), %esp     #; restore the old sp
      movl  EIP(%eax), %ecx     #; get the pc
      movl  %ecx, 0(%esp)       #; change PC

      movl $0, %eax	#;  return 0 on the second time through
      ret
	
	
ENTRY(fxsave_registers)
	movl 4(%esp), %eax	#move address for saving into eax
	fxsave 0(%eax)		#save to address
	ret
	
ENTRY(fxrstor_registers)
	movl 4(%esp), %eax	#move address for restoring into eax
	fxrstor 0(%eax)		#restore from address
	ret

ENTRY(finit_state)
	finit # initialize floating point unit
	ret
	
#ENTRY(saveustate)
#	movl $1, %eax
#	ret

ENTRY(fake_up_syscall)
	sti
	movl 4(%esp), %eax
	subl 8(%esp), %esp /* push the size of the is */	
	pushl %esp
	pushl %eax

	call fill_is
	addl $4, %esp
	call nexus_syscall
	jmp system_call_exit

	
ENTRY(check_intr)
	pushfl		#put the EFLAGS register on stack so we can look at it
	popl %eax	#get the EFLAGS off stack
	andl $512, %eax		#and to get the IF from EFLAGS (9th bit)
	shr $9, %eax		#shift it right (now 1==IF_on 0==IF_off)
				#IF_on means interrupts enabled
	ret

ENTRY(read_gdtr)
	subl $8, %esp
	sgdtl 0(%esp)
	movl 2(%esp), %eax
	addl $8, %esp
	ret

ENTRY(read_gdtr_limit)
	subl $8, %esp
	sgdtl 0(%esp)
	movl 0(%esp), %eax
	andl $0xffff, %eax
	addl $8, %esp
	ret

ENTRY(read_tr)
	str %eax
	ret

ENTRY(write_tr)
	ltr 4(%esp)
	ret

ENTRY(read_idtr)
	subl $8, %esp
	sidtl 0(%esp)
	movl 2(%esp), %eax
	addl $8, %esp
	ret

ENTRY(read_idtr_limit)
	subl $8, %esp
	sidtl 0(%esp)
	movl 0(%esp), %eax
	andl $0xffff, %eax
	addl $8, %esp
	ret

ENTRY(put_idt)
	subl $8, %esp
	sidtl 0(%esp)		#put idtr on stack
	jmp put_gdt_idt

ENTRY(put_gdt)
	subl $8, %esp
	movl gdtr_base, %eax
	movl %eax, 2(%esp)
	jmp put_gdt_idt

put_gdt_idt:	
	movl 2(%esp), %eax	#get base in %eax
	addl $8, %esp
	movl 4(%esp), %ecx	#offset in idt
	addl %ecx, %eax		#add offset??

	movl 8(%esp), %ecx	#get lo's
	movl %ecx, 0(%eax)	#enter lo's

	movl 12(%esp), %ecx	#get hi's
	movl %ecx, 4(%eax)	#enter hi's
	ret
	
ENTRY(enable_intr)
	sti
	ret
			
ENTRY(swapb)
	movl 4(%esp), %ecx
	movl 8(%esp), %eax
	A_LOCK xchgb %al, 0(%ecx)
	movzbl %al, %eax
	ret	

ENTRY(atomic_test_and_set)
	movl 4(%esp), %ecx
	movl $1, %eax
	A_LOCK xchgl %eax, 0(%ecx)
	ret	

ENTRY(atomic_clear)
	movl 4(%esp), %ecx
	movl  $0, 0(%ecx)
	ret
		
ENTRY(compare_and_swap)
	movl 4(%esp), %edx
	movl 8(%esp), %eax
	movl 12(%esp), %ecx
	A_LOCK cmpxchgl %ecx, 0(%edx)
	ret	
			

ENTRY(nexushalt)
	hlt
	ret

ENTRY(flushTLB)
	movl %cr3, %eax		#; The TLB is automatically flushed when the cr3 
	movl %eax, %cr3		#; (pdbr) is written to unless the PGE bit is set
	ret			#; on the cr4.  In that case need flushglobalTLB()
	
ENTRY(readcr0)
	movl %cr0, %eax
	ret

ENTRY(readcr2)
	movl %cr2, %eax
	ret

ENTRY(readcr3)
	movl %cr3, %eax
	ret

ENTRY(readcr4)
	movl %cr4, %eax
	ret

ENTRY(writecr0)
	movl 4(%esp), %eax
	movl %eax, %cr0
	ret

ENTRY(writecr3)
	movl 4(%esp), %eax
	movl %eax, %cr3
	ret
	
ENTRY(writecr4)
	movl 4(%esp), %eax
	movl %eax, %cr4
	ret
	
ENTRY(loadmxcsr)	
	movl 4(%esp), %eax # Get the pointer to the area where we are
			 # going to restore the thread state from
	ldmxcsr 0(%eax)
	ret
