/*
 *  linux/arch/i386/kernel/head.S -- the 32-bit startup code.
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 *
 *  Enhanced CPU detection and feature setting code by Mike Jagdis
 *  and Martin Mares, November 1997.
 */

.text
#include <linux/config.h>
/* #include <linux/threads.h> */
#include <linux/linkage.h>
#include <asm/segment.h>
#include <asm/page.h>
#include <asm/pgtable.h>
#include <asm/desc.h>
#ifdef __NEXUSXEN__
#include <xen/arch-x86_32.h>
#endif

#define OLD_CL_MAGIC_ADDR	0x90020
#define OLD_CL_MAGIC		0xA33F
#define OLD_CL_BASE_ADDR	0x90000
#define OLD_CL_OFFSET		0x90022
#define NEW_CL_POINTER		0x228	/* Relative to real mode data */

/*
 * References to members of the boot_cpu_data structure.
 */

#define CPU_PARAMS	SYMBOL_NAME(boot_cpu_data)
#define X86		CPU_PARAMS+0
#define X86_VENDOR	CPU_PARAMS+1
#define X86_MODEL	CPU_PARAMS+2
#define X86_MASK	CPU_PARAMS+3
#define X86_HARD_MATH	CPU_PARAMS+6
#define X86_CPUID	CPU_PARAMS+8
#define X86_CAPABILITY	CPU_PARAMS+12
#define X86_VENDOR_ID	CPU_PARAMS+28

#define NR_CPUS 1

/*
 * swapper_pg_dir is the main page directory, address 0x00101000
 *
 * On entry, %esi points to the real-mode code as a 32-bit pointer.
 */
startup_32:
/*
 * Set segments to known values
 */
	cld
	movl $(__KERNEL_BOOT_DS),%eax
	movl %eax,%ds
	movl %eax,%es
	movl %eax,%fs
	movl %eax,%gs

/*
 * Initialize page tables
 */
	movl $pg0-__PAGE_OFFSET,%edi /* initialize page tables */
	movl $007,%eax		/* "007" doesn't mean with right to kill, but
				   PRESENT+RW+USER */
2:	stosl
	add $0x1000,%eax
	cmp $empty_zero_page-__PAGE_OFFSET,%edi
	jne 2b

/*
 * Enable paging
 */
3:
	movl $swapper_pg_dir-__PAGE_OFFSET,%eax
	movl %eax,%cr3		/* set the page table pointer.. */
	movl %cr0,%eax
	orl $0x80000000,%eax
	movl %eax,%cr0		/* ..and set paging (PG) bit */
	jmp 1f			/* flush the prefetch-queue */
221:
	movl $1f,%eax
	jmp *%eax		/* make sure eip is relocated */
1:

	/* Set up the stack pointer */
	lss stack_start_boot,%esp

/*
 * Clear BSS first so that there are no surprises...
 * No need to cld as DF is already clear from cld above...
 */
	xorl %eax,%eax
	movl $ SYMBOL_NAME(__bss_start),%edi
	movl $ SYMBOL_NAME(_end),%ecx
	subl %edi,%ecx
	rep
	stosb

/*
 * start system 32-bit setup. We need to re-do some of the things done
 * in 16-bit mode for the "real" operations.
 */
	/*DAN:	why do we need this?
	* All we need for the setup is to load a base value into the idtr
	* the entries are set up by me in init_idt
	  call setup_idt
	*/
/*
 * Initialize eflags.  Some BIOS's leave bits like NT set.  This would
 * confuse the debugger if this code is traced.
 * XXX - best to initialize before switching to protected mode.
 */
	pushl $0
	popfl
/*
 * Copy bootup parameters out of the way. First 2kB of
 * _empty_zero_page is for boot parameters, second 2kB
 * is for the command line.
 *
 * Note: %esi still has the pointer to the real-mode data.
 */
	movl $ SYMBOL_NAME(empty_zero_page),%edi
	movl $512,%ecx
	cld
	rep
	movsl
	xorl %eax,%eax
	movl $512,%ecx
	rep
	stosl
	movl SYMBOL_NAME(empty_zero_page)+NEW_CL_POINTER,%esi
	andl %esi,%esi
	jnz 2f			# New command line protocol
	cmpw $(OLD_CL_MAGIC),OLD_CL_MAGIC_ADDR
	jne 1f
	movzwl OLD_CL_OFFSET,%esi
	addl $(OLD_CL_BASE_ADDR),%esi
2:
	movl $ SYMBOL_NAME(empty_zero_page)+2048,%edi
	movl $512,%ecx
	rep
	movsl
1:

	/* cpuinfo section */
	movb $4,X86			# at least 486

	/* get vendor info */
	xorl %eax,%eax			# call CPUID with 0 -> return vendor ID
	cpuid
	movl %eax,X86_CPUID		# save CPUID level
	movl %ebx,X86_VENDOR_ID		# lo 4 chars
	movl %edx,X86_VENDOR_ID+4	# next 4 chars
	movl %ecx,X86_VENDOR_ID+8	# last 4 chars

	/* get processor info */
	movl $1,%eax		# Use the CPUID instruction to get CPU type
	cpuid
	movb %al,%cl		# save reg for future use
	andb $0x0f,%ah		# mask processor family
	movb %ah,X86
	andb $0xf0,%al		# mask model
	shrb $4,%al
	movb %al,X86_MODEL
	andb $0x0f,%cl		# mask mask revision
	movb %cl,X86_MASK
	movl %edx,X86_CAPABILITY

	/* set flags in cr0 */
	movl %cr0,%eax		# 486 or better
	andl $0x80000011,%eax	# Save PG,PE,ET
	orl $0x50022,%eax	# set AM, WP, NE and MP
	movl %eax,%cr0

	/* load GDT and IDT */
	lgdt gdt_descr
	lidt idt_descr

	// Switch to the final DS, SS
	movl $(__KERNEL_DS),%eax
	movl %eax,%ds
	movl %eax,%es
	movl %eax,%fs
	movl %eax,%gs

	lss stack_start,%esp

	.byte 0xea			# jmpi-opcode
code32:	.long	NEXT				# will be set to 0x100000
						# for big kernels
	.word	__KERNEL_CS
NEXT:

	// Clear the BOOT CS and DS
	pushf
	cli
	movl $(boot_gdt_table), %eax
	movl $0, 16(%eax)
	movl $0, 20(%eax)
	movl $0, 24(%eax)
	movl $0, 28(%eax)
	lgdt gdt_descr
	popf

	/* load the LDT with 0 */
	xorl %eax,%eax
	lldt %ax

	cld			# gcc2 wants the direction flag cleared at all times

/* KEVIN: keep gdb from trying to crawl upwards in the call stack */
	pushl $0

	call SYMBOL_NAME(start_kernel)
L6:
	jmp L6			# main should never return here, but
				# just in case, we know what happens.


/*
 *  setup_idt
 *
 *  sets up a idt with 256 entries pointing to
 *  ignore_int, interrupt gates. It doesn't actually load
 *  idt - that can be done only after paging has been enabled
 *  and the kernel moved to PAGE_OFFSET. Interrupts
 *  are enabled elsewhere, when we can be relatively
 *  sure everything is ok.
 */
setup_idt:
	lea ignore_int,%edx
	movl $(__KERNEL_CS << 16),%eax
	movw %dx,%ax		/* selector = 0x0010 = cs */
	movw $0x8E00,%dx	/* interrupt gate - dpl=0, present */

	lea SYMBOL_NAME(idt_table),%edi
	mov $256,%ecx
rp_sidt:
	movl %eax,(%edi)
	movl %edx,4(%edi)
	addl $8,%edi
	dec %ecx
	jne rp_sidt
	ret

ENTRY(stack_start_boot)
	.long SYMBOL_NAME(init_task_union)+8192
	.long __KERNEL_BOOT_DS
ENTRY(stack_start)
	.long SYMBOL_NAME(init_task_union)+8192
	.long __KERNEL_DS

/* This is the default interrupt "handler" :-) */
int_msg:
	.asciz "Unknown interrupt\n"
	ALIGN
ignore_int:
	cld
	pushl %eax
	pushl %ecx
	pushl %edx
	pushl %es
	pushl %ds
	movl $(__KERNEL_DS),%eax
	movl %eax,%ds
	movl %eax,%es
	pushl $int_msg
	call SYMBOL_NAME(printk)
	popl %eax
	popl %ds
	popl %es
	popl %edx
	popl %ecx
	popl %eax
	iret

/*
 * The interrupt descriptor table has room for 256 idt's,
 * the global descriptor table is dependent on the number
 * of tasks we can have..
 */
#define TSS_SIZE	4
#define IDT_ENTRIES	256
#define NUM_RESERVED_GDT_ENTRY (8)
#define GDT_ENTRIES	(FIRST_RESERVED_GDT_ENTRY + NUM_RESERVED_GDT_ENTRY + TSS_SIZE)


.globl SYMBOL_NAME(idt)
.globl SYMBOL_NAME(gdt)
.globl SYMBOL_NAME(gdt_descr)

	ALIGN
	.word 0
idt_descr:
	.word IDT_ENTRIES*8-1		# idt contains 256 entries
SYMBOL_NAME(idt):
	.long SYMBOL_NAME(idt_table)

	.word 0
SYMBOL_NAME(gdt_descr):
	.word GDT_ENTRIES*8-1
SYMBOL_NAME(gdt):
	.long SYMBOL_NAME(boot_gdt_table)

/*
 * This is initialized to create an identity-mapping at 0-12M (for bootup
 * purposes) and another mapping of the 0-12M area at virtual address
 * PAGE_OFFSET.
 */
.org 0x1000
ENTRY(swapper_pg_dir)
	.long 0x00102007
	.long 0x00103007
	.long 0x00104007
	.fill BOOT_USER_PGD_PTRS-3,4,0
	/* default: 766 entries */
	.long 0x00102007
	.long 0x00103007
	.long 0x00104007
	/* default: 254 entries */
	.fill BOOT_KERNEL_PGD_PTRS-3,4,0

/*
 * The page tables are initialized to only 8MB here - the final page
 * tables are set up later depending on memory size.
 */
.org 0x2000
ENTRY(pg0)

.org 0x3000
ENTRY(pg1)

.org 0x4000
ENTRY(pg2)

/*
 * empty_zero_page must immediately follow the page tables ! (The
 * initialization loop counts until empty_zero_page)
 */

.org 0x5000
ENTRY(empty_zero_page)

.org 0x6000
ENTRY(nexustime_page)
ENTRY(nexustime)
	.fill 1,4,0
ENTRY(ntp_offset)
	.fill 1023,4,0

.org 0x7000
/*
 * Real beginning of normal "text" segment
 */
ENTRY(stext)
ENTRY(_stext)

/*
 * This starts the data section. Note that the above is all
 * in the text section because it has alignment requirements
 * that we cannot fulfill any other way.
 */
.data

ALIGN

ENTRY(idt_table)
	.fill 256,8,0

/*
 * NOTE! Make sure the gdt descriptor in head.S matches this if you
 * change anything.
 */
// // 4GB Nexus user segment descriptors -- THEY CANNOT BE PRESENT FOR SAFE VIRTUALIZATION
//	.quad 0x00cffa000000ffff	/* 0x23 user   4GB code at 0x00000000 */
//	.quad 0x00cff2000000ffff	/* 0x2b user   4GB data at 0x00000000 */

// GDT is remapped into the Per-domain address space region. To make things easier, page-align the GDT
.align	0x1000
ENTRY(boot_gdt_table)
	.quad 0x0000000000000000	/* NULL descriptor */
	.quad 0x0000000000000000	/* not used */


#if 1
	// These are the values used during the bootstrap (needed to match the temporary GDT set up during 16=>32 bit transition)
	.quad 0x00cf9a000000ffff	/* 0x10 kernel 4GB code at 0x00000000 */
	.quad 0x00cf92000000ffff	/* 0x18 kernel 4GB data at 0x00000000 */
#else
	// These are the final values
	.quad 0x0000000000000000	/* Reserved for ABI */
	.quad 0x0000000000000000	/* Reserved for ABI */
#endif

#if 1
	.quad 0x0000000000000000	/* Reserved for ABI */
	.quad 0x0000000000000000	/* Reserved for ABI */
#else
	// these are the original linux values
	//.quad 0x00cffa000000ffff	/* 0x23 user   4GB code at 0x00000000 */
	//.quad 0x00cff2000000ffff	/* 0x2b user   4GB data at 0x00000000 */
#endif


	.quad 0x0000000000000000	/* not used */
	.quad 0x0000000000000000	/* not used */
	/*
	 * The APM segments have byte granularity and their bases
	 * and limits are set at run time.
	 */
	.quad 0x0040920000000000	/* 0x40 APM set up for bad BIOS's */
	.quad 0x00409a0000000000	/* 0x48 APM CS    code */
	.quad 0x00009a0000000000	/* 0x50 APM CS 16 code (16 bit) */
	.quad 0x0040920000000000	/* 0x58 APM DS    data */

	.fill FIRST_RESERVED_GDT_ENTRY - 12,8,0
	.quad 0x0000000000000000     /* unused */
	.quad 0x00cf9a000000ffff	/* 0x0808 kernel 4GB code at 0x00000000 */
	.quad 0x00cf92000000ffff	/* 0x0810 kernel 4GB data at 0x00000000, +8 from CS for sysenter */
	.quad 0x00cbfa0000007fff	/* 0x082b Xen guest user CS (ring 3), 0 - 0xb7ffffff  + 16 from CS for sysenter */
	.quad 0x00cbf20000007fff	/* 0x0833 Xen guest user DS (ring 3), 0 - 0xb7ffffff + 24 from CS for sysenter */
	.quad 0x00cbba0000007fff	/* 0x0819 Xen guest kernel CS (ring 1), 0 - 0xb7ffffff */
	.quad 0x00cbb20000007fff	/* 0x0821 Xen guest kernel DS (ring 1), 0 - 0xb7ffffff */


	/* 11/09 ASHIEH */
	/* The %gs register, for Linux-compatible TLS and TCB, needs
	to have full length. This breaks the segmentation protection
	for Xen guests.  It should really be moved to the ldt */

	.quad 0x00cbf20000007fff
	/* .quad 0x00c0f20000000000 */	/* 0x083b CPU 0 GS, uninitialized */

	.fill NR_CPUS*4,8,0		/* space for TSS's and LDT's */

////  xen user segs
//	.quad 0x00cafa000000ffff	/* 0x83 Xen guest user CS (ring 3), 0 - 0xafffffff */
//	.quad 0x00caf2000000ffff	/* 0x8b Xen guest user DS (ring 3), 0 - 0xafffffff */

