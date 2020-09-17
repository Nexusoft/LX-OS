/* boot.S - bootstrap a multiboot-compliant kernel */
/* Copyright (C) 1999, 2001, 2010  Free Software Foundation, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#define ASM_FILE            1
#include <multiboot.h>
#include <asm/segment.h>
#include <linux/linkage.h>
#include <asm/page.h>

/* The size of our stack (8KB).  */
#define STACK_SIZE          0x2000

/* Initialized screen information */
#define SCREEN_MODE         0     //text
#define SCREEN_WIDTH        1024
#define SCREEN_HEIGHT       768
#define SCREEN_DEPTH        24

/*
 * References to members of the boot_cpu_data structure.
 */

#define CPU_PARAMS      SYMBOL_NAME(boot_cpu_data)
#define X86             CPU_PARAMS+0
#define X86_VENDOR      CPU_PARAMS+1
#define X86_MODEL       CPU_PARAMS+2
#define X86_MASK        CPU_PARAMS+3
#define X86_HARD_MATH   CPU_PARAMS+6
#define X86_CPUID       CPU_PARAMS+8
#define X86_CAPABILITY  CPU_PARAMS+12
#define X86_VENDOR_ID   CPU_PARAMS+28

/* The flags for the Multiboot header.  */
#define MULTIBOOT_HEADER_FLAGS            MULTIBOOT_PAGE_ALIGN | MULTIBOOT_MEMORY_INFO | MULTIBOOT_VIDEO_MODE | MULTIBOOT_IMAGE_ADDR
    
    .text

ENTRY(start)
ENTRY(_start)
    jmp multiboot_entry

    /* Align 32 bits boundary.  */
    .align  4

    /* Multiboot header.  */
multiboot_header:
    /* magic */
    .long   MULTIBOOT_HEADER_MAGIC
    /* flags */
    .long   MULTIBOOT_HEADER_FLAGS
    /* checksum */
    .long   -(MULTIBOOT_HEADER_MAGIC + MULTIBOOT_HEADER_FLAGS)
    /* header_addr */
    .long   multiboot_header-__PAGE_OFFSET
    /* load_addr */
    .long   _start-__PAGE_OFFSET
    /* load_end_addr */
    .long   _edata-__PAGE_OFFSET
    /* bss_end_addr */
    .long   _end-__PAGE_OFFSET
    /* entry_addr */
    .long   multiboot_entry-__PAGE_OFFSET
    .long SCREEN_MODE
    .long SCREEN_WIDTH
    .long SCREEN_HEIGHT
    .long SCREEN_DEPTH

/* our real text start */
ENTRY(stext)
ENTRY(_stext)
multiboot_entry:
    /* Check multiboot magic */
    cmpl $MULTIBOOT_BOOTLOADER_MAGIC,%eax
    jne loop
    /* Save the multiboot struct pointer */
    movl %ebx,%esi

    pushl %esi
    call multiboot_initrd

    /* Initalize page tables */
    movl $pg0-__PAGE_OFFSET,%edi
    movl $007,%eax      /* "007" doesn't mean with right to kill, but
                           PRESENT+RW+USER */
2:  stosl
    add $0x1000,%eax
    cmp $empty_zero_page-__PAGE_OFFSET,%edi
    jne 2b

    /* Enable paging */
    movl $swapper_pg_dir-__PAGE_OFFSET,%eax
    movl %eax,%cr3           /* set the page table pointer.. */
    movl %cr0,%eax
    orl $0x80000000,%eax
    orl $0x50022,%eax        /* set AM, WP, NE and MP */
    movl %eax,%cr0           /* ..and set paging (PG) bit */
    movl $1f,%eax
    jmp *%eax                /* make sure %eip is reloated */ 
1:

    lgdt gdt_descr
    lidt idt_descr

    // Switch to the final DS, SS
    movl $(__KERNEL_DS),%eax
    movl %eax,%ds
    movl %eax,%es
    movl %eax,%fs
    movl %eax,%gs

    /* Initialize the stack pointer.  */
    movl    $(stack + STACK_SIZE), %esp

    .byte 0xea          # jmpi-opcode
code32:
    .long   NEXT        # will be set to 0x100000
                        # for big kernels
    .word   __KERNEL_CS
NEXT:
    /* cpuinfo section */
    movb $4,X86         # at least 486

    /* get vendor info */
    xorl %eax,%eax          # call CPUID with 0 -> return vendor ID
    cpuid
    movl %eax,X86_CPUID     # save CPUID level
    movl %ebx,X86_VENDOR_ID     # lo 4 chars
    movl %edx,X86_VENDOR_ID+4   # next 4 chars
    movl %ecx,X86_VENDOR_ID+8   # last 4 chars

    /* get processor info */
    movl $1,%eax        # Use the CPUID instruction to get CPU type
    cpuid
    movb %al,%cl        # save reg for future use
    andb $0x0f,%ah      # mask processor family
    movb %ah,X86
    andb $0xf0,%al      # mask model
    shrb $4,%al
    movb %al,X86_MODEL
    andb $0x0f,%cl      # mask mask revision
    movb %cl,X86_MASK
    movl %edx,X86_CAPABILITY

    /* Reset EFLAGS.  */
    pushl   $0
    popf

    /* Push the pointer to the Multiboot information structure.  */
    pushl   %esi

    /* Now the nexus entry function...  */
    call    SYMBOL_NAME(nexus_init)

    /* Halt.  */
    
loop: hlt
    jmp loop

    /* Our stack area.  */
    .comm   stack, STACK_SIZE

#define TSS_SIZE    (4)
#define IDT_ENTRIES (256)
#define NUM_RESERVED_GDT_ENTRY (8)
#define GDT_ENTRIES (FIRST_RESERVED_GDT_ENTRY + NUM_RESERVED_GDT_ENTRY + TSS_SIZE)

ENTRY(idt_descr)
    .word IDT_ENTRIES*8-1
    .long SYMBOL_NAME(idt_table)

ENTRY(gdt_descr)
    .word GDT_ENTRIES*8-1
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
    .fill 765,4,0
    .long 0x00102007
    .long 0x00103007
    .long 0x00104007
    .fill 253,4,0

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
ENTRY(nxclock_rate)
    .fill 1,8,0
ENTRY(ntp_offset)
    .fill 1021,4,0

.org 0x7000
.data

ALIGN

ENTRY(idt_table)
    .fill IDT_ENTRIES,8,0

// GDT is remapped into the Per-domain address space region. To make things easier, page-align the GDT
.align 0x1000
ENTRY(boot_gdt_table)
    .fill 7168,8,0
    .quad 0x0000000000000000    /* unused */
    .quad 0x00cf9a000000ffff    /* 0x0808 kernel 4GB code at 0x00000000 */
    .quad 0x00cf92000000ffff    /* 0x0810 kernel 4GB data at 0x00000000, +8 from CS for sysenter */
    .quad 0x00cbfa0000007fff    /* 0x082b Xen guest user CS (ring 3), 0 - 0xb7ffffff  + 16 from CS for sysenter */
    .quad 0x00cbf20000007fff    /* 0x0833 Xen guest user DS (ring 3), 0 - 0xb7ffffff + 24 from CS for sysenter */
    .quad 0x00cbba0000007fff    /* 0x0819 Xen guest kernel CS (ring 1), 0 - 0xb7ffffff */
    .quad 0x00cbb20000007fff    /* 0x0821 Xen guest kernel DS (ring 1), 0 - 0xb7ffffff */
    .quad 0x00cbf20000007fff
    .fill 4,8,0                 /* space for TSS's and LDT's */
