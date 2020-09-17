/******************************************************************************
 * x86_emulate.h
 * 
 * Generic x86 (32-bit and 64-bit) instruction decoder and emulator.
 * 
 * Copyright (c) 2005 Keir Fraser
 */

#ifndef __X86_EMULATE_H__
#define __X86_EMULATE_H__

#ifndef __NEXUSKERNEL__
#include <inttypes.h>
#include <stdint.h>
#endif

struct x86_emulate_ctxt;

/*
 * Comprehensive enumeration of x86 segment registers. Note that the system
 * registers (TR, LDTR, GDTR, IDTR) are never referenced by the emulator.
 */
enum x86_segment {
    /* General purpose. */
    x86_seg_cs,
    x86_seg_ss,
    x86_seg_ds,
    x86_seg_es,
    x86_seg_fs,
    x86_seg_gs,
    /* System. */
    x86_seg_tr,
    x86_seg_ldtr,
    x86_seg_gdtr,
    x86_seg_idtr
};

/*
 * These operations represent the instruction emulator's interface to memory.
 * 
 * NOTES:
 *  1. If the access fails (cannot emulate, or a standard access faults) then
 *     it is up to the memop to propagate the fault to the guest VM via
 *     some out-of-band mechanism, unknown to the emulator. The memop signals
 *     failure by returning X86EMUL_PROPAGATE_FAULT to the emulator, which will
 *     then immediately bail.
 *  2. Valid access sizes are 1, 2, 4 and 8 bytes. On x86/32 systems only
 *     cmpxchg8b_emulated need support 8-byte accesses.
 *  3. The emulator cannot handle 64-bit mode emulation on an x86/32 system.
 */
/* Access completed successfully: continue emulation as normal. */
#define X86EMUL_CONTINUE        0
/* Access is unhandleable: bail from emulation and return error to caller. */
#define X86EMUL_UNHANDLEABLE    1
/* Terminate emulation but return success to the caller. */
#define X86EMUL_PROPAGATE_FAULT 2 /* propagate a generated fault to guest */
#define X86EMUL_RETRY_INSTR     2 /* retry the instruction for some reason */
#define X86EMUL_CMPXCHG_FAILED  2 /* cmpxchg did not see expected value */
struct x86_emulate_ops
{
    /*
     * All functions:
     *  @seg:   [IN ] Segment being dereferenced (specified as x86_seg_??).
     *  @offset:[IN ] Offset within segment.
     *  @ctxt:  [IN ] Emulation context info as passed to the emulator.
     */

    /*
     * read: Emulate a memory read.
     *  @val:   [OUT] Value read from memory, zero-extended to 'ulong'.
     *  @bytes: [IN ] Number of bytes to read from memory.
     */
    int (*read)(
        enum x86_segment seg,
        unsigned long offset,
        unsigned long *val,
        unsigned int bytes,
        struct x86_emulate_ctxt *ctxt);

    /*
     * insn_fetch: Emulate fetch from instruction byte stream.
     *  Parameters are same as for 'read'. @seg is always x86_seg_cs.
     */
    int (*insn_fetch)(
        enum x86_segment seg,
        unsigned long offset,
        unsigned long *val,
        unsigned int bytes,
        struct x86_emulate_ctxt *ctxt);

    /*
     * write: Emulate a memory write.
     *  @val:   [IN ] Value to write to memory (low-order bytes used as req'd).
     *  @bytes: [IN ] Number of bytes to write to memory.
     */
    int (*write)(
        enum x86_segment seg,
        unsigned long offset,
        unsigned long val,
        unsigned int bytes,
        struct x86_emulate_ctxt *ctxt);

    /*
     * cmpxchg: Emulate an atomic (LOCKed) CMPXCHG operation.
     *  @old:   [IN ] Value expected to be current at @addr.
     *  @new:   [IN ] Value to write to @addr.
     *  @bytes: [IN ] Number of bytes to access using CMPXCHG.
     */
    int (*cmpxchg)(
        enum x86_segment seg,
        unsigned long offset,
        unsigned long old,
        unsigned long new,
        unsigned int bytes,
        struct x86_emulate_ctxt *ctxt);

    /*
     * cmpxchg8b: Emulate an atomic (LOCKed) CMPXCHG8B operation.
     *  @old:   [IN ] Value expected to be current at @addr.
     *  @new:   [IN ] Value to write to @addr.
     * NOTES:
     *  1. This function is only ever called when emulating a real CMPXCHG8B.
     *  2. This function is *never* called on x86/64 systems.
     *  2. Not defining this function (i.e., specifying NULL) is equivalent
     *     to defining a function that always returns X86EMUL_UNHANDLEABLE.
     */
    int (*cmpxchg8b)(
        enum x86_segment seg,
        unsigned long offset,
        unsigned long old_lo,
        unsigned long old_hi,
        unsigned long new_lo,
        unsigned long new_hi,
        struct x86_emulate_ctxt *ctxt);
};

struct cpu_user_regs_disas {
    uint16_t gs, _pad5;
    uint16_t fs, _pad4;
    uint16_t es, _pad2;
    uint16_t ds, _pad3;

    uint32_t ebx;
    uint32_t ecx;
    uint32_t edx;
    uint32_t esi;
    uint32_t edi;
    uint32_t ebp;
    uint32_t eax;
    uint16_t error_code;    /* private */
    uint16_t entry_vector;  /* private */
    uint32_t eip;
    uint16_t cs;
    uint8_t  saved_upcall_mask;
    uint8_t  _pad0;
    uint32_t eflags;        /* eflags.IF == !saved_upcall_mask */
    uint32_t esp;
    uint16_t ss, _pad1;
};


struct x86_emulate_ctxt
{
    /* Register state before/after emulation. */
    struct cpu_user_regs_disas   *regs;

    /* Emulated execution mode, represented by an X86EMUL_MODE value. */
    int                     mode;
};

/* Execution mode, passed to the emulator. */
#define X86EMUL_MODE_REAL     0 /* Real mode.             */
#define X86EMUL_MODE_PROT16   2 /* 16-bit protected mode. */
#define X86EMUL_MODE_PROT32   4 /* 32-bit protected mode. */
#define X86EMUL_MODE_PROT64   8 /* 64-bit (long) mode.    */

/* Host execution mode. */
#if defined(__i386__)
#define X86EMUL_MODE_HOST X86EMUL_MODE_PROT32
#elif defined(__x86_64__)
#define X86EMUL_MODE_HOST X86EMUL_MODE_PROT64
#endif

/*
 * x86_emulate_memop: Emulate an instruction that faulted attempting to
 *                    read/write a 'special' memory area.
 * Returns -1 on failure, 0 on success.
 */
int
x86_emulate_memop(
    struct x86_emulate_ctxt *ctxt,
    struct x86_emulate_ops  *ops);

/*
 * Given the 'reg' portion of a ModRM byte, and a register block, return a
 * pointer into the block that addresses the relevant register.
 * @highbyte_regs specifies whether to decode AH,CH,DH,BH.
 */
void *
decode_register(
    uint8_t modrm_reg, struct cpu_user_regs_disas *regs, int highbyte_regs);




int x86_emulate_insn_fetch_default(enum x86_segment seg,
				   unsigned long offset,
				   unsigned long *val,
				   unsigned int bytes,
				   struct x86_emulate_ctxt *ctxt);
int x86_emulate_cmpxchg_default(enum x86_segment seg,
				unsigned long offset,
				unsigned long old,
				unsigned long new,
				unsigned int bytes,
				struct x86_emulate_ctxt *ctxt);
int x86_emulate_cmpxchg8b_default(enum x86_segment seg,
				  unsigned long offset,
				  unsigned long old_lo,
				  unsigned long old_hi,
				  unsigned long new_lo,
				  unsigned long new_hi,
				  struct x86_emulate_ctxt *ctxt);
int x86_emulate_write_default(enum x86_segment seg,
			      unsigned long vaddr,
			      unsigned long val,
			      unsigned int bytes,
			      struct x86_emulate_ctxt *ctxt);
int x86_emulate_read_default(enum x86_segment seg,
			     unsigned long vaddr,
			     unsigned long *val,
			     unsigned int bytes,
			     struct x86_emulate_ctxt *ctxt) ;


#ifndef __NEXUSKERNEL__
// This is called before doing any disassembly. Currently used by Xen
// to set up TLS register
void register_pf_handler_enter(void (*func)(struct x86_emulate_ctxt *ctxt));

/* A user app can install a hook for the memory functions */
void register_pf_handler_read(int (*func)(enum x86_segment seg,
					  unsigned long vaddr,
					  unsigned long *val,
					  unsigned int bytes,
					  struct x86_emulate_ctxt *ctxt));

void register_pf_handler_write(int (*func)(enum x86_segment seg,
					   unsigned long vaddr,
					   unsigned long val,
					   unsigned int bytes,
					   struct x86_emulate_ctxt *ctxt));

void register_pf_handler_cmpxchg(int (*func)(enum x86_segment seg,
					     unsigned long offset,
					     unsigned long old,
					     unsigned long new,
					     unsigned int bytes,
					     struct x86_emulate_ctxt *ctxt));


#endif



/* These functions are careful about opsize while performing reads and
   writes.  They should be called from handlers when the fixed up
   address is already calculated. */
int x86_emulate_do_write(unsigned long addr, unsigned long val, int bytes);
int x86_emulate_do_read(unsigned long addr, unsigned long *val, int bytes);

#ifdef __NEXUSKERNEL__
/* These two functions should only be called from the kernel */
int x86_emulate_do_out(unsigned long addr, unsigned long val, int bytes);
int x86_emulate_do_in(unsigned long addr, unsigned long *val, int bytes);
#endif

#endif /* __X86_EMULATE_H__ */
