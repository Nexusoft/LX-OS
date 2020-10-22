
/*
 * Automatically generated system call stubs.
 */

#ifndef __LIBSEL4_SEL4_CLIENT_H
#define __LIBSEL4_SEL4_CLIENT_H

#include <stddef.h>
#include <stdbool.h>
#include "sel4/types.h"
#include "sel4/invocation.h"
#include "sel4/arch/functions.h"
#include "sel4/arch/syscalls.h"


/*
 * The following code generates a compile-time error if the system call
 * stub generator has an incorrect understanding of how large a type is.
 *
 * If you receive a compile-time error here, you will need to adjust
 * the type information in the stub generator.
 */
#define assert_size_correct(type, expected_bytes) \
        typedef unsigned long __type_##type##_size_incorrect[ \
                (sizeof(type) == expected_bytes) ? 1 : -1]

assert_size_correct(uint8_t, 1);
assert_size_correct(uint16_t, 2);
assert_size_correct(uint32_t, 4);
assert_size_correct(uint64_t, 8);
assert_size_correct(int, 4);
assert_size_correct(bool, 1);
assert_size_correct(seL4_Word, 4);
assert_size_correct(seL4_CapRights, 4);
assert_size_correct(seL4_CapData_t, 4);
assert_size_correct(seL4_CPtr, 4);
assert_size_correct(seL4_CNode, 4);
assert_size_correct(seL4_IRQHandler, 4);
assert_size_correct(seL4_IRQControl, 4);
assert_size_correct(seL4_TCB, 4);
assert_size_correct(seL4_Untyped, 4);
assert_size_correct(seL4_ARM_VMAttributes, 4);
assert_size_correct(seL4_ARM_Page, 4);
assert_size_correct(seL4_ARM_PageTable, 4);
assert_size_correct(seL4_ARM_PageDirectory, 4);
assert_size_correct(seL4_UserContext, 68);

/*
 * Return types for generated methods.
 */
/*
 * Generated stubs.
 */
static inline int
seL4_ARM_PageTable_Map(seL4_ARM_PageTable service, seL4_ARM_PageDirectory pd, seL4_Word vaddr, seL4_ARM_VMAttributes attr)
{
	seL4_MessageInfo_t tag = seL4_MessageInfo_new(ARMPageTableMap, 0, 1, 2);
	seL4_MessageInfo_t output_tag;
	seL4_Word mr0;
	seL4_Word mr1;

	/* Setup input capabilities. */
	seL4_SetCap(0, pd);

	/* Marshal input parameters. */
	mr0 = vaddr;
	mr1 = attr;

	/* Perform the call, passing in-register arguments directly. */
	output_tag = __seL4_CallWithMRs(service, tag,
		&mr0, &mr1, NULL, NULL);

	return seL4_MessageInfo_get_label(output_tag);
}

static inline int
seL4_ARM_PageTable_Unmap(seL4_ARM_PageTable service)
{
	seL4_MessageInfo_t tag = seL4_MessageInfo_new(ARMPageTableUnmap, 0, 0, 0);
	seL4_MessageInfo_t output_tag;

	/* Perform the call, passing in-register arguments directly. */
	output_tag = __seL4_CallWithMRs(service, tag,
		NULL, NULL, NULL, NULL);

	return seL4_MessageInfo_get_label(output_tag);
}

static inline int
seL4_ARM_Page_Map(seL4_ARM_Page service, seL4_ARM_PageDirectory pd, seL4_Word vaddr, seL4_CapRights rights, seL4_ARM_VMAttributes attr)
{
	seL4_MessageInfo_t tag = seL4_MessageInfo_new(ARMPageMap, 0, 1, 3);
	seL4_MessageInfo_t output_tag;
	seL4_Word mr0;
	seL4_Word mr1;
	seL4_Word mr2;

	/* Setup input capabilities. */
	seL4_SetCap(0, pd);

	/* Marshal input parameters. */
	mr0 = vaddr;
	mr1 = rights;
	mr2 = attr;

	/* Perform the call, passing in-register arguments directly. */
	output_tag = __seL4_CallWithMRs(service, tag,
		&mr0, &mr1, &mr2, NULL);

	return seL4_MessageInfo_get_label(output_tag);
}

static inline int
seL4_ARM_Page_Remap(seL4_ARM_Page service, seL4_ARM_PageDirectory pd, seL4_CapRights rights, seL4_ARM_VMAttributes attr)
{
	seL4_MessageInfo_t tag = seL4_MessageInfo_new(ARMPageRemap, 0, 1, 2);
	seL4_MessageInfo_t output_tag;
	seL4_Word mr0;
	seL4_Word mr1;

	/* Setup input capabilities. */
	seL4_SetCap(0, pd);

	/* Marshal input parameters. */
	mr0 = rights;
	mr1 = attr;

	/* Perform the call, passing in-register arguments directly. */
	output_tag = __seL4_CallWithMRs(service, tag,
		&mr0, &mr1, NULL, NULL);

	return seL4_MessageInfo_get_label(output_tag);
}

static inline int
seL4_ARM_Page_Unmap(seL4_ARM_Page service)
{
	seL4_MessageInfo_t tag = seL4_MessageInfo_new(ARMPageUnmap, 0, 0, 0);
	seL4_MessageInfo_t output_tag;

	/* Perform the call, passing in-register arguments directly. */
	output_tag = __seL4_CallWithMRs(service, tag,
		NULL, NULL, NULL, NULL);

	return seL4_MessageInfo_get_label(output_tag);
}

static inline int
seL4_ARM_Page_FlushCaches(seL4_ARM_Page service)
{
	seL4_MessageInfo_t tag = seL4_MessageInfo_new(ARMPageFlushCaches, 0, 0, 0);
	seL4_MessageInfo_t output_tag;

	/* Perform the call, passing in-register arguments directly. */
	output_tag = __seL4_CallWithMRs(service, tag,
		NULL, NULL, NULL, NULL);

	return seL4_MessageInfo_get_label(output_tag);
}

static inline int
seL4_Untyped_RetypeAtOffset(seL4_Untyped service, int type, int offset, int size_bits, seL4_CNode root, int node_index, int node_depth, int node_offset, int num_objects)
{
	seL4_MessageInfo_t tag = seL4_MessageInfo_new(UntypedRetype, 0, 1, 7);
	seL4_MessageInfo_t output_tag;
	seL4_Word mr0;
	seL4_Word mr1;
	seL4_Word mr2;
	seL4_Word mr3;

	/* Setup input capabilities. */
	seL4_SetCap(0, root);

	/* Marshal input parameters. */
	mr0 = type;
	mr1 = offset;
	mr2 = size_bits;
	mr3 = node_index;
	seL4_SetMR(4, node_depth);
	seL4_SetMR(5, node_offset);
	seL4_SetMR(6, num_objects);

	/* Perform the call, passing in-register arguments directly. */
	output_tag = __seL4_CallWithMRs(service, tag,
		&mr0, &mr1, &mr2, &mr3);

	return seL4_MessageInfo_get_label(output_tag);
}

static inline int
seL4_TCB_ReadRegisters(seL4_TCB service, bool suspend_source, uint8_t arch_flags, seL4_Word count, seL4_UserContext *regs)
{
	seL4_MessageInfo_t tag = seL4_MessageInfo_new(TCBReadRegisters, 0, 0, 2);
	seL4_MessageInfo_t output_tag;
	seL4_Word mr0;
	seL4_Word mr1;
	seL4_Word mr2;
	seL4_Word mr3;

	/* Marshal input parameters. */
	mr0 = (suspend_source & 0x1) | ((arch_flags & 0xff) << 8);
	mr1 = count;

	/* Perform the call, passing in-register arguments directly. */
	output_tag = __seL4_CallWithMRs(service, tag,
		&mr0, &mr1, &mr2, &mr3);

	/* Unmarshal result. */
	regs->pc = mr0;
	regs->sp = mr1;
	regs->cpsr = mr2;
	regs->r0 = mr3;
	regs->r1 = seL4_GetMR(4);
	regs->r8 = seL4_GetMR(5);
	regs->r9 = seL4_GetMR(6);
	regs->r10 = seL4_GetMR(7);
	regs->r11 = seL4_GetMR(8);
	regs->r12 = seL4_GetMR(9);
	regs->r2 = seL4_GetMR(10);
	regs->r3 = seL4_GetMR(11);
	regs->r4 = seL4_GetMR(12);
	regs->r5 = seL4_GetMR(13);
	regs->r6 = seL4_GetMR(14);
	regs->r7 = seL4_GetMR(15);
	regs->r14 = seL4_GetMR(16);

	return seL4_MessageInfo_get_label(output_tag);
}

static inline int
seL4_TCB_WriteRegisters(seL4_TCB service, bool resume_target, uint8_t arch_flags, seL4_Word count, seL4_UserContext *regs)
{
	seL4_MessageInfo_t tag = seL4_MessageInfo_new(TCBWriteRegisters, 0, 0, 19);
	seL4_MessageInfo_t output_tag;
	seL4_Word mr0;
	seL4_Word mr1;
	seL4_Word mr2;
	seL4_Word mr3;

	/* Marshal input parameters. */
	mr0 = (resume_target & 0x1) | ((arch_flags & 0xff) << 8);
	mr1 = count;
	mr2 = regs->pc;
	mr3 = regs->sp;
	seL4_SetMR(4, regs->cpsr);
	seL4_SetMR(5, regs->r0);
	seL4_SetMR(6, regs->r1);
	seL4_SetMR(7, regs->r8);
	seL4_SetMR(8, regs->r9);
	seL4_SetMR(9, regs->r10);
	seL4_SetMR(10, regs->r11);
	seL4_SetMR(11, regs->r12);
	seL4_SetMR(12, regs->r2);
	seL4_SetMR(13, regs->r3);
	seL4_SetMR(14, regs->r4);
	seL4_SetMR(15, regs->r5);
	seL4_SetMR(16, regs->r6);
	seL4_SetMR(17, regs->r7);
	seL4_SetMR(18, regs->r14);

	/* Perform the call, passing in-register arguments directly. */
	output_tag = __seL4_CallWithMRs(service, tag,
		&mr0, &mr1, &mr2, &mr3);

	return seL4_MessageInfo_get_label(output_tag);
}

static inline int
seL4_TCB_CopyRegisters(seL4_TCB service, seL4_TCB source, bool suspend_source, bool resume_target, bool transfer_frame, bool transfer_integer, uint8_t arch_flags)
{
	seL4_MessageInfo_t tag = seL4_MessageInfo_new(TCBCopyRegisters, 0, 1, 1);
	seL4_MessageInfo_t output_tag;
	seL4_Word mr0;

	/* Setup input capabilities. */
	seL4_SetCap(0, source);

	/* Marshal input parameters. */
	mr0 = (suspend_source & 0x1) | ((resume_target & 0x1) << 1) | ((transfer_frame & 0x1) << 2) | ((transfer_integer & 0x1) << 3) | ((arch_flags & 0xff) << 8);

	/* Perform the call, passing in-register arguments directly. */
	output_tag = __seL4_CallWithMRs(service, tag,
		&mr0, NULL, NULL, NULL);

	return seL4_MessageInfo_get_label(output_tag);
}

static inline int
seL4_TCB_Configure(seL4_TCB service, seL4_Word fault_ep, uint8_t priority, seL4_CNode cspace_root, seL4_CapData_t cspace_root_data, seL4_CNode vspace_root, seL4_CapData_t vspace_root_data, seL4_Word buffer, seL4_CPtr bufferFrame)
{
	seL4_MessageInfo_t tag = seL4_MessageInfo_new(TCBConfigure, 0, 3, 5);
	seL4_MessageInfo_t output_tag;
	seL4_Word mr0;
	seL4_Word mr1;
	seL4_Word mr2;
	seL4_Word mr3;

	/* Setup input capabilities. */
	seL4_SetCap(0, cspace_root);
	seL4_SetCap(1, vspace_root);
	seL4_SetCap(2, bufferFrame);

	/* Marshal input parameters. */
	mr0 = fault_ep;
	mr1 = (priority & 0xff);
	mr2 = cspace_root_data.words[0];
	mr3 = vspace_root_data.words[0];
	seL4_SetMR(4, buffer);

	/* Perform the call, passing in-register arguments directly. */
	output_tag = __seL4_CallWithMRs(service, tag,
		&mr0, &mr1, &mr2, &mr3);

	return seL4_MessageInfo_get_label(output_tag);
}

static inline int
seL4_TCB_SetPriority(seL4_TCB service, uint8_t priority)
{
	seL4_MessageInfo_t tag = seL4_MessageInfo_new(TCBSetPriority, 0, 0, 1);
	seL4_MessageInfo_t output_tag;
	seL4_Word mr0;

	/* Marshal input parameters. */
	mr0 = (priority & 0xff);

	/* Perform the call, passing in-register arguments directly. */
	output_tag = __seL4_CallWithMRs(service, tag,
		&mr0, NULL, NULL, NULL);

	return seL4_MessageInfo_get_label(output_tag);
}

static inline int
seL4_TCB_SetIPCBuffer(seL4_TCB service, seL4_Word buffer, seL4_CPtr bufferFrame)
{
	seL4_MessageInfo_t tag = seL4_MessageInfo_new(TCBSetIPCBuffer, 0, 1, 1);
	seL4_MessageInfo_t output_tag;
	seL4_Word mr0;

	/* Setup input capabilities. */
	seL4_SetCap(0, bufferFrame);

	/* Marshal input parameters. */
	mr0 = buffer;

	/* Perform the call, passing in-register arguments directly. */
	output_tag = __seL4_CallWithMRs(service, tag,
		&mr0, NULL, NULL, NULL);

	return seL4_MessageInfo_get_label(output_tag);
}

static inline int
seL4_TCB_SetSpace(seL4_TCB service, seL4_Word fault_ep, seL4_CNode cspace_root, seL4_CapData_t cspace_root_data, seL4_CNode vspace_root, seL4_CapData_t vspace_root_data)
{
	seL4_MessageInfo_t tag = seL4_MessageInfo_new(TCBSetSpace, 0, 2, 3);
	seL4_MessageInfo_t output_tag;
	seL4_Word mr0;
	seL4_Word mr1;
	seL4_Word mr2;

	/* Setup input capabilities. */
	seL4_SetCap(0, cspace_root);
	seL4_SetCap(1, vspace_root);

	/* Marshal input parameters. */
	mr0 = fault_ep;
	mr1 = cspace_root_data.words[0];
	mr2 = vspace_root_data.words[0];

	/* Perform the call, passing in-register arguments directly. */
	output_tag = __seL4_CallWithMRs(service, tag,
		&mr0, &mr1, &mr2, NULL);

	return seL4_MessageInfo_get_label(output_tag);
}

static inline int
seL4_TCB_Suspend(seL4_TCB service)
{
	seL4_MessageInfo_t tag = seL4_MessageInfo_new(TCBSuspend, 0, 0, 0);
	seL4_MessageInfo_t output_tag;

	/* Perform the call, passing in-register arguments directly. */
	output_tag = __seL4_CallWithMRs(service, tag,
		NULL, NULL, NULL, NULL);

	return seL4_MessageInfo_get_label(output_tag);
}

static inline int
seL4_TCB_Resume(seL4_TCB service)
{
	seL4_MessageInfo_t tag = seL4_MessageInfo_new(TCBResume, 0, 0, 0);
	seL4_MessageInfo_t output_tag;

	/* Perform the call, passing in-register arguments directly. */
	output_tag = __seL4_CallWithMRs(service, tag,
		NULL, NULL, NULL, NULL);

	return seL4_MessageInfo_get_label(output_tag);
}

static inline int
seL4_TCB_BindAEP(seL4_TCB service, seL4_CPtr async_endpoint)
{
	seL4_MessageInfo_t tag = seL4_MessageInfo_new(TCBBindAEP, 0, 1, 0);
	seL4_MessageInfo_t output_tag;

	/* Setup input capabilities. */
	seL4_SetCap(0, async_endpoint);

	/* Perform the call, passing in-register arguments directly. */
	output_tag = __seL4_CallWithMRs(service, tag,
		NULL, NULL, NULL, NULL);

	return seL4_MessageInfo_get_label(output_tag);
}

static inline int
seL4_TCB_UnbindAEP(seL4_TCB service)
{
	seL4_MessageInfo_t tag = seL4_MessageInfo_new(TCBUnbindAEP, 0, 0, 0);
	seL4_MessageInfo_t output_tag;

	/* Perform the call, passing in-register arguments directly. */
	output_tag = __seL4_CallWithMRs(service, tag,
		NULL, NULL, NULL, NULL);

	return seL4_MessageInfo_get_label(output_tag);
}

static inline int
seL4_CNode_Revoke(seL4_CNode service, seL4_Word index, uint8_t depth)
{
	seL4_MessageInfo_t tag = seL4_MessageInfo_new(CNodeRevoke, 0, 0, 2);
	seL4_MessageInfo_t output_tag;
	seL4_Word mr0;
	seL4_Word mr1;

	/* Marshal input parameters. */
	mr0 = index;
	mr1 = (depth & 0xff);

	/* Perform the call, passing in-register arguments directly. */
	output_tag = __seL4_CallWithMRs(service, tag,
		&mr0, &mr1, NULL, NULL);

	return seL4_MessageInfo_get_label(output_tag);
}

static inline int
seL4_CNode_Delete(seL4_CNode service, seL4_Word index, uint8_t depth)
{
	seL4_MessageInfo_t tag = seL4_MessageInfo_new(CNodeDelete, 0, 0, 2);
	seL4_MessageInfo_t output_tag;
	seL4_Word mr0;
	seL4_Word mr1;

	/* Marshal input parameters. */
	mr0 = index;
	mr1 = (depth & 0xff);

	/* Perform the call, passing in-register arguments directly. */
	output_tag = __seL4_CallWithMRs(service, tag,
		&mr0, &mr1, NULL, NULL);

	return seL4_MessageInfo_get_label(output_tag);
}

static inline int
seL4_CNode_Recycle(seL4_CNode service, seL4_Word index, uint8_t depth)
{
	seL4_MessageInfo_t tag = seL4_MessageInfo_new(CNodeRecycle, 0, 0, 2);
	seL4_MessageInfo_t output_tag;
	seL4_Word mr0;
	seL4_Word mr1;

	/* Marshal input parameters. */
	mr0 = index;
	mr1 = (depth & 0xff);

	/* Perform the call, passing in-register arguments directly. */
	output_tag = __seL4_CallWithMRs(service, tag,
		&mr0, &mr1, NULL, NULL);

	return seL4_MessageInfo_get_label(output_tag);
}

static inline int
seL4_CNode_Copy(seL4_CNode service, seL4_Word dest_index, uint8_t dest_depth, seL4_CNode src_root, seL4_Word src_index, uint8_t src_depth, seL4_CapRights rights)
{
	seL4_MessageInfo_t tag = seL4_MessageInfo_new(CNodeCopy, 0, 1, 5);
	seL4_MessageInfo_t output_tag;
	seL4_Word mr0;
	seL4_Word mr1;
	seL4_Word mr2;
	seL4_Word mr3;

	/* Setup input capabilities. */
	seL4_SetCap(0, src_root);

	/* Marshal input parameters. */
	mr0 = dest_index;
	mr1 = (dest_depth & 0xff);
	mr2 = src_index;
	mr3 = (src_depth & 0xff);
	seL4_SetMR(4, rights);

	/* Perform the call, passing in-register arguments directly. */
	output_tag = __seL4_CallWithMRs(service, tag,
		&mr0, &mr1, &mr2, &mr3);

	return seL4_MessageInfo_get_label(output_tag);
}

static inline int
seL4_CNode_Mint(seL4_CNode service, seL4_Word dest_index, uint8_t dest_depth, seL4_CNode src_root, seL4_Word src_index, uint8_t src_depth, seL4_CapRights rights, seL4_CapData_t badge)
{
	seL4_MessageInfo_t tag = seL4_MessageInfo_new(CNodeMint, 0, 1, 6);
	seL4_MessageInfo_t output_tag;
	seL4_Word mr0;
	seL4_Word mr1;
	seL4_Word mr2;
	seL4_Word mr3;

	/* Setup input capabilities. */
	seL4_SetCap(0, src_root);

	/* Marshal input parameters. */
	mr0 = dest_index;
	mr1 = (dest_depth & 0xff);
	mr2 = src_index;
	mr3 = (src_depth & 0xff);
	seL4_SetMR(4, rights);
	seL4_SetMR(5, badge.words[0]);

	/* Perform the call, passing in-register arguments directly. */
	output_tag = __seL4_CallWithMRs(service, tag,
		&mr0, &mr1, &mr2, &mr3);

	return seL4_MessageInfo_get_label(output_tag);
}

static inline int
seL4_CNode_Move(seL4_CNode service, seL4_Word dest_index, uint8_t dest_depth, seL4_CNode src_root, seL4_Word src_index, uint8_t src_depth)
{
	seL4_MessageInfo_t tag = seL4_MessageInfo_new(CNodeMove, 0, 1, 4);
	seL4_MessageInfo_t output_tag;
	seL4_Word mr0;
	seL4_Word mr1;
	seL4_Word mr2;
	seL4_Word mr3;

	/* Setup input capabilities. */
	seL4_SetCap(0, src_root);

	/* Marshal input parameters. */
	mr0 = dest_index;
	mr1 = (dest_depth & 0xff);
	mr2 = src_index;
	mr3 = (src_depth & 0xff);

	/* Perform the call, passing in-register arguments directly. */
	output_tag = __seL4_CallWithMRs(service, tag,
		&mr0, &mr1, &mr2, &mr3);

	return seL4_MessageInfo_get_label(output_tag);
}

static inline int
seL4_CNode_Mutate(seL4_CNode service, seL4_Word dest_index, uint8_t dest_depth, seL4_CNode src_root, seL4_Word src_index, uint8_t src_depth, seL4_CapData_t badge)
{
	seL4_MessageInfo_t tag = seL4_MessageInfo_new(CNodeMutate, 0, 1, 5);
	seL4_MessageInfo_t output_tag;
	seL4_Word mr0;
	seL4_Word mr1;
	seL4_Word mr2;
	seL4_Word mr3;

	/* Setup input capabilities. */
	seL4_SetCap(0, src_root);

	/* Marshal input parameters. */
	mr0 = dest_index;
	mr1 = (dest_depth & 0xff);
	mr2 = src_index;
	mr3 = (src_depth & 0xff);
	seL4_SetMR(4, badge.words[0]);

	/* Perform the call, passing in-register arguments directly. */
	output_tag = __seL4_CallWithMRs(service, tag,
		&mr0, &mr1, &mr2, &mr3);

	return seL4_MessageInfo_get_label(output_tag);
}

static inline int
seL4_CNode_Rotate(seL4_CNode service, seL4_Word dest_index, uint8_t dest_depth, seL4_CapData_t dest_badge, seL4_CNode pivot_root, seL4_Word pivot_index, uint8_t pivot_depth, seL4_CapData_t pivot_badge, seL4_CNode src_root, seL4_Word src_index, uint8_t src_depth)
{
	seL4_MessageInfo_t tag = seL4_MessageInfo_new(CNodeRotate, 0, 2, 8);
	seL4_MessageInfo_t output_tag;
	seL4_Word mr0;
	seL4_Word mr1;
	seL4_Word mr2;
	seL4_Word mr3;

	/* Setup input capabilities. */
	seL4_SetCap(0, pivot_root);
	seL4_SetCap(1, src_root);

	/* Marshal input parameters. */
	mr0 = dest_index;
	mr1 = (dest_depth & 0xff);
	mr2 = dest_badge.words[0];
	mr3 = pivot_index;
	seL4_SetMR(4, (pivot_depth & 0xff));
	seL4_SetMR(5, pivot_badge.words[0]);
	seL4_SetMR(6, src_index);
	seL4_SetMR(7, (src_depth & 0xff));

	/* Perform the call, passing in-register arguments directly. */
	output_tag = __seL4_CallWithMRs(service, tag,
		&mr0, &mr1, &mr2, &mr3);

	return seL4_MessageInfo_get_label(output_tag);
}

static inline int
seL4_CNode_SaveCaller(seL4_CNode service, seL4_Word index, uint8_t depth)
{
	seL4_MessageInfo_t tag = seL4_MessageInfo_new(CNodeSaveCaller, 0, 0, 2);
	seL4_MessageInfo_t output_tag;
	seL4_Word mr0;
	seL4_Word mr1;

	/* Marshal input parameters. */
	mr0 = index;
	mr1 = (depth & 0xff);

	/* Perform the call, passing in-register arguments directly. */
	output_tag = __seL4_CallWithMRs(service, tag,
		&mr0, &mr1, NULL, NULL);

	return seL4_MessageInfo_get_label(output_tag);
}

static inline int
seL4_IRQControl_Get(seL4_IRQControl service, int irq, seL4_CNode root, seL4_Word index, uint8_t depth)
{
	seL4_MessageInfo_t tag = seL4_MessageInfo_new(IRQIssueIRQHandler, 0, 1, 3);
	seL4_MessageInfo_t output_tag;
	seL4_Word mr0;
	seL4_Word mr1;
	seL4_Word mr2;

	/* Setup input capabilities. */
	seL4_SetCap(0, root);

	/* Marshal input parameters. */
	mr0 = irq;
	mr1 = index;
	mr2 = (depth & 0xff);

	/* Perform the call, passing in-register arguments directly. */
	output_tag = __seL4_CallWithMRs(service, tag,
		&mr0, &mr1, &mr2, NULL);

	return seL4_MessageInfo_get_label(output_tag);
}

static inline int
seL4_IRQControl_Blah(seL4_IRQControl service)
{
	seL4_MessageInfo_t tag = seL4_MessageInfo_new(IRQInterruptControl, 0, 0, 0);
	seL4_MessageInfo_t output_tag;

	/* Perform the call, passing in-register arguments directly. */
	output_tag = __seL4_CallWithMRs(service, tag,
		NULL, NULL, NULL, NULL);

	return seL4_MessageInfo_get_label(output_tag);
}

static inline int
seL4_IRQHandler_Ack(seL4_IRQHandler service)
{
	seL4_MessageInfo_t tag = seL4_MessageInfo_new(IRQAckIRQ, 0, 0, 0);
	seL4_MessageInfo_t output_tag;

	/* Perform the call, passing in-register arguments directly. */
	output_tag = __seL4_CallWithMRs(service, tag,
		NULL, NULL, NULL, NULL);

	return seL4_MessageInfo_get_label(output_tag);
}

static inline int
seL4_IRQHandler_SetEndpoint(seL4_IRQHandler service, seL4_CPtr endpoint)
{
	seL4_MessageInfo_t tag = seL4_MessageInfo_new(IRQSetIRQHandler, 0, 1, 0);
	seL4_MessageInfo_t output_tag;

	/* Setup input capabilities. */
	seL4_SetCap(0, endpoint);

	/* Perform the call, passing in-register arguments directly. */
	output_tag = __seL4_CallWithMRs(service, tag,
		NULL, NULL, NULL, NULL);

	return seL4_MessageInfo_get_label(output_tag);
}

static inline int
seL4_IRQHandler_Clear(seL4_IRQHandler service)
{
	seL4_MessageInfo_t tag = seL4_MessageInfo_new(IRQClearIRQHandler, 0, 0, 0);
	seL4_MessageInfo_t output_tag;

	/* Perform the call, passing in-register arguments directly. */
	output_tag = __seL4_CallWithMRs(service, tag,
		NULL, NULL, NULL, NULL);

	return seL4_MessageInfo_get_label(output_tag);
}

#endif /* __LIBSEL4_SEL4_CLIENT_H */
