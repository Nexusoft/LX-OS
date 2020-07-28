#include "loader.h"
#include <inttypes.h>
#include "xen-types.h"
#include "xen.h"
#include <xen/sched.h>
#include <xen/version.h>
#include <xen/memory.h>
#include <xen/vcpu.h>
#include <xen/physdev.h>
#include <errno.h>
#include <assert.h>
#include "hypercalls.h"
#include "tests.h"
#include <nexus/Xen.interface.h>
#include <nexus/Console.interface.h>
#include "net.h"

int dbg_xen_net = 0;
#define DO_MMU_SANITY_CHECKS (1)

#undef UNIMPLEMENTED
#define UNIMPLEMENTED()                         \
    do {                                        \
        static int has_printed;                 \
        if(!has_printed) {                      \
            printf("%s()!\n", __FUNCTION__);    \
            has_printed = 1;                    \
        }                                       \
        return -ENOSYS;                         \
    } while(0);

long HYPERCALL_xen_version(int cmd, void *arg) {
    switch ( cmd )
    {
    case XENVER_version: {
        return (XEN_VERSION << 16) | XEN_SUBVERSION;
        break;
    }
    case XENVER_capabilities: {
        xen_capabilities_info_t info;
        char *p = (char *)info;
        p += sprintf(p, "xen-%d.%d-x86_32 ", XEN_VERSION, XEN_SUBVERSION);
        p++;
        *(p - 1) = '\0';
        assert(p - (char *)info < sizeof(info));
        if(copy_to_guest(arg, (char *)info, 1)) {
            return -EFAULT;
        }
        return 0;
        break;
    }
    case XENVER_get_features: {
        // This code makes mini-os crash
        xen_feature_info_t fi;
        if(copy_from_guest(&fi, arg, 1)) {
            printf("could not get fi from guest\n");
            return -EFAULT;
        }
        switch(fi.submap_idx) {
        case 0:
            fi.submap = 0;
            break;
        default:
            printf("unknown submap %d\n", fi.submap);
            return -EINVAL;
        }
        if(copy_to_guest(arg, &fi, 1)) {
            printf("could not write fi to guest\n");
            return -EFAULT;
        }
        return 0;
    }
    case XENVER_platform_parameters: {
        // This code comes straight from Xen
        xen_platform_parameters_t params = {
            .virt_start = HYPERVISOR_VIRT_START
        };
        if ( copy_to_guest(arg, &params, 1) )
            return -EFAULT;
        return 0;
    }
    default:
        PERROR("Unknown xen_version opcode! %d\n", cmd);
        return -ENOSYS;
    }
}

// xen/common/domain.c contains the small implementation in Xen
long HYPERCALL_vm_assist(unsigned int cmd, unsigned int type) {
    if(type == VMASST_TYPE_writable_pagetables) {
        if(cmd != VMASST_CMD_enable) {
            // VMM code does not support disabling this feature
            // Nexus kernel should be OK.
            printf("Writable page tables can only be enabled "
                   "(e.g., can't be turned off once they're on!\n");
            return -ENOSYS;
        }
        struct trap_info ti = {
            .vector = INTERRUPT_PAGEFAULT,
            .cs = KXENCS,
            .address = (unsigned long) vmm_pfault_handler_asm,
        };
        if(HYPERCALL_set_trap_table(&ti) != 0) {
            printf("Could not hook trap table!\n");
            return -EINVAL;
        }
        // Fall through to enable on Nexus kernel-side 
    }
    return Xen_H_vm_assist(cmd, type);
}

 /*
   linux/include/xen/interface/xen.h contains a good treatment of
   mmu_update and mmuext_op 
 */

/*
	MMU_NORMAL_PT_UPDATE
	MMU_MACHPHYS_UPDATE
*/

// mmu_update is passed verbatim to Nexus
long HYPERCALL_mmu_update(int fromVMM, 
                         mmu_update_t *ureqs, unsigned int count,
                         unsigned int *pdone, unsigned int dom_id) {
    if(DO_MMU_SANITY_CHECKS) {
        // Verify that page table portion pointing to VMM is unchanged.
        // Since we trust the guest OS, this is mostly a sanity check.
        if(!fromVMM) {
            int i;
            for(i=0; i < count; i++) {
                maddr_t ptr = ureqs[i].ptr; 	/* pte or m2p addr */
                __u32 val = ureqs[i].val; 	/* value to write into pte / m2p map */

                if( (ptr & 0x3) == MMU_NORMAL_PT_UPDATE ) {
                    if((ptr & PAGE_MASK) == gPDBR) {
                        int offset = (ptr & PAGE_OFFSET_MASK) / sizeof(__u32);
                        const int hypervisor_start = HYPERVISOR_VIRT_START >> PDIR_SHIFT;
                        if(offset >= hypervisor_start && 
                           offset < hypervisor_start + NUM_VMM_PTABS) {
                            if(val != gVMMPtable_checkVals[offset - hypervisor_start]) {
                                printf("Check val mismatch at %d, %p/%p!\n", offset, 
                                       (void *)ptr, (void *)gPDBR);
                                return -EINVAL;
                            }
                        }
                    }
                    // XXX also verify that the guest is not manipulating the page tables themselves
                }
            }
        }
    }
    return Xen_H_mmu_update(ureqs, count, pdone, dom_id);
}

long HYPERCALL_mmu_update_guest(mmu_update_t *ureqs, unsigned int count,
                               unsigned int *pdone, unsigned int dom_id) {
    return HYPERCALL_mmu_update(0, ureqs, count, pdone, dom_id);
}

// 4 arguments
long HYPERCALL_mmuext_op(struct mmuext_op *ops, unsigned int count,
                        unsigned int *pdone, unsigned int foreigndom) {
    int i;
    int do_resync = 0;
    __u32 new_pdbr = 0;
    for(i=0; i < count; i++) {
        machfn_t mfn = ops[i].arg1.mfn;
        switch(ops[i].cmd) {
        case MMUEXT_PIN_L2_TABLE: {
            // Copy in VMM and swapper pgdir entries
            DirectoryEntry *pdir = (DirectoryEntry *)KSEG_map(&mfn, 1);
            PDIR_initHigh(pdir);
            KSEG_unmap((vaddr_t)pdir);
            break;
        }
        case MMUEXT_NEW_BASEPTR: {
            // Defer the mapping so that it is reflected in the new MFN
            new_pdbr = mfn << PAGE_SHIFT;
            do_resync = 1;
            break;
        }
        }
    }
    int rv = Xen_H_mmuext_op(ops, count, pdone, foreigndom);
    if(do_resync) {
        // New_BasePTR code assumes that the call is valid
        assert(rv == 0);
        // optimization: resync after TLB flush

        PDBR_switchto(new_pdbr, 1);
        PDBR_sync();
    }
    return rv;
}

long HYPERCALL_console_io(int cmd, int count, char *buffer) {
    switch(cmd) {
    case CONSOLEIO_write: {
        int i;
        for(i=0; i < count; i++) {
            fputc(buffer[i], stdout);
        }
        break;
    }
    case CONSOLEIO_read: {
        struct VarLen desc = {
            .data = buffer,
            .len = count,
        };
        int returned_count = Console_GetData(kbdhandle, desc, count);
        if(returned_count < 0) {
            printf("Console read: Got nexus error %d %d\n", returned_count, count);
            return -EINVAL;
        }
        return returned_count;
    }
    case CONSOLEIO_setmode: {
        int rv;
        int mode = count;
        switch(mode) {
        case CONSOLEIO_RAW:
            rv = Console_SetInputMode(kbdhandle, KBD_RAW);
            if(rv != 0) {
                printf("(Medium)raw set mode returned %d!\n", rv);
            }
            return (rv == 0) ? 0 : -EINVAL;
        case CONSOLEIO_RARE:
            rv = Console_SetInputMode(kbdhandle, KBD_RARE);
            if(rv != 0) {
                printf("Xlate set mode returned %d!\n", rv);
            }
            return (rv == 0) ? 0 : -EINVAL;
        default:
            printf("Unknown console mode %d!\n", mode);
            return -EINVAL;
        }
    }
    case CONSOLEIO_get_kbent: {
        consoleio_op_t op;
        if(copy_from_guest(&op, (consoleio_op_t *)buffer, 1) != 0) {
            return -EACCES;
        }
        op.kb_ent.value  = Console_GetKeymapEntry(op.kb_ent.table, op.kb_ent.index);
        if(copy_to_guest((consoleio_op_t *)buffer, &op, 1) != 0) {
            return -EACCES;
        }
        return 0;
    }
    default:
        printf("Unknown console_io cmd=%d!\n", cmd);
        return -ENOSYS;
    }
    return 0;
}

long HYPERCALL_update_va_mapping (unsigned long va, u64 val, unsigned long flags) {
    // XXX This will be faster if it was implemented natively in Nexus
    // with a writable, mapped page table
    maddr_t ma = VMM_pte_m(va);
    // printf("update_va_mapping(%p=>%p=>%p,%x)\n", (void *)va, ma, (void *)val, (int)flags);
    mmu_update_t op = {
        .ptr = ma,
        .val = val,
    };
    int dcount;
    HYPERCALL_mmu_update(0, &op, 1, &dcount, DOMID_SELF);
    if(dcount != 1) {
        return -EINVAL;
    }

    // Flushes are assumed to be global
    switch ( flags & UVMF_FLUSHTYPE_MASK ) {
    case UVMF_NONE: {
        // No flush, fall through without doing anything
        break;
    }
    case UVMF_TLB_FLUSH: {
        if((flags & ~UVMF_FLUSHTYPE_MASK) != UVMF_ALL) {
            // printf("Warning: doing flushAll when it is not necessary\n");
        }
        flushTLB();
        break;
    }
    case UVMF_INVLPG: {
        flushTLB_one(va);
        break;
    }
    default:
        printf("Unimplemented update_va_mapping flushtype %lu\n",
               flags & UVMF_FLUSHTYPE_MASK);
        return -ENOSYS;
    }
    return 0;
}

long HYPERCALL_set_trap_table(struct trap_info *guest_table) {
    // Intercept page fault handler to handle writes to writable page
    // table
    int i;
    int table_len;
    for(i=0; ; i++) {
        struct trap_info ti;
        if(copy_from_guest(&ti, &guest_table[i], 1) != 0) {
            printf("Could not copy trap table @ %d\n", i);
            return -EACCES;
        }
        if (ti.address == 0) {
            break;
        }
    }
    table_len = i + 1;
    struct trap_info *trap_table = malloc(table_len * sizeof(struct trap_info));
    if(copy_from_guest(trap_table, guest_table, table_len) != 0) {
        printf("Could not copy trap table\n");
        free(trap_table);
        return -EACCES;
    }
    for(i=0; i < table_len; i++) {
        struct trap_info *ti = &trap_table[i];
        if(ti->vector == INTERRUPT_PAGEFAULT) {
            if(ti->cs == KXENCS &&
               ti->address == (unsigned long) vmm_pfault_handler_asm) {
                // Special case to avoid hooking VMM's writable page
                // table handler
                continue;
            }
            printf("Page Fault tab[%d]={%x:%p,%x} ", ti->vector, 
                   ti->cs, (void *)ti->address, ti->flags);
            if((ti->cs & 0x3) < 1) {
                ti->cs &= ~0x3;
                ti->cs |= 1;
            }
            guest_pfault_handler_cs = ti->cs;
            guest_pfault_handler_eip = ti->address;
            ti->cs = KXENCS;
            ti->address = (unsigned long) vmm_pfault_handler_asm;
            printf("Saved\n");
        }
    }
    int rv = Xen_H_set_trap_table(trap_table);
    free(trap_table);
    return rv;
}

long HYPERCALL_set_callbacks (unsigned long event_selector,
                             unsigned long event_address,
                             unsigned long failsafe_selector,
                             unsigned long failsafe_address) {
    return Xen_H_set_callbacks(event_selector, event_address, failsafe_selector, failsafe_address);
}

long HYPERCALL_stack_switch(unsigned long ss, unsigned long esp) {
    return Xen_H_stack_switch(ss, esp);
}

long HYPERCALL_set_timer_op(unsigned long long timeout /* ns since boot */) {
    return Xen_H_set_timer_op(timeout >> 32, timeout & 0xffffffff);
}


long HYPERCALL_arch_sched_op(int cmd, unsigned long arg) {
    switch(cmd) {
    case SCHEDOP_shutdown:
        printf("SHUTDOWN %ld\n", arg);
        // printf("looping"); while(1) ;
        exit(arg);
        break;
    }
    return Xen_H_arch_sched_op(cmd, arg);
}

long HYPERCALL_event_channel_op (int cmd, void *op) {
    return Xen_H_event_channel_op(cmd, op);
}

long HYPERCALL_callback_op(int cmd, void *arg) {
    return Xen_H_callback_op(cmd, arg);
}

long HYPERCALL_memory_op (unsigned long cmd, void *arg) {
    // Adapted from Xen 3.0.3
    switch(cmd) {
    case XENMEM_memory_map:
    {
        return -ENOSYS;
    }
    case XENMEM_machphys_mapping:
    {
        if(1) {
            // Xen Linux will use defaults if this is not implemented
            struct xen_machphys_mapping mapping = {
                .v_start = MACH2PHYS_VIRT_START,
                .v_end   = MACH2PHYS_VIRT_END,
                .max_mfn = MACH2PHYS_NR_ENTRIES - 1
            };

            if ( copy_to_guest(arg, &mapping, 1) )
                return -EFAULT;

            return 0;
        } else {
            return -ENOSYS;
        }
    }
    default:
        printf("Unknown memory_op %lu\n", cmd);
        return -ENOSYS;
    }
}

long HYPERCALL_physdev_op (int cmd, void *args) {
    return Xen_H_physdev_op(cmd, args);
}

long HYPERCALL_vcpu_op (int cmd, int vcpuid, void *extra_args) {
    int rc = 0;
    switch(cmd) {
    case VCPUOP_is_up:
        // The only cpu that is up is number 0
        rc = (vcpuid == 0);
        break;
    case VCPUOP_initialise:
        rc = 0;
        break;
    case VCPUOP_up: // No-op
        rc = (vcpuid == 0);
        break;
    default:
        printf("Unimplemented VCPU op(op %d on cpu#%d)\n", cmd, vcpuid);
        rc = -ENOSYS;
    }
    return rc;
}

long HYPERCALL_set_gdt(unsigned long *frame_list, int entries) {
    return Xen_H_set_gdt(frame_list, entries);
}

long generic_hypercall_byArray(long op, long a0, long a1, long a2, long a3, long a4, long a5);

long HYPERCALL_multicall (multicall_entry_t *call_list, int nr_calls) {
    int position = 0;

    if(0) {
        if(nr_calls > 1) {
            int i;
            for(i=0; i < nr_calls; i++) {
                multicall_entry_t *ent = &call_list[i];
                printf("{ op[%d/%d] %ld=>{ %lx %lx %lx %lx %lx %lx }", 
                       i, nr_calls, 
                       ent->op, ent->args[0], ent->args[1], ent->args[2], 
                       ent->args[3], ent->args[4], ent->args[5]);
            }
        }
    }

    while(position < nr_calls) {
        long num_processed = Xen_H_multicall(&call_list[position], nr_calls - position);
        if(num_processed < 0) {
            printf("!!!! multicall returned prematurely (%d)\n", position);
            return num_processed;
        }
        if(num_processed == 0) {
            // multicall is done
            return 0;
        }

        multicall_entry_t *ent = &call_list[num_processed];
        printf("hypercall retry %ld\n", ent->op);
        ent->result = 
            generic_hypercall_byArray(ent->op, ent->args[0],
                                                ent->args[1],ent->args[2],
                                                ent->args[3],ent->args[4],
                                                ent->args[5]);
        if(ent->result != 0) {
            printf("Multicall retry at %d => %ld\n", position, ent->result);
        }
        position += num_processed;
        printf("Multicall: %ld completed, %d to go\n", num_processed, nr_calls - position);
    }
    assert(position == nr_calls);
    return 0;
}

long HYPERCALL_fpu_taskswitch(int set) {
    UNIMPLEMENTED();
    return Xen_H_fpu_taskswitch(set);
}

long HYPERCALL_update_descriptor(u64 ma, u64 desc) {
    // printf("update descriptor %llx, %llx", ma, desc);
    return Xen_H_update_descriptor(ma, ma >> 32, desc, desc >> 32);
}

long HYPERCALL_getNexusVariables(struct NexusVariables *variables) {
    extern int printhandle;
    struct NexusVariables var = {
        .print_handle = printhandle,
        .mouse_handle = mouse_handle,
    };
    if(copy_to_guest(variables, &var, 1) != 0) {
        printf("Could not copy Nexus library variables to guest\n");
        return -EACCES;
    }
    return 0;
}

int HYPERCALL_VNet_Init(int vnic_num, char *assigned_mac) {
    if(vnic_num != 0) {
      return -SC_INVALID;
    }
    return xen_vnet_init(vnic_num, assigned_mac);
}
int HYPERCALL_VNet_Send(int vnic_num, char *user_data, int len) {
    if(dbg_xen_net) {
      printf("t");
    }
    if(vnic_num != 0) {
      return -SC_INVALID;
    }
    return xen_vnet_usend(vnic_num, user_data, len);
}
int HYPERCALL_VNet_HasPendingRecv(int vnic_num) {
    if(vnic_num != 0) {
      return -SC_INVALID;
    }
    return xen_vnet_poll(vnic_num);
}
int /* length */ HYPERCALL_VNet_Recv(int vnic_num, char *data, int len) {
    if(dbg_xen_net) {
      printf("r");
    }
    if(vnic_num != 0) {
      printf("only one vnic (#0) currently supported\n");
      return -SC_INVALID;
    }
    return xen_vnet_urecv(vnic_num, data, len);
}

int HYPERCALL_VNet_SetupIRQ(int vnic_num, int irq_num) {
    if(vnic_num != 0) {
      printf("only one vnic (#0) currently supported\n");
      return -SC_INVALID;
    }
    return xen_vnet_setup_irq(vnic_num, irq_num);
}
/*

// Code should explicitly handle all flags!

VCPUOP_register_runstate_memory_area

HYPERVISOR_get_debugreg
HYPERVISOR_set_debugreg

HYPERVISOR_xenoprof_op

--- Croak on these
HYPERVISOR_dom0_op

HYPERVISOR_grant_table_op
HYPERVISOR_update_va_mapping_otherdomain

HYPERVISOR_acm_op
HYPERVISOR_nmi_op
HYPERVISOR_hvm_op
*/
/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */


long HYPERCALL_ni_hypercall (void) {
    printf("Unimplemented hypercall!\n");
    return -ENOSYS;
}


long HYPERCALL_arch_sched_op_compat (void) {
    UNIMPLEMENTED();
}
long HYPERCALL_platform_op (void) {
    UNIMPLEMENTED();
}
long HYPERCALL_set_debugreg (void) {
    UNIMPLEMENTED();
}
long HYPERCALL_get_debugreg (void) {
    UNIMPLEMENTED();
}
long HYPERCALL_event_channel_op_compat (void) {
    UNIMPLEMENTED();
}
long HYPERCALL_physdev_op_compat (void) {
    UNIMPLEMENTED();
}
long HYPERCALL_grant_table_op     /* 20 */ (void) {
    UNIMPLEMENTED();
}
long HYPERCALL_update_va_mapping_otherdomain (void) {
    UNIMPLEMENTED();
}
long HYPERCALL_iret (void) {
    UNIMPLEMENTED();
}
long HYPERCALL_acm_op (void) {
    UNIMPLEMENTED();
}
long HYPERCALL_nmi_op (void) {
    UNIMPLEMENTED();
}
long HYPERCALL_xenoprof_op (void) {
    UNIMPLEMENTED();
}
long HYPERCALL_hvm_op (void) {
    UNIMPLEMENTED();
}
long HYPERCALL_sysctl             /* 35 */ (void) {
    UNIMPLEMENTED();
}
long HYPERCALL_domctl (void) {
    UNIMPLEMENTED();
}
