/******************************************************************************
 * xc_private.c
 *
 * Helper functions for the rest of the library.
 */

#include "loader.h"
#include <inttypes.h>
#include "xen-types.h"
#include "xenctrl.h"
#include <xen/version.h>
#include <assert.h>
#include <unistd.h>
#include <sys/mman.h>
#include <errno.h>
#include <string.h>
#include "hypercalls.h"
#include "tests.h"
#include "xg_private.h"


static inline void safe_munlock(const void *addr, size_t len)
{
    int saved_errno = errno;
    (void)munlock(addr, len);
    errno = saved_errno;
}

// #include "xc_private.h"

/* NB: arr must be mlock'ed */
int xc_get_pfn_type_batch(int xc_handle,
                          uint32_t dom, int num, unsigned long *arr)
{
#if 0
    DECLARE_DOMCTL;
    domctl.cmd = XEN_DOMCTL_getpageframeinfo2;
    domctl.domain = (domid_t)dom;
    domctl.u.getpageframeinfo2.num    = num;
    set_xen_guest_handle(domctl.u.getpageframeinfo2.array, arr);
    return do_domctl(xc_handle, &domctl);
#endif
    UNIMPLEMENTED();
    return 0;
}

#define GETPFN_ERR (~0U)
unsigned int get_pfn_type(int xc_handle,
                          unsigned long mfn,
                          uint32_t dom)
{
#if 0
    DECLARE_DOMCTL;
    domctl.cmd = XEN_DOMCTL_getpageframeinfo;
    domctl.u.getpageframeinfo.gmfn   = mfn;
    domctl.domain = (domid_t)dom;
    if ( do_domctl(xc_handle, &domctl) < 0 )
    {
        PERROR("Unexpected failure when getting page frame info!");
        return GETPFN_ERR;
    }
    return domctl.u.getpageframeinfo.type;
#endif
    UNIMPLEMENTED();
    return 0;
}

int xc_mmuext_op(
    int xc_handle,
    struct mmuext_op *op,
    unsigned int nr_ops,
    domid_t dom)
{
    int num_done;
    int rv;
    rv = HYPERCALL_mmuext_op(op, nr_ops, &num_done, DOMID_SELF);
    assert(num_done == nr_ops);
    return rv;
}

static inline int flush_mmu_updates(int xc_handle, xc_mmu_t *mmu)
{
    int count = 0;
    int rv = HYPERCALL_mmu_update(1, mmu->updates, mmu->idx,
                                  &count, mmu->subject);
    if(mmu->idx != count) {
        p2m_mapping_dump();
    }
    assert(mmu->idx == count);
    mmu->idx = 0;
    return rv;
}

xc_mmu_t *xc_init_mmu_updates(int xc_handle, domid_t dom)
{
    xc_mmu_t *mmu = malloc(sizeof(xc_mmu_t));
    if ( mmu == NULL )
        return mmu;
    mmu->idx     = 0;
    mmu->subject = dom;
    return mmu;
}

int xc_add_mmu_update(int xc_handle, xc_mmu_t *mmu,
                      unsigned long long ptr, unsigned long long val)
{
    mmu->updates[mmu->idx].ptr = ptr;
    mmu->updates[mmu->idx].val = val;

    if ( ++mmu->idx == MAX_MMU_UPDATES )
        return flush_mmu_updates(xc_handle, mmu);

    return 0;
}

int xc_finish_mmu_updates(int xc_handle, xc_mmu_t *mmu)
{
    return flush_mmu_updates(xc_handle, mmu);
}

int xc_memory_op(int xc_handle,
                 int cmd,
                 void *arg)
{
#if 0
    DECLARE_HYPERCALL;
    struct xen_memory_reservation *reservation = arg;
    struct xen_machphys_mfn_list *xmml = arg;
    struct xen_translate_gpfn_list *trans = arg;
    xen_pfn_t *extent_start;
    xen_pfn_t *gpfn_list;
    xen_pfn_t *mfn_list;
    long ret = -EINVAL;

    hypercall.op     = __HYPERVISOR_memory_op;
    hypercall.arg[0] = (unsigned long)cmd;
    hypercall.arg[1] = (unsigned long)arg;

    switch ( cmd )
    {
    case XENMEM_increase_reservation:
    case XENMEM_decrease_reservation:
    case XENMEM_populate_physmap:
        if ( mlock(reservation, sizeof(*reservation)) != 0 )
        {
            PERROR("Could not mlock");
            goto out1;
        }
        get_xen_guest_handle(extent_start, reservation->extent_start);
        if ( (extent_start != NULL) &&
             (mlock(extent_start,
                    reservation->nr_extents * sizeof(xen_pfn_t)) != 0) )
        {
            PERROR("Could not mlock");
            safe_munlock(reservation, sizeof(*reservation));
            goto out1;
        }
        break;
    case XENMEM_machphys_mfn_list:
        if ( mlock(xmml, sizeof(*xmml)) != 0 )
        {
            PERROR("Could not mlock");
            goto out1;
        }
        get_xen_guest_handle(extent_start, xmml->extent_start);
        if ( mlock(extent_start,
                   xmml->max_extents * sizeof(xen_pfn_t)) != 0 )
        {
            PERROR("Could not mlock");
            safe_munlock(xmml, sizeof(*xmml));
            goto out1;
        }
        break;
    case XENMEM_add_to_physmap:
        if ( mlock(arg, sizeof(struct xen_add_to_physmap)) )
        {
            PERROR("Could not mlock");
            goto out1;
        }
        break;
    case XENMEM_translate_gpfn_list:
        if ( mlock(trans, sizeof(*trans)) != 0 )
        {
            PERROR("Could not mlock");
            goto out1;
        }
        get_xen_guest_handle(gpfn_list, trans->gpfn_list);
        if ( mlock(gpfn_list, trans->nr_gpfns * sizeof(xen_pfn_t)) != 0 )
        {
            PERROR("Could not mlock");
            safe_munlock(trans, sizeof(*trans));
            goto out1;
        }
        get_xen_guest_handle(mfn_list, trans->mfn_list);
        if ( mlock(mfn_list, trans->nr_gpfns * sizeof(xen_pfn_t)) != 0 )
        {
            PERROR("Could not mlock");
            safe_munlock(gpfn_list, trans->nr_gpfns * sizeof(xen_pfn_t));
            safe_munlock(trans, sizeof(*trans));
            goto out1;
        }
        break;
    }

    ret = do_xen_hypercall(xc_handle, &hypercall);

    switch ( cmd )
    {
    case XENMEM_increase_reservation:
    case XENMEM_decrease_reservation:
    case XENMEM_populate_physmap:
        safe_munlock(reservation, sizeof(*reservation));
        get_xen_guest_handle(extent_start, reservation->extent_start);
        if ( extent_start != NULL )
            safe_munlock(extent_start,
                         reservation->nr_extents * sizeof(xen_pfn_t));
        break;
    case XENMEM_machphys_mfn_list:
        safe_munlock(xmml, sizeof(*xmml));
        get_xen_guest_handle(extent_start, xmml->extent_start);
        safe_munlock(extent_start,
                     xmml->max_extents * sizeof(xen_pfn_t));
        break;
    case XENMEM_add_to_physmap:
        safe_munlock(arg, sizeof(struct xen_add_to_physmap));
        break;
    case XENMEM_translate_gpfn_list:
            get_xen_guest_handle(mfn_list, trans->mfn_list);
            safe_munlock(mfn_list, trans->nr_gpfns * sizeof(xen_pfn_t));
            get_xen_guest_handle(gpfn_list, trans->gpfn_list);
            safe_munlock(gpfn_list, trans->nr_gpfns * sizeof(xen_pfn_t));
            safe_munlock(trans, sizeof(*trans));
        break;
    }

 out1:
    return ret;
#endif
    UNIMPLEMENTED();
    return 0;
}


long long xc_domain_get_cpu_usage( int xc_handle, domid_t domid, int vcpu )
{
#if 0
    DECLARE_DOMCTL;

    domctl.cmd = XEN_DOMCTL_getvcpuinfo;
    domctl.domain = (domid_t)domid;
    domctl.u.getvcpuinfo.vcpu   = (uint16_t)vcpu;
    if ( (do_domctl(xc_handle, &domctl) < 0) )
    {
        PERROR("Could not get info on domain");
        return -1;
    }
    return domctl.u.getvcpuinfo.cpu_time;
#endif
    UNIMPLEMENTED();
    return 0;
}


#ifndef __ia64__
// Return an array of mfns, appropriate for performing P2M translation
int xc_get_pfn_list(int xc_handle,
                    uint32_t domid,
                    xen_pfn_t *pfn_buf,
                    unsigned long max_pfns)
{
    int copy_pfns = MIN(gTotalVMPages, max_pfns);
    assert(sizeof(xen_pfn_t) == sizeof(phys2mach[0]));

    memcpy(pfn_buf, phys2mach, copy_pfns * sizeof(xen_pfn_t));
    return copy_pfns;
}
#endif

long xc_get_tot_pages(int xc_handle, uint32_t domid)
{
    return gTotalVMPages;
}

int xc_copy_to_domain_page(int xc_handle,
                           uint32_t domid,
                           unsigned long _dst_pfn,
                           const char *src_page)
{
    machfn_t dest_pfn = (machfn_t)_dst_pfn;
    char *dest = (char *)KSEG_map(&dest_pfn, 1);
    assert(dest != NULL);
    memcpy(dest, src_page, PAGE_SIZE);
    KSEG_unmap((vaddr_t)dest);
    return 0;
}

int xc_clear_domain_page(int xc_handle,
                         uint32_t domid,
                         unsigned long dst_pfn)
{
    void *vaddr = xc_map_foreign_range(
        xc_handle, domid, PAGE_SIZE, PROT_WRITE, dst_pfn);
    if ( vaddr == NULL )
        return -1;
    memset(vaddr, 0, PAGE_SIZE);
    nl_munmap(vaddr, PAGE_SIZE);
    return 0;
}

unsigned long xc_get_filesz(int fd)
{
    uint16_t sig;
    uint32_t _sz = 0;
    unsigned long sz;

    lseek(fd, 0, SEEK_SET);
    if ( read(fd, &sig, sizeof(sig)) != sizeof(sig) )
        return 0;
    sz = lseek(fd, 0, SEEK_END);
    if ( sig == 0x8b1f ) /* GZIP signature? */
    {
        lseek(fd, -4, SEEK_END);
        if ( read(fd, &_sz, 4) != 4 )
            return 0;
        sz = _sz;
    }
    lseek(fd, 0, SEEK_SET);

    return sz;
}

void xc_map_memcpy(unsigned long dst, const char *src, unsigned long size,
                   int xch, uint32_t dom, xen_pfn_t *parray,
                   unsigned long vstart)
{
#if 0
    char *va;
    unsigned long chunksz, done, pa;

    for ( done = 0; done < size; done += chunksz )
    {
        pa = dst + done - vstart;
        va = xc_map_foreign_range(
            xch, dom, PAGE_SIZE, PROT_WRITE, parray[pa>>PAGE_SHIFT]);
        chunksz = size - done;
        if ( chunksz > (PAGE_SIZE - (pa & (PAGE_SIZE-1))) )
            chunksz = PAGE_SIZE - (pa & (PAGE_SIZE-1));
        memcpy(va + (pa & (PAGE_SIZE-1)), src + done, chunksz);
        munmap(va, PAGE_SIZE);
    }
#endif
    UNIMPLEMENTED();
    // Check to see if the target is within the allowed vaddr bounds of a Nexus process
}

int xc_domctl(int xc_handle, struct xen_domctl *domctl)
{
    assert(domctl->domain == DOMID_SELF);
    switch(domctl->cmd) {
    case XEN_DOMCTL_getdomaininfo:
        assert(shared_info_mfn != 0);
        domctl->u.getdomaininfo = 
            ((xen_domctl_getdomaininfo_t) {
                .domain = domctl->domain,
                     .flags = 0,
                     .tot_pages = gTotalVMPages,
                     .max_pages = gTotalVMPages,
                     .shared_info_frame = shared_info_mfn,
                     .cpu_time = 0,
                     .nr_online_vcpus = 1,
                     .max_vcpu_id = 0,
                     .ssidref = 0,
                     .handle = { 0 },
            });
        return 0;
        break;
    case XEN_DOMCTL_hypercall_init: {
        printf("Hypercall init...");
        machfn_t target_mfn = domctl->u.hypercall_init.gmfn;
        // Xen code in hypercall_page_initialise() -- arch/x86/x86_32/traps.c
        int i;
        // Each entry point is a maximum of 32 bytes long
        void *target_page = 
            xc_map_foreign_range(xc_handle, domctl->domain, PAGE_SIZE,
                                 PROT_WRITE, target_mfn);
        assert(target_page != NULL);
        char *p;
        for(i=0; i < PAGE_SIZE / 32; i++) {
            p = (char *) target_page + i * 32;
            *(u8  *)(p+ 0) = 0xb8;    /* mov  $<i>,%eax */
            *(u32 *)(p+ 1) = i;
            memcpy(p + 5, hypercall_stub, hypercall_stub_end - hypercall_stub);
        }

        /*
         * HYPERVISOR_iret is special because it doesn't return and expects a
         * special stack frame. Guests jump at this transfer point instead of
         * calling it.
         */
        p = (char *) target_page + (__HYPERVISOR_iret * 32);
        memcpy(p, hypercall_iret_stub,
               hypercall_iret_stub_end - hypercall_iret_stub);

        nl_munmap(target_page, PAGE_SIZE);
        printf("done!\n");
        return 0;
        break;
    }
    case XEN_DOMCTL_setvcpucontext: {
        if(domctl->u.vcpucontext.vcpu != 0) {
            printf("VCPU is %d!\n", domctl->u.vcpucontext.vcpu);
            return -EINVAL;
        }
        assert(sizeof(*domctl->u.vcpucontext.ctxt) ==
               sizeof(initial_cpu_ctx));
        memcpy(&initial_cpu_ctx, domctl->u.vcpucontext.ctxt,
               sizeof(initial_cpu_ctx));
        return 0;
        break;
    }
    default:
        printf("Unknown XEN_DOMCTL opcode %d!!!\n", domctl->cmd);
        // UNIMPLEMENTED();
        return 0;
    }
}

int xc_version(int xc_handle, int cmd, void *arg)
{
    int rc, argsize = 0;

    switch ( cmd )
    {
    case XENVER_extraversion:
        argsize = sizeof(xen_extraversion_t);
        break;
    case XENVER_compile_info:
        argsize = sizeof(xen_compile_info_t);
        break;
    case XENVER_capabilities:
        argsize = sizeof(xen_capabilities_info_t);
        break;
    case XENVER_changeset:
        argsize = sizeof(xen_changeset_info_t);
        break;
    case XENVER_platform_parameters:
        argsize = sizeof(xen_platform_parameters_t);
        break;
    }

#ifdef VALGRIND
    if (argsize != 0)
        memset(arg, 0, argsize);
#endif

    rc = HYPERCALL_xen_version(cmd, arg);

    return rc;
}

unsigned long xc_make_page_below_4G(
    int xc_handle, uint32_t domid, unsigned long mfn)
{
#if 0
    xen_pfn_t old_mfn = mfn;
    xen_pfn_t new_mfn;

    if ( xc_domain_memory_decrease_reservation(
        xc_handle, domid, 1, 0, &old_mfn) != 0 )
    {
        DPRINTF("xc_make_page_below_4G decrease failed. mfn=%lx\n",mfn);
        return 0;
    }

    if ( xc_domain_memory_increase_reservation(
        xc_handle, domid, 1, 0, 32, &new_mfn) != 0 )
    {
        DPRINTF("xc_make_page_below_4G increase failed. mfn=%lx\n",mfn);
        return 0;
    }

    return new_mfn;
#endif
    UNIMPLEMENTED();
    return -1;
}

int xc_shadow_control(int xc_handle,
                      uint32_t domid,
                      unsigned int sop,
                      unsigned long *dirty_bitmap,
                      unsigned long pages,
                      unsigned long *mb,
                      uint32_t mode,
                      xc_shadow_op_stats_t *stats)
{
    UNIMPLEMENTED();
    return -1;
}
/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
