#ifndef _XENCTRL_H_
#define _XENCTRL_H_
// Subset of xenctrl.h

#include <inttypes.h>
#include "xen.h"
#include <xen/domctl.h>

/*
 * MMU updates.
 */
#define MAX_MMU_UPDATES 1024
struct xc_mmu {
    mmu_update_t updates[MAX_MMU_UPDATES];
    int          idx;
    domid_t      subject;
};
typedef struct xc_mmu xc_mmu_t;
xc_mmu_t *xc_init_mmu_updates(int xc_handle, domid_t dom);
int xc_add_mmu_update(int xc_handle, xc_mmu_t *mmu,
                   unsigned long long ptr, unsigned long long val);
int xc_finish_mmu_updates(int xc_handle, xc_mmu_t *mmu);

int xc_mmuext_op(int xc_handle, struct mmuext_op *op, unsigned int nr_ops,
                 domid_t dom);

int xc_get_pfn_list(int xc_handle, uint32_t domid, xen_pfn_t *pfn_buf,
                    unsigned long max_pfns);
int xc_memory_op(int xc_handle, int cmd, void *arg);
/* Get current total pages allocated to a domain. */
long xc_get_tot_pages(int xc_handle, uint32_t domid);
int xc_clear_domain_page(int xc_handle, uint32_t domid,
                         unsigned long dst_pfn);

#if 0
struct xen_domctl_shadow_op_stats {
    uint32_t fault_count;
    uint32_t dirty_count;
};
struct xen_domctl;
#endif

typedef xen_domctl_shadow_op_stats_t xc_shadow_op_stats_t;
int xc_shadow_control(int xc_handle,
                      uint32_t domid,
                      unsigned int sop,
                      unsigned long *dirty_bitmap,
                      unsigned long pages,
                      unsigned long *mb,
                      uint32_t mode,
                      xc_shadow_op_stats_t *stats);

int xc_domctl(int xc_handle, struct xen_domctl *domctl);

#define DECLARE_DOMCTL struct xen_domctl domctl

#endif //  _XENCTRL_H_
