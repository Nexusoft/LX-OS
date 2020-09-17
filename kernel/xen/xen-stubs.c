/* Stub functions */
#include <linux/linkage.h>
#include <asm/cache.h>

#ifndef SMP_CACHE_BYTES
#define SMP_CACHE_BYTES L1_CACHE_BYTES
#endif

struct xen_regs;
#ifndef __cacheline_aligned
#define __cacheline_aligned __attribute__((__aligned__(SMP_CACHE_BYTES)))
#endif

typedef struct {
        unsigned int __softirq_pending;
        unsigned int __local_irq_count;
        unsigned int __nmi_count;
        unsigned long idle_timestamp;
} __cacheline_aligned irq_cpustat_t;

asmlinkage int do_debug(struct xen_regs *regs) { return -1; } /* from arch/x86/traps.c */

asmlinkage int do_general_protection(struct xen_regs *regs) { return -1; } /* from arch/x86/traps.c */

asmlinkage int do_int3(struct xen_regs *regs) { return -1; } /* from arch/x86/traps.c */

asmlinkage void do_machine_check(struct xen_regs *regs) { } /* from arch/x86/traps.c */

void domain_crash_synchronous(void) { } /* from common/domain.c */

asmlinkage void do_nmi(struct xen_regs *regs, unsigned long reason) { } /* from arch/x86/traps.c */

asmlinkage int do_page_fault(struct xen_regs *regs) { return -1; } /* from arch/x86/traps.c */

asmlinkage void do_softirq(void) { } /* from common/softirq.c */

asmlinkage int do_spurious_interrupt_bug(struct xen_regs *regs) { return -1; } /* from arch/x86/traps.c */

asmlinkage void fatal_trap(int trapnr, struct xen_regs *regs) { } /* from arch/x86/traps.c */

asmlinkage void io_check_error(struct xen_regs *regs) { } /* from arch/x86/traps.c */

asmlinkage int math_state_restore(struct xen_regs *regs) { return -1; } /* from arch/x86/traps.c */

asmlinkage void mem_parity_error(struct xen_regs *regs) { } /* from arch/x86/traps.c */

unsigned long
search_pre_exception_table(struct xen_regs *regs) { return -1; } /* from arch/x86/extable.c */
/* Stub variables */

#ifndef NR_CPUS
#define NR_CPUS 1
#endif

irq_cpustat_t irq_stat[NR_CPUS]; /* from common/softirq.c */

unsigned long nmi_softirq_reason; /* from arch/x86/traps.c */

char opt_nmi[10] = "ignore"; /* from arch/x86/traps.c */
