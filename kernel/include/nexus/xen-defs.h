#ifndef _XEN_DEFS_H
#define _XEN_DEFS_H

#define XENCALL_VECTOR	0x81
#include "machineprimitives.h"
#include <xen/arch-x86_32.h>
#include <nexus/thread.h>

#define XEN_MPT_LEN (4 << 20)

#define GUEST_FAULT(IS) (((IS)->cs & 3) != 0)

/*
 * Guest OS must provide its own code selectors, or use the one we provide. The
 * RPL must be 1, as we only create bounce frames to ring 1. Any LDT selector
 * value is okay. Note that checking only the RPL is insufficient: if the
 * selector is poked into an interrupt, trap or call gate then the RPL is
 * ignored when the gate is accessed.
 */
#define GUEST_PL (1)
#define VALID_SEL(_s)                                                      \
    (((((_s)>>3) < FIRST_RESERVED_GDT_ENTRY) ||                            \
      (((_s)>>3) >  LAST_RESERVED_GDT_ENTRY) ||                            \
      ((_s)&4)) &&                                                         \
     (((_s)&3) == GUEST_PL))

#define VALID_CODESEL(_s) ((_s) == KXENCS || VALID_SEL(_s))

static inline unsigned long sel_makeValid(unsigned long sel) {
  Selector s = Selector_from_u32(sel);
  if(s.rpl < GUEST_PL) {
    s.rpl = GUEST_PL;
  }
  return Selector_to_u32(s);
}
static inline unsigned long cs_makeValid(unsigned long sel) {
  return sel_makeValid(sel);
}

int Descriptor_from_Selector(Selector sel, SegmentDescriptor *rv);

void xen_init(void);

struct NexusTrapInfo;
void nexus_xencall(InterruptState *is);
int inXenDomain(void);

void xendom_KTS_free(BasicThread *t, KernelThreadState *uts);

int xendom_setFastTrap(int offset);

int xendom_setExceptionStack(u32 level, u32 ss, u32 esp);
int xendom_setTrapTable(trap_info_t *new_entries);
int xendom_set_iopl(int new_iopl);
int xendom_registerSharedMFN(unsigned int shared_info_mfn);
int xendom_set_VMM_PDIR(int pdoffset, unsigned int *entries, int len);

struct callback_register;
int xendom_registerCallback(struct callback_register *reg);

/* frame_list is a kernel pointer */
void xendom_setupDomainPagetable(void);

// GDT and LDT interfaces are inherently different. LDT is directly
// expressed in terms of virtual addresses (and is expected to change
// with CR3 switch), while GDT is expressed in machine addresses.
int xendom_vGDT_set(unsigned long *frame_list, int entries);
// Convert GDT machine address to the addresses in the copy
SegmentDescriptor *xendom_vGDT_toReal(unsigned long maddr);

int xendom_vLDT_set(unsigned int base_address, int num_entries);
void thread_Xen_vLDT_writeReal(BasicThread *ut);

int xendom_fixup_seg(Selector sel, unsigned long offset);

void Page_Xen_PDIR_init(IPD *ipd, BasicThread *t, Page *p);
// See comment in mem.c for why this function is a bad idea
// int Page_Xen_Type_get_force(IPD *ipd, BasicThread *t, Page *page, int pageType);
int Page_Xen_Type_get(IPD *ipd, BasicThread *t, Page *p, int frame_type);
void Page_Xen_Type_put(IPD *ipd, BasicThread *t, Page *p, int frame_type);

int Page_Xen_Type_pin(IPD *ipd, struct BasicThread *t,
		      Page *page, __u32 pageType);
void Page_Xen_Type_unpin(IPD *ipd, struct BasicThread *t,
			 Page *page, __u32 pageType);

int xendom_vm_assist(unsigned int cmd, unsigned int type);

#define NUM_VIRQS (32)
#define NUM_EVENT_CHANNELS (1024) // 32 * 32
#define EVENT_CHANNEL_ANY (-1)

// 10 ms between Xen periodic timer interrupts
#define XEN_CLOCK_PERIOD (HZ / 100)

// 1 s between clock parameter resynchronization
#define XEN_CLOCK_SYNC_PERIOD (HZ)

// Mask is 1 if the corresponding CR0 bit is saved / restored on context switch
#define XEN_CR0_SWITCH_MASK (X86_CR0_TS)

struct EventChannelState;
enum EventChannelType {
  XEN_EC_UNBOUND,
  XEN_EC_VIRQ,
  XEN_EC_PIRQ,
  XEN_EC_IPI,

  XEN_EC_STORE, // Dummy Xen Store
  XEN_EC_CONSOLE, // Dummy Xen Console

  XEN_EC_RESERVED,
};

struct EventChannelData {
  enum EventChannelType type;
  union {
    struct {
      int virq_num;
    } virq;
  };
};

struct XenHWState;

#define LINUX_SYSCALL_VECTOR (0x80)

int xendom_VIRQ_checkAndBind(int virq_num, int channel_num);

int xendom_setSingleShotTimer(unsigned long expiration);

int xendom_EventChannel_checkAndBind(int channel_num, 
	    EventChannelData data);
int xendom_EventChannel_unbind(int channel_num);

void xendom_sti(void);
void xendom_block(void);

void ipd_Xen_sendVIRQ(IPD *ipd, int virq_num);
void thread_Xen_sendVIRQ(BasicThread *target, int virq_num);
void thread_Xen_setPendingEvent(BasicThread *target, int channel_num);
int xendom_send_virq(int virq_num);

// switchOut is on context switch out of a thread
void thread_Xen_switchOut(BasicThread *target);
// switchIn is on context switch into a thread
void thread_Xen_switchIn(BasicThread *target);
void xendom_fpu_taskswitch(int set);

KernelThreadState *thread_Xen_checkAndGetKTS(BasicThread *t);

int thread_Xen_verifyDomainTablePDE(BasicThread *target, int offset, __u32 val);

enum SpecialProcessing {
  NONE,
  LOAD_DR6,
  LOAD_CR2
};

void pass_to_cpl1_trap(int number, int have_error_code,
		  enum SpecialProcessing special,
		  const char *str, InterruptState *is);

void do_xen_debug(InterruptState *is, unsigned condition);
void do_xen_int3(InterruptState *is);
void do_xen_invalid_op(InterruptState *is);
void do_xen_nm(InterruptState *is);
void do_xen_gpf(InterruptState *is);
void do_xen_pfault(InterruptState *is);
void do_xen_sysenter(InterruptState *is);

#endif // _XEN_DEFS_H
