/** NexusOS: Kernel initialization */

#include <nexus/defs.h>
#include <nexus/galloc.h>
#include <nexus/idtgdt.h>
#include <nexus/clock.h>
#include <nexus/machineprimitives.h>
#include <nexus/mem.h>
#include <nexus/synch.h>
#include <nexus/synch-inline.h>
#include <nexus/thread.h>
#include <nexus/net.h>
#include <nexus/initrd.h>
#include <nexus/ksymbols.h>
#include <nexus/device.h>
#include <nexus/screen.h>
#include <nexus/rdtsc.h>
#include <nexus/kbd.h>
#include <nexus/test.h>
#include <nexus/ipc.h>
#include <nexus/mtrr.h>
#include <nexus/handle.h>
#include <asm/hw_irq.h>
#include <nexus/multiboot.h>

/** if an assertion fails before the screen comes up, set this to true.
    don't panic(), as that just gives a black screen. */
int kernel_init_assert;

IPD *kernelIPD;

extern void setup_arch(char **cmdline_p, multiboot_info_t *mbi);
extern void init_IRQ(void);
extern int fbcon_init_late(void);

static void 
nexus_screen_init(void) 
{
  kernelIPD->console = console_new_foreground("kernel log", NULL, 0, 1);
  console_set(kernelIPD->console);
}

asmlinkage void
multiboot_initrd(multiboot_info_t *mbi)
{
	if (CHECK_FLAG(mbi->flags,3)) {
		multiboot_module_t *mod;
		int i;
		unsigned long _initrd_start, _initrd_size;
		for (i = 0, mod = (multiboot_module_t *)mbi->mods_addr;
		     i < mbi->mods_count; i++, mod++) {
			char *modstr = (char *)mod->cmdline;
			if (*modstr == 'i' && 
			    *(modstr+1) == 'n' && 
			    *(modstr+2) == 'i' && 
			    *(modstr+3) == 't' && 
			    *(modstr+4) == 'r' && 
			    *(modstr+5) == 'd' && 
			    *(modstr+6) == '\0') {
                		/* will only be used after paging is enabled */
				_initrd_start = mod->mod_start;
				_initrd_size = (long)(mod->mod_end - mod->mod_start);
                		/* crossed into low mem, need to move to a safer location */
                		if (_initrd_start >= -KERNELVADDR) {
                    			memcpy((void *)INITRD_SAFE_START, (void *)mod->mod_start, _initrd_size);
                    			_initrd_start = INITRD_SAFE_START;
                		}
                		*(unsigned long *)(VIRT_TO_PHYS(&initrd_start)) = PHYS_TO_VIRT(_initrd_start);
                		*(unsigned long *)(VIRT_TO_PHYS(&initrd_size)) = _initrd_size;
				break;
			}
		}
	}
}

asmlinkage void 
nexus_init(multiboot_info_t *mbi) 
{
  setup_arch(NULL, mbi);

  // memory
  init_gdt();
  nexus_mem_init();
  init_idt();

#ifdef ENABLE_KDRIVERS
  pci_init();
#endif

  // framebuffer init as soon as possible: output
  vesafb_setup("mtrr");
  if (vesafb_init())
    nexuspanic();

  // initial estimation of clockrate
  // a real calibration routine is called in shell:init
  nxclock_rate = 3ULL * (1 << 30); 
  nxclock_rate_hz = nxclock_rate / HZ;

  // have output as early as possible
  ipd_init();
  nexus_screen_init();
  fbcon_init_late();	// only prints info (requires screen)
 
  // interrupts
  init_IRQ();
  nxirq_init();
  nxclock_init();
 
  // interrupts
  enable_intr();

  // execute delayed assertions now that screen is up
  assert(!get_preemption());
  init_sse();
  assert(nexus_sse_enabled);
  if (kernel_init_assert)
  	assert(kernel_init_assert);

  // run basic tests as early as possible
  ipc_init();
  unittest_runall_early();

  // XXX: only needed when using LDT (Xen)
  switch_to_final_gdt();

  init_initrd(); 
  ksym_init(); 

  // ipc must happen before syscall_init so that syscall channels are reserved
  syscall_init();

#ifdef __NEXUSXEN__
  // XXX REENABLE: xen_init();
  xen_mem_init();
#endif
 
  nexusthread_init();
  shell_init();
}

