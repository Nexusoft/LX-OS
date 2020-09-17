/** NexusOS: kernel shell (or what remains thereof) */

#include <linux/config.h>
#include <linux/ctype.h>
#include <asm/delay.h>
#include <linux/pci.h>
#include <asm/hw_irq.h>
#include <asm/io.h>
#include <asm/param.h>
#include <asm/msr.h>

#include <nexus/defs.h>
#include <nexus/queue.h>
#include <nexus/thread.h>
#include <nexus/thread-private.h>
#include <nexus/synch.h>
#include <nexus/synch-inline.h>
#include <nexus/clock.h>
#include <nexus/mem.h>
#include <nexus/guard.h>
#include <nexus/mem-private.h>	
#include <nexus/machineprimitives.h>
#include <nexus/net.h>
#include <nexus/idtgdt.h>
#include <nexus/device.h>
#include <nexus/ipd.h>
#include <nexus/service.h>
#include <nexus/util.h>
#include <nexus/kbd.h>
#include <nexus/kernelfs.h>
#include <nexus/initrd.h>
#include <nexus/ksymbols.h>
#include <nexus/regression.h>
#include <nexus/mtrr.h>
#include <nexus/handle.h>
#include <nexus/ipc_private.h>
#include <nexus/hashtable.h>
#include <nexus/test.h>
#include <nexus/elf.h>

struct kcommand {
  char *str;
  int (*func)(int argc, char **argv);
};

static struct kcommand kcommands[];


////////  kernel commands  ////////

int 
shell_help(int ac, char **av) 
{

	struct kcommand *cur;

	printk_current("kernel commands:\n");
	for (cur = kcommands; cur->str; cur++) 
		printk_current("%s\n", cur->str);
	return 0;
}

int
shell_meminfo(int ac, char **av)
{
	dump_page_utilization();
	return 0;
}

int
shell_toggle_log(int ac, char **av)
{
	extern int nxguard_log_enable;

	nxguard_log_enable = (nxguard_log_enable + 1) & 0x1;
	printk_green("<F4> %sabled kguard logging\n", 
		     nxguard_log_enable ? "en" : "dis");
	return 0;
}

int 
shell_reboot(int ac, char **av) 
{
	printk_red("Rebooting."); 
	machine_restart();
	return 0;
}

int 
shell_ps(int ac, char **av) 
{
  int __print_ipd(int i, IPD *ipd, void *ignore)
  {
    printk_current("[%d] %s\n", i, ipd->name);
    return 0;
  }

  ipd_iterate(__print_ipd, NULL);
  return 0;
}

int 
shell_top(int ac, char **av) 
{
  // v-- a race, but not important here
  nexusthread_account_show = (nexusthread_account_show + 1) & 0x1;
  return 0;
}

int
shell_stats(int ac, char **argv)
{
  extern int guard_collisions;
  extern int guard_upcalls_refmon;
  extern int guard_upcalls_guard;
  extern int guard_calls;

  printk_current("[kernel] statistics\n\n");
  
  printk("guard");
  printk_current("  %20s %d\n",   "calls", guard_calls);
  printk_current("  %20s %d\n",   "upcalls (refmon)", guard_upcalls_refmon);
  printk_current("  %20s %d\n",   "upcalls (guard)", guard_upcalls_guard);
  printk_current("  %20s %d\n", "collisions", guard_collisions);
  return 0;
}

int 
shell_kill(int ac, char **av) 
{
	IPD *ipd;
	
	if (ac < 2) {
		printk_red("expects ipd id\n");
		return 1;
	}

	ipd = ipd_find(atoi(av[1]));
	if (!ipd) {
		printk_red("no such process %s\n", av[1]);
		return 1;
	}

	ipd_kill(ipd);
	return 0;
}

int 
shell_unittest(int argc, char **argv) 
{
	unittest_runall_early();
	
	// disabled, because test_paged_ipc may not run in user context 
	// (i.e., current process != kernelIPD)
	// this is true of all kernel code that accesses the kernel heap
	//
	//unittest_runall_late();
	unittest_runall_user();
	return 0;
}

int 
shell_ifconfig(int ac, char **av) 
{
	printk_current(
	       "host mac:       %02hx.%02hx.%02hx.%02hx.%02hx.%02hx\n"
	       "host ip:        %hu.%hu.%hu.%hu\n"
	       "netmask:        %hu.%hu.%hu.%hu\n"
	       "gateway ip:     %hu.%hu.%hu.%hu\n" 
	       "packets:	%u\n",
	       default_mac_address[0] & 0xff, default_mac_address[1] & 0xff, 
	       default_mac_address[2] & 0xff, default_mac_address[3] & 0xff, 
	       default_mac_address[4] & 0xff, default_mac_address[5] & 0xff,
	       (my_ipaddress >> 0)  & 0xff, (my_ipaddress >>  8) & 0xff,
	       (my_ipaddress >> 16) & 0xff, (my_ipaddress >> 24) & 0xff,
	       (my_netmask >> 0)    & 0xff, (my_netmask >>  8) & 0xff,
	       (my_netmask >> 16)   & 0xff, (my_netmask >> 24) & 0xff,
	       (my_gateway >> 0)    & 0xff, (my_gateway >>  8) & 0xff,
	       (my_gateway >> 16)   & 0xff, (my_gateway >> 24) & 0xff,
	       switch_packetcount);
	return 0;
}

/** Test system clock calibration */
int 
shell_sysclock(int ac, char **av) 
{
	struct nxtimeval tv;
	unsigned long cur, end;
	int i;

	// print environment variables
	printk_current("tickrate  = %d\n", HZ);
	printk_current("clockrate = %llu (estimated)\n", nxclock_rate);
	assert(nxclock_rate / HZ == nxclock_rate_hz);	// overflow: fails on 8+GHZ

	// measure rate again
	for (i = 0; i < 10; i++) {
	  unsigned long khz = nxclock_calibrate();
	  printk_current("measured clockrate = %lu Mhz\n", khz >> 10);
	}

	// allow user to see tickrate
	cur = nexustime;
	end = cur + 5;
	printk_current("polling for ticks..\n");
	do {
		if (nexustime > cur) {
			printk_current(" ping!\n");
			cur = nexustime;
		}
	} while (cur < end);

	for (i = 0; i < 10; i++) {
		gettimeofday(&tv);
		printk_current("gettimeofday %lu.%lu\n", tv.tv_sec, tv.tv_usec);
	}

	return 0;
}

#ifndef DONT_DO_DEBUG_HACKS

#include <nexus/device.h>

#define IRQ_DUMMYDRV 	3
#define IRQ_MAX 	10000
static Sema sema_int = SEMA_INIT_KILLABLE;

int
dummydrv_inthandler(void *unused)
{
	V(&sema_int);
	return 0;
}

/** Measure interrupt throughput */
int
shell_dummydrv(int ac, char **av)
{
	uint64_t tdiff;
	int i;

	nxirq_get(IRQ_DUMMYDRV, dummydrv_inthandler, NULL);
	
	tdiff = rdtsc64();
	for (i = 0; i < IRQ_MAX; i++) {
		asm("int $0x23");
		P(&sema_int);
	}
	tdiff =  rdtsc64() - tdiff;
	tdiff /= IRQ_MAX;
	
	printk_current("[dummy] %d interrupts. %lld cycles/int\n", IRQ_MAX, tdiff);
	return 0;
}

int hackmode;
int
shell_hack(int ac, char **av)
{
	swap(&hackmode, 1);
	printk_red("[os] hack mode ENABLED\n");
	return 0;
}

#endif

extern int shell_netopen(int ac, char **av);

//////// list all commands for automatic calling from Debug_KCommand ////////

static struct kcommand kcommands[] = {
	{ "hack",	shell_hack },
	{ "help",	shell_help },
	{ "ifconfig",	shell_ifconfig },
	{ "kill",	shell_kill },
	{ "knetdev",	shell_netopen },
	{ "ps",		shell_ps },
	{ "top",	shell_top },
	{ "stats",	shell_stats },
	{ "reboot",	shell_reboot },
	{ "sysclock",	shell_sysclock },
	{ "unittest",	shell_unittest },
	{ "meminfo",	shell_meminfo },
	{ "log",	shell_toggle_log },
	{ "dummy",	shell_dummydrv },
	{ NULL, NULL } 
};

/** Execute a kernel command. 
    Clearly a privileged instruction:
    callers are trusted to supply safe arguments */
int
nxshell_execute(int argc, char **argv) 
{
	struct kcommand * cur;

	if (argc < 1)
		printk_red("insufficient arguments\n");

	for (cur = kcommands; cur->str; cur++)
		if (!strcmp(argv[0], cur->str))
			return cur->func(argc, argv);

	return 1;
}


////////  initialization  ////////

int 
shell_init(void) 
{
	extern const char * nxversion(void);
	char *shell_argv[] = { "explorer.app" /* NB: from initrd: no /bin */ , 
			       "bin/initscript", 
			       NULL };
 	struct nxconsole *console;
	unsigned long long clockrate;

	// initialize subsystems that depend on working threads
	kbd_start();
	kernelfs_init(); 
	nxnet_switch_init();
  	nxkguard_init();
	console_set(kernelIPD->console);

  	// calibrate CPU
  	clockrate = nxclock_calibrate() * 1000;
  	assert(clockrate);
	nxclock_rate = clockrate;
	nxclock_rate_hz = nxclock_rate / HZ;
	printk_current("detected %lluMhz CPU. %dHZ ticks\n", nxclock_rate >> 20, HZ);

	// run late self tests
#ifndef NDEBUG
	printk("executing unittests. Please wait\n");
	unittest_runall_late();
	//unittest_runall_user();
#endif

	// start initial shell
	// NB: version is only updated when the kernel is rebuilt.
	//     it may be the same for different versions of userspace 
	printk_green("[kernel] up. version %s\n"
	             "[kernel] showing log\n", nxversion());

	// disable input on kernel console
	// XXX support proper closing of virtual devices
	console_active->keyboard = NULL;

	while (1) {
		// create separate console for init process
		console = console_new_foreground(shell_argv[0], NULL, 1, 1);
		console_set(console);

		if (elf_exec(shell_argv[0], PROCESS_WAIT, 2, shell_argv) == -1) {
			printk_red("[shell] init process failed\n");
			nexuspanic();
		}

		printk("[kernel] init died. restarted\n");
		shell_argv[1] = NULL; // do not reexecute initscript
	}

	return 0;
}


