/** NexusOS: support for Linux device drivers. 
    Assortment of both real and stub symbols */

#include <asm/bitops.h>
#include <pthread.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <inttypes.h>

#include <nexus/rdtsc.h>
#include <nexus/sema.h>
#include <nexus/kshmem.h>
#include <nexus/udevice.h>
#include <nexus/x86_emulate.h>
#include <nexus/libc-protos.h>
#include <nexus/djwilldbg.h>
#include <nexus/devicecompat.h>
#include <nexus/interrupt_thread.h>

#include <nexus/Thread.interface.h>
#include <nexus/Console.interface.h>
#include <nexus/Mem.interface.h>
#include <nexus/Debug.interface.h>
#include <nexus/Device.interface.h>

//////// Device pagefault handlers ////////

/* udrivers have a set of these functions that call down to the DDRM */
int x86_emulate_read_Device(enum x86_segment seg,
			  unsigned long vaddr,
			  unsigned long *val,
			  unsigned int bytes,
			  struct x86_emulate_ctxt *ctxt)
{
  *val = Device_mem_read(vaddr, bytes);
  return X86EMUL_CONTINUE;
}

int x86_emulate_write_Device(enum x86_segment seg,
			   unsigned long vaddr,
			   unsigned long val,
			   unsigned int bytes,
			   struct x86_emulate_ctxt *ctxt)
{
  return Device_mem_write(vaddr, bytes, val);
}

//////// Linux device driver support ////////

struct sk_buff;
struct net_device;

int jiffies;
int free_count;

/** Linux kernel equivalent. 

    There are calls to printk everywhere, so a simple
    macro won't catch all. Instead, for userspace drivers
    we export this printk symbol. */
int printk(const char *fmt, ...)
{
	va_list args;
	int ret;

	va_start(args, fmt);
	ret = vprintf(fmt, args);
	va_end(args);

	return ret;
}

/* set up Device calling for page faults */
void pci_enable_pfault_handler(void) 
{
  extern void pf_handler(void *);
  register_pf_handler_read(x86_emulate_read_Device);
  register_pf_handler_write(x86_emulate_write_Device);
 
  /* catch gpf's as well */
  Thread_RegisterTrap(13, pf_handler);
}

/* Linux Call: ask the kernel to forward interrupts @param irq to us. */
int request_irq(unsigned int irq,
                void (*handler)(int, void *, void *),
                unsigned long irqflags,
                const char * devname,
                void *dev_id)
{
  return start_interrupt_thread(irq, handler, dev_id) ? -1 : 0;
}

void *kmalloc(int size, int ignored) 
{
  return malloc(size);
}

void kfree(void *ptr) 
{
  free(ptr);
}

/** Delay for @param usecs. */
void nexus_udelay(unsigned long usecs)
{
  // convention: busy poll if less than 1ms, sleep if more
  if (usecs >= 1000) {
    Thread_USleep(usecs);
  }
  else {
    uint64_t timeout = rdtsc64() + (usecs * (NXCLOCK_RATE / (1000 * 1000)));
    while (rdtsc64() < timeout) {};
  }
}

/** Used by i810 Audio device */
void __udelay(unsigned long usecs)
{
  nexus_udelay(usecs);
}

void msec_delay(unsigned int x) 
{
  //nexus_udelay(x * 1000);
  Thread_USleep(x * 1000);
}

void lock_kernel(void)
{
}

void unlock_kernel(void)
{
}

void down(void *linuxsema)
{
	// XXX: support semaphores
}

void up(void *linuxsema)
{
	// XXX: support semaphores
}

/** Linux call: wait for interrupt handler on other CPU to finish. 
    NOOP on uniprocessor */
void synchronize_irq(void) 
{
}

unsigned int nexuscompat_pci_map_single(void *arg1, void *arg2, int arg3, int arg4)
{
  return Mem_GetPhysicalAddress(arg2, arg3);
}

int get_nexustime(void)
{
	return NEXUSTIME;
}

struct nxcall_args {
	void (*fn)(void *);
	void *arg;
	char *stop;
};

void *nxcall_thread(struct nxcall_args *args)
{
	printf("[dev] background thread up\n");
	while (*args->stop == 0) {
		sleep(1);
		args->fn(args->arg);
	}

	return NULL;
}

// specific hack for the tg3_timer: run it every second
void *nxcall_every_second(void (*fn)(void *), void *arg)
{
	struct nxcall_args *args;
	pthread_t callback;

	args = malloc(sizeof(*args));
	args->fn = fn;
	args->arg = arg;
	args->stop = calloc(1, 1);

	pthread_create(&callback, NULL, nxcall_thread, args);
	return args;
}

void nxcall_stop(struct nxcall_args *args)
{
	*args->stop = 1;
	// memleak
}

// user version of kernel:clock.c function
void *register_alarm(int atime, void (*func)(void *arg), void *arg)
{
	printf("NXDEBUG: %s not implemented\n", __FUNCTION__);
	return NULL;
}

void update_alarm(void *arg, int new_atime)
{
	printf("NXDEBUG: %s not implemented\n", __FUNCTION__);
}

// user version of kernel:clock.c function
int deregister_alarm(void *arg)
{
	printf("NXDEBUG: %s not implemented\n", __FUNCTION__);
	return -1;
}

/** Linux call: modify the wakeup time of an existing timer.
    WARNING: timer mod is not implemented for udevs. XXX: fix */ 
void mod_timer(void (*func)(void), int absolutetime) 
{
}

void assert2(int val) 
{ 
	if (!val) { 
		printk("assertion failed at %s.%d. Aborting\n", __FUNCTION__, __LINE__); 
		abort(); 
	}
}

/* anything below this line is an unimplemented stub */
void do_softirq(void) { };
int min(int a, int b){return (a < b)?a:b;}
int out_of_line_bug(int line) { printk("out_of_line_bug\n"); return 0; }
int del_timer_sync(void) { printk("del_timer_sync\n"); return 0; }
int free_irq(void) { printk("free_irq\n"); return 0; }
int iounmap(void) { printk("iounmap\n"); return 0; }
int irq_stat(void) { printk("irq_stat\n"); return 0; }
int mem_map(void) { printk("mem_map\n"); return 0; }
int __netdev_watchdog_up(void) { printk("__netdev_watchdog_up\n"); return 0; }
int netif_rx(void) { printk("netif_receive_skb\n"); return 0; }
int netif_receive_skb(void) { printk("netif_receive_skb\n"); return 0; }
int pci_clear_mwi(void) { printk("pci_clear_mwi\n"); return 0; }
int pci_dev_driver(void) { printk("pci_dev_driver\n"); return 0; }
int pci_devices(void) { printk("pci_devices\n"); return 0; }
int pci_enable_wake(void) { printk("pci_enable_wake\n"); return 0; }
int pci_free_consistent(void) { printk("pci_free_consistent\n"); return 0; }
int pci_restore_state(void) { printk("pci_restore_state\n"); return 0; }
int pci_save_state(void) { printk("pci_save_state\n"); return 0; }
int pci_set_mwi(void) { printk("pci_set_mwi\n"); return 0; }
int pci_set_power_state(void) { printk("pci_set_power_state\n"); return 0; }
int pci_unregister_driver(void) { printk("pci_unregister_driver\n"); return 0; }
int schedule_timeout(void) { return 0; }
void cpu_raise_softirq(unsigned int a, unsigned int b){assert2(0);};
int __generic_copy_from_user(void){assert2(0);return -1;}
int __generic_copy_to_user(void){assert2(0);return -1;}
int __get_user_4(void){assert2(0);return -1;}
int prefetch(void){assert2(0);return -1;};
int __out_of_line_bug(void){assert2(0); return -1;};
int register_reboot_notifier(void) { return 0; }
int unregister_reboot_notifier(void){assert2(0);return -1;}
int __constant_htons(void){assert2(0);return -1;}
void skb_over_panic(struct sk_buff *skb, int len, void *here) { nx_udriver_panic(__FUNCTION__); }
void skb_under_panic(struct sk_buff *skb, int len, void *here) { nx_udriver_panic(__FUNCTION__); }

