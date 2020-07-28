#include <nexus/defs.h>
#include <nexus/galloc.h>
#include <nexus/idtgdt.h>
#include <nexus/clock.h>
#include <nexus/machineprimitives.h>
#include <nexus/mem.h>
#include <nexus/synch.h>
#include <nexus/synch-inline.h>
#include <nexus/thread.h>
#include <nexus/log.h>
#include <nexus/net.h>
#include <nexus/initrd.h>
#include <nexus/ksymbols.h>
#include <nexus/device.h>
#include <nexus/screen.h>
#include <nexus/kbd.h>
#include <nexus/test.h>

#include <nexus/ipc.h>
#include <crypto/aes.h>

#include <nexus/mtrr.h>

#include <nexus/handle.h>
#include <nexus/ddrm.h>

/** if an assertion fails before the screen comes up, set this to true.
    don't panic(), as that just gives a black screen. */
int kernel_init_assert;

struct CommandLineOpt {
  char *command;
  void (*func)(char *);
};

IPD *kernelIPD;

void (*nexus_clear_screen)(void);

extern char *boot_command_line;

extern void enable_regression_tests(char *opt);

extern void set_tsc_const(char *opt);

extern void set_skip_autorun(char *opt);

struct CommandLineOpt command_line_opts[] = {
  { "tscconst", set_tsc_const } ,
  { "skip_autorun", set_skip_autorun } ,
  { "server", set_server } ,
  { "gdb", enable_gdb_mode } ,
  {}	/* last element must be empty */
};

/* paranoid scanner because gpxe returns a commandline with
   unreadable characters (I found out the hard way) */
static void 
parse_commandline(char *cmdline) {
  struct CommandLineOpt * opt;
  char *key = NULL, *value, *ptr;
  int keylen = 0;

  ptr = cmdline;
  do {
    switch(*ptr) {
    case ' ':
    case '\t':
    case '\0':
      // found a singular token (i.e., no key=value pair)
      if (key && !keylen)
      	keylen = ptr - key;

      // found a token
      if (key) {
	opt = command_line_opts;
	while (opt->command) {
	  if (!strncmp(opt->command, key, keylen)) {
	    // match. call handler and exit loop
	    opt->func(value);
	    key = NULL;
	    break;
	  }
	  opt++;
	}
	key = NULL;
      }
      
      break;
    case '=':
      // found a compound token
      value = ptr + 1;
      keylen = ptr - key;
      break;
    default :
      // not yet reading a token? then start
      if (!key)
        key = ptr;
    }

    ptr++;
  } while (*(ptr - 1) != '\0');
}

static void 
nexus_screen_init(void) 
{
  NexusDevice *nd;

  // make new screen for kernel
  nd = find_device(DEVICE_VIDEO, NULL);
  if (!nd) nexuspanic();
  ipd_add_open_device(kernelIPD, screen_init(nd, kernelIPD));
  nexus_clear_screen = ((struct device_video_ops *)nd->data)->clear;

  add_focus(kernelIPD);
  focus(kernelIPD);
}

static void 
nexus_keyboard_init(void) 
{
  NexusDevice *nd;

  keyboard_init();

  // make new keyboard for kernel
  nd = find_device(DEVICE_KEYBOARD, NULL);
  if (!nd) nexuspanic();
  ipd_add_open_device(kernelIPD, kbd_new(nd, kernelIPD));
}

static void
__nexus_init_testvideo(void)
{
#ifndef NDEBUG
	int xx = 109, yy = 207;
	int i, j = 0;

	for (;;) {
		  nexus_blink();
		  xx = xx * 571971 % 13761;
		  yy = yy * 799103 % 41331;
		  fbcon_show_logo(xx, yy);
		  for(i = 0; i < 30000000; ++i) ;
		  if (!(++j % 20)) {
			  //nexus_clear_screen();
			  printk("Still here: %d.\n", j);
		  }
	}
  	nexus_clear_screen();
	printk("[framebuffer] returned\n");
#endif
}

void 
nexus_init(void) 
{
  tsc_per_jiffie = TSCCONST_DEFAULT;

  init_idt();
  //nexus_mem_init(); // happens in arch/i386/kernel/setup.c
  init_gdt();
  pci_init();
  
  // framebuffer init
  if (vesafb_setup("mtrr") != 0) {
    nexus_leds(1);
    nexuspanic();
  }

  if (vesafb_init() != 0){
    nexus_leds(2);
    nexuspanic();
  }
  
  if (fbcon_show_logo(-1, -1) == 0){
    nexus_leds(3);
    nexuspanic();
  }

  // have output as early as possible
  ipd_init();
  nexus_screen_init();
  printk("[framebuffer] initialized\n");

  // execute delayed assertions now that screen is up
  assert(nexus_sse_enabled);
  if (kernel_init_assert) 
	  assert(kernel_init_assert);

  // run basic tests as early as possible
  ipc_init();
  unittest_runall_early();
  nexus_timer_init();
  nexus_keyboard_init();
  nexus_aes_init();

  if (0)
    __nexus_init_testvideo();

  switch_to_final_gdt();
  nexus_aes_init();

  parse_commandline(boot_command_line);
  init_initrd(); 
  ksym_init(); 

  // ipc must happen before syscall_init so that syscall channels are reserved
  syscall_init();

#ifdef __NEXUSXEN__
  xen_init();
#endif

  debug_init();
  nexuslog_init();
  cache_init();
  shell_init();
}

