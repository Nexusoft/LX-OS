/** NexusOS: keyboard and mouse driver */

#include <stdio.h>

#include <nexus/sema.h>

int keyboard_init(void);
int psaux_init(void);

static void
int_handler(int irq, void *device, void *unused)
{
	handle_kbd_event();
}

int
main(int argc, char **argv)
{
	// register IRQ
	start_interrupt_thread(1  /* keyboard */ , int_handler, NULL);
	start_interrupt_thread(12 /* mouse (aux) */ , int_handler, NULL);
	
	// initialize hardware
	keyboard_init();
	psaux_init();

	while (1)
		sleep(3600);

	return 0;
}

