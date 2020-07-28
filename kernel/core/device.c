#include <nexus/defs.h>
#include <nexus/machineprimitives.h>
#include <nexus/clock.h>
#include <nexus/synch.h>
#include <nexus/synch-inline.h>
#include <nexus/thread.h>
#include <nexus/device.h>
#include <nexus/queue.h>
#include <nexus/ipd.h>
#include <asm/hw_irq.h>
#include <nexus/mem.h>

#include <nexus/syscalls.h>

#include <nexus/djwilldbg.h>

Queue devices[NUM_DEVICE_TYPES] = { [0 ... NUM_DEVICE_TYPES-1] = QUEUE_EMPTY };

NexusOpenDevice *current_focus[NUM_DEVICE_TYPES] = { [0 ... NUM_DEVICE_TYPES-1] = NULL };

static int in_focus_switch;
static IPD *current_ipd_focus; // warning: this should only be accessed through focus_current_ipd() due to special processing while in focus switch

static void print_device(NexusDevice *nd, char *msg) {
    if (nd->irq != IRQ_NONE) 
	    printk("[device] %s %s [irq %d]\n", msg, nd->name, nd->irq);
    else 
	    printk("[device] %s %s\n", msg, nd->name);
}

static int print_device_f(void *nd, void *msg) {
	print_device((NexusDevice *)nd, msg);
	return 0;
}

static void print_devices_type(int dt, char *name) {
	printk("Available %s devices are:", name);
	if (!queue_gethead(&devices[dt])) printk(" <none>");
	else queue_iterate(&devices[dt], print_device_f, " ");
	printk("\n");
}

void dump_devices(void) {
	print_devices_type(DEVICE_AUDIO, "audio");
	print_devices_type(DEVICE_VIDEO, "video");
	print_devices_type(DEVICE_KEYBOARD, "keyboard");
	print_devices_type(DEVICE_NETWORK, "network");
	print_devices_type(DEVICE_TPM, "tpm");
	print_devices_type(DEVICE_MOUSE, "mouse");
}

NexusDevice *nexus_register_device(int dt, char *name, int irq, void *data,
				   interrupt_handler_t interrupt_handler,
				   focus_handler_t focus_handler,
				   enum nexusdriver_domain domain) {
	NexusDevice *nd;
	
	assert(dt >= 0 && dt < NUM_DEVICE_TYPES);
	
	nd = gcalloc(1, sizeof(NexusDevice));
	nd->type = dt;
	nd->name = name;
	nd->irq = irq;
	nd->data = data;
	nd->domain = domain;
	nd->focus_handler = focus_handler;
	nd->interrupt_handler = interrupt_handler;
	print_device(nd, "Registering ");
	queue_append(&devices[dt], nd);
	if (irq != IRQ_NONE)
		enable_8259A_irq(irq);
	return nd;
}

void nexus_unregister_device(NexusDevice *nd){
  assert(!nexusthread_in_interrupt(nexusthread_self()));
  assert(nd != NULL);
  print_device(nd, "Unregistering ");
  queue_delete(&devices[nd->type], nd);
  gfree(nd);
}

int nexusdevice_is_user(NexusDevice *nd) {
  return nd->domain == DRIVER_USER ? 1 : 0;
}

NexusOpenDevice *nexus_open_device(NexusDevice *nd, void *odata) {
  
	NexusOpenDevice *nod;
	
	nod = gcalloc(1, sizeof(NexusOpenDevice));
	nod->nd = nd;
	nod->odata = odata;
	return nod;
}

static int device_match_name(void *nd, void *name) {
	return !strcmp(((NexusDevice *)nd)->name, (char *)name);
}

NexusDevice *find_device(int dt, char *name) {
	if (!name) {
		return queue_gethead(&devices[dt]);
	} else {
		return queue_find(&devices[dt], device_match_name, name);
	}
}

static void set_focused(int dt, NexusOpenDevice *nod) {
	NexusOpenDevice *prev = current_focus[dt];
	if (prev == nod) return;
	if (prev) {
		if (prev->nd->focus_handler)
			prev->nd->focus_handler(prev, 0);
		prev->focused = 0;
	}
	current_focus[dt] = nod;
	if (nod) {
		nod->focused = 1;
		if (nod->nd->focus_handler)
			nod->nd->focus_handler(nod, 1);
	}
}
  /* currentIPD = d->ipd;
  setCap(d->ipd, d->handle, &d->devstate);
  redraw(d->devstate.screen);
  */

void focus(IPD *ipd) {
	// change focus of all drivers
	// if user opens same type multiple times, don't know what will happen

	// don't let any processes or kernel threads run while we're
	// changing the focus. This is important for safety reasons
	// because memory mappings (e.g. frame buffer) are in flux!

	// This also protects focus change from things like keyboard
	// driver, which will read the focused IPD

	// No IPD is considered focused during processing. This is
	// critical to prevent frame buffer from being mapped in
	swap(&in_focus_switch, 1);

	// any subsequent activation of a frame buffer map will now
	// unmap the frame buffer. If it is currently mapped, the
	// screen focus handler will unmap them
	mb();
	// Synchronize against reads of nod->focus
	int intlevel = disable_intr();
	NexusOpenDevice *nod;
	for (nod = (NexusOpenDevice *)queue_gethead(&ipd->open_devices);
			nod; nod = (NexusOpenDevice *)queue_getnext(nod)) {
		set_focused(nod->nd->type, nod);
	}

	// make sure other devices get unfocused, even if new app does not have it opened
	int dt;
	for (dt = 0; dt < NUM_DEVICE_TYPES; dt++) {
		if (current_focus[dt] && current_focus[dt]->ipd != ipd) {
			set_focused(dt, NULL);
		}
	}
	restore_intr(intlevel);

	mb();
	current_ipd_focus = ipd;
	atomic_clear(&in_focus_switch);
	// Keyboard driver needs ipd focus change after the device
	// handle runs so that the right translation mode is in effect
}

Queue focus_queue = QUEUE_EMPTY;

void set_focus(NexusOpenDevice *nod) {
	set_focused(nod->nd->type, nod);
}

int is_focused(IPD *ipd) {
	return (focus_current_ipd() == ipd);
}

IPD *focus_current_ipd(void) {
	if(!in_focus_switch) {
		return current_ipd_focus;
	} else {
		return NULL;
	}
}

// focus_current_ipd_special() ignores focus switch. It is used for printk()
IPD *focus_current_ipd_special(void) {
	return current_ipd_focus;
}

void focus_next(void *ignored) {
	IPD *ipd = queue_getnext(current_ipd_focus);
	if (!ipd) ipd = queue_gethead(&focus_queue);
	if (!ipd || is_focused(ipd)) return;
	focus(ipd);
}

void focus_prev(void *ignored) {
	IPD *ipd = queue_getprev(current_ipd_focus);
	if (!ipd) {
	  // Go to the tail of the queue
	  IPD *prev;
	  ipd = queue_gethead(&focus_queue);
	  if(ipd == NULL) return;
	  while(ipd != NULL) {
	    prev = ipd;
	    ipd = queue_getnext(ipd);
	  }
	  ipd = prev;
	}
	if (!ipd || is_focused(ipd)) return;
	focus(ipd);
}

void add_focus(IPD *ipd) {
	queue_append(&focus_queue, ipd);
}

// number of times an IRQ has been dispatched and not yet acknowledged. 
static int numdispatch[256]; 

void irq_dispatch(int irq)
{
	assert(check_intr() == 0);
	numdispatch[irq]++;
}

void irq_done(int irq)
{
	int count;
	assert(check_intr() == 0); 

	count = --numdispatch[irq];

	if (count < 0) {
		// HACK. happens for system timer (IRQ 0)
		// not good. XXX investigate
		numdispatch[irq] = 0;
	}

	if (!count)
		enable_8259A_irq(irq);

}

/* return 1 if preempt is needed to handle irq */
int deliver_irq(int irq) {
  NexusDevice *nd;
  int preempt = 0;
  int dt;
  int kernelhandlers = 0;

  assert(check_intr() == 0); 

  for (dt = 0; dt < NUM_DEVICE_TYPES; dt++) {
    for(nd = queue_gethead(&devices[dt]); nd != NULL; nd = queue_getnext(nd)) {	// XXX slow, use lookup table instead
      if(nd->irq == irq) {
	irq_dispatch(irq);
	preempt = (*nd->interrupt_handler)(irq, nd);
	if(nd->domain == DRIVER_KERNEL)
	  kernelhandlers++;

	else
	  ;/* user irq's are ack'ed from top-halves */
	assert(check_intr() == 0); 
      }
    }
  }
  
  /* ack the irq line for each kernel handler */
  int i;
  for(i = 0; i < kernelhandlers; i++)
    irq_done(irq);

  return preempt;
}

