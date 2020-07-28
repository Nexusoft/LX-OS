/** NexusOS: userlevel device driver definitions */

#ifndef _NEXUS_UNET_H_
#define _NEXUS_UNET_H_

#include <nexus/device.h>
#include <nexus/synch.h>
#include <nexus/ipd.h>
#include <nexus/queue.h>

/* generic structure for user level drivers */
struct udevice {
	Sema *intrsema;
	Sema *intr_mask_sema;
	int intr_mask_value;
	IPD *ipd;
	Map *map;
	int irqcap;
	NexusDevice *dev; // points back to holder
	Sema *startintr;
	int firstintr;
};

/*
 * Kernel-internal state for user level network device driver.
 * Stored in NexusDevice.priv field.
 */
struct net_udevice {
	Sema *intrsema;
	Sema *intr_mask_sema;
	int intr_mask_value;
	IPD *ipd;
	Map *map;
	int irqcap;
	NexusDevice *dev; // points back to holder
	Sema *startintr;
	int firstintr;
	Sema *hard_xmit_sema; // invariant: value is # of kicks + # of packets in xmit queue
	Queue *xmit_queue;
};





extern int pollwaiters;

#endif
