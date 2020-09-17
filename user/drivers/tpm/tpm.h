/*
 * Copyright (C) 2004 IBM Corporation
 *
 * Authors:
 * Leendert van Doorn <leendert@watson.ibm.com>
 * Dave Safford <safford@watson.ibm.com>
 * Reiner Sailer <sailer@watson.ibm.com>
 * Kylene Hall <kjhall@us.ibm.com>
 *
 * Maintained by: <tpmdd_devel@lists.sourceforge.net>
 *
 * Device driver for TCG/TCPA TPM (trusted platform module).
 * Specifications at www.trustedcomputinggroup.org	 
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 * 
 */

#include <linux/stddef.h>
#include <linux/module.h>
#include <linux/errno.h>
#include <linux/timer.h>
#include <linux/param.h>
#include <linux/types.h>

#include <assert.h>

#include <nexus/sema.h>
#include <nexus/kshmem.h>
#include <nexus/Debug.interface.h>
#include <nexus/Thread.interface.h>
#include <nexus/ioport.h>
#include <nexus/udevice.h>
#include <asm/system.h>

#define __iomem
#define __user
#define __be32 u32
#define jiffies NEXUSTIME
#define IRQ_NONE (-1)

#define V(mutex)   V_nexus(mutex)

#define TPM_BUFSIZE  4096

enum tpm_timeout {
	TPM_TIMEOUT = 5,	/* msecs */
};

/* TPM addresses */
enum tpm_addr {
	TPM_SUPERIO_ADDR = 0x2E,
	TPM_ADDR = 0x4E,
};

struct tpm_chip;

struct tpm_vendor_specific {
	u8 req_complete_mask;
	u8 req_complete_val;
	u8 req_canceled;
	//void __iomem *iobase;		/* ioremapped address */
	unsigned long iobase;		/* ioremapped address */
	unsigned long base;	        /* TPM base address */

	int region_size;
	int have_region;

	int (*recv) (struct tpm_chip *, u8 *, size_t);
	int (*send) (struct tpm_chip *, u8 *, size_t);
	void (*cancel) (struct tpm_chip *);
	u8 (*status) (struct tpm_chip *);
	char name[90];
	//struct attribute_group *attr_group;
};

struct lpc_dev {
	void *driver_data;
	char name[90];
	char vendor[90];
	char description[90];
};

struct tpm_chip {
	struct lpc_dev *dev;

	int dev_num;		/* /dev/tpm# */
	int num_opens;		/* only one allowed */
	int time_expired;

	/* Data passed to and from the tpm via the read/write calls */
	u8 *data_buffer;
	atomic_t data_pending;
	unsigned long data_pending_timeout;	/* user needs to claim result */
	Sema *buffer_mutex;

	Sema *tpm_mutex;	/* tpm is processing */

	struct tpm_vendor_specific *vendor;
};

static inline int tpm_read_index(int base, int index)
{
	outb(index, base);
	return inb(base+1) & 0xFF;
}

static inline void tpm_write_index(int base, int index, int value)
{
	outb(index, base);
	outb(value & 0xFF, base+1);
}

extern int tpm_register_hardware(char *,
				 struct tpm_vendor_specific *, struct tpm_chip **);
extern int tpm_open(void *, void *);
extern int tpm_release(void *, void *);
extern ssize_t tpm_write(void *, const char __user *, size_t,
			 loff_t *);
extern ssize_t tpm_read(void *, char __user *, size_t, loff_t *);
extern void tpm_remove_hardware(struct tpm_chip *);

extern int tpm_init(void);

extern void msec_delay(unsigned int x);

