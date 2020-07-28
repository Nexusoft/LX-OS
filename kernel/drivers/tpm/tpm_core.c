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
 * Note, the TPM chip is not interrupt driven (only polling)
 * and can have very long timeouts (minutes!). Hence the unusual
 * calls to msleep.
 *
 * KW: Modified for Nexus.
 *
 */

//#include <linux/sched.h>
//#include <linux/poll.h>
//#include <linux/spinlock.h>
#include "tpm.h"

#define TPM_BUFSIZE 2048

static struct tpm_chip *tpm_chip_present = NULL; 
static spinlock_t driver_lock = SPIN_LOCK_UNLOCKED;

/*
 * Internal kernel interface to transmit TPM commands
 */
static ssize_t tpm_transmit(struct tpm_chip *chip, const char *buf,
			    size_t bufsiz)
{
	ssize_t rc;
	u32 count;
	unsigned long stop;

	count = be32_to_cpu(*((__u32 *) (buf + 2)));

	if (count == 0)
		return -ENODATA;
	if (count > bufsiz) {
		printk("%s: invalid count value %x %zx \n",
				chip->dev->name, count, bufsiz);
		return -E2BIG;
	}

	P(chip->tpm_mutex);

	if ((rc = chip->vendor->send(chip, (u8 *) buf, count)) < 0) {
		printk("%s: tpm_transmit: tpm_send: error %zd\n",
				chip->dev->name, rc);
		goto out;
	}

	stop = jiffies + 2 * 60 * HZ;
	do {
		u8 status = chip->vendor->status(chip);
		if ((status & chip->vendor->req_complete_mask) ==
		    chip->vendor->req_complete_val) {
			goto out_recv;
		}

		if ((status == chip->vendor->req_canceled)) {
			printk("%s: Operation Canceled\n", chip->dev->name);
			rc = -ECANCELED;
			goto out;
		}

		nexusthread_sleep(TPM_TIMEOUT);	/* CHECK */
		rmb();
	} while (time_before(jiffies, stop));


	chip->vendor->cancel(chip);
	printk("%s: Operation Timed Out\n", chip->dev->name);
	rc = -ETIME;
	goto out;

out_recv:
	rc = chip->vendor->recv(chip, (u8 *) buf, bufsiz);
	if (rc < 0)
		printk("%s: tpm_recv: error %zd\n", chip->dev->name, rc);
out:
	V(chip->tpm_mutex);
	return rc;
}


struct tpm_chip *tpm_find_chip(void *inode, void *file)
{
	return tpm_chip_present;
}

/*
 * Device file system interface to the TPM
 */
int tpm_open(void *inode, void *file)
{
	int rc = 0;
	struct tpm_chip *chip;

	spin_lock(&driver_lock);

	chip = tpm_find_chip(inode, file);

	if (chip == NULL) {
		rc = -ENODEV;
		goto err_out;
	}

	if (chip->num_opens) {
		printk("%s: Another process owns this TPM\n", chip->dev->name);
		rc = -EBUSY;
		goto err_out;
	}

	chip->num_opens++;

	spin_unlock(&driver_lock);

	chip->data_buffer = galloc(TPM_BUFSIZE * sizeof(u8));
	if (chip->data_buffer == NULL) {
		chip->num_opens--;
		return -ENOMEM;
	}

	atomic_set(&chip->data_pending, 0);

	return 0;

err_out:
	spin_unlock(&driver_lock);
	return rc;
}

int tpm_release(void *inode, void *file)
{
	struct tpm_chip *chip = tpm_find_chip(inode, file);

	spin_lock(&driver_lock);
	chip->num_opens--;
	P(chip->buffer_mutex);
	atomic_set(&chip->data_pending, 0);
	V(chip->buffer_mutex);
	gfree(chip->data_buffer);
	spin_unlock(&driver_lock);
	return 0;
}

ssize_t tpm_write(void *file, const char __user *buf,
		  size_t size, loff_t * off)
{
	struct tpm_chip *chip = tpm_find_chip(NULL, file);
	int in_size = size, out_size;

	/* cannot perform a write until the read has cleared
	   either via tpm_read or a user_read_timer timeout */
	while (atomic_read(&chip->data_pending) != 0) {
		if (jiffies >= chip->data_pending_timeout) {
			P(chip->buffer_mutex);
			atomic_set(&chip->data_pending, 0);
			memset(chip->data_buffer, 0, TPM_BUFSIZE);
			V(chip->buffer_mutex);
		}
		nexusthread_sleep(TPM_TIMEOUT);
	}

	P(chip->buffer_mutex);

	if (in_size > TPM_BUFSIZE)
		in_size = TPM_BUFSIZE;

	/* if (copy_from_user
	    (chip->data_buffer, (void __user *) buf, in_size)) {
		up(&chip->buffer_mutex);
		return -EFAULT;
	} */
	memcpy(chip->data_buffer, buf, in_size);

	/* atomic tpm command send and result receive */
	out_size = tpm_transmit(chip, chip->data_buffer, TPM_BUFSIZE);

	atomic_set(&chip->data_pending, out_size);
	chip->data_pending_timeout = jiffies + (60 * HZ);
	V(chip->buffer_mutex);

	return in_size;
}


ssize_t tpm_read(void * file, char __user *buf,
		 size_t size, loff_t * off)
{
	struct tpm_chip *chip = tpm_find_chip(NULL, file);
	int ret_size;

	P(chip->buffer_mutex);
	ret_size = atomic_read(&chip->data_pending);
	atomic_set(&chip->data_pending, 0);
	if (ret_size > 0) {	/* relay data */
		if (size < ret_size)
			ret_size = size;
		/* if (copy_to_user(buf, chip->data_buffer, ret_size))
			ret_size = -EFAULT; */
		memcpy(buf, chip->data_buffer, ret_size);
	}
	V(chip->buffer_mutex);

	return ret_size;
}

void tpm_remove_hardware(struct tpm_chip *chip)
{
	if (chip == NULL) {
		printk("%s: No device data found\n", chip->dev->name);
		return;
	}

	nexus_unregister_device(chip->ndev);

	spin_lock(&driver_lock);
	assert(tpm_chip_present == chip);
	tpm_chip_present = NULL;
	chip->dev->driver_data = NULL;
	if (chip->num_opens > 0) {
		P(chip->buffer_mutex);
		atomic_set(&chip->data_pending, 0);
		gfree(chip->data_buffer);
		V(chip->buffer_mutex);
	}
	spin_unlock(&driver_lock);

	sema_destroy(chip->buffer_mutex);
	sema_destroy(chip->tpm_mutex);
	gfree(chip);
}

/*
 * Called from tpm_<specific>.c probe function only for devices 
 * the driver has determined it should claim.  If needed, prior to calling
 * this function the specific probe function must call pci_enable_device.
 * Upon errant exit from this function specific probe function should call
 * pci_disable_device.
 */
int tpm_register_hardware(char *desc, struct tpm_vendor_specific *vendor, struct tpm_chip **created)
{
	struct lpc_dev *dev;
	struct tpm_chip *chip;

	if (tpm_chip_present != NULL) {
		printk("(%s %s): No available tpm device numbers\n", vendor->name, desc);
		return -ENODEV;
	}

	/* LPC device */
	dev = galloc(sizeof(*dev));
	if (dev == NULL)
		return -ENOMEM;
	memset(dev, 0, sizeof(*dev));
	strncpy(dev->vendor, vendor->name, sizeof(dev->vendor));
	strncpy(dev->description, desc, sizeof(dev->description));
	dev->devops = &vendor->ops;

	/* Driver specific per-device data */
	chip = galloc(sizeof(*chip));
	if (chip == NULL) {
		gfree(dev);
		return -ENOMEM;
	}
	memset(chip, 0, sizeof(*chip));
	chip->dev = dev;

	chip->buffer_mutex = sema_new_mutex();
	chip->tpm_mutex = sema_new_mutex();

	chip->vendor = vendor;
	chip->dev_num = 0;
	snprintf(dev->name, sizeof(dev->name), "%s%d", "tpm", chip->dev_num);

	spin_lock(&driver_lock);
	dev->driver_data = chip;
	assert(tpm_chip_present == NULL);
	tpm_chip_present = chip;
	spin_unlock(&driver_lock);

	chip->ndev = nexus_register_device(DEVICE_TPM, dev->name, IRQ_NONE, 
					   dev->devops, NULL, NULL,
					   DRIVER_KERNEL);

	*created = chip;
	printk("%s: %s %s chip detected\n",
		chip->dev->name,
		chip->dev->vendor,
		chip->dev->description);

	return 0;
}

MODULE_AUTHOR("Leendert van Doorn (leendert@watson.ibm.com)");
MODULE_DESCRIPTION("TPM Driver");
MODULE_LICENSE("GPL");
