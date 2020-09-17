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

#include "tpm.h"

#define ioport_map(addr, size)	(addr)
#define ioread8					inb
#define iowrite8				outb

/* from old tpm_atmel.h */
#ifdef CONFIG_PPC64
error support for ppc64 has been removed
#else
#define atmel_getb(chip, offset) inb(chip->vendor->base + offset)
#define atmel_putb(val, chip, offset) outb(val, chip->vendor->base + offset)

// NB: this ddrm interface is deprecated and should no longer be needed
//     all calls have been commented out
#define atmel_request_region(start, size, name) \
        Device_nopci_request_region(1, 0, (start), (size))
#define atmel_release_region(start, size) \
        Device_nopci_release_region(1, (start), (size))

/* Atmel definitions */
enum tpm_atmel_addr {
	TPM_ATMEL_BASE_ADDR_LO = 0x08,
	TPM_ATMEL_BASE_ADDR_HI = 0x09
};

/* Verify this is a 1.1 Atmel TPM */
static int atmel_verify_tpm11(void)
{
	/* verify that it is an Atmel part */
	if (tpm_read_index(TPM_ADDR, 0x04) != 'A' ||
	    tpm_read_index(TPM_ADDR, 0x05) != 'T' ||
	    tpm_read_index(TPM_ADDR, 0x06) != 'M' ||
	    tpm_read_index(TPM_ADDR, 0x07) != 'L')
		return 1;

	/* query chip for its version number */
	if (tpm_read_index(TPM_ADDR, 0x00) != 1 ||
	    tpm_read_index(TPM_ADDR, 0x01) != 1)
		return 1;

	/* This is an atmel supported part */
	return 0;
}

static inline void atmel_put_base_addr(struct tpm_vendor_specific *vendor) { }

/* Determine where to talk to device */
static unsigned long atmel_get_base_addr(struct tpm_vendor_specific *vendor)
{
	int lo, hi;

	if (atmel_verify_tpm11() != 0)
		return 0;

	lo = tpm_read_index(TPM_ADDR, TPM_ATMEL_BASE_ADDR_LO);
	hi = tpm_read_index(TPM_ADDR, TPM_ATMEL_BASE_ADDR_HI);

	vendor->base = (hi << 8) | lo;
	vendor->region_size = 2;

	return ioport_map(vendor->base, vendor->region_size);
}
#endif

/* write status bits */
enum tpm_atmel_write_status {
	ATML_STATUS_ABORT = 0x01,
	ATML_STATUS_LASTBYTE = 0x04
};

/* read status bits */
enum tpm_atmel_read_status {
	ATML_STATUS_BUSY = 0x01,
	ATML_STATUS_DATA_AVAIL = 0x02,
	ATML_STATUS_REWRITE = 0x04,
	ATML_STATUS_READY = 0x08
};

static int tpm_atml_recv(struct tpm_chip *chip, u8 *buf, size_t count)
{
	u8 status, *hdr = buf;
	u32 size;
	int i;
	__be32 *native_size;

	/* start reading header */
	if (count < 6)
		return -EIO;

	for (i = 0; i < 6; i++) {
		status = ioread8(chip->vendor->iobase + 1);
		if ((status & ATML_STATUS_DATA_AVAIL) == 0) {
			printf("%s: error reading header\n", chip->dev->name);
			return -EIO;
		}
		*buf++ = ioread8(chip->vendor->iobase);
	}

	/* size of the data received */
	native_size = (__be32 *) (hdr + 2);
	size = be32_to_cpu(*native_size);

	if (count < size) {
		printf("%s: Recv size(%d) less than available space\n",
				chip->dev->name, size);
		for (; i < size; i++) {	/* clear the waiting data anyway */
			status = ioread8(chip->vendor->iobase + 1);
			if ((status & ATML_STATUS_DATA_AVAIL) == 0) {
				printf("%s: error reading data\n", chip->dev->name);
				return -EIO;
			}
		}
		return -EIO;
	}

	/* read all the data available */
	for (; i < size; i++) {
		status = ioread8(chip->vendor->iobase + 1);
		if ((status & ATML_STATUS_DATA_AVAIL) == 0) {
			printf("%s: error reading data\n", chip->dev->name);
			return -EIO;
		}
		*buf++ = ioread8(chip->vendor->iobase);
	}

	/* make sure data available is gone */
	status = ioread8(chip->vendor->iobase + 1);

	if (status & ATML_STATUS_DATA_AVAIL) {
		printf("%s: data available is stuck\n", chip->dev->name);
		return -EIO;
	}

	return size;
}

static int tpm_atml_send(struct tpm_chip *chip, u8 *buf, size_t count)
{
	int i;

	//printf("%s: tpm_atml_send:\n", chip->dev->name);
	for (i = 0; i < count; i++) {
		//printf("%s: %d 0x%x(%d)\n", chip->dev->name, i, buf[i], buf[i]);
 		iowrite8(buf[i], chip->vendor->iobase);
	}

	return count;
}

static void tpm_atml_cancel(struct tpm_chip *chip)
{
	iowrite8(ATML_STATUS_ABORT, chip->vendor->iobase + 1);
}

static u8 tpm_atml_status(struct tpm_chip *chip)
{
	return ioread8(chip->vendor->iobase + 1);
}

static void cleanup_atmel(void);

static struct tpm_vendor_specific tpm_atmel = {
	.recv = tpm_atml_recv,
	.send = tpm_atml_send,
	.cancel = tpm_atml_cancel,
	.status = tpm_atml_status,
	.req_complete_mask = ATML_STATUS_BUSY | ATML_STATUS_DATA_AVAIL,
	.req_complete_val = ATML_STATUS_DATA_AVAIL,
	.req_canceled = ATML_STATUS_READY,
	.name = "atmel",
};

static struct tpm_chip *atmel_chip_present = NULL;

static void atml_plat_remove(struct lpc_dev *dev)
{
	struct tpm_chip *chip = dev->driver_data;
	assert(chip == atmel_chip_present);
	if (chip) {
		//if (chip->vendor->have_region)
		//	atmel_release_region(chip->vendor->base, chip->vendor->region_size);
		atmel_put_base_addr(chip->vendor);
		tpm_remove_hardware(chip);
		atmel_chip_present = NULL;
	}
}

int __init init_atmel(void)
{
	int rc = 0;

    //if (atmel_request_region(TPM_ADDR, 2, "tpm_atmel0"))
    //    return -ENODEV;

	if ((tpm_atmel.iobase = atmel_get_base_addr(&tpm_atmel)) == 0)
		return -ENODEV;

	tpm_atmel.have_region = 
            //!atmel_request_region(tpm_atmel.base, tpm_atmel.region_size,
	    //                          "tpm_atmel0");
	    1;

	if ((rc = tpm_register_hardware("tpm", &tpm_atmel, &atmel_chip_present)) < 0) {
		//if (tpm_atmel.have_region)
		//	atmel_release_region(tpm_atmel.base, tpm_atmel.region_size);
		return rc;
	}

	return 0;
}

static void cleanup_atmel(void)
{
	if (atmel_chip_present)
		atml_plat_remove(atmel_chip_present->dev);
}


MODULE_AUTHOR("Leendert van Doorn (leendert@watson.ibm.com)");
MODULE_DESCRIPTION("TPM Driver");
MODULE_LICENSE("GPL");
