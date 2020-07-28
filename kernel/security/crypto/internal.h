/*
 * Cryptographic API.
 *
 * Copyright (c) 2002 James Morris <jmorris@intercode.com.au>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option) 
 * any later version.
 *
 */
#ifndef _CRYPTO_INTERNAL_H
#define _CRYPTO_INTERNAL_H
#include <nexus/defs.h>
#include <asm/errno.h>
#include <asm/softirq.h>
//#include <asm/kmap_types.h>

#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/list.h>
#include <linux/string.h>
#include <asm/page.h>

#include <nexus/user_compat.h>

#include <libtcpa/tcpa.h> // for RAND_bytes
#define rand() ({ int r; RAND_bytes((char *)&r, sizeof(int)); r; })

#endif	/* _CRYPTO_INTERNAL_H */

