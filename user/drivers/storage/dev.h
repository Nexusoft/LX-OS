//
// dev.h
//
// Device Manager
//
// Copyright (C) 2002 Michael Ringgaard. All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions
// are met:
// 
// 1. Redistributions of source code must retain the above copyright 
//    notice, this list of conditions and the following disclaimer.  
// 2. Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the distribution.  
// 3. Neither the name of the project nor the names of its contributors
//    may be used to endorse or promote products derived from this software
//    without specific prior written permission. 
// 
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
// ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
// OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
// HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
// LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
// OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF 
// SUCH DAMAGE.
// 

#ifndef DEV_H
#define DEV_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#define S_IFPKT 0160000
#define S_IFBLK 0060000
#define S_IFCHR 0020000

#define panic(msg) do { printf("ABORTING: %s\n", msg); exit(1); } while (0);

#define NODEV (-1)

#define DEVNAMELEN              32
#define MAX_DEVS                64

#define DEV_TYPE_STREAM		1
#define DEV_TYPE_BLOCK		2
#define DEV_TYPE_PACKET		3

#define DEVFLAG_NBIO            1

#define IOCTL_GETBLKSIZE        1
#define IOCTL_GETDEVSIZE        2
#define IOCTL_GETGEOMETRY       3
#define IOCTL_REVALIDATE        4

#define RESOURCE_IO	        1
#define RESOURCE_MEM	        2
#define RESOURCE_IRQ	        3
#define RESOURCE_DMA	        4

#define BUSTYPE_HOST            0
#define BUSTYPE_PCI             1
#define BUSTYPE_ISA             2

#define BIND_BY_CLASSCODE       1
#define BIND_BY_UNITCODE        2

typedef unsigned int hddev_t;
typedef unsigned int blkno_t;

struct devfile;

struct dev;
struct bus;
struct unit;

//
// Bus
//

struct bus
{
  struct bus *next;
  struct bus *sibling;
  struct bus *parent;

  struct unit *self;

  unsigned long bustype;
  unsigned long busno;

  struct unit *units;
  struct bus *bridges;
};

//
// Unit
//

struct unit
{
  struct unit *next;
  struct unit *sibling;
  struct bus *bus;
  struct dev *dev;

  unsigned long classcode;
  unsigned long unitcode;
  unsigned long subunitcode;
  unsigned long revision;
  unsigned long unitno;

  char *classname;
  char *vendorname;
  char *productname;

  struct resource *resources;
};

//
// Resource
//

struct resource
{
  struct resource *next;
  unsigned short type;
  unsigned short flags;
  unsigned long start;
  unsigned long len;
};

//
// Driver
//

struct driver
{
  char *name;
  int type;

  int (*ioctl)(struct dev *dev, int cmd, void *args, size_t size);
  int (*read)(struct dev *dev, void *buffer, size_t count, blkno_t blkno, int flags);
  int (*write)(struct dev *dev, void *buffer, size_t count, blkno_t blkno, int flags);

  int (*attach)(struct dev *dev, struct eth_addr *hwaddr);
  int (*detach)(struct dev *dev);
  int (*transmit)(struct dev *dev, struct pbuf *p);
  int (*set_rx_mode)(struct dev *dev);
};

//
// Device
//

struct dev 
{
  char name[DEVNAMELEN];
  struct driver *driver;
  struct unit *unit;
  void *privdata;
  int refcnt;
  uid_t uid;
  gid_t gid;
  int mode;
  struct devfile *files;

  struct netif *netif;
  int (*receive)(struct netif *netif, struct pbuf *p);
};

//
// Geometry
//

struct geometry
{
  int cyls;
  int heads;
  int spt;
  int sectorsize;
  int sectors;
};

extern struct dev *devtab[];
extern unsigned int num_devs;

struct dev *device(hddev_t devno);

hddev_t dev_make(char *name, struct driver *driver, struct unit *unit, void *privdata);
hddev_t dev_open(char *name);
int dev_close(hddev_t devno);

int dev_ioctl(hddev_t devno, int cmd, void *args, size_t size);
int dev_read(hddev_t devno, void *buffer, size_t count, blkno_t blkno, int flags);
int dev_write(hddev_t devno, void *buffer, size_t count, blkno_t blkno, int flags);

#endif
