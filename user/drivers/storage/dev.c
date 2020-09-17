//
// dev.c
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

#include "dev.h"

struct dev *devtab[MAX_DEVS];
unsigned int num_devs = 0;

struct dev *device(hddev_t devno)
{
  if (devno < 0 || devno >= num_devs) return NULL;
  return devtab[devno];
}

hddev_t dev_make(char *name, struct driver *driver, struct unit *unit, void *privdata)
{
  struct dev *dev;
  hddev_t devno;
  char *p;
  unsigned int n, m;
  int exists;

  if (num_devs == MAX_DEVS) panic("too many devices");

  dev = (struct dev *) malloc(sizeof(struct dev));
  if (!dev) return NODEV;
  memset(dev, 0, sizeof(struct dev));

  strcpy(dev->name, name);
  
  p = dev->name;
  while (p[0] && p[1]) p++;
  if (*p == '#')
  {
    n = 0;
    while (1)
    {
      sprintf(p, "%d", n);
      exists = 0;
      for (m = 0; m < num_devs; m++) 
      {
	if (strcmp(devtab[m]->name, dev->name) == 0) 
	{
	  exists = 1;
	  break;
	}
      }

      if (!exists) break;
      n++;
    }
  }

  dev->driver = driver;
  dev->unit = unit;
  dev->privdata = privdata;
  dev->refcnt = 0;
  dev->mode = 0600;

  switch (dev->driver->type)
  {
    case DEV_TYPE_STREAM: dev->mode |= S_IFCHR; break;
    case DEV_TYPE_BLOCK: dev->mode |= S_IFBLK; break;
    case DEV_TYPE_PACKET: dev->mode |= S_IFPKT; break;
  }

  if (unit) unit->dev = dev;

  devno = num_devs++;
  devtab[devno] = dev;
  
  return devno;
}

hddev_t dev_open(char *name)
{
  hddev_t devno;

  for (devno = 0; devno < num_devs; devno++)
  {
    if (strcmp(devtab[devno]->name, name) == 0)
    {
      devtab[devno]->refcnt++;
      return devno;
    }
  }

  return NODEV;
}

int dev_close(hddev_t devno)
{
  if (devno < 0 || devno >= num_devs) return -ENODEV;
  if (devtab[devno]->refcnt == 0) return -EPERM;
  devtab[devno]->refcnt--;
  return 0;
}

int dev_ioctl(hddev_t devno, int cmd, void *args, size_t size)
{
  struct dev *dev;

  if (devno < 0 || devno >= num_devs) return -ENODEV;
  dev = devtab[devno];
  if (!dev->driver->ioctl) return -ENOSYS;

  return dev->driver->ioctl(dev, cmd, args, size);
}

int dev_read(hddev_t devno, void *buffer, size_t count, blkno_t blkno, int flags)
{
  struct dev *dev;

  if (devno < 0 || devno >= num_devs) return -ENODEV;
  dev = devtab[devno];
  if (!dev->driver->read) return -ENOSYS;

  return dev->driver->read(dev, buffer, count, blkno, flags);
}

int dev_write(hddev_t devno, void *buffer, size_t count, blkno_t blkno, int flags)
{
  struct dev *dev;

  if (devno < 0 || devno >= num_devs) return -ENODEV;
  dev = devtab[devno];
  if (!dev->driver->read) return -ENOSYS;

  return dev->driver->write(dev, buffer, count, blkno, flags);
}

int hddev_transmit(hddev_t devno, struct pbuf *p)
{
  struct dev *dev;

  if (devno < 0 || devno >= num_devs) return -ENODEV;
  dev = devtab[devno];
  if (!dev->driver->transmit) return -ENOSYS;

  return dev->driver->transmit(dev, p);
}

int dev_receive(hddev_t devno, struct pbuf *p)
{
  struct dev *dev;

  if (devno < 0 || devno >= num_devs) return -ENODEV;
  dev = devtab[devno];
  if (!dev->receive) return -ENOSYS;

  return dev->receive(dev->netif, p);
}
