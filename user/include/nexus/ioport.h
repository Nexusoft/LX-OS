#ifndef __IOPORT_H__
#define __IOPORT_H__

//#include <nexus/Device.interface.h>
#include "../../../common/syscalls/Device.interface.h"

static inline int __unsupported(void)
{
	Debug_printk_msg("unsupported ioport function called\n", 0);
	Thread_Exit(0, 0, 0);
	return 0;
}

static inline unsigned char inb(unsigned short port) { 
  return Device_inb(port);
} 

static inline unsigned short inw(unsigned short port) { 
  return Device_inw(port);
}

static inline unsigned int inl(unsigned short port) { 
  return Device_inl(port);
} 

static inline void outb(unsigned char value, unsigned short port) {
  unsigned long _value = value & 0xff;
  Device_outb(port, _value);
} 

static inline void outw(unsigned short value, unsigned short port) {
  unsigned long _value = value & 0xffff;
  Device_outw(port, _value);
} 

static inline void outl(unsigned int value, unsigned short port) {
  Device_outl(port, value);
}

////////  unsupported variants  ////////

static inline unsigned char inb_p(unsigned short port) { 
	return __unsupported();
}
static inline unsigned short inw_p(unsigned short port) { 
	return __unsupported();
}
static inline unsigned int inl_p(unsigned short port) { 
	return __unsupported();
}

static inline void outb_p(unsigned char value, unsigned short port) {
	__unsupported();
}
static inline void outw_p(unsigned short value, unsigned short port) {
	__unsupported();
}
static inline void outl_p(unsigned int value, unsigned short port) {
	__unsupported();
}

static inline void insb(unsigned short port, void * addr, unsigned long count) {
	__unsupported();
}
static inline void insw(unsigned short port, void * addr, unsigned long count) {
	__unsupported();
}
static inline void insl(unsigned short port, void * addr, unsigned long count) {
	__unsupported();
}

static inline void outsb(unsigned short port, void * addr, unsigned long count) {
	__unsupported();
}
static inline void outsw(unsigned short port, void * addr, unsigned long count) {
	__unsupported();
}
static inline void outsl(unsigned short port, void * addr, unsigned long count) {
	__unsupported();
}

#endif

