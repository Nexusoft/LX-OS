#ifndef __IOPORT_H__
#define __IOPORT_H__

#include <nexus/ddrm.interface.h>

static inline unsigned char inb(unsigned short port) { 
  unsigned long _v;
  unsigned long vaddr = port & 0xffff;

  ddrm_sys_read(vaddr, 1, &_v);

  return (unsigned char)_v & 0xff; 
} 
static inline unsigned char inb_p(unsigned short port) { 
  assert(0);
}


static inline unsigned short inw(unsigned short port) { 
  unsigned long _v;
  unsigned long vaddr = port & 0xffff;

  ddrm_sys_read(vaddr, 2, &_v);

  return (unsigned short)_v & 0xffff; 
} 
static inline unsigned short inw_p(unsigned short port) { 
  assert(0);
}


static inline unsigned int inl(unsigned short port) { 
  unsigned long _v;
  unsigned long vaddr = port & 0xffff;

  ddrm_sys_read(vaddr, 4, &_v);

  return _v; 
} 
static inline unsigned int inl_p(unsigned short port) { 
  assert(0);
}


static inline void outb(unsigned char value, unsigned short port) {
  unsigned long vaddr = port & 0xffff;
  unsigned long _v = value & 0xff;

  ddrm_sys_write(vaddr, 1, _v);
} 
static inline void outb_p(unsigned char value, unsigned short port) {
  assert(0);
}
static inline void outw(unsigned short value, unsigned short port) {
  unsigned long vaddr = port & 0xffff;
  unsigned long _v = value & 0xffff;

  ddrm_sys_write(vaddr, 2, _v);
} 
static inline void outw_p(unsigned short value, unsigned short port) {
  assert(0);
}
static inline void outl(unsigned int value, unsigned short port) {
  unsigned long vaddr = port & 0xffff;

  ddrm_sys_write(vaddr, 4, value);
} 
static inline void outl_p(unsigned int value, unsigned short port) {
  assert(0);
}

static inline void insb(unsigned short port, void * addr, unsigned long count) {
  assert(0);
}
static inline void insw(unsigned short port, void * addr, unsigned long count) {
  assert(0);
}
static inline void insl(unsigned short port, void * addr, unsigned long count) {
  assert(0);
}

static inline void outsb(unsigned short port, void * addr, unsigned long count) {
  assert(0);
}
static inline void outsw(unsigned short port, void * addr, unsigned long count) {
  assert(0);
}
static inline void outsl(unsigned short port, void * addr, unsigned long count) {
  assert(0);
}


#endif
