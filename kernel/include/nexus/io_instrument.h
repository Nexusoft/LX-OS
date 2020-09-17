/** NexusOS: replacements for original calls in asm/io.h */

#ifndef NEXUS_KERN_IO_H
#define NEXUS_KERN_IO_H

static inline unsigned char inb(unsigned short port) { 
  unsigned char _v;
  __asm__ __volatile__ ("in" "b" " %" "w" "1,%" "" "0" : "=a" (_v) : "Nd" (port) ); 
  return _v; 
}

static inline unsigned char inb_p(unsigned short port) { 
  unsigned char _v;
  __asm__ __volatile__ ("in" "b" " %" "w" "1,%" "" "0" "\noutb %%al,$0x80" : "=a" (_v) : "Nd" (port) ); 
  return _v; 
}

static inline unsigned short inw(unsigned short port) { 
  unsigned short _v; 
  __asm__ __volatile__ ("in" "w" " %" "w" "1,%" "" "0" : "=a" (_v) : "Nd" (port) );
  return _v;
}

static inline unsigned short inw_p(unsigned short port) { 
  unsigned short _v;
  __asm__ __volatile__ ("in" "w" " %" "w" "1,%" "" "0" "\noutb %%al,$0x80" : "=a" (_v) : "Nd" (port) );
  return _v;
}

static inline unsigned int inl(unsigned short port) { 
  unsigned int _v;
  __asm__ __volatile__ ("in" "l" " %" "w" "1,%" "" "0" : "=a" (_v) : "Nd" (port) );
  return _v;
}

static inline unsigned int inl_p(unsigned short port) { 
  unsigned int _v;
  __asm__ __volatile__ ("in" "l" " %" "w" "1,%" "" "0" "\noutb %%al,$0x80" : "=a" (_v) : "Nd" (port) );
  return _v;
}


static inline void outb(unsigned char value, unsigned short port) {
  __asm__ __volatile__ ("out" "b" " %" "b" "0,%" "w" "1" : : "a" (value), "Nd" (port));
}

static inline void outb_p(unsigned char value, unsigned short port) {
  __asm__ __volatile__ ("out" "b" " %" "b" "0,%" "w" "1" "\noutb %%al,$0x80" : : "a" (value), "Nd" (port));
}

static inline void outw(unsigned short value, unsigned short port) {
  __asm__ __volatile__ ("out" "w" " %" "w" "0,%" "w" "1" : : "a" (value), "Nd" (port));
}

static inline void outw_p(unsigned short value, unsigned short port) {
  __asm__ __volatile__ ("out" "w" " %" "w" "0,%" "w" "1" "\noutb %%al,$0x80" : : "a" (value), "Nd" (port));
}

static inline void outl(unsigned int value, unsigned short port) {
  __asm__ __volatile__ ("out" "l" " %" "0,%" "w" "1" : : "a" (value), "Nd" (port));
} 

static inline void outl_p(unsigned int value, unsigned short port) {
  __asm__ __volatile__ ("out" "l" " %" "0,%" "w" "1" "\noutb %%al,$0x80" : : "a" (value), "Nd" (port));
}

static inline void insb(unsigned short port, void * addr, unsigned long count) {
  __asm__ __volatile__ ("rep ; ins" "b" : "=D" (addr), "=c" (count) : "d" (port),"0" (addr),"1" (count));
}

static inline void insw(unsigned short port, void * addr, unsigned long count) {
  __asm__ __volatile__ ("rep ; ins" "w" : "=D" (addr), "=c" (count) : "d" (port),"0" (addr),"1" (count));
}

static inline void insl(unsigned short port, void * addr, unsigned long count) {
  __asm__ __volatile__ ("rep ; ins" "l" : "=D" (addr), "=c" (count) : "d" (port),"0" (addr),"1" (count));
}

static inline void outsb(unsigned short port, void * addr, unsigned long count) {
  __asm__ __volatile__ ("rep ; outs" "b" : "=S" (addr), "=c" (count) : "d" (port),"0" (addr),"1" (count));
}

static inline void outsw(unsigned short port, void * addr, unsigned long count) {
  __asm__ __volatile__ ("rep ; outs" "w" : "=S" (addr), "=c" (count) : "d" (port),"0" (addr),"1" (count));
}
static inline void outsl(unsigned short port, void * addr, unsigned long count) {
  __asm__ __volatile__ ("rep ; outs" "l" : "=S" (addr), "=c" (count) : "d" (port),"0" (addr),"1" (count));
}

#endif /* NEXUS_KERN_IO_H */

