#ifndef __IO_INSTRUMENT_H__
#define __IO_INSTRUMENT_H__

#undef in_logging
#undef inb_logging
#undef inw_logging
#undef inl_logging

#undef out_logging
#undef outb_logging
#undef outw_logging
#undef outl_logging

#undef ins_logging

#undef insb_logging
#undef insw_logging
#undef insl_logging

#undef outs_logging

#undef outsb_logging
#undef outsw_logging
#undef outsl_logging


#define in_logging(p,v,d)  
#define inb_logging(p,v)   
#define inw_logging(p,v)   
#define inl_logging(p,v)   

#define out_logging(p,v,d)  
#define outb_logging(p,v)   
#define outw_logging(p,v)   
#define outl_logging(p,v)   

#define ins_logging(p,a,c,d) 

#define insb_logging(p,a,c) 
#define insw_logging(p,a,c) 
#define insl_logging(p,a,c) 

#define outs_logging(p,a,c,d) 

#define outsb_logging(p,a,c) 
#define outsw_logging(p,a,c) 
#define outsl_logging(p,a,c) 

#ifdef io_instrument_logging

#undef in_logging
#undef inb_logging
#undef inw_logging
#undef inl_logging

#undef out_logging
#undef outb_logging
#undef outw_logging
#undef outl_logging

#undef ins_logging

#undef insb_logging
#undef insw_logging
#undef insl_logging

#undef outs_logging

#undef outsb_logging
#undef outsw_logging
#undef outsl_logging


#if 1
#define in_logging(p,v,d)  kernel_log_io_read(p, (unsigned char *)&v, d);
#define inb_logging(p,v)   in_logging(p,v,1)
#define inw_logging(p,v)   in_logging(p,v,2)
#define inl_logging(p,v)   in_logging(p,v,4)
#else
#define in_logging(p,v,d)  
#define inb_logging(p,v)   
#define inw_logging(p,v)   
#define inl_logging(p,v)   
#endif

#define out_logging(p,v,d)  kernel_log_io_write(p, (unsigned char *)&v, d);
#define outb_logging(p,v)   out_logging(p,v,1)
#define outw_logging(p,v)   out_logging(p,v,2)
#define outl_logging(p,v)   out_logging(p,v,4)

#if 1
#define ins_logging(p,a,c,d) do{		\
    int i;					\
    for(i = 0; i < c; i++)			\
      kernel_log_io_read(p, a + i * d, d);	\
  }while(0)

#define insb_logging(p,a,c) ins_logging(p,a,c,1)
#define insw_logging(p,a,c) ins_logging(p,a,c,2)
#define insl_logging(p,a,c) ins_logging(p,a,c,4)
#else
#define ins_logging(p,a,c,d) 
#define insb_logging(p,a,c) 
#define insw_logging(p,a,c) 
#define insl_logging(p,a,c) 
#endif


#define outs_logging(p,a,c,d) do{		\
    int i;					\
    for(i = 0; i < c; i++)			\
      kernel_log_io_write(p, a + i * d, d);	\
  }while(0)

#define outsb_logging(p,a,c) outs_logging(p,a,c,1)
#define outsw_logging(p,a,c) outs_logging(p,a,c,2)
#define outsl_logging(p,a,c) outs_logging(p,a,c,4)

#include <nexus/devicelog.h>

#endif

static inline unsigned char inb(unsigned short port) { 
  unsigned char _v;
  __asm__ __volatile__ ("in" "b" " %" "w" "1,%" "" "0" : "=a" (_v) : "Nd" (port) ); 
  inb_logging(port,_v);
  return _v; 
} 
static inline unsigned char inb_p(unsigned short port) { 
  unsigned char _v;
  __asm__ __volatile__ ("in" "b" " %" "w" "1,%" "" "0" "\noutb %%al,$0x80" : "=a" (_v) : "Nd" (port) ); 
  inb_logging(port,_v);
  return _v; 
}


static inline unsigned short inw(unsigned short port) { 
  unsigned short _v; 
  __asm__ __volatile__ ("in" "w" " %" "w" "1,%" "" "0" : "=a" (_v) : "Nd" (port) );
  inw_logging(port,_v);
  return _v;
} 
static inline unsigned short inw_p(unsigned short port) { 
  unsigned short _v;
  __asm__ __volatile__ ("in" "w" " %" "w" "1,%" "" "0" "\noutb %%al,$0x80" : "=a" (_v) : "Nd" (port) );
  inw_logging(port,_v);
  return _v;
}


static inline unsigned int inl(unsigned short port) { 
  unsigned int _v;
  __asm__ __volatile__ ("in" "l" " %" "w" "1,%" "" "0" : "=a" (_v) : "Nd" (port) );
  inl_logging(port,_v);
  return _v;
} 
static inline unsigned int inl_p(unsigned short port) { 
  unsigned int _v;
  __asm__ __volatile__ ("in" "l" " %" "w" "1,%" "" "0" "\noutb %%al,$0x80" : "=a" (_v) : "Nd" (port) );
  inl_logging(port,_v);
  return _v;
}


static inline void outb(unsigned char value, unsigned short port) {
  __asm__ __volatile__ ("out" "b" " %" "b" "0,%" "w" "1" : : "a" (value), "Nd" (port));
  outb_logging(port, value);
} 
static inline void outb_p(unsigned char value, unsigned short port) {
  __asm__ __volatile__ ("out" "b" " %" "b" "0,%" "w" "1" "\noutb %%al,$0x80" : : "a" (value), "Nd" (port));
  outb_logging(port, value);
}
static inline void outw(unsigned short value, unsigned short port) {
  __asm__ __volatile__ ("out" "w" " %" "w" "0,%" "w" "1" : : "a" (value), "Nd" (port));
  outw_logging(port, value);
} 
static inline void outw_p(unsigned short value, unsigned short port) {
  __asm__ __volatile__ ("out" "w" " %" "w" "0,%" "w" "1" "\noutb %%al,$0x80" : : "a" (value), "Nd" (port));
  outw_logging(port, value);
}
static inline void outl(unsigned int value, unsigned short port) {
  __asm__ __volatile__ ("out" "l" " %" "0,%" "w" "1" : : "a" (value), "Nd" (port));
  outl_logging(port, value);
} 
static inline void outl_p(unsigned int value, unsigned short port) {
  __asm__ __volatile__ ("out" "l" " %" "0,%" "w" "1" "\noutb %%al,$0x80" : : "a" (value), "Nd" (port));
  outl_logging(port, value);
}

static inline void insb(unsigned short port, void * addr, unsigned long count) {
  __asm__ __volatile__ ("rep ; ins" "b" : "=D" (addr), "=c" (count) : "d" (port),"0" (addr),"1" (count));
  insb_logging(port, addr, count);
}
static inline void insw(unsigned short port, void * addr, unsigned long count) {
  __asm__ __volatile__ ("rep ; ins" "w" : "=D" (addr), "=c" (count) : "d" (port),"0" (addr),"1" (count));
  insw_logging(port, addr, count);
}
static inline void insl(unsigned short port, void * addr, unsigned long count) {
  __asm__ __volatile__ ("rep ; ins" "l" : "=D" (addr), "=c" (count) : "d" (port),"0" (addr),"1" (count));
  insl_logging(port, addr, count);
}

static inline void outsb(unsigned short port, void * addr, unsigned long count) {
  __asm__ __volatile__ ("rep ; outs" "b" : "=S" (addr), "=c" (count) : "d" (port),"0" (addr),"1" (count));
  outsb_logging(port, addr, count);
}
static inline void outsw(unsigned short port, void * addr, unsigned long count) {
  __asm__ __volatile__ ("rep ; outs" "w" : "=S" (addr), "=c" (count) : "d" (port),"0" (addr),"1" (count));
  outsw_logging(port, addr, count);
}
static inline void outsl(unsigned short port, void * addr, unsigned long count) {
  __asm__ __volatile__ ("rep ; outs" "l" : "=S" (addr), "=c" (count) : "d" (port),"0" (addr),"1" (count));
  outsl_logging(port, addr, count);
}


#endif
