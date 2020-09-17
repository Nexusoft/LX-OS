#include <nexus/defs.h>
#include <nexus/x86_emulate.h>

#include <../code/x86_emulate-code.c>

int x86_emulate_do_out(unsigned long addr, unsigned long val, int bytes){
  unsigned short port = (unsigned short)(addr & 0xffff);
  
  switch(bytes){
  case 1:
    __asm__ __volatile__ ("out" "b" " %" "b" "0,%" "w" "1" : : "a" (val), "Nd" (port));
    break;
  case 2:
    __asm__ __volatile__ ("out" "w" " %" "w" "0,%" "w" "1" : : "a" (val), "Nd" (port));
    break;
  case 4:
    __asm__ __volatile__ ("out" "l" " %" "0,%" "w" "1" : : "a" (val), "Nd" (port));
    break;
  default:
    return X86EMUL_UNHANDLEABLE;
  };

  return X86EMUL_CONTINUE;
}


int x86_emulate_do_in(unsigned long addr, unsigned long *val, int bytes){
  unsigned short port = (unsigned short)(addr & 0xffff);

  switch(bytes){
  case 1:
    __asm__ __volatile__ ("in" "b" " %" "w" "1,%" "" "0" : "=a" (*val) : "Nd" (port) );
    *val &= 0xff;
    break;
  case 2:
    __asm__ __volatile__ ("in" "w" " %" "w" "1,%" "" "0" : "=a" (*val) : "Nd" (port) );
    *val &= 0xffff;
    break;
  case 4:
    __asm__ __volatile__ ("in" "l" " %" "w" "1,%" "" "0" : "=a" (*val) : "Nd" (port) );
    break;
  default:
    return X86EMUL_UNHANDLEABLE;
  };

  return X86EMUL_CONTINUE;
}


