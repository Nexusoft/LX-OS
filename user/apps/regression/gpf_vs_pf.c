/** NexusOS: Test general protection fault and pagefault handling */

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

#include <nexus/rdtsc.h>
#include <nexus/tpmcompat.h>
#include <nexus/x86_emulate.h>
#include <nexus/Thread.interface.h>

#define TRIALS 256

char *region;
char *roaddr;

struct InterruptState;

void pf_handler2(struct InterruptState *regs) 
{
	return;
}

int writefunc(enum x86_segment seg,
	      unsigned long vaddr,
	      unsigned long val,
	      unsigned int bytes,
	      struct x86_emulate_ctxt *ctxt)
{
  unsigned long offset;
  
//  offset = vaddr - (unsigned long) roaddr;
//  region[offset] = (char) val;

  return X86EMUL_CONTINUE;
}

int main(int argc, char **argv)
{
  uint64_t cycles;
  char *pfroaddr;
  int i, j;

  // test divide by zero. should cause INT
  //int x=5,y=0;
  //x /= y;

  region = malloc(TRIALS);
  
  register_pf_handler_write(writefunc);
  Thread_RegisterTrap(13, pf_handler2);

  // based on SMR, not yet integrated
  //pfroaddr = roaddr = (char *)remap_readonly((unsigned int)region, TRIALS);
  pfroaddr = roaddr = region;

  for (j = 0; j < 100; j++) {
    cycles = rdtsc64();
    for (i = 0; i < TRIALS; i++)
      pfroaddr[i % TRIALS] = i;
    cycles = rdtsc64() - cycles;
    //printf("page faults took %lld cycles\n", end - start);
  }

  for (j = 0; j < 100; j++) {
    cycles = rdtsc64();
    for (i = 0; i < TRIALS; i++)
      roaddr[i % TRIALS] = i;
    cycles = rdtsc64() - cycles;
    //printf("gpfs took %lld cycles\n", end - start);
  }
  return 0;
}

