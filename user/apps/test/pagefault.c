/** NexusOS: Test general protection fault and pagefault handling */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <sys/mman.h>

#include <nexus/test.h>
#include <nexus/rdtsc.h>
#include <nexus/x86_emulate.h>
#include <nexus/Mem.interface.h>
#include <nexus/Thread.interface.h>

#define TRIALS 1 << 10

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
  return X86EMUL_CONTINUE;
}

void run_test(char *name, char *addr)
{
  uint64_t cycles;
  int i;

  cycles = rdtsc64();
  for (i = 0; i < TRIALS; i++)
    addr[i % TRIALS] = i;
  cycles = rdtsc64() - cycles;
  printf("[%s] %lld cycles per fault\n", name, cycles / TRIALS);

}

int main(int argc, char **argv)
{
  char *region;

  test_skip_auto();

  // test how fast we can write directly
  region = malloc(TRIALS);
  run_test("direct", region);
  
  // set memory to read only to force trap
  Mem_MProtect((unsigned long) region, TRIALS, PROT_READ);

  // register handler on trap
  register_pf_handler_write(writefunc);
  Thread_RegisterTrap(13, pf_handler2);
  Thread_RegisterTrap(14, pf_handler2);

  run_test("page fault", region);
  
  // reset protection
  Mem_MProtect((unsigned long) region, TRIALS, PROT_READ | PROT_WRITE);
  run_test("direct (2)", region);

  return 0;
}

