/** NexusOS: ELF binary functions */

#ifndef NXKERN_ELF_H
#define NXKERN_ELF_H

#include <nexus/defs.h>
#include <nexus/mem.h>
#include <nexus/synch-inline.h>
#include <nexus/thread.h>
#include <nexus/thread-inline.h>
#include <nexus/ipd.h>
#include <nexus/syscall-private.h>

#define PROCESS_WAIT	0x1	///< wait until child has started
#define PROCESS_QUIET	0x2	///< don't give own console
#define PROCESS_BG	0x4

IPD *ipd_fromELF(const char *ipd_name, char *file, int size, int ac, char **av, 
		 int background, UThread **uthread_p);

UThread * elf_load(const char *filepath, int background, int ac, char **av);
int elf_exec(const char *filepath, unsigned long flags, int ac, char **av);

#endif /* NXKERN_ELF_H */

