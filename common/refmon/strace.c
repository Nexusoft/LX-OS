/** NexusOS: straightforward syscall tracing, strace (ptrace) style */

#include <nexus/defs.h>
#include <nexus/guard.h>
#include <nexus/printk.h>
#include <nexus/machine-structs.h>

static int calldepth;

static int 
nxrefmon_strace_in(struct nxguard_tuple tuple)
{
	int depth;

	depth = atomic_get_and_addto(&calldepth, 1);
	//printk_red("[trace] +%*d\n", depth, tuple.operation);
	printk_red("[trace] +%d\n", tuple.operation);
	
	return AC_ALLOW_NOCACHE;
}

static int 
nxrefmon_strace_out(struct nxguard_tuple tuple)
{
	int depth;

	depth = atomic_get_and_addto(&calldepth, -1) - 1;
	//printk_red("        -%*d\n", depth, tuple.operation);

	return 0;
}

