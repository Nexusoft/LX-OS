/** NexusOS: scheduler stresstest */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <nexus/defs.h>
#include <nexus/test.h>
#include <nexus/rdtsc.h>

#include <nexus/Thread.interface.h>

/** Test isolation with multiple queues: 
    run a busy loop in a separate account */
static int
do_isolation(void)
{
	unsigned long long tstop, tupdate, tnow;
	int quantum_index;

	quantum_index = 1;

	// NB: order of these two calls is important: must add quantum to 
	//     an account to ensure that the process will receive resources
	if (Thread_Sched_SetQuantumAccount(quantum_index, 1))
		ReturnError(1, "set quantum account failed");
	if (!Thread_Sched_SetQuantumAccount(quantum_index++, 2))
		ReturnError(1, "override quantum account succeeded");
	if (Thread_Sched_SetProcessAccount(getpid(), 1))
		ReturnError(1, "set process account failed");

	printf("Busy polling for 80 - 160 seconds (depending on CPU Hz)\n");
	printf("Increasing CPU share by 10%% every ~16 seconds..\n");
	
	// set timeouts
	tnow = rdtsc64();
	tupdate = tnow + (1ULL << 35);
	tstop = tnow + (1ULL << 38);

	while (tnow < tstop) {

		if (tnow > tupdate) {
			fprintf(stderr, "  increasing share to %d0%%\n", quantum_index);
			if (Thread_Sched_SetQuantumAccount(quantum_index++, 1))
				ReturnError(1, "set quantum account failed");
			tupdate = tnow + (1ULL << 35);
		}
		
		tnow = rdtsc64();
	};
	
	printf (".. done\n");
	return 0;
}

int 
main(int argc, char **argv)
{
	test_skip_auto();

	if (do_isolation())
		return 1;

	printf("[OK]\n");
	return 0;
}

