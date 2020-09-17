/** NexusOS: various bitmap implementations */

#include <nexus/test.h>

#ifndef NDEBUG 

int
nxtwobit_selftest(void)
{
	char bits = 0;
	
	// test basic get/set
	nxtwobit_set(&bits, 0, 0x2);
	if (nxtwobit_get(&bits, 0) != 0x2)
		ReturnError(1, "get #1");
	
	// test neighbor
	if (nxtwobit_get(&bits, 1) != 0x0)
		ReturnError(1, "get #2");

	// test overflow
	nxtwobit_set(&bits, 0, 0x9);
	if (nxtwobit_get(&bits, 0) != 0x1)
		ReturnError(1, "get #3");

	return 0;
}

int 
nxnibble_selftest(void)
{		
	char nibbles;

	nibbles = 0;

	nxnibble_set(&nibbles, 0, 0x3);
	if (nxnibble_get(&nibbles, 0) != 0x3)
		ReturnError(1, "get #1");
	if (nxnibble_get(&nibbles, 1) != 0x0)
		ReturnError(1, "get #2");

	nxnibble_set(&nibbles, 1, 0x2);
	if (nxnibble_get(&nibbles, 0) != 0x3)
		ReturnError(1, "get #3");
	if (nxnibble_get(&nibbles, 1) != 0x2)
		ReturnError(1, "get #4");

	return 0;
}

#endif

