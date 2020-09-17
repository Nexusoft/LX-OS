/** Nexus OS: compare memcpy approaches 
 
 Slower alternatives to memcpy are used to transfer data from
 user virtual addresses; faster inline ones are used when possible.
 This program compares the common alternatives on speed. It 
 tries to avoid cache effects.
 */

#include <nexus/mem.h>
#include <nexus/clock.h>
#include <nexus/galloc.h>
#include <nexus/printk.h>

#define BUFSIZE	(1 << 23)	///< exceed all data cache sizes
#define READSIZE (1 << 10)	
#define REPS	101		///< test repetitions (we do not calculate median)

typedef int (*memcpyfunc)(char *, const char *, int);

static int memcpy_wrapper(char *dest, const char *src, int len)
{
	// calls linux memcpy
	copy_from_generic(NULL, dest, src, len);
	return 0;
}

static void
__test_memcpy(memcpyfunc Fn, char *dest, const char *src, int len)
{
	uint64_t tdiff;
	int off;
	int i;
	
	tdiff = rdtsc64();
	for (i = 0; i < REPS; i++) {
		for (off = 0; off < BUFSIZE; off += READSIZE)
			Fn(dest + off, src + off, READSIZE);
	}
	tdiff = rdtsc64() - tdiff;

	printk("copied %dMB in %lluM cycles\n", 
	       REPS * (BUFSIZE >> 20), tdiff >> 20);
}

int
test_memcpy(void)
{
	char stfrom[32], stto[32];
	void *from, *to;

	// setup buffers
	from = galloc(BUFSIZE);
	if (!from)
		return 1;

	to = galloc(BUFSIZE);
	if (!to)
		return 1;

	// test performance
	//__test_memcpy(memcpy, from, to, BUFSIZE);
#ifdef MEMCPY_OPTIMIZE
	__test_memcpy(exception_memcpy_movs, from, to, BUFSIZE);
	__test_memcpy(constant_exception_memcpy_inline, from, to, BUFSIZE);
	__test_memcpy(memcpy_wrapper, from, to, BUFSIZE);
#endif

	// test stack transfer
	// NB: these are all deprecated
	//exception_memcpy(stfrom, stto, 32);
#ifdef MEMCPY_OPTIMIZE
	//exception_memcpy_movs(stfrom, stto, 32);
	//constant_exception_memcpy_inline(stfrom, stto, 32);
	memcpy_wrapper(stfrom, stto, 32);
#endif

	// release buffers
	gfree(to);
	gfree(from);

	return 0;
}

