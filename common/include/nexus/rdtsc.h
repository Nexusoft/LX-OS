/* Nexus OS
   Wrapper around Intel x86 rdtsc() instruction
 */

#ifndef NEXUS_RDTSC_H
#define NEXUS_RDTSC_H

#ifdef __NEXUSKERNEL__
#include <linux/types.h>
#else
#include <stdint.h>
#endif

static inline uint64_t
rdtsc64(void)
{
	uint32_t lo, hi;
	
	asm volatile ("rdtsc" : "=a" (lo), "=d" (hi));

	return (((uint64_t) hi) << 32) | lo;
}

static inline void
rdtsc64_poll(unsigned long cycles) 
{
	uint64_t tend;

	tend = cycles + rdtsc64();
	while (rdtsc64() < tend) {};
}

#endif /* NEXUS_RDTSC_H */

