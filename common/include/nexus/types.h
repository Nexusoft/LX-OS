#ifndef _NEXUS_TYPES_H
#define _NEXUS_TYPES_H

#ifdef __NEXUSKERNEL__
/* Would love to stay away from linux dependencies, but
 * because quite a bit of code depends on asm/ and linux/ 
 * we cannot go redeclare these types. */
#include <asm/types.h>
#include <linux/types.h>
#else
#include <stdint.h>		/* for uint_32t and friends */
#include <sys/types.h>		
#endif

#endif // _NEXUS_TYPES_H

