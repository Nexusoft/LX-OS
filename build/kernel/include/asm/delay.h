#ifndef _I386_DELAY_H
#define _I386_DELAY_H

#include <nexus/clock.h>

#define udelay(n) (nexus_udelay(n))
//#define ndelay(n) (nexus_ndelay(n))
 
#endif /* defined(_I386_DELAY_H) */
