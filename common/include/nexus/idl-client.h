#ifndef _IDL_CLIENT_H_
#define _IDL_CLIENT_H_

#ifndef __NEXUSKERNEL__

#include <string.h>
#include <stdio.h>
#include <assert.h>

#else

#include <nexus/defs.h>

#define __ipcResultCode (*&(nexusthread_self()->ipcResultCode))
#define printf_failsafe printk

#endif // __NEXUSKERNEL__

#endif // _IDL_CLIENT_H_
