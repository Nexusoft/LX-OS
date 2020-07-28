/** NexusOS: network services code.
    This supports the switch, router, etc. */
#include <nexus/defs.h>
#include <nexus/netcomp.h>
#include <nexus/ipc_private.h>
#include <nexus/user_compat.h>
#include <nexus/thread-inline.h>
#include <nexus/net.h>
#include <linux/skbuff.h>

#include <nexus/ipd.h>
#include <nexus/tap-interpose.h>

#include <../code/net-code.c>
