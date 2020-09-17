/** NexusOS: Stack tracing
    (used to hold a log, hence the name) */

#include <stdarg.h>
#include <nexus/defs.h>

#include <nexus/log.h>
#include <asm/hw_irq.h> // for _stext
#include <nexus/util.h>
#include <nexus/queue.h>
#include <nexus/machineprimitives.h>
#include <nexus/ksymbols.h>
#include <nexus/ipd.h>
#include <nexus/thread.h>
#include <nexus/thread-struct.h>

////////  Code for dumping the stack on errors  ////////
//
// XXX should be in its own file
