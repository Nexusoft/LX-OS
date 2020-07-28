#include <nexus/defs.h>
#include <nexus/tftp.h>
#include <nexus/thread.h>
#include <nexus/thread-inline.h>

#define PRINT(x...) printk_red(x)
//#define WRITEFILE(r,s,n) send_file(n,r,s)
#define WRITEFILE(r,s,n) queue_and_send_file(n,r,s)
#define RECORDSIZE (100 * 1024)
#define FILEPREFIX "malloc_kernel"

extern int show_trace_array(unsigned long *addrs, int numaddrs);
#define GET_TRACE(x,y) show_trace_array(x,y)

#include "common/code/malloc_checker-code.c"
