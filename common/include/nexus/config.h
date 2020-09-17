/** NexusOS: central configuration header 
 
    XXX move various options from other files here

    Use:
        1) label options consistently: NXCONFIG_<<LABEL>> 
 	2) toggle on/off through #define X 0 or #define X 1
           and test with #if

           Do NOT use #define/#undef/#ifdef, as a simple type or omission leads
	   to unexplained behavior. See also Rusty Russell's comments on this:
	   http://ozlabs.org/~rusty/index.cgi/tech/2008-01-04.html
*/

#ifndef NX_COMMON_CONFIG_H
#define NX_COMMON_CONFIG_H

/// do not marshall ipc_send/ipc_sendpage/ipc_recv/...  
//  but use raw syscalls (that cannot be interposed)
#define NXCONFIG_FAST_IPC 0

/// preemptible kernel
#define NXCONFIG_PREEMPT_KERNEL	0

/// attribute spent cycles to user/kernel parts of each thread
//  (required for correct reporting in times(3))
#define NXCONFIG_CYCLECOUNT_USER 0

#define NXCONFIG_CPU_QUOTA 0

/// support devices that lack access to the data they transport
#define NXCONFIG_DEVICE_BLIND 0

//////// Debugging options

#ifdef NDEBUG
#define NXCONFIG_PROFILE_SCHED 0
#define NXCONFIG_DEBUG_TRACE 0
#else
#define NXCONFIG_PROFILE_SCHED 1
#define NXCONFIG_DEBUG_TRACE 1		///< thread trace on segfault
#endif

//////// Structures

// number of kernel semaphores per process. MUST be power of two
#define NXCONFIG_WAITQUEUE_COUNT 4096

#endif /* NX_COMMON_CONFIG_H */

