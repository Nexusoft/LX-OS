/** NexusOS: Processes */

#ifndef __NEXUSIPD_H__
#define __NEXUSIPD_H__

typedef int IPD_ID;
#define IPD_ID_TYPEDEF 
#define IPD_INVALID (-1)

#include <nexus/defs.h>
#include <nexus/synch.h>
#include <nexus/device.h>
#include <nexus/thread-struct.h>
#include <nexus/syscall-defs.h>
#include <nexus/ipc.h>
#include <nexus/log.h>
#include <nexus/handle.h>
#include <nexus/screen.h>
#include <nexus/synch-inline.h>
#include <nexus/ipd-asm.h>

typedef enum IPDType {
  NATIVE = IPDType_NATIVE,
  XEN = IPDType_XEN,
} IPDType;

#define NUM_UTHREAD_BUCKETS 32
#define NUM_IPC_PORT_BUCKETS 32

#define KERNEL_IPD_ID (0)
#define INVALID_IPD_ID (-1)

// forward declarations
struct IPC_Port;
struct IPC_CommonClientContext;
struct DDRM;

struct IPD {
  
  // Identification	
  u32 id;
  char *name;
  IPD *parent;		///< link to single ancestor: process group
  char sha1[20];
  IPDType type;
  
  Sema mutex; 		///< protects most structures 
  Sema* exitsema;	///< allow parent to wait for exit
  int *exitval;		///< share exit status with parent if not NULL
  int exit_status;
  int account;		///< cpu scheduler account

  int is_reaped:1;
  int background:1;	///< don't give immediate focus
  int quiet:1;		///< don't give console access (used in selftests)
  int segfaulted;	///< if set, do not print stack trace
  int dying;		///< set to 1 when dead
  int clone_count;

  // Threads
  struct HashTable *uthreadtable;
  int threadcount;

  // Memory
  struct Map *map;
  int grantpages;	///< number of pages other processes may grant

  // Waitqueues (XXX ugly static allocation: make dynamic)
  struct Sema wq[NXCONFIG_WAITQUEUE_COUNT];
  int wq_used[NXCONFIG_WAITQUEUE_COUNT];
  int wq_last;		///< last allocated: start of search

  // Devices
  struct nxconsole *console;

  // Reference Monitor support
  int refmon_port;	///< ipc port on which refmon is waiting, if any
  char *refmon_cache;	///< in-kernel cache of refmon decisions
  int refmon_cache_pglen;
  unsigned int refmon_collisions;

  unsigned int usertraps[17];

  // Xen
#ifdef __NEXUSXEN__
  struct {
    Sema *xen_mutex;
    // The thread that represents the master CPU of the Xen context
    BasicThread *cpu0;
  } xen;
#endif

};

IPD *ipd_new(void);
IPD *ipd_find(IPD_ID ipd_id);
void ipd_del(IPD *ipd);

extern IPD *kernelIPD;

int ipd_fork(void);

//// Traps

unsigned int ipd_register_trap(IPD *ipd, int idx, unsigned int vaddr);
unsigned int ipd_get_trap(IPD *ipd, int idx);

//// Kill

void __ipd_kill(IPD *ipd);
void ipd_kill_noint(IPD *ipd);
void ipd_kill(IPD *ipd);

//// Various

void ipd_iterate(int (*func)(int, IPD *, void *), void *ctx);
void ipd_init(void);
int ipd_isXen(IPD *ipd);
UThread * ipd_load(const unsigned char *elf, int len, const char *arg);

int  ipd_waitpid(int pid);

int ipd_sha1_addcred(void);
int ipd_sha1_get(char * user_sha1);
int ipd_sha1_says(IPD *ipd, char **stmts, char *filepath, int cert);

//// Internal: do not use

int  ipd_wait_prepare(IPD *ipd, int *exitval, Sema *sema);
void ipd_wait(int *exitval, Sema *sema);

#endif

