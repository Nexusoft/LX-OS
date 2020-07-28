/** NexusOS: Processes */

#ifndef __NEXUSIPD_H__
#define __NEXUSIPD_H__

typedef int IPD_ID;
#define IPD_ID_TYPEDEF 
#define IPD_INVALID (-1)

#include <nexus/defs.h>
#include <nexus/synch.h>
#include <nexus/device.h>
#include <nexus/thread.h>
#include <nexus/kvkey.h>
#include <nexus/syscall-defs.h>
#include <nexus/ipc.h>
#include <nexus/handle.h>
#include <nexus/ddrm.h>
#include <nexus/screen.h>
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
struct HandleTable;
struct IPC_CommonClientContext;
struct DDRM;

struct IPD {
  QItem _link; // for focus queue

  u32 id;
  IPDType type;
  int is_user_ipd;
  Sema mutex; // protects most structures 
  
  // Threads
  struct HashTable *uthreadtable;
  BasicThread *thread_latest;		///< for stack trace of process
  int threadcount;

  // Memory
  struct Map *map;

  // Devices
  Queue open_devices;
  struct DDRM *ddrm;
  ScreenBuf *screenbuf;

  unsigned int usertraps[17];

  int nofocus;
  int is_reaped;

  int isdevice:1;
  int background:1;	///< don't give immediate focus
  int quiet:1;		///< don't give console access (used in selftests)

#define MAX_IPD_NAMELEN (32)
  char name[MAX_IPD_NAMELEN];

  struct {
    __u32 *shadow; // Array of pages to virtual memory shadow
    char *data; // Start of user-owned portion of hardware frame buffer
    int length; // Length to save/restore, in bytes
  } fb;

  struct {
    Sema *xen_mutex;
    // The thread that represents the master CPU of the Xen context
    BasicThread *cpu0;
  } xen;

  int clone_count;

  int transfer_to_bytes;
  int transfer_from_bytes;

#define INITIAL_CONNECTION_TABLE_SIZE (32)
  struct HandleTable conn_handle_table; // Connection_Handle => Connection
  struct HandleTable call_handle_table; // Call_Handle => CommonCtx *

  KVKey_nsk *nsk;

  Port_Handle default_notification_handle;
};

IPD *ipd_new(void);
IPD *ipd_find(IPD_ID ipd_id);
void ipd_del(IPD *ipd);

extern IPD *kernelIPD;

IPD *ipd_fork(IPD *source_ipd, BasicThread *source_thread,
	      thread_callback_t fork_fn, void *fork_ctx);

static inline int 
ipd_is_kernel(IPD *ipd) 
{
  return !ipd->is_user_ipd;
}

//// Traps

unsigned int ipd_register_trap(IPD *ipd, int idx, unsigned int vaddr);
unsigned int ipd_get_trap(IPD *ipd, int idx);

//// Threads

void ipd_add_uthread(IPD *ipd, UThread *ut, int *id);
void ipd_rm_uthread(IPD *ipd, int *id);
void ipd_killall(IPD *ipd);

//// Device I/O

struct NexusOpenDevice;
int ipd_add_open_device(IPD *ipd, struct NexusOpenDevice *nod);
struct NexusOpenDevice *ipd_get_open_device(IPD *ipd, int dt, int handle);

static inline int 
ipd_hasMappedFB(IPD *ipd) 
{
  return ipd->fb.data != NULL;
}

int PDBR_hasFramebuffer(Page *pdbr);
void ipd_fb_save(IPD *ipd);
void ipd_fb_restore(IPD *ipd);

typedef enum FB_RemapMode {
  FB_MAP_VIDEO,
  FB_MAP_MEM,
  FB_MAP_NOTHING,
} FB_RemapMode;

// ASHIEH: Keep this as pdbr rather than Map ! I've flipped it back 2x already
void ipd_fb_remap(IPD *ipd, Page *pdbr, FB_RemapMode map_mode);
void ipd_PDIR_activated(IPD *ipd, struct Map *m);
int ipd_fb_unmap(IPD *ipd, Page *pdbr);

//// Calls

#define IS_KERNEL_CALLHANDLE(X) \
  ( (X) != -1 && ((unsigned int)(X)) >= (unsigned int)KERNELVADDR )

Call_Handle 		  ipd_addCall(IPD *ipd, IPC_CommonClientContext *common_ctx);
IPC_CommonClientContext * ipd_findCall(IPD *ipd, Call_Handle handle);
void 			  ipd_delCall(IPD *ipd, Call_Handle handle);

//// Connections

#define IS_KERNEL_CONNHANDLE(X) IS_KERNEL_CALLHANDLE(X)
#define RESERVED_CONNECTION ((void *) -2)

struct IPC_Connection;
Connection_Handle ipd_addConnection(IPD *ipd, struct IPC_Connection *connection,
				    Connection_Handle requested_handle);
IPC_Connection *  ipd_findConnection(IPD *ipd, Connection_Handle conn_handle);
void 		  ipd_delConnection(IPD *ipd, Connection_Handle conn_handle);

//// NSK 

int ipd_set_nsk(IPD *ipd, KVKey_nsk *nsk);
KVKey_nsk *ipd_get_nsk(IPD *ipd);
Form *ipd_get_nsk_form(IPD *ipd);
Form *ipd_get_speaker(IPD *ipd);

//// Various

void ipd_iterate(void (*f)(void *, void *), void *ctx);
void ipd_init(void);
void ipd_setName(IPD *ipd, const char *new_name);
int ipd_isXen(IPD *ipd);
void ipd_start_all_not_run(IPD *ipd);
void ipd_destroy_all_ports(IPD *ipd);
int ipd_exec(const unsigned char *elf, int len, const char *arg);

#endif

