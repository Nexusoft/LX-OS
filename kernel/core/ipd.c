/** Nexus OS: processes */

#include <nexus/defs.h>
#include <nexus/mem.h>
#include <nexus/mem-private.h>		// for struct Map (kernelMap)
#include <nexus/thread.h>
#include <nexus/ipd.h>
#include <nexus/screen.h>
#include <nexus/syscalls.h>
#include <nexus/syscall-private.h>
#include <nexus/util.h>
#include <nexus/hashtable.h>
#include <nexus/handle.h>
#include <nexus/vector.h>
#include <nexus/device.h>
#include <nexus/ipc.h>
#include <nexus/elf.h>
#include <nexus/guard.h>
#include <nexus/ipc_private.h>
#include <nexus/synch-inline.h>
#include <nexus/Debug.interface.h>

//////// New / Del / Get ////////////////

#define NUM_ID_BUCKETS (2048)
struct HashTable *process_table;

int idcount = 0;

IPD *
ipd_new(void) 
{
  IPD *ipd;
  int i, lvl;

  ipd = gcalloc(1, sizeof(IPD));

  if (unlikely(idcount == MAX_IPD_ID))
    nexuspanic();

  // initialize non-zero variables
  ipd->type = NATIVE;
  ipd->id = idcount++;

  // initiaze datastructures
  ipd->mutex = SEMA_MUTEX_INIT;
  ipd->uthreadtable = hash_new(NUM_UTHREAD_BUCKETS, sizeof(int));

  // insert in global lookup table
  lvl = disable_intr();
  hash_insert(process_table, (char *) &ipd->id, ipd);
  restore_intr(lvl);

#ifdef __NEXUSXEN__
  ipd->xen.xen_mutex = sema_new_mutex();
#endif

  return ipd;
}

/** Deallocate a process
    Do NOT call directly: only from __nexusthread_kill when last thread dies */
void 
__ipd_kill(IPD *ipd) 
{
  Map *m;
  int lvl;

  assert(check_intr() == 1);
  assert(ipd && ipd != kernelIPD);

  // remove from global lookup table 
  lvl = disable_intr();
  hash_delete(process_table, (char *) &ipd->id);

  // XXX destroy all ports
#ifdef __NEXUSXEN__
  sema_destroy(ipd->xen.xen_mutex);
#endif

  // communicate exit status to waiting parent (if any)
  if (ipd->exitval) {
    *ipd->exitval = ipd->exit_status;
    V_noint(ipd->exitsema);
  }
  
  if (!ipd->quiet)
    printk_current("\n[%d] exit %d\n", ipd->id, ipd->exit_status);
  
  restore_intr(lvl);
  
  // cleanup reference monitor
  if (ipd->refmon_port) {
	if (ipd->refmon_cache)
		Map_free(ipd->map, (unsigned long) ipd->refmon_cache, 
		         ipd->refmon_cache_pglen);
  }

  // cleanup standard structures
  Map_del(ipd->map);
  gfree(ipd->name);

  // XXX reenable free. watch out for use of exitsema in elf.c
  //gfree(ipd);
}

/** Kill a process: do NOT call directly */
void
ipd_kill_noint(IPD *ipd)
{
  int __helper(void *t, void *unused) 
  {
    nexusthread_kill(t);
    return 0;
  }

  assert(ipd != kernelIPD);
  //assert(check_intr() == 0);
  
  swap(&ipd->dying, 1);
  hash_iterate(ipd->uthreadtable, __helper, NULL);
  nexusthread_stop();
}

/** Kill a process
    Call with interrupts ENABLED */
void
ipd_kill(IPD *ipd)
{
  int lvl;

  P(&ipd->mutex);
  lvl = disable_intr();
  ipd_kill_noint(ipd);
  restore_intr(lvl);
  V(&ipd->mutex);
}

/** Unix fork()
    Since file descriptors are not stored in memory, these can never
    be shared among processes (unlike Posix rules) */
int
ipd_fork(void) 
{
  char name[32];
  KernelThreadState *new_kts, *old_kts;
  UThread *old_uthread, *new_uthread;
  IPD *ipd;

  assert(curt->type == USERTHREAD);
  old_uthread = (UThread *) curt;

  // create process
  ipd = ipd_new();
  ipd->map = Map_new(ipd);

  // link to its parent (creating a process group)
  ipd->parent = curt->ipd;
  snprintf(name, 31, "%s.%d", curt->ipd->name, curt->ipd->clone_count++);
  ipd->name = strdup(name);
  ipd->console = curt->ipd->console;

  // copy kernel state (thread context)
  new_uthread = nexusuthread_create(0, 0 /* PC and ESP are copied below */, ipd);
  UserThreadState_copy(new_uthread->uts, old_uthread->uts);
  UserThreadState_initFromIS(new_uthread->uts, curt->syscall_is);
  new_kts = thread_getKTS((BasicThread *)new_uthread), 
  old_kts = thread_getKTS(curt);
  new_kts->user_tcb = old_kts->user_tcb;

  // copy memory
  Map_copyRW(ipd->map, curt->ipd->map);

  // start new process
  new_uthread->uts->eax = 0 /* return value of fork() in child */;
  nexusthread_start((BasicThread *) new_uthread, 0);
  
  printkx(PK_THREAD, PK_DEBUG, "[process] fork %d into %d\n", 
          curt->ipd->id, ipd->id);
  return ipd->id;
}

/** Systemwide initialization of the process subsystem */
void 
ipd_init(void) 
{
  process_table = hash_new(NUM_ID_BUCKETS, sizeof(long));
  kernelIPD = ipd_new();
  kernelIPD->name = strdup("kernel");
  kernelMap->owner = kernelIPD;
}

IPD *
ipd_find(IPD_ID ipd_id) 
{
  IPD *ipd;
  int lvl;

  lvl = disable_intr();
  ipd = hash_findItem(process_table, (char *) &ipd_id);
  restore_intr(lvl);

  assert(!ipd || ipd->id == ipd_id);

  return ipd;
}

void 
ipd_iterate(int (*func)(int, IPD *, void *), void *ctx) 
{
  struct HashBucketEntry *entry;
  int i, lvl;

  lvl = disable_intr();
  hash_iterate_ex(process_table, (FuncEx) func, ctx);
  restore_intr(lvl);
}

//////// Trap Accounting ////////////////

unsigned int ipd_register_trap(IPD *ipd, int idx, unsigned int vaddr) {
  assert(idx >= 0 && idx <= 16);
  unsigned int old = ipd->usertraps[idx];
  ipd->usertraps[idx] = vaddr;
  return old;
}

unsigned int ipd_get_trap(IPD *ipd, int idx) {
#ifdef __NEXUSXEN__
  if(ipd->type == XEN) {
    // The user trap handler is ignored under Xen, since it has its
    // own page fault handling mechanism
    printk_red("ipd_get_trap() called on Xen domain!\n");
    return 0;
  } else 
#endif
  {
      assert(ipd && idx >= 0 && idx <= 16);
      return ipd->usertraps[idx];
  }
}

//////// Various ////////////////

int ipd_isXen(IPD *ipd) {
  return ipd->type == XEN;
}

/** Start a process, where the executable is passed from userspace (unsafe) 

    @param elf an executable
    @param arg all arguments incl. the filename are passed as a single 
           string to make it easier to copy args into the kernel. 

    Serialization of args is fragile with regards to quoted strings
    For instance, [cat "hello world"] will not be parsed correctly.
    XXX replace with communicating char** across kernel boundary
 */
UThread *
ipd_load(const unsigned char *elf, int len, const char *arg) 
{
#define isalpha(car) ((car >= 'a' && car <= 'z') || (car >= 'A' && car <= 'Z')) 
#define isblank(car) (car == ' ' || car == '\t' || car == '\n')
   UThread *thread;
   IPD *process;
   char *kelf, *karg, **av, *kname = NULL; 
   int alen, ac, ac_off, i;

   // sanity check
   if (!elf || !len || !arg)
     return NULL;

   // copy file and arguments
   alen = strlen(arg);
   karg = galloc(alen + 1);
   kelf = galloc(len);
   
   peek_user(nexusthread_current_map(), (unsigned int) elf, kelf, len);
   peek_user(nexusthread_current_map(), (unsigned int) arg, karg, alen);
   karg[alen] = '\0';

   // create char ** from args
   if (!isalpha(karg[0]) && karg[0] != '/') {
	gfree(kelf);
	gfree(karg);
   	return NULL;
   }

   // first count the number of args
   ac = 1;
   for (i = 1; i < alen; i++) {
       if (!isblank(karg[i]) && isblank(karg[i - 1]))
       	ac++;
   }

   // then fill in av and replace blanks with \0
   av = galloc(sizeof(char *) * (ac + 1));
   av[0] = karg;
   ac_off = 1;
   for (i = 1; i <= alen; i++) {
       if (!isblank(karg[i]) && isblank(karg[i - 1])) {
       	karg[i - 1] = '\0';
       	av[ac_off++] = &karg[i];
       }
   }
   av[ac] = NULL;

  // extract file portion of path as name
  i = strlen(av[0]);
  while (--i >= 0 && av[0][i] != '/')
    kname = av[0] + i;

  // create executable (finally)
  thread = NULL;
  process = ipd_fromELF(kname, kelf, len, ac, av, 0, &thread);

  // cleanup
  gfree(av);
  gfree(karg);
  gfree(kelf);

  if (!thread)
    printkx(PK_PROCESS, PK_WARN, "[elf] failed to load file\n");

  return thread;
}

/** Prepare a process so that we can wait on its exit value (waitpid) */
int
ipd_wait_prepare(IPD *ipd, int *exitval, Sema *sema)
{
	int intlevel;

	// only one process (the parent) can wait
	intlevel = disable_intr();
	if (!ipd || ipd->dying || ipd->exitval) {
		restore_intr(intlevel);
		return -1;
	}

	// tell process where to write exit value
	*exitval = -1;
	ipd->exitval = exitval;
	ipd->exitsema = sema;
	
	restore_intr(intlevel);
	return 0;
}

void
ipd_wait(int *exitval, Sema *sema)
{
	if (atomic_get(exitval) == -1) // process could have already exited
		P(sema);
}

int
ipd_waitpid(int pid)
{
	Sema sema;
	IPD *ipd;
	int ret;
	
	ipd = ipd_find(pid); 
	if (!ipd) 
		return -1;

	sema = SEMA_INIT_KILLABLE;
	if (ipd_wait_prepare(ipd, &ret, &sema)) {
		printkx(PK_PROCESS, PK_WARN, "[process] could not attach\n");
		return -1;
	}

	ipd_wait(&ret, &sema);
	return ret;
}

