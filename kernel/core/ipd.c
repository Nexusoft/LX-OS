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
#include <nexus/ipc.h>
#include <nexus/elf.h>
#include <nexus/ipc_private.h>
#include <nexus/kernelfs.h>
#include <nexus/synch-inline.h>
#include <nexus/Debug.interface.h>

//////// New / Del / Get ////////////////

#define NUM_ID_BUCKETS (2048)
static struct HashTable *process_table;
static Sema process_table_mutex = SEMA_MUTEX_INIT;

IPD *
ipd_new(void) 
{
  static unsigned long idcount;
  IPD *ipd;
  int i;

  ipd = gcalloc(1, sizeof(IPD));

  if (unlikely(idcount == MAX_IPD_ID))
    nexuspanic();

  // initialize non-zero variables
  ipd->type = NATIVE;
  ipd->id = idcount++;

  // initiaze datastructures
  ipd->mutex = SEMA_MUTEX_INIT;
  ipd->xen.xen_mutex = sema_new_mutex();
  ipd->uthreadtable = hash_new(NUM_UTHREAD_BUCKETS, sizeof(int));
  queue_initialize(&ipd->open_devices);

  HandleTable_init(&ipd->conn_handle_table,
		   INITIAL_CONNECTION_TABLE_SIZE);
  HandleTable_init(&ipd->call_handle_table,
		   INITIAL_CONNECTION_TABLE_SIZE);

  // insert in global lookup table
  P(&process_table_mutex);
  hash_insert(process_table, (char *)&ipd->id, ipd);
  V(&process_table_mutex);

  // first process is the special kernel IPD
  if (ipd->id == 0) {
    ipd_setName(ipd, "kernel");
    populate_kernelIPD_syscall_conn_table(ipd);
  }
  else {
    ipd->is_user_ipd = 1;
    ipd_setName(ipd, "(unnamed)");
    populate_syscall_conn_table(ipd);
    KernelFS_addIPDNode(ipd);
  }

  return ipd;
}

IPD *
ipd_fork(IPD *old_ipd, BasicThread *old_thread, 
	 thread_callback_t fork_fn, void *fork_ctx) 
{
  char name[MAX_IPD_NAMELEN];
  KernelThreadState *new_kts, *old_kts;
  UThread *old_uthread, *new_uthread;
  IPD *ipd;

  assert(old_thread == nexusthread_self());
  assert(old_thread->type == USERTHREAD);

  old_uthread = (UThread *) old_thread;

  // create process
  ipd = ipd_new();
  sprintf(name, "%s-clone(%d)", old_ipd->name, old_ipd->clone_count++);
  ipd_setName(ipd, name);
  
  // copy memory and setup first thread
  ipd->map = Map_copyRW(old_ipd->map);
  new_uthread = nexusuthread_create(ipd->map, 0, 0, // PC and ESP will be copied below
		                    ipd, fork_fn, fork_ctx);

  // copy kernel and user thread state
  UserThreadState_copy(new_uthread->uts, old_uthread->uts);
  UserThreadState_initFromIS(new_uthread->uts, old_thread->syscall_is);
  new_uthread->uts->eax = 0;
  new_kts = thread_getKTS((BasicThread *)new_uthread), 
  old_kts = thread_getKTS(old_thread);
  new_kts->user_tcb = old_kts->user_tcb;

  // New thread is now ready to go
  nexusthread_start((BasicThread *) new_uthread, 0);
  printkx(PK_THREAD, PK_INFO, "[process] created new process %d (thread %d)\n",
	  ipd->id, new_uthread->id);
  return ipd;
}

/** Remove a process 
 
    XXX Fix: should be inverse of ipd_new, but isn't.*/
void 
ipd_del(IPD *ipd) 
{
  Map *m;
  int id;

  assert(ipd && ipd != kernelIPD);
  id = ipd->id;

  // remove from global structures
  P(&process_table_mutex);
  hash_delete(process_table, (char *)&ipd->id);
  V(&process_table_mutex);

  if (ipd->ddrm)
      ddrm_cleanup(ipd->ddrm);

  m = ipd->map;
  if (swap(&ipd->is_reaped, 1) == 0) {

    // cleanup all substructures (is not comprehensive)
    ipd_destroy_all_ports(ipd);

    // XXX find out when this can happen
    if (Map_get_active_thread_count(m) != 0)
    	printkx(PK_THREAD, PK_DEBUG, 
		"[process] killed with active mem threadcount (active %d)\n", 
		ipd->threadcount);
    else
    	Map_reap(m);
  }

  printkx(PK_THREAD, PK_DEBUG, "[process] %d removed\n", id);
}

/** systemwide initialization of the process subsystem */
void ipd_init(void) 
{
  process_table = hash_new(NUM_ID_BUCKETS, sizeof(IPD_ID));
  kernelIPD = ipd_new();
  kernelMap->owner = kernelIPD;
}

IPD *
ipd_find(IPD_ID ipd_id) 
{
  IPD *ipd;

  P(&process_table_mutex);
  ipd = hash_findItem(process_table, (char *) &ipd_id);
  V(&process_table_mutex);

  assert(!ipd || ipd->id == ipd_id);

  return ipd;
}

void 
ipd_iterate(Func f, void *ctx) 
{
  P(&process_table_mutex);
  hash_iterate(process_table, f, ctx);
  V(&process_table_mutex);
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

//////// Thread Accounting ////////////////

/* Keep track of uthreads so an entire ipd (and all uthreads) can be killed */
void ipd_add_uthread(IPD *ipd, UThread *ut, int *id){
  P(&ipd->mutex);
  hash_insert(ipd->uthreadtable, id, ut);
  V(&ipd->mutex);
}

void ipd_rm_uthread(IPD *ipd, int *id){
  P(&ipd->mutex);
  hash_delete(ipd->uthreadtable, id);
  V(&ipd->mutex);
}

/** private iterator */
static void 
ipd_killall_helper(BasicThread *t, void *unused) 
{
  if (t != nexusthread_self())
    nexusthread_kill(t);
}

/** kill all threads belonging to a process */
void 
ipd_killall(IPD *ipd) 
{
  P(&ipd->mutex);
  hash_iterate(ipd->uthreadtable, (Func)ipd_killall_helper, NULL);
  V(&ipd->mutex);
}

void ipd_start_all_not_run(IPD *ipd){
  P(&ipd->mutex);
  hash_iterate(ipd->uthreadtable, (Func) nexusthread_start_if_not_run, NULL);
  V(&ipd->mutex);
}

//////// Device I/O ////////////////

NexusOpenDevice *ipd_get_open_device(IPD *ipd, int dt, int handle) {
	NexusOpenDevice *nod = queue_gethead(&ipd->open_devices);
	if (handle < 0) {
		// find any of correct type
		while (nod && nod->nd->type != dt)
			nod = queue_getnext(nod);
	} else {
		while (nod && handle-- > 0)
			nod = queue_getnext(nod);
		if (nod && dt > 0 && nod->nd->type != dt)
			nod = NULL;
	}
	return nod;
}

// XXX need sema ?
int ipd_add_open_device(IPD *ipd, NexusOpenDevice *nod) {
	assert(ipd && !nod->ipd);
	nod->ipd = ipd;
	if (is_focused(ipd))
		set_focus(nod);
	int handle = queue_length(&ipd->open_devices);
	queue_append(&ipd->open_devices, nod);
	return handle;
}

int PDBR_hasFramebuffer(Page *pdbr) {
  return pdbr->u.fb.pdoffset != FB_INVALID_PDOFFSET;
}

static inline int ipd_fb_num_pages(IPD *ipd) {
  return (ipd->fb.length + PAGE_SIZE - 1) / PAGE_SIZE;
}


static void ipd_fb_saverestore(IPD *ipd, int is_save) {
  int num_pages = ipd_fb_num_pages(ipd);
  int pagenum;
  for(pagenum = 0; pagenum < num_pages; pagenum++) {
    int copy_len;
    char *src, *dst;
    if(pagenum < num_pages - 1) {
      copy_len = PAGE_SIZE;
    } else {
      // last page
      copy_len = ipd->fb.length % PAGE_OFFSET_MASK;
    }
    void *fb_addr = ipd->fb.data + pagenum * PAGE_SIZE;
    void *shadow_addr = (char *)PHYS_TO_VIRT(ipd->fb.shadow[pagenum]);
    if(is_save) {
      src = fb_addr;
      dst = shadow_addr;
    } else {
      dst = fb_addr;
      src = shadow_addr;
    }
    memcpy(dst,src,copy_len);
  }
}

void ipd_fb_save(IPD *ipd) {
  return ipd_fb_saverestore(ipd, 1);
}

void ipd_fb_restore(IPD *ipd) {
  return ipd_fb_saverestore(ipd, 0);
}

void ipd_fb_remap(IPD *ipd, Page *pdbr, FB_RemapMode map_mode) {
  int intlevel = disable_intr();

  //
  // Map or unmap framebuffer
  //
  if(!PDBR_hasFramebuffer(pdbr)) {
    // no frame buffer mapped in. Not all pdbrs in a Xen IPD will have
    // frame buffer mapped in
    restore_intr(intlevel);
    return;
  }

  pdbr->u.fb.is_mapped = (map_mode == FB_MAP_VIDEO);

  int pdoffset;
  int num_pages = ipd_fb_num_pages(ipd);
  int pagenum = 0;
  for(pdoffset = pdbr->u.fb.pdoffset; pagenum < num_pages; pdoffset++) {
    int i;
    Page *page_table = PDBR_getPagetable(pdbr, pdoffset << PDIR_SHIFT);
    // printk_red(" pdoffset=%d, pagenum=%d,num_pages=%d ", pdoffset, pagenum, num_pages);
    assert(page_table != NULL);
    
    PageTableEntry *ptes = (PageTableEntry *)VADDR(page_table);
    for(i=0; i < PTABLE_ENTRIES && pagenum < num_pages; i++) {
      __u32 paddr;
      char *fb_pos = ipd->fb.data + pagenum * PAGE_SIZE;
      PageTableEntry *pte = &ptes[i];

      switch(map_mode) {
      case FB_MAP_VIDEO:
	paddr = PDBR_virtToPhys_nocheck(pdbr, (__u32)fb_pos);
	goto update_valid_map;
	break;
      case FB_MAP_MEM:
	paddr = ipd->fb.shadow[pagenum];
      update_valid_map:
	*(__u32 *)pte = 0;
	pte->pagebase = paddr >> PAGE_SHIFT;
	pte->rw = 1;
	pte->user = 1;
	if(1) {
	  // XXX Set PAT flags instead
	  pte->writethrough = 0;
	  pte->uncached = 0;
	}
	PageTableEntry_makePresent(pte);
	break;
      case FB_MAP_NOTHING:
	// Zero it out to avoid confusing guest
	*(__u32*)pte = 0;
	break;
      default:
	assert(0);
      }
      pagenum++;
    }
  }

  if(readcr3() == PADDR(pdbr)) {
    flushTLB();
  }
  restore_intr(intlevel);
}

void ipd_PDIR_activated(IPD *ipd, Map *m) {
  int intlevel = disable_intr();
  int _is_focused = !!is_focused(ipd); 

  int map_in = 0;
  int do_map = 0;
  Page *pdbr = Map_getRoot(m);

  if(!PDBR_hasFramebuffer(pdbr)) {
    restore_intr(intlevel);
    return;
  }

  if( unlikely(!pdbr->u.fb.is_mapped && _is_focused) ) {
    // map gains focus
    map_in = 1;
    do_map = 1;
  } else if( unlikely(pdbr->u.fb.is_mapped && !_is_focused) ) { // must be else if since we change the test flags in each branch
    map_in = 0;
    do_map = 1;
  }

  if( unlikely(do_map) ) {
    ipd_fb_remap(ipd, Map_getRoot(m), map_in ? FB_MAP_VIDEO : FB_MAP_MEM);
  }

  assert(pdbr->u.fb.is_mapped == _is_focused);
  restore_intr(intlevel);
}

int ipd_fb_unmap(IPD *ipd, Page *pdbr) {
  if(!ipd_hasMappedFB(ipd)) {
    return -SC_INVALID;
  }
  // must do remap before clearing FB metadata from pdbr
  ipd_fb_remap(ipd, pdbr, FB_MAP_NOTHING);

  pdbr->u.fb.pdoffset = FB_INVALID_PDOFFSET;
  pdbr->u.fb.is_mapped = 0;
  return 0;
}

//////// Connection Accounting ////////////////

/** Add the given connection to the ipd. This binds the ipd as client.
    
    @param requested_handle requests a nr. or -1 for arbitrary (recommended) */
Connection_Handle
ipd_addConnection(IPD *ipd, IPC_Connection *connection, 
		  Connection_Handle requested_handle)
{
  Connection_Handle rv;
  int level;
  
  level = disable_preemption();
  rv = HandleTable_add_ext(&ipd->conn_handle_table, connection, 
		  	   requested_handle);
  restore_preemption(level);

  if (rv < 0)
    return rv;

  if (connection != RESERVED_CONNECTION)
  	IPCConnection_get(connection);
  return rv;
}

void 
ipd_delConnection(IPD *ipd, Connection_Handle conn_handle) 
{
  IPC_Connection *connection;
  int level;
  
  BUG_ON_INTERRUPT();

  level = disable_preemption();
  connection = HandleTable_find(&ipd->conn_handle_table, conn_handle);
  assert(connection);
  HandleTable_delete(&ipd->conn_handle_table, conn_handle);
  restore_preemption(level);

  if (connection != RESERVED_CONNECTION)
  	IPCConnection_put(connection);
}

IPC_Connection *
ipd_findConnection(IPD *ipd, Connection_Handle conn_handle) 
{
  IPC_Connection *rv;
  int level;

  level = disable_preemption();
  rv = HandleTable_find(&ipd->conn_handle_table, conn_handle);
  restore_preemption(level);

  // entry is reserved, but holds no valid connection
  if (unlikely(rv == RESERVED_CONNECTION))
    rv = NULL;

  if (rv)
    IPCConnection_get(rv);

  return rv;
}


/** Destroy all ports associated with a process */
void 
ipd_destroy_all_ports(IPD *ipd) 
{
	// XXX cleanup ports
}

// interator
static void 
__del_conn(Connection_Handle handle, void *obj, IPD *ipd) 
{	
	HandleTable_delete(&ipd->conn_handle_table, handle);		
	if (obj != RESERVED_CONNECTION) {
    		//IPCConnection_close(connection);
    		//IPCConnection_put(connection);
	}
}

static void
IPD_del_all_conn_handles(IPD *ipd)
{
    P(&ipd->mutex);					
    HandleTable_iterate(&ipd->conn_handle_table,			
			(HandleTable_IterateFunc)			
			__del_conn, ipd);		
    V(&ipd->mutex);					
}

//////// Call Accounting ////////////////

// the +1 only exists because the IDL interprets a 0 handle differently in
// ...ProcessNext. XXX: update the IDL and remove this hack.
Call_Handle 
ipd_addCall(IPD *ipd, IPC_CommonClientContext *common_ctx) 
{
  return HandleTable_add_noint(&ipd->call_handle_table, common_ctx) + 1;
}

IPC_CommonClientContext *
ipd_findCall(IPD *ipd, Call_Handle handle) 
{
  BUG_ON_INTERRUPT();
  return HandleTable_find_noint(&ipd->call_handle_table, handle - 1);
}

void
ipd_delCall(IPD *ipd, Call_Handle handle)
{
  HandleTable_delete_noint(&ipd->call_handle_table, handle - 1);
}

//////// NSK Support ////////////////

int ipd_set_nsk(IPD *ipd, KVKey_nsk *nsk) {
  int err = 0;

  P(&ipd->mutex);
  if (!ipd->nsk)
    ipd->nsk = nsk;
  else
    err = -1;
  V(&ipd->mutex);

  return err;
}

KVKey_nsk *ipd_get_nsk(IPD *ipd) {
  return ipd->nsk;
}

Form *ipd_get_nsk_form(IPD *ipd) {
  KVKey_nsk *nsk = ipd->nsk;
  if (!nsk) return term_fmt("anonymous");
  char *nskbuf = kvkey_serialize_pub(&nsk->pub);
  if (!nskbuf) return term_fmt("anonymous");
  return term_fmt("der(%{bytes})", nskbuf, der_msglen(nskbuf));
}

Form *ipd_get_speaker(IPD *ipd) {
  KVKey_nsk *nsk = ipd->nsk;
  if (!nsk) return term_fmt("anonymous");
  char *nskbuf = kvkey_serialize_pub(&nsk->pub);
  if (!nskbuf) return term_fmt("anonymous");
  Form *prin = term_fmt("der(%{bytes}).ipd(%{int}, %{int})",
      nskbuf, der_msglen(nskbuf), NEXUSBOOTNUM, ipd->id);
  gfree(nskbuf);
  return prin;
}

Form *ipd_says(IPD *ipd, Form *stmt) {
  return form_fmt("%{term} says %{Stmt}", ipd_get_speaker(ipd), stmt);
}

//////// Various ////////////////

int ipd_isXen(IPD *ipd) {
  return ipd->type == XEN;
}

void 
ipd_setName(IPD *ipd, const char *new_name) 
{
  strncpy(ipd->name, new_name, MAX_IPD_NAMELEN);
  ipd->name[MAX_IPD_NAMELEN - 1] = '\0';
}

/** Start a process, where the executable is passed from userspace (unsafe) 

    @param elf an executable
    @param arg all arguments incl. the filename are passed as a single 
           string to make it easier to copy args into the kernel. 
 
    Serialization of args is fragile with regards to quoted strings
    For instance, [cat "hello world"] will not be parsed correctly.
    XXX replace with communicating char** across kernel boundary
 */
int
ipd_exec(const unsigned char *elf, int len, const char *arg) 
{
#define isalpha(car) ((car >= 'a' && car <= 'z') || (car >= 'A' && car <= 'Z')) 
#define isblank(car) (car == ' ' || car == '\t' || car == '\n')
   UThread *thread;
   IPD *process;
   char *kelf, *karg, **av, *kname = NULL; 
   int alen, ac, ac_off, i;
   
   // sanity check
   if (!elf || !len || !arg)
     return -SC_INVALID;

   // copy file and arguments
   alen = peek_strlen(nexusthread_current_map(), (unsigned int) arg);
   karg = galloc(alen + 1);
   kelf = galloc(len);
   
   peek_user(nexusthread_current_map(), (unsigned int) elf, kelf, len);
   peek_user(nexusthread_current_map(), (unsigned int) arg, karg, alen);
   karg[alen] = '\0';

   // create char ** from args
   if (!isalpha(karg[0]))
   	return -SC_INVALID;

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

  if (!thread) {
    //XXX cleanup : ipd_destroy(); Map_destroy(kspace);
    return -1;
  }

  // execute
  nexusthread_start((BasicThread *) thread, 0);
  return process->id;
}

