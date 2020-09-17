/** NexusOS: Access control guard */

#include <nexus/defs.h>
#include <nexus/galloc.h>
#include <nexus/ipc.h>
#include <nexus/ipc_private.h>  // for ipc_recv
#include <nexus/elf.h>
#include <nexus/printk.h>
#include <nexus/profiler.h>
#include <nexus/fs.h>
#include <nexus/test.h>
#include <nexus/guard.h>
#include <nexus/guard-impl.h>
#include <nexus/bitmap.h>
#include <nexus/syscall-defs.h>

#include <nexus/IPC.interface.h>
#include <nexus/Guard.kernel-interface.h>

// configuration parameters
#define NXGUARD_ENABLE_CACHE	1
#define NXGUARD_DISABLED	0	///< debugging. SECURITY BREACH if !0
#define NXGUARD_VISIBLE		1
#define NXGUARD_DEBUG_CLR	0
#define MAX_COLLISION		2	///< how far to go with linear probing

// refmon cachesize. change both macros together to ensure consistency
#define REFMON_CACHE_PGLEN	(10)
#define REFMON_CACHE_SIZE	(REFMON_CACHE_PGLEN << PAGE_SHIFT)
#define REFMON_CACHE_MASK	(PAGE_SIZE - 1)

int nxguard_kern_ready;
int nxguard_log_enable = 0;

// guard cache. shared by all objects
struct HashTable *guard_porttable;	///< controlling guard for an object
char * guard_cache;
int guard_collisions, guard_upcalls_refmon, guard_upcalls_guard, guard_calls;


//////// decision cache implementation

// exponent in base-2 of structure size (2^{5})
#define DCACHE_ENTRY_POW	(5)

// Size of kernel cache. MUST be power of two
#define DCACHE_BYTESIZE		(1 << 20)
#define DCACHE_MASK		(DCACHE_BYTESIZE - 1)
#define DCACHE_ELEMCOUNT	(DCACHE_BYTESIZE >> DCACHE_ENTRY_POW)

// Number of elemens in a region
// in the guard, all elements with the same operation and object hash
// to the same region, to allow simple clearing when the goal changes
#define DCACHE_REGION_POW	(8)
#define DCACHE_REGION_BYTEPOW	(DCACHE_REGION_POW + DCACHE_ENTRY_POW)
#define DCACHE_REGIONCOUNT	(1 << DCACHE_REGION_POW)
#define DCACHE_REGIONSIZE	(1 << DCACHE_REGION_BYTEPOW)

#define MSG_START(msg)		((void *) (msg + sizeof(int) + sizeof(void *)))

/// hash over <operation, object>>
static inline unsigned long
dcache_hash_duo(struct nxguard_tuple *tuple, unsigned long elemsize_pow, 
		unsigned long mask)
{
	unsigned long key;

	// hash
#if 0
	key = SuperFastHash((char *) &tuple->operation, 
			    sizeof(int) + sizeof(unsigned long long) + sizeof(unsigned long long));
#else
#define HASH_PRIME 150000157		///< arbitrary prime > DCACHE_BYTESIZE
	key = tuple->operation + tuple->object.upper + tuple->object.lower;
	key = key * (key + 3);
	key = key % HASH_PRIME;
#endif

	// translate item offset -> byte offset
	key = key << elemsize_pow;

	// wrap 
	key = key & mask;
	
	assert(key + (1 << elemsize_pow) - 1 <= mask);
	return key;
}

static struct nxguard_tuple null_tuple;

/** Compare tuples. @return memcmp convention */
static inline int
dcache_cmp_tuples(struct nxguard_tuple *a, struct nxguard_tuple *b)
{
	if (a->operation != b->operation ||
	    a->subject != b->subject || 
	    a->object.upper != b->object.upper ||
	    a->object.lower != b->object.lower)
		return 1;
	else
		return 0;
}

/** Find an element using linear probing, starting at entry */
static unsigned int
dcache_get_linear(char *cache, unsigned long mask, struct dcache_elem *entry,
		    struct nxguard_tuple *tuple, int *collision_counter)
{
	int i;

	for (i = 0; i < MAX_COLLISION; i++) {
		
		// hit? then return decision
		if (likely(!dcache_cmp_tuples(&entry->tuple, tuple)))
			return entry->decision;
		
		// empty? then will set it after asking refmon
		if (likely(!dcache_cmp_tuples(&entry->tuple, &null_tuple)))
			return AC_UNKNOWN;

		// inc (and wrap)
		entry++;
 		if ((void *) entry > (void *) cache + mask + 1 - sizeof(*entry))
			entry = (void *) cache;
	}

#ifndef NDEBUG
	// not found
	if (collision_counter) {
		atomic_addto(collision_counter, 1);
		if (((*collision_counter) | 0xf) == 0)
			printk_red("[kguard] %u collisions in process %d\n", 
				   *collision_counter, 
				   cache == guard_cache ? -1 : curt->ipd->id);
	}
#endif

	return AC_UNKNOWN;
}

/** Find an empty slot or matching entry using linear probing, start at entry 
    @return 0 on success, 1 if failed to set */
static inline int 
dcache_set_linear(char *cache, unsigned long mask, struct dcache_elem *entry, 
		  struct nxguard_tuple *tuple, unsigned int decision)
{
	int i;

	// find entry. use linear probing in case of collisions (good cache behavior)
	for (i = 0; i < MAX_COLLISION; i++) {
	
		// reset existing entry
		if (likely(!dcache_cmp_tuples(&entry->tuple, tuple))) {
			// NB: it is unlikely, but not impossible that two
			// threads simultaneously notice a cache miss and
			// ask the guard, then call dcache_set and arrive here
			entry->decision = decision;
		}
		
		// empty? then fill
		if (likely(!dcache_cmp_tuples(&entry->tuple, &null_tuple))) {
			entry->tuple = *tuple;
			entry->decision = decision;
			return 0;
		}
		
		// inc (and wrap)
		entry++;
		if ((void *) entry > (void *) cache + mask + 1 - sizeof(*entry))
			entry = (void *) cache;
	}
	
	return 1;
}

/** Lookup a refmon-cache element by tuple */
static inline struct dcache_elem *
dcache_hash_refmon(struct nxguard_tuple *tuple)
{
	unsigned long key;

	// lookup entry
	key = dcache_hash_duo(tuple, DCACHE_ENTRY_POW, REFMON_CACHE_MASK);
	return (void *) &curt->ipd->refmon_cache[key];
}


/** Lookup a decision in a reference monitor cache */
static inline unsigned int
dcache_get_refmon(struct nxguard_tuple *tuple)
{
	struct dcache_elem *entry;

	assert(curt->ipd->refmon_cache);
	entry = dcache_hash_refmon(tuple);
	return dcache_get_linear(curt->ipd->refmon_cache, 
	 		           REFMON_CACHE_MASK, entry, tuple,
				   &curt->ipd->refmon_collisions);
}

static inline void
dcache_set_refmon(struct nxguard_tuple *tuple, unsigned int decision)
{
	struct dcache_elem *entry;
	
	assert(curt->ipd->refmon_cache);
	assert(curt->ipd->id == tuple->subject);
	entry = dcache_hash_refmon(tuple);
	dcache_set_linear(curt->ipd->refmon_cache, 
			  REFMON_CACHE_MASK, 
			  entry, tuple, decision);
}

/** Calculate the entry in the table for a tuple */
static inline unsigned long
dcache_hash_guard(struct nxguard_tuple *tuple)
{
	unsigned long region, offset;
	
	// lookup region by hash over operation and object
	region = dcache_hash_duo(tuple, DCACHE_REGION_BYTEPOW, DCACHE_MASK);

	// lookup offset within region by 'hash' over subject
	offset = tuple->subject & (DCACHE_REGIONCOUNT - 1);
	
	assert((region & (DCACHE_REGIONCOUNT - 1)) == 0);
	assert(region + offset + sizeof(*tuple) < DCACHE_BYTESIZE);
	
	// save in region
	return region + offset;
}

/** Empty the cache region that stores entries for <*, operation, object> */
static void
dcache_reset_goal(struct nxguard_tuple *tuple)
{
	unsigned long region;

	region = dcache_hash_duo(tuple, DCACHE_REGION_BYTEPOW, DCACHE_MASK);
	memset(guard_cache + region, 0, DCACHE_REGIONSIZE);
}

/** Try cached decision 
    @return the same as a userspace guard: one of AC_...  */
static int 
dcache_get_guard(struct nxguard_tuple *tuple)
{
	struct dcache_elem *entry;

	entry = (void *) (guard_cache + dcache_hash_guard(tuple));
	return dcache_get_linear(guard_cache, DCACHE_MASK, entry, tuple,
				   &guard_collisions);
}

/** Update a cache entry */
static void
dcache_set_guard(struct nxguard_tuple *tuple, int decision)
{
	struct dcache_elem *entry = (void *) (guard_cache + dcache_hash_guard(tuple));

	if (dcache_set_linear(guard_cache, DCACHE_MASK, 
			      entry, tuple, decision)) {
		
		// overwrite entry (heuristic: newer is more likely to be seen next)
		entry = (void *) (guard_cache + dcache_hash_guard(tuple));
		entry->tuple = *tuple;
		entry->decision = decision;
	}
}


//////// kguard

/// The guard has to be reentrant, to support preemption and authorities 
//  calling back into the guard (that have been called by the guard)
int
nxkguard_init(void)
{
	int port, pid, i;
	
#if NXGUARD_DISABLED
	printk_red("[guard] DISABLED\n");
	return 0;
#endif
	assert(sizeof(struct dcache_elem) == 32);

	// initialize guard datastructures
	guard_cache      = gcalloc(1, DCACHE_BYTESIZE);
  	guard_porttable  = hash_new(4096, sizeof(struct nxguard_object));

	// start port to listen for 'guard ready'
	i = IPC_CreatePort(guard_init_port);
	if (i != guard_init_port) {
		printk_current("[guard] failed to start guard as first process. HALTING\n");
		nexuspanic();
	}

	// start initial guard
#if NXGUARD_VISIBLE
	pid = elf_exec("guard_svc.app", 0 /* PROCESS_QUIET */, 2, 
		       (char *[]) { (char *) "guard_svc.app", "--debug", NULL });
#else
	pid = elf_exec("guard_svc.app", PROCESS_QUIET, 1, 
		       (char *[]) { (char *) "guard_svc.app", NULL });
#endif

	if (pid != 1) {
		printk_current("[guard] failed to start guard as first process. HALTING\n");
		nexuspanic();
	}

	// wait until guard is ready
	if (IPC_Recv(guard_init_port, &port, sizeof(port)) != sizeof(port)) {
		printk_current("[guard] failed to connect to guard\n");
		nexuspanic();
	}

#if NXGUARD_ENABLE_CACHE == 0
	printk_red("[guard] cache disabled\n");
#endif
	// open ports for the guard to send replies to access control questions
	swap(&nxguard_kern_ready, 1);
	return 0;
}

static void
nxkguard_reset_proof(char *msg)
{
	struct nxguard_tuple *tuple;
	int lvl;

	tuple = MSG_START(msg);
	lvl = disable_intr();
	dcache_set_guard(tuple, AC_UNKNOWN);
	restore_intr(lvl);
#if NXGUARD_DEBUG_CLR
	printk_green("[dcache] clr proof key=%d\n", dcache_hash_guard(tuple));
#endif
}

static void
nxkguard_reset_goal(char *msg, int ipcport)
{
	struct nxguard_tuple *tuple;
	int lvl;

	// extract embedded tuple
	tuple = (void *) (msg + (sizeof(int) + sizeof(void *)));

	// clear cache region and update guard ipc port
	lvl = disable_intr();
	dcache_reset_goal(tuple);
	hash_delete(guard_porttable, &tuple->object);
	hash_insert(guard_porttable, &tuple->object, (void *) ipcport);
	restore_intr(lvl);

#if NXGUARD_DEBUG_CLR 
	printk_green("[dcache] clr goal *.%u.%llu.%llu -> region [%d, ..]\n", 
		     tuple->operation, tuple->object.upper, tuple->object.lower,
		     (dcache_hash_region(tuple)) << DCACHE_REGION_POW);
#endif
}

/** Extract object from message: an opcode-specific operation */
static void
nxkguard_object_get(struct nxguard_tuple *tuple, char *msg, int mlen)
{
	// demultiplex: IPC
	if (tuple->operation >= SYS_IPC_Send_CMD &&
	    tuple->operation <= SYS_IPC_RecvPage_CMD) {
		int *portnum;
		
		portnum = MSG_START(msg);
		tuple->object.upper = 0;
		tuple->object.lower = *portnum;
	}
	
	// demultiplex: FS
	else if (tuple->operation >= SYS_FS_Pin_CMD && 
	        tuple->operation  < SYS_FS_Pin_CMD + 1000) {
		tuple->object.upper = 0;
		tuple->object.lower = 0;
		memcpy(&tuple->object.fsid, MSG_START(msg), sizeof(FSID)); 
	}

	// demultiplex: Guard
	else if (tuple->operation >= SYS_Guard_GetGoal_CMD &&
	         tuple->operation <= SYS_Guard_SetProof_CMD) {
		struct nxguard_tuple *msgtuple = MSG_START(msg);
		tuple->object = msgtuple->object;
	}
	
	// ... extend with demultiplex #n for each encoding method

	// demultiplex default: no objects
	else {
		tuple->object.upper = 0;
		tuple->object.lower = 0;
	}
}

/** Portion of guard that is specific to the reference monitor */
static inline int
nxkguard_in_refmon(struct nxguard_tuple *tuple) 
{
	unsigned int ret, kret;
        int lvl;

	assert(curt->ipd->id == tuple->subject);

#if NXGUARD_ENABLE_CACHE
	// try in-kernel decision cache
	if (likely(curt->ipd->refmon_cache != NULL)) {
		lvl = disable_intr();
		kret = dcache_get_refmon(tuple);
		restore_intr(lvl);
		switch (kret) {
			case AC_BLOCK_CACHE: return 1;
			case AC_ALLOW_CACHE: return 0;
			// ... else fall through
		}
	}
#endif

	// ask refmon
	switch (curt->ipd->refmon_port) {
	case REFMON_PORT_ALLOWALL: ret = AC_ALLOW_CACHE; break;
	case REFMON_PORT_BLOCKALL: ret = AC_BLOCK_CACHE; break;
	default: ret = Guard_InterposeIn_ext(curt->ipd->refmon_port, *tuple);
#ifndef NDEBUG
		 atomic_addto(&guard_upcalls_refmon, 1);
#endif
	}

#if NXGUARD_ENABLE_CACHE
	// update in-kernel decision cache 
	if (ret & __AC_CACHE) {
		lvl = disable_intr();
		dcache_set_refmon(tuple, ret);
		restore_intr(lvl);
	}
#endif

	// block only if refmon says BLOCK
	assert(ret >= 1 && ret <= 7);
	return ret & __AC_ALLOW ? 0 : 1;
}

/** Portion of guard that is specific to access control */
static inline int 
nxkguard_in_accesscontrol(struct nxguard_tuple *tuple)
{
	long port;
	int key, ret;
	int lvl;		///< verified: much cheaper than P/P_reader

	lvl = disable_intr();
#if NXGUARD_ENABLE_CACHE
	// try in-kernel decision cache 
	ret = dcache_get_guard(tuple);
	if (likely(ret & __AC_CACHE)) {
		restore_intr(lvl);
		return (ret == AC_ALLOW_CACHE) ? 0 : 1;
	}
#endif

	// lookup process to contact
	port = (long) hash_findItem(guard_porttable, &tuple->object);
	restore_intr(lvl);

	if (!port)
		port = default_guard_port;
	
	ret = Guard_InterposeIn_ext(port, *tuple); 
#ifndef NDEBUG
	atomic_addto(&guard_upcalls_guard, 1);
#endif
	
	if (ret <= 0 || ret > 8) {
		printk_red("BUG: dirty guard (%d.%d.%llu.%llu -> %d) ignored\n", 
				tuple->subject, tuple->operation,
				tuple->object.upper, tuple->object.lower,
				ret);
		ret = AC_ALLOW_NOCACHE;
	}
	assert(ret >= 1 && ret <= 7);

#if NXGUARD_ENABLE_CACHE
	// update cache
	if (ret & __AC_CACHE) {
		lvl = disable_intr();
		dcache_set_guard(tuple, ret);
		restore_intr(lvl);
	}
#endif
	
	return ret & __AC_ALLOW ? 0 : 1;
}

/** Interpose on a request: call refmon and/or authorization guard 
    @param tuple must have the subject field filled in
    @return 0 to ALLOW a call to go through, !0 to BLOCK. */
int 
nxkguard_in(int ipcport, char *msg, int mlen, 
	    struct nxguard_tuple *tuple)
{ 
	int ret;

#if NXGUARD_DISABLED
	return 0;
#endif
#ifndef NDEBUG
	atomic_addto(&guard_calls, 1);
#endif

	assert(nxguard_kern_ready);
	assert(tuple->subject > 1);

	// fill in access control tuple
	tuple->operation = ((int *) msg)[0];
	if (unlikely(tuple->operation == SYS_Thread_Exit_CMD))
		return 0;
	nxkguard_object_get(tuple, msg, mlen);

	// ask reference monitor, if any
	if (unlikely(curt->ipd->refmon_port) &&
	    nxkguard_in_refmon(tuple))
		return 1;
	
	// ask access control guard 
	ret = nxkguard_in_accesscontrol(tuple);

	// reset decisions affected by guard control operations
	switch (tuple->operation) {
	case SYS_Guard_SetGoal_CMD:  nxkguard_reset_goal(msg, ipcport); break;
	case SYS_Guard_SetProof_CMD: nxkguard_reset_proof(msg); break;
	}
	
	return ret;
}

/** Interpose on return path */
void
nxkguard_out(struct nxguard_tuple *tuple)
{
	long port; 
	int lvl, ret;
	
	port = atomic_get(&curt->ipd->refmon_port);
#if NXGUARD_ENABLE_CACHE
	// only upcall for uncached decisions
	// (forcing refmons to either actively interpose 
	//  on both in/out or on neither)
	if (port > 0 && likely(curt->ipd->refmon_cache != NULL)) {
		lvl = disable_intr();
		ret = dcache_get_refmon(tuple);
		restore_intr(lvl);
		if (ret == AC_ALLOW_CACHE) 
			return;
	}
#endif
	if (port > 0)
		Guard_InterposeOut_ext(port, *tuple); 
}

static inline void
nxkguard_refmon_init(IPD *ipd)
{
	// XXX allow subjects to choose own cache size
	ipd->refmon_cache_pglen = REFMON_CACHE_PGLEN;
	ipd->refmon_cache = (void *) Map_alloc(ipd->map, 
					       ipd->refmon_cache_pglen, 
			                       1, 0, vmem_heap);
}

/** Install interpositioning on a <subject, oper, *> tuple IF not already set: 
    we cannot reasonably clear the kernel cache once set, so once installed
    interpositioning currently cannot be undone for a given process.
   
    Also, a process must not be able to attach a reference monitor to a
    previously initialized cache, as that can generate a false sense of
    security, as certain actions will never be caught by the guard.

    @return 0 on success, the already set port on failure */
int
nxkguard_interposition_set(IPD *ipd, long ipcport)
{
	if (ipd->refmon_port)
		return ipd->refmon_port;

	nxkguard_refmon_init(ipd);
	ipd->refmon_port = ipcport;
	return 0;
}

/** Begin voluntary privilege dropping by resetting the decision cache
    All subsequent operations will gradually set the cache */
int 
nxkguard_record_begin(void)
{
    	// To avoid gaining privileges that were previously removed, the
    	// cache may only be cleared if no reference monitor is set 
    	// (reference monitors cannot be detached) 
	if (curt->ipd->refmon_port || curt->ipd->refmon_cache)
		return -1;

	nxkguard_refmon_init(curt->ipd);
	curt->ipd->refmon_port = REFMON_PORT_ALLOWALL;
	return 0;
}

/** Finalize the list of permitted operations by installing a
    reference monitor that blocks all subsequent requests */
int
nxkguard_record_end(void)
{
	swap(&curt->ipd->refmon_port, REFMON_PORT_BLOCKALL);
	return 0;
}

int 
nxkguard_allow(long subject, long operation, struct nxguard_object object)
{
	struct nxguard_tuple tuple;
	int lvl;

	if (curt->ipd->refmon_port != REFMON_PORT_ALLOWALL)
		return -1;

	tuple.subject 	   = subject;
	tuple.operation    = operation;
	tuple.object	   = object;

	lvl = disable_intr();
	dcache_set_refmon(&tuple, AC_ALLOW_CACHE);
	restore_intr(lvl);
	return 0;
}

/** Drop the privilege to execute a particular operation on an object
    This sets the process's refmon cache entry to BLOCK_CACHE. Unlike
    entries in the guard database, entries in refmon caches are never 
    cleared. They therefore serve as proof of dropped privilege.
 
    This method creates a blacklist of forbidden operations, together
    with an ALLOWALL wildcard. For a whitelist solution, see record, above.
    @return 0 on success or -1 on failure */
int
nxkguard_drop(long subject, long operation, struct nxguard_object object)
{
	struct nxguard_tuple tuple;
	int key, port, lvl;

	port = nxkguard_interposition_set(curt->ipd, REFMON_PORT_ALLOWALL);
	if (port && port != REFMON_PORT_ALLOWALL)
		return 1;

	curt->ipd->refmon_port = REFMON_PORT_ALLOWALL;

	tuple.subject 	   = subject;
	tuple.operation    = operation;
	tuple.object	   = object;

	lvl = disable_intr();
	dcache_set_refmon(&tuple, AC_BLOCK_CACHE);
	restore_intr(lvl);
	return 0;
}

/** Kernel equivalent of userspace function. 
    Differences: - kernel does not have to sign its statements
                 - kernel does not understand DER format, sends plaintext */
int 
nxguard_cred_add_raw(const char *in_fml)
{
	return Guard_AddCred_ext(default_guard_port, VARLENSTR(in_fml));
}

int
nxkguard_getsize(void)
{
	return REFMON_CACHE_SIZE;
}

#ifndef NDEBUG

int 
nxkguard_unittest(void)
{
#define TEST_LEN	(1 << 10)
#define TEST_MASK	(TEST_LEN - 1)

	struct nxguard_tuple tuple;
	unsigned long key, key2, ret;

#if NXGUARD_DISABLED
	// skip test if guard is disabled
	return 0;
#endif

	// test basic hashing
	memset(&tuple, 0, sizeof(tuple));
	key = dcache_hash_duo(&tuple, 0, TEST_MASK);
	tuple.object.upper = 1;
	key2 = dcache_hash_duo(&tuple, 0, TEST_MASK);
	if (key == key2)
		ReturnError(1, "kcache: neighbors hash to the same value");
	if ((key & ~(TEST_MASK)) != (key2 & ~(TEST_MASK)))
		ReturnError(1, "kcache: neighbors not in same region\n");

	// test empty database
	memset(guard_cache, 0, DCACHE_BYTESIZE);
	ret = dcache_get_guard(&tuple);
	if (ret != AC_UNKNOWN)
		ReturnError(1, "kcache: not zero when expected\n");
	if (ret != dcache_get_guard(&tuple))
		ReturnError(1, "kcache: inconsistent replies\n");

	// test decision insertion
	// first insert: saved should be identical
	ret = AC_ALLOW_CACHE;
	dcache_set_guard(&tuple, ret);
	if (dcache_get_guard(&tuple) != ret)
		ReturnError(1, "kcache: set failed #1\n");

	// second and conflict: must overwrite first
	ret = AC_BLOCK_CACHE;
	dcache_set_guard(&tuple, ret);
	if (dcache_get_guard(&tuple) != ret)
		ReturnError(1, "kcache: set failed #2\n");

	// reset system state
	memset(guard_cache, 0, DCACHE_BYTESIZE);
	return 0;
}

#endif

