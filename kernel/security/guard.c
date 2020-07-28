/** NexusOS: Access control guard */

#include <nexus/defs.h>
#include <nexus/user_compat.h>

#include <linux/ctype.h>
#include <linux/kernel.h>

#include <nexus/vector.h>
#include <nexus/formula.h>
#include <nexus/policy.h>
#include <nexus/guard.h>
#include <nexus/hashtable.h>
#include <nexus/debug.h>

#include <../code/guard-code.c>
#include <../code/guard_pf.c>
#include <../code/guard_eval.c>
#include <../code/guard_cred.c>

#include <nexus/synch-inline.h>
#include <nexus/hashtable.h>
#include <nexus/defs.h>
#include <nexus/galloc.h>
#include <nexus/ipc.h>
#include <nexus/printk.h>
#include <nexus/syscall-defs.h>

#include <nexus/FS.kernel-interface.h>

static struct HashTable *guard_table;

/** Tag all IPC ports that are guarded. 
    Only for these will the guard be called */
static struct HashTable *guarded_porttable;
static Sema guard_mutex = SEMA_MUTEX_INIT;

static void
nxguard_init(void)
{
	/** XXX ugly hack. integrate initialization in init.c */
	static int initialized;

	if (!initialized) {
		initialized = 1;
		guard_table = hash_new(2711 /* reasonably sized prime*/, sizeof(FSID));
		guarded_porttable = hash_new(2711, sizeof(Port_Num));
	}
}

/** Attach a policy expressed as NAL proof 
 
    @param formula is a human-readable expression 
           or NULL to clear the policy
 	   XXX replace with der notation 
 */
void
nxguard_chgoal(FSID object, int operation, const char *nal_formula)
{
	Form *formula = NULL;
	Guard *guard;

	// sanity check input
	if (nal_formula) {
		formula = form_fmt((char *) nal_formula);

		if (!form_is_proper(formula)) {
			printk_current("[guard] not a proper formula\n");
			return;
		}
	}

	P(&guard_mutex);
	
	nxguard_init();

	// remove old policy (if any)
	guard = hash_findItem(guard_table, &object);
	if (guard)
		hash_delete(guard_table, &object);
	
	if (formula) {
		// create
		guard = guard_create();
		guard_setgoal(guard, form_to_der(formula));

		// insert new policy
		hash_insert(guard_table, &object, guard);

		// intercept requests to this server
		if (!hash_findItem(guarded_porttable, &object.port))
			hash_insert(guarded_porttable, &object.port, 
				   (void *) object.port);	
	}

	V(&guard_mutex);

	printk_current("[guard] OK. goal [%s] set on %d.%llu\n",  
		       formula ? form_to_pretty(formula, 0) : "", 
		       object.port, (unsigned long long) object.nodeid);
}

/** Sole policy enforcement point: allow or deny the call to go through. 

    Requires unique subject and object identifiers: IPD id and FSID
    @param action is object specific. use static default 0 to omit it

    @return 0 on allow, any other means deny. 				*/
static int 
__nxguard_verify(FSID object, int subject, int action)
{
	_Grounds *grounds;
	Guard *guard;
	int ret = 0;

	nxguard_init();

	P(&guard_mutex);	// XXX: this may be a highly contended lock
	guard = hash_findItem(guard_table, &object);

	// trivially allow without a guard
	if (guard) {
		// hardcode FS policy
		Cred cred_owner, cred_action;
		char fml[80];
		int flen;

		// create proof
		grounds = gcalloc(1, sizeof(*grounds));

		// create grounds
		// XXX replace at least one with an authority
		sprintf(fml, "owner = %d", subject);
		cred_owner.tag = CRED_BOGUS;
		cred_owner.data = (char *) form_to_der(form_from_pretty(fml));	// XXX fix memleak
		cred_owner.open = cred_bogus_open;

		sprintf(fml, "action = %d", action);
		cred_action.tag = CRED_BOGUS;
		cred_action.data = (char *) form_to_der(form_from_pretty(fml));	// XXX fix memleak
		cred_action.open = cred_bogus_open;

		grounds->numleaves = 2;
		grounds->leaves = galloc(sizeof(void *) * grounds->numleaves);
		grounds->leaves[0] = &cred_owner;
		grounds->leaves[1] = &cred_action;

		// check proof against policy
		if (guard_check(guard, NULL, grounds))
			ret = -1;
		
		gfree(grounds->hints);
		gfree(grounds);
	}

	V(&guard_mutex);
	
	return ret;
}

/** Convenience wrapper around __nxguard_verify extracts request from msg. */
int 
nxguard_verify(Port_Num dest_port, Map *map, char *msg, int mlen, int ipd)
{ 
	FSID object;
	char *localmsg;	
	int action;
	int ret;

	// XXX take out of datapath
	nxguard_init();

	ret = (int) hash_findItem(guarded_porttable, &dest_port);
	if (ret != dest_port)
		return 0;

	// XXX drop: duplicate copy, also done in RecvCallHelper
	localmsg = galloc(mlen);
	transfer_user(NULL, (unsigned int) localmsg, map, (unsigned int) msg, mlen);

	action = *(int *) localmsg;
	if (mlen < sizeof(int) + sizeof(void *) + sizeof(FSID)) {
		printk_current("FS: call %d too short\n", action);
		return 0;
	}

	/* 1st arg is always res, 2nd is always FSID (for FS) . get that */
	memcpy(&object, localmsg + sizeof(int) + sizeof(void*), sizeof(FSID)); 

	ret = __nxguard_verify(object, ipd, action);
	printk_current("NXDEBUG: [guard] verify returned %d\n", ret);

	gfree(localmsg);
	return ret;
}

