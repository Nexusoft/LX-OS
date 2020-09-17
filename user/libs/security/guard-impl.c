/** NexusOS: serverside implementation of guard API */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <ctype.h>
#include <fcntl.h>
#include <malloc.h>

#include <openssl/md5.h>
#include <openssl/rsa.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <openssl/engine.h>

#include <nexus/defs.h>
#include <nexus/ipc.h>
#include <nexus/log.h>
#include <nexus/vector.h>
#include <nexus/formula.h>
#include <nexus/policy.h>
#include <nexus/guard.h>
#include <nexus/guard-impl.h>
#include <nexus/hashtable.h>
#include <nexus/debug.h>
#include <nexus/sema.h>
#include <nexus/test.h>
#include <nexus/nexuscalls.h>

#include <nexus/FS.interface.h>
#include <nexus/IPC.interface.h>
#include <nexus/Auth.interface.h>
#include <nexus/Thread.interface.h>
#include <nexus/ProcFS.interface.h>
#include <nexus/Debug.interface.h>

#include <../../../common/code/guard-code.c>
#include <../../../common/code/guard_pf.c>
#include <../../../common/code/guard_eval.c>

#define AUTHNAME_LEN 	(40)

/** Store hintcode proofs by the (subj, oper, obj) hash */
static struct HashTable *proofstore;

/** Store true "X says Y" statements by md5 of the statement */
static struct HashTable *credstore;

/** Store policy goals by (operating, object) */
static struct HashTable *goalstore;

/** Store stores authorities by the first N bytes of their public key */
static struct HashTable *namestore;

////////  Structures  ////////

/** Lock access to all structures */
static RWSema guard_rwlock;

int
nxguardsvc_init(void)
{
	FSID procnode;
	rand_init();

	rwsema_set(&guard_rwlock, 10);

	goalstore = hash_new(2711 /* reasonably sized prime */, sizeof(int));
	credstore = hash_new(2711, DIGESTLEN);
	proofstore = hash_new(2711, sizeof(struct nxguard_tuple));

	// create the authority database and claim the name 'guard'
	namestore = hash_new(283  /* reasonably sized prime */, PUBKEY_LEN);	
	if (nxguardsvc_name_add("guard", guard_authority_port))
		ReturnError(1, "failed to acquire name 'guard'");

	// export databases to /proc
	procnode = nxcall_fsid_byname("/proc");
	if (!FSID_isDir(procnode))
		ReturnError(1, "failed to open procfs");
	
	procfs_init(procnode);
	procfs_createdir_ex(NULL, "proofstore", proofstore,
			    procfs_readdir_hash_bin, NULL);
	procfs_createdir_ex(NULL, "labelstore", credstore,
			    procfs_readdir_hash_bin, procfs_read_string);
	procfs_createdir_ex(NULL, "goalstore",  goalstore, 
			    procfs_readdir_hash_int, NULL);
	procfs_createdir_ex(NULL, "authstore",  namestore, 
			    procfs_readdir_hash_string, NULL);

	return 0;
}

////////  Proof Store  ////////

static void 
proof_dealloc(struct proof *proof)
{
	int i;

	if (proof->num_auth) {
		// release saved formulae
		for (i = 0; i < proof->num_auth; i++) {
			free(proof->auth_req[i]);
			if (proof->auth_der[i])
				free(proof->auth_der[i]);
			if (proof->auth_form[i])
				form_free(proof->auth_form[i]);
		}
		// release premise lists
		free(proof->auth_der);
		free(proof->auth_form);
		free(proof->auth_ports);
	}

	// release main structures
	free(proof->deduction);
	free(proof);
}

static struct proof *
nxguardsvc_proof_create(struct nxguard_tuple *tuple, const char *formula, 
		        int cp_formula)
{
	struct proof *elem;

	assert(formula);
	elem = calloc(1, sizeof(*elem));
	elem->hash = *tuple;
	elem->status = PF_UNKNOWN;
	elem->deduction = cp_formula ? strdup(formula) : (char *) formula;

	return elem;
}

static void
nxguardsvc_proof_set2_locked(struct nxguard_tuple *tuple, const char *formula)
{
	struct proof *elem, *old;
	
	// remove existing (if any)
	old = hash_findItem(proofstore, tuple);
	if (old) {
		hash_delete(proofstore, old);
		proof_dealloc(old); 
	}

	// insert proof (unless NULL)
	if (formula && formula[0] != 0) {
		// XXX sanity check formula: it is coming from an untrusted source
		elem = nxguardsvc_proof_create(tuple, formula, 1);
		hash_insert(proofstore, &elem->hash, (void *) elem);
		nxlog_write_ex(2, "[guard] + proof sub=%d op=%u obj=%llu.%llu: %.50s..",
		               elem->hash.subject, elem->hash.operation, 
		               elem->hash.object.upper, elem->hash.object.lower, 
		               elem->deduction);
	}
	else
		nxlog_write_ex(2, "[guard] - proof sub=%d op=%u obj=%llu.%llu",
		               tuple->subject, tuple->operation,
		               tuple->object.upper, tuple->object.lower);
}

int
nxguardsvc_proof_set2(struct nxguard_tuple *tuple, const char *formula)
{
	P_writer(&guard_rwlock);
	nxguardsvc_proof_set2_locked(tuple, formula);
	V_writer(&guard_rwlock);
	return 0;
}

/** Retrieve a proof
    Must be called with guard_rwlock held */
static struct proof *
proofstore_acquire(struct nxguard_tuple *tuple)
{
	return hash_findItem(proofstore, tuple);
}

/** Give access to proofstore elements to code outside guard.c
    Somewhat ugly boilerplate */
struct proof *
nxguardsvc_proof_get_locked(struct nxguard_tuple *tuple)
{
	P_reader(&guard_rwlock);
	return proofstore_acquire(tuple);
}

void
nxguardsvc_unlock(void)
{
	V_reader(&guard_rwlock);
}

////////  Credential Store  ////////

/** Look in the credential store whether 
    "principal says process.caller speaksfor principal" exists. 
 
    XXX support transitive speaksfor relationships (low priority)

    @return 0 when found, -1 when not. */
static int
nxguard_cred_chkspeaksfor(const char *principal, int caller)
{
	Form *formula;
	char *readable, *der, digest[DIGESTLEN];
	int ret = -1;

	readable = malloc((2 * strlen(principal)) + 50);
	
	// generate DER-encoded credential "X says process.Y speaks for X"
	if (sprintf(readable, "%s says process.%d speaksfor %s", 
		    principal, caller, principal) < 0)
		goto cleanup_buf;
	formula = form_from_pretty(readable);
	if (!formula)
		goto cleanup_buf;
	der = (char *) form_to_der(formula);
	if (!der)
		goto cleanup_inmemory;

	// lookup credential
	ret = nxguardsvc_cred_chk((char *) der);

	free(der);
cleanup_inmemory:
	form_free(formula);
cleanup_buf:
	free(readable);

	return ret;
}

static int
nxguard_cred_chkkey(const char *label, Form *form, char *formula, int flen,
		    const char *pubkey, const char *digest, 
		    const char *sdigest, int slen)
{
	RSA *rsakey;

	// import key
	rsakey = rsakey_public_import((char *) pubkey);
	if (!rsakey) {
		nxlog_write("[guard] dropping incorrect key\n");
		return -1;
	}
	
	// verify signature
	if (nxguard_sdigest_verify(digest, rsakey, 
				   sdigest, slen)) {
		nxlog_write("[guard] dropping bad signature\n");
		RSA_free(rsakey);
		return -1;
	}
	RSA_free(rsakey);

	// verify "key:X says" matches pubkey
	if (!form->left || 
	    form->left->tag != F_TERM_PEM ||
	    !form->left->left ||
	    form->left->left->tag != F_TERM_BYTES ||
	    memcmp(form->left->left->data, pubkey, PUBKEY_LEN)) {
		nxlog_write("[guard] principal is not a key\n");
		return -1;
	}

	return 0;
}

/** Anyone can issue raw requests;
    this function accepts only these safe cases:
      (1) the kernel issued the credential
      (2) the caller speaksfor the X in "X says ..." 
	  NB: currently transitive relations are excluded
	      but subprincipals are resolved correctly
	  special case is "process.x says S", as kernel can indentify process

     XXX access control checks should NOT be performed here in application logic
         instead, set a goal on AddCred that requires a proof that the subject
	 speaksfor the principal in the label (object)

     @return 0 on accept, -1 on drop
  */
static int 
nxguard_cred_chkraw(const char *readable, int caller) 
{
	char *issuer, *end;
	int object, pid, ret;

	// trust all by kernel
	if (caller == 0)
		return 0;

	issuer = malloc(strlen(readable));       
	if (sscanf(readable, "%s says", issuer) != 1) 
		return -1;
	
	ret = -1;
	if (sscanf(issuer, "process.%d", &pid) == 1) {
		if (pid == caller)	
			ret = 0;
	}
	else {
		// while not found and a subprincipal ..X.Y, try parent ..X
		do {
			if (!nxguard_cred_chkspeaksfor(issuer, caller)) {
				ret = 0;
				break;
			}

			// if a subprincipal, try its parent
			end = strrchr(issuer, '.');
			if (end)
				*end = 0;
		} while (end);
	}

	free(issuer);
	return ret;
}

/** Add a cryptographically signed label */
int
nxguardsvc_cred_addkey(const char *label, const char *pubkey, 
		       const char *sdigest, int slen, int caller)
{
	Form *form;
	char digest[DIGESTLEN];
	char *entry, *formula;
	int flen, rlen, ret = -1;

	if (!label || strchr(label, '\n'))
		goto fail;
	
	// create in-memory tree
	form = form_from_pretty(label);
	if (!form || form->tag != F_STMT_SAYS)
		goto fail;

	// create canonical DER form
	formula = (char *) form_to_der(form);
	if (!formula) {
		free(form);
		goto fail;
	}
	flen = der_msglen(formula);
	
	// regenerate digest
	MD5(formula, flen, digest);

	// verify authenticity
	if (sdigest)
		ret = nxguard_cred_chkkey(label, form, formula, flen,
				          pubkey, digest, sdigest, slen);
	else
		ret = nxguard_cred_chkraw(label, caller);
	if (ret) {
		nxlog_write("[guard] unsupported label (%s) \n", label);
		goto cleanup;
	}

	P_writer(&guard_rwlock);

	// guard against duplicates
	entry = hash_findItem(credstore, digest);
	if (entry) {
		nxlog_write_ex(3, "[guard] duplicate credential detected\n");
		ret = 0;
		goto cleanup;
	}

	// create private copy and insert
	entry = malloc(flen);
	memcpy(entry, formula, flen);
	hash_insert(credstore, digest, entry);
	
	// print
	nxlog_write_ex(2, "[guard] + cred [%s]", label);
	ret = 0;

cleanup:
	V_writer(&guard_rwlock);
	free(formula);
	form_free(form);
	return ret;

fail:	
	nxlog_write("[guard] dropped illegible credential\n");
	return -1;
}

/** Add a system-backed label */
int
nxguardsvc_cred_add(const char *label, int caller)
{
	return nxguardsvc_cred_addkey(label, NULL, NULL, 0, caller);
}

/** check if a statement is known.
 
    @return 0 if there's a match, -1 if not */
int
nxguardsvc_cred_chk(const char *der)
{
	char digest[DIGESTLEN];

	MD5(der, der_msglen(der), digest);	
	return hash_findItem(credstore, digest) ? 0 : -1;
}

////////  Goal Store  ////////

int
nxguardsvc_goal_set2(struct nxguard_tuple *tuple, const char *formula)
{
	static int goal_ids;

	struct goal *goal;
	struct HashTable *opstore;
	
	if (!strcmp(formula, ""))
		formula = NULL;

	// XXX reduce amount of code in critical section
	P_writer(&guard_rwlock);
	
    	// Because policies attach to an (object, operation) pair, 
	// lookup is a two-step process
	// (1) lookup object table for the operation
	opstore = hash_findItem(goalstore, &tuple->operation);
	if (opstore) {
		// (2) lookup old policy and remove (if any)
		goal = hash_findItem(opstore, &tuple->object);
		if (goal) {
			hash_delete(opstore, &tuple->object);
			form_free(goal->form);
			free(goal);
		}
	}
	else {
		// create a table for this operation
		opstore = hash_new(2711 /* reasonably sized prime*/, 
				    sizeof(struct nxguard_object));
		hash_insert(goalstore, &tuple->operation, opstore);
	}

	// insert new policy
	if (formula) {
		goal = calloc(1, sizeof(struct goal));

		// initialize structure 
		goal->id = goal_ids++;
		goal->form = form_from_pretty(formula);
		if (!goal->form) {
			free(goal);
			V_writer(&guard_rwlock);
			return 1;
		}

		hash_insert(opstore, &tuple->object, goal);

		// pretty print
		nxlog_write_ex(2, "[guard] + goal [op=%u,ob=%llu.%llu]",  
		               tuple->operation, tuple->object.upper, 
		               tuple->object.lower);
	}
	else {
		nxlog_write_ex(2, "[guard] - goal [op=%u,ob=%llu.%llu]",  
		               tuple->operation, tuple->object.upper, 
		               tuple->object.lower);
	}

	V_writer(&guard_rwlock);
	return 0;
}

int
nxguardsvc_goal_get(struct nxguard_tuple *tuple, char **goalcopy)
{
	struct HashTable *opstore;
	struct goal *goal;
	
	opstore = hash_findItem(goalstore, &tuple->operation);
	if (!opstore)
		return 0;

	goal = hash_findItem(opstore, &tuple->object);
	if (!goal)
		return 0;

	*goalcopy = (char *) form_to_der(goal->form);
	return strlen(*goalcopy);
}

/** Proof evaluation

  A subject must jump through two hurdles:
  (1) have a correct proof for (sub, op, 'any') or NULL
  (2a) have a correct proof for (sub, op, obj) or
  (2b) goal happens to require trivial proof "assume <goal>"
       in which case the proofchecker actually CONSTRUCTS this (trivial) proof

  if obj == 'any', we can skip the (then duplicate) second step
 */
static int
nxguardsvc_chk_sub(struct nxguard_tuple *tuple, struct goal *goal)
{
	struct proof *proof;
	int ret;

	// (1) run proof for wildcard (unless wildcard *is* requested object)
	if (tuple->object.upper != NXGUARD_OBJECT_WILDCARD_UP ||
	    tuple->object.lower != NXGUARD_OBJECT_WILDCARD_LO) {
		static struct nxguard_tuple tstat;

		tstat.subject = tuple->subject;
		tstat.operation = tuple->operation;
		proof = proofstore_acquire(&tstat);
		if (proof)
			ret = guard_check(goal, proof);
		else
			ret = AC_ALLOW_CACHE;
	}
	else
		ret = AC_ALLOW_CACHE;

	// (2a) run test for specific object (unless already blocked)
	if (ret != AC_BLOCK_CACHE && ret != AC_BLOCK_NOCACHE) {
		proof = proofstore_acquire(tuple);
		if (proof) {
			ret = guard_check(goal, proof);
		}
		else {
			// no proof? try trivial satisfaction of goal G
			// by inserting proof "assume G;\n"
			
			//
			// NB: pretty expensive
			struct proof *proof;
			char *proofstr, *goalstr;
			int plen, rlen;

			// translate proof into textual form
			goalstr = form_to_pretty(goal->form, 0);
			assert(goalstr);

			// concatenate with prefix into proof
			plen = strlen(goalstr) + 1 + 11;
			proofstr = malloc(plen);
			rlen = snprintf(proofstr, plen - 1, "assume %s;\n", goalstr);
			assert(rlen <= plen - 1);

			// insert proof
#if 0
			proof = nxguardsvc_proof_create(tuple, proofstr, 0);
#else
			nxguardsvc_proof_set2_locked(tuple, proofstr);
			proof = proofstore_acquire(tuple);
#endif
			assert(proof);
			
			// finally, call proof checker
			ret = guard_check(goal, proof);
#if 0
			free(proof);
			free(proofstr);
#endif
			free(goalstr);

			// on failure, will return NOCACHE because it failed
			// to find the credential G. Override and cache, 
			// because any change to goal or proof will reset
			if (ret == AC_BLOCK_NOCACHE)
				ret = AC_BLOCK_CACHE;
		}
	}

	return ret;
}

/** Allow or deny the call to go through. 
    @return 0 on allow, any other means deny. 				*/
int 
nxguardsvc_chk(struct nxguard_tuple *tuple)
{
	struct HashTable *opstore;
	struct goal *goal = NULL;
	int ret;

	// default policy
	// XXX make BLOCK as default policy
	ret = AC_ALLOW_CACHE;

	// Benchmark hack 
	if (tuple->operation == SYS_Debug_Null2_CMD) {
		ret = AC_BLOCK_CACHE;
	}
	else {
		// make sure noone modifies the {cred, proof, guard} store 
		// because chk has to be reentrant, we use a reader/writer lock
		P_reader(&guard_rwlock);

		// lookup goal
		// XXX make goal lookup one-step, from current two-step
		opstore = hash_findItem(goalstore, &tuple->operation);
		if (opstore) {
			goal = hash_findItem(opstore, &tuple->object);
			if (goal) {
				ret = nxguardsvc_chk_sub(tuple, goal);
			}
		}
	
		V_reader(&guard_rwlock);
	}

// NB: this generates HEAPS of data. if written to ramfs, causes OOM
#define ENABLE_MEMLEAK
#ifdef ENABLE_MEMLEAK
	if (ret == AC_BLOCK_CACHE || ret == AC_BLOCK_NOCACHE)
		nxlog_write_ex(3, "[guard] BLOCK <%d.%d.%llu.%llu> (0x%x)",
	       	               tuple->subject, tuple->operation, 
		               tuple->object.upper, tuple->object.lower, ret);
	else
		nxlog_write_ex(3, "[guard] allow <%d.%d.%llu.%llu> (0x%x)",
	       	               tuple->subject, tuple->operation, 
		               tuple->object.upper, tuple->object.lower, ret);
#endif

	return ret;
}


////////  Authority Store  ////////

/** support variable length strings by translating into 0-padded fixed length
    NOT multithread safe */
static const char *
__nxguardsvc_name_fixedkey(const char *key)
{
	static char internal_key[PUBKEY_LEN];
	char *_key;
	int klen;

	klen = strlen(key);
	if (klen == PUBKEY_LEN)
		return key;
	
	assert(klen <= PUBKEY_LEN);
	memset(internal_key, 0, PUBKEY_LEN);
	memcpy(internal_key, key, klen);
	return internal_key;
}

/** Nameserver: say that a principal speaksfor another principal 
    @return 0 on success, 1 if name is already taken */
int
nxguardsvc_name_add(const char *key, long port)
{
	if (nxguardsvc_name_get(key))
		return 1;

	P_writer(&guard_rwlock);
	hash_insert(namestore, __nxguardsvc_name_fixedkey(key), 
		    (void *) port);
	V_writer(&guard_rwlock);
	
	nxlog_write_ex(2, "[guard] + authority %s [ipc.%d]", key, port);
	return 0;
}

/** Nameserver: lookup a principal that speaksfor another principal */
long
nxguardsvc_name_get(const char *key)
{
	// don't lock: called with lock held by nxguardsvc_chk
	return (long) hash_findItem(namestore, 
				    __nxguardsvc_name_fixedkey(key));
}

/** Nameserver: remove a speaksfor */
void
nxguardsvc_name_del(const char *key)
{
	P_writer(&guard_rwlock);
	hash_delete(namestore, key);
	V_writer(&guard_rwlock);
}

/** Ask an authority to testify that it believes a formula. */
int
nxguardsvc_auth_ask(int portnum, const char *formula)
{
	int ret;

	ret = Auth_Answer_ext(portnum, VARLENSTR(formula));
	nxlog_write_ex(2, "[guard] authority ipc.%d says %s to %.50s", 
	               portnum, ret ? "true" : "false", formula);

	return ret;
}

// selftest: call process with special authtest port: guard_auth.test
int
nxguardsvc_test(void)
{
	char question[20];
	int authport;

	// lookup authority
	authport = nxguardsvc_name_get("test");
	if (!authport) {
		nxlog_write("[guard] testport not found\n");
		return 1;
	}

	// test true statement 
	snprintf(question, 19, "authport = %d\n", authport);
	if (nxguardsvc_auth_ask(authport, question) == 0) {
		nxlog_write("[guard] selftest FAILED #1\n");
		return 1;
	}

	// test false statement
	snprintf(question, 19, "authport = %d\n", authport + 1);
	if (nxguardsvc_auth_ask(authport, question) != 0) {
		nxlog_write("[guard] selftest FAILED #2\n");
		return 1;
	}

	return 0;
}

