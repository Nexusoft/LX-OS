/** NexusOS: 'guard' process that makes access control decisions for the kernel.
             
  	The kernel consults the 'upcall' port for access control.
 	Principals send signed credentials to the 'credential' port.
	Principals attach to the 'authority' port.
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>

#include <openssl/md5.h>
#include <openssl/rand.h>

#include <nexus/defs.h>
#include <nexus/ipc.h>
#include <nexus/sema.h>
#include <nexus/guard.h>
#include <nexus/hashtable.h>

#include <nexus/IPC.interface.h>

/** Store hintcode proofs by the (subj, oper, obj) hash */
static struct HashTable *proofstore;

/** Store true "X says Y" statements by md5 of the statement */
static struct HashTable *credstore;

/** Store policy goals by (operating, object) */
static struct HashTable *goalstore;

/** Store stores authorities by the first N bytes of their public key */
static struct HashTable *authstore;
static Sema auth_mutex = SEMA_MUTEX_INIT;
static int authport;

/** Lock access to all structures */
static Sema guard_mutex = SEMA_MUTEX_INIT;


////////  Proof Store  ////////
	
struct proofstore_hash {
	int subject;
	int operation;
	struct nxguard_object object;
};

struct proofstore_elem {
	struct proofstore_hash hash;

	char *proof;

	int cached:1;		///< if true, correct will hold the result
	int correct:1;		///< outcome of cached proof checking
};

static struct proofstore_elem *
__proofstore_set(int subject, int operation, struct nxguard_object *object,
		 const char *proof)
{
	struct proofstore_elem *elem, *old;

	elem = calloc(1, sizeof(*elem));

	// set lookup triple
	elem->hash.subject = subject;
	elem->hash.operation = operation;
	elem->hash.object.lower = object->lower;
	elem->hash.object.upper = object->upper;

	P(&guard_mutex);

	// remove existing (if any)
	old = hash_findItem(proofstore, &elem->hash);
	if (old) {
		hash_delete(proofstore, old);
		free(old->proof);
		free(old);
	}

	// insert proof
	// XXX sanity check first: coming from outside
	elem->proof = strdup(proof);
	hash_insert(proofstore, &elem->hash, (void *) elem);
	
	V_nexus(&guard_mutex);

	return elem;
}

/** Retrieve a proof and keep the system locked.
    caller MUST call __proofstore_release to release the lock after use. */
static struct proofstore_elem *
__proofstore_acquire(int subject, int operation, struct nxguard_object *object)
{
	struct proofstore_elem *elem;
	struct proofstore_hash hash;

	hash.subject = subject;
	hash.operation = operation;
	hash.object = *object;

	P(&guard_mutex);
	elem = hash_findItem(proofstore, &hash);
	if (!elem) {
		V_nexus(&guard_mutex);
		return NULL;
	}
		
	return elem;
}

static void
__proofstore_release(struct proofstore_elem *elem)
{	
	V_nexus(&guard_mutex);
}


////////  Credential Store  ////////

/** Store a credential in the cache.
 
    Credentials are signed statements that match 1:1 onto assumptions
    in a deduction. Lookup is by MD5 over the DER formula.
 */
static void
__credstore_add(const char *der, const char *sdigest, int slen, 
		const char *pubkey)
{
	Form *form;
	RSA *rsakey;
	char digest[DIGESTLEN];
	char *entry, *readable;
	int dlen;

	// verify credential 
	form = form_from_der((Formula *) der);
	readable = form_to_pretty(form, 0);
	if (!form || !readable) {
		printf("[guard] dropped illegible credential\n");
		return;
	}
	free(form);
	dlen = der_msglen(der);

	// import key
	rsakey = rsakey_public_import((char *) pubkey);
	if (!rsakey) {
		fprintf(stderr, "[guard] dropping incorrect key\n");
		return;
	}
	
	// verify signature
	if (nxguard_sdigest_verify(der, dlen, rsakey, sdigest, slen)) {
		fprintf(stderr, "[guard] dropped erroneous credential\n");
		return;
	}
	RSA_free(rsakey);

	P(&guard_mutex);

	// guard against duplicates
	entry = hash_findItem(credstore, digest);
	if (entry) {
		// XXX verify that the plaintexts are the same
		printf("[guard] duplicate insertion thwarted\n");
		goto cleanup;
	}

	// create private copy and insert
	entry = malloc(dlen);
	memcpy(entry, der, dlen);
	hash_insert(credstore, digest, entry);

	printf("[guard] inserted credential %s\n", readable);
	free(readable);

cleanup:
	V_nexus(&guard_mutex);
}


////////  Goal Store  ////////

/** Attach a policy expressed as NAL proof.

    @param object contains an object ID that is unique within the
           system for this operation. Operations that do not

    @param formula is a human-readable expression 
           or NULL to clear the policy
 */
static void
__goalstore_set(struct nxguard_object *object, int operation, 
                const char *nal_formula)
{
	Form *formula = NULL;
	char *der;
	struct HashTable *opstore;

	printf("[guard] set goal op=%d goal=[%s]\n", 
	       operation, nal_formula);
	
	// sanity check input
	if (nal_formula) {
		formula = form_fmt((char *) nal_formula);

		if (!form_is_proper(formula)) {
			printf("[guard] not a proper formula\n");
			return;
		}
	}

	P(&guard_mutex);
	
    	// Because policies attach to an (object, operation) pair, 
	// lookup is a two-step process
	// (1) lookup object table for the operation
	opstore = hash_findItem(goalstore, &operation);
	if (opstore) {
	printf("CHECK: found opstore\n");
		// (2) lookup old policy and remove (if any)
		der = hash_findItem(opstore, object);
		if (der) {
			hash_delete(opstore, object);
			free(der);
		}
	}
	else {
		// create a table for this operation
		opstore = hash_new(2711 /* reasonably sized prime*/, 
				    sizeof(struct nxguard_object));
	printf("CHECK: create opstore\n");
		hash_insert(goalstore, &operation, opstore);
	}

	if (formula) {
		// insert new policy
		der = (char *) form_to_der(formula);
	printf("CHECK: insert goal\n");
		hash_insert(opstore, &object, der);
	}

	V_nexus(&guard_mutex);

	printf("[guard] OK. goal [%s] set on (O, %d)\n",  
	       formula ? form_to_pretty(formula, 0) : "", operation);
}

/** Allow or deny the call to go through. 
    @return 0 on allow, any other means deny. 				*/
static int 
__goalstore_chk(int subject, int operation, struct nxguard_object *object)
{
	struct proofstore_elem *proof;
	struct HashTable *opstore;
	char *der;
	int ret = 0;

	
	printf("[guard] access control check s=%d op=%d\n", subject, operation);
	P(&guard_mutex);	// XXX: this may be a highly contended lock

	// lookup goal
	opstore = hash_findItem(goalstore, &object);
	if (opstore) {
	printf("CHECK: found operation\n");
		der = hash_findItem(opstore, &object);
		if (der) {
	printf("CHECK: found goal\n");
			// lookup proof
			proof = __proofstore_acquire(subject, operation, object);
			if (proof) {
				if (!proof->cached) {
				// check proof against policy
	printf("CHECK: found goal and proof\n");
	//			if (guard_check(guard, NULL, grounds))
	//				ret = -1;
					// do not rerun this proof
					proof->cached = 1;
					proof->correct = ret ? 0 : -1;
				}
				else {
					ret = proof->correct ? 0 : -1;
				}
			} 
			else {
	printf("CHECK: found goal without proof\n");
				ret = -1;
			}
		}
	}

	V_nexus(&guard_mutex);
	printf("[guard] access control reply %s\n", ret ? "BLOCK" : "ALLOW");
	
	return ret;
}


////////  Authority Store  ////////

static void
__authstore_add(const char *key, long port)
{
	P(&guard_mutex);
	hash_insert(authstore, key, (void *) port);
	V_nexus(&guard_mutex);
}

static long
__authstore_get(const char *key)
{
	long ret;

	P(&guard_mutex);
	ret = (long) hash_findItem(authstore, key);
	V_nexus(&guard_mutex);
	return ret;
}

static void
__authstore_del(const char *key)
{
	P(&guard_mutex);
	hash_delete(authstore, key);
	V_nexus(&guard_mutex);
}

/** Ask an authority to testify that it believes
    a formula.
 
    @param formula is a NAL statement in human readable format 
    @return 1 if it agrees, 0 if it does NOT
 */
static int
auth_ask(const char *key, const char *formula)
{
	char *msg;
	int mlen, portnum, ret;

	mlen = strlen(formula) + 1;
	if (mlen > AUTHREQ_LEN) {
		fprintf(stderr, "[guard] authority request exceeds limit\n");
		return 0;
	}

	portnum = __authstore_get(key);
	if (!portnum)
		return 0;

	// create copy (because IPC_Send deallocates)
	msg = malloc(mlen);
	memcpy(msg, formula, mlen);

	// exchange messages
	P(&auth_mutex);
	if (IPC_Send(portnum, msg, mlen) ||
	    IPC_Recv(authport, &ret, sizeof(ret)) != sizeof(ret)) {
		fprintf(stderr, "[guard] error in authority communication\n");
		ret = 0;
	}
	V_nexus(&auth_mutex);

	printf("[guard] authority %hx%hx.. says %s to %s\n", 
	       key[0], key[1], ret ? "true" : "false", formula);

	return ret;
}


////////  Low-level messaging  ////////
// boring boilerplate. I decided against IDL generated code because this needs
// to be fast.

static int 
open_port(int in_portnum)
{
	int portnum;

	portnum = in_portnum;
	portnum = IPC_CreatePort(&portnum);
	if (portnum != in_portnum) {
		fprintf(stderr, "Error opening port %d\n", in_portnum);
		return -1;
	}

	return 0;
}

/** Listen for access control checks from the kernel 

    XXX this is a performance-critical element. speed up
        communication through shared memory, etc..
 */
static void *
thread_upcall(void *unused)
{
	struct guard_upcall_msg call;
	int ret;

	while (1) {
		// wait for authorization request
		ret = IPC_Recv(guard_upcall_port, &call, sizeof(call));
		if (ret != sizeof(call)) {
			fprintf(stderr, "Error at upcall:recv\n");
			continue;
		}

		// perform the access control check
		ret = __goalstore_chk(call.subject, call.operation, 
				      &call.object);

		// reply (an int)
		if (IPC_Send(guard_upreply_port, &ret, sizeof(ret)))
			fprintf(stderr, "Error at upcall:send\n");
	}

	// not reached
	return NULL;
}

/** Listen for credentials, verify their signatures and add them to the
    credential cache.
 */
static void *
thread_cred(void *unused)
{
	struct guard_cred_header *call;
	int mlen, ret = 0, caller;

	mlen = sizeof(struct guard_cred_header) + GUARD_CRED_MAXSZ;
	call = malloc(mlen);

	while (1) {
		// listen for statement
		ret = IPC_RecvFrom(guard_credential_port, call, mlen, &caller);
		if (ret < sizeof(call) || ret < call->length) {
			fprintf(stderr, "Error at cred:recv\n");
			continue;
		}

		printf("[guard] received %d request\n", call->type);

		// insert into store
		switch (call->type) {
		case call_goal :
		{
			struct guard_goalproof_msg *goal = (void *) call;
			__goalstore_set(&goal->object, goal->operation, 
					goal->formula);
		}
		break;
		case call_proof :
		{
			struct guard_goalproof_msg *goal = (void *) call;
			__proofstore_set(caller, goal->operation,
					 &goal->object, goal->formula);
		}
		break;
		case call_cred :
		{
			struct guard_cred_msg *cred = (void *) call;
			__credstore_add(cred->formula, cred->sdigest, 
					cred->slen, cred->pubkey);
		}
		break;
		};

		// reply (an int) if the replyport is set
		if (call->replyport >= 0 && 
		    IPC_Send(call->replyport, &ret, sizeof(ret)))
			fprintf(stderr, "Error at cred:send\n");
	}

	free(call);
	
	// not reached
	return NULL;
}

/** Accept (other half) authenticated channel requests. 
  
    Listen on a well known port for requests and start
    a challenge/response message exchange on another port.
 */
static void *
thread_auth(void *unused)
{
	struct guard_auth_challenge chal;
	struct guard_auth_response msg;
	char randbuf[CHALLENGE_LEN];
	RSA *rsakey;
	int rport;
	int ret;

	// Create private channel that clients communicate with
	// The server reuses the same private channel for all sessions.
	// It serializes communication requests to avoid crosstalk.
	authport = IPC_CreatePort(NULL);
	if (authport < 0) {
		fprintf(stderr, "[guard] error in create port\n");
		return NULL;
	}

	while (1) {
		// wait for request
		ret = IPC_Recv(guard_authority_port, &rport, sizeof(int));
		if (ret < sizeof(int)) {
			fprintf(stderr, "[guard] error in authchan request\n");
			continue;
		}

		printf("[guard] authenticated chan request on %d\n", rport);
		ret = 1;

		P(&auth_mutex);

		// create and send challenge
		chal.port = authport;
		RAND_bytes(chal.challenge, CHALLENGE_LEN);
		if (IPC_Send(rport, &chal, sizeof(chal))) {
			fprintf(stderr, "[guard] error send challenge\n");
			goto done_noreply;
		}

		// receive response
		ret = IPC_Recv(chal.port, &msg, sizeof(msg));
		if (ret < sizeof(msg)) {
			fprintf(stderr, "[guard] error in recv response\n");
			goto done_noreply;
		}

		// check response
		rsakey = rsakey_public_import(msg.pubkey);
		if (!rsakey) {
			fprintf(stderr, "[guard] dropping auth key\n");
			goto done_reply;
		}
		if (nxguard_sdigest_verify(chal.challenge, CHALLENGE_LEN, 
					   rsakey, msg.sdigest, msg.slen)) {
			fprintf(stderr, "[guard] dropping auth res\n");
			goto done_reply;
		}

		ret = 0;
		__authstore_add(msg.pubkey, rport);
		printf("[guard] accepted authority at %d\n", rport);

done_reply:
		IPC_Send(rport, &ret, sizeof(ret));
done_noreply:
		V_nexus(&auth_mutex);

#ifndef NDEBUG
		// selftest (ONLY if caller uses special 'authtest' port)
		if (rport == guard_authtest_port) {
			char question[20];

			snprintf(question, 19, "authport = %d\n", chal.port);
			if (auth_ask(msg.pubkey, question) != 1) {
				fprintf(stderr, "[guard] selftest FAILURE. Exiting\n");
				break;
			}
		}
#endif
	}
			
	IPC_DestroyPort(authport);
	return NULL;
}


////////  Support  ////////

static void
nxguard_init(void)
{
	rand_init();

	goalstore = hash_new(2711 /* reasonably sized prime */, sizeof(int));
	credstore = hash_new(2711, DIGESTLEN);

	// NB: I lookup by the a portion of the public key that I
	//     assume is random enough not to have any duplicates
	authstore = hash_new(283  /* reasonably sized prime */, 30);	

	proofstore = hash_new(2711, sizeof(int) + sizeof(int) + 
			            sizeof(struct nxguard_object));
}

/** Create listening ports */
static int
nxguard_svc_init(void)
{
	pthread_t pthread;
	
	nxguard_init();

	if (open_port(guard_upcall_port) ||
	    open_port(guard_credential_port) ||
	    open_port(guard_authority_port))
		return -1;

  	pthread_create(&pthread, NULL, thread_upcall, NULL);
  	pthread_create(&pthread, NULL, thread_cred, NULL);
  	pthread_create(&pthread, NULL, thread_auth, NULL);

	return 0;
}

int
main(int argc, char **argv)
{
	char c;

	printf("Nexus access control guard\n\n");
	if (nxguard_svc_init())
		return 1;

	// user interface thread
	printf("[guard] OK. accepting request\n");
	while (1) {
		sleep(10);
	}

	return 0;
}

